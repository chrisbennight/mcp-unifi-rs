//! Fixed-window Internet activity, with independent temporal and accounting evidence.

use super::{
    CallToolResult, CounterSemantics, CoverageStatus, DEFAULT_TOP_APPLICATIONS,
    DEFAULT_WAN_REPORT_HOURS, JsonSchema, MAXIMUM_SEARCH_LIMIT, MAXIMUM_TOP_APPLICATIONS,
    MAXIMUM_WAN_REPORT_HOURS, McpError, Serialize, StatsQueryInput, StatsQueryOutput, StatsReport,
    TopApplicationRow, TrafficCoverage, UnifiMcp, api_error, bounded_text, structured,
};
use std::collections::{BTreeMap, BTreeSet};
use unifi_api::traffic::{
    ActivityBucket, ActivityRead, ActivityReport, ActivityWindow, ApplicationActivity,
};

const HOUR_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Default, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Bytes {
    rx_bytes: u64,
    tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClientRow {
    mac: String,
    name: Option<String>,
    #[serde(flatten)]
    bytes: Bytes,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ActivityDetails {
    clients: Vec<ClientRow>,
    total_clients: usize,
    next_offset: Option<u16>,
    /// Totals across all returned clients, independent of the output page.
    client_totals: Bytes,
    application_totals: Bytes,
    /// Graph timestamps describe site activity, not collection coverage of each client.
    temporal_evidence: TemporalEvidence,
    reconciliation: Reconciliation,
    names_status: &'static str,
    limitations: &'static str,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct TemporalEvidence {
    status: &'static str,
    source: &'static str,
    observed_start_ms: Option<u64>,
    observed_end_ms: Option<u64>,
    /// Returned site graph timestamps within the requested window.
    sample_count: usize,
    /// The graph does not establish whether timestamps label bucket starts or ends.
    bucket_boundary_semantics: &'static str,
    /// The aggregate traffic response supplies no per-client collection timestamps.
    per_client_observed_interval_known: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Reconciliation {
    status: &'static str,
    complete_wan_hours: usize,
    expected_wan_hours: u64,
    site_rx_bytes: Option<f64>,
    site_tx_bytes: Option<f64>,
    /// Site minus all attributed clients; negative values expose over-attribution.
    unmatched_rx_bytes: Option<f64>,
    unmatched_tx_bytes: Option<f64>,
    reason: &'static str,
}

pub(super) fn report_window(input: &StatsQueryInput) -> Result<ActivityWindow, McpError> {
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| McpError::internal_error("system clock before epoch", None))?
            .as_millis(),
    )
    .map_err(|_| McpError::internal_error("system clock out of range", None))?;
    match (input.start_ms, input.end_ms, input.hours) {
        (Some(start), Some(end), None) if end <= now => ActivityWindow::new(start, end).map_err(|_| McpError::invalid_params("startMs/endMs must cover whole UTC hours, from one hour to seven days, ending in the past", None)),
        (None, None, hours) => {
            let hours = hours.unwrap_or(DEFAULT_WAN_REPORT_HOURS);
            if !(1..=MAXIMUM_WAN_REPORT_HOURS).contains(&hours) {
                return Err(McpError::invalid_params("hours must be between 1 and 168", None));
            }
            let end = if input.report == StatsReport::WanHourly { now } else { now / HOUR_MS * HOUR_MS };
            Ok(ActivityWindow { start: end.saturating_sub(u64::from(hours) * HOUR_MS), end })
        }
        _ => Err(McpError::invalid_params("supply both startMs/endMs instead of hours, with endMs in the past", None)),
    }
}

impl UnifiMcp {
    #[expect(
        clippy::too_many_lines,
        reason = "one bounded report combines attribution with independent temporal and WAN evidence"
    )]
    pub(super) async fn activity_stats(
        &self,
        input: StatsQueryInput,
    ) -> Result<CallToolResult, McpError> {
        let window = report_window(&input)?;
        let top = input.top.unwrap_or(DEFAULT_TOP_APPLICATIONS);
        let limit = input.limit.unwrap_or(50);
        let offset = input.offset.unwrap_or(0);
        if !(1..=MAXIMUM_TOP_APPLICATIONS).contains(&top)
            || !(1..=MAXIMUM_SEARCH_LIMIT).contains(&limit)
            || offset > 1000
            || (input.report == StatsReport::ClientWanHistory && input.top.is_some())
            || (input.report == StatsReport::DpiApplications
                && (input.limit.is_some() || input.offset.is_some()))
        {
            return Err(McpError::invalid_params(
                "top (1-50) applies only to dpiApplications; limit (1-200) and offset (0-1000) apply only to clientWanHistory",
                None,
            ));
        }
        let read = self
            .legacy()
            .activity(self.legacy_site(), window)
            .await
            .map_err(api_error)?;
        let report = match read {
            ActivityRead::Reported(report) => report,
            ActivityRead::Unsupported
                if input.report == StatsReport::DpiApplications
                    && input.hours.is_none()
                    && input.start_ms.is_none() =>
            {
                return self.dpi_stats(top).await;
            }
            ActivityRead::Unsupported => {
                return unavailable(input.report, window, CoverageStatus::Unsupported);
            }
            ActivityRead::Unrecognized => {
                return unavailable(input.report, window, CoverageStatus::Unrecognized);
            }
        };
        let (mut clients, client_totals, application_totals) = totals(&report)?;
        clients.sort_by(|a, b| {
            (u128::from(b.bytes.rx_bytes) + u128::from(b.bytes.tx_bytes))
                .cmp(&(u128::from(a.bytes.rx_bytes) + u128::from(a.bytes.tx_bytes)))
                .then_with(|| a.mac.cmp(&b.mac))
        });
        let total_clients = clients.len();
        let next = usize::from(offset).saturating_add(usize::from(limit));
        let next_offset =
            (next < total_clients).then(|| u16::try_from(next).expect("bounded client count"));
        let clients = if input.report == StatsReport::ClientWanHistory {
            clients
                .into_iter()
                .skip(usize::from(offset))
                .take(usize::from(limit))
                .collect()
        } else {
            Vec::new()
        };
        let graph = self
            .legacy()
            .activity_buckets(self.legacy_site(), window)
            .await
            .map_err(api_error)?;
        let temporal_evidence = temporal(graph, window);
        let reconciliation = self.reconcile_activity(window, &client_totals).await?;
        let total_applications = report.total_usage_by_app.len();
        let mut applications = report.total_usage_by_app;
        applications.sort_by_key(|row| {
            std::cmp::Reverse(u128::from(row.bytes_received) + u128::from(row.bytes_transmitted))
        });
        applications.truncate(usize::from(top));
        let (top_applications, names_status) = if input.report == StatsReport::DpiApplications {
            let (rows, status) = self.activity_names(applications).await;
            (Some(rows), status)
        } else {
            (None, "notRequested")
        };
        structured(StatsQueryOutput {
            report: report_name(input.report),
            coverage: TrafficCoverage {
                status: if total_clients == 0 && total_applications == 0 {
                    CoverageStatus::Empty
                } else {
                    CoverageStatus::Partial
                },
                reason: "Controller-attributed Internet activity, including unidentified traffic. Collection and classification completeness are not established; inspect temporal evidence and WAN differences.",
                unrecognized_records: 0,
            },
            counter_semantics: semantics(window),
            total_applications: Some(total_applications),
            wan_hourly: None,
            top_applications,
            activity: Some(ActivityDetails {
                clients,
                total_clients,
                next_offset: if input.report == StatsReport::ClientWanHistory {
                    next_offset
                } else {
                    None
                },
                client_totals,
                application_totals,
                temporal_evidence,
                reconciliation,
                names_status,
                limitations: "The Activity view reports Internet usage, not LAN association counters. Its aggregate response has no per-client observed timestamps, reset markers, or collection-completeness proof. Site graph gaps are unknown, not zero. IPv6, UDP/QUIC, VPN encapsulation, gateway-originated traffic, proxy attribution, and interface accounting may contribute to differences; this source does not identify their contributions. Application names describe classifier labels, not a verified service or process. Pages re-read a mutable source; reuse fixed timestamps. This read creates no retained history.",
            }),
        })
    }

    async fn activity_names(
        &self,
        rows: Vec<ApplicationActivity>,
    ) -> (Vec<TopApplicationRow>, &'static str) {
        if rows.is_empty() {
            return (Vec::new(), "empty");
        }
        let ids: Vec<_> = rows
            .iter()
            .map(|row| u32::from(row.category) << 16 | u32::from(row.application))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let cats: Vec<_> = rows
            .iter()
            .map(|row| u32::from(row.category))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let app_names = self.integration().dpi_names(&ids, false).await;
        let cat_names = self.integration().dpi_names(&cats, true).await;
        // Taxonomy enrichment is optional: a failed lookup must not discard the
        // measured bytes. Its failure is explicit in the result and operator log.
        let failed = app_names.is_err() || cat_names.is_err();
        if failed {
            tracing::warn!(
                endpoint = "network.dpi_names",
                "DPI name enrichment unavailable; preserving activity counters"
            );
        }
        let apps: BTreeMap<_, _> = app_names
            .unwrap_or_default()
            .into_iter()
            .map(|v| (v.id, v.name))
            .collect();
        let cats: BTreeMap<_, _> = cat_names
            .unwrap_or_default()
            .into_iter()
            .map(|v| (v.id, v.name))
            .collect();
        let complete = rows.iter().all(|row| {
            apps.contains_key(&(u32::from(row.category) << 16 | u32::from(row.application)))
                && cats.contains_key(&u32::from(row.category))
        });
        (
            rows.into_iter()
                .map(|row| TopApplicationRow {
                    application_id: u32::from(row.application),
                    category_id: u32::from(row.category),
                    rx_bytes: row.bytes_received,
                    tx_bytes: row.bytes_transmitted,
                    application_name: apps
                        .get(&(u32::from(row.category) << 16 | u32::from(row.application)))
                        .cloned()
                        .map(bounded_text),
                    category_name: cats
                        .get(&u32::from(row.category))
                        .cloned()
                        .map(bounded_text),
                })
                .collect(),
            if failed {
                "unavailable"
            } else if complete {
                "reported"
            } else {
                "partial"
            },
        )
    }

    async fn reconcile_activity(
        &self,
        window: ActivityWindow,
        clients: &Bytes,
    ) -> Result<Reconciliation, McpError> {
        let rows = self
            .legacy()
            .hourly_wan_report(self.legacy_site(), window.start, window.end)
            .await
            .map_err(api_error)?;
        let mut hours = BTreeSet::new();
        let mut missing_counter = false;
        let (mut rx, mut tx) = (0.0, 0.0);
        for row in rows {
            if row
                .time
                .is_some_and(|time| time < window.start || time >= window.end)
            {
                continue;
            }
            if let (Some(time), Some(received), Some(transmitted)) =
                (row.time, row.wan_rx_bytes, row.wan_tx_bytes)
            {
                if time < window.start || time >= window.end {
                    continue;
                }
                if !time.is_multiple_of(HOUR_MS)
                    || !received.is_finite()
                    || !transmitted.is_finite()
                    || received < 0.0
                    || transmitted < 0.0
                    || !hours.insert(time)
                {
                    return Err(McpError::internal_error(
                        "WAN comparison contains invalid or duplicate buckets",
                        None,
                    ));
                }
                rx += received;
                tx += transmitted;
            } else {
                missing_counter = true;
            }
        }
        let expected = (window.end - window.start) / HOUR_MS;
        let complete =
            !missing_counter && hours.len() as u64 == expected && rx.is_finite() && tx.is_finite();
        #[allow(clippy::cast_precision_loss)]
        // Site counters are already floating point; differences are approximate.
        let differences = (rx - clients.rx_bytes as f64, tx - clients.tx_bytes as f64);
        Ok(Reconciliation {
            status: if complete {
                "compared"
            } else {
                "incompleteWan"
            },
            complete_wan_hours: hours.len(),
            expected_wan_hours: expected,
            site_rx_bytes: complete.then_some(rx),
            site_tx_bytes: complete.then_some(tx),
            unmatched_rx_bytes: complete.then_some(differences.0),
            unmatched_tx_bytes: complete.then_some(differences.1),
            reason: "Site WAN minus all returned client activity over identical whole-hour boundaries, excluding the bucket at endMs. Differences use the controller's fractional WAN counters and are approximate. A positive difference is unattributed by this report; a negative difference indicates greater attributed usage. Neither identifies the cause or proves complete collection.",
        })
    }
}

fn totals(report: &ActivityReport) -> Result<(Vec<ClientRow>, Bytes, Bytes), McpError> {
    let mut seen = BTreeSet::new();
    let mut clients = Vec::new();
    let mut total = Bytes::default();
    for row in &report.client_usage_by_app {
        if row.usage_by_app.is_empty() {
            return Err(McpError::internal_error(
                "activity client has no reported counters",
                None,
            ));
        }
        let mac = super::normalize_mac(&row.client.mac);
        if !super::is_client_address(&mac) || !seen.insert(mac.clone()) {
            return Err(McpError::internal_error(
                "activity response contains invalid or duplicate client identities",
                None,
            ));
        }
        let bytes = sum(&row.usage_by_app)?;
        add(&mut total, &bytes)?;
        clients.push(ClientRow {
            mac,
            name: row.client.name.clone().map(bounded_text),
            bytes,
        });
    }
    Ok((clients, total, sum(&report.total_usage_by_app)?))
}

fn sum(rows: &[ApplicationActivity]) -> Result<Bytes, McpError> {
    let mut total = Bytes::default();
    let mut seen = BTreeSet::new();
    for row in rows {
        if !seen.insert((row.category, row.application)) {
            return Err(McpError::internal_error(
                "activity response contains duplicate application counters",
                None,
            ));
        }
        add(
            &mut total,
            &Bytes {
                rx_bytes: row.bytes_received,
                tx_bytes: row.bytes_transmitted,
            },
        )?;
    }
    Ok(total)
}

fn add(total: &mut Bytes, value: &Bytes) -> Result<(), McpError> {
    total.rx_bytes = total
        .rx_bytes
        .checked_add(value.rx_bytes)
        .ok_or_else(|| McpError::internal_error("activity byte total overflow", None))?;
    total.tx_bytes = total
        .tx_bytes
        .checked_add(value.tx_bytes)
        .ok_or_else(|| McpError::internal_error("activity byte total overflow", None))?;
    Ok(())
}

fn temporal(read: ActivityRead<Vec<ActivityBucket>>, window: ActivityWindow) -> TemporalEvidence {
    let mut result = TemporalEvidence {
        status: "unavailable",
        source: "v2/app-traffic-rate",
        observed_start_ms: None,
        observed_end_ms: None,
        sample_count: 0,
        bucket_boundary_semantics: "Observed bounds are graph sample timestamps, not proven collection boundaries. Missing timestamps do not establish zero usage.",
        per_client_observed_interval_known: false,
    };
    let rows = match read {
        ActivityRead::Reported(rows) => rows,
        ActivityRead::Unsupported => return result,
        ActivityRead::Unrecognized => {
            result.status = "unrecognized";
            return result;
        }
    };
    let times: BTreeSet<_> = rows
        .into_iter()
        .map(|row| row.timestamp)
        .filter(|time| *time >= window.start && *time <= window.end)
        .collect();
    result.sample_count = times.len();
    result.observed_start_ms = times.first().copied();
    result.observed_end_ms = times.last().copied();
    result.status = if times.is_empty() {
        "empty"
    } else {
        "reported"
    };
    result
}

fn semantics(window: ActivityWindow) -> CounterSemantics {
    CounterSemantics {
        source: "v2/traffic",
        unit: "bytes",
        scope: "Controller Activity view: attributed Internet traffic, including unidentified applications; not exhaustive WAN accounting.",
        direction: "Client perspective: rx/download is received; tx/upload is transmitted.",
        window: "Fixed requested startMs/endMs interval. Aggregate rows do not supply observed timestamps; site graph evidence is separate.",
        reset: "No reset markers supplied; missing collection or retention cannot be reconstructed.",
        requested_start_ms: Some(window.start),
        requested_end_ms: Some(window.end),
    }
}

fn report_name(report: StatsReport) -> &'static str {
    if report == StatsReport::ClientWanHistory {
        "clientWanHistory"
    } else {
        "dpiApplications"
    }
}

fn unavailable(
    report: StatsReport,
    window: ActivityWindow,
    status: CoverageStatus,
) -> Result<CallToolResult, McpError> {
    structured(StatsQueryOutput {
        report: report_name(report),
        coverage: TrafficCoverage {
            status,
            reason: "The controller Activity source is unsupported or unrecognized. No Internet attribution measurements could be established; current connection counters are not a substitute.",
            unrecognized_records: 0,
        },
        counter_semantics: semantics(window),
        total_applications: None,
        wan_hourly: None,
        top_applications: None,
        activity: None,
    })
}
