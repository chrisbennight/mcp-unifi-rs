//! Traffic coverage and source semantics shared by the client and stats tools.

use schemars::JsonSchema;
use serde::Serialize;
use unifi_api::models::ActiveClient;

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum CoverageStatus {
    Reported,
    Partial,
    Empty,
    Unrecognized,
    Unsupported,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct TrafficCoverage {
    pub status: CoverageStatus,
    pub reason: &'static str,
    /// Records excluded because their shape or required counters were unknown.
    pub unrecognized_records: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct CounterSemantics {
    pub source: &'static str,
    pub unit: &'static str,
    pub scope: &'static str,
    pub direction: &'static str,
    pub window: &'static str,
    pub reset: &'static str,
    /// Requested report boundaries, not a promise of complete upstream coverage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_start_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_end_ms: Option<u64>,
}

impl CounterSemantics {
    pub(super) fn client() -> Self {
        Self {
            source: "stat/sta",
            unit: "bytes",
            scope: "Client connection counters; LAN versus WAN is not distinguished.",
            direction: "Controller-reported rx/tx; client upload/download orientation is unverified.",
            window: "No common measurement window; association uptime does not establish counter start.",
            reset: "Not supplied by this source; do not assume lifetime or monthly totals.",
            requested_start_ms: None,
            requested_end_ms: None,
        }
    }

    pub(super) fn dpi() -> Self {
        Self {
            source: "stat/sitedpi",
            unit: "bytes",
            scope: "Site application counters; completeness and WAN-only scope are unverified.",
            direction: "Controller-reported rx/tx; upload/download orientation is unverified.",
            window: "Not supplied by this source; not comparable to a chosen WAN report window.",
            reset: "Not supplied by this source; do not assume lifetime or monthly totals.",
            requested_start_ms: None,
            requested_end_ms: None,
        }
    }

    pub(super) fn wan(start: u64, end: u64) -> Self {
        Self {
            source: "stat/report/hourly.site",
            unit: "bytes",
            scope: "Site WAN totals, without per-client attribution.",
            direction: "WAN interface: rx is received, tx is transmitted.",
            window: "Hourly controller buckets; edge buckets may be partial and missing hours are unknown.",
            reset: "Hourly report buckets; underlying counter resets are not supplied.",
            requested_start_ms: Some(start),
            requested_end_ms: Some(end),
        }
    }

    pub(super) fn unavailable_client_wan(start: u64, end: u64) -> Self {
        Self {
            source: "none",
            scope: "Requested per-client WAN-only history; no measurements available.",
            direction: "No per-client WAN counters available.",
            window: "Requested window only; no measurement window is established.",
            reset: "Unknown; no verified source.",
            ..Self::wan(start, end)
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClientCounterCoverage {
    pub status: CoverageStatus,
    /// Selected upstream field pair. Missing members remain missing.
    pub fields: &'static str,
}

pub(super) fn client_counters(
    client: &ActiveClient,
) -> (Option<u64>, Option<u64>, ClientCounterCoverage) {
    // Never combine fields from different counter families: they may reset
    // independently. Prefer a reported wired pair only for known wired clients.
    let (tx, rx, fields) = if client.is_wired == Some(true)
        && (client.wired_tx_bytes.is_some() || client.wired_rx_bytes.is_some())
    {
        (
            client.wired_tx_bytes,
            client.wired_rx_bytes,
            "wired-tx_bytes, wired-rx_bytes",
        )
    } else {
        (client.tx_bytes, client.rx_bytes, "tx_bytes, rx_bytes")
    };
    let status = match (tx, rx) {
        (Some(_), Some(_)) => CoverageStatus::Reported,
        (None, None) => CoverageStatus::Unavailable,
        _ => CoverageStatus::Partial,
    };
    (tx, rx, ClientCounterCoverage { status, fields })
}
