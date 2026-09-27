use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use unifi_api::{
    collection::{SourceStatus, TrafficSnapshot, WanReport, activity_totals},
    traffic::ActivityReport,
};

use super::config::CollectionSettings;

/// Immutable records followed by one publication selector. Every query joins on
/// revision; rewriting the selector never exposes stale clients from an old report.
pub(super) struct Publication {
    pub batches: Vec<String>,
    pub marker: String,
    pub records: usize,
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

impl Publication {
    #[expect(
        clippy::too_many_lines,
        reason = "one bounded publication assembles archive and query projections before writes"
    )]
    pub fn build(snapshot: &TrafficSnapshot, identity: &str) -> Result<Self> {
        let bytes = serde_json::to_vec(snapshot)?;
        ensure!(
            bytes.len() <= super::MAX_ARCHIVE_BYTES,
            "collection archive exceeds bound"
        );
        let revision = digest(&bytes);
        let tags = format!("collector={identity},revision={revision}");
        let timestamp = snapshot.start_ms;
        let mut lines = Vec::new();
        // Fixed-size base64 chunks preserve JSON numeric spelling and unknown
        // fields without relying on InfluxDB's numeric or string-size limits.
        let chunks: Vec<_> = bytes.chunks(12_000).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            lines.push(format!(
                "unifi_archive,{tags},part={index} data=\"{}\" {timestamp}\n",
                STANDARD.encode(chunk)
            ));
        }
        let mut summary = format!(
            "start_ms={timestamp}u,end_ms={}u,collected={},archive_parts={}u,schema=1i",
            snapshot.end_ms,
            snapshot.collected(),
            chunks.len()
        );
        for (name, source) in [
            ("activity", &snapshot.activity),
            ("graph", &snapshot.graph),
            ("wan", &snapshot.wan),
        ] {
            let status = serde_json::to_string(&source.status)?;
            write!(summary, ",{name}_status={status}")?;
        }
        let totals = if snapshot.activity.status == SourceStatus::Collected {
            let report: ActivityReport = serde_json::from_str(
                snapshot
                    .activity
                    .data
                    .as_ref()
                    .context("collected source has no data")?
                    .get(),
            )?;
            if let Ok((clients, total, applications)) = activity_totals(&report) {
                write!(
                    summary,
                    ",client_rx_bytes={}u,client_tx_bytes={}u,application_rx_bytes={}u,application_tx_bytes={}u",
                    total.rx_bytes, total.tx_bytes, applications.rx_bytes, applications.tx_bytes
                )?;
                for client in clients {
                    let name = string(&serde_json::to_string(&client.name)?);
                    lines.push(format!("unifi_client,{tags},client={} rx_bytes={}u,tx_bytes={}u,name_json={name} {timestamp}\n", client.mac, client.bytes.rx_bytes, client.bytes.tx_bytes));
                }
                summary.push_str(",totals_status=\"calculated\"");
                Some(total)
            } else {
                summary.push_str(",totals_status=\"invalid_counters\"");
                None
            }
        } else {
            None
        };
        // A retrieved empty or incomplete WAN report is still retained and
        // successfully collected; absent counters do not become invented zeroes.
        if snapshot.wan.status == SourceStatus::Collected {
            let wan: WanReport = serde_json::from_str(
                snapshot
                    .wan
                    .data
                    .as_ref()
                    .context("collected source has no data")?
                    .get(),
            )?;
            let rows: Vec<_> = wan
                .data
                .iter()
                .filter(|row| {
                    row.time
                        .is_some_and(|t| t >= snapshot.start_ms && t < snapshot.end_ms)
                })
                .collect();
            if let [row] = rows.as_slice()
                && row.time == Some(snapshot.start_ms)
                && let (Some(rx), Some(tx)) = (row.wan_rx_bytes, row.wan_tx_bytes)
                && rx.is_finite()
                && tx.is_finite()
                && rx >= 0.0
                && tx >= 0.0
            {
                write!(summary, ",site_rx_bytes={rx},site_tx_bytes={tx}")?;
                if let Some(total) = totals {
                    #[allow(clippy::cast_precision_loss)]
                    let (rx_diff, tx_diff) =
                        (rx - total.rx_bytes as f64, tx - total.tx_bytes as f64);
                    write!(
                        summary,
                        ",unmatched_rx_bytes={rx_diff},unmatched_tx_bytes={tx_diff}"
                    )?;
                }
            }
        }
        lines.push(format!("unifi_interval,{tags} {summary} {timestamp}\n"));
        let records = lines.len();
        let mut batches = Vec::new();
        let mut batch = String::new();
        for line in lines {
            ensure!(line.len() <= 64 * 1024, "collection line exceeds bound");
            if batch.len() + line.len() > 256 * 1024 {
                batches.push(std::mem::take(&mut batch));
            }
            batch.push_str(&line);
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        ensure!(
            batches.len() <= 256,
            "collection publication exceeds request bound"
        );
        Ok(Self {
            batches,
            marker: format!(
                "unifi_publication,collector={identity} revision=\"{revision}\" {timestamp}\n"
            ),
            records,
        })
    }
}

pub(super) struct InfluxSink {
    client: reqwest::Client,
    url: url::Url,
    token: zeroize::Zeroizing<String>,
}

impl InfluxSink {
    pub fn new(settings: &CollectionSettings) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        let mut url = settings.url.join("api/v2/write")?;
        url.query_pairs_mut()
            .append_pair("org", &settings.org)
            .append_pair("bucket", &settings.bucket)
            .append_pair("precision", "ms");
        Ok(Self {
            client,
            url,
            token: settings.token.clone(),
        })
    }

    async fn write(&self, body: &str) -> Result<()> {
        let response = self
            .client
            .post(self.url.clone())
            .header("Authorization", format!("Token {}", self.token.as_str()))
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(body.to_owned())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("sink_transport"))?;
        // OSS 2.x acknowledges synchronous writes with 204. Do not consume or
        // log its response body: it can echo rejected traffic or credentials.
        ensure!(
            response.status() == reqwest::StatusCode::NO_CONTENT,
            "sink_rejected"
        );
        Ok(())
    }

    pub async fn publish(&self, publication: &Publication) -> Result<()> {
        for batch in &publication.batches {
            self.write(batch).await?;
        }
        self.write(&publication.marker).await
    }
}
