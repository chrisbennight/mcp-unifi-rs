//! Lossless traffic-report records for operator-owned storage, never MCP output.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// The collection projection requires an explicit data array. Absence is an
/// unrecognized response, not a successful empty report.
#[derive(Deserialize)]
pub struct WanReport {
    pub meta: WanMeta,
    pub data: Vec<crate::models::SiteWanSample>,
}

#[derive(Deserialize)]
pub struct WanMeta {
    pub rc: String,
}

/// One complete response from a fixed traffic-report source. No Debug implementation:
/// the archive contains complete report data and must not enter diagnostic logs.
#[derive(Serialize, Deserialize)]
pub struct SourceReport {
    pub status: SourceStatus,
    pub data: Option<Box<RawValue>>,
}

/// Concrete retrieval outcomes, independent of controller accounting differences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Collected,
    Unsupported,
    Unrecognized,
    Failed,
}

/// Reports over identical requested boundaries, including all original JSON fields.
#[derive(Serialize, Deserialize)]
pub struct TrafficSnapshot {
    pub start_ms: u64,
    pub end_ms: u64,
    pub activity: SourceReport,
    pub graph: SourceReport,
    pub wan: SourceReport,
}

impl TrafficSnapshot {
    #[must_use]
    pub fn collected(&self) -> bool {
        [&self.activity, &self.graph, &self.wan]
            .iter()
            .all(|source| source.status == SourceStatus::Collected)
    }
}

mod totals;
pub use totals::{Bytes, ClientRow, activity_totals};
