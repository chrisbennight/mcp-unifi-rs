//! Internet activity reported by the Network application's Activity view.

use serde::Deserialize;

use crate::ApiError;

/// A fixed, bounded reporting window, in epoch milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct ActivityWindow {
    pub start: u64,
    pub end: u64,
}

impl ActivityWindow {
    /// # Errors
    /// Rejects empty, reversed or unaligned windows.
    pub fn new(start: u64, end: u64) -> Result<Self, ApiError> {
        if end <= start || !start.is_multiple_of(3_600_000) || !end.is_multiple_of(3_600_000) {
            return Err(ApiError::Config(
                "activity window must cover ordered whole UTC hours".to_owned(),
            ));
        }
        Ok(Self { start, end })
    }
}

/// A source's availability, separate from authentication and transport errors.
#[derive(Debug)]
pub enum ActivityRead<T> {
    Reported(T),
    Unsupported { response: Option<ApiError> },
    Unrecognized,
}

/// Activity counters used by the compact summary. The source does not return collection timestamps.
#[derive(Debug, Deserialize)]
pub struct ActivityReport {
    pub client_usage_by_app: Vec<ClientActivity>,
    pub total_usage_by_app: Vec<ApplicationActivity>,
}

/// One client and its application counters over the requested interval.
#[derive(Debug, Deserialize)]
pub struct ClientActivity {
    pub client: ActivityClient,
    pub usage_by_app: Vec<ApplicationActivity>,
}

/// Client identity and display name used by the activity summary.
#[derive(Debug, Deserialize)]
pub struct ActivityClient {
    pub mac: String,
    pub name: Option<String>,
}

/// The Activity view labels received bytes as download and transmitted as upload.
#[derive(Debug, Deserialize)]
pub struct ApplicationActivity {
    pub application: u16,
    pub category: u16,
    pub bytes_received: u64,
    pub bytes_transmitted: u64,
}

/// Observed activity graph bucket. Rates are rounded and are not byte totals.
#[derive(Debug, Deserialize)]
pub struct ActivityBucket {
    pub timestamp: u64,
    pub interval_seconds: u32,
}

/// Official DPI reference name, identified by its catalog ID.
#[derive(Debug, Deserialize)]
pub struct DpiName {
    pub id: u32,
    pub name: String,
}
