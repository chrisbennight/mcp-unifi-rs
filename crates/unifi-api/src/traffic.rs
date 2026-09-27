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
    /// Rejects empty, reversed, unaligned, or greater-than-seven-day windows.
    pub fn new(start: u64, end: u64) -> Result<Self, ApiError> {
        if end <= start
            || end - start > 168 * 3_600_000
            || !start.is_multiple_of(3_600_000)
            || !end.is_multiple_of(3_600_000)
        {
            return Err(ApiError::Config(
                "activity window must cover whole UTC hours, from one hour to seven days"
                    .to_owned(),
            ));
        }
        Ok(Self { start, end })
    }
}

/// A source's availability, separate from authentication and transport errors.
#[derive(Debug)]
pub enum ActivityRead<T> {
    Reported(T),
    Unsupported,
    Unrecognized,
}

/// Allowlisted activity totals. The source does not return collection timestamps.
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

/// Stable network identity and a display name; fingerprints are excluded.
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

impl ActivityReport {
    pub(crate) fn validate(&self) -> bool {
        self.client_usage_by_app.len() <= 1000
            && self.total_usage_by_app.len() <= 4096
            && self
                .client_usage_by_app
                .iter()
                .map(|row| row.usage_by_app.len())
                .sum::<usize>()
                <= 20_000
            && self.client_usage_by_app.iter().all(|row| {
                row.client.mac.len() == 17
                    && row
                        .client
                        .name
                        .as_ref()
                        .is_none_or(|name| name.len() <= 4096)
            })
    }
}
