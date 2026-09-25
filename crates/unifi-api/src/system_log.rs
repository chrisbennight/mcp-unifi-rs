//! Typed system-log reads for the Network 10.6.106 application API.

use serde::{Deserialize, Serialize};

use crate::ApiError;

const MAXIMUM_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAXIMUM_PAGE_SIZE: u32 = 1000;

/// Controller-defined severity, used only as a bounded upstream filter.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SystemLogSeverity {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// The first bounded page of system logs in an explicit time window.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemLogQuery {
    timestamp_from: u64,
    timestamp_to: u64,
    page_number: u32,
    page_size: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    severities: Vec<SystemLogSeverity>,
}

impl SystemLogQuery {
    /// Validate the complete time window and row bound before any request.
    ///
    /// # Errors
    /// Returns a configuration error for an inverted window, a window over
    /// seven days, or a page size outside 1-1000.
    pub fn new(start: u64, end: u64, limit: u32) -> Result<Self, ApiError> {
        if start > end || end - start > MAXIMUM_WINDOW_MS {
            return Err(ApiError::Config(
                "system log window must be ordered and no longer than seven days".to_owned(),
            ));
        }
        if !(1..=MAXIMUM_PAGE_SIZE).contains(&limit) {
            return Err(ApiError::Config(
                "system log page size must be between 1 and 1000".to_owned(),
            ));
        }
        Ok(Self {
            timestamp_from: start,
            timestamp_to: end,
            page_number: 0,
            page_size: limit,
            severities: Vec::new(),
        })
    }

    /// Restrict the query to one severity.
    #[must_use]
    pub fn severity(mut self, severity: SystemLogSeverity) -> Self {
        self.severities = vec![severity];
        self
    }

    /// Restrict the query to the controller's two highest severities.
    #[must_use]
    pub fn high_severity(mut self) -> Self {
        self.severities = vec![SystemLogSeverity::High, SystemLogSeverity::VeryHigh];
        self
    }

    pub(crate) fn validate_response(&self, page: &SystemLogPage) -> Result<(), ApiError> {
        let rows = page.data.len() as u64;
        if page.page_number != self.page_number
            || rows > u64::from(self.page_size)
            || page.total_element_count < rows
            || (rows == 0 && page.total_element_count != 0)
            || (rows != 0 && page.total_page_count == 0)
        {
            return Err(ApiError::Decode(
                "system log pagination did not match the requested page".into(),
            ));
        }
        Ok(())
    }
}

/// One page with controller-reported totals; never an implicit complete list.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemLogPage {
    pub data: Vec<SystemLogEntry>,
    pub page_number: u32,
    pub total_element_count: u64,
    pub total_page_count: u64,
}

impl SystemLogPage {
    /// Whether the controller reports rows beyond the bounded first page.
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.total_element_count > self.data.len() as u64
    }
}

/// Allowlisted Network system-log fields. Unknown properties are discarded.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemLogEntry {
    pub key: Option<String>,
    pub event: Option<String>,
    /// Epoch milliseconds.
    pub timestamp: u64,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub message_raw: Option<String>,
    pub title_raw: Option<String>,
    #[serde(default)]
    pub parameters: SystemLogParameters,
}

/// Only the entity fields needed to describe an event or match its client.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct SystemLogParameters {
    pub client: Option<SystemLogEntity>,
    pub device: Option<SystemLogEntity>,
    pub device_from: Option<SystemLogEntity>,
    pub device_to: Option<SystemLogEntity>,
    pub wlan: Option<SystemLogEntity>,
    pub network: Option<SystemLogEntity>,
}

/// Controller-supplied identity; names and identifiers are untrusted text.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemLogEntity {
    pub id: Option<String>,
    pub name: Option<String>,
}
