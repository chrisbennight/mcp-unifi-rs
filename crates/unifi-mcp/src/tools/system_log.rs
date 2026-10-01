//! Normalization for the Network application system-log API.

use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use unifi_api::{
    ApiError,
    system_log::{SystemLogEntry, SystemLogQuery, SystemLogSeverity},
};

use super::{
    EVENT_MESSAGE_CEILING, EventRow, EventSeverity, MAXIMUM_RESULT_BYTES, McpError, UnifiMcp,
    api_error, bounded_text, current_time_ms, is_client_address, parse, structured,
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct EventsReadInput {
    /// Window start in epoch milliseconds.
    start_ms: u64,
    /// Window end in epoch milliseconds; must be at least startMs.
    end_ms: u64,
    /// Zero-based controller page, including pages beyond the reported total.
    #[serde(default)]
    page: u64,
    /// Rows in one upstream page, 1-1000. Defaults to 100.
    #[serde(default = "default_page_size")]
    page_size: u32,
    severity: Option<EventSeverity>,
}

const fn default_page_size() -> u32 {
    100
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct EventsReadOutput {
    /// Complete original JSON page, including unknown metadata and fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_page: Option<u64>,
    /// A terminal first page contains fewer rows than the controller reports.
    pagination_incomplete: bool,
}

pub(super) async fn read(
    handler: &UnifiMcp,
    params: &CallToolRequestParams,
) -> Result<CallToolResult, McpError> {
    let input = parse::<EventsReadInput>(params)?;
    let mut query = SystemLogQuery::new(input.start_ms, input.end_ms, input.page_size)
        .map_err(api_error)?
        .page(input.page);
    if let Some(severity) = input.severity {
        query = query.severity(match severity {
            EventSeverity::Low => SystemLogSeverity::Low,
            EventSeverity::Medium => SystemLogSeverity::Medium,
            EventSeverity::High => SystemLogSeverity::High,
            EventSeverity::VeryHigh => SystemLogSeverity::VeryHigh,
        });
    }
    let response = handler
        .legacy()
        .system_log_records(handler.legacy_site(), &query)
        .await
        .map_err(api_error)?;
    let total_pages = response["total_page_count"]
        .as_u64()
        .expect("validated page count");
    let next_page = input.page.checked_add(1).filter(|next| *next < total_pages);
    let pagination_incomplete = input.page == 0
        && next_page.is_none()
        && response["total_element_count"]
            .as_u64()
            .expect("validated element count")
            > response["data"].as_array().expect("validated data").len() as u64;
    let text = serde_json::to_string(&response)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let large = text.len() > MAXIMUM_RESULT_BYTES;
    let mut result = structured(EventsReadOutput {
        response: (!large).then_some(response),
        response_in_content: large.then_some(true),
        next_page,
        pagination_incomplete,
    })?;
    if large {
        result
            .content
            .push(ContentBlock::text(format!("response: {text}")));
    }
    Ok(result)
}

pub(super) fn log_window(hours: u32) -> Result<(u64, u64), McpError> {
    let end = current_time_ms()?;
    Ok((end.saturating_sub(u64::from(hours) * 3_600_000), end))
}

pub(super) fn read_error(error: ApiError) -> McpError {
    api_error(error)
}

pub(super) fn event_row(entry: SystemLogEntry) -> EventRow {
    let message = message(&entry);
    EventRow {
        time: entry.timestamp,
        key: entry.key.or(entry.event),
        message,
        category: entry.category,
        severity: entry.severity,
        client_mac: entry
            .parameters
            .client
            .and_then(|client| client.id)
            .filter(|id| is_client_address(id)),
    }
}

/// Substitute only known entity names, in one pass. Inserted text is never
/// interpreted again, and expansion cannot exceed the display ceiling.
fn message(entry: &SystemLogEntry) -> Option<String> {
    let mut rest = entry
        .message_raw
        .as_deref()
        .filter(|text| !text.is_empty())
        .or(entry.title_raw.as_deref())?;
    let parameters = &entry.parameters;
    let entities = [
        ("CLIENT", &parameters.client),
        ("DEVICE", &parameters.device),
        ("DEVICE_FROM", &parameters.device_from),
        ("DEVICE_TO", &parameters.device_to),
        ("WLAN", &parameters.wlan),
        ("NETWORK", &parameters.network),
    ];
    let mut output = String::new();
    while !rest.is_empty() && output.chars().count() <= EVENT_MESSAGE_CEILING {
        let (part, remaining) = if let Some(token) = rest.strip_prefix('{') {
            if let Some(end) = token.find('}') {
                let name = &token[..end];
                let replacement = entities
                    .iter()
                    .find(|(key, _)| *key == name)
                    .and_then(|(_, entity)| entity.as_ref())
                    .and_then(|entity| {
                        entity
                            .name
                            .as_deref()
                            .filter(|name| !name.is_empty())
                            .or(entity.id.as_deref().filter(|id| !id.is_empty()))
                    });
                (replacement.unwrap_or(&rest[..end + 2]), &rest[end + 2..])
            } else {
                (rest, "")
            }
        } else {
            let end = rest.find('{').unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };
        let remaining_characters = EVENT_MESSAGE_CEILING + 1 - output.chars().count();
        output.extend(part.chars().take(remaining_characters));
        rest = remaining;
    }
    Some(bounded_text(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_client_mac_excludes_non_mac_identifiers_without_dropping_events() {
        for (id, expected_mac) in [
            ("aa:bb:cc:dd:ee:01", Some("aa:bb:cc:dd:ee:01")),
            ("AA:BB:CC:DD:EE:01", Some("AA:BB:CC:DD:EE:01")),
            ("vpn:synthetic-client:synthetic-session", None),
            ("aa:bb:cc:dd:ee:01:suffix", None),
            ("00:00:00:00:00:00", None),
            ("ff:ff:ff:ff:ff:ff", None),
            ("", None),
        ] {
            let entry: SystemLogEntry = serde_json::from_value(serde_json::json!({
                "timestamp": 1,
                "key": "CLIENT_CONNECTED",
                "message_raw": "{CLIENT} connected",
                "parameters": {"CLIENT": {"id": id, "name": "test client"}}
            }))
            .unwrap();
            let row = event_row(entry);
            assert_eq!(row.client_mac.as_deref(), expected_mac);
            assert_eq!(row.time, 1);
            assert_eq!(row.key.as_deref(), Some("CLIENT_CONNECTED"));
            assert_eq!(row.message.as_deref(), Some("test client connected"));
        }
    }

    #[test]
    fn message_substitution_preserves_inserted_text_and_signals_truncation() {
        let entry: SystemLogEntry = serde_json::from_value(serde_json::json!({
            "timestamp": 1,
            "message_raw": "{CLIENT} joined {WLAN}; {EXTENSION}",
            "parameters": {"CLIENT": {"name": "{WLAN}"}, "WLAN": {"name": "Guest"},
                "EXTENSION": {"name": "controller-field"}}
        }))
        .unwrap();
        assert_eq!(
            message(&entry).as_deref(),
            Some("{WLAN} joined Guest; {EXTENSION}")
        );
        let mut long = entry;
        long.parameters.client.as_mut().unwrap().name = Some("é".repeat(1000));
        let rendered = message(&long).unwrap();
        assert_eq!(rendered.chars().count(), EVENT_MESSAGE_CEILING);
        assert!(rendered.ends_with('…'));

        long.message_raw = Some(String::new());
        long.title_raw = Some("{DEVICE}".to_owned());
        long.parameters.device = Some(unifi_api::system_log::SystemLogEntity {
            id: Some("device-id".to_owned()),
            name: Some(String::new()),
        });
        assert_eq!(message(&long).as_deref(), Some("device-id"));
    }
}
