//! Normalization for the Network application system-log API.

use unifi_api::{ApiError, system_log::SystemLogEntry};

use super::{EVENT_MESSAGE_CEILING, EventRow, McpError, api_error, bounded_text, current_time_ms};

pub(super) fn log_window(hours: u32) -> Result<(u64, u64), McpError> {
    let end = current_time_ms()?;
    Ok((end.saturating_sub(u64::from(hours) * 3_600_000), end))
}

pub(super) fn read_error(error: ApiError) -> McpError {
    let mut error = api_error(error);
    error.message = format!("Network system-log read failed: {}", error.message).into();
    error
}

pub(super) fn event_row(entry: SystemLogEntry) -> EventRow {
    let message = message(&entry);
    EventRow {
        time: entry.timestamp,
        key: entry.key.or(entry.event),
        message,
        category: entry.category,
        severity: entry.severity,
        client_mac: entry.parameters.client.and_then(|client| client.id),
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
    fn message_substitution_is_literal_allowlisted_and_bounded() {
        let entry: SystemLogEntry = serde_json::from_value(serde_json::json!({
            "timestamp": 1,
            "message_raw": "{CLIENT} joined {WLAN}; {PASSWORD}",
            "parameters": {"CLIENT": {"name": "{WLAN}"}, "WLAN": {"name": "Guest"},
                "PASSWORD": {"name": "secret"}}
        }))
        .unwrap();
        assert_eq!(
            message(&entry).as_deref(),
            Some("{WLAN} joined Guest; {PASSWORD}")
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
