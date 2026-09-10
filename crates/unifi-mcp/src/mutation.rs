//! Shared safety machinery for write tools.
//!
//! A controller acknowledges writes whose fields it silently discards, so an
//! accepted write proves nothing. Writes therefore preview by default and are
//! judged by reading the resource back.

use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Map, Value};

/// The marker a read substitutes for secret material.
pub(crate) const REDACTION_MARKER: &str = "[redacted]";

/// Whether substituting this value would reintroduce it.
///
/// Scrubbing replaces a secret with the marker, and the result is withheld if
/// any secret survives that pass. A secret which is itself part of the marker
/// therefore survives its own replacement, and no substitution scheme fixes
/// that — the value is unreturnable in every result that mentions it. Such a
/// value is refused when configuration is read, so the failure is a startup
/// error rather than a withheld response over an irreversible write.
#[must_use]
pub fn survives_its_own_redaction(value: &str) -> bool {
    !value.is_empty() && REDACTION_MARKER.contains(value)
}

/// What the controller did with one requested field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum FieldStatus {
    /// The resource now holds the requested value.
    Persisted,
    /// The resource still holds its previous value: the write was accepted
    /// and this field discarded.
    Dropped,
    /// The resource holds a third value: the controller rewrote the input.
    Coerced,
}

/// One requested field and what the read-back found. A secret field reports
/// its status and neither value.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldOutcome {
    pub(crate) field: String,
    pub(crate) status: FieldStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) requested: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observed: Option<Value>,
}

/// One field a preview would change. A secret field names itself only.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlannedChange {
    pub(crate) field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) from: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) to: Option<Value>,
}

/// Refuse a write whose values carry the redaction marker, so a redacted read
/// cannot be written back over the secret it stands for.
pub(crate) fn reject_redacted_input(arguments: &Value) -> Result<(), McpError> {
    if carries_marker(arguments) {
        return Err(McpError::invalid_params(
            format!(
                "a value contains the redaction marker {REDACTION_MARKER}; \
                 state the intended value or omit the field"
            ),
            None,
        ));
    }
    Ok(())
}

fn carries_marker(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains(REDACTION_MARKER),
        Value::Array(items) => items.iter().any(carries_marker),
        Value::Object(map) => map.values().any(carries_marker),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// What a write would change. A field already holding the requested value is
/// not a change.
pub(crate) fn plan(
    requested: &Map<String, Value>,
    current: &Value,
    secrets: &[&str],
) -> Vec<PlannedChange> {
    requested
        .iter()
        .filter(|(field, wanted)| current.get(field.as_str()) != Some(*wanted))
        .map(|(field, wanted)| {
            let visible = !secrets.contains(&field.as_str());
            PlannedChange {
                field: field.clone(),
                from: visible.then(|| current.get(field.as_str()).cloned().unwrap_or(Value::Null)),
                to: visible.then(|| wanted.clone()),
            }
        })
        .collect()
}

/// Classify each requested field by comparing the resource before and after.
pub(crate) fn verify(
    requested: &Map<String, Value>,
    before: &Value,
    after: &Value,
    secrets: &[&str],
) -> Vec<FieldOutcome> {
    requested
        .iter()
        .map(|(field, wanted)| {
            let observed = after.get(field.as_str()).unwrap_or(&Value::Null);
            let previous = before.get(field.as_str()).unwrap_or(&Value::Null);
            let status = if observed == wanted {
                FieldStatus::Persisted
            } else if observed == previous {
                FieldStatus::Dropped
            } else {
                FieldStatus::Coerced
            };
            let visible = !secrets.contains(&field.as_str());
            FieldOutcome {
                field: field.clone(),
                status,
                requested: visible.then(|| wanted.clone()),
                observed: visible.then(|| observed.clone()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{FieldStatus, REDACTION_MARKER, plan, reject_redacted_input, verify};

    fn fields(value: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().expect("object").clone()
    }

    #[test]
    fn a_write_echoing_a_redacted_read_is_refused_wherever_the_marker_sits() {
        for arguments in [
            json!({"passphrase": REDACTION_MARKER}),
            json!({"nested": {"passphrase": REDACTION_MARKER}}),
            json!({"list": [{"passphrase": format!("prefix{REDACTION_MARKER}")}]}),
        ] {
            reject_redacted_input(&arguments).expect_err("marker must be refused");
        }
        reject_redacted_input(&json!({"name": "redacted guests"})).expect("unrelated text");
    }

    #[test]
    fn a_plan_lists_only_fields_that_would_move_and_hides_secret_values() {
        let current = json!({"enabled": true, "ssid": "Home", "passphrase": "old"});
        let changes = plan(
            &fields(&json!({"enabled": true, "ssid": "House", "passphrase": "new"})),
            &current,
            &["passphrase"],
        );
        assert_eq!(changes.len(), 2, "{changes:?}");
        let ssid = changes.iter().find(|c| c.field == "ssid").expect("ssid");
        assert_eq!(ssid.from, Some(json!("Home")));
        assert_eq!(ssid.to, Some(json!("House")));
        let rendered = serde_json::to_string(&changes).expect("serialize");
        assert!(!rendered.contains("old"), "{rendered}");
        assert!(!rendered.contains("new"), "{rendered}");
    }

    #[test]
    fn read_back_separates_persisted_from_dropped_and_coerced() {
        let before = json!({"ssid": "Home", "enabled": true, "security": "open"});
        // Kept the rename, ignored the disable, rewrote the security mode.
        let after = json!({"ssid": "House", "enabled": true, "security": "wpapsk"});
        let outcomes = verify(
            &fields(&json!({"ssid": "House", "enabled": false, "security": "wpa3"})),
            &before,
            &after,
            &[],
        );
        let status = |field: &str| {
            outcomes
                .iter()
                .find(|entry| entry.field == field)
                .unwrap_or_else(|| panic!("{field} missing"))
                .status
        };
        assert_eq!(status("ssid"), FieldStatus::Persisted);
        assert_eq!(status("enabled"), FieldStatus::Dropped);
        assert_eq!(status("security"), FieldStatus::Coerced);
    }

    #[test]
    fn a_verified_secret_field_carries_its_status_and_neither_value() {
        let outcomes = verify(
            &fields(&json!({"passphrase": "new-secret"})),
            &json!({"passphrase": "old-secret"}),
            &json!({"passphrase": "new-secret"}),
            &["passphrase"],
        );
        assert_eq!(outcomes[0].status, FieldStatus::Persisted);
        let rendered = serde_json::to_string(&outcomes).expect("serialize");
        assert!(!rendered.contains("new-secret"), "{rendered}");
        assert!(!rendered.contains("old-secret"), "{rendered}");
    }
}
