//! Shared safety machinery for write tools.
//!
//! A controller acknowledges writes whose fields it silently discards, so an
//! accepted write proves nothing. Writes therefore preview by default and are
//! judged by reading the resource back.

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Map, Value};

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

/// One requested field and what the read-back found.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldOutcome {
    pub(crate) field: String,
    pub(crate) status: FieldStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) previous: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) requested: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observed: Option<Value>,
}

/// One field a preview would change.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlannedChange {
    pub(crate) field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) from: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) to: Option<Value>,
}

/// What a write would change. A field already holding the requested value is
/// not a change.
pub(crate) fn plan(requested: &Map<String, Value>, current: &Value) -> Vec<PlannedChange> {
    requested
        .iter()
        .filter(|(field, wanted)| current.get(field.as_str()) != Some(*wanted))
        .map(|(field, wanted)| PlannedChange {
            field: field.clone(),
            from: Some(current.get(field.as_str()).cloned().unwrap_or(Value::Null)),
            to: Some(wanted.clone()),
        })
        .collect()
}

/// Classify each requested field by comparing the resource before and after.
pub(crate) fn verify(
    requested: &Map<String, Value>,
    before: &Value,
    after: &Value,
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
            FieldOutcome {
                field: field.clone(),
                status,
                previous: Some(previous.clone()),
                requested: Some(wanted.clone()),
                observed: Some(observed.clone()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{FieldStatus, plan, verify};

    fn fields(value: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().expect("object").clone()
    }

    #[test]
    fn a_plan_lists_only_fields_that_would_move_with_their_values() {
        let current = json!({"enabled": true, "ssid": "Home", "passphrase": "old"});
        let changes = plan(
            &fields(&json!({"enabled": true, "ssid": "House", "passphrase": "new"})),
            &current,
        );
        assert_eq!(changes.len(), 2, "{changes:?}");
        let ssid = changes.iter().find(|c| c.field == "ssid").expect("ssid");
        assert_eq!(ssid.from, Some(json!("Home")));
        assert_eq!(ssid.to, Some(json!("House")));
        let rendered = serde_json::to_string(&changes).expect("serialize");
        assert!(rendered.contains("old"), "{rendered}");
        assert!(rendered.contains("new"), "{rendered}");
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
    fn a_verified_field_carries_the_requested_and_observed_values() {
        let outcomes = verify(
            &fields(&json!({"passphrase": "new-secret"})),
            &json!({"passphrase": "old-secret"}),
            &json!({"passphrase": "new-secret"}),
        );
        assert_eq!(outcomes[0].status, FieldStatus::Persisted);
        let rendered = serde_json::to_string(&outcomes).expect("serialize");
        assert!(rendered.contains("new-secret"), "{rendered}");
    }
}
