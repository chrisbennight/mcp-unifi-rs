//! Per-port link, counter, `PoE`, and optical-module records from the legacy
//! device statistics read.
//!
//! The controller reports many measurements on this route as decimal strings
//! (for example `"-3.59"` for a received light level). A [`Reading`] keeps
//! three outcomes distinct: the device did not report the value, it reported a
//! number, or it reported text this crate does not recognize. An unreported
//! value is never turned into zero.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Longest unrecognized wire text retained for diagnosis.
const MAXIMUM_UNRECOGNIZED_BYTES: usize = 64;
const TRUNCATION_MARKER: &str = " [truncated]";

/// One numeric measurement as the controller reported it.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Reading {
    /// Missing, null, or an empty string: the device did not report it.
    #[default]
    Absent,
    /// A finite number.
    Value(f64),
    /// Present but not a finite number. The text is truncated to a bound.
    Unrecognized(String),
}

impl Reading {
    /// The number, when one was reported.
    #[must_use]
    pub fn value(&self) -> Option<f64> {
        match self {
            Self::Value(value) => Some(*value),
            Self::Absent | Self::Unrecognized(_) => None,
        }
    }

    fn from_json(value: &Value) -> Self {
        match value {
            Value::Null => Self::Absent,
            Value::Number(number) => number
                .as_f64()
                .filter(|parsed| parsed.is_finite())
                .map_or_else(|| Self::unrecognized(&number.to_string()), Self::Value),
            Value::String(text) => {
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    Self::Absent
                } else {
                    trimmed
                        .parse::<f64>()
                        .ok()
                        .filter(|parsed| parsed.is_finite())
                        .map_or_else(|| Self::unrecognized(trimmed), Self::Value)
                }
            }
            other => Self::unrecognized(&other.to_string()),
        }
    }

    fn unrecognized(text: &str) -> Self {
        Self::Unrecognized(bounded_text(text))
    }
}

/// Keep at most [`MAXIMUM_UNRECOGNIZED_BYTES`] of the wire text and mark any
/// cut, so a prefix is never mistaken for the complete value.
fn bounded_text(text: &str) -> String {
    if text.len() <= MAXIMUM_UNRECOGNIZED_BYTES {
        return text.to_owned();
    }
    let mut end = MAXIMUM_UNRECOGNIZED_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATION_MARKER}", &text[..end])
}

/// One whole-number counter or speed as the controller reported it. It keeps
/// the same three outcomes as [`Reading`] so one malformed value cannot fail
/// the decoding of every other port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Count {
    /// Missing, null, or an empty string: the device did not report it.
    #[default]
    Absent,
    /// A non-negative whole number.
    Value(u64),
    /// Present but not a non-negative whole number. The text is bounded.
    Unrecognized(String),
}

impl Count {
    /// The number, when one was reported.
    #[must_use]
    pub fn value(&self) -> Option<u64> {
        match self {
            Self::Value(value) => Some(*value),
            Self::Absent | Self::Unrecognized(_) => None,
        }
    }

    fn from_json(value: &Value) -> Self {
        match value {
            Value::Null => Self::Absent,
            Value::Number(number) => number
                .as_u64()
                .or_else(|| number.as_f64().and_then(whole_number))
                .map_or_else(
                    || Self::Unrecognized(bounded_text(&number.to_string())),
                    Self::Value,
                ),
            Value::String(text) => {
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    Self::Absent
                } else {
                    whole_number_text(trimmed)
                        .map_or_else(|| Self::Unrecognized(bounded_text(trimmed)), Self::Value)
                }
            }
            other => Self::Unrecognized(bounded_text(&other.to_string())),
        }
    }
}

/// A non-negative whole number written as a decimal, such as `3.0`. Beyond
/// 2^53 an `f64` no longer holds every integer, so those stay unrecognized.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is checked to be a non-negative whole number no larger than 2^53"
)]
fn whole_number(parsed: f64) -> Option<u64> {
    const LARGEST_EXACT: f64 = 9_007_199_254_740_992.0;
    (parsed.is_finite() && parsed >= 0.0 && parsed.fract() == 0.0 && parsed <= LARGEST_EXACT)
        .then_some(parsed as u64)
}

/// A whole number written as text, optionally with a zero-only fractional
/// part such as `3.0`. The text is matched exactly, never rounded through a
/// float, so `0.99999999999999999` stays unrecognized.
fn whole_number_text(text: &str) -> Option<u64> {
    let whole = match text.split_once('.') {
        None => text,
        Some((whole, zeros)) if !zeros.is_empty() && zeros.bytes().all(|byte| byte == b'0') => {
            whole
        }
        Some(_) => return None,
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    whole.parse().ok()
}

impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(deserializer)?))
    }
}

impl<'de> Deserialize<'de> for Reading {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(deserializer)?))
    }
}

/// One port from the device's `port_table`. Legacy API fields are
/// `snake_case` on the wire. Every value is controller-reported and untrusted.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SwitchPort {
    #[serde(default)]
    pub port_idx: Count,
    pub name: Option<String>,
    /// Connector family such as `GE`, `SFP`, or `SFP+`.
    pub media: Option<String>,
    pub up: Option<bool>,
    pub enable: Option<bool>,
    /// Negotiated speed in Mbps.
    #[serde(default)]
    pub speed: Count,
    pub full_duplex: Option<bool>,
    pub is_uplink: Option<bool>,
    #[serde(default)]
    pub rx_errors: Count,
    #[serde(default)]
    pub tx_errors: Count,
    #[serde(default)]
    pub rx_dropped: Count,
    #[serde(default)]
    pub tx_dropped: Count,
    /// Whether the port hardware can deliver `PoE`.
    pub port_poe: Option<bool>,
    pub poe_enable: Option<bool>,
    pub poe_good: Option<bool>,
    pub poe_mode: Option<String>,
    pub poe_class: Option<String>,
    /// Watts.
    #[serde(default)]
    pub poe_power: Reading,
    /// Volts.
    #[serde(default)]
    pub poe_voltage: Reading,
    /// Milliamps.
    #[serde(default)]
    pub poe_current: Reading,
    pub sfp_found: Option<bool>,
    pub sfp_vendor: Option<String>,
    pub sfp_part: Option<String>,
    pub sfp_serial: Option<String>,
    pub sfp_rev: Option<String>,
    pub sfp_compliance: Option<String>,
    pub sfp_rxfault: Option<bool>,
    pub sfp_txfault: Option<bool>,
    /// Received optical power in dBm.
    #[serde(default)]
    pub sfp_rxpower: Reading,
    /// Transmitted optical power in dBm.
    #[serde(default)]
    pub sfp_txpower: Reading,
    /// Module temperature in degrees Celsius.
    #[serde(default)]
    pub sfp_temperature: Reading,
    /// Module supply voltage in volts.
    #[serde(default)]
    pub sfp_voltage: Reading,
    /// Transmit bias current in milliamps.
    #[serde(default)]
    pub sfp_current: Reading,
}

impl SwitchPort {
    /// Names of the numeric fields whose wire value was present but not a
    /// number, paired with the retained text.
    #[must_use]
    pub fn unrecognized_readings(&self) -> BTreeMap<&'static str, &str> {
        let counts = [
            ("port_idx", &self.port_idx),
            ("speed", &self.speed),
            ("rx_errors", &self.rx_errors),
            ("tx_errors", &self.tx_errors),
            ("rx_dropped", &self.rx_dropped),
            ("tx_dropped", &self.tx_dropped),
        ]
        .into_iter()
        .filter_map(|(name, count)| match count {
            Count::Unrecognized(text) => Some((name, text.as_str())),
            Count::Absent | Count::Value(_) => None,
        });
        let readings = [
            ("poe_power", &self.poe_power),
            ("poe_voltage", &self.poe_voltage),
            ("poe_current", &self.poe_current),
            ("sfp_rxpower", &self.sfp_rxpower),
            ("sfp_txpower", &self.sfp_txpower),
            ("sfp_temperature", &self.sfp_temperature),
            ("sfp_voltage", &self.sfp_voltage),
            ("sfp_current", &self.sfp_current),
        ]
        .into_iter()
        .filter_map(|(name, reading)| match reading {
            Reading::Unrecognized(text) => Some((name, text.as_str())),
            Reading::Absent | Reading::Value(_) => None,
        });
        counts.chain(readings).collect()
    }
}

impl SwitchPortReport {
    /// Device-level `PoE` figures whose wire value was present but not a
    /// number, paired with the retained text.
    #[must_use]
    pub fn unrecognized_readings(&self) -> BTreeMap<&'static str, &str> {
        [
            ("total_max_power", &self.total_max_power),
            ("total_max_effective_power", &self.total_max_effective_power),
            ("total_used_power", &self.total_used_power),
        ]
        .into_iter()
        .filter_map(|(name, reading)| match reading {
            Reading::Unrecognized(text) => Some((name, text.as_str())),
            Reading::Absent | Reading::Value(_) => None,
        })
        .collect()
    }
}

/// One device record from the legacy device statistics read, reduced to the
/// identity and port fields this crate exposes.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SwitchPortReport {
    pub mac: Option<String>,
    pub name: Option<String>,
    pub model: Option<String>,
    /// Controller device family such as `usw`, `udm`, or `uap`.
    #[serde(rename = "type")]
    pub device_type: Option<String>,
    /// Total `PoE` budget in watts.
    #[serde(default)]
    pub total_max_power: Reading,
    /// Budget in watts after the device's own limits are applied.
    #[serde(default)]
    pub total_max_effective_power: Reading,
    /// Total `PoE` power currently delivered, in watts.
    #[serde(default)]
    pub total_used_power: Reading,
    #[serde(default)]
    pub port_table: Vec<SwitchPort>,
}

#[cfg(test)]
mod tests {
    use super::{Count, Reading, SwitchPortReport};
    use serde_json::json;

    #[test]
    fn readings_distinguish_absent_numeric_and_unrecognized_values() {
        let report: SwitchPortReport = serde_json::from_value(json!({
            "port_table": [{
                "port_idx": 1,
                "sfp_rxpower": "-3.59",
                "sfp_txpower": "",
                "sfp_temperature": 40.5,
                "sfp_voltage": "n/a",
                "poe_power": null
            }]
        }))
        .expect("report");
        let port = &report.port_table[0];
        assert_eq!(port.sfp_rxpower, Reading::Value(-3.59));
        assert_eq!(port.sfp_txpower, Reading::Absent);
        assert_eq!(port.sfp_temperature, Reading::Value(40.5));
        assert_eq!(port.sfp_voltage, Reading::Unrecognized("n/a".to_owned()));
        assert_eq!(port.sfp_current, Reading::Absent);
        assert_eq!(port.poe_power, Reading::Absent);
        assert_eq!(
            port.unrecognized_readings().get("sfp_voltage"),
            Some(&"n/a")
        );
    }

    #[test]
    fn unrecognized_text_is_bounded_on_a_character_boundary() {
        let long = "é".repeat(100);
        let report: SwitchPortReport =
            serde_json::from_value(json!({"total_used_power": long})).expect("report");
        match report.total_used_power {
            Reading::Unrecognized(text) => {
                assert!(text.ends_with(" [truncated]"), "{text}");
                assert!(long.starts_with(text.trim_end_matches(" [truncated]")));
            }
            other => panic!("expected unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn non_finite_numbers_are_unrecognized() {
        let report: SwitchPortReport =
            serde_json::from_value(json!({"total_max_power": "NaN", "total_used_power": "inf"}))
                .expect("report");
        assert!(matches!(report.total_max_power, Reading::Unrecognized(_)));
        assert!(matches!(report.total_used_power, Reading::Unrecognized(_)));
    }

    #[test]
    fn counts_tolerate_text_without_failing_the_whole_report() {
        let report: SwitchPortReport = serde_json::from_value(json!({
            "port_table": [
                {"port_idx": 1, "speed": "1000", "rx_errors": "n/a", "tx_errors": "",
                 "rx_dropped": -1, "tx_dropped": 7},
                {"port_idx": 2, "speed": 2500}
            ]
        }))
        .expect("one malformed counter must not fail the report");
        let first = &report.port_table[0];
        assert_eq!(first.speed, Count::Value(1000));
        assert_eq!(first.rx_errors, Count::Unrecognized("n/a".to_owned()));
        assert_eq!(first.tx_errors, Count::Absent);
        assert_eq!(first.rx_dropped, Count::Unrecognized("-1".to_owned()));
        assert_eq!(first.tx_dropped, Count::Value(7));
        assert_eq!(first.unrecognized_readings().len(), 2);
        assert_eq!(report.port_table[1].speed, Count::Value(2500));
    }

    #[test]
    fn whole_numbers_written_as_decimals_are_counts() {
        let report: SwitchPortReport = serde_json::from_value(json!({
            "port_table": [{"speed": 1000.0, "rx_errors": "3.000", "tx_errors": 2.5,
                            "rx_dropped": "0.99999999999999999", "tx_dropped": "1e3"}]
        }))
        .expect("report");
        let port = &report.port_table[0];
        assert_eq!(port.speed, Count::Value(1000));
        assert_eq!(port.rx_errors, Count::Value(3));
        assert_eq!(port.tx_errors, Count::Unrecognized("2.5".to_owned()));
        // Text is matched exactly and never rounded through a float.
        assert_eq!(
            port.rx_dropped,
            Count::Unrecognized("0.99999999999999999".to_owned())
        );
        assert_eq!(port.tx_dropped, Count::Unrecognized("1e3".to_owned()));
    }

    #[test]
    fn device_level_totals_report_unrecognized_text() {
        let report: SwitchPortReport =
            serde_json::from_value(json!({"total_used_power": "n/a", "total_max_power": 95}))
                .expect("report");
        let unrecognized = report.unrecognized_readings();
        assert_eq!(unrecognized.get("total_used_power"), Some(&"n/a"));
        assert!(!unrecognized.contains_key("total_max_power"));
    }
}
