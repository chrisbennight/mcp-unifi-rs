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
        let mut end = text.len().min(MAXIMUM_UNRECOGNIZED_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self::Unrecognized(text[..end].to_owned())
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
    pub port_idx: Option<u32>,
    pub name: Option<String>,
    /// Connector family such as `GE`, `SFP`, or `SFP+`.
    pub media: Option<String>,
    pub up: Option<bool>,
    pub enable: Option<bool>,
    /// Negotiated speed in Mbps.
    pub speed: Option<u32>,
    pub full_duplex: Option<bool>,
    pub is_uplink: Option<bool>,
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
    pub rx_dropped: Option<u64>,
    pub tx_dropped: Option<u64>,
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
        [
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
    use super::{Reading, SwitchPortReport};
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
                assert!(text.len() <= 64 && !text.is_empty() && long.starts_with(&text));
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
}
