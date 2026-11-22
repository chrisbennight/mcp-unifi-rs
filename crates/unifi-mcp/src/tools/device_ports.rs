//! Per-port link, counter, `PoE`, and optical-module diagnostics for one
//! switch or gateway, read from the legacy device statistics route.

use std::collections::BTreeMap;

use unifi_api::switch_ports::{SwitchPort, SwitchPortReport};

use super::{
    CallToolRequestParams, CallToolResult, Deserialize, JsonSchema, McpError, PORT_TABLE_CEILING,
    Serialize, UnifiMcp, api_error, parse, structured,
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct DevicePortsInput {
    /// Device id, MAC address, or exact name of one adopted switch or gateway.
    device: String,
    /// Return only ports with at least one problem indicator.
    #[serde(default)]
    only_problems: bool,
    /// Return only ports that report an optical module.
    #[serde(default)]
    sfp_only: bool,
}

/// Whole-device `PoE` budget and draw. Absent values were not reported.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PoeSummary {
    /// Total `PoE` budget in watts.
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_w: Option<f64>,
    /// Budget in watts after the device's own limits are applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_budget_w: Option<f64>,
    /// Total power the device reports delivering, in watts.
    #[serde(skip_serializing_if = "Option::is_none")]
    used_w: Option<f64>,
    /// Sum of the per-port draw this read observed, in watts, over every port
    /// the device reported, including ports omitted by a filter. Absent when
    /// no port reported a draw.
    #[serde(skip_serializing_if = "Option::is_none")]
    port_draw_sum_w: Option<f64>,
    /// Ports that contributed a draw figure to the sum.
    ports_reporting_draw: u32,
    /// Device-level figures the controller reported as text that is not a
    /// number, keyed by controller field name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(default)]
    unrecognized_values: BTreeMap<&'static str, String>,
    /// Ports whose `PoE` is enabled.
    poe_enabled_ports: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PortCounters {
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_dropped: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_dropped: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PortPoe {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    /// Whether the controller reports power delivery as healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    good: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    power_w: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    voltage_v: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_ma: Option<f64>,
}

/// Optical module identity and readings. A reading the module does not
/// report is absent, never zero.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PortSfp {
    /// Whether the controller reports a module present.
    #[serde(skip_serializing_if = "Option::is_none")]
    found: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    part: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compliance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_fault: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_fault: Option<bool>,
    /// Received optical power in dBm.
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_power_dbm: Option<f64>,
    /// Transmitted optical power in dBm.
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_power_dbm: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature_c: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    voltage_v: Option<f64>,
    /// Transmit bias current in milliamps.
    #[serde(skip_serializing_if = "Option::is_none")]
    bias_current_ma: Option<f64>,
    /// False when the module is present but reports none of the optical
    /// measurements, as some modules and gateways do.
    optical_readings_reported: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PortDiagnostics {
    idx: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// Connector family such as `GE`, `SFP`, or `SFP+`.
    #[serde(skip_serializing_if = "Option::is_none")]
    media: Option<String>,
    /// Link state.
    #[serde(skip_serializing_if = "Option::is_none")]
    up: Option<bool>,
    /// Whether the port is administratively enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    speed_mbps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_duplex: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uplink: Option<bool>,
    counters: PortCounters,
    #[serde(skip_serializing_if = "Option::is_none")]
    poe: Option<PortPoe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sfp: Option<PortSfp>,
    /// Indicators that fired for this port, such as `rxErrors` or
    /// `sfpTxFault`. An indicator is evidence to investigate, not a verdict.
    problem_indicators: Vec<&'static str>,
    /// Numeric fields the controller reported as text that is not a number,
    /// keyed by controller field name. Those readings are omitted above.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(default)]
    unrecognized_values: BTreeMap<&'static str, String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct DevicePortsOutput {
    id: String,
    name: Option<String>,
    model: Option<String>,
    mac: Option<String>,
    /// Controller device family such as `usw` or `udm`.
    device_type: Option<String>,
    /// Present when the device reports any `PoE` budget or draw figure, or
    /// has a `PoE`-capable port.
    #[serde(skip_serializing_if = "Option::is_none")]
    poe: Option<PoeSummary>,
    ports: Vec<PortDiagnostics>,
    /// Ports the device reported, before filters and the output ceiling.
    ports_reported: usize,
    /// Ports matching the filters, before the output ceiling.
    ports_matching: usize,
    /// Present when matching ports were cut at the output ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    ports_truncated: Option<bool>,
    /// Counters accumulate from the last device reset and are not rates.
    counter_semantics: &'static str,
}

/// Controller device families that carry switch ports. Access points and other
/// device families are refused so a caller learns the tool does not apply
/// rather than receiving an unrelated one-port record.
const PORT_FAMILIES: &[&str] = &["usw", "ugw", "uxg", "udm", "ucg"];
/// Longest controller-reported family text echoed in a refusal.
const MAXIMUM_ECHOED_FAMILY_CHARACTERS: usize = 32;

const COUNTER_SEMANTICS: &str = "Error and drop counters are cumulative since the device last reset, not rates. Problem indicators are evidence to investigate, not verdicts.";

impl UnifiMcp {
    pub(super) async fn devices_ports(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<DevicePortsInput>(params)?;
        let device = self.resolve_device(&input.device).await?;
        let mac = device.mac_address.as_deref().ok_or_else(|| {
            McpError::invalid_params("the selected device reports no MAC address", None)
        })?;
        let report = self
            .legacy()
            .switch_port_report(self.legacy_site(), mac)
            .await
            .map_err(api_error)?
            .ok_or_else(|| {
                McpError::invalid_params(
                    "the controller returned no port record for this device; it may be \
                     offline or not yet provisioned",
                    None,
                )
            })?;
        // A record that names no family cannot be shown to be a switch or
        // gateway, so it is refused like any other family.
        let family = report.device_type.as_deref().unwrap_or("");
        if !PORT_FAMILIES.contains(&family.to_ascii_lowercase().as_str()) {
            let shown: String = family
                .chars()
                .take(MAXIMUM_ECHOED_FAMILY_CHARACTERS)
                .collect();
            return Err(McpError::invalid_params(
                format!(
                    "devices.ports supports switches and gateways; this device reports type \"{shown}\""
                ),
                None,
            ));
        }
        if report.port_table.is_empty() {
            return Err(McpError::invalid_params(
                "the device reports no port table; devices.ports supports switches and gateways",
                None,
            ));
        }
        structured(build_output(
            device.id,
            report,
            input.only_problems,
            input.sfp_only,
        ))
    }
}

fn build_output(
    id: String,
    report: SwitchPortReport,
    only_problems: bool,
    sfp_only: bool,
) -> DevicePortsOutput {
    let ports_reported = report.port_table.len();
    let poe = poe_summary(&report);
    // Every port is evaluated so the matching count is exact, but only the
    // ports that fit the output ceiling are retained.
    let mut matching: Vec<PortDiagnostics> = Vec::new();
    let mut ports_matching = 0_usize;
    for port in report
        .port_table
        .iter()
        .map(port_diagnostics)
        .filter(|port| !only_problems || !port.problem_indicators.is_empty())
        .filter(|port| !sfp_only || port.sfp.is_some())
    {
        ports_matching += 1;
        if matching.len() < PORT_TABLE_CEILING {
            matching.push(port);
        }
    }
    let truncated = ports_matching > PORT_TABLE_CEILING;
    DevicePortsOutput {
        id,
        name: report.name,
        model: report.model,
        mac: report.mac,
        device_type: report.device_type,
        poe,
        ports: matching,
        ports_reported,
        ports_matching,
        ports_truncated: truncated.then_some(true),
        counter_semantics: COUNTER_SEMANTICS,
    }
}

fn poe_summary(report: &SwitchPortReport) -> Option<PoeSummary> {
    let poe_capable = report.port_table.iter().any(|port| {
        port.port_poe == Some(true) || port.poe_enable.is_some() || port.poe_power.value().is_some()
    });
    let budget_w = report.total_max_power.value();
    let effective_budget_w = report.total_max_effective_power.value();
    let used_w = report.total_used_power.value();
    let unrecognized_values: BTreeMap<&'static str, String> = report
        .unrecognized_readings()
        .into_iter()
        .map(|(name, text)| (name, text.to_owned()))
        .collect();
    if !poe_capable
        && budget_w.is_none()
        && effective_budget_w.is_none()
        && used_w.is_none()
        && unrecognized_values.is_empty()
    {
        return None;
    }
    let draws: Vec<f64> = report
        .port_table
        .iter()
        .filter_map(|port| port.poe_power.value())
        .collect();
    Some(PoeSummary {
        budget_w,
        effective_budget_w,
        used_w,
        port_draw_sum_w: (!draws.is_empty()).then(|| draws.iter().sum()),
        ports_reporting_draw: u32::try_from(draws.len()).unwrap_or(u32::MAX),
        unrecognized_values,
        poe_enabled_ports: u32::try_from(
            report
                .port_table
                .iter()
                .filter(|port| port.poe_enable == Some(true))
                .count(),
        )
        .unwrap_or(u32::MAX),
    })
}

fn port_diagnostics(port: &SwitchPort) -> PortDiagnostics {
    let poe = port_poe(port);
    let sfp = port_sfp(port);
    PortDiagnostics {
        idx: port
            .port_idx
            .value()
            .and_then(|idx| u32::try_from(idx).ok()),
        name: port.name.clone(),
        media: port.media.clone(),
        up: port.up,
        enabled: port.enable,
        speed_mbps: port
            .speed
            .value()
            .and_then(|speed| u32::try_from(speed).ok()),
        full_duplex: port.full_duplex,
        uplink: port.is_uplink,
        counters: PortCounters {
            rx_errors: port.rx_errors.value(),
            tx_errors: port.tx_errors.value(),
            rx_dropped: port.rx_dropped.value(),
            tx_dropped: port.tx_dropped.value(),
        },
        problem_indicators: problem_indicators(port),
        unrecognized_values: port
            .unrecognized_readings()
            .into_iter()
            .map(|(name, text)| (name, text.to_owned()))
            .collect(),
        poe,
        sfp,
    }
}

/// The controller sends an empty string for a field it has no value for.
fn nonempty(text: Option<&str>) -> Option<String> {
    text.map(str::trim)
        .filter(|trimmed| !trimmed.is_empty())
        .map(str::to_owned)
}

fn nonzero(counter: Option<u64>) -> bool {
    counter.is_some_and(|value| value > 0)
}

fn problem_indicators(port: &SwitchPort) -> Vec<&'static str> {
    let mut indicators = Vec::new();
    for (fired, name) in [
        (nonzero(port.rx_errors.value()), "rxErrors"),
        (nonzero(port.tx_errors.value()), "txErrors"),
        (nonzero(port.rx_dropped.value()), "rxDropped"),
        (nonzero(port.tx_dropped.value()), "txDropped"),
        // A cage the controller says is empty has no module to fault.
        (
            port.sfp_found != Some(false) && port.sfp_rxfault == Some(true),
            "sfpRxFault",
        ),
        (
            port.sfp_found != Some(false) && port.sfp_txfault == Some(true),
            "sfpTxFault",
        ),
    ] {
        if fired {
            indicators.push(name);
        }
    }
    indicators
}

fn port_poe(port: &SwitchPort) -> Option<PortPoe> {
    let present = port.port_poe == Some(true)
        || port.poe_enable.is_some()
        || port.poe_power.value().is_some()
        || port.poe_voltage.value().is_some()
        || port.poe_current.value().is_some();
    present.then(|| PortPoe {
        enabled: port.poe_enable,
        good: port.poe_good,
        mode: port.poe_mode.clone(),
        class: port.poe_class.clone(),
        power_w: port.poe_power.value(),
        voltage_v: port.poe_voltage.value(),
        current_ma: port.poe_current.value(),
    })
}

fn port_sfp(cage: &SwitchPort) -> Option<PortSfp> {
    let rx_power_dbm = cage.sfp_rxpower.value();
    let tx_power_dbm = cage.sfp_txpower.value();
    let temperature_c = cage.sfp_temperature.value();
    let voltage_v = cage.sfp_voltage.value();
    let bias_current_ma = cage.sfp_current.value();
    let optical_readings_reported = [
        rx_power_dbm,
        tx_power_dbm,
        temperature_c,
        voltage_v,
        bias_current_ma,
    ]
    .iter()
    .any(Option::is_some);
    let vendor = nonempty(cage.sfp_vendor.as_deref());
    let part = nonempty(cage.sfp_part.as_deref());
    let serial = nonempty(cage.sfp_serial.as_deref());
    let revision = nonempty(cage.sfp_rev.as_deref());
    let compliance = nonempty(cage.sfp_compliance.as_deref());
    // A controller that says no module is present is believed over any
    // leftover identity or reading fields.
    let faulted = cage.sfp_rxfault == Some(true) || cage.sfp_txfault == Some(true);
    let present = cage.sfp_found == Some(true)
        || (cage.sfp_found != Some(false)
            && (optical_readings_reported
                || faulted
                || vendor.is_some()
                || part.is_some()
                || serial.is_some()
                || revision.is_some()
                || compliance.is_some()));
    present.then_some(PortSfp {
        found: cage.sfp_found,
        vendor,
        part,
        serial,
        revision,
        compliance,
        rx_fault: cage.sfp_rxfault,
        tx_fault: cage.sfp_txfault,
        rx_power_dbm,
        tx_power_dbm,
        temperature_c,
        voltage_v,
        bias_current_ma,
        optical_readings_reported,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use unifi_api::switch_ports::SwitchPortReport;

    use super::build_output;
    use crate::registry::TOOL_REGISTRY;

    fn report(value: &Value) -> SwitchPortReport {
        serde_json::from_value(value.clone()).expect("report")
    }

    /// The gateway validates every result against the published output
    /// schema, so a field the server omits must not be declared required.
    #[test]
    fn results_validate_against_the_published_output_schema() {
        let tool = TOOL_REGISTRY
            .iter()
            .find(|spec| spec.name == "devices.ports")
            .expect("device ports tool is registered")
            .catalog_tool();
        let schema = Value::Object((*tool.output_schema.expect("output schema")).clone());
        let validator = jsonschema::validator_for(&schema).expect("published schema compiles");

        let sparse = json!({"mac": "aa:bb:cc:dd:ee:01", "type": "usw",
            "port_table": [{"port_idx": 1, "up": true, "speed": 1000}]});
        let populated = json!({
            "mac": "aa:bb:cc:dd:ee:01", "type": "usw",
            "total_max_power": 95, "total_used_power": "n/a",
            "port_table": [
                {"port_idx": 1, "up": true, "speed": "1000", "rx_errors": "n/a",
                 "port_poe": true, "poe_enable": true, "poe_good": true,
                 "poe_power": "4.91", "poe_voltage": "47.88", "poe_current": "102.5"},
                {"port_idx": 25, "media": "SFP+", "up": true, "sfp_found": true,
                 "sfp_vendor": "UBNT", "sfp_rxpower": "-3.59", "sfp_txpower": "oops"},
            ],
        });
        for (name, value, only_problems, sfp_only) in [
            ("a sparse device", &sparse, false, false),
            ("a populated device", &populated, false, false),
            ("a filter that matches nothing", &sparse, true, true),
        ] {
            let output = super::structured(build_output(
                "device-id".to_owned(),
                report(value),
                only_problems,
                sfp_only,
            ))
            .expect("structured result")
            .structured_content
            .expect("structured content");
            assert!(
                validator.is_valid(&output),
                "{name} must validate against the published schema: {output}"
            );
        }
    }
}
