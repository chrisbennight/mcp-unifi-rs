//! End-to-end fixture tests for `devices.ports` against one loopback fake
//! serving both controller APIs the way a `UniFi OS` console does.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const SWITCH_MAC: &str = "11:22:33:44:55:77";
const AP_MAC: &str = "11:22:33:44:55:66";
const STAT_DEVICE: &str = "/proxy/network/api/s/default/stat/device";

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("test-integration-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: "svc-mcp".to_owned(),
        password: Zeroizing::new("test-legacy-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn call(arguments: &Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "devices.ports".to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

fn envelope(data: &Value) -> Value {
    json!({"meta": {"rc": "ok"}, "data": data})
}

async fn console(device_rows: &Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 100, "count": 2, "totalCount": 2,
            "data": [
                {"id": "device-switch", "name": "Core Switch", "model": "USW-24-POE",
                 "macAddress": SWITCH_MAC, "state": "ONLINE"},
                {"id": "device-ap", "name": "Living Room AP", "model": "U6-Pro",
                 "macAddress": AP_MAC, "state": "ONLINE"},
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{STAT_DEVICE}/{SWITCH_MAC}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(device_rows)))
        .mount(&server)
        .await;
    server
}

fn switch_record() -> Value {
    json!({
        "mac": SWITCH_MAC,
        "name": "Core Switch",
        "model": "USW-24-POE",
        "type": "usw",
        "total_max_power": 95,
        "total_max_effective_power": 95,
        "total_used_power": 12.4,
        "port_table": [
            {"port_idx": 1, "name": "AP uplink", "media": "GE", "up": true, "enable": true,
             "speed": 1000, "full_duplex": true, "port_poe": true, "poe_enable": true,
             "poe_good": true, "poe_mode": "auto", "poe_class": "Class 3",
             "poe_power": "4.91", "poe_voltage": "47.88", "poe_current": "102.53",
             "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0},
            {"port_idx": 2, "media": "GE", "up": true, "enable": true, "speed": 1000,
             "port_poe": false, "rx_errors": 7, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0},
            {"port_idx": 3, "media": "GE", "up": true, "enable": true, "port_poe": true,
             "poe_enable": true, "poe_good": false, "poe_power": "0.00"},
            {"port_idx": 25, "media": "SFP+", "up": true, "enable": true, "speed": 10000,
             "sfp_found": true, "sfp_vendor": "UBNT", "sfp_part": "UF-MM-10G",
             "sfp_serial": "SN-TEST-1", "sfp_rev": "", "sfp_compliance": "10GBase-SR",
             "sfp_rxfault": false, "sfp_txfault": false, "sfp_rxpower": "-3.59",
             "sfp_txpower": "-3.51", "sfp_temperature": "40.429", "sfp_voltage": "3.281",
             "sfp_current": "11.004"},
            {"port_idx": 26, "media": "SFP+", "up": true, "enable": true,
             "sfp_found": true, "sfp_vendor": "GENERIC", "sfp_part": "SFP-LX",
             "sfp_rxfault": false, "sfp_txfault": true, "sfp_rxpower": "",
             "sfp_txpower": "", "sfp_temperature": "", "sfp_voltage": "", "sfp_current": ""},
            {"port_idx": 27, "media": "SFP+", "up": false, "enable": true,
             "sfp_found": false, "sfp_vendor": "", "sfp_part": "", "sfp_voltage": "n/a"},
        ],
    })
}

fn port(output: &Value, idx: u64) -> &Value {
    output["ports"]
        .as_array()
        .expect("ports")
        .iter()
        .find(|port| port["idx"] == idx)
        .unwrap_or_else(|| panic!("port {idx} missing from {output}"))
}

#[tokio::test]
async fn reports_poe_optical_and_counter_readings_as_numbers() {
    let server = console(&json!([switch_record()])).await;
    let output = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect("device ports")
        .structured_content
        .expect("structured");

    assert_eq!(output["id"], "device-switch");
    assert_eq!(output["deviceType"], "usw");
    assert_eq!(output["portsReported"], 6);
    assert_eq!(output["poe"]["budgetW"], 95.0);
    assert_eq!(output["poe"]["usedW"], 12.4);
    assert_eq!(output["poe"]["portDrawSumW"], 4.91);
    assert_eq!(output["poe"]["poeEnabledPorts"], 2);
    assert_eq!(output["poe"]["portsReportingDraw"], 2);

    let poe_port = port(&output, 1);
    assert_eq!(poe_port["poe"]["powerW"], 4.91);
    assert_eq!(poe_port["poe"]["voltageV"], 47.88);
    assert_eq!(poe_port["poe"]["currentMa"], 102.53);
    assert_eq!(poe_port["problemIndicators"], json!([]));
    assert!(poe_port.get("sfp").is_none());

    let copper = port(&output, 2);
    assert!(copper.get("poe").is_none());
    assert_eq!(copper["counters"]["rxErrors"], 7);
    assert_eq!(copper["problemIndicators"], json!(["rxErrors"]));

    // A linked PoE port reporting no good delivery is reported as is, not
    // flagged: a self-powered endpoint legitimately looks the same. Its zero
    // draw is a reported value, not an absent one.
    let unhealthy = port(&output, 3);
    assert_eq!(unhealthy["poe"]["powerW"], 0.0);
    assert_eq!(unhealthy["poe"]["good"], false);
    assert_eq!(unhealthy["problemIndicators"], json!([]));

    let optical = port(&output, 25);
    assert_eq!(optical["sfp"]["rxPowerDbm"], -3.59);
    assert_eq!(optical["sfp"]["txPowerDbm"], -3.51);
    assert_eq!(optical["sfp"]["temperatureC"], 40.429);
    assert_eq!(optical["sfp"]["voltageV"], 3.281);
    assert_eq!(optical["sfp"]["biasCurrentMa"], 11.004);
    assert_eq!(optical["sfp"]["opticalReadingsReported"], true);
    assert!(optical["sfp"].get("revision").is_none());
    assert_eq!(optical["problemIndicators"], json!([]));
}

#[tokio::test]
async fn unreported_optical_values_are_absent_never_zero() {
    let server = console(&json!([switch_record()])).await;
    let output = handler_for(&server)
        .call(&call(&json!({"device": SWITCH_MAC})), None)
        .await
        .expect("device ports")
        .structured_content
        .expect("structured");

    let presence_only = port(&output, 26);
    let sfp = &presence_only["sfp"];
    assert_eq!(sfp["found"], true);
    assert_eq!(sfp["opticalReadingsReported"], false);
    for field in [
        "rxPowerDbm",
        "txPowerDbm",
        "temperatureC",
        "voltageV",
        "biasCurrentMa",
    ] {
        assert!(sfp.get(field).is_none(), "{field} must be absent: {sfp}");
    }
    assert_eq!(presence_only["problemIndicators"], json!(["sfpTxFault"]));

    // An empty cage reports no module, and text that is not a number is
    // surfaced rather than dropped or coerced.
    let empty_cage = port(&output, 27);
    assert!(empty_cage.get("sfp").is_none());
    assert_eq!(empty_cage["unrecognizedValues"]["sfp_voltage"], "n/a");
}

#[tokio::test]
async fn filters_select_problem_ports_and_optical_ports() {
    let server = console(&json!([switch_record()])).await;
    let handler = handler_for(&server);

    let problems = handler
        .call(
            &call(&json!({"device": "Core Switch", "onlyProblems": true})),
            None,
        )
        .await
        .expect("problems")
        .structured_content
        .expect("structured");
    let indexes: Vec<u64> = problems["ports"]
        .as_array()
        .expect("ports")
        .iter()
        .map(|port| port["idx"].as_u64().expect("idx"))
        .collect();
    assert_eq!(indexes, [2, 26]);
    assert_eq!(problems["portsReported"], 6);
    assert_eq!(problems["portsMatching"], 2);

    let optical = handler
        .call(
            &call(&json!({"device": "Core Switch", "sfpOnly": true})),
            None,
        )
        .await
        .expect("optical")
        .structured_content
        .expect("structured");
    assert_eq!(optical["portsMatching"], 2);
}

#[tokio::test]
async fn refuses_devices_without_a_port_table_or_record() {
    let server = console(&json!([])).await;
    let handler = handler_for(&server);

    let error = handler
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect_err("no record");
    assert!(
        error.message.contains("no port record"),
        "{}",
        error.message
    );

    let error = handler
        .call(&call(&json!({"device": "No Such Device"})), None)
        .await
        .expect_err("unknown device");
    assert!(error.message.contains("no adopted device matches"));

    let mut access_point = switch_record();
    access_point["port_table"] = json!([]);
    let server = console(&json!([access_point])).await;
    let error = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect_err("no port table");
    assert!(error.message.contains("no port table"), "{}", error.message);
}

#[tokio::test]
async fn an_unsupported_route_is_an_error_not_an_empty_result() {
    let server = console(&json!([switch_record()])).await;
    server.reset().await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": "device-switch", "name": "Core Switch",
                      "macAddress": SWITCH_MAC, "state": "ONLINE"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{STAT_DEVICE}/{SWITCH_MAC}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("route not found"))
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect_err("unsupported route");
    assert!(error.message.contains("404"), "{}", error.message);
    assert!(error.message.contains("route not found"));
}

#[tokio::test]
async fn output_ceiling_is_signaled_not_silent() {
    let ports: Vec<Value> = (1..=200)
        .map(|idx| json!({"port_idx": idx, "up": true, "rx_errors": 1}))
        .collect();
    let mut record = switch_record();
    record["port_table"] = json!(ports);
    let server = console(&json!([record])).await;
    let output = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect("large device")
        .structured_content
        .expect("structured");
    assert_eq!(output["portsReported"], 200);
    assert_eq!(output["portsMatching"], 200);
    assert_eq!(output["portsTruncated"], true);
    assert_eq!(output["ports"].as_array().expect("ports").len(), 128);
}

#[tokio::test]
async fn malformed_values_do_not_fail_the_report_or_pose_as_zero() {
    let record = json!({
        "mac": SWITCH_MAC,
        "type": "usw",
        "total_max_power": 95,
        "total_used_power": "n/a",
        "port_table": [
            {"port_idx": 1, "up": true, "speed": "1000", "rx_errors": "n/a", "tx_errors": 3,
             "port_poe": true, "poe_enable": true, "poe_power": ""},
            {"port_idx": 2, "up": true, "speed": 2500, "port_poe": true, "poe_enable": true,
             "poe_power": "oops"},
        ],
    });
    let server = console(&json!([record])).await;
    let output = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect("one malformed value must not fail the device")
        .structured_content
        .expect("structured");

    assert_eq!(output["poe"]["budgetW"], 95.0);
    assert!(output["poe"].get("usedW").is_none());
    assert_eq!(
        output["poe"]["unrecognizedValues"]["total_used_power"],
        "n/a"
    );
    // No port reported a usable draw, so there is no observed sum to claim.
    assert!(output["poe"].get("portDrawSumW").is_none());
    assert_eq!(output["poe"]["portsReportingDraw"], 0);

    let first = port(&output, 1);
    assert_eq!(first["speedMbps"], 1000);
    assert!(first["counters"].get("rxErrors").is_none());
    assert_eq!(first["counters"]["txErrors"], 3);
    assert_eq!(first["unrecognizedValues"]["rx_errors"], "n/a");
    assert_eq!(first["problemIndicators"], json!(["txErrors"]));
    assert_eq!(port(&output, 2)["unrecognizedValues"]["poe_power"], "oops");
}

#[tokio::test]
async fn devices_that_are_not_switches_or_gateways_are_refused() {
    let record = json!({
        "mac": SWITCH_MAC,
        "type": "uap",
        "port_table": [{"port_idx": 1, "up": true, "speed": 1000}],
    });
    let server = console(&json!([record])).await;
    let error = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect_err("an access point is not a switch or gateway");
    assert!(
        error.message.contains("supports switches and gateways") && error.message.contains("uap"),
        "{}",
        error.message
    );

    // A gateway family is accepted.
    let gateway = json!({"mac": SWITCH_MAC, "type": "udm", "port_table": [{"port_idx": 1}]});
    let server = console(&json!([gateway])).await;
    let output = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect("gateway")
        .structured_content
        .expect("structured");
    assert_eq!(output["deviceType"], "udm");
}

#[tokio::test]
async fn text_in_the_port_index_and_stale_module_fields_do_not_mislead() {
    let record = json!({
        "mac": SWITCH_MAC,
        "type": "usw",
        "port_table": [
            {"port_idx": "one", "up": true, "poe_power": "3.2"},
            {"port_idx": 2, "sfp_found": false, "sfp_vendor": "STALE",
             "sfp_rxpower": "-1.0"},
        ],
    });
    let server = console(&json!([record])).await;
    let handler = handler_for(&server);
    let output = handler
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect("a malformed port index must not fail the device")
        .structured_content
        .expect("structured");
    let ports = output["ports"].as_array().expect("ports");
    assert_eq!(ports[0]["unrecognizedValues"]["port_idx"], "one");
    // The device summary appears from per-port draw alone.
    assert_eq!(output["poe"]["portDrawSumW"], 3.2);
    assert_eq!(output["poe"]["portsReportingDraw"], 1);
    // A module the controller says is absent is not reported as present.
    assert!(ports[1].get("sfp").is_none());

    let optical = handler
        .call(
            &call(&json!({"device": "Core Switch", "sfpOnly": true})),
            None,
        )
        .await
        .expect("optical only")
        .structured_content
        .expect("structured");
    assert_eq!(optical["portsMatching"], 0);
}

#[tokio::test]
async fn a_record_with_no_family_is_refused_and_empty_cage_faults_are_ignored() {
    let untyped = json!({"mac": SWITCH_MAC, "port_table": [{"port_idx": 1}]});
    let server = console(&json!([untyped])).await;
    let error = handler_for(&server)
        .call(&call(&json!({"device": "Core Switch"})), None)
        .await
        .expect_err("a record that names no family cannot be verified");
    assert!(error.message.contains("supports switches and gateways"));

    let record = json!({
        "mac": SWITCH_MAC,
        "type": "usw",
        "port_table": [
            {"port_idx": 1, "sfp_found": false, "sfp_txfault": true, "sfp_rxfault": true},
            {"port_idx": 2, "sfp_found": true, "sfp_txfault": true},
        ],
    });
    let server = console(&json!([record])).await;
    let output = handler_for(&server)
        .call(
            &call(&json!({"device": "Core Switch", "onlyProblems": true})),
            None,
        )
        .await
        .expect("problems")
        .structured_content
        .expect("structured");
    let indexes: Vec<u64> = output["ports"]
        .as_array()
        .expect("ports")
        .iter()
        .map(|port| port["idx"].as_u64().expect("idx"))
        .collect();
    assert_eq!(indexes, [2]);
}
