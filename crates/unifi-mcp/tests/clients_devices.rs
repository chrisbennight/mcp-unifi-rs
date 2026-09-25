//! End-to-end fixture tests for the clients and devices read tools against
//! one loopback fake serving both APIs the way a `UniFi OS` console does.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};
use zeroize::Zeroizing;

#[path = "support/network_logs.rs"]
mod network_logs;

const API_KEY: &str = "test-integration-key";
const USERNAME: &str = "svc-mcp";
const PASSWORD: &str = "test-legacy-password";
const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const AP_MAC: &str = "11:22:33:44:55:66";
const LAPTOP_MAC: &str = "aa:bb:cc:dd:ee:01";

fn ok_envelope(data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"meta": {"rc": "ok"}, "data": data})
}

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new(API_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "home",
        "default",
        vec![
            Zeroizing::new(API_KEY.to_owned()),
            Zeroizing::new(PASSWORD.to_owned()),
        ],
    )
}

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

#[expect(
    clippy::too_many_lines,
    reason = "one console fixture shared by every test"
)]
async fn console_fixture() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .and(header("X-API-KEY", API_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 100,
            "count": 1,
            "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 100,
            "count": 2,
            "totalCount": 2,
            "data": [
                {
                    "id": "device-ap",
                    "name": "Living Room AP",
                    "model": "U6-Pro",
                    "macAddress": AP_MAC,
                    "ipAddress": "192.168.1.5",
                    "state": "ONLINE",
                    "firmwareVersion": "7.0.66",
                },
                {
                    "id": "device-switch",
                    "name": "Core Switch",
                    "model": "USW-24-POE",
                    "macAddress": "11:22:33:44:55:77",
                    "ipAddress": "192.168.1.2",
                    "state": "ONLINE",
                    "firmwareVersion": "7.1.26",
                },
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/sta"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {
                    "mac": LAPTOP_MAC,
                    "hostname": "laptop",
                    "ip": "192.168.1.50",
                    "essid": "HomeNet",
                    "vlan": 10,
                    "ap_mac": AP_MAC,
                    "signal": -52,
                    "rssi": 40,
                    "tx_bytes": 1024,
                    "rx_bytes": 2048,
                    "uptime": 3600,
                    "is_wired": false,
                    "use_fixedip": true,
                    "fixed_ip": "192.168.1.50",
                },
                {
                    "mac": "aa:bb:cc:dd:ee:02",
                    "name": "Printer",
                    "hostname": "printer",
                    "ip": "192.168.1.60",
                    "is_wired": true,
                },
                {
                    "mac": "aa:bb:cc:dd:ee:03",
                    "hostname": "phone",
                    "ip": "192.168.1.70",
                    "essid": "GuestNet",
                    "vlan": 20,
                    "ap_mac": AP_MAC,
                    "signal": -70,
                    "is_wired": false,
                },
                {
                    "mac": "aa:bb:cc:dd:ee:04",
                    "hostname": "mystery",
                    "ip": "192.168.1.80",
                },
            ]))),
        )
        .mount(&server)
        .await;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .and(wiremock::matchers::body_partial_json(
            serde_json::json!({"pageSize": 200}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(network_logs::page(
            serde_json::json!([
                {"key": "EVT_WU_Roam", "message_raw": "laptop roamed", "timestamp": now - 1000,
                 "parameters": {"CLIENT": {"id": LAPTOP_MAC}}},
                {"key": "EVT_WU_Connected", "message_raw": "phone connected",
                 "timestamp": now - 2000, "parameters": {"CLIENT": {"id": "aa:bb:cc:dd:ee:03"}}},
                {"key": "EVT_WU_Connected", "message_raw": "laptop connected",
                 "timestamp": now - 3000, "parameters": {"CLIENT": {"id": "AA:BB:CC:DD:EE:01"}}},
            ]),
            3,
        )))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn clients_search_filters_paginates_and_resolves_ap_names() {
    let server = console_fixture().await;
    let handler = handler_for(&server);

    // SSID filter with concise detail: identity plus the resolved AP name.
    let result = handler
        .call(
            &call("clients.search", &serde_json::json!({"ssid": "homenet"})),
            None,
        )
        .await
        .expect("search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 1);
    assert_eq!(output["clients"][0]["hostname"], "laptop");
    assert_eq!(output["clients"][0]["connection"], "wireless");
    assert_eq!(output["clients"][0]["apName"], "Living Room AP");
    assert!(output["clients"][0].get("signalDbm").is_none());

    // Wired filter never needs the device inventory.
    let result = handler
        .call(
            &call(
                "clients.search",
                &serde_json::json!({"connection": "wired"}),
            ),
            None,
        )
        .await
        .expect("wired search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 1);
    assert_eq!(output["clients"][0]["name"], "Printer");

    // A wireless filter excludes rows whose connection type is absent.
    let result = handler
        .call(
            &call(
                "clients.search",
                &serde_json::json!({"connection": "wireless"}),
            ),
            None,
        )
        .await
        .expect("wireless search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 2);

    // An unfiltered search reports the omitted type as unknown, never a
    // fabricated one.
    let result = handler
        .call(
            &call("clients.search", &serde_json::json!({"query": "mystery"})),
            None,
        )
        .await
        .expect("unknown search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["clients"][0]["connection"], "unknown");

    // Full detail exposes association fields; pagination reports the next
    // offset over the name-sorted result.
    let result = handler
        .call(
            &call(
                "clients.search",
                &serde_json::json!({"detail": "full", "limit": 1}),
            ),
            None,
        )
        .await
        .expect("paged search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 4);
    assert_eq!(output["nextOffset"], 1);
    assert_eq!(output["clients"][0]["hostname"], "laptop");
    assert_eq!(output["clients"][0]["signalDbm"], -52);
    assert_eq!(output["clients"][0]["fixedIp"], "192.168.1.50");
}

#[tokio::test]
async fn clients_context_returns_one_client_with_its_events() {
    let server = console_fixture().await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("clients.context", &serde_json::json!({"client": "laptop"})),
            None,
        )
        .await
        .expect("context");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["mac"], LAPTOP_MAC);
    assert_eq!(output["ssid"], "HomeNet");
    assert_eq!(output["apName"], "Living Room AP");
    assert_eq!(output["useFixedIp"], true);
    assert_eq!(output["signalDbm"], -52);
    // Only this client's events, matched case-insensitively, newest first.
    let events = output["recentEvents"].as_array().expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["key"], "EVT_WU_Roam");
    assert_eq!(events[1]["key"], "EVT_WU_Connected");

    // An ambiguous or unknown selector is a caller error.
    let error = handler
        .call(
            &call("clients.context", &serde_json::json!({"client": "nope"})),
            None,
        )
        .await
        .expect_err("unknown client");
    assert!(error.message.contains("no connected client"));
}

#[tokio::test]
async fn devices_search_and_status_summarize_the_inventory() {
    let server = console_fixture().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-switch"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-switch",
            "name": "Core Switch",
            "model": "USW-24-POE",
            "macAddress": "11:22:33:44:55:77",
            "ipAddress": "192.168.1.2",
            "state": "ONLINE",
            "firmwareVersion": "7.1.26",
            "interfaces": {
                "ports": [
                    {"idx": 1, "state": "UP", "connector": "RJ45", "speedMbps": 1000},
                    {"idx": 2, "state": "DOWN", "connector": "RJ45"},
                ],
                "radios": [],
            },
        })))
        .mount(&server)
        .await;
    // The statistics read fails; status still serves identity and tables.
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-switch/statistics/latest"
        )))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("devices.search", &serde_json::json!({"query": "switch"})),
            None,
        )
        .await
        .expect("device search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 1);
    assert_eq!(output["devices"][0]["id"], "device-switch");
    assert_eq!(output["devices"][0]["model"], "USW-24-POE");

    let result = handler
        .call(
            &call(
                "devices.status",
                &serde_json::json!({"device": "Core Switch"}),
            ),
            None,
        )
        .await
        .expect("device status");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["state"], "ONLINE");
    assert_eq!(output["ports"].as_array().expect("ports").len(), 2);
    assert_eq!(output["ports"][0]["speedMbps"], 1000);
    assert!(output.get("statistics").is_none());
}

#[tokio::test]
async fn an_identifier_selector_is_never_shadowed_by_a_colliding_name() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    // The imposter's hostname is exactly the victim's MAC address.
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/sta"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"mac": "aa:bb:cc:dd:ee:10", "hostname": "victim", "is_wired": true},
                {"mac": "aa:bb:cc:dd:ee:11", "hostname": "AA:BB:CC:DD:EE:10", "is_wired": true},
            ]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(network_logs::page(serde_json::json!([]), 0)),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call(
                "clients.context",
                &serde_json::json!({"client": "aa:bb:cc:dd:ee:10"}),
            ),
            None,
        )
        .await
        .expect("mac selection");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["hostname"], "victim");
    assert_eq!(output["mac"], "aa:bb:cc:dd:ee:10");
}

#[tokio::test]
async fn rows_without_an_access_point_never_trigger_the_inventory_read() {
    let server = MockServer::start().await;
    // No Integration mocks at all: only the legacy API answers, with rows
    // that carry no ap_mac. The search must succeed without the inventory.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/stat/sta"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"mac": "aa:bb:cc:dd:ee:02", "name": "Printer", "is_wired": true},
                {"mac": "aa:bb:cc:dd:ee:04", "hostname": "mystery"},
            ]))),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("clients.search", &serde_json::json!({})), None)
        .await
        .expect("legacy-only search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 2);
    assert_eq!(output["clients"][0]["connection"], "unknown");
    assert_eq!(output["clients"][1]["connection"], "wired");
}

#[tokio::test]
async fn a_truncated_inventory_scan_is_reported_not_presented_as_complete() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 100,
            "count": 1,
            "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(&server)
        .await;
    // The catalog reports far more devices than the scan ceiling; every
    // scanned page carries unique rows.
    for page_start in (0..1000).step_by(100) {
        let filler: Vec<serde_json::Value> = (page_start..page_start + 100)
            .map(|index| {
                serde_json::json!({
                    "id": format!("device-{index}"),
                    "name": format!("Device {index}"),
                    "state": "ONLINE",
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
            .and(wiremock::matchers::query_param(
                "offset",
                page_start.to_string(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "offset": page_start,
                "limit": 100,
                "count": 100,
                "totalCount": 1500,
                "data": filler,
            })))
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server);

    let result = handler
        .call(&call("devices.search", &serde_json::json!({})), None)
        .await
        .expect("truncated search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["inventoryTruncated"], true);
    assert_eq!(output["totalMatches"], 1000);

    let error = handler
        .call(
            &call(
                "devices.status",
                &serde_json::json!({"device": "beyond-the-ceiling"}),
            ),
            None,
        )
        .await
        .expect_err("miss on truncated inventory");
    assert!(error.message.contains("scanned inventory ceiling"));

    // A name match inside the truncated prefix cannot be proven unique.
    let error = handler
        .call(
            &call("devices.status", &serde_json::json!({"device": "Device 5"})),
            None,
        )
        .await
        .expect_err("name selector on truncated inventory");
    assert!(error.message.contains("select by id or MAC"));

    // A globally unique id selector proceeds past the truncation guard.
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-5"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-5",
            "name": "Device 5",
            "state": "ONLINE",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-5/statistics/latest"
        )))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let result = handler
        .call(
            &call("devices.status", &serde_json::json!({"device": "device-5"})),
            None,
        )
        .await
        .expect("id selector on truncated inventory");
    assert_eq!(
        result.structured_content.expect("structured")["state"],
        "ONLINE"
    );
}

#[tokio::test]
async fn search_pagination_bounds_are_enforced() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);

    for arguments in [
        serde_json::json!({"limit": 0}),
        serde_json::json!({"limit": 500}),
        serde_json::json!({"offset": 20000}),
        serde_json::json!({"query": ""}),
    ] {
        let error = handler
            .call(&call("clients.search", &arguments), None)
            .await
            .expect_err("rejected page");
        assert!(
            error.message.contains("limit")
                || error.message.contains("offset")
                || error.message.contains("filters"),
            "{arguments}"
        );
    }
}
