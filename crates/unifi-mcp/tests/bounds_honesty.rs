//! Fixture tests for the bounds-honesty contract: every bounded read that
//! cannot return everything it scanned says so in the result itself, and a
//! cut text excerpt carries a visible marker.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

#[path = "support/network_logs.rs"]
mod network_logs;

const API_KEY: &str = "test-integration-key";
const USERNAME: &str = "svc-mcp";
const PASSWORD: &str = "test-legacy-password";
const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const LEGACY: &str = "/proxy/network/api/s/default";

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

async fn login_mock(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(server)
        .await;
}

async fn site_mock(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 100,
            "count": 1,
            "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(server)
        .await;
}

fn integration_page(data: &serde_json::Value) -> serde_json::Value {
    let count = data.as_array().map_or(0, Vec::len);
    serde_json::json!({
        "offset": 0,
        "limit": 200,
        "count": count,
        "totalCount": count,
        "data": data,
    })
}

#[tokio::test]
async fn an_over_ceiling_rogue_list_is_reported_truncated() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    site_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(integration_page(&serde_json::json!([]))),
        )
        .mount(&server)
        .await;
    let rogues: Vec<serde_json::Value> = (0..101)
        .map(|index| serde_json::json!({"bssid": format!("66:55:44:33:22:{index:02x}")}))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/rogueap")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!(rogues))),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("wifi.diagnose", &serde_json::json!({})), None)
        .await
        .expect("diagnose");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["rogueAps"].as_array().expect("rogues").len(), 100);
    assert_eq!(output["rogueApsTruncated"], true);
}

#[tokio::test]
async fn over_ceiling_port_and_radio_tables_are_reported_truncated() {
    let server = MockServer::start().await;
    site_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
        .respond_with(ResponseTemplate::new(200).set_body_json(integration_page(
            &serde_json::json!([{"id": "device-big", "name": "Chassis", "state": "ONLINE"}]),
        )))
        .mount(&server)
        .await;
    let ports: Vec<serde_json::Value> = (0..129)
        .map(|index| serde_json::json!({"idx": index, "state": "UP"}))
        .collect();
    let radios: Vec<serde_json::Value> = (0..17)
        .map(|index| serde_json::json!({"channel": index}))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-big"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-big",
            "name": "Chassis",
            "state": "ONLINE",
            "interfaces": {"ports": ports, "radios": radios},
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-big/statistics/latest"
        )))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call(
                "devices.status",
                &serde_json::json!({"device": "device-big"}),
            ),
            None,
        )
        .await
        .expect("status");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["ports"].as_array().expect("ports").len(), 128);
    assert_eq!(output["portsTruncated"], true);
    assert_eq!(output["radios"].as_array().expect("radios").len(), 16);
    assert_eq!(output["radiosTruncated"], true);
}

#[tokio::test]
async fn an_incomplete_upstream_event_page_is_reported_as_a_truncated_window() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("timestamp")
            .as_millis(),
    )
    .expect("timestamp range");
    let events = serde_json::json!([
        {"key": "EVT_LongMessage", "message_raw": "a".repeat(300), "timestamp": now - 1},
        {"key": "EVT_CeilingMessage", "message_raw": "b".repeat(256), "timestamp": now - 2}
    ]);
    // Even a short page is partial when the controller reports more rows.
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(network_logs::page(events, 1001)))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("events.search", &serde_json::json!({"limit": 5})),
            None,
        )
        .await
        .expect("search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["fetchWindowTruncated"], true);
    let rows = output["rows"].as_array().expect("rows").clone();
    let long_row = rows
        .iter()
        .find(|row| row["key"] == "EVT_LongMessage")
        .expect("long row");
    let message = long_row["message"].as_str().expect("message");
    assert_eq!(message.chars().count(), 256);
    assert!(message.ends_with('\u{2026}'));
    // Text at the ceiling is untouched: the marker appears only on a cut.
    let ceiling_row = rows
        .iter()
        .find(|row| row["key"] == "EVT_CeilingMessage")
        .expect("ceiling row");
    let untouched = ceiling_row["message"].as_str().expect("message");
    assert_eq!(untouched.chars().count(), 256);
    assert!(!untouched.contains('\u{2026}'));
}

#[tokio::test]
async fn overview_counts_use_totals_beyond_the_page_size() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    site_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "10.6.106"})),
        )
        .mount(&server)
        .await;
    for collection in ["devices", "clients"] {
        Mock::given(method("GET"))
            .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/{collection}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "offset": 0, "limit": 1, "count": 0, "totalCount": 0, "data": [],
            })))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/health")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(network_logs::page(
            serde_json::json!([{"timestamp": 1}]),
            5000,
        )))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let mut params = CallToolRequestParams::default();
    params.name = "network.overview".into();
    let result = handler.call(&params, None).await.expect("overview");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["recentEvents"]["total"], 5000);
    assert_eq!(output["recentEvents"]["highSeverity"], 5000);
    assert!(output.get("activeAlarms").is_none());
}

#[tokio::test]
async fn additional_system_log_pages_mark_client_context_as_truncated() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"mac": "aa:bb:cc:dd:ee:01", "hostname": "laptop", "is_wired": true},
            ]))),
        )
        .mount(&server)
        .await;
    // The client's older events may lie beyond the scan.
    let events: Vec<serde_json::Value> = (0_u64..200)
        .map(|index| serde_json::json!({"key": format!("EVT_{index}"), "timestamp": index}))
        .collect();
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(network_logs::page(serde_json::json!(events), 201)),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("clients.context", &serde_json::json!({"client": "laptop"})),
            None,
        )
        .await
        .expect("context");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["recentEventsTruncated"], true);
}

#[tokio::test]
async fn client_context_marks_omitted_matches_even_when_the_scan_is_complete() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"mac": "aa:bb:cc:dd:ee:01", "hostname": "laptop", "is_wired": true}
            ]))),
        )
        .mount(&server)
        .await;
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let events: Vec<_> = (1..=21)
        .rev()
        .map(|index| {
            serde_json::json!({
                "timestamp": now - index,
                "key": format!("event-{index}"),
                "parameters": {"CLIENT": {"id": "aa:bb:cc:dd:ee:01"}}
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(network_logs::page(serde_json::json!(events), 21)),
        )
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call("clients.context", &serde_json::json!({"client": "laptop"})),
            None,
        )
        .await
        .unwrap()
        .structured_content
        .unwrap();
    assert_eq!(result["recentEventsTruncated"], true);
    assert_eq!(result["recentEvents"].as_array().unwrap().len(), 20);
    assert_eq!(result["recentEvents"][0]["key"], "event-1");
    assert_eq!(result["recentEvents"][19]["key"], "event-20");
}

#[tokio::test]
async fn a_truncated_inventory_marks_the_ap_name_join() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    site_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"mac": "aa:bb:cc:dd:ee:01", "hostname": "laptop",
                 "ap_mac": "ff:ff:ff:ff:ff:ff", "is_wired": false},
            ]))),
        )
        .mount(&server)
        .await;
    // Every page reports a catalog far past the scan ceiling; the client's
    // access point is not inside the scanned prefix.
    for page_start in (0..1000).step_by(100) {
        let filler: Vec<serde_json::Value> = (page_start..page_start + 100)
            .map(|index| {
                serde_json::json!({
                    "id": format!("device-{index}"),
                    "name": format!("Device {index}"),
                    "macAddress": format!("00:00:00:00:{:02x}:{:02x}", index / 256, index % 256),
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
                "offset": page_start, "limit": 100, "count": 100, "totalCount": 1500,
                "data": filler,
            })))
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server);

    let result = handler
        .call(&call("clients.search", &serde_json::json!({})), None)
        .await
        .expect("search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["apLookupTruncated"], true);
    assert!(output["clients"][0].get("apName").is_none());

    // The same truncated join is signaled on the single-client context.
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(network_logs::page(serde_json::json!([]), 0)),
        )
        .mount(&server)
        .await;
    let result = handler
        .call(
            &call("clients.context", &serde_json::json!({"client": "laptop"})),
            None,
        )
        .await
        .expect("context");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["apLookupTruncated"], true);

    // wifi.diagnose folds the inventory truncation into its own signal,
    // independent of the detail-scan ceiling.
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/rogueap")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .mount(&server)
        .await;
    for index in 0..16 {
        Mock::given(method("GET"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/devices/device-{index}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": format!("device-{index}"),
                "name": format!("Device {index}"),
                "interfaces": {"ports": [], "radios": []},
            })))
            .mount(&server)
            .await;
    }
    let result = handler
        .call(&call("wifi.diagnose", &serde_json::json!({})), None)
        .await
        .expect("diagnose");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["accessPointsTruncated"], true);
}

#[tokio::test]
async fn an_over_ceiling_diagnose_radio_table_is_reported_truncated() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    site_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/rogueap")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
        .respond_with(ResponseTemplate::new(200).set_body_json(integration_page(
            &serde_json::json!([{"id": "device-manyradio", "name": "Odd AP",
                "macAddress": "11:22:33:44:55:99", "state": "ONLINE"}]),
        )))
        .mount(&server)
        .await;
    let radios: Vec<serde_json::Value> = (0..17)
        .map(|index| serde_json::json!({"channel": index}))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-manyradio"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-manyradio",
            "name": "Odd AP",
            "macAddress": "11:22:33:44:55:99",
            "state": "ONLINE",
            "interfaces": {"ports": [], "radios": radios},
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("wifi.diagnose", &serde_json::json!({})), None)
        .await
        .expect("diagnose");
    let output = result.structured_content.expect("structured");
    let ap = &output["accessPoints"][0];
    assert_eq!(ap["radios"].as_array().expect("radios").len(), 16);
    assert_eq!(ap["radiosTruncated"], true);
}

#[tokio::test]
async fn a_complete_full_system_log_page_is_not_marked_truncated() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("timestamp")
            .as_millis(),
    )
    .expect("timestamp range");
    let events: Vec<serde_json::Value> = (0_u64..1000)
        .map(|index| {
            serde_json::json!({
                "severity": "HIGH",
                "key": format!("EVT_A{index}"),
                "timestamp": now - index,
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(network_logs::ROUTE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(network_logs::page(serde_json::json!(events), 1000)),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    // Totals prove this full page is complete; its size alone is not a signal.
    let result = handler
        .call(
            &call(
                "events.search",
                &serde_json::json!({"severity": "high", "limit": 5}),
            ),
            None,
        )
        .await
        .expect("search");
    let output = result.structured_content.expect("structured");
    assert!(output.get("fetchWindowTruncated").is_none());
}
