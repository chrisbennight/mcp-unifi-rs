//! End-to-end fixture tests for the wireless diagnosis, event search, and
//! statistics tools against loopback fakes.

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

const API_KEY: &str = "test-integration-key";
const USERNAME: &str = "svc-mcp";
const PASSWORD: &str = "test-legacy-password";
const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const LEGACY: &str = "/proxy/network/api/s/default";
const AP_MAC: &str = "11:22:33:44:55:66";

fn ok_envelope(data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"meta": {"rc": "ok"}, "data": data})
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("timestamp")
            .as_millis(),
    )
    .expect("timestamp range")
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

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one console fixture drives the access-point, weak-client, and rogue contracts"
)]
async fn wifi_diagnose_summarizes_access_points_weak_clients_and_rogues() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    site_mock(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"mac": "aa:bb:cc:dd:ee:01", "hostname": "laptop", "essid": "HomeNet",
                 "ap_mac": AP_MAC, "signal": -80, "rssi": 15, "is_wired": false},
                {"mac": "aa:bb:cc:dd:ee:02", "hostname": "phone", "essid": "HomeNet",
                 "ap_mac": AP_MAC, "signal": -50, "rssi": 45, "is_wired": false},
                {"mac": "aa:bb:cc:dd:ee:03", "hostname": "printer", "is_wired": true},
                {"mac": "aa:bb:cc:dd:ee:04", "hostname": "orphan", "signal": -85,
                 "is_wired": false},
            ]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/devices")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 100,
            "count": 3,
            "totalCount": 3,
            "data": [
                {"id": "device-ap", "name": "Living Room AP", "macAddress": AP_MAC,
                 "state": "ONLINE"},
                {"id": "device-ap2", "name": "Bedroom AP",
                 "macAddress": "11:22:33:44:55:88", "state": "ONLINE"},
                {"id": "device-switch", "name": "Core Switch",
                 "macAddress": "11:22:33:44:55:77", "state": "ONLINE"},
            ],
        })))
        .mount(&server)
        .await;
    // Every inventory device is detailed within the bounded scan;
    // radio-less devices are then excluded from access points.
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-ap"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-ap",
            "name": "Living Room AP",
            "macAddress": AP_MAC,
            "state": "ONLINE",
            "interfaces": {
                "ports": [],
                "radios": [
                    {"wlanStandard": "802.11ax", "frequencyGHz": 5.0, "channel": 44},
                ],
            },
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-ap2"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-ap2",
            "name": "Bedroom AP",
            "macAddress": "11:22:33:44:55:88",
            "state": "ONLINE",
            "interfaces": {
                "ports": [],
                "radios": [
                    {"wlanStandard": "802.11ax", "frequencyGHz": 2.4, "channel": 6},
                ],
            },
        })))
        .expect(1)
        .mount(&server)
        .await;
    // A radio-less device is detailed once and excluded from access points.
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/device-switch"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-switch",
            "name": "Core Switch",
            "macAddress": "11:22:33:44:55:77",
            "state": "ONLINE",
            "interfaces": {"ports": [], "radios": []},
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/rogueap")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"bssid": "66:55:44:33:22:11", "essid": "NeighborNet", "channel": 44,
                 "rssi": 30},
            ]))),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("wifi.diagnose", &serde_json::json!({})), None)
        .await
        .expect("diagnose");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["weakSignalThresholdDbm"], -75);
    // Access points are identified by radios: the idle Bedroom AP appears
    // with zero load, and the radio-less switch is excluded.
    let aps = output["accessPoints"].as_array().expect("aps");
    assert_eq!(aps.len(), 2);
    assert_eq!(aps[0]["name"], "Living Room AP");
    assert_eq!(aps[0]["clients"], 2);
    assert_eq!(aps[0]["weakClients"], 1);
    assert_eq!(aps[0]["radios"][0]["channel"], 44);
    assert_eq!(aps[1]["name"], "Bedroom AP");
    assert_eq!(aps[1]["clients"], 0);
    assert!(output.get("accessPointsTruncated").is_none());
    // The weakest clients rank worst first, including the below-threshold
    // client that reports no access point at all.
    let weak = output["weakClients"].as_array().expect("weak");
    assert_eq!(weak.len(), 2);
    assert_eq!(weak[0]["name"], "orphan");
    assert_eq!(weak[0]["signalDbm"], -85);
    assert!(weak[0].get("apName").is_none() || weak[0]["apName"].is_null());
    assert_eq!(weak[1]["name"], "laptop");
    assert_eq!(weak[1]["apName"], "Living Room AP");
    assert_eq!(output["rogueAps"][0]["ssid"], "NeighborNet");

    // An out-of-range threshold is a caller error.
    let error = handler
        .call(
            &call(
                "wifi.diagnose",
                &serde_json::json!({"weakSignalThresholdDbm": -10}),
            ),
            None,
        )
        .await
        .expect_err("threshold bound");
    assert!(error.message.contains("between -100 and -30"));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture drives window, filter, kind, and pagination contracts"
)]
async fn events_search_windows_filters_and_paginates() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let now = now_ms();
    let recent = now - 60_000;
    let older = now - 3_600_000;
    let ancient = now - 200 * 3_600_000;
    Mock::given(method("POST"))
        .and(path(format!("{LEGACY}/stat/event")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"key": "EVT_WU_Roam", "msg": "laptop roamed", "time": recent,
                 "subsystem": "wlan", "user": "aa:bb:cc:dd:ee:01"},
                {"key": "EVT_GW_WANTransition", "msg": "wan flapped", "time": older,
                 "subsystem": "wan"},
                {"key": "EVT_AP_Adopted", "msg": "too old", "time": ancient,
                 "subsystem": "wlan"},
                {"key": "EVT_NoTimestamp", "msg": "row without time"},
                {"key": "EVT_FromTheFuture", "msg": "clock skewed row",
                 "time": now + 600_000},
            ]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{LEGACY}/stat/alarm")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"_id": "alarm-1", "key": "EVT_IPS_IpsAlert", "msg": "ips hit",
                 "time": recent - 1},
            ]))),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    // The default window keeps recent rows of both kinds, newest first,
    // and drops out-of-window and timestampless rows.
    let result = handler
        .call(&call("events.search", &serde_json::json!({})), None)
        .await
        .expect("search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 3);
    assert_eq!(output["rows"][0]["key"], "EVT_WU_Roam");
    assert_eq!(output["rows"][1]["kind"], "alarm");

    // Category and client filters narrow the set.
    let result = handler
        .call(
            &call("events.search", &serde_json::json!({"category": "wan"})),
            None,
        )
        .await
        .expect("category search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 1);
    assert_eq!(output["rows"][0]["key"], "EVT_GW_WANTransition");

    let result = handler
        .call(
            &call(
                "events.search",
                &serde_json::json!({"client": "AA:BB:CC:DD:EE:01"}),
            ),
            None,
        )
        .await
        .expect("client search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 1);
    assert_eq!(output["rows"][0]["clientMac"], "aa:bb:cc:dd:ee:01");

    // Alarms-only narrows the kind.
    let result = handler
        .call(
            &call("events.search", &serde_json::json!({"kind": "alarms"})),
            None,
        )
        .await
        .expect("alarm search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["totalMatches"], 1);
    assert_eq!(output["rows"][0]["key"], "EVT_IPS_IpsAlert");

    // Pagination walks the three-row combined result one row at a time in
    // time order, and the final page reports no continuation.
    let mut offset = 0_u64;
    let mut seen_keys = Vec::new();
    loop {
        let result = handler
            .call(
                &call(
                    "events.search",
                    &serde_json::json!({"limit": 1, "offset": offset}),
                ),
                None,
            )
            .await
            .expect("paged search");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["totalMatches"], 3);
        let rows = output["rows"].as_array().expect("rows");
        assert_eq!(rows.len(), 1);
        seen_keys.push(rows[0]["key"].as_str().expect("key").to_owned());
        match output.get("nextOffset") {
            Some(next) => offset = next.as_u64().expect("offset"),
            None => break,
        }
    }
    assert_eq!(
        seen_keys,
        ["EVT_WU_Roam", "EVT_IPS_IpsAlert", "EVT_GW_WANTransition"]
    );

    // Window bounds are enforced.
    let error = handler
        .call(
            &call("events.search", &serde_json::json!({"lastHours": 500})),
            None,
        )
        .await
        .expect_err("window bound");
    assert!(error.message.contains("lastHours"));
}

#[tokio::test]
async fn stats_query_serves_bounded_wan_and_dpi_reports() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("{LEGACY}/stat/report/hourly.site")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"time": 1_755_300_000_000_u64, "wan-tx_bytes": 1024.0,
                 "wan-rx_bytes": 4096.0},
            ]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{LEGACY}/stat/sitedpi")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"app": 5, "cat": 4, "tx_bytes": 100, "rx_bytes": 200},
                {"app": 9, "cat": 13, "tx_bytes": 5000, "rx_bytes": 9000},
            ]))),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("stats.query", &serde_json::json!({"report": "wanHourly"})),
            None,
        )
        .await
        .expect("wan report");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["report"], "wanHourly");
    assert_eq!(output["wanHourly"][0]["rxBytes"], 4096.0);
    assert!(output.get("topApplications").is_none());

    // Top talkers rank by combined volume.
    let result = handler
        .call(
            &call(
                "stats.query",
                &serde_json::json!({"report": "dpiApplications", "top": 1}),
            ),
            None,
        )
        .await
        .expect("dpi report");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["report"], "dpiApplications");
    let apps = output["topApplications"].as_array().expect("apps");
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0]["applicationId"], 9);

    // Cross-report parameters are caller errors.
    let error = handler
        .call(
            &call(
                "stats.query",
                &serde_json::json!({"report": "wanHourly", "top": 5}),
            ),
            None,
        )
        .await
        .expect_err("cross parameter");
    assert!(error.message.contains("dpiApplications"));
}
