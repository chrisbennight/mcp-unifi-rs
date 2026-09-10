//! Wire-level tests for the Integration API client against loopback fakes.

use std::time::Duration;

use unifi_api::{
    ApiError, ControllerConfig, IntegrationClient, TlsMode,
    capability::{self, FirewallGeneration},
    models::{PageRequest, VoucherCreate},
};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};
use zeroize::Zeroizing;

const API_KEY: &str = "test-integration-key";
const PREFIX: &str = "/proxy/network/integration/v1";

fn client_for(server: &MockServer) -> IntegrationClient {
    let config = ControllerConfig {
        name: "test".to_owned(),
        base_url: Url::parse(&server.uri()).expect("mock server uri"),
        api_key: Zeroizing::new(API_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    };
    IntegrationClient::new(&config).expect("client")
}

fn page_body(data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "offset": 0,
        "limit": 100,
        "count": data.as_array().map_or(0, Vec::len),
        "totalCount": data.as_array().map_or(0, Vec::len),
        "data": data,
    })
}

#[tokio::test]
async fn every_request_authenticates_with_the_api_key_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .and(header("X-API-KEY", API_KEY))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let info = client_for(&server).info().await.expect("info");
    assert_eq!(info.application_version, "9.4.19");
}

#[tokio::test]
async fn device_detail_decodes_port_and_radio_tables() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/site-1/devices/device-1")))
        .and(header("X-API-KEY", API_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "device-1",
            "name": "Core Switch",
            "model": "USW-24-POE",
            "macAddress": "11:22:33:44:55:66",
            "state": "ONLINE",
            "firmwareVersion": "7.1.26",
            "interfaces": {
                "ports": [
                    {"idx": 1, "state": "UP", "connector": "RJ45", "speedMbps": 1000},
                    {"idx": 2, "state": "DOWN", "connector": "RJ45"},
                ],
                "radios": [
                    {"wlanStandard": "802.11ax", "frequencyGHz": 5.0, "channel": 44},
                ],
            },
            "unmodelledField": true,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let detail = client_for(&server)
        .device_detail("site-1", "device-1")
        .await
        .expect("device detail");
    let interfaces = detail.interfaces.expect("interfaces");
    assert_eq!(interfaces.ports.len(), 2);
    assert_eq!(interfaces.ports[0].speed_mbps, Some(1000));
    assert_eq!(interfaces.ports[1].state.as_deref(), Some("DOWN"));
    assert_eq!(interfaces.radios[0].channel, Some(44));
}

#[tokio::test]
async fn pagination_coordinates_are_sent_and_the_envelope_is_decoded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites")))
        .and(query_param("offset", "200"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 200,
            "limit": 50,
            "count": 1,
            "totalCount": 201,
            "data": [{"id": "site-1", "name": "Default", "internalReference": "default"}],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let page = client_for(&server)
        .sites(PageRequest {
            offset: 200,
            limit: 50,
        })
        .await
        .expect("sites page");
    assert_eq!(page.total_count, 201);
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].id, "site-1");
    assert_eq!(page.data[0].name.as_deref(), Some("Default"));
}

#[tokio::test]
async fn devices_clients_and_statistics_expose_allowlisted_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/devices")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body(&serde_json::json!([{
                "id": "d1",
                "name": "Office Switch",
                "model": "USW-24-POE",
                "macAddress": "aa:bb:cc:dd:ee:ff",
                "ipAddress": "192.0.2.10",
                "state": "ONLINE",
                "firmwareVersion": "7.1.20",
                "unmodelledUpstreamField": {"nested": true},
            }]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/s1/devices/d1/statistics/latest"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uptimeSec": 86400,
            "cpuUtilizationPct": 12.5,
            "memoryUtilizationPct": 40.0,
            "uplink": {"txRateBps": 1000, "rxRateBps": 2000},
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/clients")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body(&serde_json::json!([{
                "id": "c1",
                "name": "laptop",
                "type": "WIRELESS",
                "macAddress": "11:22:33:44:55:66",
                "ipAddress": "192.0.2.50",
                "connectedAt": "2026-08-16T00:00:00Z",
                "uplinkDeviceId": "d1",
            }]))),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let devices = client
        .devices("s1", PageRequest::default())
        .await
        .expect("devices");
    assert_eq!(devices.data[0].model.as_deref(), Some("USW-24-POE"));

    let statistics = client
        .device_statistics("s1", "d1")
        .await
        .expect("statistics");
    assert_eq!(statistics.uptime_sec, Some(86400));
    assert_eq!(
        statistics
            .uplink
            .as_ref()
            .and_then(|uplink| uplink.rx_rate_bps),
        Some(2000)
    );

    let clients = client
        .clients("s1", PageRequest::default())
        .await
        .expect("clients");
    assert_eq!(clients.data[0].kind.as_deref(), Some("WIRELESS"));
    assert_eq!(clients.data[0].uplink_device_id.as_deref(), Some("d1"));
}

#[tokio::test]
async fn actions_post_their_typed_envelopes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/s1/devices/d1/actions")))
        .and(body_json(serde_json::json!({"action": "RESTART"})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{PREFIX}/sites/s1/devices/d1/interfaces/ports/7/actions"
        )))
        .and(body_json(serde_json::json!({"action": "POWER_CYCLE"})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/s1/clients/c1/actions")))
        .and(body_json(
            serde_json::json!({"action": "AUTHORIZE_GUEST_ACCESS"}),
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.restart_device("s1", "d1").await.expect("restart");
    client
        .power_cycle_port("s1", "d1", 7)
        .await
        .expect("power cycle");
    client.authorize_guest("s1", "c1").await.expect("authorize");
}

#[tokio::test]
async fn vouchers_round_trip_create_list_and_delete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/s1/hotspot/vouchers")))
        .and(body_json(serde_json::json!({
            "name": "guests",
            "count": 2,
            "timeLimitMinutes": 1440,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "vouchers": [
                {"id": "v1", "code": "111-222", "name": "guests", "createdAt": "2026-08-16T00:00:00Z"},
                {"id": "v2", "code": "333-444", "name": "guests", "createdAt": "2026-08-16T00:00:00Z"},
            ],
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/hotspot/vouchers")))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_body(
            &serde_json::json!([{"id": "v1", "code": "111-222", "name": "guests"}]),
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("{PREFIX}/sites/s1/hotspot/vouchers/v1")))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let created = client
        .create_vouchers(
            "s1",
            &VoucherCreate {
                name: "guests".to_owned(),
                count: 2,
                time_limit_minutes: 1440,
                authorized_guest_limit: None,
                data_usage_limit_m_bytes: None,
            },
        )
        .await
        .expect("create");
    assert_eq!(created.vouchers.len(), 2);
    assert_eq!(created.vouchers[0].code.as_deref(), Some("111-222"));

    let listed = client
        .vouchers("s1", PageRequest::default())
        .await
        .expect("list");
    assert_eq!(listed.data[0].id.as_deref(), Some("v1"));

    client.delete_voucher("s1", "v1").await.expect("delete");
}

#[tokio::test]
async fn rate_limited_reads_retry_once_after_the_named_delay() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let info = client_for(&server).info().await.expect("retried read");
    assert_eq!(info.application_version, "9.4.19");
}

#[tokio::test]
async fn rate_limited_reads_without_an_acceptable_delay_surface_the_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "600"))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("rate limited");
    let ApiError::RateLimited { retry_after } = error else {
        panic!("expected RateLimited, got {error:?}");
    };
    assert_eq!(retry_after, Some(Duration::from_mins(10)));
}

#[tokio::test]
async fn rate_limited_mutations_are_never_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/s1/devices/d1/actions")))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .restart_device("s1", "d1")
        .await
        .expect_err("rate limited mutation");
    assert!(matches!(error, ApiError::RateLimited { .. }));
}

#[tokio::test]
async fn upstream_errors_are_bounded_and_carry_the_extracted_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "statusCode": 401,
            "message": "invalid API key",
            "internalDetail": "x".repeat(10_000),
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("unauthorized");
    let ApiError::Status { status, message } = error else {
        panic!("expected Status, got {error:?}");
    };
    assert_eq!(status, 401);
    assert_eq!(message.as_str(), "invalid API key");
}

#[tokio::test]
async fn an_echoed_api_key_is_redacted_from_error_messages() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "statusCode": 401,
            "message": format!("invalid key {API_KEY} rejected"),
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("unauthorized");
    let ApiError::Status { message, .. } = error else {
        panic!("expected Status, got {error:?}");
    };
    assert!(
        !message.as_str().contains(API_KEY),
        "credential must never survive into the error surface"
    );
    assert_eq!(message.as_str(), "invalid key <redacted> rejected");
}

#[tokio::test]
async fn an_over_limit_multibyte_error_message_is_truncated_without_panicking() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "statusCode": 500,
            "message": "\u{e9}".repeat(600),
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("server error");
    let ApiError::Status { status, message } = error else {
        panic!("expected Status, got {error:?}");
    };
    assert_eq!(status, 500);
    assert!(
        message.as_str().len() <= 512,
        "message must respect the byte budget"
    );
    assert!(!message.as_str().is_empty());
    assert!(
        message
            .as_str()
            .chars()
            .all(|character| character == '\u{e9}')
    );
}

#[tokio::test]
async fn identifiers_with_url_syntax_stay_one_encoded_path_segment() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = client_for(&server);
    client
        .delete_voucher("s1", "v1/../../evil?x=1#frag")
        .await
        .expect("encoded delete");
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 1);
    let path = requests[0].url.path();
    assert!(
        path.ends_with("/sites/s1/hotspot/vouchers/v1%2F..%2F..%2Fevil%3Fx=1%23frag"),
        "identifier must stay one literal segment, got {path}"
    );

    let error = client
        .delete_voucher("s1", "..")
        .await
        .expect_err("dot segment rejected");
    assert!(matches!(error, ApiError::Config(_)));
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 1, "a rejected identifier sends no request");
}

#[tokio::test]
async fn capability_detection_classifies_both_firewall_generations() {
    let zone_based = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .mount(&zone_based)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/firewall/zones")))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_body(
            &serde_json::json!([{"id": "z1", "name": "Internal"}]),
        )))
        .mount(&zone_based)
        .await;
    let capabilities = capability::detect(&client_for(&zone_based), "s1")
        .await
        .expect("zone-based detection");
    assert_eq!(capabilities.firewall, FirewallGeneration::ZoneBased);
    assert_eq!(capabilities.application_version, "9.4.19");

    let classic = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "8.5.6"})),
        )
        .mount(&classic)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/firewall/zones")))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            serde_json::json!({"statusCode": 400, "message": "Zone Based Firewall is not configured"}),
        ))
        .mount(&classic)
        .await;
    let capabilities = capability::detect(&client_for(&classic), "s1")
        .await
        .expect("classic detection");
    assert_eq!(capabilities.firewall, FirewallGeneration::Classic);

    let broken = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .mount(&broken)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/firewall/zones")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&broken)
        .await;
    let error = capability::detect(&client_for(&broken), "s1")
        .await
        .expect_err("500 must propagate, not classify");
    assert!(matches!(error, ApiError::Status { status: 500, .. }));

    let unrelated = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .mount(&unrelated)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/firewall/zones")))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            serde_json::json!({"statusCode": 400, "message": "invalid site identifier"}),
        ))
        .mount(&unrelated)
        .await;
    let error = capability::detect(&client_for(&unrelated), "s1")
        .await
        .expect_err("an unrelated 400 must propagate, not classify");
    assert!(matches!(error, ApiError::Status { status: 400, .. }));
}

#[tokio::test]
async fn firewall_policies_decode_the_allowlisted_projection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/firewall/policies")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body(&serde_json::json!([{
                "id": "p1",
                "name": "Allow LAN to WAN",
                "enabled": true,
                "action": "ALLOW",
                "unmodelledUpstreamField": [1, 2, 3],
            }]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    let page = client_for(&server)
        .firewall_policies("s1", PageRequest::default())
        .await
        .expect("policies");
    assert_eq!(page.data[0].id, "p1");
    assert_eq!(page.data[0].enabled, Some(true));
    assert_eq!(page.data[0].action.as_deref(), Some("ALLOW"));
}
