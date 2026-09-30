//! Wire-level tests for the Integration API client against loopback fakes.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use unifi_api::{
    ApiError, ControllerConfig, IntegrationClient, TlsMode,
    capability::{self, FirewallGeneration},
    models::{GuestAuthorizationLimits, PageRequest, VoucherCreate},
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
async fn guest_action_validation_keeps_the_exact_controller_body() {
    for (action, field) in [
        ("AUTHORIZE_GUEST_ACCESS", "action/grantedAuthorization"),
        ("UNAUTHORIZE_GUEST_ACCESS", "action/revokedAuthorization"),
    ] {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "action": action,
            "padding": "x".repeat(700),
            "z_controller_field": "original-guest-action-tail",
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}/sites/s1/clients/c1/actions")))
            .and(body_json(serde_json::json!({"action": action})))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .mount(&server)
            .await;

        let error = if action == "AUTHORIZE_GUEST_ACCESS" {
            client_for(&server)
                .authorize_guest("s1", "c1", GuestAuthorizationLimits::default())
                .await
                .expect_err("missing grant")
        } else {
            client_for(&server)
                .unauthorize_guest("s1", "c1")
                .await
                .expect_err("missing revocation")
        };
        let ApiError::SchemaMismatch {
            path,
            response: Some(response),
            ..
        } = error
        else {
            panic!("expected controller response, got {error:?}");
        };
        assert_eq!(path.as_str(), field);
        assert_eq!(response.as_str(), body);
    }
}

#[tokio::test]
async fn invalid_dpi_name_selection_keeps_the_exact_controller_body() {
    let server = MockServer::start().await;
    let body = serde_json::json!({
        "offset": 0, "limit": 50, "count": 1, "totalCount": 2112,
        "data": [{"id": 7, "name": "Unexpected"}],
        "padding": "x".repeat(700),
        "z_controller_field": "original-dpi-tail"
    })
    .to_string();
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/dpi/applications")))
        .and(query_param("filter", "id.in(196649)"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .dpi_names(&[196_649], false)
        .await
        .expect_err("unexpected DPI row");
    let ApiError::DecodeResponse {
        response,
        diagnostic,
    } = error
    else {
        panic!("expected controller response, got {error:?}");
    };
    assert_eq!(response.as_str(), body);
    assert_eq!(diagnostic.as_str(), "unexpected DPI name selection");
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
async fn radius_profile_pages_keep_the_controllers_complete_records() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/site-1/radius/profiles")))
        .and(header("X-API-KEY", API_KEY))
        .and(query_param("offset", "2"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 2, "limit": 1, "count": 1, "totalCount": 3,
            "data": [{"id": "radius-3", "name": "Enterprise", "origin": "EXTERNAL",
                      "controllerExtension": {"enabled": true}}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let page = client_for(&server)
        .radius_profiles(
            "site-1",
            PageRequest {
                offset: 2,
                limit: 1,
            },
        )
        .await
        .expect("RADIUS profile page");
    assert_eq!(page.total_count, 3);
    assert_eq!(page.data[0]["id"], "radius-3");
    assert_eq!(page.data[0]["controllerExtension"]["enabled"], true);
}

#[tokio::test]
async fn network_pages_retain_their_complete_accepted_responses() {
    for kind in ["radius/profiles", "wifi/broadcasts"] {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "offset": 0, "limit": 1, "count": 1, "totalCount": 1,
            "data": [{"id": "row-1", "name": "Synthetic"}],
            "padding": "x".repeat(700),
            "z_controller_field": "original-page-tail"
        })
        .to_string();
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/sites/site-1/{kind}")))
            .and(query_param("limit", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .mount(&server)
            .await;

        let request = PageRequest {
            offset: 0,
            limit: 1,
        };
        let (page, response) = if kind == "radius/profiles" {
            client_for(&server)
                .radius_profiles_with_response("site-1", request)
                .await
                .expect("RADIUS page")
        } else {
            client_for(&server)
                .wifi_broadcasts_with_response("site-1", request)
                .await
                .expect("Wi-Fi broadcast page")
        };
        assert_eq!(page.data.len(), 1);
        assert_eq!(response.as_str(), body);
    }
}

#[tokio::test]
async fn wifi_broadcast_list_and_detail_preserve_controller_fields() {
    let server = MockServer::start().await;
    let row = serde_json::json!({
        "id": "wifi-1", "type": "STANDARD", "name": "Studio",
        "securityConfiguration": {"type": "WPA2_ENTERPRISE", "radiusConfiguration": {"profileId": "radius-1"}},
        "controllerExtension": {"value": "from-controller"}
    });
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/site-1/wifi/broadcasts")))
        .and(header("X-API-KEY", API_KEY))
        .and(query_param("offset", "1"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 1, "limit": 1, "count": 1, "totalCount": 2, "data": [row.clone()]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/site-1/wifi/broadcasts/wifi-1"
        )))
        .and(header("X-API-KEY", API_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(row.clone()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let page = client
        .wifi_broadcasts(
            "site-1",
            PageRequest {
                offset: 1,
                limit: 1,
            },
        )
        .await
        .expect("Wi-Fi broadcasts");
    assert_eq!(
        page.data[0]["securityConfiguration"]["radiusConfiguration"]["profileId"],
        "radius-1"
    );
    let detail = client
        .wifi_broadcast("site-1", "wifi-1")
        .await
        .expect("Wi-Fi broadcast detail");
    assert_eq!(detail["controllerExtension"]["value"], "from-controller");
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
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "action": "AUTHORIZE_GUEST_ACCESS",
            "grantedAuthorization": {
                "authorizationMethod": "API",
                "authorizedAt": "2026-09-28T00:00:00Z",
                "expiresAt": "2026-09-29T00:00:00Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.restart_device("s1", "d1").await.expect("restart");
    client
        .power_cycle_port("s1", "d1", 7)
        .await
        .expect("power cycle");
    client
        .authorize_guest("s1", "c1", GuestAuthorizationLimits::default())
        .await
        .expect("authorize");
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
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body(&serde_json::json!([{
                "id": "v1", "code": "111-222", "name": "guests",
                "createdAt": "2026-08-16T00:00:00Z", "expired": false,
                "authorizedGuestCount": 0, "timeLimitMinutes": 1440
            }]))),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/s1/hotspot/vouchers/v1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "v1", "code": "111-222", "name": "guests",
            "createdAt": "2026-08-16T00:00:00Z", "expired": false,
            "authorizedGuestCount": 0, "timeLimitMinutes": 1440
        })))
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
                rx_rate_limit_kbps: None,
                tx_rate_limit_kbps: None,
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
    assert_eq!(listed.data[0].id, "v1");
    assert_eq!(listed.data[0].code, "111-222");

    let detail = client.voucher("s1", "v1").await.expect("detail");
    assert_eq!(detail.code, "111-222");
    assert!(!detail.expired);

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
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "600")
                .set_body_json(serde_json::json!({"message":format!("controller says wait {}rate-limit-tail", "x".repeat(700))})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("rate limited");
    let ApiError::RateLimited {
        retry_after,
        message,
    } = error
    else {
        panic!("expected RateLimited, got {error:?}");
    };
    assert_eq!(retry_after, Some(Duration::from_mins(10)));
    assert!(message.as_str().contains("controller says wait"));
    assert!(message.as_str().contains("rate-limit-tail"));
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
async fn upstream_errors_keep_the_complete_controller_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "statusCode": 401,
            "message": "invalid API key",
            "internalDetail": "additional context",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("unauthorized");
    let ApiError::Status { status, message } = error else {
        panic!("expected Status, got {error:?}");
    };
    assert_eq!(status, 401);
    assert!(message.as_str().contains("invalid API key"), "{message}");
    assert!(message.as_str().contains("internalDetail"), "{message}");
    assert!(message.as_str().contains("statusCode"), "{message}");
}

#[tokio::test]
async fn an_upstream_error_message_is_returned_unchanged() {
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
    assert_eq!(
        message.as_str(),
        serde_json::json!({
            "statusCode": 401,
            "message": format!("invalid key {API_KEY} rejected"),
        })
        .to_string()
    );
}

#[tokio::test]
async fn a_successful_response_that_cannot_decode_keeps_the_controller_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"applicationVersion": 17, "detail": "version format changed"}"#,
            "application/json",
        ))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .info()
        .await
        .expect_err("incompatible response");
    let rendered = error.to_string();
    assert!(rendered.contains("controller response:"), "{rendered}");
    assert!(rendered.contains("version format changed"), "{rendered}");
    assert!(rendered.contains("applicationVersion"), "{rendered}");
}

#[tokio::test]
async fn a_long_decode_diagnostic_cannot_hide_the_controller_response() {
    let server = MockServer::start().await;
    let body = format!(
        "{{\"context\":\"controller changed this field\",\"offset\":\"{}\",\"limit\":1,\"count\":0,\"totalCount\":0,\"data\":[]}}",
        "x".repeat(600)
    );
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .sites(PageRequest {
            offset: 0,
            limit: 1,
        })
        .await
        .expect_err("invalid offset");
    let rendered = error.to_string();
    assert!(
        rendered.contains("controller changed this field"),
        "{rendered}"
    );
    assert!(rendered.contains(&"x".repeat(600)), "{rendered}");
    assert!(rendered.contains("decode error:"), "{rendered}");
    assert!(rendered.contains("expected u64"), "{rendered}");
    assert!(rendered.contains("line 1 column"), "{rendered}");
}

#[tokio::test]
async fn a_multibyte_error_message_is_returned_completely() {
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
    assert_eq!(
        message.as_str(),
        serde_json::json!({"statusCode": 500, "message": "é".repeat(600)}).to_string()
    );
}

#[tokio::test]
async fn a_non_utf8_controller_error_preserves_every_original_byte() {
    let server = MockServer::start().await;
    let mut body = vec![0xff; 1_500_000];
    body.extend_from_slice(b"controller-error-tail");
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/info")))
        .respond_with(
            ResponseTemplate::new(500).set_body_raw(body.clone(), "application/octet-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("server error");
    let ApiError::Status { status, message } = error else {
        panic!("expected Status");
    };
    assert_eq!(status, 500);
    let encoded = message
        .as_str()
        .strip_prefix("non-UTF-8 controller response (base64): ")
        .expect("lossless encoding marker");
    assert_eq!(STANDARD.decode(encoded).expect("base64 response"), body);
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
    assert_eq!(
        page.data[0]
            .action
            .as_ref()
            .and_then(serde_json::Value::as_str),
        Some("ALLOW")
    );
}

#[tokio::test]
async fn firewall_policy_delete_uses_the_typed_id_route_once() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(format!("{PREFIX}/sites/s1/firewall/policies/p1")))
        .and(header("X-API-Key", API_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_string("controller deletion accepted"))
        .expect(1)
        .mount(&server)
        .await;
    let (status, body) = client_for(&server)
        .delete_firewall_policy("s1", "p1")
        .await
        .expect("delete");
    assert_eq!(status, 200);
    assert_eq!(body, b"controller deletion accepted");
}
