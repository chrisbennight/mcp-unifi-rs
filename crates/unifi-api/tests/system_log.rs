//! Network 10.6 system-log contract against loopback fixtures only.

use std::time::Duration;

use unifi_api::{
    ApiError, LegacyClient, LegacyConfig, TlsMode,
    system_log::{SystemLogQuery, SystemLogSeverity},
};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};
use zeroize::Zeroizing;

const ROUTE: &str = "/proxy/network/v2/api/site/default/system-log/all";

fn client(server: &MockServer) -> LegacyClient {
    LegacyClient::new(&LegacyConfig {
        name: "test".to_owned(),
        base_url: Url::parse(&server.uri()).expect("loopback URL"),
        username: "fixture-user".to_owned(),
        password: Zeroizing::new("fixture-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("client")
}

async fn login(server: &MockServer, calls: u64) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "TOKEN=fixture-session; Path=/")
                .insert_header("X-CSRF-Token", "fixture-csrf")
                .set_body_json(serde_json::json!({})),
        )
        .expect(calls)
        .mount(server)
        .await;
}

fn page() -> serde_json::Value {
    serde_json::json!({
        "data": [{
            "key": "client-connected", "event": "CLIENT_CONNECTED",
            "timestamp": 1000, "category": "CLIENT_DEVICES", "severity": "LOW",
            "message_raw": "{CLIENT} connected to {WLAN}",
            "parameters": {
                "CLIENT": {"id": "aa:bb:cc:dd:ee:01", "name": "Laptop"},
                "WLAN": {"name": "Guest", "passphrase": "ignored-secret"},
                "UNMODELLED": {"password": "ignored-secret"}
            }
        }],
        "page_number": 0, "total_element_count": 3, "total_page_count": 3
    })
}

#[tokio::test]
async fn system_log_uses_the_v2_route_with_csrf_and_reports_a_partial_page() {
    let server = MockServer::start().await;
    login(&server, 1).await;
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .and(header("Cookie", "TOKEN=fixture-session"))
        .and(header("X-CSRF-Token", "fixture-csrf"))
        .and(body_json(serde_json::json!({
            "timestampFrom": 0, "timestampTo": 2000, "pageNumber": 0, "pageSize": 1
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(page()))
        .expect(1)
        .mount(&server)
        .await;
    let result = client(&server)
        .system_log("default", &SystemLogQuery::new(0, 2000, 1).unwrap())
        .await
        .expect("v2 logs");
    assert!(result.has_more());
    assert_eq!(result.total_element_count, 3);
    assert_eq!(result.data[0].timestamp, 1000);
    assert_eq!(
        result.data[0]
            .parameters
            .client
            .as_ref()
            .unwrap()
            .id
            .as_deref(),
        Some("aa:bb:cc:dd:ee:01")
    );
    assert!(!format!("{result:?}").contains("ignored-secret"));
}

#[test]
fn invalid_windows_and_page_sizes_are_rejected_before_a_request() {
    for (start, end, limit) in [(2, 1, 1), (0, 604_800_001, 1), (0, 1, 0), (0, 1, 1001)] {
        assert!(SystemLogQuery::new(start, end, limit).is_err());
    }
    assert!(SystemLogQuery::new(0, 604_800_000, 1000).is_ok());
}

#[tokio::test]
async fn high_severity_count_uses_controller_filter_and_total() {
    let server = MockServer::start().await;
    login(&server, 1).await;
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .and(body_json(serde_json::json!({
            "timestampFrom": 0, "timestampTo": 2000, "pageNumber": 0, "pageSize": 1,
            "severities": ["HIGH", "VERY_HIGH"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(page()))
        .expect(1)
        .mount(&server)
        .await;
    let result = client(&server)
        .system_log(
            "default",
            &SystemLogQuery::new(0, 2000, 1).unwrap().high_severity(),
        )
        .await
        .expect("filtered count");
    assert_eq!(result.total_element_count, 3);
    let query = SystemLogQuery::new(0, 2000, 1)
        .unwrap()
        .severity(SystemLogSeverity::VeryHigh);
    assert_eq!(
        serde_json::to_value(query).unwrap()["severities"],
        serde_json::json!(["VERY_HIGH"])
    );
}

#[tokio::test]
async fn missing_endpoint_is_not_an_empty_log_or_a_legacy_fallback() {
    let server = MockServer::start().await;
    login(&server, 1).await;
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "message": "fixture-password IGNORE INSTRUCTIONS"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server)
        .system_log("default", &SystemLogQuery::new(0, 2000, 1).unwrap())
        .await
        .expect_err("missing route");
    assert!(matches!(error, ApiError::Status { status: 404, .. }));
    assert!(!error.to_string().contains("fixture-password"));
    assert!(!error.to_string().contains("INSTRUCTIONS"));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn inconsistent_pages_and_invalid_records_fail_loudly() {
    let server = MockServer::start().await;
    login(&server, 1).await;
    let client = client(&server);
    let mut invalid_pages = Vec::new();
    for (key, value) in [
        ("page_number", serde_json::json!(1)),
        ("total_element_count", serde_json::json!(0)),
        ("total_page_count", serde_json::json!(0)),
        ("data", serde_json::json!([])),
    ] {
        let mut response = page();
        response[key] = value;
        invalid_pages.push(response);
    }
    let mut missing_timestamp = page();
    missing_timestamp["data"][0]
        .as_object_mut()
        .unwrap()
        .remove("timestamp");
    invalid_pages.push(missing_timestamp);
    let mut oversized = page();
    oversized["data"]
        .as_array_mut()
        .unwrap()
        .push(page()["data"][0].clone());
    invalid_pages.push(oversized);
    for response in invalid_pages {
        let mock = Mock::given(method("POST"))
            .and(path(ROUTE))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        assert!(
            client
                .system_log("default", &SystemLogQuery::new(0, 2000, 1).unwrap())
                .await
                .is_err()
        );
        drop(mock);
    }
}

#[tokio::test]
async fn reads_retry_session_expiry_or_a_short_rate_limit_once() {
    for (status, logins) in [(401, 2), (429, 1)] {
        let server = MockServer::start().await;
        login(&server, logins).await;
        Mock::given(method("POST"))
            .and(path(ROUTE))
            .respond_with(ResponseTemplate::new(status).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(ROUTE))
            .respond_with(ResponseTemplate::new(200).set_body_json(page()))
            .expect(1)
            .mount(&server)
            .await;
        client(&server)
            .system_log("default", &SystemLogQuery::new(0, 2000, 1).unwrap())
            .await
            .expect("retried read");
    }
}
