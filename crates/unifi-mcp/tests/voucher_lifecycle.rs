//! Voucher lifecycle tools against a loopback Network controller.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";

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

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

async fn mount_site(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(server)
        .await;
}

fn voucher(id: &str, code: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "code": code, "name": "visitor",
        "createdAt": "2026-09-28T00:00:00Z", "expired": false,
        "authorizedGuestCount": 1, "timeLimitMinutes": 60,
        "authorizedGuestLimit": 3
    })
}

#[tokio::test]
async fn search_pages_redeemable_codes_and_detail_reads_the_same_code() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/hotspot/vouchers")))
        .and(query_param("offset", "0"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 1, "count": 1, "totalCount": 2,
            "data": [voucher("v1", "111-222")],
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(voucher("v1", "111-222")))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let search = handler
        .call(
            &call("vouchers.search", &serde_json::json!({"limit": 1})),
            None,
        )
        .await
        .expect("search");
    let output = search.structured_content.expect("structured");
    assert_eq!(output["vouchers"][0]["code"], "111-222");
    assert_eq!(output["nextOffset"], 1);
    assert_eq!(output["totalCount"], 2);
    assert_eq!(
        search.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
        true
    );

    let status = handler
        .call(
            &call("vouchers.status", &serde_json::json!({"voucherId": "v1"})),
            None,
        )
        .await
        .expect("status")
        .structured_content
        .expect("structured");
    assert_eq!(status["code"], "111-222");
    assert_eq!(status["authorizedGuestCount"], 1);
}

#[tokio::test]
async fn independent_transport_returns_existing_codes() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/hotspot/vouchers")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 25, "count": 1, "totalCount": 1,
            "data": [voucher("v1", "111-222")],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(voucher("v1", "111-222")))
        .mount(&server)
        .await;
    let handler = handler_for(&server).with_local_transport();
    let list = handler
        .call(&call("vouchers.search", &serde_json::json!({})), None)
        .await
        .expect("voucher search")
        .structured_content
        .expect("structured");
    assert_eq!(list["vouchers"][0]["code"], "111-222");
    let detail = handler
        .call(
            &call("vouchers.status", &serde_json::json!({"voucherId": "v1"})),
            None,
        )
        .await
        .expect("voucher status")
        .structured_content
        .expect("structured");
    assert_eq!(detail["code"], "111-222");
}

#[tokio::test]
async fn search_rejects_invalid_page_before_contacting_the_controller() {
    let server = MockServer::start().await;
    let error = handler_for(&server)
        .call(
            &call("vouchers.search", &serde_json::json!({"limit": 0})),
            None,
        )
        .await
        .expect_err("invalid limit");
    assert!(error.message.contains("limit must be 1-100"));
}

#[tokio::test]
async fn search_refuses_a_controller_page_for_the_wrong_offset() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let response = serde_json::json!({
        "offset": 0, "limit": 1, "count": 1, "totalCount": 2,
        "data": [voucher("v1", "111-222")],
        "controllerDetail": "voucher-page-tail".repeat(100),
    });
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/hotspot/vouchers")))
        .and(query_param("offset", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "vouchers.search",
                &serde_json::json!({"offset": 1, "limit": 1}),
            ),
            None,
        )
        .await
        .expect_err("wrong page");
    assert!(error.message.contains("inconsistent voucher page"));
    assert!(error.message.contains(&response.to_string()));
}

#[tokio::test]
async fn status_and_revoke_preview_preserve_a_mismatched_controller_detail() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let response = serde_json::json!({
        "id": "other-voucher", "code": "111-222", "name": "visitor",
        "createdAt": "2026-09-28T00:00:00Z", "expired": false,
        "authorizedGuestCount": 1, "timeLimitMinutes": 60,
        "authorizedGuestLimit": 3,
        "controllerDetail": "voucher-detail-tail".repeat(100),
    });
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for name in ["vouchers.status", "vouchers.revoke"] {
        let error = handler
            .call(&call(name, &serde_json::json!({"voucherId": "v1"})), None)
            .await
            .expect_err("wrong voucher");
        assert!(error.message.contains("different voucher id"), "{error}");
        assert!(error.message.contains(&response.to_string()), "{error}");
    }
}

#[tokio::test]
async fn revoke_previews_without_deleting_and_confirmed_revoke_checks_absence() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let reads = Arc::new(AtomicUsize::new(0));
    let reads_for_response = Arc::clone(&reads);
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(move |_: &wiremock::Request| {
            if reads_for_response.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(200).set_body_json(voucher("v1", "111-222"))
            } else {
                ResponseTemplate::new(404).set_body_string("voucher no longer exists")
            }
        })
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string("controller revoked voucher"))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let preview = handler
        .call(
            &call("vouchers.revoke", &serde_json::json!({"voucherId": "v1"})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["applied"], false);
    assert!(preview.get("verified").is_none());
    assert!(preview.get("code").is_none());

    let confirmed = handler
        .call(
            &call(
                "vouchers.revoke",
                &serde_json::json!({"voucherId": "v1", "confirm": true}),
            ),
            None,
        )
        .await
        .expect("confirmed")
        .structured_content
        .expect("structured");
    assert_eq!(confirmed["applied"], true);
    assert_eq!(confirmed["responseStatus"], 200);
    assert_eq!(confirmed["responseBody"], "controller revoked voucher");
    assert_eq!(confirmed["verified"], true);
    assert_eq!(
        confirmed["readbackError"],
        "controller returned HTTP 404: voucher no longer exists"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn revoke_returns_controller_readback_failure_after_accepted_delete() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1");
    let failure = format!(
        "voucher lookup failed: {}voucher-readback-tail",
        "x".repeat(50_000)
    );
    let accepted_body = format!("voucher accepted: {}controller-tail", "y".repeat(50_000));
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(voucher("v1", "111-222")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(503).set_body_string(failure.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_string(accepted_body.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "vouchers.revoke",
                &serde_json::json!({"voucherId": "v1", "confirm": true}),
            ),
            None,
        )
        .await
        .expect("delete was accepted");
    let content = serde_json::to_value(&result.content).expect("content");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(output["responseBodyInContent"], true);
    assert!(output.get("verified").is_none());
    assert!(output.get("readbackError").is_none());
    assert_eq!(output["readbackErrorInContent"], true);
    assert!(content.to_string().contains(&failure));
    assert!(content.to_string().contains(&accepted_body));
}

#[tokio::test]
async fn accepted_voucher_deletion_returns_before_a_stalled_readback() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(voucher("v1", "111-222")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(6)))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("controller accepted voucher deletion"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let handler = handler_for(&server).with_request_limits(1, Duration::from_secs(2));
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        handler.call(
            &call(
                "vouchers.revoke",
                &serde_json::json!({"voucherId": "v1", "confirm": true}),
            ),
            None,
        ),
    )
    .await
    .expect("completed before the outer deadline")
    .expect("accepted deletion remains available");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(
        output["responseBody"],
        "controller accepted voucher deletion"
    );
    assert_eq!(output["readbackError"], "voucher readback timed out");
    assert!(output.get("verified").is_none());
}

#[tokio::test]
async fn revoke_reports_a_controller_that_acknowledges_but_keeps_the_voucher() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let response = serde_json::json!({
        "id": "v1", "code": "111-222", "name": "visitor",
        "createdAt": "2026-09-28T00:00:00Z", "expired": false,
        "authorizedGuestCount": 1, "timeLimitMinutes": 60,
        "authorizedGuestLimit": 3,
        "controllerDetail": "persisted-voucher-tail".repeat(100),
    });
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "vouchers.revoke",
                &serde_json::json!({"voucherId": "v1", "confirm": true}),
            ),
            None,
        )
        .await
        .expect("controller acknowledged deletion")
        .structured_content
        .expect("structured");
    assert_eq!(result["verified"], false);
    assert!(
        result["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&response.to_string())
    );
    assert_eq!(
        result["warnings"][0],
        "controller acknowledged deletion but the voucher still exists"
    );
}

#[tokio::test]
async fn revoke_keeps_a_readback_for_a_different_voucher_without_claiming_absence() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(voucher("v1", "111-222")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let mut response = voucher("another-voucher", "333-444");
    response["controllerDetail"] = serde_json::json!("wrong-voucher-tail".repeat(100));
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &call(
                "vouchers.revoke",
                &serde_json::json!({"voucherId": "v1", "confirm": true}),
            ),
            None,
        )
        .await
        .expect("deletion was accepted")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert!(output.get("verified").is_none());
    assert!(
        output["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&response.to_string())
    );
}
