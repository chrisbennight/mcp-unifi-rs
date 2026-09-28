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
use unifi_mcp::{UnifiMcp, handler::LocalAccess};
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
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "home",
        "default",
        vec![Zeroizing::new("test-integration-key".to_owned())],
    )
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
async fn independent_transport_requires_its_secret_grant_for_existing_codes() {
    let server = MockServer::start().await;
    let denied = handler_for(&server).with_local_access(LocalAccess {
        writes: false,
        secrets: false,
    });
    for (tool, arguments) in [
        ("vouchers.search", serde_json::json!({})),
        ("vouchers.status", serde_json::json!({"voucherId": "v1"})),
    ] {
        let error = denied
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("secret disclosure is disabled");
        assert!(error.message.contains("secret disclosure"), "{tool}");
    }
    // No controller endpoint was mounted, so a denial after a controller
    // request would fail with an upstream error instead.

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
    let allowed = handler_for(&server).with_local_access(LocalAccess {
        writes: false,
        secrets: true,
    });
    let list = allowed
        .call(&call("vouchers.search", &serde_json::json!({})), None)
        .await
        .expect("credential read granted")
        .structured_content
        .expect("structured");
    assert_eq!(list["vouchers"][0]["code"], "111-222");
    let detail = allowed
        .call(
            &call("vouchers.status", &serde_json::json!({"voucherId": "v1"})),
            None,
        )
        .await
        .expect("credential read granted")
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
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/hotspot/vouchers")))
        .and(query_param("offset", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 1, "count": 1, "totalCount": 2,
            "data": [voucher("v1", "111-222")],
        })))
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
                ResponseTemplate::new(404)
            }
        })
        .expect(3)
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
    assert_eq!(confirmed["verified"], true);
    assert_eq!(reads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn revoke_reports_a_controller_that_acknowledges_but_keeps_the_voucher() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(voucher("v1", "111-222")))
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
    assert_eq!(
        result["warnings"][0],
        "controller acknowledged deletion but the voucher still exists"
    );
}
