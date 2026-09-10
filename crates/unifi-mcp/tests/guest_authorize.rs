//! End-to-end tests for guest authorization against loopback fakes.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};
use zeroize::Zeroizing;

const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const CLIENT_ID: &str = "client-42";
const MAC: &str = "aa:bb:cc:dd:ee:ff";

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
        vec![Zeroizing::new("test-legacy-password".to_owned())],
    )
}

fn authorize(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "guests.authorize".to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

/// The controller's client list, which resolves an address to its id.
async fn mount_clients(server: &MockServer, rows: &serde_json::Value, total: u64) {
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites/{SITE_ID}/clients")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 200,
            "count": rows.as_array().expect("rows").len(),
            "totalCount": total,
            "data": rows,
        })))
        .mount(server)
        .await;
}

async fn mount_site(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn an_unconfirmed_authorization_describes_itself_and_authorizes_nothing() {
    let server = MockServer::start().await;
    // Nothing is mounted: a preview must not reach the controller at all,
    // and an action endpoint would fail this test if it were called.

    let output = handler_for(&server)
        .call(&authorize(&serde_json::json!({"client": MAC})), None)
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["client"], MAC);
    assert!(
        output["warnings"]
            .to_string()
            .contains("gains access to the guest network"),
        "{output}"
    );
}

#[tokio::test]
async fn a_confirmed_authorization_posts_the_action() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": "AA:BB:CC:DD:EE:FF"}]),
        1,
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .and(body_json(
            serde_json::json!({"action": "AUTHORIZE_GUEST_ACCESS"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({"client": MAC, "confirm": true})),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
}

#[tokio::test]
async fn the_result_says_the_effect_cannot_be_read_back() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": MAC}]),
        1,
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    // The controller exposes no authorization field on a client. Reporting
    // an accepted request as a verified outcome would be the false
    // confidence the write surface exists to avoid, so the result says so on
    // both paths rather than leaving a caller to assume.
    for confirm in [false, true] {
        let output = handler_for(&server)
            .call(
                &authorize(&serde_json::json!({"client": MAC, "confirm": confirm})),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("confirm={confirm}: {error}"))
            .structured_content
            .expect("structured");
        assert_eq!(output["verifiable"], false, "confirm={confirm}");
    }
}

#[tokio::test]
async fn a_selector_that_is_not_a_client_id_is_refused_before_any_controller_call() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for selector in ["", "client-42", "ff:ff:ff:ff:ff:ff", "aa:bb:cc"] {
        let error = handler
            .call(&authorize(&serde_json::json!({"client": selector})), None)
            .await
            .expect_err(selector);
        assert!(
            error.message.contains("unicast MAC address"),
            "{selector}: {}",
            error.message
        );
    }
}

#[tokio::test]
async fn an_address_the_controller_does_not_know_authorizes_nothing() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(&server, &serde_json::json!([]), 0).await;
    // No action endpoint: resolving must fail before anything is authorized.

    let error = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({"client": MAC, "confirm": true})),
            None,
        )
        .await
        .expect_err("unknown address");
    assert!(
        error.message.contains("is known to the controller"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn a_scan_that_stopped_short_does_not_claim_the_client_is_unknown() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    // Full pages forever: the scan ends at its ceiling without reaching the
    // address, which is not the same as the address not existing.
    let rows: Vec<serde_json::Value> = (0..200)
        .map(|index| {
            serde_json::json!({"id": format!("c{index}"), "macAddress": format!("aa:bb:cc:00:00:{index:02x}")})
        })
        .collect();
    mount_clients(&server, &serde_json::json!(rows), 100_000).await;

    let error = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({"client": MAC, "confirm": true})),
            None,
        )
        .await
        .expect_err("scan ceiling");
    assert!(
        error.message.contains("stopped at its ceiling"),
        "{}",
        error.message
    );
}
