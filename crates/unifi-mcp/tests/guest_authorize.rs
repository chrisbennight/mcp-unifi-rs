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
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

fn authorize(arguments: &serde_json::Value) -> CallToolRequestParams {
    call("guests.authorize", arguments)
}

fn grant(at: &str) -> serde_json::Value {
    serde_json::json!({
        "authorizationMethod": "API",
        "authorizedAt": at,
        "expiresAt": "2026-09-29T00:00:00Z",
        "dataUsageLimitMBytes": 500,
        "usage": {"bytes": 10, "durationSec": 20, "rxBytes": 4, "txBytes": 6}
    })
}

async fn mount_detail(server: &MockServer, before: &serde_json::Value, after: &serde_json::Value) {
    let endpoint = format!("{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}");
    Mock::given(method("GET"))
        .and(path(&endpoint))
        .respond_with(ResponseTemplate::new(200).set_body_json(before))
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(&endpoint))
        .respond_with(ResponseTemplate::new(200).set_body_json(after))
        .mount(server)
        .await;
}

fn detail(authorized: bool, authorization: Option<&serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "id": CLIENT_ID, "macAddress": MAC,
        "access": {"type": "GUEST", "authorized": authorized, "authorization": authorization}
    })
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
            .contains("resets guest traffic counters"),
        "{output}"
    );
}

#[tokio::test]
async fn accepted_guest_grant_keeps_controller_readback_error() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": MAC}]),
        1,
    )
    .await;
    let endpoint = format!("{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}");
    let failure = format!("guest read failed: {}guest-readback-tail", "x".repeat(700));
    Mock::given(method("GET"))
        .and(path(&endpoint))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail(false, None)))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&endpoint))
        .respond_with(ResponseTemplate::new(503).set_body_string(failure.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "action": "AUTHORIZE_GUEST_ACCESS",
            "grantedAuthorization": grant("2026-09-28T00:00:00Z")
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({"client": MAC, "confirm": true})),
            None,
        )
        .await
        .expect("action accepted")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["grantedAuthorization"]["dataUsageLimitMBytes"], 500);
    assert_eq!(
        output["readbackError"],
        format!("controller returned HTTP 503: {failure}")
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
    mount_detail(
        &server,
        &detail(false, None),
        &detail(true, Some(&grant("2026-09-28T00:00:00Z"))),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .and(body_json(
            serde_json::json!({"action": "AUTHORIZE_GUEST_ACCESS"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "action": "AUTHORIZE_GUEST_ACCESS",
            "grantedAuthorization": grant("2026-09-28T00:00:00Z")
        })))
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
    assert_eq!(output["verified"], true);
    assert_eq!(output["authorizedBefore"], false);
    assert_eq!(output["authorizedAfter"], true);
    assert_eq!(output["grantedAuthorization"]["dataUsageLimitMBytes"], 500);
}

#[tokio::test]
async fn malformed_guest_action_reaches_the_tool_caller() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": MAC}]),
        1,
    )
    .await;
    let before = detail(false, None);
    mount_detail(&server, &before, &before).await;
    let body = serde_json::json!({
        "action": "AUTHORIZE_GUEST_ACCESS",
        "padding": "x".repeat(700),
        "z_controller_field": "original-guest-action-tail",
    });
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .and(body_json(
            serde_json::json!({"action": "AUTHORIZE_GUEST_ACCESS"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;

    let error = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({"client": MAC, "confirm": true})),
            None,
        )
        .await
        .expect_err("missing action grant");
    assert!(
        error.message.contains(&body.to_string()),
        "{}",
        error.message
    );
    assert!(error.message.contains("action/grantedAuthorization"));
}

#[tokio::test]
async fn repeated_authorization_returns_revoked_and_new_grants() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": MAC}]),
        1,
    )
    .await;
    mount_detail(
        &server,
        &detail(true, Some(&grant("2026-09-27T00:00:00Z"))),
        &detail(true, Some(&grant("2026-09-28T00:00:00Z"))),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .and(body_json(serde_json::json!({
            "action": "AUTHORIZE_GUEST_ACCESS", "timeLimitMinutes": 120
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "action": "AUTHORIZE_GUEST_ACCESS",
            "grantedAuthorization": grant("2026-09-28T00:00:00Z"),
            "revokedAuthorization": grant("2026-09-27T00:00:00Z")
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({
                "client": MAC, "timeLimitMinutes": 120, "confirm": true
            })),
            None,
        )
        .await
        .expect("reauthorize")
        .structured_content
        .expect("structured");
    assert_eq!(output["authorizedBefore"], true);
    assert_eq!(output["verified"], true);
    assert_eq!(
        output["revokedAuthorization"]["authorizedAt"],
        "2026-09-27T00:00:00Z"
    );
    assert_eq!(
        output["grantedAuthorization"]["authorizedAt"],
        "2026-09-28T00:00:00Z"
    );
}

#[tokio::test]
async fn changed_limit_in_readback_is_visible_and_not_verified() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": MAC}]),
        1,
    )
    .await;
    let mut observed = grant("2026-09-28T00:00:00Z");
    observed["dataUsageLimitMBytes"] = serde_json::json!(100);
    mount_detail(
        &server,
        &detail(false, None),
        &detail(true, Some(&observed)),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "action": "AUTHORIZE_GUEST_ACCESS",
            "grantedAuthorization": grant("2026-09-28T00:00:00Z")
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({"client": MAC, "confirm": true})),
            None,
        )
        .await
        .expect("authorize")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], false);
    assert_eq!(output["grantedAuthorization"]["dataUsageLimitMBytes"], 500);
    assert_eq!(output["observedAuthorization"]["dataUsageLimitMBytes"], 100);
    assert!(output["warnings"].to_string().contains("not verified"));
}

#[tokio::test]
async fn guest_status_reports_current_grant_and_usage() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": MAC}]),
        1,
    )
    .await;
    let current = detail(true, Some(&grant("2026-09-28T00:00:00Z")));
    mount_detail(&server, &current, &current).await;

    let output = handler_for(&server)
        .call(
            &call("guests.status", &serde_json::json!({"client": MAC})),
            None,
        )
        .await
        .expect("status")
        .structured_content
        .expect("structured");
    assert_eq!(output["authorized"], true);
    assert_eq!(output["authorization"]["dataUsageLimitMBytes"], 500);
    assert_eq!(output["authorization"]["usage"]["bytes"], 10);
}

#[tokio::test]
async fn unauthorize_returns_revoked_grant_and_checks_state() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    mount_clients(
        &server,
        &serde_json::json!([{"id": CLIENT_ID, "macAddress": MAC}]),
        1,
    )
    .await;
    mount_detail(
        &server,
        &detail(true, Some(&grant("2026-09-28T00:00:00Z"))),
        &detail(false, None),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/clients/{CLIENT_ID}/actions"
        )))
        .and(body_json(
            serde_json::json!({"action": "UNAUTHORIZE_GUEST_ACCESS"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "action": "UNAUTHORIZE_GUEST_ACCESS",
            "revokedAuthorization": grant("2026-09-28T00:00:00Z")
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &call(
                "guests.unauthorize",
                &serde_json::json!({"client": MAC, "confirm": true}),
            ),
            None,
        )
        .await
        .expect("unauthorize")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], true);
    assert_eq!(output["authorizedAfter"], false);
    assert_eq!(output["revokedAuthorization"]["authorizationMethod"], "API");
}

#[tokio::test]
async fn invalid_limits_are_rejected_before_any_controller_call() {
    let server = MockServer::start().await;
    let error = handler_for(&server)
        .call(
            &authorize(&serde_json::json!({"client": MAC, "timeLimitMinutes": 0, "confirm": true})),
            None,
        )
        .await
        .expect_err("invalid limit");
    assert!(error.message.contains("limits"), "{}", error.message);
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
