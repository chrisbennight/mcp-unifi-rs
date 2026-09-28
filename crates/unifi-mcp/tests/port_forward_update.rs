//! End-to-end tests for the port forward write against loopback fakes.

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

const PASSWORD: &str = "test-legacy-password";
const LEGACY: &str = "/proxy/network/api/s/default";
const FORWARD: &str = "pf-1";

fn ok_envelope(data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"meta": {"rc": "ok"}, "data": data})
}

/// One stored port forward. `purpose` is a property this server does not
/// model, so it stands in for everything a controller keeps beyond the
/// projection.
fn stored(enabled: bool, name: &str) -> serde_json::Value {
    serde_json::json!({
        "_id": FORWARD,
        "name": name,
        "enabled": enabled,
        "src": "any",
        "fwd": "10.0.0.5",
        "fwd_port": "8123",
        "dst_port": "8123",
        "proto": "tcp",
        "purpose": "unmodeled",
    })
}

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
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn update(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "port_forwards.update".to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

async fn logged_in(server: &MockServer) {
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

/// The rule as it reads before the write, and again after. Registering the
/// first reading with a single use lets one test describe both moments.
async fn reads(server: &MockServer, before: &serde_json::Value, after: &serde_json::Value) {
    logged_in(server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/portforward/{FORWARD}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([before]))),
        )
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/portforward/{FORWARD}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([after]))),
        )
        .mount(server)
        .await;
}

/// Accepts the write and reports success, which is all a controller promises.
async fn accepts_the_write(server: &MockServer, expected_body: &serde_json::Value) {
    Mock::given(method("PUT"))
        .and(path(format!("{LEGACY}/rest/portforward/{FORWARD}")))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn an_unconfirmed_change_describes_itself_and_writes_nothing() {
    let server = MockServer::start().await;
    let record = stored(false, "Home Assistant");
    reads(&server, &record, &record).await;
    // No PUT is mounted: a write would fail this test.

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"enabled": true},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["forward"]["forwardTo"], "10.0.0.5");
    assert_eq!(
        output["changes"],
        serde_json::json!([{"field": "enabled", "from": false, "to": true}])
    );
    assert!(
        output["warnings"]
            .to_string()
            .contains("exposes the internal host's port"),
        "{output}"
    );
}

#[tokio::test]
async fn a_confirmed_change_sends_only_the_named_fields_and_reads_the_result_back() {
    let server = MockServer::start().await;
    reads(
        &server,
        &stored(false, "Home Assistant"),
        &stored(true, "Home Assistant"),
    )
    .await;
    // A patch carrying `name` would rename the rule the caller did not ask to
    // rename, so the absent field must not be sent at all.
    accepts_the_write(&server, &serde_json::json!({"enabled": true})).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"enabled": true},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], true);
    assert_eq!(
        output["fields"],
        serde_json::json!([{
            "field": "enabled",
            "status": "persisted",
            "previous": false,
            "requested": true,
            "observed": true,
        }])
    );
    assert_eq!(output["forward"]["enabled"], true);
}

#[tokio::test]
async fn a_confirmed_rename_verifies_instead_of_reporting_itself_as_collateral() {
    let server = MockServer::start().await;
    reads(
        &server,
        &stored(true, "Home Assistant"),
        &stored(true, "Home Assistant (moved)"),
    )
    .await;
    accepts_the_write(
        &server,
        &serde_json::json!({"name": "Home Assistant (moved)"}),
    )
    .await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"name": "Home Assistant (moved)"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    // The property the caller asked to change is the one the write changed,
    // so it belongs in `fields`, never in the collateral report. Naming it in
    // both would have the result contradict itself.
    assert_eq!(output["fields"][0]["status"], "persisted");
    assert_eq!(output["unexpectedChanges"], serde_json::json!([]));
    assert_eq!(output["verified"], true);
}

#[tokio::test]
async fn a_confirmed_rule_change_sends_and_verifies_the_match_and_target() {
    let server = MockServer::start().await;
    let before = stored(true, "Home Assistant");
    let mut after = before.clone();
    after["src"] = serde_json::json!("203.0.113.0/24");
    after["fwd"] = serde_json::json!("10.0.0.8");
    after["fwd_port"] = serde_json::json!("8443");
    after["dst_port"] = serde_json::json!("443");
    after["proto"] = serde_json::json!("tcp_udp");
    reads(&server, &before, &after).await;
    accepts_the_write(
        &server,
        &serde_json::json!({
            "src": "203.0.113.0/24", "fwd": "10.0.0.8", "fwd_port": "8443",
            "dst_port": "443", "proto": "tcp_udp"
        }),
    )
    .await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {
                    "source": "203.0.113.0/24", "forwardTo": "10.0.0.8",
                    "forwardPort": "8443", "destinationPort": "443", "protocol": "tcp_udp"
                },
                "confirm": true
            })),
            None,
        )
        .await
        .expect("rule change")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], true);
    assert_eq!(output["unexpectedChanges"], serde_json::json!([]));
    assert_eq!(output["forward"]["forwardTo"], "10.0.0.8");
    assert_eq!(output["forward"]["destinationPort"], "443");
    assert_eq!(
        output["fields"].as_array().expect("field outcomes").len(),
        5
    );
    for field in output["fields"].as_array().expect("field outcomes") {
        assert_eq!(field["status"], "persisted");
    }
}

#[tokio::test]
async fn a_rule_target_preview_names_the_previous_and_requested_values() {
    let server = MockServer::start().await;
    let record = stored(true, "Home Assistant");
    reads(&server, &record, &record).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"forwardTo": "10.0.0.8"}
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(
        output["changes"],
        serde_json::json!([{
            "field": "forwardTo", "from": "10.0.0.5", "to": "10.0.0.8"
        }])
    );
    assert!(
        output["warnings"]
            .to_string()
            .contains("changes which traffic is forwarded")
    );
}

#[tokio::test]
async fn a_field_the_controller_discarded_is_reported_as_dropped() {
    let server = MockServer::start().await;
    // The controller acknowledges the write and keeps the old value, which is
    // the failure mode reading back exists to catch.
    let record = stored(false, "Home Assistant");
    reads(&server, &record, &record).await;
    accepts_the_write(&server, &serde_json::json!({"enabled": true})).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"enabled": true},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], false);
    assert_eq!(output["fields"][0]["status"], "dropped");
}

#[tokio::test]
async fn a_property_that_moved_without_being_asked_for_is_named() {
    let server = MockServer::start().await;
    let mut after = stored(true, "Home Assistant");
    // A property this server does not model, changed by the same write.
    after["purpose"] = serde_json::json!("rewritten");
    reads(&server, &stored(false, "Home Assistant"), &after).await;
    accepts_the_write(&server, &serde_json::json!({"enabled": true})).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"enabled": true},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["unexpectedChanges"], serde_json::json!(["purpose"]));
    assert_eq!(output["verified"], false);
}

#[tokio::test]
async fn disabling_a_rule_says_what_stops_working() {
    let server = MockServer::start().await;
    let record = stored(true, "Home Assistant");
    reads(&server, &record, &record).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"enabled": false},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert!(
        output["warnings"]
            .to_string()
            .contains("stops forwarding traffic to the internal host"),
        "{output}"
    );
}

#[tokio::test]
async fn a_request_that_changes_nothing_is_refused_before_any_controller_call() {
    let server = MockServer::start().await;
    // Nothing is mounted: both refusals are decided from the request alone.
    let handler = handler_for(&server);

    let empty = handler
        .call(
            &update(&serde_json::json!({"portForward": FORWARD, "changes": {}})),
            None,
        )
        .await
        .expect_err("no field");
    assert!(
        empty.message.contains("names no field to change"),
        "{}",
        empty.message
    );

    let unknown = handler
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"destinatonPort": "443"},
            })),
            None,
        )
        .await
        .expect_err("unknown field");
    // A misspelling is the likeliest way a caller loses a change, so the
    // rejection names what would have been accepted.
    assert!(
        unknown.message.contains("destinatonPort") && unknown.message.contains("destinationPort"),
        "{}",
        unknown.message
    );
}

#[tokio::test]
async fn an_id_that_names_no_rule_changes_nothing() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let mut response = ok_envelope(&serde_json::json!([]));
    response["controllerDetail"] =
        serde_json::json!(format!("{}missing-rule-tail", "x".repeat(700)));
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/portforward/{FORWARD}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&server)
        .await;
    // No PUT is mounted: the read must fail before anything is written.

    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"enabled": true},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect_err("unknown id");
    // The accepted response is reported directly, and the absent PUT mock
    // proves nothing was written.
    assert!(error.message.contains(&response.to_string()));
    assert!(error.message.contains("missing-rule-tail"));
    assert!(error.message.contains("no row for requested id"));
}
