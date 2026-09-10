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
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "home",
        "default",
        vec![Zeroizing::new(PASSWORD.to_owned())],
    )
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
                "changes": {"destinationPort": "443"},
            })),
            None,
        )
        .await
        .expect_err("unknown field");
    // A misspelling is the likeliest way a caller loses a change, so the
    // rejection names what would have been accepted.
    assert!(
        unknown.message.contains("destinationPort") && unknown.message.contains("name, enabled"),
        "{}",
        unknown.message
    );
}

#[tokio::test]
async fn a_name_carrying_the_redaction_marker_is_refused_before_any_controller_call() {
    let server = MockServer::start().await;
    // Nothing is mounted: the refusal is decided from the request alone.
    // Every returned string is scrubbed of configured credential material, so
    // a name read back can carry the marker; writing it over the real name is
    // what this refuses.
    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "portForward": FORWARD,
                "changes": {"name": "[redacted]"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect_err("redaction marker");
    assert!(
        error.message.contains("redaction marker"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn an_id_that_names_no_rule_changes_nothing() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/portforward/{FORWARD}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
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
    // The upstream rejection is never echoed: the caller gets the bounded
    // message, and the absent PUT mock proves nothing was written.
    assert!(
        error.message.contains("controller rejected the request"),
        "{}",
        error.message
    );
}
