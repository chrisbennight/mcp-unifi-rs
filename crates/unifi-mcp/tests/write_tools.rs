//! End-to-end tests for the write surface against loopback fakes.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const PASSWORD: &str = "test-legacy-password";
const LEGACY: &str = "/proxy/network/api/s/default";
const WLAN_ID: &str = "wlan-1";

fn ok_envelope(data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"meta": {"rc": "ok"}, "data": data})
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

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

/// One wireless network as the controller stores it.
fn wlan_row(ssid: &str, enabled: bool, hidden: bool) -> serde_json::Value {
    serde_json::json!({
        "_id": WLAN_ID,
        "name": ssid,
        "enabled": enabled,
        "security": "wpapsk",
        "x_passphrase": "current-wifi-secret",
        "networkconf_id": "net-lan",
        "hide_ssid": hidden,
    })
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

/// A confirmed write reads the resource once on each side; each read yields
/// both the modeled projection and the whole-record digest.
async fn mount_reads(server: &MockServer, before: &serde_json::Value, after: &serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([before]))),
        )
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([after]))),
        )
        .mount(server)
        .await;
}

async fn mount_write(server: &MockServer) {
    Mock::given(method("PUT"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(server)
        .await;
}

fn update(arguments: &serde_json::Value) -> CallToolRequestParams {
    call("wlans.update", arguments)
}

#[tokio::test]
async fn an_unconfirmed_change_describes_itself_and_writes_nothing() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    mount_reads(
        &server,
        &wlan_row("Home", true, false),
        &wlan_row("Home", true, false),
    )
    .await;
    // No PUT is mounted: any write would fail this test.

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"enabled": false, "ssid": "Household"},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert!(output.get("fields").is_none());
    assert_eq!(output["changes"].as_array().expect("changes").len(), 2);
    let warnings = output["warnings"].to_string();
    assert!(warnings.contains("drops every client"), "{warnings}");
    assert!(warnings.contains("reconnect"), "{warnings}");
}

#[tokio::test]
async fn a_confirmed_change_is_applied_and_verified_by_reading_it_back() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    mount_reads(
        &server,
        &wlan_row("Home", true, false),
        &wlan_row("Home", true, true),
    )
    .await;
    mount_write(&server).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"hidden": true},
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
    assert_eq!(output["fields"][0]["field"], "hidden");
    assert_eq!(output["fields"][0]["status"], "persisted");
}

#[tokio::test]
async fn a_field_the_controller_discarded_reads_dropped_though_the_write_succeeded() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // The controller acknowledges the write and stores none of it. This is
    // the failure the tool exists to expose.
    mount_reads(
        &server,
        &wlan_row("Home", true, false),
        &wlan_row("Home", true, false),
    )
    .await;
    mount_write(&server).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"hidden": true},
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
async fn a_property_this_server_does_not_model_cannot_be_cleared_unnoticed() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // Every modeled field matches the request, and a scheduling property the
    // server has never heard of is gone. Comparing only the projection would
    // certify this write as clean.
    let mut before = wlan_row("Home", true, false);
    before["schedule_with_duration"] = serde_json::json!([{"start": "0100"}]);
    mount_reads(&server, &before, &wlan_row("Home", true, true)).await;
    mount_write(&server).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"hidden": true},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["fields"][0]["status"], "persisted");
    assert_eq!(output["verified"], false, "{output}");
    assert_eq!(
        output["unexpectedChanges"],
        serde_json::json!(["schedule_with_duration"]),
        "{output}"
    );
}

#[tokio::test]
async fn a_passphrase_change_reports_its_outcome_without_either_value() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let mut after = wlan_row("Home", true, false);
    after["x_passphrase"] = serde_json::json!("brand-new-secret");
    mount_reads(&server, &wlan_row("Home", true, false), &after).await;
    mount_write(&server).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"passphrase": "brand-new-secret"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["fields"][0]["status"], "persisted");
    let rendered = output.to_string();
    assert!(!rendered.contains("brand-new-secret"), "{rendered}");
    assert!(!rendered.contains("current-wifi-secret"), "{rendered}");
}

#[tokio::test]
async fn encrypting_a_network_requires_the_key_in_the_same_call() {
    let server = MockServer::start().await;
    // Nothing is mounted at all: a request that can never be applied must be
    // refused before the controller is touched, and a preview of it must be
    // refused exactly as a confirmed call is.
    for confirm in [false, true] {
        let error = handler_for(&server)
            .call(
                &update(&serde_json::json!({
                    "wlan": WLAN_ID,
                    "changes": {"security": "wpapsk"},
                    "confirm": confirm,
                })),
                None,
            )
            .await
            .expect_err("key not stated");
        assert!(
            error.message.contains("passphrase in the same call"),
            "confirm={confirm}: {}",
            error.message
        );
    }
}

#[tokio::test]
async fn a_keyless_network_cannot_be_encrypted_without_a_stated_key() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let mut keyless = wlan_row("Guest", true, false);
    keyless["security"] = serde_json::json!("open");
    keyless["x_passphrase"] = serde_json::json!("");
    mount_reads(&server, &keyless, &keyless).await;
    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"security": "wpapsk"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect_err("key not stated");
    assert!(
        error.message.contains("passphrase in the same call"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn encryption_and_its_key_travel_in_one_request() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let mut open_network = wlan_row("Guest", true, false);
    open_network["security"] = serde_json::json!("open");
    let mut secured = open_network.clone();
    secured["security"] = serde_json::json!("wpapsk");
    secured["x_passphrase"] = serde_json::json!("stated-by-the-caller");
    mount_reads(&server, &open_network, &secured).await;
    Mock::given(method("PUT"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "security": "wpapsk",
            "x_passphrase": "stated-by-the-caller",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"security": "wpapsk", "passphrase": "stated-by-the-caller"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], true, "{output}");
    assert!(
        !output.to_string().contains("stated-by-the-caller"),
        "{output}"
    );
}

#[tokio::test]
async fn a_redacted_read_written_back_is_refused_before_any_controller_call() {
    let server = MockServer::start().await;
    // Nothing is mounted: the guard must fire before the network is read.
    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"passphrase": "[redacted]"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect_err("marker refused");
    assert!(
        error.message.contains("redaction marker"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn a_change_set_naming_nothing_is_refused_before_any_controller_call() {
    let server = MockServer::start().await;
    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({"wlan": WLAN_ID, "changes": {}})),
            None,
        )
        .await
        .expect_err("empty change set");
    assert!(
        error.message.contains("names no field to change"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn a_secret_reused_as_a_visible_value_is_still_kept_out_of_the_result() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // The caller sets the ssid to the same bytes as the passphrase. Omitting
    // the field named passphrase would still return the secret as an ssid.
    mount_reads(
        &server,
        &wlan_row("Home", true, false),
        &wlan_row("shared-secret-value", true, false),
    )
    .await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"ssid": "shared-secret-value", "passphrase": "shared-secret-value"},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert!(
        !output.to_string().contains("shared-secret-value"),
        "{output}"
    );
}

#[tokio::test]
async fn a_misspelled_change_field_is_named_along_with_the_accepted_ones() {
    let server = MockServer::start().await;
    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({"wlan": WLAN_ID, "changes": {"hideSsid": true}})),
            None,
        )
        .await
        .expect_err("unknown field");
    assert!(error.message.contains("hideSsid"), "{}", error.message);
    for accepted in ["ssid", "enabled", "security", "hidden", "passphrase"] {
        assert!(error.message.contains(accepted), "{}", error.message);
    }
}

#[tokio::test]
async fn overlapping_secrets_leave_no_fragment_in_a_result() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // The stored key contains the submitted one. Replacing them one at a time
    // consumes the shorter match first and leaves the rest of the longer key
    // in the text.
    let mut current = wlan_row("Home", true, false);
    current["x_passphrase"] = serde_json::json!("prefix-inner-suffix");
    let mut after = current.clone();
    after["name"] = serde_json::json!("prefix-inner-suffix");
    mount_reads(&server, &current, &after).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"ssid": "prefix-inner-suffix", "passphrase": "inner"},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    let rendered = output.to_string();
    assert!(!rendered.contains("prefix-"), "{rendered}");
    assert!(!rendered.contains("-suffix"), "{rendered}");
    assert!(!rendered.contains("inner"), "{rendered}");
}

#[tokio::test]
async fn a_secret_the_marker_would_reintroduce_withholds_the_result() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // "redact" is a substring of the marker, so substituting the marker puts
    // the secret back. No replacement scheme survives that, which is why the
    // result is withheld rather than returned.
    let mut current = wlan_row("redact", true, false);
    current["x_passphrase"] = serde_json::json!("redact");
    mount_reads(&server, &current, &current).await;

    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"ssid": "Home"},
            })),
            None,
        )
        .await
        .expect_err("withheld");
    assert!(error.message.contains("withheld"), "{}", error.message);
}
