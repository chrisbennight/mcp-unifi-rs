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
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
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
async fn invalid_wireless_snapshot_returns_the_controller_response() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let marker = "wireless-controller-field-after-padding";
    let body = ok_envelope(&serde_json::json!([{
        "_id": 42,
        "padding": "x".repeat(700),
        "controller_field": marker,
    }]));
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;

    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"enabled": false},
            })),
            None,
        )
        .await
        .expect_err("invalid wireless snapshot");
    assert!(
        error.message.contains(&body.to_string()),
        "{}",
        error.message
    );
    assert!(error.message.contains("invalid type"), "{}", error.message);
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
async fn a_passphrase_change_reports_requested_and_observed_values() {
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
    assert!(rendered.contains("brand-new-secret"), "{rendered}");
    assert_eq!(
        output["fields"][0]["previous"], "current-wifi-secret",
        "{output}"
    );
}

#[tokio::test]
async fn selecting_wpapsk_can_retain_the_existing_passphrase() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let mut before = wlan_row("Guest", true, false);
    before["security"] = serde_json::json!("open");
    let mut after = before.clone();
    after["security"] = serde_json::json!("wpapsk");
    mount_reads(&server, &before, &after).await;
    Mock::given(method("PUT"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .and(wiremock::matchers::body_json(
            serde_json::json!({"security": "wpapsk"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"security": "wpapsk"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("existing passphrase retained")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], true, "{output}");
    assert_eq!(output["fields"][0]["field"], "security");
    assert_eq!(output["fields"][0]["previous"], "open");
    assert_eq!(output["fields"][0]["observed"], "wpapsk");
}

#[tokio::test]
async fn enterprise_security_and_radius_profile_are_sent_and_read_back() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let before = wlan_row("Office", true, false);
    let mut after = before.clone();
    after["security"] = serde_json::json!("wpaeap");
    after["radius_profile_id"] = serde_json::json!("radius-office");
    mount_reads(&server, &before, &after).await;
    Mock::given(method("PUT"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "security": "wpaeap",
            "radius_profile_id": "radius-office",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"security": "wpaeap", "radiusProfileId": "radius-office"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("enterprise update")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], true, "{output}");
    assert_eq!(output["fields"][0]["status"], "persisted");
    assert_eq!(output["fields"][1]["status"], "persisted");
    assert!(output.to_string().contains("radius-office"), "{output}");
}

#[tokio::test]
async fn a_keyless_network_mode_rejected_by_controller_is_reported_as_dropped() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let mut keyless = wlan_row("Guest", true, false);
    keyless["security"] = serde_json::json!("open");
    keyless["x_passphrase"] = serde_json::json!("");
    mount_reads(&server, &keyless, &keyless).await;
    Mock::given(method("PUT"))
        .and(path(format!("{LEGACY}/rest/wlanconf/{WLAN_ID}")))
        .and(wiremock::matchers::body_json(
            serde_json::json!({"security": "wpapsk"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"security": "wpapsk"},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("controller acknowledged the patch")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], false);
    assert_eq!(output["fields"][0]["status"], "dropped");
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
        output.to_string().contains("stated-by-the-caller"),
        "{output}"
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
async fn a_reused_controller_value_is_returned_in_the_result() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // The same controller value can appear in multiple selected fields.
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
        output.to_string().contains("shared-secret-value"),
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
    for accepted in [
        "ssid",
        "enabled",
        "security",
        "hidden",
        "passphrase",
        "radiusProfileId",
    ] {
        assert!(error.message.contains(accepted), "{}", error.message);
    }
}

#[tokio::test]
async fn overlapping_controller_values_are_returned_in_a_result() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // Both values retain their original bytes in the preview.
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
    assert!(rendered.contains("prefix-"), "{rendered}");
    assert!(rendered.contains("-suffix"), "{rendered}");
    assert!(rendered.contains("inner"), "{rendered}");
}

#[tokio::test]
async fn preview_returns_the_current_controller_value() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    let current = wlan_row("bluebird", true, false);
    mount_reads(&server, &current, &current).await;
    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "wlan": WLAN_ID,
                "changes": {"ssid": "Home"},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["changes"][0]["from"], "bluebird", "{output}");
}
