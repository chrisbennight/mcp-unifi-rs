//! End-to-end tests for the device control actions against loopback fakes.

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
const INTEGRATION: &str = "/proxy/network/integration/v1";
const LEGACY: &str = "/proxy/network/api/s/default";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const DEVICE: &str = "device-1";
const DEVICE_MAC: &str = "aa:bb:cc:dd:ee:01";

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

fn control(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "devices.control".to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

async fn site_and_device(server: &MockServer, state: &str) {
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/{DEVICE}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": DEVICE,
            "name": "Office Switch",
            "macAddress": DEVICE_MAC,
            "state": state,
        })))
        .mount(server)
        .await;
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

#[tokio::test]
async fn an_unconfirmed_action_describes_itself_and_sends_no_command() {
    let server = MockServer::start().await;
    site_and_device(&server, "ONLINE").await;
    // No action endpoint is mounted: any command would fail this test.

    let output = handler_for(&server)
        .call(
            &control(&serde_json::json!({"device": DEVICE, "action": "restart"})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["name"], "Office Switch");
    assert_eq!(output["stateBefore"], "ONLINE");
    assert!(output.get("stateAfter").is_none());
    assert!(
        output["warnings"]
            .to_string()
            .contains("takes the device offline"),
        "{output}"
    );
}

#[tokio::test]
async fn a_confirmed_restart_posts_the_action_and_reports_the_state_either_side() {
    let server = MockServer::start().await;
    site_and_device(&server, "ONLINE").await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/{DEVICE}/actions"
        )))
        .and(body_json(serde_json::json!({"action": "RESTART"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &control(&serde_json::json!({
                "device": DEVICE,
                "action": "restart",
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    // A restart takes longer than the read, so the state legitimately still
    // reads ONLINE; the result records what was seen, not that it finished.
    assert_eq!(output["stateBefore"], "ONLINE");
    assert_eq!(output["stateAfter"], "ONLINE");
}

#[tokio::test]
async fn a_port_cycle_posts_to_the_named_port() {
    let server = MockServer::start().await;
    site_and_device(&server, "ONLINE").await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/devices/{DEVICE}/interfaces/ports/7/actions"
        )))
        .and(body_json(serde_json::json!({"action": "POWER_CYCLE"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &control(&serde_json::json!({
                "device": DEVICE,
                "action": "portCycle",
                "port": 7,
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["port"], 7);
    assert!(
        output["warnings"]
            .to_string()
            .contains("reboots whatever it powers"),
        "{output}"
    );
}

#[tokio::test]
async fn locating_uses_the_hardware_address_the_device_record_carries() {
    for (action, command) in [("locate", "set-locate"), ("endLocate", "unset-locate")] {
        let server = MockServer::start().await;
        site_and_device(&server, "ONLINE").await;
        logged_in(&server).await;
        Mock::given(method("POST"))
            .and(path(format!("{LEGACY}/cmd/devmgr")))
            .and(body_json(
                serde_json::json!({"cmd": command, "mac": DEVICE_MAC}),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))),
            )
            .expect(1)
            .mount(&server)
            .await;

        handler_for(&server)
            .call(
                &control(&serde_json::json!({
                    "device": DEVICE,
                    "action": action,
                    "confirm": true,
                })),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{action}: {error}"));
    }
}

#[tokio::test]
async fn a_port_belongs_to_a_port_cycle_and_nothing_else() {
    let server = MockServer::start().await;
    // Nothing is mounted: both mismatches are decided from the request alone.
    let handler = handler_for(&server);

    let missing = handler
        .call(
            &control(&serde_json::json!({"device": DEVICE, "action": "portCycle"})),
            None,
        )
        .await
        .expect_err("port required");
    assert!(
        missing.message.contains("requires the port"),
        "{}",
        missing.message
    );

    let unwanted = handler
        .call(
            &control(&serde_json::json!({
                "device": DEVICE,
                "action": "restart",
                "port": 7,
            })),
            None,
        )
        .await
        .expect_err("port rejected");
    assert!(
        unwanted.message.contains("applies only to portCycle"),
        "{}",
        unwanted.message
    );
}

#[tokio::test]
async fn every_action_states_its_consequence_before_it_is_confirmed() {
    for (action, expected) in [
        ("restart", "takes the device offline"),
        ("locate", "flashes its locate LED"),
        ("endLocate", "stops flashing"),
    ] {
        let server = MockServer::start().await;
        site_and_device(&server, "ONLINE").await;

        let output = handler_for(&server)
            .call(
                &control(&serde_json::json!({"device": DEVICE, "action": action})),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{action}: {error}"))
            .structured_content
            .expect("structured");
        assert!(
            output["warnings"].to_string().contains(expected),
            "{action}: {output}"
        );
    }
}
