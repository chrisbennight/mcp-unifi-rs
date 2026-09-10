//! End-to-end tests for the client control actions against loopback fakes.

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
const MAC: &str = "aa:bb:cc:dd:ee:ff";

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
    params.name = "clients.control".to_owned().into();
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

fn connected_row() -> serde_json::Value {
    serde_json::json!([{"mac": MAC, "hostname": "laptop", "ip": "192.168.1.20"}])
}

/// The connected-client list, once before the action and once after.
async fn mount_client_list(
    server: &MockServer,
    before: &serde_json::Value,
    after: &serde_json::Value,
) {
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(before)))
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/stat/sta")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(after)))
        .mount(server)
        .await;
}

async fn expect_command(server: &MockServer, command: &str) {
    Mock::given(method("POST"))
        .and(path(format!("{LEGACY}/cmd/stamgr")))
        .and(body_json(serde_json::json!({"cmd": command, "mac": MAC})))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([]))))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn an_unconfirmed_action_describes_itself_and_sends_no_command() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    mount_client_list(&server, &connected_row(), &connected_row()).await;
    // No command endpoint is mounted: sending one would fail this test.

    let output = handler_for(&server)
        .call(
            &control(&serde_json::json!({"client": MAC, "action": "block"})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["action"], "block");
    assert_eq!(output["connectedBefore"], true);
    assert!(output.get("connectedAfter").is_none());
    assert!(
        output["warnings"]
            .to_string()
            .contains("denies this client network access"),
        "{output}"
    );
}

#[tokio::test]
async fn a_confirmed_block_sends_the_command_and_reports_the_client_gone() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    // A blocked client leaves the connected list, which is the observable.
    mount_client_list(&server, &connected_row(), &serde_json::json!([])).await;
    expect_command(&server, "block-sta").await;

    let output = handler_for(&server)
        .call(
            &control(&serde_json::json!({
                "client": MAC,
                "action": "block",
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["connectedBefore"], true);
    assert_eq!(output["connectedAfter"], false);
}

#[tokio::test]
async fn each_action_sends_its_own_controller_command() {
    for (action, command) in [
        ("block", "block-sta"),
        ("unblock", "unblock-sta"),
        ("reconnect", "kick-sta"),
    ] {
        let server = MockServer::start().await;
        logged_in(&server).await;
        mount_client_list(&server, &connected_row(), &connected_row()).await;
        expect_command(&server, command).await;

        handler_for(&server)
            .call(
                &control(&serde_json::json!({
                    "client": MAC,
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
async fn an_address_that_is_not_a_mac_is_refused_before_any_controller_call() {
    let server = MockServer::start().await;
    // Nothing is mounted: a name cannot identify a blocked client, which is
    // absent from the connected list, so the selector is refused outright.
    for selector in [
        "laptop",
        "192.168.1.20",
        "aa-bb-cc-dd-ee-ff",
        "aa:bb:cc",
        // Group and broadcast addresses are well formed and name no client.
        "ff:ff:ff:ff:ff:ff",
        "01:00:5e:00:00:01",
        // The unset placeholder a controller reports when it has no address.
        "00:00:00:00:00:00",
        // Long, colon-heavy input is rejected on length before it is parsed.
        &":".repeat(4096),
        // The integer parser accepts a leading sign; an octet is two hex
        // digits, so these are not addresses.
        "+2:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:+f",
    ] {
        let error = handler_for(&server)
            .call(
                &control(&serde_json::json!({"client": selector, "action": "block"})),
                None,
            )
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
async fn disconnecting_a_client_that_is_not_connected_says_so() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    mount_client_list(&server, &serde_json::json!([]), &serde_json::json!([])).await;

    let output = handler_for(&server)
        .call(
            &control(&serde_json::json!({"client": MAC, "action": "reconnect"})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["connectedBefore"], false);
    assert!(
        output["warnings"]
            .to_string()
            .contains("nothing to disconnect"),
        "{output}"
    );
}

#[tokio::test]
async fn every_action_states_its_consequence_before_it_is_confirmed() {
    // A preview exists to let an operator decide, so each action says what it
    // does to the client — including unblock, which restores access.
    for (action, expected) in [
        ("block", "denies this client network access"),
        ("unblock", "lifts a block"),
        ("reconnect", "disconnects the client"),
    ] {
        let server = MockServer::start().await;
        logged_in(&server).await;
        mount_client_list(&server, &connected_row(), &connected_row()).await;

        let output = handler_for(&server)
            .call(
                &control(&serde_json::json!({"client": MAC, "action": action})),
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

#[tokio::test]
async fn an_address_is_matched_however_the_caller_cased_it() {
    let server = MockServer::start().await;
    logged_in(&server).await;
    mount_client_list(&server, &connected_row(), &connected_row()).await;
    // The controller stores lowercase; a caller pasting from a label does not.
    expect_command(&server, "block-sta").await;

    let output = handler_for(&server)
        .call(
            &control(&serde_json::json!({
                "client": "AA:BB:CC:DD:EE:FF",
                "action": "block",
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["client"], MAC);
    assert_eq!(output["connectedBefore"], true);
}
