//! Fixed Protect device actions against bounded loopback responses.

use std::{sync::Arc, time::Duration};

use rmcp::model::{CallToolRequestParams, ContentBlock};
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, ProtectClient, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/protect/integration/v1";

fn handler_for(server: &MockServer) -> UnifiMcp {
    let protect = ProtectClient::new(&ControllerConfig {
        name: "cameras".to_owned(),
        base_url: Url::parse(&server.uri()).expect("mock server uri"),
        api_key: Zeroizing::new("test-protect-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("protect client");
    UnifiMcp::new_protect("cameras", Arc::new(protect), None)
}

fn call(arguments: &Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "protect.devices.action".into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

#[tokio::test]
async fn documented_device_actions_use_only_their_fixed_routes_and_wire_bodies() {
    let cases = [
        (
            json!({"kind":"sirenPlay","duration":10}),
            "sirens/device-1/play",
            Some(json!({"duration":10})),
        ),
        (json!({"kind":"sirenStop"}), "sirens/device-1/stop", None),
        (
            json!({"kind":"sirenTestSound","volume":80}),
            "sirens/device-1/test-sound",
            Some(json!({"volume":80})),
        ),
        (
            json!({"kind":"relayActivate","outputId":"out-1","state":"on","pulseDuration":5000}),
            "relays/device-1/outputs/out-1/activate",
            Some(json!({"state":"on","pulseDuration":5000})),
        ),
        (
            json!({"kind":"speakerTestSound","volume":0}),
            "speakers/device-1/test-sound",
            Some(json!({"volume":0})),
        ),
        (
            json!({"kind":"alarmHubTrigger","outputId":"out-1","enable":true,"delay":0,"duration":5000}),
            "alarm-hubs/device-1/outputs/out-1/trigger",
            Some(json!({"enable":true,"delay":0,"duration":5000})),
        ),
    ];
    for (action, route, body) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}/{route}")))
            .and(header("X-API-Key", "test-protect-key"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler_for(&server)
            .call(
                &call(&json!({"deviceId":"device-1","action":action,"confirm":true})),
                None,
            )
            .await
            .expect("accepted action");
        assert_eq!(
            result.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
            true
        );
        let result = result.structured_content.expect("structured result");
        assert_eq!(result["submitted"], true);
        assert_eq!(result["acceptedStatus"], 204);
        assert!(result.get("responseBody").is_none());
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        match body {
            Some(body) => assert_eq!(
                serde_json::from_slice::<Value>(&requests[0].body).expect("request JSON"),
                body
            ),
            None => assert!(requests[0].body.is_empty()),
        }
        server.verify().await;
    }
}

#[tokio::test]
async fn preview_and_invalid_siren_duration_send_no_action() {
    let server = MockServer::start().await;
    let preview = handler_for(&server)
        .call(
            &call(&json!({"deviceId":"device-1","action":{"kind":"sirenPlay","duration":10}})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured preview");
    assert_eq!(preview["submitted"], false);
    assert_eq!(preview["action"], json!({"kind":"sirenPlay","duration":10}));
    let error = handler_for(&server)
        .call(&call(&json!({"deviceId":"device-1","action":{"kind":"sirenPlay","duration":15},"confirm":true})), None)
        .await
        .expect_err("unsupported duration");
    assert!(error.message.contains("5, 10, 20, or 30"));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn rejected_device_action_keeps_the_full_controller_body() {
    let server = MockServer::start().await;
    let body = format!("{}upstream-action-tail", "x".repeat(900));
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sirens/device-1/stop")))
        .respond_with(ResponseTemplate::new(409).set_body_string(&body))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(&json!({"deviceId":"device-1","action":{"kind":"sirenStop"},"confirm":true})),
            None,
        )
        .await
        .expect_err("controller conflict");
    assert!(error.message.contains(&body));
    server.verify().await;
}

#[tokio::test]
async fn accepted_action_keeps_a_large_controller_body() {
    let server = MockServer::start().await;
    let body = format!("{}accepted-action-tail", "x".repeat(60_000));
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sirens/device-1/stop")))
        .respond_with(ResponseTemplate::new(200).set_body_string(&body))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(&json!({"deviceId":"device-1","action":{"kind":"sirenStop"},"confirm":true})),
            None,
        )
        .await
        .expect("accepted result");
    let structured = result.structured_content.expect("structured result");
    assert_eq!(structured["submitted"], true);
    assert_eq!(structured["acceptedStatus"], 200);
    assert_eq!(structured["responseBodyInContent"], true);
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&body)
    )));
    server.verify().await;
}
