//! Tool-level tests for the Protect camera surface against loopback fakes.
//!
//! The property worth the most here is the same one the client protects at the
//! wire level, one layer up: a console that cannot answer must never look like
//! a console with nothing to report. A Protect process either has a console
//! that lacks the integration API or a console that genuinely has no cameras;
//! only the latter is an empty list. A Network process does not advertise or
//! dispatch Protect tools at all.

#![recursion_limit = "256"]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use image::{ExtendedColorType, codecs::jpeg::JpegEncoder};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{CallToolRequestParams, ContentBlock};
use unifi_api::{
    ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, ProtectClient, TlsMode,
};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};
use zeroize::Zeroizing;

const API_KEY: &str = "test-integration-key";
const PROTECT_KEY: &str = "test-protect-key";
const USERNAME: &str = "svc-mcp";
const PASSWORD: &str = "test-legacy-password";
const PROTECT: &str = "/proxy/protect/integration/v1";

fn jpeg_fixture() -> Vec<u8> {
    let mut bytes = Vec::new();
    JpegEncoder::new(&mut bytes)
        .encode(&[0, 128, 255], 1, 1, ExtendedColorType::Rgb8)
        .expect("encode synthetic JPEG");
    bytes
}

/// A handler with no Protect console, which is a supported deployment.
fn handler_without_protect(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new(API_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let protect = ProtectClient::new(&ControllerConfig {
        name: "cameras".to_owned(),
        base_url,
        api_key: Zeroizing::new(PROTECT_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("protect client");
    UnifiMcp::new_protect("cameras", Arc::new(protect), None)
}

#[tokio::test]
async fn protect_server_description_includes_its_action_tools() {
    let server = MockServer::start().await;
    let instructions = handler_for(&server)
        .get_info()
        .instructions
        .expect("instructions");
    assert!(instructions.contains("operational interface"));
}

fn handler_with_events(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let protect = ProtectClient::new(&ControllerConfig {
        name: "cameras".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new(PROTECT_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("protect client");
    let events = LegacyClient::new(&LegacyConfig {
        name: "cameras".to_owned(),
        base_url,
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("Protect event client");
    UnifiMcp::new_protect("cameras", Arc::new(protect), Some(Arc::new(events)))
}

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

/// A console whose integration API answers, with the given camera list.
async fn console_with(server: &MockServer, cameras: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/meta/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "7.1.87"})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras")))
        .respond_with(ResponseTemplate::new(200).set_body_json(cameras))
        .mount(server)
        .await;
}

#[tokio::test]
async fn stream_list_returns_handles_on_independent_transport() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front/rtsps-stream")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": "rtsps://192.0.2.1:7441/synthetic-feed?enableSrtp",
            "medium": null, "low": null, "package": null,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let request = call(
        "cameras.streams.list",
        &serde_json::json!({"camera": "Front Door"}),
    );
    let output = handler_for(&server)
        .with_local_transport()
        .call(&request, None)
        .await
        .expect("streams")
        .structured_content
        .expect("structured");
    assert_eq!(output["streams"].as_array().expect("array").len(), 1);
    assert_eq!(output["streams"][0]["quality"], "high");
    assert!(output["streams"][0]["url"].as_str().is_some());
}

#[tokio::test]
async fn stream_creation_keeps_its_handle_and_complete_large_readback_error() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let route = format!("{PROTECT}/cameras/cam-front/rtsps-stream");
    let failure = format!("{}stream-readback-tail", "x".repeat(50_000));
    Mock::given(method("POST"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(503).set_body_string(failure.clone()))
        .expect(1)
        .mount(&server)
        .await;

    let result = handler_for(&server)
        .call(
            &call(
                "cameras.streams.update",
                &serde_json::json!({
                    "camera": "cam-front", "action": "create",
                    "qualities": ["high"], "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect("stream was created");
    let content = serde_json::to_value(&result.content).expect("content");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(
        output["streams"][0]["url"],
        "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp"
    );
    assert!(output.get("readbackError").is_none());
    assert_eq!(output["readbackErrorInContent"], true);
    assert!(content.to_string().contains(&failure));
    assert!(
        content
            .to_string()
            .contains("readbackError: controller returned HTTP 503:")
    );
}

#[tokio::test]
async fn stream_update_previews_creates_and_reports_readback() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let route = format!("{PROTECT}/cameras/cam-front/rtsps-stream");
    Mock::given(method("POST"))
        .and(path(&route))
        .and(header("X-API-Key", PROTECT_KEY))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "qualities": ["high", "medium"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp",
            "medium": "rtsps://192.0.2.1:7441/synthetic-medium?enableSrtp",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp",
            "medium": "rtsps://192.0.2.1:7441/synthetic-medium?enableSrtp",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let preview = handler
        .call(
            &call(
                "cameras.streams.update",
                &serde_json::json!({
                    "camera": "cam-front", "action": "create",
                    "qualities": ["high", "medium"]
                }),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["applied"], false);
    assert!(preview.get("streams").is_none());
    let output = handler
        .call(
            &call(
                "cameras.streams.update",
                &serde_json::json!({
                    "camera": "cam-front", "action": "create",
                    "qualities": ["high", "medium"], "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect("created")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], true);
    assert_eq!(output["streams"].as_array().expect("array").len(), 2);
    for qualities in [serde_json::json!([]), serde_json::json!(["high", "high"])] {
        assert!(
            handler
                .call(
                    &call(
                        "cameras.streams.update",
                        &serde_json::json!({
                            "camera": "cam-front", "action": "create",
                            "qualities": qualities, "confirm": true
                        }),
                    ),
                    None,
                )
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn stream_creation_returns_handles_before_a_slow_readback_exhausts_the_deadline() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let route = format!("{PROTECT}/cameras/cam-front/rtsps-stream");
    Mock::given(method("POST"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(serde_json::json!({
                    "high": "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp"
                })),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server).with_request_limits(4, Duration::from_secs(2));
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        handler.call(
            &call(
                "cameras.streams.update",
                &serde_json::json!({
                    "camera": "cam-front", "action": "create",
                    "qualities": ["high"], "confirm": true
                }),
            ),
            None,
        ),
    )
    .await
    .expect("tool returned before deadline")
    .expect("created")
    .structured_content
    .expect("structured");
    assert_eq!(output["applied"], true);
    assert!(output.get("verified").is_none());
    assert_eq!(output["streams"][0]["quality"], "high");
}

#[tokio::test]
async fn stream_removal_and_talkback_session_keep_their_observed_outcomes() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let route = format!("{PROTECT}/cameras/cam-front/rtsps-stream");
    Mock::given(method("DELETE"))
        .and(path(&route))
        .and(wiremock::matchers::query_param("qualities", "high"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": null, "medium": null, "low": null, "package": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{PROTECT}/cameras/cam-front/talkback-session"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": "rtp://192.0.2.1:7004", "codec": "opus",
            "samplingRate": 24000, "bitsPerSample": 16
        })))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let removed = handler
        .call(
            &call(
                "cameras.streams.update",
                &serde_json::json!({
                    "camera": "cam-front", "action": "remove",
                    "qualities": ["high"], "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect("remove")
        .structured_content
        .expect("structured");
    assert_eq!(removed["verified"], true);
    assert!(removed.get("streams").is_none());
    let preview = handler
        .call(
            &call(
                "cameras.talkback.start",
                &serde_json::json!({"camera": "cam-front"}),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["applied"], false);
    let started = handler
        .call(
            &call(
                "cameras.talkback.start",
                &serde_json::json!({"camera": "cam-front", "confirm": true}),
            ),
            None,
        )
        .await
        .expect("talkback")
        .structured_content
        .expect("structured");
    assert_eq!(started["applied"], true);
    assert_eq!(started["session"]["codec"], "opus");
    assert_eq!(started["session"]["samplingRate"], 24000);
}

#[tokio::test]
async fn camera_microphone_disable_previews_and_returns_full_controller_results() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let reads = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&reads);
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(move |_: &wiremock::Request| {
            let enabled = count.fetch_add(1, Ordering::SeqCst) < 2;
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":"cam-front", "modelKey":"camera", "name":"Front Door",
                "state":"CONNECTED", "isMicEnabled":enabled,
                "extra":{"controllerField":"preserved"}
            }))
        })
        .expect(3)
        .mount(&server)
        .await;
    let accepted = serde_json::json!({
        "id":"cam-front", "modelKey":"camera", "isMicEnabled":false,
        "extra":{"acceptedField":"preserved"}
    });
    Mock::given(method("POST"))
        .and(path(format!(
            "{PROTECT}/cameras/cam-front/disable-mic-permanently"
        )))
        .and(header("X-API-Key", PROTECT_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let preview = handler
        .call(
            &call(
                "cameras.microphone.disable",
                &serde_json::json!({"camera":"Front Door"}),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["submitted"], false);
    assert_eq!(preview["before"]["extra"]["controllerField"], "preserved");
    let confirmed = handler
        .call(
            &call(
                "cameras.microphone.disable",
                &serde_json::json!({"camera":"Front Door","confirm":true}),
            ),
            None,
        )
        .await
        .expect("disabled")
        .structured_content
        .expect("structured");
    assert_eq!(confirmed["submitted"], true);
    assert_eq!(confirmed["acceptedStatus"], 200);
    assert_eq!(confirmed["verified"], true);
    assert_eq!(confirmed["after"]["extra"]["controllerField"], "preserved");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            confirmed["responseBody"].as_str().expect("body")
        )
        .expect("JSON"),
        accepted
    );
    server.verify().await;
}

#[tokio::test]
async fn camera_microphone_disable_preserves_controller_rejection() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id":"cam-front", "modelKey":"camera", "isMicEnabled":true
        })))
        .expect(1)
        .mount(&server)
        .await;
    let rejected = r#"{"error":"camera locked","details":{"reason":"controller policy"}}"#;
    Mock::given(method("POST"))
        .and(path(format!(
            "{PROTECT}/cameras/cam-front/disable-mic-permanently"
        )))
        .respond_with(ResponseTemplate::new(409).set_body_string(rejected))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "cameras.microphone.disable",
                &serde_json::json!({"camera":"cam-front","confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("controller rejection");
    assert!(error.to_string().contains(rejected));
    server.verify().await;
}

#[tokio::test]
async fn camera_microphone_disable_keeps_large_accepted_body_and_readback_failure() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let reads = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&reads);
    let failure = format!("{}camera-readback-tail", "y".repeat(900));
    let failed_for_mock = failure.clone();
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(move |_: &wiremock::Request| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id":"cam-front", "modelKey":"camera", "isMicEnabled":true
                }))
            } else {
                ResponseTemplate::new(503).set_body_string(failed_for_mock.clone())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let accepted = format!("{}accepted-mic-tail", "x".repeat(60_000));
    Mock::given(method("POST"))
        .and(path(format!(
            "{PROTECT}/cameras/cam-front/disable-mic-permanently"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "cameras.microphone.disable",
                &serde_json::json!({"camera":"cam-front","confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted action remains available");
    let structured = result.structured_content.expect("structured");
    assert_eq!(structured["submitted"], true);
    assert_eq!(structured["acceptedStatus"], 200);
    assert_eq!(structured["responseBodyInContent"], true);
    assert!(
        structured["readbackError"]
            .as_str()
            .expect("error")
            .contains(&failure)
    );
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&accepted)
    )));
    server.verify().await;
}

#[tokio::test]
async fn ptz_action_returns_controller_readback_error() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let failure = format!("patrol read failed: {}ptz-readback-tail", "x".repeat(700));
    Mock::given(method("POST"))
        .and(path(format!(
            "{PROTECT}/cameras/cam-front/ptz/patrol/start/2"
        )))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(503).set_body_string(failure.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &call(
                "cameras.ptz.control",
                &serde_json::json!({
                    "camera": "cam-front", "action": "startPatrol", "slot": 2,
                    "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect("patrol started")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(
        output["readbackError"],
        format!("controller returned HTTP 503: {failure}")
    );
}

#[tokio::test]
async fn ptz_previews_and_verifies_a_confirmed_patrol() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{PROTECT}/cameras/cam-front/ptz/patrol/start/2"
        )))
        .and(header("X-API-Key", PROTECT_KEY))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "cam-front", "modelKey": "camera", "name": "Front Door",
            "state": "CONNECTED", "activePatrolSlot": 2,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let request = serde_json::json!({
        "camera": "Front Door", "action": "startPatrol", "slot": 2,
    });
    let preview = handler
        .call(&call("cameras.ptz.control", &request), None)
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["applied"], false);
    assert_eq!(preview["slot"], 2);

    let confirmed = handler
        .call(
            &call(
                "cameras.ptz.control",
                &serde_json::json!({
                    "camera": "Front Door", "action": "startPatrol", "slot": 2,
                    "confirm": true,
                }),
            ),
            None,
        )
        .await
        .expect("confirmed")
        .structured_content
        .expect("structured");
    assert_eq!(confirmed["applied"], true);
    assert_eq!(confirmed["verified"], true);
    assert_eq!(confirmed["activePatrolSlot"], 2);
}

#[tokio::test]
async fn camera_status_reports_a_public_active_patrol_slot() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([{
            "id": "cam-ptz", "modelKey": "camera", "name": "PTZ",
            "state": "CONNECTED", "activePatrolSlot": 3,
        }]),
    )
    .await;
    let status = handler_for(&server)
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "cam-ptz"})),
            None,
        )
        .await
        .expect("camera status")
        .structured_content
        .expect("structured");
    assert_eq!(status["activePatrolSlot"], 3);
}

#[tokio::test]
async fn camera_settings_update_returns_controller_readback_error() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let before = serde_json::json!({
        "id": "cam-front", "modelKey": "camera", "name": "Front Door",
        "state": "CONNECTED", "micVolume": 40
    });
    let detail = format!("{}settings-response-tail", "y".repeat(60_000));
    let after = serde_json::json!({
        "id": "cam-front", "modelKey": "camera", "name": "Front Door",
        "state": "CONNECTED", "micVolume": 70, "controllerOnly": detail
    });
    let failure = format!(
        "settings read failed: {}settings-readback-tail",
        "x".repeat(700)
    );
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(before))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(503).set_body_string(failure.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(after))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "cameras.settings.update",
                &serde_json::json!({
                    "camera": "cam-front", "changes": {"micVolume": 70},
                    "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect("settings changed");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseInContent"], true);
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&detail)
    )));
    assert_eq!(
        output["readbackError"],
        format!("controller returned HTTP 503: {failure}")
    );
}

#[tokio::test]
async fn camera_settings_update_returns_invalid_action_response() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "cam-front", "modelKey": "camera", "name": "Front Door",
            "state": "CONNECTED", "micVolume": 40
        })))
        .mount(&server)
        .await;
    let body = serde_json::json!({
        "id": "other-camera", "modelKey": "camera", "name": "Front Door",
        "state": "CONNECTED", "micVolume": 70,
        "padding": "x".repeat(700),
        "z_controller_field": "original-settings-tail"
    });
    Mock::given(method("PATCH"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;

    let error = handler_for(&server)
        .call(
            &call(
                "cameras.settings.update",
                &serde_json::json!({
                    "camera": "cam-front", "changes": {"micVolume": 70}, "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect_err("invalid action response");
    assert!(
        error.message.contains(&body.to_string()),
        "{}",
        error.message
    );
    assert!(error.message.contains("id"));
}

#[tokio::test]
async fn camera_settings_update_sends_named_fields_and_verifies_readback() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let before = serde_json::json!({
        "id": "cam-front", "modelKey": "camera", "name": "Front Door", "state": "CONNECTED",
        "videoMode": "default", "hdrType": "auto", "micVolume": 40,
        "osdSettings": {"isNameEnabled": true, "isDateEnabled": true}
    });
    let after = serde_json::json!({
        "id": "cam-front", "modelKey": "camera", "name": "Front Door", "state": "CONNECTED",
        "videoMode": "highFps", "hdrType": "auto", "micVolume": 40,
        "osdSettings": {"isNameEnabled": true, "isDateEnabled": false}
    });
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&before))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&after))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .and(body_json(serde_json::json!({
            "videoMode": "highFps", "osdSettings": {"isDateEnabled": false}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(&after))
        .expect(1)
        .mount(&server)
        .await;
    let request = call(
        "cameras.settings.update",
        &serde_json::json!({
            "camera": "cam-front",
            "changes": {"videoMode": "highFps", "osdSettings": {"isDateEnabled": false}},
            "confirm": true
        }),
    );
    let output = handler_for(&server)
        .call(&request, None)
        .await
        .expect("settings update")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], true);
    assert_eq!(output["after"]["osdSettings"]["isDateEnabled"], false);
    let status = handler_for(&server)
        .call(
            &call(
                "cameras.settings.read",
                &serde_json::json!({"camera": "cam-front"}),
            ),
            None,
        )
        .await
        .expect("settings read")
        .structured_content
        .expect("structured");
    assert_eq!(status["camera"]["videoMode"], "highFps");
}

#[tokio::test]
async fn camera_settings_invalid_value_is_rejected_before_controller_io() {
    let server = MockServer::start().await;
    let error = handler_for(&server)
        .call(
            &call(
                "cameras.settings.update",
                &serde_json::json!({
                    "camera": "cam-front", "changes": {"videoMode": "turbo"}, "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect_err("invalid mode");
    assert!(error.message.contains("videoMode"), "{}", error.message);
}

#[tokio::test]
async fn camera_settings_preview_does_not_patch() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let output = handler_for(&server)
        .call(
            &call(
                "cameras.settings.update",
                &serde_json::json!({
                    "camera": "cam-front", "changes": {"micVolume": 70}
                }),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["requested"]["micVolume"], 70);
}

#[tokio::test]
async fn camera_lcd_message_keeps_null_timeout_and_complete_controller_records() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let before = serde_json::json!({
        "id":"cam-front", "modelKey":"camera", "name":"Front Door", "state":"CONNECTED",
        "lcdMessage":{"type":"DO_NOT_DISTURB"}, "controllerOnly":{"version":"before"}
    });
    let after = serde_json::json!({
        "id":"cam-front", "modelKey":"camera", "name":"Front Door", "state":"CONNECTED",
        "lcdMessage":{"type":"CUSTOM_MESSAGE","text":"Welcome","resetAt":null},
        "controllerOnly":{"version":"after"}
    });
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&before))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&after))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .and(body_json(serde_json::json!({"lcdMessage":{"type":"CUSTOM_MESSAGE","text":"Welcome","resetAt":null}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(&after))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(&call("cameras.settings.update", &serde_json::json!({
            "camera":"cam-front", "changes":{"lcdMessage":{"type":"CUSTOM_MESSAGE","text":"Welcome","resetAt":null}}, "confirm":true
        })), None)
        .await
        .expect("LCD message updated")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], true);
    assert_eq!(output["before"], before);
    assert_eq!(output["response"], after);
    assert_eq!(output["after"], after);
    server.verify().await;
}

#[tokio::test]
async fn camera_settings_read_moves_large_complete_record_to_content() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let detail = format!("{}camera-record-tail", "x".repeat(60_000));
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id":"cam-front", "modelKey":"camera", "name":"Front Door", "state":"CONNECTED",
            "controllerOnly":detail
        })))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "cameras.settings.read",
                &serde_json::json!({"camera":"cam-front"}),
            ),
            None,
        )
        .await
        .expect("complete camera record");
    let structured = result.structured_content.expect("structured");
    assert_eq!(structured["cameraInContent"], true);
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&detail)
    )));
    server.verify().await;
}

#[tokio::test]
async fn camera_lcd_message_requires_text_for_custom_and_image_types() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for kind in ["CUSTOM_MESSAGE", "IMAGE"] {
        handler
            .call(
                &call(
                    "cameras.settings.update",
                    &serde_json::json!({
                        "camera":"cam-front", "changes":{"lcdMessage":{"type":kind}}, "confirm":true
                    }),
                ),
                None,
            )
            .await
            .expect_err("missing documented text field");
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn camera_settings_detects_a_newly_reported_nested_field() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let before = serde_json::json!({
        "id": "cam-front", "modelKey": "camera", "name": "Front Door", "state": "CONNECTED",
        "videoMode": "default", "osdSettings": {"isNameEnabled": true}
    });
    let after = serde_json::json!({
        "id": "cam-front", "modelKey": "camera", "name": "Front Door", "state": "CONNECTED",
        "videoMode": "default", "osdSettings": {"isNameEnabled": false, "isDateEnabled": false}
    });
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&before))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&after))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .and(body_json(
            serde_json::json!({"osdSettings": {"isNameEnabled": false}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&after))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &call(
                "cameras.settings.update",
                &serde_json::json!({
                    "camera": "cam-front", "changes": {"osdSettings": {"isNameEnabled": false}}, "confirm": true
                }),
            ),
            None,
        )
        .await
        .expect("settings update")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], false);
    assert!(
        output["before"]["osdSettings"]
            .get("isDateEnabled")
            .is_none()
    );
    assert_eq!(output["after"]["osdSettings"]["isDateEnabled"], false);
}

#[tokio::test]
async fn ptz_preset_reports_acceptance_without_claiming_position_verification() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("POST"))
        .and(path(format!("{PROTECT}/cameras/cam-front/ptz/goto/-1")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &call(
                "cameras.ptz.control",
                &serde_json::json!({
                    "camera": "cam-front", "action": "gotoPreset", "slot": -1,
                    "confirm": true,
                }),
            ),
            None,
        )
        .await
        .expect("preset")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert!(output.get("verified").is_none());
    assert!(
        output["warnings"]
            .to_string()
            .contains("does not report camera position")
    );
}

#[tokio::test]
async fn ptz_stop_verifies_the_reported_idle_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("POST"))
        .and(path(format!("{PROTECT}/cameras/cam-front/ptz/patrol/stop")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "cam-front", "modelKey": "camera", "name": "Front Door",
            "state": "CONNECTED", "activePatrolSlot": null,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &call(
                "cameras.ptz.control",
                &serde_json::json!({
                    "camera": "cam-front", "action": "stopPatrol", "confirm": true,
                }),
            ),
            None,
        )
        .await
        .expect("stop patrol")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], true);
    assert_eq!(
        output.get("activePatrolSlot"),
        Some(&serde_json::Value::Null)
    );
}

#[tokio::test]
async fn ptz_rejects_invalid_action_shape() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for arguments in [
        serde_json::json!({"camera":"cam-front","action":"gotoPreset"}),
        serde_json::json!({"camera":"cam-front","action":"startPatrol","slot":5}),
        serde_json::json!({"camera":"cam-front","action":"stopPatrol","slot":0}),
    ] {
        assert!(
            handler
                .call(&call("cameras.ptz.control", &arguments), None)
                .await
                .is_err()
        );
    }
}

fn sample_cameras() -> serde_json::Value {
    serde_json::json!([
        {
            "id": "cam-front", "modelKey": "camera", "name": "Front Door",
            "type": "G4 Doorbell", "state": "CONNECTED", "isMicEnabled": true,
            "micVolume": 80
        },
        {
            "id": "cam-back", "modelKey": "camera", "name": "Back Garden",
            "type": "G5 Bullet", "state": "DISCONNECTED"
        },
        {
            "id": "cam-shed", "modelKey": "camera", "name": "Shed",
            "type": "G5 Bullet", "state": "CONNECTED"
        }
    ])
}

fn sample_bootstrap() -> serde_json::Value {
    serde_json::json!({
        "authUser": {"email": "operator@example.invalid"},
        "users": [{"email": "another-user@example.invalid"}],
        "cameras": [
            {
                "id": "cam-front", "modelKey": "camera", "name": "Local Front Door",
                "type": "UVC G4 Doorbell", "marketName": "G4 Doorbell Pro",
                "firmwareVersion": "4.72.44", "latestFirmwareVersion": "4.73.10",
                "hardwareRevision": "12", "connectedSince": 1000, "lastSeen": 2000,
                "lastDisconnect": 900, "uptime": 100_000, "isUpdating": false,
                "isDownloadingFW": false, "isRebooting": false, "isRestoring": false,
                "isAttemptingToConnect": false, "isRecording": true, "hasRecordings": true,
                "isPoorNetwork": false, "videoMode": "default", "is2K": true, "is4K": false,
                "isThirdPartyCamera": false, "isPairedWithAiPort": false,
                "isMicEnabled": true, "micVolume": 80,
                "recordingSettings": {"mode": "always"},
                "featureFlags": {
                    "isDoorbell": true, "isPtz": false, "hasPackageCamera": true,
                    "hasWifi": true, "hasSpeaker": true, "hasMic": true, "hasHdr": true,
                    "hasSmartDetect": true, "hasLedStatus": true, "canOpticalZoom": false,
                    "hasAutoICROnly": false, "smartDetectTypes": ["person", "vehicle"],
                    "smartDetectAudioTypes": ["smoke"]
                },
                "wifiConnectionState": {
                    "signalQuality": 92, "signalStrength": -47, "phyRate": 866.7,
                    "txRate": 433.3, "channel": 44, "frequency": 5220,
                    "experience": "excellent", "connectivity": "full",
                    "ssid": "Studio Wi-Fi"
                },
                "channels": [{"rtspAlias": "front-door-high"}],
                "controllerExtension": {"enabled": true}
            },
            {
                "id": "cam-back", "modelKey": "camera", "marketName": "G5 Bullet",
                "isRecording": false, "is2K": true, "is4K": false,
                "isThirdPartyCamera": false, "isPairedWithAiPort": false,
                "recordingSettings": {"mode": "detections"},
                "featureFlags": {
                    "isDoorbell": false, "isPtz": false, "hasPackageCamera": false,
                    "hasWifi": false, "hasSpeaker": false, "hasMic": true,
                    "hasSmartDetect": true, "canOpticalZoom": false
                },
                "wiredConnectionState": {"phyRate": 1000.0}
            },
            {
                "id": "cam-shed", "modelKey": "camera", "marketName": "G5 Bullet",
                "isRecording": true, "is2K": true, "is4K": false,
                "isThirdPartyCamera": false, "isPairedWithAiPort": false,
                "recordingSettings": {"mode": "always"},
                "featureFlags": {
                    "isDoorbell": false, "isPtz": false, "hasPackageCamera": false,
                    "hasWifi": false, "hasSpeaker": false, "hasMic": true,
                    "hasSmartDetect": true, "canOpticalZoom": false
                }
            }
        ],
        "nvr": {
            "id": "nvr-1", "modelKey": "nvr", "name": "Local Recorder", "type": "UNVR",
            "marketName": "Network Video Recorder Pro", "version": "7.1.87",
            "ucoreVersion": "4.1.13", "isDbAvailable": true,
            "isRecordingDisabled": false, "isRecordingMotionOnly": false,
            "disableAudio": false, "isRecycling": true, "corruptionState": "normal",
            "hardDriveState": "normal", "lastDriveSlowEvent": 1234, "cameraUtilization": 37,
            "maxCameraCapacity": {"4K": 15, "2K": 25, "HD": 50},
            "storageStats": {
                "capacity": 7_776_000_000_u64, "remainingCapacity": 2_592_000_000_u64,
                "utilization": 0.66,
                "recordingSpace": {"total": 1_000_000, "used": 660_000, "available": 340_000},
                "storageDistribution": {
                    "recordingTypeDistributions": [
                        {"recordingType": "detections", "size": 100, "percentage": 0.1}
                    ],
                    "resolutionDistributions": [
                        {"resolution": "2K", "size": 900, "percentage": 0.9}
                    ]
                }
            },
            "systemInfo": {"ustorage": {"disks": [{"serial": "disk-123"}]}}
        }
    })
}

async fn local_console_with(server: &MockServer, bootstrap: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(serde_json::json!({
            "username": USERNAME,
            "password": PASSWORD
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .and(header("cookie", "TOKEN=protect-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(bootstrap))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "nvr-1", "modelKey": "nvr", "name": "CloudKey"
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn cameras_search_reports_public_inventory_without_inventing_local_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("cameras search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["total"], 3);
    // Name-sorted, so two runs against one console agree on order.
    assert_eq!(output["cameras"][0]["name"], "Back Garden");
    assert_eq!(output["cameras"][1]["name"], "Front Door");
    assert_eq!(output["cameras"][2]["name"], "Shed");
    // The console's own state vocabulary survives rather than becoming a bool.
    assert_eq!(output["cameras"][0]["state"], "DISCONNECTED");
    assert_eq!(output["cameras"][1]["productType"], "G4 Doorbell");
    assert_eq!(output["cameras"][1]["audio"]["enabled"], true);
    assert!(output["cameras"][1].get("recording").is_none());
    assert!(output["cameras"][1].get("classes").is_none());
    assert!(output["cameras"][1].get("features").is_none());
    assert_eq!(output["capabilities"]["publicInventory"], true);
    assert_eq!(output["capabilities"]["localEnrichment"], "notConfigured");
}

#[tokio::test]
async fn local_bootstrap_restores_camera_filters_and_operational_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["featureFlags"]["smartDetectTypes"] = serde_json::json!(
        (0..33)
            .map(|index| format!("video-{index}"))
            .collect::<Vec<_>>()
    );
    bootstrap["cameras"][0]["featureFlags"]["smartDetectAudioTypes"] = serde_json::json!(
        (0..33)
            .map(|index| format!("audio-{index}"))
            .collect::<Vec<_>>()
    );
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let result = handler
        .call(
            &call(
                "cameras.search",
                &serde_json::json!({"model": "doorbell", "class": "doorbell"}),
            ),
            None,
        )
        .await
        .expect("enriched camera search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["total"], 1);
    let camera = &output["cameras"][0];
    assert_eq!(camera["id"], "cam-front");
    assert_eq!(camera["hardwareModel"], "G4 Doorbell Pro");
    assert_eq!(
        camera["name"], "Front Door",
        "public name remains authoritative"
    );
    assert_eq!(camera["displayNameSource"], "publicName");
    assert!(
        camera["classes"]
            .as_array()
            .expect("classes")
            .contains(&serde_json::json!("doorbell"))
    );
    assert_eq!(camera["recording"], true);
    assert_eq!(camera["recordingEnabled"], true);
    assert_eq!(camera["recordingGloballyDisabled"], false);
    assert_eq!(camera["recordingMode"], "always");
    assert_eq!(camera["audio"]["supported"], true);
    assert_eq!(camera["audio"]["effectivelyEnabled"], true);
    assert_eq!(camera["features"]["twoK"], true);
    assert_eq!(camera["features"]["smartDetectTypes"][0], "video-0");
    assert_eq!(
        camera["features"]["smartDetectTypes"]
            .as_array()
            .expect("video labels")
            .len(),
        32
    );
    assert_eq!(camera["features"]["smartDetectTypesTruncated"], true);
    assert_eq!(
        camera["features"]["smartDetectAudioTypes"]
            .as_array()
            .expect("audio labels")
            .len(),
        32
    );
    assert_eq!(camera["features"]["smartDetectAudioTypesTruncated"], true);
    assert_eq!(camera["connection"]["kind"], "wifi");
    assert_eq!(camera["connection"]["signalQuality"], 92);
    assert_eq!(camera["firmwareVersion"], "4.72.44");
    assert_eq!(camera["localEnrichment"], "available");
    assert_eq!(output["capabilities"]["localEnrichment"], "available");
    assert_eq!(
        output["capabilities"]["publicInventorySource"],
        "integrationApi"
    );
    assert_eq!(
        output["capabilities"]["localInventorySource"],
        "authenticatedLocalBootstrap"
    );
    assert!(camera.get("details").is_none());
}

#[tokio::test]
async fn local_bootstrap_fields_can_be_requested_without_losing_their_values() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    local_console_with(&server, sample_bootstrap()).await;
    let handler = handler_with_events(&server);

    let camera = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({
                    "camera": "cam-front", "detailFields": ["channels", "wifiConnectionState"]
                }),
            ),
            None,
        )
        .await
        .expect("camera details")
        .structured_content
        .expect("structured");
    assert_eq!(
        camera["details"]["channels"][0]["rtspAlias"],
        "front-door-high"
    );
    assert_eq!(
        camera["details"]["wifiConnectionState"]["ssid"],
        "Studio Wi-Fi"
    );

    let full_camera = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({
                    "camera": "cam-front", "includeDetails": true
                }),
            ),
            None,
        )
        .await
        .expect("complete camera record")
        .structured_content
        .expect("structured");
    assert_eq!(
        full_camera["details"]["controllerExtension"]["enabled"],
        true
    );

    let overview = handler
        .call(
            &call(
                "protect.overview",
                &serde_json::json!({
                    "detailFields": ["authUser", "nvr", "users"]
                }),
            ),
            None,
        )
        .await
        .expect("bootstrap details")
        .structured_content
        .expect("structured");
    assert_eq!(
        overview["bootstrapDetails"]["authUser"]["email"],
        "operator@example.invalid"
    );
    assert_eq!(
        overview["bootstrapDetails"]["users"][0]["email"],
        "another-user@example.invalid"
    );
    assert_eq!(
        overview["bootstrapDetails"]["nvr"]["systemInfo"]["ustorage"]["disks"][0]["serial"],
        "disk-123"
    );
}

#[tokio::test]
async fn cameras_search_filters_by_query_and_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_for(&server);

    let by_name = handler
        .call(
            &call("cameras.search", &serde_json::json!({"query": "garden"})),
            None,
        )
        .await
        .expect("name filter");
    let output = by_name.structured_content.expect("structured");
    assert_eq!(output["total"], 1);
    assert_eq!(output["cameras"][0]["id"], "cam-back");

    let by_state = handler
        .call(
            &call("cameras.search", &serde_json::json!({"state": "connected"})),
            None,
        )
        .await
        .expect("state filter");
    let output = by_state.structured_content.expect("structured");
    assert_eq!(output["total"], 2);
    assert_eq!(output["cameras"][0]["name"], "Front Door");
}

#[tokio::test]
async fn a_bounded_page_names_its_continuation() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("cameras.search", &serde_json::json!({"limit": 2})),
            None,
        )
        .await
        .expect("first page");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["cameras"].as_array().expect("cameras").len(), 2);
    // The total is of the whole match, not the page, and the continuation is
    // present -- a caller must be able to tell it did not see everything.
    assert_eq!(output["total"], 3);
    assert_eq!(output["nextOffset"], 2);

    let last = handler
        .call(
            &call(
                "cameras.search",
                &serde_json::json!({"limit": 2, "offset": 2}),
            ),
            None,
        )
        .await
        .expect("last page");
    let output = last.structured_content.expect("structured");
    assert_eq!(output["cameras"].as_array().expect("cameras").len(), 1);
    assert!(output.get("nextOffset").is_none());
}

#[tokio::test]
async fn cameras_status_selects_by_id_or_exact_name() {
    let server = MockServer::start().await;
    let mut cameras = sample_cameras();
    cameras[0]["name"] = serde_json::json!("Étage");
    console_with(&server, cameras).await;
    let handler = handler_for(&server);

    let by_id = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "cam-shed"})),
            None,
        )
        .await
        .expect("by id");
    assert_eq!(
        by_id.structured_content.expect("structured")["name"],
        "Shed"
    );

    let by_name = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "étage"})),
            None,
        )
        .await
        .expect("by name");
    let output = by_name.structured_content.expect("structured");
    assert_eq!(output["id"], "cam-front");
    assert_eq!(output["productType"], "G4 Doorbell");
    assert_eq!(output["localEnrichment"], "notConfigured");
}

#[tokio::test]
async fn camera_snapshot_returns_image_content_and_small_metadata() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let jpeg = jpeg_fixture();
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front/snapshot")))
        .and(query_param("channel", "package"))
        .and(query_param("highQuality", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(jpeg.clone(), "image/jpeg"))
        .expect(1)
        .mount(&server)
        .await;

    let result = handler_for(&server)
        .call(
            &call(
                "cameras.snapshot",
                &serde_json::json!({"camera": "front door", "channel": "package", "highQuality": true}),
            ),
            None,
        )
        .await
        .expect("snapshot");
    assert_eq!(
        result.structured_content.as_ref().expect("metadata")["cameraId"],
        "cam-front"
    );
    assert_eq!(
        result.structured_content.as_ref().expect("metadata")["byteSize"],
        jpeg.len()
    );
    let image = result
        .content
        .iter()
        .find_map(|content| match content {
            ContentBlock::Image(image) => Some(image),
            _ => None,
        })
        .expect("MCP image content");
    assert_eq!(image.mime_type, "image/jpeg");
    assert_eq!(STANDARD.decode(&image.data).expect("base64"), jpeg);
}

#[tokio::test]
async fn camera_snapshot_forwards_the_complete_invalid_jpeg_body() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let invalid = vec![0xff; 700];
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front/snapshot")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(invalid.clone(), "image/jpeg"))
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "cameras.snapshot",
                &serde_json::json!({"camera": "cam-front"}),
            ),
            None,
        )
        .await
        .expect_err("invalid JPEG");
    assert!(error.message.contains(&STANDARD.encode(&invalid)));
    assert!(error.message.contains("decode error"));
}

#[tokio::test]
async fn protect_event_thumbnail_returns_image_content_for_the_event_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    let jpeg = jpeg_fixture();
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events/event-1/thumbnail"))
        .and(header("cookie", "TOKEN=protect-session"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(jpeg.clone(), "image/jpeg"))
        .expect(1)
        .mount(&server)
        .await;

    let result = handler_with_events(&server)
        .call(
            &call(
                "protect.event.thumbnail",
                &serde_json::json!({"event": "event-1"}),
            ),
            None,
        )
        .await
        .expect("event thumbnail");
    let metadata = result.structured_content.expect("metadata");
    assert_eq!(metadata["eventId"], "event-1");
    assert_eq!(metadata["byteSize"], jpeg.len());
    let image = result
        .content
        .iter()
        .find_map(|content| match content {
            ContentBlock::Image(image) => Some(image),
            _ => None,
        })
        .expect("MCP image content");
    assert_eq!(image.mime_type, "image/jpeg");
    assert_eq!(STANDARD.decode(&image.data).expect("base64"), jpeg);
}

#[tokio::test]
async fn camera_snapshot_accepts_a_display_name_from_local_inventory() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([{
            "id": "cam-front", "modelKey": "camera", "name": null, "state": "CONNECTED"
        }]),
    )
    .await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .truncate(1);
    local_console_with(&server, bootstrap).await;
    let jpeg = jpeg_fixture();
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front/snapshot")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(jpeg, "image/jpeg"))
        .expect(1)
        .mount(&server)
        .await;

    let result = handler_with_events(&server)
        .call(
            &call(
                "cameras.snapshot",
                &serde_json::json!({"camera": "Local Front Door"}),
            ),
            None,
        )
        .await
        .expect("snapshot by local display name");
    assert_eq!(
        result.structured_content.expect("metadata")["cameraId"],
        "cam-front"
    );
}

#[tokio::test]
async fn camera_snapshot_refuses_name_when_local_inventory_is_partial() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-front", "modelKey": "camera", "name": "Side", "state": "CONNECTED"},
            {"id": "cam-back", "modelKey": "camera", "name": null, "state": "CONNECTED"}
        ]),
    )
    .await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .truncate(1);
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(
            &call("cameras.snapshot", &serde_json::json!({"camera": "Side"})),
            None,
        )
        .await
        .expect_err("name cannot be proven unique");
    assert!(
        error
            .message
            .contains("requires complete local Protect inventory")
    );

    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras/cam-front/snapshot")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(jpeg_fixture(), "image/jpeg"))
        .expect(1)
        .mount(&server)
        .await;
    let by_id = handler
        .call(
            &call(
                "cameras.snapshot",
                &serde_json::json!({"camera": "cam-front"}),
            ),
            None,
        )
        .await
        .expect("exact id works with partial inventory");
    assert_eq!(
        by_id.structured_content.expect("metadata")["cameraId"],
        "cam-front"
    );
}

#[tokio::test]
async fn a_blank_public_name_keeps_a_separate_usable_local_display_name() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([{
            "id": "cam-front", "modelKey": "camera", "name": "  ", "state": "CONNECTED"
        }]),
    )
    .await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .truncate(1);
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let output = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({"camera": "Local Front Door"}),
            ),
            None,
        )
        .await
        .expect("local display-name selector")
        .structured_content
        .expect("structured");
    assert_eq!(output["name"], "  ");
    assert_eq!(output["displayName"], "Local Front Door");
    assert_eq!(output["displayNameSource"], "localName");
}

#[tokio::test]
async fn a_returned_256_character_camera_name_remains_selectable() {
    let server = MockServer::start().await;
    let name = "é".repeat(256);
    console_with(
        &server,
        serde_json::json!([{
            "id": "cam-long-name",
            "modelKey": "camera",
            "name": name,
            "state": "CONNECTED"
        }]),
    )
    .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": name})),
            None,
        )
        .await
        .expect("select the complete returned name");
    assert_eq!(
        result.structured_content.expect("structured")["id"],
        "cam-long-name"
    );
}

#[tokio::test]
async fn an_ambiguous_camera_name_is_refused_rather_than_resolved_by_position() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-a", "modelKey": "camera", "name": "Side", "state": "CONNECTED"},
            {"id": "cam-b", "modelKey": "camera", "name": "Side", "state": "CONNECTED"}
        ]),
    )
    .await;
    let handler = handler_for(&server);

    let error = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "Side"})),
            None,
        )
        .await
        .expect_err("ambiguous");
    assert!(
        error.message.contains("share that name"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn duplicate_public_camera_ids_fail_instead_of_merging_records() {
    let server = MockServer::start().await;
    let public = serde_json::json!([
        {"id": "cam-a", "modelKey": "camera", "name": "One", "state": "CONNECTED"},
        {"id": "cam-a", "modelKey": "camera", "name": "Two", "state": "DISCONNECTED",
         "controllerDetail": "duplicate-public-tail".repeat(100)}
    ]);
    console_with(&server, public.clone()).await;
    let handler = handler_for(&server);

    let error = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect_err("duplicate ids");
    assert!(error.message.contains("duplicate id"));
    assert!(error.message.contains(&public.to_string()));
}

#[tokio::test]
async fn public_cameras_may_share_a_physical_hardware_identity() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-a", "modelKey": "camera", "name": "One", "state": "CONNECTED", "guid": "shared"},
            {"id": "cam-b", "modelKey": "camera", "name": "Two", "state": "CONNECTED", "guid": "SHARED"}
        ]),
    )
    .await;

    let result = handler_for(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("shared physical identity");
    assert_eq!(result.structured_content.expect("structured")["total"], 2);
}

#[tokio::test]
async fn protect_overview_groups_by_the_consoles_own_state_words() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "nvr-1", "modelKey": "nvr", "name": "CloudKey", "type": "UNVR"
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("overview");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applicationVersion"], "7.1.87");
    assert_eq!(output["cameraCount"], 3);
    assert_eq!(output["camerasByState"][0]["state"], "CONNECTED");
    assert_eq!(output["camerasByState"][0]["count"], 2);
    assert_eq!(output["camerasByState"][1]["state"], "DISCONNECTED");
    assert!(output.get("notRecording").is_none());
    assert_eq!(output["recorders"][0]["name"], "CloudKey");
    assert_eq!(output["recorders"][0]["productType"], "UNVR");
    assert_eq!(output["recorders"][0]["enriched"], false);
    assert_eq!(output["capabilities"]["localEnrichment"], "notConfigured");
}

#[tokio::test]
async fn protect_overview_reports_enriched_recorder_storage_and_recording_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["nvr"]["storageStats"]["storageDistribution"]["recordingTypeDistributions"] =
        serde_json::Value::Array(
            (0..33)
                .map(|index| {
                    serde_json::json!({
                        "recordingType": format!("type-{index}"), "size": index, "percentage": 0.01
                    })
                })
                .collect(),
        );
    bootstrap["nvr"]["storageStats"]["storageDistribution"]
        .as_object_mut()
        .expect("storage distribution")
        .remove("resolutionDistributions");
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let output = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("enriched overview")
        .structured_content
        .expect("structured");
    assert_eq!(output["notRecordingCount"], 1);
    assert_eq!(output["notRecording"][0]["id"], "cam-back");
    let recorder = &output["recorders"][0];
    assert_eq!(
        recorder["name"], "CloudKey",
        "public name remains authoritative"
    );
    assert_eq!(recorder["hardwareModel"], "Network Video Recorder Pro");
    assert_eq!(recorder["protectVersion"], "7.1.87");
    assert_eq!(recorder["consoleVersion"], "4.1.13");
    assert_eq!(recorder["databaseAvailable"], true);
    assert_eq!(recorder["recordingDisabled"], false);
    assert_eq!(recorder["audioDisabled"], false);
    assert_eq!(recorder["maxCameraCapacity"]["fourK"], 15);
    assert_eq!(
        recorder["storage"]["recordingSpace"]["availableBytes"],
        340_000
    );
    assert_eq!(
        recorder["storage"]["recordingTypeDistribution"][0]["category"],
        "type-0"
    );
    assert_eq!(
        recorder["storage"]["recordingTypeDistribution"]
            .as_array()
            .expect("bounded distribution")
            .len(),
        32
    );
    assert_eq!(
        recorder["storage"]["recordingTypeDistributionTruncated"],
        true
    );
    assert!(recorder["storage"].get("resolutionDistribution").is_none());
    assert_eq!(recorder["enriched"], true);
}

#[tokio::test]
async fn duplicate_local_camera_ids_keep_the_bootstrap_response() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    let cameras = bootstrap["cameras"].as_array_mut().expect("cameras");
    cameras.push(cameras[0].clone());
    bootstrap["controllerDetail"] = serde_json::json!("duplicate-local-tail".repeat(100));
    local_console_with(&server, bootstrap.clone()).await;
    let handler = handler_with_events(&server);

    let inventory = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public inventory remains available")
        .structured_content
        .expect("structured");
    let reason = inventory["capabilities"]["localUnavailableReason"]
        .as_str()
        .expect("local error");
    assert!(reason.contains("duplicate cameras.id"));
    assert!(reason.contains(&bootstrap.to_string()));

    let error = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({"camera": "cam-front", "includeDetails": true}),
            ),
            None,
        )
        .await
        .expect_err("requested local details need valid inventory");
    assert!(error.message.contains(&bootstrap.to_string()));
}

#[tokio::test]
async fn logical_cameras_may_share_hardware_identity_across_sources() {
    let server = MockServer::start().await;
    let mut public = sample_cameras();
    public[0]["guid"] = serde_json::json!("shared-guid");
    public[1]["guid"] = serde_json::json!("shared-guid");
    console_with(&server, public).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["guid"] = serde_json::json!("shared-guid");
    bootstrap["cameras"][1]["guid"] = serde_json::json!("shared-guid");
    local_console_with(&server, bootstrap).await;

    let result = handler_with_events(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("shared hardware identity");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["total"], 3);
    assert_eq!(output["capabilities"]["localEnrichment"], "available");
}

#[tokio::test]
async fn the_same_camera_id_with_conflicting_hardware_identity_fails_loudly() {
    let server = MockServer::start().await;
    let mut public = sample_cameras();
    public[0]["guid"] = serde_json::json!("public-guid");
    public[0]["controllerDetail"] = serde_json::json!("public-conflict-tail".repeat(100));
    console_with(&server, public.clone()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["guid"] = serde_json::json!("local-guid");
    bootstrap["controllerDetail"] = serde_json::json!("local-conflict-tail".repeat(100));
    local_console_with(&server, bootstrap.clone()).await;

    let error = handler_with_events(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect_err("conflicting camera identity");
    assert!(error.message.contains("camera identities conflict"));
    assert!(error.message.contains(&public.to_string()));
    assert!(error.message.contains(&bootstrap.to_string()));
}

#[tokio::test]
async fn a_conflicting_local_recorder_cannot_supply_camera_global_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["nvr"]["id"] = serde_json::json!("different-nvr");
    bootstrap["controllerDetail"] = serde_json::json!("recorder-conflict-tail".repeat(100));
    local_console_with(&server, bootstrap.clone()).await;

    let error = handler_with_events(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect_err("conflicting recorder identity");
    assert!(error.message.contains("recorder identities conflict"));
    assert!(error.message.contains(&bootstrap.to_string()));
    assert!(error.message.contains(
        &serde_json::json!({"id": "nvr-1", "modelKey": "nvr", "name": "CloudKey"}).to_string()
    ));
}

#[tokio::test]
async fn partial_local_inventory_never_turns_model_filter_into_a_false_empty_result() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"].as_array_mut().expect("cameras").pop();
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"model": "G5"})),
            None,
        )
        .await
        .expect_err("incomplete model data");
    assert!(error.message.contains("model filtering is unavailable"));

    let output = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public inventory still works")
        .structured_content
        .expect("structured");
    assert_eq!(output["total"], 3);
    assert_eq!(output["capabilities"]["localEnrichment"], "partial");
    assert_eq!(output["cameras"][2]["localEnrichment"], "noMatchingRecord");
}

#[tokio::test]
async fn a_blank_local_market_name_is_not_complete_model_data() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][2]["marketName"] = serde_json::json!("  ");
    bootstrap["cameras"][2]["recordingSettings"]["mode"] = serde_json::json!("future-mode");
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"model": "G5"})),
            None,
        )
        .await
        .expect_err("blank model data");
    assert!(error.message.contains("model filtering is unavailable"));

    let camera = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "Shed"})),
            None,
        )
        .await
        .expect("unknown recording mode")
        .structured_content
        .expect("structured");
    assert_eq!(camera["recordingMode"], "future-mode");
    assert!(camera.get("recordingConfigured").is_none());
    assert!(camera.get("recordingEnabled").is_none());
}

#[tokio::test]
async fn an_unknown_recording_flag_suppresses_the_mixed_overview_summary() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][2]
        .as_object_mut()
        .expect("camera")
        .remove("isRecording");
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let result = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("overview");
    let output = result.structured_content.expect("structured");
    // The known idle camera cannot make this look like a complete summary
    // while another camera's recording state is absent.
    assert!(output.get("notRecording").is_none());
    assert!(output.get("notRecordingCount").is_none());
    assert_eq!(output["cameraCount"], 3);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves filtering, continuation, and uncut labels across two pages"
)]
async fn protect_events_filters_and_continues_without_a_hidden_scan_ceiling() {
    let server = MockServer::start().await;
    let mut cameras = sample_cameras();
    cameras[0]["name"] = serde_json::json!(" Front Door ");
    console_with(&server, cameras).await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(serde_json::json!({
            "username": USERNAME,
            "password": PASSWORD
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let detection_types: Vec<String> = (0..20)
        .map(|index| {
            if index == 0 {
                "person".to_owned()
            } else {
                format!("label-{index}")
            }
        })
        .collect();
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(header("cookie", "TOKEN=protect-session"))
        .and(query_param("start", "1000"))
        .and(query_param("end", "2000"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .and(query_param("types", "motion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-3", "type": "smartDetectZone", "start": 1900,
             "camera": "cam-front", "smartDetectTypes": detection_types},
            {"id": "event-2", "type": "motion", "start": 1800,
             "camera": "cam-back"},
            {"id": "event-1", "type": "smartDetectLine", "start": 1100,
             "camera": "cam-front", "smartDetectTypes": ["person"]}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(query_param("start", "1000"))
        .and(query_param("end", "1799"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-1", "type": "smartDetectLine", "start": 1100,
             "camera": "cam-front", "smartDetectTypes": ["person"],
             "metadata": {"zoneName": "Driveway"}, "thumbnail": "thumb-1"},
            {"id": "before-window", "type": "motion", "start": 999}
        ])))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_with_events(&server);

    let first = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({
                    "start": 1000,
                    "end": 2000,
                    "camera": "cam-front",
                    "detection": "person",
                    "limit": 2
                }),
            ),
            None,
        )
        .await
        .expect("first page");
    let output = first.structured_content.expect("structured");
    assert_eq!(output["rows"].as_array().expect("rows").len(), 1);
    assert!(output["rows"][0].get("details").is_none());
    assert_eq!(output["rows"][0]["cameraName"], " Front Door ");
    assert_eq!(
        output["rows"][0]["detectionTypes"]
            .as_array()
            .expect("detection types")
            .len(),
        20,
        "all labels remain reachable rather than being cut at an arbitrary row ceiling"
    );
    assert_eq!(output["scannedRows"], 2);
    assert_eq!(output["complete"], false);
    assert!(output.get("fetchWindowTruncated").is_none());
    let cursor = output["nextCursor"].clone();

    let second = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"cursor": cursor.clone(), "limit": 2, "includeDetails": true}),
            ),
            None,
        )
        .await
        .expect("second page");
    let output = second.structured_content.expect("structured");
    assert_eq!(output["rows"].as_array().expect("rows").len(), 1);
    assert_eq!(output["rows"][0]["id"], "event-1");
    assert_eq!(output["rows"][0]["details"]["type"], "smartDetectLine");
    assert_eq!(
        output["rows"][0]["details"]["metadata"]["zoneName"],
        "Driveway"
    );
    assert_eq!(output["rows"][0]["details"]["thumbnail"], "thumb-1");
    assert_eq!(
        output["rows"][0]["detectionTypes"],
        serde_json::json!(["person"])
    );
    assert_eq!(output["complete"], true);
    assert!(output.get("nextCursor").is_none());

    let selected = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"cursor": cursor, "limit": 2, "detailFields": ["metadata"]}),
            ),
            None,
        )
        .await
        .expect("selected event details")
        .structured_content
        .expect("structured");
    assert_eq!(
        selected["rows"][0]["details"]["metadata"]["zoneName"],
        "Driveway"
    );
    assert!(selected["rows"][0]["details"].get("thumbnail").is_none());
}

#[tokio::test]
async fn protect_events_serialize_an_empty_detection_label_list() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    local_console_with(&server, sample_bootstrap()).await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id": "event-without-labels",
                "type": "motion",
                "start": 1500,
                "camera": "cam-front"
            }])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_with_events(&server)
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000}),
            ),
            None,
        )
        .await
        .expect("unlabeled event")
        .structured_content
        .expect("structured");

    assert_eq!(output["rows"][0]["detectionTypes"], serde_json::json!([]));
}

#[tokio::test]
async fn protect_events_accepts_the_local_display_name_reported_by_search() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-front", "modelKey": "camera", "name": null, "state": "CONNECTED"},
            {"id": "cam-back", "modelKey": "camera", "name": "Public Front", "state": "CONNECTED"},
            {"id": "cam-shed", "modelKey": "camera", "name": null, "state": "CONNECTED"}
        ]),
    )
    .await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["name"] = serde_json::json!(" ÉTAGE ");
    bootstrap["cameras"][2]["name"] = serde_json::json!(" Public Front ");
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .truncate(3);
    local_console_with(&server, bootstrap).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-1", "type": "motion", "start": 1500, "camera": "cam-front"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let handler = handler_with_events(&server);
    let output = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": " étage "}),
            ),
            None,
        )
        .await
        .expect("events by local display name")
        .structured_content
        .expect("structured");
    assert_eq!(output["rows"][0]["cameraId"], "cam-front");

    let error = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": "Public Front"}),
            ),
            None,
        )
        .await
        .expect_err("cross-source ambiguous name");
    assert!(error.message.contains("2 cameras share that name"));
}

#[tokio::test]
async fn protect_events_refuses_name_selection_from_partial_local_inventory() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"].as_array_mut().expect("cameras").pop();
    local_console_with(&server, bootstrap).await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let error = handler_with_events(&server)
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": "Front Door"}),
            ),
            None,
        )
        .await
        .expect_err("partial name inventory must fail before event lookup");
    assert!(
        error
            .message
            .contains("camera name selection requires complete local Protect inventory"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn camera_name_selection_refuses_an_extra_local_camera_namespace() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .push(serde_json::json!({
            "id": "cam-local-only", "modelKey": "camera", "name": "Front Door"
        }));
    local_console_with(&server, bootstrap).await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let handler = handler_with_events(&server);

    for tool in ["cameras.status", "protect.events"] {
        let arguments = if tool == "cameras.status" {
            serde_json::json!({"camera": "Front Door"})
        } else {
            serde_json::json!({"start": 1000, "end": 2000, "camera": "Front Door"})
        };
        let error = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("an asymmetric name namespace must fail");
        assert!(
            error
                .message
                .contains("camera name selection requires complete local Protect inventory"),
            "{}: {}",
            tool,
            error.message
        );
    }
}

#[tokio::test]
async fn protect_events_refuses_name_selection_when_local_inventory_is_unavailable() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(503).set_body_string("local inventory failed"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let error = handler_with_events(&server)
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": "Front Door"}),
            ),
            None,
        )
        .await
        .expect_err("unavailable name inventory must fail before event lookup");
    assert_eq!(
        error.message,
        "controller returned HTTP 503: local inventory failed"
    );
}

#[tokio::test]
async fn protect_events_equal_timestamp_boundary_names_the_recovery_path() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let body = serde_json::json!([
        {"id": "event-3", "type": "motion", "start": 1900},
        {"id": "event-2", "type": "motion", "start": 1900},
        {"id": "event-1", "type": "motion", "start": 1900,
         "controller_extension": "x".repeat(700),
         "z_controller_field": "original-event-tail"}
    ]);
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(serde_json::json!({
            "username": USERNAME,
            "password": PASSWORD
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "limit": 2}),
            ),
            None,
        )
        .await
        .expect_err("equal timestamp boundary must fail");

    assert!(
        error.message.contains("retry with a higher limit"),
        "{}",
        error.message
    );
    assert!(
        error.message.contains(&body.to_string()),
        "{}",
        error.message
    );
    assert!(!error.message.contains("invalid controller configuration"));
}

#[tokio::test]
async fn protect_events_names_missing_local_session_credentials() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_for(&server);
    for (tool, arguments) in [
        (
            "protect.events",
            serde_json::json!({"start": 1000, "end": 2000}),
        ),
        (
            "protect.event.thumbnail",
            serde_json::json!({"event": "event-1"}),
        ),
    ] {
        let error = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("missing local Protect session");
        assert!(
            error
                .message
                .contains("no local Protect session is configured"),
            "{}: {}",
            tool,
            error.message
        );
    }
}

#[tokio::test]
async fn configured_local_session_reports_unavailable_when_bootstrap_cannot_be_read() {
    let server = MockServer::start().await;
    let bootstrap_failure = format!(
        "bootstrap unavailable: {}controller-local-detail",
        "x".repeat(700)
    );
    console_with(&server, sample_cameras()).await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(503).set_body_string(bootstrap_failure.clone()))
        .mount(&server)
        .await;
    let handler = handler_with_events(&server);

    let output = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public inventory")
        .structured_content
        .expect("structured");
    assert_eq!(output["capabilities"]["localEnrichment"], "unavailable");
    assert_eq!(output["cameras"][0]["localEnrichment"], "unavailable");
    assert_eq!(
        output["capabilities"]["localUnavailableReason"],
        format!("controller returned HTTP 503: {bootstrap_failure}")
    );

    let status = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({"camera": "cam-front"}),
            ),
            None,
        )
        .await
        .expect("public camera status")
        .structured_content
        .expect("structured");
    assert_eq!(status["id"], "cam-front");
    assert_eq!(
        status["localError"],
        format!("controller returned HTTP 503: {bootstrap_failure}")
    );

    let details_error = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({"camera": "cam-front", "includeDetails": true}),
            ),
            None,
        )
        .await
        .expect_err("requested local details");
    assert!(details_error.message.contains("controller-local-detail"));

    let filter_error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"model": "G5"})),
            None,
        )
        .await
        .expect_err("requested local filter");
    assert!(filter_error.message.contains("controller-local-detail"));

    let event_error = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({
                    "camera": "Front Door",
                    "start": 1000,
                    "end": 2000
                }),
            ),
            None,
        )
        .await
        .expect_err("requested camera name needs local inventory");
    assert!(event_error.message.contains("controller-local-detail"));
}

#[tokio::test]
async fn malformed_local_bootstrap_reaches_camera_results_and_errors() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["modelKey"] = serde_json::json!("nvr");
    bootstrap["padding"] = serde_json::json!("x".repeat(700));
    bootstrap["z_controller_field"] = serde_json::json!("original-bootstrap-tail");
    let original_body = bootstrap.to_string();
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let output = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public camera inventory")
        .structured_content
        .expect("structured");
    assert_eq!(output["capabilities"]["localEnrichment"], "unavailable");
    assert!(
        output["capabilities"]["localUnavailableReason"]
            .as_str()
            .expect("local error")
            .contains(&original_body)
    );

    let error = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({"camera": "cam-front", "includeDetails": true}),
            ),
            None,
        )
        .await
        .expect_err("requested local details");
    assert!(error.message.contains(&original_body), "{}", error.message);
    assert!(error.message.contains("cameras.modelKey"));
}

#[tokio::test]
async fn a_console_without_the_integration_api_is_refused_by_every_camera_tool() {
    let server = MockServer::start().await;
    // The console answers, and has no integration API at this path.
    let body = format!("protect route missing: {}controller-tail", "x".repeat(700));
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/meta/info")))
        .respond_with(ResponseTemplate::new(404).set_body_string(body.clone()))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    for (tool, arguments) in [
        ("cameras.search", serde_json::json!({})),
        ("cameras.status", serde_json::json!({"camera": "cam-a"})),
        ("protect.overview", serde_json::json!({})),
        (
            "protect.events",
            serde_json::json!({"start": 1000, "end": 2000}),
        ),
    ] {
        let error = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("console without the integration API must refuse");
        assert_eq!(
            error.message,
            format!("controller returned HTTP 404: {body}")
        );
    }
}

#[tokio::test]
async fn an_available_console_with_no_cameras_returns_an_empty_inventory() {
    let server = MockServer::start().await;
    console_with(&server, serde_json::json!([])).await;
    let output = handler_for(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("available empty inventory")
        .structured_content
        .expect("structured");
    assert_eq!(output["total"], 0);
    assert_eq!(output["cameras"], serde_json::json!([]));
    assert_eq!(output["capabilities"]["publicInventory"], true);
}

#[tokio::test]
async fn a_network_runtime_rejects_every_protect_tool_as_outside_its_catalog() {
    let server = MockServer::start().await;
    let handler = handler_without_protect(&server);

    for (tool, arguments) in [
        ("cameras.search", serde_json::json!({})),
        ("cameras.status", serde_json::json!({"camera": "cam-a"})),
        ("protect.overview", serde_json::json!({})),
        (
            "protect.events",
            serde_json::json!({"start": 1000, "end": 2000}),
        ),
        (
            "protect.event.thumbnail",
            serde_json::json!({"event": "event-1"}),
        ),
    ] {
        let error = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("Protect tool must not dispatch on Network");
        assert!(
            error.message.contains("unknown tool"),
            "{tool}: {}",
            error.message
        );
    }
}

#[tokio::test]
async fn unavailable_model_and_class_filters_fail_explicitly() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-a", "modelKey": "camera", "name": null, "state": "CONNECTED"}
        ]),
    )
    .await;
    let handler = handler_for(&server);

    let inventory = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public inventory without a name")
        .structured_content
        .expect("structured");
    assert_eq!(inventory["cameras"][0]["id"], "cam-a");
    assert!(inventory["cameras"][0].get("name").is_none());

    let model_error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"model": "G5"})),
            None,
        )
        .await
        .expect_err("model data unavailable");
    assert!(
        model_error
            .message
            .contains("model filtering is unavailable")
    );

    let class_error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"class": "doorbell"})),
            None,
        )
        .await
        .expect_err("class data unavailable");
    assert!(
        class_error
            .message
            .contains("class filtering is unavailable")
    );
}

#[tokio::test]
async fn the_overview_names_which_console_answered() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "nvr-1", "modelKey": "nvr", "name": "Recorder"
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("overview");
    assert_eq!(
        result.structured_content.expect("structured")["console"],
        "cameras"
    );
}
