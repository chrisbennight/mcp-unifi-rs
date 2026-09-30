use futures_util::{SinkExt, StreamExt};
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{Request, Response},
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use unifi_api::{ControllerConfig, ProtectClient, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

fn handler(url: &str) -> UnifiMcp {
    let protect = ProtectClient::new(&ControllerConfig {
        name: "fixture".to_owned(),
        base_url: Url::parse(url).expect("loopback URL"),
        api_key: Zeroizing::new("fixture-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(2),
    })
    .expect("client");
    UnifiMcp::new_protect("fixture", Arc::new(protect), None)
}

fn call(input: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "protect.updates".into();
    params.arguments = Some(match input {
        Value::Object(arguments) => arguments,
        _ => panic!("object arguments"),
    });
    params
}

#[expect(
    clippy::result_large_err,
    reason = "the WebSocket library fixes the callback error response type"
)]
async fn socket_server(source: &'static str, messages: Vec<Message>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("client connection");
        let mut socket = accept_hdr_async(stream, move |request: &Request, response: Response| {
            assert_eq!(
                request.uri().path(),
                format!("/proxy/protect/integration/v1/subscribe/{source}")
            );
            assert_eq!(request.headers()["X-API-Key"], "fixture-key");
            Ok(response)
        })
        .await
        .expect("WebSocket upgrade");
        for message in messages {
            let ping = if let Message::Ping(bytes) = &message {
                Some(bytes.clone())
            } else {
                None
            };
            let close = matches!(message, Message::Close(_));
            socket.send(message).await.expect("upstream message");
            if let Some(bytes) = ping {
                assert_eq!(
                    socket.next().await.expect("pong").expect("valid pong"),
                    Message::Pong(bytes)
                );
            }
            if close {
                return;
            }
        }
        // The bounded client closes its connection at the observation limit.
        while let Some(Ok(message)) = socket.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    });
    (url, task)
}

#[tokio::test]
async fn device_and_event_messages_preserve_payloads_unknown_fields_and_binary_bytes() {
    for source in ["devices", "events"] {
        let text = r#" {"type":"controller-specific","item":{"fixtureCredential":"fixture-value","number":184467440737095516170123}} "#;
        let messages = vec![
            Message::Ping(vec![1, 2].into()),
            Message::Text(text.into()),
            Message::Binary(vec![0, 255, 1].into()),
        ];
        let (url, task) = socket_server(source, messages).await;
        let result = handler(&url)
            .call(
                &call(json!({"source":source,"durationMs":2000,"maxMessages":2})),
                None,
            )
            .await
            .expect("observation");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["connected"], true);
        assert_eq!(output["end"], "messageLimit");
        assert_eq!(output["messageCount"], 2);
        assert_eq!(
            output["messages"],
            json!([{"encoding":"utf8","payload":text},{"encoding":"base64","payload":"AP8B"}])
        );
        assert_eq!(output["receivedBytes"], text.len() + 3);
        assert_ne!(result.is_error, Some(true));
        task.await.expect("fake server");
    }
}

#[tokio::test]
async fn quiet_supported_windows_and_controller_closures_are_distinct() {
    let (url, task) = socket_server("events", vec![]).await;
    let output = handler(&url)
        .call(&call(json!({"source":"events","durationMs":200})), None)
        .await
        .expect("quiet window")
        .structured_content
        .expect("structured");
    assert_eq!(output["connected"], true);
    assert_eq!(output["end"], "windowComplete");
    assert_eq!(output["messages"], json!([]));
    task.await.expect("fake server");
    let reason = "fixture upstream close reason";
    let (url, task) = socket_server(
        "devices",
        vec![
            Message::Text("complete first message".into()),
            Message::Close(Some(CloseFrame {
                code: CloseCode::Policy,
                reason: reason.into(),
            })),
        ],
    )
    .await;
    let output = handler(&url)
        .call(&call(json!({"source":"devices","durationMs":2000})), None)
        .await
        .expect("closed stream")
        .structured_content
        .expect("structured");
    assert_eq!(output["end"], "closed");
    assert_eq!(output["closeCode"], 1008);
    assert_eq!(output["closeReason"], reason);
    assert_eq!(output["messages"][0]["payload"], "complete first message");
    task.await.expect("fake server");
}

#[tokio::test]
async fn byte_limits_retain_prior_messages_and_explain_an_omitted_message() {
    for messages in [
        vec![Message::Text("ab".into()), Message::Text("cd".into())],
        vec![Message::Text("abcd".into())],
    ] {
        let (url, task) = socket_server("events", messages).await;
        let output = handler(&url)
            .call(
                &call(json!({"source":"events","durationMs":2000,"maxBytes":3})),
                None,
            )
            .await
            .expect("bounded observation")
            .structured_content
            .expect("structured");
        assert_eq!(output["end"], "byteLimit");
        assert!(
            output["error"]
                .as_str()
                .expect("limit diagnostic")
                .contains("message")
                || output["error"]
                    .as_str()
                    .expect("limit diagnostic")
                    .contains("Message")
        );
        if output["messageCount"] == 1 {
            assert_eq!(output["messages"][0]["payload"], "ab");
            assert_eq!(output["omittedMessageBytes"], 2);
        } else {
            assert_eq!(output["messageCount"], 0);
        }
        task.await.expect("fake server");
    }
}

#[tokio::test]
async fn large_messages_remain_complete_in_mcp_content() {
    let text = format!("{{\"fixtureCredential\":\"{}\"}}", "x".repeat(60000));
    let (url, task) = socket_server("devices", vec![Message::Text(text.clone().into())]).await;
    let result = handler(&url)
        .call(
            &call(json!({"source":"devices","durationMs":2000,"maxMessages":1})),
            None,
        )
        .await
        .expect("large response");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["messagesInContent"], true);
    assert!(output.get("messages").is_none());
    let content = result
        .content
        .iter()
        .find_map(|block| {
            block
                .as_text()
                .and_then(|text| text.text.strip_prefix("Complete subscription messages\n"))
        })
        .expect("complete content");
    let messages: Value = serde_json::from_str(content).expect("messages JSON");
    assert_eq!(messages[0]["payload"], text);
    task.await.expect("fake server");
}

#[tokio::test]
async fn unsupported_failed_and_rate_limited_routes_retain_complete_upstream_bodies() {
    for status in [404, 405, 500, 429] {
        let server = MockServer::start().await;
        let body = format!(
            " {{\"message\":\"upstream detail\",\"fixtureCredential\":\"{}\"}} ",
            "q".repeat(60000)
        );
        Mock::given(method("GET"))
            .and(path("/proxy/protect/integration/v1/subscribe/events"))
            .respond_with(ResponseTemplate::new(status).set_body_string(&body))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler(&server.uri())
            .call(&call(json!({"source":"events","durationMs":2000})), None)
            .await
            .expect("upstream outcome");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["connected"], false);
        assert_eq!(
            output["end"],
            if status == 404 || status == 405 {
                "unsupported"
            } else {
                "failed"
            }
        );
        assert_eq!(output["errorInContent"], true);
        assert_eq!(result.is_error, Some(true));
        assert!(
            result
                .content
                .iter()
                .filter_map(|block| block.as_text())
                .any(|text| text.text.contains(&body))
        );
    }
}

#[tokio::test]
async fn invalid_input_is_rejected_before_connection() {
    let server = MockServer::start().await;
    let handler = handler(&server.uri());
    for input in [
        json!({"source":"events","durationMs":0}),
        json!({"source":"devices","maxMessages":201}),
        json!({"source":"events","maxBytes":0}),
        json!({"source":"other"}),
    ] {
        assert!(handler.call(&call(input), None).await.is_err());
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
    let short = handler.with_request_limits(1, Duration::from_millis(500));
    assert!(
        short
            .call(&call(json!({"source":"events","durationMs":200})), None)
            .await
            .is_err()
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn an_abrupt_disconnect_keeps_the_messages_received_before_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("connection");
        let mut socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("upgrade");
        socket
            .send(Message::Text("upstream message before disconnect".into()))
            .await
            .expect("message");
        // Drop TCP without a WebSocket close frame to simulate a stream fault.
    });
    let result = handler(&url)
        .call(&call(json!({"source":"events","durationMs":2000})), None)
        .await
        .expect("partial observation");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["end"], "failed");
    assert_eq!(output["connected"], true);
    assert_eq!(
        output["messages"][0]["payload"],
        "upstream message before disconnect"
    );
    assert!(
        !output["error"]
            .as_str()
            .expect("stream diagnostic")
            .is_empty()
    );
    assert_eq!(result.is_error, Some(true));
    task.await.expect("fake server");
}
