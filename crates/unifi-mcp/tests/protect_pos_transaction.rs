//! Protect POS transaction previews and submissions against loopback responses.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, ProtectClient, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const ROUTE: &str = "/proxy/protect/integration/v1/pos/cameras/camera-1/transactions";

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

fn call(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "cameras.pos.transaction".to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

fn transaction() -> serde_json::Value {
    serde_json::json!({
        "type": "sale", "externalId": "receipt-1", "amount": 12.5,
        "currency": "USD", "lineItems": [{"title": "Coffee", "quantity": 2}],
        "location": {"id": "register-1", "name": "Front"},
        "paymentTypes": ["card"], "timestamp": 1_789_000_000_000_u64,
    })
}

#[tokio::test]
async fn preview_contains_the_complete_request_and_confirm_submits_once() {
    let server = MockServer::start().await;
    let response = serde_json::json!({
        "created": true, "eventId": "event-1",
        "controllerSpecific": {"nested": ["kept", 42]},
    });
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let preview = handler
        .call(
            &call(&serde_json::json!({
                "cameraId": "camera-1", "transaction": transaction(),
            })),
            None,
        )
        .await
        .expect("preview");
    let preview_body = preview.structured_content.expect("structured preview");
    assert_eq!(preview_body["cameraId"], "camera-1");
    assert!(
        preview_body["effect"]
            .as_str()
            .expect("effect")
            .contains("video")
    );
    assert_eq!(preview_body["transaction"], transaction());
    assert_eq!(preview_body["submitted"], false);
    assert!(preview_body.get("response").is_none());
    assert_eq!(
        preview.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
        true
    );

    let accepted = handler
        .call(
            &call(&serde_json::json!({
                "cameraId": "camera-1", "transaction": transaction(), "confirm": true,
            })),
            None,
        )
        .await
        .expect("submission")
        .structured_content
        .expect("structured submission");
    assert_eq!(accepted["submitted"], true);
    assert!(accepted.get("transaction").is_none());
    assert_eq!(accepted["response"], response);
}

#[tokio::test]
async fn large_accepted_result_remains_available_after_the_post() {
    let server = MockServer::start().await;
    let response = serde_json::json!({
        "created": true, "eventId": "event-1",
        "controllerSpecific": format!("{}pos-response-tail", "x".repeat(50_000)),
    });
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(&serde_json::json!({
                "cameraId": "camera-1", "transaction": transaction(), "confirm": true,
            })),
            None,
        )
        .await
        .expect("large accepted result");
    let content = serde_json::to_value(&result.content).expect("content");
    let body = result.structured_content.expect("structured result");
    assert_eq!(body["submitted"], true);
    assert_eq!(body["responseInContent"], true);
    assert!(body.get("response").is_none());
    assert!(content.as_array().expect("blocks").iter().any(|block| {
        block["text"]
            .as_str()
            .is_some_and(|text| text.contains(&response.to_string()))
    }));
}

#[tokio::test]
async fn maximum_documented_line_items_remain_previewable_and_submittable() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"created": false, "eventId": "event-1"});
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let mut payload = transaction();
    payload["lineItems"] = serde_json::Value::Array(
        (0..200)
            .map(|index| {
                serde_json::json!({
                    "title": format!("{index}-{}", "x".repeat(250)), "quantity": 1,
                })
            })
            .collect(),
    );
    let handler = handler_for(&server);
    let preview = handler
        .call(
            &call(&serde_json::json!({
                "cameraId": "camera-1", "transaction": payload,
            })),
            None,
        )
        .await
        .expect("large preview");
    let content = serde_json::to_value(&preview.content).expect("content");
    let preview_body = preview.structured_content.expect("structured preview");
    assert_eq!(preview_body["transactionInContent"], true);
    assert!(content.as_array().expect("blocks").iter().any(|block| {
        block["text"]
            .as_str()
            .is_some_and(|text| text.contains(&payload.to_string()))
    }));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );

    let accepted = handler
        .call(
            &call(&serde_json::json!({
                "cameraId": "camera-1", "transaction": payload, "confirm": true,
            })),
            None,
        )
        .await
        .expect("large transaction submission")
        .structured_content
        .expect("structured submission");
    assert_eq!(accepted["submitted"], true);
    assert_eq!(accepted["response"], response);
}

#[tokio::test]
async fn invalid_transaction_is_rejected_before_any_post() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for invalid in [
        serde_json::json!({"type": "sale", "externalId": "", "amount": 1}),
        serde_json::json!({"type": "sale", "externalId": "receipt-1", "amount": -1}),
        serde_json::json!({"type": "sale", "externalId": "receipt-1", "amount": 1, "currency": "usd"}),
        serde_json::json!({"type": "sale", "externalId": "receipt-1", "amount": 1, "lineItems": [{"title": "Coffee", "quantity": 0}]}),
        serde_json::json!({"type": "sale", "externalId": "receipt-1", "amount": 1, "timestamp": 0}),
    ] {
        handler
            .call(
                &call(&serde_json::json!({
                    "cameraId": "camera-1", "transaction": invalid, "confirm": true,
                })),
                None,
            )
            .await
            .expect_err("invalid transaction");
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
async fn conflict_returns_the_complete_upstream_error_without_retry() {
    let server = MockServer::start().await;
    let response = serde_json::json!({
        "message": "processing", "controllerDetail": "conflict-tail".repeat(100),
    });
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(409).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(&serde_json::json!({
                "cameraId": "camera-1", "transaction": transaction(), "confirm": true,
            })),
            None,
        )
        .await
        .expect_err("conflict");
    assert!(error.message.contains("HTTP 409"));
    assert!(error.message.contains(&response.to_string()));
}
