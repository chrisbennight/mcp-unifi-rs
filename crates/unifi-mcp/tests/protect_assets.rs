//! Protect animation asset reads and multipart uploads against a loopback API.

use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
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

const ROUTE: &str = "/proxy/protect/integration/v1/files/animations";

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

fn call(name: &str, arguments: &Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

fn upload_input(confirm: bool) -> Value {
    json!({
        "fileName":"hello.png",
        "mimeType":"image/png",
        "contentBase64":STANDARD.encode(b"PNGDATA"),
        "confirm":confirm
    })
}

#[tokio::test]
async fn asset_list_pages_complete_controller_records() {
    let server = MockServer::start().await;
    let assets = json!([
        {"name":"asset-1.png","type":"animations","path":"/data/animations/asset-1.png","extra":{"owner":"a"}},
        {"name":"asset-2.png","type":"animations","path":"/data/animations/asset-2.png","extra":{"owner":"b"}},
        {"name":"asset-3.png","type":"animations","path":"/data/animations/asset-3.png","extra":{"owner":"c"}}
    ]);
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .and(header("X-API-Key", "test-protect-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&assets))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let first = handler
        .call(&call("protect.assets.list", &json!({"limit":2})), None)
        .await
        .expect("first page")
        .structured_content
        .expect("structured");
    assert_eq!(first["fileType"], "animations");
    assert_eq!(first["totalCount"], 3);
    assert_eq!(first["nextOffset"], 2);
    assert_eq!(first["assets"][1], assets[1]);
    let second = handler
        .call(
            &call("protect.assets.list", &json!({"offset":2,"limit":2})),
            None,
        )
        .await
        .expect("second page")
        .structured_content
        .expect("structured");
    assert_eq!(second["assets"], json!([assets[2]]));
    assert!(second.get("nextOffset").is_none());
    server.verify().await;
}

#[tokio::test]
async fn asset_upload_previews_and_sends_one_multipart_file() {
    let server = MockServer::start().await;
    let accepted = json!({
        "name":"asset-1.png","type":"animations","originalName":"hello.png",
        "path":"/data/animations/asset-1.png","extra":{"controllerField":"preserved"}
    });
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .and(header("X-API-Key", "test-protect-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([accepted])))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let preview = handler
        .call(&call("protect.assets.upload", &upload_input(false)), None)
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["submitted"], false);
    assert_eq!(preview["byteSize"], 7);
    let confirmed = handler
        .call(&call("protect.assets.upload", &upload_input(true)), None)
        .await
        .expect("uploaded")
        .structured_content
        .expect("structured");
    assert_eq!(confirmed["submitted"], true);
    assert_eq!(confirmed["accepted"], accepted);
    assert_eq!(confirmed["after"], accepted);
    assert_eq!(confirmed["verified"], true);
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    let post = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .expect("POST");
    let content_type = post
        .headers
        .get("content-type")
        .expect("content type")
        .to_str()
        .expect("header");
    assert!(content_type.starts_with("multipart/form-data; boundary="));
    let body = String::from_utf8(post.body.clone()).expect("ASCII fixture");
    assert!(body.contains("name=\"file\"; filename=\"hello.png\""));
    assert!(body.contains("Content-Type: image/png"));
    assert!(body.contains("PNGDATA"));
    server.verify().await;
}

#[tokio::test]
async fn asset_upload_preserves_controller_rejection() {
    let server = MockServer::start().await;
    let rejected = r#"{"error":"file refused","detail":{"reason":"unsupported content"}}"#;
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(415).set_body_string(rejected))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(&call("protect.assets.upload", &upload_input(true)), None)
        .await
        .expect_err("controller rejection");
    assert!(error.to_string().contains(rejected));
    server.verify().await;
}

#[tokio::test]
async fn asset_upload_keeps_large_accepted_record_and_readback_error() {
    let server = MockServer::start().await;
    let detail = format!("{}asset-tail", "x".repeat(60_000));
    let accepted = json!({"name":"asset-1.png","type":"animations","path":"/data/animations/asset-1.png","extra":detail});
    let failed_read = format!("{}asset-readback-tail", "y".repeat(900));
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(503).set_body_string(&failed_read))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(&call("protect.assets.upload", &upload_input(true)), None)
        .await
        .expect("accepted record retained");
    let structured = result.structured_content.expect("structured");
    assert_eq!(structured["submitted"], true);
    assert_eq!(structured["acceptedInContent"], true);
    assert!(
        structured["readbackError"]
            .as_str()
            .expect("error")
            .contains(&failed_read)
    );
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&detail)
    )));
    server.verify().await;
}

#[tokio::test]
async fn invalid_asset_input_sends_no_request() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for arguments in [
        json!({"fileName":"hello.png","mimeType":"image/png","contentBase64":"!","confirm":true}),
        json!({"fileName":"bad\nname.png","mimeType":"image/png","contentBase64":STANDARD.encode(b"x"),"confirm":true}),
        json!({"fileName":"hello.png","mimeType":"text/plain","contentBase64":STANDARD.encode(b"x"),"confirm":true}),
    ] {
        handler
            .call(&call("protect.assets.upload", &arguments), None)
            .await
            .expect_err("invalid upload input");
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}
