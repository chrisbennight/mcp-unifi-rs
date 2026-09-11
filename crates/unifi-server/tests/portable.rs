//! Independent clients exercise the same bounded, authorized tool dispatch.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use unifi_api::TlsMode;
use unifi_mcp::{UnifiMcp, handler::LocalAccess};
use unifi_server::{
    auth::GatewayBearers,
    config::{ControllerSettings, ProtectSettings, RuntimeSettings},
    portable::{DirectHttpSettings, PortableSettings, build_direct_router, serve_stdio},
    server::build_handler,
};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const BEARER: &str = "0123456789abcdef0123456789abcdef";
const VERSION: &str = "2026-07-28";

fn binary() -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-unifi-rs"));
    command
        .env_clear()
        .args(["--transport", "stdio"])
        .env("UNIFI_MCP_SURFACE", "protect")
        .env("UNIFI_MCP_PROTECT_URL", "http://127.0.0.1:65531")
        .env("UNIFI_MCP_PROTECT_API_KEY", "fake-controller-key")
        .kill_on_drop(true);
    command
}

#[tokio::test]
async fn binary_validates_permissions_without_printing_secret_configuration() {
    for (variable, value) in [
        ("UNIFI_MCP_ALLOW_WRITES", "yes"),
        ("UNIFI_MCP_ALLOW_SECRET_DISCLOSURE", "1"),
        ("UNIFI_MCP_MAX_BODY_BYTES", "99999999"),
        ("UNIFI_MCP_MAX_CONCURRENT_REQUESTS", "0"),
        ("UNIFI_MCP_REQUEST_TIMEOUT_SECONDS", "121"),
    ] {
        let output = binary().env(variable, value).output().await.unwrap();
        assert!(!output.status.success(), "{variable}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(variable));
        assert!(!stderr.contains("fake-controller-key"));
    }
}

#[tokio::test]
async fn binary_keeps_stdout_json_only_and_blocks_sdk_payload_logging_even_at_trace() {
    use std::process::Stdio;
    let mut child = binary()
        .env("UNIFI_MCP_LOG_LEVEL", "trace,rmcp::service=trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut body = message("tools/list", json!({}));
    body["params"]["_meta"]["private-test-canary"] = json!("do-not-log-this-payload");
    stdin
        .write_all(format!("{body}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert!(response["result"]["tools"].is_array(), "{response}");
    // Malformed input produces an application warning on stderr, without its payload.
    stdin
        .write_all(b"do-not-log-this-malformed-payload\n")
        .await
        .unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid stdio message"), "{stderr}");
    assert!(!stderr.contains("do-not-log-this"), "{stderr}");
    let mut extra = String::new();
    assert_eq!(stdout.read_line(&mut extra).await.unwrap(), 0);
}

#[tokio::test]
async fn stdio_closes_on_oversized_input_without_dispatching() {
    use std::process::Stdio;
    let mut child = binary()
        .env("UNIFI_MCP_MAX_BODY_BYTES", "1024")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut body = message("tools/list", json!({}));
    body["params"]["_meta"]["padding"] = json!("x".repeat(1500));
    stdin
        .write_all(format!("{body}\n").as_bytes())
        .await
        .unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("size limit exceeded")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stdio_exits_on_sigint_with_stdin_still_open() {
    use std::process::Stdio;
    let mut child = binary()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    stdin
        .write_all(format!("{}\n", message("tools/list", json!({}))).as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(serde_json::from_str::<Value>(&line).unwrap()["result"]["tools"].is_array());
    let status = tokio::process::Command::new("kill")
        .args(["-INT", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    drop(stdin);
}

fn settings() -> PortableSettings {
    PortableSettings {
        access: LocalAccess::default(),
        max_body_bytes: 65536,
        max_concurrent_requests: 4,
        request_timeout: Duration::from_secs(5),
        log_level: "info".into(),
    }
}

fn handler(server: &MockServer, protect: bool) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).unwrap();
    let runtime = if protect {
        RuntimeSettings::Protect(ProtectSettings {
            name: "test".into(),
            base_url,
            api_key: Zeroizing::new("fake-api-key".into()),
            tls: TlsMode::SystemRoots,
            timeout: Duration::from_secs(2),
            legacy: None,
        })
    } else {
        RuntimeSettings::Network(ControllerSettings {
            name: "test".into(),
            base_url,
            api_key: Zeroizing::new("fake-api-key".into()),
            username: "test".into(),
            password: Zeroizing::new("fake-password".into()),
            tls: TlsMode::SystemRoots,
            timeout: Duration::from_secs(2),
            site: "default".into(),
        })
    };
    build_handler(&runtime).unwrap()
}

fn router(settings: &PortableSettings, handler: UnifiMcp) -> Router {
    build_direct_router(
        settings,
        &DirectHttpSettings {
            host: "127.0.0.1".into(),
            port: 8000,
            bearers: Arc::new(
                GatewayBearers::new(
                    BEARER.into(),
                    Some("abcdef0123456789abcdef0123456789".into()),
                )
                .unwrap(),
            ),
            allowed_hosts: vec!["localhost".into()],
            allowed_origins: vec![],
        },
        handler,
        &CancellationToken::new(),
    )
}

fn message(method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientInfo": {"name":"wire-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params})
}

fn request(body: &Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {BEARER}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", VERSION)
        .header("mcp-method", body["method"].as_str().unwrap());
    if let Some(name) = body["params"]["name"].as_str() {
        builder = builder.header("mcp-name", name);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn json_response(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    assert!(response.headers().get("mcp-session-id").is_none());
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn camera_mock(server: &MockServer) {
    for (endpoint, response) in [
        ("meta/info", json!({"applicationVersion":"7.1.87"})),
        (
            "cameras",
            json!([{"id":"camera-1","modelKey":"camera","name":"Test camera","state":"CONNECTED"}]),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/proxy/protect/integration/v1/{endpoint}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn operator_grants_enable_preview_and_disclosure_independently() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=test; Path=/")
                .set_body_json(json!({})),
        )
        .mount(&server)
        .await;
    let wlan = json!({"_id":"wlan-1","name":"Test","enabled":true,"security":"wpapsk","x_passphrase":"synthetic-wifi-passphrase"});
    for (endpoint, rows) in [
        ("networkconf", json!([])),
        ("wlanconf", json!([wlan.clone()])),
        ("wlanconf/wlan-1", json!([wlan])),
    ] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/proxy/network/api/s/default/rest/{endpoint}"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"meta":{"rc":"ok"},"data":rows})),
            )
            .mount(&server)
            .await;
    }
    for (writes, secrets) in [(true, false), (false, true)] {
        let mut settings = settings();
        settings.access = LocalAccess { writes, secrets };
        let router = router(&settings, handler(&server, false));
        let (_, preview) = json_response(router.clone(), request(&message("tools/call", json!({"name":"wlans.update","arguments":{"wlan":"wlan-1","changes":{"enabled":false}}})))).await;
        if writes {
            assert_eq!(
                preview["result"]["structuredContent"]["applied"], false,
                "{preview}"
            );
        } else {
            assert!(
                preview["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("write access")
            );
        }
        let (_, response) = json_response(
            router,
            request(&message(
                "tools/call",
                json!({"name":"networks.read","arguments":{"includeSecrets":true}}),
            )),
        )
        .await;
        if secrets {
            assert!(
                response["result"]["structuredContent"]
                    .to_string()
                    .contains("synthetic-wifi-passphrase"),
                "{response}"
            );
        } else {
            assert!(
                response["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("secret disclosure")
            );
        }
    }
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "PUT")
    );
}

#[tokio::test]
async fn http_lists_tools_and_reads_without_gateway_identity_or_sessions() {
    let server = MockServer::start().await;
    camera_mock(&server).await;
    let router = router(&settings(), handler(&server, true));
    let mut list = request(&message("tools/list", json!({})));
    list.headers_mut()
        .insert("mcp-session-id", "obsolete-session".parse().unwrap());
    list.headers_mut()
        .insert("last-event-id", "obsolete-event".parse().unwrap());
    let (status, body) = json_response(router.clone(), list).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "cameras.search")
    );
    let (status, body) = json_response(
        router,
        request(&message(
            "tools/call",
            json!({"name":"cameras.search","arguments":{}}),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"]["cameras"][0]["name"],
        "Test camera"
    );
}

#[tokio::test]
async fn http_rejects_missing_auth_wrong_origin_host_and_duplicate_bearers() {
    let server = MockServer::start().await;
    let router = router(&settings(), handler(&server, false));
    for (header, value, status) in [
        ("authorization", None, StatusCode::UNAUTHORIZED),
        (
            "authorization",
            Some("Bearer wrong"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "origin",
            Some("https://untrusted.example"),
            StatusCode::FORBIDDEN,
        ),
        ("host", Some("untrusted.example"), StatusCode::FORBIDDEN),
    ] {
        let mut req = request(&message("tools/list", json!({})));
        req.headers_mut().remove(header);
        if let Some(value) = value {
            req.headers_mut().insert(header, value.parse().unwrap());
        }
        assert_eq!(router.clone().oneshot(req).await.unwrap().status(), status);
    }
    let mut req = request(&message("tools/list", json!({})));
    req.headers_mut()
        .append("authorization", format!("Bearer {BEARER}").parse().unwrap());
    assert_eq!(
        router.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn http_enforces_current_protocol_headers_versions_methods_and_body_limits() {
    let server = MockServer::start().await;
    let mut settings = settings();
    settings.max_body_bytes = 1024;
    let router = router(&settings, handler(&server, false));
    let call = message(
        "tools/call",
        json!({"name":"clients.search", "arguments":{}}),
    );
    for (header, value) in [
        ("mcp-method", None),
        ("mcp-name", None),
        ("mcp-protocol-version", None),
        ("mcp-method", Some("tools/list")),
        ("mcp-name", Some("devices.search")),
        ("mcp-protocol-version", Some("2025-11-25")),
    ] {
        let mut req = request(&call);
        req.headers_mut().remove(header);
        if let Some(value) = value {
            req.headers_mut().insert(header, value.parse().unwrap());
        }
        let (status, body) = json_response(router.clone(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{header}: {body}");
        assert_eq!(body["error"]["code"], -32020, "{header}: {body}");
    }
    let mut unsupported = message("tools/list", json!({}));
    unsupported["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    let mut req = request(&unsupported);
    req.headers_mut()
        .insert("mcp-protocol-version", "2099-01-01".parse().unwrap());
    let (status, body) = json_response(router.clone(), req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]["data"].to_string().contains(VERSION),
        "{body}"
    );
    for method in ["GET", "DELETE"] {
        let mut req = request(&message("tools/list", json!({})));
        *req.method_mut() = method.parse().unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    let req = request(&message(
        "tools/call",
        json!({"name":"clients.search", "arguments":{"query":"x".repeat(2000)}}),
    ));
    assert_eq!(
        router.oneshot(req).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn direct_calls_cannot_grant_themselves_writes_or_secrets() {
    let server = MockServer::start().await;
    let router = router(&settings(), handler(&server, false));
    for (tool, arguments, expected) in [
        ("wlans.update", json!({"confirm":true}), "write access"),
        ("vouchers.create", json!({"confirm":false}), "write access"),
        (
            "networks.read",
            json!({"includeSecrets":true}),
            "secret disclosure",
        ),
    ] {
        let mut req = request(&message(
            "tools/call",
            json!({"name":tool,"arguments":arguments}),
        ));
        req.headers_mut()
            .insert("x-mcp-identity", "forged-admin".parse().unwrap());
        let (_, body) = json_response(router.clone(), req).await;
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected),
            "{body}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn stdio_accepts_fragmented_current_messages_lists_and_reads_with_no_http_listener() {
    let server = MockServer::start().await;
    camera_mock(&server).await;
    let (client, stream) = tokio::io::duplex(65536);
    let (reader, writer) = tokio::io::split(stream);
    let task = tokio::spawn(serve_stdio_owned(
        settings(),
        handler(&server, true),
        reader,
        writer,
    ));
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    for body in [
        message("tools/list", json!({})),
        message(
            "tools/call",
            json!({"name":"cameras.search","arguments":{}}),
        ),
    ] {
        let bytes = format!("{body}\n");
        write.write_all(&bytes.as_bytes()[..17]).await.unwrap();
        tokio::task::yield_now().await;
        write.write_all(&bytes.as_bytes()[17..]).await.unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), read.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert!(response.get("result").is_some(), "{response}");
        if body["method"] == "tools/call" {
            assert_eq!(
                response["result"]["structuredContent"]["cameras"][0]["name"],
                "Test camera"
            );
        }
    }
    write.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

async fn serve_stdio_owned<R, W>(
    settings: PortableSettings,
    handler: UnifiMcp,
    reader: R,
    writer: W,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    serve_stdio(&settings, handler, reader, writer, CancellationToken::new())
        .await
        .unwrap();
}

#[tokio::test]
async fn stdio_denies_confirmed_writes_and_disclosure_before_controller_io() {
    let server = MockServer::start().await;
    let (client, stream) = tokio::io::duplex(65536);
    let (reader, writer) = tokio::io::split(stream);
    let task = tokio::spawn(serve_stdio_owned(
        settings(),
        handler(&server, false),
        reader,
        writer,
    ));
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    for (name, arguments, expected) in [
        ("wlans.update", json!({"confirm":true}), "write access"),
        (
            "networks.read",
            json!({"includeSecrets":true}),
            "secret disclosure",
        ),
    ] {
        let body = message("tools/call", json!({"name":name,"arguments":arguments}));
        write
            .write_all(format!("{body}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), read.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let body: Value = serde_json::from_str(&line).unwrap();
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected),
            "{body}"
        );
    }
    write.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(server.received_requests().await.unwrap().is_empty());
}
