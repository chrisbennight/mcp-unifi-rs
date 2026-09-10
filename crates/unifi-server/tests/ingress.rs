//! Wire tests for the authenticated MCP mount: the ingress boundary and the
//! stateless Streamable HTTP round trip, exercised over real HTTP semantics
//! with a loopback JWKS fake.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    middleware,
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tower::util::ServiceExt;
use unifi_api::TlsMode;
use unifi_mcp::UnifiMcp;
use unifi_server::{
    auth::{
        GatewayBearers, IdentityPrincipal, IdentityVerifier, IdentityVerifierSettings, IngressAuth,
        require_gateway,
    },
    config::{ControllerSettings, RuntimeSettings, Settings},
    server::{build_handler, build_router},
};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const BEARER: &str = "0123456789abcdef0123456789abcdef";
const ACTOR: &str = "mcp.cacahuate.org";

#[derive(Serialize)]
struct ActorClaim {
    sub: String,
}

#[derive(Serialize)]
struct IdentityClaims {
    sub: String,
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    groups: Vec<String>,
    act: ActorClaim,
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

fn identity_token_with_groups(signing: &SigningKey, groups: &[&str]) -> String {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("timestamp")
            .as_secs(),
    )
    .expect("timestamp range");
    let claims = IdentityClaims {
        sub: "user:wire-test".into(),
        iss: "https://gateway.test".into(),
        aud: "unifi".into(),
        iat: now,
        exp: now + 300,
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        act: ActorClaim { sub: ACTOR.into() },
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("test-key".into());
    let document = signing.to_pkcs8_der().expect("PKCS#8 test key");
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_der(document.as_bytes()),
    )
    .expect("identity token")
}

fn identity_token(signing: &SigningKey) -> String {
    identity_token_with_groups(signing, &["unifi"])
}

async fn jwks_server(signing: &SigningKey) -> MockServer {
    let server = MockServer::start().await;
    let public_key = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "x": public_key,
                "kid": "test-key",
                "alg": "EdDSA"
            }]
        })))
        .mount(&server)
        .await;
    server
}

fn handler() -> UnifiMcp {
    build_handler(&RuntimeSettings::Network(ControllerSettings {
        name: "unifi".into(),
        base_url: Url::parse("https://127.0.0.1:65531").expect("controller URL"),
        api_key: Zeroizing::new("test-api-key".into()),
        username: "svc-mcp".into(),
        password: Zeroizing::new("test-password".into()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(2),
        site: "default".into(),
    }))
    .expect("handler")
}

fn settings(jwks: &MockServer) -> Settings {
    Settings {
        host: "127.0.0.1".into(),
        port: 8000,
        log_level: "info".into(),
        allowed_hosts: vec!["localhost".into()],
        allowed_origins: Vec::new(),
        request_timeout: Duration::from_secs(5),
        max_concurrent_requests: 4,
        max_body_bytes: 64 * 1024,
        bearers: Arc::new(GatewayBearers::new(BEARER.into(), None).expect("bearer")),
        identity: IdentityVerifierSettings {
            jwks_url: Url::parse(&format!("{}/jwks", jwks.uri())).expect("JWKS URL"),
            issuer: "https://gateway.test".into(),
            actor: ACTOR.into(),
            audience: "unifi".into(),
            request_timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_mins(1),
        },
        runtime: RuntimeSettings::Network(ControllerSettings {
            name: "unifi".into(),
            base_url: Url::parse("https://127.0.0.1:65531").expect("controller URL"),
            api_key: Zeroizing::new("test-api-key".into()),
            username: "svc-mcp".into(),
            password: Zeroizing::new("test-password".into()),
            tls: TlsMode::SystemRoots,
            timeout: Duration::from_secs(2),
            site: "default".into(),
        }),
    }
}

fn mcp_request(body: &str, credentials: &[(header::HeaderName, String)]) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list");
    for (name, value) in credentials {
        request = request.header(name, value);
    }
    request.body(Body::from(body.to_owned())).expect("request")
}

/// A sessionless `2026-07-28` request: the per-request `_meta` carries the
/// negotiated protocol state an initialize handshake would otherwise hold.
fn tools_list_body() -> &'static str {
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#
}

#[tokio::test]
async fn each_missing_credential_fails_closed_with_401() {
    let signing = signing_key();
    let jwks = jwks_server(&signing).await;
    let cancellation = CancellationToken::new();
    let router = build_router(&settings(&jwks), handler(), &cancellation).expect("router");

    let bearer = (header::AUTHORIZATION, format!("Bearer {BEARER}"));
    let identity = (
        header::HeaderName::from_static("x-mcp-identity"),
        identity_token(&signing),
    );
    let attempts: [&[(header::HeaderName, String)]; 3] = [
        &[],
        std::slice::from_ref(&bearer),
        std::slice::from_ref(&identity),
    ];
    for credentials in attempts {
        let response = router
            .clone()
            .oneshot(mcp_request(tools_list_body(), credentials))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn stateless_tools_list_round_trip_serves_the_registry_catalog() {
    let signing = signing_key();
    let jwks = jwks_server(&signing).await;
    let cancellation = CancellationToken::new();
    let router = build_router(&settings(&jwks), handler(), &cancellation).expect("router");

    // Two independent requests with no session header prove the mount is
    // stateless: each round trip stands alone, per-call like the gateway.
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(mcp_request(
                tools_list_body(),
                &[
                    (header::AUTHORIZATION, format!("Bearer {BEARER}")),
                    (
                        header::HeaderName::from_static("x-mcp-identity"),
                        identity_token(&signing),
                    ),
                ],
            ))
            .await
            .expect("response");
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            content_type.starts_with("application/json"),
            "{content_type}"
        );
        // This in-process response is generated by the registry under test. Do
        // not impose a second, unrelated ceiling on the complete tool catalog.
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(payload["id"], 1);
        let tools = payload["result"]["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        let registry: Vec<&str> = unifi_mcp::tools_for_surface(unifi_mcp::ToolSurface::Network)
            .map(|spec| spec.name)
            .collect();
        assert_eq!(names, registry, "{payload}");
    }
}

#[tokio::test]
async fn middleware_attaches_the_verified_principal_to_the_request() {
    let signing = signing_key();
    let jwks = jwks_server(&signing).await;
    let configuration = settings(&jwks);
    let verifier = IdentityVerifier::new(configuration.identity.clone()).expect("verifier");
    let auth = IngressAuth::new(
        Arc::clone(&configuration.bearers),
        verifier,
        configuration.allowed_hosts.clone(),
        configuration.allowed_origins.clone(),
    );
    // A probe route observes exactly what the MCP handler will: the verified
    // principal arrives as a request extension, populated from the JWT.
    let router = Router::new()
        .route(
            "/probe",
            get(
                |Extension(principal): Extension<IdentityPrincipal>| async move {
                    format!("{}:{}", principal.subject, principal.groups.join(","))
                },
            ),
        )
        .layer(middleware::from_fn_with_state(auth, require_gateway));

    let response = router
        .oneshot(
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
                .header("x-mcp-identity", identity_token(&signing))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024).await.expect("body");
    assert_eq!(bytes.as_ref(), b"user:wire-test:unifi");
}

/// One sessionless `tools/call` for `networks.read` with the secret opt-in.
fn secrets_call_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "networks.read",
            "arguments": {"includeSecrets": true},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    })
    .to_string()
}

#[tokio::test]
async fn the_verified_group_set_reaches_tool_authorization_decisions() {
    let signing = signing_key();
    let jwks = jwks_server(&signing).await;
    let cancellation = CancellationToken::new();
    let router = build_router(&settings(&jwks), handler(), &cancellation).expect("router");

    // The two callers differ only in their verified group set. The non-admin
    // is refused by the group gate; the admin passes it and fails later on
    // the unreachable controller — distinct errors that prove the verified
    // principal traversed the transport into the tool decision.
    for (groups, expected) in [
        (vec!["unifi"], "mcp-admins"),
        (vec!["unifi", "mcp-admins"], "controller"),
    ] {
        let token = identity_token_with_groups(&signing, &groups);
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "networks.read")
            .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
            .header("x-mcp-identity", token);
        let response = router
            .clone()
            .oneshot(
                request
                    .body(Body::from(secrets_call_body()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let message = payload["error"]["message"].as_str().expect("error message");
        assert!(message.contains(expected), "{groups:?}: {payload}");
    }
}
