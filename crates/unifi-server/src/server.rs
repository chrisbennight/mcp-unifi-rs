use std::sync::Arc;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

use unifi_api::{
    ApiError, ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, ProtectClient,
};
use unifi_mcp::UnifiMcp;

use crate::{
    auth::{IdentityVerifier, IngressAuth, require_gateway},
    config::{RuntimeSettings, Settings},
};

/// Construct the MCP handler's upstream clients from controller settings.
///
/// Construction is offline: no controller connection is attempted, so the
/// server boots and stays live while the controller is unreachable.
///
/// # Errors
///
/// Returns an error when a client cannot be built from the configuration,
/// such as an unusable TLS trust setting.
pub fn build_handler(runtime: &RuntimeSettings) -> Result<UnifiMcp, ApiError> {
    match runtime {
        RuntimeSettings::Network(controller) => {
            let integration = IntegrationClient::new(&ControllerConfig {
                name: controller.name.clone(),
                base_url: controller.base_url.clone(),
                api_key: controller.api_key.clone(),
                tls: controller.tls.clone(),
                timeout: controller.timeout,
            })?;
            let legacy = LegacyClient::new(&LegacyConfig {
                name: controller.name.clone(),
                base_url: controller.base_url.clone(),
                username: controller.username.clone(),
                password: controller.password.clone(),
                tls: controller.tls.clone(),
                timeout: controller.timeout,
            })?;
            Ok(UnifiMcp::new(
                Arc::new(integration),
                Arc::new(legacy),
                &controller.name,
                &controller.site,
                vec![controller.api_key.clone(), controller.password.clone()],
            ))
        }
        RuntimeSettings::Protect(console) => {
            let protect = ProtectClient::new(&ControllerConfig {
                name: console.name.clone(),
                base_url: console.base_url.clone(),
                api_key: console.api_key.clone(),
                tls: console.tls.clone(),
                timeout: console.timeout,
            })?;
            let mut redact = vec![console.api_key.clone()];
            let protect_events = console
                .legacy
                .as_ref()
                .map(|credentials| {
                    redact.push(credentials.password.clone());
                    LegacyClient::new(&LegacyConfig {
                        name: console.name.clone(),
                        base_url: console.base_url.clone(),
                        username: credentials.username.clone(),
                        password: credentials.password.clone(),
                        tls: console.tls.clone(),
                        timeout: console.timeout,
                    })
                })
                .transpose()?
                .map(Arc::new);
            Ok(UnifiMcp::new_protect(
                &console.name,
                Arc::new(protect),
                protect_events,
                redact,
            ))
        }
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

/// Compose the independent health endpoint and authenticated MCP service.
///
/// The liveness endpoint stays outside every authenticated layer. All `/mcp`
/// traffic passes the request timeout, the concurrency bound, gateway
/// ingress authentication, and then the body limit, in that order: the
/// bounds wrap everything including authentication's JWKS network I/O, and
/// authentication rejects from headers alone, so no body is buffered for an
/// unauthenticated request.
///
/// # Errors
///
/// Returns an error when the identity verifier cannot be constructed safely.
pub fn build_router(
    settings: &Settings,
    handler: UnifiMcp,
    cancellation: &CancellationToken,
) -> Result<Router, crate::auth::AuthConfigError> {
    let handler =
        handler.with_request_limits(settings.max_concurrent_requests, settings.request_timeout);
    let verifier = IdentityVerifier::new(settings.identity.clone())?;
    let auth = IngressAuth::new(
        Arc::clone(&settings.bearers),
        verifier,
        settings.allowed_hosts.clone(),
        settings.allowed_origins.clone(),
    );
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_cancellation_token(cancellation.child_token())
            .with_allowed_hosts(settings.allowed_hosts.clone())
            .with_allowed_origins(settings.allowed_origins.clone())
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );

    let mcp = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(
            settings.max_body_bytes,
            enforce_body_limit,
        ))
        .layer(middleware::from_fn_with_state(auth, require_gateway))
        .layer(ConcurrencyLimitLayer::new(settings.max_concurrent_requests))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            settings.request_timeout,
        ));

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .merge(mcp)
        .layer(TraceLayer::new_for_http()))
}

async fn enforce_body_limit(State(limit): State<usize>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, limit).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
        middleware,
        routing::post,
    };
    use rmcp::model::CallToolRequestParams;
    use tokio_util::sync::CancellationToken;
    use tower::util::ServiceExt;
    use unifi_api::TlsMode;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path, query_param},
    };
    use zeroize::Zeroizing;

    use super::{build_handler, build_router, enforce_body_limit};
    use crate::config::{
        ProtectLegacySettings, ProtectSettings, RuntimeSettings, test_support::settings,
    };

    #[tokio::test]
    async fn liveness_is_independent_and_mcp_fails_closed_without_credentials() {
        let cancellation = CancellationToken::new();
        let runtime = RuntimeSettings::Network(crate::config::test_support::controller());
        let handler = build_handler(&runtime).expect("handler");
        let router = build_router(&settings(), handler, &cancellation).expect("router");

        let health = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::OK);
        let bytes = to_bytes(health.into_body(), 1024).await.expect("body");
        let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));

        let mcp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("MCP request"),
            )
            .await
            .expect("MCP response");
        assert_eq!(mcp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn body_limit_rejects_oversized_requests_before_the_handler() {
        let router = Router::new()
            .route("/", post(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(4_usize, enforce_body_limit));

        for (body, expected) in [
            (Body::from("1234"), StatusCode::NO_CONTENT),
            (Body::from("12345"), StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/")
                        .body(body)
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), expected);
        }
    }

    #[tokio::test]
    async fn handler_construction_wires_and_scrubs_the_protect_event_session() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/proxy/protect/integration/v1/meta/info"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"applicationVersion": "7.1.87"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/proxy/protect/integration/v1/cameras"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .and(body_json(serde_json::json!({
                "username": "svc-protect-events",
                "password": "protect-local-password"
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
            .and(query_param("start", "1000"))
            .and(query_param("end", "2000"))
            .and(query_param("limit", "3"))
            .and(query_param("offset", "0"))
            .and(query_param("types", "motion"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "event-1", "type": "protect-local-password", "start": 1500}
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let protect = ProtectSettings {
            name: "cameras".to_owned(),
            base_url: Url::parse(&server.uri()).expect("mock URL"),
            api_key: Zeroizing::new("protect-api-key".to_owned()),
            tls: TlsMode::SystemRoots,
            timeout: std::time::Duration::from_secs(5),
            legacy: Some(ProtectLegacySettings {
                username: "svc-protect-events".to_owned(),
                password: Zeroizing::new("protect-local-password".to_owned()),
            }),
        };
        let runtime = RuntimeSettings::Protect(protect);
        let handler = build_handler(&runtime).expect("handler");
        let mut request = CallToolRequestParams::default();
        request.name = "protect.events".to_owned().into();
        request.arguments = Some(
            serde_json::json!({"start": 1000, "end": 2000, "limit": 2})
                .as_object()
                .expect("arguments")
                .clone(),
        );
        let result = handler.call(&request, None).await.expect("Protect events");
        let output = result.structured_content.expect("structured result");
        assert_eq!(output["rows"][0]["kind"], "[redacted]");
    }
}
