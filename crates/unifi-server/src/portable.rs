//! Independent transports with operator-configured authority.

use std::{env, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::{
    RoleServer, ServiceExt,
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{
        Transport,
        streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
        },
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use unifi_mcp::{UnifiMcp, handler::LocalAccess};

use crate::auth::GatewayBearers;

/// Bounds and fixed authority shared by stdio and independent HTTP.
#[derive(Debug)]
pub struct PortableSettings {
    pub access: LocalAccess,
    pub max_body_bytes: usize,
    pub max_concurrent_requests: usize,
    pub request_timeout: Duration,
    pub log_level: String,
}

impl PortableSettings {
    /// Read independent transport settings without any gateway credentials.
    ///
    /// # Errors
    /// Rejects malformed values and out-of-range limits.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            access: LocalAccess {
                writes: flag("UNIFI_MCP_ALLOW_WRITES")?,
                secrets: flag("UNIFI_MCP_ALLOW_SECRET_DISCLOSURE")?,
            },
            max_body_bytes: number(
                "UNIFI_MCP_MAX_BODY_BYTES",
                1024 * 1024,
                1024,
                4 * 1024 * 1024,
            )?,
            max_concurrent_requests: number("UNIFI_MCP_MAX_CONCURRENT_REQUESTS", 32, 1, 256)?,
            request_timeout: Duration::from_secs(number(
                "UNIFI_MCP_REQUEST_TIMEOUT_SECONDS",
                30,
                1,
                120,
            )? as u64),
            log_level: value("UNIFI_MCP_LOG_LEVEL", "info")?,
        })
    }

    #[must_use]
    pub fn apply(&self, handler: UnifiMcp) -> UnifiMcp {
        handler
            .with_local_access(self.access)
            .with_request_limits(self.max_concurrent_requests, self.request_timeout)
    }
}

fn value(name: &'static str, default: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => bail!("{name} must be valid Unicode"),
    }
}

fn flag(name: &'static str) -> Result<bool> {
    match value(name, "false")?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => bail!("{name} must be true or false"),
    }
}

fn number(name: &'static str, default: usize, min: usize, max: usize) -> Result<usize> {
    let parsed = value(name, &default.to_string())?
        .parse::<usize>()
        .with_context(|| format!("{name} must be an unsigned integer"))?;
    ensure!(
        (min..=max).contains(&parsed),
        "{name} must be in {min}..={max}"
    );
    Ok(parsed)
}

/// Direct HTTP uses a dedicated rotating bearer, never a controller API key.
#[derive(Debug, Clone)]
pub struct DirectHttpSettings {
    pub host: String,
    pub port: u16,
    pub bearers: Arc<GatewayBearers>,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
}

impl DirectHttpSettings {
    /// Read listener and direct client credentials from the operator environment.
    ///
    /// # Errors
    /// Rejects absent or malformed bearer credentials and invalid listener settings.
    pub fn from_env() -> Result<Self> {
        let current = secret("UNIFI_MCP_HTTP_BEARER_CURRENT")?
            .context("UNIFI_MCP_HTTP_BEARER_CURRENT is required for HTTP")?;
        let previous = secret("UNIFI_MCP_HTTP_BEARER_PREVIOUS")?;
        let host = value("UNIFI_MCP_HOST", "127.0.0.1")?;
        let port = u16::try_from(number("UNIFI_MCP_PORT", 8000, 1, u16::MAX.into())?)?;
        let default_hosts =
            format!("localhost,localhost:{port},127.0.0.1,127.0.0.1:{port},[::1],[::1]:{port}");
        Ok(Self {
            host,
            port,
            bearers: Arc::new(GatewayBearers::from_protected(current, previous)?),
            allowed_hosts: csv(&value("UNIFI_MCP_ALLOWED_HOSTS", &default_hosts)?),
            allowed_origins: csv(&value("UNIFI_MCP_ALLOWED_ORIGINS", "")?),
        })
    }
}

fn secret(name: &'static str) -> Result<Option<zeroize::Zeroizing<String>>> {
    match env::var(name) {
        Ok(value) => {
            let value = zeroize::Zeroizing::new(value);
            ensure!(
                value.len() <= 16 * 1024,
                "{name} exceeds the secret size limit"
            );
            Ok(Some(value))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => bail!("{name} is invalid"),
    }
}

fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Build a direct, authenticated HTTP endpoint using current MCP request metadata.
pub fn build_direct_router(
    settings: &PortableSettings,
    http: &DirectHttpSettings,
    handler: UnifiMcp,
    cancellation: &CancellationToken,
) -> Router {
    let handler = settings.apply(handler);
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_cancellation_token(cancellation.child_token())
            .with_allowed_hosts(http.allowed_hosts.clone())
            .with_allowed_origins(http.allowed_origins.clone())
            .with_legacy_session_mode(false)
            .with_stateless_protocol_metadata_required(true)
            .with_max_request_body_bytes(settings.max_body_bytes)
            .with_json_response(true),
    );
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(
            http.clone(),
            require_direct_client,
        ))
        .layer(ConcurrencyLimitLayer::new(settings.max_concurrent_requests))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            settings.request_timeout,
        ))
        .route(
            "/healthz",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"status":"ok", "version":env!("CARGO_PKG_VERSION")}))
            }),
        )
}

async fn require_direct_client(
    State(auth): State<DirectHttpSettings>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    if !host.is_some_and(|host| {
        auth.allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    }) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if headers.contains_key(header::ORIGIN)
        && !headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|origin| auth.allowed_origins.iter().any(|allowed| allowed == origin))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1
        || !bearer.is_some_and(|bearer| auth.bearers.accepts(bearer.as_bytes()))
    {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }
    next.run(request).await
}

/// Newline JSON transport that closes on malformed or oversized input.
/// Partial input survives cancellation of `receive`; neither payloads nor
/// parser errors are logged because they can contain tool secrets.
struct BoundedStdio<R: AsyncRead, W> {
    reader: BufReader<R>,
    pending: Vec<u8>,
    writer: Arc<Mutex<W>>,
    limit: usize,
}

impl<R, W> Transport<RoleServer> for BoundedStdio<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        let writer = Arc::clone(&self.writer);
        async move {
            let mut bytes = serde_json::to_vec(&item)
                .map_err(|_| std::io::Error::other("MCP response serialization failed"))?;
            bytes.push(b'\n');
            let mut writer = writer.lock().await;
            writer.write_all(&bytes).await?;
            writer.flush().await
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            let available = match self.reader.fill_buf().await {
                Ok(bytes) if !bytes.is_empty() => bytes,
                _ => return None,
            };
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(available.len(), |index| index + 1);
            if self.pending.len() + count > self.limit {
                tracing::warn!("stdio message size limit exceeded; closing transport");
                return None;
            }
            self.pending.extend_from_slice(&available[..count]);
            self.reader.consume(count);
            if newline.is_some() {
                let message = serde_json::from_slice(&self.pending).ok();
                self.pending.clear();
                if message.is_none() {
                    tracing::warn!("invalid stdio message; closing transport");
                }
                return message;
            }
        }
    }

    async fn close(&mut self) -> std::io::Result<()> {
        self.writer.lock().await.shutdown().await
    }
}

/// Serve newline-delimited MCP on a bounded byte stream (stdin/stdout in the binary).
///
/// # Errors
/// Reports startup or service failures without serializing incoming payloads.
pub async fn serve_stdio<R, W>(
    settings: &PortableSettings,
    handler: UnifiMcp,
    reader: R,
    writer: W,
    cancellation: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let transport = BoundedStdio {
        reader: BufReader::new(reader),
        pending: Vec::new(),
        writer: Arc::new(Mutex::new(writer)),
        limit: settings.max_body_bytes,
    };
    let running = settings
        .apply(handler)
        .serve_with_ct(transport, cancellation)
        .await
        .map_err(|_| anyhow::anyhow!("stdio MCP startup failed"))?;
    running.waiting().await.context("stdio MCP task failed")?;
    Ok(())
}
