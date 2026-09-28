//! The MCP `ServerHandler`: registry-driven `tools/list` and dispatch.
//!
//! Stateless by construction: the transport builds requests against one
//! shared handler value whose only state is the upstream clients and a
//! cached site identity, so the gateway can dial the server per call.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
};
use tokio::sync::{OnceCell, Semaphore};
use unifi_api::{IntegrationClient, LegacyClient, ProtectClient, models::PageRequest};

use crate::registry::{ToolSpec, ToolSurface, tools_for_surface};

/// How long a `tools/list` result stays fresh for clients that cache.
const CATALOG_TTL_MILLISECONDS: u64 = 300_000;

/// Page size for the site catalog scan.
const SITES_PAGE_LIMIT: u32 = 100;
/// Ceiling on scanned site rows. The controller-reported total is not an
/// in-server bound, so the scan refuses loudly past this point rather than
/// letting a console that promises an endless catalog spend unbounded
/// upstream requests. Refusing is distinct from the silent truncation this
/// bound replaces: a subset is never reported as a completed scan.
const SITES_SCAN_CEILING: u64 = 10_000;

/// The server-wide MCP handler. Clones share the upstream clients and the
/// resolved site identity; no clone ever observes another caller's data.
#[derive(Clone)]
pub struct UnifiMcp {
    runtime: Arc<Runtime>,
    local_transport: bool,
    requests: Arc<Semaphore>,
    request_timeout: std::time::Duration,
}

enum Runtime {
    Network {
        integration: Arc<IntegrationClient>,
        legacy: Arc<LegacyClient>,
        controller_name: Arc<str>,
        legacy_site: Arc<str>,
        site_id: OnceCell<String>,
    },
    Protect {
        protect: Arc<ProtectClient>,
        protect_name: Arc<str>,
        protect_events: Option<Arc<LegacyClient>>,
    },
}

impl UnifiMcp {
    #[must_use]
    pub fn new(
        integration: Arc<IntegrationClient>,
        legacy: Arc<LegacyClient>,
        controller_name: &str,
        legacy_site: &str,
    ) -> Self {
        Self {
            local_transport: false,
            requests: Arc::new(Semaphore::new(32)),
            request_timeout: std::time::Duration::from_secs(30),
            runtime: Arc::new(Runtime::Network {
                integration,
                legacy,
                controller_name: controller_name.into(),
                legacy_site: legacy_site.into(),
                site_id: OnceCell::new(),
            }),
        }
    }

    /// Construct the separate Protect-only runtime.
    #[must_use]
    pub fn new_protect(
        name: &str,
        protect: Arc<ProtectClient>,
        protect_events: Option<Arc<LegacyClient>>,
    ) -> Self {
        Self {
            local_transport: false,
            requests: Arc::new(Semaphore::new(32)),
            request_timeout: std::time::Duration::from_secs(30),
            runtime: Arc::new(Runtime::Protect {
                protect,
                protect_name: name.into(),
                protect_events,
            }),
        }
    }

    /// Mark a stdio or direct HTTP transport, which supplies its own ingress
    /// authentication without a gateway identity extension.
    #[must_use]
    pub fn with_local_transport(mut self) -> Self {
        self.local_transport = true;
        self
    }

    pub(crate) fn request_timeout(&self) -> std::time::Duration {
        self.request_timeout
    }

    /// Bound concurrent tool execution and total time, including stdio calls.
    #[must_use]
    pub fn with_request_limits(mut self, concurrency: usize, timeout: std::time::Duration) -> Self {
        self.requests = Arc::new(Semaphore::new(concurrency));
        self.request_timeout = timeout;
        self
    }

    pub(crate) fn integration(&self) -> &IntegrationClient {
        match self.runtime.as_ref() {
            Runtime::Network { integration, .. } => integration,
            Runtime::Protect { .. } => unreachable!("Protect dispatch cannot reach Network tools"),
        }
    }

    pub(crate) fn legacy(&self) -> &LegacyClient {
        match self.runtime.as_ref() {
            Runtime::Network { legacy, .. } => legacy,
            Runtime::Protect { .. } => unreachable!("Protect dispatch cannot reach Network tools"),
        }
    }

    pub(crate) fn controller_name(&self) -> &str {
        match self.runtime.as_ref() {
            Runtime::Network {
                controller_name, ..
            } => controller_name,
            Runtime::Protect { .. } => unreachable!("Protect dispatch cannot reach Network tools"),
        }
    }

    pub(crate) fn legacy_site(&self) -> &str {
        match self.runtime.as_ref() {
            Runtime::Network { legacy_site, .. } => legacy_site,
            Runtime::Protect { .. } => unreachable!("Protect dispatch cannot reach Network tools"),
        }
    }

    #[must_use]
    pub fn surface(&self) -> ToolSurface {
        match self.runtime.as_ref() {
            Runtime::Network { .. } => ToolSurface::Network,
            Runtime::Protect { .. } => ToolSurface::Protect,
        }
    }

    /// The configured Protect console name.
    pub(crate) fn protect_name(&self) -> &str {
        match self.runtime.as_ref() {
            Runtime::Protect { protect_name, .. } => protect_name,
            Runtime::Network { .. } => unreachable!("Network dispatch cannot reach Protect tools"),
        }
    }

    pub(crate) fn protect(&self) -> &ProtectClient {
        match self.runtime.as_ref() {
            Runtime::Protect { protect, .. } => protect,
            Runtime::Network { .. } => unreachable!("Network dispatch cannot reach Protect tools"),
        }
    }

    pub(crate) fn protect_events(&self) -> Result<&LegacyClient, McpError> {
        match self.runtime.as_ref() {
            Runtime::Protect { protect_events, .. } => protect_events.as_deref().ok_or_else(|| {
                McpError::invalid_params(
                    "no local Protect session is configured on this server, so \
                     historical detections cannot be read; configure the \
                     dedicated Protect username and password",
                    None,
                )
            }),
            Runtime::Network { .. } => unreachable!("Network dispatch cannot reach Protect tools"),
        }
    }

    /// The optional local Protect session used for historical events and,
    /// when supported, richer inventory. Its absence is a valid public-only
    /// configuration.
    pub(crate) fn protect_local(&self) -> Option<&LegacyClient> {
        match self.runtime.as_ref() {
            Runtime::Protect { protect_events, .. } => protect_events.as_deref(),
            Runtime::Network { .. } => unreachable!("Network dispatch cannot reach Protect tools"),
        }
    }

    /// Resolve and cache the Integration API site id: the site whose internal
    /// reference matches the configured legacy site name, scanning the
    /// paginated catalog up to [`SITES_SCAN_CEILING`] rows and refusing
    /// loudly beyond it, or the sole site when exactly one exists.
    /// Only success is cached, so a controller outage is retried per call.
    pub(crate) async fn site_id(&self) -> Result<String, McpError> {
        let Runtime::Network {
            integration,
            legacy_site,
            site_id,
            ..
        } = self.runtime.as_ref()
        else {
            unreachable!("Protect dispatch cannot resolve a Network site")
        };
        let resolved = site_id
            .get_or_try_init(|| async {
                let mut offset = 0_u64;
                let mut sole: Option<String> = None;
                loop {
                    let page = integration
                        .sites(PageRequest {
                            offset,
                            limit: SITES_PAGE_LIMIT,
                        })
                        .await
                        .map_err(crate::tools::api_error)?;
                    if let Some(site) = page.data.iter().find(|site| {
                        site.internal_reference.as_deref() == Some(legacy_site.as_ref())
                    }) {
                        return Ok(site.id.clone());
                    }
                    if offset == 0
                        && page.total_count == 1
                        && let [only] = page.data.as_slice()
                    {
                        sole = Some(only.id.clone());
                    }
                    offset += page.data.len() as u64;
                    if page.data.is_empty() || offset >= page.total_count {
                        break;
                    }
                    if offset >= SITES_SCAN_CEILING {
                        return Err(McpError::internal_error(
                            "the configured site was not found within the \
                             site-scan ceiling; refusing to page further \
                             through the catalog the controller reports",
                            None,
                        ));
                    }
                }
                sole.ok_or_else(|| {
                    McpError::internal_error(
                        "configured site was not found on the controller",
                        None,
                    )
                })
            })
            .await?;
        Ok(resolved.clone())
    }
}

impl ServerHandler for UnifiMcp {
    fn supported_protocol_versions(
        &self,
    ) -> std::borrow::Cow<'static, [rmcp::model::ProtocolVersion]> {
        if self.local_transport {
            std::borrow::Cow::Owned(vec![rmcp::model::ProtocolVersion::V_2026_07_28])
        } else {
            std::borrow::Cow::Borrowed(rmcp::model::ProtocolVersion::KNOWN_VERSIONS)
        }
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                self.surface().server_name(),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(match self.surface() {
                ToolSurface::Network => "Curated operational interface for a UniFi Network controller; tools/list is the authoritative catalog.",
                ToolSurface::Protect => "Curated read-only interface for a UniFi Protect console; tools/list is the authoritative catalog.",
            })
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send {
        // Registry order is the stable catalog order, so client and prompt
        // caches stay byte-identical between calls.
        std::future::ready(Ok(ListToolsResult::with_all_items(
            tools_for_surface(self.surface())
                .map(ToolSpec::catalog_tool)
                .collect(),
        )
        .with_ttl_ms(CATALOG_TTL_MILLISECONDS)))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        // The ingress middleware attaches the verified principal to the HTTP
        // request; the transport carries those parts into the call context.
        let principal = context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<crate::IdentityPrincipal>())
            .cloned();
        if !self.local_transport && principal.is_none() {
            return Err(McpError::invalid_request(
                "verified caller identity required",
                None,
            ));
        }
        let _permit = self.requests.try_acquire().map_err(|_| {
            McpError::internal_error("server is busy; no tool action was started", None)
        })?;
        tokio::time::timeout(self.request_timeout, self.call(&request, principal.as_ref()))
            .await.map_err(|_| McpError::internal_error("request timed out; a confirmed mutation may have taken effect; inspect controller state before another action", None))?
            .map(CallToolResponse::from)
    }
}
