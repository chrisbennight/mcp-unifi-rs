use std::time::Duration;

use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    ApiError, BoundedMessage, ControllerConfig, RecordFingerprint, TlsMode, http,
    models::{
        ApplicationInfo, ClientAction, ClientSummary, DeviceAction, DeviceDetail, DeviceStatistics,
        DeviceSummary, FirewallPolicy, FirewallZone, Page, PageRequest, PortAction, SiteSummary,
        Voucher, VoucherCreate, VoucherCreateResponse,
    },
};

/// Longest `Retry-After` the client will sleep for before retrying an
/// idempotent read once. Anything longer is surfaced to the caller.
///
/// Shared with the Protect client so both consoles answer a rate limit the
/// same way; a second copy of this policy would drift from this one.
pub(crate) const MAXIMUM_RETRY_AFTER: Duration = Duration::from_secs(10);

/// Client for one controller's official Network Integration API.
///
/// All paths live under `/proxy/network/integration/v1` on the console
/// origin; every request authenticates with the `X-API-KEY` header. Request
/// URLs are assembled from individual path segments, so an identifier
/// containing URL syntax stays one literal segment instead of re-routing the
/// request.
pub struct IntegrationClient {
    http: reqwest::Client,
    base: Url,
    api_key: Zeroizing<String>,
}

impl std::fmt::Debug for IntegrationClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IntegrationClient")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl IntegrationClient {
    /// Build a client for one controller.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Config`] when the TLS material or base URL is
    /// unusable.
    pub fn new(config: &ControllerConfig) -> Result<Self, ApiError> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .use_rustls_tls();
        builder = match &config.tls {
            TlsMode::SystemRoots => builder,
            TlsMode::CustomCa(pem) => {
                let certificate = reqwest::Certificate::from_pem(pem)
                    .map_err(|error| ApiError::Config(format!("custom CA rejected: {error}")))?;
                builder.add_root_certificate(certificate)
            }
            TlsMode::Pinned(pins) => {
                builder.use_preconfigured_tls(crate::pinning::pinned_client_config(pins.clone()))
            }
            TlsMode::AcceptInvalid => builder.danger_accept_invalid_certs(true),
        };
        let http = builder
            .build()
            .map_err(|error| ApiError::Config(format!("client construction failed: {error}")))?;
        if config.base_url.cannot_be_a_base() {
            return Err(ApiError::Config(
                "base URL cannot carry API paths".to_owned(),
            ));
        }
        Ok(Self {
            http,
            base: config.base_url.clone(),
            api_key: config.api_key.clone(),
        })
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn info(&self) -> Result<ApplicationInfo, ApiError> {
        self.get_json(&["info"], &[]).await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn sites(&self, page: PageRequest) -> Result<Page<SiteSummary>, ApiError> {
        self.get_json(&["sites"], &page_query(page)).await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn devices(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<DeviceSummary>, ApiError> {
        self.get_json(&["sites", site_id, "devices"], &page_query(page))
            .await
    }

    /// Full detail for one device, including port and radio tables.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn device_detail(
        &self,
        site_id: &str,
        device_id: &str,
    ) -> Result<DeviceDetail, ApiError> {
        self.get_json(&["sites", site_id, "devices", device_id], &[])
            .await
    }

    /// Latest statistics snapshot for one device.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn device_statistics(
        &self,
        site_id: &str,
        device_id: &str,
    ) -> Result<DeviceStatistics, ApiError> {
        self.get_json(
            &[
                "sites",
                site_id,
                "devices",
                device_id,
                "statistics",
                "latest",
            ],
            &[],
        )
        .await
    }

    /// Restart one device. Never retried.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the action.
    pub async fn restart_device(&self, site_id: &str, device_id: &str) -> Result<(), ApiError> {
        self.post_action(
            &["sites", site_id, "devices", device_id, "actions"],
            &DeviceAction::Restart,
        )
        .await
    }

    /// Power-cycle one `PoE` switch port. Never retried.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the action.
    pub async fn power_cycle_port(
        &self,
        site_id: &str,
        device_id: &str,
        port_index: u32,
    ) -> Result<(), ApiError> {
        self.post_action(
            &[
                "sites",
                site_id,
                "devices",
                device_id,
                "interfaces",
                "ports",
                &port_index.to_string(),
                "actions",
            ],
            &PortAction::PowerCycle,
        )
        .await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn clients(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<ClientSummary>, ApiError> {
        self.get_json(&["sites", site_id, "clients"], &page_query(page))
            .await
    }

    /// Authorize one client for guest access. Never retried.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the action.
    pub async fn authorize_guest(&self, site_id: &str, client_id: &str) -> Result<(), ApiError> {
        self.post_action(
            &["sites", site_id, "clients", client_id, "actions"],
            &ClientAction::AuthorizeGuestAccess,
        )
        .await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn vouchers(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<Voucher>, ApiError> {
        self.get_json(
            &["sites", site_id, "hotspot", "vouchers"],
            &page_query(page),
        )
        .await
    }

    /// Create hotspot vouchers. Never retried.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the request.
    pub async fn create_vouchers(
        &self,
        site_id: &str,
        request: &VoucherCreate,
    ) -> Result<VoucherCreateResponse, ApiError> {
        let response = self
            .send(
                self.request(Method::POST, &["sites", site_id, "hotspot", "vouchers"])?
                    .json(request),
            )
            .await?;
        decode(response).await
    }

    /// Delete one voucher. Never retried.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the request.
    pub async fn delete_voucher(&self, site_id: &str, voucher_id: &str) -> Result<(), ApiError> {
        let response = self
            .send(self.request(
                Method::DELETE,
                &["sites", site_id, "hotspot", "vouchers", voucher_id],
            )?)
            .await?;
        drop(response);
        Ok(())
    }

    /// Zone-based firewall zones. A console still on the classic firewall
    /// answers HTTP 400 here; see [`crate::capability`].
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn firewall_zones(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<FirewallZone>, ApiError> {
        self.get_json(&["sites", site_id, "firewall", "zones"], &page_query(page))
            .await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn firewall_policies(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<FirewallPolicy>, ApiError> {
        self.get_json(
            &["sites", site_id, "firewall", "policies"],
            &page_query(page),
        )
        .await
    }

    /// GET with one bounded retry when the controller rate limits and names
    /// an acceptable `Retry-After`.
    async fn get_json<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<T, ApiError> {
        let first = self
            .send(self.request_with_query(Method::GET, segments, query)?)
            .await;
        let response = match first {
            Ok(response) => response,
            Err(ApiError::RateLimited {
                retry_after: Some(delay),
            }) if delay <= MAXIMUM_RETRY_AFTER => {
                tokio::time::sleep(delay).await;
                self.send(self.request_with_query(Method::GET, segments, query)?)
                    .await?
            }
            Err(error) => return Err(error),
        };
        decode(response).await
    }

    async fn post_action<A: Serialize>(
        &self,
        segments: &[&str],
        action: &A,
    ) -> Result<(), ApiError> {
        let response = self
            .send(self.request(Method::POST, segments)?.json(action))
            .await?;
        drop(response);
        Ok(())
    }

    /// One zone-based policy exactly as the controller stores it, plus a
    /// fingerprint of every property, from a single read.
    ///
    /// The record is returned unmodelled on purpose. The only safe way to
    /// change one field of a policy is to send every other field back
    /// untouched, and a model can only send back what it understands — a
    /// property this server does not know would be dropped by the write, on
    /// the object that decides what traffic the network permits.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn firewall_policy_snapshot(
        &self,
        site_id: &str,
        policy_id: &str,
    ) -> Result<
        (
            std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>,
            RecordFingerprint,
        ),
        ApiError,
    > {
        let response = self
            .send(self.request(
                Method::GET,
                &["sites", site_id, "firewall", "policies", policy_id],
            )?)
            .await?;
        let record: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
            decode(response).await?;
        let fingerprint = RecordFingerprint::from_raw_record(&record);
        Ok((record, fingerprint))
    }

    /// Replace one zone-based policy with the record given.
    ///
    /// The upstream interface offers no partial update that can enable or
    /// disable a policy: its `PATCH` accepts only the logging flag, and its
    /// `PUT` requires the whole policy. So the caller reads the policy, alters
    /// the one field it means to change, and sends the rest back exactly as it
    /// arrived. Nothing here interprets the record.
    ///
    /// A mutation: never retried after an ambiguous transport result, and it
    /// asserts nothing about persistence.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request fails or the controller
    /// rejects the write.
    pub async fn replace_firewall_policy(
        &self,
        site_id: &str,
        policy_id: &str,
        record: &std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>,
    ) -> Result<(), ApiError> {
        let response = self
            .send(
                self.request(
                    Method::PUT,
                    &["sites", site_id, "firewall", "policies", policy_id],
                )?
                .json(record),
            )
            .await?;
        drop(response);
        Ok(())
    }

    fn request(&self, method: Method, segments: &[&str]) -> Result<RequestBuilder, ApiError> {
        self.request_with_query(method, segments, &[])
    }

    fn request_with_query(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<RequestBuilder, ApiError> {
        let url = self.endpoint(segments, query)?;
        Ok(self
            .http
            .request(method, url)
            .header("X-API-KEY", self.api_key.as_str())
            .header(reqwest::header::ACCEPT, "application/json"))
    }

    /// Assemble the request URL under the Integration API prefix from
    /// percent-encoded path segments; see [`crate::http::build_url`] for the
    /// segment validation contract.
    fn endpoint(&self, segments: &[&str], query: &[(&str, String)]) -> Result<Url, ApiError> {
        let mut all: Vec<&str> = vec!["proxy", "network", "integration", "v1"];
        all.extend_from_slice(segments);
        http::build_url(&self.base, &all, query)
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, ApiError> {
        let response = request.send().await.map_err(|error| {
            ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
        })?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ApiError::RateLimited {
                retry_after: http::retry_after(&response),
            });
        }
        Err(ApiError::Status {
            status: status.as_u16(),
            message: bounded_error_message(response, &self.api_key).await,
        })
    }
}

fn page_query(page: PageRequest) -> [(&'static str, String); 2] {
    [
        ("offset", page.offset.to_string()),
        ("limit", page.limit.to_string()),
    ]
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, ApiError> {
    let bytes = http::read_bounded_body(response).await?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ApiError::Decode(BoundedMessage::new(&error.to_string())))
}

/// Extract a bounded, human-oriented message from an upstream error body
/// without ever forwarding the raw payload. A controller that echoes the
/// submitted credential back in an error body must not leak it through the
/// error surface, so any occurrence of the key is redacted before bounding.
pub(crate) async fn bounded_error_message(response: Response, api_key: &str) -> BoundedMessage {
    let Ok(bytes) = http::read_bounded_body(response).await else {
        return BoundedMessage::new("no error detail");
    };
    bounded_error_message_from_bytes(&bytes, api_key)
}

/// Extract a bounded, credential-redacted message from an error body that a
/// caller already read in order to retain structural diagnostics such as its
/// byte count.
pub(crate) fn bounded_error_message_from_bytes(bytes: &[u8], api_key: &str) -> BoundedMessage {
    let extracted = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned());
    let redacted = if api_key.is_empty() {
        extracted
    } else {
        extracted.replace(api_key, "<redacted>")
    };
    BoundedMessage::new(&redacted)
}
