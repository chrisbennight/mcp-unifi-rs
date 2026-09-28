use std::time::Duration;

use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    ApiError, BoundedMessage, ControllerConfig, RecordFingerprint, TlsMode, http,
    models::{
        ApplicationInfo, ClientAction, ClientDetail, ClientSummary, DeviceAction, DeviceDetail,
        DeviceStatistics, DeviceSummary, FirewallPolicy, FirewallZone, GuestActionResponse,
        GuestAuthorizationLimits, Page, PageRequest, PortAction, SiteSummary, VoucherCreate,
        VoucherCreateResponse, VoucherDetails,
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

    /// Resolve a bounded set of official application IDs to display names.
    /// # Errors
    /// Rejects an empty or oversized selection and propagates upstream failures.
    pub async fn dpi_names(
        &self,
        ids: &[u32],
        categories: bool,
    ) -> Result<Vec<crate::traffic::DpiName>, ApiError> {
        if ids.is_empty() || ids.len() > 50 {
            return Err(ApiError::Config(
                "DPI name selection must contain 1-50 IDs".to_owned(),
            ));
        }
        let filter = format!(
            "id.in({})",
            ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
        );
        let page: Page<crate::traffic::DpiName> = self
            .get_json(
                &[
                    "dpi",
                    if categories {
                        "categories"
                    } else {
                        "applications"
                    },
                ],
                &[
                    ("offset", "0".to_owned()),
                    ("limit", "50".to_owned()),
                    ("filter", filter),
                ],
            )
            .await?;
        // The controller's filtered totalCount is the unfiltered catalog size.
        // Validate the actual selected rows instead of paging that total.
        if page.data.len() > ids.len()
            || page
                .data
                .iter()
                .any(|row| !ids.contains(&row.id) || row.name.len() > 4096)
        {
            return Err(ApiError::Decode("unexpected DPI name selection".into()));
        }
        Ok(page.data)
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn sites(&self, page: PageRequest) -> Result<Page<SiteSummary>, ApiError> {
        self.get_json(&["sites"], &page_query(page)).await
    }

    /// RADIUS profiles available to wireless enterprise configurations.
    /// Each bounded page retains the fields the controller returned.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn radius_profiles(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<Map<String, Value>>, ApiError> {
        self.get_json(&["sites", site_id, "radius", "profiles"], &page_query(page))
            .await
    }

    /// Page through Wi-Fi broadcasts as the official Network API reports them.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn wifi_broadcasts(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<Map<String, Value>>, ApiError> {
        self.get_json(&["sites", site_id, "wifi", "broadcasts"], &page_query(page))
            .await
    }

    /// Complete fields for one Wi-Fi broadcast from the official Network API.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn wifi_broadcast(
        &self,
        site_id: &str,
        broadcast_id: &str,
    ) -> Result<Map<String, Value>, ApiError> {
        self.get_json(&["sites", site_id, "wifi", "broadcasts", broadcast_id], &[])
            .await
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

    /// Read one connected client's official access state.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn client_detail(
        &self,
        site_id: &str,
        client_id: &str,
    ) -> Result<ClientDetail, ApiError> {
        self.get_json(&["sites", site_id, "clients", client_id], &[])
            .await
    }

    /// Authorize one guest with optional access limits. Never retried.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the action.
    pub async fn authorize_guest(
        &self,
        site_id: &str,
        client_id: &str,
        limits: GuestAuthorizationLimits,
    ) -> Result<GuestActionResponse, ApiError> {
        validate_guest_limits(&limits)?;
        let (result, bytes): (GuestActionResponse, Vec<u8>) = self
            .post_action_result(
                &["sites", site_id, "clients", client_id, "actions"],
                &ClientAction::AuthorizeGuestAccess { limits },
            )
            .await?;
        if result.action != "AUTHORIZE_GUEST_ACCESS" || result.granted_authorization.is_none() {
            return Err(ApiError::SchemaMismatch {
                endpoint: "guests.authorize",
                path: BoundedMessage::new("action/grantedAuthorization"),
                response: None,
            }
            .with_controller_response(&bytes));
        }
        Ok(result)
    }

    /// Unauthorize and disconnect one guest. Never retried.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the action.
    pub async fn unauthorize_guest(
        &self,
        site_id: &str,
        client_id: &str,
    ) -> Result<GuestActionResponse, ApiError> {
        let (result, bytes): (GuestActionResponse, Vec<u8>) = self
            .post_action_result(
                &["sites", site_id, "clients", client_id, "actions"],
                &ClientAction::UnauthorizeGuestAccess,
            )
            .await?;
        if result.action != "UNAUTHORIZE_GUEST_ACCESS" || result.revoked_authorization.is_none() {
            return Err(ApiError::SchemaMismatch {
                endpoint: "guests.unauthorize",
                path: BoundedMessage::new("action/revokedAuthorization"),
                response: None,
            }
            .with_controller_response(&bytes));
        }
        Ok(result)
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn vouchers(
        &self,
        site_id: &str,
        page: PageRequest,
    ) -> Result<Page<VoucherDetails>, ApiError> {
        self.get_json(
            &["sites", site_id, "hotspot", "vouchers"],
            &page_query(page),
        )
        .await
    }

    /// One persisted hotspot voucher, including its retrievable code.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn voucher(
        &self,
        site_id: &str,
        voucher_id: &str,
    ) -> Result<VoucherDetails, ApiError> {
        self.get_json(&["sites", site_id, "hotspot", "vouchers", voucher_id], &[])
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
                ..
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

    async fn post_action_result<A: Serialize, T: DeserializeOwned>(
        &self,
        segments: &[&str],
        action: &A,
    ) -> Result<(T, Vec<u8>), ApiError> {
        let response = self
            .send(self.request(Method::POST, segments)?.json(action))
            .await?;
        let bytes = http::read_bounded_body(response).await?;
        let result = serde_json::from_slice(&bytes)
            .map_err(|error| crate::error::decode_failure(&error, &bytes))?;
        Ok((result, bytes))
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

    /// Delete one zone-based firewall policy. Never retried after an
    /// ambiguous transport result; callers confirm absence with a read.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the controller rejects the deletion.
    pub async fn delete_firewall_policy(
        &self,
        site_id: &str,
        policy_id: &str,
    ) -> Result<(), ApiError> {
        let response = self
            .send(self.request(
                Method::DELETE,
                &["sites", site_id, "firewall", "policies", policy_id],
            )?)
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
            return Err(http::rate_limited(response).await?);
        }
        Err(ApiError::Status {
            status: status.as_u16(),
            message: bounded_error_message(response).await?,
        })
    }
}

fn page_query(page: PageRequest) -> [(&'static str, String); 2] {
    [
        ("offset", page.offset.to_string()),
        ("limit", page.limit.to_string()),
    ]
}

fn validate_guest_limits(limits: &GuestAuthorizationLimits) -> Result<(), ApiError> {
    if limits
        .time_limit_minutes
        .is_some_and(|value| !(1..=1_000_000).contains(&value))
        || limits
            .data_usage_limit_m_bytes
            .is_some_and(|value| !(1..=1_048_576).contains(&value))
        || limits
            .rx_rate_limit_kbps
            .is_some_and(|value| !(2..=100_000).contains(&value))
        || limits
            .tx_rate_limit_kbps
            .is_some_and(|value| !(2..=100_000).contains(&value))
    {
        return Err(ApiError::Config(
            "guest authorization limits are outside the Integration API ranges".to_owned(),
        ));
    }
    Ok(())
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, ApiError> {
    let bytes = http::read_bounded_body(response).await?;
    serde_json::from_slice(&bytes).map_err(|error| crate::error::decode_failure(&error, &bytes))
}

/// Keep the controller's full error body within the transport body budget.
pub(crate) async fn bounded_error_message(response: Response) -> Result<BoundedMessage, ApiError> {
    let bytes = http::read_bounded_body(response).await?;
    Ok(bounded_error_message_from_bytes(&bytes))
}

pub(crate) fn bounded_error_message_from_bytes(bytes: &[u8]) -> BoundedMessage {
    BoundedMessage::from_controller_bytes(bytes)
}
