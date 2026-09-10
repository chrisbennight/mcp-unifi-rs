//! Bounded client for a `UniFi` Protect console's official integration API.
//!
//! Protect runs on its own console with its own certificate and its own
//! credential, so this is a separate client rather than another controller
//! inside the Network one. What it is not is a separate *pattern*: the
//! official Protect API is the same shape as the Network Integration API —
//! an API-key header over a versioned prefix — so the transport, the bounded
//! read, the error vocabulary, and the retry class are all shared rather than
//! reimplemented.
//!
//! The models here are deliberately narrower than either API. Official wire
//! fields are kept separate from the local application's richer operational
//! fields, and the local bootstrap has an allowlisted camera/NVR projection
//! rather than a model of the full response. Accounts, streams, channels,
//! network names, disk identifiers, and unrelated application state never
//! enter these types.

use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::error::Category;
use tracing::{debug, warn};
use url::Url;
use zeroize::Zeroizing;

use crate::{ApiError, BoundedMessage, ControllerConfig, TlsMode, http};

/// Path prefix every request lives under on the console origin.
const PREFIX: [&str; 4] = ["proxy", "protect", "integration", "v1"];
const MAXIMUM_DEVICE_IDENTIFIER_BYTES: usize = 256;

/// What the console reported about its Protect application.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectInfo {
    pub application_version: String,
}

/// One camera from the official Integration API.
///
/// `modelKey` is the resource discriminator (`camera`), not a hardware model.
/// Optional fields are tolerated extensions and never required for
/// compatibility with the documented contract.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectCamera {
    pub id: String,
    pub model_key: String,
    #[serde(deserialize_with = "required_nullable")]
    pub name: Option<String>,
    pub state: String,
    /// Optional product type reported by some Integration API releases.
    #[serde(rename = "type")]
    pub device_type: Option<String>,
    pub guid: Option<String>,
    pub mac: Option<String>,
    pub is_mic_enabled: Option<bool>,
    pub mic_volume: Option<u8>,
}

/// The recorder as the official Integration API reports it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectNvr {
    pub id: String,
    pub model_key: String,
    #[serde(deserialize_with = "required_nullable")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub device_type: Option<String>,
    pub guid: Option<String>,
    pub mac: Option<String>,
}

/// Narrow local-session snapshot used to enrich the official inventory.
/// Unknown bootstrap sections never enter this model.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectBootstrap {
    pub cameras: Vec<ProtectLocalCamera>,
    pub nvr: ProtectLocalNvr,
}

/// Operational camera fields available from the authenticated local session.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectLocalCamera {
    pub id: String,
    pub model_key: String,
    pub guid: Option<String>,
    pub mac: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub device_type: Option<String>,
    pub market_name: Option<String>,
    pub state: Option<String>,
    pub firmware_version: Option<String>,
    pub latest_firmware_version: Option<String>,
    pub hardware_revision: Option<String>,
    pub connected_since: Option<u64>,
    pub last_seen: Option<u64>,
    pub last_disconnect: Option<u64>,
    pub uptime: Option<u64>,
    pub is_updating: Option<bool>,
    #[serde(rename = "isDownloadingFW")]
    pub is_downloading_fw: Option<bool>,
    pub is_rebooting: Option<bool>,
    pub is_restoring: Option<bool>,
    pub is_attempting_to_connect: Option<bool>,
    pub is_recording: Option<bool>,
    pub is_mic_enabled: Option<bool>,
    pub mic_volume: Option<u8>,
    pub has_recordings: Option<bool>,
    pub is_poor_network: Option<bool>,
    pub video_mode: Option<String>,
    #[serde(rename = "is2K")]
    pub is_2k: Option<bool>,
    #[serde(rename = "is4K")]
    pub is_4k: Option<bool>,
    pub is_third_party_camera: Option<bool>,
    pub is_paired_with_ai_port: Option<bool>,
    pub recording_settings: Option<ProtectRecordingSettings>,
    pub feature_flags: Option<ProtectCameraFeatureFlags>,
    pub wired_connection_state: Option<ProtectWiredConnectionState>,
    pub wifi_connection_state: Option<ProtectWifiConnectionState>,
}

/// Effective configured recording mode from the local camera record.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectRecordingSettings {
    pub mode: Option<String>,
}

/// Stable capability flags used to classify a camera without conflating its
/// resource type or product code with its functional class.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectCameraFeatureFlags {
    pub is_doorbell: Option<bool>,
    pub has_mic: Option<bool>,
    pub has_speaker: Option<bool>,
    pub has_wifi: Option<bool>,
    pub has_hdr: Option<bool>,
    pub has_package_camera: Option<bool>,
    pub has_smart_detect: Option<bool>,
    pub has_led_status: Option<bool>,
    pub can_optical_zoom: Option<bool>,
    #[serde(rename = "hasAutoICROnly")]
    pub has_auto_icr_only: Option<bool>,
    pub is_ptz: Option<bool>,
    #[serde(default)]
    pub smart_detect_types: Vec<String>,
    #[serde(default)]
    pub smart_detect_audio_types: Vec<String>,
}

/// Wired link facts that do not disclose network configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectWiredConnectionState {
    pub phy_rate: Option<f64>,
}

/// Wi-Fi link facts that do not include the SSID, BSSID, or controller host.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectWifiConnectionState {
    pub signal_quality: Option<i32>,
    pub signal_strength: Option<i32>,
    pub phy_rate: Option<f64>,
    pub tx_rate: Option<f64>,
    pub channel: Option<u16>,
    pub frequency: Option<u32>,
    pub experience: Option<String>,
    pub connectivity: Option<String>,
}

/// Operational recorder fields available from the authenticated local
/// session. Storage values are aggregate figures, never disk identifiers.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectLocalNvr {
    pub id: String,
    pub model_key: String,
    pub guid: Option<String>,
    pub mac: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub device_type: Option<String>,
    pub market_name: Option<String>,
    pub version: Option<String>,
    #[serde(rename = "ucoreVersion")]
    pub ucore_version: Option<String>,
    pub is_db_available: Option<bool>,
    pub is_recording_disabled: Option<bool>,
    pub is_recording_motion_only: Option<bool>,
    pub disable_audio: Option<bool>,
    pub is_recycling: Option<bool>,
    pub corruption_state: Option<String>,
    pub hard_drive_state: Option<String>,
    pub last_drive_slow_event: Option<u64>,
    pub camera_utilization: Option<u16>,
    pub max_camera_capacity: Option<ProtectCameraCapacity>,
    pub storage_stats: Option<ProtectStorageStats>,
}

/// Camera capacity by resolution class, as the local NVR record reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectCameraCapacity {
    #[serde(rename = "4K")]
    pub four_k: Option<u16>,
    #[serde(rename = "2K")]
    pub two_k: Option<u16>,
    #[serde(rename = "HD")]
    pub hd: Option<u16>,
}

/// Aggregate recording capacity from the local Protect application.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectStorageStats {
    pub capacity: Option<u64>,
    pub remaining_capacity: Option<u64>,
    pub utilization: Option<f64>,
    pub recording_space: Option<ProtectStorageSpace>,
    pub storage_distribution: Option<ProtectStorageDistribution>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectStorageSpace {
    pub total: Option<u64>,
    pub used: Option<u64>,
    pub available: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectStorageDistribution {
    pub recording_type_distributions: Option<Vec<ProtectRecordingTypeDistribution>>,
    pub resolution_distributions: Option<Vec<ProtectResolutionDistribution>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectRecordingTypeDistribution {
    pub recording_type: Option<String>,
    pub size: Option<u64>,
    pub percentage: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectResolutionDistribution {
    pub resolution: Option<String>,
    pub size: Option<u64>,
    pub percentage: Option<f64>,
}

/// One historical Protect event from the console's application API.
///
/// This endpoint is undocumented, so the model is intentionally narrow and
/// tolerant of everything else the console returns. In particular, image,
/// thumbnail, metadata, and detection-zone payloads never enter the typed
/// surface.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProtectEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub start: u64,
    pub end: Option<u64>,
    pub score: Option<u32>,
    pub camera: Option<String>,
    #[serde(default)]
    pub smart_detect_types: Vec<String>,
}

/// Stable time key used to resume an event scan without depending on the
/// mutable offsets of the console's newest-first list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectEventContinuation {
    /// Inclusive upper bound for the next request. Every row already returned
    /// has a strictly newer `start`, so insertions or deletions before this
    /// key cannot move an unread row.
    pub next_end: u64,
}

/// One bounded page from the historical Protect application route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectEventPage {
    /// Rows inside the requested time window, newest first.
    pub events: Vec<ProtectEvent>,
    /// Raw upstream rows consumed by this page, excluding its lookahead row.
    pub scanned_rows: usize,
    /// Present until the upstream list is exhausted or has moved older than
    /// the requested window.
    pub next: Option<ProtectEventContinuation>,
}

/// Whether this console offers the official Protect integration API.
///
/// The distinction is the point. A console that does not expose the API is a
/// different answer from a console that exposes it and has no cameras, and a
/// caller that cannot tell them apart will report an unmonitored house as an
/// empty one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectAvailability {
    /// The integration API answered, and reported this application version.
    Available { application_version: String },
    /// The console answered, but has no integration API at this path.
    Unsupported,
}

/// Client for one Protect console's official integration API.
///
/// Paths live under `/proxy/protect/integration/v1`; every request carries the
/// console's API key. Request URLs are assembled from individual path
/// segments, so an identifier containing URL syntax stays one literal segment
/// rather than re-routing the request.
pub struct ProtectClient {
    http: reqwest::Client,
    base: Url,
    api_key: Zeroizing<String>,
}

impl std::fmt::Debug for ProtectClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectClient")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl ProtectClient {
    /// Build a client for one Protect console.
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

    /// What the console reports about its Protect application.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn info(&self) -> Result<ProtectInfo, ApiError> {
        let info: ProtectInfo = self.get_json(&["meta", "info"]).await?;
        if let Some((major, minor, patch)) = parse_application_version(&info.application_version) {
            debug!(
                endpoint = "meta.info",
                application_version_valid = true,
                application_version_major = major,
                application_version_minor = minor,
                application_version_patch = patch,
                "Protect application identified"
            );
        } else {
            debug!(
                endpoint = "meta.info",
                application_version_valid = false,
                "Protect application identified"
            );
        }
        Ok(info)
    }

    /// Every camera the console knows about.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn cameras(&self) -> Result<Vec<ProtectCamera>, ApiError> {
        self.get_json_validated(&["cameras"], |cameras: &Vec<ProtectCamera>| {
            for camera in cameras {
                validate_model_key("cameras", &camera.model_key, "camera")?;
                validate_identifier("cameras", &camera.id)?;
            }
            Ok(())
        })
        .await
    }

    /// One camera by its console id.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn camera(&self, camera_id: &str) -> Result<ProtectCamera, ApiError> {
        self.get_json_validated(&["cameras", camera_id], |camera: &ProtectCamera| {
            validate_model_key("cameras.by_id", &camera.model_key, "camera")?;
            validate_identifier("cameras.by_id", &camera.id)
        })
        .await
    }

    /// The recorder this console runs. The official endpoint returns one
    /// object, not a collection.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the request or decoding fails.
    pub async fn nvr(&self) -> Result<ProtectNvr, ApiError> {
        self.get_json_validated(&["nvrs"], |nvr: &ProtectNvr| {
            validate_model_key("nvrs", &nvr.model_key, "nvr")?;
            validate_identifier("nvrs", &nvr.id)
        })
        .await
    }

    /// Whether this console offers the integration API, and at what version.
    ///
    /// A `404` is the console answering that nothing lives at this path, which
    /// is a capability answer rather than a failure. Every other error is a
    /// real failure and propagates: a console that is unreachable, or that
    /// rejects the credential, must not be reported as one without cameras.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the probe fails for any reason other than
    /// the API being absent.
    pub async fn availability(&self) -> Result<ProtectAvailability, ApiError> {
        match self.info().await {
            Ok(info) => Ok(ProtectAvailability::Available {
                application_version: info.application_version,
            }),
            Err(ApiError::Status { status: 404, .. }) => Ok(ProtectAvailability::Unsupported),
            Err(error) => Err(error),
        }
    }

    /// GET with one bounded retry when the console rate limits and names an
    /// acceptable `Retry-After`.
    ///
    /// Every Protect read here is idempotent, so a short named delay is worth
    /// waiting out rather than handing the caller an error it can do nothing
    /// useful with. A longer delay is surfaced instead of slept through.
    async fn get_json<T: DeserializeOwned>(&self, segments: &[&str]) -> Result<T, ApiError> {
        self.get_json_validated(segments, |_| Ok(())).await
    }

    async fn get_json_validated<T, F>(&self, segments: &[&str], validate: F) -> Result<T, ApiError>
    where
        T: DeserializeOwned,
        F: FnOnce(&T) -> Result<(), ApiError>,
    {
        let endpoint = endpoint_name(segments);
        let first = self
            .send(self.request(Method::GET, segments)?, endpoint)
            .await;
        let response = match first {
            Ok(response) => response,
            Err(ApiError::RateLimited {
                retry_after: Some(delay),
            }) if delay <= crate::client::MAXIMUM_RETRY_AFTER => {
                tokio::time::sleep(delay).await;
                self.send(self.request(Method::GET, segments)?, endpoint)
                    .await
                    .inspect_err(|error| log_request_error(endpoint, error))?
            }
            Err(error) => {
                log_request_error(endpoint, &error);
                return Err(error);
            }
        };
        let status = response.status().as_u16();
        let bytes = http::read_bounded_body(response)
            .await
            .inspect_err(|error| log_response_rejection(endpoint, status, error))?;
        debug!(
            endpoint,
            status,
            response_bytes = bytes.len(),
            "Protect response received"
        );
        decode_json(endpoint, &bytes)
            .and_then(|value| {
                validate(&value)?;
                Ok(value)
            })
            .inspect_err(|error| {
                log_decode_failure(endpoint, status, bytes.len(), error);
            })
    }

    fn request(&self, method: Method, segments: &[&str]) -> Result<RequestBuilder, ApiError> {
        let mut all: Vec<&str> = PREFIX.to_vec();
        all.extend_from_slice(segments);
        let url = http::build_url(&self.base, &all, &[])?;
        Ok(self
            .http
            .request(method, url)
            .header("X-API-Key", self.api_key.as_str())
            .header(reqwest::header::ACCEPT, "application/json"))
    }

    async fn send(
        &self,
        request: RequestBuilder,
        endpoint: &'static str,
    ) -> Result<Response, ApiError> {
        let response = request.send().await.map_err(|error| {
            ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
        })?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            warn!(
                endpoint,
                status = 429,
                error_kind = "rate_limited",
                "Protect request failed"
            );
            return Err(ApiError::RateLimited {
                retry_after: http::retry_after(&response),
            });
        }
        // A Protect error body is controller-reported data. Read it only so
        // diagnostics retain a bounded byte count; values from it never enter
        // the public error surface.
        let status_code = status.as_u16();
        match http::read_bounded_body(response).await {
            Ok(bytes) => {
                warn!(
                    endpoint,
                    status = status_code,
                    response_bytes = bytes.len(),
                    error_kind = "http_status",
                    "Protect request failed"
                );
            }
            Err(error) => {
                log_response_rejection(endpoint, status_code, &error);
            }
        }
        Err(ApiError::Status {
            status: status_code,
            message: BoundedMessage::new("controller returned an unsuccessful status"),
        })
    }
}

fn endpoint_name(segments: &[&str]) -> &'static str {
    match segments {
        ["meta", "info"] => "meta.info",
        ["cameras"] => "cameras",
        ["cameras", _] => "cameras.by_id",
        ["nvrs"] => "nvrs",
        _ => "protect.integration",
    }
}

fn parse_application_version(raw: &str) -> Option<(u16, u16, u16)> {
    let mut components = raw.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;
    components.next().is_none().then_some((major, minor, patch))
}

pub(crate) fn decode_json<T: DeserializeOwned>(
    endpoint: &'static str,
    bytes: &[u8],
) -> Result<T, ApiError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let decoded = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let path = error.path().to_string();
        let inner = error.inner();
        match inner.classify() {
            Category::Syntax | Category::Eof => ApiError::InvalidJson {
                endpoint,
                line: inner.line(),
                column: inner.column(),
            },
            Category::Data | Category::Io => ApiError::SchemaMismatch {
                endpoint,
                path: BoundedMessage::new(&path),
            },
        }
    })?;
    deserializer.end().map_err(|error| ApiError::InvalidJson {
        endpoint,
        line: error.line(),
        column: error.column(),
    })?;
    Ok(decoded)
}

fn validate_model_key(
    endpoint: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), ApiError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ApiError::SchemaMismatch {
            endpoint,
            path: BoundedMessage::new("modelKey"),
        })
    }
}

fn validate_identifier(endpoint: &'static str, id: &str) -> Result<(), ApiError> {
    if !id.is_empty() && id.len() <= MAXIMUM_DEVICE_IDENTIFIER_BYTES {
        Ok(())
    } else {
        Err(ApiError::SchemaMismatch {
            endpoint,
            path: BoundedMessage::new("id"),
        })
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn log_request_error(endpoint: &'static str, error: &ApiError) {
    match error {
        ApiError::Status { .. } | ApiError::RateLimited { .. } => {}
        _ => warn!(
            endpoint,
            error_kind = error_kind(error),
            "Protect request failed"
        ),
    }
}

fn log_response_rejection(endpoint: &'static str, status: u16, error: &ApiError) {
    if let ApiError::ResponseTooLarge { limit } = error {
        warn!(
            endpoint,
            status,
            response_bytes_at_least = limit.saturating_add(1),
            error_kind = "oversized_body",
            "Protect response rejected"
        );
    } else {
        warn!(
            endpoint,
            status,
            error_kind = error_kind(error),
            "Protect response rejected"
        );
    }
}

fn error_kind(error: &ApiError) -> &'static str {
    match error {
        ApiError::ResponseTooLarge { .. } => "oversized_body",
        ApiError::InvalidJson { .. } => "invalid_json",
        ApiError::SchemaMismatch { .. } => "schema_mismatch",
        _ => "upstream_failure",
    }
}

pub(crate) fn log_decode_failure(
    endpoint: &'static str,
    status: u16,
    response_bytes: usize,
    error: &ApiError,
) {
    match error {
        ApiError::SchemaMismatch { path, .. } => warn!(
            endpoint,
            status,
            response_bytes,
            error_kind = "schema_mismatch",
            schema_path = %path,
            "Protect response decoding failed"
        ),
        ApiError::InvalidJson { line, column, .. } => warn!(
            endpoint,
            status,
            response_bytes,
            error_kind = "invalid_json",
            error_line = line,
            error_column = column,
            "Protect response decoding failed"
        ),
        _ => warn!(
            endpoint,
            status,
            response_bytes,
            error_kind = error_kind(error),
            "Protect response decoding failed"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber, subscriber::with_default};

    use super::{ProtectCamera, decode_json, log_decode_failure, parse_application_version};

    #[derive(Default)]
    struct CapturedFields(Arc<Mutex<Vec<(String, String)>>>);

    impl Visit for CapturedFields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .lock()
                .expect("fields lock")
                .push((field.name().to_owned(), format!("{value:?}")));
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0
                .lock()
                .expect("fields lock")
                .push((field.name().to_owned(), value.to_string()));
        }
    }

    #[derive(Clone)]
    struct CaptureSubscriber(Arc<Mutex<Vec<(String, String)>>>);

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            event.record(&mut CapturedFields(Arc::clone(&self.0)));
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    #[test]
    fn schema_failure_log_contains_only_the_structural_path() {
        let fields = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber(Arc::clone(&fields));
        let error = decode_json::<Vec<ProtectCamera>>(
            "cameras",
            br#"[{"id":"cam-sensitive","modelKey":"camera","name":987654321,"state":"CONNECTED"}]"#,
        )
        .expect_err("wrong-typed name");

        with_default(subscriber, || {
            log_decode_failure("cameras", 200, 123, &error);
        });

        let rendered = format!("{:?}", fields.lock().expect("fields lock"));
        assert!(rendered.contains("schema_path"));
        assert!(rendered.contains("[0].name"));
        assert!(rendered.contains("response_bytes"));
        assert!(rendered.contains("123"));
        assert!(!rendered.contains("987654321"));
    }

    #[test]
    fn application_version_logging_accepts_only_three_bounded_numbers() {
        assert_eq!(parse_application_version("7.1.87"), Some((7, 1, 87)));
        for unsafe_value in [
            "credential",
            "1.2.3-extra",
            "1.2.3.example.test",
            "https://controller.test/1.2.3",
            "65536.1.1",
        ] {
            assert_eq!(parse_application_version(unsafe_value), None);
        }
    }
}
