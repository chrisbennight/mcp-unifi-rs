//! Client for the legacy controller API, used only for capabilities the
//! official Integration API lacks.
//!
//! The legacy API authenticates with a cookie session from a dedicated local
//! administrator. Accounts with MFA are unsupported by the upstream login
//! route (`api.err.Ubic2faTokenRequired`); operators create a no-MFA local
//! admin for automation. `UniFi OS` consoles log in at `/api/auth/login` and
//! serve the API under `/proxy/network/api/s/{site}`, echoing an
//! `x-csrf-token` header that mutations must return; standalone controllers
//! log in at `/api/login` and serve `/api/s/{site}` without CSRF. The client
//! holds one session per controller and re-authenticates only when the
//! controller reports the session gone — login endpoints are aggressively
//! rate limited, so a 429 at login always surfaces and is never retried.

use std::time::{Duration, Instant};

use reqwest::{Method, Response, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use url::Url;
use zeroize::Zeroizing;

mod system_log;

use crate::{
    ApiError, BoundedMessage, TlsMode, http,
    models::{
        ActiveClient, DpiApplication, HealthSubsystem, NetworkConf, PortForward, PortForwardPatch,
        RogueAp, SiteWanSample, TrafficRoute, TrafficRule, WlanConf, WlanPatch,
    },
    protect::{
        ProtectBootstrap, ProtectEvent, ProtectEventContinuation, ProtectEventPage,
        ProtectLocalCamera,
    },
};

/// Longest `Retry-After` honored before retrying an idempotent read once.
const MAXIMUM_RETRY_AFTER: Duration = Duration::from_secs(10);
const CSRF_HEADER: &str = "x-csrf-token";
/// Largest page a bounded Protect event read requests from the controller.
const MAXIMUM_RECORD_LIMIT: u32 = 1000;
/// One row is reserved for the lookahead that proves a time-keyset boundary
/// does not split simultaneous events.
const MAXIMUM_PROTECT_EVENT_PAGE_LIMIT: u32 = MAXIMUM_RECORD_LIMIT - 1;
/// Event ids are opaque identifiers, not display text. Refuse an implausible
/// wire value rather than letting one consume the bounded result budget.
const MAXIMUM_EVENT_IDENTIFIER_BYTES: usize = 256;
/// A larger inventory is refused rather than partially enriching the official
/// result or allowing a malformed bootstrap to consume unbounded work.
const MAXIMUM_PROTECT_CAMERAS: usize = 1000;
const MAXIMUM_PROTECT_DEVICE_IDENTIFIER_BYTES: usize = 256;
/// Supplying `types` is part of the time-bound contract. Protect currently
/// ignores `start` and `end` on this private route when the parameter is
/// absent, so the curated detection surface names the camera event families
/// it is willing to expose.
const PROTECT_DETECTION_TYPES: &[&str] = &[
    "motion",
    "ring",
    "smartDetectZone",
    "smartDetectLine",
    "smartAudioDetect",
    "smartDetectLoiterZone",
];
/// Longest hourly-report window; hourly buckets keep the row count bounded.
const MAXIMUM_REPORT_WINDOW_MILLISECONDS: u64 = 7 * 24 * 60 * 60 * 1000;
const LOGIN_REQUIRED_CODE: &str = "api.err.LoginRequired";

/// Connection settings for one controller's legacy API session.
pub struct LegacyConfig {
    /// Operator-chosen controller name used in logs and tool responses.
    pub name: String,
    /// Console origin, such as `https://192.168.0.66`. API paths are
    /// appended by the client.
    pub base_url: Url,
    /// Dedicated local administrator without MFA.
    pub username: String,
    pub password: Zeroizing<String>,
    pub tls: TlsMode,
    /// Per-request timeout covering connect, write, and read.
    pub timeout: Duration,
}

/// The password must never reach diagnostic output, so the formatter is
/// written by hand instead of derived through the zeroizing container.
impl std::fmt::Debug for LegacyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LegacyConfig")
            .field("name", &self.name)
            .field("base_url", &self.base_url.as_str())
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Which console family the controller runs, resolved at first login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleKind {
    UnifiOs,
    Standalone,
}

/// Whether a request may receive the bounded rate-limit retry. Stated
/// explicitly at every call site because idempotence is a property of the
/// operation, not of its HTTP verb: several legacy reads travel as POST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestClass {
    IdempotentRead,
    Mutation,
}

#[derive(Debug, Default)]
struct SessionState {
    kind: Option<ConsoleKind>,
    csrf: Option<String>,
    authenticated: bool,
    /// Incremented on every successful login. A caller that observes a
    /// login-required rejection re-authenticates only when the session is
    /// still at the generation it used; a stale observer adopts the newer
    /// session instead of stampeding the rate-limited login route.
    generation: u64,
    /// The outcome of the most recent failed login. Any caller needing a
    /// session inside the failure's backoff window receives this shared
    /// outcome instead of attempting another login against the
    /// lockout-sensitive route; a successful login clears it.
    failed_login: Option<FailedLogin>,
}

#[derive(Debug)]
struct FailedLogin {
    until: Instant,
    error: ApiError,
}

/// The legacy `{"meta":{"rc":...,"msg":...},"data":[...]}` envelope.
#[derive(Debug, Deserialize)]
struct LegacyMeta {
    rc: String,
    #[serde(default)]
    msg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyEnvelope<T> {
    meta: LegacyMeta,
    #[serde(default = "Vec::new")]
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct ProtectCameraBootstrap {
    cameras: Vec<ProtectLocalCamera>,
}

/// Every property one controller record stores, held for comparison only.
///
/// The values are private: a consumer can ask which property names differ
/// between two readings and nothing else, so the unmodeled parts of a
/// controller record never cross this crate's boundary. Comparison is on the
/// values themselves rather than a hash of them, so it cannot report two
/// different records as identical.
pub struct RecordFingerprint(serde_json::Map<String, serde_json::Value>);

impl std::fmt::Debug for RecordFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordFingerprint")
            .field("properties", &self.0.len())
            .finish()
    }
}

impl RecordFingerprint {
    /// Take a fingerprint of a record held as its original JSON text.
    ///
    /// Each property is compared as the bytes the controller sent, so two
    /// readings that differ only in a way a value model would flatten — a
    /// number beyond what `f64` distinguishes, say — still compare as
    /// different.
    pub(crate) fn from_raw_record(
        record: &std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>,
    ) -> Self {
        Self(
            record
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        serde_json::Value::String(value.get().to_owned()),
                    )
                })
                .collect(),
        )
    }

    /// The names of properties whose stored value differs between two
    /// readings, including one present in only one of them.
    #[must_use]
    pub fn changed_properties(&self, other: &Self) -> Vec<String> {
        let mut changed: Vec<String> = self
            .0
            .keys()
            .chain(other.0.keys())
            .filter(|property| self.0.get(*property) != other.0.get(*property))
            .cloned()
            .collect();
        changed.sort_unstable();
        changed.dedup();
        changed
    }
}

/// Client for one controller's legacy API.
pub struct LegacyClient {
    http: reqwest::Client,
    base: Url,
    username: String,
    password: Zeroizing<String>,
    session: Mutex<SessionState>,
}

impl std::fmt::Debug for LegacyClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LegacyClient")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl LegacyClient {
    /// Build a client for one controller. No network traffic occurs until
    /// the first call needs a session.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Config`] when the TLS material or base URL is
    /// unusable.
    pub fn new(config: &LegacyConfig) -> Result<Self, ApiError> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
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
            username: config.username.clone(),
            password: config.password.clone(),
            session: Mutex::new(SessionState::default()),
        })
    }

    /// Per-site subsystem health from `stat/health`.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn site_health(&self, site: &str) -> Result<Vec<HealthSubsystem>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["stat", "health"],
            None,
        )
        .await
    }

    /// Currently connected clients from `stat/sta`, with association,
    /// addressing, and usage fields.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn active_clients(&self, site: &str) -> Result<Vec<ActiveClient>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["stat", "sta"],
            None,
        )
        .await
    }

    /// Configured networks (VLANs, subnets, DHCP scopes) from
    /// `rest/networkconf`.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn networks(&self, site: &str) -> Result<Vec<NetworkConf>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["rest", "networkconf"],
            None,
        )
        .await
    }

    /// Configured wireless networks from `rest/wlanconf`. Rows carry secret
    /// passphrase material; callers own redaction and must never log them.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn wlans(&self, site: &str) -> Result<Vec<WlanConf>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["rest", "wlanconf"],
            None,
        )
        .await
    }

    /// One wireless network by id, from `rest/wlanconf/{id}`. Used to read a
    /// resource back after writing it, so the caller can tell what the
    /// controller actually stored. Carries secret passphrase material.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails,
    /// or [`ApiError::Rejected`] when the id names no wireless network.
    pub async fn wlan(&self, site: &str, id: &str) -> Result<WlanConf, ApiError> {
        let rows: Vec<WlanConf> = self
            .request_with_reauth(
                RequestClass::IdempotentRead,
                Method::GET,
                site,
                &["rest", "wlanconf", id],
                None,
            )
            .await?;
        // An `ok` envelope with no row means the id matched nothing. That is
        // a caller-visible outcome, not a transport fault, so it travels as a
        // rejection rather than a decode failure.
        rows.into_iter().next().ok_or_else(|| ApiError::Rejected {
            code: BoundedMessage::new("api.err.NotFound"),
            message: BoundedMessage::new("no wireless network has that id"),
        })
    }

    /// One wireless network read once, as both the allowlisted projection and
    /// a fingerprint of every property the controller stores.
    ///
    /// The projection covers a fraction of what a console keeps, so comparing
    /// two projections across a write cannot see a property outside that list
    /// being cleared; the fingerprint can. Both come from a single response,
    /// so the two views describe the same moment.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails,
    /// or [`ApiError::Rejected`] when the id names no wireless network.
    pub async fn wlan_snapshot(
        &self,
        site: &str,
        id: &str,
    ) -> Result<(WlanConf, RecordFingerprint), ApiError> {
        let rows: Vec<serde_json::Map<String, serde_json::Value>> = self
            .request_with_reauth(
                RequestClass::IdempotentRead,
                Method::GET,
                site,
                &["rest", "wlanconf", id],
                None,
            )
            .await?;
        let row = rows.into_iter().next().ok_or_else(|| ApiError::Rejected {
            code: BoundedMessage::new("api.err.NotFound"),
            message: BoundedMessage::new("no wireless network has that id"),
        })?;
        let fingerprint = RecordFingerprint(row.clone());
        let conf = serde_json::from_value(serde_json::Value::Object(row))
            .map_err(|error| ApiError::Decode(BoundedMessage::new(&error.to_string())))?;
        Ok((conf, fingerprint))
    }

    /// Apply a partial update to one wireless network. Only the fields the
    /// patch sets are sent.
    ///
    /// This is a mutation: it is never retried after an ambiguous transport
    /// result, because a resend could apply the change twice. The controller
    /// acknowledges writes whose individual fields it discards, so the caller
    /// must read the resource back rather than treat success as persistence.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Config`] for an empty patch, and an [`ApiError`]
    /// when the session or request fails or the controller rejects the write.
    pub async fn update_wlan(
        &self,
        site: &str,
        id: &str,
        patch: &WlanPatch,
    ) -> Result<(), ApiError> {
        if patch.is_empty() {
            return Err(ApiError::Config(
                "wireless network update carries no fields".to_owned(),
            ));
        }
        let body = serde_json::to_value(patch).map_err(|_| {
            ApiError::Config("wireless network patch is not serializable".to_owned())
        })?;
        // The controller can echo a submitted value back in a rejection, so
        // the passphrase this request carries is scrubbed from any resulting
        // error exactly as the login password is.
        let sent_passphrase = patch.x_passphrase.as_ref().map(|value| value.as_str());
        self.request_carrying_secrets::<serde_json::Value>(
            RequestClass::Mutation,
            Method::PUT,
            site,
            &["rest", "wlanconf", id],
            Some(body),
            sent_passphrase.as_slice(),
        )
        .await?;
        Ok(())
    }

    /// One port forward read once, as both the modeled record and a
    /// fingerprint of every property the controller stores, so a write can be
    /// judged against the same moment on both views.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails,
    /// or [`ApiError::Rejected`] when the id names no port forward.
    pub async fn port_forward_snapshot(
        &self,
        site: &str,
        id: &str,
    ) -> Result<(PortForward, RecordFingerprint), ApiError> {
        let rows: Vec<serde_json::Map<String, serde_json::Value>> = self
            .request_with_reauth(
                RequestClass::IdempotentRead,
                Method::GET,
                site,
                &["rest", "portforward", id],
                None,
            )
            .await?;
        let row = rows.into_iter().next().ok_or_else(|| ApiError::Rejected {
            code: BoundedMessage::new("api.err.NotFound"),
            message: BoundedMessage::new("no port forward has that id"),
        })?;
        let fingerprint = RecordFingerprint(row.clone());
        let forward = serde_json::from_value(serde_json::Value::Object(row))
            .map_err(|error| ApiError::Decode(BoundedMessage::new(&error.to_string())))?;
        Ok((forward, fingerprint))
    }

    /// Apply a partial update to one port forward. Only the fields the patch
    /// sets are sent.
    ///
    /// This is a mutation: it is never retried after an ambiguous transport
    /// result. The controller acknowledges writes whose individual fields it
    /// discards, so the caller must read the resource back rather than treat
    /// success as persistence.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Config`] for an empty patch, and an [`ApiError`]
    /// when the session or request fails or the controller rejects the write.
    pub async fn update_port_forward(
        &self,
        site: &str,
        id: &str,
        patch: &PortForwardPatch,
    ) -> Result<(), ApiError> {
        if patch.is_empty() {
            return Err(ApiError::Config(
                "port forward update carries no fields".to_owned(),
            ));
        }
        let body = serde_json::to_value(patch)
            .map_err(|_| ApiError::Config("port forward patch is not serializable".to_owned()))?;
        self.request_with_reauth::<serde_json::Value>(
            RequestClass::Mutation,
            Method::PUT,
            site,
            &["rest", "portforward", id],
            Some(body),
        )
        .await?;
        Ok(())
    }

    /// Disconnect one wireless client; it may reconnect immediately. Never
    /// retried after an ambiguous transport result.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session or command fails.
    pub async fn kick_client(&self, site: &str, mac: &str) -> Result<(), ApiError> {
        self.station_command(site, "kick-sta", mac).await
    }

    /// Block one client from the network. Never retried after an ambiguous
    /// transport result.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session or command fails.
    pub async fn block_client(&self, site: &str, mac: &str) -> Result<(), ApiError> {
        self.station_command(site, "block-sta", mac).await
    }

    /// Lift a client block. Never retried after an ambiguous transport
    /// result.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session or command fails.
    pub async fn unblock_client(&self, site: &str, mac: &str) -> Result<(), ApiError> {
        self.station_command(site, "unblock-sta", mac).await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn port_forwards(&self, site: &str) -> Result<Vec<PortForward>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["rest", "portforward"],
            None,
        )
        .await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn traffic_rules(&self, site: &str) -> Result<Vec<TrafficRule>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["rest", "trafficrule"],
            None,
        )
        .await
    }

    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn traffic_routes(&self, site: &str) -> Result<Vec<TrafficRoute>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["rest", "trafficroute"],
            None,
        )
        .await
    }

    /// One caller-pageable slice of historical Protect events, newest first.
    ///
    /// The official Protect integration API exposes only a live WebSocket;
    /// this bounded read is the deliberately isolated exception that uses
    /// the console's undocumented application route. It reuses the same
    /// `UniFi` OS cookie session and reauthentication rules as Network reads.
    /// The continuation is a time key rather than an upstream offset, so
    /// insertions and deletions among newer events cannot shift unread rows.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the range or continuation is invalid, the
    /// console is not `UniFi` OS, a page would split an equal-timestamp
    /// group, or the session, request, or decoding fails.
    pub async fn protect_events(
        &self,
        start: u64,
        end: u64,
        limit: u32,
        continuation: Option<&ProtectEventContinuation>,
    ) -> Result<ProtectEventPage, ApiError> {
        if start > end {
            return Err(ApiError::Config(
                "Protect event start is after end".to_owned(),
            ));
        }
        if !(1..=MAXIMUM_PROTECT_EVENT_PAGE_LIMIT).contains(&limit) {
            return Err(ApiError::Config(format!(
                "Protect event page limit must be between 1 and {MAXIMUM_PROTECT_EVENT_PAGE_LIMIT}"
            )));
        }
        if continuation.is_some_and(|cursor| cursor.next_end < start || cursor.next_end > end) {
            return Err(ApiError::Config(
                "Protect event continuation is invalid".to_owned(),
            ));
        }

        let request_end = continuation.map_or(end, |cursor| cursor.next_end);
        let request_limit = limit + 1;
        let events = self
            .protect_events_with_reauth(start, request_end, request_limit)
            .await?;
        finish_protect_event_page(start, request_end, limit, events)
    }

    /// Read the narrow camera and recorder projection from the local Protect
    /// bootstrap. The full bootstrap contains accounts, streams, and other
    /// structures that are deliberately not represented by this type.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the console is not `UniFi` OS, the
    /// session or request fails, the response does not match the allowlisted
    /// model, or the camera count exceeds the hard inventory ceiling.
    pub async fn protect_bootstrap(&self) -> Result<ProtectBootstrap, ApiError> {
        let bootstrap = self.protect_bootstrap_projection().await?;
        validate_protect_bootstrap(&bootstrap).inspect_err(|_error| {
            warn!(
                endpoint = "protect.bootstrap",
                error_kind = "schema_mismatch",
                "Protect response validation failed"
            );
        })?;
        Ok(bootstrap)
    }

    /// Read only the camera projection from the local Protect bootstrap.
    /// Recorder fields in the same response are deliberately not decoded, so
    /// camera identity remains available when recorder enrichment is not.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the console is not `UniFi` OS, the
    /// session or request fails, the camera projection is invalid, or the
    /// camera count exceeds the hard inventory ceiling.
    pub async fn protect_camera_inventory(&self) -> Result<Vec<ProtectLocalCamera>, ApiError> {
        let bootstrap: ProtectCameraBootstrap = self.protect_bootstrap_projection().await?;
        validate_protect_cameras(&bootstrap.cameras).inspect_err(|_error| {
            warn!(
                endpoint = "protect.bootstrap",
                error_kind = "schema_mismatch",
                "Protect response validation failed"
            );
        })?;
        Ok(bootstrap.cameras)
    }

    async fn protect_bootstrap_projection<T: DeserializeOwned>(&self) -> Result<T, ApiError> {
        let generation = self.ensure_session().await?;
        let first: Result<T, ApiError> = self.execute_protect_bootstrap::<T>().await;
        match first {
            Err(error) if is_login_required(&error) => {
                self.refresh_session(generation).await?;
                self.execute_protect_bootstrap::<T>().await
            }
            Err(ApiError::RateLimited {
                retry_after: Some(delay),
            }) if delay <= MAXIMUM_RETRY_AFTER => {
                tokio::time::sleep(delay).await;
                self.execute_protect_bootstrap::<T>().await
            }
            other => other,
        }
    }

    /// Site-wide deep-packet-inspection counters grouped by application.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn dpi_by_application(&self, site: &str) -> Result<Vec<DpiApplication>, ApiError> {
        let body = serde_json::json!({ "type": "by_app" });
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::POST,
            site,
            &["stat", "sitedpi"],
            Some(body),
        )
        .await
    }

    /// Neighboring access points observed by the site's radios.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session, request, or decoding fails.
    pub async fn rogue_aps(&self, site: &str) -> Result<Vec<RogueAp>, ApiError> {
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::GET,
            site,
            &["stat", "rogueap"],
            None,
        )
        .await
    }

    /// Hourly WAN throughput samples for a bounded window (epoch
    /// milliseconds, at most seven days so the hourly rows stay bounded).
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Config`] for an empty or over-wide window, and an
    /// [`ApiError`] when the session, request, or decoding fails.
    pub async fn hourly_wan_report(
        &self,
        site: &str,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<SiteWanSample>, ApiError> {
        if end_ms <= start_ms {
            return Err(ApiError::Config(
                "report window end must be after its start".to_owned(),
            ));
        }
        if end_ms - start_ms > MAXIMUM_REPORT_WINDOW_MILLISECONDS {
            return Err(ApiError::Config(
                "report window exceeds the seven-day bound".to_owned(),
            ));
        }
        let body = serde_json::json!({
            "attrs": ["time", "wan-tx_bytes", "wan-rx_bytes"],
            "start": start_ms,
            "end": end_ms,
        });
        self.request_with_reauth(
            RequestClass::IdempotentRead,
            Method::POST,
            site,
            &["stat", "report", "hourly.site"],
            Some(body),
        )
        .await
    }

    /// Restart one device by MAC. Never retried after an ambiguous
    /// transport result.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session or command fails.
    pub async fn restart_device(&self, site: &str, mac: &str) -> Result<(), ApiError> {
        self.device_command(site, "restart", mac).await
    }

    /// Toggle one device's locate LED. Never retried after an ambiguous
    /// transport result.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the session or command fails.
    pub async fn locate_device(&self, site: &str, mac: &str, on: bool) -> Result<(), ApiError> {
        let command = if on { "set-locate" } else { "unset-locate" };
        self.device_command(site, command, mac).await
    }

    async fn device_command(&self, site: &str, command: &str, mac: &str) -> Result<(), ApiError> {
        // The controller stores MACs lowercase and rejects other casings.
        let body = serde_json::json!({ "cmd": command, "mac": mac.to_lowercase() });
        self.request_with_reauth::<serde_json::Value>(
            RequestClass::Mutation,
            Method::POST,
            site,
            &["cmd", "devmgr"],
            Some(body),
        )
        .await?;
        Ok(())
    }

    async fn station_command(&self, site: &str, command: &str, mac: &str) -> Result<(), ApiError> {
        // The controller stores MACs lowercase and rejects other casings.
        let body = serde_json::json!({ "cmd": command, "mac": mac.to_lowercase() });
        self.request_with_reauth::<serde_json::Value>(
            RequestClass::Mutation,
            Method::POST,
            site,
            &["cmd", "stamgr"],
            Some(body),
        )
        .await?;
        Ok(())
    }

    /// Execute one request, re-authenticating exactly once when the
    /// controller reports the session gone.
    ///
    /// The refreshed session benefits the caller's next attempt either way,
    /// but only an idempotent read is reissued. An expiry report is not proof
    /// that a write never reached the controller, and a configuration change
    /// applied twice is worse than a failure the caller can retry, so a
    /// mutation surfaces the error instead. Every other failure surfaces
    /// as-is.
    async fn request_with_reauth<T: DeserializeOwned>(
        &self,
        class: RequestClass,
        method: Method,
        site: &str,
        tail: &[&str],
        body: Option<serde_json::Value>,
    ) -> Result<Vec<T>, ApiError> {
        self.request_carrying_secrets(class, method, site, tail, body, &[])
            .await
    }

    async fn protect_events_with_reauth(
        &self,
        start: u64,
        end: u64,
        limit: u32,
    ) -> Result<Vec<ProtectEvent>, ApiError> {
        let generation = self.ensure_session().await?;
        let first = self.execute_protect_events(start, end, limit).await;
        match first {
            Err(error) if is_login_required(&error) => {
                self.refresh_session(generation).await?;
                self.execute_protect_events(start, end, limit).await
            }
            Err(ApiError::RateLimited {
                retry_after: Some(delay),
            }) if delay <= MAXIMUM_RETRY_AFTER => {
                tokio::time::sleep(delay).await;
                self.execute_protect_events(start, end, limit).await
            }
            other => other,
        }
    }

    async fn execute_protect_events(
        &self,
        start: u64,
        end: u64,
        limit: u32,
    ) -> Result<Vec<ProtectEvent>, ApiError> {
        let kind = {
            let session = self.session.lock().await;
            session.kind.ok_or_else(|| {
                ApiError::Config("session used before console detection".to_owned())
            })?
        };
        if kind != ConsoleKind::UnifiOs {
            return Err(ApiError::Config(
                "Protect application events require a UniFi OS console".to_owned(),
            ));
        }
        let mut query = vec![
            ("start", start.to_string()),
            ("end", end.to_string()),
            ("limit", limit.to_string()),
            ("offset", "0".to_owned()),
            ("orderDirection", "DESC".to_owned()),
        ];
        query.extend(
            PROTECT_DETECTION_TYPES
                .iter()
                .map(|kind| ("types", (*kind).to_owned())),
        );
        let url = http::build_url(&self.base, &["proxy", "protect", "api", "events"], &query)?;
        let response = self
            .http
            .request(Method::GET, url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
            })
            .inspect_err(|_error| {
                warn!(
                    endpoint = "protect.events",
                    error_kind = "transport",
                    "Protect request failed"
                );
            })?;
        self.decode_protect_response(response, "protect.events")
            .await
    }

    async fn execute_protect_bootstrap<T: DeserializeOwned>(&self) -> Result<T, ApiError> {
        let kind = {
            let session = self.session.lock().await;
            session.kind.ok_or_else(|| {
                ApiError::Config("session used before console detection".to_owned())
            })?
        };
        if kind != ConsoleKind::UnifiOs {
            return Err(ApiError::Config(
                "Protect inventory requires a UniFi OS console".to_owned(),
            ));
        }
        let url = http::build_url(&self.base, &["proxy", "protect", "api", "bootstrap"], &[])?;
        let response = self
            .http
            .request(Method::GET, url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
            })
            .inspect_err(|_error| {
                warn!(
                    endpoint = "protect.bootstrap",
                    error_kind = "transport",
                    "Protect request failed"
                );
            })?;
        self.decode_protect_response(response, "protect.bootstrap")
            .await
    }

    async fn decode_protect_response<T: DeserializeOwned>(
        &self,
        response: Response,
        endpoint: &'static str,
    ) -> Result<T, ApiError> {
        self.capture_csrf(&response).await;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            warn!(
                endpoint,
                status = 401,
                error_kind = "unauthorized",
                "Protect request failed"
            );
            return Err(login_required_error());
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
        let status_code = status.as_u16();
        let bytes = http::read_bounded_body(response)
            .await
            .inspect_err(|error| log_protect_response_rejection(endpoint, status_code, error))?;
        if !status.is_success() {
            warn!(
                endpoint,
                status = status_code,
                response_bytes = bytes.len(),
                error_kind = "http_status",
                "Protect request failed"
            );
            return Err(translate_failure(
                status_code,
                &bytes,
                &[self.password.as_str()],
                RequestClass::IdempotentRead,
            ));
        }
        debug!(
            endpoint,
            status = status_code,
            response_bytes = bytes.len(),
            "Protect response received"
        );
        crate::protect::decode_json(endpoint, &bytes).inspect_err(|error| {
            crate::protect::log_decode_failure(endpoint, status_code, bytes.len(), error);
        })
    }

    /// As [`Self::request_with_reauth`], for a request whose body carries
    /// secret material. The controller can reflect a submitted value in its
    /// rejection message, so every value named here is scrubbed out of the
    /// resulting error alongside the login password. A caller that sends a
    /// secret and omits it here leaks it into diagnostics.
    async fn request_carrying_secrets<T: DeserializeOwned>(
        &self,
        class: RequestClass,
        method: Method,
        site: &str,
        tail: &[&str],
        body: Option<serde_json::Value>,
        secrets: &[&str],
    ) -> Result<Vec<T>, ApiError> {
        let generation = self.ensure_session().await?;
        let first = self
            .execute(class, method.clone(), site, tail, body.as_ref(), secrets)
            .await;
        match first {
            // Only a read is reissued. The session is refreshed either way so
            // the next call starts clean, but a write is never sent twice on
            // the strength of an expiry report: whatever the client concludes
            // from a failed write, it cannot know the controller did not
            // apply it, and one surfaced failure the caller can retry is
            // cheaper than a configuration change applied twice.
            Err(error) if is_login_required(&error) => {
                self.refresh_session(generation).await?;
                if class == RequestClass::Mutation {
                    return Err(error);
                }
                self.execute(class, method, site, tail, body.as_ref(), secrets)
                    .await
            }
            Err(ApiError::RateLimited {
                retry_after: Some(delay),
            }) if class == RequestClass::IdempotentRead && delay <= MAXIMUM_RETRY_AFTER => {
                tokio::time::sleep(delay).await;
                self.execute(class, method, site, tail, body.as_ref(), secrets)
                    .await
            }
            other => other,
        }
    }

    /// The login password plus whatever secret material this request sent.
    fn request_secrets<'a>(&'a self, extra: &[&'a str]) -> Vec<&'a str> {
        let mut secrets = vec![self.password.as_str()];
        secrets.extend_from_slice(extra);
        secrets
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        class: RequestClass,
        method: Method,
        site: &str,
        tail: &[&str],
        body: Option<&serde_json::Value>,
        secrets: &[&str],
    ) -> Result<Vec<T>, ApiError> {
        let (kind, csrf) = {
            let session = self.session.lock().await;
            let kind = session.kind.ok_or_else(|| {
                ApiError::Config("session used before console detection".to_owned())
            })?;
            (kind, session.csrf.clone())
        };
        let mut segments: Vec<&str> = match kind {
            ConsoleKind::UnifiOs => vec!["proxy", "network", "api", "s"],
            ConsoleKind::Standalone => vec!["api", "s"],
        };
        segments.push(site);
        segments.extend_from_slice(tail);
        let url = http::build_url(&self.base, &segments, &[])?;
        let mut request = self
            .http
            .request(method.clone(), url)
            .header(reqwest::header::ACCEPT, "application/json");
        if method != Method::GET
            && kind == ConsoleKind::UnifiOs
            && let Some(token) = csrf
        {
            request = request.header(CSRF_HEADER, token);
        }
        if let Some(payload) = body {
            request = request.json(payload);
        }
        let response = request.send().await.map_err(|error| {
            ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
        })?;
        self.capture_csrf(&response).await;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(login_required_error());
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ApiError::RateLimited {
                retry_after: http::retry_after(&response),
            });
        }
        let bytes = http::read_bounded_body(response).await?;
        if !status.is_success() {
            return Err(translate_failure(
                status.as_u16(),
                &bytes,
                &self.request_secrets(secrets),
                class,
            ));
        }
        let envelope: LegacyEnvelope<T> = serde_json::from_slice(&bytes)
            .map_err(|error| ApiError::Decode(BoundedMessage::new(&error.to_string())))?;
        if envelope.meta.rc == "ok" {
            Ok(envelope.data)
        } else {
            let raw = envelope.meta.msg.as_deref();
            // Session expiry read out of the controller's message text is
            // trusted only for reads. The text can echo a value the caller
            // submitted, so for a mutation it could be made to look like
            // expiry and earn a resend; a mutation therefore learns about
            // expiry only from the 401 status, which reflected content
            // cannot forge. Classification precedes the scrub so a secret
            // that merely resembles the token cannot disguise a real expiry
            // on the read path.
            if class == RequestClass::IdempotentRead && raw == Some(LOGIN_REQUIRED_CODE) {
                return Err(login_required_error());
            }
            // The decoded msg carries a reflected credential literally, so
            // the scrub applies here exactly as on the failure path, over the
            // login password and anything secret this request just sent.
            let secrets = self.request_secrets(secrets);
            let scrubbed = raw.map(|msg| scrub(msg, &secrets));
            Err(rejection(scrubbed.as_deref()))
        }
    }

    /// Ensure an authenticated session exists and return its generation. A
    /// caller arriving inside a failed login's backoff window receives that
    /// shared failure instead of attempting another login.
    async fn ensure_session(&self) -> Result<u64, ApiError> {
        let mut session = self.session.lock().await;
        if !session.authenticated {
            if let Some(shared) = shared_failure(&session) {
                return Err(shared);
            }
            if let Err(error) = self.login(&mut session).await {
                record_failure(&mut session, &error);
                return Err(error);
            }
        }
        Ok(session.generation)
    }

    /// Re-authenticate after a login-required rejection, but only when the
    /// session is still at the generation the caller used. An observer of a
    /// stale generation adopts the newer session, and any caller inside a
    /// failed login's backoff window shares that failure instead of issuing
    /// further logins against the rate-limited login route.
    async fn refresh_session(&self, observed_generation: u64) -> Result<(), ApiError> {
        let mut session = self.session.lock().await;
        if session.generation != observed_generation && session.authenticated {
            return Ok(());
        }
        if let Some(shared) = shared_failure(&session) {
            return Err(shared);
        }
        session.authenticated = false;
        match self.login(&mut session).await {
            Ok(()) => Ok(()),
            Err(error) => {
                record_failure(&mut session, &error);
                Err(error)
            }
        }
    }

    /// Log in, detecting the console family on first use: `UniFi OS`
    /// answers at `/api/auth/login`, while a standalone controller has no
    /// such route (404) and uses `/api/login`.
    async fn login(&self, session: &mut SessionState) -> Result<(), ApiError> {
        let kind = if let Some(kind) = session.kind {
            kind
        } else {
            let probe = self.send_login(&["api", "auth", "login"]).await?;
            let status = probe.status();
            if status == StatusCode::NOT_FOUND {
                drop(http::read_bounded_body(probe).await);
                session.kind = Some(ConsoleKind::Standalone);
                ConsoleKind::Standalone
            } else if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                // A transient response proves nothing about routing: surface
                // the failure without latching a kind, so the next attempt
                // re-probes instead of permanently misrouting a standalone
                // controller probed during an outage.
                return self.finish_login(session, probe).await;
            } else {
                // Any non-transient answer proves the UniFi OS login route
                // exists, including definitive rejections.
                session.kind = Some(ConsoleKind::UnifiOs);
                return self.finish_login(session, probe).await;
            }
        };
        let segments: &[&str] = match kind {
            ConsoleKind::UnifiOs => &["api", "auth", "login"],
            ConsoleKind::Standalone => &["api", "login"],
        };
        let response = self.send_login(segments).await?;
        self.finish_login(session, response).await
    }

    async fn send_login(&self, segments: &[&str]) -> Result<Response, ApiError> {
        let url = http::build_url(&self.base, segments, &[])?;
        self.http
            .request(Method::POST, url)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&serde_json::json!({
                "username": self.username,
                "password": self.password.as_str(),
            }))
            .send()
            .await
            .map_err(|error| {
                ApiError::Transport(BoundedMessage::new(&error.without_url().to_string()))
            })
    }

    async fn finish_login(
        &self,
        session: &mut SessionState,
        response: Response,
    ) -> Result<(), ApiError> {
        capture_csrf_into(session, &response);
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            // Hammering a rate-limited login triggers the controller's
            // account lockout; this always surfaces and is never retried.
            return Err(ApiError::RateLimited {
                retry_after: http::retry_after(&response),
            });
        }
        let bytes = http::read_bounded_body(response).await?;
        if !status.is_success() {
            return Err(translate_failure(
                status.as_u16(),
                &bytes,
                &[self.password.as_str()],
                RequestClass::IdempotentRead,
            ));
        }
        // A login answered 2xx can still carry a rejection envelope; the
        // session is authenticated only when no such rejection is present,
        // whether or not the rejection names a code.
        if let Some(rejected) = envelope_rejection(&bytes) {
            let scrubbed = rejected
                .code
                .map(|value| scrub(&value, &[self.password.as_str()]));
            return Err(rejection(scrubbed.as_deref()));
        }
        session.authenticated = true;
        session.generation += 1;
        session.failed_login = None;
        Ok(())
    }

    async fn capture_csrf(&self, response: &Response) {
        if let Some(token) = header_value(response, CSRF_HEADER) {
            let mut session = self.session.lock().await;
            session.csrf = Some(token);
        }
    }
}

fn capture_csrf_into(session: &mut SessionState, response: &Response) {
    if let Some(token) = header_value(response, CSRF_HEADER) {
        session.csrf = Some(token);
    }
}

fn shared_failure(session: &SessionState) -> Option<ApiError> {
    session
        .failed_login
        .as_ref()
        .filter(|failure| Instant::now() < failure.until)
        .map(|failure| failure.error.clone())
}

fn record_failure(session: &mut SessionState, error: &ApiError) {
    session.failed_login = Some(FailedLogin {
        until: Instant::now() + backoff_window(error),
        error: error.clone(),
    });
}

/// How long a failed login's outcome is shared. Rate limiting honors the
/// controller's own delay within a bounded range; any other failure gets a
/// brief burst-collapse window so one transient error cannot poison the
/// client.
fn backoff_window(error: &ApiError) -> Duration {
    match error {
        ApiError::RateLimited {
            retry_after: Some(delay),
        } => (*delay).clamp(Duration::from_secs(1), Duration::from_mins(1)),
        ApiError::RateLimited { retry_after: None } => Duration::from_secs(5),
        _ => Duration::from_secs(1),
    }
}

fn validate_protect_bootstrap(bootstrap: &ProtectBootstrap) -> Result<(), ApiError> {
    validate_protect_cameras(&bootstrap.cameras)?;
    if bootstrap.nvr.id.is_empty()
        || bootstrap.nvr.id.len() > MAXIMUM_PROTECT_DEVICE_IDENTIFIER_BYTES
    {
        return Err(ApiError::SchemaMismatch {
            endpoint: "protect.bootstrap",
            path: BoundedMessage::new("nvr.id"),
        });
    }
    if bootstrap.nvr.model_key != "nvr" {
        return Err(ApiError::SchemaMismatch {
            endpoint: "protect.bootstrap",
            path: BoundedMessage::new("nvr.modelKey"),
        });
    }
    Ok(())
}

fn validate_protect_cameras(cameras: &[ProtectLocalCamera]) -> Result<(), ApiError> {
    if cameras.len() > MAXIMUM_PROTECT_CAMERAS {
        return Err(ApiError::SchemaMismatch {
            endpoint: "protect.bootstrap",
            path: BoundedMessage::new("cameras"),
        });
    }
    for camera in cameras {
        if camera.id.is_empty() || camera.id.len() > MAXIMUM_PROTECT_DEVICE_IDENTIFIER_BYTES {
            return Err(ApiError::SchemaMismatch {
                endpoint: "protect.bootstrap",
                path: BoundedMessage::new("cameras.id"),
            });
        }
        if camera.model_key != "camera" {
            return Err(ApiError::SchemaMismatch {
                endpoint: "protect.bootstrap",
                path: BoundedMessage::new("cameras.modelKey"),
            });
        }
    }
    Ok(())
}

fn protect_decode_error_kind(error: &ApiError) -> &'static str {
    match error {
        ApiError::InvalidJson { .. } => "invalid_json",
        ApiError::SchemaMismatch { .. } => "schema_mismatch",
        ApiError::ResponseTooLarge { .. } => "oversized_body",
        _ => "upstream_failure",
    }
}

fn log_protect_response_rejection(endpoint: &'static str, status: u16, error: &ApiError) {
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
            error_kind = protect_decode_error_kind(error),
            "Protect response rejected"
        );
    }
}

fn header_value(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn is_login_required(error: &ApiError) -> bool {
    matches!(error, ApiError::Rejected { code, .. } if code.as_str() == LOGIN_REQUIRED_CODE)
}

fn login_required_error() -> ApiError {
    ApiError::Rejected {
        code: BoundedMessage::new(LOGIN_REQUIRED_CODE),
        message: BoundedMessage::new("the controller session is no longer valid"),
    }
}

/// Translate a non-success HTTP response whose body may carry the legacy
/// envelope. A login endpoint or intermediary that reflects the submitted
/// credential must not leak it through the error surface: the envelope `msg`
/// is scrubbed after JSON decoding (where a reflected credential appears
/// literally), and a body without a recognizable envelope forwards no
/// upstream content at all, because literal scrubbing cannot match a
/// credential hidden behind serialization escapes.
fn translate_failure(status: u16, bytes: &[u8], secrets: &[&str], class: RequestClass) -> ApiError {
    match envelope_rejection(bytes) {
        Some(rejected) => {
            // Same rule as the 2xx rejection path: message text decides
            // expiry for a read only, and it is read before the scrub.
            if class == RequestClass::IdempotentRead
                && rejected.code.as_deref() == Some(LOGIN_REQUIRED_CODE)
            {
                return login_required_error();
            }
            let scrubbed = rejected.code.map(|value| scrub(&value, secrets));
            rejection(scrubbed.as_deref())
        }
        None => ApiError::Status {
            status,
            message: BoundedMessage::new(
                "no recognizable error envelope in the controller response",
            ),
        },
    }
}

/// The `meta.msg` of a rejection envelope, when the body carries one.
/// A rejection envelope carried in a response body: `meta.rc` present and
/// not `ok`, with its optional `meta.msg`, since the controller can reject
/// without naming a code.
struct EnvelopeRejection {
    code: Option<String>,
}

fn envelope_rejection(bytes: &[u8]) -> Option<EnvelopeRejection> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    let rc = value
        .get("meta")
        .and_then(|meta| meta.get("rc"))
        .and_then(serde_json::Value::as_str)?;
    if rc == "ok" {
        return None;
    }
    Some(EnvelopeRejection {
        code: value
            .get("meta")
            .and_then(|meta| meta.get("msg"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

/// Replace every occurrence of every secret with the marker.
///
/// Occurrences are located first and their ranges merged, then the text is
/// rebuilt once. Replacing secrets one after another instead would let the
/// first replacement consume part of a longer secret's match and leave the
/// remainder of that secret in the text; the result here does not depend on
/// the order the secrets arrive in, or on one containing another.
fn scrub(text: &str, secrets: &[&str]) -> String {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        let mut from = 0;
        while let Some(offset) = text[from..].find(secret) {
            let start = from + offset;
            ranges.push((start, start + secret.len()));
            from = start + 1;
            while from < text.len() && !text.is_char_boundary(from) {
                from += 1;
            }
        }
    }
    if ranges.is_empty() {
        return text.to_owned();
    }
    ranges.sort_unstable();
    let mut scrubbed = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end) in ranges {
        if start >= cursor {
            scrubbed.push_str(&text[cursor..start]);
            scrubbed.push_str("<redacted>");
            cursor = end;
        } else if end > cursor {
            // An overlapping match simply extends the redacted span.
            cursor = end;
        }
    }
    scrubbed.push_str(&text[cursor..]);
    scrubbed
}

/// Map a legacy `api.err.*` code to a typed rejection with actionable
/// guidance.
fn rejection(code: Option<&str>) -> ApiError {
    let code = code.unwrap_or("api.err.Unknown");
    let guidance = match code {
        "api.err.Ubic2faTokenRequired" => {
            "the account requires MFA, which the legacy login cannot satisfy; \
             use a dedicated local administrator without MFA"
        }
        "api.err.NoPermission" => "the account lacks permission for this operation",
        "api.err.Invalid" => "the controller rejected the credentials or arguments",
        LOGIN_REQUIRED_CODE => "the controller session is no longer valid",
        _ => "the controller rejected the request",
    };
    ApiError::Rejected {
        code: BoundedMessage::new(code),
        message: BoundedMessage::new(guidance),
    }
}

fn finish_protect_event_page(
    start: u64,
    end: u64,
    limit: u32,
    mut events: Vec<ProtectEvent>,
) -> Result<ProtectEventPage, ApiError> {
    if events
        .iter()
        .any(|event| event.id.is_empty() || event.id.len() > MAXIMUM_EVENT_IDENTIFIER_BYTES)
    {
        return Err(ApiError::Decode(BoundedMessage::new(
            "Protect event response contains an invalid event id",
        )));
    }
    if events.iter().any(|event| event.start > end) {
        return Err(ApiError::Decode(BoundedMessage::new(
            "Protect event response exceeded its requested end",
        )));
    }
    if events.windows(2).any(|pair| pair[0].start < pair[1].start) {
        return Err(ApiError::Decode(BoundedMessage::new(
            "Protect event response was not ordered newest first",
        )));
    }

    let page_limit = usize::try_from(limit)
        .map_err(|_| ApiError::Config("Protect event page limit overflowed".to_owned()))?;
    if events.len() > page_limit + 1 {
        return Err(ApiError::Decode(BoundedMessage::new(
            "Protect event response exceeded its requested limit",
        )));
    }
    let lookahead_start =
        (events.len() > page_limit).then(|| events.pop().expect("lookahead row exists").start);
    let scanned_rows = events.len();
    if let Some(first_older) = events.iter().position(|event| event.start < start) {
        events.truncate(first_older);
        return Ok(ProtectEventPage {
            events,
            scanned_rows,
            next: None,
        });
    }
    let Some(lookahead_start) = lookahead_start else {
        return Ok(ProtectEventPage {
            events,
            scanned_rows,
            next: None,
        });
    };
    if lookahead_start < start {
        return Ok(ProtectEventPage {
            events,
            scanned_rows,
            next: None,
        });
    }

    let boundary_start = events.last().map(|event| event.start).ok_or_else(|| {
        ApiError::Decode(BoundedMessage::new(
            "Protect event page could not establish a continuation",
        ))
    })?;
    let next_end = if boundary_start == lookahead_start {
        while events
            .last()
            .is_some_and(|event| event.start == boundary_start)
        {
            events.pop();
        }
        if events.is_empty() {
            return Err(ApiError::Config(
                "Protect event page boundary exceeds the requested limit; retry with a higher limit"
                    .to_owned(),
            ));
        }
        boundary_start
    } else {
        let Some(next_end) = boundary_start.checked_sub(1) else {
            return Ok(ProtectEventPage {
                events,
                scanned_rows,
                next: None,
            });
        };
        next_end
    };
    Ok(ProtectEventPage {
        events,
        scanned_rows,
        next: Some(ProtectEventContinuation { next_end }),
    })
}
