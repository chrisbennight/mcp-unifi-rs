use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use url::Url;
use zeroize::Zeroizing;

const IDENTITY_HEADER: &str = "x-mcp-identity";
const MINIMUM_BEARER_BYTES: usize = 32;
const MAXIMUM_JWKS_BYTES: usize = 64 * 1024;
const MAXIMUM_IDENTITY_ACTOR_BYTES: usize = 256;
const CLOCK_SKEW_SECONDS: i64 = 30;
/// Shortest interval between JWKS fetches driven by unknown key IDs; a
/// legitimate gateway key rotation recovers within this window while a
/// bearer-holding caller cannot force per-request JWKS traffic.
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
const MAXIMUM_IDENTITY_TOKEN_AGE_SECONDS: i64 = 240;
const MAXIMUM_IDENTITY_TOKEN_LIFETIME_SECONDS: i64 = 300;

/// Current and optional previous gateway service credentials.
pub struct GatewayBearers {
    current: Zeroizing<String>,
    previous: Option<Zeroizing<String>>,
}

impl GatewayBearers {
    /// Construct a rotation set with minimum length and distinct values.
    ///
    /// # Errors
    ///
    /// Returns an error for weak, whitespace-bearing, or duplicate values.
    pub fn new(current: String, previous: Option<String>) -> Result<Self, AuthConfigError> {
        Self::from_protected(Zeroizing::new(current), previous.map(Zeroizing::new))
    }

    /// Construct a rotation set from allocations protected during configuration loading.
    ///
    /// # Errors
    ///
    /// Returns an error for weak, whitespace-bearing, or duplicate values.
    pub fn from_protected(
        current: Zeroizing<String>,
        previous: Option<Zeroizing<String>>,
    ) -> Result<Self, AuthConfigError> {
        validate_bearer(&current)?;
        if let Some(previous) = previous.as_deref() {
            validate_bearer(previous)?;
            if constant_time_equal(current.as_bytes(), previous.as_bytes()).into() {
                return Err(AuthConfigError::DuplicateBearers);
            }
        }
        Ok(Self { current, previous })
    }

    pub(crate) fn accepts(&self, supplied: &[u8]) -> bool {
        let current = constant_time_equal(supplied, self.current.as_bytes());
        let previous = self.previous.as_ref().map_or(Choice::from(0), |value| {
            constant_time_equal(supplied, value.as_bytes())
        });
        bool::from(current | previous)
    }
}

impl std::fmt::Debug for GatewayBearers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayBearers")
            .field("current", &"[REDACTED]")
            .field("previous", &self.previous.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthConfigError {
    #[error("gateway bearer must contain at least 32 bytes and no whitespace")]
    InvalidBearer,
    #[error("current and previous gateway bearers must differ")]
    DuplicateBearers,
    #[error("identity JWKS URL must use HTTPS or loopback/private HTTP")]
    UnsafeJwksUrl,
    #[error("identity issuer, actor, and timing bounds must be valid")]
    InvalidIdentitySettings,
    #[error("failed to construct the identity verification client")]
    IdentityClient,
}

fn validate_bearer(value: &str) -> Result<(), AuthConfigError> {
    if value.len() < MINIMUM_BEARER_BYTES || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(AuthConfigError::InvalidBearer);
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> Choice {
    if left.len() != right.len() {
        return Choice::from(0);
    }
    left.ct_eq(right)
}

#[derive(Debug, Clone)]
pub struct IdentityVerifierSettings {
    pub jwks_url: Url,
    pub issuer: String,
    pub actor: String,
    pub audience: String,
    pub request_timeout: Duration,
    pub cache_ttl: Duration,
}

#[derive(Clone)]
pub struct IdentityVerifier {
    settings: Arc<IdentityVerifierSettings>,
    client: reqwest::Client,
    cache: Arc<RwLock<CacheState>>,
    refresh: Arc<Mutex<()>>,
}

enum CacheLookup {
    Found(Box<jsonwebtoken::jwk::Jwk>),
    MissInCooldown,
    Refreshable,
}

/// Cached JWKS material plus the last fetch attempt, successful or not; the
/// refresh cooldown keys off the attempt so a failing JWKS endpoint cannot
/// be hammered by bearer-authenticated traffic.
#[derive(Debug, Default)]
struct CacheState {
    keys: Option<CachedKeys>,
    last_attempt: Option<Instant>,
}

#[derive(Debug)]
struct CachedKeys {
    keys: JwkSet,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct ActorClaim {
    sub: String,
}

#[derive(Debug, Deserialize)]
struct IdentityClaims {
    sub: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    groups: Vec<String>,
    act: ActorClaim,
}

/// Verified caller identity propagated by the gateway; the type lives in
/// `unifi_mcp` so the tool layer can read it from request extensions.
pub use unifi_mcp::IdentityPrincipal;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid gateway identity")]
    Invalid,
    #[error("gateway identity key is unavailable")]
    KeyUnavailable,
    #[error("gateway identity service is unavailable")]
    Unavailable,
}

impl IdentityVerifierSettings {
    /// Reject unsafe URLs, malformed trust anchors, and out-of-bounds
    /// timing values. Shared by the settings load (fail closed at startup)
    /// and verifier construction, so both enforce one definition.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe URLs, empty issuers, padded or invalid
    /// actors, or invalid bounds.
    pub fn validate(&self) -> Result<(), AuthConfigError> {
        validate_jwks_url(&self.jwks_url)?;
        if self.issuer.trim().is_empty()
            || self.actor.trim() != self.actor
            || self.actor.is_empty()
            || self.audience.trim() != self.audience
            || self.audience.is_empty()
            || self.audience.chars().any(char::is_control)
            || self.actor.len() > MAXIMUM_IDENTITY_ACTOR_BYTES
            || self.actor.chars().any(char::is_control)
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(30)
            || self.cache_ttl.is_zero()
            || self.cache_ttl > Duration::from_hours(1)
        {
            return Err(AuthConfigError::InvalidIdentitySettings);
        }
        Ok(())
    }
}

impl IdentityVerifier {
    /// Construct a bounded, redirect-free JWKS verifier.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe URLs, empty issuers, invalid bounds, or client failures.
    pub fn new(settings: IdentityVerifierSettings) -> Result<Self, AuthConfigError> {
        settings.validate()?;
        let client = reqwest::Client::builder()
            .timeout(settings.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| AuthConfigError::IdentityClient)?;
        Ok(Self {
            settings: Arc::new(settings),
            client,
            cache: Arc::new(RwLock::new(CacheState::default())),
            refresh: Arc::new(Mutex::new(())),
        })
    }

    /// Verify the identity JWT signature, audience, issuer, time, and actor.
    async fn verify(&self, token: &str) -> Result<IdentityPrincipal, IdentityError> {
        self.verify_with_time(token, None).await
    }

    #[cfg(test)]
    async fn verify_at(
        &self,
        token: &str,
        timestamp: i64,
    ) -> Result<IdentityPrincipal, IdentityError> {
        self.verify_with_time(token, Some(timestamp)).await
    }

    async fn verify_with_time(
        &self,
        token: &str,
        timestamp: Option<i64>,
    ) -> Result<IdentityPrincipal, IdentityError> {
        let header = decode_header(token).map_err(|_| IdentityError::Invalid)?;
        if header.alg != Algorithm::EdDSA {
            return Err(IdentityError::Invalid);
        }
        let key_id = header.kid.ok_or(IdentityError::Invalid)?;
        let key = self.key(&key_id).await?;
        let decoding = DecodingKey::from_jwk(&key).map_err(|_| IdentityError::Invalid)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.settings.issuer.as_str()]);
        validation.set_audience(&[self.settings.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "iat"]);
        validation.leeway = CLOCK_SKEW_SECONDS.unsigned_abs();
        let claims = decode::<IdentityClaims>(token, &decoding, &validation)
            .map_err(|_| IdentityError::Invalid)?
            .claims;
        let now = match timestamp {
            Some(timestamp) => timestamp,
            None => unix_timestamp().map_err(|_| IdentityError::Invalid)?,
        };
        let valid_lifetime = claims.exp.checked_sub(claims.iat).is_some_and(|lifetime| {
            (1..=MAXIMUM_IDENTITY_TOKEN_LIFETIME_SECONDS).contains(&lifetime)
        });
        if claims.sub.is_empty()
            || claims.act.sub != self.settings.actor
            || claims.iat
                < now.saturating_sub(
                    MAXIMUM_IDENTITY_TOKEN_AGE_SECONDS.saturating_add(CLOCK_SKEW_SECONDS),
                )
            || claims.iat > now.saturating_add(CLOCK_SKEW_SECONDS)
            || claims.exp
                > now.saturating_add(
                    MAXIMUM_IDENTITY_TOKEN_LIFETIME_SECONDS.saturating_add(CLOCK_SKEW_SECONDS),
                )
            || !valid_lifetime
            || claims.groups.len() > 256
            || claims.groups.iter().any(|group| group.len() > 256)
        {
            return Err(IdentityError::Invalid);
        }
        Ok(IdentityPrincipal {
            subject: claims.sub,
            groups: claims.groups,
        })
    }

    async fn key(&self, key_id: &str) -> Result<jsonwebtoken::jwk::Jwk, IdentityError> {
        match self.cached_lookup(key_id).await {
            CacheLookup::Found(key) => return Ok(*key),
            CacheLookup::MissInCooldown => return Err(IdentityError::KeyUnavailable),
            CacheLookup::Refreshable => {}
        }
        let _guard = self.refresh.lock().await;
        match self.cached_lookup(key_id).await {
            CacheLookup::Found(key) => return Ok(*key),
            CacheLookup::MissInCooldown => return Err(IdentityError::KeyUnavailable),
            CacheLookup::Refreshable => {}
        }
        // Every attempt arms the cooldown, and a fetched set is stored
        // whether or not it carries the requested key: neither an unknown
        // kid nor a failing JWKS endpoint may drive one remote fetch per
        // request.
        let result = self.fetch_keys().await;
        let now = Instant::now();
        let mut state = self.cache.write().await;
        state.last_attempt = Some(now);
        match result {
            Ok(keys) => {
                let key = keys.find(key_id).cloned();
                state.keys = Some(CachedKeys {
                    keys,
                    expires_at: now + self.settings.cache_ttl,
                });
                drop(state);
                key.ok_or(IdentityError::KeyUnavailable)
            }
            Err(error) => Err(error),
        }
    }

    async fn cached_lookup(&self, key_id: &str) -> CacheLookup {
        let guard = self.cache.read().await;
        let now = Instant::now();
        if let Some(cache) = guard.keys.as_ref().filter(|cache| cache.expires_at > now)
            && let Some(key) = cache.keys.find(key_id)
        {
            return CacheLookup::Found(Box::new(key.clone()));
        }
        // A fresh key set without the key, a failed attempt, or a stale set
        // all share one rule: no new fetch inside the cooldown.
        match guard.last_attempt {
            Some(attempt) if now < attempt + JWKS_REFRESH_COOLDOWN => CacheLookup::MissInCooldown,
            _ => CacheLookup::Refreshable,
        }
    }

    async fn fetch_keys(&self) -> Result<JwkSet, IdentityError> {
        let mut response = self
            .client
            .get(self.settings.jwks_url.clone())
            .send()
            .await
            .map_err(|_| IdentityError::Unavailable)?;
        if !response.status().is_success() {
            return Err(IdentityError::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| IdentityError::Unavailable)?
        {
            if body.len().saturating_add(chunk.len()) > MAXIMUM_JWKS_BYTES {
                return Err(IdentityError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| IdentityError::Unavailable)
    }
}

fn validate_jwks_url(url: &Url) -> Result<(), AuthConfigError> {
    if url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https" || url.scheme() == "http" && is_private_host(url))
    {
        Ok(())
    } else {
        Err(AuthConfigError::UnsafeJwksUrl)
    }
}

fn is_private_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback() || address.is_private(),
        Some(url::Host::Ipv6(address)) => address.is_loopback() || address.is_unique_local(),
        Some(url::Host::Domain(domain)) => domain == "localhost" || !domain.contains('.'),
        None => false,
    }
}

fn unix_timestamp() -> Result<i64, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}

#[derive(Clone)]
pub struct IngressAuth {
    bearers: Arc<GatewayBearers>,
    verifier: IdentityVerifier,
    allowed_hosts: Arc<[String]>,
    allowed_origins: Arc<[String]>,
}

impl IngressAuth {
    #[must_use]
    pub fn new(
        bearers: Arc<GatewayBearers>,
        verifier: IdentityVerifier,
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
    ) -> Self {
        Self {
            bearers,
            verifier,
            allowed_hosts: allowed_hosts.into(),
            allowed_origins: allowed_origins.into(),
        }
    }
}

#[derive(Serialize)]
struct AuthFailure {
    error: &'static str,
}

pub async fn require_gateway(
    State(auth): State<IngressAuth>,
    mut request: Request,
    next: Next,
) -> Response {
    match authenticate(&auth, request.headers()).await {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(()) => (
            StatusCode::UNAUTHORIZED,
            Json(AuthFailure {
                error: "gateway authentication required",
            }),
        )
            .into_response(),
    }
}

async fn authenticate(
    auth: &IngressAuth,
    headers: &axum::http::HeaderMap,
) -> Result<IdentityPrincipal, ()> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase)
        .ok_or(())?;
    if !auth.allowed_hosts.iter().any(|allowed| allowed == &host) {
        return Err(());
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.to_str().map_err(|_| ())?;
        if !auth.allowed_origins.iter().any(|allowed| allowed == origin) {
            return Err(());
        }
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(())?;
    if !auth.bearers.accepts(bearer.as_bytes()) {
        return Err(());
    }
    let identity = headers
        .get(IDENTITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(())?;
    auth.verifier.verify(identity).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::http::{HeaderMap, HeaderValue, header};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{
        AuthConfigError, GatewayBearers, IdentityError, IdentityVerifier, IdentityVerifierSettings,
        IngressAuth, MAXIMUM_IDENTITY_ACTOR_BYTES, MAXIMUM_JWKS_BYTES, authenticate,
        unix_timestamp,
    };

    const CURRENT_BEARER: &str = "0123456789abcdef0123456789abcdef";
    const PREVIOUS_BEARER: &str = "fedcba9876543210fedcba9876543210";
    const EXPECTED_ACTOR: &str = "gateway.example.net";

    #[derive(Clone, Serialize)]
    struct TestActorClaim {
        sub: String,
    }

    #[derive(Clone, Serialize)]
    struct TestIdentityClaims {
        sub: String,
        iss: String,
        aud: String,
        iat: i64,
        exp: i64,
        groups: Vec<String>,
        act: TestActorClaim,
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn valid_claims() -> TestIdentityClaims {
        let now = unix_timestamp().expect("timestamp");
        TestIdentityClaims {
            sub: "user:codex".into(),
            iss: "https://gateway.test".into(),
            aud: "unifi".into(),
            iat: now,
            exp: now + 300,
            groups: vec!["unifi".into()],
            act: TestActorClaim {
                sub: EXPECTED_ACTOR.into(),
            },
        }
    }

    fn token(signing: &SigningKey, claims: &TestIdentityClaims) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("test-key".into());
        let document = signing.to_pkcs8_der().expect("PKCS#8 test key");
        encode(
            &header,
            claims,
            &EncodingKey::from_ed_der(document.as_bytes()),
        )
        .expect("identity token")
    }

    async fn verifier() -> (IdentityVerifier, SigningKey, MockServer) {
        let signing = signing_key();
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
            .expect(1)
            .mount(&server)
            .await;
        let verifier = IdentityVerifier::new(IdentityVerifierSettings {
            jwks_url: Url::parse(&format!("{}/jwks", server.uri())).expect("JWKS URL"),
            issuer: "https://gateway.test".into(),
            actor: EXPECTED_ACTOR.into(),
            audience: "unifi".into(),
            request_timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_mins(1),
        })
        .expect("verifier");
        (verifier, signing, server)
    }

    #[tokio::test]
    async fn unknown_key_ids_cannot_force_per_request_jwks_fetches() {
        // The helper's JWKS mock expects exactly one fetch; repeated tokens
        // with an unknown kid must reject from the fresh cache inside the
        // cooldown instead of fetching per request.
        let (verifier, signing, server) = verifier().await;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("rotated-key".into());
        let document = signing.to_pkcs8_der().expect("PKCS#8 test key");
        let unknown = encode(
            &header,
            &valid_claims(),
            &EncodingKey::from_ed_der(document.as_bytes()),
        )
        .expect("identity token");
        for _ in 0..3 {
            assert!(matches!(
                verifier.verify(&unknown).await,
                Err(IdentityError::KeyUnavailable)
            ));
        }
        drop(server);
    }

    #[tokio::test]
    async fn jwks_failures_arm_the_cooldown_and_are_not_hammered() {
        let signing = signing_key();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        let verifier = IdentityVerifier::new(IdentityVerifierSettings {
            jwks_url: Url::parse(&server.uri()).expect("URL"),
            issuer: "https://gateway.test".into(),
            actor: EXPECTED_ACTOR.into(),
            audience: "unifi".into(),
            request_timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_mins(1),
        })
        .expect("verifier");
        let identity = token(&signing, &valid_claims());
        assert!(matches!(
            verifier.verify(&identity).await,
            Err(IdentityError::Unavailable)
        ));
        // Inside the cooldown the failure is shared without further I/O;
        // the mock's single-fetch expectation is the guard.
        for _ in 0..2 {
            assert!(matches!(
                verifier.verify(&identity).await,
                Err(IdentityError::KeyUnavailable)
            ));
        }
        drop(server);
    }

    #[tokio::test]
    async fn forged_or_malformed_tokens_are_rejected() {
        let (verifier, _signing, _server) = verifier().await;
        // Signed by a different key under the advertised kid.
        let untrusted_key = SigningKey::from_bytes(&[9_u8; 32]);
        let forged = token(&untrusted_key, &valid_claims());
        assert!(matches!(
            verifier.verify(&forged).await,
            Err(IdentityError::Invalid)
        ));

        // Wrong algorithm under the advertised kid.
        let mut hs_header = Header::new(Algorithm::HS256);
        hs_header.kid = Some("test-key".into());
        let symmetric = encode(
            &hs_header,
            &valid_claims(),
            &EncodingKey::from_secret(b"not-an-ed25519-key"),
        )
        .expect("token");
        assert!(verifier.verify(&symmetric).await.is_err());

        // No kid at all.
        let document = signing_key().to_pkcs8_der().expect("PKCS#8 test key");
        let kidless = encode(
            &Header::new(Algorithm::EdDSA),
            &valid_claims(),
            &EncodingKey::from_ed_der(document.as_bytes()),
        )
        .expect("token");
        assert!(verifier.verify(&kidless).await.is_err());

        // Not a JWT.
        assert!(verifier.verify("not-a-jwt").await.is_err());
    }

    #[test]
    fn bearer_rotation_is_constant_contract_and_redacted() {
        let bearers = GatewayBearers::new(CURRENT_BEARER.into(), Some(PREVIOUS_BEARER.into()))
            .expect("valid");
        assert!(bearers.accepts(CURRENT_BEARER.as_bytes()));
        assert!(bearers.accepts(PREVIOUS_BEARER.as_bytes()));
        assert!(!bearers.accepts(b"wrong"));
        assert!(!bearers.accepts(&CURRENT_BEARER.as_bytes()[..31]));
        let debug = format!("{bearers:?}");
        assert!(!debug.contains(CURRENT_BEARER));
        assert!(!debug.contains(PREVIOUS_BEARER));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn weak_or_duplicate_bearers_are_rejected() {
        assert_eq!(
            GatewayBearers::new("short".into(), None).expect_err("weak bearer"),
            AuthConfigError::InvalidBearer
        );
        for weak in [
            "1234567890123456789012345678901",
            "0123456789abcdef 123456789abcdef",
        ] {
            assert_eq!(
                GatewayBearers::new(weak.into(), None).expect_err("invalid bearer"),
                AuthConfigError::InvalidBearer
            );
        }
        let value = CURRENT_BEARER;
        assert_eq!(
            GatewayBearers::new(value.into(), Some(value.into())).expect_err("duplicate"),
            AuthConfigError::DuplicateBearers
        );
    }

    #[test]
    fn identity_verifier_url_and_timing_policy_is_exact() {
        let urls = [
            ("https://gateway.example.com/jwks", true),
            ("http://gateway:8080/jwks", true),
            ("http://localhost:8080/jwks", true),
            ("http://127.0.0.1:8080/jwks", true),
            ("http://10.0.0.4:8080/jwks", true),
            ("http://[::1]:8080/jwks", true),
            ("http://[fd00::1]:8080/jwks", true),
            ("http://gateway.example.com/jwks", false),
            ("ftp://gateway/jwks", false),
            ("https://user@gateway.example.com/jwks", false),
            ("https://gateway.example.com/jwks?key=1", false),
            ("https://gateway.example.com/jwks#fragment", false),
        ];
        for (raw_url, accepted) in urls {
            let result = IdentityVerifier::new(IdentityVerifierSettings {
                jwks_url: Url::parse(raw_url).expect("URL"),
                issuer: "https://gateway.test".into(),
                actor: EXPECTED_ACTOR.into(),
                audience: "unifi".into(),
                request_timeout: Duration::from_secs(2),
                cache_ttl: Duration::from_mins(1),
            });
            assert_eq!(result.is_ok(), accepted, "unexpected policy for {raw_url}");
        }

        for (issuer, timeout, cache_ttl) in [
            ("", Duration::from_secs(2), Duration::from_mins(1)),
            (
                "https://gateway.test",
                Duration::ZERO,
                Duration::from_mins(1),
            ),
            (
                "https://gateway.test",
                Duration::from_secs(31),
                Duration::from_mins(1),
            ),
            (
                "https://gateway.test",
                Duration::from_secs(2),
                Duration::ZERO,
            ),
            (
                "https://gateway.test",
                Duration::from_secs(2),
                Duration::from_secs(3601),
            ),
        ] {
            assert!(
                IdentityVerifier::new(IdentityVerifierSettings {
                    jwks_url: Url::parse("https://gateway.example.com/jwks").expect("URL"),
                    issuer: issuer.into(),
                    actor: EXPECTED_ACTOR.into(),
                    audience: "unifi".into(),
                    request_timeout: timeout,
                    cache_ttl,
                })
                .is_err()
            );
        }

        for actor in [
            String::new(),
            " leading-space".into(),
            "trailing-space ".into(),
            "control\ncharacter".into(),
            "x".repeat(MAXIMUM_IDENTITY_ACTOR_BYTES + 1),
        ] {
            assert!(
                IdentityVerifier::new(IdentityVerifierSettings {
                    jwks_url: Url::parse("https://gateway.example.com/jwks").expect("URL"),
                    issuer: "https://gateway.test".into(),
                    actor,
                    audience: "unifi".into(),
                    request_timeout: Duration::from_secs(2),
                    cache_ttl: Duration::from_mins(1),
                })
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn identity_verification_pins_signature_claims_actor_and_cache() {
        let (verifier, signing, _server) = verifier().await;
        let claims = valid_claims();
        for _ in 0..2 {
            let principal = verifier
                .verify(&token(&signing, &claims))
                .await
                .expect("valid identity");
            assert_eq!(principal.subject, "user:codex");
            assert_eq!(principal.groups, ["unifi"]);
        }

        let now = unix_timestamp().expect("timestamp");
        for boundary in [
            TestIdentityClaims {
                iat: now + 30,
                ..claims.clone()
            },
            TestIdentityClaims {
                iat: now + 30,
                exp: now + 330,
                ..claims.clone()
            },
            TestIdentityClaims {
                iat: now - 270,
                exp: now + 30,
                ..claims.clone()
            },
            TestIdentityClaims {
                groups: vec!["group".into(); 256],
                ..claims.clone()
            },
            TestIdentityClaims {
                groups: vec!["x".repeat(256)],
                ..claims.clone()
            },
        ] {
            assert!(
                verifier
                    .verify_at(&token(&signing, &boundary), now)
                    .await
                    .is_ok()
            );
        }

        let mut invalid_claims = Vec::new();
        let mut empty_subject = claims.clone();
        empty_subject.sub.clear();
        invalid_claims.push(empty_subject);
        let mut wrong_actor = claims.clone();
        wrong_actor.act.sub = "untrusted-proxy".into();
        invalid_claims.push(wrong_actor);
        let mut future = claims.clone();
        future.iat = now + 31;
        invalid_claims.push(future);
        let mut stale = claims.clone();
        stale.iat = now - 271;
        stale.exp = now + 29;
        invalid_claims.push(stale);
        let mut excessive_lifetime = claims.clone();
        excessive_lifetime.exp = now + 301;
        invalid_claims.push(excessive_lifetime);
        let mut excessive_future = claims.clone();
        excessive_future.iat = now + 30;
        excessive_future.exp = now + 331;
        invalid_claims.push(excessive_future);
        let mut reversed_lifetime = claims.clone();
        reversed_lifetime.exp = reversed_lifetime.iat;
        invalid_claims.push(reversed_lifetime);
        let mut too_many_groups = claims.clone();
        too_many_groups.groups = vec!["group".into(); 257];
        invalid_claims.push(too_many_groups);
        let mut long_group = claims.clone();
        long_group.groups = vec!["x".repeat(257)];
        invalid_claims.push(long_group);
        let mut wrong_issuer = claims.clone();
        wrong_issuer.iss = "https://other.test".into();
        invalid_claims.push(wrong_issuer);
        let mut wrong_audience = claims.clone();
        wrong_audience.aud = "other-server".into();
        invalid_claims.push(wrong_audience);
        let mut expired = claims;
        expired.exp = now - 31;
        invalid_claims.push(expired);

        for invalid in invalid_claims {
            assert!(matches!(
                verifier.verify_at(&token(&signing, &invalid), now).await,
                Err(IdentityError::Invalid)
            ));
        }
    }

    #[tokio::test]
    async fn identity_key_failures_are_bounded_and_safe() {
        let signing = signing_key();
        let claims = valid_claims();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 64 * 1024 + 1]))
            .expect(1)
            .mount(&server)
            .await;
        let verifier = IdentityVerifier::new(IdentityVerifierSettings {
            jwks_url: Url::parse(&server.uri()).expect("URL"),
            issuer: claims.iss.clone(),
            actor: EXPECTED_ACTOR.into(),
            audience: "unifi".into(),
            request_timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_mins(1),
        })
        .expect("verifier");
        assert!(matches!(
            verifier.verify(&token(&signing, &claims)).await,
            Err(IdentityError::Unavailable)
        ));

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let verifier = IdentityVerifier::new(IdentityVerifierSettings {
            jwks_url: Url::parse(&server.uri()).expect("URL"),
            issuer: claims.iss.clone(),
            actor: EXPECTED_ACTOR.into(),
            audience: "unifi".into(),
            request_timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_mins(1),
        })
        .expect("verifier");
        assert!(matches!(
            verifier.verify(&token(&signing, &claims)).await,
            Err(IdentityError::KeyUnavailable)
        ));

        let server = MockServer::start().await;
        let public_key = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        let mut bounded_jwks = serde_json::to_vec(&serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "x": public_key,
                "kid": "test-key",
                "alg": "EdDSA"
            }]
        }))
        .expect("JWKS JSON");
        bounded_jwks.resize(MAXIMUM_JWKS_BYTES, b' ');
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bounded_jwks))
            .expect(1)
            .mount(&server)
            .await;
        let verifier = IdentityVerifier::new(IdentityVerifierSettings {
            jwks_url: Url::parse(&server.uri()).expect("URL"),
            issuer: claims.iss.clone(),
            actor: EXPECTED_ACTOR.into(),
            audience: "unifi".into(),
            request_timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_mins(1),
        })
        .expect("verifier");
        assert!(verifier.verify(&token(&signing, &claims)).await.is_ok());
    }

    #[tokio::test]
    async fn ingress_auth_requires_exact_host_origin_bearer_and_identity() {
        let (verifier, signing, _server) = verifier().await;
        let auth = IngressAuth::new(
            Arc::new(
                GatewayBearers::new(CURRENT_BEARER.into(), Some(PREVIOUS_BEARER.into()))
                    .expect("bearers"),
            ),
            verifier,
            vec!["unifi-mcp:8000".into()],
            vec!["https://gateway.test".into()],
        );
        let identity = token(&signing, &valid_claims());
        let mut valid = HeaderMap::new();
        valid.insert(header::HOST, HeaderValue::from_static("unifi-mcp:8000"));
        valid.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://gateway.test"),
        );
        valid.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {CURRENT_BEARER}")).expect("authorization"),
        );
        valid.insert(
            "x-mcp-identity",
            HeaderValue::from_str(&identity).expect("identity"),
        );
        let principal = authenticate(&auth, &valid).await.expect("authenticated");
        assert_eq!(principal.subject, "user:codex");

        let mut previous = valid.clone();
        previous.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {PREVIOUS_BEARER}")).expect("authorization"),
        );
        assert!(authenticate(&auth, &previous).await.is_ok());

        for (header_name, value) in [
            (header::HOST, "other:8000"),
            (header::ORIGIN, "https://other.test"),
            (header::AUTHORIZATION, "Bearer wrong"),
            (header::AUTHORIZATION, CURRENT_BEARER),
        ] {
            let mut invalid = valid.clone();
            invalid.insert(header_name, HeaderValue::from_static(value));
            assert!(authenticate(&auth, &invalid).await.is_err());
        }
        for missing in [
            header::HOST,
            header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-mcp-identity"),
        ] {
            let mut invalid = valid.clone();
            invalid.remove(missing);
            assert!(authenticate(&auth, &invalid).await.is_err());
        }
    }
}
