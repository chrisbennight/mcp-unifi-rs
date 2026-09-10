use std::{env, sync::Arc, time::Duration};

use thiserror::Error;
use unifi_api::{TlsMode, pinning};
use unifi_mcp::ToolSurface;
use url::Url;
use zeroize::Zeroizing;

use crate::auth::{AuthConfigError, GatewayBearers, IdentityVerifierSettings};

const MAXIMUM_SECRET_BYTES: usize = 16 * 1024;
/// Ceiling on a custom CA bundle read from disk.
const MAXIMUM_CA_BYTES: u64 = 64 * 1024;
type EnvironmentLookup<'a> = dyn Fn(&'static str) -> Result<String, env::VarError> + 'a;

/// Complete runtime configuration, including the gateway ingress credentials
/// supplied by environment.
#[derive(Debug)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub log_level: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub max_body_bytes: usize,
    pub bearers: Arc<GatewayBearers>,
    pub identity: IdentityVerifierSettings,
    pub runtime: RuntimeSettings,
}

/// Upstream configuration for the one console family this process serves.
#[derive(Debug)]
pub enum RuntimeSettings {
    Network(ControllerSettings),
    Protect(ProtectSettings),
}

/// Connection settings for the one controller this server fronts.
///
/// Credentials never appear in diagnostic output: the derived container
/// `Debug` shows them redacted through `Zeroizing`, and the whole struct is
/// only formatted through [`Settings`]' derived output.
pub struct ControllerSettings {
    /// Operator-chosen controller name used in logs and tool responses.
    pub name: String,
    /// Console origin, such as `https://192.168.0.66`.
    pub base_url: Url,
    /// Integration API key.
    pub api_key: Zeroizing<String>,
    /// Dedicated local administrator for the legacy API.
    pub username: String,
    pub password: Zeroizing<String>,
    pub tls: TlsMode,
    pub timeout: Duration,
    /// Legacy API site short name, such as `default`.
    pub site: String,
}

impl std::fmt::Debug for ControllerSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerSettings")
            .field("name", &self.name)
            .field("base_url", &self.base_url.as_str())
            .field("username", &"<redacted>")
            .field("site", &self.site)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Connection settings for the Protect-only runtime.
///
/// Separate from [`ControllerSettings`] because it is a different console with
/// its own credentials and its own certificate, not a second site on the same
/// one. The official camera API authenticates by key. Historical events are
/// the one deliberate application-API exception and optionally carry their
/// own dedicated local administrator.
pub struct ProtectSettings {
    /// Operator-chosen console name used in logs and tool responses.
    pub name: String,
    /// Console origin, such as `https://192.168.0.66`.
    pub base_url: Url,
    /// Protect integration API key, minted on the console itself.
    pub api_key: Zeroizing<String>,
    pub tls: TlsMode,
    pub timeout: Duration,
    /// Local-session credentials for historical events, when configured.
    pub legacy: Option<ProtectLegacySettings>,
}

/// Dedicated local account for the Protect application event route.
pub struct ProtectLegacySettings {
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for ProtectSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectSettings")
            .field("name", &self.name)
            .field("base_url", &self.base_url.as_str())
            .field("legacy", &self.legacy.as_ref().map(|_| "<configured>"))
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// The subset of configuration the healthcheck probe needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerSettings {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {variable}: {message}")]
    Invalid {
        variable: &'static str,
        message: String,
    },
    #[error("secret environment variable {0} is unavailable or invalid")]
    SecretEnvironment(&'static str),
    #[error(transparent)]
    Auth(#[from] AuthConfigError),
}

impl Settings {
    /// Read the complete runtime configuration, including secrets supplied
    /// by environment.
    ///
    /// # Errors
    ///
    /// Returns an error when required values are absent, unsafe, malformed,
    /// or out of bounds.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::from_environment(&|variable| env::var(variable))
    }

    /// Read only the non-secret runtime surface selector.
    ///
    /// Manifest emission uses the same selector as server startup without
    /// requiring any credential to be loaded.
    ///
    /// # Errors
    ///
    /// Returns an error unless the selector is `network` or `protect`.
    pub fn surface_from_env() -> Result<ToolSurface, SettingsError> {
        surface_from_environment(&|variable| env::var(variable))
    }

    fn from_environment(environment: &EnvironmentLookup<'_>) -> Result<Self, SettingsError> {
        let listener = Self::listener_from_environment(environment)?;
        let surface = surface_from_environment(environment)?;
        let current = required_secret(environment, "UNIFI_MCP_GATEWAY_BEARER_CURRENT")?;
        let previous = optional_secret(environment, "UNIFI_MCP_GATEWAY_BEARER_PREVIOUS")?;
        let jwks_url = parse_url(
            "UNIFI_MCP_IDENTITY_JWKS_URL",
            &required(environment, "UNIFI_MCP_IDENTITY_JWKS_URL")?,
        )?;

        Ok(Self {
            host: listener.host,
            port: listener.port,
            log_level: value_or(environment, "UNIFI_MCP_LOG_LEVEL", "info"),
            allowed_hosts: {
                let defaults = match surface {
                    ToolSurface::Network => "unifi-mcp,unifi-mcp:8000,localhost,127.0.0.1",
                    ToolSurface::Protect => {
                        "unifi-protect-mcp,unifi-protect-mcp:8000,localhost,127.0.0.1"
                    }
                };
                parse_csv(&value_or(environment, "UNIFI_MCP_ALLOWED_HOSTS", defaults))
            },
            allowed_origins: parse_csv(
                &environment("UNIFI_MCP_ALLOWED_ORIGINS").unwrap_or_default(),
            ),
            request_timeout: Duration::from_secs(parse_number(
                environment,
                "UNIFI_MCP_REQUEST_TIMEOUT_SECONDS",
                30_u64,
                1,
                120,
            )?),
            max_concurrent_requests: parse_number(
                environment,
                "UNIFI_MCP_MAX_CONCURRENT_REQUESTS",
                32_usize,
                1,
                256,
            )?,
            max_body_bytes: parse_number(
                environment,
                "UNIFI_MCP_MAX_BODY_BYTES",
                1024_usize * 1024,
                1024,
                4 * 1024 * 1024,
            )?,
            bearers: Arc::new(GatewayBearers::from_protected(current, previous)?),
            identity: {
                let identity = IdentityVerifierSettings {
                    jwks_url,
                    issuer: required(environment, "UNIFI_MCP_IDENTITY_ISSUER")?,
                    actor: required_unmodified(environment, "UNIFI_MCP_IDENTITY_ACTOR")?,
                    audience: surface.server_name().to_owned(),
                    request_timeout: Duration::from_secs(3),
                    cache_ttl: Duration::from_mins(5),
                };
                // Trust anchors fail closed at load, not first use.
                identity.validate()?;
                identity
            },
            runtime: match surface {
                ToolSurface::Network => {
                    RuntimeSettings::Network(controller_from_environment(environment)?)
                }
                ToolSurface::Protect => {
                    RuntimeSettings::Protect(protect_from_environment(environment)?)
                }
            },
        })
    }

    /// Read only non-secret listener coordinates for the container
    /// healthcheck.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid port values.
    pub fn listener_from_env() -> Result<ListenerSettings, SettingsError> {
        Self::listener_from_environment(&|variable| env::var(variable))
    }

    fn listener_from_environment(
        environment: &EnvironmentLookup<'_>,
    ) -> Result<ListenerSettings, SettingsError> {
        Ok(ListenerSettings {
            host: value_or(environment, "UNIFI_MCP_HOST", "0.0.0.0"),
            port: parse_number(environment, "UNIFI_MCP_PORT", 8000_u16, 1, u16::MAX)?,
        })
    }
}

fn surface_from_environment(
    environment: &EnvironmentLookup<'_>,
) -> Result<ToolSurface, SettingsError> {
    // Absent and malformed are different answers: only "not set" (or empty)
    // may take the Network default. A non-Unicode value routed through a
    // defaulting helper would read as absence and silently start the wrong
    // surface, so the lookup is inspected directly here.
    let value = match environment("UNIFI_MCP_SURFACE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => String::new(),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(SettingsError::Invalid {
                variable: "UNIFI_MCP_SURFACE",
                message: "value is not valid Unicode".into(),
            });
        }
    };
    match value.trim() {
        "" | "network" => Ok(ToolSurface::Network),
        "protect" => Ok(ToolSurface::Protect),
        _ => Err(SettingsError::Invalid {
            variable: "UNIFI_MCP_SURFACE",
            message: "must be network or protect".into(),
        }),
    }
}

fn controller_from_environment(
    environment: &EnvironmentLookup<'_>,
) -> Result<ControllerSettings, SettingsError> {
    let base_url = controller_url(environment, &CONTROLLER_VARS)?;
    let tls = controller_tls(environment, &CONTROLLER_VARS)?;
    // A plaintext URL never performs a handshake, so a pin could not be
    // checked against anything. Accepting the pair would start a server that
    // claims verified transport and has none — the exact failure this mode
    // exists to remove, arriving quietly instead of loudly.
    if matches!(tls, TlsMode::Pinned(_)) && base_url.scheme() != "https" {
        return Err(SettingsError::Invalid {
            variable: "UNIFI_MCP_CONTROLLER_TLS",
            message: format!(
                "pinned requires an https controller URL;                  UNIFI_MCP_CONTROLLER_URL uses {}",
                base_url.scheme()
            ),
        });
    }
    Ok(ControllerSettings {
        name: value_or(environment, "UNIFI_MCP_CONTROLLER_NAME", "unifi"),
        base_url,
        api_key: required_scrubbed_secret(environment, "UNIFI_MCP_CONTROLLER_API_KEY")?,
        username: required(environment, "UNIFI_MCP_CONTROLLER_USERNAME")?,
        password: required_scrubbed_secret(environment, "UNIFI_MCP_CONTROLLER_PASSWORD")?,
        tls,
        timeout: Duration::from_secs(parse_number(
            environment,
            "UNIFI_MCP_CONTROLLER_TIMEOUT_SECONDS",
            15_u64,
            1,
            60,
        )?),
        site: {
            let site = value_or(environment, "UNIFI_MCP_CONTROLLER_SITE", "default");
            // Request construction refuses these path segments; malformed
            // coordinates fail closed at load, not on the first tool call.
            if site == "." || site == ".." || site.contains('/') {
                return Err(SettingsError::Invalid {
                    variable: "UNIFI_MCP_CONTROLLER_SITE",
                    message: "site must be a plain controller site name".into(),
                });
            }
            site
        },
    })
}

/// Read the required console for the Protect-only runtime.
fn protect_from_environment(
    environment: &EnvironmentLookup<'_>,
) -> Result<ProtectSettings, SettingsError> {
    let base_url = controller_url(environment, &PROTECT_VARS)?;
    let tls = controller_tls(environment, &PROTECT_VARS)?;
    // Same reasoning as the controller: a pin cannot be checked against a
    // handshake that never happens, so the pair fails closed at load.
    if matches!(tls, TlsMode::Pinned(_)) && base_url.scheme() != "https" {
        return Err(SettingsError::Invalid {
            variable: PROTECT_VARS.tls,
            message: format!(
                "pinned requires an https console URL; {} uses {}",
                PROTECT_VARS.url,
                base_url.scheme()
            ),
        });
    }
    let username = optional(environment, "UNIFI_MCP_PROTECT_USERNAME");
    let password = optional_scrubbed_secret(environment, "UNIFI_MCP_PROTECT_PASSWORD")?;
    let legacy = match (username, password) {
        (None, None) => None,
        (Some(username), Some(password)) => Some(ProtectLegacySettings { username, password }),
        (Some(_), None) => {
            return Err(SettingsError::SecretEnvironment(
                "UNIFI_MCP_PROTECT_PASSWORD",
            ));
        }
        (None, Some(_)) => {
            return Err(SettingsError::Missing("UNIFI_MCP_PROTECT_USERNAME"));
        }
    };
    Ok(ProtectSettings {
        name: value_or(environment, "UNIFI_MCP_PROTECT_NAME", "protect"),
        base_url,
        api_key: required_scrubbed_secret(environment, "UNIFI_MCP_PROTECT_API_KEY")?,
        tls,
        timeout: Duration::from_secs(parse_number(
            environment,
            "UNIFI_MCP_PROTECT_TIMEOUT_SECONDS",
            15_u64,
            1,
            60,
        )?),
        legacy,
    })
}

/// The console origin only: the API clients own every path under it, and
/// credentials never travel in the URL, so anything beyond
/// `scheme://host[:port]` is a misconfiguration that fails closed at load.
/// The environment variable names for one console.
///
/// The Network controller and the Protect console are validated by the same
/// code against different variables. Passing the names in keeps one copy of
/// the rules that matter — plaintext only on loopback, no credentials in the
/// URL, a pin that must accompany https — while each error still names the
/// variable the operator actually set.
struct ConsoleVars {
    url: &'static str,
    tls: &'static str,
    ca_file: &'static str,
    cert_sha256: &'static str,
}

const CONTROLLER_VARS: ConsoleVars = ConsoleVars {
    url: "UNIFI_MCP_CONTROLLER_URL",
    tls: "UNIFI_MCP_CONTROLLER_TLS",
    ca_file: "UNIFI_MCP_CONTROLLER_CA_FILE",
    cert_sha256: "UNIFI_MCP_CONTROLLER_CERT_SHA256",
};

const PROTECT_VARS: ConsoleVars = ConsoleVars {
    url: "UNIFI_MCP_PROTECT_URL",
    tls: "UNIFI_MCP_PROTECT_TLS",
    ca_file: "UNIFI_MCP_PROTECT_CA_FILE",
    cert_sha256: "UNIFI_MCP_PROTECT_CERT_SHA256",
};

fn controller_url(
    environment: &EnvironmentLookup<'_>,
    vars: &ConsoleVars,
) -> Result<Url, SettingsError> {
    let url = parse_url(vars.url, &required(environment, vars.url)?)?;
    let invalid = |message: &str| SettingsError::Invalid {
        variable: vars.url,
        message: message.into(),
    };
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid("scheme must be http or https"));
    }
    // Credentials travel to this origin, so a plaintext transport is only
    // acceptable when the hop never leaves the machine (tunnels, forwards).
    if url.scheme() == "http" && !is_loopback_host(&url) {
        return Err(invalid(
            "http is only supported for loopback controllers; use https",
        ));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(invalid("URL must not carry a path; clients own API paths"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("URL must not carry a query or fragment"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("credentials must not travel in the URL"));
    }
    Ok(url)
}

/// Consoles ship self-signed certificates, so the trust mode is an explicit
/// operator choice; an unrecognized value fails closed instead of silently
/// weakening validation.
fn controller_tls(
    environment: &EnvironmentLookup<'_>,
    vars: &ConsoleVars,
) -> Result<TlsMode, SettingsError> {
    match value_or(environment, vars.tls, "system").as_str() {
        "system" => Ok(TlsMode::SystemRoots),
        "accept-invalid" => Ok(TlsMode::AcceptInvalid),
        "custom-ca" => {
            let path = required(environment, vars.ca_file)?;
            Ok(TlsMode::CustomCa(read_bounded_ca(&path, vars.ca_file)?))
        }
        "pinned" => Ok(TlsMode::Pinned(controller_pins(environment, vars)?)),
        _ => Err(SettingsError::Invalid {
            variable: vars.tls,
            message: "expected system, custom-ca, pinned, or accept-invalid".into(),
        }),
    }
}

/// The certificate digests `pinned` accepts.
///
/// A console's certificate names neither the address it answers on nor
/// anything resolvable, so validating it by name cannot succeed; the digest is
/// the identity instead. More than one is accepted, comma separated, so a
/// console's certificate can be replaced by listing the next digest before the
/// change and removing the old one after.
fn controller_pins(
    environment: &EnvironmentLookup<'_>,
    vars: &ConsoleVars,
) -> Result<Vec<pinning::CertificateFingerprint>, SettingsError> {
    let raw = required(environment, vars.cert_sha256)?;
    let invalid = |message: String| SettingsError::Invalid {
        variable: vars.cert_sha256,
        message,
    };
    let pins = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(pinning::parse_fingerprint)
        .collect::<Result<Vec<_>, String>>()
        .map_err(invalid)?;
    if pins.is_empty() {
        // An empty list would trust nothing and fail every handshake at the
        // first request. Failing here says why.
        return Err(invalid("names no fingerprint".to_owned()));
    }
    Ok(pins)
}

/// Read the CA bundle through a hard byte ceiling. The bound is enforced on
/// the read itself, so a special file or one that grows after any check
/// yields a deterministic error instead of unbounded memory growth.
fn read_bounded_ca(path: &str, variable: &'static str) -> Result<Vec<u8>, SettingsError> {
    use std::io::Read;
    let invalid = |message: String| SettingsError::Invalid { variable, message };
    let file = std::fs::File::open(path).map_err(|error| invalid(error.to_string()))?;
    let mut pem = Vec::new();
    file.take(MAXIMUM_CA_BYTES + 1)
        .read_to_end(&mut pem)
        .map_err(|error| invalid(error.to_string()))?;
    if pem.len() as u64 > MAXIMUM_CA_BYTES {
        return Err(invalid(
            "certificate bundle exceeds the supported size".into(),
        ));
    }
    Ok(pem)
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn required_secret(
    environment: &EnvironmentLookup<'_>,
    variable: &'static str,
) -> Result<Zeroizing<String>, SettingsError> {
    let value = environment(variable).map_err(|_| SettingsError::SecretEnvironment(variable))?;
    validate_secret(variable, value)
}

fn optional_secret(
    environment: &EnvironmentLookup<'_>,
    variable: &'static str,
) -> Result<Option<Zeroizing<String>>, SettingsError> {
    match environment(variable) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => validate_secret(variable, value).map(Some),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(SettingsError::SecretEnvironment(variable)),
    }
}

fn validate_secret(
    variable: &'static str,
    value: String,
) -> Result<Zeroizing<String>, SettingsError> {
    if value.is_empty() || value.len() > MAXIMUM_SECRET_BYTES {
        return Err(SettingsError::SecretEnvironment(variable));
    }
    Ok(Zeroizing::new(value))
}

/// A controller credential, which additionally has to be redactable.
///
/// These two values are the scrub set: every result is searched for them. One
/// that survives its own redaction would make every result mentioning it
/// unreturnable, and on a write that cannot be repeated that destroys what the
/// write produced. Refusing it here turns that into a startup failure.
///
/// The gateway bearers are not in that set and carry no such constraint, so
/// they go through the plain check.
fn validate_scrubbed_secret(
    variable: &'static str,
    value: String,
) -> Result<Zeroizing<String>, SettingsError> {
    let value = validate_secret(variable, value)?;
    if unifi_mcp::survives_its_own_redaction(&value) {
        return Err(SettingsError::SecretEnvironment(variable));
    }
    Ok(value)
}

fn required_scrubbed_secret(
    environment: &EnvironmentLookup<'_>,
    variable: &'static str,
) -> Result<Zeroizing<String>, SettingsError> {
    let value = environment(variable).map_err(|_| SettingsError::SecretEnvironment(variable))?;
    validate_scrubbed_secret(variable, value)
}

fn optional_scrubbed_secret(
    environment: &EnvironmentLookup<'_>,
    variable: &'static str,
) -> Result<Option<Zeroizing<String>>, SettingsError> {
    match environment(variable) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => validate_scrubbed_secret(variable, value).map(Some),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(SettingsError::SecretEnvironment(variable)),
    }
}

fn required(
    environment: &EnvironmentLookup<'_>,
    variable: &'static str,
) -> Result<String, SettingsError> {
    optional(environment, variable).ok_or(SettingsError::Missing(variable))
}

/// Trust anchors are read exactly as configured; normalization would silently
/// change what the verifier pins.
fn required_unmodified(
    environment: &EnvironmentLookup<'_>,
    variable: &'static str,
) -> Result<String, SettingsError> {
    environment(variable).map_err(|_| SettingsError::Missing(variable))
}

fn optional(environment: &EnvironmentLookup<'_>, variable: &'static str) -> Option<String> {
    environment(variable)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn value_or(environment: &EnvironmentLookup<'_>, variable: &'static str, default: &str) -> String {
    optional(environment, variable).unwrap_or_else(|| default.to_owned())
}

fn parse_number<T>(
    environment: &EnvironmentLookup<'_>,
    variable: &'static str,
    default: T,
    minimum: T,
    maximum: T,
) -> Result<T, SettingsError>
where
    T: Copy + PartialOrd + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = optional(environment, variable);
    parse_number_value(variable, raw.as_deref(), default, minimum, maximum)
}

fn parse_number_value<T>(
    variable: &'static str,
    raw: Option<&str>,
    default: T,
    minimum: T,
    maximum: T,
) -> Result<T, SettingsError>
where
    T: Copy + PartialOrd + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = raw.map_or(Ok(default), |raw| {
        raw.parse::<T>().map_err(|error| SettingsError::Invalid {
            variable,
            message: error.to_string(),
        })
    })?;
    if value < minimum || value > maximum {
        return Err(SettingsError::Invalid {
            variable,
            message: "value is outside the supported range".into(),
        });
    }
    Ok(value)
}

fn parse_url(variable: &'static str, value: &str) -> Result<Url, SettingsError> {
    Url::parse(value).map_err(|error| SettingsError::Invalid {
        variable,
        message: error.to_string(),
    })
}

fn parse_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::{sync::Arc, time::Duration};

    use unifi_api::TlsMode;
    use url::Url;
    use zeroize::Zeroizing;

    use super::{ControllerSettings, RuntimeSettings, Settings};
    use crate::auth::{GatewayBearers, IdentityVerifierSettings};

    /// Complete settings for router tests: a valid trust configuration whose
    /// JWKS endpoint is unreachable, so identity verification always fails
    /// closed unless a test overrides the URL with a live fake, and a
    /// controller endpoint that no test dials.
    pub(crate) fn settings() -> Settings {
        Settings {
            host: "127.0.0.1".into(),
            port: 8000,
            log_level: "info".into(),
            allowed_hosts: vec!["localhost".into()],
            allowed_origins: Vec::new(),
            request_timeout: Duration::from_secs(2),
            max_concurrent_requests: 4,
            max_body_bytes: 16 * 1024,
            bearers: Arc::new(
                GatewayBearers::new("0123456789abcdef0123456789abcdef".into(), None)
                    .expect("bearer"),
            ),
            identity: IdentityVerifierSettings {
                jwks_url: Url::parse("http://127.0.0.1:65534/jwks").expect("JWKS URL"),
                issuer: "https://gateway.test".into(),
                actor: "mcp.cacahuate.org".into(),
                audience: "unifi".into(),
                request_timeout: Duration::from_secs(1),
                cache_ttl: Duration::from_mins(1),
            },
            runtime: RuntimeSettings::Network(controller()),
        }
    }

    pub(crate) fn controller() -> ControllerSettings {
        ControllerSettings {
            name: "unifi".into(),
            base_url: Url::parse("https://127.0.0.1:65531").expect("controller URL"),
            api_key: Zeroizing::new("test-api-key".into()),
            username: "svc-mcp".into(),
            password: Zeroizing::new("test-password".into()),
            tls: TlsMode::SystemRoots,
            timeout: Duration::from_secs(2),
            site: "default".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAXIMUM_SECRET_BYTES, RuntimeSettings, Settings, SettingsError, TlsMode, controller_tls,
        parse_csv, parse_number_value, validate_secret,
    };
    use std::env;

    use crate::auth::{AuthConfigError, IdentityVerifier};

    fn complete_environment(variable: &'static str) -> Result<String, std::env::VarError> {
        let value = match variable {
            "UNIFI_MCP_GATEWAY_BEARER_CURRENT" => "0123456789abcdef0123456789abcdef",
            "UNIFI_MCP_IDENTITY_JWKS_URL" => "http://127.0.0.1:65533/jwks",
            "UNIFI_MCP_IDENTITY_ISSUER" => "https://gateway.test",
            "UNIFI_MCP_IDENTITY_ACTOR" => "mcp.cacahuate.org",
            "UNIFI_MCP_CONTROLLER_URL" => "https://192.0.2.1",
            "UNIFI_MCP_CONTROLLER_API_KEY" => "controller-api-key",
            "UNIFI_MCP_CONTROLLER_USERNAME" => "svc-mcp",
            "UNIFI_MCP_CONTROLLER_PASSWORD" => "controller-password",
            _ => return Err(std::env::VarError::NotPresent),
        };
        Ok(value.to_owned())
    }

    /// The complete environment plus whatever Protect variables a case names.
    fn environment_with<'a>(
        overrides: &'a [(&'static str, &'static str)],
    ) -> impl Fn(&'static str) -> Result<String, std::env::VarError> + 'a {
        move |variable| {
            for (name, value) in overrides {
                if *name == variable {
                    return Ok((*value).to_owned());
                }
            }
            complete_environment(variable)
        }
    }

    #[test]
    fn network_is_the_default_and_ignores_protect_credentials() {
        let configured = environment_with(&[("UNIFI_MCP_PROTECT_URL", "https://192.0.2.66")]);
        let settings = Settings::from_environment(&configured).expect("settings");
        assert!(matches!(settings.runtime, RuntimeSettings::Network(_)));
    }

    #[test]
    fn protect_surface_requires_its_own_console_coordinates() {
        let protect = environment_with(&[("UNIFI_MCP_SURFACE", "protect")]);
        assert!(matches!(
            Settings::from_environment(&protect),
            Err(SettingsError::Missing("UNIFI_MCP_PROTECT_URL"))
        ));

        let settings = Settings::from_environment(&complete_environment).expect("settings");
        assert!(matches!(settings.runtime, RuntimeSettings::Network(_)));
    }

    #[test]
    fn a_configured_protect_console_is_read_and_needs_its_key() {
        let configured = environment_with(&[
            ("UNIFI_MCP_SURFACE", "protect"),
            ("UNIFI_MCP_PROTECT_URL", "https://192.0.2.66"),
            ("UNIFI_MCP_PROTECT_API_KEY", "protect-api-key"),
        ]);
        let settings = Settings::from_environment(&configured).expect("settings");
        let RuntimeSettings::Protect(protect) = settings.runtime else {
            panic!("Protect runtime")
        };
        assert_eq!(protect.base_url.as_str(), "https://192.0.2.66/");
        assert_eq!(protect.name, "protect");
        assert_eq!(settings.identity.audience, "unifi-protect");
        assert!(
            settings
                .allowed_hosts
                .contains(&"unifi-protect-mcp".to_owned())
        );

        // A URL without a key is half-configured, and fails at load rather
        // than on the first camera question.
        let keyless = environment_with(&[
            ("UNIFI_MCP_SURFACE", "protect"),
            ("UNIFI_MCP_PROTECT_URL", "https://192.0.2.66"),
        ]);
        let error = Settings::from_environment(&keyless)
            .expect_err("a console without a key must fail closed");
        assert!(
            format!("{error}").contains("UNIFI_MCP_PROTECT_API_KEY"),
            "{error}"
        );
    }

    #[test]
    fn protect_event_credentials_are_optional_as_a_complete_pair() {
        let configured = environment_with(&[
            ("UNIFI_MCP_SURFACE", "protect"),
            ("UNIFI_MCP_PROTECT_URL", "https://192.0.2.66"),
            ("UNIFI_MCP_PROTECT_API_KEY", "protect-api-key"),
            ("UNIFI_MCP_PROTECT_USERNAME", "svc-protect-events"),
            ("UNIFI_MCP_PROTECT_PASSWORD", "protect-session-password"),
        ]);
        let settings = Settings::from_environment(&configured).expect("settings");
        let RuntimeSettings::Protect(protect) = settings.runtime else {
            panic!("Protect runtime")
        };
        let legacy = protect.legacy.expect("historical event credentials");
        assert_eq!(legacy.username, "svc-protect-events");
        assert_eq!(legacy.password.as_str(), "protect-session-password");

        let username_only = environment_with(&[
            ("UNIFI_MCP_SURFACE", "protect"),
            ("UNIFI_MCP_PROTECT_URL", "https://192.0.2.66"),
            ("UNIFI_MCP_PROTECT_API_KEY", "protect-api-key"),
            ("UNIFI_MCP_PROTECT_USERNAME", "svc-protect-events"),
        ]);
        assert!(matches!(
            Settings::from_environment(&username_only),
            Err(SettingsError::SecretEnvironment(
                "UNIFI_MCP_PROTECT_PASSWORD"
            ))
        ));

        let password_only = environment_with(&[
            ("UNIFI_MCP_SURFACE", "protect"),
            ("UNIFI_MCP_PROTECT_URL", "https://192.0.2.66"),
            ("UNIFI_MCP_PROTECT_API_KEY", "protect-api-key"),
            ("UNIFI_MCP_PROTECT_PASSWORD", "protect-session-password"),
        ]);
        assert!(matches!(
            Settings::from_environment(&password_only),
            Err(SettingsError::Missing("UNIFI_MCP_PROTECT_USERNAME"))
        ));
    }

    #[test]
    fn defaults_apply_over_the_required_ingress_settings() {
        let settings = Settings::from_environment(&complete_environment).expect("settings");
        assert_eq!(settings.host, "0.0.0.0");
        assert_eq!(settings.port, 8000);
        assert_eq!(settings.log_level, "info");
        assert!(settings.allowed_hosts.contains(&"unifi-mcp".to_owned()));
        assert!(settings.allowed_origins.is_empty());
        assert_eq!(settings.max_concurrent_requests, 32);
        assert_eq!(settings.identity.audience, "unifi");
    }

    #[test]
    fn unknown_surface_fails_closed() {
        let environment = |variable: &'static str| match variable {
            "UNIFI_MCP_SURFACE" => Ok("combined".to_owned()),
            other => complete_environment(other),
        };
        assert!(matches!(
            Settings::from_environment(&environment),
            Err(SettingsError::Invalid {
                variable: "UNIFI_MCP_SURFACE",
                ..
            })
        ));

        // A malformed value must never read as absence: routed through a
        // defaulting helper it would silently start the Network surface.
        let non_unicode = |variable: &'static str| match variable {
            "UNIFI_MCP_SURFACE" => Err(env::VarError::NotUnicode(
                std::os::unix::ffi::OsStringExt::from_vec(vec![0x66, 0xff]),
            )),
            other => complete_environment(other),
        };
        assert!(matches!(
            Settings::from_environment(&non_unicode),
            Err(SettingsError::Invalid {
                variable: "UNIFI_MCP_SURFACE",
                ..
            })
        ));
    }

    #[test]
    fn missing_bearer_fails_closed() {
        let environment = |variable: &'static str| match variable {
            "UNIFI_MCP_GATEWAY_BEARER_CURRENT" => Err(std::env::VarError::NotPresent),
            other => complete_environment(other),
        };
        assert!(matches!(
            Settings::from_environment(&environment),
            Err(SettingsError::SecretEnvironment(
                "UNIFI_MCP_GATEWAY_BEARER_CURRENT"
            ))
        ));
    }

    #[test]
    fn a_secret_that_survives_its_own_redaction_fails_closed_at_load() {
        // Scrubbing replaces such a value with a marker that still contains
        // it, so the survivor check withholds every result mentioning it.
        // Reaching that at runtime on `vouchers.create` would destroy codes
        // the controller had already issued and will not repeat.
        for value in ["redacted", "[redacted]", "edact"] {
            let environment = move |variable: &'static str| match variable {
                "UNIFI_MCP_CONTROLLER_PASSWORD" => Ok(value.to_owned()),
                other => complete_environment(other),
            };
            assert!(
                matches!(
                    Settings::from_environment(&environment),
                    Err(SettingsError::SecretEnvironment(
                        "UNIFI_MCP_CONTROLLER_PASSWORD"
                    ))
                ),
                "{value}"
            );
        }
    }

    #[test]
    fn padded_actor_fails_closed_at_settings_load() {
        let environment = |variable: &'static str| match variable {
            "UNIFI_MCP_IDENTITY_ACTOR" => Ok(" padded-gateway-actor ".to_owned()),
            other => complete_environment(other),
        };
        // The unnormalized anchor reaches validation as configured and the
        // load itself rejects it, before any verifier exists.
        assert!(matches!(
            Settings::from_environment(&environment),
            Err(SettingsError::Auth(
                AuthConfigError::InvalidIdentitySettings
            ))
        ));
    }

    #[test]
    fn controller_settings_apply_defaults_and_fail_closed() {
        let settings = Settings::from_environment(&complete_environment).expect("settings");
        let RuntimeSettings::Network(controller) = settings.runtime else {
            panic!("Network runtime")
        };
        assert_eq!(controller.name, "unifi");
        assert_eq!(controller.site, "default");
        assert!(matches!(controller.tls, unifi_api::TlsMode::SystemRoots));

        let missing_key = |variable: &'static str| match variable {
            "UNIFI_MCP_CONTROLLER_API_KEY" => Err(std::env::VarError::NotPresent),
            other => complete_environment(other),
        };
        assert!(matches!(
            Settings::from_environment(&missing_key),
            Err(SettingsError::SecretEnvironment(
                "UNIFI_MCP_CONTROLLER_API_KEY"
            ))
        ));

        // An unrecognized trust mode must not silently weaken validation.
        let bad_tls = |variable: &'static str| match variable {
            "UNIFI_MCP_CONTROLLER_TLS" => Ok("trust-everything".to_owned()),
            other => complete_environment(other),
        };
        assert!(matches!(
            Settings::from_environment(&bad_tls),
            Err(SettingsError::Invalid {
                variable: "UNIFI_MCP_CONTROLLER_TLS",
                ..
            })
        ));
    }

    #[test]
    fn malformed_controller_coordinates_fail_closed_at_load() {
        for url in [
            "ftp://controller",
            "https://controller/prefix",
            "https://controller/?probe=1",
            "https://controller/#fragment",
            "https://user:secret@controller",
            "http://192.0.2.1",
            "http://controller.lan",
        ] {
            let environment = move |variable: &'static str| match variable {
                "UNIFI_MCP_CONTROLLER_URL" => Ok(url.to_owned()),
                other => complete_environment(other),
            };
            assert!(
                matches!(
                    Settings::from_environment(&environment),
                    Err(SettingsError::Invalid {
                        variable: "UNIFI_MCP_CONTROLLER_URL",
                        ..
                    })
                ),
                "{url}"
            );
        }
        for site in [".", "..", "default/extra"] {
            let environment = move |variable: &'static str| match variable {
                "UNIFI_MCP_CONTROLLER_SITE" => Ok(site.to_owned()),
                other => complete_environment(other),
            };
            assert!(
                matches!(
                    Settings::from_environment(&environment),
                    Err(SettingsError::Invalid {
                        variable: "UNIFI_MCP_CONTROLLER_SITE",
                        ..
                    })
                ),
                "{site}"
            );
        }
        // A root path alone stays valid, and plaintext is acceptable only
        // when the hop never leaves the machine.
        for url in [
            "https://controller/",
            "http://127.0.0.1:8443",
            "http://localhost",
        ] {
            let environment = move |variable: &'static str| match variable {
                "UNIFI_MCP_CONTROLLER_URL" => Ok(url.to_owned()),
                other => complete_environment(other),
            };
            assert!(Settings::from_environment(&environment).is_ok(), "{url}");
        }
    }

    #[test]
    fn oversized_ca_bundles_fail_closed_on_the_bounded_read() {
        let path =
            std::env::temp_dir().join(format!("unifi-mcp-ca-test-{}.pem", std::process::id()));
        std::fs::write(&path, vec![b'-'; 80 * 1024]).expect("write CA fixture");
        let path_value = path.to_str().expect("utf-8 path").to_owned();
        let custom = move |variable: &'static str| match variable {
            "UNIFI_MCP_CONTROLLER_TLS" => Ok("custom-ca".to_owned()),
            "UNIFI_MCP_CONTROLLER_CA_FILE" => Ok(path_value.clone()),
            other => complete_environment(other),
        };
        let result = Settings::from_environment(&custom);
        std::fs::remove_file(&path).expect("remove CA fixture");
        assert!(matches!(
            result,
            Err(SettingsError::Invalid {
                variable: "UNIFI_MCP_CONTROLLER_CA_FILE",
                ..
            })
        ));
    }

    #[test]
    fn controller_debug_output_never_contains_credentials() {
        let settings = Settings::from_environment(&complete_environment).expect("settings");
        let RuntimeSettings::Network(controller) = settings.runtime else {
            panic!("Network runtime")
        };
        let rendered = format!("{controller:?}");
        assert!(!rendered.contains("controller-api-key"));
        assert!(!rendered.contains("controller-password"));
        assert!(!rendered.contains("svc-mcp"));
    }

    #[test]
    fn valid_settings_construct_a_verifier() {
        let settings = Settings::from_environment(&complete_environment).expect("settings");
        assert!(IdentityVerifier::new(settings.identity).is_ok());
    }

    #[test]
    fn environment_secrets_are_bounded_nonempty_and_preserve_values() {
        let valid = validate_secret("TEST_SECRET", " secret-value ".into()).expect("valid secret");
        assert_eq!(valid.as_str(), " secret-value ");
        for value in [String::new(), "x".repeat(MAXIMUM_SECRET_BYTES + 1)] {
            assert!(matches!(
                validate_secret("TEST_SECRET", value),
                Err(SettingsError::SecretEnvironment("TEST_SECRET"))
            ));
        }
    }

    #[test]
    fn bounded_numbers_accept_only_the_inclusive_contract() {
        assert_eq!(
            parse_number_value("TEST_NUMBER", None, 20_u64, 1, 120).expect("default"),
            20
        );
        for invalid in ["0", "121", "not-a-number"] {
            assert!(parse_number_value("TEST_NUMBER", Some(invalid), 20_u64, 1, 120).is_err());
        }
    }

    /// The console's certificate names neither the address it answers on nor
    /// anything resolvable, so `pinned` exists to trust it by digest. The
    /// digest must survive the form an operator will paste: `openssl` prints
    /// it with colons and in upper case.
    #[test]
    fn pinned_accepts_the_fingerprint_forms_an_operator_will_paste() {
        let colons = "08:46:EE:DF:8E:AB:46:BA:59:F2:F8:07:78:47:1E:76:\
                      6C:29:B5:C0:8A:85:37:FE:A6:C4:C0:5B:02:49:3B:85";
        for value in [colons.to_owned(), colons.replace(':', "").to_lowercase()] {
            let environment = |variable: &'static str| match variable {
                "UNIFI_MCP_CONTROLLER_TLS" => Ok("pinned".to_owned()),
                "UNIFI_MCP_CONTROLLER_CERT_SHA256" => Ok(value.clone()),
                _ => Err(env::VarError::NotPresent),
            };
            match controller_tls(&environment, &super::CONTROLLER_VARS).expect("pinned") {
                TlsMode::Pinned(pins) => {
                    assert_eq!(pins.len(), 1);
                    assert_eq!(pins[0][0], 0x08);
                }
                other => panic!("expected a pinned mode, got {other:?}"),
            }
        }
    }

    /// Replacing a console's certificate without an outage means trusting the
    /// old and new digests at once.
    #[test]
    fn pinned_accepts_more_than_one_fingerprint() {
        let both = format!("{}, {}", "a".repeat(64), "b".repeat(64));
        let environment = |variable: &'static str| match variable {
            "UNIFI_MCP_CONTROLLER_TLS" => Ok("pinned".to_owned()),
            "UNIFI_MCP_CONTROLLER_CERT_SHA256" => Ok(both.clone()),
            _ => Err(env::VarError::NotPresent),
        };
        match controller_tls(&environment, &super::CONTROLLER_VARS).expect("pinned") {
            TlsMode::Pinned(pins) => assert_eq!(pins.len(), 2),
            other => panic!("expected a pinned mode, got {other:?}"),
        }
    }

    /// Each of these would otherwise fail at the first handshake, long after
    /// the mistake was made and with nothing said about which value was wrong.
    #[test]
    fn a_pin_that_cannot_be_used_fails_at_load() {
        for (value, expected) in [
            (None, "missing required environment variable"),
            // An empty value is unset everywhere else in this module, and is
            // reported the same way here rather than as a special case.
            (Some(""), "missing required environment variable"),
            (Some("  ,  "), "names no fingerprint"),
            (Some("08:46:EE"), "found 6"),
            (Some(&*"z".repeat(64)), "is not a hexadecimal digit"),
        ] {
            let environment = |variable: &'static str| match variable {
                "UNIFI_MCP_CONTROLLER_TLS" => Ok("pinned".to_owned()),
                "UNIFI_MCP_CONTROLLER_CERT_SHA256" => {
                    value.map_or(Err(env::VarError::NotPresent), |v| Ok(v.to_owned()))
                }
                _ => Err(env::VarError::NotPresent),
            };
            let error = controller_tls(&environment, &super::CONTROLLER_VARS)
                .expect_err(value.unwrap_or("absent"))
                .to_string();
            assert!(error.contains(expected), "{value:?}: {error}");
        }
    }

    /// An unrecognized mode must not fall back to a weaker one.
    /// A pin cannot be checked against a connection that never handshakes, so
    /// the pair must fail at load rather than starting a server that claims
    /// verified transport and has none.
    #[test]
    fn pinned_with_a_plaintext_controller_url_fails_at_load() {
        let environment = |variable: &'static str| match variable {
            "UNIFI_MCP_CONTROLLER_URL" => Ok("http://127.0.0.1".to_owned()),
            "UNIFI_MCP_CONTROLLER_TLS" => Ok("pinned".to_owned()),
            "UNIFI_MCP_CONTROLLER_CERT_SHA256" => Ok("a".repeat(64)),
            "UNIFI_MCP_CONTROLLER_API_KEY" => Ok("key".to_owned()),
            "UNIFI_MCP_CONTROLLER_USERNAME" => Ok("svc".to_owned()),
            "UNIFI_MCP_CONTROLLER_PASSWORD" => Ok("password".to_owned()),
            _ => Err(env::VarError::NotPresent),
        };
        let error = super::controller_from_environment(&environment)
            .expect_err("pinned over plaintext")
            .to_string();
        assert!(error.contains("requires an https"), "{error}");
        assert!(error.contains("http"), "{error}");
    }

    /// The same pair over https is the configuration this mode is for.
    #[test]
    fn pinned_over_https_loads() {
        let environment = |variable: &'static str| match variable {
            "UNIFI_MCP_CONTROLLER_URL" => Ok("https://192.168.0.1".to_owned()),
            "UNIFI_MCP_CONTROLLER_TLS" => Ok("pinned".to_owned()),
            "UNIFI_MCP_CONTROLLER_CERT_SHA256" => Ok("a".repeat(64)),
            "UNIFI_MCP_CONTROLLER_API_KEY" => Ok("key".to_owned()),
            "UNIFI_MCP_CONTROLLER_USERNAME" => Ok("svc".to_owned()),
            "UNIFI_MCP_CONTROLLER_PASSWORD" => Ok("password".to_owned()),
            _ => Err(env::VarError::NotPresent),
        };
        let settings = super::controller_from_environment(&environment).expect("pinned https");
        assert!(matches!(settings.tls, TlsMode::Pinned(_)));
    }

    #[test]
    fn an_unknown_tls_mode_is_refused_and_names_what_is_accepted() {
        let environment = |variable: &'static str| match variable {
            "UNIFI_MCP_CONTROLLER_TLS" => Ok("pinned-maybe".to_owned()),
            _ => Err(env::VarError::NotPresent),
        };
        let error = controller_tls(&environment, &super::CONTROLLER_VARS)
            .expect_err("unknown mode")
            .to_string();
        assert!(error.contains("pinned"), "{error}");
        assert!(error.contains("accept-invalid"), "{error}");
    }

    #[test]
    fn comma_separated_allowlists_are_trimmed_lowercase_and_nonempty() {
        assert_eq!(
            parse_csv(" UniFi-MCP, ,LOCALHOST,unifi-mcp:8000 "),
            ["unifi-mcp", "localhost", "unifi-mcp:8000"]
        );
        assert!(parse_csv(" , ").is_empty());
    }
}
