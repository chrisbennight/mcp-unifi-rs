use std::{path::PathBuf, time::Duration};

use anyhow::{Result, bail, ensure};
use url::Url;
use zeroize::Zeroizing;

/// Opt-in collector configuration. Tokens deliberately have no Debug rendering.
pub struct CollectionSettings {
    pub url: Url,
    pub org: String,
    pub bucket: String,
    pub token: Zeroizing<String>,
    pub directory: PathBuf,
    pub identity: String,
    pub cadence: Duration,
    pub delay_ms: u64,
    pub history_hours: u64,
    pub correction_hours: u64,
    pub intervals_per_cycle: usize,
}

impl CollectionSettings {
    /// # Errors
    /// Rejects invalid or unbounded settings before any destination request.
    pub fn from_env() -> Result<Option<Self>> {
        Self::read(|name| std::env::var(name).ok())
    }

    pub(super) fn read(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        match get("UNIFI_MCP_COLLECTION_ENABLED").as_deref() {
            None | Some("false") => return Ok(None),
            Some("true") => (),
            _ => bail!("UNIFI_MCP_COLLECTION_ENABLED must be true or false"),
        }
        let required = |name: &str| -> Result<String> {
            let value = get(name).ok_or_else(|| anyhow::anyhow!("missing {name}"))?;
            ensure!(
                !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control),
                "invalid {name}"
            );
            Ok(value)
        };
        let number = |name: &str, default: u64, min: u64, max: u64| -> Result<u64> {
            let value = get(name)
                .map_or(Ok(default), |v| v.parse::<u64>())
                .map_err(|_| anyhow::anyhow!("invalid {name}"))?;
            ensure!((min..=max).contains(&value), "out of range {name}");
            Ok(value)
        };
        let url = Url::parse(&required("UNIFI_MCP_COLLECTION_INFLUX_URL")?)
            .map_err(|_| anyhow::anyhow!("invalid collection URL"))?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "collection URL must be an HTTP(S) origin without credentials"
        );
        let identity = required("UNIFI_MCP_COLLECTION_ID")?;
        ensure!(
            identity.len() <= 128
                && identity
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "collection ID must contain only letters, digits, dot, dash, underscore"
        );
        let token = Zeroizing::new(required("UNIFI_MCP_COLLECTION_INFLUX_TOKEN")?);
        ensure!(
            token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid collection token"
        );
        let history_hours = number("UNIFI_MCP_COLLECTION_HISTORY_HOURS", 24, 1, 168)?;
        let correction_hours = number("UNIFI_MCP_COLLECTION_CORRECTION_HOURS", 3, 1, 168)?;
        ensure!(
            correction_hours <= history_hours,
            "correction window exceeds history window"
        );
        Ok(Some(Self {
            url,
            org: required("UNIFI_MCP_COLLECTION_INFLUX_ORG")?,
            bucket: required("UNIFI_MCP_COLLECTION_INFLUX_BUCKET")?,
            token,
            directory: PathBuf::from(required("UNIFI_MCP_COLLECTION_STATE_DIR")?),
            identity,
            cadence: Duration::from_secs(number(
                "UNIFI_MCP_COLLECTION_CADENCE_SECONDS",
                300,
                60,
                3600,
            )?),
            delay_ms: number("UNIFI_MCP_COLLECTION_DELAY_SECONDS", 600, 0, 86400)? * 1000,
            history_hours,
            correction_hours,
            intervals_per_cycle: usize::try_from(number(
                "UNIFI_MCP_COLLECTION_INTERVALS_PER_CYCLE",
                4,
                1,
                24,
            )?)?,
        }))
    }
}
