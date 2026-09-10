//! Per-controller capability detection.
//!
//! An empty result and an unsupported API generation are different answers,
//! and conflating them corrupts downstream reads (a firewall audit that sees
//! an empty policy list on a classic-firewall console would report an open
//! network). Consumers detect on each request that depends on the answer and
//! branch on the result. Detection is deliberately not cached: this server is
//! stateless, and a console migrated between two calls would otherwise be
//! described by a remembered answer that no longer holds.

use crate::{ApiError, IntegrationClient, models::PageRequest};

/// Which firewall generation the console runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallGeneration {
    /// Network 9.x+ zone-based firewall; the Integration API serves zones
    /// and policies.
    ZoneBased,
    /// Classic rule-based firewall; zone endpoints answer HTTP 400 and the
    /// rules are only reachable through the legacy API.
    Classic,
}

/// What one controller supports, resolved at runtime.
#[derive(Debug, Clone)]
pub struct Capabilities {
    pub application_version: String,
    pub firewall: FirewallGeneration,
}

/// Detect the controller's capabilities using one site as the probe target.
///
/// # Errors
///
/// Returns an [`ApiError`] when the version read fails or the firewall probe
/// fails with anything other than the classic-firewall rejection.
pub async fn detect(client: &IntegrationClient, site_id: &str) -> Result<Capabilities, ApiError> {
    let info = client.info().await?;
    let probe = client
        .firewall_zones(
            site_id,
            PageRequest {
                offset: 0,
                limit: 1,
            },
        )
        .await;
    let firewall = match probe {
        Ok(_) => FirewallGeneration::ZoneBased,
        // The controller's documented classic-firewall rejection is HTTP 400
        // with a message naming the zone-based firewall. Any other 400 is a
        // request-level failure and must propagate, never classify.
        Err(ApiError::Status {
            status: 400,
            message,
        }) if message
            .as_str()
            .to_lowercase()
            .contains("zone based firewall") =>
        {
            FirewallGeneration::Classic
        }
        Err(error) => return Err(error),
    };
    Ok(Capabilities {
        application_version: info.application_version,
        firewall,
    })
}
