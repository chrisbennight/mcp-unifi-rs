//! Allowlisted response and request models for the controller APIs: the
//! official Integration API and, where a model notes it, the legacy API.
//!
//! Response models deliberately omit `deny_unknown_fields`: the controller
//! adds fields across releases and this crate exposes only the allowlisted
//! subset. Request models carry the parameter set the tool surface consumes;
//! optional upstream parameters are added with the tools that need them,
//! verified against the console-served API contract.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// One page of a paginated collection.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub offset: u64,
    pub limit: u64,
    /// Records in this page.
    pub count: u64,
    pub total_count: u64,
    pub data: Vec<T>,
}

/// Offset/limit coordinates for one page request.
#[derive(Debug, Clone, Copy)]
pub struct PageRequest {
    pub offset: u64,
    pub limit: u32,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 100,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationInfo {
    pub application_version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSummary {
    pub id: String,
    pub name: Option<String>,
    pub internal_reference: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSummary {
    pub id: String,
    pub name: Option<String>,
    pub model: Option<String>,
    pub mac_address: Option<String>,
    pub ip_address: Option<String>,
    pub state: Option<String>,
    pub firmware_version: Option<String>,
}

/// Full detail for one adopted device, including port and radio tables.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDetail {
    pub id: String,
    pub name: Option<String>,
    pub model: Option<String>,
    pub mac_address: Option<String>,
    pub ip_address: Option<String>,
    pub state: Option<String>,
    pub firmware_version: Option<String>,
    pub interfaces: Option<DeviceInterfaces>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInterfaces {
    #[serde(default)]
    pub ports: Vec<DevicePort>,
    #[serde(default)]
    pub radios: Vec<DeviceRadio>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePort {
    pub idx: Option<u32>,
    pub state: Option<String>,
    pub connector: Option<String>,
    pub speed_mbps: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRadio {
    pub wlan_standard: Option<String>,
    pub frequency_g_hz: Option<f64>,
    pub channel_width_m_hz: Option<u32>,
    pub channel: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStatistics {
    pub uptime_sec: Option<u64>,
    pub cpu_utilization_pct: Option<f64>,
    pub memory_utilization_pct: Option<f64>,
    pub uplink: Option<UplinkStatistics>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UplinkStatistics {
    pub tx_rate_bps: Option<u64>,
    pub rx_rate_bps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSummary {
    pub id: String,
    pub name: Option<String>,
    /// `WIRED`, `WIRELESS`, or a future controller-defined kind.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub mac_address: Option<String>,
    pub ip_address: Option<String>,
    pub connected_at: Option<String>,
    pub uplink_device_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Voucher {
    /// Optional because a batch whose row arrives without one must still
    /// reach the caller: the code it carries exists nowhere else.
    pub id: Option<String>,
    pub code: Option<String>,
    pub name: Option<String>,
    pub created_at: Option<String>,
}

/// Request envelope for creating hotspot vouchers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherCreate {
    pub name: String,
    /// Number of vouchers to generate.
    pub count: u32,
    pub time_limit_minutes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_guest_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_usage_limit_m_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherCreateResponse {
    pub vouchers: Vec<Voucher>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallZone {
    pub id: String,
    pub name: Option<String>,
}

/// Zone-based firewall policy with its match semantics: the ordering
/// index, protocol scope, and the source and destination endpoints that say
/// what the policy governs.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallPolicy {
    pub id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub action: Option<String>,
    /// Evaluation order.
    pub index: Option<u32>,
    /// Which IP protocols the policy matches. The policy record names this
    /// `ipProtocolScope`.
    pub ip_protocol_scope: Option<String>,
    pub source: Option<PolicyEndpoint>,
    pub destination: Option<PolicyEndpoint>,
}

/// One side of a zone-based policy match.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEndpoint {
    pub zone_id: Option<String>,
    pub port: Option<String>,
}

/// One subsystem row from the legacy `stat/health` read. Legacy API fields
/// are `snake_case` on the wire, so no rename applies.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthSubsystem {
    pub subsystem: Option<String>,
    pub status: Option<String>,
}

/// Actions the Integration API accepts on a device.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "action")]
pub enum DeviceAction {
    #[serde(rename = "RESTART")]
    Restart,
}

/// Actions the Integration API accepts on one switch port.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "action")]
pub enum PortAction {
    #[serde(rename = "POWER_CYCLE")]
    PowerCycle,
}

/// Actions the Integration API accepts on a client.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "action")]
pub enum ClientAction {
    #[serde(rename = "AUTHORIZE_GUEST_ACCESS")]
    AuthorizeGuestAccess,
}

#[cfg(test)]
mod tests {
    use super::{ClientAction, DeviceAction, DeviceSummary, Page, PortAction, VoucherCreate};

    #[test]
    fn response_projections_tolerate_unknown_upstream_fields() {
        let page: Page<DeviceSummary> = serde_json::from_value(serde_json::json!({
            "offset": 0,
            "limit": 25,
            "count": 1,
            "totalCount": 1,
            "futureEnvelopeField": true,
            "data": [{
                "id": "d1",
                "name": "Office Switch",
                "macAddress": "aa:bb:cc:dd:ee:ff",
                "futureDeviceField": {"nested": [1, 2]},
            }],
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(page.total_count, 1);
        assert_eq!(page.data[0].id, "d1");
        assert_eq!(
            page.data[0].mac_address.as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(page.data[0].model, None);
    }

    #[test]
    fn action_envelopes_serialize_to_the_exact_wire_shape() {
        assert_eq!(
            serde_json::to_value(DeviceAction::Restart).expect("serialize"),
            serde_json::json!({"action": "RESTART"})
        );
        assert_eq!(
            serde_json::to_value(PortAction::PowerCycle).expect("serialize"),
            serde_json::json!({"action": "POWER_CYCLE"})
        );
        assert_eq!(
            serde_json::to_value(ClientAction::AuthorizeGuestAccess).expect("serialize"),
            serde_json::json!({"action": "AUTHORIZE_GUEST_ACCESS"})
        );
    }

    #[test]
    fn voucher_creation_serializes_camel_case_and_omits_absent_options() {
        let minimal = VoucherCreate {
            name: "guests".to_owned(),
            count: 2,
            time_limit_minutes: 1440,
            authorized_guest_limit: None,
            data_usage_limit_m_bytes: None,
        };
        assert_eq!(
            serde_json::to_value(&minimal).expect("serialize"),
            serde_json::json!({"name": "guests", "count": 2, "timeLimitMinutes": 1440})
        );

        let full = VoucherCreate {
            authorized_guest_limit: Some(1),
            data_usage_limit_m_bytes: Some(1024),
            ..minimal
        };
        assert_eq!(
            serde_json::to_value(&full).expect("serialize"),
            serde_json::json!({
                "name": "guests",
                "count": 2,
                "timeLimitMinutes": 1440,
                "authorizedGuestLimit": 1,
                "dataUsageLimitMBytes": 1024,
            })
        );
    }
}

/// Port forward from the legacy `rest/portforward` read.
#[derive(Debug, Clone, Deserialize)]
pub struct PortForward {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub src: Option<String>,
    pub fwd: Option<String>,
    pub fwd_port: Option<String>,
    pub dst_port: Option<String>,
    pub proto: Option<String>,
}

/// A partial update to one port forward, sent to the legacy
/// `rest/portforward/{id}` route. Only the fields the caller set are
/// serialized, so an absent field is left alone rather than cleared. Field
/// names match [`PortForward`].
#[derive(Debug, Default, Clone, Serialize)]
pub struct PortForwardPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl PortForwardPatch {
    /// Whether the patch would send no fields, which would be a mutation
    /// that cannot change anything.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_none() && self.enabled.is_none()
    }
}

/// Traffic rule from the legacy `rest/trafficrule` read, with the match
/// fields that say what the rule governs.
#[derive(Debug, Clone, Deserialize)]
pub struct TrafficRule {
    #[serde(rename = "_id")]
    pub id: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub action: Option<String>,
    /// What the rule matches, such as `INTERNET`, `DOMAIN`, or `IP`.
    pub matching_target: Option<String>,
    pub network_id: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

/// Traffic route from the legacy `rest/trafficroute` read, with the match
/// and target fields that say what the route steers where.
#[derive(Debug, Clone, Deserialize)]
pub struct TrafficRoute {
    #[serde(rename = "_id")]
    pub id: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    /// What the route matches, such as `INTERNET`, `DOMAIN`, or `IP`.
    pub matching_target: Option<String>,
    pub network_id: Option<String>,
    /// Egress interface the matched traffic is steered onto.
    pub interface: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

/// Controller event from the bounded legacy `stat/event` read.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyEvent {
    pub key: Option<String>,
    pub msg: Option<String>,
    /// Epoch milliseconds.
    pub time: Option<u64>,
    pub subsystem: Option<String>,
    /// Client MAC address for client-scoped events.
    pub user: Option<String>,
}

/// One currently connected client from the legacy `stat/sta` read. Legacy
/// API fields are `snake_case` on the wire, so no rename applies. Every
/// field is controller-reported and untrusted.
#[derive(Debug, Clone, Deserialize)]
pub struct ActiveClient {
    pub mac: Option<String>,
    /// Operator-assigned alias.
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub oui: Option<String>,
    pub ip: Option<String>,
    pub essid: Option<String>,
    pub vlan: Option<u16>,
    pub network: Option<String>,
    pub ap_mac: Option<String>,
    pub channel: Option<u16>,
    pub radio: Option<String>,
    /// Signal strength in dBm; wireless only.
    pub signal: Option<i32>,
    pub rssi: Option<i32>,
    pub tx_bytes: Option<u64>,
    pub rx_bytes: Option<u64>,
    /// Seconds since association.
    pub uptime: Option<u64>,
    /// Epoch seconds.
    pub last_seen: Option<u64>,
    pub is_wired: Option<bool>,
    pub use_fixedip: Option<bool>,
    pub fixed_ip: Option<String>,
}

/// One configured network from the legacy `rest/networkconf` read. Legacy
/// API fields are `snake_case` on the wire, so no rename applies.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConf {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: Option<String>,
    /// `corporate`, `guest`, `wan`, `vlan-only`, or a future purpose.
    pub purpose: Option<String>,
    pub vlan: Option<u16>,
    pub ip_subnet: Option<String>,
    pub enabled: Option<bool>,
    pub dhcpd_enabled: Option<bool>,
    pub dhcpd_start: Option<String>,
    pub dhcpd_stop: Option<String>,
}

/// One configured wireless network from the legacy `rest/wlanconf` read.
/// `x_passphrase` is secret material: consumers must redact it by default
/// and never log the structure.
#[derive(Debug, Clone, Deserialize)]
pub struct WlanConf {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    /// Security mode such as `wpapsk` or `open`.
    pub security: Option<String>,
    pub x_passphrase: Option<String>,
    /// Backing network id, resolvable against `rest/networkconf`.
    pub networkconf_id: Option<String>,
    pub hide_ssid: Option<bool>,
}

/// A partial update to one wireless network, sent to the legacy
/// `rest/wlanconf/{id}` route. Only the fields the caller set are serialized,
/// so an absent field is "leave alone" rather than "clear".
///
/// The controller merges rather than replaces, but it also accepts a write
/// and then silently discards individual fields, so a caller must confirm
/// persistence by reading the resource back instead of trusting the
/// acknowledgement. Field names match [`WlanConf`], so a value read from a
/// controller can be written back under the same name.
#[derive(Default, Clone, Serialize)]
pub struct WlanPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Security mode such as `wpapsk` or `open`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// Secret material. Never logged, never echoed back to a caller.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "secret_field"
    )]
    pub x_passphrase: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_ssid: Option<bool>,
}

/// Write the secret's inner value onto the wire. The zeroizing container has
/// no serializer of its own, and the request body is the one place the value
/// legitimately travels.
#[expect(
    clippy::ref_option,
    reason = "serde's serialize_with hook is called with a reference to the field itself"
)]
fn secret_field<S: serde::Serializer>(
    value: &Option<Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(secret) => serializer.serialize_str(secret.as_str()),
        None => serializer.serialize_none(),
    }
}

/// The passphrase must never reach diagnostic output, so the formatter is
/// written by hand and reports only whether one was set.
impl std::fmt::Debug for WlanPatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WlanPatch")
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("security", &self.security)
            .field(
                "x_passphrase",
                &self.x_passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("hide_ssid", &self.hide_ssid)
            .finish()
    }
}

impl WlanPatch {
    /// Whether the patch would send no fields at all. An empty patch is a
    /// caller mistake: it would produce an upstream write that cannot change
    /// anything while still counting as a mutation.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.enabled.is_none()
            && self.security.is_none()
            && self.x_passphrase.is_none()
            && self.hide_ssid.is_none()
    }
}

/// Controller alarm from the bounded legacy `stat/alarm` read.
#[derive(Debug, Clone, Deserialize)]
pub struct Alarm {
    #[serde(rename = "_id")]
    pub id: String,
    pub key: Option<String>,
    pub msg: Option<String>,
    /// Epoch milliseconds.
    pub time: Option<u64>,
    pub archived: Option<bool>,
}

/// Per-application deep-packet-inspection counters from `stat/sitedpi`.
#[derive(Debug, Clone, Deserialize)]
pub struct DpiApplication {
    pub app: Option<u32>,
    pub cat: Option<u32>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

/// Neighboring access point from the legacy `stat/rogueap` read.
#[derive(Debug, Clone, Deserialize)]
pub struct RogueAp {
    pub bssid: Option<String>,
    pub essid: Option<String>,
    pub channel: Option<u32>,
    pub rssi: Option<i32>,
}

/// One hourly WAN throughput sample from the legacy site report.
#[derive(Debug, Clone, Deserialize)]
pub struct SiteWanSample {
    /// Epoch milliseconds for the hour bucket.
    pub time: Option<u64>,
    #[serde(rename = "wan-tx_bytes")]
    pub wan_tx_bytes: Option<f64>,
    #[serde(rename = "wan-rx_bytes")]
    pub wan_rx_bytes: Option<f64>,
}
