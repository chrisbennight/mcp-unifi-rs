//! Tool schemas, normalization, dispatch, and the shared response machinery.
//!
//! Every input rejects unknown fields, every result is bounded, and every
//! result carries the gateway trust labels declared in the registry. Compact
//! operational views can be expanded with requested controller fields.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rmcp::{
    ErrorData as McpError,
    model::{
        CallToolRequestParams, CallToolResult, ContentBlock, MetaObject, Tool, ToolAnnotations,
    },
};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::{Map, Number, Value, json};
use unifi_api::{
    ApiError, BoundedMessage, NetworkPolicyCollection, ProtectAvailability, RecordFingerprint,
    SiteInventoryKind, SwitchingDetailKind,
    capability::{self, FirewallGeneration},
    models::{
        ActiveClient, ClientDetail, DeviceStatistics, DeviceSummary, DpiAvailability,
        GuestAuthorization, GuestAuthorizationLimits, PageRequest, PortForward, PortForwardPatch,
        Voucher, VoucherCreate, VoucherDetails, WlanConf, WlanPatch,
    },
    protect::{
        ProtectArmRoute, ProtectBootstrap, ProtectCamera, ProtectCameraFeatureFlags,
        ProtectCameraSettingsPatch, ProtectDeviceActionRoute, ProtectDeviceFamily,
        ProtectEventContinuation, ProtectLedSettings, ProtectLocalCamera, ProtectLocalNvr,
        ProtectNvr, ProtectOsdSettings, ProtectPatrolState, ProtectPtzCommand,
        ProtectSmartDetectSettings, ProtectStreamQuality, ProtectStreamUrls,
        ProtectTalkbackSession, ProtectUserFamily,
    },
};
use zeroize::Zeroizing;

use crate::{
    IdentityPrincipal,
    handler::UnifiMcp,
    mutation::{self, FieldOutcome, PlannedChange},
    registry::{ToolBehavior, ToolKind, ToolSpec},
};

mod activity;
mod firewall_policy_request;
mod legacy_configuration;
mod legacy_wlan_request;
mod network_configuration;
mod network_request;
mod network_source;
use network_source::{NetworkSourceReadInput, NetworkSourceReadOutput};
mod protect_updates;
use legacy_configuration::{
    LegacyConfigurationListInput, LegacyConfigurationResult, LegacyConfigurationStatusInput,
    PortForwardConfigureInput, WlanGroupsListInput, WlansConfigureInput,
};
use protect_updates::{ProtectUpdatesInput, ProtectUpdatesOutput};
mod wifi_request;
use network_configuration::{
    ConfigurationResult, NetworksConfigureInput, NetworksListInput, NetworksStatusInput,
    WifiBroadcastsConfigureInput,
};
mod system_log;
mod traffic;
use firewall_policy_request::FirewallPolicyRequest;
use system_log::{event_row, log_window};
use traffic::{
    ClientCounterCoverage, CounterSemantics, CoverageStatus, TrafficCoverage, client_counters,
};
use unifi_api::system_log::{SystemLogQuery, SystemLogSeverity};

const ACTION_METADATA_KEY: &str = "io.modelcontextprotocol/action-metadata";
const TRUST_ANNOTATIONS_KEY: &str = "io.modelcontextprotocol/trust-annotations";

/// Formatting target for moving complete large fields to labeled MCP content.
/// Results remain available when their structured values exceed this target.
pub(crate) const STRUCTURED_CONTENT_TARGET_BYTES: usize = 48 * 1024;
const MAXIMUM_POLICY_REQUEST_BYTES: usize = 1024 * 1024;
const MAXIMUM_ANIMATION_ASSET_BYTES: usize = 3 * 1024 * 1024;

/// Documented controller limits for Integration collection requests.
const MAXIMUM_INTEGRATION_LIMIT: u32 = 200;
const MAXIMUM_VOUCHER_LIMIT: u32 = 1000;
const DEFAULT_SEARCH_LIMIT: usize = 50;

fn integration_limit(requested: usize) -> u32 {
    u32::try_from(requested.min(MAXIMUM_INTEGRATION_LIMIT as usize))
        .expect("the native integration limit fits u32")
}

fn voucher_limit(requested: usize) -> u32 {
    u32::try_from(requested.min(MAXIMUM_VOUCHER_LIMIT as usize))
        .expect("the native voucher limit fits u32")
}

fn protect_limit(requested: usize) -> u32 {
    u32::try_from(requested.min(unifi_api::MAXIMUM_PROTECT_EVENT_PAGE_LIMIT as usize))
        .expect("the Protect event read budget fits u32")
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PageCounts {
    requested_limit: usize,
    effective_limit: u64,
    returned: usize,
}
/// Ceiling on client rows scanned to resolve one hardware address to the
/// controller's own client id.
const CLIENT_SCAN_CEILING: u64 = 1000;
/// Longest accepted filter string.
const MAXIMUM_QUERY_LENGTH: usize = 128;
/// Camera names are returned at this character ceiling and must remain usable
/// as selectors. Four bytes per scalar keeps the UTF-8 representation bounded.
const MAXIMUM_CAMERA_SELECTOR_CHARACTERS: usize = EVENT_MESSAGE_CEILING;
const MAXIMUM_CAMERA_SELECTOR_BYTES: usize = MAXIMUM_CAMERA_SELECTOR_CHARACTERS * 4;
/// Detection labels returned for each camera and label family.
const CAMERA_FEATURE_LABEL_CEILING: usize = 32;
/// Storage distribution rows returned for each dimension of the recorder.
const STORAGE_DISTRIBUTION_CEILING: usize = 32;
/// Camera references included in the recorder's active-recording summary.
const IDLE_CAMERA_LIST_CEILING: usize = 100;
/// Ceiling on device inventory rows scanned per call.
const DEVICE_INVENTORY_CEILING: u64 = 1000;
/// System-log rows scanned when building one client's recent events.
const EVENT_SCAN_LIMIT: usize = 200;
/// Recent events returned for one client.
const CONTEXT_EVENT_LIMIT: usize = 20;
/// Ceiling on one event message's characters in output.
const EVENT_MESSAGE_CEILING: usize = 256;
/// Ceilings on summarized interface tables.
const PORT_TABLE_CEILING: usize = 128;
const RADIO_TABLE_CEILING: usize = 16;

/// Wireless diagnosis bounds.
const DEFAULT_WEAK_SIGNAL_DBM: i32 = -75;
const WEAK_CLIENT_CEILING: usize = 50;
const ROGUE_AP_CEILING: usize = 100;
const AP_DETAIL_CEILING: usize = 16;

/// Event search bounds.
const DEFAULT_EVENT_WINDOW_HOURS: u32 = 24;
const EVENT_FETCH_LIMIT: usize = 1000;

/// Statistics bounds.
const DEFAULT_WAN_REPORT_HOURS: u32 = 24;
const DEFAULT_TOP_APPLICATIONS: usize = 10;

// ---------------------------------------------------------------------------
// Inputs and outputs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

/// One subsystem row of controller-reported health.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SubsystemHealth {
    /// Subsystem name as reported by the controller, such as `wan` or `wlan`.
    subsystem: String,
    /// Controller-reported status word, such as `ok` or `warning`.
    status: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct NetworkOverviewOutput {
    /// Operator-chosen controller name from server configuration.
    controller: String,
    /// `UniFi` Network application version.
    application_version: String,
    /// Controller-reported health per subsystem; unnamed rows are dropped.
    subsystems: Vec<SubsystemHealth>,
    /// System-log totals for the last 24 hours, not outstanding alarms.
    recent_events: RecentEventCounts,
    /// Total adopted devices on the site.
    devices: u64,
    /// Total known clients on the site.
    clients: u64,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RecentEventCounts {
    /// Beginning of the counting window, in epoch milliseconds.
    window_start: u64,
    /// End of the counting window, in epoch milliseconds.
    window_end: u64,
    /// Controller-reported total across all severities.
    total: u64,
    /// Controller-reported total with `HIGH` or `VERY_HIGH` severity.
    high_severity: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
enum DetailLevel {
    #[default]
    Concise,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ConnectionKind {
    Wired,
    Wireless,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClientsSearchInput {
    /// Case-insensitive substring matched against name, hostname, MAC, or IP.
    query: Option<String>,
    /// Exact wireless network name, case-insensitive.
    ssid: Option<String>,
    /// Exact VLAN id.
    vlan: Option<u16>,
    /// Restrict to wired or wireless clients.
    connection: Option<ConnectionKind>,
    /// Zero-based offset into the filtered, name-sorted result.
    #[serde(default)]
    offset: usize,
    /// Positive rows per page.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
    /// Concise identity-and-connection rows, or full association detail.
    #[serde(default)]
    detail: DetailLevel,
}

fn default_search_limit() -> usize {
    DEFAULT_SEARCH_LIMIT
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClientSelectorInput {
    /// MAC address, exact name, or exact hostname of one connected client.
    client: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DevicesSearchInput {
    /// Case-insensitive substring matched against name, model, MAC, or IP.
    query: Option<String>,
    /// Exact device state word, case-insensitive, such as `ONLINE`.
    state: Option<String>,
    /// Zero-based offset into the filtered, name-sorted result.
    #[serde(default)]
    offset: usize,
    /// Positive rows per page.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PendingDevicesListInput {
    #[serde(default)]
    offset: u64,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
    filter: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct PendingDevicesListOutput {
    page_counts: PageCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    devices: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    devices_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata_in_content: Option<bool>,
    offset: u64,
    limit: u64,
    count: u64,
    total_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DevicesAdoptInput {
    mac_address: String,
    ignore_device_limit: bool,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DevicesAdoptOutput {
    mac_address: String,
    ignore_device_limit: bool,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DevicesRemoveInput {
    device_id: String,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DevicesRemoveOutput {
    device_id: String,
    /// Online devices are reset to factory defaults by the controller.
    warning: &'static str,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_absent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeviceSelectorInput {
    /// Device id, MAC address, or exact name of one adopted device.
    device: String,
}

/// One client row; association fields populate only at `full` detail.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ClientRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    counter_coverage: Option<ClientCounterCoverage>,
    /// Operator alias when set, otherwise the reported hostname.
    name: Option<String>,
    hostname: Option<String>,
    mac: Option<String>,
    ip: Option<String>,
    /// `wired`, `wireless`, or `unknown` when the controller omits the type.
    connection: &'static str,
    ssid: Option<String>,
    vlan: Option<u16>,
    /// Resolved uplink access point name; wireless only.
    #[serde(skip_serializing_if = "Option::is_none")]
    ap_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oui: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ClientsSearchOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    counter_semantics: Option<CounterSemantics>,
    clients: Vec<ClientRow>,
    /// Total rows matching the filters before pagination.
    total_matches: u64,
    /// Offset of the next page when more rows remain.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
    /// Present when the access-point name join was built from a truncated
    /// device scan: an absent `apName` may exist beyond the scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    ap_lookup_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ClientEvent {
    /// Epoch milliseconds.
    time: Option<u64>,
    key: Option<String>,
    /// Bounded controller-reported message text; untrusted.
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ClientContextOutput {
    counter_coverage: ClientCounterCoverage,
    counter_semantics: CounterSemantics,
    name: Option<String>,
    hostname: Option<String>,
    mac: Option<String>,
    oui: Option<String>,
    /// `wired`, `wireless`, or `unknown` when the controller omits the type.
    connection: &'static str,
    ssid: Option<String>,
    vlan: Option<u16>,
    network: Option<String>,
    ap_name: Option<String>,
    ap_mac: Option<String>,
    channel: Option<u16>,
    radio: Option<String>,
    signal_dbm: Option<i32>,
    rssi: Option<i32>,
    uptime_seconds: Option<u64>,
    /// Epoch seconds.
    last_seen: Option<u64>,
    ip: Option<String>,
    use_fixed_ip: Option<bool>,
    fixed_ip: Option<String>,
    tx_bytes: Option<u64>,
    rx_bytes: Option<u64>,
    /// Up to 20 events for this client from a 200-row site-wide system-log
    /// scan over the last 24 hours, newest first.
    recent_events: Vec<ClientEvent>,
    /// Present when the controller reports additional site-wide rows or
    /// more than 20 events matched this client.
    #[serde(skip_serializing_if = "Option::is_none")]
    recent_events_truncated: Option<bool>,
    /// Present when the access-point name join was built from a truncated
    /// device scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    ap_lookup_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct DeviceRow {
    id: String,
    name: Option<String>,
    model: Option<String>,
    mac: Option<String>,
    ip: Option<String>,
    state: Option<String>,
    firmware_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct DevicesSearchOutput {
    devices: Vec<DeviceRow>,
    /// Total rows matching the filters before pagination. Scoped to the
    /// scanned prefix when `inventoryTruncated` is set.
    total_matches: u64,
    /// Offset of the next page when more rows remain.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
    /// Present when the bounded inventory scan cut the catalog short; the
    /// result covers only the scanned prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct DeviceStatisticsView {
    uptime_seconds: Option<u64>,
    cpu_utilization_pct: Option<f64>,
    memory_utilization_pct: Option<f64>,
    uplink_tx_rate_bps: Option<u64>,
    uplink_rx_rate_bps: Option<u64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct DevicePortRow {
    idx: Option<u32>,
    state: Option<String>,
    connector: Option<String>,
    speed_mbps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct DeviceRadioRow {
    wlan_standard: Option<String>,
    frequency_ghz: Option<f64>,
    channel: Option<u32>,
    channel_width_mhz: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct DeviceStatusOutput {
    id: String,
    name: Option<String>,
    model: Option<String>,
    mac: Option<String>,
    ip: Option<String>,
    state: Option<String>,
    firmware_version: Option<String>,
    /// Absent when the statistics read fails, such as for an offline
    /// device; identity and state above remain authoritative.
    #[serde(skip_serializing_if = "Option::is_none")]
    statistics: Option<DeviceStatisticsView>,
    /// Controller error from the optional statistics read, if that read failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    statistics_error: Option<String>,
    /// Summarized port table, bounded.
    ports: Vec<DevicePortRow>,
    /// Present when the port table was cut at its ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    ports_truncated: Option<bool>,
    /// Summarized radio table, bounded.
    radios: Vec<DeviceRadioRow>,
    /// Present when the radio table was cut at its ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    radios_truncated: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CamerasSearchInput {
    /// Case-insensitive substring matched against camera id or name.
    query: Option<String>,
    /// Case-insensitive substring matched against hardware model. Refused
    /// until the optional local inventory source supplies that information.
    model: Option<String>,
    /// Exact functional class. Refused until class information is available
    /// from the optional local inventory source.
    #[serde(rename = "class")]
    class_filter: Option<String>,
    /// Exact reported state, case-insensitive, as the console words it.
    state: Option<String>,
    /// Zero-based offset into the filtered, name-sorted result.
    #[serde(default)]
    offset: usize,
    /// Positive rows per page.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraSelectorInput {
    /// Camera id, exact reported name, or display name from `cameras.search`.
    camera: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraStatusInput {
    /// Camera id, exact reported name, or display name from `cameras.search`.
    camera: String,
    /// Include the complete local bootstrap camera record.
    #[serde(default)]
    include_details: bool,
    /// Top-level fields to include from the local bootstrap camera record.
    /// Use this to keep the response small when only a few fields are needed.
    detail_fields: Option<Vec<String>>,
}

/// Documented non-camera Protect resources served through fixed API paths.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum ProtectDeviceKind {
    Light,
    Sensor,
    Chime,
    Siren,
    Fob,
    Relay,
    Speaker,
    Bridge,
    LinkStation,
    AlarmHub,
}

impl From<ProtectDeviceKind> for ProtectDeviceFamily {
    fn from(kind: ProtectDeviceKind) -> Self {
        match kind {
            ProtectDeviceKind::Light => Self::Light,
            ProtectDeviceKind::Sensor => Self::Sensor,
            ProtectDeviceKind::Chime => Self::Chime,
            ProtectDeviceKind::Siren => Self::Siren,
            ProtectDeviceKind::Fob => Self::Fob,
            ProtectDeviceKind::Relay => Self::Relay,
            ProtectDeviceKind::Speaker => Self::Speaker,
            ProtectDeviceKind::Bridge => Self::Bridge,
            ProtectDeviceKind::LinkStation => Self::LinkStation,
            ProtectDeviceKind::AlarmHub => Self::AlarmHub,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectDevicesListInput {
    kind: ProtectDeviceKind,
    /// Zero-based offset into the controller's inventory for this family.
    #[serde(default)]
    offset: usize,
    /// Positive records per page.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectDevicesListOutput {
    kind: ProtectDeviceKind,
    devices: Vec<Value>,
    total_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectDevicesStatusInput {
    kind: ProtectDeviceKind,
    device_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectDevicesStatusOutput {
    kind: ProtectDeviceKind,
    device: Value,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum RelayOutputState {
    On,
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ProtectDeviceAction {
    SirenPlay {
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<u8>,
    },
    SirenStop,
    SirenTestSound {
        #[serde(skip_serializing_if = "Option::is_none")]
        volume: Option<u8>,
    },
    RelayActivate {
        output_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<RelayOutputState>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pulse_duration: Option<u64>,
    },
    SpeakerTestSound {
        #[serde(skip_serializing_if = "Option::is_none")]
        volume: Option<u8>,
    },
    AlarmHubTrigger {
        output_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        enable: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        delay: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<u64>,
    },
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectDevicesActionInput {
    device_id: String,
    action: ProtectDeviceAction,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectDevicesActionOutput {
    device_id: String,
    action: ProtectDeviceAction,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectLightModeSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<ProtectLightMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enable_at: Option<ProtectLightEnableAt>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ProtectLightMode {
    Always,
    Motion,
    Off,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ProtectLightEnableAt {
    Fulltime,
    Dark,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectLightDeviceSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    is_indicator_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pir_duration: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pir_sensitivity: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    led_level: Option<Number>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectSirenLedSettings {
    is_enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectRelayLedSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
enum ProtectNullableNumber {
    Number(Number),
    Clear,
}

fn deserialize_present_nullable_number<'de, D>(
    deserializer: D,
) -> Result<Option<ProtectNullableNumber>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Number>::deserialize(deserializer).map(|value| {
        Some(match value {
            Some(number) => ProtectNullableNumber::Number(number),
            None => ProtectNullableNumber::Clear,
        })
    })
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
enum ProtectNullableIds {
    Ids(Vec<String>),
    Clear,
}

fn deserialize_present_nullable_ids<'de, D>(
    deserializer: D,
) -> Result<Option<ProtectNullableIds>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<String>>::deserialize(deserializer).map(|value| {
        Some(match value {
            Some(ids) => ProtectNullableIds::Ids(ids),
            None => ProtectNullableIds::Clear,
        })
    })
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectSensorThresholdSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    is_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    margin: Option<Number>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_nullable_number",
        skip_serializing_if = "Option::is_none"
    )]
    low_threshold: Option<ProtectNullableNumber>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_nullable_number",
        skip_serializing_if = "Option::is_none"
    )]
    high_threshold: Option<ProtectNullableNumber>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectSensorMotionSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    is_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitivity: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitivity_when_armed: Option<Number>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectSensorAlarmSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ProtectSensorScheduleMode {
    Always,
    WhenArmed,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectChimeRingSettings {
    camera_id: String,
    repeat_times: Number,
    ringtone_id: String,
    volume: Number,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ProtectDeviceSettingsChanges {
    Light {
        name: Option<String>,
        is_light_force_enabled: Option<bool>,
        light_mode_settings: Option<ProtectLightModeSettings>,
        light_device_settings: Option<ProtectLightDeviceSettings>,
    },
    Sensor {
        name: Option<String>,
        light_settings: Option<Box<ProtectSensorThresholdSettings>>,
        humidity_settings: Option<Box<ProtectSensorThresholdSettings>>,
        temperature_settings: Option<Box<ProtectSensorThresholdSettings>>,
        motion_settings: Option<Box<ProtectSensorMotionSettings>>,
        glass_break_settings: Option<Box<ProtectSensorMotionSettings>>,
        schedule_mode: Option<ProtectSensorScheduleMode>,
        #[serde(
            default,
            deserialize_with = "deserialize_present_nullable_ids",
            skip_serializing_if = "Option::is_none"
        )]
        arm_profile_ids: Option<ProtectNullableIds>,
        has_custom_sensitivity_when_armed: Option<bool>,
        alarm_settings: Option<ProtectSensorAlarmSettings>,
    },
    Chime {
        name: Option<String>,
        camera_ids: Option<Vec<String>>,
        ring_settings: Option<Vec<ProtectChimeRingSettings>>,
    },
    Siren {
        name: Option<String>,
        volume: Option<u8>,
        led_settings: Option<ProtectSirenLedSettings>,
    },
    Relay {
        name: Option<String>,
        led_settings: Option<ProtectRelayLedSettings>,
    },
    Speaker {
        name: Option<String>,
        volume: Option<u8>,
        mic_volume: Option<u8>,
        is_mic_enabled: Option<bool>,
    },
    Fob {
        name: Option<String>,
    },
    Bridge {
        name: Option<String>,
    },
    LinkStation {
        name: Option<String>,
    },
    AlarmHub {
        name: Option<String>,
    },
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectDevicesSettingsUpdateInput {
    device_id: String,
    changes: ProtectDeviceSettingsChanges,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectDevicesSettingsUpdateOutput {
    kind: ProtectDeviceKind,
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_in_content: Option<bool>,
    before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_in_content: Option<bool>,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectArmProfilesListInput {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectArmProfilesListOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles_in_content: Option<bool>,
    total_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum ProtectArmConfigureOperation {
    Create,
    Update,
    Delete,
    Select,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectArmSchedule {
    start: String,
    end: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectArmProfileChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    automations: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedules: Option<Vec<ProtectArmSchedule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_everything: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation_delay: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectArmProfilesConfigureInput {
    operation: ProtectArmConfigureOperation,
    profile_id: Option<String>,
    changes: Option<ProtectArmProfileChanges>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum ProtectAlarmAction {
    Enable,
    Disable,
    Webhook,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectAlarmsActionInput {
    action: ProtectAlarmAction,
    trigger_id: Option<String>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectArmOperationOutput {
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_in_content: Option<bool>,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

/// Protect users and `UniFi` Identity users are separate documented resources.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum ProtectUserKind {
    User,
    IdentityUser,
}

impl From<ProtectUserKind> for ProtectUserFamily {
    fn from(kind: ProtectUserKind) -> Self {
        match kind {
            ProtectUserKind::User => Self::User,
            ProtectUserKind::IdentityUser => Self::IdentityUser,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectUsersListInput {
    kind: ProtectUserKind,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectUsersListOutput {
    kind: ProtectUserKind,
    users: Vec<Value>,
    total_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectUsersStatusInput {
    kind: ProtectUserKind,
    user_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectUsersStatusOutput {
    kind: ProtectUserKind,
    user: Value,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum PosTransactionType {
    Sale,
    Refund,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PosLineItem {
    title: String,
    quantity: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PosLocation {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PosTransaction {
    #[serde(rename = "type")]
    transaction_type: PosTransactionType,
    external_id: String,
    amount: Number,
    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_items: Option<Vec<PosLineItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<PosLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraPosTransactionInput {
    camera_id: String,
    transaction: PosTransaction,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraPosTransactionOutput {
    camera_id: String,
    effect: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction: Option<PosTransaction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_in_content: Option<bool>,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_in_content: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectAssetsListInput {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectAssetsListOutput {
    file_type: &'static str,
    assets: Vec<Value>,
    total_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
enum ProtectAssetMimeType {
    #[serde(rename = "image/gif")]
    ImageGif,
    #[serde(rename = "image/jpeg")]
    ImageJpeg,
    #[serde(rename = "image/png")]
    ImagePng,
    #[serde(rename = "audio/mpeg")]
    AudioMpeg,
    #[serde(rename = "audio/mp4")]
    AudioMp4,
    #[serde(rename = "audio/wave")]
    AudioWave,
    #[serde(rename = "audio/x-caf")]
    AudioCaf,
}

impl ProtectAssetMimeType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ImageGif => "image/gif",
            Self::ImageJpeg => "image/jpeg",
            Self::ImagePng => "image/png",
            Self::AudioMpeg => "audio/mpeg",
            Self::AudioMp4 => "audio/mp4",
            Self::AudioWave => "audio/wave",
            Self::AudioCaf => "audio/x-caf",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectAssetUploadInput {
    file_name: String,
    mime_type: ProtectAssetMimeType,
    content_base64: String,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectAssetUploadOutput {
    file_type: &'static str,
    file_name: String,
    mime_type: ProtectAssetMimeType,
    byte_size: usize,
    submitted: bool,
    accepted: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_in_content: Option<bool>,
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectViewsListInput {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectViewersListOutput {
    viewers: Vec<Value>,
    total_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectViewerStatusInput {
    viewer_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectViewerStatusOutput {
    viewer: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectViewerSettingsChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    liveview: Option<LiveviewAssignment>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(untagged)]
enum LiveviewAssignment {
    Id(String),
    Clear,
}

fn deserialize_present_nullable<'de, D>(
    deserializer: D,
) -> Result<Option<LiveviewAssignment>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| {
        Some(match value {
            Some(id) => LiveviewAssignment::Id(id),
            None => LiveviewAssignment::Clear,
        })
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectViewerSettingsUpdateInput {
    viewer_id: String,
    changes: ProtectViewerSettingsChanges,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectViewerSettingsUpdateOutput {
    viewer_id: String,
    requested: ProtectViewerSettingsChanges,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectLiveviewsListOutput {
    liveviews: Vec<Value>,
    total_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectLiveviewStatusInput {
    liveview_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectLiveviewStatusOutput {
    liveview: Value,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum LiveviewOperation {
    Create,
    Update,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum LiveviewCycleMode {
    Motion,
    Time,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LiveviewSlot {
    cameras: Vec<String>,
    cycle_mode: LiveviewCycleMode,
    cycle_interval: Number,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LiveviewChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_default: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_global: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    layout: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slots: Option<Vec<LiveviewSlot>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectLiveviewsConfigureInput {
    operation: LiveviewOperation,
    liveview_id: Option<String>,
    changes: LiveviewChanges,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectLiveviewsConfigureOutput {
    operation: LiveviewOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    liveview_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<LiveviewChanges>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_in_content: Option<bool>,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectOverviewInput {
    /// Select the summary (default), complete application info, or complete recorder record.
    #[serde(default)]
    view: ProtectOverviewView,
    /// Top-level fields from the local bootstrap response to include.
    /// Requested fields remain complete, including large values.
    detail_fields: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum ProtectOverviewView {
    #[default]
    Summary,
    ApplicationInfo,
    Recorder,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(untagged)]
enum ProtectOverviewResult {
    Summary(Box<ProtectOverviewOutput>),
    Record(RecordOutput),
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraSettingsChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mic_volume: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    video_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hdr_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    osd_settings: Option<CameraOsdChanges>,
    #[serde(skip_serializing_if = "Option::is_none")]
    led_settings: Option<CameraLedChanges>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lcd_message: Option<CameraLcdMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    smart_detect_settings: Option<CameraSmartDetectChanges>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
enum CameraResetAt {
    Timestamp(Number),
    Forever,
}

fn deserialize_camera_reset_at<'de, D>(deserializer: D) -> Result<Option<CameraResetAt>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Number>::deserialize(deserializer).map(|value| {
        Some(match value {
            Some(timestamp) => CameraResetAt::Timestamp(timestamp),
            None => CameraResetAt::Forever,
        })
    })
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum CameraLcdMessage {
    DoNotDisturb {
        #[serde(
            default,
            rename = "resetAt",
            deserialize_with = "deserialize_camera_reset_at",
            skip_serializing_if = "Option::is_none"
        )]
        reset_at: Option<CameraResetAt>,
    },
    LeavePackageAtDoor {
        #[serde(
            default,
            rename = "resetAt",
            deserialize_with = "deserialize_camera_reset_at",
            skip_serializing_if = "Option::is_none"
        )]
        reset_at: Option<CameraResetAt>,
    },
    CustomMessage {
        text: String,
        #[serde(
            default,
            rename = "resetAt",
            deserialize_with = "deserialize_camera_reset_at",
            skip_serializing_if = "Option::is_none"
        )]
        reset_at: Option<CameraResetAt>,
    },
    Image {
        text: String,
        #[serde(
            default,
            rename = "resetAt",
            deserialize_with = "deserialize_camera_reset_at",
            skip_serializing_if = "Option::is_none"
        )]
        reset_at: Option<CameraResetAt>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraOsdChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    is_name_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_date_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_logo_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_debug_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overlay_location: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraLedChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    is_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    welcome_led: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flood_led: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraSmartDetectChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    object_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio_types: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraSettingsUpdateInput {
    camera: String,
    changes: CameraSettingsChanges,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraSettingsReadOutput {
    camera_id: String,
    camera: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    camera_in_content: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraSettingsOutput {
    camera_id: String,
    applied: bool,
    requested: Option<CameraSettingsChanges>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraSettingsState {
    camera_id: String,
    name: Option<String>,
    mic_volume: Option<u8>,
    video_mode: Option<String>,
    hdr_type: Option<String>,
    osd_settings: Option<CameraOsdChanges>,
    led_settings: Option<CameraLedChanges>,
    lcd_message: Option<Value>,
    smart_detect_settings: Option<CameraSmartDetectChanges>,
}

impl From<ProtectCamera> for CameraSettingsState {
    fn from(camera: ProtectCamera) -> Self {
        Self {
            camera_id: camera.id,
            name: camera.name.map(bounded_text),
            mic_volume: camera.mic_volume,
            video_mode: camera.video_mode,
            hdr_type: camera.hdr_type,
            osd_settings: camera.osd_settings.map(|settings| CameraOsdChanges {
                is_name_enabled: settings.is_name_enabled,
                is_date_enabled: settings.is_date_enabled,
                is_logo_enabled: settings.is_logo_enabled,
                is_debug_enabled: settings.is_debug_enabled,
                overlay_location: settings.overlay_location,
            }),
            led_settings: camera.led_settings.map(|settings| CameraLedChanges {
                is_enabled: settings.is_enabled,
                welcome_led: settings.welcome_led,
                flood_led: settings.flood_led,
            }),
            lcd_message: camera.lcd_message,
            smart_detect_settings: camera.smart_detect_settings.map(|settings| {
                CameraSmartDetectChanges {
                    object_types: settings.object_types,
                    audio_types: settings.audio_types,
                }
            }),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraSnapshotInput {
    /// Camera id or exact reported name from `cameras.search`.
    camera: String,
    /// Use `package` for a doorbell's package camera.
    #[serde(default)]
    channel: SnapshotChannel,
    /// Request a snapshot at 1080p or higher when available.
    #[serde(default)]
    high_quality: bool,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum SnapshotChannel {
    #[default]
    Main,
    Package,
}

impl SnapshotChannel {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Package => "package",
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraSnapshotOutput {
    camera_id: String,
    channel: String,
    mime_type: &'static str,
    byte_size: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectEventThumbnailInput {
    /// Event id returned by `protect.events`.
    event: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ProtectEventThumbnailOutput {
    event_id: String,
    mime_type: &'static str,
    byte_size: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum CameraPtzAction {
    GotoPreset,
    StartPatrol,
    StopPatrol,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraPtzInput {
    /// Camera id or exact reported name from `cameras.search`.
    camera: String,
    action: CameraPtzAction,
    /// Preset slot (-1 for home, or a nonnegative slot) or patrol slot (0-4).
    /// Omit for stopPatrol.
    slot: Option<i32>,
    /// Run the action. Absent or false previews the request.
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraPtzOutput {
    camera_id: String,
    action: CameraPtzAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<i32>,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    /// Present for confirmed patrol actions when the camera reports its
    /// active slot. A preset move has no position readback in this API.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    /// Omitted when the camera does not report patrol state; null means idle.
    #[serde(skip_serializing_if = "Option::is_none")]
    active_patrol_slot: Option<PatrolSlotView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraDisableMicInput {
    /// Camera id or exact reported name from `cameras.search`.
    camera: String,
    /// Run the irreversible action. Absent or false previews the request.
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraDisableMicOutput {
    camera_id: String,
    effect: &'static str,
    before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_in_content: Option<bool>,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(untagged)]
enum PatrolSlotView {
    Running(u8),
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum StreamQuality {
    High,
    Medium,
    Low,
    Package,
}

impl From<StreamQuality> for ProtectStreamQuality {
    fn from(value: StreamQuality) -> Self {
        match value {
            StreamQuality::High => Self::High,
            StreamQuality::Medium => Self::Medium,
            StreamQuality::Low => Self::Low,
            StreamQuality::Package => Self::Package,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraStreamHandle {
    quality: StreamQuality,
    /// This URL grants access to the camera feed.
    url: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraStreamsListInput {
    /// Camera id or exact reported name from `cameras.search`.
    camera: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraStreamsListOutput {
    camera_id: String,
    streams: Vec<CameraStreamHandle>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum CameraStreamsAction {
    Create,
    Remove,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraStreamsUpdateInput {
    camera: String,
    action: CameraStreamsAction,
    /// One or more distinct qualities: high, medium, low, or package.
    qualities: Vec<StreamQuality>,
    /// Run the operation. Absent or false previews it.
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraStreamsUpdateOutput {
    camera_id: String,
    action: CameraStreamsAction,
    qualities: Vec<StreamQuality>,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    /// Created stream handles are retained even if readback fails.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    streams: Vec<CameraStreamHandle>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraTalkbackInput {
    camera: String,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraTalkbackSessionView {
    /// Transport handle for this one audio session.
    url: String,
    codec: String,
    sampling_rate: u32,
    bits_per_sample: u16,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CameraTalkbackOutput {
    camera_id: String,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<CameraTalkbackSessionView>,
}

/// One camera as this surface reports it.
///
/// Camera images are available through `cameras.snapshot`.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CameraView {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// A usable label selected from controller-reported identity fields.
    display_name: String,
    /// Which controller field supplied `displayName`.
    display_name_source: String,
    /// Product type reported by the Integration API, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    product_type: Option<String>,
    /// Human-facing hardware model. Absent from the documented public API.
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_model: Option<String>,
    /// Functional classes derived from explicit feature flags. Absent when
    /// those flags are unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    classes: Option<Vec<String>>,
    /// Connection state in the console's own vocabulary, not normalized to a
    /// boolean: the states are not simply on or off.
    state: String,
    /// Present when the public camera record reports patrol state. Null
    /// means the patrol is stopped; a number is its running slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    active_patrol_slot: Option<PatrolSlotView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording: Option<bool>,
    /// Whether the camera's configured recording mode enables recording,
    /// before applying the recorder-wide switch.
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_configured: Option<bool>,
    /// Effective configured state after applying the recorder-wide switch.
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_globally_disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_recordings: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poor_network: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    firmware_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_firmware_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connected_since_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_disconnect_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updating: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rebooting: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restoring: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downloading_firmware: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempting_to_connect: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    video_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio: Option<CameraAudioView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    features: Option<CameraFeaturesView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection: Option<CameraConnectionView>,
    /// Original local camera fields, included only when requested by status.
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Map<String, Value>>,
    /// Whether optional local data enriched this row.
    local_enrichment: String,
    /// Controller error from an optional local inventory read, on status calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    local_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CameraAudioView {
    #[serde(skip_serializing_if = "Option::is_none")]
    supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    globally_disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effectively_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CameraFeaturesView {
    #[serde(skip_serializing_if = "Option::is_none")]
    doorbell: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    speaker: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hdr: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_camera: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    smart_detect: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    optical_zoom: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_led: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    automatic_ir_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ptz: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_k: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    four_k: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    third_party: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_paired: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    smart_detect_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    smart_detect_types_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    smart_detect_audio_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    smart_detect_audio_types_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CameraConnectionView {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transmit_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal_quality: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal_strength_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_mhz: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    experience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connectivity: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CamerasSearchOutput {
    /// Cameras matching the filters, name-sorted.
    cameras: Vec<CameraView>,
    /// Total matching the filters before paging.
    total: usize,
    /// Continuation offset when more rows match than were returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
    capabilities: ProtectCapabilitiesView,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CameraCountRow {
    /// A state the console reported, verbatim.
    state: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RecorderView {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    display_name: String,
    display_name_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    product_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protect_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    console_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_motion_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio_disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recycling: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    corruption_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hard_drive_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    camera_utilization: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_camera_capacity: Option<RecorderCameraCapacityView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_drive_slow_event_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage: Option<RecorderStorageView>,
    enriched: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RecorderStorageView {
    #[serde(skip_serializing_if = "Option::is_none")]
    capacity_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_capacity_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    utilization: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_space: Option<RecorderSpaceView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_type_distribution: Option<Vec<RecorderDistributionView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_type_distribution_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution_distribution: Option<Vec<RecorderDistributionView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution_distribution_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RecorderCameraCapacityView {
    #[serde(skip_serializing_if = "Option::is_none")]
    four_k: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_k: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hd: Option<u16>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[expect(
    clippy::struct_field_names,
    reason = "the unit suffix keeps each aggregate storage value unambiguous in the MCP schema"
)]
struct RecorderSpaceView {
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RecorderDistributionView {
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    percentage: Option<f64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ProtectCapabilitiesView {
    public_inventory: bool,
    public_inventory_source: String,
    local_enrichment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_inventory_source: Option<String>,
    /// The public and local reads occur sequentially during one tool call;
    /// they are not an atomic controller snapshot.
    snapshot_consistency: String,
    historical_events_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ProtectOverviewOutput {
    /// Which console answered, as configured.
    console: String,
    /// Protect application version the console reported.
    application_version: String,
    /// How many cameras are in each state the console reported. Grouped on
    /// the console's own words rather than a health verdict this server would
    /// have to invent.
    cameras_by_state: Vec<CameraCountRow>,
    camera_count: usize,
    /// Cameras whose `recording` is false. Absent unless the console reported
    /// recording state for every camera, so a partial report cannot look like
    /// a complete list.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_recording: Option<Vec<CameraReferenceView>>,
    /// Present when more cameras are idle than are named above. The count
    /// stays exact, so a cut list never reads as the whole of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_recording_truncated: Option<bool>,
    /// How many cameras are idle, whether or not all of them are named.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_recording_count: Option<usize>,
    recorders: Vec<RecorderView>,
    /// Requested fields from the original local bootstrap response.
    #[serde(skip_serializing_if = "Option::is_none")]
    bootstrap_details: Option<Map<String, Value>>,
    capabilities: ProtectCapabilitiesView,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CameraReferenceView {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

struct CameraInventory {
    application_version: String,
    cameras: Vec<CameraView>,
    public_nvr: Option<ProtectNvr>,
    local_bootstrap: Option<ProtectBootstrap>,
    local_state: LocalEnrichmentState,
    local_error: Option<ApiError>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalEnrichmentState {
    Available,
    Partial,
    NotConfigured,
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CameraInventoryScope {
    Public,
    CameraNames,
    Full,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectEventsCursor {
    /// Frozen beginning of the requested window, epoch milliseconds.
    window_start: u64,
    /// Frozen end of the requested window, epoch milliseconds.
    window_end: u64,
    /// Inclusive time-key upper bound for the next page. Rows already
    /// returned have strictly newer start times.
    next_end: u64,
    /// Resolved camera id, retained so the next call cannot change filters.
    #[serde(skip_serializing_if = "Option::is_none")]
    camera_id: Option<String>,
    /// Normalized event type or smart-detection label filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    detection: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectEventsInput {
    /// Positive relative window ending now. Defaults to 24 on the first
    /// page. Cannot be combined with `start`, `end`, or `cursor`.
    last_hours: Option<u32>,
    /// Explicit window start in epoch milliseconds. Supply with `end` to read
    /// an older window of controller-retained history.
    start: Option<u64>,
    /// Explicit window end in epoch milliseconds. Supply with `start`.
    end: Option<u64>,
    /// Camera id, exact reported name, or display name from `cameras.search`.
    camera: Option<String>,
    /// Exact event type or smart-detection label, case-insensitive.
    detection: Option<String>,
    /// Continuation returned by the prior page. Pass it back unchanged and do
    /// not repeat window or filter fields.
    cursor: Option<ProtectEventsCursor>,
    /// Positive upstream scan count for this page. The event read budget applies. Filtered pages
    /// may contain fewer rows; continue until `nextCursor` is absent.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
    /// Include the controller's complete record for every returned event.
    /// Omitted or false keeps search pages compact.
    include_details: Option<bool>,
    /// Select named controller fields instead of the full record.
    /// This also enables details when `includeDetails` is omitted.
    detail_fields: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ProtectEventView {
    id: String,
    /// Event type in the console's own vocabulary.
    kind: String,
    /// Epoch milliseconds.
    start: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    camera_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    camera_name: Option<String>,
    detection_types: Vec<String>,
    /// Complete event fields exactly as the controller returned them, when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ProtectEventsOutput {
    page_counts: PageCounts,
    rows: Vec<ProtectEventView>,
    /// Frozen time window covered by this scan.
    window_start: u64,
    window_end: u64,
    /// Raw upstream rows inspected on this page, excluding one lookahead row.
    scanned_rows: usize,
    /// True only when this page proved that no older row inside the frozen
    /// window remains.
    complete: bool,
    /// Pass back unchanged to continue. Its absence proves this window is
    /// complete; there is no hidden scan ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<ProtectEventsCursor>,
}

struct ResolvedProtectEventQuery {
    window_start: u64,
    window_end: u64,
    camera_id: Option<String>,
    detection: Option<String>,
    continuation: Option<ProtectEventContinuation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum FirewallSection {
    Zones,
    Policies,
    PortForwards,
    TrafficRules,
    TrafficRoutes,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallReadInput {
    /// Restrict the response to one section. Required to use
    /// `sectionOffset`, to continue a truncated section scan.
    section: Option<FirewallSection>,
    /// Continuation offset into a paginated section scan (`zones` or
    /// `policies` only), taken from `nextSectionOffset`.
    section_offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworksReadInput {
    /// Restrict the response to one configuration section.
    section: Option<NetworksSection>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RadiusProfilesListInput {
    /// Zero-based offset into the controller's profile list.
    #[serde(default)]
    offset: u64,
    /// Positive profiles per page; the controller limit applies.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
    /// Documented controller filter expression.
    filter: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct RadiusProfilesListOutput {
    page_counts: PageCounts,
    /// Complete fields for the profiles returned on this page.
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata_in_content: Option<bool>,
    offset: u64,
    limit: u64,
    count: u64,
    total_count: u64,
    /// Continue at this offset until absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum NetworkInventoryKind {
    Countries,
    Sites,
    DpiApplications,
    DpiCategories,
    Clients,
    Devices,
    DeviceTags,
    Lags,
    McLagDomains,
    SwitchStacks,
    WanInterfaces,
    VpnServers,
    SiteToSiteVpnTunnels,
}

impl NetworkInventoryKind {
    const fn site_kind(self) -> Option<SiteInventoryKind> {
        match self {
            Self::Countries | Self::Sites | Self::DpiApplications | Self::DpiCategories => None,
            Self::Clients => Some(SiteInventoryKind::Clients),
            Self::Devices => Some(SiteInventoryKind::Devices),
            Self::DeviceTags => Some(SiteInventoryKind::DeviceTags),
            Self::Lags => Some(SiteInventoryKind::Lags),
            Self::McLagDomains => Some(SiteInventoryKind::McLagDomains),
            Self::SwitchStacks => Some(SiteInventoryKind::SwitchStacks),
            Self::WanInterfaces => Some(SiteInventoryKind::WanInterfaces),
            Self::VpnServers => Some(SiteInventoryKind::VpnServers),
            Self::SiteToSiteVpnTunnels => Some(SiteInventoryKind::SiteToSiteVpnTunnels),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworkInventoryListInput {
    kind: NetworkInventoryKind,
    #[serde(default)]
    offset: u64,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
    filter: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct NetworkInventoryListOutput {
    page_counts: PageCounts,
    kind: NetworkInventoryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records_in_content: Option<bool>,
    /// Original page fields other than its data array.
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata_in_content: Option<bool>,
    offset: u64,
    limit: u64,
    count: u64,
    total_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
    /// Filtered DPI dictionaries continue according to returned rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pagination_basis: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum NetworkSwitchingDetailKind {
    Lag,
    McLagDomain,
    SwitchStack,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworkSwitchingDetailInput {
    kind: NetworkSwitchingDetailKind,
    id: String,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum NetworkInventoryDetailKind {
    ApplicationInfo,
    Client,
    Device,
    DeviceStatistics,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworkInventoryDetailInput {
    kind: NetworkInventoryDetailKind,
    /// Required for client, device and deviceStatistics; omitted for applicationInfo.
    id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct RecordOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_in_content: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum NetworkPolicyKind {
    AclRules,
    FirewallZones,
    FirewallPolicies,
    DnsPolicies,
    TrafficMatchingLists,
}

impl NetworkPolicyKind {
    const fn collection(self) -> NetworkPolicyCollection {
        match self {
            Self::AclRules => NetworkPolicyCollection::AclRules,
            Self::FirewallZones => NetworkPolicyCollection::FirewallZones,
            Self::FirewallPolicies => NetworkPolicyCollection::FirewallPolicies,
            Self::DnsPolicies => NetworkPolicyCollection::DnsPolicies,
            Self::TrafficMatchingLists => NetworkPolicyCollection::TrafficMatchingLists,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworkPolicyListInput {
    kind: NetworkPolicyKind,
    #[serde(default)]
    offset: u64,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
    filter: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct NetworkPolicyListOutput {
    page_counts: PageCounts,
    kind: NetworkPolicyKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata_in_content: Option<bool>,
    offset: u64,
    limit: u64,
    count: u64,
    total_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworkPolicyDetailInput {
    kind: NetworkPolicyKind,
    id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct NetworkPolicyDetailOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_in_content: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallZoneRequest {
    name: String,
    network_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallZonesConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    zone: Option<FirewallZoneRequest>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallPoliciesConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    policy: Option<FirewallPolicyRequest>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum NetworkPolicyWriteOperation {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AclRuleAction {
    Allow,
    Block,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AclRuleProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
enum AclRuleDeviceFilter {
    #[serde(rename = "DEVICES")]
    Devices {
        #[serde(rename = "deviceIds")]
        device_ids: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
enum IpAclRuleEndpoint {
    #[serde(rename = "IP_ADDRESSES_OR_SUBNETS")]
    IpAddressesOrSubnets {
        #[serde(rename = "ipAddressesOrSubnets")]
        ip_addresses_or_subnets: Vec<String>,
        #[serde(rename = "portFilter", skip_serializing_if = "Option::is_none")]
        port_filter: Option<Vec<u16>>,
    },
    #[serde(rename = "NETWORKS")]
    Networks {
        #[serde(rename = "networkIds")]
        network_ids: Vec<String>,
        #[serde(rename = "portFilter", skip_serializing_if = "Option::is_none")]
        port_filter: Option<Vec<u16>>,
    },
    #[serde(rename = "PORTS")]
    Ports {
        #[serde(rename = "portFilter")]
        port_filter: Vec<u16>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
enum MacAclRuleEndpoint {
    #[serde(rename = "MAC_ADDRESSES")]
    MacAddresses {
        #[serde(rename = "macAddresses")]
        mac_addresses: Vec<String>,
        #[serde(rename = "prefixLength", skip_serializing_if = "Option::is_none")]
        prefix_length: Option<u8>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all_fields = "camelCase", deny_unknown_fields)]
enum AclRuleRequest {
    #[serde(rename = "IPV4")]
    Ipv4 {
        action: AclRuleAction,
        enabled: bool,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_filter: Option<IpAclRuleEndpoint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_filter: Option<IpAclRuleEndpoint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol_filter: Option<Vec<AclRuleProtocol>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        enforcing_device_filter: Option<AclRuleDeviceFilter>,
    },
    #[serde(rename = "MAC")]
    Mac {
        action: AclRuleAction,
        enabled: bool,
        name: String,
        network_id_filter: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_filter: Option<MacAclRuleEndpoint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_filter: Option<MacAclRuleEndpoint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        enforcing_device_filter: Option<AclRuleDeviceFilter>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
enum DnsPolicyRequest {
    #[serde(rename = "A_RECORD")]
    ARecord {
        enabled: bool,
        domain: String,
        ipv4_address: String,
        ttl_seconds: u32,
    },
    #[serde(rename = "AAAA_RECORD")]
    AaaaRecord {
        enabled: bool,
        domain: String,
        ipv6_address: String,
        ttl_seconds: u32,
    },
    #[serde(rename = "CNAME_RECORD")]
    CnameRecord {
        enabled: bool,
        domain: String,
        target_domain: String,
        ttl_seconds: u32,
    },
    #[serde(rename = "FORWARD_DOMAIN")]
    ForwardDomain {
        enabled: bool,
        domain: String,
        ip_address: String,
    },
    #[serde(rename = "MX_RECORD")]
    MxRecord {
        enabled: bool,
        domain: String,
        mail_server_domain: String,
        priority: u16,
    },
    #[serde(rename = "SRV_RECORD")]
    SrvRecord {
        enabled: bool,
        domain: String,
        port: u16,
        priority: u16,
        protocol: String,
        server_domain: String,
        service: String,
        weight: u16,
    },
    #[serde(rename = "TXT_RECORD")]
    TxtRecord {
        enabled: bool,
        domain: String,
        text: String,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
enum Ipv4ListItem {
    #[serde(rename = "IP_ADDRESS")]
    IpAddress { value: String },
    #[serde(rename = "IP_ADDRESS_RANGE")]
    IpAddressRange { start: String, stop: String },
    #[serde(rename = "SUBNET")]
    Subnet { value: String },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
enum Ipv6ListItem {
    #[serde(rename = "IP_ADDRESS")]
    IpAddress { value: String },
    #[serde(rename = "SUBNET")]
    Subnet { value: String },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
enum PortListItem {
    #[serde(rename = "PORT_NUMBER")]
    PortNumber { value: u16 },
    #[serde(rename = "PORT_NUMBER_RANGE")]
    PortNumberRange { start: u16, stop: u16 },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
enum TrafficListRequest {
    #[serde(rename = "IPV4_ADDRESSES")]
    Ipv4Addresses {
        name: String,
        items: Vec<Ipv4ListItem>,
    },
    #[serde(rename = "IPV6_ADDRESSES")]
    Ipv6Addresses {
        name: String,
        items: Vec<Ipv6ListItem>,
    },
    #[serde(rename = "PORTS")]
    Ports {
        name: String,
        items: Vec<PortListItem>,
    },
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DnsPoliciesConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    policy: Option<DnsPolicyRequest>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrafficListsConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    list: Option<TrafficListRequest>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AclRulesConfigureInput {
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    rule: Option<AclRuleRequest>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AclRulesOrderingReadInput {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AclRulesOrderingConfigureInput {
    ordered_acl_rule_ids: Vec<String>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallPolicyOrdering {
    before_system_defined: Vec<String>,
    after_system_defined: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallPolicyOrderingConfigureInput {
    ordered_firewall_policy_ids: FirewallPolicyOrdering,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct NetworkPolicyWriteOutput<K = NetworkPolicyKind> {
    kind: K,
    operation: NetworkPolicyWriteOperation,
    consequence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_in_content: Option<bool>,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_absent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

struct NetworkPolicyWritePlan {
    kind: NetworkPolicyKind,
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    requested: Option<Value>,
    confirm: bool,
}

fn policy_write_plan(
    kind: NetworkPolicyKind,
    operation: NetworkPolicyWriteOperation,
    id: Option<String>,
    requested: Option<Value>,
    confirm: bool,
) -> Result<NetworkPolicyWritePlan, McpError> {
    let valid_shape = match operation {
        NetworkPolicyWriteOperation::Create => id.is_none() && requested.is_some(),
        NetworkPolicyWriteOperation::Update => id.is_some() && requested.is_some(),
        NetworkPolicyWriteOperation::Delete => id.is_some() && requested.is_none(),
    };
    if !valid_shape {
        return Err(McpError::invalid_params(
            "create requires a request body and no id; update requires both; delete requires an id and no request body",
            None,
        ));
    }
    if id.as_ref().is_some_and(|id| {
        id.trim().is_empty() || id.len() > 256 || matches!(id.as_str(), "." | "..")
    }) {
        return Err(McpError::invalid_params(
            "id must be a nonempty id of at most 256 bytes",
            None,
        ));
    }
    if requested
        .as_ref()
        .is_some_and(|body| body.to_string().len() > MAXIMUM_POLICY_REQUEST_BYTES)
    {
        return Err(McpError::invalid_params(
            "policy request exceeds the 1 MiB request bound",
            None,
        ));
    }
    Ok(NetworkPolicyWritePlan {
        kind,
        operation,
        id,
        requested,
        confirm,
    })
}

fn validate_acl_nonempty(values: &[String], field: &str) -> Result<(), McpError> {
    if values.is_empty() || values.iter().any(String::is_empty) {
        return Err(McpError::invalid_params(
            format!("{field} requires at least one nonempty value"),
            None,
        ));
    }
    Ok(())
}

fn validate_acl_ports(values: &[u16]) -> Result<(), McpError> {
    if values.is_empty() || values.contains(&0) {
        return Err(McpError::invalid_params(
            "portFilter requires ports in 1-65535",
            None,
        ));
    }
    Ok(())
}

fn validate_ip_acl_endpoint(endpoint: &IpAclRuleEndpoint) -> Result<(), McpError> {
    match endpoint {
        IpAclRuleEndpoint::IpAddressesOrSubnets {
            ip_addresses_or_subnets,
            port_filter,
        } => {
            validate_acl_nonempty(ip_addresses_or_subnets, "ipAddressesOrSubnets")?;
            if let Some(values) = port_filter {
                validate_acl_ports(values)?;
            }
        }
        IpAclRuleEndpoint::Networks {
            network_ids,
            port_filter,
        } => {
            validate_acl_nonempty(network_ids, "networkIds")?;
            if let Some(values) = port_filter {
                validate_acl_ports(values)?;
            }
        }
        IpAclRuleEndpoint::Ports { port_filter } => validate_acl_ports(port_filter)?,
    }
    Ok(())
}

fn validate_mac_acl_endpoint(endpoint: &MacAclRuleEndpoint) -> Result<(), McpError> {
    let MacAclRuleEndpoint::MacAddresses {
        mac_addresses,
        prefix_length,
    } = endpoint;
    validate_acl_nonempty(mac_addresses, "macAddresses")?;
    if prefix_length.is_some_and(|value| !(1..=48).contains(&value)) {
        return Err(McpError::invalid_params("prefixLength must be 1-48", None));
    }
    Ok(())
}

fn validate_acl_rule_request(rule: &AclRuleRequest) -> Result<(), McpError> {
    let (name, device_filter) = match rule {
        AclRuleRequest::Ipv4 {
            name,
            source_filter,
            destination_filter,
            protocol_filter,
            enforcing_device_filter,
            ..
        } => {
            if let Some(filter) = source_filter {
                validate_ip_acl_endpoint(filter)?;
            }
            if let Some(filter) = destination_filter {
                validate_ip_acl_endpoint(filter)?;
            }
            if protocol_filter.as_ref().is_some_and(Vec::is_empty) {
                return Err(McpError::invalid_params(
                    "protocolFilter requires at least one protocol",
                    None,
                ));
            }
            (name, enforcing_device_filter)
        }
        AclRuleRequest::Mac {
            name,
            network_id_filter,
            source_filter,
            destination_filter,
            enforcing_device_filter,
            ..
        } => {
            if network_id_filter.is_empty() {
                return Err(McpError::invalid_params(
                    "networkIdFilter must be nonempty",
                    None,
                ));
            }
            if let Some(filter) = source_filter {
                validate_mac_acl_endpoint(filter)?;
            }
            if let Some(filter) = destination_filter {
                validate_mac_acl_endpoint(filter)?;
            }
            (name, enforcing_device_filter)
        }
    };
    if name.is_empty() {
        return Err(McpError::invalid_params("name must be nonempty", None));
    }
    if let Some(AclRuleDeviceFilter::Devices { device_ids }) = device_filter {
        validate_acl_nonempty(device_ids, "deviceIds")?;
    }
    Ok(())
}

fn validate_dns_policy_request(policy: &DnsPolicyRequest) -> Result<(), McpError> {
    let domain = match policy {
        DnsPolicyRequest::ARecord { domain, .. }
        | DnsPolicyRequest::AaaaRecord { domain, .. }
        | DnsPolicyRequest::CnameRecord { domain, .. }
        | DnsPolicyRequest::ForwardDomain { domain, .. }
        | DnsPolicyRequest::MxRecord { domain, .. }
        | DnsPolicyRequest::SrvRecord { domain, .. }
        | DnsPolicyRequest::TxtRecord { domain, .. } => domain,
    };
    if domain.is_empty() || domain.len() > 127 {
        return Err(McpError::invalid_params(
            "domain must contain 1-127 bytes",
            None,
        ));
    }
    match policy {
        DnsPolicyRequest::ARecord { ttl_seconds, .. }
        | DnsPolicyRequest::AaaaRecord { ttl_seconds, .. }
            if *ttl_seconds > 86_400 =>
        {
            Err(McpError::invalid_params(
                "A and AAAA record ttlSeconds must be 0-86400",
                None,
            ))
        }
        DnsPolicyRequest::CnameRecord {
            target_domain,
            ttl_seconds,
            ..
        } if target_domain.is_empty() || target_domain.len() > 127 || *ttl_seconds > 604_800 => {
            Err(McpError::invalid_params(
                "CNAME targetDomain must contain 1-127 bytes and ttlSeconds must be 0-604800",
                None,
            ))
        }
        DnsPolicyRequest::MxRecord {
            mail_server_domain, ..
        } if mail_server_domain.is_empty() || mail_server_domain.len() > 127 => Err(
            McpError::invalid_params("MX mailServerDomain must contain 1-127 bytes", None),
        ),
        DnsPolicyRequest::SrvRecord { server_domain, .. }
            if server_domain.is_empty() || server_domain.len() > 127 =>
        {
            Err(McpError::invalid_params(
                "SRV serverDomain must contain 1-127 bytes",
                None,
            ))
        }
        DnsPolicyRequest::TxtRecord { text, .. } if text.is_empty() || text.len() > 1024 => Err(
            McpError::invalid_params("TXT text must contain 1-1024 bytes", None),
        ),
        _ => Ok(()),
    }
}

fn validate_traffic_list_request(list: &TrafficListRequest) -> Result<(), McpError> {
    let (name, item_count) = match list {
        TrafficListRequest::Ipv4Addresses { name, items } => (name, items.len()),
        TrafficListRequest::Ipv6Addresses { name, items } => (name, items.len()),
        TrafficListRequest::Ports { name, items } => (name, items.len()),
    };
    if name.is_empty() || item_count == 0 {
        return Err(McpError::invalid_params(
            "name and at least one item are required",
            None,
        ));
    }
    if let TrafficListRequest::Ports { items, .. } = list {
        for item in items {
            let valid = match item {
                PortListItem::PortNumber { value } => *value > 0,
                PortListItem::PortNumberRange { start, stop } => *start > 0 && *stop > 0,
            };
            if !valid {
                return Err(McpError::invalid_params(
                    "port item values must be 1-65535",
                    None,
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WifiBroadcastsListInput {
    /// Zero-based offset into the controller's broadcast list.
    #[serde(default)]
    offset: u64,
    /// Positive broadcasts per page; the controller limit applies.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
    /// The official controller filter query, sent unchanged.
    filter: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct WifiBroadcastsListOutput {
    page_counts: PageCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcasts: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcasts_in_content: Option<bool>,
    /// Additional page fields returned by the controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_metadata_in_content: Option<bool>,
    offset: u64,
    limit: u64,
    count: u64,
    total_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WifiBroadcastsStatusInput {
    /// Official Wi-Fi broadcast id from `wifi.broadcasts.list`.
    broadcast_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum NetworksSection {
    Networks,
    Wlans,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ZoneView {
    id: String,
    name: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PolicyView {
    id: String,
    name: Option<String>,
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logging_enabled: Option<bool>,
    action: Option<String>,
    /// Evaluation order.
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<i32>,
    /// Which IP protocols the policy matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_protocol_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_port: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PortForwardView {
    id: String,
    name: Option<String>,
    enabled: Option<bool>,
    source: Option<String>,
    forward_to: Option<String>,
    forward_port: Option<String>,
    destination_port: Option<String>,
    protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct TrafficRuleView {
    id: String,
    description: Option<String>,
    enabled: Option<bool>,
    action: Option<String>,
    /// What the rule matches, such as `INTERNET`, `DOMAIN`, or `IP`.
    matching_target: Option<String>,
    network_id: Option<String>,
    domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct TrafficRouteView {
    id: String,
    description: Option<String>,
    enabled: Option<bool>,
    /// What the route matches, such as `INTERNET`, `DOMAIN`, or `IP`.
    matching_target: Option<String>,
    network_id: Option<String>,
    /// Egress interface the matched traffic is steered onto.
    interface: Option<String>,
    domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct FirewallReadOutput {
    /// `zoneBased`, from live capability detection. Only that generation is
    /// readable here; an unsupported zone API returns its original rejection.
    /// Absent when a narrowing selected only sections that
    /// exist identically on both generations, so detection was not needed and
    /// was not performed — unverified rather than guessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<&'static str>,
    /// Echo of the requested section narrowing; other sections are empty
    /// because they were filtered, not because they are empty upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<&'static str>,
    /// Present when a bounded scan cut a zone or policy section short; the
    /// audit view is then visibly partial. Continue with `section` plus
    /// `sectionOffset` when `nextSectionOffset` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    sections_truncated: Option<bool>,
    /// Continuation offset for the narrowed paginated section when its scan
    /// was cut short and the continuation is within the accepted offset
    /// bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_section_offset: Option<u64>,
    /// Present when a truncated section has no usable continuation, naming
    /// why and what to do instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation_note: Option<String>,
    /// Explains which sections apply on this console, so an empty section
    /// is never a bare empty list. Absent with `generation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_note: Option<&'static str>,
    zones: Vec<ZoneView>,
    policies: Vec<PolicyView>,
    port_forwards: Vec<PortForwardView>,
    traffic_rules: Vec<TrafficRuleView>,
    traffic_routes: Vec<TrafficRouteView>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct NetworkView {
    name: Option<String>,
    purpose: Option<String>,
    vlan: Option<u16>,
    subnet: Option<String>,
    enabled: Option<bool>,
    dhcp_enabled: Option<bool>,
    dhcp_start: Option<String>,
    dhcp_stop: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct WlanView {
    /// Stable controller id; `wlans.update` addresses a network by this.
    id: String,
    ssid: Option<String>,
    enabled: Option<bool>,
    security: Option<String>,
    hidden: Option<bool>,
    /// Backing network name resolved from configuration.
    network: Option<String>,
    /// Controller-reported passphrase, when present. The gateway classifies
    /// this tool's result as sensitive.
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    /// Controller id of the selected RADIUS profile, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    radius_profile_id: Option<String>,
}

/// Security modes accepted by the legacy wireless-network API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WlanSecurity {
    Open,
    Wpapsk,
    Wpaeap,
}

impl WlanSecurity {
    const fn wire(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Wpapsk => "wpapsk",
            Self::Wpaeap => "wpaeap",
        }
    }
}

/// The settable fields of one wireless network, named as [`WlanView`] emits
/// them. An absent field is left unchanged.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WlanChanges {
    ssid: Option<String>,
    enabled: Option<bool>,
    /// `open`, `wpapsk`, or `wpaeap`.
    security: Option<WlanSecurity>,
    /// Whether the ssid is hidden from scans.
    hidden: Option<bool>,
    /// New pre-shared key. The readback reports the controller's stored value.
    passphrase: Option<String>,
    /// Controller id of a configured RADIUS profile.
    radius_profile_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WlansUpdateInput {
    /// Wireless network id, as `networks.read` reports it.
    wlan: String,
    changes: WlanChanges,
    /// Apply the change. Absent or false describes it without writing.
    confirm: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct WlansUpdateOutput {
    wlan: String,
    /// The network's ssid, for a human reading the result.
    ssid: Option<String>,
    /// Whether the controller was written to.
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    /// What would change. Preview only.
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<PlannedChange>>,
    /// What the read-back found per requested field. Applied only.
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<FieldOutcome>>,
    /// Controller properties that moved without being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    unexpected_changes: Option<Vec<String>>,
    /// True when every requested field persisted and nothing else moved.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    /// Consequences worth knowing before confirming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// Fields that `port_forwards.update` can change on one port forward.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortForwardChanges {
    /// New label for the rule.
    name: Option<String>,
    /// Whether the rule forwards traffic.
    enabled: Option<bool>,
    /// Source selector as the controller stores it.
    source: Option<String>,
    /// Internal host that receives matching traffic.
    forward_to: Option<String>,
    /// Internal port or port range as the controller stores it.
    forward_port: Option<String>,
    /// External port or port range as the controller stores it.
    destination_port: Option<String>,
    /// Protocol as the controller stores it.
    protocol: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortForwardsUpdateInput {
    /// Port forward id, as `firewall.read` reports it.
    port_forward: String,
    changes: PortForwardChanges,
    /// Apply the change. Absent or false describes it without writing.
    confirm: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PortForwardsUpdateOutput {
    /// The rule as `firewall.read` reports it, read after a confirmed change
    /// and before an unconfirmed one.
    forward: PortForwardView,
    /// Whether the controller was written to.
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    /// What would change. Preview only.
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<PlannedChange>>,
    /// What the read-back found per requested field. Applied only.
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<FieldOutcome>>,
    /// Controller properties that moved without being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    unexpected_changes: Option<Vec<String>>,
    /// True when every requested field persisted and nothing else moved.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    /// Consequences worth knowing before confirming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GuestsAuthorizeInput {
    /// MAC address of the client, as `clients.search` reports it. This workflow
    /// resolves the corresponding Integration API client id before authorizing.
    client: String,
    time_limit_minutes: Option<u64>,
    data_usage_limit_m_bytes: Option<u64>,
    rx_rate_limit_kbps: Option<u64>,
    tx_rate_limit_kbps: Option<u64>,
    /// Authorize the client. Absent or false describes the action without
    /// performing it.
    confirm: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GuestClientInput {
    client: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GuestsUnauthorizeInput {
    client: String,
    confirm: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GuestLimitsView {
    #[serde(skip_serializing_if = "Option::is_none")]
    time_limit_minutes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_usage_limit_m_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_rate_limit_kbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_rate_limit_kbps: Option<u64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GuestAuthorizationView {
    authorization_method: String,
    authorized_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_usage_limit_m_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_rate_limit_kbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_rate_limit_kbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<GuestUsageView>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GuestUsageView {
    bytes: u64,
    duration_sec: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

impl From<GuestAuthorization> for GuestAuthorizationView {
    fn from(value: GuestAuthorization) -> Self {
        Self {
            authorization_method: value.authorization_method,
            authorized_at: value.authorized_at,
            expires_at: value.expires_at,
            data_usage_limit_m_bytes: value.data_usage_limit_m_bytes,
            rx_rate_limit_kbps: value.rx_rate_limit_kbps,
            tx_rate_limit_kbps: value.tx_rate_limit_kbps,
            usage: value.usage.map(|usage| GuestUsageView {
                bytes: usage.bytes,
                duration_sec: usage.duration_sec,
                rx_bytes: usage.rx_bytes,
                tx_bytes: usage.tx_bytes,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GuestsAuthorizeOutput {
    /// The address the action addressed, normalized.
    client: String,
    action: &'static str,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_limits: Option<GuestLimitsView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_before: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_after: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    granted_authorization: Option<GuestAuthorizationView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_authorization: Option<GuestAuthorizationView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_authorization: Option<GuestAuthorizationView>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GuestStatusOutput {
    client: String,
    authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<GuestAuthorizationView>,
}

/// What `firewall.policies.update` can change on one zone-based policy.
/// This shortcut changes flags and preserves all other controller fields.
/// Full creation and replacement use `firewall.policies.configure`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallPolicyChanges {
    /// Whether the policy is evaluated.
    enabled: Option<bool>,
    /// Generate syslog entries when the policy matches traffic.
    logging_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallPoliciesUpdateInput {
    /// Zone-based policy id, as `firewall.read` reports it under `policies`.
    policy: String,
    changes: FirewallPolicyChanges,
    /// Apply the change. Absent or false describes it without writing.
    confirm: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct FirewallPoliciesUpdateOutput {
    /// The policy as `firewall.read` reports it, read after a confirmed
    /// change and before an unconfirmed one.
    policy: PolicyView,
    /// Exact policy detail response before the attempted change.
    #[serde(skip_serializing_if = "Option::is_none")]
    before_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_response_in_content: Option<bool>,
    /// Accepted write status and complete response body, if a write was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    /// Exact policy detail response after an accepted write.
    #[serde(skip_serializing_if = "Option::is_none")]
    after_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_response_in_content: Option<bool>,
    /// Whether the controller was written to.
    applied: bool,
    /// What would change. Preview only.
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<PlannedChange>>,
    /// What the read-back found per requested field. Applied only.
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<FieldOutcome>>,
    /// Controller properties that moved without being requested. Full writes
    /// preserve unrequested fields and logging patches send only that flag.
    /// Differences can reflect the controller normalizing the
    /// record or another editor writing the policy between the write and the
    /// read-back — this tool cannot tell those apart, and either way the
    /// change was not asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    unexpected_changes: Option<Vec<String>>,
    /// True when every requested field persisted and nothing else moved.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    /// The complete controller response when read-back did not identify the
    /// policy that was changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    /// Consequences worth knowing before confirming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallPoliciesDeleteInput {
    /// Zone-based policy id, as `firewall.read` reports it.
    policy: String,
    /// Delete the policy. Absent or false previews its scope.
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct FirewallPoliciesDeleteOutput {
    policy: PolicyView,
    preview: PolicyPreviewCoverage,
    /// Exact policy detail response used to build the compact preview.
    #[serde(skip_serializing_if = "Option::is_none")]
    before_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_response_in_content: Option<bool>,
    /// Accepted deletion status and complete response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_absent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct PolicyPreviewCoverage {
    /// Full values for the official policy fields that the compact summary omits.
    details: Map<String, Value>,
    /// False if the controller record has fields the preview omits.
    complete: bool,
    omitted_fields: Vec<String>,
    omitted_fields_truncated: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VouchersCreateInput {
    /// Label the controller stores against the batch.
    name: String,
    /// How many to mint, 1-1000. Defaults to one.
    #[serde(default = "default_voucher_count")]
    count: u32,
    /// Minutes each voucher is valid once redeemed, 1-1000000.
    time_limit_minutes: u32,
    /// Devices one voucher may authorize. The controller's default applies
    /// when absent.
    guest_limit: Option<u64>,
    /// Data allowance per voucher in megabytes, 1-1048576. Unlimited when absent.
    data_limit_megabytes: Option<u64>,
    /// Download rate per voucher in kilobits per second, 2-100000.
    download_rate_limit_kbps: Option<u64>,
    /// Upload rate per voucher in kilobits per second, 2-100000.
    upload_rate_limit_kbps: Option<u64>,
    /// Mint them. Absent or false describes the batch without creating it.
    confirm: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VouchersSearchInput {
    /// Zero-based offset into the controller's voucher list.
    #[serde(default)]
    offset: u32,
    /// Positive vouchers per page. Defaults to 25; the native limit applies.
    #[serde(default = "default_voucher_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

const fn default_voucher_count() -> u32 {
    1
}

const fn default_voucher_limit() -> usize {
    25
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VoucherIdInput {
    /// Exact voucher id from `vouchers.search` or `vouchers.create`.
    voucher_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VoucherRevokeInput {
    /// Exact voucher id from `vouchers.search` or `vouchers.create`.
    voucher_id: String,
    /// Delete the voucher. Absent or false previews the effect.
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VouchersRevokeMatchingInput {
    /// Documented controller filter, sent unchanged. Maximum 2048 bytes.
    filter: String,
    /// Offset of the preview page, independent of the deletion selection.
    #[serde(default)]
    preview_offset: u32,
    /// Positive preview rows. Default 25; the native limit applies. Confirmation deletes every filter match.
    #[serde(default = "default_voucher_limit")]
    #[schemars(range(min = 1))]
    preview_limit: usize,
    /// Delete all matching vouchers. Absent or false previews one page.
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VouchersRevokeMatchingOutput {
    page_counts: PageCounts,
    filter: String,
    matches_before: u64,
    preview_complete: bool,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vouchers_deleted: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matches_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_absent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_response_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VoucherRevokeOutput {
    voucher_id: String,
    name: String,
    expired: bool,
    authorized_guest_count: u64,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VoucherReadView {
    id: String,
    /// Redeemable guest code; classified as sensitive result data.
    code: String,
    name: String,
    created_at: String,
    expired: bool,
    authorized_guest_count: u64,
    time_limit_minutes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_guest_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_usage_limit_m_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_rate_limit_kbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_rate_limit_kbps: Option<u64>,
}

impl From<VoucherDetails> for VoucherReadView {
    fn from(voucher: VoucherDetails) -> Self {
        Self {
            id: voucher.id,
            code: voucher.code,
            name: voucher.name,
            created_at: voucher.created_at,
            expired: voucher.expired,
            authorized_guest_count: voucher.authorized_guest_count,
            time_limit_minutes: voucher.time_limit_minutes,
            activated_at: voucher.activated_at,
            expires_at: voucher.expires_at,
            authorized_guest_limit: voucher.authorized_guest_limit,
            data_usage_limit_m_bytes: voucher.data_usage_limit_m_bytes,
            rx_rate_limit_kbps: voucher.rx_rate_limit_kbps,
            tx_rate_limit_kbps: voucher.tx_rate_limit_kbps,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VouchersSearchOutput {
    page_counts: PageCounts,
    vouchers: Vec<VoucherReadView>,
    offset: u64,
    limit: u64,
    total_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<u64>,
}

/// The batch a call would mint, echoed so a preview shows what is about to be
/// reviewed rather than only how much of it there is.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VoucherBatch {
    /// Label the controller stores against the batch.
    name: String,
    /// How many vouchers.
    count: u32,
    /// Minutes each voucher is valid once redeemed.
    time_limit_minutes: u32,
    /// Devices one voucher may authorize. Absent means the controller's
    /// default applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_limit: Option<u64>,
    /// Data allowance per voucher in megabytes. Absent means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    data_limit_megabytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_rate_limit_kbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_rate_limit_kbps: Option<u64>,
}

/// One voucher returned by the creation request.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VoucherView {
    /// Absent when the controller returned no identity for this row. The
    /// code is still returned so an incomplete creation response is visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

/// Checks on the creation response, separate from readback verification.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VoucherChecks {
    /// Whether the controller returned as many vouchers as were asked for.
    count_matches: bool,
    /// Whether every voucher carries a nonempty id and code.
    all_identified: bool,
    /// Whether every code differs from every other.
    all_distinct: bool,
    /// Character lengths of the returned codes. The controller defines their format.
    code_lengths: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VoucherReadbackFailure {
    voucher_id: String,
    error: String,
}

struct VoucherVerification {
    verified: bool,
    errors: Vec<VoucherReadbackFailure>,
    complete: bool,
    stop_reason: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VouchersCreateOutput {
    /// Whether the controller was asked to mint. False for a preview.
    applied: bool,
    /// What the call mints: how many vouchers, for how long, and under which
    /// limits. Two batches differing only in validity or access limits are
    /// different batches, and a preview that showed only a count could not
    /// tell them apart.
    batch: VoucherBatch,
    /// How many were requested.
    requested: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    /// Complete accepted creation body, including fields outside the voucher summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    /// The vouchers, present only on a confirmed call. These are returned
    /// even when a check below failed, so the creation response is preserved.
    #[serde(skip_serializing_if = "Option::is_none")]
    vouchers: Option<Vec<VoucherView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vouchers_in_content: Option<bool>,
    /// What could be established about the batch. Applied only.
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<VoucherChecks>,
    /// Whether every identified voucher was read back with the same code.
    /// False also covers missing ids, failed reads and mismatched codes.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    readback_errors: Vec<VoucherReadbackFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_errors_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_stop_reason: Option<&'static str>,
    /// Consequences worth knowing before confirming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// What `devices.control` can do to one adopted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum DeviceControl {
    /// Reboot the device. It is offline for a minute or two.
    Restart,
    /// Flash the locate LED.
    Locate,
    /// Stop flashing the locate LED.
    EndLocate,
    /// Power-cycle one switch port, which reboots whatever it powers.
    PortCycle,
}

impl DeviceControl {
    const fn word(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Locate => "locate",
            Self::EndLocate => "endLocate",
            Self::PortCycle => "portCycle",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DevicesControlInput {
    /// Device id, as `devices.search` reports it.
    device: String,
    action: DeviceControl,
    /// Switch port to power-cycle. Required by `portCycle` and rejected by
    /// every other action, so a port can never be sent with an action that
    /// would ignore it.
    port: Option<u32>,
    /// Apply the action. Absent or false describes it without doing it.
    confirm: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct DevicesControlOutput {
    device: String,
    /// The device's name, for a human reading the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u32>,
    applied: bool,
    /// Accepted HTTP status for a confirmed action.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    /// Controller-reported state before the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    state_before: Option<String>,
    /// Controller-reported state afterwards, on an applied action. A restart
    /// takes a minute or more, so this usually still reads the prior state:
    /// it records what the controller showed, not that the action finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    state_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// What `clients.control` can do to one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum ClientControl {
    /// Deny the client network access until it is unblocked.
    Block,
    /// Lift a block.
    Unblock,
    /// Disconnect the client; most rejoin on their own.
    Reconnect,
}

impl ClientControl {
    const fn word(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Unblock => "unblock",
            Self::Reconnect => "reconnect",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClientsControlInput {
    /// MAC address of the client, as `clients.search` reports it. A name is
    /// not accepted: a blocked client is absent from the connected list, so
    /// only the address identifies it in every state this tool handles.
    client: String,
    action: ClientControl,
    /// Apply the action. Absent or false describes it without doing it.
    confirm: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ClientsControlOutput {
    /// The address the action addressed, normalized.
    client: String,
    action: &'static str,
    /// Whether the controller was asked to act. False for a preview.
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_in_content: Option<bool>,
    /// Whether the controller listed the client as connected beforehand.
    /// Absence covers several states — blocked, powered off, out of range —
    /// so it says the client is not currently associated and nothing about
    /// its authorization.
    connected_before: bool,
    /// Whether it is in the connected list afterwards, on an applied action.
    /// A client that rejoins between the write and this read reads as
    /// connected, so this reports an observation rather than a guarantee.
    #[serde(skip_serializing_if = "Option::is_none")]
    connected_after: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readback_error_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct NetworksReadOutput {
    networks: Vec<NetworkView>,
    wlans: Vec<WlanView>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WifiDiagnoseInput {
    /// Signal floor in dBm below which a client counts as weak. Defaults to
    /// -75; accepted between -100 and -30.
    weak_signal_threshold_dbm: Option<i32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct AccessPointHealth {
    name: Option<String>,
    mac: Option<String>,
    state: Option<String>,
    radios: Vec<DeviceRadioRow>,
    /// Present when the radio table was cut at its ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    radios_truncated: Option<bool>,
    /// Connected wireless clients associated to this access point.
    clients: u32,
    /// Of those, clients below the weak-signal threshold.
    weak_clients: u32,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct WeakClientRow {
    name: Option<String>,
    mac: Option<String>,
    ssid: Option<String>,
    ap_name: Option<String>,
    signal_dbm: i32,
    rssi: Option<i32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RogueApRow {
    ssid: Option<String>,
    bssid: Option<String>,
    channel: Option<u32>,
    rssi: Option<i32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct WifiDiagnoseOutput {
    /// The threshold the weak-client sections were computed against.
    weak_signal_threshold_dbm: i32,
    /// Present when the bounded device-detail scan cut the inventory short;
    /// the access-point list is then visibly partial.
    #[serde(skip_serializing_if = "Option::is_none")]
    access_points_truncated: Option<bool>,
    access_points: Vec<AccessPointHealth>,
    /// The weakest-signal clients, worst first, bounded.
    weak_clients: Vec<WeakClientRow>,
    /// Neighboring access points reported by the controller, bounded.
    rogue_aps: Vec<RogueApRow>,
    /// Present when the rogue list was cut at its ceiling; more neighbors
    /// exist than are shown.
    #[serde(skip_serializing_if = "Option::is_none")]
    rogue_aps_truncated: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum EventSeverity {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EventsSearchInput {
    /// Restrict to one system-log severity before the bounded upstream read.
    severity: Option<EventSeverity>,
    /// Positive window in hours ending now. Defaults to 24.
    last_hours: Option<u32>,
    /// Case-insensitive substring matched against the event key or
    /// category, such as `wan`, `roam`, or `security`.
    category: Option<String>,
    /// Restrict to one client MAC address.
    client: Option<String>,
    /// Zero-based offset into the time-sorted result.
    #[serde(default)]
    offset: usize,
    /// Positive rows per page.
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1))]
    limit: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EventRow {
    /// Epoch milliseconds.
    time: u64,
    key: Option<String>,
    /// Bounded controller-reported message text; untrusted.
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EventsSearchOutput {
    rows: Vec<EventRow>,
    /// Total rows matching the filters before pagination, within the
    /// bounded fetch window.
    total_matches: u64,
    /// Offset of the next page when more rows remain.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
    /// Present when the controller reports rows beyond the bounded scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    fetch_window_truncated: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum StatsReport {
    WanHourly,
    DpiApplications,
    /// Historical Internet activity attributed to clients by the controller.
    ClientWanHistory,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StatsQueryInput {
    /// Which bounded report to run.
    report: StatsReport,
    /// Positive window in hours; defaults to 24. Activity reports end at the
    /// latest completed UTC hour; wanHourly retains its window ending now.
    hours: Option<u32>,
    /// Positive number of top applications for the DPI report. Defaults to 10.
    #[schemars(range(min = 1))]
    top: Option<usize>,
    /// Fixed interval boundaries in epoch milliseconds. Supply both, on UTC
    /// hour boundaries, instead of hours, ending in the past.
    start_ms: Option<u64>,
    end_ms: Option<u64>,
    /// Positive client-history page size; defaults to 50.
    #[schemars(range(min = 1))]
    limit: Option<usize>,
    /// Client-history row offset. Reuse fixed timestamps across pages.
    offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
enum TrafficReadSource {
    Activity,
    Graph,
    Wan,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrafficReadInput {
    source: TrafficReadSource,
    /// Positive whole UTC hours; defaults to 24 ending at the latest completed hour.
    hours: Option<u32>,
    /// Fixed UTC hour boundaries in epoch milliseconds, instead of hours.
    start_ms: Option<u64>,
    end_ms: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TrafficReadOutput {
    source: TrafficReadSource,
    status: &'static str,
    start_ms: u64,
    end_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_in_content: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct WanSampleRow {
    /// Epoch milliseconds for the hour bucket.
    time: Option<u64>,
    tx_bytes: Option<f64>,
    rx_bytes: Option<f64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct TopApplicationRow {
    /// Numeric deep-packet-inspection application id.
    application_id: u32,
    /// Numeric deep-packet-inspection category id.
    category_id: u32,
    tx_bytes: u64,
    rx_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
struct StatsQueryOutput {
    /// The requested report; coverage says what data is actually available.
    report: &'static str,
    coverage: TrafficCoverage,
    counter_semantics: CounterSemantics,
    /// Valid application records before the requested top-N selection.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_applications: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wan_hourly: Option<Vec<WanSampleRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_applications: Option<Vec<TopApplicationRow>>,
    /// Internet activity totals, temporal evidence, and WAN reconciliation.
    #[serde(skip_serializing_if = "Option::is_none")]
    activity: Option<activity::ActivityDetails>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_errors: Vec<StatsSourceError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_errors_in_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activity_in_content: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct StatsSourceError {
    source: &'static str,
    error: String,
}

// ---------------------------------------------------------------------------
// Catalog projection
// ---------------------------------------------------------------------------

impl ToolSpec {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn catalog_tool(&self) -> Tool {
        match self.kind {
            ToolKind::NetworkOverview => tool::<EmptyInput, NetworkOverviewOutput>(self),
            ToolKind::ClientsSearch => tool::<ClientsSearchInput, ClientsSearchOutput>(self),
            ToolKind::ClientsContext => tool::<ClientSelectorInput, ClientContextOutput>(self),
            ToolKind::DevicesSearch => tool::<DevicesSearchInput, DevicesSearchOutput>(self),
            ToolKind::DevicesStatus => tool::<DeviceSelectorInput, DeviceStatusOutput>(self),
            ToolKind::PendingDevicesList => {
                tool::<PendingDevicesListInput, PendingDevicesListOutput>(self)
            }
            ToolKind::DevicesAdopt => tool::<DevicesAdoptInput, DevicesAdoptOutput>(self),
            ToolKind::DevicesRemove => tool::<DevicesRemoveInput, DevicesRemoveOutput>(self),
            ToolKind::FirewallRead => tool::<FirewallReadInput, FirewallReadOutput>(self),
            ToolKind::NetworksRead => tool::<NetworksReadInput, NetworksReadOutput>(self),
            ToolKind::NetworksList => tool::<NetworksListInput, ConfigurationResult>(self),
            ToolKind::NetworksStatus => tool::<NetworksStatusInput, ConfigurationResult>(self),
            ToolKind::NetworksConfigure => {
                tool::<NetworksConfigureInput, ConfigurationResult>(self)
            }
            ToolKind::WifiBroadcastsConfigure => {
                tool::<WifiBroadcastsConfigureInput, ConfigurationResult>(self)
            }
            ToolKind::RadiusProfilesList => {
                tool::<RadiusProfilesListInput, RadiusProfilesListOutput>(self)
            }
            ToolKind::NetworkSourceRead => {
                tool::<NetworkSourceReadInput, NetworkSourceReadOutput>(self)
            }
            ToolKind::NetworkInventoryList => {
                tool::<NetworkInventoryListInput, NetworkInventoryListOutput>(self)
            }
            ToolKind::NetworkSwitchingDetail => {
                tool::<NetworkSwitchingDetailInput, RecordOutput>(self)
            }
            ToolKind::NetworkInventoryDetail => {
                tool::<NetworkInventoryDetailInput, RecordOutput>(self)
            }
            ToolKind::NetworkPolicyList => {
                tool::<NetworkPolicyListInput, NetworkPolicyListOutput>(self)
            }
            ToolKind::NetworkPolicyDetail => {
                tool::<NetworkPolicyDetailInput, NetworkPolicyDetailOutput>(self)
            }
            ToolKind::AclRulesConfigure => {
                tool::<AclRulesConfigureInput, NetworkPolicyWriteOutput>(self)
            }
            ToolKind::FirewallPoliciesOrderingRead => {
                tool::<EmptyInput, NetworkPolicyDetailOutput>(self)
            }
            ToolKind::FirewallPoliciesOrderingConfigure => tool::<
                FirewallPolicyOrderingConfigureInput,
                NetworkPolicyWriteOutput<&'static str>,
            >(self),
            ToolKind::AclRulesOrderingRead => {
                tool::<AclRulesOrderingReadInput, NetworkPolicyDetailOutput>(self)
            }
            ToolKind::AclRulesOrderingConfigure => {
                tool::<AclRulesOrderingConfigureInput, NetworkPolicyWriteOutput>(self)
            }
            ToolKind::FirewallZonesConfigure => {
                tool::<FirewallZonesConfigureInput, NetworkPolicyWriteOutput>(self)
            }
            ToolKind::FirewallPoliciesConfigure => {
                tool::<FirewallPoliciesConfigureInput, NetworkPolicyWriteOutput>(self)
            }
            ToolKind::DnsPoliciesConfigure => {
                tool::<DnsPoliciesConfigureInput, NetworkPolicyWriteOutput>(self)
            }
            ToolKind::TrafficListsConfigure => {
                tool::<TrafficListsConfigureInput, NetworkPolicyWriteOutput>(self)
            }
            ToolKind::WifiBroadcastsList => {
                tool::<WifiBroadcastsListInput, WifiBroadcastsListOutput>(self)
            }
            ToolKind::WifiBroadcastsStatus => {
                tool::<WifiBroadcastsStatusInput, Map<String, Value>>(self)
            }
            ToolKind::CamerasSearch => tool::<CamerasSearchInput, CamerasSearchOutput>(self),
            ToolKind::CamerasStatus => tool::<CameraStatusInput, CameraView>(self),
            ToolKind::ProtectDevicesList => {
                tool::<ProtectDevicesListInput, ProtectDevicesListOutput>(self)
            }
            ToolKind::ProtectDevicesStatus => {
                tool::<ProtectDevicesStatusInput, ProtectDevicesStatusOutput>(self)
            }
            ToolKind::ProtectDevicesAction => {
                tool::<ProtectDevicesActionInput, ProtectDevicesActionOutput>(self)
            }
            ToolKind::ProtectDevicesSettingsUpdate => {
                tool::<ProtectDevicesSettingsUpdateInput, ProtectDevicesSettingsUpdateOutput>(self)
            }
            ToolKind::ProtectArmProfilesList => {
                tool::<ProtectArmProfilesListInput, ProtectArmProfilesListOutput>(self)
            }
            ToolKind::ProtectArmProfilesConfigure => {
                tool::<ProtectArmProfilesConfigureInput, ProtectArmOperationOutput>(self)
            }
            ToolKind::ProtectAlarmsAction => {
                tool::<ProtectAlarmsActionInput, ProtectArmOperationOutput>(self)
            }
            ToolKind::ProtectUsersList => {
                tool::<ProtectUsersListInput, ProtectUsersListOutput>(self)
            }
            ToolKind::ProtectUsersStatus => {
                tool::<ProtectUsersStatusInput, ProtectUsersStatusOutput>(self)
            }
            ToolKind::CamerasPosTransaction => {
                tool::<CameraPosTransactionInput, CameraPosTransactionOutput>(self)
            }
            ToolKind::ProtectViewersList => {
                tool::<ProtectViewsListInput, ProtectViewersListOutput>(self)
            }
            ToolKind::ProtectViewersStatus => {
                tool::<ProtectViewerStatusInput, ProtectViewerStatusOutput>(self)
            }
            ToolKind::ProtectViewersSettingsUpdate => {
                tool::<ProtectViewerSettingsUpdateInput, ProtectViewerSettingsUpdateOutput>(self)
            }
            ToolKind::ProtectLiveviewsList => {
                tool::<ProtectViewsListInput, ProtectLiveviewsListOutput>(self)
            }
            ToolKind::ProtectLiveviewsStatus => {
                tool::<ProtectLiveviewStatusInput, ProtectLiveviewStatusOutput>(self)
            }
            ToolKind::ProtectLiveviewsConfigure => {
                tool::<ProtectLiveviewsConfigureInput, ProtectLiveviewsConfigureOutput>(self)
            }
            ToolKind::CamerasSettingsRead => {
                tool::<CameraSelectorInput, CameraSettingsReadOutput>(self)
            }
            ToolKind::CamerasSettingsUpdate => {
                tool::<CameraSettingsUpdateInput, CameraSettingsOutput>(self)
            }
            ToolKind::CamerasSnapshot => tool::<CameraSnapshotInput, CameraSnapshotOutput>(self),
            ToolKind::CamerasPtzControl => tool::<CameraPtzInput, CameraPtzOutput>(self),
            ToolKind::CamerasMicrophoneDisable => {
                tool::<CameraDisableMicInput, CameraDisableMicOutput>(self)
            }
            ToolKind::ProtectAssetsList => {
                tool::<ProtectAssetsListInput, ProtectAssetsListOutput>(self)
            }
            ToolKind::ProtectAssetsUpload => {
                tool::<ProtectAssetUploadInput, ProtectAssetUploadOutput>(self)
            }
            ToolKind::CamerasStreamsList => {
                tool::<CameraStreamsListInput, CameraStreamsListOutput>(self)
            }
            ToolKind::CamerasStreamsUpdate => {
                tool::<CameraStreamsUpdateInput, CameraStreamsUpdateOutput>(self)
            }
            ToolKind::CamerasTalkbackStart => {
                tool::<CameraTalkbackInput, CameraTalkbackOutput>(self)
            }
            ToolKind::ProtectOverview => tool::<ProtectOverviewInput, ProtectOverviewResult>(self),
            ToolKind::ProtectEvents => tool::<ProtectEventsInput, ProtectEventsOutput>(self),
            ToolKind::ProtectUpdates => tool::<ProtectUpdatesInput, ProtectUpdatesOutput>(self),
            ToolKind::ProtectEventThumbnail => {
                tool::<ProtectEventThumbnailInput, ProtectEventThumbnailOutput>(self)
            }
            ToolKind::WifiDiagnose => tool::<WifiDiagnoseInput, WifiDiagnoseOutput>(self),
            ToolKind::EventsSearch => tool::<EventsSearchInput, EventsSearchOutput>(self),
            ToolKind::EventsRead => {
                tool::<system_log::EventsReadInput, system_log::EventsReadOutput>(self)
            }
            ToolKind::StatsQuery => tool::<StatsQueryInput, StatsQueryOutput>(self),
            ToolKind::TrafficRead => tool::<TrafficReadInput, TrafficReadOutput>(self),
            ToolKind::WlansList | ToolKind::PortForwardsList => {
                tool::<LegacyConfigurationListInput, LegacyConfigurationResult>(self)
            }
            ToolKind::WlansStatus | ToolKind::PortForwardsStatus => {
                tool::<LegacyConfigurationStatusInput, LegacyConfigurationResult>(self)
            }
            ToolKind::WlanGroupsList => {
                tool::<WlanGroupsListInput, LegacyConfigurationResult>(self)
            }
            ToolKind::WlansConfigure => {
                tool::<WlansConfigureInput, LegacyConfigurationResult>(self)
            }
            ToolKind::WlansUpdate => tool::<WlansUpdateInput, WlansUpdateOutput>(self),
            ToolKind::ClientsControl => tool::<ClientsControlInput, ClientsControlOutput>(self),
            ToolKind::DevicesControl => tool::<DevicesControlInput, DevicesControlOutput>(self),
            ToolKind::GuestsStatus => tool::<GuestClientInput, GuestStatusOutput>(self),
            ToolKind::GuestsAuthorize => tool::<GuestsAuthorizeInput, GuestsAuthorizeOutput>(self),
            ToolKind::GuestsUnauthorize => {
                tool::<GuestsUnauthorizeInput, GuestsAuthorizeOutput>(self)
            }
            ToolKind::PortForwardsConfigure => {
                tool::<PortForwardConfigureInput, LegacyConfigurationResult>(self)
            }
            ToolKind::PortForwardsUpdate => {
                tool::<PortForwardsUpdateInput, PortForwardsUpdateOutput>(self)
            }
            ToolKind::FirewallPoliciesUpdate => {
                tool::<FirewallPoliciesUpdateInput, FirewallPoliciesUpdateOutput>(self)
            }
            ToolKind::FirewallPoliciesDelete => {
                tool::<FirewallPoliciesDeleteInput, FirewallPoliciesDeleteOutput>(self)
            }
            ToolKind::VouchersSearch => tool::<VouchersSearchInput, VouchersSearchOutput>(self),
            ToolKind::VouchersStatus => tool::<VoucherIdInput, VoucherReadView>(self),
            ToolKind::VouchersRevoke => tool::<VoucherRevokeInput, VoucherRevokeOutput>(self),
            ToolKind::VouchersRevokeMatching => {
                tool::<VouchersRevokeMatchingInput, VouchersRevokeMatchingOutput>(self)
            }
            ToolKind::VouchersCreate => tool::<VouchersCreateInput, VouchersCreateOutput>(self),
        }
    }
}

fn tool<I: JsonSchema, O: JsonSchema>(spec: &ToolSpec) -> Tool {
    Tool::new(
        Cow::Borrowed(spec.name),
        Cow::Borrowed(spec.description),
        Arc::new(schema_object::<I>()),
    )
    .with_raw_output_schema(Arc::new(schema_object::<O>()))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(spec.behavior.read_only)
            .destructive(spec.behavior.destructive)
            .idempotent(spec.behavior.idempotent)
            .open_world(spec.behavior.open_world),
    )
    .with_meta(action_metadata(spec.behavior))
}

fn action_metadata(behavior: ToolBehavior) -> MetaObject {
    let input_sensitivity = if behavior.input_sensitive {
        "sensitive"
    } else {
        "operational"
    };
    let return_sensitivity = if behavior.result_sensitive {
        "sensitive"
    } else {
        "operational"
    };
    let value = serde_json::json!({
        ACTION_METADATA_KEY: {
            "inputMetadata": {
                "destination": "internal",
                "sensitivity": input_sensitivity
            },
            "returnMetadata": {
                "source": "first-party",
                "sensitivity": return_sensitivity
            },
            "outcome": behavior.outcome,
            "requiresReview": behavior.requires_review
        }
    });
    match value {
        Value::Object(object) => MetaObject(object),
        _ => unreachable!("static action metadata is an object"),
    }
}

fn schema_object<T: JsonSchema>() -> Map<String, Value> {
    let mut schema =
        serde_json::to_value(schema_for!(T)).expect("Rust-derived schema must serialize");
    normalize_portable_schema(&mut schema, None);
    match schema {
        Value::Object(object) => object,
        _ => unreachable!("root JSON schema is an object"),
    }
}

/// Publish semantically equivalent object schemas where strict MCP clients do
/// not consume legal JSON Schema boolean schemas or array-valued type unions.
fn normalize_portable_schema(schema: &mut Value, parent_keyword: Option<&str>) {
    if let Value::Bool(accepts_everything) = schema {
        if parent_keyword.is_some_and(|keyword| BOOLEAN_SCHEMA_KEYWORDS.contains(&keyword)) {
            return;
        }
        *schema = if *accepts_everything {
            json!({
                "anyOf": JSON_SCHEMA_TYPES
                    .iter()
                    .map(|name| json!({"type": name}))
                    .collect::<Vec<_>>()
            })
        } else {
            json!({"not": {}})
        };
        return;
    }

    let Some(object) = schema.as_object_mut() else {
        return;
    };
    let portable_types = object.get("type").and_then(|value| {
        let values = value.as_array()?;
        let mut types: Vec<String> = Vec::with_capacity(values.len());
        for value in values {
            let name = value.as_str()?;
            if !JSON_SCHEMA_TYPES.contains(&name) || types.iter().any(|item| item == name) {
                return None;
            }
            types.push(name.to_owned());
        }
        (!types.is_empty()).then_some(types)
    });
    if let Some(types) = portable_types {
        object.remove("type");
        let branches = Value::Array(
            types
                .into_iter()
                .map(|name| json!({"type": name}))
                .collect(),
        );
        if object.contains_key("anyOf") {
            object
                .entry("allOf")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .expect("a generated allOf schema must be an array")
                .push(json!({"anyOf": branches}));
        } else {
            object.insert("anyOf".to_owned(), branches);
        }
    }

    for keyword in [
        "$defs",
        "definitions",
        "properties",
        "patternProperties",
        "dependentSchemas",
        "dependencies",
    ] {
        if let Some(children) = object.get_mut(keyword).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                normalize_portable_schema(child, Some(keyword));
            }
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for child in children {
                normalize_portable_schema(child, Some(keyword));
            }
        }
    }
    if let Some(items) = object.get_mut("items") {
        if let Some(children) = items.as_array_mut() {
            for child in children {
                normalize_portable_schema(child, Some("items"));
            }
        } else {
            normalize_portable_schema(items, Some("items"));
        }
    }
    for keyword in [
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "contentSchema",
        "additionalProperties",
        "unevaluatedProperties",
        "additionalItems",
        "unevaluatedItems",
    ] {
        if let Some(child) = object.get_mut(keyword) {
            normalize_portable_schema(child, Some(keyword));
        }
    }
}

const BOOLEAN_SCHEMA_KEYWORDS: [&str; 4] = [
    "additionalProperties",
    "unevaluatedProperties",
    "additionalItems",
    "unevaluatedItems",
];
const JSON_SCHEMA_TYPES: [&str; 7] = [
    "null", "boolean", "object", "array", "number", "string", "integer",
];

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

impl UnifiMcp {
    /// Execute one registered tool by catalog name.
    ///
    /// This is the complete dispatch path used by the MCP handler; the match
    /// over [`ToolKind`] is exhaustive, so a registered tool cannot lack a
    /// handler.
    ///
    /// # Errors
    ///
    /// Returns a caller error for unknown names or schema-violating arguments.
    /// Upstream faults preserve the complete accepted controller error body.
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive dispatch states the handler for every registered tool"
    )]
    pub async fn call(
        &self,
        params: &CallToolRequestParams,
        _principal: Option<&IdentityPrincipal>,
    ) -> Result<CallToolResult, McpError> {
        let spec = crate::registry::tools_for_surface(self.surface())
            .find(|spec| spec.name == params.name.as_ref())
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("unknown tool {:?}; tools/list is the catalog", params.name),
                    None,
                )
            })?;
        let result = match spec.kind {
            ToolKind::NetworkOverview => self.network_overview(params).await,
            ToolKind::ClientsSearch => self.clients_search(params).await,
            ToolKind::ClientsContext => self.clients_context(params).await,
            ToolKind::DevicesSearch => self.devices_search(params).await,
            ToolKind::DevicesStatus => self.devices_status(params).await,
            ToolKind::PendingDevicesList => self.pending_devices_list(params).await,
            ToolKind::DevicesAdopt => self.devices_adopt(params).await,
            ToolKind::DevicesRemove => self.devices_remove(params).await,
            ToolKind::FirewallRead => self.firewall_read(params).await,
            ToolKind::NetworksRead => self.networks_read(params).await,
            ToolKind::NetworksList => self.networks_list(params).await,
            ToolKind::NetworksStatus => self.networks_status(params).await,
            ToolKind::NetworksConfigure => self.networks_configure(params).await,
            ToolKind::WifiBroadcastsConfigure => self.wifi_broadcasts_configure(params).await,
            ToolKind::RadiusProfilesList => self.radius_profiles_list(params).await,
            ToolKind::NetworkSourceRead => self.network_source_read(params).await,
            ToolKind::NetworkInventoryList => self.network_inventory_list(params).await,
            ToolKind::NetworkInventoryDetail => self.network_inventory_detail(params).await,
            ToolKind::NetworkSwitchingDetail => self.network_switching_detail(params).await,
            ToolKind::NetworkPolicyList => self.network_policy_list(params).await,
            ToolKind::NetworkPolicyDetail => self.network_policy_detail(params).await,
            ToolKind::AclRulesConfigure => self.acl_rules_configure(params).await,
            ToolKind::FirewallPoliciesOrderingRead => {
                self.firewall_policies_ordering_read(params).await
            }
            ToolKind::FirewallPoliciesOrderingConfigure => {
                self.firewall_policies_ordering_configure(params).await
            }
            ToolKind::AclRulesOrderingRead => self.acl_rules_ordering_read(params).await,
            ToolKind::AclRulesOrderingConfigure => self.acl_rules_ordering_configure(params).await,
            ToolKind::FirewallZonesConfigure => self.firewall_zones_configure(params).await,
            ToolKind::FirewallPoliciesConfigure => self.firewall_policies_configure(params).await,
            ToolKind::DnsPoliciesConfigure => self.dns_policies_configure(params).await,
            ToolKind::TrafficListsConfigure => self.traffic_lists_configure(params).await,
            ToolKind::WifiBroadcastsList => self.wifi_broadcasts_list(params).await,
            ToolKind::WifiBroadcastsStatus => self.wifi_broadcasts_status(params).await,
            ToolKind::CamerasSearch => self.cameras_search(params).await,
            ToolKind::CamerasStatus => self.cameras_status(params).await,
            ToolKind::ProtectDevicesList => self.protect_devices_list(params).await,
            ToolKind::ProtectDevicesStatus => self.protect_devices_status(params).await,
            ToolKind::ProtectDevicesAction => self.protect_devices_action(params).await,
            ToolKind::ProtectDevicesSettingsUpdate => {
                self.protect_devices_settings_update(params).await
            }
            ToolKind::ProtectArmProfilesList => self.protect_arm_profiles_list(params).await,
            ToolKind::ProtectArmProfilesConfigure => {
                self.protect_arm_profiles_configure(params).await
            }
            ToolKind::ProtectAlarmsAction => self.protect_alarms_action(params).await,
            ToolKind::ProtectUsersList => self.protect_users_list(params).await,
            ToolKind::ProtectUsersStatus => self.protect_users_status(params).await,
            ToolKind::CamerasPosTransaction => self.cameras_pos_transaction(params).await,
            ToolKind::ProtectViewersList => self.protect_viewers_list(params).await,
            ToolKind::ProtectViewersStatus => self.protect_viewers_status(params).await,
            ToolKind::ProtectViewersSettingsUpdate => {
                self.protect_viewers_settings_update(params).await
            }
            ToolKind::ProtectLiveviewsList => self.protect_liveviews_list(params).await,
            ToolKind::ProtectLiveviewsStatus => self.protect_liveviews_status(params).await,
            ToolKind::ProtectLiveviewsConfigure => self.protect_liveviews_configure(params).await,
            ToolKind::CamerasSettingsRead => self.cameras_settings_read(params).await,
            ToolKind::CamerasSettingsUpdate => self.cameras_settings_update(params).await,
            ToolKind::CamerasSnapshot => self.cameras_snapshot(params).await,
            ToolKind::CamerasPtzControl => self.cameras_ptz_control(params).await,
            ToolKind::CamerasMicrophoneDisable => self.cameras_microphone_disable(params).await,
            ToolKind::ProtectAssetsList => self.protect_assets_list(params).await,
            ToolKind::ProtectAssetsUpload => self.protect_assets_upload(params).await,
            ToolKind::CamerasStreamsList => self.cameras_streams_list(params).await,
            ToolKind::CamerasStreamsUpdate => self.cameras_streams_update(params).await,
            ToolKind::CamerasTalkbackStart => self.cameras_talkback_start(params).await,
            ToolKind::ProtectOverview => self.protect_overview(params).await,
            ToolKind::ProtectEvents => self.protect_events_search(params).await,
            ToolKind::ProtectUpdates => self.protect_updates(params).await,
            ToolKind::ProtectEventThumbnail => self.protect_event_thumbnail(params).await,
            ToolKind::WifiDiagnose => self.wifi_diagnose(params).await,
            ToolKind::EventsSearch => self.events_search(params).await,
            ToolKind::EventsRead => system_log::read(self, params).await,
            ToolKind::StatsQuery => self.stats_query(params).await,
            ToolKind::TrafficRead => self.traffic_read(params).await,
            ToolKind::WlansList => self.wlans_list(params).await,
            ToolKind::WlansStatus => self.wlans_status(params).await,
            ToolKind::WlanGroupsList => self.wlan_groups_list(params).await,
            ToolKind::WlansConfigure => self.wlans_configure(params).await,
            ToolKind::WlansUpdate => self.wlans_update(params).await,
            ToolKind::ClientsControl => self.clients_control(params).await,
            ToolKind::DevicesControl => self.devices_control(params).await,
            ToolKind::GuestsStatus => self.guests_status(params).await,
            ToolKind::GuestsAuthorize => self.guests_authorize(params).await,
            ToolKind::GuestsUnauthorize => self.guests_unauthorize(params).await,
            ToolKind::PortForwardsList => self.port_forward_list(params).await,
            ToolKind::PortForwardsStatus => self.port_forward_status(params).await,
            ToolKind::PortForwardsConfigure => self.port_forward_configure(params).await,
            ToolKind::PortForwardsUpdate => self.port_forwards_update(params).await,
            ToolKind::FirewallPoliciesUpdate => self.firewall_policies_update(params).await,
            ToolKind::FirewallPoliciesDelete => self.firewall_policies_delete(params).await,
            ToolKind::VouchersSearch => self.vouchers_search(params).await,
            ToolKind::VouchersStatus => self.vouchers_status(params).await,
            ToolKind::VouchersRevoke => self.vouchers_revoke(params).await,
            ToolKind::VouchersRevokeMatching => self.vouchers_revoke_matching(params).await,
            ToolKind::VouchersCreate => self.vouchers_create(params).await,
        };
        result.map(|result| trust_annotated(result, spec.behavior))
    }

    async fn network_overview(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        parse::<EmptyInput>(params)?;
        let info = self.integration().info().await.map_err(api_error)?;
        let subsystems = self
            .legacy()
            .site_health(self.legacy_site())
            .await
            .map_err(api_error)?
            .into_iter()
            .filter_map(|row| {
                Some(SubsystemHealth {
                    subsystem: row.subsystem?,
                    status: row.status.unwrap_or_else(|| "unknown".to_owned()),
                })
            })
            .collect();
        let (window_start, window_end) = log_window(DEFAULT_EVENT_WINDOW_HOURS)?;
        let query = SystemLogQuery::new(window_start, window_end, 1).map_err(api_error)?;
        let total = self
            .legacy()
            .system_log(self.legacy_site(), &query)
            .await
            .map_err(system_log::read_error)?
            .total_element_count;
        let high_severity = self
            .legacy()
            .system_log(self.legacy_site(), &query.high_severity())
            .await
            .map_err(system_log::read_error)?
            .total_element_count;
        let site_id = self.site_id().await?;
        let devices = self
            .integration()
            .devices(&site_id, count_probe())
            .await
            .map_err(api_error)?
            .total_count;
        let clients = self
            .integration()
            .clients(&site_id, count_probe())
            .await
            .map_err(api_error)?
            .total_count;
        structured(NetworkOverviewOutput {
            controller: self.controller_name().to_owned(),
            application_version: info.application_version,
            subsystems,
            recent_events: RecentEventCounts {
                window_start,
                window_end,
                total,
                high_severity,
            },
            devices,
            clients,
        })
    }
}

impl UnifiMcp {
    async fn clients_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ClientsSearchInput>(params)?;
        validate_page(input.limit)?;
        let query = validate_filter(input.query.as_deref())?;
        let ssid = validate_filter(input.ssid.as_deref())?;

        let mut clients = self
            .legacy()
            .active_clients(self.legacy_site())
            .await
            .map_err(api_error)?;
        clients.retain(|client| {
            client_matches(client, query.as_deref(), ssid.as_deref(), input.vlan)
                && connection_matches(client, input.connection)
        });
        sort_clients(&mut clients);

        let total = clients.len();
        let offset = input.offset;
        let page: Vec<ActiveClient> = clients.into_iter().skip(offset).take(input.limit).collect();
        let next_offset = next_offset(offset, page.len(), total);

        // Resolve access point names only when a returned row actually
        // carries an access point to resolve.
        let (ap_names, ap_lookup_truncated) = if page.iter().any(|client| client.ap_mac.is_some()) {
            self.device_names_by_mac().await?
        } else {
            (std::collections::HashMap::new(), false)
        };
        let rows = page
            .into_iter()
            .map(|client| client_row(client, &ap_names, input.detail))
            .collect();
        structured(ClientsSearchOutput {
            counter_semantics: (input.detail == DetailLevel::Full).then(CounterSemantics::client),
            clients: rows,
            total_matches: total as u64,
            next_offset,
            ap_lookup_truncated: ap_lookup_truncated.then_some(true),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "bounded client joins and their complete output projection"
    )]
    async fn clients_context(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ClientSelectorInput>(params)?;
        let selector = input.client.trim();
        if selector.is_empty() || selector.len() > MAXIMUM_QUERY_LENGTH {
            return Err(McpError::invalid_params(
                "client selector must be a MAC, name, or hostname",
                None,
            ));
        }
        let clients = self
            .legacy()
            .active_clients(self.legacy_site())
            .await
            .map_err(api_error)?;
        let mut matches = select_clients(clients, selector);
        let client = match matches.len() {
            0 => {
                return Err(McpError::invalid_params(
                    "no connected client matches the selector; use clients.search to \
                     list connected clients and select by MAC",
                    None,
                ));
            }
            1 => matches.remove(0),
            count => {
                return Err(McpError::invalid_params(
                    format!("{count} connected clients match; select by MAC"),
                    None,
                ));
            }
        };

        let (ap_names, ap_lookup_truncated) = if client.ap_mac.is_some() {
            self.device_names_by_mac().await?
        } else {
            (std::collections::HashMap::new(), false)
        };
        let client_mac = client.mac.as_deref().map(normalize_mac);
        let (window_start, window_end) = log_window(DEFAULT_EVENT_WINDOW_HOURS)?;
        let query =
            SystemLogQuery::new(window_start, window_end, EVENT_SCAN_LIMIT).map_err(api_error)?;
        let scanned_events = self
            .legacy()
            .system_log(self.legacy_site(), &query)
            .await
            .map_err(system_log::read_error)?;
        let mut recent_events_truncated = scanned_events.has_more();
        let mut matching_events: Vec<_> = scanned_events
            .data
            .into_iter()
            .map(event_row)
            .filter(|event| {
                event.client_mac.as_deref().map(normalize_mac) == client_mac
                    && client_mac.is_some()
                    && (window_start..=window_end).contains(&event.time)
            })
            .collect();
        matching_events.sort_by_key(|event| std::cmp::Reverse(event.time));
        recent_events_truncated |= matching_events.len() > CONTEXT_EVENT_LIMIT;
        let recent_events = matching_events
            .into_iter()
            .take(CONTEXT_EVENT_LIMIT)
            .map(|event| ClientEvent {
                time: Some(event.time),
                key: event.key,
                message: event.message,
            })
            .collect();

        let ap_name = client
            .ap_mac
            .as_deref()
            .and_then(|mac| ap_names.get(&normalize_mac(mac)).cloned());
        let (tx_bytes, rx_bytes, counter_coverage) = client_counters(&client);
        structured(ClientContextOutput {
            counter_coverage,
            counter_semantics: CounterSemantics::client(),
            name: client.name.clone().or_else(|| client.hostname.clone()),
            hostname: client.hostname,
            mac: client.mac,
            oui: client.oui,
            connection: connection_word(client.is_wired),
            ssid: client.essid,
            vlan: client.vlan,
            network: client.network,
            ap_name,
            ap_mac: client.ap_mac,
            channel: client.channel,
            radio: client.radio,
            signal_dbm: client.signal,
            rssi: client.rssi,
            uptime_seconds: client.uptime,
            last_seen: client.last_seen,
            ip: client.ip,
            use_fixed_ip: client.use_fixedip,
            fixed_ip: client.fixed_ip,
            tx_bytes,
            rx_bytes,
            recent_events,
            recent_events_truncated: recent_events_truncated.then_some(true),
            ap_lookup_truncated: ap_lookup_truncated.then_some(true),
        })
    }

    async fn devices_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<DevicesSearchInput>(params)?;
        validate_page(input.limit)?;
        let query = validate_filter(input.query.as_deref())?;
        let state = validate_filter(input.state.as_deref())?;

        let (mut devices, inventory_truncated) = self.device_inventory().await?;
        devices.retain(|device| device_matches(device, query.as_deref(), state.as_deref()));
        devices.sort_by(|left, right| {
            sort_key(left.name.as_deref())
                .cmp(&sort_key(right.name.as_deref()))
                .then_with(|| left.id.cmp(&right.id))
        });

        let total = devices.len();
        let offset = input.offset;
        let rows: Vec<DeviceRow> = devices
            .into_iter()
            .skip(offset)
            .take(input.limit)
            .map(device_row)
            .collect();
        let next_offset = next_offset(offset, rows.len(), total);
        structured(DevicesSearchOutput {
            devices: rows,
            total_matches: total as u64,
            next_offset,
            inventory_truncated: inventory_truncated.then_some(true),
        })
    }

    async fn pending_devices_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<PendingDevicesListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        if input
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 2048)
        {
            return Err(McpError::invalid_params(
                "filter must be at most 2048 bytes",
                None,
            ));
        }
        let (page, response) = self
            .integration()
            .pending_devices(
                PageRequest {
                    offset: input.offset,
                    limit: integration_limit(input.limit),
                },
                input.filter.as_deref(),
            )
            .await
            .map_err(api_error)?;
        let count = page.data.len() as u64;
        if page.offset != input.offset
            || page.limit == 0
            || page.limit > u64::from(integration_limit(input.limit))
            || count > page.limit
            || page.count != count
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "pending device page reported offset {}, limit {}, count {}, and {} rows for requested offset {} and limit {}",
                    page.offset, page.limit, page.count, count, input.offset, input.limit
                ),
            ));
        }
        let next = input
            .offset
            .checked_add(count)
            .ok_or_else(|| page_validation_error(&response, "pending device offset overflow"))?;
        if (count > 0 && next > page.total_count)
            || (next < page.total_count && page.data.is_empty())
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "pending device page through offset {next} conflicts with reported total {}",
                    page.total_count
                ),
            ));
        }
        pending_devices_list_result(PendingDevicesListOutput {
            page_counts: PageCounts {
                requested_limit: input.limit,
                effective_limit: page.limit,
                returned: page.data.len(),
            },
            devices: Some(page.data),
            devices_in_content: None,
            page_metadata: Some(controller_page_metadata(&response)?),
            page_metadata_in_content: None,
            offset: page.offset,
            limit: page.limit,
            count: page.count,
            total_count: page.total_count,
            next_offset: (next < page.total_count).then_some(next),
        })
    }

    async fn devices_adopt(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<DevicesAdoptInput>(params)?;
        if input.mac_address.trim().is_empty()
            || input.mac_address.len() > 64
            || input.mac_address.chars().any(char::is_control)
        {
            return Err(McpError::invalid_params(
                "macAddress must be a nonempty address of at most 64 bytes",
                None,
            ));
        }
        let mut output = DevicesAdoptOutput {
            mac_address: input.mac_address,
            ignore_device_limit: input.ignore_device_limit,
            submitted: false,
            accepted: None,
            accepted_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return structured(output);
        }
        let site_id = self.site_id().await?;
        let accepted = self
            .integration()
            .adopt_device(&site_id, &output.mac_address, output.ignore_device_limit)
            .await
            .map_err(api_error)?;
        let accepted_id = accepted
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        output.submitted = true;
        output.accepted = Some(accepted);
        if let Some(id) = accepted_id {
            let budget = self
                .request_timeout()
                .saturating_sub(started.elapsed())
                .saturating_sub(DEVICE_LIFECYCLE_RESPONSE_RESERVE)
                .min(DEVICE_LIFECYCLE_READBACK_BUDGET);
            if budget.is_zero() {
                output.readback_error =
                    Some("device readback skipped near request deadline".to_owned());
            } else {
                match tokio::time::timeout(
                    budget,
                    self.integration().device_detail_raw(&site_id, &id),
                )
                .await
                {
                    Ok(Ok(after)) => {
                        output.verified =
                            Some(after.get("id").and_then(Value::as_str) == Some(id.as_str()));
                        output.after = Some(after);
                    }
                    Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                    Err(_) => output.readback_error = Some("device readback timed out".to_owned()),
                }
            }
        } else {
            output.readback_error =
                Some("accepted device record had no id for readback".to_owned());
        }
        devices_adopt_result(output)
    }

    async fn devices_remove(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<DevicesRemoveInput>(params)?;
        if input.device_id.trim().is_empty()
            || input.device_id.len() > 256
            || matches!(input.device_id.as_str(), "." | "..")
        {
            return Err(McpError::invalid_params(
                "deviceId must be a nonempty id of at most 256 bytes",
                None,
            ));
        }
        let mut output = DevicesRemoveOutput {
            device_id: input.device_id,
            warning: "removing an online device resets it to factory defaults",
            submitted: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            after: None,
            after_in_content: None,
            verified_absent: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return structured(output);
        }
        let site_id = self.site_id().await?;
        let (status, body) = self
            .integration()
            .remove_device(&site_id, &output.device_id)
            .await
            .map_err(api_error)?;
        output.submitted = true;
        output.response_status = Some(status);
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(DEVICE_LIFECYCLE_RESPONSE_RESERVE)
            .min(DEVICE_LIFECYCLE_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("device readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(
                budget,
                self.integration()
                    .device_detail_raw(&site_id, &output.device_id),
            )
            .await
            {
                Ok(Ok(after)) => {
                    output.after = Some(after);
                    output.verified_absent = Some(false);
                }
                Ok(Err(error @ ApiError::Status { status: 404, .. })) => {
                    output.verified_absent = Some(true);
                    output.readback_error = Some(error.to_string());
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => output.readback_error = Some("device readback timed out".to_owned()),
            }
        }
        devices_remove_result(output)
    }

    async fn devices_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<DeviceSelectorInput>(params)?;
        let selector = input.device.trim();
        if selector.is_empty() || selector.len() > MAXIMUM_QUERY_LENGTH {
            return Err(McpError::invalid_params(
                "device selector must be an id, MAC, or name",
                None,
            ));
        }
        let (inventory, inventory_truncated) = self.device_inventory().await?;
        let (mut matches, identifier_tier) = select_devices(&inventory, selector);
        let device = match matches.len() {
            0 => {
                return Err(McpError::invalid_params(
                    if inventory_truncated {
                        "no adopted device matches the selector within the scanned \
                         inventory ceiling; use devices.search and select by id or MAC"
                    } else {
                        "no adopted device matches the selector; use devices.search \
                         and select by id or MAC"
                    },
                    None,
                ));
            }
            1 => matches.remove(0),
            count => {
                return Err(McpError::invalid_params(
                    format!("{count} devices match; select by id or MAC"),
                    None,
                ));
            }
        };
        // Ids and MACs are globally unique; a name matched only within a
        // truncated prefix cannot be proven unique across the catalog.
        if inventory_truncated && !identifier_tier {
            return Err(McpError::invalid_params(
                "a name selector cannot be proven unique on a truncated inventory;                  select by id or MAC",
                None,
            ));
        }

        let site_id = self.site_id().await?;
        let detail = self
            .integration()
            .device_detail(&site_id, &device.id)
            .await
            .map_err(api_error)?;
        // Statistics are best-effort by contract: an offline device still
        // reports identity and state, with `statistics` absent.
        let (statistics, statistics_error) = match self
            .integration()
            .device_statistics(&site_id, &device.id)
            .await
        {
            Ok(statistics) => (Some(statistics_view(&statistics)), None),
            Err(error) => (None, Some(error)),
        };

        let interfaces = detail.interfaces.unwrap_or_default();
        let ports_truncated = interfaces.ports.len() > PORT_TABLE_CEILING;
        let radios_truncated = interfaces.radios.len() > RADIO_TABLE_CEILING;
        structured(DeviceStatusOutput {
            id: detail.id,
            name: detail.name,
            model: detail.model,
            mac: detail.mac_address,
            ip: detail.ip_address,
            state: detail.state,
            firmware_version: detail.firmware_version,
            statistics,
            statistics_error: statistics_error.as_ref().map(ToString::to_string),
            ports: interfaces
                .ports
                .into_iter()
                .take(PORT_TABLE_CEILING)
                .map(|port| DevicePortRow {
                    idx: port.idx,
                    state: port.state,
                    connector: port.connector,
                    speed_mbps: port.speed_mbps,
                })
                .collect(),
            ports_truncated: ports_truncated.then_some(true),
            radios: interfaces
                .radios
                .into_iter()
                .take(RADIO_TABLE_CEILING)
                .map(|radio| DeviceRadioRow {
                    wlan_standard: radio.wlan_standard,
                    frequency_ghz: radio.frequency_g_hz,
                    channel: radio.channel,
                    channel_width_mhz: radio.channel_width_m_hz,
                })
                .collect(),
            radios_truncated: radios_truncated.then_some(true),
        })
    }

    /// Every camera on the console, fetched once and reduced to the view.
    ///
    /// The availability probe runs first and its answer is not merged into the
    /// result: a console without the integration API is refused, never
    /// returned as a console with no cameras. That distinction is the whole
    /// reason the probe exists.
    #[expect(
        clippy::too_many_lines,
        reason = "inventory combines the required public source with optional local state"
    )]
    async fn camera_inventory(
        &self,
        scope: CameraInventoryScope,
    ) -> Result<CameraInventory, McpError> {
        let protect = self.protect();
        let application_version = match protect.availability().await.map_err(api_error)? {
            ProtectAvailability::Available {
                application_version,
            } => application_version,
            ProtectAvailability::Unsupported { status, response } => {
                return Err(api_error(ApiError::Status {
                    status,
                    message: response,
                }));
            }
        };
        let (public, public_response) = protect.cameras_with_response().await.map_err(api_error)?;

        let local = if scope == CameraInventoryScope::Public {
            None
        } else {
            self.protect_local()
        };
        let mut local_camera_inventory = None;
        let mut local_error = None;
        let mut local_response = None;
        let local_bootstrap = if let Some(local) = local {
            match scope {
                CameraInventoryScope::Public => None,
                CameraInventoryScope::CameraNames => {
                    match local.protect_camera_inventory_with_response().await {
                        Ok((cameras, response)) => {
                            local_response = Some(response);
                            local_camera_inventory = Some(cameras);
                        }
                        Err(error) => local_error = Some(error),
                    }
                    None
                }
                CameraInventoryScope::Full => match local.protect_bootstrap_with_response().await {
                    Ok((bootstrap, response)) => {
                        local_response = Some(response);
                        Some(bootstrap)
                    }
                    Err(error) => {
                        local_error = Some(error);
                        None
                    }
                },
            }
        } else {
            None
        };
        let local_cameras = local_bootstrap
            .as_ref()
            .map(|bootstrap| &bootstrap.cameras)
            .or(local_camera_inventory.as_ref());
        let local_by_id: BTreeMap<&str, &ProtectLocalCamera> = local_cameras
            .map(|cameras| {
                cameras
                    .iter()
                    .map(|camera| (camera.id.as_str(), camera))
                    .collect()
            })
            .unwrap_or_default();
        let local_state = match (local_cameras, local.is_some()) {
            (Some(_), _)
                if public.len() == local_by_id.len()
                    && public
                        .iter()
                        .all(|camera| local_by_id.contains_key(camera.id.as_str())) =>
            {
                LocalEnrichmentState::Available
            }
            (Some(_), _) => LocalEnrichmentState::Partial,
            (None, true) => LocalEnrichmentState::Unavailable,
            (None, false) => LocalEnrichmentState::NotConfigured,
        };
        if let Some(local_response) = local_response.as_deref() {
            reject_conflicting_camera_identity(
                &public,
                &local_by_id,
                &public_response,
                local_response,
            )?;
        }
        let public_nvr = if scope == CameraInventoryScope::Full
            && let Some(local) = local_bootstrap.as_ref().map(|value| &value.nvr)
        {
            let (public_nvr, nvr_response) =
                protect.nvr_with_response().await.map_err(api_error)?;
            reject_conflicting_recorder_identity(
                &public_nvr,
                local,
                &nvr_response,
                local_response
                    .as_deref()
                    .expect("local bootstrap response retained"),
            )?;
            Some(public_nvr)
        } else {
            None
        };
        let local_nvr = (scope == CameraInventoryScope::Full)
            .then(|| local_bootstrap.as_ref().map(|bootstrap| &bootstrap.nvr))
            .flatten();
        let mut cameras: Vec<CameraView> = public
            .into_iter()
            .map(|camera| {
                let local = local_by_id.get(camera.id.as_str()).copied();
                camera_view(camera, local, local_nvr, local_state)
            })
            .collect();
        cameras.sort_by(|left, right| left.display_name.cmp(&right.display_name));
        Ok(CameraInventory {
            application_version: bounded_text(application_version),
            cameras,
            public_nvr,
            local_bootstrap,
            local_state,
            local_error,
        })
    }

    /// Cameras by id, name, hardware model, class, or state, paged. Filters
    /// whose source is unavailable fail explicitly.
    async fn cameras_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CamerasSearchInput>(params)?;
        validate_page(input.limit)?;
        let (offset, limit) = (input.offset, input.limit);
        let query = validate_filter(input.query.as_deref())?;
        let model = validate_filter(input.model.as_deref())?;
        let class_filter = validate_filter(input.class_filter.as_deref())?;
        let state = validate_filter(input.state.as_deref())?;
        let inventory = self.camera_inventory(CameraInventoryScope::Full).await?;
        if model.is_some()
            && (inventory.local_state != LocalEnrichmentState::Available
                || inventory
                    .cameras
                    .iter()
                    .any(|camera| camera.hardware_model.is_none()))
        {
            return Err(inventory.local_error.as_ref().map_or_else(
                || unavailable_camera_filter("model"),
                |error| api_error(error.clone()),
            ));
        }
        if let Some(wanted) = class_filter.as_deref() {
            let class_data_complete = class_filter_available(&inventory.cameras, wanted)?;
            if inventory.local_state != LocalEnrichmentState::Available || !class_data_complete {
                return Err(inventory.local_error.as_ref().map_or_else(
                    || unavailable_camera_filter("class"),
                    |error| api_error(error.clone()),
                ));
            }
        }
        let capabilities =
            protect_capabilities(inventory.local_state, inventory.local_error.as_ref());

        let matched: Vec<CameraView> = inventory
            .cameras
            .into_iter()
            .filter(|camera| {
                query.as_ref().is_none_or(|needle| {
                    camera.id.to_lowercase().contains(needle)
                        || camera
                            .name
                            .as_ref()
                            .is_some_and(|name| name.to_lowercase().contains(needle))
                        || camera.display_name.to_lowercase().contains(needle)
                }) && model.as_ref().is_none_or(|needle| {
                    camera
                        .hardware_model
                        .as_ref()
                        .is_some_and(|value| value.to_lowercase().contains(needle))
                }) && class_filter.as_ref().is_none_or(|wanted| {
                    camera
                        .classes
                        .as_ref()
                        .is_some_and(|classes| classes.iter().any(|class| class == wanted))
                }) && state
                    .as_ref()
                    .is_none_or(|wanted| camera.state.to_lowercase() == *wanted)
            })
            .collect();

        let total = matched.len();
        let rows: Vec<CameraView> = matched.into_iter().skip(offset).take(limit).collect();
        let next_offset = next_offset(offset, rows.len(), total);
        structured(CamerasSearchOutput {
            cameras: rows,
            total,
            next_offset,
            capabilities,
        })
    }

    async fn protect_devices_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectDevicesListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        let devices = self
            .protect()
            .devices(input.kind.into())
            .await
            .map_err(api_error)?;
        let total_count = devices.len();
        let page: Vec<Value> = devices
            .into_iter()
            .skip(input.offset)
            .take(input.limit)
            .collect();
        let next = input.offset.saturating_add(page.len());
        structured(ProtectDevicesListOutput {
            kind: input.kind,
            devices: page,
            total_count,
            next_offset: (next < total_count).then_some(next),
        })
    }

    async fn protect_devices_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectDevicesStatusInput>(params)?;
        if input.device_id.is_empty() || input.device_id.len() > 256 {
            return Err(McpError::invalid_params(
                "deviceId must be 1-256 bytes",
                None,
            ));
        }
        let device = self
            .protect()
            .device(input.kind.into(), &input.device_id)
            .await
            .map_err(api_error)?;
        structured(ProtectDevicesStatusOutput {
            kind: input.kind,
            device,
        })
    }

    async fn protect_devices_action(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectDevicesActionInput>(params)?;
        validate_protect_action_id("deviceId", &input.device_id)?;
        let mut output = ProtectDevicesActionOutput {
            device_id: input.device_id,
            action: input.action,
            submitted: false,
            accepted_status: None,
            response_body: None,
            response_body_in_content: None,
        };
        let (route, body) = protect_action_request(&output.action)?;
        if !input.confirm {
            return structured(output);
        }
        let response = self
            .protect()
            .device_action(&output.device_id, route, body.as_ref())
            .await
            .map_err(api_error)?;
        output.submitted = true;
        output.accepted_status = Some(response.status);
        if !response.body.is_empty() {
            output.response_body =
                Some(BoundedMessage::from_controller_bytes(&response.body).to_string());
        }
        protect_action_result(output)
    }

    async fn protect_devices_settings_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<ProtectDevicesSettingsUpdateInput>(params)?;
        validate_protect_action_id("deviceId", &input.device_id)?;
        let (kind, requested) = device_settings_request(&input.changes)?;
        let family = ProtectDeviceFamily::from(kind);
        let before = self
            .protect()
            .device(family, &input.device_id)
            .await
            .map_err(api_error)?;
        let mut output = ProtectDevicesSettingsUpdateOutput {
            kind,
            device_id: input.device_id,
            requested: Some(requested),
            requested_in_content: None,
            before: Some(before),
            before_in_content: None,
            submitted: false,
            accepted_status: None,
            response_body: None,
            response_body_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return device_settings_update_result(output);
        }
        let response = self
            .protect()
            .device_settings_patch(
                family,
                &output.device_id,
                output.requested.as_ref().expect("validated changes exist"),
            )
            .await
            .map_err(api_error)?;
        output.submitted = true;
        output.accepted_status = Some(response.status);
        if !response.body.is_empty() {
            output.response_body =
                Some(BoundedMessage::from_controller_bytes(&response.body).to_string());
        }
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
            .min(CAMERA_SETTINGS_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("device readback skipped because the request deadline was near".to_owned());
        } else {
            match tokio::time::timeout(budget, self.protect().device(family, &output.device_id))
                .await
            {
                Ok(Ok(after)) => {
                    output.verified = Some(requested_json_matches(
                        output.requested.as_ref().expect("validated changes exist"),
                        &after,
                    ));
                    output.after = Some(after);
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => output.readback_error = Some("device readback timed out".to_owned()),
            }
        }
        device_settings_update_result(output)
    }

    async fn protect_arm_profiles_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectArmProfilesListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        let profiles = self.protect().arm_profiles().await.map_err(api_error)?;
        let total_count = profiles.len();
        let page = profiles
            .into_iter()
            .skip(input.offset)
            .take(input.limit)
            .collect::<Vec<_>>();
        let next = input.offset.saturating_add(page.len());
        arm_profiles_list_result(ProtectArmProfilesListOutput {
            profiles: Some(page),
            profiles_in_content: None,
            total_count,
            next_offset: (next < total_count).then_some(next),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn protect_arm_profiles_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<ProtectArmProfilesConfigureInput>(params)?;
        let profile_id = input.profile_id.as_deref();
        let changes = input.changes.as_ref();
        let (route, requested, operation) = match input.operation {
            ProtectArmConfigureOperation::Create => {
                if profile_id.is_some() {
                    return Err(McpError::invalid_params(
                        "create does not use profileId",
                        None,
                    ));
                }
                let changes = changes
                    .ok_or_else(|| McpError::invalid_params("create requires changes", None))?;
                if changes.name.is_none()
                    || changes.automations.is_none()
                    || changes.schedules.is_none()
                    || changes.record_everything.is_none()
                    || changes.activation_delay.is_none()
                {
                    return Err(McpError::invalid_params(
                        "create requires name, automations, schedules, recordEverything, and activationDelay",
                        None,
                    ));
                }
                validate_arm_changes(changes)?;
                (
                    ProtectArmRoute::Create,
                    Some(arm_changes_json(changes)?),
                    "create",
                )
            }
            ProtectArmConfigureOperation::Update => {
                let id = profile_id
                    .ok_or_else(|| McpError::invalid_params("update requires profileId", None))?;
                validate_protect_action_id("profileId", id)?;
                let changes = changes
                    .ok_or_else(|| McpError::invalid_params("update requires changes", None))?;
                validate_arm_changes(changes)?;
                if changes.name.is_none()
                    && changes.automations.is_none()
                    && changes.schedules.is_none()
                    && changes.record_everything.is_none()
                    && changes.activation_delay.is_none()
                {
                    return Err(McpError::invalid_params(
                        "changes names no field to change",
                        None,
                    ));
                }
                (
                    ProtectArmRoute::Update { profile_id: id },
                    Some(arm_changes_json(changes)?),
                    "update",
                )
            }
            ProtectArmConfigureOperation::Delete => {
                let id = profile_id
                    .ok_or_else(|| McpError::invalid_params("delete requires profileId", None))?;
                validate_protect_action_id("profileId", id)?;
                if changes.is_some() {
                    return Err(McpError::invalid_params(
                        "delete does not use changes",
                        None,
                    ));
                }
                (ProtectArmRoute::Delete { profile_id: id }, None, "delete")
            }
            ProtectArmConfigureOperation::Select => {
                let id = profile_id
                    .ok_or_else(|| McpError::invalid_params("select requires profileId", None))?;
                validate_protect_action_id("profileId", id)?;
                if changes.is_some() {
                    return Err(McpError::invalid_params(
                        "select does not use changes",
                        None,
                    ));
                }
                (
                    ProtectArmRoute::Select,
                    Some(json!({"armProfileId":id})),
                    "select",
                )
            }
        };
        let mut output = ProtectArmOperationOutput {
            operation: operation.to_owned(),
            profile_id: input.profile_id.clone(),
            trigger_id: None,
            requested,
            requested_in_content: None,
            submitted: false,
            accepted_status: None,
            response_body: None,
            response_body_in_content: None,
            observed: None,
            observed_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return protect_arm_operation_result(output);
        }
        let response = self
            .protect()
            .arm_operation(route, output.requested.as_ref())
            .await
            .map_err(api_error)?;
        let response_id = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|value| value.get("id")?.as_str().map(str::to_owned));
        output.submitted = true;
        output.accepted_status = Some(response.status);
        if !response.body.is_empty() {
            output.response_body =
                Some(BoundedMessage::from_controller_bytes(&response.body).to_string());
        }
        let readback_id = match input.operation {
            ProtectArmConfigureOperation::Create => response_id,
            ProtectArmConfigureOperation::Update | ProtectArmConfigureOperation::Delete => {
                output.profile_id.clone()
            }
            ProtectArmConfigureOperation::Select => None,
        };
        if let Some(id) = readback_id {
            let budget = self
                .request_timeout()
                .saturating_sub(started.elapsed())
                .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
                .min(CAMERA_SETTINGS_READBACK_BUDGET);
            if budget.is_zero() {
                output.readback_error = Some(
                    "arm-profile readback skipped because the request deadline was near".to_owned(),
                );
            } else {
                match tokio::time::timeout(budget, self.protect().arm_profiles()).await {
                    Ok(Ok(profiles)) => {
                        let observed = profiles.into_iter().find(|profile| {
                            profile.get("id").and_then(Value::as_str) == Some(id.as_str())
                        });
                        output.verified = Some(match input.operation {
                            ProtectArmConfigureOperation::Delete => observed.is_none(),
                            ProtectArmConfigureOperation::Create
                            | ProtectArmConfigureOperation::Update => {
                                observed.as_ref().is_some_and(|profile| {
                                    output
                                        .requested
                                        .as_ref()
                                        .and_then(Value::as_object)
                                        .is_some_and(|requested| {
                                            requested
                                                .iter()
                                                .all(|(key, value)| profile.get(key) == Some(value))
                                        })
                                })
                            }
                            ProtectArmConfigureOperation::Select => {
                                unreachable!("select has no readback id")
                            }
                        });
                        output.observed = observed;
                    }
                    Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                    Err(_) => {
                        output.readback_error = Some("arm-profile readback timed out".to_owned());
                    }
                }
            }
        }
        protect_arm_operation_result(output)
    }

    async fn protect_alarms_action(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectAlarmsActionInput>(params)?;
        let (route, operation) = match input.action {
            ProtectAlarmAction::Enable => (ProtectArmRoute::Enable, "enable"),
            ProtectAlarmAction::Disable => (ProtectArmRoute::Disable, "disable"),
            ProtectAlarmAction::Webhook => {
                let id = input
                    .trigger_id
                    .as_deref()
                    .ok_or_else(|| McpError::invalid_params("webhook requires triggerId", None))?;
                validate_protect_action_id("triggerId", id)?;
                (ProtectArmRoute::Webhook { trigger_id: id }, "webhook")
            }
        };
        if !matches!(input.action, ProtectAlarmAction::Webhook) && input.trigger_id.is_some() {
            return Err(McpError::invalid_params(
                "triggerId is only used by webhook",
                None,
            ));
        }
        let mut output = ProtectArmOperationOutput {
            operation: operation.to_owned(),
            profile_id: None,
            trigger_id: input.trigger_id.clone(),
            requested: None,
            requested_in_content: None,
            submitted: false,
            accepted_status: None,
            response_body: None,
            response_body_in_content: None,
            observed: None,
            observed_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return protect_arm_operation_result(output);
        }
        let response = self
            .protect()
            .arm_operation(route, None)
            .await
            .map_err(api_error)?;
        output.submitted = true;
        output.accepted_status = Some(response.status);
        if !response.body.is_empty() {
            output.response_body =
                Some(BoundedMessage::from_controller_bytes(&response.body).to_string());
        }
        protect_arm_operation_result(output)
    }

    async fn protect_users_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectUsersListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        let users = self
            .protect()
            .users(input.kind.into())
            .await
            .map_err(api_error)?;
        let total_count = users.len();
        let page: Vec<Value> = users
            .into_iter()
            .skip(input.offset)
            .take(input.limit)
            .collect();
        let next = input.offset.saturating_add(page.len());
        structured(ProtectUsersListOutput {
            kind: input.kind,
            users: page,
            total_count,
            next_offset: (next < total_count).then_some(next),
        })
    }

    async fn protect_users_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectUsersStatusInput>(params)?;
        if input.user_id.is_empty() || input.user_id.len() > 256 {
            return Err(McpError::invalid_params("userId must be 1-256 bytes", None));
        }
        let user = self
            .protect()
            .user(input.kind.into(), &input.user_id)
            .await
            .map_err(api_error)?;
        structured(ProtectUsersStatusOutput {
            kind: input.kind,
            user,
        })
    }

    async fn cameras_pos_transaction(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CameraPosTransactionInput>(params)?;
        if input.camera_id.is_empty()
            || input.camera_id.len() > 256
            || matches!(input.camera_id.as_str(), "." | "..")
        {
            return Err(McpError::invalid_params(
                "cameraId must be a nonempty, non-dot id of at most 256 bytes",
                None,
            ));
        }
        validate_pos_transaction(&input.transaction)?;
        let request = serde_json::to_value(&input.transaction)
            .map_err(|_| McpError::internal_error("POS transaction could not be encoded", None))?;
        let mut output = CameraPosTransactionOutput {
            camera_id: input.camera_id.clone(),
            effect: "Record a transaction as a camera event; video for its window is not confirmed",
            transaction: Some(input.transaction),
            transaction_in_content: None,
            submitted: false,
            response: None,
            response_in_content: None,
        };
        if !input.confirm {
            let preview = structured(&output)?;
            if preview
                .structured_content
                .as_ref()
                .is_none_or(|value| value.to_string().len() <= STRUCTURED_CONTENT_TARGET_BYTES)
            {
                return Ok(preview);
            }
            output.transaction = None;
            output.transaction_in_content = Some(true);
            let mut result = structured(output)?;
            result
                .content
                .push(ContentBlock::text(format!("transaction: {request}")));
            return Ok(result);
        }
        let response = self
            .protect()
            .camera_pos_transaction(&output.camera_id, &request)
            .await
            .map_err(api_error)?;
        output.transaction = None;
        output.submitted = true;
        output.response = Some(response);
        let full = structured(&output)?;
        if full
            .structured_content
            .as_ref()
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        {
            let response = output.response.take().expect("accepted response exists");
            output.response_in_content = Some(true);
            let mut result = structured(output)?;
            result
                .content
                .push(ContentBlock::text(format!("response: {response}")));
            return Ok(result);
        }
        structured(output)
    }

    async fn protect_viewers_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectViewsListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        let viewers = self.protect().viewers().await.map_err(api_error)?;
        let total_count = viewers.len();
        let page: Vec<Value> = viewers
            .into_iter()
            .skip(input.offset)
            .take(input.limit)
            .collect();
        let next = input.offset.saturating_add(page.len());
        structured(ProtectViewersListOutput {
            viewers: page,
            total_count,
            next_offset: (next < total_count).then_some(next),
        })
    }

    async fn protect_viewers_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectViewerStatusInput>(params)?;
        if input.viewer_id.is_empty() || input.viewer_id.len() > 256 {
            return Err(McpError::invalid_params(
                "viewerId must be 1-256 bytes",
                None,
            ));
        }
        let viewer = self
            .protect()
            .viewer(&input.viewer_id)
            .await
            .map_err(api_error)?;
        structured(ProtectViewerStatusOutput { viewer })
    }

    async fn protect_viewers_settings_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<ProtectViewerSettingsUpdateInput>(params)?;
        if input.viewer_id.is_empty() || input.viewer_id.len() > 256 {
            return Err(McpError::invalid_params(
                "viewerId must be 1-256 bytes",
                None,
            ));
        }
        if input.changes.name.is_none() && input.changes.liveview.is_none() {
            return Err(McpError::invalid_params(
                "changes names no field to change",
                None,
            ));
        }
        if input
            .changes
            .name
            .as_ref()
            .is_some_and(|name| name.len() > 4096)
            || input
                .changes
                .liveview
                .as_ref()
                .is_some_and(|assignment| matches!(assignment, LiveviewAssignment::Id(id) if id.is_empty() || id.len() > 256))
        {
            return Err(McpError::invalid_params(
                "name must be at most 4096 bytes and a liveview id must be 1-256 bytes",
                None,
            ));
        }
        let patch = serde_json::to_value(&input.changes)
            .map_err(|_| McpError::internal_error("viewer settings could not be encoded", None))?;
        let before = self
            .protect()
            .viewer(&input.viewer_id)
            .await
            .map_err(api_error)?;
        let mut output = ProtectViewerSettingsUpdateOutput {
            viewer_id: input.viewer_id,
            requested: input.changes,
            applied: false,
            before: Some(before),
            before_in_content: None,
            response: None,
            response_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return viewer_settings_result(output);
        }
        let response = self
            .protect()
            .viewer_settings_patch(&output.viewer_id, &patch)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response = Some(response);
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
            .min(CAMERA_SETTINGS_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("viewer readback skipped because the request deadline was near".to_owned());
            return viewer_settings_result(output);
        }
        match tokio::time::timeout(budget, self.protect().viewer(&output.viewer_id)).await {
            Ok(Ok(after)) => {
                output.verified = Some(viewer_settings_match(&output.requested, &after));
                output.after = Some(after);
            }
            Ok(Err(error)) => output.readback_error = Some(error.to_string()),
            Err(_) => output.readback_error = Some("viewer readback timed out".to_owned()),
        }
        viewer_settings_result(output)
    }

    async fn protect_liveviews_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectViewsListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        let liveviews = self.protect().liveviews().await.map_err(api_error)?;
        let total_count = liveviews.len();
        let page: Vec<Value> = liveviews
            .into_iter()
            .skip(input.offset)
            .take(input.limit)
            .collect();
        let next = input.offset.saturating_add(page.len());
        structured(ProtectLiveviewsListOutput {
            liveviews: page,
            total_count,
            next_offset: (next < total_count).then_some(next),
        })
    }

    async fn protect_liveviews_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectLiveviewStatusInput>(params)?;
        if input.liveview_id.is_empty() || input.liveview_id.len() > 256 {
            return Err(McpError::invalid_params(
                "liveviewId must be 1-256 bytes",
                None,
            ));
        }
        let liveview = self
            .protect()
            .liveview(&input.liveview_id)
            .await
            .map_err(api_error)?;
        structured(ProtectLiveviewStatusOutput { liveview })
    }

    async fn protect_liveviews_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<ProtectLiveviewsConfigureInput>(params)?;
        let id = match input.operation {
            LiveviewOperation::Create if input.liveview_id.is_some() => {
                return Err(McpError::invalid_params(
                    "create uses changes.id rather than liveviewId",
                    None,
                ));
            }
            LiveviewOperation::Create => None,
            LiveviewOperation::Update => {
                let id = input
                    .liveview_id
                    .as_deref()
                    .ok_or_else(|| McpError::invalid_params("update requires liveviewId", None))?;
                if id.is_empty() || id.len() > 256 {
                    return Err(McpError::invalid_params(
                        "liveviewId must be 1-256 bytes",
                        None,
                    ));
                }
                Some(id)
            }
        };
        let request = liveview_configuration_request(&input.changes)?;
        let before = if let Some(id) = id {
            Some(self.protect().liveview(id).await.map_err(api_error)?)
        } else {
            None
        };
        let mut output = ProtectLiveviewsConfigureOutput {
            operation: input.operation,
            liveview_id: input.liveview_id,
            requested: Some(input.changes),
            requested_in_content: None,
            applied: false,
            before,
            before_in_content: None,
            response: None,
            response_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return liveview_configure_result(output);
        }
        let response = match output.operation {
            LiveviewOperation::Create => self.protect().liveview_create(&request).await,
            LiveviewOperation::Update => {
                self.protect()
                    .liveview_patch(
                        output.liveview_id.as_deref().expect("validated id"),
                        &request,
                    )
                    .await
            }
        }
        .map_err(api_error)?;
        output.applied = true;
        if matches!(output.operation, LiveviewOperation::Create) {
            output.liveview_id = response
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        output.response = Some(response);
        let Some(id) = output.liveview_id.as_deref() else {
            output.readback_error =
                Some("accepted create response supplied no live-view id for read-back".to_owned());
            return liveview_configure_result(output);
        };
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
            .min(CAMERA_SETTINGS_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error = Some(
                "live-view read-back skipped because the request deadline was near".to_owned(),
            );
            return liveview_configure_result(output);
        }
        match tokio::time::timeout(budget, self.protect().liveview(id)).await {
            Ok(Ok(after)) => {
                output.verified = Some(liveview_changes_match(&request, &after));
                output.after = Some(after);
            }
            Ok(Err(error)) => output.readback_error = Some(error.to_string()),
            Err(_) => output.readback_error = Some("live-view read-back timed out".to_owned()),
        }
        liveview_configure_result(output)
    }

    /// One camera by id or exact name.
    async fn cameras_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CameraStatusInput>(params)?;
        validate_bootstrap_detail_request(input.include_details, input.detail_fields.as_deref())?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self.camera_inventory(CameraInventoryScope::Full).await?;
        let details = if input.include_details || input.detail_fields.is_some() {
            let raw = inventory.local_bootstrap.as_ref().ok_or_else(|| {
                inventory.local_error.as_ref().map_or_else(
                    || McpError::invalid_params("local Protect details are unavailable", None),
                    |error| api_error(error.clone()),
                )
            })?;
            let camera = camera_by_selector_ref(&inventory, selector)?;
            let row = raw.raw["cameras"]
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["id"] == camera.id))
                .ok_or_else(|| {
                    McpError::invalid_params(
                        "selected camera is absent from the local bootstrap",
                        None,
                    )
                })?;
            Some(select_bootstrap_details(
                row,
                input.include_details,
                input.detail_fields.as_deref(),
            )?)
        } else {
            None
        };
        let mut camera = camera_by_selector(&inventory, selector)?;
        camera.details = details;
        camera.local_error = inventory.local_error.as_ref().map(ToString::to_string);
        structured(camera)
    }

    async fn cameras_settings_read(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CameraSelectorInput>(params)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let (_, camera) = self
            .protect()
            .camera_with_response(&camera_id)
            .await
            .map_err(api_error)?;
        camera_settings_read_result(CameraSettingsReadOutput {
            camera_id,
            camera: Some(camera),
            camera_in_content: None,
        })
    }

    async fn cameras_settings_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<CameraSettingsUpdateInput>(params)?;
        let patch = camera_settings_patch(&input.changes)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let mut output = CameraSettingsOutput {
            camera_id: camera_id.clone(),
            applied: false,
            requested: Some(input.changes),
            requested_in_content: None,
            before: None,
            before_in_content: None,
            response: None,
            response_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings: Vec::new(),
        };
        if !input.confirm {
            return camera_settings_update_result(output);
        }
        let (before, before_raw) = self
            .protect()
            .camera_with_response(&camera_id)
            .await
            .map_err(api_error)?;
        output.before = Some(before_raw);
        let (_, response_raw) = self
            .protect()
            .camera_settings_patch_with_response(&camera_id, &patch)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response = Some(response_raw);
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
            .min(CAMERA_SETTINGS_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            None
        } else {
            Some(
                tokio::time::timeout(budget, self.protect().camera_with_response(&camera_id)).await,
            )
        };
        let mut upstream_error = None;
        match readback {
            Some(Ok(Ok((after, after_raw)))) if after.id == camera_id => {
                output.verified =
                    Some(camera_settings_match(&patch, &before.into(), &after.into()));
                output.after = Some(after_raw);
            }
            Some(Ok(Err(error))) => {
                output.readback_error = Some(error.to_string());
                upstream_error = Some(error);
            }
            Some(Err(_)) => output.warnings.push("camera readback timed out".to_owned()),
            None => output
                .warnings
                .push("camera readback skipped because the request deadline was near".to_owned()),
            _ => {}
        }
        if output.verified != Some(true) && upstream_error.is_none() {
            output.warnings.push(
                "the controller accepted the patch, but the requested settings were not verified"
                    .to_owned(),
            );
        }
        camera_settings_update_result(output)
    }

    async fn cameras_snapshot(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CameraSnapshotInput>(params)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let channel = input.channel.as_str();
        let bytes = self
            .protect()
            .camera_snapshot(&camera_id, channel, input.high_quality)
            .await
            .map_err(api_error)?;
        let mut result = structured(CameraSnapshotOutput {
            camera_id,
            channel: channel.to_owned(),
            mime_type: "image/jpeg",
            byte_size: bytes.len(),
        })?;
        result
            .content
            .push(ContentBlock::image(STANDARD.encode(bytes), "image/jpeg"));
        Ok(result)
    }

    async fn protect_event_thumbnail(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectEventThumbnailInput>(params)?;
        let bytes = self
            .protect_events()?
            .protect_event_thumbnail(&input.event)
            .await
            .map_err(api_error)?;
        let mut result = structured(ProtectEventThumbnailOutput {
            event_id: input.event,
            mime_type: "image/jpeg",
            byte_size: bytes.len(),
        })?;
        result
            .content
            .push(ContentBlock::image(STANDARD.encode(bytes), "image/jpeg"));
        Ok(result)
    }

    async fn cameras_ptz_control(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<CameraPtzInput>(params)?;
        let command = ptz_command(input.action, input.slot)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let mut output = CameraPtzOutput {
            camera_id: camera_id.clone(),
            action: input.action,
            slot: input.slot,
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            verified: None,
            active_patrol_slot: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings: Vec::new(),
        };
        if !input.confirm {
            return structured_with_accepted_response(output);
        }

        let (status, body) = self
            .protect()
            .camera_ptz(&camera_id, command)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response_status = Some(status);
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        if matches!(command, ProtectPtzCommand::GotoPreset(_)) {
            output.warnings.push(
                "controller accepted preset movement; the integration API does not report camera position"
                    .to_owned(),
            );
            return structured_with_accepted_response(output);
        }
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(PTZ_RESPONSE_RESERVE)
            .min(PTZ_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("camera readback skipped near request deadline".to_owned());
            return structured_with_accepted_response(output);
        }
        let readback = tokio::time::timeout(budget, self.protect().camera(&camera_id)).await;
        match readback {
            Err(_) => output.readback_error = Some("camera readback timed out".to_owned()),
            Ok(Ok(camera)) if camera.id == camera_id => {
                output.active_patrol_slot = patrol_slot_view(camera.active_patrol_slot);
                output.verified = match (command, camera.active_patrol_slot) {
                    (ProtectPtzCommand::StartPatrol(want), ProtectPatrolState::Running(got)) => {
                        Some(want == got)
                    }
                    (ProtectPtzCommand::StartPatrol(_), ProtectPatrolState::Stopped)
                    | (ProtectPtzCommand::StopPatrol, ProtectPatrolState::Running(_)) => {
                        Some(false)
                    }
                    (ProtectPtzCommand::StopPatrol, ProtectPatrolState::Stopped) => Some(true),
                    _ => None,
                };
                if output.verified == Some(false) {
                    output.warnings.push(
                        "controller accepted the PTZ action but the reported patrol slot did not match"
                            .to_owned(),
                    );
                } else if output.verified.is_none() {
                    output.warnings.push(
                        "controller accepted the PTZ action but did not report patrol state for verification"
                            .to_owned(),
                    );
                }
            }
            Ok(Ok(camera)) => output.warnings.push(format!(
                "controller returned camera {} during readback of {camera_id}",
                camera.id
            )),
            Ok(Err(error)) => {
                output.readback_error = Some(error.to_string());
            }
        }
        structured_with_accepted_response(output)
    }

    async fn cameras_microphone_disable(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<CameraDisableMicInput>(params)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let before = self
            .protect()
            .camera_raw(&camera_id)
            .await
            .map_err(api_error)?;
        let mut output = CameraDisableMicOutput {
            camera_id,
            effect: "permanently disable microphone; restoring it requires a camera reset",
            before: Some(before),
            before_in_content: None,
            submitted: false,
            accepted_status: None,
            response_body: None,
            response_body_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return camera_disable_mic_result(output);
        }
        let response = self
            .protect()
            .camera_disable_mic(&output.camera_id)
            .await
            .map_err(api_error)?;
        output.submitted = true;
        output.accepted_status = Some(response.status);
        output.response_body =
            Some(BoundedMessage::from_controller_bytes(&response.body).to_string());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
            .min(CAMERA_SETTINGS_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("camera readback skipped because the request deadline was near".to_owned());
        } else {
            match tokio::time::timeout(budget, self.protect().camera_raw(&output.camera_id)).await {
                Ok(Ok(after)) => {
                    output.verified = after
                        .get("isMicEnabled")
                        .and_then(Value::as_bool)
                        .map(|enabled| !enabled);
                    output.after = Some(after);
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => output.readback_error = Some("camera readback timed out".to_owned()),
            }
        }
        camera_disable_mic_result(output)
    }

    async fn protect_assets_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectAssetsListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        let assets = self.protect().animation_assets().await.map_err(api_error)?;
        let total_count = assets.len();
        let page: Vec<Value> = assets
            .into_iter()
            .skip(input.offset)
            .take(input.limit)
            .collect();
        let next = input.offset.saturating_add(page.len());
        structured(ProtectAssetsListOutput {
            file_type: "animations",
            assets: page,
            total_count,
            next_offset: (next < total_count).then_some(next),
        })
    }

    async fn protect_assets_upload(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<ProtectAssetUploadInput>(params)?;
        if input.file_name.is_empty()
            || input.file_name.len() > 255
            || input.file_name.chars().any(char::is_control)
        {
            return Err(McpError::invalid_params(
                "fileName must contain 1-255 bytes without control characters",
                None,
            ));
        }
        if input.content_base64.len() > MAXIMUM_ANIMATION_ASSET_BYTES.div_ceil(3) * 4 {
            return Err(McpError::invalid_params(
                "animation asset exceeds the 3 MiB upload bound",
                None,
            ));
        }
        let bytes = STANDARD.decode(&input.content_base64).map_err(|_| {
            McpError::invalid_params("contentBase64 must be standard padded base64", None)
        })?;
        if bytes.is_empty() || bytes.len() > MAXIMUM_ANIMATION_ASSET_BYTES {
            return Err(McpError::invalid_params(
                "animation asset must contain 1 byte to 3 MiB",
                None,
            ));
        }
        let mut output = ProtectAssetUploadOutput {
            file_type: "animations",
            file_name: input.file_name,
            mime_type: input.mime_type,
            byte_size: bytes.len(),
            submitted: false,
            accepted: None,
            accepted_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return structured(output);
        }
        let accepted = self
            .protect()
            .animation_asset_upload(&output.file_name, output.mime_type.as_str(), bytes)
            .await
            .map_err(api_error)?;
        let asset_name = accepted
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        output.submitted = true;
        output.accepted = Some(accepted);
        if let Some(asset_name) = asset_name {
            let budget = self
                .request_timeout()
                .saturating_sub(started.elapsed())
                .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
                .min(CAMERA_SETTINGS_READBACK_BUDGET);
            if budget.is_zero() {
                output.readback_error =
                    Some("asset readback skipped because the request deadline was near".to_owned());
            } else {
                match tokio::time::timeout(budget, self.protect().animation_assets()).await {
                    Ok(Ok(assets)) => {
                        output.after = assets.into_iter().find(|asset| {
                            asset.get("name").and_then(Value::as_str) == Some(asset_name.as_str())
                        });
                        output.verified = Some(output.after.is_some());
                    }
                    Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                    Err(_) => output.readback_error = Some("asset readback timed out".to_owned()),
                }
            }
        }
        protect_asset_upload_result(output)
    }

    async fn cameras_streams_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CameraStreamsListInput>(params)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let streams = self
            .protect()
            .camera_streams(&camera_id)
            .await
            .map_err(api_error)?;
        structured(CameraStreamsListOutput {
            camera_id,
            streams: stream_handles(streams),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Stream creation and removal share one accepted-response and readback contract"
    )]
    async fn cameras_streams_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<CameraStreamsUpdateInput>(params)?;
        validate_stream_quality_selection(&input.qualities)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let mut output = CameraStreamsUpdateOutput {
            camera_id: camera_id.clone(),
            action: input.action,
            qualities: input.qualities.clone(),
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
            streams: Vec::new(),
            warnings: Vec::new(),
        };
        if !input.confirm {
            return structured_with_accepted_response(output);
        }

        let qualities: Vec<ProtectStreamQuality> = input
            .qualities
            .iter()
            .copied()
            .map(ProtectStreamQuality::from)
            .collect();
        match input.action {
            CameraStreamsAction::Create => {
                let (created, status, body) = self
                    .protect()
                    .camera_streams_create(&camera_id, &qualities)
                    .await
                    .map_err(api_error)?;
                output.applied = true;
                output.response_status = Some(status);
                output.response_body =
                    Some(BoundedMessage::from_controller_bytes(&body).to_string());
                output.streams = stream_handles(created)
                    .into_iter()
                    .filter(|handle| input.qualities.contains(&handle.quality))
                    .collect();
                if !input.qualities.iter().all(|quality| {
                    output
                        .streams
                        .iter()
                        .any(|handle| handle.quality == *quality)
                }) {
                    output.warnings.push(
                        "controller accepted stream creation but omitted a requested handle"
                            .to_owned(),
                    );
                }
            }
            CameraStreamsAction::Remove => {
                let (status, body) = self
                    .protect()
                    .camera_streams_delete(&camera_id, &qualities)
                    .await
                    .map_err(api_error)?;
                output.applied = true;
                output.response_status = Some(status);
                output.response_body =
                    Some(BoundedMessage::from_controller_bytes(&body).to_string());
            }
        }
        // Verification must leave time to return newly created stream handles.
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(STREAM_RESPONSE_RESERVE)
            .min(STREAM_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            None
        } else {
            Some(tokio::time::timeout(budget, self.protect().camera_streams(&camera_id)).await)
        };
        match readback {
            Some(Ok(Ok(after))) => {
                output.verified = Some(input.qualities.iter().all(|quality| {
                    let exists = stream_url_for(&after, *quality).is_some();
                    match input.action {
                        CameraStreamsAction::Create => exists,
                        CameraStreamsAction::Remove => !exists,
                    }
                }));
                if output.verified == Some(false) {
                    output.warnings.push(
                        "controller accepted the stream change but readback did not match"
                            .to_owned(),
                    );
                }
            }
            Some(Ok(Err(error))) => {
                output.readback_error = Some(error.to_string());
            }
            Some(Err(_)) => output.warnings.push("stream readback timed out".to_owned()),
            None => output
                .warnings
                .push("stream readback skipped because the request deadline was near".to_owned()),
        }
        structured_with_accepted_response(output)
    }

    async fn cameras_talkback_start(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CameraTalkbackInput>(params)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(&inventory, selector)?.id;
        let mut output = CameraTalkbackOutput {
            camera_id,
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            session: None,
        };
        if input.confirm {
            let (session, status, body) = self
                .protect()
                .camera_talkback_session(&output.camera_id)
                .await
                .map_err(api_error)?;
            output.applied = true;
            output.response_status = Some(status);
            output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
            output.session = Some(talkback_session_view(session));
        }
        structured_with_accepted_response(output)
    }

    /// One console snapshot: version, cameras grouped by their reported
    /// state, the recorder, and explicit source capabilities.
    async fn protect_overview(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectOverviewInput>(params)?;
        if !matches!(input.view, ProtectOverviewView::Summary) {
            if input.detail_fields.is_some() {
                return Err(McpError::invalid_params(
                    "detailFields applies to the summary view",
                    None,
                ));
            }
            let record = match input.view {
                ProtectOverviewView::ApplicationInfo => self.protect().info_record().await,
                ProtectOverviewView::Recorder => self.protect().nvr_record().await,
                ProtectOverviewView::Summary => unreachable!("summary continues below"),
            }
            .map_err(api_error)?;
            return protect_overview_result(ProtectOverviewResult::Record(RecordOutput {
                record: Some(record),
                record_in_content: None,
            }));
        }
        validate_bootstrap_detail_request(false, input.detail_fields.as_deref())?;
        let inventory = self.camera_inventory(CameraInventoryScope::Full).await?;
        let CameraInventory {
            application_version,
            cameras,
            public_nvr,
            local_bootstrap,
            local_state,
            local_error,
        } = inventory;

        // Grouped on the console's own state words. Sorted by state so the
        // same console produces the same rows twice running.
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for camera in &cameras {
            *counts.entry(camera.state.clone()).or_default() += 1;
        }
        let idle: Vec<CameraReferenceView> = cameras
            .iter()
            .filter(|camera| camera.recording == Some(false))
            .map(|camera| CameraReferenceView {
                id: camera.id.clone(),
                name: camera.name.clone(),
            })
            .collect();
        let recording_summary_complete = cameras.iter().all(|camera| camera.recording.is_some());

        let public_nvr = match public_nvr {
            Some(nvr) => nvr,
            None => self.protect().nvr().await.map_err(api_error)?,
        };
        let local_nvr = local_bootstrap.as_ref().map(|bootstrap| &bootstrap.nvr);
        let recorders = vec![recorder_view(public_nvr, local_nvr)];

        let idle_count = idle.len();
        let idle_truncated = idle_count > IDLE_CAMERA_LIST_CEILING;
        let idle: Vec<CameraReferenceView> =
            idle.into_iter().take(IDLE_CAMERA_LIST_CEILING).collect();

        let bootstrap_details = match input.detail_fields.as_deref() {
            Some(fields) => {
                let bootstrap = local_bootstrap.as_ref().ok_or_else(|| {
                    local_error.as_ref().map_or_else(
                        || McpError::invalid_params("local Protect details are unavailable", None),
                        |error| api_error(error.clone()),
                    )
                })?;
                Some(select_bootstrap_details(
                    &bootstrap.raw,
                    false,
                    Some(fields),
                )?)
            }
            None => None,
        };
        protect_overview_result(ProtectOverviewResult::Summary(Box::new(
            ProtectOverviewOutput {
                console: self.protect_name().to_owned(),
                application_version,
                cameras_by_state: counts
                    .into_iter()
                    .map(|(state, count)| CameraCountRow { state, count })
                    .collect(),
                camera_count: cameras.len(),
                not_recording: recording_summary_complete.then_some(idle),
                not_recording_truncated: (recording_summary_complete && idle_truncated)
                    .then_some(true),
                not_recording_count: recording_summary_complete.then_some(idle_count),
                recorders,
                bootstrap_details,
                capabilities: protect_capabilities(local_state, local_error.as_ref()),
            },
        )))
    }

    /// Historical detections through the Protect application route.
    #[expect(
        clippy::too_many_lines,
        reason = "one event page binds camera selection, filters, continuation and count metadata"
    )]
    async fn protect_events_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectEventsInput>(params)?;
        let (include_details, detail_fields) = event_detail_selection(&input)?;
        let limit = input.limit;
        validate_page(limit)?;

        let selector = input.camera.as_deref().map(camera_selector).transpose()?;
        let mut inventory = self
            .camera_inventory(CameraInventoryScope::Public)
            .await?
            .cameras;
        if input.cursor.is_none()
            && selector
                .is_some_and(|selector| !inventory.iter().any(|camera| camera.id == selector))
        {
            let named_inventory = self
                .camera_inventory(CameraInventoryScope::CameraNames)
                .await?;
            if named_inventory.local_state != LocalEnrichmentState::Available {
                return Err(local_inventory_error(
                    named_inventory.local_error.as_ref(),
                    "camera name selection requires complete local Protect inventory; select by id",
                ));
            }
            inventory = named_inventory.cameras;
        }
        let query = resolve_protect_event_query(input, &inventory)?;
        let camera_names: BTreeMap<String, String> = inventory
            .into_iter()
            .filter_map(|camera| Some((camera.id, camera.name?)))
            .collect();

        let page = self
            .protect_events()?
            .protect_events(
                query.window_start,
                query.window_end,
                protect_limit(limit),
                query.continuation.as_ref(),
            )
            .await
            .map_err(protect_events_api_error)?;
        let rows: Vec<ProtectEventView> = page
            .events
            .into_iter()
            .filter(|event| {
                query
                    .camera_id
                    .as_deref()
                    .is_none_or(|camera| event.camera.as_deref() == Some(camera))
                    && query.detection.as_deref().is_none_or(|wanted| {
                        event.kind.eq_ignore_ascii_case(wanted)
                            || event
                                .smart_detect_types
                                .iter()
                                .any(|kind| kind.eq_ignore_ascii_case(wanted))
                    })
            })
            .map(|event| {
                let camera_name = event
                    .camera
                    .as_ref()
                    .and_then(|id| camera_names.get(id))
                    .cloned();
                ProtectEventView {
                    id: event.id,
                    kind: bounded_text(event.kind),
                    start: event.start,
                    end: event.end,
                    score: event.score,
                    camera_id: event.camera.map(bounded_text),
                    camera_name,
                    detection_types: event
                        .smart_detect_types
                        .into_iter()
                        .map(bounded_text)
                        .collect(),
                    details: select_event_details(
                        event.details,
                        include_details,
                        detail_fields.as_deref(),
                    ),
                }
            })
            .collect();

        let next_cursor = page.next.map(|next| ProtectEventsCursor {
            window_start: query.window_start,
            window_end: query.window_end,
            next_end: next.next_end,
            camera_id: query.camera_id,
            detection: query.detection,
        });
        structured(ProtectEventsOutput {
            page_counts: PageCounts {
                requested_limit: limit,
                effective_limit: u64::from(protect_limit(limit)),
                returned: rows.len(),
            },
            rows,
            window_start: query.window_start,
            window_end: query.window_end,
            scanned_rows: page.scanned_rows,
            complete: next_cursor.is_none(),
            next_cursor,
        })
    }

    async fn firewall_read(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<FirewallReadInput>(params)?;
        let start = validate_section_offset(&input)?;
        let wanted =
            |section: FirewallSection| input.section.is_none() || input.section == Some(section);

        // The Integration site identity and the generation probe are
        // dependencies of the zone sections only: the legacy sections address
        // the controller by its configured site name and read identically on
        // both console generations, so a narrowing to them resolves neither.
        let needs_generation = input.section.is_none_or(generation_specific);
        let zone_based = if needs_generation {
            let site_id = self.site_id().await?;
            let capabilities = capability::detect(self.integration(), &site_id)
                .await
                .map_err(api_error)?;
            if let Some(rejection) = capabilities.firewall_rejection {
                return Err(api_error(rejection));
            }
            capabilities.firewall == FirewallGeneration::ZoneBased
        } else {
            false
        };
        let (generation, generation_note) = if needs_generation {
            (
                Some("zoneBased"),
                Some("zone-based firewall supported by the controller capability probe"),
            )
        } else {
            (None, None)
        };

        let scan = if zone_based {
            let site_id = self.site_id().await?;
            self.zone_based_sections(&site_id, input.section, start)
                .await?
        } else {
            ZoneScan::default()
        };
        // Each section is fetched only when the narrowing selects it, so a
        // narrowed read never fails on an endpoint it did not ask for.
        let port_forwards = if wanted(FirewallSection::PortForwards) {
            self.port_forwards_section().await?
        } else {
            Vec::new()
        };
        let traffic_rules = if wanted(FirewallSection::TrafficRules) {
            self.traffic_rules_section().await?
        } else {
            Vec::new()
        };
        let traffic_routes = if wanted(FirewallSection::TrafficRoutes) {
            self.traffic_routes_section().await?
        } else {
            Vec::new()
        };

        structured(FirewallReadOutput {
            generation,
            section: input.section.map(section_word),
            sections_truncated: scan.truncated.then_some(true),
            next_section_offset: scan.next_offset,
            truncation_note: scan.note,
            generation_note,
            zones: scan.zones,
            policies: scan.policies,
            port_forwards,
            traffic_rules,
            traffic_routes,
        })
    }

    /// Gather the zone-based sections a narrowing selected, continuing a
    /// paginated section from `start` when that section is the narrowed one.
    async fn zone_based_sections(
        &self,
        site_id: &str,
        section: Option<FirewallSection>,
        start: u64,
    ) -> Result<ZoneScan, McpError> {
        let mut scan = ZoneScan::default();
        // Sections cut while unnarrowed. A continuation offset addresses one
        // section, so an unnarrowed read has none to offer; naming what was
        // cut and how to reach it keeps the flag from being a dead end.
        let mut cut: Vec<&'static str> = Vec::new();
        let mut record = |truncated: bool, this: FirewallSection, returned: usize| {
            if !truncated {
                return;
            }
            scan.truncated = true;
            if section != Some(this) {
                cut.push(section_word(this));
                return;
            }
            scan.next_offset = Some(start.saturating_add(returned as u64));
        };
        let scan_start = |this: FirewallSection| if section == Some(this) { start } else { 0 };

        if section.is_none() || section == Some(FirewallSection::Zones) {
            let (rows, truncated) = self
                .zones_section(site_id, scan_start(FirewallSection::Zones))
                .await?;
            record(truncated, FirewallSection::Zones, rows.len());
            scan.zones = rows;
        }
        if section.is_none() || section == Some(FirewallSection::Policies) {
            let (rows, truncated) = self
                .policies_section(site_id, scan_start(FirewallSection::Policies))
                .await?;
            record(truncated, FirewallSection::Policies, rows.len());
            scan.policies = rows;
        }
        if !cut.is_empty() {
            scan.note = Some(format!(
                "{} reached the response bound for this read; narrow with \
                 section and continue with sectionOffset to read the rest",
                cut.join(" and ")
            ));
        }
        Ok(scan)
    }

    async fn zones_section(
        &self,
        site_id: &str,
        start: u64,
    ) -> Result<(Vec<ZoneView>, bool), McpError> {
        let (zones, truncated) = paged_gather(start, ZONE_SCAN_CEILING, |offset| {
            let site_id = site_id.to_owned();
            async move {
                self.integration()
                    .firewall_zones(&site_id, page_at(offset))
                    .await
            }
        })
        .await?;
        Ok((
            zones
                .into_iter()
                .map(|zone| ZoneView {
                    id: zone.id,
                    name: zone.name,
                })
                .collect(),
            truncated,
        ))
    }

    async fn policies_section(
        &self,
        site_id: &str,
        start: u64,
    ) -> Result<(Vec<PolicyView>, bool), McpError> {
        let (policies, truncated) = paged_gather(start, POLICY_SCAN_CEILING, |offset| {
            let site_id = site_id.to_owned();
            async move {
                self.integration()
                    .firewall_policies(&site_id, page_at(offset))
                    .await
            }
        })
        .await?;
        Ok((
            policies
                .into_iter()
                .map(|policy| PolicyView {
                    id: policy.id,
                    name: policy.name,
                    enabled: policy.enabled,
                    logging_enabled: policy.logging_enabled,
                    action: policy
                        .action
                        .as_ref()
                        .and_then(|value| firewall_attribute_name(value, "type"))
                        .map(str::to_owned),
                    index: policy.index,
                    ip_protocol_scope: policy
                        .ip_protocol_scope
                        .as_ref()
                        .and_then(|value| firewall_attribute_name(value, "ipVersion"))
                        .map(str::to_owned),
                    source_zone_id: policy.source.as_ref().and_then(|side| side.zone_id.clone()),
                    source_port: policy.source.as_ref().and_then(|side| side.port.clone()),
                    destination_zone_id: policy
                        .destination
                        .as_ref()
                        .and_then(|side| side.zone_id.clone()),
                    destination_port: policy
                        .destination
                        .as_ref()
                        .and_then(|side| side.port.clone()),
                })
                .collect(),
            truncated,
        ))
    }

    async fn port_forwards_section(&self) -> Result<Vec<PortForwardView>, McpError> {
        Ok(self
            .legacy()
            .port_forwards(self.legacy_site())
            .await
            .map_err(api_error)?
            .into_iter()
            .map(port_forward_view)
            .collect())
    }

    async fn traffic_rules_section(&self) -> Result<Vec<TrafficRuleView>, McpError> {
        Ok(self
            .legacy()
            .traffic_rules(self.legacy_site())
            .await
            .map_err(api_error)?
            .into_iter()
            .map(|rule| TrafficRuleView {
                id: rule.id,
                description: rule.description,
                enabled: rule.enabled,
                action: rule.action,
                matching_target: rule.matching_target,
                network_id: rule.network_id,
                domains: rule.domains,
            })
            .collect())
    }

    async fn traffic_routes_section(&self) -> Result<Vec<TrafficRouteView>, McpError> {
        Ok(self
            .legacy()
            .traffic_routes(self.legacy_site())
            .await
            .map_err(api_error)?
            .into_iter()
            .map(|route| TrafficRouteView {
                id: route.id,
                description: route.description,
                enabled: route.enabled,
                matching_target: route.matching_target,
                network_id: route.network_id,
                interface: route.interface,
                domains: route.domains,
            })
            .collect())
    }

    async fn networks_read(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworksReadInput>(params)?;

        // The network list also backs wireless name resolution, so it is
        // always fetched; the section filter controls only what is emitted.
        let networks = self
            .legacy()
            .networks(self.legacy_site())
            .await
            .map_err(api_error)?;
        let wlans = if input.section == Some(NetworksSection::Networks) {
            Vec::new()
        } else {
            self.legacy()
                .wlans(self.legacy_site())
                .await
                .map_err(api_error)?
        };

        let network_names: std::collections::HashMap<String, Option<String>> = networks
            .iter()
            .map(|network| (network.id.clone(), network.name.clone()))
            .collect();
        let network_views = if input.section == Some(NetworksSection::Wlans) {
            Vec::new()
        } else {
            networks
                .into_iter()
                .map(|network| NetworkView {
                    name: network.name,
                    purpose: network.purpose,
                    vlan: network.vlan,
                    subnet: network.ip_subnet,
                    enabled: network.enabled,
                    dhcp_enabled: network.dhcpd_enabled,
                    dhcp_start: network.dhcpd_start,
                    dhcp_stop: network.dhcpd_stop,
                })
                .collect()
        };
        let wlan_views = wlans
            .into_iter()
            .map(|wlan| WlanView {
                id: wlan.id,
                ssid: wlan.name,
                enabled: wlan.enabled,
                security: wlan.security,
                hidden: wlan.hide_ssid,
                network: wlan
                    .networkconf_id
                    .as_ref()
                    .and_then(|id| network_names.get(id).cloned())
                    .flatten(),
                passphrase: wlan.x_passphrase,
                radius_profile_id: wlan.radius_profile_id,
            })
            .collect();
        structured(NetworksReadOutput {
            networks: network_views,
            wlans: wlan_views,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one bounded read validates pagination and preserves complete controller records and metadata"
    )]
    async fn network_inventory_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworkInventoryListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        if input
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 2048)
        {
            return Err(McpError::invalid_params(
                "filter must be at most 2048 bytes",
                None,
            ));
        }
        if matches!(input.kind, NetworkInventoryKind::WanInterfaces) && input.filter.is_some() {
            return Err(McpError::invalid_params(
                "the WAN inventory endpoint has no filter parameter",
                None,
            ));
        }
        let requested = PageRequest {
            offset: input.offset,
            limit: integration_limit(input.limit),
        };
        let (page, response) = if let Some(kind) = input.kind.site_kind() {
            let site_id = self.site_id().await?;
            self.integration()
                .site_inventory(&site_id, kind, requested, input.filter.as_deref())
                .await
        } else if matches!(input.kind, NetworkInventoryKind::Sites) {
            self.integration()
                .site_records(requested, input.filter.as_deref())
                .await
        } else if matches!(
            input.kind,
            NetworkInventoryKind::DpiApplications | NetworkInventoryKind::DpiCategories
        ) {
            let kind = if matches!(input.kind, NetworkInventoryKind::DpiCategories) {
                unifi_api::DpiCatalogKind::Categories
            } else {
                unifi_api::DpiCatalogKind::Applications
            };
            self.integration()
                .dpi_catalog(kind, requested, input.filter.as_deref())
                .await
        } else {
            self.integration()
                .countries(requested, input.filter.as_deref())
                .await
        }
        .map_err(api_error)?;
        let row_count = page.data.len() as u64;
        if page.offset != input.offset
            || page.limit == 0
            || page.limit > u64::from(integration_limit(input.limit))
            || row_count > page.limit
            || page.count != row_count
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "inventory page reported offset {}, limit {}, count {}, and {} rows for requested offset {} and limit {}",
                    page.offset, page.limit, page.count, row_count, input.offset, input.limit
                ),
            ));
        }
        let next = input
            .offset
            .checked_add(row_count)
            .ok_or_else(|| page_validation_error(&response, "inventory offset overflow"))?;
        if row_count > 0 && next > page.total_count {
            return Err(page_validation_error(
                &response,
                format!(
                    "inventory page through offset {next} exceeds reported total {}",
                    page.total_count
                ),
            ));
        }
        let row_based_paging = matches!(
            input.kind,
            NetworkInventoryKind::DpiApplications | NetworkInventoryKind::DpiCategories
        ) && input.filter.is_some();
        if next < page.total_count && page.data.is_empty() && !row_based_paging {
            return Err(page_validation_error(
                &response,
                format!(
                    "inventory page at offset {} returned no rows before reported total {}",
                    input.offset, page.total_count
                ),
            ));
        }
        let mut page_metadata = serde_json::from_str::<Map<String, Value>>(response.as_str())
            .map_err(|error| page_validation_error(&response, error.to_string()))?;
        page_metadata.remove("data");
        network_inventory_list_result(NetworkInventoryListOutput {
            page_counts: PageCounts {
                requested_limit: input.limit,
                effective_limit: page.limit,
                returned: page.data.len(),
            },
            kind: input.kind,
            records: Some(page.data),
            records_in_content: None,
            page_metadata: Some(page_metadata),
            page_metadata_in_content: None,
            offset: page.offset,
            limit: page.limit,
            count: page.count,
            total_count: page.total_count,
            next_offset: if row_based_paging {
                (row_count == page.limit).then_some(next)
            } else {
                (next < page.total_count).then_some(next)
            },
            pagination_basis: row_based_paging.then_some("returnedRows"),
        })
    }

    async fn network_switching_detail(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworkSwitchingDetailInput>(params)?;
        if input.id.trim().is_empty()
            || input.id.len() > 256
            || matches!(input.id.as_str(), "." | "..")
        {
            return Err(McpError::invalid_params(
                "id must be a nonempty id of at most 256 bytes",
                None,
            ));
        }
        let kind = match input.kind {
            NetworkSwitchingDetailKind::Lag => SwitchingDetailKind::Lag,
            NetworkSwitchingDetailKind::McLagDomain => SwitchingDetailKind::McLagDomain,
            NetworkSwitchingDetailKind::SwitchStack => SwitchingDetailKind::SwitchStack,
        };
        let site_id = self.site_id().await?;
        let record = self
            .integration()
            .switching_detail(&site_id, kind, &input.id)
            .await
            .map_err(api_error)?;
        record_result(RecordOutput {
            record: Some(record),
            record_in_content: None,
        })
    }

    async fn network_inventory_detail(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworkInventoryDetailInput>(params)?;
        let kind = match input.kind {
            NetworkInventoryDetailKind::ApplicationInfo => {
                if input.id.is_some() {
                    return Err(McpError::invalid_params(
                        "applicationInfo has no id parameter",
                        None,
                    ));
                }
                let record = self.integration().info_record().await.map_err(api_error)?;
                return record_result(RecordOutput {
                    record: Some(record),
                    record_in_content: None,
                });
            }
            NetworkInventoryDetailKind::Client => unifi_api::InventoryDetailKind::Client,
            NetworkInventoryDetailKind::Device => unifi_api::InventoryDetailKind::Device,
            NetworkInventoryDetailKind::DeviceStatistics => {
                unifi_api::InventoryDetailKind::DeviceStatistics
            }
        };
        let id = input.id.ok_or_else(|| {
            McpError::invalid_params(
                "id is required for client, device or deviceStatistics",
                None,
            )
        })?;
        if id.is_empty() || id.len() > 256 || matches!(id.as_str(), "." | "..") {
            return Err(McpError::invalid_params(
                "id must be a nonempty id of at most 256 bytes",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let record = self
            .integration()
            .inventory_detail(&site_id, kind, &id)
            .await
            .map_err(api_error)?;
        record_result(RecordOutput {
            record: Some(record),
            record_in_content: None,
        })
    }

    async fn network_policy_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworkPolicyListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        if input
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 2048)
        {
            return Err(McpError::invalid_params(
                "filter must be at most 2048 bytes",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let (page, response) = self
            .integration()
            .network_policy_page(
                &site_id,
                input.kind.collection(),
                PageRequest {
                    offset: input.offset,
                    limit: integration_limit(input.limit),
                },
                input.filter.as_deref(),
            )
            .await
            .map_err(api_error)?;
        let row_count = page.data.len() as u64;
        if page.offset != input.offset
            || page.limit == 0
            || page.limit > u64::from(integration_limit(input.limit))
            || row_count > page.limit
            || page.count != row_count
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "policy page reported offset {}, limit {}, count {}, and {} rows for requested offset {} and limit {}",
                    page.offset, page.limit, page.count, row_count, input.offset, input.limit
                ),
            ));
        }
        let next = input
            .offset
            .checked_add(row_count)
            .ok_or_else(|| page_validation_error(&response, "policy offset overflow"))?;
        if (row_count > 0 && next > page.total_count)
            || (next < page.total_count && page.data.is_empty())
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "policy page through offset {next} conflicts with reported total {}",
                    page.total_count
                ),
            ));
        }
        network_policy_list_result(NetworkPolicyListOutput {
            page_counts: PageCounts {
                requested_limit: input.limit,
                effective_limit: page.limit,
                returned: page.data.len(),
            },
            kind: input.kind,
            records: Some(page.data),
            records_in_content: None,
            page_metadata: Some(controller_page_metadata(&response)?),
            page_metadata_in_content: None,
            offset: page.offset,
            limit: page.limit,
            count: page.count,
            total_count: page.total_count,
            next_offset: (next < page.total_count).then_some(next),
        })
    }

    async fn network_policy_detail(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<NetworkPolicyDetailInput>(params)?;
        if input.id.trim().is_empty()
            || input.id.len() > 256
            || matches!(input.id.as_str(), "." | "..")
        {
            return Err(McpError::invalid_params(
                "id must be a nonempty id of at most 256 bytes",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let record = self
            .integration()
            .network_policy_detail(&site_id, input.kind.collection(), &input.id)
            .await
            .map_err(api_error)?;
        network_policy_detail_result(NetworkPolicyDetailOutput {
            record: Some(record),
            record_in_content: None,
        })
    }

    async fn firewall_zones_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<FirewallZonesConfigureInput>(params)?;
        let requested = input
            .zone
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
        let plan = policy_write_plan(
            NetworkPolicyKind::FirewallZones,
            input.operation,
            input.id,
            requested,
            input.confirm,
        )?;
        self.network_policy_write(plan).await
    }

    async fn firewall_policies_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<FirewallPoliciesConfigureInput>(params)?;
        let requested = input
            .policy
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
        let plan = policy_write_plan(
            NetworkPolicyKind::FirewallPolicies,
            input.operation,
            input.id,
            requested,
            input.confirm,
        )?;
        self.network_policy_write(plan).await
    }

    async fn dns_policies_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<DnsPoliciesConfigureInput>(params)?;
        let requested = input
            .policy
            .map(|policy| {
                validate_dns_policy_request(&policy)?;
                serde_json::to_value(policy)
                    .map_err(|error| McpError::invalid_params(error.to_string(), None))
            })
            .transpose()?;
        let plan = policy_write_plan(
            NetworkPolicyKind::DnsPolicies,
            input.operation,
            input.id,
            requested,
            input.confirm,
        )?;
        self.network_policy_write(plan).await
    }

    async fn acl_rules_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<AclRulesConfigureInput>(params)?;
        let requested = input
            .rule
            .map(|rule| {
                validate_acl_rule_request(&rule)?;
                serde_json::to_value(rule)
                    .map_err(|error| McpError::invalid_params(error.to_string(), None))
            })
            .transpose()?;
        let plan = policy_write_plan(
            NetworkPolicyKind::AclRules,
            input.operation,
            input.id,
            requested,
            input.confirm,
        )?;
        self.network_policy_write(plan).await
    }

    async fn firewall_policies_ordering_read(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let _: EmptyInput = parse(params)?;
        let site_id = self.site_id().await?;
        let record = self
            .integration()
            .firewall_policy_ordering(&site_id)
            .await
            .map_err(api_error)?;
        network_policy_detail_result(NetworkPolicyDetailOutput {
            record: Some(record),
            record_in_content: None,
        })
    }

    async fn firewall_policies_ordering_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<FirewallPolicyOrderingConfigureInput>(params)?;
        let requested = serde_json::json!({"orderedFirewallPolicyIds": {
            "beforeSystemDefined": input.ordered_firewall_policy_ids.before_system_defined,
            "afterSystemDefined": input.ordered_firewall_policy_ids.after_system_defined,
        }});
        if requested.to_string().len() > MAXIMUM_POLICY_REQUEST_BYTES {
            return Err(McpError::invalid_params(
                "firewall policy ordering request exceeds the 1 MiB request bound",
                None,
            ));
        }
        let mut output = NetworkPolicyWriteOutput {
            kind: "firewallPolicies",
            operation: NetworkPolicyWriteOperation::Update,
            consequence: "replace the priority order of the site's user-defined firewall policies",
            id: None,
            requested: Some(requested),
            requested_in_content: None,
            submitted: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            accepted: None,
            accepted_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            verified_absent: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return network_policy_write_result(output);
        }
        let site_id = self.site_id().await?;
        let (status, accepted) = self
            .integration()
            .replace_firewall_policy_ordering(
                &site_id,
                &input.ordered_firewall_policy_ids.before_system_defined,
                &input.ordered_firewall_policy_ids.after_system_defined,
            )
            .await
            .map_err(api_error)?;
        output.submitted = true;
        output.response_status = Some(status);
        output.accepted = Some(accepted);
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_POLICY_RESPONSE_RESERVE)
            .min(NETWORK_POLICY_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("firewall policy ordering readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(
                budget,
                self.integration().firewall_policy_ordering(&site_id),
            )
            .await
            {
                Ok(Ok(after)) => {
                    let requested_ids = output
                        .requested
                        .as_ref()
                        .and_then(|body| body.get("orderedFirewallPolicyIds"));
                    output.verified = Some(
                        after.get("orderedFirewallPolicyIds") == requested_ids
                            && output
                                .accepted
                                .as_ref()
                                .and_then(|body| body.get("orderedFirewallPolicyIds"))
                                == requested_ids,
                    );
                    output.after = Some(after);
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => {
                    output.readback_error =
                        Some("firewall policy ordering readback timed out".to_owned());
                }
            }
        }
        network_policy_write_result(output)
    }

    async fn acl_rules_ordering_read(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let _: AclRulesOrderingReadInput = parse(params)?;
        let site_id = self.site_id().await?;
        let record = self
            .integration()
            .acl_rule_ordering(&site_id)
            .await
            .map_err(api_error)?;
        network_policy_detail_result(NetworkPolicyDetailOutput {
            record: Some(record),
            record_in_content: None,
        })
    }

    async fn acl_rules_ordering_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<AclRulesOrderingConfigureInput>(params)?;
        let requested = serde_json::json!({"orderedAclRuleIds": input.ordered_acl_rule_ids});
        if requested.to_string().len() > MAXIMUM_POLICY_REQUEST_BYTES {
            return Err(McpError::invalid_params(
                "ACL ordering request exceeds the 1 MiB request bound",
                None,
            ));
        }
        let mut output = NetworkPolicyWriteOutput {
            kind: NetworkPolicyKind::AclRules,
            operation: NetworkPolicyWriteOperation::Update,
            consequence: "replace the priority order of the site's ACL rules",
            id: None,
            requested: Some(requested),
            requested_in_content: None,
            submitted: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            accepted: None,
            accepted_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            verified_absent: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return network_policy_write_result(output);
        }
        let site_id = self.site_id().await?;
        let (status, accepted) = self
            .integration()
            .replace_acl_rule_ordering(&site_id, &input.ordered_acl_rule_ids)
            .await
            .map_err(api_error)?;
        output.submitted = true;
        output.response_status = Some(status);
        output.accepted = Some(accepted);
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_POLICY_RESPONSE_RESERVE)
            .min(NETWORK_POLICY_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("ACL ordering readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(budget, self.integration().acl_rule_ordering(&site_id)).await
            {
                Ok(Ok(after)) => {
                    let requested_ids = output
                        .requested
                        .as_ref()
                        .and_then(|body| body.get("orderedAclRuleIds"));
                    output.verified = Some(
                        after.get("orderedAclRuleIds") == requested_ids
                            && output
                                .accepted
                                .as_ref()
                                .and_then(|body| body.get("orderedAclRuleIds"))
                                == requested_ids,
                    );
                    output.after = Some(after);
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => {
                    output.readback_error = Some("ACL ordering readback timed out".to_owned());
                }
            }
        }
        network_policy_write_result(output)
    }

    async fn traffic_lists_configure(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<TrafficListsConfigureInput>(params)?;
        let requested = input
            .list
            .map(|list| {
                validate_traffic_list_request(&list)?;
                serde_json::to_value(list)
                    .map_err(|error| McpError::invalid_params(error.to_string(), None))
            })
            .transpose()?;
        let plan = policy_write_plan(
            NetworkPolicyKind::TrafficMatchingLists,
            input.operation,
            input.id,
            requested,
            input.confirm,
        )?;
        self.network_policy_write(plan).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "The three fixed policy mutations share one accepted-response and readback contract"
    )]
    async fn network_policy_write(
        &self,
        plan: NetworkPolicyWritePlan,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let mut output = NetworkPolicyWriteOutput {
            kind: plan.kind,
            operation: plan.operation,
            consequence: match plan.operation {
                NetworkPolicyWriteOperation::Create => "create another policy, zone, or list",
                NetworkPolicyWriteOperation::Update => "replace the named policy, zone, or list",
                NetworkPolicyWriteOperation::Delete => {
                    "delete the named policy, zone, or list and change rules that depend on it"
                }
            },
            id: plan.id,
            requested: plan.requested,
            requested_in_content: None,
            submitted: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            accepted: None,
            accepted_in_content: None,
            after: None,
            after_in_content: None,
            verified: None,
            verified_absent: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !plan.confirm {
            return network_policy_write_result(output);
        }
        let site_id = self.site_id().await?;
        match output.operation {
            NetworkPolicyWriteOperation::Create | NetworkPolicyWriteOperation::Update => {
                let requested = output.requested.as_ref().expect("validated policy body");
                let (status, accepted) = if output.operation == NetworkPolicyWriteOperation::Create
                {
                    self.integration()
                        .network_policy_create(&site_id, output.kind.collection(), requested)
                        .await
                } else {
                    self.integration()
                        .network_policy_update(
                            &site_id,
                            output.kind.collection(),
                            output.id.as_deref().expect("validated policy id"),
                            requested,
                        )
                        .await
                }
                .map_err(api_error)?;
                let accepted_id = accepted
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                output.submitted = true;
                output.response_status = Some(status);
                output.accepted = Some(accepted);
                let id = output.id.clone().or(accepted_id.clone());
                output.id = id.clone();
                if let Some(id) = id {
                    let budget = self
                        .request_timeout()
                        .saturating_sub(started.elapsed())
                        .saturating_sub(NETWORK_POLICY_RESPONSE_RESERVE)
                        .min(NETWORK_POLICY_READBACK_BUDGET);
                    if budget.is_zero() {
                        output.readback_error =
                            Some("policy readback skipped near request deadline".to_owned());
                    } else {
                        match tokio::time::timeout(
                            budget,
                            self.integration().network_policy_detail(
                                &site_id,
                                output.kind.collection(),
                                &id,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(after)) => {
                                output.verified = Some(
                                    after.get("id").and_then(Value::as_str) == Some(id.as_str())
                                        && accepted_id.as_deref() == Some(id.as_str())
                                        && if matches!(
                                            output.kind,
                                            NetworkPolicyKind::FirewallPolicies
                                        ) {
                                            firewall_policy_request::matches(requested, &after)
                                        } else {
                                            requested_json_matches(requested, &after)
                                        },
                                );
                                output.after = Some(after);
                            }
                            Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                            Err(_) => {
                                output.readback_error =
                                    Some("policy readback timed out".to_owned());
                            }
                        }
                    }
                } else {
                    output.readback_error =
                        Some("accepted policy record had no id for readback".to_owned());
                }
            }
            NetworkPolicyWriteOperation::Delete => {
                let id = output.id.as_deref().expect("validated policy id");
                let (status, body) = self
                    .integration()
                    .network_policy_delete(&site_id, output.kind.collection(), id)
                    .await
                    .map_err(api_error)?;
                output.submitted = true;
                output.response_status = Some(status);
                output.response_body =
                    Some(BoundedMessage::from_controller_bytes(&body).to_string());
                let budget = self
                    .request_timeout()
                    .saturating_sub(started.elapsed())
                    .saturating_sub(NETWORK_POLICY_RESPONSE_RESERVE)
                    .min(NETWORK_POLICY_READBACK_BUDGET);
                if budget.is_zero() {
                    output.readback_error =
                        Some("policy readback skipped near request deadline".to_owned());
                } else {
                    match tokio::time::timeout(
                        budget,
                        self.integration().network_policy_detail(
                            &site_id,
                            output.kind.collection(),
                            id,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(after)) => {
                            output.after = Some(after);
                            output.verified_absent = Some(false);
                        }
                        Ok(Err(error @ ApiError::Status { status: 404, .. })) => {
                            output.verified_absent = Some(true);
                            output.readback_error = Some(error.to_string());
                        }
                        Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                        Err(_) => {
                            output.readback_error = Some("policy readback timed out".to_owned());
                        }
                    }
                }
            }
        }
        network_policy_write_result(output)
    }

    async fn radius_profiles_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<RadiusProfilesListInput>(params)?;
        if input.limit == 0 {
            return Err(McpError::invalid_params("limit must be positive", None));
        }
        if input
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 2048)
        {
            return Err(McpError::invalid_params(
                "filter must be at most 2048 bytes",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let (page, response) = self
            .integration()
            .radius_profile_records(
                &site_id,
                PageRequest {
                    offset: input.offset,
                    limit: integration_limit(input.limit),
                },
                input.filter.as_deref(),
            )
            .await
            .map_err(api_error)?;
        let row_count = page.data.len() as u64;
        if page.offset != input.offset
            || page.limit == 0
            || page.limit > u64::from(integration_limit(input.limit))
            || row_count > page.limit
            || page.count != row_count
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "RADIUS profile page reported offset {}, limit {}, count {}, and {} rows for requested offset {} and limit {}",
                    page.offset, page.limit, page.count, row_count, input.offset, input.limit
                ),
            ));
        }
        let next = input
            .offset
            .checked_add(row_count)
            .ok_or_else(|| page_validation_error(&response, "RADIUS profile offset overflow"))?;
        if (row_count > 0 && next > page.total_count)
            || (next < page.total_count && page.data.is_empty())
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "RADIUS profile page through offset {next} conflicts with reported total {}",
                    page.total_count
                ),
            ));
        }
        radius_profiles_list_result(RadiusProfilesListOutput {
            page_counts: PageCounts {
                requested_limit: input.limit,
                effective_limit: page.limit,
                returned: page.data.len(),
            },
            profiles: Some(page.data),
            profiles_in_content: None,
            page_metadata: Some(controller_page_metadata(&response)?),
            page_metadata_in_content: None,
            offset: page.offset,
            limit: page.limit,
            count: page.count,
            total_count: page.total_count,
            next_offset: (next < page.total_count).then_some(next),
        })
    }

    async fn wifi_broadcasts_list(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<WifiBroadcastsListInput>(params)?;
        if input.offset > i32::MAX as u64 || input.limit == 0 {
            return Err(McpError::invalid_params(
                "offset must be 0-2147483647 and limit must be positive",
                None,
            ));
        }
        if input
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 2048)
        {
            return Err(McpError::invalid_params(
                "filter must be at most 2048 bytes",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let (original, response) = self
            .integration()
            .wifi_broadcast_records(
                &site_id,
                PageRequest {
                    offset: input.offset,
                    limit: integration_limit(input.limit),
                },
                input.filter.as_deref(),
            )
            .await
            .map_err(api_error)?;
        let page: unifi_api::models::Page<Map<String, Value>> =
            serde_json::from_value(original.clone())
                .map_err(|error| page_validation_error(&response, error.to_string()))?;
        let mut page_metadata = original
            .as_object()
            .ok_or_else(|| {
                page_validation_error(&response, "Wi-Fi broadcast page must be a JSON object")
            })?
            .clone();
        for field in ["offset", "limit", "count", "totalCount", "data"] {
            page_metadata.remove(field);
        }
        let row_count = page.data.len() as u64;
        if page.offset != input.offset
            || page.limit == 0
            || page.limit > u64::from(integration_limit(input.limit))
            || row_count > page.limit
            || page.count != row_count
        {
            return Err(page_validation_error(
                &response,
                format!(
                    "Wi-Fi broadcast page reported offset {}, limit {}, count {}, and {} rows for requested offset {} and limit {}",
                    page.offset, page.limit, page.count, row_count, input.offset, input.limit
                ),
            ));
        }
        let next = input
            .offset
            .checked_add(row_count)
            .ok_or_else(|| page_validation_error(&response, "Wi-Fi broadcast offset overflow"))?;
        if row_count > 0 && next > page.total_count {
            return Err(page_validation_error(
                &response,
                format!(
                    "Wi-Fi broadcast page through offset {next} exceeds reported total {}",
                    page.total_count
                ),
            ));
        }
        if next < page.total_count && page.data.is_empty() {
            return Err(page_validation_error(
                &response,
                format!(
                    "Wi-Fi broadcast page at offset {} returned no rows before reported total {}",
                    input.offset, page.total_count
                ),
            ));
        }
        wifi_broadcasts_list_result(WifiBroadcastsListOutput {
            page_counts: PageCounts {
                requested_limit: input.limit,
                effective_limit: page.limit,
                returned: page.data.len(),
            },
            broadcasts: Some(page.data),
            broadcasts_in_content: None,
            page_metadata: (!page_metadata.is_empty()).then_some(page_metadata),
            page_metadata_in_content: None,
            offset: page.offset,
            limit: page.limit,
            count: page.count,
            total_count: page.total_count,
            next_offset: (next < page.total_count).then_some(next),
        })
    }

    async fn wifi_broadcasts_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<WifiBroadcastsStatusInput>(params)?;
        if input.broadcast_id.trim().is_empty()
            || input.broadcast_id.len() > 256
            || matches!(input.broadcast_id.as_str(), "." | "..")
        {
            return Err(McpError::invalid_params(
                "broadcastId must be a nonempty id of at most 256 bytes",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let record = self
            .integration()
            .wifi_broadcast(&site_id, &input.broadcast_id)
            .await
            .map_err(api_error)?;
        let full = structured(&record)?;
        if full
            .structured_content
            .as_ref()
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        {
            return network_policy_detail_result(NetworkPolicyDetailOutput {
                record: Some(Value::Object(record)),
                record_in_content: None,
            });
        }
        Ok(full)
    }

    /// Authorize one client for guest access, previewing unless the caller
    /// confirms.
    async fn guests_authorize(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<GuestsAuthorizeInput>(params)?;
        let client = guest_client_address(&input.client)?;
        let limits = guest_limits(&input)?;
        let warnings = vec![
            "authorization replaces any active guest grant and resets guest traffic counters"
                .to_owned(),
        ];
        let mut output = GuestsAuthorizeOutput {
            client: client.clone(),
            action: "authorize",
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            requested_limits: Some(GuestLimitsView {
                time_limit_minutes: input.time_limit_minutes,
                data_usage_limit_m_bytes: input.data_usage_limit_m_bytes,
                rx_rate_limit_kbps: input.rx_rate_limit_kbps,
                tx_rate_limit_kbps: input.tx_rate_limit_kbps,
            }),
            authorized_before: None,
            authorized_after: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
            granted_authorization: None,
            revoked_authorization: None,
            observed_authorization: None,
            warnings,
        };
        if !input.confirm.unwrap_or(false) {
            return structured(output);
        }
        let site_id = self.site_id().await?;
        let client_id = self.integration_client_id(&site_id, &client).await?;
        let before = self.guest_detail(&site_id, &client_id, &client).await?;
        output.authorized_before = before.access.as_ref().and_then(|access| access.authorized);
        let (response, status, body) = self
            .integration()
            .authorize_guest(&site_id, &client_id, limits)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response_status = Some(status);
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let grant = response
            .granted_authorization
            .expect("validated action response");
        output.granted_authorization = Some(grant.clone().into());
        output.revoked_authorization = response.revoked_authorization.map(Into::into);
        let upstream_error = self
            .guest_readback(
                &site_id,
                &client_id,
                &client,
                started,
                &mut output,
                Some(&grant),
            )
            .await;
        structured_with_mutation_readback_error(output, upstream_error.as_ref())
    }

    async fn guests_unauthorize(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<GuestsUnauthorizeInput>(params)?;
        let client = guest_client_address(&input.client)?;
        let mut output = GuestsAuthorizeOutput {
            client: client.clone(),
            action: "unauthorize",
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            requested_limits: None,
            authorized_before: None,
            authorized_after: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
            granted_authorization: None,
            revoked_authorization: None,
            observed_authorization: None,
            warnings: vec!["unauthorizing a guest also disconnects the client".to_owned()],
        };
        if !input.confirm.unwrap_or(false) {
            return structured(output);
        }
        let site_id = self.site_id().await?;
        let client_id = self.integration_client_id(&site_id, &client).await?;
        let before = self.guest_detail(&site_id, &client_id, &client).await?;
        output.authorized_before = before.access.as_ref().and_then(|access| access.authorized);
        let (response, status, body) = self
            .integration()
            .unauthorize_guest(&site_id, &client_id)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response_status = Some(status);
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        output.revoked_authorization = response.revoked_authorization.map(Into::into);
        let upstream_error = self
            .guest_readback(&site_id, &client_id, &client, started, &mut output, None)
            .await;
        structured_with_mutation_readback_error(output, upstream_error.as_ref())
    }

    async fn guests_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<GuestClientInput>(params)?;
        let client = guest_client_address(&input.client)?;
        let site_id = self.site_id().await?;
        let client_id = self.integration_client_id(&site_id, &client).await?;
        let detail = self.guest_detail(&site_id, &client_id, &client).await?;
        let access = detail.access.expect("validated guest detail");
        structured(GuestStatusOutput {
            client,
            authorized: access
                .authorized
                .expect("validated guest authorization state"),
            authorization: access.authorization.map(Into::into),
        })
    }

    async fn guest_detail(
        &self,
        site_id: &str,
        client_id: &str,
        mac: &str,
    ) -> Result<ClientDetail, McpError> {
        let (detail, response) = self
            .integration()
            .client_detail_with_response(site_id, client_id)
            .await
            .map_err(api_error)?;
        if detail.id != client_id
            || detail.mac_address.as_deref().map(normalize_mac).as_deref() != Some(mac)
        {
            return Err(api_error(guest_validation_error(
                response,
                "controller returned a different connected client",
            )));
        }
        match detail.access.as_ref() {
            Some(access) if access.kind == "GUEST" && access.authorized.is_some() => Ok(detail),
            Some(access) if access.kind != "GUEST" => Err(McpError::invalid_params(
                format!(
                    "controller response: {response}; validation error: the selected client is not on guest access"
                ),
                None,
            )),
            _ => Err(api_error(guest_validation_error(
                response,
                "controller did not report guest authorization state",
            ))),
        }
    }

    async fn guest_readback(
        &self,
        site_id: &str,
        client_id: &str,
        mac: &str,
        started: tokio::time::Instant,
        output: &mut GuestsAuthorizeOutput,
        grant: Option<&GuestAuthorization>,
    ) -> Option<ApiError> {
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(GUEST_RESPONSE_RESERVE)
            .min(GUEST_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            None
        } else {
            Some(
                tokio::time::timeout(
                    budget,
                    self.integration()
                        .client_detail_with_response(site_id, client_id),
                )
                .await,
            )
        };
        let mut upstream_error = None;
        match readback {
            Some(Ok(Ok((detail, response))))
                if detail.id == client_id
                    && detail.mac_address.as_deref().map(normalize_mac).as_deref() == Some(mac) =>
            {
                if let Some(access) = detail.access.filter(|access| access.kind == "GUEST") {
                    output.authorized_after = access.authorized;
                    output.observed_authorization = access
                        .authorization
                        .clone()
                        .map(GuestAuthorizationView::from);
                    output.verified = access.authorized.map(|authorized| {
                        if let Some(grant) = grant {
                            authorized
                                && access.authorization.as_ref().is_some_and(|observed| {
                                    observed.authorized_at == grant.authorized_at
                                        && observed.expires_at == grant.expires_at
                                        && observed.authorization_method
                                            == grant.authorization_method
                                        && observed.data_usage_limit_m_bytes
                                            == grant.data_usage_limit_m_bytes
                                        && observed.rx_rate_limit_kbps == grant.rx_rate_limit_kbps
                                        && observed.tx_rate_limit_kbps == grant.tx_rate_limit_kbps
                                })
                        } else {
                            !authorized
                        }
                    });
                }
                if output.verified != Some(true) {
                    let error = guest_validation_error(
                        response,
                        "controller guest readback did not confirm the action",
                    );
                    output.readback_error = Some(error.to_string());
                    upstream_error = Some(error);
                    output.warnings.push(
                        "the action response was returned, but the current guest state was not verified"
                            .to_owned(),
                    );
                }
            }
            Some(Ok(Ok((_, response)))) => {
                let error = guest_validation_error(
                    response,
                    "controller guest readback returned a different connected client",
                );
                output.readback_error = Some(error.to_string());
                upstream_error = Some(error);
            }
            Some(Ok(Err(error))) => {
                output.readback_error = Some(error.to_string());
                upstream_error = Some(error);
            }
            Some(Err(_)) => output.warnings.push("guest readback timed out".to_owned()),
            None => output
                .warnings
                .push("guest readback skipped because the request deadline was near".to_owned()),
        }
        if output.verified != Some(true) && upstream_error.is_none() {
            output.warnings.push(
                "the action response was returned, but the current guest state was not verified"
                    .to_owned(),
            );
        }
        upstream_error
    }

    /// The controller's id for the client at one hardware address.
    async fn integration_client_id(&self, site_id: &str, mac: &str) -> Result<String, McpError> {
        let (clients, truncated) = paged_gather(0, CLIENT_SCAN_CEILING, |offset| async move {
            self.integration().clients(site_id, page_at(offset)).await
        })
        .await?;
        clients
            .into_iter()
            .find(|client| client.mac_address.as_deref().map(normalize_mac).as_deref() == Some(mac))
            .map(|client| client.id)
            .ok_or_else(|| {
                McpError::invalid_params(
                    if truncated {
                        "no client with that address was found, and the client \
                         scan stopped at its ceiling, so the address may exist \
                         beyond it; nothing was authorized"
                    } else {
                        "no client with that address is known to the \
                         controller; clients.search lists them"
                    },
                    None,
                )
            })
    }

    /// Restart, locate, or power-cycle a port on one device, previewing
    /// unless the caller confirms.
    async fn devices_control(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<DevicesControlInput>(params)?;
        let port = validated_port(input.action, input.port)?;

        let site_id = self.site_id().await?;
        let detail = self
            .integration()
            .device_detail(&site_id, &input.device)
            .await
            .map_err(api_error)?;
        let warnings = device_control_warnings(input.action);
        let mut output = DevicesControlOutput {
            device: input.device,
            name: detail.name.clone(),
            action: input.action.word(),
            port,
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            state_before: detail.state,
            state_after: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings,
        };
        if !input.confirm.unwrap_or(false) {
            return devices_control_result(output);
        }

        let (status, body) = match input.action {
            DeviceControl::Restart => {
                let (status, body) = self
                    .integration()
                    .restart_device(&site_id, &output.device)
                    .await
                    .map_err(api_error)?;
                (Some(status), body)
            }
            DeviceControl::PortCycle => {
                let port = port
                    .ok_or_else(|| McpError::invalid_params("portCycle requires a port", None))?;
                let (status, body) = self
                    .integration()
                    .power_cycle_port(&site_id, &output.device, port)
                    .await
                    .map_err(api_error)?;
                (Some(status), body)
            }
            DeviceControl::Locate | DeviceControl::EndLocate => {
                // The locate LED is a legacy-only command, addressed by the
                // hardware address the device record already carries.
                let mac = detail.mac_address.as_deref().ok_or_else(|| {
                    McpError::invalid_params(
                        "the controller reports no hardware address for this device, \
                         so its locate LED cannot be addressed",
                        None,
                    )
                })?;
                let (status, body) = self
                    .legacy()
                    .locate_device(
                        self.legacy_site(),
                        mac,
                        input.action == DeviceControl::Locate,
                    )
                    .await
                    .map_err(api_error)?;
                (Some(status), body)
            }
        };
        output.applied = true;
        output.response_status = status;
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_ACTION_RESPONSE_RESERVE)
            .min(NETWORK_ACTION_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("device readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(
                budget,
                self.integration().device_detail(&site_id, &output.device),
            )
            .await
            {
                Ok(Ok(after)) => {
                    output.name = after.name;
                    output.state_after = after.state;
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => output.readback_error = Some("device readback timed out".to_owned()),
            }
        }
        devices_control_result(output)
    }

    /// Block, unblock, or disconnect one client, previewing unless the
    /// caller confirms.
    async fn clients_control(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<ClientsControlInput>(params)?;
        let client = normalize_mac(&input.client);
        if !is_client_address(&client) {
            return Err(McpError::invalid_params(
                "client must be the unicast MAC address of one client, such \
                 as aa:bb:cc:dd:ee:ff, as clients.search reports it; a group \
                 or broadcast address names no client",
                None,
            ));
        }
        let connected_before = self.client_is_connected(&client).await?;
        let warnings = client_control_warnings(input.action, connected_before);
        let mut output = ClientsControlOutput {
            client,
            action: input.action.word(),
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            connected_before,
            connected_after: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings,
        };

        if !input.confirm.unwrap_or(false) {
            return structured_with_accepted_response(output);
        }

        let legacy = self.legacy();
        let site = self.legacy_site();
        let (status, body) = match input.action {
            ClientControl::Block => legacy.block_client(site, &output.client).await,
            ClientControl::Unblock => legacy.unblock_client(site, &output.client).await,
            ClientControl::Reconnect => legacy.kick_client(site, &output.client).await,
        }
        .map_err(api_error)?;
        output.applied = true;
        output.response_status = Some(status);
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_ACTION_RESPONSE_RESERVE)
            .min(NETWORK_ACTION_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("client readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(budget, self.client_is_connected(&output.client)).await {
                Ok(Ok(connected)) => output.connected_after = Some(connected),
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => output.readback_error = Some("client readback timed out".to_owned()),
            }
        }
        structured_with_accepted_response(output)
    }

    /// Whether one address is in the controller's connected-client list.
    async fn client_is_connected(&self, mac: &str) -> Result<bool, McpError> {
        Ok(self
            .legacy()
            .active_clients(self.legacy_site())
            .await
            .map_err(api_error)?
            .iter()
            .any(|client| client.mac.as_deref().map(normalize_mac).as_deref() == Some(mac)))
    }

    /// Change one wireless network, previewing unless the caller confirms.
    async fn wlans_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        reject_unknown_change_fields(params, WLAN_CHANGE_FIELDS)?;
        let input = parse::<WlansUpdateInput>(params)?;
        let requested = requested_fields(&input.changes);
        if requested.is_empty() {
            return Err(McpError::invalid_params(
                "changes names no field to change",
                None,
            ));
        }

        // The patch is a pure function of the request. The controller merges
        // named fields, so an omitted passphrase remains under its control.
        let patch = wlan_patch(&input.changes);

        let (current, before_digest) = self.wlan_snapshot(&input.wlan).await?;
        let before = wlan_projection(&current);
        let warnings = wlan_warnings(&requested, &before);
        if !input.confirm.unwrap_or(false) {
            return structured(WlansUpdateOutput {
                wlan: input.wlan,
                ssid: current.name,
                applied: false,
                response_status: None,
                response_body: None,
                response_body_in_content: None,
                changes: Some(mutation::plan(&requested, &before)),
                fields: None,
                unexpected_changes: None,
                verified: None,
                readback_error: None,
                readback_error_in_content: None,
                warnings,
            });
        }

        // The digest covers every property the controller stores, including
        // those this server does not model, so a write that clears one is
        // seen rather than certified clean.
        let (status, body) = self
            .legacy()
            .update_wlan(self.legacy_site(), &input.wlan, &patch)
            .await
            .map_err(api_error)?;
        let mut output = WlansUpdateOutput {
            wlan: input.wlan,
            ssid: current.name,
            applied: true,
            response_status: Some(status),
            response_body: Some(BoundedMessage::from_controller_bytes(&body).to_string()),
            response_body_in_content: None,
            changes: None,
            fields: None,
            unexpected_changes: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings,
        };
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_ACTION_RESPONSE_RESERVE)
            .min(NETWORK_ACTION_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("wireless readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(budget, self.wlan_snapshot(&output.wlan)).await {
                Ok(Ok((after_record, after_digest))) => {
                    // Both readback reports describe this same controller response.
                    let after = wlan_projection(&after_record);
                    let fields = mutation::verify(&requested, &before, &after);
                    let unexpected = unrequested_changes(
                        &before_digest,
                        &after_digest,
                        &requested,
                        WLAN_WIRE_NAMES,
                    );
                    output.verified = Some(
                        unexpected.is_empty()
                            && fields
                                .iter()
                                .all(|outcome| outcome.status == mutation::FieldStatus::Persisted),
                    );
                    output.ssid = after_record.name;
                    output.fields = Some(fields);
                    output.unexpected_changes = Some(unexpected);
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => output.readback_error = Some("wireless readback timed out".to_owned()),
            }
        }
        structured_with_accepted_response(output)
    }

    /// Change one port forward, previewing unless the caller confirms.
    async fn port_forwards_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        reject_unknown_change_fields(params, PORT_FORWARD_CHANGE_FIELDS)?;
        let input = parse::<PortForwardsUpdateInput>(params)?;
        let requested = requested_port_forward_fields(&input.changes);
        if requested.is_empty() {
            return Err(McpError::invalid_params(
                "changes names no field to change",
                None,
            ));
        }
        let patch = PortForwardPatch {
            name: input.changes.name.clone(),
            enabled: input.changes.enabled,
            src: input.changes.source.clone(),
            fwd: input.changes.forward_to.clone(),
            fwd_port: input.changes.forward_port.clone(),
            dst_port: input.changes.destination_port.clone(),
            proto: input.changes.protocol.clone(),
        };

        let (current, before_digest) = self.port_forward_snapshot(&input.port_forward).await?;
        let before = port_forward_projection(&current);
        let warnings = port_forward_warnings(&requested, &before);
        if !input.confirm.unwrap_or(false) {
            return structured(PortForwardsUpdateOutput {
                forward: port_forward_view(current),
                applied: false,
                response_status: None,
                response_body: None,
                response_body_in_content: None,
                changes: Some(mutation::plan(&requested, &before)),
                fields: None,
                unexpected_changes: None,
                verified: None,
                readback_error: None,
                readback_error_in_content: None,
                warnings,
            });
        }

        let (status, body) = self
            .legacy()
            .update_port_forward(self.legacy_site(), &input.port_forward, &patch)
            .await
            .map_err(api_error)?;
        let mut output = PortForwardsUpdateOutput {
            forward: port_forward_view(current),
            applied: true,
            response_status: Some(status),
            response_body: Some(BoundedMessage::from_controller_bytes(&body).to_string()),
            response_body_in_content: None,
            changes: None,
            fields: None,
            unexpected_changes: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings,
        };
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(NETWORK_ACTION_RESPONSE_RESERVE)
            .min(NETWORK_ACTION_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("port-forward readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(budget, self.port_forward_snapshot(&input.port_forward))
                .await
            {
                Ok(Ok((after_record, after_digest))) => {
                    // Both readback reports describe this same controller response.
                    let after = port_forward_projection(&after_record);
                    let fields = mutation::verify(&requested, &before, &after);
                    let unexpected = unrequested_changes(
                        &before_digest,
                        &after_digest,
                        &requested,
                        PORT_FORWARD_WIRE_NAMES,
                    );
                    output.verified = Some(
                        unexpected.is_empty()
                            && fields
                                .iter()
                                .all(|outcome| outcome.status == mutation::FieldStatus::Persisted),
                    );
                    output.forward = port_forward_view(after_record);
                    output.fields = Some(fields);
                    output.unexpected_changes = Some(unexpected);
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => {
                    output.readback_error = Some("port-forward readback timed out".to_owned());
                }
            }
        }
        structured_with_accepted_response(output)
    }

    /// Verify the zone API is available, retaining the original controller rejection.
    async fn require_zone_based_firewall(&self) -> Result<(), McpError> {
        let site_id = self.site_id().await?;
        let capabilities = capability::detect(self.integration(), &site_id)
            .await
            .map_err(api_error)?;
        if let Some(rejection) = capabilities.firewall_rejection {
            return Err(api_error(rejection));
        }
        Ok(())
    }

    async fn port_forward_snapshot(
        &self,
        id: &str,
    ) -> Result<(PortForward, RecordFingerprint), McpError> {
        self.legacy()
            .port_forward_snapshot(self.legacy_site(), id)
            .await
            .map_err(api_error)
    }

    /// Change evaluation and logging flags on one policy, previewing unless
    /// the caller confirms.
    #[expect(
        clippy::too_many_lines,
        reason = "the policy preview, full-record write, and identity-checked readback form one workflow"
    )]
    async fn firewall_policies_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        reject_unknown_change_fields(params, FIREWALL_POLICY_CHANGE_FIELDS)?;
        let input = parse::<FirewallPoliciesUpdateInput>(params)?;
        let requested: Map<String, Value> = [
            ("enabled", input.changes.enabled),
            ("loggingEnabled", input.changes.logging_enabled),
        ]
        .into_iter()
        .filter_map(|(field, value)| value.map(|value| (field.to_owned(), Value::Bool(value))))
        .collect();
        if requested.is_empty() {
            return Err(McpError::invalid_params(
                "changes names no field to change",
                None,
            ));
        }

        // Preserve the zone API rejection before attempting a policy write.
        self.require_zone_based_firewall().await?;

        let site_id = self.site_id().await?;
        // `raw` is what goes back to the controller, property by property, as
        // the bytes it sent. `record` is the same reading parsed for the few
        // properties this server reads; it is never written.
        let (raw, before_digest, before_response) = self
            .integration()
            .firewall_policy_snapshot_with_response(&site_id, &input.policy)
            .await
            .map_err(api_error)?;
        let record = parsed_record(&raw);
        if record.get("id").and_then(Value::as_str) != Some(input.policy.as_str()) {
            return Err(api_error(ApiError::DecodeResponse {
                response: before_response,
                diagnostic: BoundedMessage::new("controller returned a different firewall policy"),
            }));
        }
        let before_response_text = before_response.to_string();
        let before = policy_projection(&record);
        let warnings = input
            .changes
            .enabled
            .map_or_else(Vec::new, |wanted| firewall_policy_warnings(wanted, &record));
        if !input.confirm.unwrap_or(false) {
            return firewall_update_result(FirewallPoliciesUpdateOutput {
                policy: bounded_policy_view(policy_view_from_record(&input.policy, &record)),
                before_response: Some(before_response_text),
                before_response_in_content: None,
                response_status: None,
                response_body: None,
                response_body_in_content: None,
                after_response: None,
                after_response_in_content: None,
                applied: false,
                changes: Some(mutation::plan(&requested, &before)),
                fields: None,
                unexpected_changes: None,
                verified: None,
                readback_error: None,
                readback_error_in_content: None,
                warnings,
            });
        }

        // Nothing is submitted when all requested flags already hold their
        // values. In particular, an unnecessary full replacement could
        // overwrite another editor's change.
        if requested
            .iter()
            .all(|(field, value)| record.get(field) == Some(value))
        {
            return firewall_update_result(FirewallPoliciesUpdateOutput {
                policy: bounded_policy_view(policy_view_from_record(&input.policy, &record)),
                before_response: Some(before_response_text),
                before_response_in_content: None,
                response_status: None,
                response_body: None,
                response_body_in_content: None,
                after_response: None,
                after_response_in_content: None,
                applied: false,
                changes: Some(Vec::new()),
                fields: None,
                unexpected_changes: None,
                verified: None,
                readback_error: None,
                readback_error_in_content: None,
                warnings: vec![
                    "the policy already holds that value, so nothing was sent".to_owned(),
                ],
            });
        }

        // A change to enabled requires full replacement. Logging can use the
        // partial route when enabled needs no change. Full replacement retains
        // the original bytes of every unrequested controller property.
        let enabled_changes = input
            .changes
            .enabled
            .is_some_and(|wanted| record.get("enabled").and_then(Value::as_bool) != Some(wanted));
        let (response_status, response_body) = if enabled_changes {
            let mut sent = raw;
            for (field, value) in &requested {
                sent.insert(
                    field.clone(),
                    serde_json::value::RawValue::from_string(value.to_string())
                        .expect("a JSON boolean literal is valid JSON"),
                );
            }
            self.integration()
                .replace_firewall_policy(&site_id, &input.policy, &sent)
                .await
        } else {
            self.integration()
                .patch_firewall_policy_logging(
                    &site_id,
                    &input.policy,
                    input
                        .changes
                        .logging_enabled
                        .expect("validated logging change"),
                )
                .await
        }
        .map_err(api_error)?;

        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(FIREWALL_UPDATE_RESPONSE_RESERVE)
            .min(FIREWALL_UPDATE_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            Err("policy readback skipped near request deadline".to_owned())
        } else {
            match tokio::time::timeout(
                budget,
                self.integration()
                    .firewall_policy_snapshot_with_response(&site_id, &input.policy),
            )
            .await
            {
                Ok(Ok(readback)) => Ok(readback),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("policy readback timed out".to_owned()),
            }
        };
        let (after_raw, after_digest, after_response) = match readback {
            Ok(readback) => readback,
            Err(error) => {
                return firewall_update_result(FirewallPoliciesUpdateOutput {
                    policy: bounded_policy_view(policy_view_from_record(&input.policy, &record)),
                    before_response: Some(before_response_text),
                    before_response_in_content: None,
                    response_status: Some(response_status),
                    response_body: Some(
                        BoundedMessage::from_controller_bytes(&response_body).to_string(),
                    ),
                    response_body_in_content: None,
                    after_response: None,
                    after_response_in_content: None,
                    applied: true,
                    changes: None,
                    fields: None,
                    unexpected_changes: None,
                    verified: None,
                    readback_error: Some(error),
                    readback_error_in_content: None,
                    warnings,
                });
            }
        };
        let after_response_text = after_response.to_string();
        let after_record = parsed_record(&after_raw);
        if after_record.get("id").and_then(Value::as_str) != Some(input.policy.as_str()) {
            let error = ApiError::DecodeResponse {
                response: after_response,
                diagnostic: BoundedMessage::new(
                    "controller policy readback returned a different id",
                ),
            };
            return firewall_update_result(FirewallPoliciesUpdateOutput {
                policy: bounded_policy_view(policy_view_from_record(&input.policy, &record)),
                before_response: Some(before_response_text),
                before_response_in_content: None,
                response_status: Some(response_status),
                response_body: Some(
                    BoundedMessage::from_controller_bytes(&response_body).to_string(),
                ),
                response_body_in_content: None,
                after_response: Some(after_response_text),
                after_response_in_content: None,
                applied: true,
                changes: None,
                fields: None,
                unexpected_changes: None,
                verified: None,
                readback_error: Some(error.to_string()),
                readback_error_in_content: None,
                warnings,
            });
        }
        let after = policy_projection(&after_record);
        let fields = mutation::verify(&requested, &before, &after);
        let unexpected =
            unrequested_changes(&before_digest, &after_digest, &requested, POLICY_WIRE_NAMES);
        let verified = unexpected.is_empty()
            && fields
                .iter()
                .all(|outcome| outcome.status == mutation::FieldStatus::Persisted);
        firewall_update_result(FirewallPoliciesUpdateOutput {
            policy: bounded_policy_view(policy_view_from_record(&input.policy, &after_record)),
            before_response: Some(before_response_text),
            before_response_in_content: None,
            response_status: Some(response_status),
            response_body: Some(BoundedMessage::from_controller_bytes(&response_body).to_string()),
            response_body_in_content: None,
            after_response: Some(after_response_text),
            after_response_in_content: None,
            applied: true,
            changes: None,
            fields: Some(fields),
            unexpected_changes: Some(unexpected),
            verified: Some(verified),
            readback_error: None,
            readback_error_in_content: None,
            warnings,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "deletion previews the policy and verifies absence after the upstream action"
    )]
    async fn firewall_policies_delete(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<FirewallPoliciesDeleteInput>(params)?;
        if input.policy.trim().is_empty()
            || input.policy.len() > 256
            || matches!(input.policy.as_str(), "." | "..")
        {
            return Err(McpError::invalid_params(
                "policy must be a nonempty, non-dot id of at most 256 bytes",
                None,
            ));
        }
        self.require_zone_based_firewall().await?;
        let site_id = self.site_id().await?;
        let (raw, _, response) = self
            .integration()
            .firewall_policy_snapshot_with_response(&site_id, &input.policy)
            .await
            .map_err(api_error)?;
        let record = parsed_record(&raw);
        if record.get("id").and_then(Value::as_str) != Some(input.policy.as_str()) {
            return Err(api_error(ApiError::DecodeResponse {
                response,
                diagnostic: BoundedMessage::new("controller returned a different firewall policy"),
            }));
        }
        let mut output = FirewallPoliciesDeleteOutput {
            policy: bounded_policy_view(policy_view_from_record(&input.policy, &record)),
            preview: policy_preview_coverage(&record),
            before_response: Some(response.to_string()),
            before_response_in_content: None,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            applied: false,
            verified_absent: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings: vec![
                "deleting this policy changes how later firewall policies handle matching traffic"
                    .to_owned(),
            ],
        };
        if !output.preview.complete {
            output.warnings.push(
                "the compact match description omits fields; inspect beforeResponse for the complete controller record"
                    .to_owned(),
            );
        }
        if !input.confirm {
            return firewall_delete_result(output);
        }
        let (status, body) = self
            .integration()
            .delete_firewall_policy(&site_id, &input.policy)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response_status = Some(status);
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(FIREWALL_DELETE_RESPONSE_RESERVE)
            .min(FIREWALL_DELETE_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            None
        } else {
            Some(
                tokio::time::timeout(
                    budget,
                    self.integration()
                        .firewall_policy_snapshot_with_response(&site_id, &input.policy),
                )
                .await,
            )
        };
        let mut upstream_error = None;
        output.verified_absent = match readback {
            Some(Ok(Err(error @ ApiError::Status { status: 404, .. }))) => {
                output.readback_error = Some(error.to_string());
                upstream_error = Some(error);
                Some(true)
            }
            Some(Ok(Ok((record, _, response)))) => {
                let same_policy = parsed_record(&record).get("id").and_then(Value::as_str)
                    == Some(input.policy.as_str());
                let diagnostic = if same_policy {
                    "controller acknowledged deletion but the policy still exists"
                } else {
                    "controller policy readback returned a different id"
                };
                let error = ApiError::DecodeResponse {
                    response,
                    diagnostic: BoundedMessage::new(diagnostic),
                };
                output.readback_error = Some(error.to_string());
                upstream_error = Some(error);
                same_policy.then_some(false)
            }
            Some(Ok(Err(error))) => {
                output.readback_error = Some(error.to_string());
                upstream_error = Some(error);
                None
            }
            Some(Err(_)) => {
                output.warnings.push("policy readback timed out".to_owned());
                None
            }
            None => {
                output.warnings.push(
                    "policy readback skipped because the request deadline was near".to_owned(),
                );
                None
            }
        };
        if output.verified_absent != Some(true) && upstream_error.is_none() {
            output.warnings.push(
                "the delete request was accepted, but policy absence was not verified".to_owned(),
            );
        }
        firewall_delete_result(output)
    }

    async fn vouchers_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<VouchersSearchInput>(params)?;
        if input.offset > i32::MAX as u32 || input.limit == 0 {
            return Err(McpError::invalid_params(
                "offset must fit a nonnegative 32-bit integer and limit must be positive",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let (page, response) = self
            .integration()
            .vouchers_with_response(
                &site_id,
                PageRequest {
                    offset: u64::from(input.offset),
                    limit: voucher_limit(input.limit),
                },
            )
            .await
            .map_err(api_error)?;
        if page.offset != u64::from(input.offset)
            || page.limit == 0
            || page.limit > u64::from(voucher_limit(input.limit))
            || page.count != page.data.len() as u64
            || page.count > page.limit
            || page.offset.saturating_add(page.count) > page.total_count
        {
            return Err(page_validation_error(
                &response,
                "controller returned an inconsistent voucher page",
            ));
        }
        let next = page
            .offset
            .checked_add(page.count)
            .filter(|next| *next < page.total_count);
        if next.is_some() && page.data.is_empty() {
            return Err(page_validation_error(
                &response,
                "controller returned an empty incomplete voucher page",
            ));
        }
        structured(VouchersSearchOutput {
            page_counts: PageCounts {
                requested_limit: input.limit,
                effective_limit: page.limit,
                returned: page.data.len(),
            },
            vouchers: page.data.into_iter().map(VoucherReadView::from).collect(),
            offset: page.offset,
            limit: page.limit,
            total_count: page.total_count,
            next_offset: next,
        })
    }

    async fn vouchers_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<VoucherIdInput>(params)?;
        let id = voucher_id(&input.voucher_id)?;
        let site_id = self.site_id().await?;
        let (voucher, response) = self
            .integration()
            .voucher_with_response(&site_id, id)
            .await
            .map_err(api_error)?;
        if voucher.id != id {
            return Err(page_validation_error(
                &response,
                "controller returned a different voucher id",
            ));
        }
        structured(VoucherReadView::from(voucher))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one bounded preview, deletion, and observation retain all controller responses"
    )]
    async fn vouchers_revoke_matching(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<VouchersRevokeMatchingInput>(params)?;
        if input.filter.trim().is_empty()
            || input.filter.len() > 2048
            || input.preview_offset > i32::MAX as u32
            || input.preview_limit == 0
        {
            return Err(McpError::invalid_params(
                "filter must be nonempty and at most 2048 bytes; previewOffset must fit a nonnegative 32-bit integer; previewLimit must be positive",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let (before, response) = self
            .integration()
            .voucher_records(
                &site_id,
                PageRequest {
                    offset: u64::from(input.preview_offset),
                    limit: voucher_limit(input.preview_limit),
                },
                Some(&input.filter),
            )
            .await
            .map_err(api_error)?;
        validate_voucher_records_page(
            &before,
            &response,
            u64::from(input.preview_offset),
            input.preview_limit,
        )?;
        let mut output = VouchersRevokeMatchingOutput {
            page_counts: PageCounts {
                requested_limit: input.preview_limit,
                effective_limit: before.limit,
                returned: before.data.len(),
            },
            filter: input.filter,
            matches_before: before.total_count,
            preview_complete: before.offset == 0 && before.count == before.total_count,
            applied: false,
            before_response: Some(response.to_string()),
            before_response_in_content: None,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            vouchers_deleted: None,
            matches_after: None,
            verified_absent: None,
            after_response: None,
            after_response_in_content: None,
            readback_error: None,
            readback_error_in_content: None,
        };
        if !input.confirm {
            return vouchers_revoke_matching_result(output);
        }
        let (status, body) = self
            .integration()
            .delete_matching_vouchers(&site_id, &output.filter)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response_status = Some(status);
        output.vouchers_deleted = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|record| record.get("vouchersDeleted").and_then(Value::as_u64));
        output.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(VOUCHER_RESPONSE_RESERVE)
            .min(VOUCHER_READBACK_BUDGET);
        if budget.is_zero() {
            output.readback_error =
                Some("voucher filter readback skipped near request deadline".to_owned());
        } else {
            match tokio::time::timeout(
                budget,
                self.integration().voucher_records(
                    &site_id,
                    PageRequest {
                        offset: 0,
                        limit: 1,
                    },
                    Some(&output.filter),
                ),
            )
            .await
            {
                Ok(Ok((after, response))) => {
                    output.after_response = Some(response.to_string());
                    match validate_voucher_records_page(&after, &response, 0, 1) {
                        Ok(()) => {
                            output.matches_after = Some(after.total_count);
                            output.verified_absent = Some(after.total_count == 0);
                        }
                        Err(error) => output.readback_error = Some(error.message.into_owned()),
                    }
                }
                Ok(Err(error)) => output.readback_error = Some(error.to_string()),
                Err(_) => {
                    output.readback_error = Some("voucher filter readback timed out".to_owned());
                }
            }
        }
        vouchers_revoke_matching_result(output)
    }

    async fn vouchers_revoke(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<VoucherRevokeInput>(params)?;
        let id = voucher_id(&input.voucher_id)?;
        let site_id = self.site_id().await?;
        let (voucher, response) = self
            .integration()
            .voucher_with_response(&site_id, id)
            .await
            .map_err(api_error)?;
        if voucher.id != id {
            return Err(page_validation_error(
                &response,
                "controller returned a different voucher id",
            ));
        }
        let mut result = VoucherRevokeOutput {
            voucher_id: voucher.id,
            name: voucher.name,
            expired: voucher.expired,
            authorized_guest_count: voucher.authorized_guest_count,
            applied: false,
            response_status: None,
            response_body: None,
            response_body_in_content: None,
            verified: None,
            readback_error: None,
            readback_error_in_content: None,
            warnings: Vec::new(),
        };
        if !input.confirm {
            return voucher_revoke_result(result);
        }
        let (status, body) = self
            .integration()
            .delete_voucher(&site_id, id)
            .await
            .map_err(api_error)?;
        result.applied = true;
        result.response_status = Some(status);
        result.response_body = Some(BoundedMessage::from_controller_bytes(&body).to_string());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(VOUCHER_RESPONSE_RESERVE)
            .min(VOUCHER_READBACK_BUDGET);
        if budget.is_zero() {
            result.readback_error =
                Some("voucher readback skipped near request deadline".to_owned());
            return voucher_revoke_result(result);
        }
        let Ok(readback) = tokio::time::timeout(
            budget,
            self.integration().voucher_with_response(&site_id, id),
        )
        .await
        else {
            result.readback_error = Some("voucher readback timed out".to_owned());
            return voucher_revoke_result(result);
        };
        let persisted = match readback {
            Err(error @ ApiError::Status { status: 404, .. }) => {
                result.readback_error = Some(error.to_string());
                false
            }
            Ok((voucher, response)) => {
                if voucher.id != id {
                    let error = ApiError::DecodeResponse {
                        response,
                        diagnostic: BoundedMessage::new(
                            "controller voucher readback returned a different id",
                        ),
                    };
                    result.readback_error = Some(error.to_string());
                    return voucher_revoke_result(result);
                }
                let error = ApiError::DecodeResponse {
                    response,
                    diagnostic: BoundedMessage::new(
                        "controller acknowledged deletion but the voucher still exists",
                    ),
                };
                result.readback_error = Some(error.to_string());
                true
            }
            Err(error) => {
                result.readback_error = Some(error.to_string());
                return voucher_revoke_result(result);
            }
        };
        result.verified = Some(!persisted);
        if persisted {
            result
                .warnings
                .push("controller acknowledged deletion but the voucher still exists".to_owned());
        }
        voucher_revoke_result(result)
    }

    async fn verify_created_vouchers_before_deadline(
        &self,
        site_id: &str,
        requested: u32,
        vouchers: &[Voucher],
        started: tokio::time::Instant,
    ) -> VoucherVerification {
        // A slow detail endpoint must not consume the outer tool deadline
        // after minting. Reserve time to shape and return the creation result.
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(VOUCHER_RESPONSE_RESERVE)
            .min(VOUCHER_READBACK_BUDGET);
        let deadline = tokio::time::Instant::now() + budget;
        let mut result = VoucherVerification {
            verified: usize::try_from(requested).is_ok_and(|want| want == vouchers.len()),
            errors: Vec::new(),
            complete: true,
            stop_reason: None,
        };
        let mut ids = HashSet::new();
        for voucher in vouchers {
            let (Some(id), Some(code)) = (voucher.id.as_deref(), voucher.code.as_deref()) else {
                result.verified = false;
                continue;
            };
            if !ids.insert(id) {
                result.verified = false;
            }
            if tokio::time::Instant::now() >= deadline {
                result.verified = false;
                result.complete = false;
                result.stop_reason = Some("deadline");
                break;
            }
            match tokio::time::timeout_at(
                deadline,
                self.integration().voucher_with_response(site_id, id),
            )
            .await
            {
                Ok(Ok((persisted, _))) if persisted.id == id && persisted.code == code => {}
                Ok(Ok((_, response))) => {
                    result.verified = false;
                    let message = ApiError::DecodeResponse {
                        response,
                        diagnostic: BoundedMessage::new(
                            "created voucher readback disagrees with the creation response",
                        ),
                    }
                    .to_string();
                    result.errors.push(VoucherReadbackFailure {
                        voucher_id: id.to_owned(),
                        error: message,
                    });
                }
                Ok(Err(error)) => {
                    result.verified = false;
                    let message = error.to_string();
                    result.errors.push(VoucherReadbackFailure {
                        voucher_id: id.to_owned(),
                        error: message,
                    });
                }
                Err(_) => {
                    result.verified = false;
                    result.complete = false;
                    result.stop_reason = Some("deadline");
                    break;
                }
            }
        }
        result
    }

    /// Mint hotspot vouchers, previewing unless the caller confirms.
    /// A confirmed call checks each returned id and code against the detail
    /// endpoint; incomplete verification is reported with the created rows.
    async fn vouchers_create(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let started = tokio::time::Instant::now();
        let input = parse::<VouchersCreateInput>(params)?;
        let batch = voucher_batch(&input)?;
        let request = VoucherCreate {
            name: batch.name.clone(),
            count: input.count,
            time_limit_minutes: input.time_limit_minutes,
            authorized_guest_limit: input.guest_limit,
            data_usage_limit_m_bytes: input.data_limit_megabytes,
            rx_rate_limit_kbps: input.download_rate_limit_kbps,
            tx_rate_limit_kbps: input.upload_rate_limit_kbps,
        };
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|error| McpError::internal_error(error.to_string(), None))?;
        if request_bytes.len() > MAXIMUM_VOUCHER_REQUEST_BYTES {
            return Err(McpError::invalid_params(
                "serialized voucher request exceeds the 1 MiB transport bound",
                None,
            ));
        }
        let mut warnings = vec![
            "each voucher code is a guest network credential; codes can also be read through vouchers.search and vouchers.status"
                .to_owned(),
        ];
        if !input.confirm.unwrap_or(false) {
            return structured(VouchersCreateOutput {
                applied: false,
                batch,
                requested: input.count,
                response_status: None,
                response_body: None,
                response_body_in_content: None,
                vouchers: None,
                vouchers_in_content: None,
                checks: None,
                verified: None,
                readback_errors: Vec::new(),
                readback_errors_in_content: None,
                readback_complete: None,
                readback_stop_reason: None,
                warnings,
            });
        }

        let site_id = self.site_id().await?;
        let (created, response_status, response_body) = self
            .integration()
            .create_vouchers_with_response(&site_id, &request)
            .await
            .map_err(api_error)?;

        let verification = self
            .verify_created_vouchers_before_deadline(
                &site_id,
                input.count,
                &created.vouchers,
                started,
            )
            .await;
        if !verification.verified && verification.errors.is_empty() {
            warnings.push(
                "not every created voucher could be read back with the same id and code; inspect vouchers.status or vouchers.search"
                    .to_owned(),
            );
        }

        let vouchers: Vec<VoucherView> = created
            .vouchers
            .into_iter()
            .map(|voucher| VoucherView {
                id: voucher.id,
                code: voucher.code,
            })
            .collect();
        // The checks describe the ids and codes returned by the controller.
        let checks = voucher_checks(input.count, &vouchers);
        structured_with_mutation_readback_errors(VouchersCreateOutput {
            applied: true,
            batch,
            requested: input.count,
            response_status: Some(response_status),
            response_body: Some(BoundedMessage::from_controller_bytes(&response_body).to_string()),
            response_body_in_content: None,
            vouchers: Some(vouchers),
            vouchers_in_content: None,
            checks: Some(checks),
            verified: Some(verification.verified),
            readback_errors: verification.errors,
            readback_errors_in_content: None,
            readback_complete: Some(verification.complete),
            readback_stop_reason: verification.stop_reason,
            warnings,
        })
    }

    /// One wireless network as both the modeled projection and a digest of
    /// every stored property, from a single read.
    async fn wlan_snapshot(&self, id: &str) -> Result<(WlanConf, RecordFingerprint), McpError> {
        self.legacy()
            .wlan_snapshot(self.legacy_site(), id)
            .await
            .map_err(api_error)
    }

    async fn wifi_diagnose(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<WifiDiagnoseInput>(params)?;
        let threshold = input
            .weak_signal_threshold_dbm
            .unwrap_or(DEFAULT_WEAK_SIGNAL_DBM);
        if !(-100..=-30).contains(&threshold) {
            return Err(McpError::invalid_params(
                "weakSignalThresholdDbm must be between -100 and -30",
                None,
            ));
        }

        let clients = self
            .legacy()
            .active_clients(self.legacy_site())
            .await
            .map_err(api_error)?;
        let (inventory, inventory_truncated) = self.device_inventory().await?;
        let ap_names: std::collections::HashMap<String, String> = inventory
            .iter()
            .filter_map(|device| {
                Some((
                    normalize_mac(device.mac_address.as_deref()?),
                    device.name.clone()?,
                ))
            })
            .collect();

        let (clients_by_ap, weak_clients) = wireless_load(&clients, threshold, &ap_names);

        // An access point is identified by its radios, so idle access points
        // appear with zero load. Detail reads are bounded; devices carrying
        // clients are scanned first so they are never the ones cut off.
        let site_id = self.site_id().await?;
        let mut ordered: Vec<&DeviceSummary> = inventory.iter().collect();
        ordered.sort_by_key(|device| {
            let carries_clients = device
                .mac_address
                .as_deref()
                .map(normalize_mac)
                .is_some_and(|mac| clients_by_ap.contains_key(&mac));
            !carries_clients
        });
        let access_points_truncated = inventory_truncated || ordered.len() > AP_DETAIL_CEILING;
        let mut access_points = Vec::new();
        for device in ordered.into_iter().take(AP_DETAIL_CEILING) {
            let detail = self
                .integration()
                .device_detail(&site_id, &device.id)
                .await
                .map_err(api_error)?;
            let all_radios = detail.interfaces.unwrap_or_default().radios;
            let radios_truncated = all_radios.len() > RADIO_TABLE_CEILING;
            let radios: Vec<DeviceRadioRow> = all_radios
                .into_iter()
                .take(RADIO_TABLE_CEILING)
                .map(|radio| DeviceRadioRow {
                    wlan_standard: radio.wlan_standard,
                    frequency_ghz: radio.frequency_g_hz,
                    channel: radio.channel,
                    channel_width_mhz: radio.channel_width_m_hz,
                })
                .collect();
            if radios.is_empty() {
                continue;
            }
            let (client_count, weak_count) = device
                .mac_address
                .as_deref()
                .map(normalize_mac)
                .and_then(|mac| clients_by_ap.get(&mac))
                .copied()
                .unwrap_or_default();
            access_points.push(AccessPointHealth {
                name: detail.name,
                mac: detail.mac_address,
                state: detail.state,
                radios,
                radios_truncated: radios_truncated.then_some(true),
                clients: client_count,
                weak_clients: weak_count,
            });
        }

        let (rogue_aps, rogue_aps_truncated) = self.rogue_section().await?;

        structured(WifiDiagnoseOutput {
            weak_signal_threshold_dbm: threshold,
            access_points_truncated: access_points_truncated.then_some(true),
            access_points,
            weak_clients,
            rogue_aps,
            rogue_aps_truncated: rogue_aps_truncated.then_some(true),
        })
    }

    /// The bounded neighboring-access-point list with its truncation signal.
    async fn rogue_section(&self) -> Result<(Vec<RogueApRow>, bool), McpError> {
        let all_rogues = self
            .legacy()
            .rogue_aps(self.legacy_site())
            .await
            .map_err(api_error)?;
        let truncated = all_rogues.len() > ROGUE_AP_CEILING;
        let rows = all_rogues
            .into_iter()
            .take(ROGUE_AP_CEILING)
            .map(|rogue| RogueApRow {
                ssid: rogue.essid,
                bssid: rogue.bssid,
                channel: rogue.channel,
                rssi: rogue.rssi,
            })
            .collect();
        Ok((rows, truncated))
    }

    async fn events_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<EventsSearchInput>(params)?;
        validate_page(input.limit)?;
        let category = validate_filter(input.category.as_deref())?;
        let client = validate_filter(input.client.as_deref())?;
        let window_hours = input.last_hours.unwrap_or(DEFAULT_EVENT_WINDOW_HOURS);
        if window_hours == 0 {
            return Err(McpError::invalid_params("lastHours must be positive", None));
        }
        let (window_start_ms, now_ms) = log_window(window_hours)?;
        let mut query =
            SystemLogQuery::new(window_start_ms, now_ms, EVENT_FETCH_LIMIT).map_err(api_error)?;
        if let Some(severity) = input.severity {
            query = query.severity(match severity {
                EventSeverity::Low => SystemLogSeverity::Low,
                EventSeverity::Medium => SystemLogSeverity::Medium,
                EventSeverity::High => SystemLogSeverity::High,
                EventSeverity::VeryHigh => SystemLogSeverity::VeryHigh,
            });
        }
        let page = self
            .legacy()
            .system_log(self.legacy_site(), &query)
            .await
            .map_err(system_log::read_error)?;
        let fetch_window_truncated = page.has_more();
        let mut rows: Vec<_> = page.data.into_iter().map(event_row).collect();

        rows.retain(|row| {
            (window_start_ms..=now_ms).contains(&row.time)
                && category.as_deref().is_none_or(|category| {
                    row.key
                        .as_deref()
                        .is_some_and(|key| key.to_lowercase().contains(category))
                        || row
                            .category
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(category))
                })
                && client.as_deref().is_none_or(|client| {
                    row.client_mac.as_deref().map(normalize_mac) == Some(client.to_owned())
                })
        });
        rows.sort_by_key(|row| std::cmp::Reverse(row.time));

        let total = rows.len();
        let offset = input.offset;
        let page: Vec<EventRow> = rows.into_iter().skip(offset).take(input.limit).collect();
        let next_offset = next_offset(offset, page.len(), total);
        structured(EventsSearchOutput {
            rows: page,
            total_matches: total as u64,
            next_offset,
            fetch_window_truncated: fetch_window_truncated.then_some(true),
        })
    }

    async fn stats_query(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<StatsQueryInput>(params)?;
        if input.report != StatsReport::WanHourly {
            return self.activity_stats(input).await;
        }
        if input.top.is_some() || input.limit.is_some() || input.offset.is_some() {
            return Err(McpError::invalid_params(
                "top and client pagination do not apply to wanHourly",
                None,
            ));
        }
        let window = activity::report_window(&input)?;
        let samples: Vec<_> = self
            .legacy()
            .hourly_wan_report(self.legacy_site(), window.start, window.end)
            .await
            .map_err(api_error)?
            .into_iter()
            .filter(|sample| {
                sample
                    .time
                    .is_none_or(|time| time >= window.start && time < window.end)
            })
            .map(|sample| WanSampleRow {
                time: sample.time,
                tx_bytes: sample.wan_tx_bytes,
                rx_bytes: sample.wan_rx_bytes,
            })
            .collect();
        let missing = samples
            .iter()
            .any(|row| row.time.is_none() || row.rx_bytes.is_none() || row.tx_bytes.is_none());
        structured_stats(StatsQueryOutput {
            report: "wanHourly",
            coverage: TrafficCoverage {
                status: if samples.is_empty() {
                    CoverageStatus::Empty
                } else if missing {
                    CoverageStatus::Partial
                } else {
                    CoverageStatus::Reported
                },
                reason: "Coverage describes returned buckets only; absent buckets or counters are unknown, not zero.",
                unrecognized_records: 0,
            },
            counter_semantics: CounterSemantics::wan(window.start, window.end),
            total_applications: None,
            wan_hourly: Some(samples),
            top_applications: None,
            activity: None,
            source_errors: Vec::new(),
            source_errors_in_content: None,
            activity_in_content: None,
        })
    }

    async fn traffic_read(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        use unifi_api::collection::{SourceStatus, TrafficSource};
        let input = parse::<TrafficReadInput>(params)?;
        let window = activity::report_window(&StatsQueryInput {
            report: StatsReport::ClientWanHistory,
            hours: input.hours,
            top: None,
            start_ms: input.start_ms,
            end_ms: input.end_ms,
            limit: None,
            offset: None,
        })?;
        let selected = match input.source {
            TrafficReadSource::Activity => TrafficSource::Activity,
            TrafficReadSource::Graph => TrafficSource::Graph,
            TrafficReadSource::Wan => TrafficSource::Wan,
        };
        let report = self
            .legacy()
            .traffic_source(self.legacy_site(), window, selected)
            .await
            .map_err(api_error)?;
        let data = report
            .data
            .map(|raw| {
                serde_json::from_str(raw.get()).map_err(|error| {
                    api_error(ApiError::DecodeResponse {
                        response: BoundedMessage::from_controller_bytes(raw.get().as_bytes()),
                        diagnostic: error.to_string().into(),
                    })
                })
            })
            .transpose()?;
        traffic_read_result(TrafficReadOutput {
            source: input.source,
            status: match report.status {
                SourceStatus::Collected => "collected",
                SourceStatus::Unsupported => "unsupported",
                SourceStatus::Unrecognized => "unrecognized",
                SourceStatus::Failed => "failed",
            },
            start_ms: window.start,
            end_ms: window.end,
            data,
            data_in_content: None,
            error: report.error,
            error_in_content: None,
        })
    }

    async fn dpi_stats(
        &self,
        top: usize,
        activity_response: Option<ApiError>,
    ) -> Result<CallToolResult, McpError> {
        let report = match self.legacy().dpi_by_application(self.legacy_site()).await {
            Ok(report) => report,
            Err(error) => {
                return Err(match activity_response {
                    Some(activity) => McpError::internal_error(
                        format!("activity source: {activity}; dpi source: {error}"),
                        None,
                    ),
                    None => api_error(error),
                });
            }
        };
        let mut source_errors: Vec<StatsSourceError> = activity_response
            .into_iter()
            .map(|error| StatsSourceError {
                source: "activity",
                error: error.to_string(),
            })
            .collect();
        if let Some(error) = &report.unsupported_response {
            source_errors.push(StatsSourceError {
                source: "dpi",
                error: error.to_string(),
            });
        }
        let unavailable = match report.availability {
            DpiAvailability::Unsupported => Some((
                CoverageStatus::Unsupported,
                "The legacy DPI endpoint is unavailable on this controller. This does not establish that DPI is disabled.",
            )),
            DpiAvailability::Unrecognized => Some((
                CoverageStatus::Unrecognized,
                "The controller response could not be interpreted as a DPI report.",
            )),
            DpiAvailability::Reported => None,
        };
        if let Some((status, reason)) = unavailable {
            return structured_stats(StatsQueryOutput {
                report: "dpiApplications",
                coverage: TrafficCoverage {
                    status,
                    reason,
                    unrecognized_records: 0,
                },
                counter_semantics: CounterSemantics::dpi(),
                total_applications: None,
                wan_hourly: None,
                top_applications: Some(Vec::new()),
                activity: None,
                source_errors,
                source_errors_in_content: None,
                activity_in_content: None,
            });
        }
        let status = match (
            report.applications.is_empty(),
            report.unrecognized_records > 0,
        ) {
            (true, true) => CoverageStatus::Unrecognized,
            (true, false) => CoverageStatus::Empty,
            (false, true) => CoverageStatus::Partial,
            (false, false) => CoverageStatus::Reported,
        };
        let mut applications: Vec<TopApplicationRow> = report
            .applications
            .into_iter()
            .map(|row| TopApplicationRow {
                application_id: row.app,
                category_id: row.cat,
                application_name: None,
                category_name: None,
                tx_bytes: row.tx_bytes,
                rx_bytes: row.rx_bytes,
            })
            .collect();
        applications.sort_by_key(|row| {
            std::cmp::Reverse(u128::from(row.tx_bytes) + u128::from(row.rx_bytes))
        });
        let total_applications = applications.len();
        applications.truncate(top);
        structured_stats(StatsQueryOutput {
            report: "dpiApplications",
            coverage: TrafficCoverage {
                status,
                reason: "Ranking includes only records with application/category IDs and both byte counters. Empty or incomplete data does not establish zero traffic or whether DPI is enabled; classification coverage is unknown.",
                unrecognized_records: report.unrecognized_records,
            },
            counter_semantics: CounterSemantics::dpi(),
            total_applications: Some(total_applications),
            wan_hourly: None,
            top_applications: Some(applications),
            activity: None,
            source_errors,
            source_errors_in_content: None,
            activity_in_content: None,
        })
    }

    /// The bounded adopted-device inventory, followed across pages. The
    /// boolean reports whether the scan ceiling cut the catalog short, so
    /// callers can surface the truncation instead of presenting a prefix
    /// as complete.
    async fn device_inventory(&self) -> Result<(Vec<DeviceSummary>, bool), McpError> {
        let site_id = self.site_id().await?;
        let mut devices: Vec<DeviceSummary> = Vec::new();
        let mut offset = 0_u64;
        let mut truncated = false;
        loop {
            let page = self
                .integration()
                .devices(&site_id, PageRequest { offset, limit: 100 })
                .await
                .map_err(api_error)?;
            let fetched = page.data.len() as u64;
            devices.extend(page.data);
            offset = offset.saturating_add(fetched);
            if fetched == 0 || offset >= page.total_count {
                break;
            }
            if offset >= DEVICE_INVENTORY_CEILING {
                truncated = true;
                break;
            }
        }
        Ok((devices, truncated))
    }

    /// Access point and switch names keyed by normalized MAC, plus whether
    /// the backing scan was truncated. A device beyond the scan ceiling
    /// stays unresolved — absent, never wrong — and the boolean lets
    /// callers say so.
    async fn device_names_by_mac(
        &self,
    ) -> Result<(std::collections::HashMap<String, String>, bool), McpError> {
        let (devices, truncated) = self.device_inventory().await?;
        Ok((
            devices
                .into_iter()
                .filter_map(|device| {
                    Some((normalize_mac(device.mac_address.as_deref()?), device.name?))
                })
                .collect(),
            truncated,
        ))
    }
}

/// Group wireless clients by access point and collect the weakest, worst
/// first and bounded. The per-access-point counts are (clients, weak).
fn wireless_load(
    clients: &[ActiveClient],
    threshold: i32,
    ap_names: &std::collections::HashMap<String, String>,
) -> (
    std::collections::HashMap<String, (u32, u32)>,
    Vec<WeakClientRow>,
) {
    let mut clients_by_ap: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    let mut weak_clients: Vec<WeakClientRow> = Vec::new();
    for client in clients {
        if client.is_wired == Some(true) {
            continue;
        }
        // Weakness is judged before association: a below-threshold client
        // with no reported access point still belongs in the weak list.
        let ap_mac = client.ap_mac.as_deref().map(normalize_mac);
        let weak = client.signal.is_some_and(|signal| signal < threshold);
        if let Some(ap_mac) = &ap_mac {
            let entry = clients_by_ap.entry(ap_mac.clone()).or_default();
            entry.0 += 1;
            if weak {
                entry.1 += 1;
            }
        }
        if weak {
            weak_clients.push(WeakClientRow {
                name: client.name.clone().or_else(|| client.hostname.clone()),
                mac: client.mac.clone(),
                ssid: client.essid.clone(),
                ap_name: ap_mac.and_then(|mac| ap_names.get(&mac).cloned()),
                signal_dbm: client.signal.unwrap_or(threshold),
                rssi: client.rssi,
            });
        }
    }
    weak_clients.sort_by_key(|client| client.signal_dbm);
    weak_clients.truncate(WEAK_CLIENT_CEILING);
    (clients_by_ap, weak_clients)
}

fn validate_page(limit: usize) -> Result<(), McpError> {
    if limit == 0 {
        return Err(McpError::invalid_params("limit must be positive", None));
    }
    Ok(())
}

fn event_detail_selection(
    input: &ProtectEventsInput,
) -> Result<(bool, Option<Vec<String>>), McpError> {
    let fields = input.detail_fields.clone();
    if fields.as_ref().is_some_and(|fields| {
        fields.len() > 64
            || fields
                .iter()
                .any(|field| field.is_empty() || field.len() > 256)
    }) {
        return Err(McpError::invalid_params(
            "detailFields accepts at most 64 nonempty field names of at most 256 bytes",
            None,
        ));
    }
    Ok((
        input.include_details.unwrap_or(false) || fields.is_some(),
        fields,
    ))
}

fn select_event_details(
    mut details: Map<String, Value>,
    include_details: bool,
    fields: Option<&[String]>,
) -> Option<Map<String, Value>> {
    if !include_details {
        return None;
    }
    if let Some(fields) = fields {
        details.retain(|name, _| fields.iter().any(|field| field == name));
    }
    Some(details)
}

fn resolve_protect_event_query(
    input: ProtectEventsInput,
    inventory: &[CameraView],
) -> Result<ResolvedProtectEventQuery, McpError> {
    if let Some(cursor) = input.cursor {
        if input.last_hours.is_some()
            || input.start.is_some()
            || input.end.is_some()
            || input.camera.is_some()
            || input.detection.is_some()
        {
            return Err(McpError::invalid_params(
                "cursor cannot be combined with window or filter fields",
                None,
            ));
        }
        validate_protect_window(cursor.window_start, cursor.window_end)?;
        if cursor.next_end < cursor.window_start
            || cursor.next_end > cursor.window_end
            || cursor
                .camera_id
                .as_ref()
                .is_some_and(|camera| camera.is_empty() || camera.len() > EVENT_MESSAGE_CEILING)
        {
            return Err(McpError::invalid_params(
                "Protect event cursor is invalid",
                None,
            ));
        }
        let detection = validate_filter(cursor.detection.as_deref())?;
        return Ok(ResolvedProtectEventQuery {
            window_start: cursor.window_start,
            window_end: cursor.window_end,
            camera_id: cursor.camera_id,
            detection,
            continuation: Some(ProtectEventContinuation {
                next_end: cursor.next_end,
            }),
        });
    }

    let detection = validate_filter(input.detection.as_deref())?;
    let (window_start, window_end) = match (input.start, input.end) {
        (Some(start), Some(end)) if input.last_hours.is_none() => (start, end),
        (None, None) => {
            let hours = input.last_hours.unwrap_or(DEFAULT_EVENT_WINDOW_HOURS);
            if hours == 0 {
                return Err(McpError::invalid_params("lastHours must be positive", None));
            }
            let end = current_time_ms()?;
            (end.saturating_sub(u64::from(hours) * 3_600_000), end)
        }
        _ => {
            return Err(McpError::invalid_params(
                "start and end must be supplied together and cannot be combined with lastHours",
                None,
            ));
        }
    };
    validate_protect_window(window_start, window_end)?;
    let camera_id = resolve_camera_id(input.camera.as_deref(), inventory)?;
    Ok(ResolvedProtectEventQuery {
        window_start,
        window_end,
        camera_id,
        detection,
        continuation: None,
    })
}

fn validate_protect_window(start: u64, end: u64) -> Result<(), McpError> {
    if start > end {
        return Err(McpError::invalid_params(
            "Protect event start is after end",
            None,
        ));
    }
    Ok(())
}

fn current_time_ms() -> Result<u64, McpError> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| McpError::internal_error("system clock before epoch", None))?
            .as_millis(),
    )
    .map_err(|_| McpError::internal_error("system clock out of range", None))
}

fn resolve_camera_id(
    raw: Option<&str>,
    inventory: &[CameraView],
) -> Result<Option<String>, McpError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let selector = camera_selector(raw)?;
    let mut matches: Vec<String> = inventory
        .iter()
        .filter(|camera| camera.id == selector)
        .map(|camera| camera.id.clone())
        .collect();
    if matches.is_empty() {
        let normalized_selector = selector.to_lowercase();
        matches = inventory
            .iter()
            .filter(|camera| {
                camera
                    .name
                    .as_deref()
                    .is_some_and(|name| camera_name_matches(name, &normalized_selector))
                    || camera_name_matches(&camera.display_name, &normalized_selector)
            })
            .map(|camera| camera.id.clone())
            .collect();
    }
    match matches.len() {
        0 => Err(McpError::invalid_params(
            "no camera on this console has that id or name",
            None,
        )),
        1 => Ok(matches.pop()),
        count => Err(McpError::invalid_params(
            format!("{count} cameras share that name; select by id"),
            None,
        )),
    }
}

fn camera_name_matches(candidate: &str, normalized_selector: &str) -> bool {
    candidate.trim().to_lowercase() == normalized_selector
}

fn camera_by_selector(inventory: &CameraInventory, selector: &str) -> Result<CameraView, McpError> {
    camera_by_selector_ref(inventory, selector).cloned()
}

fn camera_by_selector_ref<'a>(
    inventory: &'a CameraInventory,
    selector: &str,
) -> Result<&'a CameraView, McpError> {
    let cameras = &inventory.cameras;
    // A camera id is unique; an apparent name match is unsafe when local
    // inventory is incomplete because another camera's name may be missing.
    if let Some(camera) = cameras.iter().find(|camera| camera.id == selector) {
        return Ok(camera);
    }
    if matches!(
        inventory.local_state,
        LocalEnrichmentState::Partial | LocalEnrichmentState::Unavailable
    ) {
        return Err(local_inventory_error(
            inventory.local_error.as_ref(),
            "camera name selection requires complete local Protect inventory; select by id",
        ));
    }
    let normalized_selector = selector.to_lowercase();
    let mut matches = cameras.iter().filter(|camera| {
        camera
            .name
            .as_deref()
            .is_some_and(|name| camera_name_matches(name, &normalized_selector))
            || camera_name_matches(&camera.display_name, &normalized_selector)
    });
    match (matches.next(), matches.next()) {
        (None, _) => Err(McpError::invalid_params(
            "no camera on this console has that id or name",
            None,
        )),
        (Some(camera), None) => Ok(camera),
        (Some(_), Some(_)) => Err(McpError::invalid_params(
            "multiple cameras share that name; select by id",
            None,
        )),
    }
}

fn validate_bootstrap_detail_request(
    include_all: bool,
    fields: Option<&[String]>,
) -> Result<(), McpError> {
    if include_all && fields.is_some() {
        return Err(McpError::invalid_params(
            "use includeDetails or detailFields, not both",
            None,
        ));
    }
    if let Some(fields) = fields {
        if fields.is_empty() || fields.len() > 64 {
            return Err(McpError::invalid_params(
                "detailFields must contain 1-64 field names",
                None,
            ));
        }
        if fields
            .iter()
            .any(|field| field.is_empty() || field.len() > 256)
        {
            return Err(McpError::invalid_params(
                "detail field names must contain 1-256 bytes",
                None,
            ));
        }
    }
    Ok(())
}

fn select_bootstrap_details(
    raw: &Value,
    include_all: bool,
    fields: Option<&[String]>,
) -> Result<Map<String, Value>, McpError> {
    let object = raw
        .as_object()
        .ok_or_else(|| McpError::invalid_params("local Protect record is not an object", None))?;
    if include_all {
        return Ok(object.clone());
    }
    let fields =
        fields.ok_or_else(|| McpError::invalid_params("detailFields is required", None))?;
    let mut selected = Map::new();
    for field in fields {
        let value = object.get(field).ok_or_else(|| {
            McpError::invalid_params(format!("local Protect record has no {field} field"), None)
        })?;
        selected.insert(field.clone(), value.clone());
    }
    Ok(selected)
}

fn camera_settings_patch(
    changes: &CameraSettingsChanges,
) -> Result<ProtectCameraSettingsPatch, McpError> {
    if changes.name.as_ref().is_some_and(|name| {
        name.trim().is_empty() || name.chars().count() > 128 || name.len() > 512
    }) {
        return Err(McpError::invalid_params(
            "camera name must be 1-128 characters and at most 512 bytes",
            None,
        ));
    }
    if changes
        .mic_volume
        .is_some_and(|volume| !(1..=100).contains(&volume))
    {
        return Err(McpError::invalid_params(
            "micVolume must be between 1 and 100",
            None,
        ));
    }
    if changes.video_mode.as_deref().is_some_and(|mode| {
        !matches!(
            mode,
            "default" | "highFps" | "sport" | "slowShutter" | "lprReflex" | "lprNoneReflex"
        )
    }) {
        return Err(McpError::invalid_params("unsupported videoMode", None));
    }
    if changes
        .hdr_type
        .as_deref()
        .is_some_and(|mode| !matches!(mode, "auto" | "on" | "off"))
    {
        return Err(McpError::invalid_params(
            "hdrType must be auto, on, or off",
            None,
        ));
    }
    if changes.osd_settings.as_ref().is_some_and(|osd| {
        osd.overlay_location.as_deref().is_some_and(|location| {
            !matches!(
                location,
                "topLeft"
                    | "topMiddle"
                    | "topRight"
                    | "bottomLeft"
                    | "bottomMiddle"
                    | "bottomRight"
            )
        })
    }) {
        return Err(McpError::invalid_params(
            "unsupported overlayLocation",
            None,
        ));
    }
    if changes
        .smart_detect_settings
        .as_ref()
        .is_some_and(invalid_smart_detection)
    {
        return Err(McpError::invalid_params(
            "smart detection types must use the documented object and audio categories",
            None,
        ));
    }
    let patch = typed_camera_settings_patch(changes);
    let value = serde_json::to_value(&patch)
        .map_err(|_| McpError::internal_error("camera settings could not be encoded", None))?;
    if value.to_string().len() > 1024 * 1024 {
        return Err(McpError::invalid_params(
            "camera settings request exceeds 1 MiB",
            None,
        ));
    }
    if value.as_object().is_none_or(serde_json::Map::is_empty)
        || value.as_object().is_some_and(|fields| {
            fields
                .values()
                .any(|value| value.as_object().is_some_and(serde_json::Map::is_empty))
        })
    {
        return Err(McpError::invalid_params(
            "changes must name at least one nonempty camera setting",
            None,
        ));
    }
    Ok(patch)
}

fn typed_camera_settings_patch(changes: &CameraSettingsChanges) -> ProtectCameraSettingsPatch {
    ProtectCameraSettingsPatch {
        name: changes.name.clone(),
        lcd_message: changes
            .lcd_message
            .as_ref()
            .map(|message| serde_json::to_value(message).expect("typed LCD message serializes")),
        mic_volume: changes.mic_volume,
        video_mode: changes.video_mode.clone(),
        hdr_type: changes.hdr_type.clone(),
        osd_settings: changes.osd_settings.as_ref().map(|osd| ProtectOsdSettings {
            is_name_enabled: osd.is_name_enabled,
            is_date_enabled: osd.is_date_enabled,
            is_logo_enabled: osd.is_logo_enabled,
            is_debug_enabled: osd.is_debug_enabled,
            overlay_location: osd.overlay_location.clone(),
        }),
        led_settings: changes.led_settings.as_ref().map(|led| ProtectLedSettings {
            is_enabled: led.is_enabled,
            welcome_led: led.welcome_led,
            flood_led: led.flood_led,
        }),
        smart_detect_settings: changes.smart_detect_settings.as_ref().map(|smart| {
            ProtectSmartDetectSettings {
                object_types: smart.object_types.clone(),
                audio_types: smart.audio_types.clone(),
            }
        }),
    }
}

fn invalid_smart_detection(smart: &CameraSmartDetectChanges) -> bool {
    smart.object_types.as_ref().is_some_and(|types| {
        types.len() > 6
            || types.iter().any(|kind| {
                !matches!(
                    kind.as_str(),
                    "person" | "vehicle" | "package" | "licensePlate" | "face" | "animal"
                )
            })
    }) || smart.audio_types.as_ref().is_some_and(|types| {
        types.len() > 9
            || types.iter().any(|kind| {
                !matches!(
                    kind.as_str(),
                    "alrmSmoke"
                        | "alrmCmonx"
                        | "alrmSiren"
                        | "alrmBabyCry"
                        | "alrmSpeak"
                        | "alrmBark"
                        | "alrmBurglar"
                        | "alrmCarHorn"
                        | "alrmGlassBreak"
                )
            })
    })
}

fn camera_settings_match(
    patch: &ProtectCameraSettingsPatch,
    before: &CameraSettingsState,
    after: &CameraSettingsState,
) -> bool {
    let mut requested = serde_json::to_value(patch).expect("typed patch serializes");
    let mut before_value = serde_json::to_value(before).expect("typed camera settings serialize");
    let mut after_value = serde_json::to_value(after).expect("typed camera settings serialize");
    let requested_lcd = requested
        .as_object_mut()
        .and_then(|fields| fields.remove("lcdMessage"));
    let lcd_matches = requested_lcd.as_ref().is_none_or(|wanted| {
        // Protect can fill an omitted resetAt from recorder defaults, and
        // a camera can have no prior LCD message.
        after
            .lcd_message
            .as_ref()
            .is_some_and(|observed| requested_json_matches(wanted, observed))
    });
    if requested_lcd.is_some() {
        before_value
            .as_object_mut()
            .expect("settings object")
            .remove("lcdMessage");
        after_value
            .as_object_mut()
            .expect("settings object")
            .remove("lcdMessage");
    }
    lcd_matches && camera_settings_values_match(Some(&requested), &before_value, &after_value)
}

fn camera_settings_values_match(requested: Option<&Value>, before: &Value, after: &Value) -> bool {
    if let Some(Value::Object(fields)) = requested {
        let Some(new) = after.as_object() else {
            return false;
        };
        let Some(old) = before.as_object() else {
            return false;
        };
        return fields.iter().all(|(key, wanted)| {
            new.get(key).is_some_and(|observed| {
                camera_settings_values_match(
                    Some(wanted),
                    old.get(key).unwrap_or(&Value::Null),
                    observed,
                )
            })
        }) && old
            .iter()
            .filter(|(key, _)| !fields.contains_key(*key))
            .all(|(key, old_value)| new.get(key) == Some(old_value))
            && new
                .iter()
                .filter(|(key, _)| !fields.contains_key(*key))
                .all(|(key, new_value)| old.get(key) == Some(new_value));
    }
    match requested {
        Some(value) => after == value,
        None => before == after,
    }
}

fn camera_selector(raw: &str) -> Result<&str, McpError> {
    let selector = raw.trim();
    if selector.is_empty()
        || selector.len() > MAXIMUM_CAMERA_SELECTOR_BYTES
        || selector.chars().count() > MAXIMUM_CAMERA_SELECTOR_CHARACTERS
    {
        return Err(McpError::invalid_params(
            "camera selector must be an id or exact name of at most 256 characters",
            None,
        ));
    }
    Ok(selector)
}

fn ptz_command(action: CameraPtzAction, slot: Option<i32>) -> Result<ProtectPtzCommand, McpError> {
    match (action, slot) {
        (CameraPtzAction::GotoPreset, Some(value @ -1..=i32::MAX)) => {
            Ok(ProtectPtzCommand::GotoPreset(value))
        }
        (CameraPtzAction::StartPatrol, Some(value @ 0..=4)) => Ok(ProtectPtzCommand::StartPatrol(
            u8::try_from(value)
                .map_err(|_| McpError::invalid_params("startPatrol requires slot 0-4", None))?,
        )),
        (CameraPtzAction::StopPatrol, None) => Ok(ProtectPtzCommand::StopPatrol),
        (CameraPtzAction::GotoPreset, _) => Err(McpError::invalid_params(
            "gotoPreset requires slot -1 for home or a nonnegative preset slot",
            None,
        )),
        (CameraPtzAction::StartPatrol, _) => Err(McpError::invalid_params(
            "startPatrol requires slot 0-4",
            None,
        )),
        (CameraPtzAction::StopPatrol, _) => Err(McpError::invalid_params(
            "stopPatrol does not accept slot",
            None,
        )),
    }
}

fn patrol_slot_view(state: ProtectPatrolState) -> Option<PatrolSlotView> {
    match state {
        ProtectPatrolState::Unreported => None,
        ProtectPatrolState::Stopped => Some(PatrolSlotView::Stopped),
        ProtectPatrolState::Running(slot) => Some(PatrolSlotView::Running(slot)),
    }
}

fn validate_stream_quality_selection(qualities: &[StreamQuality]) -> Result<(), McpError> {
    if qualities.is_empty() || qualities.len() > 4 {
        return Err(McpError::invalid_params(
            "qualities must contain one to four entries",
            None,
        ));
    }
    for (index, quality) in qualities.iter().enumerate() {
        if qualities[..index].contains(quality) {
            return Err(McpError::invalid_params(
                "qualities must not contain duplicates",
                None,
            ));
        }
    }
    Ok(())
}

fn number_is_negative(value: &Number) -> bool {
    let text = value.as_str();
    text.starts_with('-')
        && text
            .split(['e', 'E'])
            .next()
            .is_some_and(|mantissa| mantissa.bytes().any(|digit| matches!(digit, b'1'..=b'9')))
}

fn number_in_range(value: &Number, minimum: i64, maximum: i64) -> bool {
    fn compare(value: &Number, bound: i64) -> std::cmp::Ordering {
        let text = value.as_str();
        let negative = number_is_negative(value);
        let bound_negative = bound < 0;
        if negative != bound_negative {
            return if negative {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        let unsigned = text.strip_prefix('-').unwrap_or(text);
        let (mantissa, exponent) = unsigned.split_once(['e', 'E']).unwrap_or((unsigned, "0"));
        let digits = mantissa.replace('.', "");
        let digits = digits.trim_start_matches('0');
        let bound_digits = bound.unsigned_abs().to_string();
        let magnitude = if digits.is_empty() {
            0_u64.cmp(&bound.unsigned_abs())
        } else if bound == 0 {
            std::cmp::Ordering::Greater
        } else {
            // Saturation only affects exponents far beyond an integer bound;
            // their magnitude still compares exactly with that bound.
            let exponent = exponent.parse::<i128>().unwrap_or_else(|_| {
                if exponent.starts_with('-') {
                    i128::MIN
                } else {
                    i128::MAX
                }
            });
            let fractional_digits = mantissa
                .split_once('.')
                .map_or(0, |(_, fraction)| fraction.len());
            let order = exponent
                .saturating_sub(fractional_digits as i128)
                .saturating_add(digits.len() as i128);
            order.cmp(&(bound_digits.len() as i128)).then_with(|| {
                let length = digits.len().max(bound_digits.len());
                digits
                    .bytes()
                    .chain(std::iter::repeat(b'0'))
                    .take(length)
                    .cmp(
                        bound_digits
                            .bytes()
                            .chain(std::iter::repeat(b'0'))
                            .take(length),
                    )
            })
        };
        if negative {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
    compare(value, minimum) != std::cmp::Ordering::Less
        && compare(value, maximum) != std::cmp::Ordering::Greater
}

fn validate_pos_transaction(transaction: &PosTransaction) -> Result<(), McpError> {
    fn text_length(value: &str, name: &str) -> Result<(), McpError> {
        if !(1..=255).contains(&value.chars().count()) {
            return Err(McpError::invalid_params(
                format!("{name} must contain 1-255 characters"),
                None,
            ));
        }
        Ok(())
    }

    text_length(&transaction.external_id, "externalId")?;
    if number_is_negative(&transaction.amount) {
        return Err(McpError::invalid_params(
            "amount must be a nonnegative number",
            None,
        ));
    }
    if let Some(currency) = &transaction.currency
        && (currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()))
    {
        return Err(McpError::invalid_params(
            "currency must be three uppercase letters",
            None,
        ));
    }
    if let Some(items) = &transaction.line_items {
        if items.len() > 200 {
            return Err(McpError::invalid_params(
                "lineItems must contain at most 200 entries",
                None,
            ));
        }
        for item in items {
            text_length(&item.title, "lineItems.title")?;
            if item.quantity == 0 {
                return Err(McpError::invalid_params(
                    "lineItems.quantity must be at least 1",
                    None,
                ));
            }
        }
    }
    if let Some(location) = &transaction.location {
        text_length(&location.id, "location.id")?;
        if let Some(name) = &location.name {
            text_length(name, "location.name")?;
        }
    }
    if let Some(payment_types) = &transaction.payment_types {
        if payment_types.len() > 20 {
            return Err(McpError::invalid_params(
                "paymentTypes must contain at most 20 entries",
                None,
            ));
        }
        for payment_type in payment_types {
            text_length(payment_type, "paymentTypes entry")?;
        }
    }
    if transaction.timestamp == Some(0) {
        return Err(McpError::invalid_params(
            "timestamp must be a positive epoch millisecond value",
            None,
        ));
    }
    Ok(())
}

fn stream_url_for(urls: &ProtectStreamUrls, quality: StreamQuality) -> Option<&str> {
    match quality {
        StreamQuality::High => urls.high.as_deref(),
        StreamQuality::Medium => urls.medium.as_deref(),
        StreamQuality::Low => urls.low.as_deref(),
        StreamQuality::Package => urls.package.as_deref(),
    }
}

fn stream_handles(urls: ProtectStreamUrls) -> Vec<CameraStreamHandle> {
    [
        (StreamQuality::High, urls.high),
        (StreamQuality::Medium, urls.medium),
        (StreamQuality::Low, urls.low),
        (StreamQuality::Package, urls.package),
    ]
    .into_iter()
    .filter_map(|(quality, url)| url.map(|url| CameraStreamHandle { quality, url }))
    .collect()
}

fn talkback_session_view(session: ProtectTalkbackSession) -> CameraTalkbackSessionView {
    CameraTalkbackSessionView {
        url: session.url,
        codec: session.codec,
        sampling_rate: session.sampling_rate,
        bits_per_sample: session.bits_per_sample,
    }
}

/// Trim a filter and reject empty or oversized values instead of silently
/// matching everything or nothing.
fn validate_filter(value: Option<&str>) -> Result<Option<String>, McpError> {
    match value {
        None => Ok(None),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.len() > MAXIMUM_QUERY_LENGTH {
                return Err(McpError::invalid_params(
                    format!("filters must be 1-{MAXIMUM_QUERY_LENGTH} characters"),
                    None,
                ));
            }
            Ok(Some(trimmed.to_lowercase()))
        }
    }
}

/// The next page's offset whenever unread matching rows remain.
fn next_offset(offset: usize, returned: usize, total: usize) -> Option<usize> {
    let consumed = offset.saturating_add(returned);
    (consumed < total).then_some(consumed)
}

/// Bound one line of controller-reported text for display, appending a
/// visible marker when the cut actually happened so a truncated excerpt is
/// never mistaken for the whole message.
fn bounded_text(text: String) -> String {
    if text.chars().count() <= EVENT_MESSAGE_CEILING {
        return text;
    }
    // The marker counts inside the ceiling: a cut message is exactly the
    // documented bound long, ellipsis included.
    let mut bounded: String = text.chars().take(EVENT_MESSAGE_CEILING - 1).collect();
    bounded.push('\u{2026}');
    bounded
}

fn bounded_nonblank_text(text: String) -> Option<String> {
    (!text.trim().is_empty()).then(|| bounded_text(text))
}

fn normalize_mac(mac: &str) -> String {
    mac.trim().to_ascii_lowercase()
}

fn sort_key(name: Option<&str>) -> String {
    name.unwrap_or_default().to_lowercase()
}

fn connection_word(is_wired: Option<bool>) -> &'static str {
    match is_wired {
        Some(true) => "wired",
        Some(false) => "wireless",
        // The controller omitted the optional field; never fabricate a type.
        None => "unknown",
    }
}

fn client_matches(
    client: &ActiveClient,
    query: Option<&str>,
    ssid: Option<&str>,
    vlan: Option<u16>,
) -> bool {
    if let Some(query) = query {
        let haystacks = [
            client.name.as_deref(),
            client.hostname.as_deref(),
            client.mac.as_deref(),
            client.ip.as_deref(),
        ];
        if !haystacks
            .iter()
            .flatten()
            .any(|value| value.to_lowercase().contains(query))
        {
            return false;
        }
    }
    if let Some(ssid) = ssid
        && client
            .essid
            .as_deref()
            .is_none_or(|essid| essid.to_lowercase() != ssid)
    {
        return false;
    }
    if let Some(vlan) = vlan
        && client.vlan != Some(vlan)
    {
        return false;
    }
    true
}

/// A connection filter matches only rows that state their type; rows with
/// the field absent appear in unfiltered results only.
fn connection_matches(client: &ActiveClient, connection: Option<ConnectionKind>) -> bool {
    match connection {
        None => true,
        Some(ConnectionKind::Wired) => client.is_wired == Some(true),
        Some(ConnectionKind::Wireless) => client.is_wired == Some(false),
    }
}

/// Tiered client selection: the globally unique MAC is authoritative and a
/// name or hostname is consulted only when no MAC matches, so a colliding
/// name can never shadow an identifier.
fn select_clients(clients: Vec<ActiveClient>, selector: &str) -> Vec<ActiveClient> {
    let selector_mac = normalize_mac(selector);
    let (by_mac, rest): (Vec<ActiveClient>, Vec<ActiveClient>) = clients
        .into_iter()
        .partition(|client| client.mac.as_deref().map(normalize_mac) == Some(selector_mac.clone()));
    if !by_mac.is_empty() {
        return by_mac;
    }
    let selector_name = selector.to_lowercase();
    rest.into_iter()
        .filter(|client| {
            client
                .name
                .as_deref()
                .is_some_and(|name| name.to_lowercase() == selector_name)
                || client
                    .hostname
                    .as_deref()
                    .is_some_and(|hostname| hostname.to_lowercase() == selector_name)
        })
        .collect()
}

fn device_matches(device: &DeviceSummary, query: Option<&str>, state: Option<&str>) -> bool {
    if let Some(query) = query {
        let haystacks = [
            device.name.as_deref(),
            device.model.as_deref(),
            device.mac_address.as_deref(),
            device.ip_address.as_deref(),
        ];
        if !haystacks
            .iter()
            .flatten()
            .any(|value| value.to_lowercase().contains(query))
        {
            return false;
        }
    }
    if let Some(state) = state
        && device
            .state
            .as_deref()
            .is_none_or(|value| value.to_lowercase() != state)
    {
        return false;
    }
    true
}

/// Tiered device selection: id, then MAC, then name, so a colliding name
/// can never shadow an identifier. The boolean reports whether the match
/// came from a globally unique identifier tier.
fn select_devices<'inventory>(
    inventory: &'inventory [DeviceSummary],
    selector: &str,
) -> (Vec<&'inventory DeviceSummary>, bool) {
    let by_id: Vec<&DeviceSummary> = inventory
        .iter()
        .filter(|device| device.id == selector)
        .collect();
    if !by_id.is_empty() {
        return (by_id, true);
    }
    let selector_mac = normalize_mac(selector);
    let by_mac: Vec<&DeviceSummary> = inventory
        .iter()
        .filter(|device| {
            device.mac_address.as_deref().map(normalize_mac) == Some(selector_mac.clone())
        })
        .collect();
    if !by_mac.is_empty() {
        return (by_mac, true);
    }
    let selector_name = selector.to_lowercase();
    (
        inventory
            .iter()
            .filter(|device| {
                device
                    .name
                    .as_deref()
                    .is_some_and(|name| name.to_lowercase() == selector_name)
            })
            .collect(),
        false,
    )
}

fn sort_clients(clients: &mut [ActiveClient]) {
    clients.sort_by(|left, right| {
        sort_key(left.name.as_deref().or(left.hostname.as_deref()))
            .cmp(&sort_key(
                right.name.as_deref().or(right.hostname.as_deref()),
            ))
            .then_with(|| left.mac.cmp(&right.mac))
    });
}

fn client_row(
    client: ActiveClient,
    ap_names: &std::collections::HashMap<String, String>,
    detail: DetailLevel,
) -> ClientRow {
    let ap_name = client
        .ap_mac
        .as_deref()
        .and_then(|mac| ap_names.get(&normalize_mac(mac)).cloned());
    let full = detail == DetailLevel::Full;
    let (tx_bytes, rx_bytes, counter_coverage) = client_counters(&client);
    ClientRow {
        counter_coverage: full.then_some(counter_coverage),
        name: client.name.clone().or_else(|| client.hostname.clone()),
        hostname: client.hostname,
        mac: client.mac,
        ip: client.ip,
        connection: connection_word(client.is_wired),
        ssid: client.essid,
        vlan: client.vlan,
        ap_name,
        signal_dbm: client.signal.filter(|_| full),
        network: client.network.filter(|_| full),
        oui: client.oui.filter(|_| full),
        uptime_seconds: client.uptime.filter(|_| full),
        tx_bytes: tx_bytes.filter(|_| full),
        rx_bytes: rx_bytes.filter(|_| full),
        fixed_ip: client.fixed_ip.filter(|_| full),
    }
}

fn device_row(device: DeviceSummary) -> DeviceRow {
    DeviceRow {
        id: device.id,
        name: device.name,
        model: device.model,
        mac: device.mac_address,
        ip: device.ip_address,
        state: device.state,
        firmware_version: device.firmware_version,
    }
}

fn statistics_view(statistics: &DeviceStatistics) -> DeviceStatisticsView {
    DeviceStatisticsView {
        uptime_seconds: statistics.uptime_sec,
        cpu_utilization_pct: statistics.cpu_utilization_pct,
        memory_utilization_pct: statistics.memory_utilization_pct,
        uplink_tx_rate_bps: statistics
            .uplink
            .as_ref()
            .and_then(|uplink| uplink.tx_rate_bps),
        uplink_rx_rate_bps: statistics
            .uplink
            .as_ref()
            .and_then(|uplink| uplink.rx_rate_bps),
    }
}

/// Page coordinates for a bounded section scan.
fn page_at(offset: u64) -> PageRequest {
    PageRequest { offset, limit: 200 }
}

/// Per-section rows gathered per call. A truncated section continues from its
/// `nextSectionOffset`, so the ceiling bounds one response, not the
/// reachable data.
const ZONE_SCAN_CEILING: u64 = 400;
const POLICY_SCAN_CEILING: u64 = 200;

/// Follow one paginated Integration collection from `start` to its end or
/// `ceiling` more rows. The boolean reports whether the ceiling cut the
/// collection short, so callers surface the truncation and hand back a
/// continuation offset instead of presenting a prefix as complete.
async fn paged_gather<T, F, Fut>(
    start: u64,
    ceiling: u64,
    mut fetch: F,
) -> Result<(Vec<T>, bool), McpError>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<unifi_api::models::Page<T>, ApiError>>,
{
    let mut items = Vec::new();
    let mut offset = start;
    let mut truncated = false;
    loop {
        let page = fetch(offset).await.map_err(api_error)?;
        let fetched = page.data.len() as u64;
        items.extend(page.data);
        offset = offset.saturating_add(fetched);
        if fetched == 0 || offset >= page.total_count {
            break;
        }
        if offset - start >= ceiling {
            truncated = true;
            break;
        }
    }
    Ok((items, truncated))
}

/// The zone-based sections of one firewall read, with the truncation state
/// their bounded scans produced.
#[derive(Default)]
struct ZoneScan {
    zones: Vec<ZoneView>,
    policies: Vec<PolicyView>,
    truncated: bool,
    next_offset: Option<u64>,
    note: Option<String>,
}

/// A continuation offset applies only to the paginated sections.
fn validate_section_offset(input: &FirewallReadInput) -> Result<u64, McpError> {
    let start = input.section_offset.unwrap_or(0);
    if input.section_offset.is_some()
        && !matches!(
            input.section,
            Some(FirewallSection::Zones | FirewallSection::Policies)
        )
    {
        return Err(McpError::invalid_params(
            "sectionOffset requires section zones or policies",
            None,
        ));
    }
    Ok(start)
}

/// Whether one section's presence or emptiness can only be read against the
/// console's firewall generation. Port forwards, traffic rules, and traffic
/// routes exist identically on both, so a narrowing to them needs no probe.
const fn generation_specific(section: FirewallSection) -> bool {
    matches!(section, FirewallSection::Zones | FirewallSection::Policies)
}

/// The stable wire word for one firewall section, echoed so a narrowed
/// response says which narrowing produced it.
const fn section_word(section: FirewallSection) -> &'static str {
    match section {
        FirewallSection::Zones => "zones",
        FirewallSection::Policies => "policies",
        FirewallSection::PortForwards => "portForwards",
        FirewallSection::TrafficRules => "trafficRules",
        FirewallSection::TrafficRoutes => "trafficRoutes",
    }
}

/// The cheapest page request that still reports the collection total.
fn count_probe() -> unifi_api::models::PageRequest {
    unifi_api::models::PageRequest {
        offset: 0,
        limit: 1,
    }
}

// ---------------------------------------------------------------------------
// Wireless network updates
// ---------------------------------------------------------------------------

/// The port a `portCycle` needs, refusing a port on any other action.
fn validated_port(action: DeviceControl, port: Option<u32>) -> Result<Option<u32>, McpError> {
    match (action, port) {
        (DeviceControl::PortCycle, Some(port)) => Ok(Some(port)),
        (DeviceControl::PortCycle, None) => Err(McpError::invalid_params(
            "portCycle requires the port to cycle; devices.status lists a \
             device's ports",
            None,
        )),
        (_, Some(_)) => Err(McpError::invalid_params(
            "port applies only to portCycle; omit it or choose portCycle",
            None,
        )),
        (_, None) => Ok(None),
    }
}

/// Consequences an operator should see before confirming a device action.
fn device_control_warnings(action: DeviceControl) -> Vec<String> {
    vec![
        match action {
            DeviceControl::Restart => {
                "restarting takes the device offline for a minute or more, with \
                 everything it serves"
            }
            DeviceControl::PortCycle => {
                "power-cycling a port reboots whatever it powers, and drops any \
                 device connected to it"
            }
            DeviceControl::Locate => "the device flashes its locate LED until locating is ended",
            DeviceControl::EndLocate => "the device stops flashing its locate LED",
        }
        .to_owned(),
    ]
}

/// Whether a string is the address of one client: six colon-separated
/// hexadecimal octets, and a unicast address.
///
/// The low bit of the first octet marks a group address, and the all-ones
/// address is broadcast. Neither names one client, so acting on either would
/// send a station command for a station that does not exist.
fn is_client_address(value: &str) -> bool {
    // The length is fixed, so it is checked first and nothing is allocated
    // from caller-controlled text: a long value is rejected on its length
    // rather than after being split apart.
    if value.len() != 17 {
        return false;
    }
    let mut octets = value.split(':');
    let mut first_byte = None;
    let mut all_zero = true;
    for index in 0..6 {
        let Some(octet) = octets.next() else {
            return false;
        };
        // The digits are checked before parsing rather than inferred from a
        // successful parse: the integer parser accepts a leading sign, so
        // `+2` would otherwise pass as a two-character octet.
        if octet.len() != 2 || !octet.chars().all(|digit| digit.is_ascii_hexdigit()) {
            return false;
        }
        let Ok(byte) = u8::from_str_radix(octet, 16) else {
            return false;
        };
        if index == 0 {
            first_byte = Some(byte);
        }
        all_zero &= byte == 0;
    }
    if octets.next().is_some() {
        return false;
    }
    // The low bit of the first octet marks a group address, and the all-zero
    // address is the placeholder a controller reports when it has none.
    // Neither names one client.
    first_byte.is_some_and(|byte| byte & 1 == 0) && !all_zero
}

fn guest_client_address(raw: &str) -> Result<String, McpError> {
    let client = normalize_mac(raw);
    if !is_client_address(&client) {
        return Err(McpError::invalid_params(
            "client must be the unicast MAC address of one client, such as aa:bb:cc:dd:ee:ff, as clients.search reports it",
            None,
        ));
    }
    Ok(client)
}

fn guest_limits(input: &GuestsAuthorizeInput) -> Result<GuestAuthorizationLimits, McpError> {
    let limits = GuestAuthorizationLimits {
        time_limit_minutes: input.time_limit_minutes,
        data_usage_limit_m_bytes: input.data_usage_limit_m_bytes,
        rx_rate_limit_kbps: input.rx_rate_limit_kbps,
        tx_rate_limit_kbps: input.tx_rate_limit_kbps,
    };
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
        return Err(McpError::invalid_params(
            "timeLimitMinutes must be 1-1000000, dataUsageLimitMBytes 1-1048576, and rate limits 2-100000 Kbps",
            None,
        ));
    }
    Ok(limits)
}

/// Consequences an operator should see before confirming a client action.
///
/// Each states what the action does, not what the client's state will become.
/// The connected-list reading cannot establish why a client is absent, so a
/// warning that predicted an outcome would contradict the observation beside
/// it in exactly the cases an operator most needs a straight answer.
fn client_control_warnings(action: ClientControl, connected: bool) -> Vec<String> {
    let mut warnings = vec![
        match action {
            ClientControl::Block => {
                "blocking denies this client network access until it is unblocked"
            }
            ClientControl::Unblock => "unblocking lifts a block on this client, if one is in place",
            ClientControl::Reconnect => {
                "reconnecting disconnects the client; most rejoin on their own within seconds"
            }
        }
        .to_owned(),
    ];
    if !connected && action == ClientControl::Reconnect {
        warnings.push("this client is not connected, so there is nothing to disconnect".to_owned());
    }
    warnings
}

/// Every field `changes` accepts. A misspelling is the likeliest way a caller
/// loses a change, so the rejection names what was accepted.
const WLAN_CHANGE_FIELDS: &[&str] = &[
    "ssid",
    "enabled",
    "security",
    "hidden",
    "passphrase",
    "radiusProfileId",
];

fn reject_unknown_change_fields(
    params: &CallToolRequestParams,
    accepted: &[&str],
) -> Result<(), McpError> {
    let Some(Value::Object(changes)) = params
        .arguments
        .as_ref()
        .and_then(|arguments| arguments.get("changes"))
    else {
        return Ok(());
    };
    let unknown: Vec<&str> = changes
        .keys()
        .map(String::as_str)
        .filter(|field| !accepted.contains(field))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(McpError::invalid_params(
        format!(
            "changes does not accept {}; the accepted fields are {}",
            unknown.join(", "),
            accepted.join(", ")
        ),
        None,
    ))
}

/// Every field `firewall.policies.update` accepts.
const FIREWALL_POLICY_CHANGE_FIELDS: &[&str] = &["enabled", "loggingEnabled"];

/// Policy flags have the same names in requests and controller records.
const POLICY_WIRE_NAMES: &[(&str, &str)] =
    &[("enabled", "enabled"), ("loggingEnabled", "loggingEnabled")];

/// Flags used by the policy update shortcut, read from the controller record.
fn policy_projection(record: &Map<String, Value>) -> Value {
    serde_json::json!({
        "enabled": record.get("enabled").and_then(Value::as_bool),
        "loggingEnabled": record.get("loggingEnabled").and_then(Value::as_bool),
    })
}

/// The properties of a raw record this server can read, parsed.
///
/// The raw form is what travels back to the controller; this is only for
/// reading the handful of properties the projection and the warnings need. A
/// property whose text does not parse is simply absent here, which costs
/// nothing: it still goes back untouched.
fn parsed_record(raw: &BTreeMap<String, Box<serde_json::value::RawValue>>) -> Map<String, Value> {
    raw.iter()
        .filter_map(|(name, value)| {
            serde_json::from_str(value.get())
                .ok()
                .map(|parsed| (name.clone(), parsed))
        })
        .collect()
}

/// Read an earlier scalar attribute or the current object's discriminator.
fn firewall_attribute_name<'a>(value: &'a Value, discriminator: &str) -> Option<&'a str> {
    value
        .as_str()
        .or_else(|| value.get(discriminator).and_then(Value::as_str))
}

/// Build the compact policy summary from the record retained by the workflow.
fn policy_view_from_record(id: &str, record: &Map<String, Value>) -> PolicyView {
    let text = |key: &str| record.get(key).and_then(Value::as_str).map(str::to_owned);
    let endpoint = |side: &str, key: &str| {
        record
            .get(side)
            .and_then(Value::as_object)
            .and_then(|value| value.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    PolicyView {
        id: text("id").unwrap_or_else(|| id.to_owned()),
        name: text("name"),
        enabled: record.get("enabled").and_then(Value::as_bool),
        logging_enabled: record.get("loggingEnabled").and_then(Value::as_bool),
        action: record
            .get("action")
            .and_then(|value| firewall_attribute_name(value, "type"))
            .map(str::to_owned),
        index: record
            .get("index")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok()),
        ip_protocol_scope: record
            .get("ipProtocolScope")
            .and_then(|value| firewall_attribute_name(value, "ipVersion"))
            .map(str::to_owned),
        source_zone_id: endpoint("source", "zoneId"),
        source_port: endpoint("source", "port"),
        destination_zone_id: endpoint("destination", "zoneId"),
        destination_port: endpoint("destination", "port"),
    }
}

/// A deletion result must remain small even when the controller supplied
/// unusually long policy labels or endpoint identifiers.
fn bounded_policy_view(mut policy: PolicyView) -> PolicyView {
    for field in [
        &mut policy.name,
        &mut policy.action,
        &mut policy.ip_protocol_scope,
        &mut policy.source_zone_id,
        &mut policy.source_port,
        &mut policy.destination_zone_id,
        &mut policy.destination_port,
    ] {
        if let Some(value) = field.take() {
            *field = Some(bounded_text(value));
        }
    }
    policy
}

/// Include the official policy fields that affect matching or explain the
/// deletion. Unknown controller fields remain named but are not echoed.
fn policy_preview_coverage(record: &Map<String, Value>) -> PolicyPreviewCoverage {
    const DETAIL_FIELDS: &[&str] = &[
        "source",
        "destination",
        "ipProtocolScope",
        "connectionStateFilter",
        "ipsecFilter",
        "schedule",
        "loggingEnabled",
        "description",
        "metadata",
    ];
    const SUMMARY_FIELDS: &[&str] = &["id", "name", "enabled", "action", "index"];
    const FIELD_LIMIT: usize = 16;
    const DETAIL_BUDGET: usize = 16 * 1024;
    let mut details = Map::new();
    let mut detail_bytes = 0;
    let mut omitted_details = Vec::new();
    for name in DETAIL_FIELDS {
        if let Some(value) = record.get(*name) {
            let bytes = name.len() + value.to_string().len();
            if detail_bytes + bytes <= DETAIL_BUDGET {
                detail_bytes += bytes;
                details.insert((*name).to_owned(), value.clone());
            } else {
                omitted_details.push((*name).to_owned());
            }
        }
    }
    let mut omitted_fields = Vec::new();
    let mut omitted_fields_truncated = false;
    let mut add = |name: String| {
        if omitted_fields.len() < FIELD_LIMIT {
            omitted_fields.push(bounded_text(name));
        } else {
            omitted_fields_truncated = true;
        }
    };
    for name in omitted_details {
        add(name);
    }
    for (name, value) in record {
        if DETAIL_FIELDS.contains(&name.as_str()) {
            continue;
        }
        if (matches!(name.as_str(), "name" | "action")
            && value
                .as_str()
                .is_some_and(|text| text.chars().count() > EVENT_MESSAGE_CEILING))
            || !SUMMARY_FIELDS.contains(&name.as_str())
            || (!value.is_null()
                && match name.as_str() {
                    "enabled" => !value.is_boolean(),
                    "index" => value
                        .as_i64()
                        .is_none_or(|index| i32::try_from(index).is_err()),
                    _ => !value.is_string(),
                })
        {
            add(name.clone());
        }
    }
    PolicyPreviewCoverage {
        details,
        complete: omitted_fields.is_empty() && !omitted_fields_truncated,
        omitted_fields,
        omitted_fields_truncated,
    }
}

/// What an operator should know before flipping a policy. A policy is one
/// step in an ordered set, so this says what the policy itself stops or starts
/// doing and names what settles the rest.
fn firewall_policy_warnings(wanted: bool, record: &Map<String, Value>) -> Vec<String> {
    if record.get("enabled").and_then(Value::as_bool) == Some(wanted) {
        // Nothing would move, and a confirmed call will not write, so there is
        // no overwrite to disclose.
        return Vec::new();
    }
    let action = record
        .get("action")
        .and_then(|value| firewall_attribute_name(value, "type"))
        .map(str::to_ascii_lowercase);
    let warning = match (action.as_deref(), wanted) {
        (Some("block" | "reject" | "drop"), false) => {
            "this policy blocks traffic; disabling it stops this policy from blocking, \
             and whether that traffic is then allowed depends on the policies after it"
        }
        (Some("block" | "reject" | "drop"), true) => {
            "this policy blocks traffic; enabling it blocks whatever reaches it and \
             matches, unless an earlier policy allows that traffic first"
        }
        (Some("allow" | "accept"), false) => {
            "this policy allows traffic; disabling it withdraws this policy's allowance, \
             and the policies after it decide"
        }
        (Some("allow" | "accept"), true) => {
            "this policy allows traffic; enabling it allows whatever reaches it and \
             matches, unless an earlier policy blocks that traffic first"
        }
        _ => {
            "the controller reports no action this server recognizes for this policy, \
             so whether the change permits or blocks traffic could not be stated"
        }
    };
    let mut warnings = vec![warning.to_owned()];
    // The whole policy is resent, so a caller should know that a concurrent
    // edit is not merged with this change.
    warnings.push(
        "this change resends the whole policy as it was just read, so an edit made \
         elsewhere between that read and this write is overwritten"
            .to_owned(),
    );
    warnings
}

/// Maximum batch size in the Integration API voucher creation contract.
const VOUCHER_BATCH_CEILING: u32 = 1000;
const MAXIMUM_VOUCHER_REQUEST_BYTES: usize = 1024 * 1024;
/// Reserve most of the tool deadline for returning a successful creation
/// response, even when the detail endpoint stalls during verification.
const VOUCHER_READBACK_BUDGET: Duration = Duration::from_secs(5);
/// Leave time for output shaping and transport serialization after readback.
const VOUCHER_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Bound a post-write stream check so created handles remain returnable.
const STREAM_READBACK_BUDGET: Duration = Duration::from_secs(5);
/// Leave time to serialize stream handles after the optional readback.
const STREAM_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
const PTZ_READBACK_BUDGET: Duration = Duration::from_secs(5);
const PTZ_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// A guest action response must remain returnable after a slow detail read.
const GUEST_READBACK_BUDGET: Duration = Duration::from_secs(5);
const GUEST_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Bound the optional camera read so an accepted patch remains reportable.
const CAMERA_SETTINGS_READBACK_BUDGET: Duration = Duration::from_secs(5);
const CAMERA_SETTINGS_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Leave time to return a successful firewall deletion after checking absence.
const FIREWALL_DELETE_READBACK_BUDGET: Duration = Duration::from_secs(5);
const FIREWALL_DELETE_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
const FIREWALL_UPDATE_READBACK_BUDGET: Duration = Duration::from_secs(5);
const FIREWALL_UPDATE_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
const DEVICE_LIFECYCLE_READBACK_BUDGET: Duration = Duration::from_secs(5);
const DEVICE_LIFECYCLE_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
const NETWORK_ACTION_READBACK_BUDGET: Duration = Duration::from_secs(5);
const NETWORK_ACTION_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
const NETWORK_POLICY_READBACK_BUDGET: Duration = Duration::from_secs(5);
const NETWORK_POLICY_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Maximum validity in the Integration API voucher creation contract.
const VOUCHER_MINUTES_CEILING: u32 = 1_000_000;

fn voucher_id(raw: &str) -> Result<&str, McpError> {
    let id = raw.trim();
    if id.is_empty() || id.len() > MAXIMUM_QUERY_LENGTH {
        return Err(McpError::invalid_params(
            "voucherId must be a bounded voucher id from vouchers.search",
            None,
        ));
    }
    Ok(id)
}

/// Validate native voucher fields before controller access.
fn voucher_batch(input: &VouchersCreateInput) -> Result<VoucherBatch, McpError> {
    if !(1..=VOUCHER_BATCH_CEILING).contains(&input.count) {
        return Err(McpError::invalid_params(
            format!("count must be between 1 and {VOUCHER_BATCH_CEILING}"),
            None,
        ));
    }
    if !(1..=VOUCHER_MINUTES_CEILING).contains(&input.time_limit_minutes) {
        return Err(McpError::invalid_params(
            format!("timeLimitMinutes must be between 1 and {VOUCHER_MINUTES_CEILING}"),
            None,
        ));
    }
    if input.name.is_empty() {
        return Err(McpError::invalid_params("name must be nonempty", None));
    }
    for (field, value, minimum, maximum) in [
        ("guestLimit", input.guest_limit, 1, i64::MAX as u64),
        (
            "dataLimitMegabytes",
            input.data_limit_megabytes,
            1,
            1_048_576,
        ),
        (
            "downloadRateLimitKbps",
            input.download_rate_limit_kbps,
            2,
            100_000,
        ),
        (
            "uploadRateLimitKbps",
            input.upload_rate_limit_kbps,
            2,
            100_000,
        ),
    ] {
        if value.is_some_and(|value| !(minimum..=maximum).contains(&value)) {
            return Err(McpError::invalid_params(
                format!("{field} must be between {minimum} and {maximum}"),
                None,
            ));
        }
    }
    Ok(VoucherBatch {
        name: input.name.clone(),
        count: input.count,
        time_limit_minutes: input.time_limit_minutes,
        guest_limit: input.guest_limit,
        data_limit_megabytes: input.data_limit_megabytes,
        download_rate_limit_kbps: input.download_rate_limit_kbps,
        upload_rate_limit_kbps: input.upload_rate_limit_kbps,
    })
}

/// What can be established about a batch without re-reading it.
///
/// These checks describe the creation response. Readback verification is
/// reported separately because the controller can acknowledge a write it
/// later fails to reproduce.
fn voucher_checks(requested: u32, vouchers: &[VoucherView]) -> VoucherChecks {
    let mut lengths: Vec<usize> = vouchers
        .iter()
        .filter_map(|voucher| voucher.code.as_ref().map(|code| code.chars().count()))
        .collect();
    lengths.sort_unstable();
    lengths.dedup();
    let mut codes: Vec<&str> = vouchers.iter().filter_map(|v| v.code.as_deref()).collect();
    codes.sort_unstable();
    let distinct = codes.len();
    codes.dedup();
    VoucherChecks {
        count_matches: usize::try_from(requested).is_ok_and(|want| want == vouchers.len()),
        all_identified: vouchers.iter().all(|voucher| {
            voucher.id.as_ref().is_some_and(|id| !id.is_empty())
                && voucher.code.as_ref().is_some_and(|code| !code.is_empty())
        }),
        all_distinct: codes.len() == distinct,
        code_lengths: lengths,
    }
}

/// Public identity and state remain authoritative. The local record supplies
/// operational fields that the public contract does not promise.
fn camera_view(
    camera: ProtectCamera,
    local: Option<&ProtectLocalCamera>,
    local_nvr: Option<&ProtectLocalNvr>,
    local_state: LocalEnrichmentState,
) -> CameraView {
    let flags = local.and_then(|value| value.feature_flags.as_ref());
    let (public_name, display_name, display_name_source) = camera_names(&camera, local);
    let mic_enabled = camera
        .is_mic_enabled
        .or_else(|| local.and_then(|value| value.is_mic_enabled));
    let mic_volume = camera
        .mic_volume
        .or_else(|| local.and_then(|value| value.mic_volume));
    let mic_supported = flags.and_then(|value| value.has_mic);
    let audio_globally_disabled = local_nvr.and_then(|value| value.disable_audio);
    let audio = (mic_supported.is_some()
        || mic_enabled.is_some()
        || mic_volume.is_some()
        || audio_globally_disabled.is_some())
    .then_some(CameraAudioView {
        supported: mic_supported,
        enabled: mic_enabled,
        volume: mic_volume,
        globally_disabled: audio_globally_disabled,
        effectively_enabled: effective_switch(mic_enabled, audio_globally_disabled),
    });
    let recording_mode = local
        .and_then(|value| value.recording_settings.as_ref())
        .and_then(|settings| settings.mode.clone())
        .map(bounded_text);
    let recording_globally_disabled = local_nvr.and_then(|value| value.is_recording_disabled);
    let recording_configured = recording_mode
        .as_deref()
        .and_then(recording_mode_configured);
    CameraView {
        id: camera.id,
        guid: camera
            .guid
            .or_else(|| local.and_then(|value| value.guid.clone()))
            .map(bounded_text),
        mac: camera
            .mac
            .or_else(|| local.and_then(|value| value.mac.clone()))
            .map(bounded_text),
        name: public_name,
        display_name,
        display_name_source: display_name_source.to_owned(),
        product_type: camera
            .device_type
            .or_else(|| local.and_then(|value| value.device_type.clone()))
            .map(bounded_text),
        hardware_model: local
            .and_then(|value| value.market_name.clone())
            .and_then(bounded_nonblank_text),
        classes: camera_classes(flags, local),
        state: bounded_text(camera.state),
        active_patrol_slot: patrol_slot_view(camera.active_patrol_slot),
        recording: local.and_then(|value| value.is_recording),
        recording_configured,
        recording_enabled: effective_switch(recording_configured, recording_globally_disabled),
        recording_globally_disabled,
        has_recordings: local.and_then(|value| value.has_recordings),
        poor_network: local.and_then(|value| value.is_poor_network),
        firmware_version: local
            .and_then(|value| value.firmware_version.clone())
            .map(bounded_text),
        latest_firmware_version: local
            .and_then(|value| value.latest_firmware_version.clone())
            .map(bounded_text),
        hardware_revision: local
            .and_then(|value| value.hardware_revision.clone())
            .map(bounded_text),
        connected_since_ms: local.and_then(|value| value.connected_since),
        last_seen_ms: local.and_then(|value| value.last_seen),
        last_disconnect_ms: local.and_then(|value| value.last_disconnect),
        uptime_ms: local.and_then(|value| value.uptime),
        updating: local.and_then(|value| value.is_updating),
        rebooting: local.and_then(|value| value.is_rebooting),
        restoring: local.and_then(|value| value.is_restoring),
        downloading_firmware: local.and_then(|value| value.is_downloading_fw),
        attempting_to_connect: local.and_then(|value| value.is_attempting_to_connect),
        video_mode: local
            .and_then(|value| value.video_mode.clone())
            .map(bounded_text),
        recording_mode,
        audio,
        features: camera_features(flags, local),
        connection: local.and_then(camera_connection),
        details: None,
        local_enrichment: local_enrichment_word(local, local_state).to_owned(),
        local_error: None,
    }
}

fn camera_names(
    camera: &ProtectCamera,
    local: Option<&ProtectLocalCamera>,
) -> (Option<String>, String, &'static str) {
    let public_name = camera.name.clone().map(bounded_text);
    let local_name = local
        .and_then(|value| value.name.clone())
        .and_then(bounded_nonblank_text)
        .map(|name| (name, "localName"));
    let local_model = local
        .and_then(|value| value.market_name.clone())
        .and_then(bounded_nonblank_text)
        .map(|model| (model, "localMarketName"));
    let local_type = local
        .and_then(|value| value.device_type.clone())
        .and_then(bounded_nonblank_text)
        .map(|product_type| (product_type, "localProductType"));
    let (display_name, source) = public_name
        .as_ref()
        .filter(|name| !name.trim().is_empty())
        .map(|name| (name.clone(), "publicName"))
        .or(local_name)
        .or(local_model)
        .or(local_type)
        .unwrap_or_else(|| (bounded_text(camera.id.clone()), "id"));
    (public_name, display_name, source)
}

fn recording_mode_configured(mode: &str) -> Option<bool> {
    if mode.eq_ignore_ascii_case("always") || mode.eq_ignore_ascii_case("detections") {
        Some(true)
    } else if mode.eq_ignore_ascii_case("never") {
        Some(false)
    } else {
        None
    }
}

fn local_enrichment_word(
    local: Option<&ProtectLocalCamera>,
    state: LocalEnrichmentState,
) -> &'static str {
    match (local, state) {
        (Some(_), _) => "available",
        (None, LocalEnrichmentState::Available | LocalEnrichmentState::Partial) => {
            "noMatchingRecord"
        }
        (None, LocalEnrichmentState::NotConfigured) => "notConfigured",
        (None, LocalEnrichmentState::Unavailable) => "unavailable",
    }
}

fn effective_switch(enabled: Option<bool>, globally_disabled: Option<bool>) -> Option<bool> {
    match (enabled, globally_disabled) {
        (Some(false), _) | (_, Some(true)) => Some(false),
        (Some(true), Some(false)) => Some(true),
        _ => None,
    }
}

fn camera_features(
    flags: Option<&ProtectCameraFeatureFlags>,
    local: Option<&ProtectLocalCamera>,
) -> Option<CameraFeaturesView> {
    let smart_detect_types_truncated =
        flags.is_some_and(|value| value.smart_detect_types.len() > CAMERA_FEATURE_LABEL_CEILING);
    let smart_detect_audio_types_truncated = flags
        .is_some_and(|value| value.smart_detect_audio_types.len() > CAMERA_FEATURE_LABEL_CEILING);
    let view = CameraFeaturesView {
        doorbell: flags.and_then(|value| value.is_doorbell),
        speaker: flags.and_then(|value| value.has_speaker),
        wifi: flags.and_then(|value| value.has_wifi),
        hdr: flags.and_then(|value| value.has_hdr),
        package_camera: flags.and_then(|value| value.has_package_camera),
        smart_detect: flags.and_then(|value| value.has_smart_detect),
        optical_zoom: flags.and_then(|value| value.can_optical_zoom),
        status_led: flags.and_then(|value| value.has_led_status),
        automatic_ir_only: flags.and_then(|value| value.has_auto_icr_only),
        ptz: flags.and_then(|value| value.is_ptz),
        two_k: local.and_then(|value| value.is_2k),
        four_k: local.and_then(|value| value.is_4k),
        third_party: local.and_then(|value| value.is_third_party_camera),
        ai_paired: local.and_then(|value| value.is_paired_with_ai_port),
        smart_detect_types: flags
            .map(|value| {
                value
                    .smart_detect_types
                    .iter()
                    .take(CAMERA_FEATURE_LABEL_CEILING)
                    .cloned()
                    .map(bounded_text)
                    .collect()
            })
            .unwrap_or_default(),
        smart_detect_types_truncated: smart_detect_types_truncated.then_some(true),
        smart_detect_audio_types: flags
            .map(|value| {
                value
                    .smart_detect_audio_types
                    .iter()
                    .take(CAMERA_FEATURE_LABEL_CEILING)
                    .cloned()
                    .map(bounded_text)
                    .collect()
            })
            .unwrap_or_default(),
        smart_detect_audio_types_truncated: smart_detect_audio_types_truncated.then_some(true),
    };
    (view.doorbell.is_some()
        || view.speaker.is_some()
        || view.wifi.is_some()
        || view.hdr.is_some()
        || view.package_camera.is_some()
        || view.smart_detect.is_some()
        || view.optical_zoom.is_some()
        || view.status_led.is_some()
        || view.automatic_ir_only.is_some()
        || view.ptz.is_some()
        || view.two_k.is_some()
        || view.four_k.is_some()
        || view.third_party.is_some()
        || view.ai_paired.is_some()
        || !view.smart_detect_types.is_empty()
        || !view.smart_detect_audio_types.is_empty()
        || view.smart_detect_types_truncated.is_some()
        || view.smart_detect_audio_types_truncated.is_some())
    .then_some(view)
}

fn camera_classes(
    flags: Option<&ProtectCameraFeatureFlags>,
    local: Option<&ProtectLocalCamera>,
) -> Option<Vec<String>> {
    let candidates = [
        (flags.and_then(|value| value.is_doorbell), "doorbell"),
        (flags.and_then(|value| value.is_ptz), "ptz"),
        (
            local.and_then(|value| value.is_third_party_camera),
            "third-party",
        ),
        (
            flags.and_then(|value| value.has_package_camera),
            "package-camera",
        ),
        (
            local.and_then(|value| value.is_paired_with_ai_port),
            "ai-paired",
        ),
        (flags.and_then(|value| value.has_speaker), "speaker"),
        (flags.and_then(|value| value.has_mic), "microphone"),
        (local.and_then(|value| value.is_2k), "2k"),
        (local.and_then(|value| value.is_4k), "4k"),
        (flags.and_then(|value| value.has_wifi), "wifi"),
        (
            flags.and_then(|value| value.has_smart_detect),
            "smart-detect",
        ),
        (
            flags.and_then(|value| value.can_optical_zoom),
            "optical-zoom",
        ),
    ];
    candidates
        .iter()
        .any(|(reported, _)| reported.is_some())
        .then(|| {
            candidates
                .into_iter()
                .filter(|(reported, _)| *reported == Some(true))
                .map(|(_, name)| name.to_owned())
                .collect()
        })
}

fn camera_connection(camera: &ProtectLocalCamera) -> Option<CameraConnectionView> {
    if let Some(connection) = camera.wired_connection_state.as_ref() {
        return Some(CameraConnectionView {
            kind: "wired".to_owned(),
            physical_rate: connection.phy_rate,
            transmit_rate: None,
            signal_quality: None,
            signal_strength_dbm: None,
            channel: None,
            frequency_mhz: None,
            experience: None,
            connectivity: None,
        });
    }
    camera
        .wifi_connection_state
        .as_ref()
        .map(|connection| CameraConnectionView {
            kind: "wifi".to_owned(),
            physical_rate: connection.phy_rate,
            transmit_rate: connection.tx_rate,
            signal_quality: connection.signal_quality,
            signal_strength_dbm: connection.signal_strength,
            channel: connection.channel,
            frequency_mhz: connection.frequency,
            experience: connection.experience.clone().map(bounded_text),
            connectivity: connection.connectivity.clone().map(bounded_text),
        })
}

fn class_filter_available(cameras: &[CameraView], wanted: &str) -> Result<bool, McpError> {
    let reported = |camera: &CameraView| match wanted {
        "doorbell" => camera.features.as_ref().and_then(|value| value.doorbell),
        "ptz" => camera.features.as_ref().and_then(|value| value.ptz),
        "third-party" => camera.features.as_ref().and_then(|value| value.third_party),
        "package-camera" => camera
            .features
            .as_ref()
            .and_then(|value| value.package_camera),
        "ai-paired" => camera.features.as_ref().and_then(|value| value.ai_paired),
        "speaker" => camera.features.as_ref().and_then(|value| value.speaker),
        "microphone" => camera.audio.as_ref().and_then(|value| value.supported),
        "2k" => camera.features.as_ref().and_then(|value| value.two_k),
        "4k" => camera.features.as_ref().and_then(|value| value.four_k),
        "wifi" => camera.features.as_ref().and_then(|value| value.wifi),
        "smart-detect" => camera
            .features
            .as_ref()
            .and_then(|value| value.smart_detect),
        "optical-zoom" => camera
            .features
            .as_ref()
            .and_then(|value| value.optical_zoom),
        _ => None,
    };
    if !matches!(
        wanted,
        "doorbell"
            | "ptz"
            | "third-party"
            | "package-camera"
            | "ai-paired"
            | "speaker"
            | "microphone"
            | "2k"
            | "4k"
            | "wifi"
            | "smart-detect"
            | "optical-zoom"
    ) {
        return Err(McpError::invalid_params(
            "class must be doorbell, ptz, third-party, package-camera, ai-paired, speaker, microphone, 2k, 4k, wifi, smart-detect, or optical-zoom",
            None,
        ));
    }
    Ok(cameras.iter().all(|camera| reported(camera).is_some()))
}

fn recorder_view(nvr: ProtectNvr, local: Option<&ProtectLocalNvr>) -> RecorderView {
    let storage = local
        .and_then(|value| value.storage_stats.as_ref())
        .map(recorder_storage_view);
    let public_name = nvr.name.map(bounded_text);
    let local_name = local
        .and_then(|value| value.name.clone())
        .and_then(bounded_nonblank_text)
        .map(|name| (name, "localName"));
    let local_model = local
        .and_then(|value| value.market_name.clone())
        .and_then(bounded_nonblank_text)
        .map(|model| (model, "localMarketName"));
    let local_type = local
        .and_then(|value| value.device_type.clone())
        .and_then(bounded_nonblank_text)
        .map(|product_type| (product_type, "localProductType"));
    let (display_name, display_name_source) = public_name
        .as_ref()
        .filter(|name| !name.trim().is_empty())
        .map(|name| (name.clone(), "publicName"))
        .or(local_name)
        .or(local_model)
        .or(local_type)
        .unwrap_or_else(|| (bounded_text(nvr.id.clone()), "id"));
    RecorderView {
        id: nvr.id,
        guid: nvr
            .guid
            .or_else(|| local.and_then(|value| value.guid.clone()))
            .map(bounded_text),
        mac: nvr
            .mac
            .or_else(|| local.and_then(|value| value.mac.clone()))
            .map(bounded_text),
        name: public_name,
        display_name,
        display_name_source: display_name_source.to_owned(),
        product_type: nvr
            .device_type
            .or_else(|| local.and_then(|value| value.device_type.clone()))
            .map(bounded_text),
        hardware_model: local
            .and_then(|value| value.market_name.clone())
            .and_then(bounded_nonblank_text),
        protect_version: local
            .and_then(|value| value.version.clone())
            .map(bounded_text),
        console_version: local
            .and_then(|value| value.ucore_version.clone())
            .map(bounded_text),
        database_available: local.and_then(|value| value.is_db_available),
        recording_disabled: local.and_then(|value| value.is_recording_disabled),
        recording_motion_only: local.and_then(|value| value.is_recording_motion_only),
        audio_disabled: local.and_then(|value| value.disable_audio),
        recycling: local.and_then(|value| value.is_recycling),
        corruption_state: local
            .and_then(|value| value.corruption_state.clone())
            .map(bounded_text),
        hard_drive_state: local
            .and_then(|value| value.hard_drive_state.clone())
            .map(bounded_text),
        camera_utilization: local.and_then(|value| value.camera_utilization),
        max_camera_capacity: local
            .and_then(|value| value.max_camera_capacity.as_ref())
            .map(|capacity| RecorderCameraCapacityView {
                four_k: capacity.four_k,
                two_k: capacity.two_k,
                hd: capacity.hd,
            }),
        last_drive_slow_event_ms: local.and_then(|value| value.last_drive_slow_event),
        storage,
        enriched: local.is_some(),
    }
}

fn recorder_storage_view(storage: &unifi_api::protect::ProtectStorageStats) -> RecorderStorageView {
    let (recording_type_distribution, recording_type_distribution_truncated) = storage
        .storage_distribution
        .as_ref()
        .and_then(|distribution| distribution.recording_type_distributions.as_ref())
        .map_or((None, None), |distribution| {
            let truncated = distribution.len() > STORAGE_DISTRIBUTION_CEILING;
            let rows = distribution
                .iter()
                .take(STORAGE_DISTRIBUTION_CEILING)
                .map(|row| RecorderDistributionView {
                    category: row.recording_type.clone().map(bounded_text),
                    size_bytes: row.size,
                    percentage: row.percentage,
                })
                .collect();
            (Some(rows), truncated.then_some(true))
        });
    let (resolution_distribution, resolution_distribution_truncated) = storage
        .storage_distribution
        .as_ref()
        .and_then(|distribution| distribution.resolution_distributions.as_ref())
        .map_or((None, None), |distribution| {
            let truncated = distribution.len() > STORAGE_DISTRIBUTION_CEILING;
            let rows = distribution
                .iter()
                .take(STORAGE_DISTRIBUTION_CEILING)
                .map(|row| RecorderDistributionView {
                    category: row.resolution.clone().map(bounded_text),
                    size_bytes: row.size,
                    percentage: row.percentage,
                })
                .collect();
            (Some(rows), truncated.then_some(true))
        });
    RecorderStorageView {
        capacity_ms: storage.capacity,
        remaining_capacity_ms: storage.remaining_capacity,
        utilization: storage.utilization,
        recording_space: storage
            .recording_space
            .as_ref()
            .map(|space| RecorderSpaceView {
                total_bytes: space.total,
                used_bytes: space.used,
                available_bytes: space.available,
            }),
        recording_type_distribution,
        recording_type_distribution_truncated,
        resolution_distribution,
        resolution_distribution_truncated,
    }
}

fn protect_capabilities(
    state: LocalEnrichmentState,
    local_error: Option<&ApiError>,
) -> ProtectCapabilitiesView {
    let (local_enrichment, local_inventory_source, local_unavailable_reason) = match state {
        LocalEnrichmentState::Available => ("available", Some("authenticatedLocalBootstrap"), None),
        LocalEnrichmentState::Partial => (
            "partial",
            Some("authenticatedLocalBootstrap"),
            Some("the local Protect inventory did not contain every public camera"),
        ),
        LocalEnrichmentState::NotConfigured => (
            "notConfigured",
            None,
            Some("local Protect credentials are not configured"),
        ),
        LocalEnrichmentState::Unavailable => (
            "unavailable",
            None,
            Some("the configured local Protect session could not be read"),
        ),
    };
    ProtectCapabilitiesView {
        public_inventory: true,
        public_inventory_source: "integrationApi".to_owned(),
        local_enrichment: local_enrichment.to_owned(),
        local_inventory_source: local_inventory_source.map(str::to_owned),
        snapshot_consistency: "sequentialRequestSnapshots".to_owned(),
        historical_events_configured: state != LocalEnrichmentState::NotConfigured,
        local_unavailable_reason: local_error
            .map(ToString::to_string)
            .or_else(|| local_unavailable_reason.map(str::to_owned)),
    }
}

fn reject_conflicting_camera_identity(
    public: &[ProtectCamera],
    local: &BTreeMap<&str, &ProtectLocalCamera>,
    public_response: &[u8],
    local_response: &[u8],
) -> Result<(), McpError> {
    // One physical device can expose multiple logical camera records, so its
    // GUID or MAC is not an inventory-wide unique key. The documented camera
    // id is the join key, and optional hardware identities must agree only for
    // the two records joined under that same id.
    if public.iter().any(|camera| {
        local.get(camera.id.as_str()).is_some_and(|local| {
            conflicting_optional_identity(camera.guid.as_deref(), local.guid.as_deref())
                || conflicting_optional_identity(camera.mac.as_deref(), local.mac.as_deref())
        })
    }) {
        return Err(conflicting_protect_identity_error(
            "camera",
            public_response,
            local_response,
        ));
    }
    Ok(())
}

fn conflicting_protect_identity_error(
    kind: &str,
    public_response: &[u8],
    local_response: &[u8],
) -> McpError {
    McpError::internal_error(
        format!(
            "public Protect controller response: {}; local Protect controller response: {}; validation error: Protect public and local {kind} identities conflict",
            BoundedMessage::from_controller_bytes(public_response),
            BoundedMessage::from_controller_bytes(local_response),
        ),
        None,
    )
}

fn conflicting_optional_identity(public: Option<&str>, local: Option<&str>) -> bool {
    matches!((public, local), (Some(public), Some(local)) if !public.eq_ignore_ascii_case(local))
}

fn unavailable_camera_filter(field: &str) -> McpError {
    McpError::invalid_params(
        format!(
            "camera {field} filtering is unavailable because this console supplied no complete {field} data"
        ),
        None,
    )
}

fn local_inventory_error(error: Option<&ApiError>, fallback: &'static str) -> McpError {
    error.map_or_else(
        || McpError::invalid_params(fallback, None),
        |error| api_error(error.clone()),
    )
}

fn reject_conflicting_recorder_identity(
    public: &ProtectNvr,
    local: &ProtectLocalNvr,
    public_response: &[u8],
    local_response: &[u8],
) -> Result<(), McpError> {
    if local.id != public.id
        || conflicting_optional_identity(public.guid.as_deref(), local.guid.as_deref())
        || conflicting_optional_identity(public.mac.as_deref(), local.mac.as_deref())
    {
        return Err(conflicting_protect_identity_error(
            "recorder",
            public_response,
            local_response,
        ));
    }
    Ok(())
}

/// Every field `port_forwards.update` accepts.
const PORT_FORWARD_CHANGE_FIELDS: &[&str] = &[
    "name",
    "enabled",
    "source",
    "forwardTo",
    "forwardPort",
    "destinationPort",
    "protocol",
];

/// The port forward as the write surface names it.
fn port_forward_projection(forward: &PortForward) -> Value {
    serde_json::json!({
        "name": forward.name,
        "enabled": forward.enabled,
        "source": forward.src,
        "forwardTo": forward.fwd,
        "forwardPort": forward.fwd_port,
        "destinationPort": forward.dst_port,
        "protocol": forward.proto,
    })
}

/// The requested change, keyed by the names the projection uses.
fn requested_port_forward_fields(changes: &PortForwardChanges) -> Map<String, Value> {
    let mut requested = Map::new();
    if let Some(name) = &changes.name {
        requested.insert("name".to_owned(), Value::String(name.clone()));
    }
    if let Some(enabled) = changes.enabled {
        requested.insert("enabled".to_owned(), Value::Bool(enabled));
    }
    for (name, value) in [
        ("source", &changes.source),
        ("forwardTo", &changes.forward_to),
        ("forwardPort", &changes.forward_port),
        ("destinationPort", &changes.destination_port),
        ("protocol", &changes.protocol),
    ] {
        if let Some(value) = value {
            requested.insert(name.to_owned(), Value::String(value.clone()));
        }
    }
    requested
}

/// Consequences an operator should see before confirming. Both directions
/// matter: one stops reaching a service, the other opens a path to it.
fn port_forward_warnings(requested: &Map<String, Value>, current: &Value) -> Vec<String> {
    let mut warnings = Vec::new();
    if [
        "source",
        "forwardTo",
        "forwardPort",
        "destinationPort",
        "protocol",
    ]
    .iter()
    .any(|field| {
        requested
            .get(*field)
            .is_some_and(|wanted| current.get(*field) != Some(wanted))
    }) {
        warnings.push(
            "changing the rule match or target changes which traffic is forwarded".to_owned(),
        );
    }
    let wanted = requested.get("enabled");
    if wanted.is_none() || current.get("enabled") == wanted {
        return warnings;
    }
    if wanted == Some(&Value::Bool(false)) {
        warnings.push(
            "disabling the rule stops forwarding traffic to the internal host, so whatever \
             reaches it through this rule stops working"
                .to_owned(),
        );
    } else {
        warnings.push(
            "enabling the rule exposes the internal host's port to the source this rule \
             allows, which is the whole internet unless source is narrowed"
                .to_owned(),
        );
    }
    warnings
}

/// The read surface's projection of one port forward, shared by the audit
/// view and the write result so both name the rule identically.
fn port_forward_view(forward: PortForward) -> PortForwardView {
    PortForwardView {
        id: forward.id,
        name: forward.name,
        enabled: forward.enabled,
        source: forward.src,
        forward_to: forward.fwd,
        forward_port: forward.fwd_port,
        destination_port: forward.dst_port,
        protocol: forward.proto,
    }
}

/// The wireless network as the read surface names it. `networkId` is not
/// settable; it is projected so a rebind is visible as a collateral change.
fn wlan_projection(wlan: &WlanConf) -> Value {
    serde_json::json!({
        "ssid": wlan.name,
        "enabled": wlan.enabled,
        "security": wlan.security,
        "hidden": wlan.hide_ssid,
        "passphrase": wlan.x_passphrase,
        "networkId": wlan.networkconf_id,
        "radiusProfileId": wlan.radius_profile_id,
    })
}

/// The requested change, keyed by the names the read surface uses.
fn requested_fields(changes: &WlanChanges) -> Map<String, Value> {
    let mut requested = Map::new();
    if let Some(ssid) = &changes.ssid {
        requested.insert("ssid".to_owned(), Value::String(ssid.clone()));
    }
    if let Some(enabled) = changes.enabled {
        requested.insert("enabled".to_owned(), Value::Bool(enabled));
    }
    if let Some(security) = changes.security {
        requested.insert(
            "security".to_owned(),
            Value::String(security.wire().to_owned()),
        );
    }
    if let Some(hidden) = changes.hidden {
        requested.insert("hidden".to_owned(), Value::Bool(hidden));
    }
    if let Some(passphrase) = &changes.passphrase {
        requested.insert("passphrase".to_owned(), Value::String(passphrase.clone()));
    }
    if let Some(profile) = &changes.radius_profile_id {
        requested.insert("radiusProfileId".to_owned(), Value::String(profile.clone()));
    }
    requested
}

/// Consequences an operator should see before confirming.
fn wlan_warnings(requested: &Map<String, Value>, current: &Value) -> Vec<String> {
    let mut warnings = Vec::new();
    let changing = |field: &str| {
        requested
            .get(field)
            .is_some_and(|wanted| current.get(field) != Some(wanted))
    };
    if requested.get("enabled") == Some(&Value::Bool(false)) && changing("enabled") {
        warnings.push("disabling the network drops every client on it".to_owned());
    }
    if requested.get("security") == Some(&Value::String("open".to_owned())) && changing("security")
    {
        warnings.push("switching to open removes encryption from this network".to_owned());
    }
    if changing("ssid")
        || changing("passphrase")
        || changing("security")
        || changing("radiusProfileId")
    {
        warnings.push("every client must reconnect after this change".to_owned());
    }
    warnings
}

/// The patch to send, built from the request alone. An omitted passphrase is
/// left unchanged by this partial controller update.
fn wlan_patch(changes: &WlanChanges) -> WlanPatch {
    WlanPatch {
        name: changes.ssid.clone(),
        enabled: changes.enabled,
        security: changes.security.map(|mode| mode.wire().to_owned()),
        x_passphrase: changes
            .passphrase
            .as_ref()
            .map(|passphrase| Zeroizing::new(passphrase.clone())),
        hide_ssid: changes.hidden,
        radius_profile_id: changes.radius_profile_id.clone(),
    }
}

/// Controller properties that moved without being requested, by the
/// controller's own property name.
/// Properties that moved without being asked for.
///
/// The fingerprint speaks the controller's property names while a request
/// speaks the read surface's, so the requested fields are translated before
/// they can be excluded. The translation is per resource: a field with no
/// entry would silently fail to be excluded and turn a change the caller
/// asked for into a reported collateral change, so every accepted field has
/// one, asserted by test.
fn unrequested_changes(
    before: &RecordFingerprint,
    after: &RecordFingerprint,
    requested: &Map<String, Value>,
    wire_names: &[(&str, &str)],
) -> Vec<String> {
    let asked_for: Vec<&str> = requested
        .keys()
        .filter_map(|field| wire_name(wire_names, field))
        .collect();
    before
        .changed_properties(after)
        .into_iter()
        .filter(|property| !asked_for.contains(&property.as_str()))
        .collect()
}

/// The controller's name for one field of the read surface.
/// The controller property each accepted field is stored under. The wireless
/// network is the case that makes this necessary: a caller says `hidden` and
/// `ssid`, the controller stores `hide_ssid` and `name`.
const WLAN_WIRE_NAMES: &[(&str, &str)] = &[
    ("ssid", "name"),
    ("enabled", "enabled"),
    ("security", "security"),
    ("hidden", "hide_ssid"),
    ("passphrase", "x_passphrase"),
    ("radiusProfileId", "radius_profile_id"),
];

/// Names exposed by the tool and stored by the controller.
const PORT_FORWARD_WIRE_NAMES: &[(&str, &str)] = &[
    ("name", "name"),
    ("enabled", "enabled"),
    ("source", "src"),
    ("forwardTo", "fwd"),
    ("forwardPort", "fwd_port"),
    ("destinationPort", "dst_port"),
    ("protocol", "proto"),
];

fn wire_name<'a>(wire_names: &[(&str, &'a str)], field: &str) -> Option<&'a str> {
    wire_names
        .iter()
        .find(|(accepted, _)| *accepted == field)
        .map(|(_, property)| *property)
}

// ---------------------------------------------------------------------------
// Shared machinery
// ---------------------------------------------------------------------------

fn parse<T: DeserializeOwned>(params: &CallToolRequestParams) -> Result<T, McpError> {
    let value = params
        .arguments
        .clone()
        .map_or_else(|| Value::Object(Map::new()), Value::Object);
    serde_json::from_value(value).map_err(|error| {
        McpError::invalid_params(
            format!("arguments do not match the advertised schema: {error}"),
            None,
        )
    })
}

pub(crate) fn structured<T: Serialize>(output: T) -> Result<CallToolResult, McpError> {
    let value = serde_json::to_value(output)
        .map_err(|_| McpError::internal_error("failed to serialize bounded result", None))?;
    Ok(CallToolResult::structured(value))
}

/// Keep the structured traffic summary bounded while preserving complete
/// source errors and, when necessary, the requested Activity page in content.
fn structured_stats(output: StatsQueryOutput) -> Result<CallToolResult, McpError> {
    let mut value = serde_json::to_value(output)
        .map_err(|_| McpError::internal_error("failed to serialize bounded result", None))?;
    let mut extra_content = Vec::new();
    if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
        && let Value::Object(fields) = &mut value
        && let Some(errors) = fields.remove("sourceErrors")
    {
        fields.insert("sourceErrorsInContent".to_owned(), Value::Bool(true));
        let text = format!("sourceErrors: {errors}");
        extra_content.push(ContentBlock::text(text));
    }
    if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
        && let Value::Object(fields) = &mut value
        && let Some(activity) = fields.remove("activity")
    {
        fields.insert("activityInContent".to_owned(), Value::Bool(true));
        extra_content.push(ContentBlock::text(format!("activity: {activity}")));
    }
    let mut result = CallToolResult::structured(value);
    result.content.extend(extra_content);
    Ok(result)
}

fn traffic_read_result(mut output: TrafficReadOutput) -> Result<CallToolResult, McpError> {
    let failed = output.status == "failed";
    let mut content = Vec::new();
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(data) = output.data.take()
    {
        output.data_in_content = Some(true);
        content.push(ContentBlock::text(format!("data: {data}")));
    }
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(error) = output.error.take()
    {
        output.error_in_content = Some(true);
        content.push(ContentBlock::text(format!("error: {error}")));
    }
    let mut result = structured(output)?;
    result.is_error = Some(failed);
    result.content.extend(content);
    Ok(result)
}

/// Keep an applied mutation's result available when a failed verification
/// read returned more text than fits beside that result.
fn structured_with_mutation_readback_error<T: Serialize>(
    output: T,
    upstream_error: Option<&ApiError>,
) -> Result<CallToolResult, McpError> {
    let mut value = serde_json::to_value(output)
        .map_err(|_| McpError::internal_error("failed to serialize bounded result", None))?;
    let mut extra_content = Vec::new();
    if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
        && let Value::Object(fields) = &mut value
        && let Some(Value::String(body)) = fields.remove("responseBody")
    {
        fields.insert("responseBodyInContent".to_owned(), Value::Bool(true));
        extra_content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
        && let Some(error) = upstream_error
        && let Value::Object(fields) = &mut value
        && fields.remove("readbackError").is_some()
    {
        fields.insert("readbackErrorInContent".to_owned(), Value::Bool(true));
        let mut result = CallToolResult::structured(value);
        result.content.extend(extra_content);
        result
            .content
            .push(ContentBlock::text(format!("readbackError: {error}")));
        return Ok(result);
    }
    let mut result = CallToolResult::structured(value);
    result.content.extend(extra_content);
    Ok(result)
}

/// Keep a confirmed action's accepted response and any later controller
/// readback failure available when either exceeds the content formatting target.
fn structured_with_accepted_response<T: Serialize>(output: T) -> Result<CallToolResult, McpError> {
    let mut value = serde_json::to_value(output)
        .map_err(|_| McpError::internal_error("failed to serialize bounded result", None))?;
    let mut content = Vec::new();
    for (field, marker) in [
        ("responseBody", "responseBodyInContent"),
        ("readbackError", "readbackErrorInContent"),
    ] {
        if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
            && let Value::Object(fields) = &mut value
            && let Some(Value::String(body)) = fields.remove(field)
        {
            fields.insert(marker.to_owned(), Value::Bool(true));
            content.push(ContentBlock::text(format!("{field}: {body}")));
        }
    }
    let mut result = CallToolResult::structured(value);
    result.content.extend(content);
    Ok(result)
}

/// Preserve issued codes, accepted bodies, and verification failures through
/// labeled content when their combined values exceed the structured bound.
fn structured_with_mutation_readback_errors<T: Serialize>(
    output: T,
) -> Result<CallToolResult, McpError> {
    let mut value = serde_json::to_value(output)
        .map_err(|_| McpError::internal_error("failed to serialize bounded result", None))?;
    let mut extra_content = Vec::new();
    if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
        && let Value::Object(fields) = &mut value
        && let Some(Value::String(body)) = fields.remove("responseBody")
    {
        fields.insert("responseBodyInContent".to_owned(), Value::Bool(true));
        extra_content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
        && let Value::Object(fields) = &mut value
        && let Some(errors) = fields.remove("readbackErrors")
    {
        fields.insert("readbackErrorsInContent".to_owned(), Value::Bool(true));
        extra_content.push(ContentBlock::text(format!("readbackErrors: {errors}")));
    }
    if value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES
        && let Value::Object(fields) = &mut value
        && let Some(vouchers) = fields.remove("vouchers")
    {
        fields.insert("vouchersInContent".to_owned(), Value::Bool(true));
        extra_content.push(ContentBlock::text(format!("vouchers: {vouchers}")));
    }
    let mut result = CallToolResult::structured(value);
    result.content.extend(extra_content);
    Ok(result)
}

fn trust_annotated(mut result: CallToolResult, behavior: ToolBehavior) -> CallToolResult {
    let trust = serde_json::json!({
        "sensitive": behavior.result_sensitive,
        "untrusted": behavior.result_untrusted
    });
    result
        .meta
        .get_or_insert_with(MetaObject::default)
        .0
        .insert(TRUST_ANNOTATIONS_KEY.to_owned(), trust);
    result
}

/// Keep the caller's recovery path for an event timestamp group that needs a
/// larger page while carrying the complete controller response.
fn protect_events_api_error(error: ApiError) -> McpError {
    if matches!(
        &error,
        ApiError::DecodeResponse { diagnostic, .. }
            if diagnostic.as_str()
                == "Protect event page boundary exceeds the requested limit; retry with a higher limit"
    ) {
        McpError::invalid_params(error.to_string(), None)
    } else {
        api_error(error)
    }
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn api_error(error: ApiError) -> McpError {
    McpError::internal_error(error.to_string(), None)
}

fn page_validation_error(
    response: &BoundedMessage,
    diagnostic: impl Into<BoundedMessage>,
) -> McpError {
    api_error(ApiError::DecodeResponse {
        response: response.clone(),
        diagnostic: diagnostic.into(),
    })
}

fn controller_page_metadata(response: &BoundedMessage) -> Result<Map<String, Value>, McpError> {
    let mut metadata = serde_json::from_str::<Map<String, Value>>(response.as_str())
        .map_err(|error| page_validation_error(response, error.to_string()))?;
    metadata.remove("data");
    Ok(metadata)
}

fn viewer_settings_match(changes: &ProtectViewerSettingsChanges, after: &Value) -> bool {
    changes
        .name
        .as_ref()
        .is_none_or(|name| after.get("name").and_then(Value::as_str) == Some(name.as_str()))
        && changes
            .liveview
            .as_ref()
            .is_none_or(|assignment| match assignment {
                LiveviewAssignment::Id(id) => {
                    after.get("liveview").and_then(Value::as_str) == Some(id.as_str())
                }
                LiveviewAssignment::Clear => after.get("liveview") == Some(&Value::Null),
            })
}

fn validate_protect_action_id(field: &str, id: &str) -> Result<(), McpError> {
    if id.is_empty() || id.len() > 256 || matches!(id, "." | "..") {
        return Err(McpError::invalid_params(
            format!("{field} must be a nonempty, non-dot id of at most 256 bytes"),
            None,
        ));
    }
    Ok(())
}

fn protect_action_request(
    action: &ProtectDeviceAction,
) -> Result<(ProtectDeviceActionRoute<'_>, Option<Value>), McpError> {
    let result = match action {
        ProtectDeviceAction::SirenPlay { duration } => {
            if duration.is_some_and(|value| !matches!(value, 5 | 10 | 20 | 30)) {
                return Err(McpError::invalid_params(
                    "siren duration must be 5, 10, 20, or 30 seconds",
                    None,
                ));
            }
            (
                ProtectDeviceActionRoute::SirenPlay,
                duration.map(|value| json!({"duration":value})),
            )
        }
        ProtectDeviceAction::SirenStop => (ProtectDeviceActionRoute::SirenStop, None),
        ProtectDeviceAction::SirenTestSound { volume } => {
            if volume.is_some_and(|value| !(1..=100).contains(&value)) {
                return Err(McpError::invalid_params(
                    "siren test volume must be 1-100",
                    None,
                ));
            }
            (
                ProtectDeviceActionRoute::SirenTestSound,
                volume.map(|value| json!({"volume":value})),
            )
        }
        ProtectDeviceAction::RelayActivate {
            output_id,
            state,
            pulse_duration,
        } => {
            validate_protect_action_id("outputId", output_id)?;
            let mut body = Map::new();
            if let Some(state) = state {
                body.insert(
                    "state".to_owned(),
                    Value::String(
                        match state {
                            RelayOutputState::On => "on",
                            RelayOutputState::Off => "off",
                        }
                        .to_owned(),
                    ),
                );
            }
            if let Some(duration) = pulse_duration {
                body.insert("pulseDuration".to_owned(), json!(duration));
            }
            (
                ProtectDeviceActionRoute::RelayActivate { output_id },
                (!body.is_empty()).then_some(Value::Object(body)),
            )
        }
        ProtectDeviceAction::SpeakerTestSound { volume } => {
            if volume.is_some_and(|value| value > 100) {
                return Err(McpError::invalid_params(
                    "speaker test volume must be 0-100",
                    None,
                ));
            }
            (
                ProtectDeviceActionRoute::SpeakerTestSound,
                volume.map(|value| json!({"volume":value})),
            )
        }
        ProtectDeviceAction::AlarmHubTrigger {
            output_id,
            enable,
            delay,
            duration,
        } => {
            validate_protect_action_id("outputId", output_id)?;
            let mut body = Map::new();
            if let Some(enable) = enable {
                body.insert("enable".to_owned(), json!(enable));
            }
            if let Some(delay) = delay {
                body.insert("delay".to_owned(), json!(delay));
            }
            if let Some(duration) = duration {
                body.insert("duration".to_owned(), json!(duration));
            }
            (
                ProtectDeviceActionRoute::AlarmHubTrigger { output_id },
                (!body.is_empty()).then_some(Value::Object(body)),
            )
        }
    };
    Ok(result)
}

#[allow(clippy::too_many_lines)]
fn device_settings_request(
    changes: &ProtectDeviceSettingsChanges,
) -> Result<(ProtectDeviceKind, Value), McpError> {
    let kind = match changes {
        ProtectDeviceSettingsChanges::Light {
            light_device_settings,
            ..
        } => {
            if light_device_settings.as_ref().is_some_and(|settings| {
                settings
                    .pir_duration
                    .as_ref()
                    .is_some_and(number_is_negative)
                    || settings
                        .pir_sensitivity
                        .as_ref()
                        .is_some_and(|value| !number_in_range(value, 0, 100))
                    || settings
                        .led_level
                        .as_ref()
                        .is_some_and(|value| !number_in_range(value, 1, 6))
            }) {
                return Err(McpError::invalid_params(
                    "light pirDuration must be nonnegative, pirSensitivity 0-100, and ledLevel 1-6",
                    None,
                ));
            }
            ProtectDeviceKind::Light
        }
        ProtectDeviceSettingsChanges::Sensor {
            light_settings,
            humidity_settings,
            temperature_settings,
            motion_settings,
            glass_break_settings,
            arm_profile_ids,
            ..
        } => {
            for (field, settings, minimum, maximum) in [
                ("lightSettings", light_settings.as_ref(), 1, 503_192),
                ("humiditySettings", humidity_settings.as_ref(), 1, 99),
                (
                    "temperatureSettings",
                    temperature_settings.as_ref(),
                    -39,
                    124,
                ),
            ] {
                if settings.is_some_and(|settings| {
                    matches!(&settings.low_threshold, Some(ProtectNullableNumber::Number(value)) if !number_in_range(value, minimum, maximum))
                }) {
                    return Err(McpError::invalid_params(
                        format!("{field}.lowThreshold is outside the documented range"),
                        None,
                    ));
                }
            }
            for (field, settings) in [
                ("motionSettings", motion_settings.as_ref()),
                ("glassBreakSettings", glass_break_settings.as_ref()),
            ] {
                if settings.is_some_and(|settings| {
                    settings
                        .sensitivity
                        .as_ref()
                        .is_some_and(|value| !number_in_range(value, 0, 100))
                        || settings
                            .sensitivity_when_armed
                            .as_ref()
                            .is_some_and(|value| !number_in_range(value, 0, 100))
                }) {
                    return Err(McpError::invalid_params(
                        format!("{field} sensitivity must be 0-100"),
                        None,
                    ));
                }
            }
            if matches!(arm_profile_ids, Some(ProtectNullableIds::Ids(ids)) if ids.len() > 32 || ids.iter().any(|id| id.chars().count() > 64))
            {
                return Err(McpError::invalid_params(
                    "armProfileIds accepts at most 32 ids of at most 64 characters each",
                    None,
                ));
            }
            ProtectDeviceKind::Sensor
        }
        ProtectDeviceSettingsChanges::Chime { ring_settings, .. } => {
            if ring_settings.as_ref().is_some_and(|rows| {
                rows.iter().any(|row| {
                    !number_in_range(&row.repeat_times, 1, 10)
                        || !number_in_range(&row.volume, 0, 100)
                })
            }) {
                return Err(McpError::invalid_params(
                    "ringSettings repeatTimes must be 1-10 and volume 0-100",
                    None,
                ));
            }
            ProtectDeviceKind::Chime
        }
        ProtectDeviceSettingsChanges::Siren { volume, .. } => {
            if volume.is_some_and(|value| !(1..=100).contains(&value)) {
                return Err(McpError::invalid_params("siren volume must be 1-100", None));
            }
            ProtectDeviceKind::Siren
        }
        ProtectDeviceSettingsChanges::Relay { .. } => ProtectDeviceKind::Relay,
        ProtectDeviceSettingsChanges::Speaker {
            volume, mic_volume, ..
        } => {
            if volume.is_some_and(|value| value > 100)
                || mic_volume.is_some_and(|value| value > 100)
            {
                return Err(McpError::invalid_params(
                    "speaker volume and micVolume must be 0-100",
                    None,
                ));
            }
            ProtectDeviceKind::Speaker
        }
        ProtectDeviceSettingsChanges::Fob { .. } => ProtectDeviceKind::Fob,
        ProtectDeviceSettingsChanges::Bridge { .. } => ProtectDeviceKind::Bridge,
        ProtectDeviceSettingsChanges::LinkStation { .. } => ProtectDeviceKind::LinkStation,
        ProtectDeviceSettingsChanges::AlarmHub { .. } => ProtectDeviceKind::AlarmHub,
    };
    let mut request = serde_json::to_value(changes)
        .map_err(|_| McpError::internal_error("device settings could not be encoded", None))?;
    let object = request
        .as_object_mut()
        .expect("tagged changes serialize to an object");
    object.remove("kind");
    object.retain(|key, value| key == "armProfileIds" || !value.is_null());
    if object.is_empty() {
        return Err(McpError::invalid_params(
            "changes names no field to change",
            None,
        ));
    }
    if request.to_string().len() > 1024 * 1024 {
        return Err(McpError::invalid_params(
            "device settings request exceeds 1 MiB",
            None,
        ));
    }
    Ok((kind, request))
}

fn device_settings_update_result(
    mut output: ProtectDevicesSettingsUpdateOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &ProtectDevicesSettingsUpdateOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(requested) = output.requested.take()
    {
        output.requested_in_content = Some(true);
        content.push(ContentBlock::text(format!("requested: {requested}")));
    }
    if exceeds(&output)?
        && let Some(before) = output.before.take()
    {
        output.before_in_content = Some(true);
        content.push(ContentBlock::text(format!("before: {before}")));
    }
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn camera_disable_mic_result(
    mut output: CameraDisableMicOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &CameraDisableMicOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(before) = output.before.take()
    {
        output.before_in_content = Some(true);
        content.push(ContentBlock::text(format!("before: {before}")));
    }
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn camera_settings_read_result(
    mut output: CameraSettingsReadOutput,
) -> Result<CallToolResult, McpError> {
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(camera) = output.camera.take()
    {
        output.camera_in_content = Some(true);
        let mut result = structured(output)?;
        result
            .content
            .push(ContentBlock::text(format!("camera: {camera}")));
        return Ok(result);
    }
    structured(output)
}

fn camera_settings_update_result(
    mut output: CameraSettingsOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &CameraSettingsOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(requested) = output.requested.take()
    {
        output.requested_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "requested: {}",
            serde_json::to_value(requested).map_err(|_| McpError::internal_error(
                "failed to serialize camera settings",
                None
            ))?
        )));
    }
    if exceeds(&output)?
        && let Some(before) = output.before.take()
    {
        output.before_in_content = Some(true);
        content.push(ContentBlock::text(format!("before: {before}")));
    }
    if exceeds(&output)?
        && let Some(response) = output.response.take()
    {
        output.response_in_content = Some(true);
        content.push(ContentBlock::text(format!("response: {response}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn protect_asset_upload_result(
    mut output: ProtectAssetUploadOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &ProtectAssetUploadOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(accepted) = output.accepted.take()
    {
        output.accepted_in_content = Some(true);
        content.push(ContentBlock::text(format!("accepted: {accepted}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn protect_action_result(
    mut output: ProtectDevicesActionOutput,
) -> Result<CallToolResult, McpError> {
    let full = structured(&output)?;
    if full
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        let mut result = structured(output)?;
        result
            .content
            .push(ContentBlock::text(format!("responseBody: {body}")));
        return Ok(result);
    }
    Ok(full)
}

fn validate_arm_changes(changes: &ProtectArmProfileChanges) -> Result<(), McpError> {
    if changes
        .name
        .as_ref()
        .is_some_and(|name| name.is_empty() || name.chars().count() > 255)
    {
        return Err(McpError::invalid_params(
            "name must contain 1-255 characters",
            None,
        ));
    }
    if changes
        .activation_delay
        .is_some_and(|delay| !matches!(delay, 0 | 60_000 | 300_000 | 600_000))
    {
        return Err(McpError::invalid_params(
            "activationDelay must be 0, 60000, 300000, or 600000 milliseconds",
            None,
        ));
    }
    Ok(())
}

fn arm_changes_json(changes: &ProtectArmProfileChanges) -> Result<Value, McpError> {
    let value = serde_json::to_value(changes)
        .map_err(|_| McpError::internal_error("arm-profile changes could not be encoded", None))?;
    if value.to_string().len() > 1024 * 1024 {
        return Err(McpError::invalid_params(
            "arm-profile request exceeds 1 MiB",
            None,
        ));
    }
    Ok(value)
}

fn protect_arm_operation_result(
    mut output: ProtectArmOperationOutput,
) -> Result<CallToolResult, McpError> {
    let mut extra = Vec::new();
    if structured(&output)?
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(requested) = output.requested.take()
    {
        output.requested_in_content = Some(true);
        extra.push(ContentBlock::text(format!("requested: {requested}")));
    }
    if structured(&output)?
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        extra.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if structured(&output)?
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(observed) = output.observed.take()
    {
        output.observed_in_content = Some(true);
        extra.push(ContentBlock::text(format!("observed: {observed}")));
    }
    if structured(&output)?
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        extra.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(extra);
    Ok(result)
}

fn wifi_broadcasts_list_result(
    mut output: WifiBroadcastsListOutput,
) -> Result<CallToolResult, McpError> {
    let mut content = Vec::new();
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(broadcasts) = output.broadcasts.take()
    {
        output.broadcasts_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "broadcasts: {}",
            serde_json::to_value(broadcasts).expect("controller JSON records")
        )));
    }
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(metadata) = output.page_metadata.take()
    {
        output.page_metadata_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "pageMetadata: {}",
            Value::Object(metadata)
        )));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn network_policy_detail_result(
    mut output: NetworkPolicyDetailOutput,
) -> Result<CallToolResult, McpError> {
    let full = structured(&output)?;
    if full
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
    {
        let record = output.record.take().expect("policy record exists");
        output.record_in_content = Some(true);
        let mut result = structured(output)?;
        result
            .content
            .push(ContentBlock::text(format!("record: {record}")));
        return Ok(result);
    }
    Ok(full)
}

fn network_policy_list_result(
    mut output: NetworkPolicyListOutput,
) -> Result<CallToolResult, McpError> {
    let mut content = Vec::new();
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(records) = output.records.take()
    {
        output.records_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "records: {}",
            Value::Array(records)
        )));
    }
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(metadata) = output.page_metadata.take()
    {
        output.page_metadata_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "pageMetadata: {}",
            Value::Object(metadata)
        )));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn network_policy_write_result<K: Serialize>(
    mut output: NetworkPolicyWriteOutput<K>,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &NetworkPolicyWriteOutput<K>| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(requested) = output.requested.take()
    {
        output.requested_in_content = Some(true);
        content.push(ContentBlock::text(format!("requested: {requested}")));
    }
    if exceeds(&output)?
        && let Some(accepted) = output.accepted.take()
    {
        output.accepted_in_content = Some(true);
        content.push(ContentBlock::text(format!("accepted: {accepted}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn firewall_update_result(
    mut output: FirewallPoliciesUpdateOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &FirewallPoliciesUpdateOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(before) = output.before_response.take()
    {
        output.before_response_in_content = Some(true);
        content.push(ContentBlock::text(format!("beforeResponse: {before}")));
    }
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after_response.take()
    {
        output.after_response_in_content = Some(true);
        content.push(ContentBlock::text(format!("afterResponse: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn firewall_delete_result(
    mut output: FirewallPoliciesDeleteOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &FirewallPoliciesDeleteOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(before) = output.before_response.take()
    {
        output.before_response_in_content = Some(true);
        content.push(ContentBlock::text(format!("beforeResponse: {before}")));
    }
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn pending_devices_list_result(
    mut output: PendingDevicesListOutput,
) -> Result<CallToolResult, McpError> {
    let mut content = Vec::new();
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(devices) = output.devices.take()
    {
        output.devices_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "devices: {}",
            Value::Array(devices)
        )));
    }
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(metadata) = output.page_metadata.take()
    {
        output.page_metadata_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "pageMetadata: {}",
            Value::Object(metadata)
        )));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn radius_profiles_list_result(
    mut output: RadiusProfilesListOutput,
) -> Result<CallToolResult, McpError> {
    let mut content = Vec::new();
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(profiles) = output.profiles.take()
    {
        output.profiles_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "profiles: {}",
            serde_json::to_value(profiles).expect("controller JSON records")
        )));
    }
    if structured(&output)?
        .structured_content
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
        && let Some(metadata) = output.page_metadata.take()
    {
        output.page_metadata_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "pageMetadata: {}",
            Value::Object(metadata)
        )));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn protect_overview_result(output: ProtectOverviewResult) -> Result<CallToolResult, McpError> {
    match output {
        ProtectOverviewResult::Summary(output) => structured(output),
        ProtectOverviewResult::Record(output) => record_result(output),
    }
}

fn record_result(mut output: RecordOutput) -> Result<CallToolResult, McpError> {
    let full = structured(&output)?;
    if full
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
    {
        let record = output.record.take().expect("detail record exists");
        output.record_in_content = Some(true);
        let mut result = structured(output)?;
        result
            .content
            .push(ContentBlock::text(format!("record: {record}")));
        return Ok(result);
    }
    Ok(full)
}

fn network_inventory_list_result(
    mut output: NetworkInventoryListOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &NetworkInventoryListOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(records) = output.records.take()
    {
        output.records_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "records: {}",
            Value::Array(records)
        )));
    }
    if exceeds(&output)?
        && let Some(metadata) = output.page_metadata.take()
    {
        output.page_metadata_in_content = Some(true);
        content.push(ContentBlock::text(format!(
            "pageMetadata: {}",
            Value::Object(metadata)
        )));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn devices_adopt_result(mut output: DevicesAdoptOutput) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &DevicesAdoptOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(accepted) = output.accepted.take()
    {
        output.accepted_in_content = Some(true);
        content.push(ContentBlock::text(format!("accepted: {accepted}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn devices_remove_result(mut output: DevicesRemoveOutput) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &DevicesRemoveOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn devices_control_result(mut output: DevicesControlOutput) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &DevicesControlOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn validate_voucher_records_page(
    page: &unifi_api::models::Page<Value>,
    response: &BoundedMessage,
    offset: u64,
    limit: usize,
) -> Result<(), McpError> {
    if page.offset != offset
        || page.limit == 0
        || page.limit > u64::from(voucher_limit(limit))
        || page.count != page.data.len() as u64
        || page.count > page.limit
        || (page.count != 0 && page.offset.saturating_add(page.count) > page.total_count)
        || (page.count == 0 && page.offset < page.total_count)
    {
        return Err(page_validation_error(
            response,
            "controller returned an inconsistent voucher page",
        ));
    }
    Ok(())
}

fn vouchers_revoke_matching_result(
    mut output: VouchersRevokeMatchingOutput,
) -> Result<CallToolResult, McpError> {
    let full = structured(&output)?;
    if full
        .structured_content
        .as_ref()
        .is_none_or(|value| value.to_string().len() <= STRUCTURED_CONTENT_TARGET_BYTES)
    {
        return Ok(full);
    }
    let mut content = Vec::new();
    for (value, marker, label) in [
        (
            &mut output.before_response,
            &mut output.before_response_in_content,
            "beforeResponse",
        ),
        (
            &mut output.response_body,
            &mut output.response_body_in_content,
            "responseBody",
        ),
        (
            &mut output.after_response,
            &mut output.after_response_in_content,
            "afterResponse",
        ),
        (
            &mut output.readback_error,
            &mut output.readback_error_in_content,
            "readbackError",
        ),
    ] {
        if let Some(value) = value.take() {
            *marker = Some(true);
            content.push(ContentBlock::text(format!("{label}: {value}")));
        }
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn voucher_revoke_result(mut output: VoucherRevokeOutput) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &VoucherRevokeOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(body) = output.response_body.take()
    {
        output.response_body_in_content = Some(true);
        content.push(ContentBlock::text(format!("responseBody: {body}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn arm_profiles_list_result(
    mut output: ProtectArmProfilesListOutput,
) -> Result<CallToolResult, McpError> {
    let full = structured(&output)?;
    if full
        .structured_content
        .as_ref()
        .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES)
    {
        let profiles = output.profiles.take().expect("page records exist");
        output.profiles_in_content = Some(true);
        let mut result = structured(output)?;
        result.content.push(ContentBlock::text(format!(
            "profiles: {}",
            Value::Array(profiles)
        )));
        return Ok(result);
    }
    Ok(full)
}

fn viewer_settings_result(
    mut output: ProtectViewerSettingsUpdateOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &ProtectViewerSettingsUpdateOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(before) = output.before.take()
    {
        output.before_in_content = Some(true);
        content.push(ContentBlock::text(format!("before: {before}")));
    }
    if exceeds(&output)?
        && let Some(response) = output.response.take()
    {
        output.response_in_content = Some(true);
        content.push(ContentBlock::text(format!("response: {response}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn liveview_changes_match(changes: &Value, after: &Value) -> bool {
    requested_json_matches(changes, after)
}

fn liveview_configuration_request(changes: &LiveviewChanges) -> Result<Value, McpError> {
    if changes
        .layout
        .as_ref()
        .is_some_and(|layout| !number_in_range(layout, 1, 26))
    {
        return Err(McpError::invalid_params(
            "layout must be between 1 and 26",
            None,
        ));
    }
    let request = serde_json::to_value(changes)
        .map_err(|_| McpError::internal_error("live-view changes could not be encoded", None))?;
    if request.to_string().len() > 1024 * 1024 {
        return Err(McpError::invalid_params(
            "live-view request exceeds the 1 MiB input budget",
            None,
        ));
    }
    Ok(request)
}

fn requested_json_matches(requested: &Value, observed: &Value) -> bool {
    match (requested, observed) {
        (Value::Number(wanted), Value::Number(actual)) => numbers_equivalent(wanted, actual),
        (Value::Array(wanted), Value::Array(actual)) => {
            wanted.len() == actual.len()
                && wanted
                    .iter()
                    .zip(actual)
                    .all(|(wanted, actual)| requested_json_matches(wanted, actual))
        }
        (Value::Object(wanted), Value::Object(actual)) => wanted.iter().all(|(name, value)| {
            actual
                .get(name)
                .is_some_and(|observed| requested_json_matches(value, observed))
        }),
        _ => requested == observed,
    }
}

fn numbers_equivalent(wanted: &Number, actual: &Number) -> bool {
    if wanted == actual {
        return true;
    }
    match (decimal_parts(wanted), decimal_parts(actual)) {
        (Some(wanted), Some(actual)) => wanted == actual,
        _ => false,
    }
}

/// Compare decimal coefficients and exponents without floating-point rounding.
/// An exponent that cannot be represented leaves equivalence unproven; the
/// original requested and observed values remain available to the caller.
fn decimal_parts(number: &Number) -> Option<(bool, String, i128)> {
    let text = number.to_string();
    let negative = text.starts_with('-');
    let unsigned = text.strip_prefix('-').unwrap_or(&text);
    let (mantissa, exponent) = unsigned.split_once(['e', 'E']).unwrap_or((unsigned, "0"));
    let fractional_digits = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let digits = mantissa.replace('.', "");
    let significant = digits.trim_start_matches('0').trim_end_matches('0');
    if significant.is_empty() {
        return Some((false, String::new(), 0));
    }
    let trailing_zeros = digits.len() - digits.trim_end_matches('0').len();
    let exponent = exponent
        .parse::<i128>()
        .ok()?
        .checked_sub(i128::try_from(fractional_digits).ok()?)?
        .checked_add(i128::try_from(trailing_zeros).ok()?)?;
    Some((negative, significant.to_owned(), exponent))
}

fn liveview_configure_result(
    mut output: ProtectLiveviewsConfigureOutput,
) -> Result<CallToolResult, McpError> {
    let exceeds = |output: &ProtectLiveviewsConfigureOutput| -> Result<bool, McpError> {
        Ok(structured(output)?
            .structured_content
            .is_some_and(|value| value.to_string().len() > STRUCTURED_CONTENT_TARGET_BYTES))
    };
    let mut content = Vec::new();
    if exceeds(&output)?
        && let Some(requested) = output.requested.take()
    {
        output.requested_in_content = Some(true);
        let requested = serde_json::to_value(requested).map_err(|_| {
            McpError::internal_error("live-view changes could not be encoded", None)
        })?;
        content.push(ContentBlock::text(format!("requested: {requested}")));
    }
    if exceeds(&output)?
        && let Some(before) = output.before.take()
    {
        output.before_in_content = Some(true);
        content.push(ContentBlock::text(format!("before: {before}")));
    }
    if exceeds(&output)?
        && let Some(response) = output.response.take()
    {
        output.response_in_content = Some(true);
        content.push(ContentBlock::text(format!("response: {response}")));
    }
    if exceeds(&output)?
        && let Some(after) = output.after.take()
    {
        output.after_in_content = Some(true);
        content.push(ContentBlock::text(format!("after: {after}")));
    }
    if exceeds(&output)?
        && let Some(error) = output.readback_error.take()
    {
        output.readback_error_in_content = Some(true);
        content.push(ContentBlock::text(format!("readbackError: {error}")));
    }
    let mut result = structured(output)?;
    result.content.extend(content);
    Ok(result)
}

fn guest_validation_error(response: BoundedMessage, diagnostic: &'static str) -> ApiError {
    ApiError::DecodeResponse {
        response,
        diagnostic: BoundedMessage::new(diagnostic),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rmcp::model::CallToolRequestParams;
    use serde_json::{Map, Value, json};

    use super::{
        BOOLEAN_SCHEMA_KEYWORDS, ClientsSearchInput, FIREWALL_POLICY_CHANGE_FIELDS,
        FirewallPolicyChanges, JSON_SCHEMA_TYPES, POLICY_WIRE_NAMES, PORT_FORWARD_CHANGE_FIELDS,
        PORT_FORWARD_WIRE_NAMES, PolicyView, PortForwardChanges, PortForwardView,
        WLAN_CHANGE_FIELDS, WLAN_WIRE_NAMES, WlanChanges, WlanView, normalize_portable_schema,
        parse, schema_object, structured, trust_annotated,
    };
    use crate::mutation::FieldOutcome;
    use crate::registry::{TOOL_REGISTRY, ToolBehavior};

    #[test]
    fn lcd_integer_reset_time_keeps_its_json_number_form() {
        let changes: super::CameraSettingsChanges = serde_json::from_value(json!({
            "lcdMessage":{"type":"CUSTOM_MESSAGE","text":"Welcome","resetAt":123_456}
        }))
        .expect("typed LCD message");
        let patch = super::camera_settings_patch(&changes).expect("camera patch");
        assert_eq!(
            patch.lcd_message.expect("LCD message")["resetAt"],
            json!(123_456)
        );
    }

    const CONSTRAINING_KEYWORDS: [&str; 43] = [
        "type",
        "enum",
        "const",
        "multipleOf",
        "maximum",
        "exclusiveMaximum",
        "minimum",
        "exclusiveMinimum",
        "maxLength",
        "minLength",
        "pattern",
        "format",
        "contentMediaType",
        "contentEncoding",
        "contentSchema",
        "maxItems",
        "minItems",
        "uniqueItems",
        "maxContains",
        "minContains",
        "maxProperties",
        "minProperties",
        "required",
        "dependentRequired",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "items",
        "prefixItems",
        "contains",
        "additionalItems",
        "unevaluatedItems",
        "properties",
        "patternProperties",
        "additionalProperties",
        "unevaluatedProperties",
        "propertyNames",
        "dependentSchemas",
        "dependencies",
        "$ref",
        "$dynamicRef",
        "$recursiveRef",
    ];

    fn for_each_subschema(node: &Map<String, Value>, mut visit: impl FnMut(&Value, &str)) {
        for keyword in [
            "properties",
            "patternProperties",
            "dependentSchemas",
            "dependencies",
            "$defs",
            "definitions",
        ] {
            if let Some(children) = node.get(keyword).and_then(Value::as_object) {
                for child in children.values() {
                    visit(child, keyword);
                }
            }
        }
        for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(children) = node.get(keyword).and_then(Value::as_array) {
                for child in children {
                    visit(child, keyword);
                }
            }
        }
        for keyword in [
            "items",
            "contains",
            "not",
            "propertyNames",
            "if",
            "then",
            "else",
            "additionalProperties",
            "unevaluatedProperties",
            "additionalItems",
            "unevaluatedItems",
            "contentSchema",
        ] {
            let Some(child) = node.get(keyword) else {
                continue;
            };
            if keyword == "items"
                && let Some(children) = child.as_array()
            {
                for child in children {
                    visit(child, keyword);
                }
                continue;
            }
            visit(child, keyword);
        }
    }

    fn schema_declares_id(schema: &Value, depth: usize) -> bool {
        if depth > 64 {
            return false;
        }
        let Some(node) = schema.as_object() else {
            return false;
        };
        if node
            .get("$id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
        {
            return true;
        }
        let mut found = false;
        for_each_subschema(node, |child, _| {
            found |= schema_declares_id(child, depth + 1);
        });
        found
    }

    fn inspector_findings(schema: &Value) -> Vec<&'static str> {
        fn walk(
            schema: &Value,
            parent_keyword: Option<&str>,
            depth: usize,
            has_embedded_ids: bool,
            findings: &mut Vec<&'static str>,
        ) {
            if depth > 64 {
                return;
            }
            if schema.is_boolean() {
                if parent_keyword.is_none_or(|keyword| !BOOLEAN_SCHEMA_KEYWORDS.contains(&keyword))
                {
                    findings.push("boolean-schema");
                }
                return;
            }
            let Some(node) = schema.as_object() else {
                return;
            };
            if node
                .get("type")
                .and_then(Value::as_array)
                .is_some_and(|types| {
                    !types.is_empty()
                        && types.iter().all(|item| {
                            item.as_str()
                                .is_some_and(|name| JSON_SCHEMA_TYPES.contains(&name))
                        })
                        && types
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<HashSet<_>>()
                            .len()
                            == types.len()
                })
            {
                findings.push("type-union");
            }
            if !has_embedded_ids
                && node
                    .get("$ref")
                    .and_then(Value::as_str)
                    .is_some_and(|reference| !reference.is_empty() && !reference.starts_with('#'))
            {
                findings.push("remote-ref");
            }
            let constrains = node
                .keys()
                .any(|keyword| CONSTRAINING_KEYWORDS.contains(&keyword.as_str()))
                || (node.contains_key("if")
                    && (node.contains_key("then") || node.contains_key("else")));
            if !constrains && parent_keyword != Some("not") {
                findings.push("untyped-schema");
            }
            for_each_subschema(node, |child, keyword| {
                walk(child, Some(keyword), depth + 1, has_embedded_ids, findings);
            });
        }

        let has_embedded_ids = schema_declares_id(schema, 0);
        let mut findings = Vec::new();
        walk(schema, None, 0, has_embedded_ids, &mut findings);
        findings
    }

    fn validates(schema: &Value, instance: &Value) -> bool {
        jsonschema::validator_for(schema)
            .expect("published schema compiles")
            .is_valid(instance)
    }

    #[test]
    fn viewer_settings_schema_accepts_an_explicit_null_assignment() {
        let schema = serde_json::to_value(schemars::schema_for!(
            super::ProtectViewerSettingsUpdateInput
        ))
        .expect("viewer settings schema");
        assert!(validates(
            &schema,
            &json!({"viewerId":"viewer-1","changes":{"liveview":null}})
        ));
        assert!(validates(
            &schema,
            &json!({"viewerId":"viewer-1","changes":{"liveview":"view-1"}})
        ));
        assert!(!validates(
            &schema,
            &json!({"viewerId":"viewer-1","changes":{"liveview":42}})
        ));
    }

    #[test]
    fn liveview_readback_compares_large_integers_exactly() {
        assert!(super::requested_json_matches(
            &json!({"slots":[{"cycleInterval":10}]}),
            &json!({"slots":[{"cycleInterval":10.0,"futureField":true}]})
        ));
        assert!(!super::requested_json_matches(
            &json!({"slots":[{"cycleInterval":9_007_199_254_740_993_u64}]}),
            &json!({"slots":[{"cycleInterval":9_007_199_254_740_992_u64}]})
        ));
        assert!(!super::requested_json_matches(
            &json!({"slots":[{"cycleInterval":9_007_199_254_740_993_u64}]}),
            &json!({"slots":[{"cycleInterval":9_007_199_254_740_992.0}]})
        ));
    }

    #[test]
    fn unknown_argument_fields_are_rejected() {
        let mut params = CallToolRequestParams::default();
        params.name = "network.overview".into();
        params.arguments = Some(
            json!({"unexpected": true})
                .as_object()
                .expect("object")
                .clone(),
        );
        assert!(parse::<super::EmptyInput>(&params).is_err());
        let mut empty = CallToolRequestParams::default();
        empty.name = "network.overview".into();
        assert!(parse::<super::EmptyInput>(&empty).is_ok());
    }

    #[test]
    fn pagination_continues_while_matching_rows_remain() {
        assert_eq!(super::next_offset(0, 50, 100), Some(50));
        assert_eq!(super::next_offset(0, 100, 100), None);
        assert_eq!(super::next_offset(10_000, 50, 20_000), Some(10_050));
        assert_eq!(super::next_offset(100_000, 50, 200_000), Some(100_050));
    }

    #[test]
    fn an_omitted_connection_type_is_never_fabricated() {
        assert_eq!(super::connection_word(None), "unknown");
        assert_eq!(super::connection_word(Some(true)), "wired");
        assert_eq!(super::connection_word(Some(false)), "wireless");
    }

    #[test]
    fn trust_metadata_preserves_complete_large_results() {
        let supplied = serde_json::json!({
            "nested": {"controller-key": "controller-value"},
            "code": "controller-code",
            "large":"x".repeat(60000),
        });
        let mut result = structured(supplied.clone()).expect("built result");
        result.is_error = Some(true);
        result
            .content
            .push(rmcp::model::ContentBlock::text("complete upstream detail"));
        let original_content = result.content.clone();
        let returned = trust_annotated(result, ToolBehavior::read());
        assert_eq!(returned.structured_content, Some(supplied));
        assert_eq!(returned.is_error, Some(true));
        assert_eq!(returned.content, original_content);
    }

    #[test]
    fn every_catalog_tool_publishes_schemas_annotations_and_action_metadata() {
        for spec in TOOL_REGISTRY {
            let tool = spec.catalog_tool();
            assert_eq!(tool.name, spec.name);
            assert!(tool.output_schema.is_some(), "{}", spec.name);
            // Hints are the registry's declared behavior: the catalog now
            // carries a write as well as reads.
            let annotations = tool.annotations.as_ref().expect("annotations");
            assert_eq!(
                annotations.read_only_hint,
                Some(spec.behavior.read_only),
                "{}",
                spec.name
            );
            assert_eq!(
                annotations.destructive_hint,
                Some(spec.behavior.destructive),
                "{}",
                spec.name
            );
            let meta = tool.meta.as_ref().expect("meta");
            assert!(
                meta.0.contains_key(super::ACTION_METADATA_KEY),
                "{}",
                spec.name
            );
            // Inputs must reject unknown fields so the schema is the contract.
            let schema = serde_json::to_value(&tool.input_schema).expect("schema");
            assert_eq!(
                schema["additionalProperties"],
                serde_json::Value::Bool(false),
                "{}",
                spec.name
            );
        }
    }

    #[test]
    fn catalog_schemas_pass_mcp_inspector_portability_rules() {
        let mut findings = Vec::new();
        for spec in TOOL_REGISTRY {
            let tool = spec.catalog_tool();
            for (kind, schema) in [
                ("inputSchema", Value::Object((*tool.input_schema).clone())),
                (
                    "outputSchema",
                    Value::Object((*tool.output_schema.expect("output schema")).clone()),
                ),
            ] {
                for rule in inspector_findings(&schema) {
                    findings.push(format!("{}.{}: {rule}", tool.name, kind));
                }
            }
        }
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn portable_schemas_preserve_free_form_and_nullable_value_domains() {
        for original in [Value::Bool(true), Value::Bool(false)] {
            let mut portable = original.clone();
            normalize_portable_schema(&mut portable, None);
            for instance in [
                json!(null),
                json!(true),
                json!(7),
                json!("value"),
                json!([1, 2]),
                json!({"nested": true}),
            ] {
                assert_eq!(
                    validates(&original, &instance),
                    validates(&portable, &instance),
                    "boolean schema normalization changed the value domain for {instance}"
                );
            }
        }

        let original = json!({
            "type": ["string", "null"],
            "anyOf": [{"maxLength": 3}]
        });
        let mut portable = original.clone();
        normalize_portable_schema(&mut portable, None);
        for instance in [json!(null), json!("ok"), json!("long"), json!(7), json!({})] {
            assert_eq!(
                validates(&original, &instance),
                validates(&portable, &instance),
                "type-union normalization changed the value domain for {instance}"
            );
        }
        assert!(portable.get("type").is_none());
        assert!(portable["allOf"][0]["anyOf"].is_array());

        let raw_outcome =
            serde_json::to_value(schemars::schema_for!(FieldOutcome)).expect("raw schema");
        let portable_outcome = Value::Object(schema_object::<FieldOutcome>());
        for requested in [
            None,
            Some(json!(null)),
            Some(json!(false)),
            Some(json!(42)),
            Some(json!("ssid")),
            Some(json!([1, 2])),
            Some(json!({"nested": true})),
        ] {
            let mut instance = json!({"field": "ssid", "status": "persisted"});
            if let Some(requested) = requested {
                instance["requested"] = requested;
            }
            assert!(validates(&raw_outcome, &instance), "{instance}");
            assert!(validates(&portable_outcome, &instance), "{instance}");
        }

        let clients_search = Value::Object(schema_object::<ClientsSearchInput>());
        assert!(validates(&clients_search, &json!({})));
        assert!(validates(&clients_search, &json!({"query": null})));
        assert!(validates(
            &clients_search,
            &json!({"query": "access point"})
        ));
        assert!(!validates(&clients_search, &json!({"query": 7})));
    }

    /// Comparing annotations with the declaration that produced them cannot
    /// catch a wrong declaration. The gateway treats these as the
    /// authorization boundary for the write surface, so the classification is
    /// stated here independently: weakening the registry fails this test.
    /// The classification each write must publish, stated independently of
    /// the registry: name, idempotent, sensitive input, sensitive result.
    /// A write that lost its classification would vanish from a
    /// registry-derived list and take its own assertion with it, and
    /// idempotence and sensitivity differ per tool, so both are named.
    const EXPECTED_WRITE_CLASSIFICATION: &[(&str, bool, bool, bool)] = &[
        // Applying the same settings twice leaves the same state; the input
        // carries a passphrase and the result reports configuration.
        ("wlans.update", true, true, true),
        ("wlans.configure", false, true, true),
        ("networks.configure", false, true, true),
        ("wifi.broadcasts.configure", false, true, true),
        // Disconnecting twice disconnects twice; no secret is involved.
        ("clients.control", false, false, true),
        // Each restart restarts; no secret is involved.
        ("devices.control", false, false, true),
        ("devices.adopt", false, true, true),
        ("devices.remove", false, false, true),
        ("acl.rules.configure", false, true, true),
        ("acl.rules.ordering.configure", true, true, true),
        ("firewall.policies.ordering.configure", true, true, true),
        ("dns.policies.configure", false, true, true),
        ("firewall.zones.configure", false, true, true),
        ("firewall.policies.configure", false, true, true),
        ("traffic.matching_lists.configure", false, true, true),
        // Reauthorization replaces the grant and resets traffic counters.
        ("guests.authorize", false, false, true),
        // Revocation disconnects the client and returns the revoked grant.
        ("guests.unauthorize", false, false, true),
        // Setting the same rule state twice leaves the same state; no secret
        // is involved, and the result names the host a rule exposes.
        ("port_forwards.update", true, false, true),
        ("port_forwards.configure", false, true, true),
        // Same, and the result names the zones and ports a policy governs.
        ("firewall.policies.update", true, false, true),
        // Repeating deletion leaves the policy absent.
        ("firewall.policies.delete", true, false, true),
        // The upstream idempotency window is short and resets on restart;
        // transaction details and event results can contain sensitive data.
        ("cameras.pos.transaction", false, true, true),
        // Siren, relay, speaker, and alarm-hub actions can have another effect
        // when repeated; device identities and responses can be sensitive.
        ("protect.devices.action", false, true, true),
        // Applying the same device settings twice leaves the same state;
        // names, audio settings, and returned device records may be sensitive.
        ("protect.devices.settings.update", true, true, true),
        // Profile creation and deletion can have another effect on repetition;
        // configuration and returned records may be sensitive.
        ("protect.arm_profiles.configure", false, true, true),
        // Alarm enablement and webhook triggers can have another effect when
        // repeated, and trigger identities and responses may be sensitive.
        ("protect.alarms.action", false, true, true),
        // Repeating a movement or patrol command may trigger another action.
        ("cameras.ptz.control", false, false, true),
        ("cameras.microphone.disable", true, false, true),
        ("protect.assets.upload", false, true, true),
        // Applying the same named settings leaves the same configuration.
        ("cameras.settings.update", true, false, true),
        // A viewer assignment is stable when repeated; device names and
        // returned configuration may be sensitive.
        ("protect.viewers.settings.update", true, true, true),
        // Creating another view can have another effect; layouts and camera
        // assignments can contain sensitive configuration.
        ("protect.liveviews.configure", false, true, true),
        // Repeating a stream creation or removal, or opening another audio
        // session, can have another upstream effect.
        ("cameras.streams.update", false, false, true),
        ("cameras.talkback.start", false, false, true),
        // Each call mints another batch; the result carries the credentials.
        ("vouchers.create", false, false, true),
        // Revoking the same voucher again leaves it absent.
        ("vouchers.revoke", true, false, true),
        ("vouchers.revoke_matching", false, true, true),
    ];

    /// The catalog text is what a model reads before choosing arguments, so
    /// a description naming a different selector than the schema accepts
    /// sends a caller to an error. Checked for the tools whose selector was
    /// changed after their description was written.
    #[test]
    fn a_catalog_description_names_the_selector_its_schema_accepts() {
        for (name, selector) in [
            ("guests.authorize", "MAC address"),
            ("clients.control", "MAC address"),
            ("wlans.update", "id"),
        ] {
            let spec = TOOL_REGISTRY
                .iter()
                .find(|spec| spec.name == name)
                .unwrap_or_else(|| panic!("{name} is not in the catalog"));
            assert!(
                spec.description.contains(selector),
                "{name} does not name {selector}"
            );
        }
    }

    #[test]
    fn every_write_tool_is_classified_for_the_gateway_as_a_write() {
        for (name, idempotent, input_sensitive, result_sensitive) in EXPECTED_WRITE_CLASSIFICATION {
            let write = TOOL_REGISTRY
                .iter()
                .find(|spec| spec.name == *name)
                .unwrap_or_else(|| panic!("{name} is not in the catalog"));
            assert!(!write.behavior.read_only, "{name}");
            assert!(write.behavior.destructive, "{name}");
            assert!(write.behavior.requires_review, "{name}");
            assert_eq!(write.behavior.idempotent, *idempotent, "{name}");
            assert_eq!(write.behavior.input_sensitive, *input_sensitive, "{name}");
            assert_eq!(write.behavior.result_sensitive, *result_sensitive, "{name}");
            assert_eq!(write.risk, "high", "{name}");
            let annotations = write.catalog_tool().annotations.expect("annotations");
            assert_eq!(annotations.read_only_hint, Some(false), "{name}");
            assert_eq!(annotations.destructive_hint, Some(true), "{name}");
            assert_eq!(annotations.idempotent_hint, Some(*idempotent), "{name}");
        }
        // Every registered write is covered above, so a new one cannot ship
        // without a stated classification.
        let writes = TOOL_REGISTRY
            .iter()
            .filter(|spec| !spec.behavior.read_only)
            .count();
        assert_eq!(writes, EXPECTED_WRITE_CLASSIFICATION.len());
    }

    /// Property names one schema publishes.
    fn schema_property_names<T: schemars::JsonSchema>() -> Vec<String> {
        schema_object::<T>()
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .expect("object schema publishes properties")
            .keys()
            .cloned()
            .collect()
    }

    /// The fingerprint comparison excludes the fields a caller asked for by
    /// translating them to the controller's property names. A field with no
    /// translation is not excluded, so a change the caller requested is
    /// reported as a collateral change and the write can never verify. The
    /// failure is silent and per field, so coverage is asserted rather than
    /// left to whichever field a test happens to exercise.
    #[test]
    fn every_field_a_write_accepts_has_a_controller_property_name() {
        for (tool, accepted, wire_names) in [
            ("wlans.update", WLAN_CHANGE_FIELDS, WLAN_WIRE_NAMES),
            (
                "port_forwards.update",
                PORT_FORWARD_CHANGE_FIELDS,
                PORT_FORWARD_WIRE_NAMES,
            ),
            (
                "firewall.policies.update",
                FIREWALL_POLICY_CHANGE_FIELDS,
                POLICY_WIRE_NAMES,
            ),
        ] {
            for field in accepted {
                assert!(
                    super::wire_name(wire_names, field).is_some(),
                    "{tool} accepts {field} with no controller property name"
                );
            }
            // The reverse, so a mapping cannot keep an entry for a field the
            // write no longer accepts.
            for (field, _) in wire_names {
                assert!(accepted.contains(field), "{tool} maps unaccepted {field}");
            }
        }
    }

    /// A value read from a resource must be writable back under the name it
    /// was read under. The read schema, the write schema, and the list a
    /// rejection quotes are three independent declarations, so without this
    /// they drift silently: the wireless read calls it `hidden` while the wire
    /// calls it `hide_ssid`, and a patch field named for the wire would be a
    /// name no caller can learn from any read.
    #[test]
    fn every_write_names_its_fields_as_the_matching_read_emits_them() {
        for (write_tool, read_tool, read, write, declared) in [
            (
                "wlans.update",
                "networks.read",
                schema_property_names::<WlanView>(),
                schema_property_names::<WlanChanges>(),
                WLAN_CHANGE_FIELDS,
            ),
            (
                "port_forwards.update",
                "firewall.read",
                schema_property_names::<PortForwardView>(),
                schema_property_names::<PortForwardChanges>(),
                PORT_FORWARD_CHANGE_FIELDS,
            ),
            (
                "firewall.policies.update",
                "firewall.read",
                schema_property_names::<PolicyView>(),
                schema_property_names::<FirewallPolicyChanges>(),
                FIREWALL_POLICY_CHANGE_FIELDS,
            ),
        ] {
            for field in &write {
                assert!(
                    read.contains(field),
                    "{write_tool} accepts {field}, which {read_tool} never emits"
                );
            }
            // The diagnostic list is what a caller is told; it must be the
            // real schema rather than a copy that can fall behind it.
            let mut declared: Vec<String> = declared.iter().map(|f| (*f).to_owned()).collect();
            declared.sort();
            let mut actual = write;
            actual.sort();
            assert_eq!(declared, actual, "{write_tool}");
        }
    }

    #[test]
    fn results_carry_the_declared_trust_labels() {
        let result = structured(serde_json::json!({"ok": true})).expect("result");
        let annotated = trust_annotated(result, ToolBehavior::read());
        let trust = &annotated.meta.expect("meta").0["io.modelcontextprotocol/trust-annotations"];
        assert_eq!(trust["sensitive"], false);
        assert_eq!(trust["untrusted"], true);
    }
}
