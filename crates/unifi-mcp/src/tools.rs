//! Tool schemas, normalization, dispatch, and the shared response machinery.
//!
//! Every input rejects unknown fields, every output is a typed bounded
//! projection with a published schema, and every result carries the gateway
//! trust labels declared in the registry. Raw controller records never leave
//! this module.

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
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use unifi_api::{
    ApiError, ProtectAvailability, RecordFingerprint,
    capability::{self, FirewallGeneration},
    models::{
        ActiveClient, ClientDetail, DeviceStatistics, DeviceSummary, DpiAvailability,
        GuestAuthorization, GuestAuthorizationLimits, PageRequest, PortForward, PortForwardPatch,
        Voucher, VoucherCreate, VoucherDetails, WlanConf, WlanPatch,
    },
    protect::{
        ProtectBootstrap, ProtectCamera, ProtectCameraFeatureFlags, ProtectCameraSettingsPatch,
        ProtectEventContinuation, ProtectLedSettings, ProtectLocalCamera, ProtectLocalNvr,
        ProtectNvr, ProtectOsdSettings, ProtectPatrolState, ProtectPtzCommand,
        ProtectSmartDetectSettings, ProtectStreamQuality, ProtectStreamUrls,
        ProtectTalkbackSession,
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
mod system_log;
mod traffic;
use system_log::{event_row, log_window};
use traffic::{
    ClientCounterCoverage, CounterSemantics, CoverageStatus, TrafficCoverage, client_counters,
};
use unifi_api::system_log::{SystemLogQuery, SystemLogSeverity};

const ACTION_METADATA_KEY: &str = "io.modelcontextprotocol/action-metadata";
const TRUST_ANNOTATIONS_KEY: &str = "io.modelcontextprotocol/trust-annotations";

/// Hard ceiling on one structured result's serialized size. A result over
/// budget is a caller-recoverable error, never a truncated or unbounded dump.
/// A tool whose result carries credentials this call created is exempt, since
/// there is nothing for the caller to recover by narrowing.
pub(crate) const MAXIMUM_RESULT_BYTES: usize = 48 * 1024;

/// Search pagination bounds shared by the list tools.
const MAXIMUM_SEARCH_LIMIT: u16 = 200;
const DEFAULT_SEARCH_LIMIT: u16 = 50;
const MAXIMUM_SEARCH_OFFSET: u16 = 10_000;
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
const EVENT_SCAN_LIMIT: u32 = 200;
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
const MAXIMUM_EVENT_WINDOW_HOURS: u32 = 168;
const EVENT_FETCH_LIMIT: u32 = 1000;

/// Statistics bounds.
const DEFAULT_WAN_REPORT_HOURS: u32 = 24;
const MAXIMUM_WAN_REPORT_HOURS: u32 = 168;
const DEFAULT_TOP_APPLICATIONS: u16 = 10;
const MAXIMUM_TOP_APPLICATIONS: u16 = 50;

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
    offset: u16,
    /// Rows per page, 1-200.
    #[serde(default = "default_search_limit")]
    limit: u16,
    /// Concise identity-and-connection rows, or full association detail.
    #[serde(default)]
    detail: DetailLevel,
}

fn default_search_limit() -> u16 {
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
    offset: u16,
    /// Rows per page, 1-200.
    #[serde(default = "default_search_limit")]
    limit: u16,
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
    next_offset: Option<u16>,
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
    next_offset: Option<u16>,
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
    offset: u16,
    /// Rows per page, 1-200.
    #[serde(default = "default_search_limit")]
    limit: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CameraSelectorInput {
    /// Camera id, exact reported name, or display name from `cameras.search`.
    camera: String,
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
    smart_detect_settings: Option<CameraSmartDetectChanges>,
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
struct CameraSettingsOutput {
    camera_id: String,
    applied: bool,
    requested: CameraSettingsChanges,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<CameraSettingsState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<CameraSettingsState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<CameraSettingsState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
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
    /// Present for confirmed patrol actions when the camera reports its
    /// active slot. A preset move has no position readback in this API.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    /// Omitted when the camera does not report patrol state; null means idle.
    #[serde(skip_serializing_if = "Option::is_none")]
    active_patrol_slot: Option<PatrolSlotView>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
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
    verified: Option<bool>,
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
    /// Whether optional local data enriched this row.
    local_enrichment: String,
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
    next_offset: Option<u16>,
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
    /// Relative window ending now, 1-168 hours. Defaults to 24 on the first
    /// page. Cannot be combined with `start`, `end`, or `cursor`.
    last_hours: Option<u32>,
    /// Explicit window start in epoch milliseconds. Supply with `end` to read
    /// an older window; adjacent windows make all retained history reachable.
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
    /// Maximum upstream rows inspected for this page, 1-200. Filtered pages
    /// may contain fewer rows; continue until `nextCursor` is absent.
    #[serde(default = "default_search_limit")]
    limit: u16,
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
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ProtectEventsOutput {
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
    /// `sectionOffset`, and the recovery knob when the composite view
    /// exceeds the response budget or reports a truncated section.
    section: Option<FirewallSection>,
    /// Continuation offset into a paginated section scan (`zones` or
    /// `policies` only), taken from `nextSectionOffset`.
    section_offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworksReadInput {
    /// Restrict the response to one section when the whole configuration
    /// would exceed the response budget.
    section: Option<NetworksSection>,
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
    action: Option<String>,
    /// Evaluation order.
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<u32>,
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
    /// readable here; a classic console is refused rather than returned with
    /// this field set. Absent when a narrowing selected only sections that
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
}

/// Security modes this tool can set. Enterprise modes need RADIUS fields the
/// server does not model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WlanSecurity {
    Open,
    Wpapsk,
}

impl WlanSecurity {
    const fn wire(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Wpapsk => "wpapsk",
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
    /// `open` or `wpapsk`.
    security: Option<WlanSecurity>,
    /// Whether the ssid is hidden from scans.
    hidden: Option<bool>,
    /// New pre-shared key. Never echoed back.
    passphrase: Option<String>,
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
    /// Consequences worth knowing before confirming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// What `port_forwards.update` can change on one port forward. The match
/// itself — source, destination port, and internal host — is not settable
/// here: rewriting where a forward points is a different rule, and an
/// operator changing one states it in the controller.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortForwardChanges {
    /// New label for the rule.
    name: Option<String>,
    /// Whether the rule forwards traffic.
    enabled: Option<bool>,
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
    /// Consequences worth knowing before confirming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GuestsAuthorizeInput {
    /// MAC address of the client, as `clients.search` reports it. The
    /// controller's own client id is not accepted because no tool on this
    /// surface reports one: the client reads come from the legacy API, which
    /// addresses clients by hardware address.
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
    requested_limits: Option<GuestLimitsView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_before: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_after: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
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
/// Only the switch is settable: what a policy matches is a nested structure
/// whose parts validate together, and rewriting one is authoring a policy
/// rather than operating one.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FirewallPolicyChanges {
    /// Whether the policy is evaluated.
    enabled: Option<bool>,
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
    /// Whether the controller was written to.
    applied: bool,
    /// What would change. Preview only.
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<PlannedChange>>,
    /// What the read-back found per requested field. Applied only.
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<FieldOutcome>>,
    /// Controller properties that moved without being requested. On this
    /// surface the whole policy is resent unchanged, so nothing here was
    /// dropped by the request. It is either the controller normalizing the
    /// record or another editor writing the policy between the write and the
    /// read-back — this tool cannot tell those apart, and either way the
    /// change was not asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    unexpected_changes: Option<Vec<String>>,
    /// True when every requested field persisted and nothing else moved.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
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
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_absent: Option<bool>,
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
    /// How many to mint, 1-100.
    count: u32,
    /// Minutes each voucher is valid once redeemed, 1-10080 (seven days).
    time_limit_minutes: u32,
    /// Devices one voucher may authorize. The controller's default applies
    /// when absent.
    guest_limit: Option<u32>,
    /// Data allowance per voucher in megabytes. Unlimited when absent.
    data_limit_megabytes: Option<u64>,
    /// Mint them. Absent or false describes the batch without creating it.
    confirm: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VouchersSearchInput {
    /// Zero-based offset into the controller's voucher list.
    #[serde(default)]
    offset: u32,
    /// Vouchers per page, 1-100. Defaults to 25.
    #[serde(default = "default_voucher_limit")]
    limit: u16,
}

const fn default_voucher_limit() -> u16 {
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

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VoucherRevokeOutput {
    voucher_id: String,
    name: String,
    expired: bool,
    authorized_guest_count: u64,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
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
    guest_limit: Option<u32>,
    /// Data allowance per voucher in megabytes. Absent means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    data_limit_megabytes: Option<u64>,
}

/// One voucher returned by the creation request.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VoucherView {
    /// Absent when the controller returned no identity for this row. The
    /// code is still returned so an incomplete creation response is visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    code: String,
}

/// Checks on the creation response, separate from readback verification.
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent checks, each a distinct question about the batch; collapsing them would report that something failed without saying what"
)]
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VoucherChecks {
    /// Whether the controller returned as many vouchers as were asked for.
    count_matches: bool,
    /// Whether every voucher carries an id and a code.
    all_identified: bool,
    /// Whether every code differs from every other.
    all_distinct: bool,
    /// Whether every code is free of whitespace and within a plausible
    /// length. A code that fails this is unusable as typed.
    all_well_formed: bool,
    /// Character length of the codes, or the differing lengths when they are
    /// not uniform. Reported rather than judged: the controller decides the
    /// format, and this server should not refuse a batch for being unfamiliar.
    code_lengths: Vec<usize>,
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
    /// The vouchers, present only on a confirmed call. These are returned
    /// even when a check below failed, so the creation response is preserved.
    #[serde(skip_serializing_if = "Option::is_none")]
    vouchers: Option<Vec<VoucherView>>,
    /// What could be established about the batch. Applied only.
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<VoucherChecks>,
    /// Whether every check on the creation response passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    well_formed: Option<bool>,
    /// Whether every identified voucher was read back with the same code.
    /// False also covers missing ids, failed reads and mismatched codes.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
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
    /// Controller-reported state before the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    state_before: Option<String>,
    /// Controller-reported state afterwards, on an applied action. A restart
    /// takes a minute or more, so this usually still reads the prior state:
    /// it records what the controller showed, not that the action finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    state_after: Option<String>,
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
    /// Window in hours ending now, 1-168. Defaults to 24.
    last_hours: Option<u32>,
    /// Case-insensitive substring matched against the event key or
    /// category, such as `wan`, `roam`, or `security`.
    category: Option<String>,
    /// Restrict to one client MAC address.
    client: Option<String>,
    /// Zero-based offset into the time-sorted result.
    #[serde(default)]
    offset: u16,
    /// Rows per page, 1-200.
    #[serde(default = "default_search_limit")]
    limit: u16,
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
    next_offset: Option<u16>,
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
    /// Window in hours, 1-168; defaults to 24. Activity reports end at the
    /// latest completed UTC hour; wanHourly retains its window ending now.
    hours: Option<u32>,
    /// Number of top applications for the DPI report, 1-50. Defaults to 10.
    top: Option<u16>,
    /// Fixed interval boundaries in epoch milliseconds. Supply both, on UTC
    /// hour boundaries, instead of hours; at most seven days, ending in the past.
    start_ms: Option<u64>,
    end_ms: Option<u64>,
    /// Client-history page size, 1-200; defaults to 50.
    limit: Option<u16>,
    /// Client-history row offset. Reuse fixed timestamps across pages.
    offset: Option<u16>,
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
}

// ---------------------------------------------------------------------------
// Catalog projection
// ---------------------------------------------------------------------------

impl ToolSpec {
    pub(crate) fn catalog_tool(&self) -> Tool {
        match self.kind {
            ToolKind::NetworkOverview => tool::<EmptyInput, NetworkOverviewOutput>(self),
            ToolKind::ClientsSearch => tool::<ClientsSearchInput, ClientsSearchOutput>(self),
            ToolKind::ClientsContext => tool::<ClientSelectorInput, ClientContextOutput>(self),
            ToolKind::DevicesSearch => tool::<DevicesSearchInput, DevicesSearchOutput>(self),
            ToolKind::DevicesStatus => tool::<DeviceSelectorInput, DeviceStatusOutput>(self),
            ToolKind::FirewallRead => tool::<FirewallReadInput, FirewallReadOutput>(self),
            ToolKind::NetworksRead => tool::<NetworksReadInput, NetworksReadOutput>(self),
            ToolKind::CamerasSearch => tool::<CamerasSearchInput, CamerasSearchOutput>(self),
            ToolKind::CamerasStatus => tool::<CameraSelectorInput, CameraView>(self),
            ToolKind::CamerasSettingsRead => tool::<CameraSelectorInput, CameraSettingsState>(self),
            ToolKind::CamerasSettingsUpdate => {
                tool::<CameraSettingsUpdateInput, CameraSettingsOutput>(self)
            }
            ToolKind::CamerasSnapshot => tool::<CameraSnapshotInput, CameraSnapshotOutput>(self),
            ToolKind::CamerasPtzControl => tool::<CameraPtzInput, CameraPtzOutput>(self),
            ToolKind::CamerasStreamsList => {
                tool::<CameraStreamsListInput, CameraStreamsListOutput>(self)
            }
            ToolKind::CamerasStreamsUpdate => {
                tool::<CameraStreamsUpdateInput, CameraStreamsUpdateOutput>(self)
            }
            ToolKind::CamerasTalkbackStart => {
                tool::<CameraTalkbackInput, CameraTalkbackOutput>(self)
            }
            ToolKind::ProtectOverview => tool::<EmptyInput, ProtectOverviewOutput>(self),
            ToolKind::ProtectEvents => tool::<ProtectEventsInput, ProtectEventsOutput>(self),
            ToolKind::ProtectEventThumbnail => {
                tool::<ProtectEventThumbnailInput, ProtectEventThumbnailOutput>(self)
            }
            ToolKind::WifiDiagnose => tool::<WifiDiagnoseInput, WifiDiagnoseOutput>(self),
            ToolKind::EventsSearch => tool::<EventsSearchInput, EventsSearchOutput>(self),
            ToolKind::StatsQuery => tool::<StatsQueryInput, StatsQueryOutput>(self),
            ToolKind::WlansUpdate => tool::<WlansUpdateInput, WlansUpdateOutput>(self),
            ToolKind::ClientsControl => tool::<ClientsControlInput, ClientsControlOutput>(self),
            ToolKind::DevicesControl => tool::<DevicesControlInput, DevicesControlOutput>(self),
            ToolKind::GuestsStatus => tool::<GuestClientInput, GuestStatusOutput>(self),
            ToolKind::GuestsAuthorize => tool::<GuestsAuthorizeInput, GuestsAuthorizeOutput>(self),
            ToolKind::GuestsUnauthorize => {
                tool::<GuestsUnauthorizeInput, GuestsAuthorizeOutput>(self)
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
    /// Returns a caller error for unknown names, schema-violating arguments,
    /// or over-budget results, and a bounded internal error for upstream
    /// faults.
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
            ToolKind::FirewallRead => self.firewall_read(params).await,
            ToolKind::NetworksRead => self.networks_read(params).await,
            ToolKind::CamerasSearch => self.cameras_search(params).await,
            ToolKind::CamerasStatus => self.cameras_status(params).await,
            ToolKind::CamerasSettingsRead => self.cameras_settings_read(params).await,
            ToolKind::CamerasSettingsUpdate => self.cameras_settings_update(params).await,
            ToolKind::CamerasSnapshot => self.cameras_snapshot(params).await,
            ToolKind::CamerasPtzControl => self.cameras_ptz_control(params).await,
            ToolKind::CamerasStreamsList => self.cameras_streams_list(params).await,
            ToolKind::CamerasStreamsUpdate => self.cameras_streams_update(params).await,
            ToolKind::CamerasTalkbackStart => self.cameras_talkback_start(params).await,
            ToolKind::ProtectOverview => self.protect_overview(params).await,
            ToolKind::ProtectEvents => self.protect_events_search(params).await,
            ToolKind::ProtectEventThumbnail => self.protect_event_thumbnail(params).await,
            ToolKind::WifiDiagnose => self.wifi_diagnose(params).await,
            ToolKind::EventsSearch => self.events_search(params).await,
            ToolKind::StatsQuery => self.stats_query(params).await,
            ToolKind::WlansUpdate => self.wlans_update(params).await,
            ToolKind::ClientsControl => self.clients_control(params).await,
            ToolKind::DevicesControl => self.devices_control(params).await,
            ToolKind::GuestsStatus => self.guests_status(params).await,
            ToolKind::GuestsAuthorize => self.guests_authorize(params).await,
            ToolKind::GuestsUnauthorize => self.guests_unauthorize(params).await,
            ToolKind::PortForwardsUpdate => self.port_forwards_update(params).await,
            ToolKind::FirewallPoliciesUpdate => self.firewall_policies_update(params).await,
            ToolKind::FirewallPoliciesDelete => self.firewall_policies_delete(params).await,
            ToolKind::VouchersSearch => self.vouchers_search(params).await,
            ToolKind::VouchersStatus => self.vouchers_status(params).await,
            ToolKind::VouchersRevoke => self.vouchers_revoke(params).await,
            ToolKind::VouchersCreate => self.vouchers_create(params).await,
        };
        result.and_then(|result| finalize(result, spec.behavior))
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
        validate_page(input.offset, input.limit)?;
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
        let offset = usize::from(input.offset);
        let page: Vec<ActiveClient> = clients
            .into_iter()
            .skip(offset)
            .take(usize::from(input.limit))
            .collect();
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
        validate_page(input.offset, input.limit)?;
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
        let offset = usize::from(input.offset);
        let rows: Vec<DeviceRow> = devices
            .into_iter()
            .skip(offset)
            .take(usize::from(input.limit))
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
        let statistics = self
            .integration()
            .device_statistics(&site_id, &device.id)
            .await
            .ok()
            .map(|statistics| statistics_view(&statistics));

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
    async fn camera_inventory(
        &self,
        scope: CameraInventoryScope,
    ) -> Result<CameraInventory, McpError> {
        let protect = self.protect();
        let application_version = match protect.availability().await.map_err(api_error)? {
            ProtectAvailability::Available {
                application_version,
            } => application_version,
            ProtectAvailability::Unsupported => {
                return Err(McpError::invalid_params(
                    "this console does not expose the Protect integration API, so \
                     its cameras cannot be read; that is not the same as a console \
                     with no cameras",
                    None,
                ));
            }
        };
        let public = protect.cameras().await.map_err(api_error)?;
        reject_duplicate_camera_ids(&public)?;

        let local = if scope == CameraInventoryScope::Public {
            None
        } else {
            self.protect_local()
        };
        let mut local_camera_inventory = None;
        let local_bootstrap = if let Some(local) = local {
            match scope {
                CameraInventoryScope::Public => None,
                CameraInventoryScope::CameraNames => {
                    if let Ok(cameras) = local.protect_camera_inventory().await {
                        reject_duplicate_local_camera_ids(&cameras)?;
                        local_camera_inventory = Some(cameras);
                    }
                    None
                }
                CameraInventoryScope::Full => match local.protect_bootstrap().await {
                    Ok(bootstrap) => {
                        reject_duplicate_local_camera_ids(&bootstrap.cameras)?;
                        Some(bootstrap)
                    }
                    Err(_) => None,
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
        reject_conflicting_camera_identity(&public, &local_by_id)?;
        let public_nvr = if scope == CameraInventoryScope::Full
            && let Some(local) = local_bootstrap.as_ref().map(|value| &value.nvr)
        {
            let public_nvr = protect.nvr().await.map_err(api_error)?;
            reject_conflicting_recorder_identity(&public_nvr, local)?;
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
        })
    }

    /// Cameras by id, name, hardware model, class, or state, paged. Filters
    /// whose source is unavailable fail explicitly.
    async fn cameras_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CamerasSearchInput>(params)?;
        validate_page(input.offset, input.limit)?;
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
            return Err(unavailable_camera_filter("model"));
        }
        if let Some(wanted) = class_filter.as_deref() {
            let class_data_complete = class_filter_available(&inventory.cameras, wanted)?;
            if inventory.local_state != LocalEnrichmentState::Available || !class_data_complete {
                return Err(unavailable_camera_filter("class"));
            }
        }
        let capabilities = protect_capabilities(inventory.local_state);

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
        let rows: Vec<CameraView> = matched
            .into_iter()
            .skip(usize::from(offset))
            .take(usize::from(limit))
            .collect();
        let next_offset = next_offset(usize::from(offset), rows.len(), total);
        structured(CamerasSearchOutput {
            cameras: rows,
            total,
            next_offset,
            capabilities,
        })
    }

    /// One camera by id or exact name.
    async fn cameras_status(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<CameraSelectorInput>(params)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self.camera_inventory(CameraInventoryScope::Full).await?;
        structured(camera_by_selector(inventory, selector)?)
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
        let camera_id = camera_by_selector(inventory, selector)?.id;
        let camera = self.protect().camera(&camera_id).await.map_err(api_error)?;
        structured(CameraSettingsState::from(camera))
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
        let camera_id = camera_by_selector(inventory, selector)?.id;
        let mut output = CameraSettingsOutput {
            camera_id: camera_id.clone(),
            applied: false,
            requested: input.changes,
            before: None,
            response: None,
            after: None,
            verified: None,
            warnings: Vec::new(),
        };
        if !input.confirm {
            return structured(output);
        }
        let before = self.protect().camera(&camera_id).await.map_err(api_error)?;
        output.before = Some(before.into());
        let response = self
            .protect()
            .camera_settings_patch(&camera_id, &patch)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.response = Some(response.into());
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(CAMERA_SETTINGS_RESPONSE_RESERVE)
            .min(CAMERA_SETTINGS_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            None
        } else {
            tokio::time::timeout(budget, self.protect().camera(&camera_id))
                .await
                .ok()
        };
        match readback {
            Some(Ok(after)) if after.id == camera_id => {
                let after: CameraSettingsState = after.into();
                output.verified = Some(camera_settings_match(
                    &patch,
                    output.before.as_ref().expect("recorded pre-write state"),
                    &after,
                ));
                output.after = Some(after);
            }
            _ => {}
        }
        if output.verified != Some(true) {
            output.warnings.push(
                "the controller accepted the patch, but the requested settings were not verified"
                    .to_owned(),
            );
        }
        structured(output)
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
        let camera_id = camera_by_selector(inventory, selector)?.id;
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
        let input = parse::<CameraPtzInput>(params)?;
        let command = ptz_command(input.action, input.slot)?;
        let selector = camera_selector(&input.camera)?;
        let inventory = self
            .camera_inventory(CameraInventoryScope::CameraNames)
            .await?;
        let camera_id = camera_by_selector(inventory, selector)?.id;
        let mut output = CameraPtzOutput {
            camera_id: camera_id.clone(),
            action: input.action,
            slot: input.slot,
            applied: false,
            verified: None,
            active_patrol_slot: None,
            warnings: Vec::new(),
        };
        if !input.confirm {
            return structured(output);
        }

        self.protect()
            .camera_ptz(&camera_id, command)
            .await
            .map_err(api_error)?;
        output.applied = true;
        if matches!(command, ProtectPtzCommand::GotoPreset(_)) {
            output.warnings.push(
                "controller accepted preset movement; the integration API does not report camera position"
                    .to_owned(),
            );
            return structured(output);
        }
        match self.protect().camera(&camera_id).await {
            Ok(camera) if camera.id == camera_id => {
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
            Ok(_) | Err(_) => output.warnings.push(
                "controller accepted the PTZ action but camera readback was unavailable".to_owned(),
            ),
        }
        structured(output)
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
        let camera_id = camera_by_selector(inventory, selector)?.id;
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
        let camera_id = camera_by_selector(inventory, selector)?.id;
        let mut output = CameraStreamsUpdateOutput {
            camera_id: camera_id.clone(),
            action: input.action,
            qualities: input.qualities.clone(),
            applied: false,
            verified: None,
            streams: Vec::new(),
            warnings: Vec::new(),
        };
        if !input.confirm {
            return structured(output);
        }

        let qualities: Vec<ProtectStreamQuality> = input
            .qualities
            .iter()
            .copied()
            .map(ProtectStreamQuality::from)
            .collect();
        match input.action {
            CameraStreamsAction::Create => {
                let created = self
                    .protect()
                    .camera_streams_create(&camera_id, &qualities)
                    .await
                    .map_err(api_error)?;
                output.applied = true;
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
                self.protect()
                    .camera_streams_delete(&camera_id, &qualities)
                    .await
                    .map_err(api_error)?;
                output.applied = true;
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
            tokio::time::timeout(budget, self.protect().camera_streams(&camera_id))
                .await
                .ok()
        };
        match readback {
            Some(Ok(after)) => {
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
            None | Some(Err(_)) => output.warnings.push(
                "controller accepted the stream change but readback was unavailable".to_owned(),
            ),
        }
        structured(output)
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
        let camera_id = camera_by_selector(inventory, selector)?.id;
        let session = if input.confirm {
            Some(
                self.protect()
                    .camera_talkback_session(&camera_id)
                    .await
                    .map_err(api_error)?,
            )
        } else {
            None
        };
        structured(CameraTalkbackOutput {
            camera_id,
            applied: session.is_some(),
            session: session.map(talkback_session_view),
        })
    }

    /// One console snapshot: version, cameras grouped by their reported
    /// state, the recorder, and explicit source capabilities.
    async fn protect_overview(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        parse::<EmptyInput>(params)?;
        let inventory = self.camera_inventory(CameraInventoryScope::Full).await?;
        let CameraInventory {
            application_version,
            cameras,
            public_nvr,
            local_bootstrap,
            local_state,
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

        structured(ProtectOverviewOutput {
            console: self.protect_name().to_owned(),
            application_version,
            cameras_by_state: counts
                .into_iter()
                .map(|(state, count)| CameraCountRow { state, count })
                .collect(),
            camera_count: cameras.len(),
            not_recording: recording_summary_complete.then_some(idle),
            not_recording_truncated: (recording_summary_complete && idle_truncated).then_some(true),
            not_recording_count: recording_summary_complete.then_some(idle_count),
            recorders,
            capabilities: protect_capabilities(local_state),
        })
    }

    /// Historical detections through the Protect application route.
    async fn protect_events_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<ProtectEventsInput>(params)?;
        let limit = input.limit;
        validate_page(0, limit)?;

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
                return Err(McpError::invalid_params(
                    "camera name selection requires complete local Protect inventory; select by id",
                    None,
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
                u32::from(limit),
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
            capability::detect(self.integration(), &site_id)
                .await
                .map_err(api_error)?
                .firewall
                == FirewallGeneration::ZoneBased
        } else {
            false
        };
        // A classic console is refused rather than answered. This surface
        // reads the zone-based firewall only, so returning what a classic
        // console does have -- port forwards and traffic rules -- alongside an
        // empty firewall would report an open network to a caller auditing
        // one. The refusal names the generation and the sections that still
        // read identically on both, so a caller that wanted those can ask for
        // them directly.
        if needs_generation && !zone_based {
            return Err(McpError::invalid_params(
                "this console runs the classic firewall, which this server does \
                 not read; its zones and policies do not exist. Narrow to \
                 portForwards, trafficRules, or trafficRoutes, which read the \
                 same on either generation",
                None,
            ));
        }
        let (generation, generation_note) = if needs_generation {
            (
                Some("zoneBased"),
                Some(
                    "zone-based firewall console; a classic console is refused \
                     rather than reported as having no firewall",
                ),
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
            // Never advertise a continuation the validator would refuse;
            // say why instead, so the contract holds in both directions.
            let next = start + returned as u64;
            if next <= MAXIMUM_SECTION_OFFSET {
                scan.next_offset = Some(next);
            } else {
                scan.note = Some(format!(
                    "continuation stops at the sectionOffset bound of \
                     {MAXIMUM_SECTION_OFFSET}; narrow the query instead"
                ));
            }
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
                    action: policy.action,
                    index: policy.index,
                    ip_protocol_scope: policy.ip_protocol_scope,
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
            })
            .collect();
        structured(NetworksReadOutput {
            networks: network_views,
            wlans: wlan_views,
        })
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
            requested_limits: Some(GuestLimitsView {
                time_limit_minutes: input.time_limit_minutes,
                data_usage_limit_m_bytes: input.data_usage_limit_m_bytes,
                rx_rate_limit_kbps: input.rx_rate_limit_kbps,
                tx_rate_limit_kbps: input.tx_rate_limit_kbps,
            }),
            authorized_before: None,
            authorized_after: None,
            verified: None,
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
        let response = self
            .integration()
            .authorize_guest(&site_id, &client_id, limits)
            .await
            .map_err(api_error)?;
        output.applied = true;
        let grant = response
            .granted_authorization
            .expect("validated action response");
        output.granted_authorization = Some(grant.clone().into());
        output.revoked_authorization = response.revoked_authorization.map(Into::into);
        self.guest_readback(
            &site_id,
            &client_id,
            &client,
            started,
            &mut output,
            Some(&grant),
        )
        .await;
        structured(output)
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
            requested_limits: None,
            authorized_before: None,
            authorized_after: None,
            verified: None,
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
        let response = self
            .integration()
            .unauthorize_guest(&site_id, &client_id)
            .await
            .map_err(api_error)?;
        output.applied = true;
        output.revoked_authorization = response.revoked_authorization.map(Into::into);
        self.guest_readback(&site_id, &client_id, &client, started, &mut output, None)
            .await;
        structured(output)
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
        let detail = self
            .integration()
            .client_detail(site_id, client_id)
            .await
            .map_err(api_error)?;
        if detail.id != client_id
            || detail.mac_address.as_deref().map(normalize_mac).as_deref() != Some(mac)
        {
            return Err(McpError::internal_error(
                "controller returned a different connected client",
                None,
            ));
        }
        match detail.access.as_ref() {
            Some(access) if access.kind == "GUEST" && access.authorized.is_some() => Ok(detail),
            Some(access) if access.kind != "GUEST" => Err(McpError::invalid_params(
                "the selected client is not on guest access",
                None,
            )),
            _ => Err(McpError::internal_error(
                "controller did not report guest authorization state",
                None,
            )),
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
    ) {
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(GUEST_RESPONSE_RESERVE)
            .min(GUEST_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            None
        } else {
            tokio::time::timeout(budget, self.integration().client_detail(site_id, client_id))
                .await
                .ok()
        };
        match readback {
            Some(Ok(detail))
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
            }
            _ => {}
        }
        if output.verified != Some(true) {
            output.warnings.push(
                "the action response was returned, but the current guest state was not verified"
                    .to_owned(),
            );
        }
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
        let input = parse::<DevicesControlInput>(params)?;
        let port = validated_port(input.action, input.port)?;

        let site_id = self.site_id().await?;
        let detail = self
            .integration()
            .device_detail(&site_id, &input.device)
            .await
            .map_err(api_error)?;
        let warnings = device_control_warnings(input.action);

        if !input.confirm.unwrap_or(false) {
            return structured(DevicesControlOutput {
                device: input.device,
                name: detail.name,
                action: input.action.word(),
                port,
                applied: false,
                state_before: detail.state,
                state_after: None,
                warnings,
            });
        }

        match input.action {
            DeviceControl::Restart => self
                .integration()
                .restart_device(&site_id, &input.device)
                .await
                .map_err(api_error)?,
            DeviceControl::PortCycle => {
                let port = port
                    .ok_or_else(|| McpError::invalid_params("portCycle requires a port", None))?;
                self.integration()
                    .power_cycle_port(&site_id, &input.device, port)
                    .await
                    .map_err(api_error)?;
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
                self.legacy()
                    .locate_device(
                        self.legacy_site(),
                        mac,
                        input.action == DeviceControl::Locate,
                    )
                    .await
                    .map_err(api_error)?;
            }
        }

        let after = self
            .integration()
            .device_detail(&site_id, &input.device)
            .await
            .map_err(api_error)?;
        structured(DevicesControlOutput {
            device: input.device,
            name: after.name,
            action: input.action.word(),
            port,
            applied: true,
            state_before: detail.state,
            state_after: after.state,
            warnings,
        })
    }

    /// Block, unblock, or disconnect one client, previewing unless the
    /// caller confirms.
    async fn clients_control(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
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

        if !input.confirm.unwrap_or(false) {
            return structured(ClientsControlOutput {
                client,
                action: input.action.word(),
                applied: false,
                connected_before,
                connected_after: None,
                warnings,
            });
        }

        let legacy = self.legacy();
        let site = self.legacy_site();
        match input.action {
            ClientControl::Block => legacy.block_client(site, &client).await,
            ClientControl::Unblock => legacy.unblock_client(site, &client).await,
            ClientControl::Reconnect => legacy.kick_client(site, &client).await,
        }
        .map_err(api_error)?;

        structured(ClientsControlOutput {
            client: client.clone(),
            action: input.action.word(),
            applied: true,
            connected_before,
            connected_after: Some(self.client_is_connected(&client).await?),
            warnings,
        })
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
                changes: Some(mutation::plan(&requested, &before)),
                fields: None,
                unexpected_changes: None,
                verified: None,
                warnings,
            });
        }

        // The digest covers every property the controller stores, including
        // those this server does not model, so a write that clears one is
        // seen rather than certified clean.
        self.legacy()
            .update_wlan(self.legacy_site(), &input.wlan, &patch)
            .await
            .map_err(api_error)?;
        // One read per side, so the field statuses and the collateral report
        // describe the same moment rather than two moments a round trip apart.
        let (after_record, after_digest) = self.wlan_snapshot(&input.wlan).await?;
        let after = wlan_projection(&after_record);
        let fields = mutation::verify(&requested, &before, &after);
        let unexpected =
            unrequested_changes(&before_digest, &after_digest, &requested, WLAN_WIRE_NAMES);
        let verified = unexpected.is_empty()
            && fields
                .iter()
                .all(|outcome| outcome.status == mutation::FieldStatus::Persisted);
        structured(WlansUpdateOutput {
            wlan: input.wlan,
            ssid: after_record.name,
            applied: true,
            changes: None,
            fields: Some(fields),
            unexpected_changes: Some(unexpected),
            verified: Some(verified),
            warnings,
        })
    }

    /// Change one port forward, previewing unless the caller confirms.
    async fn port_forwards_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
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
        };

        let (current, before_digest) = self.port_forward_snapshot(&input.port_forward).await?;
        let before = port_forward_projection(&current);
        let warnings = port_forward_warnings(&requested, &before);
        if !input.confirm.unwrap_or(false) {
            return structured(PortForwardsUpdateOutput {
                forward: port_forward_view(current),
                applied: false,
                changes: Some(mutation::plan(&requested, &before)),
                fields: None,
                unexpected_changes: None,
                verified: None,
                warnings,
            });
        }

        self.legacy()
            .update_port_forward(self.legacy_site(), &input.port_forward, &patch)
            .await
            .map_err(api_error)?;
        // One read per side, so the field statuses and the collateral report
        // describe the same moment rather than two moments a round trip apart.
        let (after_record, after_digest) = self.port_forward_snapshot(&input.port_forward).await?;
        let after = port_forward_projection(&after_record);
        let fields = mutation::verify(&requested, &before, &after);
        let unexpected = unrequested_changes(
            &before_digest,
            &after_digest,
            &requested,
            PORT_FORWARD_WIRE_NAMES,
        );
        let verified = unexpected.is_empty()
            && fields
                .iter()
                .all(|outcome| outcome.status == mutation::FieldStatus::Persisted);
        structured(PortForwardsUpdateOutput {
            forward: port_forward_view(after_record),
            applied: true,
            changes: None,
            fields: Some(fields),
            unexpected_changes: Some(unexpected),
            verified: Some(verified),
            warnings,
        })
    }

    /// Refuse the policy surface on a console that runs the classic firewall,
    /// naming the generation rather than letting the endpoint's rejection
    /// arrive as an unexplained controller failure.
    async fn require_zone_based_firewall(&self) -> Result<(), McpError> {
        let site_id = self.site_id().await?;
        let capabilities = capability::detect(self.integration(), &site_id)
            .await
            .map_err(api_error)?;
        if capabilities.firewall == FirewallGeneration::Classic {
            return Err(McpError::invalid_params(
                "this console runs the classic firewall, which has no zone-based \
                 policies; this server reads and writes the zone-based firewall \
                 only",
                None,
            ));
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

    /// Enable or disable one zone-based firewall policy, previewing unless
    /// the caller confirms.
    async fn firewall_policies_update(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        reject_unknown_change_fields(params, FIREWALL_POLICY_CHANGE_FIELDS)?;
        let input = parse::<FirewallPoliciesUpdateInput>(params)?;
        let Some(wanted) = input.changes.enabled else {
            return Err(McpError::invalid_params(
                "changes names no field to change",
                None,
            ));
        };
        let requested: Map<String, Value> = [("enabled".to_owned(), Value::Bool(wanted))]
            .into_iter()
            .collect();

        // A classic console has no policies at all, so reading one there would
        // surface as an unexplained controller failure rather than as the
        // console running a different firewall generation.
        self.require_zone_based_firewall().await?;

        let site_id = self.site_id().await?;
        // `raw` is what goes back to the controller, property by property, as
        // the bytes it sent. `record` is the same reading parsed for the few
        // properties this server reads; it is never written.
        let (raw, before_digest) = self
            .integration()
            .firewall_policy_snapshot(&site_id, &input.policy)
            .await
            .map_err(api_error)?;
        let record = parsed_record(&raw);
        let before = policy_projection(&record);
        let warnings = firewall_policy_warnings(wanted, &record);
        if !input.confirm.unwrap_or(false) {
            return structured(FirewallPoliciesUpdateOutput {
                policy: policy_view_from_record(&input.policy, &record),
                applied: false,
                changes: Some(mutation::plan(&requested, &before)),
                fields: None,
                unexpected_changes: None,
                verified: None,
                warnings,
            });
        }

        // A resend that cannot change the switch is pure downside here: it
        // does nothing, and it can overwrite an edit made since the read. The
        // other writes send a partial patch, where a field already at its
        // value costs nothing; this one sends the whole policy, so it is
        // skipped instead.
        if record.get("enabled").and_then(Value::as_bool) == Some(wanted) {
            return structured(FirewallPoliciesUpdateOutput {
                policy: policy_view_from_record(&input.policy, &record),
                applied: false,
                changes: Some(Vec::new()),
                fields: None,
                unexpected_changes: None,
                verified: None,
                warnings: vec![
                    "the policy already holds that value, so nothing was sent".to_owned(),
                ],
            });
        }

        // The whole policy goes back because the upstream interface offers no
        // partial update that can flip this switch. Every property arrives
        // from the read and leaves untouched except the one field named here,
        // so a property this server does not model cannot be dropped by the
        // write — which on a firewall policy would silently change what the
        // network permits.
        let mut sent = raw;
        sent.insert(
            "enabled".to_owned(),
            serde_json::value::RawValue::from_string(wanted.to_string())
                .expect("a JSON boolean literal is valid JSON"),
        );
        self.integration()
            .replace_firewall_policy(&site_id, &input.policy, &sent)
            .await
            .map_err(api_error)?;

        let (after_raw, after_digest) = self
            .integration()
            .firewall_policy_snapshot(&site_id, &input.policy)
            .await
            .map_err(api_error)?;
        let after_record = parsed_record(&after_raw);
        let after = policy_projection(&after_record);
        let fields = mutation::verify(&requested, &before, &after);
        let unexpected =
            unrequested_changes(&before_digest, &after_digest, &requested, POLICY_WIRE_NAMES);
        let verified = unexpected.is_empty()
            && fields
                .iter()
                .all(|outcome| outcome.status == mutation::FieldStatus::Persisted);
        structured(FirewallPoliciesUpdateOutput {
            policy: policy_view_from_record(&input.policy, &after_record),
            applied: true,
            changes: None,
            fields: Some(fields),
            unexpected_changes: Some(unexpected),
            verified: Some(verified),
            warnings,
        })
    }

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
        let (raw, _) = self
            .integration()
            .firewall_policy_snapshot(&site_id, &input.policy)
            .await
            .map_err(api_error)?;
        let record = parsed_record(&raw);
        if record.get("id").and_then(Value::as_str) != Some(input.policy.as_str()) {
            return Err(McpError::internal_error(
                "controller returned a different firewall policy",
                None,
            ));
        }
        let mut output = FirewallPoliciesDeleteOutput {
            policy: bounded_policy_view(policy_view_from_record(&input.policy, &record)),
            preview: policy_preview_coverage(&record),
            applied: false,
            verified_absent: None,
            warnings: vec![
                "deleting this policy changes how later firewall policies handle matching traffic"
                    .to_owned(),
            ],
        };
        if !output.preview.complete {
            output.warnings.push(
                "this bounded preview omits policy fields, so its match description is incomplete"
                    .to_owned(),
            );
        }
        if !input.confirm {
            return structured(output);
        }
        // Check the confirmed result shape before the irreversible call.
        let mut final_shape = output.clone();
        final_shape.applied = true;
        final_shape.verified_absent = Some(false);
        final_shape.warnings.push(
            "the delete request was accepted, but policy absence was not verified".to_owned(),
        );
        finalize(structured(final_shape)?, ToolBehavior::write(false))?;
        self.integration()
            .delete_firewall_policy(&site_id, &input.policy)
            .await
            .map_err(api_error)?;
        output.applied = true;
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(FIREWALL_DELETE_RESPONSE_RESERVE)
            .min(FIREWALL_DELETE_READBACK_BUDGET);
        let readback = if budget.is_zero() {
            None
        } else {
            tokio::time::timeout(
                budget,
                self.integration()
                    .firewall_policy_snapshot(&site_id, &input.policy),
            )
            .await
            .ok()
        };
        output.verified_absent = match readback {
            Some(Err(ApiError::Status { status: 404, .. })) => Some(true),
            Some(Ok(_)) => Some(false),
            _ => None,
        };
        if output.verified_absent != Some(true) {
            output.warnings.push(
                "the delete request was accepted, but policy absence was not verified".to_owned(),
            );
        }
        structured(output)
    }

    async fn vouchers_search(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<VouchersSearchInput>(params)?;
        if input.offset > i32::MAX as u32 || !(1..=100).contains(&input.limit) {
            return Err(McpError::invalid_params(
                "offset must fit a nonnegative 32-bit integer and limit must be 1-100",
                None,
            ));
        }
        let site_id = self.site_id().await?;
        let page = self
            .integration()
            .vouchers(
                &site_id,
                PageRequest {
                    offset: u64::from(input.offset),
                    limit: u32::from(input.limit),
                },
            )
            .await
            .map_err(api_error)?;
        if page.offset != u64::from(input.offset)
            || page.count != page.data.len() as u64
            || page.data.len() > usize::from(input.limit)
            || page.offset.saturating_add(page.count) > page.total_count
        {
            return Err(McpError::internal_error(
                "controller returned an inconsistent voucher page",
                None,
            ));
        }
        let next = page
            .offset
            .checked_add(page.count)
            .filter(|next| *next < page.total_count);
        if next.is_some() && page.data.is_empty() {
            return Err(McpError::internal_error(
                "controller returned an empty incomplete voucher page",
                None,
            ));
        }
        structured(VouchersSearchOutput {
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
        let voucher = self
            .integration()
            .voucher(&site_id, id)
            .await
            .map_err(api_error)?;
        if voucher.id != id {
            return Err(McpError::internal_error(
                "controller returned a different voucher id",
                None,
            ));
        }
        structured(VoucherReadView::from(voucher))
    }

    async fn vouchers_revoke(
        &self,
        params: &CallToolRequestParams,
    ) -> Result<CallToolResult, McpError> {
        let input = parse::<VoucherRevokeInput>(params)?;
        let id = voucher_id(&input.voucher_id)?;
        let site_id = self.site_id().await?;
        let voucher = self
            .integration()
            .voucher(&site_id, id)
            .await
            .map_err(api_error)?;
        if voucher.id != id {
            return Err(McpError::internal_error(
                "controller returned a different voucher id",
                None,
            ));
        }
        let mut result = VoucherRevokeOutput {
            voucher_id: voucher.id,
            name: voucher.name,
            expired: voucher.expired,
            authorized_guest_count: voucher.authorized_guest_count,
            applied: false,
            verified: None,
            warnings: Vec::new(),
        };
        if !input.confirm {
            return structured(result);
        }
        self.integration()
            .delete_voucher(&site_id, id)
            .await
            .map_err(api_error)?;
        result.applied = true;
        let persisted = match self.integration().voucher(&site_id, id).await {
            Err(ApiError::Status { status: 404, .. }) => false,
            Ok(_) => true,
            Err(_) => {
                result.warnings.push(
                    "controller accepted deletion but readback failed; inspect vouchers.status by id"
                        .to_owned(),
                );
                return structured(result);
            }
        };
        result.verified = Some(!persisted);
        if persisted {
            result
                .warnings
                .push("controller acknowledged deletion but the voucher still exists".to_owned());
        }
        structured(result)
    }

    async fn verify_created_vouchers(
        &self,
        site_id: &str,
        requested: u32,
        vouchers: &[Voucher],
    ) -> bool {
        let mut verified = usize::try_from(requested).is_ok_and(|want| want == vouchers.len());
        let mut ids = HashSet::new();
        for voucher in vouchers {
            let (Some(id), Some(code)) = (voucher.id.as_deref(), voucher.code.as_deref()) else {
                verified = false;
                continue;
            };
            if !ids.insert(id) {
                verified = false;
            }
            match self.integration().voucher(site_id, id).await {
                Ok(persisted) if persisted.id == id && persisted.code == code => {}
                Ok(_) | Err(_) => verified = false,
            }
        }
        verified
    }

    async fn verify_created_vouchers_before_deadline(
        &self,
        site_id: &str,
        requested: u32,
        vouchers: &[Voucher],
        started: tokio::time::Instant,
    ) -> bool {
        // A slow detail endpoint must not consume the outer tool deadline
        // after minting. Reserve time to shape and return the creation result.
        let budget = self
            .request_timeout()
            .saturating_sub(started.elapsed())
            .saturating_sub(VOUCHER_RESPONSE_RESERVE)
            .min(VOUCHER_READBACK_BUDGET);
        if budget.is_zero() {
            return false;
        }
        tokio::time::timeout(
            budget,
            self.verify_created_vouchers(site_id, requested, vouchers),
        )
        .await
        .unwrap_or(false)
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
        let mut warnings = vec![
            "each voucher code is a guest network credential; codes can also be read through vouchers.search and vouchers.status"
                .to_owned(),
        ];
        if !input.confirm.unwrap_or(false) {
            return structured(VouchersCreateOutput {
                applied: false,
                batch,
                requested: input.count,
                vouchers: None,
                checks: None,
                well_formed: None,
                verified: None,
                warnings,
            });
        }

        let site_id = self.site_id().await?;
        let created = self
            .integration()
            .create_vouchers(
                &site_id,
                &VoucherCreate {
                    name: batch.name.clone(),
                    count: input.count,
                    time_limit_minutes: input.time_limit_minutes,
                    authorized_guest_limit: input.guest_limit,
                    data_usage_limit_m_bytes: input.data_limit_megabytes,
                },
            )
            .await
            .map_err(api_error)?;

        let verified = self
            .verify_created_vouchers_before_deadline(
                &site_id,
                input.count,
                &created.vouchers,
                started,
            )
            .await;
        if !verified {
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
                code: voucher.code.unwrap_or_default(),
            })
            .collect();
        // The checks describe the ids and codes returned by the controller.
        let checks = voucher_checks(input.count, &vouchers);
        let well_formed = checks.count_matches
            && checks.all_identified
            && checks.all_distinct
            && checks.all_well_formed;
        structured(VouchersCreateOutput {
            applied: true,
            batch,
            requested: input.count,
            vouchers: Some(vouchers),
            checks: Some(checks),
            well_formed: Some(well_formed),
            verified: Some(verified),
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
        validate_page(input.offset, input.limit)?;
        let category = validate_filter(input.category.as_deref())?;
        let client = validate_filter(input.client.as_deref())?;
        let window_hours = input.last_hours.unwrap_or(DEFAULT_EVENT_WINDOW_HOURS);
        if !(1..=MAXIMUM_EVENT_WINDOW_HOURS).contains(&window_hours) {
            return Err(McpError::invalid_params(
                format!("lastHours must be between 1 and {MAXIMUM_EVENT_WINDOW_HOURS}"),
                None,
            ));
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
        let offset = usize::from(input.offset);
        let page: Vec<EventRow> = rows
            .into_iter()
            .skip(offset)
            .take(usize::from(input.limit))
            .collect();
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
        structured(StatsQueryOutput {
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
        })
    }

    async fn dpi_stats(&self, top: u16) -> Result<CallToolResult, McpError> {
        let report = self
            .legacy()
            .dpi_by_application(self.legacy_site())
            .await
            .map_err(api_error)?;
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
            return structured(StatsQueryOutput {
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
        applications.truncate(usize::from(top));
        structured(StatsQueryOutput {
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
            offset += fetched;
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

fn validate_page(offset: u16, limit: u16) -> Result<(), McpError> {
    if !(1..=MAXIMUM_SEARCH_LIMIT).contains(&limit) {
        return Err(McpError::invalid_params(
            format!("limit must be between 1 and {MAXIMUM_SEARCH_LIMIT}"),
            None,
        ));
    }
    if offset > MAXIMUM_SEARCH_OFFSET {
        return Err(McpError::invalid_params(
            format!("offset must not exceed {MAXIMUM_SEARCH_OFFSET}"),
            None,
        ));
    }
    Ok(())
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
            if !(1..=MAXIMUM_EVENT_WINDOW_HOURS).contains(&hours) {
                return Err(McpError::invalid_params(
                    format!("lastHours must be between 1 and {MAXIMUM_EVENT_WINDOW_HOURS}"),
                    None,
                ));
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
    let maximum = u64::from(MAXIMUM_EVENT_WINDOW_HOURS) * 3_600_000;
    if end - start > maximum {
        return Err(McpError::invalid_params(
            format!(
                "Protect event windows may span at most {MAXIMUM_EVENT_WINDOW_HOURS} hours; use adjacent windows for older history"
            ),
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

fn camera_by_selector(inventory: CameraInventory, selector: &str) -> Result<CameraView, McpError> {
    let CameraInventory {
        cameras,
        local_state,
        ..
    } = inventory;
    // A camera id is unique; an apparent name match is unsafe when local
    // inventory is incomplete because another camera's name may be missing.
    if let Some(camera) = cameras.iter().find(|camera| camera.id == selector) {
        return Ok(camera.clone());
    }
    if matches!(
        local_state,
        LocalEnrichmentState::Partial | LocalEnrichmentState::Unavailable
    ) {
        return Err(McpError::invalid_params(
            "camera name selection requires complete local Protect inventory; select by id",
            None,
        ));
    }
    let normalized_selector = selector.to_lowercase();
    let mut matches = cameras.into_iter().filter(|camera| {
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
    let requested = serde_json::to_value(patch).expect("typed patch serializes");
    let before = serde_json::to_value(before).expect("typed camera settings serialize");
    let after = serde_json::to_value(after).expect("typed camera settings serialize");
    camera_settings_values_match(Some(&requested), &before, &after)
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

/// The next page's offset, emitted only when that page is actually
/// requestable within the accepted offset bound; otherwise the caller sees
/// no continuation and narrows the query instead of chasing an unreachable
/// page.
fn next_offset(offset: usize, returned: usize, total: usize) -> Option<u16> {
    let consumed = offset.saturating_add(returned);
    if consumed < total && consumed <= usize::from(MAXIMUM_SEARCH_OFFSET) {
        u16::try_from(consumed).ok()
    } else {
        None
    }
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

/// Per-section rows gathered per call, sized so a ceiling-limited section
/// still fits the response budget and can actually return with its
/// truncation flag. A truncated section continues from its
/// `nextSectionOffset`, so the ceiling bounds one response, not the
/// reachable data.
const ZONE_SCAN_CEILING: u64 = 400;
const POLICY_SCAN_CEILING: u64 = 200;
/// Ceiling on a caller-supplied section continuation offset.
const MAXIMUM_SECTION_OFFSET: u64 = 100_000;

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
        offset += fetched;
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

/// A continuation offset applies only to the paginated sections and is
/// bounded; anything else is a caller error rather than a silent no-op.
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
    if start > MAXIMUM_SECTION_OFFSET {
        return Err(McpError::invalid_params(
            format!("sectionOffset must not exceed {MAXIMUM_SECTION_OFFSET}"),
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
const WLAN_CHANGE_FIELDS: &[&str] = &["ssid", "enabled", "security", "hidden", "passphrase"];

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
const FIREWALL_POLICY_CHANGE_FIELDS: &[&str] = &["enabled"];

/// A policy stores its switch under the name the read surface uses.
const POLICY_WIRE_NAMES: &[(&str, &str)] = &[("enabled", "enabled")];

/// The settable surface of a zone-based policy, read from the record the
/// controller returned rather than from a model, because the write resends
/// that record verbatim.
fn policy_projection(record: &Map<String, Value>) -> Value {
    serde_json::json!({
        "enabled": record.get("enabled").and_then(Value::as_bool),
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

/// The policy as `firewall.read` reports it, built from the same record the
/// write round-trips so both surfaces describe one reading.
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
        action: text("action"),
        index: record
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        ip_protocol_scope: text("ipProtocolScope"),
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
                        .as_u64()
                        .is_none_or(|index| u32::try_from(index).is_err()),
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
        .and_then(Value::as_str)
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

/// Most vouchers one call will mint. The limit bounds request size and
/// readback work; callers can create additional batches when needed.
const VOUCHER_BATCH_CEILING: u32 = 100;
/// Reserve most of the tool deadline for returning a successful creation
/// response, even when the detail endpoint stalls during verification.
const VOUCHER_READBACK_BUDGET: Duration = Duration::from_secs(5);
/// Leave time for output shaping and transport serialization after readback.
const VOUCHER_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Bound a post-write stream check so created handles remain returnable.
const STREAM_READBACK_BUDGET: Duration = Duration::from_secs(5);
/// Leave time to serialize stream handles after the optional readback.
const STREAM_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// A guest action response must remain returnable after a slow detail read.
const GUEST_READBACK_BUDGET: Duration = Duration::from_secs(5);
const GUEST_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Bound the optional camera read so an accepted patch remains reportable.
const CAMERA_SETTINGS_READBACK_BUDGET: Duration = Duration::from_secs(5);
const CAMERA_SETTINGS_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Leave time to return a successful firewall deletion after checking absence.
const FIREWALL_DELETE_READBACK_BUDGET: Duration = Duration::from_secs(5);
const FIREWALL_DELETE_RESPONSE_RESERVE: Duration = Duration::from_millis(500);
/// Longest validity one voucher may carry, in minutes: seven days.
const VOUCHER_MINUTES_CEILING: u32 = 7 * 24 * 60;
/// Widest code this server will call well formed. Generous on purpose — the
/// controller decides the format, and refusing an unfamiliar one would
/// condemn vouchers that already exist.
const VOUCHER_CODE_MAX: usize = 64;

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

/// The batch a request describes, or the reason it cannot be minted.
///
/// Everything decidable from the request alone is decided here, before any
/// controller call. A batch refused after minting is credentials nobody can
/// reach, which is the one outcome worse than not minting at all.
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
    // Bounded like every other caller-supplied string here, and for a sharper
    // reason: this result is exempt from the response budget so a minted code
    // can never be refused, and an unbounded label would turn that exemption
    // into an amplifier for text the caller chose.
    let name = input.name.trim();
    if name.is_empty() || name.len() > MAXIMUM_QUERY_LENGTH {
        return Err(McpError::invalid_params(
            format!("name must be 1-{MAXIMUM_QUERY_LENGTH} UTF-8 bytes once trimmed"),
            None,
        ));
    }
    Ok(VoucherBatch {
        name: name.to_owned(),
        count: input.count,
        time_limit_minutes: input.time_limit_minutes,
        guest_limit: input.guest_limit,
        data_limit_megabytes: input.data_limit_megabytes,
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
        .map(|voucher| voucher.code.chars().count())
        .collect();
    lengths.sort_unstable();
    lengths.dedup();
    let mut codes: Vec<&str> = vouchers.iter().map(|v| v.code.as_str()).collect();
    codes.sort_unstable();
    let distinct = codes.len();
    codes.dedup();
    VoucherChecks {
        count_matches: usize::try_from(requested).is_ok_and(|want| want == vouchers.len()),
        all_identified: vouchers.iter().all(|voucher| {
            voucher.id.as_ref().is_some_and(|id| !id.is_empty()) && !voucher.code.is_empty()
        }),
        all_distinct: codes.len() == distinct,
        all_well_formed: vouchers.iter().all(|voucher| {
            let code = voucher.code.chars().count();
            code > 0 && code <= VOUCHER_CODE_MAX && !voucher.code.chars().any(char::is_whitespace)
        }),
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
        local_enrichment: local_enrichment_word(local, local_state).to_owned(),
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

fn protect_capabilities(state: LocalEnrichmentState) -> ProtectCapabilitiesView {
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
        local_unavailable_reason: local_unavailable_reason.map(str::to_owned),
    }
}

fn reject_duplicate_camera_ids(
    cameras: &[unifi_api::protect::ProtectCamera],
) -> Result<(), McpError> {
    let mut seen = std::collections::BTreeSet::new();
    if cameras.iter().any(|camera| !seen.insert(&camera.id)) {
        return Err(McpError::internal_error(
            "Protect public camera inventory contains duplicate ids",
            None,
        ));
    }
    Ok(())
}

fn reject_duplicate_local_camera_ids(cameras: &[ProtectLocalCamera]) -> Result<(), McpError> {
    let mut seen = std::collections::BTreeSet::new();
    if cameras.iter().any(|camera| !seen.insert(&camera.id)) {
        return Err(McpError::internal_error(
            "Protect local camera inventory contains duplicate ids",
            None,
        ));
    }
    Ok(())
}

fn reject_conflicting_camera_identity(
    public: &[ProtectCamera],
    local: &BTreeMap<&str, &ProtectLocalCamera>,
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
        return Err(conflicting_camera_identity_error());
    }
    Ok(())
}

fn conflicting_camera_identity_error() -> McpError {
    McpError::internal_error("Protect public and local camera identities conflict", None)
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

fn reject_conflicting_recorder_identity(
    public: &ProtectNvr,
    local: &ProtectLocalNvr,
) -> Result<(), McpError> {
    if local.id != public.id
        || conflicting_optional_identity(public.guid.as_deref(), local.guid.as_deref())
        || conflicting_optional_identity(public.mac.as_deref(), local.mac.as_deref())
    {
        return Err(McpError::internal_error(
            "Protect public and local recorder identities conflict",
            None,
        ));
    }
    Ok(())
}

/// Every field `port_forwards.update` accepts.
const PORT_FORWARD_CHANGE_FIELDS: &[&str] = &["name", "enabled"];

/// The port forward as the write surface names it. Only the settable fields
/// appear: the match itself is reported through the rule view, and a change
/// to it shows up as a collateral change.
fn port_forward_projection(forward: &PortForward) -> Value {
    serde_json::json!({
        "name": forward.name,
        "enabled": forward.enabled,
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
    requested
}

/// Consequences an operator should see before confirming. Both directions
/// matter: one stops reaching a service, the other opens a path to it.
fn port_forward_warnings(requested: &Map<String, Value>, current: &Value) -> Vec<String> {
    let mut warnings = Vec::new();
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
    if changing("ssid") || changing("passphrase") || changing("security") {
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
];

/// A port forward stores both settable fields under the names the read
/// surface uses.
const PORT_FORWARD_WIRE_NAMES: &[(&str, &str)] = &[("name", "name"), ("enabled", "enabled")];

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
    serde_json::from_value(value)
        .map_err(|_| McpError::invalid_params("arguments do not match the advertised schema", None))
}

pub(crate) fn structured<T: Serialize>(output: T) -> Result<CallToolResult, McpError> {
    let value = serde_json::to_value(output)
        .map_err(|_| McpError::internal_error("failed to serialize bounded result", None))?;
    Ok(CallToolResult::structured(value))
}

/// Enforce the response budget on the values returned by the tool, then
/// attach the gateway's sensitivity and trust labels.
fn finalize(result: CallToolResult, behavior: ToolBehavior) -> Result<CallToolResult, McpError> {
    let Some(value) = result.structured_content else {
        return Ok(trust_annotated(result, behavior));
    };
    if value.to_string().len() > MAXIMUM_RESULT_BYTES {
        return Err(McpError::invalid_params(
            "result exceeds the response budget; narrow the query or lower the limit",
            None,
        ));
    }
    let mut finalized = CallToolResult::structured(value);
    finalized.content.extend(
        result
            .content
            .into_iter()
            .filter(|content| matches!(content, ContentBlock::Image(_))),
    );
    Ok(trust_annotated(finalized, behavior))
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

/// Preserve the recovery instruction for an unsplittable event boundary.
fn protect_events_api_error(error: ApiError) -> McpError {
    match error {
        ApiError::Config(message)
            if message
                == "Protect event page boundary exceeds the requested limit; retry with a higher limit" =>
        {
            McpError::invalid_params(
                "Protect event page boundary exceeds the requested limit; retry with a higher limit",
                None,
            )
        }
        other => api_error(other),
    }
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn api_error(error: ApiError) -> McpError {
    McpError::internal_error(error.to_string(), None)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rmcp::model::CallToolRequestParams;
    use serde_json::{Map, Value, json};

    use super::{
        BOOLEAN_SCHEMA_KEYWORDS, ClientsSearchInput, FIREWALL_POLICY_CHANGE_FIELDS,
        FirewallPolicyChanges, JSON_SCHEMA_TYPES, MAXIMUM_RESULT_BYTES, POLICY_WIRE_NAMES,
        PORT_FORWARD_CHANGE_FIELDS, PORT_FORWARD_WIRE_NAMES, PolicyView, PortForwardChanges,
        PortForwardView, WLAN_CHANGE_FIELDS, WLAN_WIRE_NAMES, WlanChanges, WlanView, finalize,
        normalize_portable_schema, parse, schema_object, structured, trust_annotated,
    };
    use crate::mutation::FieldOutcome;
    use crate::registry::{TOOL_REGISTRY, ToolBehavior};

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
    fn over_budget_results_return_the_recovery_error_not_a_dump() {
        // The budget applies to the values returned by the tool.
        let oversized = structured(vec!["x".repeat(1024); MAXIMUM_RESULT_BYTES / 1024 + 2])
            .expect("built result");
        let error = finalize(oversized, ToolBehavior::read()).expect_err("over budget");
        assert!(error.message.contains("narrow the query"));
        let small = structured(vec!["small"]).expect("built result");
        assert!(finalize(small, ToolBehavior::read()).is_ok());
    }

    #[test]
    fn pagination_never_advertises_an_unreachable_page() {
        assert_eq!(super::next_offset(0, 50, 100), Some(50));
        assert_eq!(super::next_offset(0, 100, 100), None);
        // More rows match, but the continuation would exceed the accepted
        // offset bound, so no next page is advertised.
        assert_eq!(super::next_offset(10_000, 50, 20_000), None);
    }

    #[test]
    fn an_omitted_connection_type_is_never_fabricated() {
        assert_eq!(super::connection_word(None), "unknown");
        assert_eq!(super::connection_word(Some(true)), "wired");
        assert_eq!(super::connection_word(Some(false)), "wireless");
    }

    #[test]
    fn finalizer_preserves_controller_values_and_property_names() {
        let supplied = serde_json::json!({
            "nested": {"controller-key": "controller-value"},
            "code": "controller-code",
        });
        let result = structured(supplied.clone()).expect("built result");
        let returned = finalize(result, ToolBehavior::read()).expect("returned result");
        assert_eq!(returned.structured_content, Some(supplied));
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
        // Disconnecting twice disconnects twice; no secret is involved.
        ("clients.control", false, false, false),
        // Each restart restarts; no secret is involved.
        ("devices.control", false, false, false),
        // Reauthorization replaces the grant and resets traffic counters.
        ("guests.authorize", false, false, true),
        // Revocation disconnects the client and returns the revoked grant.
        ("guests.unauthorize", false, false, true),
        // Setting the same rule state twice leaves the same state; no secret
        // is involved, and the result names the host a rule exposes.
        ("port_forwards.update", true, false, true),
        // Same, and the result names the zones and ports a policy governs.
        ("firewall.policies.update", true, false, true),
        // Repeating deletion leaves the policy absent.
        ("firewall.policies.delete", true, false, true),
        // Repeating a movement or patrol command may trigger another action.
        ("cameras.ptz.control", false, false, true),
        // Applying the same named settings leaves the same configuration.
        ("cameras.settings.update", true, false, true),
        // Repeating a stream creation or removal, or opening another audio
        // session, can have another upstream effect.
        ("cameras.streams.update", false, false, true),
        ("cameras.talkback.start", false, false, true),
        // Each call mints another batch; the result carries the credentials.
        ("vouchers.create", false, false, true),
        // Revoking the same voucher again leaves it absent.
        ("vouchers.revoke", true, false, true),
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
