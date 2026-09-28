//! The executable tool registry: the single source of `tools/list`, MCP
//! behavior annotations, gateway classification data, and dispatch. A tool
//! exists only by being registered here with a [`ToolKind`] variant, and the
//! dispatcher matches that enum exhaustively, so the catalog, annotations,
//! manifest, and handlers can never disagree.

/// The one console family served by a process.
///
/// Network and Protect are separate trust and deployment boundaries. A
/// process advertises exactly one surface, never a union assembled from
/// whichever credentials happened to be present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSurface {
    Network,
    Protect,
}

impl ToolSurface {
    #[must_use]
    pub const fn server_name(self) -> &'static str {
        match self {
            Self::Network => "unifi",
            Self::Protect => "unifi-protect",
        }
    }
}

/// Dispatch identity for every registered tool. Adding a variant without a
/// handler arm or a registry entry fails compilation or the registry test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    NetworkOverview,
    ClientsSearch,
    ClientsContext,
    DevicesSearch,
    DevicesStatus,
    FirewallRead,
    NetworksRead,
    RadiusProfilesList,
    WifiBroadcastsList,
    WifiBroadcastsStatus,
    CamerasSearch,
    CamerasStatus,
    ProtectDevicesList,
    ProtectDevicesStatus,
    ProtectUsersList,
    ProtectUsersStatus,
    CamerasPosTransaction,
    ProtectViewersList,
    ProtectViewersStatus,
    ProtectViewersSettingsUpdate,
    ProtectLiveviewsList,
    ProtectLiveviewsStatus,
    ProtectLiveviewsConfigure,
    CamerasSettingsRead,
    CamerasSettingsUpdate,
    CamerasSnapshot,
    CamerasPtzControl,
    CamerasStreamsList,
    CamerasStreamsUpdate,
    CamerasTalkbackStart,
    ProtectOverview,
    ProtectEvents,
    ProtectEventThumbnail,
    WifiDiagnose,
    EventsSearch,
    StatsQuery,
    WlansUpdate,
    ClientsControl,
    DevicesControl,
    GuestsStatus,
    GuestsAuthorize,
    GuestsUnauthorize,
    PortForwardsUpdate,
    FirewallPoliciesUpdate,
    FirewallPoliciesDelete,
    VouchersSearch,
    VouchersStatus,
    VouchersRevoke,
    VouchersCreate,
}

impl ToolKind {
    /// Explicit authorization classification, independent of advisory annotations.
    #[must_use]
    pub const fn requires_write_access(self) -> bool {
        match self {
            Self::WlansUpdate
            | Self::ClientsControl
            | Self::DevicesControl
            | Self::GuestsAuthorize
            | Self::GuestsUnauthorize
            | Self::PortForwardsUpdate
            | Self::FirewallPoliciesUpdate
            | Self::FirewallPoliciesDelete
            | Self::VouchersRevoke
            | Self::CamerasPtzControl
            | Self::CamerasSettingsUpdate
            | Self::CamerasStreamsUpdate
            | Self::CamerasTalkbackStart
            | Self::CamerasPosTransaction
            | Self::ProtectViewersSettingsUpdate
            | Self::ProtectLiveviewsConfigure
            | Self::VouchersCreate => true,
            Self::NetworkOverview
            | Self::ClientsSearch
            | Self::ClientsContext
            | Self::DevicesSearch
            | Self::DevicesStatus
            | Self::GuestsStatus
            | Self::FirewallRead
            | Self::NetworksRead
            | Self::RadiusProfilesList
            | Self::WifiBroadcastsList
            | Self::WifiBroadcastsStatus
            | Self::CamerasSearch
            | Self::CamerasStatus
            | Self::ProtectDevicesList
            | Self::ProtectDevicesStatus
            | Self::ProtectUsersList
            | Self::ProtectUsersStatus
            | Self::ProtectViewersList
            | Self::ProtectViewersStatus
            | Self::ProtectLiveviewsList
            | Self::ProtectLiveviewsStatus
            | Self::CamerasSettingsRead
            | Self::CamerasSnapshot
            | Self::CamerasStreamsList
            | Self::ProtectOverview
            | Self::ProtectEvents
            | Self::ProtectEventThumbnail
            | Self::WifiDiagnose
            | Self::EventsSearch
            | Self::StatsQuery
            | Self::VouchersSearch
            | Self::VouchersStatus => false,
        }
    }

    #[must_use]
    pub const fn surface(self) -> ToolSurface {
        match self {
            Self::CamerasSearch
            | Self::CamerasStatus
            | Self::ProtectDevicesList
            | Self::ProtectDevicesStatus
            | Self::ProtectUsersList
            | Self::ProtectUsersStatus
            | Self::ProtectViewersList
            | Self::ProtectViewersStatus
            | Self::ProtectViewersSettingsUpdate
            | Self::ProtectLiveviewsList
            | Self::ProtectLiveviewsStatus
            | Self::ProtectLiveviewsConfigure
            | Self::CamerasSettingsRead
            | Self::CamerasSettingsUpdate
            | Self::CamerasSnapshot
            | Self::CamerasPtzControl
            | Self::CamerasStreamsList
            | Self::CamerasStreamsUpdate
            | Self::CamerasTalkbackStart
            | Self::CamerasPosTransaction
            | Self::ProtectOverview
            | Self::ProtectEvents
            | Self::ProtectEventThumbnail => ToolSurface::Protect,
            Self::NetworkOverview
            | Self::ClientsSearch
            | Self::ClientsContext
            | Self::DevicesSearch
            | Self::DevicesStatus
            | Self::FirewallRead
            | Self::NetworksRead
            | Self::RadiusProfilesList
            | Self::WifiBroadcastsList
            | Self::WifiBroadcastsStatus
            | Self::WifiDiagnose
            | Self::EventsSearch
            | Self::StatsQuery
            | Self::WlansUpdate
            | Self::ClientsControl
            | Self::DevicesControl
            | Self::GuestsStatus
            | Self::GuestsAuthorize
            | Self::GuestsUnauthorize
            | Self::PortForwardsUpdate
            | Self::FirewallPoliciesUpdate
            | Self::FirewallPoliciesDelete
            | Self::VouchersSearch
            | Self::VouchersStatus
            | Self::VouchersRevoke
            | Self::VouchersCreate => ToolSurface::Network,
        }
    }
}

/// MCP behavior hints and gateway trust labels for one tool.
#[expect(
    clippy::struct_excessive_bools,
    reason = "MCP defines four independent boolean behavior hints, an input sensitivity flag, and two boolean result trust labels"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolBehavior {
    pub(crate) read_only: bool,
    pub(crate) destructive: bool,
    pub(crate) idempotent: bool,
    pub(crate) open_world: bool,
    pub(crate) outcome: &'static str,
    pub(crate) requires_review: bool,
    pub(crate) input_sensitive: bool,
    pub(crate) result_sensitive: bool,
    pub(crate) result_untrusted: bool,
}

impl ToolBehavior {
    /// Mark results sensitive: bounded configuration data whose disclosure
    /// still matters, labeled so the gateway can treat it accordingly.
    pub(crate) const fn result_sensitive(mut self) -> Self {
        self.result_sensitive = true;
        self
    }

    /// A write. The annotations describe a confirmed call, not the preview
    /// default. `idempotent` is stated per tool because it is a property of
    /// the operation: applying the same configuration twice leaves the same
    /// state, while disconnecting a client twice disconnects it twice, and a
    /// caller deciding whether a retry is safe reads this.
    pub(crate) const fn write(idempotent: bool) -> Self {
        Self {
            read_only: false,
            destructive: true,
            idempotent,
            open_world: false,
            outcome: "impactful",
            requires_review: true,
            input_sensitive: false,
            result_sensitive: false,
            result_untrusted: true,
        }
    }

    /// Mark inputs sensitive: the caller can supply secret material.
    pub(crate) const fn input_sensitive(mut self) -> Self {
        self.input_sensitive = true;
        self
    }

    /// A bounded idempotent read. Controller-reported names and counters are
    /// attacker-influenceable, so every result stays untrusted.
    pub(crate) const fn read() -> Self {
        Self {
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
            outcome: "benign",
            requires_review: false,
            input_sensitive: false,
            result_sensitive: false,
            result_untrusted: true,
        }
    }
}

/// One registered tool with its gateway-owned risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: &'static str,
    /// Gateway-owned risk label projected into the manifest scaffold.
    pub risk: &'static str,
    pub(crate) behavior: ToolBehavior,
    pub(crate) description: &'static str,
    pub(crate) kind: ToolKind,
}

/// A read whose bounded output carries network configuration worth treating
/// as sensitive because the returned values can include credentials.
const fn sensitive_read_spec(
    kind: ToolKind,
    name: &'static str,
    description: &'static str,
) -> ToolSpec {
    ToolSpec {
        name,
        risk: "low",
        behavior: ToolBehavior::read().result_sensitive(),
        description,
        kind,
    }
}

/// A read that returns redeemable guest credentials. The gateway uses the
/// classification and sensitivity label to decide who may invoke it.
const fn credential_read_spec(
    kind: ToolKind,
    name: &'static str,
    description: &'static str,
) -> ToolSpec {
    ToolSpec {
        name,
        risk: "high",
        behavior: ToolBehavior::read().result_sensitive(),
        description,
        kind,
    }
}

/// A configuration write, classified high risk so the gateway gates it
/// separately from the read surface.
const fn write_spec(
    kind: ToolKind,
    name: &'static str,
    description: &'static str,
    behavior: ToolBehavior,
) -> ToolSpec {
    ToolSpec {
        name,
        risk: "high",
        behavior,
        description,
        kind,
    }
}

const fn read_spec(kind: ToolKind, name: &'static str, description: &'static str) -> ToolSpec {
    ToolSpec {
        name,
        risk: "low",
        behavior: ToolBehavior::read(),
        description,
        kind,
    }
}

/// Every tool this server serves, in the stable catalog order.
pub const TOOL_REGISTRY: &[ToolSpec] = &[
    read_spec(
        ToolKind::NetworkOverview,
        "network.overview",
        "One bounded controller snapshot: application version, per-subsystem \
         health, 24-hour system-log totals, and device and client totals. Cheap enough \
         for monitoring loops; never returns raw controller records.",
    ),
    read_spec(
        ToolKind::ClientsSearch,
        "clients.search",
        "Find currently connected clients by name, hostname, MAC, IP, SSID, \
         VLAN, or wired/wireless, with pagination and a concise or full \
         detail level. Returns semantic fields such as hostnames and access \
         point names, never raw controller records.",
    ),
    read_spec(
        ToolKind::ClientsContext,
        "clients.context",
        "One connected client end to end: identity, connection and access \
         point, signal, addressing including fixed-IP, usage, and its recent \
         controller events, selected by MAC, name, or hostname.",
    ),
    read_spec(
        ToolKind::DevicesSearch,
        "devices.search",
        "Find adopted devices by name, model, MAC, or IP, optionally filtered \
         by state, with pagination. Returns the bounded inventory row per \
         device, never the raw controller record.",
    ),
    read_spec(
        ToolKind::DevicesStatus,
        "devices.status",
        "One device's bounded status: identity, state, firmware, uptime, CPU \
         and memory utilization, uplink rates, and summarized port and radio \
         tables, selected by id, MAC, or name.",
    ),
    sensitive_read_spec(
        ToolKind::FirewallRead,
        "firewall.read",
        "The normalized firewall audit view: zone-based zones and policies \
         with their match semantics, plus port forwards, traffic rules, and \
         traffic routes. Reads the zone-based firewall only; a console running \
         the classic firewall is refused by name rather than reported as \
         having no firewall, and the refusal names the sections that read the \
         same on either generation. Narrow with section, and continue a \
         truncated zone or policy section with sectionOffset.",
    ),
    sensitive_read_spec(
        ToolKind::CamerasSearch,
        "cameras.search",
        "Cameras on the Protect console by id, name, reported state, hardware \
         model, or functional class. Public inventory is enriched with bounded \
         local device, connection, recording, audio, and feature state when a \
         local session is configured. Paged and bounded. Hardware-model and \
         class filters fail explicitly when their source is unavailable. A \
         console with no Protect integration API is \
         refused rather than reported as having no cameras.",
    ),
    sensitive_read_spec(
        ToolKind::CamerasStatus,
        "cameras.status",
        "One camera on the Protect console, selected by id or exact reported \
         display name. Public identity and state remain authoritative; bounded \
         local enrichment supplies hardware, connection, firmware, recording, \
         audio, and feature facts. Request includeDetails for the complete local
         camera record or detailFields for selected original fields. Use
         cameras.snapshot to fetch an image.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectDevicesList,
        "protect.devices.list",
        "Page through full controller records for one documented non-camera Protect device family: lights, sensors, chimes, sirens, fobs, relays, speakers, bridges, link stations, or alarm hubs. Choose kind, offset, and limit.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectDevicesStatus,
        "protect.devices.status",
        "Read the complete controller record for one non-camera Protect device by documented family and exact id.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectUsersList,
        "protect.users.list",
        "Page through complete Protect or UniFi Identity user records from the documented user family. Choose kind, offset, and limit.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectUsersStatus,
        "protect.users.status",
        "Read the complete Protect or UniFi Identity user record by documented family and exact id.",
    ),
    write_spec(
        ToolKind::CamerasPosTransaction,
        "cameras.pos.transaction",
        "Preview or submit one documented Protect point-of-sale transaction for a camera id. Returns the complete accepted event result, including created and eventId when reported.",
        ToolBehavior::write(false)
            .input_sensitive()
            .result_sensitive(),
    ),
    sensitive_read_spec(
        ToolKind::ProtectViewersList,
        "protect.viewers.list",
        "Page through complete Protect viewer device records, including assigned live view and stream limit.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectViewersStatus,
        "protect.viewers.status",
        "Read the complete Protect viewer device record by exact id.",
    ),
    write_spec(
        ToolKind::ProtectViewersSettingsUpdate,
        "protect.viewers.settings.update",
        "Preview or patch a Protect viewer's name and assigned live view by exact id, then read back the complete record.",
        ToolBehavior::write(true)
            .input_sensitive()
            .result_sensitive(),
    ),
    sensitive_read_spec(
        ToolKind::ProtectLiveviewsList,
        "protect.liveviews.list",
        "Page through complete Protect live-view layouts and camera assignments.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectLiveviewsStatus,
        "protect.liveviews.status",
        "Read one complete Protect live-view layout and camera assignment by exact id.",
    ),
    write_spec(
        ToolKind::ProtectLiveviewsConfigure,
        "protect.liveviews.configure",
        "Preview or create a Protect live view, or patch an existing one by exact id. Changes name, scope, owner, layout, and camera slots; returns the full accepted result and read-back.",
        ToolBehavior::write(false)
            .input_sensitive()
            .result_sensitive(),
    ),
    sensitive_read_spec(
        ToolKind::CamerasSettingsRead,
        "cameras.settings.read",
        "Read one Protect camera's documented name, overlay, LED, microphone volume, video mode, HDR, and smart detection settings by id or exact name.",
    ),
    write_spec(
        ToolKind::CamerasSettingsUpdate,
        "cameras.settings.update",
        "Preview or patch one Protect camera's documented settings by id or exact name. Sends only named settings and reads the camera back to report the observed state.",
        ToolBehavior::write(true).result_sensitive(),
    ),
    sensitive_read_spec(
        ToolKind::CamerasSnapshot,
        "cameras.snapshot",
        "Fetch one bounded JPEG snapshot from a Protect camera, selected by id or exact reported name. Choose the main or package camera channel and optional high quality. Returns the image as MCP image content with concise metadata.",
    ),
    write_spec(
        ToolKind::CamerasPtzControl,
        "cameras.ptz.control",
        "Preview or run a Protect PTZ action for one camera: go to a preset (including home), start a patrol slot, or stop the patrol. Confirmed patrol actions read the active slot back; preset movement reports acceptance because the API exposes no position readback.",
        ToolBehavior::write(false).result_sensitive(),
    ),
    credential_read_spec(
        ToolKind::CamerasStreamsList,
        "cameras.streams.list",
        "List the existing RTSPS stream URLs for one Protect camera. URLs grant access to the camera feed and are sensitive results.",
    ),
    write_spec(
        ToolKind::CamerasStreamsUpdate,
        "cameras.streams.update",
        "Preview or create/remove selected RTSPS stream qualities for one Protect camera. A confirmed create returns the stream URLs; readback reports whether the requested qualities persisted.",
        ToolBehavior::write(false).result_sensitive(),
    ),
    write_spec(
        ToolKind::CamerasTalkbackStart,
        "cameras.talkback.start",
        "Preview or create one Protect camera talkback session. A confirmed call returns the RTP handle and audio configuration for the caller to use.",
        ToolBehavior::write(false).result_sensitive(),
    ),
    sensitive_read_spec(
        ToolKind::ProtectOverview,
        "protect.overview",
        "One Protect console snapshot: the application version, how many \
         cameras are in each reported state, the official single recorder, \
         and explicit public/local capability status. A configured local \
         session supplies recording, hardware, health, capacity, and aggregate \
         storage facts; unavailable facts remain absent. The place to start on \
         a camera question. Request detailFields to inspect selected fields
         from the original local bootstrap response.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectEvents,
        "protect.events",
        "Search historical Protect detections in a bounded window, filtered \
         by camera or detection kind, newest first with pagination. Returns \
         compact event facts, or the controller's complete event records when includeDetails is true. Use protect.event.thumbnail to fetch an event image.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectEventThumbnail,
        "protect.event.thumbnail",
        "Fetch the bounded JPEG thumbnail for one historical Protect event by its id from protect.events. Returns MCP image content and concise event metadata.",
    ),
    read_spec(
        ToolKind::WifiDiagnose,
        "wifi.diagnose",
        "One bounded wireless health snapshot: per-access-point radios and \
         client load, the weakest-signal clients with their access points, \
         and neighboring rogue access points. The place to start on \
         slow-wifi questions.",
    ),
    read_spec(
        ToolKind::EventsSearch,
        "events.search",
        "Search Network system logs in one bounded \
         window, filtered by time, severity, category, or client MAC, newest first \
         with pagination.",
    ),
    read_spec(
        ToolKind::StatsQuery,
        "stats.query",
        "Internet usage over a bounded window: clientWanHistory attributes download/upload bytes to clients; \
         dpiApplications ranks applications with names and stable IDs; wanHourly reads site WAN counters. \
         Use fixed startMs/endMs for comparable reports and client pagination. Activity reports include \
         observed site graph timestamps, collection limitations, and signed differences from WAN totals.",
    ),
    sensitive_read_spec(
        ToolKind::NetworksRead,
        "networks.read",
        "Configured networks and wireless networks: VLANs, subnets, DHCP \
         scopes, SSIDs, security modes, RADIUS profile ids, and controller-reported passphrases. \
         The result is sensitive and the gateway decides who can read it.",
    ),
    sensitive_read_spec(
        ToolKind::RadiusProfilesList,
        "radius_profiles.list",
        "Page through the official Network API's RADIUS profiles for this site. Returns the controller's profile fields unchanged, including identifiers for enterprise Wi-Fi configuration. Continue with nextOffset.",
    ),
    sensitive_read_spec(
        ToolKind::WifiBroadcastsList,
        "wifi.broadcasts.list",
        "Page through Wi-Fi broadcasts from the official Network API. Returns every controller field in each selected row with page metadata and a continuation offset.",
    ),
    sensitive_read_spec(
        ToolKind::WifiBroadcastsStatus,
        "wifi.broadcasts.status",
        "Read one Wi-Fi broadcast by its official id, returning the complete controller record including security and network configuration fields.",
    ),
    write_spec(
        ToolKind::WlansUpdate,
        "wlans.update",
        "Change one wireless network by id: rename, enable or disable, hide, \
         set the security mode, RADIUS profile id, or passphrase. Previews the change \
         and its consequences unless confirm is true; a confirmed change is \
         read back and each field reported as persisted, dropped, or \
         coerced.",
        // Applying the same settings twice leaves the same state. The input
        // can carry a passphrase and the result reports configuration.
        ToolBehavior::write(true)
            .input_sensitive()
            .result_sensitive(),
    ),
    write_spec(
        ToolKind::ClientsControl,
        "clients.control",
        "Block, unblock, or disconnect one client by MAC address. Previews \
         the action and its consequences unless confirm is true; a confirmed \
         action reports whether the client is in the connected list before \
         and after.",
        // Not idempotent: each disconnect disconnects the client again, so a
        // caller must not treat a repeat as harmless.
        ToolBehavior::write(false),
    ),
    write_spec(
        ToolKind::DevicesControl,
        "devices.control",
        "Restart one adopted device, flash or stop its locate LED, or \
         power-cycle one of its switch ports. Previews the action and its \
         consequences unless confirm is true; a confirmed action reports the \
         controller-reported state before and after.",
        // Not idempotent: each restart restarts, each port cycle cycles.
        ToolBehavior::write(false),
    ),
    sensitive_read_spec(
        ToolKind::GuestsStatus,
        "guests.status",
        "Read one connected guest's current authorization state, grant limits, expiration, and method by MAC address.",
    ),
    write_spec(
        ToolKind::GuestsAuthorize,
        "guests.authorize",
        "Preview or authorize one guest by MAC address, with optional time, data, and rate limits. Reauthorization replaces the active grant and resets traffic counters. Confirmed calls return the action grant and check current guest access.",
        ToolBehavior::write(false).result_sensitive(),
    ),
    write_spec(
        ToolKind::GuestsUnauthorize,
        "guests.unauthorize",
        "Preview or revoke one connected guest's access by MAC address. A confirmed action disconnects the client, returns the revoked grant, and checks the reported access state when still readable.",
        ToolBehavior::write(false).result_sensitive(),
    ),
    write_spec(
        ToolKind::PortForwardsUpdate,
        "port_forwards.update",
        "Update one port forward by id, as firewall.read \
         reports it. Previews the change and its consequences unless confirm \
         is true; a confirmed change is read back and each field reported as \
         persisted, dropped, or coerced. Source, target, ports, and protocol \
         can be changed along with name and enabled state.",
        // Applying the same settings twice leaves the same state. The result
        // reports which internal host a rule exposes.
        ToolBehavior::write(true).result_sensitive(),
    ),
    write_spec(
        ToolKind::FirewallPoliciesUpdate,
        "firewall.policies.update",
        "Enable or disable one zone-based firewall policy by id, as \
         firewall.read reports it under policies. Previews the change and \
         what it permits or blocks unless confirm is true; a confirmed change \
         is read back and verified. The upstream interface has no partial \
         update for this, so the whole policy is resent exactly as read with \
         only the switch altered, and an edit made elsewhere in between is \
         overwritten. What the policy matches is not settable here.",
        // Setting a policy to the state it already holds leaves the same
        // state. The result reports the zones and ports a policy governs.
        ToolBehavior::write(true).result_sensitive(),
    ),
    write_spec(
        ToolKind::FirewallPoliciesDelete,
        "firewall.policies.delete",
        "Preview or delete one zone-based firewall policy by id. A confirmed deletion is sent once and checks whether the policy is absent afterward.",
        ToolBehavior::write(true).result_sensitive(),
    ),
    credential_read_spec(
        ToolKind::VouchersSearch,
        "vouchers.search",
        "Page through hotspot vouchers with redeemable codes, expiration state, usage and limits. Returns the controller's total count and next offset; narrow each page with limit.",
    ),
    credential_read_spec(
        ToolKind::VouchersStatus,
        "vouchers.status",
        "Read one hotspot voucher by id, including its redeemable code, expiration, usage and limits.",
    ),
    write_spec(
        ToolKind::VouchersRevoke,
        "vouchers.revoke",
        "Preview or revoke one hotspot voucher by id. A confirmed revocation reads back the id and reports whether it disappeared from the controller.",
        ToolBehavior::write(true).result_sensitive(),
    ),
    write_spec(
        ToolKind::VouchersCreate,
        "vouchers.create",
        "Mint hotspot vouchers for the guest network. Previews the batch and \
         its consequences unless confirm is true. A confirmed call returns the \
         created codes and reads each identified voucher back to verify its code. \
         Codes remain available through vouchers.search and vouchers.status.",
        // Not idempotent: each call mints another batch. The result carries
        // credentials, which is why it exists.
        ToolBehavior::write(false).result_sensitive(),
    ),
];

/// Registered tools for one deployable console surface, preserving registry
/// order so catalog and manifest output remain deterministic.
pub fn tools_for_surface(surface: ToolSurface) -> impl Iterator<Item = &'static ToolSpec> {
    TOOL_REGISTRY
        .iter()
        .filter(move |spec| spec.kind.surface() == surface)
}

#[cfg(test)]
mod tests {
    use super::{TOOL_REGISTRY, ToolKind, ToolSurface, tools_for_surface};

    /// Every dispatchable kind, kept next to the enum so a new variant fails
    /// this list's exhaustive match below before it can ship unregistered.
    const ALL_KINDS: &[ToolKind] = &[
        ToolKind::NetworkOverview,
        ToolKind::ClientsSearch,
        ToolKind::ClientsContext,
        ToolKind::DevicesSearch,
        ToolKind::DevicesStatus,
        ToolKind::FirewallRead,
        ToolKind::NetworksRead,
        ToolKind::RadiusProfilesList,
        ToolKind::WifiBroadcastsList,
        ToolKind::WifiBroadcastsStatus,
        ToolKind::CamerasSearch,
        ToolKind::CamerasStatus,
        ToolKind::ProtectDevicesList,
        ToolKind::ProtectDevicesStatus,
        ToolKind::ProtectUsersList,
        ToolKind::ProtectUsersStatus,
        ToolKind::CamerasPosTransaction,
        ToolKind::ProtectViewersList,
        ToolKind::ProtectViewersStatus,
        ToolKind::ProtectViewersSettingsUpdate,
        ToolKind::ProtectLiveviewsList,
        ToolKind::ProtectLiveviewsStatus,
        ToolKind::ProtectLiveviewsConfigure,
        ToolKind::CamerasSettingsRead,
        ToolKind::CamerasSettingsUpdate,
        ToolKind::CamerasSnapshot,
        ToolKind::CamerasPtzControl,
        ToolKind::CamerasStreamsList,
        ToolKind::CamerasStreamsUpdate,
        ToolKind::CamerasTalkbackStart,
        ToolKind::ProtectOverview,
        ToolKind::ProtectEvents,
        ToolKind::ProtectEventThumbnail,
        ToolKind::WifiDiagnose,
        ToolKind::EventsSearch,
        ToolKind::StatsQuery,
        ToolKind::WlansUpdate,
        ToolKind::ClientsControl,
        ToolKind::DevicesControl,
        ToolKind::GuestsStatus,
        ToolKind::GuestsAuthorize,
        ToolKind::GuestsUnauthorize,
        ToolKind::PortForwardsUpdate,
        ToolKind::FirewallPoliciesUpdate,
        ToolKind::FirewallPoliciesDelete,
        ToolKind::VouchersSearch,
        ToolKind::VouchersStatus,
        ToolKind::VouchersRevoke,
        ToolKind::VouchersCreate,
    ];

    #[test]
    fn pos_transaction_classifies_the_write_and_both_data_directions() {
        let spec = TOOL_REGISTRY
            .iter()
            .find(|spec| spec.kind == ToolKind::CamerasPosTransaction)
            .expect("POS transaction tool");
        assert_eq!(spec.risk, "high");
        assert!(spec.behavior.destructive);
        assert!(!spec.behavior.idempotent);
        assert!(spec.behavior.input_sensitive);
        assert!(spec.behavior.result_sensitive);
    }

    #[test]
    fn viewer_settings_classifies_the_write_and_both_data_directions() {
        let spec = TOOL_REGISTRY
            .iter()
            .find(|spec| spec.kind == ToolKind::ProtectViewersSettingsUpdate)
            .expect("viewer settings tool");
        assert_eq!(spec.risk, "high");
        assert!(spec.kind.requires_write_access());
        assert!(spec.behavior.input_sensitive);
        assert!(spec.behavior.result_sensitive);
    }

    #[test]
    fn liveview_configuration_classifies_creation_and_sensitive_data() {
        let spec = TOOL_REGISTRY
            .iter()
            .find(|spec| spec.kind == ToolKind::ProtectLiveviewsConfigure)
            .expect("live-view configuration tool");
        assert_eq!(spec.risk, "high");
        assert!(spec.kind.requires_write_access());
        assert!(!spec.behavior.idempotent);
        assert!(spec.behavior.input_sensitive);
        assert!(spec.behavior.result_sensitive);
    }

    #[test]
    fn every_kind_is_registered_exactly_once_with_a_unique_name() {
        for kind in ALL_KINDS {
            // Exhaustiveness anchor: a new variant must be added here or the
            // compiler flags this match.
            match kind {
                ToolKind::NetworkOverview
                | ToolKind::ClientsSearch
                | ToolKind::ClientsContext
                | ToolKind::DevicesSearch
                | ToolKind::DevicesStatus
                | ToolKind::FirewallRead
                | ToolKind::NetworksRead
                | ToolKind::RadiusProfilesList
                | ToolKind::WifiBroadcastsList
                | ToolKind::WifiBroadcastsStatus
                | ToolKind::CamerasSearch
                | ToolKind::CamerasStatus
                | ToolKind::ProtectDevicesList
                | ToolKind::ProtectDevicesStatus
                | ToolKind::ProtectUsersList
                | ToolKind::ProtectUsersStatus
                | ToolKind::CamerasPosTransaction
                | ToolKind::ProtectViewersList
                | ToolKind::ProtectViewersStatus
                | ToolKind::ProtectViewersSettingsUpdate
                | ToolKind::ProtectLiveviewsList
                | ToolKind::ProtectLiveviewsStatus
                | ToolKind::ProtectLiveviewsConfigure
                | ToolKind::CamerasSettingsRead
                | ToolKind::CamerasSettingsUpdate
                | ToolKind::CamerasSnapshot
                | ToolKind::CamerasPtzControl
                | ToolKind::CamerasStreamsList
                | ToolKind::CamerasStreamsUpdate
                | ToolKind::CamerasTalkbackStart
                | ToolKind::ProtectOverview
                | ToolKind::ProtectEvents
                | ToolKind::ProtectEventThumbnail
                | ToolKind::WifiDiagnose
                | ToolKind::EventsSearch
                | ToolKind::StatsQuery
                | ToolKind::WlansUpdate
                | ToolKind::ClientsControl
                | ToolKind::DevicesControl
                | ToolKind::GuestsStatus
                | ToolKind::GuestsAuthorize
                | ToolKind::GuestsUnauthorize
                | ToolKind::PortForwardsUpdate
                | ToolKind::FirewallPoliciesUpdate
                | ToolKind::FirewallPoliciesDelete
                | ToolKind::VouchersSearch
                | ToolKind::VouchersStatus
                | ToolKind::VouchersRevoke
                | ToolKind::VouchersCreate => {}
            }
            assert_eq!(
                TOOL_REGISTRY
                    .iter()
                    .filter(|spec| spec.kind == *kind)
                    .count(),
                1,
                "{kind:?}"
            );
        }
        assert_eq!(TOOL_REGISTRY.len(), ALL_KINDS.len());
        let mut names: Vec<&str> = TOOL_REGISTRY.iter().map(|spec| spec.name).collect();
        names.dedup();
        assert_eq!(names.len(), TOOL_REGISTRY.len());
    }

    #[test]
    fn runtime_surfaces_are_disjoint_and_cover_the_registry() {
        let network: Vec<_> = tools_for_surface(ToolSurface::Network)
            .map(|spec| spec.name)
            .collect();
        let protect: Vec<_> = tools_for_surface(ToolSurface::Protect)
            .map(|spec| spec.name)
            .collect();
        assert_eq!(network.len() + protect.len(), TOOL_REGISTRY.len());
        assert!(network.iter().all(|name| !protect.contains(name)));
        assert_eq!(
            protect,
            [
                "cameras.search",
                "cameras.status",
                "protect.devices.list",
                "protect.devices.status",
                "protect.users.list",
                "protect.users.status",
                "cameras.pos.transaction",
                "protect.viewers.list",
                "protect.viewers.status",
                "protect.viewers.settings.update",
                "protect.liveviews.list",
                "protect.liveviews.status",
                "protect.liveviews.configure",
                "cameras.settings.read",
                "cameras.settings.update",
                "cameras.snapshot",
                "cameras.ptz.control",
                "cameras.streams.list",
                "cameras.streams.update",
                "cameras.talkback.start",
                "protect.overview",
                "protect.events",
                "protect.event.thumbnail"
            ]
        );
    }
}
