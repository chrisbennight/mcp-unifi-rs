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
    CamerasSearch,
    CamerasStatus,
    ProtectOverview,
    ProtectEvents,
    WifiDiagnose,
    EventsSearch,
    StatsQuery,
    WlansUpdate,
    ClientsControl,
    DevicesControl,
    GuestsAuthorize,
    PortForwardsUpdate,
    FirewallPoliciesUpdate,
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
            | Self::PortForwardsUpdate
            | Self::FirewallPoliciesUpdate
            | Self::VouchersCreate => true,
            Self::NetworkOverview
            | Self::ClientsSearch
            | Self::ClientsContext
            | Self::DevicesSearch
            | Self::DevicesStatus
            | Self::FirewallRead
            | Self::NetworksRead
            | Self::CamerasSearch
            | Self::CamerasStatus
            | Self::ProtectOverview
            | Self::ProtectEvents
            | Self::WifiDiagnose
            | Self::EventsSearch
            | Self::StatsQuery => false,
        }
    }

    #[must_use]
    pub const fn surface(self) -> ToolSurface {
        match self {
            Self::CamerasSearch
            | Self::CamerasStatus
            | Self::ProtectOverview
            | Self::ProtectEvents => ToolSurface::Protect,
            Self::NetworkOverview
            | Self::ClientsSearch
            | Self::ClientsContext
            | Self::DevicesSearch
            | Self::DevicesStatus
            | Self::FirewallRead
            | Self::NetworksRead
            | Self::WifiDiagnose
            | Self::EventsSearch
            | Self::StatsQuery
            | Self::WlansUpdate
            | Self::ClientsControl
            | Self::DevicesControl
            | Self::GuestsAuthorize
            | Self::PortForwardsUpdate
            | Self::FirewallPoliciesUpdate
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
    pub(crate) result_irreplaceable: bool,
}

impl ToolBehavior {
    /// Mark results sensitive: bounded configuration data whose disclosure
    /// still matters, labeled so the gateway can treat it accordingly.
    pub(crate) const fn result_sensitive(mut self) -> Self {
        self.result_sensitive = true;
        self
    }

    /// Mark the result irreplaceable: it carries values this call created that
    /// no read reproduces. Such a result is exempt from the response budget,
    /// because refusing or trimming it destroys them and leaves the caller
    /// nothing to narrow.
    ///
    /// A tool claiming this must bound every caller-supplied value it echoes,
    /// before the call that creates anything. Otherwise the exemption stops
    /// being a guarantee about generated values and becomes an amplifier for
    /// text the caller chose.
    pub(crate) const fn result_irreplaceable(mut self) -> Self {
        self.result_irreplaceable = true;
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
            result_irreplaceable: false,
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
            result_irreplaceable: false,
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
/// as sensitive even with secrets redacted.
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
         health, active alarm count, and device and client totals. Cheap enough \
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
         audio, and feature facts. Returns no image, stream, or talkback.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectOverview,
        "protect.overview",
        "One Protect console snapshot: the application version, how many \
         cameras are in each reported state, the official single recorder, \
         and explicit public/local capability status. A configured local \
         session supplies recording, hardware, health, capacity, and aggregate \
         storage facts; unavailable facts remain absent. The place to start on \
         a camera question.",
    ),
    sensitive_read_spec(
        ToolKind::ProtectEvents,
        "protect.events",
        "Search historical Protect detections in a bounded window, filtered \
         by camera or detection kind, newest first with pagination. Returns \
         typed event metadata only: never thumbnails, snapshots, or raw \
         detection payloads.",
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
        "Search recent controller events and active alarms in one bounded \
         window, filtered by time, category, or client MAC, newest first \
         with pagination.",
    ),
    read_spec(
        ToolKind::StatsQuery,
        "stats.query",
        "Bounded historical statistics: hourly WAN throughput over a chosen \
         window up to seven days, or top applications by deep packet \
         inspection volume (numeric application ids).",
    ),
    sensitive_read_spec(
        ToolKind::NetworksRead,
        "networks.read",
        "Configured networks and wireless networks: VLANs, subnets, DHCP \
         scopes, SSIDs, and security modes. Passphrases are redacted by \
         default; includeSecrets discloses them and requires the mcp-admins \
         group.",
    ),
    write_spec(
        ToolKind::WlansUpdate,
        "wlans.update",
        "Change one wireless network by id: rename, enable or disable, hide, \
         set the security mode, or set the passphrase. Previews the change \
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
    write_spec(
        ToolKind::GuestsAuthorize,
        "guests.authorize",
        "Authorize one client for guest access by MAC address, as \
         clients.search reports it. Previews the action and its consequence \
         unless confirm is true. The controller exposes no authorization \
         field on a client, so the result says the effect cannot be read back \
         rather than implying it was checked.",
        // Idempotent: authorizing an authorized client leaves it authorized.
        ToolBehavior::write(true),
    ),
    write_spec(
        ToolKind::PortForwardsUpdate,
        "port_forwards.update",
        "Enable, disable, or rename one port forward by id, as firewall.read \
         reports it. Previews the change and its consequences unless confirm \
         is true; a confirmed change is read back and each field reported as \
         persisted, dropped, or coerced. Where the rule points is not settable \
         here.",
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
        ToolKind::VouchersCreate,
        "vouchers.create",
        "Mint hotspot vouchers for the guest network. Previews the batch and \
         its consequences unless confirm is true. The controller returns each \
         code once and no read reproduces it, so the result is the only copy: \
         the batch is judged on its own shape rather than by reading back, and \
         the codes are returned whatever that judgement says. The one exception \
         is a code that would disclose a configured controller credential: it \
         is redacted, reported, and its voucher identified so it can be revoked \
         and replaced.",
        // Not idempotent: each call mints another batch. The result carries
        // credentials, which is why it exists.
        ToolBehavior::write(false)
            .result_sensitive()
            .result_irreplaceable(),
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
        ToolKind::CamerasSearch,
        ToolKind::CamerasStatus,
        ToolKind::ProtectOverview,
        ToolKind::ProtectEvents,
        ToolKind::WifiDiagnose,
        ToolKind::EventsSearch,
        ToolKind::StatsQuery,
        ToolKind::WlansUpdate,
        ToolKind::ClientsControl,
        ToolKind::DevicesControl,
        ToolKind::GuestsAuthorize,
        ToolKind::PortForwardsUpdate,
        ToolKind::FirewallPoliciesUpdate,
        ToolKind::VouchersCreate,
    ];

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
                | ToolKind::CamerasSearch
                | ToolKind::CamerasStatus
                | ToolKind::ProtectOverview
                | ToolKind::ProtectEvents
                | ToolKind::WifiDiagnose
                | ToolKind::EventsSearch
                | ToolKind::StatsQuery
                | ToolKind::WlansUpdate
                | ToolKind::ClientsControl
                | ToolKind::DevicesControl
                | ToolKind::GuestsAuthorize
                | ToolKind::PortForwardsUpdate
                | ToolKind::FirewallPoliciesUpdate
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
                "protect.overview",
                "protect.events"
            ]
        );
    }
}
