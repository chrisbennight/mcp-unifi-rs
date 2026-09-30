//! Typed full firewall policy requests from the official Network Integration API.
//! Cross-field policy validity is decided by the controller.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct FirewallPolicyRequest {
    #[serde(rename = "action")]
    action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "connectionStateFilter")]
    connection_state_filter: Option<Vec<ConnectionState>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "description")]
    description: Option<String>,
    #[serde(rename = "destination")]
    destination: Destination,
    #[serde(rename = "enabled")]
    enabled: bool,
    #[serde(rename = "ipProtocolScope")]
    ip_protocol_scope: IpProtocolScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ipsecFilter")]
    ipsec_filter: Option<IpsecFilter>,
    #[serde(rename = "loggingEnabled")]
    logging_enabled: bool,
    #[serde(rename = "name")]
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "schedule")]
    schedule: Option<Schedule>,
    #[serde(rename = "source")]
    source: Source,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum Action {
    #[serde(rename = "ALLOW")]
    Allow {
        #[serde(rename = "allowReturnTraffic")]
        allow_return_traffic: bool,
    },
    #[serde(rename = "BLOCK")]
    Block,
    #[serde(rename = "REJECT")]
    Reject,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum ConnectionState {
    #[serde(rename = "NEW")]
    New,
    #[serde(rename = "INVALID")]
    Invalid,
    #[serde(rename = "ESTABLISHED")]
    Established,
    #[serde(rename = "RELATED")]
    Related,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Destination {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "trafficFilter")]
    traffic_filter: Option<DestinationTrafficFilter>,
    #[serde(rename = "zoneId")]
    zone_id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum DestinationTrafficFilter {
    #[serde(rename = "APPLICATION")]
    Application {
        #[serde(rename = "applicationFilter")]
        application_filter: ApplicationFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "APPLICATION_CATEGORY")]
    ApplicationCategory {
        #[serde(rename = "applicationCategoryFilter")]
        application_category_filter: ApplicationCategoryFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "DOMAIN")]
    Domain {
        #[serde(rename = "domainFilter")]
        domain_filter: DomainFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "IPV6_IID")]
    Ipv6Iid {
        #[serde(rename = "ipv6IidFilter")]
        ipv6_iid_filter: Ipv6InterfaceIdentifierFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "IP_ADDRESS")]
    IpAddress {
        #[serde(rename = "ipAddressFilter")]
        ip_address_filter: IpAddressFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "NETWORK")]
    Network {
        #[serde(rename = "networkFilter")]
        network_filter: NetworkFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "PORT")]
    Port {
        #[serde(rename = "portFilter")]
        port_filter: PortFilter,
    },
    #[serde(rename = "REGION")]
    Region {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
        #[serde(rename = "regionFilter")]
        region_filter: RegionFilter,
    },
    #[serde(rename = "SITE_TO_SITE_VPN_TUNNEL")]
    SiteToSiteVpnTunnel {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
        #[serde(rename = "siteToSiteVpnTunnelFilter")]
        site_to_site_vpn_tunnel_filter: SiteToSiteVpnTunnelFilter,
    },
    #[serde(rename = "VPN_SERVER")]
    VpnServer {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
        #[serde(rename = "vpnServerFilter")]
        vpn_server_filter: VpnServerFilter,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationFilter {
    #[serde(rename = "applicationIds")]
    application_ids: Vec<i32>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum PortFilter {
    #[serde(rename = "PORTS")]
    Ports {
        #[serde(rename = "matchOpposite")]
        match_opposite: bool,
        #[serde(rename = "items")]
        items: Vec<PortMatching>,
    },
    #[serde(rename = "TRAFFIC_MATCHING_LIST")]
    TrafficMatchingList {
        #[serde(rename = "matchOpposite")]
        match_opposite: bool,
        #[serde(rename = "trafficMatchingListId")]
        traffic_matching_list_id: String,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum PortMatching {
    #[serde(rename = "PORT_NUMBER")]
    PortNumber {
        #[serde(rename = "value")]
        value: i32,
    },
    #[serde(rename = "PORT_NUMBER_RANGE")]
    PortNumberRange {
        #[serde(rename = "start")]
        start: i32,
        #[serde(rename = "stop")]
        stop: i32,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationCategoryFilter {
    #[serde(rename = "applicationCategoryIds")]
    application_category_ids: Vec<i32>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum DomainFilter {
    #[serde(rename = "DOMAINS")]
    Domains {
        #[serde(rename = "domains")]
        domains: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Ipv6InterfaceIdentifierFilter {
    #[serde(rename = "ipv6Iid")]
    ipv6_iid: String,
    #[serde(rename = "matchOpposite")]
    match_opposite: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum IpAddressFilter {
    #[serde(rename = "IP_ADDRESSES")]
    IpAddresses {
        #[serde(rename = "matchOpposite")]
        match_opposite: bool,
        #[serde(rename = "items")]
        items: Vec<IpMatching>,
    },
    #[serde(rename = "TRAFFIC_MATCHING_LIST")]
    TrafficMatchingList {
        #[serde(rename = "matchOpposite")]
        match_opposite: bool,
        #[serde(rename = "trafficMatchingListId")]
        traffic_matching_list_id: String,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum IpMatching {
    #[serde(rename = "IP_ADDRESS")]
    IpAddress {
        #[serde(rename = "value")]
        value: String,
    },
    #[serde(rename = "IP_ADDRESS_RANGE")]
    IpAddressRange {
        #[serde(rename = "start")]
        start: String,
        #[serde(rename = "stop")]
        stop: String,
    },
    #[serde(rename = "SUBNET")]
    Subnet {
        #[serde(rename = "value")]
        value: String,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NetworkFilter {
    #[serde(rename = "matchOpposite")]
    match_opposite: bool,
    #[serde(rename = "networkIds")]
    network_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RegionFilter {
    #[serde(rename = "regions")]
    regions: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SiteToSiteVpnTunnelFilter {
    #[serde(rename = "siteToSiteVpnTunnelId")]
    site_to_site_vpn_tunnel_id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct VpnServerFilter {
    #[serde(rename = "matchOpposite")]
    match_opposite: bool,
    #[serde(rename = "vpnServerIds")]
    vpn_server_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "ipVersion", deny_unknown_fields)]
pub(super) enum IpProtocolScope {
    #[serde(rename = "IPV4")]
    Ipv4 {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "protocolFilter")]
        protocol_filter: Option<ProtocolFilter>,
    },
    #[serde(rename = "IPV6")]
    Ipv6 {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "protocolFilter")]
        protocol_filter: Option<ProtocolFilter>,
    },
    #[serde(rename = "IPV4_AND_IPV6")]
    Ipv4AndIpv6 {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "protocolFilter")]
        protocol_filter: Option<ProtocolFilter>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum ProtocolFilter {
    #[serde(rename = "NAMED_PROTOCOL")]
    NamedProtocol {
        #[serde(rename = "matchOpposite")]
        match_opposite: bool,
        #[serde(rename = "protocol")]
        protocol: NamedProtocol,
    },
    #[serde(rename = "PRESET")]
    Preset {
        #[serde(rename = "preset")]
        preset: ProtocolPreset,
    },
    #[serde(rename = "PROTOCOL_NUMBER")]
    ProtocolNumber {
        #[serde(rename = "matchOpposite")]
        match_opposite: bool,
        #[serde(rename = "protocolNumber")]
        protocol_number: i32,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "name", deny_unknown_fields)]
pub(super) enum NamedProtocol {
    #[serde(rename = "ah")]
    Ah,
    #[serde(rename = "ax.25")]
    Ax25,
    #[serde(rename = "dccp")]
    Dccp,
    #[serde(rename = "ddp")]
    Ddp,
    #[serde(rename = "egp")]
    Egp,
    #[serde(rename = "eigrp")]
    Eigrp,
    #[serde(rename = "encap")]
    Encap,
    #[serde(rename = "esp")]
    Esp,
    #[serde(rename = "etherip")]
    Etherip,
    #[serde(rename = "fc")]
    Fc,
    #[serde(rename = "ggp")]
    Ggp,
    #[serde(rename = "gre")]
    Gre,
    #[serde(rename = "hip")]
    Hip,
    #[serde(rename = "hmp")]
    Hmp,
    #[serde(rename = "icmp")]
    Icmp {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "typenameFilter")]
        typename_filter: Option<IcmpTypeName>,
    },
    #[serde(rename = "icmpv6")]
    Icmpv6 {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "typenameFilter")]
        typename_filter: Option<Icmpv6TypeName>,
    },
    #[serde(rename = "idpr-cmtp")]
    IdprCmtp,
    #[serde(rename = "idrp")]
    Idrp,
    #[serde(rename = "igmp")]
    Igmp,
    #[serde(rename = "igp")]
    Igp,
    #[serde(rename = "ip")]
    Ip,
    #[serde(rename = "ipcomp")]
    Ipcomp,
    #[serde(rename = "ipencap")]
    Ipencap,
    #[serde(rename = "ipip")]
    Ipip,
    #[serde(rename = "ipv6")]
    Ipv6,
    #[serde(rename = "ipv6-frag")]
    Ipv6Frag,
    #[serde(rename = "ipv6-nonxt")]
    Ipv6Nonxt,
    #[serde(rename = "ipv6-opts")]
    Ipv6Opts,
    #[serde(rename = "ipv6-route")]
    Ipv6Route,
    #[serde(rename = "isis")]
    Isis,
    #[serde(rename = "iso-tp4")]
    IsoTp4,
    #[serde(rename = "l2tp")]
    L2tp,
    #[serde(rename = "manet")]
    Manet,
    #[serde(rename = "mobility-header")]
    MobilityHeader,
    #[serde(rename = "mpls-in-ip")]
    MplsInIp,
    #[serde(rename = "ospf")]
    Ospf,
    #[serde(rename = "pim")]
    Pim,
    #[serde(rename = "pup")]
    Pup,
    #[serde(rename = "rdp")]
    Rdp,
    #[serde(rename = "rohc")]
    Rohc,
    #[serde(rename = "rspf")]
    Rspf,
    #[serde(rename = "rsvp")]
    Rsvp,
    #[serde(rename = "sctp")]
    Sctp,
    #[serde(rename = "shim6")]
    Shim6,
    #[serde(rename = "skip")]
    Skip,
    #[serde(rename = "st")]
    St,
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "tcp_udp")]
    TcpUdp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "udplite")]
    Udplite,
    #[serde(rename = "vmtp")]
    Vmtp,
    #[serde(rename = "vrrp")]
    Vrrp,
    #[serde(rename = "wesp")]
    Wesp,
    #[serde(rename = "xns-idp")]
    XnsIdp,
    #[serde(rename = "xtp")]
    Xtp,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum IcmpTypeName {
    #[serde(rename = "ADDRESS_MASK_REPLY")]
    AddressMaskReply,
    #[serde(rename = "ADDRESS_MASK_REQUEST")]
    AddressMaskRequest,
    #[serde(rename = "COMMUNICATION_PROHIBITED")]
    CommunicationProhibited,
    #[serde(rename = "DESTINATION_UNREACHABLE")]
    DestinationUnreachable,
    #[serde(rename = "ECHO_REPLY")]
    EchoReply,
    #[serde(rename = "ECHO_REQUEST")]
    EchoRequest,
    #[serde(rename = "FRAGMENTATION_NEEDED")]
    FragmentationNeeded,
    #[serde(rename = "HOST_PRECEDENCE_VIOLATION")]
    HostPrecedenceViolation,
    #[serde(rename = "HOST_PROHIBITED")]
    HostProhibited,
    #[serde(rename = "HOST_REDIRECT")]
    HostRedirect,
    #[serde(rename = "HOST_UNKNOWN")]
    HostUnknown,
    #[serde(rename = "HOST_UNREACHABLE")]
    HostUnreachable,
    #[serde(rename = "IP_HEADER_BAD")]
    IpHeaderBad,
    #[serde(rename = "NETWORK_PROHIBITED")]
    NetworkProhibited,
    #[serde(rename = "NETWORK_REDIRECT")]
    NetworkRedirect,
    #[serde(rename = "NETWORK_UNKNOWN")]
    NetworkUnknown,
    #[serde(rename = "NETWORK_UNREACHABLE")]
    NetworkUnreachable,
    #[serde(rename = "PARAMETER_PROBLEM")]
    ParameterProblem,
    #[serde(rename = "PORT_UNREACHABLE")]
    PortUnreachable,
    #[serde(rename = "PRECEDENCE_CUTOFF")]
    PrecedenceCutoff,
    #[serde(rename = "PROTOCOL_UNREACHABLE")]
    ProtocolUnreachable,
    #[serde(rename = "REDIRECT")]
    Redirect,
    #[serde(rename = "REQUIRED_OPTION_MISSING")]
    RequiredOptionMissing,
    #[serde(rename = "ROUTER_ADVERTISEMENT")]
    RouterAdvertisement,
    #[serde(rename = "ROUTER_SOLICITATION")]
    RouterSolicitation,
    #[serde(rename = "SOURCE_QUENCH")]
    SourceQuench,
    #[serde(rename = "SOURCE_ROUTE_FAILED")]
    SourceRouteFailed,
    #[serde(rename = "TIME_EXCEEDED")]
    TimeExceeded,
    #[serde(rename = "TIMESTAMP_REPLY")]
    TimestampReply,
    #[serde(rename = "TIMESTAMP_REQUEST")]
    TimestampRequest,
    #[serde(rename = "TOS_HOST_REDIRECT")]
    TosHostRedirect,
    #[serde(rename = "TOS_HOST_UNREACHABLE")]
    TosHostUnreachable,
    #[serde(rename = "TOS_NETWORK_REDIRECT")]
    TosNetworkRedirect,
    #[serde(rename = "TOS_NETWORK_UNREACHABLE")]
    TosNetworkUnreachable,
    #[serde(rename = "TTL_ZERO_DURING_REASSEMBLY")]
    TtlZeroDuringReassembly,
    #[serde(rename = "TTL_ZERO_DURING_TRANSIT")]
    TtlZeroDuringTransit,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum Icmpv6TypeName {
    #[serde(rename = "ADDRESS_UNREACHABLE")]
    AddressUnreachable,
    #[serde(rename = "BAD_HEADER")]
    BadHeader,
    #[serde(rename = "BEYOND_SCOPE")]
    BeyondScope,
    #[serde(rename = "COMMUNICATION_PROHIBITED")]
    CommunicationProhibited,
    #[serde(rename = "DESTINATION_UNREACHABLE")]
    DestinationUnreachable,
    #[serde(rename = "ECHO_REPLY")]
    EchoReply,
    #[serde(rename = "ECHO_REQUEST")]
    EchoRequest,
    #[serde(rename = "FAILED_POLICY")]
    FailedPolicy,
    #[serde(rename = "NEIGHBOR_ADVERTISEMENT")]
    NeighborAdvertisement,
    #[serde(rename = "NEIGHBOR_SOLICITATION")]
    NeighborSolicitation,
    #[serde(rename = "NO_ROUTE")]
    NoRoute,
    #[serde(rename = "PACKET_TOO_BIG")]
    PacketTooBig,
    #[serde(rename = "PARAMETER_PROBLEM")]
    ParameterProblem,
    #[serde(rename = "PORT_UNREACHABLE")]
    PortUnreachable,
    #[serde(rename = "REDIRECT")]
    Redirect,
    #[serde(rename = "REJECT_ROUTE")]
    RejectRoute,
    #[serde(rename = "ROUTER_ADVERTISEMENT")]
    RouterAdvertisement,
    #[serde(rename = "ROUTER_SOLICITATION")]
    RouterSolicitation,
    #[serde(rename = "TIME_EXCEEDED")]
    TimeExceeded,
    #[serde(rename = "TTL_ZERO_DURING_REASSEMBLY")]
    TtlZeroDuringReassembly,
    #[serde(rename = "TTL_ZERO_DURING_TRANSIT")]
    TtlZeroDuringTransit,
    #[serde(rename = "UNKNOWN_HEADER_TYPE")]
    UnknownHeaderType,
    #[serde(rename = "UNKNOWN_OPTION")]
    UnknownOption,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "name", deny_unknown_fields)]
pub(super) enum ProtocolPreset {
    #[serde(rename = "TCP_UDP")]
    TcpUdp,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum IpsecFilter {
    #[serde(rename = "MATCH_ENCRYPTED")]
    MatchEncrypted,
    #[serde(rename = "MATCH_NOT_ENCRYPTED")]
    MatchNotEncrypted,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "mode", deny_unknown_fields)]
pub(super) enum Schedule {
    #[serde(rename = "CUSTOM")]
    Custom {
        #[serde(rename = "repeatOnDays")]
        repeat_on_days: Vec<Day>,
        #[serde(rename = "startDate")]
        start_date: String,
        #[serde(rename = "stopDate")]
        stop_date: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "timeFilter")]
        time_filter: Option<ScheduleTime>,
    },
    #[serde(rename = "EVERY_DAY")]
    EveryDay {
        #[serde(rename = "timeFilter")]
        time_filter: ScheduleTime,
    },
    #[serde(rename = "EVERY_WEEK")]
    EveryWeek {
        #[serde(rename = "repeatOnDays")]
        repeat_on_days: Vec<Day>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "timeFilter")]
        time_filter: Option<ScheduleTime>,
    },
    #[serde(rename = "ONE_TIME_ONLY")]
    OneTimeOnly {
        #[serde(rename = "date")]
        date: String,
        #[serde(rename = "timeFilter")]
        time_filter: ScheduleTime,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum Day {
    #[serde(rename = "MONDAY")]
    Monday,
    #[serde(rename = "TUESDAY")]
    Tuesday,
    #[serde(rename = "WEDNESDAY")]
    Wednesday,
    #[serde(rename = "THURSDAY")]
    Thursday,
    #[serde(rename = "FRIDAY")]
    Friday,
    #[serde(rename = "SATURDAY")]
    Saturday,
    #[serde(rename = "SUNDAY")]
    Sunday,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ScheduleTime {
    #[serde(rename = "startTime")]
    start_time: String,
    #[serde(rename = "stopTime")]
    stop_time: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "trafficFilter")]
    traffic_filter: Option<SourceTrafficFilter>,
    #[serde(rename = "zoneId")]
    zone_id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum SourceTrafficFilter {
    #[serde(rename = "IPV6_IID")]
    Ipv6Iid {
        #[serde(rename = "ipv6IidFilter")]
        ipv6_iid_filter: Ipv6InterfaceIdentifierFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "macAddressFilter")]
        mac_address_filter: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "IP_ADDRESS")]
    IpAddress {
        #[serde(rename = "ipAddressFilter")]
        ip_address_filter: IpAddressFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "macAddressFilter")]
        mac_address_filter: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "MAC_ADDRESS")]
    MacAddress {
        #[serde(rename = "macAddressFilter")]
        mac_address_filter: MacAddressFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "NETWORK")]
    Network {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "macAddressFilter")]
        mac_address_filter: Option<String>,
        #[serde(rename = "networkFilter")]
        network_filter: NetworkFilter,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
    },
    #[serde(rename = "PORT")]
    Port {
        #[serde(rename = "portFilter")]
        port_filter: PortFilter,
    },
    #[serde(rename = "REGION")]
    Region {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
        #[serde(rename = "regionFilter")]
        region_filter: RegionFilter,
    },
    #[serde(rename = "SITE_TO_SITE_VPN_TUNNEL")]
    SiteToSiteVpnTunnel {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
        #[serde(rename = "siteToSiteVpnTunnelFilter")]
        site_to_site_vpn_tunnel_filter: SiteToSiteVpnTunnelFilter,
    },
    #[serde(rename = "VPN_SERVER")]
    VpnServer {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "portFilter")]
        port_filter: Option<PortFilter>,
        #[serde(rename = "vpnServerFilter")]
        vpn_server_filter: VpnServerFilter,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct MacAddressFilter {
    #[serde(rename = "macAddresses")]
    mac_addresses: Vec<String>,
}
