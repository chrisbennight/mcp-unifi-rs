//! Typed full network configuration requests from the official Network Integration API.
//! Cross-field configuration validity is decided by the controller.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "management", deny_unknown_fields)]
pub(super) enum NetworkRequest {
    #[serde(rename = "GATEWAY")]
    Gateway {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dhcpGuarding")]
        dhcp_guarding: Option<NetworkDhcpGuarding>,
        #[serde(rename = "enabled")]
        enabled: bool,
        #[serde(rename = "name")]
        name: String,
        #[serde(rename = "vlanId")]
        vlan_id: i32,
        #[serde(rename = "cellularBackupEnabled")]
        cellular_backup_enabled: bool,
        #[serde(rename = "internetAccessEnabled")]
        internet_access_enabled: bool,
        #[serde(rename = "ipv4Configuration")]
        ipv4_configuration: Box<GatewayManagedIpv4Configuration>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "ipv6Configuration")]
        ipv6_configuration: Option<NetworkIpv6Configuration>,
        #[serde(rename = "isolationEnabled")]
        isolation_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "mdnsForwardingEnabled")]
        mdns_forwarding_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "zoneId")]
        zone_id: Option<String>,
    },
    #[serde(rename = "SWITCH")]
    Switch {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dhcpGuarding")]
        dhcp_guarding: Option<NetworkDhcpGuarding>,
        #[serde(rename = "enabled")]
        enabled: bool,
        #[serde(rename = "name")]
        name: String,
        #[serde(rename = "vlanId")]
        vlan_id: i32,
        #[serde(rename = "cellularBackupEnabled")]
        cellular_backup_enabled: bool,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "ipv4Configuration")]
        ipv4_configuration: SwitchManagedIpv4Configuration,
        #[serde(rename = "isolationEnabled")]
        isolation_enabled: bool,
    },
    #[serde(rename = "UNMANAGED")]
    Unmanaged {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dhcpGuarding")]
        dhcp_guarding: Option<NetworkDhcpGuarding>,
        #[serde(rename = "enabled")]
        enabled: bool,
        #[serde(rename = "name")]
        name: String,
        #[serde(rename = "vlanId")]
        vlan_id: i32,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NetworkDhcpGuarding {
    #[serde(rename = "trustedDhcpServerIpAddresses")]
    trusted_dhcp_server_ip_addresses: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GatewayManagedIpv4Configuration {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "additionalHostIpSubnets")]
    additional_host_ip_subnets: Option<Vec<String>>,
    #[serde(rename = "autoScaleEnabled")]
    auto_scale_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dhcpConfiguration")]
    dhcp_configuration: Option<GatewayManagedIpv4DhcpConfiguration>,
    #[serde(rename = "hostIpAddress")]
    host_ip_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "natOutboundIpAddressConfiguration")]
    nat_outbound_ip_address_configuration: Option<Vec<WanNatOutboundConfiguration>>,
    #[serde(rename = "prefixLength")]
    prefix_length: i32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "mode", deny_unknown_fields)]
pub(super) enum GatewayManagedIpv4DhcpConfiguration {
    #[serde(rename = "RELAY")]
    Relay {
        #[serde(rename = "dhcpServerIpAddresses")]
        dhcp_server_ip_addresses: Vec<String>,
    },
    #[serde(rename = "SERVER")]
    Server {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dnsServerIpAddressesOverride")]
        dns_server_ip_addresses_override: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "domainName")]
        domain_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "gatewayIpAddressOverride")]
        gateway_ip_address_override: Option<String>,
        #[serde(rename = "ipAddressRange")]
        ip_address_range: Box<IpAddressRange>,
        #[serde(rename = "leaseTimeSeconds")]
        lease_time_seconds: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "ntpServerIpAddresses")]
        ntp_server_ip_addresses: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "option43Value")]
        option43_value: Option<String>,
        #[serde(rename = "pingConflictDetectionEnabled")]
        ping_conflict_detection_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "pxeConfiguration")]
        pxe_configuration: Option<Box<PxeConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "tftpServerAddress")]
        tftp_server_address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "timeOffsetSeconds")]
        time_offset_seconds: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "winsServerIpAddresses")]
        wins_server_ip_addresses: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "wpadUrl")]
        wpad_url: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct IpAddressRange {
    #[serde(rename = "start")]
    start: String,
    #[serde(rename = "stop")]
    stop: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PxeConfiguration {
    #[serde(rename = "filename")]
    filename: String,
    #[serde(rename = "serverIpAddress")]
    server_ip_address: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum WanNatOutboundConfiguration {
    #[serde(rename = "AUTO")]
    Auto {
        #[serde(rename = "wanInterfaceId")]
        wan_interface_id: String,
        #[serde(rename = "ipAddressSelectionMode")]
        ip_address_selection_mode: IpAddressSelectionMode,
    },
    #[serde(rename = "STATIC")]
    Static {
        #[serde(rename = "wanInterfaceId")]
        wan_interface_id: String,
        #[serde(rename = "ipAddressSelectors")]
        ip_address_selectors: Vec<IpAddressSelector>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum IpAddressSelectionMode {
    #[serde(rename = "MAIN")]
    Main,
    #[serde(rename = "ALL")]
    All,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum IpAddressSelector {
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
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "interfaceType", deny_unknown_fields)]
pub(super) enum NetworkIpv6Configuration {
    #[serde(rename = "PREFIX_DELEGATION")]
    PrefixDelegation {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "additionalHostIpSubnets")]
        additional_host_ip_subnets: Option<Vec<String>>,
        #[serde(rename = "clientAddressAssignment")]
        client_address_assignment: Ipv6ClientAddressAssignment,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dnsServerIpAddressesOverride")]
        dns_server_ip_addresses_override: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "routerAdvertisement")]
        router_advertisement: Option<RouterAdvertisementConfiguration>,
        #[serde(rename = "prefixDelegationWanInterfaceId")]
        prefix_delegation_wan_interface_id: String,
    },
    #[serde(rename = "STATIC")]
    Static {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "additionalHostIpSubnets")]
        additional_host_ip_subnets: Option<Vec<String>>,
        #[serde(rename = "clientAddressAssignment")]
        client_address_assignment: Ipv6ClientAddressAssignment,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dnsServerIpAddressesOverride")]
        dns_server_ip_addresses_override: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "routerAdvertisement")]
        router_advertisement: Option<RouterAdvertisementConfiguration>,
        #[serde(rename = "hostIpAddress")]
        host_ip_address: String,
        #[serde(rename = "prefixLength")]
        prefix_length: i32,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Ipv6ClientAddressAssignment {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dhcpConfiguration")]
    dhcp_configuration: Option<DhcpConfigurationForIpv6Network>,
    #[serde(rename = "slaacEnabled")]
    slaac_enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct DhcpConfigurationForIpv6Network {
    #[serde(rename = "ipAddressSuffixRange")]
    ip_address_suffix_range: IntegrationIpv6AddressSuffixRangeSelectorDto,
    #[serde(rename = "leaseTimeSeconds")]
    lease_time_seconds: i32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct IntegrationIpv6AddressSuffixRangeSelectorDto {
    #[serde(rename = "start")]
    start: String,
    #[serde(rename = "stop")]
    stop: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RouterAdvertisementConfiguration {
    #[serde(rename = "priority")]
    priority: Priority,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum Priority {
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "HIGH")]
    High,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SwitchManagedIpv4Configuration {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "additionalHostIpSubnets")]
    additional_host_ip_subnets: Option<Vec<String>>,
    #[serde(rename = "autoScaleEnabled")]
    auto_scale_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dhcpConfiguration")]
    dhcp_configuration: Option<SwitchManagedIpv4DhcpConfiguration>,
    #[serde(rename = "hostIpAddress")]
    host_ip_address: String,
    #[serde(rename = "prefixLength")]
    prefix_length: i32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "mode", deny_unknown_fields)]
pub(super) enum SwitchManagedIpv4DhcpConfiguration {
    #[serde(rename = "RELAY")]
    Relay {
        #[serde(rename = "dhcpServerIpAddresses")]
        dhcp_server_ip_addresses: Vec<String>,
    },
    #[serde(rename = "SERVER")]
    Server {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dnsServerIpAddressesOverride")]
        dns_server_ip_addresses_override: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "domainName")]
        domain_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "gatewayIpAddressOverride")]
        gateway_ip_address_override: Option<String>,
        #[serde(rename = "ipAddressRange")]
        ip_address_range: IpAddressRange,
        #[serde(rename = "leaseTimeSeconds")]
        lease_time_seconds: i32,
    },
}
