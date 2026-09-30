//! Typed full Wi-Fi broadcast requests from the official Network Integration API.
//! The controller decides cross-field configuration validity.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Number;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum WifiBroadcastRequest {
    #[serde(rename = "IOT_OPTIMIZED")]
    IotOptimized {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "basicDataRateKbpsByFrequencyGHz")]
        basic_data_rate_kbps_by_frequency_ghz: Option<Box<WifiBasicDataRateConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "blackoutScheduleConfiguration")]
        blackout_schedule_configuration: Option<Box<BlackoutScheduleConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "broadcastingDeviceFilter")]
        broadcasting_device_filter: Option<Box<BroadcastingDeviceFilter>>,
        #[serde(rename = "channel2gLockedTo6")]
        channel2g_locked_to6: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "clientFilteringPolicy")]
        client_filtering_policy: Option<Box<WifiClientFilteringPolicy>>,
        #[serde(rename = "clientIsolationEnabled")]
        client_isolation_enabled: bool,
        #[serde(rename = "dtimPeriod2gLockedTo3")]
        dtim_period2g_locked_to3: bool,
        #[serde(rename = "enabled")]
        enabled: bool,
        #[serde(rename = "hideName")]
        hide_name: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "mdnsProxyConfiguration")]
        mdns_proxy_configuration: Option<Box<MdnsFilteringConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "multicastFilteringPolicy")]
        multicast_filtering_policy: Option<Box<MulticastFilteringPolicy>>,
        #[serde(rename = "multicastToUnicastConversionEnabled")]
        multicast_to_unicast_conversion_enabled: bool,
        #[serde(rename = "name")]
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "network")]
        network: Option<Box<WifiNetworkReference>>,
        #[serde(rename = "securityConfiguration")]
        security_configuration: Box<WifiSecurityConfiguration>,
        #[serde(rename = "uapsdEnabled")]
        uapsd_enabled: bool,
    },
    #[serde(rename = "STANDARD")]
    Standard {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "basicDataRateKbpsByFrequencyGHz")]
        basic_data_rate_kbps_by_frequency_ghz: Option<Box<WifiBasicDataRateConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "blackoutScheduleConfiguration")]
        blackout_schedule_configuration: Option<Box<BlackoutScheduleConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "broadcastingDeviceFilter")]
        broadcasting_device_filter: Option<Box<BroadcastingDeviceFilter>>,
        #[serde(rename = "channel2gLockedTo6")]
        channel2g_locked_to6: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "clientFilteringPolicy")]
        client_filtering_policy: Option<Box<WifiClientFilteringPolicy>>,
        #[serde(rename = "clientIsolationEnabled")]
        client_isolation_enabled: bool,
        #[serde(rename = "dtimPeriod2gLockedTo3")]
        dtim_period2g_locked_to3: bool,
        #[serde(rename = "enabled")]
        enabled: bool,
        #[serde(rename = "hideName")]
        hide_name: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "mdnsProxyConfiguration")]
        mdns_proxy_configuration: Option<Box<MdnsFilteringConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "multicastFilteringPolicy")]
        multicast_filtering_policy: Option<Box<MulticastFilteringPolicy>>,
        #[serde(rename = "multicastToUnicastConversionEnabled")]
        multicast_to_unicast_conversion_enabled: bool,
        #[serde(rename = "name")]
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "network")]
        network: Option<Box<WifiNetworkReference>>,
        #[serde(rename = "securityConfiguration")]
        security_configuration: Box<WifiSecurityConfiguration>,
        #[serde(rename = "uapsdEnabled")]
        uapsd_enabled: bool,
        #[serde(rename = "advertiseDeviceName")]
        advertise_device_name: bool,
        #[serde(rename = "arpProxyEnabled")]
        arp_proxy_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "bandSteeringEnabled")]
        band_steering_enabled: Option<bool>,
        #[serde(rename = "broadcastingFrequenciesGHz")]
        broadcasting_frequencies_ghz: Vec<Number>,
        #[serde(rename = "bssTransitionEnabled")]
        bss_transition_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dnsAssistanceConfiguration")]
        dns_assistance_configuration: Option<Box<DnsAssistanceConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "dtimPeriodByFrequencyGHzOverride")]
        dtim_period_by_frequency_ghz_override: Option<Box<WifiDtimPeriodConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "handoffSuggestionsConfiguration")]
        handoff_suggestions_configuration: Option<Box<WifiHandoffSuggestionsConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "hotspotConfiguration")]
        hotspot_configuration: Option<Box<WifiHotspotConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "mloEnabled")]
        mlo_enabled: Option<bool>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiBasicDataRateConfiguration {
    #[serde(rename = "5")]
    five: i32,
    #[serde(rename = "2.4")]
    two_point_four: i32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct BlackoutScheduleConfiguration {
    #[serde(rename = "days")]
    days: Vec<BlackoutScheduleConfigurationPerDay>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum BlackoutScheduleConfigurationPerDay {
    #[serde(rename = "ALL_DAY")]
    AllDay {
        #[serde(rename = "day")]
        day: Day,
    },
    #[serde(rename = "TIME_RANGE")]
    TimeRange {
        #[serde(rename = "day")]
        day: Day,
        #[serde(rename = "timeRanges")]
        time_ranges: Vec<WifiBlackoutScheduleConfigurationTimeRange>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum Day {
    #[serde(rename = "SUN")]
    Sun,
    #[serde(rename = "MON")]
    Mon,
    #[serde(rename = "TUE")]
    Tue,
    #[serde(rename = "WED")]
    Wed,
    #[serde(rename = "THU")]
    Thu,
    #[serde(rename = "FRI")]
    Fri,
    #[serde(rename = "SAT")]
    Sat,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiBlackoutScheduleConfigurationTimeRange {
    #[serde(rename = "endTime")]
    end_time: String,
    #[serde(rename = "startTime")]
    start_time: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum BroadcastingDeviceFilter {
    #[serde(rename = "DEVICES")]
    Devices {
        #[serde(rename = "deviceIds")]
        device_ids: Vec<String>,
    },
    #[serde(rename = "DEVICE_TAGS")]
    DeviceTags {
        #[serde(rename = "deviceTagIds")]
        device_tag_ids: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiClientFilteringPolicy {
    #[serde(rename = "action")]
    action: Action,
    #[serde(rename = "macAddressFilter")]
    mac_address_filter: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum Action {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "BLOCK")]
    Block,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "mode", deny_unknown_fields)]
pub(super) enum MdnsFilteringConfiguration {
    #[serde(rename = "AUTO")]
    Auto,
    #[serde(rename = "CUSTOM")]
    Custom {
        #[serde(rename = "policies")]
        policies: Vec<MdnsProxyPolicy>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "action", deny_unknown_fields)]
pub(super) enum MdnsProxyPolicy {
    #[serde(rename = "ALLOW")]
    Allow {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "deviceFilter")]
        device_filter: Option<Box<BroadcastingDeviceFilter>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "bridgingNetworkIds")]
        bridging_network_ids: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "serviceFilter")]
        service_filter: Option<Vec<MdnsService>>,
    },
    #[serde(rename = "BLOCK")]
    Block {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "deviceFilter")]
        device_filter: Option<Box<BroadcastingDeviceFilter>>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum MdnsService {
    #[serde(rename = "CUSTOM")]
    Custom {
        #[serde(rename = "name")]
        name: String,
        #[serde(rename = "typeDomain")]
        type_domain: String,
    },
    #[serde(rename = "PREDEFINED")]
    Predefined {
        #[serde(rename = "name")]
        name: PredefinedMdnsService,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum PredefinedMdnsService {
    #[serde(rename = "AMAZON_DEVICES")]
    AmazonDevices,
    #[serde(rename = "ANDROID_TV_REMOTE")]
    AndroidTvRemote,
    #[serde(rename = "APPLE_AIR_DROP")]
    AppleAirDrop,
    #[serde(rename = "APPLE_AIR_PLAY")]
    AppleAirPlay,
    #[serde(rename = "APPLE_FILE_SHARING")]
    AppleFileSharing,
    #[serde(rename = "APPLE_ICHAT")]
    AppleIchat,
    #[serde(rename = "APPLE_ITUNES")]
    AppleItunes,
    #[serde(rename = "AQARA")]
    Aqara,
    #[serde(rename = "BOSE")]
    Bose,
    #[serde(rename = "DNS_SERVICE_DISCOVERY")]
    DnsServiceDiscovery,
    #[serde(rename = "FTP_SERVERS")]
    FtpServers,
    #[serde(rename = "GOOGLE_CHROMECAST")]
    GoogleChromecast,
    #[serde(rename = "HOMEKIT")]
    Homekit,
    #[serde(rename = "MATTER_NETWORK")]
    MatterNetwork,
    #[serde(rename = "PHILIPS_HUE")]
    PhilipsHue,
    #[serde(rename = "PRINTERS")]
    Printers,
    #[serde(rename = "ROKU")]
    Roku,
    #[serde(rename = "SCANNERS")]
    Scanners,
    #[serde(rename = "SONOS")]
    Sonos,
    #[serde(rename = "SPOTIFY_CONNECT")]
    SpotifyConnect,
    #[serde(rename = "SSH_SERVERS")]
    SshServers,
    #[serde(rename = "TIME_CAPSULE")]
    TimeCapsule,
    #[serde(rename = "WEB_SERVERS")]
    WebServers,
    #[serde(rename = "WINDOWS_FILE_SHARING_SAMBA")]
    WindowsFileSharingSamba,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "action", deny_unknown_fields)]
pub(super) enum MulticastFilteringPolicy {
    #[serde(rename = "ALLOW")]
    Allow {
        #[serde(rename = "sourceMacAddressFilter")]
        source_mac_address_filter: Vec<String>,
    },
    #[serde(rename = "BLOCK")]
    Block,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum WifiNetworkReference {
    #[serde(rename = "NATIVE")]
    Native,
    #[serde(rename = "SPECIFIC")]
    Specific {
        #[serde(rename = "networkId")]
        network_id: String,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum WifiSecurityConfiguration {
    #[serde(rename = "OPEN")]
    Open {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "radiusConfiguration")]
        radius_configuration: Option<Box<WifiNonEnterpriseRadiusConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "encryption")]
        encryption: Option<Encryption>,
    },
    #[serde(rename = "WPA2_ENTERPRISE")]
    Wpa2Enterprise {
        #[serde(rename = "radiusConfiguration")]
        radius_configuration: Box<WifiEnterpriseRadiusConfiguration>,
        #[serde(rename = "coaEnabled")]
        coa_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "fastRoamingEnabled")]
        fast_roaming_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "groupRekeyIntervalSeconds")]
        group_rekey_interval_seconds: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "pmfMode")]
        pmf_mode: Option<PmfMode>,
    },
    #[serde(rename = "WPA2_PERSONAL")]
    Wpa2Personal {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "radiusConfiguration")]
        radius_configuration: Option<Box<WifiNonEnterpriseRadiusConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "fastRoamingEnabled")]
        fast_roaming_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "groupRekeyIntervalSeconds")]
        group_rekey_interval_seconds: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "passphrase")]
        passphrase: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "pmfMode")]
        pmf_mode: Option<PmfMode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "presharedKeys")]
        preshared_keys: Option<Vec<WifiPresharedKey>>,
    },
    #[serde(rename = "WPA2_WPA3_ENTERPRISE")]
    Wpa2Wpa3Enterprise {
        #[serde(rename = "radiusConfiguration")]
        radius_configuration: Box<WifiEnterpriseRadiusConfiguration>,
        #[serde(rename = "coaEnabled")]
        coa_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "fastRoamingEnabled")]
        fast_roaming_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "groupRekeyIntervalSeconds")]
        group_rekey_interval_seconds: Option<i32>,
        #[serde(rename = "pmfMode")]
        pmf_mode: PmfMode,
        #[serde(rename = "wpa3FastRoamingEnabled")]
        wpa3_fast_roaming_enabled: bool,
    },
    #[serde(rename = "WPA2_WPA3_PERSONAL")]
    Wpa2Wpa3Personal {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "radiusConfiguration")]
        radius_configuration: Option<Box<WifiNonEnterpriseRadiusConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "fastRoamingEnabled")]
        fast_roaming_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "groupRekeyIntervalSeconds")]
        group_rekey_interval_seconds: Option<i32>,
        #[serde(rename = "passphrase")]
        passphrase: String,
        #[serde(rename = "pmfMode")]
        pmf_mode: PmfMode,
        #[serde(rename = "saeConfiguration")]
        sae_configuration: Box<WifiSaeConfiguration>,
        #[serde(rename = "wpa3FastRoamingEnabled")]
        wpa3_fast_roaming_enabled: bool,
    },
    #[serde(rename = "WPA3_ENTERPRISE")]
    Wpa3Enterprise {
        #[serde(rename = "radiusConfiguration")]
        radius_configuration: Box<WifiEnterpriseRadiusConfiguration>,
        #[serde(rename = "coaEnabled")]
        coa_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "fastRoamingEnabled")]
        fast_roaming_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "groupRekeyIntervalSeconds")]
        group_rekey_interval_seconds: Option<i32>,
        #[serde(rename = "securityMode")]
        security_mode: SecurityMode,
    },
    #[serde(rename = "WPA3_PERSONAL")]
    Wpa3Personal {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "radiusConfiguration")]
        radius_configuration: Option<Box<WifiNonEnterpriseRadiusConfiguration>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "fastRoamingEnabled")]
        fast_roaming_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "groupRekeyIntervalSeconds")]
        group_rekey_interval_seconds: Option<i32>,
        #[serde(rename = "passphrase")]
        passphrase: String,
        #[serde(rename = "saeConfiguration")]
        sae_configuration: Box<WifiSaeConfiguration>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiNonEnterpriseRadiusConfiguration {
    #[serde(rename = "macAuthenticationConfiguration")]
    mac_authentication_configuration: Box<WifiRadiusMacAuthenticationConfiguration>,
    #[serde(rename = "nasId")]
    nas_id: Box<WifiRadiusNasIdConfiguration>,
    #[serde(rename = "profileId")]
    profile_id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiRadiusMacAuthenticationConfiguration {
    #[serde(rename = "macAddressFormat")]
    mac_address_format: MacAddressFormat,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum MacAddressFormat {
    #[serde(rename = "UPPERCASE_NOT_SEPARATED")]
    UppercaseCompact,
    #[serde(rename = "UPPERCASE_DASH_SEPARATED")]
    UppercaseDash,
    #[serde(rename = "UPPERCASE_COLON_SEPARATED")]
    UppercaseColon,
    #[serde(rename = "LOWERCASE_NOT_SEPARATED")]
    LowercaseCompact,
    #[serde(rename = "LOWERCASE_COLON_SEPARATED")]
    LowercaseColon,
    #[serde(rename = "LOWERCASE_DASH_SEPARATED")]
    LowercaseDash,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum WifiRadiusNasIdConfiguration {
    #[serde(rename = "DERIVED")]
    Derived {
        #[serde(rename = "source")]
        source: Source,
    },
    #[serde(rename = "USER_DEFINED")]
    UserDefined {
        #[serde(rename = "value")]
        value: String,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum Source {
    #[serde(rename = "DEVICE_MAC_ADDRESS")]
    DeviceMacAddress,
    #[serde(rename = "DEVICE_NAME")]
    DeviceName,
    #[serde(rename = "SITE_NAME")]
    SiteName,
    #[serde(rename = "BSSID")]
    Bssid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum Encryption {
    #[serde(rename = "ENHANCED_OPEN")]
    EnhancedOpen,
    #[serde(rename = "ENHANCED_OPEN_WITH_TRANSITION")]
    EnhancedOpenWithTransition,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiEnterpriseRadiusConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "macAuthenticationConfiguration")]
    mac_authentication_configuration: Option<Box<WifiRadiusMacAuthenticationConfiguration>>,
    #[serde(rename = "nasId")]
    nas_id: Box<WifiRadiusNasIdConfiguration>,
    #[serde(rename = "profileId")]
    profile_id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum PmfMode {
    #[serde(rename = "REQUIRED")]
    Required,
    #[serde(rename = "OPTIONAL")]
    Optional,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiPresharedKey {
    #[serde(rename = "network")]
    network: Box<WifiNetworkReference>,
    #[serde(rename = "passphrase")]
    passphrase: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiSaeConfiguration {
    #[serde(rename = "anticloggingThresholdSeconds")]
    anticlogging_threshold_seconds: i32,
    #[serde(rename = "syncTimeSeconds")]
    sync_time_seconds: i32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) enum SecurityMode {
    #[serde(rename = "DEFAULT")]
    Default,
    #[serde(rename = "HIGH_SECURITY_192_BIT")]
    HighSecurity192Bit,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "mode", deny_unknown_fields)]
pub(super) enum DnsAssistanceConfiguration {
    #[serde(rename = "AUTO")]
    Auto,
    #[serde(rename = "MANUAL")]
    Manual {
        #[serde(rename = "servers")]
        servers: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiDtimPeriodConfiguration {
    #[serde(rename = "5")]
    five: i32,
    #[serde(rename = "6")]
    six: i32,
    #[serde(rename = "2.4")]
    two_point_four: i32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct WifiHandoffSuggestionsConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "band5GHzRssiThreshold")]
    band5_ghz_rssi_threshold: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "band6GHzRssiThreshold")]
    band6_ghz_rssi_threshold: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum WifiHotspotConfiguration {
    #[serde(rename = "CAPTIVE_PORTAL")]
    CaptivePortal,
    #[serde(rename = "PASSPOINT")]
    Passpoint,
}
