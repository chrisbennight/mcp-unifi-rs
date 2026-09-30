//! Typed legacy WLAN fields, using the controller's request names.

use super::{Deserialize, JsonSchema, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyWlanConfiguration {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ap_group_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ap_group_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_hidden: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_hidden_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_no_delete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attr_no_edit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_cache: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bc_filter_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bc_filter_list: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bss_transition: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_beacon: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpi_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpigroup_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dtim_6e: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dtim_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dtim_na: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dtim_ng: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    element_adopt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fast_roaming_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_rekey: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hide_ssid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hotspot2conf_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hotspot2conf_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iapp_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_guest: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    l2_isolation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_filter_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_filter_list: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_filter_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcastenhance_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minrate_na_advertising_rates: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minrate_na_data_rate_kbps: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minrate_na_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minrate_ng_advertising_rates: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minrate_ng_data_rate_kbps: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minrate_ng_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minrate_setting_preference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_combine_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_combine_suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    networkconf_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no2ghz_oui: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    optimize_iot_wifi_connectivity: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_cross_connect: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pmf_cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pmf_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_preshared_keys: Option<Vec<LegacyPrivatePresharedKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_preshared_keys_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_arp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    radius_das_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    radius_mac_auth_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    radius_macacl_empty_password: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    radius_macacl_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    radiusprofile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    roam_cluster_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rrm_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sae_anti_clogging: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sae_groups: Option<Vec<i64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sae_psk: Option<Vec<LegacySaePsk>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sae_psk_vlan_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sae_sync: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule_reversed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule_with_duration: Option<Vec<LegacySchedule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    setting_preference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    site_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tdls_prohibit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uapsd_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid_workspace_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usergroup_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wep_idx: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wlan_band: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wlan_bands: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wlangroup_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wpa_enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wpa_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wpa_psk_radius: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wpa3_enhanced_192: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wpa3_fast_roaming: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wpa3_support: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wpa3_transition: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x_iapp_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x_passphrase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x_wep: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacySaePsk {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    psk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyPrivatePresharedKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    networkconf_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacySchedule {
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_minutes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_days_of_week: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_hour: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_minute: Option<i64>,
}
