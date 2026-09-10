//! End-to-end fixture tests for the firewall and networks audit reads,
//! covering both console firewall generations and the secret-redaction
//! contract against loopback fakes.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::{IdentityPrincipal, UnifiMcp};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const API_KEY: &str = "test-integration-key";
const USERNAME: &str = "svc-mcp";
const PASSWORD: &str = "test-legacy-password";
const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const WIFI_PASSPHRASE: &str = "wifi-secret-passphrase";
const LEGACY: &str = "/proxy/network/api/s/default";

fn ok_envelope(data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"meta": {"rc": "ok"}, "data": data})
}

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new(API_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "home",
        "default",
        vec![
            Zeroizing::new(API_KEY.to_owned()),
            Zeroizing::new(PASSWORD.to_owned()),
        ],
    )
}

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

fn principal(groups: &[&str]) -> IdentityPrincipal {
    IdentityPrincipal {
        subject: "user:test".to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
    }
}

async fn common_mocks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 100,
            "count": 1,
            "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(server)
        .await;
    for (endpoint, data) in [
        (
            "portforward",
            serde_json::json!([{
                "_id": "pf-1", "name": "plex", "enabled": true, "src": "any",
                "fwd": "192.168.1.10", "fwd_port": "32400", "dst_port": "32400",
                "proto": "tcp"
            }]),
        ),
        (
            "trafficrule",
            serde_json::json!([{
                "_id": "tr-1", "description": "block iot wan", "enabled": true,
                "action": "BLOCK", "matching_target": "INTERNET",
                "network_id": "net-iot", "domains": []
            }]),
        ),
        ("trafficroute", serde_json::json!([])),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("{LEGACY}/rest/{endpoint}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(&data)))
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn firewall_read_labels_a_zone_based_console() {
    let server = MockServer::start().await;
    common_mocks(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 200,
            "count": 2,
            "totalCount": 2,
            "data": [
                {"id": "zone-internal", "name": "Internal"},
                {"id": "zone-external", "name": "External"},
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/policies"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0,
            "limit": 200,
            "count": 1,
            "totalCount": 1,
            "data": [{
                "id": "policy-1", "name": "Allow LAN", "enabled": true, "action": "ALLOW",
                "index": 3, "protocol": "tcp",
                "source": {"zoneId": "zone-internal", "port": "1024-65535"},
                "destination": {"zoneId": "zone-external", "port": "443"},
            }],
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("firewall.read", &serde_json::json!({})), None)
        .await
        .expect("firewall read");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["generation"], "zoneBased");
    assert!(
        output["generationNote"]
            .as_str()
            .expect("note")
            .contains("classic console is refused")
    );
    assert_eq!(output["zones"].as_array().expect("zones").len(), 2);
    assert_eq!(output["policies"][0]["action"], "ALLOW");
    // The audit view carries what the policy governs, not just its name.
    assert_eq!(output["policies"][0]["sourceZoneId"], "zone-internal");
    assert_eq!(output["policies"][0]["sourcePort"], "1024-65535");
    assert_eq!(output["policies"][0]["destinationZoneId"], "zone-external");
    assert_eq!(output["policies"][0]["destinationPort"], "443");
    assert_eq!(output["policies"][0]["index"], 3);
    assert_eq!(output["portForwards"][0]["forwardPort"], "32400");
    assert_eq!(output["trafficRules"][0]["matchingTarget"], "INTERNET");
    assert!(output.get("sectionsTruncated").is_none());
}

#[tokio::test]
async fn an_over_ceiling_policy_inventory_returns_bounded_and_truncated() {
    let server = MockServer::start().await;
    common_mocks(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 200, "count": 1, "totalCount": 1,
            "data": [{"id": "zone-internal", "name": "Internal"}],
        })))
        .mount(&server)
        .await;
    let filler: Vec<serde_json::Value> = (0..200)
        .map(|index| serde_json::json!({"id": format!("policy-{index}")}))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/policies"
        )))
        .and(wiremock::matchers::query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 200, "count": 200, "totalCount": 1500,
            "data": filler,
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    // The bounded page returns successfully with the truncation flag, so a
    // large inventory is visibly partial rather than rejected wholesale.
    let result = handler
        .call(&call("firewall.read", &serde_json::json!({})), None)
        .await
        .expect("firewall read");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["sectionsTruncated"], true);
    assert_eq!(output["policies"].as_array().expect("policies").len(), 200);
    // An unnarrowed read has no single section to offer an offset for, so the
    // flag must still name what was cut and the narrowing that reaches it.
    assert!(output.get("nextSectionOffset").is_none());
    let note = output["truncationNote"].as_str().expect("note");
    assert!(note.contains("policies"), "{note}");
    assert!(
        note.contains("section") && note.contains("sectionOffset"),
        "{note}"
    );
    // Only the section that was actually cut is named.
    assert!(!note.contains("zones"), "{note}");
}

#[tokio::test]
async fn a_classic_console_is_refused_by_name_rather_than_read_as_an_open_network() {
    let server = MockServer::start().await;
    common_mocks(&server).await;
    // The documented classic-console rejection of the zone probe.
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "message": "feature requires the zone based firewall"
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    // Unnarrowed, and narrowed to each generation-specific section: all three
    // refuse. Returning the sections a classic console does have, with the
    // firewall silently absent, would read as an open network to a caller
    // auditing one -- which is the whole reason this refuses.
    for narrowing in [
        serde_json::json!({}),
        serde_json::json!({"section": "zones"}),
        serde_json::json!({"section": "policies"}),
    ] {
        let error = handler
            .call(&call("firewall.read", &narrowing), None)
            .await
            .expect_err("classic console refused");
        let message = error.message.to_string();
        assert!(
            message.contains("classic firewall"),
            "refusal must name the generation, got: {message}"
        );
        assert!(
            message.contains("portForwards"),
            "refusal must name what still reads on this console, got: {message}"
        );
    }
}

async fn networks_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/networkconf")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([{
                "_id": "net-1", "name": "LAN", "purpose": "corporate", "vlan": 10,
                "ip_subnet": "192.168.10.1/24", "enabled": true, "dhcpd_enabled": true,
                "dhcpd_start": "192.168.10.100", "dhcpd_stop": "192.168.10.200"
            }]))),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/wlanconf")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([{
                "_id": "wlan-1", "name": "HomeNet", "enabled": true, "security": "wpapsk",
                "x_passphrase": WIFI_PASSPHRASE, "networkconf_id": "net-1",
                "hide_ssid": false
            }]))),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn networks_read_redacts_passphrases_by_default() {
    let server = MockServer::start().await;
    networks_mocks(&server).await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("networks.read", &serde_json::json!({})), None)
        .await
        .expect("networks read");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["networks"][0]["vlan"], 10);
    assert_eq!(output["networks"][0]["dhcpStart"], "192.168.10.100");
    assert_eq!(output["wlans"][0]["ssid"], "HomeNet");
    assert_eq!(output["wlans"][0]["network"], "LAN");
    assert_eq!(output["wlans"][0]["passphrase"], "[redacted]");
    assert!(!output.to_string().contains(WIFI_PASSPHRASE));
}

#[tokio::test]
async fn the_section_filter_narrows_the_response() {
    let server = MockServer::start().await;
    networks_mocks(&server).await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("networks.read", &serde_json::json!({"section": "wlans"})),
            None,
        )
        .await
        .expect("wlans section");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["networks"], serde_json::json!([]));
    // Name resolution still works in the narrowed section.
    assert_eq!(output["wlans"][0]["network"], "LAN");

    let result = handler
        .call(
            &call("networks.read", &serde_json::json!({"section": "networks"})),
            None,
        )
        .await
        .expect("networks section");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["wlans"], serde_json::json!([]));
    assert_eq!(output["networks"][0]["vlan"], 10);
}

#[tokio::test]
async fn secret_disclosure_requires_the_admin_group() {
    let server = MockServer::start().await;
    networks_mocks(&server).await;
    let handler = handler_for(&server);
    let request = call(
        "networks.read",
        &serde_json::json!({"includeSecrets": true}),
    );

    // No principal and a non-admin principal are both refused.
    let error = handler.call(&request, None).await.expect_err("no identity");
    assert!(error.message.contains("mcp-admins"));
    let error = handler
        .call(&request, Some(&principal(&["unifi"])))
        .await
        .expect_err("non-admin");
    assert!(error.message.contains("mcp-admins"));

    // An admin explicitly opting in receives the configured passphrase.
    let result = handler
        .call(&request, Some(&principal(&["unifi", "mcp-admins"])))
        .await
        .expect("admin disclosure");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["wlans"][0]["passphrase"], WIFI_PASSPHRASE);
}

#[tokio::test]
async fn a_truncated_policy_section_is_continuable_by_offset() {
    let server = MockServer::start().await;
    common_mocks(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 200, "count": 0, "totalCount": 0, "data": [],
        })))
        .mount(&server)
        .await;
    // 300 policies upstream: the first call returns the 200-row ceiling with
    // a continuation, and the continuation returns the remaining 100.
    for page_start in [0_u64, 200] {
        let remaining = 300 - page_start;
        let count = remaining.min(200);
        let rows: Vec<serde_json::Value> = (page_start..page_start + count)
            .map(|index| serde_json::json!({"id": format!("policy-{index}")}))
            .collect();
        Mock::given(method("GET"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/firewall/policies"
            )))
            .and(wiremock::matchers::query_param(
                "offset",
                page_start.to_string(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "offset": page_start, "limit": 200, "count": count, "totalCount": 300,
                "data": rows,
            })))
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("firewall.read", &serde_json::json!({"section": "policies"})),
            None,
        )
        .await
        .expect("first page");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["section"], "policies");
    assert_eq!(output["policies"].as_array().expect("policies").len(), 200);
    assert_eq!(output["sectionsTruncated"], true);
    assert_eq!(output["nextSectionOffset"], 200);
    // Narrowing means the other sections were filtered, not empty upstream.
    assert_eq!(output["portForwards"], serde_json::json!([]));

    // The continuation reaches the rows past the ceiling and ends clean.
    let result = handler
        .call(
            &call(
                "firewall.read",
                &serde_json::json!({"section": "policies", "sectionOffset": 200}),
            ),
            None,
        )
        .await
        .expect("continuation");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["policies"].as_array().expect("policies").len(), 100);
    assert_eq!(output["policies"][0]["id"], "policy-200");
    assert!(output.get("sectionsTruncated").is_none());
    assert!(output.get("nextSectionOffset").is_none());
}

#[tokio::test]
async fn section_offset_is_rejected_outside_the_paginated_sections() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);

    let error = handler
        .call(
            &call(
                "firewall.read",
                &serde_json::json!({"section": "portForwards", "sectionOffset": 10}),
            ),
            None,
        )
        .await
        .expect_err("unsupported section offset");
    assert!(error.message.contains("zones or policies"));

    let error = handler
        .call(
            &call(
                "firewall.read",
                &serde_json::json!({"section": "policies", "sectionOffset": 200_000}),
            ),
            None,
        )
        .await
        .expect_err("offset ceiling");
    assert!(error.message.contains("sectionOffset"));
}

#[tokio::test]
async fn narrowing_isolates_a_section_from_unrelated_endpoint_failures() {
    let server = MockServer::start().await;
    common_mocks(&server).await;
    // A zone-based console whose policy endpoint is failing. The generation is
    // incidental here: what is under test is that a narrowing never pays for
    // an endpoint it did not ask for.
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 200, "count": 1, "totalCount": 1,
            "data": [{"id": "zone-internal", "name": "Internal"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/policies"
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    // Narrowing to an unrelated section succeeds: it never touches them.
    let result = handler
        .call(
            &call(
                "firewall.read",
                &serde_json::json!({"section": "portForwards"}),
            ),
            None,
        )
        .await
        .expect("narrowed read");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["section"], "portForwards");
    assert_eq!(output["portForwards"][0]["forwardPort"], "32400");

    // The composite read still surfaces the upstream failure.
    let error = handler
        .call(&call("firewall.read", &serde_json::json!({})), None)
        .await
        .expect_err("composite read");
    assert!(error.message.contains("controller returned HTTP 500"));
}

#[tokio::test]
async fn a_continuation_past_the_offset_bound_explains_instead_of_lying() {
    let server = MockServer::start().await;
    common_mocks(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 200, "count": 0, "totalCount": 0, "data": [],
        })))
        .mount(&server)
        .await;
    // A scan starting at the accepted maximum that still truncates: the
    // next offset would exceed the cap, so no offset may be advertised.
    for page_start in [100_000_u64, 100_200] {
        let rows: Vec<serde_json::Value> = (page_start..page_start + 200)
            .map(|index| serde_json::json!({"id": format!("policy-{index}")}))
            .collect();
        Mock::given(method("GET"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/firewall/policies"
            )))
            .and(wiremock::matchers::query_param(
                "offset",
                page_start.to_string(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "offset": page_start, "limit": 200, "count": 200, "totalCount": 500_000,
                "data": rows,
            })))
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call(
                "firewall.read",
                &serde_json::json!({"section": "policies", "sectionOffset": 100_000}),
            ),
            None,
        )
        .await
        .expect("boundary read");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["sectionsTruncated"], true);
    assert!(output.get("nextSectionOffset").is_none());
    let note = output["truncationNote"].as_str().expect("note");
    assert!(note.contains("sectionOffset bound"));
}

#[tokio::test]
async fn a_generation_agnostic_narrowing_needs_no_integration_call() {
    let server = MockServer::start().await;
    // Every Integration endpoint is down, including the site lookup: a
    // legacy-only narrowing addresses the controller by its configured site
    // name and must not depend on any of them.
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/info")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{LEGACY}/rest/portforward")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ok_envelope(&serde_json::json!([
                {"_id": "pf-1", "name": "plex", "enabled": true, "fwd_port": "32400"}
            ]))),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    // The narrowed section exists identically on both generations, so the
    // read succeeds and reports no generation rather than guessing one.
    let result = handler
        .call(
            &call(
                "firewall.read",
                &serde_json::json!({"section": "portForwards"}),
            ),
            None,
        )
        .await
        .expect("narrowed read");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["portForwards"][0]["forwardPort"], "32400");
    assert!(output.get("generation").is_none());
    assert!(output.get("generationNote").is_none());

    // A generation-specific narrowing still surfaces the probe failure.
    let error = handler
        .call(
            &call("firewall.read", &serde_json::json!({"section": "policies"})),
            None,
        )
        .await
        .expect_err("generation-specific narrowing");
    assert!(error.message.contains("controller returned HTTP 503"));
}
