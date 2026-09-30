use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const POLICY_ID: &str = "f435b097-683e-4bc4-8d3a-453c968a48fb";

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock URL");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("test-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: "test-user".to_owned(),
        password: Zeroizing::new("test-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn call(arguments: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "firewall.policies.configure".into();
    params.arguments = Some(match arguments {
        Value::Object(map) => map,
        _ => panic!("object arguments"),
    });
    params
}

async fn mount_site(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset":0,"limit":100,"count":1,"totalCount":1,
            "data":[{"id":SITE_ID,"name":"Default","internalReference":"default"}]
        })))
        .mount(server)
        .await;
}

fn policy() -> Value {
    json!({"name":"Lab egress","description":"Full policy authoring",
        "enabled":true,"loggingEnabled":true,
        "action":{"type":"ALLOW","allowReturnTraffic":true},
        "source":{"zoneId":SITE_ID},"destination":{"zoneId":POLICY_ID},
        "ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6"},
        "connectionStateFilter":["NEW","ESTABLISHED"],"ipsecFilter":"MATCH_NOT_ENCRYPTED"})
}

async fn preview(handler: &UnifiMcp, requested: Value) {
    let result = handler
        .call(
            &call(json!({"operation":"create","policy":requested})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(result["kind"], "firewallPolicies");
    assert_eq!(result["submitted"], false);
    assert_eq!(result["requested"], requested);
}

#[tokio::test]
async fn replacement_verification_detects_retained_optional_constraints() {
    for retained in ["none", "schedule", "source", "nestedPort", "icmpType"] {
        let server = MockServer::start().await;
        mount_site(&server).await;
        let mut requested = policy();
        if retained == "nestedPort" {
            requested["source"]["trafficFilter"] = json!({"type":"NETWORK","networkFilter":{"networkIds":[SITE_ID],"matchOpposite":false}});
        }
        if retained == "icmpType" {
            requested["ipProtocolScope"]["protocolFilter"] =
                json!({"type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"icmp"}});
        }
        let mut observed = requested.clone();
        observed["id"] = json!(POLICY_ID);
        observed["controllerExtension"] = json!({"unknown":"retained"});
        match retained {
            "schedule" => {
                observed["schedule"] = json!({"mode":"EVERY_WEEK","repeatOnDays":["MONDAY"]});
            }
            "source" => {
                observed["source"]["trafficFilter"] = json!({"type":"NETWORK","networkFilter":{"networkIds":[SITE_ID],"matchOpposite":false}});
            }
            "nestedPort" => {
                observed["source"]["trafficFilter"]["portFilter"] = json!({"type":"PORTS","matchOpposite":false,"items":[{"type":"PORT_NUMBER","value":443}]});
            }
            "icmpType" => {
                observed["ipProtocolScope"]["protocolFilter"]["protocol"]["typenameFilter"] =
                    json!("ECHO_REQUEST");
            }
            _ => {}
        }
        let route = format!("{PREFIX}/sites/{SITE_ID}/firewall/policies/{POLICY_ID}");
        Mock::given(method("PUT"))
            .and(path(&route))
            .and(body_json(requested.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&observed))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(&route))
            .respond_with(ResponseTemplate::new(200).set_body_json(&observed))
            .expect(1)
            .mount(&server)
            .await;
        let output = handler_for(&server)
            .call(
                &call(
                    json!({"operation":"update","id":POLICY_ID,"policy":requested,"confirm":true}),
                ),
                None,
            )
            .await
            .expect("accepted replacement")
            .structured_content
            .expect("structured");
        assert_eq!(output["submitted"], true);
        assert_eq!(output["verified"], retained == "none", "{retained}");
        assert_eq!(output["accepted"], observed);
        assert_eq!(output["after"], observed);
        server.verify().await;
    }
}

#[tokio::test]
async fn previews_cover_source_and_destination_filter_families_without_upstream_calls() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let ports = json!({"type":"PORTS","matchOpposite":false,"items":[
        {"type":"PORT_NUMBER","value":443},{"type":"PORT_NUMBER_RANGE","start":8000,"stop":8080}]});
    let reference_ports = json!({"type":"TRAFFIC_MATCHING_LIST","matchOpposite":true,"trafficMatchingListId":POLICY_ID});
    let shared = [
        json!({"type":"IPV6_IID","ipv6IidFilter":{"ipv6Iid":"::1234","matchOpposite":false}}),
        json!({"type":"IP_ADDRESS","ipAddressFilter":{"type":"IP_ADDRESSES","matchOpposite":true,"items":[
            {"type":"IP_ADDRESS","value":"192.0.2.1"},{"type":"IP_ADDRESS_RANGE","start":"192.0.2.3","stop":"192.0.2.5"},
            {"type":"SUBNET","value":"2001:db8::/64"}]}}),
        json!({"type":"IP_ADDRESS","ipAddressFilter":{"type":"TRAFFIC_MATCHING_LIST","matchOpposite":false,"trafficMatchingListId":POLICY_ID}}),
        json!({"type":"NETWORK","networkFilter":{"networkIds":[SITE_ID],"matchOpposite":true}}),
        json!({"type":"PORT","portFilter":reference_ports}),
        json!({"type":"REGION","regionFilter":{"regions":["US","XK"]}}),
        json!({"type":"SITE_TO_SITE_VPN_TUNNEL","siteToSiteVpnTunnelFilter":{"siteToSiteVpnTunnelId":POLICY_ID}}),
        json!({"type":"VPN_SERVER","vpnServerFilter":{"vpnServerIds":[POLICY_ID],"matchOpposite":false}}),
    ];
    for mut filter in shared {
        if filter["type"] != "PORT" {
            filter["portFilter"] = ports.clone();
        }
        for side in ["source", "destination"] {
            let mut requested = policy();
            requested[side]["trafficFilter"] = filter.clone();
            preview(&handler, requested).await;
        }
    }
    for filter in [
        json!({"type":"APPLICATION","applicationFilter":{"applicationIds":[42]},"portFilter":ports}),
        json!({"type":"APPLICATION_CATEGORY","applicationCategoryFilter":{"applicationCategoryIds":[7]},"portFilter":reference_ports}),
        json!({"type":"DOMAIN","domainFilter":{"type":"DOMAINS","domains":["example.com"]}}),
    ] {
        let mut requested = policy();
        requested["destination"]["trafficFilter"] = filter;
        preview(&handler, requested).await;
    }
    let mut requested = policy();
    requested["source"]["trafficFilter"] = json!({"type":"MAC_ADDRESS","macAddressFilter":{"macAddresses":["02:00:00:00:00:01"]},"portFilter":ports});
    preview(&handler, requested).await;
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn previews_cover_actions_protocols_and_all_schedule_modes() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let time = json!({"startTime":"08:00","stopTime":"17:30"});
    for schedule in [
        json!({"mode":"CUSTOM","repeatOnDays":["MONDAY","SUNDAY"],"startDate":"2026-10-01","stopDate":"2026-10-30","timeFilter":time}),
        json!({"mode":"EVERY_DAY","timeFilter":time}),
        json!({"mode":"EVERY_WEEK","repeatOnDays":["TUESDAY"]}),
        json!({"mode":"ONE_TIME_ONLY","date":"2026-10-02","timeFilter":time}),
    ] {
        let mut requested = policy();
        requested["schedule"] = schedule;
        preview(&handler, requested).await;
    }
    for action in [
        json!({"type":"ALLOW","allowReturnTraffic":false}),
        json!({"type":"BLOCK"}),
        json!({"type":"REJECT"}),
    ] {
        let mut requested = policy();
        requested["action"] = action;
        preview(&handler, requested).await;
    }
    for (version, protocol) in [
        (
            "IPV4",
            json!({"type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"icmp","typenameFilter":"ECHO_REQUEST"}}),
        ),
        (
            "IPV6",
            json!({"type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"icmpv6","typenameFilter":"NEIGHBOR_SOLICITATION"}}),
        ),
        (
            "IPV4_AND_IPV6",
            json!({"type":"NAMED_PROTOCOL","matchOpposite":true,"protocol":{"name":"tcp"}}),
        ),
        (
            "IPV4",
            json!({"type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"ax.25"}}),
        ),
        (
            "IPV6",
            json!({"type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"ipv6-frag"}}),
        ),
        (
            "IPV4_AND_IPV6",
            json!({"type":"PRESET","preset":{"name":"TCP_UDP"}}),
        ),
        (
            "IPV4_AND_IPV6",
            json!({"type":"PROTOCOL_NUMBER","matchOpposite":false,"protocolNumber":253}),
        ),
    ] {
        let mut requested = policy();
        requested["ipProtocolScope"] = json!({"ipVersion":version,"protocolFilter":protocol});
        preview(&handler, requested).await;
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn create_and_replace_send_full_policies_and_preserve_additional_response_fields() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let handler = handler_for(&server);
    let requested = policy();
    let mut accepted = requested.clone();
    accepted["id"] = json!(POLICY_ID);
    accepted["controllerExtension"] =
        json!({"credential":"fixture-controller-value","revision":9_007_199_254_740_993_u64});
    let route = format!("{PREFIX}/sites/{SITE_ID}/firewall/policies");
    for (verb, endpoint, status) in [
        ("POST", route.clone(), 201),
        ("PUT", format!("{route}/{POLICY_ID}"), 200),
    ] {
        Mock::given(method(verb))
            .and(path(endpoint))
            .and(body_json(requested.clone()))
            .respond_with(ResponseTemplate::new(status).set_body_json(accepted.clone()))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .expect(2)
        .mount(&server)
        .await;
    for (operation, id, status) in [("create", None, 201), ("update", Some(POLICY_ID), 200)] {
        let mut arguments = json!({"operation":operation,"policy":requested,"confirm":true});
        if let Some(id) = id {
            arguments["id"] = json!(id);
        }
        let result = handler
            .call(&call(arguments), None)
            .await
            .expect("accepted")
            .structured_content
            .expect("structured");
        assert_eq!(result["responseStatus"], status);
        assert_eq!(result["accepted"], accepted);
        assert_eq!(result["after"], accepted);
        assert_eq!(result["verified"], true);
    }
}

#[tokio::test]
async fn accepted_large_policy_survives_failed_readback_and_rejection_text_is_preserved() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/firewall/policies");
    let mut accepted = policy();
    accepted["id"] = json!(POLICY_ID);
    accepted["extension"] = json!(format!("{}accepted-policy-tail", "x".repeat(50_000)));
    Mock::given(method("POST"))
        .and(path(&route))
        .and(body_json(policy()))
        .respond_with(ResponseTemplate::new(201).set_body_json(accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("policy readback controller detail"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let result = handler
        .call(
            &call(json!({"operation":"create","policy":policy(),"confirm":true})),
            None,
        )
        .await
        .expect("accepted");
    let content = serde_json::to_value(result.content)
        .expect("content")
        .to_string();
    let output = result.structured_content.expect("structured");
    assert_eq!(output["responseStatus"], 201);
    assert_eq!(output["acceptedInContent"], true);
    assert!(content.contains("accepted-policy-tail"));
    assert!(
        output["readbackError"]
            .as_str()
            .expect("upstream text")
            .contains("policy readback controller detail")
    );
    Mock::given(method("PUT"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_string("policy zone relationship rejected by controller"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = handler
        .call(
            &call(json!({"operation":"update","id":POLICY_ID,"policy":policy(),"confirm":true})),
            None,
        )
        .await
        .expect_err("upstream rejection");
    assert!(
        error
            .message
            .contains("policy zone relationship rejected by controller")
    );
}

#[tokio::test]
async fn unknown_fields_and_missing_required_nested_inputs_fail_before_upstream_calls() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let mut unknown = policy();
    unknown["source"]["arbitraryPath"] = json!("/unsupported");
    let mut incomplete = policy();
    incomplete["action"] = json!({"type":"ALLOW"});
    for requested in [unknown, incomplete] {
        assert!(
            handler
                .call(
                    &call(json!({"operation":"create","policy":requested,"confirm":true})),
                    None
                )
                .await
                .is_err()
        );
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}
