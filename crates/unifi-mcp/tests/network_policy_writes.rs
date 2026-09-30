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
    let base_url = Url::parse(&server.uri()).expect("mock server URL");
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

fn call(name: &str, arguments: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
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
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}]
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn previews_cover_all_documented_dns_and_traffic_variants_without_writing() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let dns = [
        json!({"type":"A_RECORD","enabled":true,"domain":"a.example","ipv4Address":"192.0.2.1","ttlSeconds":60}),
        json!({"type":"AAAA_RECORD","enabled":true,"domain":"a.example","ipv6Address":"2001:db8::1","ttlSeconds":60}),
        json!({"type":"CNAME_RECORD","enabled":true,"domain":"a.example","targetDomain":"b.example","ttlSeconds":60}),
        json!({"type":"FORWARD_DOMAIN","enabled":true,"domain":"a.example","ipAddress":"192.0.2.1"}),
        json!({"type":"MX_RECORD","enabled":true,"domain":"a.example","mailServerDomain":"mail.example","priority":10}),
        json!({"type":"SRV_RECORD","enabled":true,"domain":"a.example","port":443,"priority":10,"protocol":"tcp","serverDomain":"host.example","service":"https","weight":5}),
        json!({"type":"TXT_RECORD","enabled":true,"domain":"a.example","text":"v=spf1 -all"}),
    ];
    for policy in dns {
        let result = handler
            .call(
                &call(
                    "dns.policies.configure",
                    json!({"operation":"create","policy":policy}),
                ),
                None,
            )
            .await
            .expect("DNS preview")
            .structured_content
            .expect("structured");
        assert_eq!(result["submitted"], false);
        assert_eq!(result["requested"], policy);
    }
    let traffic = [
        json!({"type":"IPV4_ADDRESSES","name":"v4","items":[{"type":"IP_ADDRESS","value":"192.0.2.1"},{"type":"IP_ADDRESS_RANGE","start":"192.0.2.1","stop":"192.0.2.10"},{"type":"SUBNET","value":"192.0.2.0/24"}]}),
        json!({"type":"IPV6_ADDRESSES","name":"v6","items":[{"type":"IP_ADDRESS","value":"2001:db8::1"},{"type":"SUBNET","value":"2001:db8::/64"}]}),
        json!({"type":"PORTS","name":"ports","items":[{"type":"PORT_NUMBER","value":443},{"type":"PORT_NUMBER_RANGE","start":8000,"stop":8100}]}),
    ];
    for list in traffic {
        let result = handler
            .call(
                &call(
                    "traffic.matching_lists.configure",
                    json!({"operation":"create","list":list}),
                ),
                None,
            )
            .await
            .expect("traffic preview")
            .structured_content
            .expect("structured");
        assert_eq!(result["submitted"], false);
        assert_eq!(result["requested"], list);
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
async fn create_and_update_return_accepted_record_and_observed_record() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let policy = json!({"type":"A_RECORD","enabled":true,"domain":"a.example","ipv4Address":"192.0.2.1","ttlSeconds":60});
    let accepted = json!({"id":POLICY_ID,"type":"A_RECORD","enabled":true,"domain":"a.example","ipv4Address":"192.0.2.1","ttlSeconds":60,"controllerExtension":{"owner":"upstream"}});
    let route = format!("{PREFIX}/sites/{SITE_ID}/dns/policies");
    Mock::given(method("POST"))
        .and(path(&route))
        .and(body_json(policy.clone()))
        .respond_with(ResponseTemplate::new(201).set_body_json(accepted.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .and(body_json(policy.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for (operation, id, status) in [("create", None, 201), ("update", Some(POLICY_ID), 200)] {
        let result = handler
            .call(
                &call(
                    "dns.policies.configure",
                    json!({"operation":operation,"id":id,"policy":policy,"confirm":true}),
                ),
                None,
            )
            .await
            .expect("policy write")
            .structured_content
            .expect("structured");
        assert_eq!(result["responseStatus"], status);
        assert_eq!(result["accepted"], accepted);
        assert_eq!(result["after"], accepted);
        assert_eq!(result["verified"], true);
    }
}

#[tokio::test]
async fn delete_preserves_upstream_body_and_checks_absence() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/traffic-matching-lists/{POLICY_ID}");
    Mock::given(method("DELETE"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_string("controller deletion accepted"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(404).set_body_string("controller says list absent"))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "traffic.matching_lists.configure",
                json!({"operation":"delete","id":POLICY_ID,"confirm":true}),
            ),
            None,
        )
        .await
        .expect("delete accepted")
        .structured_content
        .expect("structured");
    assert_eq!(result["responseStatus"], 200);
    assert_eq!(result["responseBody"], "controller deletion accepted");
    assert_eq!(result["verifiedAbsent"], true);
    assert!(
        result["readbackError"]
            .as_str()
            .expect("upstream error")
            .contains("controller says list absent")
    );
}

#[tokio::test]
async fn upstream_rejection_is_returned_without_retry_or_generic_replacement() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let list = json!({"type":"PORTS","name":"ports","items":[{"type":"PORT_NUMBER","value":443}]});
    Mock::given(method("POST"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/traffic-matching-lists"
        )))
        .and(body_json(list.clone()))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_string("upstream rejected list for a specific reason"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "traffic.matching_lists.configure",
                json!({"operation":"create","list":list,"confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("controller rejection");
    assert!(
        error
            .message
            .contains("upstream rejected list for a specific reason")
    );
}

#[tokio::test]
async fn invalid_request_does_not_contact_controller() {
    let server = MockServer::start().await;
    let result = handler_for(&server)
        .call(&call("traffic.matching_lists.configure", json!({"operation":"create","list":{"type":"PORTS","name":"ports","items":[{"type":"PORT_NUMBER","value":0}]},"confirm":true})), None)
        .await;
    assert!(
        result
            .expect_err("invalid port")
            .message
            .contains("1-65535")
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn large_accepted_record_remains_available_in_content() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let list = json!({"type":"PORTS","name":"ports","items":[{"type":"PORT_NUMBER","value":443}]});
    let accepted = json!({"id":POLICY_ID,"type":"PORTS","name":"ports","items":[{"type":"PORT_NUMBER","value":443}],"controllerExtension":format!("{}controller-tail", "x".repeat(50_000))});
    let route = format!("{PREFIX}/sites/{SITE_ID}/traffic-matching-lists");
    Mock::given(method("POST"))
        .and(path(&route))
        .and(body_json(list.clone()))
        .respond_with(ResponseTemplate::new(201).set_body_json(accepted.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "traffic.matching_lists.configure",
                json!({"operation":"create","list":list,"confirm":true}),
            ),
            None,
        )
        .await
        .expect("large response");
    let structured = result.structured_content.expect("structured");
    assert_eq!(structured["acceptedInContent"], true);
    assert_eq!(structured["afterInContent"], true);
    assert!(
        result
            .content
            .iter()
            .any(|item| format!("{item:?}").contains("controller-tail"))
    );
}

#[tokio::test]
async fn acl_rule_previews_cover_ip_and_mac_filter_variants() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let rules = [
        json!({"type":"IPV4","action":"ALLOW","enabled":true,"name":"networks","sourceFilter":{"type":"NETWORKS","networkIds":["network-1"],"portFilter":[443]},"destinationFilter":{"type":"PORTS","portFilter":[53]},"protocolFilter":["TCP","UDP"],"enforcingDeviceFilter":{"type":"DEVICES","deviceIds":["switch-1"]}}),
        json!({"type":"IPV4","action":"BLOCK","enabled":false,"name":"subnets","sourceFilter":{"type":"IP_ADDRESSES_OR_SUBNETS","ipAddressesOrSubnets":["192.0.2.0/24"]}}),
        json!({"type":"MAC","action":"BLOCK","enabled":true,"name":"macs","networkIdFilter":"network-1","sourceFilter":{"type":"MAC_ADDRESSES","macAddresses":["aa:bb:cc:dd:ee:ff"],"prefixLength":48}}),
    ];
    for rule in rules {
        let result = handler
            .call(
                &call(
                    "acl.rules.configure",
                    json!({"operation":"create","rule":rule}),
                ),
                None,
            )
            .await
            .expect("ACL preview")
            .structured_content
            .expect("structured");
        assert_eq!(result["submitted"], false);
        assert_eq!(result["requested"], rule);
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
async fn acl_rule_create_update_and_delete_keep_controller_responses() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let rule = json!({"type":"IPV4","action":"ALLOW","enabled":true,"name":"office","sourceFilter":{"type":"NETWORKS","networkIds":["network-1"]}});
    let accepted = json!({"id":POLICY_ID,"type":"IPV4","action":"ALLOW","enabled":true,"name":"office","sourceFilter":{"type":"NETWORKS","networkIds":["network-1"]},"controllerExtension":"retained"});
    let collection = format!("{PREFIX}/sites/{SITE_ID}/acl-rules");
    let detail = format!("{collection}/{POLICY_ID}");
    Mock::given(method("POST"))
        .and(path(&collection))
        .and(body_json(rule.clone()))
        .respond_with(ResponseTemplate::new(201).set_body_json(accepted.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(&detail))
        .and(body_json(rule.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&detail))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(&detail))
        .respond_with(ResponseTemplate::new(200).set_body_string("ACL deletion accepted"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&detail))
        .respond_with(ResponseTemplate::new(404).set_body_string("ACL rule absent"))
        .mount(&server)
        .await;

    let handler = handler_for(&server);
    for (operation, id, status) in [("create", None, 201), ("update", Some(POLICY_ID), 200)] {
        let output = handler
            .call(
                &call(
                    "acl.rules.configure",
                    json!({"operation":operation,"id":id,"rule":rule,"confirm":true}),
                ),
                None,
            )
            .await
            .expect("ACL write")
            .structured_content
            .expect("structured");
        assert_eq!(output["responseStatus"], status);
        assert_eq!(output["accepted"], accepted);
        assert_eq!(output["after"], accepted);
        assert_eq!(output["verified"], true);
    }
    let deleted = handler
        .call(
            &call(
                "acl.rules.configure",
                json!({"operation":"delete","id":POLICY_ID,"confirm":true}),
            ),
            None,
        )
        .await
        .expect("ACL delete")
        .structured_content
        .expect("structured");
    assert_eq!(deleted["responseStatus"], 200);
    assert_eq!(deleted["responseBody"], "ACL deletion accepted");
    assert_eq!(deleted["verifiedAbsent"], true);
    assert!(
        deleted["readbackError"]
            .as_str()
            .expect("body")
            .contains("ACL rule absent")
    );
}

#[tokio::test]
async fn invalid_acl_filter_fails_before_contacting_the_controller() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for (rule, expected) in [
        (
            json!({"type":"IPV4","action":"BLOCK","enabled":true,"name":"invalid","sourceFilter":{"type":"PORTS","portFilter":[0]}}),
            "1-65535",
        ),
        (
            json!({"type":"IPV4","action":"BLOCK","enabled":true,"name":"invalid","futureField":"must not disappear"}),
            "unknown field `futureField`",
        ),
    ] {
        let error = handler
            .call(
                &call(
                    "acl.rules.configure",
                    json!({"operation":"create","rule":rule,"confirm":true}),
                ),
                None,
            )
            .await
            .expect_err("invalid ACL request");
        assert!(error.message.contains(expected));
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
async fn acl_ordering_read_returns_the_complete_controller_record() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let ordering =
        json!({"orderedAclRuleIds":[POLICY_ID],"controllerExtension":{"priority":"reported"}});
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/acl-rules/ordering")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ordering.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(&call("acl.rules.ordering.read", json!({})), None)
        .await
        .expect("ordering read")
        .structured_content
        .expect("structured");
    assert_eq!(result["record"], ordering);
}

#[tokio::test]
async fn acl_ordering_previews_and_preserves_accepted_update() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let ids = json!([POLICY_ID]);
    let preview = handler
        .call(
            &call(
                "acl.rules.ordering.configure",
                json!({"orderedAclRuleIds":ids}),
            ),
            None,
        )
        .await
        .expect("ordering preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["submitted"], false);
    assert_eq!(preview["requested"], json!({"orderedAclRuleIds":ids}));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );

    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/acl-rules/ordering");
    let accepted = json!({"orderedAclRuleIds":ids,"controllerExtension":"accepted"});
    Mock::given(method("PUT"))
        .and(path(&route))
        .and(body_json(json!({"orderedAclRuleIds":ids})))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler
        .call(
            &call(
                "acl.rules.ordering.configure",
                json!({"orderedAclRuleIds":ids,"confirm":true}),
            ),
            None,
        )
        .await
        .expect("ordering update")
        .structured_content
        .expect("structured");
    assert_eq!(result["submitted"], true);
    assert_eq!(result["responseStatus"], 200);
    assert_eq!(result["accepted"], accepted);
    assert_eq!(result["after"], accepted);
    assert_eq!(result["verified"], true);
}

#[tokio::test]
async fn acl_ordering_rejection_returns_the_upstream_explanation() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("PUT"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/acl-rules/ordering")))
        .respond_with(ResponseTemplate::new(422).set_body_string("specific ACL order conflict"))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "acl.rules.ordering.configure",
                json!({"orderedAclRuleIds":[POLICY_ID],"confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("controller rejection");
    assert!(error.message.contains("specific ACL order conflict"));
}

#[tokio::test]
async fn acl_ordering_does_not_verify_when_acceptance_disagrees_with_request() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/acl-rules/ordering");
    Mock::given(method("PUT"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"orderedAclRuleIds":[]})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"orderedAclRuleIds":[POLICY_ID]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &call(
                "acl.rules.ordering.configure",
                json!({"orderedAclRuleIds":[POLICY_ID],"confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted ordering")
        .structured_content
        .expect("structured");
    assert_eq!(output["accepted"]["orderedAclRuleIds"], json!([]));
    assert_eq!(output["after"]["orderedAclRuleIds"], json!([POLICY_ID]));
    assert_eq!(output["verified"], false);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one controller fixture exercises create, replacement, detail, and deletion"
)]
async fn firewall_zone_lifecycle_preserves_membership_and_controller_records() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let zone = json!({"name":"Lab","networkIds":[SITE_ID]});
    let preview = handler
        .call(
            &call(
                "firewall.zones.configure",
                json!({
                    "operation":"create","zone":zone
                }),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["submitted"], false);
    assert_eq!(preview["requested"], zone);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/firewall/zones");
    let accepted = json!({"id":POLICY_ID,"name":"Lab","networkIds":[SITE_ID],"controllerExtension":"retained"});
    for (verb, endpoint, status) in [
        ("POST", route.clone(), 201),
        ("PUT", format!("{route}/{POLICY_ID}"), 200),
    ] {
        Mock::given(method(verb))
            .and(path(endpoint))
            .and(body_json(zone.clone()))
            .respond_with(ResponseTemplate::new(status).set_body_json(accepted.clone()))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(accepted.clone()))
        .up_to_n_times(3)
        .expect(3)
        .mount(&server)
        .await;
    for (operation, id, status) in [("create", None, 201), ("update", Some(POLICY_ID), 200)] {
        let mut args = json!({"operation":operation,"zone":zone,"confirm":true});
        if let Some(id) = id {
            args["id"] = json!(id);
        }
        let result = handler
            .call(&call("firewall.zones.configure", args), None)
            .await
            .expect("accepted")
            .structured_content
            .expect("structured");
        assert_eq!(result["kind"], "firewallZones");
        assert_eq!(result["responseStatus"], status);
        assert_eq!(result["accepted"], accepted);
        assert_eq!(result["after"], accepted);
        assert_eq!(result["verified"], true);
    }
    let detail = handler
        .call(
            &call(
                "network.policy.detail",
                json!({"kind":"firewallZones","id":POLICY_ID}),
            ),
            None,
        )
        .await
        .expect("detail")
        .structured_content
        .expect("structured");
    assert_eq!(detail["record"], accepted);
    Mock::given(method("DELETE"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("custom zone deletion accepted"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("custom zone absent"))
        .expect(1)
        .mount(&server)
        .await;
    let deleted = handler
        .call(
            &call(
                "firewall.zones.configure",
                json!({"operation":"delete","id":POLICY_ID,"confirm":true}),
            ),
            None,
        )
        .await
        .expect("delete")
        .structured_content
        .expect("structured");
    assert_eq!(deleted["responseBody"], "custom zone deletion accepted");
    assert_eq!(deleted["verifiedAbsent"], true);
    assert!(
        deleted["readbackError"]
            .as_str()
            .expect("upstream text")
            .contains("custom zone absent")
    );
}

#[tokio::test]
async fn firewall_zone_keeps_accepted_record_when_readback_fails() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/firewall/zones");
    let accepted = json!({"id":POLICY_ID,"name":"Empty zone","networkIds":[],
        "controllerExtension":format!("{}zone-accepted-tail", "x".repeat(50_000))});
    Mock::given(method("POST"))
        .and(path(&route))
        .and(body_json(json!({"name":"Empty zone","networkIds":[]})))
        .respond_with(ResponseTemplate::new(201).set_body_json(accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{POLICY_ID}")))
        .respond_with(ResponseTemplate::new(503).set_body_string("zone readback unavailable"))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "firewall.zones.configure",
                json!({
                    "operation":"create","zone":{"name":"Empty zone","networkIds":[]},"confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("accepted");
    let content = serde_json::to_value(&result.content)
        .expect("content")
        .to_string();
    let output = result.structured_content.expect("structured");
    assert_eq!(output["submitted"], true);
    assert_eq!(output["acceptedInContent"], true);
    assert!(
        output["readbackError"]
            .as_str()
            .expect("error")
            .contains("zone readback unavailable")
    );
    assert!(content.contains("zone-accepted-tail"));
    assert!(output.get("verified").is_none());
}

#[tokio::test]
async fn firewall_zone_rejection_remains_the_controllers_decision() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("PUT"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/firewall/zones/{POLICY_ID}"
        )))
        .respond_with(
            ResponseTemplate::new(422).set_body_string("cannot replace a system-defined zone"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server).call(&call("firewall.zones.configure", json!({
        "operation":"update","id":POLICY_ID,"zone":{"name":"Zone","networkIds":[]},"confirm":true
    })), None).await.expect_err("upstream rejection");
    assert!(
        error
            .message
            .contains("cannot replace a system-defined zone")
    );
}
