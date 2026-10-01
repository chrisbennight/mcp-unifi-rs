use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path, query_param},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const NETWORK_ID: &str = "f435b097-683e-4bc4-8d3a-453c968a48fb";

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

fn unmanaged() -> Value {
    json!({"management":"UNMANAGED","enabled":true,"name":"Lab","vlanId":10,
        "dhcpGuarding":{"trustedDhcpServerIpAddresses":["192.0.2.2"]}})
}

fn gateway() -> Value {
    json!({"management":"GATEWAY","enabled":true,"name":"Lab","vlanId":10,
        "cellularBackupEnabled":true,"internetAccessEnabled":true,"isolationEnabled":false,
        "mdnsForwardingEnabled":true,"zoneId":"zone-id",
        "ipv4Configuration":{"hostIpAddress":"192.0.2.1","prefixLength":24,"autoScaleEnabled":false,
            "additionalHostIpSubnets":["198.51.100.1/24"],
            "dhcpConfiguration":{"mode":"SERVER","ipAddressRange":{"start":"192.0.2.10","stop":"192.0.2.20"},
                "leaseTimeSeconds":3600,"pingConflictDetectionEnabled":true,"dnsServerIpAddressesOverride":["192.0.2.3"],
                "domainName":"example.test","gatewayIpAddressOverride":"192.0.2.1","ntpServerIpAddresses":["192.0.2.4"],
                "option43Value":"010203","pxeConfiguration":{"filename":"boot.ipxe","serverIpAddress":"192.0.2.5"},
                "tftpServerAddress":"192.0.2.5","timeOffsetSeconds":-3600,"winsServerIpAddresses":["192.0.2.6"],"wpadUrl":"http://example.test/proxy.pac"},
            "natOutboundIpAddressConfiguration":[{"type":"AUTO","wanInterfaceId":"wan1","ipAddressSelectionMode":"MAIN"},
                {"type":"STATIC","wanInterfaceId":"wan2","ipAddressSelectors":[{"type":"IP_ADDRESS","value":"203.0.113.2"},
                    {"type":"IP_ADDRESS_RANGE","start":"203.0.113.10","stop":"203.0.113.20"}]}]},
        "ipv6Configuration":{"interfaceType":"STATIC","hostIpAddress":"2001:db8::1","prefixLength":64,
            "additionalHostIpSubnets":["2001:db8:1::1/64"],"clientAddressAssignment":{"slaacEnabled":true,
                "dhcpConfiguration":{"ipAddressSuffixRange":{"start":"::10","stop":"::ff"},"leaseTimeSeconds":3600}},
            "dnsServerIpAddressesOverride":["2001:db8::2"],"routerAdvertisement":{"priority":"MEDIUM"}}})
}

#[tokio::test]
async fn previews_cover_management_dhcp_nat_and_ipv6_variants_without_controller_calls() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let mut delegated = gateway();
    delegated["ipv4Configuration"]["dhcpConfiguration"] =
        json!({"mode":"RELAY","dhcpServerIpAddresses":["192.0.2.2"]});
    delegated["ipv4Configuration"]["natOutboundIpAddressConfiguration"][0]["ipAddressSelectionMode"] =
        json!("ALL");
    delegated["ipv6Configuration"] = json!({"interfaceType":"PREFIX_DELEGATION","prefixDelegationWanInterfaceId":"wan1",
        "clientAddressAssignment":{"slaacEnabled":false},"routerAdvertisement":{"priority":"HIGH"}});
    let switch = json!({"management":"SWITCH","name":"Switch","enabled":true,"vlanId":20,"deviceId":"switch-id",
        "cellularBackupEnabled":false,"isolationEnabled":true,"ipv4Configuration":{"hostIpAddress":"198.51.100.1",
            "prefixLength":24,"autoScaleEnabled":false,"dhcpConfiguration":{"mode":"SERVER","ipAddressRange":{"start":"198.51.100.10","stop":"198.51.100.20"},
                "leaseTimeSeconds":3600,"dnsServerIpAddressesOverride":["198.51.100.2"],"domainName":"example.test","gatewayIpAddressOverride":"198.51.100.1"}}});
    let mut relayed_switch = switch.clone();
    relayed_switch["ipv4Configuration"]["dhcpConfiguration"] =
        json!({"mode":"RELAY","dhcpServerIpAddresses":["198.51.100.2"]});
    for network in [unmanaged(), gateway(), delegated, switch, relayed_switch] {
        let result = handler
            .call(
                &call(
                    "networks.configure",
                    json!({"operation":"create","network":network}),
                ),
                None,
            )
            .await
            .expect("preview");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["submitted"], false);
        assert_eq!(output["requested"], network);
    }
    let deletion = handler
        .call(
            &call(
                "networks.configure",
                json!({"operation":"delete","id":NETWORK_ID,"force":true}),
            ),
            None,
        )
        .await
        .expect("delete preview");
    assert_eq!(
        deletion.structured_content.expect("structured")["force"],
        true
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
async fn create_and_replace_send_full_typed_configuration_and_keep_complete_acceptance() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/networks");
    let network = gateway();
    let mut record = network.clone();
    record["id"] = json!(NETWORK_ID);
    record["controllerExtension"] =
        json!({"sharedSecret":"controller-fixture-value","counter":9_007_199_254_740_993_u64});
    let body = format!("  {record}\n");
    for verb in ["POST", "PUT"] {
        Mock::given(method(verb))
            .and(path(if verb == "POST" {
                route.clone()
            } else {
                format!("{route}/{NETWORK_ID}")
            }))
            .and(body_json(network.clone()))
            .respond_with(
                ResponseTemplate::new(if verb == "POST" { 201 } else { 200 })
                    .set_body_string(&body),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{route}/{NETWORK_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record.clone()))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for operation in ["create", "update"] {
        let mut args = json!({"operation":operation,"network":network,"confirm":true});
        if operation == "update" {
            args["id"] = json!(NETWORK_ID);
        }
        let output = handler
            .call(&call("networks.configure", args), None)
            .await
            .expect("write")
            .structured_content
            .expect("structured");
        assert_eq!(output["responseBody"], body);
        assert_eq!(output["after"], record);
        assert_eq!(
            output["responseStatus"],
            if operation == "create" { 201 } else { 200 }
        );
        assert_eq!(output["verified"], true);
    }
}

#[tokio::test]
async fn network_pages_and_references_keep_extensions_and_filter_unchanged() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/networks");
    let filter = "name.eq('Lab')";
    let page = json!({"offset":0,"limit":1,"count":1,"totalCount":2,"data":[{"id":NETWORK_ID,"futureField":{"key":"fixture"}}],"controllerPageExtension":"present"});
    Mock::given(method("GET"))
        .and(path(&route))
        .and(query_param("filter", filter))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let record = json!({"id":NETWORK_ID,"settings":{"sharedSecret":"controller-fixture-value"}});
    let references =
        json!({"references":[{"kind":"PORT_PROFILE","id":"profile"}],"controllerExtension":true});
    Mock::given(method("GET"))
        .and(path(format!("{route}/{NETWORK_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{NETWORK_ID}/references")))
        .respond_with(ResponseTemplate::new(200).set_body_json(references.clone()))
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let listed = handler
        .call(
            &call("networks.list", json!({"limit":1,"filter":filter})),
            None,
        )
        .await
        .expect("page")
        .structured_content
        .expect("structured");
    assert_eq!(listed["response"], page);
    assert_eq!(listed["nextOffset"], 1);
    let status = handler
        .call(
            &call(
                "networks.status",
                json!({"id":NETWORK_ID,"includeReferences":true}),
            ),
            None,
        )
        .await
        .expect("status")
        .structured_content
        .expect("structured");
    assert_eq!(status["response"], record);
    assert_eq!(status["references"], references);
}

#[tokio::test]
async fn forced_delete_keeps_acceptance_and_the_upstream_absence_response() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/networks/{NETWORK_ID}");
    let accepted = "{\"removedReferences\":[\"profile\"],\"controllerExtension\":\"complete\"}";
    let absent = "{\"message\":\"upstream network missing\",\"controllerExtension\":\"detail\"}";
    Mock::given(method("DELETE"))
        .and(path(&route))
        .and(query_param("force", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_string(accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(404).set_body_string(absent))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &call(
                "networks.configure",
                json!({"operation":"delete","id":NETWORK_ID,"force":true,"confirm":true}),
            ),
            None,
        )
        .await
        .expect("delete")
        .structured_content
        .expect("structured");
    assert_eq!(output["responseBody"], accepted);
    assert_eq!(output["force"], true);
    assert_eq!(output["verifiedAbsent"], true);
    assert!(
        output["readbackError"]
            .as_str()
            .expect("error")
            .contains(absent)
    );
}

#[tokio::test]
async fn a_large_accepted_identifier_keeps_the_response_when_readback_is_unusable() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let id = "x".repeat(60_000);
    let accepted = json!({"id":id,"controllerExtension":"accepted"}).to_string();
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/networks")))
        .respond_with(ResponseTemplate::new(201).set_body_string(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "networks.configure",
                json!({"operation":"create","network":unmanaged(),"confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted response");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["id"], id);
    assert_eq!(output["submitted"], true);
    assert_eq!(output["responseStatus"], 201);
    assert!(output["verified"].is_null());
    assert_eq!(output["readbackErrorInContent"], true);
    assert!(
        result
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .any(|text| text.text.starts_with("readbackError: ")
                && text.text.contains("at most 256 bytes"))
    );
    assert!(
        result
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .any(|text| text.text.strip_prefix("responseBody: ") == Some(accepted.as_str()))
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 2);
    server.verify().await;
}

#[tokio::test]
async fn large_accepted_body_and_failed_readback_are_preserved_in_content() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/networks");
    let accepted = json!({"id":NETWORK_ID,"fullExtension":"x".repeat(60_000)}).to_string();
    let failure = json!({"message":"readback unavailable","detail":"y".repeat(60_000)}).to_string();
    Mock::given(method("POST"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(201).set_body_string(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{NETWORK_ID}")))
        .respond_with(ResponseTemplate::new(503).set_body_string(&failure))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "networks.configure",
                json!({"operation":"create","network":unmanaged(),"confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted");
    let content: Value = serde_json::to_value(&result.content).expect("content");
    let texts: Vec<&str> = content
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect();
    let output = result.structured_content.expect("structured");
    assert_eq!(output["submitted"], true);
    assert_eq!(output["responseStatus"], 201);
    assert_eq!(output["responseBodyInContent"], true);
    assert_eq!(output["readbackErrorInContent"], true);
    assert_eq!(
        texts
            .iter()
            .find_map(|text| text.strip_prefix("responseBody: "))
            .expect("accepted content"),
        accepted
    );
    assert!(
        texts
            .iter()
            .find_map(|text| text.strip_prefix("readbackError: "))
            .expect("error content")
            .contains(&failure)
    );
}

#[tokio::test]
async fn non_json_acceptance_and_rejected_writes_are_not_rewritten_or_retried() {
    for status in [201, 422, 429] {
        let server = MockServer::start().await;
        mount_site(&server).await;
        let body = "controller exact reply with fixture-secret and detail";
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}/sites/{SITE_ID}/networks")))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler_for(&server)
            .call(
                &call(
                    "networks.configure",
                    json!({"operation":"create","network":unmanaged(),"confirm":true}),
                ),
                None,
            )
            .await;
        if status == 201 {
            let output = result
                .expect("acceptance preserved")
                .structured_content
                .expect("structured");
            assert_eq!(output["responseBody"], body);
            assert!(output.get("verified").is_none());
        } else {
            let error = result.expect_err("upstream rejection");
            assert!(error.message.contains(body));
        }
    }
}

#[tokio::test]
async fn invalid_input_is_rejected_before_any_upstream_call() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for (name, args) in [
        ("networks.list", json!({"limit":0})),
        ("networks.list", json!({"offset":2_147_483_648_u64})),
        ("networks.list", json!({"filter":"x".repeat(2049)})),
        ("networks.status", json!({"id":".."})),
        (
            "networks.configure",
            json!({"operation":"create","network":unmanaged(),"id":NETWORK_ID}),
        ),
        (
            "networks.configure",
            json!({"operation":"update","id":NETWORK_ID}),
        ),
        (
            "networks.configure",
            json!({"operation":"delete","id":NETWORK_ID,"network":unmanaged()}),
        ),
        (
            "networks.configure",
            json!({"operation":"create","network":{"management":"UNMANAGED","enabled":true,"name":"Lab","vlanId":10,"unknown":true}}),
        ),
    ] {
        assert!(handler.call(&call(name, args), None).await.is_err());
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
async fn large_reads_and_reference_failure_preserve_complete_controller_data() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/networks");
    let record = json!({"id":NETWORK_ID,"extension":"z".repeat(60_000)});
    let page = json!({"offset":0,"limit":50,"count":1,"totalCount":1,"data":[record.clone()],"pageExtension":"complete"});
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(page.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{NETWORK_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record.clone()))
        .mount(&server)
        .await;
    let failure =
        "{\"message\":\"exact upstream references error\",\"fixtureSecret\":\"controller-value\"}";
    Mock::given(method("GET"))
        .and(path(format!("{route}/{NETWORK_ID}/references")))
        .respond_with(ResponseTemplate::new(422).set_body_string(failure))
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for (name, args, expected) in [
        ("networks.list", json!({}), page),
        (
            "networks.status",
            json!({"id":NETWORK_ID,"includeReferences":true}),
            record,
        ),
    ] {
        let result = handler.call(&call(name, args), None).await.expect("read");
        let content: Value = serde_json::to_value(&result.content).expect("content");
        let texts: Vec<&str> = content
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect();
        let original = texts
            .iter()
            .find_map(|text| text.strip_prefix("response: "))
            .expect("complete response content");
        assert_eq!(
            serde_json::from_str::<Value>(original).expect("response JSON"),
            expected
        );
        let output = result.structured_content.expect("structured");
        assert_eq!(output["responseInContent"], true);
        if name == "networks.status" {
            assert!(
                output["readbackError"]
                    .as_str()
                    .expect("error")
                    .contains(failure)
            );
        }
    }
}

#[tokio::test]
async fn page_validation_keeps_the_original_body_and_allows_empty_pages_past_the_total() {
    for inconsistent in [false, true] {
        let server = MockServer::start().await;
        mount_site(&server).await;
        let page = json!({"offset":10,"limit":50,"count":0,"totalCount":if inconsistent {20} else {2},"data":[],"extension":"retained"});
        let body = format!("  {page}\n");
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/sites/{SITE_ID}/networks")))
            .and(query_param("offset", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body))
            .mount(&server)
            .await;
        let result = handler_for(&server)
            .call(&call("networks.list", json!({"offset":10})), None)
            .await;
        if inconsistent {
            let error = result.expect_err("inconsistent page");
            assert!(error.message.contains(&body));
        } else {
            let output = result
                .expect("empty page")
                .structured_content
                .expect("structured");
            assert_eq!(output["response"], page);
            assert!(output.get("nextOffset").is_none());
        }
    }
}

#[tokio::test]
async fn ordinary_delete_reports_a_surviving_record_without_claiming_absence() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/networks/{NETWORK_ID}");
    Mock::given(method("DELETE"))
        .and(path(&route))
        .and(query_param("force", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_string("upstream accepted deletion"))
        .expect(1)
        .mount(&server)
        .await;
    let surviving = json!({"id":NETWORK_ID,"extension":"retained"});
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(surviving.clone()))
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &call(
                "networks.configure",
                json!({"operation":"delete","id":NETWORK_ID,"confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted")
        .structured_content
        .expect("structured");
    assert_eq!(output["responseBody"], "upstream accepted deletion");
    assert_eq!(output["verifiedAbsent"], false);
    assert_eq!(output["after"], surviving);
}
