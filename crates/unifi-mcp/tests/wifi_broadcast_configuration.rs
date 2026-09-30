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
const BROADCAST_ID: &str = "f435b097-683e-4bc4-8d3a-453c968a48fb";

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

fn broadcast(security: Value, standard: bool) -> Value {
    let mut value = json!({"type":if standard {"STANDARD"} else {"IOT_OPTIMIZED"},"name":"Lab Wi-Fi","enabled":true,
        "channel2gLockedTo6":false,"clientIsolationEnabled":false,"dtimPeriod2gLockedTo3":false,"hideName":false,
        "multicastToUnicastConversionEnabled":true,"uapsdEnabled":true,
        "network":{"type":"SPECIFIC","networkId":"network-id"},
        "basicDataRateKbpsByFrequencyGHz":{"2.4":2000,"5":6000},
        "blackoutScheduleConfiguration":{"days":[{"type":"ALL_DAY","day":"SUN"},
            {"type":"TIME_RANGE","day":"MON","timeRanges":[{"startTime":"01:00","endTime":"02:00"}]}]},
        "broadcastingDeviceFilter":{"type":"DEVICE_TAGS","deviceTagIds":["tag-id"]},
        "clientFilteringPolicy":{"action":"ALLOW","macAddressFilter":["aa:bb:cc:dd:ee:ff"]},
        "multicastFilteringPolicy":{"action":"ALLOW","sourceMacAddressFilter":["aa:bb:cc:dd:ee:ff"]},
        "mdnsProxyConfiguration":{"mode":"CUSTOM","policies":[{"action":"ALLOW","bridgingNetworkIds":["other-network"],
            "serviceFilter":[{"type":"CUSTOM","name":"Example","typeDomain":"_example._tcp"},{"type":"PREDEFINED","name":"APPLE_AIR_PLAY"}]},
            {"action":"BLOCK","deviceFilter":{"type":"DEVICES","deviceIds":["ap-id"]}}]}});
    value["securityConfiguration"] = security;
    if standard {
        for (field, part) in [
            ("advertiseDeviceName", json!(true)),
            ("arpProxyEnabled", json!(true)),
            ("bandSteeringEnabled", json!(true)),
            ("broadcastingFrequenciesGHz", json!([2.4, 5, 6])),
            ("bssTransitionEnabled", json!(true)),
            (
                "dnsAssistanceConfiguration",
                json!({"mode":"MANUAL","servers":["192.0.2.2"]}),
            ),
            (
                "dtimPeriodByFrequencyGHzOverride",
                json!({"2.4":3,"5":2,"6":3}),
            ),
            (
                "handoffSuggestionsConfiguration",
                json!({"band5GHzRssiThreshold":-70,"band6GHzRssiThreshold":-80}),
            ),
            ("hotspotConfiguration", json!({"type":"CAPTIVE_PORTAL"})),
            ("mloEnabled", json!(true)),
        ] {
            value[field] = part;
        }
    }
    value
}

fn security_variants() -> Vec<Value> {
    let enterprise = json!({"profileId":"radius-id","nasId":{"type":"DERIVED","source":"DEVICE_NAME"},
        "macAuthenticationConfiguration":{"macAddressFormat":"LOWERCASE_COLON_SEPARATED"}});
    let non_enterprise = json!({"profileId":"radius-id","nasId":{"type":"USER_DEFINED","value":"fixture-nas"},
        "macAuthenticationConfiguration":{"macAddressFormat":"UPPERCASE_DASH_SEPARATED"}});
    let sae = json!({"anticloggingThresholdSeconds":5,"syncTimeSeconds":5});
    vec![
        json!({"type":"OPEN","encryption":"ENHANCED_OPEN_WITH_TRANSITION","radiusConfiguration":non_enterprise}),
        json!({"type":"WPA2_ENTERPRISE","coaEnabled":true,"radiusConfiguration":enterprise,"fastRoamingEnabled":true,"groupRekeyIntervalSeconds":3600,"pmfMode":"OPTIONAL"}),
        json!({"type":"WPA2_PERSONAL","radiusConfiguration":non_enterprise,"presharedKeys":[{"passphrase":"fixture-key-one","network":{"type":"NATIVE"}},
            {"passphrase":"fixture-key-two","network":{"type":"SPECIFIC","networkId":"network-id"}}]}),
        json!({"type":"WPA2_WPA3_ENTERPRISE","coaEnabled":true,"radiusConfiguration":enterprise,"pmfMode":"REQUIRED","wpa3FastRoamingEnabled":false}),
        json!({"type":"WPA2_WPA3_PERSONAL","passphrase":"fixture-passphrase","pmfMode":"OPTIONAL","saeConfiguration":sae,"wpa3FastRoamingEnabled":false}),
        json!({"type":"WPA3_ENTERPRISE","coaEnabled":false,"radiusConfiguration":enterprise,"securityMode":"HIGH_SECURITY_192_BIT"}),
        json!({"type":"WPA3_PERSONAL","passphrase":"fixture-passphrase","saeConfiguration":sae}),
    ]
}

#[tokio::test]
async fn previews_preserve_standard_and_iot_configuration_with_every_security_variant() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for standard in [false, true] {
        for security in security_variants() {
            let broadcast = broadcast(security, standard);
            let output = handler
                .call(
                    &call(
                        "wifi.broadcasts.configure",
                        json!({"operation":"create","broadcast":broadcast}),
                    ),
                    None,
                )
                .await
                .expect("preview")
                .structured_content
                .expect("structured");
            assert_eq!(output["submitted"], false);
            assert_eq!(output["requested"], broadcast);
        }
    }
    let mut alternative = broadcast(json!({"type":"OPEN"}), true);
    alternative["network"] = json!({"type":"NATIVE"});
    alternative["broadcastingDeviceFilter"] = json!({"type":"DEVICES","deviceIds":["ap-id"]});
    alternative["clientFilteringPolicy"]["action"] = json!("BLOCK");
    alternative["multicastFilteringPolicy"] = json!({"action":"BLOCK"});
    alternative["mdnsProxyConfiguration"] = json!({"mode":"AUTO"});
    alternative["dnsAssistanceConfiguration"] = json!({"mode":"AUTO"});
    alternative["hotspotConfiguration"] = json!({"type":"PASSPOINT"});
    let output = handler
        .call(
            &call(
                "wifi.broadcasts.configure",
                json!({"operation":"create","broadcast":alternative}),
            ),
            None,
        )
        .await
        .expect("alternative preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["requested"], alternative);
    let deletion = handler
        .call(
            &call(
                "wifi.broadcasts.configure",
                json!({"operation":"delete","broadcastId":BROADCAST_ID,"force":true}),
            ),
            None,
        )
        .await
        .expect("delete preview")
        .structured_content
        .expect("structured");
    assert_eq!(deletion["force"], true);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn create_and_replace_keep_exact_acceptance_and_complete_observed_configuration() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts");
    let requested = broadcast(security_variants().remove(2), true);
    let mut record = requested.clone();
    record["id"] = json!(BROADCAST_ID);
    record["controllerExtension"] =
        json!({"credential":"fixture-upstream-value","counter":9_007_199_254_740_993_u64});
    let accepted = format!("  {record}\n");
    for verb in ["POST", "PUT"] {
        Mock::given(method(verb))
            .and(path(if verb == "POST" {
                route.clone()
            } else {
                format!("{route}/{BROADCAST_ID}")
            }))
            .and(body_json(requested.clone()))
            .respond_with(
                ResponseTemplate::new(if verb == "POST" { 201 } else { 200 })
                    .set_body_string(&accepted),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{route}/{BROADCAST_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record.clone()))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for operation in ["create", "update"] {
        let mut args = json!({"operation":operation,"broadcast":requested,"confirm":true});
        if operation == "update" {
            args["broadcastId"] = json!(BROADCAST_ID);
        }
        let output = handler
            .call(&call("wifi.broadcasts.configure", args), None)
            .await
            .expect("write")
            .structured_content
            .expect("structured");
        assert_eq!(output["responseBody"], accepted);
        assert_eq!(output["after"], record);
        assert_eq!(output["verified"], true);
    }
}

#[tokio::test]
async fn forced_deletion_keeps_complete_acceptance_and_absence_evidence() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts/{BROADCAST_ID}");
    let body = "{\"removedReferences\":[\"profile\"],\"fixtureCredential\":\"upstream-value\"}";
    let missing = "{\"message\":\"exact upstream Wi-Fi missing\",\"extension\":true}";
    Mock::given(method("DELETE"))
        .and(path(&route))
        .and(query_param("force", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(404).set_body_string(missing))
        .mount(&server)
        .await;
    let output = handler_for(&server).call(&call("wifi.broadcasts.configure",json!({"operation":"delete","broadcastId":BROADCAST_ID,"force":true,"confirm":true})),None)
        .await.expect("accepted").structured_content.expect("structured");
    assert_eq!(output["responseBody"], body);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(output["verifiedAbsent"], true);
    assert!(
        output["readbackError"]
            .as_str()
            .expect("error")
            .contains(missing)
    );
}

#[tokio::test]
async fn oversized_acceptance_and_readback_error_remain_complete_in_content() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts");
    let accepted = json!({"id":BROADCAST_ID,"extension":"x".repeat(60_000)}).to_string();
    let failure = json!({"message":"read unavailable","extension":"y".repeat(60_000)}).to_string();
    Mock::given(method("POST"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(201).set_body_string(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{route}/{BROADCAST_ID}")))
        .respond_with(ResponseTemplate::new(503).set_body_string(&failure))
        .mount(&server)
        .await;
    let result = handler_for(&server).call(&call("wifi.broadcasts.configure",json!({"operation":"create","broadcast":broadcast(json!({"type":"OPEN"}),false),"confirm":true})),None)
        .await.expect("accepted");
    let content: Value = serde_json::to_value(&result.content).expect("content");
    let texts: Vec<&str> = content
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect();
    assert_eq!(
        texts
            .iter()
            .find_map(|text| text.strip_prefix("responseBody: "))
            .expect("body"),
        accepted
    );
    assert!(
        texts
            .iter()
            .find_map(|text| text.strip_prefix("readbackError: "))
            .expect("error")
            .contains(&failure)
    );
    let output = result.structured_content.expect("structured");
    assert_eq!(output["responseBodyInContent"], true);
    assert_eq!(output["readbackErrorInContent"], true);
}

#[tokio::test]
async fn rejected_writes_and_non_json_acceptance_are_not_rewritten_or_retried() {
    for status in [201, 422, 429] {
        let server = MockServer::start().await;
        mount_site(&server).await;
        let body = "exact controller reply with fixture-credential";
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts")))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler_for(&server).call(&call("wifi.broadcasts.configure",json!({"operation":"create","broadcast":broadcast(json!({"type":"OPEN"}),false),"confirm":true})),None).await;
        if status == 201 {
            let output = result
                .expect("acceptance")
                .structured_content
                .expect("structured");
            assert_eq!(output["responseBody"], body);
            assert!(output.get("verified").is_none());
        } else {
            assert!(result.expect_err("rejection").message.contains(body));
        }
    }
}

#[tokio::test]
async fn filtered_reads_preserve_page_extensions_and_large_records() {
    for large in [false, true] {
        let server = MockServer::start().await;
        mount_site(&server).await;
        let route = format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts");
        let record = json!({"id":BROADCAST_ID,"securityConfiguration":{"passphrase":"fixture-key"},"extension":if large {"z".repeat(60_000)} else {"present".to_owned()}});
        let filter = "name.eq('Lab Wi-Fi')";
        Mock::given(method("GET")).and(path(&route)).and(query_param("filter",filter))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"offset":0,"limit":50,"count":1,"totalCount":1,"data":[record.clone()],"pageExtension":{"fixtureCredential":"preserved"}})))
            .expect(1).mount(&server).await;
        Mock::given(method("GET"))
            .and(path(format!("{route}/{BROADCAST_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(record.clone()))
            .mount(&server)
            .await;
        let handler = handler_for(&server);
        let listed = handler
            .call(
                &call("wifi.broadcasts.list", json!({"filter":filter})),
                None,
            )
            .await
            .expect("page");
        let content: Value = serde_json::to_value(&listed.content).expect("content");
        let output = listed.structured_content.expect("structured");
        assert_eq!(
            output["pageMetadata"]["pageExtension"]["fixtureCredential"],
            "preserved"
        );
        if large {
            assert_eq!(output["broadcastsInContent"], true);
            let original = content
                .as_array()
                .expect("array")
                .iter()
                .find_map(|part| {
                    part.get("text")
                        .and_then(Value::as_str)
                        .and_then(|text| text.strip_prefix("broadcasts: "))
                })
                .expect("broadcasts content");
            assert_eq!(
                serde_json::from_str::<Value>(original).expect("JSON"),
                json!([record])
            );
        } else {
            assert_eq!(output["broadcasts"][0], record);
        }
        let detailed = handler
            .call(
                &call(
                    "wifi.broadcasts.status",
                    json!({"broadcastId":BROADCAST_ID}),
                ),
                None,
            )
            .await
            .expect("detail");
        if large {
            assert_eq!(
                detailed.structured_content.as_ref().expect("structured")["recordInContent"],
                true
            );
            let content: Value = serde_json::to_value(&detailed.content).expect("content");
            let original = content
                .as_array()
                .expect("array")
                .iter()
                .find_map(|part| {
                    part.get("text")
                        .and_then(Value::as_str)
                        .and_then(|text| text.strip_prefix("record: "))
                })
                .expect("record content");
            assert_eq!(
                serde_json::from_str::<Value>(original).expect("JSON"),
                record
            );
        } else {
            assert_eq!(detailed.structured_content.expect("structured"), record);
        }
    }
}

#[tokio::test]
async fn invalid_inputs_fail_before_controller_requests() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for (name, args) in [
        (
            "wifi.broadcasts.configure",
            json!({"operation":"create","broadcastId":BROADCAST_ID,"broadcast":broadcast(json!({"type":"OPEN"}),false)}),
        ),
        (
            "wifi.broadcasts.configure",
            json!({"operation":"update","broadcastId":BROADCAST_ID}),
        ),
        (
            "wifi.broadcasts.configure",
            json!({"operation":"delete","broadcastId":".."}),
        ),
        (
            "wifi.broadcasts.configure",
            json!({"operation":"create","broadcast":{"type":"UNKNOWN"}}),
        ),
        ("wifi.broadcasts.list", json!({"offset":2_147_483_648_u64})),
        ("wifi.broadcasts.list", json!({"filter":"x".repeat(2049)})),
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
async fn oversized_page_metadata_is_complete_and_empty_pages_beyond_the_total_are_valid() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let metadata = json!({"pageExtension":{"fixtureCredential":"m".repeat(60_000)}});
    let page = json!({"offset":10,"limit":50,"count":0,"totalCount":2,"data":[],
        "pageExtension":metadata["pageExtension"]});
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts")))
        .and(query_param("offset", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(&call("wifi.broadcasts.list", json!({"offset":10})), None)
        .await
        .expect("empty large page");
    let content: Value = serde_json::to_value(&result.content).expect("content");
    let original = content
        .as_array()
        .expect("array")
        .iter()
        .find_map(|part| {
            part.get("text")
                .and_then(Value::as_str)
                .and_then(|text| text.strip_prefix("pageMetadata: "))
        })
        .expect("metadata content");
    assert_eq!(
        serde_json::from_str::<Value>(original).expect("metadata JSON"),
        metadata
    );
    let output = result.structured_content.expect("structured");
    assert_eq!(output["pageMetadataInContent"], true);
    assert!(output.get("nextOffset").is_none());
}

#[tokio::test]
async fn update_observation_keeps_a_coerced_record_without_claiming_verification() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let requested = broadcast(json!({"type":"OPEN"}), false);
    let mut observed = requested.clone();
    observed["id"] = json!(BROADCAST_ID);
    observed["name"] = json!("controller kept another name");
    let route = format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts/{BROADCAST_ID}");
    Mock::given(method("PUT"))
        .and(path(&route))
        .and(body_json(requested.clone()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":BROADCAST_ID,"controllerExtension":"accepted"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(observed.clone()))
        .mount(&server)
        .await;
    let output = handler_for(&server).call(&call("wifi.broadcasts.configure",json!({"operation":"update","broadcastId":BROADCAST_ID,"broadcast":requested,"confirm":true})),None)
        .await.expect("accepted").structured_content.expect("structured");
    assert_eq!(output["verified"], false);
    assert_eq!(output["after"], observed);
    assert!(
        output["responseBody"]
            .as_str()
            .expect("body")
            .contains("controllerExtension")
    );
}

#[tokio::test]
async fn oversized_configuration_is_rejected_before_a_write() {
    let server = MockServer::start().await;
    let mut request = broadcast(json!({"type":"OPEN"}), false);
    request["name"] = json!("n".repeat(1_048_577));
    let error = handler_for(&server)
        .call(
            &call(
                "wifi.broadcasts.configure",
                json!({"operation":"create","broadcast":request,"confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("request bound");
    assert!(error.message.contains("1 MiB"));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn positional_page_arrays_return_the_complete_response_without_panicking() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let body = " [0,50,0,0,[]] ";
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/wifi/broadcasts")))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(&call("wifi.broadcasts.list", json!({})), None)
        .await
        .expect_err("invalid object page");
    assert!(error.message.contains(body), "{}", error.message);
    assert!(error.message.contains("page must be a JSON object"));
}
