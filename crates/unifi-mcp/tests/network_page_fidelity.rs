use std::{sync::Arc, time::Duration};

use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/network/integration/v1";
const SITE: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";

fn handler(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("loopback URL");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "fixture".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("fixture-api-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "fixture".to_owned(),
        base_url,
        username: "fixture-user".to_owned(),
        password: Zeroizing::new("fixture-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "fixture",
        "default",
    )
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

async fn site(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset":0,"limit":100,"count":1,"totalCount":1,
            "data":[{"id":SITE,"name":"Default","internalReference":"default"}]
        })))
        .mount(server)
        .await;
}

fn cases() -> [(String, &'static str, &'static str, Value); 3] {
    [
        (
            "pending-devices".to_owned(),
            "devices.pending.list",
            "devices",
            json!({}),
        ),
        (
            format!("sites/{SITE}/radius/profiles"),
            "radius_profiles.list",
            "profiles",
            json!({}),
        ),
        (
            format!("sites/{SITE}/firewall/policies"),
            "network.policy.list",
            "records",
            json!({"kind":"firewallPolicies"}),
        ),
    ]
}

fn value_from_content(result: &CallToolResult, name: &str) -> Value {
    let prefix = format!("{name}: ");
    let text = result
        .content
        .iter()
        .filter_map(|block| block.as_text())
        .find_map(|text| text.text.strip_prefix(&prefix))
        .expect("labeled content");
    serde_json::from_str(text).expect("complete content JSON")
}

#[tokio::test]
async fn list_records_metadata_and_filters_are_complete() {
    let server = MockServer::start().await;
    site(&server).await;
    let client = handler(&server);
    for (route, tool, records_name, mut arguments) in cases() {
        arguments["limit"] = json!(1);
        arguments["filter"] = json!("name.eq('office')");
        let body = json!({"offset":0,"limit":1,"count":1,"totalCount":2,
            "data":[{"id":"fixture-id","unknownField":{"credential":"fixture-record"}}],
            "unknownMetadata":{"credential":"fixture-metadata","precision":serde_json::from_str::<Value>("184467440737095516170123").expect("precise number")}});
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}")))
            .and(query_param("filter", "name.eq('office')"))
            .and(query_param("limit", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        let result = client
            .call(&call(tool, arguments), None)
            .await
            .expect("complete page");
        let output = result.structured_content.expect("structured");
        let mut metadata = body.clone();
        metadata.as_object_mut().expect("object").remove("data");
        assert_eq!(output[records_name], body["data"], "{tool}");
        assert_eq!(output["pageMetadata"], metadata, "{tool}");
        assert_eq!(output["nextOffset"], 1, "{tool}");
    }
}

#[tokio::test]
async fn large_list_records_and_metadata_remain_available() {
    let server = MockServer::start().await;
    site(&server).await;
    let client = handler(&server);
    for (route, tool, records_name, arguments) in cases() {
        let body = json!({"offset":0,"limit":50,"count":1,"totalCount":1,
            "data":[{"id":"fixture-id","credential":"r".repeat(60000)}],
            "unknownMetadata":{"credential":"m".repeat(60000)}});
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        let result = client
            .call(&call(tool, arguments), None)
            .await
            .expect("large page");
        let output = result.structured_content.as_ref().expect("structured");
        assert_eq!(output[format!("{records_name}InContent")], true, "{tool}");
        assert_eq!(output["pageMetadataInContent"], true, "{tool}");
        let mut metadata = body.clone();
        metadata.as_object_mut().expect("object").remove("data");
        assert_eq!(
            value_from_content(&result, records_name),
            body["data"],
            "{tool}"
        );
        assert_eq!(
            value_from_content(&result, "pageMetadata"),
            metadata,
            "{tool}"
        );
    }
}

#[tokio::test]
async fn empty_pages_after_the_collection_are_valid() {
    let server = MockServer::start().await;
    site(&server).await;
    let client = handler(&server);
    for (route, tool, records_name, mut arguments) in cases() {
        arguments["offset"] = json!(500_000);
        Mock::given(method("GET")).and(path(format!("{PREFIX}/{route}")))
            .and(query_param("offset","500000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset":500_000,"limit":50,"count":0,"totalCount":1,"data":[],"unknownMetadata":"preserved"
            }))).expect(1).mount(&server).await;
        let result = client
            .call(&call(tool, arguments), None)
            .await
            .expect("valid empty page");
        let output = result.structured_content.expect("structured");
        assert_eq!(output[records_name], json!([]), "{tool}");
        assert_eq!(
            output["pageMetadata"]["unknownMetadata"], "preserved",
            "{tool}"
        );
        assert!(output.get("nextOffset").is_none(), "{tool}");
    }
}

#[tokio::test]
async fn inconsistent_radius_total_retains_the_original_page() {
    let server = MockServer::start().await;
    site(&server).await;
    let body = " {\"offset\":0,\"limit\":50,\"count\":1,\"totalCount\":0,\"data\":[{\"credential\":\"fixture-original\"}],\"unknownMetadata\":true} ";
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE}/radius/profiles")))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler(&server)
        .call(&call("radius_profiles.list", json!({})), None)
        .await
        .expect_err("contradictory total");
    assert!(error.message.contains(body), "{}", error.message);
}
