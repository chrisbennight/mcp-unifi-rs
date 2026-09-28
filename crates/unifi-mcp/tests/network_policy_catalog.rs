use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
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
async fn both_policy_collections_page_complete_rows_and_support_filtering() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    for (kind, route) in [
        ("dnsPolicies", "dns/policies"),
        ("trafficMatchingLists", "traffic-matching-lists"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/sites/{SITE_ID}/{route}")))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"))
            .and(query_param("filter", "name.eq('office')"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0, "limit": 1, "count": 1, "totalCount": 2,
                "data": [{"id": POLICY_ID, "type": kind, "controllerExtension": {"source": "upstream"}}]
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server);
    for kind in ["dnsPolicies", "trafficMatchingLists"] {
        let result = handler
            .call(
                &call(
                    "network.policy.list",
                    json!({"kind": kind, "limit": 1, "filter": "name.eq('office')"}),
                ),
                None,
            )
            .await
            .expect("policy page")
            .structured_content
            .expect("structured");
        assert_eq!(result["kind"], kind);
        assert_eq!(
            result["records"][0]["controllerExtension"]["source"],
            "upstream"
        );
        assert_eq!(result["nextOffset"], 1);
    }
}

#[tokio::test]
async fn both_detail_routes_preserve_fields_and_upstream_errors() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    for (kind, route) in [
        ("dnsPolicies", "dns/policies"),
        ("trafficMatchingLists", "traffic-matching-lists"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!(
                "{PREFIX}/sites/{SITE_ID}/{route}/{POLICY_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": POLICY_ID, "type": kind, "controllerExtension": {"owner": "upstream"}
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/dns/policies/missing"
        )))
        .respond_with(ResponseTemplate::new(404).set_body_string("controller DNS policy missing"))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for kind in ["dnsPolicies", "trafficMatchingLists"] {
        let result = handler
            .call(
                &call(
                    "network.policy.detail",
                    json!({"kind": kind, "id": POLICY_ID}),
                ),
                None,
            )
            .await
            .expect("policy detail")
            .structured_content
            .expect("structured");
        assert_eq!(result["record"]["controllerExtension"]["owner"], "upstream");
    }
    let error = handler
        .call(
            &call(
                "network.policy.detail",
                json!({"kind": "dnsPolicies", "id": "missing"}),
            ),
            None,
        )
        .await
        .expect_err("upstream 404");
    assert!(error.message.contains("controller DNS policy missing"));
}

#[tokio::test]
async fn contradictory_page_returns_the_complete_controller_response() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/dns/policies")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 0, "count": 2, "totalCount": 2,
            "data": [{"id": POLICY_ID}], "controllerExtension": "exact source value"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "network.policy.list",
                json!({"kind": "dnsPolicies", "limit": 1}),
            ),
            None,
        )
        .await
        .expect_err("bad page metadata");
    assert!(error.message.contains("exact source value"));
}

#[tokio::test]
async fn large_detail_retains_the_complete_record_in_content() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/dns/policies/{POLICY_ID}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": POLICY_ID, "controllerExtension": format!("{}controller-tail", "x".repeat(50_000))
        })))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "network.policy.detail",
                json!({"kind": "dnsPolicies", "id": POLICY_ID}),
            ),
            None,
        )
        .await
        .expect("large detail");
    assert_eq!(
        result.structured_content.expect("structured")["recordInContent"],
        true
    );
    assert!(
        result
            .content
            .iter()
            .any(|item| format!("{item:?}").contains("controller-tail"))
    );
}
