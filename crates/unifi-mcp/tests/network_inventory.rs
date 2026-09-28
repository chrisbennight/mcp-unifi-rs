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
async fn every_documented_inventory_route_returns_full_rows_and_a_continuation() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let cases = [
        ("countries", "countries", true),
        ("deviceTags", "sites/SITE/device-tags", true),
        ("lags", "sites/SITE/switching/lags", true),
        ("mcLagDomains", "sites/SITE/switching/mc-lag-domains", true),
        ("switchStacks", "sites/SITE/switching/switch-stacks", true),
        ("wanInterfaces", "sites/SITE/wans", false),
        ("vpnServers", "sites/SITE/vpn/servers", true),
        (
            "siteToSiteVpnTunnels",
            "sites/SITE/vpn/site-to-site-tunnels",
            true,
        ),
    ];
    for (kind, route, has_filter) in cases {
        let route = route.replace("SITE", SITE_ID);
        let mut mock = Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}")))
            .and(query_param("offset", "0"))
            .and(query_param("limit", "1"));
        if has_filter {
            mock = mock.and(query_param("filter", "name.eq('office')"));
        }
        mock.respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 1, "count": 1, "totalCount": 2,
            "data": [{"id": kind, "controllerExtension": {"source": "upstream"}}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    }

    let handler = handler_for(&server);
    for (kind, _, has_filter) in cases {
        let mut args = json!({"kind": kind, "limit": 1});
        if has_filter {
            args["filter"] = json!("name.eq('office')");
        }
        let result = handler
            .call(&call("network.inventory.list", args), None)
            .await
            .expect("inventory page")
            .structured_content
            .expect("structured page");
        assert_eq!(result["kind"], kind);
        assert_eq!(
            result["records"][0]["controllerExtension"]["source"],
            "upstream"
        );
        assert_eq!(result["nextOffset"], 1);
    }
}

#[tokio::test]
async fn switching_details_preserve_controller_fields_and_upstream_errors() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    for (kind, route) in [
        ("lag", "lags"),
        ("mcLagDomain", "mc-lag-domains"),
        ("switchStack", "switch-stacks"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!(
                "{PREFIX}/sites/{SITE_ID}/switching/{route}/{kind}-1"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": format!("{kind}-1"), "controllerExtension": {"portCount": 4}
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/switching/lags/missing"
        )))
        .respond_with(
            ResponseTemplate::new(404).set_body_string("upstream lag missing: exact body"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for kind in ["lag", "mcLagDomain", "switchStack"] {
        let result = handler
            .call(
                &call(
                    "network.switching.detail",
                    json!({"kind": kind, "id": format!("{kind}-1")}),
                ),
                None,
            )
            .await
            .expect("switching detail")
            .structured_content
            .expect("structured detail");
        assert_eq!(result["record"]["controllerExtension"]["portCount"], 4);
    }
    let error = handler
        .call(
            &call(
                "network.switching.detail",
                json!({"kind": "lag", "id": "missing"}),
            ),
            None,
        )
        .await
        .expect_err("upstream 404");
    assert!(error.message.contains("upstream lag missing: exact body"));
}

#[tokio::test]
async fn contradictory_inventory_page_reports_the_complete_controller_response() {
    let server = MockServer::start().await;
    let upstream = json!({
        "offset": 0, "limit": 0, "count": 2, "totalCount": 2,
        "data": [{"id": "tag-1"}], "controllerExtension": "exact source value"
    });
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/countries")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&upstream))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "network.inventory.list",
                json!({"kind": "countries", "limit": 1}),
            ),
            None,
        )
        .await
        .expect_err("contradictory page");
    assert!(error.message.contains("controllerExtension"));
    assert!(error.message.contains("exact source value"));
}

#[tokio::test]
async fn unsupported_inventory_is_an_upstream_error_not_an_empty_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/countries")))
        .respond_with(ResponseTemplate::new(404).set_body_string("countries route unavailable"))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call("network.inventory.list", json!({"kind": "countries"})),
            None,
        )
        .await
        .expect_err("unsupported route");
    assert!(error.message.contains("countries route unavailable"));
}

#[tokio::test]
async fn large_switching_detail_retains_the_entire_record_in_content() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let extension = format!("{}controller-tail", "x".repeat(50_000));
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/switching/lags/large"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "large", "controllerExtension": extension
        })))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "network.switching.detail",
                json!({"kind": "lag", "id": "large"}),
            ),
            None,
        )
        .await
        .expect("large record");
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
