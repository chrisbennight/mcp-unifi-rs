use std::{sync::Arc, time::Duration};

use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Value, json};
use unifi_api::{
    ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, ProtectClient, TlsMode,
};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

fn handler(server: &MockServer, protect: bool) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("loopback URL");
    let config = ControllerConfig {
        name: "fixture".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("fixture-api-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    };
    if protect {
        return UnifiMcp::new_protect(
            "fixture",
            Arc::new(ProtectClient::new(&config).expect("Protect client")),
            None,
        );
    }
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
        Arc::new(IntegrationClient::new(&config).expect("Integration client")),
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

fn cases() -> [(bool, &'static str, &'static str, Value); 3] {
    [
        (
            false,
            "/proxy/network/integration/v1/info",
            "network.inventory.detail",
            json!({"kind":"applicationInfo"}),
        ),
        (
            true,
            "/proxy/protect/integration/v1/meta/info",
            "protect.overview",
            json!({"view":"applicationInfo"}),
        ),
        (
            true,
            "/proxy/protect/integration/v1/nvrs",
            "protect.overview",
            json!({"view":"recorder"}),
        ),
    ]
}

fn record_from_content(result: &CallToolResult) -> Value {
    let text = result
        .content
        .iter()
        .filter_map(|block| block.as_text())
        .find_map(|text| text.text.strip_prefix("record: "))
        .expect("complete record content");
    serde_json::from_str(text).expect("complete JSON")
}

#[tokio::test]
async fn controller_views_preserve_complete_records_without_other_inventory_reads() {
    for (protect, route, tool, arguments) in cases() {
        let server = MockServer::start().await;
        let body = r#"{"applicationVersion":"fixture-version","id":"fixture-recorder","modelKey":"nvr","name":"Fixture","unknownField":{"fixtureCredential":"controller-fixture","number":184467440737095516170123}}"#;
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler(&server, protect)
            .call(&call(tool, arguments), None)
            .await
            .expect("complete controller record");
        assert_eq!(
            result.structured_content.expect("structured")["record"],
            serde_json::from_str::<Value>(body).expect("original JSON")
        );
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }
}

#[tokio::test]
async fn large_controller_records_remain_available_in_content() {
    for (protect, route, tool, arguments) in cases() {
        let server = MockServer::start().await;
        let body = json!({"applicationVersion":"fixture-version","id":"fixture-recorder","modelKey":"nvr","name":"Fixture","unknownField":{"fixtureCredential":"x".repeat(60000)}});
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler(&server, protect)
            .call(&call(tool, arguments), None)
            .await
            .expect("large record");
        assert_eq!(
            result.structured_content.as_ref().expect("structured")["recordInContent"],
            true
        );
        assert_eq!(record_from_content(&result), body);
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }
}

#[tokio::test]
async fn controller_views_return_original_upstream_errors() {
    for (protect, route, tool, arguments) in cases() {
        let server = MockServer::start().await;
        let body = " {\"upstreamError\":\"exact controller reason\",\"fixtureCredential\":\"controller-fixture\"} ";
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(403).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let error = handler(&server, protect)
            .call(&call(tool, arguments), None)
            .await
            .expect_err("upstream error");
        assert!(error.message.contains(body), "{}", error.message);
        assert!(error.message.contains("403"));
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }
}

#[tokio::test]
async fn overview_bootstrap_fields_cannot_be_mixed_with_another_view() {
    let server = MockServer::start().await;
    let error = handler(&server, true)
        .call(
            &call(
                "protect.overview",
                json!({"view":"recorder","detailFields":["nvr"]}),
            ),
            None,
        )
        .await
        .expect_err("incompatible parameters");
    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn inventory_detail_ids_match_the_selected_record_kind() {
    let server = MockServer::start().await;
    let client = handler(&server, false);
    for arguments in [
        json!({"kind":"client"}),
        json!({"kind":"deviceStatistics"}),
        json!({"kind":"applicationInfo","id":"unexpected-id"}),
    ] {
        let error = client
            .call(&call("network.inventory.detail", arguments), None)
            .await
            .expect_err("invalid record selector");
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}
