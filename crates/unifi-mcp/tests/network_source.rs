use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockBuilder, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};
use zeroize::Zeroizing;

const CASES: &[(&str, &str, &str)] = &[
    ("activeClients", "GET", "stat/sta"),
    ("siteHealth", "GET", "stat/health"),
    ("networkConfiguration", "GET", "rest/networkconf"),
    ("neighborAccessPoints", "GET", "stat/rogueap"),
    ("dpiCounters", "POST", "stat/sitedpi"),
];

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock URL");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "fixture".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("test-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "fixture".to_owned(),
        base_url,
        username: "test-user".to_owned(),
        password: Zeroizing::new("test-password".to_owned()),
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

fn call(arguments: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "network.source.read".into();
    params.arguments = Some(match arguments {
        Value::Object(map) => map,
        _ => panic!("object arguments"),
    });
    params
}

async fn login(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(server)
        .await;
}

fn source_mock(verb: &str, route: &str) -> MockBuilder {
    let mock = Mock::given(method(verb)).and(path(format!("/proxy/network/api/s/default/{route}")));
    if verb == "POST" {
        mock.and(body_json(json!({"type":"by_app"})))
    } else {
        mock
    }
}

#[tokio::test]
async fn every_source_preserves_fields_metadata_numbers_and_local_continuation() {
    let server = MockServer::start().await;
    login(&server).await;
    let envelope: Value = serde_json::from_str(
        r#"{"meta":{"rc":"ok","futureField":"value"},"extension":{"credential":"synthetic-value"},"data":[{"unknown":{"number":18446744073709551616,"fraction":0.123456789012345678901},"password":"synthetic-password"},{"id":"second","unknown":true},{"id":"third"}]}"#,
    )
    .expect("fixture JSON");
    for &(_, verb, route) in CASES {
        source_mock(verb, route)
            .respond_with(ResponseTemplate::new(200).set_body_json(&envelope))
            .expect(3)
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server);
    for &(source, _, _) in CASES {
        let first = handler
            .call(&call(json!({"source":source,"limit":1})), None)
            .await
            .expect("source read")
            .structured_content
            .expect("page");
        assert_eq!(first["records"], json!([envelope["data"][0]]));
        assert_eq!(
            first["records"][0]["unknown"]["number"].to_string(),
            "18446744073709551616"
        );
        assert_eq!(
            first["records"][0]["unknown"]["fraction"].to_string(),
            "0.123456789012345678901"
        );
        assert_eq!(first["controllerMetadata"]["meta"], envelope["meta"]);
        assert_eq!(
            first["controllerMetadata"]["extension"],
            envelope["extension"]
        );
        assert!(first["controllerMetadata"].get("data").is_none());
        assert_eq!(first["totalCount"], 3);
        assert_eq!(first["nextOffset"], 1);
        let second = handler
            .call(&call(json!({"source":source,"offset":1,"limit":2})), None)
            .await
            .expect("continuation")
            .structured_content
            .expect("page");
        assert_eq!(
            second["records"],
            json!([envelope["data"][1], envelope["data"][2]])
        );
        assert!(second.get("nextOffset").is_none());
        let deep = handler
            .call(&call(json!({"source":source,"offset":u64::MAX})), None)
            .await
            .expect("deep empty page")
            .structured_content
            .expect("page");
        assert_eq!(deep["records"], json!([]));
        assert_eq!(deep["totalCount"], 3);
        assert!(deep.get("nextOffset").is_none());
        assert!(
            deep["paginationNote"]
                .as_str()
                .expect("paging note")
                .contains("new response")
        );
    }
}

#[tokio::test]
async fn large_rows_and_metadata_remain_complete_in_labeled_content() {
    let server = MockServer::start().await;
    login(&server).await;
    let row = json!({"password":"row-fixture","extension":"x".repeat(70_000)});
    let metadata =
        json!({"rc":"ok","credential":"metadata-fixture","extension":"y".repeat(70_000)});
    source_mock("GET", "stat/sta")
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"meta":metadata,"data":[row]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(&call(json!({"source":"activeClients"})), None)
        .await
        .expect("complete large page");
    let structured = result.structured_content.expect("markers");
    assert_eq!(structured["recordsInContent"], true);
    assert_eq!(structured["controllerMetadataInContent"], true);
    let texts: Vec<&str> = result
        .content
        .iter()
        .filter_map(|b| b.as_text().map(|t| t.text.as_str()))
        .collect();
    let rows = texts
        .iter()
        .find_map(|s| s.strip_prefix("records: "))
        .expect("record content");
    assert_eq!(
        serde_json::from_str::<Value>(rows).expect("rows JSON"),
        json!([row])
    );
    let meta = texts
        .iter()
        .find_map(|s| s.strip_prefix("controllerMetadata: "))
        .expect("metadata content");
    assert_eq!(
        serde_json::from_str::<Value>(meta).expect("metadata JSON"),
        json!({"meta":metadata})
    );
}

#[tokio::test]
async fn every_source_returns_the_original_error_body() {
    let server = MockServer::start().await;
    login(&server).await;
    let body = format!("original controller rejection {}", "z".repeat(60_000));
    for &(_, verb, route) in CASES {
        source_mock(verb, route)
            .respond_with(ResponseTemplate::new(404).set_body_string(&body))
            .expect(1)
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server);
    for &(source, _, _) in CASES {
        let error = handler
            .call(&call(json!({"source":source})), None)
            .await
            .expect_err("original failure");
        assert!(error.message.contains(&body));
        assert!(error.message.contains("404"));
    }
}

#[tokio::test]
async fn invalid_inputs_do_not_make_controller_requests() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for input in [
        json!({"source":"arbitrary"}),
        json!({"source":"activeClients","limit":0}),
        json!({"source":"siteHealth","limit":201}),
        json!({"source":"dpiCounters","endpoint":"/other"}),
    ] {
        assert!(handler.call(&call(input), None).await.is_err());
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}
