use serde_json::{Value, json};
use std::time::Duration;
use unifi_api::{
    LegacyClient, LegacyConfig, TlsMode, collection::SourceStatus, traffic::ActivityWindow,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};
use zeroize::Zeroizing;

const START: u64 = 1_789_200_000_000;
const END: u64 = START + 3_600_000;

async fn setup() -> (MockServer, LegacyClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let client = LegacyClient::new(&LegacyConfig {
        name: "synthetic".into(),
        base_url: server.uri().parse().unwrap(),
        username: "synthetic".into(),
        password: Zeroizing::new("test-password".into()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(2),
    })
    .unwrap();
    (server, client)
}

async fn mocks(server: &MockServer, activity: Value, graph_status: u16) {
    Mock::given(method("GET"))
        .and(path("/proxy/network/v2/api/site/default/traffic"))
        .and(query_param("start", START.to_string()))
        .and(query_param("end", END.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(activity))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST")).and(path("/proxy/network/v2/api/site/default/app-traffic-rate")).respond_with(ResponseTemplate::new(graph_status).set_body_json(json!([{"timestamp":START,"interval_seconds":3600,"rx_byte-r":1.2300,"extra":"retained"}]))).mount(server).await;
    Mock::given(method("POST")).and(path("/proxy/network/api/s/default/stat/report/hourly.site")).respond_with(ResponseTemplate::new(200).set_body_string(format!(r#"{{"meta":{{"rc":"ok","extra":"retained"}},"data":[{{"time":{START},"wan-rx_bytes":1.2300,"wan-tx_bytes":4,"unknown":123456789012345678901234567890}}]}}"#))).mount(server).await;
}

async fn fixed_sources(
    server: &MockServer,
    graph_status: u16,
    graph_body: String,
    wan_body: String,
) {
    Mock::given(method("GET"))
        .and(path("/proxy/network/v2/api/site/default/traffic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "client_usage_by_app": [], "total_usage_by_app": []
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/v2/api/site/default/app-traffic-rate"))
        .respond_with(ResponseTemplate::new(graph_status).set_body_string(graph_body))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/stat/report/hourly.site"))
        .respond_with(ResponseTemplate::new(200).set_body_string(wan_body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn one_read_retains_more_than_an_mcp_page_and_preserves_all_fields() {
    let (server, client) = setup().await;
    let rows: Vec<_> = (0..300_u16).map(|i| json!({"client":{"mac":format!("02:00:00:00:{:02x}:{:02x}", i/256,i%256),"name":"long name ".repeat(200),"fingerprint":{"original":true}},"usage_by_app":[{"application":1,"category":2,"bytes_received":1,"bytes_transmitted":2,"activity_seconds":99}]})).collect();
    let activity = json!({"client_usage_by_app":rows,"total_usage_by_app":[],"additional_metadata":{"retained":true}});
    mocks(&server, activity.clone(), 200).await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert!(snapshot.collected());
    assert_eq!(
        serde_json::from_str::<Value>(snapshot.activity.data.unwrap().get()).unwrap(),
        activity
    );
    let wan = snapshot.wan.data.unwrap();
    assert!(wan.get().contains("1.2300"));
    assert!(wan.get().contains("123456789012345678901234567890"));
    assert!(wan.get().contains("\"extra\":\"retained\""));
    assert!(snapshot.graph.data.unwrap().get().contains("rx_byte-r"));
}

#[tokio::test]
async fn unavailable_source_does_not_discard_successful_reports() {
    let (server, client) = setup().await;
    mocks(
        &server,
        json!({"client_usage_by_app":[],"total_usage_by_app":[]}),
        404,
    )
    .await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert!(!snapshot.collected());
    assert_eq!(snapshot.activity.status, SourceStatus::Collected);
    assert_eq!(snapshot.wan.status, SourceStatus::Collected);
    assert_eq!(snapshot.graph.status, SourceStatus::Unsupported);
    assert!(snapshot.activity.data.is_some());
}

#[tokio::test]
async fn unsupported_source_retains_the_controller_status_and_body() {
    let (server, client) = setup().await;
    let failure = format!("graph route missing: {}unsupported-tail", "x".repeat(700));
    fixed_sources(
        &server,
        405,
        failure.clone(),
        r#"{"meta":{"rc":"ok"},"data":[]}"#.to_owned(),
    )
    .await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert_eq!(snapshot.activity.status, SourceStatus::Collected);
    assert_eq!(snapshot.wan.status, SourceStatus::Collected);
    assert_eq!(snapshot.graph.status, SourceStatus::Unsupported);
    assert_eq!(
        snapshot.graph.error,
        Some(format!("controller returned HTTP 405: {failure}"))
    );
}

#[tokio::test]
async fn failed_source_retains_the_controller_response_beside_successful_reports() {
    let (server, client) = setup().await;
    let failure = format!("graph unavailable: {}graph-error-tail", "x".repeat(700));
    fixed_sources(
        &server,
        503,
        failure.clone(),
        r#"{"meta":{"rc":"ok"},"data":[]}"#.to_owned(),
    )
    .await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert_eq!(snapshot.activity.status, SourceStatus::Collected);
    assert_eq!(snapshot.wan.status, SourceStatus::Collected);
    assert_eq!(snapshot.graph.status, SourceStatus::Failed);
    assert_eq!(
        snapshot.graph.error,
        Some(format!("controller returned HTTP 503: {failure}"))
    );
}

#[tokio::test]
async fn rate_limited_source_retains_the_controller_status_and_body() {
    let (server, client) = setup().await;
    let failure = format!("try later: {}rate-limit-tail", "x".repeat(700));
    fixed_sources(
        &server,
        429,
        failure.clone(),
        r#"{"meta":{"rc":"ok"},"data":[]}"#.to_owned(),
    )
    .await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert_eq!(snapshot.graph.status, SourceStatus::Failed);
    assert_eq!(
        snapshot.graph.error,
        Some(format!("controller returned HTTP 429: {failure}"))
    );
}

#[tokio::test]
async fn malformed_wan_response_retains_the_controller_body() {
    let (server, client) = setup().await;
    let malformed = format!("not JSON {}wan-error-tail", "x".repeat(700));
    fixed_sources(&server, 200, "[]".to_owned(), malformed.clone()).await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert_eq!(snapshot.activity.status, SourceStatus::Collected);
    assert_eq!(snapshot.graph.status, SourceStatus::Collected);
    assert_eq!(snapshot.wan.status, SourceStatus::Failed);
    let error = snapshot.wan.error.expect("source error");
    assert!(error.contains(&malformed));
    assert!(error.contains("decode error"));
}

#[tokio::test]
async fn unrecognized_data_is_retained_but_never_claimed_as_collected_report() {
    let (server, client) = setup().await;
    mocks(&server, json!({"new_report_format":[1,2,3]}), 200).await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert_eq!(snapshot.activity.status, SourceStatus::Unrecognized);
    assert!(
        snapshot
            .activity
            .data
            .unwrap()
            .get()
            .contains("new_report_format")
    );
}

#[tokio::test]
async fn reports_preserve_large_client_collections() {
    let (server, client) = setup().await;
    let row = json!({"client":{"mac":"02:00:00:00:00:01"},"usage_by_app":[]});
    mocks(
        &server,
        json!({"client_usage_by_app":vec![row;1001],"total_usage_by_app":[]}),
        200,
    )
    .await;
    let snapshot = client
        .collect_traffic("default", ActivityWindow::new(START, END).unwrap())
        .await
        .unwrap();
    assert_eq!(snapshot.activity.status, SourceStatus::Collected);
    let archived: Value = serde_json::from_str(snapshot.activity.data.unwrap().get()).unwrap();
    assert_eq!(
        archived["client_usage_by_app"].as_array().unwrap().len(),
        1001
    );
}
