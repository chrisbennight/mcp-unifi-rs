//! Activity reports must return useful attribution, not only missing-data statuses.
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path, query_param},
};
use zeroize::Zeroizing;
const API_KEY: &str = "test-integration-key";
const USERNAME: &str = "svc-mcp";
const PASSWORD: &str = "test-legacy-password";
const START: u64 = 1_789_200_000_000;
const END: u64 = START + 7_200_000;
const TRAFFIC: &str = "/proxy/network/v2/api/site/default/traffic";
const GRAPH: &str = "/proxy/network/v2/api/site/default/app-traffic-rate";
const WAN: &str = "/proxy/network/api/s/default/stat/report/hourly.site";
fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new(API_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

async fn login_mock(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=session-1; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .mount(server)
        .await;
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/network_10_6_106_activity.json")).unwrap()
}
fn args(report: &str) -> Value {
    json!({"report":report,"startMs":START,"endMs":END})
}
async fn activity_mock(server: &MockServer, data: Value) {
    Mock::given(method("GET"))
        .and(path(TRAFFIC))
        .and(query_param("start", START.to_string()))
        .and(query_param("end", END.to_string()))
        .and(query_param("includeUnidentified", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(data))
        .mount(server)
        .await;
}
async fn evidence_mock(server: &MockServer, wan: Value) {
    Mock::given(method("POST")).and(path(GRAPH)).and(query_param("start",START.to_string())).and(query_param("end",END.to_string())).and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"timestamp":START+3_600_000,"interval_seconds":3600,"rx_byte-r":1,"tx_byte-r":2,"total_bytes":300},{"timestamp":END,"interval_seconds":3600}]))).mount(server).await;
    Mock::given(method("POST"))
        .and(path(WAN))
        .and(body_json(
            json!({"attrs":["time","wan-tx_bytes","wan-rx_bytes"],"start":START,"end":END}),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"meta":{"rc":"ok"},"data":wan})),
        )
        .mount(server)
        .await;
}
fn wan() -> Value {
    json!([{"time":START,"wan-rx_bytes":500.5,"wan-tx_bytes":20.0},{"time":START+3_600_000,"wan-rx_bytes":400.5,"wan-tx_bytes":30.0},{"time":END,"wan-rx_bytes":9999.0,"wan-tx_bytes":9999.0}])
}
async fn query(server: &MockServer, args: Value) -> Value {
    handler_for(server)
        .call(&call("stats.query", &args), None)
        .await
        .expect("activity report")
        .structured_content
        .expect("structured")
}

#[tokio::test]
async fn client_totals_are_useful_paginated_and_reconciled_over_identical_windows() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    activity_mock(&server, fixture()).await;
    evidence_mock(&server, wan()).await;
    let mut input = args("clientWanHistory");
    input["limit"] = json!(1);
    let output = query(&server, input.clone()).await;
    assert_eq!(output["counterSemantics"]["source"], "v2/traffic");
    assert_eq!(output["coverage"]["status"], "partial");
    let activity = &output["activity"];
    assert_eq!(activity["clients"][0]["name"], "Synthetic server");
    assert_eq!(activity["clients"][0]["rxBytes"], 600);
    assert_eq!(activity["clients"][0]["txBytes"], 50);
    assert_eq!(
        activity["clientTotals"],
        json!({"rxBytes":700,"txBytes":60})
    );
    assert_eq!(activity["applicationTotals"], activity["clientTotals"]);
    assert_eq!(activity["nextOffset"], 1);
    assert_eq!(activity["reconciliation"]["siteRxBytes"], 901.0);
    assert_eq!(activity["reconciliation"]["unmatchedRxBytes"], 201.0);
    assert_eq!(activity["reconciliation"]["unmatchedTxBytes"], -10.0);
    assert_eq!(
        activity["temporalEvidence"]["observedStartMs"],
        START + 3_600_000
    );
    assert_eq!(activity["temporalEvidence"]["observedEndMs"], END);
    assert_eq!(
        activity["temporalEvidence"]["perClientObservedIntervalKnown"],
        false
    );
    assert!(!output.to_string().contains("fingerprint"));
    assert!(!output.to_string().contains("excluded"));
    input["offset"] = json!(1);
    let page = query(&server, input).await;
    assert_eq!(page["activity"]["clients"][0]["rxBytes"], 100);
    assert_eq!(page["activity"]["clientTotals"], activity["clientTotals"]);
    assert!(page["activity"]["nextOffset"].is_null());
}

#[tokio::test]
async fn duplicate_wan_comparison_buckets_keep_the_complete_controller_response() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    activity_mock(&server, fixture()).await;
    let wan = json!([
        {"time": START, "wan-rx_bytes": 500.5, "wan-tx_bytes": 20.0},
        {"time": START, "wan-rx_bytes": 400.5, "wan-tx_bytes": 30.0,
         "controllerDetail": "duplicate-wan-tail".repeat(100)}
    ]);
    evidence_mock(&server, wan.clone()).await;
    let accepted = json!({"meta": {"rc": "ok"}, "data": wan});

    let error = handler_for(&server)
        .call(&call("stats.query", &args("clientWanHistory")), None)
        .await
        .expect_err("duplicate WAN hour");
    assert!(error.message.contains("invalid or duplicate buckets"));
    assert!(error.message.contains(&accepted.to_string()));
}

#[tokio::test]
async fn application_ranking_uses_verified_category_and_application_name_mapping() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    activity_mock(&server, fixture()).await;
    evidence_mock(&server, wan()).await;
    for (kind, filter, data) in [
        (
            "applications",
            "id.in(196649)",
            json!([{"id":196_649,"name":"GitHub"}]),
        ),
        (
            "categories",
            "id.in(3)",
            json!([{"id":3,"name":"File sharing"}]),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/proxy/network/integration/v1/dpi/{kind}")))
            .and(query_param("filter", filter))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"offset":0,"limit":50,"count":1,"totalCount":2112,"data":data}),
            ))
            .expect(1)
            .mount(&server)
            .await;
    }
    let mut input = args("dpiApplications");
    input["top"] = json!(1);
    let output = query(&server, input).await;
    assert_eq!(output["totalApplications"], 2);
    assert_eq!(
        output["topApplications"],
        json!([{"applicationId":41,"categoryId":3,"applicationName":"GitHub","categoryName":"File sharing","rxBytes":400,"txBytes":20}])
    );
    assert_eq!(output["activity"]["namesStatus"], "reported");
}

#[tokio::test]
async fn invalid_dpi_lookup_returns_its_controller_response_with_activity() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    activity_mock(&server, fixture()).await;
    evidence_mock(&server, wan()).await;
    let body = json!({
        "offset": 0, "limit": 50, "count": 1, "totalCount": 2112,
        "data": [{"id": 7, "name": "Unexpected"}],
        "padding": "x".repeat(700),
        "z_controller_field": "original-dpi-tail"
    });
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/dpi/applications"))
        .and(query_param("filter", "id.in(196649)"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/dpi/categories"))
        .and(query_param("filter", "id.in(3)"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 50, "count": 1, "totalCount": 2112,
            "data": [{"id": 3, "name": "File sharing"}]
        })))
        .mount(&server)
        .await;

    let mut input = args("dpiApplications");
    input["top"] = json!(1);
    let output = query(&server, input).await;
    assert_eq!(output["topApplications"][0]["rxBytes"], 400);
    assert_eq!(output["activity"]["namesStatus"], "unavailable");
    assert_eq!(output["sourceErrors"][0]["source"], "dpiApplications");
    assert!(
        output["sourceErrors"][0]["error"]
            .as_str()
            .expect("error")
            .contains(&body.to_string())
    );
}

#[tokio::test]
async fn missing_names_and_wan_hours_preserve_measured_activity_without_fake_reconciliation() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    activity_mock(&server, fixture()).await;
    evidence_mock(&server, json!([])).await;
    let output = query(&server, args("dpiApplications")).await;
    assert_eq!(output["topApplications"][0]["rxBytes"], 400);
    assert_eq!(output["activity"]["namesStatus"], "unavailable");
    assert_eq!(
        output["activity"]["reconciliation"]["status"],
        "incompleteWan"
    );
    assert!(output["activity"]["reconciliation"]["unmatchedRxBytes"].is_null());
}

#[tokio::test]
async fn empty_and_real_zero_activity_are_distinct() {
    for (data, status) in [
        (
            json!({"client_usage_by_app":[],"total_usage_by_app":[]}),
            "empty",
        ),
        (
            json!({"client_usage_by_app":[],"total_usage_by_app":[{"application":1,"category":2,"bytes_received":0,"bytes_transmitted":0}]}),
            "partial",
        ),
    ] {
        let server = MockServer::start().await;
        login_mock(&server).await;
        activity_mock(&server, data).await;
        evidence_mock(&server, json!([])).await;
        let output = query(&server, args("dpiApplications")).await;
        assert_eq!(output["coverage"]["status"], status);
        if status == "partial" {
            assert_eq!(output["topApplications"][0]["rxBytes"], 0);
        }
    }
}

#[tokio::test]
async fn malformed_activity_preserves_the_controller_response() {
    for data in [
        json!({}),
        json!({"client_usage_by_app":[],"total_usage_by_app":[{"application":1,"category":2,"bytes_received":-1,"bytes_transmitted":0}]}),
    ] {
        let server = MockServer::start().await;
        login_mock(&server).await;
        activity_mock(&server, data.clone()).await;
        let error = handler_for(&server)
            .call(&call("stats.query", &args("dpiApplications")), None)
            .await
            .expect_err("malformed activity response");
        assert!(error.message.contains(&data.to_string()));
        assert!(error.message.contains("decode error:"));
    }
}

#[tokio::test]
async fn activity_validation_error_reaches_the_tool_caller() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let mut report = fixture();
    report["client_usage_by_app"][0]["client"]["name"] =
        json!(format!("{}controller-name-tail", "x".repeat(4096)));
    report["controller_extra"] = json!("original-controller-field");
    activity_mock(&server, report.clone()).await;

    let error = handler_for(&server)
        .call(&call("stats.query", &args("clientWanHistory")), None)
        .await
        .expect_err("activity name exceeds typed bound");
    assert!(
        error.message.contains(&report.to_string()),
        "{}",
        error.message
    );
    assert!(
        error.message.contains("activity report exceeds"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn invalid_inputs_make_no_controller_requests() {
    let server = MockServer::start().await;
    for input in [
        json!({"report":"clientWanHistory","hours":169}),
        json!({"report":"clientWanHistory","startMs":START}),
        json!({"report":"clientWanHistory","startMs":START,"endMs":END,"hours":2}),
        json!({"report":"clientWanHistory","startMs":START+1,"endMs":END}),
        json!({"report":"clientWanHistory","limit":0}),
        json!({"report":"dpiApplications","limit":1}),
        json!({"report":"clientWanHistory","top":1}),
    ] {
        assert!(
            handler_for(&server)
                .call(&call("stats.query", &input), None)
                .await
                .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn bounds_duplicates_and_overflow_fail_loudly() {
    let mut duplicate_client = fixture();
    let first = duplicate_client["client_usage_by_app"][0].clone();
    duplicate_client["client_usage_by_app"]
        .as_array_mut()
        .unwrap()
        .push(first);
    let mut duplicate_app = fixture();
    let first = duplicate_app["total_usage_by_app"][0].clone();
    duplicate_app["total_usage_by_app"]
        .as_array_mut()
        .unwrap()
        .push(first);
    let mut overflow = fixture();
    overflow["client_usage_by_app"][0]["usage_by_app"][0]["bytes_received"] = json!(u64::MAX);
    for mut data in [duplicate_client, duplicate_app, overflow] {
        let server = MockServer::start().await;
        login_mock(&server).await;
        data["z_controller_field"] = json!(format!("{}original-tail", "x".repeat(700)));
        let original_body = data.to_string();
        activity_mock(&server, data).await;
        let error = handler_for(&server)
            .call(&call("stats.query", &args("clientWanHistory")), None)
            .await
            .expect_err("invalid counters");
        assert!(error.message.contains(&original_body), "{}", error.message);
    }
    let server = MockServer::start().await;
    login_mock(&server).await;
    let mut oversized = fixture();
    oversized["client_usage_by_app"] =
        json!(vec![fixture()["client_usage_by_app"][0].clone(); 1001]);
    activity_mock(&server, oversized).await;
    assert!(
        handler_for(&server)
            .call(&call("stats.query", &args("clientWanHistory")), None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn explicit_application_window_never_falls_back_to_untimed_counters() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let output = query(&server, args("dpiApplications")).await;
    assert_eq!(output["coverage"]["status"], "unsupported");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn unsupported_activity_and_dpi_retain_both_controller_responses() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let activity_body = format!("activity missing: {}activity-tail", "a".repeat(700));
    let dpi_body = format!("dpi missing: {}dpi-tail", "d".repeat(700));
    Mock::given(method("GET"))
        .and(path(TRAFFIC))
        .respond_with(ResponseTemplate::new(404).set_body_string(activity_body.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/stat/sitedpi"))
        .respond_with(ResponseTemplate::new(405).set_body_string(dpi_body.clone()))
        .mount(&server)
        .await;
    let output = query(&server, json!({"report":"dpiApplications"})).await;
    assert_eq!(output["coverage"]["status"], "unsupported");
    assert_eq!(output["sourceErrors"][0]["source"], "activity");
    assert_eq!(
        output["sourceErrors"][0]["error"],
        format!("controller returned HTTP 404: {activity_body}")
    );
    assert_eq!(output["sourceErrors"][1]["source"], "dpi");
    assert_eq!(
        output["sourceErrors"][1]["error"],
        format!("controller returned HTTP 405: {dpi_body}")
    );
}

#[tokio::test]
async fn failed_dpi_fallback_retains_the_preceding_activity_response() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let activity_body = format!("activity missing: {}activity-tail", "a".repeat(700));
    let dpi_body = format!("dpi failed: {}dpi-tail", "d".repeat(700));
    Mock::given(method("GET"))
        .and(path(TRAFFIC))
        .respond_with(ResponseTemplate::new(404).set_body_string(activity_body.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/stat/sitedpi"))
        .respond_with(ResponseTemplate::new(503).set_body_string(dpi_body.clone()))
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call("stats.query", &json!({"report":"dpiApplications"})),
            None,
        )
        .await
        .expect_err("DPI fallback failure");
    assert!(error.message.contains(&format!(
        "activity source: controller returned HTTP 404: {activity_body}"
    )));
    assert!(error.message.contains(&format!(
        "dpi source: controller returned HTTP 503: {dpi_body}"
    )));
}

#[tokio::test]
async fn large_unsupported_graph_response_preserves_activity_and_error() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    activity_mock(&server, fixture()).await;
    let graph_body = format!("graph route missing: {}graph-tail", "g".repeat(50_000));
    Mock::given(method("POST"))
        .and(path(GRAPH))
        .respond_with(ResponseTemplate::new(405).set_body_string(graph_body.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(WAN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta":{"rc":"ok"}, "data":wan()
        })))
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(&call("stats.query", &args("clientWanHistory")), None)
        .await
        .expect("activity with unsupported graph");
    let output = result.structured_content.expect("structured activity");
    assert!(
        output["activity"]["clients"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    );
    assert_eq!(
        output["activity"]["temporalEvidence"]["status"],
        "unavailable"
    );
    assert_eq!(output["sourceErrorsInContent"], true);
    assert!(result.content.iter().any(|content| {
        matches!(content, rmcp::model::ContentBlock::Text(text) if text.text.contains(&graph_body))
    }));
}

#[tokio::test]
async fn large_activity_page_and_graph_error_both_reach_the_caller() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let mut report = fixture();
    let mut clients = Vec::new();
    for index in 0..200u16 {
        let mut row = report["client_usage_by_app"][0].clone();
        row["client"]["mac"] = json!(format!(
            "02:00:00:00:{:02x}:{:02x}",
            index / 256,
            index % 256
        ));
        row["client"]["name"] = json!("n".repeat(240));
        clients.push(row);
    }
    report["client_usage_by_app"] = json!(clients);
    activity_mock(&server, report).await;
    let graph_body = format!("graph missing: {}graph-tail", "g".repeat(700));
    Mock::given(method("POST"))
        .and(path(GRAPH))
        .respond_with(ResponseTemplate::new(404).set_body_string(graph_body.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(WAN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta":{"rc":"ok"}, "data":wan()
        })))
        .mount(&server)
        .await;
    let mut input = args("clientWanHistory");
    input["limit"] = json!(200);
    let result = handler_for(&server)
        .call(&call("stats.query", &input), None)
        .await
        .expect("large activity page and graph error");
    let output = result.structured_content.expect("structured summary");
    assert_eq!(output["activityInContent"], true);
    assert_eq!(output["sourceErrorsInContent"], true);
    assert!(result.content.iter().any(|content| {
        matches!(content, rmcp::model::ContentBlock::Text(text) if text.text.contains("02:00:00:00:00:c7"))
    }));
    assert!(result.content.iter().any(|content| {
        matches!(content, rmcp::model::ContentBlock::Text(text) if text.text.contains(&graph_body))
    }));
}

#[tokio::test]
async fn activity_permission_and_session_errors_do_not_become_missing_data() {
    for status in [401, 403] {
        let server = MockServer::start().await;
        login_mock(&server).await;
        Mock::given(method("GET"))
            .and(path(TRAFFIC))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string("private upstream test-legacy-password"),
            )
            .mount(&server)
            .await;
        let error = handler_for(&server)
            .call(&call("stats.query", &args("dpiApplications")), None)
            .await
            .expect_err("authorization error");
        assert!(error.message.contains("private upstream"));
        assert!(error.message.contains(PASSWORD));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| !r.url.path().ends_with("sitedpi"))
        );
    }
}

#[tokio::test]
async fn absent_client_counters_cannot_become_measured_zero() {
    let server = MockServer::start().await;
    login_mock(&server).await;
    let mut data = fixture();
    data["client_usage_by_app"][0]["usage_by_app"] = json!([]);
    activity_mock(&server, data).await;
    assert!(
        handler_for(&server)
            .call(&call("stats.query", &args("clientWanHistory")), None)
            .await
            .is_err()
    );
}
