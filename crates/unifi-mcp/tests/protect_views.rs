//! Protect viewer and live-view reads against bounded loopback responses.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, ProtectClient, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/protect/integration/v1";

fn handler_for(server: &MockServer) -> UnifiMcp {
    let protect = ProtectClient::new(&ControllerConfig {
        name: "cameras".to_owned(),
        base_url: Url::parse(&server.uri()).expect("mock server uri"),
        api_key: Zeroizing::new("test-protect-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("protect client");
    UnifiMcp::new_protect("cameras", Arc::new(protect), None)
}

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

#[tokio::test]
async fn viewer_and_liveview_lists_page_complete_records_and_read_details() {
    for (route, tool, field, id_field, id) in [
        (
            "viewers",
            "protect.viewers",
            "viewers",
            "viewerId",
            "viewer-2",
        ),
        (
            "liveviews",
            "protect.liveviews",
            "liveviews",
            "liveviewId",
            "liveview-2",
        ),
    ] {
        let server = MockServer::start().await;
        let first = serde_json::json!({"id": format!("{route}-1")});
        let second = serde_json::json!({
            "id": id, "name": "Front display", "streamLimit": 16,
            "slots": [{"cameras": ["camera-1"], "cycleMode": "time", "cycleInterval": 10}],
            "controllerSpecific": {"nested": ["kept", 42]},
        });
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([first, second.clone()])),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&second))
            .expect(1)
            .mount(&server)
            .await;
        let handler = handler_for(&server);

        let first_page = handler
            .call(
                &call(&format!("{tool}.list"), &serde_json::json!({"limit": 1})),
                None,
            )
            .await
            .expect("first page");
        assert_eq!(
            first_page.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
            true
        );
        let first_body = first_page
            .structured_content
            .expect("structured first page");
        assert_eq!(first_body["totalCount"], 2);
        assert_eq!(first_body["nextOffset"], 1);
        assert_eq!(first_body[field].as_array().expect("rows").len(), 1);

        let second_page = handler
            .call(
                &call(
                    &format!("{tool}.list"),
                    &serde_json::json!({"offset": 1, "limit": 1}),
                ),
                None,
            )
            .await
            .expect("second page")
            .structured_content
            .expect("structured second page");
        assert_eq!(second_page[field], serde_json::json!([second.clone()]));
        assert!(second_page.get("nextOffset").is_none());

        let detail = handler
            .call(
                &call(
                    &format!("{tool}.status"),
                    &serde_json::json!({(id_field): id}),
                ),
                None,
            )
            .await
            .expect("detail")
            .structured_content
            .expect("structured detail");
        let detail_field = if route == "viewers" {
            "viewer"
        } else {
            "liveview"
        };
        assert_eq!(detail[detail_field], second);
    }
}

#[tokio::test]
async fn wrong_view_identity_keeps_the_complete_controller_response() {
    for (route, tool, id_field) in [
        ("viewers", "protect.viewers.status", "viewerId"),
        ("liveviews", "protect.liveviews.status", "liveviewId"),
    ] {
        let server = MockServer::start().await;
        let response = serde_json::json!({
            "id": "another-id", "controllerSpecific": "view-identity-tail".repeat(100),
        });
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}/requested-id")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&server)
            .await;
        let error = handler_for(&server)
            .call(
                &call(tool, &serde_json::json!({(id_field): "requested-id"})),
                None,
            )
            .await
            .expect_err("wrong identity");
        assert!(error.message.contains(&response.to_string()));
    }
}

#[tokio::test]
async fn empty_viewer_inventory_is_distinct_from_an_absent_route() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/viewers")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let empty = handler_for(&server)
        .call(&call("protect.viewers.list", &serde_json::json!({})), None)
        .await
        .expect("empty inventory")
        .structured_content
        .expect("structured inventory");
    assert_eq!(empty["totalCount"], 0);
    assert_eq!(empty["viewers"], serde_json::json!([]));

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/viewers")))
        .respond_with(ResponseTemplate::new(404).set_body_string("viewer route absent"))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(&call("protect.viewers.list", &serde_json::json!({})), None)
        .await
        .expect_err("missing route");
    assert!(error.message.contains("HTTP 404: viewer route absent"));
}
