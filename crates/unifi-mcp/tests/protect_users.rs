//! Protect user reads against bounded loopback responses.

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
async fn both_user_families_page_and_read_full_details() {
    for (kind, route) in [("user", "users"), ("identityUser", "ulp-users")] {
        let server = MockServer::start().await;
        let first = serde_json::json!({"id": "user-1", "name": "First"});
        let second = serde_json::json!({
            "id": "user-2", "email": "user@example.invalid",
            "controllerSpecific": {"nested": ["kept", 42]},
        });
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([first, second.clone()])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}/user-2")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&second))
            .expect(1)
            .mount(&server)
            .await;
        let handler = handler_for(&server);

        let list = handler
            .call(
                &call(
                    "protect.users.list",
                    &serde_json::json!({"kind": kind, "offset": 1, "limit": 1}),
                ),
                None,
            )
            .await
            .expect("user list");
        let list_result = list.structured_content.expect("structured list");
        assert_eq!(list_result["kind"], kind);
        assert_eq!(list_result["users"], serde_json::json!([second.clone()]));
        assert_eq!(list_result["totalCount"], 2);
        assert!(list_result.get("nextOffset").is_none());
        assert_eq!(
            list.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
            true
        );

        let detail = handler
            .call(
                &call(
                    "protect.users.status",
                    &serde_json::json!({"kind": kind, "userId": "user-2"}),
                ),
                None,
            )
            .await
            .expect("user detail")
            .structured_content
            .expect("structured detail");
        assert_eq!(detail["kind"], kind);
        assert_eq!(detail["user"], second);
    }
}

#[tokio::test]
async fn user_pages_report_a_continuation_until_all_records_are_returned() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/users")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "user-1", "controllerSpecific": "first"},
            {"id": "user-2", "controllerSpecific": "second"}
        ])))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let first = handler
        .call(
            &call(
                "protect.users.list",
                &serde_json::json!({"kind": "user", "offset": 0, "limit": 1}),
            ),
            None,
        )
        .await
        .expect("first page")
        .structured_content
        .expect("structured");
    assert_eq!(first["users"][0]["controllerSpecific"], "first");
    assert_eq!(first["nextOffset"], 1);
    let second = handler
        .call(
            &call(
                "protect.users.list",
                &serde_json::json!({"kind": "user", "offset": 1, "limit": 1}),
            ),
            None,
        )
        .await
        .expect("second page")
        .structured_content
        .expect("structured");
    assert_eq!(second["users"][0]["controllerSpecific"], "second");
    assert!(second.get("nextOffset").is_none());
}

#[tokio::test]
async fn user_identity_error_keeps_the_complete_controller_response() {
    let server = MockServer::start().await;
    let response = serde_json::json!({
        "id": "another-user", "controllerSpecific": "user-identity-tail".repeat(100),
    });
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/users/user-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "protect.users.status",
                &serde_json::json!({"kind": "user", "userId": "user-1"}),
            ),
            None,
        )
        .await
        .expect_err("wrong user identity");
    assert!(error.message.contains(&response.to_string()));
}

#[tokio::test]
async fn an_empty_user_inventory_is_distinct_from_a_missing_api_route() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/users")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let empty = handler_for(&server)
        .call(
            &call("protect.users.list", &serde_json::json!({"kind": "user"})),
            None,
        )
        .await
        .expect("empty inventory")
        .structured_content
        .expect("structured");
    assert_eq!(empty["totalCount"], 0);
    assert_eq!(empty["users"], serde_json::json!([]));

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/users")))
        .respond_with(ResponseTemplate::new(404).set_body_string("user route absent"))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call("protect.users.list", &serde_json::json!({"kind": "user"})),
            None,
        )
        .await
        .expect_err("missing API route");
    assert!(error.message.contains("HTTP 404: user route absent"));
}

#[tokio::test]
async fn large_user_lists_and_details_preserve_complete_records_on_the_mcp_wire() {
    for (kind, route) in [("user", "users"), ("identityUser", "ulp-users")] {
        let server = MockServer::start().await;
        let record = serde_json::json!({"id":"user-large", "fixtureCredential":"x".repeat(60000),"unknown":{"tail":"original-controller-tail"}});
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([record.clone()])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{route}/user-large")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&record))
            .expect(1)
            .mount(&server)
            .await;
        let handler = handler_for(&server);
        for (tool, arguments, field, expected) in [
            (
                "protect.users.list",
                serde_json::json!({"kind":kind,"limit":1}),
                "users",
                serde_json::json!([record.clone()]),
            ),
            (
                "protect.users.status",
                serde_json::json!({"kind":kind,"userId":"user-large"}),
                "user",
                record.clone(),
            ),
        ] {
            let result = handler
                .call(&call(tool, &arguments), None)
                .await
                .expect("complete large result");
            let wire: serde_json::Value =
                serde_json::from_slice(&serde_json::to_vec(&result).expect("MCP serialize"))
                    .expect("MCP JSON");
            assert_eq!(wire["structuredContent"][field], expected);
            assert_ne!(wire["isError"], true);
            assert_eq!(
                wire["_meta"]["io.modelcontextprotocol/trust-annotations"]["sensitive"],
                true
            );
            let content = wire["content"][0]["text"].as_str().expect("result content");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(content).expect("complete content JSON")
                    [field],
                expected
            );
        }
        assert_eq!(server.received_requests().await.expect("requests").len(), 2);
    }
}
