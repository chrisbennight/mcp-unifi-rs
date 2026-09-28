//! Documented Protect arm-profile and alarm routes against loopback responses.

use std::{sync::Arc, time::Duration};

use rmcp::model::{CallToolRequestParams, ContentBlock};
use serde_json::{Value, json};
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

fn call(name: &str, arguments: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(match arguments {
        Value::Object(map) => map,
        _ => panic!("object"),
    });
    params
}

#[tokio::test]
async fn arm_profile_list_pages_full_controller_records() {
    let server = MockServer::start().await;
    let rows = json!([
        {"id":"a","name":"Home","automations":["auto-1"],"extra":{"fromConsole":true}},
        {"id":"b","name":"Away","schedules":[{"start":"0 0 * * *","end":"0 6 * * *"}]}
    ]);
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/arm-profiles")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&rows))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call("protect.arm_profiles.list", json!({"offset":1,"limit":1})),
            None,
        )
        .await
        .expect("arm profiles")
        .structured_content
        .expect("structured result");
    assert_eq!(result["profiles"], json!([rows[1]]));
    assert_eq!(result["totalCount"], 2);
    assert!(result.get("nextOffset").is_none());
    server.verify().await;
}

#[tokio::test]
async fn a_single_large_arm_profile_remains_retrievable() {
    let server = MockServer::start().await;
    let detail = format!("{}profile-end-marker", "x".repeat(60_000));
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/arm-profiles")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{"id":"profile-1","controllerSpecific":detail}])),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(&call("protect.arm_profiles.list", json!({"limit":1})), None)
        .await
        .expect("complete large profile");
    let structured = result.structured_content.expect("structured result");
    assert_eq!(structured["profilesInContent"], true);
    assert_eq!(structured["totalCount"], 1);
    assert!(structured.get("nextOffset").is_none());
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&detail)
    )));
    server.verify().await;
}

#[tokio::test]
async fn arm_profile_operations_use_documented_routes_and_preserve_accepted_body() {
    let create = json!({"name":"Away","automations":[],"schedules":[],"recordEverything":true,"activationDelay":60000});
    let cases = [
        (
            json!({"operation":"create","changes":create}),
            "POST",
            "arm-profiles",
            Some(create),
            201,
            Some(
                json!([{"id":"profile-1","name":"Away","automations":[],"schedules":[],"recordEverything":true,"activationDelay":60000}]),
            ),
        ),
        (
            json!({"operation":"update","profileId":"profile-1","changes":{"name":"Home"}}),
            "PATCH",
            "arm-profiles/profile-1",
            Some(json!({"name":"Home"})),
            200,
            Some(json!([{"id":"profile-1","name":"Home"}])),
        ),
        (
            json!({"operation":"delete","profileId":"profile-1"}),
            "DELETE",
            "arm-profiles/profile-1",
            None,
            204,
            Some(json!([])),
        ),
        (
            json!({"operation":"select","profileId":"profile-1"}),
            "PATCH",
            "arm-profiles/settings",
            Some(json!({"armProfileId":"profile-1"})),
            204,
            None,
        ),
    ];
    for (mut input, verb, route, body, status, readback) in cases {
        let server = MockServer::start().await;
        let accepted = json!({"id":"profile-1","upstream":route}).to_string();
        Mock::given(method(verb))
            .and(path(format!("{PREFIX}/{route}")))
            .respond_with(ResponseTemplate::new(status).set_body_string(&accepted))
            .expect(1)
            .mount(&server)
            .await;
        if let Some(rows) = &readback {
            Mock::given(method("GET"))
                .and(path(format!("{PREFIX}/arm-profiles")))
                .respond_with(ResponseTemplate::new(200).set_body_json(rows))
                .expect(1)
                .mount(&server)
                .await;
        }
        input["confirm"] = json!(true);
        let result = handler_for(&server)
            .call(&call("protect.arm_profiles.configure", input), None)
            .await
            .expect("accepted arm-profile operation")
            .structured_content
            .expect("structured result");
        assert_eq!(result["submitted"], true);
        assert_eq!(result["acceptedStatus"], status);
        if status == 204 {
            assert!(result.get("responseBody").is_none());
        } else {
            assert_eq!(result["responseBody"], accepted);
        }
        if readback.is_some() {
            assert_eq!(result["verified"], true);
        } else {
            assert!(result.get("verified").is_none());
        }
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), if readback.is_some() { 2 } else { 1 });
        match body {
            Some(body) => assert_eq!(
                serde_json::from_slice::<Value>(&requests[0].body).expect("request JSON"),
                body
            ),
            None => assert!(requests[0].body.is_empty()),
        }
        server.verify().await;
    }
}

#[tokio::test]
async fn alarm_actions_use_documented_routes_and_no_request_body() {
    let cases = [
        (json!({"action":"enable"}), "arm-profiles/enable"),
        (json!({"action":"disable"}), "arm-profiles/disable"),
        (
            json!({"action":"webhook","triggerId":"doorbell"}),
            "alarm-manager/webhook/doorbell",
        ),
    ];
    for (mut input, route) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}/{route}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        input["confirm"] = json!(true);
        let result = handler_for(&server)
            .call(&call("protect.alarms.action", input), None)
            .await
            .expect("accepted alarm action")
            .structured_content
            .expect("structured result");
        assert_eq!(result["submitted"], true);
        assert_eq!(result["acceptedStatus"], 204);
        assert!(result.get("responseBody").is_none());
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].body.is_empty());
        server.verify().await;
    }
}

#[tokio::test]
async fn preview_and_invalid_arm_profile_send_no_write() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    let preview = handler
        .call(
            &call(
                "protect.arm_profiles.configure",
                json!({"operation":"select","profileId":"profile-1"}),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured preview");
    assert_eq!(preview["submitted"], false);
    assert_eq!(preview["requested"], json!({"armProfileId":"profile-1"}));
    let error = handler
        .call(
            &call(
                "protect.arm_profiles.configure",
                json!({"operation":"create","changes":{"name":"Away"},"confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("missing documented required fields");
    assert!(error.message.contains("requires name, automations"));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn alarm_rejection_keeps_the_full_controller_error() {
    let server = MockServer::start().await;
    let body = format!("{}upstream-alarm-tail", "x".repeat(900));
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/arm-profiles/enable")))
        .respond_with(ResponseTemplate::new(409).set_body_string(&body))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "protect.alarms.action",
                json!({"action":"enable","confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("controller rejection");
    assert!(error.message.contains(&body));
    server.verify().await;
}

#[tokio::test]
async fn arm_profile_write_keeps_large_accepted_body_and_readback_error() {
    let server = MockServer::start().await;
    let accepted = format!("{}accepted-profile-tail", "x".repeat(60_000));
    let rejected = format!("{}readback-error-tail", "y".repeat(900));
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/arm-profiles/profile-1")))
        .respond_with(ResponseTemplate::new(200).set_body_string(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/arm-profiles")))
        .respond_with(ResponseTemplate::new(409).set_body_string(&rejected))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call("protect.arm_profiles.configure", json!({"operation":"update","profileId":"profile-1","changes":{"name":"Home"},"confirm":true})),
            None,
        )
        .await
        .expect("accepted write with failed readback");
    let structured = result.structured_content.expect("structured result");
    assert_eq!(structured["submitted"], true);
    assert_eq!(structured["acceptedStatus"], 200);
    assert_eq!(structured["responseBodyInContent"], true);
    assert!(
        structured["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&rejected)
    );
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&accepted)
    )));
    server.verify().await;
}
