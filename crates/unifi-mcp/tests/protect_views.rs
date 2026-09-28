//! Protect viewer and live-view reads against bounded loopback responses.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, ProtectClient, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
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

#[tokio::test]
async fn viewer_settings_preview_preserves_an_explicit_null_without_patching() {
    let server = MockServer::start().await;
    let before = serde_json::json!({"id":"viewer-1","liveview":"liveview-1","extra":{"kept":true}});
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&before))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.viewers.settings.update",
                &serde_json::json!({
                    "viewerId":"viewer-1", "changes":{"liveview":null}
                }),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured preview");
    assert_eq!(result["applied"], false);
    assert_eq!(result["requested"], serde_json::json!({"liveview":null}));
    assert_eq!(result["before"], before);
    server.verify().await;
}

#[tokio::test]
async fn viewer_settings_patch_returns_complete_response_and_readback() {
    let server = MockServer::start().await;
    let before = serde_json::json!({"id":"viewer-1","name":"Old","liveview":"liveview-1"});
    let response = serde_json::json!({"id":"viewer-1","name":"New","liveview":null,"upstreamOnly":{"a":[1,2,3]}});
    let after =
        serde_json::json!({"id":"viewer-1","name":"New","liveview":null,"persistedOnly":"yes"});
    let reads = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::clone(&reads);
    let first = before.clone();
    let second = after.clone();
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(move |_: &wiremock::Request| {
            if read_count.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(&first)
            } else {
                ResponseTemplate::new(200).set_body_json(&second)
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .and(body_json(serde_json::json!({"name":"New","liveview":null})))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.viewers.settings.update",
                &serde_json::json!({
                    "viewerId":"viewer-1", "changes":{"name":"New","liveview":null}, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("patch");
    assert_eq!(
        result.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
        true
    );
    let body = result.structured_content.expect("structured patch result");
    assert_eq!(body["applied"], true);
    assert_eq!(body["verified"], true);
    assert_eq!(body["before"], before);
    assert_eq!(body["response"], response);
    assert_eq!(body["after"], after);
    server.verify().await;
}

#[tokio::test]
async fn wrong_viewer_patch_identity_keeps_the_accepted_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"viewer-1"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let response = serde_json::json!({"id":"different","controllerSpecific":"upstream-patch-tail".repeat(100)});
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "protect.viewers.settings.update",
                &serde_json::json!({
                    "viewerId":"viewer-1", "changes":{"name":"New"}, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect_err("wrong patch identity");
    assert!(error.message.contains(&response.to_string()));
    server.verify().await;
}

#[tokio::test]
async fn large_accepted_viewer_patch_response_remains_available() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"id":"viewer-1","name":"New","futureField":"controller-tail".repeat(5000)});
    let reads = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::clone(&reads);
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(move |_: &wiremock::Request| {
            let name = if read_count.fetch_add(1, Ordering::SeqCst) == 0 {
                "Old"
            } else {
                "New"
            };
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id":"viewer-1","name":name}))
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.viewers.settings.update",
                &serde_json::json!({
                    "viewerId":"viewer-1", "changes":{"name":"New"}, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("patch with large response");
    let body = result.structured_content.expect("structured result");
    assert_eq!(body["applied"], true);
    assert_eq!(body["verified"], true);
    assert_eq!(body["responseInContent"], true);
    assert!(result.content.iter().any(|item| matches!(item,
        rmcp::model::ContentBlock::Text(text) if text.text.contains(&response.to_string())
    )));
    server.verify().await;
}

#[tokio::test]
async fn viewer_patch_readback_error_keeps_the_controller_failure() {
    let server = MockServer::start().await;
    let reads = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::clone(&reads);
    let failure = format!("{}upstream-readback-tail", "x".repeat(900));
    let failure_for_mock = failure.clone();
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(move |_: &wiremock::Request| {
            if read_count.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":"viewer-1","name":"Old"}))
            } else {
                ResponseTemplate::new(503).set_body_string(failure_for_mock.clone())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let response = serde_json::json!({"id":"viewer-1","name":"New","upstreamOnly":"kept"});
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/viewers/viewer-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.viewers.settings.update",
                &serde_json::json!({
                    "viewerId":"viewer-1", "changes":{"name":"New"}, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("accepted patch remains available");
    let body = result.structured_content.expect("structured result");
    assert_eq!(body["applied"], true);
    assert_eq!(body["response"], response);
    assert!(body["verified"].is_null());
    assert!(
        body["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&failure)
    );
    server.verify().await;
}

#[tokio::test]
async fn liveview_create_previews_a_typed_layout_without_an_upstream_call() {
    let server = MockServer::start().await;
    let changes = serde_json::json!({
        "name":"Lobby", "layout":1,
        "slots":[{"cameras":["camera-1"],"cycleMode":"time","cycleInterval":10}]
    });
    let result = handler_for(&server)
        .call(
            &call(
                "protect.liveviews.configure",
                &serde_json::json!({
                    "operation":"create", "changes":changes
                }),
            ),
            None,
        )
        .await
        .expect("create preview")
        .structured_content
        .expect("structured preview");
    assert_eq!(result["operation"], "create");
    assert_eq!(result["applied"], false);
    assert_eq!(result["requested"], changes);
    server.verify().await;
}

#[tokio::test]
async fn liveview_create_returns_the_complete_response_and_verifies_readback() {
    let server = MockServer::start().await;
    let changes = serde_json::json!({
        "name":"Lobby", "isGlobal":true, "layout":1,
        "slots":[{"cameras":["camera-1"],"cycleMode":"time","cycleInterval":10}]
    });
    let response = serde_json::json!({
        "id":"view-1", "name":"Lobby", "isGlobal":true, "layout":1.0,
        "slots":[{"cameras":["camera-1"],"cycleMode":"time","cycleInterval":10.0,"futureSlotField":"kept"}],
        "futureField":{"kept":[1,2]}
    });
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/liveviews")))
        .and(body_json(&changes))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/liveviews/view-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.liveviews.configure",
                &serde_json::json!({
                    "operation":"create", "changes":changes, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("created live view");
    assert_eq!(
        result.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
        true
    );
    let body = result.structured_content.expect("structured create result");
    assert_eq!(body["applied"], true);
    assert_eq!(body["liveviewId"], "view-1");
    assert_eq!(body["verified"], true);
    assert_eq!(body["response"], response);
    assert_eq!(body["after"], response);
    server.verify().await;
}

#[tokio::test]
async fn liveview_update_patches_only_named_fields_and_reads_back() {
    let server = MockServer::start().await;
    let before = serde_json::json!({"id":"view-1","name":"Old","layout":4,"isGlobal":false});
    let response = serde_json::json!({"id":"view-1","name":"New","layout":4,"isGlobal":true,"futureField":"kept"});
    let after = response.clone();
    let reads = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::clone(&reads);
    let first = before.clone();
    let second = after.clone();
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/liveviews/view-1")))
        .respond_with(move |_: &wiremock::Request| {
            if read_count.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(&first)
            } else {
                ResponseTemplate::new(200).set_body_json(&second)
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let changes = serde_json::json!({"name":"New","isGlobal":true});
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/liveviews/view-1")))
        .and(body_json(&changes))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.liveviews.configure",
                &serde_json::json!({
                    "operation":"update", "liveviewId":"view-1", "changes":changes, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("updated live view")
        .structured_content
        .expect("structured update result");
    assert_eq!(result["applied"], true);
    assert_eq!(result["verified"], true);
    assert_eq!(result["before"], before);
    assert_eq!(result["response"], response);
    assert_eq!(result["after"], after);
    server.verify().await;
}

#[tokio::test]
async fn rejected_liveview_create_keeps_the_complete_controller_error() {
    let server = MockServer::start().await;
    let error_body = format!("{}upstream-liveview-tail", "x".repeat(900));
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/liveviews")))
        .respond_with(ResponseTemplate::new(409).set_body_string(&error_body))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "protect.liveviews.configure",
                &serde_json::json!({
                    "operation":"create", "changes":{"name":"Lobby"}, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect_err("controller conflict");
    assert!(error.message.contains(&error_body));
    server.verify().await;
}

#[tokio::test]
async fn accepted_liveview_create_without_an_id_keeps_its_result() {
    let server = MockServer::start().await;
    let response = serde_json::json!({"created":true,"controllerSpecific":"unrepeatable-result"});
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/liveviews")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.liveviews.configure",
                &serde_json::json!({
                    "operation":"create", "changes":{"name":"Lobby"}, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("accepted create response")
        .structured_content
        .expect("structured create result");
    assert_eq!(result["applied"], true);
    assert_eq!(result["response"], response);
    assert!(result.get("liveviewId").is_none());
    assert!(
        result["readbackError"]
            .as_str()
            .expect("readback diagnostic")
            .contains("no live-view id")
    );
    server.verify().await;
}

#[tokio::test]
async fn large_liveview_create_response_remains_available_in_content() {
    let server = MockServer::start().await;
    let response = serde_json::json!({
        "id":"view-1","name":"Lobby","futureField":"liveview-tail".repeat(5000)
    });
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/liveviews")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/liveviews/view-1")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id":"view-1","name":"Lobby"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                "protect.liveviews.configure",
                &serde_json::json!({
                    "operation":"create", "changes":{"name":"Lobby"}, "confirm":true
                }),
            ),
            None,
        )
        .await
        .expect("large accepted response");
    let body = result.structured_content.expect("structured create result");
    assert_eq!(body["applied"], true);
    assert_eq!(body["verified"], true);
    assert_eq!(body["responseInContent"], true);
    assert!(result.content.iter().any(|item| matches!(item,
        rmcp::model::ContentBlock::Text(text) if text.text.contains(&response.to_string())
    )));
    server.verify().await;
}
