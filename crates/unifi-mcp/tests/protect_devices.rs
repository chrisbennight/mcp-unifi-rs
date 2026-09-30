//! Non-camera Protect device reads against bounded loopback responses.

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
async fn every_documented_device_family_pages_and_reads_full_details() {
    for (kind, route) in [
        ("light", "lights"),
        ("sensor", "sensors"),
        ("chime", "chimes"),
        ("siren", "sirens"),
        ("fob", "fobs"),
        ("relay", "relays"),
        ("speaker", "speakers"),
        ("bridge", "bridges"),
        ("linkStation", "link-stations"),
        ("alarmHub", "alarm-hubs"),
    ] {
        let server = MockServer::start().await;
        let first = serde_json::json!({"id": "device-1", "state": "CONNECTED"});
        let second = serde_json::json!({
            "id": "device-2", "modelKey": "controller-model",
            "name": "Entry", "state": "CONNECTED",
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
            .and(path(format!("{PREFIX}/{route}/device-2")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&second))
            .expect(1)
            .mount(&server)
            .await;
        let handler = handler_for(&server);

        let list = handler
            .call(
                &call(
                    "protect.devices.list",
                    &serde_json::json!({"kind": kind, "offset": 1, "limit": 1}),
                ),
                None,
            )
            .await
            .expect("device list");
        let list_result = list.structured_content.expect("structured list");
        assert_eq!(list_result["kind"], kind);
        assert_eq!(list_result["devices"], serde_json::json!([second.clone()]));
        assert_eq!(list_result["totalCount"], 2);
        assert!(list_result.get("nextOffset").is_none());
        assert_eq!(
            list.meta.expect("metadata").0["io.modelcontextprotocol/trust-annotations"]["sensitive"],
            true
        );

        let detail = handler
            .call(
                &call(
                    "protect.devices.status",
                    &serde_json::json!({"kind": kind, "deviceId": "device-2"}),
                ),
                None,
            )
            .await
            .expect("device detail")
            .structured_content
            .expect("structured detail");
        assert_eq!(detail["kind"], kind);
        assert_eq!(detail["device"], second);
    }
}

#[tokio::test]
async fn inventory_pages_report_a_continuation_until_all_records_are_returned() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sensors")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "device-1", "controllerSpecific": "first"},
            {"id": "device-2", "controllerSpecific": "second"}
        ])))
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let first = handler
        .call(
            &call(
                "protect.devices.list",
                &serde_json::json!({"kind": "sensor", "offset": 0, "limit": 1}),
            ),
            None,
        )
        .await
        .expect("first page")
        .structured_content
        .expect("structured");
    assert_eq!(first["devices"][0]["controllerSpecific"], "first");
    assert_eq!(first["nextOffset"], 1);
    let second = handler
        .call(
            &call(
                "protect.devices.list",
                &serde_json::json!({"kind": "sensor", "offset": 1, "limit": 1}),
            ),
            None,
        )
        .await
        .expect("second page")
        .structured_content
        .expect("structured");
    assert_eq!(second["devices"][0]["controllerSpecific"], "second");
    assert!(second.get("nextOffset").is_none());
}

#[tokio::test]
async fn device_identity_error_keeps_the_complete_controller_response() {
    let server = MockServer::start().await;
    let response = serde_json::json!({
        "id": "another-device", "controllerSpecific": "device-identity-tail".repeat(100),
    });
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sensors/device-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "protect.devices.status",
                &serde_json::json!({"kind": "sensor", "deviceId": "device-1"}),
            ),
            None,
        )
        .await
        .expect_err("wrong device identity");
    assert!(error.message.contains(&response.to_string()));
}

#[tokio::test]
async fn an_empty_inventory_is_distinct_from_a_missing_api_route() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sensors")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let empty = handler_for(&server)
        .call(
            &call(
                "protect.devices.list",
                &serde_json::json!({"kind": "sensor"}),
            ),
            None,
        )
        .await
        .expect("empty inventory")
        .structured_content
        .expect("structured");
    assert_eq!(empty["totalCount"], 0);
    assert_eq!(empty["devices"], serde_json::json!([]));

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sensors")))
        .respond_with(ResponseTemplate::new(404).set_body_string("sensor route absent"))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                "protect.devices.list",
                &serde_json::json!({"kind": "sensor"}),
            ),
            None,
        )
        .await
        .expect_err("missing API route");
    assert!(error.message.contains("HTTP 404: sensor route absent"));
}

#[tokio::test]
async fn large_device_lists_and_status_keep_all_controller_fields() {
    let server = MockServer::start().await;
    let record = serde_json::json!({"id":"device-large","unknown":{"fixtureCredential":"x".repeat(60000),"tail":"original-tail"}});
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/lights")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([record.clone()])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/lights/device-large")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&record))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    for (tool, arguments, field, expected) in [
        (
            "protect.devices.list",
            serde_json::json!({"kind":"light","limit":1}),
            "devices",
            serde_json::json!([record.clone()]),
        ),
        (
            "protect.devices.status",
            serde_json::json!({"kind":"light","deviceId":"device-large"}),
            "device",
            record.clone(),
        ),
    ] {
        let result = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect("large complete device result");
        assert_eq!(
            result.structured_content.expect("structured")[field],
            expected
        );
    }
    assert_eq!(server.received_requests().await.expect("requests").len(), 2);
}
