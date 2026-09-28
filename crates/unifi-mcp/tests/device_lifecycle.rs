use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path, query_param},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const DEVICE_ID: &str = "e3cb38ee-a6fd-40a7-80dc-53ab0d2b0801";
const MAC: &str = "aa:bb:cc:dd:ee:ff";

fn handler_for(server: &MockServer, timeout: Duration) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server URL");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("test-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout,
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: "test-user".to_owned(),
        password: Zeroizing::new("test-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout,
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
async fn pending_devices_page_preserves_fields_and_continuation() {
    let server = MockServer::start().await;
    for (offset, id) in [(0, "first"), (1, "second")] {
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/pending-devices")))
            .and(query_param("offset", offset.to_string()))
            .and(query_param("limit", "1"))
            .and(query_param("filter", "state.eq('PENDING')"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": offset, "limit": 1, "count": 1, "totalCount": 2,
                "data": [{"id": id, "macAddress": MAC, "controllerExtension": {"source": "upstream"}}]
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    let handler = handler_for(&server, Duration::from_secs(5));
    for (offset, id) in [(0, "first"), (1, "second")] {
        let result = handler
            .call(
                &call(
                    "devices.pending.list",
                    json!({"offset": offset, "limit": 1, "filter": "state.eq('PENDING')"}),
                ),
                None,
            )
            .await
            .expect("pending page")
            .structured_content
            .expect("structured");
        assert_eq!(result["devices"][0]["id"], id);
        assert_eq!(
            result["devices"][0]["controllerExtension"]["source"],
            "upstream"
        );
        if offset == 0 {
            assert_eq!(result["nextOffset"], 1);
        } else {
            assert!(result.get("nextOffset").is_none());
        }
    }
}

#[tokio::test]
async fn unavailable_pending_route_keeps_the_upstream_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/pending-devices")))
        .respond_with(ResponseTemplate::new(404).set_body_string("pending route unavailable"))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server, Duration::from_secs(5))
        .call(&call("devices.pending.list", json!({})), None)
        .await
        .expect_err("unsupported route");
    assert!(error.message.contains("pending route unavailable"));
}

#[tokio::test]
async fn adoption_previews_then_returns_complete_accepted_and_observed_records() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/devices")))
        .and(body_json(
            json!({"macAddress": MAC, "ignoreDeviceLimit": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": DEVICE_ID, "macAddress": MAC, "controllerExtension": "accepted-only"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": DEVICE_ID, "macAddress": MAC, "controllerExtension": "readback-only"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server, Duration::from_secs(5));
    let preview = handler
        .call(
            &call(
                "devices.adopt",
                json!({"macAddress": MAC, "ignoreDeviceLimit": true}),
            ),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["submitted"], false);
    let result = handler
        .call(
            &call(
                "devices.adopt",
                json!({"macAddress": MAC, "ignoreDeviceLimit": true, "confirm": true}),
            ),
            None,
        )
        .await
        .expect("adoption")
        .structured_content
        .expect("structured");
    assert_eq!(result["submitted"], true);
    assert_eq!(result["accepted"]["controllerExtension"], "accepted-only");
    assert_eq!(result["after"]["controllerExtension"], "readback-only");
    assert_eq!(result["verified"], true);
}

#[tokio::test]
async fn adoption_rejection_and_ambiguous_transport_are_returned_without_retry() {
    let rejected = MockServer::start().await;
    mount_site(&rejected).await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/devices")))
        .respond_with(
            ResponseTemplate::new(409).set_body_string("controller refused this MAC: exact body"),
        )
        .expect(1)
        .mount(&rejected)
        .await;
    let error = handler_for(&rejected, Duration::from_secs(5))
        .call(
            &call(
                "devices.adopt",
                json!({"macAddress": MAC, "ignoreDeviceLimit": false, "confirm": true}),
            ),
            None,
        )
        .await
        .expect_err("upstream rejection");
    assert!(
        error
            .message
            .contains("controller refused this MAC: exact body")
    );

    let slow = MockServer::start().await;
    mount_site(&slow).await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/devices")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(300))
                .set_body_json(json!({"id": DEVICE_ID})),
        )
        .expect(1)
        .mount(&slow)
        .await;
    let error = handler_for(&slow, Duration::from_millis(100))
        .call(
            &call(
                "devices.adopt",
                json!({"macAddress": MAC, "ignoreDeviceLimit": false, "confirm": true}),
            ),
            None,
        )
        .await
        .expect_err("ambiguous transport");
    assert!(error.message.contains("transport failure"));
}

#[tokio::test]
async fn large_adoption_response_and_failed_readback_keep_controller_values() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/sites/{SITE_ID}/devices")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": DEVICE_ID, "controllerExtension": format!("{}accepted-tail", "x".repeat(50_000))
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(ResponseTemplate::new(503).set_body_string("readback failed: exact body"))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server, Duration::from_secs(5))
        .call(
            &call(
                "devices.adopt",
                json!({"macAddress": MAC, "ignoreDeviceLimit": false, "confirm": true}),
            ),
            None,
        )
        .await
        .expect("accepted adoption");
    let structured = result.structured_content.expect("structured");
    assert_eq!(structured["acceptedInContent"], true);
    assert!(
        structured["readbackError"]
            .as_str()
            .expect("error")
            .contains("readback failed: exact body")
    );
    assert!(
        result
            .content
            .iter()
            .any(|item| format!("{item:?}").contains("accepted-tail"))
    );
}

#[tokio::test]
async fn removal_returns_upstream_body_and_observed_absence() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("controller accepted removal: exact body"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(
            ResponseTemplate::new(404).set_body_string("controller confirms device missing"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server, Duration::from_secs(5));
    let preview = handler
        .call(
            &call("devices.remove", json!({"deviceId": DEVICE_ID})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(preview["submitted"], false);
    assert!(
        preview["warning"]
            .as_str()
            .expect("warning")
            .contains("factory defaults")
    );
    let result = handler
        .call(
            &call(
                "devices.remove",
                json!({"deviceId": DEVICE_ID, "confirm": true}),
            ),
            None,
        )
        .await
        .expect("removal")
        .structured_content
        .expect("structured");
    assert_eq!(result["submitted"], true);
    assert_eq!(result["responseStatus"], 200);
    assert_eq!(
        result["responseBody"],
        "controller accepted removal: exact body"
    );
    assert_eq!(result["verifiedAbsent"], true);
    assert!(
        result["readbackError"]
            .as_str()
            .expect("upstream 404")
            .contains("controller confirms device missing")
    );
}

#[tokio::test]
async fn removal_keeps_accepted_response_when_readback_fails() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("accepted before readback failure"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream readback unavailable"))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server, Duration::from_secs(5))
        .call(
            &call(
                "devices.remove",
                json!({"deviceId": DEVICE_ID, "confirm": true}),
            ),
            None,
        )
        .await
        .expect("accepted removal")
        .structured_content
        .expect("structured");
    assert_eq!(result["responseBody"], "accepted before readback failure");
    assert!(result.get("verifiedAbsent").is_none());
    assert!(
        result["readbackError"]
            .as_str()
            .expect("error")
            .contains("upstream readback unavailable")
    );
}

#[tokio::test]
async fn removal_rejection_and_ambiguous_transport_are_returned_without_retry() {
    let rejected = MockServer::start().await;
    mount_site(&rejected).await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(
            ResponseTemplate::new(409).set_body_string("controller refused removal: exact body"),
        )
        .expect(1)
        .mount(&rejected)
        .await;
    let error = handler_for(&rejected, Duration::from_secs(5))
        .call(
            &call(
                "devices.remove",
                json!({"deviceId": DEVICE_ID, "confirm": true}),
            ),
            None,
        )
        .await
        .expect_err("upstream rejection");
    assert!(
        error
            .message
            .contains("controller refused removal: exact body")
    );

    let slow = MockServer::start().await;
    mount_site(&slow).await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{PREFIX}/sites/{SITE_ID}/devices/{DEVICE_ID}"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(300))
                .set_body_string("accepted after client timeout"),
        )
        .expect(1)
        .mount(&slow)
        .await;
    let error = handler_for(&slow, Duration::from_millis(100))
        .call(
            &call(
                "devices.remove",
                json!({"deviceId": DEVICE_ID, "confirm": true}),
            ),
            None,
        )
        .await
        .expect_err("ambiguous transport");
    assert!(error.message.contains("transport failure"));
}
