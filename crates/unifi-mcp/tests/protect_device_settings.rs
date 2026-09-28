//! Typed non-camera Protect settings against fixed loopback routes.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rmcp::model::{CallToolRequestParams, ContentBlock};
use serde_json::{Value, json};
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

fn call(arguments: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "protect.devices.settings.update".into();
    params.arguments = Some(match arguments {
        Value::Object(map) => map,
        _ => panic!("object"),
    });
    params
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn documented_device_settings_use_fixed_routes_typed_bodies_and_readback() {
    let cases = [
        (
            "light",
            "lights",
            json!({"kind":"light","name":"Front","isLightForceEnabled":true,"lightModeSettings":{"mode":"motion","enableAt":"dark"},"lightDeviceSettings":{"isIndicatorEnabled":false,"pirDuration":30000,"pirSensitivity":50,"ledLevel":4}}),
            json!({"name":"Front","isLightForceEnabled":true,"lightModeSettings":{"mode":"motion","enableAt":"dark"},"lightDeviceSettings":{"isIndicatorEnabled":false,"pirDuration":30000.0,"pirSensitivity":50.0,"ledLevel":4.0}}),
        ),
        (
            "sensor",
            "sensors",
            json!({"kind":"sensor","name":"Window","lightSettings":{"isEnabled":true,"lowThreshold":null,"highThreshold":100},"humiditySettings":{"lowThreshold":30},"temperatureSettings":{"lowThreshold":-10},"motionSettings":{"sensitivity":50},"glassBreakSettings":{"sensitivityWhenArmed":80},"scheduleMode":"when_armed","armProfileIds":null,"hasCustomSensitivityWhenArmed":true,"alarmSettings":{"isEnabled":true}}),
            json!({"name":"Window","lightSettings":{"isEnabled":true,"lowThreshold":null,"highThreshold":100.0},"humiditySettings":{"lowThreshold":30.0},"temperatureSettings":{"lowThreshold":-10.0},"motionSettings":{"sensitivity":50.0},"glassBreakSettings":{"sensitivityWhenArmed":80.0},"scheduleMode":"when_armed","armProfileIds":null,"hasCustomSensitivityWhenArmed":true,"alarmSettings":{"isEnabled":true}}),
        ),
        (
            "chime",
            "chimes",
            json!({"kind":"chime","name":"Hall Chime","cameraIds":["camera-1"],"ringSettings":[{"cameraId":"camera-1","repeatTimes":3,"ringtoneId":"tone-1","volume":80}]}),
            json!({"name":"Hall Chime","cameraIds":["camera-1"],"ringSettings":[{"cameraId":"camera-1","repeatTimes":3.0,"ringtoneId":"tone-1","volume":80.0}]}),
        ),
        (
            "siren",
            "sirens",
            json!({"kind":"siren","name":"Hall","volume":80,"ledSettings":{"isEnabled":true}}),
            json!({"name":"Hall","volume":80,"ledSettings":{"isEnabled":true}}),
        ),
        (
            "relay",
            "relays",
            json!({"kind":"relay","name":"Gate","ledSettings":{"isEnabled":false}}),
            json!({"name":"Gate","ledSettings":{"isEnabled":false}}),
        ),
        (
            "speaker",
            "speakers",
            json!({"kind":"speaker","name":"Porch","volume":0,"micVolume":100,"isMicEnabled":true}),
            json!({"name":"Porch","volume":0,"micVolume":100,"isMicEnabled":true}),
        ),
        (
            "fob",
            "fobs",
            json!({"kind":"fob","name":"Keys"}),
            json!({"name":"Keys"}),
        ),
        (
            "bridge",
            "bridges",
            json!({"kind":"bridge","name":"Bridge"}),
            json!({"name":"Bridge"}),
        ),
        (
            "linkStation",
            "link-stations",
            json!({"kind":"linkStation","name":"Link"}),
            json!({"name":"Link"}),
        ),
        (
            "alarmHub",
            "alarm-hubs",
            json!({"kind":"alarmHub","name":"Hub"}),
            json!({"name":"Hub"}),
        ),
    ];
    for (kind, family, changes, request) in cases {
        let server = MockServer::start().await;
        let before = json!({"id":"device-1","name":"Old"});
        let mut after = request.clone();
        after["id"] = json!("device-1");
        after["controllerSpecific"] = json!("persisted");
        let reads = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reads);
        let initial = before.clone();
        let persisted = after.clone();
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/{family}/device-1")))
            .respond_with(move |_: &wiremock::Request| {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(200).set_body_json(&initial)
                } else {
                    ResponseTemplate::new(200).set_body_json(&persisted)
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let accepted = json!({"id":"device-1","controllerSpecific":"accepted"});
        Mock::given(method("PATCH"))
            .and(path(format!("{PREFIX}/{family}/device-1")))
            .and(body_json(&request))
            .respond_with(ResponseTemplate::new(200).set_body_json(&accepted))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler_for(&server)
            .call(
                &call(json!({"deviceId":"device-1","changes":changes,"confirm":true})),
                None,
            )
            .await
            .expect("accepted settings")
            .structured_content
            .expect("structured result");
        assert_eq!(result["kind"], kind);
        assert_eq!(result["requested"], request);
        assert_eq!(result["before"], before);
        assert_eq!(result["after"], after);
        assert_eq!(result["submitted"], true);
        assert_eq!(result["acceptedStatus"], 200);
        assert_eq!(result["responseBody"], accepted.to_string());
        assert_eq!(result["verified"], true);
        server.verify().await;
    }
}

#[tokio::test]
async fn preview_and_invalid_settings_send_no_patch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/bridges/device-1")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id":"device-1","name":"Old"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let preview = handler
        .call(
            &call(json!({"deviceId":"device-1","changes":{"kind":"bridge","name":"New"}})),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured result");
    assert_eq!(preview["submitted"], false);
    assert_eq!(preview["requested"], json!({"name":"New"}));
    let invalid = handler
        .call(
            &call(
                json!({"deviceId":"device-1","changes":{"kind":"siren","volume":0},"confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("invalid volume");
    assert!(invalid.message.contains("1-100"));
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    server.verify().await;
}

#[tokio::test]
async fn rejected_settings_keep_complete_controller_error() {
    let server = MockServer::start().await;
    let body = format!("{}settings-error-tail", "x".repeat(900));
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/fobs/device-1")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id":"device-1","name":"Old"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/fobs/device-1")))
        .respond_with(ResponseTemplate::new(409).set_body_string(&body))
        .expect(1)
        .mount(&server)
        .await;
    let error = handler_for(&server)
        .call(
            &call(
                json!({"deviceId":"device-1","changes":{"kind":"fob","name":"New"},"confirm":true}),
            ),
            None,
        )
        .await
        .expect_err("controller rejection");
    assert!(error.message.contains(&body));
    server.verify().await;
}

#[tokio::test]
async fn a_large_single_device_preview_keeps_the_complete_record() {
    let server = MockServer::start().await;
    let detail = format!("{}device-end-marker", "x".repeat(60_000));
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/bridges/device-1")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":"device-1","name":"Old","controllerSpecific":detail})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(json!({"deviceId":"device-1","changes":{"kind":"bridge","name":"New"}})),
            None,
        )
        .await
        .expect("large preview");
    let structured = result.structured_content.expect("structured result");
    assert_eq!(structured["beforeInContent"], true);
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&detail)
    )));
    server.verify().await;
}

#[tokio::test]
async fn accepted_patch_keeps_large_body_and_complete_readback_error() {
    let server = MockServer::start().await;
    let accepted = format!("{}accepted-settings-tail", "x".repeat(60_000));
    let failed_read = format!("{}device-readback-tail", "y".repeat(900));
    let failed_for_mock = failed_read.clone();
    let reads = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&reads);
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/fobs/device-1")))
        .respond_with(move |_: &wiremock::Request| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({"id":"device-1","name":"Old"}))
            } else {
                ResponseTemplate::new(503).set_body_string(failed_for_mock.clone())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/fobs/device-1")))
        .respond_with(ResponseTemplate::new(200).set_body_string(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &call(
                json!({"deviceId":"device-1","changes":{"kind":"fob","name":"New"},"confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted patch remains available");
    let structured = result.structured_content.expect("structured result");
    assert_eq!(structured["submitted"], true);
    assert_eq!(structured["acceptedStatus"], 200);
    assert_eq!(structured["responseBodyInContent"], true);
    assert!(
        structured["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&failed_read)
    );
    assert!(result.content.iter().any(|item| matches!(item,
        ContentBlock::Text(text) if text.text.contains(&accepted)
    )));
    server.verify().await;
}

#[tokio::test]
async fn sensor_nullable_fields_distinguish_clear_from_omission() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/sensors/device-1")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id":"device-1","name":"Old"})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let handler = handler_for(&server);
    let omitted = handler
        .call(
            &call(json!({"deviceId":"device-1","changes":{"kind":"sensor","name":"New"}})),
            None,
        )
        .await
        .expect("omitted fields preview")
        .structured_content
        .expect("structured result");
    assert_eq!(omitted["requested"], json!({"name":"New"}));
    let cleared = handler
        .call(&call(json!({"deviceId":"device-1","changes":{"kind":"sensor","armProfileIds":null,"lightSettings":{"lowThreshold":null}}})), None)
        .await
        .expect("explicit clear preview")
        .structured_content
        .expect("structured result");
    assert_eq!(
        cleared["requested"],
        json!({"armProfileIds":null,"lightSettings":{"lowThreshold":null}})
    );
    server.verify().await;
}

#[tokio::test]
async fn invalid_sensor_and_chime_ranges_send_no_request() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for changes in [
        json!({"kind":"sensor","humiditySettings":{"lowThreshold":100}}),
        json!({"kind":"sensor","motionSettings":{"sensitivityWhenArmed":101}}),
        json!({"kind":"sensor","armProfileIds":vec!["x"; 33]}),
        json!({"kind":"chime","ringSettings":[{"cameraId":"camera-1","repeatTimes":0,"ringtoneId":"tone-1","volume":50}]}),
    ] {
        handler
            .call(
                &call(json!({"deviceId":"device-1","changes":changes,"confirm":true})),
                None,
            )
            .await
            .expect_err("documented range");
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}
