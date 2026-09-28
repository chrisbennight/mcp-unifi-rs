//! Wire-level tests for the Protect integration client against loopback fakes.
//!
//! The property worth the most here is the capability boundary. A console that
//! does not expose the integration API and a console that exposes it and has
//! no cameras must not produce the same answer, and neither may be confused
//! with a console that rejected the credential or could not be reached.

use std::time::Duration;

use image::{ExtendedColorType, codecs::jpeg::JpegEncoder};
use unifi_api::protect::ProtectStreamQuality;
use unifi_api::protect::{ProtectPatrolState, ProtectPtzCommand};
use unifi_api::{ApiError, ControllerConfig, ProtectAvailability, ProtectClient, TlsMode};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};
use zeroize::Zeroizing;

const API_KEY: &str = "test-protect-key";
const PREFIX: &str = "/proxy/protect/integration/v1";

fn jpeg_fixture() -> Vec<u8> {
    let mut bytes = Vec::new();
    JpegEncoder::new(&mut bytes)
        .encode(&[0, 128, 255], 1, 1, ExtendedColorType::Rgb8)
        .expect("encode synthetic JPEG");
    bytes
}

fn client_for(server: &MockServer) -> ProtectClient {
    let config = ControllerConfig {
        name: "cameras".to_owned(),
        base_url: Url::parse(&server.uri()).expect("mock server uri"),
        api_key: Zeroizing::new(API_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    };
    ProtectClient::new(&config).expect("client")
}

#[tokio::test]
async fn every_request_authenticates_with_the_api_key_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/meta/info")))
        .and(header("X-API-Key", API_KEY))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "7.1.87"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let info = client_for(&server).info().await.expect("info");
    assert_eq!(info.application_version, "7.1.87");
}

#[tokio::test]
async fn cameras_decode_the_complete_v7_1_87_official_shape() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/protect_v7_1_87_cameras.json"),
            "application/json",
        ))
        .mount(&server)
        .await;

    let cameras = client_for(&server).cameras().await.expect("cameras");
    assert_eq!(cameras.len(), 1);
    assert_eq!(cameras[0].id, "synthetic-camera-id-001");
    assert_eq!(cameras[0].model_key, "camera");
    assert_eq!(cameras[0].name, None);
    assert_eq!(cameras[0].is_mic_enabled, Some(true));
    assert_eq!(cameras[0].mic_volume, Some(50));
    assert_eq!(cameras[0].state, "CONNECTED");
}

#[tokio::test]
async fn cameras_tolerate_and_decode_allowlisted_version_extensions() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id": "cam-extension",
                "name": "Synthetic extension camera",
                "modelKey": "camera",
                "state": "CONNECTED",
                "type": "SYNTHETIC_PRODUCT_TYPE",
                "guid": "synthetic-guid",
                "somethingAddedNextRelease": 42
            }])),
        )
        .mount(&server)
        .await;

    let cameras = client_for(&server).cameras().await.expect("cameras");
    assert_eq!(
        cameras[0].device_type.as_deref(),
        Some("SYNTHETIC_PRODUCT_TYPE")
    );
    assert_eq!(cameras[0].guid.as_deref(), Some("synthetic-guid"));
}

#[tokio::test]
async fn a_camera_id_carrying_url_syntax_stays_one_path_segment() {
    let server = MockServer::start().await;
    // A console-supplied identifier is untrusted input. If it were pasted into
    // the path it could re-route the request somewhere else entirely.
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras/..%2Fnvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "../nvrs",
            "name": "Odd",
            "modelKey": "camera",
            "state": "CONNECTED",
        })))
        .mount(&server)
        .await;

    let camera = client_for(&server).camera("../nvrs").await.expect("camera");
    assert_eq!(camera.id, "../nvrs");
}

#[tokio::test]
async fn stream_lifecycle_and_talkback_use_the_documented_typed_routes() {
    let server = MockServer::start().await;
    let route = format!("{PREFIX}/cameras/cam-1/rtsps-stream");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp",
            "medium": null,
            "low": null,
            "package": null,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(&route))
        .and(header("X-API-Key", API_KEY))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "qualities": ["high", "medium"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "high": "rtsps://192.0.2.1:7441/synthetic-high?enableSrtp",
            "medium": "rtsps://192.0.2.1:7441/synthetic-medium?enableSrtp",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(&route))
        .and(query_param("qualities", "high"))
        .and(query_param("qualities", "medium"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{PREFIX}/cameras/cam-1/talkback-session")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": "rtp://192.0.2.1:7004", "codec": "opus",
            "samplingRate": 24000, "bitsPerSample": 16,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let existing = client.camera_streams("cam-1").await.expect("streams");
    assert!(existing.high.is_some());
    assert!(existing.medium.is_none());
    let created = client
        .camera_streams_create(
            "cam-1",
            &[ProtectStreamQuality::High, ProtectStreamQuality::Medium],
        )
        .await
        .expect("create streams");
    assert!(created.medium.is_some());
    client
        .camera_streams_delete(
            "cam-1",
            &[ProtectStreamQuality::High, ProtectStreamQuality::Medium],
        )
        .await
        .expect("delete streams");
    let session = client
        .camera_talkback_session("cam-1")
        .await
        .expect("talkback session");
    assert_eq!(session.codec, "opus");
    assert_eq!(session.sampling_rate, 24000);
    assert!(client.camera_streams_create("cam-1", &[]).await.is_err());
    assert!(
        client
            .camera_streams_delete(
                "cam-1",
                &[ProtectStreamQuality::High, ProtectStreamQuality::High]
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn ptz_posts_typed_actions_once_and_decodes_patrol_state() {
    let server = MockServer::start().await;
    for suffix in ["goto/-1", "patrol/start/4", "patrol/stop"] {
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}/cameras/cam-1/ptz/{suffix}")))
            .and(header("X-API-Key", API_KEY))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
    }
    let client = client_for(&server);
    client
        .camera_ptz("cam-1", ProtectPtzCommand::GotoPreset(-1))
        .await
        .expect("home preset");
    client
        .camera_ptz("cam-1", ProtectPtzCommand::StartPatrol(4))
        .await
        .expect("patrol");
    client
        .camera_ptz("cam-1", ProtectPtzCommand::StopPatrol)
        .await
        .expect("stop");
    assert!(
        client
            .camera_ptz("cam-1", ProtectPtzCommand::StartPatrol(5))
            .await
            .is_err()
    );

    for (reported, state) in [
        (serde_json::json!({}), ProtectPatrolState::Unreported),
        (
            serde_json::json!({"activePatrolSlot": null}),
            ProtectPatrolState::Stopped,
        ),
        (
            serde_json::json!({"activePatrolSlot": 4}),
            ProtectPatrolState::Running(4),
        ),
    ] {
        let mut camera = serde_json::json!({
            "id": "cam-1", "modelKey": "camera", "name": "PTZ", "state": "CONNECTED",
        });
        camera
            .as_object_mut()
            .expect("camera object")
            .extend(reported.as_object().expect("state object").clone());
        let decoded: unifi_api::protect::ProtectCamera =
            serde_json::from_value(camera).expect("camera shape");
        assert_eq!(decoded.active_patrol_slot, state);
    }
}

#[tokio::test]
async fn camera_settings_patch_sends_only_typed_fields_and_decodes_camera() {
    use unifi_api::protect::{ProtectCameraSettingsPatch, ProtectOsdSettings};

    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(format!("{PREFIX}/cameras/cam-1")))
        .and(header("X-API-Key", API_KEY))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "videoMode": "highFps",
            "osdSettings": {"isDateEnabled": false}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "cam-1", "modelKey": "camera", "name": "Front", "state": "CONNECTED",
            "videoMode": "highFps", "osdSettings": {"isDateEnabled": false}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let response = client_for(&server)
        .camera_settings_patch(
            "cam-1",
            &ProtectCameraSettingsPatch {
                video_mode: Some("highFps".to_owned()),
                osd_settings: Some(ProtectOsdSettings {
                    is_date_enabled: Some(false),
                    ..ProtectOsdSettings::default()
                }),
                ..ProtectCameraSettingsPatch::default()
            },
        )
        .await
        .expect("patch");
    assert_eq!(response.video_mode.as_deref(), Some("highFps"));
    assert_eq!(
        response
            .osd_settings
            .and_then(|settings| settings.is_date_enabled),
        Some(false)
    );
}

#[tokio::test]
async fn snapshot_fetches_a_bounded_jpeg_with_channel_and_quality() {
    let server = MockServer::start().await;
    let jpeg = jpeg_fixture();
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras/cam-1/snapshot")))
        .and(query_param("channel", "package"))
        .and(query_param("highQuality", "true"))
        .and(header("X-API-Key", API_KEY))
        .and(header("Accept", "image/jpeg"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(jpeg.clone(), "image/jpeg"))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client_for(&server)
            .camera_snapshot("cam-1", "package", true)
            .await
            .expect("snapshot"),
        jpeg
    );
}

#[tokio::test]
async fn snapshot_refuses_non_jpeg_and_oversized_bodies() {
    let wrong_type = MockServer::start().await;
    Mock::given(path(format!("{PREFIX}/cameras/cam-1/snapshot")))
        .respond_with(ResponseTemplate::new(200).set_body_raw("secret text", "text/plain"))
        .mount(&wrong_type)
        .await;
    assert!(matches!(
        client_for(&wrong_type)
            .camera_snapshot("cam-1", "main", false)
            .await,
        Err(ApiError::Decode(_))
    ));

    let oversized = MockServer::start().await;
    Mock::given(path(format!("{PREFIX}/cameras/cam-1/snapshot")))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(vec![0xff; 4 * 1024 * 1024 + 1], "image/jpeg"),
        )
        .mount(&oversized)
        .await;
    assert!(matches!(
        client_for(&oversized)
            .camera_snapshot("cam-1", "main", false)
            .await,
        Err(ApiError::ResponseTooLarge { limit: 4_194_304 })
    ));
}

#[tokio::test]
async fn snapshot_refuses_truncated_jpeg_even_with_correct_content_type() {
    let server = MockServer::start().await;
    let mut truncated = jpeg_fixture();
    truncated.truncate(truncated.len() / 2);
    Mock::given(path(format!("{PREFIX}/cameras/cam-1/snapshot")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(truncated, "image/jpeg"))
        .mount(&server)
        .await;
    assert!(matches!(
        client_for(&server)
            .camera_snapshot("cam-1", "main", false)
            .await,
        Err(ApiError::Decode(_))
    ));
}

#[tokio::test]
async fn nvr_decodes_as_the_official_single_nullable_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/nvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/protect_v7_1_87_nvr.json"),
            "application/json",
        ))
        .mount(&server)
        .await;

    let nvr = client_for(&server).nvr().await.expect("nvr");
    assert_eq!(nvr.id, "synthetic-nvr-id-001");
    assert_eq!(nvr.name, None);
}

#[tokio::test]
async fn wrong_resource_discriminators_are_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id": "wrong-kind", "modelKey": "nvr", "name": "Wrong", "state": "CONNECTED"
            }])),
        )
        .mount(&server)
        .await;

    let error = client_for(&server).cameras().await.expect_err("wrong kind");
    assert!(
        matches!(error, ApiError::SchemaMismatch { endpoint: "cameras", ref path, .. }
        if path.as_str() == "modelKey")
    );
    assert!(error.to_string().contains("wrong-kind"), "{error}");
}

#[tokio::test]
async fn documented_nullable_names_must_still_be_present() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id": "cam-1", "modelKey": "camera", "state": "CONNECTED"
            }])),
        )
        .mount(&server)
        .await;

    let error = client_for(&server)
        .cameras()
        .await
        .expect_err("missing required nullable name");
    assert!(
        matches!(error, ApiError::SchemaMismatch { endpoint: "cameras", ref path, .. }
        if path.as_str().starts_with("[0]"))
    );
}

#[tokio::test]
async fn invalid_json_and_schema_mismatch_retain_bounded_controller_responses() {
    let invalid_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(ResponseTemplate::new(200).set_body_raw("[{", "application/json"))
        .mount(&invalid_server)
        .await;
    let invalid = client_for(&invalid_server)
        .cameras()
        .await
        .expect_err("invalid JSON");
    assert!(matches!(
        invalid,
        ApiError::InvalidJson {
            endpoint: "cameras",
            ..
        }
    ));
    assert!(invalid.to_string().contains("[{"), "{invalid}");

    let schema_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id": "cam-sensitive", "modelKey": "camera",
                "name": 987_654_321, "state": "CONNECTED"
            }])),
        )
        .mount(&schema_server)
        .await;
    let schema = client_for(&schema_server)
        .cameras()
        .await
        .expect_err("schema mismatch");
    let rendered = schema.to_string();
    assert!(matches!(
        schema,
        ApiError::SchemaMismatch {
            endpoint: "cameras",
            ..
        }
    ));
    assert!(rendered.contains("987654321"), "{rendered}");
}

#[tokio::test]
async fn an_oversized_response_has_its_own_error_category() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![b' '; 4 * 1024 * 1024 + 1], "application/json"),
        )
        .mount(&server)
        .await;

    assert!(matches!(
        client_for(&server).cameras().await.expect_err("oversized"),
        ApiError::ResponseTooLarge { limit: 4_194_304 }
    ));
}

#[tokio::test]
async fn a_console_without_the_integration_api_is_reported_as_unsupported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/meta/info")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    assert_eq!(
        client_for(&server).availability().await.expect("probe"),
        ProtectAvailability::Unsupported
    );
}

#[tokio::test]
async fn a_console_that_answers_reports_its_application_version() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/meta/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "6.2.83"})),
        )
        .mount(&server)
        .await;

    assert_eq!(
        client_for(&server).availability().await.expect("probe"),
        ProtectAvailability::Available {
            application_version: "6.2.83".to_owned()
        }
    );
}

#[tokio::test]
async fn a_rejected_credential_is_never_reported_as_an_absent_api() {
    // This is the boundary the whole probe exists for. Treating any failure as
    // "no integration API here" would turn a wrong key, or an unreachable
    // console, into the confident claim that a monitored house has no cameras.
    for status in [401, 403, 500, 502] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/meta/info")))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;

        let error = client_for(&server)
            .availability()
            .await
            .expect_err("must propagate");
        assert!(
            matches!(error, ApiError::Status { status: reported, .. } if reported == status),
            "{status}: {error}"
        );
    }
}

#[tokio::test]
async fn a_controller_error_body_reaches_the_caller() {
    const CONTROLLER_VALUE: &str = "synthetic-controller-device-id";
    const END_MARKER: &str = "protect-error-tail";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "message": format!("bad key {API_KEY} for {CONTROLLER_VALUE} {}{END_MARKER}", "x".repeat(700)),
        })))
        .mount(&server)
        .await;

    let error = client_for(&server).cameras().await.expect_err("rejected");
    let rendered = error.to_string();
    assert!(rendered.contains(API_KEY), "{rendered}");
    assert!(rendered.contains(CONTROLLER_VALUE), "{rendered}");
    assert!(rendered.contains(END_MARKER), "{rendered}");
}

#[tokio::test]
async fn rate_limited_reads_retry_once_after_the_named_delay() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/meta/info")))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/meta/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "7.1.87"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let info = client_for(&server).info().await.expect("retried read");
    assert_eq!(info.application_version, "7.1.87");
}

#[tokio::test]
async fn rate_limited_reads_without_an_acceptable_delay_surface_the_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/meta/info")))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "600")
                .set_body_raw(
                    format!("{}protect-rate-tail", "x".repeat(700)),
                    "text/plain",
                ),
        )
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("rate limited");
    let ApiError::RateLimited {
        retry_after,
        message,
    } = error
    else {
        panic!("expected RateLimited, got {error:?}");
    };
    assert_eq!(retry_after, Some(Duration::from_mins(10)));
    assert!(message.as_str().ends_with("protect-rate-tail"));
}

#[tokio::test]
async fn a_rate_limited_capability_probe_is_never_reported_as_an_absent_api() {
    // A console that is merely busy must not be mistaken for one without the
    // integration API -- the same line the 401/403/500/502 walk holds.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/meta/info")))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "600"))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .availability()
        .await
        .expect_err("rate limited");
    assert!(matches!(error, ApiError::RateLimited { .. }));
}
