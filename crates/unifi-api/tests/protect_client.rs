//! Wire-level tests for the Protect integration client against loopback fakes.
//!
//! The property worth the most here is the capability boundary. A console that
//! does not expose the integration API and a console that exposes it and has
//! no cameras must not produce the same answer, and neither may be confused
//! with a console that rejected the credential or could not be reached.

use std::time::Duration;

use unifi_api::{ApiError, ControllerConfig, ProtectAvailability, ProtectClient, TlsMode};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};
use zeroize::Zeroizing;

const API_KEY: &str = "test-protect-key";
const PREFIX: &str = "/proxy/protect/integration/v1";

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
        matches!(error, ApiError::SchemaMismatch { endpoint: "cameras", ref path }
        if path.as_str() == "modelKey")
    );
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
        matches!(error, ApiError::SchemaMismatch { endpoint: "cameras", ref path }
        if path.as_str().starts_with("[0]"))
    );
}

#[tokio::test]
async fn invalid_json_and_schema_mismatch_are_distinct_without_retaining_values() {
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
    assert!(!rendered.contains("987654321"), "{rendered}");
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
async fn a_controller_error_body_does_not_enter_the_safe_error() {
    const CONTROLLER_VALUE: &str = "synthetic-controller-device-id";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/cameras")))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "message": format!("bad key {API_KEY} for {CONTROLLER_VALUE}"),
        })))
        .mount(&server)
        .await;

    let error = client_for(&server).cameras().await.expect_err("rejected");
    let rendered = error.to_string();
    assert!(!rendered.contains(API_KEY), "{rendered}");
    assert!(!rendered.contains(CONTROLLER_VALUE), "{rendered}");
    assert!(
        rendered.contains("controller returned an unsuccessful status"),
        "{rendered}"
    );
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
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "600"))
        .expect(1)
        .mount(&server)
        .await;

    let error = client_for(&server).info().await.expect_err("rate limited");
    let ApiError::RateLimited { retry_after } = error else {
        panic!("expected RateLimited, got {error:?}");
    };
    assert_eq!(retry_after, Some(Duration::from_mins(10)));
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
