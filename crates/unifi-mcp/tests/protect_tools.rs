//! Tool-level tests for the Protect camera surface against loopback fakes.
//!
//! The property worth the most here is the same one the client protects at the
//! wire level, one layer up: a console that cannot answer must never look like
//! a console with nothing to report. A Protect process either has a console
//! that lacks the integration API or a console that genuinely has no cameras;
//! only the latter is an empty list. A Network process does not advertise or
//! dispatch Protect tools at all.

#![recursion_limit = "256"]

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{
    ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, ProtectClient, TlsMode,
};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};
use zeroize::Zeroizing;

const API_KEY: &str = "test-integration-key";
const PROTECT_KEY: &str = "test-protect-key";
const USERNAME: &str = "svc-mcp";
const PASSWORD: &str = "test-legacy-password";
const PROTECT: &str = "/proxy/protect/integration/v1";

/// A handler with no Protect console, which is a supported deployment.
fn handler_without_protect(server: &MockServer) -> UnifiMcp {
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
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "home",
        "default",
        vec![
            Zeroizing::new(API_KEY.to_owned()),
            Zeroizing::new(PASSWORD.to_owned()),
        ],
    )
}

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let protect = ProtectClient::new(&ControllerConfig {
        name: "cameras".to_owned(),
        base_url,
        api_key: Zeroizing::new(PROTECT_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("protect client");
    UnifiMcp::new_protect(
        "cameras",
        Arc::new(protect),
        None,
        vec![Zeroizing::new(PROTECT_KEY.to_owned())],
    )
}

fn handler_with_events(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let protect = ProtectClient::new(&ControllerConfig {
        name: "cameras".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new(PROTECT_KEY.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("protect client");
    let events = LegacyClient::new(&LegacyConfig {
        name: "cameras".to_owned(),
        base_url,
        username: USERNAME.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("Protect event client");
    UnifiMcp::new_protect(
        "cameras",
        Arc::new(protect),
        Some(Arc::new(events)),
        vec![
            Zeroizing::new(PROTECT_KEY.to_owned()),
            Zeroizing::new(PASSWORD.to_owned()),
        ],
    )
}

fn call(name: &str, arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

/// A console whose integration API answers, with the given camera list.
async fn console_with(server: &MockServer, cameras: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/meta/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "7.1.87"})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/cameras")))
        .respond_with(ResponseTemplate::new(200).set_body_json(cameras))
        .mount(server)
        .await;
}

fn sample_cameras() -> serde_json::Value {
    serde_json::json!([
        {
            "id": "cam-front", "modelKey": "camera", "name": "Front Door",
            "type": "G4 Doorbell", "state": "CONNECTED", "isMicEnabled": true,
            "micVolume": 80
        },
        {
            "id": "cam-back", "modelKey": "camera", "name": "Back Garden",
            "type": "G5 Bullet", "state": "DISCONNECTED"
        },
        {
            "id": "cam-shed", "modelKey": "camera", "name": "Shed",
            "type": "G5 Bullet", "state": "CONNECTED"
        }
    ])
}

fn sample_bootstrap() -> serde_json::Value {
    serde_json::json!({
        "authUser": {"email": "must-not-be-returned@example.invalid"},
        "cameras": [
            {
                "id": "cam-front", "modelKey": "camera", "name": "Local Front Door",
                "type": "UVC G4 Doorbell", "marketName": "G4 Doorbell Pro",
                "firmwareVersion": "4.72.44", "latestFirmwareVersion": "4.73.10",
                "hardwareRevision": "12", "connectedSince": 1000, "lastSeen": 2000,
                "lastDisconnect": 900, "uptime": 100_000, "isUpdating": false,
                "isDownloadingFW": false, "isRebooting": false, "isRestoring": false,
                "isAttemptingToConnect": false, "isRecording": true, "hasRecordings": true,
                "isPoorNetwork": false, "videoMode": "default", "is2K": true, "is4K": false,
                "isThirdPartyCamera": false, "isPairedWithAiPort": false,
                "isMicEnabled": true, "micVolume": 80,
                "recordingSettings": {"mode": "always"},
                "featureFlags": {
                    "isDoorbell": true, "isPtz": false, "hasPackageCamera": true,
                    "hasWifi": true, "hasSpeaker": true, "hasMic": true, "hasHdr": true,
                    "hasSmartDetect": true, "hasLedStatus": true, "canOpticalZoom": false,
                    "hasAutoICROnly": false, "smartDetectTypes": ["person", "vehicle"],
                    "smartDetectAudioTypes": ["smoke"]
                },
                "wifiConnectionState": {
                    "signalQuality": 92, "signalStrength": -47, "phyRate": 866.7,
                    "txRate": 433.3, "channel": 44, "frequency": 5220,
                    "experience": "excellent", "connectivity": "full",
                    "ssid": "must-not-be-returned-ssid"
                },
                "channels": [{"rtspAlias": "must-not-be-returned-stream"}]
            },
            {
                "id": "cam-back", "modelKey": "camera", "marketName": "G5 Bullet",
                "isRecording": false, "is2K": true, "is4K": false,
                "isThirdPartyCamera": false, "isPairedWithAiPort": false,
                "recordingSettings": {"mode": "detections"},
                "featureFlags": {
                    "isDoorbell": false, "isPtz": false, "hasPackageCamera": false,
                    "hasWifi": false, "hasSpeaker": false, "hasMic": true,
                    "hasSmartDetect": true, "canOpticalZoom": false
                },
                "wiredConnectionState": {"phyRate": 1000.0}
            },
            {
                "id": "cam-shed", "modelKey": "camera", "marketName": "G5 Bullet",
                "isRecording": true, "is2K": true, "is4K": false,
                "isThirdPartyCamera": false, "isPairedWithAiPort": false,
                "recordingSettings": {"mode": "always"},
                "featureFlags": {
                    "isDoorbell": false, "isPtz": false, "hasPackageCamera": false,
                    "hasWifi": false, "hasSpeaker": false, "hasMic": true,
                    "hasSmartDetect": true, "canOpticalZoom": false
                }
            }
        ],
        "nvr": {
            "id": "nvr-1", "modelKey": "nvr", "name": "Local Recorder", "type": "UNVR",
            "marketName": "Network Video Recorder Pro", "version": "7.1.87",
            "ucoreVersion": "4.1.13", "isDbAvailable": true,
            "isRecordingDisabled": false, "isRecordingMotionOnly": false,
            "disableAudio": false, "isRecycling": true, "corruptionState": "normal",
            "hardDriveState": "normal", "lastDriveSlowEvent": 1234, "cameraUtilization": 37,
            "maxCameraCapacity": {"4K": 15, "2K": 25, "HD": 50},
            "storageStats": {
                "capacity": 7_776_000_000_u64, "remainingCapacity": 2_592_000_000_u64,
                "utilization": 0.66,
                "recordingSpace": {"total": 1_000_000, "used": 660_000, "available": 340_000},
                "storageDistribution": {
                    "recordingTypeDistributions": [
                        {"recordingType": "detections", "size": 100, "percentage": 0.1}
                    ],
                    "resolutionDistributions": [
                        {"resolution": "2K", "size": 900, "percentage": 0.9}
                    ]
                }
            },
            "systemInfo": {"ustorage": {"disks": [{"serial": "must-not-be-returned-disk"}]}}
        }
    })
}

async fn local_console_with(server: &MockServer, bootstrap: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(serde_json::json!({
            "username": USERNAME,
            "password": PASSWORD
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .and(header("cookie", "TOKEN=protect-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(bootstrap))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "nvr-1", "modelKey": "nvr", "name": "CloudKey"
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn cameras_search_reports_public_inventory_without_inventing_local_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("cameras search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["total"], 3);
    // Name-sorted, so two runs against one console agree on order.
    assert_eq!(output["cameras"][0]["name"], "Back Garden");
    assert_eq!(output["cameras"][1]["name"], "Front Door");
    assert_eq!(output["cameras"][2]["name"], "Shed");
    // The console's own state vocabulary survives rather than becoming a bool.
    assert_eq!(output["cameras"][0]["state"], "DISCONNECTED");
    assert_eq!(output["cameras"][1]["productType"], "G4 Doorbell");
    assert_eq!(output["cameras"][1]["audio"]["enabled"], true);
    assert!(output["cameras"][1].get("recording").is_none());
    assert!(output["cameras"][1].get("classes").is_none());
    assert!(output["cameras"][1].get("features").is_none());
    assert_eq!(output["capabilities"]["publicInventory"], true);
    assert_eq!(output["capabilities"]["localEnrichment"], "notConfigured");
}

#[tokio::test]
async fn local_bootstrap_restores_camera_filters_and_operational_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["featureFlags"]["smartDetectTypes"] = serde_json::json!(
        (0..33)
            .map(|index| format!("video-{index}"))
            .collect::<Vec<_>>()
    );
    bootstrap["cameras"][0]["featureFlags"]["smartDetectAudioTypes"] = serde_json::json!(
        (0..33)
            .map(|index| format!("audio-{index}"))
            .collect::<Vec<_>>()
    );
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let result = handler
        .call(
            &call(
                "cameras.search",
                &serde_json::json!({"model": "doorbell", "class": "doorbell"}),
            ),
            None,
        )
        .await
        .expect("enriched camera search");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["total"], 1);
    let camera = &output["cameras"][0];
    assert_eq!(camera["id"], "cam-front");
    assert_eq!(camera["hardwareModel"], "G4 Doorbell Pro");
    assert_eq!(
        camera["name"], "Front Door",
        "public name remains authoritative"
    );
    assert_eq!(camera["displayNameSource"], "publicName");
    assert!(
        camera["classes"]
            .as_array()
            .expect("classes")
            .contains(&serde_json::json!("doorbell"))
    );
    assert_eq!(camera["recording"], true);
    assert_eq!(camera["recordingEnabled"], true);
    assert_eq!(camera["recordingGloballyDisabled"], false);
    assert_eq!(camera["recordingMode"], "always");
    assert_eq!(camera["audio"]["supported"], true);
    assert_eq!(camera["audio"]["effectivelyEnabled"], true);
    assert_eq!(camera["features"]["twoK"], true);
    assert_eq!(camera["features"]["smartDetectTypes"][0], "video-0");
    assert_eq!(
        camera["features"]["smartDetectTypes"]
            .as_array()
            .expect("video labels")
            .len(),
        32
    );
    assert_eq!(camera["features"]["smartDetectTypesTruncated"], true);
    assert_eq!(
        camera["features"]["smartDetectAudioTypes"]
            .as_array()
            .expect("audio labels")
            .len(),
        32
    );
    assert_eq!(camera["features"]["smartDetectAudioTypesTruncated"], true);
    assert_eq!(camera["connection"]["kind"], "wifi");
    assert_eq!(camera["connection"]["signalQuality"], 92);
    assert_eq!(camera["firmwareVersion"], "4.72.44");
    assert_eq!(camera["localEnrichment"], "available");
    assert_eq!(output["capabilities"]["localEnrichment"], "available");
    assert_eq!(
        output["capabilities"]["publicInventorySource"],
        "integrationApi"
    );
    assert_eq!(
        output["capabilities"]["localInventorySource"],
        "authenticatedLocalBootstrap"
    );
    let serialized = output.to_string();
    for excluded in [
        "must-not-be-returned@example.invalid",
        "must-not-be-returned-ssid",
        "must-not-be-returned-stream",
        "must-not-be-returned-disk",
    ] {
        assert!(
            !serialized.contains(excluded),
            "private bootstrap value leaked"
        );
    }
}

#[tokio::test]
async fn cameras_search_filters_by_query_and_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_for(&server);

    let by_name = handler
        .call(
            &call("cameras.search", &serde_json::json!({"query": "garden"})),
            None,
        )
        .await
        .expect("name filter");
    let output = by_name.structured_content.expect("structured");
    assert_eq!(output["total"], 1);
    assert_eq!(output["cameras"][0]["id"], "cam-back");

    let by_state = handler
        .call(
            &call("cameras.search", &serde_json::json!({"state": "connected"})),
            None,
        )
        .await
        .expect("state filter");
    let output = by_state.structured_content.expect("structured");
    assert_eq!(output["total"], 2);
    assert_eq!(output["cameras"][0]["name"], "Front Door");
}

#[tokio::test]
async fn a_bounded_page_names_its_continuation() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("cameras.search", &serde_json::json!({"limit": 2})),
            None,
        )
        .await
        .expect("first page");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["cameras"].as_array().expect("cameras").len(), 2);
    // The total is of the whole match, not the page, and the continuation is
    // present -- a caller must be able to tell it did not see everything.
    assert_eq!(output["total"], 3);
    assert_eq!(output["nextOffset"], 2);

    let last = handler
        .call(
            &call(
                "cameras.search",
                &serde_json::json!({"limit": 2, "offset": 2}),
            ),
            None,
        )
        .await
        .expect("last page");
    let output = last.structured_content.expect("structured");
    assert_eq!(output["cameras"].as_array().expect("cameras").len(), 1);
    assert!(output.get("nextOffset").is_none());
}

#[tokio::test]
async fn cameras_status_selects_by_id_or_exact_name() {
    let server = MockServer::start().await;
    let mut cameras = sample_cameras();
    cameras[0]["name"] = serde_json::json!("Étage");
    console_with(&server, cameras).await;
    let handler = handler_for(&server);

    let by_id = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "cam-shed"})),
            None,
        )
        .await
        .expect("by id");
    assert_eq!(
        by_id.structured_content.expect("structured")["name"],
        "Shed"
    );

    let by_name = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "étage"})),
            None,
        )
        .await
        .expect("by name");
    let output = by_name.structured_content.expect("structured");
    assert_eq!(output["id"], "cam-front");
    assert_eq!(output["productType"], "G4 Doorbell");
    assert_eq!(output["localEnrichment"], "notConfigured");
}

#[tokio::test]
async fn a_blank_public_name_keeps_a_separate_usable_local_display_name() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([{
            "id": "cam-front", "modelKey": "camera", "name": "  ", "state": "CONNECTED"
        }]),
    )
    .await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .truncate(1);
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let output = handler
        .call(
            &call(
                "cameras.status",
                &serde_json::json!({"camera": "Local Front Door"}),
            ),
            None,
        )
        .await
        .expect("local display-name selector")
        .structured_content
        .expect("structured");
    assert_eq!(output["name"], "  ");
    assert_eq!(output["displayName"], "Local Front Door");
    assert_eq!(output["displayNameSource"], "localName");
}

#[tokio::test]
async fn a_returned_256_character_camera_name_remains_selectable() {
    let server = MockServer::start().await;
    let name = "é".repeat(256);
    console_with(
        &server,
        serde_json::json!([{
            "id": "cam-long-name",
            "modelKey": "camera",
            "name": name,
            "state": "CONNECTED"
        }]),
    )
    .await;
    let handler = handler_for(&server);

    let result = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": name})),
            None,
        )
        .await
        .expect("select the complete returned name");
    assert_eq!(
        result.structured_content.expect("structured")["id"],
        "cam-long-name"
    );
}

#[tokio::test]
async fn an_ambiguous_camera_name_is_refused_rather_than_resolved_by_position() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-a", "modelKey": "camera", "name": "Side", "state": "CONNECTED"},
            {"id": "cam-b", "modelKey": "camera", "name": "Side", "state": "CONNECTED"}
        ]),
    )
    .await;
    let handler = handler_for(&server);

    let error = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "Side"})),
            None,
        )
        .await
        .expect_err("ambiguous");
    assert!(
        error.message.contains("share that name"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn duplicate_public_camera_ids_fail_instead_of_merging_records() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-a", "modelKey": "camera", "name": "One", "state": "CONNECTED"},
            {"id": "cam-a", "modelKey": "camera", "name": "Two", "state": "DISCONNECTED"}
        ]),
    )
    .await;
    let handler = handler_for(&server);

    let error = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect_err("duplicate ids");
    assert!(error.message.contains("duplicate ids"));
}

#[tokio::test]
async fn public_cameras_may_share_a_physical_hardware_identity() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-a", "modelKey": "camera", "name": "One", "state": "CONNECTED", "guid": "shared"},
            {"id": "cam-b", "modelKey": "camera", "name": "Two", "state": "CONNECTED", "guid": "SHARED"}
        ]),
    )
    .await;

    let result = handler_for(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("shared physical identity");
    assert_eq!(result.structured_content.expect("structured")["total"], 2);
}

#[tokio::test]
async fn protect_overview_groups_by_the_consoles_own_state_words() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "nvr-1", "modelKey": "nvr", "name": "CloudKey", "type": "UNVR"
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("overview");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applicationVersion"], "7.1.87");
    assert_eq!(output["cameraCount"], 3);
    assert_eq!(output["camerasByState"][0]["state"], "CONNECTED");
    assert_eq!(output["camerasByState"][0]["count"], 2);
    assert_eq!(output["camerasByState"][1]["state"], "DISCONNECTED");
    assert!(output.get("notRecording").is_none());
    assert_eq!(output["recorders"][0]["name"], "CloudKey");
    assert_eq!(output["recorders"][0]["productType"], "UNVR");
    assert_eq!(output["recorders"][0]["enriched"], false);
    assert_eq!(output["capabilities"]["localEnrichment"], "notConfigured");
}

#[tokio::test]
async fn protect_overview_reports_enriched_recorder_storage_and_recording_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["nvr"]["storageStats"]["storageDistribution"]["recordingTypeDistributions"] =
        serde_json::Value::Array(
            (0..33)
                .map(|index| {
                    serde_json::json!({
                        "recordingType": format!("type-{index}"), "size": index, "percentage": 0.01
                    })
                })
                .collect(),
        );
    bootstrap["nvr"]["storageStats"]["storageDistribution"]
        .as_object_mut()
        .expect("storage distribution")
        .remove("resolutionDistributions");
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let output = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("enriched overview")
        .structured_content
        .expect("structured");
    assert_eq!(output["notRecordingCount"], 1);
    assert_eq!(output["notRecording"][0]["id"], "cam-back");
    let recorder = &output["recorders"][0];
    assert_eq!(
        recorder["name"], "CloudKey",
        "public name remains authoritative"
    );
    assert_eq!(recorder["hardwareModel"], "Network Video Recorder Pro");
    assert_eq!(recorder["protectVersion"], "7.1.87");
    assert_eq!(recorder["consoleVersion"], "4.1.13");
    assert_eq!(recorder["databaseAvailable"], true);
    assert_eq!(recorder["recordingDisabled"], false);
    assert_eq!(recorder["audioDisabled"], false);
    assert_eq!(recorder["maxCameraCapacity"]["fourK"], 15);
    assert_eq!(
        recorder["storage"]["recordingSpace"]["availableBytes"],
        340_000
    );
    assert_eq!(
        recorder["storage"]["recordingTypeDistribution"][0]["category"],
        "type-0"
    );
    assert_eq!(
        recorder["storage"]["recordingTypeDistribution"]
            .as_array()
            .expect("bounded distribution")
            .len(),
        32
    );
    assert_eq!(
        recorder["storage"]["recordingTypeDistributionTruncated"],
        true
    );
    assert!(recorder["storage"].get("resolutionDistribution").is_none());
    assert_eq!(recorder["enriched"], true);
}

#[tokio::test]
async fn local_inventory_identity_conflicts_and_duplicates_fail_loudly() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    let cameras = bootstrap["cameras"].as_array_mut().expect("cameras");
    cameras.push(cameras[0].clone());
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect_err("duplicate local id");
    assert!(
        error
            .message
            .contains("local camera inventory contains duplicate ids")
    );
}

#[tokio::test]
async fn logical_cameras_may_share_hardware_identity_across_sources() {
    let server = MockServer::start().await;
    let mut public = sample_cameras();
    public[0]["guid"] = serde_json::json!("shared-guid");
    public[1]["guid"] = serde_json::json!("shared-guid");
    console_with(&server, public).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["guid"] = serde_json::json!("shared-guid");
    bootstrap["cameras"][1]["guid"] = serde_json::json!("shared-guid");
    local_console_with(&server, bootstrap).await;

    let result = handler_with_events(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("shared hardware identity");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["total"], 3);
    assert_eq!(output["capabilities"]["localEnrichment"], "available");
}

#[tokio::test]
async fn the_same_camera_id_with_conflicting_hardware_identity_fails_loudly() {
    let server = MockServer::start().await;
    let mut public = sample_cameras();
    public[0]["guid"] = serde_json::json!("public-guid");
    console_with(&server, public).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["guid"] = serde_json::json!("local-guid");
    local_console_with(&server, bootstrap).await;

    let error = handler_with_events(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect_err("conflicting camera identity");
    assert!(error.message.contains("camera identities conflict"));
}

#[tokio::test]
async fn a_conflicting_local_recorder_cannot_supply_camera_global_state() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["nvr"]["id"] = serde_json::json!("different-nvr");
    local_console_with(&server, bootstrap).await;

    let error = handler_with_events(&server)
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect_err("conflicting recorder identity");
    assert!(error.message.contains("recorder identities conflict"));
}

#[tokio::test]
async fn partial_local_inventory_never_turns_model_filter_into_a_false_empty_result() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"].as_array_mut().expect("cameras").pop();
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"model": "G5"})),
            None,
        )
        .await
        .expect_err("incomplete model data");
    assert!(error.message.contains("model filtering is unavailable"));

    let output = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public inventory still works")
        .structured_content
        .expect("structured");
    assert_eq!(output["total"], 3);
    assert_eq!(output["capabilities"]["localEnrichment"], "partial");
    assert_eq!(output["cameras"][2]["localEnrichment"], "noMatchingRecord");
}

#[tokio::test]
async fn a_blank_local_market_name_is_not_complete_model_data() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][2]["marketName"] = serde_json::json!("  ");
    bootstrap["cameras"][2]["recordingSettings"]["mode"] = serde_json::json!("future-mode");
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"model": "G5"})),
            None,
        )
        .await
        .expect_err("blank model data");
    assert!(error.message.contains("model filtering is unavailable"));

    let camera = handler
        .call(
            &call("cameras.status", &serde_json::json!({"camera": "Shed"})),
            None,
        )
        .await
        .expect("unknown recording mode")
        .structured_content
        .expect("structured");
    assert_eq!(camera["recordingMode"], "future-mode");
    assert!(camera.get("recordingConfigured").is_none());
    assert!(camera.get("recordingEnabled").is_none());
}

#[tokio::test]
async fn an_unknown_recording_flag_suppresses_the_mixed_overview_summary() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][2]
        .as_object_mut()
        .expect("camera")
        .remove("isRecording");
    local_console_with(&server, bootstrap).await;
    let handler = handler_with_events(&server);

    let result = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("overview");
    let output = result.structured_content.expect("structured");
    // The known idle camera cannot make this look like a complete summary
    // while another camera's recording state is absent.
    assert!(output.get("notRecording").is_none());
    assert!(output.get("notRecordingCount").is_none());
    assert_eq!(output["cameraCount"], 3);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves filtering, continuation, and uncut labels across two pages"
)]
async fn protect_events_filters_and_continues_without_a_hidden_scan_ceiling() {
    let server = MockServer::start().await;
    let mut cameras = sample_cameras();
    cameras[0]["name"] = serde_json::json!(" Front Door ");
    console_with(&server, cameras).await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(serde_json::json!({
            "username": USERNAME,
            "password": PASSWORD
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let detection_types: Vec<String> = (0..20)
        .map(|index| {
            if index == 0 {
                "person".to_owned()
            } else {
                format!("label-{index}")
            }
        })
        .collect();
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/bootstrap"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(header("cookie", "TOKEN=protect-session"))
        .and(query_param("start", "1000"))
        .and(query_param("end", "2000"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .and(query_param("types", "motion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-3", "type": "smartDetectZone", "start": 1900,
             "camera": "cam-front", "smartDetectTypes": detection_types},
            {"id": "event-2", "type": "motion", "start": 1800,
             "camera": "cam-back"},
            {"id": "event-1", "type": "smartDetectLine", "start": 1100,
             "camera": "cam-front", "smartDetectTypes": ["person"]}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(query_param("start", "1000"))
        .and(query_param("end", "1799"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-1", "type": "smartDetectLine", "start": 1100,
             "camera": "cam-front", "smartDetectTypes": ["person"]},
            {"id": "before-window", "type": "motion", "start": 999}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_with_events(&server);

    let first = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({
                    "start": 1000,
                    "end": 2000,
                    "camera": "cam-front",
                    "detection": "person",
                    "limit": 2
                }),
            ),
            None,
        )
        .await
        .expect("first page");
    let output = first.structured_content.expect("structured");
    assert_eq!(output["rows"].as_array().expect("rows").len(), 1);
    assert_eq!(output["rows"][0]["cameraName"], " Front Door ");
    assert_eq!(
        output["rows"][0]["detectionTypes"]
            .as_array()
            .expect("detection types")
            .len(),
        20,
        "all labels remain reachable rather than being cut at an arbitrary row ceiling"
    );
    assert_eq!(output["scannedRows"], 2);
    assert_eq!(output["complete"], false);
    assert!(output.get("fetchWindowTruncated").is_none());
    let cursor = output["nextCursor"].clone();

    let second = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"cursor": cursor, "limit": 2}),
            ),
            None,
        )
        .await
        .expect("second page");
    let output = second.structured_content.expect("structured");
    assert_eq!(output["rows"].as_array().expect("rows").len(), 1);
    assert_eq!(output["rows"][0]["id"], "event-1");
    assert_eq!(
        output["rows"][0]["detectionTypes"],
        serde_json::json!(["person"])
    );
    assert_eq!(output["complete"], true);
    assert!(output.get("nextCursor").is_none());
}

#[tokio::test]
async fn protect_events_serialize_an_empty_detection_label_list() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    local_console_with(&server, sample_bootstrap()).await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id": "event-without-labels",
                "type": "motion",
                "start": 1500,
                "camera": "cam-front"
            }])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_with_events(&server)
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000}),
            ),
            None,
        )
        .await
        .expect("unlabeled event")
        .structured_content
        .expect("structured");

    assert_eq!(output["rows"][0]["detectionTypes"], serde_json::json!([]));
}

#[tokio::test]
async fn protect_events_accepts_the_local_display_name_reported_by_search() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-front", "modelKey": "camera", "name": null, "state": "CONNECTED"},
            {"id": "cam-back", "modelKey": "camera", "name": "Public Front", "state": "CONNECTED"},
            {"id": "cam-shed", "modelKey": "camera", "name": null, "state": "CONNECTED"}
        ]),
    )
    .await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"][0]["name"] = serde_json::json!(" ÉTAGE ");
    bootstrap["cameras"][2]["name"] = serde_json::json!(" Public Front ");
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .truncate(3);
    local_console_with(&server, bootstrap).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-1", "type": "motion", "start": 1500, "camera": "cam-front"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let handler = handler_with_events(&server);
    let output = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": " étage "}),
            ),
            None,
        )
        .await
        .expect("events by local display name")
        .structured_content
        .expect("structured");
    assert_eq!(output["rows"][0]["cameraId"], "cam-front");

    let error = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": "Public Front"}),
            ),
            None,
        )
        .await
        .expect_err("cross-source ambiguous name");
    assert!(error.message.contains("2 cameras share that name"));
}

#[tokio::test]
async fn protect_events_refuses_name_selection_from_partial_local_inventory() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"].as_array_mut().expect("cameras").pop();
    local_console_with(&server, bootstrap).await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let error = handler_with_events(&server)
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": "Front Door"}),
            ),
            None,
        )
        .await
        .expect_err("partial name inventory must fail before event lookup");
    assert!(
        error
            .message
            .contains("camera name selection requires complete local Protect inventory"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn camera_name_selection_refuses_an_extra_local_camera_namespace() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let mut bootstrap = sample_bootstrap();
    bootstrap["cameras"]
        .as_array_mut()
        .expect("cameras")
        .push(serde_json::json!({
            "id": "cam-local-only", "modelKey": "camera", "name": "Front Door"
        }));
    local_console_with(&server, bootstrap).await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let handler = handler_with_events(&server);

    for tool in ["cameras.status", "protect.events"] {
        let arguments = if tool == "cameras.status" {
            serde_json::json!({"camera": "Front Door"})
        } else {
            serde_json::json!({"start": 1000, "end": 2000, "camera": "Front Door"})
        };
        let error = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("an asymmetric name namespace must fail");
        assert!(
            error
                .message
                .contains("camera name selection requires complete local Protect inventory"),
            "{}: {}",
            tool,
            error.message
        );
    }
}

#[tokio::test]
async fn protect_events_refuses_name_selection_when_local_inventory_is_unavailable() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let error = handler_with_events(&server)
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "camera": "Front Door"}),
            ),
            None,
        )
        .await
        .expect_err("unavailable name inventory must fail before event lookup");
    assert!(
        error
            .message
            .contains("camera name selection requires complete local Protect inventory"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn protect_events_equal_timestamp_boundary_names_the_recovery_path() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(serde_json::json!({
            "username": USERNAME,
            "password": PASSWORD
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=protect-session; Path=/")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/api/events"))
        .and(query_param("limit", "3"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"id": "event-3", "type": "motion", "start": 1900},
            {"id": "event-2", "type": "motion", "start": 1900},
            {"id": "event-1", "type": "motion", "start": 1900}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler_with_events(&server);

    let error = handler
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000, "limit": 2}),
            ),
            None,
        )
        .await
        .expect_err("equal timestamp boundary must fail");

    assert!(
        error.message.contains("retry with a higher limit"),
        "{}",
        error.message
    );
    assert!(!error.message.contains("invalid controller configuration"));
}

#[tokio::test]
async fn protect_events_names_missing_local_session_credentials() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let error = handler_for(&server)
        .call(
            &call(
                "protect.events",
                &serde_json::json!({"start": 1000, "end": 2000}),
            ),
            None,
        )
        .await
        .expect_err("missing local Protect session");
    assert!(
        error
            .message
            .contains("no local Protect session is configured"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn configured_local_session_reports_unavailable_when_bootstrap_cannot_be_read() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    let handler = handler_with_events(&server);

    let output = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public inventory")
        .structured_content
        .expect("structured");
    assert_eq!(output["capabilities"]["localEnrichment"], "unavailable");
    assert_eq!(output["cameras"][0]["localEnrichment"], "unavailable");
}

#[tokio::test]
async fn a_console_without_the_integration_api_is_refused_by_every_camera_tool() {
    let server = MockServer::start().await;
    // The console answers, and has no integration API at this path.
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/meta/info")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    for (tool, arguments) in [
        ("cameras.search", serde_json::json!({})),
        ("cameras.status", serde_json::json!({"camera": "cam-a"})),
        ("protect.overview", serde_json::json!({})),
        (
            "protect.events",
            serde_json::json!({"start": 1000, "end": 2000}),
        ),
    ] {
        let error = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("console without the integration API must refuse");
        assert!(
            error
                .message
                .contains("does not expose the Protect integration"),
            "{tool} must name the reason: {}",
            error.message
        );
        // The distinction this whole boundary exists for.
        assert!(
            error
                .message
                .contains("not the same as a console with no cameras"),
            "{tool} must distinguish itself from an empty console: {}",
            error.message
        );
    }
}

#[tokio::test]
async fn a_network_runtime_rejects_every_protect_tool_as_outside_its_catalog() {
    let server = MockServer::start().await;
    let handler = handler_without_protect(&server);

    for (tool, arguments) in [
        ("cameras.search", serde_json::json!({})),
        ("cameras.status", serde_json::json!({"camera": "cam-a"})),
        ("protect.overview", serde_json::json!({})),
        (
            "protect.events",
            serde_json::json!({"start": 1000, "end": 2000}),
        ),
    ] {
        let error = handler
            .call(&call(tool, &arguments), None)
            .await
            .expect_err("Protect tool must not dispatch on Network");
        assert!(
            error.message.contains("unknown tool"),
            "{tool}: {}",
            error.message
        );
    }
}

#[tokio::test]
async fn unavailable_model_and_class_filters_fail_explicitly() {
    let server = MockServer::start().await;
    console_with(
        &server,
        serde_json::json!([
            {"id": "cam-a", "modelKey": "camera", "name": null, "state": "CONNECTED"}
        ]),
    )
    .await;
    let handler = handler_for(&server);

    let inventory = handler
        .call(&call("cameras.search", &serde_json::json!({})), None)
        .await
        .expect("public inventory without a name")
        .structured_content
        .expect("structured");
    assert_eq!(inventory["cameras"][0]["id"], "cam-a");
    assert!(inventory["cameras"][0].get("name").is_none());

    let model_error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"model": "G5"})),
            None,
        )
        .await
        .expect_err("model data unavailable");
    assert!(
        model_error
            .message
            .contains("model filtering is unavailable")
    );

    let class_error = handler
        .call(
            &call("cameras.search", &serde_json::json!({"class": "doorbell"})),
            None,
        )
        .await
        .expect_err("class data unavailable");
    assert!(
        class_error
            .message
            .contains("class filtering is unavailable")
    );
}

#[tokio::test]
async fn the_overview_names_which_console_answered() {
    let server = MockServer::start().await;
    console_with(&server, sample_cameras()).await;
    Mock::given(method("GET"))
        .and(path(format!("{PROTECT}/nvrs")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "nvr-1", "modelKey": "nvr", "name": "Recorder"
        })))
        .mount(&server)
        .await;
    let handler = handler_for(&server);

    let result = handler
        .call(&call("protect.overview", &serde_json::json!({})), None)
        .await
        .expect("overview");
    assert_eq!(
        result.structured_content.expect("structured")["console"],
        "cameras"
    );
}
