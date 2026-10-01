//! End-to-end tests for voucher creation against loopback fakes.
//!
//! Creation results retain controller-returned codes when checks fail, and
//! readback verifies identified codes through the detail endpoint.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};
use zeroize::Zeroizing;

const PASSWORD: &str = "test-legacy-password";
const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";

fn handler_for(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("mock server uri");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "home".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("test-integration-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "home".to_owned(),
        base_url,
        username: "svc-mcp".to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn create(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "vouchers.create".to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

async fn mount_site(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(server)
        .await;
}

async fn mints(server: &MockServer, response: &serde_json::Value) {
    mount_site(server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(server)
        .await;
}

fn batch(codes: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "vouchers": codes
            .iter()
            .enumerate()
            .map(|(index, code)| serde_json::json!({
                "id": format!("voucher-{index}"),
                "code": code,
            }))
            .collect::<Vec<_>>(),
    })
}

#[tokio::test]
async fn an_unconfirmed_call_describes_the_batch_and_mints_nothing() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    // No create endpoint is mounted: minting would fail this test.

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests",
                "count": 5,
                "timeLimitMinutes": 1440,
                "guestLimit": 3,
                "dataLimitMegabytes": 512,
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["requested"], 5);
    assert!(output.get("vouchers").is_none());
    // A preview is what this reviewed write is reviewed from, so it has to
    // show which batch is about to be minted. Two batches differing only in
    // validity or access limits are different batches.
    assert_eq!(
        output["batch"],
        serde_json::json!({
            "name": "guests",
            "count": 5,
            "timeLimitMinutes": 1440,
            "guestLimit": 3,
            "dataLimitMegabytes": 512,
        }),
        "{output}"
    );
    let warnings = output["warnings"].to_string();
    assert!(warnings.contains("vouchers.status"), "{output}");
    assert!(warnings.contains("credential"), "{output}");
}

#[tokio::test]
async fn creation_retains_complete_small_and_large_accepted_bodies() {
    for extension in ["controller-field".to_owned(), "x".repeat(60_000)] {
        let server = MockServer::start().await;
        mount_site(&server).await;
        let body = format!(
            " {} ",
            serde_json::json!({"vouchers":[{
            "code":"1234567890", "name":"Upstream name", "createdAt":"2026-09-30T00:00:00Z",
            "unknownExtension":extension
        }], "unknownMetadata":true})
        );
        Mock::given(method("POST"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
            )))
            .respond_with(ResponseTemplate::new(201).set_body_string(&body))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler_for(&server)
            .call(
                &create(&serde_json::json!({
                    "name":"guests", "count":1, "timeLimitMinutes":60, "confirm":true
                })),
                None,
            )
            .await
            .expect("accepted creation");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["applied"], true);
        assert_eq!(output["responseStatus"], 201);
        assert_eq!(output["vouchers"][0]["code"], "1234567890");
        assert_eq!(output["verified"], false);
        if extension.len() > 50_000 {
            assert_eq!(output["responseBodyInContent"], true);
            assert!(
                result
                    .content
                    .iter()
                    .filter_map(|block| block.as_text())
                    .any(|text| text.text.strip_prefix("responseBody: ") == Some(body.as_str()))
            );
        } else {
            assert_eq!(output["responseBody"], body);
        }
        assert_eq!(server.received_requests().await.expect("requests").len(), 2);
        server.verify().await;
    }
}

#[tokio::test]
async fn a_confirmed_call_sends_the_batch_and_returns_every_code() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .and(body_json(serde_json::json!({
            "name": "guests",
            "count": 3,
            "timeLimitMinutes": 1440,
            "authorizedGuestLimit": 2,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch(&[
            "1234567890",
            "2345678901",
            "3456789012",
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests",
                "count": 3,
                "timeLimitMinutes": 1440,
                "guestLimit": 2,
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["vouchers"].as_array().expect("vouchers").len(), 3);
    assert_eq!(output["vouchers"][0]["code"], "1234567890");
    assert_eq!(output["checks"]["countMatches"], true);
    assert_eq!(output["checks"]["codeLengths"], serde_json::json!([10]));
}

#[tokio::test]
async fn a_batch_that_fails_a_check_still_returns_its_codes() {
    // A check on the creation response must not hide controller-returned rows.
    for (label, minted, failed) in [
        (
            "fewer than requested",
            vec!["1234567890", "2345678901"],
            "countMatches",
        ),
        (
            "a duplicate code",
            vec!["1234567890", "1234567890", "3456789012"],
            "allDistinct",
        ),
        (
            "a missing code",
            vec!["1234567890", "", "3456789012"],
            "allIdentified",
        ),
    ] {
        let server = MockServer::start().await;
        mints(&server, &batch(&minted)).await;

        let output = handler_for(&server)
            .call(
                &create(&serde_json::json!({
                    "name": "guests",
                    "count": 3,
                    "timeLimitMinutes": 1440,
                    "confirm": true,
                })),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{label}: {error}"))
            .structured_content
            .expect("structured");

        assert_eq!(output["checks"][failed], false, "{label}: {output}");
        // Every code in the creation response remains available to the caller.
        let returned: Vec<&str> = output["vouchers"]
            .as_array()
            .expect("vouchers")
            .iter()
            .map(|voucher| voucher["code"].as_str().expect("code"))
            .collect();
        assert_eq!(returned, minted, "{label}: {output}");
    }
}

#[tokio::test]
async fn controller_code_strings_have_observations_without_format_verdicts() {
    let server = MockServer::start().await;
    let long_code = "λ".repeat(80);
    let minted = [" leading and trailing ", long_code.as_str()];
    mints(&server, &batch(&minted)).await;
    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name":"guests", "count":2, "timeLimitMinutes":60, "confirm":true
            })),
            None,
        )
        .await
        .expect("complete controller strings")
        .structured_content
        .expect("structured");
    assert_eq!(output["vouchers"][0]["code"], minted[0]);
    assert_eq!(output["vouchers"][1]["code"], minted[1]);
    assert_eq!(output["checks"]["countMatches"], true);
    assert_eq!(output["checks"]["allIdentified"], true);
    assert_eq!(output["checks"]["allDistinct"], true);
    assert_eq!(output["checks"]["codeLengths"], serde_json::json!([22, 80]));
    assert!(output.get("wellFormed").is_none());
    assert!(output["checks"].get("allWellFormed").is_none());
    let body: serde_json::Value =
        serde_json::from_str(output["responseBody"].as_str().expect("original body"))
            .expect("JSON");
    assert_eq!(body["vouchers"][1]["code"], minted[1]);
}

#[tokio::test]
async fn a_row_the_controller_did_not_identify_still_yields_its_code() {
    // The identity check advertises this exact condition, so the batch has to
    // survive long enough to report it. A required id would instead discard
    // every code in the batch while decoding.
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "vouchers": [
                {"id": "voucher-0", "code": "1234567890"},
                {"code": "2345678901"},
            ],
        })))
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests",
                "count": 2,
                "timeLimitMinutes": 60,
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["checks"]["allIdentified"], false, "{output}");
    assert_eq!(output["vouchers"][1]["code"], "2345678901", "{output}");
    assert!(output["vouchers"][1].get("id").is_none(), "{output}");
}

#[tokio::test]
async fn a_missing_voucher_code_is_reported_as_missing() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "vouchers": [{"id": "voucher-0"}]
        })))
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests", "count": 1,
                "timeLimitMinutes": 60, "confirm": true
            })),
            None,
        )
        .await
        .expect("created voucher remains visible")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["vouchers"][0]["id"], "voucher-0");
    assert!(output["vouchers"][0].get("code").is_none());
    assert_eq!(output["checks"]["allIdentified"], false);
}

#[tokio::test]
async fn a_voucher_id_and_code_are_returned_exactly() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "vouchers": [{"id": format!("v-{PASSWORD}-1"), "code": PASSWORD}],
        })))
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests",
                "count": 1,
                "timeLimitMinutes": 60,
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("returned, not withheld")
        .structured_content
        .expect("structured");
    assert_eq!(
        output["vouchers"][0]["id"],
        format!("v-{PASSWORD}-1"),
        "{output}"
    );
    assert_eq!(output["vouchers"][0]["code"], PASSWORD, "{output}");
    assert_eq!(output["checks"]["allIdentified"], true, "{output}");
}

#[tokio::test]
async fn a_large_accepted_batch_keeps_every_code_in_content() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let long_code = "c".repeat(20_000);
    let minted: Vec<String> = (0..8).map(|index| format!("{long_code}{index}")).collect();
    let vouchers: Vec<serde_json::Value> = minted
        .iter()
        .enumerate()
        .map(|(index, code)| serde_json::json!({ "id": format!("voucher-{index}"), "code": code }))
        .collect();
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "vouchers": vouchers })),
        )
        .mount(&server)
        .await;

    let result = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests",
                "count": 8,
                "timeLimitMinutes": 60,
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("accepted codes remain available");
    let content = serde_json::to_value(&result.content)
        .expect("content")
        .to_string();
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(output["responseBodyInContent"], true);
    assert_eq!(output["vouchersInContent"], true);
    for code in minted {
        assert!(content.contains(&code));
    }
}

#[tokio::test]
async fn controller_generated_codes_are_returned_exactly() {
    let server = MockServer::start().await;
    mints(&server, &batch(&["1234567890", PASSWORD])).await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests",
                "count": 2,
                "timeLimitMinutes": 60,
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("returned, not withheld")
        .structured_content
        .expect("structured");
    assert_eq!(output["vouchers"].as_array().expect("vouchers").len(), 2);
    assert_eq!(output["vouchers"][0]["code"], "1234567890", "{output}");
    assert_eq!(output["vouchers"][1]["code"], PASSWORD, "{output}");
    assert_eq!(output["vouchers"][1]["id"], "voucher-1", "{output}");
}

#[tokio::test]
async fn native_limits_rates_and_original_names_reach_the_controller() {
    for name in [format!("  {}  ", "g".repeat(500)), "   ".to_owned()] {
        let server = MockServer::start().await;
        mount_site(&server).await;
        let vouchers = (0..1000)
            .map(|index| serde_json::json!({"code":format!("{index:010}")}))
            .collect::<Vec<_>>();
        Mock::given(method("POST"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
            )))
            .and(body_json(serde_json::json!({
                "name":name,"count":1000,"timeLimitMinutes":1_000_000,
                "authorizedGuestLimit":4_294_967_296_u64,"dataUsageLimitMBytes":1_048_576,
                "rxRateLimitKbps":100_000,"txRateLimitKbps":2
            })))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"vouchers":vouchers})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let output = handler_for(&server)
            .call(
                &create(&serde_json::json!({
                    "name":name,"count":1000,"timeLimitMinutes":1_000_000,
                    "guestLimit":4_294_967_296_u64,"dataLimitMegabytes":1_048_576,
                    "downloadRateLimitKbps":100_000,"uploadRateLimitKbps":2,"confirm":true
                })),
                None,
            )
            .await
            .expect("native voucher creation")
            .structured_content
            .expect("structured");
        assert_eq!(output["batch"]["name"], name);
        assert_eq!(output["batch"]["guestLimit"], 4_294_967_296_u64);
        assert_eq!(output["batch"]["downloadRateLimitKbps"], 100_000);
        assert_eq!(output["batch"]["uploadRateLimitKbps"], 2);
        assert_eq!(output["requested"], 1000);
        assert_eq!(output["vouchers"].as_array().expect("vouchers").len(), 1000);
        assert_eq!(output["vouchers"][999]["code"], "0000000999");
        assert_eq!(output["responseStatus"], 201);
        assert_eq!(server.received_requests().await.expect("requests").len(), 2);
        server.verify().await;
    }
}

#[tokio::test]
async fn default_count_and_rate_preview_do_not_contact_the_controller() {
    let server = MockServer::start().await;
    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name":"  label  ","timeLimitMinutes":1_000_000,
                "downloadRateLimitKbps":2,"uploadRateLimitKbps":100_000
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["requested"], 1);
    assert_eq!(output["batch"]["name"], "  label  ");
    assert_eq!(output["batch"]["downloadRateLimitKbps"], 2);
    assert_eq!(output["batch"]["uploadRateLimitKbps"], 100_000);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn native_optional_ranges_are_validated_before_controller_calls() {
    let server = MockServer::start().await;
    let handler = handler_for(&server);
    for (field, values) in [
        ("guestLimit", vec![0, 9_223_372_036_854_775_808_u64]),
        ("dataLimitMegabytes", vec![0, 1_048_577]),
        ("downloadRateLimitKbps", vec![1, 100_001]),
        ("uploadRateLimitKbps", vec![1, 100_001]),
    ] {
        for value in values {
            let mut input = serde_json::json!({"name":"g","timeLimitMinutes":60,"confirm":true});
            input[field] = serde_json::json!(value);
            let error = handler
                .call(&create(&input), None)
                .await
                .expect_err("native invalid range");
            assert!(error.message.contains(field));
        }
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn a_batch_that_cannot_be_satisfied_is_refused_before_it_is_minted() {
    let server = MockServer::start().await;
    // Nothing is mounted. Every refusal must be decided from the request
    // alone: a batch rejected after minting would be credentials nobody can
    // reach, which is the one outcome worse than not minting at all.
    let handler = handler_for(&server);

    for (arguments, expected) in [
        (
            serde_json::json!({"name": "g", "count": 0, "timeLimitMinutes": 60}),
            "count must be between",
        ),
        (
            serde_json::json!({"name": "g", "count": 1001, "timeLimitMinutes": 60}),
            "count must be between",
        ),
        (
            serde_json::json!({"name": "g", "count": 1, "timeLimitMinutes": 0}),
            "timeLimitMinutes must be between",
        ),
        (
            serde_json::json!({"name": "g", "count": 1, "timeLimitMinutes": 1_000_001}),
            "timeLimitMinutes must be between",
        ),
        (
            serde_json::json!({"name": "", "count": 1, "timeLimitMinutes": 60}),
            "name must be nonempty",
        ),
        // Bound the complete serialized request before calling the controller.
        (
            serde_json::json!({
                "name": "\"".repeat(600_000),
                "count": 1,
                "timeLimitMinutes": 60,
            }),
            "serialized voucher request exceeds",
        ),
    ] {
        let mut confirmed = arguments.clone();
        confirmed["confirm"] = serde_json::json!(true);
        let error = handler
            .call(&create(&confirmed), None)
            .await
            .expect_err(expected);
        assert!(error.message.contains(expected), "{}", error.message);
    }
}

#[tokio::test]
async fn failed_readback_is_reported_without_hiding_created_codes() {
    let server = MockServer::start().await;
    mints(&server, &batch(&["1234567890"])).await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests",
                "count": 1,
                "timeLimitMinutes": 60,
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], false, "{output}");
    assert_eq!(output["vouchers"][0]["code"], "1234567890");
    assert!(output.get("checks").is_some(), "{output}");
    assert_eq!(output["readbackErrors"][0]["voucherId"], "voucher-0");
    assert!(
        output["readbackErrors"][0]["error"]
            .as_str()
            .expect("error")
            .contains("controller returned HTTP 404")
    );
    assert_eq!(output["readbackComplete"], true);
}

#[tokio::test]
async fn multiple_readback_failures_identify_the_vouchers_that_failed() {
    let server = MockServer::start().await;
    mints(&server, &batch(&["1234567890", "2345678901"])).await;
    for index in 0..2 {
        Mock::given(method("GET"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/voucher-{index}"
            )))
            .respond_with(
                ResponseTemplate::new(503).set_body_string(format!("detail failure {index}")),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests", "count": 2, "timeLimitMinutes": 60,
                "confirm": true
            })),
            None,
        )
        .await
        .expect("created codes survive")
        .structured_content
        .expect("structured");
    assert_eq!(output["readbackComplete"], true);
    for index in 0..2 {
        assert_eq!(
            output["readbackErrors"][index]["voucherId"],
            format!("voucher-{index}")
        );
        assert_eq!(
            output["readbackErrors"][index]["error"],
            format!("controller returned HTTP 503: detail failure {index}")
        );
    }
}

#[tokio::test]
async fn large_readback_failure_keeps_every_issued_code_and_continues_verification() {
    let server = MockServer::start().await;
    let mut accepted = batch(&["1234567890", "2345678901"]);
    accepted["controllerExtension"] =
        serde_json::json!(format!("{}accepted-voucher-tail", "y".repeat(50_000)));
    mints(&server, &accepted).await;
    let failure = format!("detail failed: {}voucher-error-tail", "x".repeat(50_000));
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/voucher-0"
        )))
        .respond_with(ResponseTemplate::new(503).set_body_string(failure.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/voucher-1"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id":"voucher-1","code":"2345678901"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests", "count": 2, "timeLimitMinutes": 60,
                "confirm": true
            })),
            None,
        )
        .await
        .expect("created codes survive");
    let content = serde_json::to_value(&result.content).expect("content");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["vouchers"][0]["code"], "1234567890");
    assert_eq!(output["vouchers"][1]["code"], "2345678901");
    assert_eq!(output["readbackComplete"], true);
    assert!(output.get("readbackStopReason").is_none());
    assert_eq!(output["readbackErrorsInContent"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(output["responseBodyInContent"], true);
    assert!(content.to_string().contains("accepted-voucher-tail"));
    assert!(content.to_string().contains("voucher-0"));
    assert!(content.to_string().contains(&failure));
}

#[tokio::test]
async fn slow_readback_returns_the_creation_response_before_the_tool_deadline() {
    let server = MockServer::start().await;
    mints(&server, &batch(&["1234567890", "2345678901"])).await;
    for (index, code) in ["1234567890", "2345678901"].iter().enumerate() {
        Mock::given(method("GET"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/voucher-{index}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(3))
                    .set_body_json(serde_json::json!({
                        "id": format!("voucher-{index}"), "code": code, "name": "guests",
                        "createdAt": "2026-09-28T00:00:00Z", "expired": false,
                        "authorizedGuestCount": 0, "timeLimitMinutes": 60,
                    })),
            )
            .mount(&server)
            .await;
    }

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests", "count": 2, "timeLimitMinutes": 60, "confirm": true,
            })),
            None,
        )
        .await
        .expect("creation response survives slow verification")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], false, "{output}");
    assert_eq!(output["vouchers"][0]["code"], "1234567890");
    assert_eq!(output["vouchers"][1]["code"], "2345678901");
    assert_eq!(output["readbackComplete"], false);
    assert_eq!(output["readbackStopReason"], "deadline");
}

#[tokio::test]
async fn short_configured_tool_deadline_leaves_time_for_the_creation_response() {
    let server = MockServer::start().await;
    mints(&server, &batch(&["1234567890"])).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/voucher-0"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(serde_json::json!({
                    "id": "voucher-0", "code": "1234567890", "name": "guests",
                    "createdAt": "2026-09-28T00:00:00Z", "expired": false,
                    "authorizedGuestCount": 0, "timeLimitMinutes": 60,
                })),
        )
        .mount(&server)
        .await;
    let handler = handler_for(&server).with_request_limits(32, Duration::from_secs(2));
    let started = tokio::time::Instant::now();
    let request = create(&serde_json::json!({
        "name": "guests", "count": 1, "timeLimitMinutes": 60, "confirm": true,
    }));
    let output = tokio::time::timeout(Duration::from_secs(2), handler.call(&request, None))
        .await
        .expect("outer tool deadline")
        .expect("creation result")
        .structured_content
        .expect("structured");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(output["verified"], false);
    assert_eq!(output["vouchers"][0]["code"], "1234567890");
}

#[tokio::test]
async fn creation_verifies_the_code_from_the_detail_endpoint() {
    let server = MockServer::start().await;
    mints(&server, &batch(&["1234567890"])).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/voucher-0"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "voucher-0", "code": "1234567890", "name": "guests",
            "createdAt": "2026-09-28T00:00:00Z", "expired": false,
            "authorizedGuestCount": 0, "timeLimitMinutes": 60,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests", "count": 1, "timeLimitMinutes": 60, "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], true, "{output}");
}

#[tokio::test]
async fn creation_preserves_the_controller_detail_when_readback_disagrees() {
    let server = MockServer::start().await;
    mints(&server, &batch(&["1234567890"])).await;
    let response = serde_json::json!({
        "id": "voucher-0", "code": "different-code", "name": "guests",
        "createdAt": "2026-09-28T00:00:00Z", "expired": false,
        "authorizedGuestCount": 0, "timeLimitMinutes": 60,
        "controllerDetail": "voucher-readback-tail".repeat(100),
    });
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/voucher-0"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests", "count": 1, "timeLimitMinutes": 60, "confirm": true,
            })),
            None,
        )
        .await
        .expect("created code remains available")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], false);
    assert_eq!(output["vouchers"][0]["code"], "1234567890");
    assert!(
        output["readbackErrors"][0]["error"]
            .as_str()
            .expect("readback error")
            .contains(&response.to_string())
    );
}

#[tokio::test]
async fn duplicate_created_ids_cannot_verify_as_two_persisted_vouchers() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "vouchers": [
                {"id": "v1", "code": "1234567890"},
                {"id": "v1", "code": "1234567890"},
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers/v1"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "v1", "code": "1234567890", "name": "guests",
            "createdAt": "2026-09-28T00:00:00Z", "expired": false,
            "authorizedGuestCount": 0, "timeLimitMinutes": 60,
        })))
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &create(&serde_json::json!({
                "name": "guests", "count": 2, "timeLimitMinutes": 60, "confirm": true,
            })),
            None,
        )
        .await
        .expect("creation response")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], false, "{output}");
    assert_eq!(output["vouchers"].as_array().expect("rows").len(), 2);
}
