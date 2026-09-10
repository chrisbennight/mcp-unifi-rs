//! End-to-end tests for voucher creation against loopback fakes.
//!
//! The property that matters most here is unusual: the codes must survive to
//! the caller even when a check fails. They exist on the controller from the
//! moment the request succeeds, and no read reproduces them, so a result that
//! withheld them would be credentials nobody can reach.

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
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "home",
        "default",
        vec![Zeroizing::new(PASSWORD.to_owned())],
    )
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
    assert!(warnings.contains("only copy"), "{output}");
    assert!(warnings.contains("credential"), "{output}");
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
    assert_eq!(output["wellFormed"], true);
    assert_eq!(output["vouchers"].as_array().expect("vouchers").len(), 3);
    assert_eq!(output["vouchers"][0]["code"], "1234567890");
    assert_eq!(output["checks"]["countMatches"], true);
    assert_eq!(output["checks"]["codeLengths"], serde_json::json!([10]));
}

#[tokio::test]
async fn a_batch_that_fails_a_check_still_returns_its_codes() {
    // This is the property the whole design turns on. These vouchers exist on
    // the controller the moment the request succeeded, and nothing can read
    // their codes again. Withholding them because a check failed would create
    // guest access that nobody can use and nobody can find.
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
            "a code with whitespace",
            vec!["1234567890", "2345 78901", "3456789012"],
            "allWellFormed",
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

        assert_eq!(output["wellFormed"], false, "{label}: {output}");
        assert_eq!(output["checks"][failed], false, "{label}: {output}");
        // Every code the controller produced is here, not merely the first:
        // a result that carried one and dropped the rest would strand exactly
        // the credentials this test exists to protect.
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
async fn a_voucher_whose_id_was_redacted_is_not_described_as_recoverable() {
    // The identity check and the recovery advice have to describe the voucher
    // the caller receives. An id the scrub rewrites is not a handle to
    // anything, so reporting it as one would send an operator looking for a
    // voucher that cannot be found by that name.
    let server = MockServer::start().await;
    mount_site(&server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/hotspot/vouchers"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            // The id merely contains the credential rather than being it, so a
            // partial rewrite would leave something that looks like an id and
            // addresses nothing.
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
    assert!(output["vouchers"][0].get("id").is_none(), "{output}");
    assert_eq!(output["checks"]["allIdentified"], false, "{output}");
    assert!(
        output["warnings"]
            .to_string()
            .contains("can be neither used nor found"),
        "{output}"
    );
}

#[tokio::test]
async fn a_batch_far_larger_than_the_response_budget_still_returns_every_code() {
    // The response budget refuses a result the caller can ask for again. This
    // result cannot be asked for again, so it is exempt: neither an error nor
    // a trimmed batch is an acceptable answer once the vouchers exist.
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

    let output = handler_for(&server)
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
        .expect("a result, never an error")
        .structured_content
        .expect("structured");
    let returned: Vec<&str> = output["vouchers"]
        .as_array()
        .expect("vouchers")
        .iter()
        .map(|voucher| voucher["code"].as_str().expect("code"))
        .collect();
    assert_eq!(returned, minted, "every minted code comes back");
    assert_eq!(
        output["checks"]["countMatches"], true,
        "{}",
        output["checks"]
    );
}

#[tokio::test]
async fn a_code_the_credential_scrub_rewrote_is_reported_rather_than_passed_off() {
    // Every result is scrubbed of configured credential material, and a
    // controller-generated code is free to contain any substring. A rewritten
    // code looks exactly like a usable one, so the result has to say it is not.
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
    assert_eq!(output["vouchers"][1]["code"], "[redacted]", "{output}");
    assert_eq!(output["checks"]["allWellFormed"], false, "{output}");
    assert_eq!(output["wellFormed"], false, "{output}");
    let warnings = output["warnings"].to_string();
    assert!(
        warnings.contains("configured credential material"),
        "{output}"
    );
    // The loss has to be recoverable, which is the only reason it is
    // acceptable: the voucher is identified so it can be revoked, and the
    // result says to mint a replacement.
    assert!(warnings.contains("revoke it on the controller"), "{output}");
    assert_eq!(output["vouchers"][1]["id"], "voucher-1", "{output}");
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
            serde_json::json!({"name": "g", "count": 101, "timeLimitMinutes": 60}),
            "count must be between",
        ),
        (
            serde_json::json!({"name": "g", "count": 1, "timeLimitMinutes": 0}),
            "timeLimitMinutes must be between",
        ),
        (
            serde_json::json!({"name": "g", "count": 1, "timeLimitMinutes": 10081}),
            "timeLimitMinutes must be between",
        ),
        (
            serde_json::json!({"name": "   ", "count": 1, "timeLimitMinutes": 60}),
            "name must be 1-",
        ),
        // Unbounded caller text would be reflected into a result that is
        // deliberately exempt from the response budget, which is what makes
        // this bound part of the exemption rather than tidiness.
        (
            serde_json::json!({
                "name": "g".repeat(129),
                "count": 1,
                "timeLimitMinutes": 60,
            }),
            "name must be 1-",
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
async fn the_result_never_claims_the_vouchers_were_read_back() {
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
    // `verified` belongs to the writes that re-read their resource. This one
    // cannot, so it must not borrow the word: `wellFormed` says only that the
    // batch looks usable, which is all that was established.
    assert!(output.get("verified").is_none(), "{output}");
    assert!(output.get("wellFormed").is_some(), "{output}");
}
