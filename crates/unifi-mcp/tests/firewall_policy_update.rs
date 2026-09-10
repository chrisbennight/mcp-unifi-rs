//! End-to-end tests for the zone-based policy write against loopback fakes.
//!
//! The write resends the whole policy, so the assertion that matters most is
//! the request body: every property the read returned must come back
//! untouched, including ones this server does not model.

use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, body_string_contains, method, path},
};
use zeroize::Zeroizing;

const PASSWORD: &str = "test-legacy-password";
const INTEGRATION: &str = "/proxy/network/integration/v1";
const SITE_ID: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const POLICY: &str = "policy-1";

/// One stored policy. `schedule` and `ipsecFilter` are properties this server
/// does not model, standing in for everything a controller keeps beyond the
/// projection — and for the reason the whole record is resent.
fn stored(enabled: bool, action: &str) -> serde_json::Value {
    serde_json::json!({
        "id": POLICY,
        "name": "allow iot to internet",
        "enabled": enabled,
        "action": action,
        "index": 2000,
        "ipProtocolScope": "ALL",
        "loggingEnabled": false,
        "source": {"zoneId": "zone-iot", "port": "any"},
        "destination": {"zoneId": "zone-wan", "port": "any"},
        "schedule": {"mode": "ALWAYS"},
        "ipsecFilter": "NONE",
    })
}

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

fn update(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "firewall.policies.update".to_owned().into();
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
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .mount(server)
        .await;
    // The zone probe answers, which is what makes this a zone-based console.
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 1, "count": 0, "totalCount": 0, "data": [],
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_classic_console_is_refused_by_name_rather_than_by_a_failed_read() {
    // A classic console has no policies, so without this the endpoint's
    // rejection reaches the caller as an unexplained controller failure and
    // "this console has no such policy" cannot be told from "this console has
    // no policies at all".
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/sites")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "offset": 0, "limit": 100, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "name": "Default", "internalReference": "default"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{INTEGRATION}/info")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"applicationVersion": "9.4.19"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/zones"
        )))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "message": "feature requires the zone based firewall"
        })))
        .mount(&server)
        .await;
    // No policy endpoint is mounted: reaching one would fail this test.

    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": false},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect_err("refused");
    assert!(
        error.message.contains("classic firewall"),
        "{}",
        error.message
    );
    assert!(
        error.message.contains("zone-based firewall only"),
        "the refusal must say what this server does support, not name a tool \
         it no longer has: {}",
        error.message
    );
}

/// The policy as it reads before the write, and again after.
async fn reads(server: &MockServer, before: &serde_json::Value, after: &serde_json::Value) {
    mount_site(server).await;
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(before))
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(after))
        .mount(server)
        .await;
}

async fn accepts_the_write(server: &MockServer, expected_body: &serde_json::Value) {
    Mock::given(method("PUT"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}"
        )))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn an_unconfirmed_change_describes_itself_and_writes_nothing() {
    let server = MockServer::start().await;
    let record = stored(true, "ALLOW");
    reads(&server, &record, &record).await;
    // No PUT is mounted: a write would fail this test.

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": false},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["policy"]["sourceZoneId"], "zone-iot");
    // A policy's protocol scope is part of what the toggle governs, and the
    // controller names it `ipProtocolScope`. Reading any other key reports an
    // absent scope for every policy that has one.
    assert_eq!(output["policy"]["ipProtocolScope"], "ALL");
    assert_eq!(
        output["changes"],
        serde_json::json!([{"field": "enabled", "from": true, "to": false}])
    );
}

/// A property whose value no JSON value model represents exactly.
///
/// This integer is larger than `u64::MAX`, so decoding it into
/// `serde_json::Value` stores it as `f64` and writes it back as `1e28`. The
/// policy record therefore has to travel as the bytes the controller sent,
/// not as a parsed value: a number model drops precision for the same reason
/// a struct model drops fields.
const IMPRECISE: &str = "10000000000000000000000000001";

#[tokio::test]
async fn a_property_no_value_model_represents_exactly_is_resent_unchanged() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    let body = |enabled: bool| {
        format!(
            r#"{{"id":"{POLICY}","name":"n","enabled":{enabled},"action":"ALLOW","counter":{IMPRECISE}}}"#
        )
    };
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body(true), "application/json"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body(false), "application/json"))
        .mount(&server)
        .await;
    // Matched against the request text, because comparing parsed bodies would
    // put both sides through the same lossy model and pass either way.
    Mock::given(method("PUT"))
        .and(path(route))
        .and(body_string_contains(format!("\"counter\":{IMPRECISE}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": false},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], true);
}

#[tokio::test]
async fn the_whole_policy_is_resent_with_only_the_switch_altered() {
    let server = MockServer::start().await;
    reads(&server, &stored(true, "ALLOW"), &stored(false, "ALLOW")).await;
    // This is the assertion the design rests on. Every property the read
    // returned must appear in the request exactly as it arrived — including
    // `schedule` and `ipsecFilter`, which this server does not model. A write
    // that dropped either would silently change what the network permits.
    let mut expected = stored(true, "ALLOW");
    expected["enabled"] = serde_json::json!(false);
    accepts_the_write(&server, &expected).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": false},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], true);
    assert_eq!(output["fields"][0]["status"], "persisted");
}

#[tokio::test]
async fn a_switch_the_controller_discarded_is_reported_as_dropped() {
    let server = MockServer::start().await;
    // The controller accepts the replacement and keeps the old value.
    let record = stored(true, "ALLOW");
    reads(&server, &record, &record).await;
    let mut expected = stored(true, "ALLOW");
    expected["enabled"] = serde_json::json!(false);
    accepts_the_write(&server, &expected).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": false},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["verified"], false);
    assert_eq!(output["fields"][0]["status"], "dropped");
}

#[tokio::test]
async fn a_property_the_controller_moved_on_its_own_is_named() {
    let server = MockServer::start().await;
    let mut after = stored(false, "ALLOW");
    // The request sent `schedule` back untouched, so a difference here is the
    // controller's doing rather than this write dropping something.
    after["schedule"] = serde_json::json!({"mode": "EVERY_DAY"});
    reads(&server, &stored(true, "ALLOW"), &after).await;
    let mut expected = stored(true, "ALLOW");
    expected["enabled"] = serde_json::json!(false);
    accepts_the_write(&server, &expected).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": false},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("applied")
        .structured_content
        .expect("structured");
    assert_eq!(output["unexpectedChanges"], serde_json::json!(["schedule"]));
    assert_eq!(output["verified"], false);
}

#[tokio::test]
async fn the_preview_says_which_direction_the_change_moves_traffic() {
    for (action, enabled, expected) in [
        ("ALLOW", false, "withdraws this policy's allowance"),
        (
            "ALLOW",
            true,
            "unless an earlier policy blocks that traffic first",
        ),
        ("BLOCK", false, "stops this policy from blocking"),
        (
            "REJECT",
            true,
            "unless an earlier policy allows that traffic first",
        ),
    ] {
        let server = MockServer::start().await;
        let record = stored(!enabled, action);
        reads(&server, &record, &record).await;

        let output = handler_for(&server)
            .call(
                &update(&serde_json::json!({
                    "policy": POLICY,
                    "changes": {"enabled": enabled},
                })),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{action}/{enabled}: {error}"))
            .structured_content
            .expect("structured");
        let warnings = output["warnings"].to_string();
        assert!(warnings.contains(expected), "{action}/{enabled}: {output}");
        // Resending the whole policy overwrites a concurrent edit, and an
        // operator confirming this should be told so.
        assert!(
            warnings.contains("is overwritten"),
            "{action}/{enabled}: {output}"
        );
    }
}

#[tokio::test]
async fn an_action_this_server_does_not_recognize_states_no_direction() {
    let server = MockServer::start().await;
    let mut record = stored(true, "ALLOW");
    record["action"] = serde_json::json!("MIRROR");
    reads(&server, &record, &record).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": false},
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    let warnings = output["warnings"].to_string();
    assert!(warnings.contains("could not be stated"), "{output}");
    assert!(!warnings.contains("this policy "), "{output}");
}

#[tokio::test]
async fn confirming_a_change_the_policy_already_holds_sends_nothing() {
    let server = MockServer::start().await;
    let record = stored(true, "ALLOW");
    reads(&server, &record, &record).await;
    // No PUT is mounted. A resend here could not change the switch and could
    // overwrite an edit made since the read, so it must not happen at all —
    // and this is the case where an operator sees least reason to expect one.

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"enabled": true},
                "confirm": true,
            })),
            None,
        )
        .await
        .expect("no-op")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["changes"], serde_json::json!([]));
    assert!(
        output["warnings"]
            .to_string()
            .contains("already holds that value"),
        "{output}"
    );
}

#[tokio::test]
async fn every_write_that_happens_says_the_whole_policy_is_resent() {
    // The disclosure belongs to how this tool writes, not to which direction
    // the switch moves, so it must appear on every preview that precedes a
    // write.
    for (action, enabled) in [
        ("ALLOW", false),
        ("ALLOW", true),
        ("BLOCK", false),
        ("BLOCK", true),
        ("MIRROR", false),
    ] {
        let server = MockServer::start().await;
        let record = stored(!enabled, action);
        reads(&server, &record, &record).await;

        let output = handler_for(&server)
            .call(
                &update(&serde_json::json!({
                    "policy": POLICY,
                    "changes": {"enabled": enabled},
                })),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{action}/{enabled}: {error}"))
            .structured_content
            .expect("structured");
        assert!(
            output["warnings"].to_string().contains("is overwritten"),
            "{action}/{enabled}: {output}"
        );
    }
}

#[tokio::test]
async fn a_request_that_changes_nothing_is_refused_before_any_controller_call() {
    let server = MockServer::start().await;
    // Nothing is mounted: both refusals are decided from the request alone.
    let handler = handler_for(&server);

    let empty = handler
        .call(
            &update(&serde_json::json!({"policy": POLICY, "changes": {}})),
            None,
        )
        .await
        .expect_err("no field");
    assert!(
        empty.message.contains("names no field to change"),
        "{}",
        empty.message
    );

    let unknown = handler
        .call(
            &update(&serde_json::json!({
                "policy": POLICY,
                "changes": {"action": "BLOCK"},
            })),
            None,
        )
        .await
        .expect_err("unknown field");
    // What a policy matches is not settable here, and the rejection says what
    // is rather than leaving a caller to guess.
    assert!(
        unknown.message.contains("action") && unknown.message.contains("enabled"),
        "{}",
        unknown.message
    );
}
