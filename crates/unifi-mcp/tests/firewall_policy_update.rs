//! End-to-end tests for the zone-based policy write against loopback fakes.
//!
//! An enable change resends the whole policy, preserving unrequested fields.
//! A logging change uses the documented partial update without a full resend.

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
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "home", "default")
}

fn update(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "firewall.policies.update".to_owned().into();
    params.arguments = Some(arguments.as_object().expect("object").clone());
    params
}

fn delete(arguments: &serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = "firewall.policies.delete".to_owned().into();
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
    let delete_error = handler_for(&server)
        .call(
            &delete(&serde_json::json!({"policy": POLICY, "confirm": true})),
            None,
        )
        .await
        .expect_err("classic firewall cannot delete a zone policy");
    assert!(delete_error.message.contains("classic firewall"));
}

#[tokio::test]
async fn policy_delete_rejects_an_empty_id_before_controller_io() {
    let server = MockServer::start().await;
    for id in [" ", ".", ".."] {
        let error = handler_for(&server)
            .call(
                &delete(&serde_json::json!({"policy": id, "confirm": true})),
                None,
            )
            .await
            .expect_err("invalid id");
        assert!(error.message.contains("non-dot id"), "{}", error.message);
    }
}

#[tokio::test]
async fn policy_delete_preserves_a_mismatched_controller_record() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let mut response = stored(true, "BLOCK");
    response["id"] = serde_json::json!("another-policy");
    response["controllerDetail"] = serde_json::json!("policy-identity-tail".repeat(100));
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let error = handler_for(&server)
        .call(&delete(&serde_json::json!({"policy": POLICY})), None)
        .await
        .expect_err("wrong policy id");
    assert!(error.message.contains("different firewall policy"));
    assert!(error.message.contains(&response.to_string()));
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
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            output["beforeResponse"].as_str().expect("response")
        )
        .expect("controller JSON"),
        record
    );
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

#[tokio::test]
async fn policy_update_does_not_write_a_record_for_another_id() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let mut response = stored(true, "BLOCK");
    response["id"] = serde_json::json!("another-policy");
    response["controllerDetail"] = serde_json::json!("wrong-policy-before-write".repeat(100));
    Mock::given(method("GET"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let error = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY, "changes": {"enabled": false}, "confirm": true
            })),
            None,
        )
        .await
        .expect_err("wrong policy record");
    assert!(error.message.contains(&response.to_string()));
    assert!(error.message.contains("different firewall policy"));
}

#[tokio::test]
async fn policy_update_keeps_a_wrong_id_readback_after_the_write() {
    let server = MockServer::start().await;
    let before = stored(true, "BLOCK");
    let mut after = stored(false, "BLOCK");
    after["id"] = serde_json::json!("another-policy");
    after["controllerDetail"] = serde_json::json!("wrong-policy-after-write".repeat(100));
    reads(&server, &before, &after).await;
    let mut expected = before.clone();
    expected["enabled"] = serde_json::json!(false);
    accepts_the_write(&server, &expected).await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY, "changes": {"enabled": false}, "confirm": true
            })),
            None,
        )
        .await
        .expect("write was accepted")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(output["responseBody"], "{}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            output["afterResponse"].as_str().expect("response")
        )
        .expect("controller JSON"),
        after
    );
    assert!(output.get("verified").is_none());
    assert_eq!(output["policy"]["id"], POLICY);
    assert!(
        output["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&after.to_string())
    );
}

#[tokio::test]
async fn policy_update_retains_a_large_wrong_id_readback_after_an_accepted_write() {
    let server = MockServer::start().await;
    let mut before = stored(true, "BLOCK");
    before["name"] = serde_json::json!("large-policy-name".repeat(4_000));
    let mut after = stored(false, "BLOCK");
    after["id"] = serde_json::json!("another-policy");
    after["controllerDetail"] = serde_json::json!("large-readback".repeat(4_000));
    reads(&server, &before, &after).await;
    let mut expected = before.clone();
    expected["enabled"] = serde_json::json!(false);
    accepts_the_write(&server, &expected).await;

    let result = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY, "changes": {"enabled": false}, "confirm": true
            })),
            None,
        )
        .await
        .expect("accepted write must retain its result");
    let output = result.structured_content.expect("structured result");
    assert_eq!(output["applied"], true);
    assert_eq!(output["readbackErrorInContent"], true);
    assert!(output.get("verified").is_none());
    assert!(result.content.iter().any(|item| {
        matches!(item, rmcp::model::ContentBlock::Text(text) if text.text.contains(&after.to_string()))
    }));
}

#[tokio::test]
async fn accepted_policy_update_survives_a_failed_readback() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let before = stored(true, "BLOCK");
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(&before))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("specific controller readback failure"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut expected = before.clone();
    expected["enabled"] = serde_json::json!(false);
    Mock::given(method("PUT"))
        .and(path(&route))
        .and(body_json(expected))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("controller accepted the full policy"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy": POLICY, "changes": {"enabled": false}, "confirm": true
            })),
            None,
        )
        .await
        .expect("accepted write remains available")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(
        output["responseBody"],
        "controller accepted the full policy"
    );
    assert!(
        output["readbackError"]
            .as_str()
            .expect("error")
            .contains("specific controller readback failure")
    );
    assert!(output.get("verified").is_none());
}

#[tokio::test]
async fn accepted_policy_update_survives_a_stalled_readback() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let before = stored(true, "BLOCK");
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(&before))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(stored(false, "BLOCK"))
                .set_delay(Duration::from_secs(6)),
        )
        .mount(&server)
        .await;
    let mut expected = before;
    expected["enabled"] = serde_json::json!(false);
    Mock::given(method("PUT"))
        .and(path(&route))
        .and(body_json(expected))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("controller accepted before readback stalled"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let handler = handler_for(&server).with_request_limits(1, Duration::from_secs(2));
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        handler.call(
            &update(&serde_json::json!({
                "policy": POLICY, "changes": {"enabled": false}, "confirm": true
            })),
            None,
        ),
    )
    .await
    .expect("completed before the outer deadline")
    .expect("accepted write returned before the outer deadline")
    .structured_content
    .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(
        output["responseBody"],
        "controller accepted before readback stalled"
    );
    assert_eq!(output["readbackError"], "policy readback timed out");
}

#[tokio::test]
async fn policy_delete_previews_scope_without_sending_delete() {
    let server = MockServer::start().await;
    let mut record = stored(true, "BLOCK");
    record["index"] = serde_json::json!(-10);
    record["ipProtocolScope"] = serde_json::json!({
        "ipVersion": "IPV4", "protocolFilter": {"type": "PRESET", "name": "TCP_UDP"}
    });
    record["connectionStateFilter"] = serde_json::json!(["NEW", "RELATED"]);
    record["source"]["networkFilter"] =
        serde_json::json!({"type": "NETWORKS", "networkIds": ["network-1"]});
    reads(&server, &record, &record).await;
    let output = handler_for(&server)
        .call(&delete(&serde_json::json!({"policy": POLICY})), None)
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert_eq!(output["policy"]["sourceZoneId"], "zone-iot");
    assert_eq!(output["policy"]["index"], -10);
    assert!(
        !output["preview"]["omittedFields"]
            .as_array()
            .expect("omitted fields")
            .contains(&serde_json::json!("index"))
    );
    assert_eq!(output["preview"]["details"]["schedule"], record["schedule"]);
    assert_eq!(
        output["preview"]["details"]["ipsecFilter"],
        record["ipsecFilter"]
    );
    assert_eq!(output["preview"]["details"]["source"], record["source"]);
    assert_eq!(
        output["preview"]["details"]["destination"],
        record["destination"]
    );
    assert_eq!(
        output["preview"]["details"]["ipProtocolScope"],
        record["ipProtocolScope"]
    );
    assert_eq!(
        output["preview"]["details"]["connectionStateFilter"],
        record["connectionStateFilter"]
    );
    assert_eq!(output["preview"]["complete"], true);
}

#[tokio::test]
async fn policy_delete_sends_once_and_verifies_absence() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(true, "BLOCK")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(404).set_body_string("policy no longer exists"))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_string("controller deletion accepted"))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &delete(&serde_json::json!({"policy": POLICY, "confirm": true})),
            None,
        )
        .await
        .expect("delete")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseStatus"], 200);
    assert_eq!(output["responseBody"], "controller deletion accepted");
    assert_eq!(output["verifiedAbsent"], true);
    assert_eq!(
        output["readbackError"],
        "controller returned HTTP 404: policy no longer exists"
    );
}

#[tokio::test]
async fn policy_delete_returns_failed_readback_response() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    let failure = format!(
        "policy lookup failed: {}policy-readback-tail",
        "x".repeat(700)
    );
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(true, "BLOCK")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(503).set_body_string(failure.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &delete(&serde_json::json!({"policy": POLICY, "confirm": true})),
            None,
        )
        .await
        .expect("delete was accepted")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert!(output.get("verifiedAbsent").is_none());
    assert_eq!(
        output["readbackError"],
        format!("controller returned HTTP 503: {failure}")
    );
}

#[tokio::test]
async fn policy_delete_keeps_large_preview_and_confirmed_result_returnable() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let mut record = stored(true, "BLOCK");
    record["name"] = serde_json::json!("n".repeat(60_000));
    record["source"]["networkFilter"] = serde_json::json!({"networkIds": ["n".repeat(60_000)]});
    record["description"] = serde_json::json!("d".repeat(60_000));
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(&record))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let handler = handler_for(&server);
    let preview_result = handler
        .call(&delete(&serde_json::json!({"policy": POLICY})), None)
        .await
        .expect("bounded preview");
    let preview = preview_result.structured_content.expect("structured");
    assert_eq!(preview["preview"]["complete"], false);
    assert!(
        preview["preview"]["omittedFields"]
            .to_string()
            .contains("source")
    );
    assert!(
        preview["preview"]["omittedFields"]
            .to_string()
            .contains("description")
    );
    assert!(
        preview["policy"]["name"]
            .as_str()
            .expect("name")
            .ends_with('…')
    );
    assert_eq!(preview["beforeResponseInContent"], true);
    assert!(preview_result.content.iter().any(|item| {
        matches!(item, rmcp::model::ContentBlock::Text(text) if text.text.contains(&record.to_string()))
    }));

    let result = handler
        .call(
            &delete(&serde_json::json!({"policy": POLICY, "confirm": true})),
            None,
        )
        .await
        .expect("bounded confirmed result")
        .structured_content
        .expect("structured");
    assert_eq!(result["applied"], true);
    assert_eq!(result["verifiedAbsent"], true);
    assert_eq!(result["beforeResponseInContent"], true);
}

#[tokio::test]
async fn policy_delete_preserves_controller_detail_keys_and_values() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let mut record = stored(true, "BLOCK");
    record["source"]
        .as_object_mut()
        .expect("source object")
        .insert(PASSWORD.to_owned(), serde_json::json!("controller-value"));
    record["metadata"] = serde_json::json!({"nested": [{}]});
    record["metadata"]["nested"][0]
        .as_object_mut()
        .expect("nested metadata object")
        .insert(PASSWORD.to_owned(), serde_json::json!("controller-value"));
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(&record))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let handler = handler_for(&server);
    for confirm in [false, true] {
        let output = handler
            .call(
                &delete(&serde_json::json!({"policy": POLICY, "confirm": confirm})),
                None,
            )
            .await
            .expect("controller detail preserved")
            .structured_content
            .expect("structured");
        assert_eq!(output["preview"]["details"]["source"], record["source"]);
        assert_eq!(output["preview"]["details"]["metadata"], record["metadata"]);
        assert_eq!(output["preview"]["complete"], true);
        assert_eq!(output["applied"], confirm);
    }
}

#[tokio::test]
async fn policy_delete_reports_an_acknowledged_but_retained_policy() {
    let server = MockServer::start().await;
    let mut record = stored(true, "BLOCK");
    record["controllerDetail"] = serde_json::json!("retained-policy-tail".repeat(100));
    reads(&server, &record, &record).await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}"
        )))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let output = handler_for(&server)
        .call(
            &delete(&serde_json::json!({"policy": POLICY, "confirm": true})),
            None,
        )
        .await
        .expect("delete")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verifiedAbsent"], false);
    assert!(
        output["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&record.to_string())
    );
}

#[tokio::test]
async fn policy_delete_does_not_claim_absence_from_a_wrong_id_readback() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(true, "BLOCK")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let mut response = stored(true, "BLOCK");
    response["id"] = serde_json::json!("another-policy");
    response["controllerDetail"] = serde_json::json!("wrong-policy-readback-tail".repeat(100));
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let output = handler_for(&server)
        .call(
            &delete(&serde_json::json!({"policy": POLICY, "confirm": true})),
            None,
        )
        .await
        .expect("delete accepted")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert!(output.get("verifiedAbsent").is_none());
    assert!(
        output["readbackError"]
            .as_str()
            .expect("readback error")
            .contains(&response.to_string())
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
async fn every_enable_write_says_the_whole_policy_is_resent() {
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
async fn current_policy_shapes_preview_and_round_trip_without_losing_nested_fields() {
    let server = MockServer::start().await;
    let mut before = stored(true, "ALLOW");
    before["action"] = serde_json::json!({"type":"ALLOW","allowReturnTraffic":true});
    before["ipProtocolScope"] = serde_json::json!({"ipVersion":"IPV4_AND_IPV6","protocolFilter":{
        "type":"NAMED_PROTOCOL","matchOpposite":false,"protocol":{"name":"tcp"}
    }});
    before["index"] = serde_json::json!(-10);
    let mut after = before.clone();
    after["enabled"] = serde_json::json!(false);
    reads(&server, &before, &after).await;
    accepts_the_write(&server, &after).await;
    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy":POLICY,"changes":{"enabled":false},"confirm":true
            })),
            None,
        )
        .await
        .expect("replacement")
        .structured_content
        .expect("structured");
    assert_eq!(output["policy"]["action"], "ALLOW");
    assert_eq!(output["policy"]["ipProtocolScope"], "IPV4_AND_IPV6");
    assert_eq!(output["policy"]["index"], -10);
    assert_eq!(output["verified"], true);
    assert!(
        output["warnings"]
            .to_string()
            .contains("withdraws this policy")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            output["beforeResponse"].as_str().expect("before")
        )
        .expect("JSON"),
        before
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(output["afterResponse"].as_str().expect("after"))
            .expect("JSON"),
        after
    );
}

#[tokio::test]
async fn logging_preview_reports_the_flag_without_sending_a_patch() {
    let server = MockServer::start().await;
    let before = stored(true, "ALLOW");
    reads(&server, &before, &before).await;
    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy":POLICY,"changes":{"loggingEnabled":true}
            })),
            None,
        )
        .await
        .expect("preview")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], false);
    assert!(output["changes"].to_string().contains("loggingEnabled"));
    assert!(!output["warnings"].to_string().contains("whole policy"));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .all(|request| request.method == "GET")
    );
}

#[tokio::test]
async fn logging_changes_use_patch_and_keep_complete_accepted_and_observed_records() {
    for include_unchanged_enabled in [false, true] {
        let server = MockServer::start().await;
        let mut before = stored(true, "ALLOW");
        before["controllerExtension"] = serde_json::json!({"credential":"fixture-value"});
        let mut after = before.clone();
        after["loggingEnabled"] = serde_json::json!(true);
        reads(&server, &before, &after).await;
        Mock::given(method("PATCH"))
            .and(path(format!(
                "{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}"
            )))
            .and(body_json(serde_json::json!({"loggingEnabled":true})))
            .respond_with(ResponseTemplate::new(200).set_body_json(&after))
            .expect(1)
            .mount(&server)
            .await;
        let mut changes = serde_json::json!({"loggingEnabled":true});
        if include_unchanged_enabled {
            changes["enabled"] = serde_json::json!(true);
        }
        let output = handler_for(&server)
            .call(
                &update(&serde_json::json!({
                    "policy":POLICY,"changes":changes,"confirm":true
                })),
                None,
            )
            .await
            .expect("patch")
            .structured_content
            .expect("structured");
        assert_eq!(output["applied"], true);
        assert_eq!(output["verified"], true);
        assert_eq!(output["responseStatus"], 200);
        assert_eq!(output["policy"]["loggingEnabled"], true);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                output["responseBody"].as_str().expect("body")
            )
            .expect("JSON"),
            after
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                output["afterResponse"].as_str().expect("after")
            )
            .expect("JSON"),
            after
        );
        assert!(
            !server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .any(|request| request.method == "PUT")
        );
    }
}

#[tokio::test]
async fn changing_enabled_and_logging_uses_one_full_replacement_preserving_other_fields() {
    let server = MockServer::start().await;
    let mut before = stored(true, "ALLOW");
    before["extension"] = serde_json::json!({"counter":9_007_199_254_740_993_u64});
    let mut after = before.clone();
    after["enabled"] = serde_json::json!(false);
    after["loggingEnabled"] = serde_json::json!(true);
    reads(&server, &before, &after).await;
    accepts_the_write(&server, &after).await;
    let output = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy":POLICY,"changes":{"enabled":false,"loggingEnabled":true},"confirm":true
            })),
            None,
        )
        .await
        .expect("replace")
        .structured_content
        .expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["verified"], true);
    assert_eq!(output["fields"].as_array().expect("fields").len(), 2);
    assert!(
        !server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .any(|request| request.method == "PATCH")
    );
}

#[tokio::test]
async fn logging_acceptance_survives_failed_readback_and_upstream_rejection_stays_complete() {
    let server = MockServer::start().await;
    mount_site(&server).await;
    let route = format!("{INTEGRATION}/sites/{SITE_ID}/firewall/policies/{POLICY}");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored(true, "ALLOW")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("logging readback controller detail"),
        )
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(&route))
        .and(body_json(serde_json::json!({"loggingEnabled":true})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!("{}logging-acceptance-tail", "x".repeat(50_000))),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = handler_for(&server)
        .call(
            &update(&serde_json::json!({
                "policy":POLICY,"changes":{"loggingEnabled":true},"confirm":true
            })),
            None,
        )
        .await
        .expect("accepted");
    let content = serde_json::to_value(result.content)
        .expect("content")
        .to_string();
    let output = result.structured_content.expect("structured");
    assert_eq!(output["applied"], true);
    assert_eq!(output["responseBodyInContent"], true);
    assert!(content.contains("logging-acceptance-tail"));
    assert!(
        output["readbackError"]
            .as_str()
            .expect("error")
            .contains("logging readback controller detail")
    );
    let rejected_server = MockServer::start().await;
    let before = stored(true, "ALLOW");
    reads(&rejected_server, &before, &before).await;
    Mock::given(method("PATCH"))
        .and(path(&route))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_string("upstream logging rejection with controller detail"),
        )
        .expect(1)
        .mount(&rejected_server)
        .await;
    let error = handler_for(&rejected_server)
        .call(
            &update(&serde_json::json!({
                "policy":POLICY,"changes":{"loggingEnabled":true},"confirm":true
            })),
            None,
        )
        .await
        .expect_err("rejected");
    assert!(
        error
            .message
            .contains("upstream logging rejection with controller detail")
    );
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
    // The enable shortcut rejects full policy fields; creation and replacement
    // have their own typed request schema.
    assert!(
        unknown.message.contains("action") && unknown.message.contains("enabled"),
        "{}",
        unknown.message
    );
}
