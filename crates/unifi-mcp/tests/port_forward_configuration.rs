use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use unifi_api::{ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, TlsMode};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};
use zeroize::Zeroizing;

const PREFIX: &str = "/proxy/network/api/s/default/rest/portforward";

fn handler(server: &MockServer) -> UnifiMcp {
    let base_url = Url::parse(&server.uri()).expect("loopback URL");
    let integration = IntegrationClient::new(&ControllerConfig {
        name: "test".to_owned(),
        base_url: base_url.clone(),
        api_key: Zeroizing::new("fixture-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "test".to_owned(),
        base_url,
        username: "fixture-user".to_owned(),
        password: Zeroizing::new("fixture-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("client");
    UnifiMcp::new(Arc::new(integration), Arc::new(legacy), "test", "default")
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

async fn login(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "TOKEN=fixture-session; Path=/")
                .set_body_json(json!({})),
        )
        .mount(server)
        .await;
}

fn configuration() -> Value {
    json!({"name":"Service","enabled":true,"src":"198.51.100.0/24","fwd":"192.0.2.10",
        "fwd_port":"80-90","dst_port":"8080-8090","proto":"tcp_udp","destination_ip":"203.0.113.2",
        "log":true,"pfwd_interface":"wan2","attr_hidden":true,"attr_hidden_id":"custom",
        "attr_no_delete":false,"attr_no_edit":false,"site_id":"controller-site","_id":"pf-1"})
}

fn envelope(rows: Value) -> Value {
    let mut envelope = json!({"meta":{"rc":"ok","fixtureSecret":"upstream-fixture"},"unknownMetadata":9_007_199_254_740_993_u64});
    envelope["data"] = rows;
    envelope
}

#[tokio::test]
async fn previews_all_documented_fields_and_deletion_without_http() {
    let server = MockServer::start().await;
    let handler = handler(&server);
    for (operation, id, config) in [
        ("create", None, Some(configuration())),
        ("update", Some("pf-1"), Some(configuration())),
        ("delete", Some("pf-1"), None),
    ] {
        let mut input = json!({"operation":operation});
        if let Some(id) = id {
            input["id"] = json!(id);
        }
        if let Some(config) = config.clone() {
            input["configuration"] = config;
        }
        let result = handler
            .call(&call("port_forwards.configure", input), None)
            .await
            .expect("preview");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["submitted"], false);
        assert_eq!(output["requested"], config.unwrap_or(Value::Null));
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
async fn create_and_update_forward_all_fields_and_preserve_full_acceptance_and_observation() {
    for operation in ["create", "update"] {
        let server = MockServer::start().await;
        login(&server).await;
        let accepted = "{ \"meta\":{\"rc\":\"ok\",\"fixtureSecret\":\"issued-fixture\"},\"data\":[{\"_id\":\"pf-1\"}],\"counter\":9007199254740993 }";
        let mut input =
            json!({"operation":operation,"configuration":configuration(),"confirm":true});
        let (verb, route) = if operation == "create" {
            ("POST", PREFIX.to_owned())
        } else {
            input["id"] = json!("pf-1");
            ("PUT", format!("{PREFIX}/pf-1"))
        };
        Mock::given(method(verb))
            .and(path(route))
            .and(body_json(configuration()))
            .respond_with(ResponseTemplate::new(200).set_body_string(accepted))
            .expect(1)
            .mount(&server)
            .await;
        let mut stored = configuration();
        stored["unmodeledCredential"] = json!("stored-fixture");
        let after = envelope(json!([stored]));
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/pf-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&after))
            .expect(1)
            .mount(&server)
            .await;
        let result = handler(&server)
            .call(&call("port_forwards.configure", input), None)
            .await
            .expect("write");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["responseBody"], accepted);
        assert_eq!(output["after"], after);
        assert_eq!(output["verified"], true);
    }
}

#[tokio::test]
async fn deletion_preserves_acceptance_and_observed_empty_envelope_or_404() {
    for missing in [false, true] {
        let server = MockServer::start().await;
        login(&server).await;
        let accepted = "{\"meta\":{\"rc\":\"ok\",\"extra\":\"upstream\"},\"data\":[]}";
        Mock::given(method("DELETE"))
            .and(path(format!("{PREFIX}/pf-1")))
            .respond_with(ResponseTemplate::new(200).set_body_string(accepted))
            .expect(1)
            .mount(&server)
            .await;
        let template = if missing {
            ResponseTemplate::new(404).set_body_string("complete upstream absence")
        } else {
            ResponseTemplate::new(200).set_body_json(envelope(json!([])))
        };
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/pf-1")))
            .respond_with(template)
            .expect(1)
            .mount(&server)
            .await;
        let result = handler(&server)
            .call(
                &call(
                    "port_forwards.configure",
                    json!({"operation":"delete","id":"pf-1","confirm":true}),
                ),
                None,
            )
            .await
            .expect("delete");
        let output = result.structured_content.expect("structured");
        assert_eq!(output["responseBody"], accepted);
        assert_eq!(output["verifiedAbsent"], true);
        if missing {
            assert!(
                output["readbackError"]
                    .as_str()
                    .expect("error")
                    .contains("complete upstream absence")
            );
        } else {
            assert_eq!(output["after"], envelope(json!([])));
        }
    }
}

#[tokio::test]
async fn surviving_rule_and_coerced_fields_do_not_claim_verification() {
    for operation in ["delete", "update"] {
        let server = MockServer::start().await;
        login(&server).await;
        let accepted = envelope(json!([]));
        Mock::given(method(if operation == "delete" {
            "DELETE"
        } else {
            "PUT"
        }))
        .and(path(format!("{PREFIX}/pf-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&accepted))
        .expect(1)
        .mount(&server)
        .await;
        let after = envelope(json!([{"_id":"pf-1","name":"coerced","credential":"fixture"}]));
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}/pf-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&after))
            .mount(&server)
            .await;
        let mut input = json!({"operation":operation,"id":"pf-1","confirm":true});
        if operation == "update" {
            input["configuration"] = json!({"name":"requested"});
        }
        let output = handler(&server)
            .call(&call("port_forwards.configure", input), None)
            .await
            .expect("accepted")
            .structured_content
            .expect("structured");
        assert_eq!(
            output[if operation == "delete" {
                "verifiedAbsent"
            } else {
                "verified"
            }],
            false
        );
        assert_eq!(output["after"], after);
    }
}

#[tokio::test]
async fn oversized_acceptance_and_readback_error_are_complete_in_content() {
    let server = MockServer::start().await;
    login(&server).await;
    let accepted = envelope(json!([{"_id":"pf-1","credential":"x".repeat(60000)}])).to_string();
    let failure = format!("upstream-secret-fixture:{}", "y".repeat(60000));
    Mock::given(method("POST"))
        .and(path(PREFIX))
        .respond_with(ResponseTemplate::new(200).set_body_string(&accepted))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/pf-1")))
        .respond_with(ResponseTemplate::new(503).set_body_string(&failure))
        .mount(&server)
        .await;
    let result = handler(&server)
        .call(
            &call(
                "port_forwards.configure",
                json!({"operation":"create","configuration":{"name":"test"},"confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted");
    let output = result.structured_content.expect("structured");
    assert_eq!(output["submitted"], true);
    assert_eq!(output["responseBodyInContent"], true);
    assert_eq!(output["readbackErrorInContent"], true);
    let content = serde_json::to_value(result.content)
        .expect("content")
        .to_string();
    assert!(content.contains(&"x".repeat(60000)));
    assert!(content.contains(&failure));
}

#[tokio::test]
async fn upstream_http_and_envelope_rejections_are_preserved_without_retry() {
    for status in [200, 422, 429] {
        let server = MockServer::start().await;
        login(&server).await;
        let failure = "{ \"meta\": {\"rc\":\"error\",\"msg\":\"api.err.NotAllowed\",\"credential\":\"fixture\"}, \"data\":[] }";
        Mock::given(method("POST"))
            .and(path(PREFIX))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("retry-after", "0")
                    .set_body_string(failure),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = handler(&server)
            .call(
                &call(
                    "port_forwards.configure",
                    json!({"operation":"create","configuration":{"name":"test"},"confirm":true}),
                ),
                None,
            )
            .await
            .expect_err("upstream rejection");
        assert!(error.message.contains(failure));
    }
}

#[tokio::test]
async fn paged_full_records_and_detail_keep_unknown_fields_and_envelope_metadata() {
    let server = MockServer::start().await;
    login(&server).await;
    let rows = json!([{"_id":"first","credential":"first-fixture"},{"_id":"second","credential":"second-fixture","counter":9_007_199_254_740_993_u64}]);
    Mock::given(method("GET"))
        .and(path(PREFIX))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(rows.clone())))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/second")))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(json!([rows[1]]))))
        .mount(&server)
        .await;
    let handler = handler(&server);
    let first = handler
        .call(&call("port_forwards.list", json!({"limit":1})), None)
        .await
        .expect("page")
        .structured_content
        .expect("structured");
    assert_eq!(first["nextOffset"], 1);
    assert_eq!(first["response"], envelope(json!([rows[0]])));
    let second = handler
        .call(
            &call("port_forwards.list", json!({"offset":1,"limit":1})),
            None,
        )
        .await
        .expect("page")
        .structured_content
        .expect("structured");
    assert_eq!(second["response"], envelope(json!([rows[1]])));
    assert_eq!(second["nextOffset"], Value::Null);
    let beyond = handler
        .call(
            &call("port_forwards.list", json!({"offset":u32::MAX})),
            None,
        )
        .await
        .expect("empty")
        .structured_content
        .expect("structured");
    assert_eq!(beyond["response"]["data"], json!([]));
    let detail = handler
        .call(&call("port_forwards.status", json!({"id":"second"})), None)
        .await
        .expect("detail")
        .structured_content
        .expect("structured");
    assert_eq!(detail["response"], envelope(json!([rows[1]])));
}

#[tokio::test]
async fn oversized_reads_remain_complete_in_content() {
    let server = MockServer::start().await;
    login(&server).await;
    let response = envelope(json!([{"_id":"pf-1","fixtureCredential":"z".repeat(60000)}]));
    for route in [PREFIX.to_owned(), format!("{PREFIX}/pf-1")] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&server)
            .await;
    }
    for (name, input) in [
        ("port_forwards.list", json!({})),
        ("port_forwards.status", json!({"id":"pf-1"})),
    ] {
        let result = handler(&server)
            .call(&call(name, input), None)
            .await
            .expect("large read");
        assert_eq!(
            result.structured_content.expect("structured")["responseInContent"],
            true
        );
        assert!(
            serde_json::to_value(result.content)
                .expect("content")
                .to_string()
                .contains(&"z".repeat(60000))
        );
    }
}

#[tokio::test]
async fn invalid_shapes_and_request_bounds_fail_before_http() {
    let server = MockServer::start().await;
    let handler = handler(&server);
    for input in [
        json!({"operation":"create","configuration":{}}),
        json!({"operation":"create","id":"pf-1","configuration":{"name":"test"}}),
        json!({"operation":"update","configuration":{"name":"test"}}),
        json!({"operation":"delete","id":"pf-1","configuration":{"name":"test"}}),
        json!({"operation":"delete","id":".."}),
        json!({"operation":"create","configuration":{"name":"x".repeat(1_048_577)},"confirm":true}),
        json!({"operation":"create","configuration":{"enabled":"yes"},"confirm":true}),
    ] {
        handler
            .call(&call("port_forwards.configure", input), None)
            .await
            .expect_err("invalid");
    }
    handler
        .call(&call("port_forwards.list", json!({"limit":201})), None)
        .await
        .expect_err("bound");
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn incomplete_detail_preserves_its_body_and_cannot_confirm_absence() {
    let server = MockServer::start().await;
    login(&server).await;
    let incomplete = "{ \"meta\": {\"rc\":\"ok\"}, \"credential\":\"fixture\" }";
    Mock::given(method("GET"))
        .and(path(format!("{PREFIX}/pf-1")))
        .respond_with(ResponseTemplate::new(200).set_body_string(incomplete))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("{PREFIX}/pf-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(json!([]))))
        .expect(1)
        .mount(&server)
        .await;
    let handler = handler(&server);
    let error = handler
        .call(&call("port_forwards.status", json!({"id":"pf-1"})), None)
        .await
        .expect_err("missing data");
    assert!(error.message.contains(incomplete));
    let output = handler
        .call(
            &call(
                "port_forwards.configure",
                json!({"operation":"delete","id":"pf-1","confirm":true}),
            ),
            None,
        )
        .await
        .expect("accepted deletion")
        .structured_content
        .expect("structured");
    assert_eq!(output["submitted"], true);
    assert!(output.get("verifiedAbsent").is_none());
    assert!(
        output["readbackError"]
            .as_str()
            .expect("error")
            .contains(incomplete)
    );
}
