use std::{sync::Arc, time::Duration};

use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use unifi_api::{
    ControllerConfig, IntegrationClient, LegacyClient, LegacyConfig, ProtectClient, TlsMode,
};
use unifi_mcp::UnifiMcp;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

const SITE: &str = "9a3f0c62-3d11-4f9d-8b1a-7f4bb0d1c001";
const NETWORK: &str = "f435b097-683e-4bc4-8d3a-453c968a48fb";
const NUMBERS: &str = r#""large":184467440737095516170123,"negative":-184467440737095516170123,"fraction":0.12345678901234567890123456789"#;

fn config(server: &MockServer) -> ControllerConfig {
    ControllerConfig {
        name: "fixture".to_owned(),
        base_url: Url::parse(&server.uri()).expect("loopback URL"),
        api_key: Zeroizing::new("fixture-key".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    }
}

fn network_handler(server: &MockServer) -> UnifiMcp {
    let integration = IntegrationClient::new(&config(server)).expect("integration client");
    let legacy = LegacyClient::new(&LegacyConfig {
        name: "fixture".to_owned(),
        base_url: config(server).base_url,
        username: "fixture-user".to_owned(),
        password: Zeroizing::new("fixture-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("legacy client");
    UnifiMcp::new(
        Arc::new(integration),
        Arc::new(legacy),
        "fixture",
        "default",
    )
}

async fn output(handler: &UnifiMcp, name: &str, arguments: Value) -> Value {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = Some(arguments.as_object().expect("arguments").clone());
    let response = handler.call(&params, None).await.expect("tool response");
    // Exercise wire serialization as well as the in-memory tool result.
    let serialized = serde_json::to_vec(&response).expect("MCP serialization");
    let reparsed: Value = serde_json::from_slice(&serialized).expect("MCP JSON");
    reparsed["structuredContent"].clone()
}

fn assert_numbers(record: &Value) {
    for (field, expected) in [
        ("large", "184467440737095516170123"),
        ("negative", "-184467440737095516170123"),
        ("fraction", "0.12345678901234567890123456789"),
    ] {
        assert_eq!(
            record[field].as_number().expect("number").to_string(),
            expected
        );
    }
}

#[tokio::test]
async fn integration_record_numbers_survive_mcp_serialization() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/sites"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset":0,"limit":100,"count":1,"totalCount":1,
            "data":[{"id":SITE,"name":"Default","internalReference":"default"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/proxy/network/integration/v1/sites/{SITE}/networks/{NETWORK}"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!(r#"{{"id":"{NETWORK}",{NUMBERS}}}"#)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = output(
        &network_handler(&server),
        "networks.status",
        json!({"id":NETWORK}),
    )
    .await;
    assert_numbers(&result["response"]);
}

#[tokio::test]
async fn legacy_envelope_and_record_numbers_survive_mcp_serialization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/portforward/pf-1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"meta":{{"rc":"ok",{NUMBERS}}},"data":[{{"_id":"pf-1",{NUMBERS}}}]}}"#
        )))
        .expect(1)
        .mount(&server)
        .await;
    let result = output(
        &network_handler(&server),
        "port_forwards.status",
        json!({"id":"pf-1"}),
    )
    .await;
    assert_numbers(&result["response"]["meta"]);
    assert_numbers(&result["response"]["data"][0]);
}

#[tokio::test]
async fn protect_record_numbers_survive_mcp_serialization() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/proxy/protect/integration/v1/sensors/sensor-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!(r#"{{"id":"sensor-1",{NUMBERS}}}"#)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let protect = ProtectClient::new(&config(&server)).expect("protect client");
    let handler = UnifiMcp::new_protect("fixture", Arc::new(protect), None);
    let result = output(
        &handler,
        "protect.devices.status",
        json!({"kind":"sensor","deviceId":"sensor-1"}),
    )
    .await;
    assert_numbers(&result["device"]);
}
