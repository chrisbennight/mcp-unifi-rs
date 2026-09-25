//! Run the log-capture contract in its own process so parallel API tests cannot
//! register the same tracing call site under a different default subscriber.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use tracing::{Subscriber, field::Visit};
use unifi_api::{ApiError, LegacyClient, LegacyConfig, TlsMode, system_log::SystemLogQuery};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl Visit for Capture {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .lock()
            .unwrap()
            .push(format!("{}={value:?}", field.name()));
    }
}

impl Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "unifi_api::legacy::system_log"
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut self.clone());
    }
}

#[tokio::test]
async fn rejected_read_logs_fixed_endpoint_and_status_without_response_or_credentials() {
    let fields = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::set_global_default(Capture(Arc::clone(&fields)))
        .expect("this test process owns its subscriber");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "TOKEN=fixture-session; Path=/")
                .insert_header("X-CSRF-Token", "fixture-csrf")
                .set_body_json(serde_json::json!({})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/proxy/network/v2/api/site/default/system-log/all"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "meta": {"rc": "error", "msg": "api.err.NotFound"},
            "message": "fixture-password fixture-session fixture-csrf PRIVATE_EVENT_TEXT"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = LegacyClient::new(&LegacyConfig {
        name: "test".to_owned(),
        base_url: Url::parse(&server.uri()).expect("loopback URL"),
        username: "fixture-user".to_owned(),
        password: Zeroizing::new("fixture-password".to_owned()),
        tls: TlsMode::SystemRoots,
        timeout: Duration::from_secs(5),
    })
    .expect("client");
    let error = client
        .system_log("default", &SystemLogQuery::new(0, 2000, 1).unwrap())
        .await
        .expect_err("rejection");
    assert!(matches!(error, ApiError::Rejected { .. }));
    let fields = fields.lock().unwrap().join("\n");
    assert!(
        fields.contains("endpoint=\"network.system_log\""),
        "{fields}"
    );
    assert!(fields.contains("status=404"), "{fields}");
    for secret in [
        "fixture-password",
        "fixture-session",
        "fixture-csrf",
        "PRIVATE_EVENT_TEXT",
    ] {
        assert!(!fields.contains(secret));
    }
}
