//! Real TLS handshakes for the upgraded Protect subscription connection.

use futures_util::SinkExt;
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{Request, Response},
    },
};
use unifi_api::{
    ApiError, ControllerConfig, ProtectClient, TlsMode,
    protect::{ProtectSubscriptionEnd, ProtectSubscriptionMessage, ProtectSubscriptionSource},
};
use url::Url;
use zeroize::Zeroizing;

#[tokio::test]
#[expect(
    clippy::result_large_err,
    reason = "the WebSocket library fixes the callback error response type"
)]
async fn subscriptions_use_the_configured_certificate_roots_and_pins() {
    for mode in [
        "customCa",
        "pinned",
        "wrongPin",
        "systemRoots",
        "acceptInvalid",
    ] {
        let hostname = if mode == "customCa" {
            "127.0.0.1"
        } else {
            "fixture.invalid"
        };
        let certificate = rcgen::generate_simple_self_signed(vec![hostname.to_owned()])
            .expect("ephemeral certificate");
        let der = certificate.cert.der().clone();
        let fingerprint: [u8; 32] = Sha256::digest(der.as_ref()).into();
        let tls = match mode {
            "customCa" => TlsMode::CustomCa(certificate.cert.pem().into_bytes()),
            "pinned" => TlsMode::Pinned(vec![fingerprint]),
            "wrongPin" => {
                let mut other = fingerprint;
                other[0] ^= 1;
                TlsMode::Pinned(vec![other])
            }
            "systemRoots" => TlsMode::SystemRoots,
            "acceptInvalid" => TlsMode::AcceptInvalid,
            _ => unreachable!("fixture modes"),
        };
        let server = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS protocol")
        .with_no_client_auth()
        .with_single_cert(
            vec![der],
            PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into(),
        )
        .expect("certificate");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let base_url = Url::parse(&format!(
            "https://{}",
            listener.local_addr().expect("address")
        ))
        .expect("URL");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("connection");
            let Ok(tls) = TlsAcceptor::from(Arc::new(server)).accept(stream).await else {
                return false;
            };
            let mut socket = accept_hdr_async(tls, |request: &Request, response: Response| {
                assert_eq!(
                    request.uri().path(),
                    "/proxy/protect/integration/v1/subscribe/events"
                );
                assert_eq!(request.headers()["X-API-Key"], "fixture-key");
                Ok(response)
            })
            .await
            .expect("upgrade");
            socket
                .send(Message::Text("complete TLS event".into()))
                .await
                .expect("event");
            true
        });
        let client = ProtectClient::new(&ControllerConfig {
            name: "fixture".to_owned(),
            base_url,
            api_key: Zeroizing::new("fixture-key".to_owned()),
            tls,
            timeout: Duration::from_secs(2),
        })
        .expect("client");
        let result = client
            .observe_updates(
                ProtectSubscriptionSource::Events,
                Duration::from_secs(2),
                1,
                1024,
            )
            .await;
        let accepted = matches!(mode, "customCa" | "pinned" | "acceptInvalid");
        if accepted {
            let batch = result.expect("trusted TLS subscription");
            assert_eq!(batch.end, ProtectSubscriptionEnd::MessageLimit);
            assert_eq!(
                batch.messages,
                vec![ProtectSubscriptionMessage::Text(
                    "complete TLS event".to_owned()
                )]
            );
        } else {
            assert!(matches!(result, Err(ApiError::Transport(_))), "{result:?}");
        }
        assert_eq!(task.await.expect("TLS fixture"), accepted);
    }
}
