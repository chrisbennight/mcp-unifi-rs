//! Exercise controller certificate policies through a real TLS 1.3 connection.

use std::{sync::Arc, time::Duration};

use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use unifi_api::{ApiError, ControllerConfig, IntegrationClient, TlsMode};
use url::Url;
use zeroize::Zeroizing;

struct TlsFixture {
    base: Url,
    pem: Vec<u8>,
    fingerprint: [u8; 32],
    task: tokio::task::JoinHandle<bool>,
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsFixture {
    async fn start(certificate_name: &str) -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec![certificate_name.to_owned()])
            .expect("ephemeral certificate");
        let pem = certificate.cert.pem().into_bytes();
        let der = certificate.cert.der().clone();
        let fingerprint = Sha256::digest(der.as_ref()).into();
        let key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 configuration")
        .with_no_client_auth()
        .with_single_cert(vec![der], key.into())
        .expect("server certificate");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
        let base = Url::parse(&format!(
            "https://{}",
            listener.local_addr().expect("address")
        ))
        .expect("loopback URL");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let Ok(tls) = TlsAcceptor::from(Arc::new(config)).accept(stream).await else {
                return false;
            };
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let mut io = BufReader::new(tls);
            let mut request = String::new();
            io.read_line(&mut request).await.expect("request line");
            assert_eq!(
                request,
                "GET /proxy/network/integration/v1/info HTTP/1.1\r\n"
            );
            let mut authenticated = false;
            let mut header_end = false;
            for _ in 0..32 {
                let mut line = String::new();
                assert!(io.read_line(&mut line).await.expect("header") > 0);
                if line == "\r\n" {
                    header_end = true;
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("x-api-key")
                {
                    assert_eq!(value.trim(), "isolated-api-key");
                    authenticated = true;
                }
            }
            assert!(header_end && authenticated);
            let body = r#"{"applicationVersion":"9.4.19"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            io.get_mut()
                .write_all(response.as_bytes())
                .await
                .expect("response");
            io.get_mut().shutdown().await.expect("TLS shutdown");
            true
        });
        Self {
            base,
            pem,
            fingerprint,
            task,
        }
    }

    fn client(&self, tls: TlsMode) -> IntegrationClient {
        IntegrationClient::new(&ControllerConfig {
            name: "isolated".to_owned(),
            base_url: self.base.clone(),
            api_key: Zeroizing::new("isolated-api-key".to_owned()),
            tls,
            timeout: Duration::from_secs(3),
        })
        .expect("controller client")
    }

    async fn assert_request(&mut self, tls: TlsMode, succeeds: bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let result = self.client(tls).info().await;
            if succeeds {
                assert_eq!(
                    result.expect("verified HTTPS request").application_version,
                    "9.4.19"
                );
            } else {
                assert!(
                    matches!(result, Err(ApiError::Transport(_))),
                    "TLS rejection must be a transport failure"
                );
            }
            assert_eq!((&mut self.task).await.expect("TLS fixture task"), succeeds);
        })
        .await
        .expect("bounded TLS exchange");
    }
}

#[tokio::test]
async fn custom_ca_trusts_a_matching_controller_certificate() {
    let mut fixture = TlsFixture::start("127.0.0.1").await;
    fixture
        .assert_request(TlsMode::CustomCa(fixture.pem.clone()), true)
        .await;
}

#[tokio::test]
async fn custom_ca_still_rejects_a_certificate_for_another_host() {
    let mut fixture = TlsFixture::start("console.invalid").await;
    fixture
        .assert_request(TlsMode::CustomCa(fixture.pem.clone()), false)
        .await;
}

#[tokio::test]
async fn pinned_certificate_authenticates_even_when_its_name_differs() {
    let mut fixture = TlsFixture::start("console.invalid").await;
    fixture
        .assert_request(TlsMode::Pinned(vec![fixture.fingerprint]), true)
        .await;
}

#[tokio::test]
async fn pinned_certificate_rejects_an_unlisted_fingerprint() {
    let mut fixture = TlsFixture::start("console.invalid").await;
    let mut other = fixture.fingerprint;
    other[0] ^= 1;
    fixture
        .assert_request(TlsMode::Pinned(vec![other]), false)
        .await;
}
