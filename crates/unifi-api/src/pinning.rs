//! Certificate pinning for consoles that cannot be validated by name.
//!
//! A `UniFi` console ships a self-signed certificate naming `unifi.local` and
//! loopback, and answers on a LAN address that appears nowhere in it. Trusting
//! that certificate as a root still fails, because the address being dialed is
//! not one the certificate covers. The remaining honest options are to disable
//! validation entirely, or to make the certificate itself the identity.
//!
//! This is the second. The server accepts exactly the certificates whose
//! SHA-256 digest an operator listed, and nothing else — not a certificate
//! signed by the same console, and not one a public authority vouches for.
//! Chain building and name matching are deliberately skipped: they answer
//! "does someone trustworthy say this host is who it claims", and the pin
//! answers the stronger question "is this the exact certificate I was told to
//! expect".
//!
//! What it costs: a console that legitimately regenerates its certificate
//! stops being reachable until its new digest is listed. That is why the pin
//! is a set rather than one value — the next digest can be added before the
//! change and the old one removed after.

use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The SHA-256 digest of a certificate in its DER encoding, which is the value
/// `openssl x509 -fingerprint -sha256` prints and what a console's own
/// interface displays.
pub type CertificateFingerprint = [u8; 32];

/// Accepts a server certificate only when its digest is one of the pinned set.
#[derive(Debug)]
pub(crate) struct PinnedCertificates {
    pins: Vec<CertificateFingerprint>,
    provider: Arc<CryptoProvider>,
}

impl PinnedCertificates {
    pub(crate) fn new(pins: Vec<CertificateFingerprint>, provider: Arc<CryptoProvider>) -> Self {
        Self { pins, provider }
    }

    /// Whether this digest is pinned, compared without an early exit so the
    /// comparison does not report how much of a digest matched.
    fn is_pinned(&self, digest: &CertificateFingerprint) -> bool {
        self.pins
            .iter()
            .fold(subtle::Choice::from(0u8), |seen, pin| {
                seen | pin.ct_eq(digest)
            })
            .into()
    }
}

impl ServerCertVerifier for PinnedCertificates {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Only the certificate the console presented is considered. An
        // intermediate cannot vouch for an unpinned leaf, and the name being
        // dialed is not consulted, because the pin already fixes the identity
        // more tightly than a name would.
        let digest: CertificateFingerprint = Sha256::digest(end_entity.as_ref()).into();
        if self.is_pinned(&digest) {
            return Ok(ServerCertVerified::assertion());
        }
        // The message names neither digest. An operator comparing them needs
        // the console's own display or `openssl`, and echoing the presented
        // one here would put an attacker-chosen value into logs.
        Err(TlsError::General(
            "controller certificate does not match any pinned fingerprint".to_owned(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Handshake signatures stay with the provider. Pinning decides which
        // certificate is acceptable; it does not change what a valid signature
        // from that certificate looks like.
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS configuration that trusts exactly the pinned certificates.
///
/// The provider is the process default when one is installed and the built-in
/// one otherwise, so this agrees with the rest of the process rather than
/// introducing a second cryptographic backend.
pub(crate) fn pinned_client_config(pins: Vec<CertificateFingerprint>) -> rustls::ClientConfig {
    let provider = CryptoProvider::get_default().map_or_else(
        || Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        Arc::clone,
    );
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("the provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificates::new(pins, provider)))
        .with_no_client_auth();
    // The console speaks HTTP/1.1; offering h2 here would advertise a protocol
    // the rest of this client does not negotiate.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Parse one hex-encoded SHA-256 fingerprint, accepting the colon-separated
/// form `openssl` and the console's interface print as well as bare hex.
///
/// # Errors
///
/// Returns a message naming what was wrong when the value is not 32 bytes of
/// hexadecimal.
pub fn parse_fingerprint(value: &str) -> Result<CertificateFingerprint, String> {
    // Every character is checked to be ASCII hexadecimal before anything is
    // indexed. Filtering to bytes and slicing at fixed offsets would panic on
    // a multibyte character rather than returning the error this promises,
    // which is the opposite of failing closed.
    let digits: Vec<char> = value.chars().filter(|c| *c != ':' && *c != ' ').collect();
    if digits.len() != 64 {
        return Err(format!(
            "expected 64 hexadecimal characters for a SHA-256 fingerprint, found {}",
            digits.len()
        ));
    }
    if let Some(character) = digits.iter().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("`{character}` is not a hexadecimal digit"));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        // Both characters are ASCII hexadecimal, so this cannot fail.
        let high = digits[index * 2].to_digit(16).unwrap_or(0);
        let low = digits[index * 2 + 1].to_digit(16).unwrap_or(0);
        *byte = u8::try_from(high * 16 + low).unwrap_or(0);
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::{PinnedCertificates, parse_fingerprint};
    use rustls::{
        client::danger::ServerCertVerifier,
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    use std::sync::Arc;

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    #[test]
    fn a_fingerprint_is_accepted_in_the_form_openssl_and_the_console_print_it() {
        let colons = "08:46:EE:DF:8E:AB:46:BA:59:F2:F8:07:78:47:1E:76:\
                      6C:29:B5:C0:8A:85:37:FE:A6:C4:C0:5B:02:49:3B:85";
        let bare = colons.replace(':', "");
        let lower = bare.to_lowercase();
        let parsed = parse_fingerprint(colons).expect("colon form");
        assert_eq!(parsed, parse_fingerprint(&bare).expect("bare form"));
        assert_eq!(parsed, parse_fingerprint(&lower).expect("lowercase"));
        assert_eq!(parsed[0], 0x08);
        assert_eq!(parsed[31], 0x85);
    }

    #[test]
    fn a_value_that_is_not_a_fingerprint_says_what_was_wrong() {
        for (value, expected) in [
            ("08:46:EE", "found 6"),
            ("", "found 0"),
            (&"a".repeat(63), "found 63"),
            (&"z".repeat(64), "is not a hexadecimal digit"),
            // Sixty-four bytes but not sixty-four characters: slicing this at
            // fixed byte offsets lands inside a character and panics.
            (&format!("{}\u{00e9}", "a".repeat(62)), "found 63"),
            // Sixty-four characters, one of them multibyte.
            (
                &format!("{}\u{00e9}", "a".repeat(63)),
                "is not a hexadecimal digit",
            ),
        ] {
            let error = parse_fingerprint(value).expect_err(value);
            assert!(error.contains(expected), "{value}: {error}");
        }
    }

    /// The certificate bytes are not parsed, only hashed, so any distinct
    /// bytes exercise the decision this verifier makes.
    #[test]
    fn only_a_pinned_certificate_is_accepted() {
        let expected = CertificateDer::from(b"the console's certificate".to_vec());
        let impostor = CertificateDer::from(b"someone else's certificate".to_vec());
        let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(expected.as_ref()).into();

        let verifier = PinnedCertificates::new(vec![digest], provider());
        let name = ServerName::try_from("192.168.0.1").expect("server name");
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));

        assert!(
            verifier
                .verify_server_cert(&expected, &[], &name, &[], now)
                .is_ok()
        );
        let refused = verifier
            .verify_server_cert(&impostor, &[], &name, &[], now)
            .expect_err("unpinned certificate");
        // The refusal must not carry the certificate an attacker chose.
        let message = refused.to_string();
        assert!(message.contains("does not match any pinned"), "{message}");
        assert!(!message.contains("someone else"), "{message}");
    }

    /// The name being dialed is not part of the decision, which is the whole
    /// reason this mode exists: the console's certificate names neither the
    /// address it answers on nor anything resolvable here.
    #[test]
    fn the_name_being_dialed_does_not_change_the_decision() {
        let certificate = CertificateDer::from(b"the console's certificate".to_vec());
        let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(certificate.as_ref()).into();
        let verifier = PinnedCertificates::new(vec![digest], provider());
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));

        for name in ["192.168.0.1", "unifi.local", "example.invalid"] {
            let server_name = ServerName::try_from(name).expect("server name");
            assert!(
                verifier
                    .verify_server_cert(&certificate, &[], &server_name, &[], now)
                    .is_ok(),
                "{name}"
            );
        }
    }

    /// A second pin is how a console's certificate is replaced without an
    /// outage: both are accepted while the change is made.
    #[test]
    fn every_pin_in_the_set_is_accepted() {
        let first = CertificateDer::from(b"the certificate in use".to_vec());
        let second = CertificateDer::from(b"the certificate coming next".to_vec());
        let pins = vec![
            <sha2::Sha256 as sha2::Digest>::digest(first.as_ref()).into(),
            <sha2::Sha256 as sha2::Digest>::digest(second.as_ref()).into(),
        ];
        let verifier = PinnedCertificates::new(pins, provider());
        let name = ServerName::try_from("192.168.0.1").expect("server name");
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));

        for certificate in [&first, &second] {
            assert!(
                verifier
                    .verify_server_cert(certificate, &[], &name, &[], now)
                    .is_ok()
            );
        }
    }
}
