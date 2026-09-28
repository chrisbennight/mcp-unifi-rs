use std::time::Duration;

use url::Url;
use zeroize::Zeroizing;

/// How the client validates the controller's TLS certificate.
///
/// Consoles ship with self-signed certificates, so operators choose between
/// trusting a custom CA, accepting the self-signed certificate, or relying on
/// system roots when the console carries a publicly valid certificate.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Validate against the platform trust store.
    SystemRoots,
    /// Validate against exactly one additional PEM-encoded CA certificate.
    CustomCa(Vec<u8>),
    /// Accept exactly the certificates with these SHA-256 digests, and judge
    /// nothing else — not the chain, and not whether the certificate names
    /// the address being dialed. A console's own certificate names neither
    /// its address nor anything resolvable, so this is how it is trusted
    /// without turning validation off. More than one digest is accepted so a
    /// console can be given a new certificate without an outage.
    Pinned(Vec<crate::pinning::CertificateFingerprint>),
    /// Skip certificate validation entirely. Only for controllers reachable
    /// exclusively over a trusted network path.
    AcceptInvalid,
}

/// Connection settings for one named controller.
pub struct ControllerConfig {
    /// Operator-chosen controller name used in logs and tool responses.
    pub name: String,
    /// Console origin, such as `https://192.168.0.66`. API paths are
    /// appended by the client.
    pub base_url: Url,
    /// Integration API key generated in the console's control plane.
    pub api_key: Zeroizing<String>,
    pub tls: TlsMode,
    /// Per-request timeout covering connect, write, and read.
    pub timeout: Duration,
}
