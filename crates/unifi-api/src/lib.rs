//! Bounded HTTP clients and allowlisted response models for `UniFi` controllers.
//!
//! This crate owns the upstream transports and nothing model-visible:
//!
//! - [`IntegrationClient`], a client for the official Network Integration API
//!   (`X-API-KEY`, stateless), the primary backend;
//! - per-controller capability detection ([`capability`]), so a consumer can
//!   distinguish "this console does not support that" from an empty result;
//! - [`LegacyClient`], a cookie-session client (with CSRF echo) for the
//!   legacy controller API, used only for capabilities the official API
//!   lacks.
//!
//! Responses decode into typed models that tolerate unknown upstream fields.
//! Controller error bodies and failed decode bodies remain available as
//! bounded text.
//!
//! The [`collection`] interface preserves complete fixed traffic reports
//! for direct export to operator-owned storage. It is not currently wired to
//! an MCP tool.
//!
//! Another deliberate exception: a zone-based firewall policy is read and written
//! as its raw record, because the upstream interface offers no partial update
//! and a model can only resend what it understands — including a number model,
//! so each property keeps its original JSON text rather than being parsed and
//! re-serialized. That record travels back to the controller without being
//! interpreted. The controller's original response can also be returned to a
//! caller when the tool needs the full policy record.

pub mod capability;
mod client;
pub mod collection;
mod config;
mod error;
mod http;
mod legacy;
pub mod models;
pub mod pinning;
pub mod protect;
pub mod system_log;
pub mod traffic;

pub use client::{
    IntegrationClient, InventoryDetailKind, NetworkPolicyCollection, SiteInventoryKind,
    SwitchingDetailKind,
};
pub use config::{ControllerConfig, TlsMode};
pub use error::{ApiError, BoundedMessage};
pub use legacy::{LegacyClient, LegacyConfig, RecordFingerprint};
pub use protect::{ProtectAvailability, ProtectClient};
