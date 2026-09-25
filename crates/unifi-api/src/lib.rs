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
//! Responses decode into allowlisted typed models that tolerate unknown
//! upstream fields, and upstream error bodies never cross this crate's
//! boundary beyond a bounded message.
//!
//! One deliberate exception: a zone-based firewall policy is read and written
//! as its raw record, because the upstream interface offers no partial update
//! and a model can only resend what it understands — including a number model,
//! so each property keeps its original JSON text rather than being parsed and
//! re-serialized. That record travels back to the controller without being
//! interpreted; it is never handed to a caller.

pub mod capability;
mod client;
mod config;
mod error;
mod http;
mod legacy;
pub mod models;
pub mod pinning;
pub mod protect;
pub mod system_log;

pub use client::IntegrationClient;
pub use config::{ControllerConfig, TlsMode};
pub use error::{ApiError, BoundedMessage};
pub use legacy::{LegacyClient, LegacyConfig, RecordFingerprint};
pub use protect::{ProtectAvailability, ProtectClient};
