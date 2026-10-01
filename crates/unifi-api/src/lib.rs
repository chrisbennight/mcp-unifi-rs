//! Bounded HTTP clients, compact models, and complete controller records.
//!
//! [`IntegrationClient`] uses the official Network Integration API with an
//! environment-supplied API key. [`LegacyClient`] uses a cookie session for
//! legacy diagnostics and configuration. [`protect::ProtectClient`] implements
//! the official Protect Integration API.
//!
//! Compact models support operational summaries and readback verification.
//! Complete record readers retain controller fields and JSON numeric text.
//! Controller error bodies and failed decode bodies remain available in full
//! within the transport bound. Capability detection distinguishes unsupported
//! API generations from empty results while retaining original rejections.
//!
//! The [`collection`] interface exports complete fixed traffic reports to
//! operator-owned storage. On-demand MCP traffic reads expose the same sources.
//! Firewall state updates preserve unchanged controller properties before
//! replacement; authoring operations use typed controller request contracts.

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
    DpiCatalogKind, IntegrationClient, InventoryDetailKind, MAXIMUM_DPI_NAME_IDS,
    NetworkPolicyCollection, SiteInventoryKind, SwitchingDetailKind,
};
pub use config::{ControllerConfig, TlsMode};
pub use error::{ApiError, BoundedMessage};
pub use legacy::{
    LegacyClient, LegacyConfig, LegacyDiagnosticSource, MAXIMUM_PROTECT_EVENT_PAGE_LIMIT,
    RecordFingerprint,
};
pub use protect::{ProtectAvailability, ProtectClient};
