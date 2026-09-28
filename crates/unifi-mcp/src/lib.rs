//! MCP schemas, tool registry, normalization, and dispatch for the `UniFi` MCP
//! server.
//!
//! This crate owns everything model-visible: typed flat parameter structs
//! that reject unknown fields, normalized bounded response models, the
//! executable tool registry with MCP behavior annotations, and dispatch. The
//! tool surface is a curated set of workflow tools, never a raw mapping of
//! `UniFi` API endpoints. Mutations preview by default, verify writes by
//! reading back, and report
//! incomplete verification alongside the controller's response.

pub mod handler;
pub mod mutation;
pub mod registry;
pub mod tools;

pub use handler::UnifiMcp;
pub use registry::{
    TOOL_REGISTRY, ToolBehavior, ToolKind, ToolSpec, ToolSurface, tools_for_surface,
};

/// Verified caller identity propagated by the gateway ingress into request
/// extensions.
#[derive(Debug, Clone)]
pub struct IdentityPrincipal {
    pub subject: String,
    pub groups: Vec<String>,
}
