//! MCP schemas, tool registry, normalization, and dispatch for the `UniFi` MCP
//! server.
//!
//! This crate owns everything model-visible: typed flat parameter structs
//! that reject unknown fields, normalized bounded response models, the
//! executable tool registry with MCP behavior annotations, and dispatch. The
//! tool surface is a curated set of workflow tools, never a raw mapping of
//! `UniFi` API endpoints. Mutations preview by default and redact secret
//! material in responses. They verify writes by reading back, except where no
//! read reproduces what the write produced — a voucher's code exists only in
//! the response that created it — in which case the result says what it could
//! establish instead of claiming verification.

pub mod handler;
pub mod mutation;
pub mod registry;
pub mod tools;

pub use handler::UnifiMcp;
pub use mutation::survives_its_own_redaction;
pub use registry::{
    TOOL_REGISTRY, ToolBehavior, ToolKind, ToolSpec, ToolSurface, tools_for_surface,
};

/// Verified caller identity propagated by the gateway ingress into request
/// extensions; the group gate for privileged tool options reads it here.
#[derive(Debug, Clone)]
pub struct IdentityPrincipal {
    pub subject: String,
    pub groups: Vec<String>,
}

/// Group whose members may use privileged tool options such as secret
/// disclosure opt-ins.
pub const MCP_ADMIN_GROUP: &str = "mcp-admins";
