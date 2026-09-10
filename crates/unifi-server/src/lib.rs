//! Configuration, ingress, and HTTP serving for the `UniFi` MCP server.
//!
//! This crate owns environment-injected configuration, the liveness
//! endpoint, gateway ingress authentication (rotating bearer plus verified
//! gateway identity), the stateless Streamable HTTP MCP mount behind that
//! ingress, and gateway manifest emission.

pub mod auth;
pub mod config;
pub mod server;

use unifi_mcp::{ToolSurface, tools_for_surface};

/// Render an annotation-native gateway manifest scaffold from the executable
/// tool registry.
///
/// The upstream is classified in `mcp_annotations` mode, so the sidecar's MCP
/// annotations are the sole source of `side_effects` and sensitivity; this
/// projection carries only the gateway-owned `risk` and never the legacy
/// per-tool `side_effects`/`pii` flags, which annotation-mode admission
/// rejects. It is a scaffold, not a publishable manifest: annotation admission
/// also requires an `approved_behavior_hash` per tool that only the gateway can
/// compute from the live server, so each must be filled from the gateway's
/// manifest-change preview before publishing.
#[must_use]
pub fn gateway_manifest(surface: ToolSurface) -> String {
    let (name, url, bearer_env) = match surface {
        ToolSurface::Network => (
            "unifi",
            "http://unifi-mcp:8000/mcp",
            "MCP_GATEWAY_UPSTREAM_BEARER_UNIFI",
        ),
        ToolSurface::Protect => (
            "unifi-protect",
            "http://unifi-protect-mcp:8000/mcp",
            "MCP_GATEWAY_UPSTREAM_BEARER_UNIFI_PROTECT",
        ),
    };
    let mut output = format!(
        "# Annotation-native scaffold. classification_mode: mcp_annotations makes\n\
         # the sidecar's MCP annotations the sole source of tool effects and\n\
         # sensitivity; only the gateway-owned risk is projected here. Before\n\
         # publishing, add an approved_behavior_hash (64 hex chars) to each tool\n\
         # from the gateway manifest-change preview's observed_behavior_hash.\n\
         name: {name}\ntransport: http\nurl: {url}\nclassification_mode: mcp_annotations\nauth:\n  bearer_env: {bearer_env}\nsession:\n  isolation: per_call\n",
    );
    let tools: Vec<_> = tools_for_surface(surface).collect();
    // A bare `tools:` key would parse as YAML null; the empty registry must
    // project as an explicit empty sequence.
    if tools.is_empty() {
        output.push_str("tools: []\n");
    } else {
        output.push_str("tools:\n");
        for policy in tools {
            output.push_str("  - name: ");
            output.push_str(policy.name);
            output.push_str("\n    risk: ");
            output.push_str(policy.risk);
            output.push('\n');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use unifi_mcp::{ToolSurface, tools_for_surface};

    use super::gateway_manifest;

    #[test]
    fn manifests_are_annotation_native_and_project_only_the_selected_surface() {
        let cases = [
            (
                ToolSurface::Network,
                "unifi",
                "http://unifi-mcp:8000/mcp",
                "MCP_GATEWAY_UPSTREAM_BEARER_UNIFI",
                ToolSurface::Protect,
            ),
            (
                ToolSurface::Protect,
                "unifi-protect",
                "http://unifi-protect-mcp:8000/mcp",
                "MCP_GATEWAY_UPSTREAM_BEARER_UNIFI_PROTECT",
                ToolSurface::Network,
            ),
        ];
        for (surface, name, url, bearer, other) in cases {
            let manifest = gateway_manifest(surface);
            for policy in tools_for_surface(surface) {
                assert_eq!(manifest.matches(policy.name).count(), 1, "{}", policy.name);
                let entry = format!("  - name: {}\n    risk: {}\n", policy.name, policy.risk);
                assert!(manifest.contains(&entry), "{}", policy.name);
            }
            for policy in tools_for_surface(other) {
                assert!(!manifest.contains(policy.name), "{}", policy.name);
            }
            assert!(manifest.contains(&format!("name: {name}\n")));
            assert!(manifest.contains("classification_mode: mcp_annotations"));
            assert!(manifest.contains(&format!("url: {url}")));
            assert!(manifest.contains(&format!("auth:\n  bearer_env: {bearer}")));
            assert!(manifest.contains("isolation: per_call"));
            assert!(manifest.contains("tools:\n  - name: "));
            assert!(!manifest.contains("\n    side_effects:"));
            assert!(!manifest.contains("\n    pii:"));
        }
    }
}
