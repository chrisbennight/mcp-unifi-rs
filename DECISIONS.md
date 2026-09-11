# Decisions

One heading per decision, stating the rejected alternative.

## Curated workflow tools, not an endpoint mirror

The tool surface is a small set of workflow tools (search, context, diagnose,
audit, narrow typed actions). Rejected: generating a tool per UniFi endpoint.
The most popular UniFi MCP server carries 189 generated-style tools and had to
build lazy tool loading, meta-tools, and an index that itself overflows client
context to compensate; a small curated surface needs none of that machinery
and gives the gateway's tool search a clean corpus.

## Dual UniFi backend, official Integration API first

The official Network Integration API (`X-API-KEY`, stateless) is the primary
transport; the legacy controller API (cookie session + CSRF) is used only for
capabilities the official API lacks, behind per-controller capability
detection. Rejected: legacy-only (fragile across controller releases, and
Ubiquiti is actively expanding the official surface) and official-only (still
missing port forwarding, client blocking, DPI, and events).

## Stateless Streamable HTTP from day one

The MCP service runs stateless: no session identifiers, a handler built per
request, JSON responses. Rejected: stateful session mode. The protocol's
direction of travel is stateless-by-default, the gateway dials upstreams
per call, and this server holds no per-connection state that a session could
usefully carry.

## Gateway-grade ingress in-process

In gateway mode, the server verifies a rotating bearer pair plus a gateway-minted identity JWT
itself, following the hardened pattern shared by the newest sibling servers.
Rejected: trusting the private container network as the authentication
boundary — network membership is not authentication.

Independent stdio and HTTP clients use fixed operator grants for writes and
secret disclosure. Stdio relies on the process owner; direct HTTP requires a
dedicated bearer. Neither tool arguments nor advisory annotations can elevate
those grants. The same typed dispatch and redaction apply in each mode.

## Read-back verification on every mutation

After an accepted write the server re-reads the resource and classifies each
requested field as persisted, dropped, or coerced, and reports that in the
tool result. Rejected: trusting the controller's acknowledgement. UniFi
controllers routinely return success while silently dropping or rewriting
fields; this is the incumbent server's largest bug class.

## Rust toolchain and dependency posture

rmcp (the official Rust MCP SDK) for the protocol layer, axum for HTTP,
reqwest/rustls for upstream calls, mirroring the sibling `mcp-*-rs` repos.
Cargo version updates are security-only under Renovate, matching fleet policy.
