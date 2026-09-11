# Design decisions

## Curated workflow tools

Tools group common operational tasks: search, context, diagnosis, configuration
reads, and narrow actions. They return bounded summaries with explicit paging
or truncation signals. The server does not generate a tool for every controller
endpoint or return arbitrary upstream records.

## Shared tools, separate connections

Stdio, direct Streamable HTTP, and gateway HTTP share the typed tool handler.
Independent clients have fixed operator-granted permissions for writes and
secret disclosure. Stdio trusts the process owner; direct HTTP requires a
dedicated bearer. Gateway mode retains its bearer and verified identity JWT,
with group authorization owned by that gateway. Confirmation and advisory MCP
annotations are not substitutes for authorization.

## Public API and local-session clients

The Integration clients use Ubiquiti's public application APIs. Local-session
clients supply the additional data and narrow writes this implementation uses.
[Compatibility](docs/compatibility.md) records the actual backend selection;
new public endpoints can be adopted without changing the curated tool surface.
Each client owns bounds, timeouts, authentication and typed response models.

## Stateless HTTP

HTTP calls do not need server-issued session identifiers. Handler clones share
upstream clients and the resolved site ID. The independent HTTP endpoint uses
current per-request MCP metadata; stdio retains a connection to its parent.
No transport makes controller credentials selectable by a tool caller.

## Honest mutation outcomes

Mutations preview by default, validate bounded input before writing, and never
retry an ambiguous write. Where an observable state exists, read-back reports
whether the requested change persisted. Guest authorization and one-time voucher
codes have explicit verification limits. The voucher result preserves the code
returned by creation even when its subsequent checks cannot establish persistence.
The [architecture](docs/architecture.md#write-safety) explains these contracts.

## Rust and maintained protocol libraries

The workspace uses the official Rust MCP SDK, axum, and reqwest/rustls. The
lockfile and image references make dependency changes reviewable. Contributor
checks run with public dependencies and local fakes; private infrastructure is
not needed to build or test.
