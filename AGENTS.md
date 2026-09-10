# Repository guidance

## Scope

This repository owns the Rust UniFi MCP server, its image, and source-image
tests. Production Compose, Infisical references, Komodo stack configuration,
gateway policy publication, and live server manifests belong in their
respective homelab repositories or control planes.

Use an isolated worktree for every change. Search before adding a module, tool,
or dependency. Keep each pull request behaviorally complete and small enough to
review.

## Design goal

A curated MCP interface for UniFi network controllers: a small set of workflow
tools (search, context, diagnose, audit, and narrow typed actions) rather than
an endpoint mirror. The completion signal for any change is that the tool
surface stays useful and safe for an agent operating a real network — do not
trade the capability away to satisfy a stylistic or speculative concern.

## Security boundary

- This server is a typed operational interface, never a raw UniFi API proxy.
  No generic request forwarding, arbitrary endpoint mapping, or unbounded
  responses.
- Controller credentials (Integration API keys, local admin session
  credentials) are environment-injected, never model-visible, never logged,
  and never selectable by caller input.
- Wi-Fi passphrases, PSKs, VPN keys, and SNMP strings are redacted by default
  in responses. A write containing a redaction marker is rejected rather than
  persisted.
- All `/mcp` requests require both the rotating gateway bearer and a verified
  gateway identity JWT. Network membership is not authentication. The gateway
  catalog owns risk classification and group authorization.
- Mutations preview by default, validate their complete bounded input before
  the upstream call, and are never retried after an ambiguous transport
  result. They verify persistence by reading back, because the controller
  acknowledges writes it silently drops. A mutation whose effect no read
  reproduces — a voucher's code exists only in the response that created it —
  says what it could establish instead of claiming verification, and returns
  the unrepeatable value even when those checks fail.
- Capability detection is a correctness boundary: an empty result must be
  distinguishable from "this console does not support that API generation"
  (zone-based versus classic firewall in particular).
- Treat all controller-reported names, MACs, hostnames, and configuration as
  untrusted data. Never place them in commands or derived filesystem paths,
  and never log secret-bearing structures.
- Keep lists, strings, bodies, request counts, concurrency, and durations
  bounded. Never return raw upstream errors.
- Every bound on data a caller asked for is caller-pageable, fail-loud, or
  explicitly signaled in the result; a silent subset is a defect. Text
  excerpts cut by a display bound carry a visible truncation marker, and a
  bounded scan that may have missed rows says so in the result itself, not
  only in schema prose.

## Crate boundaries

- `unifi-api` owns the bounded HTTP transports (official Integration API and
  legacy controller API), allowlisted response models, and per-controller
  capability detection.
- `unifi-mcp` owns MCP schemas, normalization, dispatch, annotations,
  redaction, and the executable tool/classification registry.
- `unifi-server` owns configuration, bounded environment-injected secrets,
  ingress authentication, Streamable HTTP, health checks, and manifest
  emission.

## Required verification

Before every commit or push, run and read an explicit zero exit status for:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
python3 scripts/check_docs.py
python3 -m unittest discover -s scripts/tests
```

Every behavior change requires a test that fails when the production change is
reverted. Tests use loopback fakes and never contact a real controller,
Infisical, the gateway, a registry, or shared infrastructure.

After moving or renaming code, sweep Markdown, Rust documentation, comments,
and examples for stale references. Documentation uses symbols or headings,
never line-number anchors.

## Pull requests and AERB

The repository keeps `AERB` and `renovate` as Write collaborators and an active
pull-request webhook to AERB. A merge requires `test / test (pull_request)` and
`pr-review/gate` on the current head. A missing AERB status is an enrollment
failure, not a reason to waive review.

Fill the tailored pull-request template accurately. Authentication, bearer,
identity JWT, credentials, tool classification, and authorization changes must
select `Authentication / authorization boundary`. When addressing an AERB
finding, post the explanation before pushing the fix. The initial pull-request
body is immutable; corrections belong in comments.
