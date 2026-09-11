# Security

## Reporting

Do not disclose an exploit, credentials, or private controller data in a public
issue. When available, use this repository's
[private vulnerability report form](https://github.com/chrisbennight/mcp-unifi-rs/security/advisories/new).

The repository is currently private. Collaborators can report to the owner in
a repository issue, which is visible to repository members; omit credential
values and unrelated controller data. A public reporting channel has not yet
been enabled. Before changing visibility, the owner must enable GitHub private
vulnerability reporting and subscribe to its security notifications, or publish
another monitored private contact. The form link alone does not enable reporting.

Include the affected commit or image digest, transport, controller application
version, expected and observed behavior, and a minimal reproduction using fake
data where possible. There is no promised response time or supported-version
window yet. Fixes identify the affected behavior and source revision.

## Boundary summary

- Gateway mode requires a rotating gateway bearer and a verified identity JWT.
  Direct HTTP requires its own rotating bearer; remote deployments require
  HTTPS at a reverse proxy. Stdio trusts the process owner. Independent modes
  default to read access and enforce separate write and disclosure grants.
  See [transport permissions](docs/transports.md#permissions).
- Controller credentials are environment-injected and
  are never model-visible, logged, or caller-selectable.
- Secret material in controller responses (Wi-Fi passphrases, PSKs, VPN keys,
  SNMP strings) is redacted by default.
- Mutations preview by default and verify persistence by read-back; they are
  never retried after an ambiguous transport result.
- The container runs as a non-root distroless image with a digest-pinned,
  locked build. GitHub Actions publishes the tested image to GHCR using a
  job-scoped token; pull requests cannot publish images.

## Controller data and client responsibilities

Device names, hostnames, event messages and configuration text are untrusted
data. A name that resembles a prompt or instruction grants no authority. The
server uses typed operations and does not run this text as code. Clients must
keep tool results separate from trusted instructions and ask for the intended
action before confirming a mutation.

Read access can disclose network inventory and usage even when credentials are
redacted. Grant it only to trusted clients. Independent modes have separate
write and secret-disclosure flags; enabling writes does not enable Wi-Fi secret
reads. Voucher creation deliberately returns newly issued guest credentials.
Do not log or publish those results. SDK payload logging is disabled even when
the application log filter requests verbose SDK logs.

A timeout or broken connection after a confirmed write is an ambiguous outcome,
not proof that the write failed. Inspect controller state before another action.
Voucher codes cannot be read back, and a lost response can lose the only copy.
Read-back checks describe observable persistence, not an upstream transaction;
see [mutation contracts](docs/tool-surface.md).

## Source and image checks

CI scans the tracked source snapshot with pinned Gitleaks, redacts scanner
output, and checks Docker's actual exclusion of local environment and key files.
It also produces source and image software inventories. These checks do not
prove that arbitrary private data is absent or that dependencies are free of
vulnerabilities. Review new fixtures and dependency changes before merging.
See [distribution and maintenance](docs/distribution.md) for artifact verification
and [audit findings](docs/security-audit.md) for the migration review's limits.
