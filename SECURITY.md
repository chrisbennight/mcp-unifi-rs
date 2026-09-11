# Security

## Reporting

This is a private homelab repository; report issues directly to the repository
owner via an issue marked security.

## Boundary summary

- Gateway mode requires a rotating gateway bearer and a verified identity JWT.
  Direct HTTP requires its own rotating bearer; remote deployments require
  HTTPS at a reverse proxy. Stdio trusts the process owner. Independent modes
  default to read access and enforce separate write and disclosure grants.
  See [transport permissions](docs/transports.md#permissions).
- Controller credentials are environment-injected from a secret manager and
  are never model-visible, logged, or caller-selectable.
- Secret material in controller responses (Wi-Fi passphrases, PSKs, VPN keys,
  SNMP strings) is redacted by default.
- Mutations preview by default and verify persistence by read-back; they are
  never retried after an ambiguous transport result.
- The container runs as a non-root distroless image with a digest-pinned,
  locked build. GitHub Actions publishes the tested image to GHCR using a
  job-scoped token; pull requests cannot publish images.
