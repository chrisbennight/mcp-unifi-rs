# Security

## Reporting

This is a private homelab repository; report issues directly to the repository
owner via an issue marked security.

## Boundary summary

- The server is deployed behind an MCP gateway on a private container network;
  it is never exposed directly. Every `/mcp` request must carry the rotating
  gateway bearer and a verified gateway-minted identity JWT.
- Controller credentials are environment-injected from a secret manager and
  are never model-visible, logged, or caller-selectable.
- Secret material in controller responses (Wi-Fi passphrases, PSKs, VPN keys,
  SNMP strings) is redacted by default.
- Mutations preview by default and verify persistence by read-back; they are
  never retried after an ambiguous transport result.
- The container runs as a non-root distroless image with a digest-pinned,
  locked build; publication credentials live only in Infisical.
