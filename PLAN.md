# Plan

Architecture and roadmap for the curated UniFi MCP server. Decisions with
their rejected alternatives live in [DECISIONS.md](DECISIONS.md); the
component breakdown lives in [docs/architecture.md](docs/architecture.md).

## Goal

An MCP server that lets an agent operate UniFi network controllers safely:
a small workflow-oriented tool surface with bounded summarized responses,
preview-then-confirm mutations verified by read-back, secret redaction by
default, and per-controller capability detection across UniFi's API
generations. It runs stateless behind the homelab MCP gateway, which owns
caller authentication, authorization groups, and rate limiting.

## Roadmap

1. **Scaffold** — workspace, CI, image, review policy, liveness server.
2. **Transports** — official Integration API client with capability
   detection and multi-controller configuration; legacy controller client
   (session auth, CSRF, re-login, backoff) for the capabilities the official
   API lacks.
3. **Ingress** — gateway bearer + identity-JWT authentication, the stateless
   Streamable HTTP mount, and gateway manifest emission.
4. **Read surface** — network overview, client/device search and context,
   Wi-Fi diagnosis, normalized firewall reads, events, and bounded stats.
5. **Mutation surface** — the shared safety framework (preview/confirm,
   read-back verification, redaction round-trip guard) and the curated write
   tools built on it.
6. **Deployment** — docker-home stack, gateway registration, and group-based
   access policy.
7. **Evaluation** — realistic multi-step agent tasks against the live
   deployment, iterating tool names and descriptions on the observed
   transcripts.

## Non-goals

UniFi Protect and Access, the Site Manager cloud API, backups, admin
management, and MFA/SSO controller accounts (a dedicated local admin per
console is the supported pattern).
