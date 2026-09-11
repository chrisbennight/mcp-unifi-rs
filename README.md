# mcp-unifi-rs

Curated Rust MCP server for UniFi network controllers.

## Why

Existing UniFi MCP servers mirror the controller API — one tool per endpoint,
raw JSON responses, and hundreds of schemas that overwhelm an agent's context.
This server takes the opposite approach: a small set of workflow tools
(search, context, diagnose, audit, and narrow typed actions) designed for how
agents actually operate a network, with bounded summarized responses,
preview-then-confirm mutations, read-back write verification, and secret
redaction by default.

## Status and non-goals

The tool surface is complete: the reads and writes listed below, described in
[docs/tool-surface.md](docs/tool-surface.md). Not yet deployed — production
Compose, gateway registration, and access policy live in the homelab
deployment repositories and are tracked separately.

The zone-based firewall is the one this server reads and writes; a console
running the classic firewall is refused by name rather than answered.

Non-goals for v1: UniFi Access, the Site Manager cloud API,
backups, admin management, and MFA/SSO controller accounts (use a dedicated
local admin per console).

## Architecture

| Crate | Responsibility |
|---|---|
| `unifi-api` | Bounded HTTP transports (official Integration API + legacy controller API), allowlisted models, capability detection |
| `unifi-mcp` | MCP schemas, tool registry, normalization, dispatch, annotations, redaction |
| `unifi-server` | Configuration, authenticated Streamable HTTP, stdio, health checks |

In gateway mode, the server runs stateless behind an MCP gateway that owns caller
authentication, authorization groups, and rate limiting; the server itself
verifies a rotating gateway bearer plus a gateway-minted identity JWT on every
`/mcp` request. One process serves one console family — `UNIFI_MCP_SURFACE`
selects the network controller tools or the Protect camera tools, each a
separate deployment of the same image with its own credentials.

Two UniFi APIs answer behind it — the official Integration API where it covers
a capability, and the legacy controller API for the large part it does not.
Which serves what, and how console generations differ, is in
[docs/compatibility.md](docs/compatibility.md).

## Tools

| Tool | What it answers or does |
|---|---|
| `network.overview` | One controller snapshot: version, health, alarms, totals |
| `clients.search` | Connected clients by name, address, SSID, VLAN, or medium |
| `clients.context` | One client end to end, with its recent events |
| `devices.search` | Adopted devices by name, model, address, or state |
| `devices.status` | One device: state, firmware, utilization, ports, radios |
| `firewall.read` | Zone-based firewall audit view; a classic console is refused |
| `networks.read` | Networks and wireless networks; passphrases redacted |
| `wifi.diagnose` | Wireless health: radios, load, weak clients, rogue APs |
| `events.search` | Recent events and active alarms in a bounded window |
| `stats.query` | WAN throughput history, or top applications by volume |
| `cameras.search` | Protect inventory by id, name, state, hardware model, or functional class; richer filters fail explicitly without local enrichment |
| `cameras.status` | One camera's identity, connection, firmware, recording, audio, and feature state, with source capability status |
| `protect.overview` | Protect version, cameras by state, recorder health and storage, and explicit inventory capabilities |
| `protect.events` | Historical detections in a bounded, caller-pageable window |
| `wlans.update` | Rename, enable, hide, or re-key one wireless network |
| `clients.control` | Block, unblock, or disconnect one client |
| `devices.control` | Restart, locate, or power-cycle a port on one device |
| `guests.authorize` | Grant one client guest access |
| `port_forwards.update` | Enable, disable, or rename one port forward |
| `firewall.policies.update` | Enable or disable one zone-based firewall policy |
| `vouchers.create` | Mint hotspot vouchers for the guest network |

Writes preview by default, are never retried after an ambiguous result, and —
where the controller exposes something to compare — are judged by reading the
resource back rather than by its acknowledgement. Each sends only the fields
named, except the zone-based policy write, whose upstream interface has no
partial update and so resends the policy exactly as it was read.
[docs/tool-surface.md](docs/tool-surface.md) covers the contracts, and
[docs/evals.md](docs/evals.md) is the task set that checks whether an agent can
actually find the right tool for a real question.

## Quick start

For an independent MCP client, start with [stdio or direct HTTP](docs/transports.md).
Those modes do not require a gateway and default to read access. The existing
gateway deployment starts as follows:

```sh
set -a && . ./.env && set +a               # gateway ingress settings are required at startup
cargo run --bin mcp-unifi-rs               # binds 0.0.0.0:8000 (healthz + authenticated /mcp)
cargo run --bin mcp-unifi-rs -- --healthcheck
```

Gateway startup fails closed without the gateway ingress and controller connection
configuration; copy `.env.example` to `.env` and fill it in. The controller
itself is dialed lazily, so the server boots and stays live while the console
is unreachable. The default bind is `0.0.0.0` for
container use; set `UNIFI_MCP_HOST=127.0.0.1` to keep a local run on loopback.

Configuration is environment-driven; see `.env.example` and
[docs/configuration.md](docs/configuration.md) for what each variable does and
what fails at load.

## Development

The executable is `mcp-unifi-rs`. The workspace crates remain `unifi-api`,
`unifi-mcp`, and `unifi-server`; environment settings still use `UNIFI_MCP_`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
python3 scripts/check_docs.py
python3 -m unittest discover -s scripts/tests
```

Repository guidance for agents and contributors: [AGENTS.md](AGENTS.md).
Design decisions: [DECISIONS.md](DECISIONS.md).

## CI and container images

GitHub Actions runs the development checks and builds the image on pull
requests. Its smoke test starts both Network and Protect containers with
fake credentials and no external network access. This checks startup and
liveness, not connectivity to a controller.

After the source and image checks pass on a push to `main` or a version tag,
a separate job publishes that tested image to
`ghcr.io/chrisbennight/mcp-unifi-rs`. Every publication has a `sha-<full-commit>`
tag. Pushes to `main` also update `latest`; tags such as `v1.2.3` publish that
version without changing `latest`. Version tags use
`vMAJOR.MINOR.PATCH` with an optional `-SUFFIX`.

Tags identify a source revision or version, but a rebuild can replace the
image behind a tag. For an immutable deployment, pin the image digest from
the publication output or `docker pull`, using
`ghcr.io/chrisbennight/mcp-unifi-rs@sha256:<digest>`.
See GitHub's [pull by digest instructions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#pull-by-digest).

The workflows use GitHub-hosted Linux runners, public dependencies, and the
job-scoped GitHub token for publication. No external registry credentials or
private artifact proxy are required. The initial image target is Linux x86-64.
Package visibility is managed separately in GitHub; a private package requires
authentication to pull. To build locally:

```sh
docker build -t mcp-unifi-rs .
python3 scripts/smoke_image.py mcp-unifi-rs
```

## License

MIT
