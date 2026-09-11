# mcp-unifi-rs

MCP server for UniFi Network and Protect, written in Rust. It provides tools
for inventory, troubleshooting, configuration reads, and selected network
changes. Results are bounded, credentials stay in the server, and changes
preview before they are confirmed.

## What you need

- A UniFi console exposing the local Integration API. See
  [controller compatibility](docs/compatibility.md) for the backend and version limits.
- For Network: an application Integration API key and a dedicated local account
  for the legacy API. For Protect: its Integration API key; a local account is
  optional for richer inventory and event history.
- A client supporting MCP 2026-07-28 for independent stdio or HTTP connections.
- Rust 1.96 and a native build toolchain for a source install, or Docker for the
  Linux x86-64 image. CI runs on Linux; other host platforms are not tested here.

## Quickstart: stdio

```sh
git clone https://github.com/chrisbennight/mcp-unifi-rs.git
cd mcp-unifi-rs
cargo install --locked --path crates/unifi-server
cp .env.example .env
chmod 600 .env
```

Edit `.env` with your Network console URL, Integration API key, and local
account credentials. The URL is the console origin, such as
`https://console.example.net`, without an API path. If its certificate is not
trusted by your system, configure a custom CA or verify and pin the certificate
using the [TLS instructions](docs/configuration.md#tls-modes).

For Protect, copy [.env.protect.example](.env.protect.example) to `.env`
instead and fill in its URL and key. Both applications may run on the same
physical console; each server process selects one application and its credentials.

Load your trusted environment file, then start your MCP client from that shell:

```sh
set -a
. ./.env
set +a
```

Configure a stdio server in the client:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "mcp-unifi-rs",
      "args": ["--transport", "stdio"]
    }
  }
}
```

The client must pass the controller environment to the child process. Desktop
clients may need an absolute binary path and their own protected environment
configuration. Do not put credentials in a configuration file you share.

List the server's tools, then call `clients.search` with `{}` for Network or
`cameras.search` with `{}` for Protect. You should receive a bounded inventory
result. An empty result means no matching devices; an unsupported API or failed
request returns an explicit error. Neither call changes the controller.

Writes and secret disclosure are disabled in independent modes until the
operator grants them. See [permissions and troubleshooting](docs/transports.md).

## HTTP and containers

Direct HTTP uses a dedicated bearer supplied through
`UNIFI_MCP_HTTP_BEARER_CURRENT`; generate a random value of at least 32 bytes
through your secret manager. It is separate from your controller key.

```sh
mcp-unifi-rs --transport http
```

Connect a current MCP client to `http://127.0.0.1:8000/mcp` with that bearer.
For remote access, put HTTPS at a reverse proxy and configure the Host and
Origin allowlists. This mode accepts preconfigured bearer authentication;
clients that require OAuth discovery need an authenticating gateway.

For Docker Compose, use the same protected `.env`, including the direct HTTP
bearer. Network uses [compose.example.yml](compose.example.yml); Protect uses
[compose.protect.example.yml](compose.protect.example.yml):

```sh
docker compose --env-file .env -f compose.example.yml config --quiet
docker compose --env-file .env -f compose.example.yml up -d
```

Both examples publish only on host loopback. The health endpoint checks process
liveness; make the inventory call above to verify the console connection.
See [transport configuration](docs/transports.md) for HTTP request examples and
the existing gateway mode. Gateway remains the binary's default when
`--transport` is omitted.

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

The implementation uses the official Integration API and local-session APIs
for the capabilities listed in
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

Tests use loopback fakes and need no controller, gateway, or private services.
See [CONTRIBUTING.md](CONTRIBUTING.md), [support](SUPPORT.md),
[repository guidance](AGENTS.md), and [design decisions](DECISIONS.md).

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

[MIT](LICENSE). UniFi Access, cloud Site Manager, backup/admin management,
and controller MFA/SSO login are outside the implemented tool surface.
