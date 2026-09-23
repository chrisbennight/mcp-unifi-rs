# Installation

Choose stdio for a client that launches a local process, or authenticated HTTP
for a separately running service. Both can run without a gateway.

Run commands below from the repository root after cloning. The Compose examples
run the published `ghcr.io/chrisbennight/mcp-unifi-rs:latest` image; they do not
build the checked-out source. You need pull access to that package, including
registry authentication if it is private. Select and pin an image digest using
the [distribution guide](distribution.md) for a repeatable deployment.

## What you need

- A UniFi console exposing the local Integration API. See
  [controller compatibility](compatibility.md) for the backend and version limits.
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
using the [TLS instructions](configuration.md#tls-modes).

For Protect, copy [.env.protect.example](../.env.protect.example) to `.env`
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
operator grants them. See [permissions and troubleshooting](transports.md).

## HTTP and containers

For a source install, first follow the stdio setup through installing the
binary and loading `.env`; then start it with the HTTP command below.
For Docker, you need Docker with Compose and Git, but no host Rust toolchain.
If you have not cloned and configured the project yet:

```sh
git clone https://github.com/chrisbennight/mcp-unifi-rs.git
cd mcp-unifi-rs
cp .env.example .env
chmod 600 .env
```

Edit `.env` with the controller settings described above. For Protect, copy
`.env.protect.example` instead. Compose reads this file directly.

Direct HTTP uses a dedicated bearer supplied through
`UNIFI_MCP_HTTP_BEARER_CURRENT`; generate a random value of at least 32 bytes
through your secret manager. It is separate from your controller key.
Set it in your protected environment configuration. If you add it to `.env`,
reload that trusted file before starting the installed binary:

```sh
set -a
. ./.env
set +a
mcp-unifi-rs --transport http
```

Connect a current MCP client to `http://127.0.0.1:8000/mcp` with that bearer.
For remote access, put HTTPS at a reverse proxy and configure the Host and
Origin allowlists. This mode accepts preconfigured bearer authentication;
clients that require OAuth discovery need an authenticating gateway.

For Docker Compose, use the same protected `.env`, including the direct HTTP
bearer. Network uses [compose.example.yml](../compose.example.yml); Protect uses
[compose.protect.example.yml](../compose.protect.example.yml):

```sh
docker compose --env-file .env -f compose.example.yml config --quiet
docker compose --env-file .env -f compose.example.yml up -d
```

Both examples publish only on host loopback. The health endpoint checks process
liveness; make the inventory call above to verify the console connection.
See [transport configuration](transports.md) for HTTP request examples and
the existing gateway mode. Gateway remains the binary's default when
`--transport` is omitted.

For Protect, replace `compose.example.yml` with `compose.protect.example.yml`
in both Compose commands. To stop and remove the example containers, use the
same file you started with:

```sh
docker compose --env-file .env -f compose.example.yml down
```

This leaves your `.env` and downloaded images in place. Keep the environment file
private. To build and smoke-test an image without starting Compose:

```sh
docker build -t mcp-unifi-rs .
python3 scripts/smoke_image.py mcp-unifi-rs
```

The smoke test requires Python 3.11 or newer and uses isolated fake credentials;
it does not connect to your controller.
