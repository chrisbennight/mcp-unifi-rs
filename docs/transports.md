# Connecting a client

The binary accepts `--transport stdio`, `--transport http`, or
`--transport gateway`. Gateway remains the default for existing deployments.
Every mode uses the same Network or Protect tools and controller credentials.
One process serves one console family, selected by `UNIFI_MCP_SURFACE`.

The independent modes use MCP revision
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports).
Choose a client that supports this revision. HTTP+SSE and the older HTTP
session protocol are not supported by independent HTTP mode. Gateway mode
retains its existing SDK compatibility behavior.

## Permissions

Stdio trusts the operating-system user who starts the process. Direct HTTP
requires a dedicated bearer configured by that operator. Each process has
one fixed set of grants; all clients of that process share those grants.
Use separate processes and credentials when clients need different authority.

| Setting | Default | Effect in stdio and direct HTTP |
|---|---|---|
| `UNIFI_MCP_ALLOW_WRITES` | `false` | `true` permits mutation tools, including their previews |
| `UNIFI_MCP_ALLOW_SECRET_DISCLOSURE` | `false` | `true` permits the `networks.read` secret opt-in |
| `UNIFI_MCP_MAX_BODY_BYTES` | `1048576` | Request limit, from 1024 to 4194304 bytes; includes the newline in stdio |
| `UNIFI_MCP_MAX_CONCURRENT_REQUESTS` | `32` | Concurrent work limit, from 1 to 256 |
| `UNIFI_MCP_REQUEST_TIMEOUT_SECONDS` | `30` | Tool deadline, from 1 to 120 seconds |
| `UNIFI_MCP_LOG_LEVEL` | `info` | Log filter; logs go to stderr |

Permission flags accept exactly `true` or `false`. Neither `confirm=true`,
tool annotations, nor a caller-supplied identity header grants permission.
Granting writes still leaves each mutation in preview mode until its call
explicitly confirms. A timed-out confirmed mutation may have taken effect:
inspect controller state before deciding whether to act again.

Secret disclosure is separate from write permission. Write permission can
produce a new voucher's one-time code as part of the authorized creation
result. Keep those results private. Redaction and rejection of redaction
markers in writes remain enabled in all modes.

## Stdio

Build and install from a checkout with the pinned Rust 1.98.1 toolchain:

```sh
cargo install --locked --path crates/unifi-server
```

Set the controller environment described in
[configuration](configuration.md). Network needs its URL, Integration API
key, local account username and password. Protect needs its URL and
Integration API key; its local account is optional. Gateway bearer and JWT
settings are not needed for stdio.

Start your MCP client from the environment containing those credentials.
For clients using the common `mcpServers` configuration format:

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
launchers may not inherit your shell environment; use that client's protected
environment or secret configuration. Keep credential values out of shared
client configuration. Use an absolute binary path if the client cannot find
the Cargo bin directory.

List tools, then call `clients.search` with `{}` for Network or
`cameras.search` with `{}` for Protect. Both return bounded inventory without
changing the controller. Stdio writes only newline-delimited JSON-RPC to
stdout. Malformed, oversized, or incomplete input closes the connection;
closing stdin ends the server connection.

## Direct Streamable HTTP

Set `UNIFI_MCP_HTTP_BEARER_CURRENT` through your secret manager or protected
process environment to a newly generated random bearer of at least 32 bytes.
Do not reuse the controller API key. For rotation,
`UNIFI_MCP_HTTP_BEARER_PREVIOUS` can accept the old bearer during the transition.

```sh
mcp-unifi-rs --transport http
```

The listener defaults to `127.0.0.1:8000`; connect to
`http://127.0.0.1:8000/mcp`. Configure the client's `Authorization: Bearer`
header from the same protected bearer value. This is preconfigured bearer
authentication, not an OAuth authorization server: clients requiring OAuth
discovery need an authenticating gateway. The server does not forward the
incoming bearer to the controller.

List tools, then make the same inventory call as in stdio. A current HTTP
request carries `MCP-Protocol-Version`, `Mcp-Method`, and, for tool calls,
`Mcp-Name`. The corresponding values must match the body. For example, the
body for the first Network read is:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "clients.search",
    "arguments": {},
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "example-client", "version": "1"},
      "io.modelcontextprotocol/clientCapabilities": {}
    }
  }
}
```

Use `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method: tools/call`,
`Mcp-Name: clients.search`, `Content-Type: application/json`, and
`Accept: application/json, text/event-stream`. For Protect, change both the
body name and `Mcp-Name` to `cameras.search`. The client need not create or
retain a session ID.

For remote clients, terminate HTTPS at a reverse proxy before the server.
Set `UNIFI_MCP_HOST` for the proxy's network and restrict backend reachability
to that proxy. Never send bearer credentials across a plaintext remote link.
`UNIFI_MCP_PORT` defaults to 8000 and accepts 1 through 65535.
`UNIFI_MCP_ALLOWED_HOSTS` is a comma-separated allowlist of HTTP Host values,
including the port when clients send it. The direct default includes localhost,
127.0.0.1 and [::1], with and without the configured port. Set it explicitly
for the proxy's public hostname. If browser clients send Origin, set the exact
trusted origins in `UNIFI_MCP_ALLOWED_ORIGINS`; the default allows none.

`/healthz` reports process liveness without authentication and does not contact
the controller. It does not prove that credentials or permissions work.

## Gateway

`--transport gateway` requires the existing rotating gateway bearer and verified
gateway identity JWT described in [configuration](configuration.md).
The gateway continues to own group authorization and rate limiting. Its
administrator group controls the secret-disclosure opt-in. Independent-mode
permission flags do not alter gateway policy.

## Troubleshooting

| Symptom | Check |
|---|---|
| Missing controller configuration | Select Network or Protect and supply that surface's environment variables |
| TLS failure on the first read | Configure a trusted CA or verify and pin the console certificate; see configuration |
| HTTP 401 | Supply the dedicated direct bearer; gateway mode also requires its verified identity JWT |
| HTTP 403 | Check Host and Origin against the explicit allowlists |
| HTTP 400 HeaderMismatch | Use a current client and matching method, name, and version headers/body metadata |
| HTTP 405 on GET or DELETE | Use current Streamable HTTP POST requests, without legacy session setup |
| Write or disclosure denied | Grant the corresponding process permission; confirmation alone is insufficient |
| Empty inventory | Check the selected site and filters; unsupported API generations return an explicit error |
| Stdio closes immediately | Inspect stderr and check newline framing, valid JSON-RPC, and the message-size limit |

Source tests in `crates/unifi-server/tests/portable.rs` exercise both transports
against loopback controller fakes, including successful inventory reads and
denied privileged calls. They do not require access to a real controller.
