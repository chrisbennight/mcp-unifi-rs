# Configuration

The server reads environment variables at startup; restart it to change them.
It does not load `.env` itself. The examples show how to supply a protected
file through a shell or Docker Compose. Missing required values and invalid
bounds fail startup. Controller connections are lazy, so liveness does not
prove that a controller is reachable.

Controller credentials are environment-injected, never selected by tool input,
and scrubbed from results. Secret values are limited to 16384 bytes. A controller
key or password that cannot survive the result redactor is refused at startup.
For independent client permissions and HTTP bearer settings, see
[Connecting a client](transports.md#permissions).

## Runtime and listener

| Variable | Default | Accepted values or meaning |
| --- | --- | --- |
| `UNIFI_MCP_SURFACE` | `network` | `network` or `protect`; one application per process |
| `UNIFI_MCP_HOST` | Gateway: `0.0.0.0`; direct HTTP: `127.0.0.1` | Bind address; ignored by stdio |
| `UNIFI_MCP_PORT` | `8000` | Integer from 1 to 65535 |
| `UNIFI_MCP_LOG_LEVEL` | `info` | Tracing filter; application logs go to stderr; SDK payload logs remain disabled |
| `UNIFI_MCP_REQUEST_TIMEOUT_SECONDS` | `30` | Request/tool deadline, 1 to 120 seconds |
| `UNIFI_MCP_MAX_CONCURRENT_REQUESTS` | `32` | Concurrent request/tool work, 1 to 256 |
| `UNIFI_MCP_MAX_BODY_BYTES` | `1048576` | Request bytes, 1024 to 4194304; includes newline framing in stdio |

Out-of-range numbers are rejected, not clamped. Response limits are separate;
see [response bounds](architecture.md#response-bounds). A confirmed mutation can
have taken effect before a timeout; check controller state before another action.
The healthcheck reads only listener coordinates and needs no credentials.

## Independent clients

| Variable | Default | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_ALLOW_WRITES` | `false` | Exactly `true` permits mutation tools, including previews |
| `UNIFI_MCP_ALLOW_SECRET_DISCLOSURE` | `false` | Exactly `true` permits `networks.read` with `includeSecrets` |
| `UNIFI_MCP_HTTP_BEARER_CURRENT` | Required for direct HTTP | Dedicated bearer, at least 32 bytes, no whitespace; never reuse a controller key |
| `UNIFI_MCP_HTTP_BEARER_PREVIOUS` | Unset | Optional distinct old bearer during rotation |
| `UNIFI_MCP_ALLOWED_HOSTS` | Direct HTTP: localhost, 127.0.0.1 and [::1], with and without the configured port | Comma-separated exact Host values; configure the proxy hostname for remote access |
| `UNIFI_MCP_ALLOWED_ORIGINS` | Empty | Comma-separated trusted Origin values; any supplied Origin is rejected unless listed |

Permission flags accept only `true` and `false`. They do not change gateway
policy. Stdio requires no incoming bearer. Direct HTTP uses fixed, preconfigured
bearer authentication; it has no OAuth discovery endpoint. Its local socket is
plaintext: remote access needs HTTPS termination and a restricted proxy-to-server
connection. See [HTTP setup](transports.md#direct-streamable-http).

## Controller

A Network process reads these variables; a Protect process ignores them.
Obtain an application Integration API key and a dedicated local account as
explained in [compatibility](compatibility.md#connection-and-permission-requirements).

| Variable | Default or requirement | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_CONTROLLER_URL` | Required | Console origin, such as `https://console.example.net` |
| `UNIFI_MCP_CONTROLLER_API_KEY` | Required | Network Integration key, sent as `X-API-KEY` |
| `UNIFI_MCP_CONTROLLER_USERNAME` | Required | Dedicated local account for the legacy API |
| `UNIFI_MCP_CONTROLLER_PASSWORD` | Required | Local account password |
| `UNIFI_MCP_CONTROLLER_NAME` | `unifi` | Operator label in results |
| `UNIFI_MCP_CONTROLLER_SITE` | `default` | Legacy site short name; no `/`, `.` or `..` path segments |
| `UNIFI_MCP_CONTROLLER_TIMEOUT_SECONDS` | `15` | Each upstream request, 1 to 60 seconds |
| `UNIFI_MCP_CONTROLLER_TLS` | `system` | `system`, `custom-ca`, `pinned`, or `accept-invalid` |
| `UNIFI_MCP_CONTROLLER_CA_FILE` | Required with `custom-ca` | Readable PEM bundle, at most 65536 bytes |
| `UNIFI_MCP_CONTROLLER_CERT_SHA256` | Required with `pinned` | Comma-separated SHA-256 certificate fingerprints |

## Protect

A Protect process reads these variables; a Network process ignores them.
The URL may be the same physical console as Network, but the key must belong
to Protect. Its TLS settings are configured separately.

| Variable | Default or requirement | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_PROTECT_URL` | Required | Protect console origin |
| `UNIFI_MCP_PROTECT_API_KEY` | Required | Protect Integration key, sent as `X-API-Key` |
| `UNIFI_MCP_PROTECT_USERNAME` | Unset | Optional dedicated local account for enrichment and historical events |
| `UNIFI_MCP_PROTECT_PASSWORD` | Required with username | The account password; supplying only one of the pair fails startup |
| `UNIFI_MCP_PROTECT_NAME` | `protect` | Operator label in results |
| `UNIFI_MCP_PROTECT_TIMEOUT_SECONDS` | `15` | Each upstream request, 1 to 60 seconds |
| `UNIFI_MCP_PROTECT_TLS` | `system` | Same TLS modes as Network |
| `UNIFI_MCP_PROTECT_CA_FILE` | Required with `custom-ca` | Readable PEM bundle, at most 65536 bytes |
| `UNIFI_MCP_PROTECT_CERT_SHA256` | Required with `pinned` | Fingerprints of the Protect console certificate |

The key alone supports basic camera and recorder inventory. A local account
adds hardware, firmware, recording, connection, recorder health and storage
facts where available, and enables `protect.events`. Without that session,
unsupported enrichment filters fail explicitly instead of returning a partial
match. See the [tool reference](tool-surface.md).

## Controller URL rules

Supply only an origin: scheme, hostname or IP, and optional port. API paths
are built by the clients. Paths other than `/`, query strings, fragments and
userinfo are rejected. HTTPS is required except for loopback HTTP, which is
used by local test fakes. A cloud Site Manager URL is not a substitute for the
local application API.

## TLS modes

| Mode | Behavior |
| --- | --- |
| `system` | Validate the certificate chain and hostname against system roots |
| `custom-ca` | Validate with the supplied PEM bundle; the certificate must still cover the requested hostname/IP |
| `pinned` | Require HTTPS and an exact SHA-256 fingerprint of the presented certificate; replaces chain/hostname validation |
| `accept-invalid` | Disable certificate validation; an intercepted connection can disclose controller credentials |

Prefer a trusted certificate or custom CA. For a self-signed certificate whose
name does not match the address, pinning can identify the certificate directly.
An unknown mode fails startup. Pinning requires the digest of the certificate,
not its public key. Colons and whitespace in the fingerprint are accepted.

To inspect the certificate presented by a console, replace `HOST` with its
address:

```sh
openssl s_client -connect HOST:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2
```

This command alone does not establish trust: an interceptor can present a
different certificate. Compare the fingerprint with the console through an
already trusted administrative session or a trusted physical/local path before
configuring it. A second untrusted network observation is not independent proof.
If the readings disagree, resolve that difference before accepting a pin.

A legitimate certificate replacement requires a new pin. You can list old and
new fingerprints during a planned rotation, then remove the old one. For Docker
`custom-ca`, add a read-only mount for the bundle and set the corresponding
`*_CA_FILE` to its path inside the container; the Compose examples do not mount
host trust files automatically.

Compose forwards only the environment settings listed in its service block.
Add an entry there when overriding another setting from the tables above.

## Gateway ingress

These settings apply only to `--transport gateway`, which remains the default.
Every gateway `/mcp` request requires both the rotating bearer and a verified
identity JWT. Network membership alone grants no access.

| Variable | Requirement | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_GATEWAY_BEARER_CURRENT` | Required | Gateway service bearer, at least 32 bytes and no whitespace |
| `UNIFI_MCP_GATEWAY_BEARER_PREVIOUS` | Optional | Distinct previous bearer during rotation |
| `UNIFI_MCP_IDENTITY_JWKS_URL` | Required | Signing-key endpoint; HTTPS or permitted local/private HTTP |
| `UNIFI_MCP_IDENTITY_ISSUER` | Required | Exact trusted issuer |
| `UNIFI_MCP_IDENTITY_ACTOR` | Required | Exact expected actor; whitespace is significant |

The selected surface determines the JWT audience: `unifi` or `unifi-protect`.
Signing keys are fetched lazily with a bounded timeout and cache. Gateway Host
defaults are the selected service name (`unifi-mcp` or `unifi-protect-mcp`), that
name with port 8000, localhost, and 127.0.0.1. Override
`UNIFI_MCP_ALLOWED_HOSTS` when the Host header differs. The Origin allowlist is
empty by default in both HTTP modes.

Operators own deployment-specific gateway policy and secret-provider settings.
This repository supplies the executable, examples, and the manifest scaffold
from `mcp-unifi-rs --emit-gateway-manifest`. The scaffold is not a published
gateway policy; the gateway operator must complete its behavior approvals.
