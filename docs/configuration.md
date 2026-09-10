# Configuration

Every setting is read from the environment once, at startup, by
`unifi_server::config::Settings::from_env`. There is no configuration file and
no runtime reconfiguration: a value that is missing, malformed, or outside its
range fails the process at load rather than on the first tool call that needs
it. An operator finding out about a bad trust anchor from a failed container
start is strictly better than finding out from a firewall audit that silently
returned nothing.

Secrets arrive as environment values injected by the deployment's secret
provider. They are never written to a file in the image, never logged, never
returned by a tool, and never selectable by a caller.

A secret value that is part of the redaction marker — `redacted` itself, say —
is refused at startup. Scrubbing replaces such a value with a marker that still
contains it, so every result mentioning it would be withheld; on a write whose
output cannot be produced again that would destroy what the write created.
Failing at startup is the only place that can be caught safely.

No other value is refused, because none needs to be. The scrub covers the
string values in a result, and the check that nothing survived it covers
exactly the same ground. A secret that happens to spell a property name is left
alone by both: property names are server-authored constants, not anywhere
controller data can appear.

The variable table below is maintained by hand against
`crates/unifi-server/src/config.rs`. Nothing enforces it, so treat the module
as authoritative if the two ever disagree, and report the disagreement.

## Runtime surface

| Variable | Required | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_SURFACE` | no | `network` or `protect`. Defaults to `network`. |

One process serves one console family. The selector decides which upstream
configuration is read, which tools are advertised and dispatched, which
identity JWT audience is required (`unifi` or `unifi-protect`), and which
service name the `Host` allowlist defaults to. A `network` process reads no
Protect variable and a `protect` process reads no controller variable, so a
credential for the other surface present in the environment is ignored rather
than half-wired. Any other value fails at load.

## Listener

| Variable | Required | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_HOST` | no | Bind address. Defaults to all interfaces, because the container publishes nothing itself and the gateway reaches it over the compose network. |
| `UNIFI_MCP_PORT` | no | Bind port. |
| `UNIFI_MCP_LOG_LEVEL` | no | Tracing filter. |

`UNIFI_MCP_HOST` and `UNIFI_MCP_PORT` are also read on their own by the
container healthcheck, which needs the listener coordinates and must not
require any credential to run.

## Gateway ingress

These establish the security boundary. Both the bearer and the identity token
are required on every `/mcp` request; neither alone is sufficient, and network
membership is not authentication.

| Variable | Required | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_GATEWAY_BEARER_CURRENT` | yes | The bearer the gateway presents. Compared in constant time. |
| `UNIFI_MCP_GATEWAY_BEARER_PREVIOUS` | no | The bearer being retired. Accepting both for the length of a rotation is what makes rotation possible without a coordinated restart; leave it unset outside a rotation. |
| `UNIFI_MCP_IDENTITY_JWKS_URL` | yes | Where the gateway's signing keys are published. Fetched with its own short timeout and cached briefly, so a key rotation is picked up without a restart. |
| `UNIFI_MCP_IDENTITY_ISSUER` | yes | The issuer an identity token must claim. |
| `UNIFI_MCP_IDENTITY_ACTOR` | yes | The actor an identity token must name. Taken exactly as given, with no trimming or case folding, because a value that differs only by whitespace is a different principal and quietly accepting it would widen the boundary. |
| `UNIFI_MCP_ALLOWED_HOSTS` | no | Comma-separated `Host` values accepted. Defaults to the surface's service name (`unifi-mcp` or `unifi-protect-mcp`), its published port, and loopback. |
| `UNIFI_MCP_ALLOWED_ORIGINS` | no | Comma-separated `Origin` values accepted. Empty by default: this server has no browser client, so an absent list means no cross-origin request is allowed rather than all of them. |

The identity settings are checked at load rather than on the first request, so
a malformed JWKS URL, issuer, or actor stops the process instead of failing
every call later. That check is on the configuration only: the signing keys are
fetched when they are first needed, so a JWKS endpoint that is unreachable at
startup does not prevent one, and shows up when traffic arrives.

## Controller

Read only by the `network` surface; a `protect` process ignores this whole
table.

| Variable | Required | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_CONTROLLER_URL` | yes | The console origin, scheme and host only. See the constraints below. |
| `UNIFI_MCP_CONTROLLER_API_KEY` | yes | Integration API key, sent as `X-API-KEY`. |
| `UNIFI_MCP_CONTROLLER_USERNAME` | yes | Local admin for the legacy API. |
| `UNIFI_MCP_CONTROLLER_PASSWORD` | yes | That admin's password. |
| `UNIFI_MCP_CONTROLLER_NAME` | no | Label carried in the `network.overview` result to say which console answered. It does not appear in logs, so it cannot be used to separate log streams. |
| `UNIFI_MCP_CONTROLLER_SITE` | no | Legacy site name. Must be a plain name: a value containing a path separator, or `.`/`..`, is refused at load rather than being pasted into a request path. |
| `UNIFI_MCP_CONTROLLER_TLS` | no | `system`, `custom-ca`, `pinned`, or `accept-invalid`. See below. |
| `UNIFI_MCP_CONTROLLER_CA_FILE` | with `custom-ca` | PEM bundle to trust. Read through a byte ceiling enforced on the read itself, so a special file or one that grows cannot be read unbounded. |
| `UNIFI_MCP_CONTROLLER_CERT_SHA256` | with `pinned` | One or more certificate fingerprints, comma separated. Accepts the colon-separated upper-case form `openssl` prints as well as bare hex. |
| `UNIFI_MCP_CONTROLLER_TIMEOUT_SECONDS` | no | Per-request timeout toward the console. |

### The Protect console

Read only by the `protect` surface, where it is required: a Protect console is
a different console with its own key and its own certificate, not a second
site on the network controller, and it gets its own process. A `network`
process ignores these variables entirely — camera questions belong to the
`unifi-protect` server, not to a refusal here. The key is required alongside
the URL, so a half-configured console fails at load rather than on the first
camera question.

| Variable | Required | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_PROTECT_URL` | yes | Protect console origin, scheme and host only. |
| `UNIFI_MCP_PROTECT_API_KEY` | yes | Protect integration API key, minted on the console itself and sent as `X-API-Key`. Not the network controller's key, and not a cloud key. |
| `UNIFI_MCP_PROTECT_USERNAME` | no | Dedicated local Protect account used for bounded inventory enrichment and the undocumented historical event route. Must be supplied with the password. |
| `UNIFI_MCP_PROTECT_PASSWORD` | with a Protect username | Password for the dedicated local-session account. Environment-injected, scrubbed, and never returned or logged. |
| `UNIFI_MCP_PROTECT_NAME` | no | Label for the console. Defaults to `protect`. |
| `UNIFI_MCP_PROTECT_TLS` | no | Same four modes as the controller. The CloudKey presents a different certificate from the router, so a pinned deployment needs its own digest here. |
| `UNIFI_MCP_PROTECT_CA_FILE` | with `custom-ca` | PEM bundle to trust, read through the same byte ceiling. |
| `UNIFI_MCP_PROTECT_CERT_SHA256` | with `pinned` | Fingerprints for the Protect console's own certificate. |
| `UNIFI_MCP_PROTECT_TIMEOUT_SECONDS` | no | Per-request timeout toward the Protect console. |

The integration key is sufficient for basic camera and recorder inventory.
When both local-session variables are present, the same read-only session adds
hardware identity, feature, connection, firmware, recording, audio, recorder
health, capacity, and aggregate storage facts, and enables `protect.events`.
Supplying only one fails configuration at startup rather than deferring a
half-configured secret to the first call.

### What the controller URL may contain

The API clients own every path beneath the origin, so the URL carries the
origin and nothing else. Each of these fails at load:

- a scheme other than `http` or `https`;
- `http` to anything but a loopback host, since credentials travel to this
  origin and a plaintext hop that leaves the machine exposes them;
- a path, query, or fragment, which would mean the operator and the client
  disagree about who builds request paths;
- userinfo, because a credential in a URL ends up in logs and error text.

### TLS modes

Consoles ship self-signed certificates, so the trust decision is explicit
rather than inferred. An unrecognized value is an error, never a silent
downgrade.

- `system` — validate against the system roots. The default.
- `custom-ca` — validate against `UNIFI_MCP_CONTROLLER_CA_FILE`. The right
  answer for a console with its own certificate authority, and only when the
  certificate covers the address or name being dialed.
- `pinned` — accept exactly the certificates whose SHA-256 digest is listed in
  `UNIFI_MCP_CONTROLLER_CERT_SHA256`, and judge nothing else. Requires an
  `https` URL, since a plaintext one never presents a certificate to check.
  Read where the digest must come from before using it.
- `accept-invalid` — do not validate. This turns off the protection that keeps
  the console credentials from reaching an impostor, and is only defensible on
  a link that cannot be intercepted.

### When to pin

A UniFi console ships a self-signed certificate naming `unifi.local` and
loopback, and answers on a LAN address that appears nowhere in it. Trusting
that certificate through `custom-ca` still fails, because the address being
dialed is not one the certificate covers — the trust is fine and the name check
is not. Pinning resolves that by making the certificate itself the identity:
the chain is not built and the name is not matched, because the digest already
fixes which certificate is acceptable more tightly than a name would.

Two consequences worth knowing before choosing it.

A console that legitimately regenerates its certificate stops being reachable
until its new digest is listed. That is why more than one is accepted: add the
next digest before the change, remove the old one after. Without that, a
firmware update that rolls the certificate is an outage.

#### Where the digest must come from

A pin is exactly as trustworthy as the reading it came from, and this is the
one part of the mode that no code here can protect.

Reading the digest over the network gives whatever certificate answered. If
something is intercepting that connection, it answers with its own certificate,
its digest gets installed as the pin, and from then on the impostor is
precisely what this server expects — it receives the Integration API key and
the local administrator credentials on every request, and nothing ever warns,
because the pin matches. Pinning does not remove the risk of impersonation so
much as concentrate all of it into the moment the digest is taken.

So take the reading, then confirm it against something the network cannot
forge:

```sh
openssl s_client -connect HOST:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2
```

The trailing `cut` matters: `openssl` labels its output `sha256 Fingerprint=`,
and the setting takes the digest alone. Colons and spaces within it are
ignored, so the printed form pastes as-is, in either case.

Confirm it by at least one of:

- reading the same digest from the console's own interface, over a session you
  already trust;
- taking the reading again from a different host on a different path, and
  comparing;
- taking it from a link that cannot be intercepted at all — a direct
  connection, or the console's local console.

If the two readings disagree, do not pin either. That disagreement is the
signal this mode exists to give you, and it is only available before the pin
is set, never after.

## Request bounds

| Variable | Required | Meaning |
| --- | --- | --- |
| `UNIFI_MCP_REQUEST_TIMEOUT_SECONDS` | no | How long one `/mcp` request may run. |
| `UNIFI_MCP_MAX_CONCURRENT_REQUESTS` | no | Requests served at once. |
| `UNIFI_MCP_MAX_BODY_BYTES` | no | Largest accepted request body. |

Each is clamped to a range and rejected outside it, so a mistyped value cannot
remove the bound it was meant to set. The ranges live with the parse calls in
`Settings::from_environment`; the response-size bounds that apply to what a
tool returns are separate and are documented in
[the architecture notes](architecture.md).

## Deployment

Compose files, Infisical references, and Komodo stack configuration live in the
homelab deployment repositories, not here. This repository owns the image and
the contract above.
