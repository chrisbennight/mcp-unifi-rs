# Tool surface

A small set of reads and writes, listed below. That it stays small is the
point — this is a workflow surface, not an endpoint mirror, and a tool exists
here because an operator reaches for it, not because the controller exposes
it.

Every tool rejects unknown parameters, returns a bounded structured result, and
carries MCP behavior annotations the gateway uses for authorization. Nothing
returns a raw controller record.

The registry in `crates/unifi-mcp/src/registry.rs` is the executable source of
these names, descriptions, and classifications; this page explains them.

## Reads

Every read is annotated read-only, idempotent, and non-destructive, and is
classified `low` risk. Some additionally carry a sensitive-result label:
`firewall.read` and `networks.read`, because a firewall rule names the
addresses it governs and a wireless network names its security mode; and the
four Protect reads, because an inventory of what is watched and whether it is
watching is disclosure-relevant even without an image.

### `network.overview`

No parameters. One controller snapshot: application version, per-subsystem
health, active alarm count, and device and client totals. Cheap enough for a
monitoring loop.

The alarm count saturates at the bounded read ceiling and says so when it does,
so a large number is never quietly a wrong number.

### `clients.search`

`query`, `ssid`, `vlan`, `connection`, `offset`, `limit`, `detail`.

Currently connected clients, matched on name, hostname, MAC, IP, SSID, VLAN, or
wired versus wireless. Paged, name-sorted, with `totalMatches` and `nextOffset`.
`detail` chooses concise identity-and-connection rows or full association
detail.

### `clients.context`

`client` — MAC, exact name, or exact hostname.

One client end to end: identity, connection and access point, signal,
addressing including any fixed IP, usage, and its recent controller events. The
tool to reach for when the question is about one device rather than a
population.

### `devices.search`

`query`, `state`, `offset`, `limit`.

Adopted devices by name, model, MAC, or IP, optionally filtered by state.
Reports `inventoryTruncated` when the underlying scan hit its ceiling.

### `devices.status`

`device` — id, MAC, or exact name.

One device's status: identity, state, firmware, uptime, CPU and memory, uplink
rates, and summarized port and radio tables.

### `firewall.read`

`section`, `sectionOffset`.

The normalized firewall audit view: zone-based zones and policies with their
match semantics, plus port forwards, traffic rules, and traffic routes.

This server reads the zone-based firewall only. A console still running the
classic firewall is **refused by name**, because returning the sections it does
have with the firewall silently absent would read as an open network to a
caller auditing one. The refusal names `portForwards`, `trafficRules`, and
`trafficRoutes`, which read identically on either generation and stay available
by narrowing. Narrow with `section`; continue a truncated `zones` or `policies`
scan with `sectionOffset` taken from `nextSectionOffset`.

### `networks.read`

`includeSecrets`, `section`.

Configured networks and wireless networks: VLANs, subnets, DHCP scopes, SSIDs,
and security modes. Passphrases are redacted by default; `includeSecrets`
discloses them and requires the `mcp-admins` group.

### `wifi.diagnose`

`weakSignalThresholdDbm` — defaults to -75, accepted between -100 and -30.

One wireless health snapshot: per-access-point radios and client load, the
weakest-signal clients with their access points, and neighboring rogue access
points. The place to start on a slow-wifi question.

### `events.search`

`kind`, `lastHours`, `category`, `client`, `offset`, `limit`.

Recent controller events and active alarms in one bounded window, newest first.
Rows without a timestamp are excluded from windowed results rather than
silently dated.

### `stats.query`

`report`, `hours`, `top`.

Bounded historical statistics: hourly WAN throughput over a window up to seven
days, or top applications by deep packet inspection volume.

### `cameras.search`, `cameras.status`, `protect.overview`, `protect.events`

The Protect console, which is a separate console from the network controller
with its own key and its own certificate. These four tools are served by their
own process: a server started with `UNIFI_MCP_SURFACE=protect` advertises and
dispatches exactly them, and a `network` server does not list them at all, so
a deployment without cameras simply runs no Protect server.

Within a Protect server, a console that cannot answer must never look like a
console with nothing to report. There are two ways to end up with no cameras —
a console without the Protect integration API, and a console that genuinely
has none — and only the latter is an empty list. The former is a refusal that
says so, because an agent that cannot tell them apart will report an
unmonitored house as an empty one.

The documented Integration API is authoritative for basic inventory. Its
`modelKey` value is a resource discriminator (`camera` or `nvr`), not a
hardware model. Camera names and the recorder name may be null, and the NVR
endpoint returns one object rather than an array. The server accepts optional
product type, GUID, MAC, and microphone fields when a release supplies them,
but never requires those extensions.

`cameras.search` always pages and filters on camera id, name, and the console's
reported state. Hardware-model and class filters fail explicitly while the
local facts needed to answer them are unavailable, rather than returning a
misleading empty result. `cameras.status` takes an id or an exact
reported name or display name and refuses an ambiguous name rather than
resolving it by position. `protect.overview` groups cameras by the state words
the console itself used and wraps the official single NVR object in its
recorder list.

Search and overview responses include capabilities. Basic public inventory is
available with only the API key. Hardware model, functional class, recording,
firmware, storage, and recorder health remain absent until a local inventory
source supplies them; no false, empty, or `unknown` substitute is synthesized.
The response distinguishes a missing local configuration from a configured
session whose inventory enrichment is unavailable.

`protect.events` reads the console's undocumented historical application route
because the official integration API exposes only a live WebSocket. It needs a
dedicated local-session username and password in addition to the integration
key. Requests name the curated motion, ring, smart-detection, and smart-audio
event families explicitly because Protect otherwise ignores time bounds on
this route. The response model is allowlisted and excludes thumbnails, images,
metadata, and detection-zone payloads.

The first call accepts `lastHours` (default 24), or an explicit `start` and
`end` in epoch milliseconds for an older window, plus optional `camera` and
`detection` filters. The camera filter accepts an id, exact reported name, or
display name from camera inventory. A window may span at most seven days;
adjacent explicit windows keep older retained history reachable. Each page
returns `nextCursor` until it has proved the frozen window complete. The
cursor moves the next request's upper time key strictly before the last
complete timestamp group, so insertions and removals among newer rows cannot
shift unread history. A
one-row lookahead keeps simultaneous events together. If one timestamp group
is larger than the requested page, the call fails loudly and asks for a higher
limit instead of silently splitting it. The per-page `limit` controls work
and result size; there is no whole-window row cap or silent truncation.

One absence is deliberate. **No snapshot, stream, or talkback**: a still
image from inside a house is a different class of data from a device state, and
if it is ever exposed it will be through a tool a caller reaches for on
purpose, with its own classification and its own authorized group — not as a
convenience on the side of a status result.

## Writes

Every write is annotated as non-read-only, destructive, and requiring review,
and is classified `high` risk. Idempotence is stated per tool because it is a
property of the operation, and a caller deciding whether a retry is safe reads
it.

| Tool | Idempotent | Sensitive input | Sensitive result |
|---|---|---|---|
| `wlans.update` | yes | yes | yes |
| `clients.control` | no | no | no |
| `devices.control` | no | no | no |
| `guests.authorize` | yes | no | no |
| `port_forwards.update` | yes | no | yes |
| `firewall.policies.update` | yes | no | yes |
| `vouchers.create` | **no** | no | yes |

### What every write does

**Previews by default.** A call without `confirm` reaches no write endpoint and
describes what would change, with the consequences worth knowing first. A field
already holding the requested value is not listed as a change.

**Validates before the controller.** Input that cannot be satisfied — an empty
change set, a misspelled field, a selector of the wrong shape — is refused
before any request, and the rejection names what would have been accepted.

**Is never retried.** Writes are classed as mutations in the transport, so an
ambiguous transport result is surfaced rather than resent.

The field writes additionally refuse a redaction round trip. Every
returned string is scrubbed of configured credential material, so a value read
back can carry the `[redacted]` marker; a change carrying that marker is
refused rather than persisting it over the real value. The actions take
an enum and a hardware address or id, with no free text for a marker to travel
in.

### Field writes: `wlans.update`, `port_forwards.update`

These take a resource id and a `changes` object, and only the named fields are
sent — an absent field is left alone rather than cleared.

- `wlans.update` — `wlan`, `changes: {ssid, enabled, security, hidden, passphrase}`
- `port_forwards.update` — `portForward`, `changes: {name, enabled}`

A confirmed change is judged by reading the resource back, not by the
controller's acknowledgement, because a controller acknowledges writes whose
fields it discards. Each requested field is reported `persisted`, `dropped`, or
`coerced`; properties that moved without being requested are named separately,
compared over the controller's whole record rather than the modeled subset;
and `verified` is true only when every requested field persisted and nothing
else moved.

Secret fields report their status and neither value.

Where a port forward points — source, destination port, internal host — is
deliberately not settable. Those fields decide what the rule governs and only
validate together against an address plan this server does not model, so
changing one is authoring a rule rather than operating an existing one.

### `vouchers.create` is the one write that cannot check its own work

It takes `name`, `count`, `timeLimitMinutes`, and optionally `guestLimit` and
`dataLimitMegabytes`, and echoes all of them back under `batch`. A preview is
what this write is reviewed from, and two batches differing only in validity or
access limits are different batches — a count alone could not tell them apart.

Every other write here is judged by reading the resource back. This one cannot
be: the controller returns each voucher's code once, at creation, and no later
read reproduces it. A read-back could confirm that vouchers exist while losing
the only copy of what they are.

So the batch is judged on its own shape, and the result says which checks it
made rather than borrowing the word `verified` — whether as many came back as
were asked for, whether each carries an id and a code, whether the codes are
distinct, and whether each is free of whitespace and within a plausible length.
Code lengths are reported rather than judged: the controller decides the
format, and refusing a batch for being unfamiliar would condemn vouchers that
already exist.

**The codes come back whether or not those checks pass.** From the moment the
request succeeds the vouchers exist on the controller, and withholding their
codes because something looked wrong would create guest access nobody can use
and nobody can find. A failed check is reported alongside the codes, never
instead of them. A row the controller returned without an identity is reported
the same way — the identity check exists to say so, which it can only do if
that row survives to be reported.

One code does not come back: one that contains a configured controller
credential. Returning it would hand that credential to the caller, which no
guarantee here outranks. The voucher's id is returned where it survives
untouched, so it can be revoked on the controller and another call mints a
replacement; an id the scrub altered is dropped instead, because a rewritten id
addresses nothing while looking like it should. The result says which case
applies rather than leaving a marker to be puzzled over.

The guarantee is about what this server receives. A response that never
arrives — a timeout, a reset connection, a body past the transport's read
ceiling — cannot be delivered by any design, and the vouchers it described
exist on the controller regardless. The ceiling is orders of magnitude above a
full batch of real vouchers and is what keeps a hostile upstream from
exhausting this process; trading that away would not make delivery certain, it
would only move the failure.

The response budget gives way for the same reason. It may refuse any other
result here, because a caller can narrow the query and ask again; there is
nothing to narrow once the vouchers exist, and neither an error nor a trimmed
batch is an acceptable answer. So this result is exempt, and what bounds it is
the request: the batch ceiling and the label length, both checked before
anything is minted. Bounding the label is part of the exemption rather than
tidiness — an exempt result that echoed unbounded caller text would amplify
whatever the caller chose to send. Beyond those bounds the result is as large as
the controller's own codes made it, which is the deliberate trade against
destroying credentials.

The credential scrub runs over the codes before the checks do. Every result
here is scrubbed of configured controller credentials, and a
controller-generated code is free to contain any substring; a code the scrub
rewrote looks exactly like a usable one. Running it first means such a code
fails the form check and carries a warning saying it is not what the controller
issued, rather than being handed back as though it were.

For the same reason, everything that can refuse a batch refuses it before
minting: the count and validity bounds and the label's length are decided from
the request alone. A batch rejected after minting is the one outcome worse than
not minting at all.

Not idempotent, and says so — each call mints another batch.

### The zone-based policy write is the exception

`firewall.policies.update` takes `policy` and `changes: {enabled}`, and works
differently from every other write here, because its upstream interface leaves
no other option.

There is no partial update that can flip a policy's switch: the API's `PATCH`
accepts only the policy's logging flag, and its `PUT` requires the whole
policy. So this reads the policy, alters that one field, and sends every other
property back exactly as it arrived — including properties this server does not
model, which is the point. A write that sent back only what it understood would
drop the rest, on the object that decides what the network permits.

A classic console is refused by name before anything is read, the same line
`firewall.read` holds. Without that, the missing endpoint arrives as a generic
controller failure and "this console has no such policy" cannot be told from
"this console has no policies at all".

Two consequences a caller should know, and which the preview states:

- Resending the whole policy overwrites an edit made elsewhere between the read
  and the write. There is no merge, because the interface offers none.
- Because the request returns every property untouched, nothing named in the
  collateral-change report was lost by this write. It is either the controller
  normalizing the record or another editor writing the policy in the same
  window, which this tool cannot tell apart — what it establishes is that the
  change was not asked for.

What a policy matches is not settable. Its source, destination, protocol scope
and schedule are a nested structure whose parts validate together, and changing
one is authoring a policy rather than operating one.

### Actions: `clients.control`, `devices.control`, `guests.authorize`

These change nothing this server models, so there is nothing to classify and no
`verified` flag to earn.

`clients.control` and `devices.control` read the controller afterwards and
report what it showed, along with what that observation is worth.
`guests.authorize` does not read anything afterwards, because there is nothing
to read: see below.

- `clients.control` — `client` (MAC), `action: block | unblock | reconnect`
- `devices.control` — `device`, `action: restart | locate | endLocate | portCycle`, `port`
- `guests.authorize` — `client` (MAC)

`clients.control` takes a MAC rather than a name because a blocked client is
absent from the connected list, so only the address identifies it in every state
the tool handles. It reports whether the client was in the connected list before
and after; a client that rejoins between the write and the check reads as
connected, which is an observation and not a guarantee.

`devices.control` requires `port` for `portCycle` and rejects it for every other
action, so a port can never be sent with an action that would ignore it. A
restart takes longer than the read, so the state afterwards usually still shows
the prior value — it records what the controller showed, not that the action
finished.

`guests.authorize` reports `verifiable: false` on both paths. The controller
exposes no authorization field on a client, so there is nothing to read back,
and saying so is better than presenting an accepted request as a verified
outcome.

## Not on this surface

Creating and deleting rules is out of scope throughout: these tools operate
configuration an operator already has.

Camera snapshots, RTSPS streams, and talkback are not exposed, for the reasons
under the Protect tools above.
