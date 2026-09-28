# Tool surface

A small set of reads and writes, listed below. That it stays small is the
point — this is a workflow surface, not an endpoint mirror, and a tool exists
here because an operator reaches for it, not because the controller exposes
it.

Every tool rejects unknown parameters, returns a bounded result, and carries
MCP behavior annotations the gateway uses for authorization. Common views
stay compact; selected tools also return the controller's original fields.

The registry in `crates/unifi-mcp/src/registry.rs` is the executable source of
these names, descriptions, and classifications; this page explains them.

## Reads

Every read is annotated read-only, idempotent, and non-destructive, and is
classified `low` risk. Some additionally carry a sensitive-result label:
`firewall.read`, `networks.read`, `radius_profiles.list`, the official Wi-Fi
broadcast reads, and Protect reads.
The gateway decides who can receive these controller values.

### `network.overview`

No parameters. One controller snapshot: application version, per-subsystem
health, device and client totals, and `recentEvents` for the last 24 hours.
That summary gives `windowStart` and `windowEnd` in epoch milliseconds,
`total`, and `highSeverity` (HIGH or VERY_HIGH). Counts come from two bounded
system-log queries and their controller-reported totals. They describe recent
history, not outstanding alarms; the queries are not an atomic snapshot.

### `clients.search`

`query`, `ssid`, `vlan`, `connection`, `offset`, `limit`, `detail`.

Currently connected clients, matched on name, hostname, MAC, IP, SSID, VLAN, or
wired versus wireless. Paged, name-sorted, with `totalMatches` and `nextOffset`.
`detail` chooses concise identity-and-connection rows or full association
detail.

Full detail includes `counterCoverage` per client and shared `counterSemantics`.
Known wired clients prefer the `wired-tx_bytes` / `wired-rx_bytes` pair when
either field is present; otherwise the generic pair is used. Missing members
stay missing: fields from different counter families are never combined.
`reported` means both counters were supplied, `partial` means one was supplied,
and `unavailable` means neither was supplied. These are connection counters,
not verified WAN-only usage, rates, or totals over a shared time window.

### `clients.context`

`client` — MAC, exact name, or exact hostname.

One client end to end: identity, connection and access point, signal,
addressing including any fixed IP, usage, and its recent controller events. The
tool to reach for when the question is about one device rather than a
population.

The counter selection and coverage match full client search. `counterSemantics`
states source, byte units, scope, direction, window, and reset limitations.

Recent events cover the last 24 hours: scan up to 200 site-wide system logs,
then return up to 20 matching client events. `recentEventsTruncated` signals
additional upstream rows or matching events beyond the output limit.

### `devices.search`

`query`, `state`, `offset`, `limit`.

Adopted devices by name, model, MAC, or IP, optionally filtered by state.
Reports `inventoryTruncated` when the underlying scan hit its ceiling.

### `devices.status`

`device` — id, MAC, or exact name.

One device's status: identity, state, firmware, uptime, CPU and memory, uplink
rates, and summarized port and radio tables. If the optional statistics read
fails, `statisticsError` carries the controller response while identity and
interface state remain available.

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

`section`.

Configured networks and wireless networks: VLANs, subnets, DHCP scopes, SSIDs,
security modes, and passphrases. The gateway controls access to these values.

### `radius_profiles.list`

`offset` and `limit` (1-200, default 50) page through the official Network
API's [RADIUS profiles](https://developer.ui.com/network/v10.4.57/getradiusprofileoverviewpage)
for the selected site. Each profile preserves the fields
the controller returned, including the id needed for enterprise Wi-Fi setup.
The result includes the controller's page metadata and `nextOffset` until the
list is complete. An over-budget result fails explicitly; lower `limit` to
continue with smaller pages.

### `wifi.broadcasts.list` and `wifi.broadcasts.status`

These tools use the [official Network Wi-Fi broadcast API](https://developer.ui.com/network/v10.4.57/getwifibroadcastpage).
`wifi.broadcasts.list` accepts `offset` and `limit` (1-200, default 50),
returns complete controller fields for each selected row, and supplies
`nextOffset` until the list is complete. `wifi.broadcasts.status` accepts a
`broadcastId` from that list and returns its complete controller record,
including security and network configuration. An over-budget list fails
explicitly; lower `limit` to receive smaller pages.

### `wifi.diagnose`

`weakSignalThresholdDbm` — defaults to -75, accepted between -100 and -30.

One wireless health snapshot: per-access-point radios and client load, the
weakest-signal clients with their access points, and neighboring rogue access
points. The place to start on a slow-wifi question.

### `events.search`

`severity`, `lastHours`, `category`, `client`, `offset`, `limit`.

Network system logs, newest first. `severity` accepts `low`, `medium`, `high`,
or `veryHigh` and filters upstream. `lastHours` defaults to 24 and accepts
1-168. The tool scans one page of up to 1000 rows, then applies case-insensitive
category/key substring and client MAC filters and paginates those matches.
`totalMatches` counts matches in that scan; `fetchWindowTruncated` signals
additional upstream rows. Narrow the time window or severity when it is set.
Rows include `time` in epoch milliseconds, `key`, `message`, `category`,
`severity`, and `clientMac` when available. Missing timestamps fail decoding.
If a received page violates its pagination contract, the error includes the
complete accepted controller response and the validation diagnostic.
Known entity placeholders in messages are replaced literally; messages are
limited to 256 characters with a visible ellipsis when shortened.

### `stats.query`

`report`, `hours`, `startMs`, `endMs`, `top`, `limit`, `offset`.

- `clientWanHistory` returns the controller Activity view's historical Internet
  download/upload totals per client, sorted by combined bytes, with MAC address
  and display name. `limit` (1-200, default 50) and `offset` page the returned
  client inventory. `clientTotals` covers all returned clients, not just the page.
- `dpiApplications` ranks the same interval's application counters. `top`
  (1-50, default 10) bounds the ranking; `totalApplications` reports the number
  before selection. Numeric category/application IDs remain available when
  official catalog names are missing. `namesStatus` identifies lookup failures.
- `wanHourly` returns site WAN counters without client attribution. Missing
  counters remain unknown. Returned timestamps are restricted to the requested
  window; the bucket at `endMs` is excluded.

Use both `startMs` and `endMs` for a fixed interval of whole UTC hours, at most
seven days, ending in the past. Alternatively, `hours` (1-168, default 24)
selects a relative window. Activity reports end at the latest completed hour;
`wanHourly` retains its relative window ending now. Reuse the returned fixed
boundaries for subsequent pages and comparisons; these reads are not atomic
snapshots of controller history.

Activity responses include site graph sample timestamps as `temporalEvidence`.
Those samples do not establish per-client collection boundaries. Reconciliation
compares all returned client totals with complete site WAN hours over the same
requested boundaries. Signed differences are site minus clients, separately
by direction; missing WAN hours suppress the comparison instead of counting as
zero. Differences do not establish their cause. Collection and classification
completeness remain unknown, so nonempty activity has `partial` coverage.
An empty report is not proof of zero traffic.

Unsupported Activity sources return an explicit status. For application reports
only, an absent Activity endpoint permits the original legacy DPI fallback
when no explicit time window was requested;
its `counterSemantics` explicitly retain the unverified interval, direction,
and scope. Authentication failures never trigger that fallback. An unrecognized
Activity response is reported as such. Record/string/body bounds fail loudly;
there is no silent scan truncation. Activity record or string bounds and graph
bounds failures return the complete accepted controller body with the local
diagnostic.
Display text uses visible truncation markers.
`sourceErrors` retains the controller's status and response for Activity,
graph, and legacy DPI requests that returned 404 or 405. A console-family
decision with no request has no controller response. If the error text exceeds
the structured result budget, `sourceErrorsInContent` points to the complete
errors in an additional content block while the available report remains in
the structured result. When the requested Activity page itself exceeds that
budget, `activityInContent` points to its complete data in another content
block; the structured result keeps coverage and source information.

See [traffic compatibility](compatibility.md#traffic-counter-evidence) and
[traffic source evidence](traffic-history.md) for source limitations and examples.

### Protect cameras, streams, talkback, overview, and events

The Protect console, which is a separate console from the network controller
with its own key and its own certificate. Its tools are served by their
own process: a server started with `UNIFI_MCP_SURFACE=protect` advertises and
dispatches exactly them, and a `network` server does not list them at all, so
a deployment without cameras simply runs no Protect server.

Within a Protect server, a console that cannot answer must never look like a
console with nothing to report. There are two ways to end up with no cameras —
a console without the Protect integration API, and a console that genuinely
has none — and only the latter is an empty list. When the API probe returns
HTTP 404, camera tools return that status and the complete accepted controller
body. An agent can therefore distinguish an absent API from an empty inventory.

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

`cameras.status` can include the complete original local camera record with
`includeDetails: true`, or selected top-level fields with `detailFields`.
`protect.overview` accepts `detailFields` to return selected top-level fields
from the original local bootstrap, including recorder, account, and user
records. These fields are returned as the console reports them. A result over
the 48 KiB response budget fails explicitly; request fewer fields when needed.
If the optional local inventory read fails, `cameras.search` and
`protect.overview` include the controller error in
`capabilities.localUnavailableReason`, and `cameras.status` includes it in
`localError`. Requests that need the missing local data return that error.
If the local bootstrap fails camera or recorder validation, that error includes
the complete accepted bootstrap body and the field that failed validation.

`cameras.snapshot` fetches a JPEG from the official Protect API by camera id
or exact reported name. It returns MCP image content plus small structured
metadata, so an agent can inspect a frame without receiving a base64 string
as text. The `channel` input chooses `main` (default) or `package`; the latter
is for cameras with a package camera. `highQuality` requests 1080p or higher
when available. A response above 4 MiB fails explicitly.
A nonempty invalid JPEG returns the accepted controller response with the
decoder diagnostic. Non-UTF-8 bytes use base64; valid UTF-8 stays as text.
The same behavior applies to event thumbnails.

`cameras.settings.read` returns the official camera name, on-screen overlay,
LEDs, microphone volume, video mode, HDR mode, and smart detection settings.
`cameras.settings.update` patches only the named fields from that set. It
previews by default and, when confirmed, returns the controller's action
response and a separate read-back. `verified` requires the requested fields to
match and the other modeled settings to stay unchanged. Invalid enum values,
an empty change set, and out-of-range microphone volume are rejected before
the write. The official doorbell LCD message setting requires its own typed
message and asset workflow and is not accepted by this tool.
When the read-back fails, `readbackError` carries the controller response
alongside the accepted patch response.

`cameras.ptz.control` previews or runs a preset move, patrol start, or patrol
stop for one camera. A preset slot of `-1` means home; patrol slots are `0` to
`4`. Confirmed patrol actions read the reported active slot back and state
whether it matches. The official API does not report position after a preset
move, so that action reports controller acceptance without claiming position
verification. `cameras.status` includes `activePatrolSlot` when reported by the
console; null means no patrol is running. A failed patrol read-back returns the
controller response in `readbackError`.

`cameras.streams.list` returns the existing RTSPS stream URLs for a camera.
These URLs grant access to the camera feed, so the result is classified high
risk and sensitive. The gateway decides caller access in gateway mode.
`cameras.streams.update` previews by default;
with `confirm`, it creates or removes one or more distinct qualities: `high`,
`medium`, `low`, or `package`. A created URL is returned even if the follow-up
readback fails or times out. The result says whether the requested qualities
were observed afterward, and `readbackError` carries any controller failure.
For these camera mutations, an error that exceeds the structured result budget
is returned as a separate text content block, signaled by
`readbackErrorInContent`, so an accepted action result remains available.
`package` requires a camera with a package camera.

`cameras.talkback.start` previews or creates a talkback session. A confirmed
call returns its RTP URL, codec, sampling rate, and bit depth. The API does not
provide a session readback, so the tool reports creation and the returned
session data without claiming that the caller has sent audio.

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
this route. The paged response carries compact event facts by default.
Set `includeDetails: true` to include each returned event's complete
controller record, including detection metadata and thumbnail references. This
choice also works with a continuation cursor; lower `limit` if the expanded
page exceeds the response budget. Use
`detailFields` to select named controller fields when only part of an event's
detail is needed; it can be used without `includeDetails`. Use
`protect.event.thumbnail` with an event id from the result to fetch its image
as MCP image content. The thumbnail read uses the same local session, checks
the JPEG format, and fails explicitly when the controller has no image for
that event.

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

The snapshot tool covers still images from cameras; RTSPS URLs are transport
handles for a caller capable of consuming a live stream.

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
| `guests.authorize` | **no** | no | yes |
| `guests.unauthorize` | **no** | no | yes |
| `port_forwards.update` | yes | no | yes |
| `firewall.policies.update` | yes | no | yes |
| `firewall.policies.delete` | yes | no | yes |
| `vouchers.create` | **no** | no | yes |
| `vouchers.revoke` | yes | no | yes |
| `cameras.ptz.control` | **no** | no | yes |
| `cameras.settings.update` | yes | no | yes |
| `cameras.streams.update` | **no** | no | yes |
| `cameras.talkback.start` | **no** | no | yes |

### What every write does

**Previews by default.** A call without `confirm` reaches no write endpoint and
describes the requested action and its consequences. Configuration field updates
omit fields already holding the requested value.

**Validates before the controller.** Input that cannot be satisfied — an empty
change set, a misspelled field, a selector of the wrong shape — is refused
before any request, and the rejection names what would have been accepted.

**Is never retried.** Writes are classed as mutations in the transport, so an
ambiguous transport result is surfaced rather than resent.

For guest actions, voucher revocation, and firewall policy deletion, a
verification error too large for the structured result is returned in a
separate text content block. `readbackErrorInContent` points to that block so
the accepted action result remains available.

### Field writes: `wlans.update`, `port_forwards.update`

These take a resource id and a `changes` object, and only the named fields are
sent — an absent field is left alone rather than cleared.

- `wlans.update` — `wlan`, `changes: {ssid, enabled, security, hidden, passphrase, radiusProfileId}`
- `port_forwards.update` — `portForward`, `changes: {name, enabled, source, forwardTo, forwardPort, destinationPort, protocol}`

`wlans.update` can change the security mode without sending a new passphrase.
The controller retains or rejects its existing key configuration; the read-back
reports whether the requested mode persisted.
Security accepts `open`, `wpapsk`, and `wpaeap`. An enterprise network can
reference an existing controller RADIUS profile by `radiusProfileId`. The
profile id is reported by `networks.read` and verified after an update.

A confirmed change is judged by reading the resource back, not by the
controller's acknowledgement, because a controller acknowledges writes whose
fields it discards. Each requested field is reported `persisted`, `dropped`, or
`coerced`; properties that moved without being requested are named separately,
compared over the controller's whole record rather than the modeled subset;
and `verified` is true only when every requested field persisted and nothing
else moved.

If a wireless network or port forward snapshot cannot be decoded into its
typed record, the error includes the controller's complete accepted response
and the local decoding error.

Requested fields report their previous, requested, and observed values, including
passphrases when the caller changes one. The gateway governs access to sensitive
results.

`port_forwards.update` sends only named fields to the controller, including
the source, target, ports, and protocol. Its preview shows the requested
values and warns when the match or target changes; confirmed changes read the
rule back and report any field the controller dropped or changed.

### Voucher creation and lifecycle

It takes `name`, `count`, `timeLimitMinutes`, and optionally `guestLimit` and
`dataLimitMegabytes`, and echoes all of them back under `batch`. A preview is
what this write is reviewed from, and two batches differing only in validity or
access limits are different batches — a count alone could not tell them apart.

The official voucher list and detail endpoints return each code. `vouchers.search`
pages through vouchers and `vouchers.status` reads one by id; both return codes
as sensitive results. `vouchers.revoke` previews a deletion and, when confirmed,
checks whether the voucher disappeared from the detail endpoint. Its
`readbackError` carries the controller's response when that lookup fails,
including the HTTP 404 response used to confirm absence.

Creation checks the returned batch — whether as many came back as
were asked for, whether each carries an id and a code, whether the codes are
distinct, and whether each is free of whitespace and within a plausible length.
Code lengths are reported rather than judged: the controller decides the
format, and refusing a batch for being unfamiliar would condemn vouchers that
already exist. It also reads each identified voucher back and sets `verified`
only when the count matches and every id and code matches. A failed readback is
reported with the creation response in `readbackErrors`, with the voucher id
and complete controller error. `readbackComplete` says whether verification
reached the end of the returned batch. A deadline or accumulated error
response budget that stops later reads is named in `readbackStopReason`; those
vouchers remain reachable through `vouchers.status` or `vouchers.search`
without minting the batch again.
Large errors move to a separate text content block, signaled by
`readbackErrorsInContent`, while issued codes remain in the structured result.

**Every code the controller supplied comes back whether or not those checks
pass.** A row with no code keeps that field absent rather than inventing an
empty code. From the moment the request succeeds the vouchers exist on the
controller, and withholding their
codes because something looked wrong would create guest access nobody can use
and nobody can find. A failed check is reported alongside the codes, never
instead of them. A row the controller returned without an identity is reported
the same way — the identity check exists to say so, which it can only do if
that row survives to be reported.

The guarantee is about what this server receives. A response that never
arrives — a timeout, a reset connection, a body past the transport's read
ceiling — cannot be delivered by any design, and the vouchers it described
exist on the controller regardless. The ceiling is orders of magnitude above a
full batch of real vouchers and is what keeps a hostile upstream from
exhausting this process; trading that away would not make delivery certain, it
would only move the failure.

The standard response budget applies to creation too. If a controller returns
an unusually large batch that exceeds it, the call fails loudly and the codes
can be retrieved through the bounded voucher reads.

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

### Actions: `clients.control`, `devices.control`, `guests.authorize`, `guests.unauthorize`

`clients.control` and `devices.control` read the controller afterwards and
report what it showed, along with what that observation is worth.
Guest actions read the Integration API client detail afterwards and report
whether the observed access matches the action response.

- `clients.control` — `client` (MAC), `action: block | unblock | reconnect`
- `devices.control` — `device`, `action: restart | locate | endLocate | portCycle`, `port`
- `guests.authorize` — `client` (MAC), optional time, data, and rate limits
- `guests.unauthorize` — `client` (MAC)

`guests.status` reads the current guest authorization, expiration, limits, and
traffic usage for a connected client.

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

`guests.authorize` returns the granted record and any grant it replaced.
Repeating authorization replaces the active grant and resets traffic counters,
so it is not idempotent. `guests.unauthorize` returns the revoked grant and
disconnects the client. Both actions mark `verified` true only when a bounded
read of the connected client reports the expected state and grant metadata.
The observed grant is returned separately when it can be read. If a disconnected
client is no longer readable, the action response remains available and the
result says that verification was unavailable. If the verification read fails,
`readbackError` carries the controller response alongside the action response.

### Rule deletion: `firewall.policies.delete`

`firewall.policies.delete` removes a zone-based policy by id. It previews the
policy's match and action, then sends one DELETE when confirmed. A following
read distinguishes a policy that is absent from one the controller retained.
The `readbackError` field carries the controller's response when that read
fails, including an HTTP 404 response that confirms absence.
The preview shows full source, destination, protocol, connection-state, IPsec,
and schedule conditions alongside the compact policy summary. It also shows
the official descriptive and metadata fields when present. It marks whether
these bounded views cover the controller record and names omitted fields when
they do not; those fields may change the policy's effect. Large field values
are omitted with that signal so the preview and deletion result remain within
the response bound. Selected controller keys and values, including nested
keys, are returned as received; the gateway governs caller access to sensitive
results.

## Remaining rule workflows

Creation, ordering, and the remaining rule lifecycle operations are tracked
in the Network rule issue.
