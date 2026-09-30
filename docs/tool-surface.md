# Tool surface

Typed UniFi workflows group related capabilities into useful reads and
configuration actions. Compact summaries help discovery; complete requested
controller records and error bodies remain available within explicit bounds.

Every tool rejects unknown parameters, returns a bounded result, and carries
MCP behavior annotations the gateway uses for authorization. Common views
stay compact; selected tools also return the controller's original fields.

The registry in `crates/unifi-mcp/src/registry.rs` is the executable source of
these names, descriptions, and classifications; this page explains them.

## Reads

Every read is annotated read-only, idempotent, and non-destructive, and is
classified `low` risk. Some additionally carry a sensitive-result label:
`firewall.read`, `networks.read`, `networks.list`, `networks.status`, `radius_profiles.list`,
`devices.pending.list`, the Network inventory, switching detail, and policy
reads, the official Wi-Fi broadcast reads, and Protect reads.
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

### `devices.pending.list`

`offset`, `limit` (1-200, default 50), and the official `filter` query page
devices pending adoption across the controller. Each row retains every field
returned by the controller, including its MAC address and support state.
`nextOffset` identifies the next page. Large pages carry their records in MCP
content and set `devicesInContent`. An unsupported endpoint is reported as an
upstream error, not an empty pending inventory.
`pageMetadata` retains all original page fields except the data array, which
is returned as `devices`; large metadata moves to MCP content with
`pageMetadataInContent`.

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

### `networks.list`, `networks.status`, and `networks.configure`

These workflows use the [official Network Integration API](https://developer.ui.com/network/v10.4.57/openapi.json).
`networks.list` accepts `offset` (0-2147483647), `limit` (1-200, default 50),
and the controller's documented `filter` query (at most 2048 bytes). `response`
retains the entire page, including additional controller metadata and fields.
Use `nextOffset` to continue. An empty page beyond the total is valid; an
inconsistent page returns its complete body with a separate diagnostic.

`networks.status` takes an official network `id` and returns its complete
configuration in `response`. `includeReferences: true` also returns the
controller's complete reference report. A reference lookup failure preserves
the network record and the full upstream error in `readbackError`.

`networks.configure` takes `operation` (`create`, `update`, or `delete`),
`id` for update/delete, and a typed `network` for create/update. Management
variants are `GATEWAY`, `SWITCH`, and `UNMANAGED`. Configuration covers VLANs,
DHCP guarding, IPv4 server or relay settings, IPv6 static or prefix delegation,
SLAAC, DHCPv6, router advertisements, outbound NAT, isolation, and zone membership.
The controller decides configuration validity and support. Updates replace the
complete typed configuration. Deletion exposes the controller's `force` option
(default false), including networks with references.

Calls preview by default and submit once with `confirm: true`. The complete
accepted HTTP status and original body appear in `responseStatus` and
`responseBody`, even if readback fails or acceptance is not JSON. Readback
reports `verified` for a matching configuration or `verifiedAbsent` after a
confirmed 404. A surviving record or the full upstream readback error remains
available. Ambiguous writes are never retried.

When structured output exceeds 48 KiB, complete requested records, bodies,
and errors move to labeled MCP text content with explicit `...InContent`
markers. Each upstream response remains bounded by the transport's 4 MiB limit;
an exceeded limit fails explicitly. The gateway controls access and disclosure.

### `radius_profiles.list`

`offset`, `limit` (1-200, default 50), and the documented `filter` page through the official Network
API's [RADIUS profiles](https://developer.ui.com/network/v10.4.57/getradiusprofileoverviewpage)
for the selected site. Each profile preserves the fields
the controller returned, including the id needed for enterprise Wi-Fi setup.
The result includes the controller's page metadata and `nextOffset` until the
list is complete. `pageMetadata` preserves all original page fields except
the data array, returned as `profiles`. Large values remain in MCP content,
marked by `profilesInContent` and `pageMetadataInContent`.
Contradictory page metadata returns the complete
accepted controller response with a separate validation diagnostic.

### `network.inventory.list/detail` and `network.switching.detail`

These tools use the [official Network Integration API](https://developer.ui.com/network/v10.4.57/openapi.json).
`network.inventory.list` accepts a `kind` of `countries`, `sites`, `clients`,
`devices`, `dpiApplications`, `dpiCategories`, `deviceTags`,
`lags`, `mcLagDomains`, `switchStacks`, `wanInterfaces`, `vpnServers`, or
`siteToSiteVpnTunnels`, plus `offset` and `limit` (1-200, default 50).
The documented `filter` query is available except for WAN interfaces, whose
endpoint has no filter parameter. Countries, sites and DPI dictionaries are controller-wide; other kinds
use the selected site. Each page returns complete controller records, page
counts, and `nextOffset`. `pageMetadata` preserves all original page fields
except the data array, which is returned as `records`. Large pages retain
records and metadata in MCP content, marked by `recordsInContent` and
`pageMetadataInContent`. Invalid page metadata
returns the complete controller response with a separate diagnostic.
Filtered DPI dictionaries continue according to returned rows and mark
`paginationBasis: "returnedRows"`, because controller totals can describe the
unfiltered catalog. A full final page can require one additional empty page;
its absence of `nextOffset` ends the scan. Original totals remain available.

`network.switching.detail` accepts `kind` (`lag`, `mcLagDomain`, or
`switchStack`) and the official `id`, returning the complete controller
record. A large record is carried in MCP content and marked by
`recordInContent`.

`network.inventory.detail` accepts `kind` (`client`, `device`, or
`deviceStatistics`) and the official record `id`. It returns the complete
connected client, adopted device, or latest device statistics record,
including unknown fields and interface details. Large records remain in
MCP content with `recordInContent`. Controller errors retain their full bodies.
`kind: "applicationInfo"` requires no `id` and returns complete Network
application information without a site lookup.

### `network.policy.list` and `network.policy.detail`

These tools read [ACL rules, firewall zones, firewall policies, DNS policies, and traffic matching lists](https://developer.ui.com/network/v10.4.57/openapi.json)
from the official Network Integration API. Choose `kind` as `aclRules`,
`firewallZones`, `firewallPolicies`, `dnsPolicies`, or `trafficMatchingLists`. The list accepts `offset`, `limit`
(1-200, default 50), and the documented `filter` query. It returns complete controller rows, page
counts, and `nextOffset`; large pages carry records in MCP content and set
`recordsInContent`. `pageMetadata` retains all original page fields except
the data array, returned as `records`; large metadata moves to MCP content
with `pageMetadataInContent`. Invalid page metadata returns the complete controller
response with a separate diagnostic. The detail tool accepts `kind` and the
official `id`, returning the complete record. A large record is carried in
MCP content and marked by `recordInContent`.

`acl.rules.configure`, `dns.policies.configure`, and
`traffic.matching_lists.configure` accept
`operation` (`create`, `update`, or `delete`) and preview by default. Create
requires `rule`, `policy`, or `list` respectively; update also requires `id`;
delete requires `id` without a request body. Set `confirm: true` to submit.
ACL rules cover the documented IPv4 and MAC variants, with typed source,
destination, protocol, network, and enforcing device filters. DNS requests cover A,
AAAA, CNAME, forwarding, MX, SRV, and TXT policies. Traffic lists cover IPv4
addresses, IPv6 addresses, and ports, including the documented item variants.
The tool returns the complete accepted controller record and HTTP status for
create or update, or the complete response body and status for delete. It also
reports the subsequent detail read and whether the requested values or
deletion were observed. A failed readback does not erase an accepted write.
Large values move to MCP content with a corresponding `InContent` marker.

`firewall.zones.configure` previews or creates, replaces, or deletes a custom
firewall zone. Create requires `zone: {name, networkIds}`; update also requires
`id`; delete requires `id` without a zone body. Empty network membership is
supported. Set `confirm: true` to submit. The complete accepted status and
record or deletion body remain available even when bounded readback fails.
Read complete zone records through `network.policy.list` and
`network.policy.detail` with `kind: "firewallZones"`. The controller decides
which zones and memberships can be changed; its rejection text is returned.

`firewall.policies.configure` previews or creates, replaces, or deletes a
zone-based policy. Create requires a full `policy`; update also requires `id`;
delete requires `id` without a body. Set `confirm: true` to submit. The typed
request exposes actions, source and destination zones, traffic filters, protocol
scope, connection states, IPsec matching, logging, and all four schedule modes.
Protocol names use the documented lowercase values such as `tcp`, `icmp`, and
`ipv6-frag`; the protocol preset is `TCP_UDP`. Region filters use country codes
from `network.inventory.list` with `kind: "countries"`. Cross-field validation
belongs to the controller.
Complete accepted records and readback errors use the shared policy response
contract. Read full records with `network.policy.list/detail` and
`kind: "firewallPolicies"`. The existing `firewall.policies.update` remains a
shortcut for changing `enabled` and/or `loggingEnabled` while preserving other
fields. Logging-only changes use the documented PATCH route.

The compact `firewall.read` policy summary supports earlier string action and
protocol fields and the current structured fields. It reports the original
`action.type` as `action` and `ipProtocolScope.ipVersion` as `ipProtocolScope`,
along with the controller's signed ordering index. Full action settings and
protocol filters remain available in `network.policy.detail` records and the
flag update workflow's complete `beforeResponse` and `afterResponse`.

`acl.rules.ordering.read` returns the complete priority ordering from the
official ACL ordering endpoint. `acl.rules.ordering.configure` previews a full
replacement `orderedAclRuleIds` list and sends it only with `confirm: true`. It
returns the complete accepted controller record and HTTP status, then reads
the ordering again to report whether the requested order persisted. A failed
or stalled readback leaves the accepted response available. Large records move
to MCP content with explicit markers.

### `wifi.broadcasts.list` and `wifi.broadcasts.status`

These tools use the [official Network Wi-Fi broadcast API](https://developer.ui.com/network/v10.4.57/getwifibroadcastpage).
`wifi.broadcasts.list` accepts `offset` (0-2147483647), `limit` (1-200, default 50),
and the documented `filter` query (at most 2048 bytes),
returns complete controller fields for each selected row, and supplies
`nextOffset` until the list is complete. `wifi.broadcasts.status` accepts a
`broadcastId` from that list and returns its complete controller record,
including security and network configuration. Additional controller page fields
remain in `pageMetadata`. Large pages or metadata move to labeled MCP content
with `broadcastsInContent` or `pageMetadataInContent`; a large detail record
moves to content with `recordInContent`. The original record fields remain
unchanged. Empty pages past the reported total are valid.
Contradictory page metadata returns the complete accepted controller response
with a separate validation diagnostic.

### `wifi.broadcasts.configure`

This tool exposes the [official Wi-Fi broadcast lifecycle](https://developer.ui.com/network/v10.4.57/openapi.json).
`operation` is `create`, `update`, or `delete`; update/delete take
`broadcastId`. Create/update take a complete typed `broadcast`, with
`type: "STANDARD"` or `"IOT_OPTIMIZED"` and the controller's documented
configuration fields. Security variants include open and enhanced open,
WPA2/WPA3 personal and enterprise modes, RADIUS configuration, multiple
pre-shared keys with network assignments, protected management frames, and SAE.
Other fields cover network and broadcasting device selection, client filtering,
mDNS and multicast handling, basic rates, blackout schedules, roaming, DTIM,
DNS assistance, hotspot modes, and MLO. The controller decides cross-field
validity and support; the server preserves its rejection body.

Calls preview by default. `confirm: true` submits once. Deletion exposes the
controller's `force` option (default false). `responseStatus` and `responseBody`
retain complete acceptance even when it is not JSON or readback fails.
`after`, `verified`, `verifiedAbsent`, and `readbackError` report bounded
observation. Large fields move to labeled MCP content with corresponding
`InContent` markers. Configuration and returned values are sensitive; the
gateway decides caller access and disclosure.

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
  official catalog names are missing. `namesStatus` identifies lookup failures,
  and `sourceErrors` carries each failed application or category lookup's
  controller response.
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
there is no silent scan truncation. Activity record, string, graph, identity,
counter, and arithmetic validation errors return the complete accepted
controller body with the local diagnostic.
A malformed or duplicate WAN comparison hour returns the complete accepted
hourly site response with the validation reason.
Display text uses visible truncation markers.
`sourceErrors` retains the controller's response and local diagnostic for
Activity, graph, legacy DPI, and catalog lookup failures. HTTP failures also
include the controller's status. A console-family
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
Select `view: "applicationInfo"` or `view: "recorder"` on `protect.overview`
for the complete official application or single recorder record. These views
use only the Integration API key and require no local session or camera
inventory reads. All fields remain available as `record`; large records move
to labeled content with `recordInContent`. `detailFields` applies to the
default `summary` view.
If the optional local inventory read fails, `cameras.search` and
`protect.overview` include the controller error in
`capabilities.localUnavailableReason`, and `cameras.status` includes it in
`localError`. Requests that need the missing local data return that error.
If the local bootstrap fails camera or recorder validation, that error includes
the complete accepted bootstrap body and the field that failed validation.
Duplicate public camera ids return the complete accepted inventory response
with the identity diagnostic. Duplicate local ids leave public inventory
available and put the complete local response in
`capabilities.localUnavailableReason`; a request requiring local details
returns that error directly. If public and local camera or recorder identities
conflict, the error includes both accepted source responses so the discrepancy
can be inspected without a second request.

`cameras.snapshot` fetches a JPEG from the official Protect API by camera id
or exact reported name. It returns MCP image content plus small structured
metadata, so an agent can inspect a frame without receiving a base64 string
as text. The `channel` input chooses `main` (default) or `package`; the latter
is for cameras with a package camera. `highQuality` requests 1080p or higher
when available. A response above 4 MiB fails explicitly.
A nonempty invalid JPEG returns the accepted controller response with the
decoder diagnostic. Non-UTF-8 bytes use base64; valid UTF-8 stays as text.
The same behavior applies to event thumbnails.

### `protect.devices.list` and `protect.devices.status`

These tools read the official Protect inventory and detail endpoints for lights,
sensors, chimes, sirens, fobs, relays, speakers, bridges, link stations, and
alarm hubs. `kind` selects one documented family. The list accepts `offset` and
`limit` (1-200, default 50), returns complete records for that page, and gives
`totalCount` and `nextOffset` until the inventory is complete. The detail tool
accepts the exact `deviceId` and returns its complete controller record.
Controller-specific fields remain present, including fields unknown to this
server. A wrong-id detail or malformed inventory returns the accepted response
with a validation diagnostic. An absent API route remains an error, while an
empty inventory has `totalCount: 0`. The upstream endpoints return complete
arrays; this server pages the bounded response locally. If a page exceeds the
MCP result budget, lower `limit`.

### `protect.devices.action`

This tool groups the documented 7.3.53 POST actions for sirens (`sirenPlay`,
`sirenStop`, `sirenTestSound`), relay outputs (`relayActivate`), speaker sound
tests (`speakerTestSound`), and alarm-hub outputs (`alarmHubTrigger`). The
`action.kind` selects a typed request; `deviceId` and, where needed,
`outputId` select exact devices and outputs. Optional fields retain the
controller's documented defaults. Siren play accepts 5, 10, 20, or 30 seconds;
test volumes use their documented ranges. The default preview sends no POST.
With `confirm: true`, the tool sends one POST and reports the accepted HTTP
status and any response body. The documented success status is 204, which
confirms that the controller accepted the action; it does not prove a physical
effect. Errors retain the controller's complete bounded body. Large accepted
bodies move to labeled content. The gateway decides access to these actions.

### `protect.devices.settings.update`

This tool previews and patches documented settings by exact `deviceId` for
lights, sensors, chimes, sirens, relays, speakers, fobs, bridges, link stations,
and alarm hubs.
`changes.kind` selects the device family and its typed fields. Light settings
include force enablement, mode, activation time, and hardware controls; sirens,
relays, and speakers expose their documented LED and audio settings. The other
four families expose their documented name setting. Sensor settings include
light, humidity, temperature, motion, glass break, alarm, schedule, and arm
profile controls. Chime settings include paired camera ids and per-camera
ringtone, repetition, and volume. An explicit `null` clears nullable sensor
thresholds or `armProfileIds`; omitted fields stay off the PATCH body.

Preview reads and returns the complete device record without a PATCH. With
`confirm: true`, the tool sends one PATCH containing only named fields, keeps
the controller's full bounded accepted body, then reads the device back and
reports the observed record and verification result. A failed readback keeps
the accepted write result and complete controller error. Large result fields
move to labeled content. The gateway decides caller access.

### `protect.arm_profiles.list`, `protect.arm_profiles.configure`, and `protect.alarms.action`

The list tool pages the complete arm-profile records from Protect's documented
`arm-profiles` endpoint. It accepts `offset` and `limit` (1-200, default 50)
and returns `totalCount` and `nextOffset` with each page. If the selected page
exceeds the structured-result budget, `profilesInContent` points to the
complete page in labeled content, including when one record alone is large.

The configuration tool previews or creates, updates, deletes, or selects an arm
profile. Create requires `name`, `automations`, `schedules`,
`recordEverything`, and `activationDelay` in `changes`. Update sends only
fields named in `changes`; delete and select use `profileId`. Activation delay
is one of 0, 60000, 300000, or 600000 milliseconds. The alarm action tool
previews or enables or disables the arm alarm, or invokes an alarm-manager
webhook with its exact `triggerId`.

Neither write tool sends a write request until `confirm: true`. Each confirmed
call sends one write and returns the controller's accepted status and complete
bounded body when present. Create, update, and delete read the arm-profile list
back when an id is available and report the observed record and verification
result. Select and alarm actions report acceptance without claiming a physical
effect. Large request previews, accepted bodies, and readback detail move to
labeled content. Controller errors retain their complete bounded body. The
gateway decides access.

### `protect.users.list` and `protect.users.status`

These tools read the Protect `users` and UniFi Identity `ulp-users` resources
documented in the Protect 7.3.53 API. `kind` is `user` or `identityUser`. The
list accepts `offset` and `limit` (1-200, default 50), returns complete records
for that page, and gives
`totalCount` and `nextOffset` until the inventory is complete. The detail tool
accepts the exact `userId` and returns its complete controller record. The
upstream Protect `users` endpoint filters users by its access permissions;
`ulp-users` lists only UniFi Identity users with enrolled credentials. The
documented Identity user `email` field is an empty string when no address is
set. Controller fields remain present, including fields unknown to this
server. A wrong-id detail or malformed inventory returns the accepted response
with a validation diagnostic. An absent API route remains an upstream error,
while an empty inventory has `totalCount: 0`. The upstream endpoints return
complete arrays; this server pages the bounded response locally. If a page
exceeds the MCP result budget, lower `limit`.

### `cameras.pos.transaction`

This tool previews and, when `confirm` is true, submits one point-of-sale
transaction for an exact Protect camera id through the API documented in
Protect 7.3.53. Consoles without this route return their upstream error. The
`transaction` object accepts the documented `type` (`sale` or `refund`),
`externalId`, and nonnegative `amount`, plus optional `currency`, `lineItems`,
`location`, `paymentTypes`, and `timestamp`. Preview returns the complete
request without posting it. If that request exceeds the structured-result
budget, the complete transaction is returned in content with
`transactionInContent: true`. A confirmed call returns the complete accepted
controller result in `response`,
including `created` and `eventId` when present. Large accepted results are
returned in an additional content block with `responseInContent: true`. A
200 response establishes a recorded event; it does not establish that video
exists for the transaction window. The upstream API allows timestamps in the
preceding 24 hours and up to five minutes ahead of its clock; it may clamp
allowed future values to now.

The upstream `externalId` behavior is best-effort idempotency for one camera
within a short in-memory window. It can create a duplicate after a restart or
after that window. The server never retries a POST after an ambiguous transport
result. An upstream 409 in-progress conflict retains its status and complete
body. Input and result sensitivity metadata tells the gateway what to govern.

### `protect.viewers.list/status` and `protect.liveviews.list/status`

These tools read viewer devices and live-view configurations from the Protect
7.3.53 API. Viewer records include their assigned live view and stream limit;
live-view records include their layout and camera slots. The tools preserve
the complete controller records, including future fields. Lists accept
`offset` and `limit` (1-200, default 50) and return `totalCount` and
`nextOffset` until complete. Detail reads use the exact `viewerId` or
`liveviewId`. An empty inventory is distinct from an absent route. Invalid
records or a wrong detail id return the accepted controller body with a local
diagnostic. A result that exceeds the MCP budget fails explicitly so the
caller can lower the page limit.

`protect.viewers.settings.update` previews the viewer's current record and a
typed change to its `name` or assigned `liveview`. An explicit `null` clears
the live-view assignment. With `confirm: true`, it sends one PATCH, returns
the complete accepted response, and reads the viewer back. `verified` is true
only when the requested fields appear in that read-back. Controller errors
retain their complete upstream body. A successful PATCH response remains in
the applied result even if it omits or changes the viewer id. Large records
move to labeled content blocks; the corresponding `InContent` flags identify
those fields. The gateway decides who may use the action and see its records.

`protect.liveviews.configure` accepts `operation: "create"` or `"update"`.
Its typed `changes` cover the documented name, default and global scope,
owner, layout, and per-slot camera lists and cycling settings. The API also
documents `id` and `modelKey` in the live-view object; callers can supply
these fields in `changes` when needed. An update uses an exact `liveviewId`.
The default preview returns the requested configuration and, for updates, the
complete current record. Confirmation sends one POST or PATCH and returns the
complete accepted result. An update reads back by its requested id even if
the PATCH response omits an id; a create reads back by the returned id. A
created result without an id, failed read-back, or timed-out read-back is
reported without claiming verification. Controller failures retain their full
bodies, and large accepted records move to labeled content blocks with
corresponding flags.

`cameras.settings.read` returns the complete camera record, including the
controller's LCD message and other reported fields. `cameras.settings.update`
patches only named settings. It accepts the documented doorbell LCD message
types `DO_NOT_DISTURB`, `LEAVE_PACKAGE_AT_DOOR`, `CUSTOM_MESSAGE`, and `IMAGE`.
Custom text and image asset names use the `text` field; an explicit `null`
`resetAt` means the message lasts until changed, while an omitted `resetAt`
uses the recorder's default timeout. The tool previews by default and, when
confirmed, returns complete before, accepted, and read-back camera records.
`verified` requires the requested fields to match and the other modeled
settings to stay unchanged. Invalid enum values, an empty change set,
out-of-range microphone volume, and requests above 1 MiB are rejected before
the write. Large complete records move to labeled content blocks, with
corresponding `InContent` flags.
When the read-back fails, `readbackError` carries the controller response
alongside the accepted patch response.
If an accepted patch response names another camera or reports a different
resource type, the error includes the complete controller body and the field
that did not match.

`cameras.ptz.control` previews or runs a preset move, patrol start, or patrol
stop for one camera. A preset slot of `-1` means home; patrol slots are `0` to
`4`. Confirmed patrol actions read the reported active slot back and state
whether it matches. The official API does not report position after a preset
move, so that action reports controller acceptance without claiming position
verification. `cameras.status` includes `activePatrolSlot` when reported by the
console; null means no patrol is running. A failed patrol read-back returns the
controller response in `readbackError`. Every confirmed PTZ action returns its
accepted HTTP status and complete controller body, even when a later readback
fails or times out. Large bodies and readback errors move to labeled content.

`cameras.microphone.disable` previews the complete camera record by default.
With `confirm: true`, it sends the official permanent microphone-disable POST
once, returns the accepted status and complete controller body, then reads the
complete camera record again. `verified` is true only when the camera reports
`isMicEnabled: false`; a failed read-back is reported without claiming the
microphone is disabled. Protect says restoring the microphone requires a
camera reset. Large records and responses move to labeled content blocks,
with `InContent` flags in the structured result.

`protect.assets.list` pages through complete records from Protect's documented
`animations` file family. Results include the controller's asset name,
original filename, type, path, and any additional fields. `totalCount` and
`nextOffset` show whether more records remain. `protect.assets.upload` accepts
one of the documented image or audio MIME types, a filename, and standard
padded `contentBase64`. It previews the decoded byte size by default. With
`confirm: true`, it sends one multipart `file` part to the fixed animations
route and returns Protect's complete accepted record. A follow-up list checks
whether the returned asset name appears; a failed or inconclusive readback
does not hide the accepted result. The upload is bounded to 3 MiB of decoded
data. HTTP ingress also applies its configured request-body limit (1 MiB by
default, adjustable to 4 MiB). Uploads above that default require a higher
configured ingress limit or stdio. Large accepted records move to labeled
content blocks.

`cameras.streams.list` returns the existing RTSPS stream URLs for a camera.
These URLs grant access to the camera feed, so the result is classified high
risk and sensitive. The gateway decides caller access in gateway mode.
`cameras.streams.update` previews by default;
with `confirm`, it creates or removes one or more distinct qualities: `high`,
`medium`, `low`, or `package`. A created URL is returned even if the follow-up
readback fails or times out. Creation and removal return their accepted HTTP
status and complete controller body. The result says whether the requested qualities
were observed afterward, and `readbackError` carries any controller failure.
For these camera mutations, a large accepted body or readback error moves to
a labeled text content block with a corresponding `InContent` marker, so an
accepted action result remains available.
`package` requires a camera with a package camera.

`cameras.talkback.start` previews or creates a talkback session. A confirmed
call returns its RTP URL, codec, sampling rate, bit depth, and accepted HTTP
status and complete controller body. Large bodies move to labeled MCP content
with an explicit marker. The API does not
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
limit instead of silently splitting it. A malformed accepted event page
returns the complete controller body with a separate validation diagnostic.
The per-page `limit` controls work
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
| `wlans.configure` | no | yes | yes |
| `clients.control` | no | no | yes |
| `devices.control` | no | no | yes |
| `devices.adopt` | no | yes | yes |
| `devices.remove` | no | no | yes |
| `acl.rules.configure` | no | yes | yes |
| `acl.rules.ordering.configure` | no | yes | yes |
| `dns.policies.configure` | no | yes | yes |
| `networks.configure` | no | yes | yes |
| `wifi.broadcasts.configure` | no | yes | yes |
| `firewall.zones.configure` | no | yes | yes |
| `firewall.policies.configure` | no | yes | yes |
| `traffic.matching_lists.configure` | no | yes | yes |
| `guests.authorize` | **no** | no | yes |
| `guests.unauthorize` | **no** | no | yes |
| `port_forwards.update` | yes | no | yes |
| `port_forwards.configure` | no | yes | yes |
| `firewall.policies.update` | yes | no | yes |
| `firewall.policies.delete` | yes | no | yes |
| `vouchers.create` | **no** | no | yes |
| `vouchers.revoke` | yes | no | yes |
| `cameras.ptz.control` | **no** | no | yes |
| `cameras.microphone.disable` | yes | no | yes |
| `protect.assets.upload` | **no** | yes | yes |
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
else moved. The confirmed result also returns the accepted HTTP status and
complete legacy controller envelope. A failed or stalled readback is reported
alongside that accepted response. Large controller bodies and readback errors
move to labeled MCP content with explicit markers.

If a wireless network or port forward snapshot cannot be decoded into its
typed record, the error includes the controller's complete accepted response
and the local decoding error.
An accepted detail response with no row, multiple rows, or a different id
returns the complete controller envelope and a local diagnostic.

Requested fields report their previous, requested, and observed values, including
passphrases when the caller changes one. The gateway governs access to sensitive
results.

`port_forwards.update` sends only named fields to the controller, including
the source, target, ports, and protocol. Its preview shows the requested
values and warns when the match or target changes; confirmed changes read the
rule back and report any field the controller dropped or changed.

### Legacy WLAN lifecycle and complete reads

`wlans.list` pages complete legacy WLAN records with `offset` and `limit`
(1–200, default 50). `wlans.status` takes `id` and returns the full detail
envelope. Controller metadata and configuration values remain available,
including passphrases and fields outside the compact network view. Collection
reads are bounded by the transport body limit and fail explicitly if exceeded.

`wlans.groups.list` takes `kind` (`userGroups`, `wlanGroups`, `apGroups`) and
the same pagination arguments. It returns complete group records for WLAN
configuration references. User and WLAN groups use legacy REST envelopes;
AP groups use the controller's v2 array response. `totalCount` and `nextOffset`
describe the fetched collection without a separate depth cap.

`wlans.configure` takes `operation` (`create`, `update`, `delete`), optional
`id`, optional typed `configuration`, and `confirm` (default false). Creation
requires configuration without a path id, update requires both, and delete
requires an id without configuration. Preview makes no controller request.
Configuration retains the controller's field names and exposes security,
WPA3 and SAE, private keys, RADIUS and MAC authentication, group and network
references, radio settings, roaming, filtering, schedules, and record
attributes. Passphrases and existing key configuration can be omitted. The
controller decides supported modes, valid combinations, and attribute
mutability. Requests are bounded to 1 MiB before submission.

Confirmation submits once, retaining the exact accepted `responseBody` and
`responseStatus`. Bounded readback returns the full envelope in `after`, with
`verified` for a matching id and requested fields, or `verifiedAbsent` for an
empty detail envelope or HTTP 404 after deletion. Failed observation retains
acceptance and the complete upstream response in `readbackError`. Large
responses, requested configuration, acceptance bodies, observations, and errors
move to labeled MCP content with corresponding `...InContent` markers. The
gateway owns caller authorization and disclosure.

### Port-forward lifecycle and complete reads

`port_forwards.list` pages complete legacy records with `offset` and `limit`
(1–200, default 50). The legacy collection is fetched once within the transport
body bound, then the selected records are returned under `response.data`.
`totalCount` and `nextOffset` describe that collection; controller envelope
metadata is preserved. An oversized collection fails explicitly rather than
silently losing records. `port_forwards.status` takes `id` and returns the
complete detail envelope, including fields outside the compact firewall view.

`port_forwards.configure` takes `operation` (`create`, `update`, `delete`),
optional `id`, optional typed `configuration`, and `confirm` (default false).
Creation requires configuration without a path id; update requires both; delete
requires an id without configuration. A preview makes no controller request.
Configuration uses the controller's field names: `_id`, `name`, `enabled`,
`src`, `fwd`, `fwd_port`, `dst_port`, `proto`, `destination_ip`, `log`,
`pfwd_interface`, `site_id`, `attr_hidden`, `attr_hidden_id`, `attr_no_delete`,
and `attr_no_edit`. Missing fields are omitted from the submitted body. The
controller decides accepted values, attribute mutability, and configuration
validity. Requests are bounded to 1 MiB before submission.

Confirmation submits once and retains the accepted `responseStatus` and exact
`responseBody`. Bounded readback returns the complete envelope in `after`.
`verified` means a single observed record has the expected id and requested
fields. Deletion reports `verifiedAbsent` only for an empty detail envelope or
an upstream HTTP 404; the latter response remains in `readbackError`. Failed
observation does not discard acceptance. Large `response`, `requested`,
`responseBody`, `after`, and `readbackError` values move to labeled MCP content
with corresponding `...InContent` markers. Upstream errors are returned in full
within the transport body bound. The gateway owns authorization and disclosure.

### Voucher creation and lifecycle

It takes `name`, `count`, `timeLimitMinutes`, and optionally `guestLimit` and
`dataLimitMegabytes`, and echoes all of them back under `batch`. A preview is
what this write is reviewed from, and two batches differing only in validity or
access limits are different batches — a count alone could not tell them apart.

The official voucher list and detail endpoints return each code. `vouchers.search`
pages through vouchers and `vouchers.status` reads one by id; both return codes
as sensitive results. `vouchers.revoke` previews a deletion and, when confirmed,
returns the controller's accepted status and complete body, then checks whether
the voucher disappeared from the detail endpoint. Its
`readbackError` carries the controller's response when that lookup fails or
still returns the voucher, including the HTTP 404 response used to confirm
absence. A slow lookup cannot erase the accepted deletion response. Large
accepted bodies and readback errors move to MCP content with explicit markers.
If a voucher page or detail response disagrees with the requested offset or id,
the error includes the complete accepted controller response alongside the
validation diagnostic, including fields outside the typed voucher view.

Creation checks the returned batch — whether as many came back as
were asked for, whether each carries an id and a code, whether the codes are
distinct, and whether each is free of whitespace and within a plausible length.
Code lengths are reported rather than judged: the controller decides the
format, and refusing a batch for being unfamiliar would condemn vouchers that
already exist. It also reads each identified voucher back and sets `verified`
only when the count matches and every id and code matches. A failed readback is
reported with the creation response in `readbackErrors`, with the voucher id
and complete controller response or error. `readbackComplete` says whether verification
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

### Firewall policy flag changes

`firewall.policies.update` takes `policy` and `changes` containing `enabled`,
`loggingEnabled`, or both. A logging change uses PATCH when the requested
`enabled` value is absent or already present. That sends only `loggingEnabled`
and leaves the other controller fields to the controller.

There is no partial update that can flip a policy's switch: the API's `PATCH`
accepts only the policy's logging flag, and its `PUT` requires the whole
policy. When `enabled` needs to change, this reads the policy, alters the
requested flags, and sends every other
property back exactly as it arrived — including properties this server does not
model, which is the point. A write that sent back only what it understood would
drop the rest, on the object that decides what the network permits.
The record must identify the requested policy before the write. A mismatched
id fails with the complete accepted controller response. If the write is
accepted but read-back identifies another policy, the result says `applied`
and carries that complete response in `readbackError` without claiming
verification.

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

Use `firewall.policies.configure` to create or replace the full source,
destination, protocol scope, actions, logging, and schedule.

### Actions: `clients.control`, `devices.control`, `guests.authorize`, `guests.unauthorize`

`clients.control` and `devices.control` read the controller afterwards and
report what it showed, along with what that observation is worth.
Guest actions read the Integration API client detail afterwards and report
whether the observed access matches the action response. A detail response
that fails identity or guest-state validation remains available in the error
or `readbackError`, including fields outside the typed client view.

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
connected, which is an observation and not a guarantee. Confirmed actions return
the accepted HTTP status and complete legacy controller envelope. A failed or
stalled readback is reported alongside that acceptance. Large controller bodies
and readback errors move to labeled MCP content with structured markers.

`devices.control` requires `port` for `portCycle` and rejects it for every other
action, so a port can never be sent with an action that would ignore it. A
restart takes longer than the read, so the state afterwards usually still shows
the prior value — it records what the controller showed, not that the action
finished. Confirmed actions retain the controller's accepted HTTP status and
complete response body, including the legacy locate command's envelope.
Readback failures are reported
alongside the accepted action, and long readbacks are bounded so they cannot
erase it. Large bodies move to MCP content with explicit markers.

### `devices.adopt` and `devices.remove`

These tools use the [official Network device API](https://developer.ui.com/network/v10.4.57/openapi.json).
`devices.adopt` accepts a `macAddress` from `devices.pending.list` and an
explicit `ignoreDeviceLimit` boolean. It previews by default. A confirmed
call makes one adoption request and returns the complete accepted device
record. When that record has an id, it reads the device back and reports the
complete observed record and whether the id matches. An upstream rejection
or ambiguous transport failure is returned without retry.

`devices.remove` accepts an adopted `deviceId` and previews by default. The
preview states that removing an online device resets it to factory defaults.
A confirmed call makes one DELETE, returns the controller's accepted HTTP
status and complete body, then reads the device id back. `verifiedAbsent`
is true only when that read returns HTTP 404; another returned record makes it
false. Readback failures retain the upstream response in `readbackError` and
leave absence unverified. Large accepted or observed records move into MCP
content with explicit markers.

`guests.authorize` returns the granted record and any grant it replaced.
Repeating authorization replaces the active grant and resets traffic counters,
so it is not idempotent. `guests.unauthorize` returns the revoked grant and
disconnects the client. Both actions mark `verified` true only when a bounded
read of the connected client reports the expected state and grant metadata.
The observed grant is returned separately when it can be read. If a disconnected
client is no longer readable, the action response remains available and the
result says that verification was unavailable. If the verification read fails,
`readbackError` carries the controller response alongside the action response.
If an accepted guest action response omits the required grant or revocation,
the error includes the complete controller body and the missing field.

### Rule deletion: `firewall.policies.delete`

`firewall.policies.update` returns the controller's exact `beforeResponse` in
its preview. A confirmed write also returns the accepted `responseStatus` and
`responseBody` and, when available, the exact `afterResponse`. Readback
failure is reported alongside the accepted write. Large response fields move
to MCP content with explicit markers.

`firewall.policies.delete` removes a zone-based policy by id. It previews the
policy's match and action, then sends one DELETE when confirmed. A following
read distinguishes a policy that is absent from one the controller retained.
The `readbackError` field carries the controller's response when that read
fails or returns an unexpected policy, including an HTTP 404 response that
confirms absence. A policy identity mismatch during preview returns the
complete accepted controller response with a separate validation diagnostic.
The preview shows full source, destination, protocol, connection-state, IPsec,
and schedule conditions alongside the compact policy summary. It also shows
the official descriptive and metadata fields when present. It marks whether
these bounded views cover the controller record and names omitted fields when
they do not; those fields may change the policy's effect. `beforeResponse`
retains the complete controller record even when the compact preview omits
fields. A confirmed deletion returns the accepted `responseStatus` and
`responseBody` alongside readback. Large responses move to MCP content with
explicit `InContent` markers. The gateway governs caller access to sensitive
results.

## Remaining rule workflows

Creation, ordering, and the remaining rule lifecycle operations are tracked
in the Network rule issue.
