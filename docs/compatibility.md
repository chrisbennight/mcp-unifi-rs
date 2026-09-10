# Controller compatibility

This server talks to a UniFi console over two APIs. Which one serves
a given capability is not a preference — it is whichever one exposes the data
at all. This document records that split, what changes between console
generations, and how the difference is made visible rather than guessed at.

## The two backends

**The Integration API** (`/proxy/network/integration/v1` for Network and
`/proxy/protect/integration/v1` for Protect) is the official,
versioned, documented surface. It authenticates with an API key, returns
camelCase JSON, and paginates explicitly. It is the primary backend and the one
to prefer for anything it covers, because its shape is a published contract
rather than an observation.

**The legacy controller API** is what the console's own web interface uses. It
authenticates with a local admin session, returns snake_case records wrapped in
a result envelope, and is not versioned. It exists here because a large part of
what an operator actually needs — wireless configuration, port forwards,
events, historical statistics — has no Integration API equivalent.

Its shape depends on the console. A UniFi OS console logs in at
`/api/auth/login`, serves the API under `/proxy/network/api/s/{site}`, and
issues a CSRF token that mutations must echo back. A standalone controller logs
in at `/api/login`, serves `/api/s/{site}`, and uses no CSRF token.

The client works out which it is talking to on its first login rather than
requiring the operator to say, and remembers the answer for the session. One
case deliberately does not settle it: a rate-limited or server-error response
proves nothing about which routes exist, so no family is recorded and the next
login probes again. Latching on that answer would misroute a standalone
controller for the life of the process because it was probed during an outage.

Neither is a general escape hatch. Both are wrapped in typed, allowlisted
models; there is no path from a caller to an arbitrary endpoint on either.

## Which backend serves what

| Capability | Backend | Why |
| --- | --- | --- |
| Application version, site list | Integration | Published and stable. |
| Device inventory, detail, statistics | Integration | Richer and typed. |
| Device restart, port power cycle | Integration | Official action endpoints. |
| Client list, guest authorization | Integration | Official, and the guest action exists only here. |
| Zone-based firewall zones and policies | Integration | The only place they exist. |
| Hotspot vouchers | Integration | The only place they exist. |
| Site health subsystems | Legacy | No Integration equivalent. |
| Connected client detail | Legacy | Carries signal, uplink, and access point attribution the Integration client record omits. |
| Networks and wireless networks | Legacy | Wireless configuration is legacy-only. |
| Wireless network updates | Legacy | Follows from the read. |
| Client block, unblock, reconnect | Legacy | No Integration equivalent. |
| Port forwards, traffic rules, traffic routes | Legacy | No Integration equivalent. |
| Events and alarms | Legacy | No Integration equivalent. |
| Deep packet inspection totals, WAN history | Legacy | No Integration equivalent. |
| Neighboring access points | Legacy | No Integration equivalent. |
| Device locate LED | Legacy | The Integration action set does not include it. |
| Protect camera identity and connection state | Integration | Documented inventory; nullable names and the `camera` resource discriminator are preserved. |
| Protect recorder identity | Integration | The documented endpoint returns one NVR object with the `nvr` resource discriminator. |
| Protect historical detections | Local Protect session | The official subscription is realtime rather than a historical query. |

A tool that needs both crosses between them by hardware address, which is the
one identifier both APIs report for the same thing.

The table describes where each capability's data comes from, not which tools
ship. Some rows back a tool today, and some back a client method the tool
surface does not yet expose.

## Console generations

UniFi Network 9.0 replaced the classic rule-based firewall with a zone-based
one. A console upgraded from an earlier release may still run the classic
firewall; a console set up on 9.x runs the zone-based one. They are not
variations of one model — a zone-based console has no classic rules, and a
classic console has no zones or policies.

**This server supports the zone-based firewall only.** A classic console is
refused by name rather than served, which is the whole reason the generation is
still detected: both answer "no rules" in a way that looks identical from the
outside, and a firewall audit that reported an empty policy list on a classic
console would be describing an open network that is in fact filtered. Detecting
the generation is what turns that silence into a refusal:

- The server probes the zone endpoint on each read that depends on the
  answer. Success means zone-based. It is not cached: the server is stateless,
  and a console can be migrated between two calls, so a remembered answer would
  eventually describe a firewall the console no longer runs.
- The console's documented rejection for that endpoint — an HTTP 400 whose
  message names the zone-based firewall — means classic. Any other rejection is
  a request failure and propagates; it never classifies.
- `firewall.read` and `firewall.policies.update` both refuse a classic console
  by naming the generation. The read's refusal also names `portForwards`,
  `trafficRules`, and `trafficRoutes`, which read identically on either
  generation and remain available by narrowing.

## How a firewall change is written

A zone-based policy accepts no useful partial update, unlike every other write
here. The official Integration API's partial
update accepts only the policy's logging flag, and its full replace requires
the policy's action, source, destination, protocol scope, logging flag, name,
and enabled state together.

`firewall.policies.update` therefore resends the policy exactly as it was just
read, altering only the switch. Nothing interprets the record in between, so a
property this server does not model cannot be dropped by the write — which on
the object that decides what the network permits is the failure that matters.

What it cannot do is merge. An edit made elsewhere between the read and the
write is overwritten, because the interface offers no way to avoid that, and
the preview says so before the change is confirmed.

## Version assumptions

The server does not pin a Network release. It asks the console what it is:

- The application version is read from the console and reported by
  `network.overview`, so a result can be matched to the console that produced
  it.
- The firewall generation is probed rather than inferred from the version,
  because the version does not determine it — an upgraded console reports 9.x
  and can still run the classic firewall.

Where an endpoint exists on some releases and not others, the read reports the
absence explicitly instead of returning an empty list.

## Sites

One deployment addresses one console. The legacy API addresses a site by the
configured name directly. The Integration API identifies a site by an opaque
id, which the server resolves at runtime by finding the site whose internal
reference matches that name.

When no site matches and the controller reports exactly one site, that sole
site is used, because a controller does not always report the site key an
operator configured and failing there would make the common single-site
deployment need a value the operator cannot easily discover. The consequence is
worth knowing: on a multi-site controller a name matching nothing is an error,
but on a single-site controller the Integration calls address the site that
exists while the legacy calls keep using the configured name, so a wrong name
shows up as failing legacy reads rather than as a clean rejection.

See [the configuration reference](configuration.md).
