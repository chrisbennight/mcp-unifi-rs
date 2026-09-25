# Controller compatibility

This page describes the APIs this implementation uses. It does not claim that
other APIs lack equivalent operations. Ubiquiti continues to expand its
[application APIs](https://developer.ui.com/), including documented
[Wi-Fi Broadcast reads](https://developer.ui.com/network/v10.1.84/getwifibroadcastdetails).
Those reads do not by themselves establish support for the writes implemented here.

## Connection and permission requirements

| Deployment | Required access | Current behavior and evidence |
| --- | --- | --- |
| UniFi OS console running Network | Network Integration API key and a dedicated local account for legacy routes | Uses `/proxy/network/integration/v1` and the Network application session API; both must be available for the full Network tool set |
| Standalone or self-hosted Network application | Depends on its Integration API route and local account support | Legacy login/route detection is covered by fake tests, but the Integration client still uses the UniFi OS proxy prefix; this is not a verified end-to-end standalone deployment |
| UniFi OS console running Protect | Protect Integration API key | Basic camera and recorder inventory works without a local session |
| Protect with local-session enrichment | Protect key plus a dedicated local account allowed to read the relevant application data | Adds hardware/firmware/recording/recorder details and historical events; those routes are not the public Integration API contract |
| Controller accounts requiring MFA or cloud SSO | Interactive login | Not implemented; use a dedicated local account |
| Site Manager cloud API or UniFi Access | Separate API credentials and endpoints | Not implemented |

Network and Protect may share a physical console, but each process selects one
application and reads only its credentials. Create the key for that application,
not a Site Manager cloud key. Follow Ubiquiti's application API instructions for
your installed version. The local session client accepts username/password
login; use a dedicated account and restrict its controller permissions where
possible. The server's read/write grants limit what its clients may invoke;
they do not reduce the privileges of the stored controller account.

## Supported versions

The compatibility target is deliberately limited to these application versions
on UniFi OS consoles. Other versions and standalone Network deployments are
not supported targets. We do not maintain fallbacks for retired event and alarm
APIs.

| Application | Supported target | Live evidence |
| --- | --- | --- |
| UniFi Network | 10.6.106 | Application version, local login, subsystem health, connected-client reads, and system-log reads/count filters checked on 2026-09-25 |
| UniFi Protect | 7.2.105 | `protect.overview` with public inventory and local-session enrichment checked on 2026-09-25 |

These checks exercise the named reads. They do not claim that every tool or
mutation has been exercised against a live controller. Automated regression
tests use loopback fakes and never change a production network.

Automated tests use loopback fakes, not live consoles. Protect fixtures record
the 7.1.87 response shape with synthetic identifiers. This verifies parsing of
that shape, not every behavior of that release or a promise about later releases.
The [Protect API documentation](https://developer.ui.com/protect/v7.2.105/gettingstarted)
and the Network API catalog are references for public endpoints. Local-session
routes require separate testing when a console upgrade changes them.

The server reports application versions and checks capabilities such as the
firewall generation. Those checks do not extend the supported version range.
An absent endpoint, authentication failure, malformed response, and an empty
inventory are different outcomes; failures are not converted into an empty
list. File a compatibility issue with the application version, tool, and
redacted error if the documented setup does not work.

## Backend used by each capability

| Capability | Backend used here |
| --- | --- |
| Network version, sites, device inventory/detail/statistics | Network Integration API |
| Guest authorization and its client ID resolution | Network Integration API |
| Device restart and port power cycle | Network Integration API |
| Zone-based firewall zones/policies and hotspot vouchers | Network Integration API |
| Health, connected-client inventory/context, networks and wireless networks | Network legacy API |
| Wireless updates, client block/unblock/reconnect, device locate | Network legacy API |
| Port forwards, traffic rules/routes, historical statistics, neighboring APs | Network legacy API |
| Network event search, recent client events, overview event counts | Network v2 system-log API, using the local session |
| Protect camera and recorder identity | Protect Integration API |
| Protect hardware/firmware/recording and recorder/storage enrichment | Optional Protect local session |
| Historical Protect detections | Protect local session |

The legacy client detects UniFi OS login (`/api/auth/login`) versus standalone
login (`/api/login`). Network routes are then `/proxy/network/api/s/{site}` or
`/api/s/{site}` respectively. Rate limits and server errors do not establish a
route family. This detection applies to the legacy client only; it does not
change the Integration API prefix.

Both clients use typed, bounded responses. Neither exposes arbitrary endpoint
forwarding. See the [tool reference](tool-surface.md) for the available actions.

## Network 10.6 system logs

Network 10.6.106 returned HTTP 404 with `api.err.NotFound` for both
`stat/alarm` and `stat/event` during the live checks. `network.overview` failed
at its alarm read even though version, login, health, and client reads worked.
`list/alarm` was also rejected and is not a fallback.

The replacement is `POST /proxy/network/v2/api/site/{site}/system-log/all`.
Its request uses `timestampFrom`, `timestampTo`, `pageNumber`, `pageSize`,
and optional `severities`. Its response uses `data`, `page_number`,
`total_element_count`, and `total_page_count`. This local-session endpoint
is not part of the public Integration API contract. The live checks verified
the response shape, one-row total queries, HIGH/VERY_HIGH filtering, and
client identifiers under `parameters.CLIENT.id`. That identifier is a MAC
address for ordinary network clients, but VPN events can use other identifiers.
Event rows populate `clientMac` only for valid unicast client MAC addresses;
other events remain visible without `clientMac`.
[Unpoller's implementation](https://github.com/unpoller/unifi/blob/master/system_log.go)
provided the initial route and field reference; the installed controller's
bounded responses were the compatibility evidence.

This changes the tool contract: `network.overview` replaces `activeAlarms`
and `activeAlarmsSaturated` with `recentEvents`, containing 24-hour totals
and the counting window. High-severity history is not an outstanding alarm
count. `events.search` replaces `kind` with optional `severity`; rows expose
`category` and `severity` instead of `kind` and `subsystem`. `clients.context`
uses system logs for recent events. Retired routes are not retried.

System-log failures identify the operation in the tool error. The API logger
records the fixed endpoint name `network.system_log` and the HTTP status for
controller rejections, without response bodies, credentials, or event text.
These records use the existing process logging pipeline and can be queried
in Loki where the deployment collects the server's logs.

## Firewall generations

Ubiquiti introduced zone-based firewalling in Network 9.0 and documents a
[migration for existing configurations](https://help.ui.com/hc/en-us/articles/28223082254743-Migrating-to-Zone-Based-Firewalls-in-UniFi).
Its [requirements](https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi)
include a supported gateway and Network 9.0 or later. The version alone does
not prove that migration has happened.

This server reads and updates zone-based policies. Before a generation-dependent
operation, it probes the zone endpoint. Success identifies zone-based mode; the
specific documented rejection naming zone-based firewalling identifies classic
mode. Other failures remain errors. The result is not cached across calls.

A broad `firewall.read` or `firewall.policies.update` refuses classic mode.
On either generation, a narrowed `firewall.read` can still read `portForwards`,
`trafficRules`, or `trafficRoutes`. It never represents unsupported classic
rules as an empty zone-based policy list.

## Firewall writes and concurrent edits

The implemented policy update sends the full policy as read, changing only the
enabled flag, because the applicable replacement endpoint requires the full
record. Unknown properties survive the round trip. An external edit between
that read and write can be overwritten; the controller interface supplies no
conditional update used by this implementation. The preview warns about this.
After the write, the server reads back and reports what persisted.

## Sites

One Network process addresses one configured legacy site name, defaulting to
`default`. Integration calls resolve the corresponding opaque site ID by its
internal reference. If no reference matches and the controller reports exactly
one site, the Integration client uses that sole site. Legacy calls continue to
use the configured name. Consequently, a wrong name can fail legacy reads even
when an Integration read succeeds. On a multi-site controller, no matching site
is an error. See [configuration](configuration.md#controller).
