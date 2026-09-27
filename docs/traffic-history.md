# Internet traffic history

`stats.query` can answer which clients and applications the controller attributes
Internet usage to over a requested interval. It does not provide exhaustive
packet accounting or create a retained monitoring database.

## Verified controller sources

Bounded read-only discovery on Network 10.6.106 on 2026-09-27 inspected the
installed Activity UI and the following sources. The deployed MCP at discovery
was revision `112889582ce52721a526691a6c272500a3efb69a`; that version had the older
unavailable client-history response. Discovery did not alter configuration.

| Source | Evidence and use |
| --- | --- |
| `GET /proxy/network/v2/api/site/{site}/traffic?start=...&end=...&includeUnidentified=true` | Activity UI request. Returns `client_usage_by_app` and `total_usage_by_app` with numeric application/category IDs and separate `bytes_received`/`bytes_transmitted` counters. UI descriptions call this Internet activity and map received to download, transmitted to upload. Fixed historical windows returned nonempty results. |
| `POST /proxy/network/v2/api/site/{site}/app-traffic-rate` with the same query and `{}` | Activity graph request. Returns `timestamp` and `interval_seconds`, rounded directional byte rates, and total bytes. The MCP projects only sample timestamps as temporal evidence; it does not integrate rounded rates into fabricated byte totals. Whether a timestamp labels a bucket's start or end was not established. |
| `POST /proxy/network/api/s/{site}/stat/report/hourly.site` | Existing hourly WAN counters. Requests identical fixed boundaries and excludes the row whose timestamp equals the end boundary when comparing complete hourly labels. Fractional source counters make the differences approximate. |
| `GET /proxy/network/integration/v1/dpi/applications` and `/dpi/categories` | Official taxonomy, using a bounded numeric `id.in(...)` filter. Application ID combines category in the upper 16 bits and application in the lower 16 bits; observed mappings included GitHub, Docker, and SSL/TLS. Missing names remain unknown. The controller's filtered `totalCount` still described the entire catalog, so it cannot drive pagination of a filtered selection. |
| `GET /proxy/network/v2/api/site/{site}/traffic-flow-latest-statistics?period=DAY&top=...` | Nonempty application ranking, but only combined bytes and a relative period. Useful discovery evidence; the fixed-window Activity source provides better directional and temporal detail. |
| Legacy `stat/sitedpi`, historical `hourly.user`, and `aggregated-dashboard` | Prior evidence remains in [compatibility](compatibility.md#traffic-counter-evidence). Those reads alone did not establish usable application traffic and WAN-only client attribution. |

Local-session credentials must allow Activity and historical-report reads;
the existing Integration API key resolves optional taxonomy names. No credential
values are exposed. The fixture in [the fixture guide](../crates/unifi-mcp/tests/fixtures/README.md)
uses synthetic identities and byte values while preserving observed field shapes.

## Reading the result

For a relative week, call:

```json
{"report":"clientWanHistory","hours":168,"limit":50}
```

For repeatable pagination or application comparison, copy
`counterSemantics.requestedStartMs` and `requestedEndMs` into `startMs` and `endMs`
and omit `hours`. Both endpoints require complete UTC hours. Call
`dpiApplications` with the same boundaries and the desired `top` value.

`activity.clientTotals` includes all returned clients before pagination;
`applicationTotals` includes the complete returned application table before
ranking. Discovery found those two tables agreed for inspected windows, while
WAN totals were materially larger. The implementation does not assume that
agreement will always hold.

`reconciliation` exposes site minus client totals separately for download and
upload. Negative differences are retained. Missing, invalid, or duplicate WAN
hours must not create a believable complete comparison. Site graph sample bounds
are reported separately from the requested window. They do not certify the
retention horizon, per-client observed interval, or absence of gaps.

The controller does not itemize the discrepancy by IPv6, UDP/QUIC, VPN,
gateway-originated traffic, proxying, counter resets, or interface accounting.
These remain possible limitations, not diagnosed causes. Classifier labels such
as SSL/TLS do not identify the actual application process. The server sums each
client/application record once, rejects duplicate identities, and does not join
LAN association counters or add site application totals to client totals.

## Completion boundary

Useful attributed history and named application rankings are delivered by these
reads. Complete WAN accounting, exact per-client observed collection intervals,
and explanations of every unmatched byte remain unverified. Do not close that
remaining work merely because fixture tests pass or the response says `partial`.

If exhaustive attribution is required, the next investigation must establish a
complete gateway accounting source and its retention before proposing collection
changes. There is no evidence that missing past measurements can be recovered.
Any additional collector or retention configuration belongs in the deployment
infrastructure, with a separately reviewed proposal stating whether only future
history is possible. Existing Grafana/data-source infrastructure can consume
these bounded results; this server is not a separate reporting application.
