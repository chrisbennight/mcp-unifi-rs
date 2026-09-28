# Retained traffic collection

The optional collector copies the controller's hourly traffic reports directly
to an operator-owned InfluxDB OSS 2.x bucket. Grafana queries that bucket without
an MCP caller or model. Fully retrieving the supplied reports is collection
success; differences between router and attributed client bytes do not invalidate
that success. A valid empty report is successful too.

## Enable collection

Create a dedicated InfluxDB OSS 2.x bucket and a token with write permission for
that bucket. Use a separate read-only token for Grafana. Retention must exceed
the collection history window and the longest outage you intend to recover from.
InfluxDB Cloud's asynchronous writes and InfluxDB 3 are not supported by this
publication protocol.

Configure the existing Network controller environment described in
[configuration](configuration.md), including its TLS settings and site. Then set:

```sh
UNIFI_MCP_COLLECTION_ENABLED=true
UNIFI_MCP_COLLECTION_ID=office-default
UNIFI_MCP_COLLECTION_INFLUX_URL=https://influx.example.net
UNIFI_MCP_COLLECTION_INFLUX_ORG=operations
UNIFI_MCP_COLLECTION_INFLUX_BUCKET=unifi-traffic
UNIFI_MCP_COLLECTION_STATE_DIR=/var/lib/unifi-collection
```

Inject `UNIFI_MCP_COLLECTION_INFLUX_TOKEN` through your service's secret-backed
environment. Never put its value in shell commands, configuration examples, or
logs. InfluxDB HTTPS uses system certificate roots; HTTP is available for trusted
local connections. The collector never follows redirects or environment proxies.

Run the existing HTTP or gateway service with those settings, or run
`mcp-unifi-rs --transport collect` for a collector-only process without an MCP
listener or gateway credentials. This mode uses the existing Network runtime
configuration, including the Integration key setting, although collection itself
uses the legacy report client. Continuous collection is rejected in stdio mode,
whose lifetime is controlled by an interactive client. A collector-only container
has no HTTP health endpoint: override the image's default HTTP healthcheck with
a check of the process and `status.json` update time, or run collection alongside
the HTTP service to retain the native healthcheck.

Mount a persistent writable state directory owned by the service account. Keep
one directory and one stable collection ID per controller/site/destination.
All replicas for that collection must share this directory on a filesystem with
working exclusive file locks. A second worker cannot acquire the lock. Separate
directories do not provide distributed leader election and must not be used to
run concurrent writers for the same collection ID. Changing the controller URL,
site, collection ID, organization, bucket, or destination requires a new state
directory. Names and credentials may change without changing storage identity.

The collector uses a separate controller session and one sequential worker.
Sink outages do not fail MCP requests or its health endpoint. Controller and
sink requests have timeouts; cancellation interrupts pending network work.

## Configuration

| Variable | Default | Contract |
| --- | --- | --- |
| `UNIFI_MCP_COLLECTION_ENABLED` | `false` | `true` enables collection; otherwise no sink or state access |
| `UNIFI_MCP_COLLECTION_ID` | required when enabled | Stable controller/site identity, up to 128 ASCII letters, digits, dots, dashes, underscores |
| `UNIFI_MCP_COLLECTION_INFLUX_URL` | required when enabled | HTTP(S) origin, without credentials, query, fragment, or path prefix |
| `UNIFI_MCP_COLLECTION_INFLUX_ORG` | required when enabled | Destination organization |
| `UNIFI_MCP_COLLECTION_INFLUX_BUCKET` | required when enabled | Dedicated traffic bucket |
| `UNIFI_MCP_COLLECTION_INFLUX_TOKEN` | required when enabled | Runtime-injected bucket-write token |
| `UNIFI_MCP_COLLECTION_STATE_DIR` | required when enabled | Persistent service-owned state directory |
| `UNIFI_MCP_COLLECTION_CADENCE_SECONDS` | `300` | Delay between cycles, 60–3600 seconds |
| `UNIFI_MCP_COLLECTION_DELAY_SECONDS` | `600` | Settlement delay after an hour ends, 0–86400 seconds |
| `UNIFI_MCP_COLLECTION_HISTORY_HOURS` | `24` | Requested recovery window, 1–168 hours; does not assert that the controller retains it |
| `UNIFI_MCP_COLLECTION_CORRECTION_HOURS` | `3` | Re-read recent hours, 1–history hours |
| `UNIFI_MCP_COLLECTION_INTERVALS_PER_CYCLE` | `4` | Maximum intervals per cycle, 1–24 |

The worker requests aligned, completed UTC hours using the same explicit start
and end for all sources. A round-robin cursor covers missing intervals and recent
corrections without repeatedly favoring the oldest failure. There is a one-second
pause between intervals and a bounded cycle deadline. Older missing intervals
eventually leave the configured recovery window and increment `expired_gaps`.
No historical measurement is fabricated. There is no promise of backfilling data
the controller no longer provides.

## Retained schema

Schema version `1` retains every JSON field and its numeric spelling from the
supported sources: Network Activity `v2/traffic`, its `app-traffic-rate` graph,
and the hourly WAN report response (including its envelope metadata). Report
data is complete, including identifiers, names, fingerprints, unknown fields,
and application detail. Collection is restricted to these report endpoints;
it is not a generic API proxy. Authentication headers and session credentials
are not part of report data.

Each source response is bounded by the existing API client's body limit. Typed
record bounds are explicit failures, never silently accepted subsets. These
sources currently return complete bounded reports rather than upstream pages.
The collector bypasses MCP display pagination and top-N truncation. An
unrecognized JSON report is retained with an unrecognized status. A failed
source retains the controller's status and response body in its archived
`error` field, including a malformed WAN report's original body and decode
diagnostic. An Activity or graph HTTP 404/405 remains classified as
`unsupported` and retains that response in `error`. Successfully retrieved
sources are retained even when another source fails.

All measurements use `collector` as the stable controller/site identity and the
requested hour's start as their timestamp, with millisecond write precision.
Immutable records also carry a SHA-256 `revision` tag of the archived snapshot.

| Measurement | Fields and purpose |
| --- | --- |
| `unifi_publication` | One `revision` string field selects the fully written revision for an hour |
| `unifi_interval` | Requested boundaries, schema, archive chunk count, collection result, each source status, available totals and signed differences |
| `unifi_client` | Client MAC tag, unsigned `rx_bytes` and `tx_bytes`, full `name_json` string field |
| `unifi_archive` | `part` tag and base64 `data` string field; decode parts separately and concatenate in numeric part order to reconstruct the snapshot JSON |

`name_json` contains a JSON string or `null` inside an InfluxDB string, preserving
newlines, quotes and other name characters without line-protocol injection.
The archive preserves names exactly. Raw report data never enters operational
status or routine logs.

Client bytes use the client perspective: receive/download and transmit/upload.
WAN counters retain the source's receive/transmit values. Client and application
totals are checked unsigned sums. Signed unmatched values are WAN minus clients;
they can be negative. WAN values and differences use the controller's floating
point representation; exact original numbers remain in the archive. Missing WAN
counters are absent, not zero. Invalid or duplicate client counters prevent
derived totals, but the complete original report remains retained and collection
success is unchanged. No accounting-quality score is computed.

## Corrections and restart recovery

The worker validates a publication and saves `pending.json` before writing it.
It writes immutable revision records in bounded batches and waits for each OSS
2.x `204` response before writing the publication selector. OSS 2.x documents
`204` as fully ingested and queryable; other responses are failures. See
[InfluxDB write responses](https://docs.influxdata.com/influxdb/v2/write-data/troubleshoot/).

After a lost response or restart, the same pending revision is replayed before
any new report is fetched. Point identities are deterministic, so replay does
not add usage. Only a successful selector acknowledgement advances the local
publication checkpoint. A crash after that acknowledgement can cause another
identical replay, which has the same result.

Corrections select a new immutable revision. Queries must join on the selector;
old clients and omitted fields then disappear from the selected report without
destructive delete operations. Old revisions and interrupted writes remain in
the bucket until retention removes them. Size retention for report revisions,
including archive chunks and correction cadence, not just current client rows.

A persistent rejected pending write deliberately pauses new collection instead
of dropping that report. Repair destination access, schema, or retention and
the next cycle retries. Preserve pending data before any manual state repair.
The status file and service log indicate that publication needs attention.

## Operational status

`status.json` in the state directory contains only last collected/published
intervals, update time, publication lag, written point count, sink availability,
bounded failure categories, the recent interval success map, and expired gap
count. Its own update time distinguishes a stopped worker from a recent success.
An interval is complete only when all sources were retrieved and its publication
was acknowledged. Empty reports count as retrieved reports. Source status is
also stored in `unifi_interval` for dashboard use.

Traffic records and credentials are excluded from this status file. Protect the
state directory nevertheless: `pending.json` holds the complete report. Reading
the destination or interactive MCP reports remains governed by downstream access
policy; collection does not introduce privacy modes or alter MCP authorization.

## Grafana queries

Configure a Grafana InfluxDB data source using Flux and the separate read-only
token. The following query plots per-client hourly download/upload bytes for
the selected publication. Substitute your bucket and collection ID. Use bytes
as the panel unit and sum nonoverlapping hours for longer-period totals.

```flux
selected = from(bucket: "unifi-traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "unifi_publication" and r._field == "revision" and r.collector == "office-default")
  |> rename(columns: {_value: "revision"})
  |> keep(columns: ["_time", "collector", "revision"])
  |> group(columns: ["collector"])

clients = from(bucket: "unifi-traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "unifi_client" and (r._field == "rx_bytes" or r._field == "tx_bytes") and r.collector == "office-default")
  |> group(columns: ["collector"])

join(tables: {data: clients, selected: selected}, on: ["_time", "collector", "revision"])
  |> group(columns: ["client", "_field"])
  |> keep(columns: ["_time", "_value", "client", "_field"])
```

For router totals and the unexplained remainder, use the same selector and join
with `unifi_interval`, filtering `_field` to `site_rx_bytes`, `site_tx_bytes`,
`unmatched_rx_bytes`, and `unmatched_tx_bytes`. Keep negative differences visible.
For collection state, use the same join with `collected`, `activity_status`,
`graph_status`, and `wan_status`; use separate panels for booleans and strings.
Do not fill missing measurements with zero, and do not sum across revisions.
Grafana queries should align their selected time range to whole hours.

For archive retrieval, join `unifi_archive` with the selector over the desired
hour, order the `part` tag numerically, base64-decode each `data` field, and
concatenate. Verify the reconstructed JSON's SHA-256 equals the revision. This
recovers the original report fields even when they have no dashboard projection.
