# Network traffic fixtures

`network_10_6_106_traffic.json` preserves selected traffic field names, types,
and absence from bounded read-only checks of Network 10.6.106 on 2026-09-27.
MAC addresses and all client numeric values are synthetic. Unrelated fields
are omitted. The fixture is a projection, not a complete controller response.

The wired sample has only `wired-tx_bytes` and `wired-rx_bytes`; the wireless
sample has `tx_bytes` and `rx_bytes`. The observed DPI response was exactly
`{"meta":{"rc":"ok"},"data":[{}]}`. A separate read reported DPI enabled,
so the empty object is not evidence that traffic identification is disabled.
No nonempty application response was observed; the other diagnostic tests
cover independently sourced flat and `by_app` contracts with synthetic data.

Tests serve these fixtures on loopback and never query a live controller.

`network_10_6_106_activity.json` projects the v2 Activity response observed on
2026-09-27. Client names, MAC addresses, and byte values are synthetic. It
preserves the separate client/application tables, numeric classification IDs,
and directional byte fields. Tests also preserve the graph timestamp shape and
the official taxonomy's filtered response whose total still names the full
catalog. Unrelated fingerprints and configuration are excluded from MCP output.
See [traffic history](../../../../docs/traffic-history.md) for the live source
evidence and remaining accounting limitations.
