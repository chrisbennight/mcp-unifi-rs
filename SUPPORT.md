# Getting help

Check [connection troubleshooting](docs/transports.md#troubleshooting),
[configuration](docs/configuration.md), and
[controller compatibility](docs/compatibility.md) first.

For a non-security problem, open a
[GitHub issue](https://github.com/chrisbennight/mcp-unifi-rs/issues/new) with:

- Server version or image digest, OS, and client/version.
- Network or Protect application version and whether it runs on UniFi OS.
- Connection mode: stdio, direct HTTP, or gateway.
- The tool name and a minimal redacted call, expected result, and actual error.
- Whether the problem began after a server, client, or controller upgrade.

Never attach `.env`, bearer headers, controller keys, local account passwords,
Wi-Fi credentials, or voucher codes. Redact controller names, IPs, MACs and
camera locations when they are not needed to reproduce the issue. A synthetic
fixture is more useful than an unfiltered controller export.

For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) before posting
details. Do not put an exploitable issue or credential value in a public report.

For a feature request, describe the operator task and desired bounded result.
Include the relevant Ubiquiti API reference when available. This helps decide
whether it fits an existing workflow tool or requires a new capability.
