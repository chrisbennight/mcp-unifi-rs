# Project work

Current work is tracked in [GitHub issues](https://github.com/chrisbennight/mcp-unifi-rs/issues)
and delivered through pull requests. Issues describe the problem, intended
behavior, compatibility constraints, and verification needed for a change.

The project provides curated Network and Protect tools over stdio and HTTP.
It keeps controller credentials outside client-visible results, bounds reads,
and makes mutation previews and uncertain outcomes explicit. See
[design decisions](DECISIONS.md), [architecture](docs/architecture.md), and the
[tool reference](docs/tool-surface.md) for the implemented contracts.

Propose a new capability with a concrete operator task, the supporting UniFi
API, the required permissions, and the expected result. A new endpoint is not
by itself a reason for a new tool. Site-specific deployment and secret-provider
configuration belong to their operators.
