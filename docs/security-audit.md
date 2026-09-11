# Migration security audit

## Scope and evidence

The GitHub root commit imported one current source tree with no Gitea parents.
Historical Gitea commits, local deployment secrets and operational data were not
part of that import. This review covers the tracked source, fixtures, Docker
build context, image publication and transport boundaries. It does not certify
the safety of data outside that scope.

The initial imported-code review used Gitleaks 8.30.1 with fully redacted output
on an exported tracked snapshot. It returned zero findings. CI repeats the scan
for each candidate with the pinned official image in the workflow. A text sweep
also checked private service references, credential assignments and key blocks;
those results were reviewed separately because a credential scanner does not
classify all private information.

## Findings and dispositions

| Finding | Disposition |
| --- | --- |
| Private registry, CI and gateway setup assumptions | GitHub workflows use public dependencies and GHCR. Independent client setup and separate Network/Protect examples replace required lab deployments. Optional gateway mode remains supported. |
| Private gateway actor in synthetic authentication fixtures | Replaced with `gateway.example.net`; it was an expected test string, not a credential or required service. |
| Private domain in a workflow regression test | Retained as a forbidden-string sentinel; it prevents reintroducing that dependency and is not contacted. |
| Fake passwords, API keys and bearer strings in tests | Retained as synthetic test inputs; tests use loopback servers or containers without external network access. |
| Local `.env.*` files and nested private keys could enter Docker contexts | Expanded exclusions and added a regression that exports a real Docker context and checks which synthetic files survive. Git also ignores local environment variants. Documented example files remain included. |
| Review policy still assumed every HTTP client supplied a gateway JWT | Updated policy to distinguish gateway, direct HTTP and stdio, and include the new ingress/logging files in sensitive paths. |
| Stale private-only security reporting instructions | Documented the current private collaborator route and the separate administrator requirement for a monitored public-facing private report channel. Enabling that channel remains an administration task. |
| Branch rules and dependency service enrollment do not transfer with Git | Documented the actual GitHub check names and required enrollment verification. A passing PR does not prove these settings are enforced. |

## Fixtures and dependency provenance

The committed Protect JSON fixtures use explicit synthetic identifiers, a
locally administered MAC (`020000000001`), null names and synthetic display text.
Their tests model the 7.1.87 response shape; they are not evidence that a live
controller version passed the suite. Integration tests run against loopback
fakes. Contributors must build minimal synthetic fixtures instead of committing
raw controller responses, logs, screenshots or media.

The repository's existing [MIT license](../LICENSE) and attribution were retained.
The audited lockfile resolves 336 external packages from crates.io and three
workspace packages; all declared a license in Cargo metadata. This is a snapshot
observation, not a permanent count or a claim that all dependencies are MIT.
License alternatives and combined terms remain those of their upstream packages;
source and binary redistribution must retain applicable third-party notices.
The lockfile identifies versions and registry checksums. No private or Git-based
Rust dependencies were found.

Gitleaks is the maintained upstream credential scanner from
[gitleaks/gitleaks](https://github.com/gitleaks/gitleaks); Syft is the maintained
software inventory tool from [anchore/syft](https://github.com/anchore/syft).
Both CI images are pinned by version and digest. They run with no network,
read-only input mounts and no Docker daemon socket. Scanner-image downloads
occur through Docker before those isolated runs. Neither tool is part of the
server runtime.

## Transport and mutation review

Ingress authenticates before dispatch. Direct HTTP rejects missing, wrong or
duplicate bearers and unlisted Host/Origin values; caller-supplied identity
metadata cannot grant independent clients write or disclosure permissions.
Stdio trusts the process owner and bounds input framing. Tool annotations do
not authorize a call. Request limits and redaction remain enforced in the server.

The transport regression suite exercises malformed protocol metadata, denied
access, separate grants, successful inventory calls, oversized messages,
stdout framing and payload-log suppression. Controller text is treated as data,
not an interpreter input. Clients still need to resist instructions embedded
in tool results; redaction is not a prompt-injection detector.

Mutation tests cover preview, validation before writes, read-back failures,
ambiguous outcomes, and one-time voucher results. Once a voucher response is
received, its bounded checks are synchronous and retain the returned codes even
when those checks fail. A lost response can still lose those codes. Full-policy
firewall updates can race an external editor because that upstream API has no
conditional partial write; the documented warning remains applicable.

No new controller operations were needed for this migration. Published software
inventories and their limits are described in [distribution](distribution.md).
