# Distribution and maintenance

## Available artifacts

The repository publishes a Linux x86-64 container to
`ghcr.io/chrisbennight/mcp-unifi-rs`. There are no separately published native
binaries or tested ARM images. Source builds use the locked Cargo dependencies;
CI validates Linux with the toolchain in `rust-toolchain.toml`.

GitHub Actions publishes only after source checks, source scanning, the image
build and isolated smoke tests succeed. The publishing job loads the exact
saved image from that workflow run and checks its source-revision label. It does
not rebuild the image. Pull requests have no publication credentials.

The smoke test uses the image tagged for that commit and disables registry pulls.
If the locally built image is missing, validation fails rather than testing a
different image downloaded under the same tag.

Each publication gets `sha-<full-commit>`. A push to `main` also updates `latest`;
a version tag such as `v1.2.3` publishes that version without moving `latest`.
Version tags must match the format enforced by [image_tags.py](../scripts/image_tags.py).
A rebuilt tag can identify different bytes, so use a registry digest for a
repeatable deployment. Package visibility and pull permissions are separate
from repository visibility.

## Verify and retain a deployment

1. Select a successful main or version-tag build in
   [GitHub Actions](https://github.com/chrisbennight/mcp-unifi-rs/actions/workflows/build.yml)
   and record its full source revision.
2. Pull the corresponding `sha-<full-commit>` image, authenticating to GHCR if
   the package is private. Record the `sha256:` registry digest printed by
   Docker, then use `ghcr.io/chrisbennight/mcp-unifi-rs@sha256:<digest>` in the
   deployment. See GitHub's [pull by digest instructions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#pull-by-digest).
3. Inspect the pulled image with `docker image inspect`. Check
   `org.opencontainers.image.source`, `org.opencontainers.image.revision`, OS
   and architecture against the selected workflow and host. A label provides
   a consistency check; it is not a cryptographic attestation.
4. Retain the digest, source revision, protected configuration and software
   inventory alongside your deployment record. Do not put credentials in an
   issue or shared artifact.

CI attaches a `software-inventory` artifact to the build for 30 days. It contains
SPDX JSON inventories of the tracked source and tested container, image metadata,
the source revision, and SHA-256 checksums. Source inventory includes lockfile
dependencies for multiple platforms and tests; it is not an exact list of crates
linked into the executable. Image scanners can miss statically linked Rust
components, so use both inventories. Missing license or version fields mean
the scanner could not determine them.

The checksum for `image.tar` describes the saved Docker archive, available for
one day on publishing runs. It is different from a registry manifest digest.
Checksums detect a mismatched download but do not authenticate its author.
Inventories are not vulnerability scans or signed attestations. Preserve them
before Actions retention expires if you need a longer record.

GitHub build attestations were considered but are not enabled. For private
repositories they require an eligible Enterprise Cloud plan; access has not
been established here. The tested-image transfer currently uses `docker save`
and `docker load`, so it does not claim to preserve BuildKit attestations. See
[GitHub's availability and verification requirements](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Upgrade and rollback

Read changes since your recorded revision, including tool contracts,
configuration and controller compatibility. Keep the old image digest and
configuration, then start the new image with the same explicit transport and
permissions. Check liveness and make a read-only inventory call before enabling
workflows that confirm changes.

The server has no persistent application database to migrate. Rolling back means
redeploying the saved image digest with its matching configuration. It does not
undo changes already made to a controller. Secret rotations and controller
upgrades may also make an old configuration or image unusable; verify those
separately. Do not retry a timed-out confirmed action as part of a health check.

## Repository administration

Require pull requests on `main` and the current-head checks `test / test`,
`image`, and `pr-review/gate`. Prevent force pushes and deletion of `main`.
An administrator must apply and verify these rules in GitHub; committing a
workflow does not enforce branch protection. Request AERB through its GitHub
integration for every candidate and inspect the actual current-head result.
Its installation and posting access must cover this repository.

The existing [Renovate configuration](../renovate.json) permits routine image,
workflow and scanner updates and security-driven Cargo updates. Cargo lockfile
maintenance is disabled. Renovate must be installed or enrolled for this GitHub
repository; the configuration alone does not schedule it. Administrators should
verify a dependency update PR, enable available dependency alerts, and keep
the service's permissions limited to its needs. Do not carry over private Gitea
collaborator names or assume its webhook and permissions transferred.

Before public visibility, establish the monitored private reporting route
described in [SECURITY.md](../SECURITY.md). Repository visibility, package
visibility, protected-branch rules and security notifications are separate
settings, and none is implied by a merge.
