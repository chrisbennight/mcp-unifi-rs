# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG RUST_VERSION=1.96.0

FROM rust:${RUST_VERSION}-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950 AS builder
WORKDIR /app

# Where crates come from. This stage reaches the network, and the fleet wants
# that traffic through its caching proxy - but Docker gives a RUN step an
# environment built from this file rather than the caller's, so the address has
# to arrive as a build argument.
#
# Cargo reads no environment variable for a mirror, so unlike pip or npm it
# cannot simply be told: the redirect has to be a config file, appended from
# this value below. The name stays outside cargo's own CARGO_ namespace on
# purpose - cargo maps CARGO_REGISTRY_INDEX onto its removed registry.index key
# and aborts every invocation, and an ARG is visible to RUN as an environment
# variable, so that spelling would break the build it was meant to route.
#
# Left unsupplied it stays unset, no source is pinned, and cargo resolves from
# crates.io. That fallback is what keeps this image buildable away from the
# network the proxy lives on.
ARG CRATES_INDEX_URL

COPY . .

# Source replacement rather than an additional registry: it redirects the
# existing crates.io source instead of introducing a second one, so Cargo.lock
# goes on naming crates-io and a lock produced here still resolves from the
# public index.
#
# Appended rather than written, so whatever else .cargo/config.toml carries is
# preserved. The repository's copy deliberately no longer pins a source: a
# committed mirror address would be a hard dependency on a host that resolves
# only on the LAN, which is exactly what this argument exists to avoid.
RUN if [ -n "${CRATES_INDEX_URL}" ]; then \
      mkdir -p .cargo && \
      printf '\n[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' \
        "${CRATES_INDEX_URL}" >> .cargo/config.toml; \
    fi
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --bin unifi-mcp-rs \
    && cp target/release/unifi-mcp-rs /usr/local/bin/unifi-mcp-rs

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77 AS runtime
ARG SOURCE_REVISION=""
LABEL org.opencontainers.image.source="https://gitea.cacahuate.org/bennight/unifi-mcp-rs" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
COPY --from=builder /usr/local/bin/unifi-mcp-rs /unifi-mcp-rs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/unifi-mcp-rs", "--healthcheck"]

ENTRYPOINT ["/unifi-mcp-rs"]
