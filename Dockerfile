# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG RUST_VERSION=1.96.0

FROM rust:${RUST_VERSION}-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950 AS builder
WORKDIR /app

# Optional public or operator-managed Cargo mirror. Do not put credentials in
# build arguments; they can be retained in build metadata. Leaving this unset
# uses crates.io. Keep the name outside Cargo's reserved CARGO_ namespace.
ARG CRATES_INDEX_URL

COPY . .

# Source replacement preserves the crates.io identities in Cargo.lock.
RUN if [ -n "${CRATES_INDEX_URL}" ]; then \
      mkdir -p .cargo && \
      printf '\n[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' \
        "${CRATES_INDEX_URL}" >> .cargo/config.toml; \
    fi
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --bin mcp-unifi-rs \
    && cp target/release/mcp-unifi-rs /usr/local/bin/mcp-unifi-rs

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77 AS runtime
ARG SOURCE_REVISION=""
LABEL org.opencontainers.image.source="https://github.com/chrisbennight/mcp-unifi-rs" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
COPY --from=builder /usr/local/bin/mcp-unifi-rs /mcp-unifi-rs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/mcp-unifi-rs", "--healthcheck"]

ENTRYPOINT ["/mcp-unifi-rs"]
