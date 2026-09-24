# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e

ARG RUST_VERSION=1.98.1

FROM rust:${RUST_VERSION}-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS builder
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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
ARG SOURCE_REVISION=""
LABEL org.opencontainers.image.source="https://github.com/chrisbennight/mcp-unifi-rs" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
COPY --from=builder /usr/local/bin/mcp-unifi-rs /mcp-unifi-rs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/mcp-unifi-rs", "--healthcheck"]

ENTRYPOINT ["/mcp-unifi-rs"]
