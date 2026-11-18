# Build environment for the release binaries.
# The Rust image is the official Debian 13 (trixie) variant, pinned by digest.
# Dependabot proposes new versions.
FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    CARGO_NET_RETRY=5

# C toolchain for aws-lc-sys and libsodium-sys-stable, plus tools the build script uses.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake clang pkg-config perl git curl ca-certificates python3 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Cargo tools used by the build. Versions come from build/versions.yml through build args.
ARG CARGO_AUDITABLE_VERSION
ARG CARGO_DENY_VERSION
ARG CARGO_AUDIT_VERSION
ARG CARGO_CYCLONEDX_VERSION
RUN cargo install --locked \
      "cargo-auditable@${CARGO_AUDITABLE_VERSION}" \
      "cargo-deny@${CARGO_DENY_VERSION}" \
      "cargo-audit@${CARGO_AUDIT_VERSION}" \
      "cargo-cyclonedx@${CARGO_CYCLONEDX_VERSION}" \
 && rm -rf /usr/local/cargo/registry

WORKDIR /src
