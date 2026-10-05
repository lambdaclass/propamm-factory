# The quote updater binary, built from a crate in this repo. By default that is `example/`
# (the binary `my-propamm`); a binary of your own is a crate directory beside it, named by
# the CRATE and BIN build arguments (deploy/.env sets them for compose). The build context is
# the repository root, so the crate's `path = "../quote-updater"` dependency resolves.
ARG RUST_VERSION=1.98.1

FROM rust:${RUST_VERSION}-bookworm AS build
ARG CRATE=example
ARG BIN=my-propamm
WORKDIR /src
COPY . .
# --locked: the crate's Cargo.lock decides every version, so two builds of one commit are
# the same binary. A crate of your own needs its Cargo.lock committed for this to pass.
RUN cargo build --release --locked --manifest-path "${CRATE}/Cargo.toml" --target-dir /build \
 && install -m 0755 "/build/release/${BIN}" /quote-updater

FROM debian:bookworm-slim
# ca-certificates and libssl3 for the TLS the venue and builder websockets use; curl for the
# container's health check against /metrics.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /quote-updater /usr/local/bin/quote-updater
# The config file and the keys come from compose: CONFIG points at the mounted file, the
# UPDATER_KEY_* variables come from deploy/.env. Arguments appended by `docker compose run`
# (such as --check) land after the binary name.
ENTRYPOINT ["/usr/local/bin/quote-updater"]
