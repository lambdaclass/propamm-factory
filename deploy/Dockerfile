# The quote updater binary: the crate in example/, which is the updater this deployment
# runs. Your own pricing models go in its main.rs. The build context is the repository
# root, so its `path = "../quote-updater"` dependency resolves.
ARG RUST_VERSION=1.98.1

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
# --locked: example/Cargo.lock decides every version, so two builds of one commit are the
# same binary.
RUN cargo build --release --locked --manifest-path example/Cargo.toml --target-dir /build \
 && install -m 0755 /build/release/my-propamm /quote-updater

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
