# The quote updater for an AWS Nitro enclave: the crate in example/ built with its
# `aws-nitro` feature, packaged for `nitro-cli build-enclave`. The build context is the
# repository root. The enclave file and the hosts file come from the directory ENCLAVE_DIR
# names (default deploy/aws-nitro/local, gitignored; start it from the examples beside this
# file, see docs/enclave.md): enclave.toml and hosts. Neither holds a secret; the secrets
# and the config arrive at boot from the host.
ARG RUST_VERSION=1.98.1

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
# --locked against example/Cargo.lock, which pins every crate in the binary, the feature's
# included. What is not pinned: the two base images (tags, not digests) and the Debian
# packages below, so two builds of one commit can measure differently. The key policy in
# docs/enclave.md pins the signing certificate (PCR8), not the measurement, so that does not
# stop a release; pin by digest before relying on a measurement (PCR0) instead.
RUN cargo build --release --locked --manifest-path example/Cargo.toml \
      --features aws-nitro --target-dir /build \
 && install -m 0755 /build/release/my-propamm /quote-updater

FROM debian:bookworm-slim
ARG ENCLAVE_DIR=deploy/aws-nitro/local
# ca-certificates: the certificates every TLS connection is checked against, sealed into the
# image with everything else. libssl3: the TLS the venue, builder and RPC connections use.
# iproute2: to bring the loopback interface up.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /quote-updater /usr/local/bin/quote-updater
COPY ${ENCLAVE_DIR}/enclave.toml /app/enclave.toml
COPY ${ENCLAVE_DIR}/hosts /app/hosts
COPY deploy/aws-nitro/entrypoint.sh /app/entrypoint.sh
CMD ["/bin/sh", "/app/entrypoint.sh"]
