# The quote-signer binary with the Nitro key release, packaged for `nitro-cli
# build-enclave`. The build context is the repository root; the config and the hosts file
# come from a directory you point BUILD_DIR at (default `quote-signer/enclave/`), holding:
#
#   config.toml   the signer's config: vsock listener, nitro keys, policy, forwards
#   hosts         lines appended to /etc/hosts inside, pointing each forwarded service's
#                 name at its loopback port, e.g. `127.0.0.1 kms.eu-west-1.amazonaws.com`
#
# Neither holds a secret: the keys arrive as KMS ciphertext at boot, over vsock.
ARG RUST_VERSION=1.98.1
ARG BUILD_DIR=quote-signer/enclave

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
# --locked: the workspace Cargo.lock decides every version, so the image measurement is a
# function of the commit and nothing else.
RUN cargo build --release --locked -p quote-signer --features nitro --target-dir /build \
 && install -m 0755 /build/release/quote-signer /quote-signer

FROM debian:bookworm-slim
ARG BUILD_DIR
# ca-certificates for the TLS to KMS and the venue through the tunnels; iproute2 to bring
# the loopback interface up, which an enclave does not do by itself.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /quote-signer /usr/local/bin/quote-signer
COPY ${BUILD_DIR}/config.toml /app/config.toml
COPY ${BUILD_DIR}/hosts /app/hosts
COPY quote-signer/enclave-entrypoint.sh /app/entrypoint.sh
CMD ["/bin/sh", "/app/entrypoint.sh"]
