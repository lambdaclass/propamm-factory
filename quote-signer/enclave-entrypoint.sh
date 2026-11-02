#!/bin/sh
# The enclave's init: bring loopback up (the enclave boots with it down), point the
# forwarded services' names at their loopback ports, and run the signer.
set -eu
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set dev lo up
cat /app/hosts >> /etc/hosts
exec /usr/local/bin/quote-signer --config /app/config.toml
