#!/bin/sh
# The enclave's init: bring loopback up (an enclave boots with it down), point every host
# the updater connects to at its tunnel, and run the updater.
set -eu
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set dev lo up
cat /app/hosts >> /etc/hosts
exec /usr/local/bin/quote-updater --config /run/quote-updater/config.toml --enclave /app/enclave.toml
