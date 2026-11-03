#!/bin/sh
# The enclave's init: bring loopback up (an enclave boots with it down), point every host
# the updater connects to at its tunnel, raise the file limit, and run the updater.
set -eu
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set dev lo up
cat /app/hosts >> /etc/hosts
# Every tunnelled connection holds three descriptors in here (the vsock, the loopback pair),
# and the default soft limit of 1024 is the hard limit's quarter: take all of it.
ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
exec /usr/local/bin/quote-updater --config /run/quote-updater/config.toml --enclave /app/enclave.toml
