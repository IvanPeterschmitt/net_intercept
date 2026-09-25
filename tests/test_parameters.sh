#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "Module parameter validation"

cleanup() {
    unload_module
}

trap cleanup EXIT

expect_rejected() {
    local description="$1"
    shift

    unload_module

    if sudo insmod "${KO_FILE}" "$@" > /dev/null 2>&1; then
        fail "Invalid configuration was accepted: ${description}"
    fi

    pass "Rejected ${description}"
}

expect_rejected "unknown mode" mode=observe
expect_rejected "unknown protocol" proto=sctp
expect_rejected "invalid source IPv4 address" ip_src=300.1.1.1
expect_rejected "invalid CIDR prefix" ip_dest=192.168.1.0/33
expect_rejected "source port below range" port_src=0
expect_rejected "destination port above range" port_dest=65536
expect_rejected "drop mode without an explicit criterion" mode=drop

unload_module

echo "[TEST] Loading a valid combined configuration..."
sudo insmod "${KO_FILE}" \
    mode=drop \
    ip_src=10.0.0.0/8 \
    ip_dest=192.168.1.0/24 \
    proto=udp \
    port_src=53 \
    port_dest=5353

if ! module_loaded; then
    fail "Valid configuration did not load"
fi

pass "Accepted valid mode, CIDR, protocol, and port parameters"
