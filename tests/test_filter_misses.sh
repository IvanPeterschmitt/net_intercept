#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "Negative filtering criteria"

if [[ -z "${LOCAL_IP}" ]]; then
    fail "Unable to determine the local IPv4 address"
fi

cleanup() {
    unload_module
}

trap cleanup EXIT

run_non_matching_case() {
    local description="$1"
    shift

    unload_module

    echo "[TEST] ${description}"
    sudo insmod "${KO_FILE}" \
        mode=log \
        "$@"

    sudo dmesg -C

    curl -4 \
         --connect-timeout 5 \
         --max-time 10 \
         -s \
         https://172.66.147.243:443 \     # IP address and port of example.com, to avoid DNS resolution and ensure HTTPS traffic
         > /dev/null || true

    sleep 2
    sudo dmesg
    if sudo dmesg | grep -q "\[NET_INTERCEPT\] Intercepted packet:"; then
        fail "Traffic unexpectedly matched: ${description}"
    fi

    pass "No packet matched: ${description}"
}

unload_module

run_non_matching_case \
    "source address mismatch" \
    ip_src=192.0.2.0/24 \
    ip_dest="${LOCAL_IP}/32" \
    proto=tcp \
    port_src=443

run_non_matching_case \
    "destination address mismatch" \
    ip_src=0.0.0.0/0 \
    ip_dest=192.0.2.1 \
    proto=tcp \
    port_src=443

run_non_matching_case \
    "protocol mismatch" \
    ip_dest="${LOCAL_IP}/32" \
    proto=udp \
    port_src=53

run_non_matching_case \
    "source port mismatch" \
    ip_dest="${LOCAL_IP}/32" \
    proto=tcp \
    port_src=444

run_non_matching_case \
    "destination port mismatch" \
    ip_dest="${LOCAL_IP}/32" \
    proto=tcp \
    port_dest=1
