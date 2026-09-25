#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "Filtering by CIDR, protocol, and destination port"

if [[ -z "${LOCAL_IP}" ]]; then
    fail "Unable to determine the local IPv4 address"
fi

cleanup() {
    unload_module
}

trap cleanup EXIT

unload_module

echo "[INFO] Local IP: ${LOCAL_IP}"
echo "[TEST] Loading a TCP filter for HTTPS replies to the local host..."

sudo dmesg -C

sudo insmod "${KO_FILE}" \
    mode=log \
    ip_src=0.0.0.0/0 \
    ip_dest="${LOCAL_IP}/32" \
    proto=tcp \
    port_src=443

echo "[TEST] Generating matching TCP traffic..."
curl --connect-timeout 5 \
     --max-time 10 \
     -s \
     https://example.com \
     > /dev/null || true

sleep 2

if ! sudo dmesg | grep -Eq "\[NET_INTERCEPT\] Intercepted packet: protocol=6, .*:443 -> ${LOCAL_IP}:"; then
    fail "Matching TCP traffic was not logged"
fi

pass "CIDR, protocol, and source-port filtering matched TCP traffic"
