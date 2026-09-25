#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "Dropping matching TCP traffic"

if [[ -z "${LOCAL_IP}" ]]; then
    fail "Unable to determine the local IPv4 address"
fi

cleanup() {
    unload_module
}

trap cleanup EXIT

unload_module

echo "[INFO] Local IP: ${LOCAL_IP}"
echo "[TEST] Loading a drop rule for HTTPS replies to the local host..."
sudo insmod "${KO_FILE}" \
    mode=drop \
    ip_dest="${LOCAL_IP}/32" \
    proto=tcp \
    port_src=443

sudo dmesg -C

echo "[TEST] Generating matching TCP traffic..."
curl -4 \
     --connect-timeout 5 \
     --max-time 10 \
     -s \
     https://example.com \
     > /dev/null || true

sleep 2

if ! sudo dmesg | grep -Eq "\[NET_INTERCEPT\] Dropped packet: protocol=6, .*:443 -> ${LOCAL_IP}:"; then
    fail "Matching TCP traffic was not dropped"
fi

pass "Matching TCP traffic was dropped"
