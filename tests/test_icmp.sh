#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "ICMP packet interception"

echo "[INFO] Network interface: ${INTERFACE}"
echo "[INFO] Local IP: ${LOCAL_IP}"

load_module

echo "[TEST] Generating ICMP traffic..."

sudo dmesg -C

ping -c 3 -W 2 8.8.8.8 > /dev/null 2>&1 || true

sleep 1

echo "[TEST] Checking kernel logs..."

if check_intercept "ICMP"; then
    pass "ICMP packet was intercepted"
else
    unload_module
    fail "No intercepted ICMP packet found"
fi

unload_module
