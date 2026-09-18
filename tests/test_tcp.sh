#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "TCP packet interception"

load_module

sudo dmesg -C

echo "[TEST] Generating TCP traffic..."

curl --connect-timeout 5 \
     --max-time 10 \
     -s \
     https://google.com \
     > /dev/null || true

sleep 1

echo "[TEST] Checking kernel logs..."

if check_intercept "TCP"; then
    pass "TCP packet was intercepted"
else
    unload_module
    fail "No intercepted TCP packet found"
fi

unload_module
