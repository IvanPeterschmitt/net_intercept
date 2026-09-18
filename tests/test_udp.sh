#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "UDP packet interception"

load_module

sudo dmesg -C

echo "[TEST] Generating UDP traffic..."

if command -v dig >/dev/null 2>&1; then
    dig google.com A +time=2 +tries=1 > /dev/null 2>&1 || true
else
    echo "[WARN] 'dig' is not installed."
    echo "[WARN] Install it with:"
    echo "       sudo apt install dnsutils"
    unload_module
    exit 1
fi

sleep 1

echo "[TEST] Checking kernel logs..."

if check_intercept "UDP"; then
    pass "UDP packet was intercepted"
else
    unload_module
    fail "No intercepted UDP packet found"
fi

unload_module
