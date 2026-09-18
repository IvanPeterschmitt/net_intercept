#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "Module loading/unloading"

echo "[INFO] Project root: ${PROJECT_ROOT}"
echo "[INFO] Module: ${MODULE}"
echo "[INFO] Kernel: $(uname -r)"

echo "[TEST] Building module..."
make -C "${PROJECT_ROOT}"

if [[ ! -f "${KO_FILE}" ]]; then
    fail "Kernel module was not generated"
fi

echo "[TEST] Loading module..."
load_module

if ! module_loaded; then
    fail "Module is not loaded"
fi

pass "Module loaded successfully"

echo "[TEST] Unloading module..."
unload_module

if module_loaded; then
    fail "Module is still loaded"
fi

pass "Module unloaded successfully"
