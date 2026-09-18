#!/bin/bash

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="net_intercept"
KO_FILE="${PROJECT_ROOT}/${MODULE}.ko"
LOG_TAG="\[NET_INTERCEPT\]"

# Interface réseau principale.
INTERFACE="${INTERFACE:-$(ip route | awk '/default/ {print $5; exit}')}"

# IP de la machine.
LOCAL_IP="${LOCAL_IP:-$(ip -4 addr show "${INTERFACE}" |
    awk '/inet / {print $2}' |
    cut -d/ -f1 |
    head -n1)}"

print_test() {
    echo
    echo "========================================"
    echo "[TEST] $1"
    echo "========================================"
}

pass() {
    echo "[PASS] $1"
}

fail() {
    echo "[FAIL] $1"
    exit 1
}

module_loaded() {
    lsmod | grep -q "^${MODULE}"
}

load_module() {
    if module_loaded; then
        echo "[INFO] Module already loaded"
        return 0
    fi

    sudo insmod "${KO_FILE}"
}

unload_module() {
    if module_loaded; then
        sudo rmmod "${MODULE}"
    fi
}

clear_test_logs() {
    # On ne peut pas simplement vider dmesg sur tous les systèmes.
    # On mémorise donc le timestamp actuel.
    TEST_START_TIME="$(date '+%s')"
}

get_intercept_logs() {
    sudo dmesg | grep "${LOG_TAG}" || true
}

check_intercept() {
    if sudo dmesg | grep -q "${LOG_TAG} Proto: $1"; then
        return 0
    fi

    return 1
}
