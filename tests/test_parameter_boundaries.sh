#!/bin/bash

set -e

source "$(dirname "$0")/common.sh"

print_test "Parameter boundaries and malformed values"

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

expect_accepted() {
    local description="$1"
    shift

    unload_module

    if ! sudo insmod "${KO_FILE}" "$@" > /dev/null 2>&1; then
        fail "Valid configuration was rejected: ${description}"
    fi

    if ! module_loaded; then
        fail "Valid configuration did not load: ${description}"
    fi

    pass "Accepted ${description}"
}

expect_accepted "source port 1" mode=drop port_src=1
expect_accepted "destination port 65535" mode=drop port_dest=65535
expect_accepted "CIDR prefix /0 in log mode" mode=log ip_src=0.0.0.0/0
expect_accepted "CIDR prefix /31" mode=drop ip_dest=192.168.1.0/31
expect_accepted "CIDR prefix /32" mode=drop ip_dest=192.168.1.10/32

expect_rejected "incomplete IPv4 address" ip_src=192.168.1
expect_rejected "non-numeric IPv4 address" ip_dest=192.168.one.1
expect_rejected "empty CIDR prefix" ip_src=192.168.1.0/
expect_rejected "negative CIDR prefix" ip_dest=192.168.1.0/-1
expect_rejected "extra IPv4 octet" ip_src=192.168.1.1.5
