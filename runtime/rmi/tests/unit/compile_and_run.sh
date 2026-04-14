#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || echo $(pwd))"
TEST_DIR="$ROOT_DIR/staging/rmm-private/runtime/rmi/tests/unit"
RTM_DIR="$ROOT_DIR/staging/rmm-private/runtime/rmi"
INCLUDE_DIR="$ROOT_DIR/staging/rmm-private/runtime/include"
GRANULE_INC="$ROOT_DIR/staging/rmm-private/lib/granule/include"
ARCH_INC="$ROOT_DIR/staging/rmm-private/lib/arch/include/aarch64"
ARCH_FAKE_INC="$ROOT_DIR/staging/rmm-private/lib/arch/include/fake_host"
GRANULE_ARCH_INC="$ROOT_DIR/staging/rmm-private/lib/granule/include/aarch64"
GRANULE_FAKE_INC="$ROOT_DIR/staging/rmm-private/lib/granule/include/fake_host"
COMMON_INC="$ROOT_DIR/staging/rmm-private/lib/common/include"
SLOT_BUF_INC="$ROOT_DIR/staging/rmm-private/lib/slot_buf/include"
SMC_INC="$ROOT_DIR/staging/rmm-private/lib/smc/include"
MEASURE_INC="$ROOT_DIR/staging/rmm-private/app/attestation/rmm_stub/include"

gcc -I"$TEST_DIR" -I"$INCLUDE_DIR" -I"$RTM_DIR" -I"$GRANULE_INC" -I"$GRANULE_ARCH_INC" -I"$GRANULE_FAKE_INC" -I"$ARCH_INC" -I"$ARCH_FAKE_INC" -I"$COMMON_INC" -I"$SLOT_BUF_INC" -I"$SMC_INC" -I"$MEASURE_INC" \
    "$RTM_DIR/transition_table.c" \
    "$TEST_DIR/spinlock.c" \
    "$TEST_DIR/transition_table_test.c" -o "$TEST_DIR/transition_table_test"

"$TEST_DIR/transition_table_test"

gcc -I"$TEST_DIR" -I"$INCLUDE_DIR" -I"$RTM_DIR" -I"$GRANULE_INC" -I"$GRANULE_ARCH_INC" -I"$GRANULE_FAKE_INC" -I"$ARCH_INC" -I"$ARCH_FAKE_INC" -I"$COMMON_INC" -I"$SLOT_BUF_INC" -I"$SMC_INC" -I"$MEASURE_INC" \
    "$RTM_DIR/transition_table.c" \
    "$TEST_DIR/spinlock.c" \
    "$TEST_DIR/transition_table_strict_test.c" -o "$TEST_DIR/transition_table_strict_test"

"$TEST_DIR/transition_table_strict_test"

gcc -I"$TEST_DIR" -I"$INCLUDE_DIR" -I"$RTM_DIR" \
    "$TEST_DIR/check_cf_test.c" -o "$TEST_DIR/check_cf_test"

"$TEST_DIR/check_cf_test"

gcc -I"$TEST_DIR" \
    "$TEST_DIR/sgt_test.c" -o "$TEST_DIR/sgt_test"

"$TEST_DIR/sgt_test"

gcc -I"$TEST_DIR" \
    "$TEST_DIR/peer_activation_test.c" -o "$TEST_DIR/peer_activation_test"

"$TEST_DIR/peer_activation_test"