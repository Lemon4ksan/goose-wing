// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_qpack_blocked_streams.goose
// Verification of QPACK Blocked Streams and Dynamic Table Synchronization (RFC 9204 §2.1.2).
// Tests SETTINGS_QPACK_BLOCKED_STREAMS bounds enforcement, stream queueing,
// required insert count (RIC) resolution, and stream unblocking.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn test_qpack_blocking_limit() {
    // Create QpackTable with max_capacity = 4096 and max_blocked = 2
    var tbl = wing::new_qpack_table(4096, 2);
    assert(wing::qpack_can_block_stream(tbl));
    print("CAN_BLOCK_INIT: true");

    // Block stream 4 waiting for RIC 5
    let payload4: const u8[:] = "req4_wire";
    let ok1 = wing::qpack_block_stream(tbl, 4, 5, payload4);
    assert(ok1);
    assert(wing::qpack_is_stream_blocked(tbl, 4));
    print("STREAM_4_BLOCKED: true");

    // Block stream 8 waiting for RIC 6
    let payload8: const u8[:] = "req8_wire";
    let ok2 = wing::qpack_block_stream(tbl, 8, 6, payload8);
    assert(ok2);
    assert(wing::qpack_is_stream_blocked(tbl, 8));
    print("STREAM_8_BLOCKED: true");

    // Table now has 2 blocked streams == max_blocked (2)
    // Next attempt to block stream 12 MUST be rejected per RFC 9204 §2.1.2
    assert(!wing::qpack_can_block_stream(tbl));
    let payload12: const u8[:] = "req12_wire";
    let ok3 = wing::qpack_block_stream(tbl, 12, 7, payload12);
    assert(!ok3);
    print("STREAM_12_EXHAUSTED_REJECTED: true");
}

fn test_qpack_unblocking_progression() {
    var tbl = wing::new_qpack_table(4096, 4);

    let payload: const u8[:] = "data";
    assert(wing::qpack_block_stream(tbl, 100, 1, payload));
    assert(wing::qpack_block_stream(tbl, 101, 2, payload));
    assert(tbl.blocked_streams.len == 2);
    print("BLOCKED_COUNT_INIT: 2");

    // Unblock stream 100
    let unblocked100 = wing::qpack_unblock_stream(tbl, 100);
    assert(unblocked100);
    assert(!wing::qpack_is_stream_blocked(tbl, 100));
    assert(wing::qpack_is_stream_blocked(tbl, 101));
    assert(tbl.blocked_streams.len == 1);
    print("STREAM_100_UNBLOCKED: true");

    // Unblocking an unblocked or unknown stream returns false
    let unblocked_again = wing::qpack_unblock_stream(tbl, 100);
    assert(!unblocked_again);
    print("STREAM_100_DOUBLE_UNBLOCK_REJECTED: true");

    // Unblock stream 101
    let unblocked101 = wing::qpack_unblock_stream(tbl, 101);
    assert(unblocked101);
    assert(tbl.blocked_streams.len == 0);
    print("ALL_STREAMS_UNBLOCKED: true");
}

fn main() {
    print("=== RUNNING QPACK BLOCKED STREAMS SUITE ===");
    test_qpack_blocking_limit();
    test_qpack_unblocking_progression();
    print("QPACK BLOCKED STREAMS COMPLETE: ALL INVARIANTS PASSED");
}

// CHECK: === RUNNING QPACK BLOCKED STREAMS SUITE ===
// CHECK: CAN_BLOCK_INIT: true
// CHECK: STREAM_4_BLOCKED: true
// CHECK: STREAM_8_BLOCKED: true
// CHECK: STREAM_12_EXHAUSTED_REJECTED: true
// CHECK: BLOCKED_COUNT_INIT: 2
// CHECK: STREAM_100_UNBLOCKED: true
// CHECK: STREAM_100_DOUBLE_UNBLOCK_REJECTED: true
// CHECK: ALL_STREAMS_UNBLOCKED: true
// CHECK: QPACK BLOCKED STREAMS COMPLETE: ALL INVARIANTS PASSED
