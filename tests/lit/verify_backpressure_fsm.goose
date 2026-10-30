// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    var bp = wing::BackpressureSlot { .. };
    assert(!bp.is_active);
    assert(bp.len == 0);

    // Buffering zero-length must fail
    assert(!wing::buffer_backpressure(bp, ""));

    // Buffering valid slice
    let msg: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
    assert(wing::buffer_backpressure(bp, msg));
    assert(bp.is_active);
    assert(bp.len == msg.len);
    assert(bp.offset == 0);

    // Verify drain simulation with invalid fd returns false
    let drained, ok = wing::drain_backpressure(bp, -1);
    assert(!ok);

    // Manual offset advancement simulation
    bp.offset = msg.len;
    let drained2, ok2 = wing::drain_backpressure(bp, -1);
    // When offset >= len, drain resets slot and returns true
    assert(ok2);
    assert(!bp.is_active);
    assert(bp.len == 0);

    // Verify large payload buffering up to 16 KB
    var large_msg: u8[8192] = ['X'; 8192];
    assert(wing::buffer_backpressure(bp, large_msg[..]));
    assert(bp.len == 8192);
    wing::clear_backpressure_slot(bp);
    assert(!bp.is_active);

    print("BACKPRESSURE_FSM: OK");
}
// CHECK: BACKPRESSURE_FSM: OK
