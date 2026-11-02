// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_alloc_counter.goose
// Verification of the runtime allocation counter: interposed slice-pool span
// counting, data-stack growth watermark sampling, explicit note taps, and a
// zero-alloc demonstration over real hot-path wire primitives (CRLFCRLF scan,
// H2 frame header parse, HPACK block decode and field encode).
//
// RUN: goose build --cc gcc -O2 --include %S/alloc_hook.h -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import alloc_kit from ".";
import slice_pool;

fn test_note_tap() {
    alloc_kit::alloc_reset();
    assert(alloc_kit::alloc_events() == 0 && alloc_kit::alloc_bytes() == 0);

    alloc_kit::alloc_note(64);
    alloc_kit::alloc_note(16);
    assert(alloc_kit::alloc_events() == 2 && alloc_kit::alloc_bytes() == 80);

    alloc_kit::alloc_disable();
    alloc_kit::alloc_note(1);
    assert(alloc_kit::alloc_events() == 2 && alloc_kit::alloc_bytes() == 80);
    print("ALLOC_NOTE_TAP: OK");
}

fn test_interposed_pool_counting() {
    var pool = slice_pool<u8> {};
    alloc_kit::alloc_reset();

    // First allocations grow the pool's items array while the span tree is
    // still empty: data-stack bump, no span placement call.
    let a = pool.alloc_slice(4);
    let b = pool.alloc_slice(4);
    assert(a.len == 4 && b.len == 4 && alloc_kit::alloc_events() == 0);

    // Freeing builds span-tree bookkeeping through gs_slice_pool_free.
    pool.free_slice(a);
    assert(alloc_kit::alloc_frees() == 1);

    // Placement from the freelist runs gs_slice_pool_place under the
    // alloc_hook.h interposition: the counter observes non-cooperating code.
    let c = pool.alloc_slice(2);
    assert(c.len == 2 && alloc_kit::alloc_events() == 1 && alloc_kit::alloc_bytes() == 2);

    pool.free_slice(c);
    assert(alloc_kit::alloc_frees() == 2);
    print("ALLOC_POOL_INTERPOSE: OK");
}

fn test_growth_watermark() {
    var probe: u8[>..] = [];
    alloc_kit::alloc_reset();

    let mark = alloc_kit::alloc_mark(probe);
    assert(alloc_kit::alloc_growth(probe, mark) == 0);

    // Pure slice scans leave the watermark untouched.
    let req: const u8[:] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    let off = core::fast_find_crlfcrlf(req);
    assert(off > 0 && alloc_kit::alloc_growth(probe, mark) == 0);

    // Surviving growable-array growth on the probe's data stack is visible.
    probe.push(65);
    probe.push(66);
    assert(alloc_kit::alloc_growth(probe, mark) == 2);
    print("ALLOC_GROWTH_WATERMARK: OK");
}

fn test_zero_alloc_hot_paths() {
    let req:    const u8[:] = "GET /telemetry HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    let raw:    u8[9]       = [0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
    let hblock: u8[3]       = [0x82, 0x87, 0x84];
    let name:   const u8[:] = "x-request-id";
    let val:    const u8[:] = "9f3d2a1b";

    var dt = internal::new_dynamic_table();
    var out = internal::DecodedH2HeaderList { .. };
    var enc:   u8[..256] = [];
    var probe: u8[>..]   = [];

    alloc_kit::alloc_reset();
    let mark = alloc_kit::alloc_mark(probe);

    for _ in 1000 {
        let off = core::fast_find_crlfcrlf(req);
        assert(off > 0);

        let hdr, err = internal::parse_frame_header(raw[..]);
        assert(err == 0 && hdr.stream_id == 1);

        let derr = internal::decode_hpack_header_block(dt, hblock[..], out);
        assert(derr == 0 && out.fields.len == 3);

        enc.clear();
        let ok = internal::encode_hpack_field(dt, enc, name, val, internal::HpackIndexing.None, true);
        assert(ok && enc.len > 0);
    }

    assert(alloc_kit::alloc_growth(probe, mark) == 0);
    assert(alloc_kit::alloc_events() == 0 && alloc_kit::alloc_frees() == 0);
    print("ZERO_ALLOC_HOT_PATHS: OK");
}

fn main() {
    print("=== RUNNING RUNTIME ALLOCATION COUNTER ===");
    test_note_tap();
    test_interposed_pool_counting();
    test_growth_watermark();
    test_zero_alloc_hot_paths();
    print("RUNTIME ALLOCATION COUNTER COMPLETE: ALL CHECKS PASSED");
}

// CHECK: === RUNNING RUNTIME ALLOCATION COUNTER ===
// CHECK: ALLOC_NOTE_TAP: OK
// CHECK: ALLOC_POOL_INTERPOSE: OK
// CHECK: ALLOC_GROWTH_WATERMARK: OK
// CHECK: ZERO_ALLOC_HOT_PATHS: OK
// CHECK: RUNTIME ALLOCATION COUNTER COMPLETE: ALL CHECKS PASSED
