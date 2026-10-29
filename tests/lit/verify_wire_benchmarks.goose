// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_wire_benchmarks.goose
// Verification of Zero-Allocation Wire Primitives & Microbenchmark Latency Budgets.
// Benchmarks AVX2/SWAR CRLFCRLF scanner, TLS record header parser,
// gRPC LPM decoder, and chunked transfer FSM decoder under strict latency ceilings.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn bench_crlfcrlf_throughput() {
    let req: const u8[:] = "GET /v1/telemetry HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: wing/1.0\r\nAccept: */*\r\n\r\n";
    let iters: i64 = 5000;

    // Warm-up
    for _ in 100 {
        let _ = core::fast_find_crlfcrlf(req);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        let off = core::fast_find_crlfcrlf(req);
        assert(off > 0);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 500);
    print("BENCH_CRLFCRLF: OK");
}

fn bench_tls_record_parsing() {
    let raw_rec: u8[5] = [0x17, 0x03, 0x03, 0x01, 0x00]; // 256 bytes payload
    let iters: i64 = 5000;

    for _ in 100 {
        let _ = wing::parse_tls_record_header(raw_rec[..]);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        let ct, _, len, _, ok = wing::parse_tls_record_header(raw_rec[..]);
        assert(ok && ct == 0x17 && len == 256);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 300);
    print("BENCH_TLS_HEADER: OK");
}

fn bench_grpc_lpm_decoding() {
    let raw_lpm: u8[13] = [0x00, 0x00, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
    let iters: i64 = 5000;

    for _ in 100 {
        let _ = wing::decode_grpc_lpm_slice(raw_lpm[..], 0);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        let payload_slice, compressed, consumed, ok = wing::decode_grpc_lpm_slice(raw_lpm[..], 0);
        assert(ok && !compressed && consumed == 13 && payload_slice.len == 8);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 300);
    print("BENCH_GRPC_LPM: OK");
}

fn bench_chunk_fsm_feed() {
    let raw_chunk: const u8[:] = "A\r\n0123456789\r\n";
    let iters: i64 = 5000;

    for _ in 100 {
        var dec = internal::new_chunk_fsm_decoder();
        let st_w, _, _ = internal::chunk_fsm_feed(dec, raw_chunk);
    }

    let t0 = core::monotonic_now().nanos;
    for _ in iters {
        var dec = internal::new_chunk_fsm_decoder();
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw_chunk);
        var is_chunk = false;
        match st {
            YieldChunk => { is_chunk = true; },
            Complete => {},
            NeedMore => {},
            Error => {},
        }
        assert(is_chunk && consumed > 0 && chunk.len == 10);
    }
    let t1 = core::monotonic_now().nanos;

    let diff = (t1 - t0) as! i64;
    let avg_ns = if diff > 0 { diff / iters } else { 0 };

    assert(avg_ns <= 500);
    print("BENCH_CHUNK_FSM: OK");
}

fn main() {
    print("=== RUNNING ZERO-ALLOC WIRE BENCHMARKS ===");
    bench_crlfcrlf_throughput();
    bench_tls_record_parsing();
    bench_grpc_lpm_decoding();
    bench_chunk_fsm_feed();
    print("ZERO-ALLOC WIRE BENCHMARKS COMPLETE: ALL BUDGETS PASSED");
}

// CHECK: === RUNNING ZERO-ALLOC WIRE BENCHMARKS ===
// CHECK: BENCH_CRLFCRLF: OK
// CHECK: BENCH_TLS_HEADER: OK
// CHECK: BENCH_GRPC_LPM: OK
// CHECK: BENCH_CHUNK_FSM: OK
// CHECK: ZERO-ALLOC WIRE BENCHMARKS COMPLETE: ALL BUDGETS PASSED
