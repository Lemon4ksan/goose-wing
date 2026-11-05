// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h2_microbench.goose
// HTTP/2 microbenchmark latency budgets: frame header round-trip, HPACK field
// encode (literal + Huffman, no indexing), and HPACK header block decode
// (RFC 7541 Appendix A static indices) under strict latency ceilings.
// Complements verify_wire_benchmarks.goose (CRLFCRLF, TLS header, LPM, chunk FSM).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import os;
import core from "../..";
import wing from "../..";

// Drops the optimizer's knowledge of `buf`'s elements: a builder extern may
// legally write them (goose.h contract), so later loads are runtime work.
fn opaque_barrier(buf: u8[>..]&) {
    var nonce: u8[>..] = [];
    let _ = env("H2BENCH_NONCE", nonce);
    let _ = env("H2BENCH_NONCE", buf);
}

inline fn elapsed_ns(t0: core::MonotonicInstant, t1: core::MonotonicInstant) -> u64 {
    return t1.nanos - t0.nanos;
}

// 4096-iteration sample windows: the per-op average is a shift, not a divide.
inline fn ns_per_op_4k(elapsed: u64) -> u64 {
    return elapsed >> 12;
}

// Loop-carried round-trip feedback: the next parse sees the stream byte the
// previous parse produced, so the measured work cannot be hoisted away.
fn echo_stream_byte(live: u8[>..]&, encoded: u8[9]&) {
    live[8] = encoded[8];
}

fn echo_value_byte(val: u8[8]&, enc: u8[>..]&) {
    val[0] = enc[0];
}

fn bench_h2_frame_roundtrip() {
    // RFC 9113 Section 4.1: HEADERS frame header, length 4, END_HEADERS on
    // stream 1.
    let raw:   u8[9] = [0x00, 0x00, 0x04, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01];
    let iters: u64   = 5000;

    var live: u8[>..] = [];
    for i in 9 {
        live.push(raw[i]);
    }
    opaque_barrier(live);

    for _ in iters {
        let parsed, err = internal::parse_frame_header(live[..]);
        assert(err == 0 && parsed.frame_type == 1);
        var out: u8[9] = [0; 9];
        internal::encode_frame_header(parsed, out);
        echo_stream_byte(live, out);
    }

    let t0 = core::monotonic_now();
    for _ in iters {
        let parsed, err = internal::parse_frame_header(live[..]);
        assert(err == 0);
        assert(parsed.length == 4 && parsed.frame_type == 1);
        var out: u8[9] = [0; 9];
        internal::encode_frame_header(parsed, out);
        echo_stream_byte(live, out);
    }
    let t1 = core::monotonic_now();

    let avg_ns = ns_per_op_4k(elapsed_ns(t0, t1));

    assert(avg_ns <= 500);
    print("BENCH_H2_FRAME_ROUNDTRIP: OK ", avg_ns, " ns/op");
}

fn bench_h2_hpack_encode() {
    // Literal header field with incremental indexing suppressed; the value's
    // first byte rolls through the encoded output so the Huffman path executes
    // per iteration with runtime data.
    let name:  const u8[:] = "x-request-id";
    let iters: u64         = 5000;

    var val: u8[8] = ['9', 'f', '3', 'd', '2', 'a', '1', 'b'];
    var dt = internal::new_dynamic_table();
    var enc: u8[>..] = [];
    opaque_barrier(enc);

    for _ in iters {
        enc.clear();
        let ok = internal::encode_hpack_field(dt, enc, name, val[..], internal::HpackIndexing.None, true);
        assert(ok && enc.len > 0);
        echo_value_byte(val, enc);
    }

    let t0 = core::monotonic_now();
    for _ in iters {
        enc.clear();
        let ok = internal::encode_hpack_field(dt, enc, name, val[..], internal::HpackIndexing.None, true);
        assert(ok && enc.len > 0);
        echo_value_byte(val, enc);
    }
    let t1 = core::monotonic_now();

    let avg_ns = ns_per_op_4k(elapsed_ns(t0, t1));

    assert(avg_ns <= 800);
    print("BENCH_H2_HPACK_ENCODE: OK ", avg_ns, " ns/op");
}

fn bench_h2_hpack_decode() {
    // RFC 7541 Appendix A indices: 2 = :method GET, 7 = :scheme https, 4 = :path /.
    let hblock: u8[3] = [0x82, 0x87, 0x84];
    let iters:  u64   = 5000;

    var dt = internal::new_dynamic_table();
    var pseudo = internal::H2PseudoHeaders { .. };
    var out = wing::HeaderMap { .. };
    for _ in iters {
        let err = internal::decode_hpack_to_map(dt, hblock[..], pseudo, out);
        assert(err == 0 && pseudo.has_method && pseudo.has_scheme && pseudo.has_path);
    }

    let t0 = core::monotonic_now();
    for _ in iters {
        let err = internal::decode_hpack_to_map(dt, hblock[..], pseudo, out);
        assert(err == 0 && pseudo.has_method && pseudo.has_scheme && pseudo.has_path);
    }
    let t1 = core::monotonic_now();

    let avg_ns = ns_per_op_4k(elapsed_ns(t0, t1));

    assert(avg_ns <= 3000);
    print("BENCH_H2_HPACK_DECODE: OK ", avg_ns, " ns/op");
}

fn main() {
    print("=== RUNNING HTTP/2 MICROBENCHMARKS ===");
    bench_h2_frame_roundtrip();
    bench_h2_hpack_encode();
    bench_h2_hpack_decode();
    print("HTTP/2 MICROBENCHMARKS COMPLETE: ALL BUDGETS PASSED");
}

// CHECK: === RUNNING HTTP/2 MICROBENCHMARKS ===
// CHECK: BENCH_H2_FRAME_ROUNDTRIP: OK
// CHECK: BENCH_H2_HPACK_ENCODE: OK
// CHECK: BENCH_H2_HPACK_DECODE: OK
// CHECK: HTTP/2 MICROBENCHMARKS COMPLETE: ALL BUDGETS PASSED
