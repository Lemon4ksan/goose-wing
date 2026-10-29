// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_smuggling_desync.goose
// Verification of HTTP/1.1 Request Smuggling (CL.TE, TE.CL), Desync, and Chunked FSM Defenses.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn parse_chunk_step(buf: const u8[:]) -> i64 {
    var dec = internal::new_chunk_fsm_decoder();
    let st, consumed, chunk = internal::chunk_fsm_feed(dec, buf);
    match st {
        YieldChunk => {
            if dec.state == internal::CHUNK_STATE_IS_CHUNKED && consumed == buf.len {
                return chunk.len;
            }
            return -1;
        },
        Complete => {
            if consumed == buf.len {
                return 0;
            }
            return -1;
        },
        NeedMore => {
            return -1;
        },
        Error => {
            return -2;
        },
    }
}

fn main() {
    print("=== HTTP1_SMUGGLE_DEFENSES ===");

    // 1. Conflicting TE followed by CL (TE.CL)
    var map1 = wing::HeaderMap { .. };
    let raw_te_cl = "Transfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n";
    let err1 = wing::parse_headers(raw_te_cl, map1);
    assert(err1 == wing::HeaderParseError.InvalidContentLength);
    assert(!map1.valid);
    print("TE_CL_CONFLICT: REJECTED");

    // 2. Conflicting CL followed by TE (CL.TE)
    var map2 = wing::HeaderMap { .. };
    let raw_cl_te = "Content-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n";
    let err2 = wing::parse_headers(raw_cl_te, map2);
    assert(err2 == wing::HeaderParseError.InvalidContentLength);
    assert(!map2.valid);
    print("CL_TE_CONFLICT: REJECTED");

    // 3. Duplicate differing Content-Length headers (CL.CL)
    var map3 = wing::HeaderMap { .. };
    let raw_diff_cl = "Content-Length: 10\r\nContent-Length: 20\r\n\r\n";
    let err3 = wing::parse_headers(raw_diff_cl, map3);
    assert(err3 == wing::HeaderParseError.InvalidContentLength);
    assert(!map3.valid);
    print("DUP_CL_DIFF: REJECTED");

    // 4. Duplicate IDENTICAL Content-Length headers per RFC 9112 §6.3
    var map4 = wing::HeaderMap { .. };
    let raw_same_cl = "Content-Length: 42\r\nContent-Length: 42\r\n\r\n";
    let err4 = wing::parse_headers(raw_same_cl, map4);
    assert(err4 == wing::HeaderParseError.None);
    assert(map4.valid);
    assert(wing::get_header(map4, "content-length") == "42");
    print("DUP_CL_SAME: ACCEPTED");

    // 5. 64-bit integer overflow in Content-Length (30-digit flood)
    var map5 = wing::HeaderMap { .. };
    let raw_ovf = "Content-Length: 999999999999999999999999999999\r\n\r\n";
    let err5 = wing::parse_headers(raw_ovf, map5);
    assert(err5 == wing::HeaderParseError.InvalidContentLength);
    print("CL_OVERFLOW: REJECTED");

    // 6. obs-fold on Content-Length rejection even in compatibility mode
    var map6 = wing::HeaderMap { .. };
    let raw_fold = "Content-Length: 10\r\n 20\r\n\r\n";
    let err6 = wing::parse_headers(raw_fold, map6, true);
    assert(err6 == wing::HeaderParseError.InvalidContentLength);
    print("CL_OBS_FOLD: REJECTED");

    // 7. Duplicate Transfer-Encoding headers rejection
    var map7 = wing::HeaderMap { .. };
    let raw_dup_te = "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n";
    let err7 = wing::parse_headers(raw_dup_te, map7);
    assert(err7 == wing::HeaderParseError.InvalidContentLength);
    print("DUP_TE_HEADERS: REJECTED");

    // 8. Chunked single-register FSM stream slicing and mutation fuzzing
    let valid_chunk = "B\r\nHello World\r\n";
    assert(wire_kit::verify_split_stream(valid_chunk, -1, 11, parse_chunk_step));
    assert(wire_kit::fuzz_payload(valid_chunk, 200, parse_chunk_step));
    print("CHUNK_SPLIT_AND_FUZZ: PASS");

    // 9. Hex chunk size overflow attack
    var raw_hex_ovf: u8[>..] = [];
    assert(wire_kit::parse_hex("7FFFFFFFFFFFFFFF0D0A", raw_hex_ovf));
    assert(parse_chunk_step(raw_hex_ovf[..]) == -2);
    print("CHUNK_HEX_OVERFLOW: REJECTED");
}

// CHECK-LABEL: === HTTP1_SMUGGLE_DEFENSES ===
// CHECK-NEXT: TE_CL_CONFLICT: REJECTED
// CHECK-NEXT: CL_TE_CONFLICT: REJECTED
// CHECK-NEXT: DUP_CL_DIFF: REJECTED
// CHECK-NEXT: DUP_CL_SAME: ACCEPTED
// CHECK-NEXT: CL_OVERFLOW: REJECTED
// CHECK-NEXT: CL_OBS_FOLD: REJECTED
// CHECK-NEXT: DUP_TE_HEADERS: REJECTED
// CHECK-NEXT: CHUNK_SPLIT_AND_FUZZ: PASS
// CHECK-NEXT: CHUNK_HEX_OVERFLOW: REJECTED
