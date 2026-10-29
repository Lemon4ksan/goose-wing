// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http1_chunked.goose
// Verification of RFC 9112 Chunked Transfer Coding and Single-Register FSM via wing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing's internal 64-bit FSM decoder
fn wing_parse_http1_chunk_frame(buf: const u8[:]) -> i64 {
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

fn calc_chunk_step(size: i64, digit: i64) -> i64 {
    return (size << 4) | (digit & 15);
}

fn calc_chunk_overhead(chunk_len: i64, has_ext: i64) -> i64 {
    return chunk_len + 4 + (has_ext & 8);
}

fn main() {
    let chunk5 = "5\r\nHello\r\n";
    assert(wire_kit::verify_split_stream(chunk5, -1, 5, wing_parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk5, 100, wing_parse_http1_chunk_frame));

    let chunk0_pipe = "0\r\n\r\n";
    assert(wire_kit::verify_split_stream(chunk0_pipe, -1, 0, wing_parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk0_pipe, 100, wing_parse_http1_chunk_frame));
    assert(wing_parse_http1_chunk_frame(chunk0_pipe) == 0);

    let chunk4_ext = "4;ext=1\r\nWiki\r\n";
    assert(wire_kit::verify_split_stream(chunk4_ext, -1, 4, wing_parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk4_ext, 100, wing_parse_http1_chunk_frame));
    print("HTTP1_CHUNK_SPLIT: OK");

    var vA: u8[>..] = []; wire_kit::parse_hex("350A48656C6C6F0D0A", vA);
    assert(wing_parse_http1_chunk_frame(vA[..]) == -2);

    var vB: u8[>..] = []; wire_kit::parse_hex("353B780A48656C6C6F0D0A", vB);
    assert(wing_parse_http1_chunk_frame(vB[..]) == -2);

    var vC: u8[>..] = []; wire_kit::parse_hex("35470D0A", vC);
    assert(wing_parse_http1_chunk_frame(vC[..]) == -2);

    var vD: u8[>..] = []; wire_kit::parse_hex("340D0A57696B695858", vD);
    assert(wing_parse_http1_chunk_frame(vD[..]) == -2);

    var vE: u8[>..] = []; wire_kit::parse_hex("3130300D0A01020304", vE);
    assert(wing_parse_http1_chunk_frame(vE[..]) == -1);
    print("HTTP1_CHUNK_SECURITY: OK");

    assert(calc_chunk_step(16, 10) == 266);
    assert(calc_chunk_overhead(100, 1) == 104);
    print("HTTP1_CHUNK_ALL: PASS");
}

// CHECK: HTTP1_CHUNK_SPLIT: OK
// CHECK: HTTP1_CHUNK_SECURITY: OK
// CHECK: HTTP1_CHUNK_ALL: PASS
