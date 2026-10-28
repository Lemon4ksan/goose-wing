// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn parse_http1_chunk_frame(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 3 { return -1; }
    var size: i64 = 0;
    var i: i64 = 0;
    var seen_digits: i64 = 0;

    while i < len {
        let b = buf[i];
        if b == 13 || b == 59 { break; }
        if b == 10 { return -2; }

        var digit: i64 = -1;
        if b >= 48 && b <= 57 { digit = b - 48; }
        else if b >= 97 && b <= 102 { digit = b - 87; }
        else if b >= 65 && b <= 70 { digit = b - 55; }
        else { return -2; }

        if seen_digits >= 8 {
            return -2;
        }
        size = (size << 4) | digit;
        seen_digits += 1;
        i += 1;
    }

    if seen_digits == 0 { return -2; }

    while i < len && buf[i] != 13 {
        if buf[i] == 10 {
            return -2;
        }
        i += 1;
    }

    if i + 1 >= len { return -1; }
    if buf[i] != 13 || buf[i + 1] != 10 {
        return -2;
    }
    i += 2;

    let hdr_len = i;
    var total_needed = hdr_len + size;
    if size > 0 {
        total_needed += 2;
    }

    if len < total_needed {
        return -1;
    }

    if size > 0 {
        let cr = buf[hdr_len + size];
        let lf = buf[hdr_len + size + 1];
        if cr != 13 || lf != 10 {
            return -2;
        }
    }

    return size;
}

fn calc_chunk_step(size: i64, digit: i64) -> i64 {
    return (size << 4) | (digit & 15);
}

fn calc_chunk_overhead(chunk_len: i64, has_ext: i64) -> i64 {
    return chunk_len + 4 + (has_ext & 8);
}

fn main() {
    let chunk5 = "5\r\nHello\r\n";
    assert(wire_kit::verify_split_stream(chunk5, -1, 5, parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk5, 100, parse_http1_chunk_frame));

    let chunk0 = "0\r\n";
    assert(wire_kit::verify_split_stream(chunk0, -1, 0, parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk0, 100, parse_http1_chunk_frame));

    let chunk0_pipe = "0\r\n\r\n";
    assert(parse_http1_chunk_frame(chunk0_pipe) == 0);

    let chunk4_ext = "4;ext=1\r\nWiki\r\n";
    assert(wire_kit::verify_split_stream(chunk4_ext, -1, 4, parse_http1_chunk_frame));
    assert(wire_kit::fuzz_payload(chunk4_ext, 100, parse_http1_chunk_frame));
    print("HTTP1_CHUNK_SPLIT: OK");

    var vA: u8[>..] = []; wire_kit::parse_hex("350A48656C6C6F0D0A", vA);
    assert(parse_http1_chunk_frame(vA[..]) == -2);

    var vB: u8[>..] = []; wire_kit::parse_hex("353B780A48656C6C6F0D0A", vB);
    assert(parse_http1_chunk_frame(vB[..]) == -2);

    var vC: u8[>..] = []; wire_kit::parse_hex("35470D0A", vC);
    assert(parse_http1_chunk_frame(vC[..]) == -2);

    var vD: u8[>..] = []; wire_kit::parse_hex("340D0A57696B695858", vD);
    assert(parse_http1_chunk_frame(vD[..]) == -2);

    var vE: u8[>..] = []; wire_kit::parse_hex("3130300D0A01020304", vE);
    assert(parse_http1_chunk_frame(vE[..]) == -1);
    print("HTTP1_CHUNK_SECURITY: OK");

    assert(calc_chunk_step(16, 10) == 266);
    assert(calc_chunk_overhead(100, 1) == 104);
    print("HTTP1_CHUNK_ALL: PASS");
}

// CHECK: HTTP1_CHUNK_SPLIT: OK
// CHECK: HTTP1_CHUNK_SECURITY: OK
// CHECK: HTTP1_CHUNK_ALL: PASS
