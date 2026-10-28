// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn validate_quic_ack_wire(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len <= 0 { return -1; }
    var idx: i64 = 0;

    let ftype = buf[idx];
    idx += 1;
    if ftype != 2 && ftype != 3 { return -2; }

    if idx >= len { return -1; }
    let l0 = buf[idx];
    let tag_l = (l0 >> 6) & 3;
    var largest_acked: i64 = l0 & 63;
    var l_bytes: i64 = 1;
    if tag_l == 1 {
        l_bytes = 2;
        if idx + l_bytes > len { return -1; }
        largest_acked = (largest_acked << 8) | buf[idx + 1];
    } else if tag_l == 2 {
        l_bytes = 4;
        if idx + l_bytes > len { return -1; }
        largest_acked = (largest_acked << 24) | ((buf[idx + 1] as i64) << 16) | ((buf[idx + 2] as i64) << 8) | buf[idx + 3];
    }
    idx += l_bytes;

    if idx >= len { return -1; }
    let d0 = buf[idx];
    let tag_d = (d0 >> 6) & 3;
    var d_bytes: i64 = 1;
    if tag_d == 1 { d_bytes = 2; }
    else if tag_d == 2 { d_bytes = 4; }
    if idx + d_bytes > len { return -1; }
    idx += d_bytes;

    if idx >= len { return -1; }
    let r0 = buf[idx];
    let tag_r = (r0 >> 6) & 3;
    var r_bytes: i64 = 1;
    if tag_r == 1 { r_bytes = 2; }
    if idx + r_bytes > len { return -1; }
    idx += r_bytes;

    if idx >= len { return -1; }
    let a0 = buf[idx];
    let tag_a = (a0 >> 6) & 3;
    var first_range: i64 = a0 & 63;
    var a_bytes: i64 = 1;
    if tag_a == 1 {
        a_bytes = 2;
        if idx + a_bytes > len { return -1; }
        first_range = (first_range << 8) | buf[idx + 1];
    }
    idx += a_bytes;

    if largest_acked < first_range {
        return -3;
    }

    return largest_acked - first_range;
}

fn validate_quic_long_header_wire(buf: const u8[:]) -> i32 {
    if buf.len < 5 { return -1; }
    let first = buf[0];
    if (first & 128) == 0 { return -2; }
    if (first & 64) == 0 { return -3; }
    let long_type = (first >> 4) & 3;
    if long_type == 0 && (first & 12) != 0 {
        return -4;
    }
    return 1;
}

fn main() {
    var raw_ack: u8[>..] = [];
    assert(wire_kit::parse_hex("02406419000A", raw_ack));
    assert(wire_kit::verify_split_stream(raw_ack[..], -1, 90, validate_quic_ack_wire));
    assert(wire_kit::fuzz_payload(raw_ack[..], 100, validate_quic_ack_wire));
    print("QUIC_ACK_SPLIT: OK");

    var bad_range: u8[>..] = []; wire_kit::parse_hex("020519000A", bad_range);
    assert(validate_quic_ack_wire(bad_range[..]) == -3);
    print("QUIC_ACK_INVARIANT: OK");

    var init_ok: u8[>..] = []; wire_kit::parse_hex("C000000001", init_ok);
    assert(validate_quic_long_header_wire(init_ok[..]) == 1);

    var init_nofix: u8[>..] = []; wire_kit::parse_hex("8000000001", init_nofix);
    assert(validate_quic_long_header_wire(init_nofix[..]) == -3);

    var init_badres: u8[>..] = []; wire_kit::parse_hex("C400000001", init_badres);
    assert(validate_quic_long_header_wire(init_badres[..]) == -4);
    print("QUIC_LONG_HEADER: OK");
}

// CHECK: QUIC_ACK_SPLIT: OK
// CHECK: QUIC_ACK_INVARIANT: OK
// CHECK: QUIC_LONG_HEADER: OK
