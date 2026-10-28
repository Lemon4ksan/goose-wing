// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

// HTTP/2 9-byte header parser with strict bounds guard
fn decode_h2_header(buf: const u8[:]) -> i64 {
    if buf.len < 9 { return -1; }
    let l0 = (buf[0] as i64) << 16;
    let l1 = (buf[1] as i64) << 8;
    let l2 = buf[2] as i64;
    let ftype = buf[3];
    let sid_b0 = buf[5] as i64;
    let sid_b1 = buf[6] as i64;
    let sid_b2 = buf[7] as i64;
    let sid_b3 = buf[8] as i64;
    let sid = ((sid_b0 & 0x7F) << 24) | (sid_b1 << 16) | (sid_b2 << 8) | sid_b3;
    if sid == 0 && ftype == 1 { return -2; }
    return l0 | l1 | l2;
}

// Bounded WebSocket frame validator
fn validate_ws_frame(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 2 { return -1; }
    let b1 = buf[1];
    let masked = (b1 & 0x80) != 0;
    var payload_len: i64 = b1 & 127;
    var hdr_len: i64 = 2;
    if payload_len == 126 {
        hdr_len += 2;
        if len < hdr_len { return -1; }
        payload_len = ((buf[2] as i64) << 8) | buf[3];
    } else if payload_len == 127 {
        hdr_len += 8;
        if len < hdr_len { return -1; }
        payload_len = ((buf[6] as i64) << 24) | ((buf[7] as i64) << 16) | ((buf[8] as i64) << 8) | buf[9];
    }
    if masked {
        hdr_len += 4;
    }
    if len < hdr_len + payload_len {
        return -1;
    }
    return payload_len;
}

fn calc_h2_stream_word(hi: i64, lo: i64) -> i64 {
    return ((hi & 127) << 16) | (lo & 65535);
}

fn derive_mask_key(m1: i64, m2: i64) -> i64 {
    return ((m1 ^ 0x5A5A5A5A) << 16) | (m2 & 65535);
}

fn main() {
    var h2_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("000008010500000003", h2_pkt));
    assert(wire_kit::verify_split_stream(h2_pkt[..], -1, 8, decode_h2_header));
    assert(wire_kit::fuzz_payload(h2_pkt[..], 100, decode_h2_header));
    print("EDGE_H2_HEADER: OK");

    var ws_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("81850102030468656C6C6F", ws_pkt));
    assert(wire_kit::verify_split_stream(ws_pkt[..], -1, 5, validate_ws_frame));
    assert(wire_kit::fuzz_payload(ws_pkt[..], 100, validate_ws_frame));
    print("EDGE_WS_FRAME: OK");

    let w = calc_h2_stream_word(1, 42);
    assert(w == 65578);
    let k = derive_mask_key(12345, 67890);
    assert(k == ((12345 ^ 0x5A5A5A5A) << 16) | (67890 & 65535));
    print("EDGE_PURE_CALC: OK");
}

// CHECK: EDGE_H2_HEADER: OK
// CHECK: EDGE_WS_FRAME: OK
// CHECK: EDGE_PURE_CALC: OK
