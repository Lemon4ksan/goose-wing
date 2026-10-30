// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire bridge to HTTP/2 frame header decoder and rule validator
fn decode_h2_header(buf: const u8[:]) -> i64 {
    if buf.len < 9 { return -1; }
    let hdr, err = internal::parse_frame_header(buf, 16384);
    if err != internal::ERR_NO_ERROR { return -2; }
    if internal::validate_frame_header_rules(hdr) != internal::ERR_NO_ERROR { return -2; }
    return hdr.length;
}

// Wire bridge to WebSocket frame parser with RFC 6455 bounds checking
fn validate_ws_frame(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let opcode = buf[0] & 0x0F;
    if !wing::is_valid_ws_opcode(opcode) { return -2; }
    let masked = (buf[1] & 0x80) != 0;
    let raw_len = buf[1] & 0x7F;
    var min_hdr: i64 = 2;
    if raw_len == 126 { min_hdr += 2; }
    else if raw_len == 127 { min_hdr += 8; }
    if masked { min_hdr += 4; }
    if buf.len < min_hdr { return -1; }

    let hdr, ok = wing::parse_ws_frame_header(buf);
    if !ok { return -2; }
    let total: i64 = hdr.header_len + (hdr.payload_len as! i64);
    if buf.len < total { return -1; }
    return hdr.payload_len as! i64;
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

    var hdr_orig = internal::FrameHeader {
        length:     8,
        frame_type: internal::FRAME_HEADERS,
        flags:      internal::FLAG_END_STREAM | internal::FLAG_END_HEADERS,
        stream_id:  3,
    };
    var enc_hdr: u8[9] = [0; 9];
    internal::encode_frame_header(hdr_orig, enc_hdr);
    let hdr_dec, err = internal::parse_frame_header(enc_hdr[..]);
    assert(err == internal::ERR_NO_ERROR);
    assert(hdr_dec.length == 8);
    assert(hdr_dec.frame_type == internal::FRAME_HEADERS);
    assert(hdr_dec.flags == (internal::FLAG_END_STREAM | internal::FLAG_END_HEADERS));
    assert(hdr_dec.stream_id == 3);
    print("EDGE_ROUNDTRIP: OK");
}

// CHECK: EDGE_H2_HEADER: OK
// CHECK: EDGE_WS_FRAME: OK
// CHECK: EDGE_ROUNDTRIP: OK
