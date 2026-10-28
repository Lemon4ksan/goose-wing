// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn verify_h2_preface(buf: const u8[:]) -> i32 {
    guard buf.len >= 24 else { return 0; }
    if buf[0] != 80 || buf[1] != 82 || buf[2] != 73 || buf[3] != 32 { return 0; }
    if buf[20] == 13 && buf[21] == 10 && buf[22] == 13 && buf[23] == 10 { return 1; }
    return 0;
}

fn parse_and_validate_h2_frame(buf: const u8[:], is_client: i32) -> i32 {
    guard buf.len >= 9 else { return -1; }
    let l0 = (buf[0] as i64) << 16;
    let l1 = (buf[1] as i64) << 8;
    let l2 = buf[2] as i64;
    let length = l0 | l1 | l2;

    let ftype = buf[3];
    let flags = buf[4];

    let s0 = (buf[5] & 0x7F) as i64;
    let s1 = buf[6] as i64;
    let s2 = buf[7] as i64;
    let s3 = buf[8] as i64;
    let stream_id = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3;

    if ftype == 4 {
        if stream_id != 0 { return 1; }
        if (flags & 0x1) != 0 && length != 0 { return 6; }
        if (flags & 0x1) == 0 && (length % 6) != 0 { return 6; }
    }

    if ftype == 6 {
        if stream_id != 0 { return 1; }
        if length != 8 { return 6; }
    }

    if is_client == 1 && stream_id > 0 {
        if (stream_id & 1) == 0 { return 1; }
    }

    if ftype == 8 {
        if length != 4 { return 6; }
    }

    return 0;
}

fn main() {
    let preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert(verify_h2_preface(preface) == 1);
    print("H2_PREFACE: OK");

    var vSet: u8[>..] = []; wire_kit::parse_hex("000006040000000000", vSet);
    assert(parse_and_validate_h2_frame(vSet[..], 1) == 0);

    var vSetBadSid: u8[>..] = []; wire_kit::parse_hex("000006040000000001", vSetBadSid);
    assert(parse_and_validate_h2_frame(vSetBadSid[..], 1) == 1);

    var vSetBadAck: u8[>..] = []; wire_kit::parse_hex("000006040100000000", vSetBadAck);
    assert(parse_and_validate_h2_frame(vSetBadAck[..], 1) == 6);

    var vPing: u8[>..] = []; wire_kit::parse_hex("000008060000000000", vPing);
    assert(parse_and_validate_h2_frame(vPing[..], 1) == 0);

    var vPingBadLen: u8[>..] = []; wire_kit::parse_hex("000007060000000000", vPingBadLen);
    assert(parse_and_validate_h2_frame(vPingBadLen[..], 1) == 6);

    var vClientEven: u8[>..] = []; wire_kit::parse_hex("00000A010500000002", vClientEven);
    assert(parse_and_validate_h2_frame(vClientEven[..], 1) == 1);

    var vClientOdd: u8[>..] = []; wire_kit::parse_hex("00000A010500000003", vClientOdd);
    assert(parse_and_validate_h2_frame(vClientOdd[..], 1) == 0);

    print("H2_SPEC_INVARIANTS: OK");
}

// CHECK: H2_PREFACE: OK
// CHECK: H2_SPEC_INVARIANTS: OK
