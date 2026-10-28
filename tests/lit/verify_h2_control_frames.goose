// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

// Zero-allocation HTTP/2 control frame validator enforcing RFC 9113 invariants
fn validate_h2_ctrl_frame_wire(buf: const u8[:]) -> i64 {
    if buf.len < 9 { return -1; }
    let l0 = (buf[0] as i64) << 16;
    let l1 = (buf[1] as i64) << 8;
    let l2 = buf[2] as i64;
    let payload_len = l0 | l1 | l2;
    let ftype = buf[3];
    let flags = buf[4];
    let sid_b0 = buf[5] as i64;
    let sid_b1 = buf[6] as i64;
    let sid_b2 = buf[7] as i64;
    let sid_b3 = buf[8] as i64;
    let sid = ((sid_b0 & 127) << 24) | (sid_b1 << 16) | (sid_b2 << 8) | sid_b3;

    // RFC 9113 §6.5: SETTINGS
    if ftype == 4 {
        if sid != 0 { return 1; }
        let is_ack = (flags & 1) != 0;
        if is_ack && payload_len != 0 {
            return 6;
        }
        if (payload_len % 6) != 0 {
            return 6;
        }
        return 0;
    }

    // RFC 9113 §6.7: PING
    if ftype == 6 {
        if sid != 0 { return 1; }
        if payload_len != 8 {
            return 6;
        }
        return 0;
    }

    // RFC 9113 §6.9: WINDOW_UPDATE
    if ftype == 8 {
        if payload_len != 4 {
            return 6;
        }
        return 0;
    }

    // RFC 9113 §6.4: RST_STREAM
    if ftype == 3 {
        if sid == 0 { return 1; }
        if payload_len != 4 {
            return 6;
        }
        return 0;
    }

    return 0;
}

fn main() {
    var raw_ack: u8[>..] = [];
    assert(wire_kit::parse_hex("000000040100000000", raw_ack));
    assert(wire_kit::verify_split_stream(raw_ack[..], -1, 0, validate_h2_ctrl_frame_wire));
    assert(wire_kit::fuzz_payload(raw_ack[..], 100, validate_h2_ctrl_frame_wire));
    print("H2_CTRL_SPLIT: OK");

    var vAck6: u8[>..] = []; wire_kit::parse_hex("000006040100000000", vAck6);
    assert(validate_h2_ctrl_frame_wire(vAck6[..]) == 6);

    var vSid1: u8[>..] = []; wire_kit::parse_hex("000006040000000001", vSid1);
    assert(validate_h2_ctrl_frame_wire(vSid1[..]) == 1);

    var vLen5: u8[>..] = []; wire_kit::parse_hex("000005040000000000", vLen5);
    assert(validate_h2_ctrl_frame_wire(vLen5[..]) == 6);

    var vPing7: u8[>..] = []; wire_kit::parse_hex("000007060000000000", vPing7);
    assert(validate_h2_ctrl_frame_wire(vPing7[..]) == 6);

    var vPingSid: u8[>..] = []; wire_kit::parse_hex("000008060000000003", vPingSid);
    assert(validate_h2_ctrl_frame_wire(vPingSid[..]) == 1);

    var vRst0: u8[>..] = []; wire_kit::parse_hex("000004030000000000", vRst0);
    assert(validate_h2_ctrl_frame_wire(vRst0[..]) == 1);

    var vRst5: u8[>..] = []; wire_kit::parse_hex("000005030000000001", vRst5);
    assert(validate_h2_ctrl_frame_wire(vRst5[..]) == 6);
    print("H2_CTRL_INVARIANTS: OK");
}

// CHECK: H2_CTRL_SPLIT: OK
// CHECK: H2_CTRL_INVARIANTS: OK
