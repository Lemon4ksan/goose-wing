// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h2_control_frames.goose
// Verification of RFC 9113 HTTP/2 control frame wire invariants via wing::http2.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing's real HTTP/2 framer
fn wing_validate_h2_ctrl_frame_wire(buf: const u8[:]) -> i64 {
    guard buf.len >= 9 else { return -1; }
    let hdr, err_hdr = internal::parse_frame_header(buf);
    guard err_hdr == internal::ERR_NO_ERROR else { return err_hdr as! i64; }
    let err_rules = internal::validate_frame_header_rules(hdr);
    guard err_rules == internal::ERR_NO_ERROR else { return err_rules as! i64; }
    guard buf.len >= 9 + (hdr.length as i64) else { return -1; }
    return 0;
}

fn main() {
    var raw_ack: u8[>..] = [];
    assert(wire_kit::parse_hex("000000040100000000", raw_ack));
    assert(wire_kit::verify_split_stream(raw_ack[..], -1, 0, wing_validate_h2_ctrl_frame_wire));
    assert(wire_kit::fuzz_payload(raw_ack[..], 100, wing_validate_h2_ctrl_frame_wire));
    print("H2_CTRL_SPLIT: OK");

    var vAck6: u8[>..] = []; wire_kit::parse_hex("000006040100000000", vAck6);
    assert(wing_validate_h2_ctrl_frame_wire(vAck6[..]) == 6);

    var vSid1: u8[>..] = []; wire_kit::parse_hex("000006040000000001", vSid1);
    assert(wing_validate_h2_ctrl_frame_wire(vSid1[..]) == 1);

    var vLen5: u8[>..] = []; wire_kit::parse_hex("000005040000000000", vLen5);
    assert(wing_validate_h2_ctrl_frame_wire(vLen5[..]) == 6);

    var vPing7: u8[>..] = []; wire_kit::parse_hex("000007060000000000", vPing7);
    assert(wing_validate_h2_ctrl_frame_wire(vPing7[..]) == 6);

    var vPingSid: u8[>..] = []; wire_kit::parse_hex("000008060000000003", vPingSid);
    assert(wing_validate_h2_ctrl_frame_wire(vPingSid[..]) == 1);

    var vRst0: u8[>..] = []; wire_kit::parse_hex("000004030000000000", vRst0);
    assert(wing_validate_h2_ctrl_frame_wire(vRst0[..]) == 1);

    var vRst5: u8[>..] = []; wire_kit::parse_hex("000005030000000001", vRst5);
    assert(wing_validate_h2_ctrl_frame_wire(vRst5[..]) == 6);
    print("H2_CTRL_INVARIANTS: OK");
}

// CHECK: H2_CTRL_SPLIT: OK
// CHECK: H2_CTRL_INVARIANTS: OK
