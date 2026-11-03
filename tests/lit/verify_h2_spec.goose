// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h2_spec.goose
// Verification of RFC 9113 HTTP/2 connection preface and frame invariants via wing::http2.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn wing_verify_h2_preface(buf: const u8[:]) -> i32 {
    guard buf.len >= rfc::H2_CLIENT_PREFACE.len else { return 0; }
    if buf[..rfc::H2_CLIENT_PREFACE.len] == rfc::H2_CLIENT_PREFACE {
        return 1;
    }
    return 0;
}

fn wing_parse_and_validate_h2_frame(buf: const u8[:], is_client: bool) -> i32 {
    guard buf.len >= 9 else { return -1; }
    let hdr, err_hdr = internal::parse_frame_header(buf);
    guard err_hdr == rfc::H2_ERR_NO_ERROR else { return err_hdr as! i32; }

    let err_rules = internal::validate_frame_header_rules(hdr);
    guard err_rules == rfc::H2_ERR_NO_ERROR else { return err_rules as! i32; }

    // Client-initiated streams must be odd-numbered (RFC 9113 Section 5.1.1)
    if is_client && hdr.stream_id > 0 && (hdr.stream_id & 1) == 0 {
        return rfc::H2_ERR_PROTOCOL_ERROR as! i32;
    }

    return 0;
}

fn main() {
    let preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert(wing_verify_h2_preface(preface) == 1);
    assert(wing_verify_h2_preface(rfc::H2_CLIENT_PREFACE) == 1);
    print("H2_PREFACE: OK");

    var vSet: u8[>..] = []; wire_kit::parse_hex("000006040000000000", vSet);
    assert(wing_parse_and_validate_h2_frame(vSet[..], true) == 0);

    var vSetBadSid: u8[>..] = []; wire_kit::parse_hex("000006040000000001", vSetBadSid);
    assert(wing_parse_and_validate_h2_frame(vSetBadSid[..], true) == 1);

    var vSetBadAck: u8[>..] = []; wire_kit::parse_hex("000006040100000000", vSetBadAck);
    assert(wing_parse_and_validate_h2_frame(vSetBadAck[..], true) == 6);

    var vPing: u8[>..] = []; wire_kit::parse_hex("000008060000000000", vPing);
    assert(wing_parse_and_validate_h2_frame(vPing[..], true) == 0);

    var vPingBadLen: u8[>..] = []; wire_kit::parse_hex("000007060000000000", vPingBadLen);
    assert(wing_parse_and_validate_h2_frame(vPingBadLen[..], true) == 6);

    var vClientEven: u8[>..] = []; wire_kit::parse_hex("00000A010500000002", vClientEven);
    assert(wing_parse_and_validate_h2_frame(vClientEven[..], true) == 1);

    var vClientOdd: u8[>..] = []; wire_kit::parse_hex("00000A010500000003", vClientOdd);
    assert(wing_parse_and_validate_h2_frame(vClientOdd[..], true) == 0);

    print("H2_SPEC_INVARIANTS: OK");
}

// CHECK: H2_PREFACE: OK
// CHECK: H2_SPEC_INVARIANTS: OK
