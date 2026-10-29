// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_grpc_lpm_edge.goose
// Verification of gRPC Length-Prefixed Message (LPM) framing and RFC bounds via wing::grpc.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing's real decode_grpc_lpm_slice
fn wing_validate_grpc_lpm_wire(buf: const u8[:]) -> i64 {
    let payload_slice, _, _, ok = wing::decode_grpc_lpm_slice(buf, 0);
    if ok {
        return payload_slice.len;
    }
    guard buf.len >= (wing::GRPC_LPM_HEADER_LEN as i64) else { return -1; }
    let flag = buf[0];
    guard (flag & ~wing::GRPC_FLAG_COMPRESSED) == 0 else { return -2; }
    return -1;
}

fn main() {
    var lpm_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("000000000568656C6C6F", lpm_pkt));

    // Verify encode round-trip with wing::encode_grpc_lpm
    var encoded: u8[>..] = [];
    wing::encode_grpc_lpm("hello", encoded, false);
    assert(encoded[..] == lpm_pkt[..]);

    assert(wire_kit::verify_split_stream(lpm_pkt[..], -1, 5, wing_validate_grpc_lpm_wire));
    assert(wire_kit::fuzz_payload(lpm_pkt[..], 100, wing_validate_grpc_lpm_wire));
    print("GRPC_LPM_SPLIT: OK");

    var ovf1: u8[>..] = []; wire_kit::parse_hex("00FFFFFFFF", ovf1);
    assert(wing_validate_grpc_lpm_wire(ovf1[..]) == -1);

    var ovf2: u8[>..] = []; wire_kit::parse_hex("00FFFFFFFB", ovf2);
    assert(wing_validate_grpc_lpm_wire(ovf2[..]) == -1);

    var bad_flag: u8[>..] = []; wire_kit::parse_hex("0200000000", bad_flag);
    assert(wing_validate_grpc_lpm_wire(bad_flag[..]) == -2);
    print("GRPC_LPM_INVARIANTS: OK");
}

// CHECK: GRPC_LPM_SPLIT: OK
// CHECK: GRPC_LPM_INVARIANTS: OK
