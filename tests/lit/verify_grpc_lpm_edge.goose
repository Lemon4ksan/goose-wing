// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

// Zero-allocation gRPC LPM frame decoder with 64-bit safe length checks
fn validate_grpc_lpm_wire(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 5 { return -1; }
    let flag = buf[0];
    if (flag & 254) != 0 { return -2; }

    let b1 = buf[1];
    let b2 = buf[2];
    let b3 = buf[3];
    let b4 = buf[4];
    let payload_len: i64 = ((b1 as i64) << 24) | ((b2 as i64) << 16) | ((b3 as i64) << 8) | b4;

    let total_len: i64 = 5 + payload_len;
    if len < total_len {
        return -1;
    }
    return payload_len;
}

fn main() {
    var lpm_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("000000000568656C6C6F", lpm_pkt));
    assert(wire_kit::verify_split_stream(lpm_pkt[..], -1, 5, validate_grpc_lpm_wire));
    assert(wire_kit::fuzz_payload(lpm_pkt[..], 100, validate_grpc_lpm_wire));
    print("GRPC_LPM_SPLIT: OK");

    var ovf1: u8[>..] = []; wire_kit::parse_hex("00FFFFFFFF", ovf1);
    assert(validate_grpc_lpm_wire(ovf1[..]) == -1);

    var ovf2: u8[>..] = []; wire_kit::parse_hex("00FFFFFFFB", ovf2);
    assert(validate_grpc_lpm_wire(ovf2[..]) == -1);

    var bad_flag: u8[>..] = []; wire_kit::parse_hex("0200000000", bad_flag);
    assert(validate_grpc_lpm_wire(bad_flag[..]) == -2);
    print("GRPC_LPM_INVARIANTS: OK");
}

// CHECK: GRPC_LPM_SPLIT: OK
// CHECK: GRPC_LPM_INVARIANTS: OK
