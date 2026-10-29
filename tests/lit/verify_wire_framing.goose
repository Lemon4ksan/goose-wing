// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_wire_framing.goose
// Verification of wire framing primitives: gRPC LPM, TLS record headers, and SIMD CRLFCRLF scanning.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn decode_grpc_lpm_len(buf: const u8[:]) -> i32 {
    let payload_slice, _, _, ok = wing::decode_grpc_lpm_slice(buf, 0);
    guard ok else { return -1; }
    return payload_slice.len as! i32;
}

fn validate_tls_record_header(buf: const u8[:]) -> i32 {
    let ctype, _, _, alert, ok = wing::parse_tls_record_header(buf);
    guard ok else {
        if alert == wing::TlsAlert.RecordOverflow {
            return 22;
        }
        return -1;
    }
    return ctype as! i32;
}

fn main() {
    var grpc_raw: u8[>..] = [];
    assert(wire_kit::parse_hex("000000000B68656C6C6F20776F726C64", grpc_raw));
    let grpc_len = decode_grpc_lpm_len(grpc_raw[..]);
    assert(grpc_len == 11);
    assert(grpc_raw[5] == 104); // 'h'
    assert(grpc_raw[15] == 100); // 'd'
    print("GRPC_LPM_LEN: ", grpc_len);

    var tls_raw: u8[>..] = [];
    assert(wire_kit::parse_hex("1703030010", tls_raw));
    let tls_res = validate_tls_record_header(tls_raw[..]);
    assert(tls_res == 23); // Application Data
    print("TLS_RECORD_TYPE: ", tls_res);

    var tls_overflow: u8[>..] = [];
    assert(wire_kit::parse_hex("1703034101", tls_overflow));
    let tls_over_res = validate_tls_record_header(tls_overflow[..]);
    assert(tls_over_res == 22); // Record overflow alert
    print("TLS_OVERFLOW_ALERT: ", tls_over_res);

    let http_msg = "POST /submit HTTP/1.1\r\nContent-Length: 0\r\n\r\nBODY";
    let crlf_off = core::fast_find_crlfcrlf(http_msg);
    assert(crlf_off == 40);
    print("CRLFCRLF_OFFSET: ", crlf_off);
}

// CHECK: GRPC_LPM_LEN: 11
// CHECK: TLS_RECORD_TYPE: 23
// CHECK: TLS_OVERFLOW_ALERT: 22
// CHECK: CRLFCRLF_OFFSET: 40
