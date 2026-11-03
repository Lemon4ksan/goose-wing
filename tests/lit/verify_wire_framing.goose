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

    let key: u8[16] = [0; 16];
    let iv:  u8[12] = [0; 12];
    var sealed: u8[64] = [0; 64];
    let sealed_len, seal_alert, ok_seal = wing::tls_record_seal_aes128_gcm_into(
        key, iv, 0, rfc::TLS_CONTENT_APPLICATION_DATA, "ping", sealed[..],
    );
    assert(ok_seal && seal_alert == wing::TlsAlert.CloseNotify && sealed_len == 26);
    var dec: u8[64] = [0; 64];
    let dec_len, inner_t, _, ok_dec = wing::tls_record_decrypt_aes128_gcm_into(
        key, iv, 0, sealed[..5], sealed[5..26], dec[..],
    );
    assert(ok_dec && dec_len == 4 && inner_t == rfc::TLS_CONTENT_APPLICATION_DATA && dec[..4] == "ping");
    print("TLS_SEAL_ROUNDTRIP_LEN: ", dec_len);
}

// CHECK: GRPC_LPM_LEN: 11
// CHECK: TLS_RECORD_TYPE: 23
// CHECK: TLS_OVERFLOW_ALERT: 22
// CHECK: CRLFCRLF_OFFSET: 40
// CHECK: TLS_SEAL_ROUNDTRIP_LEN: 4
