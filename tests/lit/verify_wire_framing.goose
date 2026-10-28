// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn decode_grpc_lpm_len(buf: const u8[:]) -> i32 {
    guard buf.len >= 5 else { return -1; }
    let flag = buf[0];
    if (flag & 0xFE) != 0 { return -1; }
    let b1 = buf[1] as i32;
    let b2 = buf[2] as i32;
    let b3 = buf[3] as i32;
    let b4 = buf[4] as i32;
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}

fn validate_tls_record_header(buf: const u8[:], max_len: i32) -> i32 {
    guard buf.len >= 5 else { return -1; }
    let ctype = buf[0] as i32;
    let v_maj = buf[1];
    let v_min = buf[2];
    let len_hi = buf[3] as i32;
    let len_lo = buf[4] as i32;
    let r_len = (len_hi << 8) | len_lo;

    if v_maj != 3 || (v_min != 3 && v_min != 1) { return -1; }
    if r_len > max_len { return 22; }
    return ctype;
}

fn find_crlfcrlf_offset(buf: const u8[:]) -> i64 {
    guard buf.len >= 4 else { return -1; }
    var i: i64 = 0;
    while i <= buf.len - 4 {
        if buf[i] == 13 && buf[i + 1] == 10 && buf[i + 2] == 13 && buf[i + 3] == 10 {
            return i;
        }
        if buf[i + 1] != 13 {
            i += 2;
        } else {
            i += 1;
        }
    }
    return -1;
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
    let tls_res = validate_tls_record_header(tls_raw[..], 16640);
    assert(tls_res == 23); // Application Data
    print("TLS_RECORD_TYPE: ", tls_res);

    var tls_overflow: u8[>..] = [];
    assert(wire_kit::parse_hex("1703034101", tls_overflow));
    let tls_over_res = validate_tls_record_header(tls_overflow[..], 16640);
    assert(tls_over_res == 22); // Record overflow alert
    print("TLS_OVERFLOW_ALERT: ", tls_over_res);

    let http_msg = "POST /submit HTTP/1.1\r\nContent-Length: 0\r\n\r\nBODY";
    let crlf_off = find_crlfcrlf_offset(http_msg);
    assert(crlf_off == 40);
    print("CRLFCRLF_OFFSET: ", crlf_off);
}

// CHECK: GRPC_LPM_LEN: 11
// CHECK: TLS_RECORD_TYPE: 23
// CHECK: TLS_OVERFLOW_ALERT: 22
// CHECK: CRLFCRLF_OFFSET: 40
