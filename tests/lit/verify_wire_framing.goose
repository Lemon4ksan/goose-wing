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
    return ctype;
}

fn verify_h1_wire_parsers() {
    var st_code: u16 = 0;
    assert(wire::parse_h1_wire_status_line("HTTP/1.1 200", st_code) && st_code == 200);
    let fn_len, fn_ok = wire::scan_h1_wire_field_name("X-Valid-Header: val\r\n");
    assert(fn_ok && fn_len == 14);
    let _, bad_fn = wire::scan_h1_wire_field_name("Bad@Header-Name: val\r\n");
    assert(!bad_fn);
    let _, bad_swar = wing::scan_header_field_name_swar("Bad/Header-Name: val\r\n");
    assert(!bad_swar);

    let m_conn, l_conn, ok_conn = wing::match_http_method_u32("CONNECT authority:443 HTTP/1.1\r\n");
    assert(ok_conn && m_conn == "CONNECT" && l_conn == 8);
    let m_opt, l_opt, ok_opt = wing::match_http_method_u32("OPTIONS * HTTP/1.1\r\n");
    assert(ok_opt && m_opt == "OPTIONS" && l_opt == 8);
    let m_trc, l_trc, ok_trc = wing::match_http_method_u32("TRACE / HTTP/1.1\r\n");
    assert(ok_trc && m_trc == "TRACE" && l_trc == 6);
    let m_pat, l_pat, ok_pat = wing::match_http_method_u32("PATCH /item HTTP/1.1\r\n");
    assert(ok_pat && m_pat == "PATCH" && l_pat == 6);

    var req_map = wing::HeaderMap { .. };
    let req_err = wing::parse_request_headers("\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n", req_map);
    assert(req_err == wing::HeaderParseError.None && wing::get_header(req_map, "host") == "example.com");

    var res_map = wing::HeaderMap { .. };
    let res_err = wing::parse_response_headers_with_mode(
        "ICY 200 OK\r\nicy-name : stream\r\n\r\n",
        res_map,
        wing::H1ResponseParseMode.ClientCompat,
    );
    assert(res_err == wing::HeaderParseError.None && res_map.status_code == 200);
    assert(wing::get_header(res_map, "icy-name") == "stream");

    assert(wing::is_chunk_overhead_excessive(120000, 102400));
    assert(!wing::is_chunk_overhead_excessive(500000, 102400));
    assert(internal::is_chunk_overhead_excessive(120000, 102400));
    print("H1_WIRE_PARSERS: OK");
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
    verify_h1_wire_parsers();
}

// CHECK: GRPC_LPM_LEN: 11
// CHECK: TLS_RECORD_TYPE: 23
// CHECK: TLS_OVERFLOW_ALERT: 22
// CHECK: CRLFCRLF_OFFSET: 40
// CHECK: TLS_SEAL_ROUNDTRIP_LEN: 4
// CHECK: H1_WIRE_PARSERS: OK
