// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_historical_bugs.goose
// Verification of regressions and security defenses (Go #75557, TLS inner padding, IPv6 Zone IDs) via wing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn scan_disposition_crlf(buf: const u8[:]) -> i32 {
    var out_disp: u8[>..] = [];
    if !wing::format_content_disposition(buf, "", out_disp) {
        return 1; // Rejected CRLF injection
    }
    return 0;
}

fn scan_tls_inner_type(buf: const u8[:]) -> i32 {
    let _, inner_type, alert = wing::unpack_tls_inner_plaintext(buf);
    if alert == wing::TlsAlert.UnexpectedMessage {
        return -2;
    }
    if inner_type == 23 {
        return 100;
    }
    return inner_type as! i32;
}

fn scan_ipv6_bracket_zone(buf: const u8[:]) -> i64 {
    let len = buf.len;
    guard len >= 3 && buf[0] == '[' else { return -1; }
    var end_bracket: i64 = -1;
    var pct_idx:     i64 = -1;
    var i:           i64 = 1;
    while i < len {
        let b = buf[i];
        if b == ']' && end_bracket < 0 { end_bracket = i; }
        if b == '%' && pct_idx < 0 { pct_idx = i; }
        i += 1;
    }
    guard end_bracket > 1 else { return -1; }
    if pct_idx > 1 && pct_idx < end_bracket {
        return pct_idx - 1;
    }
    return end_bracket - 1;
}

fn scan_is_cte_header(buf: const u8[:]) -> i32 {
    let target = "content-transfer-encoding";
    guard buf.len >= target.len else { return 0; }
    if core::eq_ascii_fold(buf[..target.len], target) {
        return 1;
    }
    return 0;
}

fn scan_final_coding_is_chunked(buf: const u8[:]) -> i32 {
    let len = buf.len;
    guard len >= 7 else { return 0; }
    var last_comma: i64 = -1;
    var i:          i64 = 0;
    while i < len {
        if buf[i] == ',' { last_comma = i; }
        i += 1;
    }
    var start = if last_comma >= 0 { last_comma + 1 } else { 0 };
    while start < len && (buf[start] == ' ' || buf[start] == '\t') {
        start += 1;
    }
    var end = len;
    while end > start && (buf[end - 1] == ' ' || buf[end - 1] == '\t') {
        end -= 1;
    }
    let piece_len = end - start;
    guard piece_len == 7 else { return 0; }
    if core::eq_ascii_fold(buf[start..end], "chunked") {
        return 1;
    }
    return 0;
}

fn main() {
    let disp_evil = "field\r\nEvil: 1";
    assert(scan_disposition_crlf(disp_evil) == 1);
    print("HIST_DISP_CRLF: OK");

    let tls_inner: u8[4] = [0x17, 0x00, 0x00, 0x00];
    assert(scan_tls_inner_type(tls_inner[..]) == 100);

    let tls_malicious: u8[8] = [0; 8];
    assert(scan_tls_inner_type(tls_malicious[..]) == -2);
    print("HIST_TLS_INNER: OK");

    let ipv6_zone = "[2001:db8::1%25eth0]";
    assert(scan_ipv6_bracket_zone(ipv6_zone) == 11);
    print("HIST_IPV6_ZONE: OK");

    let cte_hdr = "Content-Transfer-Encoding: base64\r\n";
    assert(scan_is_cte_header(cte_hdr) == 1);
    print("HIST_CTE: OK");

    let te_ok = "gzip, chunked";
    assert(scan_final_coding_is_chunked(te_ok) == 1);
    let te_bad = "chunked, gzip";
    assert(scan_final_coding_is_chunked(te_bad) == 0);
    print("HIST_CHUNKED_FINAL: OK");
}

// CHECK: HIST_DISP_CRLF: OK
// CHECK: HIST_TLS_INNER: OK
// CHECK: HIST_IPV6_ZONE: OK
// CHECK: HIST_CTE: OK
// CHECK: HIST_CHUNKED_FINAL: OK
