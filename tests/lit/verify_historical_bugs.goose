// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;

fn scan_disposition_crlf(buf: const u8[:]) -> i32 {
    for b in buf {
        if b == 13 || b == 10 || b == 0 {
            return 1;
        }
    }
    return 0;
}

fn scan_tls_inner_type(buf: const u8[:]) -> i32 {
    let len = buf.len;
    if len <= 0 { return -1; }
    var found_type: i32 = 0;
    var payload_len: i64 = 0;
    var found = false;

    var i: i64 = 0;
    while i < len {
        let idx = len - 1 - i;
        let b = buf[idx];
        if !found && b != 0 {
            found_type = b;
            payload_len = idx;
            found = true;
        }
        i += 1;
    }

    if !found { return -2; }
    if found_type == 23 && payload_len == 0 { return 100; }
    if found_type != 23 && payload_len == 0 { return -3; }
    return found_type;
}

fn scan_ipv6_bracket_zone(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 3 { return -1; }
    if buf[0] != 91 { return -1; } // '['
    var end_bracket: i64 = -1;
    var pct_idx: i64 = -1;
    var i: i64 = 1;
    while i < len {
        let b = buf[i];
        if b == 93 && end_bracket < 0 { end_bracket = i; } // ']'
        if b == 37 && pct_idx < 0 { pct_idx = i; }         // '%'
        i += 1;
    }
    if end_bracket <= 1 { return -1; }
    if pct_idx > 1 && pct_idx < end_bracket {
        return pct_idx - 1;
    }
    return end_bracket - 1;
}

fn scan_is_cte_header(buf: const u8[:]) -> i32 {
    let target = "content-transfer-encoding";
    if buf.len < target.len { return 0; }
    for i in target.len {
        var b = buf[i];
        if b >= 65 && b <= 90 { b += 32; }
        if b != target[i] { return 0; }
    }
    return 1;
}

fn scan_final_coding_is_chunked(buf: const u8[:]) -> i32 {
    let len = buf.len;
    if len < 7 { return 0; }
    var last_comma: i64 = -1;
    var i: i64 = 0;
    while i < len {
        if buf[i] == 44 { last_comma = i; }
        i += 1;
    }
    var start = if last_comma >= 0 { last_comma + 1 } else { 0 };
    while start < len && (buf[start] == 32 || buf[start] == 9) {
        start += 1;
    }
    var end = len;
    while end > start && (buf[end - 1] == 32 || buf[end - 1] == 9) {
        end -= 1;
    }
    let piece_len = end - start;
    if piece_len != 7 { return 0; }
    let chunked = "chunked";
    for j in 7 {
        if buf[start + j] != chunked[j] { return 0; }
    }
    return 1;
}

fn main() {
    let disp_evil = "form-data; name=\"field\r\nEvil: 1\"";
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
