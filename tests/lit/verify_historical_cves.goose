// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_historical_cves.goose
// Verification of Historical CVEs & Regressions (Go CVE-2026-78667, OpenSSL CVE-2009-2408, uWebSockets #1876).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn test_cve_2026_78667_range_header_flood() {
    // Header exceeding 1024 bytes MUST be rejected immediately (CVE-2026-78667)
    var oversized: u8[1100] = ['a'; 1100];
    oversized[0] = 'b'; oversized[1] = 'y'; oversized[2] = 't'; oversized[3] = 'e'; oversized[4] = 's'; oversized[5] = '=';

    let rs_bad, err_bad = wing::parse_range_header(oversized[..], 1000);
    assert(err_bad == wing::RangeError.ExceededMaxRanges);
    assert(rs_bad.ranges.len == 0);
    print("CVE_2026_78667_RANGE_FLOOD_REJECTED: OK");

    let rs_good, err_good = wing::parse_range_header("bytes=0-499,500-999", 2000, true);
    assert(wing::is_ok(err_good));
    assert(rs_good.ranges.len == 1);
    assert(rs_good.ranges[0].start == 0 && rs_good.ranges[0].end_pos == 999);
    print("RANGE_COALESCE_CONTIGUOUS: OK");
}

fn test_openssl_cve_2009_2408_uri_nul() {
    assert(wing::match_uri_name_constraint("https://api.example.com/v1", "example.com"));
    assert(wing::match_uri_name_constraint("https://example.com/login", "example.com"));
    assert(!wing::match_uri_name_constraint("https://evil.com/login", "example.com"));
    print("URI_NAME_CONSTRAINTS_DOMAINS: OK");

    let nul_uri: u8[29] = [
        'h', 't', 't', 'p', 's', ':', '/', '/',
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x00,
        '.', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm',
    ];
    let nul_match = wing::match_uri_name_constraint(nul_uri[..], "example.com");
    assert(!nul_match);
    print("CVE_2009_2408_NUL_INJECTION_REJECTED: OK");
}

fn test_uwebsockets_1876_backpressure_priority() {
    var ws = wing::WebSocketSession { .. };
    wing::set_max_backpressure(ws, 80, false);

    var out_wire: u8[>..] = [];
    let _ = wing::send_text_with_status(ws, "Initial message filling backpressure quota", out_wire);
    assert(ws.is_backpressured);
    print("WS_BACKPRESSURE_SATURATED: OK");

    var dropped_wire: u8[>..] = [];
    let st2 = wing::send_text_with_status(ws, "Excessive payload dropped due to ceiling", dropped_wire);
    assert(st2 == wing::WsSendStatus.Dropped);
    print("WS_DATA_DROPPED_UNDER_BACKPRESSURE: OK");

    // Control frame Ping MUST NOT be dropped
    var ping_wire: u8[>..] = [];
    wing::send_ping(ws, "heartbeat", ping_wire);
    assert(ping_wire.len > 0);
    print("WS_PING_PRIORITY_RETAINED: OK");

    // Control frame Close MUST NOT be dropped
    var close_wire: u8[>..] = [];
    wing::close(ws, wing::WS_STATUS_NORMAL, "clean close", close_wire);
    assert(close_wire.len > 0);
    assert(ws.is_closed);
    print("WS_CLOSE_PRIORITY_RETAINED: OK");
}

fn main() {
    print("=== RUNNING HISTORICAL CVES SUITE ===");
    test_cve_2026_78667_range_header_flood();
    test_openssl_cve_2009_2408_uri_nul();
    test_uwebsockets_1876_backpressure_priority();
    print("HISTORICAL CVES COMPLETE: ALL INVARIANTS PASSED");
}

// CHECK: === RUNNING HISTORICAL CVES SUITE ===
// CHECK: CVE_2026_78667_RANGE_FLOOD_REJECTED: OK
// CHECK: RANGE_COALESCE_CONTIGUOUS: OK
// CHECK: URI_NAME_CONSTRAINTS_DOMAINS: OK
// CHECK: CVE_2009_2408_NUL_INJECTION_REJECTED: OK
// CHECK: WS_BACKPRESSURE_SATURATED: OK
// CHECK: WS_DATA_DROPPED_UNDER_BACKPRESSURE: OK
// CHECK: WS_PING_PRIORITY_RETAINED: OK
// CHECK: WS_CLOSE_PRIORITY_RETAINED: OK
// CHECK: HISTORICAL CVES COMPLETE: ALL INVARIANTS PASSED
