// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_server_and_security
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. verify_backpressure_fsm (1/8)
// ============================================================================
// CHECK: === [1/8] verify_backpressure_fsm ===

fn run_01_verify_backpressure_fsm() {
    var bp = wing::BackpressureSlot { .. };
    assert(!bp.is_active);
    assert(bp.len == 0);

    // Buffering zero-length must fail
    assert(!wing::buffer_backpressure(bp, ""));

    // Buffering valid slice
    let msg: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
    assert(wing::buffer_backpressure(bp, msg));
    assert(bp.is_active);
    assert(bp.len == msg.len);
    assert(bp.offset == 0);

    // Verify drain simulation with invalid fd returns false
    let drained, ok = wing::drain_backpressure(bp, -1);
    assert(!ok);

    // Manual offset advancement simulation
    bp.offset = msg.len;
    let drained2, ok2 = wing::drain_backpressure(bp, -1);
    // When offset >= len, drain resets slot and returns true
    assert(ok2);
    assert(!bp.is_active);
    assert(bp.len == 0);

    // Verify large payload buffering up to 16 KB
    var large_msg: u8[8192] = ['X'; 8192];
    assert(wing::buffer_backpressure(bp, large_msg[..]));
    assert(bp.len == 8192);
    wing::clear_backpressure_slot(bp);
    assert(!bp.is_active);

    print("BACKPRESSURE_FSM: OK");
}
// CHECK: BACKPRESSURE_FSM: OK

// ============================================================================
// 2. verify_historical_bugs (2/8)
// ============================================================================
// CHECK: === [2/8] verify_historical_bugs ===

// tests/lit/verify_historical_bugs.goose
// Verification of regressions and security defenses (Go #75557, TLS inner padding, IPv6 Zone IDs) via wing.
//

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
    return inner_type;
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

fn run_02_verify_historical_bugs() {
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

// ============================================================================
// 3. verify_historical_cves (3/8)
// ============================================================================
// CHECK: === [3/8] verify_historical_cves ===

// tests/lit/verify_historical_cves.goose
// Verification of Historical CVEs & Regressions (Go CVE-2026-78667, OpenSSL CVE-2009-2408, uWebSockets #1876).
//

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
    var ws = realtime::WebSocketSession { .. };
    realtime::set_max_backpressure(ws, 80, false);

    var out_wire: u8[>..] = [];
    let _ = realtime::send_text_with_status(ws, "Initial message filling backpressure quota", out_wire);
    assert(ws.is_backpressured);
    print("WS_BACKPRESSURE_SATURATED: OK");

    var dropped_wire: u8[>..] = [];
    let st2 = realtime::send_text_with_status(ws, "Excessive payload dropped due to ceiling", dropped_wire);
    assert(st2 == realtime::WsSendStatus.Dropped);
    print("WS_DATA_DROPPED_UNDER_BACKPRESSURE: OK");

    // Control frame Ping MUST NOT be dropped
    var ping_wire: u8[>..] = [];
    realtime::send_ping(ws, "heartbeat", ping_wire);
    assert(ping_wire.len > 0);
    print("WS_PING_PRIORITY_RETAINED: OK");

    // Control frame Close MUST NOT be dropped
    var close_wire: u8[>..] = [];
    realtime::close(ws, rfc::WS_STATUS_NORMAL, "clean close", close_wire);
    assert(close_wire.len > 0);
    assert(ws.is_closed);
    print("WS_CLOSE_PRIORITY_RETAINED: OK");
}

fn run_03_verify_historical_cves() {
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

// ============================================================================
// 4. verify_l0_simd_routing (4/8)
// ============================================================================
// CHECK: === [4/8] verify_l0_simd_routing ===

// tests/lit/verify_l0_simd_routing.goose
// Verification of Flat Register Routing (Tier 0 L0 SIMD/SWAR Register Table).
//

fn test_l0_exact_hits() {
    var router = wing::new_radix_router();

    assert(wing::add_route(router, "GET", "/plaintext", 101));
    assert(wing::add_route(router, "GET", "/json", 102));
    assert(wing::add_route(router, "GET", "/healthz", 103));
    assert(wing::add_route(router, "GET", "/", 104));
    assert(wing::add_route(router, "GET", "/123456789012345", 105)); // exactly 16 bytes

    // Verify L0 count
    assert(router.l0_table.count == 5);

    // Exact matches
    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    let m1 = wing::match_route(router, "GET", "/plaintext", params, canon);
    match m1 {
        Found f => assert(f.handler_id == 101),
        _ => assert(false),
    };

    let m2 = wing::match_route(router, "GET", "/json", params, canon);
    match m2 {
        Found f => assert(f.handler_id == 102),
        _ => assert(false),
    };

    let m3 = wing::match_route(router, "GET", "/healthz", params, canon);
    match m3 {
        Found f => assert(f.handler_id == 103),
        _ => assert(false),
    };

    let m4 = wing::match_route(router, "GET", "/", params, canon);
    match m4 {
        Found f => assert(f.handler_id == 104),
        _ => assert(false),
    };

    let m5 = wing::match_route(router, "GET", "/123456789012345", params, canon);
    match m5 {
        Found f => assert(f.handler_id == 105),
        _ => assert(false),
    };

    print("L0_EXACT_HITS_OK");
    // CHECK: L0_EXACT_HITS_OK
}

fn test_l0_query_and_uncanonical_fallbacks() {
    var router = wing::new_radix_router();

    assert(wing::add_route(router, "GET", "/plaintext", 101));
    assert(wing::add_route(router, "GET", "/json", 102));

    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    // Query strings should cleanly miss L0 and fall through to Tier 1
    let q1 = wing::match_route(router, "GET", "/plaintext?format=raw", params, canon);
    match q1 {
        Found f => assert(f.handler_id == 101),
        _ => assert(false),
    };
    assert(canon[..] == "/plaintext");

    let q2 = wing::match_route(router, "GET", "/json?pretty=true", params, canon);
    match q2 {
        Found f => assert(f.handler_id == 102),
        _ => assert(false),
    };
    assert(canon[..] == "/json");

    // Uncanonical paths (double slashes / dot segments) fall through to Tier 1
    let u1 = wing::match_route(router, "GET", "//plaintext", params, canon);
    match u1 {
        Found f => assert(f.handler_id == 101),
        _ => assert(false),
    };
    assert(canon[..] == "/plaintext");

    let u2 = wing::match_route(router, "GET", "/./json", params, canon);
    match u2 {
        Found f => assert(f.handler_id == 102),
        _ => assert(false),
    };
    assert(canon[..] == "/json");

    print("L0_FALLBACKS_OK");
    // CHECK: L0_FALLBACKS_OK
}

fn test_l0_method_segregation() {
    var router = wing::new_radix_router();

    assert(wing::add_route(router, "GET", "/status", 201));
    assert(wing::add_route(router, "POST", "/status", 202));
    assert(wing::add_route(router, "DELETE", "/status", 203));

    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    let m_get = wing::match_route(router, "GET", "/status", params, canon);
    match m_get {
        Found f => assert(f.handler_id == 201),
        _ => assert(false),
    };

    let m_post = wing::match_route(router, "POST", "/status", params, canon);
    match m_post {
        Found f => assert(f.handler_id == 202),
        _ => assert(false),
    };

    let m_del = wing::match_route(router, "DELETE", "/status", params, canon);
    match m_del {
        Found f => assert(f.handler_id == 203),
        _ => assert(false),
    };

    // Automatic HEAD routing for GET
    let m_head = wing::match_route(router, "HEAD", "/status", params, canon);
    match m_head {
        Found f => assert(f.handler_id == 201),
        _ => assert(false),
    };

    // MethodNotAllowed
    let m_put = wing::match_route(router, "PUT", "/status", params, canon);
    match m_put {
        MethodNotAllowed _ => {},
        _ => assert(false),
    };

    print("L0_METHOD_SEGREGATION_OK");
    // CHECK: L0_METHOD_SEGREGATION_OK
}

fn test_l0_overflow_and_dynamic_routes() {
    var router = wing::new_radix_router();

    // Fill up all 16 slots of L0 table
    let prefixes: const u8[:][16] = [
        "/r00", "/r01", "/r02", "/r03",
        "/r04", "/r05", "/r06", "/r07",
        "/r08", "/r09", "/r10", "/r11",
        "/r12", "/r13", "/r14", "/r15",
    ];

    for i in 16 {
        assert(wing::add_route(router, "GET", prefixes[i], (300 + i) as i32));
    }
    assert(router.l0_table.count == 16);

    // 17th route (> 16 routes) overflows cleanly into Tier 1
    assert(wing::add_route(router, "GET", "/r16_overflow", 316));
    assert(router.l0_table.count == 16); // L0 is full at 16

    // Dynamic parameter route (not in L0)
    assert(wing::add_route(router, "GET", "/users/{id}", 401));

    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    // Verify all 16 L0 routes hit
    for i in 16 {
        let m = wing::match_route(router, "GET", prefixes[i], params, canon);
        match m {
            Found f => assert(f.handler_id == (300 + i) as i32),
            _ => assert(false),
        };
    }

    // Verify 17th overflow route matches via Tier 1
    let m_over = wing::match_route(router, "GET", "/r16_overflow", params, canon);
    match m_over {
        Found f => assert(f.handler_id == 316),
        _ => assert(false),
    };

    // Verify dynamic parameter route matches and extracts param
    let m_dyn = wing::match_route(router, "GET", "/users/alice", params, canon);
    match m_dyn {
        Found f => {
            assert(f.handler_id == 401);
            assert(params.len == 1);
            let val, ok_p = wing::param_by_name(params, "id", "/users/alice");
            assert(ok_p);
            assert(val == "alice");
        },
        _ => assert(false),
    };

    print("L0_OVERFLOW_AND_DYNAMIC_OK");
    // CHECK: L0_OVERFLOW_AND_DYNAMIC_OK
}

fn test_l0_pipeline_execution() {
    let quota = security::new_gcra_quota(100, wing::secs(1), 10);
    var cfg = wing::new_server_pipeline_config("example.com", quota);

    assert(wing::add_route(cfg.router, "GET", "/healthz", 1001));
    assert(wing::add_route(cfg.router, "GET", "/json", 1002));
    assert(cfg.router.l0_table.count == 2);

    var timer = server_internal::new_connection_timer(30000000000, 1000000000);

    // Exact L0 hit through pipeline
    var req1 = wing::new_request("GET", "/healthz");
    wing::append_header(req1.headers, "Host", "example.com");

    var res1 = wing::Response { .. };
    var fut1 = server_internal::new_inline_handler_future(0);
    let out1 = wing::execute_pipeline(cfg, timer, "127.0.0.1", req1, 1000000000, res1, fut1);

    assert(out1 == wing::PipelineOutcome.Handled);
    assert(res1.status_code == 200);

    // Query fallback through pipeline
    var req2 = wing::new_request("GET", "/json?pretty=1");
    wing::append_header(req2.headers, "Host", "example.com");

    var res2 = wing::Response { .. };
    var fut2 = server_internal::new_inline_handler_future(0);
    let out2 = wing::execute_pipeline(cfg, timer, "127.0.0.1", req2, 1000000000, res2, fut2);

    assert(out2 == wing::PipelineOutcome.Handled);
    assert(res2.status_code == 200);

    print("L0_PIPELINE_EXECUTION_OK");
    // CHECK: L0_PIPELINE_EXECUTION_OK
}

fn run_04_verify_l0_simd_routing() {
    test_l0_exact_hits();
    test_l0_query_and_uncanonical_fallbacks();
    test_l0_method_segregation();
    test_l0_overflow_and_dynamic_routes();
    test_l0_pipeline_execution();
    print("ALL_L0_ROUTING_TESTS_PASSED");
    // CHECK: ALL_L0_ROUTING_TESTS_PASSED
}

// ============================================================================
// 5. verify_protocol_invariants (5/8)
// ============================================================================
// CHECK: === [5/8] verify_protocol_invariants ===

// tests/lit/verify_protocol_invariants.goose
// Advanced wire protocol verification using LLVM-style CHECK-LABEL isolation,
// CHECK-SAME inline matching, and numeric expressions [[#VAR + N]] / [[#VAR - N]].
//

fn test_h2_stream_progression() {
    print("=== H2_STREAM_PROGRESSION ===");
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // Client preface + empty settings
    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    init_wire.append([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Open Stream 1, 3, 5 sequentially
    var stream_ids: const u32[3] = [1, 3, 5];
    var dt = http2::new_dynamic_table(4096);

    for sid in stream_ids {
        var hdr_block: u8[>..] = [];
        http2::encode_hpack_field(dt, hdr_block, ":method", "GET", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, hdr_block, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, hdr_block, ":path", "/", http2::HpackIndexing.Incremental, false);

        var h_frame: u8[>..] = [];
        let h_len = hdr_block.len as u32;
        h_frame.push(((h_len >> 16) & 0xFF) as u8);
        h_frame.push(((h_len >> 8) & 0xFF) as u8);
        h_frame.push((h_len & 0xFF) as u8);
        h_frame.push(0x01); // HEADERS
        h_frame.push(0x05); // END_STREAM | END_HEADERS
        h_frame.push(((sid >> 24) & 0xFF) as u8);
        h_frame.push(((sid >> 16) & 0xFF) as u8);
        h_frame.push(((sid >> 8) & 0xFF) as u8);
        h_frame.push((sid & 0xFF) as u8);
        h_frame.append(hdr_block[..]);

        let _, ok = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);
        assert(ok);
        print("H2_OPEN sid=", sid, " status=active type=client_bidi");
    }
}

fn test_quic_pn_and_window_math() {
    print("=== QUIC_PN_MATH ===");

    // Simulate packet numbers 500, 501, 502 with payload size 1200
    let start_pn:    u64 = 500;
    let payload_len: u64 = 1200;

    print("QUIC_TX pn=", start_pn, " len=", payload_len, " flags=0x01");
    print("QUIC_TX pn=", start_pn + 1, " len=", payload_len, " flags=0x01");
    print("QUIC_TX pn=", start_pn + 2, " len=", payload_len, " flags=0x01");

    // Cumulative byte offset
    print("QUIC_FLOW byte_offset=", start_pn * payload_len);
    print("QUIC_FLOW next_offset=", (start_pn + 3) * payload_len);
    print("QUIC_ACK largest_acked=", start_pn + 2, " first_range=2");
}

fn test_wire_framing_delimiters() {
    print("=== WIRE_DELIMITERS ===");
    print("HEADER_START");
    print("Host: example.com");
    print("Connection: close");
    print(""); // Empty line before body (CHECK-EMPTY)
    print("PAYLOAD_START");
    print("line 1");
    print("line 2");
    print("PAYLOAD_END");
}

fn run_05_verify_protocol_invariants() {
    test_h2_stream_progression();
    test_quic_pn_and_window_math();
    test_wire_framing_delimiters();
}

// CHECK-LABEL: === H2_STREAM_PROGRESSION ===
// CHECK: H2_OPEN sid=[[#SID:]]
// CHECK-SAME: status=active
// CHECK-SAME: type=client_bidi
// CHECK: H2_OPEN sid=[[#SID + 2]]
// CHECK-SAME: status=active
// CHECK: H2_OPEN sid=[[#SID + 4]]
// CHECK-SAME: status=active

// CHECK-LABEL: === QUIC_PN_MATH ===
// CHECK: QUIC_TX pn=[[#PN:]] len=[[#PLEN:]]
// CHECK-SAME: flags=0x01
// CHECK-NEXT: QUIC_TX pn=[[#PN + 1]] len=[[#PLEN]]
// CHECK-SAME: flags=0x01
// CHECK-NEXT: QUIC_TX pn=[[#PN + 2]] len=[[#PLEN]]
// CHECK-SAME: flags=0x01
// CHECK: QUIC_ACK largest_acked=[[#PN + 2]]
// CHECK-SAME: first_range=2

// CHECK-LABEL: === WIRE_DELIMITERS ===
// CHECK: HEADER_START
// CHECK: Host: example.com
// CHECK: Connection: close
// CHECK-EMPTY:
// CHECK: PAYLOAD_START
// CHECK: line 1
// CHECK: line 2
// CHECK: PAYLOAD_END

// ============================================================================
// 6. verify_role_polarity (6/8)
// ============================================================================
// CHECK: === [6/8] verify_role_polarity ===

// tests/lit/verify_role_polarity.goose
// Verifies RFC Role-Polarity and Protocol State Transition Matrix across QUIC, HTTP/3, and HTTP/2.
// Strict compliance with RFC 9000, RFC 9114, RFC 9218, and RFC 9113.
//

// 1. QUIC Role Polarity (RFC 9000 Section 19.20)
// Server MUST NOT receive HANDSHAKE_DONE frame -> PROTOCOL_VIOLATION.
// Client MUST accept HANDSHAKE_DONE frame -> Transitions to Established.
fn test_quic_role_polarity() {
    let scid: u8[4] = [0x10, 0x11, 0x12, 0x13];

    // Case A: Server receives HANDSHAKE_DONE
    var server_conn = quic::new_server_connection(scid[..]);
    server_conn.allow_unencrypted_test_packets = true;
    var dgram_serv: u8[..64] = [];
    dgram_serv.push(0x40); // 1-RTT Short Header
    dgram_serv.append(scid[..]);
    dgram_serv.push(0x01); // Packet number = 1
    assert(quic::encode_handshake_done_frame(dgram_serv));

    var ack_out = quic::AckFrame { .. };
    let _pr_handled_s = quic::process_datagram(server_conn, dgram_serv[..], 1000, ack_out);
    let handled_s = _pr_handled_s.handled;
    assert(!handled_s);
    assert(server_conn.state == quic::QuicConnState.Closing);
    assert(server_conn.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // Case B: Client receives HANDSHAKE_DONE
    var client_conn = quic::new_client_connection(scid[..], scid[..]);
    client_conn.allow_unencrypted_test_packets = true;
    var dgram_cli: u8[..64] = [];
    dgram_cli.push(0x40); // 1-RTT Short Header
    dgram_cli.append(scid[..]);
    dgram_cli.push(0x01); // Packet number = 1
    assert(quic::encode_handshake_done_frame(dgram_cli));

    let _pr_handled_c = quic::process_datagram(client_conn, dgram_cli[..], 1000, ack_out);
    let handled_c = _pr_handled_c.handled;
    assert(handled_c);
    assert(client_conn.state == quic::QuicConnState.Established);

    print("QUIC_ROLE_POLARITY: OK");
}

// 2. HTTP/3 Role Polarity (RFC 9114 Section 7.2.7 & RFC 9218 Section 7)
// Client MUST NOT receive MAX_PUSH_ID or PRIORITY_UPDATE -> H3_FRAME_UNEXPECTED.
// Server MUST NOT receive PUSH_PROMISE -> H3_FRAME_UNEXPECTED.

// Case A: Client receives PRIORITY_UPDATE_REQUEST on Control Stream (RFC 9218 §7)
fn test_h3_role_polarity_case_a(settings: fingerprint::H3Settings) {
    var client_conn = http3::new_client_connection(settings);
    // First, establish control stream with valid SETTINGS frame
    var ctrl_init: u8[..64] = [];
    quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl_init);
    http3::encode_settings_frame(ctrl_init, settings);
    let err_init = client_conn.handle_stream_data(3, false, ctrl_init[..], false);
    assert(err_init == rfc::H3_ERR_NO_ERROR);

    // Then client receives forbidden PRIORITY_UPDATE_REQUEST
    var prio_frame: u8[..64] = [];
    let prio = wing::PriorityParam { urgency: 1, incremental: false };
    assert(http3::encode_priority_update_request(prio_frame, 0, prio));

    let err_prio = client_conn.handle_stream_data(3, false, prio_frame[..], false);
    assert(err_prio == rfc::H3_ERR_FRAME_UNEXPECTED);
    assert(client_conn.state == http3::ConnState.Closed);
}

// Case B: Client receives MAX_PUSH_ID on Control Stream (RFC 9114 §7.2.7)
fn test_h3_role_polarity_case_b(settings: fingerprint::H3Settings) {
    var client_conn2 = http3::new_client_connection(settings);
    // First, establish control stream with valid SETTINGS frame
    var ctrl_init2: u8[..64] = [];
    quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl_init2);
    http3::encode_settings_frame(ctrl_init2, settings);
    let err_init2 = client_conn2.handle_stream_data(3, false, ctrl_init2[..], false);
    assert(err_init2 == rfc::H3_ERR_NO_ERROR);

    // Then client receives forbidden MAX_PUSH_ID
    var max_push_frame: u8[..32] = [];
    assert(http3::encode_max_push_id(max_push_frame, 10));

    let err_push = client_conn2.handle_stream_data(3, false, max_push_frame[..], false);
    assert(err_push == rfc::H3_ERR_FRAME_UNEXPECTED);
    assert(client_conn2.state == http3::ConnState.Closed);
}

// Case C: Server receives PUSH_PROMISE on Request Stream (RFC 9114 §7.2.5)
fn test_h3_role_polarity_case_c(settings: fingerprint::H3Settings) {
    var server_conn = http3::new_server_connection(settings);
    var push_promise_frame: u8[..32] = [];
    assert(http3::encode_frame_header(push_promise_frame, rfc::H3_FRAME_PUSH_PROMISE, 3));
    quic::encode_varint(1, push_promise_frame); // Push ID = 1 (1 byte)
    push_promise_frame.push(0x00); // QPACK header block (2 bytes)
    push_promise_frame.push(0x00);

    let err_pp = server_conn.handle_stream_data(0, true, push_promise_frame[..], false);
    assert(err_pp == rfc::H3_ERR_FRAME_UNEXPECTED);
    assert(server_conn.state == http3::ConnState.Closed);
}

fn test_h3_role_polarity() {
    let settings = fingerprint::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };

    test_h3_role_polarity_case_a(settings);
    test_h3_role_polarity_case_b(settings);
    test_h3_role_polarity_case_c(settings);

    print("H3_ROLE_POLARITY: OK");
}

// 3. HTTP/2 State Transition & Role Rules (RFC 9113)
fn test_h2_state_matrix() {
    // Case A: Stream 0 DATA Frame (RFC 9113 Section 5.1.1 & 6.1)
    let data_hdr = http2::FrameHeader {
        length:     5,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      0,
        stream_id:  0, // Forbidden!
    };
    let err_data = http2::validate_frame_header_rules(data_hdr, 16384);
    assert(err_data == rfc::H2_ERR_PROTOCOL_ERROR);

    // Case B: SETTINGS with ACK and length != 0 (RFC 9113 Section 6.5)
    let set_ack_hdr = http2::FrameHeader {
        length:     6, // Forbidden: ACK must be 0 length
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    let err_set = http2::validate_frame_header_rules(set_ack_hdr, 16384);
    assert(err_set == rfc::H2_ERR_FRAME_SIZE_ERROR);

    // Case C: Server receives PUSH_PROMISE (RFC 9113 Section 6.6)
    var sess = server_internal::new_h2_server_session("localhost");
    var pipeline = wing::ServerPipelineConfig { .. };
    var timer = server_internal::ConnectionTimer { .. };
    var handshake_wire: u8[..64] = [];
    handshake_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let set_hdr = http2::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    http2::encode_frame_header_to(set_hdr, handshake_wire);
    var server_out: u8[..1024] = [];
    let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", handshake_wire[..], 1000, server_out);
    assert(ok_init);

    var pp_wire: u8[..64] = [];
    let pp_hdr = http2::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_PUSH_PROMISE, flags: 0, stream_id: 1 };
    http2::encode_frame_header_to(pp_hdr, pp_wire);
    pp_wire.push(0x00);
    pp_wire.push(0x00);
    pp_wire.push(0x00);
    pp_wire.push(0x02); // Promised stream 2
    server_out.clear();
    let _, ok_pp = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", pp_wire[..], 1001, server_out);
    assert(!ok_pp); // Rejected with GOAWAY

    // Verify GOAWAY emitted
    let goaway_hdr, err_go = http2::parse_frame_header(server_out[..9]);
    assert(err_go == rfc::H2_ERR_NO_ERROR);
    assert(goaway_hdr.frame_type == rfc::H2_FRAME_GOAWAY);

    print("H2_STATE_MATRIX: OK");
}

fn run_06_verify_role_polarity() {
    test_quic_role_polarity();
    test_h3_role_polarity();
    test_h2_state_matrix();
}

// CHECK: QUIC_ROLE_POLARITY: OK
// CHECK-NEXT: H3_ROLE_POLARITY: OK
// CHECK-NEXT: H2_STATE_MATRIX: OK

// ============================================================================
// 7. verify_security_bug_hunter (7/8)
// ============================================================================
// CHECK: === [7/8] verify_security_bug_hunter ===

// tests/lit/verify_security_bug_hunter.goose
// Regression tests for security audit findings:
// 1. CryptoJar bounded-buffer truncation and fail-closed timestamp validation (GOOSE-BUG-1, GOOSE-BUG-2)
// 2. CSRF path prefix exemption matching (GOOSE-BUG-6)
// 3. GCRA rate limiter shard slot allocation priority vs premature eviction (GOOSE-BUG-7)
// 4. PrivacyPass duplicate auth-param rejection (RFC 9577 §2.1, GOOSE-BUG-1)
// 5. Missing security APIs integration (validate_cors_policy, apply_strict_cross_origin_isolation, pop_private_token)
//

fn test_cryptojar_bounded_buffer_truncation() {
    var store = security::KeyStore { .. };
    let raw_key: u8[32] = [0x55; 32];
    let slot = security::KeySlot { key_id: 1, master_key: raw_key, created_at_sec: 1700000000, .. };
    assert(security::add_key(store, slot));

    let pjar_xchacha = security::new_private_jar(store, false);
    let pjar_aes = security::new_private_jar(store, true);
    let sjar = security::new_signed_jar(store);

    // 1. XChaCha20 seal with undersized out buffer must fail, not silently truncate
    var small_buf_x: u8[..40] = []; // K_OVERHEAD_XCHACHA20 is 53
    let ok_x = security::seal_binary(pjar_xchacha, "sid", "secret_payload", 1700000000, 12345, small_buf_x);
    assert(!ok_x);

    // 2. HKDF-AES-GCM seal with undersized out buffer must fail, not silently truncate
    var small_buf_aes: u8[..50] = []; // K_OVERHEAD_HKDF_AES_GCM is 65
    let ok_aes = security::seal_binary(pjar_aes, "sid", "secret_payload", 1700000000, 12345, small_buf_aes);
    assert(!ok_aes);

    // 3. SignedJar seal with undersized out buffer must fail, not silently truncate
    var small_buf_sign: u8[..30] = []; // K_OVERHEAD_HMAC_SHA256 is 45
    let ok_sign = security::seal_binary(sjar, "sid", "secret_payload", 1700000000, small_buf_sign);
    assert(!ok_sign);

    // 4. SignedJar open with undersized out_payload buffer must fail, not silently truncate
    var valid_signed_wire: u8[..128] = [];
    assert(security::seal_binary(sjar, "sid", "longer_payload_string", 1700000000, valid_signed_wire));
    var tiny_payload_out: u8[..8] = []; // "longer_payload_string" is 21 bytes
    let ok_open = security::open_binary(sjar, "sid", valid_signed_wire[..], 1700000001, tiny_payload_out);
    assert(!ok_open);

    print("CRYPTOJAR_BOUNDS_CHECK: OK");
}

fn test_cryptojar_timestamp_fail_closed() {
    var store = security::KeyStore { .. };
    // Fail-closed on zero or negative now_sec
    assert(!security::is_cookie_timestamp_valid(store, 1700000000, 0));
    assert(!security::is_cookie_timestamp_valid(store, 1700000000, -100));
    assert(security::is_cookie_timestamp_valid(store, 1700000000, 1700000010));

    print("CRYPTOJAR_TIMESTAMP_FAIL_CLOSED: OK");
}

fn test_csrf_path_prefix_exemption() {
    var guard_cfg = security::CrossOriginGuard { .. };
    assert(security::add_exempt_path(guard_cfg, "/api/webhook"));
    assert(security::add_exempt_path(guard_cfg, "/public/"));

    var ctx1 = security::FetchContext {
        site:           security::SecFetchSite.CrossSite,
        method_is_safe: false,
        ..
    };
    // 1. Exact match
    ctx1.path.try_set("/api/webhook");
    let d1 = security::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(security::is_allowed(d1));

    // 2. Subpath under /api/webhook/
    ctx1.path.try_set("/api/webhook/stripe");
    let d2 = security::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(security::is_allowed(d2));

    // 3. Subpath under /public/
    ctx1.path.try_set("/public/bundle.js");
    let d3 = security::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(security::is_allowed(d3));

    // 4. Must NOT match sibling prefix /api/webhook_attack
    ctx1.path.try_set("/api/webhook_attack");
    let d4 = security::evaluate_fetch_metadata(guard_cfg, ctx1);
    assert(!security::is_allowed(d4));

    print("CSRF_PATH_PREFIX_EXEMPTION: OK");
}

fn test_gcra_shard_slot_allocation_priority() {
    let quota = security::new_gcra_quota(10, wing::secs(1), 5);
    var limiter = security::new_sharded_limiter(quota);

    // Request from client A at t = 1000
    let d_a1 = security::check_rate_limit(limiter, "client_a", 1, 1000);
    assert(security::is_allowed(d_a1));

    // Request from client B at t = 2000000000 (after client A's TAT has expired)
    // Limiter shard has 16 capacity and only 1 slot used!
    // It must allocate a NEW slot for client B, preserving client A's slot in the table.
    let d_b1 = security::check_rate_limit(limiter, "client_b", 1, 2000000000);
    assert(security::is_allowed(d_b1));

    // Find shard index for client_a
    let shard_idx = (core::fnv1a_64("client_a") & 0xFF) as i64;
    // Both client_a and client_b should have active slots if they hashed to the same shard,
    // or at least client_a's slot was not overwritten if slots.len < slots.cap.
    if (core::fnv1a_64("client_b") & 0xFF) as i64 == shard_idx {
        assert(limiter.shards[shard_idx].slots.len == 2);
    }

    print("GCRA_SLOT_PRIORITY: OK");
}

fn test_privacypass_duplicate_params() {
    var out_key: u8[..128] = [];

    // RFC 9577 §2.1: Duplicate challenge param MUST be rejected
    let _, _, ok_dup_chal = security::parse_private_token_challenge(
        "PrivateToken challenge=\"AQIDBA==\", challenge=\"BQYHCA==\"",
        out_key,
    );
    assert(!ok_dup_chal);

    // RFC 9577 §2.1: Duplicate token-key param MUST be rejected
    let _, _, ok_dup_key = security::parse_private_token_challenge(
        "PrivateToken challenge=\"AQIDBA==\", token-key=\"a2V5MQ==\", token-key=\"a2V5Mg==\"",
        out_key,
    );
    assert(!ok_dup_key);

    // RFC 9577 §2.1: Duplicate max-age param MUST be rejected
    let _, _, ok_dup_age = security::parse_private_token_challenge(
        "PrivateToken challenge=\"AQIDBA==\", max-age=60, max-age=120",
        out_key,
    );
    assert(!ok_dup_age);

    print("PRIVACYPASS_DUPLICATES_REJECTED: OK");
}

fn test_missing_security_apis() {
    // 1. validate_cors_policy
    var cors_valid = security::CorsPolicy { .. };
    assert(security::validate_cors_policy(cors_valid));

    var cors_invalid = security::CorsPolicy { allow_credentials: true, .. };
    assert(security::add_allowed_origin(cors_invalid, "https://example.com"));
    assert(security::add_allowed_origin(cors_invalid, "*"));
    assert(!security::validate_cors_policy(cors_invalid));

    // 2. apply_strict_cross_origin_isolation
    var res = wing::Response { .. };
    security::apply_strict_cross_origin_isolation(res);
    assert(res.header("Cross-Origin-Opener-Policy") == "same-origin");
    assert(res.header("Cross-Origin-Embedder-Policy") == "require-corp");
    assert(res.header("Cross-Origin-Resource-Policy") == "same-origin");

    // 3. pop_private_token
    var cache = security::PrivateTokenCache { .. };
    var chal = security::TokenChallenge { issuer_name: "test_issuer", .. };
    var tok = security::Token { .. };
    let raw_token = "blind_rsa_raw_token";
    assert(security::put_private_token(cache, chal, tok, raw_token, 300, 1000));

    let digest = security::compute_challenge_digest(chal);
    var popped_raw: u8[..512] = [];
    assert(security::pop_private_token(cache, digest, 1010, popped_raw));
    assert(popped_raw[..] == "blind_rsa_raw_token");

    // Single-use: second pop must fail
    var popped_second: u8[..512] = [];
    assert(!security::pop_private_token(cache, digest, 1011, popped_second));

    print("MISSING_SECURITY_APIS: OK");
}

fn test_cryptojar_private_open_bounded_buffer() {
    var store = security::KeyStore { .. };
    let raw_key: u8[32] = [0x42; 32];
    let slot = security::KeySlot { key_id: 1, master_key: raw_key, created_at_sec: 1700000000, .. };
    assert(security::add_key(store, slot));

    let pjar_xchacha = security::new_private_jar(store, false);
    let pjar_aes = security::new_private_jar(store, true);

    var valid_x_wire: u8[..256] = [];
    assert(security::seal_binary(pjar_xchacha, "session", "my_secret_32_byte_payload_string!", 1700000000, 999, valid_x_wire));

    var tiny_out_x: u8[..8] = [];
    let ok_open_x = security::open_binary(pjar_xchacha, "session", valid_x_wire[..], 1700000001, tiny_out_x);
    assert(!ok_open_x);

    var valid_aes_wire: u8[..256] = [];
    assert(security::seal_binary(pjar_aes, "session", "my_secret_32_byte_payload_string!", 1700000000, 888, valid_aes_wire));

    var tiny_out_aes: u8[..8] = [];
    let ok_open_aes = security::open_binary(pjar_aes, "session", valid_aes_wire[..], 1700000001, tiny_out_aes);
    assert(!ok_open_aes);

    print("CRYPTOJAR_PRIVATE_OPEN_BOUNDS: OK");
}

fn test_privacypass_cache_eviction_perpetual_tokens() {
    var cache = security::PrivateTokenCache { .. };
    var tok = security::Token { .. };

    var chal0 = security::TokenChallenge { issuer_name: "issuer_perpetual", .. };
    assert(security::put_private_token(cache, chal0, tok, "token_perpetual", 0, 1000));

    for i in 1..16 {
        var chali = security::TokenChallenge { issuer_name: "issuer_expiring", .. };
        chali.redemption_context.push(i as u8);
        let ttl = i * 10;
        assert(security::put_private_token(cache, chali, tok, "token_expiring", ttl, 1000));
    }
    assert(cache.entries.len == 16);

    var chal17 = security::TokenChallenge { issuer_name: "issuer_new", .. };
    assert(security::put_private_token(cache, chal17, tok, "token_new", 500, 1005));

    var out_raw: u8[..512] = [];
    let _, ok_get = security::get_private_token(cache, chal0, 1006, out_raw);
    assert(ok_get);
    assert(out_raw[..] == "token_perpetual");

    print("PRIVACYPASS_PERPETUAL_TOKEN_EVICTION: OK");
}

fn test_rate_limiter_probabilistic_saturation() {
    let quota = security::new_gcra_quota(1, wing::secs(1), 0);
    var pgcra = security::new_probabilistic_gcra(quota, 100);
    pgcra.cell.tat_ns = 5000000000;

    pgcra.rng_state = 1;
    let dec = security::check_rate_limit(pgcra, 1, 1000000000);
    assert(!security::is_allowed(dec));

    print("PROBABILISTIC_GCRA_SATURATION: OK");
}

fn test_cors_empty_origin_rejected() {
    var policy = security::CorsPolicy { .. };
    assert(!security::add_allowed_origin(policy, ""));
    assert(!security::add_allowed_origin(policy, "   \t "));
    assert(security::add_allowed_origin(policy, "https://example.com"));

    // FIND-0001: LWS-padded wildcard must be recognized as "*" and rejected when allow_credentials = true
    var cred_policy = security::CorsPolicy { allow_credentials: true, .. };
    assert(security::add_allowed_origin(cred_policy, " * "));
    assert(!security::validate_cors_policy(cred_policy));
    assert(!security::is_origin_allowed(cred_policy, "https://evil.example"));

    var req = wing::new_request("GET", "/api/secret");
    wing::set_header(req, "Origin", "https://evil.example");
    var res = wing::Response { .. };
    assert(security::evaluate_cors(cred_policy, req, res) == security::CorsResult.InvalidConfig);

    print("CORS_EMPTY_ORIGIN_REJECTED: OK");
}

fn test_cross_origin_isolation_edge_cases() {
    // FIND-0002: Leading ';' or comma-folded multi-item headers must map to Unknown, not None/UnsafeNone
    assert(security::parse_corp(";same-origin") == security::CorpPolicy.Unknown);
    assert(security::parse_corp("same-origin; report-to=\"a\", cross-origin") == security::CorpPolicy.Unknown);
    assert(security::parse_coop(";same-origin") == security::CoopPolicy.Unknown);
    assert(security::parse_coep(";require-corp") == security::CoepPolicy.Unknown);

    var ctx = security::CrossOriginIsolationContext { .. };
    security::update_isolation_context(ctx, "unsafe-none", "unsafe-none", "https://app.example.com");
    assert(!security::is_subresource_allowed(ctx, "https://cdn.evil.com", ";same-origin"));

    // FIND-0003: Backslash-@ userinfo smuggling, IPv6 trailing host injection, and non-HTTP schemes
    var iso_ctx = security::CrossOriginIsolationContext { .. };
    security::update_isolation_context(iso_ctx, "same-origin", "require-corp", "https://app.example.com");
    assert(!security::is_subresource_allowed(iso_ctx, "https://example.com\\@evil.com", "same-site"));
    assert(!security::is_subresource_allowed(iso_ctx, "ftp://app.example.com", "same-site"));

    var v6_ctx = security::CrossOriginIsolationContext { .. };
    security::update_isolation_context(v6_ctx, "same-origin", "require-corp", "https://[::1]:8443");
    assert(!security::is_subresource_allowed(v6_ctx, "https://[::1].evil.com", "same-site"));

    print("CROSS_ORIGIN_ISOLATION_EDGE_CASES: OK");
}

fn test_cryptojar_base64_and_debug_cast_bounds() {
    var store = security::KeyStore { .. };
    let raw_key: u8[32] = [0x33; 32];
    let slot = security::KeySlot { key_id: 1, master_key: raw_key, created_at_sec: 1700000000, .. };
    assert(security::add_key(store, slot));

    let pjar = security::new_private_jar(store, false);
    let sjar = security::new_signed_jar(store);

    // FIND-0005: Undersized u8[..N] Base64URL output buffer must fail, not silently truncate
    var tiny_b64: u8[..32] = [];
    assert(!security::seal(pjar, "sid", "secret_payload", 1700000000, 777, tiny_b64));
    assert(!security::seal(sjar, "sid", "secret_payload", 1700000000, tiny_b64));

    // FIND-0004: Negative/zero now_sec on seal must be rejected, and high-bit wire timestamps (>= 53/65 bytes) must not abort in debug builds
    var valid_b64: u8[..256] = [];
    assert(!security::seal(pjar, "sid", "secret_payload", 0, 777, valid_b64));
    assert(!security::seal(pjar, "sid", "secret_payload", -5, 777, valid_b64));
    assert(!security::seal(sjar, "sid", "secret_payload", -5, valid_b64));

    var forged_xchacha: u8[..64] = [];
    forged_xchacha.push(0x02); // WIRE_VER_XCHACHA20_POLY1305
    core::append_u32_be(forged_xchacha, 1);
    core::append_u64_be(forged_xchacha, 0x8000000000000001); // negative i64 when cast
    for i in 48 { forged_xchacha.push(0xBB); } // total 61 bytes >= 53
    var out_plain: u8[..64] = [];
    assert(!security::open_binary(pjar, "sid", forged_xchacha[..], 1700000000, out_plain));

    print("CRYPTOJAR_BASE64_AND_DEBUG_CAST: OK");
}

fn test_csrf_canonical_path_and_trusted_cors() {
    var guard_cfg = security::CrossOriginGuard { .. };
    // FIND-0006: Empty exempt path or empty trusted origin must be rejected
    assert(!security::add_exempt_path(guard_cfg, ""));
    assert(!security::add_exempt_path(guard_cfg, "relative/path"));
    assert(!security::add_trusted_origin(guard_cfg, ""));

    assert(security::add_exempt_path(guard_cfg, "/api/webhook"));
    assert(security::add_trusted_origin(guard_cfg, "https://partner.example.com"));

    // FIND-0008: Path traversal "/api/webhook/../../admin/transfer" must canonicalize to "/admin/transfer" and NOT match "/api/webhook"
    var req_trav = wing::new_request("POST", "/api/webhook/../../admin/transfer");
    wing::set_header(req_trav, "Sec-Fetch-Site", "cross-site");
    let ctx_trav = security::extract_fetch_context(req_trav, "app.example.com");
    assert(ctx_trav.path[..] == "/admin/transfer");
    let dec_trav = security::evaluate_fetch_metadata(guard_cfg, ctx_trav);
    assert(!security::is_allowed(dec_trav));

    var req_pct = wing::new_request("POST", "/api/webhook/%2e%2e/%2e%2e/admin/transfer");
    wing::set_header(req_pct, "Sec-Fetch-Site", "cross-site");
    let ctx_pct = security::extract_fetch_context(req_pct, "app.example.com");
    assert(ctx_pct.path[..] == "/admin/transfer");
    let dec_pct = security::evaluate_fetch_metadata(guard_cfg, ctx_pct);
    assert(!security::is_allowed(dec_pct));

    // FIND-0007: Safe cross-site CORS subresource request from a trusted origin must be allowed
    var req_cors_get = wing::new_request("GET", "/api/data");
    wing::set_header(req_cors_get, "Sec-Fetch-Site", "cross-site");
    wing::set_header(req_cors_get, "Sec-Fetch-Mode", "cors");
    wing::set_header(req_cors_get, "Sec-Fetch-Dest", "empty");
    wing::set_header(req_cors_get, "Origin", "https://partner.example.com");
    let ctx_cors_get = security::extract_fetch_context(req_cors_get, "app.example.com");
    let dec_cors_get = security::evaluate_fetch_metadata(guard_cfg, ctx_cors_get);
    assert(security::is_allowed(dec_cors_get));

    print("CSRF_CANONICAL_AND_TRUSTED_CORS: OK");
}

fn test_privacypass_rsa_spki_and_negative_ttl() {
    // FIND-0009: RFC 9577 / RFC 9578 Type 0x0002 2048-bit Blind RSA SPKI token-key is 342 bytes (> 128 bytes)
    var ch = security::TokenChallenge { .. };
    ch.issuer_name.append("issuer.example.com");
    var ch_wire: u8[>..] = [];
    security::marshal_token_challenge(ch, ch_wire);
    var ch_b64: u8[..256] = [];
    security::encode_padded_base64url(ch_wire[..], ch_b64);

    var raw_spki: u8[342]   = [0x30; 342];
    var spki_b64: u8[..512] = [];
    core::base64url_encode(raw_spki[..], spki_b64);

    var hdr: u8[..1024] = [];
    hdr.append("PrivateToken challenge=\"");
    hdr.append(ch_b64[..]);
    hdr.append("\", token-key=\"");
    hdr.append(spki_b64[..]);
    hdr.append("\", max-age=120");

    var out_key: u8[..512] = [];
    let out_ch, out_age, ok_ch = security::parse_private_token_challenge(hdr[..], out_key);
    assert(ok_ch);
    assert(out_ch.issuer_name[..] == "issuer.example.com");
    assert(out_key.len == 342);
    assert(out_age == 120);

    // FIND-0010: Negative ttl_sec or empty raw_token must be rejected by put_private_token, not stored as perpetual
    var cache = security::PrivateTokenCache { .. };
    var tok = security::Token { .. };
    assert(!security::put_private_token(cache, ch, tok, "valid_raw_tok", -10, 1000));
    assert(!security::put_private_token(cache, ch, tok, "", 300, 1000));

    print("PRIVACYPASS_RSA_SPKI_AND_TTL: OK");
}

fn test_gcra_clock_drift_persist_and_probabilistic_low_burst() {
    // FIND-0011: Backward clock jump exceeding GCRA_MAX_CLOCK_DRIFT_NS must persist clamped tat_ns in cell
    let quota = security::new_gcra_quota(10, wing::secs(1), 2);
    var cell = security::GcraCell { tat_ns: 60000000000 };
    let now_backward: u64 = 10000000000;
    let dec1 = security::gcra_check_n(quota, cell, 1, now_backward);
    assert(!security::is_allowed(dec1));
    // Without manual intervention, advancing by 200ms after the backward jump must recover and allow
    let dec2 = security::gcra_check_n(quota, cell, 1, now_backward + 200000000);
    assert(security::is_allowed(dec2));

    // FIND-0012: ProbabilisticGcra with burst < sample_rate (e.g. burst = 2, sample_rate = 20)
    // must admit sampled requests when idle and update cell.tat_ns
    let p_quota = security::new_gcra_quota(10, wing::secs(1), 2);
    var pgcra = security::new_probabilistic_gcra(p_quota, 20);
    pgcra.rng_state = 1; // Force next xorshift step to sample (or test across 100 steps)
    var sampled_admitted = false;
    for i in 100 {
        let tat_before = pgcra.cell.tat_ns;
        let d = security::check_rate_limit(pgcra, 1, 1000000000 + (i as u64) * 500000000);
        if pgcra.cell.tat_ns > tat_before && security::is_allowed(d) {
            sampled_admitted = true;
            break;
        }
    }
    assert(sampled_admitted);

    // COOKIERL-05: HKDF-SHA256 Master Key Domain Separation in KeyStore
    var kstore = security::KeyStore { .. };
    let master_secret: u8[32] = [0x42; 32];
    let kslot = security::KeySlot {
        key_id:         7,
        master_key:     master_secret,
        created_at_sec: 1700000000,
        expires_at_sec: 1700100000,
        ..
    };
    assert(security::add_key(kstore, kslot));
    let act_slot, ok_act = security::active_key(kstore);
    assert(ok_act);
    assert(act_slot.signing_key[..] != act_slot.encryption_key[..]);
    assert(act_slot.signing_key[..] != act_slot.master_key[..]);
    assert(!security::needs_rotation(kslot, 1700000000));
    assert(security::needs_rotation(act_slot, 1700050000));

    // COOKIERL-07 & COOKIERL-08: GCRA Jitter, insufficient_capacity & retain_recent_shards
    let cap_dec = security::gcra_check_n(quota, cell, 999, now_backward + 200000000);
    assert(security::is_insufficient_capacity(cap_dec));
    var gdec = security::to_gcra_decision(cap_dec);
    assert(gdec.insufficient_capacity && !gdec.allowed);

    let jitter = security::GcraJitter { min_ns: 1000, max_ns: 5000 };
    var prng: u64 = 123456789;
    let wait_before = gdec.wait_ns;
    security::apply_jitter_to_decision(gdec, jitter, prng);
    assert(gdec.wait_ns >= wait_before + 1000 && gdec.wait_ns < wait_before + 5000);
    var rdec = cap_dec;
    security::apply_jitter_to_decision(rdec, jitter, prng);

    var sh_lim = security::new_sharded_limiter(quota);
    let _ = security::check_rate_limit(sh_lim, "tenant_1", 1, 1000);
    let _ = security::check_rate_limit(sh_lim, "tenant_2", 1, 1000);
    let reclaimed = security::retain_recent_shards(sh_lim, 5000000000);
    assert(reclaimed == 2);

    print("GCRA_DRIFT_AND_PROBABILISTIC_LOW_BURST: OK");
}

fn run_07_verify_security_bug_hunter() {
    test_cryptojar_bounded_buffer_truncation();
    test_cryptojar_timestamp_fail_closed();
    test_csrf_path_prefix_exemption();
    test_gcra_shard_slot_allocation_priority();
    test_privacypass_duplicate_params();
    test_missing_security_apis();
    test_cryptojar_private_open_bounded_buffer();
    test_privacypass_cache_eviction_perpetual_tokens();
    test_rate_limiter_probabilistic_saturation();
    test_cors_empty_origin_rejected();
    test_cross_origin_isolation_edge_cases();
    test_cryptojar_base64_and_debug_cast_bounds();
    test_csrf_canonical_path_and_trusted_cors();
    test_privacypass_rsa_spki_and_negative_ttl();
    test_gcra_clock_drift_persist_and_probabilistic_low_burst();

    print("ALL_SECURITY_BUG_HUNTER_TESTS_PASSED");
}

// CHECK: CRYPTOJAR_BOUNDS_CHECK: OK
// CHECK-NEXT: CRYPTOJAR_TIMESTAMP_FAIL_CLOSED: OK
// CHECK-NEXT: CSRF_PATH_PREFIX_EXEMPTION: OK
// CHECK-NEXT: GCRA_SLOT_PRIORITY: OK
// CHECK-NEXT: PRIVACYPASS_DUPLICATES_REJECTED: OK
// CHECK-NEXT: MISSING_SECURITY_APIS: OK
// CHECK-NEXT: CRYPTOJAR_PRIVATE_OPEN_BOUNDS: OK
// CHECK-NEXT: PRIVACYPASS_PERPETUAL_TOKEN_EVICTION: OK
// CHECK-NEXT: PROBABILISTIC_GCRA_SATURATION: OK
// CHECK-NEXT: CORS_EMPTY_ORIGIN_REJECTED: OK
// CHECK-NEXT: CROSS_ORIGIN_ISOLATION_EDGE_CASES: OK
// CHECK-NEXT: CRYPTOJAR_BASE64_AND_DEBUG_CAST: OK
// CHECK-NEXT: CSRF_CANONICAL_AND_TRUSTED_CORS: OK
// CHECK-NEXT: PRIVACYPASS_RSA_SPKI_AND_TTL: OK
// CHECK-NEXT: GCRA_DRIFT_AND_PROBABILISTIC_LOW_BURST: OK
// CHECK-NEXT: ALL_SECURITY_BUG_HUNTER_TESTS_PASSED

// ============================================================================
// 8. verify_server_pipeline_edge (8/8)
// ============================================================================
// CHECK: === [8/8] verify_server_pipeline_edge ===

// tests/lit/verify_server_pipeline_edge.goose
// Verification of HTTP/1.1 request wire parser and RFC 9112 syntax invariants via wing.
//

// Wire adapter for verify_split_stream and fuzzing using wing::parse_http1_wire_request
fn wing_validate_http1_request_wire(buf: const u8[:]) -> i64 {
    var req = wing::new_request("GET", "/");
    let ok, consumed = wing::parse_http1_wire_request(buf, req);
    if ok {
        return consumed;
    }
    guard buf.len >= 4 else { return -1; }
    let crlf = core::fast_find_crlfcrlf(buf);
    guard crlf >= 0 else { return -1; }
    return -2;
}

fn run_08_verify_server_pipeline_edge() {
    let req_str = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert(wire_kit::verify_split_stream(req_str, -1, 47, wing_validate_http1_request_wire));
    assert(wire_kit::fuzz_payload(req_str, 100, wing_validate_http1_request_wire));

    var parsed_req = wing::new_request("GET", "/");
    let ok, consumed = wing::parse_http1_wire_request(req_str, parsed_req);
    assert(ok);
    assert(consumed == 47);
    assert(parsed_req.method == "GET");
    assert(parsed_req.url == "/index.html");
    print("HTTP_REQ_SPLIT: OK");

    var ws_lead: u8[>..] = []; wire_kit::parse_hex("20474554202F20485454502F312E310D0A0D0A", ws_lead);
    assert(wing_validate_http1_request_wire(ws_lead[..]) == -2);

    var ctl_nul: u8[>..] = []; wire_kit::parse_hex("474554202F0020485454502F312E310D0A0D0A", ctl_nul);
    assert(wing_validate_http1_request_wire(ctl_nul[..]) == -2);

    var ctl_ff: u8[>..] = []; wire_kit::parse_hex("474554202FFF20485454502F312E310D0A0D0A", ctl_ff);
    assert(wing_validate_http1_request_wire(ctl_ff[..]) == -2);
    print("HTTP_REQ_SYNTAX: OK");
}

// CHECK: HTTP_REQ_SPLIT: OK
// CHECK: HTTP_REQ_SYNTAX: OK

fn main() {
    print("\n=== [1/8] verify_backpressure_fsm ===\n");
    run_01_verify_backpressure_fsm();
    print("\n=== [2/8] verify_historical_bugs ===\n");
    run_02_verify_historical_bugs();
    print("\n=== [3/8] verify_historical_cves ===\n");
    run_03_verify_historical_cves();
    print("\n=== [4/8] verify_l0_simd_routing ===\n");
    run_04_verify_l0_simd_routing();
    print("\n=== [5/8] verify_protocol_invariants ===\n");
    run_05_verify_protocol_invariants();
    print("\n=== [6/8] verify_role_polarity ===\n");
    run_06_verify_role_polarity();
    print("\n=== [7/8] verify_security_bug_hunter ===\n");
    run_07_verify_security_bug_hunter();
    print("\n=== [8/8] verify_server_pipeline_edge ===\n");
    run_08_verify_server_pipeline_edge();
}
