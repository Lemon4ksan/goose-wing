// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_core_and_simd
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// ============================================================================
// 1. verify_fast_string_primitives (1/10)
// ============================================================================
// CHECK: === [1/10] verify_fast_string_primitives ===

// tests/lit/verify_fast_string_primitives.goose
// Verification of zero-allocation string primitives: SIMD packed-pair search,
// byteset membership scans, 64-bit SWAR case conversion, and RFC 3629 UTF-8 decoding.
//

fn run_01_verify_fast_string_primitives() {
    // 1. Equal short verification
    assert(core::equal_short("Content-Type", "Content-Type"));
    assert(!core::equal_short("Content-Type", "Content-Length"));
    assert(core::starts_with("Bearer token123", "Bearer "));
    assert(core::ends_with("index.html", ".html"));

    // 2. Substring search (SIMD packed-pair + Two-Way)
    let text = "GET /api/v1/orders HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert(core::find(text, "orders") == 12);
    assert(core::find(text, "HTTP/1.1") == 19);
    assert(core::find(text, "missing") == -1);
    assert(core::rfind(text, "/") == 23);
    assert(core::contains(text, "example.com"));

    // 3. ByteSet search and trim
    let raw = " \t\r\n  key = value \t\r\n ";
    let cutset = " \t\r\n";
    let trimmed = core::trim_bytes(raw, cutset);
    assert(trimmed == "key = value");
    assert(core::find_byteset("foo::bar", ":/") == 3);
    assert(core::find_not_byteset("   abc", " ") == 3);
    assert(core::rfind_byteset("abc,def;ghi", ",;") == 7);
    assert(core::rfind_not_byteset("name \t ", " \t") == 3);

    // 4. In-place SWAR case conversion
    var buf: u8[32] = [0; 32];
    let sample = "HTTP/1.1 200 OK";
    for i in sample.len { buf[i] = sample[i]; }
    core::make_ascii_lowercase(buf[..sample.len]);
    assert(buf[..sample.len] == "http/1.1 200 ok");
    core::make_ascii_uppercase(buf[..sample.len]);
    assert(buf[..sample.len] == "HTTP/1.1 200 OK");

    // 5. UTF-8 scalar decoding (maximal subpart replacement)
    let cp1, sz1, ok1 = core::decode_utf8("café");
    assert(cp1 == 99 && sz1 == 1 && ok1);

    let cp2, sz2, ok2 = core::decode_utf8("é");
    assert(cp2 == 0xE9 && sz2 == 2 && ok2);

    let cp_last, sz_last, ok_last = core::decode_last_utf8("!é");
    assert(cp_last == 0xE9 && sz_last == 2 && ok_last);

    let cp_lossy, sz_lossy = core::decode_utf8_lossy("\xE2\x82!");
    assert(cp_lossy == 0xFFFD && sz_lossy == 2);

    let cp_llossy, sz_llossy = core::decode_last_utf8_lossy("!\xE2\x82");
    assert(cp_llossy == 0xFFFD && sz_llossy == 2);

    let cp_bad, sz_bad, ok_bad = core::decode_utf8("\xFFabc");
    assert(cp_bad == 0xFFFD && sz_bad == 1 && !ok_bad);

    var count = 0;
    core::char_indices("aé\xFF") { start, end, cp =>
        count++;
    };
    assert(count == 3);

    print("FAST_STRING_PRIMITIVES: PASS");
}

// CHECK: FAST_STRING_PRIMITIVES: PASS

// ============================================================================
// 2. verify_simd_scanners (2/10)
// ============================================================================
// CHECK: === [2/10] verify_simd_scanners ===

// tests/lit/verify_simd_scanners.goose
// Verification of SWAR 64-bit WebSocket masking, fast CRLFCRLF scanning, and bitmask scanners.
//

// Scans first 16 bytes of buffer for delimiter byte and produces a 16-bit bitmask.
fn scan_byte_bitmask(buf: const u8[:], target: u8) -> i32 {
    let limit = if buf.len < 16 { buf.len } else { 16 };
    var mask: i32 = 0;
    for i in limit {
        if buf[i] == target {
            mask |= (1 << (i as u32));
        }
    }
    return mask;
}

fn run_02_verify_simd_scanners() {
    let http_req = "GET /api/v2/orders HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mask = scan_byte_bitmask(http_req, '/');
    // In "GET /api/v2/orde", '/' is at index 4 (16), index 8 (256), and index 11 (2048) -> 2320
    assert(mask == 2320);
    print("SIMD_SLASH_MASK: ", mask);

    // Verify fast CRLFCRLF scanner
    let crlf_off = core::fast_find_crlfcrlf(http_req);
    assert(crlf_off == 46);
    print("CRLFCRLF_OFFSET: ", crlf_off);

    // Verify 64-bit SWAR WebSocket in-place unmasker
    var payload: u8[>..] = [];
    payload.append("Hello Goose Wing");
    let key: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];

    realtime::apply_mask_in_place(payload[..], key);
    // Double mask restores original plaintext
    realtime::apply_mask_in_place(payload[..], key);

    assert(payload[0] == 72); // 'H'
    assert(payload[1] == 101); // 'e'
    assert(payload[2] == 108); // 'l'
    assert(payload[3] == 108); // 'l'
    assert(payload[4] == 111); // 'o'
    print("RESTORED: ", payload[0], " ", payload[1], " ", payload[2], " ", payload[3], " ", payload[4]);

    // Verify fenced wire slice padding
    var fence_buf: u8[16] = [0; 16];
    assert(!core::fence_wire_slice(fence_buf[..], 15));
    assert(core::fence_wire_slice(fence_buf[..], 10));
    assert(fence_buf[10] == 13);
    assert(fence_buf[11] == 97);
    print("FENCE_PADDED: OK");
}

// CHECK: SIMD_SLASH_MASK: 2320
// CHECK: CRLFCRLF_OFFSET: 46
// CHECK: RESTORED: 72 101 108 108 111
// CHECK: FENCE_PADDED: OK

// ============================================================================
// 3. verify_swar_headers (3/10)
// ============================================================================
// CHECK: === [3/10] verify_swar_headers ===

// tests/lit/verify_swar_headers.goose
// Verification of single-pass SWAR header delimiter and character scanner.
//

fn run_03_verify_swar_headers() {
    // 1. Valid header name scanning
    let valid_raw = "Content-Length: 42\r\n";
    let name_len, ok_name = http::scan_header_field_name_swar(valid_raw);
    assert(ok_name);
    assert(name_len == 14);
    assert(valid_raw[..name_len] == "Content-Length");

    // 2. Valid header value scanning
    let val_slice = valid_raw[(name_len + 1)..]; // Skip ':'
    let val_len, crlf_len, ok_val = http::scan_header_field_value_swar(val_slice);
    assert(ok_val);
    assert(crlf_len == 2);
    assert(core::trim_lws(val_slice[..val_len]) == "42");

    // 3. Header name with space before colon (RFC 9112 Section 5.1 violation)
    let bad_space_name = "Host : example.com\r\n";
    let _, ok_bad_name = http::scan_header_field_name_swar(bad_space_name);
    assert(!ok_bad_name);

    // 4. Header value with embedded NUL (rejected)
    let bad_val_raw = "bad\x00val\r\n";
    let _, _, ok_bad_val = http::scan_header_field_value_swar(bad_val_raw);
    assert(!ok_bad_val);

    // 5. Header value with tab (allowed per RFC 9110)
    let tab_val_raw = "text/plain;\tcharset=utf-8\r\n";
    let tab_len, tab_crlf, ok_tab = http::scan_header_field_value_swar(tab_val_raw);
    assert(ok_tab);
    assert(tab_crlf == 2);
    assert(tab_len == 25);

    print("SWAR_HEADERS: OK");
}

// CHECK: SWAR_HEADERS: OK

// ============================================================================
// 4. verify_slot_stack (4/10)
// ============================================================================
// CHECK: === [4/10] verify_slot_stack ===

// tests/lit/verify_slot_stack.goose
// Verification of O(1) FreeSlotStack for reactor connection slots.
//

fn run_04_verify_slot_stack() {
    var stack = net::FreeSlotStack { .. };
    net::init_free_slots(stack, 4);

    // Initial pop order should be deterministic 0, 1, 2, 3
    let s0 = net::pop_free_slot(stack);
    let s1 = net::pop_free_slot(stack);
    let s2 = net::pop_free_slot(stack);
    let s3 = net::pop_free_slot(stack);
    let s4 = net::pop_free_slot(stack);

    assert(s0 == 0);
    assert(s1 == 1);
    assert(s2 == 2);
    assert(s3 == 3);
    assert(s4 == -1); // Empty stack returns -1

    // Push slot 2 back, pop returns 2
    assert(net::push_free_slot(stack, 2));
    assert(net::pop_free_slot(stack) == 2);
    assert(net::pop_free_slot(stack) == -1);

    // Out of bounds rejection
    assert(!net::push_free_slot(stack, -1));
    assert(!net::push_free_slot(stack, 2048));

    print("FREE_SLOT_STACK: OK");
}

// CHECK: FREE_SLOT_STACK: OK

// ============================================================================
// 5. verify_zero_cost_oop (5/10)
// ============================================================================
// CHECK: === [5/10] verify_zero_cost_oop ===

// tests/lit/verify_zero_cost_oop.goose
// Verification of Zero-Cost OOP over Vulkan-style bricks:
// Closed transport polymorphism, Pool/Client integration, HeaderSpan zero-copy,
// and Push-Sink ChunkFsm streaming.
//

fn test_transport_polymorphism() {
    print("=== Transport Polymorphism ===");
    var t_disc = net::Transport.Disconnected;
    print(if t_disc.is_connected() { "disc_connected" } else { "disc_disconnected" });
    // CHECK: disc_disconnected

    var t_mock: net::Transport = net::Transport.Mock { route_idx: 1, cursor: 0 };
    print(if t_mock.is_connected() { "mock_connected" } else { "mock_disconnected" });
    // CHECK: mock_connected

    let sent = t_mock.send("hello");
    print(if sent == 5 { "mock_sent_5" } else { "mock_sent_err" });
    // CHECK: mock_sent_5

    t_mock.close();
    print(if t_mock.is_connected() { "closed_still_connected" } else { "closed_ok" });
    // CHECK: closed_ok
}

fn test_pool_and_connection() {
    print("=== Pool and Connection ===");
    var pool = net::new_stream_pool();
    let key = net::new_pool_key(
        net::PoolScheme.Http,
        "api.example.com",
        80,
        net::new_direct_proxy_chain(),
        net::new_network_anonymization_key("api.example.com"),
        net::TlsAndDnsPolicy { .. },
    );

    let t = net::Transport.Mock { route_idx: 42, cursor: 100 };
    let cid = net::register_connection(
        pool,
        key,
        net::NegotiatedProtocol.Http11,
        t,
        "127.0.0.1",
        1,
        1000000,
    );
    print(if cid > 0 { "registered_ok" } else { "register_fail" });
    // CHECK: registered_ok

    let idx = pool.find_connection_index(cid);
    print(if idx >= 0 { "found_index_ok" } else { "found_index_fail" });
    // CHECK: found_index_ok

    if idx >= 0 {
        print(if pool.conns[idx].transport.is_connected() { "conn_transport_live" } else { "conn_transport_dead" });
        // CHECK: conn_transport_live
    }

    let closed = pool.close_pooled_connection(cid);
    print(if closed { "close_conn_ok" } else { "close_conn_fail" });
    // CHECK: close_conn_ok
}

fn test_span_headers_and_parsing() {
    print("=== Span Headers and Parsing ===");
    let raw_resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: wing-vulkan\r\n\r\n";
    var resp = http::Response { .. };

    let ok_status = wing::parse_h1_status_line("HTTP/1.1 200 OK", resp);
    print(if ok_status && resp.status_code == 200 { "status_200_ok" } else { "status_fail" });
    // CHECK: status_200_ok

    let hdr_block: const u8[:] = "Content-Type: application/json\r\nServer: wing-vulkan\r\n";
    let ok_hdrs = wing::parse_h1_header_block(hdr_block, resp);
    print(if ok_hdrs && resp.headers.entries.len == 2 { "spans_count_2" } else { "spans_fail" });
    // CHECK: spans_count_2

    let ct = resp.header("Content-Type");
    print(ct);
    // CHECK: application/json

    let srv = resp.header("Server");
    print(srv);
    // CHECK: wing-vulkan
}

fn test_push_sink_chunked_streaming() {
    print("=== Push-Sink Chunked Streaming ===");
    let chunked_wire: const u8[:] = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var dec = http_internal::new_chunk_fsm_decoder();
    var sink = http::ArenaSink { max_bytes: 65536 };
    var out_body: u8[>..] = [];

    let st, consumed = http::pump_chunk_fsm(dec, chunked_wire, sink, out_body);
    print(if st == http_internal::ChunkFsmStatus.Complete { "chunk_complete" } else { "chunk_incomplete" });
    // CHECK: chunk_complete

    print(out_body[..]);
    // CHECK: Wikipedia
}

fn test_soa_slot_encapsulation() {
    print("=== SoAConnTable Zero-Cost UFCS Encapsulation ===");
    var table = server::SoAConnTable { .. };
    var pipeline = server::ServerPipelineConfig { .. };

    let slot = table.soa_table_alloc(42, 10);
    print(if slot == 0 { "soa_alloc_0" } else { "soa_alloc_fail" });
    // CHECK: soa_alloc_0

    let tr_tcp = table.slot_transport(slot);
    print(if tr_tcp.is_connected() { "slot_tr_connected" } else { "slot_tr_disc" });
    // CHECK: slot_tr_connected

    let h2_idx = table.ensure_h2_session(slot, pipeline, "wing-h2", 1000);
    print(if h2_idx >= 0 && table.is_h2[slot] { "h2_session_bound" } else { "h2_session_fail" });
    // CHECK: h2_session_bound

    table.release_h2_session(slot, pipeline);
    print(if !table.is_h2[slot] && table.h2_slot_map[slot] == -1 { "h2_session_released" } else { "h2_release_fail" });
    // CHECK: h2_session_released

    table.soa_table_free(slot);
    let tr_disc = table.slot_transport(slot);
    print(if !tr_disc.is_connected() { "slot_freed_disc" } else { "slot_still_conn" });
    // CHECK: slot_freed_disc
}

fn run_05_verify_zero_cost_oop() {
    test_transport_polymorphism();
    test_pool_and_connection();
    test_span_headers_and_parsing();
    test_push_sink_chunked_streaming();
    test_soa_slot_encapsulation();
}

// ============================================================================
// 6. verify_overflow_fallback (6/10)
// ============================================================================
// CHECK: === [6/10] verify_overflow_fallback ===

// tests/lit/verify_overflow_fallback.goose
// Verification of Zero-Allocation Stack Fast Path & Safe Overflow Fallback via Root Struct Arena.
//

fn test_stack_fast_path() {
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };

    let raw: const u8[:] = "Host: api.example.com\r\nUser-Agent: wing/1.0\r\nAccept: */*\r\n\r\n";
    let err = http::parse_headers_with_overflow(raw, map, arena);

    assert(http::is_ok(err));
    assert(map.raw_buf.len > 0);
    assert(arena.spill_raw.len == 0); // Fast path: 0 B in spill arena
    assert(arena.spill_entries.len == 0);

    assert(http::has_header_spill(map, arena, "Host"));
    let host = http::get_header_spill(map, arena, "Host");
    assert(host == "api.example.com");

    assert(http::has_header_spill(map, arena, "User-Agent"));
    let ua = http::get_header_spill(map, arena, "User-Agent");
    assert(ua == "wing/1.0");

    assert(!http::has_header_spill(map, arena, "Non-Existent"));

    print("STACK_FAST_PATH: OK");
}

fn test_oversized_header_block() {
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };

    // Build ~10 KB headers block
    var huge_raw: u8[>..] = [];
    huge_raw.append("Host: api.example.com\r\n");
    for i in 80 {
        huge_raw.append("X-Custom-Data-Padding-");
        // Convert i to 2-digit number
        huge_raw.push('0' + ((i / 10) as u8));
        huge_raw.push('0' + ((i % 10) as u8));
        huge_raw.append(": 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_raw.append("X-Final-Marker: verified_payload\r\n\r\n");

    assert(huge_raw.len > 9000);

    // Standard parse_headers must fail with CapacityExceeded (> 8192 bytes)
    let std_err = http::parse_headers(huge_raw[..], map);
    assert(std_err == http::HeaderParseError.CapacityExceeded);

    // parse_headers_with_overflow must succeed using arena
    let of_err = http::parse_headers_with_overflow(huge_raw[..], map, arena);
    assert(http::is_ok(of_err));
    assert(arena.spill_raw.len > 9000);

    let host = http::get_header_spill(map, arena, "Host");
    assert(host == "api.example.com");

    let marker = http::get_header_spill(map, arena, "X-Final-Marker");
    assert(marker == "verified_payload");

    let pad42 = http::get_header_spill(map, arena, "X-Custom-Data-Padding-42");
    assert(pad42.len == 100);

    print("OVERSIZED_HEADER_BLOCK: OK");
}

fn test_high_header_count_overflow() {
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };

    // Build 150 short headers (exceeds 128 entries limit)
    var many_headers: u8[>..] = [];
    many_headers.append("Host: example.org\r\n");
    for i in 148 {
        many_headers.append("H-");
        many_headers.push('0' + (((i / 100) % 10) as u8));
        many_headers.push('0' + (((i / 10) % 10) as u8));
        many_headers.push('0' + ((i % 10) as u8));
        many_headers.append(": v\r\n");
    }
    many_headers.append("X-Overflow-Tail: tail_value\r\n\r\n");

    let std_err = http::parse_headers(many_headers[..], map);
    assert(std_err == http::HeaderParseError.CapacityExceeded);

    let of_err = http::parse_headers_with_overflow(many_headers[..], map, arena);
    assert(http::is_ok(of_err));

    assert(map.entries.len == 128);       // 128 entries stored in stack map
    assert(arena.spill_entries.len > 20); // Overflow entries stored in arena

    let host = http::get_header_spill(map, arena, "Host");
    assert(host == "example.org");

    let tail_val = http::get_header_spill(map, arena, "X-Overflow-Tail");
    assert(tail_val == "tail_value");

    print("HIGH_HEADER_COUNT_OVERFLOW: OK");
}

fn test_oversized_url_overflow() {
    var arena = http::OverflowArena { .. };

    var huge_url: u8[>..] = [];
    huge_url.append("https://auth.example.com/oauth/authorize?response_type=code&client_id=123456&state=active&huge_jwt=");
    for _ in 3000 {
        huge_url.push('x');
    }

    assert(huge_url.len > 3000);

    // Standard parse_url fails with InputTooLong (> 2048 bytes)
    let std_url, std_url_err = core::parse_url(huge_url[..]);
    assert(std_url_err == core::UrlParseError.InputTooLong);

    // parse_url_with_overflow succeeds without allocation using arena
    let view, of_url_err = http::parse_url_with_overflow(huge_url[..], arena);
    assert(of_url_err == core::UrlParseError.None);
    assert(view.valid);
    assert(view.host == "auth.example.com");
    assert(view.pathname == "/oauth/authorize");
    assert(view.raw.len > 3000);

    print("OVERSIZED_URL_OVERFLOW: OK");
}

fn test_oversized_response_headers_overflow() {
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };

    var huge_resp: u8[>..] = [];
    huge_resp.append("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n");
    for i in 80 {
        huge_resp.append("X-Large-Resp-Header-");
        huge_resp.push('0' + ((i / 10) as u8));
        huge_resp.push('0' + ((i % 10) as u8));
        huge_resp.append(": 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_resp.append("X-Status-Check: verified\r\n\r\n");

    let std_err = http::parse_response_headers(huge_resp[..], map);
    assert(std_err == http::HeaderParseError.CapacityExceeded);

    let of_err = http::parse_response_headers_with_overflow(huge_resp[..], map, arena);
    assert(http::is_ok(of_err));
    assert(map.status_code == 200);
    assert(map.http_major == 1);
    assert(map.http_minor == 1);

    let check = http::get_header_spill(map, arena, "X-Status-Check");
    assert(check == "verified");

    print("OVERSIZED_RESPONSE_HEADERS_OVERFLOW: OK");
}

fn test_oversized_request_headers_overflow() {
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };

    var huge_req: u8[>..] = [];
    huge_req.append("POST /api/v1/submit HTTP/1.1\r\nHost: api.example.com\r\n");
    for i in 80 {
        huge_req.append("X-Large-Req-Header-");
        huge_req.push('0' + ((i / 10) as u8));
        huge_req.push('0' + ((i % 10) as u8));
        huge_req.append(": 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_req.append("X-Req-Check: verified_req\r\n\r\n");

    let std_err = http::parse_request_headers(huge_req[..], map);
    assert(std_err == http::HeaderParseError.CapacityExceeded);

    let of_err = http::parse_request_headers_with_overflow(huge_req[..], map, arena);
    assert(http::is_ok(of_err));

    let host = http::get_header_spill(map, arena, "Host");
    assert(host == "api.example.com");

    let check = http::get_header_spill(map, arena, "X-Req-Check");
    assert(check == "verified_req");

    print("OVERSIZED_REQUEST_HEADERS_OVERFLOW: OK");
}

fn test_spill_accessors_and_serialization() {
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };

    var raw_input: u8[>..] = [];
    raw_input.append("Host: service.local\r\n");
    for i in 140 {
        raw_input.append("X-Tag: tag-");
        raw_input.push('0' + (((i / 100) % 10) as u8));
        raw_input.push('0' + (((i / 10) % 10) as u8));
        raw_input.push('0' + ((i % 10) as u8));
        raw_input.append("\r\n");
    }
    raw_input.append("\r\n");

    let err = http::parse_headers_with_overflow(raw_input[..], map, arena);
    assert(http::is_ok(err));

    var values: u8[..256][>..] = [];
    http::get_all_values_spill(map, arena, "X-Tag", values);
    assert(values.len == 140);
    assert(values[0] == "tag-000");
    assert(values[139] == "tag-139");

    var raw_out: u8[>..] = [];
    http::raw_headers_spill(map, arena, raw_out);
    assert(raw_out.len > 0);

    print("SPILL_ACCESSORS_AND_SERIALIZATION: OK");
}

fn run_06_verify_overflow_fallback() {
    test_stack_fast_path();
    test_oversized_header_block();
    test_high_header_count_overflow();
    test_oversized_url_overflow();
    test_oversized_response_headers_overflow();
    test_oversized_request_headers_overflow();
    test_spill_accessors_and_serialization();
    print("ALL_OVERFLOW_FALLBACK_TESTS_PASS");
}

// CHECK: STACK_FAST_PATH: OK
// CHECK-NEXT: OVERSIZED_HEADER_BLOCK: OK
// CHECK-NEXT: HIGH_HEADER_COUNT_OVERFLOW: OK
// CHECK-NEXT: OVERSIZED_URL_OVERFLOW: OK
// CHECK-NEXT: OVERSIZED_RESPONSE_HEADERS_OVERFLOW: OK
// CHECK-NEXT: OVERSIZED_REQUEST_HEADERS_OVERFLOW: OK
// CHECK-NEXT: SPILL_ACCESSORS_AND_SERIALIZATION: OK
// CHECK-NEXT: ALL_OVERFLOW_FALLBACK_TESTS_PASS

// ============================================================================
// 7. verify_capacity_lifecycle (7/10)
// ============================================================================
// CHECK: === [7/10] verify_capacity_lifecycle ===

// tests/lit/verify_capacity_lifecycle.goose
// Verifies 2x capacity lifecycle and slot reclamation invariants across HTTP/2, HTTP/3, and QUIC.
// Ensures bounded arrays [..N] handle at least 2*N sequential streams without slot exhaustion.
//

fn encode_client_h2_request<B>(
    dt:        http2::DynamicTable&,
    stream_id: u32,
    method:    const u8[:],
    path:      const u8[:],
    scheme:    const u8[:],
    authority: const u8[:],
    out:       B&,
) {
    var hpack_block: u8[..512] = [];
    http2::encode_hpack_field(dt, hpack_block, ":method", method, http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(dt, hpack_block, ":path", path, http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(dt, hpack_block, ":scheme", scheme, http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(dt, hpack_block, ":authority", authority, http2::HpackIndexing.Incremental, false);

    let hdr = http2::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(hdr, out);
    out.append(hpack_block[..]);
}

// 1. HTTP/2 2x Capacity Lifecycle:
// Capacity is 16 streams. Sequentially open and close 32 request streams.
fn test_h2_capacity_lifecycle() {
    var client_hpack = http2::DynamicTable { .. };
    var sess = server_internal::new_h2_server_session("localhost");
    var pipeline = server::ServerPipelineConfig { .. };
    var timer = server_internal::ConnectionTimer { .. };

    // Handshake
    var init_wire: u8[..64] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let set_hdr = http2::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    http2::encode_frame_header_to(set_hdr, init_wire);
    var server_out: u8[..4096] = [];
    let _, ok_init = server_internal::handle_h2_server_ingress(
        sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, server_out,
    );
    assert(ok_init);

    // Sequentially process 32 streams (capacity is 16)
    for i in 32 {
        let stream_id = ((i * 2) + 1) as u32;
        var req_wire: u8[..512] = [];
        encode_client_h2_request(
            client_hpack, stream_id, "GET", "/ping", "https", "example.com", req_wire,
        );

        server_out.clear();
        let consumed, ok = server_internal::handle_h2_server_ingress(
            sess, pipeline, timer, "127.0.0.1", req_wire[..], 1000 + (i as u64), server_out,
        );
        assert(ok);
        assert(consumed == req_wire.len);
        assert(sess.streams.len <= 16);
    }

    print("H2_CAPACITY_LIFECYCLE: OK");
}

// 2. HTTP/3 2x Capacity Lifecycle:
// Capacity is 32 streams. Sequentially process 64 request streams.
fn test_h3_capacity_lifecycle() {
    let settings = fingerprint::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };
    var server_conn = http3::new_server_connection(settings);

    // Ingest Control Stream with SETTINGS
    var ctrl_wire: u8[..128] = [];
    quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl_wire);
    http3::encode_settings_frame(ctrl_wire, settings);
    let err_ctrl = server_conn.handle_stream_data(3, false, ctrl_wire[..], false);
    assert(err_ctrl == rfc::H3_ERR_NO_ERROR);

    // QPACK static block: :method GET (0xD1), :scheme https (0xD7), :path / (0xC1), :authority example.com (0x50 0x0B "example.com")
    let qpack_sec: u8[18] = [
        0x00, 0x00, 0xD1, 0xD7, 0xC1, 0x50, 0x0B,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
    ];
    var req_wire: u8[..64] = [];
    assert(http3::encode_frame_header(req_wire, rfc::H3_FRAME_HEADERS, qpack_sec.len as u64));
    req_wire.append(qpack_sec[..]);

    let body = "PING";
    var data_wire: u8[..64] = [];
    assert(http3::encode_frame_header(data_wire, rfc::H3_FRAME_DATA, body.len as u64));
    data_wire.append(body);

    for i in 64 {
        let stream_id = (i * 4) as u64; // Client bidi request streams: 0, 4, 8, ...
        let err_h = server_conn.handle_stream_data(stream_id, true, req_wire[..], false);
        assert(err_h == rfc::H3_ERR_NO_ERROR);

        let err_d = server_conn.handle_stream_data(stream_id, true, data_wire[..], true);
        assert(err_d == rfc::H3_ERR_NO_ERROR);

        let s_idx, found = http3::find_stream_idx(server_conn, stream_id);
        assert(found);
        // Mark stream closed on server side to reclaim slot
        server_conn.streams[s_idx].state = http3::StreamState.Closed;

        assert(server_conn.streams.len <= 32);
    }

    print("H3_CAPACITY_LIFECYCLE: OK");
}

// 3. QUIC Stream Table 2x Capacity Lifecycle:
// Capacity is 128 streams. Sequentially process 256 streams.
fn test_quic_capacity_lifecycle() {
    var tbl = quic::new_stream_table(quic::QuicRole.Server);
    tbl.max_streams_bidi = 1000;

    for i in 256 {
        let stream_id = (i * 4) as u64; // Peer-initiated Client Bidi streams: 0, 4, 8...
        let idx, ok = quic::get_or_open_stream(tbl, stream_id, 65536);
        assert(ok);
        assert(idx >= 0);

        // Transition stream to terminal
        let _, ok_send = quic::on_send_data(tbl.streams[idx as i64], 0, 10, true);
        assert(ok_send);
        assert(quic::on_send_ack(tbl.streams[idx as i64], true));

        tbl.streams[idx as i64].recv_state = quic::QuicRecvState.DataRead;
        assert(quic::is_terminal(tbl.streams[idx as i64], tbl.role));

        assert(tbl.streams.len <= 128);
    }

    print("QUIC_CAPACITY_LIFECYCLE: OK");
}

fn run_07_verify_capacity_lifecycle() {
    test_h2_capacity_lifecycle();
    test_h3_capacity_lifecycle();
    test_quic_capacity_lifecycle();
}

// CHECK: H2_CAPACITY_LIFECYCLE: OK
// CHECK-NEXT: H3_CAPACITY_LIFECYCLE: OK
// CHECK-NEXT: QUIC_CAPACITY_LIFECYCLE: OK

// ============================================================================
// 8. verify_rio_memory_escape (8/10)
// ============================================================================
// CHECK: === [8/10] verify_rio_memory_escape ===

// Verification of RIO memory partition bounds enforcement (BUG-05).

fn run_08_verify_rio_memory_escape() {
    print("=== VERIFY_RIO_MEMORY_ESCAPE ===\n");

    // Create a parent RIO buffer descriptor representing an offset partition (4096..5120)
    let parent = net_internal::RioBufferDescriptor {
        buffer_id:     101,
        offset:        4096,
        length:        1024,
        is_registered: true,
        page_locked:   true,
    };

    // Case 1: Valid sub-slice within the partition
    let valid_sub = net_internal::rio_sub_buffer(parent, 4096, 512);
    assert(valid_sub.is_registered);
    assert(valid_sub.offset == 4096);
    assert(valid_sub.length == 512);
    print("CASE_1_VALID_SUB: OK\n");
    // CHECK: CASE_1_VALID_SUB: OK

    // Case 2: Attempt memory escape: off = 0 (before parent.offset = 4096)
    // Previously, off + len = 1024 <= 5120 was true, erroneously permitting access to bytes 0..1024!
    let escape_sub = net_internal::rio_sub_buffer(parent, 0, 1024);
    assert(!escape_sub.is_registered);
    assert(escape_sub.length == 0);
    print("CASE_2_ESCAPE_BEFORE_OFFSET_REJECTED: OK\n");
    // CHECK: CASE_2_ESCAPE_BEFORE_OFFSET_REJECTED: OK

    // Case 3: Attempt memory escape: off = 5000, len = 200 (past parent.offset + length = 5120)
    let escape_past = net_internal::rio_sub_buffer(parent, 5000, 200);
    assert(!escape_past.is_registered);
    assert(escape_past.length == 0);
    print("CASE_3_ESCAPE_PAST_END_REJECTED: OK\n");
    // CHECK: CASE_3_ESCAPE_PAST_END_REJECTED: OK

    print("ALL_RIO_BOUNDS_VERIFIED: OK\n");
    // CHECK: ALL_RIO_BOUNDS_VERIFIED: OK
}

// ============================================================================
// 9. verify_uring_leak (9/10)
// ============================================================================
// CHECK: === [9/10] verify_uring_leak ===

// Verification of io_uring completion balance under saturated CQE batch (BUG-06).

fn run_09_verify_uring_leak() {
    print("=== VERIFY_URING_LEAK ===\n");

    var state = net_internal::RingQueueState {
        ring_size:         32,
        active_pending:    0,
        submissions_total: 0,
        completions_total: 0,
    };

    var sqes: net_internal::UringSqe[33] = [net_internal::UringSqe { .. }; 33];
    for i in 33 {
        sqes[i].opcode = net_internal::URING_OP_SEND;
        sqes[i].fd = 10;
        sqes[i].len = 64;
        sqes[i].user_data = (i + 1) as u64;
    }

    var cqes: net_internal::UringCqe[..32] = [];

    // Batch 1: Submit 33 SQEs with 32 CQE slots available
    let submitted = net_internal::uring_submit_batch(state, sqes[..], cqes);
    assert(submitted == 32);
    assert(cqes.len == 32);
    // After reaping 32 completions, active_pending MUST be 0, not 1!
    assert(state.active_pending == 0);
    print("BATCH_1_SUBMITTED: ", submitted, " PENDING: ", state.active_pending, "\n");
    // CHECK: BATCH_1_SUBMITTED: 32 PENDING: 0

    // Batch 2: Submit another batch - must NOT be rejected due to leaked active_pending!
    cqes.clear();
    let submitted2 = net_internal::uring_submit_batch(state, sqes[..], cqes);
    assert(submitted2 == 32);
    assert(state.active_pending == 0);
    print("BATCH_2_NO_DEADLOCK: OK\n");
    // CHECK: BATCH_2_NO_DEADLOCK: OK

    print("ALL_URING_INVARIANTS_VERIFIED: OK\n");
    // CHECK: ALL_URING_INVARIANTS_VERIFIED: OK
}

// ============================================================================
// 10. verify_bitmask_pipeline (10/10)
// ============================================================================
// CHECK: === [10/10] verify_bitmask_pipeline ===

// tests/lit/verify_bitmask_pipeline.goose
// Verification of Bitmask Pipeline Dispatch (Pre-Baked Route PSOs & Macro-Fused Bit-Test).
//

fn test_pso_route_matching() {
    var router = server::new_radix_router();

    // 1. Zero-cost fast-path bypass probe (pso_mask = 0)
    assert(server::add_route_pso(router, "GET", "/healthz", 1001, 0));

    // 2. Default protected endpoint (default pso_mask)
    assert(server::add_route(router, "GET", "/api/v1/users/{id}", 1002));

    // 3. Custom security + egress isolation endpoint
    let custom_pso: u64 = server::STAGE_INGRESS_CORS_PREFLIGHT | server::STAGE_EGRESS_SECURITY_HEADERS;
    assert(server::add_route_pso(router, "POST", "/api/v1/secure", 1003, custom_pso));

    // Match /healthz
    var params1 = http::ZeroAllocParams { .. };
    var canon1: u8[..512] = [];
    let match1 = server::match_route(router, "GET", "/healthz", params1, canon1);
    match match1 {
        Found f => {
            assert(f.handler_id == 1001);
            assert(f.pso_mask == 0);
        },
        _ => assert(false),
    };

    // Match /api/v1/users/42
    var params2 = http::ZeroAllocParams { .. };
    var canon2: u8[..512] = [];
    let match2 = server::match_route(router, "GET", "/api/v1/users/42", params2, canon2);
    match match2 {
        Found f => {
            assert(f.handler_id == 1002);
            assert(f.pso_mask == server::DEFAULT_ROUTE_PSO_MASK);
        },
        _ => assert(false),
    };

    // Match /api/v1/secure
    var params3 = http::ZeroAllocParams { .. };
    var canon3: u8[..512] = [];
    let match3 = server::match_route(router, "POST", "/api/v1/secure", params3, canon3);
    match match3 {
        Found f => {
            assert(f.handler_id == 1003);
            assert(f.pso_mask == custom_pso);
        },
        _ => assert(false),
    };

    print("PSO_ROUTE_MATCH: OK");
}

fn test_pso_fast_path_and_ingress() {
    let quota = security::new_gcra_quota(100, wing::secs(1), 10);
    var cfg = server::new_server_pipeline_config("example.com", quota);

    // Register /healthz with pso_mask = 0
    assert(server::add_route_pso(cfg.router, "GET", "/healthz", 1001, 0));

    // Register /protected with default pso_mask
    assert(server::add_route(cfg.router, "POST", "/protected", 1002));

    var timer = server_internal::new_connection_timer(30000000000, 1000000000);

    // Case 1: Fast-path probe bypasses invalid Expect header
    var req_probe = http::new_request("GET", "/healthz");
    http::append_header(req_probe.headers, "Host", "example.com");
    http::append_header(req_probe.headers, "Expect", "invalid-unsupported-expectation");

    var res_probe = http::Response { .. };
    var fut_probe = server_internal::new_inline_handler_future(0);
    let outcome_probe = server::execute_pipeline(cfg, timer, "127.0.0.1", req_probe, 1000000000, res_probe, fut_probe);

    assert(outcome_probe == server::PipelineOutcome.Handled);
    assert(res_probe.status_code == 200);
    assert(res_probe.body == "Hello, World!");
    print("PSO_FAST_PATH_BYPASS: OK");

    // Case 2: Protected route rejects invalid Expect header with 417
    var req_bad_exp = http::new_request("POST", "/protected");
    http::append_header(req_bad_exp.headers, "Host", "example.com");
    http::append_header(req_bad_exp.headers, "Expect", "invalid-unsupported-expectation");

    var res_bad_exp = http::Response { .. };
    var fut_bad_exp = server_internal::new_inline_handler_future(0);
    let outcome_bad_exp = server::execute_pipeline(cfg, timer, "127.0.0.1", req_bad_exp, 1000000000, res_bad_exp, fut_bad_exp);

    assert(outcome_bad_exp == server::PipelineOutcome.ExpectationFailed);
    assert(res_bad_exp.status_code == 417);

    // Case 3: Protected route accepts valid Expect: 100-continue
    var req_ok_exp = http::new_request("POST", "/protected");
    http::append_header(req_ok_exp.headers, "Host", "example.com");
    http::append_header(req_ok_exp.headers, "Sec-Fetch-Site", "same-origin");
    http::append_header(req_ok_exp.headers, "Expect", "100-continue");

    var res_ok_exp = http::Response { .. };
    var fut_ok_exp = server_internal::new_inline_handler_future(0);
    let outcome_ok_exp = server::execute_pipeline(cfg, timer, "127.0.0.1", req_ok_exp, 1000000000, res_ok_exp, fut_ok_exp);

    assert(outcome_ok_exp == server::PipelineOutcome.Handled);
    assert(res_ok_exp.status_code == 200);
    print("PSO_INGRESS_ENFORCEMENT: OK");
}

fn test_pso_egress_security_headers() {
    let quota = security::new_gcra_quota(100, wing::secs(1), 10);
    var cfg = server::new_server_pipeline_config("example.com", quota);

    let secure_pso: u64 = server::STAGE_EGRESS_SECURITY_HEADERS;
    assert(server::add_route_pso(cfg.router, "GET", "/secure-api", 1002, secure_pso));

    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var req = http::new_request("GET", "/secure-api");
    http::append_header(req.headers, "Host", "example.com");

    var res = http::Response { .. };
    var fut = server_internal::new_inline_handler_future(0);
    let outcome = server::execute_pipeline(cfg, timer, "127.0.0.1", req, 1000000000, res, fut);

    assert(outcome == server::PipelineOutcome.Handled);
    assert(res.status_code == 200);
    assert(res.has_header("Strict-Transport-Security"));
    assert(res.has_header("Vary"));
    print("PSO_EGRESS_SECURITY: OK");
}

fn test_client_bitmask_interceptors() {
    var pipeline = client::InterceptorPipeline { .. };

    // Register interceptors via bitmask setters
    assert(client::add_bearer_auth(pipeline, "super-secret-token"));
    assert(client::add_request_id(pipeline, "trace-"));
    assert(client::add_traceparent(pipeline, "01"));
    assert(client::add_retry(pipeline, 3, true));

    // Verify bitmask has bits set
    assert((pipeline.active_mask & client::INTERCEPTOR_APP_AUTH_BEARER) != 0);
    assert((pipeline.active_mask & client::INTERCEPTOR_APP_REQUEST_ID) != 0);
    assert((pipeline.active_mask & client::INTERCEPTOR_APP_TRACEPARENT) != 0);
    assert((pipeline.active_mask & client::INTERCEPTOR_APP_RETRY) != 0);

    // Verify instant retry policy query
    let rpol, ok_retry = client::find_retry_policy(pipeline);
    assert(ok_retry);
    assert(rpol.max_retries == 3);
    assert(rpol.retry_on_5xx);

    // Apply request hook
    var req = http::new_request("GET", "https://api.internal/data");
    client::apply_app_interceptors_request(pipeline, req, 1600000000);

    assert(req.has_header("Authorization"));
    assert(req.header("Authorization") == "Bearer super-secret-token");
    assert(req.has_header("X-Request-ID"));
    assert(req.header("X-Request-ID") == "trace-1");
    assert(req.has_header("traceparent"));

    print("CLIENT_BITMASK_INTERCEPTORS: OK");
}

fn run_10_verify_bitmask_pipeline() {
    test_pso_route_matching();
    test_pso_fast_path_and_ingress();
    test_pso_egress_security_headers();
    test_client_bitmask_interceptors();
    print("BITMASK_PIPELINE_COMPLETE: OK");
}

// CHECK: PSO_ROUTE_MATCH: OK
// CHECK: PSO_FAST_PATH_BYPASS: OK
// CHECK: PSO_INGRESS_ENFORCEMENT: OK
// CHECK: PSO_EGRESS_SECURITY: OK
// CHECK: CLIENT_BITMASK_INTERCEPTORS: OK
// CHECK: BITMASK_PIPELINE_COMPLETE: OK

fn main() {
    print("\n=== [1/10] verify_fast_string_primitives ===\n");
    run_01_verify_fast_string_primitives();
    print("\n=== [2/10] verify_simd_scanners ===\n");
    run_02_verify_simd_scanners();
    print("\n=== [3/10] verify_swar_headers ===\n");
    run_03_verify_swar_headers();
    print("\n=== [4/10] verify_slot_stack ===\n");
    run_04_verify_slot_stack();
    print("\n=== [5/10] verify_zero_cost_oop ===\n");
    run_05_verify_zero_cost_oop();
    print("\n=== [6/10] verify_overflow_fallback ===\n");
    run_06_verify_overflow_fallback();
    print("\n=== [7/10] verify_capacity_lifecycle ===\n");
    run_07_verify_capacity_lifecycle();
    print("\n=== [8/10] verify_rio_memory_escape ===\n");
    run_08_verify_rio_memory_escape();
    print("\n=== [9/10] verify_uring_leak ===\n");
    run_09_verify_uring_leak();
    print("\n=== [10/10] verify_bitmask_pipeline ===\n");
    run_10_verify_bitmask_pipeline();
}
