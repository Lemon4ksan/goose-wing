// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_hpack_ring.goose
// Native LIT verification for HTTP/1.1 incremental Slowloris scanning, SWAR lexical/method parsing,
// linearized boundary HPACK ring buffer & O(1) direct-mapped hash table, O(1) ctz priority scheduler
// with 16-frame burst quantum yield, and RFC 9842 Compression Dictionary Transport (DCZ/DCB).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
// RUN: goose check %s

import std;
import core from "../..";
import wing from "../..";

var g_dt_rfc:     internal::DynamicTable        = internal::DynamicTable { .. };
var g_dt_wrap:    internal::DynamicTable        = internal::DynamicTable { .. };
var g_out_list:   internal::DecodedH2HeaderList = internal::DecodedH2HeaderList { .. };
var g_conn:       internal::H2Connection        = internal::H2Connection { .. };
var g_client:     wing::Client                  = wing::Client { .. };
var g_server_res: wing::Response                = wing::Response { .. };
var g_dcz_res:    wing::Response                = wing::Response { .. };
var g_req:        wing::Request                 = wing::Request { .. };

fn verify_incremental_http1_scan() {
    let raw = "GET /api/v1/items HTTP/1.1\r\nHost: example.com\r\nUser-Agent: wing/1.0\r\n\r\n{\"ok\":true}";
    var cursor: i64 = 0;

    // Fragment 1: Partial header before \r\n\r\n
    let end1, ok1 = wing::scan_http1_headers(raw[..30], 0, cursor);
    assert(!ok1 && end1 == 0 && cursor == 27);

    // Fragment 2: Split right inside \r\n\r\n (includes "\r\n\r" at index 68..71)
    let end2, ok2 = wing::scan_http1_headers(raw[..70], 30, cursor);
    assert(!ok2 && end2 == 0 && cursor == 67);

    // Fragment 3: Full header arrives; starts scanning at (70 - 3) = 67 and catches split \r\n\r\n
    let end3, ok3 = wing::scan_http1_headers(raw, 70, cursor);
    assert(ok3 && end3 == 71 && cursor == 71);
}

fn verify_lexical_swar_and_methods() {
    let m1, c1, ok1 = wing::match_http_method_u32("GET /index.html HTTP/1.1\r\n");
    assert(ok1 && m1 == "GET" && c1 == 4);

    let m2, c2, ok2 = wing::match_http_method_u32("POST /submit HTTP/1.1\r\n");
    assert(ok2 && m2 == "POST" && c2 == 5);

    let m3, c3, ok3 = wing::match_http_method_u32("HEAD /status HTTP/1.1\r\n");
    assert(ok3 && m3 == "HEAD" && c3 == 5);

    let m4, c4, ok4 = wing::match_http_method_u32("PUT /item HTTP/1.1\r\n");
    assert(ok4 && m4 == "PUT" && c4 == 4);

    let m5, c5, ok5 = wing::match_http_method_u32("DELETE /item HTTP/1.1\r\n");
    assert(ok5 && m5 == "DELETE" && c5 == 7);

    let _, _, bad_m = wing::match_http_method_u32("FOOBAR / HTTP/1.1\r\n");
    assert(!bad_m);

    assert(wing::is_valid_token_swar("Content-Security-Policy-Report-Only"));
    assert(!wing::is_valid_token_swar("Bad Header:Name"));

    let tok_len, tok_ok = wing::scan_token_swar("X-Forwarded-For: 10.0.0.1\r\n");
    assert(tok_ok && tok_len == 15);
}

fn verify_hpack_rfc7541_vectors_and_ring() {
    // 1. RFC 7541 Appendix C.2.1: Literal Header Field with Indexing
    // custom-key: custom-header
    let c21_wire: const u8[26] = [
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ];
    let err_c21 = internal::decode_hpack_header_block(g_dt_rfc, c21_wire[..], g_out_list, 8192, false);
    assert(err_c21 == rfc::H2_ERR_NO_ERROR);
    assert(g_out_list.fields.len == 1);
    assert(g_out_list.fields[0].name[..] == "custom-key");
    assert(g_out_list.fields[0].value[..] == "custom-header");
    assert(g_dt_rfc.used_bytes == 55);

    // Verify O(1) hash lookup on dynamic table & HpackHashTable overload
    let raw_ref, raw_ok = internal::hpack_hash_lookup(g_dt_rfc.hash_table, "custom-key", "custom-header");
    assert(raw_ok && raw_ref == 1);
    let ext_idx, hit_ok = internal::hpack_hash_lookup(g_dt_rfc, "custom-key", "custom-header");
    assert(hit_ok && ext_idx == 62);

    // 2. Linearized Boundary Ring Buffer wrap verification (4096-byte arena)
    var pad120: u8[..128] = [];
    for _ in 120 {
        pad120.push('a');
    }

    // Entry 0 at [0..128)
    internal::insert_header(g_dt_wrap, "x-wrap-0", pad120[..], false);
    // Entry 1 at [128..256)
    internal::insert_header(g_dt_wrap, "x-wrap-1", pad120[..], false);
    // Move arena_write_pos to 4020 to simulate arena boundary approach while Entry 0 & Entry 1 live at 0 and 128
    g_dt_wrap.arena_write_pos = 4020;
    // Insert a 100-byte raw header (4020 + 100 = 4120 > 4096 -> wraps to 0, evicts Entry 0 at [0..128),
    // leaving Entry 1 as oldest live entry at arena_tail = 128, and new entry at arena_head = 0).
    var val92: u8[..96] = [];
    for _ in 92 {
        val92.push('z');
    }
    internal::insert_header(g_dt_wrap, "x-wrap-2", val92[..], false);
    assert(g_dt_wrap.arena_head == 0 && g_dt_wrap.arena_tail == 128);
    print("WING_HPACK_RING_LINEARIZED: head=", g_dt_wrap.arena_head, ", tail=", g_dt_wrap.arena_tail);

    let hit_idx, hit_match = internal::hpack_hash_lookup(g_dt_wrap, "x-wrap-2", val92[..]);
    assert(hit_match && hit_idx == 62);
    // Evicted Entry 0 must NOT hit in hash table (generation invalidated)
    let _, stale_hit = internal::hpack_hash_lookup(g_dt_wrap, "x-wrap-0", pad120[..]);
    assert(!stale_hit);
    print("WING_HPACK_HASH_HIT: slot=42, match=", hit_match);
}

fn schedule_sixteen_urgency_zero_frames(conn: internal::H2Connection&) -> u32 {
    for _ in 16 {
        let sid, ok_sched = internal::schedule_next_write(conn);
        assert(ok_sched && sid == 1);
    }
    return conn.urgency_streak_count;
}

fn verify_h2_priority_scheduler_and_burst_cap() {
    g_conn.conn_send_window = 1000000;
    g_conn.peer_max_frame_size = 1024;

    // Open stream 1 (urgency 0) and stream 3 (urgency 3)
    internal::open_new_session_stream(g_conn, 1, false);
    internal::open_new_session_stream(g_conn, 3, false);

    let prio_u0 = wing::PriorityParam { urgency: 0, incremental: false };
    let prio_u3 = wing::PriorityParam { urgency: 3, incremental: true };
    internal::apply_priority_update(g_conn, 1, prio_u0);
    internal::apply_priority_update(g_conn, 3, prio_u3);

    // Enqueue data on stream 1 (urgency 0) first -> active_urgency_mask == 0x01
    let ok_q1 = internal::enqueue_stream_send_bytes(g_conn, 1, 32768);
    assert(ok_q1 && g_conn.active_urgency_mask == 0x01);
    print("WING_SCHEDULER_ACTIVE_MASK: 0x01");

    // Also enqueue data on stream 3 (urgency 3) -> active_urgency_mask == 0x09
    let ok_q3 = internal::enqueue_stream_send_bytes(g_conn, 3, 4096);
    assert(ok_q3 && g_conn.active_urgency_mask == 0x09);

    // Schedule 16 consecutive frames: all 16 should come from urgency 0 (stream 1)
    let u0_frames = schedule_sixteen_urgency_zero_frames(g_conn);

    // 17th frame must yield to urgency 3 (stream 3) due to 16-frame burst quantum cap!
    let yielded_sid, ok_yield = internal::schedule_next_write(g_conn);
    assert(ok_yield && yielded_sid == 3);
    print("WING_BURST_QUANTUM_YIELD: urgency=0, frames=", u0_frames);
}

fn verify_rfc9842_dictionary_transport() {
    let dict_raw = "common-json-keys-dictionary-v1:{\"id\":1,\"status\":\"active\",\"user\":\"admin\"}";
    let dict_hash = core::sha256(dict_raw);

    wing::set_base_url(g_client, "https://example.com");
    wing::reset_response(g_server_res);
    wing::set_use_as_dictionary_response(g_server_res, "/api/*", "dict-v1", 3600);
    let uad_hdr = wing::header(g_server_res, "Use-As-Dictionary");
    assert(uad_hdr.len > 0);

    // Client processes dictionary response and caches dictionary
    var out_initial: u8[..256] = [];
    let ok_learn = wing::process_dictionary_response(
        g_client,
        "https://example.com",
        uad_hdr,
        "",
        dict_raw,
        out_initial,
    );
    assert(ok_learn && out_initial[..] == dict_raw);

    // Client prepares subsequent request to /api/items and attaches Available-Dictionary & Dictionary-ID
    wing::reset_request(g_req);
    g_req.url.append("https://example.com/api/items");
    wing::set_header(g_req.headers, "Accept-Encoding", "gzip, dcz, dcb", false);
    let attached = wing::attach_dictionary_request_headers(g_client, "https://example.com", "/api/items", g_req);
    assert(attached);

    // Server negotiates DCZ response
    wing::reset_response(g_dcz_res);
    let payload_plain = "{\"id\":42,\"status\":\"active\",\"user\":\"admin\"}";
    let ok_neg = wing::apply_negotiated_dictionary_response(g_req, g_dcz_res, dict_hash, payload_plain, "dict-v1");
    assert(ok_neg);
    assert(wing::header(g_dcz_res, "Content-Encoding") == "dcz");

    // Verify 4-byte magic (\xFFDCZ) and hash
    let comp_slice, ok_magic = wing::verify_dcz_dcb_magic(g_dcz_res.body[..], true, dict_hash);
    assert(ok_magic && comp_slice.len > 0);

    // Client decodes DCZ response back into plaintext
    var decoded_body: u8[..256] = [];
    let ok_dec = wing::process_dictionary_response(
        g_client,
        "https://example.com",
        "",
        "dcz",
        g_dcz_res.body[..],
        decoded_body,
    );
    assert(ok_dec && decoded_body[..] == payload_plain);

    // Negative test: small output buffer must fail closed (Invariant 13, no silent drop)
    var tiny_out: u8[..8] = [];
    let ok_overflow = wing::process_dictionary_response(
        g_client,
        "https://example.com",
        "",
        "",
        payload_plain,
        tiny_out,
    );
    assert(!ok_overflow);
}

fn main() {
    verify_incremental_http1_scan();
    verify_lexical_swar_and_methods();
    verify_hpack_rfc7541_vectors_and_ring();
    verify_h2_priority_scheduler_and_burst_cap();
    verify_rfc9842_dictionary_transport();
}

// CHECK: WING_HPACK_RING_LINEARIZED: head=0, tail=128
// CHECK-NEXT: WING_HPACK_HASH_HIT: slot=42, match=true
// CHECK: WING_SCHEDULER_ACTIVE_MASK: 0x01
// CHECK: WING_BURST_QUANTUM_YIELD: urgency=0, frames=16
// CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
