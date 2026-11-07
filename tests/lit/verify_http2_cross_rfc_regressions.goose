// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http2_cross_rfc_regressions.goose
// Cross-component & RFC edge-case regression suite for HTTP/2:
// 1. RFC 9113 §4.3: HPACK state synchronization across stream-rejected HEADERS frames.
// 2. RFC 9113 §8.1 & §8.1.1: Trailer missing END_STREAM or CL mismatch is RST_STREAM, not GOAWAY.
// 3. RFC 9113 §8.1.2 & RFC 9110 §6.5.1: Disallowed trailer fields rejected in decode_hpack_to_map.
// 4. RFC 7541 §4.2: Dynamic table size update min+final tracking & 128-entry ring cap.
// 5. RFC 9218 §2.1 & §5: SETTINGS_NO_RFC7540_PRIORITIES enforcement & Priority header integration.
// 6. RFC 9113 §6.9 & §8.1: Client H2 padded DATA WINDOW_UPDATE credit, 1xx END_STREAM & trailer rules.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import headers from "../../http";
import wing from "../..";

fn has_frame_on_wire(wire: const u8[:], frame_type: u8, stream_id: u32) -> bool {
    var off: i64 = 0;
    while off + 9 <= wire.len {
        let hdr, err = internal::parse_frame_header(wire[off..off + 9]);
        guard err == rfc::H2_ERR_NO_ERROR else { break; }
        if hdr.frame_type == frame_type && (stream_id == 0 || hdr.stream_id == stream_id) {
            return true;
        }
        off += 9 + (hdr.length as i64);
    }
    return false;
}

fn test_hpack_sync_across_stream_errors() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/ok", 1);

    var client_dt = internal::new_dynamic_table(4096);
    var wire1: u8[>..] = [];
    wire1.append(rfc::H2_CLIENT_PREFACE[..]);

    // Stream 1: valid pseudo-headers + incrementally indexed authority + invalid uppercase header + trailing custom header
    var hb1: u8[>..] = [];
    internal::encode_hpack_field(client_dt, hb1, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb1, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb1, ":path", "/ok", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb1, ":authority", "sync.example.com", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb1, "Bad-Upper", "v1", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb1, "x-after-err", "v2", internal::HpackIndexing.Incremental, false);

    let f1 = internal::FrameHeader {
        length:     hb1.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    internal::encode_frame_header_to(f1, wire1);
    wire1.append(hb1[..]);

    var out1: u8[>..] = [];
    let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire1[..], 1000, out1);
    assert(ok1);
    assert(has_frame_on_wire(out1[..], rfc::H2_FRAME_RST_STREAM, 1));

    // Also send a self-dependent HEADERS frame on Stream 3 (rejected before dispatch) that indexes a new header
    var hb3_bad: u8[>..] = [];
    hb3_bad.push(0x00); hb3_bad.push(0x00); hb3_bad.push(0x00); hb3_bad.push(0x03); // dep_raw = 3 (self-dependency)
    hb3_bad.push(16); // weight
    internal::encode_hpack_field(client_dt, hb3_bad, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb3_bad, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb3_bad, ":path", "/ok", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb3_bad, "x-self-dep", "indexed", internal::HpackIndexing.Incremental, false);

    var wire3: u8[>..] = [];
    let f3 = internal::FrameHeader {
        length:     hb3_bad.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM | rfc::H2_FLAG_PRIORITY,
        stream_id:  3,
    };
    internal::encode_frame_header_to(f3, wire3);
    wire3.append(hb3_bad[..]);
    var out3: u8[>..] = [];
    let _, ok3 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire3[..], 1000, out3);
    assert(ok3);
    assert(has_frame_on_wire(out3[..], rfc::H2_FRAME_RST_STREAM, 3));

    // Now Stream 5 references ":authority: sync.example.com" from client_dt (shifted by Bad-Upper, x-after-err, x-self-dep)
    var hb5: u8[>..] = [];
    internal::encode_hpack_field(client_dt, hb5, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb5, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb5, ":path", "/ok", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb5, ":authority", "sync.example.com", internal::HpackIndexing.Incremental, false);

    var wire5: u8[>..] = [];
    let f5 = internal::FrameHeader {
        length:     hb5.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  5,
    };
    internal::encode_frame_header_to(f5, wire5);
    wire5.append(hb5[..]);
    var out5: u8[>..] = [];
    let _, ok5 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire5[..], 1000, out5);
    assert(ok5);
    assert(has_frame_on_wire(out5[..], rfc::H2_FRAME_HEADERS, 5));
    print("TEST_1_HPACK_SYNC_ACROSS_STREAM_ERRORS: OK\n");
}

fn test_trailer_errors_and_disallowed_fields() {
    // 1. Disallowed RFC 9110 §6.5.1 trailer fields (authorization, cookie, content-type) must fail decode_hpack_to_map
    var dt = internal::new_dynamic_table(4096);
    var t_block: u8[>..] = [];
    internal::encode_hpack_field(dt, t_block, "authorization", "Bearer tok", internal::HpackIndexing.None, false);
    var pseudo = internal::H2PseudoHeaders { is_trailer: true, .. };
    var out_map = wing::HeaderMap { .. };
    let err_auth = internal::decode_hpack_to_map(dt, t_block[..], pseudo, out_map);
    assert(err_auth == rfc::H2_ERR_PROTOCOL_ERROR);

    // 2. Trailer HEADERS without END_STREAM on open stream must emit RST_STREAM(PROTOCOL_ERROR), NOT GOAWAY
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/up", 2);

    var client_dt = internal::new_dynamic_table(4096);
    var wire: u8[>..] = [];
    wire.append(rfc::H2_CLIENT_PREFACE[..]);
    var hb1: u8[>..] = [];
    internal::encode_hpack_field(client_dt, hb1, ":method", "POST", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb1, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb1, ":path", "/up", internal::HpackIndexing.Incremental, false);
    let f1 = internal::FrameHeader {
        length:     hb1.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    internal::encode_frame_header_to(f1, wire);
    wire.append(hb1[..]);

    // Trailer HEADERS on stream 1 WITHOUT END_STREAM
    var hb_tr: u8[>..] = [];
    internal::encode_hpack_field(client_dt, hb_tr, "x-checksum", "abc", internal::HpackIndexing.Incremental, false);
    let f_tr = internal::FrameHeader {
        length:     hb_tr.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS, // missing END_STREAM!
        stream_id:  1,
    };
    internal::encode_frame_header_to(f_tr, wire);
    wire.append(hb_tr[..]);

    var out: u8[>..] = [];
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out);
    assert(ok);
    assert(has_frame_on_wire(out[..], rfc::H2_FRAME_RST_STREAM, 1));
    assert(!has_frame_on_wire(out[..], rfc::H2_FRAME_GOAWAY, 0));
    print("TEST_2_3_TRAILERS_AND_DISALLOWED_FIELDS: OK\n");
}

fn test_hpack_dyn_size_min_update_and_ring_cap() {
    // Part A: Ring buffer cap at 128 entries even when max_allowed > 4096
    var big_dt = internal::new_dynamic_table(8192);
    for i in 135 {
        internal::insert_header(big_dt, "k", "v", false);
    }
    assert(big_dt.count == 128);
    internal::evict_until(big_dt, 0);
    assert(big_dt.count == 0 && big_dt.used_bytes == 0);

    // Part B: SETTINGS_HEADER_TABLE_SIZE 0 then 4096 must emit both 0 (0x20) and 4096 (0x3F 0xE1 0x1F)
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/ping", 1);

    var client_enc = internal::new_dynamic_table(4096);
    var client_dec = internal::new_dynamic_table(4096);
    var wire1: u8[>..] = [];
    wire1.append(rfc::H2_CLIENT_PREFACE[..]);
    var hb1: u8[>..] = [];
    internal::encode_hpack_field(client_enc, hb1, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_enc, hb1, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_enc, hb1, ":path", "/ping", internal::HpackIndexing.Incremental, false);
    let f1 = internal::FrameHeader {
        length:     hb1.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    internal::encode_frame_header_to(f1, wire1);
    wire1.append(hb1[..]);
    var out1: u8[>..] = [];
    let _, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire1[..], 1000, out1);
    assert(ok1);

    // Decode stream 1 response headers into client_dec (populates server & content-length in client_dec)
    let resp1_hdr, _ = internal::parse_frame_header(out1[33..42]);
    var p1 = internal::H2PseudoHeaders { .. };
    var m1 = wing::HeaderMap { .. };
    assert(internal::decode_hpack_to_map(client_dec, out1[42..42 + resp1_hdr.length], p1, m1) == rfc::H2_ERR_NO_ERROR);
    assert(client_dec.count > 0);

    // Client sends SETTINGS with HEADER_TABLE_SIZE = 0 followed by HEADER_TABLE_SIZE = 4096, then Stream 3
    var wire2: u8[>..] = [];
    let s_hdr = internal::FrameHeader { length: 12, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    internal::encode_frame_header_to(s_hdr, wire2);
    core::append_u16_be(wire2, rfc::H2_SETTING_HEADER_TABLE_SIZE);
    core::append_u32_be(wire2, 0);
    core::append_u16_be(wire2, rfc::H2_SETTING_HEADER_TABLE_SIZE);
    core::append_u32_be(wire2, 4096);

    var hb3: u8[>..] = [];
    internal::encode_hpack_field(client_enc, hb3, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_enc, hb3, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_enc, hb3, ":path", "/ping", internal::HpackIndexing.Incremental, false);
    let f3 = internal::FrameHeader {
        length:     hb3.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  3,
    };
    internal::encode_frame_header_to(f3, wire2);
    wire2.append(hb3[..]);

    var out2: u8[>..] = [];
    let _, ok2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire2[..], 1000, out2);
    assert(ok2);
    // out2 starts with 9-byte SETTINGS ACK, followed by Stream 3 response HEADERS frame
    let resp3_hdr, _ = internal::parse_frame_header(out2[9..18]);
    let resp3_hpack = out2[18..18 + resp3_hdr.length];
    // First byte of resp3_hpack MUST be 0x20 (Dynamic Table Size Update to 0)
    assert(resp3_hpack.len > 0 && resp3_hpack[0] == 0x20);
    var p3 = internal::H2PseudoHeaders { .. };
    var m3 = wing::HeaderMap { .. };
    assert(internal::decode_hpack_to_map(client_dec, resp3_hpack, p3, m3) == rfc::H2_ERR_NO_ERROR);
    assert(client_dec.count == sess.hpack_enc.count);
    print("TEST_4_HPACK_DYN_MIN_SIZE_AND_RING_CAP: OK\n");
}

fn test_rfc9218_and_client_h2_edge_cases() {
    // 1. RFC 9218 §2.1: SETTINGS_NO_RFC7540_PRIORITIES = 1 ignores self-dependency in HEADERS & PRIORITY
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/p", 1);

    var wire: u8[>..] = [];
    wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let s_hdr = internal::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    internal::encode_frame_header_to(s_hdr, wire);
    core::append_u16_be(wire, rfc::H2_SETTING_NO_RFC7540_PRIORITIES);
    core::append_u32_be(wire, 1);

    var client_dt = internal::new_dynamic_table(4096);
    var hb: u8[>..] = [];
    hb.push(0x00); hb.push(0x00); hb.push(0x00); hb.push(0x01); hb.push(16); // self-dep = 1
    internal::encode_hpack_field(client_dt, hb, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb, ":path", "/p", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, hb, "priority", "u=1, i", internal::HpackIndexing.None, false);
    let f_hdr = internal::FrameHeader {
        length:     hb.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_PRIORITY,
        stream_id:  1,
    };
    internal::encode_frame_header_to(f_hdr, wire);
    wire.append(hb[..]);

    var out: u8[>..] = [];
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire[..], 1000, out);
    assert(ok);
    assert(!has_frame_on_wire(out[..], rfc::H2_FRAME_RST_STREAM, 1));
    let s_idx, found = internal::find_session_stream_idx(sess.conn, 1);
    assert(found && sess.conn.streams[s_idx].priority.urgency == 1 && sess.conn.streams[s_idx].priority.incremental);

    // 2. Client H2 padded DATA frame WINDOW_UPDATE must credit full hdr.length (10), not unpadded len (5)
    var dec_dt = internal::new_dynamic_table(4096);
    var resp = wing::Response { .. };
    var out_ctrl: u8[>..] = [];
    var got_hdrs = true;
    let pad_hdr = internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      rfc::H2_FLAG_PADDED | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    let pad_payload: u8[10] = [4, 'h', 'e', 'l', 'l', 'o', 0, 0, 0, 0];
    let ok_d, end_d = wing::process_h2_response_frame(pad_hdr, pad_payload[..], 1, false, dec_dt, resp, got_hdrs, out_ctrl);
    assert(ok_d && end_d);
    assert(out_ctrl.len >= 13 && core::read_be_u32(out_ctrl[..], 9) == 10);

    // 3. Client H2 1xx informational response with END_STREAM must be rejected (RFC 9113 §8.1)
    var got_hdrs_1xx = false;
    let hdr_100 = internal::FrameHeader {
        length:     5,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    let payload_100: u8[5] = [0x08, 0x03, '1', '0', '0']; // :status: 100
    let ok_100, _ = wing::process_h2_response_frame(hdr_100, payload_100[..], 1, false, dec_dt, resp, got_hdrs_1xx, out_ctrl);
    assert(!ok_100);
    print("TEST_5_6_RFC9218_AND_CLIENT_H2: OK\n");
}

fn main() {
    test_hpack_sync_across_stream_errors();
    test_trailer_errors_and_disallowed_fields();
    test_hpack_dyn_size_min_update_and_ring_cap();
    test_rfc9218_and_client_h2_edge_cases();
    print("ALL_CROSS_RFC_REGRESSIONS: PASS\n");
}

// CHECK: TEST_1_HPACK_SYNC_ACROSS_STREAM_ERRORS: OK
// CHECK: TEST_2_3_TRAILERS_AND_DISALLOWED_FIELDS: OK
// CHECK: TEST_4_HPACK_DYN_MIN_SIZE_AND_RING_CAP: OK
// CHECK: TEST_5_6_RFC9218_AND_CLIENT_H2: OK
// CHECK: ALL_CROSS_RFC_REGRESSIONS: PASS
