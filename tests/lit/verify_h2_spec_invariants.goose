// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h2_spec_invariants.goose
// Verification of RFC 9113 HTTP/2 protocol invariants:
// 1. WINDOW_UPDATE on idle stream triggers GOAWAY(PROTOCOL_ERROR) (RFC 9113 §5.1, §6.4).
// 2. Malformed request with missing pseudo-headers triggers RST_STREAM (RFC 9113 §8.1.1, §8.3.1).
// 3. Content-length mismatch on END_STREAM HEADERS triggers RST_STREAM (RFC 9113 §8.1.1).
// 4. Content-length mismatch on DATA frame triggers RST_STREAM (RFC 9113 §8.1.1, §8.1.2).
// 5. Active stream slot and counter reclamation on stream error (RFC 9113 §5.1.2).
// 6. SETTINGS_MAX_FRAME_SIZE peer tracking without overriding local receive limits (RFC 9113 §6.5.2).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s && %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn build_frame_header<B>(out: B&, length: u32, frame_type: u8, flags: u8, stream_id: u32) {
    out.push(((length >> 16) & 0xFF) as u8);
    out.push(((length >> 8) & 0xFF) as u8);
    out.push((length & 0xFF) as u8);
    out.push(frame_type);
    out.push(flags);
    out.push(((stream_id >> 24) & 0x7F) as u8);
    out.push(((stream_id >> 16) & 0xFF) as u8);
    out.push(((stream_id >> 8) & 0xFF) as u8);
    out.push((stream_id & 0xFF) as u8);
}

fn scan_frames(wire: const u8[:]) -> bool, bool, u32 {
    var has_rst = false;
    var has_goaway = false;
    var rst_sid: u32 = 0;
    var p:       i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) | ((wire[p + 6] as u32) << 16) | ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == 0x03 {
            has_rst = true;
            rst_sid = f_sid;
        }
        if f_type == 0x07 {
            has_goaway = true;
        }
        p += 9 + (f_len as i64);
    }
    return has_rst, has_goaway, rst_sid;
}

fn test_idle_stream_window_update() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // Preface + empty SETTINGS
    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS frame
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send WINDOW_UPDATE on stream 5 (idle stream; last_peer_stream_id is 0)
    var wu_frame: u8[>..] = [];
    build_frame_header(wu_frame, 4, 0x08, 0x00, 5); // WINDOW_UPDATE on stream 5
    wu_frame.push(0x00); wu_frame.push(0x00); wu_frame.push(0x04); wu_frame.push(0x00); // +1024 octets

    wire_out.clear();
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wu_frame[..], 1000, wire_out);
    let has_rst, has_goaway, _ = scan_frames(wire_out[..]);

    // RFC 9113 §5.1 & §6.4: Frame on idle stream MUST trigger GOAWAY(PROTOCOL_ERROR), NOT RST_STREAM.
    print("IDLE_WU_CONNECTION_TERMINATED: ", if !ok { "YES" } else { "NO" });
    print("IDLE_WU_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
    print("IDLE_WU_RST: ", if has_rst { "YES" } else { "NO" });
}

fn test_missing_mandatory_pseudo_headers() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Request missing :path (only :method and :scheme provided)
    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    build_frame_header(h_frame, h_block.len as u32, 0x01, 0x05, 1); // HEADERS + END_STREAM | END_HEADERS
    h_frame.append(h_block[..]);

    wire_out.clear();
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);
    let has_rst, has_goaway, sid = scan_frames(wire_out[..]);

    // RFC 9113 §8.1.1: Malformed request MUST be treated as a stream error RST_STREAM, not GOAWAY
    print("MISSING_PSEUDO_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("MISSING_PSEUDO_RST_STREAM: ", if has_rst && sid == 1 { "YES" } else { "NO" });
    print("MISSING_PSEUDO_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
}

fn test_content_length_end_stream_headers() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // HEADERS with END_STREAM but content-length: 10
    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":path", "/", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, "content-length", "10", internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    build_frame_header(h_frame, h_block.len as u32, 0x01, 0x05, 1); // HEADERS + END_STREAM | END_HEADERS
    h_frame.append(h_block[..]);

    wire_out.clear();
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);
    let has_rst, has_goaway, sid = scan_frames(wire_out[..]);

    // RFC 9113 §8.1.1: Content-length mismatch MUST be treated as a stream error RST_STREAM, not GOAWAY
    print("CL_HEADERS_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("CL_HEADERS_RST_STREAM: ", if has_rst && sid == 1 { "YES" } else { "NO" });
    print("CL_HEADERS_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
}

fn test_content_length_mismatch_data() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // HEADERS with content-length: 10, but NO END_STREAM
    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":path", "/post", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, "content-length", "10", internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    build_frame_header(h_frame, h_block.len as u32, 0x01, 0x04, 1); // HEADERS + END_HEADERS (no END_STREAM)
    h_frame.append(h_block[..]);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);

    // DATA with 3 bytes and END_STREAM (expected 10, received 3)
    var d_frame: u8[>..] = [];
    build_frame_header(d_frame, 3, 0x00, 0x01, 1); // DATA + END_STREAM
    d_frame.append("foo");

    wire_out.clear();
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d_frame[..], 1000, wire_out);
    let has_rst, has_goaway, sid = scan_frames(wire_out[..]);

    // RFC 9113 §8.1.1 & §8.1.2: Content-length mismatch MUST be stream error RST_STREAM, not GOAWAY
    print("CL_DATA_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("CL_DATA_RST_STREAM: ", if has_rst && sid == 1 { "YES" } else { "NO" });
    print("CL_DATA_GOAWAY: ", if has_goaway { "YES" } else { "NO" });
}

fn test_stream_slot_reclamation_on_error() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send HEADERS with invalid uppercase field name (RFC 9113 §8.2.1)
    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":path", "/", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, "Custom-Upper", "val", internal::HpackIndexing.Incremental, false);

    var h_frame: u8[>..] = [];
    build_frame_header(h_frame, h_block.len as u32, 0x01, 0x05, 1);
    h_frame.append(h_block[..]);

    wire_out.clear();
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_frame[..], 1000, wire_out);

    // RFC 9113 §5.1.2: Active stream slot MUST be reclaimed upon reset
    print("STREAM_RECLAIMED_ACTIVE_COUNT: ", sess.conn.active_stream_count);
}

fn test_settings_max_frame_size_isolation() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // Client advertises SETTINGS_MAX_FRAME_SIZE = 32768
    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 6, 0x04, 0x00, 0); // SETTINGS frame
    init_wire.push(0x00); init_wire.push(0x05); // SETTING_MAX_FRAME_SIZE (0x05)
    init_wire.push(0x00); init_wire.push(0x00); init_wire.push(0x80); init_wire.push(0x00); // 32768

    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // RFC 9113 §6.5.2: Server's local receive frame size must remain 16384
    print("LOCAL_MAX_FRAME_SIZE_KEPT: ", if sess.conn.local_max_frame_size == 16384 { "YES" } else { "NO" });
}

fn main() {
    test_idle_stream_window_update();
    test_missing_mandatory_pseudo_headers();
    test_content_length_end_stream_headers();
    test_content_length_mismatch_data();
    test_stream_slot_reclamation_on_error();
    test_settings_max_frame_size_isolation();
    print("H2_SPEC_INVARIANTS_VERIFIED");
}

// CHECK: IDLE_WU_CONNECTION_TERMINATED: YES
// CHECK: IDLE_WU_GOAWAY: YES
// CHECK: IDLE_WU_RST: NO
// CHECK: MISSING_PSEUDO_CONN_ALIVE: YES
// CHECK: MISSING_PSEUDO_RST_STREAM: YES
// CHECK: MISSING_PSEUDO_GOAWAY: NO
// CHECK: CL_HEADERS_CONN_ALIVE: YES
// CHECK: CL_HEADERS_RST_STREAM: YES
// CHECK: CL_HEADERS_GOAWAY: NO
// CHECK: CL_DATA_CONN_ALIVE: YES
// CHECK: CL_DATA_RST_STREAM: YES
// CHECK: CL_DATA_GOAWAY: NO
// CHECK: STREAM_RECLAIMED_ACTIVE_COUNT: 0
// CHECK: LOCAL_MAX_FRAME_SIZE_KEPT: YES
// CHECK: H2_SPEC_INVARIANTS_VERIFIED
