// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h2_and_chunk_edge.goose
// Verification of RFC 9113 HTTP/2 padded DATA frame content-length matching,
// stream-level PROTOCOL_ERROR isolation, and RFC 9112 chunk extension quoted-pair parsing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s && %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_h2_padded_data_and_overflow() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var wire_out: u8[>..] = [];

    // 1. Client preface + SETTINGS
    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    // Empty SETTINGS frame (type 4, flags 0, stream 0)
    init_wire.append([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let _, ok_init = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);
    print("H2_INIT: ", if ok_init { "OK" } else { "FAIL" });

    // 2. Stream 1: HEADERS with :method=POST, :scheme=https, :path=/echo, content-length=5
    // Encode via HPACK
    var dt = internal::new_dynamic_table(4096);
    var hdr_block: u8[>..] = [];
    internal::encode_hpack_field(dt, hdr_block, ":method", "POST", true, false);
    internal::encode_hpack_field(dt, hdr_block, ":scheme", "https", true, false);
    internal::encode_hpack_field(dt, hdr_block, ":path", "/echo", true, false);
    internal::encode_hpack_field(dt, hdr_block, "content-length", "5", true, false);

    // Frame header for HEADERS on stream 1 with END_HEADERS (flags 0x04)
    var h1_frame: u8[>..] = [];
    let h1_len = hdr_block.len as u32;
    h1_frame.push(((h1_len >> 16) & 0xFF) as u8);
    h1_frame.push(((h1_len >> 8) & 0xFF) as u8);
    h1_frame.push((h1_len & 0xFF) as u8);
    h1_frame.push(0x01); // FRAME_HEADERS
    h1_frame.push(0x04); // FLAG_END_HEADERS
    h1_frame.push(0x00); h1_frame.push(0x00); h1_frame.push(0x00); h1_frame.push(0x01); // Stream 1
    h1_frame.append(hdr_block[..]);

    let _, ok_h1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h1_frame[..], 1000, wire_out);
    print("H2_STREAM_1_HEADERS: ", if ok_h1 { "OK" } else { "FAIL" });

    // 3. Stream 1: PADDED DATA frame (flags 0x08 | 0x01 = 0x09: FLAG_PADDED | FLAG_END_STREAM)
    // Payload: pad_length (1B) = 3, data (5B) = "hello", padding (3B) = 0x00, 0x00, 0x00
    // Total frame payload: 1 + 5 + 3 = 9 bytes.
    var d1_frame: u8[>..] = [];
    d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x09); // length 9
    d1_frame.push(0x00); // FRAME_DATA
    d1_frame.push(0x09); // FLAG_PADDED | FLAG_END_STREAM
    d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x01); // Stream 1
    d1_frame.push(0x03); // Pad length: 3 bytes
    d1_frame.append("hello");
    d1_frame.push(0x00); d1_frame.push(0x00); d1_frame.push(0x00); // 3 padding bytes

    wire_out.clear();
    let _, ok_d1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d1_frame[..], 1000, wire_out);
    print("H2_STREAM_1_PADDED_DATA: ", if ok_d1 { "OK" } else { "FAIL" });

    // 4. Stream 3: Content-length overflow isolation test (RFC 9113 §8.1.2)
    var h3_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h3_block, ":method", "POST", true, false);
    internal::encode_hpack_field(dt, h3_block, ":scheme", "https", true, false);
    internal::encode_hpack_field(dt, h3_block, ":path", "/test", true, false);
    internal::encode_hpack_field(dt, h3_block, "content-length", "4", true, false);

    var h3_frame: u8[>..] = [];
    let h3_len = h3_block.len as u32;
    h3_frame.push(((h3_len >> 16) & 0xFF) as u8);
    h3_frame.push(((h3_len >> 8) & 0xFF) as u8);
    h3_frame.push((h3_len & 0xFF) as u8);
    h3_frame.push(0x01); // FRAME_HEADERS
    h3_frame.push(0x04); // FLAG_END_HEADERS
    h3_frame.push(0x00); h3_frame.push(0x00); h3_frame.push(0x00); h3_frame.push(0x03); // Stream 3
    h3_frame.append(h3_block[..]);

    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h3_frame[..], 1000, wire_out);

    // Send DATA frame on Stream 3 with 5 bytes ("12345"), exceeding declared content-length 4!
    var d3_frame: u8[>..] = [];
    d3_frame.push(0x00); d3_frame.push(0x00); d3_frame.push(0x05); // length 5
    d3_frame.push(0x00); // FRAME_DATA
    d3_frame.push(0x00); // no flags (mid-stream overflow)
    d3_frame.push(0x00); d3_frame.push(0x00); d3_frame.push(0x00); d3_frame.push(0x03); // Stream 3
    d3_frame.append("12345");

    wire_out.clear();
    let _, ok_d3 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d3_frame[..], 1000, wire_out);
    // Connection must remain alive (ok_d3 is true) while stream 3 receives RST_STREAM
    var has_rst_3 = false;
    var has_goaway = false;
    var p: i64 = 0;
    while p + 9 <= wire_out.len {
        let f_len = ((wire_out[p] as u32) << 16) | ((wire_out[p + 1] as u32) << 8) | wire_out[p + 2];
        let f_type = wire_out[p + 3];
        let f_sid = ((wire_out[p + 5] as u32) << 24) | ((wire_out[p + 6] as u32) << 16) | ((wire_out[p + 7] as u32) << 8) | wire_out[p + 8];
        if f_type == 0x03 && f_sid == 3 { has_rst_3 = true; } // RST_STREAM
        if f_type == 0x07 { has_goaway = true; } // GOAWAY
        p += 9 + (f_len as i64);
    }

    print("STREAM 3 OVERFLOW_RST: ", if has_rst_3 { "OK" } else { "FAIL" });
    print("STREAM 3 GOAWAY_EMITTED: ", if has_goaway { "YES" } else { "NO" });
}

fn test_chunk_fsm_quoted_pair() {
    var dec = internal::new_chunk_fsm_decoder();

    // Chunk size 5 with chunk extension having an escaped quote inside quoted-string:
    // 5;desc="hello \"world\""\r\nhello\r\n0\r\n\r\n
    let raw = "5;desc=\"hello \\\"world\\\"\"\r\nhello\r\n0\r\n\r\n";
    let st, _, chunk = internal::chunk_fsm_feed(dec, raw);

    print("CHUNK_QUOTED_PAIR_STATUS: ", match st {
        YieldChunk => "YIELD",
        Complete => "COMPLETE",
        NeedMore => "NEED_MORE",
        Error => "ERROR",
    });
    print("CHUNK_QUOTED_PAIR_PAYLOAD: ", chunk);
}

fn main() {
    test_h2_padded_data_and_overflow();
    test_chunk_fsm_quoted_pair();
    print("ALL_EDGE_TESTS: PASS");
}

// CHECK-DAG: H2_INIT: OK
// CHECK-DAG: H2_STREAM_1_HEADERS: OK
// CHECK: H2_STREAM_1_PADDED_DATA: OK
// CHECK: STREAM [[SID:[0-9]+]] OVERFLOW_RST: OK
// CHECK: STREAM [[SID]] GOAWAY_EMITTED: NO
// CHECK: CHUNK_QUOTED_PAIR_STATUS: YIELD
// CHECK: CHUNK_QUOTED_PAIR_PAYLOAD: hello
// CHECK: ALL_EDGE_TESTS: PASS
