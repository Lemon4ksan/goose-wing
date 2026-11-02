// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h2_spill_lane.goose
// Verification of HTTP/2 Stream Spill Slab Pool invariants:
// 1. Fast-path inline buffer retention for requests <= 8192 bytes (zero slabs allocated).
// 2. Dynamic promotion & reassembly for requests > 8 KiB (32 KiB multi-frame payload).
// 3. Flow control credit expansion: WINDOW_UPDATE (+57344) emitted upon promotion.
// 4. Maximum capacity rejection: stream exceeding 65536 bytes reset with CANCEL.
// 5. Pool saturation defense: 17th concurrent stream > 8 KiB reset with REFUSED_STREAM.
// 6. Zero-leak lifecycle: slabs released upon stream completion, reset, or error.
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

fn scan_for_window_update(wire: const u8[:], stream_id: u32) -> bool, u32 {
    var p: i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) |
                    ((wire[p + 6] as u32) << 16) |
                    ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == 0x08 && f_sid == stream_id && (p + 13 <= wire.len) {
            let inc = ((wire[p + 9] as u32) << 24) |
                      ((wire[p + 10] as u32) << 16) |
                      ((wire[p + 11] as u32) << 8) | wire[p + 12];
            return true, (inc & 0x7FFFFFFF);
        }
        p += 9 + (f_len as i64);
    }
    return false, 0;
}

fn scan_for_rst_stream(wire: const u8[:], stream_id: u32) -> bool, u32 {
    var p: i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) |
                    ((wire[p + 6] as u32) << 16) |
                    ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == 0x03 && f_sid == stream_id && (p + 13 <= wire.len) {
            let err_code = ((wire[p + 9] as u32) << 24) |
                           ((wire[p + 10] as u32) << 16) |
                           ((wire[p + 11] as u32) << 8) | wire[p + 12];
            return true, err_code;
        }
        p += 9 + (f_len as i64);
    }
    return false, 0;
}

fn count_in_use_slabs(pool: const internal::SpillSlabPool&) -> i64 {
    var count: i64 = 0;
    for &slab in pool.slabs {
        if slab.in_use { count++; }
    }
    return count;
}

fn test_inline_body_lifecycle() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/inline", 1);

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send HEADERS for stream 1
    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":path", "/inline", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, "content-length", "4096", internal::HpackIndexing.Incremental, false);

    var req_wire: u8[>..] = [];
    build_frame_header(req_wire, h_block.len as u32, 0x01, 0x04, 1); // HEADERS + END_HEADERS
    req_wire.append(h_block[..]);

    // Send 4096 bytes of body (<= 8192 inline buffer)
    var chunk: u8[>..] = [];
    for i in 4096 { chunk.push('A'); }
    build_frame_header(req_wire, 4096, 0x00, 0x01, 1); // DATA + END_STREAM
    req_wire.append(chunk[..]);

    wire_out.clear();
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", req_wire[..], 1000, wire_out);

    print("INLINE_INGRESS_OK: ", if ok { "YES" } else { "NO" });
    print("SLABS_IN_USE_INLINE: ", count_in_use_slabs(pipeline.slab_pool));
}

fn test_dynamic_promotion_and_reassembly() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/large", 2);

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Send HEADERS for stream 1
    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":path", "/large", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, "content-length", "32768", internal::HpackIndexing.Incremental, false);

    var h_wire: u8[>..] = [];
    build_frame_header(h_wire, h_block.len as u32, 0x01, 0x04, 1); // HEADERS + END_HEADERS
    h_wire.append(h_block[..]);

    wire_out.clear();
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_wire[..], 1000, wire_out);

    // Chunk 1: 16384 bytes (> 8192 -> triggers promotion to SpillSlab!)
    var chunk1: u8[>..] = [];
    for i in 16384 { chunk1.push('B'); }
    var d1_wire: u8[>..] = [];
    build_frame_header(d1_wire, 16384, 0x00, 0x00, 1); // DATA (no END_STREAM)
    d1_wire.append(chunk1[..]);

    wire_out.clear();
    let _, ok_d1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d1_wire[..], 1000, wire_out);
    let has_wu, wu_credit = scan_for_window_update(wire_out[..], 1);

    print("PROMOTION_INGRESS_OK: ", if ok_d1 { "YES" } else { "NO" });
    print("PROMOTION_WINDOW_UPDATE_EMITTED: ", if has_wu { "YES" } else { "NO" });
    print("PROMOTION_WINDOW_UPDATE_CREDIT: ", wu_credit);

    // Chunk 2: 16384 bytes with END_STREAM (total 32768 bytes)
    var chunk2: u8[>..] = [];
    for i in 16384 { chunk2.push('C'); }
    var d2_wire: u8[>..] = [];
    build_frame_header(d2_wire, 16384, 0x00, 0x01, 1); // DATA + END_STREAM
    d2_wire.append(chunk2[..]);

    wire_out.clear();
    let _, ok_d2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d2_wire[..], 1000, wire_out);

    print("COMPLETION_INGRESS_OK: ", if ok_d2 { "YES" } else { "NO" });
    print("SLABS_IN_USE_AFTER_DISPATCH: ", count_in_use_slabs(pipeline.slab_pool));
}

fn test_maximum_capacity_overflow() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/overflow", 3);

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":path", "/overflow", internal::HpackIndexing.Incremental, false);

    var h_wire: u8[>..] = [];
    build_frame_header(h_wire, h_block.len as u32, 0x01, 0x04, 1);
    h_wire.append(h_block[..]);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_wire[..], 1000, wire_out);

    // Send 4 frames of 16384 bytes = 65536 bytes (fits exactly in 64 KiB slab)
    var chunk: u8[>..] = [];
    for i in 16384 { chunk.push('X'); }
    for step in 4 {
        var d_wire: u8[>..] = [];
        build_frame_header(d_wire, 16384, 0x00, 0x00, 1);
        d_wire.append(chunk[..]);
        internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d_wire[..], 1000, wire_out);
    }

    // Now send 1 extra byte (65537 > 65536 max slab capacity)
    var overflow_wire: u8[>..] = [];
    build_frame_header(overflow_wire, 1, 0x00, 0x01, 1);
    overflow_wire.push('!');

    wire_out.clear();
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", overflow_wire[..], 1000, wire_out);

    let has_rst, rst_code = scan_for_rst_stream(wire_out[..], 1);
    print("OVERFLOW_RST_EMITTED: ", if has_rst { "YES" } else { "NO" });
    print("OVERFLOW_RST_CODE_CANCEL: ", if rst_code == internal::ERR_CANCEL { "YES" } else { "NO" });
    print("OVERFLOW_SLAB_RECLAIMED: ", if count_in_use_slabs(pipeline.slab_pool) == 0 { "YES" } else { "NO" });
}

fn test_pool_saturation_rejection() {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/saturated", 4);

    var init_wire: u8[>..] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE);
    build_frame_header(init_wire, 0, 0x04, 0x00, 0); // SETTINGS
    var wire_out: u8[>..] = [];
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);

    // Manually exhaust all 16 slab slots in pipeline.slab_pool
    for i in 16 {
        let idx = internal::acquire_spill_slab(pipeline.slab_pool);
        guard idx >= 0 else { break; }
    }
    print("ALL_SLABS_ACQUIRED: ", if count_in_use_slabs(pipeline.slab_pool) == 16 { "YES" } else { "NO" });

    // Stream 1 sends headers
    var dt = internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    internal::encode_hpack_field(dt, h_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, h_block, ":path", "/saturated", internal::HpackIndexing.Incremental, false);

    var h_wire: u8[>..] = [];
    build_frame_header(h_wire, h_block.len as u32, 0x01, 0x04, 1);
    h_wire.append(h_block[..]);
    internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h_wire[..], 1000, wire_out);

    // Stream 1 sends 10,000 bytes (> 8192 inline buffer, but pool is saturated!)
    var chunk: u8[>..] = [];
    for i in 10000 { chunk.push('S'); }
    var d_wire: u8[>..] = [];
    build_frame_header(d_wire, 10000, 0x00, 0x00, 1);
    d_wire.append(chunk[..]);

    wire_out.clear();
    let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", d_wire[..], 1000, wire_out);

    let has_rst, rst_code = scan_for_rst_stream(wire_out[..], 1);
    print("SATURATION_CONN_ALIVE: ", if ok { "YES" } else { "NO" });
    print("SATURATION_RST_EMITTED: ", if has_rst { "YES" } else { "NO" });
    print("SATURATION_RST_REFUSED: ", if rst_code == internal::ERR_REFUSED_STREAM { "YES" } else { "NO" });

    // Clean up acquired slabs
    for i in 16 {
        internal::release_spill_slab(pipeline.slab_pool, i as i32);
    }
}

fn main() {
    test_inline_body_lifecycle();
    test_dynamic_promotion_and_reassembly();
    test_maximum_capacity_overflow();
    test_pool_saturation_rejection();
    print("H2_SPILL_LANE_VERIFIED");
}

// CHECK: INLINE_INGRESS_OK: YES
// CHECK: SLABS_IN_USE_INLINE: 0
// CHECK: PROMOTION_INGRESS_OK: YES
// CHECK: PROMOTION_WINDOW_UPDATE_EMITTED: YES
// CHECK: PROMOTION_WINDOW_UPDATE_CREDIT: 57344
// CHECK: COMPLETION_INGRESS_OK: YES
// CHECK: SLABS_IN_USE_AFTER_DISPATCH: 0
// CHECK: OVERFLOW_RST_EMITTED: YES
// CHECK: OVERFLOW_RST_CODE_CANCEL: YES
// CHECK: OVERFLOW_SLAB_RECLAIMED: YES
// CHECK: ALL_SLABS_ACQUIRED: YES
// CHECK: SATURATION_CONN_ALIVE: YES
// CHECK: SATURATION_RST_EMITTED: YES
// CHECK: SATURATION_RST_REFUSED: YES
// CHECK: H2_SPILL_LANE_VERIFIED
