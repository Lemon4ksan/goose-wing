// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_wire_api.goose
// Verification of Vulkan-style zero-allocation wire command buffer recording,
// back-patching, and frame stream demuxing via wing::wire.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    print("=== WIRE_VULKAN_API_VERIFICATION ===");

    // 1. Storage and Command Buffer Initialization
    var cmd = wire::new_command_buffer();

    assert(cmd.buf.len == 0);
    assert(wire::available(cmd) == wire::WIRE_CMD_BUFFER_CAP);
    assert(!cmd.has_error);
    print("CMD_INIT: OK");

    // 2. Client Preface
    assert(wire::write_h2_preface(cmd));
    assert(cmd.buf.len == 24);
    print("CMD_PREFACE: OK");

    // 3. SETTINGS Frame (Stream 0)
    let s_list: wire::WireSetting[2] = [
        wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 0),
        wire::h2_setting(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 65535),
    ];
    assert(wire::write_h2_settings(cmd, s_list[..]));
    print("CMD_SETTINGS: OK");

    // 4. WINDOW_UPDATE Frame (Stream 0)
    assert(wire::write_h2_window_update(cmd, 0, 1048576));
    print("CMD_WINDOW_UPDATE: OK");

    // 5. Dynamic HEADERS Frame with HPACK Back-Patching
    assert(wire::begin_h2_headers(cmd, 1, rfc::H2_FLAG_END_HEADERS));
    assert(wire::hpack_indexed(cmd, 2)); // :method: GET
    assert(wire::hpack_indexed(cmd, 7)); // :scheme: https
    assert(wire::hpack_literal_without_indexing(cmd, ":path", "/healthz"));
    assert(wire::hpack_literal_never_indexed(cmd, "x-api-key", "secret-test-token"));
    assert(wire::end_h2_headers(cmd));
    print("CMD_HEADERS_DYNAMIC: OK");

    // 6. RST_STREAM, PING, and DATA Frames
    assert(wire::write_h2_rst_stream(cmd, 3, 8)); // Cancel stream 3
    let ping_data: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    assert(wire::write_h2_ping(cmd, ping_data, false));

    let payload = "hello wire world";
    assert(wire::write_h2_data(cmd, 1, payload, true));
    print("CMD_DATA: OK");

    // 7. Verify Frame Stream Demux with WireH2FrameReader
    let wire_data = cmd.buf[..];
    assert(wire_data.len > 24);

    let frames_data = wire_data[24..];
    var reader = wire::new_wire_h2_frame_reader(frames_data);

    // Frame 1: SETTINGS
    assert(wire::has_next(reader));
    let f1, p1, ok1 = wire::next_frame(reader);
    assert(ok1 && f1.frame_type == rfc::H2_FRAME_SETTINGS && f1.length == 12 && p1.len == 12);

    // Frame 2: WINDOW_UPDATE
    assert(wire::has_next(reader));
    let f2, p2, ok2 = wire::next_frame(reader);
    assert(ok2 && f2.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && f2.length == 4 && p2.len == 4);

    // Frame 3: HEADERS
    assert(wire::has_next(reader));
    let f3, p3, ok3 = wire::next_frame(reader);
    assert(ok3 && f3.frame_type == rfc::H2_FRAME_HEADERS && f3.stream_id == 1 && f3.flags == rfc::H2_FLAG_END_HEADERS);
    assert(p3.len == (f3.length as i64));

    // Frame 4: RST_STREAM
    assert(wire::has_next(reader));
    let f4, p4, ok4 = wire::next_frame(reader);
    assert(ok4 && f4.frame_type == rfc::H2_FRAME_RST_STREAM && f4.stream_id == 3 && f4.length == 4);

    // Frame 5: PING
    assert(wire::has_next(reader));
    let f5, p5, ok5 = wire::next_frame(reader);
    assert(ok5 && f5.frame_type == rfc::H2_FRAME_PING && f5.length == 8 && p5.len == 8);

    // Frame 6: DATA
    assert(wire::has_next(reader));
    let f6, p6, ok6 = wire::next_frame(reader);
    assert(ok6 && f6.frame_type == rfc::H2_FRAME_DATA && f6.stream_id == 1 && f6.flags == rfc::H2_FLAG_END_STREAM);
    assert(p6 == payload);

    // No further frames
    assert(!wire::has_next(reader));
    print("STREAM_DEMUX_VERIFIED: OK");

    // 8. Direct Frame Encoders Verification
    var direct_buf: u8[..512] = [];
    assert(wire::encode_settings_frame(s_list[..], direct_buf));
    assert(wire::encode_window_update_frame(0, 4096, direct_buf));
    assert(wire::encode_priority_update_frame(1, 2, true, direct_buf));
    assert(wire::encode_rst_stream_frame(1, 1, direct_buf));
    assert(wire::encode_ping_frame(ping_data, true, direct_buf));
    assert(wire::encode_data_frame(1, "test", false, direct_buf));
    assert(direct_buf.len > 0);

    var custom_cmd = wire::new_command_buffer();
    let custom_hdr = wire::WireFrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_PING,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    assert(wire::write_h2_frame_header(custom_cmd, custom_hdr));
    assert(custom_cmd.buf.len == 9);
    print("DIRECT_ENCODERS: OK");

    // 9. Direct HPACK Encoders and String Decoder Verification
    var hpack_raw: u8[..256] = [];
    assert(wire::hpack_encode_indexed(hpack_raw, 2));
    assert(wire::hpack_encode_literal_without_indexing(hpack_raw, "custom-header", "custom-val"));
    assert(wire::hpack_encode_literal_never_indexed(hpack_raw, "secret", "dont-index"));
    assert(hpack_raw.len > 0);

    var dec_offset: u64      = 0;
    var str_sample: u8[..64] = [];
    assert(wire::hpack_encode_string(str_sample, "decoded_target"));
    var dec_out: u8[..64] = [];
    assert(wire::hpack_decode_string(str_sample[..], dec_offset, dec_out));
    assert(dec_out == "decoded_target");
    print("HPACK_CODECS: OK");

    // 10. WireQueue Lifecycle and Invariants
    let dev_cfg = wire::WireDeviceConfig { .. };
    var queue = wire::new_wire_queue(dev_cfg);
    assert(!queue.is_connected);
    assert(queue.bytes_sent == 0);

    // Unconnected queue rejects submission safely
    let _, sub_slice_ok = wire::submit_slice(queue, "dummy");
    assert(!sub_slice_ok);

    var rx_dummy: u8[16] = [0; 16];
    let _, poll_ok = wire::poll_recv(queue, rx_dummy[..]);
    assert(!poll_ok);

    let connect_ok = wire::connect_wire_queue(queue, "127.0.0.1", 1, 10);
    assert(!connect_ok || queue.is_connected);
    wire::close_wire_queue(queue);
    assert(!queue.is_connected);
    print("QUEUE_LIFECYCLE: OK");

    // 11. Capacity Overflow Safety Guard Test
    var of_cmd = wire::new_command_buffer();
    var chunk: u8[1024] = [0; 1024];
    for i in 0..16 {
        assert(wire::write_raw(of_cmd, chunk[..]));
    }
    assert(of_cmd.buf.len == wire::WIRE_CMD_BUFFER_CAP);
    // Writing beyond capacity triggers guard
    assert(!wire::write_u8(of_cmd, 0xFF));
    assert(of_cmd.has_error);
    print("OVERFLOW_GUARD_TRIGGERED: OK");
}

// CHECK: === WIRE_VULKAN_API_VERIFICATION ===
// CHECK: CMD_INIT: OK
// CHECK: CMD_PREFACE: OK
// CHECK: CMD_SETTINGS: OK
// CHECK: CMD_WINDOW_UPDATE: OK
// CHECK: CMD_HEADERS_DYNAMIC: OK
// CHECK: CMD_DATA: OK
// CHECK: STREAM_DEMUX_VERIFIED: OK
// CHECK: DIRECT_ENCODERS: OK
// CHECK: HPACK_CODECS: OK
// CHECK: QUEUE_LIFECYCLE: OK
// CHECK: OVERFLOW_GUARD_TRIGGERED: OK
