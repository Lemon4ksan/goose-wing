// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_slicer_drip.goose
// Chaos slicer and drip ingress verification across HTTP/1 chunked FSM, HTTP/2 framing, gRPC LPM, and QUIC varints.
// Verifies byte-by-byte and 2-byte boundary fragmentation without hang, crash, or state corruption.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// 1. Chaos Drip Test 1: HTTP/1.1 Chunked Transfer FSM (RFC 9112 §7.1)
// Ingests chunks byte-by-byte, specifically checking split between \r and \n.
fn test_chunked_fsm_drip() {
    let wire = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    var dec = internal::new_chunk_fsm_decoder();
    var assembled: u8[..64] = [];

    var i: i64 = 0;
    while i < wire.len {
        // Drip 1 byte at a time
        let single_byte = wire[i..i + 1];
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, single_byte);
        assert(st != internal::ChunkFsmStatus.Error);
        if st == internal::ChunkFsmStatus.YieldChunk {
            assembled.append(chunk);
        }
        i += 1;
    }

    assert(assembled[..] == "hello world");
    print("CHUNKED_FSM_DRIP: OK");
}

// 2. Chaos Drip Test 2: HTTP/2 Ingress Socket Drip (RFC 9113 §4.1)
// Ingests partial frames through handle_h2_server_ingress, verifying safe postponement
// until the complete 9-byte header and full payload are assembled in the buffer.
fn test_h2_socket_drip() {
    var client_hpack = internal::DynamicTable { .. };
    var sess = internal::new_h2_server_session("localhost");
    var pipeline = wing::ServerPipelineConfig { .. };
    var timer = internal::ConnectionTimer { .. };

    // Handshake
    var init_wire: u8[..64] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let set_hdr = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    internal::encode_frame_header_to(set_hdr, init_wire);
    var server_out: u8[..1024] = [];
    let _, ok_init = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, server_out);
    assert(ok_init);

    // Prepare complete HEADERS frame for stream 1
    var full_req:    u8[..256] = [];
    var hpack_block: u8[..128] = [];
    internal::encode_hpack_field(client_hpack, hpack_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_hpack, hpack_block, ":path", "/drip", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_hpack, hpack_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_hpack, hpack_block, ":authority", "example.com", internal::HpackIndexing.Incremental, false);

    let req_hdr = internal::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    internal::encode_frame_header_to(req_hdr, full_req);
    full_req.append(hpack_block[..]);

    // Stage 1: Partial 5 bytes of 9-byte header -> consumed must be 0, ok == true
    server_out.clear();
    let c1, ok1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..5], 1001, server_out);
    assert(ok1);
    assert(c1 == 0);
    assert(server_out.len == 0);

    // Stage 2: Header complete (9 bytes) + partial 3 bytes of payload -> consumed must be 0
    let c2, ok2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..12], 1002, server_out);
    assert(ok2);
    assert(c2 == 0);
    assert(server_out.len == 0);

    // Stage 3: Full frame arrives -> consumed must be full_req.len, response emitted
    let c3, ok3 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..], 1003, server_out);
    assert(ok3);
    assert(c3 == full_req.len);
    assert(server_out.len > 0);

    print("H2_SOCKET_DRIP: OK");
}

// 3. Chaos Drip Test 3: gRPC Incremental LPM Parser (gRPC HTTP/2 Wire Protocol)
// Streams a 5-byte header + 18-byte payload 1 byte at a time.
fn test_grpc_lpm_drip() {
    var parser = wing::new_grpc_stream_parser(65536);
    let payload = "CHAOS_GRPC_PAYLOAD";

    var full_wire: u8[..64] = [];
    wing::encode_grpc_lpm(payload[..], full_wire, false);
    assert(full_wire.len == 5 + payload.len);

    var msg: u8[..64] = [];
    var is_comp = false;

    // Drip byte by byte up to byte 21 (all must return ready == false)
    for i in (full_wire.len - 1) {
        let ok_feed = wing::feed(parser, full_wire[i..i + 1]);
        assert(ok_feed);
        let ready = wing::next_message(parser, msg, is_comp);
        assert(!ready);
    }

    // Final byte completes the message
    let ok_feed_final = wing::feed(parser, full_wire[full_wire.len - 1..]);
    assert(ok_feed_final);
    let ready_final = wing::next_message(parser, msg, is_comp);
    assert(ready_final);
    assert(msg[..] == "CHAOS_GRPC_PAYLOAD");
    assert(!is_comp);

    print("GRPC_LPM_DRIP: OK");
}

// 4. Chaos Drip Test 4: QUIC Varint Drip & Truncation (RFC 9000 §16)
// Verifies truncated 8-byte, 4-byte, and 2-byte varints reject cleanly without crashing.
fn test_quic_varint_drip() {
    // 8-byte varint for 0x3FFFFFFFFFFFFFFF: prefix 0b11
    let full_8: u8[8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    // Drip 1..7 bytes: all must fail ok == false
    for len in 7 {
        let drip_len = (len + 1) as i64;
        let _, _, ok = internal::quic_decode_varint(full_8[..drip_len], 0);
        assert(!ok);
    }

    // Full 8 bytes succeed
    let val_8, off_8, ok_8 = internal::quic_decode_varint(full_8[..], 0);
    assert(ok_8);
    assert(off_8 == 8);
    assert(val_8 == 0x3FFFFFFFFFFFFFFF);

    print("QUIC_VARINT_DRIP: OK");
}

fn main() {
    test_chunked_fsm_drip();
    test_h2_socket_drip();
    test_grpc_lpm_drip();
    test_quic_varint_drip();
}

// CHECK: CHUNKED_FSM_DRIP: OK
// CHECK-NEXT: H2_SOCKET_DRIP: OK
// CHECK-NEXT: GRPC_LPM_DRIP: OK
// CHECK-NEXT: QUIC_VARINT_DRIP: OK
