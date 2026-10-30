// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_capacity_lifecycle.goose
// Verifies 2x capacity lifecycle and slot reclamation invariants across HTTP/2, HTTP/3, and QUIC.
// Ensures bounded arrays [..N] handle at least 2*N sequential streams without slot exhaustion.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn encode_client_h2_request<B>(
    dt: internal::DynamicTable&,
    stream_id: u32,
    method: const u8[:],
    path: const u8[:],
    scheme: const u8[:],
    authority: const u8[:],
    out: B&,
) {
    var hpack_block: u8[..512] = [];
    internal::encode_hpack_field(dt, hpack_block, ":method", method, true, false);
    internal::encode_hpack_field(dt, hpack_block, ":path", path, true, false);
    internal::encode_hpack_field(dt, hpack_block, ":scheme", scheme, true, false);
    internal::encode_hpack_field(dt, hpack_block, ":authority", authority, true, false);

    let hdr = internal::FrameHeader {
        length: hpack_block.len as u32,
        frame_type: internal::FRAME_HEADERS,
        flags: internal::FLAG_END_HEADERS | internal::FLAG_END_STREAM,
        stream_id: stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(hpack_block[..]);
}

// 1. HTTP/2 2x Capacity Lifecycle:
// Capacity is 16 streams. Sequentially open and close 32 request streams.
fn test_h2_capacity_lifecycle() {
    var client_hpack = internal::DynamicTable { .. };
    var sess = internal::new_h2_server_session("localhost");
    var pipeline = wing::ServerPipelineConfig { .. };
    var timer = internal::ConnectionTimer { .. };

    // Handshake
    var init_wire: u8[..64] = [];
    init_wire.append(internal::H2_CLIENT_PREFACE[..]);
    let set_hdr = internal::FrameHeader {
        length: 0,
        frame_type: internal::FRAME_SETTINGS,
        flags: 0,
        stream_id: 0,
    };
    internal::encode_frame_header_to(set_hdr, init_wire);
    var server_out: u8[..4096] = [];
    let _, ok_init = internal::handle_h2_server_ingress(
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
        let consumed, ok = internal::handle_h2_server_ingress(
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
    let settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size: 65536,
        qpack_blocked_streams: 16,
        enable_connect_protocol: 1,
    };
    var server_conn = internal::new_h3_server_connection(settings);

    // Ingest Control Stream with SETTINGS
    var ctrl_wire: u8[..128] = [];
    internal::quic_encode_varint(ctrl_wire, internal::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(ctrl_wire, settings);
    let err_ctrl = server_conn.handle_stream_data(3, false, ctrl_wire[..], false);
    assert(err_ctrl == internal::H3_ERR_NO_ERROR);

    // QPACK static block: :method GET (0xD1), :scheme https (0xD7), :path / (0xC1)
    let qpack_sec: u8[5] = [0x00, 0x00, 0xD1, 0xD7, 0xC1];
    var req_wire: u8[..64] = [];
    assert(internal::encode_h3_frame_header(req_wire, internal::H3_FRAME_HEADERS, qpack_sec.len as u64));
    req_wire.append(qpack_sec[..]);

    let body = "PING";
    var data_wire: u8[..64] = [];
    assert(internal::encode_h3_frame_header(data_wire, internal::H3_FRAME_DATA, body.len as u64));
    data_wire.append(body);

    for i in 64 {
        let stream_id = (i * 4) as u64; // Client bidi request streams: 0, 4, 8, ...
        let err_h = server_conn.handle_stream_data(stream_id, true, req_wire[..], false);
        assert(err_h == internal::H3_ERR_NO_ERROR);

        let err_d = server_conn.handle_stream_data(stream_id, true, data_wire[..], true);
        assert(err_d == internal::H3_ERR_NO_ERROR);

        let s_idx, found = internal::find_h3_stream_idx(server_conn, stream_id);
        assert(found);
        // Mark stream closed on server side to reclaim slot
        server_conn.streams[s_idx].state = internal::H3StreamState.Closed;

        assert(server_conn.streams.len <= 32);
    }

    print("H3_CAPACITY_LIFECYCLE: OK");
}

// 3. QUIC Stream Table 2x Capacity Lifecycle:
// Capacity is 128 streams. Sequentially process 256 streams.
fn test_quic_capacity_lifecycle() {
    var tbl = internal::new_quic_stream_table(internal::QuicRole.Server);
    tbl.max_streams_bidi = 1000;

    for i in 256 {
        let stream_id = (i * 4) as u64; // Peer-initiated Client Bidi streams: 0, 4, 8...
        let idx, ok = internal::quic_table_get_or_open_stream(tbl, stream_id, 65536);
        assert(ok);
        assert(idx >= 0);

        // Transition stream to terminal
        let ok_send, _ = internal::quic_stream_on_send_data(tbl.streams[idx as i64], 0, 10, true);
        assert(ok_send);
        assert(internal::quic_stream_on_send_ack(tbl.streams[idx as i64], true));

        tbl.streams[idx as i64].recv_state = internal::QuicRecvState.DataRead;
        assert(internal::quic_stream_is_terminal(tbl.streams[idx as i64], tbl.role));

        assert(tbl.streams.len <= 128);
    }

    print("QUIC_CAPACITY_LIFECYCLE: OK");
}

fn main() {
    test_h2_capacity_lifecycle();
    test_h3_capacity_lifecycle();
    test_quic_capacity_lifecycle();
}

// CHECK: H2_CAPACITY_LIFECYCLE: OK
// CHECK-NEXT: H3_CAPACITY_LIFECYCLE: OK
// CHECK-NEXT: QUIC_CAPACITY_LIFECYCLE: OK
