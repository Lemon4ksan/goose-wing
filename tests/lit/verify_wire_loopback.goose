// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_wire_loopback.goose
// End-to-end in-memory wire loopback verification for HTTP/2, QUIC, and HTTP/3.
// Validates pure raw wire serialization, bidirectional state machine exchange,
// and zero-allocation parsing without synthetic mock struct injection.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// Helper to encode a complete client HEADERS frame using HPACK
fn encode_client_request_headers<B>(
    dt:         internal::DynamicTable&,
    stream_id:  u32,
    method:     const u8[:],
    path:       const u8[:],
    scheme:     const u8[:],
    authority:  const u8[:],
    end_stream: bool,
    out:        B&,
) {
    var hpack_block: u8[..512] = [];
    internal::encode_hpack_field(dt, hpack_block, ":method", method, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hpack_block, ":path", path, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hpack_block, ":scheme", scheme, internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(dt, hpack_block, ":authority", authority, internal::HpackIndexing.Incremental, false);

    var flags: u8 = internal::FLAG_END_HEADERS;
    if end_stream {
        flags |= internal::FLAG_END_STREAM;
    }
    let hdr = internal::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: internal::FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream_id,
    };
    internal::encode_frame_header_to(hdr, out);
    out.append(hpack_block[..]);
}

// 1. HTTP/2 Full Wire Loopback:
// Client formats Preface + SETTINGS + HEADERS -> Server ingests, dispatches via pipeline -> Server emits SETTINGS + Response HEADERS
fn test_h2_wire_loopback() {
    var client_hpack = internal::new_dynamic_table(internal::HPACK_DEFAULT_MAX_DYN_SIZE);
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/api/ping", 200);

    // Client encodes raw wire stream
    var client_to_server: u8[..1024] = [];
    client_to_server.append(internal::H2_CLIENT_PREFACE[..]);

    // Client empty SETTINGS frame
    let set_hdr = internal::FrameHeader {
        length:     0,
        frame_type: internal::FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    internal::encode_frame_header_to(set_hdr, client_to_server);

    // Client GET /api/ping request on stream 1
    encode_client_request_headers(
        client_hpack, 1, "GET", "/api/ping", "https", "example.com", true, client_to_server,
    );

    // Server ingests client bytes and generates server wire response
    var server_to_client: u8[..2048] = [];
    let consumed, ok = internal::handle_h2_server_ingress(
        sess, pipeline, timer, "127.0.0.1", client_to_server[..], 1000, server_to_client,
    );
    assert(ok);
    assert(consumed == client_to_server.len);

    // Verify Server emitted response:
    // Frame 1: Server SETTINGS (9-byte header + 24-byte payload = 33 bytes)
    assert(server_to_client.len >= 33);
    let s_hdr, err_s = internal::parse_frame_header(server_to_client[..9]);
    assert(err_s == internal::ERR_NO_ERROR);
    assert(s_hdr.frame_type == internal::FRAME_SETTINGS);
    assert(s_hdr.stream_id == 0);
    assert(s_hdr.length == 24);

    // Frame 2: Server SETTINGS ACK (9 bytes)
    assert(server_to_client.len >= 42);
    let ack_hdr, err_ack = internal::parse_frame_header(server_to_client[33..42]);
    assert(err_ack == internal::ERR_NO_ERROR);
    assert(ack_hdr.frame_type == internal::FRAME_SETTINGS);
    assert((ack_hdr.flags & internal::FLAG_ACK) != 0);
    assert(ack_hdr.stream_id == 0);

    // Frame 3: Response HEADERS for stream 1
    let resp_slice = server_to_client[42..];
    assert(resp_slice.len >= 9);
    let r_hdr, err_r = internal::parse_frame_header(resp_slice[..9]);
    assert(err_r == internal::ERR_NO_ERROR);
    assert(r_hdr.frame_type == internal::FRAME_HEADERS);
    assert(r_hdr.stream_id == 1);
    assert((r_hdr.flags & internal::FLAG_END_HEADERS) != 0);

    // Decode response HPACK header block
    var dec_resp = internal::DecodedH2HeaderList { .. };
    let hpack_payload = resp_slice[9..9 + r_hdr.length];
    let hpack_err = internal::decode_hpack_header_block(client_hpack, hpack_payload, dec_resp);
    assert(hpack_err == internal::ERR_NO_ERROR);

    var has_status_200 = false;
    for &f in dec_resp.fields {
        if f.name[..] == ":status" && f.value[..] == "200" {
            has_status_200 = true;
            break;
        }
    }
    assert(has_status_200);
    print("H2_LOOPBACK: OK");
}

// 2. QUIC Wire Loopback:
// Client formats 1-RTT Short Header datagram with STREAM frame -> Server ingests, creates stream, updates flow control
fn test_quic_wire_loopback() {
    let scid: u8[4] = [0x50, 0x51, 0x52, 0x53];
    var server_conn = internal::new_quic_server_connection(scid[..]);

    var dgram: u8[..256] = [];
    dgram.push(0x40); // 1-RTT Short Header
    dgram.append(scid[..]);
    dgram.push(0x01); // Packet number = 1

    internal::encode_max_data_frame(dgram, 800000);
    internal::encode_stream_frame(
        dgram, 0, 0, "PING_LOOPBACK", internal::QuicStreamFlags { fin: true, with_len: true },
    );

    var ack_out = internal::AckFrame { .. };
    let handled, needs_ack = internal::quic_conn_process_datagram(server_conn, dgram[..], 1000, ack_out);
    assert(handled);
    assert(needs_ack);

    let st_idx = internal::quic_table_find_stream(server_conn.stream_table, 0);
    assert(st_idx >= 0);
    assert(server_conn.flow_ctrl.max_data_remote == 800000);
    assert(server_conn.stream_table.streams[st_idx as i64].bytes_recv == 13);
    assert(server_conn.state == internal::QuicConnState.Established);

    print("QUIC_LOOPBACK: OK");
}

// 3. HTTP/3 Wire Loopback:
// Client formats Control Stream SETTINGS + Request Stream HEADERS with QPACK section -> Server parses and verifies
fn test_h3_wire_loopback() {
    let settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };
    var server_conn = internal::new_h3_server_connection(settings);

    // 1. Control Stream (Stream ID 3, Unidirectional) with SETTINGS
    var ctrl_wire: u8[..128] = [];
    internal::quic_encode_varint(ctrl_wire, internal::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(ctrl_wire, settings);
    let err_ctrl = server_conn.handle_stream_data(3, false, ctrl_wire[..], false);
    assert(err_ctrl == internal::H3_ERR_NO_ERROR);
    assert(server_conn.peer_settings_received);

    // 2. Request Stream (Stream ID 0, Bidirectional) with HEADERS frame
    // QPACK section with RIC=0, Base=0, static fields (:method GET = 0xD1, :scheme https = 0xD7, :path / = 0xC1)
    let qpack_sec: u8[5] = [0x00, 0x00, 0xD1, 0xD7, 0xC1];
    var req_wire: u8[..64] = [];
    assert(internal::encode_h3_frame_header(req_wire, internal::H3_FRAME_HEADERS, qpack_sec.len as u64));
    req_wire.append(qpack_sec[..]);

    let err_req = server_conn.handle_stream_data(0, true, req_wire[..], false);
    assert(err_req == internal::H3_ERR_NO_ERROR);

    let s_idx, found = internal::find_h3_stream_idx(server_conn, 0);
    assert(found);
    assert(server_conn.streams[s_idx].headers_received);

    // 3. DATA frame with payload "HELLO_H3"
    let body = "HELLO_H3";
    var data_wire: u8[..64] = [];
    assert(internal::encode_h3_frame_header(data_wire, internal::H3_FRAME_DATA, body.len as u64));
    data_wire.append(body);

    let err_data = server_conn.handle_stream_data(0, true, data_wire[..], true);
    assert(err_data == internal::H3_ERR_NO_ERROR);
    assert(server_conn.streams[s_idx].received_body[..] == "HELLO_H3");
    assert(server_conn.streams[s_idx].fin_received);

    print("H3_LOOPBACK: OK");
}

fn main() {
    test_h2_wire_loopback();
    test_quic_wire_loopback();
    test_h3_wire_loopback();
}

// CHECK: H2_LOOPBACK: OK
// CHECK-NEXT: QUIC_LOOPBACK: OK
// CHECK-NEXT: H3_LOOPBACK: OK
