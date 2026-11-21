// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
//
// Protocol Smuggler — Cycle 2 Regression Suite
// Verifies fixes for 4 high-impact wire/protocol/parser/FSM bugs across:
//   - PS-C2-01 (grpc/client.goose, grpc/framing.goose, grpc/status.goose)
//   - PS-C2-02 (quic/stream.goose, quic/connection.goose, quic/AckFrame.goose)
//   - PS-C2-03 (http/sfv.goose, http/bhttp.goose, http/headers.goose)
//   - PS-C2-04 (core/url/path.goose, core/url/parser.goose)

import std;
import core from "../..";
import wing from "../..";

// ---------------------------------------------------------------------------
// PS-C2-01: gRPC-Web Trailer/Data Frame Smuggling, Bounded LPM Truncation,
//           & 64-bit google.rpc.Status.code Truncation
// ---------------------------------------------------------------------------
fn test_ps_c2_01_grpc_smuggling_and_truncation() {
    var hdrs = wing::HeaderMap { .. };
    let _ = wing::append_header(hdrs, "content-type", rfc::GRPC_WEB_CONTENT_TYPE_PROTO);
    var trls = wing::HeaderMap { .. };

    // 1a. Smuggled Data frame (0x00) AFTER a Trailer frame (0x80) must be rejected
    var smuggled_after_trailer: u8[>..] = [];
    grpc::encode_web_trailers(grpc::StatusCode.PermissionDenied, "denied", smuggled_after_trailer);
    grpc::encode_lpm("smuggled", smuggled_after_trailer, false);

    var resp1 = grpc::Response { .. };
    assert(!grpc::parse_unary_response(hdrs, trls, smuggled_after_trailer[..], true, resp1));
    assert(resp1.payload.len == 0);
    assert(!grpc::process_web_response(smuggled_after_trailer[..], rfc::GRPC_WEB_CONTENT_TYPE, resp1));

    // 1b. Duplicate Trailer frame (0x80) overwriting earlier error status with Ok must be rejected
    var dup_trailers: u8[>..] = [];
    grpc::encode_lpm("ok", dup_trailers, false);
    grpc::encode_web_trailers(grpc::StatusCode.PermissionDenied, "denied", dup_trailers);
    grpc::encode_web_trailers(grpc::StatusCode.Ok, "bypassed", dup_trailers);

    var resp2 = grpc::Response { .. };
    assert(!grpc::parse_unary_response(hdrs, trls, dup_trailers[..], true, resp2));
    assert(resp2.payload.len == 0);
    assert(!grpc::process_web_response(dup_trailers[..], rfc::GRPC_WEB_CONTENT_TYPE, resp2));

    // 1c. Multiple Data frames (0x00) in a unary gRPC-Web response must be rejected
    var multi_data: u8[>..] = [];
    grpc::encode_lpm("msg1", multi_data, false);
    grpc::encode_lpm("msg2", multi_data, false);
    grpc::encode_web_trailers(grpc::StatusCode.Ok, "", multi_data);

    var resp3 = grpc::Response { .. };
    assert(!grpc::parse_unary_response(hdrs, trls, multi_data[..], true, resp3));
    assert(resp3.payload.len == 0);
    assert(!grpc::process_web_response(multi_data[..], rfc::GRPC_WEB_CONTENT_TYPE, resp3));

    // 1d. Truncated gRPC-Web unary body (Data frame with no Trailer frame and no HTTP grpc-status) must fail
    var no_trailer_body: u8[>..] = [];
    grpc::encode_lpm("truncated_stream", no_trailer_body, false);
    var resp4 = grpc::Response { .. };
    assert(!grpc::parse_unary_response(hdrs, trls, no_trailer_body[..], true, resp4));
    assert(resp4.payload.len == 0);

    // 1e. Native gRPC unary response with trailing garbage after LPM frame must clear out_resp.payload on failure
    var native_hdrs = wing::HeaderMap { .. };
    let _ = wing::append_header(native_hdrs, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    let _ = wing::append_header(native_hdrs, "grpc-status", "0");
    var body_with_extra: u8[>..] = [];
    grpc::encode_lpm("valid_msg", body_with_extra, false);
    body_with_extra.push(0xAA);
    var resp5 = grpc::Response { .. };
    assert(!grpc::parse_unary_response(native_hdrs, trls, body_with_extra[..], false, resp5));
    assert(resp5.payload.len == 0);

    // 1f. Bounded encode_grpc_lpm and encode_grpc_web_trailers must roll back 5-byte header if payload overflows cap
    var tiny_out: u8[..8] = [];
    grpc::encode_lpm("123456", tiny_out, false);
    assert(tiny_out.len == 0);
    grpc::encode_web_trailers(grpc::StatusCode.Ok, "ok", tiny_out);
    assert(tiny_out.len == 0);

    // 1g. Duplicate/conflicting grpc-status lines in gRPC-Web trailers must be rejected
    var st_dup = grpc::StatusCode.Ok;
    var msg_dup: u8[..256] = [];
    assert(!grpc::parse_web_trailers("grpc-status: 7\r\ngrpc-status: 0\r\n", st_dup, msg_dup));
    assert(st_dup == grpc::StatusCode.Unknown);

    // 1h. 64-bit varint code (0x100000003) in google.rpc.Status must not truncate via `as u32` to 3
    // Field 1 (tag 0x08), varint 0x100000003 = [0x83, 0x80, 0x80, 0x80, 0x10]
    let spoofed_proto: u8[6] = [0x08, 0x83, 0x80, 0x80, 0x80, 0x10];
    var b64_buf: u8[..32] = [];
    core::base64_encode(spoofed_proto[..], b64_buf);
    var st_out = grpc::StatusCode.InvalidArgument;
    var msg_out:     u8[..256]              = [];
    var details_out: grpc::ErrorDetail[..4] = [];
    assert(!grpc::decode_status_details(
        b64_buf[..],
        grpc::StatusCode.InvalidArgument,
        st_out,
        msg_out,
        details_out,
    ));

    print("PS-C2-01: PASS");
}

// ---------------------------------------------------------------------------
// PS-C2-02: QUIC Evicted Closed-Stream Reopen, 1-RTT ImmediateAck/AckFrequency
//           Frame Dispatch, & Bounded Loss Detection Compaction
// ---------------------------------------------------------------------------
fn test_ps_c2_02_quic_stream_and_loss_integrity() {
    // 2a. Evicted closed stream must not be reopened by quic_table_get_or_open_stream (RFC 9000 Section 3.2)
    var tbl = quic::new_stream_table(quic::QuicRole.Server);
    tbl.max_streams_bidi = 300;
    let idx0, ok0 = quic::get_or_open_stream(tbl, 0, 65536);
    assert(ok0 && idx0 == 0);
    // Drive stream 0 (ClientBidi) to terminal state in both directions
    let _, ok_rx = quic::on_recv_stream_frame(tbl.streams[idx0], 0, 0, true);
    assert(ok_rx);
    let _ = quic::on_app_read(tbl.streams[idx0], 0);
    let _, ok_tx = quic::on_send_data(tbl.streams[idx0], 0, 0, true);
    assert(ok_tx);
    assert(quic::on_send_ack(tbl.streams[idx0], true));
    assert(quic::is_terminal(tbl.streams[idx0], quic::QuicRole.Server));

    // Fill remaining 127 slots and trigger eviction of stream 0 on the 129th stream
    var s_idx: u64 = 1;
    while s_idx <= 128 {
        let _, ok_s = quic::get_or_open_stream(tbl, s_idx * 4, 65536);
        assert(ok_s);
        s_idx += 1;
    }
    assert(quic::is_evicted_closed_stream(tbl, 0));
    let _, ok_reopen = quic::get_or_open_stream(tbl, 0, 65536);
    assert(!ok_reopen);

    // 2b. ImmediateAck (0x1f) and AckFrequency (0xaf) must be accepted in 1-RTT and rejected in 0-RTT
    var conn = quic::new_server_connection("server_cid");
    conn.state = quic::QuicConnState.Established;
    let imm_buf: u8[1] = [rfc::QUIC_FRAME_IMMEDIATE_ACK as u8];
    let _pr_ok_1rtt = quic::process_payload(
        conn,
        imm_buf[..],
        quic::QuicHeaderType.OneRtt,
        100000,
    );
    let ok_1rtt = _pr_ok_1rtt.handled;
    let ack_el_1rtt = _pr_ok_1rtt.needs_ack;
    assert(ok_1rtt && ack_el_1rtt);

    var conn_0rtt = quic::new_server_connection("server_cid");
    let _pr_ok_0rtt = quic::process_payload(
        conn_0rtt,
        imm_buf[..],
        quic::QuicHeaderType.ZeroRtt,
        100000,
    );
    let ok_0rtt = _pr_ok_0rtt.handled;
    assert(!ok_0rtt && conn_0rtt.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // 2c. detect_lost_packets must preserve uncollected packets without duplication when out_lost is full
    var space = quic::PnSpaceState {
        has_acked_packets: true,
        largest_acked_pn:  10,
        ..
    };
    // p0 (lost), p1 (not lost, pn=9), p2 (lost), p3 (lost, overflows out_lost[..2])
    space.sent_packets.push(quic::SentPacketMeta { pn: 1, time_sent_us: 1000, size_bytes: 100, .. });
    space.sent_packets.push(quic::SentPacketMeta { pn: 9, time_sent_us: 90000, size_bytes: 100, .. });
    space.sent_packets.push(quic::SentPacketMeta { pn: 2, time_sent_us: 1000, size_bytes: 100, .. });
    space.sent_packets.push(quic::SentPacketMeta { pn: 3, time_sent_us: 1000, size_bytes: 100, .. });

    let rtt = quic::RttState { smoothed_rtt_us: 10000, latest_rtt_us: 10000, .. };
    var out_lost: quic::SentPacketMeta[..2] = [];
    let ok_loss = quic::detect_lost_packets(space, rtt, 95000, out_lost);
    assert(!ok_loss);
    assert(out_lost.len == 2);
    // Remaining in sent_packets must be strictly [pn=9, pn=3] (2 packets, no duplicate pn=9 or already-removed pn=2)
    assert(space.sent_packets.len == 2);
    assert(space.sent_packets[0].pn == 9);
    assert(space.sent_packets[1].pn == 3);

    print("PS-C2-02: PASS");
}

// ---------------------------------------------------------------------------
// PS-C2-03: RFC 8941 SFV Inner-List Parameter Desync, RFC 9292 Binary HTTP
//           Control-Data Smuggling, & HeaderMap Keep-Alive / Obs-Fold Hygiene
// ---------------------------------------------------------------------------
fn test_ps_c2_03_http_sfv_bhttp_headers() {
    // 3a. RFC 8941 inner list with OWS after ';' or spaces/')' inside quoted-string parameter values
    var dict_entries: wing::SfDictEntry[..16] = [];
    let ok_dict = wing::parse_sf_dict("sig=(\"a\"; k=\"x ) y\" \"b\"; p=1);created=100", dict_entries);
    assert(ok_dict && dict_entries.len == 1);
    assert(dict_entries[0].is_inner_list && dict_entries[0].inner_items.len == 2);
    assert(dict_entries[0].inner_items[0].str_val == "a");
    assert(dict_entries[0].inner_items[1].str_val == "b");

    // 3b. RFC 9292 Binary HTTP request must reject CRLF / spaces in method or target path
    // Framing=0x00, method="GET\r\n" (len 5), scheme="https" (len 5), authority="" (0), path="/a" (2), tail=0,0,0
    let bad_bhttp_method: u8[18] = [
        0x00,
        0x05, 'G', 'E', 'T', '\r', '\n',
        0x05, 'h', 't', 't', 'p', 's',
        0x00,
        0x02, '/', 'a',
        0x00,
    ];
    var bhttp_req = wing::BhttpRequest { .. };
    assert(!wing::bhttp_decode_request(bad_bhttp_method[..], bhttp_req));
    assert(bhttp_req.method.len == 0);

    // Framing=0x00, method="GET" (3), scheme="https" (5), authority="" (0), path="/a b\r\n" (6)
    let bad_bhttp_path: u8[19] = [
        0x00,
        0x03, 'G', 'E', 'T',
        0x05, 'h', 't', 't', 'p', 's',
        0x00,
        0x06, '/', 'a', ' ', 'b', '\r', '\n',
    ];
    assert(!wing::bhttp_decode_request(bad_bhttp_path[..], bhttp_req));
    assert(bhttp_req.target.len == 0);

    // 3c. HeaderMap: parse_headers("", map) on reused keep-alive map must clear old headers and set valid = false
    var hmap = wing::HeaderMap { .. };
    let err_ok = wing::parse_headers("Host: example.com\r\n\r\n", hmap);
    assert(err_ok == wing::HeaderParseError.None && hmap.valid && hmap.entries.len == 1);

    let err_empty = wing::parse_headers("", hmap);
    assert(err_empty == wing::HeaderParseError.EmptyInput);
    assert(!hmap.valid && hmap.entries.len == 0);

    let err_trunc_resp = wing::parse_response_headers("HTTP/1.1 200 OK\r\n", hmap);
    assert(err_trunc_resp == wing::HeaderParseError.EmptyInput);
    assert(!hmap.valid);

    // 3d. HeaderMap obs-fold: comma in folded continuation line must set HEADER_FLAG_CONTAINS_COMMA
    var fold_map = wing::HeaderMap { .. };
    let err_fold = wing::parse_headers("X-List: first\r\n , second\r\n\r\n", fold_map, true);
    assert(err_fold == wing::HeaderParseError.None && fold_map.valid);
    assert(fold_map.header_contains_comma[0]);
    assert((fold_map.entries[0].flags & wing::HEADER_FLAG_CONTAINS_COMMA) != 0);

    print("PS-C2-03: PASS");
}

// ---------------------------------------------------------------------------
// PS-C2-04: core/url parse_endpoint Malformed Scheme Fallback & parse_url_view
//           Unencoded Control/Space & file: Port/Userinfo Enforcement
// ---------------------------------------------------------------------------
fn test_ps_c2_04_url_endpoint_and_view() {
    // 4a. parse_endpoint with malformed explicit-scheme URL must fail rather than joining as relative path
    let base = core::new_url("https://api.internal.corp/v1");
    assert(base.valid);

    let bad_ep1, err_ep1 = core::parse_endpoint(base, "https://evil.com:99999/steal");
    assert(!bad_ep1.valid && err_ep1 == core::UrlParseError.InvalidPort);

    let bad_ep2, err_ep2 = core::parse_endpoint(base, "http:///missing-host");
    assert(!bad_ep2.valid && err_ep2 == core::UrlParseError.MissingHost);

    // 4b. parse_url_view must reject unencoded spaces and C0/DEL control bytes in path/userinfo
    let v_space_path, _ = core::parse_url_view("http://example.com/path with space");
    assert(!v_space_path.valid);

    let v_ctl_path, _ = core::parse_url_view("http://example.com/path\x07bell");
    assert(!v_ctl_path.valid);

    let v_space_user, _ = core::parse_url_view("http://bad user@example.com/path");
    assert(!v_space_user.valid);

    // 4c. parse_url_view must reject explicit port and userinfo on file: scheme (matching parse_url / WHATWG)
    let v_file_port, err_fp = core::parse_url_view("file://localhost:8080/etc/passwd");
    assert(!v_file_port.valid && err_fp == core::UrlParseError.InvalidPort);

    let v_file_user, _ = core::parse_url_view("file://root:toor@localhost/etc/passwd");
    assert(!v_file_user.valid);

    print("PS-C2-04: PASS");
}

fn main() {
    test_ps_c2_01_grpc_smuggling_and_truncation();
    // CHECK: PS-C2-01: PASS
    test_ps_c2_02_quic_stream_and_loss_integrity();
    // CHECK: PS-C2-02: PASS
    test_ps_c2_03_http_sfv_bhttp_headers();
    // CHECK: PS-C2-03: PASS
    test_ps_c2_04_url_endpoint_and_view();
    // CHECK: PS-C2-04: PASS
}
