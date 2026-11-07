// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_grpc_bug_hunter.goose
// Cross-component and RFC edge-case regression suite for gRPC and gRPC-Web.
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn dummy_unary_ok(
    _id:  u16,
    _ctx: wing::GrpcServerContext&,
    _req: const u8[:],
    res:  u8[>..]&,
) -> wing::GrpcStatus {
    res.append("pong");
    return wing::grpc_ok();
}

fn test_f001_protobuf_tag_bounds() {
    // 1. Tag with (tag >> 3) == 0x100000001 (overflows u32 and > PB_MAX_FIELD_NUM):
    // tag = (0x100000001 << 3) | 0 = 0x800000008 -> varint [0x88, 0x80, 0x80, 0x80, 0x80, 0x01]
    let hi_varint: u8[7] = [0x88, 0x80, 0x80, 0x80, 0x80, 0x01, 0x2A];
    let _, ok_v1 = wing::pb_read_varint_field(hi_varint[..], 1);
    assert(!ok_v1);

    let hi_bytes: u8[8] = [0x8A, 0x80, 0x80, 0x80, 0x80, 0x01, 0x01, 'x'];
    let _, ok_b1 = wing::pb_read_bytes_field(hi_bytes[..], 1);
    assert(!ok_b1);

    // 2. Field number 0 (tag = 0x00, wire_type = 0) before valid field 1:
    let zero_fnum: u8[4] = [0x00, 0x01, 0x08, 0x2A];
    let _, ok_v0 = wing::pb_read_varint_field(zero_fnum[..], 1);
    assert(!ok_v0);

    let zero_fnum_b: u8[5] = [0x00, 0x01, 0x12, 0x01, 'a'];
    let _, ok_b0 = wing::pb_read_bytes_field(zero_fnum_b[..], 1);
    assert(!ok_b0);
    print("F001_PB_TAG_BOUNDS: OK");
}

fn test_f002_grpc_web_trailer_injection() {
    var ctx = wing::GrpcServerContext { .. };
    // Reject CRLF in metadata/trailer value and reserved keys
    assert(!wing::add_response_trailer(ctx, "x-custom", "val\r\ngrpc-status: 0"));
    assert(!wing::add_response_trailer(ctx, "grpc-status", "0"));
    assert(!wing::add_response_trailer(ctx, "grpc-message", "spoof"));
    assert(!wing::add_response_metadata(ctx, "content-type", "text/plain"));
    assert(!wing::add_response_metadata(ctx, "", "empty-key"));

    // Direct encode_grpc_web_trailers_with_meta defense against spoofed extra_trailers
    var spoofed: wing::GrpcMetadata[..16] = [];
    var e1 = wing::GrpcMetadata { .. };
    let _ = e1.key.try_set("grpc-status");
    let _ = e1.value.try_set("0");
    spoofed.push(e1);
    var e2 = wing::GrpcMetadata { .. };
    let _ = e2.key.try_set("x-inj");
    let _ = e2.value.try_set("v\r\ngrpc-status: 0");
    spoofed.push(e2);

    var frame: u8[>..] = [];
    wing::encode_grpc_web_trailers_with_meta(
        wing::GrpcStatusCode.PermissionDenied,
        "denied",
        spoofed[..],
        frame,
    );
    var payload: u8[>..] = [];
    var is_tr = false;
    var is_comp = false;
    let ok_dec, _ = wing::decode_grpc_web_frame(frame[..], 0, payload, is_tr, is_comp);
    assert(ok_dec && is_tr);
    var st = wing::GrpcStatusCode.Ok;
    var msg: u8[..256] = [];
    assert(wing::parse_grpc_web_trailers(payload[..], st, msg));
    assert(st == wing::GrpcStatusCode.PermissionDenied);
    print("F002_TRAILER_INJECTION: OK");
}

fn test_f003_grpc_web_text_multi_chunk() {
    // Frame 1: 5-byte empty LPM [0,0,0,0,0] -> Base64 "AAAAAAA="
    // Frame 2: Trailer frame for grpc-status: 0\r\n -> Base64
    var f1: u8[>..] = [];
    wing::encode_grpc_lpm("", f1, false);
    var b64_1: u8[>..] = [];
    wing::encode_grpc_web_text(f1[..], b64_1);

    var f2: u8[>..] = [];
    wing::encode_grpc_web_trailers(wing::GrpcStatusCode.Ok, "done", f2);
    var b64_2: u8[>..] = [];
    wing::encode_grpc_web_text(f2[..], b64_2);

    var stream_b64: u8[>..] = [];
    stream_b64.append(b64_1[..]);
    stream_b64.append(b64_2[..]);

    var decoded: u8[>..] = [];
    assert(wing::decode_grpc_web_text(stream_b64[..], decoded));
    assert(decoded.len == f1.len + f2.len);

    // Mid-quantum invalid padding must still be rejected
    var bad_out: u8[>..] = [];
    assert(!wing::decode_grpc_web_text("AA=A", bad_out));
    assert(!wing::decode_grpc_web_text("=A==", bad_out));
    print("F003_WEB_TEXT_MULTICHUNK: OK");
}

fn test_f004_bounded_buffers_and_stream_parser() {
    // 1. decode_grpc_message into u8[..64] with 100-byte input must not overflow cap 64
    var long_in:   u8[100]  = ['z'; 100];
    var small_out: u8[..64] = [];
    wing::decode_grpc_message(long_in[..], small_out);
    assert(small_out.len == 64);

    // 2. encode_grpc_message with default max_out_len (-1) into u8[..64] with 40 '%' bytes
    var pct_in:    u8[40]   = ['%'; 40];
    var small_enc: u8[..64] = [];
    wing::encode_grpc_message(pct_in[..], small_enc);
    assert(small_enc.len <= 64);

    // 3. decode_grpc_lpm into u8[..8] with 16-byte payload must fail cleanly without abort
    var lpm_16: u8[>..] = [];
    wing::encode_grpc_lpm("0123456789abcdef", lpm_16, false);
    var tiny_payload: u8[..8] = [];
    var is_comp = true;
    let ok_lpm, consumed = wing::decode_grpc_lpm(lpm_16[..], 0, tiny_payload, is_comp);
    assert(!ok_lpm && consumed == 0 && is_comp);

    // 4. GrpcStreamParser with max_size = 10 must accept a 10-byte payload (15 wire bytes)
    var parser = wing::new_grpc_stream_parser(10);
    var lpm_10: u8[>..] = [];
    wing::encode_grpc_lpm("0123456789", lpm_10, false);
    assert(wing::feed(parser, lpm_10[..]));
    var msg_out: u8[..16] = [];
    var msg_comp = false;
    assert(wing::next_message(parser, msg_out, msg_comp));
    assert(msg_out[..] == "0123456789");
    print("F004_BOUNDED_BUFFERS: OK");
}

fn test_f005_timeout_encoding_and_zero_deadline() {
    // 1. encode_grpc_timeout with 100_000_500 ms (>= 10^8, not divisible by 1000)
    // must emit <= 8 digits so parse_grpc_timeout accepts it.
    var to_buf: u8[..32] = [];
    wing::encode_grpc_timeout(100000500, to_buf);
    let parsed_ns, ok_to = wing::parse_grpc_timeout(to_buf[..]);
    assert(ok_to && parsed_ns > 0);

    // 2. grpc-timeout: 0S must immediately expire in dispatch_grpc_unary
    var d = wing::new_grpc_server_dispatcher();
    assert(wing::register_unary(d, "test.Svc", "Call", 1));
    var req = wing::new_request("POST", "/test.Svc/Call");
    wing::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    wing::set_header(req, "grpc-timeout", "0S");
    wing::encode_grpc_lpm("hi", req.body, false);
    var res = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(d, req, 5000000, res, dummy_unary_ok));
    assert(wing::header(res, rfc::HEADER_GRPC_STATUS) == "4");
    print("F005_TIMEOUT_AND_ZERO_DEADLINE: OK");
}

fn test_f006_status_and_client_parsers() {
    // 1. Non-200 HTTP status (503) with grpc-status: 0 must map to Unavailable, not Ok
    var hdrs = wing::HeaderMap { .. };
    hdrs.status_code = 503;
    let _ = wing::append_header(hdrs, rfc::HEADER_GRPC_STATUS, "0");
    var trs = wing::HeaderMap { .. };
    var msg: u8[..256] = [];
    var st_503 = wing::GrpcStatusCode.Ok;
    let _ = wing::extract_grpc_status(hdrs, trs, st_503, msg);
    assert(st_503 == wing::GrpcStatusCode.Unavailable);

    // 2. HTTP/2 :status pseudo-header ("503") when hdrs.status_code is left at default 200
    var hdrs2 = wing::HeaderMap { .. };
    let _ = wing::append_header(hdrs2, ":status", "503");
    var st_pseudo = wing::GrpcStatusCode.Ok;
    let _ = wing::extract_grpc_status(hdrs2, trs, st_pseudo, msg);
    assert(st_pseudo == wing::GrpcStatusCode.Unavailable);

    // 3. process_grpc_web_response must reject invalid Base64 and truncated frames
    var resp = wing::GrpcResponse { .. };
    assert(!wing::process_grpc_web_response("!!!not_base64!!!", rfc::GRPC_WEB_TEXT_CONTENT_TYPE, resp));
    assert(!wing::process_grpc_web_response("\x00\x00\x00\x00\x05hi", rfc::GRPC_WEB_CONTENT_TYPE, resp));

    // 4. process_grpc_web_response with trailer frame missing grpc-status must set Unknown
    var tr_no_status: u8[>..] = [];
    tr_no_status.push(rfc::GRPC_WEB_FLAG_TRAILERS);
    let raw_tr = "grpc-message: oops\r\n";
    let tr_len = raw_tr.len as u32;
    tr_no_status.push(((tr_len >> 24) & 0xFF) as u8);
    tr_no_status.push(((tr_len >> 16) & 0xFF) as u8);
    tr_no_status.push(((tr_len >> 8) & 0xFF) as u8);
    tr_no_status.push((tr_len & 0xFF) as u8);
    tr_no_status.append(raw_tr);
    var resp_no_st = wing::GrpcResponse { .. };
    let _ = wing::process_grpc_web_response(tr_no_status[..], rfc::GRPC_WEB_CONTENT_TYPE, resp_no_st);
    assert(resp_no_st.status == wing::GrpcStatusCode.Unknown);
    print("F006_CLIENT_AND_STATUS: OK");
}

fn test_f007_server_dispatch_and_encoding() {
    var d = wing::new_grpc_server_dispatcher();
    assert(wing::register_unary(d, "test.Svc", "Call", 1));

    // 1. Compressed LPM (flag=1) with identity/missing grpc-encoding must be rejected (Internal=13)
    var req_comp = wing::new_request("POST", "/test.Svc/Call");
    wing::set_header(req_comp, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    req_comp.body.push(rfc::GRPC_FLAG_COMPRESSED);
    req_comp.body.append("\x00\x00\x00\x00");
    var res_comp = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(d, req_comp, 1000, res_comp, dummy_unary_ok));
    assert(wing::header(res_comp, rfc::HEADER_GRPC_STATUS) == "13");

    // 2. Unsupported grpc-encoding ("snappy") even with uncompressed LPM must return Unimplemented (12)
    // and include grpc-accept-encoding header
    var req_enc = wing::new_request("POST", "/test.Svc/Call");
    wing::set_header(req_enc, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    wing::set_header(req_enc, "grpc-encoding", "snappy");
    wing::encode_grpc_lpm("hi", req_enc.body, false);
    var res_enc = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(d, req_enc, 1000, res_enc, dummy_unary_ok));
    assert(wing::header(res_enc, rfc::HEADER_GRPC_STATUS) == "12");
    assert(wing::header(res_enc, rfc::HEADER_GRPC_ACCEPT_ENCODING).len > 0);

    // 3. parse_grpc_path rejects extra slash or query string in method name
    var svc: u8[..64] = [];
    var mth: u8[..64] = [];
    assert(!wing::parse_grpc_path("/test.Svc/Call/Extra", svc, mth));
    assert(!wing::parse_grpc_path("/test.Svc/Call?foo=1", svc, mth));

    // 4. handle_grpc_h2_control_frame rejects SETTINGS on non-zero stream_id
    let bad_hdr = wire::WireFrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  1,
    };
    assert(!wing::handle_grpc_h2_control_frame(-1, bad_hdr, ""));
    print("F007_SERVER_DISPATCH: OK");
}

fn main() {
    test_f001_protobuf_tag_bounds();
    test_f002_grpc_web_trailer_injection();
    test_f003_grpc_web_text_multi_chunk();
    test_f004_bounded_buffers_and_stream_parser();
    test_f005_timeout_encoding_and_zero_deadline();
    test_f006_status_and_client_parsers();
    test_f007_server_dispatch_and_encoding();
}

// CHECK: F001_PB_TAG_BOUNDS: OK
// CHECK: F002_TRAILER_INJECTION: OK
// CHECK: F003_WEB_TEXT_MULTICHUNK: OK
// CHECK: F004_BOUNDED_BUFFERS: OK
// CHECK: F005_TIMEOUT_AND_ZERO_DEADLINE: OK
// CHECK: F006_CLIENT_AND_STATUS: OK
// CHECK: F007_SERVER_DISPATCH: OK
