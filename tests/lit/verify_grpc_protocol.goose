// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_grpc_protocol.goose
// Native LIT verification suite for Wave 4 Track B:
// GRPCCLI-01..09 (Connect Protocol Unary GET, EndStream 0x02 Envelope,
// grpc-status-details-bin Any unpacking & code-match, Health Check,
// Compressed-Flag 0x01 validation, grpc-web-text Accept negotiation,
// H2 RST_STREAM mapping, Alt-Svc IPv6 & ALPN %XX, GrpcStreamParser cursor).
//
// RUN: goose check %s
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn idempotent_echo_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> wing::GrpcStatus {
    let _ = handler_id;
    let _ = ctx;
    res_payload.append(req_payload);
    return wing::grpc_ok();
}

fn verify_connect_unary_get() {
    var params = wing::ConnectUnaryGetParams { .. };
    var payload: u8[>..] = [];
    let st = wing::parse_connect_get_query(
        "?connect=v1&encoding=proto&base64=1&message=cGluZw",
        params,
        payload,
    );
    assert(st == wing::GrpcStatusCode.Ok);
    assert(params.has_version);
    assert(params.base64);
    assert(params.encoding[..] == "proto");
    assert(payload[..] == "ping");

    // Server dispatch of idempotent GET vs non-idempotent rejection
    var disp = wing::GrpcServerDispatcher { .. };
    assert(wing::register_unary(
        disp,
        "test.Echo",
        "GetPing",
        1,
        wing::GrpcIdempotency.NoSideEffects,
    ));
    assert(wing::register_unary(
        disp,
        "test.Echo",
        "Mutate",
        2,
    ));
    assert(wing::register_bidi_streaming(disp, "test.Echo", "Chat", 3));
    assert(wing::find_method_by_name(disp, "test.Echo", "Chat") >= 0);

    var req = wing::new_request("GET", "/test.Echo/GetPing?connect=v1&encoding=proto&base64=1&message=cGluZw");
    var res = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(disp, req, 1000, res, 0, idempotent_echo_handler));
    assert(res.status_code == 200);
    assert(res.body[..] == "ping");

    var req_mut = wing::new_request("GET", "/test.Echo/Mutate?connect=v1&encoding=proto&base64=1&message=cGluZw");
    var res_mut = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(disp, req_mut, 1000, res_mut, 0, idempotent_echo_handler));
    assert(res_mut.status_code == 405);
    print("GRPCCLI_01_CONNECT_GET: OK");
}

fn verify_connect_end_stream() {
    var tr = wing::HeaderMap { .. };
    let _ = wing::append_header(tr, "x-custom-meta", "val123");
    var wire: u8[..512] = [];
    assert(wing::encode_connect_end_stream(
        wing::GrpcStatusCode.Unauthenticated,
        "expired token",
        tr,
        wire,
    ));
    assert(wire[0] == wing::CONNECT_FLAG_END_STREAM);
    let json_len = core::read_be_u32(wire[..], 1) as i64;
    let json_end = core::add_sat_i64(5, json_len);
    let json_slice = wire[5..json_end];

    var out_status = wing::GrpcStatusCode.Ok;
    var out_msg: u8[..256] = [];
    var out_tr = wing::HeaderMap { .. };
    assert(wing::parse_connect_end_stream(json_slice, out_status, out_msg, out_tr));
    assert(out_status == wing::GrpcStatusCode.Unauthenticated);
    assert(out_msg[..] == "expired token");
    assert(wing::get_header(out_tr, "x-custom-meta") == "val123");
    print("GRPCCLI_02_CONNECT_END_STREAM: OK");
}

fn verify_grpc_status_details_and_health() {
    // Build a google.rpc.Status with code=3 (InvalidArgument), message="bad field", and 1 Any detail
    var any_pb: u8[..128] = [];
    assert(wing::pb_write_bytes_field(1, "type.googleapis.com/BadRequest", any_pb));
    assert(wing::pb_write_bytes_field(2, "field_x", any_pb));

    var status_pb: u8[..256] = [];
    assert(wing::pb_write_varint_field(1, 3, status_pb));
    assert(wing::pb_write_bytes_field(2, "bad field", status_pb));
    assert(wing::pb_write_bytes_field(3, any_pb[..], status_pb));

    var b64_buf: u8[..512] = [];
    core::base64_encode(status_pb[..], b64_buf);

    var st_code = wing::GrpcStatusCode.Ok;
    var st_msg:  u8[..256]                  = [];
    var details: wing::GrpcErrorDetail[..4] = [];
    assert(wing::decode_grpc_status_details(
        b64_buf[..],
        wing::GrpcStatusCode.InvalidArgument,
        st_code,
        st_msg,
        details,
    ));
    assert(st_code == wing::GrpcStatusCode.InvalidArgument);
    assert(st_msg[..] == "bad field");
    assert(details.len == 1);
    assert(details[0].type_url[..] == "type.googleapis.com/BadRequest");
    assert(details[0].value[..] == "field_x");

    // Code mismatch override -> Internal
    assert(wing::decode_grpc_status_details(
        b64_buf[..],
        wing::GrpcStatusCode.NotFound,
        st_code,
        st_msg,
        details,
    ));
    assert(st_code == wing::GrpcStatusCode.Internal);
    assert(details.len == 0);
    print("GRPCCLI_03_STATUS_DETAILS: OK");

    // Health check protocol (GRPCCLI-04)
    var disp = wing::GrpcServerDispatcher { .. };
    assert(wing::set_grpc_service_health(disp, "my.Service", wing::GrpcServingStatus.Serving));
    var req_pb: u8[..64] = [];
    assert(wing::pb_write_bytes_field(1, "my.Service", req_pb));
    var lpm_req: u8[>..] = [];
    wing::encode_grpc_lpm(req_pb[..], lpm_req, false);

    var h_req = wing::new_request("POST", "/grpc.health.v1.Health/Check");
    wing::set_header(h_req.headers, "content-type", "application/grpc");
    h_req.body.append(lpm_req[..]);
    var h_res = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(disp, h_req, 1000, h_res, 0, idempotent_echo_handler));
    assert(wing::get_header(h_res.trailers, "grpc-status") == "0");
    print("GRPCCLI_04_HEALTH_CHECK: OK");
}

fn verify_compression_webtext_rst_altsvc_and_cursor() {
    // GRPCCLI-05: Compressed flag 0x01 with empty or "identity" encoding -> Internal
    assert(wing::validate_recv_compression(true, "", true) == wing::GrpcStatusCode.Internal);
    assert(wing::validate_recv_compression(true, "identity", false) == wing::GrpcStatusCode.Internal);
    assert(wing::validate_recv_compression(true, "gzip", true) == wing::GrpcStatusCode.Ok);
    assert(wing::validate_recv_compression(true, "br", true) == wing::GrpcStatusCode.Unimplemented);
    print("GRPCCLI_05_COMPRESSION_FLAG: OK");

    // GRPCCLI-06: Accept: application/grpc-web-text negotiation
    var cfg = wing::GrpcCallConfig { is_web_text: true, .. };
    let _ = cfg.service.try_set("pkg.Svc");
    let _ = cfg.method.try_set("Call");
    var hdrs = wing::HeaderMap { .. };
    wing::build_grpc_request_headers(cfg, "example.com", "https", hdrs);
    assert(wing::get_header(hdrs, "accept") == "application/grpc-web-text+proto");
    let ok_res = wing::GrpcResponse { status: wing::GrpcStatusCode.Ok, .. };
    assert(wing::is_grpc_success(ok_res));
    print("GRPCCLI_06_WEB_TEXT_ACCEPT: OK");

    // GRPCCLI-07: H2 RST_STREAM to gRPC status mapping
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_CANCEL) == wing::GrpcStatusCode.Cancelled);
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_ENHANCE_YOUR_CALM) == wing::GrpcStatusCode.ResourceExhausted);
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_INADEQUATE_SECURITY) == wing::GrpcStatusCode.PermissionDenied);
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_REFUSED_STREAM) == wing::GrpcStatusCode.Unavailable);
    print("GRPCCLI_07_RST_STREAM_MAP: OK");

    // GRPCCLI-08: Alt-Svc IPv6 authority & ALPN %XX percent-decoding
    var altsvc_list: wing::AltSvcEndpoint[..4] = [];
    let ok_alt, is_clear = wing::parse_altsvc_header(
        "h3%2D29=\"[2001:db8::1]:443\"; ma=60",
        altsvc_list,
    );
    assert(ok_alt && !is_clear);
    assert(altsvc_list.len == 1);
    assert(altsvc_list[0].proto[..] == "h3-29");
    assert(altsvc_list[0].host[..] == "[2001:db8::1]");
    assert(altsvc_list[0].port == 443);
    print("GRPCCLI_08_ALTSVC_IPV6_ALPN: OK");

    // GRPCCLI-09: GrpcStreamParser read_pos cursor without per-message shift
    var parser = wing::new_grpc_stream_parser(1024);
    var stream_bytes: u8[>..] = [];
    wing::encode_grpc_lpm("msg1", stream_bytes, false);
    wing::encode_grpc_lpm("msg2", stream_bytes, false);
    assert(parser.feed(stream_bytes[..]));
    var out1: u8[>..] = [];
    var comp1 = false;
    assert(wing::next_message(parser, out1, comp1));
    assert(out1[..] == "msg1");
    assert(parser.read_pos == 9);
    var out2: u8[>..] = [];
    var comp2 = false;
    assert(wing::next_message(parser, out2, comp2));
    assert(out2[..] == "msg2");
    assert(parser.read_pos == 0);
    print("GRPCCLI_09_PARSER_READ_POS: OK");
}

fn main() {
    verify_connect_unary_get();
    verify_connect_end_stream();
    verify_grpc_status_details_and_health();
    verify_compression_webtext_rst_altsvc_and_cursor();
}

// CHECK: GRPCCLI_01_CONNECT_GET: OK
// CHECK: GRPCCLI_02_CONNECT_END_STREAM: OK
// CHECK: GRPCCLI_03_STATUS_DETAILS: OK
// CHECK: GRPCCLI_04_HEALTH_CHECK: OK
// CHECK: GRPCCLI_05_COMPRESSION_FLAG: OK
// CHECK: GRPCCLI_06_WEB_TEXT_ACCEPT: OK
// CHECK: GRPCCLI_07_RST_STREAM_MAP: OK
// CHECK: GRPCCLI_08_ALTSVC_IPV6_ALPN: OK
// CHECK: GRPCCLI_09_PARSER_READ_POS: OK
