// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal gRPC server dispatch, wire framing, and connection loop helpers.
namespace grpc_internal;

import std;
import core;
import rfc.http;
import rfc.h2;
import rfc.grpc;
import wire.types;
import wire.h2;
import http2.hpack;
import http.headers;
import http.request;
import http.response;
import server.server;
import server.pipeline;
import .constants;
import .framing;
import .status;
import .connect;
import .health;
import .internal;
import .server;

inline fn is_request(req: const http::Request&) -> bool {
    let ct = req.header("content-type");
    if ct.len > 0 && grpc::is_content_type(ct) {
        return true;
    }
    return is_connect_get_request(req);
}

inline fn is_valid_path_segment(seg: const u8[:]) -> bool {
    guard seg.len > 0 && seg.len <= 128 else { return false; }
    for b in seg {
        guard b > 0x20 && b < 0x7F && b != '/' && b != '?' && b != '#' else { return false; }
    }
    return true;
}

fn register_method(
    d:           grpc::ServerDispatcher&,
    service:     const u8[:],
    method:      const u8[:],
    method_type: grpc::MethodType,
    handler_id:  u16,
    idempotency: grpc::Idempotency = grpc::Idempotency.Default,
) -> bool {
    var entry = grpc::MethodEntry {
        method_type: method_type,
        idempotency: idempotency,
        handler_id:  handler_id,
        ..
    };
    guard entry.service.try_set(service) && entry.method.try_set(method) else { return false; }

    entry.full_path.push('/');
    entry.full_path.append(service);
    entry.full_path.push('/');
    entry.full_path.append(method);

    return d.methods.try_push(entry);
}

// ---- Wire Response Builders ---------------------------------------------

fn append_metadata_headers(target: http::HeaderMap&, metadata: const grpc::Metadata[:]) {
    for &m in metadata {
        if is_valid_custom_metadata(m.key[..], m.value[..]) {
            let _ = target.append_header(m.key[..], m.value[..]);
        }
    }
}

fn build_trailers_only_response(
    status:  grpc::StatusCode,
    message: const u8[:],
    ctx:     const grpc::ServerContext&,
    res:     http::Response&,
) {
    res.status_code = rfc::STATUS_OK;
    res.headers.clear();
    res.trailers.clear();
    res.body.clear();
    res.presence_mask = 0;

    if ctx.is_web {
        let ct_val = if ctx.res_is_web_text {
            rfc::GRPC_WEB_TEXT_CONTENT_TYPE
        } else {
            rfc::GRPC_WEB_CONTENT_TYPE_PROTO
        };
        let _ = res.headers.append_header("content-type", ct_val);

        append_metadata_headers(res.headers, ctx.response_metadata[..]);

        var raw_trailers: u8[>..] = [];
        grpc::encode_web_trailers_with_meta(status, message, ctx.response_trailers[..], raw_trailers);

        if ctx.res_is_web_text {
            grpc::encode_web_text(raw_trailers[..], res.body);
        } else {
            res.body.append(raw_trailers[..]);
        }
    } else {
        let _ = res.headers.append_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        let _ = res.headers.append_header(rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");

        var st_val: u8[..32] = [];
        let code = grpc::status_to_code(status);
        code.format_u32_dec(st_val);
        let _ = res.headers.append_header(rfc::HEADER_GRPC_STATUS, st_val[..]);

        if message.len > 0 {
            var msg_val: u8[..1024] = [];
            grpc::encode_message(message, msg_val);
            let _ = res.headers.append_header(rfc::HEADER_GRPC_MESSAGE, msg_val[..]);
        }

        append_metadata_headers(res.headers, ctx.response_metadata[..]);
        append_metadata_headers(res.headers, ctx.response_trailers[..]);
    }
}

fn build_wire_response(
    status:       grpc::StatusCode,
    message:      const u8[:],
    raw_lpm_body: const u8[:],
    ctx:          const grpc::ServerContext&,
    res:          http::Response&,
) {
    res.status_code = rfc::STATUS_OK;
    res.headers.clear();
    res.trailers.clear();
    res.body.clear();
    res.presence_mask = 0;

    if ctx.is_web {
        let ct_val = if ctx.res_is_web_text {
            rfc::GRPC_WEB_TEXT_CONTENT_TYPE
        } else {
            rfc::GRPC_WEB_CONTENT_TYPE_PROTO
        };
        let _ = res.headers.append_header("content-type", ct_val);

        append_metadata_headers(res.headers, ctx.response_metadata[..]);

        var web_body: u8[>..] = [];
        web_body.append(raw_lpm_body);
        grpc::encode_web_trailers_with_meta(status, message, ctx.response_trailers[..], web_body);

        if ctx.res_is_web_text {
            grpc::encode_web_text(web_body[..], res.body);
        } else {
            res.body.append(web_body[..]);
        }
    } else {
        let _ = res.headers.append_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        let _ = res.headers.append_header(rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");

        append_metadata_headers(res.headers, ctx.response_metadata[..]);

        res.body.append(raw_lpm_body);

        var st_val: u8[..32] = [];
        let code = grpc::status_to_code(status);
        code.format_u32_dec(st_val);
        let _ = res.trailers.append_header(rfc::HEADER_GRPC_STATUS, st_val[..]);

        if message.len > 0 {
            var msg_val: u8[..1024] = [];
            grpc::encode_message(message, msg_val);
            let _ = res.trailers.append_header(rfc::HEADER_GRPC_MESSAGE, msg_val[..]);
        }

        append_metadata_headers(res.trailers, ctx.response_trailers[..]);
    }
}

// ---- Request Ingress Context Extraction ----------------------------------

inline fn compute_safe_deadline(base_ns: u64, ms: u64) -> u64 {
    guard base_ns > 0 else { return 0; }
    if ms == 0 {
        return if base_ns > 1 { core::sub_sat_u64(base_ns, 1) } else { 1 };
    }
    let nanos = core::mul_sat_u64(ms, core::NANOS_PER_MILLI as u64);
    return core::add_sat_u64(base_ns, nanos);
}

inline fn is_reserved_header(n: const u8[:]) -> bool {
    if n.starts_with_fold(":") { return true; }
    return n.eq_ascii_fold("te")
        || n.eq_ascii_fold("host")
        || n.eq_ascii_fold("connection")
        || n.eq_ascii_fold("keep-alive")
        || n.eq_ascii_fold("proxy-connection")
        || n.eq_ascii_fold("transfer-encoding")
        || n.eq_ascii_fold("upgrade")
        || n.eq_ascii_fold("content-length")
        || n.eq_ascii_fold("user-agent");
}

inline fn is_valid_bin_segment(seg: const u8[:]) -> bool {
    if seg.len == 0 { return true; }
    let rem = seg.len & 3;
    guard rem != 1 else { return false; }
    if rem == 0 {
        return core::is_valid_base64(seg);
    }
    for b in seg {
        guard core::base64_val(b) >= 0 else { return false; }
    }
    let last_val = core::base64_val(seg[core::sub_sat_i64(seg.len, 1)]);
    return if rem == 2 { (last_val & 0x0F) == 0 } else { (last_val & 0x03) == 0 };
}

fn is_valid_bin_header_value(raw: const u8[:]) -> bool {
    var rem = raw;
    while rem.len > 0 {
        let head, tail, has_comma = rem.split_once_byte(',');
        let seg = (if has_comma { head } else { rem }).trim_lws();
        guard is_valid_bin_segment(seg) else { return false; }
        if !has_comma { break; }
        rem = tail;
    }
    return true;
}

inline fn is_valid_request_header_pair(n: const u8[:], v: const u8[:]) -> bool {
    guard n.len > 0 else { return false; }
    for b in n {
        guard core::is_tchar(b) else { return false; }
    }
    for vb in v {
        guard vb == '\t' || (vb >= 0x20 && vb <= 0x7E) || vb >= 0x80 else { return false; }
    }
    if n.ends_with_fold("-bin") {
        return is_valid_bin_header_value(v);
    }
    return true;
}

inline fn process_request_header(
    n:                 const u8[:],
    v:                 const u8[:],
    ctx:               grpc::ServerContext&,
    now_mono_ns:       u64,
    req_start_mono_ns: u64,
) -> grpc::StatusCode {
    if n.starts_with_fold(":") { return grpc::StatusCode.Ok; }
    guard is_valid_request_header_pair(n, v) else {
        return grpc::StatusCode.InvalidArgument;
    }
    if n.eq_ascii_fold("content-type") {
        if v.len == 0 || grpc::is_content_type(v) { return grpc::StatusCode.Ok; }
        return grpc::StatusCode.InvalidArgument;
    }
    if n.eq_ascii_fold("accept") {
        if is_web_text(v) {
            ctx.res_is_web_text = true;
        }
        return grpc::StatusCode.Ok;
    }
    if n.eq_ascii_fold(rfc::HEADER_GRPC_TIMEOUT) {
        let ms, ok_to = grpc::parse_timeout(v);
        guard ok_to else { return grpc::StatusCode.InvalidArgument; }
        ctx.timeout_ms = ms;
        let base_ns = if req_start_mono_ns > 0 { req_start_mono_ns } else { now_mono_ns };
        ctx.deadline_mono_ns = compute_safe_deadline(base_ns, ms);
        return grpc::StatusCode.Ok;
    }
    if is_reserved_header(n) {
        return grpc::StatusCode.Ok;
    }
    var item = grpc::Metadata { .. };
    guard n.len <= item.key.cap && item.value.try_set(v) else {
        return grpc::StatusCode.ResourceExhausted;
    }
    n.to_lower_ascii(item.key);
    guard ctx.metadata.try_push(item) else {
        return grpc::StatusCode.ResourceExhausted;
    }
    return grpc::StatusCode.Ok;
}

inline fn init_context_transport(req: const http::Request&, ctx: grpc::ServerContext&) {
    let ct = req.header("content-type");
    ctx.is_web = is_web(ct);
    ctx.is_web_text = is_web_text(ct);
    let accept_hdr = req.header("accept");
    ctx.res_is_web_text = ctx.is_web_text || is_web_text(accept_hdr);
}

inline fn reset_server_context(ctx: grpc::ServerContext&) {
    ctx.service.clear();
    ctx.method.clear();
    ctx.metadata.clear();
    ctx.response_metadata.clear();
    ctx.response_trailers.clear();
    ctx.timeout_ms = 0;
    ctx.deadline_mono_ns = 0;
}

// Extracts service, method, timeout, and metadata from an incoming gRPC HTTP request,
// returning `Ok` or the canonical `grpc::StatusCode` failure reason.
//
// Example:
//   req.url = "/echo.Echo/Ping", req.headers = [content-type: application/grpc]
//   returns: grpc::StatusCode.Ok, ctx.service = "echo.Echo", ctx.method = "Ping"
fn extract_server_context_status(
    req:               const http::Request&,
    ctx:               grpc::ServerContext&,
    now_mono_ns:       u64 = 0,
    req_start_mono_ns: u64 = 0,
) -> grpc::StatusCode {
    reset_server_context(ctx);
    init_context_transport(req, ctx);
    var committed = false;
    defer if !committed {
        reset_server_context(ctx);
        init_context_transport(req, ctx);
    };

    let raw_url = req.url[..];
    let q_idx = raw_url.index_of_byte('?');
    let path_only = if q_idx >= 0 && is_connect_get_request(req) { raw_url[..q_idx] } else { raw_url };
    guard grpc::parse_path(path_only, ctx.service, ctx.method) else {
        return grpc::StatusCode.Unimplemented;
    }

    for &e in req.headers.entries {
        let hdr_st = process_request_header(
            http::entry_name(req.headers, e),
            http::entry_value(req.headers, e),
            ctx,
            now_mono_ns,
            req_start_mono_ns,
        );
        guard hdr_st == grpc::StatusCode.Ok else { return hdr_st; }
    }

    committed = true;
    return grpc::StatusCode.Ok;
}

inline fn is_supported_encoding(enc: const u8[:]) -> bool {
    let trimmed = enc.trim_lws();
    if trimmed.len == 0 { return true; }
    return trimmed.eq_ascii_fold("gzip") || trimmed.eq_ascii_fold("identity");
}

// Validates single-message LPM request body for Unary and ServerStreaming RPCs.
//
// Example:
//   req.body = [0x00, 0x00, 0x00, 0x00, 0x04, "ping"], ctx.is_web_text = false
//   returns: true, req_payload = "ping"
fn decode_and_validate_single_lpm(
    d:           const grpc::ServerDispatcher&,
    req:         const http::Request&,
    ctx:         const grpc::ServerContext&,
    res:         http::Response&,
    req_payload: u8[>..]&,
) -> bool {
    let enc = grpc::get_metadata(ctx, rfc::HEADER_GRPC_ENCODING).trim_lws();
    guard is_supported_encoding(enc) else {
        build_trailers_only_response(grpc::StatusCode.Unimplemented, "Unsupported grpc-encoding", ctx, res);
        return false;
    }

    var wire_bytes: u8[>..] = [];
    if ctx.is_web_text {
        guard grpc::decode_web_text(req.body[..], wire_bytes) else {
            build_trailers_only_response(
                grpc::StatusCode.InvalidArgument, "Invalid Base64 gRPC-Web-Text payload", ctx, res,
            );
            return false;
        }
    }
    let wire_slice = if ctx.is_web_text { wire_bytes[..] } else { req.body[..] };

    guard wire_slice.len >= rfc::GRPC_LPM_HEADER_LEN else {
        build_trailers_only_response(grpc::StatusCode.InvalidArgument, "Incomplete 5-byte LPM header", ctx, res);
        return false;
    }

    var is_compressed = false;
    var tmp_payload: u8[>..] = [];
    let consumed, ok_lpm = grpc::decode_lpm(wire_slice, 0, tmp_payload, is_compressed);
    if !ok_lpm || consumed != wire_slice.len {
        build_trailers_only_response(grpc::StatusCode.InvalidArgument, "Malformed LPM framing", ctx, res);
        return false;
    }

    let comp_st = grpc::validate_recv_compression(is_compressed, enc, true);
    guard comp_st == grpc::StatusCode.Ok else {
        build_trailers_only_response(
            comp_st, "Compressed frame without compression encoding", ctx, res,
        );
        return false;
    }

    if is_compressed {
        var decomp_buf: u8[>..] = [];
        let ok_gz, gz_err = core::gzip_decompress_with_limit(tmp_payload[..], decomp_buf, d.max_message_size);
        guard ok_gz else {
            let is_overflow = gz_err == core::CompressError.OutputBufferOverflow;
            let code = if is_overflow {
                grpc::StatusCode.ResourceExhausted
            } else {
                grpc::StatusCode.Internal
            };
            let msg = if is_overflow {
                "Decompressed message exceeds max configured message size"
            } else {
                "Failed to decompress gRPC gzip payload"
            };
            build_trailers_only_response(code, msg, ctx, res);
            return false;
        }
        tmp_payload.clear();
        tmp_payload.append(decomp_buf[..]);
    }

    if (tmp_payload.len as u32) > d.max_message_size {
        build_trailers_only_response(
            grpc::StatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
        );
        return false;
    }

    req_payload.clear();
    req_payload.append(tmp_payload[..]);
    return true;
}

fn build_connect_unary_get_response(
    st:          const grpc::Status&,
    res_payload: const u8[:],
    encoding:    const u8[:],
    ctx:         const grpc::ServerContext&,
    res:         http::Response&,
) {
    res.headers.clear();
    res.trailers.clear();
    res.body.clear();
    res.presence_mask = 0;

    append_metadata_headers(res.headers, ctx.response_metadata[..]);
    if st.code == grpc::StatusCode.Ok {
        res.status_code = rfc::STATUS_OK;
        let ct = if encoding == "json" { grpc::CONNECT_MIME_JSON } else { grpc::CONNECT_MIME_PROTO };
        let _ = res.headers.append_header("content-type", ct);
        res.body.append(res_payload);
        return;
    }

    res.status_code = connect_error_http_status(st.code);
    let _ = res.headers.append_header("content-type", grpc::CONNECT_MIME_JSON);
    encode_connect_unary_error_json(st, res.body);
}

fn dispatch_connect_unary_get<HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status>(
    d:           const grpc::ServerDispatcher&,
    req:         const http::Request&,
    entry:       const grpc::MethodEntry&,
    now_mono_ns: u64,
    ctx:         grpc::ServerContext&,
    res:         http::Response&,
) -> bool {
    if entry.idempotency != grpc::Idempotency.NoSideEffects {
        res.status_code = rfc::STATUS_METHOD_NOT_ALLOWED;
        let _ = res.headers.append_header("allow", "POST");
        return true;
    }
    if ctx.is_deadline_exceeded(now_mono_ns) {
        let dl_st = grpc::error(grpc::StatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch");
        build_connect_unary_get_response(dl_st, "", "proto", ctx, res);
        return true;
    }
    let q_idx = req.url[..].index_of_byte('?');
    let query_slice = if q_idx >= 0 { req.url[core::add_sat_i64(q_idx, 1)..] } else { "" };
    var params = grpc::ConnectUnaryGetParams { .. };
    var req_payload: u8[>..] = [];
    let q_code = grpc::parse_connect_get_query(query_slice, params, req_payload);
    if q_code != grpc::StatusCode.Ok {
        let q_err = grpc::error(q_code, "Invalid Connect GET query parameters");
        build_connect_unary_get_response(q_err, "", "json", ctx, res);
        return true;
    }
    if (req_payload.len as u32) > d.max_message_size {
        let sz_err = grpc::error(grpc::StatusCode.ResourceExhausted, "Message exceeds max size");
        build_connect_unary_get_response(sz_err, "", params.encoding[..], ctx, res);
        return true;
    }
    var res_payload: u8[>..] = [];
    let st = HandlerFn(entry.handler_id, ctx, req_payload[..], res_payload);
    build_connect_unary_get_response(st, res_payload[..], params.encoding[..], ctx, res);
    return true;
}

fn prepare_method_dispatch(
    d:                 const grpc::ServerDispatcher&,
    req:               const http::Request&,
    expected_type:     grpc::MethodType,
    now_mono_ns:       u64,
    req_start_mono_ns: u64,
    ctx:               grpc::ServerContext&,
    res:               http::Response&,
) -> i64, bool {
    init_context_transport(req, ctx);
    if !req.method[..].eq_ascii_fold("POST") {
        build_trailers_only_response(grpc::StatusCode.Internal, "HTTP method must be POST", ctx, res);
        return 0, false;
    }
    let ctx_st = extract_server_context_status(req, ctx, now_mono_ns, req_start_mono_ns);
    if ctx_st != grpc::StatusCode.Ok {
        let ctx_msg = if ctx_st == grpc::StatusCode.Unimplemented {
            "Malformed gRPC URI path"
        } else {
            "Malformed gRPC request headers"
        };
        build_trailers_only_response(ctx_st, ctx_msg, ctx, res);
        return 0, false;
    }
    var path_buf: u8[..260] = [];
    path_buf.push('/');
    path_buf.append(ctx.service[..]);
    path_buf.push('/');
    path_buf.append(ctx.method[..]);
    let method_idx, ok_method = d.find_method(path_buf[..]);
    if !ok_method {
        var err_msg: u8[..256] = [];
        err_msg.append("Method not found: ");
        err_msg.append(path_buf[..]);
        build_trailers_only_response(grpc::StatusCode.Unimplemented, err_msg[..], ctx, res);
        return 0, false;
    }
    let entry .= d.methods[method_idx];
    if ctx.is_web && !d.enable_web {
        build_trailers_only_response(grpc::StatusCode.PermissionDenied, "gRPC-Web transport disabled", ctx, res);
        return 0, false;
    }
    if entry.method_type != expected_type {
        build_trailers_only_response(grpc::StatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return 0, false;
    }
    if ctx.is_deadline_exceeded(now_mono_ns) {
        build_trailers_only_response(
            grpc::StatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
        );
        return 0, false;
    }
    return method_idx, true;
}

fn append_decompressed_stream_span(
    raw_msg:   const u8[:],
    span:      grpc::MessageSpan,
    max_size:  u32,
    ctx:       const grpc::ServerContext&,
    res:       http::Response&,
    new_wire:  u8[>..]&,
    new_spans: grpc::MessageSpan[..32]&,
) -> bool {
    let offset_start = new_wire.len as u32;
    if !span.compressed {
        new_wire.append(raw_msg);
        new_spans.push(grpc::MessageSpan { offset: offset_start, len: span.len, compressed: false });
        return true;
    }
    let ok_gz, gz_err = core::gzip_decompress_with_limit(raw_msg, new_wire, max_size);
    guard ok_gz else {
        let is_overflow = gz_err == core::CompressError.OutputBufferOverflow;
        let code = if is_overflow {
            grpc::StatusCode.ResourceExhausted
        } else {
            grpc::StatusCode.Internal
        };
        build_trailers_only_response(code, "Failed to decompress client stream message", ctx, res);
        return false;
    }
    let decomp_len = core::sub_sat_u64(new_wire.len as u64, offset_start) as u32;
    new_spans.push(grpc::MessageSpan { offset: offset_start, len: decomp_len, compressed: false });
    return true;
}

fn validate_and_decompress_client_stream(
    reader:   grpc::ClientStreamReader&,
    max_size: u32,
    ctx:      const grpc::ServerContext&,
    res:      http::Response&,
) -> bool {
    let enc = grpc::get_metadata(ctx, rfc::HEADER_GRPC_ENCODING).trim_lws();
    guard is_supported_encoding(enc) else {
        build_trailers_only_response(grpc::StatusCode.Unimplemented, "Unsupported grpc-encoding", ctx, res);
        return false;
    }
    var any_compressed = false;
    for &span in reader.spans {
        if span.compressed {
            any_compressed = true;
        } else if span.len > max_size {
            build_trailers_only_response(
                grpc::StatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
            );
            return false;
        }
    }
    guard any_compressed else { return true; }
    guard enc.eq_ascii_fold("gzip") else {
        build_trailers_only_response(
            grpc::StatusCode.Internal, "Compressed frame without compression encoding", ctx, res,
        );
        return false;
    }

    var new_wire:  u8[>..]                 = [];
    var new_spans: grpc::MessageSpan[..32] = [];
    for i in reader.spans.len {
        let span = reader.spans[i];
        let raw_msg = grpc::get_client_stream_message(reader, i);
        guard append_decompressed_stream_span(raw_msg, span, max_size, ctx, res, new_wire, new_spans) else {
            return false;
        }
    }
    reader.wire.clear();
    reader.wire.append(new_wire[..]);
    reader.spans = new_spans;
    return true;
}

// ---- HTTP/2 & gRPC-Web Connection Loop Helpers --------------------------

fn slice_h2_headers_fragment(
    payload:   const u8[:],
    flags:     u8,
    stream_id: u32 = 0,
) -> const u8[:], bool {
    var pad_offset: i64 = 0;
    var pay_end:    i64 = payload.len;
    if (flags & rfc::H2_FLAG_PADDED) != 0 {
        guard payload.len > 0 else { return "", false; }
        let pad_len = payload[0] as i64;
        guard pad_len < payload.len else { return "", false; }
        pad_offset = core::add_sat_i64(pad_offset, 1);
        pay_end = core::sub_sat_i64(pay_end, pad_len);
    }
    if (flags & rfc::H2_FLAG_PRIORITY) != 0 {
        let next_off = core::add_sat_i64(pad_offset, 5);
        guard next_off <= pay_end else { return "", false; }
        let dep_id = core::read_be_u32(payload, pad_offset) & 0x7FFFFFFF;
        guard stream_id == 0 || dep_id != stream_id else { return "", false; }
        pad_offset = next_off;
    }
    guard pad_offset <= pay_end else { return "", false; }
    return payload[pad_offset..pay_end], true;
}

fn execute_server_unary<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:    server::HttpServer&,
    d:         const grpc::ServerDispatcher&,
    client_ip: const u8[:],
    req:       const http::Request&,
    res:       http::Response&,
) {
    server.pipeline.trust_proxy_headers = server.trust_proxy_headers;
    let now_ns = core::as_nanos(core::monotonic_now());
    var future = server_internal::new_inline_handler_future(0);
    let outcome = server::execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    if outcome == server::PipelineOutcome.RouteNotFound {
        let _ = grpc::dispatch_unary(d, req, now_ns, res, HandlerFn);
    }
}

inline fn is_valid_h2_settings_frame(hdr: const wire::WireFrameHeader&) -> bool {
    let pay_u64: u64 = hdr.length;
    let is_mult6 = core::mul_sat_u64(div_u64(pay_u64, 6), 6) == pay_u64;
    guard hdr.stream_id == 0 else { return false; }
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        return pay_u64 == 0;
    }
    return is_mult6;
}

inline fn validate_h2_settings_payload(payload: const u8[:]) -> bool {
    var off: i64 = 0;
    while core::add_sat_i64(off, 6) <= payload.len {
        let s = wire::WireSetting {
            id:  core::read_be_u16(payload, off),
            val: core::read_be_u32(payload, core::add_sat_i64(off, 2)),
        };
        guard wire::is_valid_wire_setting(s) else { return false; }
        off = core::add_sat_i64(off, 6);
    }
    return off == payload.len;
}

inline fn slice_h2_data_payload(payload: const u8[:], flags: u8) -> const u8[:], bool {
    if (flags & rfc::H2_FLAG_PADDED) == 0 {
        return payload, true;
    }
    guard payload.len > 0 else { return "", false; }
    let pad_len = payload[0] as i64;
    let data_end = core::sub_sat_i64(payload.len, pad_len);
    guard 1 <= data_end && pad_len < payload.len else { return "", false; }
    return payload[1..data_end], true;
}

fn drain_h2_frames<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    conn_fd:           i64,
    server:            server::HttpServer&,
    d:                 const grpc::ServerDispatcher&,
    peer_ip:           const u8[:],
    hpack_dec:         http2::DynamicTable&,
    hpack_enc:         http2::DynamicTable&,
    pending:           http::Request&,
    pending_stream_id: u32&,
    in_buf:            u8[..65536]&,
    out_wire:          u8[..65536]&,
) -> bool {
    var cursor: i64 = 0;
    var is_running = true;
    while is_running {
        let hdr, payload, ok_frame = wire::read_wire_h2_frame(in_buf[..], cursor);
        if !ok_frame {
            break;
        }
        is_running = grpc::handle_h2_wire_frame(
            conn_fd,
            server,
            d,
            peer_ip,
            hpack_dec,
            hpack_enc,
            pending,
            pending_stream_id,
            hdr,
            payload,
            out_wire,
            HandlerFn,
        );
    }
    if cursor > 0 {
        in_buf.compact_wire_buffer(cursor);
    }
    return is_running;
}

fn serve_h2_connection<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:      server::HttpServer&,
    d:           const grpc::ServerDispatcher&,
    conn_fd:     i64,
    initial_buf: const u8[:],
) {
    let empty_settings: wire::WireSetting[0] = [];
    var srv_set_wire: u8[..16] = [];
    let _ = wire::encode_settings_frame(empty_settings[..], srv_set_wire);
    let _ = net::tcp_send(conn_fd, srv_set_wire[..]);

    var peer_ip: u8[..64] = [];
    net::tcp_get_peer_ip(conn_fd, peer_ip);

    var hpack_dec = http2::new_dynamic_table(4096);
    var hpack_enc = http2::new_dynamic_table(4096);
    var pending = http::new_request("POST", "");
    var pending_stream_id: u32 = 0;

    var in_buf:   u8[..65536] = [];
    var out_wire: u8[..65536] = [];
    var chunk:    u8[..4096]  = [];

    if initial_buf.len > 24 {
        guard in_buf.try_append(initial_buf[24..]) else { return; }
    }

    var is_running = true;
    while is_running {
        is_running = drain_h2_frames(
            conn_fd,
            server,
            d,
            peer_ip[..],
            hpack_dec,
            hpack_enc,
            pending,
            pending_stream_id,
            in_buf,
            out_wire,
            HandlerFn,
        );
        if !is_running {
            break;
        }

        chunk.clear();
        let recvd = net::tcp_recv(conn_fd, chunk, 4096, 50);
        if recvd == -2 {
            continue;
        }
        let next_in = core::add_sat_i64(in_buf.len, recvd as i64);
        guard next_in <= in_buf.cap && server::try_append_recv_chunk(recvd, chunk, in_buf) else {
            break;
        }
    }
}

fn serve_web_http1<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:  server::HttpServer&,
    d:       const grpc::ServerDispatcher&,
    conn_fd: i64,
    req_raw: const u8[:],
) {
    var out_wire: u8[..65536] = [];
    var req = http::new_request("GET", "");
    let ok_parse, _ = server::parse_http1_wire_request(req_raw, req);
    guard ok_parse else {
        server::serialize_bad_request_error(server.server_name[..], out_wire);
        let _ = net::tcp_send(conn_fd, out_wire[..]);
        return;
    }

    var peer_ip: u8[..64] = [];
    net::tcp_get_peer_ip(conn_fd, peer_ip);

    var res = http::Response { .. };
    execute_server_unary(server, d, peer_ip[..], req, res, HandlerFn);

    server::serialize_http1_response(res, server.server_name[..], out_wire);
    let _ = net::tcp_send(conn_fd, out_wire[..]);
}

fn try_dispatch_connection_turn<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:  server::HttpServer&,
    d:       const grpc::ServerDispatcher&,
    conn_fd: i64,
    in_buf:  const u8[:],
) -> bool {
    guard !server::is_partial_h2_client_preface(in_buf) else {
        return false;
    }
    if server::is_h2_client_preface(in_buf) {
        serve_h2_connection(server, d, conn_fd, in_buf, HandlerFn);
        return true;
    }
    var hdr_scan_cursor: i64 = 0;
    guard server::has_ready_http1_request(in_buf, hdr_scan_cursor) else {
        return false;
    }
    if core::starts_with(in_buf, "GET /shutdown") {
        var out_wire: u8[..4096] = [];
        let _, _ = server::handle_connection_wire(server, "127.0.0.1", in_buf, 0, out_wire);
        let _ = net::tcp_send(conn_fd, out_wire[..]);
        server.is_running = false;
        return true;
    }
    serve_web_http1(server, d, conn_fd, in_buf, HandlerFn);
    return true;
}

fn serve_connection<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:  server::HttpServer&,
    d:       const grpc::ServerDispatcher&,
    conn_fd: i64,
) {
    var in_buf:     u8[..65536] = [];
    var chunk:      u8[..4096]  = [];
    var wait_ticks: u64         = 0;

    while wait_ticks < 20 {
        chunk.clear();
        let recvd = net::tcp_recv(conn_fd, chunk, 4096, 100);
        if recvd == -2 {
            wait_ticks = core::add_sat_u64(wait_ticks, 1);
            continue;
        }
        let next_in = core::add_sat_i64(in_buf.len, recvd as i64);
        guard next_in <= in_buf.cap && server::try_append_recv_chunk(recvd, chunk, in_buf) else {
            break;
        }
        wait_ticks = 0;

        if try_dispatch_connection_turn(server, d, conn_fd, in_buf[..], HandlerFn) {
            return;
        }
    }
}
