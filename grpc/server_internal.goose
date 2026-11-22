// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal gRPC server registration, wire response builders, and request ingress helpers.
namespace grpc_internal;

import std;
import core;
import rfc.http;
import rfc.grpc;
import http.headers;
import http.request;
import http.response;
import .constants;
import .framing;
import .status;
import .internal;
import .connect_internal;
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
