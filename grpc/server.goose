// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC server dispatcher.
// Implements RFC gRPC over HTTP/2, RFC 7540/9113 framing, and RFC gRPC-Web (binary and text).
namespace wing;

import std;
import grpc.constants;
import grpc.framing;
import grpc.status;
import grpc.connect;
import grpc.health;
import http.headers;
import http.request;
import http.response;
import core from "..";

// Inspects an incoming Request to determine if it is a gRPC or Connect GET call.
fn is_grpc_request(req: const Request&) -> bool {
    let ct = req.header("content-type");
    if ct.len > 0 && is_grpc_content_type(ct) {
        return true;
    }
    return is_connect_get_request(req);
}

inline fn is_valid_grpc_path_segment(seg: const u8[:]) -> bool {
    guard seg.len > 0 && seg.len <= 128 else { return false; }
    for b in seg {
        guard b > 0x20 && b < 0x7F && b != '/' && b != '?' && b != '#' else { return false; }
    }
    return true;
}

// Parses standard gRPC URI path: `/{service}/{method}` or `/{package}.{service}/{method}`.
// Leaves `out_service` and `out_method` untouched when returning false.
//
// Example:
//   path = "/helloworld.Greeter/SayHello"
//   returns: ok = true, out_service = "helloworld.Greeter", out_method = "SayHello"
fn parse_grpc_path<S, M>(
    path:        const u8[:],
    out_service: S&,
    out_method:  M&,
) -> bool {
    guard path.len >= 3 && path[0] == '/' else { return false; }
    let service_part, method_part, ok_split = path[1..].split_once_byte('/');
    guard ok_split
        && is_valid_grpc_path_segment(service_part)
        && is_valid_grpc_path_segment(method_part) else {
        return false;
    }
    guard service_part.len <= out_service.cap && method_part.len <= out_method.cap else {
        return false;
    }
    let _ = out_service.try_set(service_part);
    let _ = out_method.try_set(method_part);
    return true;
}

// ---- Server Invocation Context ------------------------------------------

struct GrpcServerContext {
    service:           u8[..128]          = [],
    method:            u8[..128]          = [],
    peer_ip:           u8[..48]           = [],
    timeout_ms:        u64                = 0,
    deadline_mono_ns:  u64                = 0,
    is_web:            bool               = false,
    is_web_text:       bool               = false,
    res_is_web_text:   bool               = false,
    metadata:          GrpcMetadata[..16] = [],
    response_metadata: GrpcMetadata[..16] = [],
    response_trailers: GrpcMetadata[..16] = [],
}

fn get_metadata(ctx: const GrpcServerContext&, key: const u8[:]) -> const u8[:] {
    for &m in ctx.metadata {
        if m.key[..].eq_ascii_fold(key) {
            return m.value[..];
        }
    }
    return "";
}

fn add_response_metadata(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool {
    guard is_valid_grpc_custom_metadata(key, value) else { return false; }
    var item = GrpcMetadata { .. };
    guard item.key.try_set(key) && item.value.try_set(value) else { return false; }
    return ctx.response_metadata.try_push(item);
}

fn add_response_trailer(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool {
    guard is_valid_grpc_custom_metadata(key, value) else { return false; }
    var item = GrpcMetadata { .. };
    guard item.key.try_set(key) && item.value.try_set(value) else { return false; }
    return ctx.response_trailers.try_push(item);
}

fn is_deadline_exceeded(ctx: const GrpcServerContext&, now_mono_ns: u64) -> bool {
    if ctx.deadline_mono_ns > 0 {
        return now_mono_ns > ctx.deadline_mono_ns;
    }
    return false;
}

// ---- Service & Method Registry ------------------------------------------

enum GrpcMethodType {
    Unary,
    ClientStreaming,
    ServerStreaming,
    BidiStreaming,
}

enum GrpcIdempotency {
    Default,
    Idempotent,
    NoSideEffects,
}

struct GrpcMethodEntry {
    service:     u8[..128]       = [],
    method:      u8[..128]       = [],
    full_path:   u8[..260]       = [],
    method_type: GrpcMethodType  = GrpcMethodType.Unary,
    idempotency: GrpcIdempotency = GrpcIdempotency.Default,
    handler_id:  u16             = 0,
}

struct GrpcServerDispatcher {
    methods:          GrpcMethodEntry[..64]        = [],
    health_entries:   GrpcHealthServiceEntry[..32] = [],
    max_message_size: u32                          = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    enable_web:       bool                         = true,
}

fn new_grpc_server_dispatcher(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcServerDispatcher {
    return GrpcServerDispatcher {
        methods:          [],
        health_entries:   [],
        max_message_size: max_msg_size,
        enable_web:       true,
    };
}

// Registers or updates the serving status of a service for `/grpc.health.v1.Health/Check` (gRFC A66).
fn set_grpc_service_health(
    d:       GrpcServerDispatcher&,
    service: const u8[:],
    status:  GrpcServingStatus,
) -> bool {
    guard service.len <= 128 else { return false; }
    for i in d.health_entries.len {
        if d.health_entries[i].service[..] == service {
            d.health_entries[i].status = status;
            return true;
        }
    }
    var entry = GrpcHealthServiceEntry { status: status, .. };
    guard entry.service.try_set(service) else { return false; }
    return d.health_entries.try_push(entry);
}

// Looks up the serving status for a service in `d.health_entries` (gRFC A66).
fn lookup_grpc_service_health(
    d:       const GrpcServerDispatcher&,
    service: const u8[:],
) -> GrpcServingStatus, bool {
    for &entry in d.health_entries {
        if entry.service[..] == service {
            return entry.status, true;
        }
    }
    if service.len == 0 && d.health_entries.len == 0 {
        return GrpcServingStatus.Serving, true;
    }
    return GrpcServingStatus.ServiceUnknown, false;
}

fn register_method(
    d:           GrpcServerDispatcher&,
    service:     const u8[:],
    method:      const u8[:],
    method_type: GrpcMethodType,
    handler_id:  u16,
    idempotency: GrpcIdempotency = GrpcIdempotency.Default,
) -> bool {
    var entry = GrpcMethodEntry {
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

fn register_unary(
    d:           GrpcServerDispatcher&,
    service:     const u8[:],
    method:      const u8[:],
    handler_id:  u16,
    idempotency: GrpcIdempotency = GrpcIdempotency.Default,
) -> bool {
    return register_method(d, service, method, GrpcMethodType.Unary, handler_id, idempotency);
}

fn register_server_streaming(
    d:          GrpcServerDispatcher&,
    service:    const u8[:],
    method:     const u8[:],
    handler_id: u16,
) -> bool {
    return register_method(d, service, method, GrpcMethodType.ServerStreaming, handler_id);
}

fn register_client_streaming(
    d:          GrpcServerDispatcher&,
    service:    const u8[:],
    method:     const u8[:],
    handler_id: u16,
) -> bool {
    return register_method(d, service, method, GrpcMethodType.ClientStreaming, handler_id);
}

fn register_bidi_streaming(
    d:          GrpcServerDispatcher&,
    service:    const u8[:],
    method:     const u8[:],
    handler_id: u16,
) -> bool {
    return register_method(d, service, method, GrpcMethodType.BidiStreaming, handler_id);
}

fn find_method(d: const GrpcServerDispatcher&, full_path: const u8[:]) -> i64 {
    for i in d.methods.len {
        if d.methods[i].full_path[..] == full_path {
            return i;
        }
    }
    return -1;
}

fn find_method_by_name(d: const GrpcServerDispatcher&, service: const u8[:], method: const u8[:]) -> i64 {
    for i in d.methods.len {
        if d.methods[i].service[..] == service && d.methods[i].method[..] == method {
            return i;
        }
    }
    return -1;
}

// ---- Wire Response Builders ---------------------------------------------

// Appends gRPC metadata entries into a response header or trailer list.
fn append_grpc_metadata_headers(target: HeaderMap&, metadata: const GrpcMetadata[:]) {
    for &m in metadata {
        if is_valid_grpc_custom_metadata(m.key[..], m.value[..]) {
            let _ = append_header(target, m.key[..], m.value[..]);
        }
    }
}

// Builds a Trailers-Only response (used for immediate errors or zero-data failures)
fn build_grpc_trailers_only_response(
    status:  GrpcStatusCode,
    message: const u8[:],
    ctx:     const GrpcServerContext&,
    out_res: Response&,
) {
    out_res.status_code = rfc::STATUS_OK;
    out_res.headers.clear();
    out_res.trailers.clear();
    out_res.body.clear();
    out_res.presence_mask = 0;

    if ctx.is_web {
        // gRPC-Web: Trailers are framed in body with flag 0x80
        let ct_val = if ctx.res_is_web_text {
            rfc::GRPC_WEB_TEXT_CONTENT_TYPE
        } else {
            rfc::GRPC_WEB_CONTENT_TYPE_PROTO
        };
        let _ = append_header(out_res.headers, "content-type", ct_val);

        append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);

        var raw_trailers: u8[>..] = [];
        encode_grpc_web_trailers_with_meta(status, message, ctx.response_trailers[..], raw_trailers);

        if ctx.res_is_web_text {
            encode_grpc_web_text(raw_trailers[..], out_res.body);
        } else {
            out_res.body.append(raw_trailers[..]);
        }
    } else {
        // Native HTTP/2 gRPC: Trailers-Only sent in single initial HEADERS frame
        let _ = append_header(out_res.headers, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        let _ = append_header(out_res.headers, rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");

        var st_val: u8[..32] = [];
        let code = grpc_status_to_code(status);
        code.format_u32_dec(st_val);
        let _ = append_header(out_res.headers, rfc::HEADER_GRPC_STATUS, st_val[..]);

        if message.len > 0 {
            var msg_val: u8[..1024] = [];
            encode_grpc_message(message, msg_val);
            let _ = append_header(out_res.headers, rfc::HEADER_GRPC_MESSAGE, msg_val[..]);
        }

        append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);
        append_grpc_metadata_headers(out_res.headers, ctx.response_trailers[..]);
    }
}

// Builds a standard gRPC wire response (Headers + Body LPM + Trailers)
fn build_grpc_wire_response(
    status:       GrpcStatusCode,
    message:      const u8[:],
    raw_lpm_body: const u8[:],
    ctx:          const GrpcServerContext&,
    out_res:      Response&,
) {
    out_res.status_code = rfc::STATUS_OK;
    out_res.headers.clear();
    out_res.trailers.clear();
    out_res.body.clear();
    out_res.presence_mask = 0;

    if ctx.is_web {
        // gRPC-Web
        let ct_val = if ctx.res_is_web_text {
            rfc::GRPC_WEB_TEXT_CONTENT_TYPE
        } else {
            rfc::GRPC_WEB_CONTENT_TYPE_PROTO
        };
        let _ = append_header(out_res.headers, "content-type", ct_val);

        append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);

        var web_body: u8[>..] = [];
        web_body.append(raw_lpm_body);
        encode_grpc_web_trailers_with_meta(status, message, ctx.response_trailers[..], web_body);

        if ctx.res_is_web_text {
            encode_grpc_web_text(web_body[..], out_res.body);
        } else {
            out_res.body.append(web_body[..]);
        }
    } else {
        // Native HTTP/2 gRPC
        let _ = append_header(out_res.headers, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        let _ = append_header(out_res.headers, rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");

        append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);

        out_res.body.append(raw_lpm_body);

        // Trailers
        var st_val: u8[..32] = [];
        let code = grpc_status_to_code(status);
        code.format_u32_dec(st_val);
        let _ = append_header(out_res.trailers, rfc::HEADER_GRPC_STATUS, st_val[..]);

        if message.len > 0 {
            var msg_val: u8[..1024] = [];
            encode_grpc_message(message, msg_val);
            let _ = append_header(out_res.trailers, rfc::HEADER_GRPC_MESSAGE, msg_val[..]);
        }

        append_grpc_metadata_headers(out_res.trailers, ctx.response_trailers[..]);
    }
}

// ---- Request Ingress Context Extraction ----------------------------------

inline fn compute_safe_grpc_deadline(base_ns: u64, ms: u64) -> u64 {
    guard base_ns > 0 else { return 0; }
    if ms == 0 {
        return if base_ns > 1 { core::sub_sat_u64(base_ns, 1) } else { 1 };
    }
    let nanos = core::mul_sat_u64(ms, NANOS_PER_MILLI);
    return core::add_sat_u64(base_ns, nanos);
}

inline fn is_reserved_grpc_header(n: const u8[:]) -> bool {
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

inline fn is_valid_grpc_bin_segment(seg: const u8[:]) -> bool {
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

fn is_valid_grpc_bin_header_value(raw: const u8[:]) -> bool {
    var rem = raw;
    while rem.len > 0 {
        let head, tail, has_comma = rem.split_once_byte(',');
        let seg = (if has_comma { head } else { rem }).trim_lws();
        guard is_valid_grpc_bin_segment(seg) else { return false; }
        if !has_comma { break; }
        rem = tail;
    }
    return true;
}

inline fn is_valid_grpc_request_header_pair(n: const u8[:], v: const u8[:]) -> bool {
    guard n.len > 0 else { return false; }
    for b in n {
        guard core::is_tchar(b) else { return false; }
    }
    for vb in v {
        guard vb == '\t' || (vb >= 0x20 && vb <= 0x7E) || vb >= 0x80 else { return false; }
    }
    if n.ends_with_fold("-bin") {
        return is_valid_grpc_bin_header_value(v);
    }
    return true;
}

inline fn process_grpc_request_header(
    n:                 const u8[:],
    v:                 const u8[:],
    out_ctx:           GrpcServerContext&,
    now_mono_ns:       u64,
    req_start_mono_ns: u64,
) -> GrpcStatusCode {
    if n.starts_with_fold(":") { return GrpcStatusCode.Ok; }
    guard is_valid_grpc_request_header_pair(n, v) else {
        return GrpcStatusCode.InvalidArgument;
    }
    if n.eq_ascii_fold("content-type") {
        if v.len == 0 || is_grpc_content_type(v) { return GrpcStatusCode.Ok; }
        return GrpcStatusCode.InvalidArgument;
    }
    if n.eq_ascii_fold("accept") {
        if is_grpc_web_text(v) {
            out_ctx.res_is_web_text = true;
        }
        return GrpcStatusCode.Ok;
    }
    if n.eq_ascii_fold(rfc::HEADER_GRPC_TIMEOUT) {
        let ms, ok_to = parse_grpc_timeout(v);
        guard ok_to else { return GrpcStatusCode.InvalidArgument; }
        out_ctx.timeout_ms = ms;
        let base_ns = if req_start_mono_ns > 0 { req_start_mono_ns } else { now_mono_ns };
        out_ctx.deadline_mono_ns = compute_safe_grpc_deadline(base_ns, ms);
        return GrpcStatusCode.Ok;
    }
    if is_reserved_grpc_header(n) {
        return GrpcStatusCode.Ok;
    }
    var item = GrpcMetadata { .. };
    guard n.len <= item.key.cap && item.value.try_set(v) else {
        return GrpcStatusCode.ResourceExhausted;
    }
    n.to_lower_ascii(item.key);
    guard out_ctx.metadata.try_push(item) else {
        return GrpcStatusCode.ResourceExhausted;
    }
    return GrpcStatusCode.Ok;
}

inline fn init_grpc_context_transport(req: const Request&, out_ctx: GrpcServerContext&) {
    let ct = req.header("content-type");
    out_ctx.is_web = is_grpc_web(ct);
    out_ctx.is_web_text = is_grpc_web_text(ct);
    let accept_hdr = req.header("accept");
    out_ctx.res_is_web_text = out_ctx.is_web_text || is_grpc_web_text(accept_hdr);
}

inline fn reset_grpc_server_context(out_ctx: GrpcServerContext&) {
    out_ctx.service.clear();
    out_ctx.method.clear();
    out_ctx.metadata.clear();
    out_ctx.response_metadata.clear();
    out_ctx.response_trailers.clear();
    out_ctx.timeout_ms = 0;
    out_ctx.deadline_mono_ns = 0;
}

// Extracts service, method, timeout, and metadata from an incoming gRPC HTTP request,
// returning `Ok` or the canonical `GrpcStatusCode` failure reason.
//
// Example:
//   req.url = "/echo.Echo/Ping", req.headers = [content-type: application/grpc]
//   returns: GrpcStatusCode.Ok, out_ctx.service = "echo.Echo", out_ctx.method = "Ping"
fn extract_grpc_server_context_status(
    req:               const Request&,
    out_ctx:           GrpcServerContext&,
    now_mono_ns:       u64 = 0,
    req_start_mono_ns: u64 = 0,
) -> GrpcStatusCode {
    reset_grpc_server_context(out_ctx);
    init_grpc_context_transport(req, out_ctx);
    var committed = false;
    defer if !committed {
        reset_grpc_server_context(out_ctx);
        init_grpc_context_transport(req, out_ctx);
    };

    let raw_url = req.url[..];
    let q_idx = raw_url.index_of_byte('?');
    let path_only = if q_idx >= 0 && is_connect_get_request(req) { raw_url[..q_idx] } else { raw_url };
    guard parse_grpc_path(path_only, out_ctx.service, out_ctx.method) else {
        return GrpcStatusCode.Unimplemented;
    }

    for &e in req.headers.entries {
        let hdr_st = process_grpc_request_header(
            entry_name(req.headers, e),
            entry_value(req.headers, e),
            out_ctx,
            now_mono_ns,
            req_start_mono_ns,
        );
        guard hdr_st == GrpcStatusCode.Ok else { return hdr_st; }
    }

    committed = true;
    return GrpcStatusCode.Ok;
}

// ---- Streaming Primitives -----------------------------------------------

struct GrpcMessageSpan {
    offset:     u32  = 0,
    len:        u32  = 0,
    compressed: bool = false,
}

struct GrpcClientStreamReader {
    spans: GrpcMessageSpan[..32] = [],
    wire:  u8[>..]               = [],
}

// Parses sequential client stream LPM frames into message spans.
//
// Example:
//   raw_body = "\x00\x00\x00\x00\x04ping\x00\x00\x00\x00\x04pong", is_web_text = false
//   returns: ok = true, out_reader.spans.len = 2
fn parse_client_stream(
    raw_body:    const u8[:],
    is_web_text: bool,
    out_reader:  GrpcClientStreamReader&,
) -> bool {
    out_reader.wire.clear();
    out_reader.spans.clear();
    var committed = false;
    defer if !committed {
        out_reader.wire.clear();
        out_reader.spans.clear();
    };

    if is_web_text {
        guard decode_grpc_web_text(raw_body, out_reader.wire) else { return false; }
    } else {
        out_reader.wire.append(raw_body);
    }

    var idx: u64 = 0;
    let wire_slice = out_reader.wire[..];
    let total_len = wire_slice.len as u64;
    while core::add_sat_u64(idx, rfc::GRPC_LPM_HEADER_LEN) <= total_len {
        let flag = wire_slice[idx as i64];
        guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else { return false; }
        let is_comp = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

        let hdr_off = (core::add_sat_u64(idx, 1)) as i64;
        let len_val = core::read_be_u32(wire_slice, hdr_off);
        idx = core::add_sat_u64(idx, 5);

        let payload_offset = idx as u32;
        let next_idx = core::add_sat_u64(idx, len_val);
        guard next_idx <= total_len else { return false; }
        idx = next_idx;

        let span = GrpcMessageSpan {
            offset:     payload_offset,
            len:        len_val,
            compressed: is_comp,
        };
        guard out_reader.spans.try_push(span) else { return false; }
    }

    guard idx == total_len else { return false; }
    committed = true;
    return true;
}

fn get_client_stream_message(reader: const GrpcClientStreamReader&, idx: i64) -> const u8[:] {
    guard idx >= 0 && idx < reader.spans.len else { return ""; }
    let span = reader.spans[idx];
    let start = span.offset as i64;
    let end = core::add_sat_u64(span.offset, span.len) as i64;
    guard end <= reader.wire.len else { return ""; }
    return reader.wire[start..end];
}

struct GrpcServerStreamWriter {
    message_count: u32     = 0,
    body:          u8[>..] = [],
}

fn write_stream_message(
    writer:     GrpcServerStreamWriter&,
    payload:    const u8[:],
    compressed: bool = false,
) {
    encode_grpc_lpm(payload, writer.body, compressed);
    writer.message_count = core::add_sat_u64(writer.message_count, 1) as u32;
}

// ---- Core Dispatch Execution --------------------------------------------

inline fn is_supported_grpc_encoding(enc: const u8[:]) -> bool {
    let trimmed = enc.trim_lws();
    if trimmed.len == 0 { return true; }
    return trimmed.eq_ascii_fold("gzip") || trimmed.eq_ascii_fold("identity");
}

// Validates received message compression flag (`0x01`) against the `grpc-encoding` header.
// Per gRPC compression spec (`grpc-go` `checkRecvPayload` / `tonic` `decode_chunk`),
// setting `Compressed-Flag = 1` when `grpc-encoding` is empty or `"identity"` is an `Internal` error.
fn validate_recv_compression(is_compressed: bool, enc: const u8[:], is_server: bool) -> GrpcStatusCode {
    let trimmed = enc.trim_lws();
    if !is_compressed {
        if is_supported_grpc_encoding(trimmed) {
            return GrpcStatusCode.Ok;
        }
        return if is_server { GrpcStatusCode.Unimplemented } else { GrpcStatusCode.Internal };
    }
    if trimmed.len == 0 || trimmed.eq_ascii_fold("identity") {
        return GrpcStatusCode.Internal;
    }
    if trimmed.eq_ascii_fold("gzip") {
        return GrpcStatusCode.Ok;
    }
    return if is_server { GrpcStatusCode.Unimplemented } else { GrpcStatusCode.Internal };
}

// Validates single-message LPM request body for Unary and ServerStreaming RPCs.
//
// Example:
//   req.body = [0x00, 0x00, 0x00, 0x00, 0x04, "ping"], ctx.is_web_text = false
//   returns: true, req_payload = "ping"
fn decode_and_validate_single_lpm(
    d:           const GrpcServerDispatcher&,
    req:         const Request&,
    ctx:         const GrpcServerContext&,
    res:         Response&,
    req_payload: u8[>..]&,
) -> bool {
    req_payload.clear();
    var committed = false;
    defer if !committed { req_payload.clear(); };
    let enc = get_metadata(ctx, rfc::HEADER_GRPC_ENCODING).trim_lws();
    guard is_supported_grpc_encoding(enc) else {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Unsupported grpc-encoding", ctx, res);
        return false;
    }

    var wire_bytes: u8[>..] = [];
    if ctx.is_web_text {
        guard decode_grpc_web_text(req.body[..], wire_bytes) else {
            build_grpc_trailers_only_response(
                GrpcStatusCode.InvalidArgument, "Invalid Base64 gRPC-Web-Text payload", ctx, res,
            );
            return false;
        }
    }
    let wire_slice = if ctx.is_web_text { wire_bytes[..] } else { req.body[..] };

    var is_compressed = false;
    if wire_slice.len >= rfc::GRPC_LPM_HEADER_LEN {
        let ok_lpm, consumed = decode_grpc_lpm(wire_slice, 0, req_payload, is_compressed);
        if !ok_lpm || consumed != wire_slice.len {
            build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Malformed LPM framing", ctx, res);
            return false;
        }
    } else {
        build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Incomplete 5-byte LPM header", ctx, res);
        return false;
    }

    let comp_st = validate_recv_compression(is_compressed, enc, true);
    guard comp_st == GrpcStatusCode.Ok else {
        build_grpc_trailers_only_response(
            comp_st, "Compressed frame without compression encoding", ctx, res,
        );
        return false;
    }

    if is_compressed {
        var decomp_buf: u8[>..] = [];
        let ok_gz, gz_err = core::gzip_decompress_with_limit(req_payload[..], decomp_buf, d.max_message_size);
        guard ok_gz else {
            let is_overflow = gz_err == core::CompressError.OutputBufferOverflow;
            let code = if is_overflow { GrpcStatusCode.ResourceExhausted } else { GrpcStatusCode.Internal };
            let msg = if is_overflow {
                "Decompressed message exceeds max configured message size"
            } else {
                "Failed to decompress gRPC gzip payload"
            };
            build_grpc_trailers_only_response(code, msg, ctx, res);
            return false;
        }
        req_payload.clear();
        req_payload.append(decomp_buf[..]);
    }

    if (req_payload.len as u32) > d.max_message_size {
        build_grpc_trailers_only_response(
            GrpcStatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
        );
        return false;
    }

    committed = true;
    return true;
}

// Built-in handler for `/grpc.health.v1.Health/Check` (gRFC A66).
fn handle_builtin_grpc_health_check(
    d:   const GrpcServerDispatcher&,
    req: const Request&,
    ctx: const GrpcServerContext&,
    res: Response&,
) -> bool {
    var req_payload: u8[>..] = [];
    guard decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }
    let target_svc, ok_pb = try_decode_grpc_health_check_request(req_payload[..]);
    if !ok_pb {
        build_grpc_trailers_only_response(
            GrpcStatusCode.InvalidArgument, "Malformed HealthCheckRequest protobuf", ctx, res,
        );
        return true;
    }
    let serving_st, found = lookup_grpc_service_health(d, target_svc);
    if !found {
        build_grpc_trailers_only_response(GrpcStatusCode.NotFound, "unknown service", ctx, res);
        return true;
    }
    var lpm_response: u8[>..] = [];
    encode_grpc_health_check_lpm(serving_st, lpm_response);
    build_grpc_wire_response(GrpcStatusCode.Ok, "", lpm_response[..], ctx, res);
    return true;
}

// Builds a Connect Protocol unary response for HTTP GET requests.
fn build_connect_unary_get_response(
    st:          const GrpcStatus&,
    res_payload: const u8[:],
    encoding:    const u8[:],
    ctx:         const GrpcServerContext&,
    out_res:     Response&,
) {
    out_res.headers.clear();
    out_res.trailers.clear();
    out_res.body.clear();
    out_res.presence_mask = 0;

    append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);
    if st.code == GrpcStatusCode.Ok {
        out_res.status_code = rfc::STATUS_OK;
        let ct = if encoding == "json" { CONNECT_MIME_JSON } else { CONNECT_MIME_PROTO };
        let _ = append_header(out_res.headers, "content-type", ct);
        out_res.body.append(res_payload);
        return;
    }

    out_res.status_code = connect_error_http_status(st.code);
    let _ = append_header(out_res.headers, "content-type", CONNECT_MIME_JSON);
    encode_connect_unary_error_json(st, out_res.body);
}

// Dispatches a Connect Protocol unary HTTP GET request for idempotent (`NoSideEffects`) methods.
fn dispatch_connect_unary_get<HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus>(
    d:           const GrpcServerDispatcher&,
    req:         const Request&,
    entry:       const GrpcMethodEntry&,
    now_mono_ns: u64,
    ctx:         GrpcServerContext&,
    res:         Response&,
) -> bool {
    if entry.idempotency != GrpcIdempotency.NoSideEffects {
        res.status_code = rfc::STATUS_METHOD_NOT_ALLOWED;
        let _ = append_header(res.headers, "allow", "POST");
        return true;
    }
    if is_deadline_exceeded(ctx, now_mono_ns) {
        let dl_st = grpc_error(GrpcStatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch");
        build_connect_unary_get_response(dl_st, "", "proto", ctx, res);
        return true;
    }
    let q_idx = req.url[..].index_of_byte('?');
    let query_slice = if q_idx >= 0 { req.url[core::add_sat_i64(q_idx, 1)..] } else { "" };
    var params = ConnectUnaryGetParams { .. };
    var req_payload: u8[>..] = [];
    let q_code = parse_connect_get_query(query_slice, params, req_payload);
    if q_code != GrpcStatusCode.Ok {
        let q_err = grpc_error(q_code, "Invalid Connect GET query parameters");
        build_connect_unary_get_response(q_err, "", "json", ctx, res);
        return true;
    }
    if (req_payload.len as u32) > d.max_message_size {
        let sz_err = grpc_error(GrpcStatusCode.ResourceExhausted, "Message exceeds max size");
        build_connect_unary_get_response(sz_err, "", params.encoding[..], ctx, res);
        return true;
    }
    var res_payload: u8[>..] = [];
    let st = HandlerFn(entry.handler_id, ctx, req_payload[..], res_payload);
    build_connect_unary_get_response(st, res_payload[..], params.encoding[..], ctx, res);
    return true;
}

// Unary RPC Dispatcher:
// Executes a single Request-Response RPC cycle conforming to RFC gRPC over HTTP/2 and gRPC-Web.
fn dispatch_grpc_unary<HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus>(
    d:                 const GrpcServerDispatcher&,
    req:               const Request&,
    now_mono_ns:       u64,
    res:               Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    // 1. Validate gRPC Content-Type
    guard is_grpc_request(req) else { return false; }

    var ctx = GrpcServerContext { .. };
    init_grpc_context_transport(req, ctx);

    let is_conn_get = is_connect_get_request(req);
    // 2. Validate HTTP Method (RFC gRPC mandates POST; Connect allows GET with connect=v1)
    if !req.method[..].eq_ascii_fold("POST") && !is_conn_get {
        build_grpc_trailers_only_response(GrpcStatusCode.Internal, "HTTP method must be POST", ctx, res);
        return true;
    }

    // 3. Extract Context & Validate URI Path
    let ctx_st = extract_grpc_server_context_status(req, ctx, now_mono_ns, req_start_mono_ns);
    if ctx_st != GrpcStatusCode.Ok {
        let ctx_msg = if ctx_st == GrpcStatusCode.Unimplemented {
            "Malformed gRPC URI path"
        } else {
            "Malformed gRPC request headers"
        };
        build_grpc_trailers_only_response(ctx_st, ctx_msg, ctx, res);
        return true;
    }

    // 4. Match Registered Service & Method
    var path_buf: u8[..260] = [];
    path_buf.push('/');
    path_buf.append(ctx.service[..]);
    path_buf.push('/');
    path_buf.append(ctx.method[..]);

    if path_buf[..] == "/grpc.health.v1.Health/Check" && !is_conn_get {
        if is_deadline_exceeded(ctx, now_mono_ns) {
            build_grpc_trailers_only_response(
                GrpcStatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
            );
            return true;
        }
        return handle_builtin_grpc_health_check(d, req, ctx, res);
    }

    let method_idx = find_method(d, path_buf[..]);
    if method_idx < 0 {
        var err_msg: u8[..256] = [];
        err_msg.append("Method not found: ");
        err_msg.append(path_buf[..]);
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, err_msg[..], ctx, res);
        return true;
    }

    let entry = d.methods[method_idx];
    if ctx.is_web && !d.enable_web {
        build_grpc_trailers_only_response(GrpcStatusCode.PermissionDenied, "gRPC-Web transport disabled", ctx, res);
        return true;
    }
    if entry.method_type != GrpcMethodType.Unary {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return true;
    }

    if is_conn_get {
        return dispatch_connect_unary_get(d, req, entry, now_mono_ns, ctx, res, HandlerFn);
    }

    // 5. Check Deadline Expiration
    if is_deadline_exceeded(ctx, now_mono_ns) {
        build_grpc_trailers_only_response(
            GrpcStatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
        );
        return true;
    }

    // 6. Decode Request LPM Payload
    var req_payload: u8[>..] = [];
    guard decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }

    // 7. Invoke User Handler
    var res_payload: u8[>..] = [];
    let st = HandlerFn(entry.handler_id, ctx, req_payload[..], res_payload);

    // 8. Generate Wire Response
    if st.code != GrpcStatusCode.Ok && res_payload.len == 0 {
        // Pure error without payload -> Trailers-Only response
        build_grpc_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        // Standard payload + trailers response
        var lpm_response: u8[>..] = [];
        encode_grpc_lpm(res_payload[..], lpm_response, false);
        build_grpc_wire_response(st.code, st.message[..], lpm_response[..], ctx, res);
    }

    return true;
}

// Default UFCS unary gRPC stage hook on wire::NoOpStage.
fn on_grpc_unary<B>(
    _stage:      wire::NoOpStage&,
    _handler_id: u16,
    _ctx:        GrpcServerContext&,
    _req_bytes:  const u8[:],
    _res_bytes:  B&,
) -> GrpcStatus {
    return grpc_error(GrpcStatusCode.Unimplemented, "Method not implemented");
}

// Validates gRPC unary method routing, transport policy, and deadline on `req`, returning the handler ID.
fn prepare_grpc_unary_dispatch(
    d:                 const GrpcServerDispatcher&,
    req:               const Request&,
    now_mono_ns:       u64,
    req_start_mono_ns: u64,
    ctx:               GrpcServerContext&,
    res:               Response&,
) -> u16, bool {
    init_grpc_context_transport(req, ctx);
    if !req.method[..].eq_ascii_fold("POST") {
        build_grpc_trailers_only_response(GrpcStatusCode.Internal, "HTTP method must be POST", ctx, res);
        return 0, false;
    }
    let ctx_st = extract_grpc_server_context_status(req, ctx, now_mono_ns, req_start_mono_ns);
    if ctx_st != GrpcStatusCode.Ok {
        let ctx_msg = if ctx_st == GrpcStatusCode.Unimplemented {
            "Malformed gRPC URI path"
        } else {
            "Malformed gRPC request headers"
        };
        build_grpc_trailers_only_response(ctx_st, ctx_msg, ctx, res);
        return 0, false;
    }
    var path_buf: u8[..260] = [];
    path_buf.push('/');
    path_buf.append(ctx.service[..]);
    path_buf.push('/');
    path_buf.append(ctx.method[..]);
    let method_idx = find_method(d, path_buf[..]);
    if method_idx < 0 {
        var err_msg: u8[..256] = [];
        err_msg.append("Method not found: ");
        err_msg.append(path_buf[..]);
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, err_msg[..], ctx, res);
        return 0, false;
    }
    let entry = d.methods[method_idx];
    if ctx.is_web && !d.enable_web {
        build_grpc_trailers_only_response(GrpcStatusCode.PermissionDenied, "gRPC-Web transport disabled", ctx, res);
        return 0, false;
    }
    if entry.method_type != GrpcMethodType.Unary {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return 0, false;
    }
    if is_deadline_exceeded(ctx, now_mono_ns) {
        build_grpc_trailers_only_response(
            GrpcStatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
        );
        return 0, false;
    }
    return entry.handler_id, true;
}

// Stateful UFCS `<Stage>` Unary RPC Dispatcher: invokes `on_grpc_unary`.
fn dispatch_grpc_unary_stage<Stage>(
    d:                 const GrpcServerDispatcher&,
    stage:             Stage&,
    req:               const Request&,
    now_mono_ns:       u64,
    res:               Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard is_grpc_request(req) else { return false; }
    var ctx = GrpcServerContext { .. };
    let handler_id, ok_prep = prepare_grpc_unary_dispatch(d, req, now_mono_ns, req_start_mono_ns, ctx, res);
    guard ok_prep else { return true; }

    var req_payload: u8[>..] = [];
    guard decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }

    var res_payload: u8[>..] = [];
    let st = on_grpc_unary(stage, handler_id, ctx, req_payload[..], res_payload);
    if st.code != GrpcStatusCode.Ok && res_payload.len == 0 {
        build_grpc_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        var lpm_response: u8[>..] = [];
        encode_grpc_lpm(res_payload[..], lpm_response, false);
        build_grpc_wire_response(st.code, st.message[..], lpm_response[..], ctx, res);
    }
    return true;
}

// Server-Streaming RPC Dispatcher:
// Handler sends 0, 1, or multiple messages through GrpcServerStreamWriter.
fn dispatch_grpc_server_streaming<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], GrpcServerStreamWriter&) -> GrpcStatus,
>(
    d:                 const GrpcServerDispatcher&,
    req:               const Request&,
    now_mono_ns:       u64,
    res:               Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard is_grpc_request(req) else { return false; }
    var ctx = GrpcServerContext { .. };
    init_grpc_context_transport(req, ctx);

    if !req.method[..].eq_ascii_fold("POST") {
        build_grpc_trailers_only_response(GrpcStatusCode.Internal, "HTTP method must be POST", ctx, res);
        return true;
    }

    let ctx_st = extract_grpc_server_context_status(req, ctx, now_mono_ns, req_start_mono_ns);
    if ctx_st != GrpcStatusCode.Ok {
        let ctx_msg = if ctx_st == GrpcStatusCode.Unimplemented {
            "Malformed gRPC URI path"
        } else {
            "Malformed gRPC request headers"
        };
        build_grpc_trailers_only_response(ctx_st, ctx_msg, ctx, res);
        return true;
    }

    var path_buf: u8[..260] = [];
    path_buf.push('/');
    path_buf.append(ctx.service[..]);
    path_buf.push('/');
    path_buf.append(ctx.method[..]);

    let method_idx = find_method(d, path_buf[..]);
    if method_idx < 0 {
        var err_msg: u8[..256] = [];
        err_msg.append("Method not found: ");
        err_msg.append(path_buf[..]);
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, err_msg[..], ctx, res);
        return true;
    }

    let entry = d.methods[method_idx];
    if ctx.is_web && !d.enable_web {
        build_grpc_trailers_only_response(GrpcStatusCode.PermissionDenied, "gRPC-Web transport disabled", ctx, res);
        return true;
    }
    if entry.method_type != GrpcMethodType.ServerStreaming {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return true;
    }

    if is_deadline_exceeded(ctx, now_mono_ns) {
        build_grpc_trailers_only_response(
            GrpcStatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
        );
        return true;
    }

    var req_payload: u8[>..] = [];
    guard decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }

    var writer = GrpcServerStreamWriter { .. };
    let st = HandlerFn(entry.handler_id, ctx, req_payload[..], writer);

    if st.code != GrpcStatusCode.Ok && writer.body.len == 0 {
        build_grpc_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        build_grpc_wire_response(st.code, st.message[..], writer.body[..], ctx, res);
    }

    return true;
}

fn append_decompressed_stream_span(
    raw_msg:   const u8[:],
    span:      GrpcMessageSpan,
    max_size:  u32,
    ctx:       const GrpcServerContext&,
    res:       Response&,
    new_wire:  u8[>..]&,
    new_spans: GrpcMessageSpan[..32]&,
) -> bool {
    let offset_start = new_wire.len as u32;
    if !span.compressed {
        new_wire.append(raw_msg);
        new_spans.push(GrpcMessageSpan { offset: offset_start, len: span.len, compressed: false });
        return true;
    }
    let ok_gz, gz_err = core::gzip_decompress_with_limit(raw_msg, new_wire, max_size);
    guard ok_gz else {
        let is_overflow = gz_err == core::CompressError.OutputBufferOverflow;
        let code = if is_overflow { GrpcStatusCode.ResourceExhausted } else { GrpcStatusCode.Internal };
        build_grpc_trailers_only_response(code, "Failed to decompress client stream message", ctx, res);
        return false;
    }
    let decomp_len = core::sub_sat_u64(new_wire.len as u64, offset_start) as u32;
    new_spans.push(GrpcMessageSpan { offset: offset_start, len: decomp_len, compressed: false });
    return true;
}

fn validate_and_decompress_client_stream(
    reader:   GrpcClientStreamReader&,
    max_size: u32,
    ctx:      const GrpcServerContext&,
    res:      Response&,
) -> bool {
    let enc = get_metadata(ctx, rfc::HEADER_GRPC_ENCODING).trim_lws();
    guard is_supported_grpc_encoding(enc) else {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Unsupported grpc-encoding", ctx, res);
        return false;
    }
    var any_compressed = false;
    for &span in reader.spans {
        if span.compressed {
            any_compressed = true;
        } else if span.len > max_size {
            build_grpc_trailers_only_response(
                GrpcStatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
            );
            return false;
        }
    }
    guard any_compressed else { return true; }
    guard enc.eq_ascii_fold("gzip") else {
        build_grpc_trailers_only_response(
            GrpcStatusCode.Internal, "Compressed frame without compression encoding", ctx, res,
        );
        return false;
    }

    var new_wire:  u8[>..]               = [];
    var new_spans: GrpcMessageSpan[..32] = [];
    for i in reader.spans.len {
        let span = reader.spans[i];
        let raw_msg = get_client_stream_message(reader, i);
        guard append_decompressed_stream_span(raw_msg, span, max_size, ctx, res, new_wire, new_spans) else {
            return false;
        }
    }
    reader.wire.clear();
    reader.wire.append(new_wire[..]);
    reader.spans = new_spans;
    return true;
}

// Client-Streaming RPC Dispatcher:
// Parses all received LPM messages from the request body into GrpcClientStreamReader.
fn dispatch_grpc_client_streaming<
    HandlerFn: fn(u16, GrpcServerContext&, const GrpcClientStreamReader&, u8[>..]&) -> GrpcStatus,
>(
    d:                 const GrpcServerDispatcher&,
    req:               const Request&,
    now_mono_ns:       u64,
    res:               Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard is_grpc_request(req) else { return false; }
    var ctx = GrpcServerContext { .. };
    init_grpc_context_transport(req, ctx);

    if !req.method[..].eq_ascii_fold("POST") {
        build_grpc_trailers_only_response(GrpcStatusCode.Internal, "HTTP method must be POST", ctx, res);
        return true;
    }

    let ctx_st = extract_grpc_server_context_status(req, ctx, now_mono_ns, req_start_mono_ns);
    if ctx_st != GrpcStatusCode.Ok {
        let ctx_msg = if ctx_st == GrpcStatusCode.Unimplemented {
            "Malformed gRPC URI path"
        } else {
            "Malformed gRPC request headers"
        };
        build_grpc_trailers_only_response(ctx_st, ctx_msg, ctx, res);
        return true;
    }

    var path_buf: u8[..260] = [];
    path_buf.push('/');
    path_buf.append(ctx.service[..]);
    path_buf.push('/');
    path_buf.append(ctx.method[..]);

    let method_idx = find_method(d, path_buf[..]);
    if method_idx < 0 {
        var err_msg: u8[..256] = [];
        err_msg.append("Method not found: ");
        err_msg.append(path_buf[..]);
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, err_msg[..], ctx, res);
        return true;
    }

    let entry = d.methods[method_idx];
    if ctx.is_web && !d.enable_web {
        build_grpc_trailers_only_response(GrpcStatusCode.PermissionDenied, "gRPC-Web transport disabled", ctx, res);
        return true;
    }
    if entry.method_type != GrpcMethodType.ClientStreaming {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return true;
    }

    if is_deadline_exceeded(ctx, now_mono_ns) {
        build_grpc_trailers_only_response(
            GrpcStatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
        );
        return true;
    }

    var reader = GrpcClientStreamReader { .. };
    let ok_stream = parse_client_stream(req.body[..], ctx.is_web_text, reader);
    if !ok_stream {
        build_grpc_trailers_only_response(
            GrpcStatusCode.InvalidArgument, "Malformed client stream LPM frames", ctx, res,
        );
        return true;
    }

    guard validate_and_decompress_client_stream(reader, d.max_message_size, ctx, res) else {
        return true;
    }

    var res_payload: u8[>..] = [];
    let st = HandlerFn(entry.handler_id, ctx, reader, res_payload);

    if st.code != GrpcStatusCode.Ok && res_payload.len == 0 {
        build_grpc_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        var lpm_response: u8[>..] = [];
        encode_grpc_lpm(res_payload[..], lpm_response, false);
        build_grpc_wire_response(st.code, st.message[..], lpm_response[..], ctx, res);
    }

    return true;
}

// ---- Bidirectional Streaming LPM Coordinator -----------------------------

enum H2StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

struct H2Stream {
    stream_id:               u32           = 0,
    state:                   H2StreamState = H2StreamState.Open,
    send_window:             i64           = 65535,
    recv_window:             i64           = 65535,
    pending_send_bytes:      u32           = 0,
    declared_content_length: i64           = -1,
    received_data_bytes:     i64           = 0,
    headers_received:        bool          = false,
    trailers_received:       bool          = false,
    status_code:             i32           = 0,
    active:                  bool          = true,
}

// Bounded zero-allocation Length-Prefixed Message (LPM) stream reader (Invariant 10 & 13).
struct GrpcLpmReader {
    spans:        GrpcMessageSpan[..32] = [],
    wire_buf:     u8[..16384]           = [],
    read_cursor:  i64                   = 0,
    max_msg_size: u32                   = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
}

// Bounded zero-allocation Length-Prefixed Message (LPM) stream writer (Invariant 13).
struct GrpcLpmWriter {
    message_count: u32         = 0,
    wire_buf:      u8[..16384] = [],
}

// Feeds raw wire bytes into `GrpcLpmReader` and parses complete 5-byte LPM frames.
// Rejects truncated frames, invalid compression flags, or capacity overflows (Invariant 13).
fn feed_grpc_lpm_reader(reader: GrpcLpmReader&, raw: const u8[:]) -> bool {
    var committed = false;
    defer if !committed {
        reader.wire_buf.clear();
        reader.spans.clear();
        reader.read_cursor = 0;
    };
    guard reader.wire_buf.try_set(raw) else { return false; }
    reader.spans.clear();
    reader.read_cursor = 0;

    var idx: u64 = 0;
    let wire_slice = reader.wire_buf[..];
    let total_len = wire_slice.len as u64;
    let limit = if reader.max_msg_size > 0 {
        reader.max_msg_size
    } else {
        rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE
    };

    while core::add_sat_u64(idx, rfc::GRPC_LPM_HEADER_LEN) <= total_len {
        let flag = wire_slice[idx as i64];
        guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else { return false; }
        let is_comp = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

        let hdr_off = (core::add_sat_u64(idx, 1)) as i64;
        let len_val = core::read_be_u32(wire_slice, hdr_off);
        guard len_val <= limit else { return false; }
        idx = core::add_sat_u64(idx, 5);

        let payload_offset = idx as u32;
        let next_idx = core::add_sat_u64(idx, len_val);
        guard next_idx <= total_len else { return false; }
        idx = next_idx;

        let span = GrpcMessageSpan {
            offset:     payload_offset,
            len:        len_val,
            compressed: is_comp,
        };
        guard reader.spans.try_push(span) else { return false; }
    }

    guard idx == total_len else { return false; }
    committed = true;
    return true;
}

// Reads the next zero-copy message slice from `GrpcLpmReader` and advances `read_cursor`.
//
// Example:
//   reader has 1 frame "ping" at span 0, reader.read_cursor = 0
//   returns: ("ping", true), reader.read_cursor = 1
fn read_next_grpc_lpm(reader: GrpcLpmReader&) -> const u8[:], bool {
    guard reader.read_cursor >= 0 && reader.read_cursor < reader.spans.len else {
        return "", false;
    }
    let span = reader.spans[reader.read_cursor];
    let start = span.offset as i64;
    let end = (core::add_sat_u64(span.offset, span.len)) as i64;
    guard end <= reader.wire_buf.len else { return "", false; }
    reader.read_cursor = (core::add_sat_u64(reader.read_cursor as u64, 1)) as i64;
    return reader.wire_buf[start..end], true;
}

// Encodes and appends a single LPM frame into `GrpcLpmWriter` with fail-closed bounds checking.
fn write_grpc_lpm_frame(
    writer:     GrpcLpmWriter&,
    payload:    const u8[:],
    compressed: bool = false,
) -> bool {
    let frame_len = core::add_sat_u64(5, payload.len as u64);
    let total_needed = core::add_sat_u64(writer.wire_buf.len as u64, frame_len);
    guard total_needed <= (writer.wire_buf.cap as u64) else { return false; }

    let flag: u8 = if compressed { rfc::GRPC_FLAG_COMPRESSED } else { 0x00 };
    writer.wire_buf.push(flag);
    writer.wire_buf.append_u32_be(payload.len as u32);
    writer.wire_buf.append(payload);
    writer.message_count = (core::add_sat_u64(writer.message_count, 1)) as u32;
    return true;
}

// Coordinates full-duplex bidirectional streaming of Length-Prefixed Messages (LPM)
// over an active HTTP/2 stream (`H2Stream`), enforcing flow-control window bounds and
// RFC 9113 stream state validity.
fn dispatch_grpc_bidi_streaming(
    conn:   H2Stream&,
    reader: GrpcLpmReader&,
    writer: GrpcLpmWriter&,
) -> bool {
    guard conn.state == H2StreamState.Open || conn.state == H2StreamState.HalfClosedRemote else {
        return false;
    }
    let start_cursor = reader.read_cursor;
    let prev_out = writer.wire_buf.len;
    let prev_count = writer.message_count;
    var committed = false;
    defer if !committed {
        reader.read_cursor = start_cursor;
        writer.wire_buf.resize(prev_out);
        writer.message_count = prev_count;
    };

    let limit = if reader.max_msg_size > 0 {
        reader.max_msg_size
    } else {
        rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE
    };
    var consumed_in: i64 = 0;
    while reader.read_cursor < reader.spans.len {
        let span = reader.spans[reader.read_cursor];
        let msg, ok = read_next_grpc_lpm(reader);
        guard ok else { return false; }
        let frame_in = core::add_sat_i64(5, span.len);
        consumed_in = core::add_sat_i64(consumed_in, frame_in);
        if span.compressed {
            var decomp_buf: u8[..16384] = [];
            let ok_gz, _ = core::gzip_decompress_with_limit(msg, decomp_buf, limit);
            guard ok_gz else { return false; }
            guard write_grpc_lpm_frame(writer, decomp_buf[..], false) else { return false; }
        } else {
            guard write_grpc_lpm_frame(writer, msg, false) else { return false; }
        }
    }

    let delta_out = core::sub_sat_i64(writer.wire_buf.len, prev_out);
    guard conn.recv_window >= consumed_in && conn.send_window >= delta_out else {
        return false;
    }

    let next_recvd = core::add_sat_u64(conn.received_data_bytes as u64, consumed_in as u64);
    conn.received_data_bytes = next_recvd as i64;
    conn.recv_window = (core::sub_sat_u64(conn.recv_window as u64, consumed_in as u64)) as i64;
    conn.send_window = (core::sub_sat_u64(conn.send_window as u64, delta_out as u64)) as i64;
    conn.pending_send_bytes = writer.wire_buf.len as u32;
    committed = true;
    return true;
}

// ---- Public Server Pipeline & Transport Integration ---------------------

fn emit_grpc_h2_response_frames<B>(
    hpack_enc: h2_internal::DynamicTable&,
    stream_id: u32,
    res:       const Response&,
    out:       B&,
) {
    let end_hdr = res.body.len == 0 && res.trailers.entries.len == 0;
    let code_val = if res.status_code > 0 { res.status_code as i32 } else { 200 };
    let status_pseudo = h2_internal::H2PseudoHeaders {
        status:     code_val,
        has_status: true,
        ..
    };
    let _ = wire::encode_h2_headers_frame_from_map(
        hpack_enc, stream_id, status_pseudo, res.headers, end_hdr, out,
    );

    if res.body.len > 0 {
        let has_trailers = res.trailers.entries.len > 0;
        var offset: i64 = 0;
        while offset < res.body.len {
            let rem = core::sub_sat_i64(res.body.len, offset);
            let chunk_len = min(rem, rfc::H2_DEFAULT_MAX_FRAME_SIZE as i64);
            let next_offset = core::add_sat_i64(offset, chunk_len);
            let is_last = next_offset >= res.body.len;
            let end_data = is_last && !has_trailers;
            let _ = wire::encode_data_frame(
                stream_id, res.body[offset..next_offset], end_data, out,
            );
            offset = next_offset;
        }
    }

    if res.trailers.entries.len > 0 {
        let tr_pseudo = h2_internal::H2PseudoHeaders {
            is_trailer: true,
            ..
        };
        let _ = wire::encode_h2_headers_frame_from_map(
            hpack_enc, stream_id, tr_pseudo, res.trailers, true, out,
        );
    }
}

fn slice_grpc_h2_headers_fragment(
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

fn execute_grpc_server_unary<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    server:    HttpServer&,
    d:         const GrpcServerDispatcher&,
    client_ip: const u8[:],
    req:       const Request&,
    res:       Response&,
) {
    server.pipeline.trust_proxy_headers = server.trust_proxy_headers;
    let now_ns = core::as_nanos(core::monotonic_now());
    var future = server_internal::new_inline_handler_future(0);
    let outcome = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    if outcome == PipelineOutcome.RouteNotFound {
        let _ = dispatch_grpc_unary(d, req, now_ns, res, HandlerFn);
    }
}

inline fn is_valid_h2_settings_frame(hdr: const wire::WireFrameHeader&) -> bool {
    let pay_u64: u64 = hdr.length;
    let is_mult6 = core::mul_sat_u64(grpc_div_u64(pay_u64, 6), 6) == pay_u64;
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

fn handle_grpc_h2_control_frame(
    conn:    i64,
    hdr:     const wire::WireFrameHeader&,
    payload: const u8[:],
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS {
        guard is_valid_h2_settings_frame(hdr) && payload.len == hdr.length else { return false; }
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
            guard validate_h2_settings_payload(payload) else { return false; }
            var ack: u8[..16] = [];
            let ack_hdr = wire::WireFrameHeader {
                length:     0,
                frame_type: rfc::H2_FRAME_SETTINGS,
                flags:      rfc::H2_FLAG_ACK,
                stream_id:  0,
            };
            let _ = wire::encode_frame_header(ack_hdr, ack);
            let _ = tcp_send(conn, ack[..]);
        }
        return true;
    }
    if hdr.frame_type == rfc::H2_FRAME_PING {
        guard hdr.stream_id == 0 && payload.len == 8 else { return false; }
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
            var ping_data: u8[8] = [0; 8];
            for p in 8 { ping_data[p] = payload[p]; }
            var pong: u8[..24] = [];
            let _ = wire::encode_ping_frame(ping_data, true, pong);
            let _ = tcp_send(conn, pong[..]);
        }
        return true;
    }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE {
        guard payload.len == 4 else { return false; }
        let inc = core::read_be_u32(payload, 0) & 0x7FFFFFFF;
        return inc >= 1 && inc <= rfc::H2_MAX_WINDOW_SIZE;
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM {
        return hdr.stream_id > 0 && (hdr.stream_id & 1) == 1 && payload.len == 4;
    }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY {
        guard hdr.stream_id > 0 && payload.len == 5 else { return false; }
        let dep_id = core::read_be_u32(payload, 0) & 0x7FFFFFFF;
        return dep_id != hdr.stream_id;
    }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY {
        guard hdr.stream_id == 0 && payload.len >= 8 else { return false; }
        return false;
    }
    if hdr.frame_type == rfc::H2_FRAME_PUSH_PROMISE || hdr.frame_type == rfc::H2_FRAME_CONTINUATION {
        return false;
    }
    return true;
}

inline fn slice_grpc_h2_data_payload(payload: const u8[:], flags: u8) -> const u8[:], bool {
    if (flags & rfc::H2_FLAG_PADDED) == 0 {
        return payload, true;
    }
    guard payload.len > 0 else { return "", false; }
    let pad_len = payload[0] as i64;
    let data_end = core::sub_sat_i64(payload.len, pad_len);
    guard 1 <= data_end && pad_len < payload.len else { return "", false; }
    return payload[1..data_end], true;
}

fn handle_grpc_h2_wire_frame<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    conn:              i64,
    server:            HttpServer&,
    d:                 const GrpcServerDispatcher&,
    client_ip:         const u8[:],
    hpack_dec:         h2_internal::DynamicTable&,
    hpack_enc:         h2_internal::DynamicTable&,
    pending:           Request&,
    pending_stream_id: u32&,
    hdr:               const wire::WireFrameHeader&,
    payload:           const u8[:],
    out_wire:          u8[..65536]&,
) -> bool {
    guard hdr.length <= rfc::H2_DEFAULT_MAX_FRAME_SIZE && payload.len == hdr.length else {
        return false;
    }
    if hdr.frame_type != rfc::H2_FRAME_HEADERS && hdr.frame_type != rfc::H2_FRAME_DATA {
        let ok_ctrl = handle_grpc_h2_control_frame(conn, hdr, payload);
        if ok_ctrl && hdr.frame_type == rfc::H2_FRAME_RST_STREAM && hdr.stream_id == pending_stream_id {
            reset_server_request_fast(pending);
            pending_stream_id = 0;
        }
        return ok_ctrl;
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        guard hdr.stream_id > 0 && (hdr.stream_id & 1) == 1
            && (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0
            && pending_stream_id == 0
            && pending.headers.entries.len == 0 else {
            return false;
        }
        let frag, ok_frag = slice_grpc_h2_headers_fragment(payload, hdr.flags, hdr.stream_id);
        guard ok_frag else { return false; }
        var pseudo = h2_internal::H2PseudoHeaders { .. };
        reset_server_request_fast(pending);
        let _ = pending.method.try_set("POST");
        let hpack_res = h2_internal::decode_hpack_to_map(
            hpack_dec, frag, pseudo, pending.headers, 8192, true,
        );
        guard hpack_res == rfc::H2_ERR_NO_ERROR
            && pseudo.has_method
            && !pseudo.has_status
            && !pseudo.has_protocol else {
            reset_server_request_fast(pending);
            return false;
        }
        pending_stream_id = hdr.stream_id;
        if pseudo.method.len > 0 {
            let _ = pending.method.try_set(pseudo.method[..]);
        }
        if pseudo.path.len > 0 {
            let _ = pending.url.try_set(pseudo.path[..]);
        } else {
            pending.url.clear();
        }
        if pseudo.authority.len > 0 && header(pending, "host").len == 0 {
            let _ = append_header(pending.headers, "host", pseudo.authority[..]);
        }
        if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
            var res = Response { .. };
            execute_grpc_server_unary(server, d, client_ip, pending, res, HandlerFn);
            out_wire.clear();
            emit_grpc_h2_response_frames(hpack_enc, hdr.stream_id, res, out_wire);
            if out_wire.len > 0 {
                let _ = tcp_send(conn, out_wire[..]);
            }
            reset_server_request_fast(pending);
            pending_stream_id = 0;
        }
        return true;
    }
    guard hdr.stream_id > 0 &&
        hdr.stream_id == pending_stream_id &&
        pending.headers.entries.len > 0 else {
        return false;
    }
    let data_slice, ok_data = slice_grpc_h2_data_payload(payload, hdr.flags);
    guard ok_data else { return false; }
    let max_body = max(
        core::add_sat_u64(d.max_message_size, rfc::GRPC_LPM_HEADER_LEN),
        core::add_sat_u64(rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE, rfc::GRPC_LPM_HEADER_LEN),
    );
    guard core::add_sat_u64(pending.body.len as u64, data_slice.len as u64) <= max_body else {
        reset_server_request_fast(pending);
        pending_stream_id = 0;
        return false;
    }
    pending.body.append(data_slice);
    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        var res = Response { .. };
        execute_grpc_server_unary(server, d, client_ip, pending, res, HandlerFn);
        out_wire.clear();
        emit_grpc_h2_response_frames(hpack_enc, hdr.stream_id, res, out_wire);
        if out_wire.len > 0 {
            let _ = tcp_send(conn, out_wire[..]);
        }
        reset_server_request_fast(pending);
        pending_stream_id = 0;
    }
    return true;
}

fn drain_grpc_h2_frames<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    conn_fd:           i64,
    server:            HttpServer&,
    d:                 const GrpcServerDispatcher&,
    peer_ip:           const u8[:],
    hpack_dec:         h2_internal::DynamicTable&,
    hpack_enc:         h2_internal::DynamicTable&,
    pending:           Request&,
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
        is_running = handle_grpc_h2_wire_frame(
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

// Serves a gRPC over HTTP/2 connection session on `conn_fd` through `server.pipeline` and `d`.
fn serve_grpc_h2_connection<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    server:      HttpServer&,
    d:           const GrpcServerDispatcher&,
    conn_fd:     i64,
    initial_buf: const u8[:],
) {
    let empty_settings: wire::WireSetting[0] = [];
    var srv_set_wire: u8[..16] = [];
    let _ = wire::encode_settings_frame(empty_settings[..], srv_set_wire);
    let _ = tcp_send(conn_fd, srv_set_wire[..]);

    var peer_ip: u8[..64] = [];
    tcp_get_peer_ip(conn_fd, peer_ip);

    var hpack_dec = h2_internal::new_dynamic_table(4096);
    var hpack_enc = h2_internal::new_dynamic_table(4096);
    var pending = new_request("POST", "");
    var pending_stream_id: u32 = 0;

    var in_buf:   u8[..65536] = [];
    var out_wire: u8[..65536] = [];
    var chunk:    u8[..4096]  = [];

    if initial_buf.len > 24 {
        guard in_buf.try_append(initial_buf[24..]) else { return; }
    }

    var is_running = true;
    while is_running {
        is_running = drain_grpc_h2_frames(
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
        let recvd = tcp_recv(conn_fd, chunk, 4096, 50);
        if recvd == -2 {
            continue;
        }
        let next_in = core::add_sat_i64(in_buf.len, recvd as i64);
        guard next_in <= in_buf.cap && try_append_recv_chunk(recvd, chunk, in_buf) else {
            break;
        }
    }
}

// Processes a gRPC-Web HTTP/1.1 request wire buffer through `server.pipeline` and `d`,
// sending the serialized response over `conn_fd`.
fn serve_grpc_web_http1<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    server:  HttpServer&,
    d:       const GrpcServerDispatcher&,
    conn_fd: i64,
    req_raw: const u8[:],
) {
    var out_wire: u8[..65536] = [];
    var req = new_request("GET", "");
    let ok_parse, _ = parse_http1_wire_request(req_raw, req);
    guard ok_parse else {
        serialize_bad_request_error(server.server_name[..], out_wire);
        let _ = tcp_send(conn_fd, out_wire[..]);
        return;
    }

    var peer_ip: u8[..64] = [];
    tcp_get_peer_ip(conn_fd, peer_ip);

    var res = Response { .. };
    execute_grpc_server_unary(server, d, peer_ip[..], req, res, HandlerFn);

    serialize_http1_response(res, server.server_name[..], out_wire);
    let _ = tcp_send(conn_fd, out_wire[..]);
}

fn try_dispatch_grpc_connection_turn<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    server:  HttpServer&,
    d:       const GrpcServerDispatcher&,
    conn_fd: i64,
    in_buf:  const u8[:],
) -> bool {
    guard !is_partial_h2_client_preface(in_buf) else {
        return false;
    }
    if is_h2_client_preface(in_buf) {
        serve_grpc_h2_connection(server, d, conn_fd, in_buf, HandlerFn);
        return true;
    }
    var hdr_scan_cursor: i64 = 0;
    guard has_ready_http1_request(in_buf, hdr_scan_cursor) else {
        return false;
    }
    if core::starts_with(in_buf, "GET /shutdown") {
        var out_wire: u8[..4096] = [];
        let _, _ = handle_connection_wire(server, "127.0.0.1", in_buf, 0, out_wire);
        let _ = tcp_send(conn_fd, out_wire[..]);
        server.is_running = false;
        return true;
    }
    serve_grpc_web_http1(server, d, conn_fd, in_buf, HandlerFn);
    return true;
}

// Serves a gRPC connection (HTTP/2 h2c, gRPC-Web HTTP/1.1, or `/shutdown` probe) on `conn_fd`.
fn serve_grpc_connection<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    server:  HttpServer&,
    d:       const GrpcServerDispatcher&,
    conn_fd: i64,
) {
    var in_buf:     u8[..65536] = [];
    var chunk:      u8[..4096]  = [];
    var wait_ticks: u64         = 0;

    while wait_ticks < 20 {
        chunk.clear();
        let recvd = tcp_recv(conn_fd, chunk, 4096, 100);
        if recvd == -2 {
            wait_ticks = core::add_sat_u64(wait_ticks, 1);
            continue;
        }
        let next_in = core::add_sat_i64(in_buf.len, recvd as i64);
        guard next_in <= in_buf.cap && try_append_recv_chunk(recvd, chunk, in_buf) else {
            break;
        }
        wait_ticks = 0;

        if try_dispatch_grpc_connection_turn(server, d, conn_fd, in_buf[..], HandlerFn) {
            return;
        }
    }
}

// Runs the accept loop on `listener_fd`, serving gRPC (h2c and gRPC-Web) connections.
fn serve_grpc_listener<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&) -> GrpcStatus,
>(
    listener_fd: i64,
    server:      HttpServer&,
    d:           const GrpcServerDispatcher&,
) {
    server.is_running = true;
    while server.is_running {
        let conn = tcp_accept(listener_fd, 200);
        if conn < 0 {
            continue;
        }
        serve_grpc_connection(server, d, conn, HandlerFn);
        tcp_close(conn);
    }
}
