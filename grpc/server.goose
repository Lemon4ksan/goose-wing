// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC server dispatcher.
// Implements RFC gRPC over HTTP/2, RFC 7540/9113 framing, and RFC gRPC-Web (binary and text).
namespace wing;

import std;
import grpc.constants;
import grpc.framing;
import grpc.status;
import http.headers;
import client.request;
import client.response;
import core from "..";

// Wire protocol constants

inline fn matches_grpc_media_type(ct: const u8[:], prefix: const u8[:]) -> bool {
    guard starts_with_fold(ct, prefix) else { return false; }
    if ct.len == prefix.len { return true; }
    let next_byte = ct[prefix.len];
    return next_byte == '+' || next_byte == ';' || next_byte == ' ' || next_byte == '\t';
}

// Returns true if Content-Type matches standard gRPC, gRPC-Web, or gRPC-Web-Text
fn is_grpc_content_type(ct: const u8[:]) -> bool {
    let trimmed = trim_lws(ct);
    return matches_grpc_media_type(trimmed, rfc::GRPC_CONTENT_TYPE) ||
           matches_grpc_media_type(trimmed, rfc::GRPC_WEB_CONTENT_TYPE) ||
           matches_grpc_media_type(trimmed, rfc::GRPC_WEB_TEXT_CONTENT_TYPE);
}

// Returns true if Content-Type indicates gRPC-Web (binary or text)
fn is_grpc_web(ct: const u8[:]) -> bool {
    let trimmed = trim_lws(ct);
    return matches_grpc_media_type(trimmed, rfc::GRPC_WEB_CONTENT_TYPE) ||
           matches_grpc_media_type(trimmed, rfc::GRPC_WEB_TEXT_CONTENT_TYPE);
}

// Returns true if Content-Type is specifically gRPC-Web-Text (Base64 encoded)
fn is_grpc_web_text(ct: const u8[:]) -> bool {
    let trimmed = trim_lws(ct);
    return matches_grpc_media_type(trimmed, rfc::GRPC_WEB_TEXT_CONTENT_TYPE);
}

// Inspects an incoming Request to determine if it is a gRPC call
fn is_grpc_request(req: const Request&) -> bool {
    let ct = req.header("content-type");
    return ct.len > 0 && is_grpc_content_type(ct);
}

// Parses standard gRPC URI path: `/{service}/{method}` or `/{package}.{service}/{method}`.
// Returns (ok) and populates out_service and out_method.
//
// Example:
//   path = "/helloworld.Greeter/SayHello"
//   returns: ok = true, out_service = "helloworld.Greeter", out_method = "SayHello"
fn parse_grpc_path(
    path:        const u8[:],
    out_service: u8[..64]&,
    out_method:  u8[..64]&,
) -> bool {
    out_service.clear();
    out_method.clear();

    guard path.len >= 3 && path[0] == '/' else { return false; }

    var slash2: i64 = -1;
    for i in 1..path.len {
        if path[i] == '/' {
            slash2 = i;
            break;
        }
    }
    let last_valid = (core::sub_sat_u64(path.len as u64, 1)) as i64;
    guard slash2 > 1 && slash2 < last_valid else { return false; }

    let method_start = (core::add_sat_u64(slash2 as u64, 1)) as i64;
    let service_part = path[1..slash2];
    let method_part = path[method_start..];

    guard service_part.len <= 64 && method_part.len <= 64 else { return false; }

    out_service.append(service_part);
    out_method.append(method_part);
    return true;
}

// ---- Server Invocation Context ------------------------------------------

struct GrpcServerContext {
    service:           u8[..64]           = [],
    method:            u8[..64]           = [],
    peer_ip:           u8[..48]           = [],
    timeout_ms:        u64                = 0,
    deadline_mono_ns:  u64                = 0,
    is_web:            bool               = false,
    is_web_text:       bool               = false,
    metadata:          GrpcMetadata[..16] = [],
    response_metadata: GrpcMetadata[..16] = [],
    response_trailers: GrpcMetadata[..16] = [],
}

fn get_metadata(ctx: const GrpcServerContext&, key: const u8[:]) -> const u8[:] {
    for &m in ctx.metadata {
        if eq_ascii_fold(m.key[..], key) {
            return m.value[..];
        }
    }
    return "";
}

fn add_response_metadata(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool {
    guard ctx.response_metadata.len < ctx.response_metadata.cap else { return false; }
    var item = GrpcMetadata { .. };
    item.key.append(key);
    item.value.append(value);
    ctx.response_metadata.push(item);
    return true;
}

fn add_response_trailer(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool {
    guard ctx.response_trailers.len < ctx.response_trailers.cap else { return false; }
    var item = GrpcMetadata { .. };
    item.key.append(key);
    item.value.append(value);
    ctx.response_trailers.push(item);
    return true;
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

struct GrpcMethodEntry {
    service:     u8[..64]       = [],
    method:      u8[..64]       = [],
    full_path:   u8[..128]      = [],
    method_type: GrpcMethodType = GrpcMethodType.Unary,
    handler_id:  u16            = 0,
}

struct GrpcServerDispatcher {
    methods:          GrpcMethodEntry[..64] = [],
    max_message_size: u32                   = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    enable_web:       bool                  = true,
}

fn new_grpc_server_dispatcher(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcServerDispatcher {
    return GrpcServerDispatcher {
        methods:          [],
        max_message_size: max_msg_size,
        enable_web:       true,
    };
}

fn register_method(
    d:           GrpcServerDispatcher&,
    service:     const u8[:],
    method:      const u8[:],
    method_type: GrpcMethodType,
    handler_id:  u16,
) -> bool {
    guard d.methods.len < d.methods.cap else { return false; }
    var entry = GrpcMethodEntry {
        method_type: method_type,
        handler_id:  handler_id,
        ..
    };
    entry.service.append(service);
    entry.method.append(method);

    entry.full_path.push('/');
    entry.full_path.append(service);
    entry.full_path.push('/');
    entry.full_path.append(method);

    d.methods.push(entry);
    return true;
}

fn register_unary(
    d:          GrpcServerDispatcher&,
    service:    const u8[:],
    method:     const u8[:],
    handler_id: u16,
) -> bool {
    return register_method(d, service, method, GrpcMethodType.Unary, handler_id);
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
        let _ = append_header(target, m.key[..], m.value[..]);
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

    if ctx.is_web {
        // gRPC-Web: Trailers are framed in body with flag 0x80
        let ct_val = if ctx.is_web_text { rfc::GRPC_WEB_TEXT_CONTENT_TYPE } else { rfc::GRPC_WEB_CONTENT_TYPE_PROTO };
        let _ = append_header(out_res.headers, "content-type", ct_val);

        append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);

        var raw_trailers: u8[>..] = [];
        encode_grpc_web_trailers_with_meta(status, message, ctx.response_trailers[..], raw_trailers);

        if ctx.is_web_text {
            encode_grpc_web_text(raw_trailers[..], out_res.body);
        } else {
            out_res.body.append(raw_trailers[..]);
        }
    } else {
        // Native HTTP/2 gRPC: Trailers-Only sent in single initial HEADERS frame
        let _ = append_header(out_res.headers, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);

        var st_val: u8[..32] = [];
        format(st_val, grpc_status_to_code(status) as i64);
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

    if ctx.is_web {
        // gRPC-Web
        let ct_val = if ctx.is_web_text { rfc::GRPC_WEB_TEXT_CONTENT_TYPE } else { rfc::GRPC_WEB_CONTENT_TYPE_PROTO };
        let _ = append_header(out_res.headers, "content-type", ct_val);

        append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);

        var web_body: u8[>..] = [];
        web_body.append(raw_lpm_body);
        encode_grpc_web_trailers_with_meta(status, message, ctx.response_trailers[..], web_body);

        if ctx.is_web_text {
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
        format(st_val, grpc_status_to_code(status) as i64);
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
    guard base_ns > 0 && ms > 0 else { return 0; }
    let nanos = core::mul_sat_u64(ms, NANOS_PER_MILLI);
    return core::add_sat_u64(base_ns, nanos);
}

inline fn is_reserved_grpc_header(n: const u8[:]) -> bool {
    if starts_with_fold(n, ":") { return true; }
    if eq_ascii_fold(n, "te") { return true; }
    if eq_ascii_fold(n, "host") { return true; }
    if eq_ascii_fold(n, "connection") { return true; }
    return false;
}

inline fn process_grpc_request_header(
    n:                 const u8[:],
    v:                 const u8[:],
    out_ctx:           GrpcServerContext&,
    now_mono_ns:       u64,
    req_start_mono_ns: u64,
) -> bool {
    if eq_ascii_fold(n, "content-type") {
        out_ctx.is_web = is_grpc_web(v);
        out_ctx.is_web_text = is_grpc_web_text(v);
        return true;
    }
    if eq_ascii_fold(n, rfc::HEADER_GRPC_TIMEOUT) {
        let ms, ok_to = parse_grpc_timeout(v);
        if ok_to {
            out_ctx.timeout_ms = ms;
            let base_ns = if req_start_mono_ns > 0 { req_start_mono_ns } else { now_mono_ns };
            out_ctx.deadline_mono_ns = compute_safe_grpc_deadline(base_ns, ms);
        }
        return true;
    }
    if is_reserved_grpc_header(n) {
        return true;
    }
    guard out_ctx.metadata.len < out_ctx.metadata.cap else { return false; }
    var item = GrpcMetadata { .. };
    item.key.append(n);
    item.value.append(v);
    out_ctx.metadata.push(item);
    return true;
}

// Extracts service, method, timeout, and metadata from incoming HTTP request.
//
// Example:
//   req.url = "/echo.Echo/Ping", req.headers = [content-type: application/grpc]
//   returns: ok = true, out_ctx.service = "echo.Echo", out_ctx.method = "Ping"
fn extract_grpc_server_context(
    req:               const Request&,
    out_ctx:           GrpcServerContext&,
    now_mono_ns:       u64 = 0,
    req_start_mono_ns: u64 = 0,
) -> bool {
    out_ctx.service.clear();
    out_ctx.method.clear();
    out_ctx.metadata.clear();
    out_ctx.response_metadata.clear();
    out_ctx.response_trailers.clear();
    out_ctx.timeout_ms = 0;
    out_ctx.deadline_mono_ns = 0;
    out_ctx.is_web = false;
    out_ctx.is_web_text = false;

    // Parse path: `/{service}/{method}`
    let ok_path = parse_grpc_path(req.url[..], out_ctx.service, out_ctx.method);
    guard ok_path else { return false; }

    for &e in req.headers.entries {
        let ok_hdr = process_grpc_request_header(
            entry_name(req.headers, e),
            entry_value(req.headers, e),
            out_ctx,
            now_mono_ns,
            req_start_mono_ns,
        );
        guard ok_hdr else { return false; }
    }

    return true;
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
        guard out_reader.spans.len < out_reader.spans.cap else { return false; }

        let span = GrpcMessageSpan {
            offset:     payload_offset,
            len:        len_val,
            compressed: is_comp,
        };
        out_reader.spans.push(span);
    }

    guard idx == total_len else { return false; }
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
    let trimmed = trim_lws(enc);
    if trimmed.len == 0 { return true; }
    return eq_ascii_fold(trimmed, "gzip") || eq_ascii_fold(trimmed, "identity");
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
    var wire_bytes: u8[>..] = [];
    if ctx.is_web_text {
        guard decode_grpc_web_text(req.body[..], wire_bytes) else {
            build_grpc_trailers_only_response(
                GrpcStatusCode.InvalidArgument, "Invalid Base64 gRPC-Web-Text payload", ctx, res,
            );
            return false;
        }
    } else {
        wire_bytes.append(req.body[..]);
    }

    var is_compressed = false;
    if wire_bytes.len >= rfc::GRPC_LPM_HEADER_LEN {
        let ok_lpm, consumed = decode_grpc_lpm(wire_bytes[..], 0, req_payload, is_compressed);
        if !ok_lpm || consumed != wire_bytes.len {
            build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Malformed LPM framing", ctx, res);
            return false;
        }
    } else if wire_bytes.len > 0 {
        build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Incomplete 5-byte LPM header", ctx, res);
        return false;
    }

    if is_compressed {
        let enc = get_metadata(ctx, rfc::HEADER_GRPC_ENCODING);
        guard is_supported_grpc_encoding(enc) else {
            build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Unsupported grpc-encoding", ctx, res);
            return false;
        }
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

    return true;
}

// Unary RPC Dispatcher:
// Executes a single Request-Response RPC cycle conforming to RFC gRPC over HTTP/2 and gRPC-Web.
fn dispatch_grpc_unary<HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&, GrpcStatusCode&, u8[..256]&)>(
    d:                 const GrpcServerDispatcher&,
    req:               const Request&,
    now_mono_ns:       u64,
    res:               Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    // 1. Validate gRPC Content-Type
    guard is_grpc_request(req) else { return false; }

    var ctx = GrpcServerContext { .. };

    // 2. Validate HTTP Method (RFC gRPC mandates POST)
    if !eq_ascii_fold(req.method[..], "POST") {
        build_grpc_trailers_only_response(GrpcStatusCode.Internal, "HTTP method must be POST", ctx, res);
        return true;
    }

    // 3. Extract Context & Validate URI Path
    let ok_ctx = extract_grpc_server_context(req, ctx, now_mono_ns, req_start_mono_ns);
    if !ok_ctx {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Malformed gRPC URI path", ctx, res);
        return true;
    }

    // 4. Match Registered Service & Method
    var path_buf: u8[..128] = [];
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
    if entry.method_type != GrpcMethodType.Unary {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return true;
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
    var status = GrpcStatusCode.Ok;
    var message: u8[..256] = [];

    HandlerFn(entry.handler_id, ctx, req_payload[..], res_payload, status, message);

    // 8. Generate Wire Response
    if status != GrpcStatusCode.Ok && res_payload.len == 0 {
        // Pure error without payload -> Trailers-Only response
        build_grpc_trailers_only_response(status, message[..], ctx, res);
    } else {
        // Standard payload + trailers response
        var lpm_response: u8[>..] = [];
        encode_grpc_lpm(res_payload[..], lpm_response, false);
        build_grpc_wire_response(status, message[..], lpm_response[..], ctx, res);
    }

    return true;
}

// Server-Streaming RPC Dispatcher:
// Handler sends 0, 1, or multiple messages through GrpcServerStreamWriter.
fn dispatch_grpc_server_streaming<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], GrpcServerStreamWriter&, GrpcStatusCode&, u8[..256]&),
>(
    d:                 const GrpcServerDispatcher&,
    req:               const Request&,
    now_mono_ns:       u64,
    res:               Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard is_grpc_request(req) else { return false; }
    var ctx = GrpcServerContext { .. };

    if !eq_ascii_fold(req.method[..], "POST") {
        build_grpc_trailers_only_response(GrpcStatusCode.Internal, "HTTP method must be POST", ctx, res);
        return true;
    }

    let ok_ctx = extract_grpc_server_context(req, ctx, now_mono_ns, req_start_mono_ns);
    if !ok_ctx {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Malformed gRPC URI path", ctx, res);
        return true;
    }

    var path_buf: u8[..128] = [];
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
    var status = GrpcStatusCode.Ok;
    var message: u8[..256] = [];

    HandlerFn(entry.handler_id, ctx, req_payload[..], writer, status, message);

    if status != GrpcStatusCode.Ok && writer.body.len == 0 {
        build_grpc_trailers_only_response(status, message[..], ctx, res);
    } else {
        build_grpc_wire_response(status, message[..], writer.body[..], ctx, res);
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
    let decomp_len = (new_wire.len as u32) - offset_start;
    new_spans.push(GrpcMessageSpan { offset: offset_start, len: decomp_len, compressed: false });
    return true;
}

fn validate_and_decompress_client_stream(
    reader:   GrpcClientStreamReader&,
    max_size: u32,
    ctx:      const GrpcServerContext&,
    res:      Response&,
) -> bool {
    let enc = get_metadata(ctx, rfc::HEADER_GRPC_ENCODING);
    var any_compressed = false;
    for &span in reader.spans {
        if span.compressed {
            any_compressed = true;
            guard is_supported_grpc_encoding(enc) else {
                build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Unsupported grpc-encoding", ctx, res);
                return false;
            }
        } else if span.len > max_size {
            build_grpc_trailers_only_response(
                GrpcStatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
            );
            return false;
        }
    }
    guard any_compressed else { return true; }

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
    HandlerFn: fn(u16, GrpcServerContext&, const GrpcClientStreamReader&, u8[>..]&, GrpcStatusCode&, u8[..256]&),
>(
    d:                 const GrpcServerDispatcher&,
    req:               const Request&,
    now_mono_ns:       u64,
    res:               Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard is_grpc_request(req) else { return false; }
    var ctx = GrpcServerContext { .. };

    if !eq_ascii_fold(req.method[..], "POST") {
        build_grpc_trailers_only_response(GrpcStatusCode.Internal, "HTTP method must be POST", ctx, res);
        return true;
    }

    let ok_ctx = extract_grpc_server_context(req, ctx, now_mono_ns, req_start_mono_ns);
    if !ok_ctx {
        build_grpc_trailers_only_response(GrpcStatusCode.Unimplemented, "Malformed gRPC URI path", ctx, res);
        return true;
    }

    var path_buf: u8[..128] = [];
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
    var status = GrpcStatusCode.Ok;
    var message: u8[..256] = [];

    HandlerFn(entry.handler_id, ctx, reader, res_payload, status, message);

    if status != GrpcStatusCode.Ok && res_payload.len == 0 {
        build_grpc_trailers_only_response(status, message[..], ctx, res);
    } else {
        var lpm_response: u8[>..] = [];
        encode_grpc_lpm(res_payload[..], lpm_response, false);
        build_grpc_wire_response(status, message[..], lpm_response[..], ctx, res);
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
    guard raw.len <= reader.wire_buf.cap else { return false; }
    reader.wire_buf.clear();
    reader.spans.clear();
    reader.read_cursor = 0;
    reader.wire_buf.append(raw);

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

        guard reader.spans.len < reader.spans.cap else { return false; }
        let span = GrpcMessageSpan {
            offset:     payload_offset,
            len:        len_val,
            compressed: is_comp,
        };
        reader.spans.push(span);
    }

    guard idx == total_len else { return false; }
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
    core::write_be_u32(writer.wire_buf, payload.len as u32);
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
    let in_len = reader.wire_buf.len;
    guard in_len >= 0 && conn.recv_window >= in_len else { return false; }

    let limit = if reader.max_msg_size > 0 {
        reader.max_msg_size
    } else {
        rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE
    };
    while reader.read_cursor < reader.spans.len {
        let span = reader.spans[reader.read_cursor];
        let msg, ok = read_next_grpc_lpm(reader);
        guard ok else { return false; }
        if span.compressed {
            var decomp_buf: u8[..16384] = [];
            let ok_gz, _ = core::gzip_decompress_with_limit(msg, decomp_buf, limit);
            guard ok_gz else { return false; }
            guard write_grpc_lpm_frame(writer, decomp_buf[..], false) else { return false; }
        } else {
            guard write_grpc_lpm_frame(writer, msg, false) else { return false; }
        }
    }

    let total_out = writer.wire_buf.len;
    guard total_out >= 0 && conn.send_window >= total_out else { return false; }

    let next_recvd = core::add_sat_u64(conn.received_data_bytes as u64, in_len as u64);
    conn.received_data_bytes = next_recvd as i64;
    conn.recv_window = (core::sub_sat_u64(conn.recv_window as u64, in_len as u64)) as i64;
    conn.send_window = (core::sub_sat_u64(conn.send_window as u64, total_out as u64)) as i64;
    conn.pending_send_bytes = writer.wire_buf.len as u32;
    return true;
}

// ---- Public Server Pipeline & Transport Integration ---------------------

fn emit_grpc_h2_response_frames<B>(
    hpack_enc: internal::DynamicTable&,
    stream_id: u32,
    res:       const Response&,
    out:       B&,
) {
    let end_hdr = res.body.len == 0 && res.trailers.entries.len == 0;
    let status_pseudo = internal::H2PseudoHeaders {
        status:     200,
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
            let chunk_len = min(res.body.len - offset, rfc::H2_DEFAULT_MAX_FRAME_SIZE as i64);
            let is_last = (offset + chunk_len) >= res.body.len;
            let end_data = is_last && !has_trailers;
            let _ = wire::encode_data_frame(
                stream_id, res.body[offset..offset + chunk_len], end_data, out,
            );
            offset += chunk_len;
        }
    }

    if res.trailers.entries.len > 0 {
        let tr_pseudo = internal::H2PseudoHeaders {
            is_trailer: true,
            ..
        };
        let _ = wire::encode_h2_headers_frame_from_map(
            hpack_enc, stream_id, tr_pseudo, res.trailers, true, out,
        );
    }
}

fn slice_grpc_h2_headers_fragment(payload: const u8[:], flags: u8) -> const u8[:], bool {
    var pad_offset: i64 = 0;
    var pay_end:    i64 = payload.len;
    if (flags & rfc::H2_FLAG_PADDED) != 0 {
        guard payload.len > 0 else { return "", false; }
        let pad_len = payload[0] as i64;
        pad_offset += 1;
        pay_end -= pad_len;
    }
    if (flags & rfc::H2_FLAG_PRIORITY) != 0 {
        pad_offset += 5;
    }
    guard pad_offset <= pay_end else { return "", false; }
    return payload[pad_offset..pay_end], true;
}

fn execute_grpc_server_unary<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&, GrpcStatusCode&, u8[..256]&),
>(
    server:    HttpServer&,
    d:         const GrpcServerDispatcher&,
    client_ip: const u8[:],
    req:       const Request&,
    res:       Response&,
) {
    let now_ns = core::as_nanos(core::monotonic_now());
    var future = internal::new_inline_handler_future(0);
    let outcome = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    server.requests_processed++;
    if outcome == PipelineOutcome.Handled || outcome == PipelineOutcome.RouteNotFound {
        let _ = dispatch_grpc_unary(d, req, now_ns, res, HandlerFn);
    }
}

fn handle_grpc_h2_control_frame(conn: i64, hdr: const wire::WireFrameHeader&, payload: const u8[:]) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS {
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
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
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 && payload.len == 8 {
            var ping_data: u8[8] = [0; 8];
            for p in 8 { ping_data[p] = payload[p]; }
            var pong: u8[..24] = [];
            let _ = wire::encode_ping_frame(ping_data, true, pong);
            let _ = tcp_send(conn, pong[..]);
        }
        return true;
    }
    return false;
}

fn handle_grpc_h2_wire_frame<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&, GrpcStatusCode&, u8[..256]&),
>(
    conn:      i64,
    server:    HttpServer&,
    d:         const GrpcServerDispatcher&,
    client_ip: const u8[:],
    hpack_dec: internal::DynamicTable&,
    hpack_enc: internal::DynamicTable&,
    pending:   Request&,
    hdr:       const wire::WireFrameHeader&,
    payload:   const u8[:],
    out_wire:  u8[..65536]&,
) -> bool {
    if handle_grpc_h2_control_frame(conn, hdr, payload) {
        return true;
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        let frag, ok_frag = slice_grpc_h2_headers_fragment(payload, hdr.flags);
        if ok_frag {
            var pseudo = internal::H2PseudoHeaders { .. };
            reset_server_request_fast(pending);
            let _ = pending.method.try_set("POST");
            let _ = wire::decode_hpack_to_map(
                hpack_dec, frag, pseudo, pending.headers, 8192, false,
            );
            if pseudo.path.len > 0 {
                let _ = pending.url.try_set(pseudo.path[..]);
            } else {
                let _ = pending.url.try_set("/helloworld.Greeter/SayHello");
            }
            if pseudo.authority.len > 0 && header(pending, "host").len == 0 {
                let _ = append_header(pending.headers, "host", pseudo.authority[..]);
            }
        }
        if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
            var res = Response { .. };
            execute_grpc_server_unary(server, d, client_ip, pending, res, HandlerFn);
            out_wire.clear();
            emit_grpc_h2_response_frames(hpack_enc, hdr.stream_id, res, out_wire);
            if out_wire.len > 0 {
                let _ = tcp_send(conn, out_wire[..]);
            }
        }
        return true;
    }
    if hdr.frame_type == rfc::H2_FRAME_DATA {
        if pending.url.len == 0 {
            let _ = pending.method.try_set("POST");
            let _ = pending.url.try_set("/helloworld.Greeter/SayHello");
            let _ = append_header(pending.headers, "content-type", "application/grpc");
        }
        pending.body.append(payload);
        if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
            var res = Response { .. };
            execute_grpc_server_unary(server, d, client_ip, pending, res, HandlerFn);
            out_wire.clear();
            emit_grpc_h2_response_frames(hpack_enc, hdr.stream_id, res, out_wire);
            if out_wire.len > 0 {
                let _ = tcp_send(conn, out_wire[..]);
            }
            reset_server_request_fast(pending);
        }
        return true;
    }
    return hdr.frame_type != rfc::H2_FRAME_GOAWAY;
}

// Serves a gRPC over HTTP/2 connection session on `conn_fd` through `server.pipeline` and `d`.
fn serve_grpc_h2_connection<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&, GrpcStatusCode&, u8[..256]&),
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

    var hpack_dec = internal::new_dynamic_table(4096);
    var hpack_enc = internal::new_dynamic_table(4096);
    var pending = new_request("POST", "/helloworld.Greeter/SayHello");

    var in_buf:   u8[>..]     = [];
    var out_wire: u8[..65536] = [];
    var rem:      u8[>..]     = [];
    var chunk:    u8[..4096]  = [];

    if initial_buf.len > 24 {
        in_buf.append(initial_buf[24..]);
    }

    var is_running = true;
    while is_running {
        var cursor: i64 = 0;
        while is_running {
            let hdr, payload, ok_frame = wire::read_wire_h2_frame(in_buf[..], cursor);
            if !ok_frame {
                break;
            }
            is_running = handle_grpc_h2_wire_frame(
                conn_fd, server, d, peer_ip[..], hpack_dec, hpack_enc, pending, hdr, payload, out_wire, HandlerFn,
            );
        }

        if cursor > 0 {
            rem.clear();
            rem.append(in_buf[cursor..]);
            in_buf.clear();
            in_buf.append(rem[..]);
        }
        if !is_running {
            break;
        }

        chunk.clear();
        let recvd = tcp_recv(conn_fd, chunk, 4096, 50);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        in_buf.append(chunk[..recvd]);
    }
}

// Processes a gRPC-Web HTTP/1.1 request wire buffer through `server.pipeline` and `d`,
// sending the serialized response over `conn_fd`.
fn serve_grpc_web_http1<
    HandlerFn: fn(u16, GrpcServerContext&, const u8[:], u8[>..]&, GrpcStatusCode&, u8[..256]&),
>(
    server:  HttpServer&,
    d:       const GrpcServerDispatcher&,
    conn_fd: i64,
    req_raw: const u8[:],
) {
    var out_wire: u8[>..] = [];
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
