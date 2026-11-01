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
const HTTP_STATUS_OK: i32 = 200;

// ---- Protocol Detection and Content-Type Helpers -------------------------

inline fn matches_grpc_media_type(ct: const u8[:], prefix: const u8[:]) -> bool {
    guard starts_with_fold(ct, prefix) else { return false; }
    if ct.len == prefix.len { return true; }
    let next_byte = ct[prefix.len];
    return next_byte == '+' || next_byte == ';' || next_byte == ' ' || next_byte == '\t';
}

// Returns true if Content-Type matches standard gRPC, gRPC-Web, or gRPC-Web-Text
fn is_grpc_content_type(ct: const u8[:]) -> bool {
    let trimmed = trim_lws(ct);
    return matches_grpc_media_type(trimmed, GRPC_CONTENT_TYPE) ||
           matches_grpc_media_type(trimmed, GRPC_WEB_CONTENT_TYPE) ||
           matches_grpc_media_type(trimmed, GRPC_WEB_TEXT_CONTENT_TYPE);
}

// Returns true if Content-Type indicates gRPC-Web (binary or text)
fn is_grpc_web(ct: const u8[:]) -> bool {
    let trimmed = trim_lws(ct);
    return matches_grpc_media_type(trimmed, GRPC_WEB_CONTENT_TYPE) ||
           matches_grpc_media_type(trimmed, GRPC_WEB_TEXT_CONTENT_TYPE);
}

// Returns true if Content-Type is specifically gRPC-Web-Text (Base64 encoded)
fn is_grpc_web_text(ct: const u8[:]) -> bool {
    let trimmed = trim_lws(ct);
    return matches_grpc_media_type(trimmed, GRPC_WEB_TEXT_CONTENT_TYPE);
}

// Inspects an incoming Request to determine if it is a gRPC call
fn is_grpc_request(req: const Request&) -> bool {
    var ct = req.header("content-type");
    if ct.len == 0 {
        ct = find_header(req.headers[..], "content-type");
    }
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
    guard slash2 > 1 && slash2 < (path.len - 1) else { return false; }

    let service_part = path[1..slash2];
    let method_part = path[(slash2 + 1)..];

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
    max_message_size: u32                   = GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    enable_web:       bool                  = true,
}

fn new_grpc_server_dispatcher(max_msg_size: u32 = GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcServerDispatcher {
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
fn append_grpc_metadata_headers<H>(target: H&, metadata: const GrpcMetadata[:]) {
    for &m in metadata {
        guard target.len < target.cap else { break; }
        var item = HeaderItem { .. };
        item.name.append(m.key[..]);
        item.value.append(m.value[..]);
        target.push(item);
    }
}

// Builds a Trailers-Only response (used for immediate errors or zero-data failures)
fn build_grpc_trailers_only_response(
    status:  GrpcStatusCode,
    message: const u8[:],
    ctx:     const GrpcServerContext&,
    out_res: Response&,
) {
    out_res.status_code = HTTP_STATUS_OK;
    out_res.headers.clear();
    out_res.trailers.clear();
    out_res.body.clear();

    if ctx.is_web {
        // gRPC-Web: Trailers are framed in body with flag 0x80
        var ct = HeaderItem { .. };
        ct.name.append("content-type");
        if ctx.is_web_text {
            ct.value.append(GRPC_WEB_TEXT_CONTENT_TYPE);
        } else {
            ct.value.append(GRPC_WEB_CONTENT_TYPE_PROTO);
        }
        out_res.headers.push(ct);

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
        var ct = HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(GRPC_CONTENT_TYPE_PROTO);
        out_res.headers.push(ct);

        var st = HeaderItem { .. };
        st.name.append(HEADER_GRPC_STATUS);
        format(st.value, grpc_status_to_code(status) as i64);
        out_res.headers.push(st);

        if message.len > 0 {
            var msg_item = HeaderItem { .. };
            msg_item.name.append(HEADER_GRPC_MESSAGE);
            encode_grpc_message(message, msg_item.value);
            out_res.headers.push(msg_item);
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
    out_res.status_code = HTTP_STATUS_OK;
    out_res.headers.clear();
    out_res.trailers.clear();
    out_res.body.clear();

    if ctx.is_web {
        // gRPC-Web
        var ct = HeaderItem { .. };
        ct.name.append("content-type");
        if ctx.is_web_text {
            ct.value.append(GRPC_WEB_TEXT_CONTENT_TYPE);
        } else {
            ct.value.append(GRPC_WEB_CONTENT_TYPE_PROTO);
        }
        out_res.headers.push(ct);

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
        var ct = HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append(GRPC_CONTENT_TYPE_PROTO);
        out_res.headers.push(ct);

        var enc_item = HeaderItem { .. };
        enc_item.name.append(HEADER_GRPC_ACCEPT_ENCODING);
        enc_item.value.append("identity,gzip");
        out_res.headers.push(enc_item);

        append_grpc_metadata_headers(out_res.headers, ctx.response_metadata[..]);

        out_res.body.append(raw_lpm_body);

        // Trailers
        var st = HeaderItem { .. };
        st.name.append(HEADER_GRPC_STATUS);
        format(st.value, grpc_status_to_code(status) as i64);
        out_res.trailers.push(st);

        if message.len > 0 {
            var msg_item = HeaderItem { .. };
            msg_item.name.append(HEADER_GRPC_MESSAGE);
            encode_grpc_message(message, msg_item.value);
            out_res.trailers.push(msg_item);
        }

        append_grpc_metadata_headers(out_res.trailers, ctx.response_trailers[..]);
    }
}

// ---- Request Ingress Context Extraction ----------------------------------

inline fn compute_safe_grpc_deadline(base_ns: u64, ms: u64) -> u64 {
    guard base_ns > 0 && ms > 0 else { return 0; }
    let max_ms_for_nanos: u64 = 18446744073709; // u64::MAX / 10^6
    let safe_ms = if ms > max_ms_for_nanos { max_ms_for_nanos } else { ms };
    let nanos = safe_ms * NANOS_PER_MILLI;
    let max_add: u64 = 0xFFFFFFFFFFFFFFFF - base_ns;
    let safe_nanos = if nanos > max_add { max_add } else { nanos };
    return base_ns + safe_nanos;
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

    // Inspect headers
    for &hdr in req.headers {
        let n = hdr.name[..];
        let v = hdr.value[..];

        if eq_ascii_fold(n, "content-type") {
            out_ctx.is_web = is_grpc_web(v);
            out_ctx.is_web_text = is_grpc_web_text(v);
        } else if eq_ascii_fold(n, HEADER_GRPC_TIMEOUT) {
            let ms, ok_to = parse_grpc_timeout(v);
            if ok_to {
                out_ctx.timeout_ms = ms;
                let base_ns = if req_start_mono_ns > 0 { req_start_mono_ns } else { now_mono_ns };
                out_ctx.deadline_mono_ns = compute_safe_grpc_deadline(base_ns, ms);
            }
        } else if !starts_with_fold(n, ":") &&
                   !eq_ascii_fold(n, "te") &&
                   !eq_ascii_fold(n, "host") &&
                   !eq_ascii_fold(n, "connection") {
            // User metadata
            guard out_ctx.metadata.len < out_ctx.metadata.cap else { return false; }
            var item = GrpcMetadata { .. };
            item.key.append(n);
            item.value.append(v);
            out_ctx.metadata.push(item);
        }
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

    var reader = core::new_slice_reader(out_reader.wire[..]);
    while reader.remaining() >= GRPC_LPM_HEADER_LEN {
        let flag, err_flag = reader.read_u8();
        guard err_flag == core::IoError.None else { return false; }
        guard (flag & ~GRPC_FLAG_COMPRESSED) == 0 else { return false; }
        let is_comp = (flag & GRPC_FLAG_COMPRESSED) != 0;

        let len_val, err_len = reader.read_u32_be();
        guard err_len == core::IoError.None else { return false; }

        let payload_offset = reader.cursor as u32;
        guard reader.remaining() >= len_val else { return false; }
        let skip_err = reader.skip(len_val);
        guard skip_err == core::IoError.None else { return false; }
        guard out_reader.spans.len < out_reader.spans.cap else { return false; }

        let span = GrpcMessageSpan {
            offset:     payload_offset,
            len:        len_val,
            compressed: is_comp,
        };
        out_reader.spans.push(span);
    }

    guard reader.remaining() == 0 else { return false; }
    return true;
}

fn get_client_stream_message(reader: const GrpcClientStreamReader&, idx: i64) -> const u8[:] {
    guard idx >= 0 && idx < reader.spans.len else { return ""; }
    let span = reader.spans[idx];
    let start = span.offset as i64;
    let end = (span.offset + span.len) as i64;
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
    writer.message_count += 1;
}

// ---- Core Dispatch Execution --------------------------------------------

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
    var wire_bytes: u8[>..] = [];
    if ctx.is_web_text {
        guard decode_grpc_web_text(req.body[..], wire_bytes) else {
            build_grpc_trailers_only_response(
                GrpcStatusCode.InvalidArgument, "Invalid Base64 gRPC-Web-Text payload", ctx, res,
            );
            return true;
        }
    } else {
        wire_bytes.append(req.body[..]);
    }

    var req_payload: u8[>..] = [];
    var is_compressed = false;
    if wire_bytes.len >= GRPC_LPM_HEADER_LEN {
        let ok_lpm, consumed = decode_grpc_lpm(wire_bytes[..], 0, req_payload, is_compressed);
        if !ok_lpm || (consumed as i64) != wire_bytes.len {
            build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Malformed LPM framing", ctx, res);
            return true;
        }
    } else if wire_bytes.len > 0 {
        build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Incomplete 5-byte LPM header", ctx, res);
        return true;
    }

    if (req_payload.len as u32) > d.max_message_size {
        build_grpc_trailers_only_response(
            GrpcStatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
        );
        return true;
    }

    if is_compressed {
        build_grpc_trailers_only_response(
            GrpcStatusCode.Unimplemented, "Compression not implemented for method", ctx, res,
        );
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

    // Decode single request message
    var wire_bytes: u8[>..] = [];
    if ctx.is_web_text {
        guard decode_grpc_web_text(req.body[..], wire_bytes) else {
            build_grpc_trailers_only_response(
                GrpcStatusCode.InvalidArgument, "Invalid Base64 gRPC-Web-Text payload", ctx, res,
            );
            return true;
        }
    } else {
        wire_bytes.append(req.body[..]);
    }

    var req_payload: u8[>..] = [];
    var is_compressed = false;
    if wire_bytes.len >= GRPC_LPM_HEADER_LEN {
        let ok_lpm, consumed = decode_grpc_lpm(wire_bytes[..], 0, req_payload, is_compressed);
        if !ok_lpm || (consumed as i64) != wire_bytes.len {
            build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Malformed LPM framing", ctx, res);
            return true;
        }
    } else if wire_bytes.len > 0 {
        build_grpc_trailers_only_response(GrpcStatusCode.InvalidArgument, "Incomplete 5-byte LPM header", ctx, res);
        return true;
    }

    if (req_payload.len as u32) > d.max_message_size {
        build_grpc_trailers_only_response(
            GrpcStatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
        );
        return true;
    }

    if is_compressed {
        build_grpc_trailers_only_response(
            GrpcStatusCode.Unimplemented, "Compression not implemented for method", ctx, res,
        );
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

fn validate_client_stream_spans(
    reader:   const GrpcClientStreamReader&,
    max_size: u32,
    ctx:      const GrpcServerContext&,
    res:      Response&,
) -> bool {
    for span in reader.spans {
        if span.len > max_size {
            build_grpc_trailers_only_response(
                GrpcStatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
            );
            return false;
        }
        if span.compressed {
            build_grpc_trailers_only_response(
                GrpcStatusCode.Unimplemented, "Compression not implemented for method", ctx, res,
            );
            return false;
        }
    }
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

    guard validate_client_stream_spans(reader, d.max_message_size, ctx, res) else {
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
