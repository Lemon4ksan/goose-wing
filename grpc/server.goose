// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC server dispatcher.
// Implements RFC gRPC over HTTP/2, RFC 7540/9113 framing, and RFC gRPC-Web (binary and text).
namespace grpc;

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
import .constants;
import .framing;
import .status;
import .connect;
import .health;
import .internal;
import .connect_internal;
import .server_internal;
import .server_dispatch_internal;

// Parses standard gRPC URI path: `/{service}/{method}` or `/{package}.{service}/{method}`.
// Leaves `out_service` and `out_method` untouched when returning false.
//
// Example:
//   path = "/helloworld.Greeter/SayHello"
//   returns: ok = true, out_service = "helloworld.Greeter", out_method = "SayHello"
fn parse_path<S, M>(
    path:        const u8[:],
    out_service: S&,
    out_method:  M&,
) -> bool {
    guard path.len >= 3 && path[0] == '/' else { return false; }
    let service_part, method_part, ok_split = path[1..].split_once_byte('/');
    guard ok_split
        && grpc_internal::is_valid_path_segment(service_part)
        && grpc_internal::is_valid_path_segment(method_part) else {
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

struct ServerContext {
    service:           u8[..128]      = [],
    method:            u8[..128]      = [],
    peer_ip:           u8[..48]       = [],
    timeout_ms:        u64            = 0,
    deadline_mono_ns:  u64            = 0,
    is_web:            bool           = false,
    is_web_text:       bool           = false,
    res_is_web_text:   bool           = false,
    metadata:          Metadata[..16] = [],
    response_metadata: Metadata[..16] = [],
    response_trailers: Metadata[..16] = [],
}

fn get_metadata(ctx: const ServerContext&, key: const u8[:]) -> const u8[:] {
    for &m in ctx.metadata {
        if m.key[..].eq_ascii_fold(key) {
            return m.value[..];
        }
    }
    return "";
}

fn add_response_metadata(ctx: ServerContext&, key: const u8[:], value: const u8[:]) -> bool {
    guard grpc_internal::is_valid_custom_metadata(key, value) else { return false; }
    var item = Metadata { .. };
    guard item.key.try_set(key) && item.value.try_set(value) else { return false; }
    return ctx.response_metadata.try_push(item);
}

fn add_response_trailer(ctx: ServerContext&, key: const u8[:], value: const u8[:]) -> bool {
    guard grpc_internal::is_valid_custom_metadata(key, value) else { return false; }
    var item = Metadata { .. };
    guard item.key.try_set(key) && item.value.try_set(value) else { return false; }
    return ctx.response_trailers.try_push(item);
}

fn is_deadline_exceeded(ctx: const ServerContext&, now_mono_ns: u64) -> bool {
    if ctx.deadline_mono_ns > 0 {
        return now_mono_ns > ctx.deadline_mono_ns;
    }
    return false;
}

// ---- Service & Method Registry ------------------------------------------

enum MethodType {
    Unary,
    ClientStreaming,
    ServerStreaming,
    BidiStreaming,
}

enum Idempotency {
    Default,
    Idempotent,
    NoSideEffects,
}

struct MethodEntry {
    service:     u8[..128]   = [],
    method:      u8[..128]   = [],
    full_path:   u8[..260]   = [],
    method_type: MethodType  = MethodType.Unary,
    idempotency: Idempotency = Idempotency.Default,
    handler_id:  u16         = 0,
}

struct ServerDispatcher {
    methods:          MethodEntry[..64]        = [],
    health_entries:   HealthServiceEntry[..32] = [],
    max_message_size: u32                      = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    enable_web:       bool                     = true,
}

fn new_server_dispatcher(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> ServerDispatcher {
    return ServerDispatcher {
        methods:          [],
        health_entries:   [],
        max_message_size: max_msg_size,
        enable_web:       true,
    };
}

// Registers or updates the serving status of a service for `/grpc.health.v1.Health/Check` (gRFC A66).
fn set_service_health(
    d:       ServerDispatcher&,
    service: const u8[:],
    status:  ServingStatus,
) -> bool {
    guard service.len <= 128 else { return false; }
    for &entry in d.health_entries {
        if entry.service[..] == service {
            entry.status = status;
            return true;
        }
    }
    var entry = HealthServiceEntry { status: status, .. };
    guard entry.service.try_set(service) else { return false; }
    return d.health_entries.try_push(entry);
}

// Looks up the serving status for a service in `d.health_entries` (gRFC A66).
fn lookup_service_health(
    d:       const ServerDispatcher&,
    service: const u8[:],
) -> ServingStatus, bool {
    for &entry in d.health_entries {
        if entry.service[..] == service {
            return entry.status, true;
        }
    }
    if service.len == 0 && d.health_entries.len == 0 {
        return ServingStatus.Serving, true;
    }
    return ServingStatus.ServiceUnknown, false;
}

fn register_unary(
    d:           ServerDispatcher&,
    service:     const u8[:],
    method:      const u8[:],
    handler_id:  u16,
    idempotency: Idempotency = Idempotency.Default,
) -> bool {
    return grpc_internal::register_method(d, service, method, MethodType.Unary, handler_id, idempotency);
}

fn register_server_streaming(
    d:          ServerDispatcher&,
    service:    const u8[:],
    method:     const u8[:],
    handler_id: u16,
) -> bool {
    return grpc_internal::register_method(d, service, method, MethodType.ServerStreaming, handler_id);
}

fn register_client_streaming(
    d:          ServerDispatcher&,
    service:    const u8[:],
    method:     const u8[:],
    handler_id: u16,
) -> bool {
    return grpc_internal::register_method(d, service, method, MethodType.ClientStreaming, handler_id);
}

fn register_bidi_streaming(
    d:          ServerDispatcher&,
    service:    const u8[:],
    method:     const u8[:],
    handler_id: u16,
) -> bool {
    return grpc_internal::register_method(d, service, method, MethodType.BidiStreaming, handler_id);
}

fn find_method(d: const ServerDispatcher&, full_path: const u8[:]) -> i64, bool {
    for &entry, i in d.methods {
        if entry.full_path[..] == full_path {
            return i, true;
        }
    }
    return 0, false;
}

fn find_method_by_name(
    d:       const ServerDispatcher&,
    service: const u8[:],
    method:  const u8[:],
) -> i64, bool {
    for &entry, i in d.methods {
        if entry.service[..] == service && entry.method[..] == method {
            return i, true;
        }
    }
    return 0, false;
}

// ---- Streaming Primitives -----------------------------------------------

struct MessageSpan {
    offset:     u32  = 0,
    len:        u32  = 0,
    compressed: bool = false,
}

struct ClientStreamReader {
    spans: MessageSpan[..32] = [],
    wire:  u8[>..]           = [],
}

// Parses sequential client stream LPM frames into message spans.
//
// Example:
//   raw_body = "\x00\x00\x00\x00\x04ping\x00\x00\x00\x00\x04pong", is_web_text = false
//   returns: ok = true, out_reader.spans.len = 2
fn parse_client_stream(
    raw_body:    const u8[:],
    is_web_text: bool,
    out_reader:  ClientStreamReader&,
) -> bool {
    out_reader.wire.clear();
    out_reader.spans.clear();
    var committed = false;
    defer if !committed {
        out_reader.wire.clear();
        out_reader.spans.clear();
    };

    if is_web_text {
        guard decode_web_text(raw_body, out_reader.wire) else { return false; }
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

        let span = MessageSpan {
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

fn get_client_stream_message(reader: const ClientStreamReader&, idx: i64) -> const u8[:] {
    guard idx >= 0 && idx < reader.spans.len else { return ""; }
    let span = reader.spans[idx];
    let start = span.offset as i64;
    let end = core::add_sat_u64(span.offset, span.len) as i64;
    guard end <= reader.wire.len else { return ""; }
    return reader.wire[start..end];
}

struct ServerStreamWriter {
    message_count: u32     = 0,
    body:          u8[>..] = [],
}

fn write_stream_message(
    writer:     ServerStreamWriter&,
    payload:    const u8[:],
    compressed: bool = false,
) {
    encode_lpm(payload, writer.body, compressed);
    writer.message_count = core::add_sat_u64(writer.message_count, 1) as u32;
}

// ---- Core Dispatch Execution --------------------------------------------

// Validates received message compression flag (`0x01`) against the `grpc-encoding` header.
// Per gRPC compression spec (`grpc-go` `checkRecvPayload` / `tonic` `decode_chunk`),
// setting `Compressed-Flag = 1` when `grpc-encoding` is empty or `"identity"` is an `Internal` error.
fn validate_recv_compression(is_compressed: bool, enc: const u8[:], is_server: bool) -> StatusCode {
    let trimmed = enc.trim_lws();
    if !is_compressed {
        if grpc_internal::is_supported_encoding(trimmed) {
            return StatusCode.Ok;
        }
        return if is_server { StatusCode.Unimplemented } else { StatusCode.Internal };
    }
    if trimmed.len == 0 || trimmed.eq_ascii_fold("identity") {
        return StatusCode.Internal;
    }
    if trimmed.eq_ascii_fold("gzip") {
        return StatusCode.Ok;
    }
    return if is_server { StatusCode.Unimplemented } else { StatusCode.Internal };
}

// Built-in handler for `/grpc.health.v1.Health/Check` (gRFC A66).
fn handle_builtin_health_check(
    d:   const ServerDispatcher&,
    req: const http::Request&,
    ctx: const ServerContext&,
    res: http::Response&,
) -> bool {
    var req_payload: u8[>..] = [];
    guard grpc_internal::decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }
    let target_svc, ok_pb = grpc_internal::try_decode_health_check_request(req_payload[..]);
    if !ok_pb {
        grpc_internal::build_trailers_only_response(
            StatusCode.InvalidArgument, "Malformed HealthCheckRequest protobuf", ctx, res,
        );
        return true;
    }
    let serving_st, found = d.lookup_service_health(target_svc);
    if !found {
        grpc_internal::build_trailers_only_response(StatusCode.NotFound, "unknown service", ctx, res);
        return true;
    }
    var lpm_response: u8[>..] = [];
    grpc_internal::encode_health_check_lpm(serving_st, lpm_response);
    grpc_internal::build_wire_response(StatusCode.Ok, "", lpm_response[..], ctx, res);
    return true;
}

// Unary RPC Dispatcher:
// Executes a single Request-Response RPC cycle conforming to RFC gRPC over HTTP/2 and gRPC-Web.
fn dispatch_unary<HandlerFn: fn(u16, ServerContext&, const u8[:], u8[>..]&) -> Status>(
    d:                 const ServerDispatcher&,
    req:               const http::Request&,
    now_mono_ns:       u64,
    res:               http::Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard grpc_internal::is_request(req) else { return false; }

    var ctx = ServerContext { .. };
    grpc_internal::init_context_transport(req, ctx);

    let is_conn_get = grpc_internal::is_connect_get_request(req);
    if !req.method[..].eq_ascii_fold("POST") && !is_conn_get {
        grpc_internal::build_trailers_only_response(StatusCode.Internal, "HTTP method must be POST", ctx, res);
        return true;
    }

    let ctx_st = grpc_internal::extract_server_context_status(req, ctx, now_mono_ns, req_start_mono_ns);
    if ctx_st != StatusCode.Ok {
        let ctx_msg = if ctx_st == StatusCode.Unimplemented {
            "Malformed gRPC URI path"
        } else {
            "Malformed gRPC request headers"
        };
        grpc_internal::build_trailers_only_response(ctx_st, ctx_msg, ctx, res);
        return true;
    }

    var path_buf: u8[..260] = [];
    path_buf.push('/');
    path_buf.append(ctx.service[..]);
    path_buf.push('/');
    path_buf.append(ctx.method[..]);

    if path_buf[..] == "/grpc.health.v1.Health/Check" && !is_conn_get {
        if ctx.is_deadline_exceeded(now_mono_ns) {
            grpc_internal::build_trailers_only_response(
                StatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
            );
            return true;
        }
        return handle_builtin_health_check(d, req, ctx, res);
    }

    let method_idx, ok_method = d.find_method(path_buf[..]);
    if !ok_method {
        var err_msg: u8[..256] = [];
        err_msg.append("Method not found: ");
        err_msg.append(path_buf[..]);
        grpc_internal::build_trailers_only_response(StatusCode.Unimplemented, err_msg[..], ctx, res);
        return true;
    }

    let entry .= d.methods[method_idx];
    if ctx.is_web && !d.enable_web {
        grpc_internal::build_trailers_only_response(
            StatusCode.PermissionDenied, "gRPC-Web transport disabled", ctx, res,
        );
        return true;
    }
    if entry.method_type != MethodType.Unary {
        grpc_internal::build_trailers_only_response(StatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return true;
    }

    if is_conn_get {
        return grpc_internal::dispatch_connect_unary_get(d, req, entry, now_mono_ns, ctx, res, HandlerFn);
    }

    if ctx.is_deadline_exceeded(now_mono_ns) {
        grpc_internal::build_trailers_only_response(
            StatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
        );
        return true;
    }

    var req_payload: u8[>..] = [];
    guard grpc_internal::decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }

    var res_payload: u8[>..] = [];
    let st = HandlerFn(entry.handler_id, ctx, req_payload[..], res_payload);

    if st.code != StatusCode.Ok && res_payload.len == 0 {
        grpc_internal::build_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        var lpm_response: u8[>..] = [];
        encode_lpm(res_payload[..], lpm_response, false);
        grpc_internal::build_wire_response(st.code, st.message[..], lpm_response[..], ctx, res);
    }

    return true;
}

// Default UFCS unary gRPC stage hook on wire::NoOpStage.
fn on_unary<B>(
    _stage:      wire::NoOpStage&,
    _handler_id: u16,
    _ctx:        ServerContext&,
    _req_bytes:  const u8[:],
    _res_bytes:  B&,
) -> Status {
    return error(StatusCode.Unimplemented, "Method not implemented");
}

// Stateful UFCS `<Stage>` Unary RPC Dispatcher: invokes `on_unary`.
fn dispatch_unary_stage<Stage>(
    d:                 const ServerDispatcher&,
    stage:             Stage&,
    req:               const http::Request&,
    now_mono_ns:       u64,
    res:               http::Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard grpc_internal::is_request(req) else { return false; }
    var ctx = ServerContext { .. };
    let method_idx, ok_prep = grpc_internal::prepare_method_dispatch(
        d, req, MethodType.Unary, now_mono_ns, req_start_mono_ns, ctx, res,
    );
    guard ok_prep else { return true; }

    var req_payload: u8[>..] = [];
    guard grpc_internal::decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }

    let handler_id = d.methods[method_idx].handler_id;
    var res_payload: u8[>..] = [];
    let st = on_unary(stage, handler_id, ctx, req_payload[..], res_payload);
    if st.code != StatusCode.Ok && res_payload.len == 0 {
        grpc_internal::build_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        var lpm_response: u8[>..] = [];
        encode_lpm(res_payload[..], lpm_response, false);
        grpc_internal::build_wire_response(st.code, st.message[..], lpm_response[..], ctx, res);
    }
    return true;
}

// Server-Streaming RPC Dispatcher:
// Handler sends 0, 1, or multiple messages through ServerStreamWriter.
fn dispatch_server_streaming<
    HandlerFn: fn(u16, ServerContext&, const u8[:], ServerStreamWriter&) -> Status,
>(
    d:                 const ServerDispatcher&,
    req:               const http::Request&,
    now_mono_ns:       u64,
    res:               http::Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard grpc_internal::is_request(req) else { return false; }
    var ctx = ServerContext { .. };
    let method_idx, ok_prep = grpc_internal::prepare_method_dispatch(
        d, req, MethodType.ServerStreaming, now_mono_ns, req_start_mono_ns, ctx, res,
    );
    guard ok_prep else { return true; }

    var req_payload: u8[>..] = [];
    guard grpc_internal::decode_and_validate_single_lpm(d, req, ctx, res, req_payload) else {
        return true;
    }

    var writer = ServerStreamWriter { .. };
    let st = HandlerFn(d.methods[method_idx].handler_id, ctx, req_payload[..], writer);

    if st.code != StatusCode.Ok && writer.body.len == 0 {
        grpc_internal::build_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        grpc_internal::build_wire_response(st.code, st.message[..], writer.body[..], ctx, res);
    }

    return true;
}

// Client-Streaming RPC Dispatcher:
// Parses all received LPM messages from the request body into ClientStreamReader.
fn dispatch_client_streaming<
    HandlerFn: fn(u16, ServerContext&, const ClientStreamReader&, u8[>..]&) -> Status,
>(
    d:                 const ServerDispatcher&,
    req:               const http::Request&,
    now_mono_ns:       u64,
    res:               http::Response&,
    req_start_mono_ns: u64 = 0,
) -> bool {
    guard grpc_internal::is_request(req) else { return false; }
    var ctx = ServerContext { .. };
    let method_idx, ok_prep = grpc_internal::prepare_method_dispatch(
        d, req, MethodType.ClientStreaming, now_mono_ns, req_start_mono_ns, ctx, res,
    );
    guard ok_prep else { return true; }

    var reader = ClientStreamReader { .. };
    let ok_stream = parse_client_stream(req.body[..], ctx.is_web_text, reader);
    if !ok_stream {
        grpc_internal::build_trailers_only_response(
            StatusCode.InvalidArgument, "Malformed client stream LPM frames", ctx, res,
        );
        return true;
    }

    guard grpc_internal::validate_and_decompress_client_stream(reader, d.max_message_size, ctx, res) else {
        return true;
    }

    var res_payload: u8[>..] = [];
    let st = HandlerFn(d.methods[method_idx].handler_id, ctx, reader, res_payload);

    if st.code != StatusCode.Ok && res_payload.len == 0 {
        grpc_internal::build_trailers_only_response(st.code, st.message[..], ctx, res);
    } else {
        var lpm_response: u8[>..] = [];
        encode_lpm(res_payload[..], lpm_response, false);
        grpc_internal::build_wire_response(st.code, st.message[..], lpm_response[..], ctx, res);
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
struct LpmReader {
    spans:        MessageSpan[..32] = [],
    wire_buf:     u8[..16384]       = [],
    read_cursor:  i64               = 0,
    max_msg_size: u32               = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
}

// Bounded zero-allocation Length-Prefixed Message (LPM) stream writer (Invariant 13).
struct LpmWriter {
    message_count: u32         = 0,
    wire_buf:      u8[..16384] = [],
}

// Feeds raw wire bytes into `LpmReader` and parses complete 5-byte LPM frames.
// Rejects truncated frames, invalid compression flags, or capacity overflows (Invariant 13).
fn feed_lpm_reader(reader: LpmReader&, raw: const u8[:]) -> bool {
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

        let span = MessageSpan {
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

// Reads the next zero-copy message slice from `LpmReader` and advances `read_cursor`.
//
// Example:
//   reader has 1 frame "ping" at span 0, reader.read_cursor = 0
//   returns: ("ping", true), reader.read_cursor = 1
fn read_next_lpm(reader: LpmReader&) -> const u8[:], bool {
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

// Encodes and appends a single LPM frame into `LpmWriter` with fail-closed bounds checking.
fn write_lpm_frame(
    writer:     LpmWriter&,
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
fn dispatch_bidi_streaming(
    conn:   H2Stream&,
    reader: LpmReader&,
    writer: LpmWriter&,
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
        let msg, ok = read_next_lpm(reader);
        guard ok else { return false; }
        let frame_in = core::add_sat_i64(5, span.len);
        consumed_in = core::add_sat_i64(consumed_in, frame_in);
        if span.compressed {
            var decomp_buf: u8[..16384] = [];
            let ok_gz, _ = core::gzip_decompress_with_limit(msg, decomp_buf, limit);
            guard ok_gz else { return false; }
            guard write_lpm_frame(writer, decomp_buf[..], false) else { return false; }
        } else {
            guard write_lpm_frame(writer, msg, false) else { return false; }
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

fn emit_h2_response_frames<B>(
    hpack_enc: http2::DynamicTable&,
    stream_id: u32,
    res:       const http::Response&,
    out:       B&,
) {
    let end_hdr = res.body.len == 0 && res.trailers.entries.len == 0;
    let code_val = if res.status_code > 0 { res.status_code as i32 } else { 200 };
    let status_pseudo = http2::PseudoHeaders {
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
        let tr_pseudo = http2::PseudoHeaders {
            is_trailer: true,
            ..
        };
        let _ = wire::encode_h2_headers_frame_from_map(
            hpack_enc, stream_id, tr_pseudo, res.trailers, true, out,
        );
    }
}

fn handle_h2_control_frame(
    conn:    i64,
    hdr:     const wire::WireFrameHeader&,
    payload: const u8[:],
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS {
        guard grpc_internal::is_valid_h2_settings_frame(hdr) && payload.len == hdr.length else { return false; }
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
            guard grpc_internal::validate_h2_settings_payload(payload) else { return false; }
            var ack: u8[..16] = [];
            let ack_hdr = wire::WireFrameHeader {
                length:     0,
                frame_type: rfc::H2_FRAME_SETTINGS,
                flags:      rfc::H2_FLAG_ACK,
                stream_id:  0,
            };
            let _ = wire::encode_frame_header(ack_hdr, ack);
            let _ = net::tcp_send(conn, ack[..]);
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
            let _ = net::tcp_send(conn, pong[..]);
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

fn handle_h2_wire_frame<
    HandlerFn: fn(u16, ServerContext&, const u8[:], u8[>..]&) -> Status,
>(
    conn:              i64,
    server:            server::HttpServer&,
    d:                 const ServerDispatcher&,
    client_ip:         const u8[:],
    hpack_dec:         http2::DynamicTable&,
    hpack_enc:         http2::DynamicTable&,
    pending:           http::Request&,
    pending_stream_id: u32&,
    hdr:               const wire::WireFrameHeader&,
    payload:           const u8[:],
    out_wire:          u8[..65536]&,
) -> bool {
    guard hdr.length <= rfc::H2_DEFAULT_MAX_FRAME_SIZE && payload.len == hdr.length else {
        return false;
    }
    if hdr.frame_type != rfc::H2_FRAME_HEADERS && hdr.frame_type != rfc::H2_FRAME_DATA {
        let ok_ctrl = handle_h2_control_frame(conn, hdr, payload);
        if ok_ctrl && hdr.frame_type == rfc::H2_FRAME_RST_STREAM && hdr.stream_id == pending_stream_id {
            server::reset_server_request_fast(pending);
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
        let frag, ok_frag = grpc_internal::slice_h2_headers_fragment(payload, hdr.flags, hdr.stream_id);
        guard ok_frag else { return false; }
        var pseudo = http2::PseudoHeaders { .. };
        server::reset_server_request_fast(pending);
        let _ = pending.method.try_set("POST");
        let hpack_res = http2::decode_hpack_to_map(
            hpack_dec, frag, pseudo, pending.headers, 8192, true,
        );
        guard hpack_res == rfc::H2_ERR_NO_ERROR
            && pseudo.has_method
            && !pseudo.has_status
            && !pseudo.has_protocol else {
            server::reset_server_request_fast(pending);
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
        if pseudo.authority.len > 0 && pending.header("host").len == 0 {
            let _ = pending.headers.append_header("host", pseudo.authority[..]);
        }
        if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
            var res = http::Response { .. };
            grpc_internal::execute_server_unary(server, d, client_ip, pending, res, HandlerFn);
            out_wire.clear();
            emit_h2_response_frames(hpack_enc, hdr.stream_id, res, out_wire);
            if out_wire.len > 0 {
                let _ = net::tcp_send(conn, out_wire[..]);
            }
            server::reset_server_request_fast(pending);
            pending_stream_id = 0;
        }
        return true;
    }
    guard hdr.stream_id > 0
        && hdr.stream_id == pending_stream_id
        && pending.headers.entries.len > 0 else {
        return false;
    }
    let data_slice, ok_data = grpc_internal::slice_h2_data_payload(payload, hdr.flags);
    guard ok_data else { return false; }
    let max_body = max(
        core::add_sat_u64(d.max_message_size, rfc::GRPC_LPM_HEADER_LEN),
        core::add_sat_u64(rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE, rfc::GRPC_LPM_HEADER_LEN),
    );
    guard core::add_sat_u64(pending.body.len as u64, data_slice.len as u64) <= max_body else {
        server::reset_server_request_fast(pending);
        pending_stream_id = 0;
        return false;
    }
    pending.body.append(data_slice);
    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        var res = http::Response { .. };
        grpc_internal::execute_server_unary(server, d, client_ip, pending, res, HandlerFn);
        out_wire.clear();
        emit_h2_response_frames(hpack_enc, hdr.stream_id, res, out_wire);
        if out_wire.len > 0 {
            let _ = net::tcp_send(conn, out_wire[..]);
        }
        server::reset_server_request_fast(pending);
        pending_stream_id = 0;
    }
    return true;
}

// Runs the accept loop on `listener_fd`, serving gRPC (h2c and gRPC-Web) connections.
fn serve_listener<
    HandlerFn: fn(u16, ServerContext&, const u8[:], u8[>..]&) -> Status,
>(
    listener_fd: i64,
    server:      server::HttpServer&,
    d:           const ServerDispatcher&,
) {
    server.is_running = true;
    while server.is_running {
        let conn = net::tcp_accept(listener_fd, 200);
        if conn < 0 {
            continue;
        }
        grpc_internal::serve_connection(server, d, conn, HandlerFn);
        net::tcp_close(conn);
    }
}
