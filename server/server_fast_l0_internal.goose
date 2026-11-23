// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal fast L0 static GET path, header memoization, batching, and pipelined stream turns.
namespace server_internal;

import std;
import core;
import rfc.http;
import rfc.h2;
import rfc.ws;
import http.headers;
import http.headers.chunked;
import http.request;
import http.response;
import http.compression_dict;
import http2.framing;
import net.tcp;
import net.proxy_protocol;
import net.accel;
import tls.session;
import tls.backend;
import realtime.ws_handshake;
import realtime.websocket;
import realtime.topic_tree;
import wire.pipeline;
import .router;
import .router_internal;
import .router_l0_internal;
import .pool;
import .pipeline;
import .pipeline_internal;
import .profiler;
import .h2_mux_types_internal;
import .h2_mux_frames_internal;
import .h2_mux_streams_internal;
import .soa_timer;
import .internal;
import .h1_codec;
import .h1_codec_internal;
import .h1_serialize_internal;
import .cork;
import .stream_consumer;
import .sni;
import .server;
import .reactor;
import .reactor_async_internal;
import .reactor_conn_internal;
import .reactor_io_internal;
import .reactor_accel_internal;
import .server_h1_internal;
import .server_transport_internal;

inline fn is_noop_server_stage(stage: const wire::NoOpStage&) -> bool {
    return true;
}

inline fn is_noop_server_stage<Stage>(stage: const Stage&) -> bool {
    return false;
}

inline fn can_try_fast_l0_static<Stage>(server: const server::HttpServer&, stage: const Stage&) -> bool {
    guard is_noop_server_stage(stage) && !server.omit_server_header && !server.omit_date_header else {
        return false;
    }
    guard server.pipeline.router.l0_table.count > 0 && server.pipeline.router.static_payloads.len > 0 else {
        return false;
    }
    return !server.pipeline.enable_rate_limiter
        && !server.pipeline.enable_csrf_guard
        && !server.pipeline.enable_cors
        && server.pipeline.edge_filter.rules.len == 0
        && !server.pipeline.route_cache.is_valid;
}

// Validates a `Host` header slice, optionally memoizing the last valid value on `pipeline`.
fn validate_fast_host_slice(
    pipeline: server::ServerPipelineConfig&,
    host_val: const u8[:],
    memoize:  bool = false,
) -> bool {
    guard host_val.len > 0 else { return false; }
    if memoize && pipeline.has_valid_host && host_val == pipeline.last_valid_host[..] {
        return true;
    }
    guard validate_host_header_chars(host_val) && server::validate_host_header_structure(host_val) else {
        return false;
    }
    if memoize && pipeline.last_valid_host.try_set(host_val) {
        pipeline.has_valid_host = true;
    }
    return true;
}

// Evaluates a known header inside a fast L0 static GET header block.
inline fn eval_fast_l0_known_header(
    server:    server::HttpServer&,
    known_id:  http::KnownHeaderId,
    hval:      const u8[:],
    has_host:  bool&,
    out_close: bool&,
) -> bool {
    return match known_id {
        Host => {
            guard !has_host
                && validate_fast_host_slice(server.pipeline, hval, server.enable_header_memoization) else {
                return false;
            }
            has_host = true;
            true
        },
        Connection => {
            if hval.len == 10 && hval.eq_ascii_fold("keep-alive") {
                return true;
            }
            if hval.contains_fold("close") {
                out_close = true;
                return true;
            }
            !hval.contains_fold("upgrade")
        },
        ContentLength => false,
        TransferEncoding => false,
        Upgrade => false,
        Expect => false,
        SecWebSocketKey => false,
        _ => true,
    };
}

// Scans a single HTTP/1.1 header line for a zero-body static GET request without allocating a `HeaderMap`.
//
// Example:
//   rest = "Host: localhost\r\n\r\n", cursor = 0
//   returns: true, cursor = 17, has_host = true
fn scan_fast_l0_static_header_line(
    server:    server::HttpServer&,
    rest:      const u8[:],
    cursor:    i64&,
    has_host:  bool&,
    out_close: bool&,
) -> bool {
    let cur_slice = rest[cursor..];
    let name_len, ok_name = http::scan_header_field_name_swar(cur_slice);
    guard ok_name && name_len > 0 && name_len <= 256 else { return false; }
    let hname = cur_slice[..name_len];

    let val_start = core::add_sat_i64(name_len, 1);
    let val_slice = cur_slice[val_start..];
    let val_len, crlf_len, ok_val = http::scan_header_field_value_swar(val_slice);
    guard ok_val && crlf_len == 2 && val_len <= 4096 else { return false; }
    let lead_ws, end_ws = trim_header_value_bounds(val_slice[..val_len]);
    let hval = val_slice[lead_ws..end_ws];

    let known_id = http::identify_known_header(hname);
    guard eval_fast_l0_known_header(server, known_id, hval, has_host, out_close) else {
        return false;
    }

    advance_header_cursor(cursor, name_len, val_len, crlf_len);
    return true;
}

inline fn try_match_cached_l0_headers(
    server:    server::HttpServer&,
    rest:      const u8[:],
    out_close: bool&,
) -> bool {
    guard server.enable_header_memoization
        && server.fast_l0_last_headers.len > 0
        && rest == server.fast_l0_last_headers[..] else {
        return false;
    }
    if !server.pipeline.has_valid_host && server.fast_l0_last_host.len > 0 {
        let _ = server.pipeline.last_valid_host.try_set(server.fast_l0_last_host[..]);
        server.pipeline.has_valid_host = true;
    }
    out_close = server.fast_l0_last_close;
    return true;
}

inline fn record_cached_l0_headers(
    server:    server::HttpServer&,
    rest:      const u8[:],
    out_close: bool,
) {
    guard server.enable_header_memoization else { return; }
    if rest.len <= 256 && server.fast_l0_last_headers.try_set(rest) {
        let _ = server.fast_l0_last_host.try_set(server.pipeline.last_valid_host[..]);
        server.fast_l0_last_close = out_close;
    }
}

// Scans HTTP/1.1 request headers for a zero-body static GET request without allocating a `HeaderMap`.
//
// Example:
//   rest = "Host: localhost\r\nConnection: keep-alive\r\n\r\n"
//   returns: true, out_close = false
fn scan_fast_l0_static_headers(
    server:    server::HttpServer&,
    rest:      const u8[:],
    out_close: bool&,
) -> bool {
    if try_match_cached_l0_headers(server, rest, out_close) {
        return true;
    }
    var cursor:   i64  = 0;
    var has_host: bool = false;
    out_close = false;

    while cursor < rest.len {
        let rem = rest[cursor..];
        if rem.len >= 2 && rem[0] == '\r' && rem[1] == '\n' {
            guard has_host && verify_headers_terminator_consumed(cursor, rest.len) else {
                return false;
            }
            record_cached_l0_headers(server, rest, out_close);
            return true;
        }
        guard scan_fast_l0_static_header_line(server, rest, cursor, has_host, out_close) else {
            return false;
        }
    }
    return false;
}

// Appends the status line, Server header, Date header, and pre-rendered static payload frame.
inline fn append_fast_l0_static_response<B>(
    server:      server::HttpServer&,
    sp:          const server::StaticRoutePayload&,
    now_sec:     i64,
    wants_close: bool,
    wire_out:    B&,
) {
    refresh_http_server_date(server, now_sec);
    wire_out.append(server.cached_date.fast_prefix[..]);
    if wants_close {
        wire_out.append(sp.payload_close[..]);
    } else {
        wire_out.append(sp.payload_keep[..]);
    }
}

inline fn is_valid_fast_static_path(path: const u8[:]) -> bool {
    guard path.len >= 1 && path.len <= 16 && path[0] == '/' else { return false; }
    for b in path {
        guard b >= 0x21 && b <= 0x7E && b != '?' && b != '#' else { return false; }
    }
    return true;
}

// Extracts the request path and header block start from a `GET <path> HTTP/1.1\r\n` request line.
//
// Example:
//   header_bytes = "GET /plaintext HTTP/1.1\r\nHost: a\r\n\r\n"
//   returns: "/plaintext", rest_offset = 25, ok = true
fn parse_fast_l0_get_request_line(header_bytes: const u8[:]) -> const u8[:], i64, bool {
    guard core::read_le_u32(header_bytes, 0) == rfc::METHOD_GET_U32 else { return "", 0, false; }
    let sp2 = swar_find_space(header_bytes, 4);
    let rest_offset = core::add_sat_i64(sp2, 11);
    guard sp2 >= 5 && sp2 <= 20 && rest_offset <= header_bytes.len else { return "", 0, false; }
    let ver_pos = core::add_sat_i64(sp2, 1);
    guard core::read_le_u64(header_bytes, ver_pos) == rfc::HTTP_VERSION_1_1_U64 else { return "", 0, false; }
    let cr_pos = core::add_sat_i64(sp2, 9);
    let lf_pos = core::add_sat_i64(sp2, 10);
    guard header_bytes[cr_pos] == '\r' && header_bytes[lf_pos] == '\n' else { return "", 0, false; }
    let path = header_bytes[4..sp2];
    guard is_valid_fast_static_path(path) else { return "", 0, false; }
    return path, rest_offset, true;
}

// Matches `path` in `server.pipeline.router.l0_table` and returns the static payload index if eligible.
fn match_fast_l0_static_payload(server: const server::HttpServer&, path: const u8[:]) -> i32 {
    let l0_slot = match_l0(path, 0, server.pipeline.router.l0_table);
    guard l0_slot >= 0 else { return -1; }
    let slot_idx = l0_slot as i64;
    let slot_pso = server.pipeline.router.l0_table.pso_mask[slot_idx] & server.pipeline.server_pso_capabilities;
    let heavy_pso = server::STAGE_EGRESS_ALL | server::STAGE_INGRESS_AUTH_JWT | server::STAGE_INGRESS_ROUTE_RATELIMIT;
    guard (slot_pso & heavy_pso) == 0 else { return -1; }
    let handler_id = server.pipeline.router.l0_table.handler_id[slot_idx];
    return find_static_payload_index(server.pipeline.router, handler_id);
}

// Attempts to serve a single HTTP/1.1 static GET request from the L0 register table
// without allocating `Request` or `Response`.
//
// Example:
//   stream = "GET /plaintext HTTP/1.1\r\nHost: localhost\r\n\r\n"
//   returns: true, out_consumed = 44, out_close = false
fn try_fast_l0_static_turn<B>(
    server:       server::HttpServer&,
    stream:       const u8[:],
    hdr_end:      i64,
    now_sec:      i64,
    wire_out:     B&,
    out_consumed: i64&,
    out_close:    bool&,
    out_sp_idx:   i32&,
) -> bool {
    let header_end_idx = core::add_sat_i64(hdr_end, 4);
    let hdr_limit = if server.max_header_bytes > 0 { min(8192, server.max_header_bytes) } else { 8192 };
    guard hdr_end >= 14 && header_end_idx <= hdr_limit else { return false; }
    guard core::add_sat_i64(wire_out.len, 768) <= wire_out.cap else { return false; }

    let header_bytes = stream[..header_end_idx];
    let path, rest_offset, ok_line = parse_fast_l0_get_request_line(header_bytes);
    guard ok_line else { return false; }

    let sp_idx = match_fast_l0_static_payload(server, path);
    guard sp_idx >= 0 else { return false; }

    guard scan_fast_l0_static_headers(server, header_bytes[rest_offset..], out_close) else {
        return false;
    }

    if path == "/shutdown" {
        server.is_running = false;
    }
    append_fast_l0_static_response(
        server,
        server.pipeline.router.static_payloads[sp_idx as i64],
        now_sec,
        out_close,
        wire_out,
    );
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    out_consumed = header_end_idx;
    out_sp_idx = sp_idx;
    return true;
}

// Batches consecutive identical pipelined L0 static GET requests already in `stream_in` into `wire_out`
// when Keep-Alive header memoization (`server.enable_header_memoization`) is explicitly enabled.
fn drain_identical_l0_pipelined_batch<B>(
    server:         server::HttpServer&,
    prev_req:       const u8[:],
    sp_idx:         i32,
    fast_close:     bool,
    stream_in:      const u8[:],
    wire_out:       B&,
    total_handled:  i64&,
    total_consumed: i64&,
) -> const u8[:] {
    var stream = stream_in;
    let step = prev_req.len;
    guard server.enable_header_memoization
        && !fast_close
        && step > 0
        && sp_idx >= 0
        && server.is_running else {
        return stream;
    }
    let sp_i64 = sp_idx as i64;
    while stream.len >= step && core::add_sat_i64(wire_out.len, 768) <= wire_out.cap {
        guard stream[..step] == prev_req else { break; }
        wire_out.append(server.cached_date.fast_prefix[..]);
        wire_out.append(server.pipeline.router.static_payloads[sp_i64].payload_keep[..]);
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        total_handled = core::add_sat_i64(total_handled, 1);
        total_consumed = core::add_sat_i64(total_consumed, step);
        stream = stream[step..];
    }
    return stream;
}

// Runs the zero-allocation L0 static GET fast loop over `stream_in`, returning `(rem_stream, done)`.
//
// Example:
//   stream_in = "GET /plaintext HTTP/1.1\r\nHost: localhost\r\n\r\n"
//   returns: "", done = true, total_handled = 1
inline fn is_incomplete_l0_prefix(server: const server::HttpServer&, stream: const u8[:]) -> bool {
    let hdr_limit = if server.max_header_bytes > 0 { min(8192, server.max_header_bytes) } else { 8192 };
    return stream.len <= hdr_limit && is_possible_http_method_prefix(stream);
}

fn drain_fast_l0_static_stream<B>(
    server:           server::HttpServer&,
    stream_in:        const u8[:],
    now_ns:           u64,
    wire_out:         B&,
    total_handled:    i64&,
    total_consumed:   i64&,
    conn_wants_close: bool&,
) -> const u8[:], bool {
    var stream = stream_in;
    let now_sec = nanos_to_http_date_sec(now_ns);
    while stream.len > 0 {
        stream = strip_pipelined_crlf(stream, total_consumed);
        if stream.len == 0 {
            return stream, true;
        }
        let _pf = server::prof_enter("http1.framing");
        let hdr_end = core::fast_find_crlfcrlf(stream);
        server::prof_leave(_pf);
        if hdr_end < 0 {
            return stream, is_incomplete_l0_prefix(server, stream);
        }
        var fast_step:  i64  = 0;
        var fast_close: bool = false;
        var sp_idx:     i32  = -1;
        let _pl0 = server::prof_enter("http1.l0_turn");
        let ok_l0 = try_fast_l0_static_turn(server, stream, hdr_end, now_sec, wire_out, fast_step, fast_close, sp_idx);
        server::prof_leave(_pl0);
        guard ok_l0 else {
            return stream, false;
        }
        let prev_req = stream[..fast_step];
        total_handled = core::add_sat_i64(total_handled, 1);
        total_consumed = core::add_sat_i64(total_consumed, fast_step);
        stream = drain_identical_l0_pipelined_batch(
            server, prev_req, sp_idx, fast_close, stream[fast_step..], wire_out, total_handled, total_consumed,
        );
        if fast_close {
            conn_wants_close = true;
            return stream, true;
        }
    }
    return stream, true;
}

enum StreamTurnResult {
    Continue,
    Stop,
    ParseFail,
    KeepStreamFail,
}

inline fn classify_h1_stream_parse_failure<B>(
    server:   const server::HttpServer&,
    parse_st: server::H1WireParseStatus,
    stream:   const u8[:],
    wire_out: B&,
) -> StreamTurnResult {
    if parse_st == server::H1WireParseStatus.Incomplete && is_possible_http_method_prefix(stream) {
        return StreamTurnResult.KeepStreamFail;
    }
    emit_h1_parse_status_error(server, parse_st, wire_out);
    return StreamTurnResult.ParseFail;
}

fn process_pipelined_stream_turn<Stage, B>(
    server:           server::HttpServer&,
    client_ip:        const u8[:],
    stream:           const u8[:],
    now_ns:           u64,
    req:              http::Request&,
    res:              http::Response&,
    wire_out:         B&,
    wire_in_len:      i64,
    total_handled:    i64&,
    total_consumed:   i64&,
    conn_wants_close: bool&,
    stage:            Stage&,
) -> StreamTurnResult, i64 {
    guard core::add_sat_i64(wire_out.len, 256) <= wire_out.cap else { return StreamTurnResult.Stop, 0; }

    server::reset_server_request_fast(req);
    let parse_st, consumed = server::parse_http1_wire_request_with_limits(
        stream, req, server.max_header_bytes, server.max_body_bytes,
    );
    guard parse_st == server::H1WireParseStatus.Ok && consumed > 0 else {
        return classify_h1_stream_parse_failure(server, parse_st, stream, wire_out), 0;
    }

    if try_handle_pipelined_websocket(server, req, wire_out) {
        total_handled = core::add_sat_i64(total_handled, 1);
        total_consumed = core::add_sat_i64(total_consumed, consumed);
        return StreamTurnResult.Stop, consumed;
    }

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, wire_out, stage);
    total_handled = core::add_sat_i64(total_handled, 1);
    total_consumed = core::add_sat_i64(total_consumed, consumed);

    if wants_close || req.method[..] == "CONNECT" {
        conn_wants_close = true;
        if req.method[..] == "CONNECT" { total_consumed = wire_in_len; }
        return StreamTurnResult.Stop, consumed;
    }

    return StreamTurnResult.Continue, consumed;
}

fn drain_pipelined_stream_turns<Stage, B>(
    server:           server::HttpServer&,
    client_ip:        const u8[:],
    stream_in:        const u8[:],
    wire_in_len:      i64,
    now_ns:           u64,
    req:              http::Request&,
    res:              http::Response&,
    wire_out:         B&,
    total_handled:    i64&,
    total_consumed:   i64&,
    conn_wants_close: bool&,
    stage:            Stage&,
) -> bool {
    var offset: i64 = 0;
    while offset < stream_in.len {
        var crlf_skip: i64 = 0;
        let cur = strip_pipelined_crlf(stream_in[offset..], crlf_skip);
        if crlf_skip > 0 {
            total_consumed = core::add_sat_i64(total_consumed, crlf_skip);
            offset = core::add_sat_i64(offset, crlf_skip);
        }
        if cur.len == 0 { break; }

        let turn_res, step_consumed = process_pipelined_stream_turn(
            server, client_ip, cur, now_ns, req, res,
            wire_out, wire_in_len, total_handled, total_consumed, conn_wants_close, stage,
        );
        match turn_res {
            Continue => {
                offset = core::add_sat_i64(offset, step_consumed);
            },
            Stop => {
                break;
            },
            ParseFail => {
                conn_wants_close = true;
                return false;
            },
            KeepStreamFail => {
                conn_wants_close = false;
                return true;
            },
        };
    }
    return true;
}

fn try_prepare_single_pipeline_turn<B>(
    server:         const server::HttpServer&,
    stream_in:      const u8[:],
    wire_out:       const B&,
    total_consumed: i64&,
    out_has_req:    bool&,
) -> bool {
    guard is_turn_scratch_ready(server) && core::add_sat_i64(wire_out.len, 256) <= wire_out.cap else {
        return false;
    }

    var probe_consumed = total_consumed;
    let stream = strip_pipelined_crlf(stream_in, probe_consumed);
    if stream.len == 0 {
        total_consumed = probe_consumed;
        out_has_req = false;
        return true;
    }

    reset_server_request_fixed(g_turn_req);
    var presence_tracker = http::HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard parse_http1_request_headers_fixed(stream, g_turn_req, presence_tracker, body_start_idx) else {
        return false;
    }
    let hdr_cap = if server.max_header_bytes > 0 { server.max_header_bytes } else { 16384 };
    guard body_start_idx <= hdr_cap else { return false; }

    let has_te = (presence_tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0;
    let cl_len = if has_cl { presence_tracker.parsed_cl } else { 0 };
    let body_cap = if server.max_body_bytes >= 0 { server.max_body_bytes } else { server::MAX_SERVER_BODY_LIMIT };
    let expected_end = core::add_sat_i64(body_start_idx, cl_len);
    guard !has_te && cl_len >= 0 && cl_len <= body_cap && expected_end == stream.len else {
        return false;
    }

    let consumed = stream.len;
    if cl_len > 0 {
        let _pbf = server::prof_enter("http1.body_framing");
        g_turn_req.body.append(stream[body_start_idx..consumed]);
        server::prof_leave(_pbf);
    }

    total_consumed = core::add_sat_i64(probe_consumed, consumed);
    out_has_req = true;
    return true;
}

fn finish_single_pipeline_turn<Stage, B>(
    server:           server::HttpServer&,
    local_ip:         const u8[:],
    wire_in_len:      i64,
    now_ns:           u64,
    wire_out:         B&,
    total_handled:    i64&,
    total_consumed:   i64&,
    conn_wants_close: bool&,
    stage:            Stage&,
) {
    total_handled = core::add_sat_i64(total_handled, 1);
    acquire_turn_scratch(server);
    defer release_turn_scratch(server);
    if try_handle_pipelined_websocket(server, g_turn_req, wire_out) {
        return;
    }

    var future = server_internal::new_inline_handler_future(0);
    let _ = server::execute_server_pipeline_with_stage(
        server.pipeline, server.timer, local_ip, g_turn_req, now_ns, g_turn_res, future, stage,
    );

    let wants_close = check_and_apply_connection_close(g_turn_req, g_turn_res);
    server::serialize_http1_response(
        g_turn_res, server.server_name[..], wire_out, 0, resolve_server_header_policy(server),
    );
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);

    if wants_close || g_turn_req.method[..] == "CONNECT" {
        conn_wants_close = true;
        if g_turn_req.method[..] == "CONNECT" { total_consumed = wire_in_len; }
    }
}
