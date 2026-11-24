// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/1.1 wire turn execution, policy helpers, and pipelined parse failure recovery.
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
import .prof_hooks;
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
import .server_transport_internal;

inline fn resolve_server_header_policy(server: const server::HttpServer&) -> server::ServerHeaderPolicy {
    if server.omit_server_header && server.omit_date_header {
        return server::ServerHeaderPolicy.OmitBoth;
    }
    if server.omit_server_header {
        return server::ServerHeaderPolicy.OmitServer;
    }
    if server.omit_date_header {
        return server::ServerHeaderPolicy.OmitDate;
    }
    return server::ServerHeaderPolicy.Standard;
}

inline fn resolve_accept_conn_limit(server: const server::HttpServer&, explicit_max: i64) -> i64 {
    if explicit_max > 0 { return explicit_max; }
    return if server.max_connections > 0 { server.max_connections } else { 0 };
}

inline fn resolve_server_recv_timeout_ms(server: const server::HttpServer&, has_buffered: bool) -> u32 {
    let ms = if has_buffered { server.read_body_timeout_ms } else { server.read_header_timeout_ms };
    return if ms > 0 { ms } else { 5000 };
}

inline fn emit_h1_parse_status_error<B>(
    server:   const server::HttpServer&,
    status:   server::H1WireParseStatus,
    wire_out: B&,
) {
    let policy = resolve_server_header_policy(server);
    match status {
        HeadersTooLarge => { server::serialize_headers_too_large_error(server.server_name[..], wire_out, policy); },
        ContentTooLarge => { server::serialize_content_too_large_error(server.server_name[..], wire_out, policy); },
        _ => { server::serialize_bad_request_error(server.server_name[..], wire_out, policy); },
    };
}

inline fn is_http1_ingress_ready_or_over_limit(server: server::HttpServer&, in_buf: const u8[:]) -> bool {
    let pre = inspect_h1_wire_header_limit(in_buf, server.max_header_bytes);
    if pre == server::H1WireParseStatus.HeadersTooLarge || pre == server::H1WireParseStatus.BadRequest {
        return true;
    }
    if pre == server::H1WireParseStatus.Ok && server.max_body_bytes >= 0
        && server.max_body_bytes < server::MAX_SERVER_BODY_LIMIT {
        var tracker = http::HeaderPresenceTracker { .. };
        var body_start: i64 = 0;
        var probe = http::Request { .. };
        if parse_http1_request_headers(in_buf, probe, tracker, body_start)
            && (tracker.mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0
            && tracker.parsed_cl > server.max_body_bytes {
            return true;
        }
    }
    return server::has_ready_http1_request(in_buf, server.pipeline.hdr_scan_cursor);
}

inline fn strip_required_proxy_preface<B>(
    server:       const server::HttpServer&,
    wire_in:      const u8[:],
    effective_ip: u8[..64]&,
    wire_out:     B&,
) -> const u8[:], bool {
    var proxy_hdr = net::ProxyHeader { .. };
    let policy = resolve_server_header_policy(server);
    guard net::detect_proxy_protocol(wire_in) != net::ProxyProtocolVersion.None else {
        // uWS #1927 / HAProxy spec: When PROXY protocol is required, connections
        // without a valid PROXY preface MUST NOT fall through to plain HTTP.
        server::serialize_bad_request_error(server.server_name[..], wire_out, policy);
        return wire_in, false;
    }
    let stripped, has_proxy = net::detect_and_strip_proxy_header(wire_in, proxy_hdr);
    guard has_proxy else {
        server::serialize_bad_request_error(server.server_name[..], wire_out, policy);
        return wire_in, false;
    }
    if proxy_hdr.src_ip_str.len > 0 {
        let _ = effective_ip.try_set(proxy_hdr.src_ip_str[..]);
    }
    return stripped, true;
}

fn headers_have_conn_token(headers: const http::HeaderMap&, token: const u8[:]) -> bool {
    for &entry in headers.entries {
        if http::entry_name(headers, entry).eq_ascii_fold("connection") {
            if client::header_has_token(http::entry_value(headers, entry), token) {
                return true;
            }
        }
    }
    return false;
}

// Checks whether request or response demands connection closure (RFC 9112 §9.3 & NGINX proxy_pass harmony).
// Applies "Connection: close" to response headers if close is requested or for HTTP/1.0 without keep-alive.
fn check_and_apply_connection_close(req: const http::Request&, res: http::Response&) -> bool {
    guard res.status_code != 101 else { return false; }
    let has_conn_hdr = http::has_header(req, "connection") ||
        http::has_header(res, "connection") ||
        (res.presence_mask & http::RES_PRESENCE_CONNECTION) != 0;
    if !has_conn_hdr && !req.is_http10 && req.method[0] != 'C' {
        return false;
    }
    let wants_close = req.method[..] == "CONNECT" ||
        headers_have_conn_token(req.headers, "close") ||
        (req.is_http10 && !headers_have_conn_token(req.headers, "keep-alive")) ||
        headers_have_conn_token(res.headers, "close");
    if wants_close {
        http::set_header(res, "Connection", "close");
        return true;
    }
    return false;
}

inline fn apply_shutdown_connection_close(server: server::HttpServer&, res: http::Response&) {
    guard server.honor_shutdown_flag && net::shutdown_requested() else { return; }
    server.is_running = false;
    if res.status_code != rfc::STATUS_SWITCHING_PROTOCOLS {
        http::set_header(res, "Connection", "close");
    }
}

inline fn reset_server_response_fixed(res: http::Response&) {
    res.status_code = rfc::STATUS_OK;
    res.presence_mask = 0;
    res.headers.clear();
    res.trailers.clear();
}

inline fn reset_server_request_fixed(req: http::Request&) {
    req.method.clear();
    req.url.clear();
    req.trailers.clear();
    req.query_params.clear();
    req.is_http10 = false;
}

var g_turn_req: http::Request = http::Request { .. };

var g_turn_res: http::Response = http::Response { .. };

inline fn is_turn_scratch_ready(server: const server::HttpServer&) -> bool {
    return !server.turn_in_use && g_turn_req.body.len == 0 && g_turn_res.body.len == 0;
}

inline fn acquire_turn_scratch(server: server::HttpServer&) {
    server.turn_in_use = true;
    reset_server_response_fixed(g_turn_res);
}

inline fn release_turn_scratch(server: server::HttpServer&) {
    g_turn_req.body.clear();
    g_turn_res.body.clear();
    server.turn_in_use = false;
}

fn try_prepare_single_h1_wire_turn(
    server:     const server::HttpServer&,
    raw_stream: const u8[:],
) -> bool {
    guard is_turn_scratch_ready(server) else { return false; }

    reset_server_request_fixed(g_turn_req);
    var presence_tracker = http::HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard parse_http1_request_headers_fixed(raw_stream, g_turn_req, presence_tracker, body_start_idx) else {
        return false;
    }
    let hdr_cap = if server.max_header_bytes > 0 { server.max_header_bytes } else { 16384 };
    guard body_start_idx <= hdr_cap else { return false; }

    let has_te = (presence_tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0;
    let cl_len = if has_cl { presence_tracker.parsed_cl } else { 0 };
    let body_cap = if server.max_body_bytes >= 0 { server.max_body_bytes } else { server::MAX_SERVER_BODY_LIMIT };
    let total_consumed = core::add_sat_i64(body_start_idx, cl_len);
    guard !has_te && cl_len >= 0 && cl_len <= body_cap && raw_stream.len >= total_consumed else {
        return false;
    }
    if cl_len > 0 {
        let _pbf = server_prof::lit_prof_enter("http1.body_framing");
        g_turn_req.body.append(raw_stream[body_start_idx..total_consumed]);
        server_prof::lit_prof_leave(_pbf);
    }
    return true;
}

// Runs `WsUpgradeAuth` on `<Stage>` prior to emitting `101 Switching Protocols`.
// Serializes the stage's rejection response (`401`/`403`/etc.) and returns `false` if denied.
fn authorize_ws_upgrade_stage<Stage, B>(
    server:   server::HttpServer&,
    req:      const http::Request&,
    ws_idx:   i32,
    now_ns:   u64,
    res:      http::Response&,
    wire_out: B&,
    stage:    Stage&,
) -> bool {
    if is_noop_server_stage(stage) { return true; }
    reset_server_response_fast(res);
    var sctx = server::ServerStageCtx { handler_id: ws_idx, now_ns: now_ns, .. };
    let verdict = server::on_server_stage(
        stage, wire::ServerHookPhase.WsUpgradeAuth, server.pipeline, req, sctx, res,
    );
    let allowed = match verdict {
        Continue => true,
        ShortCircuit sc => {
            if res.status_code < 400 { res.status_code = sc.status_code as i32; }
            false
        },
        _ => {
            if res.status_code < rfc::STATUS_BAD_REQUEST { res.status_code = rfc::STATUS_FORBIDDEN; }
            false
        },
    };
    if !allowed {
        res.set_header("Connection", "close");
        server::serialize_http1_response(
            res, server.server_name[..], wire_out, 0, resolve_server_header_policy(server),
        );
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    }
    return allowed;
}

fn finish_single_h1_wire_turn<Stage, B>(
    server:       server::HttpServer&,
    effective_ip: const u8[:],
    now_ns:       u64,
    wire_out:     B&,
    stage:        Stage&,
) -> server::PipelineOutcome {
    acquire_turn_scratch(server);
    defer release_turn_scratch(server);
    if server.ws_route_count > 0
        && (g_turn_req.presence_mask & http::HDR_PRESENCE_UPGRADE) != 0
        && realtime::is_websocket_upgrade_request(g_turn_req) {
        let ws_idx = server::find_ws_route(server, g_turn_req.url[..]);
        if ws_idx >= 0 {
            if !authorize_ws_upgrade_stage(server, g_turn_req, ws_idx, now_ns, g_turn_res, wire_out, stage) {
                return server::PipelineOutcome.Handled;
            }
            if server::complete_ws_upgrade(server, g_turn_req, server.ws_routes[ws_idx as i64], wire_out) {
                return server::PipelineOutcome.Handled;
            }
        }
    }

    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }

    var future = server_internal::new_inline_handler_future(0);
    let out_outcome = if is_noop_server_stage(stage) {
        server::execute_pipeline(server.pipeline, server.timer, effective_ip, g_turn_req, now_ns, g_turn_res, future)
    } else {
        server::execute_server_pipeline_with_stage(
            server.pipeline, server.timer, effective_ip, g_turn_req, now_ns, g_turn_res, future, stage,
        )
    };

    check_and_apply_connection_close(g_turn_req, g_turn_res);
    apply_shutdown_connection_close(server, g_turn_res);
    server::serialize_http1_response(
        g_turn_res, server.server_name[..], wire_out, 0, resolve_server_header_policy(server),
    );
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);

    return out_outcome;
}

fn execute_single_h1_wire_turn<Stage, B>(
    server:       server::HttpServer&,
    effective_ip: const u8[:],
    raw_stream:   const u8[:],
    now_ns:       u64,
    req:          http::Request&,
    res:          http::Response&,
    wire_out:     B&,
    stage:        Stage&,
) -> server::PipelineOutcome, bool {
    server::reset_server_request_fast(req);
    let parse_st, _ = server::parse_http1_wire_request_with_limits(
        raw_stream, req, server.max_header_bytes, server.max_body_bytes,
    );
    guard parse_st == server::H1WireParseStatus.Ok else {
        emit_h1_parse_status_error(server, parse_st, wire_out);
        return server::PipelineOutcome.Handled, false;
    }

    // WebSocket Upgrade Interception (uWebSockets app.ws pattern) with pre-101 auth hook
    if server.ws_route_count > 0
        && (req.presence_mask & http::HDR_PRESENCE_UPGRADE) != 0
        && realtime::is_websocket_upgrade_request(req) {
        let ws_idx = server::find_ws_route(server, req.url[..]);
        if ws_idx >= 0 {
            if !authorize_ws_upgrade_stage(server, req, ws_idx, now_ns, res, wire_out, stage) {
                return server::PipelineOutcome.Handled, false;
            }
            if server::complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out) {
                return server::PipelineOutcome.Handled, true;
            }
        }
    }

    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }

    reset_server_response_fast(res);
    var future = server_internal::new_inline_handler_future(0);
    let outcome = if is_noop_server_stage(stage) {
        server::execute_pipeline(server.pipeline, server.timer, effective_ip, req, now_ns, res, future)
    } else {
        server::execute_server_pipeline_with_stage(
            server.pipeline, server.timer, effective_ip, req, now_ns, res, future, stage,
        )
    };

    check_and_apply_connection_close(req, res);
    apply_shutdown_connection_close(server, res);

    server::serialize_http1_response(
        res, server.server_name[..], wire_out, 0, resolve_server_header_policy(server),
    );
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);

    return outcome, true;
}

const H1_KNOWN_METHODS: (const u8[:])[9] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

fn is_possible_http_method_prefix(stream_in: const u8[:]) -> bool {
    guard stream_in.len > 0 else { return true; }
    var stream = stream_in;
    if stream.len == 1 && stream[0] == '\r' { return true; }
    if stream.len >= 2 && stream[0] == '\r' && stream[1] == '\n' {
        stream = stream[2..];
        guard stream.len > 0 else { return true; }
    }
    for m in H1_KNOWN_METHODS {
        if core::starts_with(stream, m) { return true; }
        if stream.len < m.len && m[..stream.len] == stream { return true; }
    }
    return false;
}

// Checks if pipelined stream body with Content-Length is incomplete or exceeds payload limits.
fn check_pipelined_content_length<B>(
    stream:      const u8[:],
    hdr_end:     i64,
    cl_str:      const u8[:],
    server_name: const u8[:],
    wire_out:    B&,
    out_keep:    bool&,
) -> bool {
    guard cl_str.len > 0 else { return false; }
    let cl_val, cl_ok = cl_str.trim_lws().parse_i64_dec();
    guard cl_ok && cl_val >= 0 else { return false; }
    if cl_val > server::MAX_SERVER_BODY_LIMIT {
        // RFC 9110 Section 15.5.14: Payload Too Large
        serialize_payload_too_large_error(server_name, wire_out);
        out_keep = false;
        return true;
    }
    if stream.len < core::add_sat_i64(core::add_sat_i64(hdr_end, 4), cl_val) {
        out_keep = true;
        return true;
    }
    return false;
}

// Scans chunk headers in `chunk_slice` to accumulate total declared payload bytes and detect framing errors.
//
// Example:
//   chunk_slice = "5\r\nhello\r\n0\r\n\r\n"
//   returns: total_sz = 5, err = ChunkedDecodeError.None
fn scan_chunked_cumulative_size(chunk_slice: const u8[:]) -> u64, http::ChunkedDecodeError {
    var cur:      i64 = 0;
    var total_sz: u64 = 0;
    while cur < chunk_slice.len {
        let chunk_sz, sz_err = http::read_chunk_size_line(chunk_slice, cur);
        guard sz_err == http::ChunkedDecodeError.None else { return total_sz, sz_err; }
        total_sz = core::add_sat_u64(total_sz, chunk_sz);
        if total_sz > (server::MAX_SERVER_BODY_LIMIT as u64) || chunk_sz == 0 {
            return total_sz, http::ChunkedDecodeError.None;
        }
        let data_end = core::add_sat_i64(cur, chunk_sz as i64);
        let next_cur = core::add_sat_i64(data_end, 2);
        guard next_cur <= chunk_slice.len else { return total_sz, http::ChunkedDecodeError.UnexpectedEof; }
        guard chunk_slice[data_end] == '\r' && chunk_slice[core::add_sat_i64(data_end, 1)] == '\n' else {
            return total_sz, http::ChunkedDecodeError.MalformedChunkEnding;
        }
        cur = next_cur;
    }
    return total_sz, http::ChunkedDecodeError.UnexpectedEof;
}

fn check_pipelined_chunked_head<B>(
    stream:      const u8[:],
    hdr_end:     i64,
    server_name: const u8[:],
    wire_out:    B&,
    out_keep:    bool&,
) -> bool {
    let chunk_slice = stream[core::add_sat_i64(hdr_end, 4)..];
    let total_sz, sz_err = scan_chunked_cumulative_size(chunk_slice);
    if total_sz > (server::MAX_SERVER_BODY_LIMIT as u64) {
        serialize_payload_too_large_error(server_name, wire_out);
        out_keep = false;
        return false;
    }
    if sz_err != http::ChunkedDecodeError.None &&
       sz_err != http::ChunkedDecodeError.UnexpectedEof &&
       sz_err != http::ChunkedDecodeError.EmptyInput {
        server::serialize_bad_request_error(server_name, wire_out);
        out_keep = false;
        return false;
    }
    out_keep = true;
    return true;
}

enum PipeStepResult {
    Continue,
    Stop,
    Error,
}

// Strips at most one optional benign CRLF between pipelined requests (RFC 9112 Section 2.2).
//
// Example:
//   stream = "\r\nGET / HTTP/1.1", consumed_crlf = 0
//   returns: "GET / HTTP/1.1", consumed_crlf = 2
inline fn strip_pipelined_crlf(stream: const u8[:], consumed_crlf: i64&) -> const u8[:] {
    if stream.len >= 2 && stream[0] == '\r' && stream[1] == '\n' {
        if stream.len == 2 || (stream[2] != '\r' && stream[2] != '\n') {
            consumed_crlf = core::add_sat_i64(consumed_crlf, 2);
            return stream[2..];
        }
    }
    return stream;
}

fn try_handle_pipelined_websocket<B>(
    server:   server::HttpServer&,
    req:      const http::Request&,
    wire_out: B&,
) -> bool {
    guard server.ws_route_count > 0 && (req.presence_mask & http::HDR_PRESENCE_UPGRADE) != 0 else { return false; }
    guard realtime::is_websocket_upgrade_request(req) else { return false; }
    let ws_idx = server::find_ws_route(server, req.url[..]);
    guard ws_idx >= 0 else { return false; }
    return server::complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out);
}

inline fn reset_server_response_fast(res: http::Response&) {
    res.status_code = rfc::STATUS_OK;
    res.presence_mask = 0;
    res.headers.clear();
    res.trailers.clear();
    res.body.clear();
}

fn dispatch_pipelined_request<Stage, B>(
    server:    server::HttpServer&,
    client_ip: const u8[:],
    req:       http::Request&,
    res:       http::Response&,
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> bool {
    reset_server_response_fast(res);
    var future = server_internal::new_inline_handler_future(0);
    let _ = server::execute_server_pipeline_with_stage(
        server.pipeline, server.timer, client_ip, req, now_ns, res, future, stage,
    );

    let wants_close = check_and_apply_connection_close(req, res);
    server::serialize_http1_response(
        res, server.server_name[..], wire_out, 0, resolve_server_header_policy(server),
    );
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    return wants_close;
}

inline fn classify_h1_pipe_parse_failure<B>(
    server:   const server::HttpServer&,
    parse_st: server::H1WireParseStatus,
    stream:   const u8[:],
    pipe:     core::PipeBuffer&,
    wire_out: B&,
) -> PipeStepResult {
    pipe.advance_to(0, pipe.readable_len());
    if parse_st == server::H1WireParseStatus.Incomplete && is_possible_http_method_prefix(stream) {
        return PipeStepResult.Stop;
    }
    emit_h1_parse_status_error(server, parse_st, wire_out);
    return PipeStepResult.Error;
}

fn process_pipelined_pipe_step<Stage, B>(
    server:        server::HttpServer&,
    client_ip:     const u8[:],
    pipe:          core::PipeBuffer&,
    req:           http::Request&,
    res:           http::Response&,
    now_ns:        u64,
    total_handled: i64&,
    wire_out:      B&,
    stage:         Stage&,
) -> PipeStepResult {
    let stream = pipe.readable_slice();
    server::reset_server_request_fast(req);
    let parse_st, consumed = server::parse_http1_wire_request_with_limits(
        stream, req, server.max_header_bytes, server.max_body_bytes,
    );

    if parse_st != server::H1WireParseStatus.Ok || consumed <= 0 {
        return classify_h1_pipe_parse_failure(server, parse_st, stream, pipe, wire_out);
    }

    if try_handle_pipelined_websocket(server, req, wire_out) {
        total_handled = core::add_sat_i64(total_handled, 1);
        pipe.advance_to(consumed, consumed);
        pipe.advance_to(pipe.readable_len(), pipe.readable_len());
        return PipeStepResult.Stop;
    }

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, wire_out, stage);
    total_handled = core::add_sat_i64(total_handled, 1);
    pipe.advance_to(consumed, consumed);

    if req.method[..] == "CONNECT" || wants_close {
        pipe.advance_to(pipe.readable_len(), pipe.readable_len());
        return PipeStepResult.Stop;
    }
    return PipeStepResult.Continue;
}

inline fn refresh_http_server_date(server: server::HttpServer&, now_sec: i64) {
    update_server_cached_date(server.cached_date, now_sec, server.server_name[..]);
}

// Converts monotonic nanoseconds to seconds for HTTP Date header caching.
inline fn nanos_to_http_date_sec(now_ns: u64) -> i64 {
    return div_euclid(now_ns, 1000000000) as i64;
}

// Handles incomplete pipelined HTTP stream or syntax errors.
fn handle_pipelined_parse_failure<B>(
    server_name:     const u8[:],
    stream:          const u8[:],
    req:             const http::Request&,
    wire_out:        B&,
    out_keep_stream: bool&,
) -> bool {
    let hdr_end = core::fast_find_crlfcrlf(stream);
    let is_valid_prefix = is_possible_http_method_prefix(stream);

    if hdr_end >= 0 && core::add_sat_i64(hdr_end, 4) <= 8192 && is_valid_prefix && req.headers.entries.len > 0 {
        let has_te = http::has_header(req, "transfer-encoding");
        let has_cl = http::has_header(req, "content-length");
        // If both TE and CL are present, reject immediately as smuggling attempt (RFC 9112 §6.1, §6.3)
        if has_te && has_cl {
            server::serialize_bad_request_error(server_name, wire_out);
            out_keep_stream = false;
            return false;
        }

        // Headers are complete; check if Content-Length body is still incomplete
        let cl_str = req.header("content-length");
        var cl_handled_keep = false;
        if has_cl {
            let cl_done = check_pipelined_content_length(
                stream,
                hdr_end,
                cl_str,
                server_name,
                wire_out,
                cl_handled_keep,
            );
            if cl_done {
                out_keep_stream = cl_handled_keep;
                return cl_handled_keep;
            }
        }
        let te_str = req.header("transfer-encoding");
        if has_te && validate_decodeable_chunked_te(te_str) {
            return check_pipelined_chunked_head(
                stream,
                hdr_end,
                server_name,
                wire_out,
                out_keep_stream,
            );
        }
    }

    if hdr_end >= 0 || stream.len > 8192 || !is_valid_prefix {
        // Complete headers but invalid syntax, or header overflow > 8192,
        // or trailing unparseable poison bytes: 400 Bad Request
        server::serialize_bad_request_error(server_name, wire_out);
        out_keep_stream = false;
        return false;
    }
    // Legitimate incomplete request across packet boundary: return so caller preserves stream in leftover
    out_keep_stream = true;
    return true;
}
