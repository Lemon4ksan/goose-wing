// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/1.1 pipelining, fast L0 static turns, WebSocket upgrade, and listener loop helpers.
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
import .pool;
import .pipeline;
import .pipeline_internal;
import .profiler;
import .h2_multiplexer;
import .soa_timer;
import .internal;
import .h1_codec;
import .h1_codec_internal;
import .cork;
import .stream_consumer;
import .sni;
import .server;
import .reactor;
import .reactor_internal;

const WS_UPGRADE_PREFIX: const u8[:] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";

const WS_SUBPROTO_PREFIX: const u8[:] = "Sec-WebSocket-Protocol: ";

const WS_PERMESSAGE_DEFLATE_HDR: const u8[:] = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n";

const WS_HDR_CRLF: const u8[:] = "\r\n";

fn serialize_and_init_ws_upgrade<B>(
    route_behavior: const realtime::WsBehavior&,
    pending:        realtime::WsPendingUpgrade&,
    subproto:       const u8[:],
    out_wire:       B&,
) -> realtime::WebSocketSession, bool {
    var session = realtime::new_websocket_session(false);
    guard subproto.len <= session.subprotocol.cap && pending.user_data.len <= session.user_data.cap else {
        return realtime::WebSocketSession { .. }, false;
    }

    var accept_key: u8[..64] = [];
    realtime::compute_websocket_accept(pending.client_key[..], accept_key);

    let prev_out_len = out_wire.len;
    out_wire.append(WS_UPGRADE_PREFIX);
    out_wire.append(accept_key[..]);
    out_wire.append(WS_HDR_CRLF);
    var expected_add = core::add_sat_i64(
        WS_UPGRADE_PREFIX.len,
        core::add_sat_i64(accept_key.len, WS_HDR_CRLF.len),
    );

    if subproto.len > 0 {
        out_wire.append(WS_SUBPROTO_PREFIX);
        out_wire.append(subproto);
        out_wire.append(WS_HDR_CRLF);
        let sub_add = core::add_sat_i64(
            WS_SUBPROTO_PREFIX.len,
            core::add_sat_i64(subproto.len, WS_HDR_CRLF.len),
        );
        expected_add = core::add_sat_i64(expected_add, sub_add);
    }

    let compress_active = route_behavior.compression != realtime::WS_COMPRESS_DISABLED
        && pending.extensions[..].contains_fold("permessage-deflate");
    if compress_active {
        out_wire.append(WS_PERMESSAGE_DEFLATE_HDR);
        expected_add = core::add_sat_i64(expected_add, WS_PERMESSAGE_DEFLATE_HDR.len);
    }

    out_wire.append(WS_HDR_CRLF);
    expected_add = core::add_sat_i64(expected_add, WS_HDR_CRLF.len);
    guard out_wire.len == core::add_sat_i64(prev_out_len, expected_add) else {
        return realtime::WebSocketSession { .. }, false;
    }

    session.compress_mode = route_behavior.compression;
    session.permessage_deflate = compress_active;
    session.max_payload_length = route_behavior.max_payload_length;
    session.max_backpressure = route_behavior.max_backpressure;
    session.close_on_backpressure_limit = route_behavior.close_on_backpressure_limit;
    session.idle_timeout_s = route_behavior.idle_timeout_s;
    session.max_lifetime_s = route_behavior.max_lifetime_s;
    session.send_pings_automatically = route_behavior.send_pings_automatically;
    session.reset_idle_timeout_on_send = route_behavior.reset_idle_timeout_on_send;

    if subproto.len > 0 {
        session.subprotocol.append(subproto);
    }
    session.user_tag = pending.user_tag;
    if pending.user_data.len > 0 {
        session.user_data.append(pending.user_data[..]);
    }

    pending.in_use = false;
    return session, true;
}

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

fn populate_server_tls_backend_config(
    srv:       const server::HttpServer&,
    alpn_wire: const u8[:],
    bcfg:      tls::TlsBackendConfig&,
) -> bool, tls::TlsBackendStatus {
    guard bcfg.cert_pem_file.try_set(srv.tls_cert_pem_file[..]) &&
        bcfg.key_pem_file.try_set(srv.tls_key_pem_file[..]) else {
        return false, tls::TlsBackendStatus.Error;
    }
    if srv.tls_require_client_cert {
        guard srv.tls_ca_file.len > 0 && bcfg.ca_file.try_set(srv.tls_ca_file[..]) else {
            return false, tls::TlsBackendStatus.VerifyError;
        }
    }
    if srv.tls_keylog_file.len > 0 {
        guard bcfg.keylog_file.try_set(srv.tls_keylog_file[..]) else {
            return false, tls::TlsBackendStatus.Error;
        }
    }
    if alpn_wire.len > 0 {
        guard bcfg.alpn_wire.try_set(alpn_wire) else { return false, tls::TlsBackendStatus.Error; }
    } else if srv.tls_alpn_wire.len > 0 {
        guard bcfg.alpn_wire.try_set(srv.tls_alpn_wire[..]) else { return false, tls::TlsBackendStatus.Error; }
    } else {
        let def_alpn: u8[12] = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
        let _ = bcfg.alpn_wire.try_set(def_alpn[..]);
    }
    return true, tls::TlsBackendStatus.Ok;
}

// Emits the initial HTTP/2 server SETTINGS frame reflecting `server.max_h2_concurrent_streams`
// and `server.max_header_bytes`, returning 24 if the client preface was consumed.
fn prepare_h2_server_preface<B>(
    sess:       H2ServerSession&,
    server:     const server::HttpServer&,
    raw_stream: const u8[:],
    out_wire:   B&,
) -> i64 {
    let max_streams = if server.max_h2_concurrent_streams > 0 { server.max_h2_concurrent_streams } else { 100 };
    sess.conn.max_concurrent_streams = max_streams;
    if server.max_header_bytes > 0 {
        sess.conn.max_header_list_size = min(server.max_header_bytes, 0x7FFFFFFF) as u32;
    }
    if server.omit_server_header {
        sess.server_name.clear();
    }
    guard !sess.preface_handled && server::is_h2_client_preface(raw_stream) else {
        return 0;
    }
    sess.preface_handled = true;
    let hdr = http2::FrameHeader {
        length:     24,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    http2::encode_frame_header_to(hdr, out_wire);
    out_wire.append_u16_be(rfc::H2_SETTING_MAX_CONCURRENT_STREAMS);
    out_wire.append_u32_be(max_streams);
    out_wire.append_u16_be(rfc::H2_SETTING_INITIAL_WINDOW_SIZE);
    out_wire.append_u32_be(8192);
    out_wire.append_u16_be(rfc::H2_SETTING_MAX_FRAME_SIZE);
    out_wire.append_u32_be(16384);
    out_wire.append_u16_be(rfc::H2_SETTING_ENABLE_CONNECT_PROTO);
    out_wire.append_u32_be(1);
    sess.server_settings_sent = true;
    sess.pending_settings_ack = true;
    return 24;
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
    let pre = server::inspect_h1_wire_header_limit(in_buf, server.max_header_bytes);
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
    if res.status_code != 101 {
        http::set_header(res, "Connection", "close");
    }
}

inline fn reset_server_response_fixed(res: http::Response&) {
    res.status_code = 200;
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
        let _pbf = server::prof_enter("http1.body_framing");
        g_turn_req.body.append(raw_stream[body_start_idx..total_consumed]);
        server::prof_leave(_pbf);
    }
    return true;
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
        if ws_idx >= 0 && server::complete_ws_upgrade(server, g_turn_req, server.ws_routes[ws_idx as i64], wire_out) {
            return server::PipelineOutcome.Handled;
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

    // WebSocket Upgrade Interception (uWebSockets app.ws pattern)
    if server.ws_route_count > 0
        && (req.presence_mask & http::HDR_PRESENCE_UPGRADE) != 0
        && realtime::is_websocket_upgrade_request(req) {
        let ws_idx = server::find_ws_route(server, req.url[..]);
        if ws_idx >= 0 && server::complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out) {
            return server::PipelineOutcome.Handled, true;
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

fn is_possible_http_method_prefix(stream_in: const u8[:]) -> bool {
    guard stream_in.len > 0 else { return true; }
    var stream = stream_in;
    if stream.len == 1 && stream[0] == '\r' { return true; }
    if stream.len >= 2 && stream[0] == '\r' && stream[1] == '\n' {
        stream = stream[2..];
        guard stream.len > 0 else { return true; }
    }
    if core::starts_with(stream, "GET") { return true; }
    if core::starts_with(stream, "POST") { return true; }
    if core::starts_with(stream, "HEAD") { return true; }
    if core::starts_with(stream, "PUT") { return true; }
    if core::starts_with(stream, "DELETE") { return true; }
    if core::starts_with(stream, "OPTIONS") { return true; }
    if core::starts_with(stream, "PATCH") { return true; }
    if core::starts_with(stream, "CONNECT") { return true; }
    if core::starts_with(stream, "TRACE") { return true; }
    if stream.len < 7 {
        if "OPTIONS"[..stream.len] == stream { return true; }
        if "CONNECT"[..stream.len] == stream { return true; }
        if "DELETE"[..stream.len] == stream { return true; }
        if "PATCH"[..stream.len] == stream { return true; }
        if "TRACE"[..stream.len] == stream { return true; }
        if "POST"[..stream.len] == stream { return true; }
        if "HEAD"[..stream.len] == stream { return true; }
        if "GET"[..stream.len] == stream { return true; }
        if "PUT"[..stream.len] == stream { return true; }
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
    if stream.len < (hdr_end + 4 + cl_val) {
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
    res.status_code = 200;
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
    server::refresh_http_server_date(server, now_sec);
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
    let now_sec = server::nanos_to_http_date_sec(now_ns);
    while stream.len > 0 {
        stream = strip_pipelined_crlf(stream, total_consumed);
        if stream.len == 0 {
            return stream, true;
        }
        let _pf = server::prof_enter("http1.framing");
        let hdr_end = core::fast_find_crlfcrlf(stream);
        server::prof_leave(_pf);
        if hdr_end < 0 {
            let hdr_limit = if server.max_header_bytes > 0 { min(8192, server.max_header_bytes) } else { 8192 };
            if stream.len <= hdr_limit && is_possible_http_method_prefix(stream) {
                return stream, true;
            }
            return stream, false;
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
    var stream = stream_in;
    while stream.len > 0 {
        stream = strip_pipelined_crlf(stream, total_consumed);
        if stream.len == 0 { break; }

        let turn_res, step_consumed = process_pipelined_stream_turn(
            server, client_ip, stream, now_ns, req, res,
            wire_out, wire_in_len, total_handled, total_consumed, conn_wants_close, stage,
        );
        match turn_res {
            Continue => {
                stream = stream[step_consumed..];
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

inline fn handle_h2_pipe_ingress<Stage, B>(
    server:     server::HttpServer&,
    client_ip:  const u8[:],
    pipe:       core::PipeBuffer&,
    h2_sess:    server_internal::H2ServerSession&,
    now_ns:     u64,
    unread_len: i64,
    wire_out:   B&,
    stage:      Stage&,
) -> i64, bool {
    let stream = pipe.readable_slice();
    let pref_len = prepare_h2_server_preface(h2_sess, server, stream, wire_out);
    let consumed_body, ok_h2 = server_internal::handle_h2_server_ingress(
        h2_sess, server.pipeline, server.timer, client_ip, stream[pref_len..],
        div_euclid(now_ns, 1000000), wire_out, stage,
    );
    let consumed_h2 = core::add_sat_i64(pref_len, consumed_body);
    if ok_h2 {
        pipe.advance_to(consumed_h2, consumed_h2);
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        return 1, true;
    }
    pipe.advance_to(consumed_h2, unread_len);
    return 0, false;
}

// Executes one ingress step of an HTTP/2 server session and flushes any outbound frames.
inline fn step_h2_server_session_buf<InBuf, OutBuf>(
    conn_fd:  i64,
    server:   server::HttpServer&,
    h2_idx:   i64,
    peer_ip:  const u8[:],
    h2_in:    InBuf&,
    now_ns:   u64,
    out_wire: OutBuf&,
) -> bool {
    out_wire.clear();
    let pref_len = prepare_h2_server_preface(
        server::g_default_reactor.h2_sessions[h2_idx], server, h2_in[..], out_wire,
    );
    let consumed_body, ok = server_internal::handle_h2_server_ingress(
        server::g_default_reactor.h2_sessions[h2_idx],
        server.pipeline,
        server.timer,
        peer_ip,
        h2_in[pref_len..],
        div_euclid(now_ns, 1000000),
        out_wire,
    );
    let consumed = core::add_sat_i64(pref_len, consumed_body);
    if out_wire.len > 0 {
        let _ = net::tcp_send(conn_fd, out_wire[..]);
    }
    guard ok else { return false; }
    if consumed > 0 {
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        h2_in.compact_wire_buffer(consumed);
    }
    return true;
}

// Runs a persistent HTTP/2 server session loop over `conn_fd` using caller-supplied `h2_in` buffer (RFC 9113).
fn serve_h2_connection_buf<InBuf>(
    server:          server::HttpServer&,
    conn_fd:         i64,
    h2_in:           InBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    guard conn_fd > 0 else { return false; }
    server.pipeline.trust_proxy_headers = server.pipeline.trust_proxy_headers || server.trust_proxy_headers;
    let h2_idx = server::alloc_temp_h2_session(
        server.pipeline, server.server_name[..], 1000000000, server.max_h2_concurrent_streams,
    );
    guard h2_idx >= 0 && h2_idx < server::REACTOR_MAX_H2_SESSIONS else { return false; }
    defer server::free_reactor_h2_session(h2_idx as i16, server.pipeline);

    var peer_ip: u8[..64] = [];
    net::tcp_get_peer_ip(conn_fd, peer_ip);

    var out_wire:   u8[..65536] = [];
    var chunk:      u8[..4096]  = [];
    var now_ns:     u64         = 1000000000;
    var idle_ticks: u64         = 0;
    loop {
        if !step_h2_server_session_buf(conn_fd, server, h2_idx, peer_ip[..], h2_in, now_ns, out_wire) {
            chunk.clear();
            let _ = net::tcp_recv(conn_fd, chunk, 4096, 10);
            return false;
        }
        chunk.clear();
        let recvd = net::tcp_recv(conn_fd, chunk, 4096, recv_timeout_ms);
        if recvd == -2 {
            idle_ticks = core::add_sat_u64(idle_ticks, 1);
            if idle_ticks >= 2 { break; }
            continue;
        }
        if !server::try_append_recv_chunk(recvd, chunk, h2_in) {
            break;
        }
        idle_ticks = 0;
        now_ns = core::add_sat_u64(now_ns, 10000000);
    }
    return true;
}

// Completes an RFC 6455 HTTP/1.1 WebSocket upgrade on `conn_fd`, wires route behavior limits,
// compacts `in_buf` past the HTTP request, and drives the WebSocket frame loop.
fn serve_http1_upgraded_ws<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:     i64,
    server:      server::HttpServer&,
    req:         const http::Request&,
    consumed:    i64,
    stage:       Stage&,
    in_buf:      InBuf&,
    ws_frag_buf: FragBuf&,
    out_wire:    OutBuf&,
) -> bool {
    let r_idx = server::find_ws_route(server, req.url[..]);
    guard r_idx >= 0 else { return false; }
    let behavior = server.ws_routes[r_idx as i64].behavior;
    var ws_res = http::Response { .. };
    var ws, ok_ws = realtime::ws_upgrade_request(req, ws_res, behavior.subprotocol[..]);
    guard ok_ws else { return false; }
    ws.max_payload_length = behavior.max_payload_length;
    ws.max_backpressure = behavior.max_backpressure;
    ws.close_on_backpressure_limit = behavior.close_on_backpressure_limit;
    ws.idle_timeout_s = behavior.idle_timeout_s;
    ws.max_lifetime_s = behavior.max_lifetime_s;
    ws.send_pings_automatically = behavior.send_pings_automatically;
    ws.reset_idle_timeout_on_send = behavior.reset_idle_timeout_on_send;
    let ua_upg = req.header("user-agent");
    if behavior.compression != realtime::WS_COMPRESS_DISABLED && !realtime::ws_has_broken_compression(ua_upg) {
        let client_ext = req.header("sec-websocket-extensions");
        if client_ext.contains_fold("permessage-deflate") {
            ws_res.set_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover");
            ws.enable_permessage_deflate(behavior.compression);
        }
    }
    out_wire.clear();
    server::serialize_http1_response(
        ws_res, server.server_name[..], out_wire, 0, resolve_server_header_policy(server),
    );
    let _ = net::tcp_send(conn_fd, out_wire[..]);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    in_buf.compact_wire_buffer(consumed);
    realtime::serve_ws_session_buf(conn_fd, ws, stage, in_buf, ws_frag_buf, out_wire);
    return true;
}

// Flushes buffered HTTP/1.1 response frames in `out_wire` to `conn_fd` and resets the cork buffer.
inline fn flush_http1_cork_buf<OutBuf>(conn_fd: i64, out_wire: OutBuf&) {
    if out_wire.len > 0 {
        let _ = net::tcp_send(conn_fd, out_wire[..]);
        out_wire.clear();
    }
}

fn dispatch_http1_connection_turn<Stage, OutBuf>(
    conn_fd:  i64,
    server:   server::HttpServer&,
    peer_ip:  const u8[:],
    req:      const http::Request&,
    stage:    Stage&,
    out_wire: OutBuf&,
) -> bool {
    var res = http::Response { .. };
    let now_ns = core::monotonic_now().as_nanos();
    let _ = server::dispatch_server_request_with_stage(server, peer_ip, req, now_ns, res, stage);
    if req.url[..] == "/shutdown" && res.status_code == 200 {
        server.is_running = false;
    }
    if server.honor_shutdown_flag && net::shutdown_requested() {
        server.is_running = false;
    }
    let conn_hdr = res.header("Connection");
    let wants_ka = server.is_running && conn_hdr.eq_ascii_fold("keep-alive");
    if !wants_ka && conn_hdr.len == 0 {
        http::set_header(res, "Connection", "close");
    }
    if out_wire.len >= 12288 {
        flush_http1_cork_buf(conn_fd, out_wire);
    }
    server::serialize_http1_response(
        res, server.server_name[..], out_wire, 0, resolve_server_header_policy(server),
    );
    return wants_ka;
}

// Serves an auxiliary concurrent connection accepted while a primary connection is idle pre-preface (h2spec).
fn serve_idle_aux_connection(listener_fd: i64, server: server::HttpServer&, recv_timeout_ms: u32) -> bool {
    guard listener_fd > 0 else { return false; }
    let aux_conn = net::tcp_accept(listener_fd, 0);
    guard aux_conn > 0 else { return false; }
    var aux_in:    u8[..65536] = [];
    var aux_chunk: u8[..4096]  = [];
    var ticks:     u64         = 0;
    while ticks < 10 {
        aux_chunk.clear();
        let recvd = net::tcp_recv(aux_conn, aux_chunk, 4096, 15);
        if recvd == -2 {
            ticks = core::add_sat_u64(ticks, 1);
            continue;
        }
        if !server::try_append_recv_chunk(recvd, aux_chunk, aux_in) {
            break;
        }
        ticks = 0;
        if !server::is_partial_h2_client_preface(aux_in[..]) {
            if server::is_h2_client_preface(aux_in[..]) {
                let _ = serve_h2_connection_buf(server, aux_conn, aux_in, recv_timeout_ms);
            }
            break;
        }
    }
    net::tcp_close(aux_conn);
    return true;
}

// Processes a complete buffered HTTP/1.1 request in `in_buf` (WebSocket upgrade or HTTP/1.1 pipeline turn).
// Returns true if the connection loop should continue reading another keep-alive request.
fn process_ready_http1_connection_buf<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:     i64,
    server:      server::HttpServer&,
    peer_ip:     const u8[:],
    stage:       Stage&,
    in_buf:      InBuf&,
    ws_frag_buf: FragBuf&,
    out_wire:    OutBuf&,
) -> bool {
    var req = http::new_request("GET", "");
    let parse_st, consumed = server::parse_http1_wire_request_with_limits(
        in_buf[..], req, server.max_header_bytes, server.max_body_bytes,
    );
    guard parse_st == server::H1WireParseStatus.Ok && consumed > 0 else {
        flush_http1_cork_buf(conn_fd, out_wire);
        emit_h1_parse_status_error(server, parse_st, out_wire);
        flush_http1_cork_buf(conn_fd, out_wire);
        return false;
    }
    if realtime::is_websocket_upgrade_request(req) {
        flush_http1_cork_buf(conn_fd, out_wire);
        if serve_http1_upgraded_ws(conn_fd, server, req, consumed, stage, in_buf, ws_frag_buf, out_wire) {
            return false;
        }
    }
    let wants_ka = dispatch_http1_connection_turn(conn_fd, server, peer_ip, req, stage, out_wire);
    in_buf.compact_wire_buffer(consumed);
    return wants_ka;
}

// RFC 9113 Section 3.4: HTTP/2 Connection Preface - An invalid connection preface MUST be treated as a PROTOCOL_ERROR connection error; connection termination without GOAWAY is permitted.
inline fn is_invalid_connection_preface(in_buf: const u8[:]) -> bool {
    if in_buf.len >= 4 && in_buf[..4] == "PRI " {
        return true;
    }
    if in_buf.len >= 18 && in_buf[..18] == "INVALID CONNECTION" {
        return true;
    }
    return false;
}

// Handles a newly received HTTP/2 preface or invalid connection preface in `in_buf`.
// Returns true if the connection was handled/terminated as HTTP/2 or invalid preface.
fn try_dispatch_h2_or_invalid_preface_buf<InBuf>(
    server:          server::HttpServer&,
    conn_fd:         i64,
    in_buf:          InBuf&,
    recv_timeout_ms: u32,
) -> bool {
    guard !server::is_partial_h2_client_preface(in_buf[..]) else { return false; }
    if server::is_h2_client_preface(in_buf[..]) {
        let _ = serve_h2_connection_buf(server, conn_fd, in_buf, recv_timeout_ms);
        return true;
    }
    return is_invalid_connection_preface(in_buf[..]);
}

// Handles an idle poll timeout (`recvd == -2`) on `conn_fd`, polling `listener_fd` for auxiliary connections.
inline fn step_idle_connection_poll(
    listener_fd:     i64,
    server:          server::HttpServer&,
    in_buf_len:      i64,
    recv_timeout_ms: u32,
    idle_ticks:      u64&,
) {
    if in_buf_len == 0 && serve_idle_aux_connection(listener_fd, server, recv_timeout_ms) {
        idle_ticks = 0;
        return;
    }
    idle_ticks = core::add_sat_u64(idle_ticks, 1);
}

// Polls `conn_fd` once and appends received bytes to `in_buf`, handling idle timeouts and HTTP/2 prefaces.
// Returns true if the caller should continue polling `conn_fd`, or false if the connection is complete/closed.
fn poll_http_connection_ingress_buf<InBuf>(
    listener_fd:     i64,
    conn_fd:         i64,
    server:          server::HttpServer&,
    in_buf:          InBuf&,
    poll_ms:         u32,
    recv_timeout_ms: u32,
    idle_ticks:      u64&,
) -> bool {
    var chunk: u8[..4096] = [];
    let recvd = net::tcp_recv(conn_fd, chunk, 4096, poll_ms);
    if recvd == -2 {
        step_idle_connection_poll(listener_fd, server, in_buf.len, recv_timeout_ms, idle_ticks);
        return idle_ticks < 25;
    }
    guard server::try_append_recv_chunk(recvd, chunk, in_buf) else { return false; }
    idle_ticks = 0;
    return !try_dispatch_h2_or_invalid_preface_buf(server, conn_fd, in_buf, recv_timeout_ms);
}

fn step_page_ring_conn<Stage>(
    server:  server::HttpServer&,
    conn:    i64,
    peer_ip: const u8[:],
    ring:    core::PageRingBuffer&,
    cork:    core::CorkBuffer&,
    stage:   Stage&,
) -> bool {
    let recv_ms = resolve_server_recv_timeout_ms(server, ring.count > 0);
    let recvd = ring.page_ring_recv(conn, 65536, recv_ms);
    guard recvd > 0 else { return false; }
    let now_ns = core::monotonic_now().as_nanos();
    let _, ok_handle = server::handle_connection_page_ring(server, peer_ip, ring, now_ns, cork, stage);
    let should_close = !ok_handle || server::response_wire_has_connection_close(cork.cork_as_slice());
    if !ok_handle {
        if cork.cork_pending() > 0 { net::tcp_flush_cork(conn, cork); }
        return false;
    }
    if cork.cork_pending() > 0 {
        let sent = net::tcp_flush_cork(conn, cork);
        return sent > 0 && !should_close;
    }
    return !should_close;
}

// Executes a live TCP accept and dispatch loop using hardware page-mirrored ring buffer (PageRingBuffer) and `<Stage>`.
fn serve_page_ring_loop<Stage>(
    server:          server::HttpServer&,
    listener_fd:     i64,
    max_connections: i64,
    ring:            core::PageRingBuffer&,
    stage:           Stage&,
) -> i64 {
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;
    server::init_run_state(server);

    while !server::should_stop(server) && (max_connections == 0 || total_served < max_connections) {
        let conn = net::tcp_accept(listener_fd, 200);
        if conn <= 0 {
            continue;
        }
        let _ = net::tcp_set_nodelay(conn, server.tcp_nodelay);
        defer net::tcp_close(conn);

        ring.page_ring_clear();
        cork.cork_reset();
        net::tcp_get_peer_ip(conn, peer_ip);

        while !server::should_stop(server) {
            if !step_page_ring_conn(server, conn, peer_ip[..], ring, cork, stage) {
                break;
            }
        }
        total_served = core::add_sat_i64(total_served, 1);
    }
    server.is_running = false;

    return total_served;
}

// Executes a live TCP accept and dispatch loop using hardware page-mirrored ring buffer (PageRingBuffer).
fn serve_page_ring_loop(
    server:          server::HttpServer&,
    listener_fd:     i64,
    max_connections: i64,
    ring:            core::PageRingBuffer&,
) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_page_ring_loop(server, listener_fd, max_connections, ring, noop);
}

fn step_pipe_loop_conn<Stage>(
    server:  server::HttpServer&,
    conn:    i64,
    peer_ip: const u8[:],
    pipe:    core::PipeBuffer&,
    cork:    core::CorkBuffer&,
    h2_idx:  i64,
    stage:   Stage&,
) -> bool {
    guard !server::should_stop(server) else { return false; }
    let recv_ms = resolve_server_recv_timeout_ms(server, pipe.readable_len() > 0);
    let recvd = net::tcp_recv_pipe(conn, pipe, 4096, recv_ms);
    guard recvd > 0 else { return false; }
    let now_ns = core::monotonic_now().as_nanos();
    let _, ok = server::handle_connection_pipe(
        server, peer_ip, pipe, now_ns, cork, server::g_default_reactor.h2_sessions[h2_idx], stage,
    );
    let should_close = !ok || server::response_wire_has_connection_close(cork.cork_as_slice());
    if !ok {
        if cork.cork_pending() > 0 { net::tcp_flush_cork(conn, cork); }
        return false;
    }
    if cork.cork_pending() > 0 {
        let sent = net::tcp_flush_cork(conn, cork);
        return sent > 0 && !should_close;
    }
    return !should_close;
}

// Executes a live TCP accept and dispatch loop using standard PipeBuffer and `<Stage>`.
fn serve_pipe_loop<Stage>(
    server:          server::HttpServer&,
    listener_fd:     i64,
    max_connections: i64,
    stage:           Stage&,
) -> i64 {
    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;
    server::init_run_state(server);

    while !server::should_stop(server) && (max_connections == 0 || total_served < max_connections) {
        let conn = net::tcp_accept(listener_fd, 200);
        if conn <= 0 {
            continue;
        }
        let _ = net::tcp_set_nodelay(conn, server.tcp_nodelay);
        defer net::tcp_close(conn);

        pipe.pipe_reset();
        cork.cork_reset();
        net::tcp_get_peer_ip(conn, peer_ip);
        let h2_idx = server::alloc_temp_h2_session(
            server.pipeline, server.server_name[..], 0, server.max_h2_concurrent_streams,
        );
        if h2_idx < 0 || h2_idx >= server::REACTOR_MAX_H2_SESSIONS {
            total_served = core::add_sat_i64(total_served, 1);
            continue;
        }
        defer server::free_reactor_h2_session(h2_idx as i16, server.pipeline);

        while step_pipe_loop_conn(server, conn, peer_ip[..], pipe, cork, h2_idx, stage) {}
        total_served = core::add_sat_i64(total_served, 1);
    }
    server.is_running = false;

    return total_served;
}

// Executes a live TCP accept and dispatch loop using standard PipeBuffer.
fn serve_pipe_loop(server: server::HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_pipe_loop(server, listener_fd, max_connections, noop);
}

inline fn verify_tls_slot_sni(server: const server::HttpServer&, slot_idx: i32) -> bool {
    guard server.sni_registry.count > 0 else { return true; }
    let sni_host = tls::g_tls_cipher_slots[slot_idx as i64].server_name[..];
    let _, ok_sni = server::resolve_sni_credentials(server, sni_host);
    return ok_sni;
}

fn step_tls_loop_conn(
    server:   server::HttpServer&,
    conn:     i64,
    slot_idx: u16,
    peer_ip:  const u8[:],
    pipe:     core::PipeBuffer&,
    cork:     core::CorkBuffer&,
    h2_idx:   i64,
) -> bool {
    let recv_ms = resolve_server_recv_timeout_ms(server, pipe.readable_len() > 0);
    let recvd = server::tls_recv_pipe(conn, slot_idx, pipe, 4096, recv_ms);
    guard recvd > 0 else { return false; }

    let now_ns = core::monotonic_now().as_nanos();
    let _, ok = server::handle_connection_pipe(
        server, peer_ip, pipe, now_ns, cork, server::g_default_reactor.h2_sessions[h2_idx],
    );
    let should_close = !ok || server::response_wire_has_connection_close(cork.cork_as_slice());
    if !ok {
        if cork.cork_pending() > 0 { server::tls_flush_cork(conn, slot_idx, cork); }
        return false;
    }
    if cork.cork_pending() > 0 {
        let sent = server::tls_flush_cork(conn, slot_idx, cork);
        return sent > 0 && !should_close;
    }
    return !should_close;
}

// Incremental Sans-IO pipeline handler using hardware page-mirrored ring buffer (PageRingBuffer) and `<Stage>`.
// Eliminates buffer wraparound splitting and memmove compaction during streaming request processing.
fn handle_page_ring_h2_preface<Stage, B>(
    server:     server::HttpServer&,
    client_ip:  const u8[:],
    ring:       core::PageRingBuffer&,
    peek_slice: const u8[:],
    now_ns:     u64,
    wire_out:   B&,
    out_done:   bool&,
    out_ok:     bool&,
    stage:      Stage&,
) -> i64 {
    if server::is_partial_h2_client_preface(peek_slice) {
        out_done = true;
        out_ok = true;
        return 0;
    }
    guard server::is_h2_client_preface(peek_slice) else {
        out_done = false;
        out_ok = true;
        return 0;
    }
    let h2_idx = server::alloc_temp_h2_session(
        server.pipeline, server.server_name[..], now_ns, server.max_h2_concurrent_streams,
    );
    guard h2_idx >= 0 && h2_idx < server::REACTOR_MAX_H2_SESSIONS else {
        out_done = true;
        out_ok = false;
        ring.page_ring_clear();
        return 0;
    }
    defer server::free_reactor_h2_session(h2_idx as i16, server.pipeline);
    let pref_len = prepare_h2_server_preface(
        server::g_default_reactor.h2_sessions[h2_idx], server, peek_slice, wire_out,
    );
    let consumed_body, ok_h2 = server_internal::handle_h2_server_ingress(
        server::g_default_reactor.h2_sessions[h2_idx],
        server.pipeline,
        server.timer,
        client_ip,
        peek_slice[pref_len..],
        div_euclid(now_ns, 1000000),
        wire_out,
        stage,
    );
    let consumed_h2 = core::add_sat_i64(pref_len, consumed_body);
    out_done = true;
    out_ok = ok_h2;
    if ok_h2 {
        ring.page_ring_discard(consumed_h2);
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        return 1;
    }
    ring.page_ring_clear();
    return 0;
}

inline fn verify_mmap_transfer_complete(
    offset:    u64,
    file_size: u64,
    prev_len:  i64,
    hdr_len:   i64,
    cur_len:   i64,
) -> bool {
    return offset == file_size && cur_len == prev_len + hdr_len + (file_size as i64);
}
