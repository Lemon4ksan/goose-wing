// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal WebSocket upgrade, TLS backend/loop, HTTP/2 session loop, and page-ring/pipe accept loops.
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
import .server_fast_l0_internal;

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

fn populate_server_tls_backend_config(
    srv:       const server::HttpServer&,
    alpn_wire: const u8[:],
    bcfg:      tls::TlsBackendConfig&,
) -> bool, tls::TlsBackendStatus {
    guard bcfg.cert_pem_file.try_set(srv.tls_cert_pem_file[..]) &&
        bcfg.key_pem_file.try_set(srv.tls_key_pem_file[..]) else {
        return false, tls::TlsBackendStatus.Error;
    }
    bcfg.require_client_cert = srv.tls_require_client_cert;
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

inline fn is_valid_alpn_wire(alpn_wire: const u8[:]) -> bool {
    var pos: i64 = 0;
    while pos < alpn_wire.len {
        let plen = alpn_wire[pos] as i64;
        let next_pos = core::add_sat_i64(core::add_sat_i64(pos, 1), plen);
        guard plen > 0 && next_pos <= alpn_wire.len else { return false; }
        pos = next_pos;
    }
    return true;
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
        guard step_h2_server_session_buf(conn_fd, server, h2_idx, peer_ip[..], h2_in, now_ns, out_wire) else {
            chunk.clear();
            let _ = net::tcp_recv(conn_fd, chunk, 4096, 10);
            return false;
        }
        chunk.clear();
        let recvd = net::tcp_recv(conn_fd, chunk, 4096, recv_timeout_ms);
        if recvd == -2 {
            idle_ticks = core::add_sat_u64(idle_ticks, 1);
            guard idle_ticks < 2 else { break; }
            continue;
        }
        guard server::try_append_recv_chunk(recvd, chunk, h2_in) else { break; }
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
    negotiate_ws_route_compression(req, ws_res, ws, behavior.compression);
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

// Negotiates RFC 7692 permessage-deflate parameters from the upgrade request and configures `ws`.
fn negotiate_ws_route_compression(
    req:         const http::Request&,
    ws_res:      http::Response&,
    ws:          realtime::WebSocketSession&,
    compression: u16,
) {
    let ua_upg = req.header("user-agent");
    guard compression != realtime::WS_COMPRESS_DISABLED && !realtime::ws_has_broken_compression(ua_upg) else {
        return;
    }
    let client_ext = req.header("sec-websocket-extensions");
    guard client_ext.len > 0 else { return; }

    let dedicated = compression == realtime::WS_COMPRESS_DEDICATED;
    let srv_cfg = realtime::PerMessageDeflateConfig {
        server_max_window_bits:     rfc::WS_PMD_MAX_WINDOW_BITS,
        client_max_window_bits:     rfc::WS_PMD_MAX_WINDOW_BITS,
        server_no_context_takeover: !dedicated,
        client_no_context_takeover: !dedicated,
    };
    let neg, ok_neg = realtime::negotiate_permessage_deflate(client_ext, srv_cfg);
    guard ok_neg else { return; }

    var ext_val: u8[..192] = [];
    realtime::append_permessage_deflate_response(neg, ext_val);
    ws_res.set_header("Sec-WebSocket-Extensions", ext_val[..]);
    let opts = realtime::WsContextTakeoverOptions {
        server_no_context: neg.server_no_context_takeover,
        client_no_context: neg.client_no_context_takeover,
    };
    ws.enable_permessage_deflate(compression, opts);
    ws.server_max_window_bits = neg.server_max_window_bits;
    ws.client_max_window_bits = neg.client_max_window_bits;
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
    return offset == file_size && cur_len == core::add_sat_i64(core::add_sat_i64(prev_len, hdr_len), file_size as i64);
}
