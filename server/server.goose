// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone zero-allocation HTTP server engine, wire protocol serializer, and connection coordinator.
// Conforms to RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1 Framing), and RFC 9113 (HTTP/2 Preface Detection).
namespace wing;

import std;
import core from "..";
import .router;
import .pool;
import .pipeline;
import .profiler;
import .h2_multiplexer;
import .soa_timer;
import realtime.topic_tree;
import http.compression_dict;

import .h1_codec;
import .cork;
import .stream_consumer;
import .sni;
import net.accel;

// ---- 1. HttpServer Container and Route Registration -------------------------

struct WsRouteEntry {
    path:     u8[..128]  = [],
    behavior: WsBehavior = WsBehavior { .. },
    in_use:   bool       = false,
}

struct HttpServer {
    pipeline:                  ServerPipelineConfig             = ServerPipelineConfig { .. },
    host:                      u8[..256]                        = "127.0.0.1",
    port:                      u16                              = 8080,
    server_name:               u8[..64]                         = "goose-wing/1.0",
    timer:                     server_internal::ConnectionTimer = server_internal::ConnectionTimer { .. },
    is_running:                bool                             = false,
    requests_processed:        u64                              = 0,
    accept_proxy_protocol:     bool                             = false,
    trust_proxy_headers:       bool                             = false,
    topic_tree:                TopicTree                        = TopicTree { .. },
    ws_routes:                 WsRouteEntry[..16]               = [WsRouteEntry { .. }; 16],
    ws_route_count:            i32                              = 0,
    shared_compressor:         SharedWsCompressor               = SharedWsCompressor { .. },
    sni_registry:              SniRegistry                      = SniRegistry { .. },
    worker_ring:               core::SpscRing                   = core::SpscRing { .. },
    cached_date:               CachedHttpDate                   = CachedHttpDate { .. },
    fast_l0_last_headers:      u8[..256]                        = [],
    fast_l0_last_host:         u8[..128]                        = [],
    fast_l0_last_close:        bool                             = false,
    enable_header_memoization: bool                             = false,
    turn_in_use:               bool                             = false,
    handle_os_signals:         bool                             = false,
    honor_shutdown_flag:       bool                             = true,
    shutdown_grace_ns:         u64                              = 2000000000,
    accel_mode:                ReactorAccelMode                 = ReactorAccelMode.Auto,
    enable_ktls_offload:       bool                             = true,
}

// Enables or disables Keep-Alive HTTP/1.1 header block memoization (`g_h1_parse_cache`,
// `try_match_cached_l0_headers`, and `drain_identical_l0_pipelined_batch`).
// Disabled by default (`false`) so every request executes full SWAR header scanning.
fn set_header_memoization(server: HttpServer&, enabled: bool) {
    server.enable_header_memoization = enabled;
    g_h1_parse_cache.enabled = enabled;
    if !enabled {
        g_h1_parse_cache.rest_headers.clear();
        g_h1_parse_cache.has_valid_host = false;
        server.fast_l0_last_headers.clear();
        server.fast_l0_last_host.clear();
        server.pipeline.has_valid_host = false;
    }
}

inline fn refresh_http_server_date(server: HttpServer&, now_sec: i64) {
    update_server_cached_date(server.cached_date, now_sec, server.server_name[..]);
}

fn new_http_server(
    host_str: const u8[:] = "127.0.0.1",
    port_num: u16         = 8080,
) -> HttpServer {
    var server = HttpServer {
        pipeline:           new_default_server_pipeline_config(host_str),
        port:               port_num,
        timer:              server_internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running:         true,
        requests_processed: 0,
        ..
    };
    let _ = server.host.try_set(host_str[..min(host_str.len, 256)]);
    return server;
}

fn new_http_server_with_quota<Q>(
    host_str: const u8[:],
    port_num: u16,
    quota:    Q,
) -> HttpServer {
    var server = HttpServer {
        pipeline:           new_server_pipeline_config(host_str, quota),
        port:               port_num,
        timer:              server_internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running:         true,
        requests_processed: 0,
        ..
    };
    let _ = server.host.try_set(host_str[..min(host_str.len, 256)]);
    return server;
}

// Registers routing handlers on the server instance
fn add_get_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "GET", path, handler_id);
}

// Registers a pre-rendered static GET route for zero-copy line-rate delivery
fn add_static_get_route(
    server:       HttpServer&,
    path:         const u8[:],
    content_type: const u8[:],
    body:         const u8[:],
    handler_id:   i32 = 0,
) {
    let _ = add_static_route(server.pipeline.router, "GET", path, content_type, body, handler_id);
}

fn add_post_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "POST", path, handler_id);
}

fn add_put_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "PUT", path, handler_id);
}

fn add_delete_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "DELETE", path, handler_id);
}

// Registers a declarative WebSocket route on the server instance (uWebSockets app.ws pattern)
fn add_ws_route(server: HttpServer&, path: const u8[:], behavior: const WsBehavior& = WsBehavior { .. }) -> bool {
    guard path.len > 0 && path.len <= 128 else { return false; }
    var canon_path: u8[..128] = [];
    guard canonicalize_route_path(path, canon_path) else { return false; }
    for i in server.ws_routes.len {
        if server.ws_routes[i].in_use && server.ws_routes[i].path[..] == canon_path[..] {
            server.ws_routes[i].behavior = behavior;
            add_get_route(server, canon_path[..], behavior.handler_id);
            return true;
        }
    }
    guard server.ws_route_count < server.ws_routes.len as i32 else { return false; }
    for i in server.ws_routes.len {
        if !server.ws_routes[i].in_use {
            let _ = server.ws_routes[i].path.try_set(canon_path[..]);
            server.ws_routes[i].behavior = behavior;
            server.ws_routes[i].in_use = true;
            server.ws_route_count += 1;
            add_get_route(server, canon_path[..], behavior.handler_id);
            return true;
        }
    }
    return false;
}

fn find_ws_route(server: const HttpServer&, path: const u8[:]) -> i32 {
    var canon_path: u8[..256] = [];
    guard canonicalize_route_path(path, canon_path) else { return -1; }
    for i in server.ws_routes.len {
        if server.ws_routes[i].in_use && server.ws_routes[i].path[..] == canon_path[..] {
            return i as i32;
        }
    }
    return -1;
}

// ---- 2. Server Pub/Sub Broadcast Engine (uWebSockets TopicTree) -------------

fn publish(server: HttpServer&, topic: const u8[:], message: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64 {
    return publish(server.topic_tree, topic, message, opcode);
}

fn publish_text(server: HttpServer&, topic: const u8[:], text: const u8[:]) -> i64 {
    return publish_text(server.topic_tree, topic, text);
}

fn publish_binary(server: HttpServer&, topic: const u8[:], data: const u8[:]) -> i64 {
    return publish_binary(server.topic_tree, topic, data);
}

fn subscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
    return subscribe(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
    return unsubscribe(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_all(server: HttpServer&, sock_fd: i64) -> i32 {
    return unsubscribe_all(server.topic_tree, sock_fd);
}

fn find_subscribers(server: const HttpServer&, topic: const u8[:], out_fds: i64[..512]&) -> i64 {
    return find_subscribers(server.topic_tree, topic, out_fds);
}

fn subscribe_ex(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
    out_old:       i32&,
    out_new:       i32&,
) -> bool {
    return subscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn unsubscribe_ex(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
    out_old:       i32&,
    out_new:       i32&,
) -> bool {
    return unsubscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
) -> bool {
    return subscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
) -> bool {
    return unsubscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_all_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(server: HttpServer&, sock_fd: i64) -> i32 {
    return unsubscribe_all_with_hook<HookFn>(server.topic_tree, sock_fd);
}

fn get_socket_topic_count(server: const HttpServer&, sock_fd: i64) -> i32 {
    return socket_subscription_count(server.topic_tree, sock_fd);
}

fn get_socket_topics(server: const HttpServer&, sock_fd: i64, out_topics: u8[..64][..32]&) -> i32 {
    return get_socket_topics(server.topic_tree, sock_fd, out_topics);
}

fn iterate_socket_topics<IterFn: fn(const u8[:])>(server: const HttpServer&, sock_fd: i64) -> i32 {
    return iterate_socket_topics<IterFn>(server.topic_tree, sock_fd);
}

// ---- 3. WebSocket Upgrade Handshake & Framing -------------------------------

// Asynchronous WebSocket Upgrade helpers (uWebSockets res->onAborted & res->upgrade pattern)
fn defer_ws_upgrade(
    server:  const HttpServer&,
    req:     const Request&,
    sock_fd: i64,
) -> WsPendingUpgrade, bool {
    guard is_websocket_upgrade_request(req) else {
        return WsPendingUpgrade { .. }, false;
    }
    let r_idx = find_ws_route(server, req.url[..]);
    guard r_idx >= 0 else {
        return WsPendingUpgrade { .. }, false;
    }
    let client_key = req.headers.find_header("Sec-WebSocket-Key");
    guard is_valid_websocket_key(client_key) else {
        return WsPendingUpgrade { .. }, false;
    }
    let subprotocol = req.headers.find_header("Sec-WebSocket-Protocol");
    let extensions = req.headers.find_header("Sec-WebSocket-Extensions");
    guard subprotocol.len <= 64 && extensions.len <= 256 else {
        return WsPendingUpgrade { .. }, false;
    }

    var pending = new_ws_pending_upgrade(sock_fd, client_key, r_idx, subprotocol, extensions);
    return pending, true;
}

const WS_UPGRADE_PREFIX:         const u8[:] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
const WS_SUBPROTO_PREFIX:        const u8[:] = "Sec-WebSocket-Protocol: ";
const WS_PERMESSAGE_DEFLATE_HDR: const u8[:] = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n";
const WS_HDR_CRLF:               const u8[:] = "\r\n";

inline fn serialize_and_init_ws_upgrade<B>(
    route_behavior: const WsBehavior&,
    pending:        WsPendingUpgrade&,
    subproto:       const u8[:],
    out_wire:       B&,
) -> WebSocketSession, bool {
    var session = new_websocket_session(false);
    guard subproto.len <= session.subprotocol.cap && pending.user_data.len <= session.user_data.cap else {
        return WebSocketSession { .. }, false;
    }

    var accept_key: u8[..64] = [];
    compute_websocket_accept(pending.client_key[..], accept_key);

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

    let compress_active = route_behavior.compression != WS_COMPRESS_DISABLED
        && pending.extensions[..].contains_fold("permessage-deflate");
    if compress_active {
        out_wire.append(WS_PERMESSAGE_DEFLATE_HDR);
        expected_add = core::add_sat_i64(expected_add, WS_PERMESSAGE_DEFLATE_HDR.len);
    }

    out_wire.append(WS_HDR_CRLF);
    expected_add = core::add_sat_i64(expected_add, WS_HDR_CRLF.len);
    guard out_wire.len == core::add_sat_i64(prev_out_len, expected_add) else {
        return WebSocketSession { .. }, false;
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

fn complete_ws_upgrade<B>(
    server:   HttpServer&,
    pending:  WsPendingUpgrade&,
    out_wire: B&,
) -> WebSocketSession, bool {
    guard pending.in_use && !pending.is_aborted else {
        return WebSocketSession { .. }, false;
    }

    let route_behavior = if pending.route_idx >= 0 && pending.route_idx < server.ws_routes.len as i32 {
        server.ws_routes[pending.route_idx as i64].behavior
    } else {
        WsBehavior { .. }
    };

    let has_subproto = route_behavior.subprotocol.len > 0
        && pending.subprotocol.len > 0
        && has_subprotocol_token(pending.subprotocol[..], route_behavior.subprotocol[..]);
    let subproto = if has_subproto {
        route_behavior.subprotocol[..]
    } else {
        ""
    };

    return serialize_and_init_ws_upgrade(route_behavior, pending, subproto, out_wire);
}

fn complete_ws_upgrade<Req, B>(
    server:   HttpServer&,
    req:      const Req&,
    entry:    const WebSocketRoute&,
    wire_out: B&,
) -> bool {
    let subproto = entry.behavior.subprotocol[..];
    var ws_res = Response { .. };
    var sess, ok_upg = ws_upgrade_request(req, ws_res, subproto);
    guard ok_upg else { return false; }

    sess.max_payload_length = entry.behavior.max_payload_length;
    sess.max_backpressure = entry.behavior.max_backpressure;
    sess.close_on_backpressure_limit = entry.behavior.close_on_backpressure_limit;
    sess.idle_timeout_s = entry.behavior.idle_timeout_s;
    sess.max_lifetime_s = entry.behavior.max_lifetime_s;
    sess.send_pings_automatically = entry.behavior.send_pings_automatically;
    sess.reset_idle_timeout_on_send = entry.behavior.reset_idle_timeout_on_send;

    let ua_upg = req.header("user-agent");
    let allow_comp = entry.behavior.compression != WS_COMPRESS_DISABLED
        && !ws_has_broken_compression(ua_upg);
    if allow_comp {
        let client_ext = req.header("sec-websocket-extensions");
        if client_ext.contains_fold("permessage-deflate") {
            ws_res.set_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover");
            enable_permessage_deflate(sess, entry.behavior.compression);
        }
    }
    serialize_http1_response(ws_res, server.server_name[..], wire_out);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    return true;
}

// ---- 4. Single-Turn & Pipelined HTTP/1.1 Wire Execution ---------------------

inline fn strip_required_proxy_preface<B>(
    server:       const HttpServer&,
    wire_in:      const u8[:],
    effective_ip: u8[..64]&,
    wire_out:     B&,
) -> const u8[:], bool {
    var proxy_hdr = ProxyHeader { .. };
    guard detect_proxy_protocol(wire_in) != ProxyProtocolVersion.None else {
        // uWS #1927 / HAProxy spec: When PROXY protocol is required, connections
        // without a valid PROXY preface MUST NOT fall through to plain HTTP.
        serialize_bad_request_error(server.server_name[..], wire_out);
        return wire_in, false;
    }
    let stripped, has_proxy = detect_and_strip_proxy_header(wire_in, proxy_hdr);
    guard has_proxy else {
        serialize_bad_request_error(server.server_name[..], wire_out);
        return wire_in, false;
    }
    if proxy_hdr.src_ip_str.len > 0 {
        let _ = effective_ip.try_set(proxy_hdr.src_ip_str[..]);
    }
    return stripped, true;
}

fn headers_have_conn_token(headers: const HeaderMap&, token: const u8[:]) -> bool {
    for &entry in headers.entries {
        if entry_name(headers, entry).eq_ascii_fold("connection") {
            if header_has_token(entry_value(headers, entry), token) {
                return true;
            }
        }
    }
    return false;
}

// Checks whether request or response demands connection closure (RFC 9112 §9.3 & NGINX proxy_pass harmony).
// Applies "Connection: close" to response headers if close is requested or for HTTP/1.0 without keep-alive.
fn check_and_apply_connection_close(req: const Request&, res: Response&) -> bool {
    guard res.status_code != 101 else { return false; }
    let has_conn_hdr = has_header(req, "connection") ||
        has_header(res, "connection") ||
        (res.presence_mask & RES_PRESENCE_CONNECTION) != 0;
    if !has_conn_hdr && !req.is_http10 && req.method[0] != 'C' {
        return false;
    }
    let wants_close = req.method[..] == "CONNECT" ||
        headers_have_conn_token(req.headers, "close") ||
        (req.is_http10 && !headers_have_conn_token(req.headers, "keep-alive")) ||
        headers_have_conn_token(res.headers, "close");
    if wants_close {
        set_header(res, "Connection", "close");
        return true;
    }
    return false;
}

inline fn apply_shutdown_connection_close(server: HttpServer&, res: Response&) {
    guard server.honor_shutdown_flag && shutdown_requested() else { return; }
    server.is_running = false;
    if res.status_code != 101 {
        set_header(res, "Connection", "close");
    }
}

inline fn reset_server_response_fixed(res: Response&) {
    res.status_code = 200;
    res.presence_mask = 0;
    res.headers.clear();
    res.trailers.clear();
}

inline fn reset_server_request_fixed(req: Request&) {
    req.method.clear();
    req.url.clear();
    req.trailers.clear();
    req.query_params.clear();
    req.is_http10 = false;
}

var g_turn_req: Request  = Request { .. };
var g_turn_res: Response = Response { .. };

inline fn is_turn_scratch_ready(server: const HttpServer&) -> bool {
    return !server.turn_in_use && g_turn_req.body.len == 0 && g_turn_res.body.len == 0;
}

inline fn acquire_turn_scratch(server: HttpServer&) {
    server.turn_in_use = true;
    reset_server_response_fixed(g_turn_res);
}

inline fn release_turn_scratch(server: HttpServer&) {
    g_turn_req.body.clear();
    g_turn_res.body.clear();
    server.turn_in_use = false;
}

fn try_prepare_single_h1_wire_turn(
    server:     const HttpServer&,
    raw_stream: const u8[:],
) -> bool {
    guard is_turn_scratch_ready(server) else { return false; }

    reset_server_request_fixed(g_turn_req);
    var presence_tracker = HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard parse_http1_request_headers_fixed(raw_stream, g_turn_req, presence_tracker, body_start_idx) else {
        return false;
    }

    let has_te = (presence_tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;
    let cl_len = if has_cl { presence_tracker.parsed_cl } else { 0 };
    let total_consumed = core::add_sat_i64(body_start_idx, cl_len);
    guard !has_te && cl_len >= 0 && cl_len <= MAX_SERVER_BODY_LIMIT && raw_stream.len >= total_consumed else {
        return false;
    }
    if cl_len > 0 {
        let _pbf = prof_enter("http1.body_framing");
        g_turn_req.body.append(raw_stream[body_start_idx..total_consumed]);
        prof_leave(_pbf);
    }
    return true;
}

fn finish_single_h1_wire_turn<Stage, B>(
    server:       HttpServer&,
    effective_ip: const u8[:],
    now_ns:       u64,
    wire_out:     B&,
    stage:        Stage&,
) -> PipelineOutcome {
    acquire_turn_scratch(server);
    defer release_turn_scratch(server);
    if server.ws_route_count > 0
        && (g_turn_req.presence_mask & HDR_PRESENCE_UPGRADE) != 0
        && is_websocket_upgrade_request(g_turn_req) {
        let ws_idx = find_ws_route(server, g_turn_req.url[..]);
        if ws_idx >= 0 && complete_ws_upgrade(server, g_turn_req, server.ws_routes[ws_idx as i64], wire_out) {
            return PipelineOutcome.Handled;
        }
    }

    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }

    var future = server_internal::new_inline_handler_future(0);
    let out_outcome = if is_noop_server_stage(stage) {
        execute_pipeline(server.pipeline, server.timer, effective_ip, g_turn_req, now_ns, g_turn_res, future)
    } else {
        execute_server_pipeline_with_stage(
            server.pipeline, server.timer, effective_ip, g_turn_req, now_ns, g_turn_res, future, stage,
        )
    };

    check_and_apply_connection_close(g_turn_req, g_turn_res);
    apply_shutdown_connection_close(server, g_turn_res);
    serialize_http1_response(g_turn_res, server.server_name[..], wire_out);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);

    return out_outcome;
}

fn execute_single_h1_wire_turn<Stage, B>(
    server:       HttpServer&,
    effective_ip: const u8[:],
    raw_stream:   const u8[:],
    now_ns:       u64,
    req:          Request&,
    res:          Response&,
    wire_out:     B&,
    stage:        Stage&,
) -> PipelineOutcome, bool {
    reset_server_request_fast(req);
    let ok_parse, _ = parse_http1_wire_request(raw_stream, req);
    guard ok_parse else {
        serialize_bad_request_error(server.server_name[..], wire_out);
        return PipelineOutcome.Handled, false;
    }

    // WebSocket Upgrade Interception (uWebSockets app.ws pattern)
    if server.ws_route_count > 0
        && (req.presence_mask & HDR_PRESENCE_UPGRADE) != 0
        && is_websocket_upgrade_request(req) {
        let ws_idx = find_ws_route(server, req.url[..]);
        if ws_idx >= 0 && complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out) {
            return PipelineOutcome.Handled, true;
        }
    }

    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }

    reset_server_response_fast(res);
    var future = server_internal::new_inline_handler_future(0);
    let outcome = if is_noop_server_stage(stage) {
        execute_pipeline(server.pipeline, server.timer, effective_ip, req, now_ns, res, future)
    } else {
        execute_server_pipeline_with_stage(
            server.pipeline, server.timer, effective_ip, req, now_ns, res, future, stage,
        )
    };

    check_and_apply_connection_close(req, res);
    apply_shutdown_connection_close(server, res);

    serialize_http1_response(res, server.server_name[..], wire_out);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);

    return outcome, true;
}

// Processes an incoming raw connection payload, performing protocol detection (H1 vs H2 preface),
// executing the server pipeline with `<Stage>`, and serializing the wire response.
fn handle_connection_wire<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> PipelineOutcome, bool {
    g_h1_parse_cache.enabled = server.enable_header_memoization;
    wire_out.clear();

    var effective_ip: u8[..64] = [];
    let _ = effective_ip.try_set(client_ip[..min(client_ip.len, 64)]);
    var raw_stream = wire_in;

    if server.accept_proxy_protocol {
        let stripped, ok_proxy = strip_required_proxy_preface(server, wire_in, effective_ip, wire_out);
        guard ok_proxy else {
            return PipelineOutcome.Handled, false;
        }
        raw_stream = stripped;
    }

    if is_h2_client_preface(raw_stream) {
        if server.trust_proxy_headers {
            server.pipeline.trust_proxy_headers = true;
        }
        let now_ms = div_euclid(now_ns, 1000000);
        var sess = server_internal::new_h2_server_session(server.server_name[..], now_ms);
        defer server_internal::cleanup_h2_server_session(sess, server.pipeline);
        let _, ok_h2 = server_internal::handle_h2_server_ingress(
            sess, server.pipeline, server.timer, effective_ip[..], raw_stream, now_ms, wire_out, stage,
        );
        if ok_h2 {
            server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
            return PipelineOutcome.Handled, true;
        }
        return PipelineOutcome.Handled, false;
    }

    let is_fast = try_prepare_single_h1_wire_turn(server, raw_stream);
    if !is_fast {
        var req = new_request("GET", "");
        var res = Response { .. };
        return execute_single_h1_wire_turn(
            server, effective_ip[..], raw_stream, now_ns, req, res, wire_out, stage,
        );
    }
    let fast_outcome = finish_single_h1_wire_turn(
        server, effective_ip[..], now_ns, wire_out, stage,
    );
    return fast_outcome, true;
}

// Processes an incoming raw connection payload, performing protocol detection (H1 vs H2 preface),
// executing the server pipeline, and serializing the wire response.
fn handle_connection_wire<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
) -> PipelineOutcome, bool {
    var noop = wire::NoOpStage {};
    return handle_connection_wire(server, client_ip, wire_in, now_ns, wire_out, noop);
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
    if cl_val > MAX_SERVER_BODY_LIMIT {
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
fn scan_chunked_cumulative_size(chunk_slice: const u8[:]) -> u64, ChunkedDecodeError {
    var cur:      i64 = 0;
    var total_sz: u64 = 0;
    while cur < chunk_slice.len {
        var chunk_sz: u64 = 0;
        let sz_err = read_chunk_size_line(chunk_slice, cur, chunk_sz);
        guard sz_err == ChunkedDecodeError.None else { return total_sz, sz_err; }
        total_sz = core::add_sat_u64(total_sz, chunk_sz);
        if total_sz > (MAX_SERVER_BODY_LIMIT as u64) || chunk_sz == 0 {
            return total_sz, ChunkedDecodeError.None;
        }
        let data_end = core::add_sat_i64(cur, chunk_sz as i64);
        let next_cur = core::add_sat_i64(data_end, 2);
        guard next_cur <= chunk_slice.len else { return total_sz, ChunkedDecodeError.UnexpectedEof; }
        guard chunk_slice[data_end] == '\r' && chunk_slice[core::add_sat_i64(data_end, 1)] == '\n' else {
            return total_sz, ChunkedDecodeError.MalformedChunkEnding;
        }
        cur = next_cur;
    }
    return total_sz, ChunkedDecodeError.UnexpectedEof;
}

inline fn check_pipelined_chunked_head<B>(
    stream:      const u8[:],
    hdr_end:     i64,
    server_name: const u8[:],
    wire_out:    B&,
    out_keep:    bool&,
) -> bool {
    let chunk_slice = stream[core::add_sat_i64(hdr_end, 4)..];
    let total_sz, sz_err = scan_chunked_cumulative_size(chunk_slice);
    if total_sz > (MAX_SERVER_BODY_LIMIT as u64) {
        serialize_payload_too_large_error(server_name, wire_out);
        out_keep = false;
        return false;
    }
    if sz_err != ChunkedDecodeError.None &&
       sz_err != ChunkedDecodeError.UnexpectedEof &&
       sz_err != ChunkedDecodeError.EmptyInput {
        serialize_bad_request_error(server_name, wire_out);
        out_keep = false;
        return false;
    }
    out_keep = true;
    return true;
}

// Handles incomplete pipelined HTTP stream or syntax errors.
fn handle_pipelined_parse_failure<B>(
    server_name:     const u8[:],
    stream:          const u8[:],
    req:             const Request&,
    wire_out:        B&,
    out_keep_stream: bool&,
) -> bool {
    let hdr_end = core::fast_find_crlfcrlf(stream);
    let is_valid_prefix = is_possible_http_method_prefix(stream);

    if hdr_end >= 0 && hdr_end + 4 <= 8192 && is_valid_prefix && req.headers.entries.len > 0 {
        let has_te = has_header(req, "transfer-encoding");
        let has_cl = has_header(req, "content-length");
        // If both TE and CL are present, reject immediately as smuggling attempt (RFC 9112 §6.1, §6.3)
        if has_te && has_cl {
            serialize_bad_request_error(server_name, wire_out);
            out_keep_stream = false;
            return false;
        }

        // Headers are complete; check if Content-Length body is still incomplete
        let cl_str = req.header("content-length");
        var cl_handled_keep = false;
        if has_cl && check_pipelined_content_length(stream, hdr_end, cl_str, server_name, wire_out, cl_handled_keep) {
            out_keep_stream = cl_handled_keep;
            return cl_handled_keep;
        }
        let te_str = req.header("transfer-encoding");
        if has_te && validate_decodeable_chunked_te(te_str) {
            return check_pipelined_chunked_head(stream, hdr_end, server_name, wire_out, out_keep_stream);
        }
    }

    if hdr_end >= 0 || stream.len > 8192 || !is_valid_prefix {
        // Complete headers but invalid syntax, or header overflow > 8192,
        // or trailing unparseable poison bytes: 400 Bad Request
        serialize_bad_request_error(server_name, wire_out);
        out_keep_stream = false;
        return false;
    }
    // Legitimate incomplete request across packet boundary: return so caller preserves stream in leftover
    out_keep_stream = true;
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
    server:   HttpServer&,
    req:      const Request&,
    wire_out: B&,
) -> bool {
    guard server.ws_route_count > 0 && (req.presence_mask & HDR_PRESENCE_UPGRADE) != 0 else { return false; }
    guard is_websocket_upgrade_request(req) else { return false; }
    let ws_idx = find_ws_route(server, req.url[..]);
    guard ws_idx >= 0 else { return false; }
    return complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out);
}

inline fn reset_server_response_fast(res: Response&) {
    res.status_code = 200;
    res.presence_mask = 0;
    res.headers.clear();
    res.trailers.clear();
    res.body.clear();
}

inline fn reset_server_request_fast(req: Request&) {
    req.method.clear();
    req.url.clear();
    req.trailers.clear();
    req.query_params.clear();
    req.body.clear();
    req.is_http10 = false;
}

// Extended server request context holding long header token arena (RFC 9112 Section 2.1).
struct ServerRequest {
    raw_header_arena: u8[..8192] = [],
    req:              Request    = Request { .. },
}

inline fn reset_server_request(sreq: ServerRequest&) {
    reset_server_request_fast(sreq.req);
    sreq.raw_header_arena.clear();
}

fn dispatch_pipelined_request<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    req:       Request&,
    res:       Response&,
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> bool {
    reset_server_response_fast(res);
    var future = server_internal::new_inline_handler_future(0);
    let _ = execute_server_pipeline_with_stage(
        server.pipeline, server.timer, client_ip, req, now_ns, res, future, stage,
    );

    let wants_close = check_and_apply_connection_close(req, res);
    serialize_http1_response(res, server.server_name[..], wire_out);
    server.requests_processed++;
    return wants_close;
}

fn process_pipelined_pipe_step<Stage, B>(
    server:        HttpServer&,
    client_ip:     const u8[:],
    pipe:          core::PipeBuffer&,
    req:           Request&,
    res:           Response&,
    now_ns:        u64,
    total_handled: i64&,
    wire_out:      B&,
    stage:         Stage&,
) -> PipeStepResult {
    let stream = pipe.readable_slice();
    reset_server_request_fast(req);
    let ok_parse, consumed = parse_http1_wire_request(stream, req);

    if !ok_parse || consumed <= 0 {
        var keep = false;
        let _ = handle_pipelined_parse_failure(server.server_name[..], stream, req, wire_out, keep);
        if keep {
            pipe.advance_to(0, pipe.readable_len());
            return PipeStepResult.Stop;
        }
        pipe.advance_to(0, pipe.readable_len());
        return PipeStepResult.Error;
    }

    if try_handle_pipelined_websocket(server, req, wire_out) {
        total_handled++;
        pipe.advance_to(consumed, consumed);
        pipe.advance_to(pipe.readable_len(), pipe.readable_len());
        return PipeStepResult.Stop;
    }

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, wire_out, stage);
    total_handled++;
    pipe.advance_to(consumed, consumed);

    if req.method[..] == "CONNECT" || wants_close {
        pipe.advance_to(pipe.readable_len(), pipe.readable_len());
        return PipeStepResult.Stop;
    }
    return PipeStepResult.Continue;
}

// ---- 5. Fast L0 Static Route Scanner & Batch Drainer ------------------------

inline fn is_noop_server_stage(stage: const wire::NoOpStage&) -> bool {
    return true;
}

inline fn is_noop_server_stage<Stage>(stage: const Stage&) -> bool {
    return false;
}

inline fn can_try_fast_l0_static<Stage>(server: const HttpServer&, stage: const Stage&) -> bool {
    guard is_noop_server_stage(stage) else { return false; }
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
    pipeline: ServerPipelineConfig&,
    host_val: const u8[:],
    memoize:  bool = false,
) -> bool {
    guard host_val.len > 0 else { return false; }
    if memoize && pipeline.has_valid_host && host_val == pipeline.last_valid_host[..] {
        return true;
    }
    guard validate_host_header_chars(host_val) && validate_host_header_structure(host_val) else {
        return false;
    }
    if memoize && pipeline.last_valid_host.try_set(host_val) {
        pipeline.has_valid_host = true;
    }
    return true;
}

// Evaluates a known header inside a fast L0 static GET header block.
inline fn eval_fast_l0_known_header(
    server:    HttpServer&,
    known_id:  KnownHeaderId,
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
    server:    HttpServer&,
    rest:      const u8[:],
    cursor:    i64&,
    has_host:  bool&,
    out_close: bool&,
) -> bool {
    let cur_slice = rest[cursor..];
    let name_len, ok_name = scan_header_field_name_swar(cur_slice);
    guard ok_name && name_len > 0 && name_len <= 256 else { return false; }
    let hname = cur_slice[..name_len];

    let val_start = core::add_sat_i64(name_len, 1);
    let val_slice = cur_slice[val_start..];
    let val_len, crlf_len, ok_val = scan_header_field_value_swar(val_slice);
    guard ok_val && crlf_len == 2 && val_len <= 4096 else { return false; }
    let lead_ws, end_ws = trim_header_value_bounds(val_slice[..val_len]);
    let hval = val_slice[lead_ws..end_ws];

    let known_id = identify_known_header(hname);
    guard eval_fast_l0_known_header(server, known_id, hval, has_host, out_close) else {
        return false;
    }

    advance_header_cursor(cursor, name_len, val_len, crlf_len);
    return true;
}

inline fn try_match_cached_l0_headers(
    server:    HttpServer&,
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
    server:    HttpServer&,
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
    server:    HttpServer&,
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
    server:      HttpServer&,
    sp:          const StaticRoutePayload&,
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
fn match_fast_l0_static_payload(server: const HttpServer&, path: const u8[:]) -> i32 {
    let l0_slot = match_l0(path, 0, server.pipeline.router.l0_table);
    guard l0_slot >= 0 else { return -1; }
    let slot_idx = l0_slot as i64;
    let slot_pso = server.pipeline.router.l0_table.pso_mask[slot_idx] & server.pipeline.server_pso_capabilities;
    let heavy_pso = STAGE_EGRESS_ALL | STAGE_INGRESS_AUTH_JWT | STAGE_INGRESS_ROUTE_RATELIMIT;
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
    server:       HttpServer&,
    stream:       const u8[:],
    hdr_end:      i64,
    now_sec:      i64,
    wire_out:     B&,
    out_consumed: i64&,
    out_close:    bool&,
    out_sp_idx:   i32&,
) -> bool {
    let header_end_idx = core::add_sat_i64(hdr_end, 4);
    guard hdr_end >= 14 && header_end_idx <= 8192 else { return false; }
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
    server:         HttpServer&,
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

// Converts monotonic nanoseconds to seconds for HTTP Date header caching.
inline fn nanos_to_http_date_sec(now_ns: u64) -> i64 {
    return div_euclid(now_ns, 1000000000) as i64;
}

// Runs the zero-allocation L0 static GET fast loop over `stream_in`, returning `(rem_stream, done)`.
//
// Example:
//   stream_in = "GET /plaintext HTTP/1.1\r\nHost: localhost\r\n\r\n"
//   returns: "", done = true, total_handled = 1
fn drain_fast_l0_static_stream<B>(
    server:           HttpServer&,
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
        let _pf = prof_enter("http1.framing");
        let hdr_end = core::fast_find_crlfcrlf(stream);
        prof_leave(_pf);
        if hdr_end < 0 {
            if stream.len <= 8192 && is_possible_http_method_prefix(stream) {
                return stream, true;
            }
            return stream, false;
        }
        var fast_step:  i64  = 0;
        var fast_close: bool = false;
        var sp_idx:     i32  = -1;
        let _pl0 = prof_enter("http1.l0_turn");
        let ok_l0 = try_fast_l0_static_turn(server, stream, hdr_end, now_sec, wire_out, fast_step, fast_close, sp_idx);
        prof_leave(_pl0);
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

fn process_pipelined_stream_turn<Stage, B>(
    server:           HttpServer&,
    client_ip:        const u8[:],
    stream:           const u8[:],
    now_ns:           u64,
    req:              Request&,
    res:              Response&,
    wire_out:         B&,
    wire_in_len:      i64,
    step_consumed:    i64&,
    total_handled:    i64&,
    total_consumed:   i64&,
    conn_wants_close: bool&,
    stage:            Stage&,
) -> StreamTurnResult {
    guard wire_out.len + 256 <= wire_out.cap else { return StreamTurnResult.Stop; }

    reset_server_request_fast(req);
    let ok_parse, consumed = parse_http1_wire_request(stream, req);
    guard ok_parse && consumed > 0 else {
        var keep = false;
        let _ = handle_pipelined_parse_failure(server.server_name[..], stream, req, wire_out, keep);
        return if keep { StreamTurnResult.KeepStreamFail } else { StreamTurnResult.ParseFail };
    }

    if try_handle_pipelined_websocket(server, req, wire_out) {
        total_handled++;
        total_consumed += consumed;
        step_consumed = consumed;
        return StreamTurnResult.Stop;
    }

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, wire_out, stage);
    total_handled++;
    total_consumed += consumed;
    step_consumed = consumed;

    if wants_close || req.method[..] == "CONNECT" {
        conn_wants_close = true;
        if req.method[..] == "CONNECT" { total_consumed = wire_in_len; }
        return StreamTurnResult.Stop;
    }

    return StreamTurnResult.Continue;
}

fn drain_pipelined_stream_turns<Stage, B>(
    server:           HttpServer&,
    client_ip:        const u8[:],
    stream_in:        const u8[:],
    wire_in_len:      i64,
    now_ns:           u64,
    req:              Request&,
    res:              Response&,
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

        var step_consumed: i64 = 0;
        let turn_res = process_pipelined_stream_turn(
            server, client_ip, stream, now_ns, req, res,
            wire_out, wire_in_len, step_consumed, total_handled, total_consumed, conn_wants_close, stage,
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
    server:         const HttpServer&,
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
    var presence_tracker = HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard parse_http1_request_headers_fixed(stream, g_turn_req, presence_tracker, body_start_idx) else {
        return false;
    }

    let has_te = (presence_tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;
    let cl_len = if has_cl { presence_tracker.parsed_cl } else { 0 };
    let expected_end = core::add_sat_i64(body_start_idx, cl_len);
    guard !has_te && cl_len >= 0 && cl_len <= MAX_SERVER_BODY_LIMIT && expected_end == stream.len else {
        return false;
    }

    let consumed = stream.len;
    if cl_len > 0 {
        let _pbf = prof_enter("http1.body_framing");
        g_turn_req.body.append(stream[body_start_idx..consumed]);
        prof_leave(_pbf);
    }

    total_consumed = core::add_sat_i64(probe_consumed, consumed);
    out_has_req = true;
    return true;
}

fn finish_single_pipeline_turn<Stage, B>(
    server:           HttpServer&,
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
    let _ = execute_server_pipeline_with_stage(
        server.pipeline, server.timer, local_ip, g_turn_req, now_ns, g_turn_res, future, stage,
    );

    let wants_close = check_and_apply_connection_close(g_turn_req, g_turn_res);
    serialize_http1_response(g_turn_res, server.server_name[..], wire_out);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);

    if wants_close || g_turn_req.method[..] == "CONNECT" {
        conn_wants_close = true;
        if g_turn_req.method[..] == "CONNECT" { total_consumed = wire_in_len; }
    }
}

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests with `<Stage>`.
// Returns (total_requests_processed, total_bytes_consumed, ok, wants_close).
fn handle_connection_wire_pipelined_stream<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> i64, i64, bool, bool {
    g_h1_parse_cache.enabled = server.enable_header_memoization;
    if server.trust_proxy_headers { server.pipeline.trust_proxy_headers = true; }
    wire_out.clear();
    let wire_in_len = wire_in.len;
    var stream = wire_in;
    var total_handled:    i64  = 0;
    var total_consumed:   i64  = 0;
    var conn_wants_close: bool = false;

    if can_try_fast_l0_static(server, stage) {
        let rem_stream, fast_done = drain_fast_l0_static_stream(
            server, stream, now_ns, wire_out, total_handled, total_consumed, conn_wants_close,
        );
        if fast_done {
            return total_handled, total_consumed, true, conn_wants_close;
        }
        stream = rem_stream;
    }

    var has_fast_req = false;
    let is_fast = try_prepare_single_pipeline_turn(
        server, stream, wire_out, total_consumed, has_fast_req,
    );
    var local_ip: u8[..64] = [];
    let _ = local_ip.try_set(client_ip[..min(client_ip.len, 64)]);
    if !is_fast {
        var req = new_request("GET", "");
        var res = Response { .. };
        let ok = drain_pipelined_stream_turns(
            server, local_ip[..], stream, wire_in_len, now_ns,
            req, res, wire_out,
            total_handled, total_consumed, conn_wants_close, stage,
        );
        return total_handled, total_consumed, ok, conn_wants_close;
    }
    if has_fast_req {
        finish_single_pipeline_turn(
            server, local_ip[..], wire_in_len, now_ns, wire_out,
            total_handled, total_consumed, conn_wants_close, stage,
        );
    }
    return total_handled, total_consumed, true, conn_wants_close;
}

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests.
// Returns (total_requests_processed, total_bytes_consumed, ok, wants_close).
fn handle_connection_wire_pipelined_stream<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
) -> i64, i64, bool, bool {
    var noop = wire::NoOpStage {};
    return handle_connection_wire_pipelined_stream(server, client_ip, wire_in, now_ns, wire_out, noop);
}

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests with `<Stage>`.
fn handle_connection_wire_pipelined<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> i64, bool {
    let count, _, ok, _ = handle_connection_wire_pipelined_stream(
        server, client_ip, wire_in, now_ns, wire_out, stage,
    );
    return count, ok;
}

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests (RFC 9112 Section 9.3).
// Concatenates all serialized responses into wire_out and returns (total_requests_processed, ok).
fn handle_connection_wire_pipelined<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
) -> i64, bool {
    let count, _, ok, _ = handle_connection_wire_pipelined_stream(server, client_ip, wire_in, now_ns, wire_out);
    return count, ok;
}

// ---- 6. HTTP/2 & Duplex Pipe Connection Handlers ----------------------------

inline fn handle_h2_pipe_ingress<Stage, B>(
    server:     HttpServer&,
    client_ip:  const u8[:],
    pipe:       core::PipeBuffer&,
    h2_sess:    server_internal::H2ServerSession&,
    now_ns:     u64,
    unread_len: i64,
    wire_out:   B&,
    stage:      Stage&,
) -> i64, bool {
    let stream = pipe.readable_slice();
    let consumed_h2, ok_h2 = server_internal::handle_h2_server_ingress(
        h2_sess, server.pipeline, server.timer, client_ip, stream, now_ns / 1000000, wire_out, stage,
    );
    if ok_h2 {
        pipe.advance_to(consumed_h2, consumed_h2);
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        return 1, true;
    }
    pipe.advance_to(consumed_h2, unread_len);
    return 0, false;
}

// Incremental Sans-IO pipeline handler using PipeBuffer and `<Stage>`.
fn handle_connection_pipe<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
    h2_sess:   server_internal::H2ServerSession&,
    stage:     Stage&,
) -> i64, bool {
    g_h1_parse_cache.enabled = server.enable_header_memoization;
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let unread_len = pipe.readable_len();
    guard unread_len > 0 else { return 0, true; }

    var total_handled: i64 = 0;

    if h2_sess.preface_handled {
        return handle_h2_pipe_ingress(server, client_ip, pipe, h2_sess, now_ns, unread_len, wire_out, stage);
    }

    // Sliced H2 preface: wait for the remaining bytes instead of parsing as HTTP/1.1
    if pipe.consumed == 0 && is_partial_h2_client_preface(pipe.readable_slice()) {
        return 0, true;
    }

    // Check for HTTP/2 connection preface if at the very start of the stream
    if pipe.consumed == 0 && unread_len >= 24 {
        let stream = pipe.readable_slice();
        if is_h2_client_preface(stream) {
            return handle_h2_pipe_ingress(server, client_ip, pipe, h2_sess, now_ns, unread_len, wire_out, stage);
        }
    }

    var req = new_request("GET", "");
    var res = Response { .. };

    while pipe.readable_len() > 0 {
        let res_step = process_pipelined_pipe_step(
            server, client_ip, pipe, req, res, now_ns, total_handled, wire_out, stage,
        );
        if res_step == PipeStepResult.Error {
            return total_handled, false;
        } else if res_step == PipeStepResult.Stop {
            break;
        }
    }

    return total_handled, true;
}

// Incremental Sans-IO pipeline handler using PipeBuffer (RFC 9112 & System.IO.Pipelines model).
// Reads from the pipe buffer, processes all complete pipelined requests, and updates
// pipe cursors (consumed, examined) with strict monotonicity.
// Returns (total_requests_processed, ok).
fn handle_connection_pipe<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
    h2_sess:   server_internal::H2ServerSession&,
) -> i64, bool {
    var noop = wire::NoOpStage {};
    return handle_connection_pipe(server, client_ip, pipe, now_ns, wire_out, h2_sess, noop);
}

inline fn alloc_temp_h2_session(
    pipeline:    ServerPipelineConfig&,
    server_name: const u8[:],
    now_ns:      u64,
) -> i64 {
    return alloc_reactor_h2_session(pipeline, server_name, now_ns / 1000000);
}

fn handle_connection_pipe_with_stage<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> i64, bool {
    let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], now_ns);
    guard h2_idx >= 0 && h2_idx < REACTOR_MAX_H2_SESSIONS else { return 0, false; }
    defer free_reactor_h2_session(h2_idx as i16, server.pipeline);
    return handle_connection_pipe(
        server, client_ip, pipe, now_ns, wire_out, g_default_reactor.h2_sessions[h2_idx], stage,
    );
}

fn handle_connection_pipe<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
) -> i64, bool {
    var noop = wire::NoOpStage {};
    return handle_connection_pipe_with_stage(server, client_ip, pipe, now_ns, wire_out, noop);
}

// Dispatches an HTTP `Request` through `server.pipeline` with a compile-time `<UserStage>` hook.
fn dispatch_server_request_with_stage<UserStage>(
    server:     HttpServer&,
    client_ip:  const u8[:],
    req:        const Request&,
    now_ns:     u64,
    res:        Response&,
    user_stage: UserStage&,
) -> PipelineOutcome {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    var future = server_internal::new_inline_handler_future(0);
    let outcome = execute_server_pipeline_with_stage(
        server.pipeline, server.timer, client_ip, req, now_ns, res, future, user_stage,
    );
    server.requests_processed++;
    return outcome;
}

// ---- 7. Socket Listener Loops, TLS & Page-Ring Execution --------------------

// Probes buffered HTTP/1.1 wire bytes after `\r\n\r\n` (`hdr_end`) to check if the full request body has arrived.
// Returns true immediately on header parse errors or smuggling conflicts so the main parser emits 400 Bad Request.
fn is_http1_request_ready(in_buf: const u8[:], hdr_end: i64) -> bool {
    let body_start = core::add_sat_i64(hdr_end, 4);
    var tracker = HeaderPresenceTracker { .. };
    var parsed_start: i64 = 0;
    var probe_req = Request { .. };
    guard parse_http1_request_headers(in_buf, probe_req, tracker, parsed_start) else {
        return true;
    }
    let has_te = (tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;
    if has_te && has_cl {
        return true;
    }
    if has_cl {
        return in_buf.len >= core::add_sat_i64(body_start, tracker.parsed_cl);
    }
    if has_te {
        guard body_start <= in_buf.len else { return false; }
        let chunk_slice = in_buf[body_start..];
        var cur: i64 = 0;
        loop {
            var csize: u64 = 0;
            let err = read_chunk_size_line(chunk_slice, cur, csize);
            if err == ChunkedDecodeError.UnexpectedEof { return false; }
            guard err == ChunkedDecodeError.None && csize <= (MAX_SERVER_BODY_LIMIT as u64) else { return true; }
            if csize == 0 {
                let tr_err = parse_chunked_trailers(chunk_slice, cur);
                return tr_err != ChunkedDecodeError.UnexpectedEof;
            }
            let sz_i = csize as i64;
            if cur + sz_i + 2 > chunk_slice.len { return false; }
            guard chunk_slice[cur + sz_i] == '\r' && chunk_slice[cur + sz_i + 1] == '\n' else { return true; }
            cur += sz_i + 2;
        }
    }
    return true;
}

// Executes one ingress step of an HTTP/2 server session and flushes any outbound frames.
inline fn step_h2_server_session_buf<InBuf, OutBuf>(
    conn_fd:  i64,
    server:   HttpServer&,
    h2_idx:   i64,
    peer_ip:  const u8[:],
    h2_in:    InBuf&,
    now_ns:   u64,
    out_wire: OutBuf&,
) -> bool {
    out_wire.clear();
    let consumed, ok = server_internal::handle_h2_server_ingress(
        g_default_reactor.h2_sessions[h2_idx],
        server.pipeline,
        server.timer,
        peer_ip,
        h2_in[..],
        div_euclid(now_ns, 1000000),
        out_wire,
    );
    if out_wire.len > 0 {
        let _ = tcp_send(conn_fd, out_wire[..]);
    }
    guard ok else { return false; }
    if consumed > 0 {
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        h2_in.compact_wire_buffer(consumed);
    }
    return true;
}

// Appends `recvd` bytes from `chunk` into `in_buf` if valid and within 16 MB wire limit.
inline fn try_append_recv_chunk<InBuf, ChunkBuf>(recvd: i32, chunk: const ChunkBuf&, in_buf: InBuf&) -> bool {
    guard recvd > 0 else { return false; }
    let n = recvd as i64;
    guard n <= chunk.len && core::add_sat_i64(in_buf.len, n) <= 16777216 else { return false; }
    return in_buf.try_append(chunk[..n]);
}

// Runs a persistent HTTP/2 server session loop over `conn_fd` using caller-supplied `h2_in` buffer (RFC 9113).
fn serve_h2_connection_buf<InBuf>(
    server:          HttpServer&,
    conn_fd:         i64,
    h2_in:           InBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    guard conn_fd > 0 else { return false; }
    server.pipeline.trust_proxy_headers = server.pipeline.trust_proxy_headers || server.trust_proxy_headers;
    let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], 1000000000);
    guard h2_idx >= 0 && h2_idx < REACTOR_MAX_H2_SESSIONS else { return false; }
    defer free_reactor_h2_session(h2_idx as i16, server.pipeline);

    var peer_ip: u8[..64] = [];
    tcp_get_peer_ip(conn_fd, peer_ip);

    var out_wire:   u8[..65536] = [];
    var chunk:      u8[..4096]  = [];
    var now_ns:     u64         = 1000000000;
    var idle_ticks: u64         = 0;
    loop {
        if !step_h2_server_session_buf(conn_fd, server, h2_idx, peer_ip[..], h2_in, now_ns, out_wire) {
            chunk.clear();
            let _ = tcp_recv(conn_fd, chunk, 4096, 10);
            return false;
        }
        chunk.clear();
        let recvd = tcp_recv(conn_fd, chunk, 4096, recv_timeout_ms);
        if recvd == -2 {
            idle_ticks = core::add_sat_u64(idle_ticks, 1);
            if idle_ticks >= 2 { break; }
            continue;
        }
        if !try_append_recv_chunk(recvd, chunk, h2_in) {
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
    server:      HttpServer&,
    req:         const Request&,
    consumed:    i64,
    stage:       Stage&,
    in_buf:      InBuf&,
    ws_frag_buf: FragBuf&,
    out_wire:    OutBuf&,
) -> bool {
    let r_idx = find_ws_route(server, req.url[..]);
    guard r_idx >= 0 else { return false; }
    let behavior = server.ws_routes[r_idx as i64].behavior;
    var ws_res = Response { .. };
    var ws, ok_ws = ws_upgrade_request(req, ws_res, behavior.subprotocol[..]);
    guard ok_ws else { return false; }
    ws.max_payload_length = behavior.max_payload_length;
    ws.max_backpressure = behavior.max_backpressure;
    ws.close_on_backpressure_limit = behavior.close_on_backpressure_limit;
    ws.idle_timeout_s = behavior.idle_timeout_s;
    ws.max_lifetime_s = behavior.max_lifetime_s;
    ws.send_pings_automatically = behavior.send_pings_automatically;
    ws.reset_idle_timeout_on_send = behavior.reset_idle_timeout_on_send;
    let ua_upg = req.header("user-agent");
    if behavior.compression != WS_COMPRESS_DISABLED && !ws_has_broken_compression(ua_upg) {
        let client_ext = req.header("sec-websocket-extensions");
        if client_ext.contains_fold("permessage-deflate") {
            ws_res.set_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover");
            enable_permessage_deflate(ws, behavior.compression);
        }
    }
    out_wire.clear();
    serialize_http1_response(ws_res, server.server_name[..], out_wire);
    let _ = tcp_send(conn_fd, out_wire[..]);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    in_buf.compact_wire_buffer(consumed);
    serve_ws_session_buf(conn_fd, ws, stage, in_buf, ws_frag_buf, out_wire);
    return true;
}

// Flushes buffered HTTP/1.1 response frames in `out_wire` to `conn_fd` and resets the cork buffer.
inline fn flush_http1_cork_buf<OutBuf>(conn_fd: i64, out_wire: OutBuf&) {
    if out_wire.len > 0 {
        let _ = tcp_send(conn_fd, out_wire[..]);
        out_wire.clear();
    }
}

// Dispatches a single parsed HTTP/1.1 request through `server` and `stage`, appends the response
// into `out_wire` for pipelined cork batching, and returns true if keep-alive should continue.
inline fn server_should_stop(server: const HttpServer&) -> bool {
    return !server.is_running || (server.honor_shutdown_flag && shutdown_requested());
}

inline fn server_init_run_state(server: HttpServer&) {
    if server.handle_os_signals {
        let _ = install_shutdown_signals();
    }
    server.is_running = true;
}

fn dispatch_http1_connection_turn<Stage, OutBuf>(
    conn_fd:  i64,
    server:   HttpServer&,
    peer_ip:  const u8[:],
    req:      const Request&,
    stage:    Stage&,
    out_wire: OutBuf&,
) -> bool {
    var res = Response { .. };
    let now_ns = core::monotonic_now().as_nanos();
    let _ = dispatch_server_request_with_stage(server, peer_ip, req, now_ns, res, stage);
    if req.url[..] == "/shutdown" && res.status_code == 200 {
        server.is_running = false;
    }
    if server.honor_shutdown_flag && shutdown_requested() {
        server.is_running = false;
    }
    let conn_hdr = res.header("Connection");
    let wants_ka = server.is_running && conn_hdr.eq_ascii_fold("keep-alive");
    if !wants_ka && conn_hdr.len == 0 {
        set_header(res, "Connection", "close");
    }
    if out_wire.len >= 12288 {
        flush_http1_cork_buf(conn_fd, out_wire);
    }
    serialize_http1_response(res, server.server_name[..], out_wire);
    return wants_ka;
}

// Serves an auxiliary concurrent connection accepted while a primary connection is idle pre-preface (h2spec).
fn serve_idle_aux_connection(listener_fd: i64, server: HttpServer&, recv_timeout_ms: u32) -> bool {
    guard listener_fd > 0 else { return false; }
    let aux_conn = tcp_accept(listener_fd, 0);
    guard aux_conn > 0 else { return false; }
    var aux_in:    u8[..65536] = [];
    var aux_chunk: u8[..4096]  = [];
    var ticks:     u64         = 0;
    while ticks < 10 {
        aux_chunk.clear();
        let recvd = tcp_recv(aux_conn, aux_chunk, 4096, 15);
        if recvd == -2 {
            ticks = core::add_sat_u64(ticks, 1);
            continue;
        }
        if !try_append_recv_chunk(recvd, aux_chunk, aux_in) {
            break;
        }
        ticks = 0;
        if !is_partial_h2_client_preface(aux_in[..]) {
            if is_h2_client_preface(aux_in[..]) {
                let _ = serve_h2_connection_buf(server, aux_conn, aux_in, recv_timeout_ms);
            }
            break;
        }
    }
    tcp_close(aux_conn);
    return true;
}

// Processes a complete buffered HTTP/1.1 request in `in_buf` (WebSocket upgrade or HTTP/1.1 pipeline turn).
// Returns true if the connection loop should continue reading another keep-alive request.
fn process_ready_http1_connection_buf<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:     i64,
    server:      HttpServer&,
    peer_ip:     const u8[:],
    stage:       Stage&,
    in_buf:      InBuf&,
    ws_frag_buf: FragBuf&,
    out_wire:    OutBuf&,
) -> bool {
    var req = new_request("GET", "");
    let ok_req, consumed = parse_http1_wire_request(in_buf[..], req);
    guard ok_req && consumed > 0 else {
        flush_http1_cork_buf(conn_fd, out_wire);
        serialize_bad_request_error(server.server_name[..], out_wire);
        flush_http1_cork_buf(conn_fd, out_wire);
        return false;
    }
    if is_websocket_upgrade_request(req) {
        flush_http1_cork_buf(conn_fd, out_wire);
        if serve_http1_upgraded_ws(conn_fd, server, req, consumed, stage, in_buf, ws_frag_buf, out_wire) {
            return false;
        }
    }
    let wants_ka = dispatch_http1_connection_turn(conn_fd, server, peer_ip, req, stage, out_wire);
    in_buf.compact_wire_buffer(consumed);
    return wants_ka;
}

// Checks whether `in_buf` contains a complete HTTP/1.1 request ready for dispatch (when not an H2 preface).
inline fn has_ready_http1_request(in_buf: const u8[:], hdr_scan_cursor: i64&) -> bool {
    guard !is_partial_h2_client_preface(in_buf) && !is_h2_client_preface(in_buf) else { return false; }
    let hdr_end = scan_crlfcrlf_incremental(in_buf, hdr_scan_cursor);
    guard hdr_end >= 0 else { return false; }
    return is_http1_request_ready(in_buf, hdr_end);
}

// Handles a newly received HTTP/2 preface or invalid PRI prefix in `in_buf`.
// Returns true if the connection was handled/terminated as HTTP/2 or invalid PRI.
fn try_dispatch_h2_or_invalid_preface_buf<InBuf>(
    server:          HttpServer&,
    conn_fd:         i64,
    in_buf:          InBuf&,
    recv_timeout_ms: u32,
) -> bool {
    guard !is_partial_h2_client_preface(in_buf[..]) else { return false; }
    if is_h2_client_preface(in_buf[..]) {
        let _ = serve_h2_connection_buf(server, conn_fd, in_buf, recv_timeout_ms);
        return true;
    }
    return in_buf.len >= 4 && in_buf[..4] == "PRI ";
}

// Handles an idle poll timeout (`recvd == -2`) on `conn_fd`, polling `listener_fd` for auxiliary connections.
inline fn step_idle_connection_poll(
    listener_fd:     i64,
    server:          HttpServer&,
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
    server:          HttpServer&,
    in_buf:          InBuf&,
    poll_ms:         u32,
    recv_timeout_ms: u32,
    idle_ticks:      u64&,
) -> bool {
    var chunk: u8[..4096] = [];
    let recvd = tcp_recv(conn_fd, chunk, 4096, poll_ms);
    if recvd == -2 {
        step_idle_connection_poll(listener_fd, server, in_buf.len, recv_timeout_ms, idle_ticks);
        return idle_ticks < 25;
    }
    guard try_append_recv_chunk(recvd, chunk, in_buf) else { return false; }
    idle_ticks = 0;
    return !try_dispatch_h2_or_invalid_preface_buf(server, conn_fd, in_buf, recv_timeout_ms);
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection on `conn_fd` using caller-supplied buffers.
fn serve_http_connection_on_listener_buf<Stage, InBuf, FragBuf, OutBuf>(
    listener_fd:     i64,
    conn_fd:         i64,
    server:          HttpServer&,
    stage:           Stage&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    guard conn_fd > 0 else { return server.is_running; }
    g_h1_parse_cache.enabled = server.enable_header_memoization;
    in_buf.clear();
    out_wire.clear();
    var peer_ip:    u8[..64] = [];
    var idle_ticks: u64      = 0;
    server.pipeline.hdr_scan_cursor = 0;
    let need_peer_ip = server.pipeline.enable_rate_limiter
        || server.trust_proxy_headers
        || server.pipeline.trust_proxy_headers;
    if need_peer_ip {
        tcp_get_peer_ip(conn_fd, peer_ip);
    } else {
        let _ = peer_ip.try_set("127.0.0.1");
    }
    let poll_ms: u32 = min(max(recv_timeout_ms, 1), 100);

    loop {
        if has_ready_http1_request(in_buf[..], server.pipeline.hdr_scan_cursor) {
            idle_ticks = 0;
            if process_ready_http1_connection_buf(
                conn_fd, server, peer_ip[..], stage, in_buf, ws_frag_buf, out_wire,
            ) {
                server.pipeline.hdr_scan_cursor = 0;
                continue;
            }
            flush_http1_cork_buf(conn_fd, out_wire);
            break;
        }
        flush_http1_cork_buf(conn_fd, out_wire);
        if !poll_http_connection_ingress_buf(
            listener_fd, conn_fd, server, in_buf, poll_ms, recv_timeout_ms, idle_ticks,
        ) {
            break;
        }
    }
    flush_http1_cork_buf(conn_fd, out_wire);
    return server.is_running;
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection on `conn_fd` using caller-supplied buffers.
fn serve_http_connection_buf<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:         i64,
    server:          HttpServer&,
    stage:           Stage&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    return serve_http_connection_on_listener_buf(
        -1, conn_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms,
    );
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection with caller buffers and default `wire::NoOpStage`.
fn serve_http_connection_buf<InBuf, FragBuf, OutBuf>(
    conn_fd:         i64,
    server:          HttpServer&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    var stage = wire::NoOpStage {};
    return serve_http_connection_buf(conn_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection with 64 KB stack buffers and `<Stage>`.
fn serve_http_connection<Stage>(
    conn_fd:         i64,
    server:          HttpServer&,
    stage:           Stage&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    var in_buf:      u8[..65536] = [];
    var ws_frag_buf: u8[..65536] = [];
    var out_wire:    u8[..65536] = [];
    return serve_http_connection_buf(conn_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection with 64 KB stack buffers and `wire::NoOpStage`.
fn serve_http_connection(
    conn_fd:         i64,
    server:          HttpServer&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    var stage = wire::NoOpStage {};
    return serve_http_connection(conn_fd, server, stage, recv_timeout_ms);
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections on `listener_fd` using caller buffers.
fn serve_http_listener_buf<Stage, InBuf, FragBuf, OutBuf>(
    listener_fd:     i64,
    server:          HttpServer&,
    stage:           Stage&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) {
    guard listener_fd > 0 else { return; }
    server_init_run_state(server);
    while !server_should_stop(server) {
        let conn = tcp_accept(listener_fd, 200);
        if conn <= 0 {
            continue;
        }
        let _ = serve_http_connection_on_listener_buf(
            listener_fd, conn, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms,
        );
        tcp_close(conn);
    }
    server.is_running = false;
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections with caller buffers and `wire::NoOpStage`.
fn serve_http_listener_buf<InBuf, FragBuf, OutBuf>(
    listener_fd:     i64,
    server:          HttpServer&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) {
    var stage = wire::NoOpStage {};
    serve_http_listener_buf(listener_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections with 64 KB stack buffers and `<Stage>`.
fn serve_http_listener<Stage>(
    listener_fd:     i64,
    server:          HttpServer&,
    stage:           Stage&,
    recv_timeout_ms: u32 = 500,
) {
    var in_buf:      u8[..65536] = [];
    var ws_frag_buf: u8[..65536] = [];
    var out_wire:    u8[..65536] = [];
    serve_http_listener_buf(listener_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections with 64 KB stack buffers.
fn serve_http_listener(
    listener_fd:     i64,
    server:          HttpServer&,
    recv_timeout_ms: u32 = 500,
) {
    var stage = wire::NoOpStage {};
    serve_http_listener(listener_fd, server, stage, recv_timeout_ms);
}

inline fn response_wire_has_connection_close(wire: const u8[:]) -> bool {
    return wire.contains_fold("\r\nconnection: close\r\n");
}

// Binds and listens on a Unix Domain Socket (AF_UNIX) path (uWebSockets app.listen(path) pattern).
// Eliminates network stack TCP overhead for local IPC and sidecar communication.
// Returns listening socket handle, or -1 on error.
fn listen_unix(server: HttpServer&, path: const u8[:], backlog: i32 = 128) -> i64 {
    return tcp_listen_unix(path, backlog);
}

// Adopts an externally accepted or inherited socket descriptor into the server environment
// (uWebSockets us_adopt_accepted_socket pattern).
fn adopt_socket(server: HttpServer&, raw_fd: i64) -> i64 {
    return adopt_socket(raw_fd);
}

inline fn step_page_ring_conn<Stage>(
    server:  HttpServer&,
    conn:    i64,
    peer_ip: const u8[:],
    ring:    core::PageRingBuffer&,
    cork:    core::CorkBuffer&,
    stage:   Stage&,
) -> bool {
    let recvd = ring.page_ring_recv(conn, 65536, 5000);
    guard recvd > 0 else { return false; }
    let now_ns = core::monotonic_now().as_nanos();
    let _, ok_handle = handle_connection_page_ring(server, peer_ip, ring, now_ns, cork, stage);
    let should_close = !ok_handle || response_wire_has_connection_close(cork.cork_as_slice());
    if !ok_handle {
        if cork.cork_pending() > 0 { tcp_flush_cork(conn, cork); }
        return false;
    }
    if cork.cork_pending() > 0 {
        let sent = tcp_flush_cork(conn, cork);
        return sent > 0 && !should_close;
    }
    return !should_close;
}

// Executes a live TCP accept and dispatch loop using hardware page-mirrored ring buffer (PageRingBuffer) and `<Stage>`.
fn serve_page_ring_loop<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    max_connections: i64,
    ring:            core::PageRingBuffer&,
    stage:           Stage&,
) -> i64 {
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;
    server_init_run_state(server);

    while !server_should_stop(server) && (max_connections == 0 || total_served < max_connections) {
        let conn = tcp_accept(listener_fd, 200);
        if conn <= 0 {
            continue;
        }
        defer tcp_close(conn);

        ring.page_ring_clear();
        cork.cork_reset();
        tcp_get_peer_ip(conn, peer_ip);

        while !server_should_stop(server) {
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
    server:          HttpServer&,
    listener_fd:     i64,
    max_connections: i64,
    ring:            core::PageRingBuffer&,
) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_page_ring_loop(server, listener_fd, max_connections, ring, noop);
}

inline fn step_pipe_loop_conn<Stage>(
    server:  HttpServer&,
    conn:    i64,
    peer_ip: const u8[:],
    pipe:    core::PipeBuffer&,
    cork:    core::CorkBuffer&,
    h2_idx:  i64,
    stage:   Stage&,
) -> bool {
    guard !server_should_stop(server) else { return false; }
    let recvd = tcp_recv_pipe(conn, pipe, 4096, 5000);
    guard recvd > 0 else { return false; }
    let now_ns = core::monotonic_now().as_nanos();
    let _, ok = handle_connection_pipe(
        server, peer_ip, pipe, now_ns, cork, g_default_reactor.h2_sessions[h2_idx], stage,
    );
    let should_close = !ok || response_wire_has_connection_close(cork.cork_as_slice());
    if !ok {
        if cork.cork_pending() > 0 { tcp_flush_cork(conn, cork); }
        return false;
    }
    if cork.cork_pending() > 0 {
        let sent = tcp_flush_cork(conn, cork);
        return sent > 0 && !should_close;
    }
    return !should_close;
}

// Executes a live TCP accept and dispatch loop using standard PipeBuffer and `<Stage>`.
fn serve_pipe_loop<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    max_connections: i64,
    stage:           Stage&,
) -> i64 {
    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;
    server_init_run_state(server);

    while !server_should_stop(server) && (max_connections == 0 || total_served < max_connections) {
        let conn = tcp_accept(listener_fd, 200);
        if conn <= 0 {
            continue;
        }
        defer tcp_close(conn);

        pipe.pipe_reset();
        cork.cork_reset();
        tcp_get_peer_ip(conn, peer_ip);
        let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], 0);
        if h2_idx < 0 || h2_idx >= REACTOR_MAX_H2_SESSIONS {
            total_served = core::add_sat_i64(total_served, 1);
            continue;
        }
        defer free_reactor_h2_session(h2_idx as i16, server.pipeline);

        while step_pipe_loop_conn(server, conn, peer_ip[..], pipe, cork, h2_idx, stage) {}
        total_served = core::add_sat_i64(total_served, 1);
    }
    server.is_running = false;

    return total_served;
}

// Executes a live TCP accept and dispatch loop using standard PipeBuffer.
fn serve_pipe_loop(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_pipe_loop(server, listener_fd, max_connections, noop);
}

// Executes a live TCP accept and dispatch loop with a custom `<Stage>` hook.
fn serve_with_stage<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    stage:           Stage&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }

    var ring = core::PageRingBuffer { .. };
    let ok_ring = ring.page_ring_init(65536);
    if ok_ring {
        defer ring.page_ring_close();
        return serve_page_ring_loop(server, listener_fd, max_connections, ring, stage);
    }

    return serve_pipe_loop(server, listener_fd, max_connections, stage);
}

// Executes a live TCP accept and dispatch loop.
// Transparently uses high-performance hardware page-mirrored ring buffer (PageRingBuffer)
// with seamless fallback to PipeBuffer for restricted environments.
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_with_stage(server, listener_fd, noop, max_connections);
}

fn tls_recv_pipe(
    fd:         i64,
    slot_idx:   u16,
    pipe:       core::PipeBuffer&,
    min_span:   i64 = 4096,
    timeout_ms: u32 = 5000,
) -> i32 {
    guard fd > 0 else { return -1; }
    let span, err = pipe.get_write_span(min_span);
    if err != core::IoError.None { return -1; }
    let recvd = tls_transport_recv_slice(fd, slot_idx, span, timeout_ms);
    if recvd > 0 { pipe.commit_write(recvd); }
    return recvd;
}

fn tls_flush_cork(fd: i64, slot_idx: u16, cork: core::CorkBuffer&) -> i32 {
    let slice = cork.cork_as_slice();
    guard slice.len > 0 else { return 0; }
    let sent = tls_transport_send(fd, slot_idx, slice);
    cork.cork_reset();
    return sent;
}

inline fn verify_tls_slot_sni(server: const HttpServer&, slot_idx: i32) -> bool {
    guard server.sni_registry.count > 0 else { return true; }
    let sni_host = g_tls_cipher_slots[slot_idx as i64].server_name[..];
    let _, ok_sni = resolve_sni_credentials(server, sni_host);
    return ok_sni;
}

inline fn step_tls_loop_conn(
    server:   HttpServer&,
    conn:     i64,
    slot_idx: u16,
    peer_ip:  const u8[:],
    pipe:     core::PipeBuffer&,
    cork:     core::CorkBuffer&,
    h2_idx:   i64,
) -> bool {
    let recvd = tls_recv_pipe(conn, slot_idx, pipe, 4096, 5000);
    guard recvd > 0 else { return false; }

    let now_ns = core::monotonic_now().as_nanos();
    let _, ok = handle_connection_pipe(
        server, peer_ip, pipe, now_ns, cork, g_default_reactor.h2_sessions[h2_idx],
    );
    let should_close = !ok || response_wire_has_connection_close(cork.cork_as_slice());
    if !ok {
        if cork.cork_pending() > 0 { tls_flush_cork(conn, slot_idx, cork); }
        return false;
    }
    if cork.cork_pending() > 0 {
        let sent = tls_flush_cork(conn, slot_idx, cork);
        return sent > 0 && !should_close;
    }
    return !should_close;
}

// Executes a live TLS 1.3 HTTPS accept and dispatch loop using PipeBuffer and TLS record AEAD.
fn serve_tls(
    server:          HttpServer&,
    listener_fd:     i64,
    tls_config:      const TlsServerHandshakeConfig&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;
    server_init_run_state(server);

    while !server_should_stop(server) && (max_connections == 0 || total_served < max_connections) {
        let conn = tcp_accept(listener_fd, 200);
        if conn <= 0 { continue; }

        let slot_idx, ok_hs = tls_server_handshake(conn, tls_config);
        if !ok_hs || !verify_tls_slot_sni(server, slot_idx) {
            if ok_hs {
                tls_transport_close(conn, slot_idx);
            } else {
                tcp_close(conn);
            }
            total_served = core::add_sat_i64(total_served, 1);
            continue;
        }
        defer tls_transport_close(conn, slot_idx);

        pipe.pipe_reset();
        cork.cork_reset();
        tcp_get_peer_ip(conn, peer_ip);
        let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], 0);
        if h2_idx < 0 || h2_idx >= REACTOR_MAX_H2_SESSIONS {
            total_served = core::add_sat_i64(total_served, 1);
            continue;
        }
        defer free_reactor_h2_session(h2_idx as i16, server.pipeline);

        while !server_should_stop(server) {
            if !step_tls_loop_conn(server, conn, slot_idx, peer_ip[..], pipe, cork, h2_idx) {
                break;
            }
        }
        total_served = core::add_sat_i64(total_served, 1);
    }
    server.is_running = false;
    return total_served;
}

// ---- 8. Page-Ring Zero-Copy & Static Mmap Transfers -------------------------

// Incremental Sans-IO pipeline handler using hardware page-mirrored ring buffer (PageRingBuffer) and `<Stage>`.
// Eliminates buffer wraparound splitting and memmove compaction during streaming request processing.
inline fn handle_page_ring_h2_preface<Stage, B>(
    server:     HttpServer&,
    client_ip:  const u8[:],
    ring:       core::PageRingBuffer&,
    peek_slice: const u8[:],
    now_ns:     u64,
    wire_out:   B&,
    out_done:   bool&,
    out_ok:     bool&,
    stage:      Stage&,
) -> i64 {
    if is_partial_h2_client_preface(peek_slice) {
        out_done = true;
        out_ok = true;
        return 0;
    }
    guard is_h2_client_preface(peek_slice) else {
        out_done = false;
        out_ok = true;
        return 0;
    }
    let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], now_ns);
    guard h2_idx >= 0 && h2_idx < REACTOR_MAX_H2_SESSIONS else {
        out_done = true;
        out_ok = false;
        ring.page_ring_clear();
        return 0;
    }
    defer free_reactor_h2_session(h2_idx as i16, server.pipeline);
    let consumed_h2, ok_h2 = server_internal::handle_h2_server_ingress(
        g_default_reactor.h2_sessions[h2_idx],
        server.pipeline,
        server.timer,
        client_ip,
        peek_slice,
        now_ns / 1000000,
        wire_out,
        stage,
    );
    out_done = true;
    out_ok = ok_h2;
    if ok_h2 {
        ring.page_ring_discard(consumed_h2);
        server.requests_processed++;
        return 1;
    }
    ring.page_ring_clear();
    return 0;
}

fn handle_connection_page_ring<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    ring:      core::PageRingBuffer&,
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> i64, bool {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    guard ring.count > 0 else { return 0, true; }

    g_default_reactor.chunk.len = 0;
    let peek_n = ring.page_ring_peek(g_default_reactor.chunk.bytes[..]);
    guard peek_n > 0 else { return 0, true; }
    let peek_slice = g_default_reactor.chunk.bytes[..peek_n];

    if is_partial_h2_client_preface(peek_slice) || is_h2_client_preface(peek_slice) {
        var h2_done = false;
        var h2_ok = true;
        let h2_cnt = handle_page_ring_h2_preface(
            server, client_ip, ring, peek_slice, now_ns, wire_out, h2_done, h2_ok, stage,
        );
        if h2_done {
            return h2_cnt, h2_ok;
        }
    }

    let total_handled, total_consumed, ok_pipe, wants_close = handle_connection_wire_pipelined_stream(
        server, client_ip, peek_slice, now_ns, wire_out, stage,
    );
    if !ok_pipe {
        ring.page_ring_clear();
        return total_handled, false;
    }
    if total_consumed > 0 {
        ring.page_ring_discard(total_consumed);
    }
    if wants_close {
        ring.page_ring_clear();
    }
    return total_handled, true;
}

fn handle_connection_page_ring<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    ring:      core::PageRingBuffer&,
    now_ns:    u64,
    wire_out:  B&,
) -> i64, bool {
    var noop = wire::NoOpStage {};
    return handle_connection_page_ring(server, client_ip, ring, now_ns, wire_out, noop);
}

// Executes a live TCP accept and dispatch loop explicitly using PageRingBuffer.
fn serve_page_ring(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    guard listener_fd > 0 else { return 0; }
    var ring = core::PageRingBuffer { .. };
    let ok = ring.page_ring_init(65536);
    guard ok else { return 0; }
    defer ring.page_ring_close();
    return serve_page_ring_loop(server, listener_fd, max_connections, ring);
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

// Serves a static file using memory-mapped pages directly to the wire response buffer.
fn serve_static_mmap_file<B>(
    path:         const u8[:],
    content_type: const u8[:],
    wire_out:     B&,
) -> bool {
    guard content_type.len <= 384 else { return false; }
    var mf, ok = core::mmap_file_open(path);
    guard ok else { return false; }
    defer mf.mmap_file_close();

    var hdr_buf: u8[..512] = [];
    hdr_buf.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    hdr_buf.append(content_type);
    hdr_buf.append("\r\nContent-Length: ");
    mf.size.format_u64_dec(hdr_buf);
    hdr_buf.append("\r\nConnection: keep-alive\r\n\r\n");

    let prev_len = wire_out.len;
    var committed = false;
    defer if !committed { wire_out.resize(prev_len); };
    wire_out.append(hdr_buf[..]);

    var chunk_buf: u8[4096] = [0; 4096];
    var offset:    u64      = 0;
    while offset < mf.size {
        let rem = mf.size - offset;
        let ask = min(rem, 4096);
        let n, r_ok = mf.mmap_file_read(offset, chunk_buf[..(ask as i64)]);
        guard r_ok && n > 0 else { break; }
        wire_out.append(chunk_buf[..n]);
        offset = offset + (n as u64);
    }
    committed = verify_mmap_transfer_complete(offset, mf.size, prev_len, hdr_buf.len, wire_out.len);
    return committed;
}

// Sends a static file directly from kernel memory-mapped pages to a socket with zero user-space copying.
fn send_static_mmap_file(
    sock_fd:      i64,
    path:         const u8[:],
    content_type: const u8[:],
) -> bool {
    guard sock_fd > 0 && content_type.len <= 384 else { return false; }
    var mf, ok = core::mmap_file_open(path);
    guard ok else { return false; }
    defer mf.mmap_file_close();
    guard mf.size <= 0x7FFFFFFF else { return false; }

    var hdr_buf: u8[..512] = [];
    hdr_buf.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    hdr_buf.append(content_type);
    hdr_buf.append("\r\nContent-Length: ");
    mf.size.format_u64_dec(hdr_buf);
    hdr_buf.append("\r\nConnection: keep-alive\r\n\r\n");

    let sent_hdr = native_tcp_send(sock_fd, hdr_buf[..]);
    guard sent_hdr == (hdr_buf.len as i32) else { return false; }

    guard mf.size > 0 else { return true; }
    let sent_body, body_ok = mf.mmap_file_send(0, mf.size as u32, sock_fd);
    return body_ok && (sent_body as u64) == mf.size;
}
