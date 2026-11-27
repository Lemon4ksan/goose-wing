// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone zero-allocation HTTP server engine, wire protocol serializer, and connection coordinator.
// Conforms to RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1 Framing), and RFC 9113 (HTTP/2 Preface Detection).
namespace server;

import std;
import core;
import .router;
import .pool;
import .pipeline;
import .h2_mux_types_internal;
import .h2_mux_frames_internal;
import .h2_mux_streams_internal;
import .soa_timer;
import realtime.topic_tree;
import http.compression_dict;
import .h1_codec;
import .cork;
import .stream_consumer;
import .sni;
import net.accel;
import net.transport;
import tls.backend;
import .server_h1_internal;
import .server_fast_l0_internal;
import .server_transport_internal;
import .h1_codec_internal;
import .pipeline_internal;
import .router_internal;
import .reactor;

struct WsRouteEntry {
    path:     u8[..128]            = [],
    behavior: realtime::WsBehavior = realtime::WsBehavior { .. },
    in_use:   bool                 = false,
}

struct HttpServer {
    pipeline:                     ServerPipelineConfig             = ServerPipelineConfig { .. },
    host:                         u8[..256]                        = "127.0.0.1",
    port:                         u16                              = 8080,
    server_name:                  u8[..64]                         = "goose-wing/1.0",
    timer:                        server_internal::ConnectionTimer = server_internal::ConnectionTimer { .. },
    is_running:                   bool                             = false,
    requests_processed:           u64                              = 0,
    accept_proxy_protocol:        bool                             = false,
    trust_proxy_headers:          bool                             = false,
    proxy_protocol_trusted_cidrs: u8[..64][..8]                    = [],
    topic_tree:                   realtime::TopicTree              = realtime::TopicTree { .. },
    ws_routes:                    WsRouteEntry[..16]               = [WsRouteEntry { .. }; 16],
    ws_route_count:               i32                              = 0,
    shared_compressor:            realtime::SharedWsCompressor     = realtime::SharedWsCompressor { .. },
    sni_registry:                 SniRegistry                      = SniRegistry { .. },
    cached_date:                  CachedHttpDate                   = CachedHttpDate { .. },
    fast_l0_last_headers:         u8[..256]                        = [],
    fast_l0_last_host:            u8[..128]                        = [],
    fast_l0_last_close:           bool                             = false,
    enable_header_memoization:    bool                             = false,
    turn_in_use:                  bool                             = false,
    handle_os_signals:            bool                             = false,
    honor_shutdown_flag:          bool                             = true,
    shutdown_grace_ns:            u64                              = 2000000000,
    accel_mode:                   net::ReactorAccelMode            = net::ReactorAccelMode.Auto,
    enable_ktls_offload:          bool                             = true,
    tls_backend:                  tls::TlsBackendKind              = tls::TlsBackendKind.Auto,
    tls_min_version:              tls::TlsMinVersion               = tls::TlsMinVersion.Tls13,
    tls_cert_pem_file:            u8[..256]                        = [],
    tls_key_pem_file:             u8[..256]                        = [],
    tls_ca_file:                  u8[..256]                        = [],
    tls_require_client_cert:      bool                             = false,
    tls_alpn_wire:                u8[..64]                         = [],
    tls_keylog_file:              u8[..256]                        = [],
    tls_handshake_timeout_ms:     u32                              = 5000,
    idle_timeout_ms:              u64                              = 30000,
    read_header_timeout_ms:       u32                              = 5000,
    read_body_timeout_ms:         u32                              = 15000,
    max_header_bytes:             i64                              = 16384,
    max_body_bytes:               i64                              = 10485760,
    max_connections:              i32                              = 0,
    max_h2_concurrent_streams:    u32                              = 100,
    omit_server_header:           bool                             = false,
    omit_date_header:             bool                             = false,
    so_reuseport:                 bool                             = false,
    listen_backlog:               i32                              = 128,
    tcp_nodelay:                  bool                             = true,
}

// Listening TCP socket tuning options applied by `set_server_socket_options` and `listen_http_server`.
struct ServerSocketOptions {
    listen_backlog: i32  = 128,
    so_reuseport:   bool = false,
    tcp_nodelay:    bool = true,
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

// Initializes an existing `HttpServer` in place without allocating a multi-megabyte stack temporary.
fn init_http_server_inplace(
    server:   HttpServer&,
    host_str: const u8[:] = "127.0.0.1",
    port_num: u16         = 8080,
) {
    init_server_pipeline_config_inplace(
        server.pipeline,
        host_str,
        security::new_gcra_quota(1000, wing::secs(1), 100),
    );
    server.port = port_num;
    server.timer = server_internal::new_connection_timer(30000000000, 1000000000);
    server.is_running = true;
    server.requests_processed = 0;
    let _ = server.host.try_set(host_str[..min(host_str.len, 256)]);
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

// Registers a route on `server` directly from a shared contract spec (`.method` and `.path_template`).
fn add_contract_route<S>(server: HttpServer&, spec: const S&, handler_id: i32) -> bool {
    return add_route(server.pipeline.router, spec.method[..], spec.path_template[..], handler_id);
}

// Registers a declarative WebSocket route on the server instance (uWebSockets app.ws pattern)
fn add_ws_route(
    server:   HttpServer&,
    path:     const u8[:],
    behavior: const realtime::WsBehavior& = realtime::WsBehavior { .. },
) -> bool {
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

fn publish(server: HttpServer&, topic: const u8[:], message: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64 {
    return server.topic_tree.publish(topic, message, opcode);
}

fn publish_text(server: HttpServer&, topic: const u8[:], text: const u8[:]) -> i64 {
    return server.topic_tree.publish_text(topic, text);
}

fn publish_binary(server: HttpServer&, topic: const u8[:], data: const u8[:]) -> i64 {
    return server.topic_tree.publish_binary(topic, data);
}

fn subscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
    return server.topic_tree.subscribe(sock_fd, topic_pattern);
}

fn unsubscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
    return server.topic_tree.unsubscribe(sock_fd, topic_pattern);
}

fn unsubscribe_all(server: HttpServer&, sock_fd: i64) -> i32 {
    return server.topic_tree.unsubscribe_all(sock_fd);
}

fn find_subscribers(server: const HttpServer&, topic: const u8[:], out_fds: i64[..512]&) -> i64 {
    return server.topic_tree.find_subscribers(topic, out_fds);
}

fn subscribe_ex(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
    out_old:       i32&,
    out_new:       i32&,
) -> bool {
    let old_cnt, new_cnt, ok = server.topic_tree.subscribe_ex(sock_fd, topic_pattern);
    out_old = old_cnt;
    out_new = new_cnt;
    return ok;
}

fn unsubscribe_ex(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
    out_old:       i32&,
    out_new:       i32&,
) -> bool {
    let old_cnt, new_cnt, ok = server.topic_tree.unsubscribe_ex(sock_fd, topic_pattern);
    out_old = old_cnt;
    out_new = new_cnt;
    return ok;
}

fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
) -> bool {
    return realtime::subscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
) -> bool {
    return realtime::unsubscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_all_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(server: HttpServer&, sock_fd: i64) -> i32 {
    return realtime::unsubscribe_all_with_hook<HookFn>(server.topic_tree, sock_fd);
}

fn get_socket_topic_count(server: const HttpServer&, sock_fd: i64) -> i32 {
    return server.topic_tree.socket_subscription_count(sock_fd);
}

fn get_socket_topics(server: const HttpServer&, sock_fd: i64, out_topics: u8[..64][..32]&) -> i32 {
    return server.topic_tree.get_socket_topics(sock_fd, out_topics);
}

fn iterate_socket_topics<IterFn: fn(const u8[:])>(server: const HttpServer&, sock_fd: i64) -> i32 {
    return realtime::iterate_socket_topics<IterFn>(server.topic_tree, sock_fd);
}

// Asynchronous WebSocket Upgrade helpers (uWebSockets res->onAborted & res->upgrade pattern)
fn defer_ws_upgrade(
    server:  const HttpServer&,
    req:     const http::Request&,
    sock_fd: i64,
) -> realtime::WsPendingUpgrade, bool {
    guard realtime::is_websocket_upgrade_request(req) else {
        return realtime::WsPendingUpgrade { .. }, false;
    }
    let r_idx = find_ws_route(server, req.url[..]);
    guard r_idx >= 0 else {
        return realtime::WsPendingUpgrade { .. }, false;
    }
    let client_key = req.headers.find_header("Sec-WebSocket-Key");
    guard realtime::is_valid_websocket_key(client_key) else {
        return realtime::WsPendingUpgrade { .. }, false;
    }
    let subprotocol = req.headers.find_header("Sec-WebSocket-Protocol");
    let extensions = req.headers.find_header("Sec-WebSocket-Extensions");
    guard subprotocol.len <= 64 && extensions.len <= 256 else {
        return realtime::WsPendingUpgrade { .. }, false;
    }

    var pending = realtime::new_ws_pending_upgrade(sock_fd, client_key, r_idx, subprotocol, extensions);
    return pending, true;
}

fn complete_ws_upgrade<B>(
    server:   HttpServer&,
    pending:  realtime::WsPendingUpgrade&,
    out_wire: B&,
) -> realtime::WebSocketSession, bool {
    guard pending.in_use && !pending.is_aborted else {
        return realtime::WebSocketSession { .. }, false;
    }

    let route_behavior = if pending.route_idx >= 0 && pending.route_idx < server.ws_routes.len as i32 {
        server.ws_routes[pending.route_idx as i64].behavior
    } else {
        realtime::WsBehavior { .. }
    };

    let has_subproto = route_behavior.subprotocol.len > 0
        && pending.subprotocol.len > 0
        && realtime::has_subprotocol_token(pending.subprotocol[..], route_behavior.subprotocol[..]);
    let subproto = if has_subproto {
        route_behavior.subprotocol[..]
    } else {
        ""
    };

    return server_internal::serialize_and_init_ws_upgrade(route_behavior, pending, subproto, out_wire);
}

fn complete_ws_upgrade<Req, B>(
    server:   HttpServer&,
    req:      const Req&,
    entry:    const WebSocketRoute&,
    wire_out: B&,
) -> bool {
    let subproto = entry.behavior.subprotocol[..];
    var ws_res = http::Response { .. };
    var sess, ok_upg = realtime::ws_upgrade_request(req, ws_res, subproto);
    guard ok_upg else { return false; }

    sess.max_payload_length = entry.behavior.max_payload_length;
    sess.max_backpressure = entry.behavior.max_backpressure;
    sess.close_on_backpressure_limit = entry.behavior.close_on_backpressure_limit;
    sess.idle_timeout_s = entry.behavior.idle_timeout_s;
    sess.max_lifetime_s = entry.behavior.max_lifetime_s;
    sess.send_pings_automatically = entry.behavior.send_pings_automatically;
    sess.reset_idle_timeout_on_send = entry.behavior.reset_idle_timeout_on_send;
    server_internal::negotiate_ws_route_compression(req, ws_res, sess, entry.behavior.compression);
    serialize_http1_response(
        ws_res, server.server_name[..], wire_out, 0, server_internal::resolve_server_header_policy(server),
    );
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    return true;
}

// Returns true if `peer_ip` matches at least one configured `proxy_protocol_trusted_cidrs`
// entry (fail-closed when empty).
fn is_trusted_proxy_protocol_peer(server: const HttpServer&, peer_ip: const u8[:]) -> bool {
    return server_internal::is_ip_in_cidr_list(peer_ip, server.proxy_protocol_trusted_cidrs);
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
        guard is_trusted_proxy_protocol_peer(server, effective_ip[..]) else {
            serialize_bad_request_error(server.server_name[..], wire_out);
            return PipelineOutcome.Handled, false;
        }
        let stripped, ok_proxy = server_internal::strip_required_proxy_preface(server, wire_in, effective_ip, wire_out);
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
        let pref_len = server_internal::prepare_h2_server_preface(sess, server, raw_stream, wire_out);
        let _, ok_h2 = server_internal::handle_h2_server_ingress(
            sess, server.pipeline, server.timer, effective_ip[..], raw_stream[pref_len..], now_ms, wire_out, stage,
        );
        if ok_h2 {
            server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
            return PipelineOutcome.Handled, true;
        }
        return PipelineOutcome.Handled, false;
    }

    let is_fast = server_internal::try_prepare_single_h1_wire_turn(server, raw_stream);
    if !is_fast {
        var req = http::new_request("GET", "");
        var res = http::Response { .. };
        return server_internal::execute_single_h1_wire_turn(
            server, effective_ip[..], raw_stream, now_ns, req, res, wire_out, stage,
        );
    }
    let fast_outcome = server_internal::finish_single_h1_wire_turn(
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

inline fn reset_server_request_fast(req: http::Request&) {
    req.method.clear();
    req.url.clear();
    req.trailers.clear();
    req.query_params.clear();
    req.body.clear();
    req.is_http10 = false;
}

// Extended server request context holding long header token arena (RFC 9112 Section 2.1).
struct ServerRequest {
    raw_header_arena: u8[..8192]    = [],
    req:              http::Request = http::Request { .. },
}

inline fn reset_server_request(sreq: ServerRequest&) {
    reset_server_request_fast(sreq.req);
    sreq.raw_header_arena.clear();
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
    var total_handled:    i64  = 0;
    var total_consumed:   i64  = 0;
    var conn_wants_close: bool = false;

    if server_internal::can_try_fast_l0_static(server, stage) {
        let _, fast_done = server_internal::drain_fast_l0_static_stream(
            server, wire_in, now_ns, wire_out, total_handled, total_consumed, conn_wants_close,
        );
        if fast_done {
            return total_handled, total_consumed, true, conn_wants_close;
        }
    }

    let rem_off = min(total_consumed, wire_in.len);
    var has_fast_req = false;
    let is_fast = server_internal::try_prepare_single_pipeline_turn(
        server, wire_in[rem_off..], wire_out, total_consumed, has_fast_req,
    );
    var local_ip: u8[..64] = [];
    let _ = local_ip.try_set(client_ip[..min(client_ip.len, 64)]);
    if !is_fast {
        var req = http::new_request("GET", "");
        var res = http::Response { .. };
        let ok = server_internal::drain_pipelined_stream_turns(
            server, local_ip[..], wire_in[rem_off..], wire_in_len, now_ns,
            req, res, wire_out,
            total_handled, total_consumed, conn_wants_close, stage,
        );
        return total_handled, total_consumed, ok, conn_wants_close;
    }
    if has_fast_req {
        server_internal::finish_single_pipeline_turn(
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
        return server_internal::handle_h2_pipe_ingress(
            server, client_ip, pipe, h2_sess, now_ns, unread_len, wire_out, stage,
        );
    }

    // Sliced H2 preface: wait for the remaining bytes instead of parsing as HTTP/1.1
    if pipe.consumed == 0 && is_partial_h2_client_preface(pipe.readable_slice()) {
        return 0, true;
    }

    // Check for HTTP/2 connection preface if at the very start of the stream
    if pipe.consumed == 0 && unread_len >= 24 && is_h2_client_preface(pipe.readable_slice()) {
        return server_internal::handle_h2_pipe_ingress(
            server, client_ip, pipe, h2_sess, now_ns, unread_len, wire_out, stage,
        );
    }

    if pipe.consumed == 0 && server_internal::is_invalid_connection_preface(pipe.readable_slice()) {
        return 0, false;
    }

    var req = http::new_request("GET", "");
    var res = http::Response { .. };

    while pipe.readable_len() > 0 {
        let res_step = server_internal::process_pipelined_pipe_step(
            server, client_ip, pipe, req, res, now_ns, total_handled, wire_out, stage,
        );
        if res_step == server_internal::PipeStepResult.Error {
            return total_handled, false;
        } else if res_step == server_internal::PipeStepResult.Stop {
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
    max_streams: u32 = 0,
) -> i64 {
    return alloc_reactor_h2_session(pipeline, server_name, div_euclid(now_ns, 1000000), max_streams);
}

fn handle_connection_pipe_with_stage<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> i64, bool {
    let h2_idx = alloc_temp_h2_session(
        server.pipeline, server.server_name[..], now_ns, server.max_h2_concurrent_streams,
    );
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
    req:        const http::Request&,
    now_ns:     u64,
    res:        http::Response&,
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

// Probes buffered HTTP/1.1 wire bytes after `\r\n\r\n` (`hdr_end`) to check if the full request body has arrived.
// Returns true immediately on header parse errors or smuggling conflicts so the main parser emits 400 Bad Request.
fn is_http1_request_ready(in_buf: const u8[:], hdr_end: i64) -> bool {
    let body_start = core::add_sat_i64(hdr_end, 4);
    var tracker = http::HeaderPresenceTracker { .. };
    var parsed_start: i64 = 0;
    var probe_req = http::Request { .. };
    guard server_internal::parse_http1_request_headers(in_buf, probe_req, tracker, parsed_start) else {
        return true;
    }
    let has_te = (tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (tracker.mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0;
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
            let csize, err = http::read_chunk_size_line(chunk_slice, cur);
            if err == http::ChunkedDecodeError.UnexpectedEof { return false; }
            guard err == http::ChunkedDecodeError.None && csize <= (MAX_SERVER_BODY_LIMIT as u64) else { return true; }
            if csize == 0 {
                let tr_err = http::parse_chunked_trailers(chunk_slice, cur);
                return tr_err != http::ChunkedDecodeError.UnexpectedEof;
            }
            let sz_i = csize as i64;
            if cur + sz_i + 2 > chunk_slice.len { return false; }
            guard chunk_slice[cur + sz_i] == '\r' && chunk_slice[cur + sz_i + 1] == '\n' else { return true; }
            cur += sz_i + 2;
        }
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

// Dispatches a single parsed HTTP/1.1 request through `server` and `stage`, appends the response
// into `out_wire` for pipelined cork batching, and returns true if keep-alive should continue.
inline fn should_stop(server: const HttpServer&) -> bool {
    return !server.is_running || (server.honor_shutdown_flag && net::shutdown_requested());
}

inline fn init_run_state(server: HttpServer&) {
    if server.handle_os_signals {
        let _ = net::install_shutdown_signals();
    }
    server.is_running = true;
}

// Checks whether `in_buf` contains a complete HTTP/1.1 request ready for dispatch (when not an H2 preface).
inline fn has_ready_http1_request(in_buf: const u8[:], hdr_scan_cursor: i64&) -> bool {
    guard !is_partial_h2_client_preface(in_buf) && !is_h2_client_preface(in_buf) else { return false; }
    guard !server_internal::is_invalid_connection_preface(in_buf) else { return false; }
    let hdr_end = server_internal::scan_crlfcrlf_incremental(in_buf, hdr_scan_cursor);
    guard hdr_end >= 0 else { return false; }
    return is_http1_request_ready(in_buf, hdr_end);
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
        net::tcp_get_peer_ip(conn_fd, peer_ip);
    } else {
        let _ = peer_ip.try_set("127.0.0.1");
    }
    let poll_ms: u32 = min(max(recv_timeout_ms, 1), 100);

    loop {
        if server_internal::is_http1_ingress_ready_or_over_limit(server, in_buf[..]) {
            idle_ticks = 0;
            if server_internal::process_ready_http1_connection_buf(
                conn_fd, server, peer_ip[..], stage, in_buf, ws_frag_buf, out_wire,
            ) {
                server.pipeline.hdr_scan_cursor = 0;
                continue;
            }
            server_internal::flush_http1_cork_buf(conn_fd, out_wire);
            break;
        }
        server_internal::flush_http1_cork_buf(conn_fd, out_wire);
        if !server_internal::poll_http_connection_ingress_buf(
            listener_fd, conn_fd, server, in_buf, poll_ms, recv_timeout_ms, idle_ticks,
        ) {
            break;
        }
    }
    server_internal::flush_http1_cork_buf(conn_fd, out_wire);
    return server.is_running;
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
    init_run_state(server);
    var accepted: i64 = 0;
    let conn_cap: i64 = max(server.max_connections, 0);
    while !should_stop(server) && (conn_cap == 0 || accepted < conn_cap) {
        let conn = net::tcp_accept(listener_fd, 200);
        if conn <= 0 {
            continue;
        }
        let _ = net::tcp_set_nodelay(conn, server.tcp_nodelay);
        let _ = serve_http_connection_on_listener_buf(
            listener_fd, conn, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms,
        );
        net::tcp_close(conn);
        accepted = core::add_sat_i64(accepted, 1);
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
    return net::tcp_listen_unix(path, backlog);
}

// Adopts an externally accepted or inherited socket descriptor into the server environment
// (uWebSockets us_adopt_accepted_socket pattern).
fn adopt_socket(server: HttpServer&, raw_fd: i64) -> i64 {
    return net::adopt_socket(raw_fd);
}

// Executes a live TCP accept and dispatch loop with a custom `<Stage>` hook.
fn serve_with_stage<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    stage:           Stage&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    let eff_max = server_internal::resolve_accept_conn_limit(server, max_connections);

    var ring = core::PageRingBuffer { .. };
    let ok_ring = ring.page_ring_init(65536);
    if ok_ring {
        defer ring.page_ring_close();
        return server_internal::serve_page_ring_loop(server, listener_fd, eff_max, ring, stage);
    }

    return server_internal::serve_pipe_loop(server, listener_fd, eff_max, stage);
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
    let recvd = tls::transport_recv_slice(fd, slot_idx, span, timeout_ms);
    if recvd > 0 { pipe.commit_write(recvd); }
    return recvd;
}

fn tls_flush_cork(fd: i64, slot_idx: u16, cork: core::CorkBuffer&) -> i32 {
    let slice = cork.cork_as_slice();
    guard slice.len > 0 else { return 0; }
    let sent = tls::transport_send(fd, slot_idx, slice);
    cork.cork_reset();
    return sent;
}

// Configures pluggable TLS backend settings on `srv` without partial mutation on error.
fn configure_server_tls_backend(
    srv:      HttpServer&,
    kind:     tls::TlsBackendKind,
    min_ver:  tls::TlsMinVersion = tls::TlsMinVersion.Tls13,
    cert_pem: const u8[:]        = "",
    key_pem:  const u8[:]        = "",
) -> bool {
    guard cert_pem.len <= srv.tls_cert_pem_file.cap && key_pem.len <= srv.tls_key_pem_file.cap else {
        return false;
    }
    guard (cert_pem.len == 0) == (key_pem.len == 0) else {
        return false;
    }
    var cert_buf: u8[..256] = [];
    var key_buf:  u8[..256] = [];
    guard cert_buf.try_set(cert_pem) && key_buf.try_set(key_pem) else {
        return false;
    }
    srv.tls_backend = kind;
    srv.tls_min_version = min_ver;
    srv.tls_cert_pem_file = cert_buf;
    srv.tls_key_pem_file = key_buf;
    return true;
}

// Configures server-side mutual TLS (mTLS) verification on `srv` transactionally.
// Rejects oversize CA paths or an empty CA path when `require_client_cert` is true.
fn configure_server_mtls(
    srv:                 HttpServer&,
    ca_pem_file:         const u8[:],
    require_client_cert: bool = true,
) -> bool {
    guard ca_pem_file.len <= srv.tls_ca_file.cap else { return false; }
    guard !require_client_cert || ca_pem_file.len > 0 else { return false; }
    var ca_buf: u8[..256] = [];
    guard ca_buf.try_set(ca_pem_file) else { return false; }
    srv.tls_ca_file = ca_buf;
    srv.tls_require_client_cert = require_client_cert;
    return true;
}

// Configures default RFC 7301 length-prefixed ALPN wire protocol list on `srv` transactionally.
// Pass an empty slice to revert to the default `h2` + `http/1.1` preference list.
fn set_server_tls_alpn(srv: HttpServer&, alpn_wire: const u8[:]) -> bool {
    guard alpn_wire.len <= srv.tls_alpn_wire.cap && server_internal::is_valid_alpn_wire(alpn_wire) else {
        return false;
    }
    var alpn_buf: u8[..64] = [];
    guard alpn_buf.try_set(alpn_wire) else { return false; }
    srv.tls_alpn_wire = alpn_buf;
    return true;
}

// Configures NSS SSLKEYLOGFILE output path for TLS handshakes on `srv` transactionally.
fn set_server_tls_keylog_file(srv: HttpServer&, path: const u8[:]) -> bool {
    guard path.len <= srv.tls_keylog_file.cap else { return false; }
    var log_buf: u8[..256] = [];
    guard log_buf.try_set(path) else { return false; }
    srv.tls_keylog_file = log_buf;
    return true;
}

// Configures idle, header read, body read, and TLS handshake timeouts on `srv`,
// synchronizing `srv.timer` and `srv.pipeline.deadline_ns`.
fn set_server_timeouts(
    srv:            HttpServer&,
    idle_ms:        u64,
    read_header_ms: u32,
    read_body_ms:   u32,
    tls_hs_ms:      u32 = 5000,
) {
    srv.idle_timeout_ms = idle_ms;
    srv.read_header_timeout_ms = read_header_ms;
    srv.read_body_timeout_ms = read_body_ms;
    srv.tls_handshake_timeout_ms = tls_hs_ms;
    let deadline_ns = core::mul_sat_u64(idle_ms, 1000000);
    if deadline_ns > 0 {
        srv.pipeline.deadline_ns = deadline_ns;
        srv.timer.half_deadline_ns = max(deadline_ns >> 1, 1);
    }
}

// Configures ingress DoS ceilings (header block bytes, body bytes, concurrent/accept connection cap,
// and HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS`) on `srv` and its pipeline.
fn set_server_limits(
    srv:              HttpServer&,
    max_header_bytes: i64,
    max_body_bytes:   i64,
    max_connections:  i32,
    max_h2_streams:   u32 = 100,
) {
    let eff_hdr = if max_header_bytes > 0 { max_header_bytes } else { 16384 };
    let eff_body = if max_body_bytes >= 0 { max_body_bytes } else { MAX_SERVER_BODY_LIMIT };
    let eff_conns = max(max_connections, 0);
    let eff_h2 = if max_h2_streams > 0 { max_h2_streams } else { 100 };
    srv.max_header_bytes = eff_hdr;
    srv.max_body_bytes = eff_body;
    srv.max_connections = eff_conns;
    srv.max_h2_concurrent_streams = eff_h2;
    srv.pipeline.max_header_bytes = eff_hdr;
    srv.pipeline.max_body_bytes = eff_body;
    srv.pipeline.max_h2_concurrent_streams = eff_h2;
}

// Configures automatic `Server` and `Date` header visibility on HTTP/1.1 wire responses.
fn set_server_header_visibility(srv: HttpServer&, policy: ServerHeaderPolicy) {
    match policy {
        Standard => {
            srv.omit_server_header = false;
            srv.omit_date_header = false;
        },
        OmitServer => {
            srv.omit_server_header = true;
            srv.omit_date_header = false;
        },
        OmitDate => {
            srv.omit_server_header = false;
            srv.omit_date_header = true;
        },
        OmitBoth => {
            srv.omit_server_header = true;
            srv.omit_date_header = true;
        },
    };
}

// Applies listening TCP socket tuning options (`listen_backlog`, `so_reuseport`, `tcp_nodelay`) on `srv`.
fn set_server_socket_options(srv: HttpServer&, opts: const ServerSocketOptions&) {
    srv.listen_backlog = if opts.listen_backlog > 0 { opts.listen_backlog } else { 128 };
    srv.so_reuseport = opts.so_reuseport;
    srv.tcp_nodelay = opts.tcp_nodelay;
}

// Opens a TCP listening socket bound to `srv.host:srv.port` applying backlog, SO_REUSEPORT, and TCP_NODELAY.
fn listen_http_server(srv: const HttpServer&) -> i64 {
    let backlog = if srv.listen_backlog > 0 { srv.listen_backlog } else { 128 };
    let fd = net::tcp_listen(srv.host[..], srv.port, backlog);
    guard fd > 0 else { return -1; }
    if srv.so_reuseport {
        let _ = net::tcp_set_reuseport(fd, true);
    }
    let _ = net::tcp_set_nodelay(fd, srv.tcp_nodelay);
    return fd;
}

// Performs a server-side TLS handshake over `client_fd` using `srv`'s configured TLS backend.
// Returns `(transport, negotiated_alpn, status)`; caller retains `client_fd` ownership on failure.
fn accept_tls_backend_connection(
    srv:        const HttpServer&,
    client_fd:  i64,
    alpn_wire:  const u8[:] = "",
    timeout_ms: u32         = 0,
) -> net::Transport, u8[..64], tls::TlsBackendStatus {
    var empty_alpn: u8[..64] = [];
    guard client_fd > 0 && alpn_wire.len <= 64 else {
        return net::Transport.Disconnected, empty_alpn, tls::TlsBackendStatus.Error;
    }
    var bcfg = tls::TlsBackendConfig {
        kind:        srv.tls_backend,
        min_version: srv.tls_min_version,
        is_server:   true,
        ..
    };
    let ok_cfg, cfg_err = server_internal::populate_server_tls_backend_config(srv, alpn_wire, bcfg);
    guard ok_cfg else {
        return net::Transport.Disconnected, empty_alpn, cfg_err;
    }
    let eff_timeout = if timeout_ms > 0 {
        timeout_ms
    } else if srv.tls_handshake_timeout_ms > 0 {
        srv.tls_handshake_timeout_ms
    } else {
        5000
    };
    let ep_slot, neg_alpn, st = tls::endpoint_server_handshake_fd(client_fd, bcfg, eff_timeout);
    guard st == tls::TlsBackendStatus.Ok && ep_slot >= 0 else {
        return net::Transport.Disconnected, neg_alpn, st;
    }
    return net::Transport.TlsBackend { fd: client_fd, endpoint_slot: ep_slot }, neg_alpn, tls::TlsBackendStatus.Ok;
}

// Executes a live TLS 1.3 HTTPS accept and dispatch loop using PipeBuffer and TLS record AEAD.
fn serve_tls(
    server:          HttpServer&,
    listener_fd:     i64,
    tls_config:      const tls::ServerHandshakeConfig&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;
    let eff_max = server_internal::resolve_accept_conn_limit(server, max_connections);
    init_run_state(server);

    while !should_stop(server) && (eff_max == 0 || total_served < eff_max) {
        let conn = net::tcp_accept(listener_fd, 200);
        if conn <= 0 { continue; }
        let _ = net::tcp_set_nodelay(conn, server.tcp_nodelay);

        let slot_idx, ok_hs = server_internal::server_accept_tls_handshake(server, conn, tls_config);
        if !ok_hs {
            net::tcp_close(conn);
            total_served = core::add_sat_i64(total_served, 1);
            continue;
        }
        defer tls::transport_close(conn, slot_idx);

        pipe.pipe_reset();
        cork.cork_reset();
        net::tcp_get_peer_ip(conn, peer_ip);
        let h2_idx = alloc_temp_h2_session(
            server.pipeline, server.server_name[..], 0, server.max_h2_concurrent_streams,
        );
        if h2_idx < 0 || h2_idx >= REACTOR_MAX_H2_SESSIONS {
            total_served = core::add_sat_i64(total_served, 1);
            continue;
        }
        defer free_reactor_h2_session(h2_idx as i16, server.pipeline);

        while !should_stop(server) {
            if !server_internal::step_tls_loop_conn(server, conn, slot_idx, peer_ip[..], pipe, cork, h2_idx) {
                break;
            }
        }
        total_served = core::add_sat_i64(total_served, 1);
    }
    server.is_running = false;
    return total_served;
}

fn handle_connection_page_ring_scratch<Stage, B>(
    server:     HttpServer&,
    client_ip:  const u8[:],
    ring:       core::PageRingBuffer&,
    now_ns:     u64,
    wire_out:   B&,
    peek_chunk: server_internal::ReactorIngressBuf&,
    stage:      Stage&,
) -> i64, bool {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    guard ring.count > 0 else { return 0, true; }

    server_internal::ensure_reactor_ingress_buf(peek_chunk);
    peek_chunk.len = 0;
    let peek_n = ring.page_ring_peek(peek_chunk.bytes[..]);
    guard peek_n > 0 else { return 0, true; }
    let peek_slice = peek_chunk.bytes[..peek_n];

    if is_partial_h2_client_preface(peek_slice) || is_h2_client_preface(peek_slice) {
        var h2_done = false;
        var h2_ok = true;
        let h2_cnt = server_internal::handle_page_ring_h2_preface(
            server, client_ip, ring, peek_slice, now_ns, wire_out, h2_done, h2_ok, stage,
        );
        return h2_cnt, h2_ok;
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

fn handle_connection_page_ring<Stage, B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    ring:      core::PageRingBuffer&,
    now_ns:    u64,
    wire_out:  B&,
    stage:     Stage&,
) -> i64, bool {
    var peek_chunk = server_internal::ReactorIngressBuf { .. };
    return handle_connection_page_ring_scratch(
        server, client_ip, ring, now_ns, wire_out, peek_chunk, stage,
    );
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
    let eff_max = server_internal::resolve_accept_conn_limit(server, max_connections);
    var ring = core::PageRingBuffer { .. };
    let ok = ring.page_ring_init(65536);
    guard ok else { return 0; }
    defer ring.page_ring_close();
    return server_internal::serve_page_ring_loop(server, listener_fd, eff_max, ring);
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
    committed = server_internal::verify_mmap_transfer_complete(offset, mf.size, prev_len, hdr_buf.len, wire_out.len);
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

    let sent_hdr = net_internal::native_tcp_send(sock_fd, hdr_buf[..]);
    guard sent_hdr == (hdr_buf.len as i32) else { return false; }

    guard mf.size > 0 else { return true; }
    let sent_body, body_ok = mf.mmap_file_send(0, mf.size as u32, sock_fd);
    return body_ok && (sent_body as u64) == mf.size;
}
