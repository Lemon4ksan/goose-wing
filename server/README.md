# `server`

Package `server` (`namespace server;`) implements HTTP/1.1, HTTP/2, HTTP/3,
WebSocket, and Server-Sent Events (SSE) servers in `goose-wing` without heap
allocation.

Internal framing, connection pools, HTTP/2 multiplexing, and event-loop plumbing
live in `namespace server_internal;` across thematic `*_internal.goose` modules.

## Quick start

Create an `HttpServer`, register routes, open a listening socket, and start the
reactor loop:

```goose
import wing;

var srv = server::new_http_server("127.0.0.1", 8080);
server::add_static_get_route(srv, "/healthz", "text/plain", "ok");
server::add_get_route(srv, "/users/:id", 10);

let listener = server::reactor_listen_accelerated(srv);
guard listener > 0 else { return; }
let _ = server::serve_reactor(srv, listener);
```

For large benchmarks or stack-constrained threads, initialize an `HttpServer` in
place with `server::init_http_server_inplace(srv, "127.0.0.1", 8080)`.

## Task recipes

### HTTP/1.1, HTTP/2, and TLS 1.3 server

Configure timeouts, payload ceilings, socket flags, and a TLS backend before
listening. `serve_tls` and `serve_reactor_tls` negotiate `h2` and `http/1.1`
over ALPN and return `431` or `413` when headers or bodies exceed limits.

```goose
var srv = server::new_http_server("0.0.0.0", 8443);
server::set_server_timeouts(srv, 30000, 5000, 15000, 5000);
server::set_server_limits(srv, 16384, 1048576, 4096, 100);
server::set_server_header_visibility(srv, server::ServerHeaderPolicy.OmitServer);
server::set_server_socket_options(srv, server::ServerSocketOptions {
    listen_backlog: 256,
    so_reuseport:   true,
    tcp_nodelay:    true,
});

let _ = server::configure_server_tls_backend(
    srv,
    tls::TlsBackendKind.PureGoose,
    tls::TlsMinVersion.Tls13,
    "cert.pem",
    "key.pem",
);
let _ = server::set_server_tls_alpn(srv, "\x02h2\x08http/1.1");

let listener = server::listen_http_server(srv);
let _ = server::serve_tls(srv, listener, tls_cfg);
```

### Routing and middleware pipeline

Register static or parameterized routes (`:id`, `{id}`, `*filepath`) on
`srv.pipeline.router` or group them under a shared prefix. Implement
`server::on_server_stage` on a user stage struct to run hooks at `PreRoute`,
`PostAuth`, `RouteHandler`, `ResumeHandler`, `PreSerialize`, `AfterResponse`,
and `OnError`.

```goose
struct ApiStage {}

fn on_server_stage(
    stage: ApiStage&,
    phase: wire::ServerHookPhase,
    cfg:   server::ServerPipelineConfig&,
    req:   const http::Request&,
    ctx:   server::ServerStageCtx&,
    res:   http::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.RouteHandler else {
        return wire::StageVerdict.Continue;
    }
    if ctx.handler_id == 10 {
        let user_id = server::route_param_or(cfg, ctx, req.url[..], "id", "0");
        res.status_code = 200;
        http::set_header(res, "Content-Type", "text/plain");
        let _ = res.body.try_set(user_id);
    }
    return wire::StageVerdict.Continue;
}

var srv = server::new_http_server("127.0.0.1", 8080);
let api = server::make_route_group("/api/v1");
let _ = server::add_group_route(srv.pipeline.router, api, "GET", "/users/:id", 10);
var stage = ApiStage {};
let _ = server::serve_reactor_with_stage(srv, listener, stage);
```

### WebSocket and SSE handlers

Register WebSocket routes with `add_ws_route` and broadcast frames across
MQTT-style topic wildcards (`+` and `#`) using `subscribe` and `publish_text`.
For Server-Sent Events over HTTP/1.1 chunked encoding, stream events through
`ServerCork`.

```goose
// WebSocket route and topic pub/sub
let _ = server::add_ws_route(srv, "/chat", realtime::WsBehavior { handler_id: 20, .. });
let _ = server::subscribe(srv, client_fd, "rooms/+/messages");
let _ = server::publish_text(srv, "rooms/general/messages", "hello");

// Server-Sent Events over HTTP/1.1 chunked transfer
var cork = server::new_server_cork(client_fd);
var res = server::init_text_stream_response();
let _ = server::cork_begin_http1_chunked(cork, res, "goose-wing");
let _ = server::cork_write_sse_chunk(cork, "hello", "message", "1");
let _ = server::cork_end_http1_chunked(cork);
```

### Streaming responses and graceful shutdown

Use `ResponseStream` to send bodies larger than 16 KB with explicit flow-control
backpressure across HTTP/1.1, HTTP/2, and HTTP/3. Check `should_stop` after
`init_run_state` to exit cleanly on `SIGINT` or `SIGTERM`.

```goose
var stream = server::make_http2_response_stream(stream_id, 65535, 65535, 16384, sock_fd);
var res = http::Response { status_code: 200, .. };
http::set_header(res, "Content-Type", "application/octet-stream");
let _ = server::stream_begin(stream, res);

let written, st = server::stream_write(stream, payload);
if st == server::StreamWriteStatus.WouldBlock {
    server::stream_on_window_update(stream, conn_delta, stream_delta);
}
let _ = server::stream_end(stream);

// Graceful shutdown in a custom loop
server::init_run_state(srv);
while !server::should_stop(srv) {
    // serve connections or step async_reactor_step(...)
}
```

### Edge filtering, caching, and SNI

Attach L7 prefix/header rules to `srv.pipeline.edge_filter`, configure
stale-while-revalidate caching in `srv.pipeline.route_cache`, and register exact
or wildcard TLS certificates (`*.example.com`) with `add_server_name`.

```goose
let block_admin = server::make_edge_filter_rule(
    "block-admin",
    "/admin",
    server::EdgeFilterVerdict.BlockForbidden,
);
let _ = server::add_edge_filter_rule(srv.pipeline.edge_filter, block_admin);

srv.pipeline.route_cache = server::new_http_route_cache(1000, 5000);
let _ = server::cache_store(srv.pipeline.route_cache, now_ms, body, 10, "application/json", "/items");

let _ = server::add_server_name(srv, "*.example.com", cert_pem, key_pem);
let creds, found = server::resolve_sni_credentials(srv, "api.example.com");
```

## Public API reference

### 1. Server lifecycle, limits, and TLS (`server/server.goose`)

Constructs and configures `HttpServer`, applies timeouts, payload limits,
TLS/mTLS policies, and runs synchronous or Sans-IO serving entrypoints.

```goose
struct HttpServer { ... }
enum ServerHeaderPolicy { Standard, OmitServer, OmitDate, OmitBoth }
enum H1WireParseStatus { Ok, Incomplete, BadRequest, HeadersTooLarge, ContentTooLarge }
struct ServerSocketOptions {
    listen_backlog: i32 = 128, so_reuseport: bool = false, tcp_nodelay: bool = true
}

fn new_http_server(host_str: const u8[:] = "127.0.0.1", port_num: u16 = 8080) -> HttpServer
fn init_http_server_inplace(server: HttpServer&, host_str: const u8[:] = "127.0.0.1", port_num: u16 = 8080)
fn new_http_server_with_quota<Q>(host_str: const u8[:], port_num: u16, quota: Q) -> HttpServer
fn set_header_memoization(server: HttpServer&, enabled: bool)
fn set_server_timeouts(srv: HttpServer&, idle_ms: u64, read_header_ms: u32, read_body_ms: u32, tls_hs_ms: u32 = 5000)
fn set_server_limits(srv: HttpServer&, max_header_bytes: i64, max_body_bytes: i64, max_connections: i32, max_h2_streams: u32 = 100)
fn set_server_header_visibility(srv: HttpServer&, policy: ServerHeaderPolicy)
fn set_server_socket_options(srv: HttpServer&, opts: const ServerSocketOptions&)
fn configure_server_tls_backend(srv: HttpServer&, kind: tls::TlsBackendKind, min_ver: tls::TlsMinVersion = tls::TlsMinVersion.Tls13, cert_pem: const u8[:] = "", key_pem: const u8[:] = "") -> bool
fn configure_server_mtls(srv: HttpServer&, ca_pem_file: const u8[:], require_client_cert: bool = true) -> bool
fn set_server_tls_alpn(srv: HttpServer&, alpn_wire: const u8[:]) -> bool
fn set_server_tls_keylog_file(srv: HttpServer&, path: const u8[:]) -> bool
fn listen_http_server(srv: const HttpServer&) -> i64
fn listen_unix(server: HttpServer&, path: const u8[:], backlog: i32 = 128) -> i64
fn adopt_socket(server: HttpServer&, raw_fd: i64) -> i64
fn init_run_state(server: HttpServer&)
fn should_stop(server: const HttpServer&) -> bool
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64
fn serve_with_stage<Stage>(server: HttpServer&, listener_fd: i64, stage: Stage&, max_connections: i64 = 0) -> i64
fn serve_tls(server: HttpServer&, listener_fd: i64, tls_config: const tls::ServerHandshakeConfig&, max_connections: i64 = 0) -> i64
fn accept_tls_backend_connection(srv: const HttpServer&, client_fd: i64, alpn_wire: const u8[:] = "", timeout_ms: u32 = 0) -> net::Transport, u8[..64], tls::TlsBackendStatus
fn handle_connection_wire<B>(server: HttpServer&, client_ip: const u8[:], wire_in: const u8[:], now_ns: u64, wire_out: B&) -> PipelineOutcome, bool
fn serve_static_mmap_file<B>(filepath: const u8[:], content_type: const u8[:], server_name: const u8[:], wire_out: B&) -> bool
```

### 2. Reactors, async host loop, and HTTP/3 (`server/reactor.goose`, `server/async_reactor.goose`, `server/soa_timer.goose`)

Drives non-blocking OS event loops (`io_uring`, RIO, `kqueue`, `epoll`),
inversion-of-control `AsyncServerReactor` loops, 4096-slot `SoAConnTable`
timers, and HTTP/3 UDP/L2 endpoints.

```goose
root struct AsyncServerReactor { ... }
root struct SoAConnTable { ... }
enum H3L2Backend { UdpFallback, AfXdp, Dpdk }
struct H3L2Config { ... }
struct H3ServerEndpoint { ... }

fn reactor_listen_accelerated(server: const HttpServer&, backlog: i32 = 0) -> i64
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64
fn serve_reactor_with_stage<Stage>(server: HttpServer&, listener_fd: i64, stage: Stage&, max_connections: i64 = 0) -> i64
fn serve_reactor_tls(server: HttpServer&, listener_fd: i64, tls_config: const tls::ServerHandshakeConfig&, max_connections: i64 = 0) -> i64
fn serve_reactor_tls_with_stage<Stage>(server: HttpServer&, listener_fd: i64, tls_config: const tls::ServerHandshakeConfig&, stage: Stage&, max_connections: i64 = 0) -> i64
fn async_reactor_listen_http(host: net::Host&, reactor: AsyncServerReactor&, addr: core::ConnectAddr, backlog: i32 = 128) -> bool
fn async_reactor_step<App>(host: net::Host&, server: HttpServer&, reactor: AsyncServerReactor&, app: App&, timeout_ms: i64, now_ns: u64) -> i32
fn serve_reactor_with_app<App>(host: net::Host&, server: HttpServer&, reactor: AsyncServerReactor&, addr: core::ConnectAddr, app: App&, backlog: i32 = 128, max_iters: i64 = 0, poll_timeout_ms: i64 = 10) -> bool
fn serve_reactor_with_io<Stage, Driver>(host: net::Host&, server: HttpServer&, reactor: AsyncServerReactor&, addr: core::ConnectAddr, stage: Stage, driver: Driver, backlog: i32 = 128, max_iters: i64 = 0, poll_timeout_ms: i64 = 10) -> bool
fn new_h3_server_endpoint(settings: http3::Settings = http3::Settings { .. }) -> H3ServerEndpoint
fn handle_h3_quic_datagram<B>(server: HttpServer&, ep: H3ServerEndpoint&, client_ip: const u8[:], datagram: const u8[:], now_ns: u64, out_wire: B&) -> bool
fn serve_h3(server: HttpServer&, udp_fd: i64, max_datagrams: i64 = 1) -> i64
fn serve_h3_l2(server: HttpServer&, ep: H3ServerEndpoint&, cfg: const H3L2Config&, xsk: net_internal::AfXdpSocket&, max_packets: i64 = 64) -> i64
fn soa_table_alloc(table: SoAConnTable&, fd: i64, timeout_tick: u8) -> i64
fn soa_table_free(table: SoAConnTable&, slot: i64)
fn soa_table_touch(table: SoAConnTable&, slot: i64, new_tick: u8)
fn soa_table_sweep_expired(table: SoAConnTable&, wheel: const core::TickTimerWheel&, out_expired: i64[:]) -> i64
```

### 3. Routing and route groups (`server/router.goose`, `server/server.goose`)

Matches static paths in an L0 register table and dynamic `:param` or `*wildcard`
paths in a method-segregated radix trie.

```goose
struct RadixRouter { ... }
struct RouteGroup { ... }
enum RouteMatchResult {
    Found { handler_id: i32, entries_mask: u32, pso_mask: u64, ingress_mask: u64, egress_mask: u64 },
    NotFound,
    MethodNotAllowed { allow_header: u8[..64] }
}

fn new_radix_router() -> RadixRouter
fn add_route(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, entries_mask: u32 = 0, pso_mask: u64 = DEFAULT_ROUTE_PSO_MASK) -> bool
fn add_route_pso(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, pso_mask: u64) -> bool
fn add_static_route(router: RadixRouter&, method: const u8[:], path: const u8[:], content_type: const u8[:], body: const u8[:], handler_id: i32 = 0) -> bool
fn add_get_route(server: HttpServer&, path: const u8[:], handler_id: i32)
fn add_static_get_route(server: HttpServer&, path: const u8[:], content_type: const u8[:], body: const u8[:], handler_id: i32 = 0)
fn add_post_route(server: HttpServer&, path: const u8[:], handler_id: i32)
fn add_put_route(server: HttpServer&, path: const u8[:], handler_id: i32)
fn add_delete_route(server: HttpServer&, path: const u8[:], handler_id: i32)
fn make_route_group(prefix: const u8[:], pso_mask: u64 = DEFAULT_ROUTE_PSO_MASK, ingress_mask: u64 = wire::STAGE_SRV_IN_DEFAULT_MASK, egress_mask: u64 = wire::STAGE_SRV_OUT_DEFAULT_MASK) -> RouteGroup
fn add_group_route(router: RadixRouter&, group: const RouteGroup&, method: const u8[:], sub_path: const u8[:], handler_id: i32) -> bool
fn match_route(router: const RadixRouter&, method: const u8[:], path: const u8[:], params: http::ZeroAllocParams&) -> RouteMatchResult
```

### 4. Middleware pipeline and request context (`server/pipeline.goose`)

Configures per-route security and middleware stages, extracts typed request
context values, and supports async request suspension and resumption.

```goose
enum PipelineOutcome {
    Handled, Pending, RateLimited, CsrfRejected, CorsPreflight,
    MethodNotAllowed, RouteNotFound, SlowlorisClosed, ExpectationFailed
}
struct ServerPipelineConfig { ... }
struct ServerStageCtx { ... }

fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig
fn configure_tier_limiter(cfg: ServerPipelineConfig&, tier_idx: u8, quota: security::GcraQuota) -> bool
fn route_param(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&, url: const u8[:], name: const u8[:]) -> const u8[:], bool
fn route_param_or(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&, url: const u8[:], name: const u8[:], fallback: const u8[:]) -> const u8[:]
fn peer_ip(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const u8[:]
fn auth_subject(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const u8[:]
fn auth_claims(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const auth::JwtClaims&, bool
fn session_data(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const u8[:]
fn suspend_server_request(sctx: ServerStageCtx&) -> bool
fn on_server_stage<First, Next>(chain: wire::StageChain<First, Next>&, phase: wire::ServerHookPhase, cfg: ServerPipelineConfig&, req: const http::Request&, ctx: ServerStageCtx&, res: http::Response&) -> wire::StageVerdict
fn on_server_body_chunk<First, Next>(chain: wire::StageChain<First, Next>&, cfg: ServerPipelineConfig&, req: const http::Request&, ctx: ServerStageCtx&, chunk: const u8[:], is_last: bool, res: http::Response&) -> wire::StageVerdict
fn execute_pipeline(cfg: ServerPipelineConfig&, conn_timer: server_internal::ConnectionTimer&, client_ip: const u8[:], req: const http::Request&, now_ns: u64, res: http::Response&, out_future: server_internal::InlineHandlerFuture&) -> PipelineOutcome
fn execute_server_pipeline_with_stage<UserStage>(cfg: ServerPipelineConfig&, conn_timer: server_internal::ConnectionTimer&, client_ip: const u8[:], req: const http::Request&, now_ns: u64, res: http::Response&, out_future: server_internal::InlineHandlerFuture&, user_stage: UserStage&) -> PipelineOutcome
fn resume_server_pipeline_egress<UserStage>(cfg: ServerPipelineConfig&, req: const http::Request&, now_ns: u64, sctx: ServerStageCtx&, res: http::Response&, user_stage: UserStage&) -> PipelineOutcome
```

### 5. WebSocket pub/sub and SSE corking (`server/server.goose`, `server/cork.goose`)

Manages WebSocket route registration, deferred upgrades, wildcard pub/sub
routing, and 16 KB corked chunked/SSE output.

```goose
struct ServerCork { ... }

fn add_ws_route(server: HttpServer&, path: const u8[:], behavior: const realtime::WsBehavior& = realtime::WsBehavior { .. }) -> bool
fn defer_ws_upgrade(req: const http::Request&, client_ip: const u8[:], fd: i64, now_ns: u64) -> realtime::WsUpgradeContext, bool
fn complete_ws_upgrade<B>(ctx: const realtime::WsUpgradeContext&, out_wire: B&, selected_subprotocol: const u8[:] = "", negotiate_deflate: bool = false) -> bool
fn subscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool
fn unsubscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool
fn unsubscribe_all(server: HttpServer&, sock_fd: i64) -> i32
fn publish(server: HttpServer&, topic: const u8[:], message: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64
fn publish_text(server: HttpServer&, topic: const u8[:], text: const u8[:]) -> i64
fn publish_binary(server: HttpServer&, topic: const u8[:], data: const u8[:]) -> i64
fn find_subscribers(server: const HttpServer&, topic: const u8[:], out_fds: i64[..512]&) -> i64
fn new_server_cork(fd: i64) -> ServerCork
fn init_text_stream_response(status_code: i32 = 200) -> http::Response
fn cork_begin_http1_chunked(sc: ServerCork&, res: const http::Response&, server_name: const u8[:] = "goose-wing") -> i32
fn cork_write_http1_chunk(sc: ServerCork&, chunk: const u8[:]) -> i32
fn cork_write_sse_chunk(sc: ServerCork&, data: const u8[:], event: const u8[:] = "", id: const u8[:] = "", retry_ms: i32 = -1, include_id: bool = false) -> i32
fn cork_end_http1_chunked(sc: ServerCork&) -> i32
```

### 6. Streaming responses and flow control (`server/stream.goose`, `server/stream_consumer.goose`)

Streams unbounded response bodies and request-body pull windows with uniform
backpressure across HTTP/1.1, HTTP/2, and HTTP/3.

```goose
enum StreamProtocol { Http1, Http2, Http3 }
enum StreamWriteStatus { Ok, WouldBlock, Closed, Error }
struct ResponseStream { ... }
enum WindowProtocol { Http1, Http2, Http3 }
struct WindowReplenishment { ... }
struct RequestStreamWindow { ... }

fn make_http1_response_stream(sock_fd: i64 = -1, server_name: const u8[:] = "goose-wing") -> ResponseStream
fn make_http2_response_stream(stream_id: u32, conn_window: i64 = 65535, stream_window: i64 = 65535, max_frame_size: u32 = 16384, sock_fd: i64 = -1, server_name: const u8[:] = "goose-wing") -> ResponseStream
fn make_http3_response_stream(stream_id: u64, conn_credit: u64 = 65536, stream_credit: u64 = 65536, sock_fd: i64 = -1, server_name: const u8[:] = "goose-wing") -> ResponseStream
fn stream_begin(stream: ResponseStream&, res: http::Response&) -> StreamWriteStatus
fn stream_write(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus
fn stream_flush(stream: ResponseStream&) -> StreamWriteStatus
fn stream_end(stream: ResponseStream&) -> StreamWriteStatus
fn stream_drain_wire(stream: ResponseStream&, dst: u8[:]) -> i64
fn stream_on_window_update(stream: ResponseStream&, conn_delta: i64, stream_delta: i64)
fn stream_on_quic_max_data(stream: ResponseStream&, new_max_data: u64, new_max_stream_data: u64)
fn stream_can_write(stream: const ResponseStream&) -> i64
fn make_request_stream_window(protocol: WindowProtocol, stream_id: u64, stream_window: u64 = 65536, conn_window: u64 = 65536, update_threshold_pct: u32 = 50) -> RequestStreamWindow
fn request_window_on_ingress(win: RequestStreamWindow&, received_bytes: u64) -> bool
fn request_window_available(win: const RequestStreamWindow&) -> u64
fn request_window_on_consume(win: RequestStreamWindow&, consumed_bytes: u64) -> WindowReplenishment
fn request_window_encode_h2_updates<B>(win: const RequestStreamWindow&, rep: const WindowReplenishment&, out: B&) -> bool
fn request_window_encode_quic_updates<B>(win: const RequestStreamWindow&, rep: const WindowReplenishment&, out: B&) -> bool
```

### 7. Edge filtering, route caching, and SNI (`server/edge_filter.goose`, `server/cache.goose`, `server/sni.goose`)

Inspects requests before routing, caches pre-serialized responses with
stale-while-revalidate windows, and resolves multi-domain TLS certificates.

```goose
enum EdgeFilterVerdict { Pass, BlockForbidden, ThrottleRate, DropConnection }
struct EdgeFilterRule { ... }
struct EdgeFilter { ... }
enum CacheLookup { HitFresh, HitStaleNeedsUpdate, Miss }
struct HttpRouteCache { ... }
struct SniRegistry { ... }
struct SniCredentials { cert_pem: const u8[:], key_pem: const u8[:] }

fn make_edge_filter_rule(name: const u8[:], path_prefix: const u8[:], verdict: EdgeFilterVerdict) -> EdgeFilterRule
fn add_edge_filter_rule(filter: EdgeFilter&, rule: EdgeFilterRule) -> bool
fn evaluate_edge_filter(filter: EdgeFilter&, method: const u8[:], path: const u8[:], headers: const http::HeaderMap&) -> EdgeFilterVerdict
fn new_http_route_cache(lower_ms: u64 = 1000, upper_ms: u64 = 5000) -> HttpRouteCache
fn cache_lookup(c: HttpRouteCache&, now_ms: u64, req_handler_id: i32 = -1, url_key: const u8[:] = "") -> CacheLookup
fn cache_store(c: HttpRouteCache&, now_ms: u64, data: const u8[:], handler_id: i32 = -1, content_type: const u8[:] = "", url_key: const u8[:] = "", etag: const u8[:] = "") -> bool
fn cache_invalidate(c: HttpRouteCache&)
fn add_server_name<S>(server: S&, pattern: const u8[:], cert_pem: const u8[:], key_pem: const u8[:]) -> bool
fn remove_server_name<S>(server: S&, pattern: const u8[:]) -> bool
fn resolve_sni_credentials<S>(server: const S&, hostname: const u8[:]) -> SniCredentials, bool
```
