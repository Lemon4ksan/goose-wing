# `server`

Package `server` (`namespace server;` for public APIs,
`namespace server_internal;` for internal pools, HTTP/2 multiplexing, and
protocol plumbing) implements the zero-allocation HTTP/1.1, HTTP/2, HTTP/3, and
WebSocket server engine of `goose-wing`, combining a two-tier L0 register and
Radix Tree router, a bitmask-driven security and caching pipeline, an L7 WAF
edge filter, and an event-loop reactor.

```goose
var srv = server::new_http_server("127.0.0.1", 8080);
server::add_static_route(srv.pipeline.router, "GET", "/healthz", "text/plain", "ok");
```

## Public API Reference

### 1. HTTP Server Lifecycle, TLS & Pub/Sub (`server/server.goose`)

```goose
// Public namespace: server
struct HttpServer {
    pipeline: ServerPipelineConfig, host: u8[..256], port: u16,
    server_name: u8[..64], timer: server_internal::ConnectionTimer,
    topic_tree: realtime::TopicTree, ws_routes: WsRouteEntry[..16],
    shared_compressor: realtime::SharedWsCompressor, sni_registry: SniRegistry,
    worker_ring: core::SpscRing, cached_date: CachedHttpDate,
    accel_mode: wing::ReactorAccelMode = wing::ReactorAccelMode.Auto,
    enable_header_memoization: bool = false,
    tls_backend: tls::TlsBackendKind = tls::TlsBackendKind.PureGoose,
    tls_min_version: tls::TlsMinVersion = tls::TlsMinVersion.Tls13,
    tls_cert_pem_file: u8[..256] = [], tls_key_pem_file: u8[..256] = [],
    tls_ca_file: u8[..256] = [], tls_require_client_cert: bool = false,
    tls_alpn_wire: u8[..64] = [], tls_keylog_file: u8[..256] = [],
    tls_handshake_timeout_ms: u32 = 5000, idle_timeout_ms: u64 = 30000,
    read_header_timeout_ms: u32 = 5000, read_body_timeout_ms: u32 = 15000,
    max_header_bytes: i64 = 16384, max_body_bytes: i64 = 10485760,
    max_connections: i32 = 0, max_h2_concurrent_streams: u32 = 100,
    omit_server_header: bool = false, omit_date_header: bool = false,
    so_reuseport: bool = false, listen_backlog: i32 = 128,
    tcp_nodelay: bool = true, ...
}
enum ServerHeaderPolicy { Standard, OmitServer, OmitDate, OmitBoth }
enum H1WireParseStatus { Ok, Incomplete, BadRequest, HeadersTooLarge, ContentTooLarge }
struct ServerSocketOptions {
    listen_backlog: i32 = 128, so_reuseport: bool = false, tcp_nodelay: bool = true
}
fn new_http_server(host_str: const u8[:] = "127.0.0.1", port_num: u16 = 8080) -> HttpServer
fn init_http_server_inplace(server: HttpServer&, host_str: const u8[:] = "127.0.0.1", port_num: u16 = 8080)
fn new_http_server_with_quota<Q>(host_str: const u8[:], port_num: u16, quota: Q) -> HttpServer
fn set_header_memoization(server: HttpServer&, enabled: bool)
fn init_run_state(server: HttpServer&)
fn should_stop(server: const HttpServer&) -> bool
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64
fn serve_with_stage<UserStage>(server: HttpServer&, listener_fd: i64, user_stage: UserStage&, max_connections: i64 = 0) -> i64
fn serve_tls(server: HttpServer&, listener_fd: i64, tls_cfg: const wing::TlsServerHandshakeConfig&, max_connections: i64 = 0) -> i64
fn configure_server_tls_backend(srv: HttpServer&, kind: tls::TlsBackendKind, min_ver: tls::TlsMinVersion = tls::TlsMinVersion.Tls13, cert_pem: const u8[:] = "", key_pem: const u8[:] = "") -> bool
fn configure_server_mtls(srv: HttpServer&, ca_pem_file: const u8[:], require_client_cert: bool = true) -> bool
fn set_server_tls_alpn(srv: HttpServer&, alpn_wire: const u8[:]) -> bool
fn set_server_tls_keylog_file(srv: HttpServer&, path: const u8[:]) -> bool
fn set_server_timeouts(srv: HttpServer&, idle_ms: u64, read_header_ms: u32, read_body_ms: u32, tls_hs_ms: u32 = 5000)
fn set_server_limits(srv: HttpServer&, max_header_bytes: i64, max_body_bytes: i64, max_connections: i32, max_h2_streams: u32 = 100)
fn set_server_header_visibility(srv: HttpServer&, policy: ServerHeaderPolicy)
fn set_server_socket_options(srv: HttpServer&, opts: const ServerSocketOptions&)
fn listen_http_server(srv: const HttpServer&) -> i64
fn accept_tls_backend_connection(srv: const HttpServer&, client_fd: i64, alpn_wire: const u8[:] = "", timeout_ms: u32 = 0) -> net::Transport, u8[..64], tls::TlsBackendStatus
fn parse_http1_wire_request_with_limits<Req>(wire: const u8[:], out_req: Req&, max_header_bytes: i64 = 16384, max_body_bytes: i64 = MAX_SERVER_BODY_LIMIT) -> H1WireParseStatus, i64
fn serialize_headers_too_large_error<B>(server_name: const u8[:], wire_out: B&, header_policy: ServerHeaderPolicy = ServerHeaderPolicy.Standard)
fn serialize_content_too_large_error<B>(server_name: const u8[:], wire_out: B&, header_policy: ServerHeaderPolicy = ServerHeaderPolicy.Standard)
fn handle_connection_wire<B>(server: HttpServer&, client_ip: const u8[:], wire_in: const u8[:], now_ns: u64, wire_out: B&) -> PipelineOutcome, bool
fn subscribe(server: HttpServer&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe(server: HttpServer&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe_all(server: HttpServer&, sock_fd: i64) -> i32
fn publish(server: HttpServer&, topic: const u8[:], payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64
fn publish_text(server: HttpServer&, topic: const u8[:], text: const u8[:]) -> i64
fn publish_binary(server: HttpServer&, topic: const u8[:], data: const u8[:]) -> i64
fn find_subscribers(server: const HttpServer&, topic: const u8[:], out_fds: i64[..512]&) -> i64
```

`HttpServer` combines synchronous serving loops (`serve`, `serve_with_stage`,
and TLS 1.3 `serve_tls` with `h2` / `http/1.1` ALPN and SNI certificate
selection), pluggable TLS backend controls (`configure_server_tls_backend`,
`configure_server_mtls`, `set_server_tls_alpn`, `set_server_tls_keylog_file`,
and `accept_tls_backend_connection`), operational limits and hygiene setters
(`set_server_timeouts`, `set_server_limits`, `set_server_header_visibility`,
`set_server_socket_options`, and `listen_http_server`), and a Sans-IO wire
processor (`handle_connection_wire`). Oversized HTTP/1.1 headers and payloads
exceeding `max_header_bytes` or `max_body_bytes` return `431 Request Header
Fields Too Large` or `413 Content Too Large`, respectively. By default,
`enable_header_memoization` is `false` so every HTTP/1.1 request executes full
64-bit SWAR header scanning without reusing cached Keep-Alive header blocks;
call `set_header_memoization(server, true)` to opt in to Keep-Alive header
memoization (`g_h1_parse_cache` and pipelined identical-request batching).
Routing and middleware state live inside `server.pipeline`
(`server.pipeline.router`, `server.pipeline.edge_filter`,
`server.pipeline.route_cache`). Built-in WebSocket pub/sub routes messages
across `server.topic_tree` using MQTT wildcard patterns (`+` and `#`),
collecting up to 512 matching socket descriptors (`i64[..512]`) in
`find_subscribers`.

### 2. Reactor Event Loop & HTTP/3 Server Endpoint (`server/reactor.goose`)

```goose
const REACTOR_MAX_H2_SESSIONS: i64 = 128;
enum H3L2Backend { UdpFallback, AfXdp, Dpdk }
struct H3L2Config {
    backend: H3L2Backend, local_ep: net_internal::L2UdpEndpoint,
    udp_fd: i64, dpdk_port_id: u16, dpdk_queue_id: u16
}
struct H3ServerEndpoint {
    conn: h3_internal::H3Connection
}
fn reactor_listen_accelerated(server: const HttpServer&, backlog: i32 = 0) -> i64
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_requests: i64 = 0) -> i64
fn serve_reactor_with_stage<UserStage>(server: HttpServer&, listener_fd: i64, user_stage: UserStage&, max_requests: i64 = 0) -> i64
fn serve_reactor_tls(server: HttpServer&, listener_fd: i64, tls_cfg: const wing::TlsServerHandshakeConfig&, max_requests: i64 = 0) -> i64
fn serve_reactor_tls_with_stage<Stage>(server: HttpServer&, listener_fd: i64, tls_cfg: const wing::TlsServerHandshakeConfig&, stage: Stage&, max_requests: i64 = 0) -> i64
fn new_h3_server_endpoint(settings: http3::Settings = http3::Settings { .. }) -> H3ServerEndpoint
fn handle_h3_quic_datagram<B>(server: HttpServer&, ep: H3ServerEndpoint&, client_ip: const u8[:], datagram: const u8[:], now_ns: u64, out_wire: B&) -> bool
fn handle_h3_server_datagram<B>(server: HttpServer&, h3_conn: http3::Connection&, stream_id: u64, client_ip: const u8[:], rx_wire: const u8[:], now_ns: u64, tx_wire: B&) -> bool
fn serve_h3(server: HttpServer&, udp_fd: i64, max_datagrams: i64 = 1) -> i64
fn serve_h3_l2(server: HttpServer&, ep: H3ServerEndpoint&, cfg: const H3L2Config&, xsk: net_internal::AfXdpSocket&, max_packets: i64 = 64) -> i64
```

`serve_reactor`, `serve_reactor_with_stage`, and `serve_reactor_tls` drive a
single-threaded non-blocking event loop over accelerated OS completion and
readiness backends (`IoUring` provided buffer rings + `IORING_OP_ACCEPT`/
`RECV`/`SEND`, Windows `RIO` pinned slabs + persistent overlapped `AcceptEx`,
macOS/BSD `kqueue`, and opportunistic Linux `SOL_TLS` `kTLS` with automatic
`epoll`/`WSAPoll` fallback for standard `tcp_listen` sockets), paired with a
4096-slot `SoAConnTable`, a 128-slot `H2ServerSession` pool, and a 256-slot
in-memory TLS 1.3 cipher table. `H3ServerEndpoint` supports three datapaths:

1. `serve_h3` batches up to 32 datagrams per `recvmmsg` / `sendmmsg` transition
   (`batch_recv_messages` and `batch_send_messages`) and demultiplexes direct
   RFC 9114 HTTP/3 frames (`SETTINGS`, `HEADERS`, `DATA` with QPACK) for
   internal/loopback hops.
2. `serve_h3_l2` decodes Ethernet II + IPv4/IPv6 + UDP frames from `AF_XDP` UMEM
   or `DPDK` burst queues via `net/driver/l2_frame.goose`, dispatches payloads
   through `handle_h3_quic_datagram`, and encodes L2 UDP responses.
3. `QuicConnection` (`quic/connection.goose`, `quic/tls_quic.goose`) paired with
   `H3Connection` (`http3/connection.goose`) handles encrypted Initial,
   Handshake, and 1-RTT short-header packets, AEAD packet protection, and
   congestion control.

### 3. Radix Tree & Flat Register Routing (`server/router.goose`)

```goose
struct L0RegisterTable { ... }
enum RouteMatchResult {
    Found { handler_id: i32, entries_mask: u32, pso_mask: u64, ingress_mask: u64, egress_mask: u64 },
    NotFound,
    MethodNotAllowed { allow_header: u8[..64] }
}
struct ZeroAllocParams { spans: ParamSpan[8], len: i64 }
struct RadixRouter {
    trees: MethodTree[..9],
    l0_table: L0RegisterTable,
    static_payloads: StaticRoutePayload[..32]
}
fn new_radix_router() -> RadixRouter
fn init_radix_router_inplace(r: RadixRouter&)
fn init_default_static_payloads(r: RadixRouter&)
fn add_route(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, entries_mask: u32 = 0, pso_mask: u64 = DEFAULT_ROUTE_PSO_MASK) -> bool
fn add_route_pso(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, pso_mask: u64) -> bool
fn add_static_route(router: RadixRouter&, method: const u8[:], path: const u8[:], content_type: const u8[:], body: const u8[:], handler_id: i32 = 0) -> bool
fn match_route(router: const RadixRouter&, method: const u8[:], path: const u8[:], params: ZeroAllocParams&) -> RouteMatchResult
```

`RadixRouter` pairs a Tier 0 `L0RegisterTable` (matching exact paths up to 16
bytes across 16 slots via two 64-bit word comparisons) with a Tier 1
method-segregated compressed radix trie (`MethodTree[..9]`: 8 standard HTTP
methods plus slot 8 as an extension bucket for valid RFC 9110 `tchar` custom or
WebDAV methods such as `PROPFIND`, `MKCOL`, `REPORT`, `LOCK`, and `UNLOCK`) for
parameterized (`:id` / `{id}`) and wildcard (`*filepath` / `{*filepath}`)
routes. `init_default_static_payloads` populates standard built-in static
payload slots `1001..1003` (`DEFAULT_PLAINTEXT_PAYLOAD`, `DEFAULT_JSON_PAYLOAD`,
`DEFAULT_METRICS_PAYLOAD`). Each route stores a pre-baked 64-bit `pso_mask`
(`STAGE_INGRESS_*` in bits `0..31`, `STAGE_EGRESS_*` in bits `32..63`) alongside
role-scoped `ingress_mask` and `egress_mask`.

### 4. Server Pipeline & Composable Stage Bricks (`server/pipeline.goose`)

```goose
enum PipelineOutcome {
    Handled, Pending, RateLimited, CsrfRejected, CorsPreflight,
    MethodNotAllowed, RouteNotFound, SlowlorisClosed, ExpectationFailed
}
struct ServerCompressAndEtagMemo {
    etag_src: u8[..512], etag_val: u8[..32],
    gzip_src: u8[..512], gzip_dst: u8[..512],
    compress_scratch: u8[..2048]
}
struct ServerPipelineConfig {
    limiter: ShardedGcraLimiter, tier_limiters: ShardedGcraLimiter[..4],
    csrf_guard: CrossOriginGuard, cors_policy: CorsPolicy,
    router: RadixRouter, private_jar: PrivateJar,
    edge_filter: EdgeFilter, route_cache: HttpRouteCache,
    jwks: Jwks, jwt_options: JwtValidationOptions,
    security_txt: SecurityTxt, dpop_replay_cache: DPoPReplayCache,
    wire_pipeline: wire::WirePipeline, header_pool: server_internal::HeaderMapPool,
    ext_pool: server_internal::ExtensionsPool, slab_pool: server_internal::SpillSlabPool,
    memo: ServerCompressAndEtagMemo, target_host: u8[..256],
    server_pso_capabilities: u64, max_header_bytes: i64 = 16384,
    max_body_bytes: i64 = 10485760, max_h2_concurrent_streams: u32 = 100, ...
}
struct ServerStageCtx {
    ext_slot_idx: i32, handler_id: i32, entries_mask: u32, pso_mask: u64,
    ingress_mask: u64, egress_mask: u64, now_ns: u64, outcome: PipelineOutcome, ...
}
fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig
fn init_server_pipeline_config_inplace(cfg: ServerPipelineConfig&, target_host: const u8[:], quota: security::GcraQuota)
fn check_pipeline_dos_limits(cfg: const ServerPipelineConfig&, req: const http::Request&) -> i32
fn validate_pipeline_expect_header(req: const wing::Request&) -> bool
fn execute_pipeline(cfg: ServerPipelineConfig&, conn_timer: server_internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: server_internal::InlineHandlerFuture&) -> PipelineOutcome
fn execute_server_pipeline_with_stage<UserStage>(cfg: ServerPipelineConfig&, conn_timer: server_internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: server_internal::InlineHandlerFuture&, user_stage: UserStage&) -> PipelineOutcome
fn execute_server_pipeline_async<UserStage>(cfg: ServerPipelineConfig&, conn_timer: server_internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: server_internal::InlineHandlerFuture&, sctx: ServerStageCtx&, user_stage: UserStage&) -> PipelineOutcome
fn suspend_server_request(sctx: ServerStageCtx&) -> bool
fn resume_server_pipeline_egress<UserStage>(cfg: ServerPipelineConfig&, req: const Request&, now_ns: u64, sctx: ServerStageCtx&, res: Response&, user_stage: UserStage&) -> PipelineOutcome
fn on_server_stage<First, Next>(chain: wire::StageChain<First, Next>&, phase: wire::ServerHookPhase, cfg: ServerPipelineConfig&, req: const Request&, ctx: ServerStageCtx&, res: Response&) -> wire::StageVerdict
fn on_server_custom_slot<First, Next>(chain: wire::StageChain<First, Next>&, slot_id: u8, param_slot: u8, cfg: ServerPipelineConfig&, req: const Request&, sctx: ServerStageCtx&, res: Response&) -> wire::StageVerdict
fn stage_server_slowloris(timer: server_internal::ConnectionTimer&, enabled: bool, now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_expect_100(req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_edge_filter(filter: EdgeFilter&, req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_ratelimit_ip<Limiter>(limiter: Limiter&, enabled: bool, peer_ip: const u8[:], now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_route_match<Router>(router: const Router&, req: const Request&, ext: server_internal::RequestExtensions&, out_match: RouteMatchResult&, res: Response&) -> wire::StageVerdict
fn stage_server_ratelimit_route<Limiter>(limiter: Limiter&, enabled: bool, peer_ip: const u8[:], route_path: const u8[:], now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_cors(cors_policy: const CorsPolicy&, enabled: bool, req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_csrf(csrf_guard: const CrossOriginGuard&, enabled: bool, target_host: const u8[:], req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_auth_cookie<Jar>(jar: const Jar&, req: const Request&, ext: server_internal::RequestExtensions&, now_ns: u64) -> wire::StageVerdict
fn stage_server_auth_jwt(jwks: const Jwks&, jwt_options: const JwtValidationOptions&, req: const Request&, ext: server_internal::RequestExtensions&, now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_cache_lookup(cache: HttpRouteCache&, req: const Request&, now_ms: u64, res: Response&, handler_id: i32 = -1) -> wire::StageVerdict
fn stage_server_etag(req: const Request&, res: Response&, memo: ServerCompressAndEtagMemo& = ServerCompressAndEtagMemo { .. }) -> wire::StageVerdict
fn stage_server_compress(req: const Request&, res: Response&, mask: u64, memo: ServerCompressAndEtagMemo& = ServerCompressAndEtagMemo { .. }) -> wire::StageVerdict
fn stage_server_cache_store(cache: HttpRouteCache&, now_ms: u64, res: Response&, handler_id: i32 = -1, url_key: const u8[:] = "") -> wire::StageVerdict
fn stage_server_security_headers(res: Response&) -> wire::StageVerdict
fn stage_server_metrics_log(ext: const server_internal::RequestExtensions&, res: Response&, mask: u64, now_ns: u64) -> wire::StageVerdict
```

`execute_pipeline` and `execute_server_pipeline_with_stage` intersect
`cfg.server_pso_capabilities` with each matched route's `pso_mask` so static or
public routes bypass unused CSRF, JWT, or rate-limit stages.
`ServerPipelineConfig` owns per-instance `memo: ServerCompressAndEtagMemo`
scratch state for ETag and compression memoization. User stages hook into
lifecycle phases via `server::on_server_stage` (`wire::ServerHookPhase`:
`PreRoute`, `PostAuth`, `BodyChunk`, `RouteHandler`, `ResumeHandler`,
`PreSerialize`, `AfterResponse`, `OnError`), into streaming request chunks via
`server::on_server_body_chunk`, and into programmable custom stage bindings
(`STAGE_ID_USER_0..3`, stage IDs `16..19` in
`cfg.wire_pipeline.custom_bindings`) via `server::on_server_custom_slot`.

### 4b. Inversion-of-Control Async Server Reactor (`server/async_reactor.goose`)

```goose
root struct AsyncServerReactor { ... }
struct StageDriverBridge<Stage, Driver> { stage: Stage, driver: Driver }
fn async_reactor_listen_http(host: NetHost&, reactor: AsyncServerReactor&, addr: core::ConnectAddr, backlog: i32 = 128) -> bool
fn async_reactor_register_client_link(reactor: AsyncServerReactor&, link: core::IoLink) -> i64
fn async_reactor_step<App>(host: NetHost&, server: HttpServer&, reactor: AsyncServerReactor&, app: App&, timeout_ms: i64, now_ns: u64) -> i32
fn serve_reactor_with_app<App>(host: NetHost&, server: HttpServer&, reactor: AsyncServerReactor&, addr: core::ConnectAddr, app: App&, backlog: i32 = 128, max_iters: i64 = 0, poll_timeout_ms: i64 = 10) -> bool
fn serve_reactor_with_io<Stage, Driver>(host: NetHost&, server: HttpServer&, reactor: AsyncServerReactor&, addr: core::ConnectAddr, stage: Stage, driver: Driver, backlog: i32 = 128, max_iters: i64 = 0, poll_timeout_ms: i64 = 10) -> bool
```

`AsyncServerReactor` runs HTTP/1.1 and multiplexed HTTP/2 connections over
`wing::NetHost` while sharing the same event loop with external protocol drivers
(`pg` pools, caches, custom sockets). Handlers suspend via
`suspend_server_request(sctx)` with generation-checked `core::WakeToken` keys
and resume through `ResumeHandler` when `core::host_wake` fires, discarding
stale wakes safely if the client socket disconnected mid-query.

### 5. L7 WAF Edge Filter (`server/edge_filter.goose`)

```goose
enum EdgeFilterVerdict {
    Pass, BlockForbidden, ThrottleRate, DropConnection
}
struct EdgeFilterRule {
    name: u8[..64], path_prefix: u8[..64],
    required_header: u8[..64], verdict: EdgeFilterVerdict, enabled: bool
}
struct EdgeFilter {
    rules: EdgeFilterRule[..16], total_inspected: u64,
    total_blocked: u64, max_payload_bytes: i64, enabled: bool
}
fn make_edge_filter_rule(name: const u8[:], path_prefix: const u8[:], verdict: EdgeFilterVerdict) -> EdgeFilterRule
fn add_edge_filter_rule(filter: EdgeFilter&, rule: EdgeFilterRule) -> bool
fn evaluate_edge_filter(filter: EdgeFilter&, method: const u8[:], path: const u8[:], headers: const HeaderMap&) -> EdgeFilterVerdict
```

`EdgeFilter` inspects requests before routing against up to 16 L7 rules
(`EdgeFilterRule[..16]`), matching `path_prefix` and optional `required_header`
constraints to return an `EdgeFilterVerdict` (`EdgeVerdict`: `Pass`,
`BlockForbidden`, `ThrottleRate`, or `DropConnection`).

### 6. HTTP/2 Server Multiplexer (`server/h2_multiplexer.goose`, RFC 9113)

```goose
struct H2ServerStream {
    stream_id: u32, state: H2StreamState, req: Request,
    pseudo: H2PseudoHeaders, body_complete: bool, end_stream_received: bool
}
struct H2ServerSession { ... }
fn new_h2_server_session() -> H2ServerSession
fn reset_h2_server_session_inplace(sess: H2ServerSession&)
fn initiate_graceful_shutdown<B>(sess: H2ServerSession&, out_wire: B&)
fn emit_response_headers<B>(sess: H2ServerSession&, stream_id: u32, status_code: i32, headers: const HeaderField[:], end_stream: bool, out_wire: B&)
fn emit_response_data<B>(sess: H2ServerSession&, stream_id: u32, data: const u8[:], end_stream: bool, out_wire: B&)
fn emit_response_trailers<B>(sess: H2ServerSession&, stream_id: u32, trailers: const HeaderField[:], out_wire: B&)
fn handle_h2_server_ingress<B>(sess: H2ServerSession&, server: HttpServer&, client_ip: const u8[:], wire_in: const u8[:], now_ns: u64, out_wire: B&) -> i64, bool
```

`H2ServerSession` multiplexes up to 32 concurrent HTTP/2 streams with connection
and stream flow-control windows, HPACK dynamic table decoding, and RFC 9113 §6.8
two-phase graceful `GOAWAY` shutdown (`0x7FFFFFFF` followed by
`last_peer_stream_id`). `handle_h2_server_ingress` returns
`(consumed_bytes, ok)` and sets `ok = false` on connection-level RFC 9113
protocol errors.

### 7. Route Caching (`server/cache.goose`)

```goose
enum CacheLookup { HitFresh, HitStaleNeedsUpdate, Miss }
struct CacheEntry {
    wire: u8[..16384], content_type: u8[..64], etag: u8[..64],
    url_key: u8[..256], url_hash: u64, created_ms: u64,
    handler_id: i32, prev_lru: i32, next_lru: i32, valid: bool
}
struct HttpRouteCache {
    wire: u8[..16384], content_type: u8[..64], etag: u8[..64],
    entries: CacheEntry[..8], lower_expiry_ms: u64, upper_expiry_ms: u64,
    created_ms: u64, handler_id: i32, lru_head: i32, lru_tail: i32,
    valid: bool, is_updating: bool
}
fn new_http_route_cache(lower_ms: u64 = 1000, upper_ms: u64 = 5000) -> HttpRouteCache
fn cache_lookup(c: HttpRouteCache&, now_ms: u64, req_handler_id: i32 = -1, url_key: const u8[:] = "") -> CacheLookup
fn cache_store(c: HttpRouteCache&, now_ms: u64, data: const u8[:], handler_id: i32 = -1, content_type: const u8[:] = "", url_key: const u8[:] = "", etag: const u8[:] = "") -> bool
fn cache_invalidate(c: HttpRouteCache&)
```

`HttpRouteCache` maintains 8 associative cache slots (`CacheEntry[..8]`) ordered
by an O(1) intrusive doubly-linked LRU list (`lru_head`, `lru_tail`, `prev_lru`,
`next_lru`), storing pre-serialized response bodies up to 16 KB (`u8[..16384]`)
with Stale-While-Revalidate semantics (`HitFresh`, `HitStaleNeedsUpdate`,
`Miss`) across `lower_expiry_ms` and `upper_expiry_ms`.

### 8. Server Object Pools, SoA Timers & RDTSC Profiler (`server/pool.goose`, `server/soa_timer.goose`, `server/profiler.goose`)

```goose
// Object Pools & Connection Timers (server/pool.goose)
struct HeaderMapPool { ... }
struct RequestExtensions { ... }
struct ExtensionsPool { ... }
struct SpillSlabPool { ... }
struct ConnectionTimer { ... }
fn acquire_header_map(pool: HeaderMapPool&) -> i32
fn release_header_map(pool: HeaderMapPool&, idx: i32)
fn acquire_extensions(pool: ExtensionsPool&) -> i32
fn release_extensions(pool: ExtensionsPool&, idx: i32)
fn acquire_spill_slab(pool: SpillSlabPool&) -> i32
fn release_spill_slab(pool: SpillSlabPool&, idx: i32)
fn new_connection_timer(now_ns: u64, header_timeout_ns: u64 = 5000000000, min_rate_bytes_per_sec: u64 = 1024) -> ConnectionTimer
fn check_connection_tick(timer: ConnectionTimer&, now_ns: u64, bytes_received: u64, headers_complete: bool) -> bool

// SoA Connection Sweep Table (server/soa_timer.goose)
const SOA_TABLE_CAP: i64 = 4096;
struct SoAConnTable { ... }
fn soa_table_alloc(table: SoAConnTable&, fd: i64, timeout_tick: u8) -> i64
fn soa_table_free(table: SoAConnTable&, slot: i64)
fn soa_table_touch(table: SoAConnTable&, slot: i64, new_tick: u8)
fn soa_table_sweep_expired(table: SoAConnTable&, wheel: const TickTimerWheel&, out_expired: i64[:]) -> i64

// RDTSC Cycle Profiler (server/profiler.goose)
const PROF_STAGE_FRAMING: i32 = 0;
const PROF_STAGE_MISC: i32 = 7;
fn prof_rdtsc() -> u64
fn prof_reset()
fn prof_record(stage: i32, cycles: u64)
fn prof_total_cycles(stage: i32) -> u64
fn prof_sample_count(stage: i32) -> u64
fn prof_min_cycles(stage: i32) -> u64
fn prof_max_cycles(stage: i32) -> u64
fn prof_avg_cycles(stage: i32) -> u64
fn prof_print_summary()
```

`SoAConnTable` packs 4096 connection timestamps, file descriptors, and states
into parallel arrays so `soa_table_sweep_expired` scans all 4096 slots in a
linear L1D-friendly pass and outputs expired slot indices into `out_expired`
(`i64[:]`). `server/profiler.goose` records hardware RDTSC cycle counts across 8
pipeline stages (`PROF_STAGE_FRAMING` through `PROF_STAGE_MISC`).

### 9. Unified zero-copy streaming and backpressure (`server/stream.goose`, `server/stream_consumer.goose`, `server/cork.goose`)

```goose
// Unified H1/H2/H3 response streaming (server/stream.goose)
enum StreamProtocol { Http1, Http2, Http3 }
enum StreamWriteStatus { Ok, WouldBlock, Closed, Error }
struct ResponseStream {
    protocol: StreamProtocol = StreamProtocol.Http1,
    cork: ServerCork = new_server_cork(-1),
    server_name: u8[..64] = "goose-wing",
    headers_sent: bool = false,
    ended: bool = false,
    closed: bool = false,
    body_bytes_sent: u64 = 0,
    frames_emitted: u64 = 0,
    ...
}
fn make_http1_response_stream(sock_fd: i64 = -1, server_name: const u8[:] = "goose-wing") -> ResponseStream
fn make_http2_response_stream(stream_id: u32, conn_window: i64 = 65535, stream_window: i64 = 65535, max_frame_size: u32 = 16384, sock_fd: i64 = -1, server_name: const u8[:] = "goose-wing") -> ResponseStream
fn make_http3_response_stream(stream_id: u64, conn_credit: u64 = 65536, stream_credit: u64 = 65536, sock_fd: i64 = -1, server_name: const u8[:] = "goose-wing") -> ResponseStream
fn stream_begin(stream: ResponseStream&, res: http::Response&) -> StreamWriteStatus
fn stream_write(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus
fn stream_end(stream: ResponseStream&) -> StreamWriteStatus
fn stream_flush(stream: ResponseStream&) -> StreamWriteStatus
fn stream_drain_wire(stream: ResponseStream&, dst: u8[:]) -> i64
fn stream_on_window_update(stream: ResponseStream&, conn_delta: i64, stream_delta: i64)
fn stream_on_quic_max_data(stream: ResponseStream&, new_max_data: u64, new_max_stream_data: u64)
fn stream_can_write(stream: const ResponseStream&) -> i64

// Request pull-rate flow-control windows (server/stream_consumer.goose)
enum WindowProtocol { Http1, Http2, Http3 }
struct WindowReplenishment {
    should_update_stream: bool = false,
    should_update_conn: bool = false,
    stream_increment: u64 = 0,
    conn_increment: u64 = 0,
}
struct RequestStreamWindow {
    protocol: WindowProtocol = WindowProtocol.Http2,
    stream_id: u64 = 0,
    stream_window_size: u64 = 65536,
    conn_window_size: u64 = 65536,
    is_backpressured: bool = false,
    ...
}
fn make_request_stream_window(protocol: WindowProtocol, stream_id: u64, stream_window: u64 = 65536, conn_window: u64 = 65536, update_threshold_pct: u32 = 50) -> RequestStreamWindow
fn request_window_on_ingress(win: RequestStreamWindow&, received_bytes: u64) -> bool
fn request_window_available(win: const RequestStreamWindow&) -> u64
fn request_window_on_consume(win: RequestStreamWindow&, consumed_bytes: u64) -> WindowReplenishment
fn request_window_encode_h2_updates<B>(win: const RequestStreamWindow&, rep: const WindowReplenishment&, out: B&) -> bool
fn request_window_encode_quic_updates<B>(win: const RequestStreamWindow&, rep: const WindowReplenishment&, out: B&) -> bool

// Non-blocking cork and vectored raw send (server/cork.goose)
const CORK_WOULD_BLOCK: i32 = -2;
fn cork_send_raw(fd: i64, data: const u8[:]) -> i32
fn cork_send_raw2(fd: i64, head: const u8[:], body: const u8[:]) -> i32
```

`ResponseStream` provides closed-polymorphism response streaming across
HTTP/1.1, HTTP/2, and HTTP/3 with zero heap allocation and no 16 KB response
body cap. Handlers call `stream_begin`, `stream_write`, and idempotent
`stream_end` identically across protocols: HTTP/1.1 coalesces small chunks in
`ServerCork`, bypasses buffer copies for chunks `>= CORK_BUFFER_CAP` via
vectored `cork_send_raw2`, and surfaces non-blocking `CORK_WOULD_BLOCK` (`-2`)
as `StreamWriteStatus.WouldBlock` with partial offset tracking; HTTP/2 clamps
every `DATA` frame to `min(chunk.len, max_frame_size, conn_send_window,
stream_send_window)` and resumes when `stream_on_window_update` replenishes
credit; HTTP/3 clamps `H3_FRAME_DATA` frames to QUIC connection and stream
credits and resumes on `stream_on_quic_max_data` or `stream_on_window_update`.
`RequestStreamWindow` couples inbound pull rate to HTTP/2 `WINDOW_UPDATE` and
QUIC `MAX_DATA` / `MAX_STREAM_DATA` emission so slow consumers exert real wire
backpressure without growing buffers.
