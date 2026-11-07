# `server`

Package `server` implements the zero-allocation HTTP/1.1, HTTP/2, HTTP/3, and
WebSocket server engine of `goose-wing`, combining a two-tier L0 register and
Radix Tree router, a bitmask-driven security and caching pipeline, an L7 WAF
edge filter, and an event-loop reactor.

```goose
var srv = new_http_server("127.0.0.1", 8080);
add_static_route(srv.router, "GET", "/healthz", "text/plain", "ok");
```

## Public API Reference

### 1. HTTP Server Lifecycle, TLS & Pub/Sub (`server/server.goose`)

```goose
struct HttpServer {
    pipeline_cfg: ServerPipelineConfig, router: RadixRouter,
    topic_tree: TopicTree, ws_behaviors: WsBehaviorTable,
    tls_config: ServerTlsConfig, cork_buffers: ServerCork[..1024],
    wire_pipeline: wire::WirePipeline, edge_filter: EdgeFilter
}
fn new_http_server(host: const u8[:] = "127.0.0.1", port: u16 = 8080) -> HttpServer
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64
fn serve_tls(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64
fn handle_connection_wire<B>(server: HttpServer&, client_ip: const u8[:], wire_in: const u8[:], now_ns: u64, wire_out: B&) -> PipelineOutcome, bool
fn subscribe(server: HttpServer&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe(server: HttpServer&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe_all(server: HttpServer&, sock_fd: i64) -> i32
fn publish(server: HttpServer&, topic: const u8[:], payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64
fn publish_text(server: HttpServer&, topic: const u8[:], text: const u8[:]) -> i64
fn publish_binary(server: HttpServer&, topic: const u8[:], data: const u8[:]) -> i64
fn find_subscribers(server: const HttpServer&, topic: const u8[:], out_fds: i64[..256]&) -> i64
```

`HttpServer` combines synchronous serving loops (`serve` and TLS 1.3 `serve_tls`
with `h2` / `http/1.1` ALPN and 0-RTT early data) with a Sans-IO wire processor
(`handle_connection_wire`). Built-in WebSocket pub/sub routes messages across
`server.topic_tree` using MQTT wildcard patterns (`+` and `#`), collecting up to
256 matching socket descriptors (`i64[..256]`) in `find_subscribers`.

### 2. Reactor Event Loop & HTTP/3 Server Endpoint (`server/reactor.goose`)

```goose
struct H3ServerEndpoint {
    local_cid: u8[..20], quic_tp: QuicTransportParams,
    h3_conn: H3Connection, wt_demuxer: WebTransportDemuxer,
    masque_tunnels: MasqueTunnelSession[..16]
}
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_requests: i64 = 0) -> i64
fn serve_reactor_with_stage<UserStage>(server: HttpServer&, listener_fd: i64, max_requests: i64, user_stage: UserStage&) -> i64
fn serve_reactor_tls(server: HttpServer&, listener_fd: i64, max_requests: i64 = 0) -> i64
fn new_h3_server_endpoint(server_cid: const u8[:] = "\x88\x77\x66\x55\x44\x33\x22\x11") -> H3ServerEndpoint
fn handle_h3_quic_datagram(server: HttpServer&, ep: H3ServerEndpoint&, client_ip: const u8[:], raw_udp: const u8[:], now_ns: u64, out_udp: u8[>..]&) -> bool
fn handle_h3_server_datagram(server: HttpServer&, ep: H3ServerEndpoint&, client_ip: const u8[:], stream_id: u64, h3_wire: const u8[:], now_ns: u64, out_h3_wire: u8[>..]&) -> bool
fn serve_h3(server: HttpServer&, udp_fd: i64, max_datagrams: i64 = 1) -> i64
```

`serve_reactor`, `serve_reactor_with_stage`, and `serve_reactor_tls` drive a
single-threaded non-blocking event loop over `Poller`, a 1024-slot
`SoAConnTable`, and per-slot `PageRingBuffer` arenas. `H3ServerEndpoint`
demultiplexes QUIC packets (`handle_h3_quic_datagram`), HTTP/3 request streams,
WebTransport sessions, and up to 16 MASQUE tunnels (`MasqueTunnelSession[..16]`)
over UDP (`serve_h3`).

### 3. Radix Tree & Flat Register Routing (`server/router.goose`)

```goose
struct L0RegisterTable { ... }
enum RouteMatchResult { Found, NotFound, MethodNotAllowed }
struct ZeroAllocParams {
    entries: ParamSpan[..8], matched_handler_id: i32,
    matched_pso_mask: u64, allowed_methods_mask: u16
}
struct RadixRouter { ... }
fn new_radix_router() -> RadixRouter
fn add_route(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, entries_mask: u32 = 0, pso_mask: u64 = DEFAULT_ROUTE_PSO_MASK) -> bool
fn add_route_pso(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, pso_mask: u64) -> bool
fn add_static_route(router: RadixRouter&, method: const u8[:], path: const u8[:], content_type: const u8[:], body: const u8[:], handler_id: i32 = 0) -> bool
fn match_route(router: const RadixRouter&, method: const u8[:], path: const u8[:], params: ZeroAllocParams&) -> RouteMatchResult
fn param_val(params: const ZeroAllocParams&, idx: i64, req_path: const u8[:]) -> const u8[:]
fn param_by_name(params: const ZeroAllocParams&, name: const u8[:], req_path: const u8[:]) -> const u8[:]
```

`RadixRouter` pairs a Tier 0 `L0RegisterTable` (matching exact paths up to 16
bytes across 16 slots via two 64-bit word comparisons) with a Tier 1
method-isolated compressed radix trie for parameterized (`:id`) and wildcard
(`*filepath`) routes. `ZeroAllocParams` records up to 8 parameter byte spans
(`ParamSpan[..8]`) into `req_path` alongside the route's pre-baked 64-bit PSO
stage mask (`matched_pso_mask`).

### 4. Server Pipeline & Composable Stage Bricks (`server/pipeline.goose`)

```goose
enum PipelineOutcome {
    Handled, RateLimited, CsrfRejected, CorsPreflight, MethodNotAllowed,
    RouteNotFound, SlowlorisClosed, ExpectationFailed
}
struct ServerPipelineConfig { ... }
struct ServerStageCtx {
    ext_slot_idx: i32, handler_id: i32, entries_mask: u32, pso_mask: u64,
    ingress_mask: u64, egress_mask: u64, now_ns: u64, outcome: PipelineOutcome, ...
}
fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig
fn validate_pipeline_expect_header(req: const Request&) -> bool
fn execute_pipeline(cfg: ServerPipelineConfig&, conn_timer: internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: internal::InlineHandlerFuture&) -> PipelineOutcome
fn execute_server_pipeline_with_stage<UserStage>(cfg: ServerPipelineConfig&, edge_filter: EdgeFilter&, wire_pipe: const wire::WirePipeline&, conn_timer: internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: internal::InlineHandlerFuture&, user_stage: UserStage&) -> PipelineOutcome
fn stage_server_slowloris(timer: internal::ConnectionTimer&, enabled: bool, now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_expect_100(req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_edge_filter(filter: EdgeFilter&, req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_ratelimit_ip<Limiter>(limiter: Limiter&, enabled: bool, peer_ip: const u8[:], now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_route_match<Router>(router: const Router&, req: const Request&, ext: internal::RequestExtensions&, out_match: RouteMatchResult&, res: Response&) -> wire::StageVerdict
fn stage_server_ratelimit_route<Limiter>(limiter: Limiter&, enabled: bool, peer_ip: const u8[:], route_path: const u8[:], now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_cors(cors_policy: const CorsPolicy&, enabled: bool, req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_csrf(csrf_guard: const CrossOriginGuard&, enabled: bool, target_host: const u8[:], req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_auth_cookie<Jar>(jar: const Jar&, req: const Request&, ext: internal::RequestExtensions&, now_ns: u64) -> wire::StageVerdict
fn stage_server_auth_jwt(jwks: const Jwks&, jwt_options: const JwtValidationOptions&, req: const Request&, ext: internal::RequestExtensions&, now_ns: u64, res: Response&) -> wire::StageVerdict
fn stage_server_cache_lookup(cache: HttpRouteCache&, req: const Request&, now_ms: u64, res: Response&, handler_id: i32 = -1) -> wire::StageVerdict
fn stage_server_etag(req: const Request&, res: Response&) -> wire::StageVerdict
fn stage_server_compress(req: const Request&, res: Response&, mask: u64) -> wire::StageVerdict
fn stage_server_cache_store(cache: HttpRouteCache&, now_ms: u64, res: const Response&, handler_id: i32 = -1, url_key: const u8[:] = "") -> wire::StageVerdict
fn stage_server_security_headers(res: Response&) -> wire::StageVerdict
fn stage_server_metrics_log(ext: const internal::RequestExtensions&, res: Response&, mask: u64, now_ns: u64) -> wire::StageVerdict
```

`execute_pipeline` and `execute_server_pipeline_with_stage` intersect the
server's global `wire::WirePipeline` mask with each route's `matched_pso_mask`
so static or public routes bypass unused CSRF, JWT, or rate-limit stages in zero
branches.

### 5. L7 WAF Edge Filter (`server/edge_filter.goose`)

```goose
enum EdgeFilterVerdict {
    Allow, BlockIp, BlockMethod, BlockPathPrefix, BlockUserAgent,
    BlockHeaderTooLarge, BlockQueryTooLarge, BlockSuspiciousPayload
}
struct EdgeFilterRule {
    match_ip: u8[..64], match_path_prefix: u8[..128],
    match_user_agent: u8[..128], status_code: u16, active: bool
}
struct EdgeFilter { total_inspected: u64, total_blocked: u64, rules: EdgeFilterRule[..16] }
fn make_edge_filter_rule(ip: const u8[:], path_prefix: const u8[:], ua: const u8[:], status: u16 = 403) -> EdgeFilterRule
fn add_edge_filter_rule(f: EdgeFilter&, ip: const u8[:], path_prefix: const u8[:], ua: const u8[:], status: u16 = 403) -> bool
fn evaluate_edge_filter(f: EdgeFilter&, client_ip: const u8[:], req: const Request&, res: Response&) -> EdgeFilterVerdict
```

`EdgeFilter` inspects requests before routing against up to 16 custom blocking
rules (`EdgeFilterRule[..16]`), header and query size limits, path traversal
sequences (`..`), and SQLi/XSS token signatures, writing the HTTP rejection
status into `res` when blocked.

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
enum CacheLookup { Hit, Miss }
struct HttpRouteCache { payload: u8[..4096], valid: bool, ... }
fn new_http_route_cache(lower_expiry_ms: u64 = 1000, upper_expiry_ms: u64 = 5000) -> HttpRouteCache
fn cache_lookup(c: const HttpRouteCache&, now_ms: u64) -> CacheLookup
fn cache_store(c: HttpRouteCache&, now_ms: u64, wire_data: const u8[:]) -> bool
fn cache_invalidate(c: HttpRouteCache&)
```

`HttpRouteCache` stores pre-serialized response payloads up to 4096 bytes
(`u8[..4096]`) with lower and upper TTL bounds; `cache_store` returns `false` if
`wire_data.len > 4096`.

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
struct SoAConnTable { ... }
fn soa_table_alloc(table: SoAConnTable&, fd: i32, now_ms: u64) -> i32
fn soa_table_free(table: SoAConnTable&, slot: i32)
fn soa_table_touch(table: SoAConnTable&, slot: i32, now_ms: u64)
fn soa_table_sweep_expired(table: SoAConnTable&, now_ms: u64, idle_timeout_ms: u64, out_expired_fds: i32[..1024]&) -> i32

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

`SoAConnTable` packs 1024 connection timestamps, file descriptors, and states
into parallel arrays so `soa_table_sweep_expired` scans all 1024 slots in a
linear pass and outputs expired descriptors into `out_expired_fds`
(`i32[..1024]`). `server/profiler.goose` records hardware RDTSC cycle counts
across 8 pipeline stages (`PROF_STAGE_FRAMING` through `PROF_STAGE_MISC`).
