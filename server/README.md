# `server`

Package `server` implements the zero-allocation HTTP/1.1, HTTP/2, HTTP/3, and
WebSocket server engine of `goose-wing`, combining a two-tier L0 register and
Radix Tree router, a bitmask-driven security and caching pipeline, an L7 WAF
edge filter, and an event-loop reactor.

```goose
var srv = new_http_server("127.0.0.1", 8080);
add_static_route(srv.pipeline.router, "GET", "/healthz", "text/plain", "ok");
```

## Public API Reference

### 1. HTTP Server Lifecycle, TLS & Pub/Sub (`server/server.goose`)

```goose
struct HttpServer {
    pipeline: ServerPipelineConfig, host: u8[..256], port: u16,
    server_name: u8[..64], timer: internal::ConnectionTimer,
    topic_tree: TopicTree, ws_routes: WsRouteEntry[..16],
    shared_compressor: SharedWsCompressor, sni_registry: SniRegistry,
    worker_ring: core::SpscRing, cached_date: CachedHttpDate,
    enable_header_memoization: bool = false, ...
}
fn new_http_server(host: const u8[:], port: u16, quota: GcraQuota = new_gcra_quota(1000, core::secs(1), 100)) -> HttpServer
fn set_header_memoization(server: HttpServer&, enabled: bool)
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64
fn serve_with_stage<UserStage>(server: HttpServer&, listener_fd: i64, user_stage: UserStage&, max_connections: i64 = 0) -> i64
fn serve_tls(server: HttpServer&, listener_fd: i64, tls_cfg: const TlsServerHandshakeConfig&, max_connections: i64 = 0) -> i64
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
selection) with a Sans-IO wire processor (`handle_connection_wire`). By default,
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
struct H3ServerEndpoint {
    conn: internal::H3Connection
}
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_requests: i64 = 0) -> i64
fn serve_reactor_with_stage<UserStage>(server: HttpServer&, listener_fd: i64, user_stage: UserStage&, max_requests: i64 = 0) -> i64
fn serve_reactor_tls(server: HttpServer&, listener_fd: i64, tls_cfg: const TlsServerHandshakeConfig&, max_requests: i64 = 0) -> i64
fn new_h3_server_endpoint(settings: H3Settings = H3Settings { .. }) -> H3ServerEndpoint
fn handle_h3_quic_datagram<B>(server: HttpServer&, ep: H3ServerEndpoint&, client_ip: const u8[:], datagram: const u8[:], now_ns: u64, out_wire: B&) -> bool
fn handle_h3_server_datagram<B>(server: HttpServer&, h3_conn: internal::H3Connection&, stream_id: u64, client_ip: const u8[:], rx_wire: const u8[:], now_ns: u64, tx_wire: B&) -> bool
fn serve_h3(server: HttpServer&, udp_fd: i64, max_datagrams: i64 = 1) -> i64
```

`serve_reactor`, `serve_reactor_with_stage`, and `serve_reactor_tls` drive a
single-threaded non-blocking event loop over `Poller`, a 4096-slot
`SoAConnTable` (`SOA_TABLE_CAP = 4096`), a 128-slot `H2ServerSession` pool
(`REACTOR_MAX_H2_SESSIONS = 128`, returning `-1` on saturation instead of
overwriting active sessions), and per-connection `ReactorLeftoverBuf` /
`PageRingBuffer` arenas. `H3ServerEndpoint` supports two distinct UDP transport
modes:

1. **Unencrypted H3 over UDP (Datagram Direct)**: `serve_h3` and
   `handle_h3_server_datagram` demultiplex direct RFC 9114 HTTP/3 frames
   (`SETTINGS`, `HEADERS`, `DATA` with QPACK compression,
   `(datagram[0] & 0xC0) == 0`) carried over raw UDP datagrams for
   zero-handshake internal/loopback hops.
2. **Full QUIC v1 (RFC 9000 + RFC 9001 TLS 1.3)**: `QuicConnection`
   (`quic/connection.goose`, `quic/tls_quic.goose`) paired with `H3Connection`
   (`http3/connection.goose`) handles encrypted Initial, Handshake, and 1-RTT
   short-header packets (`(datagram[0] & 0x80) != 0`), AEAD packet protection,
   header protection, and loss/congestion control.

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
fn init_default_static_payloads(r: RadixRouter&)
fn add_route(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, entries_mask: u32 = 0, pso_mask: u64 = DEFAULT_ROUTE_PSO_MASK) -> bool
fn add_route_pso(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, pso_mask: u64) -> bool
fn add_static_route(router: RadixRouter&, method: const u8[:], path: const u8[:], content_type: const u8[:], body: const u8[:], handler_id: i32 = 0) -> bool
fn match_route(router: const RadixRouter&, method: const u8[:], path: const u8[:], params: ZeroAllocParams&) -> RouteMatchResult
fn param_val(params: const ZeroAllocParams&, idx: i64, req_path: const u8[:]) -> const u8[:]
fn param_by_name(params: const ZeroAllocParams&, name: const u8[:], req_path: const u8[:]) -> const u8[:], bool
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
    Handled, RateLimited, CsrfRejected, CorsPreflight, MethodNotAllowed,
    RouteNotFound, SlowlorisClosed, ExpectationFailed
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
    wire_pipeline: wire::WirePipeline, header_pool: internal::HeaderMapPool,
    ext_pool: internal::ExtensionsPool, slab_pool: internal::SpillSlabPool,
    memo: ServerCompressAndEtagMemo, target_host: u8[..256],
    server_pso_capabilities: u64, ...
}
struct ServerStageCtx {
    ext_slot_idx: i32, handler_id: i32, entries_mask: u32, pso_mask: u64,
    ingress_mask: u64, egress_mask: u64, now_ns: u64, outcome: PipelineOutcome, ...
}
fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig
fn validate_pipeline_expect_header(req: const Request&) -> bool
fn execute_pipeline(cfg: ServerPipelineConfig&, conn_timer: internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: internal::InlineHandlerFuture&) -> PipelineOutcome
fn execute_server_pipeline_with_stage<UserStage>(cfg: ServerPipelineConfig&, conn_timer: internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: internal::InlineHandlerFuture&, user_stage: UserStage&) -> PipelineOutcome
fn on_server_stage<First, Next>(chain: wire::StageChain<First, Next>&, phase: wire::ServerHookPhase, cfg: ServerPipelineConfig&, req: const Request&, ctx: ServerStageCtx&, res: Response&) -> wire::StageVerdict
fn on_server_custom_slot<First, Next>(chain: wire::StageChain<First, Next>&, slot_id: u8, param_slot: u8, cfg: ServerPipelineConfig&, req: const Request&, sctx: ServerStageCtx&, res: Response&) -> wire::StageVerdict
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
fn stage_server_etag(req: const Request&, res: Response&, memo: ServerCompressAndEtagMemo& = ServerCompressAndEtagMemo { .. }) -> wire::StageVerdict
fn stage_server_compress(req: const Request&, res: Response&, mask: u64, memo: ServerCompressAndEtagMemo& = ServerCompressAndEtagMemo { .. }) -> wire::StageVerdict
fn stage_server_cache_store(cache: HttpRouteCache&, now_ms: u64, res: Response&, handler_id: i32 = -1, url_key: const u8[:] = "") -> wire::StageVerdict
fn stage_server_security_headers(res: Response&) -> wire::StageVerdict
fn stage_server_metrics_log(ext: const internal::RequestExtensions&, res: Response&, mask: u64, now_ns: u64) -> wire::StageVerdict
```

`execute_pipeline` and `execute_server_pipeline_with_stage` intersect
`cfg.server_pso_capabilities` with each matched route's `pso_mask` so static or
public routes bypass unused CSRF, JWT, or rate-limit stages.
`ServerPipelineConfig` owns per-instance `memo: ServerCompressAndEtagMemo`
scratch state for ETag and compression memoization. User stages hook into
lifecycle phases via `on_server_stage` (`wire::ServerHookPhase`: `PreRoute`,
`PostAuth`, `BodyChunk`, `RouteHandler`, `PreSerialize`, `AfterResponse`,
`OnError`) and into programmable custom stage bindings (`STAGE_ID_USER_0..3`,
stage IDs `16..19` in `cfg.wire_pipeline.custom_bindings`) via
`on_server_custom_slot`.

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
