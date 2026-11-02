# `server`

Package `server` delivers the high-throughput, zero-allocation HTTP/1.1, HTTP/2, and WebSocket server engine of `goose-wing`. It features a linear-time Radix Tree router, a multi-stage defense-in-depth security pipeline (Slowloris protection, GCRA rate limiting, CORS/CSRF validation, encrypted session jar decoding), hardware page-ring pipelining, and both threaded (`serve`) and event-loop reactor (`serve_reactor`) architectures.

## Public API Reference

### 1. HTTP Server Lifecycle & Serving (`server/server.goose`)

- **`struct HttpServer`**: Core server instance supporting thread-per-worker and share-nothing reactor event loops.
- **`fn new_http_server(host: const u8[:] = "127.0.0.1", port: u16 = 8080) -> HttpServer`**: Constructor for `HttpServer` with default host and port.
- **`fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64`**: Synchronous multi-threaded blocking worker serving loop.
- **`fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64`**: Single-thread epoll/WSAPoll reactor serving loop (~3.1 MB RSS footprint, 1024 concurrent slots).
- **`fn handle_connection_wire<B>(server: HttpServer&, client_ip: const u8[:], wire_in: const u8[:], now_ns: u64, wire_out: B&) -> PipelineOutcome, bool`**: Sans-IO connection processing.

### 2. Radix Tree & Flat Register Routing (`server/router.goose`)

Two-tier zero-allocation HTTP router combining a Tier 0 Flat Register Table (L0 SWAR/SIMD) for line-rate exact matches with a Tier 1 Radix Tree for parameterized and wildcard routes.

- **`struct L0RegisterTable`**: 16-slot Structure of Arrays (592 bytes, L1D resident) comparing two 64-bit words (`w0`, `w1`) per route via SIMD or SWAR.
- **`enum RouteMatchResult`**: Route lookup outcome (`Found`, `NotFound`, `MethodNotAllowed`).
- **`struct ZeroAllocParams`**: Zero-allocation captured path parameter index storage.
- **`struct RadixRouter`**: Method-isolated compressed radix trie.
- **`fn new_radix_router() -> RadixRouter`**: Constructs an empty `RadixRouter`.
- **`fn add_route(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, entries_mask: u32 = 0, pso_mask: u64 = DEFAULT_ROUTE_PSO_MASK) -> bool`**: Registers route with handler ID and optional PSO mask.
- **`fn add_route_pso(router: RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, pso_mask: u64) -> bool`**: Registers route with an explicit Pre-Baked Pipeline State Object (PSO) bitmask.
- **`fn add_static_route(router: RadixRouter&, method: const u8[:], path: const u8[:], content_type: const u8[:], body: const u8[:], handler_id: i32 = 0) -> bool`**: Registers static line-rate response route.
- **`fn match_route(router: const RadixRouter&, method: const u8[:], path: const u8[:], params: ZeroAllocParams&) -> RouteMatchResult`**: Matches request method and path against L0 register table and Radix tree.
- **`fn param_val(params: const ZeroAllocParams&, idx: i64, req_path: const u8[:]) -> const u8[:]`**: Extracts parameter value by index.
- **`fn param_by_name(params: const ZeroAllocParams&, name: const u8[:], req_path: const u8[:]) -> const u8[:]`**: Extracts parameter value by name.

### 3. Server Pipeline & Security Defense (`server/pipeline.goose`)

Register-based bitmask pipeline (Pre-Baked Route PSOs & Macro-Fused Bit-Test) defending against Slowloris, DoS bursts, CORS/CSRF attacks, and request smuggling.

- **`enum PipelineOutcome`**: Pipeline execution status (`Handled`, `RateLimited`, `CsrfRejected`, `CorsPreflight`, `MethodNotAllowed`, `RouteNotFound`, `SlowlorisClosed`, `ExpectationFailed`).
- **`struct ServerPipelineConfig`**: Master pipeline configuration holding limiter, csrf guard, cors policy, router, slab pool, and header pool.
- **`fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig`**: Constructs default pipeline configuration for target host.
- **`fn validate_pipeline_expect_header(req: const Request&) -> bool`**: Validates `Expect: 100-continue` header conformance.
- **`fn execute_pipeline(cfg: ServerPipelineConfig&, conn_timer: internal::ConnectionTimer&, client_ip: const u8[:], req: const Request&, now_ns: u64, res: Response&, out_future: internal::InlineHandlerFuture&) -> PipelineOutcome`**: Executes full request pipeline with pre-baked PSOs.

### 4. Route Caching (`server/cache.goose`)

- **`enum CacheLookup`**: Route cache lookup result (`Hit`, `Miss`).
- **`struct HttpRouteCache`**: Fast O(1) in-memory route cache with TTL and automatic invalidation.
- **`fn new_http_route_cache(lower_expiry_ms: u64 = 1000, upper_expiry_ms: u64 = 5000) -> HttpRouteCache`**: Constructs route cache.
- **`fn cache_lookup(c: const HttpRouteCache&, now_ms: u64) -> CacheLookup`**: Performs cache lookup.
- **`fn cache_store(c: HttpRouteCache&, now_ms: u64, wire_data: const u8[:]) -> bool`**: Stores response payload in cache.
- **`fn cache_invalidate(c: HttpRouteCache&)`**: Invalidates all cache entries.

### 5. TopicTree Socket Broadcast (`server/server.goose`)

- **`struct TopicTree`**: Hierarchical MQTT-style pub/sub topic tree with live socket broadcasting, batch queuing, and subscriber drainage.
- **`fn subscribe(tree: TopicTree&, sock_fd: i64, topic: const u8[:]) -> bool`**: Subscribes socket to topic.
- **`fn unsubscribe(tree: TopicTree&, sock_fd: i64, topic: const u8[:]) -> bool`**: Unsubscribes socket from topic.
- **`fn publish_text(tree: const TopicTree&, topic: const u8[:], message: const u8[:]) -> i64`**: Publishes text message to all matching subscribers.
- **`fn publish_batch(tree: TopicTree&, topic: const u8[:], message: const u8[:]) -> i64`**: Enqueues message batch.
- **`fn drain_subscribers(tree: TopicTree&, sock_fd: i64, wire_out: u8[:]) -> i64`**: Drains pending outbound frames for socket.
- **`fn drainable_count(tree: const TopicTree&) -> i64`**: Returns number of pending frames.
