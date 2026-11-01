# `server`

Package `server` delivers the high-throughput, zero-allocation HTTP/1.1, HTTP/2, and WebSocket server engine of `goose-wing`. It features a linear-time Radix Tree router, a multi-stage defense-in-depth security pipeline (Slowloris protection, GCRA rate limiting, CORS/CSRF validation, encrypted session jar decoding), hardware page-ring pipelining, and both threaded (`serve`) and event-loop reactor (`serve_reactor`) architectures.

## Public API Reference

### 1. HTTP Server Lifecycle & Serving (`server/server.goose`)

Core server instance supporting thread-per-worker and share-nothing reactor event loops.

```goose
struct HttpServer {
    host:                  u8[..256]            = "127.0.0.1",
    port:                  u16                  = 8080,
    server_name:           u8[..64]             = "wing",
    pipeline:              ServerPipelineConfig = ServerPipelineConfig { .. },
    fast_path:             bool                 = false,
    trust_proxy_headers:   bool                 = false,
    accept_proxy_protocol: bool                 = false,
    max_body_size:         i64                  = 4194304, // 4 MB
}

// Constructor
fn new_http_server(host: const u8[:] = "127.0.0.1", port: u16 = 8080) -> HttpServer;

// Serving loops
// Synchronous multi-threaded blocking worker
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64;

// Single-thread epoll/WSAPoll reactor (~3.1 MB RSS footprint, 1024 concurrent slots)
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64;

// Sans-IO connection processing
fn handle_connection_wire<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
) -> PipelineOutcome, bool;
```

### 2. Radix Tree Routing (`server/router.goose`)

Zero-allocation method-isolated radix routing table with parameter extraction and RFC 3986 path canonicalization.

```goose
enum RouteMatchResult {
    Found { handler_id: i32, entries_mask: u32 },
    NotFound,
    MethodNotAllowed { allow_header: u8[..64] },
}

struct ZeroAllocParams {
    len: i64 = 0,
}

struct RadixRouter { .. }

// Router lifecycle
fn new_radix_router() -> RadixRouter;

// Route registration
fn add_route(
    router:       RadixRouter&,
    method:       const u8[:],
    path:         const u8[:],
    handler_id:   i32,
    entries_mask: u32 = 0,
) -> bool;

fn add_static_route(
    router:       RadixRouter&,
    method:       const u8[:],
    path:         const u8[:],
    content_type: const u8[:],
    body:         const u8[:],
    handler_id:   i32 = 0,
) -> bool;

// Request matching
fn match_route(
    router: const RadixRouter&,
    method: const u8[:],
    path:   const u8[:],
    params: ZeroAllocParams&,
) -> RouteMatchResult;

// Parameter extraction
fn param_val(params: const ZeroAllocParams&, idx: i64, req_path: const u8[:]) -> const u8[:];
fn param_by_name(params: const ZeroAllocParams&, name: const u8[:], req_path: const u8[:]) -> const u8[:];
```

### 3. Server Pipeline & Security Defense (`server/pipeline.goose`)

Multi-stage defense-in-depth pipeline defending against Slowloris, DoS bursts, CORS/CSRF attacks, and request smuggling.

```goose
enum PipelineOutcome {
    Handled,
    RateLimited,
    Rejected,
    ExpectFailed,
}

struct ServerPipelineConfig {
    target_host:           u8[..256]   = [],
    enable_slowloris_timer: bool       = true,
    enable_rate_limiter:   bool        = false,
    enable_cors_defense:   bool        = false,
    enable_csrf_defense:   bool        = false,
    trust_proxy_headers:   bool        = false,
    router:                RadixRouter = RadixRouter { .. },
}

fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig;
fn validate_pipeline_expect_header(req: const Request&) -> bool;
```

### 4. Route Caching (`server/cache.goose`)

Fast O(1) in-memory route cache with TTL and automatic invalidation.

```goose
enum CacheLookup {
    Hit { wire_payload: const u8[:] },
    Miss,
}

struct HttpRouteCache { .. }

fn new_http_route_cache(lower_expiry_ms: u64 = 1000, upper_expiry_ms: u64 = 5000) -> HttpRouteCache;
fn cache_lookup(c: const HttpRouteCache&, now_ms: u64) -> CacheLookup;
fn cache_store(c: HttpRouteCache&, now_ms: u64, wire_data: const u8[:]) -> bool;
fn cache_invalidate(c: HttpRouteCache&);
```

### 5. TopicTree Socket Broadcast (`server/server.goose`)

Hierarchical MQTT-style pub/sub topic tree with live socket broadcasting, batch queuing, and subscriber drainage.

```goose
struct TopicTree { .. }

fn subscribe(tree: TopicTree&, sock_fd: i64, topic: const u8[:]) -> bool;
fn unsubscribe(tree: TopicTree&, sock_fd: i64, topic: const u8[:]) -> bool;
fn publish_text(tree: const TopicTree&, topic: const u8[:], message: const u8[:]) -> i64;
fn publish_batch(tree: TopicTree&, topic: const u8[:], message: const u8[:]) -> i64;
fn drain_subscribers(tree: TopicTree&, sock_fd: i64, wire_out: u8[:]) -> i64;
fn drainable_count(tree: const TopicTree&) -> i64;
```
