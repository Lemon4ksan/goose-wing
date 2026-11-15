# `proxy`

Package `proxy` implements the Layer 7 reverse proxy gateway, upstream load
balancing (Round-Robin, Power of Two Choices, Least Connections, and Ketama
consistent hashing), active background health checking, and Generic Cell Rate
Algorithm (GCRA) rate limiting for `goose-wing`.

```goose
var rp = new_reverse_proxy(LbPolicy.RoundRobin);
add_upstream_target(rp.cluster, "10.0.0.1", 8080, 1);
add_upstream_target(rp.cluster, "10.0.0.2", 8080, 1);
```

## Public API

### 1. Reverse Proxy Gateway (`proxy/reverse_proxy.goose`, RFC 9110 §7.6)

```goose
enum ProxyTransportKind { PlaintextTcp, KernelTlsOffload, UserSpaceTls }
struct ProxyStreamRing { buf: u8[65536], read_pos: i64, write_pos: i64, total_forwarded: u64 }
struct UpstreamAccelControl {
    has_accel_redirect: bool, redirect_uri: u8[..256],
    limit_rate_bytes_sec: u64, buffering_enabled: bool, cache_expires_sec: i64
}
struct UpstreamResponse {
    early_hints_count: i32, early_hints_wire: u8[..2048],
    status_code: i32, headers: HeaderMap, body: u8[>..], accel: UpstreamAccelControl
}
struct ProxyConfig {
    strip_hop_by_hop: bool, append_forwarded: bool, preserve_host: bool,
    trust_incoming_xff: bool, max_active_conns_per_target: i32,
    enable_rate_limiting: bool, rate_limit_rps: u64, rate_limit_burst: u64,
    via_pseudonym: u8[..64], http_version: u8[..16]
}
struct ReverseProxy { ... }
fn can_use_kernel_splice(client_tp: ProxyTransportKind, upstream_tp: ProxyTransportKind) -> bool
fn incoming_slice(ring: const ProxyStreamRing&) -> const u8[:]
fn advance_read(ring: ProxyStreamRing&, consumed: i64)
fn feed_stream_chunk(ring: ProxyStreamRing&, chunk: const u8[:]) -> bool
fn forward_userspace_stream_chunk<B>(ring: ProxyStreamRing&, chunk: const u8[:], out_wire: B&) -> i64, bool
fn parse_x_accel_control_header(name: const u8[:], val: const u8[:], accel: UpstreamAccelControl&) -> bool
fn try_rewrite_upstream_url<B>(url_val: const u8[:], backend_url_prefix: const u8[:], public_url_prefix: const u8[:], out_rewritten: B&) -> bool
fn process_and_filter_upstream_response_headers(in_headers: const HeaderMap&, backend_url_prefix: const u8[:], public_url_prefix: const u8[:], out_headers: HeaderMap&, out_location_buf: u8[..512]&, accel: UpstreamAccelControl&) -> bool
fn execute_proxy_exchange(proxy: ReverseProxy&, pool: StreamPool&, method: const u8[:], uri: const u8[:], in_headers: const HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_resp: Response&, timeout_ms: u32 = 5000, now_ns: u64 = 0) -> bool
fn capture_upstream_early_hints(in_resp: const Response&, out_upstream: UpstreamResponse&)
fn new_reverse_proxy(policy: LbPolicy = LbPolicy.RoundRobin) -> ReverseProxy
fn prepare_proxy_request<B>(proxy: ReverseProxy&, method: const u8[:], uri: const u8[:], in_headers: const HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_wire: B&) -> i32, bool
fn prepare_proxy_request_at<B>(proxy: ReverseProxy&, method: const u8[:], uri: const u8[:], in_headers: const HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_wire: B&, now_ns: u64) -> i32, bool
fn exchange_prepared_wire_on_conn_with_hints<B1, B2>(proxy: ReverseProxy&, target_idx: i32, out_wire: const u8[:], now_ms: u64, client_103_out: B1&, final_resp_out: B2&) -> i32, bool
fn finish_proxy_request(proxy: ReverseProxy&, target_idx: i32, success: bool)
fn abort_proxy_request(proxy: ReverseProxy&, target_idx: i32)
fn set_proxy_rate_limit(proxy: ReverseProxy&, rps: u64, burst: u64)
fn filter_and_forward_headers(in_headers: const HeaderMap&, out_headers: HeaderMap&, client_ip: const u8[:], proto: const u8[:], upstream_host: const u8[:], config: const ProxyConfig&) -> bool
fn serialize_upstream_request<B>(method: const u8[:], uri: const u8[:], headers: const HeaderMap&, body: const u8[:], out: B&, http_version: const u8[:] = "HTTP/1.1") -> bool
```

`ReverseProxy` sanitizes RFC 9110 §7.6 hop-by-hop headers (`Connection`,
`Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization`), appends
`Via` and `X-Forwarded-*` metadata, intercepts internal `X-Accel-*` headers into
`UpstreamAccelControl`, rewrites `3xx` `Location` prefixes into a 512-byte
buffer (`u8[..512]`), and forwards RFC 8297 `103 Early Hints` frames before the
final upstream response. `ProxyStreamRing` streams large payloads through a
fixed 64 KB (`u8[65536]`) ring buffer when `can_use_kernel_splice` reports
user-space TLS on either leg.

### 2. Load Balancer, Circuit Breaker & Ketama Ring (`proxy/load_balancer.goose`)

```goose
enum LbPolicy { RoundRobin, RandomTwoChoice, LeastConnections, ConsistentHash }
enum UpstreamHealthState { Up, Down, Probing }
struct UpstreamTarget {
    host: u8[..64], port: u16, active_conns: i32, weight: u16,
    is_healthy: bool, health_state: UpstreamHealthState, fails: i32,
    successes: i32, healthy_threshold: i32, unhealthy_threshold: i32,
    total_requests: u64
}
struct UpstreamCluster {
    targets: UpstreamTarget[..16], policy: LbPolicy,
    circuit_open: bool, max_fails: i32
}
struct KetamaPoint { hash: u32, target_idx: i32 }
struct KetamaRing { points: KetamaPoint[..256], built: bool }
fn new_upstream_cluster(policy: LbPolicy = LbPolicy.RoundRobin, max_fails: i32 = 3) -> UpstreamCluster
fn add_upstream_target(cluster: UpstreamCluster&, host: const u8[:], port: u16, weight: u16 = 1) -> bool
fn select_upstream(cluster: UpstreamCluster&) -> i32, bool
fn build_ketama_ring(cluster: const UpstreamCluster&, ring: KetamaRing&, vnodes_per_weight: i32 = 8)
fn select_consistent_backend(cluster: UpstreamCluster&, ring: KetamaRing&, routing_key: const u8[:], max_load_factor: f64 = 1.25) -> i32, bool
fn release_upstream_connection(cluster: UpstreamCluster&, target_idx: i32)
fn record_upstream_success(cluster: UpstreamCluster&, target_idx: i32)
fn record_upstream_failure(cluster: UpstreamCluster&, target_idx: i32)
fn record_probe_result(cluster: UpstreamCluster&, target_idx: i32, probe_ok: bool) -> UpstreamHealthState
fn set_upstream_probing(cluster: UpstreamCluster&, target_idx: i32) -> bool
fn set_target_health_thresholds(cluster: UpstreamCluster&, target_idx: i32, healthy_thresh: i32, unhealthy_thresh: i32) -> bool
```

`UpstreamCluster` manages up to 16 backend targets (`UpstreamTarget[..16]`) with
per-target passive circuit breaking and active `Probing` recovery. `KetamaRing`
hashes up to 256 virtual nodes (`KetamaPoint[..256]`) sorted by 32-bit hash;
`select_consistent_backend` walks the ring from `routing_key` and applies
bounded-load overflow protection (`max_load_factor = 1.25`) so hot keys spill to
the next healthy node along the continuum.

### 3. Active Health Check Engine (`proxy/health_check.goose`, RFC 9110)

```goose
enum HealthState { Up, Down, Probing }
struct HealthCheckConfig {
    interval_ms: u64, timeout_ms: u64, healthy_threshold: u32,
    unhealthy_threshold: u32, expected_status: u16, path: u8[..64]
}
struct UpstreamHealth { ... }
struct ClusterHealthChecker { ... }
fn new_health_check_config(interval_ms: u64 = 5000, timeout_ms: u64 = 2000, healthy_thresh: u32 = 2, unhealthy_thresh: u32 = 3) -> HealthCheckConfig
fn record_probe_success(health: UpstreamHealth&, rtt_us: u32, config: const HealthCheckConfig&) -> HealthState
fn record_probe_failure(health: UpstreamHealth&, config: const HealthCheckConfig&) -> HealthState
fn enter_probing_state(health: UpstreamHealth&) -> bool
fn format_health_probe_request(host: const u8[:], path: const u8[:], out: u8[>..]&)
fn parse_probe_status_code(wire: const u8[:]) -> u16, bool
fn evaluate_probe_response(wire: const u8[:], expected_status: u16) -> bool
fn new_cluster_health_checker(config: HealthCheckConfig = HealthCheckConfig { .. }) -> ClusterHealthChecker
fn register_target_for_probing(checker: ClusterHealthChecker&, target_idx: i32) -> bool
fn on_probe_success(checker: ClusterHealthChecker&, cluster: UpstreamCluster&, target_idx: i32, rtt_us: u32) -> HealthState
fn on_probe_failure(checker: ClusterHealthChecker&, cluster: UpstreamCluster&, target_idx: i32) -> HealthState
fn check_probe_timeouts(checker: ClusterHealthChecker&, cluster: UpstreamCluster&, now_ms: u64) -> i32
```

`ClusterHealthChecker` schedules periodic HTTP/1.1 health probes (`GET` against
`config.path`, up to 64 bytes) across registered cluster targets, requiring
`healthy_threshold` consecutive passes to promote a `Probing` node to `Up` and
`unhealthy_threshold` consecutive failures or timeouts (`check_probe_timeouts`)
to mark a node `Down`. Gateway GCRA rate limiting (`GcraConfig`,
`GatewayRateLimiter`) lives in `security/gcra.goose`.
