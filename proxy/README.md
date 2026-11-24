# `proxy`

Package `proxy` (`namespace proxy;`, internal helpers in
`namespace proxy_internal;`) implements the Layer 7 reverse proxy gateway,
upstream load balancing (Round-Robin, Power of Two Choices, Least Connections,
smooth weighted round-robin, and Ketama consistent hashing), and active
background health checking for `goose-wing`.

```goose
import wing;

var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
rp.cluster.add_upstream_target("10.0.0.1", 8080, 1);
rp.cluster.add_upstream_target("10.0.0.2", 8080, 1);
```

## Public API

### 1. Reverse Proxy Gateway (`proxy/reverse_proxy.goose`, RFC 9110 §7.6)

```goose
const TARGET_NONE: i32 = -1;
enum TransportKind { PlainTcp, Http1Connect, Tls, WebSocket, WebTransport, Unknown }
enum WireReuse { Close, KeepAlive }
struct StreamRing { buf: u8[..16384], read_pos: i64, total_read: u64, total_sent: u64 }
struct UpstreamAccelControl {
    disable_buffering: bool, incremental_preferred: bool, has_accel_expires: bool,
    accel_expires_sec: i64, limit_rate_bps: u64, accel_redirect: u8[..1024]
}
struct UpstreamResponse {
    early_hints: wing::EarlyHintsResponse, has_early_hints: bool,
    accel: UpstreamAccelControl, resp: wing::Response
}
struct Config {
    strip_hop_by_hop: bool, append_forwarded: bool, emit_rfc7239_forwarded: bool,
    preserve_host: bool, trust_incoming_xff: bool, max_active_conns_per_target: i32,
    enable_rate_limiting: bool, rate_limit_rps: u64, rate_limit_burst: u64,
    forward_client_cert: bool, client_cert_der_len: i32, client_cert_der: u8[..4096],
    via_pseudonym: u8[..32], http_version: u8[..8]
}
struct ReverseProxy { ... }
fn is_forwarded_metadata_header(name: const u8[:]) -> bool
fn filter_and_forward_headers(in_headers: const wing::HeaderMap&, out_headers: wing::HeaderMap&, client_ip: const u8[:], proto: const u8[:], upstream_host: const u8[:], config: const Config&) -> bool
fn serialize_upstream_request<B>(method: const u8[:], uri: const u8[:], headers: const wing::HeaderMap&, body: const u8[:], out: B&, http_version: const u8[:] = "HTTP/1.1") -> bool
fn new_reverse_proxy(policy: LbPolicy = LbPolicy.RoundRobin) -> ReverseProxy
fn prepare_proxy_request<B>(rp: ReverseProxy&, method: const u8[:], uri: const u8[:], in_headers: const wing::HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_wire: B&) -> i32, bool
fn prepare_proxy_request_at<B>(rp: ReverseProxy&, method: const u8[:], uri: const u8[:], in_headers: const wing::HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_wire: B&, now_ns: u64) -> i32, bool
fn finish_proxy_request(rp: ReverseProxy&, target_idx: i32, success: bool)
fn complete_upstream_exchange(rp: ReverseProxy&, target_idx: i32, status_code: i32, transport_ok: bool)
fn abort_proxy_request(rp: ReverseProxy&, target_idx: i32)
fn set_proxy_rate_limit(rp: ReverseProxy&, rps: u64, burst: u64)
fn can_use_kernel_splice(kind: TransportKind, is_encrypted: bool) -> bool
fn incoming_slice(ring: const StreamRing&) -> const u8[:]
fn advance_read(ring: StreamRing&, consumed: i64) -> bool
fn compact_stream_ring(ring: StreamRing&)
fn feed_stream_chunk(ring: StreamRing&, chunk: const u8[:]) -> bool
fn forward_userspace_stream_chunk(src: StreamRing&, dst: StreamRing&, kind: TransportKind, ws_mask: u8[4]) -> i64, bool
fn park_proxy_upstream_conn(rp: ReverseProxy&, fd: i32, host: const u8[:], port: u16, tls_fingerprint: u64 = 0, nik: u64 = 0) -> bool
fn exchange_prepared_wire_on_conn(conn: wing::PooledConnection&, method: const u8[:], wire_req: const u8[:], out_resp: wing::Response&, timeout_ms: u32) -> WireReuse, bool
fn exchange_prepared_wire_on_conn_with_hints(conn: wing::PooledConnection&, method: const u8[:], wire_req: const u8[:], out_upstream: UpstreamResponse&, timeout_ms: u32) -> WireReuse, bool
fn parse_x_accel_control_header(name: const u8[:], val: const u8[:], accel: UpstreamAccelControl&) -> bool
fn try_rewrite_upstream_url<B>(url_val: const u8[:], backend_url_prefix: const u8[:], public_url_prefix: const u8[:], out: B&) -> const u8[:], bool
fn process_and_filter_upstream_response_headers<B>(in_headers: const wing::HeaderMap&, backend_url_prefix: const u8[:], public_url_prefix: const u8[:], out_headers: wing::HeaderMap&, out_location_buf: B&, accel: UpstreamAccelControl&) -> bool
fn capture_upstream_early_hints(in_resp: const wing::Response&, out_upstream: UpstreamResponse&)
fn execute_proxy_exchange(rp: ReverseProxy&, pool: wing::StreamPool&, method: const u8[:], uri: const u8[:], in_headers: const wing::HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_resp: wing::Response&, timeout_ms: u32 = 5000, now_ns: u64 = 0) -> bool
```

`ReverseProxy` sanitizes RFC 9110 §7.6 hop-by-hop headers (`Connection`,
`Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization`), appends
`Via` and `X-Forwarded-*` metadata, intercepts internal `X-Accel-*` headers into
`UpstreamAccelControl`, rewrites `Location` and `Content-Location` prefixes via
`try_rewrite_upstream_url`, and forwards RFC 8297 `103 Early Hints` frames
before the final upstream response. `StreamRing` streams payloads through a
bounded 16 KB (`u8[..16384]`) ring buffer when `can_use_kernel_splice` reports
encrypted or framed user-space transports.

### 2. Load Balancer, Circuit Breaker & Ketama Ring (`proxy/load_balancer.goose`)

```goose
enum LbPolicy { RoundRobin, RandomTwoChoice, LeastConnections, ConsistentHash }
enum UpstreamHealthState { Up, Down, Probing }
struct UpstreamTarget {
    host: u8[..64], port: u16, active_conns: i32, weight: u16,
    is_healthy: bool, health_state: UpstreamHealthState, fails: i32,
    successes: i32, healthy_threshold: i32, unhealthy_threshold: i32,
    total_requests: u64, ejected_until_ms: i64, has_explicit_thresholds: bool
}
struct UpstreamCluster {
    targets: UpstreamTarget[..16], policy: LbPolicy, rr_index: i32,
    max_fails: i32, circuit_open: bool, rng_state: u64, ketama_ring: KetamaRing
}
struct KetamaPoint { hash: u32, backend_idx: u16 }
struct KetamaRing { points: KetamaPoint[..1024] }
struct DynamicWeightEntry { effective_weight: i32, active_inflight: i32, need_drain: bool }
struct DynamicWeightBalancer {
    entries: DynamicWeightEntry[..16], max_weight_per_server: i32,
    error_penalty: i32, current_index: i32, current_weight: i32,
    max_effective_weight: i32, weight_gcd: i32
}
fn new_upstream_cluster(policy: LbPolicy = LbPolicy.RoundRobin, max_fails: i32 = 3) -> UpstreamCluster
fn add_upstream_target(cluster: UpstreamCluster&, host: const u8[:], port: u16, weight: u16 = 1) -> bool
fn next_prng(state: u64&) -> u64
fn evaluate_two_choice(target1: const UpstreamTarget&, r1: i32, target2: const UpstreamTarget&, r2: i32) -> i32
fn select_upstream(cluster: UpstreamCluster&) -> i32, bool
fn build_ketama_ring(pool: const UpstreamCluster&, ring: KetamaRing&)
fn select_consistent_backend(pool: UpstreamCluster&, ring: const KetamaRing&, key: const u8[:], now_ms: i64) -> i64, bool
fn release_upstream_connection(cluster: UpstreamCluster&, target_idx: i32)
fn record_upstream_success(cluster: UpstreamCluster&, target_idx: i32)
fn record_upstream_failure(cluster: UpstreamCluster&, target_idx: i32)
fn record_probe_result(target: UpstreamTarget&, probe_ok: bool) -> UpstreamHealthState
fn set_upstream_probing(cluster: UpstreamCluster&, target_idx: i32) -> bool
fn set_target_health_thresholds(cluster: UpstreamCluster&, target_idx: i32, healthy_thresh: i32, unhealthy_thresh: i32) -> bool
fn recompute_balancer_ratios(bal: DynamicWeightBalancer&)
fn penalize_upstream_weight(bal: DynamicWeightBalancer&, idx: i64)
fn reward_upstream_weight(bal: DynamicWeightBalancer&, idx: i64)
fn select_weighted_upstream(bal: DynamicWeightBalancer&) -> i64, bool
```

`UpstreamCluster` manages up to 16 backend targets (`UpstreamTarget[..16]`) with
per-target passive circuit breaking and active `Probing` recovery. `KetamaRing`
hashes up to 1024 virtual nodes (`KetamaPoint[..1024]`) sorted by 32-bit hash;
`select_consistent_backend` walks the ring from `key` and skips unhealthy or
outlier-ejected backends (`ejected_until_ms`). `DynamicWeightBalancer` adjusts
effective backend weights smoothly using GCD weighted round-robin.

### 3. Active Health Check Engine (`proxy/health_check.goose`, RFC 9110)

```goose
enum HealthState { Up, Down, Probing }
struct HealthCheckConfig {
    interval_ms: u64, timeout_ms: u64, healthy_threshold: u32,
    unhealthy_threshold: u32, expected_status: u16, path: u8[..64]
}
struct UpstreamHealth { ... }
struct TargetProbeSlot { ... }
struct ClusterHealthChecker { ... }
fn new_health_check_config(interval_ms: u64 = 5000, timeout_ms: u64 = 2000, healthy_thresh: u32 = 2, unhealthy_thresh: u32 = 3) -> HealthCheckConfig
fn record_probe_success(health: UpstreamHealth&, rtt_us: u32, config: const HealthCheckConfig&) -> HealthState
fn record_probe_failure(health: UpstreamHealth&, config: const HealthCheckConfig&) -> HealthState
fn enter_probing_state(health: UpstreamHealth&) -> bool
fn format_health_probe_request<B>(host: const u8[:], path: const u8[:], out: B&) -> bool
fn parse_probe_status_code(wire: const u8[:]) -> u16, bool
fn evaluate_probe_response(wire: const u8[:], expected_status: u16) -> bool
fn new_cluster_health_checker(config: HealthCheckConfig = HealthCheckConfig { .. }) -> ClusterHealthChecker
fn register_target_for_probing(checker: ClusterHealthChecker&, target_idx: i32) -> bool
fn sync_slot_from_cluster(slot: TargetProbeSlot&, cluster_state: UpstreamHealthState)
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

### 4. HTTP/2 Upstream Multiplexer (`proxy/h2_upstream.goose`, RFC 9113, RFC 7541)

```goose
enum H2UpstreamTransport { H2Tls, H2c }
enum H2UpstreamStreamEnd { OpenBody, EndStream }
enum H2UpstreamHeaderFilter { ApplyProxyFilters, DirectHeaders }
enum H2UpstreamEventKind { None, ResponseHead, ResponseData, ResponseTrailers, ResponseEnd, StreamReset, GoAway, PingAck, ProtocolError }
struct H2UpstreamConfig
struct H2UpstreamEvent
struct H2UpstreamSession

fn h2_upstream_open(cfg: H2UpstreamConfig) -> H2UpstreamSession
fn h2_upstream_close(sess: H2UpstreamSession&)
fn h2_upstream_poll_event(sess: H2UpstreamSession&, out_ev: H2UpstreamEvent&) -> bool
fn h2_upstream_drain_wire(sess: H2UpstreamSession&, out: u8[>..]&) -> i64
fn h2_upstream_open_stream(sess: H2UpstreamSession&, method: const u8[:], scheme: const u8[:], authority: const u8[:], path: const u8[:], in_headers: const http::HeaderMap&, client_ip: const u8[:], stream_end: H2UpstreamStreamEnd = H2UpstreamStreamEnd.OpenBody, header_filter: H2UpstreamHeaderFilter = H2UpstreamHeaderFilter.ApplyProxyFilters) -> u32, bool
fn h2_upstream_send_data(sess: H2UpstreamSession&, stream_id: u32, data: const u8[:], end_stream: bool) -> i64, bool
fn h2_upstream_send_trailers(sess: H2UpstreamSession&, stream_id: u32, trailers: const http::HeaderMap&) -> bool
fn h2_upstream_reset_stream(sess: H2UpstreamSession&, stream_id: u32, error_code: u32 = rfc::H2_ERR_CANCEL) -> bool
fn h2_upstream_send_ping(sess: H2UpstreamSession&, opaque_data: const u8[:]) -> bool
fn h2_upstream_send_goaway(sess: H2UpstreamSession&, error_code: u32 = rfc::H2_ERR_NO_ERROR) -> bool
fn h2_upstream_feed(sess: H2UpstreamSession&, wire_in: const u8[:]) -> bool
fn h2_upstream_can_open_stream(sess: const H2UpstreamSession&) -> bool
fn h2_upstream_active_streams(sess: const H2UpstreamSession&) -> u32
fn h2_upstream_is_draining(sess: const H2UpstreamSession&) -> bool
fn h2_upstream_validate_alpn(sess: const H2UpstreamSession&, alpn: const u8[:]) -> bool
```

`H2UpstreamSession` multiplexes client-initiated odd HTTP/2 streams (`1, 3, 5,
...`) over thread-local shared-nothing pools using generation-guarded handles.
`H2UpstreamConfig.max_frame_size` is bounded to `16384` bytes to match fixed 16
KB chunk buffers, and `h2_upstream_validate_alpn` verifies negotiated ALPN
tokens against `transport`. It preserves `te: trailers` and
`HEADER_FLAG_SENSITIVE` (`NeverIndexed`) across gRPC, Connect-RPC, full-duplex
streaming, coalesced `WINDOW_UPDATE` WAN fan-out, and graceful `GOAWAY` drain.
