# `proxy`

Layer 7 Reverse Proxy Gateway, Upstream Load Balancing, Active Background Health Checking, and Generic Cell Rate Algorithm (GCRA) Rate Limiter subsystem for `goose-wing`.

## Public API

### Reverse Proxy Gateway (`reverse_proxy.goose`, RFC 9110 §7.6)

- **`struct ProxyConfig`**: Reverse proxy gateway options (`strip_hop_by_hop`, `append_forwarded`, `preserve_host`, `trust_incoming_xff`, `max_active_conns_per_target`, `enable_rate_limiting`, `rate_limit_rps`, `rate_limit_burst`, `via_pseudonym`, `http_version`).
- **`struct ReverseProxy`**: Layer 7 gateway managing upstream cluster routing, rate limiting, concurrency backpressure, and request metrics.
- **`fn new_reverse_proxy(policy: LbPolicy = LbPolicy.RoundRobin) -> ReverseProxy`**: Initializes a reverse proxy gateway instance.
- **`fn prepare_proxy_request(proxy: ReverseProxy&, method: const u8[:], uri: const u8[:], in_headers: const HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_wire: u8[>..]&) -> i32, bool`**: Selects healthy upstream, checks rate limits and concurrency ceilings, rewrites hop-by-hop/forwarded headers, and serializes forward HTTP/1.1 wire request.
- **`fn prepare_proxy_request_at(proxy: ReverseProxy&, method: const u8[:], uri: const u8[:], in_headers: const HeaderMap&, client_ip: const u8[:], proto: const u8[:], body: const u8[:], out_wire: u8[>..]&, now_ns: u64) -> i32, bool`**: Explicit monotonic timestamp variant of `prepare_proxy_request`.
- **`fn finish_proxy_request(proxy: ReverseProxy&, target_idx: i32, success: bool)`**: Completes dispatched proxy request cleanly, releasing upstream active connection credit and updating target health.
- **`fn abort_proxy_request(proxy: ReverseProxy&, target_idx: i32)`**: Aborts in-flight request on client disconnect, timeout, or network error.
- **`fn set_proxy_rate_limit(proxy: ReverseProxy&, rps: u64, burst: u64)`**: Dynamically reconfigures gateway GCRA rate limit parameters.
- **`fn filter_and_forward_headers(in_headers: const HeaderMap&, out_headers: HeaderMap&, client_ip: const u8[:], proto: const u8[:], upstream_host: const u8[:], config: const ProxyConfig&) -> bool`**: Strips hop-by-hop headers, normalizes Content-Length/Transfer-Encoding framing, and injects `Via` and `X-Forwarded-*` metadata.
- **`fn serialize_upstream_request(method: const u8[:], uri: const u8[:], headers: const HeaderMap&, body: const u8[:], out: u8[>..]&, http_version: const u8[:] = "HTTP/1.1")`**: Serializes upstream HTTP request buffer via `wire::encode_h1_request`.

### Load Balancer & Circuit Breaker (`load_balancer.goose`)

- **`enum LbPolicy`**: Load balancing algorithm (`RoundRobin`, `RandomTwoChoice` / P2C, `LeastConnections`).
- **`enum UpstreamHealthState`**: Target health status (`Up`, `Down`, `Probing`).
- **`struct UpstreamTarget`**: Target server definition (`host: u8[..64]`, `port: u16`, `active_conns: i32`, `weight: u16`, `is_healthy: bool`, `health_state`, `fails`, `successes`, `healthy_threshold`, `unhealthy_threshold`, `total_requests`).
- **`struct UpstreamCluster`**: Bounded pool of upstream targets (`targets: UpstreamTarget[..16]`, `policy`, `circuit_open`, `max_fails`).
- **`fn new_upstream_cluster(policy: LbPolicy = LbPolicy.RoundRobin, max_fails: i32 = 3) -> UpstreamCluster`**: Initializes an upstream target cluster.
- **`fn add_upstream_target(cluster: UpstreamCluster&, host: const u8[:], port: u16, weight: u16 = 1) -> bool`**: Registers an upstream endpoint in the cluster.
- **`fn select_upstream(cluster: UpstreamCluster&) -> i32, bool`**: Evaluates policy to pick the next available healthy target, incrementing active connection count.
- **`fn release_upstream_connection(cluster: UpstreamCluster&, target_idx: i32)`**: Decrements target active connection counter.
- **`fn record_upstream_success(cluster: UpstreamCluster&, target_idx: i32)`**: Records successful response, resetting failure streaks and restoring open circuits.
- **`fn record_upstream_failure(cluster: UpstreamCluster&, target_idx: i32)`**: Records request failure, tripping circuit breaker if threshold is reached.
- **`fn set_upstream_probing(cluster: UpstreamCluster&, target_idx: i32) -> bool`**: Marks a Down target for active health verification probing.
- **`fn set_target_health_thresholds(cluster: UpstreamCluster&, target_idx: i32, healthy_thresh: i32, unhealthy_thresh: i32) -> bool`**: Configures consecutive success/failure thresholds.

### Active Health Check Engine (`health_check.goose`, RFC 9110)

- **`enum HealthState`**: Target health classification (`Up`, `Down`, `Probing`).
- **`struct HealthCheckConfig`**: Prober parameters (`interval_ms`, `timeout_ms`, `healthy_threshold`, `unhealthy_threshold`, `expected_status: u16`, `path: u8[..64]`).
- **`fn new_health_check_config(interval_ms: u64 = 5000, timeout_ms: u64 = 2000, healthy_thresh: u32 = 2, unhealthy_thresh: u32 = 3) -> HealthCheckConfig`**: Constructs prober configuration.
- **`struct UpstreamHealth`**: Probe telemetry tracking consecutive outcomes, probe timestamps, round-trip time, and total counts.
- **`fn record_probe_success(health: UpstreamHealth&, rtt_us: u32, config: const HealthCheckConfig&) -> HealthState`**: Applies probe success to health state machine.
- **`fn record_probe_failure(health: UpstreamHealth&, config: const HealthCheckConfig&) -> HealthState`**: Applies probe failure to health state machine.
- **`fn should_probe(health: const UpstreamHealth&, now_ms: u64, config: const HealthCheckConfig&) -> bool`**: Checks if target is due for background probing.
- **`fn format_health_probe_request<B>(target_host: const u8[:], config: const HealthCheckConfig&, out: B&)`**: Serializes active HTTP/1.1 probe request (`GET /healthz`).
- **`fn evaluate_probe_response(status_code: u16, config: const HealthCheckConfig&) -> bool`**: Validates probe HTTP status code against expected status.
- **`struct ClusterHealthChecker`**: Multi-target background health check coordinator.
- **`fn new_cluster_health_checker(config: HealthCheckConfig = HealthCheckConfig { .. }) -> ClusterHealthChecker`**: Initializes cluster prober.
- **`fn register_target_for_probing(checker: ClusterHealthChecker&, target_idx: i32) -> bool`**: Registers an upstream target slot for probing.
- **`fn poll_next_probe(checker: ClusterHealthChecker&, cluster: const UpstreamCluster&, now_ms: u64, out_wire: u8[>..]&) -> i32, bool`**: Drives probing lifecycle and prepares active HTTP health probe wire request.
- **`fn on_probe_success(checker: ClusterHealthChecker&, cluster: UpstreamCluster&, target_idx: i32, rtt_us: u32) -> HealthState`**: Handles active probe success, resetting failures and advancing target state machine.
- **`fn on_probe_failure(checker: ClusterHealthChecker&, cluster: UpstreamCluster&, target_idx: i32) -> HealthState`**: Handles active probe failure, advancing failure count and tripping circuit state.
- **`fn check_probe_timeouts(checker: ClusterHealthChecker&, cluster: UpstreamCluster&, now_ms: u64) -> i32`**: Sweeps timed-out active health check probes in flight.

### Generic Cell Rate Algorithm Rate Limiter (`gcra.goose`)

- **`struct GcraConfig`**: Quota parameters (`emission_interval_ns`, `tau_ns`, `max_burst`, `limit_window_ns`).
- **`fn new_gcra_config(rate_per_sec: u64, burst_capacity: u64) -> GcraConfig`**: Derives emission interval $T$ and burst headroom $\tau$ from rate and burst.
- **`fn new_gcra_config_interval(interval_ns: u64, tau_ns: u64, max_burst: u64) -> GcraConfig`**: Constructs GCRA quota from explicit nanosecond intervals.
- **`struct GcraTatCell`**: Single Theoretical Arrival Time tracking cell (`tat_ns: u64`).
- **`struct GcraDecision`**: Rate limit evaluation decision (`allowed: bool`, `remaining_burst: u64`, `retry_after_ns: u64`, `reset_after_ns: u64`, `tat_ns: u64`).
- **`fn gcra_check(config: const GcraConfig&, cell: GcraTatCell&, cost: u64, now_ns: u64) -> GcraDecision`**: Evaluates rate limit admission for cost units and advances TAT on success.
- **`fn gcra_peek(config: const GcraConfig&, cell: const GcraTatCell&, cost: u64, now_ns: u64) -> GcraDecision`**: Evaluates rate limit admission without mutating TAT cell state.
- **`fn gcra_penalize(config: const GcraConfig&, cell: GcraTatCell&, penalty_ns: u64, now_ns: u64)`**: Injects penalty delay into TAT for backpressure or abuse suppression.
- **`fn gcra_reset(cell: GcraTatCell&)`**: Clears cell TAT state.
- **`struct GatewayRateLimiter`**: Multi-client bounded table rate limiter (`config: GcraConfig`, `entries: GatewayClientEntry[..64]`, `total_allowed`, `total_rejected`).
- **`fn new_gateway_rate_limiter(rate_per_sec: u64, burst_capacity: u64) -> GatewayRateLimiter`**: Initializes gateway rate limiter.
- **`fn check_gateway_rate_limit(limiter: GatewayRateLimiter&, client_id: const u8[:], cost: u64, now_ns: u64) -> GcraDecision`**: Evaluates rate limit for a client identifier with LRU slot recycling.
- **`fn penalize_gateway_client(limiter: GatewayRateLimiter&, client_id: const u8[:], penalty_ns: u64, now_ns: u64)`**: Penalizes an abusive client identifier.
- **`fn evict_idle_gateway_clients(limiter: GatewayRateLimiter&, max_idle_ns: u64, now_ns: u64) -> i32`**: Sweeps expired idle client entries.
- **`fn reset_gateway_rate_limiter(limiter: GatewayRateLimiter&)`**: Resets all client entries and global counters.
