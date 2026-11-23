// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Load Balancer, Upstream Health Tracking, and Circuit Breaker Engine.
// Implements Round-Robin, Power-of-Two-Random (P2C), Least-Connections, and Ketama balancing.
namespace proxy;

import std;
import core;
import .internal;

enum LbPolicy {
    RoundRobin,
    RandomTwoChoice,
    LeastConnections,
    ConsistentHash,
    WeightedRoundRobin,
}

struct KetamaPoint {
    hash:        u32 = 0,
    backend_idx: u16 = 0,
}

struct KetamaRing {
    points: KetamaPoint[..1024] = [],
}

enum UpstreamHealthState {
    Up,
    Down,
    Probing,
}

struct UpstreamTarget {
    host:                    u8[..128]           = [],
    port:                    u16                 = 80,
    active_conns:            i32                 = 0,
    weight:                  u16                 = 1,
    is_healthy:              bool                = true,
    health_state:            UpstreamHealthState = UpstreamHealthState.Up,
    fails:                   i32                 = 0,
    successes:               i32                 = 0,
    healthy_threshold:       i32                 = 2,
    unhealthy_threshold:     i32                 = 3,
    total_requests:          u64                 = 0,
    ejected_until_ms:        i64                 = 0,
    has_explicit_thresholds: bool                = false,
    draining:                bool                = false,
    use_tls:                 bool                = false,
    sni_host:                u8[..128]           = [],
    wrr_current_weight:      i32                 = 0,
}

struct UpstreamCluster {
    targets:      UpstreamTarget[..16] = [],
    policy:       LbPolicy             = LbPolicy.RoundRobin,
    rr_index:     i32                  = 0,
    max_fails:    i32                  = 3,
    circuit_open: bool                 = false,
    rng_state:    u64                  = 0x123456789abcdef0,
    ketama_ring:  KetamaRing           = KetamaRing { .. },
}

fn new_upstream_cluster(policy: LbPolicy = LbPolicy.RoundRobin, max_fails: i32 = 3) -> UpstreamCluster {
    let t_ns = core::as_nanos(core::monotonic_now());
    let seed = if t_ns != 0 { t_ns ^ 0x123456789abcdef0 } else { 0x123456789abcdef0 };
    return UpstreamCluster {
        policy:       policy,
        max_fails:    max(max_fails, 0),
        circuit_open: false,
        rng_state:    seed,
        ..
    };
}

// Registers an upstream backend target with optional TLS and SNI override configuration.
fn add_upstream_target_tls(
    cluster:  UpstreamCluster&,
    host:     const u8[:],
    port:     u16,
    weight:   u16,
    use_tls:  bool,
    sni_host: const u8[:],
) -> bool {
    guard port > 0 && proxy_internal::is_valid_upstream_host(host) else { return false; }
    if sni_host.len > 0 {
        guard proxy_internal::is_valid_upstream_host(sni_host) else { return false; }
    }

    var target = UpstreamTarget {
        port:       port,
        weight:     max(weight, 1),
        is_healthy: true,
        use_tls:    use_tls,
        ..
    };
    guard target.host.try_set(host) else { return false; }
    guard target.sni_host.try_set(sni_host) else { return false; }
    guard cluster.targets.try_push(target) else { return false; }
    proxy_internal::update_cluster_circuit_state(cluster);
    if cluster.policy == LbPolicy.ConsistentHash {
        build_ketama_ring(cluster, cluster.ketama_ring);
    }
    return true;
}

fn add_upstream_target(cluster: UpstreamCluster&, host: const u8[:], port: u16, weight: u16 = 1) -> bool {
    return add_upstream_target_tls(cluster, host, port, weight, false, "");
}

// 64-bit LCG pseudo-random generator with Knuth MMIX multiplier.
inline fn next_prng(state: u64&) -> u64 {
    let lo, _ = core::mul_wide_u64(state, 6364136223846793005);
    let s = lo ^ 1442695040888963407;
    state = s;
    return s;
}

inline fn evaluate_two_choice(
    target1: const UpstreamTarget&,
    r1:      i32,
    target2: const UpstreamTarget&,
    r2:      i32,
) -> i32 {
    let w1 = max(target1.weight as u64, 1);
    let w2 = max(target2.weight as u64, 1);
    let load1 = core::mul_sat_u64(target1.active_conns as u64, w2);
    let load2 = core::mul_sat_u64(target2.active_conns as u64, w1);
    return if load1 <= load2 { r1 } else { r2 };
}

// Selects next healthy upstream target index according to configured LbPolicy and optional routing key.
fn select_upstream_with_key(cluster: UpstreamCluster&, hash_key: const u8[:]) -> i32, bool {
    guard !cluster.circuit_open else { return proxy_internal::NO_UPSTREAM_TARGET, false; }
    let n = cluster.targets.len as i32;
    guard n > 0 else { return proxy_internal::NO_UPSTREAM_TARGET, false; }

    if cluster.policy == LbPolicy.RoundRobin {
        return proxy_internal::select_round_robin(cluster, n);
    }
    if cluster.policy == LbPolicy.LeastConnections {
        return proxy_internal::select_least_connections(cluster, n);
    }
    if cluster.policy == LbPolicy.WeightedRoundRobin {
        return proxy_internal::select_weighted_rr(cluster, n);
    }
    if cluster.policy == LbPolicy.ConsistentHash {
        if cluster.ketama_ring.points.len == 0 {
            build_ketama_ring(cluster, cluster.ketama_ring);
        }
        if hash_key.len == 0 {
            return proxy_internal::select_round_robin(cluster, n);
        }
        let now_ms = proxy_internal::current_monotonic_ms();
        let idx64, ok_ch = select_consistent_backend(cluster, cluster.ketama_ring, hash_key, now_ms);
        guard ok_ch else { return proxy_internal::NO_UPSTREAM_TARGET, false; }
        return idx64 as i32, true;
    }
    return proxy_internal::select_p2c(cluster, n);
}

// Selects next healthy upstream target index according to configured LbPolicy.
fn select_upstream(cluster: UpstreamCluster&) -> i32, bool {
    return select_upstream_with_key(cluster, "");
}

// Marks target `target_idx` as draining or active without dropping in-flight connections.
fn set_target_draining(cluster: UpstreamCluster&, target_idx: i32, draining: bool) -> bool {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return false; }
    cluster.targets[target_idx].draining = draining;
    proxy_internal::update_cluster_circuit_state(cluster);
    return true;
}

// Updates target `target_idx` weight, resets WRR accumulator state, and rebuilds Ketama ring if active.
fn set_target_weight(cluster: UpstreamCluster&, target_idx: i32, weight: u16) -> bool {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return false; }
    cluster.targets[target_idx].weight = max(weight, 1);
    for &t in cluster.targets {
        t.wrr_current_weight = 0;
    }
    if cluster.policy == LbPolicy.ConsistentHash {
        build_ketama_ring(cluster, cluster.ketama_ring);
    }
    return true;
}

// Removes target at `target_idx`, shifting remaining targets in order and updating ring/circuit state.
fn remove_upstream_target(cluster: UpstreamCluster&, target_idx: i32) -> bool {
    let n = cluster.targets.len;
    guard target_idx >= 0 && target_idx < n else { return false; }
    var i = target_idx as i64;
    let last = core::sub_sat_i64(n, 1);
    while i < last {
        let next_i = core::add_sat_i64(i, 1);
        cluster.targets[i] = cluster.targets[next_i];
        i = next_i;
    }
    cluster.targets.resize(last);
    for &t in cluster.targets {
        t.wrr_current_weight = 0;
    }
    if last == 0 {
        cluster.rr_index = 0;
    } else if cluster.rr_index > target_idx {
        cluster.rr_index = core::sub_sat_i64(cluster.rr_index, 1) as i32;
    }
    if cluster.rr_index < 0 || cluster.rr_index >= (last as i32) {
        cluster.rr_index = 0;
    }
    if cluster.policy == LbPolicy.ConsistentHash {
        build_ketama_ring(cluster, cluster.ketama_ring);
    }
    proxy_internal::update_cluster_circuit_state(cluster);
    return true;
}

// Releases an active connection for an upstream target upon response completion.
fn release_upstream_connection(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    proxy_internal::dec_active_conns(cluster.targets[target_idx]);
}

// Records an active or passive health probe result on `target` and evaluates flapping hysteresis.
// Requires `unhealthy_threshold` consecutive failures to trip Down, and `healthy_threshold`
// consecutive successes in Half-Open (`Probing`) state to close the circuit back to Up.
fn record_probe_result(target: UpstreamTarget&, probe_ok: bool) -> UpstreamHealthState {
    if probe_ok {
        target.fails = 0;
        let _ = proxy_internal::inc_target_successes(target);
    } else {
        target.successes = 0;
        let _ = proxy_internal::inc_target_fails(target);
        if target.health_state == UpstreamHealthState.Probing {
            target.health_state = UpstreamHealthState.Down;
            target.is_healthy = false;
            return target.health_state;
        }
    }
    let _ = proxy_internal::evaluate_circuit_breaker(target, 0);
    return target.health_state;
}

// Records success, clearing failure streak and restoring circuit if applicable.
fn record_upstream_success(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    let target .= cluster.targets[target_idx];
    target.fails = 0;
    let s = proxy_internal::inc_target_successes(target);

    let target_h = max(target.healthy_threshold, 1);
    let healthy_thresh = if !target.has_explicit_thresholds && cluster.max_fails > 0 {
        1
    } else {
        target_h
    };

    if target.health_state == UpstreamHealthState.Probing {
        if s >= healthy_thresh {
            target.health_state = UpstreamHealthState.Up;
            target.is_healthy = true;
            cluster.circuit_open = false;
        }
    } else if target.health_state == UpstreamHealthState.Down {
        if s >= healthy_thresh {
            target.health_state = UpstreamHealthState.Up;
            target.is_healthy = true;
            cluster.circuit_open = false;
        } else {
            target.health_state = UpstreamHealthState.Probing;
            cluster.circuit_open = false;
        }
    } else {
        target.health_state = UpstreamHealthState.Up;
        target.is_healthy = true;
        cluster.circuit_open = false;
    }
}

// Records connection or timeout failure, tripping circuit breaker if ceiling reached.
fn record_upstream_failure(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    let target .= cluster.targets[target_idx];
    target.successes = 0;
    let fails = proxy_internal::inc_target_fails(target);

    let target_u = if target.unhealthy_threshold > 0 {
        target.unhealthy_threshold
    } else {
        3
    };
    let max_f = if target.has_explicit_thresholds {
        target_u
    } else if cluster.max_fails > 0 {
        cluster.max_fails
    } else {
        target_u
    };
    if fails >= max_f || target.health_state == UpstreamHealthState.Probing {
        target.health_state = UpstreamHealthState.Down;
        target.is_healthy = false;
    }
    proxy_internal::update_cluster_circuit_state(cluster);
}

// Transitions a Down target to Probing state for active health check verification.
fn set_upstream_probing(cluster: UpstreamCluster&, target_idx: i32) -> bool {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return false; }
    let target .= cluster.targets[target_idx];
    guard target.health_state == UpstreamHealthState.Down else { return false; }
    target.health_state = UpstreamHealthState.Probing;
    target.successes = 0;
    cluster.circuit_open = false;
    return true;
}

// Configures target-specific consecutive healthy and unhealthy thresholds.
fn set_target_health_thresholds(
    cluster:          UpstreamCluster&,
    target_idx:       i32,
    healthy_thresh:   i32,
    unhealthy_thresh: i32,
) -> bool {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return false; }
    let target .= cluster.targets[target_idx];
    target.healthy_threshold = max(healthy_thresh, 1);
    target.unhealthy_threshold = max(unhealthy_thresh, 1);
    target.has_explicit_thresholds = true;
    return true;
}

// ---- Ketama Consistent Hashing Continuum (Pingora Parity) -----------------

// Builds a Pingora-compatible Ketama consistent hashing continuum from `pool.targets`.
fn build_ketama_ring(pool: const UpstreamCluster&, ring: KetamaRing&) {
    ring.points.clear();
    let n = pool.targets.len;
    guard n > 0 else { return; }
    var total_weight: i64 = 0;
    for &t in pool.targets {
        total_weight = core::add_sat_i64(total_weight, max(t.weight as i64, 1));
    }
    let ring_cap = ring.points.cap;
    for &target, idx in pool.targets {
        let w = max(target.weight as i64, 1);
        let num_pts = proxy_internal::calc_ketama_target_points(w, total_weight, n, ring_cap);
        var base_key: u8[..160] = [];
        guard base_key.try_append(target.host[..]) && base_key.try_push(0) else { continue; }
        target.port.format_u64_dec(base_key);
        let base_crc = core::crc32(base_key[..]);
        var prev_hash: u32 = 0;
        for _ in num_pts {
            var le_bytes: u8[4] = [
                (prev_hash & 0xFF) as u8,
                ((prev_hash >> 8) & 0xFF) as u8,
                ((prev_hash >> 16) & 0xFF) as u8,
                ((prev_hash >> 24) & 0xFF) as u8,
            ];
            let h = core::crc32_update(base_crc, le_bytes[..]);
            proxy_internal::insert_ketama_point(ring, KetamaPoint { hash: h, backend_idx: idx as u16 });
            prev_hash = h;
        }
    }
}

// Selects a routable backend from `pool` via Ketama consistent hashing over `key`,
// stepping clockwise on the ring if the primary node is unhealthy or ejected.
fn select_consistent_backend(
    pool:   UpstreamCluster&,
    ring:   const KetamaRing&,
    key:    const u8[:],
    now_ms: i64,
) -> i64, bool {
    guard !pool.circuit_open && pool.targets.len > 0 && ring.points.len > 0 else {
        return proxy_internal::NO_UPSTREAM_TARGET, false;
    }
    let key_hash = core::crc32(key);
    let ring_len = ring.points.len as u64;
    var ring_idx = proxy_internal::find_ketama_start_idx(ring, key_hash) as u64;
    for _ in (ring_len as i64) {
        let b_idx = ring.points[ring_idx as i64].backend_idx as i64;
        if b_idx >= 0 && b_idx < pool.targets.len {
            if proxy_internal::is_backend_routable(pool.targets[b_idx], now_ms) {
                proxy_internal::record_target_dispatch(pool.targets[b_idx]);
                return b_idx, true;
            }
        }
        let next_idx = core::add_sat_u64(ring_idx, 1);
        ring_idx = if next_idx >= ring_len { 0 } else { next_idx };
    }
    return proxy_internal::NO_UPSTREAM_TARGET, false;
}

// ---- Dynamic Error-Penalty Weighted Balancer (Smooth GCD WRR) --------------

struct DynamicWeightEntry {
    effective_weight: i32  = 100,
    active_inflight:  i32  = 0,
    need_drain:       bool = false,
}

struct DynamicWeightBalancer {
    entries:               DynamicWeightEntry[..16] = [],
    max_weight_per_server: i32                      = 100,
    error_penalty:         i32                      = 15,
    current_index:         i32                      = -1,
    current_weight:        i32                      = 0,
    max_effective_weight:  i32                      = 100,
    weight_gcd:            i32                      = 100,
}

fn recompute_balancer_ratios(bal: DynamicWeightBalancer&) {
    guard bal.entries.len > 0 else {
        bal.max_effective_weight = 0;
        bal.weight_gcd = 1;
        return;
    }
    var g: i32 = 0;
    var m: i32 = 0;
    for &e in bal.entries {
        if !e.need_drain {
            let w = max(e.effective_weight, 1);
            g = if g == 0 { w } else { proxy_internal::gcd_positive_i32(g, w) };
            m = max(m, w);
        }
    }
    bal.weight_gcd = max(g, 1);
    bal.max_effective_weight = m;
    if bal.current_weight > m {
        bal.current_weight = m;
    }
}

// Penalizes an upstream on socket or connect error without abruptly dropping weight to 0.
fn penalize_upstream_weight(bal: DynamicWeightBalancer&, idx: i64) {
    guard idx >= 0 && idx < bal.entries.len else { return; }
    let penalty = max(bal.error_penalty, 1);
    let reduced = core::sub_sat_i64(bal.entries[idx].effective_weight, penalty);
    bal.entries[idx].effective_weight = max(reduced as i32, 1);
    recompute_balancer_ratios(bal);
}

// Restores upstream weight incrementally upon a healthy connection or exchange.
fn reward_upstream_weight(bal: DynamicWeightBalancer&, idx: i64) {
    guard idx >= 0 && idx < bal.entries.len else { return; }
    let step = max(bal.error_penalty, 1);
    let cap = max(bal.max_weight_per_server, 1);
    let raised = core::add_sat_i64(bal.entries[idx].effective_weight, step);
    bal.entries[idx].effective_weight = min(raised as i32, cap);
    recompute_balancer_ratios(bal);
}

// Selects the next non-draining upstream index via GCD weighted round-robin.
fn select_weighted_upstream(bal: DynamicWeightBalancer&) -> i64, bool {
    recompute_balancer_ratios(bal);
    let n = bal.entries.len;
    guard n > 0 && bal.max_effective_weight > 0 else { return -1, false; }
    let max_iters = core::add_sat_u64(core::mul_sat_u64(n as u64, bal.max_effective_weight as u64), n as u64) as i64;
    for _ in max_iters {
        let idx = proxy_internal::step_weighted_round_robin(bal, n as i32);
        guard idx >= 0 && idx < bal.entries.len else { return -1, false; }
        let cand .= bal.entries[idx];
        if cand.effective_weight >= bal.current_weight && !cand.need_drain {
            return idx, true;
        }
    }
    return -1, false;
}
