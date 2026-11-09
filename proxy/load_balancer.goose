// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Load Balancer, Upstream Health Tracking, and Circuit Breaker Engine.
// Implements Round-Robin, Power-of-Two-Random (P2C), and Least-Connections balancing.
namespace wing;

import std;
import core from "..";

const NO_UPSTREAM_TARGET: i32 = -1;

enum LbPolicy {
    RoundRobin,
    RandomTwoChoice,
    LeastConnections,
    ConsistentHash,
}

enum LbStrategy {
    RoundRobin,
    RandomTwoChoice,
    LeastConnections,
    ConsistentHash,
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
    host:                u8[..64]            = [],
    port:                u16                 = 80,
    active_conns:        i32                 = 0,
    weight:              u16                 = 1,
    is_healthy:          bool                = true,
    health_state:        UpstreamHealthState = UpstreamHealthState.Up,
    fails:               i32                 = 0,
    successes:           i32                 = 0,
    healthy_threshold:   i32                 = 2,
    unhealthy_threshold: i32                 = 3,
    total_requests:      u64                 = 0,
    ejected_until_ms:    i64                 = 0,
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
    return UpstreamCluster {
        policy:       policy,
        max_fails:    max_fails,
        circuit_open: false,
        ..
    };
}

fn add_upstream_target(cluster: UpstreamCluster&, host: const u8[:], port: u16, weight: u16 = 1) -> bool {
    guard host.len > 0 else { return false; }

    var target = UpstreamTarget {
        port:       port,
        weight:     max(weight, 1),
        is_healthy: true,
        ..
    };
    guard target.host.try_set(host) else { return false; }
    guard cluster.targets.try_push(target) else { return false; }
    if cluster.policy == LbPolicy.ConsistentHash {
        build_ketama_ring(cluster, cluster.ketama_ring);
    }
    return true;
}

// 64-bit LCG pseudo-random generator with Knuth MMIX multiplier
inline fn next_prng(state: u64&) -> u64 {
    let lo, _ = core::mul_wide_u64(state, 6364136223846793005);
    let s = lo ^ 1442695040888963407;
    state = s;
    return s;
}

inline fn inc_active_conns(target: UpstreamTarget&) {
    target.active_conns = (core::add_sat_u64(target.active_conns as u64, 1)) as i32;
}

inline fn inc_total_requests(target: UpstreamTarget&) {
    target.total_requests = core::add_sat_u64(target.total_requests, 1);
}

inline fn record_target_dispatch(target: UpstreamTarget&) {
    inc_active_conns(target);
    inc_total_requests(target);
}

inline fn advance_rr_index(cur_rr: i32, n: i32) -> i32 {
    let next_rr = (core::add_sat_u64(cur_rr as u64, 1)) as i32;
    return if next_rr >= n { 0 } else { next_rr };
}

inline fn is_target_selectable(target: const UpstreamTarget&) -> bool {
    return target.is_healthy || target.health_state == UpstreamHealthState.Probing;
}

// Selects next healthy upstream via Round-Robin.
fn select_round_robin(cluster: UpstreamCluster&, n: i32) -> i32, bool {
    for _ in n {
        let idx = cluster.rr_index;
        cluster.rr_index = advance_rr_index(cluster.rr_index, n);

        if is_target_selectable(cluster.targets[idx]) {
            record_target_dispatch(cluster.targets[idx]);
            return idx, true;
        }
    }
    return NO_UPSTREAM_TARGET, false;
}

inline fn evaluate_two_choice(target1: const UpstreamTarget&, r1: i32, target2: const UpstreamTarget&, r2: i32) -> i32 {
    let w1 = max(target1.weight as u64, 1);
    let w2 = max(target2.weight as u64, 1);
    let load1 = core::mul_sat_u64(target1.active_conns as u64, w2);
    let load2 = core::mul_sat_u64(target2.active_conns as u64, w1);
    return if load1 <= load2 { r1 } else { r2 };
}

// Finds healthy target with least active connections weighted by target capacity.
fn find_least_conn_target(cluster: const UpstreamCluster&, n: i32) -> i32 {
    var best_idx: i32 = NO_UPSTREAM_TARGET;

    for i in n {
        guard is_target_selectable(cluster.targets[i]) else { continue; }
        if best_idx == NO_UPSTREAM_TARGET {
            best_idx = i;
        } else {
            best_idx = evaluate_two_choice(cluster.targets[best_idx], best_idx, cluster.targets[i], i);
        }
    }
    return best_idx;
}

// Selects next healthy upstream via Least-Connections.
fn select_least_connections(cluster: UpstreamCluster&, n: i32) -> i32, bool {
    let best_idx = find_least_conn_target(cluster, n);
    if best_idx >= 0 {
        record_target_dispatch(cluster.targets[best_idx]);
        return best_idx, true;
    }
    return NO_UPSTREAM_TARGET, false;
}

// Fast Lemire reduction without division or modulo
inline fn pick_random_index(cluster: UpstreamCluster&, n: i32) -> i32 {
    let r_val = next_prng(cluster.rng_state);
    return (((r_val & 0xFFFFFFFF) * (n as u64)) >> 32) as i32;
}

fn pick_two_distinct(cluster: UpstreamCluster&, n: i32) -> i32, i32 {
    let r1 = pick_random_index(cluster, n);
    var r2 = pick_random_index(cluster, n);
    if r2 == r1 {
        r2 = advance_rr_index(r1, n);
    }
    return r1, r2;
}

// Selects next healthy upstream via Power-of-Two-Random-Choices (P2C).
fn select_p2c(cluster: UpstreamCluster&, n: i32) -> i32, bool {
    if n == 1 {
        if is_target_selectable(cluster.targets[0]) {
            record_target_dispatch(cluster.targets[0]);
            return 0, true;
        }
        return NO_UPSTREAM_TARGET, false;
    }

    let r1, r2 = pick_two_distinct(cluster, n);
    let h1 = is_target_selectable(cluster.targets[r1]);
    let h2 = is_target_selectable(cluster.targets[r2]);

    if h1 && h2 {
        let chosen = evaluate_two_choice(cluster.targets[r1], r1, cluster.targets[r2], r2);
        record_target_dispatch(cluster.targets[chosen]);
        return chosen, true;
    }
    if h1 {
        record_target_dispatch(cluster.targets[r1]);
        return r1, true;
    }
    if h2 {
        record_target_dispatch(cluster.targets[r2]);
        return r2, true;
    }
    // Fallback to least-connections scan when both random choices are unhealthy
    // to prevent dropping traffic when other cluster targets remain healthy.
    return select_least_connections(cluster, n);
}

// Selects next healthy upstream target index according to configured LbPolicy.
fn select_upstream(cluster: UpstreamCluster&) -> i32, bool {
    guard !cluster.circuit_open else { return NO_UPSTREAM_TARGET, false; }
    let n = cluster.targets.len as i32;
    guard n > 0 else { return NO_UPSTREAM_TARGET, false; }

    if cluster.policy == LbPolicy.RoundRobin {
        return select_round_robin(cluster, n);
    }
    if cluster.policy == LbPolicy.LeastConnections {
        return select_least_connections(cluster, n);
    }
    if cluster.policy == LbPolicy.ConsistentHash {
        if cluster.ketama_ring.points.len == 0 {
            build_ketama_ring(cluster, cluster.ketama_ring);
        }
        let idx64, ok_ch = select_consistent_backend(cluster, cluster.ketama_ring, "default", 0);
        if ok_ch {
            return idx64 as i32, true;
        }
    }
    return select_p2c(cluster, n);
}

inline fn dec_active_conns(target: UpstreamTarget&) {
    let cur = target.active_conns;
    guard cur > 0 else { return; }
    target.active_conns = (core::sub_sat_u64(cur as u64, 1)) as i32;
}

// Releases an active connection for an upstream target upon response completion.
fn release_upstream_connection(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    dec_active_conns(cluster.targets[target_idx]);
}

inline fn inc_target_successes(target: UpstreamTarget&) -> i32 {
    let s = (core::add_sat_u64(target.successes as u64, 1)) as i32;
    target.successes = s;
    return s;
}

// Evaluates target circuit breaker state against consecutive healthy/unhealthy thresholds (haproxy hysteresis).
fn evaluate_circuit_breaker(target: UpstreamTarget&, max_fails_override: i32 = 0) -> bool {
    let unhealthy_thresh = if target.unhealthy_threshold > 0 {
        target.unhealthy_threshold
    } else if max_fails_override > 0 {
        max_fails_override
    } else {
        3
    };
    let healthy_thresh = if target.healthy_threshold > 0 { target.healthy_threshold } else { 2 };

    if target.fails >= unhealthy_thresh {
        target.health_state = UpstreamHealthState.Down;
        target.is_healthy = false;
        return false;
    }

    if target.health_state == UpstreamHealthState.Down {
        if target.successes > 0 {
            target.health_state = UpstreamHealthState.Probing;
        } else {
            target.is_healthy = false;
            return false;
        }
    }

    if target.health_state == UpstreamHealthState.Probing {
        if target.successes >= healthy_thresh {
            target.health_state = UpstreamHealthState.Up;
            target.is_healthy = true;
            return true;
        }
        target.is_healthy = false;
        return false;
    }

    target.health_state = UpstreamHealthState.Up;
    target.is_healthy = true;
    return true;
}

// Records an active or passive health probe result on `target` and evaluates flapping hysteresis.
// Requires `unhealthy_threshold` consecutive failures to trip Down, and `healthy_threshold`
// consecutive successes in Half-Open (`Probing`) state to close the circuit back to Up.
fn record_probe_result(target: UpstreamTarget&, probe_ok: bool) -> UpstreamHealthState {
    if probe_ok {
        target.fails = 0;
        let _ = inc_target_successes(target);
    } else {
        target.successes = 0;
        let _ = inc_target_fails(target);
        if target.health_state == UpstreamHealthState.Probing {
            target.health_state = UpstreamHealthState.Down;
            target.is_healthy = false;
            return target.health_state;
        }
    }
    let _ = evaluate_circuit_breaker(target, 0);
    return target.health_state;
}

// Records success, clearing failure streak and restoring circuit if applicable.
fn record_upstream_success(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    cluster.targets[target_idx].fails = 0;
    let s = inc_target_successes(cluster.targets[target_idx]);

    let healthy_thresh = max(cluster.targets[target_idx].healthy_threshold, 1);

    if cluster.targets[target_idx].health_state == UpstreamHealthState.Probing {
        if s >= healthy_thresh {
            cluster.targets[target_idx].health_state = UpstreamHealthState.Up;
            cluster.targets[target_idx].is_healthy = true;
            cluster.circuit_open = false;
        }
    } else if cluster.targets[target_idx].health_state == UpstreamHealthState.Down {
        if s >= healthy_thresh || cluster.max_fails > 0 {
            cluster.targets[target_idx].health_state = UpstreamHealthState.Up;
            cluster.targets[target_idx].is_healthy = true;
            cluster.circuit_open = false;
        } else {
            cluster.targets[target_idx].health_state = UpstreamHealthState.Probing;
            cluster.circuit_open = false;
        }
    } else {
        cluster.targets[target_idx].health_state = UpstreamHealthState.Up;
        cluster.targets[target_idx].is_healthy = true;
        cluster.circuit_open = false;
    }
}

fn update_cluster_circuit_state(cluster: UpstreamCluster&) {
    var any_healthy = false;
    for &t in cluster.targets {
        if is_target_selectable(t) {
            any_healthy = true;
            break;
        }
    }
    if !any_healthy {
        cluster.circuit_open = true;
    }
}

inline fn inc_target_fails(target: UpstreamTarget&) -> i32 {
    let fails = (core::add_sat_u64(target.fails as u64, 1)) as i32;
    target.fails = fails;
    return fails;
}

// Records connection or timeout failure, tripping circuit breaker if ceiling reached.
fn record_upstream_failure(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    cluster.targets[target_idx].successes = 0;
    let fails = inc_target_fails(cluster.targets[target_idx]);

    let max_f = if cluster.max_fails > 0 {
        cluster.max_fails
    } else {
        cluster.targets[target_idx].unhealthy_threshold
    };
    if fails >= max_f || cluster.targets[target_idx].health_state == UpstreamHealthState.Probing {
        cluster.targets[target_idx].health_state = UpstreamHealthState.Down;
        cluster.targets[target_idx].is_healthy = false;
    }
    update_cluster_circuit_state(cluster);
}

// Transitions a Down target to Probing state for active health check verification.
fn set_upstream_probing(cluster: UpstreamCluster&, target_idx: i32) -> bool {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return false; }
    guard cluster.targets[target_idx].health_state == UpstreamHealthState.Down else { return false; }
    cluster.targets[target_idx].health_state = UpstreamHealthState.Probing;
    cluster.targets[target_idx].successes = 0;
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
    cluster.targets[target_idx].healthy_threshold = max(healthy_thresh, 1);
    cluster.targets[target_idx].unhealthy_threshold = max(unhealthy_thresh, 1);
    return true;
}

// ---- Ketama Consistent Hashing Continuum (Pingora Parity) -----------------

const KETAMA_POINTS_PER_WEIGHT: u32 = 16;

// Checks whether a backend target is healthy/probing and not outlier-ejected at `now_ms`.
inline fn is_backend_routable(target: const UpstreamTarget&, now_ms: i64) -> bool {
    if target.ejected_until_ms > 0 && now_ms < target.ejected_until_ms {
        return false;
    }
    return is_target_selectable(target);
}

// Inserts `pt` into sorted `ring.points`, deduplicating identical 32-bit hash positions.
fn insert_ketama_point(ring: KetamaRing&, pt: KetamaPoint) {
    var lo: u64 = 0;
    var hi: u64 = ring.points.len as u64;
    while lo < hi {
        let mid = core::add_sat_u64(lo, core::sub_sat_u64(hi, lo) >> 1);
        let cur = ring.points[mid as i64].hash;
        if cur == pt.hash {
            return;
        }
        if cur < pt.hash {
            lo = core::add_sat_u64(mid, 1);
        } else {
            hi = mid;
        }
    }
    guard ring.points.try_push(pt) else { return; }
    var pos: u64 = core::sub_sat_u64(ring.points.len as u64, 1);
    while pos > lo {
        let prev = core::sub_sat_u64(pos, 1);
        ring.points[pos as i64] = ring.points[prev as i64];
        pos = prev;
    }
    ring.points[lo as i64] = pt;
}

// Builds a Pingora-compatible Ketama consistent hashing continuum from `pool.targets`.
fn build_ketama_ring(pool: const UpstreamCluster&, ring: KetamaRing&) {
    ring.points.clear();
    for idx in pool.targets.len {
        let target = pool.targets[idx];
        let w = max(target.weight as u32, 1);
        let num_pts = core::mul_sat_u64(w, KETAMA_POINTS_PER_WEIGHT) as i64;
        var base_key: u8[..96] = [];
        base_key.append(target.host[..]);
        base_key.push(0);
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
            insert_ketama_point(ring, KetamaPoint { hash: h, backend_idx: idx as u16 });
            prev_hash = h;
        }
    }
}

// Binary-searches `ring.points` for the first point with `hash >= key_hash`, wrapping to index 0.
fn find_ketama_start_idx(ring: const KetamaRing&, key_hash: u32) -> i64 {
    var lo: u64 = 0;
    var hi: u64 = ring.points.len as u64;
    while lo < hi {
        let mid = core::add_sat_u64(lo, core::sub_sat_u64(hi, lo) >> 1);
        let cur = ring.points[mid as i64].hash;
        if cur < key_hash {
            lo = core::add_sat_u64(mid, 1);
        } else {
            hi = mid;
        }
    }
    if lo >= (ring.points.len as u64) {
        return 0;
    }
    return lo as i64;
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
        return NO_UPSTREAM_TARGET, false;
    }
    let key_hash = core::crc32(key);
    let ring_len = ring.points.len as u64;
    var ring_idx = find_ketama_start_idx(ring, key_hash) as u64;
    for _ in (ring_len as i64) {
        let b_idx = ring.points[ring_idx as i64].backend_idx as i64;
        if b_idx >= 0 && b_idx < pool.targets.len {
            if is_backend_routable(pool.targets[b_idx], now_ms) {
                record_target_dispatch(pool.targets[b_idx]);
                return b_idx, true;
            }
        }
        let next_idx = core::add_sat_u64(ring_idx, 1);
        ring_idx = if next_idx >= ring_len { 0 } else { next_idx };
    }
    return NO_UPSTREAM_TARGET, false;
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

fn gcd_positive_i32(a_in: i32, b_in: i32) -> i32 {
    var a = max(a_in, 1);
    var b = max(b_in, 1);
    while a != b {
        if a > b {
            a = core::sub_sat_i64(a, b) as i32;
        } else {
            b = core::sub_sat_i64(b, a) as i32;
        }
    }
    return max(a, 1);
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
            g = if g == 0 { w } else { gcd_positive_i32(g, w) };
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

inline fn step_weighted_round_robin(bal: DynamicWeightBalancer&, n: i32) -> i64 {
    let next_idx = core::add_sat_i64(bal.current_index, 1) as i32;
    bal.current_index = if next_idx >= n || next_idx < 0 { 0 } else { next_idx };
    if bal.current_index == 0 {
        bal.current_weight = core::sub_sat_i64(bal.current_weight, bal.weight_gcd) as i32;
        if bal.current_weight <= 0 {
            bal.current_weight = bal.max_effective_weight;
        }
    }
    return bal.current_index;
}

// Selects the next non-draining upstream index via GCD weighted round-robin.
fn select_weighted_upstream(bal: DynamicWeightBalancer&) -> i64, bool {
    recompute_balancer_ratios(bal);
    let n = bal.entries.len;
    guard n > 0 && bal.max_effective_weight > 0 else { return -1, false; }
    let max_iters = core::add_sat_u64(core::mul_sat_u64(n as u64, bal.max_effective_weight as u64), n as u64) as i64;
    for _ in max_iters {
        let idx = step_weighted_round_robin(bal, n as i32);
        guard idx >= 0 && idx < bal.entries.len else { return -1, false; }
        let cand .= bal.entries[idx];
        if cand.effective_weight >= bal.current_weight && !cand.need_drain {
            return idx, true;
        }
    }
    return -1, false;
}
