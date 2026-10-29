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
}

struct UpstreamTarget {
    host: u8[..64] = [],
    port: u16 = 80,
    active_conns: i32 = 0,
    weight: u16 = 1,
    is_healthy: bool = true,
    fails: i32 = 0,
    total_requests: u64 = 0,
}

struct UpstreamCluster {
    targets: UpstreamTarget[..16] = [],
    policy: LbPolicy = LbPolicy.RoundRobin,
    rr_index: i32 = 0,
    max_fails: i32 = 3,
    circuit_open: bool = false,
    rng_state: u64 = 0x123456789abcdef0,
}

fn new_upstream_cluster(policy: LbPolicy = LbPolicy.RoundRobin, max_fails: i32 = 3) -> UpstreamCluster {
    return UpstreamCluster {
        policy: policy,
        max_fails: max_fails,
        circuit_open: false,
        ..
    };
}

fn add_upstream_target(cluster: UpstreamCluster&, host: const u8[:], port: u16, weight: u16 = 1) -> bool {
    guard cluster.targets.len < cluster.targets.cap else { return false; }
    guard host.len <= 64 else { return false; }

    var target = UpstreamTarget {
        port: port,
        weight: if weight > 0 { weight } else { 1 },
        is_healthy: true,
        ..
    };
    target.host.append(host);
    cluster.targets.push(target);
    return true;
}

inline fn prng_mul(val: u64) -> u64 {
    return val * 6364136223846793005;
}

// 64-bit linear congruential PRNG generator (Knuth MMIX parameters)
inline fn next_prng(state: u64&) -> u64 {
    let s = prng_mul(state) + 1442695040888963407;
    state = s;
    return s;
}

inline fn inc_active_conns(target: UpstreamTarget&) {
    target.active_conns = target.active_conns + 1;
}

inline fn inc_total_requests(target: UpstreamTarget&) {
    target.total_requests = target.total_requests + 1;
}

inline fn record_target_dispatch(target: UpstreamTarget&) {
    inc_active_conns(target);
    inc_total_requests(target);
}

inline fn advance_rr_index(cur_rr: i32, n: i32) -> i32 {
    let next_rr = cur_rr + 1;
    return if next_rr >= n { 0 } else { next_rr };
}

// Selects next healthy upstream via Round-Robin.
fn select_round_robin(cluster: UpstreamCluster&, n: i32) -> i32, bool {
    for _ in n {
        let idx = cluster.rr_index;
        cluster.rr_index = advance_rr_index(cluster.rr_index, n);

        if cluster.targets[idx].is_healthy {
            record_target_dispatch(cluster.targets[idx]);
            return idx, true;
        }
    }
    return NO_UPSTREAM_TARGET, false;
}

// Finds healthy target with least active connections.
fn find_least_conn_target(cluster: const UpstreamCluster&, n: i32) -> i32 {
    var best_idx: i32 = NO_UPSTREAM_TARGET;
    var min_conns: i32 = 2147483647;

    for i in n {
        if cluster.targets[i].is_healthy {
            let c = cluster.targets[i].active_conns;
            if c < min_conns {
                min_conns = c;
                best_idx = i;
            }
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

inline fn evaluate_two_choice(target1: const UpstreamTarget&, r1: i32, target2: const UpstreamTarget&, r2: i32) -> i32 {
    return if target1.active_conns <= target2.active_conns { r1 } else { r2 };
}

// Selects next healthy upstream via Power-of-Two-Random-Choices (P2C).
fn select_p2c(cluster: UpstreamCluster&, n: i32) -> i32, bool {
    if n == 1 {
        if cluster.targets[0].is_healthy {
            record_target_dispatch(cluster.targets[0]);
            return 0, true;
        }
        return NO_UPSTREAM_TARGET, false;
    }

    let r1, r2 = pick_two_distinct(cluster, n);
    let h1 = cluster.targets[r1].is_healthy;
    let h2 = cluster.targets[r2].is_healthy;

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
    return NO_UPSTREAM_TARGET, false;
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
    return select_p2c(cluster, n);
}

inline fn sub_one(x: i32) -> i32 {
    return x - 1;
}

inline fn dec_active_conns(target: UpstreamTarget&) {
    let cur = target.active_conns;
    if cur > 0 {
        target.active_conns = sub_one(cur);
    }
}

// Releases an active connection for an upstream target upon response completion.
fn release_upstream_connection(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    dec_active_conns(cluster.targets[target_idx]);
}

// Records success, clearing failure streak and restoring circuit if applicable.
fn record_upstream_success(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    cluster.targets[target_idx].fails = 0;
    cluster.targets[target_idx].is_healthy = true;
    cluster.circuit_open = false;
}

fn update_cluster_circuit_state(cluster: UpstreamCluster&) {
    var any_healthy = false;
    for &t in cluster.targets {
        if t.is_healthy {
            any_healthy = true;
            break;
        }
    }
    if !any_healthy {
        cluster.circuit_open = true;
    }
}

inline fn inc_target_fails(target: UpstreamTarget&) -> i32 {
    let fails = target.fails + 1;
    target.fails = fails;
    return fails;
}

// Records connection or timeout failure, tripping circuit breaker if ceiling reached.
fn record_upstream_failure(cluster: UpstreamCluster&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    let fails = inc_target_fails(cluster.targets[target_idx]);

    if fails >= cluster.max_fails {
        cluster.targets[target_idx].is_healthy = false;
    }
    update_cluster_circuit_state(cluster);
}
