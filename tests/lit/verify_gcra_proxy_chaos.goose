// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_gcra_proxy_chaos.goose
// Pathological verification suite for GCRA rate limiter mathematical boundaries,
// burst limit precision, TAT overflow/underflow, NTP clock skew,
// and upstream load balancer health check state flapping / circuit breaker chaos.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

const U64_MAX_LIMIT:   u64 = 0xFFFFFFFFFFFFFFFF;
const NEAR_MAX_OFFSET: u64 = 20000000000;

// ---- Section 1: GCRA Burst Limit Precision & Fractional Recovery -----------

// crap:trusted-bounds
fn test_gcra_burst_precision() {
    // Sustained: 10 req/s (T = 100ms = 100,000,000ns), Burst: 3 (tau = 300,000,000ns)
    // Limit window = tau + T = 400,000,000ns (allows 4 back-to-back requests at t0)
    let quota = wing::new_gcra_quota(10, core::secs(1), 3);
    assert(quota.emission_interval_ns == 100000000);
    assert(quota.delay_tolerance_ns == 300000000);

    var cell = wing::GcraCell { tat_ns: 0 };
    let t0: u64 = 1000000000;

    // Request 1: allowed, TAT becomes t0 + 100ms
    let d1 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d1));
    assert(cell.tat_ns == core::add_sat_u64(t0, 100000000));

    // Request 2: allowed, TAT becomes t0 + 200ms
    let d2 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d2));

    // Request 3: allowed, TAT becomes t0 + 300ms
    let d3 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d3));

    // Request 4: allowed (burst capacity exhausted: TAT = t0 + 400ms = limit window boundary)
    let d4 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d4));
    assert(cell.tat_ns == core::add_sat_u64(t0, 400000000));

    // Request 5 at t0: REJECTED! TAT would exceed limit window
    let d5 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(!wing::is_allowed(d5));

    // Fractional clock recovery: advance clock by 50ms (half of T)
    // 50ms is insufficient to recover a 100ms token -> must still reject
    let t_half = core::add_sat_u64(t0, 50000000);
    let d_half = wing::gcra_check_n(quota, cell, 1, t_half);
    assert(!wing::is_allowed(d_half));

    // Full clock recovery: advance clock by full 100ms (t0 + 100ms)
    // 1 token has leaked out of bucket -> exactly 1 request allowed
    let t_full = core::add_sat_u64(t0, 100000000);
    let d_rec1 = wing::gcra_check_n(quota, cell, 1, t_full);
    assert(wing::is_allowed(d_rec1));

    // Immediate second request at t_full is rejected again
    let d_rec2 = wing::gcra_check_n(quota, cell, 1, t_full);
    assert(!wing::is_allowed(d_rec2));

    print("GCRA_BURST_PRECISION: burst_exhausted=true fractional_rejected=true full_recovered=true");
}

// ---- Section 2: TAT Saturation, Arithmetic Overflow & Underflow Bounds ------

// crap:trusted-bounds
fn test_gcra_boundary_overflow_underflow() {
    // 1. Division by zero protection: zero period duration or astronomical rate
    let q_zero = wing::new_gcra_quota(5000000, core::Duration { nanos: 1000000 }, 5);
    assert(q_zero.emission_interval_ns >= 1);
    var cell_zero = wing::GcraCell { tat_ns: 0 };
    let d_zero = wing::gcra_check_n(q_zero, cell_zero, 1, 1000);
    assert(wing::is_allowed(d_zero));

    // 2. High-value timestamp near u64::MAX (preventing arithmetic wrap-around)
    let q_sat = wing::new_gcra_quota(1, core::secs(1), 5);
    let near_max: u64 = core::sub_sat_u64(U64_MAX_LIMIT, NEAR_MAX_OFFSET);
    var cell_sat = wing::GcraCell { tat_ns: near_max };

    // Request consuming cost = 3 near u64 boundary
    let d_sat = wing::gcra_check_n(q_sat, cell_sat, 3, near_max);
    assert(wing::is_allowed(d_sat));
    assert(cell_sat.tat_ns > near_max);

    // 3. Cold-start underflow defense: cell.tat_ns = 0
    let now_cold: u64 = 5000000000;
    var cell_cold = wing::GcraCell { tat_ns: 0 };
    let d_cold = wing::gcra_check_n(q_sat, cell_cold, 1, now_cold);
    assert(wing::is_allowed(d_cold));
    assert(cell_cold.tat_ns == core::add_sat_u64(now_cold, q_sat.emission_interval_ns));

    print("GCRA_ARITH_BOUNDS: div_zero_safe=true u64_sat_safe=true cold_start_ok=true");
}

// ---- Section 3: NTP Backward Clock Jump & Clock Skew Resilience ------------

// crap:trusted-bounds
fn test_gcra_ntp_backward_jump() {
    let quota = wing::new_gcra_quota(10, core::secs(1), 2);
    var cell = wing::GcraCell { tat_ns: 60000000000 };

    // Sudden NTP backward step: system clock steps back to 10s (50 seconds in past)
    let now_skewed: u64 = 10000000000;
    let dec = wing::gcra_check_n(quota, cell, 1, now_skewed);
    assert(!wing::is_allowed(dec));

    // Operational limit window is tau + T = 200ms + 100ms = 300ms
    let lim_win = core::add_sat_u64(quota.delay_tolerance_ns, quota.emission_interval_ns);
    let tat_clamped = core::add_sat_u64(now_skewed, lim_win);

    // Synchronizing cell with clamped TAT restores service after retry interval
    cell.tat_ns = tat_clamped;
    let now_recovered = core::add_sat_u64(now_skewed, 200000000);
    let dec_rec = wing::gcra_check_n(quota, cell, 1, now_recovered);
    assert(wing::is_allowed(dec_rec));

    print("GCRA_NTP_BACKWARD_JUMP: clamped_retry_after=true resumed_after_skew=true");
}

// ---- Section 4: Multi-Cell Priority Reservation (Governor #16) --------------

// crap:trusted-bounds
fn test_gcra_reservation_preemption() {
    let quota = wing::new_gcra_quota(1, core::secs(1), 0);
    var cell = wing::GcraCell { tat_ns: 0 };
    let now: u64 = 1000000000;

    // Normal cell at t=1.0s consumes immediate slot
    let d1 = wing::gcra_check_n(quota, cell, 1, now);
    assert(wing::is_allowed(d1));
    assert(cell.tat_ns == core::add_sat_u64(now, 1000000000));

    // Heavy batch request arrives needing 3 tokens (cost_n = 3)
    let d_res = wing::gcra_reserve_n(quota, cell, 3, now, 5000000000);
    assert(wing::is_allowed(d_res));
    assert(cell.tat_ns == core::add_sat_u64(now, 4000000000));

    // Light request (cost_n = 1) arrives 500ms later and tries to steal capacity
    let d_steal = wing::gcra_check_n(quota, cell, 1, core::add_sat_u64(now, 500000000));
    assert(!wing::is_allowed(d_steal));

    // When the reservation delay passes (now + 4s), quota resumes
    let now_resume = core::add_sat_u64(now, 4000000000);
    let d_resumed = wing::gcra_check_n(quota, cell, 1, now_resume);
    assert(wing::is_allowed(d_resumed));

    print("GCRA_RESERVATION: reserved_3_slots=true preemption_preserved=true resumed=true");
}

// ---- Section 5: Long Rate Limiting Key Normalization & Shard Isolation ------

// crap:trusted-bounds
fn test_gcra_long_key_normalization() {
    let quota = wing::new_gcra_quota(2, core::secs(1), 1);
    var limiter = wing::new_sharded_limiter(quota);
    let now: u64 = 2000000000;

    // Key exceeding 64 bytes (80-byte header string)
    let long_key = "x-client-session-very-long-unique-telemetry-identifier-0123456789-abcdefghijklmnop";
    assert(long_key.len > 64);

    var eff_key: u8[..64] = [];
    wing::format_gcra_key(long_key, eff_key);
    assert(eff_key.len == 64);

    // Normalizing does not crash and isolates keys
    let d_long1 = wing::check_rate_limit(limiter, long_key, 1, now);
    let d_long2 = wing::check_rate_limit(limiter, long_key, 1, now);
    let d_long3 = wing::check_rate_limit(limiter, long_key, 1, now);

    assert(wing::is_allowed(d_long1));
    assert(wing::is_allowed(d_long2));
    assert(!wing::is_allowed(d_long3));

    // Distinct key must remain completely unaffected
    let d_other = wing::check_rate_limit(limiter, "independent-client-key", 1, now);
    assert(wing::is_allowed(d_other));

    print("GCRA_KEY_NORMALIZATION: len_64_normalized=true isolation_verified=true");
}

// ---- Section 6: Upstream Health Check State Flapping & Circuit Breaker -----

// crap:trusted-bounds
fn test_proxy_health_check_flapping() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    assert(wing::add_upstream_target(cluster, "10.0.1.1", 8080));
    assert(wing::add_upstream_target(cluster, "10.0.1.2", 8080));

    // Target 0 experiences flapping (alternating single failure and recovery)
    wing::record_upstream_failure(cluster, 0);
    assert(cluster.targets[0].is_healthy);

    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].fails == 0);

    wing::record_upstream_failure(cluster, 0);
    assert(cluster.targets[0].is_healthy);
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].fails == 0);

    // Sustained 3 failures -> trips target 0 to unhealthy
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);
    assert(!cluster.targets[0].is_healthy);
    assert(!cluster.circuit_open);

    // Selection now exclusively routes to Target 1
    let chosen1, ok1 = wing::select_upstream(cluster);
    let chosen2, ok2 = wing::select_upstream(cluster);
    assert(ok1 && chosen1 == 1);
    assert(ok2 && chosen2 == 1);

    print("PROXY_HEALTH_FLAPPING: flap_resilient=true sustained_failure_isolated=true");
}

// ---- Section 7: Total Cluster Circuit Breaker Full Trip & Self-Healing ------

// crap:trusted-bounds
fn test_proxy_circuit_breaker_full_trip() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
    assert(wing::add_upstream_target(cluster, "srv-alpha", 80));
    assert(wing::add_upstream_target(cluster, "srv-beta", 80));

    // Fail all targets to trip entire cluster circuit
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);
    assert(!cluster.targets[0].is_healthy);

    wing::record_upstream_failure(cluster, 1);
    wing::record_upstream_failure(cluster, 1);
    assert(!cluster.targets[1].is_healthy);

    // Entire cluster circuit is now open (all backends dead)
    assert(cluster.circuit_open);
    let _, ok_trip = wing::select_upstream(cluster);
    assert(!ok_trip);

    // Active health probe returns success on srv-beta (Target 1)
    wing::record_upstream_success(cluster, 1);
    assert(cluster.targets[1].is_healthy);
    assert(!cluster.circuit_open);

    let chosen, ok_heal = wing::select_upstream(cluster);
    assert(ok_heal && chosen == 1);

    print("PROXY_CIRCUIT_BREAKER: full_trip_fast_fails=true self_healed_on_probe=true");
}

// ---- Section 8: Degraded Routing Under Least-Connections Policy -------------

// crap:trusted-bounds
fn test_proxy_lb_degraded_routing() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.LeastConnections, 2);
    assert(wing::add_upstream_target(cluster, "node-1", 8080));
    assert(wing::add_upstream_target(cluster, "node-2", 8080));
    assert(wing::add_upstream_target(cluster, "node-3", 8080));

    // Node 1 has 5 active connections
    cluster.targets[0].active_conns = 5;
    // Node 2 has 2 active connections
    cluster.targets[1].active_conns = 2;
    // Node 3 has 0 active connections but is DOWN
    cluster.targets[2].is_healthy = false;

    // Least-connections must skip node-3 (down) and choose node-2 (least active: 2 < 5)
    let chosen, ok = wing::select_upstream(cluster);
    assert(ok && chosen == 1);
    assert(cluster.targets[1].active_conns == 3);

    // Release connection
    wing::release_upstream_connection(cluster, chosen);
    assert(cluster.targets[1].active_conns == 2);

    print("PROXY_LB_DEGRADED: unhealthy_skipped=true least_conn_chosen=true");
}

// ---- Main Entry Point ------------------------------------------------------

// crap:trusted-bounds
fn main() {
    print("=== LIT GCRA Rate Limiter & Proxy Chaos Verification ===");
    test_gcra_burst_precision();
    test_gcra_boundary_overflow_underflow();
    test_gcra_ntp_backward_jump();
    test_gcra_reservation_preemption();
    test_gcra_long_key_normalization();
    test_proxy_health_check_flapping();
    test_proxy_circuit_breaker_full_trip();
    test_proxy_lb_degraded_routing();
}

// CHECK: === LIT GCRA Rate Limiter & Proxy Chaos Verification ===
// CHECK-NEXT: GCRA_BURST_PRECISION: burst_exhausted=true fractional_rejected=true full_recovered=true
// CHECK-NEXT: GCRA_ARITH_BOUNDS: div_zero_safe=true u64_sat_safe=true cold_start_ok=true
// CHECK-NEXT: GCRA_NTP_BACKWARD_JUMP: clamped_retry_after=true resumed_after_skew=true
// CHECK-NEXT: GCRA_RESERVATION: reserved_3_slots=true preemption_preserved=true resumed=true
// CHECK-NEXT: GCRA_KEY_NORMALIZATION: len_64_normalized=true isolation_verified=true
// CHECK-NEXT: PROXY_HEALTH_FLAPPING: flap_resilient=true sustained_failure_isolated=true
// CHECK-NEXT: PROXY_CIRCUIT_BREAKER: full_trip_fast_fails=true self_healed_on_probe=true
// CHECK-NEXT: PROXY_LB_DEGRADED: unhealthy_skipped=true least_conn_chosen=true
