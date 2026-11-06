// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_proxy_regressions.goose
// Regression test suite verifying fixes for proxy subsystem bugs:
// 1. Load balancer Down target hysteresis bypass (flapping bug)
// 2. Health check target_idx OOB bounds checks
// 3. GCRA client_id > 64 byte rate limit bypass
// 4. ReverseProxy duplicate Via header on forwarding
// 5. Client cert DER bounds check safety
// 6. Probing slot sync on Down cluster target
// 7. add_upstream_target empty host validation
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// 1. Verify load balancer Down target recovery hysteresis
fn test_lb_down_hysteresis() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 0);
    assert(wing::add_upstream_target(cluster, "srv-1", 80, 1));
    assert(wing::set_target_health_thresholds(cluster, 0, 2, 3));

    // Force target 0 into Down state
    cluster.targets[0].health_state = wing::UpstreamHealthState.Down;
    cluster.targets[0].is_healthy = false;
    cluster.targets[0].successes = 0;
    cluster.targets[0].fails = 3;

    // First success on Down target with threshold 2: transitions to Probing!
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].health_state == wing::UpstreamHealthState.Probing);
    assert(!cluster.targets[0].is_healthy);
    assert(!cluster.circuit_open);

    // Second success: threshold 2 is met, now transitions to Up!
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].health_state == wing::UpstreamHealthState.Up);
    assert(cluster.targets[0].is_healthy);
    assert(!cluster.circuit_open);
    print("LB_DOWN_HYSTERESIS: ok\n");
}

// 2. Verify health check OOB target_idx bounds protection
fn test_health_check_bounds() {
    var cfg = wing::new_health_check_config(1000, 500, 2, 3);
    var checker = wing::new_cluster_health_checker(cfg);
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    assert(wing::add_upstream_target(cluster, "srv-1", 80, 1));
    assert(wing::register_target_for_probing(checker, 0));

    // target_idx 99 is out-of-bounds (cluster has only 1 target). Must return Down safely without panicking.
    let s1 = wing::on_probe_success(checker, cluster, 99, 100);
    assert(s1 == wing::HealthState.Down);

    let s2 = wing::on_probe_failure(checker, cluster, 99);
    assert(s2 == wing::HealthState.Down);

    // Corrupt a slot with invalid target_idx to test check_probe_timeouts bounds guard
    checker.slots[0].target_idx = 99;
    checker.slots[0].active_in_flight = true;
    checker.slots[0].probe_start_ms = 1000;
    let timed_out = wing::check_probe_timeouts(checker, cluster, 2000);
    assert(timed_out == 0);

    print("HEALTH_CHECK_BOUNDS: ok\n");
}
// 3. Verify GCRA rate limiter tracks and limits oversized client_id (> 64 bytes)
fn test_gcra_oversized_client_id() {
    var limiter = wing::new_gateway_rate_limiter(10, 2); // 10 req/s, burst 2
    let now_ns: u64 = 1000000000;
    // 68-byte client ID
    let long_id = "client-token-with-oversized-identifier-exceeding-64-bytes-0123456789abc";
    assert(long_id.len > 64);

    // Initial burst requests should be allowed
    let d1 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(d1.allowed);
    let d2 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(d2.allowed);
    let d3 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(d3.allowed);

    // Subsequent requests in the same millisecond must be rate-limited, NOT bypassed!
    let d4 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(!d4.allowed);

    print("GCRA_OVERSIZED_CLIENT_ID: ok\n");
}

// 4. Verify ReverseProxy does not duplicate Via header on forwarding
fn test_reverse_proxy_via_dedup() {
    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "api.example.com"));
    assert(wing::append_header(in_headers, "Via", "1.0 upstream-cache"));

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.via_pseudonym.clear();
    cfg.via_pseudonym.append("wing-gw");

    let ok = wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.1",
        "https",
        "backend.internal:8080",
        cfg,
    );
    assert(ok);

    // Count Via headers in out_headers: must be exactly 1!
    var via_count = 0;
    for i in out_headers.entries.len {
        let entry = out_headers.entries[i];
        let name = out_headers.raw_buf[entry.name_begin..entry.name_end];
        if core::eq_ascii_fold(name, "via") {
            via_count++;
        }
    }
    assert(via_count == 1);
    let v = wing::get_header(out_headers, "Via");
    assert(v == "1.0 upstream-cache, 1.1 wing-gw");

    print("REVERSE_PROXY_VIA_DEDUP: ok\n");
}
// 5. Verify client cert DER length mismatch does not abort
fn test_reverse_proxy_client_cert_safety() {
    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "api.example.com"));

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.forward_client_cert = true;
    cfg.client_cert_der_len = 100; // mismatch: client_cert_der has len 0!

    // Must not panic or crash
    let ok = wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.1",
        "https",
        "backend:8080",
        cfg,
    );
    assert(ok);
    print("CLIENT_CERT_SAFETY: ok\n");
}

// 6. Verify add_upstream_target rejects empty host
fn test_add_target_empty_host() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    assert(!wing::add_upstream_target(cluster, "", 80, 1));
    assert(cluster.targets.len == 0);
    print("ADD_TARGET_EMPTY_HOST: ok\n");
}

// 7. Verify probing slot sync when cluster target drops Down
fn test_health_check_probing_sync() {
    var slot = wing::TargetProbeSlot { .. };
    slot.health.state = wing::HealthState.Probing;
    slot.health.consecutive_successes = 1;

    // Cluster drops to Down: slot must sync to Down and clear successes!
    wing::sync_slot_from_cluster(slot, wing::UpstreamHealthState.Down);
    assert(slot.health.state == wing::HealthState.Down);
    assert(slot.health.consecutive_successes == 0);
    print("HEALTH_CHECK_PROBING_SYNC: ok\n");
}

fn main() {
    test_lb_down_hysteresis();
    // CHECK: LB_DOWN_HYSTERESIS: ok
    test_health_check_bounds();
    // CHECK: HEALTH_CHECK_BOUNDS: ok
    test_gcra_oversized_client_id();
    // CHECK: GCRA_OVERSIZED_CLIENT_ID: ok
    test_reverse_proxy_via_dedup();
    // CHECK: REVERSE_PROXY_VIA_DEDUP: ok
    test_reverse_proxy_client_cert_safety();
    // CHECK: CLIENT_CERT_SAFETY: ok
    test_add_target_empty_host();
    // CHECK: ADD_TARGET_EMPTY_HOST: ok
    test_health_check_probing_sync();
    // CHECK: HEALTH_CHECK_PROBING_SYNC: ok
    print("ALL_PROXY_REGRESSIONS_PASS\n");
    // CHECK: ALL_PROXY_REGRESSIONS_PASS
}
