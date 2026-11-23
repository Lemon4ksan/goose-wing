// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
//
// Verification suite for Task 3: Dynamic target lifecycle, draining,
// Nginx smooth WeightedRoundRobin, key-aware Ketama, and 128-byte TLS targets.

import std;
import wing from "../..";

fn test_consistent_hash_keyed_and_empty_fallback() {
    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.ConsistentHash, 3);
    assert(proxy::add_upstream_target(cluster, "10.0.1.1", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.1.2", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.1.3", 8080, 1));

    var counts: i32[3] = [0, 0, 0];
    for i in 64 {
        var key: u8[..32] = [];
        let _ = key.try_set("client-key-");
        i.format_i64_dec(key);
        let idx, ok = proxy::select_upstream_with_key(cluster, key[..]);
        assert(ok && idx >= 0 && idx < 3);
        counts[idx] = counts[idx] + 1;
        proxy::release_upstream_connection(cluster, idx);
    }
    assert(counts[0] > 0 && counts[1] > 0 && counts[2] > 0);

    // Empty key must fall back to Round-Robin across all 3 targets.
    let rr0, ok0 = proxy::select_upstream_with_key(cluster, "");
    let rr1, ok1 = proxy::select_upstream_with_key(cluster, "");
    let rr2, ok2 = proxy::select_upstream_with_key(cluster, "");
    let rr3, ok3 = proxy::select_upstream_with_key(cluster, "");
    assert(ok0 && ok1 && ok2 && ok3);
    assert(rr0 == 0 && rr1 == 1 && rr2 == 2 && rr3 == 0);

    print("KETAMA_KEYED_AND_RR_FALLBACK: ok\n");
    // CHECK: KETAMA_KEYED_AND_RR_FALLBACK: ok
}

fn test_draining_failover_and_active_conns() {
    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.ConsistentHash, 3);
    assert(proxy::add_upstream_target(cluster, "10.0.2.1", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.2.2", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.2.3", 8080, 1));

    let primary, ok1 = proxy::select_upstream_with_key(cluster, "session-sticky-42");
    assert(ok1 && primary >= 0 && primary < 3);
    let conns_before = cluster.targets[primary].active_conns;
    assert(conns_before == 1);

    assert(proxy::set_target_draining(cluster, primary, true));
    assert(cluster.targets[primary].draining);
    assert(cluster.targets[primary].active_conns == conns_before);

    let failover, ok2 = proxy::select_upstream_with_key(cluster, "session-sticky-42");
    assert(ok2 && failover != primary && failover >= 0 && failover < 3);
    assert(cluster.targets[primary].active_conns == conns_before);

    proxy::release_upstream_connection(cluster, primary);
    assert(cluster.targets[primary].active_conns == 0);
    proxy::release_upstream_connection(cluster, failover);

    print("DRAINING_FAILOVER_PRESERVES_CONNS: ok\n");
    // CHECK: DRAINING_FAILOVER_PRESERVES_CONNS: ok
}

fn test_smooth_weighted_round_robin() {
    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.WeightedRoundRobin, 3);
    assert(proxy::add_upstream_target(cluster, "10.0.3.1", 8080, 3));
    assert(proxy::add_upstream_target(cluster, "10.0.3.2", 8080, 1));

    var c0: i32 = 0;
    var c1: i32 = 0;
    for _ in 8 {
        let idx, ok = proxy::select_upstream(cluster);
        assert(ok && (idx == 0 || idx == 1));
        if idx == 0 {
            c0 = c0 + 1;
        } else {
            c1 = c1 + 1;
        }
        proxy::release_upstream_connection(cluster, idx);
    }
    assert(c0 == 6 && c1 == 2);

    assert(proxy::set_target_weight(cluster, 1, 3));
    c0 = 0;
    c1 = 0;
    for _ in 8 {
        let idx, ok = proxy::select_upstream(cluster);
        assert(ok && (idx == 0 || idx == 1));
        if idx == 0 {
            c0 = c0 + 1;
        } else {
            c1 = c1 + 1;
        }
        proxy::release_upstream_connection(cluster, idx);
    }
    assert(c0 == 4 && c1 == 4);

    print("SMOOTH_WRR_DYNAMIC_WEIGHT: ok\n");
    // CHECK: SMOOTH_WRR_DYNAMIC_WEIGHT: ok
}

fn test_remove_upstream_target_rebuilds_ketama() {
    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.ConsistentHash, 3);
    assert(proxy::add_upstream_target(cluster, "10.0.4.1", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.4.2", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.4.3", 8080, 1));

    assert(!proxy::remove_upstream_target(cluster, -1));
    assert(!proxy::remove_upstream_target(cluster, 3));
    assert(proxy::remove_upstream_target(cluster, 0));
    assert(cluster.targets.len == 2);
    assert(cluster.targets[0].host[..] == "10.0.4.2");
    assert(cluster.targets[1].host[..] == "10.0.4.3");
    assert(cluster.ketama_ring.points.len > 0);
    for &pt in cluster.ketama_ring.points {
        assert(pt.backend_idx < 2);
    }

    for i in 16 {
        var key: u8[..32] = [];
        let _ = key.try_set("k-");
        i.format_i64_dec(key);
        let idx, ok = proxy::select_upstream_with_key(cluster, key[..]);
        assert(ok && idx >= 0 && idx < 2);
        proxy::release_upstream_connection(cluster, idx);
    }

    print("REMOVE_TARGET_KETAMA_REBUILD: ok\n");
    // CHECK: REMOVE_TARGET_KETAMA_REBUILD: ok
}

fn test_add_upstream_target_tls_100b_fqdn() {
    var fqdn: u8[..128] = [];
    for _ in 10 {
        assert(fqdn.try_append("subnode01."));
    }
    // 100 bytes exactly ("subnode01." * 10)
    assert(fqdn.len == 100);

    var sni: u8[..128] = [];
    for _ in 10 {
        assert(sni.try_append("tlssni001."));
    }
    assert(sni.len == 100);

    var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
    assert(proxy::add_upstream_target_tls(rp.cluster, fqdn[..], 8443, 2, true, sni[..]));
    assert(rp.cluster.targets.len == 1);
    assert(rp.cluster.targets[0].use_tls);
    assert(rp.cluster.targets[0].host[..] == fqdn[..]);
    assert(rp.cluster.targets[0].sni_host[..] == sni[..]);

    var in_hdr = http::HeaderMap { .. };
    assert(http::append_header(in_hdr, "Host", "edge.example.com"));
    var wire: u8[>..] = [];
    let t_idx, ok_prep = proxy::prepare_proxy_request_at(
        rp,
        "GET",
        "/health",
        in_hdr,
        "192.0.2.1",
        "https",
        "",
        wire,
        1000000000,
    );
    assert(ok_prep && t_idx == 0);

    print("TLS_100B_FQDN_TARGET: ok\n");
    // CHECK: TLS_100B_FQDN_TARGET: ok
}

fn test_draining_preserves_circuit_open_on_success_and_probe() {
    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 2);
    assert(proxy::add_upstream_target(cluster, "10.0.5.1", 8080, 1));
    var checker = proxy::new_cluster_health_checker(proxy::new_health_check_config(1000, 500, 1, 2));
    assert(proxy::register_target_for_probing(checker, 0));

    let chosen, ok_sel = proxy::select_upstream(cluster);
    assert(ok_sel && chosen == 0);
    assert(!cluster.circuit_open);

    // Mark the only healthy target as draining -> circuit_open must trip true.
    assert(proxy::set_target_draining(cluster, 0, true));
    assert(cluster.circuit_open);

    // Completing an in-flight request or active probe on the draining target must NOT clear circuit_open.
    proxy::record_upstream_success(cluster, 0);
    proxy::release_upstream_connection(cluster, 0);
    assert(cluster.circuit_open);
    let _ = proxy::on_probe_success(checker, cluster, 0, 100);
    assert(cluster.circuit_open);

    let _, ok_while_draining = proxy::select_upstream(cluster);
    assert(!ok_while_draining);

    // Undraining restores circuit_open = false and routes cleanly again.
    assert(proxy::set_target_draining(cluster, 0, false));
    assert(!cluster.circuit_open);
    let restored, ok_restored = proxy::select_upstream(cluster);
    assert(ok_restored && restored == 0);

    print("DRAINING_CIRCUIT_OPEN_PRESERVED: ok\n");
    // CHECK: DRAINING_CIRCUIT_OPEN_PRESERVED: ok
}

fn main() {
    test_consistent_hash_keyed_and_empty_fallback();
    test_draining_failover_and_active_conns();
    test_smooth_weighted_round_robin();
    test_remove_upstream_target_rebuilds_ketama();
    test_add_upstream_target_tls_100b_fqdn();
    test_draining_preserves_circuit_open_on_success_and_probe();
}
