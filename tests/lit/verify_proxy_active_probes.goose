// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
//
// Verification suite for Task 4: Live HTTP/HTTPS active health probes,
// slot unregistration/compaction, and measured RTT propagation.

import std;
import wing from "../..";

thread_fn mock_http_health_server(listener_fd: i64) {
    // Serve 5 probes: 3x 503 Service Unavailable, then 2x 200 OK.
    for i in 5 {
        let conn = net::tcp_accept(listener_fd, 5000);
        assert(conn > 0);
        var rx: u8[1024] = [0; 1024];
        let n = net::tcp_recv_slice(conn, rx[..], 5000);
        assert(n > 0);
        assert(core::starts_with(rx[..n], "GET /healthz HTTP/1.1\r\n"));
        assert(core::contains(rx[..n], "Host: 127.0.0.1:"));

        if i < 3 {
            let resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            assert(net::tcp_send(conn, resp) == resp.len as i32);
        } else {
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            assert(net::tcp_send(conn, resp) == resp.len as i32);
        }
        net::tcp_close(conn);
    }
}

thread_fn mock_https_health_server(listener_fd: i64) {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(
        seed,
        "probe.internal.test",
        "probe.internal.test",
        "127.0.0.1",
        cert_der,
    ));

    var srv_cfg = tls::ServerHandshakeConfig {
        priv_seed:            seed,
        handshake_timeout_ms: 5000,
        ..
    };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));
    assert(srv_cfg.alpn.try_set("http/1.1"));

    // Conn 1: Trusted TLS probe -> 200 OK.
    let conn1 = net::tcp_accept(listener_fd, 5000);
    assert(conn1 > 0);
    let slot1, ok_hs1 = tls::server_handshake(conn1, srv_cfg);
    assert(ok_hs1);
    var t1: net::Transport = net::Transport.Tls {
        fd:            conn1,
        record_seq_rx: 0,
        record_seq_tx: 0,
        cipher_slot:   slot1,
    };
    var rx1: u8[1024] = [0; 1024];
    let n1 = t1.recv_slice(rx1[..], 5000);
    assert(n1 > 0 && core::starts_with(rx1[..n1], "GET /ready HTTP/1.1\r\n"));
    let ok_resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    assert(t1.send(ok_resp) == ok_resp.len as i32);
    t1.close();

    // Conn 2: Untrusted CA store -> client aborts handshake cleanly.
    let conn2 = net::tcp_accept(listener_fd, 5000);
    assert(conn2 > 0);
    let slot2, ok_hs2 = tls::server_handshake(conn2, srv_cfg);
    if ok_hs2 {
        tls::transport_close(conn2, slot2);
    } else {
        net::tcp_close(conn2);
    }
}

fn test_live_http_active_probes_and_recovery() {
    let listener = net::tcp_listen("127.0.0.1", 0, 16);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(mock_http_health_server, listener);

    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 3);
    assert(proxy::add_upstream_target(cluster, "127.0.0.1", port, 1));

    var cfg = proxy::new_health_check_config(1000, 2000, 2, 3);
    var checker = proxy::new_cluster_health_checker(cfg);
    assert(proxy::register_target_for_probing(checker, 0));

    // Probe 1 (initial, total_probes == 0): 503 -> still Up (1/3 failures).
    let n1 = proxy::step_due_health_probes(checker, cluster, 1000);
    assert(n1 == 1);
    assert(checker.slots[0].health.state == proxy::HealthState.Up);
    assert(checker.slots[0].health.consecutive_failures == 1);
    assert(checker.slots[0].health.last_probe_time_ms == 1000);

    // Not due yet at 1500 ms (< interval 1000 ms).
    let n_skip = proxy::step_due_health_probes(checker, cluster, 1500);
    assert(n_skip == 0);

    // Probe 2 (2000 ms): 503 -> still Up (2/3 failures).
    let n2 = proxy::step_due_health_probes(checker, cluster, 2000);
    assert(n2 == 1);
    assert(checker.slots[0].health.state == proxy::HealthState.Up);
    assert(checker.slots[0].health.consecutive_failures == 2);

    // Probe 3 (3000 ms): 503 -> trips Down (3/3 failures).
    let n3 = proxy::step_due_health_probes(checker, cluster, 3000);
    assert(n3 == 1);
    assert(checker.slots[0].health.state == proxy::HealthState.Down);
    assert(cluster.targets[0].health_state == proxy::UpstreamHealthState.Down);
    assert(!cluster.targets[0].is_healthy);
    assert(cluster.circuit_open);

    // Probe 4 (4000 ms): server now returns 200 OK -> Down -> Probing, rtt_us > 0.
    let n4 = proxy::step_due_health_probes(checker, cluster, 4000);
    assert(n4 == 1);
    assert(checker.slots[0].health.state == proxy::HealthState.Probing);
    assert(cluster.targets[0].health_state == proxy::UpstreamHealthState.Probing);
    assert(checker.slots[0].health.last_rtt_us > 0);

    // Probe 5 (5000 ms): second 200 OK -> Probing -> Up (healthy_threshold == 2).
    let n5 = proxy::step_due_health_probes(checker, cluster, 5000);
    assert(n5 == 1);
    assert(checker.slots[0].health.state == proxy::HealthState.Up);
    assert(cluster.targets[0].health_state == proxy::UpstreamHealthState.Up);
    assert(cluster.targets[0].is_healthy);
    assert(!cluster.circuit_open);
    assert(checker.slots[0].health.last_rtt_us > 0);
    assert(checker.total_checks_dispatched == 5);

    assert(thread_wait(tid));
    net::tcp_close(listener);

    print("HTTP_ACTIVE_PROBE_LIFECYCLE: ok\n");
    // CHECK: HTTP_ACTIVE_PROBE_LIFECYCLE: ok
}

fn test_live_https_active_probe_with_sni_and_ca_store() {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(
        seed,
        "probe.internal.test",
        "probe.internal.test",
        "127.0.0.1",
        cert_der,
    ));
    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    // Build an unrelated CA store so untrusted verification must fail closed.
    let other_seed: u8[32] = [0x99; 32];
    var other_cert: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(
        other_seed,
        "other.internal.test",
        "other.internal.test",
        "",
        other_cert,
    ));
    var wrong_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(wrong_trust, other_cert[..]));

    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(mock_https_health_server, listener);

    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 2);
    assert(proxy::add_upstream_target_tls(cluster, "127.0.0.1", port, 1, true, "probe.internal.test"));

    var cfg = proxy::new_health_check_config(1000, 3000, 1, 1);
    assert(cfg.path.try_set("/ready"));
    var checker = proxy::new_cluster_health_checker(cfg);
    assert(proxy::register_target_for_probing(checker, 0));

    let st_ok = proxy::execute_active_health_probe(checker, cluster, 0, 1000, trust);
    assert(st_ok == proxy::HealthState.Up);
    assert(checker.slots[0].health.last_rtt_us > 0);
    assert(checker.slots[0].health.consecutive_successes == 1);

    let st_fail = proxy::execute_active_health_probe(checker, cluster, 0, 2000, wrong_trust);
    assert(st_fail == proxy::HealthState.Down);
    assert(checker.slots[0].health.failed_probes == 1);

    assert(thread_wait(tid));
    net::tcp_close(listener);

    print("HTTPS_ACTIVE_PROBE_SNI_AND_CA: ok\n");
    // CHECK: HTTPS_ACTIVE_PROBE_SNI_AND_CA: ok
}

fn test_unregister_target_and_slot_compaction() {
    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 3);
    assert(proxy::add_upstream_target(cluster, "10.0.0.1", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.0.2", 8080, 1));
    assert(proxy::add_upstream_target(cluster, "10.0.0.3", 8080, 1));

    var checker = proxy::new_cluster_health_checker(proxy::new_health_check_config(1000, 500, 2, 3));
    assert(proxy::register_target_for_probing(checker, 0));
    assert(proxy::register_target_for_probing(checker, 1));
    assert(proxy::register_target_for_probing(checker, 2));

    // Give targets 1 and 2 distinct probe metrics to verify slot identity after compaction.
    let _ = proxy::on_probe_success(checker, cluster, 1, 111);
    let _ = proxy::on_probe_success(checker, cluster, 2, 222);

    assert(!proxy::unregister_target_for_probing(checker, -1));
    assert(!proxy::unregister_target_for_probing(checker, 5));

    assert(proxy::remove_upstream_target(cluster, 0));
    assert(proxy::unregister_target_for_probing(checker, 0));
    assert(checker.slots.len == 2);
    assert(checker.slots[0].target_idx == 0);
    assert(checker.slots[0].health.last_rtt_us == 111);
    assert(checker.slots[1].target_idx == 1);
    assert(checker.slots[1].health.last_rtt_us == 222);

    // Removing the last element also unregisters cleanly.
    assert(proxy::remove_upstream_target(cluster, 1));
    assert(proxy::unregister_target_for_probing(checker, 1));
    assert(checker.slots.len == 1);
    assert(checker.slots[0].target_idx == 0);
    assert(checker.slots[0].health.last_rtt_us == 111);

    // Unregistering already-removed slot index > current slots returns false.
    assert(!proxy::unregister_target_for_probing(checker, 1));

    // Unregistering an unregistered middle index must return false without mutating higher indices.
    var sparse_checker = proxy::new_cluster_health_checker(proxy::new_health_check_config(1000, 500, 2, 3));
    assert(proxy::register_target_for_probing(sparse_checker, 0));
    assert(proxy::register_target_for_probing(sparse_checker, 2));
    assert(!proxy::unregister_target_for_probing(sparse_checker, 1));
    assert(sparse_checker.slots.len == 2);
    assert(sparse_checker.slots[0].target_idx == 0);
    assert(sparse_checker.slots[1].target_idx == 2);

    print("UNREGISTER_SLOT_COMPACTION: ok\n");
    // CHECK: UNREGISTER_SLOT_COMPACTION: ok
}

thread_fn mock_trickle_http_server(listener_fd: i64) {
    let conn = net::tcp_accept(listener_fd, 5000);
    assert(conn > 0);
    var rx: u8[1024] = [0; 1024];
    let n = net::tcp_recv_slice(conn, rx[..], 2000);
    assert(n > 0);
    // Trickle 1 byte every 50 ms without CRLF (600 ms total if uninterrupted).
    for _ in 12 {
        let sent = net::tcp_send(conn, "X");
        if sent <= 0 { break; }
        sleep_ms(50);
    }
    net::tcp_close(conn);
}

fn test_cumulative_probe_deadline() {
    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(mock_trickle_http_server, listener);

    var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 1);
    assert(proxy::add_upstream_target(cluster, "127.0.0.1", port, 1));
    var checker = proxy::new_cluster_health_checker(proxy::new_health_check_config(1000, 120, 1, 1));
    assert(proxy::register_target_for_probing(checker, 0));

    let start = core::monotonic_now();
    let st = proxy::execute_active_health_probe(checker, cluster, 0, 1000);
    let elapsed_ms = core::as_millis(core::duration_since(core::monotonic_now(), start));

    assert(st == proxy::HealthState.Down);
    assert(checker.slots[0].health.failed_probes == 1);
    assert(elapsed_ms < 500);

    assert(thread_wait(tid));
    net::tcp_close(listener);

    print("CUMULATIVE_PROBE_DEADLINE: ok\n");
    // CHECK: CUMULATIVE_PROBE_DEADLINE: ok
}

fn test_complete_upstream_exchange_measured_rtt() {
    var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
    assert(proxy::add_upstream_target(rp.cluster, "10.0.1.1", 8080, 1));
    assert(proxy::register_target_for_probing(rp.health_checker, 0));

    let idx1, ok1 = proxy::select_upstream(rp.cluster);
    assert(ok1 && idx1 == 0);
    proxy::complete_upstream_exchange(rp, idx1, 200, true, 420);
    assert(rp.health_checker.slots[0].health.last_rtt_us == 420);

    // Default rtt_us = 0 preserves backward-compatible 4-arg call shape.
    let idx2, ok2 = proxy::select_upstream(rp.cluster);
    assert(ok2 && idx2 == 0);
    proxy::complete_upstream_exchange(rp, idx2, 200, true);
    assert(rp.health_checker.slots[0].health.last_rtt_us == 0);

    print("COMPLETE_EXCHANGE_RTT_US: ok\n");
    // CHECK: COMPLETE_EXCHANGE_RTT_US: ok
}

fn main() {
    test_live_http_active_probes_and_recovery();
    test_live_https_active_probe_with_sni_and_ca_store();
    test_unregister_target_and_slot_compaction();
    test_cumulative_probe_deadline();
    test_complete_upstream_exchange_measured_rtt();
}
