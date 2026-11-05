// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Layer 7 Reverse Proxy, Load Balancer, Active Health Checker, and GCRA Rate Limiter
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// 1. Load Balancer: Weights, PRNG, and State Transitions
// ----------------------------------------------------------------------------
fn test_load_balancer(t: lit::T&) {
    t.run("LeastConnections respects upstream weights") { sub =>
        var cluster = wing::new_upstream_cluster(wing::LbPolicy.LeastConnections, 3);
        sub.assert_true(wing::add_upstream_target(cluster, "srv-weight-1", 80, 1), "add target 1");
        sub.assert_true(wing::add_upstream_target(cluster, "srv-weight-2", 80, 2), "add target 2");

        // Both targets have 1 active connection.
        // Target 0 (weight 1): normalized load = 1 / 1 = 1.0
        // Target 1 (weight 2): normalized load = 1 / 2 = 0.5
        cluster.targets[0].active_conns = 1;
        cluster.targets[1].active_conns = 1;

        let chosen, ok = wing::select_upstream(cluster);
        sub.assert_true(ok, "upstream selected");
        sub.assert_eq(chosen, 1, "target with weight 2 chosen over weight 1 with equal connections");
    };

    t.run("PowerOfTwoChoices respects target weights") { sub =>
        var t1 = wing::UpstreamTarget { active_conns: 2, weight: 1, .. };
        var t2 = wing::UpstreamTarget { active_conns: 3, weight: 2, .. };

        // t1: 2 conns * 2 weight2 = 4
        // t2: 3 conns * 1 weight1 = 3 -> t2 has lower weighted load
        let chosen = wing::evaluate_two_choice(t1, 0, t2, 1);
        sub.assert_eq(chosen, 1, "P2C selects target 2 due to higher weight capacity");
    };

    t.run("PRNG preserves non-zero 64-bit entropy") { sub =>
        var state: u64 = 0x123456789abcdef0;
        let r1 = wing::next_prng(state);
        let r2 = wing::next_prng(state);
        let r3 = wing::next_prng(state);

        sub.assert_ne(r1, r2, "PRNG values differ across steps");
        sub.assert_ne(r2, r3, "PRNG sequence continues");
        sub.assert_ne(state, 0, "PRNG state remains non-zero");
    };

    t.run("Probing target is selectable during recovery") { sub =>
        var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
        sub.assert_true(wing::add_upstream_target(cluster, "srv-probe", 80, 1), "add target");
        cluster.targets[0].is_healthy = false;
        cluster.targets[0].health_state = wing::UpstreamHealthState.Probing;

        let chosen, ok = wing::select_upstream(cluster);
        sub.assert_true(ok, "probing target is selected for trial traffic");
        sub.assert_eq(chosen, 0, "target 0 selected");
    };
}

// ----------------------------------------------------------------------------
// 2. Active Health Check: Prober State Machine & Thresholds
// ----------------------------------------------------------------------------
fn test_health_check(t: lit::T&) {
    t.run("Probing failure immediately trips to Down") { sub =>
        let config = wing::new_health_check_config(5000, 2000, 2, 3);
        var health = wing::UpstreamHealth {
            state:                 wing::HealthState.Probing,
            consecutive_successes: 1,
            consecutive_failures:  0,
            ..
        };

        let new_state = wing::record_probe_failure(health, config);
        sub.assert_eq(new_state, wing::HealthState.Down, "failure during Probing immediately trips Down");
        sub.assert_eq(health.consecutive_successes, 0, "success streak cleared on failure");
    };

    t.run("Consecutive successes transition Probing to Up") { sub =>
        let config = wing::new_health_check_config(5000, 2000, 2, 3);
        var health = wing::UpstreamHealth {
            state:                 wing::HealthState.Down,
            consecutive_successes: 0,
            consecutive_failures:  3,
            ..
        };

        // First success transitions Down -> Probing
        let s1 = wing::record_probe_success(health, 500, config);
        sub.assert_eq(s1, wing::HealthState.Probing, "first success enters Probing");

        // Second success reaches healthy_threshold (2) -> transitions to Up
        let s2 = wing::record_probe_success(health, 400, config);
        sub.assert_eq(s2, wing::HealthState.Up, "second success reaches threshold and enters Up");
    };

    t.run("Probe HTTP status code parser") { sub =>
        let wire_200 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let code_200, ok_200 = wing::parse_probe_status_code(wire_200);
        sub.assert_true(ok_200, "parse 200 ok");
        sub.assert_eq(code_200, 200, "status 200");

        let wire_503 = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
        let code_503, ok_503 = wing::parse_probe_status_code(wire_503);
        sub.assert_true(ok_503, "parse 503 ok");
        sub.assert_eq(code_503, 503, "status 503");

        let config = wing::new_health_check_config(5000, 2000, 2, 3);
        sub.assert_true(wing::evaluate_probe_response(wire_200, 200), "validate expected 200");
        sub.assert_false(wing::evaluate_probe_response(wire_503, 200), "reject unexpected 503");
    };
}

// ----------------------------------------------------------------------------
// 3. GCRA Rate Limiter: Headroom, Burst Headroom, and Buffer Limits
// ----------------------------------------------------------------------------
fn test_gcra_rate_limiter(t: lit::T&) {
    t.run("Burst headroom derivation: tau = T * B") { sub =>
        // 10 req/sec -> T = 100,000,000 ns (100ms)
        // burst = 5 -> tau = 100ms * 5 = 500ms
        // window = tau + T = 600ms
        let config = wing::new_gcra_config(10, 5);
        sub.assert_eq(config.emission_interval_ns, 100000000, "T is 100ms");
        sub.assert_eq(config.tau_ns, 500000000, "tau is 500ms");
        sub.assert_eq(config.limit_window_ns, 600000000, "limit window is 600ms");
    };

    t.run("Multi-cell burst allowance at t=0") { sub =>
        let config = wing::new_gcra_config(10, 2); // T=100ms, tau=200ms, burst=2
        var cell = wing::GcraTatCell { tat_ns: 0 };
        let now: u64 = 1000000000; // t=1.0s

        // 1st request admitted
        let d1 = wing::gcra_check(config, cell, 1, now);
        sub.assert_true(d1.allowed, "1st request allowed");

        // 2nd request admitted
        let d2 = wing::gcra_check(config, cell, 1, now);
        sub.assert_true(d2.allowed, "2nd request allowed");

        // 3rd request admitted
        let d3 = wing::gcra_check(config, cell, 1, now);
        sub.assert_true(d3.allowed, "3rd request allowed");

        // 4th request rejected (burst capacity 2 exhausted at instant t=1.0s)
        let d4 = wing::gcra_check(config, cell, 1, now);
        sub.assert_false(d4.allowed, "4th request rejected");
    };

    t.run("Client ID overflow rejected without truncation") { sub =>
        var limiter = wing::new_gateway_rate_limiter(10, 5);
        let oversized_key = "012345678901234567890123456789012345678901234567890123456789012345"; // 66 bytes

        let slot = wing::find_client_slot(limiter, oversized_key);
        sub.assert_eq(slot, wing::GATEWAY_LIMITER_NONE, "oversized client ID rejected by find_client_slot");

        let dec = wing::check_gateway_rate_limit(limiter, oversized_key, 1, 1000000000);
        sub.assert_true(dec.allowed, "fallback admission handled");
        sub.assert_eq(limiter.entries.len, 0, "oversized key was NOT inserted into entries table");
    };
}

// ----------------------------------------------------------------------------
// 4. Reverse Proxy: Stream Ring Buffer & Zero-Copy Forwarding
// ----------------------------------------------------------------------------
fn test_reverse_proxy_streaming(t: lit::T&) {
    t.run("Stream ring compacting and slice vending") { sub =>
        var ring = wing::ProxyStreamRing { .. };
        sub.assert_true(wing::feed_stream_chunk(ring, "Hello, World!"), "feed chunk");
        sub.assert_eq(ring.buf.len, 13, "buffered length");

        let slice1 = wing::incoming_slice(ring);
        sub.assert_eq(slice1, "Hello, World!", "incoming slice");

        // Consume 7 bytes ("Hello, ")
        sub.assert_true(wing::advance_read(ring, 7), "advance read 7 bytes");
        sub.assert_eq(ring.read_pos, 7, "read cursor at 7");

        let slice2 = wing::incoming_slice(ring);
        sub.assert_eq(slice2, "World!", "incoming slice after advance");

        // Compact ring
        wing::compact_stream_ring(ring);
        sub.assert_eq(ring.read_pos, 0, "read cursor reset to 0 after compaction");
        sub.assert_eq(ring.buf.len, 6, "compacted length is remaining 6 bytes");

        let slice3 = wing::incoming_slice(ring);
        sub.assert_eq(slice3, "World!", "incoming slice after compaction");
    };

    t.run("WebSocket userspace streaming masking") { sub =>
        var src = wing::ProxyStreamRing { .. };
        var dst = wing::ProxyStreamRing { .. };

        sub.assert_true(wing::feed_stream_chunk(src, "ping"), "feed plain payload");

        let mask: u8[4] = [0x12, 0x34, 0x56, 0x78];
        let n, ok = wing::forward_userspace_stream_chunk(src, dst, wing::ProxyTransportKind.WebSocket, mask);
        sub.assert_true(ok, "forward chunk ok");
        sub.assert_eq(n, 4, "forwarded 4 bytes");

        let masked_slice = wing::incoming_slice(dst);
        sub.assert_eq(masked_slice[0], ('p' as u8) ^ 0x12, "byte 0 masked with key[0]");
        sub.assert_eq(masked_slice[1], ('i' as u8) ^ 0x34, "byte 1 masked with key[1]");
        sub.assert_eq(masked_slice[2], ('n' as u8) ^ 0x56, "byte 2 masked with key[2]");
        sub.assert_eq(masked_slice[3], ('g' as u8) ^ 0x78, "byte 3 masked with key[3]");
    };

    t.run("Live ReverseProxy exchange over StreamPool") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        guard listener > 0 else { return; }
        let port = wing::tcp_getsockname_port(listener);
        sub.assert_gt(port as i64, 0, "ephemeral port allocated");

        let client_sock = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client_sock, 0, "connected to upstream listener");
        let server_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_sock, 0, "accepted upstream socket");

        let canned_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nUpstream Pong";
        let _ = wing::tcp_send(server_sock, canned_resp);

        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        sub.assert_true(wing::add_upstream_target(proxy.cluster, "127.0.0.1", port, 1), "added upstream");

        var pool = wing::new_stream_pool();
        let pkey = wing::new_pool_key(
            wing::PoolScheme.Http,
            "127.0.0.1",
            port,
            wing::new_direct_proxy_chain(),
            wing::NetworkAnonymizationKey { .. },
            wing::TlsAndDnsPolicy { .. },
        );
        let t = wing::Transport.Tcp { fd: client_sock };
        let cid = wing::register_connection(pool, pkey, wing::NegotiatedProtocol.Http11, t, "127.0.0.1", 1, 1000);
        sub.assert_gt(cid as i64, 0, "registered warm connection in pool");
        let _ = wing::release_connection(pool, cid, 1000);

        var in_hdrs = wing::HeaderMap { .. };
        let _ = wing::append_header(in_hdrs, "Host", "edge.example.com");
        var resp = wing::Response { .. };
        let ok_ex = wing::execute_proxy_exchange(
            proxy, pool, "GET", "/v1/health", in_hdrs, "203.0.113.5", "https", "", resp, 2000, 2000,
        );
        sub.assert_true(ok_ex, "execute_proxy_exchange succeeded");
        sub.assert_eq(resp.status_code, 200, "upstream status 200");
        sub.assert_bytes_eq(resp.body[..], "Upstream Pong", "upstream body forwarded");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 0, "active conns released after exchange");
        sub.assert_eq(proxy.cluster.targets[0].successes, 1, "upstream success recorded");

        wing::tcp_close(server_sock);
        wing::tcp_close(listener);
        wing::close_pooled_connection(pool, cid);
    };
}

fn main() {
    var runner = lit::new_runner("Proxy & Load Balancer Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Load Balancer: Weights, PRNG, and State Transitions", test_load_balancer);
    lit::run_case(runner, "2. Active Health Check: Prober State Machine & Thresholds", test_health_check);
    lit::run_case(runner, "3. GCRA Rate Limiter: Headroom, Burst Headroom, and Buffer Limits", test_gcra_rate_limiter);
    lit::run_case(runner, "4. Reverse Proxy: Stream Ring Buffer & Zero-Copy Forwarding", test_reverse_proxy_streaming);

    let ok = lit::finish(runner);
    assert(ok);
}
