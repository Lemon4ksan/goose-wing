// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for proxy/health_check and load_balancer integration:
// Active background health check probing, state machine transitions (UP, DOWN, PROBING),
// consecutive success/failure thresholds, and circuit breaker interlock.
import std;
import core from "..";
import wing from "..";

fn test_health_state_transitions(t: core::T&) {
    t.run("Up -> Down on Consecutive Failures") { sub =>
        let cfg = wing::new_health_check_config(5000, 2000, 2, 3);
        var health = wing::new_upstream_health();
        sub.assert_true(health.state == wing::HealthState.Up, "Initial state is Up");

        // Fail 1 & 2: still Up
        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Up, "State remains Up after 1 failure");
        sub.assert_eq(health.consecutive_failures, 1, "Consecutive failures = 1");

        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Up, "State remains Up after 2 failures");

        // Fail 3: threshold reached -> transitions to Down
        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Down, "State transitioned to Down at 3 failures");
        sub.assert_eq(health.consecutive_failures, 3, "Consecutive failures = 3");
    };

    t.run("Down -> Probing -> Up on Consecutive Successes") { sub =>
        let cfg = wing::new_health_check_config(5000, 2000, 2, 3);
        var health = wing::new_upstream_health();
        health.state = wing::HealthState.Down;
        health.consecutive_failures = 3;

        // Manual or probe entry to Probing
        let entered = wing::enter_probing_state(health);
        sub.assert_true(entered, "Successfully entered Probing state from Down");
        sub.assert_true(health.state == wing::HealthState.Probing, "State is Probing");

        // First success: not yet Up (threshold is 2)
        wing::record_probe_success(health, 1500, cfg);
        sub.assert_true(health.state == wing::HealthState.Probing, "Still Probing after 1 success");
        sub.assert_eq(health.consecutive_successes, 1, "Consecutive successes = 1");
        sub.assert_eq(health.consecutive_failures, 0, "Failures reset on success");

        // Second success: reaches threshold 2 -> transitions to Up
        wing::record_probe_success(health, 1200, cfg);
        sub.assert_true(health.state == wing::HealthState.Up, "State transitioned to Up at 2 successes");
        sub.assert_eq(health.consecutive_successes, 2, "Consecutive successes = 2");
    };

    t.run("Probing Failure Demotes to Down") { sub =>
        let cfg = wing::new_health_check_config(5000, 2000, 2, 1);
        var health = wing::new_upstream_health();
        health.state = wing::HealthState.Probing;
        health.consecutive_successes = 1;

        // Failure during probing immediately drops back to Down
        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Down, "Failed probe in Probing drops to Down");
        sub.assert_eq(health.consecutive_successes, 0, "Successes reset to 0");
    };
}

fn test_probe_wire_and_response_parsing(t: core::T&) {
    t.run("Format Health Probe HTTP/1.1 Request") { sub =>
        var wire: u8[>..] = [];
        wing::format_health_probe_request("api.internal:8080", "/healthz", wire);

        let s = wire[..];
        sub.assert_true(s.len > 0, "Wire buffer populated");
        sub.assert_eq(s[0..4], "GET ", "Begins with GET");
        sub.assert_true(core::contains(s, "Host: api.internal:8080"), "Contains Host header");
        sub.assert_true(core::contains(s, "User-Agent: wing-health-probe"), "Contains User-Agent");
        sub.assert_true(core::contains(s, "Connection: close"), "Contains Connection: close");
    };

    t.run("Parse HTTP Status Code from Wire Response") { sub =>
        let resp_200: u8[..64] = "HTTP/1.1 200 OK\r\nContent-Len: 0\r\n";
        let code200, ok200 = wing::parse_probe_status_code(resp_200[..]);
        sub.assert_true(ok200, "Parsed 200 response");
        sub.assert_eq(code200, 200, "Code is 200");
        sub.assert_true(wing::evaluate_probe_response(resp_200[..], 200), "Evaluate 200 matches expected");

        let resp_503: u8[..64] = "HTTP/1.1 503 Unavailable\r\n\r\n";
        let code503, ok503 = wing::parse_probe_status_code(resp_503[..]);
        sub.assert_true(ok503, "Parsed 503 response");
        sub.assert_eq(code503, 503, "Code is 503");
        sub.assert_true(!wing::evaluate_probe_response(resp_503[..], 200), "503 does not match 200");

        let resp_bad: u8[..16] = "GARBAGE DATA";
        let _, ok_bad = wing::parse_probe_status_code(resp_bad[..]);
        sub.assert_true(!ok_bad, "Garbage data rejected cleanly");
    };
}

fn test_cluster_health_checker_integration(t: core::T&) {
    t.run("Cluster Active Health Check Engine") { sub =>
        var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
        wing::add_upstream_target(cluster, "10.0.0.1", 8080);
        wing::add_upstream_target(cluster, "10.0.0.2", 8080);

        let cfg = wing::new_health_check_config(1000, 500, 2, 2);
        var checker = wing::new_cluster_health_checker(cfg);
        wing::register_target_for_probing(checker, 0);
        wing::register_target_for_probing(checker, 1);

        // Fail target 0 via load balancer failures
        wing::record_upstream_failure(cluster, 0);
        wing::record_upstream_failure(cluster, 0);
        sub.assert_true(!cluster.targets[0].is_healthy, "Target 0 is marked unhealthy");
        sub.assert_true(cluster.targets[0].health_state == wing::UpstreamHealthState.Down, "Target 0 state is Down");

        // Fail target 1 via health checker failure
        let state1 = wing::on_probe_failure(checker, cluster, 1);
        sub.assert_true(state1 == wing::HealthState.Up, "Target 1 remains Up on 1st fail");
        let state2 = wing::on_probe_failure(checker, cluster, 1);
        sub.assert_true(state2 == wing::HealthState.Down, "Target 1 Down on 2nd fail");
        sub.assert_true(cluster.circuit_open, "Cluster circuit tripped open when all targets are Down");

        // Recover target 0 via active probe successes
        wing::on_probe_success(checker, cluster, 0, 800);
        sub.assert_true(cluster.targets[0].health_state == wing::UpstreamHealthState.Probing, "Target 0 enters Probing");

        wing::on_probe_success(checker, cluster, 0, 750);
        sub.assert_true(cluster.targets[0].health_state == wing::UpstreamHealthState.Up, "Target 0 promoted to Up");
        sub.assert_true(cluster.targets[0].is_healthy, "Target 0 is healthy again");
        sub.assert_true(!cluster.circuit_open, "Cluster circuit breaker restored");

        // Verify upstream dispatch now succeeds and selects target 0
        let chosen, ok = wing::select_upstream(cluster);
        sub.assert_true(ok, "Upstream selection succeeds");
        sub.assert_eq(chosen, 0, "Target 0 selected");
    };
}

fn test_reverse_proxy_hardening(t: core::T&) {
    t.run("Connection Leak Defense and Lifecycle") { sub =>
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "upstream.local:8080", 8080);

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "frontend.test");

        var wire: u8[>..] = [];
        let t_idx, ok = wing::prepare_proxy_request(proxy, "GET", "/api", in_headers, "127.0.0.1", "http", "", wire);
        sub.assert_true(ok, "Proxy request prepared");
        sub.assert_eq(t_idx, 0, "Dispatched to target 0");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 1, "Target 0 active_conns = 1");

        // Complete successfully -> active_conns decremented
        wing::finish_proxy_request(proxy, t_idx, true);
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 0, "Active conns decremented to 0 upon finish");

        // Dispatched second time, then aborted -> active_conns decremented cleanly
        let t_idx2, ok2 = wing::prepare_proxy_request(proxy, "GET", "/api", in_headers, "127.0.0.1", "http", "", wire);
        sub.assert_true(ok2, "Second request prepared");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 1, "Active conns is 1");

        wing::abort_proxy_request(proxy, t_idx2);
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 0, "Active conns decremented to 0 upon abort");
    };

    t.run("Concurrency Backpressure and Overload Defense") { sub =>
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "backend.srv:8080", 8080);
        proxy.config.max_active_conns_per_target = 2;

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "test.example.com");

        var wire: u8[>..] = [];
        let idx1, ok1 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.1", "http", "", wire);
        let idx2, ok2 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.2", "http", "", wire);
        sub.assert_true(ok1 && ok2, "First 2 requests admitted up to concurrency ceiling");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Active connections reached ceiling of 2");

        // 3rd request exceeds max_active_conns_per_target (2)
        let idx3, ok3 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.3", "http", "", wire);
        sub.assert_true(!ok3, "3rd request rejected due to target concurrency overload");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Active conns remains 2 (no connection leak!)");
        sub.assert_eq(proxy.total_overloaded, 1, "total_overloaded recorded");
        sub.assert_eq(proxy.total_dropped, 1, "total_dropped recorded");

        // Finishing request 1 frees slot
        wing::finish_proxy_request(proxy, idx1, true);
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 1, "Active conns decreased to 1");

        // Now next request succeeds
        let idx4, ok4 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.4", "http", "", wire);
        sub.assert_true(ok4, "Admitted after connection freed");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Active conns is back to 2");
    };

    t.run("Hop-by-hop and Metadata Spoofing Defense") { sub =>
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "app.internal:80", 80);

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "legit.example.com");
        wing::append_header(in_headers, "Connection", "keep-alive, X-Secret-Internal");
        wing::append_header(in_headers, "X-Secret-Internal", "should-be-stripped");
        wing::append_header(in_headers, "X-Forwarded-Host", "evil-spoof.com");
        wing::append_header(in_headers, "X-Forwarded-Proto", "gopher");
        wing::append_header(in_headers, "X-Forwarded-Ssl", "on");

        var wire: u8[>..] = [];
        let _, ok = wing::prepare_proxy_request(proxy, "GET", "/secure", in_headers, "203.0.113.5", "https", "", wire);
        sub.assert_true(ok, "Request prepared");

        let s = wire[..];
        sub.assert_true(!core::contains(s, "evil-spoof.com"), "Spoofed X-Forwarded-Host stripped");
        sub.assert_true(!core::contains(s, "gopher"), "Spoofed X-Forwarded-Proto stripped");
        sub.assert_true(!core::contains(s, "should-be-stripped"), "Connection-listed token stripped");
        sub.assert_true(!core::contains(s, "X-Forwarded-Ssl"), "X-Forwarded-Ssl stripped");
        sub.assert_true(core::contains(s, "X-Forwarded-Proto: https"), "Valid proxy proto injected");
        sub.assert_true(core::contains(s, "X-Forwarded-Host: legit.example.com"), "Valid proxy host injected");
    };

    t.run("GCRA Rate Limiting Shield") { sub =>
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "backend.internal:8080", 8080);
        proxy.config.enable_rate_limiting = true;
        proxy.rate_limiter = wing::new_gateway_rate_limiter(10, 1); // 10 rps, burst 1

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "test.example.com");

        var wire: u8[>..] = [];
        let client_ip: u8[..16] = "198.51.100.77";
        let now_ns: u64 = 1000000000;

        let _, ok1 = wing::prepare_proxy_request_at(proxy, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        let _, ok2 = wing::prepare_proxy_request_at(proxy, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(ok1 && ok2, "Burst requests admitted");

        // 3rd request at same timestamp -> Rate limited!
        let _, ok3 = wing::prepare_proxy_request_at(proxy, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(!ok3, "3rd request rejected by GCRA rate limit");
        sub.assert_eq(proxy.total_rate_limited, 1, "total_rate_limited recorded");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Upstream active conns untouched by rejected request");
    };
}

fn main() {
    var runner = core::new_runner("proxy/health_check & Load Balancer Integration", core::Verbosity.Verbose);
    core::run_case(runner, "1. Health State Machine Transitions", test_health_state_transitions);
    core::run_case(runner, "2. Probe Wire Formatting and Response Evaluation", test_probe_wire_and_response_parsing);
    core::run_case(runner, "3. Cluster Health Checker Engine", test_cluster_health_checker_integration);
    core::run_case(runner, "4. Reverse Proxy Hardening & Backpressure", test_reverse_proxy_hardening);
    let ok = core::finish(runner);
    assert(ok);
}
