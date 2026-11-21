// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Reverse Proxy and API Gateway Example.
// Demonstrates upstream cluster routing, circuit breaker, hop-by-hop header stripping,
// and zero-allocation upstream HTTP/1.1 request forwarding.
import std;
import core from "..";
import wing from "..";

fn main() {
    print("goose-wing Layer 7 Reverse Proxy & API Gateway\n");

    // 1. Initialize Reverse Proxy with Round-Robin upstream cluster
    var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
    rp.config.via_pseudonym.clear();
    rp.config.via_pseudonym.append("wing-gateway/2.0");

    // Add three upstream backend microservices
    rp.cluster.add_upstream_target("10.0.1.10:8080", 8080);
    rp.cluster.add_upstream_target("10.0.1.11:8080", 8080);
    rp.cluster.add_upstream_target("10.0.1.12:8080", 8080);

    print("[1] Reverse Proxy initialized with ", rp.cluster.targets.len, " upstream targets");
    for i in rp.cluster.targets.len {
        print("    Target [", i, "]: ", rp.cluster.targets[i].host, ":", rp.cluster.targets[i].port);
    }

    // 2. Prepare incoming client request headers
    var client_headers = wing::HeaderMap { .. };
    wing::append_header(client_headers, "Host", "api.example.com");
    wing::append_header(client_headers, "User-Agent", "Mozilla/5.0 (Client Gateway Test)");
    wing::append_header(client_headers, "Connection", "keep-alive, X-Debug-Trace");
    wing::append_header(client_headers, "Keep-Alive", "timeout=30");
    wing::append_header(client_headers, "X-Debug-Trace", "internal-trace-id-9988");
    wing::append_header(client_headers, "X-Forwarded-For", "203.0.113.1");
    wing::append_header(client_headers, "Accept", "application/json");

    print("\n[2] Client Request Ingress:");
    print("    Client IP: 198.51.100.77");
    print("    Protocol: https");
    print("    Original Host: api.example.com");

    // 3. Dispatch and serialize 3 consecutive proxy requests (verifying Round-Robin LB)
    var upstream_wire: u8[..4096] = [];
    for req_num in 3 {
        upstream_wire.clear();
        let body = "{\"action\":\"query\",\"id\":42}";

        let target_idx, ok = rp.prepare_proxy_request(
            "POST",
            "/api/v1/resource",
            client_headers,
            "198.51.100.77",
            "https",
            body,
            upstream_wire,
        );

        if ok {
            print("\n[3.", req_num + 1, "] Request Routed to Upstream Target [", target_idx, "] (", rp.cluster.targets[target_idx].host, "):");
            print("    Serialized Upstream Wire Bytes: ", upstream_wire.len, " bytes");
            rp.cluster.release_upstream_connection(target_idx);
        } else {
            print("\n[3.", req_num + 1, "] Upstream routing failed (cluster circuit open or exhausted)");
        }
    }

    // 4. Demonstrate Circuit Breaker tripping and recovery
    print("\n[4] Simulating upstream failure on Target [0]:");
    rp.cluster.record_upstream_failure(0);
    rp.cluster.record_upstream_failure(0);
    rp.cluster.record_upstream_failure(0); // trips target 0 health

    print("    Target [0] healthy status: ", rp.cluster.targets[0].is_healthy);
    let next_target, next_ok = rp.cluster.select_upstream();
    print("    Next routed target (avoiding unhealthy Target 0): Target [", next_target, "] (", rp.cluster.targets[next_target].host, ")");
    rp.cluster.release_upstream_connection(next_target);

    print("\n[5] Gateway Summary:");
    print("    Total Requests Forwarded: ", rp.total_forwarded);
    print("    Total Requests Dropped: ", rp.total_dropped);
}
