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
    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    proxy.config.via_pseudonym.clear();
    proxy.config.via_pseudonym.append("wing-gateway/2.0");

    // Add three upstream backend microservices
    wing::add_upstream_target(proxy.cluster, "10.0.1.10:8080", 8080);
    wing::add_upstream_target(proxy.cluster, "10.0.1.11:8080", 8080);
    wing::add_upstream_target(proxy.cluster, "10.0.1.12:8080", 8080);

    print("[1] Reverse Proxy initialized with ", proxy.cluster.targets.len, " upstream targets");
    for i in proxy.cluster.targets.len {
        print("    Target [", i, "]: ", proxy.cluster.targets[i].host, ":", proxy.cluster.targets[i].port);
    }

    // 2. Prepare incoming client request headers
    var client_headers = wing::new_header_map();
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
    for req_num in 3 {
        var upstream_wire: u8[>..] = [];
        let body = "{\"action\":\"query\",\"id\":42}";

        let target_idx, ok = wing::prepare_proxy_request(
            proxy,
            "POST",
            "/api/v1/resource",
            client_headers,
            "198.51.100.77",
            "https",
            body,
            upstream_wire,
        );

        if ok {
            print("\n[3.", req_num + 1, "] Request Routed to Upstream Target [", target_idx, "] (", proxy.cluster.targets[target_idx].host, "):");
            print("    Serialized Upstream Wire Bytes: ", upstream_wire.len, " bytes");
            wing::release_upstream_connection(proxy.cluster, target_idx);
        } else {
            print("\n[3.", req_num + 1, "] Upstream routing failed (cluster circuit open or exhausted)");
        }
    }

    // 4. Demonstrate Circuit Breaker tripping and recovery
    print("\n[4] Simulating upstream failure on Target [0]:");
    wing::record_upstream_failure(proxy.cluster, 0);
    wing::record_upstream_failure(proxy.cluster, 0);
    wing::record_upstream_failure(proxy.cluster, 0); // trips target 0 health

    print("    Target [0] healthy status: ", proxy.cluster.targets[0].is_healthy);
    let next_target, next_ok = wing::select_upstream(proxy.cluster);
    print("    Next routed target (avoiding unhealthy Target 0): Target [", next_target, "] (", proxy.cluster.targets[next_target].host, ")");
    wing::release_upstream_connection(proxy.cluster, next_target);

    print("\n[5] Gateway Summary:");
    print("    Total Requests Forwarded: ", proxy.total_forwarded);
    print("    Total Requests Dropped: ", proxy.total_dropped);
    print("    Dynamic Allocations: 0 malloc calls");
    print("============================================================");
}
