// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// RFC 9110 §7.6: Layer 7 Reverse Proxy Hop-by-Hop Filter and Load Balancer Verification
import std;
import core from "../..";
import wing from "../..";

fn test_load_balancer_round_robin() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    wing::add_upstream_target(cluster, "10.0.0.1", 8080);
    wing::add_upstream_target(cluster, "10.0.0.2", 8080);
    wing::add_upstream_target(cluster, "10.0.0.3", 8080);

    let idx1, ok1 = wing::select_upstream(cluster);
    let idx2, ok2 = wing::select_upstream(cluster);
    let idx3, ok3 = wing::select_upstream(cluster);
    let idx4, ok4 = wing::select_upstream(cluster);

    print("LB_RR: ", ok1, " ", idx1, " -> ", ok2, " ", idx2, " -> ", ok3, " ", idx3, " -> ", ok4, " ", idx4, "\n");
    // CHECK: LB_RR: true 0 -> true 1 -> true 2 -> true 0
}

fn test_load_balancer_circuit_breaker() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
    wing::add_upstream_target(cluster, "10.0.0.1", 8080);
    wing::add_upstream_target(cluster, "10.0.0.2", 8080);

    // Fail target 0 twice -> marks target 0 unhealthy
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);

    let idx1, ok1 = wing::select_upstream(cluster);
    let idx2, ok2 = wing::select_upstream(cluster);

    // Fail target 1 twice -> trips circuit breaker
    wing::record_upstream_failure(cluster, 1);
    wing::record_upstream_failure(cluster, 1);

    let idx3, ok3 = wing::select_upstream(cluster);

    print(
        "LB_CB: t0_fail_routed_to_t1=", (idx1 == 1 && idx2 == 1),
        " circuit_open=", cluster.circuit_open,
        " exhausted=", !ok3, "\n",
    );
    // CHECK: LB_CB: t0_fail_routed_to_t1=true circuit_open=true exhausted=true

    // Recover target 0
    wing::record_upstream_success(cluster, 0);
    let idx4, ok4 = wing::select_upstream(cluster);
    print("LB_RECOVER: ok=", ok4, " target=", idx4, " circuit_open=", cluster.circuit_open, "\n");
    // CHECK: LB_RECOVER: ok=true target=0 circuit_open=false
}

fn test_load_balancer_least_connections() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.LeastConnections, 3);
    wing::add_upstream_target(cluster, "srv-a", 80);
    wing::add_upstream_target(cluster, "srv-b", 80);

    // Target 0 has 5 active connections, target 1 has 1 active connection
    cluster.targets[0].active_conns = 5;
    cluster.targets[1].active_conns = 1;

    let chosen, ok = wing::select_upstream(cluster);
    print("LB_LEAST_CONN: chosen=", chosen, " active_conns=", cluster.targets[chosen].active_conns, "\n");
    // CHECK: LB_LEAST_CONN: chosen=1 active_conns=2

    wing::release_upstream_connection(cluster, chosen);
    print("LB_RELEASE: conns_after_release=", cluster.targets[1].active_conns, "\n");
    // CHECK: LB_RELEASE: conns_after_release=1
}

fn test_reverse_proxy_hop_by_hop_stripping() {
    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "frontend.example.com");
    wing::append_header(in_headers, "User-Agent", "curl/8.0");
    wing::append_header(in_headers, "Connection", "keep-alive, X-Foo-Internal");
    wing::append_header(in_headers, "Keep-Alive", "timeout=5");
    wing::append_header(in_headers, "Upgrade", "websocket");
    wing::append_header(in_headers, "Transfer-Encoding", "chunked");
    wing::append_header(in_headers, "X-Foo-Internal", "secret-token");
    wing::append_header(in_headers, "X-Custom-Data", "retained-value");
    wing::append_header(in_headers, "TE", "trailers");

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.preserve_host = false;
    cfg.via_pseudonym.clear();
    cfg.via_pseudonym.append("wing-gw");

    wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "203.0.113.195",
        "https",
        "backend.internal:8080",
        cfg,
    );

    let h_host = wing::get_header(out_headers, "Host");
    let h_ua = wing::get_header(out_headers, "User-Agent");
    let h_conn = wing::get_header(out_headers, "Connection");
    let h_ka = wing::get_header(out_headers, "Keep-Alive");
    let h_upg = wing::get_header(out_headers, "Upgrade");
    let h_te = wing::get_header(out_headers, "TE");
    let h_internal = wing::get_header(out_headers, "X-Foo-Internal");
    let h_data = wing::get_header(out_headers, "X-Custom-Data");
    let h_xff = wing::get_header(out_headers, "X-Forwarded-For");
    let h_proto = wing::get_header(out_headers, "X-Forwarded-Proto");
    let h_xfh = wing::get_header(out_headers, "X-Forwarded-Host");
    let h_via = wing::get_header(out_headers, "Via");

    print("H_HOST: ", h_host, "\n");
    // CHECK: H_HOST: backend.internal:8080
    print("H_UA: ", h_ua, "\n");
    // CHECK: H_UA: curl/8.0
    print("H_STRIPPED: conn=", h_conn.len, " ka=", h_ka.len, " upg=", h_upg.len, " internal=", h_internal.len, "\n");
    // CHECK: H_STRIPPED: conn=0 ka=0 upg=0 internal=0
    print("H_TE_TRAILERS: ", h_te, "\n");
    // CHECK: H_TE_TRAILERS: trailers
    print("H_CUSTOM: ", h_data, "\n");
    // CHECK: H_CUSTOM: retained-value
    print("H_XFF: ", h_xff, "\n");
    // CHECK: H_XFF: 203.0.113.195
    print("H_PROTO: ", h_proto, "\n");
    // CHECK: H_PROTO: https
    print("H_XFH: ", h_xfh, "\n");
    // CHECK: H_XFH: frontend.example.com
    print("H_VIA: ", h_via, "\n");
    // CHECK: H_VIA: 1.1 wing-gw
}

fn test_reverse_proxy_xff_chaining() {
    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "api.example.com");
    wing::append_header(in_headers, "X-Forwarded-For", "198.51.100.1, 10.0.0.1");

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.trust_incoming_xff = true;

    wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.42",
        "http",
        "app-cluster",
        cfg,
    );

    let chained_xff = wing::get_header(out_headers, "X-Forwarded-For");
    print("XFF_CHAINED: ", chained_xff, "\n");
    // CHECK: XFF_CHAINED: 198.51.100.1, 10.0.0.1, 192.0.2.42
}

fn test_reverse_proxy_xff_untrusted_perimeter() {
    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "api.example.com");
    wing::append_header(in_headers, "X-Forwarded-For", "127.0.0.1, 10.0.0.1");

    var out_headers = wing::HeaderMap { .. };
    let cfg = wing::ProxyConfig { .. }; // trust_incoming_xff is false by default

    wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.42",
        "http",
        "app-cluster",
        cfg,
    );

    let perimeter_xff = wing::get_header(out_headers, "X-Forwarded-For");
    print("XFF_PERIMETER: ", perimeter_xff, "\n");
    // CHECK: XFF_PERIMETER: 192.0.2.42
}

fn test_upstream_request_wire_serialization() {
    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    wing::add_upstream_target(proxy.cluster, "upstream.local:9000", 9000);

    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "public.example.com");
    wing::append_header(in_headers, "Accept", "application/json");

    var wire_out: u8[>..] = [];
    let body = "{\"event\":\"ping\"}";

    let idx, ok = wing::prepare_proxy_request(
        proxy,
        "POST",
        "/api/v2/events",
        in_headers,
        "172.16.0.5",
        "https",
        body,
        wire_out,
    );

    print("WIRE_OK: ", ok, " target_idx=", idx, "\n");
    // CHECK: WIRE_OK: true target_idx=0

    let wire_str = wire_out[..];
    print("WIRE_START: ", wire_str[0..28], "\n");
    // CHECK: WIRE_START: POST /api/v2/events HTTP/1.1
    print("WIRE_TOTAL_LEN: ", wire_out.len > 100, "\n");
    // CHECK: WIRE_TOTAL_LEN: true
}

fn main() {
    print("=== LIT Reverse Proxy & Load Balancer Verification ===\n");
    test_load_balancer_round_robin();
    test_load_balancer_circuit_breaker();
    test_load_balancer_least_connections();
    test_reverse_proxy_hop_by_hop_stripping();
    test_reverse_proxy_xff_chaining();
    test_reverse_proxy_xff_untrusted_perimeter();
    test_upstream_request_wire_serialization();
}
