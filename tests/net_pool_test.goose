// Verification suite for net/pool: 5-dimensional PoolKey isolation,
// two-slice WantQueue, liveness health checks, HTTP/2 IP coalescing, and soft-cap quotas.
import std;
import wing from "..";

fn test_pool_key_dimensions_and_isolation(t: wing::T&) {
    t.run("5-Dimensional PoolKey Exact Match and Partition Isolation") { sub =>
        let nak1 = wing::new_network_anonymization_key("https://a.com", false, 0, 1, 0);
        let nak2 = wing::new_network_anonymization_key("https://a.com", false, 0, 1, 0);
        let nak_cross = wing::new_network_anonymization_key("https://a.com", true, 0, 1, 0);
        let nak_nonce = wing::new_network_anonymization_key("https://a.com", false, 42, 1, 0);
        let nak_part = wing::new_network_anonymization_key("https://a.com", false, 0, 2, 0);
        let nak_worker = wing::new_network_anonymization_key("https://a.com", false, 0, 1, 99);

        sub.assert_true(wing::network_anonymization_key_equals(nak1, nak2), "Identical NAK matches");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_cross), "Cross-site flag isolates partition");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_nonce), "Ephemeral nonce isolates partition");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_part), "Network isolation partition isolates partition");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_worker), "Worker session ID isolates proxy automation workers");

        let direct_chain = wing::new_direct_proxy_chain();
        let socks_proxy = wing::new_proxy_server(wing::ProxyScheme.Socks5h, "proxy.local", 1080);
        let socks_chain = wing::new_single_proxy_chain(socks_proxy);

        let default_policy = wing::TlsAndDnsPolicy { .. };
        var privacy_policy = wing::TlsAndDnsPolicy { .. };
        privacy_policy.privacy_mode = wing::PrivacyMode.Enabled;

        let key1 = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, default_policy);
        let key2 = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak2, default_policy);
        let key_scheme = wing::new_pool_key(wing::PoolScheme.Http, "api.service.com", 80, direct_chain, nak1, default_policy);
        let key_proxy = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, socks_chain, nak1, default_policy);
        let key_priv = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, privacy_policy);

        sub.assert_true(wing::pool_key_equals(key1, key2), "Key1 equals Key2 with identical dimensions");
        sub.assert_false(wing::pool_key_equals(key1, key_scheme), "Scheme mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_proxy), "Proxy chain mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_priv), "Privacy mode mismatch isolates socket group");
    };

    t.run("Preconnect Scheme Normalization") { sub =>
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Ws) == wing::PoolScheme.Http, "WS maps to HTTP");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Wss) == wing::PoolScheme.Https, "WSS maps to HTTPS");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Https) == wing::PoolScheme.Https, "HTTPS preserved");
    };
}

fn test_want_queue_dual_slice(t: wing::T&) {
    t.run("FIFO Operations and Reallocation-Free Promotion") { sub =>
        var q = wing::new_want_queue();
        sub.assert_true(wing::is_queue_empty(q), "Initial queue is empty");

        let nak = wing::new_network_anonymization_key("https://origin.io");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "origin.io", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var w1 = wing::WantConn { req_id: 101, key: copy(key), .. };
        var w2 = wing::WantConn { req_id: 102, key: copy(key), .. };
        var w3 = wing::WantConn { req_id: 103, key: copy(key), .. };

        sub.assert_true(wing::push_want(q, w1), "Pushed w1");
        sub.assert_true(wing::push_want(q, w2), "Pushed w2");
        sub.assert_true(wing::push_want(q, w3), "Pushed w3");
        sub.assert_eq(wing::queue_len(q), 3, "Queue len == 3");

        let p1, ok1 = wing::pop_want(q);
        sub.assert_true(ok1 && p1.req_id == 101, "Popped w1 in FIFO order");

        // Cancel w2 while still in queue
        sub.assert_true(wing::cancel_want(q, 102), "Cancelled w2");

        let p3, ok3 = wing::pop_want(q);
        sub.assert_true(ok3 && p3.req_id == 103, "Popped w3, skipping cancelled w2");

        let p_none, ok_none = wing::pop_want(q);
        sub.assert_false(ok_none, "Queue exhausted");
    };
}

fn test_connection_liveness_and_extensive_checks(t: wing::T&) {
    t.run("OkHttp isHealthy and Non-Blocking FIN Detection") { sub =>
        let nak = wing::new_network_anonymization_key("https://example.com");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var conn = wing::PooledConnection {
            conn_id: 1,
            key: key,
            protocol: wing::NegotiatedProtocol.Http11,
            active_allocations: 0,
            idle_at_ns: 1000000000, // Idle at 1.0s
            ..
        };

        // Within healthy threshold (500ms idle) -> healthy without extensive checks
        sub.assert_true(wing::is_connection_healthy(conn, 1500000000, false), "Fresh idle connection is healthy");

        // After healthy threshold (2.5s idle) without FIN -> healthy
        sub.assert_true(wing::is_connection_healthy(conn, 3500000000, true), "Idle connection with open socket is healthy");

        // Remote closed socket (FIN received / source_exhausted)
        conn.source_exhausted = true;
        sub.assert_false(wing::is_connection_healthy(conn, 3500000000, true), "Extensive check detects source_exhausted EOF/FIN");
        sub.assert_true(conn.no_new_exchanges, "Connection marked no_new_exchanges on EOF");
        sub.assert_true(conn.closed, "Connection marked closed on EOF");
    };
}

fn test_http2_ip_coalescing_and_san_matching(t: wing::T&) {
    t.run("Chromium H2 IP Coalescing with Wildcard SAN") { sub =>
        let nak = wing::new_network_anonymization_key("https://example.com");
        let key_a = wing::new_pool_key(wing::PoolScheme.Https, "alpha.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_b = wing::new_pool_key(wing::PoolScheme.Https, "beta.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_unrelated = wing::new_pool_key(wing::PoolScheme.Https, "other.org", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var conn = wing::PooledConnection {
            conn_id: 10,
            key: copy(key_a),
            protocol: wing::NegotiatedProtocol.Http2,
            max_concurrent_streams: 100,
            active_allocations: 1,
            cert_valid: true,
            ..
        };
        conn.resolved_ip.append("93.184.216.34");
        var san1: u8[..128] = [];
        san1.append("alpha.example.com");
        conn.san_hosts.push(san1);
        var san_wild: u8[..128] = [];
        san_wild.append("*.example.com");
        conn.san_hosts.push(san_wild);

        // Target beta.example.com resolves to same IP 93.184.216.34 and matches *.example.com SAN
        let can_coalesce_b, is_neg_b = wing::can_coalesce_h2_connection(conn, key_b, "93.184.216.34");
        sub.assert_true(can_coalesce_b, "H2 connection coalesced for beta.example.com under *.example.com");
        sub.assert_false(is_neg_b, "Not a negative IP pool result");

        // Target other.org resolves to same IP but SAN does NOT match
        let can_coalesce_other, is_neg_other = wing::can_coalesce_h2_connection(conn, key_unrelated, "93.184.216.34");
        sub.assert_false(can_coalesce_other, "H2 connection rejected for unrelated domain");
        sub.assert_true(is_neg_other, "Recorded negative IP pool result for metric tracking");
    };
}

fn test_stream_pool_quotas_and_eviction(t: wing::T&) {
    t.run("Soft-Cap LRU Eviction and Priority Reuse") { sub =>
        var pool = wing::new_stream_pool(6, 32, 2); // Soft-cap of 2 connections
        let nak = wing::new_network_anonymization_key("https://service.net");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "service.net", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Add 2 connections
        let c1 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 1000000);
        let c2 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 2000000);

        // Release c1 at t=3.0s, making it idle
        wing::release_connection(pool, c1, 3000000000);

        // Adding 3rd connection exceeds soft-cap (2) -> triggers eviction of oldest idle (c1)
        let c3 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 4000000);

        sub.assert_true(pool.conns[0].closed, "Oldest idle connection c1 was evicted");
        sub.assert_eq(c3, 3, "New connection c3 registered successfully");

        // OkHttp Priority Rule: acquire_pooled_connection prefers healthy pooled connection
        let acquired_id, ok_acq = wing::acquire_pooled_connection(pool, key, "1.1.1.1", 5000000000);
        // c2 was active with allocation 1, but c3 was active with allocation 1. If we release c2:
        wing::release_connection(pool, c2, 4500000000);
        let acquired_c2, ok_c2 = wing::acquire_pooled_connection(pool, key, "1.1.1.1", 5000000000);
        sub.assert_true(ok_c2 && acquired_c2 == c2, "Reused pooled connection c2 over new dial");
    };
}

fn main() {
    var runner = wing::new_runner("net/pool Connection Pool & Isolation Suite", wing::Verbosity.Verbose);
    wing::run_case(runner, "1. PoolKey Dimensions & Isolation", test_pool_key_dimensions_and_isolation);
    wing::run_case(runner, "2. WantQueue Dual-Slice FIFO", test_want_queue_dual_slice);
    wing::run_case(runner, "3. Connection Liveness & Extensive Checks", test_connection_liveness_and_extensive_checks);
    wing::run_case(runner, "4. HTTP/2 IP Coalescing & SAN Matching", test_http2_ip_coalescing_and_san_matching);
    wing::run_case(runner, "5. StreamPool Quotas & Eviction", test_stream_pool_quotas_and_eviction);
    let ok = wing::finish(runner);
    assert(ok);
}
