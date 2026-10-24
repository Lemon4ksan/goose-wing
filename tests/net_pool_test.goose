// Verification suite for net/pool: 5-dimensional PoolKey isolation,
// two-slice WantQueue, liveness health checks, HTTP/2 IP coalescing, soft-cap quotas,
// CVE-2026-94441, CVE-2026-56866, and Go #23427 / #49377 defenses.
import std;
import core from "..";
import wing from "..";

fn test_pool_key_dimensions_and_isolation(t: core::T&) {
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

        // Case insensitivity of top frame site
        let nak_upper = wing::new_network_anonymization_key("HTTPS://A.COM", false, 0, 1, 0);
        sub.assert_true(wing::network_anonymization_key_equals(nak1, nak_upper), "Top frame site matches case-insensitively");

        let direct_chain = wing::new_direct_proxy_chain();
        let socks_proxy = wing::new_proxy_server(wing::ProxyScheme.Socks5h, "proxy.local", 1080);
        let socks_chain = wing::new_single_proxy_chain(socks_proxy);
        let http_proxy = wing::new_proxy_server(wing::ProxyScheme.Http, "proxy.local", 8080);
        let http_chain = wing::new_single_proxy_chain(http_proxy);

        let default_policy = wing::TlsAndDnsPolicy { .. };
        var privacy_policy = wing::TlsAndDnsPolicy { .. };
        privacy_policy.privacy_mode = wing::PrivacyMode.Enabled;

        var doh_policy = wing::TlsAndDnsPolicy { .. };
        doh_policy.secure_dns_policy = wing::SecureDnsPolicy.Disable;

        var cert_policy = wing::TlsAndDnsPolicy { .. };
        cert_policy.disable_cert_network_fetches = true;

        var net_policy = wing::TlsAndDnsPolicy { .. };
        net_policy.target_network_id = 999;

        let key1 = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, default_policy);
        let key2 = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak2, default_policy);
        let key_case = wing::new_pool_key(wing::PoolScheme.Https, "API.SERVICE.COM", 443, direct_chain, nak1, default_policy);
        let key_port = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 8443, direct_chain, nak1, default_policy);
        let key_scheme = wing::new_pool_key(wing::PoolScheme.Http, "api.service.com", 80, direct_chain, nak1, default_policy);
        let key_h2c = wing::new_pool_key(wing::PoolScheme.H2c, "api.service.com", 80, direct_chain, nak1, default_policy);
        let key_proxy_socks = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, socks_chain, nak1, default_policy);
        let key_proxy_http = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, http_chain, nak1, default_policy);
        let key_priv = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, privacy_policy);
        let key_doh = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, doh_policy);
        let key_cert = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, cert_policy);
        let key_net = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, net_policy);

        sub.assert_true(wing::pool_key_equals(key1, key2), "Key1 equals Key2 with identical dimensions");
        sub.assert_true(wing::pool_key_equals(key1, key_case), "Host matches case-insensitively");
        sub.assert_false(wing::pool_key_equals(key1, key_port), "Port mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_scheme), "Scheme mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_h2c), "H2c plaintext scheme isolates socket group (CVE-2026-94441)");
        sub.assert_false(wing::pool_key_equals(key_scheme, key_h2c), "Http and H2c schemes are strictly isolated");
        sub.assert_false(wing::pool_key_equals(key1, key_proxy_socks), "Proxy chain mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key_proxy_socks, key_proxy_http), "Different proxy protocols isolated");
        sub.assert_false(wing::pool_key_equals(key1, key_priv), "Privacy mode mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_doh), "Secure DNS policy mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_cert), "Cert network fetch flag mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_net), "Target network ID mismatch isolates socket group");

        let h1 = wing::pool_key_hash(key1);
        let h2 = wing::pool_key_hash(key2);
        let h_case = wing::pool_key_hash(key_case);
        let h_port = wing::pool_key_hash(key_port);
        let h_scheme = wing::pool_key_hash(key_scheme);
        sub.assert_eq(h1, h2, "Identical PoolKey produces identical hash");
        sub.assert_eq(h1, h_case, "Case-folded host produces identical hash");
        sub.assert_ne(h1, h_port, "Port difference changes hash");
        sub.assert_ne(h1, h_scheme, "Scheme difference changes hash");
    };

    t.run("Preconnect Scheme Normalization") { sub =>
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Ws) == wing::PoolScheme.Http, "WS maps to HTTP");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Wss) == wing::PoolScheme.Https, "WSS maps to HTTPS");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Http) == wing::PoolScheme.Http, "HTTP preserved");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Https) == wing::PoolScheme.Https, "HTTPS preserved");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.H2c) == wing::PoolScheme.H2c, "H2c preserved");

        sub.assert_true(wing::is_cryptographic_scheme(wing::PoolScheme.Https), "HTTPS is cryptographic");
        sub.assert_true(wing::is_cryptographic_scheme(wing::PoolScheme.Wss), "WSS is cryptographic");
        sub.assert_false(wing::is_cryptographic_scheme(wing::PoolScheme.Http), "HTTP is not cryptographic");
        sub.assert_false(wing::is_cryptographic_scheme(wing::PoolScheme.Ws), "WS is not cryptographic");
        sub.assert_false(wing::is_cryptographic_scheme(wing::PoolScheme.H2c), "H2c is not cryptographic");
    };
}

fn test_want_queue_dual_slice(t: core::T&) {
    t.run("FIFO Operations and Reallocation-Free Promotion") { sub =>
        var q = wing::new_want_queue();
        sub.assert_true(wing::is_queue_empty(q), "Initial queue is empty");
        sub.assert_eq(wing::queue_len(q), 0, "Initial queue len is 0");

        let nak = wing::new_network_anonymization_key("https://origin.io");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "origin.io", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var w1 = wing::WantConn { req_id: 101, key: copy(key), .. };
        var w2 = wing::WantConn { req_id: 102, key: copy(key), .. };
        var w3 = wing::WantConn { req_id: 103, key: copy(key), .. };

        sub.assert_true(wing::push_want(q, w1), "Pushed w1");
        sub.assert_true(wing::push_want(q, w2), "Pushed w2");
        sub.assert_true(wing::push_want(q, w3), "Pushed w3");
        sub.assert_eq(wing::queue_len(q), 3, "Queue len == 3");
        sub.assert_false(wing::is_queue_empty(q), "Queue is not empty");

        let p1, ok1 = wing::pop_want(q);
        sub.assert_true(ok1 && p1.req_id == 101, "Popped w1 in FIFO order");
        sub.assert_eq(wing::queue_len(q), 2, "Queue len == 2 after popping w1");

        // Cancel w2 while still in queue
        sub.assert_true(wing::cancel_want(q, 102), "Cancelled w2");
        sub.assert_false(wing::cancel_want(q, 99999), "Non-existent request ID cancellation returns false");

        let p3, ok3 = wing::pop_want(q);
        sub.assert_true(ok3 && p3.req_id == 103, "Popped w3, skipping cancelled w2");
        sub.assert_eq(wing::queue_len(q), 0, "Queue len == 0 after skipping w2 and popping w3");

        let p_none, ok_none = wing::pop_want(q);
        sub.assert_false(ok_none, "Queue exhausted");
        sub.assert_true(wing::is_queue_empty(q), "Queue is empty when exhausted");
    };

    t.run("Tail-to-Head Compaction Under Sustained Load") { sub =>
        var q = wing::new_want_queue();
        let nak = wing::new_network_anonymization_key("https://origin.io");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "origin.io", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Fill tail slice to maximum capacity (32 items)
        for i in 32 {
            var item = wing::WantConn { req_id: (i + 1) as u64, key: copy(key), .. };
            let pushed = wing::push_want(q, item);
            sub.assert_true(pushed, "Pushed item into tail");
        }
        sub.assert_eq(wing::queue_len(q), 32, "Queue filled with 32 items");

        // Pop 16 items: first pop transfers tail into head, then advances head_pos
        for i in 16 {
            let item, ok = wing::pop_want(q);
            sub.assert_true(ok, "Popped item cleanly");
            sub.assert_eq(item.req_id, (i + 1) as u64, "Popped in strictly ascending FIFO order");
        }
        sub.assert_eq(wing::queue_len(q), 16, "16 items remaining in head");

        // Push 16 more items into freshly empty tail slice
        for i in 16 {
            var item = wing::WantConn { req_id: (100 + i) as u64, key: copy(key), .. };
            let pushed = wing::push_want(q, item);
            sub.assert_true(pushed, "Pushed into tail slice while head has items");
        }
        sub.assert_eq(wing::queue_len(q), 32, "Queue has 16 in head + 16 in tail = 32 total");

        // Pop remaining 16 from head
        for i in 16 {
            let item, ok = wing::pop_want(q);
            sub.assert_true(ok, "Popped item from head");
            sub.assert_eq(item.req_id, (17 + i) as u64, "Expected head item id");
        }

        // Next pop triggers compaction of tail into head
        let item100, ok100 = wing::pop_want(q);
        sub.assert_true(ok100, "Popped first item from compacted tail");
        sub.assert_eq(item100.req_id, 100, "Compacted tail item preserved FIFO order");
    };
}

fn test_connection_liveness_and_extensive_checks(t: core::T&) {
    t.run("OkHttp isHealthy and Non-Blocking FIN Detection") { sub =>
        let nak = wing::new_network_anonymization_key("https://example.com");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var conn = wing::PooledConnection {
            conn_id: 1,
            key: copy(key),
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

        // Already closed connection
        sub.assert_false(wing::is_connection_healthy(conn, 3600000000, false), "Closed connection is unhealthy");

        // Remote RST received
        var conn_rst = wing::PooledConnection {
            conn_id: 2,
            key: copy(key),
            remote_rst: true,
            ..
        };
        sub.assert_false(wing::is_connection_healthy(conn_rst, 2000000000, false), "Connection with remote RST is unhealthy");

        // Marked no_new_exchanges (e.g. Connection: close header received)
        var conn_no_new = wing::PooledConnection {
            conn_id: 3,
            key: copy(key),
            no_new_exchanges: true,
            ..
        };
        sub.assert_false(wing::is_connection_healthy(conn_no_new, 2000000000, false), "Connection with no_new_exchanges is unhealthy");

        // Active multiplexed streams on HTTP/2 remain healthy while active
        var conn_h2 = wing::PooledConnection {
            conn_id: 4,
            key: copy(key),
            protocol: wing::NegotiatedProtocol.Http2,
            active_allocations: 5,
            ..
        };
        sub.assert_true(wing::is_connection_healthy(conn_h2, 5000000000, false), "Active HTTP/2 multiplexed stream is healthy");
    };
}

fn test_http2_ip_coalescing_and_san_matching(t: core::T&) {
    t.run("Chromium H2 IP Coalescing with Wildcard SAN & Security Boundaries") { sub =>
        let nak = wing::new_network_anonymization_key("https://example.com");
        let nak_other = wing::new_network_anonymization_key("https://other-site.com");
        let key_a = wing::new_pool_key(wing::PoolScheme.Https, "alpha.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_b = wing::new_pool_key(wing::PoolScheme.Https, "beta.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_deep = wing::new_pool_key(wing::PoolScheme.Https, "sub.beta.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_apex = wing::new_pool_key(wing::PoolScheme.Https, "example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_unrelated = wing::new_pool_key(wing::PoolScheme.Https, "other.org", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_nak_mismatch = wing::new_pool_key(wing::PoolScheme.Https, "beta.example.com", 443, wing::new_direct_proxy_chain(), nak_other, wing::TlsAndDnsPolicy { .. });
        let key_http_plaintext = wing::new_pool_key(wing::PoolScheme.Http, "beta.example.com", 80, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

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

        // 1. Target beta.example.com resolves to same IP 93.184.216.34 and matches *.example.com SAN
        let can_coalesce_b, is_neg_b = wing::can_coalesce_h2_connection(conn, key_b, "93.184.216.34");
        sub.assert_true(can_coalesce_b, "H2 connection coalesced for beta.example.com under *.example.com");
        sub.assert_false(is_neg_b, "Not a negative IP pool result");

        // 2. Wildcard boundary: multi-level subdomain (*.example.com must NOT match sub.beta.example.com)
        let can_coalesce_deep, is_neg_deep = wing::can_coalesce_h2_connection(conn, key_deep, "93.184.216.34");
        sub.assert_false(can_coalesce_deep, "Wildcard *.example.com does NOT cover multi-level sub.beta.example.com");
        sub.assert_true(is_neg_deep, "Negative IP pool result recorded");

        // 3. Wildcard boundary: apex domain (*.example.com must NOT match example.com)
        let can_coalesce_apex, is_neg_apex = wing::can_coalesce_h2_connection(conn, key_apex, "93.184.216.34");
        sub.assert_false(can_coalesce_apex, "Wildcard *.example.com does NOT cover apex domain example.com");
        sub.assert_true(is_neg_apex, "Negative IP pool result recorded");

        // 4. Target other.org resolves to same IP but SAN does NOT match
        let can_coalesce_other, is_neg_other = wing::can_coalesce_h2_connection(conn, key_unrelated, "93.184.216.34");
        sub.assert_false(can_coalesce_other, "H2 connection rejected for unrelated domain");
        sub.assert_true(is_neg_other, "Recorded negative IP pool result for metric tracking");

        // 5. Partition isolation: NAK mismatch blocks coalescing even if IP and SAN match
        let can_coalesce_nak, is_neg_nak = wing::can_coalesce_h2_connection(conn, key_nak_mismatch, "93.184.216.34");
        sub.assert_false(can_coalesce_nak, "NAK cross-site partition mismatch blocks coalescing");

        // 6. Security invariant CVE-2026-94441: Scheme mismatch blocks coalescing
        let can_coalesce_plain, is_neg_plain = wing::can_coalesce_h2_connection(conn, key_http_plaintext, "93.184.216.34");
        sub.assert_false(can_coalesce_plain, "Plaintext HTTP connection cannot coalesce with HTTPS (CVE-2026-94441)");

        // 7. Invalid certificate: cert_valid = false blocks coalescing
        var conn_bad_cert = copy(conn);
        conn_bad_cert.cert_valid = false;
        let can_coalesce_cert, is_neg_cert = wing::can_coalesce_h2_connection(conn_bad_cert, key_b, "93.184.216.34");
        sub.assert_false(can_coalesce_cert, "Invalid certificate blocks coalescing");
        sub.assert_true(is_neg_cert, "Recorded negative result on invalid certificate");

        // 8. IP mismatch: 93.184.216.34 vs 93.184.216.99
        let can_coalesce_ip, is_neg_ip = wing::can_coalesce_h2_connection(conn, key_b, "93.184.216.99");
        sub.assert_false(can_coalesce_ip, "Different IP address blocks coalescing");
    };
}

fn test_stream_pool_quotas_and_eviction(t: core::T&) {
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

        // Multiple releases do not corrupt active allocations count below 0
        wing::release_connection(pool, c2, 5000000000);
        sub.assert_eq(pool.conns[1].active_allocations, 0, "Active allocations clamped to 0");
    };

    t.run("Active Connections Immune to Soft-Cap Eviction") { sub =>
        var pool = wing::new_stream_pool(6, 32, 2);
        let nak = wing::new_network_anonymization_key("https://busy.net");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "busy.net", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Register 2 connections and keep both active (active_allocations == 1)
        let c1 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "2.2.2.2", 1, 1000000);
        let c2 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "2.2.2.2", 1, 2000000);

        // Neither is released, so both have active_allocations = 1.
        // Registering a 3rd connection exceeds soft-cap (2), but neither can be evicted because both are active!
        let c3 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "2.2.2.2", 1, 3000000);

        sub.assert_false(pool.conns[0].closed, "Active connection c1 not evicted");
        sub.assert_false(pool.conns[1].closed, "Active connection c2 not evicted");
        sub.assert_eq(c3, 3, "New connection c3 accepted under soft-cap pressure");
    };
}

fn test_cve_2026_56866_connect_rejection_pool_safety(t: core::T&) {
    t.run("CVE-2026-56866: Rejected CONNECT Sockets Must Never Be Returned to Pool") { sub =>
        let nak = wing::new_network_anonymization_key("https://proxy-target.com");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "proxy-target.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Simulate a socket where CONNECT tunnel was rejected (e.g. 407 Proxy Auth or 502 Bad Gateway)
        var failed_tunnel_conn = wing::PooledConnection {
            conn_id: 101,
            key: copy(key),
            protocol: wing::NegotiatedProtocol.Http11,
            no_new_exchanges: true, // Marked immediately on CONNECT rejection
            closed: true,           // Marked closed to prevent reuse
            ..
        };

        // Liveness check must immediately report unhealthy
        let healthy = wing::is_connection_healthy(failed_tunnel_conn, 2000000000, false);
        sub.assert_false(healthy, "Rejected CONNECT connection is strictly unhealthy");

        // Attempting to acquire from a pool containing closed/no_new_exchanges connection must fail
        var pool = wing::new_stream_pool(6, 32, 10);
        pool.conns.push(failed_tunnel_conn);

        let acq_id, ok_acq = wing::acquire_pooled_connection(pool, key, "", 2500000000);
        sub.assert_false(ok_acq, "Acquire never returns a rejected CONNECT socket (prevents response desync)");
    };
}

fn main() {
    var runner = core::new_runner("net/pool Connection Pool & Isolation Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. PoolKey Dimensions & Isolation", test_pool_key_dimensions_and_isolation);
    core::run_case(runner, "2. WantQueue Dual-Slice FIFO", test_want_queue_dual_slice);
    core::run_case(runner, "3. Connection Liveness & Extensive Checks", test_connection_liveness_and_extensive_checks);
    core::run_case(runner, "4. HTTP/2 IP Coalescing & SAN Matching", test_http2_ip_coalescing_and_san_matching);
    core::run_case(runner, "5. StreamPool Quotas & Eviction", test_stream_pool_quotas_and_eviction);
    core::run_case(runner, "6. CVE-2026-56866 CONNECT Rejection Pool Safety", test_cve_2026_56866_connect_rejection_pool_safety);
    let ok = core::finish(runner);
    assert(ok);
}
