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

// 8. F001: prepare_proxy_request_at must fail closed on wire buffer overflow, bad URI, or Content-Length mismatch
fn test_f001_wire_serialization_and_cl_mismatch() {
    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    assert(wing::add_upstream_target(proxy.cluster, "backend.internal", 8080, 1));

    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "public.example.com"));

    //Tiny wire buffer that overflows during encode_h1_request
    var tiny_wire: u8[..16] = [];
    let idx_over, ok_over = wing::prepare_proxy_request_at(
        proxy, "GET", "/api/v1/resource", in_headers, "192.0.2.10", "https", "", tiny_wire, 1000000000,
    );
    assert(!ok_over && idx_over == wing::PROXY_TARGET_NONE);
    assert(proxy.cluster.targets[0].active_conns == 0);
    assert(proxy.total_forwarded == 0 && proxy.total_dropped == 1);

    // Content-Length header in in_headers contradicting actual body length (RFC 9112 §6.2)
    var bad_cl_headers = wing::HeaderMap { .. };
    assert(wing::append_header(bad_cl_headers, "Host", "public.example.com"));
    assert(wing::append_header(bad_cl_headers, "Content-Length", "999"));
    var full_wire: u8[>..] = [];
    let idx_cl, ok_cl = wing::prepare_proxy_request_at(
        proxy, "POST", "/submit", bad_cl_headers, "192.0.2.10", "https", "hello", full_wire, 1000000000,
    );
    assert(!ok_cl && idx_cl == wing::PROXY_TARGET_NONE);
    assert(proxy.cluster.targets[0].active_conns == 0);
    print("F001_WIRE_AND_CL_GUARD: ok\n");
}

// 9. F002: Multi-header Via preservation (RFC 9110 §7.6.3) and XFF overflow fail-closed
fn test_f002_multi_via_and_xff_overflow() {
    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "api.example.com"));
    assert(wing::append_header(in_headers, "Via", "1.1 edge-proxy"));
    assert(wing::append_header(in_headers, "Via", "1.1 mesh-proxy"));

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.via_pseudonym.clear();
    cfg.via_pseudonym.append("wing-gw");

    assert(wing::filter_and_forward_headers(in_headers, out_headers, "192.0.2.1", "https", "backend:8080", cfg));
    let v = wing::get_header(out_headers, "Via");
    assert(v == "1.1 edge-proxy, 1.1 mesh-proxy, 1.1 wing-gw");

    // Multi-header XFF exceeding 1024 bytes when trust_incoming_xff = true must fail closed (not panic or drop hops)
    var xff_headers = wing::HeaderMap { .. };
    assert(wing::append_header(xff_headers, "Host", "api.example.com"));
    assert(wing::append_header(xff_headers, "X-Forwarded-For", "10.0.0.1"));
    var big_xff: u8[..600] = [];
    for _ in 550 { big_xff.push('1'); }
    assert(wing::append_header(xff_headers, "X-Forwarded-For", big_xff[..]));
    assert(wing::append_header(xff_headers, "X-Forwarded-For", big_xff[..]));
    cfg.trust_incoming_xff = true;
    var out_xff = wing::HeaderMap { .. };
    let ok_xff = wing::filter_and_forward_headers(xff_headers, out_xff, "192.0.2.1", "https", "backend:8080", cfg);
    assert(!ok_xff);
    print("F002_MULTI_VIA_AND_XFF_GUARD: ok\n");
}

// 10. F003: Reject Connection: content-length / host and format bare IPv6 / pre-ported upstream Host cleanly
fn test_f003_connection_smuggle_and_ipv6_host() {
    var smuggle_cl = wing::HeaderMap { .. };
    assert(wing::append_header(smuggle_cl, "Host", "api.example.com"));
    assert(wing::append_header(smuggle_cl, "Connection", "keep-alive, content-length"));
    assert(wing::append_header(smuggle_cl, "Content-Length", "5"));
    var out_smuggle = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    assert(!wing::filter_and_forward_headers(smuggle_cl, out_smuggle, "192.0.2.1", "http", "backend:8080", cfg));

    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    assert(wing::add_upstream_target(proxy.cluster, "2001:db8::1", 8080, 1));
    var in_hdr = wing::HeaderMap { .. };
    assert(wing::append_header(in_hdr, "Host", "edge.example.com"));
    var wire: u8[>..] = [];
    let _, ok_v6 = wing::prepare_proxy_request_at(proxy, "GET", "/v6", in_hdr, "192.0.2.1", "http", "", wire, 1000000000);
    assert(ok_v6);
    assert(core::contains(wire[..], "Host: [2001:db8::1]:8080\r\n"));
    print("F003_CONN_SMUGGLE_AND_IPV6_HOST: ok\n");
}

// 11. F004: exchange_prepared_wire_on_conn caps 1xx responses (RFC 9110 §15.2) and drains conn.rx_buf
fn test_f004_exchange_interim_and_rx_buf() {
    var conn_flood = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    for _ in 7 {
        conn_flood.rx_buf.append("HTTP/1.1 100 Continue\r\n\r\n");
    }
    conn_flood.rx_buf.append("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    var resp_flood = wing::Response { .. };
    let ok_flood, _ = wing::exchange_prepared_wire_on_conn(conn_flood, "GET", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", resp_flood, 100);
    assert(!ok_flood);

    var conn_clean = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    conn_clean.rx_buf.append("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPONG");
    var resp_clean = wing::Response { .. };
    resp_clean.body.append("STALE_BODY");
    let ok_clean, ka = wing::exchange_prepared_wire_on_conn(conn_clean, "GET", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", resp_clean, 100);
    assert(ok_clean && ka);
    assert(resp_clean.body[..] == "PONG");
    assert(conn_clean.rx_buf.len == 0);
    print("F004_EXCHANGE_1XX_AND_RX_BUF: ok\n");
}

// 12. F005 & F006: Health check Probing/Up sync + status parser & GCRA slot reuse / penalty
fn test_f005_and_f006_health_and_gcra() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
    assert(wing::add_upstream_target(cluster, "10.0.0.1", 8080, 1));
    var checker = wing::new_cluster_health_checker(wing::new_health_check_config(1000, 500, 2, 2));
    assert(!wing::register_target_for_probing(checker, -1));
    assert(wing::register_target_for_probing(checker, 0));

    let _, ok_4digit = wing::parse_probe_status_code("HTTP/1.1 2000 OK\r\n\r\n");
    assert(!ok_4digit);

    wing::on_probe_failure(checker, cluster, 0);
    wing::on_probe_failure(checker, cluster, 0);
    assert(cluster.circuit_open);
    // 1st probe success enters Probing and must reopen circuit for trial traffic
    wing::on_probe_success(checker, cluster, 0, 200);
    assert(!cluster.circuit_open);
    // Passive recovery to Up must sync back to slot so next probe success keeps target Up
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].is_healthy);
    wing::on_probe_success(checker, cluster, 0, 200);
    assert(cluster.targets[0].is_healthy);

    var limiter = wing::new_gateway_rate_limiter(10, 1);
    let _ = wing::check_gateway_rate_limit(limiter, "10.0.0.1", 1, 1000000000);
    assert(wing::evict_idle_gateway_clients(limiter, 100, 5000000000) == 1);
    let _ = wing::check_gateway_rate_limit(limiter, "10.0.0.2", 1, 5000000000);
    assert(limiter.entries.len == 1);
    wing::penalize_gateway_client(limiter, "10.0.0.99", 5000000000, 5000000000);
    assert(!wing::check_gateway_rate_limit(limiter, "10.0.0.99", 1, 5100000000).allowed);
    wing::reset_gateway_rate_limiter(limiter);
    assert(limiter.entries.len == 0);
    print("F005_F006_HEALTH_AND_GCRA: ok\n");
}

// 13. SRVPROXY-01 & SRVPROXY-02: 103 Early Hints serializer, no-early-hints: 1 suppression, CASPer cookie & proxy 103 capture
fn test_srvproxy_01_02_early_hints_and_casper() {
    let hints, ok_hints = wing::parse_early_hints(
        103, "</style.css>; rel=preload; as=style; crossorigin, </app.js>; rel=preload; as=script",
    );
    assert(ok_hints && hints.links.len == 2);

    var out_103: u8[..512] = [];
    assert(!wing::format_early_hints_http1(hints, "1", out_103));
    assert(out_103.len == 0);
    assert(wing::format_early_hints_http1(hints, "", out_103));
    assert(core::contains(out_103[..], "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style; crossorigin\r\n"));

    var cset = wing::CasperSet { .. };
    assert(!wing::casper_lookup_and_insert(cset, "/style.css", "v1"));
    assert(wing::casper_lookup_and_insert(cset, "/style.css", "v1"));
    assert(!wing::casper_lookup_and_insert(cset, "/app.js", "v2"));

    var cookie_buf: u8[..128] = [];
    assert(wing::encode_casper_cookie(cset, cookie_buf));
    assert(cookie_buf.len > 0);

    var decoded_set = wing::CasperSet { .. };
    assert(wing::decode_casper_cookie(cookie_buf[..], decoded_set));
    assert(decoded_set.keys.len == cset.keys.len);
    assert(wing::casper_lookup_and_insert(decoded_set, "/style.css", "v1"));

    var conn_103 = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    conn_103.rx_buf.append("HTTP/1.1 103 Early Hints\r\nLink: </hero.webp>; rel=preload; as=image\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    var up_resp = wing::UpstreamResponse { .. };
    var early_hints = wing::EarlyHintsResponse { .. };
    var has_eh = false;
    let ok_ex, ka_ex = wing::exchange_prepared_wire_on_conn_with_hints(
        conn_103, "GET", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", up_resp.resp, early_hints, has_eh, 100,
    );
    up_resp.early_hints = early_hints;
    up_resp.has_early_hints = has_eh;
    assert(ok_ex && ka_ex);
    assert(up_resp.has_early_hints);
    assert(up_resp.early_hints.links.len == 1);
    assert(up_resp.early_hints.links[0].uri[..] == "/hero.webp");
    assert(up_resp.resp.status_code == 200);
    print("SRVPROXY_01_02_EARLY_HINTS_CASPER: ok\n");
}

// 14. SRVPROXY-03 & SRVPROXY-04: Ketama consistent hashing ring & cache stampede AgeTimeout / GiveUp
fn test_srvproxy_03_04_ketama_and_cache_lock() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.ConsistentHash, 3);
    assert(wing::add_upstream_target(cluster, "10.0.0.1", 8080, 1));
    assert(wing::add_upstream_target(cluster, "10.0.0.2", 8080, 2));
    assert(wing::add_upstream_target(cluster, "10.0.0.3", 8080, 1));

    var ring = wing::KetamaRing { .. };
    wing::build_ketama_ring(cluster, ring);
    assert(ring.points.len > 0);

    let idx1, ok1 = wing::select_consistent_backend(cluster, ring, "/users/42", 1000);
    let idx2, ok2 = wing::select_consistent_backend(cluster, ring, "/users/42", 1000);
    assert(ok1 && ok2 && idx1 == idx2);

    cluster.targets[idx1].ejected_until_ms = 5000;
    let idx_failover, ok_fo = wing::select_consistent_backend(cluster, ring, "/users/42", 2000);
    assert(ok_fo && idx_failover != idx1);

    let idx_recovered, ok_rec = wing::select_consistent_backend(cluster, ring, "/users/42", 6000);
    assert(ok_rec && idx_recovered == idx1);

    var writers = wing::CacheWriters { .. };
    let is_ldr, fl_idx = wing::start_writer_or_join(writers, "/asset");
    assert(is_ldr && fl_idx >= 0);
    wing::abort_writer(writers, fl_idx);
    assert(wing::acquire_at(writers, 0xABCD, 1000, 5000));
    assert(!wing::acquire_at(writers, 0xABCD, 3000, 5000));
    // Preempt expired lock after age_timeout_ms (1000 + 5000 <= 6000)
    assert(wing::acquire_at(writers, 0xABCD, 6000, 5000));
    wing::release_with_status(writers, 0xABCD, wing::CacheLockStatus.GiveUp);
    assert(wing::acquire(writers, 0xABCD));
    wing::release_with_status(writers, 0xABCD, wing::CacheLockStatus.Done);
    print("SRVPROXY_03_04_KETAMA_CACHE_LOCK: ok\n");
}

// 15. SRVPROXY-05..08: X-Accel-* filtering, Location rewrite, empty POST CL:0, 304 CL, PROXYv2 CRC32C & FastHTTP Host/CRLF
fn test_srvproxy_05_06_07_08_headers_crc32c_and_memo() {
    var up_hdrs = wing::HeaderMap { .. };
    assert(wing::append_header(up_hdrs, "X-Accel-Buffering", "no"));
    assert(wing::append_header(up_hdrs, "X-Accel-Expires", "120"));
    assert(wing::append_header(up_hdrs, "X-Accel-Limit-Rate", "65536"));
    assert(wing::append_header(up_hdrs, "X-Accel-Redirect", "/internal/files/a.bin"));
    assert(wing::append_header(up_hdrs, "Location", "http://10.0.0.1:8080/app/login"));
    assert(wing::append_header(up_hdrs, "Content-Type", "text/plain"));

    var client_hdrs = wing::HeaderMap { .. };
    var loc_buf: u8[..512] = [];
    var accel = wing::UpstreamAccelControl { .. };
    assert(wing::process_and_filter_upstream_response_headers(
        up_hdrs, "http://10.0.0.1:8080/app", "https://example.com/public", client_hdrs, loc_buf, accel,
    ));
    assert(accel.disable_buffering && accel.has_accel_expires && accel.accel_expires_sec == 120);
    assert(accel.limit_rate_bps == 65536 && accel.accel_redirect[..] == "/internal/files/a.bin");
    assert(wing::get_header(client_hdrs, "X-Accel-Buffering") == "");
    assert(wing::get_header(client_hdrs, "Location") == "https://example.com/public/login");

    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    assert(wing::add_upstream_target(proxy.cluster, "backend.internal", 8080, 1));
    var post_hdr = wing::HeaderMap { .. };
    assert(wing::append_header(post_hdr, "Host", "edge.example.com"));
    var post_wire: u8[>..] = [];
    let _, ok_post = wing::prepare_proxy_request_at(proxy, "POST", "/empty", post_hdr, "192.0.2.1", "http", "", post_wire, 1000);
    assert(ok_post && core::contains(post_wire[..], "Content-Length: 0\r\n"));

    var res_304 = wing::Response { status_code: 304, .. };
    res_304.set_header("Content-Length", "4096");
    res_304.set_header("ETag", "\"v1\"");
    var wire_304: u8[..512] = [];
    wing::serialize_http1_response(res_304, "wing", wire_304);
    assert(core::contains(wire_304[..], "Content-Length: 4096\r\n"));

    var pp2_hdr = wing::ProxyHeader {
        version:  wing::ProxyProtocolVersion.V2,
        command:  wing::ProxyCommand.Proxy,
        family:   wing::ProxyAddressFamily.Inet4,
        src_ipv4: [192, 0, 2, 10],
        dst_ipv4: [198, 51, 100, 1],
        src_port: 54321,
        dst_port: 443,
        ..
    };
    var pp2_wire: u8[..128] = [];
    assert(wing::format_proxy_v2(pp2_hdr, pp2_wire));
    assert(wing::append_proxy_v2_crc32c(pp2_wire));
    let parsed_pp2, consumed_pp2, ok_pp2 = wing::parse_proxy_v2(pp2_wire[..]);
    assert(ok_pp2 && consumed_pp2 == pp2_wire.len && parsed_pp2.src_port == 54321);
    pp2_wire[pp2_wire.len - 1] = pp2_wire[pp2_wire.len - 1] ^ 0xFF;
    let _, _, ok_bad = wing::parse_proxy_v2(pp2_wire[..]);
    assert(!ok_bad);

    var last_host: u8[..128] = [];
    var has_host = false;
    assert(wing::validate_span_host_header_memoized(post_hdr, 0, last_host, has_host));
    assert(has_host && last_host[..] == "edge.example.com");
    assert(wing::validate_span_host_header_memoized(post_hdr, 0, last_host, has_host));

    var scan_cur: i64 = 0;
    let partial_req = "GET / HTTP/1.1\r\nHost: edge.example.com\r\n";
    assert(wing::scan_crlfcrlf_incremental(partial_req, scan_cur) == -1 && scan_cur == partial_req.len);
    let full_req = "GET / HTTP/1.1\r\nHost: edge.example.com\r\n\r\n";
    assert(wing::scan_crlfcrlf_incremental(full_req, scan_cur) == 38 && scan_cur == 0);

    var date_buf: u8[..64] = [];
    wing::format_local_http_date(date_buf, 1700000000);
    var srv = wing::new_http_server_with_quota("127.0.0.1", 8080, wing::new_gcra_quota(100, core::secs(1), 10));
    wing::refresh_http_server_date(srv, 1700000000);
    wing::add_put_route(srv, "/put", 1);
    wing::add_delete_route(srv, "/del", 2);
    var stg_req = wing::new_request("PUT", "/put");
    var stg_match = wing::RouteMatchResult.NotFound;
    let _ = wing::stage_server_route_match(srv.pipeline.router, stg_req, srv.pipeline.ext_pool.slots[0], stg_match, res_304);
    var te_buf: u8[..64] = [];
    let _ = wing::collect_transfer_encoding_headers(stg_req.headers, te_buf);
    assert(wing::serve_page_ring(srv, -1, 0) == 0);
    assert(!wing::send_static_mmap_file(-1, "/nonexistent", "text/plain"));
    print("SRVPROXY_05_06_07_08_ALL: ok\n");
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
    test_f001_wire_serialization_and_cl_mismatch();
    // CHECK: F001_WIRE_AND_CL_GUARD: ok
    test_f002_multi_via_and_xff_overflow();
    // CHECK: F002_MULTI_VIA_AND_XFF_GUARD: ok
    test_f003_connection_smuggle_and_ipv6_host();
    // CHECK: F003_CONN_SMUGGLE_AND_IPV6_HOST: ok
    test_f004_exchange_interim_and_rx_buf();
    // CHECK: F004_EXCHANGE_1XX_AND_RX_BUF: ok
    test_f005_and_f006_health_and_gcra();
    // CHECK: F005_F006_HEALTH_AND_GCRA: ok
    test_srvproxy_01_02_early_hints_and_casper();
    // CHECK: SRVPROXY_01_02_EARLY_HINTS_CASPER: ok
    test_srvproxy_03_04_ketama_and_cache_lock();
    // CHECK: SRVPROXY_03_04_KETAMA_CACHE_LOCK: ok
    test_srvproxy_05_06_07_08_headers_crc32c_and_memo();
    // CHECK: SRVPROXY_05_06_07_08_ALL: ok
    print("ALL_PROXY_REGRESSIONS_PASS\n");
    // CHECK: ALL_PROXY_REGRESSIONS_PASS
}
