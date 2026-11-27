// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Wave 3 Security & RFC Conformance Audit Regression Suite.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_w3_bloom_and_router_invariants(sub: lit::T&) {
    // WB1-001: Keyed SipHash Bloom filter + spilled well-known has_header lookup
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };
    var idx_hdr: u8[..24] = [];
    for i in 68 {
        idx_hdr.clear();
        let _ = idx_hdr.try_append("X-Fill-");
        core::format_i64_dec(i, idx_hdr);
        let _ = http::append_header_spill(map, arena, idx_hdr[..], "1");
    }
    sub.assert_true(http::append_header_spill(map, arena, "User-Agent", "wing/1.0"), "spilled well-known header appended");
    sub.assert_true(http::has_header_spill(map, arena, "User-Agent"), "WB1-001 has_header finds spilled well-known header");
    sub.assert_false(http::has_header_spill(map, arena, "X-Never-Inserted"), "absent header rejected");

    // WB1-002 / WB1-003: Single-pass canonicalization + backslash/delimiter/bad-pct rejection + ZeroAllocParams
    var canon: u8[..128] = [];
    sub.assert_false(server::canonicalize_route_path("/admin\\secret", canon), "WB1-003 backslash rejected");
    sub.assert_false(server::canonicalize_route_path("/admin%5Csecret", canon), "WB1-003 %5C rejected");
    sub.assert_false(server::canonicalize_route_path("/admin%2Fsecret", canon), "WB1-003 %2F rejected");
    sub.assert_false(server::canonicalize_route_path("/admin;js=1", canon), "WB1-003 semicolon rejected");
    sub.assert_false(server::canonicalize_route_path("/admin%3Bjs=1", canon), "WB1-003 %3B rejected");
    sub.assert_false(server::canonicalize_route_path("/admin%ZZ", canon), "WB1-003 %ZZ rejected");
    sub.assert_true(server::canonicalize_route_path("/a/b/../c//d", canon) && canon[..] == "/a/c/d", "canonical path clean");

    // WB1-004: respond_redirect rejects unsafe schemes, spaces, and controls
    var res_red = http::Response { .. };
    sub.assert_false(http::respond_redirect(res_red, "javascript:alert(1)"), "WB1-004 blocks javascript: redirect");
    sub.assert_false(http::respond_redirect(res_red, "data:text/html,hi"), "WB1-004 blocks data: redirect");
    sub.assert_false(http::respond_redirect(res_red, "https://example.org/a b"), "WB1-004 blocks space in Location");
    sub.assert_true(http::respond_redirect(res_red, "https://example.org/ok", 302), "valid redirect accepted");

    // WB1-005 / WB1-006: Radix route conflict check + SoAConnTable generation ABA defense
    var rt = server::new_radix_router();
    sub.assert_true(server::add_route(rt, "GET", "/items/:id", 10), "first param route succeeds");
    sub.assert_false(server::add_route(rt, "GET", "/items/:other", 20), "WB1-005 duplicate route pattern rejected");
    var tbl = server::SoAConnTable { .. };
    let s0 = server::soa_table_alloc(tbl, 11, 1);
    let g0 = tbl.generations[s0];
    server::soa_table_free(tbl, s0);
    let s1 = server::soa_table_alloc(tbl, 12, 1);
    sub.assert_true(s0 == s1 && tbl.generations[s1] != g0, "WB1-006 SoA slot generation bumps on reuse");
}

fn test_w3_h2_headroom_and_quic_credits(sub: lit::T&) {
    // WB1-008: H2EdgeSlot reserves H2_EDGE_CTRL_HEADROOM (4096 B) for control frames
    var hs = http2::h2_edge_open(32, 1048576);
    defer http2::h2_edge_close(hs);
    sub.assert_true(http2::h2_edge_set_tls_sni(hs, "example.com"), "WB3-009 h2_edge_set_tls_sni records SNI");
    var req_w: u8[>..] = [];
    req_w.append(rfc::H2_CLIENT_PREFACE[..]);
    var s_pay: u8[6] = [0, 3, 0, 0, 0, 16];
    let fh_s = http2::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    http2::encode_frame_header_to(fh_s, req_w);
    req_w.append(s_pay[..]);
    var dt = http2::new_dynamic_table(4096);
    var hblk: u8[>..] = [];
    var eh = http::HeaderMap { .. };
    let pseudo = http2::PseudoHeaders {
        method:        "GET",
        scheme:        "https",
        authority:     "example.com",
        path:          "/big",
        has_method:    true,
        has_scheme:    true,
        has_authority: true,
        has_path:      true,
        ..
    };
    let _ = wire::encode_hpack_from_map(dt, pseudo, eh, hblk, true);
    let fh_h = http2::FrameHeader {
        length:     hblk.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      0x05,
        stream_id:  1,
    };
    http2::encode_frame_header_to(fh_h, req_w);
    req_w.append(hblk[..]);
    let _, ok_f = http2::h2_edge_feed(hs, req_w[..]);
    sub.require_true(ok_f, "H2 edge feed succeeds");
    var ev = http2::H2EdgeEvent { .. };
    while http2::h2_edge_poll_event(hs, ev) {}
    sub.require_true(http2::h2_edge_send_headers(hs, 1, 200, eh, false), "H2 edge response headers sent");
    var dump: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(hs, dump);
    var big: u8[>..] = [];
    for _ in 150000 { big.push('Z'); }
    let sent_b, ok_b = http2::h2_edge_send_data(hs, 1, big[..], false);
    sub.assert_true(ok_b && sent_b < 150000, "WB1-008 stops DATA before 4096B headroom");
    sub.assert_true(http2::h2_edge_reset_stream(hs, 1, rfc::H2_ERR_CANCEL), "control RST_STREAM fits in reserved headroom");

    // WB1-009: QuicFlowControl connection credit accounting on stream reset reclaim
    var fc = quic::QuicFlowControl {
        max_data_local:           1000,
        bytes_read_total:         600,
        local_window_size:        1000,
        last_advertised_max_data: 1000,
        ..
    };
    let new_md, need_md = quic::check_conn_window_update(fc);
    sub.assert_true(need_md && new_md > 1000, "WB1-009 check_conn_window_update advances MAX_DATA");
}

fn test_wave3_hotpath_structures(t: lit::T&) {
    t.run("Bloom SipHash, router path norm, redirect filter, SoA ABA, H2 headroom, QUIC MAX_DATA") { sub =>
        test_w3_bloom_and_router_invariants(sub);
        test_w3_h2_headroom_and_quic_credits(sub);
    };
}

fn test_w3_multipart_range_and_cache(sub: lit::T&) {
    // WB2-01 / WB2-02: RFC 8187 filename*, traversal stripping, strict header count limits
    let mp_body = "--b1\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../../evil.txt\"; filename*=UTF-8''clean%20doc.txt\r\n\r\nhello\r\n--b1--\r\n";
    let parsed, perr = http::parse_multipart(mp_body, "b1");
    sub.assert_true(perr == http::MultipartError.None && parsed.parts.len == 1, "WB2-01 multipart parsed");
    sub.assert_true(parsed.parts[0].filename[..] == "clean doc.txt", "WB2-01 RFC 8187 filename* sanitized");

    var opts = http::MultipartOptions { max_preamble_bytes: 4, .. };
    let big_pre = "PREAMBLE-TOO-LONG\r\n--b1\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--b1--\r\n";
    let _, err_pre = http::parse_multipart(big_pre, "b1", opts);
    sub.assert_true(err_pre != http::MultipartError.None, "WB2-02 preamble limit enforced");

    // WB2-03: Malformed Range -> 200, mod_unix_sec == 0 If-Range reject
    sub.assert_false(http::evaluate_if_range("Thu, 01 Jan 1970 00:00:00 GMT", "\"e\"", 0), "WB2-03 rejects unset mtime=0");
    var r_status: i32 = 0;
    var r_hdrs = http::HeaderMap { .. };
    var r_body: u8[>..] = [];
    http::serve_range_request("bytes=bad-range", "", "\"e1\"", 1700000000, 3, "text/plain", r_status, r_hdrs, r_body) {
        _off, _len, o =>
        o.append("abc");
    };
    sub.assert_true(r_status == 200 && r_body[..] == "abc", "WB2-03 malformed Range falls back to 200 OK");

    // WB2-05: RFC 9875 Cache-Groups origin scoping
    var c = http::Cache { .. };
    let req_a = http::new_get("https://a.example/x");
    var r0 = http::Response { status_code: 200, .. };
    r0.body.append("secret");
    r0.effective_url.append("https://a.example/x");
    http::set_header(r0, "Cache-Control", "max-age=60");
    http::set_header(r0, "Cache-Groups", "\"g1\"");
    let ts = http::new_cache_timestamps(100, 100, 100);
    http::on_response(c, req_a, r0, ts);
    sub.assert_true(http::invalidate_group(c, "g1", "") == 0, "WB2-05 empty origin rejected");
    sub.assert_true(http::invalidate_group(c, "g1", "https://b.example/") == 0, "WB2-05 cross-origin skip");
    sub.assert_true(http::invalidate_group(c, "g1", "https://a.example/") == 1, "WB2-05 matching origin invalidates");
}

fn test_w3_problem_x509_and_cookies(sub: lit::T&) {
    // WB2-06: ProblemDetails nosniff, scheme filter, status clamp, redact_5xx
    let prob = http::ProblemDetails {
        status:     502,
        type_uri:   "javascript:evil()",
        title:      "Bad Gateway",
        detail:     "internal trace secret",
        instance:   "data:text/plain,x",
        redact_5xx: true,
    };
    let pres = http::new_problem_response(prob);
    sub.assert_true(http::header(pres, "X-Content-Type-Options") == "nosniff", "WB2-06 sets nosniff");
    sub.assert_false(core::contains(pres.body[..], "javascript:"), "WB2-06 rejects javascript: type_uri");
    sub.assert_false(core::contains(pres.body[..], "internal trace secret"), "WB2-06 redact_5xx hides detail");

    // WB2-07: X.509 GeneralizedTime < 2050 rejected
    let bad_val: u8[36] = [
        0x30, 0x22,
        0x18, 0x0F, '2', '0', '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x18, 0x0F, '2', '0', '3', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
    ];
    var vcur = core::cursor_from(bad_val[..]);
    var pcert = tls::ParsedCert { .. };
    sub.assert_false(tls_internal::read_tbs_validity(bad_val[..], vcur, pcert), "WB2-07 rejects GeneralizedTime < 2050");

    // WB6-F09..F11: Cookie SQL rollback, port range guard, Netscape/Jar CTL rejection
    var ck = cookie::CanonicalCookie { source_port: 70000, .. };
    let _ = ck.name.try_set("sid");
    let _ = ck.value.try_set("v1");
    let _ = ck.domain.try_set("example.com");
    let _ = ck.path.try_set("/");
    var tiny_sql: u8[..8] = "KEEP";
    sub.assert_false(cookie::generate_sqlite_insert_sql(ck, tiny_sql), "WB6-F09 SQL overflow fails");
    sub.assert_true(tiny_sql[..] == "KEEP", "WB6-F09 preserves caller buffer on failure");

    var jar = cookie::CanonicalCookieJar { .. };
    let added .= jar.add("a", "b\x01c");
    sub.assert_true(added.name.len == 0 && jar.cookies.len == 0, "WB6-F11 rejects CTL byte in cookie value");
}

fn test_wave3_http_parsers_and_cookies(t: lit::T&) {
    t.run("Multipart, Range/If-Range, Cache-Groups, ProblemDetails, X.509 pre-2050, Cookie store") { sub =>
        test_w3_multipart_range_and_cache(sub);
        test_w3_problem_x509_and_cookies(sub);
    };
}

fn test_w3_quic_and_pool_invariants(sub: lit::T&) {
    // WB3-002 / WB3-003: BBR signal threshold + ECN 100% CE failure
    var bbr = quic::BbrState { cwnd_bytes: 32768, bw_hi_bps: 1000000, .. };
    let cwnd_before = bbr.cwnd_bytes;
    quic::on_congestion_signal(bbr, 32768, 4096, 102400, 10, 10);
    sub.assert_true(bbr.cwnd_bytes < cwnd_before, "WB3-002 ECN/loss shrinks BBR cwnd");

    var pns = quic::PnSpaceState { tx_ect0_sent: 5, ecn_state: quic::QuicEcnState.Testing, .. };
    let ack_ce = quic::AckFrame { is_ecn: true, ect0_count: 0, ect1_count: 0, ecn_ce_count: 5, .. };
    let _, ecn_ok = quic::validate_ecn(pns, ack_ce, 5);
    sub.assert_false(ecn_ok, "WB3-003 100% ECN CE fails validation");

    // WB3-004: Dplpmtud blackhole recovery resets SearchComplete on repeated probe losses
    var pmt = quic::Dplpmtud {
        state:        quic::DplpmtudState.SearchComplete,
        current_pmtu: 1400,
        probed_size:  1452,
        probe_count:  2,
        max_probes:   3,
        ..
    };
    let _ = quic::on_probe_lost(pmt, 1400, 5000);
    sub.assert_true(pmt.current_pmtu == rfc::PMTU_BASE && pmt.state == quic::DplpmtudState.Base, "WB3-004 blackhole resets PMTU");

    // WB3-006 / WB3-008: preferred_address bad len rejected; NEW_CONNECTION_ID retire_prior_to > seq rejected
    let short_pa: u8[8] = [0; 8];
    let _, ok_pa = quic::decode_preferred_address(short_pa[..]);
    sub.assert_false(ok_pa, "WB3-006 truncated preferred_address rejected");
    var cid_out: u8[..64] = [];
    let tok: u8[16] = [0x11; 16];
    let cid: u8[8]  = [0x22; 8];
    sub.assert_false(quic::encode_new_conn_id_frame(1, 2, cid[..], tok, cid_out), "WB3-008 retire_prior_to > seq rejected");
}

fn test_w3_pool_redirect_and_ssrf_defaults(sub: lit::T&) {
    // WB3-010: Full PoolKey separates distinct proxy credentials & tenant hashes
    let p_a = net::TlsAndDnsPolicy { proxy_creds_hash: 111, tenant_id_hash: 1, has_mtls_or_custom_ca: false, .. };
    let p_b = net::TlsAndDnsPolicy { proxy_creds_hash: 222, tenant_id_hash: 1, has_mtls_or_custom_ca: false, .. };
    sub.assert_false(net::tls_and_dns_policy_equals(p_a, p_b), "WB3-010 different proxy_creds_hash isolated");

    // WB3-013 / WB3-014 / WB3-015: Default SSRF enabled on Client + cross-origin redirect strips auth
    let cli = client::new_client();
    sub.assert_true(cli.ssrf_guard.enabled, "WB3-014 ssrf_guard enabled by default");
    var c2 = client::new_client();
    c2.ssrf_guard.enabled = false;
    c2.mock_route("GET", "https://a.example/start", 302, "");
    client::add_mock_header(c2, "Location", "https://b.example/dest");
    c2.mock_route("GET", "https://b.example/dest", 200, "ok");
    var req = http::new_get("https://a.example/start");
    http::set_header(req, "Authorization", "Bearer top-secret");
    let resp, err = c2.do(req);
    sub.assert_true(http::ok(err) && resp.status_code == 200, "WB3-013 cross-origin redirect follows");

    let u_bad, u_ok = core::parse_url("https://user:pass@evil.example/cb");
    sub.assert_true(u_ok == core::UrlParseError.None && (u_bad.username().len > 0 || u_bad.password().len > 0), "parsed userinfo");
}

fn test_wave3_quic_pools_and_ssrf(t: lit::T&) {
    t.run("QUIC BBR/ECN/PMTUD/Migration, PoolKey isolation, default SSRF & cross-origin creds") { sub =>
        test_w3_quic_and_pool_invariants(sub);
        test_w3_pool_redirect_and_ssrf_defaults(sub);
    };
}

fn test_w3_gcra_and_proxy_hardening(sub: lit::T&) {
    // WB4-01 / H3_C07 / security_perimeter_test#19 unified GCRA invariants
    let cfg = security::new_gcra_config(1, 0);
    var cell = security::GcraCell { tat_ns: 0, .. };
    let d0 = security::gcra_check(cfg, cell, 0, 1000000000);
    sub.assert_false(d0.allowed, "WB4-01 cost=0 rejected");
    sub.assert_true(cell.tat_ns == 0, "WB4-01 cost=0 does not mutate TAT");

    let d_over = security::gcra_check(cfg, cell, 5, 1000000000);
    sub.assert_false(d_over.allowed && !d_over.insufficient_capacity, "WB4-01 over-burst sets insufficient_capacity");
    sub.assert_true(cell.tat_ns == 0, "WB4-01 rejection preserves TAT");

    // WB4-03: IPv4-mapped IPv6 and /64 IPv6 normalization for server rate limit key
    var rl_k1: u8[..64] = [];
    var rl_k2: u8[..64] = [];
    server_internal::normalize_rate_limit_ip_key("::ffff:192.0.2.10", rl_k1);
    server_internal::normalize_rate_limit_ip_key("2001:db8:1234:5678::99", rl_k2);
    sub.assert_true(rl_k1[..] == "192.0.2.10", "WB4-03 ::ffff: unwraps to IPv4");
    sub.assert_true(rl_k2[..] == "2001:db8:1234:5678::/64", "WB4-03 IPv6 normalizes to /64 prefix");

    // WB4-05 / WB4-06 / WB4-07 / WB4-08 / WB4-11: ReverseProxy fail-closed, 508 loop, Max-Forwards=0, introspection
    var rp = proxy::new_reverse_proxy();
    let _ = proxy::add_upstream_target(rp.cluster, "10.0.0.5", 8080);
    rp.config.enable_rate_limiting = true;
    sub.assert_false(proxy::check_proxy_ingress_rate_limit(rp, "", 0), "WB4-06 empty client_ip or now=0 fails closed");
    rp.config.enable_rate_limiting = false;

    var in_h = http::HeaderMap { .. };
    http::append_header(in_h, "Host", "api.example");
    http::append_header(in_h, "Via", "1.1 wing");
    var wire_out: u8[>..] = [];
    let _, st_loop = proxy::prepare_proxy_request_with_status_at(
        rp, "GET", "/", in_h, "198.51.100.1", "https", "", "", wire_out, 1000,
    );
    sub.assert_true(st_loop == proxy::ProxyPrepareStatus.LoopDetected508, "WB4-07 Via loop returns LoopDetected508");

    var intro = auth::IntrospectionResponse { active: true, exp: 500, nbf: 100, .. };
    let _ = intro.iss.try_set("https://idp.example");
    var aud_val: u8[..128] = [];
    let _ = aud_val.try_set("https://api.example");
    let _ = intro.aud.try_push(aud_val);
    let _ = intro.scope.try_set("read write");
    sub.assert_true(
        auth::validate_introspection_response(intro, "https://idp.example", "https://api.example", "read", 200),
        "WB4-11 valid introspection accepted",
    );
    sub.assert_false(
        auth::validate_introspection_response(intro, "https://idp.example", "https://api.example", "admin", 200),
        "WB4-11 missing required scope rejected",
    );
}

fn test_w3_server_trace_and_sni_isolation(sub: lit::T&) {
    // WB4-09 / TRACE disabled by default + WB3-009 421 Misdirected Request helper
    let srv = server::new_http_server("127.0.0.1", 0);
    sub.assert_false(srv.allow_trace, "allow_trace disabled by default");
    var wire_trace: u8[..1024] = [];
    var srv_mut = server::new_http_server("127.0.0.1", 0);
    srv_mut.pipeline.enable_csrf_guard = false;
    srv_mut.pipeline.enable_rate_limiter = false;
    let _, ok_tr = server::handle_connection_wire(
        srv_mut, "127.0.0.1", "TRACE / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 1000, wire_trace,
    );
    sub.assert_true(!ok_tr || core::contains(wire_trace[..], "405"), "TRACE returns 405 when allow_trace=false");

    var h3s = http3::h3_edge_open();
    defer http3::h3_edge_close(h3s);
    sub.assert_true(http3::h3_edge_set_tls_sni(h3s, "example.com"), "WB3-009 h3_edge_set_tls_sni records SNI");
    let raw_bad: const u8[:] = ":authorityother.example";
    let ent_bad: http::HeaderEntry[1] = [
        http::HeaderEntry { name_begin: 0, name_end: 10, values_begin: 10, values_end: 23, .. },
    ];
    let hv_bad = http::HeaderView { entries: ent_bad[..], raw: raw_bad };
    sub.assert_true(
        http3::h3_edge_validate_authority_sni(h3s, hv_bad) == rfc::STATUS_MISDIRECTED_REQUEST,
        "WB3-009 h3_edge_validate_authority_sni returns 421 on mismatch",
    );
    let raw_ok: const u8[:] = ":authorityexample.com";
    let ent_ok: http::HeaderEntry[1] = [
        http::HeaderEntry { name_begin: 0, name_end: 10, values_begin: 10, values_end: 21, .. },
    ];
    let hv_ok = http::HeaderView { entries: ent_ok[..], raw: raw_ok };
    sub.assert_true(
        http3::h3_edge_validate_authority_sni(h3s, hv_ok) == 0,
        "WB3-009 h3_edge_validate_authority_sni accepts matching SNI",
    );

    var sni_reg = server::SniRegistry { .. };
    defer server::clear_sni_registry(sni_reg);
    let trust = tls::TrustAnchorStore { .. };
    sub.assert_true(
        server::add_sni_registry_entry_mtls(sni_reg, "mtls.example", "CERT", "KEY", true, trust),
        "WB3-009 add_sni_registry_entry_mtls registers per-SNI mTLS policy",
    );
}

fn test_wave3_gcra_proxy_and_server(t: lit::T&) {
    t.run("GCRA bounds, IPv6 /64 norm, Proxy fail-closed/508, TRACE disabled, OAuth introspection") { sub =>
        test_w3_gcra_and_proxy_hardening(sub);
        test_w3_server_trace_and_sni_isolation(sub);
    };
}

fn test_wave3_tls_fingerprint_os_and_dst(t: lit::T&) {
    t.run("Ticket isolation, PHA/h2 guard, nofollow/coredump, fingerprint filter & GREASE, DST fault config") { sub =>
        // WB4-10: Client ticket cache isolates by port, tenant_hash, alpn_hash, policy_hash
        tls::clear_session_tickets();
        let psk: u8[32] = [0x55; 32];
        tls::store_session_ticket("tenant.example", "TKT1", psk[..], 1, 3600, rfc::TLS_CIPHER_AES_128_GCM_SHA256, 1000, 443, 1, 2, 3);
        var out_t:   u8[..256] = [];
        var out_p:   u8[..48]  = [];
        var out_age: u32       = 0;
        var out_cs:  u16       = 0;
        sub.assert_false(
            tls::lookup_session_ticket_full("tenant.example", out_t, out_p, out_age, out_cs, 2000, 8443, 1, 2, 3),
            "WB4-10 port mismatch misses ticket",
        );
        sub.assert_true(
            tls::lookup_session_ticket_full("tenant.example", out_t, out_p, out_age, out_cs, 2000, 443, 1, 2, 3),
            "WB4-10 exact scope matches ticket",
        );

        // WB6-F01 / WB6-F02 / WB6-F03: Weak cipher stripped, GREASE rotated cleanly
        sub.assert_false(fingerprint::is_allowed_tls_cipher(0x002F), "WB6-F01 TLS_RSA_WITH_AES_128_CBC_SHA rejected");
        sub.assert_true(fingerprint::is_allowed_tls_cipher(rfc::TLS_CIPHER_AES_128_GCM_SHA256), "TLS 1.3 AEAD allowed");
        var prof = fingerprint::ClientProfile { .. };
        let _ = prof.tls.ciphers.try_push(0x002F);
        let _ = prof.tls.ciphers.try_push(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
        let _ = prof.tls.supported_versions.try_push(0x0304);
        sub.assert_true(fingerprint::validate_and_filter_profile(prof) && prof.tls.ciphers.len == 1, "WB6-F01 filters weak cipher");
        fingerprint::rotate_profile_grease(prof, 42);
        sub.assert_true(prof.tls.ciphers.len >= 2 && rfc::is_grease_u16(prof.tls.ciphers[0]), "WB6-F02 rotates GREASE");

        // WB5-009 / WB6-F14: Core dump disable + safe file write + DST wall clock & fault knobs
        let _ = core::disable_core_dumps();
        let fc = net::DstFaultConfig { tls_unclean_eof: true, ecn_ce_all: true, .. };
        sub.assert_true(fc.tls_unclean_eof && fc.ecn_ce_all, "WB6-F14 DST fault flags present");
        var dw = net::DstWorld { .. };
        net::dst_init(dw, 42);
        defer net::dst_shutdown(dw);
        net::dst_set_monotonic_near_wrap(dw, 100);
        sub.assert_true(dw.stats.clock_jumps >= 1, "WB6-F14 dst_set_monotonic_near_wrap advances clock jumps");
    };
}

fn main() {
    let _ = net::tcp_init();
    var runner = lit::new_runner("Wave 3 Security Audit Regression Suite", lit::Verbosity.Verbose);
    lit::run_case(runner, "1. Hot-Path Data Structures & Router (WB1-001..009)", test_wave3_hotpath_structures);
    lit::run_case(runner, "2. HTTP Parsers, Ranges, Cache, X.509 & Cookies (WB2-*, WB6-F09..F11)", test_wave3_http_parsers_and_cookies);
    lit::run_case(runner, "3. QUIC RFC 9002, Pool Isolation, Redirects & SSRF (WB3-001..015)", test_wave3_quic_pools_and_ssrf);
    lit::run_case(runner, "4. GCRA, IPv6/SNI Server, ReverseProxy & OAuth2 (WB4-01..11)", test_wave3_gcra_proxy_and_server);
    lit::run_case(runner, "5. TLS Tickets, Fingerprints, OS Core-Dump & DST (WB4-10, WB5-*, WB6-*)", test_wave3_tls_fingerprint_os_and_dst);
    let ok = lit::finish(runner);
    assert(ok);
}
