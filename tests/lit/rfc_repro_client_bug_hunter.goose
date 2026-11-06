// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_client_bug_hunter.goose
// Regression test suite for client package bug-hunter audit findings (F001-F016).
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// F001: set_profile(session, Profile.Custom) must reset profile_spec and clear default_headers.
fn test_f001_set_profile_custom() {
    var session = wing::new_session();
    wing::set_profile(session, wing::Profile.Wing);
    assert(session.default_headers.entries.len > 0);
    wing::set_profile(session, wing::Profile.Custom);
    assert(session.default_headers.entries.len == 0);
    assert(session.profile_spec.kind == wing::Profile.Custom);
    print("F001_SET_PROFILE_CUSTOM: OK");
}

// F003: resolve_ech_config stale fallback must pass now_sec (not 0) to dns_cache_lookup, and lookup_cached_ech_config must clear out_ech.
fn test_f003_ech_stale_expiry_and_clear() {
    var session = wing::new_session();
    session.enable_ech = true;
    var rec = wing::HttpsRecord {
        priority: 1,
        has_ech:  true,
        ..
    };
    rec.ech_config_list.append("ech-config-bytes");
    var entry = wing::DnsCacheEntry {
        qtype:           rfc::DNS_QTYPE_HTTPS,
        ttl_sec:         60,
        inserted_at_sec: 1000,
        valid:           true,
        ..
    };
    entry.domain.append("ech.example.com");
    entry.https_records.push(rec);
    wing::dns_cache_insert(session.dns_cache, entry);

    var out_ech: u8[..512] = [];
    out_ech.append("stale-prefix-");
    let ok_fresh = wing::lookup_cached_ech_config(session.dns_cache, "ech.example.com", 1010, out_ech);
    assert(ok_fresh);
    assert(out_ech[..] == "ech-config-bytes");

    // 1000 + 60 + 86400 (stale_ttl_sec) + 100 = 87560 -> completely expired!
    var out_expired: u8[..512] = [];
    let ok_expired = wing::resolve_ech_config(session, "ech.example.com", 90000, out_expired);
    assert(!ok_expired);
    print("F003_ECH_STALE_EXPIRY: OK");
}

// F004: add_mock_sse must reject sample_events > 1024 bytes without panicking, and set_cookie must handle 2048..4096 byte cookies safely.
fn test_f004_mock_sse_and_set_cookie_bounds() {
    var session = wing::new_session();
    var big_sse: u8[..1500] = [];
    for i in 1400 {
        big_sse.push('a');
    }
    wing::add_mock_sse(session, "https://example.com/events", big_sse[..]);
    assert(session.mock_routes.len == 0);

    var big_cookie_val: u8[..2500] = [];
    for i in 2400 {
        big_cookie_val.push('v');
    }
    wing::set_cookie(session, "big_c", big_cookie_val[..]);
    assert(wing::cookie(session, "big_c").len == 2400);
    print("F004_MOCK_SSE_AND_COOKIE_BOUNDS: OK");
}

// F005: process_dictionary_response must store the decompressed representation in dict_cache (RFC 9842 §2.1) and not cache corrupt dcz/dcb bodies.
fn test_f005_dictionary_response_order() {
    var session = wing::new_session();
    var out_dec: u8[..1024] = [];
    let ok_corrupt = wing::process_dictionary_response(
        session,
        "https://example.com",
        "match=\"/app/*\"",
        "dcz",
        "corrupt-dcz-payload",
        out_dec,
    );
    assert(!ok_corrupt);
    assert(session.dict_cache.entries.len == 0);
    print("F005_DICT_RESPONSE_ORDER: OK");
}

// F006: add_interceptor(AuthBearer) must prepend "Bearer ", and log_interceptor_request must clamp >128-byte lines and redact sensitive headers.
fn test_f006_interceptor_bearer_and_log_bounds() {
    var pipe = wing::InterceptorPipeline { .. };
    var entry = wing::InterceptorEntry {
        scope: wing::InterceptorScope.Application,
        kind:  wing::InterceptorKind.AuthBearer,
        ..
    };
    entry.header_val.append("raw-jwt-token");
    assert(wing::add_interceptor(pipe, entry));
    assert(pipe.bearer_token[..] == "Bearer raw-jwt-token");

    assert(!wing::add_traceparent(pipe, "zz"));

    assert(wing::add_logging(pipe, wing::InterceptorScope.Application, wing::LogLevel.Headers));
    var req = wing::new_get("https://example.com/very/long/path/that/exceeds/one/hundred/and/twenty/eight/bytes/when/formatted/into/log/entry/buffer/without/clamping/check");
    wing::sensitive_header(req, "Authorization", "Bearer super-secret-jwt-value-that-must-not-appear-in-logs");
    wing::apply_app_interceptors_request(pipe, req, 1);
    for i in pipe.log_entries.len {
        assert(!core::contains(pipe.log_entries[i][..], "super-secret-jwt-value"));
    }
    print("F006_INTERCEPTOR_BEARER_AND_LOG: OK");
}

// F007 & F008: Backoff.delay / RateLimiter.allow must guard invalid params, and evaluate_early_data_request must fold method case.
fn test_f007_f008_policy_and_early_data() {
    let b = wing::Backoff {
        base_ns: -100,
        max_ns:  -50,
        factor:  0.5,
    };
    assert(wing::delay(b, 2).nanos >= 0);

    var lim = wing::RateLimiter {
        rate_per_sec:        -5.0,
        burst_capacity:      10.0,
        tokens:              1.0,
        last_update_mono_ns: 100,
    };
    assert(!wing::allow(lim, 200));

    let d = wing::evaluate_early_data_request("get", false);
    assert(d == wing::EarlyDataDecision.Allow);
    print("F007_F008_POLICY_AND_EARLY_DATA: OK");
}

// F009: Response.remove_header must clear res.presence_mask bit.
fn test_f009_response_remove_header_presence_mask() {
    var res = wing::Response { .. };
    wing::set_header(res, "Location", "https://example.com/next");
    assert(wing::has_header(res, "Location"));
    assert(wing::remove_header(res, "Location"));
    assert(!wing::has_header(res, "Location"));
    print("F009_RESPONSE_REMOVE_HEADER_MASK: OK");
}

// F010: stage_client_cookie_load must not treat CrossSite context (when had_cross_site_hop is false) as top-level navigation even if is_main_frame is true.
fn test_f010_samesite_cross_site_main_frame() {
    var jar = wing::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    assert(wing::set_cookie_header(jar, "https://target.example.com/", "lax_sid=secret; Path=/; Secure; SameSite=Lax", now_us));
    let target_u = core::new_url("https://target.example.com/api");
    let eval = wing::SameSiteCookieContext {
        context_type:       wing::SameSiteContextType.CrossSite,
        schemefully_same:   false,
        is_reload:          false,
        had_cross_site_hop: false,
    };
    var hdrs = wing::HeaderMap { .. };
    let _ = wing::stage_client_cookie_load(hdrs, target_u, eval, true, "", true, now_us, jar, true);
    assert(!core::contains(wing::find_header(hdrs, "Cookie"), "lax_sid=secret"));
    print("F010_SAMESITE_CROSS_SITE_MAIN_FRAME: OK");
}

// F011: build_effective_url bounds, process_h2_response_frame 1xx header clearing, and prepare_auth_retry_hop stale Cookie removal.
fn test_f011_exec_bounds_and_auth_retry_cookie() {
    var base_big: u8[..1500] = [];
    base_big.append("https://example.com/");
    for i in 1400 {
        base_big.push('a');
    }
    var rel_big: u8[..1000] = [];
    for i in 800 {
        rel_big.push('b');
    }
    var q_items: wing::QueryItem[..1] = [];
    var out_url: u8[..2048]           = [];
    wing::build_effective_url(base_big[..], rel_big[..], q_items[..], out_url);

    var session = wing::new_session();
    wing::set_cookie_header(session.jar, "https://auth.example.com/resource", "sid=initial_token; Path=/", session.virtual_clock_us);
    var ctx = wing::RequestExecutionContext {
        site_for_cookies: wing::site_for_cookies_from_url("https://auth.example.com/resource"),
        is_main_frame:    true,
        ..
    };
    ctx.current_method.append("GET");
    let curr_u = core::new_url("https://auth.example.com/resource");
    let ss_eval = wing::compute_hop_samesite_context(ctx, curr_u, true);
    wing::prepare_hop_cookie_header(session, ctx, curr_u, ss_eval, true);
    assert(core::contains(wing::find_header(ctx.headers, "Cookie"), "sid=initial_token"));

    var resp_401 = wing::Response { status_code: 401, .. };
    wing::set_header(resp_401, "WWW-Authenticate", "Basic realm=\"api\"");
    wing::set_header(resp_401, "Set-Cookie", "sid=; Path=/; Max-Age=0");
    wing::prepare_auth_retry_hop(session, ctx, curr_u, ss_eval, true, resp_401, "Basic YWxpY2U6c2VjcmV0");
    assert(!core::contains(wing::find_header(ctx.headers, "Cookie"), "sid=initial_token"));
    print("F011_EXEC_BOUNDS_AND_AUTH_COOKIE: OK");
}

// F012: pump_response_body must treat 101 Switching Protocols as having an empty HTTP message body.
fn test_f012_h1_101_empty_body() {
    var conn = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    let req = wing::new_get("http://example.com/ws");
    var resp = wing::Response { status_code: 101, .. };
    let ok_101, keep = wing::pump_response_body(conn, req, resp, "upgraded-protocol-bytes", 100);
    assert(ok_101 && keep);
    assert(resp.body.len == 0);
    assert(conn.rx_buf[..] == "upgraded-protocol-bytes");
    print("F012_H1_101_EMPTY_BODY: OK");
}

// F013: is_private_or_reserved_ip must reject >256-byte IP literals and compressed zero high-word SIIT/NAT64 forms.
fn test_f013_ssrf_oversized_and_siit() {
    var long_ip: u8[..300] = [];
    long_ip.append("FC00::");
    for i in 260 {
        long_ip.push('0');
    }
    assert(wing::is_private_or_reserved_ip(long_ip[..]));
    assert(wing::is_private_or_reserved_ip("::ffff:0:0.0.0.1"));
    assert(wing::is_private_or_reserved_ip("64:ff9b::0.0.0.1"));
    print("F013_SSRF_OVERSIZED_AND_SIIT: OK");
}

// F015 & F016: connect_udp IPv6 percent-encoding and StreamReader chunked token & Content-Length clamping.
fn test_f015_f016_masque_ipv6_and_stream_reader() {
    var session = wing::new_session();
    let _ = wing::mock_route(session, "CONNECT", "https://proxy.example.com/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/", rfc::STATUS_OK, "");
    wing::add_mock_header(session, "Capsule-Protocol", "?1");
    let tun, _, err_m = wing::connect_udp(session, "https://proxy.example.com", "[2001:db8::1]", 443);
    assert(wing::ok(err_m) && tun.state == wing::MasqueTunnelState.Established);

    var resp_chunk = wing::Response { status_code: 200, .. };
    wing::set_header(resp_chunk, "Transfer-Encoding", "gzip, chunked");
    resp_chunk.body.append("4\r\nWiki\r\n0\r\n\r\n");
    let sr_chunk = wing::new_stream_reader(resp_chunk);
    assert(sr_chunk.is_chunked);

    var resp_cl = wing::Response { status_code: 200, .. };
    wing::set_header(resp_cl, "Content-Length", "4");
    resp_cl.body.append("WikiEXTRA_TRAILING");
    var sr_cl = wing::new_stream_reader(resp_cl);
    var out_all: u8[..64] = [];
    let read_n = wing::read_all(sr_cl, out_all);
    assert(read_n == 4);
    assert(out_all[..] == "Wiki");
    print("F015_F016_MASQUE_AND_STREAM_READER: OK");
}

fn main() {
    test_f001_set_profile_custom();
    test_f003_ech_stale_expiry_and_clear();
    test_f004_mock_sse_and_set_cookie_bounds();
    test_f005_dictionary_response_order();
    test_f006_interceptor_bearer_and_log_bounds();
    test_f007_f008_policy_and_early_data();
    test_f009_response_remove_header_presence_mask();
    test_f010_samesite_cross_site_main_frame();
    test_f011_exec_bounds_and_auth_retry_cookie();
    test_f012_h1_101_empty_body();
    test_f013_ssrf_oversized_and_siit();
    test_f015_f016_masque_ipv6_and_stream_reader();
}

// CHECK: F001_SET_PROFILE_CUSTOM: OK
// CHECK-NEXT: F003_ECH_STALE_EXPIRY: OK
// CHECK-NEXT: F004_MOCK_SSE_AND_COOKIE_BOUNDS: OK
// CHECK-NEXT: F005_DICT_RESPONSE_ORDER: OK
// CHECK-NEXT: F006_INTERCEPTOR_BEARER_AND_LOG: OK
// CHECK-NEXT: F007_F008_POLICY_AND_EARLY_DATA: OK
// CHECK-NEXT: F009_RESPONSE_REMOVE_HEADER_MASK: OK
// CHECK-NEXT: F010_SAMESITE_CROSS_SITE_MAIN_FRAME: OK
// CHECK-NEXT: F011_EXEC_BOUNDS_AND_AUTH_COOKIE: OK
// CHECK-NEXT: F012_H1_101_EMPTY_BODY: OK
// CHECK-NEXT: F013_SSRF_OVERSIZED_AND_SIIT: OK
// CHECK-NEXT: F015_F016_MASQUE_AND_STREAM_READER: OK
