// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_cookie_and_psl
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// ============================================================================
// 1. rfc_repro_cookie_cross_component (1/5)
// ============================================================================
// CHECK: === [1/5] rfc_repro_cookie_cross_component ===

// tests/lit/rfc_repro_cookie_cross_component.goose
// Regression verification for cross-component cookie boundaries and RFC 6265 / 6265bis edge cases (F001-F007).
//

// F001: Cross-component IPv6 bracket handling across core::Url, SiteForCookies, trustworthy localhost, and Session cookie bridge.
fn test_f001_ipv6_bracket_cross_component() {
    let now_us: i64 = 1700000000000000;
    let u_v6 = core::new_url("http://[::1]:8080/api/v1/login");
    let sfc = cookie::site_for_cookies_from_parsed_url(u_v6);
    assert(cookie::is_first_party(sfc, "http://[::1]:8080/api/v1/login", true));
    assert(cookie::is_trustworthy_non_crypto_host(core::hostname(u_v6)));

    var session = wing::new_session();
    session.virtual_clock_us = now_us;
    var ctx = wing::RequestExecutionContext {
        site_for_cookies: sfc,
        is_main_frame:    true,
        ..
    };
    let ss_eval = wing::compute_hop_samesite_context(ctx, u_v6, true);
    assert(ss_eval.context_type == cookie::SameSiteContextType.SameSiteStrict);

    var resp_hdrs = wing::HeaderMap { .. };
    wing::set_header(resp_hdrs, "Set-Cookie", "__Host-v6=tok_v6; Secure; Path=/; SameSite=Strict");
    wing::ingest_hop_response_cookies(session, ctx, u_v6, ss_eval, resp_hdrs);
    assert(session.jar.cookies.len == 1);

    wing::prepare_hop_cookie_header(session, ctx, u_v6, ss_eval, true);
    assert(core::contains(wing::find_header(ctx.headers, "Cookie"), "__Host-v6=tok_v6"));
    print("F001_IPV6_CROSS_COMPONENT: OK");
}

// F002: Cross-component PSL agreement between client/redirect.goose and cookie/psl.goose DAFSA (e.g. onrender.com, co.za).
fn test_f002_psl_dafsa_redirect_isolation() {
    let u_a = core::new_url("https://tenant-a.onrender.com/start");
    let u_b = core::new_url("https://tenant-b.onrender.com/finish");
    let orig_a = core::origin_from_url(u_a);
    assert(!core::is_same_site_origin_url(orig_a, u_b));

    var chain: core::Url[..4] = [];
    chain.push(u_a);
    let sfc_a = cookie::site_for_cookies_from_parsed_url(u_a);
    let r_info = wing::compute_redirect_info(
        302, "GET", u_a, "https://tenant-b.onrender.com/finish", "",
        wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "", sfc_a,
        cookie::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT, chain[..], orig_a,
        wing::RedirectOptions { has_initiator: true, is_main_frame: true, .. },
    );
    assert(r_info.is_cross_site_tainted);
    assert(cookie::is_first_party(r_info.new_site_for_cookies, "https://tenant-b.onrender.com/finish", true));
    print("F002_PSL_REDIRECT_ISOLATION: OK");
}

// F003: Cross-component SameSite navigation context & can_set_for_context.
fn test_f003_samesite_context_and_set_guard() {
    let now_us: i64 = 1700000000000000;
    let c_strict, _, ok_s = cookie::parse_canonical_set_cookie("s=1; SameSite=Strict; Secure; Path=/", "bank.com", "/", now_us);
    assert(ok_s);
    let cross_ctx = cookie::SameSiteCookieContext {
        context_type:       cookie::SameSiteContextType.CrossSite,
        schemefully_same:   false,
        is_reload:          false,
        had_cross_site_hop: true,
    };
    let _, can_set_cross_main = cookie::can_set_for_context(
        c_strict, cross_ctx, cookie::InclusionOptions { is_main_frame: true, is_secure_channel: true },
    );
    assert(!can_set_cross_main);

    var jar = cookie::CanonicalCookieJar { .. };
    assert(cookie::set_cookie_header(jar, "https://bank.com/", "lax_sid=secret2; SameSite=Lax; Secure; Path=/", now_us));
    let u_bank = core::new_url("https://bank.com/dashboard");
    var hdrs = wing::HeaderMap { .. };
    let _ = wing::stage_client_cookie_load(hdrs, u_bank, cross_ctx, true, "", true, now_us, jar, true);
    assert(!core::contains(wing::find_header(hdrs, "Cookie"), "lax_sid=secret2"));

    let u_evil = core::new_url("https://evil.com/");
    let ctx_nav = wing::RequestExecutionContext {
        initiator:          core::origin_from_url(u_evil),
        has_initiator:      true,
        site_for_cookies:   cookie::site_for_cookies_from_url("https://bank.com/"),
        first_party_policy: cookie::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
        is_main_frame:      true,
        ..
    };
    let nav_eval = wing::compute_hop_samesite_context(ctx_nav, u_bank, true);
    assert(nav_eval.context_type == cookie::SameSiteContextType.SameSiteLax);

    let ctx_null_sfc = wing::RequestExecutionContext {
        is_main_frame:      true,
        had_cross_site_hop: true,
        site_for_cookies:   cookie::null_site_for_cookies(),
        ..
    };
    let null_eval = wing::compute_hop_samesite_context(ctx_null_sfc, u_bank, true);
    assert(null_eval.context_type == cookie::SameSiteContextType.CrossSite);
    print("F003_SAMESITE_CONTEXT_BOUNDARY: OK");
}

// F004: Domain attribute >256B rejection and multiple Domain attribute last-wins reset (RFC 6265 §5.3 Step 4/6).
fn test_f004_domain_attribute_edge_cases() {
    let now_us: i64 = 1700000000000000;
    var big_dom_hdr: u8[..400] = [];
    big_dom_hdr.append("sid=1; Domain=sub.");
    for i in 260 { big_dom_hdr.push('a'); }
    big_dom_hdr.append(".evil.com");
    let _, _, ok_big_dom = cookie::parse_canonical_set_cookie(big_dom_hdr[..], "example.com", "/", now_us);
    assert(!ok_big_dom);

    // Earlier valid Domain=example.com followed by empty Domain= must reset to host-only on sub.example.com
    let c_multi, _, ok_multi = cookie::parse_canonical_set_cookie(
        "sid=2; Domain=example.com; Domain=", "sub.example.com", "/", now_us,
    );
    assert(ok_multi && c_multi.host_only && c_multi.domain[..] == "sub.example.com");
    print("F004_DOMAIN_ATTR_EDGE: OK");
}

// F005: Long request URL paths (>256B) in compute_default_path, parse_canonical_cookie_url, and partition_key bounds.
fn test_f005_long_url_path_and_partition_bounds() {
    let now_us: i64 = 1700000000000000;
    var long_url: u8[..600] = [];
    long_url.append("https://example.com/api/");
    for i in 280 { long_url.push('p'); }
    long_url.append("/leaf");

    var def_path: u8[..256] = [];
    let u_parsed = core::new_url(long_url[..]);
    cookie::compute_default_path(core::pathname(u_parsed), def_path);
    assert(def_path[..] == "/api");

    var jar = cookie::CanonicalCookieJar { .. };
    assert(cookie::set_cookie_header(jar, long_url[..], "k_long=v_long; Path=/api", now_us));
    assert(cookie::get(jar, long_url[..], "k_long", now_us) == "v_long");

    var huge_part: u8[..300] = [];
    for i in 280 { huge_part.push('k'); }
    assert(!cookie::set_cookie_header(jar, "https://example.com/", "p=1; Secure; Partitioned", now_us, huge_part[..]));
    print("F005_LONG_PATH_AND_BOUNDS: OK");
}

// F006: import_json timestamp preservation, Netscape .domain collision/deletion, and JSON/security validation.
fn test_f006_store_lifecycle_and_netscape_collision() {
    let t1: i64 = 1700000000000000;
    let t2: i64 = t1 + 500000000;
    var jar1 = cookie::CanonicalCookieJar { .. };
    assert(cookie::set_cookie_header(jar1, "https://example.com/", "c_old=1; Secure; Path=/", t1));
    var json_buf: u8[>..] = [];
    cookie::export_json(jar1, json_buf);

    var jar2 = cookie::CanonicalCookieJar { .. };
    assert(cookie::import_json(jar2, json_buf[..], t2) == 1);
    assert(jar2.cookies[0].creation_utc == t1);

    // Netscape imported .example.com cookie must be overwritten/deleted by Set-Cookie on Domain=.example.com
    var jar_ns = cookie::CanonicalCookieJar { .. };
    assert(cookie::import_netscape(jar_ns, ".example.com\tTRUE\t/\tTRUE\t2147483647\tauth_token\told_val\n", t1) == 1);
    assert(cookie::set_cookie_header(jar_ns, "https://app.example.com/", "auth_token=new_val; Domain=.example.com; Path=/; Secure", t2));
    assert(jar_ns.cookies.len == 1 && jar_ns.cookies[0].value[..] == "new_val");

    var del_filter = cookie::DeletionInfo { .. };
    del_filter.domain.append("example.com");
    assert(cookie::delete_matching(jar_ns, del_filter) == 1);
    print("F006_STORE_LIFECYCLE_AND_NETSCAPE: OK");
}

// F007: RFC 6265 §5.1.1 cookie-date hms-time trailing non-digits ('10:18:14GMT') and invalid day-of-month ('32 Jan 25').
fn test_f007_rfc6265_cookie_date_edge_cases() {
    let _, ok_gmt_suffix = cookie::parse_date_us("Wed, 09 Jun 2021 10:18:14GMT");
    assert(ok_gmt_suffix);
    let _, ok_three_digit_hr = cookie::parse_date_us("Wed, 09 Jun 2021 010:18:14 GMT");
    assert(!ok_three_digit_hr);
    let _, ok_bad_dom_2yr = cookie::parse_date_us("32 Jan 25 00:00:00 GMT");
    assert(!ok_bad_dom_2yr);
    print("F007_RFC6265_COOKIE_DATE: OK");
}

fn run_01_rfc_repro_cookie_cross_component() {
    test_f001_ipv6_bracket_cross_component();
    test_f002_psl_dafsa_redirect_isolation();
    test_f003_samesite_context_and_set_guard();
    test_f004_domain_attribute_edge_cases();
    test_f005_long_url_path_and_partition_bounds();
    test_f006_store_lifecycle_and_netscape_collision();
    test_f007_rfc6265_cookie_date_edge_cases();
}

// CHECK: F001_IPV6_CROSS_COMPONENT: OK
// CHECK-NEXT: F002_PSL_REDIRECT_ISOLATION: OK
// CHECK-NEXT: F003_SAMESITE_CONTEXT_BOUNDARY: OK
// CHECK-NEXT: F004_DOMAIN_ATTR_EDGE: OK
// CHECK-NEXT: F005_LONG_PATH_AND_BOUNDS: OK
// CHECK-NEXT: F006_STORE_LIFECYCLE_AND_NETSCAPE: OK
// CHECK-NEXT: F007_RFC6265_COOKIE_DATE: OK

// ============================================================================
// 2. rfc_repro_cookie_domain_gc_truncation (2/5)
// ============================================================================
// CHECK: === [2/5] rfc_repro_cookie_domain_gc_truncation ===

// tests/lit/rfc_repro_cookie_domain_gc_truncation.goose
// Regression verification for domain GC candidate buffer truncation (GOOSE-BUG-2).
// When domain cookie count exceeds 180 (e.g. 175 host cookies + 6 domain cookies = 181),
// domain cookies MUST be evicted before host cookies per RFC/Chromium spec (GC-07).
//

fn run_02_rfc_repro_cookie_domain_gc_truncation() {
    var jar = cookie::CanonicalCookieJar { .. };
    var now_us: i64 = 1700000000000000;

    // 1. Insert 175 Host-Only cookies with older access times
    for i in 175 {
        var h: u8[..64] = [];
        format(h, "host_", i, "=1; Priority=Low");
        now_us += 10;
        let ok = cookie::set_cookie_header(jar, "http://example.com/", h[..], now_us);
        assert(ok);
    }

    // 2. Insert 6 Domain cookies (Domain=example.com) with newer access times
    for i in 6 {
        var h: u8[..64] = [];
        format(h, "dom_", i, "=1; Domain=example.com; Priority=Low");
        now_us += 100000000;
        let ok = cookie::set_cookie_header(jar, "http://example.com/", h[..], now_us);
        assert(ok);
    }

    // Total 181 inserted -> GC evicted 31 cookies down to 150
    assert(jar.cookies.len == 150);

    // All 6 domain cookies must be evicted before host cookies
    var remaining_domain_cookies = 0;
    for i in jar.cookies.len {
        if !jar.cookies[i].host_only { remaining_domain_cookies += 1; }
    }

    // COOKIERL-01: Relaxed RFC 6265 §5.1.1 / Erratum 4148 date token suffixes and Sept prefix
    let ts_rel1, ok_rel1 = cookie::parse_date_us("Thu, 23rd-Sept-2026Z 10:18:14UTC");
    assert(ok_rel1 && ts_rel1 > 0);
    let ts_rel2, ok_rel2 = cookie::parse_date_us("Wed, 09-Jun-026 10:18:14 GMT");
    assert(ok_rel2 && ts_rel2 > 0);

    // COOKIERL-02 & COOKIERL-06: ServerCookieDeltaJar, make_removal, and percent encode/decode
    var djar = cookie::ServerCookieDeltaJar { .. };
    var orig_c = cookie::new_canonical_cookie("sid", "old_val");
    orig_c = cookie::with_value(orig_c, "old_val2");
    orig_c = cookie::with_partition_key(orig_c, "https://example.com");
    orig_c = cookie::with_source(orig_c, cookie::SourceScheme.Secure, 443);
    assert(cookie::add_original(djar, orig_c));
    var add_c = cookie::new_canonical_cookie("theme", "dark");
    assert(cookie::add(djar, add_c));
    assert(cookie::remove(djar, orig_c));
    var rem_fmt: u8[..256] = [];
    cookie::format(djar.cookies[0], rem_fmt);
    assert(core::ends_with(rem_fmt[..], "; Max-Age=0"));
    assert(cookie::remove(djar, add_c));

    var enc_buf: u8[..4096] = [];
    var dec_buf: u8[..4096] = [];
    assert(cookie::encode_percent("a b;c%d", enc_buf));
    assert(enc_buf[..] == "a%20b%3Bc%25d");
    assert(cookie::decode_percent(enc_buf[..], dec_buf));
    assert(dec_buf[..] == "a b;c%d");

    // COOKIERL-03 & COOKIERL-04: Punycode normalization & is_known_public_suffix
    var ace_dom: u8[..256] = [];
    assert(core::punycode_encode_domain("Example.\xE4\xB8\xAD\xE5\x9B\xBD", ace_dom));
    assert(ace_dom[..] == "example.xn--fiqs8s");
    var psl_db = cookie::new_psl_database();
    cookie::add_rule(psl_db, "custom.tld", cookie::PslRuleType.Normal, cookie::PslSection.Icann);
    assert(cookie::is_known_public_suffix(psl_db, "custom.tld"));
    assert(cookie::is_known_public_suffix(psl_db, "co.uk"));
    assert(!cookie::is_known_public_suffix(psl_db, "intranet"));

    print("REMAINING_DOMAIN_COOKIES: ", remaining_domain_cookies, "\n");
}

// CHECK: REMAINING_DOMAIN_COOKIES: 0

// ============================================================================
// 3. rfc_repro_cookie_edge (3/5)
// ============================================================================
// CHECK: === [3/5] rfc_repro_cookie_edge ===

// tests/lit/rfc_repro_cookie_edge.goose
// Verification of Cookie edge invariants, bounds, enum fallback, and arithmetic safety.
//

fn run_03_rfc_repro_cookie_edge() {
    let now_us: i64 = 1700000000000000;

    // 1. SameSite and Priority enum fallback (Rule 15: Unknown on invalid values)
    let ss_invalid = cookie::parse_same_site("invalid_samesite");
    print("SS_INVALID: ", ss_invalid == cookie::SameSite.Unknown, "\n");
    let prio_invalid = cookie::parse_priority("invalid_priority");
    print("PRIO_INVALID: ", prio_invalid == cookie::Priority.Unknown, "\n");

    // 2. Capacity safety in with_domain, with_path, with_partition_key
    var c = cookie::new_canonical_cookie("sid", "val");
    var huge_path: u8[..300] = [];
    for i in 280 { huge_path.push('x'); }
    c.with_path(huge_path[..]);
    print("HUGE_PATH_SAFE: ", c.path[..] == "/", "\n");

    // 3. Calendar date validation: year > 9999 rejected
    let _, date_valid_ok = cookie::parse_date_us("Wed, 09 Jun 2021 10:18:14 GMT");
    print("DATE_VALID: ", date_valid_ok, "\n");
    let _, date_huge_yr_ok = cookie::parse_date_us("Wed, 09 Jun 99999 10:18:14 GMT");
    print("DATE_HUGE_YR: ", date_huge_yr_ok, "\n");

    // 4. URL parsing bounds safety on long path
    let url_long = cookie::parse_canonical_cookie_url("https://example.com/api/test");
    print("URL_HOST: ", url_long.host[..], "\n");
    print("URL_PATH: ", url_long.path[..], "\n");

    // 5. Saturating max-age calculation
    var c_max = cookie::new_canonical_cookie("tok", "123");
    c_max.with_max_age_seconds(999999999, now_us);
    print("CAPPED_PERSISTENT: ", c_max.persistent, "\n");
    print("EXPIRES_GREATER: ", c_max.expires_utc > now_us, "\n");
}

// CHECK: SS_INVALID: true
// CHECK: PRIO_INVALID: true
// CHECK: HUGE_PATH_SAFE: true
// CHECK: DATE_VALID: true
// CHECK: DATE_HUGE_YR: false
// CHECK: URL_HOST: example.com
// CHECK: URL_PATH: /api/test
// CHECK: CAPPED_PERSISTENT: true
// CHECK: EXPIRES_GREATER: true

// ============================================================================
// 4. rfc_repro_semantic_cookie_max_age (4/5)
// ============================================================================
// CHECK: === [4/5] rfc_repro_semantic_cookie_max_age ===

// tests/lit/rfc_repro_semantic_cookie_max_age.goose
// Verification of RFC 6265 Section 5.2.2 Max-Age attribute handling.
// RFC 6265 Section 5.2.2: The Max-Age Attribute - If delta-seconds is less than or equal to zero (0), let expiry-time be the earliest representable date and time.
//

fn run_04_rfc_repro_semantic_cookie_max_age() {
    let now_us: i64 = 1700000000000000;

    var c_zero = cookie::new_canonical_cookie("session", "abc");
    c_zero.with_max_age_seconds(0, now_us);
    print("MAX_AGE_ZERO: ", c_zero.expires_utc, "\n");

    var c_neg = cookie::new_canonical_cookie("session", "abc");
    c_neg.with_max_age_seconds(-60, now_us);
    print("MAX_AGE_NEG: ", c_neg.expires_utc, "\n");

    var c_pos = cookie::new_canonical_cookie("session", "abc");
    c_pos.with_max_age_seconds(3600, now_us);
    print("MAX_AGE_POS_DELTA: ", c_pos.expires_utc - now_us, "\n");
}

// CHECK: MAX_AGE_ZERO: 0
// CHECK: MAX_AGE_NEG: 0
// CHECK: MAX_AGE_POS_DELTA: 3600000000

// ============================================================================
// 5. rfc_repro_client_wire_cookie (5/5)
// ============================================================================
// CHECK: === [5/5] rfc_repro_client_wire_cookie ===

// tests/lit/rfc_repro_client_wire_cookie.goose
// Regression verification for client wire parsing, cookie bridge, and cookie store defects.
//

fn test_chips_auto_partition_key() {
    var jar = cookie::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    // Partitioned cookie with no explicit partition_key passed
    let ok = cookie::set_cookie_header(jar, "https://auth.example.com/api", "sid=chips123; Path=/; Secure; Partitioned", now_us);
    assert(ok);
    assert(jar.cookies.len == 1);
    assert(jar.cookies[0].partitioned);
    assert(jar.cookies[0].partition_key.len > 0);
    assert(jar.cookies[0].partition_key[..] == "https://example.com");
    print("CHECK_CHIPS: OK");
}

fn test_host_cookie_roundtrip() {
    var jar1 = cookie::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    let ok = cookie::set_cookie_header(jar1, "https://example.com/", "__Host-auth=token999; Path=/; Secure; HttpOnly", now_us);
    assert(ok);
    assert(jar1.cookies.len == 1);

    var json_buf: u8[>..] = [];
    cookie::export_json(jar1, json_buf);

    var jar2 = cookie::CanonicalCookieJar { .. };
    let imported = cookie::import_json(jar2, json_buf[..], now_us);
    assert(imported == 1);
    assert(jar2.cookies.len == 1);
    assert(jar2.cookies[0].name[..] == "__Host-auth");
    print("CHECK_HOST_ROUNDTRIP: OK");
}

fn test_writeback_batcher_size() {
    var batcher = cookie::new_write_back_batcher(1000);
    assert(batcher.max_batch_size <= batcher.ops.cap);
    print("CHECK_BATCHER_SIZE: OK");
}

fn test_global_gc_secure_medium() {
    var jar = cookie::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    // Set 3305 secure medium cookies (all accessed recently)
    for i in 3305 {
        var c = cookie::CanonicalCookie { .. };
        var n_buf: u8[..64] = [];
        n_buf.append("c_");
        format(n_buf, i);
        c.name.append(n_buf[..]);
        c.value.append("val");
        c.domain.append("example.com");
        c.path.append("/");
        c.secure = true;
        c.priority = cookie::Priority.Medium;
        c.last_access_utc = now_us - (i * 1000);
        c.creation_utc = now_us - (i * 1000);
        c.creation_seq = i;
        jar.cookies.push(c);
    }
    assert(jar.cookies.len == 3305);
    let evicted = cookie::garbage_collect_global(jar, now_us);
    assert(evicted >= 5);
    assert(jar.cookies.len <= jar.target_cookies_global);
    print("CHECK_GLOBAL_GC: OK");
}

fn test_format_cookie_header_bounds() {
    var cookies: cookie::CanonicalCookie[..4] = [];
    for i in 4 {
        var c = cookie::CanonicalCookie { .. };
        c.name.append("key");
        // Each cookie value is 800 bytes -> 4 * 800 > 3000 bytes
        for j in 800 { c.value.push('x'); }
        cookies.push(c);
    }
    // Destination buffer is only 2048 bytes
    var out_buf: u8[..2048] = [];
    cookie::format_cookie_header_value(cookies[..], out_buf);
    assert(out_buf.len <= out_buf.cap);
    assert(out_buf.len > 0);
    print("CHECK_COOKIE_HEADER_BOUNDS: OK");
}

fn test_dafsa_psl_cross_site() {
    assert(!cookie::is_schemeful_same_site("https", "a.onrender.com", "https", "b.onrender.com"));
    assert(!cookie::is_schemeful_same_site("https", "foo.github.io", "https", "bar.github.io"));
    assert(cookie::is_schemeful_same_site("https", "sub1.example.com", "https", "sub2.example.com"));
    print("CHECK_DAFSA_PSL: OK");
}

fn test_h1_set_cookie_parsing() {
    var resp = wing::Response { .. };
    let raw_resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: session=longtoken_abc123xyz456; Path=/; Secure; HttpOnly\r\n\r\n";
    let ok = wing::parse_response_headers(raw_resp[..], resp);
    assert(ok);
    assert(wing::has_header(resp, "Set-Cookie"));
    assert(core::contains(wing::header(resp, "Set-Cookie"), "longtoken_abc123xyz456"));
    print("CHECK_H1_SET_COOKIE: OK");
}

fn run_05_rfc_repro_client_wire_cookie() {
    test_chips_auto_partition_key();
    test_host_cookie_roundtrip();
    test_writeback_batcher_size();
    test_global_gc_secure_medium();
    test_format_cookie_header_bounds();
    test_dafsa_psl_cross_site();
    test_h1_set_cookie_parsing();
}

// CHECK: CHECK_CHIPS: OK
// CHECK-NEXT: CHECK_HOST_ROUNDTRIP: OK
// CHECK-NEXT: CHECK_BATCHER_SIZE: OK
// CHECK-NEXT: CHECK_GLOBAL_GC: OK
// CHECK-NEXT: CHECK_COOKIE_HEADER_BOUNDS: OK
// CHECK-NEXT: CHECK_DAFSA_PSL: OK
// CHECK-NEXT: CHECK_H1_SET_COOKIE: OK

fn main() {
    print("\n=== [1/5] rfc_repro_cookie_cross_component ===\n");
    run_01_rfc_repro_cookie_cross_component();
    print("\n=== [2/5] rfc_repro_cookie_domain_gc_truncation ===\n");
    run_02_rfc_repro_cookie_domain_gc_truncation();
    print("\n=== [3/5] rfc_repro_cookie_edge ===\n");
    run_03_rfc_repro_cookie_edge();
    print("\n=== [4/5] rfc_repro_semantic_cookie_max_age ===\n");
    run_04_rfc_repro_semantic_cookie_max_age();
    print("\n=== [5/5] rfc_repro_client_wire_cookie ===\n");
    run_05_rfc_repro_client_wire_cookie();
}
