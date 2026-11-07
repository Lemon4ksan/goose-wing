// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_cookie_cross_component.goose
// Regression verification for cross-component cookie boundaries and RFC 6265 / 6265bis edge cases (F001-F007).
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// F001: Cross-component IPv6 bracket handling across core::Url, SiteForCookies, trustworthy localhost, and Session cookie bridge.
fn test_f001_ipv6_bracket_cross_component() {
    let now_us: i64 = 1700000000000000;
    let u_v6 = core::new_url("http://[::1]:8080/api/v1/login");
    let sfc = wing::site_for_cookies_from_parsed_url(u_v6);
    assert(wing::is_first_party(sfc, "http://[::1]:8080/api/v1/login", true));
    assert(wing::is_trustworthy_non_crypto_host(core::hostname(u_v6)));

    var session = wing::new_session();
    session.virtual_clock_us = now_us;
    var ctx = wing::RequestExecutionContext {
        site_for_cookies: sfc,
        is_main_frame:    true,
        ..
    };
    let ss_eval = wing::compute_hop_samesite_context(ctx, u_v6, true);
    assert(ss_eval.context_type == wing::SameSiteContextType.SameSiteStrict);

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
    let sfc_a = wing::site_for_cookies_from_parsed_url(u_a);
    let r_info = wing::compute_redirect_info(
        302, "GET", u_a, "https://tenant-b.onrender.com/finish", "",
        wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "", sfc_a,
        wing::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT, chain[..], orig_a,
        wing::RedirectOptions { has_initiator: true, is_main_frame: true, .. },
    );
    assert(r_info.is_cross_site_tainted);
    assert(wing::is_first_party(r_info.new_site_for_cookies, "https://tenant-b.onrender.com/finish", true));
    print("F002_PSL_REDIRECT_ISOLATION: OK");
}

// F003: Cross-component SameSite navigation context & can_set_canonical_cookie_for_context.
fn test_f003_samesite_context_and_set_guard() {
    let now_us: i64 = 1700000000000000;
    let c_strict, _, ok_s = wing::parse_canonical_set_cookie("s=1; SameSite=Strict; Secure; Path=/", "bank.com", "/", now_us);
    assert(ok_s);
    let cross_ctx = wing::SameSiteCookieContext {
        context_type:       wing::SameSiteContextType.CrossSite,
        schemefully_same:   false,
        is_reload:          false,
        had_cross_site_hop: true,
    };
    let can_set_cross_main, _ = wing::can_set_canonical_cookie_for_context(
        c_strict, cross_ctx, wing::CookieInclusionOptions { is_main_frame: true, is_secure_channel: true },
    );
    assert(!can_set_cross_main);

    var jar = wing::CanonicalCookieJar { .. };
    assert(wing::set_cookie_header(jar, "https://bank.com/", "lax_sid=secret2; SameSite=Lax; Secure; Path=/", now_us));
    let u_bank = core::new_url("https://bank.com/dashboard");
    var hdrs = wing::HeaderMap { .. };
    let _ = wing::stage_client_cookie_load(hdrs, u_bank, cross_ctx, true, "", true, now_us, jar, true);
    assert(!core::contains(wing::find_header(hdrs, "Cookie"), "lax_sid=secret2"));

    let u_evil = core::new_url("https://evil.com/");
    let ctx_nav = wing::RequestExecutionContext {
        initiator:          core::origin_from_url(u_evil),
        has_initiator:      true,
        site_for_cookies:   wing::site_for_cookies_from_url("https://bank.com/"),
        first_party_policy: wing::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
        is_main_frame:      true,
        ..
    };
    let nav_eval = wing::compute_hop_samesite_context(ctx_nav, u_bank, true);
    assert(nav_eval.context_type == wing::SameSiteContextType.SameSiteLax);

    let ctx_null_sfc = wing::RequestExecutionContext {
        is_main_frame:      true,
        had_cross_site_hop: true,
        site_for_cookies:   wing::null_site_for_cookies(),
        ..
    };
    let null_eval = wing::compute_hop_samesite_context(ctx_null_sfc, u_bank, true);
    assert(null_eval.context_type == wing::SameSiteContextType.CrossSite);
    print("F003_SAMESITE_CONTEXT_BOUNDARY: OK");
}

// F004: Domain attribute >256B rejection and multiple Domain attribute last-wins reset (RFC 6265 §5.3 Step 4/6).
fn test_f004_domain_attribute_edge_cases() {
    let now_us: i64 = 1700000000000000;
    var big_dom_hdr: u8[..400] = [];
    big_dom_hdr.append("sid=1; Domain=sub.");
    for i in 260 { big_dom_hdr.push('a'); }
    big_dom_hdr.append(".evil.com");
    let _, _, ok_big_dom = wing::parse_canonical_set_cookie(big_dom_hdr[..], "example.com", "/", now_us);
    assert(!ok_big_dom);

    // Earlier valid Domain=example.com followed by empty Domain= must reset to host-only on sub.example.com
    let c_multi, _, ok_multi = wing::parse_canonical_set_cookie(
        "sid=2; Domain=example.com; Domain=", "sub.example.com", "/", now_us,
    );
    assert(ok_multi && c_multi.host_only && c_multi.domain[..] == "sub.example.com");
    print("F004_DOMAIN_ATTR_EDGE: OK");
}

// F005: Long request URL paths (>256B) in compute_default_cookie_path, parse_canonical_cookie_url, and partition_key bounds.
fn test_f005_long_url_path_and_partition_bounds() {
    let now_us: i64 = 1700000000000000;
    var long_url: u8[..600] = [];
    long_url.append("https://example.com/api/");
    for i in 280 { long_url.push('p'); }
    long_url.append("/leaf");

    var def_path: u8[..256] = [];
    let u_parsed = core::new_url(long_url[..]);
    wing::compute_default_cookie_path(core::pathname(u_parsed), def_path);
    assert(def_path[..] == "/api");

    var jar = wing::CanonicalCookieJar { .. };
    assert(wing::set_cookie_header(jar, long_url[..], "k_long=v_long; Path=/api", now_us));
    assert(wing::get(jar, long_url[..], "k_long", now_us) == "v_long");

    var huge_part: u8[..300] = [];
    for i in 280 { huge_part.push('k'); }
    assert(!wing::set_cookie_header(jar, "https://example.com/", "p=1; Secure; Partitioned", now_us, huge_part[..]));
    print("F005_LONG_PATH_AND_BOUNDS: OK");
}

// F006: import_json timestamp preservation, Netscape .domain collision/deletion, and JSON/security validation.
fn test_f006_store_lifecycle_and_netscape_collision() {
    let t1: i64 = 1700000000000000;
    let t2: i64 = t1 + 500000000;
    var jar1 = wing::CanonicalCookieJar { .. };
    assert(wing::set_cookie_header(jar1, "https://example.com/", "c_old=1; Secure; Path=/", t1));
    var json_buf: u8[>..] = [];
    wing::export_json(jar1, json_buf);

    var jar2 = wing::CanonicalCookieJar { .. };
    assert(wing::import_json(jar2, json_buf[..], t2) == 1);
    assert(jar2.cookies[0].creation_utc == t1);

    // Netscape imported .example.com cookie must be overwritten/deleted by Set-Cookie on Domain=.example.com
    var jar_ns = wing::CanonicalCookieJar { .. };
    assert(wing::import_netscape(jar_ns, ".example.com\tTRUE\t/\tTRUE\t2147483647\tauth_token\told_val\n", t1) == 1);
    assert(wing::set_cookie_header(jar_ns, "https://app.example.com/", "auth_token=new_val; Domain=.example.com; Path=/; Secure", t2));
    assert(jar_ns.cookies.len == 1 && jar_ns.cookies[0].value[..] == "new_val");

    var del_filter = wing::CookieDeletionInfo { .. };
    del_filter.domain.append("example.com");
    assert(wing::delete_matching(jar_ns, del_filter) == 1);
    print("F006_STORE_LIFECYCLE_AND_NETSCAPE: OK");
}

// F007: RFC 6265 §5.1.1 cookie-date hms-time trailing non-digits ('10:18:14GMT') and invalid day-of-month ('32 Jan 25').
fn test_f007_rfc6265_cookie_date_edge_cases() {
    let _, ok_gmt_suffix = wing::parse_cookie_date_us("Wed, 09 Jun 2021 10:18:14GMT");
    assert(ok_gmt_suffix);
    let _, ok_three_digit_hr = wing::parse_cookie_date_us("Wed, 09 Jun 2021 010:18:14 GMT");
    assert(!ok_three_digit_hr);
    let _, ok_bad_dom_2yr = wing::parse_cookie_date_us("32 Jan 25 00:00:00 GMT");
    assert(!ok_bad_dom_2yr);
    print("F007_RFC6265_COOKIE_DATE: OK");
}

fn main() {
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
