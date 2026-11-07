// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_cookie_domain_gc_truncation.goose
// Regression verification for domain GC candidate buffer truncation (GOOSE-BUG-2).
// When domain cookie count exceeds 180 (e.g. 175 host cookies + 6 domain cookies = 181),
// domain cookies MUST be evicted before host cookies per RFC/Chromium spec (GC-07).
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    var jar = wing::CanonicalCookieJar { .. };
    var now_us: i64 = 1700000000000000;

    // 1. Insert 175 Host-Only cookies with older access times
    for i in 175 {
        var h: u8[..64] = [];
        format(h, "host_", i, "=1; Priority=Low");
        now_us += 10;
        let ok = wing::set_cookie_header(jar, "http://example.com/", h[..], now_us);
        assert(ok);
    }

    // 2. Insert 6 Domain cookies (Domain=example.com) with newer access times
    for i in 6 {
        var h: u8[..64] = [];
        format(h, "dom_", i, "=1; Domain=example.com; Priority=Low");
        now_us += 100000000;
        let ok = wing::set_cookie_header(jar, "http://example.com/", h[..], now_us);
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
    let ts_rel1, ok_rel1 = wing::parse_cookie_date_us("Thu, 23rd-Sept-2026Z 10:18:14UTC");
    assert(ok_rel1 && ts_rel1 > 0);
    let ts_rel2, ok_rel2 = wing::parse_cookie_date_us("Wed, 09-Jun-026 10:18:14 GMT");
    assert(ok_rel2 && ts_rel2 > 0);

    // COOKIERL-02 & COOKIERL-06: ServerCookieDeltaJar, make_removal, and percent encode/decode
    var djar = wing::ServerCookieDeltaJar { .. };
    var orig_c = wing::new_canonical_cookie("sid", "old_val");
    orig_c = wing::with_value(orig_c, "old_val2");
    orig_c = wing::with_partition_key(orig_c, "https://example.com");
    orig_c = wing::with_source(orig_c, wing::CookieSourceScheme.Secure, 443);
    assert(wing::add_original(djar, orig_c));
    var add_c = wing::new_canonical_cookie("theme", "dark");
    assert(wing::add(djar, add_c));
    assert(wing::remove(djar, orig_c));
    var rem_fmt: u8[..256] = [];
    wing::format(rem_fmt, djar.cookies[0]);
    assert(core::ends_with(rem_fmt[..], "; Max-Age=0"));
    assert(wing::remove(djar, add_c));

    var enc_buf: u8[..4096] = [];
    var dec_buf: u8[..4096] = [];
    assert(wing::encode_cookie_percent("a b;c%d", enc_buf));
    assert(enc_buf[..] == "a%20b%3Bc%25d");
    assert(wing::decode_cookie_percent(enc_buf[..], dec_buf));
    assert(dec_buf[..] == "a b;c%d");

    // COOKIERL-03 & COOKIERL-04: Punycode normalization & is_known_public_suffix
    var ace_dom: u8[..256] = [];
    assert(wing::punycode_encode_domain("Example.\xE4\xB8\xAD\xE5\x9B\xBD", ace_dom));
    assert(ace_dom[..] == "example.xn--fiqs8s");
    var psl_db = wing::new_psl_database();
    wing::add_psl_rule(psl_db, "custom.tld", wing::PslRuleType.Normal, wing::PslSection.Icann);
    assert(wing::is_known_public_suffix(psl_db, "custom.tld"));
    assert(wing::is_known_public_suffix(psl_db, "co.uk"));
    assert(!wing::is_known_public_suffix(psl_db, "intranet"));

    print("REMAINING_DOMAIN_COOKIES: ", remaining_domain_cookies, "\n");
}

// CHECK: REMAINING_DOMAIN_COOKIES: 0
