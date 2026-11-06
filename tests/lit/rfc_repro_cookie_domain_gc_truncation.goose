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

    print("REMAINING_DOMAIN_COOKIES: ", remaining_domain_cookies, "\n");
}

// CHECK: REMAINING_DOMAIN_COOKIES: 0
