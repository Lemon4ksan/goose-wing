// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_client_wire_cookie.goose
// Regression verification for client wire parsing, cookie bridge, and cookie store defects.
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_chips_auto_partition_key() {
    var jar = wing::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    // Partitioned cookie with no explicit partition_key passed
    let ok = wing::set_cookie_header(jar, "https://auth.example.com/api", "sid=chips123; Path=/; Secure; Partitioned", now_us);
    assert(ok);
    assert(jar.cookies.len == 1);
    assert(jar.cookies[0].partitioned);
    assert(jar.cookies[0].partition_key.len > 0);
    assert(jar.cookies[0].partition_key[..] == "https://example.com");
    print("CHECK_CHIPS: OK");
}

fn test_host_cookie_roundtrip() {
    var jar1 = wing::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    let ok = wing::set_cookie_header(jar1, "https://example.com/", "__Host-auth=token999; Path=/; Secure; HttpOnly", now_us);
    assert(ok);
    assert(jar1.cookies.len == 1);

    var json_buf: u8[>..] = [];
    wing::export_json(jar1, json_buf);

    var jar2 = wing::CanonicalCookieJar { .. };
    let imported = wing::import_json(jar2, json_buf[..], now_us);
    assert(imported == 1);
    assert(jar2.cookies.len == 1);
    assert(jar2.cookies[0].name[..] == "__Host-auth");
    print("CHECK_HOST_ROUNDTRIP: OK");
}

fn test_writeback_batcher_size() {
    var batcher = wing::new_write_back_batcher(1000);
    assert(batcher.max_batch_size <= batcher.ops.cap);
    print("CHECK_BATCHER_SIZE: OK");
}

fn test_global_gc_secure_medium() {
    var jar = wing::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    // Set 3305 secure medium cookies (all accessed recently)
    for i in 3305 {
        var c = wing::CanonicalCookie { .. };
        var n_buf: u8[..64] = [];
        n_buf.append("c_");
        format(n_buf, i);
        c.name.append(n_buf[..]);
        c.value.append("val");
        c.domain.append("example.com");
        c.path.append("/");
        c.secure = true;
        c.priority = wing::CookiePriority.Medium;
        c.last_access_utc = now_us - (i * 1000);
        c.creation_utc = now_us - (i * 1000);
        c.creation_seq = i;
        jar.cookies.push(c);
    }
    assert(jar.cookies.len == 3305);
    let evicted = wing::garbage_collect_global(jar, now_us);
    assert(evicted >= 5);
    assert(jar.cookies.len <= jar.target_cookies_global);
    print("CHECK_GLOBAL_GC: OK");
}

fn test_format_cookie_header_bounds() {
    var cookies: wing::CanonicalCookie[..4] = [];
    for i in 4 {
        var c = wing::CanonicalCookie { .. };
        c.name.append("key");
        // Each cookie value is 800 bytes -> 4 * 800 > 3000 bytes
        for j in 800 { c.value.push('x'); }
        cookies.push(c);
    }
    // Destination buffer is only 2048 bytes
    var out_buf: u8[..2048] = [];
    wing::format_cookie_header_value(out_buf, cookies[..]);
    assert(out_buf.len <= out_buf.cap);
    assert(out_buf.len > 0);
    print("CHECK_COOKIE_HEADER_BOUNDS: OK");
}

fn test_dafsa_psl_cross_site() {
    assert(!wing::is_schemeful_same_site("https", "a.onrender.com", "https", "b.onrender.com"));
    assert(!wing::is_schemeful_same_site("https", "foo.github.io", "https", "bar.github.io"));
    assert(wing::is_schemeful_same_site("https", "sub1.example.com", "https", "sub2.example.com"));
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

fn main() {
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
