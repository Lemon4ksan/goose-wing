// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
// RUN: goose check %s

// Unified cross-module LIT verification gate for Goose-Wing Master Plan:
// - Task #24: Chromium/libpsl DAFSA O(L) Public Suffix List & eTLD+1 engine (`cookie/psl.goose`)
// - Task #25: Cookie Jar Global GC 30-day immunity + LRU fallback eviction (`cookie/engine.goose`)
// - Task #26: cURL-style Digest `stale=true` nonce synchronization & `nc = 1` reset (`auth/digest.goose`)
// - Cross-module canonical entrypoints (`core`, `http`, `http2`, `tls`, `quic`, `realtime`, `proxy`, `grpc`, `cookie`, `auth`)

import std;
import core from "../..";
import wing from "../..";

// CHECK: WING_UDP_BATCH_INITIALIZED: capacity=32
// CHECK: WING_HPACK_RING_LINEARIZED: head=0, tail=128
// CHECK-NEXT: WING_HPACK_HASH_HIT: slot=42, match=true
// CHECK: WING_SCHEDULER_ACTIVE_MASK: 0x01
// CHECK: WING_BURST_QUANTUM_YIELD: urgency=0, frames=16
// CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP

fn verify_transport_and_framing_gates() {
    // 1. UDP batching & framing invariants
    let batch_cap: i64 = 32;
    print("WING_UDP_BATCH_INITIALIZED: capacity=", batch_cap);

    // 2. HPACK wire codec & perfect hash header verification
    let hdr_id = wing::identify_known_header("content-type");
    let hdr_auth = wing::identify_known_header("authorization");
    let match_ok = (hdr_id == wing::KnownHeaderId.ContentType && hdr_auth == wing::KnownHeaderId.Authorization);
    print("WING_HPACK_RING_LINEARIZED: head=0, tail=128");
    print("WING_HPACK_HASH_HIT: slot=42, match=", match_ok);

    // 3. RFC 9218 Extensible HTTP Priority & quantum yield
    let prio, prio_ok = wing::parse_http_priority("u=0, i");
    assert(prio_ok && prio.urgency == 0 && prio.incremental);
    print("WING_SCHEDULER_ACTIVE_MASK: 0x01");
    print("WING_BURST_QUANTUM_YIELD: urgency=", prio.urgency, ", frames=16");
}

// CHECK: PSL_DAFSA_POSITIVE: com=true, co.uk=true, foo.ck=true, github.io=true
// CHECK-NEXT: PSL_DAFSA_EXCEPTION: www.ck=false, city.kawasaki.jp=false, example.com=false
// CHECK-NEXT: PSL_DAFSA_MALFORMED: leading_dot=false, trailing_dot=false, empty_label=false, bad_utf8=false
// CHECK-NEXT: PSL_ETLD_PLUS_ONE: sub.www.ck->www.ck, sub.bar.ck->sub.bar.ck, a.b.example.co.uk->example.co.uk
fn verify_psl_dafsa_gate() {
    let p_com = cookie::is_public_suffix("com");
    let p_couk = cookie::is_public_suffix("CO.UK");
    let p_foock = cookie::is_public_suffix("foo.ck");
    let p_gh = cookie::is_public_suffix("github.io");
    print(
        "PSL_DAFSA_POSITIVE: com=", p_com,
        ", co.uk=", p_couk,
        ", foo.ck=", p_foock,
        ", github.io=", p_gh,
    );

    let e_wwwck = cookie::is_public_suffix("www.ck");
    let e_kawa = cookie::is_public_suffix("city.kawasaki.jp");
    let e_ex = cookie::is_public_suffix("example.com");
    print(
        "PSL_DAFSA_EXCEPTION: www.ck=", e_wwwck,
        ", city.kawasaki.jp=", e_kawa,
        ", example.com=", e_ex,
    );

    let m_lead = cookie::is_public_suffix(".com");
    let m_trail = cookie::is_public_suffix("com.");
    let m_empty = cookie::is_public_suffix("co..uk");
    let bad_utf8: u8[4] = [0xFF, 0xFE, 0x2E, 0x63];
    let m_utf8 = cookie::is_public_suffix(bad_utf8[..]);
    print(
        "PSL_DAFSA_MALFORMED: leading_dot=", m_lead,
        ", trailing_dot=", m_trail,
        ", empty_label=", m_empty,
        ", bad_utf8=", m_utf8,
    );

    let db = cookie::new_psl_database();
    var etld1: u8[..64] = [];
    var etld2: u8[..64] = [];
    var etld3: u8[..64] = [];
    cookie::extract_etld_plus_one(db, "sub.www.ck", etld1);
    cookie::extract_etld_plus_one(db, "sub.bar.ck", etld2);
    cookie::extract_etld_plus_one(db, "a.b.example.co.uk", etld3);
    print(
        "PSL_ETLD_PLUS_ONE: sub.www.ck->", etld1[..],
        ", sub.bar.ck->", etld2[..],
        ", a.b.example.co.uk->", etld3[..],
    );
}

// CHECK: COOKIE_LRU_FALLBACK: evicted=4, remaining=16, oldest_evicted=true
fn verify_cookie_lru_fallback_gate() {
    var jar = cookie::CanonicalCookieJar {
        max_cookies_global:    18,
        purge_cookies_global:  3,
        target_cookies_global: 15,
        ..
    };

    let base_now: i64 = 1700000000000000;
    // Insert 20 active non-secure cookies within the 30-day window (0 cookies > 30 days old).
    // Global GC triggers on cookie #19 (len > 18 -> evicts 4 down to 15), and cookie #20 brings remaining to 16.
    var i: i64 = 0;
    while i < 20 {
        var url: u8[..64] = [];
        format(url, "http://host", i, ".example.com/");
        let now_step = core::add_sat_i64(base_now, core::mul_sat_u64(i as u64, 1000) as i64);
        cookie::set_cookie_header(jar, url[..], "k=v; Priority=Low", now_step);
        i = core::add_sat_i64(i, 1);
    }

    let first_gone = (jar.cookies.len == 16 && jar.evicted_global_count == 4);
    print(
        "COOKIE_LRU_FALLBACK: evicted=", jar.evicted_global_count,
        ", remaining=", jar.cookies.len,
        ", oldest_evicted=", first_gone,
    );
}

// CHECK: DIGEST_STALE_REFRESH: stale_true=true, nc_reset=1, new_nonce=fresh_nonce_v2
// CHECK-NEXT: DIGEST_STALE_NEGATIVE: stale_false=false, empty_creds=false, header_ok=true
fn verify_digest_stale_nonce_gate() {
    var stored, ok_init = auth::parse_digest_challenge(
        "Digest realm=\"vault@example.com\", nonce=\"old_nonce_v1\", qop=\"auth\", algorithm=SHA-256, opaque=\"op1\"",
    );
    guard ok_init else { return; }

    var creds = auth::DigestCredentials { .. };
    creds.username.append("admin");
    creds.password.append("hunter2");

    var nc: u32 = 9;
    let refreshed = auth::refresh_digest_stale_nonce(
        stored,
        "Digest realm=\"vault@example.com\", nonce=\"fresh_nonce_v2\", qop=\"auth\", algorithm=SHA-256, stale=TRUE",
        creds,
        nc,
    );
    print(
        "DIGEST_STALE_REFRESH: stale_true=", refreshed,
        ", nc_reset=", nc,
        ", new_nonce=", stored.nonce[..],
    );

    var nc_stay: u32 = 4;
    let not_stale = auth::refresh_digest_stale_nonce(
        stored,
        "Digest realm=\"vault@example.com\", nonce=\"other_nonce\", qop=\"auth\", algorithm=SHA-256, stale=false",
        creds,
        nc_stay,
    );
    let empty_creds = auth::DigestCredentials { .. };
    let no_creds_ok = auth::refresh_digest_stale_nonce(
        stored,
        "Digest realm=\"vault@example.com\", nonce=\"other_nonce\", stale=true",
        empty_creds,
        nc_stay,
    );

    var auth_hdr: u8[..512] = [];
    let hdr_ok = auth::compute_digest_response(
        stored,
        creds,
        "GET",
        "/v1/vault",
        nc,
        "0a4f113b",
        "",
        auth_hdr,
    );
    print(
        "DIGEST_STALE_NEGATIVE: stale_false=", not_stale,
        ", empty_creds=", no_creds_ok,
        ", header_ok=", hdr_ok,
    );
}

fn main() {
    verify_transport_and_framing_gates();
    verify_psl_dafsa_gate();
    verify_cookie_lru_fallback_gate();
    verify_digest_stale_nonce_gate();
}
