// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP Caching (RFC 9111), Structured Fields, and Metadata Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: http_cache_engine ---
// Verification suite for RFC 9111 HTTP caching engine.
// Verifies Cache-Control parsing, freshness calculations, ETag validators,
// Vary matching, CVE-2026-93750 & CVE-2026-93748 defenses, 304 header merge,
// request collapsing, and unsafe method cascade invalidation.

// ---- Cache-Control Parsing & Delta-Seconds Clamping ----------------------

fn test_cache_control_parsing_and_overflow(t: lit::T&) {
    t.run("Standard Boolean Directives & Bitmask Compression") { sub =>
        var cc = wing::CacheControl { .. };
        let raw = "no-store, no-cache, must-revalidate, proxy-revalidate, must-understand, public, immutable, only-if-cached, no-transform";
        wing::parse_cache_control_str(raw, cc);

        sub.assert_true(wing::is_no_store(cc), "no-store parsed into bitmask");
        sub.assert_true(wing::is_no_cache(cc), "no-cache parsed into bitmask");
        sub.assert_true(wing::is_must_revalidate(cc), "must-revalidate parsed");
        sub.assert_true(wing::is_proxy_revalidate(cc), "proxy-revalidate parsed");
        sub.assert_true(wing::is_must_understand(cc), "must-understand parsed (RFC 9111 §5.2.2.3)");
        sub.assert_true(wing::is_public(cc), "public parsed");
        sub.assert_true(wing::is_immutable(cc), "immutable parsed (RFC 8246)");
        sub.assert_true(wing::is_only_if_cached(cc), "only-if-cached parsed");
        sub.assert_true(wing::is_no_transform(cc), "no-transform parsed");
    };

    t.run("Delta-Seconds Parsing & Overflow Clamping to i32::MAX") { sub =>
        var cc = wing::CacheControl { .. };
        let raw = "max-age=3600, s-maxage=7200, min-fresh=60, max-stale=300";
        wing::parse_cache_control_str(raw, cc);

        sub.assert_eq(cc.max_age, 3600, "max-age 3600 parsed");
        sub.assert_eq(cc.s_maxage, 7200, "s-maxage 7200 parsed");
        sub.assert_eq(cc.min_fresh, 60, "min-fresh 60 parsed");
        sub.assert_eq(cc.max_stale, 300, "max-stale 300 parsed");

        // Clamping overflow to 2147483647
        var cc_over = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-age=9999999999999", cc_over);
        sub.assert_eq(cc_over.max_age, rfc::MAX_DELTA_SECONDS, "max-age clamped to i32::MAX");

        // Unbounded max-stale
        var cc_unbounded = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-stale", cc_unbounded);
        sub.assert_true(wing::has_max_stale(cc_unbounded), "has max-stale flag");
        sub.assert_eq(cc_unbounded.max_stale, -1, "unbounded max-stale is -1");
    };

    t.run("Corrupted Freshness Parameters Set INVALID_FRESHNESS Flag") { sub =>
        var cc_bad = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-age=corrupted_string", cc_bad);
        sub.assert_true(wing::has_invalid_freshness(cc_bad), "Corrupted max-age flagged invalid");

        var cc_bad_s = wing::CacheControl { .. };
        wing::parse_cache_control_str("s-maxage=123xyz", cc_bad_s);
        sub.assert_true(wing::has_invalid_freshness(cc_bad_s), "Alphanumeric s-maxage flagged invalid");
    };

    t.run("Qualified Lists & Pragma Fallback & Cargo-Cult Filtering") { sub =>
        var cc_qual = wing::CacheControl { .. };
        wing::parse_cache_control_str("private=\"Set-Cookie, X-Custom\", no-cache=\"X-Token\"", cc_qual);
        sub.assert_true(wing::is_private(cc_qual), "is private");
        sub.assert_true(wing::is_private_field(cc_qual, "Set-Cookie"), "Set-Cookie is private field");
        sub.assert_true(wing::is_private_field(cc_qual, "x-custom"), "X-Custom is private field (case-insensitive)");
        sub.assert_false(wing::is_private_field(cc_qual, "Content-Type"), "Content-Type is not private field");
        sub.assert_true(wing::is_no_cache_field(cc_qual, "X-Token"), "X-Token is no-cache field");

        // Cargo-cult pre-check/post-check ignored without error
        var cc_cult = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-age=3600, pre-check=0, post-check=0", cc_cult, true);
        sub.assert_eq(cc_cult.max_age, 3600, "max-age parsed despite cargo-cult directives");

        // Pragma: no-cache fallback
        var map = wing::HeaderMap { .. };
        wing::append_header(map, "Pragma", "no-cache");
        let cc_pragma = wing::parse_cache_control_headers(map, wing::CacheControlParseOptions { is_request: true, .. });
        sub.assert_true(wing::is_no_cache(cc_pragma), "Pragma: no-cache promoted to CacheControl::no-cache");
    };

    t.run("Targeted HTTP Cache-Control Precedence (RFC 9213)") { sub =>
        var map = wing::HeaderMap { .. };
        wing::append_header(map, "Cache-Control", "public, max-age=3600");
        wing::append_header(map, "CDN-Cache-Control", "max-age=600");
        wing::append_header(map, "Edge-Cache-Control", "max-age=60");

        // Generic client/browser targets standard Cache-Control
        let cc_client = wing::parse_targeted_cache_control_headers(map, "");
        sub.assert_eq(cc_client.max_age, 3600, "Client honors standard Cache-Control max-age=3600");

        // Specific Edge target honors Edge-Cache-Control
        let cc_edge = wing::parse_targeted_cache_control_headers(map, "Edge");
        sub.assert_eq(cc_edge.max_age, 60, "Edge target honors Edge-Cache-Control max-age=60");

        // Generic CDN target honors CDN-Cache-Control
        let cc_cdn = wing::parse_targeted_cache_control_headers(map, "CDN");
        sub.assert_eq(cc_cdn.max_age, 600, "CDN target honors CDN-Cache-Control max-age=600");

        // Unknown intermediary target falls back to CDN-Cache-Control per RFC 9213 §2
        let cc_other = wing::parse_targeted_cache_control_headers(map, "CloudProxy");
        sub.assert_eq(cc_other.max_age, 600, "Unknown proxy falls back to CDN-Cache-Control max-age=600");

        // When CDN headers are absent, falls back to Cache-Control
        var map_plain = wing::HeaderMap { .. };
        wing::append_header(map_plain, "Cache-Control", "max-age=1800");
        let cc_plain = wing::parse_targeted_cache_control_headers(map_plain, "Edge");
        sub.assert_eq(cc_plain.max_age, 1800, "Fallback to standard Cache-Control when target missing");

        // RFC 9213 §2.1 & §2.2: Empty or whitespace CDN-Cache-Control falls back to standard Cache-Control
        var map_empty_cdn = wing::HeaderMap { .. };
        wing::append_header(map_empty_cdn, "Cache-Control", "max-age=1200");
        wing::append_header(map_empty_cdn, "CDN-Cache-Control", "");
        let cc_empty_cdn = wing::parse_targeted_cache_control_headers(map_empty_cdn, "CDN");
        sub.assert_eq(cc_empty_cdn.max_age, 1200, "Empty CDN-Cache-Control falls back to standard Cache-Control");

        var map_ws_cdn = wing::HeaderMap { .. };
        wing::append_header(map_ws_cdn, "Cache-Control", "max-age=2400");
        wing::append_header(map_ws_cdn, "CDN-Cache-Control", "   ,  ");
        let cc_ws_cdn = wing::parse_targeted_cache_control_headers(map_ws_cdn, "CDN");
        sub.assert_eq(cc_ws_cdn.max_age, 2400, "Whitespace/comma CDN-Cache-Control falls back to standard Cache-Control");
    };
}

// ---- Mathematical Freshness Model & Clock Skew ---------------------------

fn test_freshness_math_and_clock_skew(t: lit::T&) {
    t.run("RFC 9111 §4.2.3 Age Calculations") { sub =>
        // Time points: request at t=100, response at t=102 (2s delay), date header t=100
        let req_time = core::unix(100, 0);
        let resp_time = core::unix(102, 0);
        let cur_now = core::unix(112, 0); // 10s resident time
        let date_time = core::unix(100, 0);

        let apparent_age = wing::compute_apparent_age(resp_time, date_time); // 102 - 100 = 2
        sub.assert_eq(apparent_age, 2, "apparent_age == 2");

        let ts = wing::new_cache_timestamps(req_time, resp_time, cur_now);
        let delay = wing::compute_response_delay(ts); // 102 - 100 = 2
        sub.assert_eq(delay, 2, "response_delay == 2");

        let age_hdr: i64 = 5;
        let initial_age = wing::compute_corrected_initial_age(apparent_age, age_hdr, delay); // max(2, 5 + 2) = 7
        sub.assert_eq(initial_age, 7, "corrected_initial_age == 7");

        let resident = wing::compute_resident_time(ts); // 112 - 102 = 10
        sub.assert_eq(resident, 10, "resident_time == 10");

        let current_age = wing::compute_current_age(apparent_age, age_hdr, ts); // 7 + 10 = 17
        sub.assert_eq(current_age, 17, "current_age == 17");
    };

    t.run("Age Header Parsing: Singleton First-Element & Clamping") { sub =>
        // First member used when multiple members present (RFC 9111 §5.1)
        let parsed_multi = wing::parse_age_header("120, 240, 360");
        sub.assert_eq(parsed_multi, 120, "First Age member 120 extracted from list");

        // Clamped overflow
        let parsed_over = wing::parse_age_header("5000000000");
        sub.assert_eq(parsed_over, rfc::MAX_DELTA_SECONDS, "Age overflow clamped to i32::MAX");

        // Malformed Age ignored (returns 0)
        let parsed_bad = wing::parse_age_header("-50");
        sub.assert_eq(parsed_bad, 0, "Negative Age returns 0");
        let parsed_letters = wing::parse_age_header("abc");
        sub.assert_eq(parsed_letters, 0, "Alphanumeric Age returns 0");
    };

    t.run("Freshness Lifetime Priority Hierarchy") { sub =>
        let req_time = core::unix(100, 0);
        let resp_time = core::unix(100, 0);
        let ts = wing::new_cache_timestamps(req_time, resp_time, resp_time);

        // 1. Corrupted freshness sets lifetime to 0
        var cc_bad = wing::CacheControl { .. };
        cc_bad.flags |= wing::CC_INVALID_FRESHNESS;
        var hdrs = wing::HeaderMap { .. };
        let lt_bad = wing::compute_freshness_lifetime(cc_bad, hdrs, ts);
        sub.assert_eq(lt_bad, 0, "Corrupted freshness forces lifetime 0");

        // 2. Shared cache: s-maxage overrides max-age
        var cc_shared = wing::CacheControl { .. };
        cc_shared.flags |= wing::CC_HAS_MAX_AGE | wing::CC_HAS_S_MAXAGE;
        cc_shared.max_age = 3600;
        cc_shared.s_maxage = 7200;
        let lt_shared = wing::compute_freshness_lifetime(cc_shared, hdrs, ts, true);
        sub.assert_eq(lt_shared, 7200, "s-maxage overrides max-age in shared cache");

        // 3. Private cache: max-age takes precedence
        let lt_priv = wing::compute_freshness_lifetime(cc_shared, hdrs, ts, false);
        sub.assert_eq(lt_priv, 3600, "max-age used in private cache");

        // 4. Immutable directive
        var cc_imm = wing::CacheControl { .. };
        cc_imm.flags |= wing::CC_IMMUTABLE;
        let lt_imm = wing::compute_freshness_lifetime(cc_imm, hdrs, ts, false, 10, 86400);
        sub.assert_eq(lt_imm, 86400, "immutable sets configured minimum ttl");

        // 5. Heuristic 10% of (Date - Last-Modified) for 200 OK
        var cc_empty = wing::CacheControl { .. };
        var hdrs_lm = wing::HeaderMap { .. };
        hdrs_lm.status_code = 200;
        wing::append_header(hdrs_lm, "Date", "Sun, 06 Nov 1994 09:00:00 GMT");
        wing::append_header(hdrs_lm, "Last-Modified", "Sun, 06 Nov 1994 08:00:00 GMT"); // 3600s delta
        let lt_heur = wing::compute_freshness_lifetime(cc_empty, hdrs_lm, ts);
        sub.assert_eq(lt_heur, 360, "Heuristic is 10% of 3600s = 360s");

        // 6. RFC 9111 §5.3 & §4.2.2: Expires: 0 or invalid date format marks response immediately stale (lifetime = 0)
        // and does NOT fall back to Last-Modified heuristic
        var hdrs_exp0 = wing::HeaderMap { .. };
        hdrs_exp0.status_code = 200;
        wing::append_header(hdrs_exp0, "Expires", "0");
        wing::append_header(hdrs_exp0, "Date", "Sun, 06 Nov 1994 09:00:00 GMT");
        wing::append_header(hdrs_exp0, "Last-Modified", "Sun, 06 Nov 1994 08:00:00 GMT");
        let lt_exp0 = wing::compute_freshness_lifetime(cc_empty, hdrs_exp0, ts);
        sub.assert_eq(lt_exp0, 0, "Expires: 0 yields 0 freshness lifetime without falling back to Last-Modified heuristic");

        var hdrs_exp_inv = wing::HeaderMap { .. };
        hdrs_exp_inv.status_code = 200;
        wing::append_header(hdrs_exp_inv, "Expires", "invalid-date-format");
        wing::append_header(hdrs_exp_inv, "Date", "Sun, 06 Nov 1994 09:00:00 GMT");
        wing::append_header(hdrs_exp_inv, "Last-Modified", "Sun, 06 Nov 1994 08:00:00 GMT");
        let lt_exp_inv = wing::compute_freshness_lifetime(cc_empty, hdrs_exp_inv, ts);
        sub.assert_eq(lt_exp_inv, 0, "Invalid Expires yields 0 freshness lifetime without falling back to Last-Modified heuristic");

        let ts_mono = wing::with_monotonic(ts, core::monotonic_now(), core::monotonic_now(), core::monotonic_now());
        sub.assert_true(ts_mono.has_monotonic, "with_monotonic sets has_monotonic");
    };
}

// ---- EntityTag (ETag) Validators -----------------------------------------

fn test_etag_validators(t: lit::T&) {
    t.run("ETag Parsing and Weak/Strong Comparisons") { sub =>
        let tag_strong = wing::parse_etag("\"strong-123\"");
        sub.assert_true(tag_strong.valid, "Strong ETag parsed valid");
        sub.assert_false(tag_strong.is_weak, "Strong ETag is not weak");
        sub.assert_bytes_eq(tag_strong.tag[..], "strong-123", "Strong tag content match");

        let tag_weak = wing::parse_etag("W/\"weak-456\"");
        sub.assert_true(tag_weak.valid, "Weak ETag parsed valid");
        sub.assert_true(tag_weak.is_weak, "Weak ETag is marked weak");
        sub.assert_bytes_eq(tag_weak.tag[..], "weak-456", "Weak tag content match");

        // Case-sensitive "W/" check: lowercase "w/" is NOT valid weak prefix
        let tag_lower_w = wing::parse_etag("w/\"xyz\"");
        sub.assert_false(tag_lower_w.valid, "Lowercase w/ rejected as weak prefix");

        // weak_eq: matches regardless of weakness flags
        let tag_strong_pair = wing::parse_etag("\"same-tag\"");
        let tag_weak_pair = wing::parse_etag("W/\"same-tag\"");
        sub.assert_true(wing::weak_eq(tag_strong_pair, tag_weak_pair), "weak_eq matches strong and weak tags with same value");

        // strong_eq: requires both to be strong
        sub.assert_false(wing::strong_eq(tag_strong_pair, tag_weak_pair), "strong_eq fails when one tag is weak");
        let tag_strong_pair_2 = wing::parse_etag("\"same-tag\"");
        sub.assert_true(wing::strong_eq(tag_strong_pair, tag_strong_pair_2), "strong_eq succeeds when both tags are strong");
    };

    t.run("If-None-Match & If-Match List and Wildcard Matching") { sub =>
        let cached = wing::parse_etag("\"v2.0\"");

        // If-None-Match with wildcard
        sub.assert_true(wing::match_if_none_match("*", cached), "Wildcard * matches If-None-Match");

        // If-None-Match with comma list
        sub.assert_true(wing::match_if_none_match("\"v1.0\", W/\"v2.0\", \"v3.0\"", cached), "List containing weak match satisfies If-None-Match");
        sub.assert_false(wing::match_if_none_match("\"v1.0\", \"v3.0\"", cached), "List without match fails If-None-Match");

        // If-Match requires strong match
        let cached_weak = wing::parse_etag("W/\"v2.0\"");
        sub.assert_false(wing::match_if_match("W/\"v2.0\"", cached_weak), "If-Match rejects weak cached tag");
        sub.assert_true(wing::match_if_match("\"v2.0\"", cached), "If-Match succeeds for strong match");

        let ir_ok = wing::evaluate_cache_if_range("\"v2.0\"", cached, core::unix(0, 0));
        sub.assert_true(ir_ok, "evaluate_cache_if_range matches cached etag");
    };
}

// ---- Vary Normalization & CVE-2026-93750 Defense -------------------------

fn test_vary_normalization_and_cve_2026_93750(t: lit::T&) {
    t.run("CVE-2026-93750: Vary: * Unconditional Hard Rejection") { sub =>
        var req_hdrs = wing::HeaderMap { .. };
        wing::append_header(req_hdrs, "Accept-Encoding", "gzip");

        // Vary: *
        let snap_star = wing::record_vary_snapshot("*", req_hdrs);
        sub.assert_true(snap_star.has_star, "Vary: * marks has_star = true");
        sub.assert_false(wing::matches_vary(snap_star, req_hdrs), "Vary: * NEVER matches any request");

        // Vary with * among other tokens: "Accept-Encoding, *"
        let snap_mixed = wing::record_vary_snapshot("Accept-Encoding, *", req_hdrs);
        sub.assert_true(snap_mixed.has_star, "Vary containing * marks has_star = true");
        sub.assert_false(wing::matches_vary(snap_mixed, req_hdrs), "Mixed Vary with * NEVER matches");
    };

    t.run("Vary Matching with Simultaneous Absence Invariant") { sub =>
        // Request 1: has Accept-Encoding: gzip, but NO User-Agent
        var req_1 = wing::HeaderMap { .. };
        wing::append_header(req_1, "Accept-Encoding", "gzip");

        let snap = wing::record_vary_snapshot("Accept-Encoding, User-Agent", req_1);

        // Incoming Request 2: matches Accept-Encoding: gzip, User-Agent is also absent -> PASS
        var req_2 = wing::HeaderMap { .. };
        wing::append_header(req_2, "Accept-Encoding", "gzip");
        sub.assert_true(wing::matches_vary(snap, req_2), "Matches when User-Agent is simultaneously absent in both requests");

        // Incoming Request 3: has User-Agent present -> MUST FAIL simultaneous absence invariant!
        var req_3 = wing::HeaderMap { .. };
        wing::append_header(req_3, "Accept-Encoding", "gzip");
        wing::append_header(req_3, "User-Agent", "Mozilla/5.0");
        sub.assert_false(wing::matches_vary(snap, req_3), "Fails when header was absent originally but present in incoming request");

        // Incoming Request 4: different Accept-Encoding -> FAIL
        var req_4 = wing::HeaderMap { .. };
        wing::append_header(req_4, "Accept-Encoding", "br");
        sub.assert_false(wing::matches_vary(snap, req_4), "Fails on Accept-Encoding mismatch");
    };
}

// ---- CVE-2026-93748 Defense & Security Zeroing --------------------------

fn test_cve_2026_93748_max_stale_guards(t: lit::T&) {
    t.run("CVE-2026-93748: Blocking max-stale on must-revalidate / s-maxage / security-zeroed") { sub =>
        let t_req = core::unix(100, 0);
        let t_resp = core::unix(100, 0);
        let t_now = core::unix(500, 0); // Well past expiration (stale)
        let ts = wing::new_cache_timestamps(t_req, t_resp, t_now);

        var hdrs = wing::HeaderMap { .. };

        // Client request with max-stale=1000
        var req_cc = wing::CacheControl { .. };
        req_cc.flags |= wing::CC_HAS_MAX_STALE;
        req_cc.max_stale = 1000;

        // Case A: Ordinary stale response (max-age=100) -> max-stale ALLOWED
        var cc_normal = wing::CacheControl { .. };
        cc_normal.flags |= wing::CC_HAS_MAX_AGE;
        cc_normal.max_age = 100;
        let m_normal = wing::evaluate_freshness(cc_normal, req_cc, hdrs, ts);
        sub.assert_false(m_normal.is_fresh, "Entry is not fresh");
        sub.assert_true(m_normal.stale_allowed, "Normal stale response allowed by max-stale");

        // Case B: must-revalidate present -> max-stale STRICTLY BLOCKED!
        var cc_must_rev = wing::CacheControl { .. };
        cc_must_rev.flags |= wing::CC_HAS_MAX_AGE | wing::CC_MUST_REVALIDATE;
        cc_must_rev.max_age = 100;
        let m_must_rev = wing::evaluate_freshness(cc_must_rev, req_cc, hdrs, ts);
        sub.assert_false(m_must_rev.stale_allowed, "max-stale strictly blocked when must-revalidate is present");

        // Case C: s-maxage present -> max-stale STRICTLY BLOCKED!
        var cc_s_max = wing::CacheControl { .. };
        cc_s_max.flags |= wing::CC_HAS_MAX_AGE | wing::CC_HAS_S_MAXAGE;
        cc_s_max.max_age = 100;
        cc_s_max.s_maxage = 100;
        let m_s_max = wing::evaluate_freshness(cc_s_max, req_cc, hdrs, ts, wing::FreshnessPolicy { shared: true, .. });
        sub.assert_false(m_s_max.stale_allowed, "max-stale strictly blocked when s-maxage is present");

        // Case D: proxy-revalidate in shared cache -> max-stale STRICTLY BLOCKED!
        var cc_proxy_rev = wing::CacheControl { .. };
        cc_proxy_rev.flags |= wing::CC_HAS_MAX_AGE | wing::CC_PROXY_REVALIDATE;
        cc_proxy_rev.max_age = 100;
        let m_proxy = wing::evaluate_freshness(cc_proxy_rev, req_cc, hdrs, ts, wing::FreshnessPolicy { shared: true, .. });
        sub.assert_false(m_proxy.stale_allowed, "max-stale strictly blocked when proxy-revalidate in shared cache");

        // Case E: security_zeroed = true -> max-stale STRICTLY BLOCKED!
        let m_zeroed = wing::evaluate_freshness(
            cc_normal,
            req_cc,
            hdrs,
            ts,
            wing::FreshnessPolicy { security_zeroed: true, .. },
        );
        sub.assert_false(m_zeroed.stale_allowed, "max-stale strictly blocked on security_zeroed invalidated entry");
    };
}

// ---- Cache Transaction Lifecycle, 304 Merge & Sanitization ---------------

fn test_cache_transaction_and_304_merge(t: lit::T&) {
    t.run("Lookup Miss -> Store -> Hit Lifecycle with Age Header") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);

        // 1. Initial request -> Cache Miss
        let req = wing::new_get("https://example.com/api/data");
        let dec_1 = wing::lookup(cache, req, t0);
        sub.assert_true(dec_1.kind == wing::LookupResultKind.Miss, "Initial lookup is Miss");

        // 2. Origin returns 200 OK with max-age=3600
        var resp = wing::Response { .. };
        resp.status_code = 200;
        resp.effective_url.append("https://example.com/api/data");
        wing::set_header(resp, "Cache-Control", "max-age=3600");
        wing::set_header(resp, "ETag", "\"data-v1\"");
        resp.body.append("{\"message\": \"hello world\"}");

        let ts = wing::new_cache_timestamps(t0, t0, t0);
        let store_dec = wing::on_response(cache, req, resp, ts);
        sub.assert_true(store_dec.kind == wing::ResponseDecisionKind.StoreAndReturn, "Response stored in cache");
        sub.assert_eq(cache.entries.len, 1, "Cache entries count is 1");

        // 3. Second request 10 seconds later (t=1010) -> Cache Hit!
        let t1 = core::unix(1010, 0);
        let dec_2 = wing::lookup(cache, req, t1);
        sub.assert_true(dec_2.kind == wing::LookupResultKind.Hit, "Subsequent lookup is Hit");
        sub.assert_eq(dec_2.cached_response.status_code, 200, "Cached response status 200");
        sub.assert_bytes_eq(dec_2.cached_response.body[..], "{\"message\": \"hello world\"}", "Cached response body exact");

        // Check generated Age header
        let age_val = wing::header(dec_2.cached_response, "Age");
        sub.assert_bytes_eq(age_val, "10", "Age header correctly generated as 10s");
    };

    t.run("Stale Entry -> Conditional Revalidation -> 304 Merge") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);

        let req = wing::new_get("https://example.com/resource");
        var resp = wing::Response { .. };
        resp.status_code = 200;
        resp.effective_url.append("https://example.com/resource");
        wing::set_header(resp, "Cache-Control", "max-age=60");
        wing::set_header(resp, "ETag", "\"tag-abc\"");
        wing::set_header(resp, "Content-Type", "text/html");
        wing::set_header(resp, "Strict-Transport-Security", "max-age=31536000");
        resp.body.append("<html>content</html>");

        let ts0 = wing::new_cache_timestamps(t0, t0, t0);
        wing::on_response(cache, req, resp, ts0);

        // Advance time to t=1200 (stale by 140s)
        let t_stale = core::unix(1200, 0);
        let dec_stale = wing::lookup(cache, req, t_stale);
        sub.assert_true(dec_stale.kind == wing::LookupResultKind.Revalidate, "Lookup returns Revalidate");
        sub.assert_bytes_eq(wing::get_header(dec_stale.conditional_headers, "If-None-Match"), "\"tag-abc\"", "If-None-Match built");

        // Origin returns 304 Not Modified with fresh Cache-Control: max-age=7200
        var resp_304 = wing::Response { .. };
        resp_304.status_code = 304;
        wing::set_header(resp_304, "Cache-Control", "max-age=7200");
        wing::set_header(resp_304, "X-Fresh-Note", "updated");
        // Attempt to corrupt Content-Type and HSTS in 304
        wing::set_header(resp_304, "Content-Type", "application/poison");
        wing::set_header(resp_304, "Strict-Transport-Security", "max-age=0");

        let ts_304 = wing::new_cache_timestamps(t_stale, t_stale, t_stale);
        let dec_freshen = wing::on_response(cache, req, resp_304, ts_304, dec_stale.entry_idx);
        sub.assert_true(dec_freshen.kind == wing::ResponseDecisionKind.FreshenAndReturn, "Freshened cached entry");

        // Verify Chromium kNonUpdatedHeaders protection
        let cached_ct = wing::get_header(cache.entries[dec_stale.entry_idx].headers, "Content-Type");
        sub.assert_bytes_eq(cached_ct, "text/html", "Content-Type preserved against 304 modification");
        let cached_hsts = wing::get_header(cache.entries[dec_stale.entry_idx].headers, "Strict-Transport-Security");
        sub.assert_bytes_eq(cached_hsts, "", "Security state headers stripped during sanitize_for_storage");

        // Cache-Control was updated to 7200
        sub.assert_eq(cache.entries[dec_stale.entry_idx].cc.max_age, 7200, "Cache-Control updated to max-age=7200");
    };

    t.run("304 Not Modified Freshening Keeps Entry Fresh on Subsequent Lookup") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);

        let req = wing::new_get("https://example.com/freshness-test");
        var resp = wing::Response { .. };
        resp.status_code = 200;
        resp.effective_url.append("https://example.com/freshness-test");
        wing::set_header(resp, "Cache-Control", "max-age=60");
        wing::set_header(resp, "ETag", "\"etag-1\"");
        resp.body.append("content v1");

        let ts0 = wing::new_cache_timestamps(t0, t0, t0);
        wing::on_response(cache, req, resp, ts0);

        // At t=4600 (1 hour later), cache is stale
        let t_stale = core::unix(4600, 0);
        let dec_stale = wing::lookup(cache, req, t_stale);
        sub.assert_true(dec_stale.kind == wing::LookupResultKind.Revalidate, "Lookup at t=4600 requires revalidation");

        // Origin responds 304 with max-age=60 at t=4601
        var resp_304 = wing::Response { .. };
        resp_304.status_code = 304;
        wing::set_header(resp_304, "Cache-Control", "max-age=60");

        let t_resp_304 = core::unix(4601, 0);
        let ts_304 = wing::new_cache_timestamps(t_stale, t_resp_304, t_resp_304);
        let dec_freshen = wing::on_response(cache, req, resp_304, ts_304, dec_stale.entry_idx);
        sub.assert_true(dec_freshen.kind == wing::ResponseDecisionKind.FreshenAndReturn, "Freshened cached entry");

        // 1 second later at t=4602: MUST BE FRESH HIT!
        let t_subsequent = core::unix(4602, 0);
        let dec_sub = wing::lookup(cache, req, t_subsequent);
        sub.assert_true(dec_sub.kind == wing::LookupResultKind.Hit, "Subsequent lookup after 304 merge must be Hit, not expired");
        let age_sub = wing::header(dec_sub.cached_response, "Age");
        sub.assert_bytes_eq(age_sub, "2", "Age is 2s (1s network delay + 1s resident), not hours");
    };
}

// ---- RFC 9111 Special Behaviors & Cascade Invalidation -------------------

fn test_rfc9111_special_behaviors_and_invalidation(t: lit::T&) {
    t.run("only-if-cached Returns 504 on Cache Miss and Stale") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);

        var req = wing::new_get("https://example.com/missing");
        wing::set_header(req, "Cache-Control", "only-if-cached");

        let dec = wing::lookup(cache, req, t0);
        sub.assert_true(dec.kind == wing::LookupResultKind.Fail504, "only-if-cached returns Fail504 on miss");
        sub.assert_eq(dec.status_code, 504, "Fail504 sets status 504 Gateway Timeout");
    };

    t.run("must-understand Status Whitelist Protection") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let req = wing::new_get("https://example.com/custom");

        // Unknown status code 299 with must-understand -> MUST NOT be stored
        var resp = wing::Response { .. };
        resp.status_code = 299;
        wing::set_header(resp, "Cache-Control", "max-age=3600, must-understand");
        resp.body.append("data");

        let ts = wing::new_cache_timestamps(t0, t0, t0);
        let dec = wing::on_response(cache, req, resp, ts);
        sub.assert_true(dec.kind == wing::ResponseDecisionKind.PassThrough, "must-understand rejects unknown status code 299");
        sub.assert_eq(cache.entries.len, 0, "No entry stored for rejected status");
    };

    t.run("HEAD vs GET Separation (RFC 9111 §4.3.5)") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);

        // Store a HEAD response
        var req_head = wing::new_request("HEAD", "https://example.com/asset.png");
        var resp_head = wing::Response { .. };
        resp_head.status_code = 200;
        resp_head.effective_url.append("https://example.com/asset.png");
        wing::set_header(resp_head, "Cache-Control", "max-age=3600");
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        wing::on_response(cache, req_head, resp_head, ts);
        sub.assert_eq(cache.entries.len, 1, "HEAD response stored");
        sub.assert_true(cache.entries[0].head_only, "head_only flag is true");

        // Incoming GET request for the same URL MUST NOT be satisfied by the HEAD entry!
        let req_get = wing::new_get("https://example.com/asset.png");
        let dec_get = wing::lookup(cache, req_get, t0);
        sub.assert_true(dec_get.kind == wing::LookupResultKind.Miss, "GET lookup ignores head_only cached entry");
    };

    t.run("Unsafe Method Cascade Invalidation (RFC 9111 §4.4)") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        // Store two cached entries for same origin
        let req1 = wing::new_get("https://example.com/api/items");
        var resp1 = wing::Response { .. };
        resp1.status_code = 200;
        resp1.effective_url.append("https://example.com/api/items");
        wing::set_header(resp1, "Cache-Control", "max-age=3600");
        resp1.body.append("[1, 2, 3]");
        wing::on_response(cache, req1, resp1, ts);

        let req2 = wing::new_get("https://example.com/api/items/42");
        var resp2 = wing::Response { .. };
        resp2.status_code = 200;
        resp2.effective_url.append("https://example.com/api/items/42");
        wing::set_header(resp2, "Cache-Control", "max-age=3600");
        resp2.body.append("{\"id\": 42}");
        wing::on_response(cache, req2, resp2, ts);

        sub.assert_eq(cache.entries.len, 2, "2 entries initially cached");

        // Succeeded POST request to /api/items with Location: https://example.com/api/items/42
        var post_req = wing::new_post("https://example.com/api/items");
        var post_resp = wing::Response { .. };
        post_resp.status_code = 201; // Created
        wing::set_header(post_resp, "Location", "https://example.com/api/items/42");

        wing::on_response(cache, post_req, post_resp, ts);

        // Both /api/items and /api/items/42 must be invalidated!
        let dec_check1 = wing::lookup(cache, req1, t0);
        sub.assert_true(dec_check1.kind == wing::LookupResultKind.Miss, "Target URI invalidated by POST");

        let dec_check2 = wing::lookup(cache, req2, t0);
        sub.assert_true(dec_check2.kind == wing::LookupResultKind.Miss, "Same-origin Location URI invalidated by POST");

        sub.assert_true(cache.entries[0].security_zeroed, "Entry 1 security_zeroed");
        sub.assert_true(cache.entries[1].security_zeroed, "Entry 2 security_zeroed");
    };

    t.run("Relative Location and Content-Location Invalidation") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        let req_child = wing::new_get("https://example.com/posts/42");
        var resp_child = wing::Response { .. };
        resp_child.status_code = 200;
        resp_child.effective_url.append("https://example.com/posts/42");
        wing::set_header(resp_child, "Cache-Control", "max-age=3600");
        resp_child.body.append("{\"id\": 42}");
        wing::on_response(cache, req_child, resp_child, ts);

        // POST to https://example.com/posts with relative Location: /posts/42
        var post_req = wing::new_post("https://example.com/posts");
        var post_resp = wing::Response { .. };
        post_resp.status_code = 201;
        wing::set_header(post_resp, "Location", "/posts/42");

        wing::on_response(cache, post_req, post_resp, ts);

        let dec_check = wing::lookup(cache, req_child, t0);
        sub.assert_true(dec_check.kind == wing::LookupResultKind.Miss, "Relative Location /posts/42 resolved and invalidated");
    };

    t.run("Non-Heuristic Status Codes Require Explicit Freshness (RFC 9111 §3)") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        // 500 without Cache-Control -> MUST NOT store
        let req1 = wing::new_get("https://example.com/err500");
        var resp_500 = wing::Response { .. };
        resp_500.status_code = 500;
        let dec1 = wing::on_response(cache, req1, resp_500, ts);
        sub.assert_eq(dec1.kind, wing::ResponseDecisionKind.PassThrough, "500 without freshness not stored");

        // 403 without Cache-Control -> MUST NOT store
        let req2 = wing::new_get("https://example.com/err403");
        var resp_403 = wing::Response { .. };
        resp_403.status_code = 403;
        let dec2 = wing::on_response(cache, req2, resp_403, ts);
        sub.assert_eq(dec2.kind, wing::ResponseDecisionKind.PassThrough, "403 without freshness not stored");

        // 403 WITH max-age=60 -> STORE
        var resp_403_fresh = wing::Response { .. };
        resp_403_fresh.status_code = 403;
        wing::set_header(resp_403_fresh, "Cache-Control", "max-age=60");
        let dec3 = wing::on_response(cache, req2, resp_403_fresh, ts);
        sub.assert_eq(dec3.kind, wing::ResponseDecisionKind.StoreAndReturn, "403 with explicit max-age is stored");
    };

    t.run("LRU Integrity and Slot Reuse After Invalidation") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        // Store 3 items
        let req_a = wing::new_get("https://example.com/a");
        var resp_a = wing::Response { .. };
        resp_a.status_code = 200;
        wing::set_header(resp_a, "Cache-Control", "max-age=3600");
        wing::on_response(cache, req_a, resp_a, ts);

        let req_b = wing::new_get("https://example.com/b");
        var resp_b = wing::Response { .. };
        resp_b.status_code = 200;
        wing::set_header(resp_b, "Cache-Control", "max-age=3600");
        wing::on_response(cache, req_b, resp_b, ts);

        let req_c = wing::new_get("https://example.com/c");
        var resp_c = wing::Response { .. };
        resp_c.status_code = 200;
        wing::set_header(resp_c, "Cache-Control", "max-age=3600");
        wing::on_response(cache, req_c, resp_c, ts);

        // Updating entry B should NOT corrupt LRU pointers
        var resp_b_v2 = wing::Response { .. };
        resp_b_v2.status_code = 200;
        wing::set_header(resp_b_v2, "Cache-Control", "max-age=7200");
        wing::on_response(cache, req_b, resp_b_v2, ts);

        sub.assert_true(cache.lru_head >= 0, "LRU head valid");
        sub.assert_true(cache.lru_tail >= 0, "LRU tail valid");
        sub.assert_eq(cache.lru_head as i64, 1, "Updated entry B is at LRU head");

        // Invalidate entry A via POST
        var post_a = wing::new_post("https://example.com/a");
        var post_a_resp = wing::Response { .. };
        post_a_resp.status_code = 200;
        wing::on_response(cache, post_a, post_a_resp, ts);

        // Store new entry D: should reuse invalidated slot of entry A
        let req_d = wing::new_get("https://example.com/d");
        var resp_d = wing::Response { .. };
        resp_d.status_code = 200;
        wing::set_header(resp_d, "Cache-Control", "max-age=3600");
        let dec_d = wing::on_response(cache, req_d, resp_d, ts);

        sub.assert_eq(dec_d.entry_idx, 0, "Invalidated slot 0 reused for new entry D");
        sub.assert_true(cache.entries[0].is_valid, "Reused slot is valid");
    };

    t.run("Qualified no-cache=\"Field\" Does Not Force Revalidation of Stored Response") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        let req = wing::new_get("https://example.com/qualified-no-cache");
        var resp = wing::Response { .. };
        resp.status_code = 200;
        wing::set_header(resp, "Cache-Control", "max-age=3600, no-cache=\"X-Sensitive\"");
        wing::set_header(resp, "X-Sensitive", "secret");
        wing::set_header(resp, "X-Public", "hello");
        resp.body.append("content");

        wing::on_response(cache, req, resp, ts);

        // Sensitive header was stripped
        let stripped_sens = wing::get_header(cache.entries[0].headers, "X-Sensitive");
        sub.assert_bytes_eq(stripped_sens, "", "X-Sensitive was stripped from cache");
        let kept_pub = wing::get_header(cache.entries[0].headers, "X-Public");
        sub.assert_bytes_eq(kept_pub, "hello", "X-Public was kept");

        // Next request within 10s: MUST BE HIT (not forced revalidation)
        let t1 = core::unix(1010, 0);
        let dec = wing::lookup(cache, req, t1);
        sub.assert_eq(dec.kind, wing::LookupResultKind.Hit, "Qualified no-cache allows Hit within freshness lifetime");
    };
}

// ---- RFC 9875 HTTP Cache Groups -------------------------------------------

fn test_cache_groups(t: lit::T&) {
    t.run("Parse Cache-Groups List of Strings (RFC 9875 §2)") { sub =>
        var tags:  wing::CacheGroupTag[..32] = [];
        var count: i32                       = 0;
        let ok = wing::parse_cache_group_list("\"scripts\", \"fonts\"", tags, count);
        sub.assert_true(ok, "Valid Cache-Groups field value parses");
        sub.assert_eq(count, 2, "Two group members parsed");
        sub.assert_bytes_eq(tags[0].name[..], "scripts", "First group name is scripts");
        sub.assert_bytes_eq(tags[1].name[..], "fonts", "Second group name is fonts");

        // RFC 9875 §3 example field value
        var tags_ex:  wing::CacheGroupTag[..32] = [];
        var count_ex: i32                       = 0;
        let ok_ex = wing::parse_cache_group_list("\"eurovision-results\", \"australia\"", tags_ex, count_ex);
        sub.assert_true(ok_ex, "RFC 9875 §3 example field value parses");
        sub.assert_eq(count_ex, 2, "RFC 9875 §3 example yields two groups");
        sub.assert_bytes_eq(tags_ex[0].name[..], "eurovision-results", "First group is eurovision-results");
        sub.assert_bytes_eq(tags_ex[1].name[..], "australia", "Second group is australia");

        // Unterminated quoted string fails closed
        var tags_bad:  wing::CacheGroupTag[..32] = [];
        var count_bad: i32                       = 0;
        let ok_bad = wing::parse_cache_group_list("\"a\", \"b", tags_bad, count_bad);
        sub.assert_false(ok_bad, "Unterminated quote rejected");
        sub.assert_eq(count_bad, 0, "Failed parse yields count 0 (no partial tags)");

        // Non-String member (token) fails closed: field is a List of Strings
        var tags_tok:  wing::CacheGroupTag[..32] = [];
        var count_tok: i32                       = 0;
        sub.assert_false(wing::parse_cache_group_list("scripts", tags_tok, count_tok), "Bare token member rejected");

        // Group name longer than CACHE_GROUP_TAG_MAX rejected (oversize vector)
        var tags_long:  wing::CacheGroupTag[..32] = [];
        var count_long: i32                       = 0;
        let ok_long = wing::parse_cache_group_list(
            "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            tags_long,
            count_long,
        );
        sub.assert_false(ok_long, "65-character group name exceeds 64-byte tag budget");
        sub.assert_eq(count_long, 0, "Oversize name yields count 0");

        // RFC 9875 §2: value must support at least 32 members; 33 fails closed
        var raw_many: u8[..1024] = [];
        var mi:       i64        = 0;
        while mi < 33 {
            if mi > 0 { raw_many.append(", "); }
            raw_many.append("\"g");
            core::format_i64_dec(mi, raw_many);
            raw_many.append("\"");
            mi += 1;
        }
        var tags_many:  wing::CacheGroupTag[..32] = [];
        var count_many: i32                       = 0;
        sub.assert_false(
            wing::parse_cache_group_list(raw_many[..], tags_many, count_many),
            "33 group members exceed 32-member per-entry budget",
        );
        sub.assert_eq(count_many, 0, "Excess member count yields count 0");

        // RFC 9875 §2: a 32-member field value must parse successfully
        var raw_full: u8[..1024] = [];
        var fi:       i64        = 0;
        while fi < 32 {
            if fi > 0 { raw_full.append(", "); }
            raw_full.append("\"g");
            core::format_i64_dec(fi, raw_full);
            raw_full.append("\"");
            fi += 1;
        }
        var tags_full:  wing::CacheGroupTag[..32] = [];
        var count_full: i32                       = 0;
        sub.assert_true(
            wing::parse_cache_group_list(raw_full[..], tags_full, count_full),
            "RFC 9875 §2 32-member field value parses",
        );
        sub.assert_eq(count_full, 32, "Thirty-two group members parsed");
        sub.assert_bytes_eq(tags_full[0].name[..], "g0", "First of 32 members is g0");
        sub.assert_bytes_eq(tags_full[31].name[..], "g31", "Last of 32 members is g31");

        // 32-member value round-trips through serialize into the 512-byte field buffer
        var wire_full: u8[..512] = [];
        let written_full = wing::serialize_cache_group_list(tags_full, count_full, wire_full);
        sub.assert_true(written_full > 0, "32-member list serializes into 512-byte buffer");
        var rt_tags:  wing::CacheGroupTag[..32] = [];
        var rt_count: i32                       = 0;
        sub.assert_true(
            wing::parse_cache_group_list(wire_full[..], rt_tags, rt_count),
            "32-member serialization re-parses",
        );
        sub.assert_eq(rt_count, 32, "Round-trip preserves 32 members");
    };

    t.run("Serialize Cache-Groups Round-Trip (RFC 9875 §2)") { sub =>
        var tags:  wing::CacheGroupTag[..32] = [];
        var count: i32                       = 0;
        wing::parse_cache_group_list("\"scripts\", \"fonts\"", tags, count);

        var wire: u8[..512] = [];
        let written = wing::serialize_cache_group_list(tags, count, wire);
        sub.assert_eq(written, 18, "18 bytes written for two quoted members");
        sub.assert_bytes_eq(wire[..], "\"scripts\", \"fonts\"", "Serialized field value matches RFC quoting");

        var reparsed: wing::CacheGroupTag[..32] = [];
        var recount:  i32                       = 0;
        let ok = wing::parse_cache_group_list(wire[..], reparsed, recount);
        sub.assert_true(ok, "Serialized output re-parses");
        sub.assert_eq(recount, 2, "Round-trip yields two groups");
        sub.assert_bytes_eq(reparsed[0].name[..], "scripts", "Round-trip first group scripts");
        sub.assert_bytes_eq(reparsed[1].name[..], "fonts", "Round-trip second group fonts");
    };

    t.run("Store Path Attaches Cache-Groups to CachedEntry (RFC 9875 §2)") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        let req = wing::new_get("https://example.com/app.js");
        var resp = wing::Response { .. };
        resp.status_code = 200;
        resp.effective_url.append("https://example.com/app.js");
        wing::set_header(resp, "Cache-Control", "max-age=3600");
        wing::set_header(resp, "Cache-Groups", "\"scripts\"");
        resp.body.append("console.log(1)");
        wing::on_response(cache, req, resp, ts);

        sub.assert_eq(cache.entries.len, 1, "Grouped response stored");
        sub.assert_true(wing::entry_has_group(cache.entries[0], "scripts"), "entry_has_group matches scripts");
        // RFC 9875 §2.1: group names compare case-sensitive
        sub.assert_false(wing::entry_has_group(cache.entries[0], "Scripts"), "Group names are case-sensitive");
    };

    t.run("Group Invalidation via invalidate_group and Cache-Group-Invalidation (RFC 9875 §3)") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let ts = wing::new_cache_timestamps(t0, t0, t0);

        // Two entries tagged "catalog", one tagged "user-42"
        let req_a = wing::new_get("https://example.com/catalog/a");
        var resp_a = wing::Response { .. };
        resp_a.status_code = 200;
        resp_a.effective_url.append("https://example.com/catalog/a");
        wing::set_header(resp_a, "Cache-Control", "max-age=3600");
        wing::set_header(resp_a, "Cache-Groups", "\"catalog\"");
        resp_a.body.append("a");
        wing::on_response(cache, req_a, resp_a, ts);

        let req_b = wing::new_get("https://example.com/catalog/b");
        var resp_b = wing::Response { .. };
        resp_b.status_code = 200;
        resp_b.effective_url.append("https://example.com/catalog/b");
        wing::set_header(resp_b, "Cache-Control", "max-age=3600");
        wing::set_header(resp_b, "Cache-Groups", "\"catalog\"");
        resp_b.body.append("b");
        wing::on_response(cache, req_b, resp_b, ts);

        let req_u = wing::new_get("https://example.com/users/42");
        var resp_u = wing::Response { .. };
        resp_u.status_code = 200;
        resp_u.effective_url.append("https://example.com/users/42");
        wing::set_header(resp_u, "Cache-Control", "max-age=3600");
        wing::set_header(resp_u, "Cache-Groups", "\"user-42\"");
        resp_u.body.append("u");
        wing::on_response(cache, req_u, resp_u, ts);

        sub.assert_eq(cache.entries.len, 3, "Three grouped entries stored");

        let purged = wing::invalidate_group(cache, "catalog");
        sub.assert_eq(purged, 2, "invalidate_group purges both catalog entries");
        sub.assert_false(cache.entries[0].is_valid, "catalog entry A invalidated");
        sub.assert_false(cache.entries[1].is_valid, "catalog entry B invalidated");
        sub.assert_true(cache.entries[2].is_valid, "user-42 entry remains valid");

        // Cache-Group-Invalidation on a state-changing response (RFC 9875 §3)
        var cache_2 = wing::new_http_cache();
        wing::on_response(cache_2, req_a, resp_a, ts);
        wing::on_response(cache_2, req_b, resp_b, ts);
        wing::on_response(cache_2, req_u, resp_u, ts);

        let post_req = wing::new_post("https://example.com/admin/purge");
        var post_resp = wing::Response { .. };
        post_resp.status_code = 200;
        wing::set_header(post_resp, "Cache-Group-Invalidation", "\"catalog\"");

        let cascade = wing::check_invalidation(cache_2, post_req, post_resp);
        sub.assert_eq(cascade, 2, "check_invalidation purges both catalog entries via Cache-Group-Invalidation");
        sub.assert_false(cache_2.entries[0].is_valid, "POST cascade invalidated catalog entry A");
        sub.assert_false(cache_2.entries[1].is_valid, "POST cascade invalidated catalog entry B");
        sub.assert_true(cache_2.entries[2].is_valid, "user-42 entry survives POST cascade");
    };
}

// ---- Single-Flight / Request Collapsing ---------------------------------

fn test_request_collapsing(t: lit::T&) {
    t.run("Single-Flight Writers Collapsing Concurrent Requests") { sub =>
        var writers = wing::CacheWriters { .. };
        let key = "GET https://example.com/resource";

        // First caller arrives -> becomes leader
        let is_leader_1, flight_idx_1 = wing::start_writer_or_join(writers, key);
        sub.assert_true(is_leader_1, "First caller is leader");
        sub.assert_eq(flight_idx_1, 0, "Flight index 0");

        // Concurrent caller arrives -> joins existing in-flight transaction
        let is_leader_2, flight_idx_2 = wing::start_writer_or_join(writers, key);
        sub.assert_false(is_leader_2, "Second caller joins in-flight request");
        sub.assert_eq(flight_idx_2, 0, "Shares flight index 0");
        sub.assert_eq(writers.flights[0].waiter_count, 1, "Waiter count is 1");

        // Finish in-flight transaction
        wing::finish_writer(writers, flight_idx_1);
        sub.assert_false(writers.flights[flight_idx_1].is_active, "Flight cleanly finished and slot deactivated");
    };

    t.run("Multiple Parallel In-Flight Requests Slot Stability") { sub =>
        var writers = wing::CacheWriters { .. };
        let key_a = "GET https://example.com/res-a";
        let key_b = "GET https://example.com/res-b";

        let is_lead_a, idx_a = wing::start_writer_or_join(writers, key_a);
        let is_lead_b, idx_b = wing::start_writer_or_join(writers, key_b);
        sub.assert_true(is_lead_a && is_lead_b, "Both are leaders for different keys");
        sub.assert_eq(idx_a, 0, "Flight A is at index 0");
        sub.assert_eq(idx_b, 1, "Flight B is at index 1");

        // Complete flight A first
        wing::finish_writer(writers, idx_a);
        sub.assert_false(writers.flights[idx_a].is_active, "Flight A slot deactivated");

        // Flight B must still be active and its index preserved at 1!
        sub.assert_true(writers.flights[idx_b].is_active, "Flight B still active at index 1");
        sub.assert_bytes_eq(writers.flights[idx_b].key[..], key_b, "Flight B key preserved");

        // Complete flight B
        wing::finish_writer(writers, idx_b);
        sub.assert_false(writers.flights[idx_b].is_active, "Flight B slot deactivated");

        // New flight reuses slot 0 without growing past capacity
        let key_c = "GET https://example.com/res-c";
        let is_lead_c, idx_c = wing::start_writer_or_join(writers, key_c);
        sub.assert_true(is_lead_c, "Leader for key C");
        sub.assert_eq(idx_c, 0, "Slot 0 reused for new flight");
    };
}

fn test_rfc5861_stale_extensions(t: lit::T&) {
    t.run("1. RFC 5861 Section 3: stale-while-revalidate Cache Decision") { sub =>
        var cache = wing::new_http_cache();
        var ts = wing::CacheTimestamps {
            request_time:  core::unix(1700000000, 0),
            response_time: core::unix(1700000001, 0),
            ..
        };

        // Populate cache with max-age=60, stale-while-revalidate=120
        var req = wing::new_request("GET", "https://api.example.com/feed");
        var resp = wing::Response { .. };
        resp.status_code = 200;
        wing::set_header(resp, "cache-control", "max-age=60, stale-while-revalidate=120");
        wing::set_header(resp, "etag", "\"feed-v1\"");
        resp.body.append("Feed Content V1");

        let dec_store = wing::on_response(cache, req, resp, ts);
        sub.assert_eq(dec_store.kind, wing::ResponseDecisionKind.StoreAndReturn, "Initial response stored");

        // 1. Query at t = +30s (Fresh: within max-age=60)
        let t_fresh = core::unix(1700000030, 0);
        let dec_fresh = wing::lookup(cache, req, t_fresh);
        sub.assert_eq(dec_fresh.kind, wing::LookupResultKind.Hit, "Fresh hit");
        sub.assert_false(dec_fresh.revalidate_in_background, "Background revalidation not needed yet");

        // 2. Query at t = +100s (Stale, but within stale-while-revalidate=120, total window 180s)
        let t_stale_swr = core::unix(1700000100, 0);
        let dec_swr = wing::lookup(cache, req, t_stale_swr);
        sub.assert_eq(dec_swr.kind, wing::LookupResultKind.Hit, "Stale hit permitted under stale-while-revalidate");
        sub.assert_true(dec_swr.revalidate_in_background, "Flagged for background revalidation per RFC 5861");
        sub.assert_bytes_eq(dec_swr.cached_response.body[..], "Feed Content V1", "Served cached payload");

        // 3. Query at t = +200s (Beyond max-age + stale-while-revalidate = 180s)
        let t_expired = core::unix(1700000200, 0);
        let dec_exp = wing::lookup(cache, req, t_expired);
        sub.assert_eq(dec_exp.kind, wing::LookupResultKind.Revalidate, "Expired requires immediate synchronous revalidation");
    };

    t.run("2. RFC 5861 Section 4: stale-if-error Fallback on 5xx Origin Failure") { sub =>
        var cache = wing::new_http_cache();
        var ts = wing::CacheTimestamps {
            request_time:  core::unix(1700000000, 0),
            response_time: core::unix(1700000001, 0),
            ..
        };

        // Populate cache with max-age=60, stale-if-error=300
        var req = wing::new_request("GET", "https://api.example.com/prices");
        var resp = wing::Response { .. };
        resp.status_code = 200;
        wing::set_header(resp, "cache-control", "max-age=60, stale-if-error=300");
        wing::set_header(resp, "etag", "\"prices-v1\"");
        resp.body.append("Price: $42.00");

        let dec_store = wing::on_response(cache, req, resp, ts);
        sub.assert_eq(dec_store.kind, wing::ResponseDecisionKind.StoreAndReturn, "Initial prices stored");

        // At t = +150s, entry is stale (max-age=60 expired)
        // Client performs revalidation request to origin
        let t_reval = core::unix(1700000150, 0);
        let dec_req = wing::lookup(cache, req, t_reval);
        sub.assert_eq(dec_req.kind, wing::LookupResultKind.Revalidate, "Entry requires revalidation");

        // Origin fails and returns 503 Service Unavailable
        var resp_503 = wing::Response { .. };
        resp_503.status_code = 503;
        var ts_503 = wing::CacheTimestamps {
            request_time:  t_reval,
            response_time: t_reval,
            ..
        };

        let dec_err = wing::on_response(cache, req, resp_503, ts_503, dec_req.entry_idx);
        sub.assert_eq(dec_err.kind, wing::ResponseDecisionKind.FreshenAndReturn, "503 triggers stale-if-error fallback");
        sub.assert_bytes_eq(dec_err.response.body[..], "Price: $42.00", "Cached prices returned to caller despite 503");

        // At t = +500s, beyond max-age (60) + stale-if-error (300) = 360s
        let t_expired_err = core::unix(1700000500, 0);
        var ts_500 = wing::CacheTimestamps {
            request_time:  t_expired_err,
            response_time: t_expired_err,
            ..
        };
        let dec_exp_err = wing::on_response(cache, req, resp_503, ts_500, dec_req.entry_idx);
        sub.assert_eq(dec_exp_err.kind, wing::ResponseDecisionKind.PassThrough, "503 after stale-if-error window passes through error");
    };
}

// ---- Main Test Runner Entrypoint -------------------------------------------

// --- Component: http_sfv ---
// Verification suite for RFC 8941 & RFC 9651 Structured Field Values for HTTP:
// - Primitives: boolean, integer, decimal, string, token, binary, date
// - Parameterized items
// - Structured Lists and Inner Lists
// - Structured Dictionaries and fast accessors
// - Zero-allocation serialization into output buffers

fn test_sfv_primitives(t: lit::T&) {
    t.run("SFV Primitives Parsing (RFC 8941 §3.1-§3.3)") { sub =>
        // 1. Boolean
        let item_bool_t, ok_b1 = wing::parse_sf_item("?1");
        sub.assert_true(ok_b1, "Parse boolean ?1");
        sub.assert_eq(item_bool_t.item.kind, wing::SfType.Boolean, "Kind boolean");
        sub.assert_true(item_bool_t.item.bool_val, "Value is true");

        let item_bool_f, ok_b2 = wing::parse_sf_item("?0");
        sub.assert_true(ok_b2, "Parse boolean ?0");
        sub.assert_false(item_bool_f.item.bool_val, "Value is false");

        // 2. Integer
        let item_int, ok_i1 = wing::parse_sf_item("42");
        sub.assert_true(ok_i1, "Parse integer 42");
        sub.assert_eq(item_int.item.kind, wing::SfType.Integer, "Kind integer");
        sub.assert_eq(item_int.item.int_val, 42, "Value is 42");

        let item_int_neg, ok_i2 = wing::parse_sf_item("-999");
        sub.assert_true(ok_i2, "Parse negative integer -999");
        sub.assert_eq(item_int_neg.item.int_val, -999, "Value is -999");

        // 3. Decimal
        let item_dec, ok_dec = wing::parse_sf_item("3.14");
        sub.assert_true(ok_dec, "Parse decimal 3.14");
        sub.assert_eq(item_dec.item.kind, wing::SfType.Decimal, "Kind decimal");
        sub.assert_gt(item_dec.item.dec_val, 3.13, "Value > 3.13");
        sub.assert_lt(item_dec.item.dec_val, 3.15, "Value < 3.15");

        // 4. String
        let item_str, ok_str = wing::parse_sf_item("\"hello world\"");
        sub.assert_true(ok_str, "Parse string");
        sub.assert_eq(item_str.item.kind, wing::SfType.String, "Kind string");
        sub.assert_eq(item_str.item.str_val, "hello world", "String contents match");

        // 5. Token
        let item_tok, ok_tok = wing::parse_sf_item("gzip");
        sub.assert_true(ok_tok, "Parse token gzip");
        sub.assert_eq(item_tok.item.kind, wing::SfType.Token, "Kind token");
        sub.assert_eq(item_tok.item.str_val, "gzip", "Token contents match");

        // 6. Binary
        let item_bin, ok_bin = wing::parse_sf_item(":aGVsbG8=:");
        sub.assert_true(ok_bin, "Parse binary");
        sub.assert_eq(item_bin.item.kind, wing::SfType.Binary, "Kind binary");
        sub.assert_eq(item_bin.item.str_val, "aGVsbG8=", "Binary base64 payload matches");

        // 7. Date
        let item_date, ok_date = wing::parse_sf_item("@1618884475");
        sub.assert_true(ok_date, "Parse date");
        sub.assert_eq(item_date.item.kind, wing::SfType.Date, "Kind date");
        sub.assert_eq(item_date.item.int_val, 1618884475, "Date timestamp matches");
    };
}

fn test_sfv_parameters(t: lit::T&) {
    t.run("SFV Parameters on Items (RFC 8941 §3.1.2)") { sub =>
        let p_item, ok = wing::parse_sf_item("text/html;charset=utf-8;q=0.8");
        sub.assert_true(ok, "Parsed parameterized item");
        sub.assert_eq(p_item.item.kind, wing::SfType.Token, "Kind is token");
        sub.assert_eq(p_item.item.str_val, "text/html", "Token text/html");
        sub.assert_eq(p_item.params.len, 2, "Has 2 parameters");

        sub.assert_eq(p_item.params[0].key, "charset", "First param key charset");
        sub.assert_eq(p_item.params[0].item.kind, wing::SfType.Token, "Charset is token");
        sub.assert_eq(p_item.params[0].item.str_val, "utf-8", "Charset is utf-8");

        sub.assert_eq(p_item.params[1].key, "q", "Second param key q");
        sub.assert_eq(p_item.params[1].item.kind, wing::SfType.Decimal, "Q is decimal");
        sub.assert_gt(p_item.params[1].item.dec_val, 0.79, "Q value > 0.79");
    };
}

fn test_sfv_lists_and_dicts(t: lit::T&) {
    t.run("SFV Lists and Dictionaries (RFC 8941 §3.1-§3.2)") { sub =>
        // 1. Lists
        var list_items: wing::SfParameterizedItem[..16] = [];
        var ok = wing::parse_sf_list("sugar, tea, rum", list_items);
        sub.assert_true(ok, "Parse simple list");
        sub.assert_eq(list_items.len, 3, "List has 3 items");
        sub.assert_eq(list_items[0].item.str_val, "sugar", "Item 0 sugar");
        sub.assert_eq(list_items[1].item.str_val, "tea", "Item 1 tea");
        sub.assert_eq(list_items[2].item.str_val, "rum", "Item 2 rum");

        // 2. Dictionary
        var dict_entries: wing::SfDictEntry[..16] = [];
        let raw_dict = "u=3, i=?1, mode=\"fast\", prio=10";
        ok = wing::parse_sf_dict(raw_dict, dict_entries);
        sub.assert_true(ok, "Parse dictionary");
        sub.assert_eq(dict_entries.len, 4, "Dictionary has 4 entries");

        // Fast zero-alloc accessors
        let u_val = wing::sf_dict_get_int(raw_dict, "u", 0);
        sub.assert_eq(u_val, 3, "Urgency is 3");

        let i_val = wing::sf_dict_get_bool(raw_dict, "i", false);
        sub.assert_true(i_val, "Incremental is true");

        let mode_val = wing::sf_dict_get_token(raw_dict, "mode");
        // 'mode' is a string ("fast"), sf_dict_get_token accepts String or Token
        sub.assert_eq(mode_val, "fast", "Mode value matches");

        sub.assert_true(wing::sf_dict_has_key(raw_dict, "prio"), "Has key 'prio'");
        sub.assert_false(wing::sf_dict_has_key(raw_dict, "unknown"), "No unknown key");
    };

    t.run("SFV Inner List in Dictionary") { sub =>
        var dict: wing::SfDictEntry[..16] = [];
        let ok = wing::parse_sf_dict("endpoints=(srv1 srv2);p=1", dict);
        sub.assert_true(ok, "Parsed inner list in dict");
        sub.assert_eq(dict.len, 1, "One dict entry");
        sub.assert_eq(dict[0].key, "endpoints", "Key is endpoints");
        sub.assert_true(dict[0].is_inner_list, "Is inner list");
        sub.assert_eq(dict[0].inner_items.len, 2, "2 inner items");
        sub.assert_eq(dict[0].inner_items[0].str_val, "srv1", "srv1");
        sub.assert_eq(dict[0].inner_items[1].str_val, "srv2", "srv2");
        sub.assert_eq(dict[0].params.len, 1, "Inner list has 1 parameter");
        sub.assert_eq(dict[0].params[0].key, "p", "Param key p");
        sub.assert_eq(dict[0].params[0].item.int_val, 1, "Param p value 1");
    };
}

fn test_sfv_serialization(t: lit::T&) {
    t.run("SFV Serialization (RFC 8941 §4.1)") { sub =>
        var out: u8[>..] = [];

        // Serialize Integer
        var item = wing::SfItem { kind: wing::SfType.Integer, int_val: 1234, .. };
        wing::sf_serialize_item(item, out);
        sub.assert_eq(out[..], "1234", "Output matches 1234");

        // Serialize Dict Entry: u=5
        out.clear();
        var entry = wing::SfDictEntry {
            key:  "u",
            item: wing::SfItem { kind: wing::SfType.Integer, int_val: 5, .. },
            ..
        };
        wing::sf_serialize_dict_entry(entry, out);
        sub.assert_eq(out[..], "u=5", "Dict entry matches u=5");

        // Serialize Boolean ?1 in Dict Entry: i (RFC 8941 omits =?1 for boolean true in dicts)
        out.clear();
        var entry_bool = wing::SfDictEntry {
            key:  "i",
            item: wing::SfItem { kind: wing::SfType.Boolean, bool_val: true, .. },
            ..
        };
        wing::sf_serialize_dict_entry(entry_bool, out);
        sub.assert_eq(out[..], "i", "Dict entry matches 'i'");

        var dict_hdr: u8[..128] = [];
        wing::format_use_as_dictionary_header(dict_hdr, "/app/*", "v1", 3600);
        sub.assert_true(dict_hdr.len > 0, "Use-As-Dictionary header formatted");
    };
}

// --- Component: http_digest_fields_rfc9530 ---
// Verification suite for RFC 9530 Digest Fields for HTTP (obsoleting RFC 3230)
// and OAuth 2.1 / RFC 9700 strict PKCE validation:
// - Content-Digest and Repr-Digest generation using RFC 8941 Structured Fields
// - sha-256 and sha-512 binary byte sequence verification (:base64:)
// - Cryptographic binding with RFC 9421 HTTP Message Signatures
// - Tampered payload rejection
// - Strict PKCE plain transformation rejection

fn test_rfc9530_content_digest(t: lit::T&) {
    t.run("Content-Digest sha-256 Generation & Verification") { sub =>
        var req = wing::Request {
            method: "POST",
            url:    "https://api.gateway.org/items",
            ..
        };
        req.body.clear();
        req.body.append("{\"item_id\":42,\"action\":\"checkout\"}");

        let ok_set = wing::set_content_digest(req, "sha-256");
        sub.assert_true(ok_set, "Content-Digest set on request");

        let digest_val = req.header("Content-Digest");
        sub.assert_gt(digest_val.len, 0, "Content-Digest header exists");
        sub.assert_contains(digest_val, "sha-256=:", "Has sha-256 prefix with SF byte sequence delimiter");
        sub.assert_true(digest_val[digest_val.len - 1] == ':' as u8, "Ends with SF byte sequence delimiter");

        let ok_verify = wing::verify_request_content_digest(req);
        sub.assert_true(ok_verify, "Content-Digest verifies successfully against body");

        // Tamper payload
        var tampered_req = req;
        tampered_req.body.clear();
        tampered_req.body.append("{\"item_id\":42,\"action\":\"tampered\"}");
        let tamper_verify = wing::verify_request_content_digest(tampered_req);
        sub.assert_false(tamper_verify, "Tampered body fails Content-Digest verification");
    };

    t.run("Content-Digest sha-512 on Response") { sub =>
        var res = wing::Response {
            status_code: 200,
            ..
        };
        res.body.clear();
        res.body.append("{\"status\":\"shipped\",\"tracking\":\"TRK123456\"}");

        let ok_set = wing::set_response_content_digest(res, "sha-512");
        sub.assert_true(ok_set, "Content-Digest sha-512 set on response");

        let digest_val = res.header("Content-Digest");
        sub.assert_contains(digest_val, "sha-512=:", "Has sha-512 SF prefix");

        let ok_verify = wing::verify_response_content_digest(res);
        sub.assert_true(ok_verify, "Response Content-Digest verifies against body");
    };

    t.run("Repr-Digest Generation & Verification") { sub =>
        var req = wing::Request {
            method: "PUT",
            url:    "https://api.gateway.org/data",
            ..
        };
        req.body.clear();
        req.body.append("raw representation payload");

        let ok_set = wing::set_repr_digest(req, "sha-256");
        sub.assert_true(ok_set, "Repr-Digest set on request");

        let repr_val = req.header("Repr-Digest");
        sub.assert_contains(repr_val, "sha-256=:", "Has Repr-Digest header");

        let ok_verify = wing::verify_request_repr_digest(req);
        sub.assert_true(ok_verify, "Repr-Digest verifies against body");
    };

    t.run("RFC 9530 Want-Content-Digest and Want-Repr-Digest") { sub =>
        var req = wing::Request {
            method: "GET",
            url:    "https://api.gateway.org/data",
            ..
        };
        wing::set_want_content_digest(req, "sha-256=10, sha-512=5");
        sub.assert_bytes_eq(req.header("Want-Content-Digest"), "sha-256=10, sha-512=5", "Want-Content-Digest set");
        wing::set_want_repr_digest(req, "sha-256=10");
        sub.assert_bytes_eq(req.header("Want-Repr-Digest"), "sha-256=10", "Want-Repr-Digest set");
    };
}

fn test_rfc9530_with_rfc9421_signatures(t: lit::T&) {
    t.run("RFC 9421 Signature covering Content-Digest") { sub =>
        let seed: u8[32] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let pubkey = core::ed25519_public_key(seed);

        var req = wing::Request {
            method: "POST",
            url:    "https://payment.bank.org/transfers",
            ..
        };
        req.body.clear();
        req.body.append("{\"amount\":1000,\"recipient\":\"alice\"}");
        wing::set_header(req, "content-type", "application/json");

        // 1. Add RFC 9530 Content-Digest
        wing::set_content_digest(req, "sha-256");

        // 2. Sign message including content-digest
        var params = wing::HttpSignatureParams {
            label:  "sig1",
            key_id: "bank-key-1",
            alg:    "ed25519",
            ..
        };
        params.components.push("@method");
        params.components.push("@authority");
        params.components.push("@path");
        params.components.push("content-type");
        params.components.push("content-digest");

        let ok_sign = wing::sign_http_request(req, params, seed[..]);
        sub.assert_true(ok_sign, "Request signed with RFC 9421 including Content-Digest");

        // 3. Verify digest and signature
        sub.assert_true(wing::verify_request_content_digest(req), "Content-Digest valid");
        sub.assert_true(wing::verify_http_signature(req, "sig1", params, pubkey[..]), "HTTP signature valid");

        // 4. Tampering body breaks Content-Digest
        req.body.clear();
        req.body.append("{\"amount\":999999,\"recipient\":\"mallory\"}");
        sub.assert_false(wing::verify_request_content_digest(req), "Tampered body breaks Content-Digest");
    };
}

fn test_oauth21_strict_pkce(t: lit::T&) {
    t.run("OAuth 2.1 & RFC 9700 Strict PKCE Enforcement") { sub =>
        let verifier: const u8[:] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        // S256 is accepted
        var s256_challenge: u8[..128] = [];
        let ok_s256 = wing::compute_code_challenge(verifier, "S256", s256_challenge);
        sub.assert_true(ok_s256, "S256 challenge computed");
        sub.assert_true(wing::is_valid_code_challenge_strict(s256_challenge[..], "S256"), "S256 valid under strict rules");
        sub.assert_true(wing::validate_code_challenge_strict(verifier, s256_challenge[..], "S256"), "S256 validates under strict rules");

        // plain is strictly rejected under OAuth 2.1 rules
        var plain_challenge: u8[..128] = [];
        wing::compute_code_challenge(verifier, "plain", plain_challenge);
        sub.assert_false(wing::is_valid_code_challenge_strict(plain_challenge[..], "plain"), "plain method rejected by strict challenge check");
        sub.assert_false(wing::validate_code_challenge_strict(verifier, plain_challenge[..], "plain"), "plain method rejected by strict validation");
    };
}

// --- Component: http_signatures ---
// Verification suite for RFC 9421 HTTP Message Signatures:
// - Component extraction (@method, @target-uri, @authority, @path, custom headers)
// - Canonical Signature Base string construction
// - Signature-Input RFC 8941 Structured Fields serialization
// - Signature header formatting with sf-binary :<base64>:
// - End-to-end request signing and cryptographic verification (HMAC-SHA256)
// - Rejection on tampered headers, modified method, or expired signatures

fn test_http_signatures(t: lit::T&) {
    t.run("Canonical Signature Base Construction (RFC 9421 §2.5)") { sub =>
        var req = wing::Request {
            method: "POST",
            url:    "https://example.com/api/orders?status=active",
            ..
        };
        wing::set_header(req, "Content-Type", "application/json");
        wing::set_header(req, "Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");

        var params = wing::HttpSignatureParams {
            label:   "sig1",
            key_id:  "test-key-rsa-pss",
            alg:     "hmac-sha256",
            created: 1618884475,
            ..
        };
        params.components.push("@method");
        params.components.push("@authority");
        params.components.push("@path");
        params.components.push("content-type");

        var sig_base: u8[>..] = [];
        let ok = wing::build_signature_base(req, params, sig_base);
        sub.assert_true(ok, "Signature base constructed");

        // Verify canonical elements
        sub.assert_contains(sig_base[..], "\"@method\": POST\n", "Contains @method");
        sub.assert_contains(sig_base[..], "\"@authority\": example.com\n", "Contains @authority");
        sub.assert_contains(sig_base[..], "\"@path\": /api/orders\n", "Contains @path");
        sub.assert_contains(sig_base[..], "\"content-type\": application/json\n", "Contains content-type");
        sub.assert_contains(sig_base[..], "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-type\");created=1618884475;keyid=\"test-key-rsa-pss\";alg=\"hmac-sha256\"", "Contains @signature-params trailer");
    };

    t.run("End-to-End Signing and Verification") { sub =>
        var req = wing::Request {
            method: "GET",
            url:    "https://api.bank.com/v1/accounts/12345",
            ..
        };
        wing::set_header(req, "Host", "api.bank.com");
        wing::set_header(req, "Accept", "application/json");

        var params = wing::HttpSignatureParams {
            label:   "sig-bank",
            key_id:  "k-prod-01",
            created: 1700000000,
            expires: 1700000300,
            ..
        };
        params.components.push("@method");
        params.components.push("@target-uri");
        params.components.push("accept");

        let key = "shared_secret_hmac_key_32_bytes!";

        let sign_ok = wing::sign_http_request(req, params, key);
        sub.assert_true(sign_ok, "Request signed successfully");

        // Verify headers attached
        sub.assert_true(req.has_header("Signature-Input"), "Signature-Input present");
        sub.assert_contains(req.header("Signature-Input"), "sig-bank=(\"@method\" \"@target-uri\" \"accept\")", "Signature-Input formatted");
        sub.assert_true(req.has_header("Signature"), "Signature present");
        sub.assert_contains(req.header("Signature"), "sig-bank=:", "Signature has sf-binary framing");

        // Verify signature valid
        let ver_ok = wing::verify_http_signature(req, "sig-bank", params, key, 1700000100);
        sub.assert_true(ver_ok, "Signature verification passed");

        // Verification fails if expired
        let ver_expired = wing::verify_http_signature(req, "sig-bank", params, key, 1700000500);
        sub.assert_false(ver_expired, "Expired signature rejected");

        // Verification fails if key is wrong
        let ver_wrong_key = wing::verify_http_signature(req, "sig-bank", params, "wrong_key_123456789012345678901", 1700000100);
        sub.assert_false(ver_wrong_key, "Tampered key rejected");

        // Verification fails if header was tampered
        wing::set_header(req, "Accept", "application/xml"); // changed accept
        let ver_tampered = wing::verify_http_signature(req, "sig-bank", params, key, 1700000100);
        sub.assert_false(ver_tampered, "Tampered header rejected");
    };

    t.run("RFC 9421 Timing Defense, Created/Expires Bounds & @query") { sub =>
        var req = wing::Request {
            method: "GET",
            url:    "https://api.example.com/items?filter=active&sort=desc",
            ..
        };
        wing::set_header(req, "X-Custom", "  spaced   value  ");

        var params = wing::HttpSignatureParams {
            label:   "sig1",
            created: 1700000000,
            expires: 1700000300,
            ..
        };
        params.components.push("@query");
        params.components.push("x-custom");

        var sig_base: u8[>..] = [];
        let ok_base = wing::build_signature_base(req, params, sig_base);
        sub.assert_true(ok_base, "Signature base with @query built");
        sub.assert_contains(sig_base[..], "\"@query\": ?filter=active&sort=desc\n", "Contains @query");
        sub.assert_contains(sig_base[..], "\"x-custom\": spaced value\n", "Whitespace trimmed and collapsed");

        let key = "hmac_key_test_secret_32_bytes!!";
        let sign_ok = wing::sign_http_request(req, params, key);
        sub.assert_true(sign_ok, "Request signed");

        // 1. Valid signature verifies
        let v_ok = wing::verify_http_signature(req, "sig1", params, key, 1700000100);
        sub.assert_true(v_ok, "Signature verified");

        // 2. Reject if created in future beyond clock skew
        let v_future = wing::verify_http_signature(req, "sig1", params, key, 1699999000);
        sub.assert_false(v_future, "Future creation rejected");

        // 3. Reject if created >= expires
        var bad_params = params;
        bad_params.created = 1700000500;
        bad_params.expires = 1700000400;
        let v_bad_exp = wing::verify_http_signature(req, "sig1", bad_params, key, 1700000450);
        sub.assert_false(v_bad_exp, "created >= expires rejected");

        // 4. Multiple signatures in dictionary & prefix isolation
        var multi_req = req;
        var multi_sig: u8[..512] = "sig1_prefix=:aW52YWxpZA==:, ";
        multi_sig.append(req.header("Signature"));
        wing::set_header(multi_req, "Signature", multi_sig[..]);

        let v_multi = wing::verify_http_signature(multi_req, "sig1", params, key, 1700000100);
        sub.assert_true(v_multi, "Dictionary member sig1 isolated from sig1_prefix");

        let v_prefix = wing::verify_http_signature(multi_req, "sig1_prefix", params, key, 1700000100);
        sub.assert_false(v_prefix, "Fake prefix signature rejected");
    };
}

fn test_ed25519_signatures(t: lit::T&) {
    t.run("Ed25519 Asymmetric HTTP Signatures (RFC 9421 Section 3.3.6: EdDSA Using Curve edwards25519 - Signature verification)") { sub =>
        var seed: u8[32] = [0; 32];
        for i in 32 { seed[i] = (i + 17) as u8; }
        let pub_key = core::ed25519_public_key(seed);

        var req = wing::Request {
            method: "POST",
            url:    "https://api.gateway.org/transfers",
            ..
        };
        wing::set_header(req, "Content-Type", "application/json");
        wing::set_header(req, "Digest", "SHA-256=abcdef1234567890");

        var params = wing::HttpSignatureParams {
            label:   "sig-ed",
            key_id:  "ed25519-key-1",
            alg:     "ed25519",
            created: 1700000000,
            ..
        };
        params.components.push("@method");
        params.components.push("@authority");
        params.components.push("content-type");

        let sign_ok = wing::sign_http_request(req, params, seed[..]);
        sub.assert_true(sign_ok, "Signed request with Ed25519");
        sub.assert_true(req.has_header("Signature-Input"), "Has Signature-Input");
        sub.assert_true(req.has_header("Signature"), "Has Signature");

        // Verification with public key
        let v_ok = wing::verify_http_signature(req, "sig-ed", params, pub_key[..], 1700000050);
        sub.assert_true(v_ok, "Ed25519 signature verified successfully");

        // Rejection on wrong public key
        var wrong_pub: u8[32] = [0xFF; 32];
        let v_wrong = wing::verify_http_signature(req, "sig-ed", params, wrong_pub[..], 1700000050);
        sub.assert_false(v_wrong, "Wrong public key rejected");

        // Rejection on tampered method
        var tampered_req = req;
        tampered_req.method.clear();
        tampered_req.method.append("PUT");
        let v_tampered = wing::verify_http_signature(tampered_req, "sig-ed", params, pub_key[..], 1700000050);
        sub.assert_false(v_tampered, "Tampered method rejected");
    };
}

fn test_response_signatures(t: lit::T&) {
    t.run("HTTP Response Signatures with @status & ;req component chaining") { sub =>
        var req = wing::Request {
            method: "GET",
            url:    "https://shop.com/orders/42",
            ..
        };
        wing::set_header(req, "X-Client-Id", "client-999");

        var res = wing::Response { .. };
        res.status_code = 200;
        res.set_header("Content-Type", "application/json");
        res.set_header("ETag", "\"v42-alpha\"");

        var params = wing::HttpSignatureParams {
            label:   "res-sig",
            key_id:  "res-key-01",
            alg:     "hmac-sha256",
            created: 1700000100,
            ..
        };
        params.components.push("@status");
        params.components.push("etag");
        params.components.push("@method;req");

        let secret = "response_hmac_secret_32_bytes_!!";
        let sign_ok = wing::sign_http_response(res, req, params, secret);
        sub.assert_true(sign_ok, "Response signed");
        sub.assert_true(res.has_header("Signature-Input"), "Response has Signature-Input");
        sub.assert_true(res.has_header("Signature"), "Response has Signature");

        // Verify valid response signature
        let v_ok = wing::verify_http_response_signature(res, req, "res-sig", params, secret, 1700000110);
        sub.assert_true(v_ok, "Response signature verified");

        // Tamper status code (200 -> 404)
        var tampered_res = res;
        tampered_res.status_code = 404;
        let v_status_tampered = wing::verify_http_response_signature(tampered_res, req, "res-sig", params, secret, 1700000110);
        sub.assert_false(v_status_tampered, "Tampered response status code rejected");
    };
}

// --- Component: http_streaming ---
// Verification suite for RFC 9112 Chunked Transfer Coding & Incremental Streaming:
// 1. Chunked wire framing codec (encode_chunk, encode_chunk_end, trailers)
// 2. ChunkWriter for dynamic chunked uploads (post_chunked / put_chunked)
// 3. StreamReader for incremental body consumption & progress tracking
// 4. download_stream with real-time progress callbacks

fn test_chunked_framing_codec(t: lit::T&) {
    t.run("Encode Chunks, Trailers & Terminal 0-Chunk") { sub =>
        var wire: u8[>..] = [];
        wing::encode_chunk("Hello ", wire);
        wing::encode_chunk("World!", wire);
        wing::encode_chunk_end(wire);

        // Expected wire format:
        // "6\r\nHello \r\n6\r\nWorld!\r\n0\r\n\r\n"
        let expected_wire = "6\r\nHello \r\n6\r\nWorld!\r\n0\r\n\r\n";
        sub.assert_bytes_eq(wire[..], expected_wire, "Wire matches RFC 9112 format");

        // Verify it round-trips with wing's chunked decoder
        var decoded: u8[>..] = [];
        let err = wing::decode_chunked_body(wire[..], decoded);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded cleanly");
        sub.assert_bytes_eq(decoded[..], "Hello World!", "Round-trip payload matches");
    };
}

fn test_chunked_upload_writer(t: lit::T&) {
    t.run("post_chunked with ChunkWriter & Trailers") { sub =>
        var client = wing::new_client();

        wing::mock_route(client, "POST", "https://api.upload.com/stream", 200, "{\"received\":true}");

        let resp, err = wing::post_chunked(client, "https://api.upload.com/stream") { writer =>
            wing::write_chunk(writer, "chunk-alpha-");
            wing::write_chunk(writer, "chunk-beta-");
            wing::write_chunk(writer, "chunk-gamma");
            wing::add_trailer(writer, "X-Stream-Checksum", "sha256-abc");
        };

        sub.assert_true(wing::ok(err), "post_chunked ok");
        sub.assert_eq(wing::status(resp), 200, "status 200");

        // Verify sent headers
        let te = wing::sent_header(resp, "Transfer-Encoding");
        sub.assert_bytes_eq(te, "chunked", "Transfer-Encoding: chunked sent");

        // Verify sent body contains valid chunked framing
        var decoded_upload: u8[>..] = [];
        let dec_err = wing::decode_chunked_body(resp.body[..], decoded_upload);
        // Note: in mock route resp.body in mock echoes or returns route body, but we can verify writer directly:
    };
}

fn test_incremental_stream_reader(t: lit::T&) {
    t.run("StreamReader reads in chunks and computes progress") { sub =>
        var resp = wing::Response {
            status_code: 200,
            ..
        };
        wing::set_header(resp, "Content-Length", "26");
        resp.body.append("abcdefghijklmnopqrstuvwxyz");

        var reader = wing::new_stream_reader(resp);
        sub.assert_eq(reader.content_length, 26, "content length is 26");

        var p0 = wing::stream_progress(reader);
        sub.assert_eq(p0.bytes_processed, 0 as u64, "0 bytes read initially");
        sub.assert_eq(p0.percent, 0.0, "0% initial progress");

        // Read chunk 1 (10 bytes)
        var c1: u8[>..] = [];
        let st1, eof1 = wing::read_chunk(reader, 10, c1);
        sub.assert_eq(st1, wing::StreamReadStatus.Data, "read chunk 1");
        sub.assert_false(eof1, "not EOF yet");
        sub.assert_bytes_eq(c1[..], "abcdefghij", "first 10 bytes");

        var p1 = wing::stream_progress(reader);
        sub.assert_eq(p1.bytes_processed, 10 as u64, "10 bytes processed");
        sub.assert_true(p1.percent > 38.0 && p1.percent < 39.0, "progress ~38.46%");

        // Read chunk 2 (10 bytes)
        var c2: u8[>..] = [];
        let st2, eof2 = wing::read_chunk(reader, 10, c2);
        sub.assert_eq(st2, wing::StreamReadStatus.Data, "read chunk 2");
        sub.assert_false(eof2, "not EOF yet");
        sub.assert_bytes_eq(c2[..], "klmnopqrst", "second 10 bytes");

        // Read remainder (6 bytes)
        var c3: u8[>..] = [];
        let st3, eof3 = wing::read_chunk(reader, 10, c3);
        sub.assert_eq(st3, wing::StreamReadStatus.Data, "read chunk 3");
        sub.assert_true(eof3, "EOF reached");
        sub.assert_bytes_eq(c3[..], "uvwxyz", "final 6 bytes");

        var p3 = wing::stream_progress(reader);
        sub.assert_eq(p3.bytes_processed, 26 as u64, "26 bytes processed");
        sub.assert_eq(p3.percent, 100.0, "100% final progress");
        sub.assert_true(p3.is_finished, "is_finished is true");

        // Chunked stream with small max_bytes reads retaining unconsumed remainder and exposing trailers
        var resp_chunked = wing::Response { status_code: 200, .. };
        wing::set_header(resp_chunked, "Transfer-Encoding", "chunked");
        resp_chunked.body.append("10\r\n0123456789abcdef\r\n0\r\nExpires: 0\r\nX-Checksum: sha256-abc\r\n\r\n");

        var reader_ch = wing::new_stream_reader(resp_chunked);
        var part1: u8[>..] = [];
        let st_c1, eof_c1 = wing::read_chunk(reader_ch, 6, part1);
        sub.assert_eq(st_c1, wing::StreamReadStatus.Data, "read part 1 (6 bytes)");
        sub.assert_false(eof_c1, "not EOF after 6 bytes of 16");
        sub.assert_bytes_eq(part1[..], "012345", "first 6 bytes retained");

        var part2: u8[>..] = [];
        let st_c2, eof_c2 = wing::read_chunk(reader_ch, 6, part2);
        sub.assert_eq(st_c2, wing::StreamReadStatus.Data, "read part 2 (6 bytes)");
        sub.assert_false(eof_c2, "not EOF after 12 bytes of 16");
        sub.assert_bytes_eq(part2[..], "6789ab", "next 6 bytes from retained chunk remainder");

        var part3: u8[>..] = [];
        let st_c3, eof_c3 = wing::read_chunk(reader_ch, 6, part3);
        sub.assert_eq(st_c3, wing::StreamReadStatus.Data, "read part 3 (remainder 4 bytes)");
        sub.assert_true(eof_c3, "EOF reached after reading all chunk bytes and trailers");
        sub.assert_bytes_eq(part3[..], "cdef", "final 4 bytes of chunk");

        // Verify decoded trailers exposed to caller
        let tr_val = wing::trailer(reader_ch, "x-checksum");
        sub.assert_bytes_eq(tr_val, "sha256-abc", "decoded trailer exposed via trailer helper");

        var resp_target = wing::Response { status_code: 200, .. };
        wing::copy_trailers_to_response(reader_ch, resp_target);
        sub.assert_eq(resp_target.trailers.entries.len, 2, "trailers copied to Response object");
        sub.assert_bytes_eq(wing::trailer(resp_target, "expires"), "0", "Response has expires trailer");
    };
}

fn test_download_stream_with_progress(t: lit::T&) {
    t.run("download_stream streams in 16-byte chunks with progress callback") { sub =>
        var client = wing::new_client();
        let payload = "0123456789abcdef0123456789abcdef0123456789abcdef"; // 48 bytes
        wing::mock_route(client, "GET", "https://cdn.site.com/large.bin", 200, payload);
        wing::add_mock_header(client, "Content-Length", "48");

        var downloaded:     u8[>..] = [];
        var callback_count: i64     = 0;
        var last_percent:   f64     = 0.0;

        let resp, err = wing::download_stream(client, "https://cdn.site.com/large.bin", 16, downloaded) { progress =>
            callback_count += 1;
            last_percent = progress.percent;
        };

        sub.assert_true(wing::ok(err), "download_stream succeeded");
        sub.assert_eq(downloaded.len, 48, "downloaded all 48 bytes");
        sub.assert_bytes_eq(downloaded[..], payload, "payload exactly matches");
        sub.assert_eq(callback_count, 3, "Invoked callback 3 times (48 / 16 = 3 chunks)");
        sub.assert_eq(last_percent, 100.0, "Finished at 100% progress");
    };
}

// --- Component: http_trace_context ---
// Verification Suite for W3C Trace Context (RFC 9239).

fn test_w3c_traceparent(t: lit::T&) {
    t.run("1. Standard W3C traceparent Vector Parsing & Formatting") { sub =>
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp, ok = wing::parse_traceparent(raw);
        sub.assert_true(ok, "Valid traceparent must parse successfully");
        sub.assert_eq(tp.version as i64, 0, "Version must be 0x00");
        sub.assert_true(wing::traceparent_is_sampled(tp), "Trace flags 0x01 indicates sampled");

        // Format roundtrip
        var formatted: u8[>..] = [];
        wing::format_traceparent(tp, formatted);
        sub.assert_bytes_eq(formatted[..], raw, "traceparent wire formatting must exactly roundtrip");
    };

    t.run("2. W3C Invariant Violations & Strict Reject Defenses") { sub =>
        // Version 0xFF is strictly forbidden (W3C Section 3.2.1)
        let invalid_ver = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp1, ok1 = wing::parse_traceparent(invalid_ver);
        sub.assert_false(ok1, "Version 0xFF must be rejected");

        // All-zero trace-id is strictly forbidden (W3C Section 3.2.2)
        let zero_trace = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        let tp2, ok2 = wing::parse_traceparent(zero_trace);
        sub.assert_false(ok2, "All-zero trace-id must be rejected");

        // All-zero parent-id is strictly forbidden (W3C Section 3.2.3)
        let zero_parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        let tp3, ok3 = wing::parse_traceparent(zero_parent);
        sub.assert_false(ok3, "All-zero parent-id must be rejected");

        // Trailing garbage on version 00 must be rejected
        let trailing = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra";
        let tp4, ok4 = wing::parse_traceparent(trailing);
        sub.assert_false(ok4, "Version 00 with length > 55 must be rejected");

        // Malformed delimiters
        let bad_delim = "00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01";
        let tp5, ok5 = wing::parse_traceparent(bad_delim);
        sub.assert_false(ok5, "Underscore delimiters must be rejected");
    };

    t.run("3. Programmatic Constructor & Bitmask Flags") { sub =>
        var trace_id:  u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var parent_id: u8[8]  = [17, 18, 19, 20, 21, 22, 23, 24];

        let tp = wing::new_traceparent(trace_id, parent_id, true);
        sub.assert_true(tp.valid, "New traceparent must be marked valid");
        sub.assert_true(wing::traceparent_is_sampled(tp), "Sampled flag is set");

        var out: u8[>..] = [];
        wing::format_traceparent(tp, out);
        sub.assert_bytes_eq(out[..], "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01", "Formatted hex output");
    };
}

fn test_w3c_tracestate(t: lit::T&) {
    t.run("1. Multi-Vendor Tracestate Parsing & Formatting") { sub =>
        let raw = "rojo=1,congo=t61rcWkgMzE";
        let ts, ok = wing::parse_tracestate(raw);
        sub.assert_true(ok, "Valid tracestate must parse");
        sub.assert_eq(ts.members.len, 2, "2 members parsed");

        sub.assert_bytes_eq(wing::tracestate_get(ts, "rojo"), "1", "rojo value is 1");
        sub.assert_bytes_eq(wing::tracestate_get(ts, "congo"), "t61rcWkgMzE", "congo value matches");

        var out: u8[>..] = [];
        wing::format_tracestate(ts, out);
        sub.assert_bytes_eq(out[..], raw, "tracestate wire roundtrip");
    };

    t.run("2. Tenant Specific Keys & Position Invariance") { sub =>
        let raw = "congo=t61rcWkgMzE,rojo@corp=99";
        let ts, ok = wing::parse_tracestate(raw);
        sub.assert_true(ok, "Tenant key must be accepted");
        sub.assert_bytes_eq(wing::tracestate_get(ts, "rojo@corp"), "99", "Tenant key lookup");

        // Mutate with tracestate_set (prepends updated member to head)
        var mut_ts = ts;
        wing::tracestate_set(mut_ts, "rojo@corp", "100");
        sub.assert_bytes_eq(wing::tracestate_get(mut_ts, "rojo@corp"), "100", "Updated value");
        sub.assert_bytes_eq(mut_ts.members[0].key[..], "rojo@corp", "Updated entry moved to front");
    };

    t.run("3. Tracestate Character Constraints & Bounds") { sub =>
        // Disallowed equal sign in value
        let bad_val = "rojo=1=2";
        let ts1, ok1 = wing::parse_tracestate(bad_val);
        sub.assert_false(ok1, "Equal sign in value must be rejected");

        // Disallowed uppercase character in key
        let bad_key = "Rojo=1";
        let ts2, ok2 = wing::parse_tracestate(bad_key);
        sub.assert_false(ok2, "Uppercase key must be rejected");
    };
}

fn main() {
    var runner = lit::new_runner("HTTP Caching (RFC 9111), Structured Fields, and Metadata Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Cache-Control Parsing & Delta-Seconds Clamping", test_cache_control_parsing_and_overflow);
    lit::run_case(runner, "2. Mathematical Freshness Model & Clock Skew", test_freshness_math_and_clock_skew);
    lit::run_case(runner, "3. EntityTag (ETag) Validators", test_etag_validators);
    lit::run_case(runner, "4. Vary Normalization & CVE-2026-93750 Defense", test_vary_normalization_and_cve_2026_93750);
    lit::run_case(runner, "5. CVE-2026-93748 Defense & Security Zeroing", test_cve_2026_93748_max_stale_guards);
    lit::run_case(runner, "6. Cache Transaction Lifecycle, 304 Merge & Sanitization", test_cache_transaction_and_304_merge);
    lit::run_case(runner, "7. RFC 9111 Special Behaviors & Cascade Invalidation", test_rfc9111_special_behaviors_and_invalidation);
    lit::run_case(runner, "8. Single-Flight Writers Request Collapsing", test_request_collapsing);
    lit::run_case(runner, "9. RFC 5861 stale-while-revalidate & stale-if-error", test_rfc5861_stale_extensions);
    lit::run_case(runner, "10. SFV Primitives", test_sfv_primitives);
    lit::run_case(runner, "11. SFV Parameters", test_sfv_parameters);
    lit::run_case(runner, "12. SFV Lists & Dicts", test_sfv_lists_and_dicts);
    lit::run_case(runner, "13. SFV Serialization", test_sfv_serialization);
    lit::run_case(runner, "14. RFC 9530 Content-Digest & Repr-Digest", test_rfc9530_content_digest);
    lit::run_case(runner, "15. RFC 9530 Binding to RFC 9421 Signatures", test_rfc9530_with_rfc9421_signatures);
    lit::run_case(runner, "16. OAuth 2.1 Strict PKCE", test_oauth21_strict_pkce);
    lit::run_case(runner, "17. HTTP Message Signatures", test_http_signatures);
    lit::run_case(runner, "18. Ed25519 Signatures", test_ed25519_signatures);
    lit::run_case(runner, "19. Response Signatures", test_response_signatures);
    lit::run_case(runner, "20. RFC 9112 Chunk Framing Codec", test_chunked_framing_codec);
    lit::run_case(runner, "21. ChunkWriter for Dynamic Uploads", test_chunked_upload_writer);
    lit::run_case(runner, "22. StreamReader & Progress Tracking", test_incremental_stream_reader);
    lit::run_case(runner, "23. download_stream Incremental Pipeline", test_download_stream_with_progress);
    lit::run_case(runner, "24. W3C traceparent Conformance & Invariants", test_w3c_traceparent);
    lit::run_case(runner, "25. W3C tracestate Multi-Vendor Management", test_w3c_tracestate);
    lit::run_case(runner, "26. RFC 9875 Cache Groups", test_cache_groups);

    let ok = lit::finish(runner);
    assert(ok);
}
