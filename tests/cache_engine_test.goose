// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Comprehensive verification suite for RFC 9111 HTTP Caching Engine.
// Verifies Cache-Control parsing, freshness calculations, ETag validators,
// Vary matching, CVE-2026-93750 & CVE-2026-93748 defenses, 304 header merge,
// request collapsing, and unsafe method cascade invalidation.
import std;
import core from "..";
import wing from "..";

// ---- 1. Cache-Control Parsing & Delta-Seconds Clamping ----------------------

fn test_cache_control_parsing_and_overflow(t: core::T&) {
    t.run("Standard Boolean Directives & Bitmask Compression") { sub =>
        var cc = wing::new_cache_control();
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
        var cc = wing::new_cache_control();
        let raw = "max-age=3600, s-maxage=7200, min-fresh=60, max-stale=300";
        wing::parse_cache_control_str(raw, cc);

        sub.assert_eq(cc.max_age, 3600, "max-age 3600 parsed");
        sub.assert_eq(cc.s_maxage, 7200, "s-maxage 7200 parsed");
        sub.assert_eq(cc.min_fresh, 60, "min-fresh 60 parsed");
        sub.assert_eq(cc.max_stale, 300, "max-stale 300 parsed");

        // Clamping overflow to 2147483647
        var cc_over = wing::new_cache_control();
        wing::parse_cache_control_str("max-age=9999999999999", cc_over);
        sub.assert_eq(cc_over.max_age, wing::MAX_DELTA_SECONDS, "max-age clamped to i32::MAX");

        // Unbounded max-stale
        var cc_unbounded = wing::new_cache_control();
        wing::parse_cache_control_str("max-stale", cc_unbounded);
        sub.assert_true(wing::has_max_stale(cc_unbounded), "has max-stale flag");
        sub.assert_eq(cc_unbounded.max_stale, -1, "unbounded max-stale is -1");
    };

    t.run("Corrupted Freshness Parameters Set INVALID_FRESHNESS Flag") { sub =>
        var cc_bad = wing::new_cache_control();
        wing::parse_cache_control_str("max-age=corrupted_string", cc_bad);
        sub.assert_true(wing::has_invalid_freshness(cc_bad), "Corrupted max-age flagged invalid");

        var cc_bad_s = wing::new_cache_control();
        wing::parse_cache_control_str("s-maxage=123xyz", cc_bad_s);
        sub.assert_true(wing::has_invalid_freshness(cc_bad_s), "Alphanumeric s-maxage flagged invalid");
    };

    t.run("Qualified Lists & Pragma Fallback & Cargo-Cult Filtering") { sub =>
        var cc_qual = wing::new_cache_control();
        wing::parse_cache_control_str("private=\"Set-Cookie, X-Custom\", no-cache=\"X-Token\"", cc_qual);
        sub.assert_true(wing::is_private(cc_qual), "is private");
        sub.assert_true(wing::is_private_field(cc_qual, "Set-Cookie"), "Set-Cookie is private field");
        sub.assert_true(wing::is_private_field(cc_qual, "x-custom"), "X-Custom is private field (case-insensitive)");
        sub.assert_false(wing::is_private_field(cc_qual, "Content-Type"), "Content-Type is not private field");
        sub.assert_true(wing::is_no_cache_field(cc_qual, "X-Token"), "X-Token is no-cache field");

        // Cargo-cult pre-check/post-check ignored without error
        var cc_cult = wing::new_cache_control();
        wing::parse_cache_control_str("max-age=3600, pre-check=0, post-check=0", cc_cult, true);
        sub.assert_eq(cc_cult.max_age, 3600, "max-age parsed despite cargo-cult directives");

        // Pragma: no-cache fallback
        var map = wing::new_header_map();
        wing::append_header(map, "Pragma", "no-cache");
        let cc_pragma = wing::parse_cache_control_headers(map, true);
        sub.assert_true(wing::is_no_cache(cc_pragma), "Pragma: no-cache promoted to CacheControl::no-cache");
    };
}

// ---- 2. Mathematical Freshness Model & Clock Skew ---------------------------

fn test_freshness_math_and_clock_skew(t: core::T&) {
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
        sub.assert_eq(parsed_over, wing::MAX_DELTA_SECONDS, "Age overflow clamped to i32::MAX");

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
        var cc_bad = wing::new_cache_control();
        cc_bad.flags |= wing::CC_INVALID_FRESHNESS;
        var hdrs = wing::new_header_map();
        let lt_bad = wing::compute_freshness_lifetime(cc_bad, hdrs, ts);
        sub.assert_eq(lt_bad, 0, "Corrupted freshness forces lifetime 0");

        // 2. Shared cache: s-maxage overrides max-age
        var cc_shared = wing::new_cache_control();
        cc_shared.flags |= wing::CC_HAS_MAX_AGE | wing::CC_HAS_S_MAXAGE;
        cc_shared.max_age = 3600;
        cc_shared.s_maxage = 7200;
        let lt_shared = wing::compute_freshness_lifetime(cc_shared, hdrs, ts, true);
        sub.assert_eq(lt_shared, 7200, "s-maxage overrides max-age in shared cache");

        // 3. Private cache: max-age takes precedence
        let lt_priv = wing::compute_freshness_lifetime(cc_shared, hdrs, ts, false);
        sub.assert_eq(lt_priv, 3600, "max-age used in private cache");

        // 4. Immutable directive
        var cc_imm = wing::new_cache_control();
        cc_imm.flags |= wing::CC_IMMUTABLE;
        let lt_imm = wing::compute_freshness_lifetime(cc_imm, hdrs, ts, false, 10, 86400);
        sub.assert_eq(lt_imm, 86400, "immutable sets configured minimum ttl");

        // 5. Heuristic 10% of (Date - Last-Modified) for 200 OK
        var cc_empty = wing::new_cache_control();
        var hdrs_lm = wing::new_header_map();
        hdrs_lm.status_code = 200;
        wing::append_header(hdrs_lm, "Date", "Sun, 06 Nov 1994 09:00:00 GMT");
        wing::append_header(hdrs_lm, "Last-Modified", "Sun, 06 Nov 1994 08:00:00 GMT"); // 3600s delta
        let lt_heur = wing::compute_freshness_lifetime(cc_empty, hdrs_lm, ts);
        sub.assert_eq(lt_heur, 360, "Heuristic is 10% of 3600s = 360s");
    };
}

// ---- 3. EntityTag (ETag) Validators -----------------------------------------

fn test_etag_validators(t: core::T&) {
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
    };
}

// ---- 4. Vary Normalization & CVE-2026-93750 Defense -------------------------

fn test_vary_normalization_and_cve_2026_93750(t: core::T&) {
    t.run("CVE-2026-93750: Vary: * Unconditional Hard Rejection") { sub =>
        var req_hdrs = wing::new_header_map();
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
        var req_1 = wing::new_header_map();
        wing::append_header(req_1, "Accept-Encoding", "gzip");

        let snap = wing::record_vary_snapshot("Accept-Encoding, User-Agent", req_1);

        // Incoming Request 2: matches Accept-Encoding: gzip, User-Agent is also absent -> PASS
        var req_2 = wing::new_header_map();
        wing::append_header(req_2, "Accept-Encoding", "gzip");
        sub.assert_true(wing::matches_vary(snap, req_2), "Matches when User-Agent is simultaneously absent in both requests");

        // Incoming Request 3: has User-Agent present -> MUST FAIL simultaneous absence invariant!
        var req_3 = wing::new_header_map();
        wing::append_header(req_3, "Accept-Encoding", "gzip");
        wing::append_header(req_3, "User-Agent", "Mozilla/5.0");
        sub.assert_false(wing::matches_vary(snap, req_3), "Fails when header was absent originally but present in incoming request");

        // Incoming Request 4: different Accept-Encoding -> FAIL
        var req_4 = wing::new_header_map();
        wing::append_header(req_4, "Accept-Encoding", "br");
        sub.assert_false(wing::matches_vary(snap, req_4), "Fails on Accept-Encoding mismatch");
    };
}

// ---- 5. CVE-2026-93748 Defense & Security Zeroing --------------------------

fn test_cve_2026_93748_max_stale_guards(t: core::T&) {
    t.run("CVE-2026-93748: Blocking max-stale on must-revalidate / s-maxage / security-zeroed") { sub =>
        let t_req = core::unix(100, 0);
        let t_resp = core::unix(100, 0);
        let t_now = core::unix(500, 0); // Well past expiration (stale)
        let ts = wing::new_cache_timestamps(t_req, t_resp, t_now);

        var hdrs = wing::new_header_map();

        // Client request with max-stale=1000
        var req_cc = wing::new_cache_control();
        req_cc.flags |= wing::CC_HAS_MAX_STALE;
        req_cc.max_stale = 1000;

        // Case A: Ordinary stale response (max-age=100) -> max-stale ALLOWED
        var cc_normal = wing::new_cache_control();
        cc_normal.flags |= wing::CC_HAS_MAX_AGE;
        cc_normal.max_age = 100;
        let m_normal = wing::evaluate_freshness(cc_normal, req_cc, hdrs, ts);
        sub.assert_false(m_normal.is_fresh, "Entry is not fresh");
        sub.assert_true(m_normal.stale_allowed, "Normal stale response allowed by max-stale");

        // Case B: must-revalidate present -> max-stale STRICTLY BLOCKED!
        var cc_must_rev = wing::new_cache_control();
        cc_must_rev.flags |= wing::CC_HAS_MAX_AGE | wing::CC_MUST_REVALIDATE;
        cc_must_rev.max_age = 100;
        let m_must_rev = wing::evaluate_freshness(cc_must_rev, req_cc, hdrs, ts);
        sub.assert_false(m_must_rev.stale_allowed, "max-stale strictly blocked when must-revalidate is present");

        // Case C: s-maxage present -> max-stale STRICTLY BLOCKED!
        var cc_s_max = wing::new_cache_control();
        cc_s_max.flags |= wing::CC_HAS_MAX_AGE | wing::CC_HAS_S_MAXAGE;
        cc_s_max.max_age = 100;
        cc_s_max.s_maxage = 100;
        let m_s_max = wing::evaluate_freshness(cc_s_max, req_cc, hdrs, ts, true);
        sub.assert_false(m_s_max.stale_allowed, "max-stale strictly blocked when s-maxage is present");

        // Case D: proxy-revalidate in shared cache -> max-stale STRICTLY BLOCKED!
        var cc_proxy_rev = wing::new_cache_control();
        cc_proxy_rev.flags |= wing::CC_HAS_MAX_AGE | wing::CC_PROXY_REVALIDATE;
        cc_proxy_rev.max_age = 100;
        let m_proxy = wing::evaluate_freshness(cc_proxy_rev, req_cc, hdrs, ts, true);
        sub.assert_false(m_proxy.stale_allowed, "max-stale strictly blocked when proxy-revalidate in shared cache");

        // Case E: security_zeroed = true -> max-stale STRICTLY BLOCKED!
        let m_zeroed = wing::evaluate_freshness(cc_normal, req_cc, hdrs, ts, false, true);
        sub.assert_false(m_zeroed.stale_allowed, "max-stale strictly blocked on security_zeroed invalidated entry");
    };
}

// ---- 6. Cache Transaction Lifecycle, 304 Merge & Sanitization ---------------

fn test_cache_transaction_and_304_merge(t: core::T&) {
    t.run("Lookup Miss -> Store -> Hit Lifecycle with Age Header") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);

        // 1. Initial request -> Cache Miss
        let req = wing::new_get("https://example.com/api/data");
        let dec_1 = wing::lookup(cache, req, t0);
        sub.assert_true(dec_1.kind == wing::LookupResultKind.Miss, "Initial lookup is Miss");

        // 2. Origin returns 200 OK with max-age=3600
        var resp = wing::new_response();
        resp.status_code = 200;
        resp.effective_url.append("https://example.com/api/data");
        let h_cc = wing::make_header("Cache-Control", "max-age=3600");
        let h_etag = wing::make_header("ETag", "\"data-v1\"");
        resp.headers.push(h_cc);
        resp.headers.push(h_etag);
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
        var resp = wing::new_response();
        resp.status_code = 200;
        resp.effective_url.append("https://example.com/resource");
        resp.headers.push(wing::make_header("Cache-Control", "max-age=60"));
        resp.headers.push(wing::make_header("ETag", "\"tag-abc\""));
        resp.headers.push(wing::make_header("Content-Type", "text/html"));
        resp.headers.push(wing::make_header("Strict-Transport-Security", "max-age=31536000"));
        resp.body.append("<html>content</html>");

        let ts0 = wing::new_cache_timestamps(t0, t0, t0);
        wing::on_response(cache, req, resp, ts0);

        // Advance time to t=1200 (stale by 140s)
        let t_stale = core::unix(1200, 0);
        let dec_stale = wing::lookup(cache, req, t_stale);
        sub.assert_true(dec_stale.kind == wing::LookupResultKind.Revalidate, "Lookup returns Revalidate");
        sub.assert_bytes_eq(wing::get_header(dec_stale.conditional_headers, "If-None-Match"), "\"tag-abc\"", "If-None-Match built");

        // Origin returns 304 Not Modified with fresh Cache-Control: max-age=7200
        var resp_304 = wing::new_response();
        resp_304.status_code = 304;
        resp_304.headers.push(wing::make_header("Cache-Control", "max-age=7200"));
        resp_304.headers.push(wing::make_header("X-Fresh-Note", "updated"));
        // Attempt to corrupt Content-Type and HSTS in 304
        resp_304.headers.push(wing::make_header("Content-Type", "application/poison"));
        resp_304.headers.push(wing::make_header("Strict-Transport-Security", "max-age=0"));

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
}

// ---- 7. RFC 9111 Special Behaviors & Cascade Invalidation -------------------

fn test_rfc9111_special_behaviors_and_invalidation(t: core::T&) {
    t.run("only-if-cached Returns 504 on Cache Miss and Stale") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);

        var req = wing::new_get("https://example.com/missing");
        wing::header(req, "Cache-Control", "only-if-cached");

        let dec = wing::lookup(cache, req, t0);
        sub.assert_true(dec.kind == wing::LookupResultKind.Fail504, "only-if-cached returns Fail504 on miss");
        sub.assert_eq(dec.status_code, 504, "Fail504 sets status 504 Gateway Timeout");
    };

    t.run("must-understand Status Whitelist Protection") { sub =>
        var cache = wing::new_http_cache();
        let t0 = core::unix(1000, 0);
        let req = wing::new_get("https://example.com/custom");

        // Unknown status code 299 with must-understand -> MUST NOT be stored
        var resp = wing::new_response();
        resp.status_code = 299;
        resp.headers.push(wing::make_header("Cache-Control", "max-age=3600, must-understand"));
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
        var resp_head = wing::new_response();
        resp_head.status_code = 200;
        resp_head.effective_url.append("https://example.com/asset.png");
        resp_head.headers.push(wing::make_header("Cache-Control", "max-age=3600"));
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
        var resp1 = wing::new_response();
        resp1.status_code = 200;
        resp1.effective_url.append("https://example.com/api/items");
        resp1.headers.push(wing::make_header("Cache-Control", "max-age=3600"));
        resp1.body.append("[1, 2, 3]");
        wing::on_response(cache, req1, resp1, ts);

        let req2 = wing::new_get("https://example.com/api/items/42");
        var resp2 = wing::new_response();
        resp2.status_code = 200;
        resp2.effective_url.append("https://example.com/api/items/42");
        resp2.headers.push(wing::make_header("Cache-Control", "max-age=3600"));
        resp2.body.append("{\"id\": 42}");
        wing::on_response(cache, req2, resp2, ts);

        sub.assert_eq(cache.entries.len, 2, "2 entries initially cached");

        // Succeeded POST request to /api/items with Location: https://example.com/api/items/42
        var post_req = wing::new_post("https://example.com/api/items");
        var post_resp = wing::new_response();
        post_resp.status_code = 201; // Created
        post_resp.headers.push(wing::make_header("Location", "https://example.com/api/items/42"));

        wing::on_response(cache, post_req, post_resp, ts);

        // Both /api/items and /api/items/42 must be invalidated!
        let dec_check1 = wing::lookup(cache, req1, t0);
        sub.assert_true(dec_check1.kind == wing::LookupResultKind.Miss, "Target URI invalidated by POST");

        let dec_check2 = wing::lookup(cache, req2, t0);
        sub.assert_true(dec_check2.kind == wing::LookupResultKind.Miss, "Same-origin Location URI invalidated by POST");

        sub.assert_true(cache.entries[0].security_zeroed, "Entry 1 security_zeroed");
        sub.assert_true(cache.entries[1].security_zeroed, "Entry 2 security_zeroed");
    };
}

// ---- 8. Single-Flight / Request Collapsing ---------------------------------

fn test_request_collapsing(t: core::T&) {
    t.run("Single-Flight Writers Collapsing Concurrent Requests") { sub =>
        var writers = wing::new_cache_writers();
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
        sub.assert_eq(writers.flights.len, 0, "Flight cleanly finished and removed");
    };
}

fn test_rfc5861_stale_extensions(t: core::T&) {
    t.run("1. RFC 5861 Section 3: stale-while-revalidate Cache Decision") { sub =>
        var cache = wing::new_http_cache();
        var ts = wing::CacheTimestamps {
            request_time: core::unix(1700000000, 0),
            response_time: core::unix(1700000001, 0),
            ..
        };

        // Populate cache with max-age=60, stale-while-revalidate=120
        var req = wing::new_request("GET", "https://api.example.com/feed");
        var resp = wing::new_response();
        resp.status_code = 200;
        wing::header(resp, "cache-control", "max-age=60, stale-while-revalidate=120");
        wing::header(resp, "etag", "\"feed-v1\"");
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
            request_time: core::unix(1700000000, 0),
            response_time: core::unix(1700000001, 0),
            ..
        };

        // Populate cache with max-age=60, stale-if-error=300
        var req = wing::new_request("GET", "https://api.example.com/prices");
        var resp = wing::new_response();
        resp.status_code = 200;
        wing::header(resp, "cache-control", "max-age=60, stale-if-error=300");
        wing::header(resp, "etag", "\"prices-v1\"");
        resp.body.append("Price: $42.00");

        let dec_store = wing::on_response(cache, req, resp, ts);
        sub.assert_eq(dec_store.kind, wing::ResponseDecisionKind.StoreAndReturn, "Initial prices stored");

        // At t = +150s, entry is stale (max-age=60 expired)
        // Client performs revalidation request to origin
        let t_reval = core::unix(1700000150, 0);
        let dec_req = wing::lookup(cache, req, t_reval);
        sub.assert_eq(dec_req.kind, wing::LookupResultKind.Revalidate, "Entry requires revalidation");

        // Origin fails and returns 503 Service Unavailable
        var resp_503 = wing::new_response();
        resp_503.status_code = 503;
        var ts_503 = wing::CacheTimestamps {
            request_time: t_reval,
            response_time: t_reval,
            ..
        };

        let dec_err = wing::on_response(cache, req, resp_503, ts_503, dec_req.entry_idx);
        sub.assert_eq(dec_err.kind, wing::ResponseDecisionKind.FreshenAndReturn, "503 triggers stale-if-error fallback");
        sub.assert_bytes_eq(dec_err.response.body[..], "Price: $42.00", "Cached prices returned to caller despite 503");
    };
}

// ---- Main Test Runner Entrypoint -------------------------------------------

fn main() {
    var runner = core::new_runner("RFC 9111 & RFC 5861 HTTP Caching Engine Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Cache-Control Parsing & Delta-Seconds Clamping", test_cache_control_parsing_and_overflow);
    core::run_case(runner, "2. Mathematical Freshness Model & Clock Skew", test_freshness_math_and_clock_skew);
    core::run_case(runner, "3. EntityTag (ETag) Validators", test_etag_validators);
    core::run_case(runner, "4. Vary Normalization & CVE-2026-93750 Defense", test_vary_normalization_and_cve_2026_93750);
    core::run_case(runner, "5. CVE-2026-93748 Defense & Security Zeroing", test_cve_2026_93748_max_stale_guards);
    core::run_case(runner, "6. Cache Transaction Lifecycle, 304 Merge & Sanitization", test_cache_transaction_and_304_merge);
    core::run_case(runner, "7. RFC 9111 Special Behaviors & Cascade Invalidation", test_rfc9111_special_behaviors_and_invalidation);
    core::run_case(runner, "8. Single-Flight Writers Request Collapsing", test_request_collapsing);
    core::run_case(runner, "9. RFC 5861 stale-while-revalidate & stale-if-error", test_rfc5861_stale_extensions);

    let ok = core::finish(runner);
    assert(ok);
}
