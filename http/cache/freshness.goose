// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9111 Section 4.2: Mathematical time and freshness calculation engine.
// Implements apparent age, response delay, corrected initial age, resident time,
// and hierarchical freshness lifetime calculations with clock skew & monotonic protection.
namespace http;

import std;
import core from "../..";
import http.headers;
import http.cache.cache_control;
import http.cache.internal;

// ---- cache timestamps & clock model ----------------------------------------

// Wall-clock (Unix seconds) and monotonic (nanoseconds) timestamps captured across request/response lifecycle.
struct CacheTimestamps {
    request_sec:      i64  = 0,
    response_sec:     i64  = 0,
    now_sec:          i64  = 0,
    request_mono_ns:  u64  = 0,
    response_mono_ns: u64  = 0,
    now_mono_ns:      u64  = 0,
    has_monotonic:    bool = false,
    clock_available:  bool = true,
}

// Constructs CacheTimestamps with specified wall-clock unix seconds.
fn new_cache_timestamps(req_sec: i64, resp_sec: i64, cur_now_sec: i64) -> CacheTimestamps {
    return CacheTimestamps {
        request_sec:     req_sec,
        response_sec:    resp_sec,
        now_sec:         cur_now_sec,
        clock_available: true,
        ..
    };
}

// Returns a copy of ts with monotonic clock nanosecond timestamps recorded.
fn with_monotonic(
    ts:           CacheTimestamps,
    req_mono_ns:  u64,
    resp_mono_ns: u64,
    cur_mono_ns:  u64,
) -> CacheTimestamps {
    var updated = ts;
    updated.request_mono_ns = req_mono_ns;
    updated.response_mono_ns = resp_mono_ns;
    updated.now_mono_ns = cur_mono_ns;
    updated.has_monotonic = true;
    return updated;
}

// ---- freshness evaluation result -------------------------------------------

// Freshness evaluation metrics and decision flags.
struct FreshnessMetrics {
    current_age_sec:                i64  = 0,
    freshness_lifetime_sec:         i64  = 0,
    is_fresh:                       bool = false,
    requires_revalidation:          bool = false,
    stale_allowed:                  bool = false,
    stale_while_revalidate_allowed: bool = false,
    stale_if_error_allowed:         bool = false,
}

// ---- age header parser -----------------------------------------------------

// Parses Age header delta-seconds, selecting the first member if multiple present (RFC 9111 §5.1).
// Clamps values exceeding i32::MAX to 2147483647. Returns 0 for negative or malformed values.
//
// Example:
//   raw_age = "120"
//   returns: 120
fn parse_age_header(raw_age: const u8[:]) -> i64 {
    var s = raw_age.trim_lws();
    guard s.len > 0 else { return 0; }

    var comma_idx: i64 = -1;
    for i in s.len {
        if s[i] == ',' {
            comma_idx = i;
            break;
        }
    }
    if comma_idx >= 0 {
        s = s[..comma_idx].trim_lws();
    }
    guard s.len > 0 else { return 0; }

    var val: i64 = 0;
    for b in s {
        guard b >= '0' && b <= '9' else {
            return 0;
        }
        val = min(val * 10 + (b - '0'), rfc::MAX_DELTA_SECONDS);
    }
    return val;
}

// ---- rfc 9111 section 4.2.3: age calculations ------------------------------

// Computes apparent_age = max(0, response_sec - date_sec).
fn compute_apparent_age(response_sec: i64, date_sec: i64) -> i64 {
    let diff = response_sec - date_sec;
    return max(0, diff);
}

// Computes response_delay = max(0, response_time - request_time).
// Uses monotonic clock when available to avoid NTP step skew.
fn compute_response_delay(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = core::duration_since(
            core::MonotonicInstant { nanos: ts.response_mono_ns },
            core::MonotonicInstant { nanos: ts.request_mono_ns },
        );
        return max(0, dur.as_secs());
    }
    return max(0, core::sub_sat_i64(ts.response_sec, ts.request_sec));
}

// Computes corrected_initial_age = max(apparent_age, age_hdr + response_delay).
fn compute_corrected_initial_age(apparent_age: i64, age_hdr: i64, response_delay: i64) -> i64 {
    return max(apparent_age, core::add_sat_i64(age_hdr, response_delay));
}

// Computes resident_time = max(0, now - response_time).
// Protected by monotonic clock to guarantee non-decreasing values.
fn compute_resident_time(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = core::duration_since(
            core::MonotonicInstant { nanos: ts.now_mono_ns },
            core::MonotonicInstant { nanos: ts.response_mono_ns },
        );
        return max(0, dur.as_secs());
    }
    return max(0, core::sub_sat_i64(ts.now_sec, ts.response_sec));
}

// Computes current_age = corrected_initial_age + resident_time.
fn compute_current_age(apparent_age: i64, age_hdr: i64, ts: const CacheTimestamps&) -> i64 {
    let delay = compute_response_delay(ts);
    let initial_age = compute_corrected_initial_age(apparent_age, age_hdr, delay);
    let resident = compute_resident_time(ts);
    return min(core::add_sat_i64(initial_age, resident), rfc::MAX_DELTA_SECONDS);
}

// ---- freshness lifetime helpers --------------------------------------------

// Computes freshness lifetime according to RFC 9111 priority hierarchy.
// Evaluates s-maxage (shared) > max-age > Expires > immutable > Last-Modified heuristic.
fn compute_freshness_lifetime(
    resp_cc:               const CacheControl&,
    resp_headers:          const HeaderMap&,
    ts:                    const CacheTimestamps&,
    shared:                bool = false,
    heuristic_fraction:    i64  = 10,
    immutable_min_ttl_sec: i64  = 31536000,
) -> i64 {
    guard !has_invalid_freshness(resp_cc) else { return 0; }

    if shared && has_s_maxage(resp_cc) && resp_cc.s_maxage >= 0 {
        return resp_cc.s_maxage;
    }
    if has_max_age(resp_cc) && resp_cc.max_age >= 0 {
        return resp_cc.max_age;
    }

    let exp_lt, ok_exp = http_internal::compute_expires_lifetime(resp_headers, ts.response_sec);
    if ok_exp { return exp_lt; }

    if is_immutable(resp_cc) {
        return immutable_min_ttl_sec;
    }

    return http_internal::compute_last_modified_heuristic(resp_headers, ts.response_sec, heuristic_fraction);
}

// ---- freshness evaluation against request & response directives -------------

// Policy options governing cache freshness, max-stale allowance, and security overrides.
struct FreshnessPolicy {
    shared:          bool = false,
    security_zeroed: bool = false,
}

// Checks whether max-stale serving is strictly prohibited
// (RFC 9111 Section 5.2.2.1 max-stale prohibition under must-revalidate).
fn is_max_stale_blocked(resp_cc: const CacheControl&, policy: FreshnessPolicy) -> bool {
    if is_must_revalidate(resp_cc) { return true; }
    if policy.shared && is_proxy_revalidate(resp_cc) { return true; }
    if policy.shared && has_s_maxage(resp_cc) { return true; }
    if policy.security_zeroed { return true; }
    return false;
}

// Evaluates whether cached response satisfies request freshness constraints or requires revalidation.
// Enforces max-age, min-fresh, and RFC 9111 Section 5.2.2.1 max-stale prohibition under must-revalidate.
fn evaluate_freshness(
    resp_cc:               const CacheControl&,
    req_cc:                const CacheControl&,
    resp_headers:          const HeaderMap&,
    ts:                    const CacheTimestamps&,
    policy:                FreshnessPolicy = FreshnessPolicy { .. },
    heuristic_fraction:    i64             = 10,
    immutable_min_ttl_sec: i64             = 31536000,
) -> FreshnessMetrics {
    var metrics = FreshnessMetrics { .. };

    let age_hdr = parse_age_header(get_header(resp_headers, "age"));
    let date_raw = get_header(resp_headers, "date");
    var date_sec = ts.response_sec;
    if date_raw.len > 0 {
        let d, ok_d = core::parse_http_date(date_raw);
        if ok_d { date_sec = core::unix(d); }
    }
    let apparent_age = compute_apparent_age(ts.response_sec, date_sec);

    metrics.current_age_sec = compute_current_age(apparent_age, age_hdr, ts);
    metrics.freshness_lifetime_sec = compute_freshness_lifetime(
        resp_cc, resp_headers, ts, policy.shared, heuristic_fraction, immutable_min_ttl_sec,
    );

    let basic_fresh = metrics.current_age_sec < metrics.freshness_lifetime_sec;
    var req_max_age_ok = !has_invalid_freshness(req_cc);
    if has_max_age(req_cc) && req_cc.max_age >= 0 {
        req_max_age_ok = req_max_age_ok && (metrics.current_age_sec <= req_cc.max_age);
    }

    var req_min_fresh_ok = !has_invalid_freshness(req_cc);
    if has_min_fresh(req_cc) && req_cc.min_fresh >= 0 {
        let remaining = metrics.freshness_lifetime_sec - metrics.current_age_sec;
        req_min_fresh_ok = req_min_fresh_ok && (remaining >= req_cc.min_fresh);
    }

    metrics.is_fresh = basic_fresh && req_max_age_ok && req_min_fresh_ok;

    if !metrics.is_fresh && !basic_fresh && req_max_age_ok && req_min_fresh_ok {
        var is_swr = false;
        metrics.stale_allowed = http_internal::evaluate_stale_allowance(
            resp_cc, req_cc, metrics.current_age_sec, metrics.freshness_lifetime_sec, policy, is_swr,
        );
        metrics.stale_while_revalidate_allowed = is_swr;
        metrics.stale_if_error_allowed = http_internal::evaluate_stale_if_error(
            resp_cc, req_cc, metrics.current_age_sec, metrics.freshness_lifetime_sec, policy,
        );
    }

    let resp_force_rev = is_no_cache(resp_cc) && (resp_cc.no_cache_overflow || resp_cc.no_cache_fields.len == 0);
    let req_force_rev = is_no_cache(req_cc);
    let force_rev = resp_force_rev || req_force_rev;
    metrics.requires_revalidation = force_rev || (!metrics.is_fresh && !metrics.stale_allowed);

    return metrics;
}
