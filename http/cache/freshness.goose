// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9111 Section 4.2: Mathematical time and freshness calculation engine.
// Implements apparent age, response delay, corrected initial age, resident time,
// and hierarchical freshness lifetime calculations with clock skew & monotonic protection.
namespace wing;

import std;
import core from "../..";
import http.headers;
import http.cache.cache_control;

// ---- cache timestamps & clock model ----------------------------------------

// Wall-clock and monotonic timestamps captured across request/response lifecycle.
struct CacheTimestamps {
    request_time:    core::Time             = core::Time { .. },
    response_time:   core::Time             = core::Time { .. },
    now:             core::Time             = core::Time { .. },
    request_mono:    core::MonotonicInstant = core::MonotonicInstant { .. },
    response_mono:   core::MonotonicInstant = core::MonotonicInstant { .. },
    now_mono:        core::MonotonicInstant = core::MonotonicInstant { .. },
    has_monotonic:   bool                   = false,
    clock_available: bool                   = true,
}

// Constructs a zero-initialized CacheTimestamps structure.
// Constructs CacheTimestamps with specified wall-clock times.
fn new_cache_timestamps(req_time: core::Time, resp_time: core::Time, cur_now: core::Time) -> CacheTimestamps {
    return CacheTimestamps {
        request_time:    req_time,
        response_time:   resp_time,
        now:             cur_now,
        clock_available: true,
        ..
    };
}

// Returns a copy of ts with monotonic clock instants recorded.
fn with_monotonic(
    ts:        CacheTimestamps,
    req_mono:  core::MonotonicInstant,
    resp_mono: core::MonotonicInstant,
    cur_mono:  core::MonotonicInstant,
) -> CacheTimestamps {
    var updated = ts;
    updated.request_mono = req_mono;
    updated.response_mono = resp_mono;
    updated.now_mono = cur_mono;
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

// Computes apparent_age = max(0, response_time - date_value).
fn compute_apparent_age(response_time: core::Time, date_value: core::Time) -> i64 {
    let diff = core::unix(response_time) - core::unix(date_value);
    return max(0, diff);
}

// Computes response_delay = max(0, response_time - request_time).
// Uses monotonic clock when available to avoid NTP step skew.
fn compute_response_delay(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = core::duration_since(ts.response_mono, ts.request_mono);
        return max(0, dur.as_secs());
    }
    let diff = core::unix(ts.response_time) - core::unix(ts.request_time);
    return max(0, diff);
}

// Computes corrected_initial_age = max(apparent_age, age_hdr + response_delay).
fn compute_corrected_initial_age(apparent_age: i64, age_hdr: i64, response_delay: i64) -> i64 {
    return max(apparent_age, core::add_sat_i64(age_hdr, response_delay));
}

// Computes resident_time = max(0, now - response_time).
// Protected by monotonic clock to guarantee non-decreasing values.
fn compute_resident_time(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = core::duration_since(ts.now_mono, ts.response_mono);
        return max(0, dur.as_secs());
    }
    let diff = core::unix(ts.now) - core::unix(ts.response_time);
    return max(0, diff);
}

// Computes current_age = corrected_initial_age + resident_time.
fn compute_current_age(apparent_age: i64, age_hdr: i64, ts: const CacheTimestamps&) -> i64 {
    let delay = compute_response_delay(ts);
    let initial_age = compute_corrected_initial_age(apparent_age, age_hdr, delay);
    let resident = compute_resident_time(ts);
    return min(core::add_sat_i64(initial_age, resident), rfc::MAX_DELTA_SECONDS);
}

// ---- freshness lifetime helpers --------------------------------------------

// Computes freshness lifetime from Expires header relative to ref_time (RFC 9111 §4.2.1 & §5.3).
// If Expires is "0" or invalid date format, lifetime is 0 and immediately stale (RFC 9111 §5.3 & §4.2.2).
fn compute_expires_lifetime(resp_headers: const HeaderMap&, ref_time: core::Time) -> i64, bool {
    let expires_raw = get_header(resp_headers, "expires");
    let trimmed = expires_raw.trim_lws();
    guard trimmed.len > 0 else { return 0, false; }

    let exp_time, ok_exp = core::parse_http_date(trimmed);
    // RFC 9111 §5.3 & §4.2.2: An invalid date format (or "0") means immediately stale (lifetime = 0)
    // and prevents fallback to heuristic freshness from Last-Modified.
    guard ok_exp else { return 0, true; }

    let date_raw = get_header(resp_headers, "date");
    var base_time = ref_time;
    if date_raw.len > 0 {
        let d_time, ok_d = core::parse_http_date(date_raw);
        if ok_d { base_time = d_time; }
    }

    let diff = core::unix(exp_time) - core::unix(base_time);
    return max(0, diff), true;
}

// Computes heuristic freshness lifetime (default 10% of Date - Last-Modified) (RFC 9111 §4.2.2).
fn compute_last_modified_heuristic(
    resp_headers:       const HeaderMap&,
    ref_time:           core::Time,
    heuristic_fraction: i64,
) -> i64 {
    guard rfc::is_heuristically_cacheable_status(resp_headers.status_code) else { return 0; }

    let lm_raw = get_header(resp_headers, "last-modified");
    guard lm_raw.len > 0 else { return 0; }

    let lm_time, ok_lm = core::parse_http_date(lm_raw);
    guard ok_lm else { return 0; }

    let date_raw = get_header(resp_headers, "date");
    var base_time = ref_time;
    if date_raw.len > 0 {
        let d_time, ok_d = core::parse_http_date(date_raw);
        if ok_d { base_time = d_time; }
    }

    let delta = core::unix(base_time) - core::unix(lm_time);
    guard delta > 0 else { return 0; }

    let heuristic = (delta * heuristic_fraction) / 100;
    return max(0, heuristic);
}

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

    let exp_lt, ok_exp = compute_expires_lifetime(resp_headers, ts.response_time);
    if ok_exp { return exp_lt; }

    if is_immutable(resp_cc) {
        return immutable_min_ttl_sec;
    }

    return compute_last_modified_heuristic(resp_headers, ts.response_time, heuristic_fraction);
}

// ---- freshness evaluation against request & response directives -------------

// Policy options governing cache freshness, max-stale allowance, and security overrides.
struct FreshnessPolicy {
    shared:          bool = false,
    security_zeroed: bool = false,
}

// Checks whether max-stale serving is strictly prohibited by RFC 9111 or CVE-2026-93748 defense.
fn is_max_stale_blocked(resp_cc: const CacheControl&, policy: FreshnessPolicy) -> bool {
    if is_must_revalidate(resp_cc) { return true; }
    if policy.shared && is_proxy_revalidate(resp_cc) { return true; }
    if policy.shared && has_s_maxage(resp_cc) { return true; }
    if policy.security_zeroed { return true; }
    return false;
}

// Evaluates whether serving stale response is permitted under max-stale or stale-while-revalidate.
fn evaluate_stale_allowance(
    resp_cc:     const CacheControl&,
    req_cc:      const CacheControl&,
    current_age: i64,
    lifetime:    i64,
    policy:      FreshnessPolicy,
    out_swr:     bool&,
) -> bool {
    out_swr = false;
    guard !is_max_stale_blocked(resp_cc, policy) else { return false; }
    guard current_age >= lifetime else { return false; }

    let stale_sec = current_age - lifetime;

    // 1. Client max-stale (RFC 9111 Section 5.2.1: Request Directives - Client max-stale directive)
    if has_max_stale(req_cc) {
        if req_cc.max_stale < 0 || stale_sec <= req_cc.max_stale {
            return true;
        }
    }

    // 2. Server stale-while-revalidate (RFC 5861 Section 3)
    if has_stale_while_revalidate(resp_cc) && resp_cc.stale_while_revalidate >= 0 {
        if stale_sec <= resp_cc.stale_while_revalidate {
            out_swr = true;
            return true;
        }
    }

    return false;
}

// Evaluates whether a stale cached response can be served during upstream error (RFC 5861 Section 4).
fn evaluate_stale_if_error(
    resp_cc:     const CacheControl&,
    req_cc:      const CacheControl&,
    current_age: i64,
    lifetime:    i64,
    policy:      FreshnessPolicy,
) -> bool {
    guard !is_max_stale_blocked(resp_cc, policy) else { return false; }
    guard current_age >= lifetime else { return false; }
    let stale_sec = current_age - lifetime;

    var max_sie: i32 = -1;
    if has_stale_if_error(req_cc) && req_cc.stale_if_error >= 0 {
        max_sie = req_cc.stale_if_error;
    } else if has_stale_if_error(resp_cc) && resp_cc.stale_if_error >= 0 {
        max_sie = resp_cc.stale_if_error;
    }

    if max_sie >= 0 {
        return stale_sec <= max_sie;
    }
    return false;
}

// Evaluates whether cached response satisfies request freshness constraints or requires revalidation.
// Enforces max-age, min-fresh, and max-stale with CVE-2026-93748 defense.
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
    var date_time = ts.response_time;
    if date_raw.len > 0 {
        let d, ok_d = core::parse_http_date(date_raw);
        if ok_d { date_time = d; }
    }
    let apparent_age = compute_apparent_age(ts.response_time, date_time);

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
        metrics.stale_allowed = evaluate_stale_allowance(
            resp_cc, req_cc, metrics.current_age_sec, metrics.freshness_lifetime_sec, policy, is_swr,
        );
        metrics.stale_while_revalidate_allowed = is_swr;
        metrics.stale_if_error_allowed = evaluate_stale_if_error(
            resp_cc, req_cc, metrics.current_age_sec, metrics.freshness_lifetime_sec, policy,
        );
    }

    let resp_force_rev = is_no_cache(resp_cc) && (resp_cc.no_cache_overflow || resp_cc.no_cache_fields.len == 0);
    let req_force_rev = is_no_cache(req_cc);
    let force_rev = resp_force_rev || req_force_rev;
    metrics.requires_revalidation = force_rev || (!metrics.is_fresh && !metrics.stale_allowed);

    return metrics;
}
