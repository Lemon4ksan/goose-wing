// RFC 9111 Section 4.2: Mathematical time and freshness calculation engine.
// Implements apparent age, response delay, corrected initial age, resident time,
// and hierarchical freshness lifetime calculations with clock skew & monotonic protection.
namespace wing;

import std;
import core.time;
import http.headers;
import http.cache.cache_control;

// ---- cache timestamps & clock model ----------------------------------------

// Wall-clock and monotonic timestamps captured across request/response lifecycle.
struct CacheTimestamps {
    request_time: Time = Time { .. },
    response_time: Time = Time { .. },
    now: Time = Time { .. },
    request_mono: MonotonicInstant = MonotonicInstant { .. },
    response_mono: MonotonicInstant = MonotonicInstant { .. },
    now_mono: MonotonicInstant = MonotonicInstant { .. },
    has_monotonic: bool = false,
    clock_available: bool = true,
}

// Constructs a zero-initialized CacheTimestamps structure.
fn new_cache_timestamps() -> CacheTimestamps {
    return CacheTimestamps { .. };
}

// Constructs CacheTimestamps with specified wall-clock times.
fn new_cache_timestamps(req_time: Time, resp_time: Time, cur_now: Time) -> CacheTimestamps {
    return CacheTimestamps {
        request_time: req_time,
        response_time: resp_time,
        now: cur_now,
        clock_available: true,
        ..
    };
}

// Returns a copy of ts with monotonic clock instants recorded.
fn with_monotonic(ts: CacheTimestamps, req_mono: MonotonicInstant, resp_mono: MonotonicInstant, cur_mono: MonotonicInstant) -> CacheTimestamps {
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
    current_age_sec: i64 = 0,
    freshness_lifetime_sec: i64 = 0,
    is_fresh: bool = false,
    requires_revalidation: bool = false,
    stale_allowed: bool = false,
}

// ---- status code heuristic cacheability ------------------------------------

// Returns whether status_code is heuristically cacheable by default (RFC 9111 Section 4.2.2).
fn is_heuristically_cacheable_status(status_code: i32) -> bool {
    return status_code == 200 || status_code == 203 || status_code == 204 || status_code == 206 ||
           status_code == 300 || status_code == 301 || status_code == 308 ||
           status_code == 404 || status_code == 405 || status_code == 410 || status_code == 414 ||
           status_code == 501;
}

// ---- age header parser -----------------------------------------------------

// Parses Age header delta-seconds, selecting the first member if multiple present (RFC 9111 §5.1).
// Clamps values exceeding i32::MAX to 2147483647. Returns 0 for negative or malformed values.
fn parse_age_header(raw_age: const u8[:]) -> i64 {
    var s = trim_lws(raw_age);
    guard s.len > 0 else { return 0; }

    var comma_idx: i64 = -1;
    for i in s.len {
        if s[i] == ',' {
            comma_idx = i;
            break;
        }
    }
    if comma_idx >= 0 {
        s = trim_lws(s[..comma_idx]);
    }
    guard s.len > 0 else { return 0; }

    var val: i64 = 0;
    for b in s {
        guard b >= '0' && b <= '9' else {
            return 0;
        }
        val = val * 10 + (b - '0');
        if val > MAX_DELTA_SECONDS {
            val = MAX_DELTA_SECONDS;
        }
    }
    return val;
}

// ---- rfc 9111 section 4.2.3: age calculations ------------------------------

// Computes apparent_age = max(0, response_time - date_value).
fn compute_apparent_age(response_time: Time, date_value: Time) -> i64 {
    let diff = unix(response_time) - unix(date_value);
    return if diff > 0 { diff } else { 0 };
}

// Computes response_delay = max(0, response_time - request_time).
// Uses monotonic clock when available to avoid NTP step skew.
fn compute_response_delay(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = duration_since(ts.response_mono, ts.request_mono);
        let s = as_secs(dur);
        return if s > 0 { s } else { 0 };
    }
    let diff = unix(ts.response_time) - unix(ts.request_time);
    return if diff > 0 { diff } else { 0 };
}

// Computes corrected_initial_age = max(apparent_age, age_hdr + response_delay).
fn compute_corrected_initial_age(apparent_age: i64, age_hdr: i64, response_delay: i64) -> i64 {
    let corrected_age_value = age_hdr + response_delay;
    return if apparent_age > corrected_age_value { apparent_age } else { corrected_age_value };
}

// Computes resident_time = max(0, now - response_time).
// Protected by monotonic clock to guarantee non-decreasing values.
fn compute_resident_time(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = duration_since(ts.now_mono, ts.response_mono);
        let s = as_secs(dur);
        return if s > 0 { s } else { 0 };
    }
    let diff = unix(ts.now) - unix(ts.response_time);
    return if diff > 0 { diff } else { 0 };
}

// Computes current_age = corrected_initial_age + resident_time.
fn compute_current_age(apparent_age: i64, age_hdr: i64, ts: const CacheTimestamps&) -> i64 {
    let delay = compute_response_delay(ts);
    let initial_age = compute_corrected_initial_age(apparent_age, age_hdr, delay);
    let resident = compute_resident_time(ts);
    let current_age = initial_age + resident;
    return if current_age > MAX_DELTA_SECONDS { MAX_DELTA_SECONDS } else { current_age };
}

// ---- freshness lifetime helpers --------------------------------------------

// Computes freshness lifetime from Expires header relative to ref_time (RFC 9111 §4.2.1).
fn compute_expires_lifetime(resp_headers: const HeaderMap&, ref_time: Time) -> i64, bool {
    let expires_raw = get_header(resp_headers, "expires");
    guard expires_raw.len > 0 else { return 0, false; }

    let exp_time, ok_exp = parse_http_date(expires_raw);
    guard ok_exp else { return 0, false; }

    let date_raw = get_header(resp_headers, "date");
    var base_time = ref_time;
    if date_raw.len > 0 {
        let d_time, ok_d = parse_http_date(date_raw);
        if ok_d { base_time = d_time; }
    }

    let diff = unix(exp_time) - unix(base_time);
    return (if diff > 0 { diff } else { 0 }), true;
}

// Computes heuristic freshness lifetime (default 10% of Date - Last-Modified) (RFC 9111 §4.2.2).
fn compute_last_modified_heuristic(resp_headers: const HeaderMap&, ref_time: Time, heuristic_fraction: i64) -> i64 {
    guard is_heuristically_cacheable_status(resp_headers.status_code) else { return 0; }

    let lm_raw = get_header(resp_headers, "last-modified");
    guard lm_raw.len > 0 else { return 0; }

    let lm_time, ok_lm = parse_http_date(lm_raw);
    guard ok_lm else { return 0; }

    let date_raw = get_header(resp_headers, "date");
    var base_time = ref_time;
    if date_raw.len > 0 {
        let d_time, ok_d = parse_http_date(date_raw);
        if ok_d { base_time = d_time; }
    }

    let delta = unix(base_time) - unix(lm_time);
    guard delta > 0 else { return 0; }

    let heuristic = (delta * heuristic_fraction) / 100;
    return if heuristic > 0 { heuristic } else { 0 };
}

// Computes freshness lifetime according to RFC 9111 priority hierarchy.
// Evaluates s-maxage (shared) > max-age > Expires > immutable > Last-Modified heuristic.
fn compute_freshness_lifetime(
    resp_cc: const CacheControl&,
    resp_headers: const HeaderMap&,
    ts: const CacheTimestamps&,
    shared: bool = false,
    heuristic_fraction: i64 = 10,
    immutable_min_ttl_sec: i64 = 31536000
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

// Checks whether max-stale serving is strictly prohibited by RFC 9111 or CVE-2026-93748 defense.
fn is_max_stale_blocked(resp_cc: const CacheControl&, shared: bool, security_zeroed: bool) -> bool {
    if is_must_revalidate(resp_cc) { return true; }
    if shared && is_proxy_revalidate(resp_cc) { return true; }
    if has_s_maxage(resp_cc) { return true; }
    if security_zeroed { return true; }
    return false;
}

// Evaluates whether serving stale response is permitted under max-stale.
fn evaluate_stale_allowance(
    resp_cc: const CacheControl&,
    req_cc: const CacheControl&,
    current_age: i64,
    lifetime: i64,
    shared: bool,
    security_zeroed: bool
) -> bool {
    guard has_max_stale(req_cc) else { return false; }
    guard !is_max_stale_blocked(resp_cc, shared, security_zeroed) else { return false; }

    let stale_sec = current_age - lifetime;
    if req_cc.max_stale < 0 { return true; }
    return stale_sec <= req_cc.max_stale;
}

// Evaluates whether cached response satisfies request freshness constraints or requires revalidation.
// Enforces max-age, min-fresh, and max-stale with CVE-2026-93748 defense.
fn evaluate_freshness(
    resp_cc: const CacheControl&,
    req_cc: const CacheControl&,
    resp_headers: const HeaderMap&,
    ts: const CacheTimestamps&,
    shared: bool = false,
    security_zeroed: bool = false,
    heuristic_fraction: i64 = 10,
    immutable_min_ttl_sec: i64 = 31536000
) -> FreshnessMetrics {
    var metrics = FreshnessMetrics { .. };

    let age_hdr = parse_age_header(get_header(resp_headers, "age"));
    let date_raw = get_header(resp_headers, "date");
    var date_time = ts.response_time;
    if date_raw.len > 0 {
        let d, ok_d = parse_http_date(date_raw);
        if ok_d { date_time = d; }
    }
    let apparent_age = compute_apparent_age(ts.response_time, date_time);

    metrics.current_age_sec = compute_current_age(apparent_age, age_hdr, ts);
    metrics.freshness_lifetime_sec = compute_freshness_lifetime(
        resp_cc, resp_headers, ts, shared, heuristic_fraction, immutable_min_ttl_sec
    );

    let basic_fresh = metrics.current_age_sec < metrics.freshness_lifetime_sec;
    var req_max_age_ok = true;
    if has_max_age(req_cc) && req_cc.max_age >= 0 {
        req_max_age_ok = (metrics.current_age_sec <= req_cc.max_age);
    }

    var req_min_fresh_ok = true;
    if has_min_fresh(req_cc) && req_cc.min_fresh >= 0 {
        let remaining = metrics.freshness_lifetime_sec - metrics.current_age_sec;
        req_min_fresh_ok = (remaining >= req_cc.min_fresh);
    }

    metrics.is_fresh = basic_fresh && req_max_age_ok && req_min_fresh_ok;

    if !metrics.is_fresh {
        metrics.stale_allowed = evaluate_stale_allowance(
            resp_cc, req_cc, metrics.current_age_sec, metrics.freshness_lifetime_sec, shared, security_zeroed
        );
    }

    let force_rev = is_no_cache(resp_cc) || is_no_cache(req_cc);
    metrics.requires_revalidation = force_rev || (!metrics.is_fresh && !metrics.stale_allowed);

    return metrics;
}
