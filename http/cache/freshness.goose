// RFC 9111 Section 4.2: Mathematical time and freshness calculation engine.
// Implements apparent age, response delay, corrected initial age, resident time,
// and hierarchical freshness lifetime calculations with clock skew & monotonic protection.
namespace wing;

import std;
import core.time;
import http.headers;
import http.cache.cache_control;

// ---- cache timestamps & clock model ----------------------------------------

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

fn new_cache_timestamps() -> CacheTimestamps {
    return CacheTimestamps { .. };
}

fn new_cache_timestamps(req_time: Time, resp_time: Time, cur_now: Time) -> CacheTimestamps {
    var ts = CacheTimestamps {
        request_time: req_time,
        response_time: resp_time,
        now: cur_now,
        clock_available: true,
        ..
    };
    return ts;
}

fn with_monotonic(ts: CacheTimestamps, req_mono: MonotonicInstant, resp_mono: MonotonicInstant, cur_mono: MonotonicInstant) -> CacheTimestamps {
    var updated = ts;
    updated.request_mono = req_mono;
    updated.response_mono = resp_mono;
    updated.now_mono = cur_mono;
    updated.has_monotonic = true;
    return updated;
}

// ---- freshness evaluation result -------------------------------------------

struct FreshnessMetrics {
    current_age_sec: i64 = 0,
    freshness_lifetime_sec: i64 = 0,
    is_fresh: bool = false,
    requires_revalidation: bool = false,
    stale_allowed: bool = false,
}

// ---- status code heuristic cacheability ------------------------------------

// RFC 9110 Section 15 & RFC 9111 Section 4.2.2: Status codes heuristically cacheable by default
fn is_heuristically_cacheable_status(status_code: i32) -> bool {
    return status_code == 200 || status_code == 203 || status_code == 204 || status_code == 206 ||
           status_code == 300 || status_code == 301 || status_code == 308 ||
           status_code == 404 || status_code == 405 || status_code == 410 || status_code == 414 ||
           status_code == 501;
}

// ---- age header parser -----------------------------------------------------

// RFC 9111 Section 5.1: Age Header Field
// "A recipient that parses an Age header field value that contains more than one member
// MUST use the first member."
// Delta-seconds: non-negative integer clamped to 2147483647 (i32::MAX).
fn parse_age_header(raw_age: const u8[:]) -> i64 {
    var s = trim_lws(raw_age);
    guard s.len > 0 else { return 0; }

    // Find first member if comma-separated list is present
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

    // Parse non-negative decimal digits
    var val: i64 = 0;
    for b in s {
        guard b >= '0' && b <= '9' else {
            return 0; // Malformed Age header ignored per RFC 9111 §5.1
        }
        val = val * 10 + (b - '0');
        if val > MAX_DELTA_SECONDS {
            val = MAX_DELTA_SECONDS;
        }
    }
    return val;
}

// ---- rfc 9111 section 4.2.3: age calculations ------------------------------

// apparent_age = max(0, response_time - date_value)
fn compute_apparent_age(response_time: Time, date_value: Time) -> i64 {
    let resp_unix = unix(response_time);
    let date_unix = unix(date_value);
    let diff = resp_unix - date_unix;
    return if diff > 0 { diff } else { 0 };
}

// response_delay = response_time - request_time
// Uses monotonic clock if available to prevent NTP jumps / wall-clock steps from distorting RTT
fn compute_response_delay(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = duration_since(ts.response_mono, ts.request_mono);
        let s = as_secs(dur);
        return if s > 0 { s } else { 0 };
    }
    let diff = unix(ts.response_time) - unix(ts.request_time);
    return if diff > 0 { diff } else { 0 };
}

// corrected_age_value = age_value + response_delay
// corrected_initial_age = max(apparent_age, corrected_age_value)
fn compute_corrected_initial_age(apparent_age: i64, age_hdr: i64, response_delay: i64) -> i64 {
    let corrected_age_value = age_hdr + response_delay;
    return if apparent_age > corrected_age_value { apparent_age } else { corrected_age_value };
}

// resident_time = now - response_time
// Protected by monotonic clock to guarantee monotonically non-decreasing resident time
fn compute_resident_time(ts: const CacheTimestamps&) -> i64 {
    if ts.has_monotonic {
        let dur = duration_since(ts.now_mono, ts.response_mono);
        let s = as_secs(dur);
        return if s > 0 { s } else { 0 };
    }
    let diff = unix(ts.now) - unix(ts.response_time);
    return if diff > 0 { diff } else { 0 };
}

// current_age = corrected_initial_age + resident_time
fn compute_current_age(apparent_age: i64, age_hdr: i64, ts: const CacheTimestamps&) -> i64 {
    let delay = compute_response_delay(ts);
    let initial_age = compute_corrected_initial_age(apparent_age, age_hdr, delay);
    let resident = compute_resident_time(ts);
    let current_age = initial_age + resident;
    return if current_age > MAX_DELTA_SECONDS { MAX_DELTA_SECONDS } else { current_age };
}

// ---- rfc 9111 section 4.2.1: freshness lifetime hierarchy ------------------

// Computes freshness lifetime according to strict RFC 9111 hierarchy:
// 1. Invalid freshness flag -> 0
// 2. s-maxage (if shared) -> s_maxage
// 3. max-age -> max_age
// 4. Expires - Date (or Expires - response_time)
// 5. immutable -> immutable_min_ttl_sec
// 6. Heuristic freshness (status 200/203/204/206/300/301/308/404/405/410/414/501 with Last-Modified)
fn compute_freshness_lifetime(
    resp_cc: const CacheControl&,
    resp_headers: const HeaderMap&,
    ts: const CacheTimestamps&,
    shared: bool = false,
    heuristic_fraction: i64 = 10,
    immutable_min_ttl_sec: i64 = 31536000
) -> i64 {
    // 1. Corrupted freshness parameters force lifetime = 0 (RFC 9111 §4.2.1)
    if has_invalid_freshness(resp_cc) {
        return 0;
    }

    // 2. Shared cache and s-maxage directive
    if shared && has_s_maxage(resp_cc) && resp_cc.s_maxage >= 0 {
        return resp_cc.s_maxage;
    }

    // 3. max-age directive
    if has_max_age(resp_cc) && resp_cc.max_age >= 0 {
        return resp_cc.max_age;
    }

    // 4. Expires header calculation
    let expires_raw = get_header(resp_headers, "expires");
    if expires_raw.len > 0 {
        let exp_time, ok_exp = parse_http_date(expires_raw);
        if ok_exp {
            let date_raw = get_header(resp_headers, "date");
            var ref_time = ts.response_time;
            if date_raw.len > 0 {
                let d_time, ok_d = parse_http_date(date_raw);
                if ok_d {
                    ref_time = d_time;
                }
            }
            let diff = unix(exp_time) - unix(ref_time);
            return if diff > 0 { diff } else { 0 };
        }
    }

    // 5. Immutable directive (RFC 8246)
    if is_immutable(resp_cc) {
        return immutable_min_ttl_sec;
    }

    // 6. Heuristic freshness for cacheable status codes (RFC 9111 §4.2.2)
    let status_code = resp_headers.status_code;
    if is_heuristically_cacheable_status(status_code) {
        let lm_raw = get_header(resp_headers, "last-modified");
        if lm_raw.len > 0 {
            let lm_time, ok_lm = parse_http_date(lm_raw);
            if ok_lm {
                let date_raw = get_header(resp_headers, "date");
                var ref_time = ts.response_time;
                if date_raw.len > 0 {
                    let d_time, ok_d = parse_http_date(date_raw);
                    if ok_d {
                        ref_time = d_time;
                    }
                }
                let delta = unix(ref_time) - unix(lm_time);
                if delta > 0 {
                    // Default 10% of (Date - Last-Modified)
                    let heuristic = (delta * heuristic_fraction) / 100;
                    return if heuristic > 0 { heuristic } else { 0 };
                }
            }
        }
    }

    return 0;
}

// ---- freshness evaluation against request & response directives -------------

// Evaluates whether a cached response satisfies the client request or requires revalidation.
// Enforces RFC 9111 rules for max-age, min-fresh, and max-stale with CVE-2026-93748 defense.
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

    // Parse Age header
    let age_raw = get_header(resp_headers, "age");
    let age_hdr = parse_age_header(age_raw);

    // Compute apparent age
    let date_raw = get_header(resp_headers, "date");
    var date_time = ts.response_time;
    if date_raw.len > 0 {
        let d, ok_d = parse_http_date(date_raw);
        if ok_d {
            date_time = d;
        }
    }
    let apparent_age = compute_apparent_age(ts.response_time, date_time);

    // Compute current age and freshness lifetime
    metrics.current_age_sec = compute_current_age(apparent_age, age_hdr, ts);
    metrics.freshness_lifetime_sec = compute_freshness_lifetime(
        resp_cc,
        resp_headers,
        ts,
        shared,
        heuristic_fraction,
        immutable_min_ttl_sec
    );

    // If response or request has no-cache or must-revalidate/proxy-revalidate, check freshness constraints
    let basic_fresh = metrics.current_age_sec < metrics.freshness_lifetime_sec;

    // Request max-age restriction: client can require response to be no older than req_cc.max_age
    var req_max_age_satisfied = true;
    if has_max_age(req_cc) && req_cc.max_age >= 0 {
        if metrics.current_age_sec > req_cc.max_age {
            req_max_age_satisfied = false;
        }
    }

    // Request min-fresh restriction: client can require response to remain fresh for at least min_fresh seconds
    var req_min_fresh_satisfied = true;
    if has_min_fresh(req_cc) && req_cc.min_fresh >= 0 {
        let remaining_freshness = metrics.freshness_lifetime_sec - metrics.current_age_sec;
        if remaining_freshness < req_cc.min_fresh {
            req_min_fresh_satisfied = false;
        }
    }

    // Determine initial freshness
    if basic_fresh && req_max_age_satisfied && req_min_fresh_satisfied {
        metrics.is_fresh = true;
    } else {
        metrics.is_fresh = false;
    }

    // Check stale-serving allowance (RFC 9111 Section 5.2.1.2: max-stale)
    // CVE-2026-93748 Defense:
    // max-stale is STRICTLY BLOCKED if:
    // 1. must-revalidate is present in cached response
    // 2. proxy-revalidate is present in cached response for a shared cache
    // 3. s-maxage is present in cached response (s-maxage implies proxy-revalidate / overrides max-stale per §5.2.2.10)
    // 4. Cached entry is marked security_zeroed / invalidated
    if !metrics.is_fresh && has_max_stale(req_cc) {
        let blocked = is_must_revalidate(resp_cc) ||
                      (shared && is_proxy_revalidate(resp_cc)) ||
                      has_s_maxage(resp_cc) ||
                      security_zeroed;

        if !blocked {
            let stale_sec = metrics.current_age_sec - metrics.freshness_lifetime_sec;
            if req_cc.max_stale < 0 {
                // Unbounded max-stale
                metrics.stale_allowed = true;
            } else if stale_sec <= req_cc.max_stale {
                metrics.stale_allowed = true;
            }
        }
    }

    // Determine if revalidation is required
    // Must revalidate if not fresh and stale is not allowed, or if no-cache is present
    if is_no_cache(resp_cc) || is_no_cache(req_cc) {
        metrics.requires_revalidation = true;
    } else if !metrics.is_fresh && !metrics.stale_allowed {
        metrics.requires_revalidation = true;
    }

    return metrics;
}
