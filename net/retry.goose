// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Two-tier resilience retry architecture: Tier 1 zero-delay stale socket recovery
// with one-shot stream guards and QUIC protocol fallback; Tier 2 exponential backoff
// with Full/Equal/Decorrelated Jitter, RFC 9110 Retry-After parser, and Google SRE retry budgets.
namespace wing;

import std;
import core from "..";
import http.headers;

// ---- Tier 1: Zero-Delay Stale Socket Recovery & QUIC Fallback -----------

const ERR_QUIC_PROTOCOL_ERROR: i32 = -356; // Chromium net error code parity

// Checks if request carries a valid non-empty Idempotency-Key header.
fn has_idempotency_key<Req>(req: const Req&) -> bool {
    return req.header("Idempotency-Key").len > 0;
}

// Verifies all 4 mandatory invariants for Tier 1 zero-delay retry (net/http parity):
// 1. Connection was reused from Keep-Alive pool (reused == true).
// 2. Failure occurred before response headers arrived (!headers_received).
// 3. Method is idempotent OR request has an Idempotency-Key.
// 4. Request has no body OR body is rewindable with GetBody (prevents one-shot stream bug).
fn should_retry_tier1_stale_socket<Req>(
    reused_connection: bool,
    req:               const Req&,
    headers_received:  bool = false,
) -> bool {
    // Invariant 1: Only reused connections are retried at Tier 1; fresh dials fail fast
    guard reused_connection else { return false; }

    // Invariant 2: Failure must happen before response headers are received
    guard !headers_received else { return false; }

    // Invariant 3: Method must be idempotent OR provide Idempotency-Key
    let idempotent = rfc::is_idempotent_method(req.method[..]) || has_idempotency_key(req);
    guard idempotent else { return false; }

    // Invariant 4: Prevent form-data one-shot-stream retry bug:
    // Body must either be empty OR rewindable
    if req.body.len > 0 && (!req.rewindable || req.body_consumed) {
        return false;
    }

    return true;
}

struct Tier1Decision {
    retry_immediately:            bool = false,
    disable_alternative_services: bool = false, // Disables QUIC/Alt-Svc on retry
}

// Evaluates Tier 1 network errors, including Chromium ERR_QUIC_PROTOCOL_ERROR fallback.
fn evaluate_tier1_retry<Req>(
    err_code:          i32,
    reused_connection: bool,
    req:               const Req&,
    headers_received:  bool = false,
) -> Tier1Decision {
    // Chromium QUIC protocol fallback: automatically retry over TCP/TLS before headers
    // strictly requiring idempotent method or idempotency key, and rewindable/unconsumed body.
    if err_code == ERR_QUIC_PROTOCOL_ERROR && !headers_received {
        let idempotent = rfc::is_idempotent_method(req.method[..]) || has_idempotency_key(req);
        let rewindable_ok = req.body.len == 0 || (req.rewindable && !req.body_consumed);
        if idempotent && rewindable_ok {
            return Tier1Decision {
                retry_immediately:            true,
                disable_alternative_services: true,
            };
        }
    }

    let retry_ok = should_retry_tier1_stale_socket(reused_connection, req, headers_received);
    return Tier1Decision {
        retry_immediately:            retry_ok,
        disable_alternative_services: false,
    };
}

// ---- Tier 2: Exponential Backoff & 3 Jitter Strategies ------------------

enum JitterStrategy {
    None,
    FullJitter,       // Default recommended strategy
    EqualJitter,      // Guarantees non-zero floor
    DecorrelatedJitter, // Stateful previous-sleep random walk
}

struct BackoffConfig {
    base_ms:  i64            = 100,
    cap_ms:   i64            = 10000,
    strategy: JitterStrategy = JitterStrategy.FullJitter,
}

fn new_backoff_config(
    base:  i64            = 100,
    cap:   i64            = 10000,
    strat: JitterStrategy = JitterStrategy.FullJitter,
) -> BackoffConfig {
    return BackoffConfig {
        base_ms:  base,
        cap_ms:   cap,
        strategy: strat,
    };
}

// Pseudo-random uniform integer in range [min_val, max_val] using WyRand and Lemire fast-range.
inline fn uniform_random(seed: u64&, min_val: i64, max_val: i64) -> i64 {
    guard max_val > min_val else { return min_val; }
    seed += core::WYP0_V42;
    let rnd = core::wymum(seed ^ core::WYP1_V42, seed);
    let diff = (max_val as u64) - (min_val as u64);
    let range = core::add_sat_u64(diff, 1);
    let offset = core::fast_range_biased_u64(rnd, range) as! i64;
    return min_val + offset;
}

// Computes backoff duration using specified Jitter algorithm (AWS Architecture parity).
fn compute_backoff_jitter_ms(
    cfg:           const BackoffConfig&,
    attempt:       i64,
    prev_sleep_ms: i64&,
    rng_seed:      u64&,
) -> i64 {
    // Compute capped deterministic exponential target t = min(c, b * 2^a)
    let safe_attempt = min(max(0, attempt), 60);
    let safe_base = max(0, cfg.base_ms);
    let safe_cap = max(0, cfg.cap_ms);
    let exp_bound = core::shl_sat_u64(safe_base as u64, safe_attempt as u32);
    let target_t = core::ct_min_u64(safe_cap as u64, exp_bound) as! i64;

    return match cfg.strategy {
        None => target_t,

        // Full Jitter: U(0, min(c, b * 2^a))
        FullJitter => {
            let sleep_ms = uniform_random(rng_seed, 0, target_t);
            prev_sleep_ms = sleep_ms;
            sleep_ms
        },

        // Equal Jitter: t/2 + U(0, t/2)
        EqualJitter => {
            let half = target_t / 2;
            let sleep_ms = half + uniform_random(rng_seed, 0, half);
            prev_sleep_ms = sleep_ms;
            sleep_ms
        },

        // Decorrelated Jitter: min(c, U(b, prev_sleep * 3))
        DecorrelatedJitter => {
            let prev = if prev_sleep_ms > 0 { prev_sleep_ms } else { safe_base };
            let upper = if prev > 3074457345618258602 { 9223372036854775807 } else { prev * 3 };
            let rnd_sleep = uniform_random(rng_seed, safe_base, upper);
            let sleep_ms = core::ct_min_i64(rnd_sleep, safe_cap);
            prev_sleep_ms = sleep_ms;
            sleep_ms
        },
    };
}

// ---- RFC 9110 Retry-After parser & Circuit Breaker ----------------------

fn try_parse_retry_after_seconds(clean: const u8[:]) -> i64, bool {
    var all_digits = true;
    for i in clean.len {
        let ch = clean[i];
        if ch < '0' || ch > '9' {
            all_digits = false;
            break;
        }
    }
    guard all_digits else { return 0, false; }
    let secs, ok_s = core::parse_digits(clean);
    guard ok_s && secs >= 0 else { return 0, false; }
    return core::retry_after_sec_to_ms_sat(secs), true;
}

fn try_parse_retry_after_http_date(clean: const u8[:], now_unix_ms: i64) -> i64, bool {
    let parsed_time, ok_t = core::parse_http_date(clean);
    guard ok_t else { return 0, false; }

    let target_unix_ms = parsed_time.unix_milli();
    if target_unix_ms <= now_unix_ms {
        return 0, true;
    }
    return core::sub_sat_i64(target_unix_ms, now_unix_ms), true;
}

// Strict parser for RFC 9110 Retry-After header:
// Supports delay-seconds (1*DIGIT without signs/decimals/units) and IMF-fixdate with exact UTC round-trip check.
//
// Example:
//   header_raw = "120", now_unix_ms = 1000
//   returns: 120000, true
fn parse_retry_after_ms(
    header_raw:  const u8[:],
    now_unix_ms: i64,
) -> i64, bool {
    // RFC 9110 Section 10.2.3: Retry-After - trim OWS (SP / HTAB) and reject ASCII CTLs
    let clean = header_raw.trim_lws();
    let has_no_ctl = core::swar_find_ctl(clean) == clean.len && !clean.contains_byte(0x7F);
    guard clean.len > 0 && has_no_ctl else { return 0, false; }

    let sec_ms, ok_sec = try_parse_retry_after_seconds(clean);
    if ok_sec {
        return sec_ms, true;
    }

    return try_parse_retry_after_http_date(clean, now_unix_ms);
}

// Local Host Circuit Breaker registry entry for excessive Retry-After windows
struct HostCircuitBreakerEntry {
    host:                  u8[..256] = [],
    blocked_until_mono_ns: i64       = 0,
    is_blocked:            bool      = false,
}

struct HostCircuitBreaker {
    hosts:              HostCircuitBreakerEntry[..16] = [],
    max_retry_after_ms: i64                           = 60000, // 60s interactive agent ceiling (or 24h for crawler)
}

fn new_host_circuit_breaker(max_wait_ms: i64 = 60000) -> HostCircuitBreaker {
    return HostCircuitBreaker {
        max_retry_after_ms: max_wait_ms,
        ..
    };
}

// Records or trips circuit breaker when Retry-After exceeds max allowable wait.
fn trip_circuit_breaker_if_exceeded(
    breaker:        HostCircuitBreaker&,
    host_str:       const u8[:],
    retry_after_ms: i64,
    now_mono_ns:    i64,
) -> bool {
    guard retry_after_ms > breaker.max_retry_after_ms else { return false; }
    guard host_str.len > 0 && host_str.len <= 256 else { return false; }

    let block_dur_ns = min(retry_after_ms, 9223372036854) * 1000000;
    let unblock_at = core::add_sat_i64(now_mono_ns, block_dur_ns);

    for &h in breaker.hosts {
        if h.host[..].eq_ascii_fold(host_str) {
            h.blocked_until_mono_ns = max(h.blocked_until_mono_ns, unblock_at);
            h.is_blocked = true;
            return true;
        }
    }

    var entry = HostCircuitBreakerEntry {
        blocked_until_mono_ns: unblock_at,
        is_blocked:            true,
        ..
    };
    let _ = entry.host.try_set(host_str);
    if breaker.hosts.try_push(entry) {
        return true;
    }

    var reclaim_idx: i64 = 0;
    for i in breaker.hosts.len {
        if !breaker.hosts[i].is_blocked || now_mono_ns >= breaker.hosts[i].blocked_until_mono_ns {
            reclaim_idx = i;
            break;
        }
        if breaker.hosts[i].blocked_until_mono_ns < breaker.hosts[reclaim_idx].blocked_until_mono_ns {
            reclaim_idx = i;
        }
    }
    let _ = breaker.hosts[reclaim_idx].host.try_set(host_str);
    breaker.hosts[reclaim_idx].blocked_until_mono_ns = unblock_at;
    breaker.hosts[reclaim_idx].is_blocked = true;
    return true;
}

// Checks whether requests to host are currently blocked by circuit breaker.
fn is_host_circuit_broken(
    breaker:     HostCircuitBreaker&,
    host_str:    const u8[:],
    now_mono_ns: i64,
) -> bool {
    for &h in breaker.hosts {
        guard h.host[..].eq_ascii_fold(host_str) else { continue; }
        guard h.is_blocked else { return false; }
        if now_mono_ns >= h.blocked_until_mono_ns {
            h.is_blocked = false;
            return false;
        }
        return true;
    }
    return false;
}

// ---- Adaptive Retry Budget (Google SRE) ---------------------------------

// Rate-limiting container capping retry traffic as a fixed percentage of total requests.
struct AdaptiveRetryBudget {
    window_start_mono_ns: i64 = 0,
    window_duration_ns:   i64 = 10000000000, // 10s sliding window
    total_requests:       i64 = 0,
    retried_requests:     i64 = 0,
    max_retry_ratio_pct:  i64 = 20,        // Max 20% retry ratio
    min_retries_per_sec:  i64 = 2,         // 2 retries/sec minimum floor for low-traffic clients
}

fn new_adaptive_retry_budget(
    ratio_pct:      i64 = 20,
    min_per_sec:    i64 = 2,
    window_dur_sec: i64 = 10,
) -> AdaptiveRetryBudget {
    return AdaptiveRetryBudget {
        window_duration_ns:  window_dur_sec * 1000000000,
        max_retry_ratio_pct: ratio_pct,
        min_retries_per_sec: min_per_sec,
        ..
    };
}

// Records a primary request initiation.
fn record_primary_request(budget: AdaptiveRetryBudget&, now_mono_ns: i64) {
    if now_mono_ns - budget.window_start_mono_ns >= budget.window_duration_ns {
        budget.window_start_mono_ns = now_mono_ns;
        budget.total_requests = 0;
        budget.retried_requests = 0;
    }
    budget.total_requests++;
}

// Checks if retry budget permits another retry attempt, recording it if approved.
fn allow_retry_budget(budget: AdaptiveRetryBudget&, now_mono_ns: i64) -> bool {
    if now_mono_ns - budget.window_start_mono_ns >= budget.window_duration_ns {
        budget.window_start_mono_ns = now_mono_ns;
        budget.total_requests = 0;
        budget.retried_requests = 0;
    }

    let window_secs = budget.window_duration_ns / 1000000000;
    let allowed_by_ratio = (budget.total_requests * budget.max_retry_ratio_pct) / 100;
    let allowed_by_floor = budget.min_retries_per_sec * window_secs;
    let total_allowed = core::ct_max_i64(allowed_by_ratio, allowed_by_floor);

    if budget.retried_requests < total_allowed {
        budget.retried_requests++;
        return true;
    }

    return false;
}

// ---- Conditional Mid-Stream Range + Strong ETag Resumption -----------------

struct RangeResumeTracker {
    etag:           u8[..256] = [],
    bytes_received: u64       = 0,
    total_length:   i64       = -1,
    resumable:      bool      = false,
}

// RFC 9110 Section 8.8.3: ETag - validates non-empty strong entity-tag (`"..."`),
// rejecting weak `W/` validators prohibited in byte-range `If-Match` preconditions.
//
// Example:
//   etag = "\"abc123\""
//   returns: true
fn is_strong_etag_validator(etag: const u8[:]) -> bool {
    let clean = etag.trim_lws();
    guard clean.len >= 2 else { return false; }
    guard !clean.starts_with_fold("w/") else { return false; }
    return clean.starts_with("\"") && clean.ends_with("\"");
}

// Captures strong ETag and total byte length from an initial 200 OK GET response.
fn arm_range_resume(
    tracker: RangeResumeTracker&,
    method:  const u8[:],
    status:  i32,
    headers: const HeaderMap&,
) {
    tracker = RangeResumeTracker { .. };
    guard method == "GET" && status == 200 else { return; }
    let etag = get_header(headers, "ETag").trim_lws();
    guard is_strong_etag_validator(etag) else { return; }
    guard !has_header(headers, "Content-Encoding") else { return; }
    guard tracker.etag.try_set(etag) else { return; }

    let cl_raw = get_header(headers, "Content-Length").trim_lws();
    if cl_raw.len > 0 {
        let cl_val, ok_cl = cl_raw.parse_u64_dec();
        guard ok_cl && cl_val <= 9223372036854775807 else { return; }
        tracker.total_length = cl_val as i64;
    }
    tracker.resumable = true;
}

// Formats `Range: bytes=<start>-<end>` and `If-Match: <etag>` into `req_headers` after a mid-body drop.
//
// Example:
//   tracker = RangeResumeTracker { etag: "\"v1\"", bytes_received: 4096, total_length: 8192, resumable: true }
//   returns: true (sets Range: "bytes=4096-8191" and If-Match: "\"v1\"")
fn build_range_resume_headers(tracker: const RangeResumeTracker&, req_headers: HeaderMap&) -> bool {
    guard tracker.resumable && tracker.bytes_received > 0 else { return false; }
    if tracker.total_length >= 0 && (tracker.bytes_received as i64) >= tracker.total_length {
        return false;
    }
    var range_val: u8[..64] = [];
    guard range_val.try_append("bytes=") else { return false; }
    tracker.bytes_received.format_u64_dec(range_val);
    guard range_val.try_push('-') else { return false; }
    if tracker.total_length > 0 {
        let end_byte = core::sub_sat_u64(tracker.total_length as u64, 1);
        end_byte.format_u64_dec(range_val);
    }
    set_header(req_headers, "Range", range_val[..]);
    set_header(req_headers, "If-Match", tracker.etag[..]);
    return true;
}
