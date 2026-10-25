// Two-tier resilience retry architecture: Tier 1 zero-delay stale socket recovery
// with one-shot stream guards and QUIC protocol fallback; Tier 2 exponential backoff
// with Full/Equal/Decorrelated Jitter, RFC 9110 Retry-After parser, and Google SRE retry budgets.
namespace wing;

import std;

// ---- 1. Tier 1: Zero-Delay Stale Socket Recovery & QUIC Fallback -----------

let ERR_QUIC_PROTOCOL_ERROR: i32 = -356; // Chromium net error code parity

// Checks whether an HTTP method is semantically idempotent per RFC 9110.
fn is_idempotent_method(method: const u8[:]) -> bool {
    return eq_ascii_fold(method, "GET") ||
           eq_ascii_fold(method, "HEAD") ||
           eq_ascii_fold(method, "PUT") ||
           eq_ascii_fold(method, "DELETE") ||
           eq_ascii_fold(method, "OPTIONS") ||
           eq_ascii_fold(method, "TRACE") ||
           eq_ascii_fold(method, "QUERY");
}

// Checks if request carries a valid non-empty Idempotency-Key header.
fn has_idempotency_key(req: const Request&) -> bool {
    return req.header("Idempotency-Key").len > 0;
}

// Verifies all 4 mandatory invariants for Tier 1 zero-delay retry (net/http parity):
// 1. Connection was reused from Keep-Alive pool (reused == true).
// 2. Failure occurred before response headers arrived (!headers_received).
// 3. Method is idempotent OR request has an Idempotency-Key.
// 4. Request has no body OR body is rewindable with GetBody (prevents one-shot stream bug).
fn should_retry_tier1_stale_socket(
    reused_connection: bool,
    headers_received: bool,
    req: const Request&
) -> bool {
    // Invariant 1: Only reused connections are retried at Tier 1; fresh dials fail fast
    guard reused_connection else { return false; }

    // Invariant 2: Failure must happen before response headers are received
    guard !headers_received else { return false; }

    // Invariant 3: Method must be idempotent OR provide Idempotency-Key
    let idempotent = is_idempotent_method(req.method[..]) || has_idempotency_key(req);
    guard idempotent else { return false; }

    // Invariant 4: Prevent form-data one-shot-stream retry bug:
    // Body must either be empty OR rewindable
    if req.body.len > 0 && (!req.rewindable || req.body_consumed) {
        return false;
    }

    return true;
}

struct Tier1Decision {
    retry_immediately: bool = false,
    disable_alternative_services: bool = false, // Disables QUIC/Alt-Svc on retry
}

// Evaluates Tier 1 network errors, including Chromium ERR_QUIC_PROTOCOL_ERROR fallback.
fn evaluate_tier1_retry(
    err_code: i32,
    reused_connection: bool,
    headers_received: bool,
    req: const Request&
) -> Tier1Decision {
    // Chromium QUIC protocol fallback: automatically retry over TCP/TLS before headers
    if err_code == ERR_QUIC_PROTOCOL_ERROR && !headers_received {
        return Tier1Decision {
            retry_immediately: true,
            disable_alternative_services: true,
        };
    }

    let retry_ok = should_retry_tier1_stale_socket(reused_connection, headers_received, req);
    return Tier1Decision {
        retry_immediately: retry_ok,
        disable_alternative_services: false,
    };
}

// ---- 2. Tier 2: Exponential Backoff & 3 Jitter Strategies ------------------

enum JitterStrategy {
    None,
    FullJitter,       // Default recommended strategy
    EqualJitter,      // Guarantees non-zero floor
    DecorrelatedJitter,// Stateful previous-sleep random walk
}

struct BackoffConfig {
    base_ms: i64 = 100,
    cap_ms: i64 = 10000,
    strategy: JitterStrategy = JitterStrategy.FullJitter,
}

fn new_backoff_config(
    base: i64 = 100,
    cap: i64 = 10000,
    strat: JitterStrategy = JitterStrategy.FullJitter
) -> BackoffConfig {
    return BackoffConfig {
        base_ms: base,
        cap_ms: cap,
        strategy: strat,
    };
}

// Pseudo-random uniform integer in range [min_val, max_val] using WyRand and Lemire fast-range.
inline fn uniform_random(seed: u64&, min_val: i64, max_val: i64) -> i64 {
    guard max_val > min_val else { return min_val; }
    seed += core::WYP0_V42;
    let rnd = core::wymum(seed ^ core::WYP1_V42, seed);
    let range = (max_val - min_val + 1) as u64;
    let offset = core::fast_range_biased_u64(rnd, range) as! i64;
    return min_val + offset;
}

// Computes backoff duration using specified Jitter algorithm (AWS Architecture parity).
fn compute_backoff_jitter_ms(
    cfg: const BackoffConfig&,
    attempt: i64,
    prev_sleep_ms: i64&,
    rng_seed: u64&
) -> i64 {
    // Compute capped deterministic exponential target t = min(c, b * 2^a)
    let exp_bound = core::shl_sat_u64(cfg.base_ms as u64, (if attempt > 60 { 60 } else { attempt }) as u32);
    let target_t = core::ct_min_u64(cfg.cap_ms as u64, exp_bound) as! i64;

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
            let prev = if prev_sleep_ms > 0 { prev_sleep_ms } else { cfg.base_ms };
            let upper = prev * 3;
            let rnd_sleep = uniform_random(rng_seed, cfg.base_ms, upper);
            let sleep_ms = core::ct_min_i64(rnd_sleep, cfg.cap_ms);
            prev_sleep_ms = sleep_ms;
            sleep_ms
        },
    };
}

// ---- 3. RFC 9110 Retry-After parser & Circuit Breaker ----------------------

// Strict parser for RFC 9110 Retry-After header:
// Supports delay-seconds (1*DIGIT without signs/decimals/units) and IMF-fixdate with exact UTC round-trip check.
fn parse_retry_after_ms(
    header_raw: const u8[:],
    now_unix_ms: i64
) -> i64, bool {
    let clean = trim(header_raw);
    guard clean.len > 0 else { return 0, false; }

    // 1. Check for integer delay-seconds (1*DIGIT)
    var all_digits = true;
    for i in clean.len {
        let ch = clean[i];
        if ch < '0' || ch > '9' {
            all_digits = false;
            break;
        }
    }

    if all_digits {
        let secs, ok_s = core::parse_digits(clean);
        guard ok_s && secs >= 0 else { return 0, false; }
        return core::retry_after_sec_to_ms_sat(secs), true;
    }

    // 2. Check for HTTP-date (IMF-fixdate, e.g. "Wed, 21 Oct 2015 07:28:00 GMT")
    let parsed_time, ok_t = core::parse_http_date(clean);
    guard ok_t else { return 0, false; }

    // Strict validation: exact IMF-fixdate round-trip check to catch invalid calendar days
    var formatted_back: u8[..64] = [];
    format_http(formatted_back, parsed_time);
    guard eq_ascii_fold(formatted_back[..], clean) else { return 0, false; }

    let target_unix_ms = unix_milli(parsed_time);
    if target_unix_ms <= now_unix_ms {
        // Date is in the past: clamp to 0 ms (immediate retry allowed)
        return 0, true;
    }

    let delta_ms = target_unix_ms - now_unix_ms;
    return delta_ms, true;
}

// Local Host Circuit Breaker registry entry for excessive Retry-After windows
struct HostCircuitBreakerEntry {
    host: u8[..256] = [],
    blocked_until_mono_ns: i64 = 0,
    is_blocked: bool = false,
}

struct HostCircuitBreaker {
    hosts: HostCircuitBreakerEntry[..16] = [],
    max_retry_after_ms: i64 = 60000, // 60s interactive agent ceiling (or 24h for crawler)
}

fn new_host_circuit_breaker(max_wait_ms: i64 = 60000) -> HostCircuitBreaker {
    return HostCircuitBreaker {
        max_retry_after_ms: max_wait_ms,
        ..
    };
}

// Records or trips circuit breaker when Retry-After exceeds max allowable wait.
fn trip_circuit_breaker_if_exceeded(
    breaker: HostCircuitBreaker&,
    host_str: const u8[:],
    retry_after_ms: i64,
    now_mono_ns: i64
) -> bool {
    guard retry_after_ms > breaker.max_retry_after_ms else { return false; }

    let block_dur_ns = retry_after_ms * 1000000;
    let unblock_at = now_mono_ns + block_dur_ns;

    for &h in breaker.hosts {
        if eq_ascii_fold(h.host[..], host_str) {
            h.blocked_until_mono_ns = unblock_at;
            h.is_blocked = true;
            return true;
        }
    }

    if breaker.hosts.len < 16 {
        var entry = HostCircuitBreakerEntry {
            blocked_until_mono_ns: unblock_at,
            is_blocked: true,
            ..
        };
        entry.host.append(host_str);
        breaker.hosts.push(entry);
        return true;
    }

    return true;
}

// Checks whether requests to host are currently blocked by circuit breaker.
fn is_host_circuit_broken(
    breaker: HostCircuitBreaker&,
    host_str: const u8[:],
    now_mono_ns: i64
) -> bool {
    for &h in breaker.hosts {
        if eq_ascii_fold(h.host[..], host_str) {
            if h.is_blocked {
                if now_mono_ns >= h.blocked_until_mono_ns {
                    h.is_blocked = false;
                    return false;
                }
                return true;
            }
        }
    }
    return false;
}

// ---- 4. Adaptive Retry Budget (Google SRE) ---------------------------------

// Rate-limiting container capping retry traffic as a fixed percentage of total requests.
struct AdaptiveRetryBudget {
    window_start_mono_ns: i64 = 0,
    window_duration_ns: i64 = 10000000000, // 10s sliding window
    total_requests: i64 = 0,
    retried_requests: i64 = 0,
    max_retry_ratio_pct: i64 = 20,         // Max 20% retry ratio
    min_retries_per_sec: i64 = 2,          // 2 retries/sec minimum floor for low-traffic clients
}

fn new_adaptive_retry_budget(
    ratio_pct: i64 = 20,
    min_per_sec: i64 = 2,
    window_dur_sec: i64 = 10
) -> AdaptiveRetryBudget {
    return AdaptiveRetryBudget {
        window_duration_ns: window_dur_sec * 1000000000,
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
