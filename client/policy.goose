// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Networking and retry policies: exponential backoff and token bucket rate limiting.
namespace client;

import std;
import core;

// ---- exponential backoff policy --------------------------------------------

// Exponential backoff policy for retrying failed network requests.
struct Backoff {
    base_ns: i64 = 100 * core::MILLISECOND, // Base initial retry delay in nanoseconds.
    max_ns:  i64 = 10 * core::SECOND,       // Upper bound cap for retry delay in nanoseconds.
    factor:  f64 = 2.0,                     // Multiplier applied per failed attempt.
}

fn new_backoff(base_ns: i64, max_ns: i64, factor: f64 = 2.0) -> Backoff {
    return Backoff {
        base_ns: base_ns,
        max_ns:  max_ns,
        factor:  factor,
    };
}

// The retry delay for an attempt (0-indexed) in nanoseconds, capped at max_ns.
fn delay(backoff: const Backoff&, attempt: i64) -> i64 {
    let cap_ns = max(0, backoff.max_ns);
    let base_ns = max(0, backoff.base_ns);
    if attempt <= 0 || cap_ns == 0 || base_ns == 0 {
        return min(base_ns, cap_ns);
    }
    let eff_factor = if backoff.factor >= 1.0 { backoff.factor } else { 1.0 };
    let safe_attempt = min(attempt, 60);
    var current: f64 = base_ns;
    let cap_f64: f64 = cap_ns;
    for _ in safe_attempt {
        current *= eff_factor;
        if !(current < cap_f64) {
            return cap_ns;
        }
    }
    let res = current as i64;
    return min(max(0, res), cap_ns);
}

// ---- token bucket rate limiter ---------------------------------------------

// Token bucket rate limiter for pacing requests.
struct RateLimiter {
    rate_per_sec:        f64 = 1.0, // Tokens replenished per second.
    burst_capacity:      f64 = 1.0, // Maximum token capacity (allowed burst size).
    tokens:              f64 = 1.0, // Current available token balance.
    last_update_mono_ns: i64 = 0,   // Monotonic timestamp of the last token balance update.
}

fn new_rate_limiter(rate_per_sec: f64, burst: i64) -> RateLimiter {
    let capacity = if burst > 0 { burst as f64 } else { 1.0 };
    return RateLimiter {
        rate_per_sec:        rate_per_sec,
        burst_capacity:      capacity,
        tokens:              capacity,
        last_update_mono_ns: core::sim_now_ns(),
    };
}

// Attempts to consume one token using an explicit monotonic timestamp (for deterministic testing).
fn allow(limiter: RateLimiter&, now_mono: i64) -> bool {
    guard now_mono >= limiter.last_update_mono_ns && limiter.rate_per_sec > 0.0 && limiter.burst_capacity >= 1.0 else {
        return false;
    }
    let elapsed_sec = (now_mono - limiter.last_update_mono_ns) as f64 / 1000000000.0;
    var new_tokens = limiter.tokens + elapsed_sec * limiter.rate_per_sec;
    if !(new_tokens <= limiter.burst_capacity) {
        new_tokens = limiter.burst_capacity;
    }
    guard new_tokens >= 1.0 else { return false; }
    limiter.last_update_mono_ns = now_mono;
    limiter.tokens = new_tokens - 1.0;
    return true;
}

// Attempts to consume one token using the current monotonic system clock.
fn allow(limiter: RateLimiter&) -> bool {
    return allow(limiter, core::sim_now_ns());
}
