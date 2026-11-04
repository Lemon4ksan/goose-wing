// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Networking and retry policies: exponential backoff and token bucket rate limiting.
namespace wing;

import std;

// ---- exponential backoff policy --------------------------------------------

// Exponential backoff policy for retrying failed network requests.
struct Backoff {
    base_ns: i64 = 100 * core::MILLISECOND, // Base initial retry delay in nanoseconds.
    max_ns:  i64 = 10 * core::SECOND,       // Upper bound cap for retry delay in nanoseconds.
    factor:  f64 = 2.0,               // Multiplier applied per failed attempt.
}

fn new_backoff(base: core::Duration, max_delay: core::Duration, factor: f64 = 2.0) -> Backoff {
    return Backoff {
        base_ns: base.nanos,
        max_ns:  max_delay.nanos,
        factor:  factor,
    };
}

// The retry delay for an attempt (0-indexed), capped at max_ns.
fn delay(backoff: const Backoff&, attempt: i64) -> core::Duration {
    let cap_ns = backoff.max_ns;
    if attempt <= 0 {
        let initial = if backoff.base_ns > cap_ns { cap_ns } else { backoff.base_ns };
        return core::Duration { nanos: initial };
    }
    let safe_attempt = if attempt > 60 { 60 } else { attempt };
    var current: f64 = backoff.base_ns;
    for step_idx in safe_attempt {
        current *= backoff.factor;
        if current >= cap_ns {
            return core::Duration { nanos: cap_ns };
        }
    }
    let res = current as i64;
    return core::Duration { nanos: if res > cap_ns { cap_ns } else { res } };
}

// ---- token bucket rate limiter ---------------------------------------------

// Token bucket rate limiter for pacing requests.
struct RateLimiter {
    rate_per_sec:        f64 = 1.0,  // Tokens replenished per second.
    burst_capacity:      f64 = 1.0,  // Maximum token capacity (allowed burst size).
    tokens:              f64 = 1.0,  // Current available token balance.
    last_update_mono_ns: i64 = 0,    // Monotonic timestamp of the last token balance update.
}

fn new_rate_limiter(rate_per_sec: f64, burst: i64) -> RateLimiter {
    let capacity = if burst > 0 { burst as f64 } else { 1.0 };
    return RateLimiter {
        rate_per_sec:        rate_per_sec,
        burst_capacity:      capacity,
        tokens:              capacity,
        last_update_mono_ns: clock_ns(),
    };
}

// Attempts to consume one token using an explicit monotonic timestamp (for deterministic testing).
fn allow(limiter: RateLimiter&, now_mono: i64) -> bool {
    guard now_mono >= limiter.last_update_mono_ns else { return false; }
    let elapsed_sec = (now_mono - limiter.last_update_mono_ns) as f64 / 1000000000.0;
    limiter.last_update_mono_ns = now_mono;
    limiter.tokens += elapsed_sec * limiter.rate_per_sec;
    if limiter.tokens > limiter.burst_capacity {
        limiter.tokens = limiter.burst_capacity;
    }
    if limiter.tokens >= 1.0 {
        limiter.tokens -= 1.0;
        return true;
    }
    return false;
}

// Attempts to consume one token using the current monotonic system clock.
fn allow(limiter: RateLimiter&) -> bool {
    return allow(limiter, clock_ns());
}
