// Networking and resilience policies for goose-wing (Backoff, RateLimiter).
namespace wing;

import std;
import core.time;

// Exponential backoff policy for retrying failed network requests.
struct Backoff {
    base_ns: i64 = 100 * MILLISECOND, // Base initial retry delay in nanoseconds.
    max_ns: i64 = 10 * SECOND,        // Upper bound cap for retry delay in nanoseconds.
    factor: f64 = 2.0,                // Multiplier applied per failed attempt.
}

fn new_backoff(base: Duration, max_delay: Duration, factor: f64 = 2.0) -> Backoff {
    return Backoff {
        base_ns: base.nanos,
        max_ns: max_delay.nanos,
        factor: factor,
    };
}

// Calculates retry delay for the given attempt count (0-indexed). Capped at max_ns.
fn delay(backoff: const Backoff&, attempt: i64) -> Duration {
    if attempt <= 0 { return Duration { nanos: backoff.base_ns }; }
    var current: f64 = backoff.base_ns;
    for step_idx in attempt {
        current *= backoff.factor;
        if current >= backoff.max_ns {
            return Duration { nanos: backoff.max_ns };
        }
    }
    let res = current as i64;
    return Duration { nanos: if res > backoff.max_ns { backoff.max_ns } else { res } };
}

// --- Token Bucket Rate Limiter ---

// Token bucket rate limiter for pacing outbound network requests.
struct RateLimiter {
    rate_per_sec: f64 = 1.0,         // Tokens replenished per second.
    burst_capacity: f64 = 1.0,       // Maximum token capacity (allowed burst size).
    tokens: f64 = 1.0,               // Current available token balance.
    last_update_mono_ns: i64 = 0,    // Monotonic timestamp of the last token balance update.
}

fn new_rate_limiter(rate_per_sec: f64, burst: i64) -> RateLimiter {
    let capacity = if burst > 0 { burst as f64 } else { 1.0 };
    return RateLimiter {
        rate_per_sec: rate_per_sec,
        burst_capacity: capacity,
        tokens: capacity,
        last_update_mono_ns: clock_ns(),
    };
}

// Attempts to consume 1 token. Returns true if request is allowed, or false if rate limit is exhausted.
fn allow(limiter: RateLimiter&) -> bool {
    let now_mono = clock_ns();
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
