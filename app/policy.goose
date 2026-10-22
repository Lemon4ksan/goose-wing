// Networking and resilience policies for goose-wing (Backoff, RateLimiter).
namespace wing;

import std;
import core.time;

// --- Exponential Backoff ---

struct Backoff {
    base_ns: i64 = 100 * MILLISECOND,
    max_ns: i64 = 10 * SECOND,
    factor: f64 = 2.0,
}

fn new_backoff(base: Duration, max_delay: Duration, factor: f64 = 2.0) -> Backoff {
    return Backoff {
        base_ns: base.nanos,
        max_ns: max_delay.nanos,
        factor: factor,
    };
}

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

struct RateLimiter {
    rate_per_sec: f64 = 1.0,
    burst_capacity: f64 = 1.0,
    tokens: f64 = 1.0,
    last_update_mono_ns: i64 = 0,
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
