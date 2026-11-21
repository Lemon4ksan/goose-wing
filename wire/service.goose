// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Protocol-agnostic zero-allocation resilience middleware layers (Service<Req, Res> combinators).
namespace wire;

import std;
import core;
import .pipeline;

// RFC 9110 Section 15.5.22: 429 (Too Many Requests) - status code returned on rate-limit rejection.
const SERVICE_STATUS_TOO_MANY_REQUESTS: u16 = 429;

// RFC 9110 Section 15.6.4: 503 (Service Unavailable) - status code returned when circuit breaker is open.
const SERVICE_STATUS_UNAVAILABLE: u16 = 503;

// Default error code returned when a retry loop terminates without a valid attempt.
const SERVICE_ERR_EXCHANGE_ABORTED: i32 = -1;

// ---- 1. Service Call & Layer Stacking Combinators ---------------------------

// Compile-time zero-allocation middleware wrapper pairing an outer service stage with an inner service.
struct LayeredService<Outer, Inner> {
    outer: Outer,
    inner: Inner,
}

// Composes `outer` and `inner` into a monomorphized `LayeredService<Outer, Inner>` without heap allocation.
inline fn stack_service<Outer, Inner>(outer: Outer, inner: Inner) -> LayeredService<Outer, Inner> {
    return LayeredService<Outer, Inner> {
        outer: outer,
        inner: inner,
    };
}

// Executes `svc.outer.exchange(req, res)` first and forwards to `svc.inner.exchange(req, res)` on `Continue`.
fn exchange<Outer, Inner, Req, Res>(
    svc: LayeredService<Outer, Inner>&,
    req: const Req&,
    res: Res&,
) -> StageVerdict {
    let outer_verdict = svc.outer.exchange(req, res);
    guard outer_verdict == StageVerdict.Continue else { return outer_verdict; }
    return svc.inner.exchange(req, res);
}

// ---- 2. Protocol-Agnostic Retry Middleware ----------------------------------

// Token-bucket retry policy parameters bounding per-request attempts and aggregate retry amplification.
struct RetryConfig {
    max_attempts:  i32 = 3,
    budget_tokens: i32 = 100,
    budget_max:    i32 = 100,
    token_cost:    i32 = 10,
    reward_tokens: i32 = 1,
}

// Monomorphized retry middleware wrapping any `<Inner>` service over `<Req, Res>`.
struct RetryService<Inner> {
    inner:                  Inner,
    config:                 RetryConfig = RetryConfig { .. },
    retries_executed:       u64         = 0,
    budget_exhausted_count: u64         = 0,
}

// Constructs a `RetryService<Inner>` configured with `max_attempts` (clamped to `>= 1`).
fn new_retry_service<Inner>(inner: Inner, max_attempts: i32 = 3) -> RetryService<Inner> {
    return RetryService<Inner> {
        inner:  inner,
        config: RetryConfig { max_attempts: max(max_attempts, 1), .. },
        ..
    };
}

// Returns true when a pipeline verdict indicates a transient failure eligible for retry.
inline fn is_transient_service_verdict(verdict: StageVerdict) -> bool {
    return match verdict {
        RetryAuth => true,
        Abort _ => true,
        _ => false,
    };
}

// Returns true when the retry token bucket holds enough tokens to fund a retry attempt.
inline fn can_afford_retry(cfg: const RetryConfig&) -> bool {
    return cfg.budget_tokens >= cfg.token_cost;
}

// Replenishes the retry token budget upon a `Continue` verdict, clamped to `budget_max`.
inline fn replenish_retry_budget(cfg: RetryConfig&) {
    let replenished = core::add_sat_i64(cfg.budget_tokens, cfg.reward_tokens);
    let ceiling = max(cfg.budget_max, 0) as i64;
    cfg.budget_tokens = min(max(replenished, 0), ceiling) as i32;
}

// Deducts `token_cost` from the retry budget when capacity permits, or increments `budget_exhausted_count`.
inline fn consume_retry_budget<Inner>(svc: RetryService<Inner>&) -> bool {
    guard svc.config.can_afford_retry() else {
        svc.budget_exhausted_count = core::add_sat_u64(svc.budget_exhausted_count, 1);
        return false;
    }
    let remaining = core::sub_sat_i64(svc.config.budget_tokens, svc.config.token_cost);
    svc.config.budget_tokens = max(remaining, 0) as i32;
    svc.retries_executed = core::add_sat_u64(svc.retries_executed, 1);
    return true;
}

// Executes `svc.inner.exchange(req, res)` in a bounded loop up to `svc.config.max_attempts`.
// Retries on `RetryAuth` or `Abort` when `req.is_retryable_request()` and the token budget allows.
fn exchange<Inner, Req, Res>(svc: RetryService<Inner>&, req: const Req&, res: Res&) -> StageVerdict {
    let max_tries = max(svc.config.max_attempts, 1) as i64;
    var last_verdict: StageVerdict = StageVerdict.Abort { err_code: SERVICE_ERR_EXCHANGE_ABORTED };
    var attempt:      i64          = 0;
    while attempt < max_tries {
        attempt = core::add_sat_i64(attempt, 1);
        last_verdict = svc.inner.exchange(req, res);
        if last_verdict == StageVerdict.Continue {
            replenish_retry_budget(svc.config);
            return last_verdict;
        }
        guard attempt < max_tries else { return last_verdict; }
        guard is_transient_service_verdict(last_verdict) && req.is_retryable_request() else {
            return last_verdict;
        }
        guard consume_retry_budget(svc) else { return last_verdict; }
    }
    return last_verdict;
}

// ---- 3. Protocol-Agnostic Rate-Limit Middleware -----------------------------

// Monomorphized rate-limiting middleware evaluating `req.service_key()` against `<Limiter>`.
struct RateLimitService<Inner, Limiter> {
    inner:          Inner,
    limiter:        Limiter,
    now_ns:         u64 = 0,
    rejected_count: u64 = 0,
}

// Constructs a `RateLimitService<Inner, Limiter>` initialized at `now_ns`.
fn new_rate_limit_service<Inner, Limiter>(
    inner:   Inner,
    limiter: Limiter,
    now_ns:  u64 = 0,
) -> RateLimitService<Inner, Limiter> {
    return RateLimitService<Inner, Limiter> {
        inner:          inner,
        limiter:        limiter,
        now_ns:         now_ns,
        rejected_count: 0,
    };
}

// Evaluates `svc.limiter.allow_service_key(req.service_key(), svc.now_ns)` before forwarding to `svc.inner`.
fn exchange<Inner, Limiter, Req, Res>(
    svc: RateLimitService<Inner, Limiter>&,
    req: const Req&,
    res: Res&,
) -> StageVerdict {
    let key = req.service_key();
    if !svc.limiter.allow_service_key(key, svc.now_ns) {
        svc.rejected_count = core::add_sat_u64(svc.rejected_count, 1);
        return StageVerdict.ShortCircuit { status_code: SERVICE_STATUS_TOO_MANY_REQUESTS };
    }
    return svc.inner.exchange(req, res);
}

// ---- 4. Protocol-Agnostic Circuit Breaker Middleware ------------------------

// Operational state of a `CircuitBreakerService` finite state machine.
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

// Monomorphized circuit breaker middleware isolating failing backends with a timed cooldown window.
struct CircuitBreakerService<Inner> {
    inner:                Inner,
    state:                BreakerState = BreakerState.Closed,
    failure_threshold:    u32          = 5,
    consecutive_failures: u32          = 0,
    open_until_ms:        u64          = 0,
    cooldown_ms:          u64          = 5000,
    now_ms:               u64          = 0,
}

// Constructs a `CircuitBreakerService<Inner>` with `failure_threshold` and `cooldown_ms`.
fn new_circuit_breaker_service<Inner>(
    inner:             Inner,
    failure_threshold: u32 = 5,
    cooldown_ms:       u64 = 5000,
) -> CircuitBreakerService<Inner> {
    return CircuitBreakerService<Inner> {
        inner:             inner,
        state:             BreakerState.Closed,
        failure_threshold: max(failure_threshold, 1),
        cooldown_ms:       cooldown_ms,
        ..
    };
}

// Returns true when the circuit breaker is actively open inside its cooldown window.
inline fn is_breaker_open<Inner>(svc: const CircuitBreakerService<Inner>&) -> bool {
    return svc.state == BreakerState.Open && svc.now_ms < svc.open_until_ms;
}

// Resets the circuit breaker state machine and failure counters back to `Closed`.
fn reset_breaker<Inner>(svc: CircuitBreakerService<Inner>&) {
    svc.state = BreakerState.Closed;
    svc.consecutive_failures = 0;
    svc.open_until_ms = 0;
}

// Advances the circuit breaker monotonic clock to `now_ms` and transitions `Open` to `HalfOpen` after cooldown.
fn advance_breaker_clock<Inner>(svc: CircuitBreakerService<Inner>&, now_ms: u64) {
    svc.now_ms = now_ms;
    if svc.state == BreakerState.Open && svc.now_ms >= svc.open_until_ms {
        svc.state = BreakerState.HalfOpen;
    }
}

// Updates circuit breaker state and failure counters following an inner service `verdict`.
inline fn record_breaker_outcome<Inner>(svc: CircuitBreakerService<Inner>&, verdict: StageVerdict) {
    match verdict {
        Abort _ => {
            let fails = core::add_sat_u32(svc.consecutive_failures, 1);
            svc.consecutive_failures = fails;
            if fails >= svc.failure_threshold || svc.state == BreakerState.HalfOpen {
                svc.state = BreakerState.Open;
                svc.open_until_ms = core::add_sat_u64(svc.now_ms, svc.cooldown_ms);
            }
        },
        Continue => {
            svc.consecutive_failures = 0;
            svc.state = BreakerState.Closed;
        },
        _ => {},
    };
}

// Short-circuits with 503 when `Open` before `open_until_ms`, probes in `HalfOpen`, and trips on `Abort`.
fn exchange<Inner, Req, Res>(svc: CircuitBreakerService<Inner>&, req: const Req&, res: Res&) -> StageVerdict {
    if svc.is_breaker_open() {
        return StageVerdict.ShortCircuit { status_code: SERVICE_STATUS_UNAVAILABLE };
    }
    if svc.state == BreakerState.Open {
        svc.state = BreakerState.HalfOpen;
    }
    let verdict = svc.inner.exchange(req, res);
    record_breaker_outcome(svc, verdict);
    return verdict;
}

// ---- 5. Protocol-Agnostic Coalescing / Singleflight Middleware --------------

// Monomorphized request-coalescing middleware backed by `core::SingleflightGroup`.
struct SingleflightService<Inner> {
    inner:          Inner,
    group:          core::SingleflightGroup = core::SingleflightGroup { .. },
    coalesced_hits: u64                     = 0,
}

// Constructs a `SingleflightService<Inner>` with an empty `core::SingleflightGroup`.
fn new_singleflight_service<Inner>(inner: Inner) -> SingleflightService<Inner> {
    return SingleflightService<Inner> {
        inner: inner,
        ..
    };
}

// Suppresses duplicate calls sharing `req.service_key()` via `svc.group`, executing `svc.inner` for the leader.
fn exchange<Inner, Req, Res>(svc: SingleflightService<Inner>&, req: const Req&, res: Res&) -> StageVerdict {
    let key = req.service_key();
    guard key.len > 0 else {
        return svc.inner.exchange(req, res);
    }
    let is_leader, _, _ = core::start_or_join(svc.group, key);
    if !is_leader {
        svc.coalesced_hits = core::add_sat_u64(svc.coalesced_hits, 1);
        return StageVerdict.Continue;
    }
    let verdict = svc.inner.exchange(req, res);
    if verdict == StageVerdict.Continue {
        let _, _ = core::finish_call(svc.group, key, 1, true);
    } else {
        let _, _ = core::finish_call(svc.group, key, 0, false);
        let _ = core::forget(svc.group, key);
    }
    return verdict;
}
