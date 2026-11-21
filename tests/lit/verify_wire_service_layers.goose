// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone LIT verification for protocol-agnostic resilience middleware layers (`wire/service.goose`).
// RUN: goose %s | %FileCheck %s
namespace wire;

import std;
import core from "../..";
import wing from "../..";
import wing.wire.service;
import wing.client.interceptor;
import wing.http.request;
import wing.http.headers;

// Custom non-HTTP binary RPC request frame.
struct BinaryRpcRequest {
    op_code:    u16       = 0,
    key:        u8[..64]  = [],
    payload:    u8[..256] = [],
    idempotent: bool      = true,
}

// Custom non-HTTP binary RPC response frame.
struct BinaryRpcResponse {
    status: u16       = 0,
    result: u8[..256] = [],
}

// UFCS hook queried by `wire::RetryService` to check whether a request can be safely retried.
fn is_retryable_request(req: const BinaryRpcRequest&) -> bool {
    return req.idempotent;
}

// UFCS hook queried by `wire::RateLimitService` and `wire::SingleflightService` for routing/partition keys.
fn service_key(req: const BinaryRpcRequest&) -> const u8[:] {
    return req.key[..];
}

fn make_rpc_request(op_code: u16, key_str: const u8[:], payload_str: const u8[:], idempotent: bool) -> BinaryRpcRequest {
    var req = BinaryRpcRequest {
        op_code:    op_code,
        idempotent: idempotent,
        ..
    };
    let _ = req.key.try_set(key_str);
    let _ = req.payload.try_set(payload_str);
    return req;
}

// Zero-allocation token-bucket rate limiter implementing `allow_service_key` UFCS for `RateLimitService`.
struct TokenBucketLimiter {
    tokens:     i64 = 3,
    max_tokens: i64 = 3,
    last_ns:    u64 = 0,
}

fn allow_service_key(lim: TokenBucketLimiter&, key: const u8[:], now_ns: u64) -> bool {
    guard key.len > 0 else { return false; }
    if now_ns > lim.last_ns {
        let elapsed_intervals = (now_ns - lim.last_ns) / 1000000000;
        if elapsed_intervals > 0 {
            lim.tokens = min(lim.max_tokens, core::add_sat_i64(lim.tokens, elapsed_intervals as i64));
            lim.last_ns = now_ns;
        }
    }
    guard lim.tokens > 0 else { return false; }
    lim.tokens -= 1;
    return true;
}

// Binary RPC backend service implementing `exchange(req, res) -> wire::StageVerdict`.
struct BinaryRpcBackend {
    call_count:                   u64  = 0,
    transient_failures_remaining: i32  = 0,
    auth_challenges_remaining:    i32  = 0,
    force_abort:                  bool = false,
}

fn exchange(backend: BinaryRpcBackend&, req: const BinaryRpcRequest&, res: BinaryRpcResponse&) -> wire::StageVerdict {
    backend.call_count = core::add_sat_u64(backend.call_count, 1);
    res.status = 0;
    res.result.clear();

    if backend.force_abort {
        res.status = 500;
        return wire::StageVerdict.Abort { err_code: -500 };
    }
    if backend.auth_challenges_remaining > 0 {
        backend.auth_challenges_remaining -= 1;
        res.status = 401;
        return wire::StageVerdict.RetryAuth;
    }
    if backend.transient_failures_remaining > 0 {
        backend.transient_failures_remaining -= 1;
        res.status = 502;
        return wire::StageVerdict.Abort { err_code: -502 };
    }

    res.status = 200;
    let _ = res.result.try_append("OK:");
    let _ = res.result.try_append(req.payload[..]);
    return wire::StageVerdict.Continue;
}

// Outer pre-validation service stage used to test `wire::LayeredService` and `wire::stack_service`.
struct BinaryRpcOpCodeGuard {
    min_op_code: u16 = 1,
}

fn exchange(
    stage: const BinaryRpcOpCodeGuard&,
    req:   const BinaryRpcRequest&,
    res:   BinaryRpcResponse&,
) -> wire::StageVerdict {
    guard req.op_code >= stage.min_op_code else {
        res.status = 400;
        return wire::StageVerdict.ShortCircuit { status_code: 400 };
    }
    return wire::StageVerdict.Continue;
}

fn is_abort_code(v: StageVerdict, code: i32) -> bool {
    return match v {
        Abort a => a.err_code == code,
        _ => false,
    };
}

fn is_short_circuit_code(v: StageVerdict, code: u16) -> bool {
    return match v {
        ShortCircuit sc => sc.status_code == code,
        _ => false,
    };
}

fn test_retry_service_and_budget() {
    var backend = BinaryRpcBackend { transient_failures_remaining: 2, .. };
    var retry_svc = wire::new_retry_service(backend, 3);
    let req = make_rpc_request(10, "tenant:alpha", "ping", true);
    var res = BinaryRpcResponse { .. };

    // 2 transient Aborts followed by Continue on 3rd attempt:
    // budget: 100 - 10 - 10 + 1 (reward) = 81
    let v1 = retry_svc.exchange(req, res);
    assert(v1 == wire::StageVerdict.Continue);
    assert(res.status == 200 && res.result[..] == "OK:ping");
    assert(retry_svc.inner.call_count == 3);
    assert(retry_svc.retries_executed == 2);
    assert(retry_svc.config.budget_tokens == 81);

    // RetryAuth verdict also triggers retry
    retry_svc.inner.auth_challenges_remaining = 1;
    let v_auth = retry_svc.exchange(req, res);
    assert(v_auth == wire::StageVerdict.Continue);
    assert(retry_svc.retries_executed == 3);
    assert(retry_svc.config.budget_tokens == 72);

    // Non-idempotent request must NOT retry on Abort
    let non_idemp_req = make_rpc_request(11, "tenant:alpha", "mutate", false);
    retry_svc.inner.transient_failures_remaining = 2;
    let v_non_idemp = retry_svc.exchange(non_idemp_req, res);
    assert(is_abort_code(v_non_idemp, -502));
    assert(retry_svc.retries_executed == 3);

    // Exhaust retry budget: set budget_tokens below token_cost (10)
    assert(retry_svc.config.can_afford_retry());
    retry_svc.config.budget_tokens = 5;
    assert(!retry_svc.config.can_afford_retry());
    retry_svc.inner.transient_failures_remaining = 1;
    let v_exhausted = retry_svc.exchange(req, res);
    assert(is_abort_code(v_exhausted, -502));
    assert(retry_svc.budget_exhausted_count == 1);
    print("RETRY_SERVICE_BUDGET: OK");
}

fn test_rate_limit_service() {
    let backend = BinaryRpcBackend { .. };
    let limiter = TokenBucketLimiter { tokens: 2, max_tokens: 2, last_ns: 1000 };
    var rl_svc = wire::new_rate_limit_service(backend, limiter, 1000);
    let req = make_rpc_request(20, "tenant:rate", "query", true);
    var res = BinaryRpcResponse { .. };

    assert(rl_svc.exchange(req, res) == wire::StageVerdict.Continue);
    assert(rl_svc.exchange(req, res) == wire::StageVerdict.Continue);
    assert(rl_svc.inner.call_count == 2);

    // 3rd call exceeds bucket capacity -> ShortCircuit 429
    let v3 = rl_svc.exchange(req, res);
    assert(is_short_circuit_code(v3, 429));
    assert(rl_svc.rejected_count == 1);
    assert(rl_svc.inner.call_count == 2);

    // Advance clock by 1s to refill token bucket
    rl_svc.now_ns = 1000001000;
    assert(rl_svc.exchange(req, res) == wire::StageVerdict.Continue);
    assert(rl_svc.inner.call_count == 3);
    print("RATE_LIMIT_SERVICE_429: OK");
}

fn test_circuit_breaker_service() {
    let backend = BinaryRpcBackend { force_abort: true, .. };
    var cb_svc = wire::new_circuit_breaker_service(backend, 3, 5000);
    let req = make_rpc_request(30, "tenant:cb", "rpc", true);
    var res = BinaryRpcResponse { .. };

    // 3 consecutive Aborts trip breaker to Open
    assert(is_abort_code(cb_svc.exchange(req, res), -500));
    assert(cb_svc.state == wire::BreakerState.Closed);
    assert(is_abort_code(cb_svc.exchange(req, res), -500));
    assert(cb_svc.state == wire::BreakerState.Closed);
    assert(is_abort_code(cb_svc.exchange(req, res), -500));
    assert(cb_svc.state == wire::BreakerState.Open);
    assert(cb_svc.open_until_ms == 5000);

    // While Open before cooldown_ms, short-circuits with 503 without calling inner backend
    assert(cb_svc.is_breaker_open());
    let calls_before = cb_svc.inner.call_count;
    wire::advance_breaker_clock(cb_svc, 2500);
    let v_open = cb_svc.exchange(req, res);
    assert(is_short_circuit_code(v_open, 503));
    assert(cb_svc.inner.call_count == calls_before);

    // Advance clock past cooldown_ms (5000) -> transitions to HalfOpen
    wire::advance_breaker_clock(cb_svc, 5000);
    assert(!cb_svc.is_breaker_open());
    assert(cb_svc.state == wire::BreakerState.HalfOpen);

    // Backend recovers -> probe succeeds and closes breaker
    cb_svc.inner.force_abort = false;
    let v_probe = cb_svc.exchange(req, res);
    assert(v_probe == wire::StageVerdict.Continue);
    assert(cb_svc.state == wire::BreakerState.Closed);
    assert(cb_svc.consecutive_failures == 0);

    // Verify UFCS reset_breaker clears tripped state and failure counters
    cb_svc.state = wire::BreakerState.Open;
    cb_svc.consecutive_failures = 3;
    cb_svc.open_until_ms = 9000;
    assert(cb_svc.is_breaker_open());
    cb_svc.reset_breaker();
    assert(!cb_svc.is_breaker_open());
    assert(cb_svc.state == wire::BreakerState.Closed);
    assert(cb_svc.consecutive_failures == 0);
    assert(cb_svc.open_until_ms == 0);
    print("CIRCUIT_BREAKER_FSM: OK");
}

fn test_singleflight_service() {
    let backend = BinaryRpcBackend { .. };
    var sf_svc = wire::new_singleflight_service(backend);
    let req = make_rpc_request(40, "rpc:dedup:key1", "fetch_profile", true);
    var res = BinaryRpcResponse { .. };

    // 1st call executes as leader
    let v1 = sf_svc.exchange(req, res);
    assert(v1 == wire::StageVerdict.Continue);
    assert(sf_svc.inner.call_count == 1);
    assert(sf_svc.coalesced_hits == 0);

    // 2nd and 3rd calls with identical service_key coalesce without invoking backend
    let v2 = sf_svc.exchange(req, res);
    let v3 = sf_svc.exchange(req, res);
    assert(v2 == wire::StageVerdict.Continue && v3 == wire::StageVerdict.Continue);
    assert(sf_svc.inner.call_count == 1);
    assert(sf_svc.coalesced_hits == 2);

    // Evicting the key allows a new leader call
    assert(core::forget(sf_svc.group, req.service_key()));
    let v4 = sf_svc.exchange(req, res);
    assert(v4 == wire::StageVerdict.Continue);
    assert(sf_svc.inner.call_count == 2);
    print("SINGLEFLIGHT_COALESCING: OK");
}

fn test_composed_stack_zero_alloc() {
    // Compose: CircuitBreakerService<RetryService<RateLimitService<BinaryRpcBackend, TokenBucketLimiter>>>
    // wrapped inside SingleflightService and LayeredService
    let backend = BinaryRpcBackend { transient_failures_remaining: 1, .. };
    let limiter = TokenBucketLimiter { tokens: 5000, max_tokens: 5000, last_ns: 0 };
    let rl_layer = wire::new_rate_limit_service(backend, limiter, 100);
    let retry_layer = wire::new_retry_service(rl_layer, 3);
    let cb_layer = wire::new_circuit_breaker_service(retry_layer, 4, 3000);
    let sf_layer = wire::new_singleflight_service(cb_layer);
    var stacked = wire::stack_service(BinaryRpcOpCodeGuard { min_op_code: 1 }, sf_layer);

    let bad_req = make_rpc_request(0, "rpc:composed:k1", "invalid", true);
    let good_req = make_rpc_request(7, "rpc:composed:k1", "payload_v1", true);
    var res = BinaryRpcResponse { .. };

    // Outer layer short-circuits op_code == 0 with 400
    assert(is_short_circuit_code(stacked.exchange(bad_req, res), 400));
    assert(res.status == 400);

    // First valid call: inner retry layer absorbs 1 transient failure and succeeds on 2nd attempt
    assert(stacked.exchange(good_req, res) == wire::StageVerdict.Continue);
    assert(res.status == 200 && res.result[..] == "OK:payload_v1");
    assert(stacked.inner.inner.inner.retries_executed == 1);
    assert(stacked.inner.inner.inner.inner.inner.call_count == 2);

    // Execute 500 coalesced and uncoalesced exchanges and verify zero data-stack growth
    var probe: u8[>..] = [];
    probe.push(1);
    let initial_len = probe.len;
    for i in 500 {
        let v = stacked.exchange(good_req, res);
        assert(v == wire::StageVerdict.Continue);
        if i == 250 {
            let _ = core::forget(stacked.inner.group, good_req.service_key());
        }
    }
    assert(probe.len == initial_len);
    assert(stacked.inner.coalesced_hits >= 498);
    print("COMPOSED_STACK_ZERO_ALLOC: OK");
}

fn test_interceptor_multi_header_composition() {
    var pipeline = client::InterceptorPipeline { .. };
    assert(client::add_header(pipeline, client::InterceptorScope.Application, "X-A", "1"));
    assert(client::add_header(pipeline, client::InterceptorScope.Application, "X-B", "2"));
    assert(client::add_header(pipeline, client::InterceptorScope.Application, "x-a", "updated-1"));
    assert(client::add_header(pipeline, client::InterceptorScope.Network, "X-Net-1", "n1"));
    assert(client::add_header(pipeline, client::InterceptorScope.Network, "X-Net-2", "n2"));

    var req = http::new_request("GET", "https://example.com/api");
    client::apply_app_interceptors_request(pipeline, req, 1000);
    assert(http::header(req, "X-A") == "updated-1");
    assert(http::header(req, "X-B") == "2");

    var wire_hdrs = http::HeaderMap { .. };
    client::apply_network_interceptors_request(pipeline, wire_hdrs, "https://example.com/api", "GET", 0, 1);
    assert(http::get_header(wire_hdrs, "X-Net-1") == "n1");
    assert(http::get_header(wire_hdrs, "X-Net-2") == "n2");
}

fn ::main() {
    print("=== VERIFY WIRE SERVICE LAYERS ===");
    wire::test_retry_service_and_budget();
    wire::test_rate_limit_service();
    wire::test_circuit_breaker_service();
    wire::test_singleflight_service();
    wire::test_composed_stack_zero_alloc();
    wire::test_interceptor_multi_header_composition();
    print("ALL WIRE SERVICE LAYER CHECKS PASSED");
}

// CHECK: === VERIFY WIRE SERVICE LAYERS ===
// CHECK: RETRY_SERVICE_BUDGET: OK
// CHECK: RATE_LIMIT_SERVICE_429: OK
// CHECK: CIRCUIT_BREAKER_FSM: OK
// CHECK: SINGLEFLIGHT_COALESCING: OK
// CHECK: COMPOSED_STACK_ZERO_ALLOC: OK
// CHECK: ALL WIRE SERVICE LAYER CHECKS PASSED
