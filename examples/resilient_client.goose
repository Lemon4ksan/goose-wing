// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of goose-wing Two-Tier Resilience Engine:
// 1. Authenticated Request Construction with Idempotency & Tracing
// 2. Tier 1 Zero-Delay Stale Socket Recovery (net/http invariants)
// 3. Tier 2 Exponential Backoff with AWS Jitter Strategies
// 4. Google SRE Adaptive Retry Budget (Token Bucket traffic capping)
// 5. Host Circuit Breaker & RFC 9110 Retry-After Protection
import std;
import core from "..";
import wing from "..";

fn main() {
    print("============================================================");
    print(" goose-wing Resilient Networking & SRE Fault-Tolerance Demo");
    print("============================================================");

    // 1. Build an authenticated, idempotent request with distributed tracing
    var req = wing::new_request("POST", "/v1/payments/settle") { r =>
        r.bearer("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M");
        r.set_header("Idempotency-Key", "idemp-wing-987654321");
        r.set_header("Content-Type", "application/json");
        r.query("dry_run", "false");
        r.text("{\"account_id\":10928,\"amount_cents\":4950}");
    };
    wing::enrich_tracing(req, "trace-wing-9988-cluster");

    print("\n[1] Outgoing Authenticated Request Constructed:");
    print("    Method: ", req.method, ", Target URL: ", req.url);
    print("    Idempotency-Key: ", req.header("Idempotency-Key"));
    print("    X-Trace-Id: ", req.header("X-Trace-Id"));
    print("    Payload: ", req.body);

    // 2. Tier 1: Zero-Delay Stale Socket Recovery Verification
    // net/http invariant: reused Keep-Alive sockets that broke before headers arrive
    // are automatically retried without sleeping if idempotent or has Idempotency-Key.
    let is_reused_conn = true;
    let headers_received = false;
    let tier1_allowed = wing::should_retry_tier1_stale_socket(is_reused_conn, headers_received, req);
    print("\n[2] Tier 1 Zero-Delay Stale Socket Recovery:");
    print("    Reused Connection: ", is_reused_conn, ", Headers Received: ", headers_received);
    print("    Eligible for Instant Stale Re-dial: ", tier1_allowed);

    // 3. Tier 2: Exponential Backoff with AWS Jitter Algorithms
    var b_cfg = wing::BackoffConfig {
        base_ms: 100,
        cap_ms: 2000,
        strategy: wing::JitterStrategy.EqualJitter,
    };
    var rng_seed: u64 = 133742;
    var prev_sleep: i64 = 0;

    print("\n[3] Tier 2 Exponential Backoff with AWS Equal Jitter:");
    print("    Base: 100ms, Cap: 2000ms, Strategy: EqualJitter");
    for attempt in 4 {
        let sleep_ms = wing::compute_backoff_jitter_ms(b_cfg, attempt, prev_sleep, rng_seed);
        print("    -> Attempt ", attempt + 1, " Backoff Delay: ", sleep_ms, "ms");
    }

    // 4. Google SRE Adaptive Retry Budget
    // Prevents thundering herds by limiting retries to <= 20% of total cluster egress
    var budget = wing::new_adaptive_retry_budget(20, 2, 10);
    print("\n[4] Google SRE Adaptive Retry Budget (Max 20% retry ratio):");
    let now_mono_ns: i64 = 1000000000;
    wing::record_primary_request(budget, now_mono_ns);
    wing::record_primary_request(budget, now_mono_ns);
    wing::record_primary_request(budget, now_mono_ns);

    let can_retry_1 = wing::allow_retry_budget(budget, now_mono_ns);
    print("    Requests: 3, Retries allowed under budget: ", can_retry_1);

    // 5. Host Circuit Breaker & RFC 9110 Retry-After Protection
    // Configured with a max allowable retry delay of 10s (10000ms)
    var breaker = wing::new_host_circuit_breaker(10000);
    let target_host = "api.internal.cluster";

    print("\n[5] Host Circuit Breaker & RFC 9110 Retry-After Evaluation:");
    let initial_status = wing::is_host_circuit_broken(breaker, target_host, now_mono_ns);
    print("    Initial Host '", target_host, "' Broken: ", initial_status);

    // Upstream sends 503 Service Unavailable with Retry-After: 30 (30,000ms)
    let retry_after_header = "30";
    let retry_after_ms, ok_ra = wing::parse_retry_after_ms(retry_after_header, 1700000000000);
    print("    Parsed Upstream 'Retry-After: 30' -> ", retry_after_ms, "ms (Valid: ", ok_ra, ")");

    // Exceeds 10s max allowable wait -> Trips host circuit breaker
    let tripped = wing::trip_circuit_breaker_if_exceeded(breaker, target_host, retry_after_ms, now_mono_ns);
    let tripped_status = wing::is_host_circuit_broken(breaker, target_host, now_mono_ns);
    print("    Excessive Delay Tripped Circuit: ", tripped, " (Host Blocked: ", tripped_status, ")");

    // Fast-forward past the backoff window
    let future_mono_ns = now_mono_ns + (retry_after_ms * 1000000) + 1000;
    let recovered_status = wing::is_host_circuit_broken(breaker, target_host, future_mono_ns);
    print("    After 30s Expiry -> Host Automatically Recovered: ", !recovered_status);

    print("\n============================================================");
    print(" Fault-Tolerance Demo Complete (100% Zero-Allocation)");
    print("============================================================");
}
