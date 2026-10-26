// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for net/retry: Tier 1 zero-delay stale socket recovery,
// one-shot stream bug guards, QUIC protocol fallback, Full/Equal/Decorrelated Jitter,
// RFC 9110 Retry-After parser, circuit breaker, Google SRE adaptive retry budget,
// and Go #81671 (idempotent QUERY method).
import std;
import core from "..";
import wing from "..";

fn test_tier1_stale_socket_and_quic_fallback(t: core::T&) {
    t.run("Tier 1 4-Condition Invariant Evaluation") { sub =>
        // 1. Standard idempotent GET on reused Keep-Alive connection before headers
        var req_get = wing::new_request("GET", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_get), "Reused GET before headers approved for immediate Tier 1 retry");

        // 2. Fresh dial connection failure: MUST NOT retry at Tier 1 (fails fast)
        sub.assert_false(wing::should_retry_tier1_stale_socket(false, false, req_get), "Fresh connection failure rejected for Tier 1 retry");

        // 3. Response headers already received: MUST NOT retry at Tier 1
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, true, req_get), "Failure after response headers rejected for Tier 1 retry");

        // 4. Non-idempotent POST without Idempotency-Key: MUST NOT retry
        var req_post = wing::new_request("POST", "https://api.io/payments");
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, false, req_post), "Non-idempotent POST without Idempotency-Key rejected");

        // 5. Non-idempotent POST WITH Idempotency-Key: approved for retry
        wing::header(req_post, "Idempotency-Key", "uuid-v4-998811-aabbcc");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_post), "POST with Idempotency-Key approved for Tier 1 retry");

        // 6. Non-idempotent PATCH without Idempotency-Key: rejected
        var req_patch = wing::new_request("PATCH", "https://api.io/items/1");
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, false, req_patch), "PATCH without Idempotency-Key rejected");

        // 7. Non-idempotent PATCH WITH Idempotency-Key: approved
        wing::header(req_patch, "Idempotency-Key", "patch-key-1");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_patch), "PATCH with Idempotency-Key approved");

        // 8. Idempotent RFC methods sweep
        var req_head = wing::new_request("HEAD", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_head), "HEAD is idempotent");

        var req_put = wing::new_request("PUT", "https://api.io/items/1");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_put), "PUT is idempotent");

        var req_del = wing::new_request("DELETE", "https://api.io/items/1");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_del), "DELETE is idempotent");

        var req_opt = wing::new_request("OPTIONS", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_opt), "OPTIONS is idempotent");

        var req_trace = wing::new_request("TRACE", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_trace), "TRACE is idempotent");
    };

    t.run("Go #81671 & RFC 9110: QUERY Method Safe & Replayable") { sub =>
        // RFC 9110 and draft-ietf-httpbis-safe-method-w-body:
        // QUERY method is safe and idempotent, and carries a request body.
        // It MUST be replayable on stale socket disconnections.
        var req_query = wing::new_request("QUERY", "https://api.io/search");
        wing::text(req_query, "SELECT id, name FROM users WHERE active = true");
        sub.assert_true(wing::is_idempotent_method("QUERY"), "QUERY recognized as idempotent");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_query), "QUERY with rewindable body replayable on stale socket drop");
    };

    t.run("Defense against One-Shot Stream Retry Bug (Go #41907 / #41913)") { sub =>
        // Request with non-empty body that is NOT rewindable (already consumed stream)
        var req_stream = wing::new_request("PUT", "https://api.io/upload");
        req_stream.body.append("multipart-stream-chunk-data");
        req_stream.rewindable = false;
        req_stream.body_consumed = true;

        sub.assert_false(wing::should_retry_tier1_stale_socket(true, false, req_stream), "Unrewindable consumed body stream rejected (prevents sending empty body)");

        // Non-empty body with rewindable = false but body_consumed = false
        var req_unrewind = wing::new_request("PUT", "https://api.io/upload");
        req_unrewind.body.append("data");
        req_unrewind.rewindable = false;
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, false, req_unrewind), "Unrewindable body rejected");

        // Non-empty body with rewindable = true and body_consumed = true
        var req_consumed = wing::new_request("PUT", "https://api.io/upload");
        req_consumed.body.append("data");
        req_consumed.rewindable = true;
        req_consumed.body_consumed = true;
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, false, req_consumed), "Already-consumed rewindable body rejected");

        // Request with rewindable body buffer (GetBody pattern)
        var req_rewindable = wing::new_request("PUT", "https://api.io/upload");
        wing::text(req_rewindable, "rewindable-payload-data");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, false, req_rewindable), "Rewindable body approved for retry");
    };

    t.run("Chromium ERR_QUIC_PROTOCOL_ERROR Automatic TCP Fallback") { sub =>
        var req = wing::new_request("GET", "https://quic.example.com");
        let dec = wing::evaluate_tier1_retry(wing::ERR_QUIC_PROTOCOL_ERROR, false, false, req);

        sub.assert_true(dec.retry_immediately, "Immediate retry on ERR_QUIC_PROTOCOL_ERROR");
        sub.assert_true(dec.disable_alternative_services, "disable_alternative_services flagged to force reliable TCP/TLS");

        // If headers were already received, cannot fallback immediately
        let dec_headers = wing::evaluate_tier1_retry(wing::ERR_QUIC_PROTOCOL_ERROR, false, true, req);
        sub.assert_false(dec_headers.retry_immediately, "QUIC error after headers received does not trigger blind retry");
    };
}

fn test_tier2_exponential_backoff_and_jitter(t: core::T&) {
    t.run("Deterministic Backoff and 3 Jitter Strategies") { sub =>
        var seed: u64 = 123456789;
        var prev_sleep: i64 = 0;

        let cfg_full = wing::new_backoff_config(100, 5000, wing::JitterStrategy.FullJitter);
        let cfg_equal = wing::new_backoff_config(100, 5000, wing::JitterStrategy.EqualJitter);
        let cfg_decorr = wing::new_backoff_config(100, 5000, wing::JitterStrategy.DecorrelatedJitter);
        let cfg_none = wing::new_backoff_config(100, 5000, wing::JitterStrategy.None);

        // Attempt 0: target 100 ms
        let t0 = wing::compute_backoff_jitter_ms(cfg_none, 0, prev_sleep, seed);
        sub.assert_eq(t0, 100, "Attempt 0 deterministic delay is 100 ms");

        // Attempt 1: target 200 ms
        let t1 = wing::compute_backoff_jitter_ms(cfg_none, 1, prev_sleep, seed);
        sub.assert_eq(t1, 200, "Attempt 1 deterministic delay is 200 ms");

        // Attempt 3: target 100 * 2^3 = 800 ms
        let t3 = wing::compute_backoff_jitter_ms(cfg_none, 3, prev_sleep, seed);
        sub.assert_eq(t3, 800, "Attempt 3 deterministic delay is 800 ms");

        // Attempt 10: target 100 * 2^10 = 102400 ms -> clamped to cap 5000 ms
        let t10 = wing::compute_backoff_jitter_ms(cfg_none, 10, prev_sleep, seed);
        sub.assert_eq(t10, 5000, "Attempt 10 clamped to cap 5000 ms");

        // Attempt 50: large attempt number must NOT overflow 64-bit integer
        let t50 = wing::compute_backoff_jitter_ms(cfg_none, 50, prev_sleep, seed);
        sub.assert_eq(t50, 5000, "Attempt 50 clamped safely without integer overflow");

        // Full Jitter: in range [0, 800]
        for i in 20 {
            let fj = wing::compute_backoff_jitter_ms(cfg_full, 3, prev_sleep, seed);
            sub.assert_true(fj >= 0 && fj <= 800, "Full Jitter within [0, 800]");
        }

        // Equal Jitter: in range [half, target] = [400, 800]
        for i in 20 {
            let ej = wing::compute_backoff_jitter_ms(cfg_equal, 3, prev_sleep, seed);
            sub.assert_true(ej >= 400 && ej <= 800, "Equal Jitter maintains non-zero floor within [400, 800]");
        }

        // Decorrelated Jitter bounded by [base, cap]
        prev_sleep = 100;
        for i in 20 {
            let dj = wing::compute_backoff_jitter_ms(cfg_decorr, 3, prev_sleep, seed);
            sub.assert_true(dj >= 100 && dj <= 5000, "Decorrelated Jitter bounded by [base, cap]");
        }
    };
}

fn test_rfc9110_retry_after_parser(t: core::T&) {
    t.run("delay-seconds (1*DIGIT) Parsing") { sub =>
        let now_ms: i64 = 1700000000000;

        let ms0, ok0 = wing::parse_retry_after_ms("0", now_ms);
        sub.assert_true(ok0, "Parsed delay-seconds '0'");
        sub.assert_eq(ms0, 0, "0 seconds is 0 ms");

        let ms1, ok1 = wing::parse_retry_after_ms("1", now_ms);
        sub.assert_true(ok1, "Parsed delay-seconds '1'");
        sub.assert_eq(ms1, 1000, "1 second is 1000 ms");

        let ms120, ok120 = wing::parse_retry_after_ms("120", now_ms);
        sub.assert_true(ok120, "Parsed delay-seconds '120'");
        sub.assert_eq(ms120, 120000, "120 seconds is 120,000 ms");

        let ms86400, ok86400 = wing::parse_retry_after_ms("86400", now_ms);
        sub.assert_true(ok86400, "Parsed delay-seconds '86400'");
        sub.assert_eq(ms86400, 86400000, "86400 seconds is 86,400,000 ms (24h)");

        // Leading/trailing whitespace trimmed
        let ms_ws, ok_ws = wing::parse_retry_after_ms("  45  ", now_ms);
        sub.assert_true(ok_ws, "Parsed delay-seconds with whitespace");
        sub.assert_eq(ms_ws, 45000, "45 seconds is 45,000 ms");

        // Invalid integer formats rejected
        let _, bad1 = wing::parse_retry_after_ms("120s", now_ms);
        sub.assert_false(bad1, "Rejected unit suffix '120s'");

        let _, bad2 = wing::parse_retry_after_ms("-10", now_ms);
        sub.assert_false(bad2, "Rejected negative delay-seconds '-10'");

        let _, bad3 = wing::parse_retry_after_ms("+10", now_ms);
        sub.assert_false(bad3, "Rejected explicit positive sign '+10'");

        let _, bad4 = wing::parse_retry_after_ms("12.5", now_ms);
        sub.assert_false(bad4, "Rejected decimal delay-seconds '12.5'");

        let _, bad5 = wing::parse_retry_after_ms("abc", now_ms);
        sub.assert_false(bad5, "Rejected alphanumeric string");

        let _, bad6 = wing::parse_retry_after_ms("", now_ms);
        sub.assert_false(bad6, "Rejected empty string");

        let _, bad7 = wing::parse_retry_after_ms("   ", now_ms);
        sub.assert_false(bad7, "Rejected whitespace-only string");
    };

    t.run("IMF-fixdate Parsing and Exact UTC Round-Trip Validation") { sub =>
        // Wednesday, 21 Oct 2015 07:28:00 GMT = 1445412480000 ms
        let http_date = "Wed, 21 Oct 2015 07:28:00 GMT";

        // If current time is earlier (e.g. 1445412470000, 10s earlier)
        let delta_ms, ok_date = wing::parse_retry_after_ms(http_date, 1445412470000);
        sub.assert_true(ok_date, "Parsed valid future IMF-fixdate");
        sub.assert_eq(delta_ms, 10000, "Calculated 10,000 ms delta");

        // If date is in the past: clamped to 0 ms
        let delta_past, ok_past = wing::parse_retry_after_ms(http_date, 1500000000000);
        sub.assert_true(ok_past, "Parsed past IMF-fixdate");
        sub.assert_eq(delta_past, 0, "Past date clamped to 0 ms (never negative)");

        // Invalid calendar date: Feb 31 rejected by round-trip check
        let bad_date = "Wed, 31 Feb 2024 12:00:00 GMT";
        let _, ok_bad = wing::parse_retry_after_ms(bad_date, 1700000000000);
        sub.assert_false(ok_bad, "Invalid calendar day 31 Feb rejected by round-trip validator");

        // Invalid month string
        let bad_month = "Wed, 21 Foo 2026 07:28:00 GMT";
        let _, ok_bm = wing::parse_retry_after_ms(bad_month, 1700000000000);
        sub.assert_false(ok_bm, "Invalid month 'Foo' rejected");
    };
}

fn test_circuit_breaker_and_adaptive_retry_budget(t: core::T&) {
    t.run("Host Circuit Breaker on Excessive Retry-After") { sub =>
        var breaker = wing::new_host_circuit_breaker(60000); // 60s max wait

        // Retry-After of 30s does not trip circuit breaker
        let tripped_small = wing::trip_circuit_breaker_if_exceeded(breaker, "api.overloaded.com", 30000, 0);
        sub.assert_false(tripped_small, "30s does not trip circuit breaker");
        sub.assert_false(wing::is_host_circuit_broken(breaker, "api.overloaded.com", 0), "Host not blocked");

        // Retry-After of 300s (> 60s) trips circuit breaker
        let tripped_large = wing::trip_circuit_breaker_if_exceeded(breaker, "api.overloaded.com", 300000, 1000000000);
        sub.assert_true(tripped_large, "300s trips circuit breaker");
        sub.assert_true(wing::is_host_circuit_broken(breaker, "api.overloaded.com", 2000000000), "Host blocked by circuit breaker");

        // Advance beyond unblock deadline (1s + 300s = 301s)
        sub.assert_false(wing::is_host_circuit_broken(breaker, "api.overloaded.com", 302000000000), "Host unblocked after cool-down");

        // Different host is not blocked
        sub.assert_false(wing::is_host_circuit_broken(breaker, "other.healthy.com", 2000000000), "Other host is not blocked");
    };

    t.run("Google SRE Adaptive Retry Budget") { sub =>
        // 20% max ratio, 2 retries/sec floor, 10s window (floor = 20 retries allowed)
        var budget = wing::new_adaptive_retry_budget(20, 2, 10);

        // Record 100 primary requests
        for i in 100 {
            wing::record_primary_request(budget, 1000000000);
        }

        // Allowed retries: max(100 * 20% = 20, 2 * 10 = 20) = 20 retries
        for i in 20 {
            let ok = wing::allow_retry_budget(budget, 1000000000);
            sub.assert_true(ok, "Retry within budget allowed");
        }

        // 21st retry attempt exceeds budget during flood
        let blocked = wing::allow_retry_budget(budget, 1000000000);
        sub.assert_false(blocked, "Retry exceeding 20% budget rejected to prevent retry storm");

        // After window advances (t = 12s, delta = 11s > 10s window), budget resets
        wing::record_primary_request(budget, 12000000000);
        sub.assert_eq(budget.retried_requests, 0, "Retried requests reset in new window");
        let ok_new = wing::allow_retry_budget(budget, 12000000000);
        sub.assert_true(ok_new, "Retry permitted after window resets");
    };
}

fn main() {
    var runner = core::new_runner("net/retry Two-Tier Resilience Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Tier 1 Stale Socket & QUIC Fallback", test_tier1_stale_socket_and_quic_fallback);
    core::run_case(runner, "2. Tier 2 Backoff & Jitter Strategies", test_tier2_exponential_backoff_and_jitter);
    core::run_case(runner, "3. RFC 9110 Retry-After Parser", test_rfc9110_retry_after_parser);
    core::run_case(runner, "4. Circuit Breaker & Adaptive Retry Budget", test_circuit_breaker_and_adaptive_retry_budget);
    let ok = core::finish(runner);
    assert(ok);
}
