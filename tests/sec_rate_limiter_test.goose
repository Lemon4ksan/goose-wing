// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for GCRA rate limiter, burst tolerance, and sharded storage.
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Mathematical GCRA TAT Scheduling & Burst Tolerance
// ----------------------------------------------------------------------------
fn test_gcra_tat_and_burst(t: core::T&) {
    t.run("Single-Cell Ingress & Burst Tolerance Exhaustion") { sub =>
        // Limit: 10 req/s (T = 100 ms), Burst: 2 (tau = 200 ms)
        let quota = wing::new_gcra_quota(10, core::secs(1), 2);
        sub.assert_eq(quota.emission_interval_ns, 100000000, "T = 100ms");
        sub.assert_eq(quota.delay_tolerance_ns, 200000000, "tau = 200ms");

        var cell = wing::GcraCell { tat_ns: 0 };
        let t0: u64 = 1000000000; // t = 1.0s

        // Request 1 at t0: allowed, TAT becomes t0 + 100ms
        let d1 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(wing::is_allowed(d1), "req 1 allowed");
        sub.assert_eq(cell.tat_ns, t0 + 100000000, "TAT advanced by T");

        // Request 2 at t0: allowed, TAT becomes t0 + 200ms
        let d2 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(wing::is_allowed(d2), "req 2 allowed");
        sub.assert_eq(cell.tat_ns, t0 + 200000000, "TAT advanced to t0 + 200ms");

        // Request 3 at t0: allowed (burst limit = tau + T = 300ms)
        let d3 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(wing::is_allowed(d3), "req 3 allowed at burst threshold");
        sub.assert_eq(cell.tat_ns, t0 + 300000000, "TAT at max window limit");

        // Request 4 at t0: REJECTED! TAT would exceed limit window
        let d4 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_false(wing::is_allowed(d4), "req 4 rejected (burst exceeded)");
        let ok_rej = match d4 {
            Rejected r => r.retry_after_ns > 0,
            _ => false,
        };
        sub.assert_true(ok_rej, "retry_after_ns > 0 on rejection");
        sub.assert_eq(cell.tat_ns, t0 + 300000000, "TAT unchanged on rejection");

        // Advance clock by 100ms: quota for 1 cell recovers!
        let t1 = t0 + 100000000;
        let d5 = wing::gcra_check_n(quota, cell, 1, t1);
        sub.assert_true(wing::is_allowed(d5), "req 5 allowed after 100ms clock advance");
        sub.assert_eq(cell.tat_ns, t0 + 400000000, "TAT advanced to t0 + 400ms");
    };
}

// ----------------------------------------------------------------------------
// 2. Anti-Starvation Multi-Cell Priority Reservation (governor #16 Fix)
// ----------------------------------------------------------------------------
fn test_anti_starvation_reservation(t: core::T&) {
    t.run("Priority Reservation Preempts Small Subsequent Requests") { sub =>
        // Limit: 1 req/sec (T = 1s), Burst: 0 (tau = 0)
        let quota = wing::new_gcra_quota(1, core::secs(1), 0);
        var cell = wing::GcraCell { tat_ns: 0 };
        let now: u64 = 1000000000;

        // Ingress 1: cost 1 cell at now: allowed, TAT = now + 1s
        let d1 = wing::gcra_check_n(quota, cell, 1, now);
        sub.assert_true(wing::is_allowed(d1), "initial cell allowed");
        sub.assert_eq(cell.tat_ns, now + 1000000000, "TAT = now + 1s");

        // Heavy request requesting n=3 cells arrives immediately at now
        // Standard check would reject it. With gcra_reserve_n and max_wait = 5s:
        let d_res = wing::gcra_reserve_n(quota, cell, 3, now, 5000000000);
        let ok_res = match d_res {
            Reserved r => r.wait_ns == 3000000000 && r.new_tat_ns == now + 4000000000,
            _ => false,
        };
        sub.assert_true(ok_res, "heavy request successfully reserved slot ahead of time");
        sub.assert_eq(cell.tat_ns, now + 4000000000, "TAT advanced by 3 cells to 4s");

        // Subsequent lighter request (n=1) arriving at now + 500ms tries to steal:
        let d_steal = wing::gcra_check_n(quota, cell, 1, now + 500000000);
        sub.assert_false(wing::is_allowed(d_steal), "lighter request cannot steal reserved heavy slot");

        // Heavy request completes reservation wait time and executes cleanly
        let now_after_wait = now + 3000000000;
        let d_after = wing::gcra_check_n(quota, cell, 1, now_after_wait + 1000000000);
        sub.assert_true(wing::is_allowed(d_after), "pipeline resumes after reservation window");
    };
}

// ----------------------------------------------------------------------------
// 3. 256-Micro-Shard Table & Per-Key Isolation
// ----------------------------------------------------------------------------
fn test_sharded_gcra_limiter(t: core::T&) {
    t.run("Independent Client Quotas Across Shards") { sub =>
        // Limit: 2 req/s, Burst: 1 (allows 2 immediate requests at t0, 3rd rejected)
        let quota = wing::new_gcra_quota(2, core::secs(1), 1);
        var limiter = wing::new_sharded_limiter(quota);
        let now: u64 = 2000000000;

        let ip_a = "192.168.1.10";
        let ip_b = "10.0.0.5";

        // IP A exhausts its quota (2 requests)
        let d_a1 = wing::check_rate_limit(limiter, ip_a, 1, now);
        let d_a2 = wing::check_rate_limit(limiter, ip_a, 1, now);
        let d_a3 = wing::check_rate_limit(limiter, ip_a, 1, now);

        sub.assert_true(wing::is_allowed(d_a1), "IP A req 1 allowed");
        sub.assert_true(wing::is_allowed(d_a2), "IP A req 2 allowed");
        sub.assert_false(wing::is_allowed(d_a3), "IP A req 3 rejected (exhausted)");

        // IP B must NOT be affected by IP A's exhaustion!
        let d_b1 = wing::check_rate_limit(limiter, ip_b, 1, now);
        let d_b2 = wing::check_rate_limit(limiter, ip_b, 1, now);
        sub.assert_true(wing::is_allowed(d_b1), "IP B req 1 allowed independently");
        sub.assert_true(wing::is_allowed(d_b2), "IP B req 2 allowed independently");
    };

    t.run("FNV-1a 256-Shard Uniform Key Distribution") { sub =>
        var seen_shards: bool[256] = [false; 256];
        var distinct_shards = 0;

        // Hash 100 distinct mock IP keys
        for i in 100 {
            var ip_buf: u8[..32] = [];
            ip_buf.append("192.168.");
            format(ip_buf, i);
            ip_buf.append(".1");

            let shard = (core::fnv1a_64(ip_buf[..]) & 0xFF) as i64;
            if !seen_shards[shard] {
                seen_shards[shard] = true;
                distinct_shards += 1;
            }
        }

        // 100 random keys should hit at least 25 distinct shards
        sub.assert_true(distinct_shards > 25, "FNV-1a uniformly distributes keys across 256 shards");
    };
}

// ----------------------------------------------------------------------------
// 4. Extreme DDoS Probabilistic Sampling (5%)
// ----------------------------------------------------------------------------
fn test_probabilistic_ddos_mitigation(t: core::T&) {
    t.run("5% Statistical Sampling Under Extreme Load") { sub =>
        let quota = wing::new_gcra_quota(1000, core::secs(1), 100);
        var pgcra = wing::new_probabilistic_gcra(quota, 20); // 1-in-20 = 5%

        var sampled_count = 0;
        var non_sampled_count = 0;
        let now: u64 = 1000000000;

        // Run 500 requests
        for i in 500 {
            let tat_before = pgcra.cell.tat_ns;
            let dec = wing::check_rate_limit(pgcra, 1, now);
            if pgcra.cell.tat_ns != tat_before {
                sampled_count += 1;
            } else {
                non_sampled_count += 1;
            }
        }

        // Sampling rate is 1/20 = 5% (+/- random variance)
        sub.assert_true(sampled_count > 0, "sampled requests touched TAT cell");
        sub.assert_true(non_sampled_count > sampled_count, "majority of requests passed without lock/write");
    };
}

// ----------------------------------------------------------------------------
// 5. IETF RateLimit-* Header Synthesis
// ----------------------------------------------------------------------------
fn test_ietf_rate_limit_headers(t: core::T&) {
    t.run("IETF Headers on Allowed Request") { sub =>
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        let dec: wing::RateLimitDecision = wing::RateLimitDecision.Allowed {
            remaining_burst: 8,
            new_tat_ns: 1200000000,
            reset_after_ns: 200000000,
        };

        var res = wing::new_response();
        wing::apply_rate_limit_headers(res, quota, dec);

        sub.assert_true(res.has_header("RateLimit-Limit"), "RateLimit-Limit emitted");
        sub.assert_eq(res.header("RateLimit-Limit"), "100", "RateLimit-Limit = 100");
        sub.assert_true(res.has_header("RateLimit-Remaining"), "RateLimit-Remaining emitted");
        sub.assert_eq(res.header("RateLimit-Remaining"), "8", "RateLimit-Remaining = 8");
        sub.assert_true(res.has_header("RateLimit-Reset"), "RateLimit-Reset emitted");
        sub.assert_eq(res.header("RateLimit-Reset"), "1", "RateLimit-Reset ceiling ceil(0.2s) = 1s");
    };

    t.run("IETF Headers & 429 Status on Rejected Request") { sub =>
        let quota = wing::new_gcra_quota(50, core::secs(1), 0);
        let dec: wing::RateLimitDecision = wing::RateLimitDecision.Rejected {
            retry_after_ns: 2500000000, // 2.5 seconds
            current_tat_ns: 3500000000,
        };

        var res = wing::new_response();
        wing::apply_rate_limit_headers(res, quota, dec);

        sub.assert_eq(res.status_code, 429, "status set to 429 Too Many Requests");

        sub.assert_true(res.has_header("Retry-After"), "Retry-After emitted");
        sub.assert_eq(res.header("Retry-After"), "3", "Retry-After ceil(2.5s) = 3s");
        sub.assert_true(res.has_header("RateLimit-Remaining"), "RateLimit-Remaining is 0");
        sub.assert_eq(res.header("RateLimit-Remaining"), "0", "RateLimit-Remaining = 0 on rejection");
    };
}

// ----------------------------------------------------------------------------
// 6. GCRA Arithmetic, Overflow & Zero Emission Invariants
// ----------------------------------------------------------------------------
fn test_gcra_arithmetic_and_overflow(t: core::T&) {
    t.run("Zero Emission Interval Handling & Division by Zero") { sub =>
        // Limit 2,000,000 req per 1 ms (p_ns = 1,000,000, l = 2,000,000 -> p_ns / l = 0)
        let quota = wing::new_gcra_quota(2000000, core::Duration { nanos: 1000000 }, 10);
        sub.assert_true(quota.emission_interval_ns >= 1, "emission interval floored to >= 1ns to prevent division by zero");

        var cell = wing::GcraCell { tat_ns: 0 };
        let dec = wing::gcra_check_n(quota, cell, 1, 1000000);
        sub.assert_true(wing::is_allowed(dec), "admission succeeds without divide-by-zero panic");
    };

    t.run("Accurate Burst Remaining Calculation in Reservation") { sub =>
        // Limit: 1 req/s (T = 1s), Burst: 5 (tau = 5s)
        let quota = wing::new_gcra_quota(1, core::secs(1), 5);
        var cell = wing::GcraCell { tat_ns: 0 };
        let now: u64 = 1000000000;

        // Immediate reservation consuming 3 tokens
        let dec = wing::gcra_reserve_n(quota, cell, 3, now, 10000000000);
        sub.assert_true(wing::is_allowed(dec), "reservation allowed immediately");
        let remaining = match dec {
            Allowed a => a.remaining_burst,
            _ => 999,
        };
        // After consuming 3 tokens from initial burst capacity of 5, remaining burst must decrement
        sub.assert_true(remaining < 5, "remaining_burst must decrement, not report static quota.burst");
        sub.assert_eq(remaining, 3, "remaining_burst decrements to 3 after cost 3");
    };

    t.run("U64 Nanosecond Overflow In Burst Calculation") { sub =>
        let quota = wing::new_gcra_quota(1, core::secs(1), 5); // T = 1s, tau = 5s
        let now: u64 = 18446744073709551615 - 30000000000; // 30s before u64::MAX
        var cell = wing::GcraCell { tat_ns: now };

        // Consuming 3 tokens near u64 limit:
        let dec = wing::gcra_check_n(quota, cell, 3, now);
        sub.assert_true(wing::is_allowed(dec), "admission succeeds near u64 boundaries");
        let remaining = match dec {
            Allowed a => a.remaining_burst,
            _ => 999,
        };
        // After cost 3 from burst 5, remaining burst must decrement to 3
        sub.assert_eq(remaining, 3, "burst correctly decrements without u64 wrap-around");
    };

    t.run("Clock Drift & Backward NTP Jump Recovery") { sub =>
        let quota = wing::new_gcra_quota(10, core::secs(1), 2);
        var cell = wing::GcraCell { tat_ns: 60000000000 }; // TAT at 60s
        let now_backward: u64 = 10000000000; // Clock jumped back to 10s (50s backward jump)
        let dec = wing::gcra_check_n(quota, cell, 1, now_backward);
        let retry_after = match dec {
            Rejected r => r.retry_after_ns,
            Allowed _ => 0,
            _ => 999999999999,
        };
        sub.assert_true(retry_after <= 200000000, "retry_after bounded to emission interval under 50s clock jump");
    };

    t.run("Clock Drift & Backward NTP Jump Recovery in Reservation") { sub =>
        let quota = wing::new_gcra_quota(1, core::secs(1), 0);
        var cell = wing::GcraCell { tat_ns: 70000000000 }; // TAT at 70s
        let now_backward: u64 = 10000000000; // Clock jumped back to 10s
        let dec = wing::gcra_reserve_n(quota, cell, 1, now_backward, 5000000000);
        let wait_ns = match dec {
            Reserved r => r.wait_ns,
            Allowed _ => 0,
            Rejected r => r.retry_after_ns,
        };
        sub.assert_true(wait_ns <= 1000000000, "reservation wait_ns bounded under 60s clock jump");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("Rate Limiter Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Mathematical GCRA TAT Scheduling & Burst Tolerance", test_gcra_tat_and_burst);
    core::run_case(runner, "2. Anti-Starvation Multi-Cell Priority Reservation", test_anti_starvation_reservation);
    core::run_case(runner, "3. 256-Micro-Shard Table & Per-Key Isolation", test_sharded_gcra_limiter);
    core::run_case(runner, "4. Extreme DDoS Probabilistic Sampling (5%)", test_probabilistic_ddos_mitigation);
    core::run_case(runner, "5. IETF RateLimit-* Header Synthesis", test_ietf_rate_limit_headers);
    core::run_case(runner, "6. GCRA Arithmetic, Overflow & Zero Emission Invariants", test_gcra_arithmetic_and_overflow);

    let ok = core::finish(runner);
    assert(ok);
}
