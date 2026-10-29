// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for proxy/gcra: Zero-allocation GCRA rate limiting,
// burst tolerance (tau), emission interval (T), TAT tracking,
// clock drift protection, and bounded GatewayRateLimiter.
import std;
import core from "..";
import wing from "..";

fn test_gcra_core_algorithm(t: core::T&) {
    t.run("GCRA Quota and Single-Cell Conformance") { sub =>
        // 10 rps -> T = 100ms (100,000,000 ns), burst = 2 -> tau = 200ms (200,000,000 ns)
        let cfg = wing::new_gcra_config(10, 2);
        sub.assert_eq(cfg.emission_interval_ns, 100000000, "Emission interval T is 100ms");
        sub.assert_eq(cfg.tau_ns, 200000000, "Burst tolerance tau is 200ms");
        sub.assert_eq(cfg.max_burst, 2, "Max burst capacity is 2");

        var cell = wing::GcraTatCell { tat_ns: 0 };
        let now_ns: u64 = 1000000000; // 1.0s

        // Cell 1: Initial arrival
        let dec1 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec1.allowed, "First cell is allowed");
        sub.assert_eq(dec1.remaining_burst, 2, "Burst capacity remains 2 on cold start");
        sub.assert_eq(cell.tat_ns, 1100000000, "TAT advanced to now + T");

        // Cell 2: Immediate burst arrival at same timestamp
        let dec2 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec2.allowed, "Burst cell 2 is allowed");
        sub.assert_eq(dec2.remaining_burst, 1, "Remaining burst decremented to 1");
        sub.assert_eq(cell.tat_ns, 1200000000, "TAT advanced to 1.2s");

        // Cell 3: Second burst arrival at same timestamp
        let dec3 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec3.allowed, "Burst cell 3 is allowed");
        sub.assert_eq(dec3.remaining_burst, 0, "Remaining burst exhausted (0)");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT advanced to 1.3s");

        // Cell 4: Over-burst arrival at same timestamp -> REJECT
        let dec4 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(!dec4.allowed, "Cell 4 rejected due to burst exhaustion");
        sub.assert_true(dec4.retry_after_ns > 0, "Retry-after is non-zero");
        sub.assert_eq(dec4.retry_after_ns, 100000000, "Retry-after is 100ms");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT unchanged on rejection");

        // Advance clock by 100ms -> Cell 5 admitted
        let now_later = now_ns + 100000000;
        let dec5 = wing::gcra_check(cfg, cell, 1, now_later);
        sub.assert_true(dec5.allowed, "Cell 5 admitted after 100ms delay");
        sub.assert_eq(dec5.remaining_burst, 0, "Remaining burst is 0");
    };

    t.run("GCRA Peek, Penalize, and Reset Semantics") { sub =>
        let cfg = wing::new_gcra_config(5, 1); // 200ms per cell
        var cell = wing::GcraTatCell { tat_ns: 0 };
        let now_ns: u64 = 5000000000;

        // Peek should not alter TAT
        let peek_dec = wing::gcra_peek(cfg, cell, 1, now_ns);
        sub.assert_true(peek_dec.allowed, "Peek shows cell is allowed");
        sub.assert_eq(cell.tat_ns, 0, "Cell TAT remains untouched after peek");

        // Check mutates TAT
        let check_dec = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(check_dec.allowed, "Check allows request");
        sub.assert_eq(cell.tat_ns, 5200000000, "Check advances TAT by 200ms");

        // Penalize pushes TAT further into future
        wing::gcra_penalize(cfg, cell, 1000000000, now_ns); // +1s penalty
        sub.assert_eq(cell.tat_ns, 6200000000, "Penalize pushed TAT by 1.0s");

        // Subsequent check at 5.1s should fail due to penalty
        let pen_check = wing::gcra_check(cfg, cell, 1, 5100000000);
        sub.assert_true(!pen_check.allowed, "Request rejected under penalty delay");

        // Reset clears TAT
        wing::gcra_reset(cell);
        sub.assert_eq(cell.tat_ns, 0, "Reset restores cell TAT to 0");
    };

    t.run("BUG-04 Defense: NTP Backward Jump Clamping Updates cell.tat_ns") { sub =>
        let cfg = wing::new_gcra_config(10, 2); // limit_window = 300ms
        // Set TAT to distant future (50s in future due to corrupted clock)
        var cell = wing::GcraTatCell { tat_ns: 50000000000 };
        let now_ns: u64 = 1000000000; // clock jumped back to 1.0s

        // BUG-04 fix verifies cell.tat_ns is clamped down even when request is rejected
        let dec = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(!dec.allowed, "Rejected during clamped limit window");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT clamped to now + limit_window (1.3s)");

        // After limit window passes (at 1.4s), client recovers without permanent lockout
        let dec_rec = wing::gcra_check(cfg, cell, 1, 1400000000);
        sub.assert_true(dec_rec.allowed, "Client successfully recovers after clamped window");
    };
}

fn test_gateway_rate_limiter(t: core::T&) {
    t.run("Multi-Client Isolation and Limiting") { sub =>
        var limiter = wing::new_gateway_rate_limiter(10, 2);
        let client_a: u8[..16] = "192.168.1.100";
        let client_b: u8[..16] = "10.0.0.1";
        let now_ns: u64 = 1000000000;

        // Client A consumes all 3 burst tokens
        let da1 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        let da2 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        let da3 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        sub.assert_true(da1.allowed && da2.allowed && da3.allowed, "Client A burst allowed");

        // 4th request from Client A rejected
        let da4 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        sub.assert_true(!da4.allowed, "Client A over-burst rejected");

        // Client B is isolated and has full capacity
        let db1 = wing::check_gateway_rate_limit(limiter, client_b[..], 1, now_ns);
        sub.assert_true(db1.allowed, "Client B allowed independently of Client A");

        sub.assert_eq(limiter.total_allowed, 4, "Global allowed count is 4");
        sub.assert_eq(limiter.total_rejected, 1, "Global rejected count is 1");
    };

    t.run("Idle Client Eviction and Table Reset") { sub =>
        var limiter = wing::new_gateway_rate_limiter(5, 1);
        let client_old: u8[..16] = "172.16.0.5";
        let now_ns: u64 = 1000000000;

        wing::check_gateway_rate_limit(limiter, client_old[..], 1, now_ns);
        sub.assert_eq(limiter.entries.len, 1, "1 client slot registered");

        // Evict with 2s max_idle at now + 5s (idle time = 5s > 2s)
        let now_later = now_ns + 5000000000;
        let evicted = wing::evict_idle_gateway_clients(limiter, 2000000000, now_later);
        sub.assert_eq(evicted, 1, "1 idle client entry evicted");

        // Reset clears all counters
        wing::reset_gateway_rate_limiter(limiter);
        sub.assert_eq(limiter.total_allowed, 0, "Allowed reset to 0");
        sub.assert_eq(limiter.total_rejected, 0, "Rejected reset to 0");
    };
}

fn main() {
    var runner = core::new_runner("proxy/gcra Rate Limiting & Gateway Sentinel Shield", core::Verbosity.Verbose);
    core::run_case(runner, "1. GCRA Core Algorithm & Conformance", test_gcra_core_algorithm);
    core::run_case(runner, "2. Gateway Multi-Client Rate Limiter", test_gateway_rate_limiter);
    let ok = core::finish(runner);
    assert(ok);
}
