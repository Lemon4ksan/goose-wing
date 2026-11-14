// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap millisecond token bucket rate limiter with saturating refill math.
namespace core;

import std;
import core.math;

struct TokenBucket {
    tokens:         u64 = 1000,
    burst:          u64 = 1000,
    rate_per_sec:   u64 = 33,
    last_refill_ms: u64 = 0,
}

// Refills `tb` up to `tb.burst` based on elapsed milliseconds since `last_refill_ms`.
fn token_bucket_refill(tb: TokenBucket&, now_ms: u64) {
    guard now_ms > tb.last_refill_ms else { return; }
    let elapsed_ms = sub_sat_u64(now_ms, tb.last_refill_ms);
    let prod_lo, prod_hi = mul_wide_u64(elapsed_ms, tb.rate_per_sec);
    if prod_hi != 0 {
        tb.tokens = tb.burst;
        tb.last_refill_ms = now_ms;
        return;
    }
    // Exact division by 1000 for all u64: floor(prod_lo / 1000) == floor((prod_lo >> 3) / 125).
    // Magic multiplier ceil(2^67 / 125) = 0x10624DD2F1A9FBE8 is exact for all 61-bit quotients.
    let _, div_hi = mul_wide_u64(prod_lo >> 3, 0x10624DD2F1A9FBE8);
    let added = div_hi >> 3;
    if added > 0 {
        tb.tokens = min(add_sat_u64(tb.tokens, added), tb.burst);
        tb.last_refill_ms = now_ms;
    }
}

// Consumes `count` tokens from `tb` after refilling at `now_ms`. Returns false if insufficient.
//
// Example:
//   tb = TokenBucket { tokens: 5, burst: 5, rate_per_sec: 1, .. }, consume(tb, 0, 1) -> true (4 left)
fn token_bucket_consume(tb: TokenBucket&, now_ms: u64, count: u64 = 1) -> bool {
    token_bucket_refill(tb, now_ms);
    guard tb.tokens >= count else { return false; }
    tb.tokens = sub_sat_u64(tb.tokens, count);
    return true;
}
