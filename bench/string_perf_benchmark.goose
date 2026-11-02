// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Comparative Head-to-Head Benchmark for String and Byte Search Algorithms:
// 1. Token Equality: Baseline memcmp slice equality vs equal_short (unaligned XOR).
// 2. Byte Set Trimming: Baseline per-byte contains_byte loop vs 256-byte stack table find_not_byteset.
// 3. ASCII Lowercase: Baseline scalar loop vs 64-bit SWAR parallel transform.
// 4. Substring Search: Baseline std::find vs Vectorized SIMD Packed-Pair search.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Baseline Implementations (Current goose-wing code) ---

fn baseline_starts_with(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    return s[..prefix.len] == prefix;
}

fn baseline_trim_bytes(val: const u8[:], cutset: const u8[:]) -> const u8[:] {
    var start: i64 = 0;
    while start < val.len && core::contains_byte(cutset, val[start]) {
        start++;
    }
    var end_pos: i64 = val.len;
    while end_pos > start && core::contains_byte(cutset, val[end_pos - 1]) {
        end_pos--;
    }
    return val[start..end_pos];
}

fn baseline_to_lower(buf: u8[:]) {
    for i in buf.len {
        let b = buf[i];
        if b >= 'A' && b <= 'Z' {
            buf[i] = b + 32;
        }
    }
}

// --- Benchmark Cases ---

fn test_token_equality_benchmark(t: lit::T&) {
    t.run("Token Equality: memcmp vs equal_short") { sub =>
        let iters: i64 = 500000;
        let tokens: const u8[:][8] = [
            "Content-Type: application/json",
            "Authorization: Bearer token123",
            "User-Agent: goose-wing/2.0",
            "Host: api.example.internal",
            "Accept: text/html,application/xhtml+xml",
            "Connection: keep-alive",
            "Transfer-Encoding: chunked",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        ];
        let prefix: const u8[:] = "Content-Type: ";

        // 1. Baseline: memcmp
        let w_base = core::stopwatch();
        var matches_base: i64 = 0;
        for _ in iters {
            for tok in tokens {
                core::prefetch_t0(tok);
                if baseline_starts_with(tok, prefix) {
                    matches_base++;
                }
            }
        }
        let dt_base = core::elapsed(w_base);
        sub.assert_eq(matches_base, iters);

        // 2. Candidate: equal_short
        let w_opt = core::stopwatch();
        var matches_opt: i64 = 0;
        for _ in iters {
            for tok in tokens {
                core::prefetch_t0(tok);
                if tok.len >= prefix.len && core::equal_short(tok[..prefix.len], prefix) {
                    matches_opt++;
                }
            }
        }
        let dt_opt = core::elapsed(w_opt);
        sub.assert_eq(matches_opt, iters);

        let total_lookups = iters * 8;
        print("\n  [BENCHMARK 1] Multi-Header Token Equality (", total_lookups, " lookups):");
        print("  - Baseline (memcmp):      ", dt_base.as_micros(), " us");
        print("  - Optimized (equal_short): ", dt_opt.as_micros(), " us");
        if dt_opt.as_micros() > 0 {
            let speedup_x10 = (dt_base.as_micros() * 10) / dt_opt.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn test_byteset_trim_benchmark(t: lit::T&) {
    t.run("ByteSet Trim: contains_byte loop vs 256-byte stack table") { sub =>
        let iters:  i64         = 200000;
        let sample: const u8[:] = " \t\r\n  \t\r\nHello World, Zero-Allocation Networking!\r\n \t\r\n ";
        let cutset: const u8[:] = " \t\r\n";

        // 1. Baseline: contains_byte loop
        let w_base = core::stopwatch();
        var dummy_len_base: i64 = 0;
        for _ in iters {
            let res = baseline_trim_bytes(sample, cutset);
            dummy_len_base += res.len;
        }
        let dt_base = core::elapsed(w_base);

        // 2. Candidate: find_byteset / find_not_byteset
        let w_opt = core::stopwatch();
        var dummy_len_opt: i64 = 0;
        for _ in iters {
            let res = core::trim_bytes(sample, cutset);
            dummy_len_opt += res.len;
        }
        let dt_opt = core::elapsed(w_opt);
        sub.assert_eq(dummy_len_base, dummy_len_opt);

        print("\n  [BENCHMARK 2] Cutset Trim (", iters, " iterations):");
        print("  - Baseline (contains_byte loop): ", dt_base.as_micros(), " us");
        print("  - Optimized (byteset table):    ", dt_opt.as_micros(), " us");
        if dt_opt.as_micros() > 0 {
            let speedup_x10 = (dt_base.as_micros() * 10) / dt_opt.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn test_ascii_lower_benchmark(t: lit::T&) {
    t.run("ASCII Lowercase: scalar loop vs 64-bit SWAR") { sub =>
        let iters: i64 = 200000;
        var text_base: u8[64] = [0; 64];
        var text_opt:  u8[64] = [0; 64];
        let original: const u8[:] = "HTTP/1.1 200 OK - CONTENT-TYPE: APPLICATION/JSON; CHARSET=UTF-8!";
        for i in original.len {
            text_base[i] = original[i];
            text_opt[i] = original[i];
        }

        // 1. Baseline: scalar loop
        let w_base = core::stopwatch();
        for _ in iters {
            baseline_to_lower(text_base[..original.len]);
        }
        let dt_base = core::elapsed(w_base);

        // 2. Candidate: make_ascii_lowercase (SWAR)
        let w_opt = core::stopwatch();
        for _ in iters {
            core::make_ascii_lowercase(text_opt[..original.len]);
        }
        let dt_opt = core::elapsed(w_opt);
        sub.assert_eq(text_base[..original.len], text_opt[..original.len]);

        print("\n  [BENCHMARK 3] ASCII Lowercase (", iters, " iterations, 64-byte payload):");
        print("  - Baseline (scalar loop): ", dt_base.as_micros(), " us");
        print("  - Optimized (64-bit SWAR):", dt_opt.as_micros(), " us");
        if dt_opt.as_micros() > 0 {
            let speedup_x10 = (dt_base.as_micros() * 10) / dt_opt.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn test_substring_search_benchmark(t: lit::T&) {
    t.run("Substring Search: std::find vs SIMD Packed-Pair / Two-Way") { sub =>
        let iters:       i64         = 200000;
        let haystack:    const u8[:] = "GET /v1/projects/goose-wing/branches/perf-fast-string-search/commits HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: goose-wing/1.0\r\nAccept: application/json\r\nAuthorization: Bearer secret_token_xyz\r\n\r\n";
        let needle_hit:  const u8[:] = "Authorization: Bearer";
        let needle_miss: const u8[:] = "X-Non-Existent-Header: True";

        // 1. Baseline: std::find (Hit + Miss)
        let w_base = core::stopwatch();
        var hits_base: i64 = 0;
        for _ in iters {
            if find(haystack, needle_hit) >= 0 { hits_base++; }
            if find(haystack, needle_miss) >= 0 { hits_base++; }
        }
        let dt_base = core::elapsed(w_base);
        sub.assert_eq(hits_base, iters);

        // 2. Candidate: core::find (Hit + Miss)
        let w_opt = core::stopwatch();
        var hits_opt: i64 = 0;
        for _ in iters {
            if core::find(haystack, needle_hit) >= 0 { hits_opt++; }
            if core::find(haystack, needle_miss) >= 0 { hits_opt++; }
        }
        let dt_opt = core::elapsed(w_opt);
        sub.assert_eq(hits_opt, iters);

        let total_searches = iters * 2;
        print("\n  [BENCHMARK 4] Substring Search (", total_searches, " searches across hit & miss):");
        print("  - Baseline (std::find):         ", dt_base.as_micros(), " us");
        print("  - Optimized (SIMD Packed-Pair): ", dt_opt.as_micros(), " us");
        if dt_opt.as_micros() > 0 {
            let speedup_x10 = (dt_base.as_micros() * 10) / dt_opt.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn main() {
    let runner = lit::new_runner("Goose-Wing String Optimization Benchmark Suite");

    lit::run_case(runner, "1. Token Equality: memcmp vs equal_short", test_token_equality_benchmark);
    lit::run_case(runner, "2. ByteSet Trim: contains_byte vs stack table", test_byteset_trim_benchmark);
    lit::run_case(runner, "3. ASCII Lowercase: scalar vs 64-bit SWAR", test_ascii_lower_benchmark);
    lit::run_case(runner, "4. Substring Search: std::find vs SIMD Packed-Pair", test_substring_search_benchmark);

    let ok = lit::finish(runner);
    assert(ok);
}
