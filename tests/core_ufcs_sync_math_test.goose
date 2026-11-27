// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite: core/ufcs, core/sync (singleflight, spsc_ring), and core/math.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_ufcs_bridges(t: lit::T&) {
    t.run("UFCS string trim and push bounds") { sub =>
        let s: const u8[:] = " \t\nhello\r ";
        sub.assert_bytes_eq(s.trim_ascii_space(), "hello");
        sub.assert_bytes_eq("ab///".trim_end_bytes("/"), "ab");

        var dyn_buf: u8[>..] = [];
        sub.assert_true(dyn_buf.try_push(0 as i64));
        sub.assert_true(dyn_buf.try_push(255 as i64));
        sub.assert_false(dyn_buf.try_push(-1 as i64));
        sub.assert_false(dyn_buf.try_push(256 as i64));
        sub.assert_eq(dyn_buf.len, 2);
    };
}

fn test_sync_primitives(t: lit::T&) {
    t.run("SpscRing invalid cap, uninitialized/closed guards & idempotent close") { sub =>
        let _, ok0 = core::spsc_init(0);
        let _, ok_big = core::spsc_init(0x40000001);
        sub.assert_false(ok0 || ok_big);

        var uninit = core::SpscRing { .. };
        var dummy: u64 = 0;
        sub.assert_false(core::spsc_push(uninit, 1));
        sub.assert_false(core::spsc_pop(uninit, dummy));
        sub.assert_eq(core::spsc_count(uninit), 0 as u32);
        sub.assert_eq(core::spsc_available(uninit), 0 as u32);
        core::spsc_close(uninit);

        var ring, ok_r = core::spsc_init(4);
        sub.assert_true(ok_r);
        sub.assert_gt(core::spsc_available(ring), 0 as u32);
        sub.assert_true(core::spsc_push(ring, 42));
        sub.assert_eq(core::spsc_count(ring), 1 as u32);
        core::spsc_close(ring);
        core::spsc_close(ring);
    };
}

fn test_math_edge_cases(t: lit::T&) {
    t.run("FlatIndex invalid cap, full table, tombstone/backward-shift, gen wrap") { sub =>
        var bad3: core::FlatIndexBucket[3] = [core::FlatIndexBucket { .. }; 3];
        sub.assert_false(core::flat_index_get(bad3[..], 1).found);
        sub.assert_false(core::flat_index_get_or_put(bad3[..], 1).found);
        sub.assert_false(core::flat_index_remove(bad3[..], 1).found);

        var b4: core::FlatIndexBucket[4] = [core::FlatIndexBucket { .. }; 4];
        sub.assert_false(core::flat_index_remove(b4[..], 999).found);
        let _, ok_oob = core::flat_index_commit_put(b4[..], -1, 1, 0);
        sub.assert_false(ok_oob);
        for k: u64 in 4 {
            let r = core::flat_index_get_or_put(b4[..], k + 10);
            let _, ok_c = core::flat_index_commit_put(b4[..], r.bucket_idx, k + 10, k as u16);
            sub.assert_true(ok_c);
        }
        // Table is full: lookup missing key loops all 4 buckets and returns not found
        sub.assert_false(core::flat_index_get(b4[..], 999).found);
        sub.assert_false(core::flat_index_remove(b4[..], 999).found);
        let r_occ = core::flat_index_get_or_put(b4[..], 10);
        let _, ok_occ = core::flat_index_commit_put(b4[..], r_occ.bucket_idx, 99, 0);
        sub.assert_false(ok_occ);

        // Generation wrap-around (0xFFFF -> 1 instead of 0)
        sub.assert_true(core::flat_index_remove(b4[..], 10).found);
        let r_free = core::flat_index_get_or_put(b4[..], 10);
        b4[r_free.bucket_idx].gen = 0xFFFF;
        let new_g, ok_w = core::flat_index_commit_put(b4[..], r_free.bucket_idx, 10, 0);
        sub.assert_true(ok_w && new_g == 1);
    };

    t.run("Arithmetic, random, hash, bits edge paths") { sub =>
        sub.assert_eq(core::mul_sat_i64(core::I64_MAX, -2), core::I64_MIN);
        sub.assert_eq(core::mul_sat_i64(core::I64_MAX, 2), core::I64_MAX);
        sub.assert_eq(core::rem_euclid_i64(core::I64_MIN, -1), 0);
        sub.assert_eq(core::rem_euclid_i64(5, 0), 0);
        sub.assert_eq(core::div_euclid_i64(core::I64_MIN, -1), core::I64_MAX);
        sub.assert_eq(core::div_euclid_i64(5, 0), 0);

        var rng0 = core::new_wyrand(0);
        sub.assert_eq(core::fast_range_unbiased_u32(rng0, 1), 0 as u32);
        for _ in 32 {
            let v = core::fast_range_unbiased_u32(rng0, 0x90000001 as u32);
            sub.assert_lt(v, 0x90000001 as u32);
        }

        let data40 = "0123456789abcdefghijklmnopqrstuvwxyzABCD";
        sub.assert_eq(core::wy_read_small(data40, 0), 0 as u64);

        sub.assert_eq(core::next_pow2_u64(0), 1 as u64);
        sub.assert_eq(core::next_pow2_u64(0x8000000000000001), 0x8000000000000000);
    };
}

fn main() {
    let runner = lit::new_runner("Core UFCS, Sync, and Math Verification Suite");
    lit::run_case(runner, "1. UFCS Bridges", test_ufcs_bridges);
    lit::run_case(runner, "2. SPSC Ring Primitives", test_sync_primitives);
    lit::run_case(runner, "3. Math Edge Cases", test_math_edge_cases);
    assert(lit::finish(runner));
}
