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
    t.run("UFCS string trim, token iteration, push bounds, and bitmask flags") { sub =>
        let s: const u8[:] = " \t\nhello\r ";
        sub.assert_bytes_eq(s.trim_ascii_space_start(), "hello\r ");
        sub.assert_bytes_eq(s.trim_ascii_space_end(), " \t\nhello");
        sub.assert_bytes_eq("ab///".trim_end_bytes("/"), "ab");

        var upper: u8[..16] = [];
        "aBc123".to_upper_ascii(upper);
        sub.assert_bytes_eq(upper[..], "ABC123");

        var count:   i64 = 0;
        var sum_len: i64 = 0;
        "alpha,,beta,gamma,".each_non_empty_token(',') { tok =>
            count += 1;
            sum_len += tok.len;
        };
        sub.assert_eq(count, 3);
        sub.assert_eq(sum_len, 14);

        var dyn_buf: u8[>..] = [];
        sub.assert_true(dyn_buf.try_push(0 as i64));
        sub.assert_true(dyn_buf.try_push(255 as i64));
        sub.assert_false(dyn_buf.try_push(-1 as i64));
        sub.assert_false(dyn_buf.try_push(256 as i64));
        sub.assert_eq(dyn_buf.len, 2);

        var mask: u64 = 0x05;
        mask.clear_flag(0x01 as u64);
        sub.assert_eq(mask, 0x04 as u64);
        mask.toggle_flag(0x06 as u64);
        sub.assert_eq(mask, 0x02 as u64);
    };
}

fn test_sync_primitives(t: lit::T&) {
    t.run("SingleflightGroup full lifecycle, shared waiters, overflow & error guards") { sub =>
        var g = core::SingleflightGroup { .. };
        let lead1, val1, sh1 = core::start_or_join(g, "k1");
        sub.assert_true(lead1 && val1 == 0 && !sh1);
        let lead_f, _, sh_f = core::start_or_join(g, "k1");
        sub.assert_true(!lead_f && sh_f);
        sub.assert_true(core::is_shared(g, "k1"));
        sub.assert_eq(core::waiter_count(g, "k1"), 1);
        sub.assert_eq(core::waiter_count(g, "missing"), 0);
        sub.assert_false(core::forget_unshared(g, "k1"), "cannot forget_unshared while waiter_count > 0");
        sub.assert_false(core::forget_unshared(g, "missing"));
        let l_single, _, _ = core::start_or_join(g, "single");
        sub.assert_true(l_single);
        let _, _ = core::finish_call(g, "single", 5, true);
        sub.assert_true(core::forget_unshared(g, "single"));

        let _, ok_rv_before = core::result_value(g, "k1");
        sub.assert_false(ok_rv_before);
        let ok_fin_miss, _ = core::finish_call(g, "missing", 10, true);
        sub.assert_false(ok_fin_miss);

        let ok_fin, waiters = core::finish_call(g, "k1", 777, true);
        sub.assert_true(ok_fin && waiters == 1);
        let lead_done, val_done, sh_done = core::start_or_join(g, "k1");
        sub.assert_true(!lead_done && val_done == 777 && sh_done);
        let rv, ok_rv = core::result_value(g, "k1");
        sub.assert_true(ok_rv && rv == 777);

        sub.assert_false(core::forget(g, "missing"));
        sub.assert_true(core::forget(g, "k1"));

        // Capacity overflow (32 entries)
        for i in 32 {
            var kbuf: u8[..16] = [];
            kbuf.append("key-");
            core::format_i64_dec(i, kbuf);
            let l, _, _ = core::start_or_join(g, kbuf[..]);
            sub.assert_true(l);
        }
        let l_ov, v_ov, sh_ov = core::start_or_join(g, "key-overflow");
        sub.assert_true(l_ov && v_ov == 0 && !sh_ov);
    };

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

    t.run("Bitmask, arithmetic, random, hash, bits, network, free_list edge paths") { sub =>
        var m64: u64 = 0xFF;
        core::clear_bit_u64(m64, 64);
        core::clear_bit_u64(m64, 1);
        sub.assert_eq(m64, 0xFD as u64);
        var zero64: u64 = 0;
        let _, ok_pop = core::pop_lowest_bit_u64(zero64);
        sub.assert_false(ok_pop);

        var words: u64[2] = [0, 0];
        sub.assert_false(core::bitset_test(words[..], 200));
        sub.assert_false(core::bitset_clear(words[..], 200));
        let _, ok_ns_oob = core::bitset_next_set(words[..], 200);
        sub.assert_false(ok_ns_oob);
        let _, ok_ns_empty = core::bitset_next_set(words[..], 0);
        sub.assert_false(ok_ns_empty);

        sub.assert_eq(core::mul_sat_i64(core::I64_MAX, -2), core::I64_MIN);
        sub.assert_eq(core::mul_sat_i64(core::I64_MAX, 2), core::I64_MAX);
        sub.assert_eq(core::rem_euclid_i64(core::I64_MIN, -1), 0);
        sub.assert_eq(core::rem_euclid_i64(5, 0), 0);
        sub.assert_eq(core::div_euclid_i64(core::I64_MIN, -1), core::I64_MAX);
        sub.assert_eq(core::div_euclid_i64(5, 0), 0);
        sub.assert_eq(core::fast_mod_reduce_i32(5, 0), 0);

        var rng0 = core::new_wyrand(0);
        sub.assert_eq(core::fast_range_unbiased_u32(rng0, 1), 0 as u32);
        for _ in 32 {
            let v = core::fast_range_unbiased_u32(rng0, 0x90000001 as u32);
            sub.assert_lt(v, 0x90000001 as u32);
        }
        let xo = core::new_xoroshiro64_star_star(0x61c8864680b583eb);
        sub.assert_true(xo.s0 != 0);

        let data40 = "0123456789abcdefghijklmnopqrstuvwxyzABCD";
        sub.assert_true(core::xxhash32(data40, 1) != 0);
        sub.assert_eq(core::wy_read_small(data40, 0), 0 as u64);

        sub.assert_eq(core::next_pow2_u32(0x80000001 as u32), 0x80000000 as u32);
        sub.assert_eq(core::next_pow2_u64(0), 1 as u64);
        sub.assert_eq(core::next_pow2_u64(0x8000000000000001), 0x8000000000000000);

        sub.assert_eq(core::backoff_full_jitter_ms(rng0, 0, 100, 1), 0 as u64);
        let _ = core::backoff_full_jitter_ms(rng0, core::U64_MAX, core::U64_MAX, 0);
        let _ = core::backoff_decorrelated_jitter_ms(rng0, 0, core::U64_MAX, core::U64_MAX);
        sub.assert_eq(core::backoff_equal_jitter_ms(rng0, 1, 100, 0), 0 as u64);

        var empty_fl = core::FreeIndexList { .. };
        var empty_next: i32[0] = [];
        core::free_list_init(empty_fl, empty_next[..]);
        var next2: i32[2] = [0, 0];
        core::free_list_init(empty_fl, next2[..]);
        sub.assert_false(core::free_list_free(empty_fl, next2[..], 99));
        sub.assert_true(core::free_list_free(empty_fl, next2[..], 0));
    };
}

fn main() {
    let runner = lit::new_runner("Core UFCS, Sync, and Math Verification Suite");
    lit::run_case(runner, "1. UFCS Bridges", test_ufcs_bridges);
    lit::run_case(runner, "2. Sync Primitives (Singleflight, SPSC)", test_sync_primitives);
    lit::run_case(runner, "3. Math Edge Cases", test_math_edge_cases);
    assert(lit::finish(runner));
}
