// Verification and conformance test suite for core/math.goose (std.math).
// Tests branchless constant-time arithmetic, saturation logic, Euclidean division,
// 128-bit multiplication without u128, WyRand v4.2, Lemire fast-range,
// Jacobson EWMA RTT (RFC 6298 / RFC 9002 Errata ID 7539),
// non-cryptographic hashes (FNV-1a, xxHash32, wyhash64), and SOCKS5 CT frame validation.
import std;
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Branchless Constant-Time Arithmetic & Selection
// ----------------------------------------------------------------------------
fn test_branchless_constant_time(t: wing::T&) {
    t.run("ct_is_zero_u32 and ct_is_zero_u64") { sub =>
        sub.assert_eq(wing::ct_is_zero_u32(0), 1, "0 is zero (u32)");
        sub.assert_eq(wing::ct_is_zero_u32(1), 0, "1 is not zero (u32)");
        sub.assert_eq(wing::ct_is_zero_u32(0x80000000), 0, "MSB set is not zero (u32)");
        sub.assert_eq(wing::ct_is_zero_u32(0xFFFFFFFF), 0, "all ones is not zero (u32)");

        sub.assert_eq(wing::ct_is_zero_u64(0), 1, "0 is zero (u64)");
        sub.assert_eq(wing::ct_is_zero_u64(1), 0, "1 is not zero (u64)");
        sub.assert_eq(wing::ct_is_zero_u64(0x8000000000000000), 0, "MSB set is not zero (u64)");
        sub.assert_eq(wing::ct_is_zero_u64(0xFFFFFFFFFFFFFFFF), 0, "all ones is not zero (u64)");
    };

    t.run("ct_eq, ct_lt, ct_gt") { sub =>
        sub.assert_eq(wing::ct_eq_u32(42, 42), 1, "42 == 42");
        sub.assert_eq(wing::ct_eq_u32(42, 43), 0, "42 != 43");
        sub.assert_eq(wing::ct_eq_u64(10000000000, 10000000000), 1, "10B == 10B");
        sub.assert_eq(wing::ct_eq_u64(10000000000, 10000000001), 0, "10B != 10B+1");

        sub.assert_eq(wing::ct_lt_u32(10, 20), 1, "10 < 20 (u32)");
        sub.assert_eq(wing::ct_lt_u32(20, 20), 0, "20 !< 20 (u32)");
        sub.assert_eq(wing::ct_lt_u32(30, 20), 0, "30 !< 20 (u32)");

        sub.assert_eq(wing::ct_lt_u64(100, 200), 1, "100 < 200 (u64)");
        sub.assert_eq(wing::ct_lt_u64(200, 200), 0, "200 !< 200 (u64)");
        sub.assert_eq(wing::ct_lt_u64(300, 200), 0, "300 !< 200 (u64)");

        sub.assert_eq(wing::ct_gt_u32(20, 10), 1, "20 > 10 (u32)");
        sub.assert_eq(wing::ct_gt_u32(10, 20), 0, "10 !> 20 (u32)");
        sub.assert_eq(wing::ct_gt_u64(200, 100), 1, "200 > 100 (u64)");
        sub.assert_eq(wing::ct_gt_u64(100, 200), 0, "100 !> 200 (u64)");
    };

    t.run("ct_mask, ct_select, ct_min, ct_max") { sub =>
        sub.assert_eq(wing::ct_mask_u32(1), 0xFFFFFFFF, "mask(1) u32");
        sub.assert_eq(wing::ct_mask_u32(0), 0, "mask(0) u32");
        sub.assert_eq(wing::ct_mask_u64(1), 0xFFFFFFFFFFFFFFFF, "mask(1) u64");
        sub.assert_eq(wing::ct_mask_u64(0), 0, "mask(0) u64");

        let mask_t = wing::ct_mask_u32(1);
        let mask_f = wing::ct_mask_u32(0);
        sub.assert_eq(wing::ct_select_u32(mask_t, 555, 999), 555, "ct_select true (u32)");
        sub.assert_eq(wing::ct_select_u32(mask_f, 555, 999), 999, "ct_select false (u32)");

        let mask64_t = wing::ct_mask_u64(1);
        let mask64_f = wing::ct_mask_u64(0);
        sub.assert_eq(wing::ct_select_u64(mask64_t, 123456789012, 987654321098), 123456789012, "ct_select true (u64)");
        sub.assert_eq(wing::ct_select_u64(mask64_f, 123456789012, 987654321098), 987654321098, "ct_select false (u64)");

        sub.assert_eq(wing::ct_min_u32(15, 25), 15, "min_u32 15 vs 25");
        sub.assert_eq(wing::ct_min_u32(40, 30), 30, "min_u32 40 vs 30");
        sub.assert_eq(wing::ct_max_u32(15, 25), 25, "max_u32 15 vs 25");
        sub.assert_eq(wing::ct_max_u32(40, 30), 40, "max_u32 40 vs 30");

        sub.assert_eq(wing::ct_min_u64(500, 1000), 500, "min_u64");
        sub.assert_eq(wing::ct_max_u64(500, 1000), 1000, "max_u64");
    };

    t.run("ct_abs_i64 and clamp functions") { sub =>
        sub.assert_eq(wing::ct_abs_i64(500), 500, "abs(500)");
        sub.assert_eq(wing::ct_abs_i64(-500), 500, "abs(-500)");
        sub.assert_eq(wing::ct_abs_i64(0), 0, "abs(0)");

        sub.assert_eq(wing::clamp_u32(5, 10, 20), 10, "clamp_u32 below");
        sub.assert_eq(wing::clamp_u32(15, 10, 20), 15, "clamp_u32 within");
        sub.assert_eq(wing::clamp_u32(25, 10, 20), 20, "clamp_u32 above");

        sub.assert_eq(wing::clamp_u64(5, 10, 20), 10, "clamp_u64 below");
        sub.assert_eq(wing::clamp_u64(15, 10, 20), 15, "clamp_u64 within");
        sub.assert_eq(wing::clamp_u64(25, 10, 20), 20, "clamp_u64 above");

        sub.assert_eq(wing::clamp_i64(-5, 10, 20), 10, "clamp_i64 below");
        sub.assert_eq(wing::clamp_i64(15, 10, 20), 15, "clamp_i64 within");
        sub.assert_eq(wing::clamp_i64(25, 10, 20), 20, "clamp_i64 above");
    };
}

// ----------------------------------------------------------------------------
// 2. Saturation & Checked Arithmetic
// ----------------------------------------------------------------------------
fn test_saturation_and_checked_arithmetic(t: wing::T&) {
    t.run("Unsigned Saturation (add_sat, sub_sat, mul_sat)") { sub =>
        sub.assert_eq(wing::add_sat_u32(0xFFFFFFFF, 1), 0xFFFFFFFF, "add_sat_u32 overflow");
        sub.assert_eq(wing::add_sat_u32(100, 200), 300, "add_sat_u32 normal");

        sub.assert_eq(wing::sub_sat_u32(10, 20), 0, "sub_sat_u32 underflow");
        sub.assert_eq(wing::sub_sat_u32(30, 10), 20, "sub_sat_u32 normal");

        sub.assert_eq(wing::add_sat_u64(wing::U64_MAX, 1), wing::U64_MAX, "add_sat_u64 overflow");
        sub.assert_eq(wing::add_sat_u64(500, 500), 1000, "add_sat_u64 normal");

        sub.assert_eq(wing::sub_sat_u64(10, 20), 0, "sub_sat_u64 underflow");
        sub.assert_eq(wing::sub_sat_u64(50, 20), 30, "sub_sat_u64 normal");

        sub.assert_eq(wing::mul_sat_u32(0x80000000, 2), 0xFFFFFFFF, "mul_sat_u32 overflow");
        sub.assert_eq(wing::mul_sat_u32(20, 30), 600, "mul_sat_u32 normal");

        sub.assert_eq(wing::mul_sat_u64(0x8000000000000000, 2), wing::U64_MAX, "mul_sat_u64 overflow");
        sub.assert_eq(wing::mul_sat_u64(1000, 2000), 2000000, "mul_sat_u64 normal");
    };

    t.run("shl_sat_u64 and Signed Saturation") { sub =>
        sub.assert_eq(wing::shl_sat_u64(1, 64), wing::U64_MAX, "shl_sat shift == 64");
        sub.assert_eq(wing::shl_sat_u64(1, 100), wing::U64_MAX, "shl_sat shift > 64");
        sub.assert_eq(wing::shl_sat_u64(0x8000000000000000, 1), wing::U64_MAX, "shl_sat bit loss");
        sub.assert_eq(wing::shl_sat_u64(10, 3), 80, "shl_sat normal 10 << 3");
        sub.assert_eq(wing::shl_sat_u64(0, 100), 0, "shl_sat 0 shifted is 0");

        sub.assert_eq(wing::add_sat_i64(wing::I64_MAX - 5, 10), wing::I64_MAX, "add_sat_i64 positive ovf");
        sub.assert_eq(wing::add_sat_i64(wing::I64_MIN + 5, -10), wing::I64_MIN, "add_sat_i64 negative ovf");
        sub.assert_eq(wing::add_sat_i64(100, -30), 70, "add_sat_i64 normal");

        sub.assert_eq(wing::sub_sat_i64(wing::I64_MIN + 5, 10), wing::I64_MIN, "sub_sat_i64 negative ovf");
        sub.assert_eq(wing::sub_sat_i64(wing::I64_MAX - 5, -10), wing::I64_MAX, "sub_sat_i64 positive ovf");
        sub.assert_eq(wing::sub_sat_i64(100, 30), 70, "sub_sat_i64 normal");
    };

    t.run("Checked Arithmetic and Retry-After Conversion") { sub =>
        let c_u32_ovf = wing::add_checked_u32(0xFFFFFFFF, 1);
        sub.assert_eq(c_u32_ovf.overflow, true, "add_checked_u32 ovf flag");
        sub.assert_eq(c_u32_ovf.value, 0, "add_checked_u32 wrapped val");

        let c_u32_ok = wing::add_checked_u32(100, 200);
        sub.assert_eq(c_u32_ok.overflow, false, "add_checked_u32 ok flag");
        sub.assert_eq(c_u32_ok.value, 300, "add_checked_u32 ok val");

        let c_u64_ovf = wing::add_checked_u64(wing::U64_MAX, 1);
        sub.assert_eq(c_u64_ovf.overflow, true, "add_checked_u64 ovf flag");

        let c_i64_ovf = wing::mul_checked_i64(wing::I64_MAX, 2);
        sub.assert_eq(c_i64_ovf.overflow, true, "mul_checked_i64 ovf flag");

        let c_i64_ok = wing::mul_checked_i64(10, -5);
        sub.assert_eq(c_i64_ok.overflow, false, "mul_checked_i64 ok flag");
        sub.assert_eq(c_i64_ok.value, -50, "mul_checked_i64 ok val");

        sub.assert_eq(wing::retry_after_sec_to_ms_sat(10), 10000, "retry-after 10s -> 10000ms");
        sub.assert_eq(wing::retry_after_sec_to_ms_sat(-5), 0, "retry-after negative -> 0ms");
        sub.assert_eq(wing::retry_after_sec_to_ms_sat(wing::I64_MAX), wing::I64_MAX, "retry-after huge -> I64_MAX");
    };
}

// ----------------------------------------------------------------------------
// 3. 128-Bit Multiplication & Wymum Without u128
// ----------------------------------------------------------------------------
fn test_wide_multiplication_and_wymum(t: wing::T&) {
    t.run("mul_wide_u64 Standard Vectors") { sub =>
        let lo0, hi0 = wing::mul_wide_u64(0, 123456789);
        sub.assert_eq(lo0, 0, "mul_wide 0 * X lo");
        sub.assert_eq(hi0, 0, "mul_wide 0 * X hi");

        let lo1, hi1 = wing::mul_wide_u64(1, 123456789);
        sub.assert_eq(lo1, 123456789, "mul_wide 1 * X lo");
        sub.assert_eq(hi1, 0, "mul_wide 1 * X hi");

        // 2^32 * 2^32 = 2^64 (lo = 0, hi = 1)
        let lo2, hi2 = wing::mul_wide_u64(0x100000000, 0x100000000);
        sub.assert_eq(lo2, 0, "2^32 * 2^32 lo");
        sub.assert_eq(hi2, 1, "2^32 * 2^32 hi");

        // (2^64 - 1) * (2^64 - 1) = 2^128 - 2^65 + 1 -> lo = 1, hi = 0xFFFFFFFFFFFFFFFE
        let lo_max, hi_max = wing::mul_wide_u64(wing::U64_MAX, wing::U64_MAX);
        sub.assert_eq(lo_max, 1, "MAX * MAX lo");
        sub.assert_eq(hi_max, 0xFFFFFFFFFFFFFFFE, "MAX * MAX hi");
    };

    t.run("wymum Invariant and Folding") { sub =>
        let w0 = wing::wymum(0, 0);
        sub.assert_eq(w0, 0, "wymum(0, 0) == 0");

        let w1 = wing::wymum(1, 1);
        sub.assert_eq(w1, 1, "wymum(1, 1) == 1");

        // wymum must mix lo ^ hi
        let lo_m, hi_m = wing::mul_wide_u64(0x100000000, 0x100000000);
        let expected = lo_m ^ hi_m;
        let w_cross = wing::wymum(0x100000000, 0x100000000);
        sub.assert_eq(w_cross, expected, "wymum mixes lo ^ hi correctly");
    };
}

// ----------------------------------------------------------------------------
// 4. Bit Manipulation & Endianness Codecs
// ----------------------------------------------------------------------------
fn test_bit_manipulation_and_endianness(t: wing::T&) {
    t.run("rotl32, rotr32, rotl64, rotr64") { sub =>
        let val32: u32 = 0x12345678;
        let rot8 = wing::rotl32(val32, 8);
        sub.assert_eq(rot8, 0x34567812, "rotl32 by 8");
        sub.assert_eq(wing::rotr32(rot8, 8), val32, "rotr32 invert rotl32");

        sub.assert_eq(wing::rotl32(val32, 0), val32, "rotl32 by 0");
        sub.assert_eq(wing::rotl32(val32, 32), val32, "rotl32 by 32");

        let val64: u64 = 0x0123456789ABCDEF;
        let rot16 = wing::rotl64(val64, 16);
        sub.assert_eq(rot16, 0x456789ABCDEF0123, "rotl64 by 16");
        sub.assert_eq(wing::rotr64(rot16, 16), val64, "rotr64 invert rotl64");
    };

    t.run("is_pow2 and next_pow2") { sub =>
        sub.assert_eq(wing::is_pow2_u32(0), false, "0 is not pow2 (u32)");
        sub.assert_eq(wing::is_pow2_u32(1), true, "1 is pow2 (u32)");
        sub.assert_eq(wing::is_pow2_u32(1024), true, "1024 is pow2 (u32)");
        sub.assert_eq(wing::is_pow2_u32(1023), false, "1023 is not pow2 (u32)");

        sub.assert_eq(wing::next_pow2_u32(0), 1, "next_pow2(0)");
        sub.assert_eq(wing::next_pow2_u32(1), 1, "next_pow2(1)");
        sub.assert_eq(wing::next_pow2_u32(5), 8, "next_pow2(5)");
        sub.assert_eq(wing::next_pow2_u32(16), 16, "next_pow2(16)");
        sub.assert_eq(wing::next_pow2_u32(17), 32, "next_pow2(17)");

        sub.assert_eq(wing::is_pow2_u64(0x8000000000000000), true, "2^63 is pow2 (u64)");
        sub.assert_eq(wing::next_pow2_u64(0x8000000000000001), 0x8000000000000000, "next_pow2 overflow clamp");
    };

    t.run("bswap16, bswap32, bswap64") { sub =>
        sub.assert_eq(wing::bswap16(0x1234), 0x3412, "bswap16");
        sub.assert_eq(wing::bswap32(0x12345678), 0x78563412, "bswap32");
        sub.assert_eq(wing::bswap64(0x0102030405060708), 0x0807060504030201, "bswap64");
    };
}

// ----------------------------------------------------------------------------
// 5. Euclidean Division & Remainder
// ----------------------------------------------------------------------------
fn test_euclidean_division_and_remainder(t: wing::T&) {
    t.run("rem_euclid_i64 strictly in [0, |b|)") { sub =>
        sub.assert_eq(wing::rem_euclid_i64(7, 3), 1, "7 % 3 == 1");
        sub.assert_eq(wing::rem_euclid_i64(-7, 3), 2, "-7 % 3 == 2 (Euclidean non-negative!)");
        sub.assert_eq(wing::rem_euclid_i64(7, -3), 1, "7 % -3 == 1");
        sub.assert_eq(wing::rem_euclid_i64(-7, -3), 2, "-7 % -3 == 2");
        sub.assert_eq(wing::rem_euclid_i64(0, 5), 0, "0 % 5 == 0");
    };

    t.run("div_euclid_i64 Quotient Identity a = q * b + r") { sub =>
        // 7 = 2 * 3 + 1
        sub.assert_eq(wing::div_euclid_i64(7, 3), 2, "7 / 3 == 2");
        // -7 = -3 * 3 + 2
        sub.assert_eq(wing::div_euclid_i64(-7, 3), -3, "-7 / 3 == -3");
        // 7 = -2 * -3 + 1
        sub.assert_eq(wing::div_euclid_i64(7, -3), -2, "7 / -3 == -2");
        // -7 = 3 * -3 + 2
        sub.assert_eq(wing::div_euclid_i64(-7, -3), 3, "-7 / -3 == 3");
    };

    t.run("fast_mod_reduce_i32 Ring Buffer Indexing") { sub =>
        sub.assert_eq(wing::fast_mod_reduce_i32(0, 16), 0, "idx 0 in buf 16");
        sub.assert_eq(wing::fast_mod_reduce_i32(15, 16), 15, "idx 15 in buf 16");
        sub.assert_eq(wing::fast_mod_reduce_i32(16, 16), 0, "idx 16 wraps to 0");
        sub.assert_eq(wing::fast_mod_reduce_i32(-1, 16), 15, "idx -1 wraps to 15");
        sub.assert_eq(wing::fast_mod_reduce_i32(-17, 16), 15, "idx -17 wraps to 15");
    };
}

// ----------------------------------------------------------------------------
// 6. PRNGs & Lemire Fast-Range Mapping
// ----------------------------------------------------------------------------
fn test_prng_and_lemire_range(t: wing::T&) {
    t.run("WyRand Determinism and State Progression") { sub =>
        var rng1 = wing::new_wyrand(42);
        var rng2 = wing::new_wyrand(42);

        let v1 = wing::next_u64(rng1);
        let v2 = wing::next_u64(rng2);
        sub.assert_eq(v1, v2, "WyRand deterministic from same seed");
        sub.assert_ne(v1, 0, "WyRand output non-zero");

        let v3 = wing::next_u64(rng1);
        sub.assert_ne(v1, v3, "WyRand steps sequentially");

        let u1 = wing::next_u32(rng2);
        sub.assert_ne(u1, 0, "WyRand next_u32 non-zero");
    };

    t.run("Xoroshiro64StarStar Generation") { sub =>
        var rng = wing::new_xoroshiro64(123456);
        let a = wing::next_u32(rng);
        let b = wing::next_u32(rng);
        sub.assert_ne(a, b, "Xoroshiro64 steps state");
    };

    t.run("Lemire Fast-Range Bounds (Biased and Unbiased)") { sub =>
        // Boundary check: output must strictly be in [0, range)
        for i in 100 {
            let r_biased = wing::fast_range_biased_u32((i * 123456789) as u32, 50);
            sub.assert_lt(r_biased, 50, "fast_range_biased_u32 < 50");
        }

        let r64_biased = wing::fast_range_biased_u64(wing::U64_MAX, 100);
        sub.assert_lt(r64_biased, 100, "fast_range_biased_u64 < 100");

        var rng = wing::new_wyrand(999);
        for i in 100 {
            let r_unbiased = wing::fast_range_unbiased_u32(rng, 37);
            sub.assert_lt(r_unbiased, 37, "fast_range_unbiased_u32 < 37");
        }
    };
}

// ----------------------------------------------------------------------------
// 7. Backoff & Jitter Strategies (Happy Eyeballs / AWS)
// ----------------------------------------------------------------------------
fn test_backoff_and_jitter_strategies(t: wing::T&) {
    t.run("AWS Full and Equal Jitter Bounds") { sub =>
        var rng = wing::new_wyrand(1234);
        let base_ms: u64 = 100;
        let cap_ms: u64 = 10000;

        for attempt in 10 {
            let sleep_full = wing::backoff_full_jitter_ms(rng, base_ms, cap_ms, attempt as u32);
            sub.assert_le(sleep_full, cap_ms, "Full Jitter <= cap");

            let sleep_equal = wing::backoff_equal_jitter_ms(rng, base_ms, cap_ms, attempt as u32);
            sub.assert_le(sleep_equal, cap_ms, "Equal Jitter <= cap");
        }
    };

    t.run("AWS Decorrelated Jitter (Clamping Flaw Immunity)") { sub =>
        var rng = wing::new_wyrand(5678);
        let base_ms: u64 = 50;
        let cap_ms: u64 = 5000;
        var sleep_ms = base_ms;

        // In naive implementations, if sleep_ms >= cap_ms, clamping to [base_ms, cap_ms]
        // causes the range [base_ms, sleep * 3] to collapse or become degenerate.
        // Goose-wing math guarantees sleep >= base_ms and <= cap_ms always!
        for i in 50 {
            sleep_ms = wing::backoff_decorrelated_jitter_ms(rng, base_ms, cap_ms, sleep_ms);
            sub.assert_ge(sleep_ms, base_ms, "Decorrelated sleep >= base");
            sub.assert_le(sleep_ms, cap_ms, "Decorrelated sleep <= cap");
        }
    };

    t.run("Happy Eyeballs Delay Clamping (RFC 8305)") { sub =>
        // Candidate delay below absolute minimum 10ms -> clamped to 10ms
        let d_low = wing::clamp_happy_eyeballs_delay_ms(5, false);
        sub.assert_eq(d_low, 10, "RFC 8305 floor >= 10ms");

        // First family recommended min 100ms
        let d_first = wing::clamp_happy_eyeballs_delay_ms(50, true);
        sub.assert_eq(d_first, 100, "RFC 8305 first family >= 100ms");

        // Normal CAD within window [100ms, 2000ms]
        let d_normal = wing::clamp_happy_eyeballs_delay_ms(250, false);
        sub.assert_eq(d_normal, 250, "Normal CAD preserved");

        // Max CAD ceiling 2000ms
        let d_high = wing::clamp_happy_eyeballs_delay_ms(5000, false);
        sub.assert_eq(d_high, 2000, "Max CAD clamped to 2000ms");
    };
}

// ----------------------------------------------------------------------------
// 8. Jacobson EWMA RTT Estimator (RFC 6298 / RFC 9002 Errata ID 7539)
// ----------------------------------------------------------------------------
fn test_jacobson_rtt_estimator_errata7539(t: wing::T&) {
    t.run("Initial State and First Sample") { sub =>
        var est = wing::new_jacobson_rtt_estimator(333000);
        sub.assert_eq(est.has_sample, false, "init has no sample");
        sub.assert_eq(wing::smoothed_rtt_us(est), 333000, "init srtt 333ms");
        sub.assert_eq(wing::rttvar_us(est), 166500, "init rttvar 166.5ms");

        // First RTT sample: 100 ms (100,000 us)
        wing::on_rtt_sample(est, 100000, 0, 25000, false);
        sub.assert_eq(est.has_sample, true, "has sample after first update");
        sub.assert_eq(est.min_rtt_us, 100000, "min_rtt initialized to first sample");
        sub.assert_eq(wing::smoothed_rtt_us(est), 100000, "first sample srtt == sample");
        sub.assert_eq(wing::rttvar_us(est), 50000, "first sample rttvar == sample / 2");
    };

    t.run("RFC 9002 Errata ID 7539 Variance Order Invariant") { sub =>
        var est = wing::new_jacobson_rtt_estimator(100000);
        wing::on_rtt_sample(est, 100000, 0, 25000, false);

        // Second sample: 120 ms (120,000 us)
        // With Errata ID 7539:
        // prior_srtt = 100,000 us
        // abs_diff = |120,000 - 100,000| = 20,000 us
        // rttvar_scaled was 200,000 (4 * 50,000).
        // rttvar_scaled = 200,000 - 50,000 + 20,000 = 170,000.
        // rttvar = 170,000 / 4 = 42,500 us.
        // srtt_scaled was 800,000 (8 * 100,000).
        // srtt_scaled = 800,000 - 100,000 + 120,000 = 820,000.
        // srtt = 820,000 / 8 = 102,500 us.
        wing::on_rtt_sample(est, 120000, 0, 25000, false);

        sub.assert_eq(wing::smoothed_rtt_us(est), 102500, "Errata 7539 srtt");
        sub.assert_eq(wing::rttvar_us(est), 42500, "Errata 7539 rttvar calculated before srtt update");
    };

    t.run("Defensive Ack Delay Subtraction & Handshake Bounding") { sub =>
        var est = wing::new_jacobson_rtt_estimator(50000);
        wing::on_rtt_sample(est, 50000, 0, 25000, false);

        // Before handshake confirmation: ack_delay is ignored
        wing::on_rtt_sample(est, 60000, 10000, 25000, false);
        // sample with unconfirmed handshake treats adjusted_rtt = latest_rtt (60,000)
        sub.assert_eq(est.min_rtt_us, 50000, "min_rtt remains 50ms");

        // After handshake confirmation:
        // Peer reports malicious ack_delay 50,000 us on latest_rtt 60,000 us
        // min_rtt is 50,000 us. latest_rtt (60,000) < min_rtt (50,000) + ack_delay (25,000 clamped).
        // Goose-wing math DEFENSIVELY rejects subtracting ack_delay so adjusted_rtt does not shrink below min_rtt!
        wing::on_rtt_sample(est, 60000, 50000, 25000, true);
        sub.assert_ge(wing::smoothed_rtt_us(est), 50000, "Defensive barrier protects srtt");
    };

    t.run("Probe Timeout (PTO) and Loss Time Threshold") { sub =>
        var est = wing::new_jacobson_rtt_estimator(80000);
        wing::on_rtt_sample(est, 80000, 0, 25000, false);

        // PTO = smoothed_rtt + 4 * rttvar + max_ack_delay
        // = 80,000 + 4 * 40,000 + 25,000 = 80,000 + 160,000 + 25,000 = 265,000 us
        let pto = wing::probe_timeout_us(est, 25000);
        sub.assert_eq(pto, 265000, "RFC 9002 PTO formula");

        // Loss time threshold = max(9/8 * max(latest_rtt, srtt), timer_granularity)
        let loss_thresh = wing::loss_time_threshold_us(est);
        // 9/8 * 80,000 = 90,000 us
        sub.assert_eq(loss_thresh, 90000, "QUIC loss time threshold 9/8 ratio");
    };
}

// ----------------------------------------------------------------------------
// 9. Fast Non-Cryptographic Hashing & Combinators
// ----------------------------------------------------------------------------
fn test_fast_non_cryptographic_hashes(t: wing::T&) {
    t.run("FNV-1a 32-bit and 64-bit Test Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(wing::fnv1a_32(empty_buf[..]), 0x811C9DC5, "FNV-1a 32-bit empty offset");
        sub.assert_eq(wing::fnv1a_64(empty_buf[..]), 0xCBF29CE484222325, "FNV-1a 64-bit empty offset");

        let hello = "hello";
        sub.assert_eq(wing::fnv1a_32(hello[..]), 0x4F9F2CAB, "FNV-1a 32-bit 'hello'");
        sub.assert_eq(wing::fnv1a_64(hello[..]), 0xA430D84680AABD0B, "FNV-1a 64-bit 'hello'");
    };

    t.run("xxHash32 Reference Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(wing::xxhash32(empty_buf[..], 0), 0x02CC5D05, "xxHash32 empty seed 0");

        let hello = "hello";
        sub.assert_eq(wing::xxhash32(hello[..], 0), 0xFB0077F9, "xxHash32 'hello' seed 0");
    };

    t.run("wyhash64 Consistency and Block Processing") { sub =>
        let empty_buf: u8[0] = [];
        let h_empty = wing::wyhash64(empty_buf[..], 0);
        sub.assert_ne(h_empty, 0, "wyhash64 empty seed 0 produces well-distributed hash");

        let msg = "The quick brown fox jumps over the lazy dog";
        let h_msg1 = wing::wyhash64(msg[..], 0);
        let h_msg2 = wing::wyhash64(msg[..], 0);
        sub.assert_eq(h_msg1, h_msg2, "wyhash64 deterministic");
        sub.assert_ne(h_msg1, h_empty, "wyhash64 distinguishes message");

        // Long string (> 48 bytes) exercising 48-byte loop and remainder handling
        let long_msg = "goose-wing high-performance deterministic network stack zero-heap constant-time core math primitives";
        let h_long = wing::wyhash64(long_msg[..], 42);
        sub.assert_ne(h_long, 0, "wyhash64 48-byte chunk processing");
    };

    t.run("Non-Commutative Hash Combinators") { sub =>
        let h1: u64 = 0x1234567890ABCDEF;
        let h2: u64 = 0xFEDCBA0987654321;
        let comb12 = wing::hash_combine_u64(h1, h2);
        let comb21 = wing::hash_combine_u64(h2, h1);
        sub.assert_ne(comb12, comb21, "hash_combine_u64 must be non-commutative");

        let h32_1: u32 = 0x12345678;
        let h32_2: u32 = 0x87654321;
        let comb32_12 = wing::hash_combine_u32(h32_1, h32_2);
        let comb32_21 = wing::hash_combine_u32(h32_2, h32_1);
        sub.assert_ne(comb32_12, comb32_21, "hash_combine_u32 must be non-commutative");
    };
}

// ----------------------------------------------------------------------------
// 10. Constant-Time SOCKS5 Frame Length Validation
// ----------------------------------------------------------------------------
fn test_socks5_frame_validation_ct(t: wing::T&) {
    t.run("SOCKS5 Address Types and Bounds") { sub =>
        // IPv4 (ATYP 0x01): [VER=5, CMD=1, RSV=0, ATYP=1, IPv4 (4B), Port (2B)] -> 10 bytes
        let buf_ipv4: u8[10] = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];
        let len_ipv4 = wing::socks5_expected_frame_len_ct(buf_ipv4[..]);
        sub.assert_eq(len_ipv4, 10, "SOCKS5 IPv4 expected length");

        // Too short (< 5 bytes)
        let buf_short: u8[4] = [0x05, 0x01, 0x00, 0x01];
        let len_short = wing::socks5_expected_frame_len_ct(buf_short[..]);
        sub.assert_eq(len_short, 0, "SOCKS5 frame < 5 bytes returns 0");

        // IPv6 (ATYP 0x04): 4 header + 16 addr + 2 port = 22 bytes
        let buf_ipv6: u8[6] = [0x05, 0x01, 0x00, 0x04, 0x00, 0x00];
        let len_ipv6 = wing::socks5_expected_frame_len_ct(buf_ipv6[..]);
        sub.assert_eq(len_ipv6, 22, "SOCKS5 IPv6 expected length");

        // FQDN (ATYP 0x03): 4 header + 1 len + N bytes + 2 port = 7 + N
        // domain_len = 14 -> 7 + 14 = 21 bytes
        let buf_fqdn: u8[6] = [0x05, 0x01, 0x00, 0x03, 14, 0x00];
        let len_fqdn = wing::socks5_expected_frame_len_ct(buf_fqdn[..]);
        sub.assert_eq(len_fqdn, 21, "SOCKS5 FQDN expected length (7 + 14 = 21)");

        // FQDN with 0 length domain is invalid
        let buf_fqdn_zero: u8[6] = [0x05, 0x01, 0x00, 0x03, 0, 0x00];
        let len_fqdn_zero = wing::socks5_expected_frame_len_ct(buf_fqdn_zero[..]);
        sub.assert_eq(len_fqdn_zero, 0, "SOCKS5 FQDN with zero length invalid");

        // Non-SOCKS5 version (e.g. SOCKS4 = 4)
        let buf_v4: u8[6] = [0x04, 0x01, 0x00, 0x01, 127, 0];
        let len_v4 = wing::socks5_expected_frame_len_ct(buf_v4[..]);
        sub.assert_eq(len_v4, 0, "SOCKS4 version rejected");

        // Unknown ATYP returns 0
        let buf_bad_atyp: u8[6] = [0x05, 0x01, 0x00, 0x02, 10, 0];
        let len_bad_atyp = wing::socks5_expected_frame_len_ct(buf_bad_atyp[..]);
        sub.assert_eq(len_bad_atyp, 0, "SOCKS5 unknown ATYP returns 0");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("core/math Conformance Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. Branchless Constant-Time Arithmetic & Selection", test_branchless_constant_time);
    wing::run_case(runner, "2. Saturation & Checked Arithmetic", test_saturation_and_checked_arithmetic);
    wing::run_case(runner, "3. 128-Bit Multiplication & Wymum Without u128", test_wide_multiplication_and_wymum);
    wing::run_case(runner, "4. Bit Manipulation & Endianness Codecs", test_bit_manipulation_and_endianness);
    wing::run_case(runner, "5. Euclidean Division & Remainder", test_euclidean_division_and_remainder);
    wing::run_case(runner, "6. PRNGs & Lemire Fast-Range Mapping", test_prng_and_lemire_range);
    wing::run_case(runner, "7. Backoff & Jitter Strategies (Happy Eyeballs / AWS)", test_backoff_and_jitter_strategies);
    wing::run_case(runner, "8. Jacobson EWMA RTT Estimator (RFC 6298 / RFC 9002 Errata ID 7539)", test_jacobson_rtt_estimator_errata7539);
    wing::run_case(runner, "9. Fast Non-Cryptographic Hashing & Combinators", test_fast_non_cryptographic_hashes);
    wing::run_case(runner, "10. Constant-Time SOCKS5 Frame Length Validation", test_socks5_frame_validation_ct);

    let ok = wing::finish(runner);
    assert(ok);
}
