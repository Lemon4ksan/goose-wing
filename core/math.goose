// Mathematical, bitwise, statistical, and non-cryptographic hashing primitives.
// Zero-heap, branchless constant-time arithmetic, Jacobson EWMA (RFC 6298 / RFC 9002 Errata 7539),
// WyRand v4.2, xoroshiro64**, Lemire fast-range, and Happy Eyeballs (RFC 8305) pacing.
namespace wing;

import std;

// ---- 1. Fundamental Constants & Checked Arithmetic Results -----------------

const U32_MAX: u32 = 0xFFFFFFFF;
const U64_MAX: u64 = 0xFFFFFFFFFFFFFFFF;
const I32_MIN: i32 = -2147483647 - 1;
const I32_MAX: i32 = 2147483647;
const I64_MIN: i64 = -9223372036854775807 - 1;
const I64_MAX: i64 = 9223372036854775807;

// Happy Eyeballs v2/v3 normative pacing constants (RFC 8305 / draft-ietf-happy-happyeyeballs-v3)
const HE_ABSOLUTE_MIN_DELAY_MS: i64       = 10;   // MUST NOT be less than 10ms
const HE_RECOMMENDED_MIN_DELAY_MS: i64    = 100;
const HE_DEFAULT_ATTEMPT_DELAY_MS: i64    = 250;
const HE_GO_FALLBACK_DELAY_MS: i64        = 300;
const HE_MAX_ATTEMPT_DELAY_MS: i64        = 2000;
const HE_LAST_RESORT_SYNTHESIS_MS: i64    = 2000;

// QUIC loss detection & congestion constants (RFC 9002)
const QUIC_INITIAL_RTT_US: u64            = 333000; // 333 ms
const QUIC_AGGRESSIVE_INITIAL_RTT_US: u64 = 100000; // 100 ms
const QUIC_TIMER_GRANULARITY_US: u64      = 1000;   // 1 ms
const QUIC_PACKET_THRESHOLD: u64          = 3;

struct CheckedU32 {
    value: u32 = 0,
    overflow: bool = false,
}

struct CheckedU64 {
    value: u64 = 0,
    overflow: bool = false,
}

struct CheckedI64 {
    value: i64 = 0,
    overflow: bool = false,
}

// 64x64 -> 128-bit unsigned expanding multiplication returning (lo, hi).
// Pure 64-bit portable arithmetic without 128-bit compiler intrinsics or heap allocs.
inline fn mul_wide_u64(a: u64, b: u64) -> u64, u64 {
    let a_lo = a & 0xFFFFFFFF;
    let a_hi = a >> 32;
    let b_lo = b & 0xFFFFFFFF;
    let b_hi = b >> 32;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let mid = (p0 >> 32) + (p1 & 0xFFFFFFFF) + (p2 & 0xFFFFFFFF);
    let lo = (p0 & 0xFFFFFFFF) | (mid << 32);
    let hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return lo, hi;
}

// ---- 2. Constant-Time Branchless Primitives --------------------------------

// Returns 1 if x < y, 0 otherwise, in strictly constant time without CF branch penalty.
inline fn ct_lt_u32(x: u32, y: u32) -> u32 {
    return (x ^ ((x ^ y) | ((x - y) ^ y))) >> 31;
}

// Returns 1 if x < y, 0 otherwise, in strictly constant time.
inline fn ct_lt_u64(x: u64, y: u64) -> u64 {
    return (x ^ ((x ^ y) | ((x - y) ^ y))) >> 63;
}

inline fn ct_gt_u32(x: u32, y: u32) -> u32 {
    return ct_lt_u32(y, x);
}

inline fn ct_gt_u64(x: u64, y: u64) -> u64 {
    return ct_lt_u64(y, x);
}

// Returns 1 if x == 0, 0 otherwise.
inline fn ct_is_zero_u32(x: u32) -> u32 {
    return 1 ^ ((x | (0 - x)) >> 31);
}

// Returns 1 if x == 0, 0 otherwise.
inline fn ct_is_zero_u64(x: u64) -> u64 {
    return 1 ^ ((x | (0 - x)) >> 63);
}

inline fn ct_eq_u32(x: u32, y: u32) -> u32 {
    return ct_is_zero_u32(x ^ y);
}

inline fn ct_eq_u64(x: u64, y: u64) -> u64 {
    return ct_is_zero_u64(x ^ y);
}

// Expands low bit {0, 1} to full mask {0x00000000, 0xFFFFFFFF}.
inline fn ct_mask_u32(bit: u32) -> u32 {
    return 0 - (bit & 1);
}

// Expands low bit {0, 1} to full mask {0x0, 0xFFFFFFFFFFFFFFFF}.
inline fn ct_mask_u64(bit: u64) -> u64 {
    return 0 - (bit & 1);
}

// Constant-time multiplexer: returns a if mask is all 1s, b if mask is 0.
inline fn ct_select_u32(mask: u32, a: u32, b: u32) -> u32 {
    return b ^ (mask & (a ^ b));
}

// Constant-time multiplexer: returns a if mask is all 1s, b if mask is 0.
inline fn ct_select_u64(mask: u64, a: u64, b: u64) -> u64 {
    return b ^ (mask & (a ^ b));
}

inline fn ct_min_u32(a: u32, b: u32) -> u32 {
    let m = ct_mask_u32(ct_lt_u32(a, b));
    return ct_select_u32(m, a, b);
}

inline fn ct_max_u32(a: u32, b: u32) -> u32 {
    let m = ct_mask_u32(ct_gt_u32(a, b));
    return ct_select_u32(m, a, b);
}

inline fn ct_min_u64(a: u64, b: u64) -> u64 {
    let m = ct_mask_u64(ct_lt_u64(a, b));
    return ct_select_u64(m, a, b);
}

inline fn ct_max_u64(a: u64, b: u64) -> u64 {
    let m = ct_mask_u64(ct_gt_u64(a, b));
    return ct_select_u64(m, a, b);
}

// Signed comparison x < y in constant time by inverting the MSB sign bit.
inline fn ct_lt_i64(x: i64, y: i64) -> u64 {
    let ux = (x as! u64) ^ 0x8000000000000000;
    let uy = (y as! u64) ^ 0x8000000000000000;
    return ct_lt_u64(ux, uy);
}

inline fn ct_gt_i64(x: i64, y: i64) -> u64 {
    return ct_lt_i64(y, x);
}

inline fn ct_min_i64(a: i64, b: i64) -> i64 {
    let m = ct_mask_u64(ct_lt_i64(a, b));
    return ct_select_u64(m, a as! u64, b as! u64) as! i64;
}

inline fn ct_max_i64(a: i64, b: i64) -> i64 {
    let m = ct_mask_u64(ct_lt_i64(b, a));
    return ct_select_u64(m, a as! u64, b as! u64) as! i64;
}

// Branchless absolute value of signed 32-bit integer returning unsigned magnitude.
inline fn ct_abs_u32(x: i32) -> u32 {
    let mask = (x >> 31) as! u32;
    return ((x as! u32) + mask) ^ mask;
}

// Branchless absolute value of signed 64-bit integer returning unsigned magnitude.
inline fn ct_abs_u64(x: i64) -> u64 {
    let mask = (x >> 63) as! u64;
    return ((x as! u64) + mask) ^ mask;
}

// Branchless absolute value of signed 64-bit integer, saturating I64_MIN to I64_MAX.
inline fn ct_abs_i64(x: i64) -> i64 {
    let u = ct_abs_u64(x);
    let max_u = I64_MAX as! u64;
    return ct_min_u64(u, max_u) as! i64;
}

inline fn clamp_u32(val: u32, lo: u32, hi: u32) -> u32 {
    return ct_min_u32(ct_max_u32(val, lo), hi);
}

inline fn clamp_u64(val: u64, lo: u64, hi: u64) -> u64 {
    return ct_min_u64(ct_max_u64(val, lo), hi);
}

inline fn clamp_i64(val: i64, lo: i64, hi: i64) -> i64 {
    return ct_min_i64(ct_max_i64(val, lo), hi);
}

// ---- 3. Saturation & Checked Arithmetic -------------------------------------

inline fn add_sat_u32(a: u32, b: u32) -> u32 {
    let sum = a + b;
    let carry_mask = ct_mask_u32(ct_lt_u32(sum, a));
    return sum | carry_mask;
}

inline fn sub_sat_u32(a: u32, b: u32) -> u32 {
    let diff = a - b;
    let borrow_mask = ct_mask_u32(ct_lt_u32(a, b));
    return diff & (~borrow_mask);
}

inline fn add_sat_u64(a: u64, b: u64) -> u64 {
    let sum = a + b;
    let carry_mask = ct_mask_u64(ct_lt_u64(sum, a));
    return sum | carry_mask;
}

inline fn sub_sat_u64(a: u64, b: u64) -> u64 {
    let diff = a - b;
    let borrow_mask = ct_mask_u64(ct_lt_u64(a, b));
    return diff & (~borrow_mask);
}

inline fn mul_sat_u32(a: u32, b: u32) -> u32 {
    let prod = (a as u64) * b;
    let hi = (prod >> 32) as! u32;
    let lo = (prod & 0xFFFFFFFF) as! u32;
    let overflow_mask = ct_mask_u32(1 ^ ct_is_zero_u32(hi));
    return lo | overflow_mask;
}

inline fn mul_sat_u64(a: u64, b: u64) -> u64 {
    let lo, hi = mul_wide_u64(a, b);
    let overflow_mask = ct_mask_u64(1 ^ ct_is_zero_u64(hi));
    return lo | overflow_mask;
}

// Saturating left-shift for base * 2^attempt preventing CPU UB and wrap-around.
inline fn shl_sat_u64(base: u64, shift: u32) -> u64 {
    if base == 0 {
        return 0;
    }
    if shift >= 64 {
        return U64_MAX;
    }
    let shifted = base << shift;
    if shifted >> shift != base {
        return U64_MAX;
    }
    return shifted;
}

// Branchless signed saturating addition.
inline fn add_sat_i64(a: i64, b: i64) -> i64 {
    let ua = a as! u64;
    let ub = b as! u64;
    let usum = ua + ub;
    let ovf_bit = (((ua ^ usum) & (ub ^ usum)) >> 63) & 1;
    let ovf_mask = ct_mask_u64(ovf_bit);
    let sat_limit = 0x7FFFFFFFFFFFFFFF + (ua >> 63);
    return ct_select_u64(ovf_mask, sat_limit, usum) as! i64;
}

// Branchless signed saturating subtraction.
inline fn sub_sat_i64(a: i64, b: i64) -> i64 {
    let ua = a as! u64;
    let ub = b as! u64;
    let udiff = ua - ub;
    let ovf_bit = (((ua ^ ub) & (ua ^ udiff)) >> 63) & 1;
    let ovf_mask = ct_mask_u64(ovf_bit);
    let sat_limit = 0x7FFFFFFFFFFFFFFF + (ua >> 63);
    return ct_select_u64(ovf_mask, sat_limit, udiff) as! i64;
}

inline fn add_checked_u32(a: u32, b: u32) -> CheckedU32 {
    let sum = a + b;
    return CheckedU32 {
        value: sum,
        overflow: ct_lt_u32(sum, a) != 0,
    };
}

inline fn add_checked_u64(a: u64, b: u64) -> CheckedU64 {
    let sum = a + b;
    return CheckedU64 {
        value: sum,
        overflow: ct_lt_u64(sum, a) != 0,
    };
}

// Checked signed 64-bit multiplication without 128-bit types or signed UB.
inline fn mul_checked_i64(a: i64, b: i64) -> CheckedI64 {
    if a == 0 || b == 0 {
        return CheckedI64 { value: 0, overflow: false };
    }
    let abs_a = ct_abs_u64(a);
    let abs_b = ct_abs_u64(b);
    let lo, hi = mul_wide_u64(abs_a, abs_b);
    let sign_neg = (((a as! u64) ^ (b as! u64)) >> 63) & 1;
    let max_mag = 0x7FFFFFFFFFFFFFFF + sign_neg;
    let ovf = (hi != 0) || (lo > max_mag);
    let prod_val = ((a as! u64) * (b as! u64)) as! i64;
    return CheckedI64 {
        value: prod_val,
        overflow: ovf,
    };
}

// Converts seconds from RFC 9110 Retry-After header to milliseconds with saturation.
inline fn retry_after_sec_to_ms_sat(seconds: i64) -> i64 {
    let clamped_sec = ct_max_i64(seconds, 0) as! u64;
    let ms_u64 = mul_sat_u64(clamped_sec, 1000);
    let max_i64_u = I64_MAX as! u64;
    return ct_min_u64(ms_u64, max_i64_u) as! i64;
}

// ---- 4. Bit Twiddling & Network Byte Order ---------------------------------

inline fn rotl32(x: u32, r: u32) -> u32 {
    return (x << (r & 31)) | (x >> ((0 - r) & 31));
}

inline fn rotr32(x: u32, r: u32) -> u32 {
    return (x >> (r & 31)) | (x << ((0 - r) & 31));
}

inline fn rotl64(x: u64, r: u32) -> u64 {
    let sh = (r & 63) as u64;
    let inv = ((0 - r) & 63) as u64;
    return (x << sh) | (x >> inv);
}

inline fn rotr64(x: u64, r: u32) -> u64 {
    let sh = (r & 63) as u64;
    let inv = ((0 - r) & 63) as u64;
    return (x >> sh) | (x << inv);
}

inline fn is_pow2_u32(x: u32) -> bool {
    return (x != 0) && ((x & (x - 1)) == 0);
}

inline fn is_pow2_u64(x: u64) -> bool {
    return (x != 0) && ((x & (x - 1)) == 0);
}

inline fn next_pow2_u32(x: u32) -> u32 {
    if x <= 1 {
        return 1;
    }
    if x > 0x80000000 {
        return 0x80000000;
    }
    var v = x - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

inline fn next_pow2_u64(x: u64) -> u64 {
    if x <= 1 {
        return 1;
    }
    if x > 0x8000000000000000 {
        return 0x8000000000000000;
    }
    var v = x - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    return v + 1;
}

inline fn bswap16(x: u16) -> u16 {
    return (x << 8) | (x >> 8);
}

inline fn bswap32(x: u32) -> u32 {
    return ((x & 0x000000FF) << 24) |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0xFF000000) >> 24);
}

inline fn bswap64(x: u64) -> u64 {
    let hi = bswap32((x & 0xFFFFFFFF) as! u32) as u64;
    let lo = bswap32((x >> 32) as! u32) as u64;
    return (hi << 32) | lo;
}

// ---- 5. Euclidean Division & Remainder --------------------------------------

// Euclidean remainder in [0, |rhs|) preserving non-negative ring buffer indices.
inline fn rem_euclid_i64(lhs: i64, rhs: i64) -> i64 {
    if rhs == 0 {
        return 0;
    }
    if lhs == I64_MIN && rhs == -1 {
        return 0;
    }
    let r = lhs % rhs;
    let neg_mask = (r >> 63) as! u64;
    let abs_rhs = ct_abs_u64(rhs);
    return ((r as! u64) + (abs_rhs & neg_mask)) as! i64;
}

// Euclidean quotient satisfying lhs = rhs * div_euclid(lhs, rhs) + rem_euclid(lhs, rhs).
inline fn div_euclid_i64(lhs: i64, rhs: i64) -> i64 {
    if rhs == 0 {
        return 0;
    }
    if lhs == I64_MIN && rhs == -1 {
        return I64_MAX;
    }
    let q = lhs / rhs;
    let r = rem_euclid_i64(lhs, rhs);
    let lhs_neg_bit = ((lhs as! u64) >> 63) & 1;
    let rem_nz_bit = 1 ^ ct_is_zero_u64(r as! u64);
    let need_adj_mask = ct_mask_u64(lhs_neg_bit & rem_nz_bit);
    let rhs_neg_bit = ((rhs as! u64) >> 63) & 1;
    let adjust = ct_select_u64(ct_mask_u64(rhs_neg_bit), 1, U64_MAX);
    return ((q as! u64) + (adjust & need_adj_mask)) as! i64;
}

// Fast branchless modulo reduction for inputs in strict [-q, q - 1] interval.
inline fn fast_mod_reduce_i32(x: i32, q: i32) -> i32 {
    let r = x % q;
    return if r < 0 { r + q } else { r };
}

// ---- 6. PRNGs (WyRand v4.2, w1rand, xoroshiro64**) & Lemire Fast-Range -----

const WYP0_V42: u64 = 0x2d358dccaa6c78a5;
const WYP1_V42: u64 = 0x8bb84b93962eacc9;
const WYP2_V42: u64 = 0x4b33a62ed433d4a3;
const WYP3_V42: u64 = 0x4d5a2da51de1aa47;

// Non-bijective 128-bit mixing primitive wymum(a, b) = (hi ^ lo).
inline fn wymum(a: u64, b: u64) -> u64 {
    let lo, hi = mul_wide_u64(a, b);
    return hi ^ lo;
}

// Bijective seed scrambler with Stafford constants (SplitMix64).
inline fn splitmix64(state: u64&) -> u64 {
    state += 0x9E3779B97F4A7C15;
    var z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

// High-speed 64-bit pseudo-random number generator (WyRand v4.2 final).
struct WyRand {
    state: u64 = 0,
}

fn new_wyrand(seed: u64) -> WyRand {
    var s = seed;
    let init_state = splitmix64(s);
    return WyRand { state: init_state };
}

inline fn next_u64(rng: WyRand&) -> u64 {
    rng.state += WYP0_V42;
    return wymum(rng.state, rng.state ^ WYP1_V42);
}

inline fn next_u32(rng: WyRand&) -> u32 {
    return (next_u64(rng) >> 32) as! u32;
}

// Compact single-constant generator w1rand by Wang Yi.
inline fn w1rand_next(state: u64&) -> u64 {
    const C: u64 = 0xd07ebc63274654c7;
    state += C;
    return wymum(state, state ^ C);
}

// 32-bit generator Xoroshiro64** (triplet 26, 9, 13 with star-star scrambler 5, 5).
struct Xoroshiro64StarStar {
    s0: u32 = 0x9E3779BB,
    s1: u32 = 0x85EBCA77,
}

fn new_xoroshiro64_star_star(seed: u64) -> Xoroshiro64StarStar {
    var sm = seed;
    let w = splitmix64(sm);
    var lo = (w & 0xFFFFFFFF) as! u32;
    let hi = (w >> 32) as! u32;
    if lo == 0 && hi == 0 {
        lo = 0x9E3779BB;
    }
    return Xoroshiro64StarStar { s0: lo, s1: hi };
}

inline fn new_xoroshiro64(seed: u64) -> Xoroshiro64StarStar {
    return new_xoroshiro64_star_star(seed);
}

inline fn next_u32(rng: Xoroshiro64StarStar&) -> u32 {
    let s0 = rng.s0;
    var s1 = rng.s1;
    let result = rotl32(s0 * 0x9E3779BB, 5) * 5;

    s1 ^= s0;
    rng.s0 = rotl32(s0, 26) ^ s1 ^ (s1 << 9);
    rng.s1 = rotl32(s1, 13);
    return result;
}

// Variant Xoroshiro64* for fast floating point generation.
inline fn next_star_u32(rng: Xoroshiro64StarStar&) -> u32 {
    let s0 = rng.s0;
    var s1 = rng.s1;
    let result = s0 * 0x9E3779BB;

    s1 ^= s0;
    rng.s0 = rotl32(s0, 26) ^ s1 ^ (s1 << 9);
    rng.s1 = rotl32(s1, 13);
    return result;
}

// Branchless biased Lemire fast-range mapping for interval [0, range).
inline fn fast_range_biased_u32(random_word: u32, range: u32) -> u32 {
    let prod = (random_word as u64) * range;
    return (prod >> 32) as! u32;
}

// Branchless biased Lemire fast-range mapping for interval [0, range).
inline fn fast_range_biased_u64(random_word: u64, range: u64) -> u64 {
    let _, hi = mul_wide_u64(random_word, range);
    return hi;
}

// Unbiased Lemire fast-range mapping with rejection sampling for sensitive intervals.
fn fast_range_unbiased_u32(rng: WyRand&, range: u32) -> u32 {
    if range <= 1 {
        return 0;
    }
    var x = next_u32(rng);
    var m = (x as u64) * range;
    var l = (m & 0xFFFFFFFF) as! u32;
    if l < range {
        let threshold = (0 - range) % range;
        while l < threshold {
            x = next_u32(rng);
            m = (x as u64) * range;
            l = (m & 0xFFFFFFFF) as! u32;
        }
    }
    return (m >> 32) as! u32;
}

// ---- 7. Backoff & Jitter Strategies (Happy Eyeballs / AWS) -----------------

inline fn backoff_full_jitter_ms(rng: WyRand&, base_ms: u64, cap_ms: u64, attempt: u32) -> u64 {
    let exp_bound = ct_min_u64(cap_ms, shl_sat_u64(base_ms, attempt));
    let span = add_sat_u64(exp_bound, 1);
    return fast_range_biased_u64(next_u64(rng), span);
}

inline fn backoff_equal_jitter_ms(rng: WyRand&, base_ms: u64, cap_ms: u64, attempt: u32) -> u64 {
    let temp = ct_min_u64(cap_ms, shl_sat_u64(base_ms, attempt));
    let half = temp >> 1;
    let span = add_sat_u64(temp - half, 1);
    let rand_part = fast_range_biased_u64(next_u64(rng), span);
    return add_sat_u64(half, rand_part);
}

// Clamping-flaw-free Decorrelated Jitter: moves min(cap, ...) inside upper span before PRNG.
inline fn backoff_decorrelated_jitter_ms(rng: WyRand&, base_ms: u64, cap_ms: u64, prev_sleep_ms: u64) -> u64 {
    let effective_prev = ct_max_u64(prev_sleep_ms, base_ms);
    let upper = ct_min_u64(cap_ms, mul_sat_u64(effective_prev, 3));
    let span = add_sat_u64(sub_sat_u64(upper, base_ms), 1);
    return add_sat_u64(base_ms, fast_range_biased_u64(next_u64(rng), span));
}

// Clamps Happy Eyeballs connection attempt delay according to RFC 8305 / HEv3 rules.
inline fn clamp_happy_eyeballs_delay_ms(candidate_delay_ms: i64, enforce_recommended_min: bool = false) -> i64 {
    let floor_ms = if enforce_recommended_min {
        HE_RECOMMENDED_MIN_DELAY_MS
    } else {
        HE_ABSOLUTE_MIN_DELAY_MS
    };
    return clamp_i64(candidate_delay_ms, floor_ms, HE_MAX_ATTEMPT_DELAY_MS);
}

// ---- 8. Jacobson EWMA RTT Estimator (RFC 6298 / RFC 9002 Errata 7539) ------

struct JacobsonRttEstimator {
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    latest_rtt_us: u64 = 0,
    srtt_scaled: u64 = 0,   // 8 * smoothed_rtt (Q61.3)
    rttvar_scaled: u64 = 0, // 4 * rttvar       (Q62.2)
    has_sample: bool = false,
}

fn new_jacobson_rtt_estimator(initial_rtt_us: u64 = QUIC_INITIAL_RTT_US) -> JacobsonRttEstimator {
    return JacobsonRttEstimator {
        min_rtt_us: 0xFFFFFFFFFFFFFFFF,
        latest_rtt_us: 0,
        srtt_scaled: initial_rtt_us << 3,
        rttvar_scaled: initial_rtt_us << 1, // 4 * (initial_rtt / 2)
        has_sample: false,
    };
}

inline fn smoothed_rtt_us(est: const JacobsonRttEstimator&) -> u64 {
    return est.srtt_scaled >> 3;
}

inline fn rttvar_us(est: const JacobsonRttEstimator&) -> u64 {
    return est.rttvar_scaled >> 2;
}

// Updates RTT state with incoming sample adhering to Errata 7539 (rttvar updated before srtt).
fn on_rtt_sample(
    est: JacobsonRttEstimator&,
    latest_rtt_us: u64,
    ack_delay_us: u64,
    max_ack_delay_us: u64,
    handshake_confirmed: bool
) {
    if latest_rtt_us == 0 {
        return;
    }
    est.latest_rtt_us = latest_rtt_us;

    if !est.has_sample {
        est.min_rtt_us = latest_rtt_us;
        est.srtt_scaled = latest_rtt_us << 3;
        est.rttvar_scaled = latest_rtt_us << 1;
        est.has_sample = true;
        return;
    }

    // 1. Update min_rtt
    est.min_rtt_us = ct_min_u64(est.min_rtt_us, latest_rtt_us);

    // 2. Bound ack_delay after handshake confirmation
    let effective_ack_delay = if handshake_confirmed {
        ct_min_u64(ack_delay_us, max_ack_delay_us)
    } else {
        ack_delay_us
    };

    // 3. Defensive ack_delay subtraction (never allow adjusted_rtt < min_rtt)
    let min_plus_delay = add_sat_u64(est.min_rtt_us, effective_ack_delay);
    let can_subtract_mask = ct_mask_u64(1 ^ ct_lt_u64(latest_rtt_us, min_plus_delay));
    let adjusted_rtt = ct_select_u64(
        can_subtract_mask,
        latest_rtt_us - effective_ack_delay,
        latest_rtt_us
    );

    // 4. Calculate deviation against prior smoothed_rtt (RFC 6298 / Errata ID 7539)
    let prior_srtt = est.srtt_scaled >> 3;
    let abs_diff = ct_select_u64(
        ct_mask_u64(ct_lt_u64(prior_srtt, adjusted_rtt)),
        adjusted_rtt - prior_srtt,
        prior_srtt - adjusted_rtt
    );

    // 5. Update rttvar accumulator: V4 = V4 - (V4 >> 2) + |diff|
    est.rttvar_scaled = (est.rttvar_scaled - (est.rttvar_scaled >> 2)) + abs_diff;

    // 6. Update srtt accumulator: S8 = S8 - prior_srtt + adjusted_rtt
    est.srtt_scaled = (est.srtt_scaled - prior_srtt) + adjusted_rtt;
}

// Probe Timeout (PTO) timer computation according to RFC 9002 Section 6.2.1.
inline fn probe_timeout_us(est: const JacobsonRttEstimator&, max_ack_delay_us: u64) -> u64 {
    let srtt = est.srtt_scaled >> 3;
    let var_term = ct_max_u64(est.rttvar_scaled, QUIC_TIMER_GRANULARITY_US);
    return add_sat_u64(add_sat_u64(srtt, var_term), max_ack_delay_us);
}

// Packet loss time threshold (RFC 9002 Section 6.1.2): 9/8 * max(smoothed_rtt, latest_rtt).
inline fn loss_time_threshold_us(est: const JacobsonRttEstimator&) -> u64 {
    let base = ct_max_u64(est.srtt_scaled >> 3, est.latest_rtt_us);
    return add_sat_u64(base, base >> 3);
}

// ---- 9. Non-Cryptographic Fast Hashing (FNV-1a, xxHash32, wyhash v4.2) ------

const FNV1A_32_OFFSET: u32 = 0x811C9DC5;
const FNV1A_32_PRIME: u32  = 0x01000193;
const FNV1A_64_OFFSET: u64 = 0xCBF29CE484222325;
const FNV1A_64_PRIME: u64  = 0x00000100000001B3;

inline fn fnv1a_32(data: const u8[:]) -> u32 {
    var h: u32 = FNV1A_32_OFFSET;
    for i in data.len {
        h ^= data[i];
        h *= FNV1A_32_PRIME;
    }
    return h;
}

inline fn fnv1a_64(data: const u8[:]) -> u64 {
    var h: u64 = FNV1A_64_OFFSET;
    for i in data.len {
        h ^= data[i];
        h *= FNV1A_64_PRIME;
    }
    return h;
}

const XXH_PRIME32_1: u32 = 0x9E3779B1;
const XXH_PRIME32_2: u32 = 0x85EBCA77;
const XXH_PRIME32_3: u32 = 0xC2B2AE3D;
const XXH_PRIME32_4: u32 = 0x27D4EB2F;
const XXH_PRIME32_5: u32 = 0x165667B1;

inline fn read_le_u32(data: const u8[:], offset: i64) -> u32 {
    return (data[offset]) |
           ((data[offset + 1] as u32) << 8) |
           ((data[offset + 2] as u32) << 16) |
           ((data[offset + 3] as u32) << 24);
}

inline fn read_le_u64(data: const u8[:], offset: i64) -> u64 {
    return (read_le_u32(data, offset)) |
           ((read_le_u32(data, offset + 4) as u64) << 32);
}

inline fn xxh32_round(acc: u32, input: u32) -> u32 {
    var a = acc + input * XXH_PRIME32_2;
    a = rotl32(a, 13);
    return a * XXH_PRIME32_1;
}

inline fn xxh32_avalanche(h_in: u32) -> u32 {
    var h = h_in;
    h ^= h >> 15;
    h *= XXH_PRIME32_2;
    h ^= h >> 13;
    h *= XXH_PRIME32_3;
    h ^= h >> 16;
    return h;
}

fn xxhash32(data: const u8[:], seed: u32 = 0) -> u32 {
    let len = data.len;
    var offset = 0;
    var h32: u32 = 0;

    if len >= 16 {
        var v1 = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
        var v2 = seed + XXH_PRIME32_2;
        var v3 = seed;
        var v4 = seed - XXH_PRIME32_1;

        let limit = len - 16;
        while offset <= limit {
            v1 = xxh32_round(v1, read_le_u32(data, offset));
            v2 = xxh32_round(v2, read_le_u32(data, offset + 4));
            v3 = xxh32_round(v3, read_le_u32(data, offset + 8));
            v4 = xxh32_round(v4, read_le_u32(data, offset + 12));
            offset += 16;
        }
        h32 = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18);
    } else {
        h32 = seed + XXH_PRIME32_5;
    }

    h32 += len as u32;

    while offset + 4 <= len {
        h32 += read_le_u32(data, offset) * XXH_PRIME32_3;
        h32 = rotl32(h32, 17) * XXH_PRIME32_4;
        offset += 4;
    }

    while offset < len {
        h32 += data[offset] * XXH_PRIME32_5;
        h32 = rotl32(h32, 11) * XXH_PRIME32_1;
        offset++;
    }

    return xxh32_avalanche(h32);
}

inline fn wy_read_small(data: const u8[:], len: i64) -> u64 {
    return ((data[0] as u64) << 16) |
           ((data[len >> 1] as u64) << 8) |
           data[len - 1];
}

fn wyhash64_with_secret(data: const u8[:], seed_in: u64, secret: const u64[4]&) -> u64 {
    let len = data.len;
    var seed = seed_in ^ wymum(seed_in ^ secret[0], secret[1]);
    var a: u64 = 0;
    var b: u64 = 0;

    if len <= 16 {
        if len >= 4 {
            let half = (len >> 3) << 2;
            a = ((read_le_u32(data, 0) as u64) << 32) | read_le_u32(data, half);
            b = ((read_le_u32(data, len - 4) as u64) << 32) | read_le_u32(data, len - 4 - half);
        } else if len > 0 {
            a = wy_read_small(data, len);
            b = 0;
        } else {
            a = 0;
            b = 0;
        }
    } else {
        var i = len;
        var p = 0;
        if i > 48 {
            var see1 = seed;
            var see2 = seed;
            while i > 48 {
                seed = wymum(read_le_u64(data, p) ^ secret[1], read_le_u64(data, p + 8) ^ seed);
                see1 = wymum(read_le_u64(data, p + 16) ^ secret[2], read_le_u64(data, p + 24) ^ see1);
                see2 = wymum(read_le_u64(data, p + 32) ^ secret[3], read_le_u64(data, p + 40) ^ see2);
                p += 48;
                i -= 48;
            }
            seed ^= see1 ^ see2;
        }
        while i > 16 {
            seed = wymum(read_le_u64(data, p) ^ secret[1], read_le_u64(data, p + 8) ^ seed);
            i -= 16;
            p += 16;
        }
        a = read_le_u64(data, len - 16);
        b = read_le_u64(data, len - 8);
    }

    a ^= secret[1];
    b ^= seed;
    let lo, hi = mul_wide_u64(a, b);
    return wymum(lo ^ secret[0] ^ (len as u64), hi ^ secret[1]);
}

inline fn wyhash64(data: const u8[:], seed: u64 = 0) -> u64 {
    let default_secret: u64[4] = [WYP0_V42, WYP1_V42, WYP2_V42, WYP3_V42];
    return wyhash64_with_secret(data, seed, default_secret);
}

// Non-commutative 64-bit hash combiner based on wymum for composite socket keys.
inline fn hash_combine_u64(h1: u64, h2: u64) -> u64 {
    return wymum(h1 ^ WYP0_V42, h2 ^ WYP1_V42);
}

// Non-commutative 32-bit hash combiner based on xxHash round.
inline fn hash_combine_u32(h1: u32, h2: u32) -> u32 {
    return xxh32_avalanche(xxh32_round(h1 ^ XXH_PRIME32_5, h2));
}

// ---- 10. Constant-Time SOCKS5 Frame Length Validation (RFC 1928) ------------

// Branchless expected frame length calculation for SOCKS5 request/reply frames.
// Returns 0 if version is not 0x05 or ATYP is unrecognized, otherwise returns expected wire length.
fn socks5_expected_frame_len_ct(buf: const u8[:]) -> u32 {
    if buf.len < 5 {
        return 0;
    }
    let ver = buf[0] as u32;
    let atyp = buf[3] as u32;
    let domain_len = buf[4] as u32;

    let is_v5_mask = ct_mask_u32(ct_eq_u32(ver, 0x05));
    let m_ipv4   = ct_mask_u32(ct_eq_u32(atyp, 0x01));
    let m_domain = ct_mask_u32(ct_eq_u32(atyp, 0x03));
    let m_ipv6   = ct_mask_u32(ct_eq_u32(atyp, 0x04));

    // Domain name must contain 1..255 characters
    let valid_domain_mask = m_domain & (~ct_mask_u32(ct_is_zero_u32(domain_len)));

    let len_ipv4: u32   = 10;                 // 4 header + 4 IPv4 + 2 port
    let len_domain: u32 = 7 + domain_len;     // 4 header + 1 len + domain + 2 port
    let len_ipv6: u32   = 22;                 // 4 header + 16 IPv6 + 2 port

    let selected_len = (m_ipv4 & len_ipv4) |
                       (valid_domain_mask & len_domain) |
                       (m_ipv6 & len_ipv6);

    return selected_len & is_v5_mask;
}
