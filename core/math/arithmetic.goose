// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Saturating arithmetic, checked arithmetic, 128-bit multiplication, and Euclidean division.
namespace core;

import std;
import core.math.ct;

struct CheckedU32 {
    value:    u32  = 0,
    overflow: bool = false,
}

struct CheckedU64 {
    value:    u64  = 0,
    overflow: bool = false,
}

struct CheckedI64 {
    value:    i64  = 0,
    overflow: bool = false,
}

extern fn mulhi_u64(a: u64, b: u64) -> u64 = "wing_mulhi_u64";

// 64x64 -> 128-bit unsigned expanding multiplication returning (lo, hi).
// Executed in a single hardware instruction (mulq on x86-64, umulh on ARM64).
inline fn mul_wide_u64(a: u64, b: u64) -> u64, u64 {
    let lo = a * b;
    let hi = mulhi_u64(a, b);
    return lo, hi;
}

// Non-bijective 128-bit mixing primitive wymum(a, b) = (hi ^ lo).
inline fn wymum(a: u64, b: u64) -> u64 {
    let lo, hi = mul_wide_u64(a, b);
    return hi ^ lo;
}

// Branchless unsigned saturating addition (32-bit).
inline fn add_sat_u32(a: u32, b: u32) -> u32 {
    let sum = a + b;
    let overflow_mask = ct_mask_u32(ct_lt_u32(sum, a));
    return sum | overflow_mask;
}

// Branchless unsigned saturating addition (64-bit).
inline fn add_sat_u64(a: u64, b: u64) -> u64 {
    let sum = a + b;
    let overflow_mask = ct_mask_u64(ct_lt_u64(sum, a));
    return sum | overflow_mask;
}

// Branchless unsigned saturating subtraction (32-bit).
inline fn sub_sat_u32(a: u32, b: u32) -> u32 {
    let diff = a - b;
    let borrow_mask = ct_mask_u32(ct_lt_u32(a, b));
    return diff & (~borrow_mask);
}

// Branchless unsigned saturating subtraction (64-bit).
inline fn sub_sat_u64(a: u64, b: u64) -> u64 {
    let diff = a - b;
    let borrow_mask = ct_mask_u64(ct_lt_u64(a, b));
    return diff & (~borrow_mask);
}

// Branchless unsigned saturating multiplication (32-bit).
inline fn mul_sat_u32(a: u32, b: u32) -> u32 {
    let prod = (a as u64) * b;
    let hi = (prod >> 32) as! u32;
    let lo = (prod & 0xFFFFFFFF) as! u32;
    let overflow_mask = ct_mask_u32(1 ^ ct_is_zero_u32(hi));
    return lo | overflow_mask;
}

// Branchless unsigned saturating multiplication (64-bit).
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
    if (shifted >> shift) != base {
        return U64_MAX;
    }
    return shifted;
}

// Branchless signed saturating addition (64-bit).
inline fn add_sat_i64(a: i64, b: i64) -> i64 {
    let ua = a as! u64;
    let ub = b as! u64;
    let usum = ua + ub;
    let ovf_bit = (((ua ^ usum) & (ub ^ usum)) >> 63) & 1;
    let ovf_mask = ct_mask_u64(ovf_bit);
    let sat_val = ct_select_u64(ct_mask_u64((ua >> 63) & 1), I64_MIN as! u64, I64_MAX as! u64);
    return ct_select_u64(ovf_mask, sat_val, usum) as! i64;
}

// Branchless signed saturating subtraction (64-bit).
inline fn sub_sat_i64(a: i64, b: i64) -> i64 {
    let ua = a as! u64;
    let ub = b as! u64;
    let udiff = ua - ub;
    let ovf_bit = (((ua ^ ub) & (ua ^ udiff)) >> 63) & 1;
    let ovf_mask = ct_mask_u64(ovf_bit);
    let sat_val = ct_select_u64(ct_mask_u64((ua >> 63) & 1), I64_MIN as! u64, I64_MAX as! u64);
    return ct_select_u64(ovf_mask, sat_val, udiff) as! i64;
}

// Checked unsigned 32-bit addition.
inline fn add_checked_u32(a: u32, b: u32) -> CheckedU32 {
    let sum = a + b;
    return CheckedU32 {
        value:    sum,
        overflow: ct_lt_u32(sum, a) == 1,
    };
}

// Checked unsigned 64-bit addition.
inline fn add_checked_u64(a: u64, b: u64) -> CheckedU64 {
    let sum = a + b;
    return CheckedU64 {
        value:    sum,
        overflow: ct_lt_u64(sum, a) == 1,
    };
}

// Checked signed 64-bit multiplication.
fn mul_checked_i64(a: i64, b: i64) -> CheckedI64 {
    if a == 0 || b == 0 {
        return CheckedI64 { value: 0, overflow: false };
    }
    let s_a = ct_abs_i64(a) as! u64;
    let s_b = ct_abs_i64(b) as! u64;
    let lo, hi = mul_wide_u64(s_a, s_b);

    let sign_bit = (((a as! u64) ^ (b as! u64)) >> 63) & 1;
    let limit_u64 = ct_select_u64(ct_mask_u64(sign_bit), 0x8000000000000000, 0x7FFFFFFFFFFFFFFF);
    if hi != 0 || lo > limit_u64 {
        return CheckedI64 { value: 0, overflow: true };
    }

    let prod_u64 = if sign_bit == 1 { 0 - lo } else { lo };
    return CheckedI64 {
        value:    prod_u64 as! i64,
        overflow: false,
    };
}

// Signed saturating multiplication (64-bit).
inline fn mul_sat_i64(a: i64, b: i64) -> i64 {
    let res = mul_checked_i64(a, b);
    if !res.overflow {
        return res.value;
    }
    let sign_bit = (((a as! u64) ^ (b as! u64)) >> 63) & 1;
    return if sign_bit == 1 { I64_MIN } else { I64_MAX };
}

// Unsigned 64-bit quotient and remainder returning (0, n) when d == 0.
fn div_rem_u64(n: u64, d: u64) -> u64, u64 {
    guard d > 0 else { return 0, n; }
    return n / d, n % d;
}

inline fn safe_euclid_divisor(lhs: i64, rhs: i64) -> i64 {
    if rhs == 0 { return 1; }
    if lhs == I64_MIN && rhs == sub_sat_i64(0, 1) { return 1; }
    return rhs;
}

// Computes Euclidean remainder: 0 <= r < |rhs| for all inputs (0 when rhs == 0).
inline fn rem_euclid_i64(lhs: i64, rhs: i64) -> i64 {
    return lhs % safe_euclid_divisor(lhs, rhs);
}

// Computes Euclidean division quotient satisfying lhs = q * rhs + rem_euclid_i64(lhs, rhs).
inline fn div_euclid_i64(lhs: i64, rhs: i64) -> i64 {
    guard rhs != 0 else { return 0; }
    if lhs == I64_MIN && rhs == sub_sat_i64(0, 1) { return I64_MAX; }
    let q = lhs / safe_euclid_divisor(lhs, rhs);
    if lhs < 0 && rem_euclid_i64(lhs, rhs) != 0 {
        return if rhs > 0 { sub_sat_i64(q, 1) } else { add_sat_i64(q, 1) };
    }
    return q;
}

// Fast modulo reduction for ring buffer indices.
inline fn fast_mod_reduce_i32(x: i32, q: i32) -> i32 {
    guard q > 0 else { return 0; }
    return x % q;
}
