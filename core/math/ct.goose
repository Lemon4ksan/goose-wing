// Constant-time branchless arithmetic, bit masking, and bounds clamping.
// Protects against timing side-channel attacks and CPU branch mispredictions.
namespace core;

import std;

// Fundamental integer boundary constants
const U32_MAX: u32 = 0xFFFFFFFF;
const U64_MAX: u64 = 0xFFFFFFFFFFFFFFFF;
const I32_MIN: i32 = -2147483647 - 1;
const I32_MAX: i32 = 2147483647;
const I64_MIN: i64 = -9223372036854775807 - 1;
const I64_MAX: i64 = 9223372036854775807;

// Returns 1 if x == 0, 0 otherwise (branchless 32-bit).
inline fn ct_is_zero_u32(x: u32) -> u32 {
    return 1 ^ (((x | (0 - x)) >> 31) & 1);
}

// Returns 1 if x == 0, 0 otherwise (branchless 64-bit).
inline fn ct_is_zero_u64(x: u64) -> u64 {
    return 1 ^ (((x | (0 - x)) >> 63) & 1);
}

// Returns 1 if a == b, 0 otherwise (branchless 32-bit).
inline fn ct_eq_u32(a: u32, b: u32) -> u32 {
    let diff = a ^ b;
    return 1 ^ (((diff | (0 - diff)) >> 31) & 1);
}

// Returns 1 if a == b, 0 otherwise (branchless 64-bit).
inline fn ct_eq_u64(a: u64, b: u64) -> u64 {
    let diff = a ^ b;
    return 1 ^ (((diff | (0 - diff)) >> 63) & 1);
}

// Returns 1 if a < b, 0 otherwise (branchless unsigned 32-bit comparison).
inline fn ct_lt_u32(a: u32, b: u32) -> u32 {
    let diff = a - b;
    let bit = ((~a & b) | ((~a ^ b) & diff)) >> 31;
    return bit & 1;
}

// Returns 1 if a < b, 0 otherwise (branchless unsigned 64-bit comparison).
inline fn ct_lt_u64(a: u64, b: u64) -> u64 {
    let diff = a - b;
    let bit = ((~a & b) | ((~a ^ b) & diff)) >> 63;
    return bit & 1;
}

// Returns 1 if a > b, 0 otherwise (branchless unsigned 32-bit comparison).
inline fn ct_gt_u32(a: u32, b: u32) -> u32 {
    return ct_lt_u32(b, a);
}

// Returns 1 if a > b, 0 otherwise (branchless unsigned 64-bit comparison).
inline fn ct_gt_u64(a: u64, b: u64) -> u64 {
    return ct_lt_u64(b, a);
}

// Creates an all-ones mask (0xFFFFFFFF) if bit == 1, or 0 if bit == 0.
inline fn ct_mask_u32(bit: u32) -> u32 {
    return 0 - (bit & 1);
}

// Creates an all-ones mask (0xFFFFFFFFFFFFFFFF) if bit == 1, or 0 if bit == 0.
inline fn ct_mask_u64(bit: u64) -> u64 {
    return 0 - (bit & 1);
}

// Constant-time multiplexer: returns if_true when mask is ~0, if_false when mask is 0.
inline fn ct_select_u32(mask: u32, if_true: u32, if_false: u32) -> u32 {
    return (if_false & (~mask)) | (if_true & mask);
}

// Constant-time multiplexer: returns if_true when mask is ~0, if_false when mask is 0.
inline fn ct_select_u64(mask: u64, if_true: u64, if_false: u64) -> u64 {
    return (if_false & (~mask)) | (if_true & mask);
}

// Branchless unsigned minimum (32-bit).
inline fn ct_min_u32(a: u32, b: u32) -> u32 {
    let mask = ct_mask_u32(ct_lt_u32(a, b));
    return ct_select_u32(mask, a, b);
}

// Branchless unsigned maximum (32-bit).
inline fn ct_max_u32(a: u32, b: u32) -> u32 {
    let mask = ct_mask_u32(ct_lt_u32(b, a));
    return ct_select_u32(mask, a, b);
}

// Branchless unsigned minimum (64-bit).
inline fn ct_min_u64(a: u64, b: u64) -> u64 {
    let mask = ct_mask_u64(ct_lt_u64(a, b));
    return ct_select_u64(mask, a, b);
}

// Branchless unsigned maximum (64-bit).
inline fn ct_max_u64(a: u64, b: u64) -> u64 {
    let mask = ct_mask_u64(ct_lt_u64(b, a));
    return ct_select_u64(mask, a, b);
}

// Branchless signed minimum (64-bit).
inline fn ct_min_i64(a: i64, b: i64) -> i64 {
    let diff = a - b;
    let s = ((diff ^ ((a ^ b) & (diff ^ a))) >> 63) & 1;
    let mask = 0 - s;
    let ua = a as! u64;
    let ub = b as! u64;
    return ((ub & (~mask as! u64)) | (ua & (mask as! u64))) as! i64;
}

// Branchless signed maximum (64-bit).
inline fn ct_max_i64(a: i64, b: i64) -> i64 {
    let diff = b - a;
    let s = ((diff ^ ((a ^ b) & (diff ^ b))) >> 63) & 1;
    let mask = 0 - s;
    let ua = a as! u64;
    let ub = b as! u64;
    return ((ub & (~mask as! u64)) | (ua & (mask as! u64))) as! i64;
}

// Branchless absolute value for i64 without branching.
inline fn ct_abs_i64(x: i64) -> i64 {
    let mask = x >> 63;
    return (x ^ mask) - mask;
}

// Branchless signed minimum (32-bit).
inline fn ct_min_i32(a: i32, b: i32) -> i32 {
    let diff = a - b;
    let s = ((diff ^ ((a ^ b) & (diff ^ a))) >> 31) & 1;
    let mask = 0 - s;
    let ua = a as! u32;
    let ub = b as! u32;
    return ((ub & (~mask as! u32)) | (ua & (mask as! u32))) as! i32;
}

// Branchless signed maximum (32-bit).
inline fn ct_max_i32(a: i32, b: i32) -> i32 {
    let diff = b - a;
    let s = ((diff ^ ((a ^ b) & (diff ^ b))) >> 31) & 1;
    let mask = 0 - s;
    let ua = a as! u32;
    let ub = b as! u32;
    return ((ub & (~mask as! u32)) | (ua & (mask as! u32))) as! i32;
}

// Clamps signed 32-bit value into [low, high].
inline fn clamp_i32(val: i32, low: i32, high: i32) -> i32 {
    return ct_min_i32(ct_max_i32(val, low), high);
}

// Clamps unsigned 32-bit value into [low, high].
inline fn clamp_u32(val: u32, low: u32, high: u32) -> u32 {
    return ct_min_u32(ct_max_u32(val, low), high);
}

// Clamps unsigned 64-bit value into [low, high].
inline fn clamp_u64(val: u64, low: u64, high: u64) -> u64 {
    return ct_min_u64(ct_max_u64(val, low), high);
}

// Clamps signed 64-bit value into [low, high].
inline fn clamp_i64(val: i64, low: i64, high: i64) -> i64 {
    return ct_min_i64(ct_max_i64(val, low), high);
}
