// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap bitmask and multi-word bitset primitives for flag words (u32/u64) and u64[:] bitsets.
namespace core;

import std;

// ---- 32-bit flag-word helpers ----------------------------------------------

// Sets all bits in `flag` on `mask`.
inline fn set_flag_u32(mask: u32&, flag: u32) {
    mask |= flag;
}

// Clears all bits in `flag` from `mask`.
inline fn clear_flag_u32(mask: u32&, flag: u32) {
    mask &= ~flag;
}

// Toggles all bits in `flag` on `mask`.
inline fn toggle_flag_u32(mask: u32&, flag: u32) {
    mask ^= flag;
}

// Extracts and clears the lowest set bit index (0..31) in `mask`.
//
// Example:
//   mask = 0b1010 -> returns (1, true), mask = 0b1000
inline fn pop_lowest_bit_u32(mask: u32&) -> u32, bool {
    guard mask != 0 else { return 0, false; }
    let idx = ctz(mask) as u32;
    mask &= sub_sat_u64(mask, 1) as u32;
    return idx, true;
}

// ---- 64-bit flag-word & bit-index helpers ----------------------------------

// Returns true if any bit in `flag` is set in `mask`.
inline fn has_flag_u64(mask: u64, flag: u64) -> bool {
    return (mask & flag) != 0;
}

// Returns true if every bit in `flags` is set in `mask`.
inline fn has_all_flags_u64(mask: u64, flags: u64) -> bool {
    return (mask & flags) == flags;
}

// Sets all bits in `flag` on `mask`.
inline fn set_flag_u64(mask: u64&, flag: u64) {
    mask |= flag;
}

// Clears all bits in `flag` from `mask`.
inline fn clear_flag_u64(mask: u64&, flag: u64) {
    mask &= ~flag;
}

// Toggles all bits in `flag` on `mask`.
inline fn toggle_flag_u64(mask: u64&, flag: u64) {
    mask ^= flag;
}

// Returns true if bit `bit_idx` (0..63) is set in `mask`. Out-of-range returns false.
inline fn test_bit_u64(mask: u64, bit_idx: u32) -> bool {
    guard bit_idx < 64 else { return false; }
    return (mask & shl_sat_u64(1, bit_idx)) != 0;
}

// Sets bit `bit_idx` (0..63) in `mask`. Out-of-range is a no-op.
inline fn set_bit_u64(mask: u64&, bit_idx: u32) {
    guard bit_idx < 64 else { return; }
    mask |= shl_sat_u64(1, bit_idx);
}

// Clears bit `bit_idx` (0..63) in `mask`. Out-of-range is a no-op.
inline fn clear_bit_u64(mask: u64&, bit_idx: u32) {
    guard bit_idx < 64 else { return; }
    mask &= ~shl_sat_u64(1, bit_idx);
}

// Extracts and clears the lowest set bit index (0..63) in `mask`.
//
// Example:
//   mask = 0x14 -> returns (2, true), mask = 0x10
inline fn pop_lowest_bit_u64(mask: u64&) -> u32, bool {
    guard mask != 0 else { return 0, false; }
    let idx = ctz(mask) as u32;
    mask &= sub_sat_u64(mask, 1);
    return idx, true;
}

// ---- multi-word zero-heap bitset over u64[:] -------------------------------

// Returns true if `bit` is set in `words`. Out-of-range returns false.
fn bitset_test(words: const u64[:], bit: u64) -> bool {
    let word_idx = (bit >> 6) as i64;
    guard word_idx >= 0 && word_idx < words.len else { return false; }
    return (words[word_idx] & shl_sat_u64(1, (bit & 63) as u32)) != 0;
}

// Sets `bit` in `words`. Returns false if `bit` exceeds `words.len * 64`.
fn bitset_set(words: u64[:], bit: u64) -> bool {
    let word_idx = (bit >> 6) as i64;
    guard word_idx >= 0 && word_idx < words.len else { return false; }
    words[word_idx] |= shl_sat_u64(1, (bit & 63) as u32);
    return true;
}

// Clears `bit` in `words`. Returns false if `bit` exceeds `words.len * 64`.
fn bitset_clear(words: u64[:], bit: u64) -> bool {
    let word_idx = (bit >> 6) as i64;
    guard word_idx >= 0 && word_idx < words.len else { return false; }
    words[word_idx] &= ~shl_sat_u64(1, (bit & 63) as u32);
    return true;
}

// Finds the first set bit at or after `from_bit`. Returns (bit_idx, true) or (0, false).
//
// Example:
//   words = [0, 0x04], from_bit = 64 -> returns (66, true)
fn bitset_next_set(words: const u64[:], from_bit: u64) -> u64, bool {
    var word_idx = (from_bit >> 6) as i64;
    guard word_idx >= 0 && word_idx < words.len else { return 0, false; }

    let low_mask = sub_sat_u64(shl_sat_u64(1, (from_bit & 63) as u32), 1);
    var w = words[word_idx] & (~low_mask);
    while word_idx < words.len {
        if w != 0 {
            let base, _ = mul_wide_u64(word_idx as u64, 64);
            return base | (ctz(w) as u64), true;
        }
        word_idx = add_sat_i64(word_idx, 1);
        if word_idx < words.len {
            w = words[word_idx];
        }
    }
    return 0, false;
}

// Returns true if any bit is set in `words`.
fn bitset_any(words: const u64[:]) -> bool {
    for w in words {
        if w != 0 {
            return true;
        }
    }
    return false;
}

// Clears all bits in `words` to zero.
fn bitset_clear_all(words: u64[:]) {
    for &w in words {
        w = 0;
    }
}

// Returns total number of set bits across all words in `words`.
fn bitset_popcount(words: const u64[:]) -> u64 {
    var total: u64 = 0;
    for w in words {
        total = add_sat_u64(total, popcount(w) as u64);
    }
    return total;
}
