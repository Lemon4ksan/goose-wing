// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public Suffix List rules, eTLD+1 extraction, and domain/path matching (RFC 6265 Section 5.1).
namespace wing;

import std;
import core from "..";
import .constants;

// ---- public suffix data structures and enumerations ------------------------

// Chromium / libpsl DAFSA (Deterministic Acyclic Finite State Automaton) bitmask flags
// and BNF byte-range boundaries (vendor/libpsl/src/psl-make-dafsa & lookup_string_in_fixed_set.c).
const PSL_DAFSA_NOT_FOUND:      i32 = -1;
const PSL_DAFSA_FLAG_EXCEPTION: i32 = 1;
const PSL_DAFSA_FLAG_WILDCARD:  i32 = 2;
const PSL_DAFSA_FLAG_PRIVATE:   i32 = 8;

const DAFSA_KEY_MIN_CHAR:       u8 = 0x1F;
const DAFSA_KEY_MAX_CHAR:       u8 = 0x7F;
const DAFSA_RETURN_MIN:         u8 = 0x80;
const DAFSA_RETURN_MAX:         u8 = 0x8F;
const DAFSA_END_CHAR_MIN:       u8 = 0x9F;
const DAFSA_CHAR_MASK:          u8 = 0x7F;
const DAFSA_END_BIT:            u8 = 0x80;
const DAFSA_OFFSET_TYPE_MASK:   u8 = 0x60;
const DAFSA_OFFSET_LOW_MASK:    u8 = 0x1F;
const DAFSA_OFFSET_SINGLE_MASK: u8 = 0x3F;
const DAFSA_RETURN_VAL_MASK:    u8 = 0x0F;

const PSL_DAFSA_LEN: i64 = 920;
const PSL_DAFSA_GRAPH: u8[920] = [
    0x1D, 0x0F, 0x04, 0x15, 0x08, 0x06, 0x0A, 0x3A, 0x0B, 0x03, 0x28, 0x2F, 0x36, 0x1E, 0x0B, 0x1E,
    0x07, 0x0F, 0x0B, 0x40, 0x50, 0x22, 0x20, 0x20, 0x40, 0xA0, 0x3B, 0xC0, 0x56, 0xF9, 0x02, 0x89,
    0x6F, 0x6B, 0x6F, 0x68, 0x61, 0x6D, 0xE1, 0xC1, 0x4D, 0xE5, 0xC2, 0xF9, 0x78, 0xF9, 0xC3, 0x55,
    0xF7, 0x03, 0x06, 0x87, 0x77, 0x77, 0x2E, 0xE3, 0xC2, 0xE5, 0x6F, 0x72, 0x6B, 0x65, 0xF2, 0xC0,
    0x8B, 0x65, 0xE2, 0xC0, 0xDC, 0x76, 0x65, 0x72, 0x63, 0x65, 0xEC, 0xC0, 0xD4, 0xF5, 0x41, 0xBB,
    0x41, 0x77, 0x96, 0xF4, 0x05, 0x42, 0x29, 0xC1, 0x04, 0x65, 0xE3, 0xC2, 0x8E, 0xF3, 0x0B, 0x0C,
    0x04, 0x04, 0x09, 0x06, 0x08, 0x41, 0xF2, 0xC0, 0xBA, 0xF4, 0x02, 0x84, 0x6F, 0xF2, 0xC0, 0x8B,
    0x61, 0x74, 0xE5, 0xC1, 0x94, 0x70, 0xE2, 0xC0, 0xCF, 0x69, 0xF4, 0xC0, 0x7E, 0xE5, 0x03, 0xC3,
    0x16, 0x6E, 0x64, 0xE1, 0xC0, 0xEF, 0x63, 0x68, 0x2E, 0xF5, 0xC2, 0x2B, 0x61, 0x70, 0x70, 0x6F,
    0x72, 0xEF, 0xC0, 0xE2, 0xB3, 0xC1, 0x82, 0xF2, 0x03, 0xC2, 0xA5, 0x61, 0x69, 0x6C, 0x77, 0xE1,
    0xC0, 0x7E, 0xF1, 0xC2, 0x81, 0xF0, 0x05, 0x03, 0x03, 0x07, 0x83, 0xF2, 0xC0, 0xE0, 0xF0, 0xC0,
    0x97, 0xEC, 0x03, 0xC2, 0xE2, 0xE3, 0xC0, 0x9F, 0xE7, 0xC2, 0x6A, 0xE1, 0x02, 0x8A, 0x72, 0x6C,
    0x69, 0x61, 0x6D, 0x65, 0x6E, 0xF4, 0xC2, 0x55, 0x67, 0x65, 0xF3, 0xC1, 0x7B, 0xEF, 0x04, 0x17,
    0xC0, 0x94, 0xF2, 0x03, 0xC0, 0xEC, 0xE7, 0x03, 0xC2, 0xBD, 0xAE, 0x41, 0xA3, 0x07, 0x04, 0x03,
    0x04, 0x03, 0x03, 0x40, 0xE7, 0x02, 0x03, 0x09, 0x85, 0xEE, 0x04, 0x08, 0xC2, 0x9E, 0x72, 0x65,
    0x6E, 0x64, 0x65, 0xF2, 0xC2, 0x68, 0x6C, 0x69, 0x6E, 0xE5, 0xC2, 0x9D, 0xEE, 0x08, 0x0D, 0x40,
    0x64, 0x16, 0x41, 0xF7, 0x8B, 0x67, 0x72, 0x6F, 0xEB, 0x03, 0xC0, 0xD3, 0x2D, 0x66, 0x72, 0x65,
    0xE5, 0x8E, 0xE5, 0x03, 0xC0, 0xAC, 0xF4, 0x04, 0x0A, 0xC2, 0x72, 0x6C, 0x69, 0x66, 0x79, 0x2E,
    0x61, 0x70, 0xF0, 0xC2, 0x4B, 0xAE, 0x41, 0x58, 0x07, 0x04, 0x0A, 0x03, 0x40, 0xE7, 0x02, 0x03,
    0x09, 0x85, 0xED, 0x07, 0x0A, 0x05, 0x03, 0x31, 0xC1, 0x10, 0x79, 0x73, 0x68, 0x6F, 0x70, 0x69,
    0x66, 0xF9, 0xC2, 0x1A, 0x73, 0x6B, 0xAE, 0xC1, 0x42, 0xE9, 0xC2, 0x44, 0xE5, 0x08, 0xC2, 0x42,
    0xEC, 0x02, 0x85, 0x74, 0x64, 0xAE, 0xC2, 0x29, 0xE7, 0xC2, 0x19, 0xEB, 0x07, 0x03, 0x04, 0x03,
    0x42, 0x16, 0x83, 0xF7, 0xC1, 0xBF, 0x6F, 0x62, 0xE5, 0x8B, 0xE8, 0xC1, 0xB8, 0x61, 0x77, 0x61,
    0x73, 0x61, 0x6B, 0x69, 0x2E, 0x6A, 0xF0, 0xC1, 0xAC, 0xEA, 0x03, 0xC2, 0x0C, 0xED, 0xC1, 0xA5,
    0xE9, 0x04, 0x07, 0xC2, 0x02, 0xEE, 0x05, 0x41, 0xB8, 0xC0, 0x54, 0x66, 0xEF, 0xC2, 0x0A, 0xE8,
    0x03, 0xC1, 0xED, 0x65, 0x72, 0x6F, 0x6B, 0xF5, 0xC0, 0x68, 0xE7, 0x06, 0x03, 0x22, 0x1E, 0xC1,
    0x40, 0xF2, 0xC1, 0xD0, 0xEF, 0x03, 0x16, 0x84, 0xF6, 0x04, 0x04, 0xC1, 0xE6, 0x74, 0xAE, 0xC1,
    0xD3, 0xAE, 0x40, 0xCC, 0x07, 0x04, 0x07, 0x03, 0x03, 0x40, 0xE7, 0x02, 0x0C, 0x85, 0x62, 0xAE,
    0xC0, 0xCC, 0xAE, 0x41, 0xC2, 0x83, 0x69, 0xF4, 0x02, 0x84, 0x6C, 0x61, 0xE2, 0x92, 0x68, 0x75,
    0xE2, 0x02, 0x8C, 0x75, 0x73, 0x65, 0x72, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0xEE, 0xC1, 0x75, 0x2E,
    0x69, 0xEF, 0xC1, 0x8C, 0x65, 0x6E, 0x2E, 0xE9, 0xC1, 0xA9, 0xE6, 0x07, 0x04, 0x0F, 0x40, 0xB0,
    0xC0, 0xD1, 0x6C, 0xF9, 0xC0, 0x52, 0xE9, 0x03, 0xC1, 0x9D, 0x72, 0x65, 0x62, 0x61, 0x73, 0x65,
    0x61, 0x70, 0xF0, 0xC1, 0x59, 0x65, 0x64, 0x2E, 0x75, 0xF3, 0xC1, 0x8D, 0xE5, 0x05, 0x03, 0x06,
    0xC1, 0x25, 0xF2, 0xC1, 0x10, 0x6C, 0x62, 0x2E, 0xE1, 0xC1, 0x3B, 0xE4, 0x03, 0xC1, 0x53, 0xF5,
    0x03, 0xC1, 0x74, 0xAE, 0x40, 0x5A, 0x07, 0x04, 0x07, 0x06, 0xC0, 0xFA, 0xE4, 0x04, 0x0B, 0xC1,
    0x44, 0x79, 0x6E, 0x64, 0x6E, 0x73, 0x2E, 0x6F, 0x72, 0xE7, 0xC1, 0x34, 0xE5, 0x04, 0x03, 0xC1,
    0x53, 0xF6, 0xC1, 0x55, 0x6E, 0x6F, 0x2E, 0x64, 0x65, 0xF6, 0xC1, 0x24, 0xE3, 0x0A, 0x40, 0x4A,
    0x14, 0x03, 0x31, 0x40, 0x9A, 0x0E, 0x85, 0xEF, 0x04, 0x3D, 0xC0, 0xFE, 0xED, 0x04, 0x13, 0xC1,
    0x23, 0x70, 0x75, 0x74, 0x65, 0x2E, 0x61, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x61, 0x77, 0x73, 0x2E,
    0x63, 0x6F, 0x6D, 0x8A, 0xAE, 0x09, 0x07, 0x04, 0x03, 0x04, 0x03, 0x03, 0xC0, 0xFA, 0xF4, 0x03,
    0xC1, 0x04, 0xF7, 0xC1, 0x14, 0x73, 0xE7, 0xC1, 0x10, 0xF2, 0xC0, 0xB6, 0x6D, 0xF8, 0xC1, 0x09,
    0xE8, 0xC0, 0xEF, 0xE2, 0xC0, 0xF2, 0xE1, 0xC0, 0xA9, 0xAE, 0x40, 0xE3, 0x02, 0x03, 0x03, 0x03,
    0x83, 0x6C, 0x6F, 0x75, 0xE4, 0x04, 0x07, 0xC0, 0xE7, 0x66, 0x72, 0x6F, 0x6E, 0xF4, 0xC0, 0xBC,
    0x61, 0x70, 0xF0, 0xC0, 0xB7, 0xEB, 0xC0, 0x6D, 0x69, 0x74, 0x79, 0xAE, 0x03, 0x09, 0x8F, 0x79,
    0x6F, 0x6B, 0x6F, 0x68, 0x61, 0x6D, 0xE1, 0x9E, 0xF3, 0x02, 0x85, 0x65, 0x6E, 0x64, 0xE1, 0x95,
    0x61, 0x70, 0x70, 0x6F, 0x72, 0xEF, 0x8F, 0xEB, 0x02, 0x84, 0x6F, 0x62, 0xE5, 0x88, 0x61, 0x77,
    0x61, 0x73, 0x61, 0x6B, 0x69, 0x2E, 0x6A, 0xF0, 0xB6, 0xE8, 0xC0, 0xAD, 0xE2, 0x07, 0x03, 0x28,
    0x03, 0x02, 0xC0, 0x62, 0xF9, 0xC0, 0xA2, 0xEC, 0x02, 0xA1, 0xEF, 0x02, 0x90, 0x67, 0x73, 0x70,
    0x6F, 0x74, 0x2E, 0x63, 0xEF, 0x03, 0xC0, 0x57, 0x2E, 0x75, 0xEB, 0xC0, 0x63, 0x62, 0x2E, 0x63,
    0x6F, 0x72, 0x65, 0x2E, 0x77, 0x69, 0x6E, 0x64, 0x6F, 0xF7, 0xA4, 0x2E, 0x75, 0x6B, 0x81, 0xE9,
    0xC0, 0x63, 0x64, 0x82, 0xE3, 0xC0, 0x6F, 0xE1, 0x0B, 0x0D, 0x03, 0x03, 0x04, 0x0A, 0x0D, 0x0E,
    0x02, 0x03, 0x9F, 0x7A, 0x75, 0x72, 0x65, 0x77, 0x65, 0x62, 0x73, 0x69, 0x74, 0x65, 0xF3, 0xAB,
    0xF5, 0xC0, 0x56, 0xF4, 0xC0, 0x53, 0x72, 0xF0, 0xC0, 0x4E, 0x70, 0xF0, 0x03, 0xC0, 0x48, 0x73,
    0x70, 0x6F, 0xF4, 0x89, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x61, 0x77, 0x73, 0x2E, 0x63, 0x6F, 0xED,
    0x8E, 0x6C, 0x77, 0x61, 0x79, 0x73, 0x64, 0x61, 0x74, 0x61, 0x2E, 0x6E, 0x65, 0x74, 0x88, 0xE9,
    0xA7, 0x64, 0xAE, 0x95, 0x63, 0xAE, 0x07, 0x02, 0x03, 0x03, 0x03, 0x03, 0x85, 0xFA, 0x98, 0x75,
    0xEB, 0x96, 0x6E, 0xFA, 0x93, 0x6B, 0xF2, 0x90, 0x6A, 0xF0, 0x8D, 0xE9, 0x02, 0x83, 0xEC, 0x88,
    0x63, 0xEE, 0x85, 0x62, 0x2E, 0x63, 0x61, 0x80,
];

// Decodes a 1-, 2-, or 3-byte child jump delta from the DAFSA offset list and advances `pos`.
// If `pos` sits on an end-of-offsets entry (`0x80` bit set), sets `pos = PSL_DAFSA_LEN` after decoding.
//
// Example:
//   PSL_DAFSA_GRAPH[0] = 0x1D, pos = 0, offset = 0
//   returns: true, pos = 1, offset = 29
fn dafsa_get_next_offset(pos: i64&, offset: i64&) -> bool {
    guard pos >= 0 && pos < PSL_DAFSA_LEN else {
        return false;
    }
    let b0 = PSL_DAFSA_GRAPH[pos];
    let offset_type = b0 & DAFSA_OFFSET_TYPE_MASK;
    var bytes_consumed: i64 = 1;
    var delta:          i64 = b0 & DAFSA_OFFSET_SINGLE_MASK;

    if offset_type == 0x60 {
        guard core::add_sat_i64(pos, 2) < PSL_DAFSA_LEN else {
            return false;
        }
        let b0_low: u64 = b0 & DAFSA_OFFSET_LOW_MASK;
        let b1:     u64 = PSL_DAFSA_GRAPH[core::add_sat_i64(pos, 1)];
        let b2:     u64 = PSL_DAFSA_GRAPH[core::add_sat_i64(pos, 2)];
        let hi_mid = core::add_sat_u64(core::mul_sat_u64(b0_low, 65536), core::mul_sat_u64(b1, 256));
        delta = core::add_sat_u64(hi_mid, b2) as i64;
        bytes_consumed = 3;
    } else if offset_type == 0x40 {
        guard core::add_sat_i64(pos, 1) < PSL_DAFSA_LEN else {
            return false;
        }
        let b0_low: u64 = b0 & DAFSA_OFFSET_LOW_MASK;
        let b1:     u64 = PSL_DAFSA_GRAPH[core::add_sat_i64(pos, 1)];
        delta = core::add_sat_u64(core::mul_sat_u64(b0_low, 256), b1) as i64;
        bytes_consumed = 2;
    }

    if (b0 & DAFSA_END_BIT) != 0 {
        pos = PSL_DAFSA_LEN;
    } else {
        pos = core::add_sat_i64(pos, bytes_consumed);
    }
    offset = core::add_sat_i64(offset, delta);
    return offset >= 0 && offset < PSL_DAFSA_LEN;
}

// Evaluates a single DAFSA node character against `key_byte` in ASCII or `0x1F` multibyte UTF-8 mode.
//
// Example:
//   key_byte = 'c', mb_mode = false, node_char = 'c' -> returns true
fn dafsa_is_match(key_byte: u8, mb_mode: bool&, node_char: u8) -> bool {
    if mb_mode {
        if (node_char & 0x80) != 0 {
            if (key_byte ^ 0xC0) == node_char {
                mb_mode = false;
                return true;
            }
        } else {
            if (key_byte ^ 0x80) == node_char {
                return true;
            }
        }
        return false;
    }
    return key_byte == node_char;
}

// Consumes intermediate plain-ASCII or `0x1F` multibyte characters of a DAFSA node label against `key`.
// Stops when `node_pos` reaches a terminal byte (`>= 0x80`) or when `key_idx` reaches `key.len`.
//
// Example:
//   key = "co.uk", key_idx = 0, node_pos = 109 ('o', 'r' | 0x80)
//   returns: true (when prefix matches up to terminal byte)
fn dafsa_consume_prefix_label(key: const u8[:], key_idx: i64&, node_pos: i64&, mb_mode: bool&) -> bool {
    while node_pos >= 0 && node_pos < PSL_DAFSA_LEN {
        let b = PSL_DAFSA_GRAPH[node_pos];
        if !mb_mode && b == DAFSA_KEY_MIN_CHAR {
            mb_mode = true;
            node_pos = core::add_sat_i64(node_pos, 1);
            continue;
        }
        if b < DAFSA_KEY_MIN_CHAR || b >= DAFSA_KEY_MAX_CHAR {
            return true;
        }
        guard key_idx < key.len else {
            return false;
        }
        let kb = key[key_idx];
        guard dafsa_is_match(kb, mb_mode, b) else {
            return false;
        }
        key_idx = core::add_sat_i64(key_idx, 1);
        node_pos = core::add_sat_i64(node_pos, 1);
    }
    return false;
}

// Evaluates the terminal byte of a DAFSA node at `node_pos` after prefix characters have matched.
// Returns `0` on mismatch, `1` when `out_ret` holds a final return value, or `2` to descend to `node_pos`.
//
// Example:
//   key = "uk", key_idx = 1, node_pos = 197 ('k' | 0x80, 0x80)
//   returns: 1, out_ret = 0, key_idx = 2, node_pos = 198
fn dafsa_eval_node_terminal(
    key:      const u8[:],
    key_idx:  i64&,
    node_pos: i64&,
    mb_mode:  bool&,
    out_ret:  i32&,
) -> i32 {
    guard dafsa_consume_prefix_label(key, key_idx, node_pos, mb_mode) && node_pos < PSL_DAFSA_LEN else {
        return 0;
    }
    let term = PSL_DAFSA_GRAPH[node_pos];
    if !mb_mode && term >= DAFSA_RETURN_MIN && term <= DAFSA_RETURN_MAX {
        guard key_idx == key.len else {
            return 0;
        }
        let v: i32 = term & DAFSA_RETURN_VAL_MASK;
        out_ret = v;
        return 1;
    }
    guard term >= DAFSA_END_CHAR_MIN && key_idx < key.len else {
        return 0;
    }
    let kb = key[key_idx];
    let term_char = if mb_mode { term } else { term & DAFSA_CHAR_MASK };
    guard dafsa_is_match(kb, mb_mode, term_char) else {
        return 0;
    }
    key_idx = core::add_sat_i64(key_idx, 1);
    node_pos = core::add_sat_i64(node_pos, 1);
    return 2;
}

// Evaluates the compiled Chromium/libpsl DAFSA for `key` in O(L) time with zero heap allocation.
// Returns the 4-bit rule flag mask (`0..15`) on exact match, or `PSL_DAFSA_NOT_FOUND` (`-1`).
//
// Example:
//   key = "co.uk"  -> returns 0 (standard ICANN suffix)
//   key = "ck"     -> returns 2 (PSL_DAFSA_FLAG_WILDCARD)
//   key = "www.ck" -> returns 1 (PSL_DAFSA_FLAG_EXCEPTION)
fn dafsa_lookup_string(key: const u8[:]) -> i32 {
    guard key.len > 0 else {
        return PSL_DAFSA_NOT_FOUND;
    }
    var pos:     i64  = 0;
    var offset:  i64  = 0;
    var key_idx: i64  = 0;
    var mb_mode: bool = false;

    while dafsa_get_next_offset(pos, offset) {
        var node_pos = offset;
        var saved_key_idx = key_idx;
        var saved_mb_mode = mb_mode;
        var out_ret: i32 = PSL_DAFSA_NOT_FOUND;
        let step = dafsa_eval_node_terminal(key, key_idx, node_pos, mb_mode, out_ret);
        if step == 1 {
            return out_ret;
        }
        if step == 2 {
            pos = node_pos;
            offset = node_pos;
        } else {
            key_idx = saved_key_idx;
            mb_mode = saved_mb_mode;
        }
    }
    return PSL_DAFSA_NOT_FOUND;
}

// Scans forward in `norm` from `start` to the next '.' delimiter (or `norm.len`).
//
// Example:
//   norm = "www.ck", start = 0 -> returns 3
fn dafsa_scan_to_next_dot(norm: const u8[:], start: i64) -> i64 {
    var dot = start;
    while dot < norm.len && norm[dot] != 0x2E {
        dot = core::add_sat_i64(dot, 1);
    }
    return dot;
}

// Resolves the public suffix slice when a DAFSA rule matches at `idx` with `flags`.
//
// Example:
//   norm = "sub.www.ck", idx = 4, prev_dot = 0, flags = 1 -> returns "ck", true, true
fn dafsa_resolve_rule_flags(norm: const u8[:], idx: i64, prev_dot: i64, flags: i32) -> const u8[:], bool, bool, bool {
    guard flags != PSL_DAFSA_NOT_FOUND else {
        return norm[0..0], false, false, false;
    }
    let candidate = norm[idx..norm.len];
    let is_icann = (flags & PSL_DAFSA_FLAG_PRIVATE) == 0;
    let is_exception = (flags & PSL_DAFSA_FLAG_EXCEPTION) != 0;
    if is_exception {
        let next_start = core::add_sat_i64(dafsa_scan_to_next_dot(norm, idx), 1);
        if next_start < norm.len {
            return norm[next_start..norm.len], true, is_icann, true;
        }
        return candidate, true, is_icann, true;
    }
    if (flags & PSL_DAFSA_FLAG_WILDCARD) != 0 {
        if idx > 0 {
            let wild_start = core::add_sat_i64(prev_dot, 1);
            return norm[wild_start..norm.len], true, is_icann, false;
        }
        return candidate, true, is_icann, false;
    }
    return candidate, true, is_icann, false;
}

//Evaluates candidate suffixes of `norm` (a lowercase, leading/trailing-dot-free domain)
// from longest to shortest against the DAFSA, applying exception (`!`), wildcard (`*.`),
// and exact rules per the Public Suffix List specification (https://publicsuffix.org/list/).
// Returns `(suffix_slice, matched, is_icann, is_exception)`.
//
// Example:
//   norm = "sub.www.ck" -> returns "ck", true, true, true (exception rule !www.ck drops 1 label)
//   norm = "sub.foo.ck" -> returns "foo.ck", true, true, false (wildcard rule *.ck includes 1 label)
fn dafsa_find_public_suffix(norm: const u8[:]) -> const u8[:], bool, bool, bool {
    guard norm.len > 0 else {
        return norm[0..0], false, false, false;
    }
    var idx:      i64 = 0;
    var prev_dot: i64 = -1;
    while idx < norm.len {
        let flags = dafsa_lookup_string(norm[idx..norm.len]);
        let suf, matched, is_icann, is_exc = dafsa_resolve_rule_flags(norm, idx, prev_dot, flags);
        if matched {
            return suf, true, is_icann, is_exc;
        }
        let next_dot = dafsa_scan_to_next_dot(norm, idx);
        prev_dot = if idx == 0 { -1 } else { core::sub_sat_i64(idx, 1) };
        idx = core::add_sat_i64(next_dot, 1);
    }
    return norm[0..0], false, false, false;
}

const PUNYCODE_BASE:         u64 = 36;
const PUNYCODE_TMIN:         u64 = 1;
const PUNYCODE_TMAX:         u64 = 26;
const PUNYCODE_SKEW:         u64 = 38;
const PUNYCODE_DAMP:         u64 = 700;
const PUNYCODE_INITIAL_BIAS: u64 = 72;
const PUNYCODE_INITIAL_N:    u64 = 128;
const PUNYCODE_DIGITS: u8[36] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
];

fn punycode_div_u64(n: u64, d: u64) -> u64, u64 {
    guard d > 0 && n >= d else { return 0, n; }
    var cur_d = d;
    var cur_q: u64 = 1;
    let half_n = n >> 1;
    while cur_d <= half_n {
        cur_d = core::add_sat_u64(cur_d, cur_d);
        cur_q = core::add_sat_u64(cur_q, cur_q);
    }
    var rem_n = n;
    var quotient: u64 = 0;
    while cur_q > 0 {
        if rem_n >= cur_d {
            rem_n = core::sub_sat_u64(rem_n, cur_d);
            quotient = quotient | cur_q;
        }
        cur_d = cur_d >> 1;
        cur_q = cur_q >> 1;
    }
    return quotient, rem_n;
}

fn punycode_adapt(delta_in: u64, numpoints: u64, firsttime: bool) -> u64 {
    var d0 = delta_in >> 1;
    if firsttime {
        let q0, _ = punycode_div_u64(delta_in, PUNYCODE_DAMP);
        d0 = q0;
    }
    let d1, _ = punycode_div_u64(d0, max(numpoints, 1));
    var delta = core::add_sat_u64(d0, d1);
    let base_minus_tmin: u64 = 35;
    let threshold:       u64 = 455;
    var k: u64 = 0;
    while delta > threshold {
        let q, _ = punycode_div_u64(delta, base_minus_tmin);
        delta = q;
        k = core::add_sat_u64(k, PUNYCODE_BASE);
    }
    let num = core::mul_sat_u64(36, delta);
    let den = core::add_sat_u64(delta, PUNYCODE_SKEW);
    let tail, _ = punycode_div_u64(num, den);
    return core::add_sat_u64(k, tail);
}

fn punycode_emit_delta(q_in: u64, bias: u64, out_ace: u8[..63]&) -> bool {
    var q = q_in;
    var k = PUNYCODE_BASE;
    while true {
        let bias_plus_tmax = core::add_sat_u64(bias, PUNYCODE_TMAX);
        let t = if k <= bias {
            PUNYCODE_TMIN
        } else if k >= bias_plus_tmax {
            PUNYCODE_TMAX
        } else {
            core::sub_sat_u64(k, bias)
        };
        if q < t { break; }
        let base_minus_t = core::sub_sat_u64(PUNYCODE_BASE, t);
        let q_minus_t = core::sub_sat_u64(q, t);
        let q_next, rem = punycode_div_u64(q_minus_t, base_minus_t);
        let digit = min(core::add_sat_u64(t, rem), 35) as i64;
        let ch = PUNYCODE_DIGITS[digit];
        guard out_ace.try_push(ch) else { return false; }
        q = q_next;
        k = core::add_sat_u64(k, PUNYCODE_BASE);
    }
    let final_digit = min(q, 35) as i64;
    let final_ch = PUNYCODE_DIGITS[final_digit];
    return out_ace.try_push(final_ch);
}

fn punycode_extract_codepoints(utf8_label: const u8[:], cps: u64[..63]&, has_non_ascii: bool&) -> bool {
    var idx: i64 = 0;
    while idx < utf8_label.len {
        let cp, sz, ok = core::decode_utf8(utf8_label[idx..]);
        guard ok && sz > 0 && cps.len < cps.cap else { return false; }
        var norm_cp = cp as u64;
        if norm_cp < 0x80 {
            let b = norm_cp as u8;
            guard b > 0x20 && b != 0x7F && b != 0x2E else { return false; }
            norm_cp = core::to_lower_ascii_byte(b);
        } else {
            has_non_ascii = true;
        }
        cps.push(norm_cp);
        idx = core::add_sat_i64(idx, sz);
    }
    return cps.len > 0;
}

fn punycode_copy_basic_codepoints(cps: const u64[:], out_ace: u8[..63]&) -> u64, bool {
    var basic_count: u64 = 0;
    for c in cps {
        if c < 0x80 {
            guard out_ace.try_push(c as u8) else { return 0, false; }
            basic_count = core::add_sat_u64(basic_count, 1);
        }
    }
    if basic_count > 0 {
        guard out_ace.try_push('-') else { return 0, false; }
    }
    return basic_count, true;
}

fn punycode_find_next_min_cp(cps: const u64[:], n: u64) -> u64 {
    var m: u64 = 0xFFFFFFFF;
    for c in cps {
        if c >= n && c < m { m = c; }
    }
    return m;
}

fn punycode_step_non_basic(
    cps:         const u64[:],
    n:           u64,
    basic_count: u64,
    delta:       u64&,
    bias:        u64&,
    h:           u64&,
    out_ace:     u8[..63]&,
) -> bool {
    for c in cps {
        if c < n {
            delta = core::add_sat_u64(delta, 1);
            guard delta <= 0xFFFFFFFF else { return false; }
        } else if c == n {
            guard punycode_emit_delta(delta, bias, out_ace) else { return false; }
            let next_h = core::add_sat_u64(h, 1);
            bias = punycode_adapt(delta, next_h, h == basic_count);
            delta = 0;
            h = next_h;
        }
    }
    return true;
}

// Encodes a single UTF-8 domain label into an ASCII/ACE Punycode label (`xn--...`, RFC 3492).
//
// Example:
//   utf8_label = "\xE4\xB8\xAD\xE5\x9B\xBD" ("中国"), out_ace = []
//   returns: true, out_ace = "xn--fiqs8s"
fn punycode_encode_label(utf8_label: const u8[:], out_ace: u8[..63]&) -> bool {
    out_ace.clear();
    guard utf8_label.len > 0 && core::validate_utf8(utf8_label) else { return false; }
    var cps: u64[..63] = [];
    var has_non_ascii = false;
    guard punycode_extract_codepoints(utf8_label, cps, has_non_ascii) else { return false; }
    if !has_non_ascii {
        for c in cps {
            guard out_ace.try_push(c as u8) else { return false; }
        }
        return true;
    }
    guard out_ace.try_append("xn--") else { return false; }
    let basic_count, ok_basic = punycode_copy_basic_codepoints(cps[..], out_ace);
    guard ok_basic else { return false; }

    var n = PUNYCODE_INITIAL_N;
    var delta: u64 = 0;
    var bias = PUNYCODE_INITIAL_BIAS;
    var h = basic_count;
    let total_cp = cps.len as u64;
    while h < total_cp {
        let m = punycode_find_next_min_cp(cps[..], n);
        let step_mul = core::mul_sat_u64(core::sub_sat_u64(m, n), core::add_sat_u64(h, 1));
        delta = core::add_sat_u64(delta, step_mul);
        guard delta <= 0xFFFFFFFF else { return false; }
        n = m;
        guard punycode_step_non_basic(cps[..], n, basic_count, delta, bias, h, out_ace) else { return false; }
        delta = core::add_sat_u64(delta, 1);
        n = core::add_sat_u64(n, 1);
    }
    return true;
}

// Normalizes a UTF-8 or ASCII domain into lowercase Punycode/ACE (`xn--...`) labels (RFC 3492).
//
// Example:
//   utf8_domain = "Example.\xE4\xB8\xAD\xE5\x9B\xBD", out_ace = []
//   returns: true, out_ace = "example.xn--fiqs8s"
fn punycode_encode_domain(utf8_domain: const u8[:], out_ace: u8[..256]&) -> bool {
    out_ace.clear();
    guard utf8_domain.len > 0 && utf8_domain.len <= 256 else { return false; }
    guard core::validate_utf8(utf8_domain) else { return false; }
    let last_idx = core::sub_sat_i64(utf8_domain.len, 1);
    guard utf8_domain[0] != 0x2E && utf8_domain[last_idx] != 0x2E else { return false; }
    guard !core::is_ip_address_literal(utf8_domain) else { return false; }
    var start: i64 = 0;
    while start < utf8_domain.len {
        let dot = dafsa_scan_to_next_dot(utf8_domain, start);
        guard dot > start else { return false; }
        var label_ace: u8[..63] = [];
        guard punycode_encode_label(utf8_domain[start..dot], label_ace) else { return false; }
        if out_ace.len > 0 {
            guard out_ace.try_push('.') else { return false; }
        }
        guard out_ace.try_append(label_ace[..]) else { return false; }
        start = core::add_sat_i64(dot, 1);
    }
    return out_ace.len > 0;
}

// Validates that `domain` is non-empty, <= 256 bytes, valid UTF-8, has no leading
// or trailing '.', has no empty '..' labels, is not an IP literal, and normalizes to lowercase.
//
// Example:
//   domain = "Example.CO.UK", out = [] -> returns true, out = "example.co.uk"
//   domain = ".com", out = []          -> returns false (leading dot rejected)
fn validate_and_lowercase_psl_domain(domain: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    guard domain.len > 0 && domain.len <= 256 else {
        return false;
    }
    var has_non_ascii = false;
    for b in domain {
        if b >= 0x80 {
            has_non_ascii = true;
            break;
        }
    }
    if has_non_ascii {
        return punycode_encode_domain(domain, out);
    }
    let last_idx = core::sub_sat_i64(domain.len, 1);
    guard domain[0] != 0x2E && domain[last_idx] != 0x2E else {
        return false;
    }
    guard !core::is_ip_address_literal(domain) else {
        return false;
    }
    var i: i64 = 0;
    var prev_was_dot = false;
    while i < domain.len {
        let b = domain[i];
        guard b > 0x20 && b != 0x7F else {
            return false;
        }
        if b == 0x2E {
            guard !prev_was_dot else {
                return false;
            }
            prev_was_dot = true;
        } else {
            prev_was_dot = false;
        }
        guard out.len < out.cap else {
            return false;
        }
        out.push(core::to_lower_ascii_byte(b));
        i = core::add_sat_i64(i, 1);
    }
    return true;
}

// Evaluates the compiled Chromium/libpsl DAFSA binary automaton in O(L) time.
// Returns `true` if `domain` is a public suffix (ICANN or Private), `false` if it is a
// registrable domain (e.g. `example.com`, `www.ck`, `city.kawasaki.jp`) or malformed
// (leading/trailing dots, empty labels, IP literal, or invalid UTF-8).
//
// Example:
//   domain = "co.uk"   -> returns true
//   domain = "foo.ck"  -> returns true (*.ck wildcard)
//   domain = "www.ck"  -> returns false (!www.ck exception)
//   domain = ".com"    -> returns false (leading dot rejected)
fn psl_is_public_suffix(domain: const u8[:]) -> bool {
    var norm: u8[..256] = [];
    guard validate_and_lowercase_psl_domain(domain, norm) else {
        return false;
    }
    let suffix, matched, _, _ = dafsa_find_public_suffix(norm[0..norm.len]);
    if matched {
        return suffix.len == norm.len;
    }
    var i: i64 = 0;
    while i < norm.len {
        if norm[i] == 0x2E {
            return false;
        }
        i = core::add_sat_i64(i, 1);
    }
    return true;
}

enum PslRuleType {
    Normal,
    Wildcard,
    Exception,
}

enum PslSection {
    Icann,
    Private,
}

struct PslRule {
    pattern:   u8[..64]    = [],
    rule_type: PslRuleType = PslRuleType.Normal,
    section:   PslSection  = PslSection.Icann,
}

struct PslDatabase {
    use_dafsa: bool          = false,
    rules:     PslRule[..64] = [],
}

struct PslMatch {
    suffix:             u8[..256] = [],
    registrable_domain: u8[..256] = [],
    is_icann:           bool      = false,
    is_private:         bool      = false,
    is_known:           bool      = false,
}

fn new_psl_rule(pattern: const u8[:], rule_type: PslRuleType, section: PslSection) -> PslRule {
    var new_rule = PslRule { rule_type: rule_type, section: section, .. };
    guard new_rule.pattern.try_set(pattern) else { return new_rule; }
    to_lower(new_rule.pattern[..]);
    return new_rule;
}

fn add_psl_rule(db: PslDatabase&, pattern: const u8[:], rule_type: PslRuleType, section: PslSection) {
    guard db.rules.len < db.rules.cap else { return; }
    db.rules.push(new_psl_rule(pattern, rule_type, section));
}

fn new_psl_database() -> PslDatabase {
    return PslDatabase { rules: [], use_dafsa: true };
}

// ---- public suffix query and matching engine -------------------------------

//Normalizes domain: strips leading/trailing dots and outer IPv6 brackets, then converts to lowercase or Punycode.
fn psl_normalize_domain<B>(domain: const u8[:], out: B&) -> bool {
    out.clear();
    let trimmed = core::trim_byte(core::trim_byte(core::trim_byte(domain, '.'), '['), ']');
    guard trimmed.len > 0 && trimmed.len <= 256 else { return false; }
    var has_non_ascii = false;
    for b in trimmed {
        if b >= 0x80 {
            has_non_ascii = true;
            break;
        }
    }
    if has_non_ascii {
        var ace_buf: u8[..256] = [];
        guard punycode_encode_domain(trimmed, ace_buf) else { return false; }
        return out.try_set(ace_buf[..]);
    }
    guard out.try_set(trimmed) else { return false; }
    to_lower(out[..]);
    return true;
}

fn psl_match_exception(rule: const PslRule&, norm: const u8[:]) -> const u8[:] {
    if rule.rule_type != PslRuleType.Exception {
        return "";
    }
    let pat = rule.pattern[..];
    if norm != pat && !core::ends_with_dot_suffix(norm, pat) {
        return "";
    }
    let first_dot = core::index_of_byte(pat, '.');
    if first_dot < 0 {
        return pat;
    }
    let start = core::add_sat_i64(first_dot, 1);
    if start >= pat.len {
        return pat;
    }
    return pat[start..];
}

fn psl_match_normal(pat: const u8[:], norm: const u8[:], out_start: i64&, out_labels: i32&) -> bool {
    let pat_len = pat.len;
    let norm_len = norm.len;
    let dots = core::count_byte(pat, '.');
    let num_labels = core::add_sat_i64(dots, 1) as i32;
    if norm == pat {
        out_start = 0;
        out_labels = num_labels;
        return true;
    }
    if !core::ends_with_dot_suffix(norm, pat) {
        return false;
    }
    if norm_len < pat_len {
        return false;
    }
    let suffix_start = core::sub_sat_i64(norm_len, pat_len);
    out_start = suffix_start;
    out_labels = num_labels;
    return true;
}

fn psl_match_wildcard(pat: const u8[:], norm: const u8[:], out_start: i64&, out_labels: i32&) -> bool {
    let dots = core::count_byte(pat, '.');
    if norm == pat {
        out_start = 0;
        out_labels = core::add_sat_i64(dots, 1) as i32;
        return true;
    }
    if !core::ends_with_dot_suffix(norm, pat) {
        return false;
    }
    let n_len = norm.len;
    let p_len = pat.len;
    if n_len <= p_len {
        return false;
    }
    let rem_len = core::sub_sat_i64(n_len, p_len);
    let prefix_len = core::sub_sat_i64(rem_len, 1);
    if prefix_len < 0 || prefix_len > n_len {
        return false;
    }
    let prefix = norm[..prefix_len];
    let last_dot = core::last_index_of_byte(prefix, '.');
    let next_dot = core::add_sat_i64(last_dot, 1);
    var start: i64 = 0;
    if last_dot >= 0 {
        start = next_dot;
    }
    let num_labels = core::add_sat_i64(dots, 2) as i32;
    out_start = start;
    out_labels = num_labels;
    return true;
}

fn psl_find_best_rule(db: const PslDatabase&, norm: const u8[:], out_start: i64&, out_sec: PslSection&) -> bool {
    var best_labels: i32 = 0;
    var best_start:  i64 = 0;
    var best_sec = PslSection.Icann;
    var found = false;

    for &rule in db.rules {
        var start_idx: i64 = 0;
        var labels:    i32 = 0;
        var matched = false;

        if rule.rule_type == PslRuleType.Normal {
            matched = psl_match_normal(rule.pattern[..], norm, start_idx, labels);
        } else if rule.rule_type == PslRuleType.Wildcard {
            matched = psl_match_wildcard(rule.pattern[..], norm, start_idx, labels);
        }

        if matched && labels > best_labels {
            best_labels = labels;
            best_start = start_idx;
            best_sec = rule.section;
            found = true;
        }
    }

    if found {
        out_start = best_start;
        out_sec = best_sec;
        return true;
    }
    return false;
}

// Evaluates custom exception rules in `db.rules` against `norm`.
//
// Example:
//   norm = "www.ck" -> returns "ck", true, true (when !www.ck rule exists in db.rules)
fn psl_find_custom_exception(db: const PslDatabase&, norm: const u8[:]) -> const u8[:], bool, bool {
    for &rule in db.rules {
        let exc_suffix = psl_match_exception(rule, norm);
        if exc_suffix.len > 0 {
            return exc_suffix, true, (rule.section == PslSection.Icann);
        }
    }
    return norm[0..0], false, false;
}

// Computes the Public Suffix for `domain` against `db` per Mozilla PSL specification.
// Returns (has_suffix, is_icann).
fn find_public_suffix<B>(db: const PslDatabase&, domain: const u8[:], out: B&) -> bool, bool {
    out.clear();
    let res, ok = match_public_suffix(db, domain);
    guard ok else { return false, false; }
    out.append(res.suffix[..]);
    return true, res.is_icann;
}

fn psl_find_known_suffix(db: const PslDatabase&, norm: const u8[:]) -> const u8[:], bool, bool {
    let exc_suf, exc_ok, exc_icann = psl_find_custom_exception(db, norm);
    if exc_ok {
        return exc_suf, true, exc_icann;
    }
    var dafsa_suf = norm[0..0];
    var dafsa_matched = false;
    var dafsa_icann = false;
    var dafsa_is_exc = false;
    if db.use_dafsa {
        let ds, dm, di, de = dafsa_find_public_suffix(norm);
        dafsa_suf = ds;
        dafsa_matched = dm;
        dafsa_icann = di;
        dafsa_is_exc = de;
    }
    if dafsa_matched && dafsa_is_exc {
        return dafsa_suf, true, dafsa_icann;
    }
    var best_start: i64 = 0;
    var best_sec = PslSection.Icann;
    if psl_find_best_rule(db, norm, best_start, best_sec) {
        let custom_suf = norm[best_start..];
        if dafsa_matched && dafsa_suf.len > custom_suf.len {
            return dafsa_suf, true, dafsa_icann;
        }
        return custom_suf, true, (best_sec == PslSection.Icann);
    }
    if dafsa_matched {
        return dafsa_suf, true, dafsa_icann;
    }
    return norm[0..0], false, false;
}

// Evaluates `domain` against `db` and returns a `PslMatch` distinguishing explicitly listed
// suffixes (`is_known == true`) from the implicit `*` fallback rule (`is_known == false`).
fn match_public_suffix(db: const PslDatabase&, domain: const u8[:]) -> PslMatch, bool {
    var m = PslMatch { .. };
    var norm_buf: u8[..256] = [];
    guard psl_normalize_domain(domain, norm_buf) else { return m, false; }
    let norm = norm_buf[..];
    guard !core::is_ip_address_literal(norm) else { return m, false; }

    let known_suf, matched_known, is_icann = psl_find_known_suffix(db, norm);
    if matched_known {
        let _ = m.suffix.try_set(known_suf);
        m.is_known = true;
        m.is_icann = is_icann;
        m.is_private = !is_icann;
    } else {
        let last_dot = core::last_index_of_byte(norm, '.');
        let next_dot = core::add_sat_i64(last_dot, 1);
        let tld_start = if last_dot >= 0 { next_dot } else { 0 };
        let _ = m.suffix.try_set(norm[tld_start..]);
        m.is_known = false;
        m.is_icann = true;
        m.is_private = false;
    }

    if norm.len > m.suffix.len && core::count_byte(norm, '.') > 0 {
        let reg_start = psl_find_registrable_start(norm, m.suffix.len);
        if reg_start >= 0 && reg_start <= norm.len {
            let _ = m.registrable_domain.try_set(norm[reg_start..]);
        }
    }
    return m, true;
}

// Whether `domain` is an explicitly listed public suffix in `db` (`PSL_TYPE_NO_STAR_RULE` / `Suffix::is_known`),
// excluding synthetic fallback `*` matches on unknown TLDs or single-label intranet hosts.
fn is_known_public_suffix(db: const PslDatabase&, domain: const u8[:]) -> bool {
    var norm_buf: u8[..256] = [];
    guard psl_normalize_domain(domain, norm_buf) else { return false; }
    let norm = norm_buf[..];
    guard !core::is_ip_address_literal(norm) else { return false; }
    let m, ok = match_public_suffix(db, norm);
    guard ok && m.is_known && m.suffix.len > 0 else { return false; }
    return eq_ascii_fold(norm, m.suffix[..]);
}

// Whether domain is itself a public suffix in the database.
fn is_public_suffix(db: const PslDatabase&, domain: const u8[:], is_icann_only: bool = false) -> bool {
    var norm_buf: u8[..256] = [];
    if !psl_normalize_domain(domain, norm_buf) {
        return false;
    }
    let norm = norm_buf[..];
    if core::is_ip_address_literal(norm) { return false; }

    var suffix: u8[..256] = [];
    let ok, is_icann = find_public_suffix(db, norm, suffix);
    if !ok || suffix.len == 0 {
        return false;
    }
    if is_icann_only && !is_icann { return false; }

    return eq_ascii_fold(norm, suffix[..]);
}

fn psl_find_registrable_start(clean_host: const u8[:], suffix_len: i64) -> i64 {
    let host_len = clean_host.len;
    let min_needed = core::add_sat_i64(suffix_len, 1);
    if host_len <= min_needed {
        return 0;
    }
    let prefix_len = core::sub_sat_i64(host_len, min_needed);
    if prefix_len < 0 || prefix_len > host_len {
        return 0;
    }
    let prefix = clean_host[..prefix_len];
    let last_dot = core::last_index_of_byte(prefix, '.');
    let next_pos = core::add_sat_i64(last_dot, 1);
    if last_dot >= 0 {
        return next_pos;
    }
    return 0;
}

// Extracts the effective top-level domain plus one (eTLD+1 / registrable domain) using database.
//
// Example:
//   host = "sub.example.co.uk"
//   out = "example.co.uk"
fn extract_etld_plus_one<B>(db: const PslDatabase&, host: const u8[:], out: B&) {
    out.clear();
    var norm_buf: u8[..256] = [];
    guard psl_normalize_domain(host, norm_buf) else { return; }
    let clean_host = norm_buf[..];

    let has_dot = core::count_byte(clean_host, '.') > 0;
    guard has_dot && !core::is_ip_address_literal(clean_host) else {
        out.append(clean_host);
        return;
    }

    var suffix: u8[..256] = [];
    let ok, _ = find_public_suffix(db, clean_host, suffix);
    guard ok && suffix.len > 0 && !eq_ascii_fold(clean_host, suffix[..]) else {
        out.append(clean_host);
        return;
    }

    let start_pos = psl_find_registrable_start(clean_host, suffix.len);
    guard start_pos >= 0 && start_pos <= clean_host.len else {
        out.append(clean_host);
        return;
    }
    out.append(clean_host[start_pos..]);
}

// Extracts eTLD+1 from host using the full compiled DAFSA automaton.
fn psl_extract_etld_plus_one<B>(host: const u8[:], out: B&) {
    let db = PslDatabase { use_dafsa: true, .. };
    extract_etld_plus_one(db, host, out);
}

// ---- public suffix & rfc 6265 scoping api ----------------------------------

// Whether domain is a public suffix (cannot set domain cookies for it).
fn is_public_suffix_domain(domain: const u8[:]) -> bool {
    let clean_domain = core::trim_byte(domain, '.');
    guard clean_domain.len > 0 else { return false; }
    return psl_is_public_suffix(clean_domain);
}

// Matches host against cookie domain (RFC 6265 Section 5.1.3).
fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }

    let clean_host = core::trim_byte(core::trim_byte(core::trim_byte(host, '.'), '['), ']');
    let clean_domain = core::trim_byte(core::trim_byte(core::trim_byte(cookie_domain, '.'), '['), ']');

    if eq_ascii_fold(clean_host, clean_domain) {
        return true;
    }
    guard !core::is_ip_address_literal(clean_host) else { return false; }
    return core::ends_with_dot_suffix(clean_host, clean_domain);
}

// Overload taking an explicit PSL database: rejects cookie_domain if it is a public suffix
fn cookie_domain_match(db: const PslDatabase&, host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }
    guard !is_public_suffix(db, cookie_domain) else { return false; }
    return cookie_domain_match(host, cookie_domain);
}

// Computes the default cookie path from request URI path (RFC 6265 Section 5.1.4).
fn compute_default_cookie_path<B>(uri_path: const u8[:], out: B&) {
    out.clear();
    if uri_path.len == 0 || uri_path[0] != '/' {
        let _ = out.try_push('/');
        return;
    }
    let last_slash_idx = core::last_index_of_byte(uri_path, '/');
    if last_slash_idx <= 0 {
        let _ = out.try_push('/');
        return;
    }
    let bounded_len = min(last_slash_idx, out.cap);
    let prefix = if bounded_len < last_slash_idx {
        let prev_slash = core::last_index_of_byte(uri_path[..bounded_len], '/');
        if prev_slash > 0 { uri_path[..prev_slash] } else { "/" }
    } else {
        uri_path[..last_slash_idx]
    };
    let _ = out.try_set(prefix);
}

// Whether request path matches cookie path prefix (RFC 6265 Section 5.1.4).
fn cookie_path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool {
    let req = if req_path.len == 0 { "/" } else { req_path };
    let cpath = if cookie_path.len == 0 { "/" } else { cookie_path };

    if req == cpath { return true; }
    guard starts_with(req, cpath) else { return false; }
    if core::ends_with(cpath, "/") { return true; }
    return core::starts_with(req[cpath.len..], "/");
}

// ---- runtime updatable psl database ----------------------------------------

// Parses a Public Suffix List rule line into a PslRule.
//
// Example:
//   line = "*.co.uk", sec = PslSection.Icann
//   returns: true, out_rule.pattern = "co.uk"
fn parse_psl_rule_line(line: const u8[:], sec: PslSection, out_rule: PslRule&) -> bool {
    guard line.len > 0 && !(line.len >= 2 && line[0] == '/' && line[1] == '/') else { return false; }
    var is_exc = false;
    var is_wild = false;
    var pat = line;

    if starts_with(pat, "!") {
        is_exc = true;
        pat = pat[1..];
    } else if starts_with(pat, "*.") {
        is_wild = true;
        pat = pat[2..];
    }

    let r_type = if is_exc {
        PslRuleType.Exception
    } else if is_wild {
        PslRuleType.Wildcard
    } else {
        PslRuleType.Normal
    };

    out_rule = new_psl_rule(pat, r_type, sec);
    return true;
}

// Ingests official Mozilla public suffix list format, preserving ICANN vs Private sections.
fn update_with_list(db: PslDatabase&, psl_text: const u8[:]) {
    var current_section = PslSection.Icann;

    each_split(psl_text, '\n') { raw_line =>
        let line = trim(raw_line);
        if core::starts_with(line, "// ===BEGIN ICANN DOMAINS===") {
            current_section = PslSection.Icann;
        } else if core::starts_with(line, "// ===BEGIN PRIVATE DOMAINS===") {
            current_section = PslSection.Private;
        } else {
            var rule = PslRule { .. };
            if db.rules.len < db.rules.cap && parse_psl_rule_line(line, current_section, rule) {
                db.rules.push(rule);
            }
        }
    };
}
