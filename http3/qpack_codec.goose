// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Leaf QPACK primitive codecs, static/dynamic lookups, and syntax validators (RFC 9204).
namespace http3;

import std;
import core;
import rfc.h3_quic;
import http2.hpack;
import .internal;
import .types;

// ---- Static Table Lookup (RFC 9204 Appendix A) -----------------------------

// Returns static table entry at 0-based index (0..98).
fn get_qpack_static_field(idx: u64) -> QpackStaticEntry, bool {
    guard idx < rfc::QPACK_STATIC_TABLE_SIZE else {
        return QpackStaticEntry { .. }, false;
    }
    let row = h3_internal::QPACK_STATIC_TABLE[idx as i64];
    return QpackStaticEntry { name: row.name, val: row.val }, true;
}

// Searches static table for matching name and optional value via O(1) name-length bucket dispatch.
// Returns (0-based index, exact_value_match).
fn find_qpack_static_field(name: const u8[:], val: const u8[:]) -> u64, bool {
    let start, end = h3_internal::qpack_candidate_range(name.len);
    var matched_name_idx: u64 = 0;
    var name_found = false;
    var i = max(0, start);
    while i < end {
        let idx: i64 = min(h3_internal::QPACK_LENGTH_CANDIDATES[i] as i64, 98);
        let entry = h3_internal::QPACK_STATIC_TABLE[idx];
        if entry.name == name {
            if entry.val == val {
                return idx as u64, true;
            }
            if !name_found {
                matched_name_idx = idx as u64;
                name_found = true;
            }
        }
        i = core::add_sat_i64(i, 1);
    }
    return matched_name_idx, false;
}

// ---- Prefix Integer, RIC, Base, and String Codecs --------------------------

// Decodes a QPACK prefixed integer up to 62 bits (RFC 9204 Section 4.1.1).
// Returns (value, next_offset, ok).
// Guarantees zero allocation, 62-bit boundary checks, and overflow detection.
//
// Example:
//   src = [0x0A], offset = 0, prefix_bits = 5
//   returns: 10, 1, true
fn qpack_decode_int(src: const u8[:], offset: u64, prefix_bits: u8) -> u64, u64, bool {
    guard offset < (src.len as u64) else { return 0, offset, false; }
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return 0, offset, false; }

    let mask = (((1 as u32) << prefix_bits) - 1) as u8;
    var val = (src[offset] & mask) as u64;
    var idx = offset + 1;

    if val < mask {
        return val, idx, true;
    }

    // Multibyte continuation (RFC 7541 Section 5.1 & RFC 9204 Section 4.1.1)
    var shift: u32 = 0;
    while idx < (src.len as u64) {
        let b = src[idx];
        let payload = (b & 0x7F) as u64;

        // Up to 62 bits: maximum shift is 56
        if shift > 56 || (shift == 56 && (payload > 0x3F || (b & 0x80) != 0)) {
            return 0, idx, false; // Exceeds 62 bits: RFC 9204 §4.1.1 overflow
        }

        let term = payload << shift;
        if (rfc::QUIC_VARINT_MAX - val) < term {
            return 0, idx, false; // Overflow beyond 2^62 - 1
        }
        val += term;
        idx++;

        if (b & 0x80) == 0 {
            return val, idx, true;
        }
        shift += 7;
    }

    return 0, offset, false;
}

// Decodes Required Insert Count per RFC 9204 Section 4.5.1.1.
//
// Example:
//   enc_ric = 0, total_inserts = 0, max_cap = 4096
//   returns: 0, QpackError.None
fn decode_ric(enc_ric: u64, total_inserts: u64, max_cap: u64) -> u64, QpackError {
    if enc_ric == 0 {
        return 0, QpackError.None;
    }
    let max_entries = max_cap / rfc::QPACK_ENTRY_OVERHEAD;
    let full_range = 2 * max_entries;
    guard full_range > 0 && enc_ric <= full_range else {
        return 0, QpackError.DecompressionFailed;
    }
    guard (0xFFFFFFFFFFFFFFFF - total_inserts) >= max_entries else {
        return 0, QpackError.DecompressionFailed;
    }
    let max_value = total_inserts + max_entries;
    let max_wrapped = (max_value / full_range) * full_range;
    guard (0xFFFFFFFFFFFFFFFF - max_wrapped) >= (enc_ric - 1) else {
        return 0, QpackError.DecompressionFailed;
    }
    var ric = max_wrapped + enc_ric - 1;

    if ric > max_value {
        guard ric > full_range else {
            return 0, QpackError.DecompressionFailed;
        }
        ric -= full_range;
    }
    guard ric != 0 && ric <= 0x3FFFFFFFFFFFFFFF else {
        return 0, QpackError.DecompressionFailed;
    }
    return ric, QpackError.None;
}

// Encodes Required Insert Count per RFC 9204 Section 4.5.1.1.
fn encode_ric(ric: u64, max_cap: u64) -> u64 {
    if ric == 0 {
        return 0;
    }
    let max_entries = max_cap / rfc::QPACK_ENTRY_OVERHEAD;
    let full_range = 2 * max_entries;
    if full_range == 0 {
        return 0;
    }
    return (ric % full_range) + 1;
}

// Decodes Base index from sign bit S and DeltaBase (RFC 9204 Section 4.5.1.2).
// RFC 9204 §4.5.1.2: If Required Insert Count is 0, any non-negative Base is valid.
// Sign bit 1 is invalid when RIC is 0 since Base would be negative.
//
// Example:
//   sign_bit = 0, delta_base = 0, ric = 0
//   returns: 0, QpackError.None
fn decode_base(sign_bit: u8, delta_base: u64, ric: u64) -> u64, QpackError {
    guard sign_bit == 0 || sign_bit == 1 else {
        return 0, QpackError.DecompressionFailed;
    }
    if ric == 0 {
        guard sign_bit == 0 else {
            return 0, QpackError.DecompressionFailed;
        }
        guard delta_base <= 0x3FFFFFFFFFFFFFFF else {
            return 0, QpackError.DecompressionFailed;
        }
        return delta_base, QpackError.None;
    }
    if sign_bit == 0 {
        guard (0xFFFFFFFFFFFFFFFF - ric) >= delta_base else {
            return 0, QpackError.DecompressionFailed;
        }
        let base = ric + delta_base;
        guard base <= 0x3FFFFFFFFFFFFFFF else {
            return 0, QpackError.DecompressionFailed;
        }
        return base, QpackError.None;
    }
    guard ric > delta_base else {
        return 0, QpackError.DecompressionFailed;
    }
    return ric - delta_base - 1, QpackError.None;
}

// Encodes Base index relative to RIC into sign bit and DeltaBase.
fn encode_base(base: u64, ric: u64) -> u8, u64 {
    if ric == 0 {
        return 0, 0;
    }
    if base >= ric {
        return 0, base - ric;
    }
    return 1, ric - base - 1;
}

// Decodes string literal with Huffman or raw octets (RFC 9204 Section 4.1.2).
//
// Example:
//   src = [0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F], offset = 0, prefix_bits = 7, out = []
//   returns: 6, true, out = "hello"
fn decode_qpack_string<B>(src: const u8[:], offset: u64, prefix_bits: u8, out: B&) -> u64, bool {
    guard offset < (src.len as u64) else { return offset, false; }
    let is_huff = (src[offset] & ((1 as u8) << prefix_bits)) != 0;
    let str_len, next_off, ok_len = qpack_decode_int(src, offset, prefix_bits);
    guard ok_len else { return offset, false; }

    let noff = next_off as i64;
    let slen = str_len as i64;
    guard noff >= 0 && slen >= 0 && noff <= (src.len - slen) else { return offset, false; }

    let raw_slice = src[noff..noff + slen];
    if is_huff {
        let ok_huff = http2::huff_decode_bytes(raw_slice, out);
        guard ok_huff else { return offset, false; }
    } else {
        guard out.try_append(raw_slice) else { return offset, false; }
    }
    return next_off + str_len, true;
}

// ---- Field Syntax Validation & Dynamic Table Zero-Copy Lookup --------------

fn validate_qpack_field_val(val: const u8[:]) -> bool {
    for b in val {
        if (b < 0x20 && b != '\t') || b == 0x7F {
            return false;
        }
    }
    if val.len > 0 {
        let first = val[0];
        let last = val[val.len - 1];
        if first == ' ' || first == '\t' || last == ' ' || last == '\t' {
            return false;
        }
    }
    return true;
}

fn validate_qpack_field_name(name: const u8[:]) -> bool {
    guard name.len > 0 && (name.len > 1 || name[0] != ':') else { return false; }
    for i in name.len {
        let c = name[i];
        if i == 0 && c == ':' {
            continue;
        }
        if !h3_internal::is_qpack_token_char(c) {
            return false;
        }
    }
    return true;
}

// Looks up an entry by absolute index in dynamic table, returning zero-copy slices into `tbl.arena`.
fn qpack_lookup_absolute(tbl: const QpackTable&, abs_idx: u64) -> const u8[:], const u8[:], bool {
    for &e in tbl.entries {
        if e.abs_index == abs_idx {
            let n_start = e.name_off as i64;
            let n_end = n_start + e.name_len;
            let v_start = e.val_off as i64;
            let v_end = v_start + e.val_len;
            guard n_end <= 16384 && v_end <= 16384 else { return "", "", false; }
            return tbl.arena[n_start..n_end], tbl.arena[v_start..v_end], true;
        }
    }
    return "", "", false;
}

inline fn try_push_header_field<F>(out_fields: F&, field: const HeaderField&) -> bool {
    return out_fields.try_push(field);
}

inline fn try_push_header_field(out_fields: HeaderField[>..]&, field: const HeaderField&) -> bool {
    out_fields.push(field);
    return true;
}

// Emits a parsed field line, enforcing SETTINGS_MAX_FIELD_SECTION_SIZE + 32-byte overhead.
fn emit_field_checked<F>(
    out_fields:  F&,
    budget_left: u64&,
    name:        const u8[:],
    val:         const u8[:],
    never_index: bool = false,
) -> QpackError {
    guard validate_qpack_field_name(name) && validate_qpack_field_val(val) else {
        return QpackError.DecompressionFailed;
    }
    let cost = h3_internal::qpack_entry_cost(name.len as u64, val.len as u64);
    guard out_fields.len < 128 && budget_left >= cost else { return QpackError.HeaderListTooLarge; }
    var field = HeaderField { never_index: never_index, .. };
    guard field.name.try_set(name) &&
          field.value.try_set(val) &&
          try_push_header_field(out_fields, field) else {
        return QpackError.HeaderListTooLarge;
    }
    budget_left -= cost;
    return QpackError.None;
}
