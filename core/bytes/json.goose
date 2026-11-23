// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation RFC 8259 JSON string escaping, formatting, and bounded reader primitives.
// Bridges stdlib `json::Reader` and `json::scan_string` onto stack-bounded `u8[..N]` buffers
// without allocating intermediate `u8[>..]` scratch arenas on hot paths.
namespace core;

import std;
import json;
import core.math;
import core.bytes.parse;
import core.bytes.format;

// Returns true if `s` contains no characters requiring RFC 8259 §7 JSON string escaping.
inline fn is_json_plain_string(s: const u8[:]) -> bool {
    for c in s {
        if c < 0x20 || c == '"' || c == '\\' { return false; }
    }
    return true;
}

// Appends `s` to `out` with RFC 8259 §7 escape sequences (without surrounding quotes).
//
// Example:
//   s = "hello \"world\"\n", out = ""
//   appends: hello \"world\"\n
fn escape_json_string<B>(s: const u8[:], out: B&) {
    let hex = "0123456789abcdef";
    for b in s {
        if b == '"' {
            out.append("\\\"");
        } else if b == '\\' {
            out.append("\\\\");
        } else if b == '\r' {
            out.append("\\r");
        } else if b == '\n' {
            out.append("\\n");
        } else if b == '\t' {
            out.append("\\t");
        } else if b == 8 {
            out.append("\\b");
        } else if b == 12 {
            out.append("\\f");
        } else if b < 0x20 {
            out.append("\\u00");
            out.push(hex[(b >> 4) as i64]);
            out.push(hex[(b & 0x0F) as i64]);
        } else {
            out.push(b);
        }
    }
}

// Formats `s` as a double-quoted RFC 8259 §7 JSON string into any appendable buffer `out`.
//
// Example:
//   s = "ok", out = ""
//   appends: "ok"
fn format_json_string<B>(out: B&, s: const u8[:]) {
    out.push('"');
    if is_json_plain_string(s) {
        out.append(s);
    } else {
        escape_json_string(s, out);
    }
    out.push('"');
}

// Formats `key` as a double-quoted JSON object member name followed by ':' into `out`.
//
// Example:
//   key = "status", out = "{"
//   appends: {"status":
fn format_json_key<B>(out: B&, key: const u8[:]) {
    out.push('"');
    if is_json_plain_string(key) {
        out.append(key);
    } else {
        escape_json_string(key, out);
    }
    out.append("\":");
}

// Returns the 2-byte RFC 8259 §7 short escape sequence for `b`, or empty if none applies.
inline fn json_short_escape_seq(b: u8) -> const u8[:] {
    if b == '"' { return "\\\""; }
    if b == '\\' { return "\\\\"; }
    if b == '\r' { return "\\r"; }
    if b == '\n' { return "\\n"; }
    if b == '\t' { return "\\t"; }
    if b == 8 { return "\\b"; }
    if b == 12 { return "\\f"; }
    return "";
}

inline fn try_escape_json_byte<B>(b: u8, out: B&) -> bool {
    let seq = json_short_escape_seq(b);
    if seq.len > 0 {
        return out.try_append(seq);
    }
    if b < 0x20 {
        let hex = "0123456789abcdef";
        return out.try_append("\\u00") &&
            out.try_push(hex[(b >> 4) as i64]) &&
            out.try_push(hex[(b & 0x0F) as i64]);
    }
    return out.try_push(b);
}

// Fallibly appends `s` to `out` with RFC 8259 §7 escape sequences (without surrounding quotes).
// Rolls back `out` and returns false if capacity is exceeded.
fn try_escape_json_string<B>(s: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    for b in s {
        guard try_escape_json_byte(b, out) else { return false; }
    }
    committed = true;
    return true;
}

// Fallibly formats `s` as a double-quoted RFC 8259 §7 JSON string into `out`.
fn try_format_json_string<B>(out: B&, s: const u8[:]) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_push('"' as u8) else { return false; }
    if is_json_plain_string(s) {
        guard out.try_append(s) else { return false; }
    } else {
        guard try_escape_json_string(s, out) else { return false; }
    }
    guard out.try_push('"' as u8) else { return false; }
    committed = true;
    return true;
}

// Fallibly formats `key` as a double-quoted JSON object member name followed by ':' into `out`.
fn try_format_json_key<B>(out: B&, key: const u8[:]) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_push('"' as u8) else { return false; }
    if is_json_plain_string(key) {
        guard out.try_append(key) else { return false; }
    } else {
        guard try_escape_json_string(key, out) else { return false; }
    }
    guard out.try_append("\":") else { return false; }
    committed = true;
    return true;
}

// Fallibly formats a signed 64-bit integer as base-10 ASCII into `out`.
fn try_format_i64_dec<B>(val: i64, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_i64_dec(tmp);
    return out.try_append(tmp[..]);
}

// Encodes a Unicode scalar `cp` into 1..4 UTF-8 bytes without branches.
// crap:ignore
inline fn encode_utf8_scalar_bytes(cp: u32) -> u8, u8, u8, u8 {
    let b1 = (0xC0 | ((cp >> 6) & 0x1F)) as! u8;
    let b2_lead = (0xE0 | ((cp >> 12) & 0x0F)) as! u8;
    let b4_lead = (0xF0 | ((cp >> 18) & 0x07)) as! u8;
    let c1 = (0x80 | ((cp >> 12) & 0x3F)) as! u8;
    let c2 = (0x80 | ((cp >> 6) & 0x3F)) as! u8;
    let c3 = (0x80 | (cp & 0x3F)) as! u8;
    let lead = if cp < 0x80 {
        cp as! u8
    } else if cp < 0x800 {
        b1
    } else if cp < 0x10000 {
        b2_lead
    } else {
        b4_lead
    };
    let out1 = if cp < 0x800 { c3 } else if cp < 0x10000 { c2 } else { c1 };
    let out2 = if cp < 0x10000 { c3 } else { c2 };
    return lead, out1, out2, c3;
}

// Appends UTF-8 encoded bytes of Unicode scalar `cp` into bounded buffer `dst`.
// Returns false if `dst` lacks remaining capacity.
inline fn try_push_utf8_codepoint<B>(dst: B&, cp: u32) -> bool {
    let c = if cp > 0x10FFFF { 0xFFFD as u32 } else { cp };
    let b0, b1, b2, b3 = encode_utf8_scalar_bytes(c);
    let needed: i64 = if c < 0x80 {
        1
    } else if c < 0x800 {
        2
    } else if c < 0x10000 {
        3
    } else {
        4
    };
    guard add_sat_i64(dst.len, needed) <= dst.cap else { return false; }
    dst.push(b0);
    if needed >= 2 { dst.push(b1); }
    if needed >= 3 { dst.push(b2); }
    if needed == 4 { dst.push(b3); }
    return true;
}

// Packs four 4-bit hex digit values into a 16-bit code unit.
//
// Example:
//   d0 = 0, d1 = 0, d2 = 4, d3 = 1
//   returns: 65 (0x0041)
// crap:ignore
inline fn pack_hex4_u32(d0: i32, d1: i32, d2: i32, d3: i32) -> u32 {
    return ((d0 as! u32) << 12) | ((d1 as! u32) << 8) | ((d2 as! u32) << 4) | (d3 as! u32);
}

// Combines a UTF-16 high surrogate (0xD800..0xDBFF) and low surrogate (0xDC00..0xDFFF) into a scalar value.
// crap:ignore
inline fn combine_utf16_surrogates(hi: u32, lo: u32) -> u32 {
    return 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
}

// Parses 4 hexadecimal digits from `text[pos..pos + 4]` into a 16-bit code unit.
//
// Example:
//   text = "0041", pos = 0, end = 4
//   returns: 65, ok = true
inline fn parse_json_hex4(text: const u8[:], pos: i64, end: i64) -> u32, bool {
    guard add_sat_i64(pos, 4) <= end else { return 0, false; }
    let d0 = hex_digit_to_val(text[pos]);
    let d1 = hex_digit_to_val(text[add_sat_i64(pos, 1)]);
    let d2 = hex_digit_to_val(text[add_sat_i64(pos, 2)]);
    let d3 = hex_digit_to_val(text[add_sat_i64(pos, 3)]);
    guard (d0 | d1 | d2 | d3) >= 0 else { return 0, false; }
    return pack_hex4_u32(d0, d1, d2, d3), true;
}

// Maps single-character JSON escape `e` (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`) to its decoded byte.
inline fn map_json_short_escape(e: u8) -> u8, bool {
    if e == '"' || e == '\\' || e == '/' { return e, true; }
    if e == 'n' { return '\n', true; }
    if e == 't' { return '\t', true; }
    if e == 'r' { return '\r', true; }
    if e == 'b' { return 8, true; }
    if e == 'f' { return 12, true; }
    return 0, false;
}

// Decodes a `\uXXXX` escape (and optional UTF-16 low surrogate pair) starting at `text[pos]`.
//
// Example:
//   text = "0041", pos = 0, end = 4
//   returns: cp = 65, next_pos = 4, ok = true
inline fn decode_json_unicode_escape(text: const u8[:], pos: i64, end: i64) -> u32, i64, bool {
    let hi, ok_hi = parse_json_hex4(text, pos, end);
    guard ok_hi else { return 0, pos, false; }
    let after_hi = add_sat_i64(pos, 4);
    if hi < 0xD800 || hi > 0xDFFF {
        return hi, after_hi, true;
    }
    guard hi < 0xDC00 && add_sat_i64(after_hi, 6) <= end &&
          text[after_hi] == '\\' && text[add_sat_i64(after_hi, 1)] == 'u' else {
        return 0, pos, false;
    }
    let lo_start = add_sat_i64(after_hi, 2);
    let lo, ok_lo = parse_json_hex4(text, lo_start, end);
    guard ok_lo && lo >= 0xDC00 && lo <= 0xDFFF else { return 0, pos, false; }
    return combine_utf16_surrogates(hi, lo), add_sat_i64(after_hi, 6), true;
}

// Decodes an escaped JSON string body `text[at..end]` directly into bounded buffer `dst`.
// Returns false on malformed escape sequences or when `dst` capacity is exceeded.
//
// Example:
//   text = "hello \\\"world\\\"", at = 0, end = 15
//   returns: true, dst = "hello \"world\""
fn decode_json_string_into<B>(text: const u8[:], at: i64, end: i64, dst: B&) -> bool {
    dst.clear();
    guard at >= 0 && end >= at && end <= text.len else { return false; }
    var pos = at;
    while pos < end {
        let c = text[pos];
        pos = add_sat_i64(pos, 1);
        if c != '\\' {
            guard c >= 0x20 && c != '"' && dst.len < dst.cap else { dst.clear(); return false; }
            dst.push(c);
            continue;
        }
        guard pos < end else { dst.clear(); return false; }
        let e = text[pos];
        pos = add_sat_i64(pos, 1);
        if e == 'u' {
            let cp, next_pos, ok_u = decode_json_unicode_escape(text, pos, end);
            guard ok_u && try_push_utf8_codepoint(dst, cp) else { dst.clear(); return false; }
            pos = next_pos;
        } else {
            let decoded_b, ok_short = map_json_short_escape(e);
            guard ok_short && dst.len < dst.cap else { dst.clear(); return false; }
            dst.push(decoded_b);
        }
    }
    guard validate_utf8(dst[..]) else { dst.clear(); return false; }
    return true;
}

// Reads a JSON string token from `r` directly into bounded buffer `dst` without heap/data-stack scratch allocation.
// Unescaped strings copy in one slice operation; escaped strings decode in-place into `dst`.
// Returns false if the next token is not a valid string or exceeds `dst.cap` (leaving `r` advanced past the string).
//
// Example:
//   r at "\"HS256\"", dst: u8[..16]
//   returns: true, dst = "HS256"
fn read_json_string_into<B>(r: json::Reader&, dst: B&) -> bool {
    dst.clear();
    guard json::peek(r) == '"' else {
        json::fail(r, "expected a string");
        return false;
    }
    let start = add_sat_i64(r.pos, 1);
    let end, escaped = json::scan_string(r.text, start);
    guard end >= 0 else {
        json::fail(r, "bad string");
        return false;
    }
    r.pos = add_sat_i64(end, 1);
    if escaped {
        guard json::valid_escapes(r.text, start, end) else {
            r.pos = sub_sat_i64(start, 1);
            json::fail(r, "bad escape");
            return false;
        }
        return decode_json_string_into(r.text, start, end, dst);
    }
    let raw = r.text[start..end];
    guard validate_utf8(raw) else {
        json::fail(r, "invalid utf-8");
        return false;
    }
    guard raw.len <= dst.cap else { return false; }
    dst.append(raw);
    return true;
}
