// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Fast query parameter scanner, percent decoding, and form URL-encoding.
namespace core;

import std;

fn percent_decode_query<B>(input_bytes: const u8[:], out: B&) -> bool {
    out.clear();
    var scan_idx: i64 = 0;
    let total = input_bytes.len;
    while scan_idx < total {
        let has_hex = input_bytes[scan_idx] == '%' && scan_idx + 2 < total;
        let hi = if has_hex { hex_digit_to_val(input_bytes[scan_idx + 1]) } else { -1 };
        let lo = if has_hex { hex_digit_to_val(input_bytes[scan_idx + 2]) } else { -1 };
        let is_esc = hi >= 0 && lo >= 0;
        let decoded_char = if is_esc { (((hi << 4) | lo) & 0xFF) as u8 } else { input_bytes[scan_idx] };
        guard out.try_push(decoded_char) else {
            out.clear();
            return false;
        }
        scan_idx += if is_esc { 3 } else { 1 };
    }
    return true;
}

// Sanitizes query input by stripping leading '?' and truncating at fragment '#'.
//
// Example:
//   raw = "?foo=bar#frag"
//   returns: "foo=bar", base = 1
fn sanitize_query_input(raw: const u8[:]) -> const u8[:], i64 {
    guard raw.len > 0 else { return "", 0; }
    let input_no_q, had_q = strip_prefix(raw, "?");
    var input = input_no_q;
    let base: i64 = if had_q { 1 } else { 0 };
    let hash_idx = index_of_byte(input, '#');
    if hash_idx >= 0 { input = input[..hash_idx]; }
    return input, base;
}

// ---- Fast Zero-Allocation Query Parameter Lookup (uWebSockets QueryParser) ---

enum QueryParamMatch {
    Missing,
    Valueless,
    Value,
}

inline fn query_key_matches(raw_stmt_key: const u8[:], key: const u8[:]) -> bool {
    if raw_stmt_key == key { return true; }
    guard contains_byte(raw_stmt_key, '%') else { return false; }
    var dec_key: u8[..64] = [];
    return percent_decode_query(raw_stmt_key, dec_key) && dec_key[..] == key;
}

inline fn match_query_statement(statement: const u8[:], key: const u8[:]) -> const u8[:], QueryParamMatch {
    let raw_key, raw_val, has_eq = statement.split_once_byte('=');
    let stmt_key = if has_eq { raw_key } else { statement };
    guard query_key_matches(stmt_key, key) else { return "", QueryParamMatch.Missing; }
    if has_eq { return raw_val, QueryParamMatch.Value; }
    return "", QueryParamMatch.Valueless;
}

fn find_raw_query_param(raw_query: const u8[:], key: const u8[:]) -> const u8[:], QueryParamMatch {
    guard key.len > 0 && raw_query.len > 0 else { return "", QueryParamMatch.Missing; }
    let q, _ = sanitize_query_input(raw_query);
    var rem = q;
    while rem.len > 0 {
        let statement, tail, has_amp = rem.split_once_byte('&');
        rem = if has_amp { tail } else { "" };
        guard statement.len > 0 else { continue; }
        let val, kind = match_query_statement(statement, key);
        if kind != QueryParamMatch.Missing { return val, kind; }
    }
    return "", QueryParamMatch.Missing;
}

// Fast zero-allocation query parameter lookup directly from raw query slice.
// Scans raw_query for key without allocating a QueryParamsList or parsing unrelated parameters.
// Returns QueryParamMatch.Value (and writes decoded value into out), QueryParamMatch.Valueless
// (clears out), or QueryParamMatch.Missing (not found or buffer overflow).
//
// Example:
//   raw_query = "?a=1&flag", key = "a" -> QueryParamMatch.Value, out = "1"
//   raw_query = "?a=1&flag", key = "flag" -> QueryParamMatch.Valueless, out = ""
//   raw_query = "?a=1&flag", key = "z" -> QueryParamMatch.Missing
fn get_query_param_fast<B>(raw_query: const u8[:], key: const u8[:], out: B&) -> QueryParamMatch {
    let raw_val, match_kind = find_raw_query_param(raw_query, key);
    if match_kind == QueryParamMatch.Valueless {
        out.clear();
        return QueryParamMatch.Valueless;
    }
    guard match_kind == QueryParamMatch.Value else { return QueryParamMatch.Missing; }
    guard percent_decode_query(raw_val, out) else {
        out.clear();
        return QueryParamMatch.Missing;
    }
    return QueryParamMatch.Value;
}

// Fast zero-allocation query parameter existence check.
fn has_query_param_fast(raw_query: const u8[:], key: const u8[:]) -> bool {
    let _, match_kind = find_raw_query_param(raw_query, key);
    return match_kind != QueryParamMatch.Missing;
}

// ---- Form URL-Encoding (WHATWG / RFC 6749 / RFC 7009 / RFC 7662) ------------

const UPPER_HEX_DIGITS: const u8[16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

inline fn is_form_urlencode_safe(b: u8) -> bool {
    return is_ascii_alphanumeric(b) || b == '-' || b == '.' || b == '_' || b == '*';
}

inline fn append_form_urlencoded(src: const u8[:], dst: u8[..1024]&) -> bool {
    var temp: u8[..1024] = [];
    let rem = sub_sat_i64(dst.cap, dst.len);
    for b in src {
        if b == ' ' || is_form_urlencode_safe(b) {
            guard temp.len < rem else { return false; }
            temp.push(if b == ' ' { '+' } else { b });
        } else {
            guard sub_sat_i64(rem, temp.len) >= 3 else { return false; }
            temp.push('%');
            temp.push(UPPER_HEX_DIGITS[(b >> 4) & 0x0F]);
            temp.push(UPPER_HEX_DIGITS[b & 0x0F]);
        }
    }
    dst.append(temp[..]);
    return true;
}

// Decodes an `application/x-www-form-urlencoded` slice into `out`.
//
// Example:
//   src = "a%3Ab+c"
//   returns: ok = true, out = "a:b c"
fn decode_form_urlencoded(src: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    var temp: u8[..256] = [];
    defer secure_zeroize_slice(temp[..]);
    var i: i64 = 0;
    let total = src.len;
    while i < total {
        let b = src[i];
        if b == '+' {
            guard temp.try_push(' ') else { return false; }
            i += 1;
        } else if b == '%' {
            guard i + 2 < total else { return false; }
            let hi = hex_digit_to_val(src[i + 1]);
            let lo = hex_digit_to_val(src[i + 2]);
            guard hi >= 0 && lo >= 0 else { return false; }
            let decoded = ((hi << 4) | lo) as u8;
            guard decoded != 0 && temp.try_push(decoded) else { return false; }
            i += 3;
        } else {
            guard b != 0 && temp.try_push(b) else { return false; }
            i += 1;
        }
    }
    out.append(temp[..]);
    return true;
}

inline fn needs_query_component_escape(b: u8) -> bool {
    if b <= 0x20 || b >= 0x7F { return true; }
    return b == '&' || b == '=' || b == '#' || b == '+' || b == '%';
}

// Escapes special delimiters and control characters in a query parameter component (RFC 3986 §3.4).
// Rolls back `out` to its original length if buffer capacity is exceeded.
//
// Example:
//   raw = "a&b=c", out = []
//   returns: true, out = "a%26b%3Dc"
fn append_query_component<B>(raw: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    for b in raw {
        if needs_query_component_escape(b) {
            guard out.try_push('%') else { return false; }
            guard out.try_push(UPPER_HEX_DIGITS[((b >> 4) & 0x0F) as i64]) else { return false; }
            guard out.try_push(UPPER_HEX_DIGITS[(b & 0x0F) as i64]) else { return false; }
        } else {
            guard out.try_push(b) else { return false; }
        }
    }
    committed = true;
    return true;
}
