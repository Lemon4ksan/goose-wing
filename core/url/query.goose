// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// core/url/query.goose
// WHATWG search parameter tokenizer, percent decoding, and SWAR parameter scanner.
namespace core;

import std;

// ---- query parameter parsing & whatwg search params -------------------------

const MAX_URL_QUERY_PARAMS_LIMIT: i64 = 128;
const MAX_URL_QUERY_KEY_LIMIT:    i64 = 64;
const MAX_URL_QUERY_VAL_LIMIT:    i64 = 256;
const MAX_URL_QUERY_TOKEN_LIMIT:  i64 = 256;

const QUERY_TOKEN_FLAG_ESCAPE:    u64 = (1 as u64) << 63;
const QUERY_TOKEN_FLAG_VALUELESS: u64 = (1 as u64) << 62;

// Zero-copy URL query tokens container (RFC 3986 §3.4).
// Memory footprint: ~1048 bytes on stack (1 KB) instead of legacy ~43 KB.
struct QueryTokens {
    wire:     const u8[:] = "",
    tokens:   u64[..128]  = [],
    overflow: bool        = false,
}

// Packs a zero-copy query parameter descriptor into a single 64-bit integer.
//
// Layout:
//   Bit 63:     has_escape (percent character detected)
//   Bit 62:     is_valueless (no '=' delimiter present)
//   Bits 32..61: key_offset (up to 1GB wire offset)
//   Bits 16..31: key_len (up to 64KB)
//   Bits 0..15:  val_len (up to 64KB)
inline fn pack_query_token(
    key_offset: i64,
    key_len:    i64,
    val_len:    i64,
    flags:      u64,
) -> u64 {
    let off_part:  u64 = ((key_offset as u64) & 0x3FFFFFFF) << 32;
    let klen_part: u64 = ((key_len as u64) & 0xFFFF) << 16;
    let vlen_part: u64 = (val_len as u64) & 0xFFFF;
    return flags | off_part | klen_part | vlen_part;
}

inline fn query_token_offset(tok: u64) -> i64 {
    return ((tok >> 32) & 0x3FFFFFFF) as i64;
}

inline fn query_token_key_len(tok: u64) -> i64 {
    return ((tok >> 16) & 0xFFFF) as i64;
}

inline fn query_token_val_len(tok: u64) -> i64 {
    return (tok & 0xFFFF) as i64;
}

inline fn query_token_is_valueless(tok: u64) -> bool {
    return (tok & QUERY_TOKEN_FLAG_VALUELESS) != 0;
}

inline fn query_token_has_escape(tok: u64) -> bool {
    return (tok & QUERY_TOKEN_FLAG_ESCAPE) != 0;
}

// Extracts zero-copy key slice from backing wire buffer.
// crap:trusted
inline fn query_token_key(tok: u64, wire: const u8[:]) -> const u8[:] {
    let off = query_token_offset(tok);
    let len = query_token_key_len(tok);
    guard off >= 0 && off + len <= wire.len else { return ""; }
    return wire[off..off + len];
}

// Extracts zero-copy value slice from backing wire buffer.
// Computes val_offset as (key_offset + key_len + 1).
// crap:trusted
inline fn query_token_val(tok: u64, wire: const u8[:]) -> const u8[:] {
    guard !query_token_is_valueless(tok) else { return ""; }
    let off = query_token_offset(tok);
    let klen = query_token_key_len(tok);
    let vlen = query_token_val_len(tok);
    let val_off = off + klen + 1;
    guard val_off >= 0 && val_off + vlen <= wire.len else { return ""; }
    return wire[val_off..val_off + vlen];
}

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

// Extracts a single 64-bit query token descriptor from pair slice.
// Returns (token, is_overflow).
//
// Example:
//   pair = "key=val", base_offset = 1, start = 0
//   returns: tok (pack offset 1, k_len 3, v_len 3), is_overflow = false
fn extract_token_descriptor(
    pair:        const u8[:],
    base_offset: i64,
    start:       i64,
) -> u64, bool {
    let eq_pos = index_of_byte(pair, '=');
    let flags: u64 = if contains_byte(pair, '%') { QUERY_TOKEN_FLAG_ESCAPE } else { 0 };
    let key_off = base_offset + start;
    let off_over = key_off < 0 || key_off > 0x3FFFFFFF;

    if eq_pos < 0 {
        let is_over = off_over || pair.len > MAX_URL_QUERY_KEY_LIMIT || pair.len > 0xFFFF;
        return pack_query_token(key_off, min(pair.len, 0xFFFF), 0, flags | QUERY_TOKEN_FLAG_VALUELESS), is_over;
    }

    let k_raw = eq_pos;
    let v_raw = pair.len - (eq_pos + 1);
    let is_over = off_over || k_raw > MAX_URL_QUERY_KEY_LIMIT || v_raw > MAX_URL_QUERY_VAL_LIMIT
        || k_raw > 0xFFFF || v_raw > 0xFFFF;
    return pack_query_token(key_off, min(k_raw, 0xFFFF), min(v_raw, 0xFFFF), flags), is_over;
}

// Parses a wire query string into zero-copy 64-bit token descriptors (RFC 3986 §3.4).
// Only '&' is treated as a parameter delimiter; ';' is kept as literal content (CVE-2021-31525).
// Truncates query string at '#' fragment delimiter.
//
// Example:
//   raw_search = "?foo=bar&baz=qux"
//   returns: QueryTokens with 2 tokens: ("foo", "bar"), ("baz", "qux")
fn parse_query_params(raw_search: const u8[:]) -> QueryTokens {
    var res = QueryTokens { wire: raw_search, .. };
    let input, base_offset = sanitize_query_input(raw_search);
    let total = input.len;
    guard total > 0 else { return res; }

    var start: i64 = 0;
    while start < total {
        if res.tokens.len >= res.tokens.cap {
            res.overflow = true;
            break;
        }
        let rel = index_of_byte(input[start..], '&');
        let end = if rel >= 0 { start + rel } else { total };
        let pair = input[start..end];
        let token_start = start;
        start = end + 1;
        guard pair.len > 0 else { continue; }

        let tok, is_over = extract_token_descriptor(pair, base_offset, token_start);
        if is_over {
            res.overflow = true;
            if base_offset + token_start > 0x3FFFFFFF || pair.len > 0xFFFF { continue; }
        }
        res.tokens.push(tok);
    }
    return res;
}

fn find_query_token(tokens: const QueryTokens&, key_str: const u8[:]) -> u64, bool {
    for tok in tokens.tokens {
        let raw_key = query_token_key(tok, tokens.wire);
        if query_token_has_escape(tok) && (contains_byte(raw_key, '%') || contains_byte(raw_key, '+')) {
            var dec_key: u8[..64] = [];
            if percent_decode_query(raw_key, dec_key) && dec_key[..] == key_str {
                return tok, true;
            }
        } else if raw_key == key_str {
            return tok, true;
        }
    }
    return 0, false;
}

// Retrieves the first parameter value slice for given key from QueryTokens.
// Fast path performs direct zero-copy byte slice comparison.
// Fallback matches percent-encoded wire keys against plain ASCII search keys.
fn get_query_param(tokens: const QueryTokens&, key_str: const u8[:]) -> const u8[:] {
    let tok, ok = find_query_token(tokens, key_str);
    return if ok { query_token_val(tok, tokens.wire) } else { "" };
}

// Checks if QueryTokens contains a parameter for given key.
fn has_query_param(tokens: const QueryTokens&, key_str: const u8[:]) -> bool {
    let _, ok = find_query_token(tokens, key_str);
    return ok;
}

// Retrieves and percent-decodes parameter value for given key into caller-provided buffer `out`.
// Returns true if key was found and successfully decoded.
fn get_query_param_decoded<B>(tokens: const QueryTokens&, key_str: const u8[:], out: B&) -> bool {
    out.clear();
    let tok, ok = find_query_token(tokens, key_str);
    guard ok else { return false; }
    if query_token_is_valueless(tok) { return true; }
    return percent_decode_query(query_token_val(tok, tokens.wire), out);
}

// CVE-2026-39825 & CVE-2025-61726 defense: Count query parameters separated by '&',
// verify total count does not exceed limit, and enforce per-token length limit (256 bytes)
// to prevent fixed-buffer parser overflow.
fn validate_query_param_count(query: const u8[:], max_allowed: i64 = MAX_URL_QUERY_PARAMS_LIMIT) -> bool {
    guard query.len > 0 else { return true; }
    var q = query;
    if q[0] == '?' {
        q = q[1..];
    }
    let hash_idx = core::index_of_byte(q, '#');
    if hash_idx >= 0 {
        q = q[..hash_idx];
    }
    guard q.len > 0 else { return true; }
    guard max_allowed >= 1 else { return false; }
    var count:     i64 = 1;
    var token_len: i64 = 0;
    for b in q {
        if b == '&' {
            if token_len > MAX_URL_QUERY_TOKEN_LIMIT {
                return false;
            }
            token_len = 0;
            count++;
            if count > max_allowed {
                return false;
            }
        } else {
            token_len++;
            if token_len > MAX_URL_QUERY_TOKEN_LIMIT {
                return false;
            }
        }
    }
    if token_len > MAX_URL_QUERY_TOKEN_LIMIT {
        return false;
    }
    return true;
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
