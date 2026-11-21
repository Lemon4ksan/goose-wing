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

// Finds the next '&' delimiter starting at `start` using 64-bit SWAR word scanning.
//
// Example:
//   s = "foo=bar&baz=qux", start = 0
//   returns: 7 (points to '&')
inline fn find_next_ampersand(s: const u8[:], start: i64) -> i64 {
    var i = start;
    while i + 8 <= s.len {
        let w = read_le_u64(s, i);
        if swar_has_byte(w, '&') {
            break;
        }
        i += 8;
    }
    while i < s.len {
        if s[i] == '&' {
            return i;
        }
        i++;
    }
    return s.len;
}

// Finds the first '=' in `s` using 64-bit SWAR word scanning.
// Returns 0-based index or -1 if not found.
//
// Example:
//   s = "foo=bar"
//   returns: 3
inline fn find_first_equals(s: const u8[:]) -> i64 {
    var i: i64 = 0;
    while i + 8 <= s.len {
        let w = read_le_u64(s, i);
        if swar_has_byte(w, '=') {
            break;
        }
        i += 8;
    }
    while i < s.len {
        if s[i] == '=' {
            return i;
        }
        i++;
    }
    return -1;
}

// Scans `s` for presence of percent-encoding character '%' using SWAR.
inline fn slice_has_percent(s: const u8[:]) -> bool {
    var i: i64 = 0;
    while i + 8 <= s.len {
        let w = read_le_u64(s, i);
        if swar_has_byte(w, '%') {
            return true;
        }
        i += 8;
    }
    while i < s.len {
        if s[i] == '%' {
            return true;
        }
        i++;
    }
    return false;
}

fn percent_decode_query<B>(input_bytes: const u8[:], out: B&) -> bool {
    out.clear();
    var scan_idx: i64 = 0;
    while scan_idx < input_bytes.len {
        let idx1 = add_sat_i64(scan_idx, 1);
        let idx2 = add_sat_i64(scan_idx, 2);
        let has_hex = input_bytes[scan_idx] == '%' && idx2 < input_bytes.len;
        let hi = if has_hex { hex_digit_to_val(input_bytes[idx1]) } else { -1 };
        let lo = if has_hex { hex_digit_to_val(input_bytes[idx2]) } else { -1 };
        let is_esc = hi >= 0 && lo >= 0;
        let decoded_char = if is_esc { (((hi << 4) | lo) & 0xFF) as u8 } else { input_bytes[scan_idx] };
        guard out.try_push(decoded_char) else {
            out.clear();
            return false;
        }
        let step: i64 = if is_esc { 3 } else { 1 };
        scan_idx = add_sat_i64(scan_idx, step);
    }
    return true;
}

// Sanitizes query input by stripping leading '?' and truncating at fragment '#'.
//
// Example:
//   raw = "?foo=bar#frag"
//   returns: "foo=bar", base = 1
inline fn sanitize_query_input(raw: const u8[:]) -> const u8[:], i64 {
    guard raw.len > 0 else { return "", 0; }
    let input_no_q, had_q = strip_prefix(raw, "?");
    var input = input_no_q;
    let base: i64 = if had_q { 1 } else { 0 };
    let hash_idx = core::index_of_byte(input, '#');
    if hash_idx >= 0 {
        input = input[..hash_idx];
    }
    return input, base;
}

// Extracts a single 64-bit query token descriptor from pair slice.
// Returns (token, is_overflow).
//
// Example:
//   pair = "key=val", base_offset = 1, start = 0
//   returns: tok (pack offset 1, k_len 3, v_len 3), is_overflow = false
inline fn extract_token_descriptor(
    pair:        const u8[:],
    base_offset: i64,
    start:       i64,
) -> u64, bool {
    let eq_pos = find_first_equals(pair);
    let has_esc = slice_has_percent(pair);
    let flags: u64 = if has_esc { QUERY_TOKEN_FLAG_ESCAPE } else { 0 };
    let key_off = add_sat_i64(base_offset, start);
    let off_over = key_off < 0 || key_off > 0x3FFFFFFF;

    if eq_pos < 0 {
        let is_over = off_over || (pair.len > MAX_URL_QUERY_KEY_LIMIT) || (pair.len > 0xFFFF);
        let k_len = min(pair.len, 0xFFFF);
        let tok = pack_query_token(key_off, k_len, 0, flags | QUERY_TOKEN_FLAG_VALUELESS);
        return tok, is_over;
    }

    let k_raw = eq_pos;
    let v_raw = pair.len - (eq_pos + 1);
    let is_over = off_over ||
        (k_raw > MAX_URL_QUERY_KEY_LIMIT) ||
        (v_raw > MAX_URL_QUERY_VAL_LIMIT) ||
        (k_raw > 0xFFFF) ||
        (v_raw > 0xFFFF);
    let k_len = min(k_raw, 0xFFFF);
    let v_len = min(v_raw, 0xFFFF);
    let tok = pack_query_token(key_off, k_len, v_len, flags);
    return tok, is_over;
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
    guard input.len > 0 else { return res; }

    var start: i64 = 0;
    while start < input.len {
        if res.tokens.len >= res.tokens.cap {
            res.overflow = true;
            break;
        }
        let end = find_next_ampersand(input, start);
        let pair = input[start..end];
        let token_start = start;
        start = end + 1;
        guard pair.len > 0 else { continue; }

        let tok, is_over = extract_token_descriptor(pair, base_offset, token_start);
        if is_over {
            res.overflow = true;
            let key_off = add_sat_i64(base_offset, token_start);
            if key_off > 0x3FFFFFFF || pair.len > 0xFFFF {
                continue;
            }
        }
        res.tokens.push(tok);
    }
    return res;
}

// Retrieves the first parameter value slice for given key from QueryTokens.
// Fast path performs direct zero-copy byte slice comparison.
// Fallback matches percent-encoded wire keys against plain ASCII search keys.
fn get_query_param(tokens: const QueryTokens&, key_str: const u8[:]) -> const u8[:] {
    for tok in tokens.tokens {
        let raw_key = query_token_key(tok, tokens.wire);
        var matches = false;
        if query_token_has_escape(tok) && (contains_byte(raw_key, '%') || contains_byte(raw_key, '+')) {
            var dec_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_key, dec_key);
            matches = dec_ok && (dec_key[..] == key_str);
        } else {
            matches = (raw_key == key_str);
        }
        if matches {
            return query_token_val(tok, tokens.wire);
        }
    }
    return "";
}

// Checks if QueryTokens contains a parameter for given key.
fn has_query_param(tokens: const QueryTokens&, key_str: const u8[:]) -> bool {
    for tok in tokens.tokens {
        let raw_key = query_token_key(tok, tokens.wire);
        var matches = false;
        if query_token_has_escape(tok) && (contains_byte(raw_key, '%') || contains_byte(raw_key, '+')) {
            var dec_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_key, dec_key);
            matches = dec_ok && (dec_key[..] == key_str);
        } else {
            matches = (raw_key == key_str);
        }
        if matches {
            return true;
        }
    }
    return false;
}

// Retrieves and percent-decodes parameter value for given key into caller-provided buffer `out`.
// Returns true if key was found and successfully decoded.
fn get_query_param_decoded<B>(tokens: const QueryTokens&, key_str: const u8[:], out: B&) -> bool {
    out.clear();
    for tok in tokens.tokens {
        let raw_key = query_token_key(tok, tokens.wire);
        var matches = false;
        if query_token_has_escape(tok) && (contains_byte(raw_key, '%') || contains_byte(raw_key, '+')) {
            var dec_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_key, dec_key);
            matches = dec_ok && (dec_key[..] == key_str);
        } else {
            matches = (raw_key == key_str);
        }
        if matches {
            if query_token_is_valueless(tok) {
                return true;
            }
            let raw_val = query_token_val(tok, tokens.wire);
            return percent_decode_query(raw_val, out);
        }
    }
    return false;
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
    guard key.len > 0 && raw_query.len > 0 else { return QueryParamMatch.Missing; }

    var q = raw_query;
    if q[0] == '?' {
        q = q[1..];
    }
    let hash_idx = core::index_of_byte(q, '#');
    if hash_idx >= 0 {
        q = q[..hash_idx];
    }

    var cursor: i64 = 0;
    while cursor < q.len {
        var end = q.len;
        let amp_pos = core::index_of_byte(q[cursor..], '&');
        if amp_pos >= 0 {
            end = cursor + amp_pos;
        }

        let statement = q[cursor..end];
        cursor = if amp_pos >= 0 { end + 1 } else { end };
        guard statement.len > 0 else { continue; }

        let eq_pos = core::index_of_byte(statement, '=');
        let raw_stmt_key = if eq_pos >= 0 { statement[..eq_pos] } else { statement };

        var matches = (raw_stmt_key == key);
        if !matches && core::index_of_byte(raw_stmt_key, '%') >= 0 {
            var decoded_stmt_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_stmt_key, decoded_stmt_key);
            matches = dec_ok && (decoded_stmt_key[..] == key);
        }

        if matches {
            if eq_pos < 0 {
                out.clear();
                return QueryParamMatch.Valueless;
            }
            let stmt_val = statement[eq_pos + 1..];
            out.clear();
            let dec_ok = percent_decode_query(stmt_val, out);
            guard dec_ok else {
                out.clear();
                return QueryParamMatch.Missing;
            }
            return QueryParamMatch.Value;
        }
    }
    return QueryParamMatch.Missing;
}

// Fast zero-allocation query parameter existence check.
fn has_query_param_fast(raw_query: const u8[:], key: const u8[:]) -> bool {
    guard key.len > 0 && raw_query.len > 0 else { return false; }

    var q = raw_query;
    if q[0] == '?' {
        q = q[1..];
    }
    let hash_idx = core::index_of_byte(q, '#');
    if hash_idx >= 0 {
        q = q[..hash_idx];
    }

    var cursor: i64 = 0;
    while cursor < q.len {
        var end = q.len;
        let amp_pos = core::index_of_byte(q[cursor..], '&');
        if amp_pos >= 0 {
            end = cursor + amp_pos;
        }

        let statement = q[cursor..end];
        cursor = if amp_pos >= 0 { end + 1 } else { end };
        guard statement.len > 0 else { continue; }

        let eq_pos = core::index_of_byte(statement, '=');
        let raw_stmt_key = if eq_pos >= 0 { statement[..eq_pos] } else { statement };

        var matches = (raw_stmt_key == key);
        if !matches && core::index_of_byte(raw_stmt_key, '%') >= 0 {
            var decoded_stmt_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_stmt_key, decoded_stmt_key);
            matches = dec_ok && (decoded_stmt_key[..] == key);
        }

        if matches {
            return true;
        }
    }
    return false;
}

// ---- Form URL-Encoding (WHATWG / RFC 6749 / RFC 7009 / RFC 7662) ------------

const UPPER_HEX_DIGITS: const u8[16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

const FORM_HEX_NIBBLE_LUT: const u8[256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

const FORM_HEX_HI_LUT: const u8[256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 255, 255, 255, 255, 255, 255,
    255, 160, 176, 192, 208, 224, 240, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 160, 176, 192, 208, 224, 240, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

inline fn is_form_urlencode_safe(b: u8) -> bool {
    if b >= 'A' && b <= 'Z' { return true; }
    if b >= 'a' && b <= 'z' { return true; }
    if b >= '0' && b <= '9' { return true; }
    return b == '-' || b == '.' || b == '_' || b == '*';
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
            temp.push(UPPER_HEX_DIGITS[((b >> 4) & 0x0F) as i64]);
            temp.push(UPPER_HEX_DIGITS[(b & 0x0F) as i64]);
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
inline fn decode_form_urlencoded(src: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    var temp: u8[..256] = [];
    defer secure_zeroize_slice(temp[..]);
    var i: i64 = 0;
    while i < src.len {
        let b = src[i];
        if b == '+' {
            guard temp.try_push(' ') else { return false; }
            i = add_sat_i64(i, 1);
        } else if b == '%' {
            let i1 = add_sat_i64(i, 1);
            let i2 = add_sat_i64(i, 2);
            guard i2 < src.len else { return false; }
            let hi = FORM_HEX_HI_LUT[src[i1]];
            let lo = FORM_HEX_NIBBLE_LUT[src[i2]];
            guard hi != 255 && lo <= 15 else { return false; }
            let decoded = hi | lo;
            guard decoded != 0 && temp.try_push(decoded) else { return false; }
            i = add_sat_i64(i, 3);
        } else {
            guard b != 0 && temp.try_push(b) else { return false; }
            i = add_sat_i64(i, 1);
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
