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
    var scan_idx = 0;
    while scan_idx < input_bytes.len {
        guard out.len < out.cap else { return false; }
        let b = input_bytes[scan_idx];
        if b == '%' && scan_idx + 2 < input_bytes.len {
            let high_nibble = hex_digit_to_val(input_bytes[scan_idx + 1]);
            let low_nibble = hex_digit_to_val(input_bytes[scan_idx + 2]);
            if high_nibble >= 0 && low_nibble >= 0 {
                let decoded_char = ((high_nibble << 4) | low_nibble) as u8;
                out.push(decoded_char);
                scan_idx += 3;
                continue;
            }
        }
        out.push(b);
        scan_idx++;
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
    var input = raw;
    var base: i64 = 0;
    if input[0] == '?' {
        input = input[1..];
        base = 1;
    }
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

    if eq_pos < 0 {
        let is_over = (pair.len > MAX_URL_QUERY_KEY_LIMIT) || (pair.len > 0xFFFF);
        let k_len = if pair.len > 0xFFFF { 0xFFFF } else { pair.len };
        let tok = pack_query_token(base_offset + start, k_len, 0, flags | QUERY_TOKEN_FLAG_VALUELESS);
        return tok, is_over;
    }

    let k_raw = eq_pos;
    let v_raw = pair.len - (eq_pos + 1);
    let is_over = (k_raw > MAX_URL_QUERY_KEY_LIMIT) ||
        (v_raw > MAX_URL_QUERY_VAL_LIMIT) ||
        (k_raw > 0xFFFF) ||
        (v_raw > 0xFFFF);
    let k_len = if k_raw > 0xFFFF { 0xFFFF } else { k_raw };
    let v_len = if v_raw > 0xFFFF { 0xFFFF } else { v_raw };
    let tok = pack_query_token(base_offset + start, k_len, v_len, flags);
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
        start = end + 1;
        guard pair.len > 0 else { continue; }

        let tok, is_over = extract_token_descriptor(pair, base_offset, end - pair.len);
        if is_over {
            res.overflow = true;
            if pair.len > 0xFFFF {
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
        var matches = (raw_key == key_str);
        if !matches && query_token_has_escape(tok) {
            var dec_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_key, dec_key);
            matches = dec_ok && (dec_key[..] == key_str);
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
        var matches = (raw_key == key_str);
        if !matches && query_token_has_escape(tok) {
            var dec_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_key, dec_key);
            matches = dec_ok && (dec_key[..] == key_str);
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
        var matches = (raw_key == key_str);
        if !matches && query_token_has_escape(tok) {
            var dec_key: u8[..64] = [];
            let dec_ok = percent_decode_query(raw_key, dec_key);
            matches = dec_ok && (dec_key[..] == key_str);
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

// Fast zero-allocation query parameter lookup directly from raw query slice.
// Scans raw_query for key without allocating a QueryParamsList or parsing unrelated parameters.
// Returns (found, is_valueless). If found and has a value, out is cleared and the decoded value is written into out.
fn get_query_param_fast<B>(raw_query: const u8[:], key: const u8[:], out: B&) -> bool, bool {
    guard key.len > 0 && raw_query.len > 0 else { return false, false; }

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
                return true, true;
            }
            let stmt_val = statement[eq_pos + 1..];
            out.clear();
            let dec_ok = percent_decode_query(stmt_val, out);
            guard dec_ok else {
                out.clear();
                return false, false;
            }
            return true, false;
        }
    }
    return false, false;
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
