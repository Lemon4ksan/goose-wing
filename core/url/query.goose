// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// URL query parameter parsing and WHATWG search params.
namespace core;

import std;

// ---- query parameter parsing & whatwg search params -------------------------

struct QueryParamItem {
    key: u8[..64] = [],
    val: u8[..256] = [],
}

struct QueryParamsList {
    items: QueryParamItem[..128] = [],
    overflow: bool = false,
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
        } else if b == '+' {
            out.push(' ');
            scan_idx++;
            continue;
        }
        out.push(b);
        scan_idx++;
    }
    return true;
}

// Parses a query string into key-value pairs, decoding percent sequences.
// Only '&' is treated as a parameter delimiter; ';' is kept as literal content.
fn parse_query_params(raw_search: const u8[:]) -> QueryParamsList {
    var list = QueryParamsList { .. };
    var input = raw_search;
    if input.len > 0 && input[0] == '?' {
        input = input[1..];
    }
    let hash_idx = core::index_of_byte(input, '#');
    if hash_idx >= 0 {
        input = input[..hash_idx];
    }
    guard input.len > 0 else { return list; }

    var start = 0;
    while start < input.len && list.items.len < list.items.cap {
        var end = input.len;
        for i in start..input.len {
            if input[i] == '&' {
                end = i;
                break;
            }
        }
        let pair = input[start..end];
        if pair.len > 0 {
            var eq_pos = -1;
            for i in pair.len {
                if pair[i] == '=' {
                    eq_pos = i;
                    break;
                }
            }
            var item = QueryParamItem { .. };
            if eq_pos >= 0 {
                let k = pair[..eq_pos];
                let v = pair[eq_pos + 1..];
                let ok_k = percent_decode_query(k, item.key);
                let ok_v = percent_decode_query(v, item.val);
                if !ok_k || !ok_v {
                    list.overflow = true;
                }
            } else {
                let ok_k = percent_decode_query(pair, item.key);
                if !ok_k {
                    list.overflow = true;
                }
            }
            list.items.push(item);
        }
        start = end + 1;
    }
    if start < input.len {
        list.overflow = true;
    }
    return list;
}

// Retrieves the first parameter value for given key from QueryParamsList.
fn get_query_param(list: const QueryParamsList&, key_str: const u8[:]) -> const u8[:] {
    for idx in list.items.len {
        if list.items[idx].key[..] == key_str {
            return list.items[idx].val[..];
        }
    }
    return "";
}

// Checks if list contains a parameter for given key.
fn has_query_param(list: const QueryParamsList&, key_str: const u8[:]) -> bool {
    for idx in list.items.len {
        if list.items[idx].key[..] == key_str {
            return true;
        }
    }
    return false;
}

// CVE-2026-39825 & CVE-2025-61726 defense: Count query parameters separated by '&',
// verify total count does not exceed limit, and enforce per-token length limit (256 bytes)
// to prevent fixed-buffer parser overflow.
const MAX_URL_QUERY_PARAMS_LIMIT: i64 = 128;
const MAX_URL_QUERY_TOKEN_LIMIT: i64 = 256;

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
    var count: i64 = 1;
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
        if !matches && (core::index_of_byte(raw_stmt_key, '%') >= 0 || core::index_of_byte(raw_stmt_key, '+') >= 0) {
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
        if !matches && (core::index_of_byte(raw_stmt_key, '%') >= 0 || core::index_of_byte(raw_stmt_key, '+') >= 0) {
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
