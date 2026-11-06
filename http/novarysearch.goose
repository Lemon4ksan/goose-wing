// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C No-Vary-Search Cache Normalization Engine.
// Enables HTTP cache hits across query string variations by stripping ignored tracking
// parameters (e.g. `utm_*`, `fbclid`) and normalizing parameter ordering.
// Conforms to W3C Navigation & Cache No-Vary-Search Specification.
namespace wing;

import std;
import core from "..";

// ---- No-Vary-Search Model -----------------------------------------------

struct NoVarySearch {
    ignore_all_params: bool           = false, // `params` without argument
    params:            u8[..64][..16] = [],    // Explicit list of ignored parameters
    except_params:     u8[..64][..16] = [],    // Parameters that MUST NOT be ignored
    key_order_matters: bool           = true,  // Default true (W3C No-Vary-Search §2.1)
    is_valid:          bool           = false,
}

struct QueryParam {
    key: u8[..64]  = [],
    val: u8[..256] = [],
}

// ---- Header Parser ------------------------------------------------------

// Reads a Structured Field item or inner list value for No-Vary-Search.
// Advances `cursor` past the consumed value slice.
//
// Example:
//   raw = "params=(\"a\" \"b\")", cursor = 7
//   returns: "(\"a\" \"b\")", ok = true, cursor = 16
fn read_nvs_value(raw: const u8[:], cursor: i64&) -> const u8[:], bool {
    while cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == '\t') { cursor++; }
    guard cursor < raw.len else { return "", false; }

    if raw[cursor] == '(' {
        let rel_close = raw[cursor..].find_unquoted_byte(')');
        guard rel_close < raw[cursor..].len else { return "", false; }
        let list_end = cursor + rel_close + 1;
        let val_slice = raw[cursor..list_end];
        cursor = list_end;
        return val_slice, true;
    }
    if cursor + 2 <= raw.len && raw[cursor] == '?' {
        let val_slice = raw[cursor..cursor + 2];
        cursor += 2;
        return val_slice, true;
    }
    return "", false;
}

fn apply_nvs_params(nvs: NoVarySearch&, has_val: bool, val: const u8[:]) -> bool {
    if !has_val {
        nvs.ignore_all_params = true;
        return true;
    }
    if val.len >= 2 && val[0] == '(' {
        return parse_inner_string_list(val, nvs.params);
    }
    if val == "?0" {
        nvs.ignore_all_params = false;
        return true;
    }
    return false;
}

fn apply_nvs_except(nvs: NoVarySearch&, has_val: bool, val: const u8[:]) -> bool {
    guard has_val && val.len >= 2 && val[0] == '(' else { return false; }
    return parse_inner_string_list(val, nvs.except_params);
}

fn apply_nvs_key_order(nvs: NoVarySearch&, has_val: bool, val: const u8[:]) -> bool {
    if !has_val || val == "?1" {
        nvs.key_order_matters = false;
        return true;
    }
    if val == "?0" {
        nvs.key_order_matters = true;
        return true;
    }
    return false;
}

fn apply_nvs_item(nvs: NoVarySearch&, token: const u8[:], has_val: bool, val: const u8[:]) -> bool {
    if token == "params" {
        return apply_nvs_params(nvs, has_val, val);
    }
    if token == "except" {
        return apply_nvs_except(nvs, has_val, val);
    }
    if token == "key-order" {
        return apply_nvs_key_order(nvs, has_val, val);
    }
    return false;
}

fn read_nvs_token(raw: const u8[:], cursor: i64&) -> const u8[:] {
    let rem = raw[cursor..].trim_start_bytes(" \t,");
    cursor = raw.len - rem.len;
    guard rem.len > 0 else { return ""; }

    var tok_len: i64 = 0;
    while tok_len < rem.len && rem[tok_len] != '=' && rem[tok_len] != ',' &&
          rem[tok_len] != ' ' && rem[tok_len] != '\t' {
        tok_len++;
    }
    let token = rem[..tok_len];
    let post = rem[tok_len..].trim_start_bytes(" \t");
    cursor = raw.len - post.len;
    return token;
}

// Reads next directive name, value presence, and raw value slice.
//
// Example:
//   raw = "params, key-order", cursor = 0
//   returns: token = "params", has_val = false, val = "", ok = true
fn read_next_nvs_directive(raw: const u8[:], cursor: i64&) -> const u8[:], bool, const u8[:], bool {
    let token = read_nvs_token(raw, cursor);
    guard token.len > 0 else { return "", false, "", true; }

    var has_val = false;
    var val_slice: const u8[:] = raw[..0];
    if cursor < raw.len && raw[cursor] == '=' {
        cursor++;
        let v, ok_v = read_nvs_value(raw, cursor);
        guard ok_v else { return "", false, "", false; }
        val_slice = v;
        has_val = true;
    }
    return token, has_val, val_slice, true;
}

// Parses `No-Vary-Search: params, except=("id"), key-order`
//
// Example:
//   raw = "params, key-order"
//   returns: nvs with ignore_all_params=true, key_order_matters=false, ok = true
fn parse_no_vary_search(raw: const u8[:]) -> NoVarySearch, bool {
    var nvs = NoVarySearch { is_valid: true, .. };
    var cursor: i64 = 0;

    while cursor < raw.len {
        let token, has_val, val_slice, ok = read_next_nvs_directive(raw, cursor);
        guard ok else { return NoVarySearch { .. }, false; }
        guard token.len > 0 else { break; }

        guard apply_nvs_item(nvs, token, has_val, val_slice) else {
            return NoVarySearch { .. }, false;
        }
    }

    return nvs, true;
}

// Reads the next double-quoted string from an inner list slice.
// Advances cursor past the closing quote.
//
// Example:
//   s = "(\"a\" \"b\")", cursor = 1
//   returns: "a", has_item = true, ok = true, cursor = 4
fn read_next_quoted_string(s: const u8[:], cursor: i64&) -> const u8[:], bool, bool {
    while cursor < s.len && (s[cursor] == ' ' || s[cursor] == '\t' || s[cursor] == '(') {
        cursor++;
    }
    if cursor >= s.len || s[cursor] == ')' {
        return "", false, true;
    }
    guard s[cursor] == '"' else { return "", false, false; }
    let start = cursor + 1;
    var p = cursor + 1;
    var escaped = false;
    while p < s.len {
        let b = s[p];
        if escaped {
            escaped = false;
        } else if b == '\\' {
            escaped = true;
        } else if b == '"' {
            break;
        }
        p += 1;
    }
    guard p < s.len && s[p] == '"' && !escaped else { return "", false, false; }
    cursor = p + 1;
    return s[start..p], true, true;
}

// Parses space-separated quoted strings enclosed in parentheses.
//
// Example:
//   inner_list = "(\"a\" \"b\")"
//   returns: true, out populated with "a" and "b"
fn parse_inner_string_list<E>(inner_list: const u8[:], out: E&) -> bool {
    var cursor: i64 = 0;
    while cursor < inner_list.len {
        let str, has_item, ok = read_next_quoted_string(inner_list, cursor);
        guard ok else { return false; }
        guard has_item else { break; }
        guard str.len <= 64 && out.len < out.cap else { return false; }

        var item: u8[..64] = [];
        item.append(str);
        out.push(item);
    }
    return true;
}

// ---- Query Parameter Filter & Normalizer --------------------------------

fn is_param_ignored(nvs: const NoVarySearch&, key: const u8[:]) -> bool {
    // 1. If key is in except_params, it is NEVER ignored
    for &exc in nvs.except_params {
        if exc[..] == key {
            return false;
        }
    }

    // 2. If ignore_all_params is true, ignore it
    if nvs.ignore_all_params {
        return true;
    }

    // 3. If key is in explicit params list, ignore it
    for &p in nvs.params {
        if p[..] == key {
            return true;
        }
    }

    return false;
}

fn bytes_less_than(a: const u8[:], b: const u8[:]) -> bool {
    let min_len = if a.len < b.len { a.len } else { b.len };
    for i in min_len {
        if a[i] < b[i] { return true; }
        if a[i] > b[i] { return false; }
    }
    return a.len < b.len;
}

// Parses a single key=value query string parameter.
//
// Example:
//   pair = "key=value"
//   returns: true, p.key="key", p.val="value"
fn parse_single_query_param(pair: const u8[:], p: QueryParam&) -> bool {
    let k, v, has_eq = pair.split_once_byte('=');
    guard k.len <= p.key.cap else { return false; }
    p.key.append(k);
    if has_eq {
        guard v.len <= p.val.cap else { return false; }
        p.val.append(v);
    }
    return true;
}

// Parses query string and applies No-Vary-Search filtering rules.
//
// Example:
//   raw_query = "?a=1&b=2", nvs ignores "a"
//   returns: true, params contains only "b=2"
fn parse_and_filter_query_params(raw_query: const u8[:], nvs: const NoVarySearch&, params: QueryParam[..128]&) -> bool {
    let trimmed = if raw_query.len > 0 && raw_query[0] == '?' { raw_query[1..] } else { raw_query };
    var tok = make_byte_tokenizer(trimmed, '&');

    loop {
        let pair, ok = tok.token_next();
        guard ok else { break; }
        if pair.len == 0 { continue; }

        var p = QueryParam { .. };
        guard parse_single_query_param(pair, p) else { return false; }

        if !is_param_ignored(nvs, p.key[..]) {
            guard params.len < params.cap else { return false; }
            params.push(p);
        }
    }
    return true;
}

fn serialize_normalized_query<B>(params: const QueryParam[:], out: B&) {
    for &p, i in params {
        if i > 0 {
            out.push('&');
        }
        out.append(p.key[..]);
        if p.val.len > 0 {
            out.push('=');
            out.append(p.val[..]);
        }
    }
}

// Normalizes a raw query string (e.g. `utm_source=tw&id=10&utm_medium=web`)
// into a canonical sorted string without ignored parameters (`id=10`)
fn normalize_query_for_cache<B>(raw_query: const u8[:], nvs: const NoVarySearch&, out: B&) {
    out.clear();
    var params: QueryParam[..128] = [];
    guard parse_and_filter_query_params(raw_query, nvs, params) else { return; }

    // If key-order does not matter (default), sort parameters alphabetically by key
    if !nvs.key_order_matters && params.len > 1 {
        sort(params) { a, b => bytes_less_than(a.key[..], b.key[..]) };
    }

    serialize_normalized_query(params[..], out);
}
