// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C No-Vary-Search Cache Normalization Engine.
// Enables HTTP cache hits across query string variations by stripping ignored tracking
// parameters (e.g. `utm_*`, `fbclid`) and normalizing parameter ordering.
// Conforms to W3C Navigation & Cache No-Vary-Search Specification.
namespace wing;

import std;
import core from "..";
import .sfv;

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

fn copy_sfv_inner_string_list(items: const SfvItem[:], out: u8[..64][..16]&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    for &item in items {
        guard item.bare.kind == SfvType.String else { return false; }
        var name: u8[..64] = [];
        guard name.try_set(item.bare.text[..]) && out.try_push(name) else { return false; }
    }
    committed = true;
    return true;
}

fn apply_nvs_params(nvs: NoVarySearch&, member: const SfvMember&) -> bool {
    if member.is_inner_list {
        guard copy_sfv_inner_string_list(member.inner_list[..], nvs.params) else { return false; }
        nvs.ignore_all_params = false;
        return true;
    }
    guard member.item.bare.kind == SfvType.Boolean else { return false; }
    nvs.ignore_all_params = member.item.bare.bool_val;
    nvs.params.clear();
    return true;
}

fn apply_nvs_except(nvs: NoVarySearch&, member: const SfvMember&, has_except: bool&) -> bool {
    guard member.is_inner_list && copy_sfv_inner_string_list(member.inner_list[..], nvs.except_params) else {
        return false;
    }
    has_except = true;
    return true;
}

fn apply_nvs_key_order(nvs: NoVarySearch&, member: const SfvMember&) -> bool {
    guard !member.is_inner_list && member.item.bare.kind == SfvType.Boolean else { return false; }
    nvs.key_order_matters = !member.item.bare.bool_val;
    return true;
}

fn apply_nvs_entry(nvs: NoVarySearch&, entry: const SfvDictEntry&, has_except: bool&) -> bool {
    let key = entry.key[..];
    if key == "params" {
        return apply_nvs_params(nvs, entry.member);
    }
    if key == "except" {
        return apply_nvs_except(nvs, entry.member, has_except);
    }
    if key == "key-order" {
        return apply_nvs_key_order(nvs, entry.member);
    }
    return true;
}

// RFC 9651 Section 3.2: Dictionaries - Validate except/params dependency after full dictionary parse.
//
// Example:
//   raw = "params, key-order"
//   returns: nvs with ignore_all_params=true, key_order_matters=false, ok = true
fn parse_no_vary_search(raw: const u8[:]) -> NoVarySearch, bool {
    var dict = SfvDict { .. };
    guard parse_sfv_dict(raw, dict) else {
        return NoVarySearch { .. }, false;
    }
    var nvs = NoVarySearch { is_valid: true, .. };
    var has_except = false;
    for &entry in dict.entries {
        guard apply_nvs_entry(nvs, entry, has_except) else {
            return NoVarySearch { .. }, false;
        }
    }
    guard !has_except || nvs.ignore_all_params else {
        return NoVarySearch { .. }, false;
    }
    return nvs, true;
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
    let min_len = min(a.len, b.len);
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
    guard p.key.try_append(k) else { return false; }
    if has_eq {
        guard p.val.try_append(v) else { return false; }
    }
    return true;
}

inline fn try_decode_nvs_pct_octet(raw: const u8[:], i: i64) -> u8, i64 {
    let next = core::add_sat_i64(i, 1);
    let hex_end = core::add_sat_i64(i, 3);
    guard hex_end <= raw.len else { return '%', next; }
    let hval, ok_h = raw[next..hex_end].parse_u8_hex();
    guard ok_h else { return '%', next; }
    return hval, hex_end;
}

// Decodes URL-encoded query parameter key bytes ('+' as space and '%HH' hex octets).
//
// Example:
//   raw = "%75tm+source", out = []
//   returns: true, out = "utm source"
fn decode_nvs_query_key(raw: const u8[:], out: u8[..128]&) -> bool {
    out.clear();
    var i: i64 = 0;
    while i < raw.len {
        let b = raw[i];
        var dec:  u8  = 0;
        var next: i64 = core::add_sat_i64(i, 1);
        if b == '+' {
            dec = ' ';
        } else if b == '%' {
            let pct_b, pct_next = try_decode_nvs_pct_octet(raw, i);
            dec = pct_b;
            next = pct_next;
        } else {
            dec = b;
        }
        guard out.try_push(dec) else {
            out.clear();
            return false;
        }
        i = next;
    }
    return true;
}

// Parses query string and applies No-Vary-Search filtering rules.
//
// Example:
//   raw_query = "?a=1&b=2", nvs ignores "a"
//   returns: true, params contains only "b=2"
fn parse_and_filter_query_params(raw_query: const u8[:], nvs: const NoVarySearch&, params: QueryParam[..128]&) -> bool {
    params.clear();
    var committed = false;
    defer if !committed { params.clear(); };
    let trimmed = if raw_query.len > 0 && raw_query[0] == '?' { raw_query[1..] } else { raw_query };
    var tok = core::make_byte_tokenizer(trimmed, '&');

    loop {
        let pair, ok = tok.token_next();
        guard ok else { break; }
        if pair.len == 0 { continue; }

        let k_raw, _, _ = pair.split_once_byte('=');
        var k_dec: u8[..128] = [];
        let has_dec = decode_nvs_query_key(k_raw, k_dec);
        let key_view = if has_dec { k_dec[..] } else { k_raw };
        if is_param_ignored(nvs, key_view) {
            continue;
        }

        var p = QueryParam { .. };
        guard parse_single_query_param(pair, p) && params.try_push(p) else { return false; }
    }
    committed = true;
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

fn try_normalize_query_for_cache<B>(raw_query: const u8[:], nvs: const NoVarySearch&, out: B&) -> bool {
    out.clear();
    var params: QueryParam[..128] = [];
    guard parse_and_filter_query_params(raw_query, nvs, params) else { return false; }

    // If key-order does not matter, sort parameters alphabetically by key
    if !nvs.key_order_matters && params.len > 1 {
        sort(params) { a, b => bytes_less_than(a.key[..], b.key[..]) };
    }

    serialize_normalized_query(params[..], out);
    return true;
}

// Normalizes a raw query string (e.g. `utm_source=tw&id=10&utm_medium=web`)
// into a canonical sorted string without ignored parameters (`id=10`)
fn normalize_query_for_cache<B>(raw_query: const u8[:], nvs: const NoVarySearch&, out: B&) {
    let _ = try_normalize_query_for_cache(raw_query, nvs, out);
}

// Evaluates whether two URLs are cache-equivalent under a W3C No-Vary-Search policy.
fn are_urls_nvs_equivalent(url_a: const u8[:], url_b: const u8[:], nvs: const NoVarySearch&) -> bool {
    if url_a == url_b { return true; }
    guard nvs.is_valid else { return false; }
    let base_a, query_a, _ = url_a.split_once_byte('?');
    let base_b, query_b, _ = url_b.split_once_byte('?');
    guard base_a == base_b else { return false; }
    var norm_a: u8[..1024] = [];
    var norm_b: u8[..1024] = [];
    guard try_normalize_query_for_cache(query_a, nvs, norm_a) else { return false; }
    guard try_normalize_query_for_cache(query_b, nvs, norm_b) else { return false; }
    return norm_a[..] == norm_b[..];
}
