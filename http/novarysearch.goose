// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C No-Vary-Search Cache Normalization Engine.
// Enables HTTP cache hits across query string variations by stripping ignored tracking
// parameters (e.g. `utm_*`, `fbclid`) and normalizing parameter ordering.
// Conforms to W3C Navigation & Cache No-Vary-Search Specification.
namespace wing;

import std;
import core from "..";
import http.headers;

// ---- 1. No-Vary-Search Model -----------------------------------------------

struct NoVarySearch {
    ignore_all_params: bool = false,       // `params` without argument
    params: u8[..16][..64] = [],           // Explicit list of ignored parameters
    except_params: u8[..16][..64] = [],    // Parameters that MUST NOT be ignored
    key_order_matters: bool = false,       // Default false (key order does not affect cache hit)
    is_valid: bool = false,
}

struct QueryParam {
    key: u8[..64] = [],
    val: u8[..256] = [],
}

// ---- 2. Header Parser ------------------------------------------------------

// Parses `No-Vary-Search: params, except=("id"), key-order`
fn parse_no_vary_search(raw: const u8[:]) -> NoVarySearch, bool {
    var nvs = NoVarySearch { is_valid: true, .. };
    var cursor: i64 = 0;

    while cursor < raw.len {
        while cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == '\t' || raw[cursor] == ',') {
            cursor++;
        }
        guard cursor < raw.len else { break; }

        let token_start = cursor;
        while cursor < raw.len && raw[cursor] != '=' && raw[cursor] != ',' && raw[cursor] != ' ' && raw[cursor] != '\t' {
            cursor++;
        }
        let token = raw[token_start..cursor];

        while cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == '\t') { cursor++; }

        var has_val = false;
        var val_slice: const u8[:] = "";
        if cursor < raw.len && raw[cursor] == '=' {
            cursor++; // skip '='
            while cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == '\t') { cursor++; }

            if cursor < raw.len && raw[cursor] == '(' {
                // Inner list: e.g. ("id" "page")
                let rel_close = core::index_of_byte(raw[cursor..], ')');
                let list_end = if rel_close >= 0 { cursor + rel_close + 1 } else { raw.len };
                val_slice = raw[cursor..list_end];
                cursor = list_end;
                has_val = true;
            } else if cursor < raw.len && raw[cursor] == '?' {
                // Boolean: ?0 or ?1
                val_slice = raw[cursor..cursor + 2];
                cursor += 2;
                has_val = true;
            }
        }

        if token == "params" {
            if !has_val {
                nvs.ignore_all_params = true;
            } else if val_slice.len >= 2 && val_slice[0] == '(' {
                // Parse strings inside inner list
                parse_inner_string_list(val_slice, nvs.params);
            } else if val_slice == "?0" {
                nvs.ignore_all_params = false;
            }
        } else if token == "except" {
            if has_val && val_slice.len >= 2 && val_slice[0] == '(' {
                parse_inner_string_list(val_slice, nvs.except_params);
            }
        } else if token == "key-order" {
            if has_val && val_slice == "?0" {
                nvs.key_order_matters = true;
            } else {
                nvs.key_order_matters = false;
            }
        }
    }

    return nvs, true;
}

fn parse_inner_string_list<E>(inner_list: const u8[:], out: E&) {
    var cursor: i64 = 0;
    while cursor < inner_list.len {
        let rel_q1 = core::index_of_byte(inner_list[cursor..], '"');
        guard rel_q1 >= 0 else { break; }
        let start = cursor + rel_q1 + 1;

        let rel_q2 = core::index_of_byte(inner_list[start..], '"');
        guard rel_q2 >= 0 else { break; }
        let end = start + rel_q2;

        if end > start && out.len < out.cap {
            var item: u8[..64] = [];
            let item_len = core::ct_min_i64(end - start, item.cap);
            item.append(inner_list[start..start + item_len]);
            out.push(item);
        }
        cursor = end + 1;
    }
}

// ---- 3. Query Parameter Filter & Normalizer --------------------------------

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

// Normalizes a raw query string (e.g. `utm_source=tw&id=10&utm_medium=web`)
// into a canonical sorted string without ignored parameters (`id=10`)
fn normalize_query_for_cache<B>(raw_query: const u8[:], nvs: const NoVarySearch&, out: B&) {
    var params: QueryParam[..128] = [];

    var cursor: i64 = 0;
    // Skip leading '?' if present
    if raw_query.len > 0 && raw_query[0] == '?' {
        cursor = 1;
    }

    while cursor < raw_query.len {
        let rel_amp = core::index_of_byte(raw_query[cursor..], '&');
        let amp_pos = if rel_amp >= 0 { cursor + rel_amp } else { raw_query.len };

        let pair = raw_query[cursor..amp_pos];
        cursor = if amp_pos < raw_query.len { amp_pos + 1 } else { raw_query.len };
        if pair.len == 0 { continue; }

        let k, v, has_eq = pair.split_once_byte('=');
        var p = QueryParam { .. };
        guard k.len <= p.key.cap else {
            out.clear();
            return;
        }
        if has_eq {
            guard v.len <= p.val.cap else {
                out.clear();
                return;
            }
            p.key.append(k);
            p.val.append(v);
        } else {
            p.key.append(pair[..k.len]);
        }

        // Only keep if not ignored by No-Vary-Search rules
        if !is_param_ignored(nvs, p.key[..]) {
            guard params.len < params.cap else {
                out.clear();
                return;
            }
            params.push(p);
        }
    }

    // If key-order does not matter (default), sort parameters alphabetically by key
    if !nvs.key_order_matters && params.len > 1 {
        for i in params.len {
            for j in (i + 1)..params.len {
                if bytes_less_than(params[j].key[..], params[i].key[..]) {
                    let tmp = params[i];
                    params[i] = params[j];
                    params[j] = tmp;
                }
            }
        }
    }

    // Serialize normalized query
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
