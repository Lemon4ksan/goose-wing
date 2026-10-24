// W3C No-Vary-Search Cache Normalization Engine.
// Enables HTTP cache hits across query string variations by stripping ignored tracking
// parameters (e.g. `utm_*`, `fbclid`) and normalizing parameter ordering.
// Conforms to W3C Navigation & Cache No-Vary-Search Specification.
namespace wing;

import std;
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
        if cursor == raw.len { break; }

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
                let list_start = cursor;
                while cursor < raw.len && raw[cursor] != ')' { cursor++; }
                if cursor < raw.len && raw[cursor] == ')' { cursor++; }
                val_slice = raw[list_start..cursor];
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
    var i: i64 = 0;
    while i < inner_list.len {
        while i < inner_list.len && inner_list[i] != '"' { i++; }
        if i >= inner_list.len { break; }
        i++; // skip open quote

        let str_start = i;
        while i < inner_list.len && inner_list[i] != '"' { i++; }
        if i > str_start && out.len < 16 {
            var item: u8[..64] = [];
            item.append(inner_list[str_start..i]);
            out.push(item);
        }
        if i < inner_list.len { i++; } // skip closing quote
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
    var params: QueryParam[..32] = [];

    var cursor: i64 = 0;
    // Skip leading '?' if present
    if raw_query.len > 0 && raw_query[0] == '?' {
        cursor = 1;
    }

    while cursor < raw_query.len {
        var amp_pos = raw_query.len;
        for i in cursor..raw_query.len {
            if raw_query[i] == '&' {
                amp_pos = i;
                break;
            }
        }

        let pair = raw_query[cursor..amp_pos];
        cursor = if amp_pos < raw_query.len { amp_pos + 1 } else { raw_query.len };
        if pair.len == 0 { continue; }

        var eq_pos: i64 = -1;
        for i in pair.len {
            if pair[i] == '=' {
                eq_pos = i;
                break;
            }
        }

        var p = QueryParam { .. };
        if eq_pos >= 0 {
            p.key.append(pair[..eq_pos]);
            p.val.append(pair[eq_pos + 1..]);
        } else {
            p.key.append(pair);
        }

        // Only keep if not ignored by No-Vary-Search rules
        if !is_param_ignored(nvs, p.key[..]) && params.len < 32 {
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
    for i in params.len {
        if i > 0 {
            out.push('&');
        }
        out.append(params[i].key[..]);
        if params[i].val.len > 0 {
            out.push('=');
            out.append(params[i].val[..]);
        }
    }
}
