// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C No-Vary-Search Cache Normalization Engine.
// Enables HTTP cache hits across query string variations by stripping ignored tracking
// parameters (e.g. `utm_*`, `fbclid`) and normalizing parameter ordering.
// Conforms to W3C Navigation & Cache No-Vary-Search Specification.
namespace http;

import std;
import core;
import .sfv;
import http.ext_internal;

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

struct NvsDictParseState {
    nvs:               NoVarySearch   = NoVarySearch { is_valid: true, .. },
    has_except:        bool           = false,
    params_type_ok:    bool           = true,
    except_type_ok:    bool           = true,
    key_order_type_ok: bool           = true,
    seen_keys:         u8[..64][..64] = [],
}

// RFC 9651 Section 3.2: Dictionaries - Validate except/params dependency after full dictionary parse.
//
// Example:
//   raw = "params, key-order"
//   returns: nvs with ignore_all_params=true, key_order_matters=false, ok = true
fn parse_no_vary_search(raw: const u8[:]) -> NoVarySearch, bool {
    var cursor = http_internal::sf_skip_ws(raw, 0);
    var state = NvsDictParseState { .. };
    if cursor == raw.len {
        return state.nvs, true;
    }

    while cursor < raw.len {
        guard http_internal::parse_nvs_dict_member(raw, cursor, state) else {
            return NoVarySearch { .. }, false;
        }
        var has_more = false;
        guard http_internal::sfv_advance_comma(raw, cursor, has_more) else {
            return NoVarySearch { .. }, false;
        }
        if !has_more { break; }
    }

    guard state.params_type_ok &&
          state.except_type_ok &&
          state.key_order_type_ok &&
          (!state.has_except || state.nvs.ignore_all_params) else {
        return NoVarySearch { .. }, false;
    }
    return state.nvs, true;
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

// Normalizes a raw query string (e.g. `utm_source=tw&id=10&utm_medium=web`)
// into a canonical sorted string without ignored parameters (`id=10`)
fn normalize_query_for_cache<B>(raw_query: const u8[:], nvs: const NoVarySearch&, out: B&) {
    let _ = http_internal::try_normalize_query_for_cache(raw_query, nvs, out);
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
    guard http_internal::try_normalize_query_for_cache(query_a, nvs, norm_a) else { return false; }
    guard http_internal::try_normalize_query_for_cache(query_b, nvs, norm_b) else { return false; }
    return norm_a[..] == norm_b[..];
}
