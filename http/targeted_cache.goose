// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9213: Targeted HTTP Cache-Control.
// Zero-allocation parser and precedence evaluator for CDN-Cache-Control and targeted cache headers.
namespace http;

import std;
import core;
import http.headers;
import http.sfv;
import http.cache.cache_control;
import http.ext_internal;

// RFC 9213 Section 2.2: Cache Behavior - Match either an exact targeted header field name or `<target_name>-cache-control`.
fn check_target_cache_control(
    map:               const HeaderMap&,
    target_name:       const u8[:],
    cc:                CacheControl&,
    ignore_cargo_cult: bool,
) -> bool {
    guard target_name.len > 0 && !target_name.eq_ascii_fold("cdn") &&
          !target_name.eq_ascii_fold("cdn-cache-control") &&
          !target_name.eq_ascii_fold("cache-control") else {
        return false;
    }
    if is_valid_header_name(target_name) && map.get_header(target_name).len > 0 {
        if http_internal::parse_named_cache_control(map, target_name, cc, ignore_cargo_cult) {
            return true;
        }
    }
    guard !target_name.ends_with_fold("-cache-control") && target_name.len <= 48 else {
        return false;
    }
    var target_hdr: u8[..64] = [];
    guard target_hdr.try_append(target_name) && target_hdr.try_append("-cache-control") else { return false; }
    return http_internal::parse_named_cache_control(map, target_hdr[..], cc, ignore_cargo_cult);
}

// Parses targeted Cache-Control headers (RFC 9213 Section 2).
// Precedence hierarchy per RFC 9213:
// 1. <target_name>-cache-control (e.g. "fastly-cache-control") if target_name is non-empty and not "cdn"
// 2. cdn-cache-control (RFC 9213 Section 2.1)
// 3. Fallback to standard cache-control (and Pragma fallback)
//
// Example:
//   target_name = "fastly", map has "Fastly-Cache-Control: max-age=60"
//   returns: cc with max_age=60
fn parse_targeted_cache_control_headers(
    map:         const HeaderMap&,
    target_name: const u8[:]              = "",
    opts:        CacheControlParseOptions = CacheControlParseOptions { .. },
) -> CacheControl {
    var cc = CacheControl { .. };

    // 1. Specific target header (e.g. "fastly-cache-control")
    if check_target_cache_control(map, target_name, cc, opts.ignore_cargo_cult) {
        return cc;
    }

    // 2. General CDN-Cache-Control (RFC 9213 Section 2.1)
    if target_name.len > 0 {
        if http_internal::parse_named_cache_control(map, "cdn-cache-control", cc, opts.ignore_cargo_cult) {
            return cc;
        }
    }

    // 3. Fallback to standard Cache-Control
    return parse_cache_control_headers(map, opts);
}
