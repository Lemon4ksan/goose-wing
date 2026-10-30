// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9213: Targeted HTTP Cache-Control.
// Zero-allocation parser and precedence evaluator for CDN-Cache-Control and targeted cache headers.
namespace wing;

import std;
import core from "..";
import http.headers;
import http.cache.cache_control;

// Helper to parse all instances of a specific header name from HeaderMap into CacheControl.
//
// Example:
//   header_name = "cdn-cache-control", map contains "CDN-Cache-Control: max-age=600"
//   returns: true, cc populated with max_age=600
fn parse_named_cache_control(
    map:               const HeaderMap&,
    header_name:       const u8[:],
    cc:                CacheControl&,
    ignore_cargo_cult: bool,
) -> bool {
    var found = false;
    for entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if eq_ascii_fold(name, header_name) {
            found = true;
            let val = map.raw_buf[entry.values_begin..entry.values_end];
            parse_cache_control_str(val, cc, ignore_cargo_cult);
        }
    }
    return found;
}

fn check_target_cache_control(
    map:               const HeaderMap&,
    target_name:       const u8[:],
    cc:                CacheControl&,
    ignore_cargo_cult: bool,
) -> bool {
    guard target_name.len > 0 && !target_name.eq_ascii_fold("cdn") else { return false; }
    guard target_name.len <= 48 else { return false; }
    var target_hdr: u8[>..] = [];
    target_hdr.append(target_name);
    target_hdr.append("-cache-control");
    return parse_named_cache_control(map, target_hdr[..], cc, ignore_cargo_cult);
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
        if parse_named_cache_control(map, "cdn-cache-control", cc, opts.ignore_cargo_cult) {
            return cc;
        }
    }

    // 3. Fallback to standard Cache-Control
    return parse_cache_control_headers(map, opts);
}
