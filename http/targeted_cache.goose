// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9213: Targeted HTTP Cache-Control.
// Zero-allocation parser and precedence evaluator for CDN-Cache-Control and targeted cache headers.
namespace wing;

import std;
import core from "..";
import http.headers;
import http.cache.cache_control;

fn is_empty_or_whitespace_value(val: const u8[:]) -> bool {
    for b in val {
        if b != ' ' && b != '\t' && b != ',' && b != '\r' && b != '\n' {
            return false;
        }
    }
    return true;
}

// Helper to parse all instances of a specific header name from HeaderMap into CacheControl.
// If the header value is empty or contains only whitespace/commas, it is ignored (RFC 9213 §2.1 & §2.2).
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
    var parsed = CacheControl { .. };
    var found = false;
    for entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if name.eq_ascii_fold(header_name) {
            let val = map.raw_buf[entry.values_begin..entry.values_end];
            if !is_empty_or_whitespace_value(val) {
                found = true;
                parse_cache_control_str(val, parsed, ignore_cargo_cult);
            }
        }
    }
    let has_recognized = parsed.flags != 0 || parsed.no_cache_fields.len > 0 || parsed.private_fields.len > 0;
    if found && has_recognized {
        cc = parsed;
        return true;
    }
    return false;
}

fn check_target_cache_control(
    map:               const HeaderMap&,
    target_name:       const u8[:],
    cc:                CacheControl&,
    ignore_cargo_cult: bool,
) -> bool {
    guard target_name.len > 0 && !target_name.eq_ascii_fold("cdn") else { return false; }
    guard target_name.len <= 48 else { return false; }
    var target_hdr: u8[..64] = [];
    guard target_hdr.try_append(target_name) && target_hdr.try_append("-cache-control") else { return false; }
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
