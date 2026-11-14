// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9213: Targeted HTTP Cache-Control.
// Zero-allocation parser and precedence evaluator for CDN-Cache-Control and targeted cache headers.
namespace wing;

import std;
import core from "..";
import http.headers;
import http.sfv;
import http.cache.cache_control;

fn is_empty_or_whitespace_value(val: const u8[:]) -> bool {
    for b in val {
        if b != ' ' && b != '\t' && b != ',' && b != '\r' && b != '\n' {
            return false;
        }
    }
    return true;
}

inline fn clamp_targeted_delta_seconds(v: i64) -> i32 {
    if v > rfc::MAX_DELTA_SECONDS {
        return rfc::MAX_DELTA_SECONDS;
    }
    return v as i32;
}

fn apply_targeted_sf_int_entry(k: const u8[:], e: const SfDictEntry&, cc: CacheControl&) -> bool, bool {
    if k == "max-age" {
        guard !e.is_inner_list && e.item.kind == SfType.Integer && e.item.int_val >= 0 else { return true, false; }
        cc.max_age = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | CC_HAS_MAX_AGE;
        return true, true;
    }
    if k == "s-maxage" {
        guard !e.is_inner_list && e.item.kind == SfType.Integer && e.item.int_val >= 0 else { return true, false; }
        cc.s_maxage = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | CC_HAS_S_MAXAGE;
        return true, true;
    }
    if k == "stale-while-revalidate" {
        guard !e.is_inner_list && e.item.kind == SfType.Integer && e.item.int_val >= 0 else { return true, false; }
        cc.stale_while_revalidate = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | CC_STALE_WHILE_REVALIDATE;
        return true, true;
    }
    if k == "stale-if-error" {
        guard !e.is_inner_list && e.item.kind == SfType.Integer && e.item.int_val >= 0 else { return true, false; }
        cc.stale_if_error = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | CC_STALE_IF_ERROR;
        return true, true;
    }
    return false, true;
}

fn targeted_bool_flag_for_key(k: const u8[:]) -> u32 {
    if k == "no-store" { return CC_NO_STORE; }
    if k == "no-cache" { return CC_NO_CACHE; }
    if k == "must-revalidate" { return CC_MUST_REVALIDATE; }
    if k == "proxy-revalidate" { return CC_PROXY_REVALIDATE; }
    if k == "must-understand" { return CC_MUST_UNDERSTAND; }
    if k == "private" { return CC_PRIVATE; }
    if k == "public" { return CC_PUBLIC; }
    if k == "immutable" { return CC_IMMUTABLE; }
    if k == "no-transform" { return CC_NO_TRANSFORM; }
    return 0;
}

fn apply_targeted_sf_entry(e: const SfDictEntry&, cc: CacheControl&) -> bool {
    let k = e.key;
    let matched_int, ok_int = apply_targeted_sf_int_entry(k, e, cc);
    if matched_int {
        return ok_int;
    }
    if k == "no-cache" && !e.is_inner_list && e.item.kind == SfType.String {
        var unq_nc: u8[..256] = [];
        guard sf_unescape_string(e.item.str_val, unq_nc) else { return false; }
        cc.flags = cc.flags | CC_NO_CACHE;
        parse_field_names(unq_nc[..], cc.no_cache_fields, cc.no_cache_overflow);
        return true;
    }
    if k == "private" && !e.is_inner_list && e.item.kind == SfType.String {
        var unq_pr: u8[..256] = [];
        guard sf_unescape_string(e.item.str_val, unq_pr) else { return false; }
        cc.flags = cc.flags | CC_PRIVATE;
        parse_field_names(unq_pr[..], cc.private_fields, cc.private_overflow);
        return true;
    }
    let flag = targeted_bool_flag_for_key(k);
    if flag != 0 {
        guard !e.is_inner_list && e.item.kind == SfType.Boolean else { return false; }
        if e.item.bool_val {
            cc.flags = cc.flags | flag;
        }
        return true;
    }
    return true;
}

// RFC 9213 Section 2.1: Syntax - Parse targeted header as RFC 8941 SF Dictionary and ignore field on parse error.
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
    guard map.get_header(header_name).len > 0 else { return false; }
    var combined: u8[..2048] = [];
    guard map.get_combined(header_name, combined, 2048) && !is_empty_or_whitespace_value(combined[..]) else {
        return false;
    }
    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(combined[..], entries) && entries.len > 0 else { return false; }

    var parsed = CacheControl { .. };
    for &e in entries {
        guard apply_targeted_sf_entry(e, parsed) else { return false; }
    }
    if ignore_cargo_cult && (parsed.flags & CC_HAS_MAX_AGE) != 0 && parsed.max_age > 0 {
        parsed.flags = parsed.flags & ~(CC_NO_CACHE | CC_MUST_REVALIDATE);
    }
    cc = parsed;
    return true;
}

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
        if parse_named_cache_control(map, target_name, cc, ignore_cargo_cult) {
            return true;
        }
    }
    guard !target_name.ends_with_fold("-cache-control") && target_name.len <= 48 else {
        return false;
    }
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
