// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9111 Section 5.2: Cache-Control and Pragma zero-heap parser.
// Compresses directives into a 16-bit bitmask and handles delta-seconds overflow clamping.
namespace wing;

import std;
import http.headers;

// ---- cache-control bitmask flags -------------------------------------------

const CC_FLAG_NONE:              u32 = 0x0000;
const CC_NO_STORE:               u32 = 0x0001;  // no-store
const CC_NO_CACHE:               u32 = 0x0002;  // no-cache (unqualified or qualified)
const CC_MUST_REVALIDATE:        u32 = 0x0004;  // must-revalidate
const CC_PROXY_REVALIDATE:       u32 = 0x0008;  // proxy-revalidate
const CC_MUST_UNDERSTAND:        u32 = 0x0010;  // must-understand (RFC 9111 Section 5.2.2.3)
const CC_PRIVATE:                u32 = 0x0020;  // private (unqualified or qualified)
const CC_PUBLIC:                 u32 = 0x0040;  // public
const CC_IMMUTABLE:              u32 = 0x0080;  // immutable (RFC 8246)
const CC_ONLY_IF_CACHED:         u32 = 0x0100;  // only-if-cached (RFC 9111 Section 5.2.1)
const CC_NO_TRANSFORM:           u32 = 0x0200;  // no-transform
const CC_INVALID_FRESHNESS:      u32 = 0x0400;  // corrupted/non-digit max-age/s-maxage/min-fresh -> lifetime = 0
const CC_HAS_MAX_AGE:            u32 = 0x0800;  // max-age=delta-seconds
const CC_HAS_S_MAXAGE:           u32 = 0x1000;  // s-maxage=delta-seconds
const CC_HAS_MAX_STALE:          u32 = 0x2000;  // max-stale[=delta-seconds]
const CC_HAS_MIN_FRESH:          u32 = 0x4000;  // min-fresh=delta-seconds
const CC_STALE_WHILE_REVALIDATE: u32 = 0x8000;  // stale-while-revalidate=delta-seconds (RFC 5861 Section 3)
const CC_STALE_IF_ERROR:         u32 = 0x10000; // stale-if-error=delta-seconds (RFC 5861 Section 4)

// ---- cache-control structure -----------------------------------------------

// Structured representation of parsed HTTP Cache-Control directives.
struct CacheControl {
    flags:                  u32            = 0,
    max_age:                i32            = -1,
    s_maxage:               i32            = -1,
    max_stale:              i32            = -1, // -1 with CC_HAS_MAX_STALE means unbounded max-stale
    min_fresh:              i32            = -1,
    stale_while_revalidate: i32            = -1,
    stale_if_error:         i32            = -1,
    private_overflow:       bool           = false,
    no_cache_overflow:      bool           = false,
    private_fields:         u8[..64][..16] = [],
    no_cache_fields:        u8[..64][..16] = [],
}

// Constructs a zero-initialized CacheControl structure with default unset values (-1).
// ---- flag inspectors -------------------------------------------------------

// Returns whether the specified bitmask flag is set.
fn has_flag(cc: const CacheControl&, flag: u32) -> bool {
    return (cc.flags & flag) == flag;
}

// Returns true if no-store directive is set.
fn is_no_store(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_NO_STORE) != 0;
}

// Returns true if no-cache directive is set.
fn is_no_cache(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_NO_CACHE) != 0;
}

// Returns true if must-revalidate directive is set.
fn is_must_revalidate(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_MUST_REVALIDATE) != 0;
}

// Returns true if proxy-revalidate directive is set.
fn is_proxy_revalidate(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_PROXY_REVALIDATE) != 0;
}

// Returns true if must-understand directive is set (RFC 9111 Section 5.2.2.3).
fn is_must_understand(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_MUST_UNDERSTAND) != 0;
}

// Returns true if private directive is set.
fn is_private(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_PRIVATE) != 0;
}

// Returns true if public directive is set.
fn is_public(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_PUBLIC) != 0;
}

// Returns true if immutable directive is set (RFC 8246).
fn is_immutable(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_IMMUTABLE) != 0;
}

// RFC 9111 Section 5.2.1: Request Directives - Returns true if only-if-cached directive is set.
fn is_only_if_cached(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_ONLY_IF_CACHED) != 0;
}

// Returns true if no-transform directive is set.
fn is_no_transform(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_NO_TRANSFORM) != 0;
}

// Returns true if non-digit or corrupted delta-seconds forced freshness invalidation.
fn has_invalid_freshness(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_INVALID_FRESHNESS) != 0;
}

// Returns true if max-age directive was present.
fn has_max_age(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_MAX_AGE) != 0;
}

// Returns true if s-maxage directive was present.
fn has_s_maxage(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_S_MAXAGE) != 0;
}

// Returns true if max-stale directive was present.
fn has_max_stale(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_MAX_STALE) != 0;
}

// Returns true if min-fresh directive was present.
fn has_min_fresh(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_MIN_FRESH) != 0;
}

// Returns true if stale-while-revalidate directive was present (RFC 5861 Section 3).
fn has_stale_while_revalidate(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_STALE_WHILE_REVALIDATE) != 0;
}

// Returns true if stale-if-error directive was present (RFC 5861 Section 4).
fn has_stale_if_error(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_STALE_IF_ERROR) != 0;
}

// Checks if a given field name is covered by qualified private="field1, field2".
fn is_private_field(cc: const CacheControl&, field_name: const u8[:]) -> bool {
    guard (cc.flags & CC_PRIVATE) != 0 else { return false; }
    if cc.private_overflow || cc.private_fields.len == 0 { return true; }
    for &f in cc.private_fields {
        if eq_ascii_fold(f[..], field_name) {
            return true;
        }
    }
    return false;
}

// Checks if a given field name is covered by qualified no-cache="field1, field2".
fn is_no_cache_field(cc: const CacheControl&, field_name: const u8[:]) -> bool {
    guard (cc.flags & CC_NO_CACHE) != 0 else { return false; }
    if cc.no_cache_overflow || cc.no_cache_fields.len == 0 { return true; }
    for &f in cc.no_cache_fields {
        if eq_ascii_fold(f[..], field_name) {
            return true;
        }
    }
    return false;
}

// ---- delta-seconds parsing with overflow clamp ------------------------------

// Parses a non-negative decimal delta-seconds token, clamping overflow to i32::MAX.
// Strips optional surrounding double quotes.
//
// Example:
//   raw_val = "3600"
//   returns: 3600, ok = true
fn parse_delta_seconds(raw_val: const u8[:]) -> i32, bool {
    let s = raw_val.trim_lws().trim_byte('"').trim_lws();
    guard s.len > 0 else { return 0, false; }

    var acc: i64 = 0;
    for b in s {
        guard b >= '0' && b <= '9' else {
            return 0, false;
        }
        let digit = (b - '0');
        acc = core::ct_min_i64(acc * 10 + digit, rfc::MAX_DELTA_SECONDS);
    }
    return acc as i32, true;
}

// Extracts comma-separated or quoted field names into an inline fixed-capacity array.
//
// Example:
//   raw_val = "\"Set-Cookie\", \"Private-Token\""
//   appends names to out_fields, sets overflow=false
fn parse_field_names(raw_val: const u8[:], out_fields: u8[..64][..16]&, overflow: bool&) {
    let s = raw_val.trim_lws().trim_byte('"').trim_lws();
    guard s.len > 0 else { return; }

    var tok = make_byte_tokenizer(s, ',');
    while true {
        let name_tok, ok = tok.token_next();
        guard ok else { break; }
        let trimmed_name = name_tok.trim_lws();
        if trimmed_name.len > 0 {
            if out_fields.len < out_fields.cap && trimmed_name.len <= 64 {
                var buf: u8[..64] = [];
                buf.append(trimmed_name);
                out_fields.push(buf);
            } else {
                overflow = true;
            }
        }
    }
}

// ---- directive dispatcher helpers ------------------------------------------

// Applies boolean or field-list Cache-Control directives.
fn apply_cache_control_boolean(name: const u8[:], val: const u8[:], cc: CacheControl&) -> bool {
    if eq_ascii_fold(name, "no-store") {
        cc.flags |= CC_NO_STORE;
        return true;
    }
    if eq_ascii_fold(name, "no-cache") {
        cc.flags |= CC_NO_CACHE;
        if val.len > 0 {
            let s = val.trim_lws().trim_byte('"').trim_lws();
            if s.len > 0 {
                parse_field_names(val, cc.no_cache_fields, cc.no_cache_overflow);
            } else {
                cc.no_cache_overflow = true;
            }
        } else {
            cc.no_cache_overflow = true;
        }
        return true;
    }
    if eq_ascii_fold(name, "must-revalidate") {
        cc.flags |= CC_MUST_REVALIDATE;
        return true;
    }
    if eq_ascii_fold(name, "proxy-revalidate") {
        cc.flags |= CC_PROXY_REVALIDATE;
        return true;
    }
    if eq_ascii_fold(name, "must-understand") {
        cc.flags |= CC_MUST_UNDERSTAND;
        return true;
    }
    if eq_ascii_fold(name, "public") {
        cc.flags |= CC_PUBLIC;
        return true;
    }
    if eq_ascii_fold(name, "private") {
        cc.flags |= CC_PRIVATE;
        if val.len > 0 {
            let s = val.trim_lws().trim_byte('"').trim_lws();
            if s.len > 0 {
                parse_field_names(val, cc.private_fields, cc.private_overflow);
            } else {
                cc.private_overflow = true;
            }
        } else {
            cc.private_overflow = true;
        }
        return true;
    }
    if eq_ascii_fold(name, "immutable") {
        cc.flags |= CC_IMMUTABLE;
        return true;
    }
    if eq_ascii_fold(name, "only-if-cached") {
        cc.flags |= CC_ONLY_IF_CACHED;
        return true;
    }
    if eq_ascii_fold(name, "no-transform") {
        cc.flags |= CC_NO_TRANSFORM;
        return true;
    }
    return false;
}

// Applies delta-seconds numeric Cache-Control directives.
fn apply_cache_control_numeric(name: const u8[:], val: const u8[:], cc: CacheControl&) -> bool {
    if eq_ascii_fold(name, "max-age") {
        let secs, ok = parse_delta_seconds(val);
        if ok { cc.flags |= CC_HAS_MAX_AGE; cc.max_age = secs; }
        else { cc.flags |= CC_INVALID_FRESHNESS; }
        return true;
    }
    if eq_ascii_fold(name, "s-maxage") {
        let secs, ok = parse_delta_seconds(val);
        if ok { cc.flags |= CC_HAS_S_MAXAGE; cc.s_maxage = secs; }
        else { cc.flags |= CC_INVALID_FRESHNESS; }
        return true;
    }
    if eq_ascii_fold(name, "max-stale") {
        cc.flags |= CC_HAS_MAX_STALE;
        if val.len > 0 {
            let secs, ok = parse_delta_seconds(val);
            cc.max_stale = if ok { secs } else { -1 };
        } else {
            cc.max_stale = -1;
        }
        return true;
    }
    if eq_ascii_fold(name, "min-fresh") {
        let secs, ok = parse_delta_seconds(val);
        if ok { cc.flags |= CC_HAS_MIN_FRESH; cc.min_fresh = secs; }
        else { cc.flags |= CC_INVALID_FRESHNESS; }
        return true;
    }
    if eq_ascii_fold(name, "stale-while-revalidate") {
        let secs, ok = parse_delta_seconds(val);
        if ok { cc.flags |= CC_STALE_WHILE_REVALIDATE; cc.stale_while_revalidate = secs; }
        return true;
    }
    if eq_ascii_fold(name, "stale-if-error") {
        let secs, ok = parse_delta_seconds(val);
        if ok { cc.flags |= CC_STALE_IF_ERROR; cc.stale_if_error = secs; }
        return true;
    }
    return false;
}

// Dispatches a single name[=value] directive token.
fn apply_directive(name: const u8[:], val: const u8[:], cc: CacheControl&, ignore_cargo_cult: bool) {
    if apply_cache_control_boolean(name, val, cc) { return; }
    if apply_cache_control_numeric(name, val, cc) { return; }
    if ignore_cargo_cult && (eq_ascii_fold(name, "pre-check") || eq_ascii_fold(name, "post-check")) {
        // Legacy IE directives safely ignored
    }
}

// ---- cache-control string parser -------------------------------------------

// Parses a single Cache-Control header line or comma-separated token stream.
//
// Example:
//   raw = "max-age=3600, no-transform"
//   populates cc.max_age=3600, sets CC_NO_TRANSFORM flag
fn parse_cache_control_str(raw: const u8[:], cc: CacheControl&, ignore_cargo_cult: bool = true) {
    var cursor: i64 = 0;
    let len = raw.len;

    while cursor < len {
        let rem = raw[cursor..];
        let trimmed_lead = core::trim_start_bytes(rem, " \t,");
        cursor += rem.len - trimmed_lead.len;
        guard cursor < len else { break; }

        var token_end = cursor;
        var in_quotes = false;
        while token_end < len {
            let b = raw[token_end];
            if b == '"' && (token_end == cursor || raw[token_end - 1] != '\\') {
                in_quotes = !in_quotes;
            } else if b == ',' && !in_quotes {
                break;
            }
            token_end++;
        }

        let directive_slice = trim_lws(raw[cursor..token_end]);
        cursor = token_end + 1;
        guard directive_slice.len > 0 else { continue; }

        let name_raw, val_raw, has_eq = directive_slice.split_once_byte('=');
        let name = name_raw.trim_lws();
        let val = if has_eq { val_raw.trim_lws() } else { "" };

        apply_directive(name, val, cc, ignore_cargo_cult);
    }
}

// Checks if a Pragma header contains the no-cache directive.
fn contains_pragma_no_cache(pragma_val: const u8[:]) -> bool {
    var tok = make_byte_tokenizer(pragma_val, ',');
    while true {
        let item, ok = tok.token_next();
        guard ok else { break; }
        if item.trim_lws().eq_ascii_fold("no-cache") {
            return true;
        }
    }
    return false;
}

// Options for parsing cache-control headers across requests and responses.
struct CacheControlParseOptions {
    is_request:        bool = false,
    ignore_cargo_cult: bool = true,
}

// Parses all Cache-Control (and optional Pragma fallback) headers from HeaderMap.
//
// Example:
//   map = headers with "Cache-Control: max-age=60"
//   returns: cc with max_age=60
fn parse_cache_control_headers(
    map:  const HeaderMap&,
    opts: CacheControlParseOptions = CacheControlParseOptions { .. },
) -> CacheControl {
    var cc = CacheControl { .. };
    var has_cc_header = false;

    for entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if eq_ascii_fold(name, "cache-control") {
            has_cc_header = true;
            let val = map.raw_buf[entry.values_begin..entry.values_end];
            parse_cache_control_str(val, cc, opts.ignore_cargo_cult);
        }
    }

    if !has_cc_header {
        let pragma_val = get_header(map, "pragma");
        if pragma_val.len > 0 && contains_pragma_no_cache(pragma_val) {
            cc.flags |= CC_NO_CACHE;
        }
    }

    return cc;
}
