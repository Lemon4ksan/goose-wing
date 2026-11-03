// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9110 & RFC 9111 Section 4.1: Conditional request validators and Vary matching engine.
// Implements EntityTag (ETag) weak/strong comparisons, Last-Modified revalidation,
// RFC 9111 §4.1 Vary normalization with CVE-2026-93750 defense, and 304 merge filtering.
namespace wing;

import std;
import http.headers;
import http.cache.cache_control;

// ---- entity tag (etag) model (rfc 9110 section 8.8.3) ----------------------

// Parsed entity tag with weakness indicator and opaque ASCII token.
struct EntityTag {
    is_weak: bool      = false,
    tag:     u8[..128] = [],
    valid:   bool      = false,
}

// Constructs a zero-initialized invalid EntityTag.
// Parses an ETag header value into an EntityTag struct (RFC 9110 §8.8.3).
// Handles case-sensitive "W/" weak prefix and strips enclosing double quotes.
//
// Example:
//   raw = "W/\"xyzzy\""
//   returns: etag with tag="xyzzy", is_weak=true, valid=true
fn parse_etag(raw: const u8[:]) -> EntityTag {
    var etag = EntityTag { .. };
    var s = trim_lws(raw);
    guard s.len >= 2 else { return etag; }

    if s.len >= 4 && s[0] == 'W' && s[1] == '/' {
        etag.is_weak = true;
        s = s[2..];
    }

    guard s.len >= 2 && s[0] == '"' && s[s.len - 1] == '"' else {
        return etag;
    }

    let inner_tag = s[1..s.len - 1];
    guard inner_tag.len <= 128 else { return etag; }

    etag.tag.append(inner_tag);
    etag.valid = true;
    return etag;
}

// Performs weak comparison of two entity tags (RFC 9110 §8.8.3.2).
// Opaque tags must match byte-for-byte; weakness flags are ignored.
fn weak_eq(a: EntityTag, b: EntityTag) -> bool {
    guard a.valid && b.valid else { return false; }
    guard a.tag.len == b.tag.len else { return false; }
    for i in a.tag.len {
        if a.tag[i] != b.tag[i] { return false; }
    }
    return true;
}

// Performs strong comparison of two entity tags (RFC 9110 §8.8.3.2).
// Requires that neither tag is weak and opaque tags match byte-for-byte.
fn strong_eq(a: EntityTag, b: EntityTag) -> bool {
    guard a.valid && b.valid else { return false; }
    guard !a.is_weak && !b.is_weak else { return false; }
    guard a.tag.len == b.tag.len else { return false; }
    for i in a.tag.len {
        if a.tag[i] != b.tag[i] { return false; }
    }
    return true;
}

fn read_next_etag_token(s: const u8[:], cursor: i64&) -> const u8[:] {
    let rem = s[cursor..].trim_start_bytes(" \t,");
    cursor = s.len - rem.len;
    guard rem.len > 0 else { return ""; }

    var in_quotes = false;
    var end_idx: i64 = 0;
    while end_idx < rem.len {
        let b = rem[end_idx];
        if b == '"' {
            in_quotes = !in_quotes;
        } else if b == ',' && !in_quotes {
            break;
        }
        end_idx++;
    }
    let tag = rem[..end_idx].trim_lws();
    cursor += if end_idx < rem.len { end_idx + 1 } else { end_idx };
    return tag;
}

// Checks if cached ETag matches an incoming If-None-Match header (RFC 9110 §13.1.2).
// Supports wildcard "*" and comma-separated lists of ETags using weak_eq.
fn match_if_none_match(raw_if_none_match: const u8[:], cached_etag: const EntityTag&) -> bool {
    guard cached_etag.valid else { return false; }
    let s = trim_lws(raw_if_none_match);
    if s == "*" { return true; }

    var cursor: i64 = 0;
    while cursor < s.len {
        let tag = read_next_etag_token(s, cursor);
        guard tag.len > 0 else { break; }
        if tag == "*" || weak_eq(parse_etag(tag), cached_etag) {
            return true;
        }
    }
    return false;
}

// Checks if cached ETag matches an incoming If-Match header using strong_eq (RFC 9110 §13.1.1).
fn match_if_match(raw_if_match: const u8[:], cached_etag: const EntityTag&) -> bool {
    guard cached_etag.valid else { return false; }
    let s = trim_lws(raw_if_match);
    if s == "*" { return true; }

    var cursor: i64 = 0;
    while cursor < s.len {
        let tag = read_next_etag_token(s, cursor);
        guard tag.len > 0 else { break; }
        if tag == "*" || strong_eq(parse_etag(tag), cached_etag) {
            return true;
        }
    }
    return false;
}

// Evaluates an If-Range header as either a strong entity-tag or an exact HTTP-date (RFC 9110 §13.1.5).
fn evaluate_cache_if_range(
    raw_if_range:         const u8[:],
    cached_etag:          const EntityTag&,
    cached_last_modified: core::Time,
) -> bool {
    var s = trim_lws(raw_if_range);
    guard s.len > 0 else { return false; }

    if s[0] == '"' || (s.len >= 2 && s[0] == 'W' && s[1] == '/') {
        return strong_eq(parse_etag(s), cached_etag);
    }

    let parsed_date, ok_date = core::parse_http_date(s);
    if ok_date && !is_zero(cached_last_modified) {
        return core::unix(parsed_date) == core::unix(cached_last_modified);
    }
    return false;
}

// ---- vary matching & cve-2026-93750 defense --------------------------------

// Single request header field recorded in a Vary snapshot.
struct VaryItem {
    name:      u8[..64]  = [],
    value:     u8[..256] = [],
    is_absent: bool      = false,
}

// Complete Vary snapshot captured from the original request/response exchange.
struct VarySnapshot {
    items:    VaryItem[..16] = [],
    has_star: bool           = false,
    valid:    bool           = true,
}

// Constructs a zero-initialized VarySnapshot.
// Checks if field_name already exists in recorded vary items.
fn has_vary_field(items: const VaryItem[..16]&, field_name: const u8[:]) -> bool {
    for &item in items {
        if eq_ascii_fold(item.name[..], field_name) { return true; }
    }
    return false;
}

// Extracts canonical header value from request headers for Vary recording.
//
// Example:
//   field_name = "Accept-Encoding", req_headers has "Accept-Encoding: gzip"
//   returns: true, out_val="gzip", is_oversized=false
fn extract_vary_value(
    req_headers:  const HeaderMap&,
    field_name:   const u8[:],
    out_val:      u8[..256]&,
    is_oversized: bool&,
) -> bool {
    var val_buf: u8[..512] = [];
    let ok_c = get_combined(req_headers, field_name, val_buf);
    let raw = if ok_c && val_buf.len > 0 {
        trim_lws(val_buf[..])
    } else if has_header(req_headers, field_name) {
        trim_lws(get_header(req_headers, field_name))
    } else {
        return false; // Absent
    };

    if raw.len > out_val.cap {
        is_oversized = true;
        return false;
    }
    out_val.append(raw);
    return true;
}

// Records the request headers specified in the response's Vary header.
// Defends against CVE-2026-93750 by marking has_star = true on "*", preventing subsequent matches.
fn record_vary_snapshot(cached_vary_raw: const u8[:], req_headers: const HeaderMap&) -> VarySnapshot {
    var snap = VarySnapshot { .. };
    var s = trim_lws(cached_vary_raw);
    guard s.len > 0 else { return snap; }

    var cursor: i64 = 0;
    while cursor < s.len {
        var end_idx = cursor;
        while end_idx < s.len && s[end_idx] != ',' { end_idx++; }
        let field_name = trim_lws(s[cursor..end_idx]);
        cursor = end_idx + 1;
        guard field_name.len > 0 else { continue; }

        if field_name == "*" {
            snap.has_star = true;
            return snap;
        }

        if !has_vary_field(snap.items, field_name) {
            guard snap.items.len < snap.items.cap && field_name.len <= 64 else {
                snap.valid = false;
                return snap;
            }
            var item = VaryItem { .. };
            item.name.append(field_name);
            var is_oversized = false;
            item.is_absent = !extract_vary_value(req_headers, field_name, item.value, is_oversized);
            if is_oversized {
                snap.valid = false;
                return snap;
            }
            snap.items.push(item);
        }
    }

    return snap;
}

// Evaluates whether incoming request headers match the cached representation's Vary invariants.
// Enforces strict simultaneous absence: absent in original requires absent in incoming (RFC 9111 §4.1).
fn matches_vary(snap: const VarySnapshot&, incoming_req_headers: const HeaderMap&) -> bool {
    guard !snap.has_star && snap.valid else { return false; }

    var incoming_buf: u8[..512] = [];
    for &item in snap.items {
        let field_name = item.name[..];
        let incoming_present = has_header(incoming_req_headers, field_name);

        if item.is_absent {
            if incoming_present { return false; }
            continue;
        }

        if !incoming_present { return false; }

        incoming_buf.clear();
        let ok_c = get_combined(incoming_req_headers, field_name, incoming_buf);
        let incoming_val = if ok_c && incoming_buf.len > 0 {
            trim_lws(incoming_buf[..])
        } else {
            trim_lws(get_header(incoming_req_headers, field_name))
        };

        if !eq_ascii_fold(incoming_val, item.value[..]) { return false; }
    }

    return true;
}

// ---- storage sanitization & 304 header merge -------------------------------

// Checks whether a header must be stripped prior to storage in cache.
fn should_strip_from_cache(entry_flags: u8, name: const u8[:], shared: bool, cc: const CacheControl&) -> bool {
    if (entry_flags & HEADER_FLAG_SECURITY_STATE) != 0 ||
       eq_ascii_fold(name, "strict-transport-security") ||
       eq_ascii_fold(name, "x-content-type-options") ||
       eq_ascii_fold(name, "x-webkit-csp") ||
       starts_with_fold(name, "x-content-") ||
       starts_with_fold(name, "x-webkit-") {
        return true;
    }
    if (entry_flags & HEADER_FLAG_CHALLENGE) != 0 ||
       eq_ascii_fold(name, "www-authenticate") ||
       eq_ascii_fold(name, "proxy-authenticate") {
        return true;
    }
    if shared && ((entry_flags & HEADER_FLAG_COOKIE_STATE) != 0 ||
       eq_ascii_fold(name, "set-cookie") ||
       eq_ascii_fold(name, "set-cookie2") ||
       eq_ascii_fold(name, "clear-site-data")) {
        return true;
    }
    if shared && is_private_field(cc, name) && cc.private_fields.len > 0 { return true; }
    if is_no_cache_field(cc, name) && cc.no_cache_fields.len > 0 { return true; }
    return false;
}

// Strips hop-by-hop headers, challenges, cookies (shared), security state headers,
// and qualified private/no-cache fields prior to cache storage. Rejects embedded NULs/CRLF.
//
// Example:
//   src = headers with "Connection: close", "ETag: 123"
//   populates dst with sanitized headers without hop-by-hop
fn sanitize_for_storage(
    src:    const HeaderMap&,
    dst:    HeaderMap&,
    shared: bool                = false,
    cc:     const CacheControl& = CacheControl { .. },
) {
    reset_for_keep_alive(dst);

    var intermediate = HeaderMap { .. };
    strip_hop_by_hop_headers(src, intermediate);

    for entry in intermediate.entries {
        let name = intermediate.raw_buf[entry.name_begin..entry.name_end];
        let val = intermediate.raw_buf[entry.values_begin..entry.values_end];

        if has_embedded_nulls(name) || has_embedded_nulls(val) || !is_valid_header_value(val) {
            continue;
        }
        if should_strip_from_cache(entry.flags, name, shared, cc) {
            continue;
        }

        append_header(dst, name, val);
    }
}

// Updates cached headers with new values from a 304 response (RFC 9111 §3.2).
// Strictly protects Content-Type, Content-Encoding, Content-Range, cookies, and security state headers.
fn merge_cached_headers_304(cached: HeaderMap&, resp_304: const HeaderMap&) {
    for entry in resp_304.entries {
        let name = resp_304.raw_buf[entry.name_begin..entry.name_end];
        let val = resp_304.raw_buf[entry.values_begin..entry.values_end];

        if has_embedded_nulls(name) || has_embedded_nulls(val) || !is_valid_header_value(val) {
            continue;
        }
        if should_update_header_304(entry.flags, name) {
            insert_header(cached, name, val);
        }
    }
}
