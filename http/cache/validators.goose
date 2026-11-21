// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9110 & RFC 9111 Section 4.1: Conditional request validators and Vary matching engine.
// Implements EntityTag (ETag) weak/strong comparisons, Last-Modified revalidation,
// RFC 9111 Section 4.1 Vary-star poisoning defense, and 304 merge filtering.
namespace http;

import std;
import core from "../..";
import http.headers;
import http.cache.cache_control;
import http.cache.internal;

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
    var s = raw.trim_lws();
    guard s.len >= 2 else { return etag; }

    if s.len >= 4 && s[0] == 'W' && s[1] == '/' {
        etag.is_weak = true;
        s = s[2..];
    }

    guard s.len >= 2 && s[0] == '"' && s[s.len - 1] == '"' else {
        return etag;
    }

    let inner_tag = s[1..^1];
    for b in inner_tag {
        guard b > 0x20 && b != '"' && b != 0x7F else { return etag; }
    }
    guard etag.tag.try_set(inner_tag) else { return etag; }

    etag.valid = true;
    return etag;
}

// Performs weak comparison of two entity tags (RFC 9110 §8.8.3.2).
// Opaque tags must match byte-for-byte; weakness flags are ignored.
fn weak_eq(a: EntityTag, b: EntityTag) -> bool {
    guard a.valid && b.valid else { return false; }
    return core::equal_short(a.tag[..], b.tag[..]);
}

// Performs strong comparison of two entity tags (RFC 9110 §8.8.3.2).
// Requires that neither tag is weak and opaque tags match byte-for-byte.
fn strong_eq(a: EntityTag, b: EntityTag) -> bool {
    guard a.valid && b.valid && !a.is_weak && !b.is_weak else { return false; }
    return core::equal_short(a.tag[..], b.tag[..]);
}

// Checks if cached ETag matches an incoming If-None-Match header (RFC 9110 §13.1.2).
// Supports wildcard "*" and comma-separated lists of ETags using weak_eq.
fn match_if_none_match(raw_if_none_match: const u8[:], cached_etag: const EntityTag&) -> bool {
    guard cached_etag.valid else { return false; }
    let s = raw_if_none_match.trim_lws();
    if s == "*" { return true; }

    var cursor: i64 = 0;
    while cursor < s.len {
        let tag = http_internal::read_next_etag_token(s, cursor);
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
    let s = raw_if_match.trim_lws();
    if s == "*" { return true; }

    var cursor: i64 = 0;
    while cursor < s.len {
        let tag = http_internal::read_next_etag_token(s, cursor);
        guard tag.len > 0 else { break; }
        if tag == "*" || strong_eq(parse_etag(tag), cached_etag) {
            return true;
        }
    }
    return false;
}

// Evaluates an If-Range header as either a strong entity-tag or an exact HTTP-date (RFC 9110 §13.1.5).
fn evaluate_cache_if_range(
    raw_if_range:             const u8[:],
    cached_etag:              const EntityTag&,
    cached_last_modified_sec: i64,
) -> bool {
    var s = raw_if_range.trim_lws();
    guard s.len > 0 else { return false; }

    if s[0] == '"' || (s.len >= 2 && s[0] == 'W' && s[1] == '/') {
        return strong_eq(parse_etag(s), cached_etag);
    }

    let parsed_date, ok_date = core::parse_http_date(s);
    if ok_date && cached_last_modified_sec != 0 {
        return core::unix(parsed_date) == cached_last_modified_sec;
    }
    return false;
}

// ---- vary matching & rfc 9111 section 4.1 vary-star poisoning defense ------

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

// Records the request headers specified in the response's Vary header.
// RFC 9111 Section 4.1 Vary-star poisoning defense: marks has_star = true on "*", preventing subsequent matches.
fn record_vary_snapshot(cached_vary_raw: const u8[:], req_headers: const HeaderMap&) -> VarySnapshot {
    var snap = VarySnapshot { .. };
    var s = cached_vary_raw.trim_lws();
    guard s.len > 0 else { return snap; }

    var cursor: i64 = 0;
    while cursor < s.len {
        var end_idx = cursor;
        while end_idx < s.len && s[end_idx] != ',' { end_idx++; }
        let field_name = s[cursor..end_idx].trim_lws();
        cursor = end_idx + 1;
        guard field_name.len > 0 else { continue; }

        if field_name == "*" {
            snap.has_star = true;
            return snap;
        }

        if !http_internal::has_vary_field(snap.items, field_name) {
            var item = VaryItem { .. };
            guard item.name.try_set(field_name) else {
                snap.valid = false;
                return snap;
            }
            var is_oversized = false;
            item.is_absent = !http_internal::extract_vary_value(req_headers, field_name, item.value, is_oversized);
            if is_oversized || !snap.items.try_push(item) {
                snap.valid = false;
                return snap;
            }
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
        let ok_c = get_combined(incoming_req_headers, field_name, incoming_buf, 512);
        guard ok_c else { return false; }
        let incoming_val = incoming_buf[..].trim_lws();

        if !incoming_val.eq_ascii_fold(item.value[..]) { return false; }
    }

    return true;
}

// ---- storage sanitization & 304 header merge -------------------------------

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

        let invalid = http_internal::has_embedded_nulls(name) ||
            http_internal::has_embedded_nulls(val) || !is_valid_header_value(val);
        if invalid {
            continue;
        }
        if http_internal::should_strip_from_cache(entry.flags, name, shared, cc) {
            continue;
        }

        append_header(dst, name, val);
    }
}

// Updates cached headers with new values from a 304 response (RFC 9111 §3.2).
// Strictly protects Content-Type, Content-Encoding, Content-Range, cookies, and security state headers.
fn merge_cached_headers_304(cached: HeaderMap&, resp_304: const HeaderMap&) {
    guard cached.valid && resp_304.valid else { return; }
    cached.merge_with_headers_304(resp_304);
}
