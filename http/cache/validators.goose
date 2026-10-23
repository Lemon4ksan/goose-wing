// RFC 9110 & RFC 9111 Section 4.1: Conditional request validators and Vary matching engine.
// Implements EntityTag (ETag) weak/strong comparisons, Last-Modified revalidation,
// RFC 9111 §4.1 Vary normalization with CVE-2026-93750 defense, and 304 merge filtering.
namespace wing;

import std;
import core.time;
import app.profile;
import http.headers;
import http.cache.cache_control;

// ---- entity tag (etag) model (rfc 9110 section 8.8.3) ----------------------

struct EntityTag {
    is_weak: bool = false,
    tag: u8[..128] = [],
    valid: bool = false,
}

fn new_entity_tag() -> EntityTag {
    return EntityTag { .. };
}

// Parses an ETag header value into an EntityTag struct.
// Handles case-sensitive weak prefix "W/" and quoted opaque tag.
fn parse_etag(raw: const u8[:]) -> EntityTag {
    var etag = new_entity_tag();
    var s = trim_lws(raw);
    guard s.len >= 2 else { return etag; }

    // Case-sensitive "W/" prefix check (RFC 9110 §8.8.3)
    if s.len >= 4 && s[0] == 'W' && s[1] == '/' {
        etag.is_weak = true;
        s = s[2..];
    }

    // Must be enclosed in double quotes: "..."
    guard s.len >= 2 && s[0] == '"' && s[s.len - 1] == '"' else {
        return etag;
    }

    let inner_tag = s[1..s.len - 1];
    guard inner_tag.len <= 128 else { return etag; }

    etag.tag.append(inner_tag);
    etag.valid = true;
    return etag;
}

// RFC 9110 Section 8.8.3.2: Weak comparison function
// Two entity tags are weakly equal if their opaque tags are character-by-character identical,
// regardless of whether either or both are weak. Used for If-None-Match and 304 validation.
fn weak_eq(a: const EntityTag&, b: const EntityTag&) -> bool {
    guard a.valid && b.valid else { return false; }
    guard a.tag.len == b.tag.len else { return false; }
    for i in a.tag.len {
        if a.tag[i] != b.tag[i] {
            return false;
        }
    }
    return true;
}

// RFC 9110 Section 8.8.3.2: Strong comparison function
// Two entity tags are strongly equal only if NEITHER is weak and their opaque tags match.
// Used for If-Match, If-Range (206 partial content), and byte-range resumption.
fn strong_eq(a: const EntityTag&, b: const EntityTag&) -> bool {
    guard a.valid && b.valid else { return false; }
    guard !a.is_weak && !b.is_weak else { return false; }
    guard a.tag.len == b.tag.len else { return false; }
    for i in a.tag.len {
        if a.tag[i] != b.tag[i] {
            return false;
        }
    }
    return true;
}

// Checks if cached ETag matches an incoming If-None-Match header value
// Supports wildcard "*" and comma-separated lists of ETags using weak_eq
fn match_if_none_match(raw_if_none_match: const u8[:], cached_etag: const EntityTag&) -> bool {
    guard cached_etag.valid else { return false; }
    var s = trim_lws(raw_if_none_match);
    if s == "*" {
        return true;
    }

    var cursor: i64 = 0;
    while cursor < s.len {
        // Skip leading whitespace or commas
        while cursor < s.len && (s[cursor] == ' ' || s[cursor] == '\t' || s[cursor] == ',') {
            cursor++;
        }
        guard cursor < s.len else { break; }

        var end_idx = cursor;
        var in_quotes = false;
        while end_idx < s.len {
            let b = s[end_idx];
            if b == '"' {
                in_quotes = !in_quotes;
            } else if b == ',' && !in_quotes {
                break;
            }
            end_idx++;
        }

        let tag_slice = trim_lws(s[cursor..end_idx]);
        cursor = end_idx + 1;
        if tag_slice == "*" {
            return true;
        }
        let parsed = parse_etag(tag_slice);
        if weak_eq(parsed, cached_etag) {
            return true;
        }
    }
    return false;
}

// Checks if cached ETag matches an incoming If-Match header value using strong_eq
fn match_if_match(raw_if_match: const u8[:], cached_etag: const EntityTag&) -> bool {
    guard cached_etag.valid else { return false; }
    var s = trim_lws(raw_if_match);
    if s == "*" {
        return true;
    }

    var cursor: i64 = 0;
    while cursor < s.len {
        while cursor < s.len && (s[cursor] == ' ' || s[cursor] == '\t' || s[cursor] == ',') {
            cursor++;
        }
        guard cursor < s.len else { break; }

        var end_idx = cursor;
        var in_quotes = false;
        while end_idx < s.len {
            let b = s[end_idx];
            if b == '"' {
                in_quotes = !in_quotes;
            } else if b == ',' && !in_quotes {
                break;
            }
            end_idx++;
        }

        let tag_slice = trim_lws(s[cursor..end_idx]);
        cursor = end_idx + 1;
        if tag_slice == "*" {
            return true;
        }
        let parsed = parse_etag(tag_slice);
        if strong_eq(parsed, cached_etag) {
            return true;
        }
    }
    return false;
}

// RFC 9110 Section 13.1.5: If-Range evaluation
// If-Range can be either an entity-tag (requiring strong match) or an HTTP-date
fn evaluate_cache_if_range(raw_if_range: const u8[:], cached_etag: const EntityTag&, cached_last_modified: Time) -> bool {
    var s = trim_lws(raw_if_range);
    guard s.len > 0 else { return false; }

    // If starts with quote or W/, evaluate as entity-tag
    if s[0] == '"' || (s.len >= 2 && s[0] == 'W' && s[1] == '/') {
        let tag = parse_etag(s);
        return strong_eq(tag, cached_etag);
    }

    // Otherwise evaluate as HTTP-date (must match cached Last-Modified exactly)
    let parsed_date, ok_date = parse_http_date(s);
    if ok_date && !zero(cached_last_modified) {
        return unix(parsed_date) == unix(cached_last_modified);
    }
    return false;
}

// ---- vary matching & cve-2026-93750 defense --------------------------------

struct VaryItem {
    name: u8[..64] = [],
    value: u8[..256] = [],
    is_absent: bool = false,
}

struct VarySnapshot {
    items: VaryItem[..16] = [],
    has_star: bool = false,
    valid: bool = true,
}

fn new_vary_snapshot() -> VarySnapshot {
    return VarySnapshot { .. };
}

// Records the request headers specified in the response's Vary header.
// Defends against CVE-2026-93750: if Vary contains "*", marks has_star = true
// so that this representation will never match any subsequent request.
fn record_vary_snapshot(cached_vary_raw: const u8[:], req_headers: const HeaderMap&) -> VarySnapshot {
    var snap = new_vary_snapshot();
    var s = trim_lws(cached_vary_raw);
    guard s.len > 0 else { return snap; }

    var cursor: i64 = 0;
    while cursor < s.len {
        var end_idx = cursor;
        while end_idx < s.len && s[end_idx] != ',' {
            end_idx++;
        }
        let field_name = trim_lws(s[cursor..end_idx]);
        cursor = end_idx + 1;
        guard field_name.len > 0 else { continue; }

        // CVE-2026-93750 defense: Vary: * can never match any request
        if field_name == "*" {
            snap.has_star = true;
            return snap;
        }

        // Check if header already recorded
        var already = false;
        for &item in snap.items {
            if eq_ascii_fold(item.name[..], field_name) {
                already = true;
                break;
            }
        }
        if already { continue; }

        if snap.items.len < 16 {
            var item = VaryItem { .. };
            item.name.append(field_name);

            // Fetch combined or single header value from request
            var val_buf: u8[>..] = [];
            let ok_c = get_combined(req_headers, field_name, val_buf);
            if ok_c && val_buf.len > 0 {
                let trimmed = trim_lws(val_buf[..]);
                if trimmed.len <= 256 {
                    item.value.append(trimmed);
                } else {
                    item.value.append(trimmed[..256]);
                }
                item.is_absent = false;
            } else if has_header(req_headers, field_name) {
                let single = trim_lws(get_header(req_headers, field_name));
                if single.len <= 256 {
                    item.value.append(single);
                } else {
                    item.value.append(single[..256]);
                }
                item.is_absent = false;
            } else {
                item.is_absent = true;
            }
            snap.items.push(item);
        }
    }

    return snap;
}

// RFC 9111 Section 4.1: Vary Matching Algorithm
// Verifies whether the incoming request headers match the cached request headers
// for all fields listed in the Vary header.
// Enforces strict simultaneous-absence invariant: if the header was absent in the
// original request, it MUST ALSO be absent in the incoming request.
fn matches_vary(snap: const VarySnapshot&, incoming_req_headers: const HeaderMap&) -> bool {
    // CVE-2026-93750 defense: Vary: * always fails match
    guard !snap.has_star && snap.valid else { return false; }

    for &item in snap.items {
        let field_name = item.name[..];
        let incoming_present = has_header(incoming_req_headers, field_name);

        if item.is_absent {
            // Strict simultaneous absence: incoming request must not have this header
            if incoming_present {
                return false;
            }
        } else {
            // Header was present in original request: incoming must have it too
            if !incoming_present {
                return false;
            }
            var incoming_buf: u8[>..] = [];
            let ok_c = get_combined(incoming_req_headers, field_name, incoming_buf);
            let incoming_val = if ok_c && incoming_buf.len > 0 {
                trim_lws(incoming_buf[..])
            } else {
                trim_lws(get_header(incoming_req_headers, field_name))
            };

            // Compare canonical values
            if !eq_ascii_fold(incoming_val, item.value[..]) {
                return false;
            }
        }
    }

    return true;
}

// ---- storage sanitization & 304 header merge -------------------------------

// Strips hop-by-hop headers, auth challenges, cookies (in shared cache),
// security state headers, and qualified private/no-cache fields prior to cache storage.
// Enforces security invariants: rejects embedded \0, \r, \n in all values.
fn sanitize_for_storage(src: const HeaderMap&, dst: HeaderMap&, shared: bool = false, cc: const CacheControl& = CacheControl { .. }) {
    reset_for_keep_alive(dst);

    // Strip standard hop-by-hop headers and custom Connection tokens first
    var intermediate = new_header_map();
    strip_hop_by_hop_headers(src, intermediate);

    for entry in intermediate.entries {
        let name = intermediate.raw_buf[entry.name_begin..entry.name_end];
        let val = intermediate.raw_buf[entry.values_begin..entry.values_end];

        // Security check: reject embedded nulls or malformed header values
        if has_embedded_nulls(name) || has_embedded_nulls(val) || !is_valid_header_value(val) {
            continue;
        }

        // Strip security state headers (HSTS, CSP, etc. must not be cached as stale override)
        if (entry.flags & HEADER_FLAG_SECURITY_STATE) != 0 ||
           eq_ascii_fold(name, "strict-transport-security") ||
           eq_ascii_fold(name, "x-content-type-options") ||
           eq_ascii_fold(name, "x-webkit-csp") ||
           starts_with_ignore_case(name, "x-content-") ||
           starts_with_ignore_case(name, "x-webkit-") {
            continue;
        }

        // Strip authentication challenges
        if (entry.flags & HEADER_FLAG_CHALLENGE) != 0 ||
           eq_ascii_fold(name, "www-authenticate") ||
           eq_ascii_fold(name, "proxy-authenticate") {
            continue;
        }

        // Shared cache must never store cookies or session clearing state
        if shared && ((entry.flags & HEADER_FLAG_COOKIE_STATE) != 0 ||
           eq_ascii_fold(name, "set-cookie") ||
           eq_ascii_fold(name, "set-cookie2") ||
           eq_ascii_fold(name, "clear-site-data")) {
            continue;
        }

        // Strip qualified private fields
        if is_private_field(cc, name) && cc.private_fields.len > 0 {
            continue;
        }

        // Strip qualified no-cache fields
        if is_no_cache_field(cc, name) && cc.no_cache_fields.len > 0 {
            continue;
        }

        append_header(dst, name, val);
    }
}

// RFC 9111 Section 3.2: 304 Not Modified header merge
// Updates cached headers with new values from 304 response, strictly preserving
// message framing, body encoding, cookies, challenges, and security state headers.
fn merge_cached_headers_304(cached: HeaderMap&, resp_304: const HeaderMap&) {
    for entry in resp_304.entries {
        let name = resp_304.raw_buf[entry.name_begin..entry.name_end];
        let val = resp_304.raw_buf[entry.values_begin..entry.values_end];

        // Security check
        if has_embedded_nulls(name) || has_embedded_nulls(val) || !is_valid_header_value(val) {
            continue;
        }

        // Strict RFC 9111 §3.2 & Chromium kNonUpdatedHeaders check
        if should_update_header_304(entry.flags, name) {
            insert_header(cached, name, val);
        }
    }
}
