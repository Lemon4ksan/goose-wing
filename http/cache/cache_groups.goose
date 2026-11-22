// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9875: HTTP Cache Groups — Cache-Groups and Cache-Group-Invalidation response header fields.
// Parses and serializes List-of-Strings field values (RFC 9875 §2 and §3), attaches groups to
// stored responses, and invalidates stored responses by group membership. Group names are opaque
// strings compared case-sensitively (RFC 9875 §2.1).
namespace http;

import std;
import core;
import http.sfv;
import http.sfv_sig_internal;
import http.sfv_wire_internal;
import http.cache.engine;
import http.cache.internal;

// ---- RFC 9875 group limits -------------------------------------------------

// Maximum characters in a single cache group name (List of Strings per RFC 9875 §2; engine budget 64).
const CACHE_GROUP_TAG_MAX: i32 = 64;

// ---- cache group tag model -------------------------------------------------

// One cache group member: bounded name buffer plus explicit byte length (RFC 9875 §2).
struct CacheGroupTag {
    len:  i32      = 0,
    name: u8[..64] = [],
}

// Parses a Cache-Groups or Cache-Group-Invalidation List-of-Strings field value (RFC 9875 §2/§3).
// Fails closed: a non-String member, oversize name, excess member count, or malformed list yields
// ok == false with out_tags cleared. Unrecognised parameters are ignored (RFC 9875 §2).
//
// Example:
//   raw = "\"scripts\", \"fonts\"", out_tags = []
//   returns: true, out_tags = ["scripts", "fonts"] (out_tags.len == 2)
fn parse_cache_group_list(raw: const u8[:], out_tags: CacheGroupTag[..32]&) -> bool {
    var committed = false;
    defer if !committed { out_tags.clear(); };
    var parsed: CacheGroupTag[..32] = [];

    var cursor = http_internal::sf_skip_ws(raw, 0);

    while cursor < raw.len {
        var bare = SfvBareItem { .. };
        guard http_internal::parse_sfv_bare_item(raw, cursor, bare) else { return false; }
        guard bare.kind == SfvType.String else { return false; }

        guard http_internal::skip_sfv_parameters(raw, cursor) else { return false; }

        var tag = CacheGroupTag { len: bare.text.len as i32, .. };
        guard tag.name.try_set(bare.text[..]) && parsed.try_push(tag) else { return false; }

        var has_more = false;
        guard http_internal::sfv_advance_comma(raw, cursor, has_more) else { return false; }
        if !has_more { break; }
    }

    out_tags = parsed;
    committed = true;
    return true;
}

// Computes the exact wire length of the quoted List-of-Strings value for `tags` (RFC 9875 §2).
// Members cost name + 4 bytes ("name", with separator); the trailing ", " is subtracted for
// non-empty lists.
//
// Example:
//   tags = ["scripts", "fonts"]
//   returns: 18 ("\"scripts\", \"fonts\"")
fn cache_group_list_wire_len(tags: const CacheGroupTag[:]) -> i64 {
    guard tags.len > 0 else { return 0; }
    var total: i64 = 0;
    for &tag in tags {
        total = core::add_sat_i64(total, core::add_sat_i64(tag.name.len, 4));
    }
    return core::sub_sat_i64(total, 2);
}

// Serializes cache group members into a quoted List-of-Strings field value (RFC 9875 §2/§3).
// Members are joined by ", ". Rolls back `out` on capacity overflow and returns false.
//
// Example:
//   tags = ["scripts", "fonts"], out = []
//   returns: true, out = "\"scripts\", \"fonts\""
fn serialize_cache_group_list<B>(tags: const CacheGroupTag[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    for &tag, slot in tags {
        if slot > 0 {
            guard out.try_append(", ") else { return false; }
        }
        guard out.try_push('"') &&
              out.try_append(tag.name[..]) &&
              out.try_push('"') else {
            return false;
        }
    }
    committed = true;
    return true;
}

// Reports whether a stored response belongs to the given group.
// Names compare character-by-character, case sensitive (RFC 9875 §2.1).
// Evaluates `entry.headers.get_header("cache-groups")` on demand to avoid storing a 2.1 KB tag array per CachedEntry.
fn entry_has_group(entry: const CachedEntry&, group: const u8[:]) -> bool {
    let raw_cg = entry.headers.get_header("cache-groups");
    guard raw_cg.len > 0 else { return false; }
    var tags: CacheGroupTag[..32] = [];
    guard parse_cache_group_list(raw_cg, tags) && tags.len > 0 else { return false; }
    for &tag in tags {
        if tag.name[..] == group { return true; }
    }
    return false;
}

// Invalidates every valid stored response carrying the given group on the same origin; returns
// entries invalidated (group invalidation per RFC 9875 §2.1 & §3). Applies the same entry reset as
// invalidate_matching_url (invalid, security-zeroed, LRU-detached).
fn invalidate_group(
    cache:    Cache&,
    group:    const u8[:],
    base_url: const u8[:] = "",
) -> i64 {
    var count: i64 = 0;
    var has_origin = false;
    var base_orig = core::Origin { .. };
    if base_url.len > 0 {
        let parsed_base, err_base = core::parse_url(base_url);
        guard err_base == core::UrlParseError.None && parsed_base.valid else { return 0; }
        base_orig = core::origin_from_url(parsed_base);
        has_origin = base_orig.scheme.len > 0;
    }
    for &entry, idx in cache.entries {
        if !entry.is_valid { continue; }
        if !entry_has_group(entry, group) { continue; }
        if has_origin {
            let entry_url, err_u = core::parse_url(entry.url[..]);
            if err_u != core::UrlParseError.None || !entry_url.valid { continue; }
            let entry_orig = core::origin_from_url(entry_url);
            if !core::is_same_origin(entry_orig, base_orig) { continue; }
        }
        entry.is_valid = false;
        entry.security_zeroed = true;
        http_internal::lru_detach(cache, idx as i32);
        count = core::add_sat_i64(count, 1);
    }
    return count;
}
