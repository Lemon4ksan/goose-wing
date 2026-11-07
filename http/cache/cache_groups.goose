// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9875: HTTP Cache Groups — Cache-Groups and Cache-Group-Invalidation response header fields.
// Parses and serializes List-of-Strings field values (RFC 9875 §2 and §3), attaches groups to
// stored responses, and invalidates stored responses by group membership. Group names are opaque
// strings compared case-sensitively (RFC 9875 §2.1).
namespace wing;

import std;
import http.mime;
import http.cache.engine;

// ---- RFC 9875 group limits -------------------------------------------------

// Maximum characters in a single cache group name (List of Strings per RFC 9875 §2; engine budget 64).
const CACHE_GROUP_TAG_MAX: i32 = 64;

// Maximum group members per stored response (RFC 9875 §2 mandates at least 32; engine budget 32)..
const CACHE_GROUP_MAX_PER_ENTRY: i32 = 32;

// ---- cache group tag model -------------------------------------------------

// One cache group member: bounded name buffer plus explicit byte length (RFC 9875 §2).
struct CacheGroupTag {
    len:  i32      = 0,
    name: u8[..64] = [],
}

// Parses a Cache-Groups or Cache-Group-Invalidation List-of-Strings field value (RFC 9875 §2/§3).
// Fails closed: a non-String member, oversize name, excess member count, or malformed list yields
// ok == false with out_count == 0. Unrecognised parameters are ignored (RFC 9875 §2).
//
// Example:
//   raw = "\"scripts\", \"fonts\"", out_tags = [], out_count = 0
//   returns: true, out_tags = ["scripts", "fonts"], out_count = 2
fn parse_cache_group_list(raw: const u8[:], out_tags: CacheGroupTag[..32]&, out_count: i32&) -> bool {
    out_count = 0;
    var parsed: CacheGroupTag[..32] = [];

    var cursor: i64 = 0;
    sfv_skip_ows(raw, cursor);

    while cursor < raw.len {
        var bare = SfvBareItem { .. };
        guard parse_sfv_bare_item(raw, cursor, bare) else { return false; }
        guard bare.kind == SfvType.String else { return false; }

        var ignored_params: SfvParam[..16] = [];
        guard parse_sfv_parameters(raw, cursor, ignored_params) else { return false; }

        guard bare.text.len <= CACHE_GROUP_TAG_MAX else { return false; }
        guard parsed.len < CACHE_GROUP_MAX_PER_ENTRY else { return false; }

        var tag = CacheGroupTag { .. };
        tag.name.append(bare.text[..]);
        tag.len = bare.text.len as i32;
        parsed.push(tag);

        var has_more = false;
        guard sfv_advance_comma(raw, cursor, has_more) else { return false; }
        if !has_more { break; }
    }

    out_tags = parsed;
    out_count = parsed.len as i32;
    return true;
}

// Computes the exact wire length of the quoted List-of-Strings value for the first count members
// (RFC 9875 §2). Members cost name + 4 bytes ("name", with separator); the trailing ", " is
// subtracted for non-empty lists. Clamped to tags.len so out-of-range counts never index past
// the caller's tag vector.
//
// Example:
//   tags = ["scripts", "fonts"], count = 2
//   returns: 18 ("\"scripts\", \"fonts\"")
fn cache_group_list_wire_len(tags: const CacheGroupTag[..32]&, count: i32) -> i64 {
    var wire: u8[..2176] = [];
    var limit = tags.len;
    if count < tags.len { limit = count; }
    for slot in 0..limit {
        wire.append("\"");
        wire.append(tags[slot].name[..]);
        wire.append("\", ");
    }
    var trailing: i64 = 0;
    if count > 0 { trailing = 2; }
    return wire.len - trailing;
}

// Byte delta appended to the caller-owned buffer during this serialization.
fn cache_group_bytes_written(now_len: i64, start_len: i64) -> i64 {
    return now_len - start_len;
}

// Accumulates two counts of invalidated stored responses (RFC 9875 §2.2.1 group purge totals).
fn add_invalidated_entries(total: i64, purged: i64) -> i64 {
    return total + purged;
}

// Serializes cache group members into a quoted List-of-Strings field value (RFC 9875 §2/§3).
// Members are joined by ", ". Returns bytes written, or -1 when count is out of range or the
// output would overflow the caller-owned buffer.
//
// Example:
//   tags = ["scripts", "fonts"], count = 2, out = []
//   returns: 18, out = "\"scripts\", \"fonts\""
fn serialize_cache_group_list(tags: const CacheGroupTag[..32]&, count: i32, out: u8[..512]&) -> i32 {
    guard count >= 0 && count <= tags.len &&
        cache_group_list_wire_len(tags, count) <= out.cap - out.len else { return -1; }
    let start_len = out.len;
    for slot in 0..count {
        if slot > 0 { out.append(", "); }
        out.append("\"");
        out.append(tags[slot].name[..]);
        out.append("\"");
    }
    return cache_group_bytes_written(out.len, start_len) as i32;
}

// Reports whether a stored response belongs to the given group.
// Names compare character-by-character, case sensitive (RFC 9875 §2.1).
// Evaluates `entry.headers.get_header("cache-groups")` on demand to avoid storing a 2.1 KB tag array per CachedEntry.
fn entry_has_group(entry: const CachedEntry&, group: const u8[:]) -> bool {
    let raw_cg = entry.headers.get_header("cache-groups");
    guard raw_cg.len > 0 else { return false; }
    var tags:  CacheGroupTag[..32] = [];
    var count: i32                 = 0;
    guard parse_cache_group_list(raw_cg, tags, count) && count > 0 else { return false; }
    for slot in 0..count {
        if tags[slot].name[..] == group { return true; }
    }
    return false;
}

// Invalidates every valid stored response carrying the given group on the same origin; returns
// entries invalidated (group invalidation per RFC 9875 §2.1 & §3). Applies the same entry reset as
// invalidate_matching_url (invalid, security-zeroed, LRU-detached).
fn invalidate_group(
    cache:     HttpCache&,
    group:     const u8[:],
    base_orig: core::Origin = core::Origin { .. },
) -> i64 {
    var count: i64 = 0;
    let check_origin = base_orig.scheme.len > 0;
    for &entry, idx in cache.entries {
        if !entry.is_valid { continue; }
        if !entry_has_group(entry, group) { continue; }
        if check_origin {
            let entry_url, err_u = core::parse_url(entry.url[..]);
            if err_u != core::UrlParseError.None || !entry_url.valid { continue; }
            let entry_orig = core::origin_from_url(entry_url);
            if !core::is_same_origin(entry_orig, base_orig) { continue; }
        }
        entry.is_valid = false;
        entry.security_zeroed = true;
        cache.lru_detach(idx as i32);
        count = add_invalidated_entries(count, 1);
    }
    return count;
}
