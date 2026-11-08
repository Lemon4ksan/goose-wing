// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// server/cache.goose
// Coalescing High-Throughput HTTP Route Cache (uWebSockets HttpCache.h).
// Protects endpoints from thundering herds by caching rendered HTTP wire responses.
// Uses dual-expiry windows (lower_expiry_ms, upper_expiry_ms):
// - lower_expiry_ms: Freshness window; requests served instantly from cache.
// - upper_expiry_ms: Maximum staleness; served during background refresh to prevent herd spikes.
namespace wing;

import std;
import core from "..";

enum CacheLookup {
    HitFresh,
    HitStaleNeedsUpdate,
    Miss,
}

struct CacheEntry {
    created_ms:   u64         = 0,
    handler_id:   i32         = -1,
    content_type: u8[..64]    = [],
    etag:         u8[..64]    = [],
    url_key:      u8[..256]   = [],
    wire:         u8[..16384] = [],
    is_valid:     bool        = false,
    prev_lru:     i32         = -1,
    next_lru:     i32         = -1,
}

struct HttpRouteCache {
    created_ms:      u64             = 0,
    lower_expiry_ms: u64             = 1000,
    upper_expiry_ms: u64             = 5000,
    handler_id:      i32             = -1,
    content_type:    u8[..64]        = [],
    etag:            u8[..64]        = [],
    url_key:         u8[..256]       = [],
    wire:            u8[..16384]     = [],
    is_valid:        bool            = false,
    is_updating:     bool            = false,
    entries:         CacheEntry[..8] = [],
    lru_head:        i32             = -1,
    lru_tail:        i32             = -1,
}

fn new_http_route_cache(lower_expiry_ms: u64 = 1000, upper_expiry_ms: u64 = 5000) -> HttpRouteCache {
    return HttpRouteCache {
        lower_expiry_ms: lower_expiry_ms,
        upper_expiry_ms: upper_expiry_ms,
        created_ms:      0,
        handler_id:      -1,
        is_valid:        false,
        is_updating:     false,
        lru_head:        -1,
        lru_tail:        -1,
        ..
    };
}

// Detaches `idx` from the intrusive doubly-linked LRU list in O(1).
fn detach_cache_lru(cache: HttpRouteCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    let prev = node.prev_lru;
    let next = node.next_lru;
    if prev >= 0 {
        cache.entries[prev as i64].next_lru = next;
    } else if cache.lru_head == idx {
        cache.lru_head = next;
    }
    if next >= 0 {
        cache.entries[next as i64].prev_lru = prev;
    } else if cache.lru_tail == idx {
        cache.lru_tail = prev;
    }
    node.prev_lru = -1;
    node.next_lru = -1;
}

// Appends `idx` to the MRU tail (`lru_tail`) of the intrusive LRU list in O(1).
fn attach_cache_lru_tail(cache: HttpRouteCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    node.prev_lru = cache.lru_tail;
    node.next_lru = -1;
    if cache.lru_tail >= 0 {
        cache.entries[cache.lru_tail as i64].next_lru = idx;
    } else {
        cache.lru_head = idx;
    }
    cache.lru_tail = idx;
}

// Promotes `idx` to the MRU tail in O(1) (`OrderedDict.move_to_end` equivalent).
fn touch_cache_lru(cache: HttpRouteCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    if cache.lru_tail == idx {
        return;
    }
    detach_cache_lru(cache, idx);
    attach_cache_lru_tail(cache, idx);
}

inline fn route_entry_matches(
    e:          const CacheEntry&,
    handler_id: i32,
    url_key:    const u8[:],
) -> bool {
    guard e.is_valid && e.wire.len > 0 else { return false; }
    if handler_id >= 0 && e.handler_id >= 0 && e.handler_id != handler_id {
        return false;
    }
    if url_key.len > 0 && e.url_key.len > 0 && e.url_key[..] != url_key {
        return false;
    }
    return true;
}

inline fn sync_active_cache_entry(c: HttpRouteCache&, e: const CacheEntry&) {
    if !c.is_valid || c.handler_id != e.handler_id || c.created_ms != e.created_ms || c.url_key[..] != e.url_key[..] {
        let _ = c.wire.try_set(e.wire[..]);
        let _ = c.content_type.try_set(e.content_type[..]);
        let _ = c.url_key.try_set(e.url_key[..]);
        let _ = c.etag.try_set(e.etag[..]);
        c.handler_id = e.handler_id;
        c.created_ms = e.created_ms;
        c.is_valid = true;
    }
}

inline fn classify_cache_age(c: const HttpRouteCache&, created_ms: u64, now_ms: u64) -> CacheLookup {
    let age = core::sub_sat_u64(now_ms, created_ms);
    if age <= c.lower_expiry_ms {
        return CacheLookup.HitFresh;
    }
    if age <= c.upper_expiry_ms {
        return CacheLookup.HitStaleNeedsUpdate;
    }
    return CacheLookup.Miss;
}

// Looks up cached wire response at time now_ms and promotes hit entry in O(1) LRU order.
fn cache_lookup(
    c:          HttpRouteCache&,
    now_ms:     u64,
    handler_id: i32         = -1,
    url_key:    const u8[:] = "",
) -> CacheLookup {
    guard url_key.len <= c.url_key.cap else {
        return CacheLookup.Miss;
    }
    for i in c.entries.len {
        let hit .= c.entries[i];
        if route_entry_matches(hit, handler_id, url_key) {
            touch_cache_lru(c, i as i32);
            sync_active_cache_entry(c, hit);
            return classify_cache_age(c, hit.created_ms, now_ms);
        }
    }
    guard c.entries.len == 0 && c.is_valid && c.wire.len > 0 else {
        return CacheLookup.Miss;
    }
    if handler_id >= 0 && c.handler_id >= 0 && c.handler_id != handler_id {
        return CacheLookup.Miss;
    }
    if url_key.len > 0 && c.url_key.len > 0 && c.url_key[..] != url_key {
        return CacheLookup.Miss;
    }
    return classify_cache_age(c, c.created_ms, now_ms);
}

inline fn populate_cache_entry(
    entry:        CacheEntry&,
    now_ms:       u64,
    wire_data:    const u8[:],
    handler_id:   i32,
    content_type: const u8[:],
    url_key:      const u8[:],
    etag:         const u8[:],
) {
    let _ = entry.wire.try_set(wire_data);
    let _ = entry.content_type.try_set(content_type);
    let _ = entry.url_key.try_set(url_key);
    let _ = entry.etag.try_set(etag);
    entry.handler_id = handler_id;
    entry.created_ms = now_ms;
    entry.is_valid = true;
}

// Stores rendered wire bytes into cache and updates the O(1) intrusive LRU list.
fn cache_store(
    c:            HttpRouteCache&,
    now_ms:       u64,
    wire_data:    const u8[:],
    handler_id:   i32         = -1,
    content_type: const u8[:] = "",
    url_key:      const u8[:] = "",
    etag:         const u8[:] = "",
) -> bool {
    c.is_updating = false;
    guard wire_data.len <= c.wire.cap
        && content_type.len <= c.content_type.cap
        && url_key.len <= c.url_key.cap
        && etag.len <= c.etag.cap else {
        return false;
    }
    let _ = c.wire.try_set(wire_data);
    let _ = c.content_type.try_set(content_type);
    let _ = c.url_key.try_set(url_key);
    let _ = c.etag.try_set(etag);
    c.handler_id = handler_id;
    c.created_ms = now_ms;
    c.is_valid = true;

    for i in c.entries.len {
        let cur .= c.entries[i];
        if cur.is_valid && cur.handler_id == handler_id && cur.url_key[..] == url_key {
            populate_cache_entry(cur, now_ms, wire_data, handler_id, content_type, url_key, etag);
            touch_cache_lru(c, i as i32);
            return true;
        }
    }

    let new_idx = c.entries.len as i32;
    var entry = CacheEntry { prev_lru: -1, next_lru: -1, .. };
    populate_cache_entry(entry, now_ms, wire_data, handler_id, content_type, url_key, etag);
    if c.entries.try_push(entry) {
        attach_cache_lru_tail(c, new_idx);
    } else {
        let victim_idx: i32 = if c.lru_head >= 0 && c.lru_head < c.entries.len { c.lru_head } else { 0 };
        detach_cache_lru(c, victim_idx);
        c.entries[victim_idx as i64] = entry;
        attach_cache_lru_tail(c, victim_idx);
    }
    return true;
}

// Invalidates cache and resets intrusive LRU links.
fn cache_invalidate(c: HttpRouteCache&) {
    c.is_valid = false;
    c.is_updating = false;
    c.etag.clear();
    c.url_key.clear();
    c.wire.clear();
    c.entries.clear();
    c.lru_head = -1;
    c.lru_tail = -1;
}
