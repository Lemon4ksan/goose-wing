// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation DNS cache with TTL and Stale-While-Revalidate (RFC 1035 & RFC 5861).
// Backed by an intrusive doubly-linked LRU list over a bounded 64-entry array.
namespace wing;

import std;
import core from "..";
import .svcb;

// ---- DNS Cache with TTL and Stale-While-Revalidate (RFC 1035 & RFC 5861) -

enum DnsCacheStatus {
    Fresh,   // Within TTL
    Stale,   // Expired past TTL, but within stale-while-revalidate window
    Expired, // Beyond stale window or not found
}

struct DnsCacheEntry {
    domain:          u8[..255]        = [],
    qtype:           u16              = rfc::DNS_QTYPE_A,
    ipv4_hints:      u32[..8]         = [],
    ipv6_hints:      u8[16][..8]      = [],
    https_records:   HttpsRecord[..4] = [],
    inserted_at_sec: i64              = 0,
    ttl_sec:         u32              = 300,
    stale_ttl_sec:   u32              = 86400, // 24-hour max stale grace period
    valid:           bool             = false,
    lru_prev:        i32              = -1,
    lru_next:        i32              = -1,
}

struct DnsCache {
    entries:  DnsCacheEntry[..64] = [],
    lru_head: i32                 = -1,
    lru_tail: i32                 = -1,
}

// Detaches `idx` from the intrusive doubly-linked DNS LRU list in O(1).
fn detach_dns_lru(cache: DnsCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    let prev = node.lru_prev;
    let next = node.lru_next;
    if prev >= 0 {
        cache.entries[prev as i64].lru_next = next;
    } else if cache.lru_head == idx {
        cache.lru_head = next;
    }
    if next >= 0 {
        cache.entries[next as i64].lru_prev = prev;
    } else if cache.lru_tail == idx {
        cache.lru_tail = prev;
    }
    node.lru_prev = -1;
    node.lru_next = -1;
}

// Appends `idx` to the MRU tail (`lru_tail`) of the intrusive DNS LRU list in O(1).
fn attach_dns_lru_tail(cache: DnsCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    node.lru_prev = cache.lru_tail;
    node.lru_next = -1;
    if cache.lru_tail >= 0 {
        cache.entries[cache.lru_tail as i64].lru_next = idx;
    } else {
        cache.lru_head = idx;
    }
    cache.lru_tail = idx;
}

// Promotes `idx` to the MRU tail in O(1) (`OrderedDict.move_to_end` equivalent).
fn touch_dns_lru(cache: DnsCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    if cache.lru_tail == idx {
        return;
    }
    detach_dns_lru(cache, idx);
    attach_dns_lru_tail(cache, idx);
}

fn dns_cache_lookup(
    cache:     const DnsCache&,
    domain:    const u8[:],
    qtype:     u16,
    now_sec:   i64,
    out_entry: DnsCacheEntry&,
) -> DnsCacheStatus {
    for &e in cache.entries {
        if e.valid && e.qtype == qtype && e.domain[..].eq_ascii_fold(domain) {
            guard e.ttl_sec > 0 && now_sec >= e.inserted_at_sec else { return DnsCacheStatus.Expired; }
            let elapsed = core::sub_sat_i64(now_sec, e.inserted_at_sec);
            let ttl_i64:   i64 = e.ttl_sec;
            let stale_i64: i64 = e.stale_ttl_sec;
            let total_ttl_i64 = core::add_sat_i64(ttl_i64, stale_i64);
            if elapsed < ttl_i64 {
                out_entry = e;
                return DnsCacheStatus.Fresh;
            } else if elapsed < total_ttl_i64 {
                out_entry = e;
                return DnsCacheStatus.Stale;
            } else {
                return DnsCacheStatus.Expired;
            }
        }
    }
    return DnsCacheStatus.Expired;
}

fn dns_cache_insert(cache: DnsCache&, entry: const DnsCacheEntry&) {
    for i in cache.entries.len {
        let cur .= cache.entries[i];
        let is_match = cur.valid &&
            cur.qtype == entry.qtype &&
            cur.domain[..].eq_ascii_fold(entry.domain[..]);
        if is_match {
            let prev = cur.lru_prev;
            let next = cur.lru_next;
            cur = entry;
            cur.valid = true;
            cur.lru_prev = prev;
            cur.lru_next = next;
            touch_dns_lru(cache, i as i32);
            return;
        }
    }

    let new_idx = cache.entries.len as i32;
    if cache.entries.try_push(entry) {
        let cur .= cache.entries[new_idx as i64];
        cur.valid = true;
        cur.lru_prev = -1;
        cur.lru_next = -1;
        attach_dns_lru_tail(cache, new_idx);
    } else {
        let victim_idx: i32 = if cache.lru_head >= 0 && cache.lru_head < cache.entries.len {
            cache.lru_head
        } else {
            0
        };
        detach_dns_lru(cache, victim_idx);
        let cur .= cache.entries[victim_idx as i64];
        cur = entry;
        cur.valid = true;
        cur.lru_prev = -1;
        cur.lru_next = -1;
        attach_dns_lru_tail(cache, victim_idx);
    }
}
