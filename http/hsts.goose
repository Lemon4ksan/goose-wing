// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 6797 HTTP Strict Transport Security (HSTS) & Automated Protocol Upgrade Engine.
// Supports:
// - `Strict-Transport-Security` response header parsing (max-age, includeSubDomains, preload)
// - Dynamic HSTS Host Cache with TTL expiration and deletion (max-age=0)
// - Embedded static Chromium/IETF Preload List (top secure domains & .dev / .app HSTS TLDs)
// - Pre-flight transparent URL upgrade (rewriting http:// to https:// before network dispatch)
// - RFC 6797 Section 8.1 transport security constraint (insecure HTTP HSTS rejection)
namespace wing;

import std;
import core from "..";

// ---- 1. HSTS Directive Model ------------------------------------------------

struct HstsDirective {
    max_age_sec:        i64  = 0,
    include_subdomains: bool = false,
    preload:            bool = false,
    valid:              bool = false,
}

// ---- 2. Header Parsing (RFC 6797 Section 6.1) -------------------------------

// Parses delta-seconds from max-age directive, supporting optional quotes.
//
// Example:
//   val = "31536000"
//   returns: 31536000, ok = true
fn parse_hsts_max_age(val: const u8[:]) -> i64, bool {
    guard val.len > 0 else { return 0, false; }
    var unquoted = val;
    if val[0] == '"' {
        guard val.len >= 2 && val[val.len - 1] == '"' else { return 0, false; }
        unquoted = val[1..val.len - 1];
    }
    guard unquoted.len > 0 && unquoted[0] >= '0' && unquoted[0] <= '9' else { return 0, false; }
    return unquoted.parse_i64_dec();
}

fn apply_hsts_directive(d: HstsDirective&, trimmed: const u8[:]) -> bool {
    let name, val, has_val = trimmed.split_once_byte('=');
    let key = name.trim_lws();
    if eq_ascii_fold(key, "includesubdomains") {
        d.include_subdomains = true;
        return true;
    }
    if eq_ascii_fold(key, "preload") {
        d.preload = true;
        return true;
    }
    if eq_ascii_fold(key, "max-age") {
        guard !d.valid && has_val else { return false; }
        let parsed_age, age_ok = parse_hsts_max_age(val.trim_lws());
        guard age_ok else { return false; }
        d.max_age_sec = parsed_age;
        d.valid = true;
        return true;
    }
    return true;
}

// Parses `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
//
// Example:
//   raw = "max-age=31536000; includeSubDomains"
//   returns: d with max_age_sec=31536000, include_subdomains=true, ok = true
fn parse_hsts_header(raw: const u8[:]) -> HstsDirective, bool {
    var d = HstsDirective { .. };
    guard raw.len > 0 else { return d, false; }

    var tok = make_byte_tokenizer(raw, ';');
    while true {
        let part, ok = tok.token_next();
        guard ok else { break; }
        let trimmed = part.trim_lws();
        guard trimmed.len > 0 else { continue; }
        guard apply_hsts_directive(d, trimmed) else { return d, false; }
    }

    return d, d.valid;
}

// ---- 3. HSTS Cache & Preload List -------------------------------------------

struct HstsEntry {
    host:               u8[..256] = [],
    expiry_epoch_sec:   i64       = 0,
    include_subdomains: bool      = false,
    is_preload:         bool      = false,
    valid:              bool      = false,
}

struct HstsCache {
    entries:             HstsEntry[..16] = [],
    enable_preload_list: bool            = true,
}

fn host_matches_domain(sub: const u8[:], domain: const u8[:]) -> bool {
    if eq_ascii_fold(sub, domain) { return true; }
    guard sub.len > domain.len + 1 else { return false; }
    guard ends_with_fold(sub, domain) else { return false; }
    return sub[sub.len - domain.len - 1] == '.';
}

fn is_preloaded_tld(hostname: const u8[:]) -> bool {
    return ends_with_fold(hostname, ".dev") || ends_with_fold(hostname, ".app") ||
           ends_with_fold(hostname, ".page") || ends_with_fold(hostname, ".bank");
}

fn is_preloaded_property(h: const u8[:]) -> bool {
    if host_matches_domain(h, "google.com") || host_matches_domain(h, "github.com") { return true; }
    if host_matches_domain(h, "paypal.com") || host_matches_domain(h, "bankofamerica.com") { return true; }
    if host_matches_domain(h, "cloudflare.com") || host_matches_domain(h, "wikipedia.org") { return true; }
    return false;
}

// Checks if a hostname matches static preload list (Chromium HSTS Preload list subset)
fn is_static_preloaded_host(hostname: const u8[:]) -> bool, bool {
    if is_preloaded_tld(hostname) || is_preloaded_property(hostname) {
        return true, true;
    }
    return false, false;
}

// Checks if host is a subdomain of parent (e.g. "api.example.com" of "example.com")
fn is_subdomain_of(sub: const u8[:], parent: const u8[:]) -> bool {
    guard sub.len > parent.len + 1 else { return false; }
    guard ends_with_fold(sub, parent) else { return false; }
    return sub[sub.len - parent.len - 1] == '.';
}

fn entry_matches_hsts(entry: const HstsEntry&, hostname: const u8[:], now_sec: i64) -> bool {
    guard entry.valid && entry.expiry_epoch_sec >= now_sec else { return false; }
    if eq_ascii_fold(hostname, entry.host[..]) {
        return true;
    }
    return entry.include_subdomains && is_subdomain_of(hostname, entry.host[..]);
}

// Queries if hostname is a Known HSTS Host
fn is_hsts_host(cache: const HstsCache&, hostname: const u8[:], now_sec: i64) -> bool {
    let clean = hostname.trim_end_byte('.');
    guard clean.len > 0 else { return false; }
    // RFC 6797 Section 8.1.1: An HSTS Host MUST NOT be an IP address literal
    guard !core::is_ip_address_literal(clean) else { return false; }

    // 1. Check dynamic cache
    for &entry in cache.entries {
        if entry_matches_hsts(entry, clean, now_sec) {
            return true;
        }
    }

    // 2. Check static preload list
    if cache.enable_preload_list {
        let preloaded, _ = is_static_preloaded_host(clean);
        return preloaded;
    }

    return false;
}

fn find_hsts_entry_index(cache: const HstsCache&, hostname: const u8[:]) -> i64 {
    for i in cache.entries.len {
        guard i < cache.entries.len else { break; }
        let entry = &cache.entries[i];
        if entry.valid && eq_ascii_fold(entry.host[..], hostname) {
            return i;
        }
    }
    return -1;
}

fn find_hsts_evict_index(cache: const HstsCache&, now_sec: i64) -> i64 {
    var evict_idx: i64 = 0;
    guard cache.entries.len > 0 else { return 0; }
    var min_expiry = cache.entries[0].expiry_epoch_sec;
    for i in cache.entries.len {
        guard i < cache.entries.len else { break; }
        let entry = &cache.entries[i];
        if !entry.valid || entry.expiry_epoch_sec < now_sec {
            return i;
        }
        if entry.expiry_epoch_sec < min_expiry {
            min_expiry = entry.expiry_epoch_sec;
            evict_idx = i;
        }
    }
    return evict_idx;
}

fn store_hsts_entry(cache: HstsCache&, entry: const HstsEntry&, now_sec: i64) {
    if cache.entries.len < cache.entries.cap {
        cache.entries.push(entry);
    } else {
        let evict_idx = find_hsts_evict_index(cache, now_sec);
        if evict_idx >= 0 && evict_idx < cache.entries.len {
            cache.entries[evict_idx] = entry;
        }
    }
}

inline fn is_valid_hsts_hostname(name: const u8[:]) -> bool {
    guard name.len > 0 && name.len <= 256 else { return false; }
    return !core::is_ip_address_literal(name);
}

// Ingests a validated Strict-Transport-Security header into the HSTS cache
// RFC 6797 Section 8.1: Must ONLY be called for secure HTTPS connections!
fn hsts_cache_update(
    cache:      HstsCache&,
    hostname:   const u8[:],
    raw_header: const u8[:],
    now_sec:    i64,
) -> bool {
    let clean = hostname.trim_end_byte('.');
    guard is_valid_hsts_hostname(clean) else { return false; }

    let dir, ok_d = parse_hsts_header(raw_header);
    guard ok_d else { return false; }

    let existing_idx = find_hsts_entry_index(cache, clean);

    // RFC 6797 Section 6.1.1: max-age=0 signals deletion of known HSTS host
    if dir.max_age_sec == 0 {
        if existing_idx >= 0 && existing_idx < cache.entries.len {
            cache.entries[existing_idx].valid = false;
        }
        return true;
    }

    let expiry = now_sec + dir.max_age_sec;

    // Update existing entry
    if existing_idx >= 0 && existing_idx < cache.entries.len {
        cache.entries[existing_idx].expiry_epoch_sec = expiry;
        cache.entries[existing_idx].include_subdomains = dir.include_subdomains;
        return true;
    }

    // Insert new entry
    var new_entry = HstsEntry {
        expiry_epoch_sec:   expiry,
        include_subdomains: dir.include_subdomains,
        is_preload:         dir.preload,
        valid:              true,
        ..
    };
    new_entry.host.append(clean);
    store_hsts_entry(cache, new_entry, now_sec);
    return true;
}

// ---- 4. Automated URL Upgrade Engine (RFC 6797 Section 8.3) ------------------

fn find_authority_end(url: const u8[:]) -> i64 {
    for i in 7..url.len {
        let b = url[i];
        if b == '/' || b == '?' || b == '#' {
            return i;
        }
    }
    return url.len;
}

fn split_http_url(raw_url: const u8[:]) -> const u8[:], const u8[:], const u8[:], bool {
    guard raw_url.len >= 7 else { return "", "", "", false; }
    guard starts_with(raw_url, "http://") else { return "", "", "", false; }

    let auth_end = find_authority_end(raw_url);
    let auth = raw_url[7..auth_end];
    let host, port, _ = auth.split_once_byte(':');
    let rem = if auth_end < raw_url.len { raw_url[auth_end..] } else { "" };
    return host, port, rem, true;
}

// Automatically upgrades `http://` URL to `https://` if the host is a Known HSTS Host.
// Returns true if URL was upgraded, false if left unchanged.
fn hsts_upgrade_url<B>(
    cache:   const HstsCache&,
    raw_url: const u8[:],
    now_sec: i64,
    out_url: B&,
) -> bool {
    let host, port, rem, ok = split_http_url(raw_url);
    guard ok else { return false; }
    guard is_hsts_host(cache, host, now_sec) else { return false; }

    out_url.clear();
    out_url.append("https://");
    out_url.append(host);
    if port.len > 0 && port != "80" {
        out_url.push(':');
        out_url.append(port);
    }
    if rem.len > 0 {
        out_url.append(rem);
    }
    return true;
}
