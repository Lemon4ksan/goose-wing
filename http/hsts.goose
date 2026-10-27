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

// ---- 1. HSTS Directive Model ------------------------------------------------

struct HstsDirective {
    max_age_sec: i64 = 0,
    include_subdomains: bool = false,
    preload: bool = false,
    valid: bool = false,
}

// ---- 2. Header Parsing (RFC 6797 Section 6.1) -------------------------------

// Parses `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
fn parse_hsts_header(raw: const u8[:]) -> HstsDirective, bool {
    var d = HstsDirective { .. };
    guard raw.len > 0 else { return d, false; }

    var idx: i64 = 0;
    while idx < raw.len {
        // Skip whitespace and semicolons
        while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t' || raw[idx] == ';') {
            idx += 1;
        }
        guard idx < raw.len else { break; }

        // Read token
        let token_start = idx;
        while idx < raw.len && raw[idx] != '=' && raw[idx] != ';' && raw[idx] != ' ' && raw[idx] != '\t' {
            idx += 1;
        }
        let token = raw[token_start..idx];

        if eq_ascii_fold(token, "includesubdomains") {
            d.include_subdomains = true;
        } else if eq_ascii_fold(token, "preload") {
            d.preload = true;
        } else if eq_ascii_fold(token, "max-age") {
            guard !d.valid else { return d, false; } // RFC 6797 §6.1: Duplicate max-age is forbidden!
            // Read '='
            while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t' || raw[idx] == '=') {
                idx += 1;
            }
            // Skip optional quote
            var in_quote = false;
            if idx < raw.len && raw[idx] == '"' {
                in_quote = true;
                idx += 1;
            }
            var num: i64 = 0;
            var has_digit = false;
            while idx < raw.len && raw[idx] >= '0' && raw[idx] <= '9' {
                num = num * 10 + (raw[idx] - '0');
                has_digit = true;
                idx += 1;
            }
            if in_quote {
                guard idx < raw.len && raw[idx] == '"' else { return d, false; }
                idx += 1;
            }
            if has_digit {
                d.max_age_sec = num;
                d.valid = true;
            }
        } else {
            // Skip unknown directive to next delimiter
            while idx < raw.len && raw[idx] != ';' {
                idx += 1;
            }
        }
    }

    return d, d.valid;
}

// ---- 3. HSTS Cache & Preload List -------------------------------------------

struct HstsEntry {
    host: u8[..256] = [],
    expiry_epoch_sec: i64 = 0,
    include_subdomains: bool = false,
    is_preload: bool = false,
    valid: bool = false,
}

struct HstsCache {
    entries: HstsEntry[..16] = [],
    enable_preload_list: bool = true,
}

fn new_hsts_cache() -> HstsCache {
    return HstsCache { .. };
}

// Checks if a hostname matches static preload list (Chromium HSTS Preload list subset)
fn is_static_preloaded_host(hostname: const u8[:]) -> bool, bool {
    // Top-Level Domains (TLDs) requiring HTTPS: .dev, .app, .page, .bank
    if ends_with_fold(hostname, ".dev") || ends_with_fold(hostname, ".app") ||
       ends_with_fold(hostname, ".page") || ends_with_fold(hostname, ".bank") {
        return true, true; // matches, include_subdomains = true
    }

    // Top secure web properties
    if eq_ascii_fold(hostname, "google.com") || ends_with_fold(hostname, ".google.com") { return true, true; }
    if eq_ascii_fold(hostname, "github.com") || ends_with_fold(hostname, ".github.com") { return true, true; }
    if eq_ascii_fold(hostname, "paypal.com") || ends_with_fold(hostname, ".paypal.com") { return true, true; }
    if eq_ascii_fold(hostname, "bankofamerica.com") || ends_with_fold(hostname, ".bankofamerica.com") { return true, true; }
    if eq_ascii_fold(hostname, "cloudflare.com") || ends_with_fold(hostname, ".cloudflare.com") { return true, true; }
    if eq_ascii_fold(hostname, "wikipedia.org") || ends_with_fold(hostname, ".wikipedia.org") { return true, true; }

    return false, false;
}

// Checks if host is a subdomain of parent (e.g. "api.example.com" of "example.com")
fn is_subdomain_of(sub: const u8[:], parent: const u8[:]) -> bool {
    guard sub.len > parent.len + 1 else { return false; }
    guard ends_with_fold(sub, parent) else { return false; }
    return sub[sub.len - parent.len - 1] == '.';
}

// Queries if hostname is a Known HSTS Host
fn is_hsts_host(cache: const HstsCache&, hostname: const u8[:], now_sec: i64) -> bool {
    guard hostname.len > 0 else { return false; }

    // 1. Check dynamic cache
    for &entry in cache.entries {
        if entry.valid {
            if entry.expiry_epoch_sec >= now_sec {
                if eq_ascii_fold(hostname, entry.host[..]) {
                    return true;
                }
                if entry.include_subdomains && is_subdomain_of(hostname, entry.host[..]) {
                    return true;
                }
            }
        }
    }

    // 2. Check static preload list
    if cache.enable_preload_list {
        let preloaded, _ = is_static_preloaded_host(hostname);
        if preloaded {
            return true;
        }
    }

    return false;
}

// Ingests a validated Strict-Transport-Security header into the HSTS cache
// RFC 6797 Section 8.1: Must ONLY be called for secure HTTPS connections!
fn hsts_cache_update(
    cache: HstsCache&,
    hostname: const u8[:],
    raw_header: const u8[:],
    now_sec: i64,
) -> bool {
    guard hostname.len > 0 else { return false; }
    let dir, ok_d = parse_hsts_header(raw_header);
    guard ok_d else { return false; }

    // RFC 6797 Section 6.1.1: max-age=0 signals deletion of known HSTS host
    if dir.max_age_sec == 0 {
        for i in cache.entries.len {
            if cache.entries[i].valid && eq_ascii_fold(cache.entries[i].host[..], hostname) {
                cache.entries[i].valid = false;
                return true;
            }
        }
        return true;
    }

    let expiry = now_sec + dir.max_age_sec;

    // Update existing entry
    for i in cache.entries.len {
        if cache.entries[i].valid && eq_ascii_fold(cache.entries[i].host[..], hostname) {
            cache.entries[i].expiry_epoch_sec = expiry;
            cache.entries[i].include_subdomains = dir.include_subdomains;
            return true;
        }
    }

    // Insert new entry
    var new_entry = HstsEntry {
        expiry_epoch_sec: expiry,
        include_subdomains: dir.include_subdomains,
        is_preload: dir.preload,
        valid: true,
        ..
    };
    new_entry.host.append(hostname);

    if cache.entries.len < cache.entries.cap {
        cache.entries.push(new_entry);
        return true;
    }

    // Evict oldest or expired entry
    var evict_idx: i64 = 0;
    var min_expiry = cache.entries[0].expiry_epoch_sec;
    for i in cache.entries.len {
        if !cache.entries[i].valid || cache.entries[i].expiry_epoch_sec < now_sec {
            evict_idx = i;
            break;
        }
        if cache.entries[i].expiry_epoch_sec < min_expiry {
            min_expiry = cache.entries[i].expiry_epoch_sec;
            evict_idx = i;
        }
    }
    cache.entries[evict_idx] = new_entry;
    return true;
}

// ---- 4. Automated URL Upgrade Engine (RFC 6797 Section 8.3) ------------------

// Automatically upgrades `http://` URL to `https://` if the host is a Known HSTS Host.
// Returns true if URL was upgraded, false if left unchanged.
fn hsts_upgrade_url<B>(
    cache: const HstsCache&,
    raw_url: const u8[:],
    now_sec: i64,
    out_url: B&,
) -> bool {
    out_url.clear();
    // Must start with "http://"
    guard raw_url.len >= 8 else {
        out_url.append(raw_url);
        return false;
    }
    guard raw_url[0] == 'h' && raw_url[1] == 't' && raw_url[2] == 't' &&
          raw_url[3] == 'p' && raw_url[4] == ':' && raw_url[5] == '/' && raw_url[6] == '/' else {
        out_url.append(raw_url);
        return false;
    }

    // Extract hostname from raw_url (up to ':', '/', '?', '#', or end)
    var host_end = raw_url.len;
    var port_start: i64 = -1;
    for i in 7..raw_url.len {
        let b = raw_url[i];
        if b == ':' && port_start < 0 {
            port_start = i;
        } else if b == '/' || b == '?' || b == '#' {
            host_end = i;
            break;
        }
    }

    var hostname: u8[..256] = [];
    let end_of_host = if port_start >= 0 && port_start < host_end { port_start } else { host_end };
    guard (end_of_host - 7) <= hostname.cap else {
        out_url.append(raw_url);
        return false;
    }
    hostname.append(raw_url[7..end_of_host]);

    // Check if known HSTS host
    if is_hsts_host(cache, hostname[..], now_sec) {
        // Rewrite to https://
        out_url.append("https://");
        out_url.append(hostname[..]);

        // If port was explicitly :80, omit it (default port 443 for https)
        // If non-80 port, preserve it
        if port_start >= 0 && port_start < host_end {
            let port_str = raw_url[port_start + 1..host_end];
            if port_str != "80" {
                out_url.push(':');
                out_url.append(port_str);
            }
        }

        // Append remainder of URL (path, query, fragment)
        if host_end < raw_url.len {
            out_url.append(raw_url[host_end..]);
        }
        return true;
    }

    out_url.append(raw_url);
    return false;
}
