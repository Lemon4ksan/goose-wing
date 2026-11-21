// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 6797 HTTP Strict Transport Security (HSTS) & Automated Protocol Upgrade Engine.
// Supports:
// - `Strict-Transport-Security` response header parsing (max-age, includeSubDomains, preload)
// - Dynamic HSTS Host Cache with TTL expiration and deletion (max-age=0)
// - Embedded static Chromium/IETF Preload List (top secure domains & .dev / .app HSTS TLDs)
// - Pre-flight transparent URL upgrade (rewriting http:// to https:// before network dispatch)
// - RFC 6797 Section 8.1 transport security constraint (insecure HTTP HSTS rejection)
namespace http;

import std;
import core from "..";
import rfc.http;
import .mime;
import http.ext_internal;

// ---- HSTS Directive Model ------------------------------------------------

struct HstsDirective {
    max_age_sec:        i64  = 0,
    include_subdomains: bool = false,
    preload:            bool = false,
    valid:              bool = false,
}

// ---- Header Parsing (RFC 6797 Section 6.1) -------------------------------

// Parses `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
//
// Example:
//   raw = "max-age=31536000; includeSubDomains"
//   returns: d with max_age_sec=31536000, include_subdomains=true, ok = true
fn parse_hsts_header(raw: const u8[:]) -> HstsDirective, bool {
    var d = HstsDirective { .. };
    guard raw.len > 0 else { return d, false; }

    var seen_ext: u8[..64][..16] = [];
    var rem = raw;
    while rem.len > 0 {
        let semi_idx = rem.find_unquoted_byte(';');
        let part = rem[..semi_idx].trim_lws();
        rem = if semi_idx < rem.len { rem[semi_idx + 1..] } else { rem[..0] };
        guard part.len > 0 else { continue; }
        guard http_internal::apply_hsts_directive(d, seen_ext, part) else {
            return HstsDirective { .. }, false;
        }
    }

    guard d.valid else { return HstsDirective { .. }, false; }
    return d, true;
}

// ---- HSTS Cache & Preload List -------------------------------------------

struct HstsEntry {
    host:               u8[..256] = [],
    expiry_epoch_sec:   i64       = 0,
    include_subdomains: bool      = false,
    is_preload:         bool      = false,
    valid:              bool      = false,
}

struct HstsCache {
    entries:             HstsEntry[..128] = [],
    enable_preload_list: bool             = true,
}

const HSTS_PRELOAD_TLDS: const u8[:][30] = [
    ".dev", ".app", ".page", ".bank", ".insurance", ".chrome",
    ".gle", ".gmail", ".goog", ".google", ".hangouts", ".nexus",
    ".play", ".search", ".youtube", ".android", ".fly", ".foo",
    ".meet", ".new", ".phd", ".prof", ".rsvp", ".day",
    ".boo", ".dad", ".esq", ".mov", ".zip", ".ing",
];

const HSTS_PRELOAD_DOMAINS: const u8[:][64] = [
    "google.com", "github.com", "paypal.com", "bankofamerica.com",
    "cloudflare.com", "wikipedia.org", "stripe.com", "facebook.com",
    "twitter.com", "x.com", "apple.com", "microsoft.com",
    "amazon.com", "linkedin.com", "dropbox.com", "slack.com",
    "discord.com", "zoom.us", "notion.so", "figma.com",
    "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
    "crates.io", "golang.org", "rust-lang.org", "python.org",
    "mozilla.org", "eff.org", "torproject.org", "signal.org",
    "proton.me", "protonmail.com", "fastmail.com", "tutanota.com",
    "1password.com", "bitwarden.com", "lastpass.com", "dashlane.com",
    "chase.com", "wellsfargo.com", "citibank.com", "americanexpress.com",
    "capitalone.com", "hsbc.com", "barclays.co.uk", "revolut.com",
    "wise.com", "coinbase.com", "binance.com", "kraken.com",
    "vercel.com", "netlify.com", "heroku.com", "digitalocean.com",
    "linode.com", "vultr.com", "render.com", "fly.io",
    "supabase.com", "planetscale.com", "tailscale.com", "wireguard.com",
];

// Queries if hostname is a Known HSTS Host
fn is_hsts_host(cache: const HstsCache&, hostname: const u8[:], now_sec: i64) -> bool {
    let clean = hostname.trim_end_byte('.');
    guard clean.len > 0 else { return false; }
    // RFC 6797 Section 8.1.1: An HSTS Host MUST NOT be an IP address literal
    guard !core::is_ip_address_literal(clean) && !http_internal::is_localhost_hsts_exempt(clean) else { return false; }

    // 1. Check dynamic cache
    for &entry in cache.entries {
        if http_internal::entry_matches_hsts(entry, clean, now_sec) {
            return true;
        }
    }

    // 2. Check static preload list
    if cache.enable_preload_list {
        let preloaded, _ = http_internal::is_static_preloaded_host(clean);
        return preloaded;
    }

    return false;
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
    guard http_internal::is_valid_hsts_hostname(clean) else { return false; }

    let dir, ok_d = parse_hsts_header(raw_header);
    guard ok_d else { return false; }

    let existing_idx = http_internal::find_hsts_entry_index(cache, clean);

    // RFC 6797 Section 6.1.1: max-age=0 signals deletion of known HSTS host
    if dir.max_age_sec == 0 {
        if existing_idx >= 0 && existing_idx < cache.entries.len {
            cache.entries[existing_idx].valid = false;
        }
        return true;
    }

    let expiry = core::add_sat_i64(now_sec, dir.max_age_sec);

    // Update existing entry
    if existing_idx >= 0 && existing_idx < cache.entries.len {
        cache.entries[existing_idx].expiry_epoch_sec = expiry;
        cache.entries[existing_idx].include_subdomains = dir.include_subdomains;
        cache.entries[existing_idx].is_preload = dir.preload;
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
    http_internal::store_hsts_entry(cache, new_entry, now_sec);
    return true;
}

// ---- HSTS Cache Persistence (RFC 6797 Section 5.3) ------------------------

// Serializes active unexpired dynamic HSTS entries into tab-separated lines.
fn save_hsts_cache<B>(cache: const HstsCache&, now_sec: i64, out: B&) -> i64 {
    var saved: i64 = 0;
    for &entry in cache.entries {
        if entry.valid && entry.expiry_epoch_sec >= now_sec {
            http_internal::format_hsts_cache_line(entry, out);
            saved += 1;
        }
    }
    return saved;
}

// Deserializes persisted HSTS entries into `cache`, skipping expired or invalid hosts.
fn load_hsts_cache(cache: HstsCache&, data: const u8[:], now_sec: i64) -> i64 {
    guard data.len > 0 else { return 0; }
    var loaded: i64 = 0;
    var tok = core::make_byte_tokenizer(data, '\n');
    loop {
        let line, ok = tok.token_next();
        guard ok else { break; }
        let entry, entry_ok = http_internal::parse_hsts_cache_line(line, now_sec);
        if entry_ok {
            http_internal::upsert_hsts_entry(cache, entry, now_sec);
            loaded += 1;
        }
    }
    return loaded;
}

// ---- Automated URL Upgrade Engine (RFC 6797 Section 8.3) ------------------

// Splits an `http://` URL into `(host, port, path_and_query, ok)`.
//
// Example:
//   raw_url = "http://user@example.com:8080/api?q=1"
//   returns: host = "example.com", port = "8080", rem = "/api?q=1", ok = true
fn split_http_url(raw_url: const u8[:]) -> const u8[:], const u8[:], const u8[:], bool {
    guard raw_url.len >= 7 else { return "", "", "", false; }
    guard raw_url.starts_with_fold("http://") else { return "", "", "", false; }

    let auth_end = http_internal::find_authority_end(raw_url);
    let auth = raw_url[7..auth_end];
    let _, host, port, ok = http_internal::split_authority_components(auth);
    guard ok else { return "", "", "", false; }
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
    guard raw_url.len >= 7 && raw_url.starts_with_fold("http://") else { return false; }
    guard raw_url.len + 1 <= out_url.cap else { return false; }
    let auth_end = http_internal::find_authority_end(raw_url);
    let auth = raw_url[7..auth_end];
    let userinfo, host, port, ok = http_internal::split_authority_components(auth);
    guard ok else { return false; }
    guard is_hsts_host(cache, host, now_sec) else { return false; }
    let rem = if auth_end < raw_url.len { raw_url[auth_end..] } else { "" };

    out_url.clear();
    out_url.append("https://");
    if userinfo.len > 0 {
        out_url.append(userinfo);
    }
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
