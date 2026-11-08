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
import rfc.http;

// ---- HSTS Directive Model ------------------------------------------------

struct HstsDirective {
    max_age_sec:        i64  = 0,
    include_subdomains: bool = false,
    preload:            bool = false,
    valid:              bool = false,
}

// ---- Header Parsing (RFC 6797 Section 6.1) -------------------------------

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
        unquoted = val[1..^1];
    }
    guard unquoted.len > 0 && unquoted[0] >= '0' && unquoted[0] <= '9' else { return 0, false; }
    return unquoted.parse_i64_dec();
}

fn apply_hsts_directive(d: HstsDirective&, trimmed: const u8[:]) -> bool {
    let name, val, has_val = trimmed.split_once_byte('=');
    let key = name.trim_lws();
    if key.eq_ascii_fold(rfc::HSTS_DIR_INCLUDE_SUBDOMAINS) {
        guard !has_val && !d.include_subdomains else { return false; }
        d.include_subdomains = true;
        return true;
    }
    if key.eq_ascii_fold(rfc::HSTS_DIR_PRELOAD) {
        guard !has_val && !d.preload else { return false; }
        d.preload = true;
        return true;
    }
    if key.eq_ascii_fold(rfc::HSTS_DIR_MAX_AGE) {
        guard !d.valid && has_val else { return false; }
        let parsed_age, age_ok = parse_hsts_max_age(val.trim_lws());
        guard age_ok else { return false; }
        d.max_age_sec = parsed_age;
        d.valid = true;
        return true;
    }
    guard key.len > 0 else { return false; }
    for b in key {
        guard core::is_tchar(b) else { return false; }
    }
    if has_val {
        let v_trim = val.trim_lws();
        guard v_trim.len > 0 else { return false; }
        if v_trim[0] == '"' {
            guard v_trim.len >= 2 && v_trim[v_trim.len - 1] == '"' else { return false; }
        }
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

    var rem = raw;
    while rem.len > 0 {
        let semi_idx = rem.find_unquoted_byte(';');
        let part = rem[..semi_idx].trim_lws();
        rem = if semi_idx < rem.len { rem[semi_idx + 1..] } else { rem[..0] };
        guard part.len > 0 else { continue; }
        guard apply_hsts_directive(d, part) else { return d, false; }
    }

    return d, d.valid;
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

fn host_matches_domain(sub: const u8[:], domain: const u8[:]) -> bool {
    if sub.eq_ascii_fold(domain) { return true; }
    guard sub.len > domain.len + 1 else { return false; }
    guard sub.ends_with_fold(domain) else { return false; }
    return sub[sub.len - domain.len - 1] == '.';
}

fn is_preloaded_tld(hostname: const u8[:]) -> bool {
    for tld in HSTS_PRELOAD_TLDS {
        if hostname.ends_with_fold(tld) {
            return true;
        }
    }
    return false;
}

fn is_preloaded_property(h: const u8[:]) -> bool {
    for dom in HSTS_PRELOAD_DOMAINS {
        if host_matches_domain(h, dom) {
            return true;
        }
    }
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
    guard sub.ends_with_fold(parent) else { return false; }
    return sub[sub.len - parent.len - 1] == '.';
}

fn entry_matches_hsts(entry: const HstsEntry&, hostname: const u8[:], now_sec: i64) -> bool {
    guard entry.valid && entry.expiry_epoch_sec >= now_sec else { return false; }
    if hostname.eq_ascii_fold(entry.host[..]) {
        return true;
    }
    return entry.include_subdomains && is_subdomain_of(hostname, entry.host[..]);
}

// RFC 6797 / Chromium `transport_security_state.cc:266-268`: `localhost` and `*.localhost`
// are exempt from HSTS upgrades so local development servers do not break plain HTTP localhost.
inline fn is_localhost_hsts_exempt(clean: const u8[:]) -> bool {
    return clean.eq_ascii_fold("localhost") || clean.ends_with_fold(".localhost");
}

// Queries if hostname is a Known HSTS Host
fn is_hsts_host(cache: const HstsCache&, hostname: const u8[:], now_sec: i64) -> bool {
    let clean = hostname.trim_end_byte('.');
    guard clean.len > 0 else { return false; }
    // RFC 6797 Section 8.1.1: An HSTS Host MUST NOT be an IP address literal
    guard !core::is_ip_address_literal(clean) && !is_localhost_hsts_exempt(clean) else { return false; }

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
        if entry.valid && entry.host[..].eq_ascii_fold(hostname) {
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
    if !cache.entries.try_push(entry) {
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
    store_hsts_entry(cache, new_entry, now_sec);
    return true;
}

// ---- HSTS Cache Persistence (RFC 6797 Section 5.3) ------------------------

fn format_hsts_cache_line<B>(entry: const HstsEntry&, out: B&) {
    out.append(entry.host[..]);
    out.push('\t');
    format(out, entry.expiry_epoch_sec);
    out.push('\t');
    out.push(if entry.include_subdomains { '1' } else { '0' });
    out.push('\t');
    out.push(if entry.is_preload { '1' } else { '0' });
    out.push('\n');
}

// Serializes active unexpired dynamic HSTS entries into tab-separated lines.
fn save_hsts_cache<B>(cache: const HstsCache&, now_sec: i64, out: B&) -> i64 {
    var saved: i64 = 0;
    for &entry in cache.entries {
        if entry.valid && entry.expiry_epoch_sec >= now_sec {
            format_hsts_cache_line(entry, out);
            saved += 1;
        }
    }
    return saved;
}

// Parses a single serialized HSTS cache line (`host\texpiry\tinclude_subdomains\tpreload`).
//
// Example:
//   line = "example.com\t1700003600\t1\t0"
//   returns: entry with host="example.com", expiry_epoch_sec=1700003600, ok = true
fn parse_hsts_cache_line(line: const u8[:], now_sec: i64) -> HstsEntry, bool {
    var entry = HstsEntry { .. };
    let trimmed = line.trim_bytes(" \t\r\n");
    guard trimmed.len > 0 && trimmed[0] != '#' else { return entry, false; }

    var tok = core::make_byte_tokenizer(trimmed, '\t');
    let host_part, ok_h = tok.token_next();
    let exp_part, ok_e = tok.token_next();
    let sub_part, ok_s = tok.token_next();
    let pre_part, ok_p = tok.token_next();
    guard ok_h && ok_e && ok_s else { return entry, false; }

    let clean = host_part.trim_end_byte('.');
    guard is_valid_hsts_hostname(clean) else { return entry, false; }

    let expiry, exp_ok = exp_part.parse_i64_dec();
    guard exp_ok && expiry >= now_sec else { return entry, false; }

    entry.host.append(clean);
    entry.expiry_epoch_sec = expiry;
    entry.include_subdomains = (sub_part == "1" || sub_part.eq_ascii_fold("true"));
    entry.is_preload = ok_p && (pre_part == "1" || pre_part.eq_ascii_fold("true"));
    entry.valid = true;
    return entry, true;
}

fn upsert_hsts_entry(cache: HstsCache&, entry: const HstsEntry&, now_sec: i64) {
    let existing_idx = find_hsts_entry_index(cache, entry.host[..]);
    if existing_idx >= 0 && existing_idx < cache.entries.len {
        cache.entries[existing_idx] = entry;
    } else {
        store_hsts_entry(cache, entry, now_sec);
    }
}

// Deserializes persisted HSTS entries into `cache`, skipping expired or invalid hosts.
fn load_hsts_cache(cache: HstsCache&, data: const u8[:], now_sec: i64) -> i64 {
    guard data.len > 0 else { return 0; }
    var loaded: i64 = 0;
    var tok = core::make_byte_tokenizer(data, '\n');
    loop {
        let line, ok = tok.token_next();
        guard ok else { break; }
        let entry, entry_ok = parse_hsts_cache_line(line, now_sec);
        if entry_ok {
            upsert_hsts_entry(cache, entry, now_sec);
            loaded += 1;
        }
    }
    return loaded;
}

// ---- Automated URL Upgrade Engine (RFC 6797 Section 8.3) ------------------

fn find_authority_end(url: const u8[:]) -> i64 {
    for i in 7..url.len {
        let b = url[i];
        if b == '/' || b == '?' || b == '#' {
            return i;
        }
    }
    return url.len;
}

// Extracts `(host, port)` from a bracketed IPv6 host-port slice.
//
// Example:
//   host_port = "[2001:db8::1]:8080"
//   returns: host = "[2001:db8::1]", port = "8080", ok = true
fn split_ipv6_host_port(host_port: const u8[:]) -> const u8[:], const u8[:], bool {
    let close_idx = host_port.index_of_byte(']');
    guard close_idx > 1 && close_idx < host_port.len else { return "", "", false; }
    let host = host_port[..close_idx + 1];
    let after = close_idx + 1;
    if after == host_port.len {
        return host, "", true;
    }
    guard after < host_port.len && host_port[after] == ':' else { return "", "", false; }
    let port_start = after + 1;
    guard port_start <= host_port.len else { return "", "", false; }
    return host, host_port[port_start..], true;
}

// Extracts `(userinfo, host, port)` from an authority slice, handling `userinfo@` and IPv6 `[...]` brackets.
//
// Example:
//   auth = "user:pass@example.com:8080"
//   returns: userinfo = "user:pass@", host = "example.com", port = "8080", ok = true
fn split_authority_components(auth: const u8[:]) -> const u8[:], const u8[:], const u8[:], bool {
    guard auth.len > 0 else { return "", "", "", false; }
    let at_idx = auth.last_index_of_byte('@');
    var userinfo = auth[..0];
    var host_port = auth;
    if at_idx >= 0 {
        let split_at = at_idx + 1;
        guard split_at <= auth.len else { return "", "", "", false; }
        userinfo = auth[..split_at];
        host_port = auth[split_at..];
    }
    guard host_port.len > 0 else { return "", "", "", false; }

    if host_port[0] == '[' {
        let host, port, ok = split_ipv6_host_port(host_port);
        return userinfo, host, port, ok;
    }

    let host, port, _ = host_port.split_once_byte(':');
    guard host.len > 0 else { return "", "", "", false; }
    return userinfo, host, port, true;
}

// Splits an `http://` URL into `(host, port, path_and_query, ok)`.
//
// Example:
//   raw_url = "http://user@example.com:8080/api?q=1"
//   returns: host = "example.com", port = "8080", rem = "/api?q=1", ok = true
fn split_http_url(raw_url: const u8[:]) -> const u8[:], const u8[:], const u8[:], bool {
    guard raw_url.len >= 7 else { return "", "", "", false; }
    guard raw_url.starts_with_fold("http://") else { return "", "", "", false; }

    let auth_end = find_authority_end(raw_url);
    let auth = raw_url[7..auth_end];
    let _, host, port, ok = split_authority_components(auth);
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
    let auth_end = find_authority_end(raw_url);
    let auth = raw_url[7..auth_end];
    let userinfo, host, port, ok = split_authority_components(auth);
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
