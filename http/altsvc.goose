// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP Alternative Services (RFC 7838 Alt-Svc) Engine.
// Zero-heap parser, cache, and HTTP/3 connection promotion manager.
// - Supports `h3=":443"; ma=86400; persist=1`, `clear`, multiple alternative entries
// - Manages per-origin alternative service mapping with TTL (`ma`) and failure backoff
// - Promotes TCP (H1/H2) connections to UDP (HTTP/3 / QUIC)
namespace http;

import std;
import core from "..";
import .headers.lexical;
import .mime;
import http.ext_internal;

// ---- Alt-Svc Models & Constants -----------------------------------------

struct AltSvcEndpoint {
    proto:       u8[..16]  = [],    // e.g. "h3", "h2"
    host:        u8[..128] = [],    // Alternate host (empty if same as origin)
    port:        u16       = 443,
    max_age_sec: u32       = 86400, // Default 24 hours per RFC 7838 Section 3.1
    persist:     bool      = false, // Survives network change if true
}

struct AltSvcOriginEntry {
    origin:           u8[..128]           = [], // e.g. "example.com:443"
    endpoints:        AltSvcEndpoint[..4] = [],
    inserted_at_sec:  i64                 = 0,
    failed_attempts:  u8                  = 0, // Consecutive connection failures for backoff
    broken_until_sec: i64                 = 0, // Exponential backoff timestamp
    valid:            bool                = false,
}

struct AltSvcCache {
    entries: AltSvcOriginEntry[..64] = [],
}

// ---- RFC 7838 Header Parser ---------------------------------------------

// Parses host:port authority from Alt-Svc quoted string.
//
// Example:
//   authority = "alt.example.com:8443"
//   returns: true, ep.host="alt.example.com", ep.port=8443
fn parse_altsvc_authority(authority: const u8[:], ep: AltSvcEndpoint&) -> bool {
    let host_part, port_part, has_colon = authority.rsplit_once_byte(':');
    guard has_colon && http_internal::is_valid_altsvc_host(host_part) && port_part.len > 0 else { return false; }
    for b in port_part {
        guard core::is_ascii_digit(b) else { return false; }
    }

    let port_num, port_ok = port_part.parse_u32_dec();
    guard port_ok && port_num > 0 && port_num <= 65535 else { return false; }

    if host_part.len > 0 {
        guard ep.host.try_append(host_part) else { return false; }
    }
    ep.port = port_num as! u16;
    return true;
}

// Parses `Alt-Svc` header value (RFC 7838 Section 3):
// e.g. `h3=":443"; ma=86400; persist=1, h2="alt.example.com:8443"`
// or `clear`
//
// Example:
//   raw = "h3=\":443\"; ma=86400"
//   returns: true, is_clear = false, endpoints pushed into out_endpoints
fn parse_altsvc_header<E>(raw: const u8[:], out_endpoints: E&) -> bool, bool {
    let trimmed = raw.trim_lws();
    if trimmed == "clear" {
        return true, true; // is_clear = true
    }

    var rem = trimmed;
    while rem.len > 0 {
        let entry_str, next_rem = http_internal::read_next_altsvc_entry(rem);
        rem = next_rem;
        guard entry_str.len > 0 else { break; }

        var ep = AltSvcEndpoint { .. };
        guard http_internal::parse_single_altsvc_entry(entry_str, ep) else { continue; }
        if !out_endpoints.try_push(ep) && ep.proto[..] == "h3" {
            for i in out_endpoints.len {
                guard out_endpoints[i].proto[..] != "h3" else { continue; }
                out_endpoints[i] = ep;
                break;
            }
        }
    }

    return true, false;
}

// ---- Alt-Svc Cache Operations -------------------------------------------

// Inserts or updates an Alt-Svc mapping for an origin (RFC 7838 Section 3)
fn update(
    cache:      AltSvcCache&,
    origin:     const u8[:],
    raw_altsvc: const u8[:],
    now_sec:    i64,
) {
    var endpoints: AltSvcEndpoint[..4] = [];
    let ok, is_clear = parse_altsvc_header(raw_altsvc, endpoints);
    guard ok else { return; }

    let existing_idx = http_internal::find_origin_entry_idx(cache, origin);

    // If "clear", invalidate origin entry
    if is_clear {
        if existing_idx >= 0 && existing_idx < cache.entries.len {
            cache.entries[existing_idx].valid = false;
        }
        return;
    }

    guard endpoints.len > 0 else { return; }

    if existing_idx >= 0 && existing_idx < cache.entries.len {
        http_internal::update_altsvc_entry(cache.entries[existing_idx], endpoints[..], now_sec);
        return;
    }

    http_internal::insert_new_altsvc_entry(cache, origin, endpoints[..], now_sec);
}

// Queries Alt-Svc cache for HTTP/3 ("h3") endpoint promotion
fn lookup_h3(
    cache:   const AltSvcCache&,
    origin:  const u8[:],
    now_sec: i64,
    out_ep:  AltSvcEndpoint&,
) -> bool {
    let idx = http_internal::find_origin_entry_idx(cache, origin);
    guard idx >= 0 else { return false; }

    // Check if marked broken (failure backoff)
    if now_sec < cache.entries[idx].broken_until_sec {
        return false;
    }

    for &ep in cache.entries[idx].endpoints {
        if ep.proto[..] == "h3" {
            let elapsed = now_sec - cache.entries[idx].inserted_at_sec;
            if elapsed >= 0 && elapsed < ep.max_age_sec {
                out_ep = ep;
                return true;
            }
        }
    }
    return false;
}

// Records an alternative service connection failure with exponential backoff (Chromium/Mach model)
fn record_failure(cache: AltSvcCache&, origin: const u8[:], now_sec: i64) {
    let idx = http_internal::find_origin_entry_idx(cache, origin);
    guard idx >= 0 else { return; }

    if cache.entries[idx].failed_attempts < 255 {
        cache.entries[idx].failed_attempts++;
    }
    let shift = min(max(cache.entries[idx].failed_attempts as i64, 1), 6);
    // Backoff: 5s, 10s, 20s, 40s, 80s, 160s, max 320s
    let backoff_sec: i64 = 5 * (1 << (shift - 1));
    cache.entries[idx].broken_until_sec = core::add_sat_i64(now_sec, backoff_sec);
}

// Records an alternative service connection success, resetting consecutive failures and clearing broken status.
fn record_success(cache: AltSvcCache&, origin: const u8[:]) {
    let idx = http_internal::find_origin_entry_idx(cache, origin);
    guard idx >= 0 else { return; }

    cache.entries[idx].failed_attempts = 0;
    cache.entries[idx].broken_until_sec = 0;
}

// Checks if an origin's alternative service is currently marked broken (within exponential backoff).
fn is_broken(cache: const AltSvcCache&, origin: const u8[:], now_sec: i64) -> bool {
    let idx = http_internal::find_origin_entry_idx(cache, origin);
    guard idx >= 0 else { return false; }
    return now_sec < cache.entries[idx].broken_until_sec;
}

// Returns the number of consecutive failure attempts recorded for an origin.
fn failed_attempts(cache: const AltSvcCache&, origin: const u8[:]) -> u8 {
    let idx = http_internal::find_origin_entry_idx(cache, origin);
    guard idx >= 0 else { return 0; }
    return cache.entries[idx].failed_attempts;
}

// ---- Server-Side Serializer ---------------------------------------------

// Formats standard Alt-Svc header string: e.g. `h3=":443"; ma=86400; persist=1`
fn format_altsvc_header<B>(
    out:         B&,
    proto:       const u8[:],
    port:        u16,
    max_age_sec: u32  = 86400,
    persist:     bool = true,
) {
    out.append(proto);
    out.append("=\":");
    port.format_u64_dec(out);
    out.append("\"; ma=");
    max_age_sec.format_u64_dec(out);
    if persist {
        out.append("; persist=1");
    }
}
