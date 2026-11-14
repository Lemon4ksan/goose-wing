// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP Alternative Services (RFC 7838 Alt-Svc) Engine.
// Zero-heap parser, cache, and HTTP/3 connection promotion manager.
// - Supports `h3=":443"; ma=86400; persist=1`, `clear`, multiple alternative entries
// - Manages per-origin alternative service mapping with TTL (`ma`) and failure backoff
// - Promotes TCP (H1/H2) connections to UDP (HTTP/3 / QUIC)
namespace wing;

import std;
import core from "..";
import .headers.lexical;
import .mime;

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

// Finds index of valid origin entry in cache, or -1 if not found.
fn find_origin_entry_idx(cache: const AltSvcCache&, origin: const u8[:]) -> i64 {
    for &entry, idx in cache.entries {
        if entry.valid && entry.origin[..] == origin {
            return idx;
        }
    }
    return -1;
}

// ---- RFC 7838 Header Parser ---------------------------------------------

// Parses single parameter token: e.g. `ma=86400` or `persist=1` (RFC 7838 Section 3).
//
// Example:
//   param_str = "ma=86400"
//   returns: true, mutates ep.max_age_sec to 86400
fn parse_altsvc_param(param_str: const u8[:], ep: AltSvcEndpoint&) -> bool {
    let p_name_raw, p_val_raw, ok = param_str.split_once_byte('=');
    guard ok else { return false; }

    let p_name = p_name_raw.trim_lws();
    let v_trim = p_val_raw.trim_lws();
    guard p_name.len > 0 && is_valid_token_swar(p_name) && v_trim.len > 0 else { return false; }

    var p_val: u8[..128] = [];
    guard decode_token_or_quoted_param(v_trim, p_val, 128) else { return false; }

    if p_name == "ma" {
        guard p_val.len > 0 else { return false; }
        for b in p_val[..] {
            guard core::is_ascii_digit(b) else { return false; }
        }
        let num, num_ok = p_val[..].parse_u32_dec();
        guard num_ok else { return false; }
        ep.max_age_sec = num;
    } else if p_name == "persist" {
        if p_val[..] == "1" {
            ep.persist = true;
        }
    }
    return true;
}

// Parses semicolon-delimited parameter list for an Alt-Svc entry (RFC 7838 Section 3).
//
// Example:
//   params_part = "; ma=86400; persist=1"
//   returns: true, populates ep parameters
fn parse_altsvc_params(params_part: const u8[:], ep: AltSvcEndpoint&) -> bool {
    let trimmed = params_part.trim_lws();
    if trimmed.len == 0 {
        return true;
    }
    guard trimmed[0] == ';' else { return false; }

    var rem = trimmed[1..];
    while rem.len > 0 {
        let semi_idx = rem.find_unquoted_byte(';');
        let p_trim = rem[..semi_idx].trim_lws();
        guard p_trim.len > 0 && parse_altsvc_param(p_trim, ep) else { return false; }
        if semi_idx >= rem.len {
            break;
        }
        rem = rem[semi_idx + 1..];
        guard rem.trim_lws().len > 0 else { return false; }
    }
    return true;
}

// Validates host component in Alt-Svc authority (RFC 7838 §3 & RFC 3986 §3.2.2).
// Bracketed IPv6 literals must start with '[', end with ']', and contain no interior brackets;
// non-bracketed hostnames must not contain ':' or brackets.
inline fn is_valid_altsvc_host(host_part: const u8[:]) -> bool {
    guard host_part.len > 0 else { return true; }
    if host_part[0] == '[' {
        let last_idx = core::sub_sat_i64(host_part.len, 1);
        guard host_part.len >= 3 && host_part[last_idx] == ']' else { return false; }
        let inner = host_part[1..last_idx];
        guard inner.index_of_byte('[') < 0 && inner.index_of_byte(']') < 0 else { return false; }
        return inner.index_of_byte(':') >= 0;
    }
    return host_part.index_of_byte(':') < 0 &&
           host_part.index_of_byte('[') < 0 &&
           host_part.index_of_byte(']') < 0;
}

inline fn is_upper_hex_digit(b: u8) -> bool {
    return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F');
}

// RFC 7838 Section 3.1: Caching Alt-Svc Header Field Values - Percent-decode ALPN protocol-id token.
//
// Example:
//   proto_token = "h3%2F1"
//   returns: true, out_proto = "h3/1"
fn decode_altsvc_proto_id(proto_token: const u8[:], out_proto: u8[..16]&) -> bool {
    out_proto.clear();
    guard proto_token.len > 0 else { return false; }
    var committed = false;
    defer if !committed { out_proto.clear(); };

    var i: i64 = 0;
    while i < proto_token.len {
        let b = proto_token[i];
        if b == '%' {
            let hex_end = core::add_sat_i64(i, 3);
            guard hex_end <= proto_token.len else { return false; }
            let hex_pair = proto_token[core::add_sat_i64(i, 1)..hex_end];
            guard is_upper_hex_digit(hex_pair[0]) && is_upper_hex_digit(hex_pair[1]) else {
                return false;
            }
            let dec, ok_hex = hex_pair.parse_u8_hex();
            guard ok_hex && core::is_ascii_printable(dec) && out_proto.try_push(dec) else {
                return false;
            }
            i = hex_end;
        } else {
            guard core::is_tchar(b) && out_proto.try_push(b) else { return false; }
            i = core::add_sat_i64(i, 1);
        }
    }
    committed = out_proto.len > 0;
    return committed;
}

// Parses host:port authority from Alt-Svc quoted string.
//
// Example:
//   authority = "alt.example.com:8443"
//   returns: true, ep.host="alt.example.com", ep.port=8443
fn parse_altsvc_authority(authority: const u8[:], ep: AltSvcEndpoint&) -> bool {
    let host_part, port_part, has_colon = authority.rsplit_once_byte(':');
    guard has_colon && is_valid_altsvc_host(host_part) && port_part.len > 0 else { return false; }
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

// Scans the closing '"' of an RFC 9110 quoted-string starting at index 0, returning slice end index or -1.
//
// Example:
//   s = "\"alt.example.com:443\"; ma=60"
//   returns: 21
fn scan_altsvc_quoted_end(s: const u8[:]) -> i64 {
    guard s.len >= 2 && s[0] == '"' else { return -1; }
    var idx: i64 = 1;
    while idx < s.len {
        let b = s[idx];
        if b == '\\' {
            idx = core::add_sat_i64(idx, 2);
            continue;
        }
        if b == '"' {
            return core::add_sat_i64(idx, 1);
        }
        idx = core::add_sat_i64(idx, 1);
    }
    return -1;
}

// Parses a single Alt-Svc protocol=authority[; params] directive (RFC 7838 §3).
//
// Example:
//   entry_str = "h3=\":443\"; ma=86400"
//   returns: true, ep.proto="h3", ep.port=443, ep.max_age_sec=86400
fn parse_single_altsvc_entry(entry_str: const u8[:], ep: AltSvcEndpoint&) -> bool {
    ep = AltSvcEndpoint { .. };
    var committed = false;
    defer if !committed { ep = AltSvcEndpoint { .. }; };

    let proto_token, rem_entry, has_eq = entry_str.split_once_byte('=');
    guard has_eq && proto_token.len > 0 && decode_altsvc_proto_id(proto_token, ep.proto) else {
        return false;
    }

    let q_end = scan_altsvc_quoted_end(rem_entry);
    guard q_end >= 2 else { return false; }

    var authority: u8[..160] = [];
    guard strict_unquote(rem_entry[..q_end], authority, 160) &&
          parse_altsvc_authority(authority[..], ep) &&
          parse_altsvc_params(rem_entry[q_end..], ep) else {
        return false;
    }
    committed = true;
    return true;
}

fn read_next_altsvc_entry(rem: const u8[:]) -> const u8[:], const u8[:] {
    let s = rem.trim_start_bytes(" \t,");
    guard s.len > 0 else { return "", ""; }
    let entry_len = s.find_unquoted_byte(',');
    let entry_str = s[..entry_len].trim_lws();
    let next_rem = if entry_len < s.len { s[entry_len + 1..] } else { s[entry_len..] };
    return entry_str, next_rem;
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
        let entry_str, next_rem = read_next_altsvc_entry(rem);
        rem = next_rem;
        guard entry_str.len > 0 else { break; }

        var ep = AltSvcEndpoint { .. };
        guard parse_single_altsvc_entry(entry_str, ep) else { continue; }
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

fn update_altsvc_entry(
    entry:     AltSvcOriginEntry&,
    endpoints: const AltSvcEndpoint[:],
    now_sec:   i64,
) {
    entry.endpoints.clear();
    for &ep in endpoints { entry.endpoints.push(ep); }
    entry.inserted_at_sec = now_sec;
    if now_sec >= entry.broken_until_sec {
        entry.failed_attempts = 0;
        entry.broken_until_sec = 0;
    }
}

fn find_oldest_altsvc_idx(cache: const AltSvcCache&) -> i64 {
    var oldest_idx: i64 = 0;
    guard cache.entries.len > 0 else { return 0; }
    var oldest_time = cache.entries[0].inserted_at_sec;
    for &e, i in cache.entries {
        if !e.valid { return i; }
        if e.inserted_at_sec < oldest_time {
            oldest_time = e.inserted_at_sec;
            oldest_idx = i;
        }
    }
    return oldest_idx;
}

fn insert_new_altsvc_entry(
    cache:     AltSvcCache&,
    origin:    const u8[:],
    endpoints: const AltSvcEndpoint[:],
    now_sec:   i64,
) {
    var entry = AltSvcOriginEntry {
        inserted_at_sec: now_sec,
        valid:           true,
        ..
    };
    guard entry.origin.try_set(origin) else { return; }
    for &ep in endpoints { entry.endpoints.push(ep); }

    if !cache.entries.try_push(entry) {
        let oldest_idx = find_oldest_altsvc_idx(cache);
        if oldest_idx >= 0 && oldest_idx < cache.entries.len {
            cache.entries[oldest_idx] = entry;
        }
    }
}

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

    let existing_idx = find_origin_entry_idx(cache, origin);

    // If "clear", invalidate origin entry
    if is_clear {
        if existing_idx >= 0 && existing_idx < cache.entries.len {
            cache.entries[existing_idx].valid = false;
        }
        return;
    }

    guard endpoints.len > 0 else { return; }

    if existing_idx >= 0 && existing_idx < cache.entries.len {
        update_altsvc_entry(cache.entries[existing_idx], endpoints[..], now_sec);
        return;
    }

    insert_new_altsvc_entry(cache, origin, endpoints[..], now_sec);
}

// Queries Alt-Svc cache for HTTP/3 ("h3") endpoint promotion
fn lookup_h3(
    cache:   const AltSvcCache&,
    origin:  const u8[:],
    now_sec: i64,
    out_ep:  AltSvcEndpoint&,
) -> bool {
    let idx = find_origin_entry_idx(cache, origin);
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
    let idx = find_origin_entry_idx(cache, origin);
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
    let idx = find_origin_entry_idx(cache, origin);
    guard idx >= 0 else { return; }

    cache.entries[idx].failed_attempts = 0;
    cache.entries[idx].broken_until_sec = 0;
}

// Checks if an origin's alternative service is currently marked broken (within exponential backoff).
fn is_broken(cache: const AltSvcCache&, origin: const u8[:], now_sec: i64) -> bool {
    let idx = find_origin_entry_idx(cache, origin);
    guard idx >= 0 else { return false; }
    return now_sec < cache.entries[idx].broken_until_sec;
}

// Returns the number of consecutive failure attempts recorded for an origin.
fn failed_attempts(cache: const AltSvcCache&, origin: const u8[:]) -> u8 {
    let idx = find_origin_entry_idx(cache, origin);
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
