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

// Parses single parameter token: e.g. `ma=86400` or `persist=1`.
//
// Example:
//   param_str = "ma=86400"
//   mutates ep.max_age_sec to 86400
fn parse_altsvc_param(param_str: const u8[:], ep: AltSvcEndpoint&) {
    let p_name_raw, p_val_raw, ok = param_str.split_once_byte('=');
    guard ok else { return; }

    let p_name = p_name_raw.trim_lws();
    let v_trim = p_val_raw.trim_lws();
    guard v_trim.len > 0 else { return; }
    var p_val = v_trim;
    if v_trim[0] == '"' {
        guard v_trim.len >= 2 && v_trim[v_trim.len - 1] == '"' else { return; }
        p_val = v_trim[1..v_trim.len - 1];
    } else {
        guard v_trim[v_trim.len - 1] != '"' else { return; }
    }

    if p_name == "ma" {
        let num, num_ok = p_val.parse_u32_dec();
        if num_ok { ep.max_age_sec = num; }
    } else if p_name == "persist" {
        if p_val == "1" {
            ep.persist = true;
        }
    }
}

// Parses semicolon-delimited parameter list for an Alt-Svc entry.
//
// Example:
//   params_part = "; ma=86400; persist=1"
//   populates ep parameters
fn parse_altsvc_params(params_part: const u8[:], ep: AltSvcEndpoint&) {
    var rem = params_part;
    while rem.len > 0 {
        let semi_idx = rem.find_unquoted_byte(';');
        let p_trim = rem[..semi_idx].trim_lws();
        rem = if semi_idx < rem.len { rem[semi_idx + 1..] } else { rem[..0] };
        if p_trim.len > 0 {
            parse_altsvc_param(p_trim, ep);
        }
    }
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

// Percent-decodes an Alt-Svc ALPN protocol-id token (RFC 7838 §3), rejecting control bytes.
//
// Example:
//   proto_token = "h3%2D29"
//   returns: true, out_proto = "h3-29"
fn decode_altsvc_proto_id(proto_token: const u8[:], out_proto: u8[..16]&) -> bool {
    guard core::percent_decode_query(proto_token, out_proto) && out_proto.len > 0 else {
        out_proto.clear();
        return false;
    }
    var i: u64 = 0;
    let total = proto_token.len as u64;
    while i < total {
        let b = proto_token[i as i64];
        if b == '%' {
            let i1 = core::add_sat_u64(i, 1);
            let i2 = core::add_sat_u64(i, 2);
            guard i2 < total else { return false; }
            let hi = core::hex_digit_to_val(proto_token[i1 as i64]);
            let lo = core::hex_digit_to_val(proto_token[i2 as i64]);
            guard hi >= 0 && lo >= 0 else { return false; }
            i = core::add_sat_u64(i, 3);
        } else {
            i = core::add_sat_u64(i, 1);
        }
    }
    for dec_b in out_proto {
        guard dec_b > 0x20 && dec_b < 0x7F else {
            out_proto.clear();
            return false;
        }
    }
    return true;
}

// Parses host:port authority from Alt-Svc quoted string.
//
// Example:
//   authority = "alt.example.com:8443"
//   returns: true, ep.host="alt.example.com", ep.port=8443
fn parse_altsvc_authority(authority: const u8[:], ep: AltSvcEndpoint&) -> bool {
    let host_part, port_part, has_colon = authority.rsplit_once_byte(':');
    guard has_colon && is_valid_altsvc_host(host_part) else { return false; }

    if host_part.len > 0 {
        guard host_part.len <= ep.host.cap else { return false; }
        ep.host.append(host_part);
    }

    let port_num, port_ok = port_part.parse_u32_dec();
    guard port_ok && port_num > 0 && port_num <= 65535 else { return false; }
    ep.port = port_num as! u16;
    return true;
}

// Parses a single Alt-Svc protocol=authority[; params] directive (RFC 7838 §3).
//
// Example:
//   entry_str = "h3=\":443\"; ma=86400"
//   returns: true, ep.proto="h3", ep.port=443, ep.max_age_sec=86400
fn parse_single_altsvc_entry(entry_str: const u8[:], ep: AltSvcEndpoint&) -> bool {
    let proto_token_raw, rem_entry_raw, has_eq = entry_str.split_once_byte('=');
    guard has_eq && proto_token_raw.len > 0 else { return false; }

    let proto_token = proto_token_raw.trim_lws();
    let rem_entry = rem_entry_raw.trim_lws();

    guard decode_altsvc_proto_id(proto_token, ep.proto) else { return false; }

    // Find authority inside quotes: "host:port"
    guard rem_entry.len >= 2 && rem_entry[0] == '"' else { return false; }
    let rel_q = rem_entry[1..].index_of_byte('"');
    guard rel_q >= 0 else { return false; }

    let authority = rem_entry[1..rel_q + 1];
    guard parse_altsvc_authority(authority, ep) else { return false; }

    let params_part = rem_entry[rel_q + 2..];
    parse_altsvc_params(params_part, ep);
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
    let trimmed = trim_lws(raw);
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
        if out_endpoints.len < out_endpoints.cap {
            out_endpoints.push(ep);
        } else if ep.proto[..] == "h3" {
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
    guard origin.len <= entry.origin.cap else { return; }
    entry.origin.append(origin);
    for &ep in endpoints { entry.endpoints.push(ep); }

    if cache.entries.len < cache.entries.cap {
        cache.entries.push(entry);
    } else {
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
    core::format_u64_dec(port as u64, out);
    out.append("\"; ma=");
    core::format_u64_dec(max_age_sec as u64, out);
    if persist {
        out.append("; persist=1");
    }
}
