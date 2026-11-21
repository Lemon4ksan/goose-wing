// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/ext_internal.goose).
namespace http_internal;

import std;
import core from "..";
import http.altsvc;
import http.cache.cache_control;
import http.early_hints;
import http.headers.lexical;
import http.headers;
import http.hsts;
import http.mime;
import http.novarysearch;
import http.sfv;
import http.targeted_cache;
import rfc.http;

// ---- http/altsvc.goose internal helpers ----

// Finds index of valid origin entry in cache, or -1 if not found.
fn find_origin_entry_idx(cache: const http::AltSvcCache&, origin: const u8[:]) -> i64 {
    for &entry, idx in cache.entries {
        if entry.valid && entry.origin[..] == origin {
            return idx;
        }
    }
    return -1;
}

// Parses single parameter token: e.g. `ma=86400` or `persist=1` (RFC 7838 Section 3).
//
// Example:
//   param_str = "ma=86400"
//   returns: true, mutates ep.max_age_sec to 86400
fn parse_altsvc_param(param_str: const u8[:], ep: http::AltSvcEndpoint&) -> bool {
    let p_name_raw, p_val_raw, ok = param_str.split_once_byte('=');
    guard ok else { return false; }

    let p_name = p_name_raw.trim_lws();
    let v_trim = p_val_raw.trim_lws();
    guard p_name.len > 0 && http::is_valid_token_swar(p_name) && v_trim.len > 0 else { return false; }

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
fn parse_altsvc_params(params_part: const u8[:], ep: http::AltSvcEndpoint&) -> bool {
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
fn parse_single_altsvc_entry(entry_str: const u8[:], ep: http::AltSvcEndpoint&) -> bool {
    ep = http::AltSvcEndpoint { .. };
    var committed = false;
    defer if !committed { ep = http::AltSvcEndpoint { .. }; };

    let proto_token, rem_entry, has_eq = entry_str.split_once_byte('=');
    guard has_eq && proto_token.len > 0 && decode_altsvc_proto_id(proto_token, ep.proto) else {
        return false;
    }

    let q_end = scan_altsvc_quoted_end(rem_entry);
    guard q_end >= 2 else { return false; }

    var authority: u8[..160] = [];
    guard http::strict_unquote(rem_entry[..q_end], authority, 160) &&
          http::parse_altsvc_authority(authority[..], ep) &&
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

fn update_altsvc_entry(
    entry:     http::AltSvcOriginEntry&,
    endpoints: const http::AltSvcEndpoint[:],
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

fn find_oldest_altsvc_idx(cache: const http::AltSvcCache&) -> i64 {
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
    cache:     http::AltSvcCache&,
    origin:    const u8[:],
    endpoints: const http::AltSvcEndpoint[:],
    now_sec:   i64,
) {
    var entry = http::AltSvcOriginEntry {
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

// ---- http/early_hints.goose internal helpers ----

// Parses single Link parameter: e.g. `rel=preload` or `as=style` (RFC 8288 §3).
//
// Example:
//   param_str = "rel=preload"
//   mutates link.rel to "preload"
fn parse_link_param(param_str: const u8[:], link: http::EarlyHintLink&) -> bool {
    let p_name_raw, p_val_raw, has_eq = param_str.split_once_byte('=');
    if !has_eq {
        let p_name = param_str.trim_lws();
        guard http::is_valid_header_name(p_name) else { return false; }
        if p_name.eq_ascii_fold("crossorigin") {
            link.crossorigin = true;
        }
        return true;
    }

    let p_name = p_name_raw.trim_lws();
    let p_val_trim = p_val_raw.trim_lws();
    guard http::is_valid_header_name(p_name) else { return false; }
    var p_val: u8[..256] = [];
    guard decode_token_or_quoted_param(p_val_trim, p_val, 256) else { return false; }

    if p_name.eq_ascii_fold("rel") {
        guard link.rel.len == 0 else { return true; }
        guard link.rel.try_append(p_val[..]) else { return false; }
    } else if p_name.eq_ascii_fold("as") {
        guard link.as_type.len == 0 else { return true; }
        guard link.as_type.try_append(p_val[..]) else { return false; }
    } else if p_name.eq_ascii_fold("crossorigin") {
        link.crossorigin = true;
    }
    return true;
}

fn find_link_entry_end(s: const u8[:]) -> i64 {
    var in_quotes = false;
    var in_angle = false;
    var escaped = false;
    for i in s.len {
        let b = s[i];
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes && b == '\\' {
            escaped = true;
            continue;
        }
        if b == '"' && !in_angle {
            in_quotes = !in_quotes;
        } else if b == '<' && !in_quotes {
            in_angle = true;
        } else if b == '>' && !in_quotes {
            in_angle = false;
        } else if !in_quotes && !in_angle && b == ',' {
            return i;
        }
    }
    return s.len;
}

fn read_next_link_param(rem: const u8[:]) -> const u8[:], const u8[:] {
    let s = rem.trim_start_bytes(" \t;");
    guard s.len > 0 else { return "", ""; }
    let p_len = s.find_unquoted_byte(';');
    let param = s[..p_len].trim_lws();
    let next_rem = if p_len < s.len { s[p_len + 1..] } else { s[..0] };
    return param, next_rem;
}

// Parses RFC 8288 semicolon-separated link parameters.
//
// Example:
//   params_str = "; rel=preload; as=style"
//   returns: true, link populated with rel="preload", as_type="style"
fn parse_link_params(params_str: const u8[:], link: http::EarlyHintLink&) -> bool {
    var rem = params_str;
    while rem.len > 0 {
        let param, next_rem = read_next_link_param(rem);
        guard param.len > 0 else { break; }
        guard parse_link_param(param, link) else { return false; }
        rem = next_rem;
    }
    return true;
}

// Parses a single RFC 8288 Link element (<URI> with optional semicolon parameters).
//
// Example:
//   entry_str = "</style.css>; rel=preload; as=style"
//   returns: true, link populated with uri="/style.css", rel="preload", as_type="style"
fn parse_single_link(entry_str: const u8[:], link: http::EarlyHintLink&) -> bool {
    link = http::EarlyHintLink { .. };
    var committed = false;
    defer if !committed { link = http::EarlyHintLink { .. }; };
    guard entry_str.len > 2 && entry_str[0] == '<' else { return false; }
    let rel_close = entry_str[1..].index_of_byte('>');
    guard rel_close >= 0 else { return false; }
    let close_idx = 1 + rel_close;
    let uri_slice = entry_str[1..close_idx];
    guard uri_slice.len > 0 && link.uri.try_append(uri_slice) else { return false; }

    let after_uri = entry_str[close_idx + 1..].trim_lws_start();
    if after_uri.len > 0 {
        guard after_uri[0] == ';' else { return false; }
        guard parse_link_params(after_uri, link) else { return false; }
    }
    committed = true;
    return true;
}

// Formats a single `EarlyHintLink` into an HTTP `Link: <uri>; ...` header line.
fn format_single_early_hint_link<B>(link: const http::EarlyHintLink&, out: B&) -> bool {
    guard link.uri.len > 0 else { return false; }
    let base_needed = core::add_sat_u64(link.uri.len as u64, 64);
    guard core::add_sat_u64(out.len as u64, base_needed) <= (out.cap as u64) else { return false; }
    out.append("Link: <");
    out.append(link.uri[..]);
    out.push('>');
    if link.rel.len > 0 {
        out.append("; rel=");
        out.append(link.rel[..]);
    }
    if link.as_type.len > 0 {
        out.append("; as=");
        out.append(link.as_type[..]);
    }
    if link.crossorigin {
        out.append("; crossorigin");
    }
    out.append("\r\n");
    return true;
}

// Computes truncated fingerprint for (path, etag) bounded by `(capacity_bits + remainder_bits)` bits.
fn compute_casper_key(set: const http::CasperSet&, path: const u8[:], etag: const u8[:]) -> u64 {
    let h_path = core::fnv1a_64(path);
    let h_etag = core::fnv1a_64(etag);
    let combined = core::hash_combine_u64(h_path, h_etag);
    let total_bits = min(core::add_sat_u64(set.capacity_bits, set.remainder_bits), 14);
    let drop_bits = core::sub_sat_u64(64, total_bits);
    let mask = if total_bits == 0 { 0 } else { 0xFFFFFFFFFFFFFFFF >> drop_bits };
    return combined & mask;
}

// Looks up `key` in sorted `set.keys`; returns `(insert_idx, found)`.
fn find_casper_key_slot(set: const http::CasperSet&, key: u64) -> i64, bool {
    var lo: u64 = 0;
    var hi: u64 = set.keys.len as u64;
    while lo < hi {
        let mid = core::add_sat_u64(lo, core::sub_sat_u64(hi, lo) >> 1);
        let cur = set.keys[mid as i64];
        if cur == key {
            return mid as i64, true;
        }
        if cur < key {
            lo = core::add_sat_u64(mid, 1);
        } else {
            hi = mid;
        }
    }
    return lo as i64, false;
}

inline fn append_casper_bit<B>(out: B&, cur_byte: u64&, bit_pos: u64&, bit: u64) -> bool {
    cur_byte = ((cur_byte << 1) | (bit & 1)) & 0xFF;
    bit_pos = core::add_sat_u64(bit_pos, 1);
    if bit_pos == 8 {
        let b_val: u8 = if cur_byte == 0 { 0 } else { (cur_byte & 0xFF) as u8 };
        guard out.try_push(b_val) else { return false; }
        cur_byte = 0;
        bit_pos = 0;
    }
    return true;
}

inline fn read_casper_bit(raw: const u8[:], byte_idx: i64&, bit_pos: u64&) -> u64, bool {
    guard byte_idx < raw.len else { return 0, false; }
    let shift = core::sub_sat_u64(7, bit_pos);
    let bit = (raw[byte_idx] as u64 >> shift) & 1;
    bit_pos = core::add_sat_u64(bit_pos, 1);
    if bit_pos == 8 {
        bit_pos = 0;
        byte_idx = core::add_sat_i64(byte_idx, 1);
    }
    return bit, true;
}

// Decodes a single Golomb-Rice delta step from `raw` at `(byte_idx, bit_pos)`.
//
// Example:
//   raw = [0x40], rem_bits = 6, byte_idx = 0, bit_pos = 0
//   returns: delta = 16, has_val = true, valid = true, byte_idx = 0, bit_pos = 7
inline fn decode_casper_golomb_step(
    raw:      const u8[:],
    rem_bits: u64,
    byte_idx: i64&,
    bit_pos:  u64&,
) -> u64, bool, bool {
    var q: u64 = 0;
    var got_zero = false;
    while byte_idx < raw.len {
        let b, ok_b = read_casper_bit(raw, byte_idx, bit_pos);
        guard ok_b else { break; }
        if b == 0 {
            got_zero = true;
            break;
        }
        q = core::add_sat_u64(q, 1);
        guard q <= 512 else { return 0, false, false; }
    }
    guard got_zero else { return 0, false, true; }
    var r:     u64 = 0;
    var r_idx: u64 = rem_bits;
    while r_idx > 0 {
        r_idx = core::sub_sat_u64(r_idx, 1);
        let rb, ok_r = read_casper_bit(raw, byte_idx, bit_pos);
        guard ok_r else { return 0, false, true; }
        r = core::add_sat_u64(core::add_sat_u64(r, r), rb);
    }
    var q_scaled: u64 = q;
    var s_idx:    u64 = rem_bits;
    while s_idx > 0 {
        s_idx = core::sub_sat_u64(s_idx, 1);
        q_scaled = core::add_sat_u64(q_scaled, q_scaled);
    }
    return core::add_sat_u64(q_scaled, r), true, true;
}

// ---- http/hsts.goose internal helpers ----

// Parses non-empty ASCII decimal digits into `i64`.
//
// Example:
//   s = "31536000"
//   returns: 31536000, ok = true
fn parse_hsts_digits(s: const u8[:]) -> i64, bool {
    guard s.len > 0 else { return 0, false; }
    for b in s {
        guard core::is_ascii_digit(b) else { return 0, false; }
    }
    return s.parse_i64_dec();
}

// RFC 6797 Section 6.1.1: The max-age Directive - Unescape quoted-string before delta-seconds parse.
//
// Example:
//   val = "31536000"
//   returns: 31536000, ok = true
fn parse_hsts_max_age(val: const u8[:]) -> i64, bool {
    guard val.len > 0 else { return 0, false; }
    if val[0] == '"' {
        var unq_buf: u8[..32] = [];
        guard http::strict_unquote(val, unq_buf, 32) else { return 0, false; }
        return parse_hsts_digits(unq_buf[..]);
    }
    return parse_hsts_digits(val);
}

// RFC 6797 Section 6.1: Strict-Transport-Security HTTP Response Header Field - Every directive MUST appear at most once.
fn record_unique_hsts_ext(seen_ext: u8[..64][..16]&, key: const u8[:]) -> bool {
    for &ext in seen_ext {
        if ext[..].eq_ascii_fold(key) {
            return false;
        }
    }
    var name_buf: u8[..64] = [];
    return name_buf.try_set(key) && seen_ext.try_push(name_buf);
}

fn apply_hsts_directive(d: http::HstsDirective&, seen_ext: u8[..64][..16]&, trimmed: const u8[:]) -> bool {
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
    // RFC 6797 Section 6.1: Strict-Transport-Security HTTP Response Header Field - Validate token or quoted-string extension value.
    if has_val {
        var ext_val: u8[..256] = [];
        guard decode_token_or_quoted_param(val.trim_lws(), ext_val, 256) else { return false; }
    }
    return record_unique_hsts_ext(seen_ext, key);
}

fn host_matches_domain(sub: const u8[:], domain: const u8[:]) -> bool {
    if sub.eq_ascii_fold(domain) { return true; }
    guard sub.len > domain.len + 1 else { return false; }
    guard sub.ends_with_fold(domain) else { return false; }
    return sub[sub.len - domain.len - 1] == '.';
}

fn is_preloaded_tld(hostname: const u8[:]) -> bool {
    for tld in http::HSTS_PRELOAD_TLDS {
        if hostname.ends_with_fold(tld) {
            return true;
        }
    }
    return false;
}

fn is_preloaded_property(h: const u8[:]) -> bool {
    for dom in http::HSTS_PRELOAD_DOMAINS {
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

fn entry_matches_hsts(entry: const http::HstsEntry&, hostname: const u8[:], now_sec: i64) -> bool {
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

fn find_hsts_entry_index(cache: const http::HstsCache&, hostname: const u8[:]) -> i64 {
    for i in cache.entries.len {
        guard i < cache.entries.len else { break; }
        let entry = &cache.entries[i];
        if entry.valid && entry.host[..].eq_ascii_fold(hostname) {
            return i;
        }
    }
    return -1;
}

fn find_hsts_evict_index(cache: const http::HstsCache&, now_sec: i64) -> i64 {
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

fn store_hsts_entry(cache: http::HstsCache&, entry: const http::HstsEntry&, now_sec: i64) {
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

fn format_hsts_cache_line<B>(entry: const http::HstsEntry&, out: B&) {
    out.append(entry.host[..]);
    out.push('\t');
    format(out, entry.expiry_epoch_sec);
    out.push('\t');
    out.push(if entry.include_subdomains { '1' } else { '0' });
    out.push('\t');
    out.push(if entry.is_preload { '1' } else { '0' });
    out.push('\n');
}

// Parses a single serialized HSTS cache line (`host\texpiry\tinclude_subdomains\tpreload`).
//
// Example:
//   line = "example.com\t1700003600\t1\t0"
//   returns: entry with host="example.com", expiry_epoch_sec=1700003600, ok = true
fn parse_hsts_cache_line(line: const u8[:], now_sec: i64) -> http::HstsEntry, bool {
    var entry = http::HstsEntry { .. };
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

fn upsert_hsts_entry(cache: http::HstsCache&, entry: const http::HstsEntry&, now_sec: i64) {
    let existing_idx = find_hsts_entry_index(cache, entry.host[..]);
    if existing_idx >= 0 && existing_idx < cache.entries.len {
        cache.entries[existing_idx] = entry;
    } else {
        store_hsts_entry(cache, entry, now_sec);
    }
}

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

// ---- http/novarysearch.goose internal helpers ----

fn record_nvs_dict_key(seen_keys: u8[..64][..64]&, key: const u8[..64]&) -> bool {
    for &existing in seen_keys {
        if existing[..] == key[..] {
            return true;
        }
    }
    return seen_keys.try_push(key);
}

inline fn append_nvs_string_item(
    bare:        const http::SfvBareItem&,
    out_strings: u8[..64][..16]&,
    all_strings: bool&,
) {
    guard all_strings && bare.kind == http::SfvType.String else {
        all_strings = false;
        return;
    }
    var name: u8[..64] = [];
    if !name.try_set(bare.text[..]) || !out_strings.try_push(name) {
        all_strings = false;
    }
}

// Parses an RFC 9651 inner list of string items without allocating a full SfvMember frame.
// Leaves `cursor` and `out_strings` unchanged on syntax error.
//
// Example:
//   raw = "(\"utm_source\" \"fbclid\");p=1", cursor = 0
//   returns: ok = true, cursor = 27, out_strings = ["utm_source", "fbclid"], all_strings = true
fn parse_nvs_inner_list(
    raw:         const u8[:],
    cursor:      i64&,
    out_strings: u8[..64][..16]&,
    all_strings: bool&,
) -> bool {
    let saved_cursor = cursor;
    out_strings.clear();
    all_strings = true;
    var committed = false;
    defer if !committed {
        cursor = saved_cursor;
        out_strings.clear();
    };

    cursor = core::add_sat_i64(cursor, 1); // skip '('
    var closed = false;
    var item_count: i64 = 0;
    while cursor < raw.len {
        cursor = sf_skip_sp(raw, cursor);
        if cursor < raw.len && raw[cursor] == ')' {
            cursor = core::add_sat_i64(cursor, 1);
            closed = true;
            break;
        }
        item_count = core::add_sat_i64(item_count, 1);
        guard item_count <= 32 else { return false; }
        var bare = http::SfvBareItem { .. };
        guard parse_sfv_bare_item(raw, cursor, bare) && skip_sfv_parameters(raw, cursor) else { return false; }
        append_nvs_string_item(bare, out_strings, all_strings);
        guard cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == ')') else { return false; }
    }
    guard closed && skip_sfv_parameters(raw, cursor) else { return false; }
    committed = true;
    return true;
}

fn apply_nvs_inner_list_entry(
    state:       http::NvsDictParseState&,
    key:         const u8[:],
    list_vals:   const u8[..64][..16]&,
    all_strings: bool,
) {
    if key == "params" {
        state.params_type_ok = all_strings;
        if all_strings {
            state.nvs.params = list_vals;
            state.nvs.ignore_all_params = false;
        }
        return;
    }
    if key == "except" {
        state.has_except = true;
        state.except_type_ok = all_strings;
        if all_strings {
            state.nvs.except_params = list_vals;
        }
        return;
    }
    if key == "key-order" {
        state.key_order_type_ok = false;
    }
}

fn apply_nvs_bare_entry(state: http::NvsDictParseState&, key: const u8[:], bare: const http::SfvBareItem&) {
    if key == "params" {
        state.params_type_ok = (bare.kind == http::SfvType.Boolean);
        if state.params_type_ok {
            state.nvs.ignore_all_params = bare.bool_val;
            state.nvs.params.clear();
        }
        return;
    }
    if key == "except" {
        state.has_except = true;
        state.except_type_ok = false;
        return;
    }
    if key == "key-order" {
        state.key_order_type_ok = (bare.kind == http::SfvType.Boolean);
        if state.key_order_type_ok {
            state.nvs.key_order_matters = !bare.bool_val;
        }
    }
}

// Parses one RFC 9651 dictionary member for No-Vary-Search and updates `state`.
// Leaves `cursor` unchanged on syntax error.
//
// Example:
//   raw = "params=(\"a\"), key-order", cursor = 0
//   returns: ok = true, cursor = 12 (points to ',')
fn parse_nvs_dict_member(raw: const u8[:], cursor: i64&, state: http::NvsDictParseState&) -> bool {
    let saved_cursor = cursor;
    var committed = false;
    defer if !committed { cursor = saved_cursor; };

    var key: u8[..64] = [];
    guard http::parse_sfv_key(raw, cursor, key) && record_nvs_dict_key(state.seen_keys, key) else { return false; }

    if cursor < raw.len && raw[cursor] == '=' {
        cursor = core::add_sat_i64(cursor, 1);
        if cursor < raw.len && raw[cursor] == '(' {
            var list_vals: u8[..64][..16] = [];
            var all_strings = false;
            guard parse_nvs_inner_list(raw, cursor, list_vals, all_strings) else { return false; }
            apply_nvs_inner_list_entry(state, key[..], list_vals, all_strings);
            committed = true;
            return true;
        }
        var bare = http::SfvBareItem { .. };
        guard parse_sfv_bare_item(raw, cursor, bare) && skip_sfv_parameters(raw, cursor) else { return false; }
        apply_nvs_bare_entry(state, key[..], bare);
        committed = true;
        return true;
    }

    guard skip_sfv_parameters(raw, cursor) else { return false; }
    let true_item = http::SfvBareItem { kind: http::SfvType.Boolean, bool_val: true, .. };
    apply_nvs_bare_entry(state, key[..], true_item);
    committed = true;
    return true;
}

fn bytes_less_than(a: const u8[:], b: const u8[:]) -> bool {
    let min_len = min(a.len, b.len);
    for i in min_len {
        if a[i] < b[i] { return true; }
        if a[i] > b[i] { return false; }
    }
    return a.len < b.len;
}

// Parses a single key=value query string parameter.
//
// Example:
//   pair = "key=value"
//   returns: true, p.key="key", p.val="value"
fn parse_single_query_param(pair: const u8[:], p: http::QueryParam&) -> bool {
    let k, v, has_eq = pair.split_once_byte('=');
    guard p.key.try_append(k) else { return false; }
    if has_eq {
        guard p.val.try_append(v) else { return false; }
    }
    return true;
}

inline fn try_decode_nvs_pct_octet(raw: const u8[:], i: i64) -> u8, i64 {
    let next = core::add_sat_i64(i, 1);
    let hex_end = core::add_sat_i64(i, 3);
    guard hex_end <= raw.len else { return '%', next; }
    let hval, ok_h = raw[next..hex_end].parse_u8_hex();
    guard ok_h else { return '%', next; }
    return hval, hex_end;
}

// Decodes URL-encoded query parameter key bytes ('+' as space and '%HH' hex octets).
//
// Example:
//   raw = "%75tm+source", out = []
//   returns: true, out = "utm source"
fn decode_nvs_query_key(raw: const u8[:], out: u8[..128]&) -> bool {
    out.clear();
    var i: i64 = 0;
    while i < raw.len {
        let b = raw[i];
        var dec:  u8  = 0;
        var next: i64 = core::add_sat_i64(i, 1);
        if b == '+' {
            dec = ' ';
        } else if b == '%' {
            let pct_b, pct_next = try_decode_nvs_pct_octet(raw, i);
            dec = pct_b;
            next = pct_next;
        } else {
            dec = b;
        }
        guard out.try_push(dec) else {
            out.clear();
            return false;
        }
        i = next;
    }
    return true;
}

// Parses query string and applies No-Vary-Search filtering rules.
//
// Example:
//   raw_query = "?a=1&b=2", nvs ignores "a"
//   returns: true, params contains only "b=2"
fn parse_and_filter_query_params(
    raw_query: const u8[:],
    nvs:       const http::NoVarySearch&,
    params:    http::QueryParam[..128]&,
) -> bool {
    params.clear();
    var committed = false;
    defer if !committed { params.clear(); };
    let trimmed = if raw_query.len > 0 && raw_query[0] == '?' { raw_query[1..] } else { raw_query };
    var tok = core::make_byte_tokenizer(trimmed, '&');

    loop {
        let pair, ok = tok.token_next();
        guard ok else { break; }
        if pair.len == 0 { continue; }

        let k_raw, _, _ = pair.split_once_byte('=');
        var k_dec: u8[..128] = [];
        let has_dec = decode_nvs_query_key(k_raw, k_dec);
        let key_view = if has_dec { k_dec[..] } else { k_raw };
        if http::is_param_ignored(nvs, key_view) {
            continue;
        }

        var p = http::QueryParam { .. };
        guard parse_single_query_param(pair, p) && params.try_push(p) else { return false; }
    }
    committed = true;
    return true;
}

fn serialize_normalized_query<B>(params: const http::QueryParam[:], out: B&) {
    for &p, i in params {
        if i > 0 {
            out.push('&');
        }
        out.append(p.key[..]);
        if p.val.len > 0 {
            out.push('=');
            out.append(p.val[..]);
        }
    }
}

fn try_normalize_query_for_cache<B>(raw_query: const u8[:], nvs: const http::NoVarySearch&, out: B&) -> bool {
    out.clear();
    var params: http::QueryParam[..128] = [];
    guard parse_and_filter_query_params(raw_query, nvs, params) else { return false; }

    // If key-order does not matter, sort parameters alphabetically by key
    if !nvs.key_order_matters && params.len > 1 {
        sort(params) { a, b => bytes_less_than(a.key[..], b.key[..]) };
    }

    serialize_normalized_query(params[..], out);
    return true;
}

// ---- http/targeted_cache.goose internal helpers ----

fn is_empty_or_whitespace_value(val: const u8[:]) -> bool {
    for b in val {
        if b != ' ' && b != '\t' && b != ',' && b != '\r' && b != '\n' {
            return false;
        }
    }
    return true;
}

inline fn clamp_targeted_delta_seconds(v: i64) -> i32 {
    return min<i64>(v, rfc::MAX_DELTA_SECONDS) as i32;
}

fn apply_targeted_sf_int_entry(k: const u8[:], e: const http::SfDictEntry&, cc: http::CacheControl&) -> bool, bool {
    if k == "max-age" {
        guard !e.is_inner_list && e.item.kind == http::SfType.Integer && e.item.int_val >= 0 else {
            return true, false;
        }
        cc.max_age = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | http::CC_HAS_MAX_AGE;
        return true, true;
    }
    if k == "s-maxage" {
        guard !e.is_inner_list && e.item.kind == http::SfType.Integer && e.item.int_val >= 0 else {
            return true, false;
        }
        cc.s_maxage = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | http::CC_HAS_S_MAXAGE;
        return true, true;
    }
    if k == "stale-while-revalidate" {
        guard !e.is_inner_list && e.item.kind == http::SfType.Integer && e.item.int_val >= 0 else {
            return true, false;
        }
        cc.stale_while_revalidate = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | http::CC_STALE_WHILE_REVALIDATE;
        return true, true;
    }
    if k == "stale-if-error" {
        guard !e.is_inner_list && e.item.kind == http::SfType.Integer && e.item.int_val >= 0 else {
            return true, false;
        }
        cc.stale_if_error = clamp_targeted_delta_seconds(e.item.int_val);
        cc.flags = cc.flags | http::CC_STALE_IF_ERROR;
        return true, true;
    }
    return false, true;
}

fn targeted_bool_flag_for_key(k: const u8[:]) -> u32 {
    if k == "no-store" { return http::CC_NO_STORE; }
    if k == "no-cache" { return http::CC_NO_CACHE; }
    if k == "must-revalidate" { return http::CC_MUST_REVALIDATE; }
    if k == "proxy-revalidate" { return http::CC_PROXY_REVALIDATE; }
    if k == "must-understand" { return http::CC_MUST_UNDERSTAND; }
    if k == "private" { return http::CC_PRIVATE; }
    if k == "public" { return http::CC_PUBLIC; }
    if k == "immutable" { return http::CC_IMMUTABLE; }
    if k == "no-transform" { return http::CC_NO_TRANSFORM; }
    return 0;
}

fn apply_targeted_sf_entry(e: const http::SfDictEntry&, cc: http::CacheControl&) -> bool {
    let k = e.key;
    let matched_int, ok_int = apply_targeted_sf_int_entry(k, e, cc);
    if matched_int {
        return ok_int;
    }
    if k == "no-cache" && !e.is_inner_list && e.item.kind == http::SfType.String {
        var unq_nc: u8[..256] = [];
        guard http::sf_unescape_string(e.item.str_val, unq_nc) else { return false; }
        cc.flags = cc.flags | http::CC_NO_CACHE;
        parse_field_names(unq_nc[..], cc.no_cache_fields, cc.no_cache_overflow);
        return true;
    }
    if k == "private" && !e.is_inner_list && e.item.kind == http::SfType.String {
        var unq_pr: u8[..256] = [];
        guard http::sf_unescape_string(e.item.str_val, unq_pr) else { return false; }
        cc.flags = cc.flags | http::CC_PRIVATE;
        parse_field_names(unq_pr[..], cc.private_fields, cc.private_overflow);
        return true;
    }
    let flag = targeted_bool_flag_for_key(k);
    if flag != 0 {
        guard !e.is_inner_list && e.item.kind == http::SfType.Boolean else { return false; }
        if e.item.bool_val {
            cc.flags = cc.flags | flag;
        }
        return true;
    }
    return true;
}

// RFC 9213 Section 2.1: Syntax - Parse targeted header as RFC 8941 SF Dictionary and ignore field on parse error.
//
// Example:
//   header_name = "cdn-cache-control", map contains "CDN-Cache-Control: max-age=600"
//   returns: true, cc populated with max_age=600
fn parse_named_cache_control(
    map:               const http::HeaderMap&,
    header_name:       const u8[:],
    cc:                http::CacheControl&,
    ignore_cargo_cult: bool,
) -> bool {
    guard map.get_header(header_name).len > 0 else { return false; }
    var combined: u8[..2048] = [];
    guard map.get_combined(header_name, combined, 2048) && !is_empty_or_whitespace_value(combined[..]) else {
        return false;
    }
    var entries: http::SfDictEntry[..16] = [];
    guard http::parse_sf_dict(combined[..], entries) && entries.len > 0 else { return false; }

    var parsed = http::CacheControl { .. };
    for &e in entries {
        guard apply_targeted_sf_entry(e, parsed) else { return false; }
    }
    if ignore_cargo_cult && (parsed.flags & http::CC_HAS_MAX_AGE) != 0 && parsed.max_age > 0 {
        parsed.flags = parsed.flags & ~(http::CC_NO_CACHE | http::CC_MUST_REVALIDATE);
    }
    cc = parsed;
    return true;
}
