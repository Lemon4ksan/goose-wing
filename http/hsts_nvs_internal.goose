// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/hsts_nvs_internal.goose).
namespace http_internal;

import std;
import core;
import http.headers.lexical;
import http.headers;
import http.hsts;
import http.mime;
import http.message_internal;
import http.novarysearch;
import http.sfv;
import http.sfv_sig_internal;
import http.sfv_wire_internal;
import rfc.http;

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
    return sub.eq_ascii_fold(domain) || is_subdomain_of(sub, domain);
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
    let prefix, ok = sub.strip_suffix_fold(parent);
    return ok && prefix.len > 1 && core::ends_with(prefix, ".");
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
    let after = core::add_sat_i64(close_idx, 1);
    let host = host_port[..after];
    if after == host_port.len {
        return host, "", true;
    }
    let port, has_colon = host_port[after..].strip_prefix(":");
    guard has_colon else { return "", "", false; }
    return host, port, true;
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
        let split_at = core::add_sat_i64(at_idx, 1);
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
    let trimmed, _ = raw_query.strip_prefix("?");
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
