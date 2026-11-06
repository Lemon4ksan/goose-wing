// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9211 (Cache-Status HTTP Response Header) and RFC 9209 (Proxy-Status HTTP Response Header).
// Provides standardized zero-heap diagnostic inspection and formatting for intermediary caches,
// proxies, CDN edge nodes, and next-hop failure reporting.
namespace wing;

import std;
import core from "..";

// ---- RFC 9211 Cache-Status Model -----------------------------------------

struct CacheStatusEntry {
    cache_name: u8[..64]  = [],
    hit:        bool      = false,
    fwd:        u8[..32]  = [],
    fwd_status: i32       = 0,
    ttl:        i64       = 0,
    stored:     bool      = false,
    collapsed:  bool      = false,
    key:        u8[..128] = [],
    detail:     u8[..128] = [],
}

// ---- RFC 9209 Proxy-Status Model -----------------------------------------

struct ProxyStatusEntry {
    proxy_name:      u8[..64]  = [],
    error_type:      u8[..64]  = [],
    next_hop:        u8[..64]  = [],
    details:         u8[..256] = [],
    received_status: i32       = 0,
}

// ---- Diagnostics Parser Helpers ------------------------------------------

// Skips leading whitespace and comma delimiters.
// Advances `idx` past the skipped bytes.
//
// Example:
//   raw = ",  item", idx = 0
//   idx becomes 3 (pointing to 'i')
fn skip_status_list_delims(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    let trimmed = core::trim_start_bytes(rem, " \t,");
    idx += rem.len - trimmed.len;
}

// Skips semicolon, space, and tab parameter delimiters.
// Advances `idx` past the skipped bytes.
//
// Example:
//   raw = ";  foo=bar", idx = 0
//   idx becomes 3 (pointing to 'f')
fn skip_status_param_delims(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    let trimmed = core::trim_start_bytes(rem, "; \t");
    idx += rem.len - trimmed.len;
}

// Skips linear whitespace spaces and tabs.
// Advances `idx` past the whitespace.
//
// Example:
//   raw = "  token", idx = 0
//   idx becomes 2 (pointing to 't')
fn skip_lws_at(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    let trimmed = core::trim_lws_start(rem);
    idx += rem.len - trimmed.len;
}

// Reads target name token up to delimiter.
// Advances `idx` past the token.
//
// Example:
//   raw = "OriginCache; hit", idx = 0
//   returns: "OriginCache", idx becomes 11
fn read_status_target_name(raw: const u8[:], idx: i64&) -> const u8[:] {
    let start = idx;
    while idx < raw.len {
        let b = raw[idx];
        if b == ';' || b == ',' || b == ' ' || b == '\t' {
            break;
        }
        idx += 1;
    }
    return raw[start..idx];
}

// Reads parameter name token up to '=' or delimiter.
// Advances `idx` past the token.
//
// Example:
//   raw = "ttl=120", idx = 0
//   returns: "ttl", idx becomes 3
fn read_status_param_name(raw: const u8[:], idx: i64&) -> const u8[:] {
    let start = idx;
    while idx < raw.len {
        let b = raw[idx];
        if b == '=' || b == ';' || b == ',' || b == ' ' || b == '\t' {
            break;
        }
        idx += 1;
    }
    return raw[start..idx];
}

// Reads double-quoted parameter string value with backslash-escapes.
// Advances `idx` past closing quote.
//
// Example:
//   raw = "\"xyzzy\"", idx = 0
//   returns: "xyzzy", idx becomes 7
fn read_quoted_status_val(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    let start_idx = idx;
    var p = idx + 1; // skip opening quote
    let v_start = p;
    var escaped = false;
    while p < raw.len {
        let b = raw[p];
        if escaped {
            escaped = false;
        } else if b == '\\' {
            escaped = true;
        } else if b == '"' {
            break;
        }
        p += 1;
    }
    guard p < raw.len && raw[p] == '"' && !escaped else {
        idx = start_idx;
        return raw[..0], false;
    }
    let val = raw[v_start..p];
    idx = p + 1; // skip closing quote
    return val, true;
}

// Reads unquoted token parameter value.
// Advances `idx` past the token.
//
// Example:
//   raw = "120; next", idx = 0
//   returns: "120", idx becomes 3
fn read_token_status_val(raw: const u8[:], idx: i64&) -> const u8[:] {
    let v_start = idx;
    while idx < raw.len {
        let b = raw[idx];
        if b == ';' || b == ',' || b == ' ' || b == '\t' {
            break;
        }
        idx += 1;
    }
    return raw[v_start..idx];
}

// Reads parameter key-value pair.
// Advances `idx` past consumed parameter.
//
// Example:
//   raw = "; ttl=120", idx = 0
//   returns: p_name="ttl", p_val="120", ok=true
fn read_status_param(raw: const u8[:], idx: i64&) -> const u8[:], const u8[:], bool {
    skip_status_param_delims(raw, idx);
    guard idx < raw.len && raw[idx] != ',' else { return raw[..0], raw[..0], false; }

    let param_name = read_status_param_name(raw, idx);
    skip_lws_at(raw, idx);

    var param_val = raw[..0];
    if idx < raw.len && raw[idx] == '=' {
        idx += 1; // skip '='
        skip_lws_at(raw, idx);
        if idx < raw.len && raw[idx] == '"' {
            let q_val, q_ok = read_quoted_status_val(raw, idx);
            guard q_ok else { return raw[..0], raw[..0], false; }
            param_val = q_val;
        } else {
            param_val = read_token_status_val(raw, idx);
        }
    }
    return param_name, param_val, true;
}

// ---- RFC 9211 Cache-Status Parser and Formatter --------------------------

fn apply_cache_status_flags(entry: CacheStatusEntry&, name: const u8[:]) -> bool {
    if core::eq_ascii_fold(name, "hit") {
        entry.hit = true;
        return true;
    }
    if core::eq_ascii_fold(name, "stored") {
        entry.stored = true;
        return true;
    }
    if core::eq_ascii_fold(name, "collapsed") {
        entry.collapsed = true;
        return true;
    }
    return false;
}

fn apply_cache_status_param(entry: CacheStatusEntry&, name: const u8[:], val: const u8[:]) -> bool {
    guard !apply_cache_status_flags(entry, name) else { return true; }

    if core::eq_ascii_fold(name, "ttl") {
        let ttl_v, ok = core::parse_i64_dec(val);
        guard ok else { return false; }
        entry.ttl = ttl_v;
    } else if core::eq_ascii_fold(name, "fwd") {
        guard val.len <= entry.fwd.cap else { return false; }
        entry.fwd.clear();
        entry.fwd.append(val);
    } else if core::eq_ascii_fold(name, "fwd-status") {
        let fwd_v, ok = core::parse_i64_dec(val);
        guard ok && fwd_v >= 0 && fwd_v <= 999 else { return false; }
        entry.fwd_status = fwd_v as! i32;
    } else if core::eq_ascii_fold(name, "key") {
        guard val.len <= entry.key.cap else { return false; }
        entry.key.clear();
        entry.key.append(val);
    } else if core::eq_ascii_fold(name, "detail") {
        guard val.len <= entry.detail.cap else { return false; }
        entry.detail.clear();
        entry.detail.append(val);
    }
    return true;
}

// Parses a single cache-status entry into out_entry.
// Advances `idx` past the entry.
//
// Example:
//   raw = "OriginCache; hit; ttl=120", idx = 0
//   returns: true, out_entry populated, idx points to end
fn parse_single_cache_status_entry(raw: const u8[:], idx: i64&, out_entry: CacheStatusEntry&) -> bool {
    skip_status_list_delims(raw, idx);
    guard idx < raw.len else { return false; }

    out_entry = CacheStatusEntry { .. };
    let name = read_status_target_name(raw, idx);
    guard name.len <= out_entry.cache_name.cap else { return false; }
    out_entry.cache_name.append(name);

    while idx < raw.len && raw[idx] != ',' {
        let p_name, p_val, ok = read_status_param(raw, idx);
        guard ok else { return false; }
        guard apply_cache_status_param(out_entry, p_name, p_val) else { return false; }
    }
    return true;
}

// Parses a `Cache-Status: OriginCache; hit; ttl=120; key="xyz"` header.
//
// Example:
//   raw = "OriginCache; hit; ttl=120"
//   returns: 1, out_entries contains 1 parsed entry
fn parse_cache_status_header(
    raw:         const u8[:],
    out_entries: CacheStatusEntry[..8]&,
) -> i64 {
    var idx = 0;
    while idx < raw.len && out_entries.len < out_entries.cap {
        var entry = CacheStatusEntry { .. };
        guard parse_single_cache_status_entry(raw, idx, entry) else { break; }
        out_entries.push(entry);
    }
    return out_entries.len;
}

fn format_cache_status_flags<B>(entry: const CacheStatusEntry&, out: B&) {
    if entry.hit {
        out.append("; hit");
    }
    if entry.stored {
        out.append("; stored");
    }
    if entry.collapsed {
        out.append("; collapsed");
    }
    if entry.ttl > 0 {
        out.append("; ttl=");
        core::format_i64_dec(entry.ttl, out);
    }
}

fn format_cache_status_meta<B>(entry: const CacheStatusEntry&, out: B&) {
    if entry.fwd.len > 0 {
        out.append("; fwd=");
        out.append(entry.fwd[..]);
    }
    if entry.fwd_status > 0 {
        out.append("; fwd-status=");
        core::format_i64_dec(entry.fwd_status as i64, out);
    }
    if entry.key.len > 0 {
        out.append("; key=\"");
        out.append(entry.key[..]);
        out.push('"' as u8);
    }
    if entry.detail.len > 0 {
        out.append("; detail=\"");
        out.append(entry.detail[..]);
        out.push('"' as u8);
    }
}

// Formats a CacheStatusEntry into an RFC 9211 header string
fn format_cache_status<B>(entry: const CacheStatusEntry&, out: B&) {
    out.append(entry.cache_name[..]);
    format_cache_status_flags(entry, out);
    format_cache_status_meta(entry, out);
}

// ---- RFC 9209 Proxy-Status Parser and Formatter --------------------------

fn apply_proxy_status_param(entry: ProxyStatusEntry&, name: const u8[:], val: const u8[:]) -> bool {
    if core::eq_ascii_fold(name, "error") {
        guard val.len <= entry.error_type.cap else { return false; }
        entry.error_type.clear();
        entry.error_type.append(val);
    } else if core::eq_ascii_fold(name, "next-hop") {
        guard val.len <= entry.next_hop.cap else { return false; }
        entry.next_hop.clear();
        entry.next_hop.append(val);
    } else if core::eq_ascii_fold(name, "details") {
        guard val.len <= entry.details.cap else { return false; }
        entry.details.clear();
        entry.details.append(val);
    } else if core::eq_ascii_fold(name, "received-status") {
        let rec_v, ok = core::parse_i64_dec(val);
        guard ok && rec_v >= 0 && rec_v <= 999 else { return false; }
        entry.received_status = rec_v as! i32;
    }
    return true;
}

// Parses a single proxy-status entry into out_entry.
// Advances `idx` past the entry.
//
// Example:
//   raw = "edge1; error=connection_refused", idx = 0
//   returns: true, out_entry populated, idx points to end
fn parse_single_proxy_status_entry(raw: const u8[:], idx: i64&, out_entry: ProxyStatusEntry&) -> bool {
    skip_status_list_delims(raw, idx);
    guard idx < raw.len else { return false; }

    out_entry = ProxyStatusEntry { .. };
    let name = read_status_target_name(raw, idx);
    guard name.len <= out_entry.proxy_name.cap else { return false; }
    out_entry.proxy_name.append(name);

    while idx < raw.len && raw[idx] != ',' {
        let p_name, p_val, ok = read_status_param(raw, idx);
        guard ok else { return false; }
        guard apply_proxy_status_param(out_entry, p_name, p_val) else { return false; }
    }
    return true;
}

// Parses a `Proxy-Status: edge1; error=connection_refused; details="upstream tcp rst"` header.
//
// Example:
//   raw = "edge1; error=connection_refused"
//   returns: 1, out_entries contains 1 parsed entry
fn parse_proxy_status_header(
    raw:         const u8[:],
    out_entries: ProxyStatusEntry[..8]&,
) -> i64 {
    var idx = 0;
    while idx < raw.len && out_entries.len < out_entries.cap {
        var entry = ProxyStatusEntry { .. };
        guard parse_single_proxy_status_entry(raw, idx, entry) else { break; }
        out_entries.push(entry);
    }
    return out_entries.len;
}

// Formats a ProxyStatusEntry into an RFC 9209 header string
fn format_proxy_status<B>(entry: const ProxyStatusEntry&, out: B&) {
    out.append(entry.proxy_name[..]);
    if entry.error_type.len > 0 {
        out.append("; error=");
        out.append(entry.error_type[..]);
    }
    if entry.next_hop.len > 0 {
        out.append("; next-hop=\"");
        out.append(entry.next_hop[..]);
        out.push('"' as u8);
    }
    if entry.details.len > 0 {
        out.append("; details=\"");
        out.append(entry.details[..]);
        out.push('"' as u8);
    }
    if entry.received_status > 0 {
        out.append("; received-status=");
        core::format_i64_dec(entry.received_status as i64, out);
    }
}
