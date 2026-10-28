// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9211 (Cache-Status HTTP Response Header) and RFC 9209 (Proxy-Status HTTP Response Header).
// Provides standardized zero-heap diagnostic inspection and formatting for intermediary caches,
// proxies, CDN edge nodes, and next-hop failure reporting.
namespace wing;

import std;
import core from "..";

// ---- 1. RFC 9211 Cache-Status Model -----------------------------------------

struct CacheStatusEntry {
    cache_name: u8[..64] = [],
    hit: bool = false,
    fwd: u8[..32] = [],
    fwd_status: i32 = 0,
    ttl: i64 = 0,
    stored: bool = false,
    collapsed: bool = false,
    key: u8[..128] = [],
    detail: u8[..128] = [],
}

// ---- 2. RFC 9209 Proxy-Status Model -----------------------------------------

struct ProxyStatusEntry {
    proxy_name: u8[..64] = [],
    error_type: u8[..64] = [],
    next_hop: u8[..64] = [],
    details: u8[..256] = [],
    received_status: i32 = 0,
}

// ---- 3. Diagnostics Parser Helpers ------------------------------------------

fn skip_status_list_delims(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    let trimmed = core::trim_start_bytes(rem, " \t,");
    idx += rem.len - trimmed.len;
}

fn skip_status_param_delims(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    let trimmed = core::trim_start_bytes(rem, "; \t");
    idx += rem.len - trimmed.len;
}

fn skip_lws_at(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    let trimmed = core::trim_lws_start(rem);
    idx += rem.len - trimmed.len;
}

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

fn read_quoted_status_val(raw: const u8[:], idx: i64&) -> const u8[:] {
    idx += 1; // skip opening quote
    let v_start = idx;
    let rel_quote = core::index_of_byte(raw[idx..], '"');
    if rel_quote >= 0 {
        let val = raw[v_start..idx + rel_quote];
        idx += rel_quote + 1; // skip closing quote
        return val;
    }
    let val = raw[v_start..];
    idx = raw.len;
    return val;
}

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
            param_val = read_quoted_status_val(raw, idx);
        } else {
            param_val = read_token_status_val(raw, idx);
        }
    }
    return param_name, param_val, true;
}

// ---- 4. RFC 9211 Cache-Status Parser and Formatter --------------------------

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

fn apply_cache_status_param(entry: CacheStatusEntry&, name: const u8[:], val: const u8[:]) {
    guard !apply_cache_status_flags(entry, name) else { return; }

    if core::eq_ascii_fold(name, "ttl") {
        let ttl_v, _ = core::parse_i64_dec(val);
        entry.ttl = ttl_v;
    } else if core::eq_ascii_fold(name, "fwd") {
        entry.fwd.clear();
        entry.fwd.append(val);
    } else if core::eq_ascii_fold(name, "fwd-status") {
        let fwd_v, _ = core::parse_i64_dec(val);
        entry.fwd_status = fwd_v as! i32;
    } else if core::eq_ascii_fold(name, "key") {
        entry.key.clear();
        entry.key.append(val);
    } else if core::eq_ascii_fold(name, "detail") {
        entry.detail.clear();
        entry.detail.append(val);
    }
}

fn parse_single_cache_status_entry(raw: const u8[:], idx: i64&, out_entry: CacheStatusEntry&) -> bool {
    skip_status_list_delims(raw, idx);
    guard idx < raw.len else { return false; }

    out_entry = CacheStatusEntry { .. };
    let name = read_status_target_name(raw, idx);
    out_entry.cache_name.append(name);

    while idx < raw.len && raw[idx] != ',' {
        let p_name, p_val, ok = read_status_param(raw, idx);
        guard ok else { break; }
        apply_cache_status_param(out_entry, p_name, p_val);
    }
    return true;
}

// Parses a `Cache-Status: OriginCache; hit; ttl=120; key="xyz"` header
fn parse_cache_status_header(
    raw: const u8[:],
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

// ---- 5. RFC 9209 Proxy-Status Parser and Formatter --------------------------

fn apply_proxy_status_param(entry: ProxyStatusEntry&, name: const u8[:], val: const u8[:]) {
    if core::eq_ascii_fold(name, "error") {
        entry.error_type.clear();
        entry.error_type.append(val);
    } else if core::eq_ascii_fold(name, "next-hop") {
        entry.next_hop.clear();
        entry.next_hop.append(val);
    } else if core::eq_ascii_fold(name, "details") {
        entry.details.clear();
        entry.details.append(val);
    } else if core::eq_ascii_fold(name, "received-status") {
        let rec_v, _ = core::parse_i64_dec(val);
        entry.received_status = rec_v as! i32;
    }
}

fn parse_single_proxy_status_entry(raw: const u8[:], idx: i64&, out_entry: ProxyStatusEntry&) -> bool {
    skip_status_list_delims(raw, idx);
    guard idx < raw.len else { return false; }

    out_entry = ProxyStatusEntry { .. };
    let name = read_status_target_name(raw, idx);
    out_entry.proxy_name.append(name);

    while idx < raw.len && raw[idx] != ',' {
        let p_name, p_val, ok = read_status_param(raw, idx);
        guard ok else { break; }
        apply_proxy_status_param(out_entry, p_name, p_val);
    }
    return true;
}

// Parses a `Proxy-Status: edge1; error=connection_refused; details="upstream tcp rst"` header
fn parse_proxy_status_header(
    raw: const u8[:],
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
