// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9211 (Cache-Status HTTP Response Header) and RFC 9209 (Proxy-Status HTTP Response Header).
// Provides standardized zero-heap diagnostic inspection and formatting for intermediary caches,
// proxies, CDN edge nodes, and next-hop failure reporting.
namespace wing;

import std;

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

// ---- 3. Helper Parsing Routines ---------------------------------------------

fn status_format_int<B>(out: B&, val: i64) {
    if val == 0 {
        out.push('0' as u8);
        return;
    }
    var v = val;
    var digits: u8[..32] = [];
    while v > 0 {
        let d = (v % 10) as u8;
        digits.push(('0' as u8) + d);
        v /= 10;
    }
    var i = digits.len;
    while i > 0 {
        i -= 1;
        out.push(digits[i]);
    }
}

fn status_parse_int(val: const u8[:]) -> i64 {
    var num: i64 = 0;
    var started = false;
    for b in val {
        if b >= '0' && b <= '9' {
            num = num * 10 + (b - '0');
            started = true;
        } else if started {
            break;
        }
    }
    return num;
}

// ---- 4. RFC 9211 Cache-Status Parser and Formatter --------------------------

// Parses a `Cache-Status: OriginCache; hit; ttl=120; key="xyz"` header
fn parse_cache_status_header(
    raw: const u8[:],
    out_entries: CacheStatusEntry[..8]&,
) -> i64 {
    out_entries.clear();
    var idx = 0;

    while idx < raw.len && out_entries.len < out_entries.cap {
        // Skip whitespace
        while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t' || raw[idx] == ',') {
            idx += 1;
        }
        guard idx < raw.len else { break; }

        var entry = CacheStatusEntry { .. };

        // Parse cache identifier (up to ';' or ',' or end)
        var name_start = idx;
        while idx < raw.len && raw[idx] != ';' && raw[idx] != ',' && raw[idx] != ' ' {
            idx += 1;
        }
        entry.cache_name.append(raw[name_start..idx]);

        // Parse parameters separated by ';'
        while idx < raw.len && raw[idx] != ',' {
            if raw[idx] == ';' || raw[idx] == ' ' || raw[idx] == '\t' {
                idx += 1;
                continue;
            }

            var p_name_start = idx;
            while idx < raw.len && raw[idx] != '=' && raw[idx] != ';' && raw[idx] != ',' && raw[idx] != ' ' {
                idx += 1;
            }
            let param_name = raw[p_name_start..idx];

            var has_eq = false;
            while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t') {
                idx += 1;
            }
            if idx < raw.len && raw[idx] == '=' {
                has_eq = true;
                idx += 1;
            }

            var param_val: const u8[:] = "";
            if has_eq {
                while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t') {
                    idx += 1;
                }
                var v_start = idx;
                if idx < raw.len && raw[idx] == '"' {
                    idx += 1;
                    v_start = idx;
                    while idx < raw.len && raw[idx] != '"' {
                        idx += 1;
                    }
                    param_val = raw[v_start..idx];
                    if idx < raw.len && raw[idx] == '"' { idx += 1; }
                } else {
                    while idx < raw.len && raw[idx] != ';' && raw[idx] != ',' && raw[idx] != ' ' {
                        idx += 1;
                    }
                    param_val = raw[v_start..idx];
                }
            }

            // Assign standard RFC 9211 parameters
            if eq_ascii_fold(param_name, "hit") {
                entry.hit = true;
            } else if eq_ascii_fold(param_name, "stored") {
                entry.stored = true;
            } else if eq_ascii_fold(param_name, "collapsed") {
                entry.collapsed = true;
            } else if eq_ascii_fold(param_name, "ttl") {
                entry.ttl = status_parse_int(param_val);
            } else if eq_ascii_fold(param_name, "fwd") {
                entry.fwd.clear();
                entry.fwd.append(param_val);
            } else if eq_ascii_fold(param_name, "fwd-status") {
                entry.fwd_status = status_parse_int(param_val) as! i32;
            } else if eq_ascii_fold(param_name, "key") {
                entry.key.clear();
                entry.key.append(param_val);
            } else if eq_ascii_fold(param_name, "detail") {
                entry.detail.clear();
                entry.detail.append(param_val);
            }
        }

        out_entries.push(entry);
    }

    return out_entries.len;
}

// Formats a CacheStatusEntry into an RFC 9211 header string
fn format_cache_status<B>(entry: const CacheStatusEntry&, out: B&) {
    out.append(entry.cache_name[..]);
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
        status_format_int(out, entry.ttl);
    }
    if entry.fwd.len > 0 {
        out.append("; fwd=");
        out.append(entry.fwd[..]);
    }
    if entry.fwd_status > 0 {
        out.append("; fwd-status=");
        status_format_int(out, entry.fwd_status as i64);
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

// ---- 5. RFC 9209 Proxy-Status Parser and Formatter --------------------------

// Parses a `Proxy-Status: edge1; error=connection_refused; details="upstream tcp rst"` header
fn parse_proxy_status_header(
    raw: const u8[:],
    out_entries: ProxyStatusEntry[..8]&,
) -> i64 {
    out_entries.clear();
    var idx = 0;

    while idx < raw.len && out_entries.len < out_entries.cap {
        while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t' || raw[idx] == ',') {
            idx += 1;
        }
        guard idx < raw.len else { break; }

        var entry = ProxyStatusEntry { .. };

        var name_start = idx;
        while idx < raw.len && raw[idx] != ';' && raw[idx] != ',' && raw[idx] != ' ' {
            idx += 1;
        }
        entry.proxy_name.append(raw[name_start..idx]);

        while idx < raw.len && raw[idx] != ',' {
            if raw[idx] == ';' || raw[idx] == ' ' || raw[idx] == '\t' {
                idx += 1;
                continue;
            }

            var p_name_start = idx;
            while idx < raw.len && raw[idx] != '=' && raw[idx] != ';' && raw[idx] != ',' && raw[idx] != ' ' {
                idx += 1;
            }
            let param_name = raw[p_name_start..idx];

            var has_eq = false;
            while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t') {
                idx += 1;
            }
            if idx < raw.len && raw[idx] == '=' {
                has_eq = true;
                idx += 1;
            }

            var param_val: const u8[:] = "";
            if has_eq {
                while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t') {
                    idx += 1;
                }
                var v_start = idx;
                if idx < raw.len && raw[idx] == '"' {
                    idx += 1;
                    v_start = idx;
                    while idx < raw.len && raw[idx] != '"' {
                        idx += 1;
                    }
                    param_val = raw[v_start..idx];
                    if idx < raw.len && raw[idx] == '"' { idx += 1; }
                } else {
                    while idx < raw.len && raw[idx] != ';' && raw[idx] != ',' && raw[idx] != ' ' {
                        idx += 1;
                    }
                    param_val = raw[v_start..idx];
                }
            }

            // Assign standard RFC 9209 parameters
            if eq_ascii_fold(param_name, "error") {
                entry.error_type.clear();
                entry.error_type.append(param_val);
            } else if eq_ascii_fold(param_name, "next-hop") {
                entry.next_hop.clear();
                entry.next_hop.append(param_val);
            } else if eq_ascii_fold(param_name, "details") {
                entry.details.clear();
                entry.details.append(param_val);
            } else if eq_ascii_fold(param_name, "received-status") {
                entry.received_status = status_parse_int(param_val) as! i32;
            }
        }

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
        status_format_int(out, entry.received_status as i64);
    }
}
