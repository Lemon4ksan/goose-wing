// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal reverse-proxy header filtering, Via loop detection, Forwarded metadata, and rewriting helpers.
namespace proxy_internal;

import std;
import core;
import http.headers;
import http.forwarded;
import wire.h1;
import .reverse_proxy;

// ---- Reverse Proxy Header, Via & Forwarded Metadata Helpers ---------------

fn format_chained_xff(buf: u8[..1024]&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    var committed = false;
    defer if !committed { buf.clear(); };
    guard buf.try_set(existing_xff) else { return false; }
    guard buf.try_append(", ") else { return false; }
    guard buf.try_append(client_ip) else { return false; }
    committed = true;
    return true;
}

fn append_chained_xff(
    out_headers:  http::HeaderMap&,
    out_arena:    http::OverflowArena&,
    existing_xff: const u8[:],
    client_ip:    const u8[:],
) -> bool {
    var chained: u8[..1024] = [];
    guard format_chained_xff(chained, existing_xff, client_ip) else { return false; }
    return http::append_header_spill(out_headers, out_arena, "X-Forwarded-For", chained[..]);
}

fn append_forwarded_for(
    out_headers:  http::HeaderMap&,
    out_arena:    http::OverflowArena&,
    existing_xff: const u8[:],
    client_ip:    const u8[:],
) -> bool {
    guard client_ip.len > 0 else { return true; }
    if existing_xff.len > 0 {
        return append_chained_xff(out_headers, out_arena, existing_xff, client_ip);
    }
    return http::append_header_spill(out_headers, out_arena, "X-Forwarded-For", client_ip);
}

inline fn is_standard_h2_request_pseudo(name: const u8[:]) -> bool {
    return name == ":method" ||
        name == ":scheme" ||
        name == ":authority" ||
        name == ":path" ||
        name == ":protocol";
}

fn entries_have_header_token(
    entries:    const http::HeaderEntry[:],
    stack_raw:  const u8[:],
    spill_raw:  const u8[:],
    hdr_name:   const u8[:],
    target_tok: const u8[:],
) -> bool {
    for &entry in entries {
        guard http::resolve_entry_name_buf(stack_raw, spill_raw, entry).eq_ascii_fold(hdr_name) else {
            continue;
        }
        let val = http::resolve_entry_value_buf(stack_raw, spill_raw, entry);
        var tok = core::make_byte_tokenizer(val, ',');
        loop {
            let raw_tok, ok = core::token_next(tok);
            guard ok else { break; }
            if raw_tok.trim_lws().eq_ascii_fold(target_tok) {
                return true;
            }
        }
    }
    return false;
}

inline fn header_map_has_token_slices(
    headers:       const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    hdr_name:      const u8[:],
    target_tok:    const u8[:],
) -> bool {
    return entries_have_header_token(headers.entries[..], headers.raw_buf[..], spill_raw, hdr_name, target_tok) ||
        entries_have_header_token(spill_entries, headers.raw_buf[..], spill_raw, hdr_name, target_tok);
}

// Validates `sec-websocket-key` (base64-encoded 16-byte nonce) and `sec-websocket-version` ("13") entries.
//
// Example:
//   entries = [Sec-WebSocket-Key: ..., Sec-WebSocket-Version: 13]
//   returns: key_count = 1, ver_count = 1, key_valid = true, ver_valid = true
fn scan_ws_entries(
    entries:   const http::HeaderEntry[:],
    stack_raw: const u8[:],
    spill_raw: const u8[:],
    key_count: i64&,
    ver_count: i64&,
    key_valid: bool&,
    ver_valid: bool&,
) {
    for &entry in entries {
        let name = http::resolve_entry_name_buf(stack_raw, spill_raw, entry);
        if name.eq_ascii_fold("sec-websocket-key") {
            key_count = core::add_sat_i64(key_count, 1);
            let ws_key = http::resolve_entry_value_buf(stack_raw, spill_raw, entry).trim_lws();
            var decoded_key: u8[..24] = [];
            key_valid = ws_key.len == 24 &&
                core::base64_decode(ws_key, decoded_key) &&
                decoded_key.len == 16;
        } else if name.eq_ascii_fold("sec-websocket-version") {
            ver_count = core::add_sat_i64(ver_count, 1);
            ver_valid = http::resolve_entry_value_buf(stack_raw, spill_raw, entry).trim_lws() == "13";
        }
    }
}

// Validates RFC 6455 Section 4.1 WebSocket upgrade headers under `UpgradePolicy.AllowWebSocket`.
fn is_valid_websocket_upgrade_headers_slices(
    in_headers:    const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    config:        const proxy::Config&,
    method:        const u8[:] = "GET",
) -> bool {
    guard config.upgrade_policy == proxy::UpgradePolicy.AllowWebSocket else { return false; }
    guard method.eq_ascii_fold("GET") && !config.http_version[..].eq_ascii_fold("HTTP/1.0") else {
        return false;
    }
    let has_conn_upg = http::entries_have_connection_token(
        in_headers.entries[..], in_headers.raw_buf[..], spill_raw, "upgrade",
    ) || http::entries_have_connection_token(
        spill_entries, in_headers.raw_buf[..], spill_raw, "upgrade",
    );
    guard has_conn_upg else { return false; }
    guard header_map_has_token_slices(in_headers, spill_entries, spill_raw, "upgrade", "websocket") else {
        return false;
    }

    var key_count: i64 = 0;
    var ver_count: i64 = 0;
    var key_valid = false;
    var ver_valid = false;
    scan_ws_entries(
        in_headers.entries[..], in_headers.raw_buf[..], spill_raw, key_count, ver_count, key_valid, ver_valid,
    );
    scan_ws_entries(
        spill_entries, in_headers.raw_buf[..], spill_raw, key_count, ver_count, key_valid, ver_valid,
    );
    return key_count == 1 && ver_count == 1 && key_valid && ver_valid;
}

inline fn should_forward_ws_upgrade_field(
    name:               const u8[:],
    config:             const proxy::Config&,
    ws_upgrade_allowed: bool,
) -> bool {
    guard config.upgrade_policy == proxy::UpgradePolicy.AllowWebSocket && ws_upgrade_allowed else {
        return false;
    }
    if name.starts_with_fold("sec-websocket-") {
        return true;
    }
    return !config.strip_hop_by_hop;
}

fn should_forward_header_slices(
    name:               const u8[:],
    val:                const u8[:],
    in_headers:         const http::HeaderMap&,
    spill_entries:      const http::HeaderEntry[:],
    spill_raw:          const u8[:],
    config:             const proxy::Config&,
    ws_upgrade_allowed: bool,
) -> bool {
    if name.eq_ascii_fold("host") {
        return config.preserve_host;
    }
    if proxy::is_forwarded_metadata_header(name) {
        return false;
    }
    if name.eq_ascii_fold("max-forwards") {
        return true;
    }
    // RFC 9112 Section 6.3: Message Body Length - remove Content-Length if Transfer-Encoding is present.
    if name.eq_ascii_fold("content-length") &&
       http::has_header_slices(in_headers, spill_entries, spill_raw, "transfer-encoding") {
        return false;
    }
    // RFC 9110 Section 7.8: Strip Upgrade and Sec-WebSocket-* under Strip, or under AllowWebSocket unless valid.
    if name.eq_ascii_fold("upgrade") || name.starts_with_fold("sec-websocket-") {
        return should_forward_ws_upgrade_field(name, config, ws_upgrade_allowed);
    }
    guard config.strip_hop_by_hop else { return true; }

    if http::is_hop_by_hop_header_name(name) {
        // RFC 9110 Section 7.6.1: Connection - TE may only be forwarded if the value is trailers.
        return name.eq_ascii_fold("te") && val.trim_lws().eq_ascii_fold("trailers");
    }
    if header_map_has_token_slices(in_headers, spill_entries, spill_raw, "connection", name)
        && !http::is_protected_end_to_end_header(name) {
        return false;
    }

    return true;
}

inline fn check_cl_match(val: const u8[:], first_found: bool&, target_val: i64&) -> bool {
    let parsed_cl, ok_cl = http::validate_content_length_value(val);
    guard ok_cl else { return false; }
    if !first_found {
        target_val = parsed_cl;
        first_found = true;
        return true;
    }
    return parsed_cl == target_val;
}

inline fn format_canonical_content_length(val: const u8[:], out_buf: u8[..24]&) -> bool {
    let parsed_cl, ok_cl = http::validate_content_length_value(val);
    guard ok_cl else { return false; }
    out_buf.clear();
    parsed_cl.format_i64_dec(out_buf);
    return true;
}

inline fn append_canonical_content_length(
    out_headers: http::HeaderMap&,
    name:        const u8[:],
    val:         const u8[:],
) -> bool {
    var cl_buf: u8[..24] = [];
    guard format_canonical_content_length(val, cl_buf) else { return false; }
    return http::append_header(out_headers, name, cl_buf[..]);
}

inline fn append_canonical_content_length_spill(
    out_headers: http::HeaderMap&,
    out_arena:   http::OverflowArena&,
    name:        const u8[:],
    val:         const u8[:],
) -> bool {
    var cl_buf: u8[..24] = [];
    guard format_canonical_content_length(val, cl_buf) else { return false; }
    return http::append_header_spill(out_headers, out_arena, name, cl_buf[..]);
}

fn check_framing_entries(
    entries:        const http::HeaderEntry[:],
    stack_raw:      const u8[:],
    spill_raw:      const u8[:],
    first_cl_found: bool&,
    first_cl_val:   i64&,
    has_te:         bool&,
) -> bool {
    for &entry in entries {
        let name = http::resolve_entry_name_buf(stack_raw, spill_raw, entry);
        let val = http::resolve_entry_value_buf(stack_raw, spill_raw, entry);

        if name.eq_ascii_fold("content-length") {
            guard check_cl_match(val, first_cl_found, first_cl_val) else { return false; }
        }
        if name.eq_ascii_fold("transfer-encoding") {
            guard !has_te && http::validate_transfer_encoding_value(val) else { return false; }
            has_te = true;
        }
    }
    return true;
}

fn has_consistent_framing_headers_slices(
    in_headers:    const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
) -> bool {
    let bad_cl = http::entries_have_connection_token(
        in_headers.entries[..], in_headers.raw_buf[..], spill_raw, "content-length",
    ) || http::entries_have_connection_token(spill_entries, in_headers.raw_buf[..], spill_raw, "content-length");
    let bad_te = http::entries_have_connection_token(
        in_headers.entries[..], in_headers.raw_buf[..], spill_raw, "transfer-encoding",
    ) || http::entries_have_connection_token(spill_entries, in_headers.raw_buf[..], spill_raw, "transfer-encoding");
    let bad_host = http::entries_have_connection_token(
        in_headers.entries[..], in_headers.raw_buf[..], spill_raw, "host",
    ) || http::entries_have_connection_token(spill_entries, in_headers.raw_buf[..], spill_raw, "host");
    let bad_mf = http::entries_have_connection_token(
        in_headers.entries[..], in_headers.raw_buf[..], spill_raw, "max-forwards",
    ) || http::entries_have_connection_token(spill_entries, in_headers.raw_buf[..], spill_raw, "max-forwards");
    // RFC 9110 Section 7.6.1: Connection - MUST NOT send connection option for end-to-end framing or routing fields.
    guard !bad_cl && !bad_te && !bad_host && !bad_mf else { return false; }

    var first_cl_found = false;
    var first_cl_val: i64 = 0;
    var has_te = false;
    guard check_framing_entries(
        in_headers.entries[..], in_headers.raw_buf[..], spill_raw, first_cl_found, first_cl_val, has_te,
    ) else { return false; }
    guard check_framing_entries(
        spill_entries, in_headers.raw_buf[..], spill_raw, first_cl_found, first_cl_val, has_te,
    ) else { return false; }
    // RFC 9112 Section 6.3: Message Body Length - reject messages with both Transfer-Encoding and Content-Length.
    guard !(first_cl_found && has_te) else { return false; }
    return true;
}

// Validates framing header integrity before forwarding.
fn has_consistent_framing_headers(in_headers: const http::HeaderMap&) -> bool {
    return has_consistent_framing_headers_slices(in_headers, in_headers.entries[..0], "");
}

fn copy_filtered_entries_spill(
    entries:       const http::HeaderEntry[:],
    in_headers:    const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    out_headers:   http::HeaderMap&,
    out_arena:     http::OverflowArena&,
    config:        const proxy::Config&,
    allow_ws:      bool,
) -> bool {
    for &entry in entries {
        let name = http::resolve_entry_name_buf(in_headers.raw_buf[..], spill_raw, entry);
        let val = http::resolve_entry_value_buf(in_headers.raw_buf[..], spill_raw, entry);

        if is_standard_h2_request_pseudo(name) {
            continue;
        }
        // RFC 9113 Section 8.3: HTTP Control Data - reject non-standard or unstripped pseudo-headers.
        guard http::is_valid_header_name(name) && http::is_valid_header_value(val) else { return false; }
        if !should_forward_header_slices(name, val, in_headers, spill_entries, spill_raw, config, allow_ws) {
            continue;
        }
        if name.eq_ascii_fold("content-length") {
            guard http::has_header_spill(out_headers, out_arena, "content-length") ||
                append_canonical_content_length_spill(out_headers, out_arena, name, val) else {
                return false;
            }
            continue;
        }
        guard http::append_header_spill(
            out_headers, out_arena, name, val, entry.flags & http::HEADER_FLAG_SENSITIVE,
        ) else { return false; }
    }
    return true;
}

fn copy_filtered_headers_spill(
    in_headers:    const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    out_headers:   http::HeaderMap&,
    out_arena:     http::OverflowArena&,
    config:        const proxy::Config&,
    method:        const u8[:] = "GET",
) -> bool {
    let allow_ws = is_valid_websocket_upgrade_headers_slices(
        in_headers, spill_entries, spill_raw, config, method,
    );
    guard copy_filtered_entries_spill(
        in_headers.entries[..], in_headers, spill_entries, spill_raw, out_headers, out_arena, config, allow_ws,
    ) else { return false; }
    if spill_entries.len > 0 {
        return copy_filtered_entries_spill(
            spill_entries, in_headers, spill_entries, spill_raw, out_headers, out_arena, config, allow_ws,
        );
    }
    return true;
}

fn format_via(buf: u8[..64]&, pseudonym: const u8[:], http_version: const u8[:]) -> bool {
    let ver_suffix, has_http = http_version.strip_prefix("HTTP/");
    let ver_str = if has_http && ver_suffix.len > 0 {
        ver_suffix
    } else if http_version.len > 0 {
        http_version
    } else {
        "1.1"
    };
    var committed = false;
    defer if !committed { buf.clear(); };
    guard buf.try_set(ver_str) else { return false; }
    guard buf.try_append(" ") else { return false; }
    guard buf.try_append(pseudonym) else { return false; }
    committed = true;
    return true;
}

// Extracts the `received-by` pseudonym or host[:port] token from a single RFC 9110 Via hop.
//
// Example:
//   hop = "1.1 wing-gw (Goose)"
//   returns: "wing-gw"
inline fn extract_via_received_by(hop: const u8[:]) -> const u8[:] {
    let trimmed = hop.trim_lws();
    var idx: i64 = 0;
    while idx < trimmed.len && !core::is_lws(trimmed[idx]) {
        idx = core::add_sat_i64(idx, 1);
    }
    let after_proto = trimmed[idx..].trim_lws_start();
    var end_idx: i64 = 0;
    while end_idx < after_proto.len && !core::is_lws(after_proto[end_idx]) && after_proto[end_idx] != '(' {
        end_idx = core::add_sat_i64(end_idx, 1);
    }
    return after_proto[..end_idx];
}

inline fn strip_via_port(received_by: const u8[:]) -> const u8[:] {
    guard received_by.len > 0 else { return ""; }
    if received_by[0] == '[' {
        let close_idx = received_by.index_of_byte(']');
        if close_idx > 0 {
            return received_by[..core::add_sat_i64(close_idx, 1)];
        }
        return received_by;
    }
    let col = received_by.last_index_of_byte(':');
    return if col > 0 { received_by[..col] } else { received_by };
}

inline fn matches_via_pseudonym(hop: const u8[:], pseudonym: const u8[:]) -> bool {
    let received_by = extract_via_received_by(hop);
    guard received_by.len > 0 else { return false; }
    if received_by.eq_ascii_fold(pseudonym) {
        return true;
    }
    return !pseudonym.contains_byte(':') && strip_via_port(received_by).eq_ascii_fold(pseudonym);
}

// Finds the next unparenthesized comma in an RFC 9110 Section 7.6.3 `Via` header value.
//
// Example:
//   s = "1.1 edge (gw, 1.1 wing), 1.1 backend"
//   returns: 23 (index of the comma after ')')
fn find_next_via_comma(s: const u8[:]) -> i64 {
    var i:           i64 = 0;
    var paren_depth: i64 = 0;
    while i < s.len {
        let b = s[i];
        if paren_depth > 0 && b == '\\' {
            i = core::add_sat_i64(i, 2);
            continue;
        }
        if b == '(' {
            paren_depth = core::add_sat_i64(paren_depth, 1);
        } else if b == ')' && paren_depth > 0 {
            paren_depth = core::sub_sat_i64(paren_depth, 1);
        } else if b == ',' && paren_depth == 0 {
            return i;
        }
        i = core::add_sat_i64(i, 1);
    }
    return s.len;
}

fn has_via_pseudonym_loop(combined_via: const u8[:], pseudonym: const u8[:]) -> bool {
    guard combined_via.len > 0 && pseudonym.len > 0 else { return false; }
    var cursor: i64 = 0;
    while cursor < combined_via.len {
        let rel_comma = find_next_via_comma(combined_via[cursor..]);
        let comma_idx = core::add_sat_i64(cursor, rel_comma);
        if matches_via_pseudonym(combined_via[cursor..comma_idx], pseudonym) {
            return true;
        }
        if comma_idx >= combined_via.len {
            break;
        }
        cursor = core::add_sat_i64(comma_idx, 1);
    }
    return false;
}

fn inject_via_header_spill(
    out_headers:   http::HeaderMap&,
    out_arena:     http::OverflowArena&,
    in_headers:    const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    pseudonym:     const u8[:],
    http_version:  const u8[:],
) -> bool {
    var combined: u8[..1024] = [];
    let has_existing = http::has_header_slices(in_headers, spill_entries, spill_raw, "Via");
    if has_existing {
        guard http::get_combined_slices(in_headers, spill_entries, spill_raw, "Via", combined, 950) else {
            return false;
        }
        // RFC 9110 Section 7.6.3: Via - detect forwarding loops when own pseudonym is already present.
        guard !has_via_pseudonym_loop(combined[..], pseudonym) else { return false; }
    }
    guard pseudonym.len > 0 else {
        guard combined.len > 0 else { return true; }
        return http::append_header_spill(out_headers, out_arena, "Via", combined[..]);
    }
    var via_buf: u8[..64] = [];
    guard format_via(via_buf, pseudonym, http_version) else { return false; }
    guard combined.len > 0 else {
        return http::append_header_spill(out_headers, out_arena, "Via", via_buf[..]);
    }
    guard combined.try_append(", ") && combined.try_append(via_buf[..]) else { return false; }
    return http::append_header_spill(out_headers, out_arena, "Via", combined[..]);
}

fn append_forwarded_metadata_xff_spill(
    out_headers:        http::HeaderMap&,
    out_arena:          http::OverflowArena&,
    in_headers:         const http::HeaderMap&,
    spill_entries:      const http::HeaderEntry[:],
    spill_raw:          const u8[:],
    client_ip:          const u8[:],
    trust_incoming_xff: bool,
) -> bool {
    guard trust_incoming_xff && http::has_header_slices(in_headers, spill_entries, spill_raw, "X-Forwarded-For") else {
        return append_forwarded_for(out_headers, out_arena, "", client_ip);
    }
    var combined_buf: u8[..1024] = [];
    guard http::get_combined_slices(
        in_headers, spill_entries, spill_raw, "X-Forwarded-For", combined_buf, 1024,
    ) else { return false; }
    return append_forwarded_for(out_headers, out_arena, combined_buf[..], client_ip);
}

inline fn populate_forwarded_for_node(elem: http::ForwardedElement&, client_ip: const u8[:]) -> bool {
    // RFC 7239 Section 6: Node Identifiers - IPv6 addresses MUST be enclosed in square brackets.
    if client_ip.contains_byte(':') && !core::starts_with(client_ip, "[") {
        return elem.for_node.try_set("[") &&
            elem.for_node.try_append(client_ip) &&
            elem.for_node.try_push(']');
    }
    return elem.for_node.try_set(client_ip);
}

fn append_rfc7239_forwarded_spill(
    out_headers: http::HeaderMap&,
    out_arena:   http::OverflowArena&,
    client_ip:   const u8[:],
    orig_host:   const u8[:],
    proto:       const u8[:],
    config:      const proxy::Config&,
) -> bool {
    guard config.emit_rfc7239_forwarded else { return true; }
    var elem = http::ForwardedElement { .. };
    guard elem.by.try_set(config.via_pseudonym[..]) else { return false; }
    guard populate_forwarded_for_node(elem, client_ip) else { return false; }
    guard elem.host.try_set(orig_host) else { return false; }
    guard elem.proto.try_set(proto) else { return false; }
    var fwd_buf: u8[..512] = [];
    http::format_forwarded_element(elem, fwd_buf);
    guard fwd_buf.len > 0 else { return false; }
    return http::append_header_spill(out_headers, out_arena, rfc::HEADER_FORWARDED, fwd_buf[..]);
}

fn inject_forwarded_metadata_spill(
    out_headers:   http::HeaderMap&,
    out_arena:     http::OverflowArena&,
    in_headers:    const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    client_ip:     const u8[:],
    proto:         const u8[:],
    config:        const proxy::Config&,
) -> bool {
    guard append_forwarded_metadata_xff_spill(
        out_headers,
        out_arena,
        in_headers,
        spill_entries,
        spill_raw,
        client_ip,
        config.trust_incoming_xff,
    ) else { return false; }

    let orig_host = http::get_header_slices(in_headers, spill_entries, spill_raw, "Host");
    if proto.len > 0 {
        guard http::append_header_spill(out_headers, out_arena, "X-Forwarded-Proto", proto) else { return false; }
    }
    let existing_xf_host = http::get_header_slices(in_headers, spill_entries, spill_raw, "X-Forwarded-Host");
    if config.trust_incoming_xff && existing_xf_host.len > 0 {
        guard http::append_header_spill(out_headers, out_arena, "X-Forwarded-Host", existing_xf_host) else {
            return false;
        }
    } else if orig_host.len > 0 && !config.preserve_host {
        guard http::append_header_spill(out_headers, out_arena, "X-Forwarded-Host", orig_host) else { return false; }
    }
    return append_rfc7239_forwarded_spill(out_headers, out_arena, client_ip, orig_host, proto, config);
}

fn ensure_forwarded_head_framing_spill(
    in_headers:      const http::HeaderMap&,
    spill_entries:   const http::HeaderEntry[:],
    spill_raw:       const u8[:],
    forward_headers: http::HeaderMap&,
    forward_arena:   http::OverflowArena&,
    method:          const u8[:],
    http_version:    const u8[:],
) -> bool {
    let has_cl = http::has_header_spill(forward_headers, forward_arena, "content-length");
    if http::has_header_slices(in_headers, spill_entries, spill_raw, "transfer-encoding") {
        guard !has_cl && http_version != "HTTP/1.0" else { return false; }
        if !http::has_header_spill(forward_headers, forward_arena, "transfer-encoding") {
            let te_val = http::get_header_slices(in_headers, spill_entries, spill_raw, "transfer-encoding").trim_lws();
            guard te_val.len > 0 else { return false; }
            return http::append_header_spill(forward_headers, forward_arena, "Transfer-Encoding", te_val);
        }
        return true;
    }
    guard !has_cl else { return true; }
    if method == "POST" || method == "PUT" || method == "PATCH" {
        return http::append_header_spill(forward_headers, forward_arena, "Content-Length", "0");
    }
    return true;
}

fn ensure_forwarded_body_framing_spill(
    forward_headers: http::HeaderMap&,
    forward_arena:   http::OverflowArena&,
    body:            const u8[:],
    method:          const u8[:] = "",
) -> bool {
    let has_cl = http::has_header_spill(forward_headers, forward_arena, "content-length");
    let has_te = http::has_header_spill(forward_headers, forward_arena, "transfer-encoding");
    guard !(has_cl && has_te) else { return false; }
    if has_cl {
        let parsed_cl, ok_cl = http::validate_content_length_value(
            http::get_header_spill(forward_headers, forward_arena, "content-length"),
        );
        guard ok_cl else { return false; }
        return parsed_cl == body.len;
    }
    if body.len == 0 {
        if method == "POST" || method == "PUT" || method == "PATCH" {
            return http::append_header_spill(forward_headers, forward_arena, "Content-Length", "0");
        }
        return true;
    }
    var cl_buf: u8[..32] = [];
    body.len.format_i64_dec(cl_buf);
    return http::append_header_spill(forward_headers, forward_arena, "Content-Length", cl_buf[..]);
}

// Enforces RFC 9110 Section 7.6.2 Max-Forwards hop decrement and zero-hop halt on TRACE and OPTIONS.
fn apply_max_forwards_policy_spill(
    method:          const u8[:],
    forward_headers: http::HeaderMap&,
    forward_arena:   http::OverflowArena&,
) -> bool {
    guard method.eq_ascii_fold("TRACE") || method.eq_ascii_fold("OPTIONS") else {
        return true;
    }
    var found = false;
    var hops: u64 = 0;
    let total = http::header_count_spill(forward_headers, forward_arena);
    for i in total {
        let entry, ok_e = http::header_entry_at_spill(forward_headers, forward_arena, i);
        guard ok_e else { break; }
        guard http::entry_name_spill(forward_headers, forward_arena, entry).eq_ascii_fold("max-forwards") else {
            continue;
        }
        let val = http::entry_value_spill(forward_headers, forward_arena, entry).trim_lws();
        let parsed, ok = val.parse_u64_dec();
        guard ok else { return false; }
        if !found {
            hops = parsed;
            found = true;
        } else {
            guard parsed == hops else { return false; }
        }
    }
    guard found else { return true; }
    // RFC 9110 Section 7.6.2: Max-Forwards - MUST NOT forward the request when Max-Forwards is zero.
    guard hops > 0 else { return false; }
    var mf_buf: u8[..24] = [];
    let next_hops = core::sub_sat_u64(hops, 1);
    next_hops.format_u64_dec(mf_buf);
    return http::set_or_replace_spill(forward_headers, forward_arena, "Max-Forwards", mf_buf[..]);
}

inline fn is_valid_accel_redirect_target(target: const u8[:]) -> bool {
    guard target.len > 0 && target[0] == '/' && !core::starts_with(target, "//") else {
        return false;
    }
    return wire::is_valid_h1_request_target(target);
}

inline fn matches_backend_url_prefix(url_val: const u8[:], backend_url_prefix: const u8[:]) -> bool {
    guard backend_url_prefix.len > 0 && url_val.len >= backend_url_prefix.len else {
        return false;
    }
    let scheme_idx = core::find(backend_url_prefix, "://");
    if scheme_idx >= 0 {
        let auth_start = core::add_sat_i64(scheme_idx, 3);
        guard backend_url_prefix.len > auth_start else { return false; }
        let slash_rel = backend_url_prefix[auth_start..].index_of_byte('/');
        if slash_rel >= 0 {
            let origin_len = core::add_sat_i64(auth_start, slash_rel);
            let origin_ok = url_val[..origin_len].eq_ascii_fold(backend_url_prefix[..origin_len]);
            let path_ok = core::starts_with(url_val[origin_len..], backend_url_prefix[origin_len..]);
            guard origin_ok && path_ok else { return false; }
        } else {
            guard url_val[..backend_url_prefix.len].eq_ascii_fold(backend_url_prefix) else {
                return false;
            }
        }
    } else {
        guard core::starts_with(url_val, backend_url_prefix) else { return false; }
    }

    if core::ends_with(backend_url_prefix, "/") {
        return true;
    }
    let rem = url_val[backend_url_prefix.len..];
    return rem.len == 0 || rem[0] == '/' || rem[0] == '?' || rem[0] == '#';
}

fn filter_single_upstream_response_header<B>(
    in_headers:          const http::HeaderMap&,
    entry_idx:           i64,
    backend_url_prefix:  const u8[:],
    public_url_prefix:   const u8[:],
    out_headers:         http::HeaderMap&,
    out_location_buf:    B&,
    accel:               proxy::UpstreamAccelControl&,
    first_loc_entry_idx: i64&,
) -> bool {
    let entry .= in_headers.entries[entry_idx];
    let name = http::entry_name(in_headers, entry);
    let val = http::entry_value(in_headers, entry);
    if name == ":status" {
        return true;
    }
    // RFC 9110 Section 5.1: Field Names - reject malformed or unstripped pseudo-headers in responses.
    guard http::is_valid_header_name(name) && http::is_valid_header_value(val) else { return false; }

    if name.starts_with_fold("x-accel-") {
        return proxy::parse_x_accel_control_header(name, val, accel);
    }
    if http::is_hop_by_hop_header_name(name) {
        return true;
    }
    if http::is_token_in_connection_header_map(in_headers, name)
        && !http::is_protected_end_to_end_header(name) {
        return true;
    }
    if name.eq_ascii_fold("content-length") {
        if !http::has_header(out_headers, "content-length") {
            return append_canonical_content_length(out_headers, name, val);
        }
        return true;
    }
    if name.eq_ascii_fold("location") {
        // RFC 9110 Section 10.2.2: Location - reject conflicting duplicate Location header fields.
        let clean_loc = val.trim_lws();
        if first_loc_entry_idx >= 0 {
            let prev_loc = http::entry_value(in_headers, in_headers.entries[first_loc_entry_idx]).trim_lws();
            return clean_loc == prev_loc;
        }
        first_loc_entry_idx = entry_idx;
        let rewritten, ok_loc = proxy::try_rewrite_upstream_url(
            clean_loc, backend_url_prefix, public_url_prefix, out_location_buf,
        );
        guard ok_loc else { return false; }
        return http::append_header(out_headers, name, rewritten);
    }
    if name.eq_ascii_fold("content-location") {
        // RFC 9110 Section 8.7: Content-Location - rewrite matching internal backend origin prefix.
        var cloc_buf: u8[..512] = [];
        let rewritten_cloc, ok_cloc = proxy::try_rewrite_upstream_url(
            val.trim_lws(), backend_url_prefix, public_url_prefix, cloc_buf,
        );
        guard ok_cloc else { return false; }
        return http::append_header(out_headers, name, rewritten_cloc);
    }
    return http::append_header(out_headers, name, val);
}
