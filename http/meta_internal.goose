// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/meta_internal.goose).
namespace http_internal;

import std;
import core;
import http.forwarded;
import http.headers;
import http.mime;
import http.priority;
import http.response;
import http.security_txt;
import http.server_timing;
import http.sfv;
import http.status_diagnostics;
import http.trace;
import rfc.http;

// ---- http/forwarded.goose internal helpers ----

// Appends an RFC 7239 node identifier with quotes if it contains IPv6 or non-token characters.
fn append_quoted_node<B>(val: const u8[:], out: B&) {
    let needs_quotes = val.contains_byte(':') || val.contains_byte('[') || val.contains_byte(']');
    if needs_quotes && (val.len == 0 || val[0] != '"') {
        out.push('"');
        out.append(val);
        out.push('"');
    } else {
        out.append(val);
    }
}

// Validates an RFC 7239 Section 5.4 URI scheme (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`).
fn is_valid_forwarded_proto(val: const u8[:]) -> bool {
    guard val.len > 0 && core::is_ascii_alpha(val[0]) else { return false; }
    for i in 1..val.len {
        let b = val[i];
        guard core::is_ascii_alpha(b) || core::is_ascii_digit(b) || b == '+' || b == '-' || b == '.' else {
            return false;
        }
    }
    return true;
}

fn is_valid_obf_token(val: const u8[:]) -> bool {
    guard val.len >= 2 && val[0] == '_' else { return false; }
    for i in 1..val.len {
        let b = val[i];
        guard core::is_ascii_alpha(b) || core::is_ascii_digit(b) || b == '.' || b == '_' || b == '-' else {
            return false;
        }
    }
    return true;
}

fn is_valid_decimal_port(port: const u8[:]) -> bool {
    guard port.len >= 1 && port.len <= 5 else { return false; }
    for b in port {
        guard core::is_ascii_digit(b) else { return false; }
    }
    let p_val, ok = port.parse_u32_dec();
    return ok && p_val <= 65535;
}

fn is_valid_node_port(port: const u8[:]) -> bool {
    guard port.len > 0 else { return false; }
    if port[0] == '_' {
        return is_valid_obf_token(port);
    }
    return is_valid_decimal_port(port);
}

fn is_valid_ipv4_octet(oct: const u8[:]) -> bool {
    guard oct.len >= 1 && oct.len <= 3 else { return false; }
    for b in oct {
        guard core::is_ascii_digit(b) else { return false; }
    }
    let v, ok = oct.parse_u32_dec();
    return ok && v <= 255;
}

fn is_valid_ipv4_nodename(s: const u8[:]) -> bool {
    let o1, r1, ok1 = s.split_once_byte('.');
    guard ok1 && is_valid_ipv4_octet(o1) else { return false; }
    let o2, r2, ok2 = r1.split_once_byte('.');
    guard ok2 && is_valid_ipv4_octet(o2) else { return false; }
    let o3, o4, ok3 = r2.split_once_byte('.');
    return ok3 && is_valid_ipv4_octet(o3) && is_valid_ipv4_octet(o4);
}

fn is_valid_ipv6_nodename(inner: const u8[:]) -> bool {
    guard inner.len >= 2 && inner.len <= 45 && inner.contains_byte(':') else { return false; }
    for b in inner {
        guard core::is_ascii_hexdigit(b) || b == ':' || b == '.' else { return false; }
    }
    return true;
}

// Validates an RFC 7239 Section 6 node (`nodename [ ":" node-port ]`).
fn is_valid_forwarded_node(val: const u8[:]) -> bool {
    guard val.len > 0 else { return false; }
    if val[0] == '[' {
        let inner, after, has_close = val[1..].split_once_byte(']');
        guard has_close && is_valid_ipv6_nodename(inner) else { return false; }
        if after.len == 0 {
            return true;
        }
        return after[0] == ':' && is_valid_node_port(after[1..]);
    }
    let host_part, port_part, has_colon = val.split_once_byte(':');
    if has_colon {
        guard is_valid_node_port(port_part) else { return false; }
    }
    return host_part == "unknown" || is_valid_obf_token(host_part) || is_valid_ipv4_nodename(host_part);
}

fn is_valid_reg_name_byte(b: u8) -> bool {
    return core::is_uri_unreserved(b) ||
           b == '!' || b == '$' || b == '&' || b == '\'' || b == '(' || b == ')' ||
           b == '*' || b == '+' || b == ',' || b == ';' || b == '=' || b == '%';
}

// Validates an RFC 7239 Section 5.3 host (`uri-host [ ":" port ]`).
fn is_valid_forwarded_host(val: const u8[:]) -> bool {
    guard val.len > 0 else { return false; }
    if val[0] == '[' {
        let inner, after, has_close = val[1..].split_once_byte(']');
        guard has_close && is_valid_ipv6_nodename(inner) else { return false; }
        if after.len == 0 {
            return true;
        }
        return after[0] == ':' && is_valid_decimal_port(after[1..]);
    }
    let host_part, port_part, has_colon = val.split_once_byte(':');
    guard host_part.len > 0 else { return false; }
    for b in host_part {
        guard is_valid_reg_name_byte(b) else { return false; }
    }
    return !has_colon || is_valid_decimal_port(port_part);
}

// Applies a parsed parameter key-value pair to a ForwardedElement (RFC 7239 Section 4 & Section 5.5).
fn apply_forwarded_param(
    param_str: const u8[:],
    out:       http::ForwardedElement&,
    ext_keys:  u8[..64][..16]&,
) -> bool {
    let key, val_raw, has_eq = param_str.split_once_byte('=');
    guard has_eq && http::is_valid_header_name(key) else { return false; }
    var val: u8[..128] = [];
    guard decode_token_or_quoted_param(val_raw, val, 128) else { return false; }

    if key.eq_ascii_fold("by") {
        guard is_valid_forwarded_node(val[..]) && out.by.len == 0 && out.by.try_append(val[..]) else {
            return false;
        }
        return true;
    }
    if key.eq_ascii_fold("for") {
        guard is_valid_forwarded_node(val[..]) && out.for_node.len == 0 && out.for_node.try_append(val[..]) else {
            return false;
        }
        return true;
    }
    if key.eq_ascii_fold("host") {
        guard is_valid_forwarded_host(val[..]) && out.host.len == 0 && out.host.try_append(val[..]) else {
            return false;
        }
        return true;
    }
    if key.eq_ascii_fold("proto") {
        guard is_valid_forwarded_proto(val[..]) && out.proto.len == 0 && out.proto.try_append(val[..]) else {
            return false;
        }
        return true;
    }
    // RFC 7239 Section 5.5: Extensions - Accept valid token=value extension parameters without duplicates
    for &seen in ext_keys {
        guard !seen[..].eq_ascii_fold(key) else { return false; }
    }
    var kbuf: u8[..64] = [];
    return kbuf.try_set(key) && ext_keys.try_push(kbuf);
}

// ---- http/priority.goose internal helpers ----

fn urgency_to_ascii(u: u8) -> u8 {
    match u {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        _ => '3',
    }
}

// ---- http/security_txt.goose internal helpers ----

fn is_security_txt_comment_or_pgp(trimmed: const u8[:]) -> bool {
    guard trimmed.len > 0 else { return true; }
    guard trimmed[0] != '#' else { return true; }
    guard !trimmed.starts_with("-----") else { return true; }
    guard !trimmed.starts_with("Hash:") else { return true; }
    return false;
}

inline fn is_valid_security_txt_uri(val: const u8[:], https_only_web: bool) -> bool {
    guard val.len > 0 && val.len <= 256 && core::find_byteset(val, " \t\r\n") < 0 else { return false; }
    if https_only_web && val.starts_with_fold("http://") {
        return false;
    }
    let scheme, rest, has_colon = val.split_once_byte(':');
    guard has_colon && scheme.len > 0 && rest.len > 0 && core::is_ascii_alpha(scheme[0]) else { return false; }
    for b in scheme[1..] {
        guard core::is_ascii_alpha(b) || core::is_ascii_digit(b) || b == '+' || b == '-' || b == '.' else {
            return false;
        }
    }
    return true;
}

fn apply_security_txt_contact(val: const u8[:], sec: http::SecurityTxt&) -> bool {
    guard is_valid_security_txt_uri(val, true) && sec.contact.try_push(val) else {
        sec.status = http::SEC_TXT_ERR_INVALID_FIELD;
        return false;
    }
    sec.has_contact = true;
    return true;
}

fn apply_security_txt_expires(val: const u8[:], now_epoch: i64, sec: http::SecurityTxt&) -> bool {
    guard !sec.has_expires else {
        sec.status = http::SEC_TXT_ERR_DUPLICATE_EXPIRES;
        return false;
    }
    let parsed_time, ok = core::parse_rfc3339(val);
    guard ok && sec.expires.try_set(val) else {
        sec.status = http::SEC_TXT_ERR_INVALID_EXPIRES;
        return false;
    }
    sec.expires_unix = parsed_time.unix();
    sec.has_expires = true;

    guard now_epoch <= 0 || sec.expires_unix >= now_epoch else {
        sec.is_expired = true;
        sec.status = http::SEC_TXT_ERR_EXPIRED;
        return false;
    }
    return true;
}

fn apply_security_txt_canonical(val: const u8[:], sec: http::SecurityTxt&) -> bool {
    guard val.starts_with_fold("https://") && is_valid_security_txt_uri(val, true) else {
        sec.status = http::SEC_TXT_ERR_INVALID_CANONICAL;
        return false;
    }
    guard sec.canonical.try_push(val) else {
        sec.status = http::SEC_TXT_ERR_INVALID_FIELD;
        return false;
    }
    return true;
}

fn push_security_txt_uri_slot(val: const u8[:], slot: u8[..256][..4]&, sec: http::SecurityTxt&) -> bool {
    guard is_valid_security_txt_uri(val, true) && slot.try_push(val) else {
        sec.status = http::SEC_TXT_ERR_INVALID_FIELD;
        return false;
    }
    return true;
}

fn apply_security_txt_metadata(name: const u8[:], val: const u8[:], sec: http::SecurityTxt&) -> bool {
    if name.eq_ascii_fold("encryption") {
        return push_security_txt_uri_slot(val, sec.encryption, sec);
    }
    if name.eq_ascii_fold("acknowledgments") || name.eq_ascii_fold("acknowledgements") {
        return push_security_txt_uri_slot(val, sec.acknowledgments, sec);
    }
    if name.eq_ascii_fold("policy") {
        return push_security_txt_uri_slot(val, sec.policy, sec);
    }
    if name.eq_ascii_fold("hiring") {
        return push_security_txt_uri_slot(val, sec.hiring, sec);
    }
    if name.eq_ascii_fold("preferred-languages") {
        guard sec.preferred_languages.len == 0 && val.len > 0 && sec.preferred_languages.try_append(val) else {
            sec.status = http::SEC_TXT_ERR_INVALID_FIELD;
            return false;
        }
        return true;
    }
    return true;
}

fn apply_security_txt_field(
    name:      const u8[:],
    val:       const u8[:],
    now_epoch: i64,
    sec:       http::SecurityTxt&,
) -> bool {
    guard val.len > 0 else {
        sec.status = http::SEC_TXT_ERR_EMPTY_VALUE;
        return false;
    }

    if name.eq_ascii_fold("contact") {
        return apply_security_txt_contact(val, sec);
    }
    if name.eq_ascii_fold("expires") {
        return apply_security_txt_expires(val, now_epoch, sec);
    }
    if name.eq_ascii_fold("canonical") {
        return apply_security_txt_canonical(val, sec);
    }

    return apply_security_txt_metadata(name, val, sec);
}

fn validate_mandatory_security_fields(sec: http::SecurityTxt&) -> bool {
    guard sec.has_contact else {
        sec.status = http::SEC_TXT_ERR_MISSING_CONTACT;
        return false;
    }
    guard sec.has_expires else {
        sec.status = http::SEC_TXT_ERR_MISSING_EXPIRES;
        return false;
    }
    guard !sec.is_expired else {
        sec.status = http::SEC_TXT_ERR_EXPIRED;
        return false;
    }
    sec.is_valid = true;
    sec.status = http::SEC_TXT_OK;
    return true;
}

// Parses a single line from security.txt (RFC 9116 §2.1).
//
// Example:
//   line = "Contact: mailto:sec@example.com", now_epoch = 1700000000
//   returns: true (Contact field populated)
fn parse_security_txt_line(line: const u8[:], now_epoch: i64, sec: http::SecurityTxt&) -> bool {
    let trimmed = line.trim_ascii_space();
    guard !is_security_txt_comment_or_pgp(trimmed) else { return true; }

    let raw_name, raw_val, has_colon = trimmed.split_once_byte(':');
    guard has_colon else { return true; }

    let name = raw_name.trim_ascii_space();
    let val = raw_val.trim_ascii_space();

    return apply_security_txt_field(name, val, now_epoch, sec);
}

// ---- http/server_timing.goose internal helpers ----

// RFC 9110 Section 5.6.4: Quoted Strings - Reject non-HTAB control octets and enforce capacity.
inline fn copy_valid_timing_desc(src: const u8[:], dst: u8[..64]&) -> bool {
    dst.clear();
    for b in src {
        if b == '\r' || b == '\n' || b == 0 { continue; }
        guard (b == '\t' || (b >= 0x20 && b != 0x7F)) && dst.try_push(b) else {
            dst.clear();
            return false;
        }
    }
    return true;
}

// ---- http/status_diagnostics.goose internal helpers ----

// Skips leading whitespace and comma delimiters.
// Advances `idx` past the skipped bytes.
//
// Example:
//   raw = ",  item", idx = 0
//   idx becomes 3 (pointing to 'i')
fn skip_status_list_delims(raw: const u8[:], idx: i64&) {
    let rem = raw[idx..];
    let trimmed = rem.trim_start_bytes(" \t,");
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
    let trimmed = rem.trim_start_bytes("; \t");
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
    let trimmed = rem.trim_lws_start();
    idx += rem.len - trimmed.len;
}

// Reads target name token up to delimiter.
// Advances `idx` past the token.
//
// Example:
//   raw = "OriginCache; hit", idx = 0
//   returns: "OriginCache", idx becomes 11
fn read_status_target_name(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    if idx < raw.len && raw[idx] == '"' {
        return read_quoted_status_val(raw, idx);
    }
    let start = idx;
    while idx < raw.len {
        let b = raw[idx];
        if b == ';' || b == ',' || b == ' ' || b == '\t' {
            break;
        }
        idx += 1;
    }
    return raw[start..idx], idx > start;
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

fn apply_cache_status_flags(entry: http::CacheStatusEntry&, name: const u8[:], val: const u8[:]) -> bool, bool {
    let is_true = val.len == 0 || val == "?1";
    let is_false = val == "?0";
    if name.eq_ascii_fold("hit") {
        guard is_true || is_false else { return true, false; }
        entry.hit = is_true;
        return true, true;
    }
    if name.eq_ascii_fold("stored") {
        guard is_true || is_false else { return true, false; }
        entry.stored = is_true;
        return true, true;
    }
    if name.eq_ascii_fold("collapsed") {
        guard is_true || is_false else { return true, false; }
        entry.collapsed = is_true;
        return true, true;
    }
    return false, true;
}

fn apply_cache_status_param(entry: http::CacheStatusEntry&, name: const u8[:], val: const u8[:]) -> bool {
    let matched_flag, flag_ok = apply_cache_status_flags(entry, name, val);
    if matched_flag { return flag_ok; }

    if name.eq_ascii_fold("ttl") {
        let ttl_v, ok = val.parse_i64_dec();
        guard ok else { return false; }
        entry.ttl = ttl_v;
    } else if name.eq_ascii_fold("fwd") {
        guard entry.fwd.try_set(val) else { return false; }
    } else if name.eq_ascii_fold("fwd-status") {
        let fwd_v, ok = val.parse_i64_dec();
        guard ok && fwd_v >= 100 && fwd_v <= 599 else { return false; }
        entry.fwd_status = fwd_v as! i32;
    } else if name.eq_ascii_fold("key") {
        guard entry.key.try_set(val) else { return false; }
    } else if name.eq_ascii_fold("detail") {
        guard entry.detail.try_set(val) else { return false; }
    }
    return true;
}

fn format_cache_status_flags<B>(entry: const http::CacheStatusEntry&, out: B&) {
    if entry.hit {
        out.append("; hit");
    }
    if entry.stored {
        out.append("; stored");
    }
    if entry.collapsed {
        out.append("; collapsed");
    }
    if entry.ttl != 0 {
        out.append("; ttl=");
        entry.ttl.format_i64_dec(out);
    }
}

fn format_cache_status_meta<B>(entry: const http::CacheStatusEntry&, out: B&) {
    if entry.fwd.len > 0 {
        out.append("; fwd=");
        out.append(entry.fwd[..]);
    }
    if entry.fwd_status > 0 {
        out.append("; fwd-status=");
        entry.fwd_status.format_i64_dec(out);
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

fn apply_proxy_status_param(entry: http::ProxyStatusEntry&, name: const u8[:], val: const u8[:]) -> bool {
    if name.eq_ascii_fold("error") {
        guard entry.error_type.try_set(val) else { return false; }
    } else if name.eq_ascii_fold("next-hop") {
        guard entry.next_hop.try_set(val) else { return false; }
    } else if name.eq_ascii_fold("details") {
        guard entry.details.try_set(val) else { return false; }
    } else if name.eq_ascii_fold("received-status") {
        let rec_v, ok = val.parse_i64_dec();
        guard ok && rec_v >= 100 && rec_v <= 599 else { return false; }
        entry.received_status = rec_v as! i32;
    }
    return true;
}

// ---- http/trace.goose internal helpers ----

inline fn hex_val(c: u8) -> i32 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return -1;
}

// Key validation conforming to W3C Section 3.3:
// simple key: [a-z][a-z0-9_*/-]{0,255}
// multi-tenant key: [a-z0-9_*/-]{1,241}@[a-z][a-z0-9_*/-]{0,13}
fn is_valid_tracestate_key(key: const u8[:]) -> bool {
    guard key.len >= 1 && key.len <= 256 else { return false; }
    var at_pos: i64 = -1;
    for i in key.len {
        let b = key[i];
        if b == '@' {
            guard at_pos < 0 else { return false; } // only one '@' allowed
            at_pos = i;
            continue;
        }
        let is_alpha_num = (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9');
        let valid_char = is_alpha_num || b == '_' || b == '-' || b == '*' || b == '/';
        guard valid_char else { return false; }
    }
    if at_pos >= 0 {
        let tenant_len = at_pos;
        let system_len = key.len - at_pos - 1;
        guard tenant_len >= 1 && tenant_len <= 241 else { return false; }
        guard system_len >= 1 && system_len <= 14 else { return false; }
        let sys_first = key[at_pos + 1];
        guard sys_first >= 'a' && sys_first <= 'z' else { return false; }
        let tenant_first = key[0];
        let is_alnum = (tenant_first >= 'a' && tenant_first <= 'z') ||
            (tenant_first >= '0' && tenant_first <= '9');
        guard is_alnum else { return false; }
    } else {
        // Simple key MUST start with lowercase ASCII letter (W3C §3.3.1.1: lcalpha)
        let first = key[0];
        guard first >= 'a' && first <= 'z' else { return false; }
    }
    return true;
}

fn find_tracestate_entry_bounds(raw: const u8[:], cursor: i64, out_eq: i64&, out_comma: i64&) {
    var i = cursor;
    while i < raw.len {
        let b = raw[i];
        if b == '=' && out_eq < 0 {
            out_eq = i;
        } else if b == ',' {
            out_comma = i;
            break;
        }
        i++;
    }
}
