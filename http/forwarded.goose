// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7239: Forwarded HTTP Extension.
// Standardized proxy forwarding metadata header (obsoleting X-Forwarded-For,
// X-Forwarded-Proto, and X-Forwarded-Host).
namespace wing;

import std;
import core from "..";
import .headers;
import .mime;

// RFC 7239 Section 4: A single forwarded-element item.
struct ForwardedElement {
    by:       u8[..128] = [],
    for_node: u8[..128] = [],
    host:     u8[..128] = [],
    proto:    u8[..16]  = [],
}

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

// Formats a ForwardedElement into an RFC 7239 wire string.
//
// Example:
//   elem = ForwardedElement { for_node: "192.0.2.60", proto: "https", host: "api.example.com" }
//   returns: "for=192.0.2.60;proto=https;host=api.example.com"
fn format_forwarded_element<B>(elem: const ForwardedElement&, out: B&) {
    var has_param = false;

    if elem.by.len > 0 {
        out.append("by=");
        append_quoted_node(elem.by[..], out);
        has_param = true;
    }
    if elem.for_node.len > 0 {
        if has_param { out.push(';'); }
        out.append("for=");
        append_quoted_node(elem.for_node[..], out);
        has_param = true;
    }
    if elem.host.len > 0 {
        if has_param { out.push(';'); }
        out.append("host=");
        append_quoted_node(elem.host[..], out);
        has_param = true;
    }
    if elem.proto.len > 0 {
        if has_param { out.push(';'); }
        out.append("proto=");
        out.append(elem.proto[..]);
    }
}

// Appends `Forwarded` header to outgoing HeaderMap.
fn append_forwarded_header(out_headers: HeaderMap&, elem: const ForwardedElement&) -> bool {
    var buf: u8[..512] = [];
    format_forwarded_element(elem, buf);
    guard buf.len > 0 else { return false; }
    return append_header(out_headers, rfc::HEADER_FORWARDED, buf[..]);
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
    out:       ForwardedElement&,
    ext_keys:  u8[..64][..16]&,
) -> bool {
    let key, val_raw, has_eq = param_str.split_once_byte('=');
    guard has_eq && is_valid_header_name(key) else { return false; }
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

// Parses a single RFC 7239 forwarded-element item (e.g. `for=192.0.2.60;proto=https`).
//
// Example:
//   raw = "for=192.0.2.60;proto=https;host=example.com"
//   returns: true, out.for_node = "192.0.2.60", out.proto = "https"
fn parse_forwarded_element(raw: const u8[:], out: ForwardedElement&) -> bool {
    out.by.clear();
    out.for_node.clear();
    out.host.clear();
    out.proto.clear();
    var committed = false;
    defer if !committed {
        out.by.clear();
        out.for_node.clear();
        out.host.clear();
        out.proto.clear();
    };

    let trimmed = raw.trim_lws();
    guard trimmed.len > 0 && !core::starts_with(trimmed, ";") && !core::ends_with(trimmed, ";") else {
        return false;
    }

    var ext_keys:  u8[..64][..16] = [];
    var has_param: bool           = false;
    var rem = trimmed;
    while rem.len > 0 {
        let p_len = rem.find_unquoted_byte(';');
        let p_str = rem[..p_len].trim_lws();
        guard p_str.len > 0 && apply_forwarded_param(p_str, out, ext_keys) else { return false; }
        has_param = true;
        if p_len >= rem.len {
            break;
        }
        rem = rem[core::add_sat_i64(p_len, 1)..];
    }
    committed = has_param;
    return committed;
}

// Parses a complete RFC 7239 Forwarded header value into a list of elements.
//
// Example:
//   raw = "for=192.0.2.60;proto=http, for=198.51.100.1"
//   returns: 2 (stores 2 elements in out_elements)
fn parse_forwarded_header(raw: const u8[:], out_elements: ForwardedElement[..8]&) -> i64 {
    out_elements.clear();
    var committed = false;
    defer if !committed { out_elements.clear(); };

    let trimmed = raw.trim_lws();
    guard trimmed.len > 0 && !core::starts_with(trimmed, ",") && !core::ends_with(trimmed, ",") else {
        return 0;
    }

    var rem = trimmed;
    while rem.len > 0 {
        let elem_len = rem.find_unquoted_byte(',');
        let elem_str = rem[..elem_len].trim_lws();
        var elem = ForwardedElement { .. };
        guard elem_str.len > 0 &&
              parse_forwarded_element(elem_str, elem) &&
              out_elements.try_push(elem) else {
            return 0;
        }
        if elem_len >= rem.len {
            break;
        }
        rem = rem[core::add_sat_i64(elem_len, 1)..];
    }
    committed = out_elements.len > 0;
    return out_elements.len;
}
