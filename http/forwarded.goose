// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7239: Forwarded HTTP Extension.
// Standardized proxy forwarding metadata header (obsoleting X-Forwarded-For,
// X-Forwarded-Proto, and X-Forwarded-Host).
namespace wing;

import std;
import core from "..";
import .headers;

// RFC 7239 Section 4: A single forwarded-element item.
struct ForwardedElement {
    by:       u8[..128] = [],
    for_node: u8[..128] = [],
    host:     u8[..128] = [],
    proto:    u8[..16]  = [],
}

// Appends an RFC 7239 node identifier with quotes if it contains IPv6 or non-token characters.
fn append_quoted_node<B>(val: const u8[:], out: B&) {
    let needs_quotes = core::contains(val, ":") || core::contains(val, "[") || core::contains(val, "]");
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

// Applies a parsed parameter key-value pair to a ForwardedElement.
fn apply_forwarded_param(param_str: const u8[:], out: ForwardedElement&) -> bool {
    let key_raw, val_raw, has_eq = param_str.split_once_byte('=');
    guard has_eq else { return false; }
    let key = key_raw.trim_lws();
    let val = val_raw.trim_lws().trim_byte('"');

    if core::eq_ascii_fold(key, "by") {
        guard val.len <= out.by.cap else { return false; }
        out.by.clear();
        out.by.append(val);
        return true;
    }
    if core::eq_ascii_fold(key, "for") {
        guard val.len <= out.for_node.cap else { return false; }
        out.for_node.clear();
        out.for_node.append(val);
        return true;
    }
    if core::eq_ascii_fold(key, "host") {
        guard val.len <= out.host.cap else { return false; }
        out.host.clear();
        out.host.append(val);
        return true;
    }
    if core::eq_ascii_fold(key, "proto") {
        guard val.len <= out.proto.cap else { return false; }
        out.proto.clear();
        out.proto.append(val);
        return true;
    }
    return false;
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

    var rem = raw.trim_lws();
    while rem.len > 0 {
        rem = rem.trim_start_bytes(" \t;");
        guard rem.len > 0 else { break; }

        let p_len = rem.find_unquoted_byte(';');
        let p_str = rem[..p_len].trim_lws();
        rem = rem[p_len..];

        apply_forwarded_param(p_str, out);
    }
    return out.by.len > 0 || out.for_node.len > 0 || out.host.len > 0 || out.proto.len > 0;
}

// Parses a complete RFC 7239 Forwarded header value into a list of elements.
//
// Example:
//   raw = "for=192.0.2.60;proto=http, for=198.51.100.1"
//   returns: 2 (stores 2 elements in out_elements)
fn parse_forwarded_header(raw: const u8[:], out_elements: ForwardedElement[..8]&) -> i64 {
    out_elements.clear();
    var rem = raw.trim_lws();
    while rem.len > 0 && out_elements.len < out_elements.cap {
        rem = rem.trim_start_bytes(" \t,");
        guard rem.len > 0 else { break; }

        let elem_len = rem.find_unquoted_byte(',');
        let elem_str = rem[..elem_len].trim_lws();
        rem = rem[elem_len..];

        var elem = ForwardedElement { .. };
        if parse_forwarded_element(elem_str, elem) {
            out_elements.push(elem);
        }
    }
    return out_elements.len;
}
