// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7239: Forwarded HTTP Extension.
// Standardized proxy forwarding metadata header (obsoleting X-Forwarded-For,
// X-Forwarded-Proto, and X-Forwarded-Host).
namespace http;

import std;
import core;
import .headers;
import .mime;
import http.meta_internal;

// RFC 7239 Section 4: A single forwarded-element item.
struct ForwardedElement {
    by:       u8[..128] = [],
    for_node: u8[..128] = [],
    host:     u8[..128] = [],
    proto:    u8[..16]  = [],
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
        http_internal::append_quoted_node(elem.by[..], out);
        has_param = true;
    }
    if elem.for_node.len > 0 {
        if has_param { out.push(';'); }
        out.append("for=");
        http_internal::append_quoted_node(elem.for_node[..], out);
        has_param = true;
    }
    if elem.host.len > 0 {
        if has_param { out.push(';'); }
        out.append("host=");
        http_internal::append_quoted_node(elem.host[..], out);
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
        guard p_str.len > 0 && http_internal::apply_forwarded_param(p_str, out, ext_keys) else { return false; }
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
