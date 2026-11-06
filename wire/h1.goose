// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Sans-IO HTTP/1.1 request and response wire framing (RFC 9112).
namespace wire;

import std;
import core from "..";
import http.headers;

enum H1HeaderFilterMode {
    PreserveAll,
    StripHopByHop,
}

inline fn is_valid_h1_request_target(target: const u8[:]) -> bool {
    guard target.len > 0 else { return false; }
    for b in target {
        guard b > 0x20 && b != 0x7F else { return false; }
    }
    return true;
}

inline fn is_valid_h1_host_value(host: const u8[:]) -> bool {
    for b in host {
        guard b > 0x20 && b < 0x7F &&
              b != '/' && b != '?' && b != '#' && b != '\\' && b != '@' else {
            return false;
        }
    }
    return true;
}

inline fn should_skip_h1_header(
    headers:     const wing::HeaderMap&,
    name:        const u8[:],
    val:         const u8[:],
    filter_mode: H1HeaderFilterMode,
) -> bool {
    guard filter_mode == H1HeaderFilterMode.StripHopByHop else { return false; }
    if wing::is_hop_by_hop_header_name(name) {
        return !(core::eq_ascii_fold(name, "te") && core::eq_ascii_fold(core::trim_lws(val), "trailers"));
    }
    return wing::is_token_in_connection_header_map(headers, name);
}

inline fn validate_h1_header_entries(headers: const wing::HeaderMap&, filter_mode: H1HeaderFilterMode) -> bool {
    for &e in headers.entries {
        let name = wing::entry_name(headers, e);
        let val = wing::entry_value(headers, e);
        if should_skip_h1_header(headers, name, val, filter_mode) {
            continue;
        }
        guard wing::is_valid_header_name(name) && wing::is_valid_header_value(val) else {
            return false;
        }
    }
    return true;
}

struct H1HeaderScanFlags {
    has_host:   bool = false,
    has_server: bool = false,
    has_cl:     bool = false,
    has_te:     bool = false,
}

fn append_h1_request_headers<B>(
    headers:     const wing::HeaderMap&,
    filter_mode: H1HeaderFilterMode,
    flags:       H1HeaderScanFlags&,
    out:         B&,
) -> bool {
    for &e in headers.entries {
        let name = wing::entry_name(headers, e);
        let val = wing::entry_value(headers, e);
        if should_skip_h1_header(headers, name, val, filter_mode) {
            continue;
        }
        if core::eq_ascii_fold(name, "host") { flags.has_host = true; }
        if core::eq_ascii_fold(name, "content-length") { flags.has_cl = true; }
        if core::eq_ascii_fold(name, "transfer-encoding") { flags.has_te = true; }
        guard out.try_append(name) &&
              out.try_append(": ") &&
              out.try_append(val) &&
              out.try_append("\r\n") else {
            return false;
        }
    }
    return true;
}

// Serializes an HTTP/1.1 request head and optional body into `out` (RFC 9112 §3).
// Validates method token, request-target, and header field values against CRLF injection.
//
// Example:
//   encode_h1_request("GET", "/index.html", "example.com", headers, "", H1HeaderFilterMode.PreserveAll, out)
//   returns: true, out = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
fn encode_h1_request<B>(
    method:       const u8[:],
    target:       const u8[:],
    host:         const u8[:],
    headers:      const wing::HeaderMap&,
    body:         const u8[:],
    filter_mode:  H1HeaderFilterMode,
    out:          B&,
    http_version: const u8[:] = "HTTP/1.1",
) -> bool {
    let eff_target = if target.len > 0 { target } else { "/" };
    let eff_ver = if http_version.len > 0 { http_version } else { "HTTP/1.1" };
    guard wing::is_valid_header_name(method) &&
          is_valid_h1_request_target(eff_target) &&
          is_valid_h1_host_value(host) &&
          is_valid_h1_request_target(eff_ver) &&
          validate_h1_header_entries(headers, filter_mode) else {
        return false;
    }

    let start_len = out.len;
    guard out.try_append(method) &&
          out.try_append(" ") &&
          out.try_append(eff_target) &&
          out.try_append(" ") &&
          out.try_append(eff_ver) &&
          out.try_append("\r\n") else {
        out.resize(start_len);
        return false;
    }

    var flags = H1HeaderScanFlags { .. };
    guard append_h1_request_headers(headers, filter_mode, flags, out) else {
        out.resize(start_len);
        return false;
    }

    if !flags.has_host && host.len > 0 {
        guard out.try_append("Host: ") &&
              out.try_append(host) &&
              out.try_append("\r\n") else {
            out.resize(start_len);
            return false;
        }
    }

    if !flags.has_cl && !flags.has_te && body.len > 0 {
        var cl_str: u8[..32] = [];
        core::format_u64_dec(body.len as u64, cl_str);
        guard out.try_append("Content-Length: ") &&
              out.try_append(cl_str[..]) &&
              out.try_append("\r\n") else {
            out.resize(start_len);
            return false;
        }
    }

    guard out.try_append("\r\n") && out.try_append(body) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

fn append_h1_response_headers<B>(
    headers:         const wing::HeaderMap&,
    is_empty_status: bool,
    flags:           H1HeaderScanFlags&,
    out:             B&,
) -> bool {
    for &e in headers.entries {
        let name = wing::entry_name(headers, e);
        let val = wing::entry_value(headers, e);
        if is_empty_status &&
           (core::eq_ascii_fold(name, "content-length") || core::eq_ascii_fold(name, "transfer-encoding")) {
            continue;
        }
        if core::eq_ascii_fold(name, "server") { flags.has_server = true; }
        if core::eq_ascii_fold(name, "content-length") { flags.has_cl = true; }
        if core::eq_ascii_fold(name, "transfer-encoding") { flags.has_te = true; }
        guard out.try_append(name) &&
              out.try_append(": ") &&
              out.try_append(val) &&
              out.try_append("\r\n") else {
            return false;
        }
    }
    return true;
}

// Serializes an HTTP/1.1 response status line, headers, and optional body into `out` (RFC 9112 §4).
// Suppresses body emission when `is_head_request` is true or status code has no message body (1xx, 204, 304).
//
// Example:
//   encode_h1_response(200, "OK", "goose-wing", headers, "hello", false, out)
//   returns: true, out = "HTTP/1.1 200 OK\r\nServer: goose-wing\r\nContent-Length: 5\r\n\r\nhello"
fn encode_h1_response<B>(
    status_code:     u16,
    reason:          const u8[:],
    server_name:     const u8[:],
    headers:         const wing::HeaderMap&,
    body:            const u8[:],
    is_head_request: bool,
    out:             B&,
) -> bool {
    guard status_code >= 100 && status_code <= 599 else { return false; }
    let eff_reason = if reason.len > 0 { reason } else { rfc::status_phrase(status_code as i32) };
    guard wing::is_valid_header_value(eff_reason) &&
          wing::is_valid_header_value(server_name) &&
          validate_h1_header_entries(headers, H1HeaderFilterMode.PreserveAll) else {
        return false;
    }

    let start_len = out.len;
    var sc_str: u8[..16] = [];
    core::format_u64_dec(status_code as u64, sc_str);
    guard out.try_append("HTTP/1.1 ") &&
          out.try_append(sc_str[..]) &&
          out.try_append(" ") &&
          out.try_append(eff_reason) &&
          out.try_append("\r\n") else {
        out.resize(start_len);
        return false;
    }

    let is_empty_status = rfc::is_empty_body_status(status_code as i32);
    var flags = H1HeaderScanFlags { .. };
    guard append_h1_response_headers(headers, is_empty_status, flags, out) else {
        out.resize(start_len);
        return false;
    }

    if !flags.has_server && server_name.len > 0 {
        guard out.try_append("Server: ") &&
              out.try_append(server_name) &&
              out.try_append("\r\n") else {
            out.resize(start_len);
            return false;
        }
    }

    if !is_empty_status && !flags.has_cl && !flags.has_te {
        var cl_str: u8[..32] = [];
        core::format_u64_dec(body.len as u64, cl_str);
        guard out.try_append("Content-Length: ") &&
              out.try_append(cl_str[..]) &&
              out.try_append("\r\n") else {
            out.resize(start_len);
            return false;
        }
    }

    let body_to_emit = if !is_head_request && !is_empty_status { body } else { "" };
    guard out.try_append("\r\n") && out.try_append(body_to_emit) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

inline fn is_valid_h1_reason_phrase(reason: const u8[:]) -> bool {
    for b in reason {
        guard (b >= 0x20 && b <= 0x7E) || b >= 0x80 || b == '\t' else { return false; }
    }
    return true;
}

// Parses an HTTP/1.x status line (RFC 9112 §4) and extracts the 3-digit status code into `out_status`.
//
// Example:
//   line = "HTTP/1.1 200 OK"
//   returns: true, out_status = 200
fn parse_h1_wire_status_line(line: const u8[:], out_status: u16&) -> bool {
    let ver_str, rest, has_sp1 = core::split_once_byte(line, ' ');
    guard has_sp1 && (ver_str == "HTTP/1.1" || ver_str == "HTTP/1.0") else { return false; }

    let code_str, reason_str, has_sp2 = core::split_once_byte(rest, ' ');
    let sc_part = if has_sp2 { code_str } else { rest };
    guard sc_part.len == 3 else { return false; }
    let sc, ok_sc = core::parse_i32_dec(sc_part);
    guard ok_sc && sc >= 100 && sc <= 599 else { return false; }
    if has_sp2 {
        guard is_valid_h1_reason_phrase(reason_str) else { return false; }
    }
    out_status = sc as u16;
    return true;
}

// Decodes an HTTP/1.1 response status line and headers directly into `out_headers` (RFC 9112 §4).
// Returns `(body_start_offset, HeaderParseError)`. When headers are incomplete (`\r\n\r\n` not yet received),
// returns `(0, HeaderParseError.Incomplete)`.
//
// Example:
//   raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody"
//   returns: consumed = 45, err = HeaderParseError.None, out_status = 200
fn decode_h1_response_head(
    raw:            const u8[:],
    out_status:     u16&,
    out_headers:    wing::HeaderMap&,
    allow_obs_fold: bool = false,
) -> i64, wing::HeaderParseError {
    out_status = 0;
    out_headers.clear();

    let head_no_end, _, has_crlfcrlf = core::split_once(raw, "\r\n\r\n");
    guard has_crlfcrlf else {
        return 0, wing::HeaderParseError.Incomplete;
    }
    let body_offset = head_no_end.len + 4;

    let status_line, headers_no_end, has_crlf = core::split_once(head_no_end, "\r\n");
    if !has_crlf {
        guard head_no_end.len >= 12 && parse_h1_wire_status_line(head_no_end, out_status) else {
            return 0, wing::HeaderParseError.MalformedStatusLine;
        }
        return body_offset, wing::HeaderParseError.None;
    }

    guard status_line.len >= 12 && parse_h1_wire_status_line(status_line, out_status) else {
        return 0, wing::HeaderParseError.MalformedStatusLine;
    }

    if headers_no_end.len == 0 {
        return body_offset, wing::HeaderParseError.None;
    }

    let err = wing::parse_headers(headers_no_end, out_headers, allow_obs_fold);
    guard err == wing::HeaderParseError.None else {
        out_headers.clear();
        return 0, err;
    }
    return body_offset, wing::HeaderParseError.None;
}
