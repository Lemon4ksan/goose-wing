// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Sans-IO HTTP/1.1 request and response wire framing (RFC 9112).
namespace wire;

import std;
import core from "..";

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
    headers:     const http::HeaderMap&,
    name:        const u8[:],
    val:         const u8[:],
    filter_mode: H1HeaderFilterMode,
) -> bool {
    guard filter_mode == H1HeaderFilterMode.StripHopByHop else { return false; }
    if http::is_hop_by_hop_header_name(name) {
        return !(name.eq_ascii_fold("te") && val.trim_lws().eq_ascii_fold("trailers"));
    }
    return http::is_token_in_connection_header_map(headers, name);
}

struct H1HeaderScanFlags {
    has_host:   bool = false,
    has_server: bool = false,
    has_cl:     bool = false,
    has_te:     bool = false,
    cl_val:     i64  = -1,
}

fn record_h1_framing_header(name: const u8[:], val: const u8[:], flags: H1HeaderScanFlags&) -> bool {
    if name.eq_ascii_fold("transfer-encoding") {
        guard !flags.has_cl && val.trim_lws().len > 0 else { return false; }
        flags.has_te = true;
        return true;
    }
    if name.eq_ascii_fold("content-length") {
        // RFC 9112 Section 6.2: Content-Length - reject duplicate Content-Length or Transfer-Encoding co-presence.
        guard !flags.has_te && !flags.has_cl else { return false; }
        let trimmed_cl = val.trim_lws();
        let parsed_cl, ok_cl = trimmed_cl.parse_i64_dec();
        let _, ok_u = trimmed_cl.parse_u64_dec();
        guard ok_cl && ok_u && parsed_cl >= 0 else { return false; }
        flags.has_cl = true;
        flags.cl_val = parsed_cl;
    }
    return true;
}

fn check_and_record_h1_header_entry(
    name:       const u8[:],
    val:        const u8[:],
    is_request: bool,
    flags:      H1HeaderScanFlags&,
) -> bool {
    guard http::is_valid_header_name(name) && http::is_valid_header_value(val) else {
        return false;
    }
    if is_request && name.eq_ascii_fold("host") {
        guard !flags.has_host && is_valid_h1_host_value(val.trim_lws()) else { return false; }
        flags.has_host = true;
    }
    if name.eq_ascii_fold("server") {
        flags.has_server = true;
    }
    return record_h1_framing_header(name, val, flags);
}

fn append_h1_request_headers<B>(
    headers:     const http::HeaderMap&,
    filter_mode: H1HeaderFilterMode,
    flags:       H1HeaderScanFlags&,
    out:         B&,
) -> bool {
    for &e in headers.entries {
        let name = http::entry_name(headers, e);
        let val = http::entry_value(headers, e);
        if should_skip_h1_header(headers, name, val, filter_mode) {
            continue;
        }
        guard check_and_record_h1_header_entry(name, val, true, flags) else { return false; }
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
    headers:      const http::HeaderMap&,
    body:         const u8[:],
    filter_mode:  H1HeaderFilterMode,
    out:          B&,
    http_version: const u8[:] = "HTTP/1.1",
) -> bool {
    let eff_target = if target.len > 0 { target } else { "/" };
    let eff_ver = if http_version.len > 0 { http_version } else { "HTTP/1.1" };
    let valid_ver = eff_ver == "HTTP/1.1" || eff_ver == "HTTP/1.0";
    guard http::is_valid_header_name(method) &&
          is_valid_h1_request_target(eff_target) &&
          is_valid_h1_host_value(host) &&
          valid_ver else {
        return false;
    }

    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };

    guard out.try_append(method) &&
          out.try_append(" ") &&
          out.try_append(eff_target) &&
          out.try_append(" ") &&
          out.try_append(eff_ver) &&
          out.try_append("\r\n") else {
        return false;
    }

    var flags = H1HeaderScanFlags { .. };
    guard append_h1_request_headers(headers, filter_mode, flags, out) else { return false; }
    // RFC 9112 Section 3.2: Request Target - an HTTP/1.1 client MUST send a Host header field in all requests.
    guard eff_ver != "HTTP/1.1" || flags.has_host || host.len > 0 else { return false; }
    // RFC 9112 Section 6.1: Transfer-Encoding - MUST NOT apply Transfer-Encoding to an HTTP/1.0 message.
    guard !(eff_ver == "HTTP/1.0" && flags.has_te) else { return false; }
    guard !(flags.has_cl && body.len > 0 && flags.cl_val != body.len) else { return false; }

    if !flags.has_host && host.len > 0 {
        guard out.try_append("Host: ") &&
              out.try_append(host) &&
              out.try_append("\r\n") else {
            return false;
        }
    }

    if !flags.has_cl && !flags.has_te && body.len > 0 {
        var cl_str: u8[..32] = [];
        body.len.format_i64_dec(cl_str);
        guard out.try_append("Content-Length: ") &&
              out.try_append(cl_str[..]) &&
              out.try_append("\r\n") else {
            return false;
        }
    }

    guard out.try_append("\r\n") && out.try_append(body) else { return false; }
    committed = true;
    return true;
}

fn append_h1_response_headers<B>(
    headers:     const http::HeaderMap&,
    status_code: u16,
    flags:       H1HeaderScanFlags&,
    out:         B&,
) -> bool {
    let forbid_cl = status_code < 200 || status_code == 204;
    let forbid_te = rfc::is_empty_body_status(status_code as i32);
    for &e in headers.entries {
        let name = http::entry_name(headers, e);
        let val = http::entry_value(headers, e);
        guard check_and_record_h1_header_entry(name, val, false, flags) else { return false; }
        guard !(forbid_cl && name.eq_ascii_fold("content-length")) &&
              !(forbid_te && name.eq_ascii_fold("transfer-encoding")) else {
            return false;
        }
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
    headers:         const http::HeaderMap&,
    body:            const u8[:],
    is_head_request: bool,
    out:             B&,
) -> bool {
    guard status_code >= 100 && status_code <= 599 else { return false; }
    let eff_reason = if reason.len > 0 { reason } else { rfc::status_phrase(status_code as i32) };
    guard http::is_valid_header_value(eff_reason) &&
          http::is_valid_header_value(server_name) else {
        return false;
    }

    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };

    var sc_str: u8[..16] = [];
    status_code.format_u64_dec(sc_str);
    guard out.try_append("HTTP/1.1 ") &&
          out.try_append(sc_str[..]) &&
          out.try_append(" ") &&
          out.try_append(eff_reason) &&
          out.try_append("\r\n") else {
        return false;
    }

    let is_empty_status = rfc::is_empty_body_status(status_code as i32);
    var flags = H1HeaderScanFlags { .. };
    guard append_h1_response_headers(headers, status_code, flags, out) else { return false; }
    guard !(!is_head_request && !is_empty_status && flags.has_cl && flags.cl_val != body.len) else {
        return false;
    }

    if !flags.has_server && server_name.len > 0 {
        guard out.try_append("Server: ") &&
              out.try_append(server_name) &&
              out.try_append("\r\n") else {
            return false;
        }
    }

    if !is_empty_status && !flags.has_cl && !flags.has_te {
        var cl_str: u8[..32] = [];
        body.len.format_i64_dec(cl_str);
        guard out.try_append("Content-Length: ") &&
              out.try_append(cl_str[..]) &&
              out.try_append("\r\n") else {
            return false;
        }
    }

    let body_to_emit = if !is_head_request && !is_empty_status { body } else { "" };
    guard out.try_append("\r\n") && out.try_append(body_to_emit) else { return false; }
    committed = true;
    return true;
}

inline fn is_valid_h1_reason_phrase(reason: const u8[:]) -> bool {
    for b in reason {
        guard (b >= 0x20 && b <= 0x7E) || b >= 0x80 || b == '\t' else { return false; }
    }
    return true;
}

// Scans header field name characters up to ':', validating RFC 9110 tchars via 8-byte SWAR chunks.
//
// Example:
//   src = "Content-Type: text/plain\r\n"
//   returns: 12, ok = true (points to ':')
fn scan_h1_wire_field_name(src: const u8[:]) -> i64, bool {
    guard src.len > 0 else { return 0, false; }
    var i: i64 = 0;
    while core::add_sat_i64(i, 8) <= src.len {
        if !http::is_valid_token_word_swar(src, i) {
            break;
        }
        i = core::add_sat_i64(i, 8);
    }
    while i < src.len {
        let b = src[i];
        if b == ':' {
            guard i > 0 else { return 0, false; }
            return i, true;
        }
        guard http::is_tchar(b) else { return 0, false; }
        i = core::add_sat_i64(i, 1);
    }
    return 0, false;
}

// Parses an HTTP/1.x status line (RFC 9112 §4) and extracts the 3-digit status code into `out_status`.
//
// Example:
//   line = "HTTP/1.1 200 OK"
//   returns: true, out_status = 200
fn parse_h1_wire_status_line(line: const u8[:], out_status: u16&) -> bool {
    guard line.len >= 12 else { return false; }
    let ver_str, rest, has_sp1 = line.split_once_byte(' ');
    guard has_sp1 && (ver_str == "HTTP/1.1" || ver_str == "HTTP/1.0") else { return false; }

    let code_str, reason_str, has_sp2 = rest.split_once_byte(' ');
    let sc_part = if has_sp2 { code_str } else { rest };
    guard sc_part.len == 3 else { return false; }
    let sc, ok_sc = sc_part.parse_i32_dec();
    guard ok_sc && sc >= 100 && sc <= 599 else { return false; }
    if has_sp2 {
        guard is_valid_h1_reason_phrase(reason_str) else { return false; }
    }
    out_status = sc as u16;
    return true;
}

inline fn has_bare_cr_or_lf(s: const u8[:]) -> bool {
    for i in s.len {
        let b = s[i];
        if b == '\r' && (core::add_sat_i64(i, 1) >= s.len || s[i + 1] != '\n') {
            return true;
        }
        if b == '\n' && (i == 0 || s[i - 1] != '\r') {
            return true;
        }
    }
    return false;
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
    out_headers:    http::HeaderMap&,
    allow_obs_fold: bool = false,
) -> i64, http::HeaderParseError {
    var committed = false;
    out_status = 0;
    out_headers.clear();
    defer if !committed {
        out_status = 0;
        out_headers.clear();
    };

    let crlfcrlf_off = core::fast_find_crlfcrlf(raw);
    guard crlfcrlf_off >= 0 else {
        return 0, http::HeaderParseError.Incomplete;
    }
    let head_no_end = raw[..crlfcrlf_off];
    let body_offset = core::add_sat_i64(crlfcrlf_off, 4);

    let status_line, headers_no_end, has_crlf = head_no_end.split_once("\r\n");
    if !has_crlf {
        guard head_no_end.len >= 12 &&
              !has_bare_cr_or_lf(head_no_end) &&
              parse_h1_wire_status_line(head_no_end, out_status) else {
            return 0, http::HeaderParseError.MalformedStatusLine;
        }
        out_headers.status_code = out_status;
        out_headers.http_major = 1;
        out_headers.http_minor = if core::starts_with(head_no_end, "HTTP/1.0 ") { 0 } else { 1 };
        committed = true;
        return body_offset, http::HeaderParseError.None;
    }

    guard status_line.len >= 12 &&
          !has_bare_cr_or_lf(status_line) &&
          parse_h1_wire_status_line(status_line, out_status) else {
        return 0, http::HeaderParseError.MalformedStatusLine;
    }
    let minor: u8 = if core::starts_with(status_line, "HTTP/1.0 ") { 0 } else { 1 };

    if headers_no_end.len == 0 {
        out_headers.status_code = out_status;
        out_headers.http_major = 1;
        out_headers.http_minor = minor;
        committed = true;
        return body_offset, http::HeaderParseError.None;
    }

    guard !has_bare_cr_or_lf(headers_no_end) else {
        return 0, http::HeaderParseError.InvalidHeaderValue;
    }

    let err = http::parse_headers(headers_no_end, out_headers, allow_obs_fold);
    guard err == http::HeaderParseError.None else {
        return 0, err;
    }
    out_headers.status_code = out_status;
    out_headers.http_major = 1;
    out_headers.http_minor = minor;
    committed = true;
    return body_offset, http::HeaderParseError.None;
}
