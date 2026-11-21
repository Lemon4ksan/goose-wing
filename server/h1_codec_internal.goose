// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/1.1 lexical parsing, framing validation, and serialization helpers for `server/h1_codec.goose`.
namespace server_internal;

import std;
import core;
import rfc.http;
import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import http.headers.perfect_hash;
import http.request;
import http.response;
import wire.h1;
import .profiler;
import .h1_codec;

// Appends transfer-encoding header value with comma delimiter.
fn append_te_header_value<B>(te_buf: B&, val: const u8[:]) -> bool {
    if te_buf.len > 0 {
        let needed = core::add_sat_i64(core::add_sat_i64(te_buf.len, 2), val.len);
        guard needed <= te_buf.cap else { return false; }
        te_buf.append(", ");
        te_buf.append(val);
        return true;
    }
    return te_buf.try_append(val);
}

// Scans slice for the first space delimiter (' ') starting at `start` offset using 64-bit SWAR.
// Returns the index of the first space, or -1 if none found.
//
// Example:
//   s = "/index.html HTTP/1.1", start = 0
//   returns: 11
fn swar_find_space(s: const u8[:], start: i64) -> i64 {
    var i: i64 = start;
    let limit = s.len - 8;
    while i <= limit {
        let w = core::read_le_u64(s, i);
        let x = w ^ 0x2020202020202020;
        let zero_match = (x - 0x0101010101010101) & (~x) & 0x8080808080808080;
        if zero_match != 0 {
            return i + (ctz(zero_match) >> 3);
        }
        i += 8;
    }
    while i < s.len {
        if s[i] == ' ' { return i; }
        i++;
    }
    return -1;
}

// RFC 9112 Section 3.2: Request Target - visible ASCII excluding '#' fragment delimiter
fn validate_request_target_chars(path_slice: const u8[:]) -> bool {
    for b in path_slice {
        guard b >= 0x21 && b <= 0x7E && b != '#' else { return false; }
    }
    return true;
}

// Scans and recognizes standard HTTP methods using 64-bit SWAR word matching.
// Returns consumed method length (without trailing space) and method name slice.
// If not a standard method, returns 0 and "".
//
// Example:
//   w0 = 0x20544547 ("GET ")
//   returns: 3, "GET"
inline fn match_swar_method(w0: u64) -> i64, const u8[:] {
    let w0_32 = (w0 & 0xFFFFFFFF) as u32;
    if w0_32 == rfc::METHOD_GET_U32 {
        return 3, "GET";
    }
    if (w0 & 0xFFFFFFFFFF) == rfc::METHOD_POST_U64 {
        return 4, "POST";
    }
    if (w0 & 0xFFFFFFFFFF) == rfc::METHOD_HEAD_U64 {
        return 4, "HEAD";
    }
    if w0_32 == rfc::METHOD_PUT_U32 {
        return 3, "PUT";
    }
    if (w0 & 0xFFFFFFFFFFFFFF) == rfc::METHOD_DELETE_U64 {
        return 6, "DELETE";
    }
    if w0 == rfc::METHOD_OPTIONS_U64 {
        return 7, "OPTIONS";
    }
    if w0 == rfc::METHOD_CONNECT_U64 {
        return 7, "CONNECT";
    }
    if (w0 & 0xFFFFFFFFFFFF) == rfc::METHOD_PATCH_U64 {
        return 5, "PATCH";
    }
    if (w0 & 0xFFFFFFFFFFFF) == rfc::METHOD_TRACE_U64 {
        return 5, "TRACE";
    }
    return 0, "";
}

// RFC 9112 §3.2.3: Validates authority-form request target for CONNECT method (host:port).
inline fn validate_connect_authority(target: const u8[:]) -> bool {
    guard target.len >= 3 else { return false; }
    if target[0] == '[' {
        let close_idx = target.index_of_byte(']');
        guard close_idx > 1 && close_idx + 2 < target.len && target[close_idx + 1] == ':' else {
            return false;
        }
        var comp_buf: u8[..64] = [];
        guard core::parse_and_compress_ipv6(target[1..close_idx], comp_buf) else {
            return false;
        }
        let port_num, port_ok = core::parse_port_number(target[(close_idx + 2)..]);
        return port_ok && port_num > 0;
    }
    let col = target.index_of_byte(':');
    guard col > 0 && col + 1 < target.len else { return false; }
    guard validate_host_header_chars(target[..col]) && server::validate_host_header_structure(target) else {
        return false;
    }
    let port_num, port_ok = core::parse_port_number(target[(col + 1)..]);
    return port_ok && port_num > 0;
}

// RFC 3986 Section 3.2.2: Host - reg-name characters and valid pct-encoded triplets
fn validate_host_header_chars(host_val: const u8[:]) -> bool {
    for i in host_val.len {
        let b = host_val[i];
        guard b > 0x20 && b < 0x7F else { return false; }
        guard b != '/' && b != '?' && b != '#' && b != '@' && b != ','
            && b != '\\' && b != '<' && b != '>' && b != '"' && b != '^'
            && b != '|' && b != '`' && b != '{' && b != '}' else {
            return false;
        }
        if b == '%' {
            let rem = host_val[i..];
            guard rem.len >= 3
                && core::is_ascii_hexdigit(rem[1])
                && core::is_ascii_hexdigit(rem[2]) else {
                return false;
            }
        }
    }
    return true;
}

inline fn trim_header_value_bounds(slice: const u8[:]) -> i64, i64 {
    var start: i64 = 0;
    while start < slice.len && (slice[start] == ' ' || slice[start] == '\t') {
        start++;
    }
    var end_pos: i64 = slice.len;
    while end_pos > start && (slice[end_pos - 1] == ' ' || slice[end_pos - 1] == '\t') {
        end_pos--;
    }
    return start, end_pos;
}

fn validate_span_host_header(
    headers:  const http::HeaderMap&,
    host_idx: i16,
) -> bool {
    let idx = host_idx as i64;
    guard idx >= 0 && idx < headers.entries.len else { return false; }
    let host_val = http::entry_value(headers, headers.entries[idx]);
    guard host_val.len > 0 && validate_host_header_chars(host_val) else { return false; }
    guard server::validate_host_header_structure(host_val) else { return false; }
    return true;
}

// Validates that a Transfer-Encoding value uses only unparameterized `identity` before final
// unparameterized `chunked` when no transfer-coding decompression layer is installed.
fn validate_decodeable_chunked_te(val: const u8[:]) -> bool {
    guard http::validate_transfer_encoding_value(val) else { return false; }
    let trimmed = val.trim_lws();
    var cursor: i64 = 0;
    while cursor <= trimmed.len {
        let comma_idx = core::add_sat_i64(cursor, trimmed[cursor..].find_unquoted_byte(','));
        let piece = trimmed[cursor..comma_idx].trim_lws();
        let semi_idx = piece.find_unquoted_byte(';');
        guard semi_idx == piece.len else { return false; }
        guard piece.eq_ascii_fold("identity") || piece.eq_ascii_fold("chunked") else { return false; }
        if comma_idx == trimmed.len {
            break;
        }
        cursor = core::add_sat_i64(comma_idx, 1);
    }
    return true;
}

fn validate_span_te_header(
    headers: const http::HeaderMap&,
    te_idx:  i16,
) -> bool {
    let idx = te_idx as i64;
    guard idx >= 0 && idx < headers.entries.len else { return false; }
    let te_val = http::entry_value(headers, headers.entries[idx]);
    return validate_decodeable_chunked_te(te_val);
}

inline fn clear_request_headers_state<Req>(req: Req&) {
    req.headers.clear();
    req.presence_mask = 0;
}

inline fn has_smuggling_conflict(mask: u32) -> bool {
    let both = http::HDR_PRESENCE_TRANSFER_ENCODING | http::HDR_PRESENCE_CONTENT_LENGTH;
    return (mask & both) == both;
}

struct H1HeaderParseCache {
    enabled:          bool                        = false,
    valid_host:       u8[..128]                   = [],
    has_valid_host:   bool                        = false,
    rest_headers:     u8[..1024]                  = [],
    raw_buf:          u8[..1024]                  = [],
    entries:          http::HeaderEntry[..32]     = [],
    inline_slots:     u8[64]                      = [0xFF; 64],
    contains_comma:   bool[..32]                  = [],
    presence_mask:    u32                         = 0,
    presence_tracker: http::HeaderPresenceTracker = http::HeaderPresenceTracker { .. },
}

fn validate_request_host_presence<Req>(
    out_req:          const Req&,
    presence_tracker: const http::HeaderPresenceTracker&,
) -> bool {
    let has_host = (presence_tracker.mask & http::HDR_PRESENCE_HOST) != 0;
    if !out_req.is_http10 {
        guard has_host else { return false; }
    }
    if has_host {
        if server::g_h1_parse_cache.enabled {
            guard server::validate_span_host_header_memoized(
                out_req.headers,
                presence_tracker.host_idx,
                server::g_h1_parse_cache.valid_host,
                server::g_h1_parse_cache.has_valid_host,
            ) else {
                return false;
            }
        } else {
            guard validate_span_host_header(out_req.headers, presence_tracker.host_idx) else {
                return false;
            }
        }
    }
    return true;
}

inline fn store_parsed_header_item<Req>(
    out_req: Req&,
    hname:   const u8[:],
    hval:    const u8[:],
) -> bool {
    guard hname.len <= 256 && hval.len <= 4096 else { return false; }
    return http::append_header(out_req.headers, hname, hval);
}

inline fn advance_header_cursor(
    cursor:   i64&,
    name_len: i64,
    val_len:  i64,
    crlf_len: i64,
) {
    cursor += name_len + 1 + val_len + crlf_len;
}

// Parses a single wire header line using single-pass SWAR scanning and tchar validation.
// Advances `cursor` past the trailing CRLF delimiter.
//
// Example:
//   rest_headers = "Host: example.com\r\n\r\n", cursor = 0
//   returns: ok = true, cursor = 19 (points to final CRLF)
fn parse_http1_wire_header_line<Req>(
    rest_headers:     const u8[:],
    cursor:           i64&,
    presence_tracker: http::HeaderPresenceTracker&,
    out_req:          Req&,
    base_offset:      i64 = 0,
) -> bool {
    // Single-pass SWAR header name scanning & RFC 9110 tchar validation
    let name_len, ok_name = http::scan_header_field_name_swar(rest_headers[cursor..]);
    guard ok_name && name_len > 0 else { return false; }
    let hname = rest_headers[cursor..(cursor + name_len)];

    // Single-pass SWAR header value scanning & CTL/CRLF detection
    let val_slice = rest_headers[(cursor + name_len + 1)..];
    let val_len, crlf_len, ok_val = http::scan_header_field_value_swar(val_slice);
    guard ok_val && crlf_len == 2 else { return false; }
    let lead_ws, end_ws = trim_header_value_bounds(val_slice[..val_len]);
    let hval = val_slice[lead_ws..end_ws];

    // O(1) Header Presence & Duplicate/Smuggling Verification (uWebSockets bitmask pattern)
    let cur_hdr_idx = out_req.headers.entries.len as i16;
    let known_id = http::identify_known_header(hname);
    let saved_tracker = presence_tracker;
    let saved_mask = out_req.presence_mask;
    guard http::track_known_header_presence(presence_tracker, known_id, hval, cur_hdr_idx) else {
        return false;
    }

    out_req.presence_mask |= http::header_id_to_bit(known_id);

    guard store_parsed_header_item(out_req, hname, hval) else {
        presence_tracker = saved_tracker;
        out_req.presence_mask = saved_mask;
        return false;
    }

    advance_header_cursor(cursor, name_len, val_len, crlf_len);
    return true;
}

inline fn verify_headers_terminator_consumed(cursor: i64, total_len: i64) -> bool {
    return cursor + 2 == total_len;
}

inline fn is_headers_cache_already_loaded<Req>(out_req: const Req&) -> bool {
    guard out_req.headers.valid
        && out_req.headers.entries.len == server::g_h1_parse_cache.entries.len
        && out_req.headers.raw_buf.len == server::g_h1_parse_cache.raw_buf.len
        && out_req.presence_mask == server::g_h1_parse_cache.presence_mask else {
        return false;
    }
    return out_req.headers.raw_buf[..] == server::g_h1_parse_cache.raw_buf[..];
}

fn try_restore_cached_headers_stream<Req>(
    rest_headers:     const u8[:],
    out_req:          Req&,
    presence_tracker: http::HeaderPresenceTracker&,
) -> bool {
    guard server::g_h1_parse_cache.enabled
        && server::g_h1_parse_cache.rest_headers.len > 0
        && rest_headers == server::g_h1_parse_cache.rest_headers[..] else {
        return false;
    }
    if is_headers_cache_already_loaded(out_req) {
        presence_tracker = server::g_h1_parse_cache.presence_tracker;
        return true;
    }
    clear_request_headers_state(out_req);
    out_req.headers.raw_buf.append(server::g_h1_parse_cache.raw_buf[..]);
    out_req.headers.entries.append(server::g_h1_parse_cache.entries[..]);
    out_req.headers.inline_slots = server::g_h1_parse_cache.inline_slots;
    out_req.headers.header_contains_comma.append(server::g_h1_parse_cache.contains_comma[..]);
    out_req.presence_mask = server::g_h1_parse_cache.presence_mask;
    presence_tracker = server::g_h1_parse_cache.presence_tracker;
    return true;
}

fn save_cached_headers_stream<Req>(
    rest_headers:     const u8[:],
    out_req:          const Req&,
    presence_tracker: const http::HeaderPresenceTracker&,
) {
    guard server::g_h1_parse_cache.enabled && rest_headers.len > 0 && rest_headers.len <= 1024 else { return; }
    guard out_req.headers.raw_buf.len <= 1024 && out_req.headers.entries.len <= 32 else { return; }
    guard out_req.headers.header_contains_comma.len <= 32 else { return; }
    let _ = server::g_h1_parse_cache.rest_headers.try_set(rest_headers);
    let _ = server::g_h1_parse_cache.raw_buf.try_set(out_req.headers.raw_buf[..]);
    let _ = server::g_h1_parse_cache.entries.try_set(out_req.headers.entries[..]);
    server::g_h1_parse_cache.inline_slots = out_req.headers.inline_slots;
    let _ = server::g_h1_parse_cache.contains_comma.try_set(out_req.headers.header_contains_comma[..]);
    server::g_h1_parse_cache.presence_mask = out_req.presence_mask;
    server::g_h1_parse_cache.presence_tracker = presence_tracker;
}

// Validates HTTP/1.1 framing limits and parses the request line up to the start of headers.
//
// Example:
//   wire = "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
//   returns: rest_headers = "Host: a\r\n\r\n", base_offset = 16, ok = true, body_start_idx = 27
fn parse_http1_request_preamble<Req>(
    wire:           const u8[:],
    out_req:        Req&,
    body_start_idx: i64&,
) -> const u8[:], i64, bool {
    guard wire.len >= 4 else { return "", 0, false; }

    // RFC 9112 Section 3.1: No whitespace is allowed before the method name
    guard wire[0] != ' ' && wire[0] != '\t' else { return "", 0, false; }

    // RFC 9112 Section 2.2: A server that is expecting to receive a request-line
    // SHOULD ignore at least one empty line (CRLF) received prior to any request-line.
    // A server MUST NOT ignore more than one empty line.
    var req_offset: i64 = 0;
    if wire.len >= 2 && wire[0] == '\r' && wire[1] == '\n' {
        req_offset = 2;
        guard req_offset < wire.len else { return "", 0, false; }
        guard wire[req_offset] != '\r' && wire[req_offset] != '\n' &&
              wire[req_offset] != ' ' && wire[req_offset] != '\t' else { return "", 0, false; }
    }

    let active_wire = wire[req_offset..];

    // Find end of headers (\r\n\r\n) via AVX2 / 32-bit fast scanner
    let _pf = server::prof_enter("http1.framing");
    let hdr_end = core::fast_find_crlfcrlf(active_wire);
    server::prof_leave(_pf);
    // RFC 9112 Section 2.1 & uWS #1658: Total header block must not exceed 8192 bytes
    if hdr_end > 8192 || (hdr_end < 0 && active_wire.len > 8192) {
        return "", 0, false;
    }
    guard hdr_end >= 0 else { return "", 0, false; }
    let header_end_idx = core::add_sat_i64(hdr_end, 4);
    guard header_end_idx <= 8192 else { return "", 0, false; }
    let header_bytes = active_wire[..header_end_idx];

    // Find end of request line
    let line_end = find(header_bytes, "\r\n");
    guard line_end > 0 else { return "", 0, false; }
    guard server::parse_http1_request_line(header_bytes[..line_end], out_req) else { return "", 0, false; }

    let rest_start = core::add_sat_i64(line_end, 2);
    body_start_idx = core::add_sat_i64(req_offset, header_end_idx);
    return header_bytes[rest_start..], core::add_sat_i64(req_offset, rest_start), true;
}

// Parses HTTP/1.1 request-line and headers up to the body boundary without shrinking `out_req.body`.
// Enforces RFC 9112 Section 3.1, 3.2, 5.1 and Section 6.1 (smuggling protection).
//
// Example:
//   wire = "POST /api HTTP/1.1\r\nHost: loc\r\n\r\n..."
//   returns: ok = true, body_start_idx = 33
fn parse_http1_request_headers_fixed<Req>(
    wire:             const u8[:],
    out_req:          Req&,
    presence_tracker: http::HeaderPresenceTracker&,
    body_start_idx:   i64&,
) -> bool {
    var next_body_start: i64 = 0;
    let rest_headers, base_offset, ok_pre = parse_http1_request_preamble(wire, out_req, next_body_start);
    guard ok_pre else {
        clear_request_headers_state(out_req);
        return false;
    }

    // Parse headers
    presence_tracker = http::HeaderPresenceTracker { .. };
    guard server::parse_http1_headers_stream(rest_headers, out_req, presence_tracker, base_offset) else {
        clear_request_headers_state(out_req);
        return false;
    }

    out_req.trailers.clear();

    // RFC 9112 Section 3.2 & uWS #1949: Host header validation
    let _phv = server::prof_enter("http1.host_val");
    let ok_host = validate_request_host_presence(out_req, presence_tracker);
    server::prof_leave(_phv);
    guard ok_host else {
        clear_request_headers_state(out_req);
        return false;
    }

    // RFC 9112 Section 6.1 Smuggling Protection:
    // If both Transfer-Encoding and Content-Length are present, reject as smuggling attempt.
    if has_smuggling_conflict(presence_tracker.mask) {
        clear_request_headers_state(out_req);
        return false;
    }

    if (presence_tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0 {
        // RFC 9112 Section 6.1: Transfer-Encoding - reject Transfer-Encoding in HTTP/1.0 requests
        guard !out_req.is_http10 && validate_span_te_header(out_req.headers, presence_tracker.te_idx) else {
            clear_request_headers_state(out_req);
            return false;
        }
    }

    body_start_idx = next_body_start;
    return true;
}

// Parses HTTP/1.1 request-line and headers up to the body boundary.
// Enforces RFC 9112 Section 3.1, 3.2, 5.1 and Section 6.1 (smuggling protection).
// Returns true on valid headers, populating `presence_tracker` and `body_start_idx`.
//
// Example:
//   wire = "POST /api HTTP/1.1\r\nHost: loc\r\n\r\n..."
//   returns: ok = true, body_start_idx = 33
fn parse_http1_request_headers<Req>(
    wire:             const u8[:],
    out_req:          Req&,
    presence_tracker: http::HeaderPresenceTracker&,
    body_start_idx:   i64&,
) -> bool {
    guard parse_http1_request_headers_fixed(wire, out_req, presence_tracker, body_start_idx) else {
        return false;
    }
    out_req.body.clear();
    return true;
}

struct ResponseFramingInfo {
    has_te: bool     = false,
    te_buf: u8[..64] = [],
    has_cl: bool     = false,
    cl_len: i64      = 0,
}

// Parses raw HTTP/1.1 response header lines into header items (RFC 9112 Section 5).
//
// Parses a single HTTP/1.1 response header line using SWAR scanning and records its HeaderSpan.
// Advances `cursor` past the trailing CRLF delimiter.
//
// Example:
//   rest_headers = "Content-Type: text/plain\r\n\r\n", cursor = 0
//   returns: ok = true, cursor = 26
fn parse_http1_wire_response_header_line<Res>(
    rest_headers: const u8[:],
    cursor:       i64&,
    out_res:      Res&,
    base_offset:  i64 = 0,
) -> bool {
    let name_len, ok_name = http::scan_header_field_name_swar(rest_headers[cursor..]);
    guard ok_name && name_len > 0 else { return false; }
    let hname = rest_headers[cursor..(cursor + name_len)];

    let val_slice = rest_headers[(cursor + name_len + 1)..];
    let val_len, crlf_len, ok_val = http::scan_header_field_value_swar(val_slice);
    guard ok_val && crlf_len == 2 else { return false; }
    let lead_ws, end_ws = trim_header_value_bounds(val_slice[..val_len]);
    let hval = val_slice[lead_ws..end_ws];

    guard hname.len <= 256 && hval.len <= 4096 else { return false; }
    guard http::append_header(out_res.headers, hname, hval) else { return false; }
    advance_header_cursor(cursor, name_len, val_len, crlf_len);
    return true;
}

// Example:
//   rest_headers = "Content-Type: text/plain\r\n\r\n"
//   returns: true (out_res.headers populated)
fn parse_http1_response_headers_block<Res>(
    rest_headers: const u8[:],
    out_res:      Res&,
    base_offset:  i64 = 0,
) -> bool {
    var cursor: i64 = 0;
    out_res.headers.clear();
    while cursor < rest_headers.len {
        if rest_headers[cursor] == '\r' && cursor + 1 < rest_headers.len && rest_headers[cursor + 1] == '\n' {
            if cursor + 2 == rest_headers.len {
                return true;
            }
            out_res.headers.clear();
            return false;
        }
        guard parse_http1_wire_response_header_line(rest_headers, cursor, out_res, base_offset) else {
            out_res.headers.clear();
            return false;
        }
    }
    return true;
}

fn inspect_response_framing_headers(headers: const http::HeaderMap&) -> ResponseFramingInfo, bool {
    var info = ResponseFramingInfo { .. };
    var cl_count = 0;

    for &e in headers.entries {
        let hname = http::entry_name(headers, e);
        let hval = http::entry_value(headers, e);
        if hname.eq_ascii_fold("transfer-encoding") {
            if info.has_te {
                guard info.te_buf.len + 2 + hval.len <= info.te_buf.cap else { return info, false; }
                info.te_buf.append(", ");
                info.te_buf.append(hval);
            } else {
                info.has_te = true;
                guard info.te_buf.try_set(hval) else { return info, false; }
            }
        } else if hname.eq_ascii_fold("content-length") {
            info.has_cl = true;
            cl_count++;
            let parsed_cl, ok_cl = http::validate_content_length_value(hval);
            guard ok_cl && parsed_cl >= 0 else { return info, false; }
            if cl_count == 1 {
                info.cl_len = parsed_cl;
            } else if info.cl_len != parsed_cl {
                return info, false;
            }
        }
    }
    return info, true;
}

inline fn purge_conflicting_cl_from_response<Res>(out_res: Res&) {
    http::remove_header_by_name(out_res.headers, "content-length");
    out_res.presence_mask = detect_response_presence_mask(out_res.headers);
}

// RFC 9112 Section 4: Status Line - HTTP-version SP status-code SP [ reason-phrase ]
//
// Example:
//   status_line = "HTTP/1.1 200 OK"
//   returns: true, out_res.status_code = 200
fn parse_http1_wire_status_line<Res>(status_line: const u8[:], out_res: Res&) -> bool {
    guard status_line.len >= 12 &&
          status_line[..7] == "HTTP/1." &&
          (status_line[7] == '0' || status_line[7] == '1') &&
          status_line[8] == ' ' &&
          (status_line.len == 12 || status_line[12] == ' ') else {
        return false;
    }
    if status_line.len > 13 {
        for b in status_line[13..] {
            guard http::is_valid_header_value_byte(b) else { return false; }
        }
    }

    guard status_line[9] >= '1' && status_line[9] <= '5' &&
          status_line[10] >= '0' && status_line[10] <= '9' &&
          status_line[11] >= '0' && status_line[11] <= '9' else {
        return false;
    }
    let c0 = status_line[9] - '0';
    let c1 = status_line[10] - '0';
    let c2 = status_line[11] - '0';
    out_res.status_code = c0 as i32 * 100 + c1 as i32 * 10 + c2;
    let _ = out_res.protocol.try_set(status_line[..8]);
    return true;
}

inline fn clear_parsed_wire_response<Res>(out_res: Res&) {
    out_res.status_code = 0;
    out_res.protocol.clear();
    out_res.headers.clear();
    out_res.trailers.clear();
    out_res.body.clear();
    out_res.presence_mask = 0;
}

// Serializes an HTTP/1.1 response status line (RFC 9112 Section 4).
fn serialize_status_line<B>(status_code: i32, out: B&) {
    let pre = rfc::status_line_h1(status_code);
    if pre.len > 0 {
        out.append(pre);
        return;
    }
    out.append("HTTP/1.1 ");
    var code_buf: u8[16] = [0; 16];
    let n = core::fast_u64toa(status_code as u64, code_buf[..]);
    if n > 0 {
        out.append(code_buf[..n]);
    } else {
        status_code.format_i64_dec(out);
    }
    out.push(' ');
    out.append(rfc::status_phrase(status_code));
    out.append("\r\n");
}

fn serialize_server_header<B>(server_name: const u8[:], out: B&) {
    guard server_name.len > 0 else { return; }
    if server_name == "goose-wing" {
        out.append(server::DEFAULT_SERVER_HEADER);
        return;
    }
    out.append("Server: ");
    out.append(server_name);
    out.append("\r\n");
}

fn serialize_http1_chunked_response<Res, B>(
    res:         const Res&,
    server_name: const u8[:],
    chunk_size:  i64,
    out_wire:    B&,
) {
    serialize_status_line(res.status_code, out_wire);
    serialize_server_header(server_name, out_wire);
    if !res.has_header("date") {
        out_wire.append(server::get_cached_http_date_header(0));
    }
    out_wire.append("Transfer-Encoding: chunked\r\n");

    if res.trailers.entries.len > 0 {
        out_wire.append("Trailer: ");
        for i in res.trailers.entries.len {
            if i > 0 { out_wire.append(", "); }
            out_wire.append(http::entry_name(res.trailers, res.trailers.entries[i]));
        }
        out_wire.append("\r\n");
    }

    let has_conn = res.has_header("connection");
    for &e in res.headers.entries {
        let hname = http::entry_name(res.headers, e);
        let hval = http::entry_value(res.headers, e);
        if hname.eq_ascii_fold("content-length") { continue; }
        if hname.eq_ascii_fold("transfer-encoding") { continue; }
        if hname.eq_ascii_fold("trailer") && res.trailers.entries.len > 0 { continue; }

        out_wire.append(hname);
        out_wire.append(": ");
        out_wire.append(hval);
        out_wire.append("\r\n");
    }

    if !has_conn {
        out_wire.append("Connection: keep-alive\r\n");
    }
    out_wire.append("\r\n");

    client::encode_chunked_payload(res.body[..], res.trailers, chunk_size, out_wire);
}

const HTTP1_200_SERVER_GOOSE: const u8[:] = "HTTP/1.1 200 OK\r\nServer: goose-wing\r\n";

const HTTP1_200_SERVER_GOOSE_V1: const u8[:] = "HTTP/1.1 200 OK\r\nServer: goose-wing/1.0\r\n";

fn update_server_cached_date(
    date:        server::CachedHttpDate&,
    now_sec:     i64,
    server_name: const u8[:] = "goose-wing",
) {
    let tick_sec = if now_sec > 0 { now_sec } else { core::now().wall_sec };
    if date.header_str.len == 0 || date.last_sec != tick_sec {
        date.last_sec = tick_sec;
        date.last_tsc = server::prof_rdtsc();
        let wall_sec = if now_sec >= 1577836800 { now_sec } else { core::now().wall_sec };
        date.header_str.clear();
        date.header_str.append("Date: ");
        core::format_http(date.header_str, core::unix(wall_sec, 0));
        date.header_str.append("\r\n");

        date.fast_prefix.clear();
        date.fast_prefix.append("HTTP/1.1 200 OK\r\n");
        serialize_server_header(server_name, date.fast_prefix);
        date.fast_prefix.append(date.header_str[..]);

        date.fast_prefix_v1.clear();
        date.fast_prefix_v1.append(HTTP1_200_SERVER_GOOSE_V1);
        date.fast_prefix_v1.append(date.header_str[..]);
    }
}

var g_compat_date: server::CachedHttpDate = server::CachedHttpDate { .. };

// Formats Content-Length decimal header fast without divisions for common lengths.
const CL_HEADER_PREFIX: const u8[:] = "Content-Length: ";

fn serialize_content_length_header<B>(body_len: i64, out: B&) {
    if body_len <= 0 {
        out.append("Content-Length: 0\r\n");
        return;
    }
    var buf: u8[48] = [0; 48];
    for i in 16 {
        buf[i] = CL_HEADER_PREFIX[i];
    }
    var pos: i64 = 16;
    if body_len > 0 && body_len < 10 {
        buf[pos] = ('0' + (body_len as u8));
        pos += 1;
    } else if body_len >= 10 && body_len < 100 {
        buf[pos] = ('0' + ((body_len / 10) as u8));
        buf[pos + 1] = ('0' + ((body_len % 10) as u8));
        pos += 2;
    } else {
        let n = core::fast_u64toa(body_len as u64, buf[pos..]);
        pos += n;
    }
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;
    out.append(buf[..pos]);
}

fn detect_response_presence_mask(headers: const http::HeaderMap&) -> u16 {
    var mask: u16 = 0;
    for &e in headers.entries {
        let hname = http::entry_name(headers, e);
        let nlen = hname.len;
        if nlen == 4 {
            if (hname[0] == 'd' || hname[0] == 'D') && hname.eq_ascii_fold("date") {
                mask = mask | http::RES_PRESENCE_DATE;
            }
        } else if nlen == 6 {
            if (hname[0] == 's' || hname[0] == 'S') && hname.eq_ascii_fold("server") {
                mask = mask | http::RES_PRESENCE_SERVER;
            }
        } else if nlen == 10 {
            if (hname[0] == 'c' || hname[0] == 'C') && hname.eq_ascii_fold("connection") {
                mask = mask | http::RES_PRESENCE_CONNECTION;
            }
        } else if nlen == 12 {
            if (hname[0] == 'c' || hname[0] == 'C') && hname.eq_ascii_fold("content-type") {
                mask = mask | http::RES_PRESENCE_CONTENT_TYPE;
            }
        } else if nlen == 14 {
            if (hname[0] == 'c' || hname[0] == 'C') && hname.eq_ascii_fold("content-length") {
                mask = mask | http::RES_PRESENCE_CONTENT_LENGTH;
            }
        } else if nlen == 17 {
            if (hname[0] == 't' || hname[0] == 'T') && hname.eq_ascii_fold("transfer-encoding") {
                mask = mask | http::RES_PRESENCE_TRANSFER_ENCODING;
            }
        }
    }
    return mask;
}

fn serialize_response_headers_list<B>(headers: const http::HeaderMap&, status_code: i32, has_te: bool, out: B&) {
    // RFC 9110 §8.6: Forbid Content-Length on 1xx and 204 responses, but allow explicit Content-Length on 304 Not Modified.
    let forbid_wire_cl = (status_code >= 100 && status_code < 200) || status_code == 204;
    let is_no_te_status = forbid_wire_cl || status_code == 304;
    for &e in headers.entries {
        let hname = http::entry_name(headers, e);
        let hval = http::entry_value(headers, e);
        let nlen = hname.len;
        if (forbid_wire_cl || has_te) && nlen == 14 && hname.eq_ascii_fold("content-length") {
            continue;
        }
        if is_no_te_status && nlen == 17 && hname.eq_ascii_fold("transfer-encoding") {
            continue;
        }

        if nlen == 12 && (hname[0] == 'c' || hname[0] == 'C') && hname.eq_ascii_fold(rfc::HEADER_CONTENT_TYPE) {
            if hval == rfc::MIME_TEXT_PLAIN {
                out.append(rfc::HTTP1_CT_TEXT_PLAIN);
                continue;
            }
            if hval == rfc::MIME_APPLICATION_JSON {
                out.append(rfc::HTTP1_CT_APP_JSON);
                continue;
            }
        }

        out.append(hname);
        out.append(": ");
        out.append(hval);
        out.append("\r\n");
    }
}

fn serialize_payload_too_large_error<B>(server_name: const u8[:], wire_out: B&) {
    var err_resp = http::Response { .. };
    err_resp.status_code = 413; // Payload Too Large
    http::set_header(err_resp, "Connection", "close");
    server::serialize_http1_response(err_resp, server_name, wire_out);
}
