// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/1.1 wire request parser, status/header serializer, chunked framer, and date cache (RFC 9110, RFC 9112).
namespace wing;

import std;
import core from "..";
import rfc.http;
import rfc.h2;
import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import http.headers.perfect_hash;
import net.tcp;
import client.request;
import client.response;
import .profiler;

// ---- HTTP/1.1 Wire Request Parser ---------------------------------------

// RFC 3986 §3.2.2 & RFC 9112 §3.2: Validates structural host header integrity.
fn validate_host_header_structure(host_val: const u8[:]) -> bool {
    guard host_val.len > 0 else { return true; }
    if host_val[0] != '[' {
        for b in host_val {
            guard b != '[' && b != ']' else { return false; }
        }
        let col_idx = host_val.index_of_byte(':');
        if col_idx < 0 {
            return true;
        }
        guard col_idx > 0 else { return false; }
        let port_slice = host_val[(col_idx + 1)..];
        guard port_slice.len > 0 && port_slice.len <= 5 else { return false; }
        for pb in port_slice {
            guard pb >= '0' && pb <= '9' else { return false; }
        }
        let p_val, p_ok = port_slice.parse_u64_dec();
        return p_ok && p_val >= 1 && p_val <= 65535;
    }
    let close_idx = host_val.index_of_byte(']');
    guard close_idx > 1 else { return false; }
    var comp_buf: u8[..64] = [];
    guard core::parse_and_compress_ipv6(host_val[1..close_idx], comp_buf) else {
        return false;
    }
    if close_idx + 1 >= host_val.len {
        return true;
    }
    guard host_val[close_idx + 1] == ':' else { return false; }
    let port_part = host_val[close_idx + 2..];
    guard port_part.len > 0 && port_part.len <= 5 else { return false; }
    for pb in port_part {
        guard pb >= '0' && pb <= '9' else { return false; }
    }
    let p_num, p_ok = port_part.parse_u64_dec();
    return p_ok && p_num >= 1 && p_num <= 65535;
}

// Appends transfer-encoding header value with comma delimiter.
fn append_te_header_value(te_buf: u8[..64]&, val: const u8[:]) -> bool {
    if te_buf.len > 0 {
        guard te_buf.len + 2 + val.len <= te_buf.cap else { return false; }
        te_buf.append(", ");
        te_buf.append(val);
        return true;
    }
    return te_buf.try_append(val);
}

// Collects transfer-encoding headers into single buffer.
fn collect_transfer_encoding_headers(headers: const HeaderMap&, out_te: u8[..64]&) -> bool {
    for &hdr in headers.entries {
        if entry_name(headers, hdr).eq_ascii_fold("transfer-encoding") {
            guard append_te_header_value(out_te, entry_value(headers, hdr)) else { return false; }
        }
    }
    return true;
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

// Validates that request-target contains only visible ASCII characters (0x21..0x7E) per RFC 9112 §3.2.
fn validate_request_target_chars(path_slice: const u8[:]) -> bool {
    for b in path_slice {
        guard b >= 0x21 && b <= 0x7E else { return false; }
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
    guard validate_host_header_chars(target[..col]) && validate_host_header_structure(target) else {
        return false;
    }
    let port_num, port_ok = core::parse_port_number(target[(col + 1)..]);
    return port_ok && port_num > 0;
}

// Parses the HTTP/1.x request line (Method SP Request-URI SP HTTP-Version).
//
// Example:
//   req_line = "GET /index.html HTTP/1.1"
//   returns: true, out_req.method = "GET", out_req.url = "/index.html"
fn parse_http1_request_line<Req>(
    req_line: const u8[:],
    out_req:  Req&,
) -> bool {
    let _prof = prof_enter("http1.req_line");
    defer prof_leave(_prof);
    guard req_line.len >= 14 else { return false; }

    let w0 = core::read_le_u64(req_line, 0);
    let m_len, m_slice = match_swar_method(w0);
    var sp1:        i64  = m_len;
    var is_connect: bool = false;
    var is_options: bool = false;

    if m_len > 0 {
        let _ = out_req.method.try_set(m_slice);
        is_connect = (w0 == rfc::METHOD_CONNECT_U64);
        is_options = (w0 == rfc::METHOD_OPTIONS_U64);
    } else {
        sp1 = swar_find_space(req_line, 0);
        guard sp1 > 0 && sp1 <= out_req.method.cap else { return false; }
        let custom_method = req_line[..sp1];
        guard is_valid_header_name(custom_method) else { return false; }
        let _ = out_req.method.try_set(custom_method);
        is_connect = (custom_method == "CONNECT");
        is_options = (custom_method == "OPTIONS");
    }

    let sp2 = swar_find_space(req_line, sp1 + 1);
    guard sp2 > sp1 + 1 else { return false; }
    let path_slice = req_line[(sp1 + 1)..sp2];
    guard path_slice.len <= out_req.url.cap else { return false; }
    guard validate_request_target_chars(path_slice) else { return false; }

    if path_slice[0] == '/' {
        guard !is_connect else { return false; }
    } else if path_slice.len == 1 && path_slice[0] == '*' {
        guard is_options else { return false; }
    } else if is_connect {
        guard validate_connect_authority(path_slice) else { return false; }
    } else {
        return false;
    }

    let _ = out_req.url.try_set(path_slice);

    guard req_line.len - (sp2 + 1) == 8 else { return false; }
    let proto_u64 = core::read_le_u64(req_line, sp2 + 1);
    guard proto_u64 == rfc::HTTP_VERSION_1_1_U64 || proto_u64 == rfc::HTTP_VERSION_1_0_U64 else { return false; }
    out_req.is_http10 = (proto_u64 == rfc::HTTP_VERSION_1_0_U64);
    return true;
}

fn validate_host_header_chars(host_val: const u8[:]) -> bool {
    for b in host_val {
        guard b > 0x20 && b < 0x7F else { return false; }
        guard b != '/' && b != '?' && b != '#' && b != '@' && b != ','
            && b != '\\' && b != '<' && b != '>' && b != '"' && b != '^'
            && b != '|' && b != '`' && b != '{' && b != '}' else {
            return false;
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
    headers:  const HeaderMap&,
    host_idx: i16,
) -> bool {
    let idx = host_idx as i64;
    guard idx >= 0 && idx < headers.entries.len else { return false; }
    let host_val = entry_value(headers, headers.entries[idx]);
    guard host_val.len > 0 && validate_host_header_chars(host_val) else { return false; }
    guard validate_host_header_structure(host_val) else { return false; }
    return true;
}

// Validates the `Host` header, skipping redundant character/authority parsing when the keep-alive
// `Host` slice matches the previously validated `last_valid_host` on the connection (FastHTTP parity).
fn validate_span_host_header_memoized(
    headers:         const HeaderMap&,
    host_idx:        i16,
    last_valid_host: u8[..128]&,
    has_valid_host:  bool&,
) -> bool {
    let idx = host_idx as i64;
    guard idx >= 0 && idx < headers.entries.len else { return false; }
    let host_val = entry_value(headers, headers.entries[idx]);
    if has_valid_host && host_val == last_valid_host[..] {
        return true;
    }
    guard validate_span_host_header(headers, host_idx) else { return false; }
    if last_valid_host.try_set(host_val) {
        has_valid_host = true;
    }
    return true;
}

// Incrementally scans `active_wire` for the `\r\n\r\n` header terminator starting at `max(hdr_scan_cursor - 3, 0)`.
// Updates `hdr_scan_cursor` to `active_wire.len` if incomplete, or resets to `0` when found (FastHTTP parity).
//
// Example:
//   active_wire = "GET / HTTP/1.1\r\nHost: a\r\n\r\n", hdr_scan_cursor = 14
//   returns: 23, hdr_scan_cursor = 0
fn scan_crlfcrlf_incremental(active_wire: const u8[:], hdr_scan_cursor: i64&) -> i64 {
    let cur_val = hdr_scan_cursor;
    let clamped_cursor = min(max(cur_val, 0), active_wire.len);
    let scan_start = max(core::sub_sat_i64(clamped_cursor, 3), 0);
    let rel_idx = core::fast_find_crlfcrlf(active_wire[scan_start..]);
    if rel_idx < 0 {
        hdr_scan_cursor = active_wire.len;
        return -1;
    }
    hdr_scan_cursor = 0;
    return core::add_sat_i64(scan_start, rel_idx);
}

fn validate_span_te_header(
    headers: const HeaderMap&,
    te_idx:  i16,
) -> bool {
    let idx = te_idx as i64;
    guard idx >= 0 && idx < headers.entries.len else { return false; }
    let te_val = entry_value(headers, headers.entries[idx]);
    guard validate_transfer_encoding_value(te_val) else { return false; }
    return true;
}

inline fn clear_request_headers_state<Req>(req: Req&) {
    req.headers.clear();
    req.presence_mask = 0;
}

inline fn has_smuggling_conflict(mask: u32) -> bool {
    let both = HDR_PRESENCE_TRANSFER_ENCODING | HDR_PRESENCE_CONTENT_LENGTH;
    return (mask & both) == both;
}

var g_last_valid_host: u8[..128] = [];
var g_has_valid_host:  bool      = false;

fn validate_request_host_presence<Req>(
    out_req:          const Req&,
    presence_tracker: const HeaderPresenceTracker&,
) -> bool {
    let has_host = (presence_tracker.mask & HDR_PRESENCE_HOST) != 0;
    if !out_req.is_http10 {
        guard has_host else { return false; }
    }
    if has_host {
        guard validate_span_host_header_memoized(
            out_req.headers, presence_tracker.host_idx, g_last_valid_host, g_has_valid_host,
        ) else {
            return false;
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
    return append_header(out_req.headers, hname, hval);
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
    presence_tracker: HeaderPresenceTracker&,
    out_req:          Req&,
    base_offset:      i64 = 0,
) -> bool {
    // Single-pass SWAR header name scanning & RFC 9110 tchar validation
    let name_len, ok_name = scan_header_field_name_swar(rest_headers[cursor..]);
    guard ok_name && name_len > 0 else { return false; }
    let hname = rest_headers[cursor..(cursor + name_len)];

    // Single-pass SWAR header value scanning & CTL/CRLF detection
    let val_slice = rest_headers[(cursor + name_len + 1)..];
    let val_len, crlf_len, ok_val = scan_header_field_value_swar(val_slice);
    guard ok_val && crlf_len == 2 else { return false; }
    let lead_ws, end_ws = trim_header_value_bounds(val_slice[..val_len]);
    let hval = val_slice[lead_ws..end_ws];

    // O(1) Header Presence & Duplicate/Smuggling Verification (uWebSockets bitmask pattern)
    let cur_hdr_idx = out_req.headers.entries.len as i16;
    let known_id = identify_known_header(hname);
    guard track_known_header_presence(presence_tracker, known_id, hval, cur_hdr_idx) else {
        return false;
    }

    out_req.presence_mask |= header_id_to_bit(known_id);

    guard store_parsed_header_item(out_req, hname, hval) else {
        return false;
    }

    advance_header_cursor(cursor, name_len, val_len, crlf_len);
    return true;
}

inline fn verify_headers_terminator_consumed(cursor: i64, total_len: i64) -> bool {
    return cursor + 2 == total_len;
}

var g_last_rest_headers:     u8[..1024]            = [];
var g_last_raw_buf:          u8[..1024]            = [];
var g_last_entries:          HeaderEntry[..32]     = [];
var g_last_inline_slots:     u8[64]                = [0xFF; 64];
var g_last_contains_comma:   bool[..32]            = [];
var g_last_presence_mask:    u32                   = 0;
var g_last_presence_tracker: HeaderPresenceTracker = HeaderPresenceTracker { .. };

inline fn is_headers_cache_already_loaded<Req>(out_req: const Req&) -> bool {
    guard out_req.headers.valid
        && out_req.headers.entries.len == g_last_entries.len
        && out_req.headers.raw_buf.len == g_last_raw_buf.len
        && out_req.presence_mask == g_last_presence_mask else {
        return false;
    }
    return out_req.headers.raw_buf[..] == g_last_raw_buf[..];
}

inline fn try_restore_cached_headers_stream<Req>(
    rest_headers:     const u8[:],
    out_req:          Req&,
    presence_tracker: HeaderPresenceTracker&,
) -> bool {
    guard g_last_rest_headers.len > 0 && rest_headers == g_last_rest_headers[..] else {
        return false;
    }
    if is_headers_cache_already_loaded(out_req) {
        presence_tracker = g_last_presence_tracker;
        return true;
    }
    clear_request_headers_state(out_req);
    out_req.headers.raw_buf.append(g_last_raw_buf[..]);
    out_req.headers.entries.append(g_last_entries[..]);
    out_req.headers.inline_slots = g_last_inline_slots;
    out_req.headers.header_contains_comma.append(g_last_contains_comma[..]);
    out_req.presence_mask = g_last_presence_mask;
    presence_tracker = g_last_presence_tracker;
    return true;
}

inline fn save_cached_headers_stream<Req>(
    rest_headers:     const u8[:],
    out_req:          const Req&,
    presence_tracker: const HeaderPresenceTracker&,
) {
    guard rest_headers.len > 0 && rest_headers.len <= 1024 else { return; }
    guard out_req.headers.raw_buf.len <= 1024 && out_req.headers.entries.len <= 32 else { return; }
    guard out_req.headers.header_contains_comma.len <= 32 else { return; }
    let _ = g_last_rest_headers.try_set(rest_headers);
    let _ = g_last_raw_buf.try_set(out_req.headers.raw_buf[..]);
    let _ = g_last_entries.try_set(out_req.headers.entries[..]);
    g_last_inline_slots = out_req.headers.inline_slots;
    let _ = g_last_contains_comma.try_set(out_req.headers.header_contains_comma[..]);
    g_last_presence_mask = out_req.presence_mask;
    g_last_presence_tracker = presence_tracker;
}

// Parses raw HTTP/1.x header lines into HeaderItem entries and tracks presence bitmask.
// Uses single-pass SWAR scanning for header name, delimiter, value, and CTL validation.
//
// Example:
//   rest_headers = "Host: localhost\r\nUser-Agent: test\r\n\r\n"
//   returns: true, out_req.headers.len = 2
fn parse_http1_headers_stream<Req>(
    rest_headers:     const u8[:],
    out_req:          Req&,
    presence_tracker: HeaderPresenceTracker&,
    base_offset:      i64 = 0,
) -> bool {
    let _prof = prof_enter("http1.headers");
    defer prof_leave(_prof);
    if try_restore_cached_headers_stream(rest_headers, out_req, presence_tracker) {
        return true;
    }
    clear_request_headers_state(out_req);
    var cursor: i64 = 0;
    while cursor < rest_headers.len {
        // Empty line reached (RFC 9112 Section 2.1)
        if rest_headers[cursor] == '\r' && cursor + 1 < rest_headers.len && rest_headers[cursor + 1] == '\n' {
            break;
        }

        guard parse_http1_wire_header_line(rest_headers, cursor, presence_tracker, out_req, base_offset) else {
            return false;
        }
    }
    guard verify_headers_terminator_consumed(cursor, rest_headers.len) else {
        return false;
    }
    save_cached_headers_stream(rest_headers, out_req, presence_tracker);
    return true;
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
    let _pf = prof_enter("http1.framing");
    let hdr_end = core::fast_find_crlfcrlf(active_wire);
    prof_leave(_pf);
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
    guard parse_http1_request_line(header_bytes[..line_end], out_req) else { return "", 0, false; }

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
    presence_tracker: HeaderPresenceTracker&,
    body_start_idx:   i64&,
) -> bool {
    var next_body_start: i64 = 0;
    let rest_headers, base_offset, ok_pre = parse_http1_request_preamble(wire, out_req, next_body_start);
    guard ok_pre else {
        clear_request_headers_state(out_req);
        return false;
    }

    // Parse headers
    presence_tracker = HeaderPresenceTracker { .. };
    guard parse_http1_headers_stream(rest_headers, out_req, presence_tracker, base_offset) else {
        clear_request_headers_state(out_req);
        return false;
    }

    out_req.trailers.clear();

    // RFC 9112 Section 3.2 & uWS #1949: Host header validation
    let _phv = prof_enter("http1.host_val");
    let ok_host = validate_request_host_presence(out_req, presence_tracker);
    prof_leave(_phv);
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

    if (presence_tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0 {
        guard validate_span_te_header(out_req.headers, presence_tracker.te_idx) else {
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
    presence_tracker: HeaderPresenceTracker&,
    body_start_idx:   i64&,
) -> bool {
    guard parse_http1_request_headers_fixed(wire, out_req, presence_tracker, body_start_idx) else {
        return false;
    }
    out_req.body.clear();
    return true;
}

// Parses an incoming raw HTTP/1.1 request wire stream.
// Supports Content-Length and RFC 9112 Chunked Transfer Coding with Trailers.
// Enforces RFC 9112 Section 6.1 Smuggling Defense (TE/CL conflict detection).
// Returns (ok, total_bytes_consumed).
//
// Example:
//   wire = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
//   returns: true, consumed = 35
fn parse_http1_wire_request<Req>(wire: const u8[:], out_req: Req&) -> bool, i64 {
    var presence_tracker = HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard parse_http1_request_headers(wire, out_req, presence_tracker, body_start_idx) else {
        return false, 0;
    }

    let has_te = (presence_tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;

    var cl_len: i64 = 0;
    if has_cl {
        cl_len = presence_tracker.parsed_cl;
    }

    if has_te {
        let _pbf = prof_enter("http1.body_framing");
        defer prof_leave(_pbf);
        guard validate_span_te_header(out_req.headers, presence_tracker.te_idx) else {
            clear_request_headers_state(out_req);
            return false, 0;
        }

        let dec_err, chunked_consumed = decode_chunked_body_with_trailers(
            wire[body_start_idx..],
            out_req.body,
            out_req.trailers,
        );
        if dec_err != ChunkedDecodeError.None || out_req.body.len > MAX_SERVER_BODY_LIMIT {
            out_req.body.clear();
            out_req.trailers.clear();
            if dec_err != ChunkedDecodeError.UnexpectedEof &&
               dec_err != ChunkedDecodeError.EmptyInput &&
               dec_err != ChunkedDecodeError.None {
                clear_request_headers_state(out_req);
            }
            return false, 0;
        }

        let total_consumed = body_start_idx + chunked_consumed;
        return true, total_consumed;
    }

    // Guard against signed integer addition overflow and enforce MAX_SERVER_BODY_LIMIT (10 MB)
    guard cl_len >= 0 && cl_len <= MAX_SERVER_BODY_LIMIT && wire.len >= body_start_idx + cl_len else {
        return false, 0;
    }
    let total_consumed = body_start_idx + cl_len;

    if cl_len > 0 {
        let _pbf = prof_enter("http1.body_framing");
        out_req.body.append(wire[body_start_idx..total_consumed]);
        prof_leave(_pbf);
    }

    return true, total_consumed;
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
    let name_len, ok_name = scan_header_field_name_swar(rest_headers[cursor..]);
    guard ok_name && name_len > 0 else { return false; }
    let hname = rest_headers[cursor..(cursor + name_len)];

    let val_slice = rest_headers[(cursor + name_len + 1)..];
    let val_len, crlf_len, ok_val = scan_header_field_value_swar(val_slice);
    guard ok_val && crlf_len == 2 else { return false; }
    let lead_ws, end_ws = trim_header_value_bounds(val_slice[..val_len]);
    let hval = val_slice[lead_ws..end_ws];

    guard hname.len <= 256 && hval.len <= 4096 else { return false; }
    guard append_header(out_res.headers, hname, hval) else { return false; }
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

fn inspect_response_framing_headers(headers: const HeaderMap&) -> ResponseFramingInfo, bool {
    var info = ResponseFramingInfo { .. };
    var cl_count = 0;

    for &e in headers.entries {
        let hname = entry_name(headers, e);
        let hval = entry_value(headers, e);
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
            var parsed_cl: i64 = 0;
            let ok_cl = validate_content_length_value(hval, parsed_cl);
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
    remove_header_by_name(out_res.headers, "content-length");
    out_res.presence_mask = detect_response_presence_mask(out_res.headers);
}

// Parses an HTTP/1.1 status line and populates out_res.status_code and out_res.protocol (RFC 9112 §4).
//
// Example:
//   status_line = "HTTP/1.1 200 OK"
//   returns: true, out_res.status_code = 200
fn parse_http1_wire_status_line<Res>(status_line: const u8[:], out_res: Res&) -> bool {
    guard status_line.len >= 12 &&
          status_line[..7] == "HTTP/1." &&
          (status_line[7] == '0' || status_line[7] == '1') &&
          status_line[8] == ' ' else {
        return false;
    }
    if status_line.len > 12 {
        guard status_line[12] == ' ' else { return false; }
        for b in status_line[13..] {
            guard is_valid_header_value_byte(b) else { return false; }
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

// Parses an incoming raw HTTP/1.1 response wire stream into a Response model.
// Supports Content-Length and RFC 9112 Chunked Transfer Coding with Trailers.
// Returns (ok, total_bytes_consumed).
//
// Example:
//   wire = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
//   returns: true, consumed = 42
fn parse_http1_wire_response<Res>(wire: const u8[:], out_res: Res&) -> bool, i64 {
    guard wire.len >= 4 else { return false, 0; }

    let hdr_end = core::fast_find_crlfcrlf(wire);
    guard hdr_end >= 0 && hdr_end + 4 <= 8192 else { return false, 0; }
    let header_end_idx = hdr_end + 4;
    let header_bytes = wire[..header_end_idx];

    let line_end = find(header_bytes, "\r\n");
    guard line_end > 0 else { return false, 0; }
    guard parse_http1_wire_status_line(header_bytes[..line_end], out_res) else { return false, 0; }

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    guard parse_http1_response_headers_block(rest_headers, out_res, line_end + 2) else { return false, 0; }

    out_res.trailers.clear();
    out_res.body.clear();
    out_res.presence_mask = detect_response_presence_mask(out_res.headers);

    let framing, ok_frame = inspect_response_framing_headers(out_res.headers);
    guard ok_frame else { return false, 0; }

    let is_empty_status = rfc::is_empty_body_status(out_res.status_code);

    // RFC 9112 Section 6.1 & RFC 7230 §3.3.3: In responses, Transfer-Encoding overrides Content-Length.
    // If Transfer-Encoding is present, it MUST be valid and chunked MUST be final; invalid TE must reject.
    if framing.has_te {
        guard validate_transfer_encoding_value(framing.te_buf[..]) else { return false, 0; }
        // RFC 9112 Section 6.1: An intermediary or recipient processing chunked MUST remove Content-Length
        if framing.has_cl {
            purge_conflicting_cl_from_response(out_res);
        }
        // RFC 9112 §6.3 Rule 1: 1xx, 204, and 304 responses NEVER have a message body
        if is_empty_status {
            return true, header_end_idx;
        }
        let dec_err, chunked_consumed = decode_chunked_body_with_trailers(
            wire[header_end_idx..],
            out_res.body,
            out_res.trailers,
        );
        guard dec_err == ChunkedDecodeError.None else { return false, 0; }
        return true, header_end_idx + chunked_consumed;
    }

    // Status 204 No Content, 304 Not Modified, or 1xx: MUST NOT include message body
    if is_empty_status {
        return true, header_end_idx;
    }

    if framing.has_cl {
        guard framing.cl_len >= 0 && framing.cl_len <= 0x7FFFFFFF && wire.len >= header_end_idx + framing.cl_len else {
            return false, 0;
        }
        if framing.cl_len > 0 {
            out_res.body.append(wire[header_end_idx..(header_end_idx + framing.cl_len)]);
        }
        return true, header_end_idx + framing.cl_len;
    }

    // Otherwise, consume remainder of stream until connection close
    if wire.len > header_end_idx {
        out_res.body.append(wire[header_end_idx..]);
    }
    return true, wire.len;
}

// ---- HTTP/1.1 Wire Response Serializer -----------------------------------

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
        (status_code as i64).format_i64_dec(out);
    }
    out.push(' ');
    out.append(rfc::status_phrase(status_code));
    out.append("\r\n");
}

const DEFAULT_SERVER_HEADER: const u8[:] = "Server: goose-wing\r\n";

fn serialize_server_header<B>(server_name: const u8[:], out: B&) {
    guard server_name.len > 0 else { return; }
    if server_name == "goose-wing" {
        out.append(DEFAULT_SERVER_HEADER);
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
        out_wire.append(get_cached_http_date_header(0));
    }
    out_wire.append("Transfer-Encoding: chunked\r\n");

    if res.trailers.entries.len > 0 {
        out_wire.append("Trailer: ");
        for i in res.trailers.entries.len {
            if i > 0 { out_wire.append(", "); }
            out_wire.append(entry_name(res.trailers, res.trailers.entries[i]));
        }
        out_wire.append("\r\n");
    }

    let has_conn = res.has_header("connection");
    for &e in res.headers.entries {
        let hname = entry_name(res.headers, e);
        let hval = entry_value(res.headers, e);
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

    encode_chunked_payload(res.body[..], res.trailers, chunk_size, out_wire);
}

// ---- Cached RFC 7231 Date Header (uWebSockets LoopData::date pattern) ------

const HTTP1_200_SERVER_GOOSE:    const u8[:] = "HTTP/1.1 200 OK\r\nServer: goose-wing\r\n";
const HTTP1_200_SERVER_GOOSE_V1: const u8[:] = "HTTP/1.1 200 OK\r\nServer: goose-wing/1.0\r\n";

// Formats the Date header at most once per second into a reusable pre-baked string.
// Eliminates repetitive wall-clock system calls and calendar math for every HTTP response.
struct CachedHttpDate {
    header_str:     u8[..64]  = [],
    fast_prefix:    u8[..160] = [],
    fast_prefix_v1: u8[..128] = [],
    last_sec:       i64       = 0,
    last_tsc:       u64       = 0,
}

fn update_server_cached_date(
    date:        CachedHttpDate&,
    now_sec:     i64,
    server_name: const u8[:] = "goose-wing",
) {
    let tick_sec = if now_sec > 0 { now_sec } else { core::now().wall_sec };
    if date.header_str.len == 0 || date.last_sec != tick_sec {
        date.last_sec = tick_sec;
        date.last_tsc = prof_rdtsc();
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

fn format_local_http_date(out: u8[..64]&, now_sec: i64) {
    let _ = out.try_set(get_cached_http_date_header(now_sec));
}

var g_compat_date: CachedHttpDate = CachedHttpDate { .. };

fn get_cached_http_date_header(now_sec: i64 = 0) -> const u8[:] {
    update_server_cached_date(g_compat_date, now_sec);
    return g_compat_date.header_str[..];
}

// Formats Content-Length decimal header fast without divisions for common lengths.
const CL_HEADER_PREFIX: const u8[:] = "Content-Length: ";

fn serialize_content_length_header<B>(body_len: i64, out: B&) {
    if body_len <= 0 {
        out.append("Content-Length: 0\r\n");
        return;
    }
    if body_len == 13 {
        out.append("Content-Length: 13\r\n");
        return;
    }
    if body_len == 27 {
        out.append("Content-Length: 27\r\n");
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

fn detect_response_presence_mask(headers: const HeaderMap&) -> u16 {
    var mask: u16 = 0;
    for &e in headers.entries {
        let hname = entry_name(headers, e);
        let nlen = hname.len;
        if nlen == 4 {
            if (hname[0] == 'd' || hname[0] == 'D') && hname.eq_ascii_fold("date") {
                mask = mask | RES_PRESENCE_DATE;
            }
        } else if nlen == 6 {
            if (hname[0] == 's' || hname[0] == 'S') && hname.eq_ascii_fold("server") {
                mask = mask | RES_PRESENCE_SERVER;
            }
        } else if nlen == 10 {
            if (hname[0] == 'c' || hname[0] == 'C') && hname.eq_ascii_fold("connection") {
                mask = mask | RES_PRESENCE_CONNECTION;
            }
        } else if nlen == 12 {
            if (hname[0] == 'c' || hname[0] == 'C') && hname.eq_ascii_fold("content-type") {
                mask = mask | RES_PRESENCE_CONTENT_TYPE;
            }
        } else if nlen == 14 {
            if (hname[0] == 'c' || hname[0] == 'C') && hname.eq_ascii_fold("content-length") {
                mask = mask | RES_PRESENCE_CONTENT_LENGTH;
            }
        } else if nlen == 17 {
            if (hname[0] == 't' || hname[0] == 'T') && hname.eq_ascii_fold("transfer-encoding") {
                mask = mask | RES_PRESENCE_TRANSFER_ENCODING;
            }
        }
    }
    return mask;
}

fn serialize_response_headers_list<B>(headers: const HeaderMap&, status_code: i32, has_te: bool, out: B&) {
    // RFC 9110 §8.6: Forbid Content-Length on 1xx and 204 responses, but allow explicit Content-Length on 304 Not Modified.
    let forbid_wire_cl = (status_code >= 100 && status_code < 200) || status_code == 204;
    let is_no_te_status = forbid_wire_cl || status_code == 304;
    for &e in headers.entries {
        let hname = entry_name(headers, e);
        let hval = entry_value(headers, e);
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

// Serializes only the HTTP/1.1 response status line and headers into out_wire,
// omitting the body. Used for zero-copy vectored transmission via tcp_send2.
fn serialize_http1_headers<Res, B>(
    res:               const Res&,
    server_name:       const u8[:],
    out_wire:          B&,
    now_sec:           i64 = 0,
    override_body_len: i64 = -1,
) {
    let date_hdr = get_cached_http_date_header(now_sec);
    let eff_body_len = if override_body_len >= 0 { override_body_len } else { res.body.len };

    var mask = res.presence_mask;
    if mask == 0 && res.headers.entries.len > 0 {
        mask = detect_response_presence_mask(res.headers);
    }

    let is_default_srv = server_name == "goose-wing" || server_name == "goose-wing/1.0";
    if res.status_code == 200 && is_default_srv {
        if mask == RES_PRESENCE_CONTENT_TYPE && res.headers.entries.len == 1 && res.trailers.entries.len == 0
            && entry_name(res.headers, res.headers.entries[0]).eq_ascii_fold("content-type")
        {
            if server_name == "goose-wing" {
                out_wire.append(g_compat_date.fast_prefix[..]);
            } else {
                out_wire.append(g_compat_date.fast_prefix_v1[..]);
            }
            serialize_content_length_header(eff_body_len, out_wire);
            let h0_name = entry_name(res.headers, res.headers.entries[0]);
            let h0_val = entry_value(res.headers, res.headers.entries[0]);
            if h0_val == rfc::MIME_TEXT_PLAIN {
                out_wire.append(rfc::HTTP1_CT_TEXT_PLAIN);
            } else if h0_val == rfc::MIME_APPLICATION_JSON {
                out_wire.append(rfc::HTTP1_CT_APP_JSON);
            } else {
                out_wire.append(h0_name);
                out_wire.append(": ");
                out_wire.append(h0_val);
                out_wire.append("\r\n");
            }
            out_wire.append(rfc::HTTP1_CONN_KEEP_ALIVE);
            return;
        }
    }
    if res.status_code == 200 && is_default_srv && (mask & (RES_PRESENCE_SERVER | RES_PRESENCE_DATE)) == 0 {
        if server_name == "goose-wing" {
            out_wire.append(g_compat_date.fast_prefix[..]);
        } else {
            out_wire.append(g_compat_date.fast_prefix_v1[..]);
        }
    } else {
        if res.status_code == 200 && server_name == "goose-wing" && (mask & RES_PRESENCE_SERVER) == 0 {
            out_wire.append(HTTP1_200_SERVER_GOOSE);
        } else {
            serialize_status_line(res.status_code, out_wire);
            if (mask & RES_PRESENCE_SERVER) == 0 {
                serialize_server_header(server_name, out_wire);
            }
        }

        // Emit RFC 7231 Date header if not explicitly overridden by response
        if (mask & RES_PRESENCE_DATE) == 0 {
            out_wire.append(date_hdr);
        }
    }

    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    let has_te = (mask & RES_PRESENCE_TRANSFER_ENCODING) != 0;
    if !is_empty_status {
        if (mask & RES_PRESENCE_CONTENT_LENGTH) == 0 && !has_te {
            serialize_content_length_header(eff_body_len, out_wire);
        }
    }

    serialize_response_headers_list(res.headers, res.status_code, has_te, out_wire);

    let has_conn = (mask & RES_PRESENCE_CONNECTION) != 0;
    if !has_conn {
        out_wire.append(rfc::HTTP1_CONN_KEEP_ALIVE);
    } else {
        out_wire.append("\r\n");
    }
}

// Serializes a complete HTTP/1.1 response into raw wire bytes.
// Automatically uses chunked transfer encoding if Transfer-Encoding: chunked is requested or if trailers are present.
fn serialize_http1_response<Res, B>(
    res:         const Res&,
    server_name: const u8[:],
    out_wire:    B&,
    now_sec:     i64 = 0,
) {
    let _prof = prof_enter("http1.resp_serialize");
    defer prof_leave(_prof);
    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    if !is_empty_status {
        if res.trailers.entries.len > 0 {
            serialize_http1_chunked_response(res, server_name, 4096, out_wire);
            return;
        }
        let has_te = if res.presence_mask != 0 {
            (res.presence_mask & RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else if res.headers.entries.len > 0 {
            (detect_response_presence_mask(res.headers) & RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else {
            false
        };
        if has_te {
            let te = header(res, "transfer-encoding");
            if te.eq_ascii_fold("chunked") {
                serialize_http1_chunked_response(res, server_name, 4096, out_wire);
                return;
            }
        }
    }

    serialize_http1_headers(res, server_name, out_wire, now_sec);

    // RFC 9110 §8.6 & Go #81642 / uWS #1370: Status 204, 304, and 1xx MUST NOT emit a message body on wire
    if res.body.len > 0 && !is_empty_status {
        out_wire.append(res.body[..]);
    }
}

// Sends an HTTP/1.1 response over a TCP socket using zero-copy Vectored I/O (tcp_send2 / WSASend / writev).
// Headers are serialized into wire_headers, and res.body is transmitted directly without copying into headers.
fn send_http1_response<Res, B>(fd: i64, res: const Res&, server_name: const u8[:], wire_headers: B&) -> i32 {
    wire_headers.clear();
    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    if !is_empty_status {
        let has_te = if res.presence_mask != 0 {
            (res.presence_mask & RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else if res.headers.entries.len > 0 {
            (detect_response_presence_mask(res.headers) & RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else {
            false
        };
        if has_te || res.trailers.entries.len > 0 {
            let te = header(res, "transfer-encoding");
            if te.eq_ascii_fold("chunked") || res.trailers.entries.len > 0 {
                serialize_http1_chunked_response(res, server_name, 4096, wire_headers);
                return tcp_send(fd, wire_headers[..]);
            }
        }
    }

    serialize_http1_headers(res, server_name, wire_headers);
    if res.body.len == 0 || is_empty_status {
        return tcp_send(fd, wire_headers[..]);
    }
    return tcp_send2(fd, wire_headers[..], res.body[..]);
}

// Sends an HTTP/1.1 response where the payload is provided as an IoVecArray of up to 15 chunks,
// prepending wire headers zero-copy via tcp_sendv (WSASend / writev).
fn send_http1_response_iov<Res, B>(
    fd:           i64,
    res:          const Res&,
    server_name:  const u8[:],
    body_iov:     const core::IoVecArray&,
    wire_headers: B&,
) -> i32 {
    wire_headers.clear();
    let n = body_iov.iovec_count();
    var iov_total: i64 = 0;
    for i in n {
        let chunk = body_iov.iovec_get(i);
        iov_total += chunk.len;
    }
    let ov_len = if res.body.len == 0 && iov_total > 0 { iov_total } else { -1 };
    serialize_http1_headers(res, server_name, wire_headers, 0, ov_len);
    guard fd > 0 else { return 0; }
    var arr = core::new_iovec_array();
    arr.iovec_push(wire_headers[..]);
    var total_sent: i32 = 0;
    for i in n {
        let chunk = body_iov.iovec_get(i);
        if chunk.len > 0 {
            if arr.iovec_count() >= 16 {
                let sent = tcp_sendv(fd, arr);
                guard sent >= 0 else { return sent; }
                total_sent += sent;
                arr = core::new_iovec_array();
            }
            arr.iovec_push(chunk);
        }
    }
    if arr.iovec_count() > 0 {
        let sent = tcp_sendv(fd, arr);
        guard sent >= 0 else { return sent; }
        total_sent += sent;
    }
    return total_sent;
}

// Ends the response without emitting a body payload (RFC 9110 §9.3.2 / §15.4.5 & uWebSockets endWithoutBody pattern).
// Serializes headers with an optional reported Content-Length (e.g. for HEAD requests or 304 Not Modified).
// If `close_connection` is true, sets Connection: close.
fn end_without_body<Res, B>(
    res:                     Res&,
    server_name:             const u8[:],
    out_wire:                B&,
    reported_content_length: i64  = -1,
    close_connection:        bool = false,
) {
    if reported_content_length >= 0 {
        var len_buf: u8[..32] = [];
        reported_content_length.format_i64_dec(len_buf);
        set_header(res, "Content-Length", len_buf[..]);
    }
    if close_connection {
        set_header(res, "Connection", "close");
    }
    serialize_http1_headers(res, server_name, out_wire);
}

// Sends an HTTP/1.1 response without body directly over a socket descriptor
// (uWebSockets endWithoutBody socket pattern).
fn send_http1_end_without_body<Res, B>(
    fd:                      i64,
    res:                     Res&,
    server_name:             const u8[:],
    wire_headers:            B&,
    reported_content_length: i64  = -1,
    close_connection:        bool = false,
) -> i32 {
    wire_headers.clear();
    end_without_body(res, server_name, wire_headers, reported_content_length, close_connection);
    guard fd > 0 else { return 0; }
    return tcp_send(fd, wire_headers[..]);
}

fn is_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len >= 24 && raw_stream[..24] == rfc::H2_CLIENT_PREFACE[..];
}

// True while a short read is still a strict prefix of the 24-byte H2 preface.
// The preface contains "\r\n\r\n" at offset 14, so a sliced first TCP segment
// must not fall through to the HTTP/1.1 parser (found by Toxiproxy SlicerToxic).
fn is_partial_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len > 0 && raw_stream.len < 24 && raw_stream == rfc::H2_CLIENT_PREFACE[..raw_stream.len];
}

const MAX_SERVER_BODY_LIMIT: i64 = 10 * 1024 * 1024; // 10 MB payload limit

fn serialize_payload_too_large_error<B>(server_name: const u8[:], wire_out: B&) {
    var err_resp = Response { .. };
    err_resp.status_code = 413; // Payload Too Large
    set_header(err_resp, "Connection", "close");
    serialize_http1_response(err_resp, server_name, wire_out);
}

fn serialize_bad_request_error<B>(server_name: const u8[:], wire_out: B&) {
    var err_resp = Response { .. };
    err_resp.status_code = 400; // Bad Request
    serialize_http1_response(err_resp, server_name, wire_out);
}
