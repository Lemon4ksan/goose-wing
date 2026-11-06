// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone zero-allocation HTTP server engine, wire protocol serializer, and connection coordinator.
// Conforms to RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1 Framing), and RFC 9113 (HTTP/2 Preface Detection).
namespace wing;

import std;
import core from "..";
import .router;
import .pool;
import .pipeline;
import .h2_multiplexer;
import .soa_timer;
import realtime.topic_tree;
import http.compression_dict;

// ---- HTTP/1.1 Wire Request Parser ---------------------------------------

// RFC 3986 §3.2.2 & RFC 9112 §3.2: Validates structural host header integrity.
fn validate_host_header_structure(host_val: const u8[:]) -> bool {
    guard host_val.len > 0 else { return true; }
    if host_val[0] != '[' {
        for b in host_val {
            guard b != '[' && b != ']' else { return false; }
        }
        let col_idx = core::index_of_byte(host_val, ':');
        if col_idx < 0 {
            return true;
        }
        guard col_idx > 0 else { return false; }
        let port_slice = host_val[(col_idx + 1)..];
        guard port_slice.len > 0 && port_slice.len <= 5 else { return false; }
        for pb in port_slice {
            guard pb >= '0' && pb <= '9' else { return false; }
        }
        let p_val, p_ok = core::parse_u64_dec(port_slice);
        return p_ok && p_val <= 65535;
    }
    let close_idx = core::index_of_byte(host_val, ']');
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
    let p_num, p_ok = core::parse_u64_dec(port_part);
    return p_ok && p_num <= 65535;
}

// Appends transfer-encoding header value with comma delimiter.
fn append_te_header_value(te_buf: u8[..64]&, val: const u8[:]) -> bool {
    if te_buf.len > 0 {
        guard te_buf.len + 2 + val.len <= te_buf.cap else { return false; }
        te_buf.append(", ");
        te_buf.append(val);
        return true;
    }
    guard val.len <= te_buf.cap else { return false; }
    te_buf.append(val);
    return true;
}

// Collects transfer-encoding headers into single buffer.
fn collect_transfer_encoding_headers<H>(headers: const H&, out_te: u8[..64]&) -> bool {
    for &hdr in headers {
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
            guard append_te_header_value(out_te, hdr.value[..]) else { return false; }
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
        let close_idx = core::index_of_byte(target, ']');
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
    let col = core::index_of_byte(target, ':');
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
    guard req_line.len >= 14 else { return false; }

    let w0 = core::read_le_u64(req_line, 0);
    let m_len, m_slice = match_swar_method(w0);
    var sp1:        i64  = m_len;
    var is_connect: bool = false;
    var is_options: bool = false;

    if m_len > 0 {
        out_req.method.clear();
        out_req.method.append(m_slice);
        is_connect = (w0 == rfc::METHOD_CONNECT_U64);
        is_options = (w0 == rfc::METHOD_OPTIONS_U64);
    } else {
        sp1 = swar_find_space(req_line, 0);
        guard sp1 > 0 && sp1 <= out_req.method.cap else { return false; }
        let custom_method = req_line[..sp1];
        guard is_valid_header_name(custom_method) else { return false; }
        out_req.method.clear();
        out_req.method.append(custom_method);
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

    out_req.url.clear();
    out_req.url.append(path_slice);

    guard req_line.len - (sp2 + 1) == 8 else { return false; }
    let proto_u64 = core::read_le_u64(req_line, sp2 + 1);
    guard proto_u64 == rfc::HTTP_VERSION_1_1_U64 || proto_u64 == rfc::HTTP_VERSION_1_0_U64 else { return false; }
    out_req.is_http10 = (proto_u64 == rfc::HTTP_VERSION_1_0_U64);
    return true;
}

fn validate_host_header_chars(host_val: const u8[:]) -> bool {
    for b in host_val {
        guard b != '/' && b != '?' && b != '#' && b != '@' && b != ',' && b != ' ' && b != '\t' else {
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

fn validate_request_host_presence<Req>(
    out_req:          const Req&,
    presence_tracker: const HeaderPresenceTracker&,
) -> bool {
    let has_host = (presence_tracker.mask & HDR_PRESENCE_HOST) != 0;
    if !out_req.is_http10 {
        guard has_host else { return false; }
    }
    if has_host {
        guard validate_span_host_header(out_req.headers, presence_tracker.host_idx) else {
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
    return verify_headers_terminator_consumed(cursor, rest_headers.len);
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
    guard wire.len >= 4 else { return false; }

    // RFC 9112 Section 3.1: No whitespace is allowed before the method name
    guard wire[0] != ' ' && wire[0] != '\t' else { return false; }

    // RFC 9112 Section 2.2: A server that is expecting to receive a request-line
    // SHOULD ignore at least one empty line (CRLF) received prior to any request-line.
    // A server MUST NOT ignore more than one empty line.
    var req_offset: i64 = 0;
    if wire.len >= 2 && wire[0] == '\r' && wire[1] == '\n' {
        req_offset = 2;
        guard req_offset < wire.len else { return false; }
        guard wire[req_offset] != '\r' && wire[req_offset] != '\n' &&
              wire[req_offset] != ' ' && wire[req_offset] != '\t' else { return false; }
    }

    let active_wire = wire[req_offset..];

    // Find end of headers (\r\n\r\n) via AVX2 / 32-bit fast scanner
    let hdr_end = core::fast_find_crlfcrlf(active_wire);
    // RFC 9112 Section 2.1 & uWS #1658: Total header block must not exceed 8192 bytes
    if hdr_end > 8192 || (hdr_end < 0 && active_wire.len > 8192) {
        return false;
    }
    guard hdr_end >= 0 else { return false; }
    let header_end_idx = hdr_end + 4;
    guard header_end_idx <= 8192 else { return false; }
    let header_bytes = active_wire[..header_end_idx];

    // Find end of request line
    let line_end = find(header_bytes, "\r\n");
    guard line_end > 0 else { return false; }
    guard parse_http1_request_line(header_bytes[..line_end], out_req) else { return false; }

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    clear_request_headers_state(out_req);
    presence_tracker = HeaderPresenceTracker { .. };
    let base_offset = req_offset + line_end + 2;
    guard parse_http1_headers_stream(rest_headers, out_req, presence_tracker, base_offset) else {
        clear_request_headers_state(out_req);
        return false;
    }

    out_req.trailers.clear();
    out_req.body.clear();

    // RFC 9112 Section 3.2 & uWS #1949: Host header validation
    guard validate_request_host_presence(out_req, presence_tracker) else {
        clear_request_headers_state(out_req);
        return false;
    }

    // RFC 9112 Section 6.1 Smuggling Protection:
    // If both Transfer-Encoding and Content-Length are present, reject as smuggling attempt.
    if has_smuggling_conflict(presence_tracker.mask) {
        clear_request_headers_state(out_req);
        return false;
    }

    body_start_idx = req_offset + header_end_idx;
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
        guard validate_span_te_header(out_req.headers, presence_tracker.te_idx) else {
            clear_request_headers_state(out_req);
            return false, 0;
        }

        let dec_err, chunked_consumed = decode_chunked_body_with_trailers(
            wire[body_start_idx..],
            out_req.body,
            out_req.trailers,
        );
        if dec_err != ChunkedDecodeError.None {
            out_req.body.clear();
            out_req.trailers.clear();
            if dec_err != ChunkedDecodeError.UnexpectedEof {
                clear_request_headers_state(out_req);
            }
            return false, 0;
        }

        let total_consumed = body_start_idx + chunked_consumed;
        return true, total_consumed;
    }

    // Guard against signed integer addition overflow
    guard cl_len >= 0 && cl_len <= 0x7FFFFFFF && wire.len >= body_start_idx + cl_len else { return false, 0; }
    let total_consumed = body_start_idx + cl_len;

    if cl_len > 0 {
        out_req.body.append(wire[body_start_idx..total_consumed]);
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
        if eq_ascii_fold(hname, "transfer-encoding") {
            if info.has_te {
                guard info.te_buf.len + 2 + hval.len <= info.te_buf.cap else { return info, false; }
                info.te_buf.append(", ");
                info.te_buf.append(hval);
            } else {
                info.has_te = true;
                guard hval.len <= info.te_buf.cap else { return info, false; }
                info.te_buf.append(hval);
            }
        } else if eq_ascii_fold(hname, "content-length") {
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
    out_res.protocol.clear();
    out_res.protocol.append(status_line[..8]);
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
    guard hdr_end >= 0 && hdr_end <= 8192 else { return false, 0; }
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
        core::format_i64_dec(status_code as i64, out);
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
        if eq_ascii_fold(hname, "content-length") { continue; }
        if eq_ascii_fold(hname, "transfer-encoding") { continue; }
        if eq_ascii_fold(hname, "trailer") && res.trailers.entries.len > 0 { continue; }

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

const HTTP1_200_SERVER_GOOSE: const u8[:] = "HTTP/1.1 200 OK\r\nServer: goose-wing\r\n";
const HTTP1_CT_TEXT_PLAIN:    const u8[:] = "Content-Type: text/plain\r\n";
const HTTP1_CT_APP_JSON:      const u8[:] = "Content-Type: application/json\r\n";
const HTTP1_CONN_KEEP_ALIVE:  const u8[:] = "Connection: keep-alive\r\n\r\n";

// Formats the Date header at most once per second into a reusable pre-baked string.
// Eliminates repetitive wall-clock system calls and calendar math for every HTTP response.
struct CachedHttpDate {
    header_str:  u8[..64]  = [],
    fast_prefix: u8[..128] = [],
    last_sec:    i64       = 0,
    last_tsc:    u64       = 0,
}

fn update_server_cached_date(date: CachedHttpDate&, now_sec: i64) {
    let wall_sec = if now_sec > 0 { now_sec } else { core::now().wall_sec };
    if date.header_str.len == 0 || date.last_sec != wall_sec {
        date.last_sec = wall_sec;
        date.last_tsc = prof_rdtsc();
        date.header_str.clear();
        date.header_str.append("Date: ");
        core::format_http(date.header_str, core::unix(wall_sec, 0));
        date.header_str.append("\r\n");

        date.fast_prefix.clear();
        date.fast_prefix.append(HTTP1_200_SERVER_GOOSE);
        date.fast_prefix.append(date.header_str[..]);
    }
}

fn format_local_http_date(out: u8[..64]&, now_sec: i64) {
    out.clear();
    out.append(get_cached_http_date_header(now_sec));
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
            if (hname[0] == 'd' || hname[0] == 'D') && eq_ascii_fold(hname, "date") {
                mask = mask | RES_PRESENCE_DATE;
            }
        } else if nlen == 10 {
            if (hname[0] == 'c' || hname[0] == 'C') && eq_ascii_fold(hname, "connection") {
                mask = mask | RES_PRESENCE_CONNECTION;
            }
        } else if nlen == 12 {
            if (hname[0] == 'c' || hname[0] == 'C') && eq_ascii_fold(hname, "content-type") {
                mask = mask | RES_PRESENCE_CONTENT_TYPE;
            }
        } else if nlen == 14 {
            if (hname[0] == 'c' || hname[0] == 'C') && eq_ascii_fold(hname, "content-length") {
                mask = mask | RES_PRESENCE_CONTENT_LENGTH;
            }
        } else if nlen == 17 {
            if (hname[0] == 't' || hname[0] == 'T') && eq_ascii_fold(hname, "transfer-encoding") {
                mask = mask | RES_PRESENCE_TRANSFER_ENCODING;
            }
        }
    }
    return mask;
}

fn serialize_response_headers_list<B>(headers: const HeaderMap&, is_empty_status: bool, out: B&) {
    for &e in headers.entries {
        let hname = entry_name(headers, e);
        let hval = entry_value(headers, e);
        let nlen = hname.len;
        if is_empty_status {
            let is_suppressed = (nlen == 14 && eq_ascii_fold(hname, "content-length"))
                || (nlen == 17 && eq_ascii_fold(hname, "transfer-encoding"));
            if is_suppressed {
                continue;
            }
        }

        if nlen == 12 && (hname[0] == 'c' || hname[0] == 'C') && eq_ascii_fold(hname, "content-type") {
            if hval == "text/plain" {
                out.append("Content-Type: text/plain\r\n");
                continue;
            }
            if hval == "application/json" {
                out.append("Content-Type: application/json\r\n");
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
        if mask == RES_PRESENCE_CONTENT_TYPE && res.headers.entries.len == 1 && res.trailers.entries.len == 0 {
            if server_name == "goose-wing" {
                out_wire.append(g_compat_date.fast_prefix[..]);
            } else {
                out_wire.append("HTTP/1.1 200 OK\r\nServer: goose-wing/1.0\r\n");
                out_wire.append(date_hdr);
            }
            serialize_content_length_header(eff_body_len, out_wire);
            let h0_name = entry_name(res.headers, res.headers.entries[0]);
            let h0_val = entry_value(res.headers, res.headers.entries[0]);
            if h0_val == "text/plain" {
                out_wire.append(HTTP1_CT_TEXT_PLAIN);
            } else if h0_val == "application/json" {
                out_wire.append(HTTP1_CT_APP_JSON);
            } else {
                out_wire.append(h0_name);
                out_wire.append(": ");
                out_wire.append(h0_val);
                out_wire.append("\r\n");
            }
            out_wire.append(HTTP1_CONN_KEEP_ALIVE);
            return;
        }
    }
    if res.status_code == 200 && server_name == "goose-wing" {
        out_wire.append(HTTP1_200_SERVER_GOOSE);
    } else {
        serialize_status_line(res.status_code, out_wire);
        serialize_server_header(server_name, out_wire);
    }

    // Emit RFC 7231 Date header if not explicitly overridden by response
    if (mask & RES_PRESENCE_DATE) == 0 {
        out_wire.append(date_hdr);
    }

    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    if !is_empty_status {
        if (mask & RES_PRESENCE_CONTENT_LENGTH) == 0 && (mask & RES_PRESENCE_TRANSFER_ENCODING) == 0 {
            serialize_content_length_header(eff_body_len, out_wire);
        }
    }

    serialize_response_headers_list(res.headers, is_empty_status, out_wire);

    let has_conn = (mask & RES_PRESENCE_CONNECTION) != 0;
    if !has_conn {
        out_wire.append(HTTP1_CONN_KEEP_ALIVE);
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
            if eq_ascii_fold(te, "chunked") {
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
            if eq_ascii_fold(te, "chunked") || res.trailers.entries.len > 0 {
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
    let n = core::iovec_count(body_iov);
    var iov_total: i64 = 0;
    for i in n {
        let chunk = core::iovec_get(body_iov, i);
        iov_total += chunk.len;
    }
    let ov_len = if res.body.len == 0 && iov_total > 0 { iov_total } else { -1 };
    serialize_http1_headers(res, server_name, wire_headers, 0, ov_len);
    guard fd > 0 else { return 0; }
    var arr = core::new_iovec_array();
    core::iovec_push(arr, wire_headers[..]);
    for i in n {
        let chunk = core::iovec_get(body_iov, i);
        if chunk.len > 0 {
            core::iovec_push(arr, chunk);
        }
    }
    return tcp_sendv(fd, arr);
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
        core::format_i64_dec(reported_content_length, len_buf);
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

// Outbound Cork Buffer Manager for TCP connections (uWebSockets 16 KB Cork Buffer pattern).
// Aggregates headers, frames, and small payload chunks into a single 16384-byte buffer
// before flushing via 1 system call.
struct ServerCork {
    buffer:  core::CorkBuffer = core::new_cork_buffer(),
    sock_fd: i64              = -1,
}

fn new_server_cork(fd: i64) -> ServerCork {
    return ServerCork {
        buffer:  core::new_cork_buffer(),
        sock_fd: fd,
    };
}

// Writes data into the cork buffer. If it fits, data is buffered without any syscall.
// If the buffer would overflow, pending data is flushed first, then data is buffered or sent directly.
fn server_cork_write(sc: ServerCork&, data: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 && data.len > 0 else { return 0; }
    let avail = core::cork_available(sc.buffer);
    if data.len <= avail {
        let written, _ = core::cork_write(sc.buffer, data);
        return written as i32;
    }

    // Buffer would overflow: flush current pending bytes first
    let flushed = server_cork_flush(sc);
    guard flushed >= 0 && core::cork_is_empty(sc.buffer) else { return -1; }

    if data.len >= core::CORK_BUFFER_CAP {
        // Larger than cork buffer: send directly via TCP
        return tcp_send(sc.sock_fd, data);
    }

    let written, _ = core::cork_write(sc.buffer, data);
    return written as i32;
}

// Writes two contiguous slices (e.g. headers and body) directly into the cork buffer
// without combining them into an intermediate buffer first (zero-copy vectored buffering).
fn server_cork_write2(sc: ServerCork&, head: const u8[:], body: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return 0; }
    let total_len = head.len + body.len;
    guard total_len > 0 else { return 0; }

    let avail = core::cork_available(sc.buffer);
    if total_len <= avail {
        if head.len > 0 { let _ = core::cork_write(sc.buffer, head); }
        if body.len > 0 { let _ = core::cork_write(sc.buffer, body); }
        return total_len as i32;
    }

    let flushed = server_cork_flush(sc);
    guard flushed >= 0 && core::cork_is_empty(sc.buffer) else { return -1; }

    if total_len >= core::CORK_BUFFER_CAP {
        if head.len > 0 && body.len > 0 {
            return tcp_send2(sc.sock_fd, head, body);
        }
        if head.len > 0 {
            return tcp_send(sc.sock_fd, head);
        }
        return tcp_send(sc.sock_fd, body);
    }

    if head.len > 0 { let _ = core::cork_write(sc.buffer, head); }
    if body.len > 0 { let _ = core::cork_write(sc.buffer, body); }
    return total_len as i32;
}

fn write_cork_chunked_response_stream<Res>(sc: ServerCork&, res: const Res&, server_name: const u8[:]) -> i32 {
    if res.body.len <= 8192 {
        var wire_out: u8[..16384] = [];
        serialize_http1_chunked_response(res, server_name, 4096, wire_out);
        return server_cork_write(sc, wire_out[..]);
    }
    var empty_res = Response {
        status_code:   res.status_code,
        headers:       res.headers,
        trailers:      res.trailers,
        presence_mask: res.presence_mask,
        ..
    };
    var hdr_wire: u8[..8192] = [];
    serialize_http1_chunked_response(empty_res, server_name, 4096, hdr_wire);
    let term_idx = core::fast_find_crlfcrlf(hdr_wire[..]);
    guard term_idx >= 0 else { return -1; }
    let hdr_sent = server_cork_write(sc, hdr_wire[..(term_idx + 4)]);
    guard hdr_sent >= 0 else { return -1; }
    var total_written: i32 = hdr_sent;
    var off:           i64 = 0;
    while off < res.body.len {
        let chunk_n = min(res.body.len - off, 4096);
        var chunk_hdr: u8[..32] = [];
        core::format_u64_hex(chunk_n as u64, chunk_hdr);
        chunk_hdr.append("\r\n");
        let w1 = server_cork_write2(sc, chunk_hdr[..], res.body[off..(off + chunk_n)]);
        guard w1 >= 0 else { return -1; }
        let w2 = server_cork_write(sc, "\r\n");
        guard w2 >= 0 else { return -1; }
        total_written += w1 + w2;
        off += chunk_n;
    }
    let tail_slice = hdr_wire[(term_idx + 4)..];
    let w_tail = server_cork_write(sc, tail_slice);
    guard w_tail >= 0 else { return -1; }
    return total_written + w_tail;
}

// Serializes and writes an HTTP/1.1 response into the cork buffer.
// Zero-copy: formats headers in a small stack buffer and writes headers + body
// directly into the cork buffer or socket via vectored I/O without intermediate body copies.
fn server_cork_write_response<Res>(sc: ServerCork&, res: const Res&, server_name: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return 0; }
    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    let te = header(res, "transfer-encoding");
    if !is_empty_status && (eq_ascii_fold(te, "chunked") || res.trailers.entries.len > 0) {
        return write_cork_chunked_response_stream(sc, res, server_name);
    }

    var hdr_buf: u8[..8192] = [];
    serialize_http1_headers(res, server_name, hdr_buf);
    if res.body.len == 0 || is_empty_status {
        return server_cork_write(sc, hdr_buf[..]);
    }
    return server_cork_write2(sc, hdr_buf[..], res.body[..]);
}

// Flushes all pending data in the cork buffer to the socket in a single syscall.
fn server_cork_flush(sc: ServerCork&) -> i32 {
    guard sc.sock_fd > 0 && !core::cork_is_empty(sc.buffer) else { return 0; }
    return tcp_flush_cork(sc.sock_fd, sc.buffer);
}

// State of a streaming HTTP/1.1 request body consumer (uWebSockets onData / onDataV2 pattern)
struct HttpStreamConsumer {
    content_length:    i64  = -1,
    bytes_received:    i64  = 0,
    header_end_idx:    i64  = 0,
    is_chunked:        bool = false,
    is_headers_parsed: bool = false,
    is_finished:       bool = false,
}

// Parses request headers and prepares a streaming body reader without buffering the entire body.
// Returns (ok, header_end_offset).
fn begin_http_stream_request<Req>(
    wire:     const u8[:],
    out_req:  Req&,
    consumer: HttpStreamConsumer&,
) -> bool, i64 {
    consumer.is_headers_parsed = false;
    consumer.is_finished = false;
    consumer.bytes_received = 0;

    var tracker = HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard parse_http1_request_headers(wire, out_req, tracker, body_start_idx) else {
        return false, 0;
    }

    consumer.header_end_idx = body_start_idx;
    consumer.is_headers_parsed = true;

    let has_te = (tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;

    if has_te {
        guard validate_span_te_header(out_req.headers, tracker.te_idx) else {
            consumer.is_headers_parsed = false;
            clear_request_headers_state(out_req);
            return false, 0;
        }
        consumer.is_chunked = true;
        consumer.content_length = -1;
    } else if has_cl {
        consumer.is_chunked = false;
        consumer.content_length = tracker.parsed_cl;
        if consumer.content_length == 0 {
            consumer.is_finished = true;
        }
    } else {
        consumer.is_chunked = false;
        consumer.content_length = 0;
        consumer.is_finished = true;
    }

    return true, body_start_idx;
}

inline fn peek_terminal_zero_chunk(incoming: const u8[:], cursor: i64&) -> bool {
    guard cursor < incoming.len else { return false; }
    var peek_cur = cursor;
    var next_sz: u64 = 1;
    let next_err = read_chunk_size_line(incoming, peek_cur, next_sz);
    guard next_err == ChunkedDecodeError.None && next_sz == 0 else { return false; }
    let tr_err = parse_chunked_trailers(incoming, peek_cur);
    guard tr_err == ChunkedDecodeError.None else { return false; }
    cursor = peek_cur;
    return true;
}

inline fn feed_fixed_length_http_stream(
    consumer: HttpStreamConsumer&,
    incoming: const u8[:],
) -> i64, bool, bool {
    let remaining = consumer.content_length - consumer.bytes_received;
    guard remaining > 0 else {
        consumer.is_finished = true;
        return 0, true, true;
    }

    let chunk_len = min(incoming.len, remaining);
    consumer.bytes_received += chunk_len;
    let is_last = consumer.bytes_received >= consumer.content_length;
    if is_last {
        consumer.is_finished = true;
    }
    return chunk_len, is_last, true;
}

// Steps one frame of a chunked HTTP stream at `cursor`, returning `(data_slice, has_data, is_last, ok)`.
// On partial input (`UnexpectedEof`), returns `has_data = false, is_last = false, ok = true` and leaves `cursor`
// at the start of the incomplete chunk.
//
// Example:
//   incoming = "5\r\nhello\r\n0\r\n\r\n", cursor = 0
//   returns: data_slice = "hello", has_data = true, is_last = true, ok = true, cursor = 15
fn step_chunked_http_stream_frame(
    consumer: HttpStreamConsumer&,
    incoming: const u8[:],
    cursor:   i64&,
) -> const u8[:], bool, bool, bool {
    let chunk_start = cursor;
    var chunk_size: u64 = 0;
    let line_err = read_chunk_size_line(incoming, cursor, chunk_size);
    if line_err == ChunkedDecodeError.UnexpectedEof {
        cursor = chunk_start;
        return "", false, false, true;
    }
    guard line_err == ChunkedDecodeError.None && chunk_size <= (MAX_SERVER_BODY_LIMIT as u64) else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    if chunk_size == 0 {
        let tr_err = parse_chunked_trailers(incoming, cursor);
        if tr_err == ChunkedDecodeError.UnexpectedEof {
            cursor = chunk_start;
            return "", false, false, true;
        }
        guard tr_err == ChunkedDecodeError.None else {
            cursor = chunk_start;
            return "", false, false, false;
        }
        consumer.is_finished = true;
        return "", false, true, true;
    }
    let csize = chunk_size as i64;
    if cursor + csize + 2 > incoming.len {
        cursor = chunk_start;
        return "", false, false, true;
    }
    guard incoming[cursor + csize] == '\r' && incoming[cursor + csize + 1] == '\n' else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    guard consumer.bytes_received + csize <= MAX_SERVER_BODY_LIMIT else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    let data_slice = incoming[cursor..(cursor + csize)];
    cursor += csize + 2;
    consumer.bytes_received += csize;

    let finished_now = peek_terminal_zero_chunk(incoming, cursor);
    if finished_now {
        consumer.is_finished = true;
    }
    return data_slice, true, finished_now, true;
}

// Feeds incoming wire slice chunks to an onData callback (uWebSockets onData(chunk, is_last) pattern).
// Invokes `Callback(chunk, is_last)` as data arrives across packet boundaries.
// Returns (consumed_bytes, is_last, ok).
fn feed_http_stream_chunk<Callback: fn(const u8[:], bool)>(
    consumer: HttpStreamConsumer&,
    incoming: const u8[:],
) -> i64, bool, bool {
    guard consumer.is_headers_parsed && !consumer.is_finished else { return 0, false, false; }
    guard incoming.len > 0 else { return 0, false, true; }

    if consumer.content_length >= 0 {
        let chunk_len, is_last, ok = feed_fixed_length_http_stream(consumer, incoming);
        if chunk_len > 0 {
            Callback(incoming[..chunk_len], is_last);
        }
        return chunk_len, is_last, ok;
    }

    var cursor: i64 = 0;
    while cursor < incoming.len {
        let data_slice, has_data, is_last, ok = step_chunked_http_stream_frame(consumer, incoming, cursor);
        guard ok else { return cursor, false, false; }
        if has_data {
            Callback(data_slice, is_last);
        }
        if is_last || !has_data {
            return cursor, is_last, true;
        }
    }
    return cursor, false, true;
}

// Connection lifecycle context for asynchronous streaming backpressure and abort notifications
// (uWebSockets res->onWritable & res->onAborted pattern).
struct HttpAsyncContext {
    sock_fd:          i64  = -1,
    is_aborted:       bool = false,
    is_backpressured: bool = false,
    total_written:    u64  = 0,
    user_tag:         u64  = 0,
    in_use:           bool = false,
}

// Dispatches a client abort event if the client disconnected during async processing
fn notify_client_aborted<Callback: fn(i64, u64)>(
    ctx: HttpAsyncContext&,
) {
    if !ctx.is_aborted && ctx.in_use {
        ctx.is_aborted = true;
        Callback(ctx.sock_fd, ctx.user_tag);
    }
}

// Dispatches a writable notification when socket drains after backpressure (uWebSockets onWritable)
fn notify_socket_writable<Callback: fn(i64, u64, u64) -> bool>(
    ctx: HttpAsyncContext&,
) -> bool {
    guard ctx.in_use && !ctx.is_aborted else { return false; }
    let ok = Callback(ctx.sock_fd, ctx.total_written, ctx.user_tag);
    if ok {
        ctx.is_backpressured = false;
    }
    return ok;
}

// ---- HttpServer Container and Session Coordinator -----------------------

// Dynamic Runtime SNI multi-certificate credentials (uWebSockets addServerName / removeServerName pattern).
struct SniCertEntry {
    pattern:  u8[..128]  = [],
    cert_pem: u8[..4096] = [],
    key_pem:  u8[..4096] = [],
    in_use:   bool       = false,
}

const MAX_SNI_DOMAINS: i64 = 32;

struct SniRegistry {
    entries: SniCertEntry[32] = [SniCertEntry { .. }; 32],
    count:   i32              = 0,
}

struct SniCredentials {
    cert_pem: const u8[:] = "",
    key_pem:  const u8[:] = "",
}

struct WsRouteEntry {
    path:     u8[..128]  = [],
    behavior: WsBehavior = WsBehavior { .. },
    in_use:   bool       = false,
}

struct HttpServer {
    pipeline:              ServerPipelineConfig      = ServerPipelineConfig { .. },
    host:                  u8[..256]                 = "127.0.0.1",
    port:                  u16                       = 8080,
    server_name:           u8[..64]                  = "goose-wing/1.0",
    timer:                 internal::ConnectionTimer = internal::ConnectionTimer { .. },
    is_running:            bool                      = false,
    requests_processed:    u64                       = 0,
    accept_proxy_protocol: bool                      = false,
    trust_proxy_headers:   bool                      = false,
    topic_tree:            TopicTree                 = TopicTree { .. },
    ws_routes:             WsRouteEntry[..16]        = [WsRouteEntry { .. }; 16],
    ws_route_count:        i32                       = 0,
    shared_compressor:     SharedWsCompressor        = SharedWsCompressor { .. },
    sni_registry:          SniRegistry               = SniRegistry { .. },
    worker_ring:           core::SpscRing            = core::SpscRing { .. },
    cached_date:           CachedHttpDate            = CachedHttpDate { .. },
}

inline fn refresh_http_server_date(server: HttpServer&, now_sec: i64) {
    update_server_cached_date(server.cached_date, now_sec);
}

fn new_http_server(
    host_str: const u8[:] = "127.0.0.1",
    port_num: u16         = 8080,
) -> HttpServer {
    var server = HttpServer {
        pipeline:           new_default_server_pipeline_config(host_str),
        port:               port_num,
        timer:              internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running:         true,
        requests_processed: 0,
        ..
    };
    let _ = server.host.try_set(host_str[..min(host_str.len, 256)]);
    return server;
}

fn new_http_server_with_quota<Q>(
    host_str: const u8[:],
    port_num: u16,
    quota:    Q,
) -> HttpServer {
    var server = HttpServer {
        pipeline:           new_server_pipeline_config(host_str, quota),
        port:               port_num,
        timer:              internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running:         true,
        requests_processed: 0,
        ..
    };
    let _ = server.host.try_set(host_str[..min(host_str.len, 256)]);
    return server;
}

// Registers routing handlers on the server instance
fn add_get_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "GET", path, handler_id);
}

// Registers a pre-rendered static GET route for zero-copy line-rate delivery
fn add_static_get_route(
    server:       HttpServer&,
    path:         const u8[:],
    content_type: const u8[:],
    body:         const u8[:],
    handler_id:   i32 = 0,
) {
    let _ = add_static_route(server.pipeline.router, "GET", path, content_type, body, handler_id);
}

fn add_post_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "POST", path, handler_id);
}

fn add_put_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "PUT", path, handler_id);
}

fn add_delete_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "DELETE", path, handler_id);
}

// Registers a declarative WebSocket route on the server instance (uWebSockets app.ws pattern)
fn add_ws_route(server: HttpServer&, path: const u8[:], behavior: const WsBehavior& = WsBehavior { .. }) -> bool {
    guard path.len > 0 && path.len <= 128 && server.ws_route_count < server.ws_routes.len as i32 else { return false; }
    var canon_path: u8[..128] = [];
    guard canonicalize_route_path(path, canon_path) else { return false; }
    for i in server.ws_routes.len {
        if !server.ws_routes[i].in_use {
            let _ = server.ws_routes[i].path.try_set(canon_path[..]);
            server.ws_routes[i].behavior = behavior;
            server.ws_routes[i].in_use = true;
            server.ws_route_count += 1;
            add_get_route(server, canon_path[..], behavior.handler_id);
            return true;
        }
    }
    return false;
}

fn find_ws_route(server: const HttpServer&, path: const u8[:]) -> i32 {
    var canon_path: u8[..256] = [];
    guard canonicalize_route_path(path, canon_path) else { return -1; }
    for i in server.ws_routes.len {
        if server.ws_routes[i].in_use && server.ws_routes[i].path[..] == canon_path[..] {
            return i as i32;
        }
    }
    return -1;
}

// ---- Dynamic Runtime SNI Multi-Certificate Engine (uWebSockets app.addServerName pattern) ----

// Matches a hostname against an SNI domain pattern (RFC 6125 §6.4.3 & uWebSockets pattern).
// Supports exact domains ("example.com") and wildcard patterns ("*.example.com").
// Case-insensitive.
fn sni_pattern_matches(pattern: const u8[:], hostname: const u8[:]) -> bool {
    let p_norm = x509_strip_trailing_dot(pattern);
    let h_norm = x509_strip_trailing_dot(hostname);
    guard p_norm.len > 0 && h_norm.len > 0 else { return false; }
    if eq_ascii_fold(p_norm, h_norm) {
        return true;
    }
    if p_norm.len >= 3 && p_norm[0] == '*' && p_norm[1] == '.' {
        return match_dns_san(p_norm, h_norm);
    }
    return false;
}

// Registers or updates an SNI domain pattern with certificate and private key credentials.
// Supports exact domains and wildcard patterns (uWebSockets app.addServerName).
fn add_server_name(
    server:   HttpServer&,
    pattern:  const u8[:],
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> bool {
    let p_norm = x509_strip_trailing_dot(pattern);
    guard p_norm.len > 0 && p_norm.len <= 128 else { return false; }
    guard cert_pem.len > 0 && cert_pem.len <= 4096 && key_pem.len > 0 && key_pem.len <= 4096 else {
        return false;
    }

    // Check if pattern already registered: update in place
    for i in server.sni_registry.entries.len {
        let entry_pat = x509_strip_trailing_dot(server.sni_registry.entries[i].pattern[..]);
        if server.sni_registry.entries[i].in_use && eq_ascii_fold(entry_pat, p_norm) {
            let _ = server.sni_registry.entries[i].cert_pem.try_set(cert_pem);
            let _ = server.sni_registry.entries[i].key_pem.try_set(key_pem);
            return true;
        }
    }

    // Find first empty slot
    guard server.sni_registry.count < server.sni_registry.entries.len as i32 else { return false; }
    for i in server.sni_registry.entries.len {
        if !server.sni_registry.entries[i].in_use {
            let _ = server.sni_registry.entries[i].pattern.try_set(p_norm);
            let _ = server.sni_registry.entries[i].cert_pem.try_set(cert_pem);
            let _ = server.sni_registry.entries[i].key_pem.try_set(key_pem);
            server.sni_registry.entries[i].in_use = true;
            server.sni_registry.count += 1;
            return true;
        }
    }
    return false;
}

// Removes a previously registered SNI domain pattern (uWebSockets app.removeServerName).
fn remove_server_name(server: HttpServer&, pattern: const u8[:]) -> bool {
    let p_norm = x509_strip_trailing_dot(pattern);
    guard p_norm.len > 0 && server.sni_registry.count > 0 else { return false; }
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        if entry.in_use && eq_ascii_fold(x509_strip_trailing_dot(entry.pattern[..]), p_norm) {
            entry.in_use = false;
            entry.pattern.clear();
            entry.cert_pem.clear();
            entry.key_pem.clear();
            server.sni_registry.count -= 1;
            return true;
        }
    }
    return false;
}

// Resolves TLS credentials for an SNI hostname using exact match first, then wildcard (RFC 6125 §6.4.3).
// Returns (SniCredentials, ok).
fn resolve_sni_credentials(
    server:       const HttpServer&,
    sni_hostname: const u8[:],
) -> SniCredentials, bool {
    let h_norm = x509_strip_trailing_dot(sni_hostname);
    guard server.sni_registry.count > 0 && h_norm.len > 0 else {
        return SniCredentials { .. }, false;
    }

    // Phase 1: Exact match priority
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        if entry.in_use && eq_ascii_fold(x509_strip_trailing_dot(entry.pattern[..]), h_norm) {
            return SniCredentials {
                cert_pem: entry.cert_pem[..],
                key_pem:  entry.key_pem[..],
            }, true;
        }
    }

    // Phase 2: Wildcard match (*.domain.com)
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        guard entry.in_use else { continue; }
        let pat = x509_strip_trailing_dot(entry.pattern[..]);
        guard pat.len >= 3 && pat[0] == '*' && pat[1] == '.' else { continue; }
        if match_dns_san(pat, h_norm) {
            return SniCredentials {
                cert_pem: entry.cert_pem[..],
                key_pem:  entry.key_pem[..],
            }, true;
        }
    }

    return SniCredentials { .. }, false;
}

// Resolves TLS credentials for an SNI hostname with fallback handler for missing server names
// (uWebSockets app.missingServerName pattern).
fn resolve_sni_credentials_with_fallback<Fallback: fn(const u8[:]) -> SniCredentials>(
    server:       const HttpServer&,
    sni_hostname: const u8[:],
) -> SniCredentials, bool {
    let creds, ok = resolve_sni_credentials(server, sni_hostname);
    if ok { return creds, true; }
    let fb_creds = Fallback(sni_hostname);
    if fb_creds.cert_pem.len > 0 {
        return fb_creds, true;
    }
    return SniCredentials { .. }, false;
}

// ---- Server Pub/Sub Broadcast Engine (uWebSockets TopicTree pattern) --------

fn publish(server: HttpServer&, topic: const u8[:], message: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64 {
    return publish(server.topic_tree, topic, message, opcode);
}

fn publish_text(server: HttpServer&, topic: const u8[:], text: const u8[:]) -> i64 {
    return publish_text(server.topic_tree, topic, text);
}

fn publish_binary(server: HttpServer&, topic: const u8[:], data: const u8[:]) -> i64 {
    return publish_binary(server.topic_tree, topic, data);
}

fn subscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
    return subscribe(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
    return unsubscribe(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_all(server: HttpServer&, sock_fd: i64) -> i32 {
    return unsubscribe_all(server.topic_tree, sock_fd);
}

fn find_subscribers(server: const HttpServer&, topic: const u8[:], out_fds: i64[..512]&) -> i64 {
    return find_subscribers(server.topic_tree, topic, out_fds);
}

fn subscribe_ex(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
    out_old:       i32&,
    out_new:       i32&,
) -> bool {
    return subscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn unsubscribe_ex(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
    out_old:       i32&,
    out_new:       i32&,
) -> bool {
    return unsubscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
) -> bool {
    return subscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server:        HttpServer&,
    sock_fd:       i64,
    topic_pattern: const u8[:],
) -> bool {
    return unsubscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_all_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(server: HttpServer&, sock_fd: i64) -> i32 {
    return unsubscribe_all_with_hook<HookFn>(server.topic_tree, sock_fd);
}

fn get_socket_topic_count(server: const HttpServer&, sock_fd: i64) -> i32 {
    return socket_subscription_count(server.topic_tree, sock_fd);
}

fn get_socket_topics(server: const HttpServer&, sock_fd: i64, out_topics: u8[..64][..32]&) -> i32 {
    return get_socket_topics(server.topic_tree, sock_fd, out_topics);
}

fn iterate_socket_topics<IterFn: fn(const u8[:])>(server: const HttpServer&, sock_fd: i64) -> i32 {
    return iterate_socket_topics<IterFn>(server.topic_tree, sock_fd);
}

// Asynchronous WebSocket Upgrade helpers (uWebSockets res->onAborted & res->upgrade pattern)
fn defer_ws_upgrade(
    server:  const HttpServer&,
    req:     const Request&,
    sock_fd: i64,
) -> WsPendingUpgrade, bool {
    guard is_websocket_upgrade_request(req) else {
        return WsPendingUpgrade { .. }, false;
    }
    let r_idx = find_ws_route(server, req.url[..]);
    guard r_idx >= 0 else {
        return WsPendingUpgrade { .. }, false;
    }
    let client_key = req.headers.find_header("Sec-WebSocket-Key");
    guard is_valid_websocket_key(client_key) else {
        return WsPendingUpgrade { .. }, false;
    }
    let subprotocol = req.headers.find_header("Sec-WebSocket-Protocol");
    let extensions = req.headers.find_header("Sec-WebSocket-Extensions");
    guard subprotocol.len <= 64 && extensions.len <= 64 else {
        return WsPendingUpgrade { .. }, false;
    }

    var pending = new_ws_pending_upgrade(sock_fd, client_key, r_idx, subprotocol, extensions);
    return pending, true;
}

inline fn serialize_and_init_ws_upgrade<B>(
    route_behavior: const WsBehavior&,
    pending:        WsPendingUpgrade&,
    subproto:       const u8[:],
    out_wire:       B&,
) -> WebSocketSession, bool {
    var session = new_websocket_session(false);
    guard subproto.len <= session.subprotocol.cap && pending.user_data.len <= session.user_data.cap else {
        return WebSocketSession { .. }, false;
    }

    var accept_key: u8[..64] = [];
    compute_websocket_accept(pending.client_key[..], accept_key);

    let prev_out_len = out_wire.len;
    out_wire.append("HTTP/1.1 101 Switching Protocols\r\n");
    out_wire.append("Upgrade: websocket\r\n");
    out_wire.append("Connection: Upgrade\r\n");
    out_wire.append("Sec-WebSocket-Accept: ");
    out_wire.append(accept_key[..]);
    out_wire.append("\r\n");
    var expected_add: i64 = 97 + accept_key.len;

    if subproto.len > 0 {
        out_wire.append("Sec-WebSocket-Protocol: ");
        out_wire.append(subproto);
        out_wire.append("\r\n");
        expected_add += 26 + subproto.len;
    }

    let compress_active = route_behavior.compression != WS_COMPRESS_DISABLED
        && core::contains_fold(pending.extensions[..], "permessage-deflate");
    if compress_active {
        out_wire.append("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n");
        expected_add += 74;
    }

    out_wire.append("\r\n");
    expected_add += 2;
    guard out_wire.len == prev_out_len + expected_add else {
        return WebSocketSession { .. }, false;
    }

    session.compress_mode = route_behavior.compression;
    session.permessage_deflate = compress_active;
    session.max_payload_length = route_behavior.max_payload_length;
    session.max_backpressure = route_behavior.max_backpressure;
    session.close_on_backpressure_limit = route_behavior.close_on_backpressure_limit;
    session.idle_timeout_s = route_behavior.idle_timeout_s;
    session.max_lifetime_s = route_behavior.max_lifetime_s;
    session.send_pings_automatically = route_behavior.send_pings_automatically;
    session.reset_idle_timeout_on_send = route_behavior.reset_idle_timeout_on_send;

    if subproto.len > 0 {
        session.subprotocol.append(subproto);
    }
    session.user_tag = pending.user_tag;
    if pending.user_data.len > 0 {
        session.user_data.append(pending.user_data[..]);
    }

    pending.in_use = false;
    return session, true;
}

fn complete_ws_upgrade<B>(
    server:   HttpServer&,
    pending:  WsPendingUpgrade&,
    out_wire: B&,
) -> WebSocketSession, bool {
    guard pending.in_use && !pending.is_aborted else {
        return WebSocketSession { .. }, false;
    }

    let route_behavior = if pending.route_idx >= 0 && pending.route_idx < server.ws_routes.len as i32 {
        server.ws_routes[pending.route_idx as i64].behavior
    } else {
        WsBehavior { .. }
    };

    let has_subproto = route_behavior.subprotocol.len > 0
        && pending.subprotocol.len > 0
        && has_subprotocol_token(pending.subprotocol[..], route_behavior.subprotocol[..]);
    let subproto = if has_subproto {
        route_behavior.subprotocol[..]
    } else {
        ""
    };

    return serialize_and_init_ws_upgrade(route_behavior, pending, subproto, out_wire);
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

// Checks whether request or response demands connection closure (RFC 9112 §9.3 & NGINX proxy_pass harmony).
// Applies "Connection: close" to response headers if close is requested or for HTTP/1.0 without keep-alive.
fn check_and_apply_connection_close(req: const Request&, res: Response&) -> bool {
    guard res.status_code != 101 else { return false; }
    let has_conn_hdr = has_header(req, "connection") ||
        (res.presence_mask & RES_PRESENCE_CONNECTION) != 0;
    if !has_conn_hdr && !req.is_http10 && req.method[0] != 'C' {
        return false;
    }
    let req_conn = header(req, "connection");
    let res_conn = header(res, "connection");
    let wants_close = req.method[..] == "CONNECT" ||
        core::contains_fold(req_conn, "close") ||
        (req.is_http10 && !core::contains_fold(req_conn, "keep-alive")) ||
        core::contains_fold(res_conn, "close");
    if wants_close {
        set_header(res, "Connection", "close");
        return true;
    }
    return false;
}

fn complete_ws_upgrade<Req, B>(
    server:   HttpServer&,
    req:      const Req&,
    entry:    const WebSocketRoute&,
    wire_out: B&,
) -> bool {
    let subproto = entry.behavior.subprotocol[..];
    var ws_res = Response { .. };
    var sess, ok_upg = ws_upgrade_request(req, ws_res, subproto);
    guard ok_upg else { return false; }

    sess.max_payload_length = entry.behavior.max_payload_length;
    sess.max_backpressure = entry.behavior.max_backpressure;
    sess.close_on_backpressure_limit = entry.behavior.close_on_backpressure_limit;
    sess.idle_timeout_s = entry.behavior.idle_timeout_s;
    sess.max_lifetime_s = entry.behavior.max_lifetime_s;
    sess.send_pings_automatically = entry.behavior.send_pings_automatically;
    sess.reset_idle_timeout_on_send = entry.behavior.reset_idle_timeout_on_send;

    let ua_upg = req.header("user-agent");
    let allow_comp = entry.behavior.compression == WS_COMPRESS_SHARED_COMPRESSOR
        && !ws_has_broken_compression(ua_upg);
    if allow_comp {
        let client_ext = req.header("sec-websocket-extensions");
        if core::contains_fold(client_ext, "permessage-deflate") {
            ws_res.set_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover");
            enable_permessage_deflate(sess, WS_COMPRESS_SHARED_COMPRESSOR);
        }
    }
    serialize_http1_response(ws_res, server.server_name[..], wire_out);
    server.requests_processed++;
    return true;
}

// Processes an incoming raw connection payload, performing protocol detection (H1 vs H2 preface),
// executing the server pipeline, and serializing the wire response.
fn handle_connection_wire<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
) -> PipelineOutcome, bool {
    wire_out.clear();

    var effective_ip: u8[..64] = [];
    let _ = effective_ip.try_set(client_ip[..min(client_ip.len, 64)]);
    var raw_stream = wire_in;

    if server.accept_proxy_protocol {
        var proxy_hdr = ProxyHeader { .. };
        let is_proxy = detect_proxy_protocol(wire_in);
        if is_proxy != ProxyProtocolVersion.None {
            let stripped, has_proxy = detect_and_strip_proxy_header(wire_in, proxy_hdr);
            guard has_proxy else {
                serialize_bad_request_error(server.server_name[..], wire_out);
                return PipelineOutcome.Handled, false;
            }
            raw_stream = stripped;
            if proxy_hdr.src_ip_str.len > 0 {
                effective_ip.clear();
                effective_ip.append(proxy_hdr.src_ip_str[..]);
            }
        } else {
            // uWS #1927 / HAProxy spec: When PROXY protocol is required, connections
            // without a valid PROXY preface MUST NOT fall through to plain HTTP.
            serialize_bad_request_error(server.server_name[..], wire_out);
            return PipelineOutcome.Handled, false;
        }
    }

    if is_h2_client_preface(raw_stream) {
        if server.trust_proxy_headers {
            server.pipeline.trust_proxy_headers = true;
        }
        let now_ms = (now_ns / 1000000) as u64;
        var sess = internal::new_h2_server_session(server.server_name[..], now_ms);
        defer internal::cleanup_h2_server_session(sess, server.pipeline);
        let _, ok_h2 = internal::handle_h2_server_ingress(
            sess, server.pipeline, server.timer, effective_ip[..], raw_stream, now_ms, wire_out,
        );
        if ok_h2 {
            server.requests_processed++;
            return PipelineOutcome.Handled, true;
        }
        return PipelineOutcome.Handled, false;
    }

    var req = new_request("GET", "");
    let ok_parse, _ = parse_http1_wire_request(raw_stream, req);
    guard ok_parse else {
        serialize_bad_request_error(server.server_name[..], wire_out);
        return PipelineOutcome.Handled, false;
    }

    // WebSocket Upgrade Interception (uWebSockets app.ws pattern)
    if is_websocket_upgrade_request(req) {
        let ws_idx = find_ws_route(server, req.url[..]);
        if ws_idx >= 0 && complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out) {
            return PipelineOutcome.Handled, true;
        }
    }

    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }

    var res = Response { .. };
    var future = internal::new_inline_handler_future(0);
    let outcome = execute_pipeline(server.pipeline, server.timer, effective_ip[..], req, now_ns, res, future);

    check_and_apply_connection_close(req, res);

    serialize_http1_response(res, server.server_name[..], wire_out);
    server.requests_processed++;

    return outcome, true;
}

fn is_possible_http_method_prefix(stream: const u8[:]) -> bool {
    guard stream.len > 0 else { return true; }
    if core::starts_with(stream, "GET") { return true; }
    if core::starts_with(stream, "POST") { return true; }
    if core::starts_with(stream, "HEAD") { return true; }
    if core::starts_with(stream, "PUT") { return true; }
    if core::starts_with(stream, "DELETE") { return true; }
    if core::starts_with(stream, "OPTIONS") { return true; }
    if core::starts_with(stream, "PATCH") { return true; }
    if core::starts_with(stream, "CONNECT") { return true; }
    if core::starts_with(stream, "TRACE") { return true; }
    if stream.len < 7 {
        if "OPTIONS"[..stream.len] == stream { return true; }
        if "CONNECT"[..stream.len] == stream { return true; }
        if "DELETE"[..stream.len] == stream { return true; }
        if "PATCH"[..stream.len] == stream { return true; }
        if "TRACE"[..stream.len] == stream { return true; }
        if "POST"[..stream.len] == stream { return true; }
        if "HEAD"[..stream.len] == stream { return true; }
        if "GET"[..stream.len] == stream { return true; }
        if "PUT"[..stream.len] == stream { return true; }
    }
    return false;
}

// Checks if pipelined stream body with Content-Length is incomplete or exceeds payload limits.
fn check_pipelined_content_length<B>(
    stream:      const u8[:],
    hdr_end:     i64,
    cl_str:      const u8[:],
    server_name: const u8[:],
    wire_out:    B&,
    out_keep:    bool&,
) -> bool {
    guard cl_str.len > 0 else { return false; }
    let cl_val, cl_ok = core::parse_i64_dec(trim(cl_str));
    guard cl_ok && cl_val >= 0 else { return false; }
    if cl_val > MAX_SERVER_BODY_LIMIT {
        // RFC 9110 Section 15.5.14: Payload Too Large
        serialize_payload_too_large_error(server_name, wire_out);
        out_keep = false;
        return true;
    }
    if stream.len < (hdr_end + 4 + cl_val) {
        out_keep = true;
        return true;
    }
    return false;
}

inline fn check_pipelined_chunked_head<B>(
    stream:      const u8[:],
    hdr_end:     i64,
    server_name: const u8[:],
    wire_out:    B&,
    out_keep:    bool&,
) -> bool {
    let chunk_slice = stream[(hdr_end + 4)..];
    var chunk_cur:      i64 = 0;
    var first_chunk_sz: u64 = 0;
    let sz_err = read_chunk_size_line(chunk_slice, chunk_cur, first_chunk_sz);
    if sz_err == ChunkedDecodeError.None && first_chunk_sz > (MAX_SERVER_BODY_LIMIT as u64) {
        serialize_payload_too_large_error(server_name, wire_out);
        out_keep = false;
        return false;
    }
    if sz_err != ChunkedDecodeError.None && sz_err != ChunkedDecodeError.UnexpectedEof {
        serialize_bad_request_error(server_name, wire_out);
        out_keep = false;
        return false;
    }
    out_keep = true;
    return true;
}

// Handles incomplete pipelined HTTP stream or syntax errors.
fn handle_pipelined_parse_failure<B>(
    server_name:     const u8[:],
    stream:          const u8[:],
    req:             const Request&,
    wire_out:        B&,
    out_keep_stream: bool&,
) -> bool {
    let hdr_end = core::fast_find_crlfcrlf(stream);
    let is_valid_prefix = is_possible_http_method_prefix(stream);

    if hdr_end >= 0 && stream.len <= 8192 && is_valid_prefix && req.headers.entries.len > 0 {
        // If both TE and CL are present, reject immediately as smuggling attempt (RFC 9112 §6.1, §6.3)
        let te_str = req.header("transfer-encoding");
        let cl_str = req.header("content-length");
        if te_str.len > 0 && cl_str.len > 0 {
            serialize_bad_request_error(server_name, wire_out);
            out_keep_stream = false;
            return false;
        }

        // Headers are complete; check if Content-Length body is still incomplete
        var cl_handled_keep = false;
        if check_pipelined_content_length(stream, hdr_end, cl_str, server_name, wire_out, cl_handled_keep) {
            out_keep_stream = cl_handled_keep;
            return cl_handled_keep;
        }
        if core::contains_fold(te_str, "chunked") {
            return check_pipelined_chunked_head(stream, hdr_end, server_name, wire_out, out_keep_stream);
        }
    }

    if hdr_end >= 0 || stream.len > 8192 || !is_valid_prefix {
        // Complete headers but invalid syntax, or header overflow > 8192,
        // or trailing unparseable poison bytes: 400 Bad Request
        serialize_bad_request_error(server_name, wire_out);
        out_keep_stream = false;
        return false;
    }
    // Legitimate incomplete request across packet boundary: return so caller preserves stream in leftover
    out_keep_stream = true;
    return true;
}

enum PipeStepResult {
    Continue,
    Stop,
    Error,
}

// Strips optional benign CRLFs between pipelined requests (RFC 9112 Section 2.2).
//
// Example:
//   stream = "\r\nGET / HTTP/1.1", consumed_crlf = 0
//   returns: "GET / HTTP/1.1", consumed_crlf = 2
inline fn strip_pipelined_crlf(stream: const u8[:], consumed_crlf: i64&) -> const u8[:] {
    var s = stream;
    while s.len > 0 && (s[0] == '\r' || s[0] == '\n') {
        s = s[1..];
        consumed_crlf++;
    }
    return s;
}

fn try_handle_pipelined_websocket<B>(
    server:   HttpServer&,
    req:      const Request&,
    wire_out: B&,
) -> bool {
    guard is_websocket_upgrade_request(req) else { return false; }
    let ws_idx = find_ws_route(server, req.url[..]);
    guard ws_idx >= 0 else { return false; }
    return complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out);
}

inline fn reset_server_response_fast(res: Response&) {
    res.status_code = 200;
    res.presence_mask = 0;
    res.headers.clear();
    res.trailers.clear();
    res.body.clear();
}

inline fn reset_server_request_fast(req: Request&) {
    req.method.clear();
    req.url.clear();
    req.presence_mask = 0;
    req.headers.clear();
    req.trailers.clear();
    req.query_params.clear();
    req.body.clear();
    req.is_http10 = false;
}

// Extended server request context holding long header token arena (RFC 9112 Section 2.1).
struct ServerRequest {
    raw_header_arena: u8[..8192] = [],
    req:              Request    = Request { .. },
}

inline fn reset_server_request(sreq: ServerRequest&) {
    reset_server_request_fast(sreq.req);
    sreq.raw_header_arena.clear();
}

fn dispatch_pipelined_request<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    req:       Request&,
    res:       Response&,
    now_ns:    u64,
    wire_out:  B&,
) -> bool {
    reset_server_response_fast(res);
    var future = internal::new_inline_handler_future(0);
    let _ = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);

    let wants_close = check_and_apply_connection_close(req, res);
    serialize_http1_response(res, server.server_name[..], wire_out);
    server.requests_processed++;
    return wants_close;
}

fn process_pipelined_pipe_step<B>(
    server:        HttpServer&,
    client_ip:     const u8[:],
    pipe:          core::PipeBuffer&,
    req:           Request&,
    res:           Response&,
    now_ns:        u64,
    total_handled: i64&,
    wire_out:      B&,
) -> PipeStepResult {
    let stream = core::readable_slice(pipe);
    reset_server_request_fast(req);
    let ok_parse, consumed = parse_http1_wire_request(stream, req);

    if !ok_parse || consumed <= 0 {
        var keep = false;
        let _ = handle_pipelined_parse_failure(server.server_name[..], stream, req, wire_out, keep);
        if keep {
            core::advance_to(pipe, 0, pipe.readable_len());
            return PipeStepResult.Stop;
        }
        core::advance_to(pipe, 0, pipe.readable_len());
        return PipeStepResult.Error;
    }

    if try_handle_pipelined_websocket(server, req, wire_out) {
        total_handled++;
        core::advance_to(pipe, consumed, consumed);
        core::advance_to(pipe, pipe.readable_len(), pipe.readable_len());
        return PipeStepResult.Stop;
    }

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, wire_out);
    total_handled++;
    core::advance_to(pipe, consumed, consumed);

    if req.method[..] == "CONNECT" || wants_close {
        core::advance_to(pipe, pipe.readable_len(), pipe.readable_len());
        return PipeStepResult.Stop;
    }
    return PipeStepResult.Continue;
}

enum StreamTurnResult {
    Continue,
    Stop,
    ParseFail,
    KeepStreamFail,
}

fn process_pipelined_stream_turn<B>(
    server:           HttpServer&,
    client_ip:        const u8[:],
    stream:           const u8[:],
    now_ns:           u64,
    req:              Request&,
    res:              Response&,
    wire_out:         B&,
    wire_in_len:      i64,
    step_consumed:    i64&,
    total_handled:    i64&,
    total_consumed:   i64&,
    conn_wants_close: bool&,
) -> StreamTurnResult {
    guard wire_out.len + 256 <= wire_out.cap else { return StreamTurnResult.Stop; }

    reset_server_request_fast(req);
    let ok_parse, consumed = parse_http1_wire_request(stream, req);
    guard ok_parse && consumed > 0 else {
        var keep = false;
        let _ = handle_pipelined_parse_failure(server.server_name[..], stream, req, wire_out, keep);
        return if keep { StreamTurnResult.KeepStreamFail } else { StreamTurnResult.ParseFail };
    }

    if try_handle_pipelined_websocket(server, req, wire_out) {
        total_handled++;
        total_consumed += consumed;
        step_consumed = consumed;
        return StreamTurnResult.Stop;
    }

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, wire_out);
    total_handled++;
    total_consumed += consumed;
    step_consumed = consumed;

    if wants_close || req.method[..] == "CONNECT" {
        conn_wants_close = true;
        if req.method[..] == "CONNECT" { total_consumed = wire_in_len; }
        return StreamTurnResult.Stop;
    }

    return StreamTurnResult.Continue;
}

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests.
// Returns (total_requests_processed, total_bytes_consumed, ok, wants_close).
fn handle_connection_wire_pipelined_stream<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
) -> i64, i64, bool, bool {
    if server.trust_proxy_headers { server.pipeline.trust_proxy_headers = true; }
    wire_out.clear();
    var stream = wire_in;
    var total_handled:    i64  = 0;
    var total_consumed:   i64  = 0;
    var conn_wants_close: bool = false;

    var req = new_request("GET", "");
    var res = Response { .. };

    while stream.len > 0 {
        stream = strip_pipelined_crlf(stream, total_consumed);
        if stream.len == 0 { break; }

        var step_consumed: i64 = 0;
        let turn_res = process_pipelined_stream_turn(
            server, client_ip, stream, now_ns, req, res,
            wire_out, wire_in.len, step_consumed, total_handled, total_consumed, conn_wants_close,
        );
        match turn_res {
            Continue => {
                stream = stream[step_consumed..];
            },
            Stop => {
                break;
            },
            ParseFail => {
                return total_handled, total_consumed, false, true;
            },
            KeepStreamFail => {
                return total_handled, total_consumed, true, false;
            },
        };
    }

    return total_handled, total_consumed, true, conn_wants_close;
}

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests (RFC 9112 Section 9.3).
// Concatenates all serialized responses into wire_out and returns (total_requests_processed, ok).
fn handle_connection_wire_pipelined<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    wire_in:   const u8[:],
    now_ns:    u64,
    wire_out:  B&,
) -> i64, bool {
    let count, _, ok, _ = handle_connection_wire_pipelined_stream(server, client_ip, wire_in, now_ns, wire_out);
    return count, ok;
}

inline fn handle_h2_pipe_ingress<B>(
    server:     HttpServer&,
    client_ip:  const u8[:],
    pipe:       core::PipeBuffer&,
    h2_sess:    internal::H2ServerSession&,
    now_ms:     u64,
    unread_len: i64,
    wire_out:   B&,
) -> i64, bool {
    let stream = core::readable_slice(pipe);
    let consumed_h2, ok_h2 = internal::handle_h2_server_ingress(
        h2_sess, server.pipeline, server.timer, client_ip, stream, now_ms, wire_out,
    );
    if ok_h2 {
        core::advance_to(pipe, consumed_h2, consumed_h2);
        server.requests_processed++;
        return 1, true;
    }
    core::advance_to(pipe, consumed_h2, unread_len);
    return 0, false;
}

// Incremental Sans-IO pipeline handler using PipeBuffer (RFC 9112 & System.IO.Pipelines model).
// Reads from the pipe buffer, processes all complete pipelined requests, and updates
// pipe cursors (consumed, examined) with strict monotonicity.
// Returns (total_requests_processed, ok).
fn handle_connection_pipe<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
    h2_sess:   internal::H2ServerSession&,
) -> i64, bool {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let unread_len = pipe.readable_len();
    guard unread_len > 0 else { return 0, true; }

    let now_ms = (now_ns / 1000000) as u64;
    var total_handled: i64 = 0;

    if h2_sess.preface_handled {
        return handle_h2_pipe_ingress(server, client_ip, pipe, h2_sess, now_ms, unread_len, wire_out);
    }

    // Sliced H2 preface: wait for the remaining bytes instead of parsing as HTTP/1.1
    if pipe.consumed == 0 && is_partial_h2_client_preface(core::readable_slice(pipe)) {
        return 0, true;
    }

    // Check for HTTP/2 connection preface if at the very start of the stream
    if pipe.consumed == 0 && unread_len >= 24 {
        let stream = core::readable_slice(pipe);
        if is_h2_client_preface(stream) {
            return handle_h2_pipe_ingress(server, client_ip, pipe, h2_sess, now_ms, unread_len, wire_out);
        }
    }

    var req = new_request("GET", "");
    var res = Response { .. };

    while pipe.readable_len() > 0 {
        let res_step = process_pipelined_pipe_step(
            server, client_ip, pipe, req, res, now_ns, total_handled, wire_out,
        );
        if res_step == PipeStepResult.Error {
            return total_handled, false;
        } else if res_step == PipeStepResult.Stop {
            break;
        }
    }

    return total_handled, true;
}

inline fn alloc_temp_h2_session(
    pipeline:    ServerPipelineConfig&,
    server_name: const u8[:],
    now_ns:      u64,
) -> i64 {
    let idx = alloc_reactor_h2_session(pipeline, server_name, now_ns / 1000000) as i64;
    return clamp(idx, 0, 7);
}

fn handle_connection_pipe<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
) -> i64, bool {
    let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], now_ns);
    defer free_reactor_h2_session(h2_idx as i16, server.pipeline);
    return handle_connection_pipe(server, client_ip, pipe, now_ns, wire_out, g_reactor_h2_sessions[h2_idx]);
}

// Dispatches an HTTP `Request` through `server.pipeline` with a compile-time `<UserStage>` hook.
fn dispatch_server_request_with_stage<UserStage>(
    server:     HttpServer&,
    client_ip:  const u8[:],
    req:        const Request&,
    now_ns:     u64,
    res:        Response&,
    user_stage: UserStage&,
) -> PipelineOutcome {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    var future = internal::new_inline_handler_future(0);
    let outcome = execute_server_pipeline_with_stage(
        server.pipeline, server.timer, client_ip, req, now_ns, res, future, user_stage,
    );
    server.requests_processed++;
    return outcome;
}

// Probes buffered HTTP/1.1 wire bytes after `\r\n\r\n` (`hdr_end`) to check if the full request body has arrived.
// Returns true immediately on header parse errors or smuggling conflicts so the main parser emits 400 Bad Request.
fn is_http1_request_ready(in_buf: const u8[:], hdr_end: i64) -> bool {
    let body_start = core::add_sat_i64(hdr_end, 4);
    var tracker = HeaderPresenceTracker { .. };
    var parsed_start: i64 = 0;
    var probe_req = Request { .. };
    guard parse_http1_request_headers(in_buf, probe_req, tracker, parsed_start) else {
        return true;
    }
    let has_te = (tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;
    if has_te && has_cl {
        return true;
    }
    if has_cl {
        return in_buf.len >= core::add_sat_i64(body_start, tracker.parsed_cl);
    }
    if has_te {
        guard body_start <= in_buf.len else { return false; }
        return find(in_buf[body_start..], "0\r\n\r\n") >= 0;
    }
    return true;
}

// Executes one ingress step of an HTTP/2 server session and flushes any outbound frames.
inline fn step_h2_server_session_buf<InBuf, OutBuf>(
    conn_fd:  i64,
    server:   HttpServer&,
    h2_idx:   i64,
    peer_ip:  const u8[:],
    h2_in:    InBuf&,
    now_ms:   u64,
    out_wire: OutBuf&,
) -> bool {
    out_wire.clear();
    let consumed, ok = internal::handle_h2_server_ingress(
        g_reactor_h2_sessions[h2_idx], server.pipeline, server.timer, peer_ip, h2_in[..], now_ms, out_wire,
    );
    if out_wire.len > 0 {
        let _ = tcp_send(conn_fd, out_wire[..]);
    }
    guard ok else { return false; }
    if consumed > 0 {
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        core::compact_wire_buffer(h2_in, consumed);
    }
    return true;
}

// Appends `recvd` bytes from `chunk` into `in_buf` if valid and within 16 MB wire limit.
inline fn try_append_recv_chunk<InBuf, ChunkBuf>(recvd: i32, chunk: const ChunkBuf&, in_buf: InBuf&) -> bool {
    guard recvd > 0 else { return false; }
    let n = recvd as i64;
    guard core::add_sat_i64(in_buf.len, n) <= 16777216 else { return false; }
    in_buf.append(chunk[..n]);
    return true;
}

// Runs a persistent HTTP/2 server session loop over `conn_fd` using caller-supplied `h2_in` buffer (RFC 9113).
fn serve_h2_connection_buf<InBuf>(
    server:          HttpServer&,
    conn_fd:         i64,
    h2_in:           InBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    guard conn_fd > 0 else { return false; }
    server.pipeline.trust_proxy_headers = server.pipeline.trust_proxy_headers || server.trust_proxy_headers;
    let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], 1000000000);
    defer free_reactor_h2_session(h2_idx as i16, server.pipeline);

    var peer_ip: u8[..64] = [];
    tcp_get_peer_ip(conn_fd, peer_ip);

    var out_wire:   u8[..65536] = [];
    var chunk:      u8[..4096]  = [];
    var now_ms:     u64         = 1000;
    var idle_ticks: u64         = 0;
    loop {
        if !step_h2_server_session_buf(conn_fd, server, h2_idx, peer_ip[..], h2_in, now_ms, out_wire) {
            chunk.clear();
            let _ = tcp_recv(conn_fd, chunk, 4096, 10);
            return false;
        }
        chunk.clear();
        let recvd = tcp_recv(conn_fd, chunk, 4096, recv_timeout_ms);
        if recvd == -2 {
            idle_ticks = core::add_sat_u64(idle_ticks, 1);
            if idle_ticks >= 2 { break; }
            continue;
        }
        if !try_append_recv_chunk(recvd, chunk, h2_in) {
            break;
        }
        idle_ticks = 0;
        now_ms = core::add_sat_u64(now_ms, 10);
    }
    return true;
}

// Completes an RFC 6455 HTTP/1.1 WebSocket upgrade on `conn_fd`, wires route behavior limits,
// compacts `in_buf` past the HTTP request, and drives the WebSocket frame loop.
fn serve_http1_upgraded_ws<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:     i64,
    server:      HttpServer&,
    req:         const Request&,
    consumed:    i64,
    stage:       Stage&,
    in_buf:      InBuf&,
    ws_frag_buf: FragBuf&,
    out_wire:    OutBuf&,
) -> bool {
    let r_idx = find_ws_route(server, req.url[..]);
    guard server.ws_route_count == 0 || r_idx >= 0 else { return false; }
    let behavior = if r_idx >= 0 {
        server.ws_routes[r_idx as i64].behavior
    } else {
        WsBehavior { .. }
    };
    var ws_res = Response { .. };
    var ws, ok_ws = ws_upgrade_request(req, ws_res, behavior.subprotocol[..]);
    guard ok_ws else { return false; }
    ws.max_payload_length = behavior.max_payload_length;
    ws.max_backpressure = behavior.max_backpressure;
    ws.close_on_backpressure_limit = behavior.close_on_backpressure_limit;
    ws.idle_timeout_s = behavior.idle_timeout_s;
    ws.max_lifetime_s = behavior.max_lifetime_s;
    ws.send_pings_automatically = behavior.send_pings_automatically;
    ws.reset_idle_timeout_on_send = behavior.reset_idle_timeout_on_send;
    out_wire.clear();
    serialize_http1_response(ws_res, server.server_name[..], out_wire);
    let _ = tcp_send(conn_fd, out_wire[..]);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    core::compact_wire_buffer(in_buf, consumed);
    serve_ws_session_buf(conn_fd, ws, stage, in_buf, ws_frag_buf, out_wire);
    return true;
}

// Dispatches a single parsed HTTP/1.1 request through `server` and `stage`, writes the response,
// updates `server.is_running` on `/shutdown` (`200 OK`), and returns true if keep-alive should continue.
fn dispatch_http1_connection_turn<Stage, OutBuf>(
    conn_fd:  i64,
    server:   HttpServer&,
    peer_ip:  const u8[:],
    req:      const Request&,
    stage:    Stage&,
    out_wire: OutBuf&,
) -> bool {
    var res = Response { .. };
    let now_ns = core::as_nanos(core::monotonic_now());
    let _ = dispatch_server_request_with_stage(server, peer_ip, req, now_ns, res, stage);
    if req.url[..] == "/shutdown" && res.status_code == 200 {
        server.is_running = false;
    }
    let conn_hdr = res.header("Connection");
    let wants_ka = server.is_running && core::eq_ascii_fold(conn_hdr, "keep-alive");
    if !wants_ka && conn_hdr.len == 0 {
        set_header(res, "Connection", "close");
    }
    out_wire.clear();
    serialize_http1_response(res, server.server_name[..], out_wire);
    let _ = tcp_send(conn_fd, out_wire[..]);
    return wants_ka;
}

// Serves an auxiliary concurrent connection accepted while a primary connection is idle pre-preface (h2spec).
fn serve_idle_aux_connection(listener_fd: i64, server: HttpServer&, recv_timeout_ms: u32) -> bool {
    guard listener_fd > 0 else { return false; }
    let aux_conn = tcp_accept(listener_fd, 0);
    guard aux_conn > 0 else { return false; }
    var aux_in:    u8[..65536] = [];
    var aux_chunk: u8[..4096]  = [];
    var ticks:     u64         = 0;
    while ticks < 10 {
        aux_chunk.clear();
        let recvd = tcp_recv(aux_conn, aux_chunk, 4096, 15);
        if recvd == -2 {
            ticks = core::add_sat_u64(ticks, 1);
            continue;
        }
        if !try_append_recv_chunk(recvd, aux_chunk, aux_in) {
            break;
        }
        ticks = 0;
        if !is_partial_h2_client_preface(aux_in[..]) {
            if is_h2_client_preface(aux_in[..]) {
                let _ = serve_h2_connection_buf(server, aux_conn, aux_in, recv_timeout_ms);
            }
            break;
        }
    }
    tcp_close(aux_conn);
    return true;
}

// Processes a complete buffered HTTP/1.1 request in `in_buf` (WebSocket upgrade or HTTP/1.1 pipeline turn).
// Returns true if the connection loop should continue reading another keep-alive request.
fn process_ready_http1_connection_buf<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:     i64,
    server:      HttpServer&,
    peer_ip:     const u8[:],
    stage:       Stage&,
    in_buf:      InBuf&,
    ws_frag_buf: FragBuf&,
    out_wire:    OutBuf&,
    ka_count:    i64&,
) -> bool {
    var req = new_request("GET", "");
    let ok_req, consumed = parse_http1_wire_request(in_buf[..], req);
    guard ok_req && consumed > 0 else {
        out_wire.clear();
        serialize_bad_request_error(server.server_name[..], out_wire);
        let _ = tcp_send(conn_fd, out_wire[..]);
        return false;
    }
    if is_websocket_upgrade_request(req) {
        if serve_http1_upgraded_ws(conn_fd, server, req, consumed, stage, in_buf, ws_frag_buf, out_wire) {
            return false;
        }
    }
    let wants_ka = dispatch_http1_connection_turn(conn_fd, server, peer_ip, req, stage, out_wire);
    core::compact_wire_buffer(in_buf, consumed);
    ka_count = core::add_sat_i64(ka_count, 1);
    return wants_ka && ka_count < 4;
}

// Checks whether `in_buf` contains a complete HTTP/1.1 request ready for dispatch (when not an H2 preface).
inline fn has_ready_http1_request(in_buf: const u8[:]) -> bool {
    guard !is_partial_h2_client_preface(in_buf) && !is_h2_client_preface(in_buf) else { return false; }
    let hdr_end = core::fast_find_crlfcrlf(in_buf);
    guard hdr_end >= 0 else { return false; }
    return is_http1_request_ready(in_buf, hdr_end);
}

// Handles a newly received HTTP/2 preface or invalid PRI prefix in `in_buf`.
// Returns true if the connection was handled/terminated as HTTP/2 or invalid PRI.
fn try_dispatch_h2_or_invalid_preface_buf<InBuf>(
    server:          HttpServer&,
    conn_fd:         i64,
    in_buf:          InBuf&,
    recv_timeout_ms: u32,
) -> bool {
    guard !is_partial_h2_client_preface(in_buf[..]) else { return false; }
    if is_h2_client_preface(in_buf[..]) {
        let _ = serve_h2_connection_buf(server, conn_fd, in_buf, recv_timeout_ms);
        return true;
    }
    return in_buf.len >= 4 && in_buf[..4] == "PRI ";
}

// Handles an idle poll timeout (`recvd == -2`) on `conn_fd`, polling `listener_fd` for auxiliary connections.
inline fn step_idle_connection_poll(
    listener_fd:     i64,
    server:          HttpServer&,
    in_buf_len:      i64,
    recv_timeout_ms: u32,
    idle_ticks:      u64&,
) {
    if in_buf_len == 0 && serve_idle_aux_connection(listener_fd, server, recv_timeout_ms) {
        idle_ticks = 0;
        return;
    }
    idle_ticks = core::add_sat_u64(idle_ticks, 1);
}

// Polls `conn_fd` once and appends received bytes to `in_buf`, handling idle timeouts and HTTP/2 prefaces.
// Returns true if the caller should continue polling `conn_fd`, or false if the connection is complete/closed.
fn poll_http_connection_ingress_buf<InBuf>(
    listener_fd:     i64,
    conn_fd:         i64,
    server:          HttpServer&,
    in_buf:          InBuf&,
    poll_ms:         u32,
    recv_timeout_ms: u32,
    idle_ticks:      u64&,
) -> bool {
    var chunk: u8[..4096] = [];
    let recvd = tcp_recv(conn_fd, chunk, 4096, poll_ms);
    if recvd == -2 {
        step_idle_connection_poll(listener_fd, server, in_buf.len, recv_timeout_ms, idle_ticks);
        return idle_ticks < 25;
    }
    guard try_append_recv_chunk(recvd, chunk, in_buf) else { return false; }
    idle_ticks = 0;
    return !try_dispatch_h2_or_invalid_preface_buf(server, conn_fd, in_buf, recv_timeout_ms);
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection on `conn_fd` using caller-supplied buffers.
fn serve_http_connection_on_listener_buf<Stage, InBuf, FragBuf, OutBuf>(
    listener_fd:     i64,
    conn_fd:         i64,
    server:          HttpServer&,
    stage:           Stage&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    guard conn_fd > 0 else { return server.is_running; }
    in_buf.clear();
    var peer_ip:    u8[..64] = [];
    var idle_ticks: u64      = 0;
    var ka_count:   i64      = 0;
    tcp_get_peer_ip(conn_fd, peer_ip);
    let poll_ms: u32 = min(max(recv_timeout_ms, 1), 100);

    loop {
        if has_ready_http1_request(in_buf[..]) {
            idle_ticks = 0;
            if process_ready_http1_connection_buf(
                conn_fd, server, peer_ip[..], stage, in_buf, ws_frag_buf, out_wire, ka_count,
            ) {
                continue;
            }
            break;
        }
        if !poll_http_connection_ingress_buf(
            listener_fd, conn_fd, server, in_buf, poll_ms, recv_timeout_ms, idle_ticks,
        ) {
            break;
        }
    }
    return server.is_running;
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection on `conn_fd` using caller-supplied buffers.
fn serve_http_connection_buf<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:         i64,
    server:          HttpServer&,
    stage:           Stage&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    return serve_http_connection_on_listener_buf(
        -1, conn_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms,
    );
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection with caller buffers and default `wire::NoOpStage`.
fn serve_http_connection_buf<InBuf, FragBuf, OutBuf>(
    conn_fd:         i64,
    server:          HttpServer&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    var stage = wire::NoOpStage {};
    return serve_http_connection_buf(conn_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection with 64 KB stack buffers and `<Stage>`.
fn serve_http_connection<Stage>(
    conn_fd:         i64,
    server:          HttpServer&,
    stage:           Stage&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    var in_buf:      u8[..65536] = [];
    var ws_frag_buf: u8[..65536] = [];
    var out_wire:    u8[..65536] = [];
    return serve_http_connection_buf(conn_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Drives an HTTP/1.1, HTTP/2 (`h2c`), or WebSocket connection with 64 KB stack buffers and `wire::NoOpStage`.
fn serve_http_connection(
    conn_fd:         i64,
    server:          HttpServer&,
    recv_timeout_ms: u32 = 500,
) -> bool {
    var stage = wire::NoOpStage {};
    return serve_http_connection(conn_fd, server, stage, recv_timeout_ms);
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections on `listener_fd` using caller buffers.
fn serve_http_listener_buf<Stage, InBuf, FragBuf, OutBuf>(
    listener_fd:     i64,
    server:          HttpServer&,
    stage:           Stage&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) {
    guard listener_fd > 0 else { return; }
    server.is_running = true;
    while server.is_running {
        let conn = tcp_accept(listener_fd, 200);
        if conn <= 0 {
            continue;
        }
        let _ = serve_http_connection_on_listener_buf(
            listener_fd, conn, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms,
        );
        tcp_close(conn);
    }
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections with caller buffers and `wire::NoOpStage`.
fn serve_http_listener_buf<InBuf, FragBuf, OutBuf>(
    listener_fd:     i64,
    server:          HttpServer&,
    in_buf:          InBuf&,
    ws_frag_buf:     FragBuf&,
    out_wire:        OutBuf&,
    recv_timeout_ms: u32 = 500,
) {
    var stage = wire::NoOpStage {};
    serve_http_listener_buf(listener_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections with 64 KB stack buffers and `<Stage>`.
fn serve_http_listener<Stage>(
    listener_fd:     i64,
    server:          HttpServer&,
    stage:           Stage&,
    recv_timeout_ms: u32 = 500,
) {
    var in_buf:      u8[..65536] = [];
    var ws_frag_buf: u8[..65536] = [];
    var out_wire:    u8[..65536] = [];
    serve_http_listener_buf(listener_fd, server, stage, in_buf, ws_frag_buf, out_wire, recv_timeout_ms);
}

// Accepts and serves HTTP/1.1, HTTP/2 (`h2c`), and WebSocket connections with 64 KB stack buffers.
fn serve_http_listener(
    listener_fd:     i64,
    server:          HttpServer&,
    recv_timeout_ms: u32 = 500,
) {
    var stage = wire::NoOpStage {};
    serve_http_listener(listener_fd, server, stage, recv_timeout_ms);
}

inline fn response_wire_has_connection_close(wire: const u8[:]) -> bool {
    let hdr_end = core::fast_find_crlfcrlf(wire);
    let hdr_slice = if hdr_end >= 0 { wire[..(hdr_end + 2)] } else { wire };
    return core::contains_fold(hdr_slice, "\r\nconnection: close\r\n");
}

// Binds and listens on a Unix Domain Socket (AF_UNIX) path (uWebSockets app.listen(path) pattern).
// Eliminates network stack TCP overhead for local IPC and sidecar communication.
// Returns listening socket handle, or -1 on error.
fn listen_unix(server: HttpServer&, path: const u8[:], backlog: i32 = 128) -> i64 {
    return tcp_listen_unix(path, backlog);
}

// Adopts an externally accepted or inherited socket descriptor into the server environment
// (uWebSockets us_adopt_accepted_socket pattern).
fn adopt_socket(server: HttpServer&, raw_fd: i64) -> i64 {
    return adopt_socket(raw_fd);
}

// Executes a live TCP accept and dispatch loop using hardware page-mirrored ring buffer (PageRingBuffer).
fn serve_page_ring_loop(
    server:          HttpServer&,
    listener_fd:     i64,
    max_connections: i64,
    ring:            core::PageRingBuffer&,
) -> i64 {
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;

    while max_connections == 0 || total_served < max_connections {
        let conn = tcp_accept(listener_fd, 0);
        if conn <= 0 {
            continue;
        }
        defer tcp_close(conn);

        core::page_ring_clear(ring);
        cork.cork_reset();
        tcp_get_peer_ip(conn, peer_ip);

        loop {
            let recvd = core::page_ring_recv(ring, conn, 65536, 5000);
            if recvd <= 0 {
                break;
            }

            let now_ns = core::as_nanos(core::monotonic_now());
            let count, ok_handle = handle_connection_page_ring(server, peer_ip[..], ring, now_ns, cork);
            let should_close = !ok_handle || response_wire_has_connection_close(core::cork_as_slice(cork));
            if !ok_handle {
                if cork.cork_pending() > 0 { tcp_flush_cork(conn, cork); }
                break;
            }

            if cork.cork_pending() > 0 {
                let sent = tcp_flush_cork(conn, cork);
                if sent <= 0 || should_close { break; }
            } else if should_close {
                break;
            }
        }
        total_served++;
    }

    return total_served;
}

// Executes a live TCP accept and dispatch loop using standard PipeBuffer.
fn serve_pipe_loop(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;

    while max_connections == 0 || total_served < max_connections {
        let conn = tcp_accept(listener_fd, 0);
        if conn <= 0 {
            continue;
        }
        defer tcp_close(conn);

        pipe.pipe_reset();
        cork.cork_reset();
        tcp_get_peer_ip(conn, peer_ip);
        let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], 0);
        defer free_reactor_h2_session(h2_idx as i16, server.pipeline);

        loop {
            let recvd = tcp_recv_pipe(conn, pipe, 4096, 5000);
            if recvd <= 0 {
                break;
            }

            let now_ns = core::as_nanos(core::monotonic_now());
            let count, ok = handle_connection_pipe(
                server, peer_ip[..], pipe, now_ns, cork, g_reactor_h2_sessions[h2_idx],
            );
            let should_close = !ok || response_wire_has_connection_close(core::cork_as_slice(cork));
            if !ok {
                if cork.cork_pending() > 0 { tcp_flush_cork(conn, cork); }
                break;
            }

            if cork.cork_pending() > 0 {
                let sent = tcp_flush_cork(conn, cork);
                if sent <= 0 || should_close { break; }
            } else if should_close {
                break;
            }
        }
        total_served++;
    }

    return total_served;
}

// Executes a live TCP accept and dispatch loop.
// Transparently uses high-performance hardware page-mirrored ring buffer (PageRingBuffer)
// with seamless fallback to PipeBuffer for restricted environments.
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    guard listener_fd > 0 else { return 0; }

    var ring = core::PageRingBuffer { .. };
    let ok_ring = core::page_ring_init(ring, 65536);
    if ok_ring {
        defer core::page_ring_close(ring);
        return serve_page_ring_loop(server, listener_fd, max_connections, ring);
    }

    return serve_pipe_loop(server, listener_fd, max_connections);
}

fn tls_recv_pipe(
    fd:         i64,
    slot_idx:   u16,
    pipe:       core::PipeBuffer&,
    min_span:   i64 = 4096,
    timeout_ms: u32 = 5000,
) -> i32 {
    guard fd > 0 else { return -1; }
    let span, err = core::get_write_span(pipe, min_span);
    if err != core::IoError.None { return -1; }
    let recvd = tls_transport_recv_slice(fd, slot_idx, span, timeout_ms);
    if recvd > 0 { core::commit_write(pipe, recvd); }
    return recvd;
}

fn tls_flush_cork(fd: i64, slot_idx: u16, cork: core::CorkBuffer&) -> i32 {
    let slice = core::cork_as_slice(cork);
    guard slice.len > 0 else { return 0; }
    let sent = tls_transport_send(fd, slot_idx, slice);
    cork.cork_reset();
    return sent;
}

// Executes a live TLS 1.3 HTTPS accept and dispatch loop using PipeBuffer and TLS record AEAD.
fn serve_tls(
    server:          HttpServer&,
    listener_fd:     i64,
    tls_config:      const TlsServerHandshakeConfig&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    var peer_ip:      u8[..64] = [];
    var total_served: i64      = 0;

    while max_connections == 0 || total_served < max_connections {
        let conn = tcp_accept(listener_fd, 0);
        if conn <= 0 { continue; }

        let slot_idx, ok_hs = tls_server_handshake(conn, tls_config);
        if !ok_hs {
            tcp_close(conn);
            total_served++;
            continue;
        }

        pipe.pipe_reset();
        cork.cork_reset();
        tcp_get_peer_ip(conn, peer_ip);
        let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], 0);

        loop {
            let recvd = tls_recv_pipe(conn, slot_idx, pipe, 4096, 5000);
            if recvd <= 0 { break; }

            let now_ns = core::as_nanos(core::monotonic_now());
            let _, ok = handle_connection_pipe(
                server, peer_ip[..], pipe, now_ns, cork, g_reactor_h2_sessions[h2_idx],
            );
            let should_close = !ok || response_wire_has_connection_close(core::cork_as_slice(cork));
            if !ok {
                if cork.cork_pending() > 0 { tls_flush_cork(conn, slot_idx, cork); }
                break;
            }
            if cork.cork_pending() > 0 {
                let sent = tls_flush_cork(conn, slot_idx, cork);
                if sent <= 0 || should_close { break; }
            } else if should_close {
                break;
            }
        }
        free_reactor_h2_session(h2_idx as i16, server.pipeline);
        tls_transport_close(conn, slot_idx);
        total_served++;
    }
    return total_served;
}

// ---------------------------------------------------------------------------
// Hardware Virtual Memory Page Pipeline Handlers
// ---------------------------------------------------------------------------

// Incremental Sans-IO pipeline handler using hardware page-mirrored ring buffer (PageRingBuffer).
// Eliminates buffer wraparound splitting and memmove compaction during streaming request processing.
inline fn handle_page_ring_h2_preface<B>(
    server:     HttpServer&,
    client_ip:  const u8[:],
    ring:       core::PageRingBuffer&,
    peek_slice: const u8[:],
    now_ns:     u64,
    wire_out:   B&,
    out_done:   bool&,
    out_ok:     bool&,
) -> i64 {
    if is_partial_h2_client_preface(peek_slice) {
        out_done = true;
        out_ok = true;
        return 0;
    }
    guard is_h2_client_preface(peek_slice) else {
        out_done = false;
        out_ok = true;
        return 0;
    }
    let now_ms = (now_ns / 1000000) as u64;
    let h2_idx = alloc_temp_h2_session(server.pipeline, server.server_name[..], now_ns);
    defer free_reactor_h2_session(h2_idx as i16, server.pipeline);
    let consumed_h2, ok_h2 = internal::handle_h2_server_ingress(
        g_reactor_h2_sessions[h2_idx],
        server.pipeline,
        server.timer,
        client_ip,
        peek_slice,
        now_ms,
        wire_out,
    );
    out_done = true;
    out_ok = ok_h2;
    if ok_h2 {
        core::page_ring_discard(ring, consumed_h2);
        server.requests_processed++;
        return 1;
    }
    core::page_ring_clear(ring);
    return 0;
}

fn handle_connection_page_ring<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    ring:      core::PageRingBuffer&,
    now_ns:    u64,
    wire_out:  B&,
) -> i64, bool {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    guard ring.count > 0 else { return 0, true; }

    var peek_buf: u8[65536] = [0; 65536];
    var req = new_request("GET", "");
    var res = Response { .. };
    var total_handled: i64 = 0;

    while ring.count > 0 {
        let peek_n = core::page_ring_peek(ring, peek_buf[..]);
        guard peek_n > 0 else { break; }

        if total_handled == 0 {
            var h2_done = false;
            var h2_ok = true;
            let h2_cnt = handle_page_ring_h2_preface(
                server, client_ip, ring, peek_buf[..peek_n], now_ns, wire_out, h2_done, h2_ok,
            );
            if h2_done {
                return h2_cnt, h2_ok;
            }
        }

        reset_server_request_fast(req);
        let ok_parse, consumed = parse_http1_wire_request(peek_buf[..peek_n], req);

        if !ok_parse || consumed <= 0 {
            var keep = false;
            let _ = handle_pipelined_parse_failure(server.server_name[..], peek_buf[..peek_n], req, wire_out, keep);
            if keep {
                return total_handled, true;
            }
            core::page_ring_clear(ring);
            return total_handled, false;
        }

        if try_handle_pipelined_websocket(server, req, wire_out) {
            total_handled++;
            core::page_ring_clear(ring);
            break;
        }

        let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, wire_out);
        total_handled++;
        core::page_ring_discard(ring, consumed);

        if req.method[..] == "CONNECT" || wants_close {
            core::page_ring_clear(ring);
            break;
        }
    }

    return total_handled, true;
}

// Executes a live TCP accept and dispatch loop explicitly using PageRingBuffer.
fn serve_page_ring(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    guard listener_fd > 0 else { return 0; }
    var ring = core::PageRingBuffer { .. };
    let ok = core::page_ring_init(ring, 65536);
    guard ok else { return 0; }
    defer core::page_ring_close(ring);
    return serve_page_ring_loop(server, listener_fd, max_connections, ring);
}

inline fn verify_mmap_transfer_complete(
    offset:    u64,
    file_size: u64,
    prev_len:  i64,
    hdr_len:   i64,
    cur_len:   i64,
) -> bool {
    return offset == file_size && cur_len == prev_len + hdr_len + (file_size as i64);
}

// Serves a static file using memory-mapped pages directly to the wire response buffer.
fn serve_static_mmap_file<B>(
    path:         const u8[:],
    content_type: const u8[:],
    wire_out:     B&,
) -> bool {
    guard content_type.len <= 384 else { return false; }
    var mf, ok = core::mmap_file_open(path);
    guard ok else { return false; }
    defer core::mmap_file_close(mf);

    var hdr_buf: u8[..512] = [];
    hdr_buf.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    hdr_buf.append(content_type);
    hdr_buf.append("\r\nContent-Length: ");
    var num_buf: u8[..32] = [];
    core::fast_u64toa(mf.size, num_buf);
    hdr_buf.append(num_buf[..]);
    hdr_buf.append("\r\nConnection: keep-alive\r\n\r\n");

    let prev_len = wire_out.len;
    wire_out.append(hdr_buf[..]);

    var chunk_buf: u8[4096] = [0; 4096];
    var offset:    u64      = 0;
    while offset < mf.size {
        let rem = mf.size - offset;
        let ask = min(rem, 4096);
        let n, r_ok = core::mmap_file_read(mf, offset, chunk_buf[..(ask as i64)]);
        guard r_ok && n > 0 else { break; }
        wire_out.append(chunk_buf[..n]);
        offset = offset + (n as u64);
    }
    return verify_mmap_transfer_complete(offset, mf.size, prev_len, hdr_buf.len, wire_out.len);
}

// Sends a static file directly from kernel memory-mapped pages to a socket with zero user-space copying.
fn send_static_mmap_file(
    sock_fd:      i64,
    path:         const u8[:],
    content_type: const u8[:],
) -> bool {
    guard sock_fd > 0 && content_type.len <= 384 else { return false; }
    var mf, ok = core::mmap_file_open(path);
    guard ok else { return false; }
    defer core::mmap_file_close(mf);
    guard mf.size <= 0x7FFFFFFF else { return false; }

    var hdr_buf: u8[..512] = [];
    hdr_buf.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    hdr_buf.append(content_type);
    hdr_buf.append("\r\nContent-Length: ");
    var num_buf: u8[..32] = [];
    core::fast_u64toa(mf.size, num_buf);
    hdr_buf.append(num_buf[..]);
    hdr_buf.append("\r\nConnection: keep-alive\r\n\r\n");

    let sent_hdr = native_tcp_send(sock_fd, hdr_buf[..]);
    guard sent_hdr == (hdr_buf.len as i32) else { return false; }

    guard mf.size > 0 else { return true; }
    let sent_body, body_ok = core::mmap_file_send(mf, 0, mf.size as u32, sock_fd);
    return body_ok && (sent_body as u64) == mf.size;
}

// ---- rfc 9842 compression dictionary transport negotiation -----------------

// RFC 9842 Section 2.1: Use-As-Dictionary - Attaches `Use-As-Dictionary` response header advertising
// the current response payload as a shared compression dictionary for future matching requests.
fn set_use_as_dictionary_response(
    res:           Response&,
    match_pattern: const u8[:],
    id_str:        const u8[:] = "",
    ttl_sec:       u32         = 86400,
) {
    guard match_pattern.len <= 128 && id_str.len <= 64 else { return; }
    var hdr_val: u8[..512] = [];
    format_use_as_dictionary_header(hdr_val, match_pattern, id_str, ttl_sec);
    set_header(res, "Use-As-Dictionary", hdr_val[..]);
}

// RFC 9842 Section 6: Checks whether a comma-separated `Accept-Encoding` header list contains `target_token`.
fn accept_encoding_has_token(ae: const u8[:], target_token: const u8[:]) -> bool {
    var cursor: i64 = 0;
    while cursor < ae.len {
        var comma_idx = cursor;
        while comma_idx < ae.len && ae[comma_idx] != ',' {
            comma_idx++;
        }
        let item = ae[cursor..comma_idx].trim_lws();
        var semi_idx: i64 = 0;
        while semi_idx < item.len && item[semi_idx] != ';' {
            semi_idx++;
        }
        let coding = item[..semi_idx].trim_lws();
        if coding.len > 0 && core::eq_ascii_fold(coding, target_token) {
            return true;
        }
        cursor = comma_idx + 1;
    }
    return false;
}

// RFC 9842 Section 2.2 & Section 6: Negotiates Compression Dictionary Transport on an incoming `Request`
// by verifying `Available-Dictionary` (RFC 9651 `:base64:` byte sequence), `Dictionary-ID`, and `Accept-Encoding`
// (`dcz` or `dcb`), returning the negotiated Content-Encoding (`"dcz"` or `"dcb"`) and `ok == true`.
fn negotiate_compression_dictionary(
    req:           const Request&,
    expected_hash: const u8[32]&,
    expected_id:   const u8[:] = "",
) -> const u8[:], bool {
    guard expected_id.len <= 126 else { return "", false; }
    let avail_hdr = find_header(req.headers, "Available-Dictionary").trim_lws();
    guard avail_hdr.len >= 3 && avail_hdr[0] == ':' && avail_hdr[avail_hdr.len - 1] == ':' else {
        return "", false;
    }

    var expected_b64: u8[..64] = [];
    format_available_dictionary_header(expected_b64, expected_hash);
    guard core::ct_eq_bytes(avail_hdr, expected_b64[..]) else {
        return "", false;
    }

    if expected_id.len > 0 {
        let id_hdr = find_header(req.headers, "Dictionary-ID").trim_lws();
        var exp_id_wire: u8[..128] = [];
        format_dictionary_id_header(exp_id_wire, expected_id);
        guard id_hdr == exp_id_wire[..] else { return "", false; }
    }

    let ae = find_header(req.headers, "Accept-Encoding");
    if accept_encoding_has_token(ae, rfc::ENCODING_DCZ) {
        return rfc::ENCODING_DCZ, true;
    }
    if accept_encoding_has_token(ae, rfc::ENCODING_DCB) {
        return rfc::ENCODING_DCB, true;
    }
    return "", false;
}

// RFC 9842 Section 4 & Section 5: Encodes a server `Response` body using `dcz` (`\xFFDCZ` + 32-byte SHA-256)
// or `dcb` (`\xFFDCB` + 32-byte SHA-256) when negotiated by `negotiate_compression_dictionary`.
fn apply_negotiated_dictionary_response(
    req:         const Request&,
    res:         Response&,
    dict_hash:   const u8[32]&,
    raw_content: const u8[:],
    expected_id: const u8[:] = "",
) -> bool {
    let enc, ok = negotiate_compression_dictionary(req, dict_hash, expected_id);
    guard ok && raw_content.len <= 16300 else { return false; }

    var encoded_body: u8[..16420] = [];
    if enc == rfc::ENCODING_DCZ {
        guard encode_dcz_response(encoded_body, dict_hash, raw_content) else { return false; }
        res.body.clear();
        res.body.append(encoded_body[..]);
        set_header(res, "Content-Encoding", rfc::ENCODING_DCZ);
        set_header(res, "Vary", "Accept-Encoding, Available-Dictionary");
        return true;
    }
    if enc == rfc::ENCODING_DCB {
        guard encode_dcb_response(encoded_body, dict_hash, raw_content) else { return false; }
        res.body.clear();
        res.body.append(encoded_body[..]);
        set_header(res, "Content-Encoding", rfc::ENCODING_DCB);
        set_header(res, "Vary", "Accept-Encoding, Available-Dictionary");
        return true;
    }
    return false;
}
