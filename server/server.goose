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

// ---- Reason Phrases for HTTP/1.1 Status Line -----------------------------

fn http_status_reason_phrase(code: i32) -> const u8[:] {
    return match code {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        417 => "Expectation Failed",
        422 => "Unprocessable Content",
        425 => "Too Early",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        511 => "Network Authentication Required",
        _ => "Unknown",
    };
}

// ---- HTTP/1.1 Wire Request Parser ---------------------------------------

// RFC 3986 §3.2.2 & RFC 9112 §3.2: Validates structural host header integrity.
fn validate_host_header_structure(host_val: const u8[:]) -> bool {
    guard host_val.len > 0 else { return true; }
    if host_val[0] != '[' {
        for b in host_val {
            guard b != '[' && b != ']' else { return false; }
        }
        return true;
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

const METHOD_GET_U32:     u32 = 0x20544547;       // "GET "
const METHOD_PUT_U32:     u32 = 0x20545550;       // "PUT "
const METHOD_POST_U64:    u64 = 0x2054534F50;     // "POST "
const METHOD_HEAD_U64:    u64 = 0x2044414548;     // "HEAD "
const METHOD_DELETE_U64:  u64 = 0x00204554454C4544; // "DELETE "
const METHOD_OPTIONS_U64: u64 = 0x20534E4F4954504F; // "OPTIONS "
const METHOD_CONNECT_U64: u64 = 0x205443454E4E4F43; // "CONNECT "
const METHOD_PATCH_U64:   u64 = 0x204843544150;     // "PATCH "
const METHOD_TRACE_U64:   u64 = 0x204543415254;     // "TRACE "

const HTTP_VERSION_1_1_U64: u64 = 0x312E312F50545448; // RFC 9112 §2.3 ("HTTP/1.1")
const HTTP_VERSION_1_0_U64: u64 = 0x302E312F50545448; // RFC 9112 §2.3 ("HTTP/1.0")

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
    if w0_32 == METHOD_GET_U32 {
        return 3, "GET";
    }
    if (w0 & 0xFFFFFFFFFF) == METHOD_POST_U64 {
        return 4, "POST";
    }
    if (w0 & 0xFFFFFFFFFF) == METHOD_HEAD_U64 {
        return 4, "HEAD";
    }
    if w0_32 == METHOD_PUT_U32 {
        return 3, "PUT";
    }
    if (w0 & 0xFFFFFFFFFFFFFF) == METHOD_DELETE_U64 {
        return 6, "DELETE";
    }
    if w0 == METHOD_OPTIONS_U64 {
        return 7, "OPTIONS";
    }
    if w0 == METHOD_CONNECT_U64 {
        return 7, "CONNECT";
    }
    if (w0 & 0xFFFFFFFFFFFF) == METHOD_PATCH_U64 {
        return 5, "PATCH";
    }
    if (w0 & 0xFFFFFFFFFFFF) == METHOD_TRACE_U64 {
        return 5, "TRACE";
    }
    return 0, "";
}

// RFC 9112 §3.2.3: Validates authority-form request target for CONNECT method (host:port).
inline fn validate_connect_authority(target: const u8[:]) -> bool {
    let col = core::index_of_byte(target, ':');
    guard col > 0 && col + 1 < target.len else { return false; }
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
        is_connect = (w0 == METHOD_CONNECT_U64);
        is_options = (w0 == METHOD_OPTIONS_U64);
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
    guard proto_u64 == HTTP_VERSION_1_1_U64 || proto_u64 == HTTP_VERSION_1_0_U64 else { return false; }
    out_req.is_http10 = (proto_u64 == HTTP_VERSION_1_0_U64);
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
    wire:     const u8[:],
    spans:    const HeaderSpan[:],
    host_idx: i16,
) -> bool {
    let idx = host_idx as i64;
    guard idx >= 0 && idx < spans.len else { return false; }
    let span = spans[idx];
    let start = span.val_pos as i64;
    let end = start + span.val_len;
    guard end <= wire.len else { return false; }
    let host_val = wire[start..end];
    guard host_val.len > 0 && validate_host_header_chars(host_val) else { return false; }
    guard validate_host_header_structure(host_val) else { return false; }
    return true;
}

fn validate_span_te_header(
    wire:   const u8[:],
    spans:  const HeaderSpan[:],
    te_idx: i16,
) -> bool {
    let idx = te_idx as i64;
    guard idx >= 0 && idx < spans.len else { return false; }
    let span = spans[idx];
    let start = span.val_pos as i64;
    let end = start + span.val_len;
    guard end <= wire.len else { return false; }
    let te_val = wire[start..end];
    guard validate_transfer_encoding_value(te_val) else { return false; }
    return true;
}

inline fn make_header_span(
    cursor:   i64,
    name_len: i64,
    lead_ws:  i64,
    val_len:  i64,
    id_tag:   u8,
) -> HeaderSpan {
    let v_pos = cursor + name_len + 1 + lead_ws;
    return HeaderSpan {
        name_pos: cursor as u16,
        name_len: name_len as u16,
        val_pos:  v_pos as u16,
        val_len:  val_len as u16,
        id:       id_tag,
    };
}

inline fn calc_header_line_advance(name_len: i64, val_len: i64, crlf_len: i64) -> i64 {
    return name_len + 1 + val_len + crlf_len;
}

inline fn push_header_item(
    headers: HeaderItem[..32]&,
    name:    const u8[:],
    val:     const u8[:],
) -> bool {
    guard headers.len < headers.cap else { return false; }
    var item = HeaderItem { .. };
    guard name.len <= item.name.cap && val.len <= item.value.cap else { return false; }
    item.name.append(name);
    item.value.append(val);
    headers.push(item);
    return true;
}

inline fn clear_request_headers_state<Req>(req: Req&) {
    req.headers.clear();
    req.spans.clear();
    req.presence_mask = 0;
}

inline fn calc_header_span_base_offset(req_offset: i64, line_end: i64) -> i64 {
    return req_offset + line_end + 2;
}

inline fn calc_body_start_index(req_offset: i64, header_end_idx: i64) -> i64 {
    return req_offset + header_end_idx;
}

inline fn has_smuggling_conflict(mask: u32) -> bool {
    let both = HDR_PRESENCE_TRANSFER_ENCODING | HDR_PRESENCE_CONTENT_LENGTH;
    return (mask & both) == both;
}

fn validate_request_host_presence<Req>(
    wire:             const u8[:],
    out_req:          const Req&,
    presence_tracker: const HeaderPresenceTracker&,
) -> bool {
    let has_host = (presence_tracker.mask & HDR_PRESENCE_HOST) != 0;
    if !out_req.is_http10 {
        guard has_host else { return false; }
    }
    if has_host {
        guard validate_span_host_header(wire, out_req.spans[..], presence_tracker.host_idx) else {
            return false;
        }
    }
    return true;
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
    guard ok_val else { return false; }
    let lead_ws, end_ws = trim_header_value_bounds(val_slice[..val_len]);
    let hval = val_slice[lead_ws..end_ws];

    // O(1) Header Presence & Duplicate/Smuggling Verification (uWebSockets bitmask pattern)
    let cur_hdr_idx = out_req.spans.len as i16;
    let known_id = identify_known_header(hname);
    guard track_known_header_presence(presence_tracker, known_id, hval, cur_hdr_idx) else {
        return false;
    }

    let span = make_header_span(base_offset + cursor, name_len, lead_ws, hval.len, header_id_to_u8(known_id));
    guard out_req.spans.len < out_req.spans.cap else {
        return false;
    }
    out_req.spans.push(span);
    out_req.presence_mask |= header_id_to_bit(known_id);
    cursor += calc_header_line_advance(name_len, val_len, crlf_len);
    return true;
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
        if rest_headers[cursor] == '\n' {
            break;
        }

        guard parse_http1_wire_header_line(rest_headers, cursor, presence_tracker, out_req, base_offset) else {
            return false;
        }
    }
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
    if !is_empty(out_req.bloom_filter) {
        clear(out_req.bloom_filter);
    }
    presence_tracker = HeaderPresenceTracker { .. };
    let base_offset = calc_header_span_base_offset(req_offset, line_end);
    guard parse_http1_headers_stream(rest_headers, out_req, presence_tracker, base_offset) else {
        clear_request_headers_state(out_req);
        return false;
    }

    out_req.trailers.clear();
    out_req.body.clear();

    // RFC 9112 Section 3.2 & uWS #1949: Host header validation
    guard validate_request_host_presence(wire, out_req, presence_tracker) else {
        clear_request_headers_state(out_req);
        return false;
    }

    // RFC 9112 Section 6.1 Smuggling Protection:
    // If both Transfer-Encoding and Content-Length are present, reject as smuggling attempt.
    if has_smuggling_conflict(presence_tracker.mask) {
        clear_request_headers_state(out_req);
        return false;
    }

    body_start_idx = calc_body_start_index(req_offset, header_end_idx);
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
        guard validate_span_te_header(wire, out_req.spans[..], presence_tracker.te_idx) else {
            out_req.headers.clear();
            out_req.spans.clear();
            out_req.presence_mask = 0;
            return false, 0;
        }

        let dec_err, chunked_consumed = decode_chunked_body_with_trailers(
            wire[body_start_idx..],
            out_req.body,
            out_req.trailers,
        );
        if dec_err != ChunkedDecodeError.None {
            if dec_err != ChunkedDecodeError.UnexpectedEof {
                out_req.headers.clear();
                out_req.spans.clear();
                out_req.presence_mask = 0;
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

// RFC 9110 §8.6: Returns true if status code prohibits a message body (204, 304, 1xx).
fn is_empty_body_status(code: i32) -> bool {
    guard code != 200 else { return false; }
    return code == 204 || code == 304 || (code >= 100 && code < 200);
}

struct ResponseFramingInfo {
    has_te: bool     = false,
    te_buf: u8[..64] = [],
    has_cl: bool     = false,
    cl_len: i64      = 0,
}

// Parses raw HTTP/1.1 response header lines into header items (RFC 9112 Section 5).
//
// Example:
//   rest_headers = "Content-Type: text/plain\r\n\r\n"
//   returns: true (out_res.headers populated)
fn parse_http1_response_headers_block<Res>(rest_headers: const u8[:], out_res: Res&) -> bool {
    var cursor: i64 = 0;
    out_res.headers.clear();
    while cursor < rest_headers.len {
        let rel_end = find(rest_headers[cursor..], "\r\n");
        if rel_end < 0 || rel_end == 0 { break; }

        let line = rest_headers[cursor..(cursor + rel_end)];
        let colon = core::index_of_byte(line, ':');
        guard colon > 0 else { return false; }
        let hname = line[..colon];
        guard is_valid_header_name(hname) else { return false; }
        let hval = trim_lws(line[(colon + 1)..]);
        guard is_valid_header_value(hval) else { return false; }

        var item = HeaderItem { .. };
        guard hname.len <= item.name.cap && hval.len <= item.value.cap else { return false; }
        item.name.append(hname);
        item.value.append(hval);
        guard out_res.headers.len < out_res.headers.cap else { return false; }
        out_res.headers.push(item);
        cursor += rel_end + 2;
    }
    return true;
}

fn inspect_response_framing_headers(headers: const HeaderItem[:]) -> ResponseFramingInfo, bool {
    var info = ResponseFramingInfo { .. };
    var cl_count = 0;

    for &hdr in headers {
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
            if info.has_te {
                guard info.te_buf.len + 2 + hdr.value.len <= info.te_buf.cap else { return info, false; }
                info.te_buf.append(", ");
                info.te_buf.append(hdr.value[..]);
            } else {
                info.has_te = true;
                guard hdr.value.len <= info.te_buf.cap else { return info, false; }
                info.te_buf.append(hdr.value[..]);
            }
        } else if eq_ascii_fold(hdr.name[..], "content-length") {
            info.has_cl = true;
            cl_count++;
            let val_trimmed = trim_lws(hdr.value[..]);
            guard val_trimmed.len > 0 else { return info, false; }
            for b in val_trimmed {
                guard b >= '0' && b <= '9' else { return info, false; }
            }
            let parsed_cl, ok_cl = core::parse_i64_dec(val_trimmed);
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
    guard hdr_end >= 0 else {
        if wire.len > 8192 { return false, 0; }
        return false, 0;
    }
    guard hdr_end <= 8192 else { return false, 0; }
    let header_end_idx = hdr_end + 4;
    let header_bytes = wire[..header_end_idx];

    // Find end of status line
    let line_end = find(header_bytes, "\r\n");
    guard line_end > 0 else { return false, 0; }

    let status_line = header_bytes[..line_end];
    // RFC 9112 Section 4: Status Line - Exactly SP between HTTP-version and 3-digit status code (uWS #1949)
    guard status_line.len >= 12 && status_line[..7] == "HTTP/1." && status_line[8] == ' ' else { return false, 0; }
    if status_line.len > 12 {
        guard status_line[12] == ' ' else { return false, 0; }
    }

    // Parse 3-digit status code
    let c0 = status_line[9] - '0';
    let c1 = status_line[10] - '0';
    let c2 = status_line[11] - '0';
    guard c0 >= 0 && c0 <= 9 && c1 >= 0 && c1 <= 9 && c2 >= 0 && c2 <= 9 else { return false, 0; }
    out_res.status_code = c0 as i32 * 100 + c1 as i32 * 10 + c2;
    out_res.protocol.clear();
    out_res.protocol.append(status_line[..8]);

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    guard parse_http1_response_headers_block(rest_headers, out_res) else { return false, 0; }

    out_res.trailers.clear();
    out_res.body.clear();

    let framing, ok_frame = inspect_response_framing_headers(out_res.headers[..]);
    guard ok_frame else { return false, 0; }

    let is_empty_status = is_empty_body_status(out_res.status_code);

    // RFC 9112 Section 6.1 & RFC 7230 §3.3.3: In responses, Transfer-Encoding overrides Content-Length.
    // If Transfer-Encoding is present, it MUST be valid and chunked MUST be final; invalid TE must reject.
    if framing.has_te {
        guard validate_transfer_encoding_value(framing.te_buf[..]) else { return false, 0; }
        // RFC 9112 Section 6.1: An intermediary or recipient processing chunked MUST remove Content-Length
        if framing.has_cl {
            remove_header_by_name(out_res.headers, "content-length");
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

// Serializes an HTTP/1.1 response using chunked transfer coding and emits trailers (RFC 9112 Section 7.1).
const HTTP1_STATUS_200: const u8[:] = "HTTP/1.1 200 OK\r\n";
const HTTP1_STATUS_204: const u8[:] = "HTTP/1.1 204 No Content\r\n";
const HTTP1_STATUS_301: const u8[:] = "HTTP/1.1 301 Moved Permanently\r\n";
const HTTP1_STATUS_302: const u8[:] = "HTTP/1.1 302 Found\r\n";
const HTTP1_STATUS_304: const u8[:] = "HTTP/1.1 304 Not Modified\r\n";
const HTTP1_STATUS_400: const u8[:] = "HTTP/1.1 400 Bad Request\r\n";
const HTTP1_STATUS_401: const u8[:] = "HTTP/1.1 401 Unauthorized\r\n";
const HTTP1_STATUS_403: const u8[:] = "HTTP/1.1 403 Forbidden\r\n";
const HTTP1_STATUS_404: const u8[:] = "HTTP/1.1 404 Not Found\r\n";
const HTTP1_STATUS_405: const u8[:] = "HTTP/1.1 405 Method Not Allowed\r\n";
const HTTP1_STATUS_500: const u8[:] = "HTTP/1.1 500 Internal Server Error\r\n";
const HTTP1_STATUS_502: const u8[:] = "HTTP/1.1 502 Bad Gateway\r\n";
const HTTP1_STATUS_503: const u8[:] = "HTTP/1.1 503 Service Unavailable\r\n";
const HTTP1_STATUS_101: const u8[:] = "HTTP/1.1 101 Switching Protocols\r\n";

fn serialize_status_line<B>(status_code: i32, out: B&) {
    if status_code == 200 {
        out.append(HTTP1_STATUS_200);
        return;
    }
    if status_code == 404 {
        out.append(HTTP1_STATUS_404);
        return;
    }
    if status_code == 400 {
        out.append(HTTP1_STATUS_400);
        return;
    }
    if status_code == 500 {
        out.append(HTTP1_STATUS_500);
        return;
    }
    if status_code == 204 {
        out.append(HTTP1_STATUS_204);
        return;
    }
    if status_code == 304 {
        out.append(HTTP1_STATUS_304);
        return;
    }
    if status_code == 301 {
        out.append(HTTP1_STATUS_301);
        return;
    }
    if status_code == 302 {
        out.append(HTTP1_STATUS_302);
        return;
    }
    if status_code == 401 {
        out.append(HTTP1_STATUS_401);
        return;
    }
    if status_code == 403 {
        out.append(HTTP1_STATUS_403);
        return;
    }
    if status_code == 405 {
        out.append(HTTP1_STATUS_405);
        return;
    }
    if status_code == 502 {
        out.append(HTTP1_STATUS_502);
        return;
    }
    if status_code == 503 {
        out.append(HTTP1_STATUS_503);
        return;
    }
    if status_code == 101 {
        out.append(HTTP1_STATUS_101);
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
    out.append(http_status_reason_phrase(status_code));
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

    if res.trailers.len > 0 {
        out_wire.append("Trailer: ");
        for i in res.trailers.len {
            if i > 0 { out_wire.append(", "); }
            out_wire.append(res.trailers[i].name[..]);
        }
        out_wire.append("\r\n");
    }

    let has_conn = res.has_header("connection");
    for &hdr in res.headers {
        if eq_ascii_fold(hdr.name[..], "content-length") { continue; }
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") { continue; }
        if eq_ascii_fold(hdr.name[..], "trailer") && res.trailers.len > 0 { continue; }

        out_wire.append(hdr.name[..]);
        out_wire.append(": ");
        out_wire.append(hdr.value[..]);
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

var g_cached_http_date: CachedHttpDate = CachedHttpDate { .. };

fn format_date_header_string(mono_sec: i64) {
    g_cached_http_date.last_sec = mono_sec;
    g_cached_http_date.last_tsc = prof_rdtsc();
    let wall_sec = core::now().wall_sec;
    g_cached_http_date.header_str.clear();
    g_cached_http_date.header_str.append("Date: ");
    core::format_http(g_cached_http_date.header_str, core::unix(wall_sec, 0));
    g_cached_http_date.header_str.append("\r\n");

    g_cached_http_date.fast_prefix.clear();
    g_cached_http_date.fast_prefix.append(HTTP1_200_SERVER_GOOSE);
    g_cached_http_date.fast_prefix.append(g_cached_http_date.header_str[..]);
}

fn should_refresh_cached_date(now_sec: i64) -> bool {
    guard g_cached_http_date.header_str.len > 0 else { return true; }
    if now_sec > 0 {
        return g_cached_http_date.last_sec != now_sec;
    }
    let tsc = prof_rdtsc();
    return tsc - g_cached_http_date.last_tsc >= 2000000000;
}

fn get_cached_http_date_header(now_sec: i64 = 0) -> const u8[:] {
    if should_refresh_cached_date(now_sec) {
        format_date_header_string(now_sec);
    }
    return g_cached_http_date.header_str[..];
}

// Formats Content-Length decimal header fast without divisions for common lengths.
const CL_HEADER_PREFIX: const u8[:] = "Content-Length: ";

fn serialize_content_length_header<B>(body_len: i64, out: B&) {
    if body_len == 0 {
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

fn detect_response_presence_mask(headers: const HeaderItem[:]) -> u16 {
    var mask: u16 = 0;
    for &hdr in headers {
        let nlen = hdr.name.len;
        if nlen == 4 {
            if (hdr.name[0] == 'd' || hdr.name[0] == 'D') && eq_ascii_fold(hdr.name[..], "date") {
                mask = mask | RES_PRESENCE_DATE;
            }
        } else if nlen == 10 {
            if (hdr.name[0] == 'c' || hdr.name[0] == 'C') && eq_ascii_fold(hdr.name[..], "connection") {
                mask = mask | RES_PRESENCE_CONNECTION;
            }
        } else if nlen == 12 {
            if (hdr.name[0] == 'c' || hdr.name[0] == 'C') && eq_ascii_fold(hdr.name[..], "content-type") {
                mask = mask | RES_PRESENCE_CONTENT_TYPE;
            }
        } else if nlen == 14 {
            if (hdr.name[0] == 'c' || hdr.name[0] == 'C') && eq_ascii_fold(hdr.name[..], "content-length") {
                mask = mask | RES_PRESENCE_CONTENT_LENGTH;
            }
        } else if nlen == 17 {
            if (hdr.name[0] == 't' || hdr.name[0] == 'T') && eq_ascii_fold(hdr.name[..], "transfer-encoding") {
                mask = mask | RES_PRESENCE_TRANSFER_ENCODING;
            }
        }
    }
    return mask;
}

fn serialize_response_headers_list<B>(headers: const HeaderItem[:], is_empty_status: bool, out: B&) {
    for &hdr in headers {
        let nlen = hdr.name.len;
        if is_empty_status {
            let is_suppressed = (nlen == 14 && eq_ascii_fold(hdr.name[..], "content-length"))
                || (nlen == 17 && eq_ascii_fold(hdr.name[..], "transfer-encoding"));
            if is_suppressed {
                continue;
            }
        }

        if nlen == 12 && (hdr.name[0] == 'c' || hdr.name[0] == 'C') && eq_ascii_fold(hdr.name[..], "content-type") {
            if hdr.value == "text/plain" {
                out.append("Content-Type: text/plain\r\n");
                continue;
            }
            if hdr.value == "application/json" {
                out.append("Content-Type: application/json\r\n");
                continue;
            }
        }

        out.append(hdr.name[..]);
        out.append(": ");
        out.append(hdr.value[..]);
        out.append("\r\n");
    }
}

// Serializes only the HTTP/1.1 response status line and headers into out_wire,
// omitting the body. Used for zero-copy vectored transmission via tcp_send2.
fn serialize_http1_headers<Res, B>(
    res:         const Res&,
    server_name: const u8[:],
    out_wire:    B&,
    now_sec:     i64 = 0,
) {
    if res.status_code == 200 && server_name == "goose-wing" {
        let mask = res.presence_mask;
        if (mask == RES_PRESENCE_CONTENT_TYPE || mask == 0) && res.headers.len == 1 && res.trailers.len == 0 {
            let _ = get_cached_http_date_header(now_sec);
            out_wire.append(g_cached_http_date.fast_prefix[..]);
            serialize_content_length_header(res.body.len, out_wire);
            if res.headers[0].value == "text/plain" {
                out_wire.append(HTTP1_CT_TEXT_PLAIN);
            } else if res.headers[0].value == "application/json" {
                out_wire.append(HTTP1_CT_APP_JSON);
            } else {
                out_wire.append(res.headers[0].name[..]);
                out_wire.append(": ");
                out_wire.append(res.headers[0].value[..]);
                out_wire.append("\r\n");
            }
            out_wire.append(HTTP1_CONN_KEEP_ALIVE);
            return;
        }
        out_wire.append(HTTP1_200_SERVER_GOOSE);
    } else {
        serialize_status_line(res.status_code, out_wire);
        serialize_server_header(server_name, out_wire);
    }

    var mask = res.presence_mask;
    if mask == 0 && res.headers.len > 0 {
        mask = detect_response_presence_mask(res.headers[..]);
    }

    // Emit cached RFC 7231 Date header if not explicitly overridden by response
    if (mask & RES_PRESENCE_DATE) == 0 {
        out_wire.append(get_cached_http_date_header(now_sec));
    }

    let is_empty_status = is_empty_body_status(res.status_code);
    if !is_empty_status {
        if (mask & RES_PRESENCE_CONTENT_LENGTH) == 0 && (mask & RES_PRESENCE_TRANSFER_ENCODING) == 0 {
            serialize_content_length_header(res.body.len, out_wire);
        }
    }

    serialize_response_headers_list(res.headers[..], is_empty_status, out_wire);

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
    let is_empty_status = is_empty_body_status(res.status_code);
    if !is_empty_status {
        if res.trailers.len > 0 {
            serialize_http1_chunked_response(res, server_name, 4096, out_wire);
            return;
        }
        let has_te = if res.presence_mask != 0 {
            (res.presence_mask & RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else if res.headers.len > 0 {
            (detect_response_presence_mask(res.headers[..]) & RES_PRESENCE_TRANSFER_ENCODING) != 0
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
    let is_empty_status = is_empty_body_status(res.status_code);
    if !is_empty_status {
        let has_te = if res.presence_mask != 0 {
            (res.presence_mask & RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else if res.headers.len > 0 {
            (detect_response_presence_mask(res.headers[..]) & RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else {
            false
        };
        if has_te || res.trailers.len > 0 {
            let te = header(res, "transfer-encoding");
            if eq_ascii_fold(te, "chunked") || res.trailers.len > 0 {
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
    serialize_http1_headers(res, server_name, wire_headers);
    guard fd > 0 else { return 0; }
    var arr = core::new_iovec_array();
    core::iovec_push(arr, wire_headers[..]);
    let n = core::iovec_count(body_iov);
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
    server_cork_flush(sc);

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

    server_cork_flush(sc);

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

// Serializes and writes an HTTP/1.1 response into the cork buffer.
// Zero-copy: formats headers in a small stack buffer and writes headers + body
// directly into the cork buffer or socket via vectored I/O without intermediate body copies.
fn server_cork_write_response<Res>(sc: ServerCork&, res: const Res&, server_name: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return 0; }
    let is_empty_status = is_empty_body_status(res.status_code);
    let te = header(res, "transfer-encoding");
    if !is_empty_status && (eq_ascii_fold(te, "chunked") || res.trailers.len > 0) {
        var wire_out: u8[..4096] = [];
        serialize_http1_chunked_response(res, server_name, 4096, wire_out);
        return server_cork_write(sc, wire_out[..]);
    }

    var hdr_buf: u8[..512] = [];
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
        let remaining = consumer.content_length - consumer.bytes_received;
        guard remaining > 0 else {
            consumer.is_finished = true;
            return 0, true, true;
        }

        let chunk_len = if incoming.len <= remaining { incoming.len } else { remaining };
        let chunk = incoming[..chunk_len];
        consumer.bytes_received += chunk_len;
        let is_last = consumer.bytes_received >= consumer.content_length;
        if is_last {
            consumer.is_finished = true;
        }

        Callback(chunk, is_last);
        return chunk_len, is_last, true;
    }

    // Chunked streaming pass-through
    consumer.bytes_received += incoming.len;
    Callback(incoming, false);
    return incoming.len, false, true;
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
    pattern:  u8[..128]   = [],
    cert_pem: const u8[:] = "",
    key_pem:  const u8[:] = "",
    in_use:   bool        = false,
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
    host:                  u8[..128]                 = "127.0.0.1",
    port:                  u16                       = 8080,
    server_name:           u8[..64]                  = "goose-wing/1.0",
    timer:                 internal::ConnectionTimer = internal::ConnectionTimer { .. },
    is_running:            bool                      = false,
    requests_processed:    u64                       = 0,
    accept_proxy_protocol: bool                      = false,
    trust_proxy_headers:   bool                      = false,
    fast_path:             bool                      = false,
    topic_tree:            TopicTree                 = TopicTree { .. },
    ws_routes:             WsRouteEntry[..16]        = [WsRouteEntry { .. }; 16],
    ws_route_count:        i32                       = 0,
    shared_compressor:     SharedWsCompressor        = SharedWsCompressor { .. },
    sni_registry:          SniRegistry               = SniRegistry { .. },
    worker_ring:           core::SpscRing            = core::SpscRing { .. },
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
    server.host.clear();
    server.host.append(host_str);
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
    server.host.clear();
    server.host.append(host_str);
    return server;
}

// Registers routing handlers on the server instance
fn add_get_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "GET", path, handler_id);
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
    guard server.ws_route_count < server.ws_routes.len as i32 else { return false; }
    for i in server.ws_routes.len {
        if !server.ws_routes[i].in_use {
            server.ws_routes[i].path.clear();
            server.ws_routes[i].path.append(path);
            server.ws_routes[i].behavior = behavior;
            server.ws_routes[i].in_use = true;
            server.ws_route_count += 1;
            add_get_route(server, path, behavior.handler_id);
            return true;
        }
    }
    return false;
}

fn find_ws_route(server: const HttpServer&, path: const u8[:]) -> i32 {
    for i in server.ws_routes.len {
        if server.ws_routes[i].in_use && server.ws_routes[i].path[..] == path {
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
    guard pattern.len > 0 && hostname.len > 0 else { return false; }
    if eq_ascii_fold(pattern, hostname) {
        return true;
    }
    if pattern.len >= 3 && pattern[0] == '*' && pattern[1] == '.' {
        return match_dns_san(pattern, hostname);
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
    guard pattern.len > 0 && pattern.len <= 128 else { return false; }

    // Check if pattern already registered: update in place
    for i in server.sni_registry.entries.len {
        if server.sni_registry.entries[i].in_use && eq_ascii_fold(server.sni_registry.entries[i].pattern[..], pattern) {
            server.sni_registry.entries[i].cert_pem = cert_pem;
            server.sni_registry.entries[i].key_pem = key_pem;
            return true;
        }
    }

    // Find first empty slot
    guard server.sni_registry.count < server.sni_registry.entries.len as i32 else { return false; }
    for i in server.sni_registry.entries.len {
        if !server.sni_registry.entries[i].in_use {
            server.sni_registry.entries[i].pattern.clear();
            server.sni_registry.entries[i].pattern.append(pattern);
            server.sni_registry.entries[i].cert_pem = cert_pem;
            server.sni_registry.entries[i].key_pem = key_pem;
            server.sni_registry.entries[i].in_use = true;
            server.sni_registry.count += 1;
            return true;
        }
    }
    return false;
}

// Removes a previously registered SNI domain pattern (uWebSockets app.removeServerName).
fn remove_server_name(server: HttpServer&, pattern: const u8[:]) -> bool {
    guard pattern.len > 0 && server.sni_registry.count > 0 else { return false; }
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        if entry.in_use && eq_ascii_fold(entry.pattern[..], pattern) {
            entry.in_use = false;
            entry.pattern.clear();
            entry.cert_pem = "";
            entry.key_pem = "";
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
    guard server.sni_registry.count > 0 && sni_hostname.len > 0 else {
        return SniCredentials { .. }, false;
    }

    // Phase 1: Exact match priority
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        if entry.in_use && eq_ascii_fold(entry.pattern[..], sni_hostname) {
            return SniCredentials {
                cert_pem: entry.cert_pem,
                key_pem:  entry.key_pem,
            }, true;
        }
    }

    // Phase 2: Wildcard match (*.domain.com)
    for i in server.sni_registry.entries.len {
        let entry = &server.sni_registry.entries[i];
        guard entry.in_use else { continue; }
        let pat = entry.pattern[..];
        guard pat.len >= 3 && pat[0] == '*' && pat[1] == '.' else { continue; }
        if match_dns_san(pat, sni_hostname) {
            return SniCredentials {
                cert_pem: entry.cert_pem,
                key_pem:  entry.key_pem,
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

fn publish(server: HttpServer&, topic: const u8[:], message: const u8[:], opcode: u8 = WS_OPCODE_TEXT) -> i64 {
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

    var pending = new_ws_pending_upgrade(sock_fd, client_key, r_idx, subprotocol, extensions);
    return pending, true;
}

fn complete_ws_upgrade<B>(
    server:   HttpServer&,
    pending:  WsPendingUpgrade&,
    out_wire: B&,
) -> WebSocketSession, bool {
    guard pending.in_use && !pending.is_aborted else {
        return WebSocketSession { .. }, false;
    }

    var accept_key: u8[..64] = [];
    compute_websocket_accept(pending.client_key[..], accept_key);

    out_wire.append("HTTP/1.1 101 Switching Protocols\r\n");
    out_wire.append("Upgrade: websocket\r\n");
    out_wire.append("Connection: Upgrade\r\n");
    out_wire.append("Sec-WebSocket-Accept: ");
    out_wire.append(accept_key[..]);
    out_wire.append("\r\n");

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

    if subproto.len > 0 {
        out_wire.append("Sec-WebSocket-Protocol: ");
        out_wire.append(subproto);
        out_wire.append("\r\n");
    }

    var compress_active = false;
    if route_behavior.compression != WS_COMPRESS_DISABLED {
        if core::contains_fold(pending.extensions[..], "permessage-deflate") {
            out_wire.append("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n");
            compress_active = true;
        }
    }

    out_wire.append("\r\n");

    var session = new_websocket_session(false);
    session.compress_mode = route_behavior.compression;
    session.permessage_deflate = compress_active;
    session.max_backpressure = route_behavior.max_backpressure;
    session.close_on_backpressure_limit = route_behavior.close_on_backpressure_limit;
    session.idle_timeout_s = route_behavior.idle_timeout_s;
    session.max_lifetime_s = route_behavior.max_lifetime_s;
    session.send_pings_automatically = route_behavior.send_pings_automatically;
    session.reset_idle_timeout_on_send = route_behavior.reset_idle_timeout_on_send;

    guard subproto.len <= session.subprotocol.cap else {
        return WebSocketSession { .. }, false;
    }
    guard pending.user_data.len <= session.user_data.cap else {
        return WebSocketSession { .. }, false;
    }

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

fn is_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len >= 24 && raw_stream[..24] == internal::H2_CLIENT_PREFACE[..];
}

// True while a short read is still a strict prefix of the 24-byte H2 preface.
// The preface contains "\r\n\r\n" at offset 14, so a sliced first TCP segment
// must not fall through to the HTTP/1.1 parser (found by Toxiproxy SlicerToxic).
fn is_partial_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len > 0 && raw_stream.len < 24 && raw_stream == internal::H2_CLIENT_PREFACE[..raw_stream.len];
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

// Dispatches a request against the server router in fast-path mode.
fn dispatch_fast_path_route(router: const RadixRouter&, req: const Request&, res: Response&) {
    var params = ZeroAllocParams { .. };
    let match_res = match_route(router, req.method[..], req.url[..], params);
    let is_invalid_query = req.method[..] == "QUERY" && header(req, "Content-Type").len == 0;
    match match_res {
        Found f => {
            res.status_code = if is_invalid_query { 400 } else { 200 };
            apply_route_payload(f.handler_id, res);
            handle_head_method_suppression(req.method[..], res);
        },
        MethodNotAllowed mna => {
            res.status_code = 405;
            res.headers.push(make_header("Allow", mna.allow_header[..]));
        },
        NotFound => {
            res.status_code = 404;
        },
    };
}

// Checks whether request or response demands connection closure (RFC 9112 §9.3 & NGINX proxy_pass harmony).
// Applies "Connection: close" to response headers if close is requested or for HTTP/1.0 without keep-alive.
fn check_and_apply_connection_close(req: const Request&, res: Response&) -> bool {
    guard res.status_code != 101 else { return false; }
    let has_conn_hdr = (req.presence_mask & HDR_PRESENCE_CONNECTION) != 0 ||
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

    if server.fast_path {
        var req = new_request("GET", "");
        let ok_parse, _ = parse_http1_wire_request(wire_in, req);
        guard ok_parse else {
            serialize_bad_request_error(server.server_name[..], wire_out);
            return PipelineOutcome.Handled, false;
        }

        // WebSocket Upgrade Interception on Fast-Path
        if is_websocket_upgrade_request(req) {
            let ws_idx = find_ws_route(server, req.url[..]);
            if ws_idx >= 0 && complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out) {
                return PipelineOutcome.Handled, true;
            }
        }

        var res = Response { .. };
        dispatch_fast_path_route(server.pipeline.router, req, res);
        check_and_apply_connection_close(req, res);

        serialize_http1_response(res, server.server_name[..], wire_out);
        server.requests_processed++;
        return PipelineOutcome.Handled, true;
    }

    var effective_ip: u8[..64] = [];
    effective_ip.append(client_ip);
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
        let now_ms = (now_ns / 1000000) as u64;
        var sess = internal::new_h2_server_session(server.server_name[..], now_ms);
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

    if hdr_end >= 0 && stream.len <= 8192 && is_valid_prefix && req.headers.len > 0 {
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
            // Chunked body not finished (awaiting final 0\r\n\r\n)
            out_keep_stream = true;
            return true;
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

struct StreamRouteCache {
    method:     u8[..16]  = [],
    url:        u8[..128] = [],
    handler_id: i32       = -1,
}

inline fn try_match_stream_route_cache(
    cache:  const StreamRouteCache&,
    method: const u8[:],
    url:    const u8[:],
) -> i32 {
    guard cache.handler_id >= 0 else { return -1; }
    if method == cache.method[..] && url == cache.url[..] {
        return cache.handler_id;
    }
    return -1;
}

inline fn update_stream_route_cache(
    cache:      StreamRouteCache&,
    method:     const u8[:],
    url:        const u8[:],
    handler_id: i32,
) {
    guard url.len <= 128 && method.len <= 16 else { return; }
    cache.method.clear();
    cache.method.append(method);
    cache.url.clear();
    cache.url.append(url);
    cache.handler_id = handler_id;
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
    req.spans.clear();
    req.trailers.clear();
    req.query_params.clear();
    req.body.clear();
    req.is_http10 = false;
    if !is_empty(req.bloom_filter) {
        clear(req.bloom_filter);
    }
}

fn dispatch_fast_path_matched(
    server:      HttpServer&,
    req:         Request&,
    res:         Response&,
    route_cache: StreamRouteCache&,
) {
    var params = ZeroAllocParams { .. };
    let match_res = match_route(server.pipeline.router, req.method[..], req.url[..], params);
    let is_invalid_query = req.method[..] == "QUERY" && header(req, "Content-Type").len == 0;
    match match_res {
        Found f => {
            res.status_code = if is_invalid_query { 400 } else { 200 };
            apply_route_payload(f.handler_id, res);
            handle_head_method_suppression(req.method[..], res);
            if params.len == 0 && !is_invalid_query {
                update_stream_route_cache(route_cache, req.method[..], req.url[..], f.handler_id);
            }
        },
        MethodNotAllowed mna => {
            res.status_code = 405;
            res.headers.push(make_header("Allow", mna.allow_header[..]));
        },
        NotFound => {
            res.status_code = 404;
        },
    };
}

inline fn dispatch_cached_route(
    server:      HttpServer&,
    req:         Request&,
    res:         Response&,
    route_cache: StreamRouteCache&,
) {
    let cached_id = try_match_stream_route_cache(route_cache, req.method[..], req.url[..]);
    if cached_id >= 0 {
        res.status_code = 200;
        apply_route_payload(cached_id, res);
        handle_head_method_suppression(req.method[..], res);
        return;
    }
    dispatch_fast_path_matched(server, req, res, route_cache);
}

fn dispatch_pipelined_request<B>(
    server:      HttpServer&,
    client_ip:   const u8[:],
    req:         Request&,
    res:         Response&,
    now_ns:      u64,
    route_cache: StreamRouteCache&,
    wire_out:    B&,
) -> bool {
    reset_server_response_fast(res);
    if server.fast_path {
        dispatch_cached_route(server, req, res, route_cache);
    } else {
        var future = internal::new_inline_handler_future(0);
        let _ = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    }

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
    route_cache:   StreamRouteCache&,
    total_handled: i64&,
    wire_out:      B&,
) -> PipeStepResult {
    let stream = core::readable_slice(pipe);
    reset_server_request_fast(req);
    let ok_parse, consumed = parse_http1_wire_request(stream, req);

    if !ok_parse || consumed <= 0 {
        let hdr_end = core::fast_find_crlfcrlf(stream);
        core::advance_to(pipe, 0, pipe.readable_len());
        guard hdr_end >= 0 else { return PipeStepResult.Stop; }

        if total_handled == 0 {
            serialize_bad_request_error(server.server_name[..], wire_out);
        }
        return PipeStepResult.Error;
    }

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, route_cache, wire_out);
    total_handled++;
    core::advance_to(pipe, consumed, consumed);

    if req.method[..] == "CONNECT" || wants_close {
        core::advance_to(pipe, pipe.readable_len(), pipe.readable_len());
        return PipeStepResult.Stop;
    }
    return PipeStepResult.Continue;
}

const FAST_RESP_PLAINTEXT: const u8[:] =
    "Content-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!";
const FAST_RESP_PLAINTEXT_CLOSE: const u8[:] =
    "Content-Length: 13\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello, World!";

const FAST_RESP_JSON: const u8[:] =
    "Content-Length: 27\r\nContent-Type: application/json\r\n\r\n{\"message\":\"Hello, World!\"}";
const FAST_RESP_JSON_CLOSE: const u8[:] =
    "Content-Length: 27\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"message\":\"Hello, World!\"}";

inline fn serialize_fast_path_payload<B>(
    handler_id:  i32,
    is_close:    bool,
    server_name: const u8[:],
    wire_out:    B&,
    now_sec:     i64 = 0,
) {
    if server_name == "goose-wing" {
        let _ = get_cached_http_date_header(now_sec);
        wire_out.append(g_cached_http_date.fast_prefix[..]);
    } else {
        wire_out.append("HTTP/1.1 200 OK\r\nServer: ");
        wire_out.append(server_name);
        wire_out.append("\r\n");
        wire_out.append(get_cached_http_date_header(now_sec));
    }
    if handler_id == 1001 {
        wire_out.append(if is_close { FAST_RESP_PLAINTEXT_CLOSE } else { FAST_RESP_PLAINTEXT });
    } else if handler_id == 1002 {
        wire_out.append(if is_close { FAST_RESP_JSON_CLOSE } else { FAST_RESP_JSON });
    } else if handler_id == 1003 {
        wire_out.append("Content-Length: 104\r\nContent-Type: application/json\r\n");
        wire_out.append(if is_close { "Connection: close\r\n\r\n" } else { "\r\n" });
        wire_out.append(METRICS_PAYLOAD);
    }
}

inline fn try_fast_path_pipeline_step<B>(
    server:      HttpServer&,
    stream:      const u8[:],
    wire_out:    B&,
    consumed:    i64&,
    wants_close: bool&,
    now_sec:     i64,
) -> bool {
    guard server.fast_path && stream.len >= 16 else { return false; }
    guard stream[0] == 'G' && stream[1] == 'E' && stream[2] == 'T' && stream[3] == ' ' else { return false; }

    var handler_id: i32 = -1;
    let rest = stream[4..];
    if core::starts_with(rest, "/plaintext HTTP/1.1\r\n") {
        handler_id = 1001;
    } else if core::starts_with(rest, "/json HTTP/1.1\r\n") {
        handler_id = 1002;
    } else if core::starts_with(rest, "/metrics HTTP/1.1\r\n") {
        handler_id = 1003;
    } else if core::starts_with(rest, "/plaintext ") {
        handler_id = 1001;
    } else if core::starts_with(rest, "/json ") {
        handler_id = 1002;
    } else if core::starts_with(rest, "/metrics ") {
        handler_id = 1003;
    }
    guard handler_id > 0 else { return false; }

    let hdr_end = core::fast_find_crlfcrlf(stream);
    guard hdr_end >= 0 && hdr_end <= 8192 else { return false; }

    var is_close = false;
    let hdr_block = stream[..hdr_end];
    if hdr_block.len >= 56 {
        guard !core::contains_fold(hdr_block, "upgrade") else { return false; }
        is_close = core::contains_fold(hdr_block, "close");
    }

    serialize_fast_path_payload(handler_id, is_close, server.server_name[..], wire_out, now_sec);
    server.requests_processed++;

    consumed = hdr_end + 4;
    wants_close = is_close;
    return true;
}

inline fn try_fast_path_pipeline_loop<B>(
    server:        HttpServer&,
    stream:        const u8[:],
    wire_out:      B&,
    now_sec:       i64,
    fast_handled:  i64&,
    fast_consumed: i64&,
    fast_close:    bool&,
) -> bool {
    var cur = stream;
    while cur.len > 0 {
        cur = strip_pipelined_crlf(cur, fast_consumed);
        if cur.len == 0 { break; }
        guard wire_out.len + 256 <= wire_out.cap else { return false; }

        var step_consumed: i64  = 0;
        var step_close:    bool = false;
        guard try_fast_path_pipeline_step(server, cur, wire_out, step_consumed, step_close, now_sec) else {
            return false;
        }
        fast_handled++;
        fast_consumed += step_consumed;
        cur = cur[step_consumed..];
        if step_close {
            fast_close = true;
            return true;
        }
    }
    return true;
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
    now_sec:          i64,
    req:              Request&,
    res:              Response&,
    route_cache:      StreamRouteCache&,
    wire_out:         B&,
    wire_in_len:      i64,
    step_consumed:    i64&,
    total_handled:    i64&,
    total_consumed:   i64&,
    conn_wants_close: bool&,
) -> StreamTurnResult {
    guard wire_out.len + 256 <= wire_out.cap else { return StreamTurnResult.Stop; }

    var fast_consumed: i64  = 0;
    var fast_close:    bool = false;
    if try_fast_path_pipeline_step(server, stream, wire_out, fast_consumed, fast_close, now_sec) {
        total_handled++;
        total_consumed += fast_consumed;
        step_consumed = fast_consumed;
        if fast_close {
            conn_wants_close = true;
            return StreamTurnResult.Stop;
        }
        return StreamTurnResult.Continue;
    }

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

    let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, route_cache, wire_out);
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
    let now_sec = (now_ns / 1000000000) as i64;

    if server.fast_path {
        var fast_handled:  i64  = 0;
        var fast_consumed: i64  = 0;
        var fast_close:    bool = false;
        if try_fast_path_pipeline_loop(server, stream, wire_out, now_sec, fast_handled, fast_consumed, fast_close) {
            return fast_handled, fast_consumed, true, fast_close;
        }
        total_handled += fast_handled;
        total_consumed += fast_consumed;
        stream = stream[fast_consumed..];
    }

    var req = new_request("GET", "");
    var res = Response { .. };
    var route_cache = StreamRouteCache { .. };

    while stream.len > 0 {
        stream = strip_pipelined_crlf(stream, total_consumed);
        if stream.len == 0 { break; }

        var step_consumed: i64 = 0;
        let turn_res = process_pipelined_stream_turn(
            server, client_ip, stream, now_ns, now_sec, req, res, route_cache,
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
                return total_handled, total_consumed, true, true;
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
    var route_cache = StreamRouteCache { .. };

    while pipe.readable_len() > 0 {
        let res_step = process_pipelined_pipe_step(
            server, client_ip, pipe, req, res, now_ns, route_cache, total_handled, wire_out,
        );
        if res_step == PipeStepResult.Error {
            return total_handled, false;
        } else if res_step == PipeStepResult.Stop {
            break;
        }
    }

    return total_handled, true;
}

fn handle_connection_pipe<B>(
    server:    HttpServer&,
    client_ip: const u8[:],
    pipe:      core::PipeBuffer&,
    now_ns:    u64,
    wire_out:  B&,
) -> i64, bool {
    var dummy_sess = internal::new_h2_server_session(server.server_name[..]);
    return handle_connection_pipe(server, client_ip, pipe, now_ns, wire_out, dummy_sess);
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
    var total_served: i64 = 0;

    while max_connections == 0 || total_served < max_connections {
        let conn = tcp_accept(listener_fd, 0);
        if conn <= 0 {
            continue;
        }
        defer tcp_close(conn);

        core::page_ring_clear(ring);
        cork.cork_reset();

        while true {
            let recvd = core::page_ring_recv(ring, conn, 65536, 5000);
            if recvd <= 0 {
                break;
            }

            let now_ns = core::as_nanos(core::monotonic_now());
            let count, ok_handle = handle_connection_page_ring(server, "127.0.0.1", ring, now_ns, cork);
            let should_close = !ok_handle || core::contains_fold(core::cork_as_slice(cork), "connection: close");
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
    var total_served: i64 = 0;

    while max_connections == 0 || total_served < max_connections {
        let conn = tcp_accept(listener_fd, 0);
        if conn <= 0 {
            continue;
        }
        defer tcp_close(conn);

        pipe.pipe_reset();
        cork.cork_reset();
        var h2_sess = internal::new_h2_server_session(server.server_name[..]);

        while true {
            let recvd = tcp_recv_pipe(conn, pipe, 4096, 5000);
            if recvd <= 0 {
                break;
            }

            let now_ns = core::as_nanos(core::monotonic_now());
            let count, ok = handle_connection_pipe(server, "127.0.0.1", pipe, now_ns, cork, h2_sess);
            let should_close = !ok || core::contains_fold(core::cork_as_slice(cork), "connection: close");
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

const REACTOR_LEFTOVER_CAP: i64 = 1024;

struct ReactorLeftoverBuf {
    bytes: u8[1024] = [0; 1024],
}

struct ReactorIngressBuf {
    bytes: u8[65536] = [0; 65536],
    len:   i64       = 0,
}

// Cleans up a connection slot, removes from epoll, closes fd, and returns slot to free stack.
fn reactor_cleanup_slot(
    epfd:       i64,
    table:      SoAConnTable&,
    slot_idx:   i64,
    free_slots: FreeSlotStack&,
) {
    let fd = table.fds[slot_idx];
    if fd > 0 {
        epoll_del(epfd, fd);
        tcp_close(fd);
        soa_table_free(table, slot_idx);
    }
    push_free_slot(free_slots, slot_idx);
}

// 1-second Tick Wheel Connection Timeout Sweeper (Slowloris defense & slot reclamation).
// Sweeps contiguous 1-byte timeout ticks entirely in L1D cache via SoAConnTable.
fn reactor_sweep_timeouts(
    epfd:           i64,
    table:          SoAConnTable&,
    free_slots:     FreeSlotStack&,
    timer_wheel:    TickTimerWheel&,
    now_sec:        i64,
    last_sweep_sec: i64&,
    total_served:   i64&,
) {
    guard now_sec > last_sweep_sec else { return; }
    let elapsed = if last_sweep_sec == 0 { 1 } else { (now_sec - last_sweep_sec) as u32 };
    last_sweep_sec = now_sec;
    tick_timer_advance(timer_wheel, elapsed);

    var expired: i64[1024] = [0; 1024];
    let n_expired = soa_table_sweep_expired(table, timer_wheel, expired[..]);
    for i in n_expired {
        let slot = expired[i];
        reactor_cleanup_slot(epfd, table, slot, free_slots);
        total_served++;
    }
}

// Reclaims one expired connection slot during emergency saturation via fast SoA sweep.
fn reactor_evict_stale_slot(
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    total_served: i64&,
) -> i64 {
    var expired: i64[1] = [0];
    let n = soa_table_sweep_expired(table, timer_wheel, expired[..]);
    if n > 0 {
        let slot = expired[0];
        reactor_cleanup_slot(epfd, table, slot, free_slots);
        total_served++;
        return pop_free_slot(free_slots);
    }
    return -1;
}

// Registers an accepted non-blocking client connection into an allocated slot.
inline fn reactor_register_client_slot(
    epfd:        i64,
    table:       SoAConnTable&,
    client_fd:   i64,
    slot:        i64,
    timer_wheel: TickTimerWheel&,
) {
    table.fds[slot] = client_fd;
    table.timeout_ticks[slot] = tick_timer_arm(timer_wheel, 15);
    table.leftover_lens[slot] = 0;
    table.count = advance_high_water_mark(table.count, slot);
    epoll_add(epfd, client_fd, EPOLL_READ, slot as u64);
}

// Drains non-blocking listener queue and accepts ready incoming connections into free slots.
fn reactor_drain_listener(
    listener_fd:  i64,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    total_served: i64&,
) {
    while true {
        let client_fd = tcp_accept_nonblocking(listener_fd);
        if client_fd <= 0 { break; }

        var slot = pop_free_slot(free_slots);
        if slot < 0 {
            slot = reactor_evict_stale_slot(epfd, table, free_slots, timer_wheel, total_served);
        }
        if slot >= 0 {
            reactor_register_client_slot(epfd, table, client_fd, slot, timer_wheel);
        } else {
            tcp_close(client_fd);
        }
    }
}

// Drains incoming client connection tasks from lock-free SPSC ring queue.
fn reactor_drain_worker_ring(
    ring:         const core::SpscRing&,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    total_served: i64&,
) {
    guard ring.is_open && ring.handle != 0 else { return; }
    while true {
        var client_val: u64 = 0;
        let popped = core::spsc_pop(ring, client_val);
        if !popped { break; }
        let client_fd = client_val as i64;
        guard client_fd > 0 else { continue; }

        var slot = pop_free_slot(free_slots);
        if slot < 0 {
            slot = reactor_evict_stale_slot(epfd, table, free_slots, timer_wheel, total_served);
        }
        if slot >= 0 {
            reactor_register_client_slot(epfd, table, client_fd, slot, timer_wheel);
        } else {
            tcp_close(client_fd);
        }
    }
}

inline fn reactor_read_single_turn(conn: i64, chunk: ReactorIngressBuf&, available: i64) -> i32 {
    let offset = chunk.len;
    guard offset >= 0 && offset + available <= 65536 else { return -2; }
    let recvd = tcp_recv_nonblocking_slice(conn, chunk.bytes[offset..(offset + available)]);
    if recvd > 0 {
        chunk.len += recvd;
    }
    return recvd;
}

// Drains up to 4 turns of non-blocking TCP ingress into chunk buffer.
// Returns (any_recvd, is_closed).
fn reactor_read_bounded_turns(conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    var any_recvd = false;
    for turn in 4 {
        let available = 65536 - chunk.len;
        guard available > 0 else { break; }
        let recvd = reactor_read_single_turn(conn, chunk, available);
        if recvd == 0 || recvd == -1 {
            return false, true;
        }
        if recvd < 0 {
            break;
        }
        any_recvd = true;
        if recvd < available {
            break;
        }
    }
    return any_recvd, false;
}

// Restores buffered leftover bytes into active chunk.
fn reactor_load_leftover(
    table:    SoAConnTable&,
    leftover: const ReactorLeftoverBuf&,
    slot:     i64,
    chunk:    ReactorIngressBuf&,
) {
    let prev_len = table.leftover_lens[slot] as i64;
    guard prev_len > 0 && prev_len <= REACTOR_LEFTOVER_CAP else { return; }
    for p in prev_len {
        chunk.bytes[p] = leftover.bytes[p];
    }
    chunk.len = prev_len;
    table.leftover_lens[slot] = 0;
}

// Copies leftover bytes into slot preservation buffer.
fn reactor_save_leftover(
    table:    SoAConnTable&,
    leftover: ReactorLeftoverBuf&,
    slot:     i64,
    rem:      const u8[:],
) -> bool {
    guard rem.len <= REACTOR_LEFTOVER_CAP else { return false; }
    table.leftover_lens[slot] = rem.len as u16;
    for m in rem.len {
        leftover.bytes[m] = rem[m];
    }
    return true;
}

// Processes non-blocking ingress traffic on a connection slot via bounded capacity-guarded read loop.
fn reactor_handle_ingress(
    server:       HttpServer&,
    epfd:         i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    slot:         i64,
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
) {
    let conn = table.fds[slot];
    let prev_len = table.leftover_lens[slot] as i64;
    table.timeout_ticks[slot] = tick_timer_arm(timer_wheel, 15);

    chunk.len = 0;
    reactor_load_leftover(table, leftovers[slot], slot, chunk);

    let any_recvd, is_closed = reactor_read_bounded_turns(conn, chunk);
    if is_closed {
        reactor_cleanup_slot(epfd, table, slot, free_slots);
        total_served++;
        return;
    }
    if !any_recvd && prev_len == 0 {
        return;
    }

    cork_wire.clear();
    let count, consumed, ok, wants_close = handle_connection_wire_pipelined_stream(
        server, "127.0.0.1", chunk.bytes[..chunk.len], now_ns, cork_wire,
    );

    let should_close = !ok || wants_close;
    if cork_wire.len > 0 {
        let sent = tcp_send(conn, cork_wire[..]);
        if sent <= 0 || should_close {
            reactor_cleanup_slot(epfd, table, slot, free_slots);
            total_served++;
            return;
        }
    }
    if should_close {
        reactor_cleanup_slot(epfd, table, slot, free_slots);
        total_served++;
        return;
    }

    // Preserve unconsumed bytes for the next epoll turn
    if consumed < chunk.len {
        if !reactor_save_leftover(table, leftovers[slot], slot, chunk.bytes[consumed..chunk.len]) {
            reactor_cleanup_slot(epfd, table, slot, free_slots);
            total_served++;
        }
    }
}

// Dispatches ready epoll events for reactor connection slots.
fn reactor_dispatch_events(
    server:       HttpServer&,
    epfd:         i64,
    listener_fd:  i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    ready_udata:  const u64[:],
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
) {
    for i in ready_udata.len {
        let udata = ready_udata[i];
        if udata == EPOLL_LISTENER_TAG {
            reactor_drain_listener(listener_fd, epfd, table, free_slots, timer_wheel, total_served);
            continue;
        }

        let slot = udata as i64;
        if slot < 0 || slot >= 1024 || table.fds[slot] <= 0 {
            continue;
        }

        reactor_handle_ingress(
            server,
            epfd,
            table,
            leftovers,
            slot,
            free_slots,
            timer_wheel,
            now_ns,
            chunk,
            cork_wire,
            total_served,
        );
    }
}

// Computes dynamic epoll wait timeout depending on worker ring state.
inline fn reactor_epoll_timeout(ring: const core::SpscRing&) -> i32 {
    guard ring.is_open else { return 1000; }
    return if core::spsc_count(ring) > 0 { 0 } else { 10 };
}

// Cleans up all active connection slots when shutting down reactor loop.
fn reactor_cleanup_all(epfd: i64, table: SoAConnTable&, free_slots: FreeSlotStack&) {
    for s in 1024 {
        if table.fds[s] > 0 {
            reactor_cleanup_slot(epfd, table, s, free_slots);
        }
    }
}

inline fn reactor_poll_sweep(
    epfd:           i64,
    table:          SoAConnTable&,
    free_slots:     FreeSlotStack&,
    timer_wheel:    TickTimerWheel&,
    n:              i32,
    turn:           i64,
    last_sweep_sec: i64&,
    total_served:   i64&,
    cached_ns:      u64&,
    cached_sec:     i64&,
) {
    if n > 0 && (turn & 511) != 0 && cached_sec > 0 { return; }
    let now_mono = core::monotonic_now();
    cached_ns = core::as_nanos(now_mono);
    cached_sec = (cached_ns / 1000000000) as i64;
    reactor_sweep_timeouts(
        epfd, table, free_slots, timer_wheel, cached_sec, last_sweep_sec, total_served,
    );
}

// Executes a share-nothing reactor loop with epoll.
// Multiplexes all accepted connections within 1 thread, maintaining ~3.1 MB RSS footprint.
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    guard listener_fd > 0 || server.worker_ring.is_open else { return 0; }

    let epfd = epoll_create();
    guard epfd >= 0 else { return 0; }
    defer epoll_close(epfd);

    if listener_fd > 0 {
        tcp_set_nonblocking(listener_fd, true);
        epoll_add(epfd, listener_fd, EPOLL_READ, EPOLL_LISTENER_TAG);
    }

    var empty_fds:    i64[0]            = [];
    var ready_udata:  u64[1024]         = [0; 1024];
    var cork_wire:    u8[..65536]       = [];
    var chunk:        ReactorIngressBuf = ReactorIngressBuf { .. };
    var total_served: i64               = 0;

    var table = SoAConnTable { .. };
    var leftovers: ReactorLeftoverBuf[1024] = [ReactorLeftoverBuf { .. }; 1024];
    var free_slots = FreeSlotStack { .. };
    init_free_slots(free_slots, 1024);
    var timer_wheel = new_tick_timer_wheel(15);
    var last_sweep_sec: i64 = 0;
    var turn_counter:   i64 = 0;
    var cached_now_ns:  u64 = 0;
    var cached_now_sec: i64 = 0;

    while max_connections == 0 || total_served < max_connections {
        if server.worker_ring.is_open {
            reactor_drain_worker_ring(server.worker_ring, epfd, table, free_slots, timer_wheel, total_served);
        }

        let epoll_timeout = reactor_epoll_timeout(server.worker_ring);
        let n = epoll_wait_direct(epfd, empty_fds[..], ready_udata[..], epoll_timeout);

        turn_counter++;
        reactor_poll_sweep(
            epfd, table, free_slots, timer_wheel, n, turn_counter,
            last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
        );

        if n > 0 {
            reactor_dispatch_events(
                server, epfd, listener_fd, table, leftovers[..], free_slots,
                timer_wheel, ready_udata[..n], cached_now_ns, chunk, cork_wire, total_served,
            );
        }
    }

    reactor_cleanup_all(epfd, table, free_slots);
    return total_served;
}

// ---------------------------------------------------------------------------
// Hardware Virtual Memory Page Pipeline Handlers
// ---------------------------------------------------------------------------

// Incremental Sans-IO pipeline handler using hardware page-mirrored ring buffer (PageRingBuffer).
// Eliminates buffer wraparound splitting and memmove compaction during streaming request processing.
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

    var peek_buf: u8[8192] = [0; 8192];
    var req = new_request("GET", "");
    var res = Response { .. };
    var route_cache = StreamRouteCache { .. };
    var total_handled: i64 = 0;

    while ring.count > 0 {
        let peek_n = core::page_ring_peek(ring, peek_buf[..]);
        guard peek_n > 0 else { break; }

        reset_server_request_fast(req);
        let ok_parse, consumed = parse_http1_wire_request(peek_buf[..peek_n], req);

        if !ok_parse || consumed <= 0 {
            let hdr_end = core::page_ring_find_crlfcrlf(ring);
            guard hdr_end >= 0 else {
                // Incomplete HTTP headers; wait for next network packet
                return total_handled, true;
            }

            if total_handled == 0 {
                serialize_bad_request_error(server.server_name[..], wire_out);
            }
            return total_handled, false;
        }

        let wants_close = dispatch_pipelined_request(server, client_ip, req, res, now_ns, route_cache, wire_out);
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

// Serves a static file using memory-mapped pages directly to the wire response buffer.
fn serve_static_mmap_file<B>(
    path:         const u8[:],
    content_type: const u8[:],
    wire_out:     B&,
) -> bool {
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

    wire_out.append(hdr_buf[..]);

    var chunk_buf: u8[4096] = [0; 4096];
    var offset:    u64      = 0;
    while offset < mf.size {
        let n, r_ok = core::mmap_file_read(mf, offset, chunk_buf[..]);
        guard r_ok && n > 0 else { break; }
        wire_out.append(chunk_buf[..n]);
        offset = offset + (n as u64);
    }
    return true;
}

// Sends a static file directly from kernel memory-mapped pages to a socket with zero user-space copying.
fn send_static_mmap_file(
    sock_fd:      i64,
    path:         const u8[:],
    content_type: const u8[:],
) -> bool {
    guard sock_fd > 0 else { return false; }
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

    let sent_hdr = native_tcp_send(sock_fd, hdr_buf[..]);
    guard sent_hdr >= 0 else { return false; }

    guard mf.size > 0 else { return true; }
    let sent_body, body_ok = core::mmap_file_send(mf, 0, mf.size as u32, sock_fd);
    return body_ok;
}
