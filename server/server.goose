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
import realtime.topic_tree;

// ---- 1. Reason Phrases for HTTP/1.1 Status Line -----------------------------

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

// ---- 2. HTTP/1.1 Wire Request Parser ---------------------------------------

// RFC 3986 §3.2.2 & RFC 9112 §3.2: Validates structural host header integrity.
//
// Example:
//   host_val = "[::1]:8080"
//   returns: true
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

fn validate_request_target_chars(path_slice: const u8[:]) -> bool {
    for b in path_slice {
        guard b >= 0x21 && b <= 0x7E else { return false; }
    }
    return true;
}

// Parses the HTTP/1.x request line (Method SP Request-URI SP HTTP-Version).
//
// Example:
//   req_line = "GET /index.html HTTP/1.1"
//   returns: true, out_req.method = "GET", out_req.url = "/index.html"
fn parse_http1_request_line<Req>(
    req_line: const u8[:],
    out_req: Req&,
) -> bool {
    let sp1 = core::index_of_byte(req_line, ' ');
    guard sp1 > 0 else { return false; }
    let method_slice = req_line[..sp1];
    guard is_valid_header_name(method_slice) && method_slice.len <= out_req.method.cap else { return false; }
    out_req.method.clear();
    out_req.method.append(method_slice);

    let rest = req_line[(sp1 + 1)..];
    let sp2_rel = core::index_of_byte(rest, ' ');
    guard sp2_rel > 0 else { return false; }
    let path_slice = rest[..sp2_rel];
    guard path_slice.len > 0 && path_slice.len <= out_req.url.cap else { return false; }
    guard validate_request_target_chars(path_slice) else { return false; }

    if method_slice == "CONNECT" {
        guard path_slice != "*" && path_slice[0] != '/' else { return false; }
        let col = core::index_of_byte(path_slice, ':');
        guard col > 0 && col + 1 < path_slice.len else { return false; }
        let port_num, port_ok = core::parse_port_number(path_slice[(col + 1)..]);
        guard port_ok && port_num > 0 else { return false; }
    } else if path_slice == "*" {
        guard method_slice == "OPTIONS" else { return false; }
    } else {
        guard path_slice[0] == '/' else { return false; }
    }

    out_req.url.clear();
    out_req.url.append(path_slice);

    let proto_slice = rest[(sp2_rel + 1)..];
    guard proto_slice == "HTTP/1.1" || proto_slice == "HTTP/1.0" else { return false; }
    out_req.is_http10 = (proto_slice == "HTTP/1.0");
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

// Parses a single wire header line using single-pass SWAR scanning and tchar validation.
// Advances `cursor` past the trailing CRLF delimiter.
//
// Example:
//   rest_headers = "Host: example.com\r\n\r\n", cursor = 0
//   returns: ok = true, cursor = 19 (points to final CRLF)
fn parse_http1_wire_header_line<Req>(
    rest_headers: const u8[:],
    cursor: i64&,
    presence_tracker: HeaderPresenceTracker&,
    out_req: Req&,
) -> bool {
    // Single-pass SWAR header name scanning & RFC 9110 tchar validation
    let name_len, ok_name = scan_header_field_name_swar(rest_headers[cursor..]);
    guard ok_name && name_len > 0 else { return false; }
    let hname = rest_headers[cursor..(cursor + name_len)];

    // Single-pass SWAR header value scanning & CTL/CRLF detection
    let val_slice = rest_headers[(cursor + name_len + 1)..];
    let val_len, crlf_len, ok_val = scan_header_field_value_swar(val_slice);
    guard ok_val else { return false; }
    let hval = trim_lws(val_slice[..val_len]);

    // O(1) Header Presence & Duplicate/Smuggling Verification (uWebSockets bitmask pattern)
    let cur_hdr_idx = out_req.headers.len as i16;
    guard track_header_presence(presence_tracker, hname, hval, cur_hdr_idx) else {
        return false;
    }

    var item = HeaderItem { .. };
    guard hname.len <= item.name.cap && hval.len <= item.value.cap else {
        return false;
    }
    item.name.append(hname);
    item.value.append(hval);
    guard out_req.headers.len < out_req.headers.cap else {
        return false;
    }
    out_req.headers.push(item);
    add_header(out_req.bloom_filter, hname);
    cursor += name_len + 1 + val_len + crlf_len;
    return true;
}

// Parses raw HTTP/1.x header lines into HeaderItem entries and tracks presence bitmask.
// Uses single-pass SWAR scanning for header name, delimiter, value, and CTL validation.
//
// Example:
//   rest_headers = "Host: localhost\r\nUser-Agent: test\r\n\r\n"
//   returns: true, out_req.headers.len = 2
fn parse_http1_headers_stream<Req>(
    rest_headers: const u8[:],
    out_req: Req&,
    presence_tracker: HeaderPresenceTracker&,
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

        guard parse_http1_wire_header_line(rest_headers, cursor, presence_tracker, out_req) else {
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
    wire: const u8[:],
    out_req: Req&,
    presence_tracker: HeaderPresenceTracker&,
    body_start_idx: i64&,
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
    let line_end = core::index_of_slice(header_bytes, "\r\n");
    guard line_end > 0 else { return false; }
    guard parse_http1_request_line(header_bytes[..line_end], out_req) else { return false; }

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    out_req.headers.clear();
    clear(out_req.bloom_filter);
    presence_tracker = HeaderPresenceTracker { .. };
    guard parse_http1_headers_stream(rest_headers, out_req, presence_tracker) else {
        out_req.headers.clear();
        return false;
    }

    out_req.trailers.clear();
    out_req.body.clear();

    // RFC 9112 Section 3.2 & uWS #1949: Host header validation
    if !out_req.is_http10 {
        // Must have exactly one Host header in HTTP/1.1 (verified via bitmask presence)
        guard (presence_tracker.mask & HDR_PRESENCE_HOST) != 0 else {
            out_req.headers.clear();
            return false;
        }
    }
    if (presence_tracker.mask & HDR_PRESENCE_HOST) != 0 {
        let host_idx = presence_tracker.host_idx as i64;
        guard host_idx >= 0 && host_idx < out_req.headers.len else {
            out_req.headers.clear();
            return false;
        }

        let host_val = out_req.headers[host_idx].value[..];
        guard host_val.len > 0 && validate_host_header_chars(host_val) else {
            out_req.headers.clear();
            return false;
        }

        // Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Structural IP-literal Host validation
        guard validate_host_header_structure(host_val) else {
            out_req.headers.clear();
            return false;
        }
    }

    // Check for Transfer-Encoding and Content-Length using bitmask presence
    let has_te = (presence_tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;

    // RFC 9112 Section 6.1 Smuggling Protection:
    // If both Transfer-Encoding and Content-Length are present, reject as smuggling attempt.
    if has_te && has_cl {
        out_req.headers.clear();
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

    var te_buf: u8[..64] = [];
    if has_te {
        guard collect_transfer_encoding_headers(out_req.headers, te_buf) else {
            out_req.headers.clear();
            return false, 0;
        }
    }

    if has_te {
        // Must validate transfer encoding value per RFC 9112 Section 6.3 & 7.1
        guard validate_transfer_encoding_value(te_buf[..]) else {
            out_req.headers.clear();
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
    return code == 204 || code == 304 || (code >= 100 && code < 200);
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
    let line_end = core::index_of_slice(header_bytes, "\r\n");
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
    var cursor: i64 = 0;
    out_res.headers.clear();
    while cursor < rest_headers.len {
        let rel_end = core::index_of_slice(rest_headers[cursor..], "\r\n");
        if rel_end < 0 { break; }
        if rel_end == 0 { break; }

        let line = rest_headers[cursor..(cursor + rel_end)];
        let colon = core::index_of_byte(line, ':');
        guard colon > 0 else { return false, 0; }
        let hname = line[..colon];
        guard is_valid_header_name(hname) else { return false, 0; }
        let hval = trim_lws(line[(colon + 1)..]);
        guard is_valid_header_value(hval) else { return false, 0; }

        var item = HeaderItem { .. };
        guard hname.len <= item.name.cap && hval.len <= item.value.cap else { return false, 0; }
        item.name.append(hname);
        item.value.append(hval);
        guard out_res.headers.len < out_res.headers.cap else { return false, 0; }
        out_res.headers.push(item);
        cursor += rel_end + 2;
    }

    out_res.trailers.clear();
    out_res.body.clear();

    // Check Transfer-Encoding
    var has_te = false;
    var te_buf: u8[..64] = [];
    var has_cl = false;
    var cl_count = 0;
    var cl_len: i64 = 0;

    for &hdr in out_res.headers {
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
            if has_te {
                guard te_buf.len + 2 + hdr.value.len <= te_buf.cap else { return false, 0; }
                te_buf.append(", ");
                te_buf.append(hdr.value[..]);
            } else {
                has_te = true;
                te_buf.clear();
                guard hdr.value.len <= te_buf.cap else { return false, 0; }
                te_buf.append(hdr.value[..]);
            }
        } else if eq_ascii_fold(hdr.name[..], "content-length") {
            has_cl = true;
            cl_count++;
            let val_trimmed = trim_lws(hdr.value[..]);
            guard val_trimmed.len > 0 else { return false, 0; }
            // RFC 9110 §8.6: Content-Length = 1*DIGIT (no leading '+' or '-' sign)
            for b in val_trimmed {
                guard b >= '0' && b <= '9' else { return false, 0; }
            }
            let parsed_cl, ok_cl = core::parse_i64_dec(val_trimmed);
            guard ok_cl && parsed_cl >= 0 else { return false, 0; }
            if cl_count == 1 {
                cl_len = parsed_cl;
            } else if cl_len != parsed_cl {
                // Conflicting multiple Content-Length headers -> reject
                return false, 0;
            }
        }
    }

    let is_empty_status = is_empty_body_status(out_res.status_code);

    // RFC 9112 Section 6.1 & RFC 7230 §3.3.3: In responses, Transfer-Encoding overrides Content-Length.
    // If Transfer-Encoding is present, it MUST be valid and chunked MUST be final; invalid TE must reject.
    if has_te {
        guard validate_transfer_encoding_value(te_buf[..]) else { return false, 0; }
        // RFC 9112 Section 6.1: An intermediary or recipient processing chunked MUST remove Content-Length
        if has_cl {
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

    if has_cl {
        guard cl_len >= 0 && cl_len <= 0x7FFFFFFF && wire.len >= header_end_idx + cl_len else { return false, 0; }
        if cl_len > 0 {
            out_res.body.append(wire[header_end_idx..(header_end_idx + cl_len)]);
        }
        return true, header_end_idx + cl_len;
    }

    // Otherwise, consume remainder of stream until connection close
    if wire.len > header_end_idx {
        out_res.body.append(wire[header_end_idx..]);
    }
    return true, wire.len;
}

// ---- 3. HTTP/1.1 Wire Response Serializer -----------------------------------

// Serializes an HTTP/1.1 response using chunked transfer coding and emits trailers (RFC 9112 Section 7.1).
fn serialize_status_line<B>(status_code: i32, out: B&) {
    if status_code == 101 {
        out.append("HTTP/1.1 101 Switching Protocols\r\n");
        return;
    }
    if status_code == 200 {
        out.append("HTTP/1.1 200 OK\r\n");
        return;
    }
    if status_code == 404 {
        out.append("HTTP/1.1 404 Not Found\r\n");
        return;
    }
    if status_code == 400 {
        out.append("HTTP/1.1 400 Bad Request\r\n");
        return;
    }
    if status_code == 500 {
        out.append("HTTP/1.1 500 Internal Server Error\r\n");
        return;
    }
    out.append("HTTP/1.1 ");
    core::format_i64_dec(status_code as i64, out);
    out.push(' ');
    out.append(http_status_reason_phrase(status_code));
    out.append("\r\n");
}

fn serialize_server_header<B>(server_name: const u8[:], out: B&) {
    if server_name.len > 0 {
        out.append("Server: ");
        out.append(server_name);
        out.append("\r\n");
    }
}

fn serialize_http1_chunked_response<Res, B>(
    res: const Res&,
    server_name: const u8[:],
    chunk_size: i64,
    out_wire: B&,
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

// Formats the Date header at most once per second into a reusable pre-baked string.
// Eliminates repetitive wall-clock system calls and calendar math for every HTTP response.
struct CachedHttpDate {
    header_str: u8[..64] = [],
    last_sec: i64 = 0,
}

var g_cached_http_date: CachedHttpDate = CachedHttpDate { .. };

fn get_cached_http_date_header(now_sec: i64 = 0) -> const u8[:] {
    let eff_sec = if now_sec > 0 { now_sec } else { core::now().wall_sec };
    if g_cached_http_date.last_sec != eff_sec || g_cached_http_date.header_str.len == 0 {
        g_cached_http_date.last_sec = eff_sec;
        g_cached_http_date.header_str.clear();
        g_cached_http_date.header_str.append("Date: ");
        core::format_http(g_cached_http_date.header_str, core::unix(eff_sec, 0));
        g_cached_http_date.header_str.append("\r\n");
    }
    return g_cached_http_date.header_str[..];
}

// Serializes only the HTTP/1.1 response status line and headers into out_wire,
// omitting the body. Used for zero-copy vectored transmission via tcp_send2.
fn serialize_http1_headers<Res, B>(res: const Res&, server_name: const u8[:], out_wire: B&) {
    serialize_status_line(res.status_code, out_wire);
    serialize_server_header(server_name, out_wire);

    var mask = res.presence_mask;
    if mask == 0 && res.headers.len > 0 {
        for &hdr in res.headers {
            if eq_ascii_fold(hdr.name[..], "date") {
                mask = mask | RES_PRESENCE_DATE;
            } else if eq_ascii_fold(hdr.name[..], "content-length") {
                mask = mask | RES_PRESENCE_CONTENT_LENGTH;
            } else if eq_ascii_fold(hdr.name[..], "connection") {
                mask = mask | RES_PRESENCE_CONNECTION;
            } else if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
                mask = mask | RES_PRESENCE_TRANSFER_ENCODING;
            }
        }
    }

    // Emit cached RFC 7231 Date header if not explicitly overridden by response
    if (mask & RES_PRESENCE_DATE) == 0 {
        out_wire.append(get_cached_http_date_header());
    }

    let is_empty_status = is_empty_body_status(res.status_code);

    if !is_empty_status {
        // uWS #1855 / RFC 9110 §8.6: Do not emit automatic Content-Length
        // if already specified in res.headers (e.g. HEAD)
        if (mask & RES_PRESENCE_CONTENT_LENGTH) == 0 && (mask & RES_PRESENCE_TRANSFER_ENCODING) == 0 {
            if res.body.len == 0 {
                out_wire.append("Content-Length: 0\r\n");
            } else {
                out_wire.append("Content-Length: ");
                core::format_i64_dec(res.body.len, out_wire);
                out_wire.append("\r\n");
            }
        }
    }

    let has_conn = (mask & RES_PRESENCE_CONNECTION) != 0;

    for &hdr in res.headers {
        // RFC 9110 §8.6 & uWS #1370: Suppress Content-Length and Transfer-Encoding on empty body
        let is_suppressed_hdr = eq_ascii_fold(hdr.name[..], "content-length")
            || eq_ascii_fold(hdr.name[..], "transfer-encoding");
        if is_empty_status && is_suppressed_hdr {
            continue;
        }

        out_wire.append(hdr.name[..]);
        out_wire.append(": ");
        out_wire.append(hdr.value[..]);
        out_wire.append("\r\n");
    }

    if !has_conn {
        out_wire.append("Connection: keep-alive\r\n");
    }

    out_wire.append("\r\n");
}

// Serializes a complete HTTP/1.1 response into raw wire bytes.
// Automatically uses chunked transfer encoding if Transfer-Encoding: chunked is requested or if trailers are present.
fn serialize_http1_response<Res, B>(res: const Res&, server_name: const u8[:], out_wire: B&) {
    let is_empty_status = is_empty_body_status(res.status_code);
    let te = header(res, "transfer-encoding");
    if !is_empty_status && (eq_ascii_fold(te, "chunked") || res.trailers.len > 0) {
        serialize_http1_chunked_response(res, server_name, 4096, out_wire);
        return;
    }

    serialize_http1_headers(res, server_name, out_wire);

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
    let te = header(res, "transfer-encoding");
    if !is_empty_status && (eq_ascii_fold(te, "chunked") || res.trailers.len > 0) {
        serialize_http1_chunked_response(res, server_name, 4096, wire_headers);
        return tcp_send(fd, wire_headers[..]);
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
    fd: i64,
    res: const Res&,
    server_name: const u8[:],
    body_iov: const core::IoVecArray&,
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
//
// Example:
//   res.status_code = 200, reported_content_length = 1048576, close_connection = false
//   out_wire populated with "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n"
fn end_without_body<Res, B>(
    res: Res&,
    server_name: const u8[:],
    out_wire: B&,
    reported_content_length: i64 = -1,
    close_connection: bool = false,
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
    fd: i64,
    res: Res&,
    server_name: const u8[:],
    wire_headers: B&,
    reported_content_length: i64 = -1,
    close_connection: bool = false,
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
    buffer: core::CorkBuffer = core::new_cork_buffer(),
    sock_fd: i64 = -1,
}

fn new_server_cork(fd: i64) -> ServerCork {
    return ServerCork {
        buffer: core::new_cork_buffer(),
        sock_fd: fd,
    };
}

// Writes data into the cork buffer. If it fits, data is buffered without any syscall.
// If the buffer would overflow, pending data is flushed first, then data is buffered or sent directly.
fn server_cork_write(sc: ServerCork&, data: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 && data.len > 0 else { return 0; }
    let avail = core::cork_available(sc.buffer);
    if data.len <= avail {
        core::append(sc.buffer, data);
        return data.len as i32;
    }

    // Buffer would overflow: flush current pending bytes first
    server_cork_flush(sc);

    if data.len >= core::CORK_BUFFER_CAP {
        // Larger than cork buffer: send directly via TCP
        return tcp_send(sc.sock_fd, data);
    }

    core::append(sc.buffer, data);
    return data.len as i32;
}

// Flushes all pending data in the cork buffer to the socket in a single syscall.
fn server_cork_flush(sc: ServerCork&) -> i32 {
    guard sc.sock_fd > 0 && !core::cork_is_empty(sc.buffer) else { return 0; }
    return tcp_flush_cork(sc.sock_fd, sc.buffer);
}

// State of a streaming HTTP/1.1 request body consumer (uWebSockets onData / onDataV2 pattern)
struct HttpStreamConsumer {
    content_length: i64 = -1,
    bytes_received: i64 = 0,
    header_end_idx: i64 = 0,
    is_chunked: bool = false,
    is_headers_parsed: bool = false,
    is_finished: bool = false,
}

// Parses request headers and prepares a streaming body reader without buffering the entire body.
// Returns (ok, header_end_offset).
//
// Example:
//   wire = "POST /upload HTTP/1.1\r\nHost: api\r\nContent-Length: 1048576\r\n\r\n<data>"
//   returns: ok = true, header_end_idx = points to start of body, consumer.content_length = 1048576
fn begin_http_stream_request<Req>(
    wire: const u8[:],
    out_req: Req&,
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
//
// Example:
//   consumer initialized with content_length = 10, chunk = "0123456789"
//   calls Callback("0123456789", true), returns: 10, true, true
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
    sock_fd: i64 = -1,
    is_aborted: bool = false,
    is_backpressured: bool = false,
    total_written: u64 = 0,
    user_tag: u64 = 0,
    in_use: bool = false,
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

// ---- 4. HttpServer Container and Session Coordinator -----------------------

// Dynamic Runtime SNI multi-certificate credentials (uWebSockets addServerName / removeServerName pattern).
struct SniCertEntry {
    pattern: u8[..128] = [],
    cert_pem: const u8[:] = "",
    key_pem: const u8[:] = "",
    in_use: bool = false,
}

const MAX_SNI_DOMAINS: i64 = 32;

struct SniRegistry {
    entries: SniCertEntry[32] = [SniCertEntry { .. }; 32],
    count: i32 = 0,
}

struct SniCredentials {
    cert_pem: const u8[:] = "",
    key_pem: const u8[:] = "",
}

struct WsRouteEntry {
    path: u8[..128] = [],
    behavior: WsBehavior = WsBehavior { .. },
    in_use: bool = false,
}

struct HttpServer {
    pipeline: ServerPipelineConfig = ServerPipelineConfig { .. },
    host: u8[..128] = "127.0.0.1",
    port: u16 = 8080,
    server_name: u8[..64] = "goose-wing/1.0",
    timer: internal::ConnectionTimer = internal::ConnectionTimer { .. },
    is_running: bool = false,
    requests_processed: u64 = 0,
    accept_proxy_protocol: bool = false,
    trust_proxy_headers: bool = false,
    fast_path: bool = false,
    topic_tree: TopicTree = TopicTree { .. },
    ws_routes: WsRouteEntry[..16] = [WsRouteEntry { .. }; 16],
    ws_route_count: i32 = 0,
    shared_compressor: SharedWsCompressor = SharedWsCompressor { .. },
    sni_registry: SniRegistry = SniRegistry { .. },
}

fn new_http_server(
    host_str: const u8[:] = "127.0.0.1",
    port_num: u16 = 8080,
) -> HttpServer {
    var server = HttpServer {
        pipeline: new_default_server_pipeline_config(host_str),
        port: port_num,
        timer: internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running: true,
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
    quota: Q,
) -> HttpServer {
    var server = HttpServer {
        pipeline: new_server_pipeline_config(host_str, quota),
        port: port_num,
        timer: internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running: true,
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
//
// Example:
//   pattern = "*.example.com", hostname = "api.example.com"
//   returns: true
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
    server: HttpServer&,
    pattern: const u8[:],
    cert_pem: const u8[:],
    key_pem: const u8[:],
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
    server: const HttpServer&,
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
                key_pem: entry.key_pem,
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
                key_pem: entry.key_pem,
            }, true;
        }
    }

    return SniCredentials { .. }, false;
}

// Resolves TLS credentials for an SNI hostname with fallback handler for missing server names
// (uWebSockets app.missingServerName pattern).
fn resolve_sni_credentials_with_fallback<Fallback: fn(const u8[:]) -> SniCredentials>(
    server: const HttpServer&,
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
    server: HttpServer&,
    sock_fd: i64,
    topic_pattern: const u8[:],
    out_old: i32&,
    out_new: i32&,
) -> bool {
    return subscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn unsubscribe_ex(
    server: HttpServer&,
    sock_fd: i64,
    topic_pattern: const u8[:],
    out_old: i32&,
    out_new: i32&,
) -> bool {
    return unsubscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server: HttpServer&,
    sock_fd: i64,
    topic_pattern: const u8[:],
) -> bool {
    return subscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    server: HttpServer&,
    sock_fd: i64,
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
    server: const HttpServer&,
    req: const Request&,
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
    server: HttpServer&,
    pending: WsPendingUpgrade&,
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
        Found f => { res.status_code = if is_invalid_query { 400 } else { 200 }; },
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
//
// Example:
//   req header "connection: close"
//   returns: true (res has "Connection: close")
fn check_and_apply_connection_close(req: const Request&, res: Response&) -> bool {
    guard res.status_code != 101 else { return false; }
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
    server: HttpServer&,
    req: const Req&,
    entry: const WebSocketRoute&,
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
    server: HttpServer&,
    client_ip: const u8[:],
    wire_in: const u8[:],
    now_ns: u64,
    wire_out: B&,
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
    stream: const u8[:],
    hdr_end: i64,
    cl_str: const u8[:],
    server_name: const u8[:],
    wire_out: B&,
    out_keep: bool&,
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
    server_name: const u8[:],
    stream: const u8[:],
    req: const Request&,
    wire_out: B&,
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

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests.
// Returns (total_requests_processed, total_bytes_consumed, ok, wants_close).
fn handle_connection_wire_pipelined_stream<B>(
    server: HttpServer&,
    client_ip: const u8[:],
    wire_in: const u8[:],
    now_ns: u64,
    wire_out: B&,
) -> i64, i64, bool, bool {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    wire_out.clear();
    var stream = wire_in;
    var total_handled: i64 = 0;
    var total_consumed: i64 = 0;
    var conn_wants_close: bool = false;

    var req = new_request("GET", "");
    var res = Response { .. };

    while stream.len > 0 {
        // Strip optional benign CRLFs between pipelined requests (RFC 9112 §2.2)
        while stream.len > 0 && (stream[0] == '\r' || stream[0] == '\n') {
            stream = stream[1..];
            total_consumed++;
        }
        if stream.len == 0 { break; }

        reset_request(req);
        let ok_parse, consumed = parse_http1_wire_request(stream, req);
        guard ok_parse && consumed > 0 else {
            var keep_stream = false;
            let _ = handle_pipelined_parse_failure(
                server.server_name[..],
                stream,
                req,
                wire_out,
                keep_stream,
            );
            return total_handled, total_consumed, keep_stream, true;
        }

        // WebSocket Upgrade Interception on Pipelined Stream
        if is_websocket_upgrade_request(req) {
            let ws_idx = find_ws_route(server, req.url[..]);
            if ws_idx >= 0 && complete_ws_upgrade(server, req, server.ws_routes[ws_idx as i64], wire_out) {
                total_handled++;
                total_consumed += consumed;
                return total_handled, total_consumed, true, false;
            }
        }

        reset_response(res);
        if server.fast_path {
            dispatch_fast_path_route(server.pipeline.router, req, res);
        } else {
            var future = internal::new_inline_handler_future(0);
            let outcome = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
        }

        let wants_close = check_and_apply_connection_close(req, res);
        if wants_close {
            conn_wants_close = true;
        }

        serialize_http1_response(res, server.server_name[..], wire_out);
        server.requests_processed++;
        total_handled++;
        total_consumed += consumed;

        // RFC 9112 §9.3.6 & CVE-2026-94439: Stop pipelined HTTP processing upon CONNECT or Connection: close
        if req.method[..] == "CONNECT" {
            total_consumed = wire_in.len;
            conn_wants_close = true;
            break;
        }

        if wants_close {
            break;
        }

        stream = stream[consumed..];
    }

    return total_handled, total_consumed, true, conn_wants_close;
}

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests (RFC 9112 Section 9.3).
// Concatenates all serialized responses into wire_out and returns (total_requests_processed, ok).
fn handle_connection_wire_pipelined<B>(
    server: HttpServer&,
    client_ip: const u8[:],
    wire_in: const u8[:],
    now_ns: u64,
    wire_out: B&,
) -> i64, bool {
    let count, _, ok, _ = handle_connection_wire_pipelined_stream(server, client_ip, wire_in, now_ns, wire_out);
    return count, ok;
}

inline fn handle_h2_pipe_ingress<B>(
    server: HttpServer&,
    client_ip: const u8[:],
    pipe: core::PipeBuffer&,
    h2_sess: internal::H2ServerSession&,
    now_ms: u64,
    unread_len: i64,
    wire_out: B&,
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
    server: HttpServer&,
    client_ip: const u8[:],
    pipe: core::PipeBuffer&,
    now_ns: u64,
    wire_out: B&,
    h2_sess: internal::H2ServerSession&,
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
        let stream = core::readable_slice(pipe);
        reset_request(req);
        let ok_parse, consumed = parse_http1_wire_request(stream, req);

        if !ok_parse || consumed <= 0 {
            // Incomplete frame / chunk: examine all currently readable bytes without consuming
            let hdr_end = core::fast_find_crlfcrlf(stream);
            core::advance_to(pipe, 0, pipe.readable_len());
            guard hdr_end >= 0 else { break; }

            // Headers are complete but parsing failed -> fatal syntax / smuggling error!
            if total_handled == 0 {
                serialize_bad_request_error(server.server_name[..], wire_out);
            }
            return total_handled, false;
        }

        reset_response(res);
        if server.fast_path {
            dispatch_fast_path_route(server.pipeline.router, req, res);
        } else {
            var future = internal::new_inline_handler_future(0);
            let outcome = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
        }

        let wants_close = check_and_apply_connection_close(req, res);

        serialize_http1_response(res, server.server_name[..], wire_out);
        server.requests_processed++;
        total_handled++;

        core::advance_to(pipe, consumed, consumed);

        // RFC 9112 §9.3.6 & CVE-2026-94439: Stop pipelined HTTP processing upon CONNECT or Connection: close
        if req.method[..] == "CONNECT" || wants_close {
            core::advance_to(pipe, pipe.readable_len(), pipe.readable_len());
            break;
        }
    }

    return total_handled, true;
}

fn handle_connection_pipe<B>(
    server: HttpServer&,
    client_ip: const u8[:],
    pipe: core::PipeBuffer&,
    now_ns: u64,
    wire_out: B&,
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

// Executes a live TCP accept and dispatch loop.
// Uses pipelined ingestion and automatic CorkBuffer batching.
fn serve(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    guard listener_fd > 0 else { return 0; }
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

const REACTOR_LEFTOVER_CAP: i64 = 1024;

struct ReactorConnSlot {
    fd: i64 = -1,
    leftover_len: i64 = 0,
    timeout_tick: u8 = 255,
    leftover: u8[1024] = [0; 1024],
}

// Cleans up a connection slot, removes from epoll, closes fd, and returns slot to free stack.
fn reactor_cleanup_slot(
    epfd: i64,
    slot: ReactorConnSlot&,
    slot_idx: i64,
    free_slots: FreeSlotStack&,
) {
    if slot.fd > 0 {
        epoll_del(epfd, slot.fd);
        tcp_close(slot.fd);
        slot.fd = -1;
        slot.leftover_len = 0;
        slot.timeout_tick = 255;
    }
    push_free_slot(free_slots, slot_idx);
}

// 1-second Tick Wheel Connection Timeout Sweeper (Slowloris defense & slot reclamation).
fn reactor_sweep_timeouts(
    epfd: i64,
    active_slots: ReactorConnSlot[:],
    free_slots: FreeSlotStack&,
    timer_wheel: TickTimerWheel&,
    now_sec: i64,
    last_sweep_sec: i64&,
    total_served: i64&,
) {
    guard now_sec > last_sweep_sec else { return; }
    let elapsed = if last_sweep_sec == 0 { 1 } else { (now_sec - last_sweep_sec) as u32 };
    last_sweep_sec = now_sec;
    tick_timer_advance(timer_wheel, elapsed);

    for s in active_slots.len {
        if active_slots[s].fd > 0 && tick_timer_is_expired(timer_wheel, active_slots[s].timeout_tick) {
            reactor_cleanup_slot(epfd, active_slots[s], s, free_slots);
            total_served++;
        }
    }
}

// Reclaims one expired connection slot during emergency saturation.
fn reactor_evict_stale_slot(
    epfd: i64,
    active_slots: ReactorConnSlot[:],
    free_slots: FreeSlotStack&,
    timer_wheel: TickTimerWheel&,
    total_served: i64&,
) -> i64 {
    for s in active_slots.len {
        if active_slots[s].fd > 0 && tick_timer_is_expired(timer_wheel, active_slots[s].timeout_tick) {
            reactor_cleanup_slot(epfd, active_slots[s], s, free_slots);
            total_served++;
            return pop_free_slot(free_slots);
        }
    }
    return -1;
}

// Drains non-blocking listener queue and accepts ready incoming connections into free slots.
fn reactor_drain_listener(
    listener_fd: i64,
    epfd: i64,
    active_slots: ReactorConnSlot[:],
    free_slots: FreeSlotStack&,
    timer_wheel: TickTimerWheel&,
    total_served: i64&,
) {
    while true {
        let client_fd = tcp_accept_nonblocking(listener_fd);
        if client_fd <= 0 { break; }
        tcp_set_nonblocking(client_fd, true);

        var slot = pop_free_slot(free_slots);
        if slot < 0 {
            slot = reactor_evict_stale_slot(epfd, active_slots, free_slots, timer_wheel, total_served);
        }
        if slot >= 0 {
            active_slots[slot].fd = client_fd;
            active_slots[slot].leftover_len = 0;
            active_slots[slot].timeout_tick = tick_timer_arm(timer_wheel, 15);
            epoll_add(epfd, client_fd, EPOLL_READ, slot as u64);
        } else {
            tcp_close(client_fd);
        }
    }
}

// Drains up to 4 turns of non-blocking TCP ingress into chunk buffer.
// Returns (any_recvd, is_closed).
fn reactor_read_bounded_turns(conn: i64, chunk: u8[..65536]&) -> bool, bool {
    var any_recvd = false;
    for turn in 4 {
        let available = chunk.cap - chunk.len;
        guard available > 0 else { break; }
        let recvd = tcp_recv_nonblocking(conn, chunk);
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
fn reactor_load_leftover(slot: ReactorConnSlot&, chunk: u8[..65536]&) {
    let prev_len = slot.leftover_len;
    guard prev_len > 0 && prev_len <= REACTOR_LEFTOVER_CAP else { return; }
    for p in prev_len {
        chunk.push(slot.leftover[p]);
    }
    slot.leftover_len = 0;
}

// Copies leftover bytes into slot preservation buffer.
fn reactor_save_leftover(slot: ReactorConnSlot&, rem: const u8[:]) -> bool {
    guard rem.len <= REACTOR_LEFTOVER_CAP else { return false; }
    slot.leftover_len = rem.len;
    for m in rem.len {
        slot.leftover[m] = rem[m];
    }
    return true;
}

// Processes non-blocking ingress traffic on a connection slot via bounded capacity-guarded read loop.
fn reactor_handle_ingress(
    server: HttpServer&,
    epfd: i64,
    active_slots: ReactorConnSlot[:],
    slot: i64,
    free_slots: FreeSlotStack&,
    timer_wheel: TickTimerWheel&,
    now_ns: u64,
    chunk: u8[..65536]&,
    cork_wire: u8[..16384]&,
    total_served: i64&,
) {
    let conn = active_slots[slot].fd;
    let prev_len = active_slots[slot].leftover_len;
    active_slots[slot].timeout_tick = tick_timer_arm(timer_wheel, 15);

    chunk.clear();
    reactor_load_leftover(active_slots[slot], chunk);

    let any_recvd, is_closed = reactor_read_bounded_turns(conn, chunk);
    if is_closed {
        reactor_cleanup_slot(epfd, active_slots[slot], slot, free_slots);
        total_served++;
        return;
    }
    if !any_recvd && prev_len == 0 {
        return;
    }

    cork_wire.clear();
    let count, consumed, ok, wants_close = handle_connection_wire_pipelined_stream(
        server, "127.0.0.1", chunk[..], now_ns, cork_wire,
    );

    let should_close = !ok || wants_close;
    if cork_wire.len > 0 {
        let sent = tcp_send(conn, cork_wire[..]);
        if sent <= 0 || should_close {
            reactor_cleanup_slot(epfd, active_slots[slot], slot, free_slots);
            total_served++;
            return;
        }
    }
    if should_close {
        reactor_cleanup_slot(epfd, active_slots[slot], slot, free_slots);
        total_served++;
        return;
    }

    // Preserve unconsumed bytes for the next epoll turn
    if consumed < chunk.len {
        if !reactor_save_leftover(active_slots[slot], chunk[consumed..]) {
            reactor_cleanup_slot(epfd, active_slots[slot], slot, free_slots);
            total_served++;
        }
    }
}

// Executes a share-nothing reactor loop with epoll.
// Multiplexes all accepted connections within 1 thread, maintaining ~3.1 MB RSS footprint.
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    guard listener_fd > 0 else { return 0; }
    tcp_set_nonblocking(listener_fd, true);

    let epfd = epoll_create();
    guard epfd >= 0 else { return 0; }
    defer epoll_close(epfd);
    epoll_add(epfd, listener_fd, EPOLL_READ, EPOLL_LISTENER_TAG);

    var ready_fds: i64[256] = [0; 256];
    var ready_udata: u64[256] = [0; 256];
    var cork_wire: u8[..16384] = [];
    var chunk: u8[..65536] = [];
    var total_served: i64 = 0;

    var active_slots: ReactorConnSlot[256] = [ReactorConnSlot { .. }; 256];
    var free_slots = FreeSlotStack { .. };
    init_free_slots(free_slots, active_slots.len);
    var timer_wheel = new_tick_timer_wheel(15);
    var last_sweep_sec: i64 = 0;

    while max_connections == 0 || total_served < max_connections {
        let n = epoll_wait_direct(epfd, ready_fds[..], ready_udata[..], 1000);

        let now_mono = core::monotonic_now();
        let now_ns = core::as_nanos(now_mono);
        let now_sec = (now_ns / 1000000000) as i64;

        reactor_sweep_timeouts(
            epfd, active_slots[..], free_slots, timer_wheel, now_sec, last_sweep_sec, total_served,
        );

        if n <= 0 { continue; }

        for i in n {
            let udata = ready_udata[i];
            if udata == EPOLL_LISTENER_TAG {
                reactor_drain_listener(listener_fd, epfd, active_slots[..], free_slots, timer_wheel, total_served);
                continue;
            }

            let slot = udata as i64;
            if slot < 0 || slot >= active_slots.len || active_slots[slot].fd <= 0 {
                continue;
            }

            reactor_handle_ingress(
                server, epfd, active_slots[..], slot, free_slots, timer_wheel, now_ns, chunk, cork_wire, total_served,
            );
        }
    }

    for s in active_slots.len {
        if active_slots[s].fd > 0 {
            reactor_cleanup_slot(epfd, active_slots[s], s, free_slots);
        }
    }

    return total_served;
}
