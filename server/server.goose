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
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    };
}

// ---- 2. HTTP/1.1 Wire Request Parser ---------------------------------------

// Parses an incoming raw HTTP/1.1 request wire stream.
// Supports Content-Length and RFC 9112 Chunked Transfer Coding with Trailers.
// Enforces RFC 9112 Section 6.1 Smuggling Defense (TE/CL conflict detection).
// Returns (ok, total_bytes_consumed).
fn parse_http1_wire_request<Req>(wire: const u8[:], out_req: Req&) -> bool, i64 {
    guard wire.len >= 4 else { return false, 0; }

    // RFC 9112 Section 3.1: No whitespace is allowed before the method name
    guard wire[0] != ' ' && wire[0] != '\t' else { return false, 0; }

    // RFC 9112 Section 2.2: A server that is expecting to receive a request-line
    // SHOULD ignore at least one empty line (CRLF) received prior to any request-line.
    // A server MUST NOT ignore more than one empty line.
    var req_offset: i64 = 0;
    if wire.len >= 2 && wire[0] == '\r' && wire[1] == '\n' {
        req_offset = 2;
        guard req_offset < wire.len else { return false, 0; }
        guard wire[req_offset] != '\r' && wire[req_offset] != '\n' &&
              wire[req_offset] != ' ' && wire[req_offset] != '\t' else { return false, 0; }
    }

    let active_wire = wire[req_offset..];

    // Find end of headers (\r\n\r\n) via AVX2 / 32-bit fast scanner
    let hdr_end = core::fast_find_crlfcrlf(active_wire);
    // RFC 9112 Section 2.1 & uWS #1658: Total header block must not exceed 8192 bytes
    if hdr_end > 8192 || (hdr_end < 0 && active_wire.len > 8192) {
        return false, 0;
    }
    guard hdr_end >= 0 else { return false, 0; }
    let header_end_idx = hdr_end + 4;
    guard header_end_idx <= 8192 else { return false, 0; }
    let header_bytes = active_wire[..header_end_idx];

    // Find end of request line
    let line_end = core::index_of_slice(header_bytes, "\r\n");
    guard line_end > 0 else { return false, 0; }
    let req_line = header_bytes[..line_end];

    // Parse method (first space)
    let sp1 = core::index_of_byte(req_line, ' ');
    guard sp1 > 0 else { return false, 0; }
    let method_slice = req_line[..sp1];
    guard is_valid_header_name(method_slice) && method_slice.len <= out_req.method.cap else { return false, 0; }
    out_req.method.clear();
    out_req.method.append(method_slice);

    // Parse path (second space)
    let rest = req_line[(sp1 + 1)..];
    let sp2_rel = core::index_of_byte(rest, ' ');
    guard sp2_rel > 0 else { return false, 0; }
    let path_slice = rest[..sp2_rel];
    guard path_slice.len > 0 && path_slice.len <= out_req.url.cap else { return false, 0; }

    // RFC 9110 Section 4.1 & RFC 9112 Section 3.2 (uWS #1951):
    // Request target must only consist of visible ASCII characters (0x21..0x7E).
    // Reject CTLs (0x00..0x1F, 0x7F) and non-ASCII raw UTF-8 / binary bytes (>= 0x80).
    for b in path_slice {
        guard b >= 0x21 && b <= 0x7E else { return false, 0; }
    }

    // RFC 9112 Section 3.2.3 & Section 9.3.6:
    // Authority-form ("host:port") is ONLY valid for CONNECT requests.
    // Asterisk-form ("*") is ONLY valid for OPTIONS requests.
    // Origin-form requests for other methods must start with '/'.
    if method_slice == "CONNECT" {
        guard path_slice != "*" && path_slice[0] != '/' else { return false, 0; }
        let col = core::index_of_byte(path_slice, ':');
        guard col > 0 && col + 1 < path_slice.len else { return false, 0; }
        let port_num, port_ok = core::parse_port_number(path_slice[(col + 1)..]);
        guard port_ok && port_num > 0 else { return false, 0; }
    } else if path_slice == "*" {
        guard method_slice == "OPTIONS" else { return false, 0; }
    } else {
        guard path_slice[0] == '/' else { return false, 0; }
    }

    out_req.url.clear();
    out_req.url.append(path_slice);

    // Parse protocol version
    let proto_slice = rest[(sp2_rel + 1)..];
    guard proto_slice == "HTTP/1.1" || proto_slice == "HTTP/1.0" else { return false, 0; }

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    var cursor: i64 = 0;

    out_req.headers.clear();
    clear(out_req.bloom_filter);
    var presence_tracker = new_header_presence_tracker();

    while cursor < rest_headers.len {
        let rel_end = core::index_of_slice(rest_headers[cursor..], "\r\n");
        if rel_end < 0 { break; }
        if rel_end == 0 { break; } // Empty line reached

        let line = rest_headers[cursor..(cursor + rel_end)];
        let colon = core::index_of_byte(line, ':');
        // RFC 9112 Section 5.1 & Go #34540 / CVE-2019-16276:
        // Reject header field names with leading whitespace, spaces before colon, or non-tchar bytes.
        guard colon > 0 else { return false, 0; }
        let hname = line[..colon];
        guard is_valid_header_name(hname) else { return false, 0; }

        let hval = trim_lws(line[(colon + 1)..]);
        guard is_valid_header_value(hval) else { return false, 0; }

        // O(1) Header Presence & Duplicate/Smuggling Verification (uWebSockets bitmask pattern)
        let cur_hdr_idx = out_req.headers.len as i16;
        guard track_header_presence(presence_tracker, hname, hval, cur_hdr_idx) else { return false, 0; }

        var item = HeaderItem { .. };
        guard hname.len <= item.name.cap && hval.len <= item.value.cap else { return false, 0; }
        item.name.append(hname);
        item.value.append(hval);
        guard out_req.headers.len < out_req.headers.cap else { return false, 0; }
        out_req.headers.push(item);
        add_header(out_req.bloom_filter, hname);
        cursor += rel_end + 2;
    }

    out_req.trailers.clear();
    out_req.body.clear();

    // RFC 9112 Section 3.2 & uWS #1949: Host header validation
    if proto_slice == "HTTP/1.1" {
        // Must have exactly one Host header in HTTP/1.1 (verified via bitmask presence)
        guard (presence_tracker.mask & HDR_PRESENCE_HOST) != 0 else { return false, 0; }
    }
    if (presence_tracker.mask & HDR_PRESENCE_HOST) != 0 {
        let host_idx = presence_tracker.host_idx as i64;
        guard host_idx >= 0 && host_idx < out_req.headers.len else { return false, 0; }

        let host_val = out_req.headers[host_idx].value[..];
        guard host_val.len > 0 else { return false, 0; }
        // RFC 9112 Section 3.2, 7.2 & 9.5: Authority in Host MUST NOT contain path ('/'),
        // query ('?'), fragment ('#'), userinfo ('@'), multiple values (','), or whitespace
        for b in host_val {
            guard b != '/' && b != '?' && b != '#' && b != '@' && b != ',' && b != ' ' && b != '\t' else { return false, 0; }
        }

        // Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Structural IP-literal Host validation
        if host_val[0] == '[' {
            let close_idx = core::index_of_byte(host_val, ']');
            guard close_idx > 1 else { return false, 0; }
            var comp_buf: u8[..64] = [];
            guard core::parse_and_compress_ipv6(host_val[1..close_idx], comp_buf) else { return false, 0; }
            if close_idx + 1 < host_val.len {
                guard host_val[close_idx + 1] == ':' else { return false, 0; }
                let port_part = host_val[close_idx + 2..];
                guard port_part.len > 0 && port_part.len <= 5 else { return false, 0; }
                for pb in port_part { guard pb >= '0' && pb <= '9' else { return false, 0; } }
                let p_num, p_ok = core::parse_u64_dec(port_part);
                guard p_ok && p_num <= 65535 else { return false, 0; }
            }
        } else {
            for b in host_val {
                guard b != '[' && b != ']' else { return false, 0; }
            }
        }
    }

    // Check for Transfer-Encoding and Content-Length using bitmask presence
    let has_te = (presence_tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;

    // RFC 9112 Section 6.1 Smuggling Protection:
    // If both Transfer-Encoding and Content-Length are present, reject as smuggling attempt.
    if has_te && has_cl {
        return false, 0;
    }

    var cl_len: i64 = 0;
    if has_cl {
        cl_len = presence_tracker.parsed_cl;
    }

    var te_buf: u8[..64] = [];
    if has_te {
        for &hdr in out_req.headers {
            if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
                if te_buf.len > 0 {
                    guard te_buf.len + 2 + hdr.value.len <= te_buf.cap else { return false, 0; }
                    te_buf.append(", ");
                    te_buf.append(hdr.value[..]);
                } else {
                    guard hdr.value.len <= te_buf.cap else { return false, 0; }
                    te_buf.append(hdr.value[..]);
                }
            }
        }
    }

    let body_start_idx = req_offset + header_end_idx;

    if has_te {
        // Must validate transfer encoding value per RFC 9112 Section 6.3 & 7.1
        guard validate_transfer_encoding_value(te_buf[..]) else { return false, 0; }

        let dec_err, chunked_consumed = decode_chunked_body_with_trailers(
            wire[body_start_idx..],
            out_req.body,
            out_req.trailers,
        );
        guard dec_err == ChunkedDecodeError.None else { return false, 0; }

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

// Parses an incoming raw HTTP/1.1 response wire stream into a Response model.
// Supports Content-Length and RFC 9112 Chunked Transfer Coding with Trailers.
// Returns (ok, total_bytes_consumed).
fn parse_http1_wire_response<Res>(wire: const u8[:], out_res: Res&) -> bool, i64 {
    guard wire.len >= 4 else { return false, 0; }

    let hdr_end = core::fast_find_crlfcrlf(wire);
    guard hdr_end >= 0 else { return false, 0; }
    let header_end_idx = hdr_end + 4;
    let header_bytes = wire[..header_end_idx];

    // Find end of status line
    let line_end = core::index_of_slice(header_bytes, "\r\n");
    guard line_end > 0 else { return false, 0; }

    let status_line = header_bytes[..line_end];
    // RFC 9112 §3.1.2 & uWS #1949: Exactly SP between HTTP-version and 3-digit status code
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

    // RFC 9112 Section 6.1 & RFC 7230 §3.3.3: In responses, Transfer-Encoding overrides Content-Length.
    // If Transfer-Encoding is present, it MUST be valid and chunked MUST be final; invalid TE must reject.
    if has_te {
        guard validate_transfer_encoding_value(te_buf[..]) else { return false, 0; }
        // RFC 9112 Section 6.1: An intermediary or recipient processing chunked MUST remove Content-Length
        if has_cl {
            remove_header_by_name(out_res.headers, "content-length");
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
    if out_res.status_code == 204 || out_res.status_code == 304 || (out_res.status_code >= 100 && out_res.status_code < 200) {
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

    if res.status_code != 204 && res.status_code != 304 {
        // uWS #1855 / RFC 9110 §8.6: Do not emit automatic Content-Length if already specified in res.headers (e.g. HEAD)
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
    let is_empty_status = res.status_code == 204 || res.status_code == 304 || (res.status_code >= 100 && res.status_code < 200);

    for &hdr in res.headers {
        // RFC 9110 §8.6 & uWS #1370: Suppress Content-Length from 204 No Content, 304 Not Modified, and 1xx Informational
        if is_empty_status && eq_ascii_fold(hdr.name[..], "content-length") {
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
    let te = header(res, "transfer-encoding");
    if eq_ascii_fold(te, "chunked") || res.trailers.len > 0 {
        serialize_http1_chunked_response(res, server_name, 4096, out_wire);
        return;
    }

    serialize_http1_headers(res, server_name, out_wire);

    // RFC 9110 §8.6 & Go #81642 / uWS #1370: Status 204, 304, and 1xx MUST NOT emit a message body on wire
    let is_empty_status = res.status_code == 204 || res.status_code == 304 || (res.status_code >= 100 && res.status_code < 200);
    if res.body.len > 0 && !is_empty_status {
        out_wire.append(res.body[..]);
    }
}

// Sends an HTTP/1.1 response over a TCP socket using zero-copy Vectored I/O (tcp_send2 / WSASend / writev).
// Headers are serialized into wire_headers, and res.body is transmitted directly without being copied into wire_headers.
fn send_http1_response<Res, B>(fd: i64, res: const Res&, server_name: const u8[:], wire_headers: B&) -> i32 {
    wire_headers.clear();
    let te = header(res, "transfer-encoding");
    if eq_ascii_fold(te, "chunked") || res.trailers.len > 0 {
        serialize_http1_chunked_response(res, server_name, 4096, wire_headers);
        return tcp_send(fd, wire_headers[..]);
    }

    serialize_http1_headers(res, server_name, wire_headers);
    let is_empty_status = res.status_code == 204 || res.status_code == 304 || (res.status_code >= 100 && res.status_code < 200);
    if res.body.len == 0 || is_empty_status {
        return tcp_send(fd, wire_headers[..]);
    }
    return tcp_send2(fd, wire_headers[..], res.body[..]);
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

// ---- 4. HttpServer Container and Session Coordinator -----------------------

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
    fast_path: bool = false,
    topic_tree: TopicTree = TopicTree { .. },
    ws_routes: WsRouteEntry[..16] = [WsRouteEntry { .. }; 16],
    ws_route_count: i32 = 0,
    shared_compressor: SharedWsCompressor = SharedWsCompressor { .. },
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

fn subscribe_ex(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:], out_old: i32&, out_new: i32&) -> bool {
    return subscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn unsubscribe_ex(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:], out_old: i32&, out_new: i32&) -> bool {
    return unsubscribe_ex(server.topic_tree, sock_fd, topic_pattern, out_old, out_new);
}

fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
    return subscribe_with_hook<HookFn>(server.topic_tree, sock_fd, topic_pattern);
}

fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(server: HttpServer&, sock_fd: i64, topic_pattern: const u8[:]) -> bool {
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

    let subproto = if pending.subprotocol.len > 0 {
        pending.subprotocol[..]
    } else {
        route_behavior.subprotocol[..]
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
    session.send_pings_automatically = route_behavior.send_pings_automatically;
    session.reset_idle_timeout_on_send = route_behavior.reset_idle_timeout_on_send;

    if subproto.len > 0 && subproto.len <= session.subprotocol.cap {
        session.subprotocol.append(subproto);
    }
    session.user_tag = pending.user_tag;
    if pending.user_data.len > 0 && pending.user_data.len <= session.user_data.cap {
        session.user_data.append(pending.user_data[..]);
    }

    pending.in_use = false;
    return session, true;
}

fn is_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len >= 24 && raw_stream[..24] == H2_CLIENT_PREFACE[..];
}

// True while a short read is still a strict prefix of the 24-byte H2 preface.
// The preface contains "\r\n\r\n" at offset 14, so a sliced first TCP segment
// must not fall through to the HTTP/1.1 parser (found by Toxiproxy SlicerToxic).
fn is_partial_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len > 0 && raw_stream.len < 24 && raw_stream == H2_CLIENT_PREFACE[..raw_stream.len];
}

const MAX_SERVER_BODY_LIMIT: i64 = 10 * 1024 * 1024; // 10 MB payload limit

fn serialize_payload_too_large_error<B>(server_name: const u8[:], wire_out: B&) {
    var err_resp = new_response();
    err_resp.status_code = 413; // Payload Too Large
    set_header(err_resp, "Connection", "close");
    serialize_http1_response(err_resp, server_name, wire_out);
}

fn serialize_bad_request_error<B>(server_name: const u8[:], wire_out: B&) {
    var err_resp = new_response();
    err_resp.status_code = 400; // Bad Request
    serialize_http1_response(err_resp, server_name, wire_out);
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
            if ws_idx >= 0 {
                let entry = &server.ws_routes[ws_idx as i64];
                let subproto = entry.behavior.subprotocol[..];
                var ws_res = new_response();
                var sess, ok_upg = ws_upgrade_request(req, ws_res, subproto);
                if ok_upg {
                    sess.max_backpressure = entry.behavior.max_backpressure;
                    sess.close_on_backpressure_limit = entry.behavior.close_on_backpressure_limit;
                    sess.idle_timeout_s = entry.behavior.idle_timeout_s;
                    sess.send_pings_automatically = entry.behavior.send_pings_automatically;
                    sess.reset_idle_timeout_on_send = entry.behavior.reset_idle_timeout_on_send;
                    if entry.behavior.compression == WS_COMPRESS_SHARED_COMPRESSOR {
                        let client_ext = req.header("sec-websocket-extensions");
                        if core::contains_fold(client_ext, "permessage-deflate") {
                            ws_res.set_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover");
                            enable_permessage_deflate(sess, WS_COMPRESS_SHARED_COMPRESSOR);
                        }
                    }
                    serialize_http1_response(ws_res, server.server_name[..], wire_out);
                    server.requests_processed++;
                    return PipelineOutcome.Handled, true;
                }
            }
        }

        var res = new_response();
        var params = ZeroAllocParams { .. };
        let match_res = match_route(server.pipeline.router, req.method[..], req.url[..], params);
        match match_res {
            Found f => {
                res.status_code = 200;
            },
            MethodNotAllowed mna => {
                res.status_code = 405;
                res.headers.push(make_header("Allow", mna.allow_header[..]));
            },
            NotFound => {
                res.status_code = 404;
            },
        };

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
        var sess = new_h2_server_session(server.server_name[..], now_ms);
        let _, ok_h2 = handle_h2_server_ingress(sess, server.pipeline, server.timer, effective_ip[..], raw_stream, now_ms, wire_out);
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
        if ws_idx >= 0 {
            let entry = &server.ws_routes[ws_idx as i64];
            let subproto = entry.behavior.subprotocol[..];
            var ws_res = new_response();
            var sess, ok_upg = ws_upgrade_request(req, ws_res, subproto);
            if ok_upg {
                sess.max_backpressure = entry.behavior.max_backpressure;
                sess.close_on_backpressure_limit = entry.behavior.close_on_backpressure_limit;
                sess.idle_timeout_s = entry.behavior.idle_timeout_s;
                sess.send_pings_automatically = entry.behavior.send_pings_automatically;
                sess.reset_idle_timeout_on_send = entry.behavior.reset_idle_timeout_on_send;
                if entry.behavior.compression == WS_COMPRESS_SHARED_COMPRESSOR {
                    let client_ext = req.header("sec-websocket-extensions");
                    if core::contains_fold(client_ext, "permessage-deflate") {
                        ws_res.set_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover");
                        enable_permessage_deflate(sess, WS_COMPRESS_SHARED_COMPRESSOR);
                    }
                }
                serialize_http1_response(ws_res, server.server_name[..], wire_out);
                server.requests_processed++;
                return PipelineOutcome.Handled, true;
            }
        }
    }

    var res = new_response();
    var future = internal::new_inline_handler_future(0);
    let outcome = execute_pipeline(server.pipeline, server.timer, effective_ip[..], req, now_ns, res, future);

    // RFC 9110 & CVE-2026-94439: HTTP/1 server connection desynchronization defense.
    // If request method is CONNECT, force Connection: close so the server never treats
    // an established tunnel or subsequent bytes as pipelined HTTP requests.
    if req.method[..] == "CONNECT" {
        set_header(res, "Connection", "close");
    }

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

// Processes an incoming connection stream that may contain multiple pipelined HTTP requests.
// Returns (total_requests_processed, total_bytes_consumed, ok).
fn handle_connection_wire_pipelined_stream<B>(
    server: HttpServer&,
    client_ip: const u8[:],
    wire_in: const u8[:],
    now_ns: u64,
    wire_out: B&,
) -> i64, i64, bool {
    wire_out.clear();
    var stream = wire_in;
    var total_handled: i64 = 0;
    var total_consumed: i64 = 0;

    while stream.len > 0 {
        // Strip optional benign CRLFs between pipelined requests (RFC 9112 §2.2)
        while stream.len > 0 && (stream[0] == '\r' || stream[0] == '\n') {
            stream = stream[1..];
            total_consumed++;
        }
        if stream.len == 0 { break; }

        var req = new_request("GET", "");
        let ok_parse, consumed = parse_http1_wire_request(stream, req);
        guard ok_parse && consumed > 0 else {
            let hdr_end = core::fast_find_crlfcrlf(stream);
            let is_valid_prefix = is_possible_http_method_prefix(stream);

            if hdr_end >= 0 && stream.len <= 8192 && is_valid_prefix {
                // Headers are complete; check if Content-Length body is still incomplete
                let cl_str = req.header("content-length");
                if cl_str.len > 0 {
                    let cl_val, cl_ok = core::parse_i64_dec(trim(cl_str));
                    if cl_ok && cl_val >= 0 {
                        if cl_val > MAX_SERVER_BODY_LIMIT {
                            // RFC 9110 Section 15.5.14: Payload Too Large
                            serialize_payload_too_large_error(server.server_name[..], wire_out);
                            return total_handled, total_consumed, false;
                        }
                        if stream.len < (hdr_end + 4 + cl_val) {
                            // Body incomplete: keep stream in leftover and await remaining packets
                            return total_handled, total_consumed, true;
                        }
                    }
                }
                let te_str = req.header("transfer-encoding");
                if core::contains_fold(te_str, "chunked") {
                    // Chunked body not finished (awaiting final 0\r\n\r\n)
                    return total_handled, total_consumed, true;
                }
            }

            if hdr_end >= 0 || stream.len > 8192 || !is_valid_prefix {
                // Complete headers but invalid syntax, or header overflow > 8192,
                // or trailing unparseable poison bytes: 400 Bad Request
                serialize_bad_request_error(server.server_name[..], wire_out);
                return total_handled, total_consumed, false;
            }
            // Legitimate incomplete request across packet boundary: return so caller preserves stream in leftover
            return total_handled, total_consumed, true;
        }

        // WebSocket Upgrade Interception on Pipelined Stream
        if is_websocket_upgrade_request(req) {
            let ws_idx = find_ws_route(server, req.url[..]);
            if ws_idx >= 0 {
                let entry = &server.ws_routes[ws_idx as i64];
                let subproto = entry.behavior.subprotocol[..];
                var ws_res = new_response();
                var sess, ok_upg = ws_upgrade_request(req, ws_res, subproto);
                if ok_upg {
                    sess.max_backpressure = entry.behavior.max_backpressure;
                    sess.close_on_backpressure_limit = entry.behavior.close_on_backpressure_limit;
                    sess.idle_timeout_s = entry.behavior.idle_timeout_s;
                    sess.send_pings_automatically = entry.behavior.send_pings_automatically;
                    sess.reset_idle_timeout_on_send = entry.behavior.reset_idle_timeout_on_send;
                    if entry.behavior.compression == WS_COMPRESS_SHARED_COMPRESSOR {
                        let client_ext = req.header("sec-websocket-extensions");
                        if core::contains_fold(client_ext, "permessage-deflate") {
                            ws_res.set_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover");
                            enable_permessage_deflate(sess, WS_COMPRESS_SHARED_COMPRESSOR);
                        }
                    }
                    serialize_http1_response(ws_res, server.server_name[..], wire_out);
                    server.requests_processed++;
                    total_handled++;
                    total_consumed += consumed;
                    return total_handled, total_consumed, true;
                }
            }
        }

        var res = new_response();
        if server.fast_path {
            var params = ZeroAllocParams { .. };
            let match_res = match_route(server.pipeline.router, req.method[..], req.url[..], params);
            match match_res {
                Found f => { res.status_code = 200; },
                MethodNotAllowed mna => {
                    res.status_code = 405;
                    res.headers.push(make_header("Allow", mna.allow_header[..]));
                },
                NotFound => { res.status_code = 404; },
            };
        } else {
            var future = internal::new_inline_handler_future(0);
            let outcome = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
        }

        if req.method[..] == "CONNECT" {
            set_header(res, "Connection", "close");
        }

        serialize_http1_response(res, server.server_name[..], wire_out);
        server.requests_processed++;
        total_handled++;
        total_consumed += consumed;

        // RFC 9112 §9.3.6 & CVE-2026-94439: Stop pipelined HTTP processing upon CONNECT
        if req.method[..] == "CONNECT" {
            total_consumed = wire_in.len;
            break;
        }

        stream = stream[consumed..];
    }

    return total_handled, total_consumed, true;
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
    let count, _, ok = handle_connection_wire_pipelined_stream(server, client_ip, wire_in, now_ns, wire_out);
    return count, ok;
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
) -> i64, bool {
    let unread_len = pipe.readable_len();
    guard unread_len > 0 else { return 0, true; }

    var total_handled: i64 = 0;

    // Sliced H2 preface: wait for the remaining bytes instead of parsing as HTTP/1.1
    if pipe.consumed == 0 && is_partial_h2_client_preface(core::readable_slice(pipe)) {
        return 0, true;
    }

    // Check for HTTP/2 connection preface if at the very start of the stream
    if pipe.consumed == 0 && unread_len >= 24 {
        let stream = core::readable_slice(pipe);
        if is_h2_client_preface(stream) {
            let now_ms = (now_ns / 1000000) as u64;
            var sess = new_h2_server_session(server.server_name[..], now_ms);
            let consumed_h2, ok_h2 = handle_h2_server_ingress(sess, server.pipeline, server.timer, client_ip, stream, now_ms, wire_out);
            if ok_h2 {
                core::advance_to(pipe, consumed_h2, consumed_h2);
                server.requests_processed++;
                return 1, true;
            }
            core::advance_to(pipe, consumed_h2, unread_len);
            return 0, false;
        }
    }

    while pipe.readable_len() > 0 {
        let stream = core::readable_slice(pipe);
        var req = new_request("GET", "");
        let ok_parse, consumed = parse_http1_wire_request(stream, req);

        if ok_parse && consumed > 0 {
            var res = new_response();
            if server.fast_path {
                var params = ZeroAllocParams { .. };
                let match_res = match_route(server.pipeline.router, req.method[..], req.url[..], params);
                match match_res {
                    Found f => { res.status_code = 200; },
                    MethodNotAllowed mna => {
                        res.status_code = 405;
                        res.headers.push(make_header("Allow", mna.allow_header[..]));
                    },
                    NotFound => { res.status_code = 404; },
                };
            } else {
                var future = internal::new_inline_handler_future(0);
                let outcome = execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
            }

            if req.method[..] == "CONNECT" {
                set_header(res, "Connection", "close");
            }

            serialize_http1_response(res, server.server_name[..], wire_out);
            server.requests_processed++;
            total_handled++;

            core::advance_to(pipe, consumed, consumed);

            // RFC 9112 §9.3.6 & CVE-2026-94439: Stop pipelined HTTP processing upon CONNECT
            if req.method[..] == "CONNECT" {
                core::advance_to(pipe, pipe.readable_len(), pipe.readable_len());
                break;
            }
        } else {
            // Check if headers are complete via fast scanner
            let hdr_end = core::fast_find_crlfcrlf(stream);
            if hdr_end >= 0 {
                // Headers are complete but parsing failed -> fatal syntax / smuggling error!
                if total_handled == 0 {
                    serialize_bad_request_error(server.server_name[..], wire_out);
                }
                core::advance_to(pipe, 0, pipe.readable_len());
                return total_handled, false;
            } else {
                // Incomplete frame / chunk: examine all currently readable bytes without consuming
                core::advance_to(pipe, 0, pipe.readable_len());
                break;
            }
        }
    }

    return total_handled, true;
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

        while true {
            let recvd = tcp_recv_pipe(conn, pipe, 4096, 5000);
            if recvd <= 0 {
                break;
            }

            let now_ns = core::as_nanos(core::monotonic_now());
            let count, ok = handle_connection_pipe(server, "127.0.0.1", pipe, now_ns, cork);
            if !ok {
                if cork.cork_pending() > 0 {
                    tcp_flush_cork(conn, cork);
                }
                break;
            }

            if cork.cork_pending() > 0 {
                let sent = tcp_flush_cork(conn, cork);
                if sent <= 0 {
                    break;
                }
            }
        }
        total_served++;
    }

    return total_served;
}

struct ReactorConnSlot {
    fd: i64 = -1,
    leftover_len: i64 = 0,
    timeout_tick: u8 = 255,
    leftover: u8[4096] = [0; 4096],
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

    var ready_fds: i64[..128] = [];
    var ready_udata: u64[..128] = [];
    var cork_wire: u8[..16384] = [];
    var chunk: u8[..65536] = [];
    var total_served: i64 = 0;

    var active_slots: ReactorConnSlot[128] = [ReactorConnSlot { .. }; 128];
    var next_free_slot: i64 = 0;
    var timer_wheel = new_tick_timer_wheel(15);
    var last_sweep_sec: i64 = 0;

    while max_connections == 0 || total_served < max_connections {
        let n = epoll_wait(epfd, ready_fds, ready_udata, 1000);

        // 1-second Tick Wheel Connection Timeout Sweeper (Slowloris defense & slot reclamation)
        let now_sec = (core::as_nanos(core::monotonic_now()) / 1000000000) as i64;
        if now_sec > last_sweep_sec {
            let elapsed = if last_sweep_sec == 0 { 1 } else { (now_sec - last_sweep_sec) as u32 };
            last_sweep_sec = now_sec;
            tick_timer_advance(timer_wheel, elapsed);

            for s in active_slots.len {
                if active_slots[s].fd > 0 && tick_timer_is_expired(timer_wheel, active_slots[s].timeout_tick) {
                    epoll_del(epfd, active_slots[s].fd);
                    tcp_close(active_slots[s].fd);
                    active_slots[s].fd = -1;
                    active_slots[s].leftover_len = 0;
                    active_slots[s].timeout_tick = 255;
                    total_served++;
                    if s < next_free_slot { next_free_slot = s; }
                }
            }
        }

        if n <= 0 { continue; }

        for i in n {
            let udata = ready_udata[i];
            if udata == EPOLL_LISTENER_TAG {
                while true {
                    let client_fd = tcp_accept_nonblocking(listener_fd);
                    if client_fd <= 0 { break; }
                    tcp_set_nonblocking(client_fd, true);

                    var slot: i64 = -1;
                    for k in active_slots.len {
                        let s = (next_free_slot + k) % active_slots.len;
                        if active_slots[s].fd == -1 {
                            slot = s;
                            next_free_slot = (s + 1) % active_slots.len;
                            break;
                        }
                    }
                    if slot < 0 {
                        // Emergency sweep if slots are full: evict any expired or stale connection
                        for s in active_slots.len {
                            if active_slots[s].fd > 0 && tick_timer_is_expired(timer_wheel, active_slots[s].timeout_tick) {
                                epoll_del(epfd, active_slots[s].fd);
                                tcp_close(active_slots[s].fd);
                                active_slots[s].fd = -1;
                                active_slots[s].leftover_len = 0;
                                active_slots[s].timeout_tick = 255;
                                total_served++;
                                slot = s;
                                break;
                            }
                        }
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
                continue;
            }

            let slot = udata as i64;
            if slot < 0 || slot >= active_slots.len || active_slots[slot].fd <= 0 {
                continue;
            }
            let conn = active_slots[slot].fd;
            let prev_len = active_slots[slot].leftover_len;
            active_slots[slot].timeout_tick = tick_timer_arm(timer_wheel, 15);

            chunk.clear();
            if prev_len > 0 && prev_len <= 4096 {
                for p in prev_len {
                    chunk.push(active_slots[slot].leftover[p]);
                }
                active_slots[slot].leftover_len = 0;
            }

            let recvd = tcp_recv_nonblocking(conn, chunk);
            if recvd == 0 || recvd == -1 {
                epoll_del(epfd, conn);
                tcp_close(conn);
                active_slots[slot].fd = -1;
                active_slots[slot].leftover_len = 0;
                active_slots[slot].timeout_tick = 255;
                next_free_slot = slot;
                total_served++;
                continue;
            }
            if recvd < 0 {
                if prev_len > 0 {
                    active_slots[slot].leftover_len = prev_len;
                }
                continue;
            }

            cork_wire.clear();
            let now_ns = core::as_nanos(core::monotonic_now());
            let count, consumed, ok = handle_connection_wire_pipelined_stream(server, "127.0.0.1", chunk[..], now_ns, cork_wire);

            if cork_wire.len > 0 {
                let sent = tcp_send(conn, cork_wire[..]);
                if sent <= 0 || !ok {
                    epoll_del(epfd, conn);
                    tcp_close(conn);
                    active_slots[slot].fd = -1;
                    active_slots[slot].leftover_len = 0;
                    active_slots[slot].timeout_tick = 255;
                    next_free_slot = slot;
                    total_served++;
                    continue;
                }
            }
            if !ok {
                epoll_del(epfd, conn);
                tcp_close(conn);
                active_slots[slot].fd = -1;
                active_slots[slot].leftover_len = 0;
                active_slots[slot].timeout_tick = 255;
                next_free_slot = slot;
                total_served++;
                continue;
            }

            // Preserve unconsumed bytes for the next epoll turn
            if consumed < chunk.len {
                let rem = chunk[consumed..];
                if rem.len <= 4096 {
                    active_slots[slot].leftover_len = rem.len;
                    for m in rem.len {
                        active_slots[slot].leftover[m] = rem[m];
                    }
                } else {
                    epoll_del(epfd, conn);
                    tcp_close(conn);
                    active_slots[slot].fd = -1;
                    active_slots[slot].leftover_len = 0;
                    active_slots[slot].timeout_tick = 255;
                    next_free_slot = slot;
                    total_served++;
                }
            }
        }
    }

    return total_served;
}
