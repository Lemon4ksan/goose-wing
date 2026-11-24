// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/1.1 wire request parser, status/header serializer, chunked framer, and date cache (RFC 9110, RFC 9112).
namespace server;

import std;
import core;
import rfc.http;
import rfc.h2;
import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import http.headers.perfect_hash;
import net.tcp;
import http.request;
import http.response;
import .prof_hooks;
import .h1_codec_internal;
import .h1_serialize_internal;
import .internal;

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
        if port_slice.len == 0 {
            return true;
        }
        guard port_slice.len <= 5 else { return false; }
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
    if port_part.len == 0 {
        return true;
    }
    guard port_part.len <= 5 else { return false; }
    for pb in port_part {
        guard pb >= '0' && pb <= '9' else { return false; }
    }
    let p_num, p_ok = port_part.parse_u64_dec();
    return p_ok && p_num >= 1 && p_num <= 65535;
}

// Controls whether parse_http1_request_line accepts forward-proxy absolute-form URIs (RFC 9112 §3.2.2).
enum RequestTargetMode {
    OriginOnly,
    AllowAbsoluteForm,
}

enum RequestTargetVerb {
    Regular,
    Connect,
    Options,
}

// Parses the HTTP/1.x request line (Method SP Request-URI SP HTTP-Version).
//
// Example:
//   req_line = "GET /index.html HTTP/1.1"
//   returns: true, out_req.method = "GET", out_req.url = "/index.html"
fn parse_http1_request_line<Req>(
    req_line:    const u8[:],
    out_req:     Req&,
    target_mode: RequestTargetMode = RequestTargetMode.OriginOnly,
) -> bool {
    let _prof = server_prof::lit_prof_enter("http1.req_line");
    defer server_prof::lit_prof_leave(_prof);
    guard req_line.len >= 14 else { return false; }

    let w0 = core::read_le_u64(req_line, 0);
    let m_len, _ = server_internal::match_swar_method(w0);
    var sp1:  i64               = m_len;
    var verb: RequestTargetVerb = RequestTargetVerb.Regular;

    if m_len > 0 {
        if w0 == rfc::METHOD_CONNECT_U64 {
            verb = RequestTargetVerb.Connect;
        } else if w0 == rfc::METHOD_OPTIONS_U64 {
            verb = RequestTargetVerb.Options;
        }
    } else {
        sp1 = server_internal::swar_find_space(req_line, 0);
        guard sp1 > 0 && sp1 <= out_req.method.cap else { return false; }
        let custom_method = req_line[..sp1];
        guard http::is_valid_header_name(custom_method) else { return false; }
        if custom_method == "CONNECT" {
            verb = RequestTargetVerb.Connect;
        } else if custom_method == "OPTIONS" {
            verb = RequestTargetVerb.Options;
        }
    }

    let sp2 = server_internal::swar_find_space(req_line, sp1 + 1);
    guard sp2 > sp1 + 1 else { return false; }
    let path_slice = req_line[(sp1 + 1)..sp2];
    guard path_slice.len <= out_req.url.cap else { return false; }
    guard server_internal::validate_request_target_chars(path_slice) else { return false; }
    guard server_internal::validate_http1_request_target_for_mode(path_slice, verb, target_mode) else { return false; }

    guard req_line.len - (sp2 + 1) == 8 else { return false; }
    let proto_u64 = core::read_le_u64(req_line, sp2 + 1);
    guard proto_u64 == rfc::HTTP_VERSION_1_1_U64 || proto_u64 == rfc::HTTP_VERSION_1_0_U64 else { return false; }
    let _ = out_req.method.try_set(req_line[..sp1]);
    let _ = out_req.url.try_set(path_slice);
    out_req.is_http10 = (proto_u64 == rfc::HTTP_VERSION_1_0_U64);
    return true;
}

var g_h1_parse_cache: server_internal::H1HeaderParseCache = server_internal::H1HeaderParseCache { .. };

// Parses raw HTTP/1.x header lines into HeaderItem entries and tracks presence bitmask.
// Uses single-pass SWAR scanning for header name, delimiter, value, and CTL validation.
//
// Example:
//   rest_headers = "Host: localhost\r\nUser-Agent: test\r\n\r\n"
//   returns: true, out_req.headers.len = 2
fn parse_http1_headers_stream<Req>(
    rest_headers:     const u8[:],
    out_req:          Req&,
    presence_tracker: http::HeaderPresenceTracker&,
    base_offset:      i64 = 0,
) -> bool {
    let _prof = server_prof::lit_prof_enter("http1.headers");
    defer server_prof::lit_prof_leave(_prof);
    if server_internal::try_restore_cached_headers_stream(rest_headers, out_req, presence_tracker) {
        return true;
    }
    server_internal::clear_request_headers_state(out_req);
    var cursor: i64 = 0;
    while cursor < rest_headers.len {
        // Empty line reached (RFC 9112 Section 2.1)
        if rest_headers[cursor] == '\r' && cursor + 1 < rest_headers.len && rest_headers[cursor + 1] == '\n' {
            break;
        }

        let ok_hdr = server_internal::parse_http1_wire_header_line(
            rest_headers,
            cursor,
            presence_tracker,
            out_req,
            base_offset,
        );
        guard ok_hdr else {
            server_internal::clear_request_headers_state(out_req);
            presence_tracker = http::HeaderPresenceTracker { .. };
            return false;
        }
    }
    guard server_internal::verify_headers_terminator_consumed(cursor, rest_headers.len) else {
        server_internal::clear_request_headers_state(out_req);
        presence_tracker = http::HeaderPresenceTracker { .. };
        return false;
    }
    server_internal::save_cached_headers_stream(rest_headers, out_req, presence_tracker);
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
    var presence_tracker = http::HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard server_internal::parse_http1_request_headers(wire, out_req, presence_tracker, body_start_idx) else {
        return false, 0;
    }

    let has_te = (presence_tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (presence_tracker.mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0;

    var cl_len: i64 = 0;
    if has_cl {
        cl_len = presence_tracker.parsed_cl;
    }

    if has_te {
        let _pbf = server_prof::lit_prof_enter("http1.body_framing");
        defer server_prof::lit_prof_leave(_pbf);
        guard server_internal::validate_span_te_header(out_req.headers, presence_tracker.te_idx) else {
            server_internal::clear_request_headers_state(out_req);
            return false, 0;
        }

        let dec_err, chunked_consumed = http::decode_chunked_body_with_trailers(
            wire[body_start_idx..],
            out_req.body,
            out_req.trailers,
        );
        if dec_err != http::ChunkedDecodeError.None || out_req.body.len > MAX_SERVER_BODY_LIMIT {
            out_req.body.clear();
            out_req.trailers.clear();
            if dec_err != http::ChunkedDecodeError.UnexpectedEof &&
               dec_err != http::ChunkedDecodeError.EmptyInput {
                server_internal::clear_request_headers_state(out_req);
            }
            return false, 0;
        }

        let total_consumed = body_start_idx + chunked_consumed;
        return true, total_consumed;
    }

    // Guard against signed integer addition overflow and enforce MAX_SERVER_BODY_LIMIT (10 MB)
    guard cl_len >= 0 && cl_len <= MAX_SERVER_BODY_LIMIT else {
        server_internal::clear_request_headers_state(out_req);
        return false, 0;
    }
    let total_consumed = core::add_sat_i64(body_start_idx, cl_len);
    guard wire.len >= total_consumed else {
        return false, 0;
    }

    if cl_len > 0 {
        let _pbf = server_prof::lit_prof_enter("http1.body_framing");
        out_req.body.append(wire[body_start_idx..total_consumed]);
        server_prof::lit_prof_leave(_pbf);
    }

    return true, total_consumed;
}

// Outcome of HTTP/1.1 request wire parsing with explicit header and body DoS limit classification.
enum H1WireParseStatus {
    Ok,
    Incomplete,
    BadRequest,
    HeadersTooLarge,
    ContentTooLarge,
}

// Parses an incoming HTTP/1.1 wire request while enforcing configurable header and body byte ceilings.
// Distinguishes 431 (`HeadersTooLarge`), 413 (`ContentTooLarge`), incomplete segments, and 400 (`BadRequest`).
//
// Example:
//   wire = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n", max_header_bytes = 1024, max_body_bytes = 64
//   returns: H1WireParseStatus.ContentTooLarge, 0
fn parse_http1_wire_request_with_limits<Req>(
    wire:             const u8[:],
    out_req:          Req&,
    max_header_bytes: i64 = 16384,
    max_body_bytes:   i64 = MAX_SERVER_BODY_LIMIT,
) -> H1WireParseStatus, i64 {
    let pre_st = server_internal::inspect_h1_wire_header_limit(wire, max_header_bytes);
    guard pre_st == H1WireParseStatus.Ok else { return pre_st, 0; }

    var presence_tracker = http::HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard server_internal::parse_http1_request_headers(wire, out_req, presence_tracker, body_start_idx) else {
        return H1WireParseStatus.BadRequest, 0;
    }
    let eff_body = if max_body_bytes >= 0 { max_body_bytes } else { MAX_SERVER_BODY_LIMIT };
    if (presence_tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0 {
        return server_internal::parse_http1_wire_chunked_body_with_limit(
            wire, body_start_idx, presence_tracker.te_idx, out_req, eff_body,
        );
    }
    let has_cl = (presence_tracker.mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0;
    let cl_len = if has_cl { presence_tracker.parsed_cl } else { 0 };
    guard cl_len >= 0 else {
        server_internal::clear_request_headers_state(out_req);
        return H1WireParseStatus.BadRequest, 0;
    }
    if cl_len > eff_body {
        server_internal::clear_request_headers_state(out_req);
        return H1WireParseStatus.ContentTooLarge, 0;
    }
    let total_consumed = core::add_sat_i64(body_start_idx, cl_len);
    guard wire.len >= total_consumed else { return H1WireParseStatus.Incomplete, 0; }
    if cl_len > 0 {
        let _pbf = server_prof::lit_prof_enter("http1.body_framing");
        out_req.body.append(wire[body_start_idx..total_consumed]);
        server_prof::lit_prof_leave(_pbf);
    }
    return H1WireParseStatus.Ok, total_consumed;
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
    guard server_internal::parse_http1_wire_status_line(header_bytes[..line_end], out_res) else { return false, 0; }
    var committed = false;
    defer if !committed {
        server_internal::clear_parsed_wire_response(out_res);
    };

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    let ok_hdrs = server_internal::parse_http1_response_headers_block(
        rest_headers,
        out_res,
        line_end + 2,
    );
    guard ok_hdrs else { return false, 0; }

    out_res.trailers.clear();
    out_res.body.clear();
    out_res.presence_mask = server_internal::detect_response_presence_mask(out_res.headers);

    let framing, ok_frame = server_internal::inspect_response_framing_headers(out_res.headers);
    guard ok_frame else { return false, 0; }

    let is_empty_status = rfc::is_empty_body_status(out_res.status_code);

    // RFC 9112 Section 6.1: Transfer-Encoding - reject Transfer-Encoding in HTTP/1.0 responses.
    if framing.has_te {
        guard out_res.protocol[..] == "HTTP/1.1"
            && server_internal::validate_decodeable_chunked_te(framing.te_buf[..]) else {
            return false, 0;
        }
        // RFC 9112 Section 6.1: An intermediary or recipient processing chunked MUST remove Content-Length
        if framing.has_cl {
            server_internal::purge_conflicting_cl_from_response(out_res);
        }
        // RFC 9112 §6.3 Rule 1: 1xx, 204, and 304 responses NEVER have a message body
        if is_empty_status {
            committed = true;
            return true, header_end_idx;
        }
        let dec_err, chunked_consumed = http::decode_chunked_body_with_trailers(
            wire[header_end_idx..],
            out_res.body,
            out_res.trailers,
        );
        guard dec_err == http::ChunkedDecodeError.None else { return false, 0; }
        committed = true;
        return true, header_end_idx + chunked_consumed;
    }

    // Status 204 No Content, 304 Not Modified, or 1xx: MUST NOT include message body
    if is_empty_status {
        committed = true;
        return true, header_end_idx;
    }

    if framing.has_cl {
        guard framing.cl_len >= 0 && framing.cl_len <= MAX_SERVER_BODY_LIMIT &&
              wire.len >= header_end_idx + framing.cl_len else {
            return false, 0;
        }
        if framing.cl_len > 0 {
            out_res.body.append(wire[header_end_idx..(header_end_idx + framing.cl_len)]);
        }
        committed = true;
        return true, header_end_idx + framing.cl_len;
    }

    // Otherwise, consume remainder of stream up to MAX_SERVER_BODY_LIMIT
    if wire.len > header_end_idx {
        let rem_body = wire[header_end_idx..];
        guard rem_body.len <= MAX_SERVER_BODY_LIMIT else { return false, 0; }
        out_res.body.append(rem_body);
    }
    committed = true;
    return true, wire.len;
}

const DEFAULT_SERVER_HEADER: const u8[:] = "Server: goose-wing\r\n";

// Controls omission of automatic `Server` and `Date` response headers on HTTP/1.1 wire output.
enum ServerHeaderPolicy {
    Standard,
    OmitServer,
    OmitDate,
    OmitBoth,
}

// Formats the Date header at most once per second into a reusable pre-baked string.
// Eliminates repetitive wall-clock system calls and calendar math for every HTTP response.
struct CachedHttpDate {
    header_str:     u8[..64]  = [],
    fast_prefix:    u8[..160] = [],
    fast_prefix_v1: u8[..128] = [],
    last_sec:       i64       = 0,
    last_tsc:       u64       = 0,
}

fn get_cached_http_date_header(now_sec: i64 = 0) -> const u8[:] {
    server_internal::update_server_cached_date(server_internal::g_compat_date, now_sec);
    return server_internal::g_compat_date.header_str[..];
}

// Serializes only the HTTP/1.1 response status line and headers into out_wire,
// omitting the body. Used for zero-copy vectored transmission via tcp_send2.
fn serialize_http1_headers<Res, B>(
    res:               const Res&,
    server_name:       const u8[:],
    out_wire:          B&,
    now_sec:           i64                = 0,
    override_body_len: i64                = -1,
    header_policy:     ServerHeaderPolicy = ServerHeaderPolicy.Standard,
) {
    let date_hdr = get_cached_http_date_header(now_sec);
    let eff_body_len = if override_body_len >= 0 { override_body_len } else { res.body.len };

    var mask = res.presence_mask;
    if mask == 0 && res.headers.entries.len > 0 {
        mask = server_internal::detect_response_presence_mask(res.headers);
    }
    if header_policy == ServerHeaderPolicy.Standard
        && server_internal::serialize_http1_fast_single_ct(res, server_name, eff_body_len, mask, out_wire) {
        return;
    }

    server_internal::serialize_http1_status_and_meta(
        res.status_code, server_name, date_hdr, mask, header_policy, out_wire,
    );

    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    let has_te = (mask & http::RES_PRESENCE_TRANSFER_ENCODING) != 0;
    if !is_empty_status && (mask & http::RES_PRESENCE_CONTENT_LENGTH) == 0 && !has_te {
        server_internal::serialize_content_length_header(eff_body_len, out_wire);
    }

    server_internal::serialize_response_headers_list(res.headers, res.status_code, has_te, out_wire);

    let has_conn = (mask & http::RES_PRESENCE_CONNECTION) != 0;
    if !has_conn {
        out_wire.append(rfc::HTTP1_CONN_KEEP_ALIVE);
    } else {
        out_wire.append("\r\n");
    }
}

// Serializes a complete HTTP/1.1 response into raw wire bytes.
// Automatically uses chunked transfer encoding if Transfer-Encoding: chunked is requested or if trailers are present.
fn serialize_http1_response<Res, B>(
    res:           const Res&,
    server_name:   const u8[:],
    out_wire:      B&,
    now_sec:       i64                = 0,
    header_policy: ServerHeaderPolicy = ServerHeaderPolicy.Standard,
) {
    let _prof = server_prof::lit_prof_enter("http1.resp_serialize");
    defer server_prof::lit_prof_leave(_prof);
    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    if !is_empty_status {
        if res.trailers.entries.len > 0 {
            server_internal::serialize_http1_chunked_with_policy(res, server_name, 4096, out_wire, header_policy);
            return;
        }
        let has_te = if res.presence_mask != 0 {
            (res.presence_mask & http::RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else if res.headers.entries.len > 0 {
            (server_internal::detect_response_presence_mask(res.headers) & http::RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else {
            false
        };
        if has_te && http::header(res, "transfer-encoding").eq_ascii_fold("chunked") {
            server_internal::serialize_http1_chunked_with_policy(res, server_name, 4096, out_wire, header_policy);
            return;
        }
    }

    serialize_http1_headers(res, server_name, out_wire, now_sec, -1, header_policy);

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
            (res.presence_mask & http::RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else if res.headers.entries.len > 0 {
            (server_internal::detect_response_presence_mask(res.headers) & http::RES_PRESENCE_TRANSFER_ENCODING) != 0
        } else {
            false
        };
        if has_te || res.trailers.entries.len > 0 {
            let te = http::header(res, "transfer-encoding");
            if te.eq_ascii_fold("chunked") || res.trailers.entries.len > 0 {
                server_internal::serialize_http1_chunked_response(res, server_name, 4096, wire_headers);
                return net::tcp_send(fd, wire_headers[..]);
            }
        }
    }

    serialize_http1_headers(res, server_name, wire_headers);
    if res.body.len == 0 || is_empty_status {
        return net::tcp_send(fd, wire_headers[..]);
    }
    return net::tcp_send2(fd, wire_headers[..], res.body[..]);
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
                let sent = net::tcp_sendv(fd, arr);
                guard sent >= 0 else { return sent; }
                total_sent += sent;
                arr = core::new_iovec_array();
            }
            arr.iovec_push(chunk);
        }
    }
    if arr.iovec_count() > 0 {
        let sent = net::tcp_sendv(fd, arr);
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
        http::set_header(res, "Content-Length", len_buf[..]);
    }
    if close_connection {
        http::set_header(res, "Connection", "close");
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
    return net::tcp_send(fd, wire_headers[..]);
}

checkfree fn is_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len >= 24 && raw_stream[..24] == rfc::H2_CLIENT_PREFACE[..];
}

// True while a short read is still a strict prefix of the 24-byte H2 preface.
// The preface contains "\r\n\r\n" at offset 14, so a sliced first TCP segment
// must not fall through to the HTTP/1.1 parser (found by Toxiproxy SlicerToxic).
checkfree fn is_partial_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len > 0 && raw_stream.len < 24 && raw_stream == rfc::H2_CLIENT_PREFACE[..raw_stream.len];
}

const MAX_SERVER_BODY_LIMIT: i64 = 10 * 1024 * 1024; // 10 MB payload limit

fn serialize_bad_request_error<B>(
    server_name:   const u8[:],
    wire_out:      B&,
    header_policy: ServerHeaderPolicy = ServerHeaderPolicy.Standard,
) {
    var err_resp = http::Response { status_code: rfc::STATUS_BAD_REQUEST, .. };
    serialize_http1_response(err_resp, server_name, wire_out, 0, header_policy);
}

fn serialize_headers_too_large_error<B>(
    server_name:   const u8[:],
    wire_out:      B&,
    header_policy: ServerHeaderPolicy = ServerHeaderPolicy.Standard,
) {
    var err_resp = http::Response { status_code: rfc::STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE, .. };
    http::set_header(err_resp, "Connection", "close");
    serialize_http1_response(err_resp, server_name, wire_out, 0, header_policy);
}

fn serialize_content_too_large_error<B>(
    server_name:   const u8[:],
    wire_out:      B&,
    header_policy: ServerHeaderPolicy = ServerHeaderPolicy.Standard,
) {
    var err_resp = http::Response { status_code: rfc::STATUS_CONTENT_TOO_LARGE, .. };
    http::set_header(err_resp, "Connection", "close");
    serialize_http1_response(err_resp, server_name, wire_out, 0, header_policy);
}
