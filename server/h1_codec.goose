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
import .profiler;
import .h1_codec_internal;
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

// Collects transfer-encoding headers into `out_te`. Rolls back `out_te` on overflow.
fn collect_transfer_encoding_headers<B>(headers: const http::HeaderMap&, out_te: B&) -> bool {
    let saved_len = out_te.len;
    var committed = false;
    defer if !committed { out_te.resize(saved_len); };
    for &hdr in headers.entries {
        if http::entry_name(headers, hdr).eq_ascii_fold("transfer-encoding") {
            guard server_internal::append_te_header_value(out_te, http::entry_value(headers, hdr)) else {
                return false;
            }
        }
    }
    committed = true;
    return true;
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

inline fn validate_http1_request_target_for_mode(
    path_slice:  const u8[:],
    verb:        RequestTargetVerb,
    target_mode: RequestTargetMode,
) -> bool {
    if path_slice[0] == '/' {
        return verb != RequestTargetVerb.Connect;
    }
    if path_slice.len == 1 && path_slice[0] == '*' {
        return verb == RequestTargetVerb.Options;
    }
    if verb == RequestTargetVerb.Connect {
        return server_internal::validate_connect_authority(path_slice);
    }
    guard target_mode == RequestTargetMode.AllowAbsoluteForm && verb != RequestTargetVerb.Options else {
        return false;
    }
    let uv, _ = core::parse_url_view(path_slice);
    return uv.valid && uv.host.len > 0 &&
        (uv.scheme.eq_ascii_fold("http") || uv.scheme.eq_ascii_fold("https"));
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
    let _prof = prof_enter("http1.req_line");
    defer prof_leave(_prof);
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
    guard validate_http1_request_target_for_mode(path_slice, verb, target_mode) else { return false; }

    guard req_line.len - (sp2 + 1) == 8 else { return false; }
    let proto_u64 = core::read_le_u64(req_line, sp2 + 1);
    guard proto_u64 == rfc::HTTP_VERSION_1_1_U64 || proto_u64 == rfc::HTTP_VERSION_1_0_U64 else { return false; }
    let _ = out_req.method.try_set(req_line[..sp1]);
    let _ = out_req.url.try_set(path_slice);
    out_req.is_http10 = (proto_u64 == rfc::HTTP_VERSION_1_0_U64);
    return true;
}

// Validates the `Host` header, skipping redundant character/authority parsing when the keep-alive
// `Host` slice matches the previously validated `last_valid_host` on the connection (FastHTTP parity).
fn validate_span_host_header_memoized(
    headers:         const http::HeaderMap&,
    host_idx:        i16,
    last_valid_host: u8[..128]&,
    has_valid_host:  bool&,
) -> bool {
    let idx = host_idx as i64;
    guard idx >= 0 && idx < headers.entries.len else { return false; }
    let host_val = http::entry_value(headers, headers.entries[idx]);
    if has_valid_host && host_val == last_valid_host[..] {
        return true;
    }
    guard server_internal::validate_span_host_header(headers, host_idx) else { return false; }
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
    let _prof = prof_enter("http1.headers");
    defer prof_leave(_prof);
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
        let _pbf = prof_enter("http1.body_framing");
        defer prof_leave(_pbf);
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
        let _pbf = prof_enter("http1.body_framing");
        out_req.body.append(wire[body_start_idx..total_consumed]);
        prof_leave(_pbf);
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

inline fn strip_leading_h1_wire_crlf(wire: const u8[:]) -> const u8[:], H1WireParseStatus {
    guard wire.len > 0 else { return "", H1WireParseStatus.Incomplete; }
    guard wire[0] != ' ' && wire[0] != '\t' else { return "", H1WireParseStatus.BadRequest; }
    if wire.len == 1 && wire[0] == '\r' {
        return "", H1WireParseStatus.Incomplete;
    }
    guard wire.len >= 2 && wire[0] == '\r' && wire[1] == '\n' else {
        return wire, H1WireParseStatus.Ok;
    }
    guard wire.len > 2 else { return "", H1WireParseStatus.Incomplete; }
    let b0 = wire[2];
    guard b0 != '\r' && b0 != '\n' && b0 != ' ' && b0 != '\t' else {
        return "", H1WireParseStatus.BadRequest;
    }
    return wire[2..], H1WireParseStatus.Ok;
}

// Checks HTTP/1.1 wire prefix framing and header block byte cap before full header parsing.
//
// Example:
//   wire = "GET / HTTP/1.1\r\nHost: a\r\n\r\n", max_header_bytes = 16
//   returns: H1WireParseStatus.HeadersTooLarge
fn inspect_h1_wire_header_limit(wire: const u8[:], max_header_bytes: i64) -> H1WireParseStatus {
    let active, pre_st = strip_leading_h1_wire_crlf(wire);
    guard pre_st == H1WireParseStatus.Ok else { return pre_st; }
    let hdr_end = core::fast_find_crlfcrlf(active);
    if max_header_bytes > 0 {
        let measured = if hdr_end >= 0 { core::add_sat_i64(hdr_end, 4) } else { active.len };
        if measured > max_header_bytes {
            return H1WireParseStatus.HeadersTooLarge;
        }
    }
    if hdr_end < 0 {
        return if active.len > 8192 { H1WireParseStatus.BadRequest } else { H1WireParseStatus.Incomplete };
    }
    return H1WireParseStatus.Ok;
}

// Parses a chunked HTTP/1.1 request body while enforcing `eff_body` bytes maximum payload size.
//
// Example:
//   wire = "...\r\n\r\n5\r\nhello\r\n0\r\n\r\n", eff_body = 64
//   returns: H1WireParseStatus.Ok, total_consumed
fn parse_http1_wire_chunked_body_with_limit<Req>(
    wire:           const u8[:],
    body_start_idx: i64,
    te_idx:         i16,
    out_req:        Req&,
    eff_body:       i64,
) -> H1WireParseStatus, i64 {
    let _pbf = prof_enter("http1.body_framing");
    defer prof_leave(_pbf);
    guard server_internal::validate_span_te_header(out_req.headers, te_idx) else {
        server_internal::clear_request_headers_state(out_req);
        return H1WireParseStatus.BadRequest, 0;
    }
    let body_wire = wire[body_start_idx..];
    let dec_err, chunked_consumed = http::decode_chunked_body_with_trailers(
        body_wire, out_req.body, out_req.trailers,
    );
    if out_req.body.len > eff_body {
        out_req.body.clear();
        out_req.trailers.clear();
        server_internal::clear_request_headers_state(out_req);
        return H1WireParseStatus.ContentTooLarge, 0;
    }
    if dec_err == http::ChunkedDecodeError.UnexpectedEof || dec_err == http::ChunkedDecodeError.EmptyInput {
        var cur: i64 = 0;
        let csz, sz_err = http::read_chunk_size_line(body_wire, cur);
        out_req.body.clear();
        out_req.trailers.clear();
        if sz_err == http::ChunkedDecodeError.None && csz > (eff_body as u64) {
            server_internal::clear_request_headers_state(out_req);
            return H1WireParseStatus.ContentTooLarge, 0;
        }
        return H1WireParseStatus.Incomplete, 0;
    }
    guard dec_err == http::ChunkedDecodeError.None else {
        out_req.body.clear();
        out_req.trailers.clear();
        server_internal::clear_request_headers_state(out_req);
        return H1WireParseStatus.BadRequest, 0;
    }
    return H1WireParseStatus.Ok, core::add_sat_i64(body_start_idx, chunked_consumed);
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
    let pre_st = inspect_h1_wire_header_limit(wire, max_header_bytes);
    guard pre_st == H1WireParseStatus.Ok else { return pre_st, 0; }

    var presence_tracker = http::HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard server_internal::parse_http1_request_headers(wire, out_req, presence_tracker, body_start_idx) else {
        return H1WireParseStatus.BadRequest, 0;
    }
    let eff_body = if max_body_bytes >= 0 { max_body_bytes } else { MAX_SERVER_BODY_LIMIT };
    if (presence_tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0 {
        return parse_http1_wire_chunked_body_with_limit(
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
        let _pbf = prof_enter("http1.body_framing");
        out_req.body.append(wire[body_start_idx..total_consumed]);
        prof_leave(_pbf);
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

fn format_local_http_date(out: u8[..64]&, now_sec: i64) {
    let _ = out.try_set(get_cached_http_date_header(now_sec));
}

fn get_cached_http_date_header(now_sec: i64 = 0) -> const u8[:] {
    server_internal::update_server_cached_date(server_internal::g_compat_date, now_sec);
    return server_internal::g_compat_date.header_str[..];
}

inline fn serialize_http1_fast_single_ct<Res, B>(
    res:          const Res&,
    server_name:  const u8[:],
    eff_body_len: i64,
    mask:         u16,
    out_wire:     B&,
) -> bool {
    guard res.status_code == 200 && (server_name == "goose-wing" || server_name == "goose-wing/1.0") else {
        return false;
    }
    guard mask == http::RES_PRESENCE_CONTENT_TYPE
        && res.headers.entries.len == 1
        && res.trailers.entries.len == 0 else {
        return false;
    }
    let h0_name = http::entry_name(res.headers, res.headers.entries[0]);
    guard h0_name.eq_ascii_fold("content-type") else { return false; }
    if server_name == "goose-wing" {
        out_wire.append(server_internal::g_compat_date.fast_prefix[..]);
    } else {
        out_wire.append(server_internal::g_compat_date.fast_prefix_v1[..]);
    }
    server_internal::serialize_content_length_header(eff_body_len, out_wire);
    let h0_val = http::entry_value(res.headers, res.headers.entries[0]);
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
    return true;
}

inline fn policy_omits_server_header(policy: ServerHeaderPolicy) -> bool {
    return policy == ServerHeaderPolicy.OmitServer || policy == ServerHeaderPolicy.OmitBoth;
}

inline fn policy_omits_date_header(policy: ServerHeaderPolicy) -> bool {
    return policy == ServerHeaderPolicy.OmitDate || policy == ServerHeaderPolicy.OmitBoth;
}

inline fn serialize_http1_status_and_meta<B>(
    status_code:   i32,
    server_name:   const u8[:],
    date_hdr:      const u8[:],
    mask:          u16,
    header_policy: ServerHeaderPolicy,
    out_wire:      B&,
) {
    let omit_server = policy_omits_server_header(header_policy);
    let omit_date = policy_omits_date_header(header_policy);
    if header_policy == ServerHeaderPolicy.Standard && status_code == 200
        && (mask & (http::RES_PRESENCE_SERVER | http::RES_PRESENCE_DATE)) == 0 {
        if server_name == "goose-wing" {
            out_wire.append(server_internal::g_compat_date.fast_prefix[..]);
            return;
        }
        if server_name == "goose-wing/1.0" {
            out_wire.append(server_internal::g_compat_date.fast_prefix_v1[..]);
            return;
        }
    }
    server_internal::serialize_status_line(status_code, out_wire);
    if !omit_server && (mask & http::RES_PRESENCE_SERVER) == 0 {
        server_internal::serialize_server_header(server_name, out_wire);
    }
    if !omit_date && (mask & http::RES_PRESENCE_DATE) == 0 {
        out_wire.append(date_hdr);
    }
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
        && serialize_http1_fast_single_ct(res, server_name, eff_body_len, mask, out_wire) {
        return;
    }

    serialize_http1_status_and_meta(res.status_code, server_name, date_hdr, mask, header_policy, out_wire);

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

inline fn serialize_chunked_header_fields<B>(
    headers:      const http::HeaderMap&,
    has_trailers: bool,
    out_wire:     B&,
) {
    for &e in headers.entries {
        let hname = http::entry_name(headers, e);
        let skip = hname.eq_ascii_fold("content-length")
            || hname.eq_ascii_fold("transfer-encoding")
            || (has_trailers && hname.eq_ascii_fold("trailer"));
        guard !skip else { continue; }
        out_wire.append(hname);
        out_wire.append(": ");
        out_wire.append(http::entry_value(headers, e));
        out_wire.append("\r\n");
    }
}

fn serialize_http1_chunked_with_policy<Res, B>(
    res:           const Res&,
    server_name:   const u8[:],
    chunk_size:    i64,
    out_wire:      B&,
    header_policy: ServerHeaderPolicy,
) {
    if header_policy == ServerHeaderPolicy.Standard {
        server_internal::serialize_http1_chunked_response(res, server_name, chunk_size, out_wire);
        return;
    }
    server_internal::serialize_status_line(res.status_code, out_wire);
    if !policy_omits_server_header(header_policy) {
        server_internal::serialize_server_header(server_name, out_wire);
    }
    if !policy_omits_date_header(header_policy) && !res.has_header("date") {
        out_wire.append(get_cached_http_date_header(0));
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
    serialize_chunked_header_fields(res.headers, res.trailers.entries.len > 0, out_wire);
    if !res.has_header("connection") {
        out_wire.append("Connection: keep-alive\r\n");
    }
    out_wire.append("\r\n");
    client::encode_chunked_payload(res.body[..], res.trailers, chunk_size, out_wire);
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
    let _prof = prof_enter("http1.resp_serialize");
    defer prof_leave(_prof);
    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    if !is_empty_status {
        if res.trailers.entries.len > 0 {
            serialize_http1_chunked_with_policy(res, server_name, 4096, out_wire, header_policy);
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
            serialize_http1_chunked_with_policy(res, server_name, 4096, out_wire, header_policy);
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
    var err_resp = http::Response { status_code: 400, .. };
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
