// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-copy HTTP/1.1 wire request view parser, chunked decoder, and response serializer (RFC 9112).
// Parses directly into borrowed `const u8[:]` slices with ~640 B request stack footprint.
namespace h1;

import std;
import core.bytes.case;
import core.bytes.trim;
import core.bytes.search;
import core.bytes.split;
import core.bytes.parse;
import core.bytes.format;
import core.bytes.utf8;
import core.math.arithmetic;
import .transport;

// RFC 9112 Section 5: Field Syntax - bounded header count and head block limits.
const MAX_H1_HEADERS:    i64 = 64;
const MAX_H1_HEAD_BYTES: i64 = 8192;
const MAX_H1_BODY_BYTES: i64 = 10485760;

// Bitmask flags recorded on parsed `RequestView` and `ResponseHeadView`.
const H1_FLAG_HTTP10:          u16 = 1 << 0;
const H1_FLAG_HAS_HOST:        u16 = 1 << 1;
const H1_FLAG_HAS_CL:          u16 = 1 << 2;
const H1_FLAG_HAS_TE:          u16 = 1 << 3;
const H1_FLAG_CONN_CLOSE:      u16 = 1 << 4;
const H1_FLAG_CONN_KEEP_ALIVE: u16 = 1 << 5;

enum ParseStatus {
    Complete,
    Incomplete,
    BadRequest,
    HeadersTooLarge,
    PayloadTooLarge,
}

// 8-byte zero-copy offset span indexing a header name and trimmed value inside `raw`.
struct HeaderSlice {
    name_start: u16 = 0,
    name_end:   u16 = 0,
    val_start:  u16 = 0,
    val_end:    u16 = 0,
}

// ~640-byte zero-copy view over a parsed HTTP/1.1 request in a wire or ring buffer.
struct RequestView {
    raw:            const u8[:]       = "",
    method:         const u8[:]       = "",
    target:         const u8[:]       = "",
    path:           const u8[:]       = "",
    query:          const u8[:]       = "",
    body:           const u8[:]       = "",
    host:           const u8[:]       = "",
    headers:        HeaderSlice[..64] = [],
    content_length: i64               = 0,
    flags:          u16               = 0,
}

// ~2.6 KB stack-bounded response builder supporting both zero-copy views and dynamic bodies.
struct ResponseView {
    status_code:  u16         = 200,
    content_type: u8[..64]    = "text/plain",
    extra_hdrs:   u8[..512]   = [],
    body:         const u8[:] = "",
    body_buf:     u8[..2048]  = [],
    close_conn:   bool        = false,
}

// ---- Bounded Buffer Helpers (Zero core.ufcs / core.crypto Dependency) -------

inline fn buf_append<B>(dst: B&, src: const u8[:]) -> bool {
    guard dst.len >= 0 && src.len >= 0 && core::add_sat_i64(dst.len, src.len) <= dst.cap else {
        return false;
    }
    dst.append(src);
    return true;
}

inline fn buf_push<B, T>(dst: B&, item: T) -> bool {
    guard dst.len >= 0 && dst.len < dst.cap else { return false; }
    dst.push(item);
    return true;
}

inline fn buf_set<B>(dst: B&, src: const u8[:]) -> bool {
    guard src.len >= 0 && src.len <= dst.cap else { return false; }
    dst.clear();
    dst.append(src);
    return true;
}

// ---- RFC 9110 / RFC 9112 Lexical Validators ---------------------------------

// RFC 9110 Section 5.6.2: Tokens - verifies non-empty HTTP token characters.
fn is_valid_token(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

// RFC 9110 Section 5.5: Field Values - permits HTAB, SP, VCHAR, and obs-text (0x80..0xFF).
fn is_valid_field_value(s: const u8[:]) -> bool {
    for b in s {
        guard b == '\t' || (b >= 0x20 && b <= 0x7E) || b >= 0x80 else { return false; }
    }
    return true;
}

// RFC 9112 Section 3.2: Request Target - visible ASCII excluding '#' fragment delimiter.
fn is_valid_request_target(target: const u8[:], method: const u8[:]) -> bool {
    guard target.len > 0 else { return false; }
    let valid_start = target[0] == '/' || (target.len == 1 && target[0] == '*' && method == "OPTIONS");
    guard valid_start else { return false; }
    for b in target {
        guard b >= 0x21 && b <= 0x7E && b != '#' else { return false; }
    }
    return true;
}

// Checks whether `s` contains any bare CR or bare LF not paired as `\r\n`.
fn has_bare_cr_or_lf(s: const u8[:]) -> bool {
    for i in s.len {
        let b = s[i];
        if b == '\r' {
            let nxt = core::add_sat_i64(i, 1);
            guard nxt < s.len && s[nxt] == '\n' else { return true; }
        }
        if b == '\n' {
            guard i > 0 && s[core::sub_sat_i64(i, 1)] == '\r' else { return true; }
        }
    }
    return false;
}

// Checks whether a comma-separated header value contains `token` (case-insensitive).
fn header_value_has_token(val: const u8[:], token: const u8[:]) -> bool {
    var rem = val;
    while rem.len > 0 {
        let head, tail, has_comma = core::split_once_byte(rem, ',');
        if core::eq_ascii_fold(core::trim_lws(head), token) {
            return true;
        }
        if !has_comma { break; }
        rem = tail;
    }
    return false;
}

// ---- Zero-Copy RequestView Accessors ----------------------------------------

// Extracts zero-copy slice of `name` from `raw` for `hs`, returning "" if out of bounds.
inline fn header_slice_name(raw: const u8[:], hs: HeaderSlice) -> const u8[:] {
    let s = hs.name_start as i64;
    let e = hs.name_end as i64;
    guard s <= e && e <= raw.len else { return ""; }
    return raw[s..e];
}

// Extracts zero-copy slice of trimmed value from `raw` for `hs`, returning "" if out of bounds.
inline fn header_slice_val(raw: const u8[:], hs: HeaderSlice) -> const u8[:] {
    let s = hs.val_start as i64;
    let e = hs.val_end as i64;
    guard s <= e && e <= raw.len else { return ""; }
    return raw[s..e];
}

// Looks up the first header matching `name` (ASCII case-insensitive) as a zero-copy slice.
fn header(req: const RequestView&, name: const u8[:]) -> const u8[:] {
    for i in req.headers.len {
        let hs = req.headers[i];
        if core::eq_ascii_fold(header_slice_name(req.raw, hs), name) {
            return header_slice_val(req.raw, hs);
        }
    }
    return "";
}

// Returns true when `req` contains at least one header matching `name` (case-insensitive).
fn has_header(req: const RequestView&, name: const u8[:]) -> bool {
    for i in req.headers.len {
        if core::eq_ascii_fold(header_slice_name(req.raw, req.headers[i]), name) {
            return true;
        }
    }
    return false;
}

// RFC 9112 Section 9.3: Persistence - determines whether the connection must close after this turn.
fn wants_close(req: const RequestView&) -> bool {
    if (req.flags & H1_FLAG_CONN_CLOSE) != 0 {
        return true;
    }
    if (req.flags & H1_FLAG_HTTP10) != 0 {
        return (req.flags & H1_FLAG_CONN_KEEP_ALIVE) == 0;
    }
    return false;
}

enum QueryMatch {
    Missing,
    Valueless,
    Value,
}

// Decodes an application/x-www-form-urlencoded query value (`+` -> `' '`, `%XX` -> byte) into `out`.
// Rolls back `out` on malformed percent-escape or capacity overflow.
//
// Example:
//   raw = "hello%20world+ok", out = []
//   returns: true, out = "hello world ok"
fn decode_query_component<B>(raw: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    out.clear();
    var idx: i64 = 0;
    while idx < raw.len {
        let b = raw[idx];
        if b == '+' {
            guard buf_push(out, ' ') else { return false; }
            idx = core::add_sat_i64(idx, 1);
            continue;
        }
        if b == '%' {
            let p1 = core::add_sat_i64(idx, 1);
            let p3 = core::add_sat_i64(idx, 3);
            guard p3 <= raw.len else { return false; }
            let dec_byte, ok_hex = core::parse_u8_hex(raw[p1..p3]);
            guard ok_hex else { return false; }
            guard buf_push(out, dec_byte) else { return false; }
            idx = p3;
            continue;
        }
        guard buf_push(out, b) else { return false; }
        idx = core::add_sat_i64(idx, 1);
    }
    committed = true;
    return true;
}

// Looks up a raw (zero-copy) query parameter by `key` directly inside `req.query`.
fn query_param_raw(req: const RequestView&, key: const u8[:]) -> const u8[:], QueryMatch {
    guard key.len > 0 && req.query.len > 0 else { return "", QueryMatch.Missing; }
    var rem = req.query;
    while rem.len > 0 {
        let pair, tail, has_amp = core::split_once_byte(rem, '&');
        if pair.len > 0 {
            let k, v, has_eq = core::split_once_byte(pair, '=');
            if k == key {
                if !has_eq { return "", QueryMatch.Valueless; }
                return v, QueryMatch.Value;
            }
        }
        if !has_amp { break; }
        rem = tail;
    }
    return "", QueryMatch.Missing;
}

// Looks up and percent-decodes a query parameter from `req.query` into `out`.
fn query_param<B>(req: const RequestView&, key: const u8[:], out: B&) -> QueryMatch {
    out.clear();
    let raw_val, m = query_param_raw(req, key);
    guard m == QueryMatch.Value else { return m; }
    guard decode_query_component(raw_val, out) else { return QueryMatch.Missing; }
    return QueryMatch.Value;
}

// ---- RFC 9112 Zero-Copy Request Parser --------------------------------------

// Parses a single header line at `wire[line_start..line_end]` and updates framing flags.
fn record_request_header_line(
    wire:       const u8[:],
    line_start: i64,
    line_end:   i64,
    req:        RequestView&,
) -> ParseStatus {
    guard line_start >= 0 && line_start < line_end && line_end <= wire.len && line_end <= MAX_H1_HEAD_BYTES else {
        return ParseStatus.BadRequest;
    }
    let line = wire[line_start..line_end];
    let col = core::index_of_byte(line, ':');
    guard col > 0 else { return ParseStatus.BadRequest; }

    let name = line[..col];
    guard is_valid_token(name) else { return ParseStatus.BadRequest; }
    let raw_val = line[core::add_sat_i64(col, 1)..];
    let lead = core::trim_lws_start(raw_val);
    let trimmed = core::trim_lws_end(lead);
    guard is_valid_field_value(trimmed) else { return ParseStatus.BadRequest; }

    let lead_skip = core::sub_sat_i64(raw_val.len, lead.len);
    let v_start = core::add_sat_i64(core::add_sat_i64(line_start, core::add_sat_i64(col, 1)), lead_skip);
    let v_end = core::add_sat_i64(v_start, trimmed.len);
    let hs = HeaderSlice {
        name_start: line_start as u16,
        name_end:   core::add_sat_i64(line_start, col) as u16,
        val_start:  v_start as u16,
        val_end:    v_end as u16,
    };
    guard buf_push(req.headers, hs) else { return ParseStatus.HeadersTooLarge; }
    return apply_request_framing_header(name, trimmed, req);
}

// RFC 9112 Section 6.2: Content-Length - validates numeric length, smuggling absence, and duplicates.
fn apply_content_length_header(val: const u8[:], flags: u16&, content_length: i64&) -> ParseStatus {
    guard (flags & H1_FLAG_HAS_TE) == 0 else { return ParseStatus.BadRequest; }
    let cl_u, ok_u = core::parse_u64_dec(val);
    guard ok_u else { return ParseStatus.BadRequest; }
    guard cl_u <= (MAX_H1_BODY_BYTES as u64) else { return ParseStatus.PayloadTooLarge; }
    let cl_i = cl_u as i64;
    if (flags & H1_FLAG_HAS_CL) != 0 {
        guard content_length == cl_i else { return ParseStatus.BadRequest; }
    }
    flags = flags | H1_FLAG_HAS_CL;
    content_length = cl_i;
    return ParseStatus.Complete;
}

// RFC 9112 Section 6.1: Transfer-Encoding - rejects TE+CL conflicts, HTTP/1.0 TE, and unknown codings.
fn apply_transfer_encoding_header(val: const u8[:], flags: u16&) -> ParseStatus {
    guard (flags & H1_FLAG_HAS_CL) == 0 && (flags & H1_FLAG_HTTP10) == 0 else {
        return ParseStatus.BadRequest;
    }
    guard core::eq_ascii_fold(val, "chunked") else { return ParseStatus.BadRequest; }
    flags = flags | H1_FLAG_HAS_TE;
    return ParseStatus.Complete;
}

// Validates Host, Content-Length, Transfer-Encoding, and Connection framing semantics.
fn apply_request_framing_header(name: const u8[:], val: const u8[:], req: RequestView&) -> ParseStatus {
    if core::eq_ascii_fold(name, "host") {
        // RFC 9112 Section 3.2: Request Target - reject duplicate or empty Host headers.
        guard (req.flags & H1_FLAG_HAS_HOST) == 0 && val.len > 0 else { return ParseStatus.BadRequest; }
        req.flags = req.flags | H1_FLAG_HAS_HOST;
        req.host = val;
        return ParseStatus.Complete;
    }
    if core::eq_ascii_fold(name, "content-length") {
        return apply_content_length_header(val, req.flags, req.content_length);
    }
    if core::eq_ascii_fold(name, "transfer-encoding") {
        return apply_transfer_encoding_header(val, req.flags);
    }
    if core::eq_ascii_fold(name, "connection") {
        if header_value_has_token(val, "close") {
            req.flags = req.flags | H1_FLAG_CONN_CLOSE;
        }
        if header_value_has_token(val, "keep-alive") {
            req.flags = req.flags | H1_FLAG_CONN_KEEP_ALIVE;
        }
    }
    return ParseStatus.Complete;
}

// Scans a chunked body in `src` (RFC 9112 Section 7.1), returning total framed bytes consumed.
//
// Example:
//   src = "5\r\nhello\r\n0\r\n\r\n"
//   returns: 15, ParseStatus.Complete
fn scan_chunked_framing(src: const u8[:]) -> i64, ParseStatus {
    var cursor:     i64 = 0;
    var total_body: i64 = 0;
    while cursor < src.len {
        let crlf = core::find_crlf(src[cursor..]);
        guard crlf >= 0 else { return 0, ParseStatus.Incomplete; }
        let sz_line = src[cursor..core::add_sat_i64(cursor, crlf)];
        let sz_hex, _, _ = core::split_once_byte(sz_line, ';');
        let chunk_u, ok_hex = core::parse_u64_hex(core::trim_lws(sz_hex));
        guard ok_hex else { return 0, ParseStatus.BadRequest; }
        guard chunk_u <= (MAX_H1_BODY_BYTES as u64) else { return 0, ParseStatus.PayloadTooLarge; }
        let chunk_len = chunk_u as i64;
        cursor = core::add_sat_i64(cursor, core::add_sat_i64(crlf, 2));
        if chunk_len == 0 {
            guard core::add_sat_i64(cursor, 2) <= src.len else { return 0, ParseStatus.Incomplete; }
            guard src[cursor] == '\r' && src[core::add_sat_i64(cursor, 1)] == '\n' else {
                return 0, ParseStatus.BadRequest;
            }
            return core::add_sat_i64(cursor, 2), ParseStatus.Complete;
        }
        total_body = core::add_sat_i64(total_body, chunk_len);
        guard total_body <= MAX_H1_BODY_BYTES else { return 0, ParseStatus.PayloadTooLarge; }
        let end_data = core::add_sat_i64(cursor, chunk_len);
        let end_chunk = core::add_sat_i64(end_data, 2);
        guard end_chunk <= src.len else { return 0, ParseStatus.Incomplete; }
        guard src[end_data] == '\r' && src[core::add_sat_i64(end_data, 1)] == '\n' else {
            return 0, ParseStatus.BadRequest;
        }
        cursor = end_chunk;
    }
    return 0, ParseStatus.Incomplete;
}

// Decodes RFC 9112 Section 7.1 chunked body bytes into `out`. Rolls back `out` on error.
//
// Example:
//   raw_chunked = "5\r\nhello\r\n0\r\n\r\n", out = []
//   returns: 15, ParseStatus.Complete, out = "hello"
fn decode_chunked_body<B>(raw_chunked: const u8[:], out: B&) -> i64, ParseStatus {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    var cursor: i64 = 0;
    while cursor < raw_chunked.len {
        let crlf = core::find_crlf(raw_chunked[cursor..]);
        guard crlf >= 0 else { return 0, ParseStatus.Incomplete; }
        let sz_line = raw_chunked[cursor..core::add_sat_i64(cursor, crlf)];
        let sz_hex, _, _ = core::split_once_byte(sz_line, ';');
        let chunk_u, ok_hex = core::parse_u64_hex(core::trim_lws(sz_hex));
        guard ok_hex else { return 0, ParseStatus.BadRequest; }
        guard chunk_u <= (MAX_H1_BODY_BYTES as u64) else { return 0, ParseStatus.PayloadTooLarge; }
        let chunk_len = chunk_u as i64;
        cursor = core::add_sat_i64(cursor, core::add_sat_i64(crlf, 2));
        if chunk_len == 0 {
            guard core::add_sat_i64(cursor, 2) <= raw_chunked.len else { return 0, ParseStatus.Incomplete; }
            guard raw_chunked[cursor] == '\r' && raw_chunked[core::add_sat_i64(cursor, 1)] == '\n' else {
                return 0, ParseStatus.BadRequest;
            }
            committed = true;
            return core::add_sat_i64(cursor, 2), ParseStatus.Complete;
        }
        let end_data = core::add_sat_i64(cursor, chunk_len);
        let end_chunk = core::add_sat_i64(end_data, 2);
        guard end_chunk <= raw_chunked.len else { return 0, ParseStatus.Incomplete; }
        guard raw_chunked[end_data] == '\r' && raw_chunked[core::add_sat_i64(end_data, 1)] == '\n' else {
            return 0, ParseStatus.BadRequest;
        }
        guard buf_append(out, raw_chunked[cursor..end_data]) else { return 0, ParseStatus.PayloadTooLarge; }
        cursor = end_chunk;
    }
    return 0, ParseStatus.Incomplete;
}

// Parses the HTTP/1.x request line (`METHOD SP target SP HTTP/1.x`) into `req`.
//
// Example:
//   line = "GET /users/42?role=admin HTTP/1.1"
//   returns: true, req.method = "GET", req.path = "/users/42", req.query = "role=admin"
fn parse_request_line(line: const u8[:], req: RequestView&) -> bool {
    let sp1 = core::index_of_byte(line, ' ');
    guard sp1 > 0 else { return false; }
    let method = line[..sp1];
    guard is_valid_token(method) else { return false; }

    let after_m = core::add_sat_i64(sp1, 1);
    let sp2_rel = core::index_of_byte(line[after_m..], ' ');
    guard sp2_rel > 0 else { return false; }
    let sp2 = core::add_sat_i64(after_m, sp2_rel);
    let target = line[after_m..sp2];
    guard is_valid_request_target(target, method) else { return false; }

    let ver = line[core::add_sat_i64(sp2, 1)..];
    guard ver == "HTTP/1.1" || ver == "HTTP/1.0" else { return false; }
    req.method = method;
    req.target = target;
    let path, query, has_q = core::split_once_byte(target, '?');
    req.path = path;
    req.query = if has_q { query } else { "" };
    if ver == "HTTP/1.0" {
        req.flags = req.flags | H1_FLAG_HTTP10;
    }
    return true;
}

// Loops through all header lines inside `wire[start..hdr_end]` and records offset spans into `req`.
//
// Example:
//   wire = "GET / HTTP/1.1\r\nHost: a\r\n\r\n", start = 16, hdr_end = 23
//   returns: ParseStatus.Complete, req.headers.len = 1
fn collect_request_headers(wire: const u8[:], start: i64, hdr_end: i64, req: RequestView&) -> ParseStatus {
    var cursor = start;
    while cursor < hdr_end {
        let rel = core::find_crlf(wire[cursor..hdr_end]);
        let line_end = if rel >= 0 { core::add_sat_i64(cursor, rel) } else { hdr_end };
        let st = record_request_header_line(wire, cursor, line_end, req);
        guard st == ParseStatus.Complete else { return st; }
        if rel < 0 { break; }
        cursor = core::add_sat_i64(line_end, 2);
    }
    return ParseStatus.Complete;
}

// Resolves framed body bounds (chunked or Content-Length) for a parsed request head.
//
// Example:
//   wire = "...\r\n\r\nhello", body_start = 42, req.content_length = 5
//   returns: 47, ParseStatus.Complete, req.body = "hello"
fn resolve_request_body_bounds(wire: const u8[:], body_start: i64, req: RequestView&) -> i64, ParseStatus {
    if (req.flags & H1_FLAG_HAS_TE) != 0 {
        let chunk_consumed, c_st = scan_chunked_framing(wire[body_start..]);
        guard c_st == ParseStatus.Complete else { return 0, c_st; }
        let total = core::add_sat_i64(body_start, chunk_consumed);
        req.body = wire[body_start..total];
        return total, ParseStatus.Complete;
    }
    let total = core::add_sat_i64(body_start, req.content_length);
    guard wire.len >= total else { return 0, ParseStatus.Incomplete; }
    req.body = wire[body_start..total];
    return total, ParseStatus.Complete;
}

// Parses a raw HTTP/1.1 request directly into a zero-copy `RequestView` over `wire` (RFC 9112).
// Returns `(RequestView, bytes_consumed, ParseStatus)`. Zero copies on request path, headers, or body.
//
// Example:
//   wire = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
//   returns: RequestView { method: "GET", path: "/health", .. }, 41, ParseStatus.Complete
fn parse_request_view(wire: const u8[:]) -> RequestView, i64, ParseStatus {
    var empty = RequestView { .. };
    guard wire.len > 0 else { return empty, 0, ParseStatus.Incomplete; }
    let hdr_end = core::fast_find_crlfcrlf(wire);
    if hdr_end < 0 {
        let st = if wire.len > MAX_H1_HEAD_BYTES { ParseStatus.HeadersTooLarge } else { ParseStatus.Incomplete };
        return empty, 0, st;
    }
    let body_start = core::add_sat_i64(hdr_end, 4);
    guard body_start <= MAX_H1_HEAD_BYTES else { return empty, 0, ParseStatus.HeadersTooLarge; }
    let head = wire[..hdr_end];
    guard !has_bare_cr_or_lf(head) else { return empty, 0, ParseStatus.BadRequest; }

    let rl_end = core::find_crlf(head);
    let req_line = if rl_end >= 0 { head[..rl_end] } else { head };
    var req = RequestView { raw: wire, .. };
    guard parse_request_line(req_line, req) else { return empty, 0, ParseStatus.BadRequest; }

    if rl_end >= 0 {
        let hdr_start = core::add_sat_i64(rl_end, 2);
        let h_st = collect_request_headers(wire, hdr_start, hdr_end, req);
        guard h_st == ParseStatus.Complete else { return empty, 0, h_st; }
    }
    // RFC 9112 Section 3.2: Request Target - HTTP/1.1 requests MUST include a Host header field.
    guard (req.flags & H1_FLAG_HTTP10) != 0 || (req.flags & H1_FLAG_HAS_HOST) != 0 else {
        return empty, 0, ParseStatus.BadRequest;
    }
    let total, b_st = resolve_request_body_bounds(wire, body_start, req);
    guard b_st == ParseStatus.Complete else { return empty, 0, b_st; }
    return req, total, ParseStatus.Complete;
}

// ---- Zero-Copy / Stack-Bounded Response Serializer --------------------------

// Resets `res` to a clean `200 OK` state for reuse across pipelined keep-alive requests.
fn reset_response(res: ResponseView&) {
    res.status_code = 200;
    let _ = buf_set(res.content_type, "text/plain");
    res.extra_hdrs.clear();
    res.body = "";
    res.body_buf.clear();
    res.close_conn = false;
}

// Configures `res` with a zero-copy `text/plain` slice (no copy into `body_buf`).
fn set_text_view(res: ResponseView&, status: u16, body_view: const u8[:]) {
    res.status_code = status;
    let _ = buf_set(res.content_type, "text/plain");
    res.body_buf.clear();
    res.body = body_view;
}

// Configures `res` with a zero-copy `application/json` slice (no copy into `body_buf`).
fn set_json_view(res: ResponseView&, status: u16, body_view: const u8[:]) {
    res.status_code = status;
    let _ = buf_set(res.content_type, "application/json");
    res.body_buf.clear();
    res.body = body_view;
}

// Copies a dynamic body into `res.body_buf` with explicit content type and status.
fn set_body_buf(res: ResponseView&, status: u16, content_type: const u8[:], body: const u8[:]) -> bool {
    guard is_valid_field_value(content_type) else { return false; }
    guard content_type.len <= res.content_type.cap && body.len <= res.body_buf.cap else { return false; }
    res.status_code = status;
    let _ = buf_set(res.content_type, content_type);
    res.body = "";
    let _ = buf_set(res.body_buf, body);
    return true;
}

// Appends a dynamic chunk to `res.body_buf` (clears zero-copy `res.body` view).
fn write_body(res: ResponseView&, chunk: const u8[:]) -> bool {
    res.body = "";
    return buf_append(res.body_buf, chunk);
}

// Appends a validated header line (`Name: Value\r\n`) to `res.extra_hdrs`. Rolls back on overflow.
fn add_header(res: ResponseView&, name: const u8[:], val: const u8[:]) -> bool {
    guard is_valid_token(name) && is_valid_field_value(val) else { return false; }
    let saved_len = res.extra_hdrs.len;
    var committed = false;
    defer if !committed { res.extra_hdrs.resize(saved_len); };
    guard buf_append(res.extra_hdrs, name) &&
          buf_append(res.extra_hdrs, ": ") &&
          buf_append(res.extra_hdrs, val) &&
          buf_append(res.extra_hdrs, "\r\n") else {
        return false;
    }
    committed = true;
    return true;
}

// RFC 9110 Section 15: Status Codes - canonical reason phrase lookup.
fn status_phrase(code: u16) -> const u8[:] {
    return match code {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
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
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
}

// RFC 9112 Section 6.3: Message Body Length - 1xx, 204, and 304 responses never carry a body.
inline fn is_empty_body_status(code: u16) -> bool {
    return (code >= 100 && code < 200) || code == 204 || code == 304;
}

inline fn active_response_body(res: const ResponseView&) -> const u8[:] {
    return if res.body.len > 0 { res.body } else { res.body_buf[..] };
}

// Serializes an HTTP/1.1 response status line and headers into `out` (RFC 9112 Section 4).
// Rolls back `out` on capacity overflow.
//
// Example:
//   res = ResponseView { status_code: 200, body: "ok", .. }, is_head_req = false
//   returns: true, out appended with "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n..."
fn serialize_response_head<B>(res: const ResponseView&, is_head_req: bool, out: B&) -> bool {
    guard res.status_code >= 100 && res.status_code <= 599 else { return false; }
    let _ = is_head_req;
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    var code_buf: u8[..8] = [];
    core::format_u64_dec(res.status_code as u64, code_buf);
    guard buf_append(out, "HTTP/1.1 ") &&
          buf_append(out, code_buf[..]) &&
          buf_append(out, " ") &&
          buf_append(out, status_phrase(res.status_code)) &&
          buf_append(out, "\r\n") else {
        return false;
    }

    if res.content_type.len > 0 {
        guard buf_append(out, "Content-Type: ") &&
              buf_append(out, res.content_type[..]) &&
              buf_append(out, "\r\n") else {
            return false;
        }
    }

    let body = active_response_body(res);
    if !is_empty_body_status(res.status_code) {
        var cl_buf: u8[..24] = [];
        core::format_i64_dec(body.len, cl_buf);
        guard buf_append(out, "Content-Length: ") &&
              buf_append(out, cl_buf[..]) &&
              buf_append(out, "\r\n") else {
            return false;
        }
    }

    let conn_hdr = if res.close_conn { "Connection: close\r\n" } else { "Connection: keep-alive\r\n" };
    guard buf_append(out, conn_hdr) &&
          buf_append(out, res.extra_hdrs[..]) &&
          buf_append(out, "\r\n") else {
        return false;
    }
    committed = true;
    return true;
}

// Serializes the full HTTP/1.1 response (head + body) into `out`, omitting body on HEAD or 1xx/204/304.
// Rolls back `out` on capacity overflow.
//
// Example:
//   res = ResponseView { status_code: 200, body: "pong", .. }, is_head_req = false
//   returns: true, out ends with "\r\n\r\npong"
fn serialize_response<B>(res: const ResponseView&, is_head_req: bool, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard serialize_response_head(res, is_head_req, out) else { return false; }
    if !is_head_req && !is_empty_body_status(res.status_code) {
        let body = active_response_body(res);
        guard buf_append(out, body) else { return false; }
    }
    committed = true;
    return true;
}

// Transmits `res` over `s` via single-syscall vectored send (`send2`), avoiding body copy.
fn send_response_vectored(s: TcpStream&, res: const ResponseView&, is_head_req: bool) -> bool {
    var head_buf: u8[..1024] = [];
    guard serialize_response_head(res, is_head_req, head_buf) else { return false; }
    if is_head_req || is_empty_body_status(res.status_code) {
        return send_all(s, head_buf[..]);
    }
    let body = active_response_body(res);
    if body.len == 0 {
        return send_all(s, head_buf[..]);
    }
    let sent = send2(s, head_buf[..], body);
    let total = core::add_sat_i64(head_buf.len, body.len);
    if sent == (total as i32) {
        return true;
    }
    guard sent > 0 else { return false; }
    let sent_i = sent as i64;
    if sent_i < head_buf.len {
        return send_all(s, head_buf[sent_i..]) && send_all(s, body);
    }
    let body_off = core::sub_sat_i64(sent_i, head_buf.len);
    return send_all(s, body[body_off..]);
}
