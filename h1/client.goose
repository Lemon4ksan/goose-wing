// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Minimal zero-copy HTTP/1.1 client wire encoder and response parser (RFC 9112).
// Operates over any `<Io>` stream (`TcpStream` or `MemoryStream`) without TLS/H2/H3/cookie bloat.
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
import .wire;

// ~640-byte zero-copy view over a parsed HTTP/1.1 response inside a caller receive buffer.
struct ResponseHeadView {
    raw:            const u8[:]       = "",
    status_code:    u16               = 0,
    headers:        HeaderSlice[..64] = [],
    body:           const u8[:]       = "",
    content_length: i64               = 0,
    flags:          u16               = 0,
}

// Looks up the first response header matching `name` (case-insensitive) as a zero-copy slice.
fn header(res: const ResponseHeadView&, name: const u8[:]) -> const u8[:] {
    for i in res.headers.len {
        let hs = res.headers[i];
        if core::eq_ascii_fold(header_slice_name(res.raw, hs), name) {
            return header_slice_val(res.raw, hs);
        }
    }
    return "";
}

// Serializes an HTTP/1.1 client request into `out` (RFC 9112 Section 3).
// Rejects CRLF injection and rolls back `out` on capacity overflow.
//
// Example:
//   encode_client_request("GET", "/health", "127.0.0.1", "", "", out)
//   returns: true, out = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
fn encode_client_request<B>(
    method:     const u8[:],
    target:     const u8[:],
    host:       const u8[:],
    extra_hdrs: const u8[:],
    body:       const u8[:],
    out:        B&,
) -> bool {
    let eff_target = if target.len > 0 { target } else { "/" };
    guard is_valid_token(method) &&
          is_valid_request_target(eff_target, method) &&
          host.len > 0 &&
          is_valid_field_value(host) &&
          !has_bare_cr_or_lf(extra_hdrs) else {
        return false;
    }

    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    guard buf_append(out, method) &&
          buf_append(out, " ") &&
          buf_append(out, eff_target) &&
          buf_append(out, " HTTP/1.1\r\nHost: ") &&
          buf_append(out, host) &&
          buf_append(out, "\r\n") else {
        return false;
    }

    if body.len > 0 {
        var cl_buf: u8[..24] = [];
        core::format_i64_dec(body.len, cl_buf);
        guard buf_append(out, "Content-Length: ") &&
              buf_append(out, cl_buf[..]) &&
              buf_append(out, "\r\n") else {
            return false;
        }
    }

    guard buf_append(out, extra_hdrs) &&
          buf_append(out, "\r\n") &&
          buf_append(out, body) else {
        return false;
    }
    committed = true;
    return true;
}

// Parses an HTTP/1.x status line (`HTTP/1.x NNN reason`) into `res`.
//
// Example:
//   line = "HTTP/1.1 200 OK"
//   returns: true, res.status_code = 200
fn parse_status_line(line: const u8[:], res: ResponseHeadView&) -> bool {
    guard line.len >= 12 else { return false; }
    let ver, rest, has_sp1 = core::split_once_byte(line, ' ');
    guard has_sp1 && (ver == "HTTP/1.1" || ver == "HTTP/1.0") else { return false; }
    let code_str, reason, has_sp2 = core::split_once_byte(rest, ' ');
    let sc_part = if has_sp2 { code_str } else { rest };
    guard sc_part.len == 3 else { return false; }
    let sc, ok_sc = core::parse_u32_dec(sc_part);
    guard ok_sc && sc >= 100 && sc <= 599 else { return false; }
    if has_sp2 {
        guard is_valid_field_value(reason) else { return false; }
    }
    res.status_code = sc as u16;
    if ver == "HTTP/1.0" {
        res.flags = res.flags | H1_FLAG_HTTP10;
    }
    return true;
}

fn record_response_header_line(
    wire:       const u8[:],
    line_start: i64,
    line_end:   i64,
    res:        ResponseHeadView&,
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
    guard buf_push(res.headers, hs) else { return ParseStatus.HeadersTooLarge; }
    return apply_response_framing_header(name, trimmed, res);
}

fn apply_response_framing_header(name: const u8[:], val: const u8[:], res: ResponseHeadView&) -> ParseStatus {
    if core::eq_ascii_fold(name, "content-length") {
        return apply_content_length_header(val, res.flags, res.content_length);
    }
    if core::eq_ascii_fold(name, "transfer-encoding") {
        return apply_transfer_encoding_header(val, res.flags);
    }
    if core::eq_ascii_fold(name, "connection") && header_value_has_token(val, "close") {
        res.flags = res.flags | H1_FLAG_CONN_CLOSE;
    }
    return ParseStatus.Complete;
}

// Loops through all response header lines inside `wire[start..hdr_end]` and records offset spans into `res`.
//
// Example:
//   wire = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", start = 17, hdr_end = 34
//   returns: ParseStatus.Complete, res.headers.len = 1
fn collect_response_headers(wire: const u8[:], start: i64, hdr_end: i64, res: ResponseHeadView&) -> ParseStatus {
    var cursor = start;
    while cursor < hdr_end {
        let rel = core::find_crlf(wire[cursor..hdr_end]);
        let line_end = if rel >= 0 { core::add_sat_i64(cursor, rel) } else { hdr_end };
        let st = record_response_header_line(wire, cursor, line_end, res);
        guard st == ParseStatus.Complete else { return st; }
        if rel < 0 { break; }
        cursor = core::add_sat_i64(line_end, 2);
    }
    return ParseStatus.Complete;
}

// Resolves response body framing bounds (empty-body status, chunked, Content-Length, or EOF).
fn resolve_response_body_bounds(
    wire:        const u8[:],
    body_start:  i64,
    is_head_req: bool,
    res:         ResponseHeadView&,
) -> i64, ParseStatus {
    if is_head_req || is_empty_body_status(res.status_code) {
        return body_start, ParseStatus.Complete;
    }
    if (res.flags & H1_FLAG_HAS_TE) != 0 {
        let chunk_consumed, c_st = scan_chunked_framing(wire[body_start..]);
        guard c_st == ParseStatus.Complete else { return 0, c_st; }
        let total = core::add_sat_i64(body_start, chunk_consumed);
        res.body = wire[body_start..total];
        return total, ParseStatus.Complete;
    }
    if (res.flags & H1_FLAG_HAS_CL) != 0 {
        let total = core::add_sat_i64(body_start, res.content_length);
        guard wire.len >= total else { return 0, ParseStatus.Incomplete; }
        res.body = wire[body_start..total];
        return total, ParseStatus.Complete;
    }
    res.body = wire[body_start..];
    return wire.len, ParseStatus.Complete;
}

// Parses a raw HTTP/1.1 wire response into a zero-copy `ResponseHeadView` over `wire` (RFC 9112).
// Returns `(ResponseHeadView, bytes_consumed, ParseStatus)`.
//
// Example:
//   wire = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong", is_head_req = false
//   returns: ResponseHeadView { status_code: 200, body: "pong", .. }, 42, ParseStatus.Complete
fn parse_response_view(wire: const u8[:], is_head_req: bool) -> ResponseHeadView, i64, ParseStatus {
    var empty = ResponseHeadView { .. };
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

    let sl_end = core::find_crlf(head);
    let status_line = if sl_end >= 0 { head[..sl_end] } else { head };
    var res = ResponseHeadView { raw: wire, .. };
    guard parse_status_line(status_line, res) else { return empty, 0, ParseStatus.BadRequest; }

    if sl_end >= 0 {
        let hdr_start = core::add_sat_i64(sl_end, 2);
        let h_st = collect_response_headers(wire, hdr_start, hdr_end, res);
        guard h_st == ParseStatus.Complete else { return empty, 0, h_st; }
    }
    let total, b_st = resolve_response_body_bounds(wire, body_start, is_head_req, res);
    guard b_st == ParseStatus.Complete else { return empty, 0, b_st; }
    return res, total, ParseStatus.Complete;
}

// Executes one zero-copy HTTP/1.1 client exchange over `<Io>`, storing raw bytes in `rx_buf`.
// Returned `ResponseHeadView` slices borrow directly from `rx_buf`.
fn exchange_stream<Io, RxBuf>(
    io:         Io&,
    method:     const u8[:],
    target:     const u8[:],
    host:       const u8[:],
    extra_hdrs: const u8[:],
    req_body:   const u8[:],
    rx_buf:     RxBuf&,
    timeout_ms: u32 = 5000,
) -> ResponseHeadView, bool {
    var empty = ResponseHeadView { .. };
    var tx_buf: u8[..4096] = [];
    guard encode_client_request(method, target, host, extra_hdrs, req_body, tx_buf) else {
        return empty, false;
    }
    guard send_all(io, tx_buf[..]) else { return empty, false; }

    rx_buf.clear();
    let is_head = method == "HEAD";
    var chunk: u8[1024] = [0; 1024];
    loop {
        let recvd = io.recv_slice(chunk[..], timeout_ms);
        if recvd <= 0 {
            if rx_buf.len == 0 { return empty, false; }
            let res, _, st = parse_response_view(rx_buf[..], is_head);
            return res, st == ParseStatus.Complete;
        }
        guard buf_append(rx_buf, chunk[..recvd]) else { return empty, false; }
        let res, _, st = parse_response_view(rx_buf[..], is_head);
        if st == ParseStatus.Complete {
            return res, true;
        }
        if st != ParseStatus.Incomplete {
            return empty, false;
        }
    }
    return empty, false;
}
