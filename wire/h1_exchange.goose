// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// wire/h1_exchange.goose
// Zero-allocation HTTP/1.1 exchange engine over PooledConnection with
// HeaderSpan zero-copy parsing and chunked transfer decoding.
namespace wing;

import std;
import core;
import http.response;
import http.request;
import net.pool;
import net.slowloris;
import net.transport;
import http.headers;
import .h1;

// ---- 1. Request Serialization ----------------------------------------------

fn format_request_target(
    req:     const Request&,
    url_val: const core::Url&,
    out:     u8[..4096]&,
) -> bool {
    if req.method == "CONNECT" {
        var host_buf: u8[..280] = [];
        core::format_outgoing_host(url_val, host_buf);
        guard host_buf.len > 0 else { return false; }
        return out.try_append(host_buf[..]);
    }
    let p = url_val.pathname();
    if p.len == 0 {
        guard out.try_append("/") else { return false; }
    } else {
        guard out.try_append(p) else { return false; }
    }
    let q = url_val.search();
    if q.len > 0 {
        guard out.try_append(q) else { return false; }
    }
    return true;
}

fn serialize_h1_request(
    req:     const Request&,
    url_val: const core::Url&,
    out:     u8[..4096]&,
) -> bool {
    var committed = false;
    defer if !committed { out.clear(); };
    var target_buf: u8[..4096] = [];
    guard format_request_target(req, url_val, target_buf) else { return false; }
    let has_cl = req.header("Content-Length").len > 0;
    let has_te = req.header("Transfer-Encoding").len > 0;
    guard !(req.method[..].eq_ascii_fold("TRACE") && (req.body.len > 0 || has_cl || has_te)) else {
        return false;
    }
    if has_cl {
        let cl_val, ok_cl = http::validate_content_length_value(req.header("Content-Length"));
        guard ok_cl && cl_val == req.body.len else { return false; }
    }
    let needs_zero_cl = req.method[..].eq_ascii_fold(rfc::METHOD_POST) || req.method[..].eq_ascii_fold(rfc::METHOD_PUT);
    var hdrs = req.headers;
    if !has_cl && !has_te && (req.body.len > 0 || needs_zero_cl) {
        var cl_buf: u8[..32] = [];
        req.body.len.format_i64_dec(cl_buf);
        guard http::append_header(hdrs, "Content-Length", cl_buf[..]) else { return false; }
    }
    var host_buf: u8[..280] = [];
    core::format_outgoing_host(url_val, host_buf);
    guard host_buf.len > 0 else { return false; }
    out.clear();
    guard wire::encode_h1_request(
        req.method[..],
        target_buf[..],
        host_buf[..],
        hdrs,
        "",
        wire::H1HeaderFilterMode.PreserveAll,
        out,
    ) else { return false; }
    committed = true;
    return true;
}

// ---- 3. Response Status and Header Parsing ----------------------------------

// Parses 3-digit ASCII status code string into numeric integer (RFC 9112 §4, RFC 9110 §15).
//
// Example:
//   status_str = "200"
//   returns: 200
fn parse_h1_status_code(status_str: const u8[:]) -> i32 {
    guard status_str.len == 3 else { return 0; }
    let val, ok = status_str.parse_u32_dec();
    guard ok && val >= 100 && val <= 599 else { return 0; }
    return val as i32;
}

inline fn is_valid_h1_reason_phrase(reason: const u8[:]) -> bool {
    for b in reason {
        let ok = b == '\t' || b == ' ' || (b >= 0x21 && b != 0x7F);
        guard ok else { return false; }
    }
    return true;
}

// Parses HTTP/1.1 status line: `HTTP/1.1 <status> <reason>\r\n` (RFC 9112 §4).
// Populates resp.protocol and resp.status_code.
//
// Example:
//   line = "HTTP/1.1 200 OK"
//   returns: ok = true, resp.status_code = 200, resp.protocol = "HTTP/1.1"
fn parse_h1_status_line(
    line: const u8[:],
    resp: Response&,
) -> bool {
    guard starts_with(line, "HTTP/1.1 ") || starts_with(line, "HTTP/1.0 ") else { return false; }
    guard line.len >= 12 && (line.len == 12 || line[12] == ' ') else { return false; }
    if line.len > 13 {
        guard is_valid_h1_reason_phrase(line[13..]) else { return false; }
    }

    let code = parse_h1_status_code(line[9..12]);
    guard code >= 100 && code <= 599 else { return false; }
    guard resp.protocol.try_set(line[..8]) else { return false; }
    resp.status_code = code;
    return true;
}

// Strips Content-Length if Transfer-Encoding is present to prevent HTTP desync (RFC 9112 §6.1).
//
// Example:
//   resp.headers = [("Transfer-Encoding", "chunked"), ("Content-Length", "10")]
//   returns: Content-Length removed from headers
fn strip_conflicting_content_length(resp: Response&) {
    guard http::has_header(resp.headers, "Transfer-Encoding") && http::has_header(resp.headers, "Content-Length") else {
        return;
    }
    resp.had_te_cl_conflict = true;
    http::remove_header_by_name(resp.headers, "content-length");
    resp.presence_mask = resp.presence_mask & (~http::RES_PRESENCE_CONTENT_LENGTH);
}

inline fn split_next_strict_crlf_line(hb: const u8[:], offset: i64&) -> const u8[:], bool {
    let rem = hb[offset..];
    let rel_nl = rem.index_of_byte('\n');
    if rel_nl < 0 {
        offset = hb.len;
        guard rem.len > 0 && !rem.contains_byte('\r') else { return "", false; }
        return rem, true;
    }
    let cr_idx = core::sub_sat_i64(rel_nl, 1);
    guard rel_nl >= 2 && rem[cr_idx] == '\r' else { return "", false; }
    let line = rem[..cr_idx];
    offset = core::add_sat_i64(offset, core::add_sat_i64(rel_nl, 1));
    guard !line.contains_byte('\r') else { return "", false; }
    return line, true;
}

// Example:
//   header_bytes = "Content-Type: text/plain\r\nContent-Length: 5\r\n"
//   returns: ok = true, resp.headers.entries.len = 2
fn parse_h1_header_block(
    header_bytes: const u8[:],
    resp:         Response&,
) -> bool {
    resp.headers.clear();
    resp.presence_mask = 0;
    resp.had_te_cl_conflict = false;

    let hb = if core::ends_with(header_bytes, "\r\n") { header_bytes[..^2] } else { header_bytes };
    var offset: i64 = 0;
    while offset < hb.len {
        let line, line_ok = split_next_strict_crlf_line(hb, offset);
        guard line_ok else { return false; }
        let col = line.index_of_byte(':');
        guard col > 0 else { return false; }

        let hname = line[..col];
        let raw_val = line[(col + 1)..];
        let v_lead = raw_val.trim_lws_start();
        let v_trim = v_lead.trim_lws_end();
        let lead_spaces = raw_val.len - v_lead.len;
        let v_start = col + 1 + lead_spaces;
        let v_len = v_trim.len;
        let hval = line[v_start..(v_start + v_len)];

        guard http::is_valid_header_name(hname) && http::is_valid_header_value(hval) else { return false; }
        if hname.eq_ascii_fold("content-length") {
            let cl_u, cl_ok = hval.parse_u64_dec();
            let prev_cl = http::header(resp, "Content-Length");
            guard cl_ok && cl_u <= 0x7FFFFFFFFFFFFFFF && (prev_cl.len == 0 || prev_cl == hval) else {
                return false;
            }
        }
        guard http::append_header(resp.headers, hname, hval) else { return false; }
        http::update_response_presence(resp, hname);
    }
    strip_conflicting_content_length(resp);
    return true;
}

// Splits response header block into status line and headers, parsing both into resp.
//
// Example:
//   header_block = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
//   returns: ok = true, resp.status_code = 200
fn parse_response_headers(header_block: const u8[:], resp: Response&) -> bool {
    let trimmed_4, had_4 = header_block.strip_suffix("\r\n\r\n");
    let raw_block = if had_4 {
        trimmed_4
    } else {
        let trimmed_2, had_2 = header_block.strip_suffix("\r\n");
        if had_2 { trimmed_2 } else { header_block }
    };
    let status_cr, headers_part, has_lf = raw_block.split_once_byte('\n');
    if !has_lf {
        guard !raw_block.contains_byte('\r') else { return false; }
        resp.headers.clear();
        resp.presence_mask = 0;
        resp.had_te_cl_conflict = false;
        return parse_h1_status_line(raw_block, resp);
    }
    let status_line, has_cr = status_cr.strip_suffix("\r");
    guard has_cr && status_line.len >= 12 && !status_line.contains_byte('\r') else { return false; }
    guard parse_h1_status_line(status_line, resp) && headers_part.len > 0 else { return false; }
    return parse_h1_header_block(headers_part, resp);
}

// ---- 4. Body Streaming Pumps ------------------------------------------------

fn pump_h1_fixed_body(
    conn:       net::PooledConnection&,
    bytes_left: u64&,
    resp:       Response&,
    timeout_ms: u32,
) -> bool {
    var raw_chunk: u8[4096] = [0; 4096];
    while bytes_left > 0 {
        let chunk_cap: u64 = 4096;
        let to_read_u64 = min(bytes_left, chunk_cap);
        let to_read = to_read_u64 as i64;
        let recvd = conn.transport.recv_slice(raw_chunk[..to_read], timeout_ms);
        guard recvd > 0 else { return false; }
        resp.body.append(raw_chunk[..recvd]);
        let recvd_u64 = recvd as u64;
        bytes_left = if bytes_left > recvd_u64 { bytes_left - recvd_u64 } else { 0 };
    }
    return true;
}

inline fn record_chunk_trailers(
    is_trailer_mode: bool,
    consumed:        i64,
    remaining:       const u8[:],
    trailer_buf:     u8[..4096]&,
) -> bool {
    guard is_trailer_mode && consumed > 0 else { return true; }
    return trailer_buf.try_append(remaining[..consumed]);
}

fn feed_chunk_slice(
    dec:         http_internal::ChunkFsmDecoder&,
    buf:         const u8[:],
    resp:        Response&,
    trailer_buf: u8[..4096]&,
    out_cursor:  i64&,
) -> bool, bool {
    out_cursor = 0;
    while out_cursor < buf.len {
        let is_tr = (dec.state & 0x1000000000000000) != 0;
        let remaining = buf[out_cursor..];
        let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, remaining);
        if is_tr {
            guard record_chunk_trailers(true, consumed, remaining, trailer_buf) else { return true, false; }
        } else if dec.last_trailer_start >= 0 && dec.last_trailer_start < consumed {
            let tr_slice = remaining[dec.last_trailer_start..consumed];
            guard record_chunk_trailers(true, tr_slice.len, tr_slice, trailer_buf) else { return true, false; }
        }
        out_cursor += consumed;
        if chunk.len > 0 {
            resp.body.append(chunk);
        }
        if st == http_internal::ChunkFsmStatus.Complete {
            if trailer_buf.len > 0 {
                var tr_cur: i64 = 0;
                let tr_err = http::parse_chunked_trailers_with_out(trailer_buf[..], tr_cur, resp.trailers);
                guard tr_err == http::ChunkedDecodeError.None else { return true, false; }
            }
            return true, true;
        }
        if st == http_internal::ChunkFsmStatus.Error {
            return true, false;
        }
    }
    return false, true;
}

fn pump_h1_chunked_body(
    conn:       net::PooledConnection&,
    dec:        http_internal::ChunkFsmDecoder&,
    leftover:   const u8[:],
    resp:       Response&,
    timeout_ms: u32,
) -> bool {
    var trailer_buf:  u8[..4096] = [];
    var consumed_cur: i64        = 0;
    if leftover.len > 0 {
        let done, ok = feed_chunk_slice(dec, leftover, resp, trailer_buf, consumed_cur);
        if done {
            if ok && consumed_cur < leftover.len {
                guard conn.rx_buf.try_append(leftover[consumed_cur..]) else { return false; }
            }
            return ok;
        }
    }

    var wire_buf: u8[4096] = [0; 4096];
    loop {
        let recvd = conn.transport.recv_slice(wire_buf[..], timeout_ms);
        guard recvd > 0 else { return false; }
        let done, ok = feed_chunk_slice(dec, wire_buf[..recvd], resp, trailer_buf, consumed_cur);
        if done {
            if ok && consumed_cur < recvd {
                guard conn.rx_buf.try_append(wire_buf[consumed_cur..recvd]) else { return false; }
            }
            return ok;
        }
    }
    return true;
}

// ---- 5. Top-Level Exchange Execution ----------------------------------------

// Sends an entire buffer across transport, retrying until complete or error.
//
// Example:
//   buf = "GET / HTTP/1.1\r\n\r\n"
//   returns: true
fn send_all(trans: net::Transport&, buf: const u8[:]) -> bool {
    var sent_total: i64 = 0;
    while sent_total < buf.len {
        let sent = trans.send(buf[sent_total..]);
        guard sent > 0 else { return false; }
        sent_total += sent;
    }
    return true;
}

fn send_h1_request(
    conn:    net::PooledConnection&,
    req:     const Request&,
    url_val: const core::Url&,
) -> bool {
    var req_wire: u8[..4096] = [];
    guard serialize_h1_request(req, url_val, req_wire) else { return false; }
    guard send_all(conn.transport, req_wire[..]) else { return false; }

    if client::header_has_token(req.header("Transfer-Encoding"), "chunked") && !req.body_prechunked {
        var chunk_wire: u8[>..] = [];
        guard client::encode_chunked_payload(req.body[..], req.trailers, 4096, chunk_wire) else {
            return false;
        }
        return send_all(conn.transport, chunk_wire[..]);
    }
    if req.body.len > 0 {
        guard send_all(conn.transport, req.body[..]) else { return false; }
    }
    return true;
}

inline fn feed_h1_header_guard(
    guard_reader: net::HeaderReader&,
    rx_buf:       const u8[:],
    from_idx:     i64,
    hdr_end_idx:  i64,
    now_ns:       i64,
) -> bool {
    let inspect_end = if hdr_end_idx >= 0 { hdr_end_idx + 4 } else { rx_buf.len };
    guard inspect_end > from_idx else { return true; }
    return net::feed_header_bytes(guard_reader, rx_buf[from_idx..inspect_end], now_ns) == net::SlowlorisViolation.None;
}

fn read_response_headers_into<B>(conn: net::PooledConnection&, dst: B&, timeout_ms: u32) -> i64, bool {
    let start_ns = (core::as_nanos(core::monotonic_now()) & 0x7FFFFFFFFFFFFFFF) as i64;
    let hdr_timeout_ns = max(10000000000, (timeout_ms as i64) * 1000000);
    var guard_reader = net::new_header_reader(
        net::SlowlorisDefenseConfig { response_header_timeout_ns: hdr_timeout_ns, .. },
        start_ns,
    );
    var hdr_end_idx: i64 = core::fast_find_crlfcrlf(dst[..]);
    guard feed_h1_header_guard(guard_reader, dst[..], 0, hdr_end_idx, start_ns) else {
        return 0, false;
    }

    var raw_recv: u8[4096] = [0; 4096];
    while hdr_end_idx < 0 {
        let prev_len = dst.len;
        let recvd = conn.transport.recv_slice(raw_recv[..], timeout_ms);
        guard recvd > 0 else { return 0, false; }
        guard dst.try_append(raw_recv[..recvd]) else { return 0, false; }
        hdr_end_idx = core::fast_find_crlfcrlf(dst[..]);
        let now_ns = (core::as_nanos(core::monotonic_now()) & 0x7FFFFFFFFFFFFFFF) as i64;
        guard feed_h1_header_guard(guard_reader, dst[..], prev_len, hdr_end_idx, now_ns) else {
            return 0, false;
        }
    }
    return hdr_end_idx, true;
}

fn read_response_headers(conn: net::PooledConnection&, timeout_ms: u32) -> i64, bool {
    return read_response_headers_into(conn, conn.rx_buf, timeout_ms);
}

fn pump_cl_body(
    conn:       net::PooledConnection&,
    resp:       Response&,
    leftover:   const u8[:],
    cl_str:     const u8[:],
    timeout_ms: u32,
) -> bool {
    let cl_val, ok_cl = cl_str.parse_u64_dec();
    guard ok_cl && cl_val <= 0x7FFFFFFFFFFFFFFF else { return false; }

    let init_bytes = min(leftover.len, cl_val as i64);
    if init_bytes > 0 {
        resp.body.append(leftover[..init_bytes]);
    }
    if leftover.len > init_bytes {
        guard conn.rx_buf.try_append(leftover[init_bytes..]) else { return false; }
    }
    let init_u64 = init_bytes as u64;
    var remaining_cl = if cl_val > init_u64 { cl_val - init_u64 } else { 0 };
    return pump_h1_fixed_body(conn, remaining_cl, resp, timeout_ms);
}

// RFC 9112 Section 6.3: Message Body Length - 204 and 304 responses are always terminated by the
// first empty line after headers; if a non-HEAD 204/304 carries non-zero Content-Length or
// Transfer-Encoding, the connection MUST NOT be reused to prevent response smuggling.
fn has_rogue_empty_status_framing(method: const u8[:], status: i32, headers: const HeaderMap&) -> bool {
    guard !method.eq_ascii_fold("HEAD") && (status == 204 || status == 304) else { return false; }
    if http::has_header(headers, "Transfer-Encoding") {
        return true;
    }
    let cl = http::get_header(headers, "Content-Length").trim_lws();
    guard cl.len > 0 else { return false; }
    let cl_val, ok_cl = cl.parse_u64_dec();
    return !ok_cl || cl_val > 0;
}

fn headers_have_connection_token(headers: const HeaderMap&, token: const u8[:]) -> bool {
    for &hdr in headers.entries {
        if http::entry_name(headers, hdr).eq_ascii_fold("connection") {
            if client::header_has_token(http::entry_value(headers, hdr), token) {
                return true;
            }
        }
    }
    return false;
}

fn collect_h1_response_te(headers: const HeaderMap&, out_te: u8[..256]&) -> bool {
    out_te.clear();
    var committed = false;
    defer if !committed { out_te.clear(); };
    for &hdr in headers.entries {
        if http::entry_name(headers, hdr).eq_ascii_fold("transfer-encoding") {
            let val = http::entry_value(headers, hdr).trim_lws();
            guard val.len > 0 else { return false; }
            if out_te.len > 0 {
                guard out_te.try_append(", ") else { return false; }
            }
            guard out_te.try_append(val) else { return false; }
        }
    }
    committed = true;
    return out_te.len > 0;
}

// Classifies a non-empty Transfer-Encoding header (RFC 9112 Section 6.1 & Section 6.3):
// returns `0` on invalid syntax or duplicate `chunked`, `1` when `chunked` is the final coding,
// and `2` when `chunked` is not final (requires close-delimited EOF framing).
fn classify_h1_transfer_encoding(te: const u8[:]) -> i32 {
    let trimmed = te.trim_lws();
    guard trimmed.len > 0 && !core::starts_with(trimmed, ",") && !core::ends_with(trimmed, ",") else {
        return 0;
    }
    var rem = trimmed;
    var seen_chunked: bool = false;
    var last_chunked: bool = false;
    while rem.len > 0 {
        let head, tail, has_comma = rem.split_once_unquoted_byte(',');
        let piece = head.trim_lws();
        guard piece.len > 0 && http::is_valid_transfer_coding(piece) else { return 0; }
        let tok_raw, _, has_semi = piece.split_once_unquoted_byte(';');
        let tok = tok_raw.trim_lws();
        last_chunked = tok.eq_ascii_fold("chunked");
        if last_chunked {
            guard !has_semi && !seen_chunked else { return 0; }
            seen_chunked = true;
        }
        if !has_comma { break; }
        rem = tail;
    }
    return if last_chunked { 1 } else { 2 };
}

fn pump_eof_response_body(
    conn:       net::PooledConnection&,
    resp:       Response&,
    leftover:   const u8[:],
    timeout_ms: u32,
) -> bool {
    if leftover.len > 0 {
        resp.body.append(leftover);
    }
    var raw_recv: u8[4096] = [0; 4096];
    loop {
        let recvd = conn.transport.recv_slice(raw_recv[..], timeout_ms);
        if recvd == 0 { return true; }
        guard recvd > 0 && recvd <= raw_recv.len else { return false; }
        resp.body.append(raw_recv[..recvd]);
    }
    return false;
}

fn pump_response_body(
    conn:       net::PooledConnection&,
    req:        const Request&,
    resp:       Response&,
    leftover:   const u8[:],
    timeout_ms: u32,
) -> bool, bool {
    let is_conn_close = headers_have_connection_token(resp.headers, "close") ||
        headers_have_connection_token(req.headers, "close");
    let keep_alive = !is_conn_close && !resp.had_te_cl_conflict &&
        (resp.protocol == "HTTP/1.1" || resp.protocol == "h1");

    let is_upgrade = resp.status_code == rfc::STATUS_SWITCHING_PROTOCOLS;
    if is_upgrade {
        let req_upgrades = headers_have_connection_token(req.headers, "upgrade") &&
            req.headers.find_header("Upgrade").trim_lws().len > 0;
        guard req_upgrades else { return false, false; }
    }
    let is_connect_2xx = req.method[..].eq_ascii_fold("CONNECT") &&
        resp.status_code >= rfc::STATUS_OK && resp.status_code < 300;
    if req.method[..].eq_ascii_fold("HEAD") || is_connect_2xx || is_upgrade ||
        rfc::is_empty_body_status(resp.status_code) {
        let status = resp.status_code;
        if status == 204 || status == 304 {
            let ok_ka = keep_alive && !has_rogue_empty_status_framing(req.method[..], status, resp.headers);
            let appended = !ok_ka || leftover.len == 0 || conn.rx_buf.try_append(leftover);
            return true, ok_ka && appended;
        }
        // RFC 9110 §9.3.6 / §15.2.2: 101 Switching Protocols and CONNECT 2xx leave HTTP/1.1 framing.
        let eff_keep_alive = keep_alive && !is_upgrade && !is_connect_2xx;
        let can_preserve = eff_keep_alive || is_upgrade || is_connect_2xx;
        if can_preserve && leftover.len > 0 {
            guard conn.rx_buf.try_append(leftover) else { return false, false; }
        }
        return true, eff_keep_alive;
    }

    if http::has_header(resp.headers, "Transfer-Encoding") {
        guard resp.protocol != "HTTP/1.0" else { return false, false; }
        var te_combined: u8[..256] = [];
        guard collect_h1_response_te(resp.headers, te_combined) else { return false, false; }
        let te_mode = classify_h1_transfer_encoding(te_combined[..]);
        guard te_mode != 0 else { return false, false; }
        if te_mode == 1 {
            var dec = http_internal::new_chunk_fsm_decoder();
            let ok_chunk = pump_h1_chunked_body(conn, dec, leftover, resp, timeout_ms);
            if ok_chunk {
                http::remove_header_by_name(resp.headers, "transfer-encoding");
                resp.presence_mask = resp.presence_mask & (~http::RES_PRESENCE_TRANSFER_ENCODING);
            }
            return ok_chunk, keep_alive;
        }
        return pump_eof_response_body(conn, resp, leftover, timeout_ms), false;
    }

    let cl_str = resp.header("Content-Length");
    if cl_str.len > 0 {
        let ok_fixed = pump_cl_body(conn, resp, leftover, cl_str, timeout_ms);
        return ok_fixed, keep_alive;
    }

    return pump_eof_response_body(conn, resp, leftover, timeout_ms), false;
}

// Executes an end-to-end HTTP/1.1 exchange over a pooled connection with zero heap allocation.
fn execute_h1_exchange(
    conn:       net::PooledConnection&,
    req:        const Request&,
    url_val:    const core::Url&,
    resp:       Response&,
    timeout_ms: u32 = 5000,
) -> bool, bool {
    http::reset_response(resp);
    guard send_h1_request(conn, req, url_val) else { return false, false; }

    var hdr_buf: u8[..16384] = [];
    if conn.rx_buf.len > 0 {
        guard hdr_buf.try_append(conn.rx_buf[..]) else { return false, false; }
        conn.rx_buf.clear();
    }

    for interim_step in 6 {
        let hdr_end_idx, ok_hdr = read_response_headers_into(conn, hdr_buf, timeout_ms);
        guard ok_hdr && hdr_end_idx >= 0 else { return false, false; }

        guard parse_response_headers(hdr_buf[..hdr_end_idx], resp) else { return false, false; }
        let leftover_start = hdr_end_idx + 4;

        // RFC 9112 §6.3 / RFC 9110 §15.2: 1xx informational responses (except 101 Switching Protocols)
        // must be consumed while continuing to wait for final response (max 5 interim responses).
        let is_interim = resp.status_code >= rfc::STATUS_CONTINUE &&
            resp.status_code < rfc::STATUS_OK &&
            resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS;
        if is_interim {
            guard !resp.had_te_cl_conflict &&
                !http::has_header(resp.headers, "Transfer-Encoding") &&
                !http::has_header(resp.headers, "Content-Length") else {
                return false, false;
            }
            hdr_buf.compact_wire_buffer(leftover_start);
            continue;
        }

        return pump_response_body(conn, req, resp, hdr_buf[leftover_start..], timeout_ms);
    }
    return false, false;
}

// ---- 6. 4-Phase Timeouts & Keep-Alive Header Synchronization ---------------

struct ExchangeTimeouts {
    connect_timeout_ms:             u32 = 10000,
    headers_timeout_ms:             u32 = 30000,
    body_chunk_timeout_ms:          u32 = 30000,
    keep_alive_default_ns:          i64 = 4000000000,
    keep_alive_max_ns:              i64 = 600000000000,
    keep_alive_threshold_margin_ns: i64 = 1000000000,
}

struct KeepAliveHints {
    has_timeout:  bool = false,
    timeout_sec:  u64  = 0,
    has_max_reqs: bool = false,
    max_reqs:     u64  = 0,
}

// Parses `Keep-Alive` header parameters `timeout=<delta-seconds>` and `max=<uint>`.
// Ignores unknown extension parameters and quoted values safely without allocation.
//
// Example:
//   raw = "timeout=5, max=100"
//   returns: KeepAliveHints { has_timeout: true, timeout_sec: 5, has_max_reqs: true, max_reqs: 100 }
fn parse_keep_alive_header(raw: const u8[:]) -> KeepAliveHints {
    var hints = KeepAliveHints { .. };
    var rem = raw.trim_lws();
    while rem.len > 0 {
        let param, rest, has_comma = rem.split_once_unquoted_byte(',');
        rem = if has_comma { rest.trim_lws() } else { "" };
        let clean_param = param.trim_lws();
        guard clean_param.len > 0 else { continue; }

        let k_raw, v_raw, has_eq = clean_param.split_once_byte('=');
        guard has_eq else { continue; }
        let key = k_raw.trim_lws();
        let val = v_raw.trim_lws().trim_byte('"');
        if key.eq_ascii_fold("timeout") {
            let secs, ok_s = val.parse_u64_dec();
            if ok_s {
                hints.has_timeout = true;
                hints.timeout_sec = secs;
            }
        } else if key.eq_ascii_fold("max") {
            let max_v, ok_m = val.parse_u64_dec();
            if ok_m {
                hints.has_max_reqs = true;
                hints.max_reqs = max_v;
            }
        }
    }
    return hints;
}

// Computes the effective per-connection idle timeout in nanoseconds and whether the socket
// can be kept alive after applying `keep_alive_threshold_margin_ns` and `max_reqs`.
//
// Example:
//   hints = { has_timeout: true, timeout_sec: 5, has_max_reqs: true, max_reqs: 100 }, use_count = 1
//   cfg = ExchangeTimeouts { keep_alive_threshold_margin_ns: 1000000000, .. }
//   returns: 4000000000, true
fn resolve_peer_keep_alive_budget(
    hints:     const KeepAliveHints&,
    use_count: i64,
    cfg:       const ExchangeTimeouts&,
) -> i64, bool {
    if hints.has_max_reqs {
        if hints.max_reqs == 0 || (use_count >= 0 && (use_count as u64) >= hints.max_reqs) {
            return 0, false;
        }
    }
    if !hints.has_timeout {
        let def_ns = min(max(cfg.keep_alive_default_ns, 0), max(cfg.keep_alive_max_ns, 0));
        return def_ns, def_ns > 0;
    }
    let raw_ns_u64 = core::mul_sat_u64(hints.timeout_sec, 1000000000);
    let clamped_u64 = min(raw_ns_u64, 9223372036854775807);
    let adjusted_ns = core::sub_sat_i64(clamped_u64 as i64, max(cfg.keep_alive_threshold_margin_ns, 0));
    guard adjusted_ns > 0 else { return 0, false; }
    let capped_ns = min(adjusted_ns, max(cfg.keep_alive_max_ns, 0));
    return capped_ns, capped_ns > 0;
}

// Computes remaining header read budget in milliseconds from a monotonic deadline,
// preventing 1-byte Slowloris server drips from extending `headers_timeout_ms`.
fn remaining_deadline_ms(deadline_mono_ns: i64, now_mono_ns: i64) -> u32, bool {
    guard deadline_mono_ns > now_mono_ns else { return 0, false; }
    let diff_ns = core::sub_sat_i64(deadline_mono_ns, now_mono_ns) as u64;
    let rounded_ns = core::add_sat_u64(diff_ns, 999999);
    let _, hi = core::mul_wide_u64(rounded_ns >> 6, 9671406556917033398);
    let ms_u64 = hi >> 13;
    let clamped = min(max(ms_u64, 1), 4294967295);
    return clamped as u32, true;
}

// ---- 7. Zero-Copy Streaming Sink & Bounded Body Drain ----------------------

enum StreamSinkVerdict {
    Continue,
    AbortExchange,
}

struct ResponseHead {
    status_code: i32       = 0,
    protocol:    u8[..16]  = "HTTP/1.1",
    headers:     HeaderMap = HeaderMap { .. },
}

// Built-in sink adapter that appends into `Response` while enforcing an optional `max_response_bytes` cap.
struct BufferedBodySink {
    resp:               Response&,
    max_response_bytes: u64 = 0,
}

fn on_headers(sink: BufferedBodySink&, head: const ResponseHead&) -> StreamSinkVerdict {
    sink.resp.status_code = head.status_code;
    let _ = sink.resp.protocol.try_set(head.protocol[..]);
    sink.resp.headers = head.headers;
    if sink.max_response_bytes > 0 {
        let cl_str = http::get_header(head.headers, "Content-Length").trim_lws();
        if cl_str.len > 0 {
            let cl_val, ok_cl = cl_str.parse_u64_dec();
            if !ok_cl || cl_val > sink.max_response_bytes {
                return StreamSinkVerdict.AbortExchange;
            }
        }
    }
    return StreamSinkVerdict.Continue;
}

fn on_data(sink: BufferedBodySink&, chunk: const u8[:]) -> StreamSinkVerdict {
    if sink.max_response_bytes > 0 {
        let next_len = core::add_sat_u64(sink.resp.body.len as u64, chunk.len as u64);
        guard next_len <= sink.max_response_bytes else {
            return StreamSinkVerdict.AbortExchange;
        }
    }
    sink.resp.body.append(chunk);
    return StreamSinkVerdict.Continue;
}

fn on_complete(sink: BufferedBodySink&, trailers: const HeaderMap&) {
    http::copy_headers(trailers, sink.resp.trailers);
}

// Pumps an exact `Content-Length` body directly into `sink.on_data(chunk)` using a 4 KB stack array.
fn stream_h1_fixed_body<Sink>(
    conn:           net::PooledConnection&,
    content_length: u64,
    leftover:       const u8[:],
    body_timeout:   u32,
    sink:           Sink&,
) -> bool {
    let init_len = min(leftover.len as u64, content_length) as i64;
    if init_len > 0 {
        guard sink.on_data(leftover[..init_len]) == StreamSinkVerdict.Continue else { return false; }
    }
    if leftover.len > init_len {
        guard conn.rx_buf.try_append(leftover[init_len..]) else { return false; }
    }
    var remaining = core::sub_sat_u64(content_length, init_len as u64);
    var raw_chunk: u8[4096] = [0; 4096];
    while remaining > 0 {
        let to_read = min(remaining, 4096) as i64;
        let recvd = conn.transport.recv_slice(raw_chunk[..to_read], body_timeout);
        guard recvd > 0 else { return false; }
        guard sink.on_data(raw_chunk[..recvd]) == StreamSinkVerdict.Continue else { return false; }
        remaining = core::sub_sat_u64(remaining, recvd as u64);
    }
    var empty_trailers = HeaderMap { .. };
    sink.on_complete(empty_trailers);
    return true;
}

// Drains and discards at most `max_drain_bytes` of a fixed-length unread HTTP/1.1 body
// so redirect hops and auth challenges can recycle the keep-alive socket instead of closing it.
fn drain_h1_fixed_body_bounded(
    conn:            net::PooledConnection&,
    content_length:  u64,
    leftover_len:    u64,
    max_drain_bytes: u64,
    timeout_ms:      u32,
) -> bool {
    guard content_length <= max_drain_bytes else { return false; }
    var remaining = core::sub_sat_u64(content_length, leftover_len);
    var scratch: u8[4096] = [0; 4096];
    while remaining > 0 {
        let step = min(remaining, 4096) as i64;
        let recvd = conn.transport.recv_slice(scratch[..step], timeout_ms);
        guard recvd > 0 else { return false; }
        remaining = core::sub_sat_u64(remaining, recvd as u64);
    }
    return true;
}
