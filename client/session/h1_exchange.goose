// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// client/session/h1_exchange.goose
// Zero-allocation HTTP/1.1 exchange engine over PooledConnection with
// HeaderSpan zero-copy parsing and chunked transfer decoding.
namespace wing;

import std;
import core from "../..";
import client.client;
import client.response;
import client.request;
import net.pool;
import net.transport;
import http.headers;
import wire.h1;

// ---- 1. Exchange Protocol State Machine ------------------------------------

enum H1ExchangeState {
    Init,
    SendingHeaders,
    SendingBody,
    RecvStatusLine,
    RecvHeaders,
    RecvFixedBody,
    RecvChunkedBody,
    Complete,
    Failed,
}

// ---- 2. Request Serialization ----------------------------------------------

fn format_request_target(
    req:     const Request&,
    url_val: const core::Url&,
    out:     u8[..4096]&,
) -> bool {
    if req.method == "CONNECT" {
        return out.try_append(url_val.host());
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
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    out.clear();
    var target_buf: u8[..4096] = [];
    guard format_request_target(req, url_val, target_buf) else { return false; }
    let has_cl = req.header("Content-Length").len > 0;
    let has_te = req.header("Transfer-Encoding").len > 0;
    let needs_zero_cl = req.method[..].eq_ascii_fold(rfc::METHOD_POST) || req.method[..].eq_ascii_fold(rfc::METHOD_PUT);
    var hdrs = req.headers;
    if !has_cl && !has_te && (req.body.len > 0 || needs_zero_cl) {
        var cl_buf: u8[..32] = [];
        req.body.len.format_i64_dec(cl_buf);
        guard append_header(hdrs, "Content-Length", cl_buf[..]) else { return false; }
    }
    guard wire::encode_h1_request(
        req.method[..],
        target_buf[..],
        url_val.host(),
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
    guard line.len >= 12 else { return false; }

    let _ = resp.protocol.try_set(line[..8]);

    let code = parse_h1_status_code(line[9..12]);
    guard code >= 100 && code <= 599 else { return false; }
    resp.status_code = code;
    return true;
}

// Strips Content-Length if Transfer-Encoding is present to prevent HTTP desync (RFC 9112 §6.1).
//
// Example:
//   resp.headers = [("Transfer-Encoding", "chunked"), ("Content-Length", "10")]
//   returns: Content-Length removed from headers
fn strip_conflicting_content_length(resp: Response&) {
    let te = header(resp, "Transfer-Encoding");
    let cl = header(resp, "Content-Length");
    guard te.len > 0 && cl.len > 0 else { return; }
    remove_header_by_name(resp.headers, "content-length");
    resp.presence_mask = resp.presence_mask & (~RES_PRESENCE_CONTENT_LENGTH);
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

    var offset: i64 = 0;
    while offset < header_bytes.len {
        let rel_nl = header_bytes[offset..].index_of_byte('\n');
        let line_end = if rel_nl >= 0 { offset + rel_nl } else { header_bytes.len };
        let line_raw = header_bytes[offset..line_end];
        let line = line_raw.trim_end_byte('\r');
        offset = line_end + 1;

        guard line.len > 0 else { continue; }
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

        guard is_valid_header_name(hname) && is_valid_header_value(hval) else { return false; }
        if hname.eq_ascii_fold("content-length") {
            let _, cl_ok = hval.parse_u64_dec();
            let prev_cl = header(resp, "Content-Length");
            guard cl_ok && (prev_cl.len == 0 || prev_cl == hval) else { return false; }
        }
        guard append_header(resp.headers, hname, hval) else { return false; }
        update_response_presence(resp, hname);
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
    let first_line_end = header_block.index_of_byte('\n');
    if first_line_end < 0 {
        let status_only = header_block.trim_end_byte('\r');
        resp.headers.clear();
        resp.presence_mask = 0;
        return parse_h1_status_line(status_only, resp);
    }
    guard first_line_end > 0 else { return false; }

    let status_raw = header_block[..first_line_end];
    let status_line = status_raw.trim_end_byte('\r');
    guard parse_h1_status_line(status_line, resp) else { return false; }

    let headers_part = header_block[(first_line_end + 1)..];
    return parse_h1_header_block(headers_part, resp);
}

// ---- 4. Body Streaming Pumps ------------------------------------------------

fn pump_h1_fixed_body(
    conn:       PooledConnection&,
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
    dec:         internal::ChunkFsmDecoder&,
    buf:         const u8[:],
    resp:        Response&,
    trailer_buf: u8[..4096]&,
    out_cursor:  i64&,
) -> bool, bool {
    out_cursor = 0;
    while out_cursor < buf.len {
        let is_tr = (dec.state & 0x1000000000000000) != 0;
        let remaining = buf[out_cursor..];
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, remaining);
        if is_tr {
            guard record_chunk_trailers(true, consumed, remaining, trailer_buf) else { return true, false; }
        } else if (dec.state & 0x1000000000000000) != 0 || st == internal::ChunkFsmStatus.Complete {
            let nl = remaining[..consumed].index_of_byte('\n');
            if nl >= 0 && (nl + 1) < consumed {
                let tr_slice = remaining[(nl + 1)..consumed];
                guard record_chunk_trailers(true, tr_slice.len, tr_slice, trailer_buf) else { return true, false; }
            }
        }
        out_cursor += consumed;
        if chunk.len > 0 {
            resp.body.append(chunk);
        }
        if st == internal::ChunkFsmStatus.Complete {
            if trailer_buf.len > 0 {
                var tr_cur: i64 = 0;
                let tr_err = parse_chunked_trailers_with_out(trailer_buf[..], tr_cur, resp.trailers);
                guard tr_err == ChunkedDecodeError.None else { return true, false; }
            }
            return true, true;
        }
        if st == internal::ChunkFsmStatus.Error {
            return true, false;
        }
    }
    return false, true;
}

fn pump_h1_chunked_body(
    conn:       PooledConnection&,
    dec:        internal::ChunkFsmDecoder&,
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
                let _ = conn.rx_buf.try_append(leftover[consumed_cur..]);
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
                let _ = conn.rx_buf.try_append(wire_buf[consumed_cur..recvd]);
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
fn send_all(trans: Transport&, buf: const u8[:]) -> bool {
    var sent_total: i64 = 0;
    while sent_total < buf.len {
        let sent = trans.send(buf[sent_total..]);
        guard sent > 0 else { return false; }
        sent_total += sent;
    }
    return true;
}

fn send_h1_request(
    conn:    PooledConnection&,
    req:     const Request&,
    url_val: const core::Url&,
) -> bool {
    var req_wire: u8[..4096] = [];
    guard serialize_h1_request(req, url_val, req_wire) else { return false; }
    guard send_all(conn.transport, req_wire[..]) else { return false; }

    if req.body.len > 0 {
        guard send_all(conn.transport, req.body[..]) else { return false; }
    }
    return true;
}

fn read_response_headers(conn: PooledConnection&, timeout_ms: u32) -> i64, bool {
    var hdr_end_idx: i64      = core::fast_find_crlfcrlf(conn.rx_buf[..]);
    var raw_recv:    u8[4096] = [0; 4096];

    while hdr_end_idx < 0 {
        let recvd = conn.transport.recv_slice(raw_recv[..], timeout_ms);
        guard recvd > 0 else { return 0, false; }
        guard conn.rx_buf.try_append(raw_recv[..recvd]) else { return 0, false; }
        hdr_end_idx = core::fast_find_crlfcrlf(conn.rx_buf[..]);
    }
    return hdr_end_idx, true;
}

fn pump_cl_body(
    conn:       PooledConnection&,
    resp:       Response&,
    leftover:   const u8[:],
    cl_str:     const u8[:],
    timeout_ms: u32,
) -> bool {
    let cl_val, ok_cl = cl_str.parse_u64_dec();
    guard ok_cl else { return false; }

    let init_bytes = min(leftover.len, cl_val as i64);
    if init_bytes > 0 {
        resp.body.append(leftover[..init_bytes]);
    }
    if leftover.len > init_bytes {
        let _ = conn.rx_buf.try_append(leftover[init_bytes..]);
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
    if has_header(headers, "Transfer-Encoding") {
        return true;
    }
    let cl = get_header(headers, "Content-Length").trim_lws();
    guard cl.len > 0 else { return false; }
    let cl_val, ok_cl = cl.parse_u64_dec();
    return !ok_cl || cl_val > 0;
}

fn pump_response_body(
    conn:       PooledConnection&,
    req:        const Request&,
    resp:       Response&,
    leftover:   const u8[:],
    timeout_ms: u32,
) -> bool, bool {
    let req_conn = req.header("Connection");
    let conn_hdr = resp.header("Connection");
    let is_conn_close = header_has_token(conn_hdr, "close") || header_has_token(req_conn, "close");
    let keep_alive = !is_conn_close && (resp.protocol == "HTTP/1.1" || resp.protocol == "h1");

    let is_upgrade = resp.status_code == rfc::STATUS_SWITCHING_PROTOCOLS;
    if req.method == "HEAD" || is_upgrade || rfc::is_empty_body_status(resp.status_code) {
        let status = resp.status_code;
        if status == 204 || status == 304 {
            let allow_ka = keep_alive && !has_rogue_empty_status_framing(req.method[..], status, resp.headers);
            if allow_ka && leftover.len > 0 {
                let _ = conn.rx_buf.try_append(leftover);
            }
            return true, allow_ka;
        }
        if (keep_alive || is_upgrade) && leftover.len > 0 {
            let _ = conn.rx_buf.try_append(leftover);
        }
        return true, keep_alive || is_upgrade;
    }

    let te = resp.header("Transfer-Encoding");
    if header_has_token(te, "chunked") {
        var dec = internal::new_chunk_fsm_decoder();
        let ok_chunk = pump_h1_chunked_body(conn, dec, leftover, resp, timeout_ms);
        if ok_chunk {
            remove_header_by_name(resp.headers, "transfer-encoding");
            resp.presence_mask = resp.presence_mask & (~RES_PRESENCE_TRANSFER_ENCODING);
        }
        return ok_chunk, keep_alive;
    }

    let cl_str = resp.header("Content-Length");
    if cl_str.len > 0 {
        let ok_fixed = pump_cl_body(conn, resp, leftover, cl_str, timeout_ms);
        return ok_fixed, keep_alive;
    }

    // Close-delimited body
    if leftover.len > 0 {
        resp.body.append(leftover);
    }
    var raw_recv: u8[4096] = [0; 4096];
    loop {
        let recvd = conn.transport.recv_slice(raw_recv[..], timeout_ms);
        if recvd <= 0 { break; }
        resp.body.append(raw_recv[..recvd]);
    }
    return true, false;
}

// Executes an end-to-end HTTP/1.1 exchange over a pooled connection with zero heap allocation.
fn execute_h1_exchange(
    conn:       PooledConnection&,
    req:        const Request&,
    url_val:    const core::Url&,
    resp:       Response&,
    timeout_ms: u32 = 5000,
) -> bool, bool {
    reset_response(resp);
    guard send_h1_request(conn, req, url_val) else { return false, false; }

    for interim_step in 6 {
        let hdr_end_idx, ok_hdr = read_response_headers(conn, timeout_ms);
        guard ok_hdr && hdr_end_idx >= 0 else { return false, false; }

        guard parse_response_headers(conn.rx_buf[..hdr_end_idx], resp) else { return false, false; }
        let leftover_start = hdr_end_idx + 4;

        // RFC 9112 §6.3 / RFC 9110 §15.2: 1xx informational responses (except 101 Switching Protocols)
        // must be consumed while continuing to wait for final response (max 5 interim responses).
        let is_interim = resp.status_code >= rfc::STATUS_CONTINUE &&
            resp.status_code < rfc::STATUS_OK &&
            resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS;
        if is_interim {
            conn.rx_buf.compact_wire_buffer(leftover_start);
            continue;
        }

        var leftover: u8[..8192] = [];
        leftover.append(conn.rx_buf[leftover_start..]);
        conn.rx_buf.clear();
        return pump_response_body(conn, req, resp, leftover[..], timeout_ms);
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
        let cl_str = get_header(head.headers, "Content-Length").trim_lws();
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
    copy_headers(trailers, sink.resp.trailers);
}

// Pumps an exact `Content-Length` body directly into `sink.on_data(chunk)` using a 4 KB stack array.
fn stream_h1_fixed_body<Sink>(
    conn:           PooledConnection&,
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
    conn:            PooledConnection&,
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
