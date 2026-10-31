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

fn serialize_headers_with_host_check(
    req:     const Request&,
    url_val: const core::Url&,
    out:     u8[..4096]&,
    has_cl:  bool&,
) -> bool {
    var has_host = false;
    has_cl = false;

    for &h in req.headers {
        if eq_ascii_fold(h.name[..], "Host") { has_host = true; }
        if eq_ascii_fold(h.name[..], "Content-Length") { has_cl = true; }
        guard out.try_append(h.name[..]) &&
              out.try_append(": ") &&
              out.try_append(h.value[..]) &&
              out.try_append("\r\n") else { return false; }
    }

    if !has_host {
        guard out.try_append("Host: ") &&
              out.try_append(url_val.host()) &&
              out.try_append("\r\n") else { return false; }
    }
    return true;
}

fn serialize_h1_request(
    req:     const Request&,
    url_val: const core::Url&,
    out:     u8[..4096]&,
) -> bool {
    out.clear();

    guard out.try_append(req.method[..]) && out.try_append(" ") else { return false; }
    guard format_request_target(req, url_val, out) else { return false; }
    guard out.try_append(" HTTP/1.1\r\n") else { return false; }

    var has_cl = false;
    guard serialize_headers_with_host_check(req, url_val, out, has_cl) else { return false; }

    if !has_cl && req.body.len > 0 {
        var cl_buf: u8[..32] = [];
        core::format_u64_dec(req.body.len as u64, cl_buf);
        guard out.try_append("Content-Length: ") &&
              out.try_append(cl_buf[..]) &&
              out.try_append("\r\n") else { return false; }
    }

    guard out.try_append("\r\n") else { return false; }
    return true;
}

// ---- 3. Response Status and Header Parsing ----------------------------------

// Parses 3-digit ASCII status code string into numeric integer (RFC 9112 §3.1.2).
//
// Example:
//   status_str = "200"
//   returns: 200
fn parse_h1_status_code(status_str: const u8[:]) -> i32 {
    guard status_str.len == 3 else { return 0; }
    let val, ok = core::parse_u32_dec(status_str);
    guard ok && val >= 100 && val <= 599 else { return 0; }
    return val as i32;
}

// Parses HTTP/1.1 status line: `HTTP/1.1 <status> <reason>\r\n` (RFC 9112 §3.1.2).
// Populates resp.protocol and resp.status_code.
//
// Example:
//   line = "HTTP/1.1 200 OK"
//   returns: ok = true, resp.status_code = 200, resp.protocol = "HTTP/1.1"
fn parse_h1_status_line(
    line: const u8[:],
    resp: Response&,
) -> bool {
    guard line.len >= 12 else { return false; }
    guard starts_with(line, "HTTP/") else { return false; }

    let sp1_idx = core::index_of_byte(line, ' ');
    guard sp1_idx > 5 && (sp1_idx + 4) <= line.len else { return false; }

    resp.protocol.clear();
    resp.protocol.append(line[..sp1_idx]);

    let code_start = sp1_idx + 1;
    let code_end = sp1_idx + 4;
    let code = parse_h1_status_code(line[code_start..code_end]);
    guard code >= 100 && code <= 599 else { return false; }
    resp.status_code = code;
    return true;
}

// Parses raw HTTP response header block into zero-copy spans and HeaderItem views (RFC 9112 §2.1).
// Populates resp.raw_headers, resp.spans, and resp.headers.
//
// Example:
//   header_bytes = "Content-Type: text/plain\r\nContent-Length: 5\r\n"
//   returns: ok = true, resp.spans.len = 2, resp.headers.len = 2
fn parse_h1_header_block(
    header_bytes: const u8[:],
    resp:         Response&,
) -> bool {
    resp.raw_headers.clear();
    guard resp.raw_headers.try_append(header_bytes) else { return false; }
    resp.spans.clear();
    resp.headers.clear();

    var offset: i64 = 0;
    while offset < header_bytes.len {
        let rel_nl = core::index_of_byte(header_bytes[offset..], '\n');
        guard rel_nl >= 0 else { break; }
        let line_end = offset + rel_nl;
        let line_raw = header_bytes[offset..line_end];
        let line = core::trim_end_byte(line_raw, '\r');
        let line_start = offset;
        offset = line_end + 1;

        guard line.len > 0 else { continue; }
        let col = core::index_of_byte(line, ':');
        guard col > 0 else { continue; }

        let hname = line[..col];
        let raw_val = line[(col + 1)..];
        let v_lead = core::trim_lws_start(raw_val);
        let v_trim = core::trim_lws_end(v_lead);
        let lead_spaces = raw_val.len - v_lead.len;
        let v_start = col + 1 + lead_spaces;
        let v_len = v_trim.len;
        let hval = line[v_start..(v_start + v_len)];

        let span = HeaderSpan {
            name_pos: line_start as u16,
            name_len: hname.len as u16,
            val_pos:  (line_start + v_start) as u16,
            val_len:  v_len as u16,
            id:       0,
        };
        guard resp.spans.len < resp.spans.cap else { return false; }
        resp.spans.push(span);

        guard resp.headers.len < resp.headers.cap else { return false; }
        resp.headers.push(make_header(hname, hval));
    }
    return true;
}

// Splits response header block into status line and headers, parsing both into resp.
//
// Example:
//   header_block = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
//   returns: ok = true, resp.status_code = 200
fn parse_response_headers(header_block: const u8[:], resp: Response&) -> bool {
    let first_line_end = core::index_of_byte(header_block, '\n');
    guard first_line_end > 0 else { return false; }

    let status_raw = header_block[..first_line_end];
    let status_line = core::trim_end_byte(status_raw, '\r');
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
        let to_read_u64 = if bytes_left > chunk_cap { chunk_cap } else { bytes_left };
        let to_read = to_read_u64 as i64;
        let recvd = conn.transport.recv_slice(raw_chunk[..to_read], timeout_ms);
        guard recvd > 0 else { return false; }
        resp.body.append(raw_chunk[..recvd]);
        let recvd_u64 = recvd as u64;
        bytes_left = if bytes_left > recvd_u64 { bytes_left - recvd_u64 } else { 0 };
    }
    return true;
}

fn feed_chunk_slice(
    dec:  internal::ChunkFsmDecoder&,
    buf:  const u8[:],
    resp: Response&,
) -> bool, bool {
    var cursor: i64 = 0;
    while cursor < buf.len {
        let remaining = buf[cursor..];
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, remaining);
        cursor += consumed;
        if chunk.len > 0 {
            resp.body.append(chunk);
        }
        if st == internal::ChunkFsmStatus.Complete {
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
    if leftover.len > 0 {
        let done, ok = feed_chunk_slice(dec, leftover, resp);
        if done { return ok; }
    }

    var wire_buf: u8[4096] = [0; 4096];
    while true {
        let recvd = conn.transport.recv_slice(wire_buf[..], timeout_ms);
        guard recvd > 0 else { return false; }
        let done, ok = feed_chunk_slice(dec, wire_buf[..recvd], resp);
        if done { return ok; }
    }
    return true;
}

// ---- 5. Top-Level Exchange Execution ----------------------------------------

fn send_h1_request(
    conn:    PooledConnection&,
    req:     const Request&,
    url_val: const core::Url&,
) -> bool {
    var req_wire: u8[..4096] = [];
    guard serialize_h1_request(req, url_val, req_wire) else { return false; }
    let sent = conn.transport.send(req_wire[..]);
    guard sent > 0 else { return false; }

    if req.body.len > 0 {
        let body_sent = conn.transport.send(req.body[..]);
        guard body_sent >= 0 else { return false; }
    }
    return true;
}

fn read_response_headers(conn: PooledConnection&, timeout_ms: u32) -> i64, bool {
    conn.rx_buf.clear();
    var hdr_end_idx: i64      = -1;
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
    let cl_val, ok_cl = core::parse_u64_dec(cl_str);
    guard ok_cl else { return false; }

    let init_bytes = if (leftover.len as u64) > cl_val { cl_val as i64 } else { leftover.len };
    if init_bytes > 0 {
        resp.body.append(leftover[..init_bytes]);
    }
    let init_u64 = init_bytes as u64;
    var remaining_cl = if cl_val > init_u64 { cl_val - init_u64 } else { 0 };
    return pump_h1_fixed_body(conn, remaining_cl, resp, timeout_ms);
}

fn pump_response_body(
    conn:       PooledConnection&,
    req:        const Request&,
    resp:       Response&,
    leftover:   const u8[:],
    timeout_ms: u32,
) -> bool, bool {
    let conn_hdr = resp.header("Connection");
    let is_conn_close = eq_ascii_fold(conn_hdr, "close");
    let keep_alive = !is_conn_close && (resp.protocol == "HTTP/1.1" || resp.protocol == "h1");

    if req.method == "HEAD" || resp.status_code == 204 || resp.status_code == 304 {
        return true, keep_alive;
    }

    let te = resp.header("Transfer-Encoding");
    if eq_ascii_fold(te, "chunked") {
        var dec = internal::new_chunk_fsm_decoder();
        let ok_chunk = pump_h1_chunked_body(conn, dec, leftover, resp, timeout_ms);
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
    while true {
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
    guard send_h1_request(conn, req, url_val) else { return false, false; }
    let hdr_end_idx, ok_hdr = read_response_headers(conn, timeout_ms);
    guard ok_hdr && hdr_end_idx >= 0 else { return false, false; }

    guard parse_response_headers(conn.rx_buf[..hdr_end_idx], resp) else { return false, false; }
    let leftover = conn.rx_buf[(hdr_end_idx + 4)..];
    return pump_response_body(conn, req, resp, leftover, timeout_ms);
}
