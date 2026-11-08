// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Outbound Cork Buffer Manager for TCP connections (uWebSockets 16 KB Cork Buffer pattern).
// Aggregates headers, frames, and small payload chunks into a single 16384-byte buffer
// before flushing via 1 system call.
namespace wing;

import std;
import core from "..";
import rfc.http;
import http.headers;
import net.tcp;
import client.response;
import .h1_codec;

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
    let avail = sc.buffer.cork_available();
    if data.len <= avail {
        let written, _ = sc.buffer.cork_write(data);
        return written as i32;
    }

    // Buffer would overflow: flush current pending bytes first
    let flushed = server_cork_flush(sc);
    guard flushed >= 0 && sc.buffer.cork_is_empty() else { return -1; }

    if data.len >= core::CORK_BUFFER_CAP {
        // Larger than cork buffer: send directly via TCP
        return tcp_send(sc.sock_fd, data);
    }

    let written, _ = sc.buffer.cork_write(data);
    return written as i32;
}

// Writes two contiguous slices (e.g. headers and body) directly into the cork buffer
// without combining them into an intermediate buffer first (zero-copy vectored buffering).
fn server_cork_write2(sc: ServerCork&, head: const u8[:], body: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return 0; }
    let total_len = core::add_sat_i64(head.len, body.len);
    guard total_len > 0 else { return 0; }

    let avail = sc.buffer.cork_available();
    if total_len <= avail {
        let _ = sc.buffer.cork_write(head);
        let _ = sc.buffer.cork_write(body);
        return total_len as i32;
    }

    let flushed = server_cork_flush(sc);
    guard flushed >= 0 && sc.buffer.cork_is_empty() else { return -1; }

    if total_len >= core::CORK_BUFFER_CAP {
        if head.len > 0 && body.len > 0 {
            return tcp_send2(sc.sock_fd, head, body);
        }
        if head.len > 0 {
            return tcp_send(sc.sock_fd, head);
        }
        return tcp_send(sc.sock_fd, body);
    }

    let _ = sc.buffer.cork_write(head);
    let _ = sc.buffer.cork_write(body);
    return total_len as i32;
}

fn write_cork_chunked_response_stream<Res>(sc: ServerCork&, res: const Res&, server_name: const u8[:]) -> i32 {
    if res.body.len <= 8192 {
        var wire_out: u8[..16384] = [];
        serialize_http1_chunked_response(res, server_name, 4096, wire_out);
        return server_cork_write(sc, wire_out[..]);
    }
    var empty_res = Response {
        status_code:   res.status_code,
        headers:       res.headers,
        trailers:      res.trailers,
        presence_mask: res.presence_mask,
        ..
    };
    var hdr_wire: u8[..8192] = [];
    serialize_http1_chunked_response(empty_res, server_name, 4096, hdr_wire);
    let term_idx = core::fast_find_crlfcrlf(hdr_wire[..]);
    guard term_idx >= 0 else { return -1; }
    let hdr_end = core::add_sat_i64(term_idx, 4);
    let hdr_sent = server_cork_write(sc, hdr_wire[..hdr_end]);
    guard hdr_sent >= 0 else { return -1; }
    var total_written: i32 = hdr_sent;
    var off:           i64 = 0;
    while off < res.body.len {
        let chunk_n = min(core::sub_sat_i64(res.body.len, off), 4096);
        var chunk_hdr: u8[..32] = [];
        (chunk_n as u64).format_u64_hex(chunk_hdr);
        chunk_hdr.append("\r\n");
        let chunk_end = core::add_sat_i64(off, chunk_n);
        let w1 = server_cork_write2(sc, chunk_hdr[..], res.body[off..chunk_end]);
        guard w1 >= 0 else { return -1; }
        let w2 = server_cork_write(sc, "\r\n");
        guard w2 >= 0 else { return -1; }
        total_written = core::add_sat_i64(total_written, core::add_sat_i64(w1, w2)) as i32;
        off = chunk_end;
    }
    let tail_slice = hdr_wire[hdr_end..];
    let w_tail = server_cork_write(sc, tail_slice);
    guard w_tail >= 0 else { return -1; }
    return core::add_sat_i64(total_written, w_tail) as i32;
}

// Serializes and writes an HTTP/1.1 response into the cork buffer.
// Zero-copy: formats headers in a small stack buffer and writes headers + body
// directly into the cork buffer or socket via vectored I/O without intermediate body copies.
fn server_cork_write_response<Res>(sc: ServerCork&, res: const Res&, server_name: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return 0; }
    let is_empty_status = rfc::is_empty_body_status(res.status_code);
    let te = header(res, "transfer-encoding");
    if !is_empty_status && (te.eq_ascii_fold("chunked") || res.trailers.entries.len > 0) {
        return write_cork_chunked_response_stream(sc, res, server_name);
    }

    var hdr_buf: u8[..8192] = [];
    serialize_http1_headers(res, server_name, hdr_buf);
    if res.body.len == 0 || is_empty_status {
        return server_cork_write(sc, hdr_buf[..]);
    }
    return server_cork_write2(sc, hdr_buf[..], res.body[..]);
}

// Flushes all pending data in the cork buffer to the socket in a single syscall.
fn server_cork_flush(sc: ServerCork&) -> i32 {
    guard sc.sock_fd > 0 && !sc.buffer.cork_is_empty() else { return 0; }
    return tcp_flush_cork(sc.sock_fd, sc.buffer);
}
