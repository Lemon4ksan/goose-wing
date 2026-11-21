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
import http.response;
import realtime.sse;
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

// RFC 9112 Section 7.1: Chunked Transfer Coding - writes `<hex>\r\n<payload>\r\n` atomically into `sc`.
fn cork_write_chunk_frame(sc: ServerCork&, chunk_hdr: const u8[:], payload: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return -1; }
    let head_body_len = core::add_sat_i64(chunk_hdr.len, payload.len);
    let frame_len = core::add_sat_i64(head_body_len, 2);
    if frame_len <= sc.buffer.cork_available() {
        let _ = sc.buffer.cork_write(chunk_hdr);
        let _ = sc.buffer.cork_write(payload);
        let _ = sc.buffer.cork_write("\r\n");
        return frame_len as i32;
    }

    let flushed = server_cork_flush(sc);
    guard flushed >= 0 && sc.buffer.cork_is_empty() else { return -1; }

    if frame_len < core::CORK_BUFFER_CAP {
        let _ = sc.buffer.cork_write(chunk_hdr);
        let _ = sc.buffer.cork_write(payload);
        let _ = sc.buffer.cork_write("\r\n");
        return frame_len as i32;
    }

    let w1 = tcp_send2(sc.sock_fd, chunk_hdr, payload);
    guard w1 >= 0 else { return -1; }
    let w2 = tcp_send(sc.sock_fd, "\r\n");
    guard w2 >= 0 else { return -1; }
    return core::add_sat_i64(w1, w2) as i32;
}

fn write_cork_chunked_response_stream<Res>(sc: ServerCork&, res: const Res&, server_name: const u8[:]) -> i32 {
    // RFC 9112 Section 6.1: Transfer-Encoding - forbidden in 1xx/204/304 and HTTP/1.0 responses
    guard sc.sock_fd > 0
        && !rfc::is_empty_body_status(res.status_code)
        && res.protocol[..] != "HTTP/1.0" else {
        return -1;
    }
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
        let chunk_u64 = chunk_n as u64;
        var chunk_hdr: u8[..32] = [];
        chunk_u64.format_u64_hex(chunk_hdr);
        chunk_hdr.append("\r\n");
        let chunk_end = core::add_sat_i64(off, chunk_n);
        let w_chunk = cork_write_chunk_frame(sc, chunk_hdr[..], res.body[off..chunk_end]);
        guard w_chunk >= 0 else { return -1; }
        total_written = core::add_sat_i64(total_written, w_chunk) as i32;
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

// Configures an HTTP response for progressive UTF-8 text streaming with MIME-sniffing disabled.
fn init_text_stream_response(res: Response&) {
    res.status_code = rfc::STATUS_OK;
    set_header(res, rfc::HEADER_CONTENT_TYPE, "text/plain; charset=utf-8");
    set_header(res, "X-Content-Type-Options", "nosniff");
    set_header(res, "Cache-Control", "no-cache");
    set_header(res, rfc::HEADER_TRANSFER_ENCODING, "chunked");
    remove_header(res, rfc::HEADER_CONTENT_LENGTH);
    res.body.clear();
}

// Writes response status + headers for an open HTTP/1.1 chunked stream into `sc`
// without writing the terminating `0\r\n\r\n` chunk.
fn cork_begin_http1_chunked(
    sc:          ServerCork&,
    res:         Response&,
    server_name: const u8[:],
) -> i32 {
    // RFC 9112 Section 6.1: Transfer-Encoding - forbidden in 1xx/204/304 and HTTP/1.0 responses
    guard sc.sock_fd > 0
        && !rfc::is_empty_body_status(res.status_code)
        && res.protocol[..] != "HTTP/1.0" else {
        return -1;
    }
    set_header(res, rfc::HEADER_TRANSFER_ENCODING, "chunked");
    remove_header(res, rfc::HEADER_CONTENT_LENGTH);
    var hdr_wire: u8[..8192] = [];
    serialize_http1_chunked_response(res, server_name, 4096, hdr_wire);
    let term_idx = core::fast_find_crlfcrlf(hdr_wire[..]);
    guard term_idx >= 0 else { return -1; }
    let hdr_end = core::add_sat_i64(term_idx, 4);
    return server_cork_write(sc, hdr_wire[..hdr_end]);
}

// RFC 9112 Section 7.1: Chunked Transfer Coding - writes `<hex>\r\n<payload>\r\n` into `sc`.
// Empty `payload` is a no-op so callers cannot accidentally emit the terminal chunk early.
fn cork_write_http1_chunk(sc: ServerCork&, payload: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return -1; }
    guard payload.len > 0 else { return 0; }
    var chunk_hdr: u8[..24] = [];
    (payload.len as u64).format_u64_hex(chunk_hdr, false);
    chunk_hdr.append("\r\n");
    return cork_write_chunk_frame(sc, chunk_hdr[..], payload);
}

// RFC 9112 Section 7.1: Chunked Transfer Coding - writes terminating `0\r\n\r\n` and flushes `sc`.
fn cork_end_http1_chunked(sc: ServerCork&, flush_now: bool = true) -> i32 {
    let w = server_cork_write(sc, "0\r\n\r\n");
    guard w >= 0 else { return -1; }
    if flush_now {
        let flushed = server_cork_flush(sc);
        guard flushed >= 0 else { return -1; }
    }
    return w;
}

// Formats a W3C SSE frame on the stack via `sse_format_event` and writes it as an
// HTTP/1.1 chunk into `sc`, flushing immediately for real-time delivery.
fn cork_write_sse_chunk(
    sc:         ServerCork&,
    event_type: const u8[:],
    data:       const u8[:],
    id:         const u8[:] = "",
    retry_ms:   u32         = 0,
    flush_now:  bool        = true,
) -> i32 {
    var frame: u8[..4096] = [];
    realtime::sse_format_event(frame, event_type, data, id, retry_ms);
    guard frame.len > 0 else { return 0; }
    let written = cork_write_http1_chunk(sc, frame[..]);
    guard written >= 0 else { return -1; }
    if flush_now {
        let flushed = server_cork_flush(sc);
        guard flushed >= 0 else { return -1; }
    }
    return written;
}
