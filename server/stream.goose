// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unified zero-copy streaming response API with explicit flow-control backpressure
// across HTTP/1.1, HTTP/2 (RFC 9113), and HTTP/3 over QUIC (RFC 9114 / RFC 9000).
namespace server;

import std;
import core;
import rfc.http;
import rfc.h2;
import rfc.h3_quic;
import http.headers;
import http.response;
import http2.framing;
import http2.hpack;
import quic.packet;
import quic.stream;
import quic.flow_control;
import http3.framing;
import http3.qpack;
import .h1_codec;
import .cork;

// ---- Closed-Polymorphism Streaming Types -----------------------------------

enum StreamProtocol {
    Http1,
    Http2,
    Http3,
}

enum StreamWriteStatus {
    Ok,
    WouldBlock,
    Closed,
    Error,
}

struct ResponseStream {
    protocol:        StreamProtocol = StreamProtocol.Http1,
    cork:            ServerCork     = new_server_cork(-1),
    server_name:     u8[..64]       = "goose-wing",
    headers_sent:    bool           = false,
    ended:           bool           = false,
    closed:          bool           = false,
    body_bytes_sent: u64            = 0,
    frames_emitted:  u64            = 0,
    // HTTP/1.1 framing & partial non-blocking write tracking
    h1_chunked:          bool     = true,
    h1_content_length:   i64      = -1,
    h1_in_chunk_rem:     i64      = 0,
    h1_need_chunk_crlf:  bool     = false,
    h1_pending_ctrl:     u8[..32] = [],
    h1_pending_ctrl_pos: i64      = 0,
    // HTTP/2 two-level flow-control windows (RFC 9113 Section 6.9)
    h2_stream_id:          u32 = 1,
    h2_max_frame_size:     u32 = rfc::H2_DEFAULT_MAX_FRAME_SIZE,
    h2_conn_send_window:   i64 = rfc::H2_DEFAULT_WINDOW_SIZE,
    h2_stream_send_window: i64 = rfc::H2_DEFAULT_WINDOW_SIZE,
    // HTTP/3 + QUIC flow-control credits (RFC 9114 / RFC 9000 Section 4)
    h3_stream_id:   u64                   = 0,
    quic_flow:      quic::QuicFlowControl = quic::new_flow_control(65536, 65536),
    quic_stream:    quic::QuicStream      = quic::new_stream(0, 65536),
    h3_fin_emitted: bool                  = false,
}

// ---- Protocol Stream Factories ---------------------------------------------

fn make_http1_response_stream(
    sock_fd:     i64         = -1,
    server_name: const u8[:] = "goose-wing",
) -> ResponseStream {
    var s = ResponseStream {
        protocol: StreamProtocol.Http1,
        cork:     new_server_cork(sock_fd),
        ..
    };
    let _ = s.server_name.try_set(server_name[..min(server_name.len, s.server_name.cap)]);
    return s;
}

fn make_http2_response_stream(
    stream_id:      u32,
    conn_window:    i64         = 65535,
    stream_window:  i64         = 65535,
    max_frame_size: u32         = 16384,
    sock_fd:        i64         = -1,
    server_name:    const u8[:] = "goose-wing",
) -> ResponseStream {
    let clamped_frame = clamp(max_frame_size as i64, 16384, 16777215) as u32;
    var s = ResponseStream {
        protocol:              StreamProtocol.Http2,
        cork:                  new_server_cork(sock_fd),
        h2_stream_id:          stream_id & 0x7FFFFFFF,
        h2_max_frame_size:     clamped_frame,
        h2_conn_send_window:   min(conn_window, rfc::H2_MAX_WINDOW_SIZE),
        h2_stream_send_window: min(stream_window, rfc::H2_MAX_WINDOW_SIZE),
        ..
    };
    let _ = s.server_name.try_set(server_name[..min(server_name.len, s.server_name.cap)]);
    return s;
}

fn make_http3_response_stream(
    stream_id:     u64,
    conn_credit:   u64         = 65536,
    stream_credit: u64         = 65536,
    sock_fd:       i64         = -1,
    server_name:   const u8[:] = "goose-wing",
) -> ResponseStream {
    var qs = quic::new_stream(stream_id, 65536);
    qs.send_max_data = min(stream_credit, rfc::QUIC_VARINT_MAX);
    var s = ResponseStream {
        protocol:     StreamProtocol.Http3,
        cork:         new_server_cork(sock_fd),
        h3_stream_id: stream_id,
        quic_flow:    quic::new_flow_control(conn_credit, 65536),
        quic_stream:  qs,
        ..
    };
    let _ = s.server_name.try_set(server_name[..min(server_name.len, s.server_name.cap)]);
    return s;
}

// ---- Shared Wire Egress & Flush Primitives ---------------------------------

inline fn stream_is_hop_by_hop_header(name: const u8[:]) -> bool {
    return name.eq_ascii_fold("connection") ||
        name.eq_ascii_fold("keep-alive") ||
        name.eq_ascii_fold("proxy-connection") ||
        name.eq_ascii_fold("transfer-encoding") ||
        name.eq_ascii_fold("upgrade") ||
        name.eq_ascii_fold("te");
}

fn stream_flush_pending_ctrl(stream: ResponseStream&) -> StreamWriteStatus {
    let rem = core::sub_sat_i64(stream.h1_pending_ctrl.len, stream.h1_pending_ctrl_pos);
    guard rem > 0 else { return StreamWriteStatus.Ok; }
    let tail = stream.h1_pending_ctrl[stream.h1_pending_ctrl_pos..];
    if stream.cork.sock_fd <= 0 {
        guard tail.len <= stream.cork.buffer.cork_available() else { return StreamWriteStatus.WouldBlock; }
        let _ = stream.cork.buffer.cork_write(tail);
        stream.h1_pending_ctrl.clear();
        stream.h1_pending_ctrl_pos = 0;
        return StreamWriteStatus.Ok;
    }
    let sent = cork_send_raw(stream.cork.sock_fd, tail);
    if sent == CORK_WOULD_BLOCK || sent == 0 { return StreamWriteStatus.WouldBlock; }
    if sent < 0 {
        stream.closed = true;
        return StreamWriteStatus.Error;
    }
    stream.h1_pending_ctrl_pos = core::add_sat_i64(stream.h1_pending_ctrl_pos, sent);
    if stream.h1_pending_ctrl_pos >= stream.h1_pending_ctrl.len {
        stream.h1_pending_ctrl.clear();
        stream.h1_pending_ctrl_pos = 0;
        return StreamWriteStatus.Ok;
    }
    return StreamWriteStatus.WouldBlock;
}

// Flushes buffered cork bytes and any pending H1 framing control bytes to `stream.cork.sock_fd`.
fn stream_flush(stream: ResponseStream&) -> StreamWriteStatus {
    guard !stream.closed else { return StreamWriteStatus.Closed; }
    if stream.cork.sock_fd > 0 && !stream.cork.buffer.cork_is_empty() {
        let flushed = server_cork_flush(stream.cork);
        if flushed == CORK_WOULD_BLOCK { return StreamWriteStatus.WouldBlock; }
        if flushed < 0 {
            stream.closed = true;
            return StreamWriteStatus.Error;
        }
        if !stream.cork.buffer.cork_is_empty() { return StreamWriteStatus.WouldBlock; }
    }
    return stream_flush_pending_ctrl(stream);
}

// Drains emitted sans-IO wire bytes from `stream.cork.buffer` into `dst` and compacts the buffer.
fn stream_drain_wire(stream: ResponseStream&, dst: u8[:]) -> i64 {
    guard dst.len > 0 else { return 0; }
    let pending = stream.cork.buffer.cork_as_slice();
    guard pending.len > 0 else { return 0; }
    let take = min(pending.len, dst.len);
    core::ct_copy_bytes(dst[..take], pending[..take]);
    stream.cork.buffer.cork_consume(take);
    return take;
}

// Writes an atomic wire block (header + optional payload) to cork or socket.
fn stream_emit_wire_parts(
    stream:  ResponseStream&,
    head:    const u8[:],
    payload: const u8[:],
) -> StreamWriteStatus {
    let total = core::add_sat_i64(head.len, payload.len);
    guard total > 0 else { return StreamWriteStatus.Ok; }
    if stream.cork.sock_fd <= 0 {
        guard total <= stream.cork.buffer.cork_available() else { return StreamWriteStatus.WouldBlock; }
        if head.len > 0 { let _ = stream.cork.buffer.cork_write(head); }
        if payload.len > 0 { let _ = stream.cork.buffer.cork_write(payload); }
        return StreamWriteStatus.Ok;
    }
    let w = server_cork_write2(stream.cork, head, payload);
    if w == CORK_WOULD_BLOCK { return StreamWriteStatus.WouldBlock; }
    if w < 0 {
        stream.closed = true;
        return StreamWriteStatus.Error;
    }
    if w < total { return StreamWriteStatus.WouldBlock; }
    return StreamWriteStatus.Ok;
}

// ---- Protocol-Specific Header Emitters (stream_begin) ----------------------

fn stream_begin_http1(stream: ResponseStream&, res: http::Response&) -> StreamWriteStatus {
    if res.status_code == 0 { res.status_code = rfc::STATUS_OK; }
    let is_empty = rfc::is_empty_body_status(res.status_code);
    var hdr_buf: u8[..8192] = [];
    if is_empty {
        stream.h1_chunked = false;
        stream.h1_content_length = 0;
        serialize_http1_headers(res, stream.server_name[..], hdr_buf, 0, 0);
    } else {
        let te = http::header(res, rfc::HEADER_TRANSFER_ENCODING);
        let cl_raw = http::header(res, rfc::HEADER_CONTENT_LENGTH);
        if !te.eq_ascii_fold("chunked") && cl_raw.len > 0 {
            let cl_val, ok_cl = cl_raw.trim_lws().parse_i64_dec();
            guard ok_cl && cl_val >= 0 else { return StreamWriteStatus.Error; }
            stream.h1_chunked = false;
            stream.h1_content_length = cl_val;
            serialize_http1_headers(res, stream.server_name[..], hdr_buf, 0, cl_val);
        } else {
            // RFC 9112 Section 6.1: Transfer-Encoding - forbidden in HTTP/1.0 responses.
            guard res.protocol[..] != "HTTP/1.0" else { return StreamWriteStatus.Error; }
            http::set_header(res, rfc::HEADER_TRANSFER_ENCODING, "chunked");
            let _ = http::remove_header(res, rfc::HEADER_CONTENT_LENGTH);
            stream.h1_chunked = true;
            stream.h1_content_length = -1;
            serialize_http1_headers(res, stream.server_name[..], hdr_buf, 0, 0);
        }
    }
    let st = stream_emit_wire_parts(stream, hdr_buf[..], "");
    guard st == StreamWriteStatus.Ok else { return st; }
    stream.headers_sent = true;
    if is_empty { stream.ended = true; }
    return StreamWriteStatus.Ok;
}

fn stream_begin_http2(stream: ResponseStream&, res: http::Response&) -> StreamWriteStatus {
    if res.status_code == 0 { res.status_code = rfc::STATUS_OK; }
    let is_empty = rfc::is_empty_body_status(res.status_code);
    var dt = http2::new_dynamic_table(0);
    var hpack_block: u8[..8192] = [];
    var status_str:  u8[..16]   = [];
    res.status_code.format_i64_dec(status_str);
    guard http2::encode_hpack_field(dt, hpack_block, ":status", status_str[..], http2::HpackIndexing.None, true) else {
        return StreamWriteStatus.Error;
    }
    if stream.server_name.len > 0 && !http::has_header(res, "server") {
        let _ = http2::encode_hpack_field(
            dt, hpack_block, "server", stream.server_name[..], http2::HpackIndexing.None, true,
        );
    }
    for &e in res.headers.entries {
        let name = http::entry_name(res.headers, e);
        let val = http::entry_value(res.headers, e);
        guard !stream_is_hop_by_hop_header(name) else { continue; }
        var lower: u8[..256] = [];
        guard name.len > 0 && name.len <= lower.cap else { return StreamWriteStatus.Error; }
        name.to_lower_ascii(lower);
        guard http2::encode_hpack_field(dt, hpack_block, lower[..], val, http2::HpackIndexing.None, true) else {
            return StreamWriteStatus.Error;
        }
    }
    var flags: u8 = rfc::H2_FLAG_END_HEADERS;
    if is_empty { flags |= rfc::H2_FLAG_END_STREAM; }
    let fhdr = http2::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream.h2_stream_id,
    };
    var raw_hdr: u8[9] = [0; 9];
    http2::encode_frame_header(fhdr, raw_hdr);
    let st = stream_emit_wire_parts(stream, raw_hdr[..], hpack_block[..]);
    guard st == StreamWriteStatus.Ok else { return st; }
    stream.headers_sent = true;
    stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    if is_empty { stream.ended = true; }
    return StreamWriteStatus.Ok;
}

fn stream_begin_http3(stream: ResponseStream&, res: http::Response&) -> StreamWriteStatus {
    if res.status_code == 0 { res.status_code = rfc::STATUS_OK; }
    let is_empty = rfc::is_empty_body_status(res.status_code);
    var qpack_block: u8[..8192] = [];
    // RFC 9204 Section 4.5.1: Static-only QPACK prefix (RIC = 0, DeltaBase = 0).
    guard qpack_block.try_push(0x00) && qpack_block.try_push(0x00) else { return StreamWriteStatus.Error; }
    var status_str: u8[..16] = [];
    res.status_code.format_i64_dec(status_str);
    guard http3::encode_qpack_field(qpack_block, ":status", status_str[..], true) else {
        return StreamWriteStatus.Error;
    }
    if stream.server_name.len > 0 && !http::has_header(res, "server") {
        let _ = http3::encode_qpack_field(qpack_block, "server", stream.server_name[..], true);
    }
    for &e in res.headers.entries {
        let name = http::entry_name(res.headers, e);
        let val = http::entry_value(res.headers, e);
        guard !stream_is_hop_by_hop_header(name) else { continue; }
        var lower: u8[..256] = [];
        guard name.len > 0 && name.len <= lower.cap else { return StreamWriteStatus.Error; }
        name.to_lower_ascii(lower);
        guard http3::encode_qpack_field(qpack_block, lower[..], val, true) else {
            return StreamWriteStatus.Error;
        }
    }
    var h3_hdr: u8[..16] = [];
    guard http3::encode_frame_header(h3_hdr, rfc::H3_FRAME_HEADERS, qpack_block.len as u64) else {
        return StreamWriteStatus.Error;
    }
    let st = stream_emit_wire_parts(stream, h3_hdr[..], qpack_block[..]);
    guard st == StreamWriteStatus.Ok else { return st; }
    stream.headers_sent = true;
    stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    if is_empty {
        let _, _ = quic::on_send_data(stream.quic_stream, stream.quic_stream.bytes_sent, 0, true);
        stream.h3_fin_emitted = true;
        stream.ended = true;
    }
    return StreamWriteStatus.Ok;
}

// ---- HTTP/1.1 Streaming Body Writer (Zero 16 KB Ceiling + Partial Offset) --

fn stream_h1_queue_crlf(stream: ResponseStream&) -> StreamWriteStatus {
    stream.h1_need_chunk_crlf = false;
    let w = cork_send_raw(stream.cork.sock_fd, "\r\n");
    if w == 2 { return StreamWriteStatus.Ok; }
    if w == 1 {
        let _ = stream.h1_pending_ctrl.try_set("\n");
        stream.h1_pending_ctrl_pos = 0;
        return StreamWriteStatus.WouldBlock;
    }
    if w == CORK_WOULD_BLOCK || w == 0 {
        let _ = stream.h1_pending_ctrl.try_set("\r\n");
        stream.h1_pending_ctrl_pos = 0;
        return StreamWriteStatus.WouldBlock;
    }
    stream.closed = true;
    return StreamWriteStatus.Error;
}

fn stream_h1_continue_partial_chunk(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    let to_send = min(chunk.len, stream.h1_in_chunk_rem);
    let sent = cork_send_raw(stream.cork.sock_fd, chunk[..to_send]);
    if sent == CORK_WOULD_BLOCK || sent == 0 { return 0, StreamWriteStatus.WouldBlock; }
    if sent < 0 {
        stream.closed = true;
        return 0, StreamWriteStatus.Error;
    }
    let sent_i64 = sent as i64;
    stream.h1_in_chunk_rem = core::sub_sat_i64(stream.h1_in_chunk_rem, sent_i64);
    stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, sent_i64 as u64);
    if stream.h1_in_chunk_rem > 0 {
        return sent_i64, StreamWriteStatus.WouldBlock;
    }
    if stream.h1_need_chunk_crlf {
        let crlf_st = stream_h1_queue_crlf(stream);
        if crlf_st != StreamWriteStatus.Ok { return sent_i64, crlf_st; }
    }
    return sent_i64, StreamWriteStatus.Ok;
}

fn stream_h1_write_fixed(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    var rem_allowed = chunk.len;
    if stream.h1_content_length >= 0 {
        let already = stream.body_bytes_sent as i64;
        guard already <= stream.h1_content_length else { return 0, StreamWriteStatus.Error; }
        let cl_rem = core::sub_sat_i64(stream.h1_content_length, already);
        guard chunk.len <= cl_rem else { return 0, StreamWriteStatus.Error; }
        rem_allowed = min(chunk.len, cl_rem);
    }
    if stream.cork.sock_fd <= 0 {
        let avail = stream.cork.buffer.cork_available();
        guard avail > 0 else { return 0, StreamWriteStatus.WouldBlock; }
        let take = min(rem_allowed, avail);
        let _ = stream.cork.buffer.cork_write(chunk[..take]);
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, take as u64);
        return take, if take < rem_allowed { StreamWriteStatus.WouldBlock } else { StreamWriteStatus.Ok };
    }
    let w = server_cork_write(stream.cork, chunk[..rem_allowed]);
    if w == CORK_WOULD_BLOCK || w == 0 { return 0, StreamWriteStatus.WouldBlock; }
    if w < 0 {
        stream.closed = true;
        return 0, StreamWriteStatus.Error;
    }
    let w_i64 = w as i64;
    stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, w_i64 as u64);
    return w_i64, if w_i64 < rem_allowed { StreamWriteStatus.WouldBlock } else { StreamWriteStatus.Ok };
}

fn stream_h1_write_chunked_sans_io(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    var offset: i64 = 0;
    while offset < chunk.len {
        let avail = stream.cork.buffer.cork_available();
        // Reserve up to 12 bytes for `<hex>\r\n` + `\r\n` framing overhead.
        guard avail > 12 else { return offset, StreamWriteStatus.WouldBlock; }
        let max_pay = core::sub_sat_i64(avail, 12);
        let take = min(core::sub_sat_i64(chunk.len, offset), max_pay);
        var chdr: u8[..24] = [];
        (take as u64).format_u64_hex(chdr, false);
        chdr.append("\r\n");
        let _ = stream.cork.buffer.cork_write(chdr[..]);
        let _ = stream.cork.buffer.cork_write(chunk[offset..core::add_sat_i64(offset, take)]);
        let _ = stream.cork.buffer.cork_write("\r\n");
        offset = core::add_sat_i64(offset, take);
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, take as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    }
    return offset, StreamWriteStatus.Ok;
}

fn stream_h1_write_chunked_direct(
    stream: ResponseStream&,
    chdr:   const u8[:],
    sub:    const u8[:],
) -> i64, StreamWriteStatus {
    let w1 = cork_send_raw2(stream.cork.sock_fd, chdr, sub);
    if w1 == CORK_WOULD_BLOCK || w1 == 0 { return 0, StreamWriteStatus.WouldBlock; }
    if w1 < 0 {
        stream.closed = true;
        return 0, StreamWriteStatus.Error;
    }
    let sent = w1 as i64;
    if sent < chdr.len {
        let _ = stream.h1_pending_ctrl.try_set(chdr[sent..]);
        stream.h1_pending_ctrl_pos = 0;
        stream.h1_in_chunk_rem = sub.len;
        stream.h1_need_chunk_crlf = true;
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
        return 0, StreamWriteStatus.WouldBlock;
    }
    let body_sent = core::sub_sat_i64(sent, chdr.len);
    stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, body_sent as u64);
    stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    if body_sent < sub.len {
        stream.h1_in_chunk_rem = core::sub_sat_i64(sub.len, body_sent);
        stream.h1_need_chunk_crlf = true;
        return body_sent, StreamWriteStatus.WouldBlock;
    }
    let crlf_st = stream_h1_queue_crlf(stream);
    if crlf_st == StreamWriteStatus.Error { return body_sent, StreamWriteStatus.Error; }
    return body_sent, StreamWriteStatus.Ok;
}

fn stream_write_http1(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    let ctrl_st = stream_flush_pending_ctrl(stream);
    guard ctrl_st == StreamWriteStatus.Ok else { return 0, ctrl_st; }
    if !stream.h1_chunked { return stream_h1_write_fixed(stream, chunk); }
    if stream.cork.sock_fd <= 0 { return stream_h1_write_chunked_sans_io(stream, chunk); }

    var offset: i64 = 0;
    if stream.h1_in_chunk_rem > 0 {
        let n_cont, st_cont = stream_h1_continue_partial_chunk(stream, chunk);
        offset = core::add_sat_i64(offset, n_cont);
        if st_cont != StreamWriteStatus.Ok || offset >= chunk.len { return offset, st_cont; }
    }
    if stream.h1_need_chunk_crlf {
        let st_cr = stream_h1_queue_crlf(stream);
        guard st_cr == StreamWriteStatus.Ok else { return offset, st_cr; }
    }

    let sub = chunk[offset..];
    var chdr: u8[..24] = [];
    (sub.len as u64).format_u64_hex(chdr, false);
    chdr.append("\r\n");
    let frame_len = core::add_sat_i64(core::add_sat_i64(chdr.len, sub.len), 2);
    if frame_len <= stream.cork.buffer.cork_available() {
        let _ = stream.cork.buffer.cork_write(chdr[..]);
        let _ = stream.cork.buffer.cork_write(sub);
        let _ = stream.cork.buffer.cork_write("\r\n");
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, sub.len as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
        return chunk.len, StreamWriteStatus.Ok;
    }
    let fl_st = stream_flush(stream);
    guard fl_st == StreamWriteStatus.Ok else { return offset, fl_st; }
    if frame_len < core::CORK_BUFFER_CAP {
        let _ = stream.cork.buffer.cork_write(chdr[..]);
        let _ = stream.cork.buffer.cork_write(sub);
        let _ = stream.cork.buffer.cork_write("\r\n");
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, sub.len as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
        return chunk.len, StreamWriteStatus.Ok;
    }
    let n_dir, st_dir = stream_h1_write_chunked_direct(stream, chdr[..], sub);
    return core::add_sat_i64(offset, n_dir), st_dir;
}

// ---- HTTP/2 Streaming Body Writer (Two-Level Flow Control) -----------------

fn stream_write_http2(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    var offset: i64 = 0;
    let max_frame = clamp(stream.h2_max_frame_size as i64, 16384, 16777215);
    while offset < chunk.len {
        let quota = min(max(0, stream.h2_conn_send_window), max(0, stream.h2_stream_send_window));
        if quota <= 0 { return offset, StreamWriteStatus.WouldBlock; }
        let rem = core::sub_sat_i64(chunk.len, offset);
        var flen = min(min(rem, max_frame), quota);
        if stream.cork.sock_fd <= 0 {
            let avail = stream.cork.buffer.cork_available();
            if avail <= rfc::H2_FRAME_HEADER_LEN { return offset, StreamWriteStatus.WouldBlock; }
            flen = min(flen, core::sub_sat_i64(avail, rfc::H2_FRAME_HEADER_LEN));
        }
        let fhdr = http2::FrameHeader {
            length:     flen as u32,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      0,
            stream_id:  stream.h2_stream_id,
        };
        var raw_hdr: u8[9] = [0; 9];
        http2::encode_frame_header(fhdr, raw_hdr);
        let end_off = core::add_sat_i64(offset, flen);
        let st = stream_emit_wire_parts(stream, raw_hdr[..], chunk[offset..end_off]);
        guard st == StreamWriteStatus.Ok else { return offset, st; }
        // RFC 9113 Section 6.9.1: Atomically deduct connection and stream send windows.
        stream.h2_conn_send_window = core::sub_sat_i64(stream.h2_conn_send_window, flen);
        stream.h2_stream_send_window = core::sub_sat_i64(stream.h2_stream_send_window, flen);
        offset = end_off;
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, flen as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    }
    return offset, StreamWriteStatus.Ok;
}

// ---- HTTP/3 Streaming Body Writer (QUIC Flow Control) ----------------------

fn stream_write_http3(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    var offset: i64 = 0;
    while offset < chunk.len {
        let conn_cr = quic::remaining_conn_credit(stream.quic_flow);
        let strm_cr = quic::remaining_stream_credit(stream.quic_stream);
        let credit = min(min(conn_cr, strm_cr), 0x7FFFFFFF) as i64;
        if credit <= 0 { return offset, StreamWriteStatus.WouldBlock; }
        let rem = core::sub_sat_i64(chunk.len, offset);
        var flen = min(rem, credit);
        if stream.cork.sock_fd <= 0 {
            let avail = stream.cork.buffer.cork_available();
            // Reserve up to 10 bytes for H3_FRAME_DATA type + length VarInts.
            if avail <= 10 { return offset, StreamWriteStatus.WouldBlock; }
            flen = min(flen, core::sub_sat_i64(avail, 10));
        }
        var h3_hdr: u8[..16] = [];
        guard http3::encode_frame_header(h3_hdr, rfc::H3_FRAME_DATA, flen as u64) else {
            return offset, StreamWriteStatus.Error;
        }
        let end_off = core::add_sat_i64(offset, flen);
        let st = stream_emit_wire_parts(stream, h3_hdr[..], chunk[offset..end_off]);
        guard st == StreamWriteStatus.Ok else { return offset, st; }
        guard quic::record_send(
            stream.quic_flow, stream.quic_stream, stream.quic_stream.bytes_sent, flen as u64,
        ) else {
            return offset, StreamWriteStatus.Error;
        }
        offset = end_off;
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, flen as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    }
    return offset, StreamWriteStatus.Ok;
}

// ---- Public Unified Protocol-Agnostic Streaming API ------------------------

// Emits response status and headers for HTTP/1.1, HTTP/2, or HTTP/3 without buffering the body.
fn stream_begin(stream: ResponseStream&, res: http::Response&) -> StreamWriteStatus {
    guard !stream.closed else { return StreamWriteStatus.Closed; }
    guard !stream.headers_sent else { return StreamWriteStatus.Error; }
    return match stream.protocol {
        Http1 => stream_begin_http1(stream, res),
        Http2 => stream_begin_http2(stream, res),
        Http3 => stream_begin_http3(stream, res),
    };
}

// Emits payload bytes under protocol flow-control and socket backpressure.
// Returns `(bytes_accepted, status)` so callers resume cleanly from `chunk[bytes_accepted..]` on `WouldBlock`.
fn stream_write(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    guard !stream.closed && !stream.ended else { return 0, StreamWriteStatus.Closed; }
    guard stream.headers_sent else { return 0, StreamWriteStatus.Error; }
    guard chunk.len > 0 else { return 0, StreamWriteStatus.Ok; }
    if stream.protocol == StreamProtocol.Http1 {
        return stream_write_http1(stream, chunk);
    }
    if stream.protocol == StreamProtocol.Http2 {
        return stream_write_http2(stream, chunk);
    }
    return stream_write_http3(stream, chunk);
}

// Idempotently terminates the response stream (`0\r\n\r\n` for H1, `END_STREAM` for H2, QUIC `FIN` for H3).
fn stream_end(stream: ResponseStream&) -> StreamWriteStatus {
    guard !stream.closed else { return StreamWriteStatus.Closed; }
    if stream.ended { return stream_flush(stream); }
    guard stream.headers_sent else { return StreamWriteStatus.Error; }
    if stream.protocol == StreamProtocol.Http1 {
        let ctrl_st = stream_flush_pending_ctrl(stream);
        guard ctrl_st == StreamWriteStatus.Ok else { return ctrl_st; }
        guard stream.h1_in_chunk_rem == 0 else { return StreamWriteStatus.Error; }
        if stream.h1_need_chunk_crlf {
            let cr_st = stream_h1_queue_crlf(stream);
            guard cr_st == StreamWriteStatus.Ok else { return cr_st; }
        }
        if stream.h1_chunked {
            let term_st = stream_emit_wire_parts(stream, "0\r\n\r\n", "");
            guard term_st == StreamWriteStatus.Ok else { return term_st; }
        }
        stream.ended = true;
        return stream_flush(stream);
    }
    if stream.protocol == StreamProtocol.Http2 {
        let fhdr = http2::FrameHeader {
            length:     0,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      rfc::H2_FLAG_END_STREAM,
            stream_id:  stream.h2_stream_id,
        };
        var raw_hdr: u8[9] = [0; 9];
        http2::encode_frame_header(fhdr, raw_hdr);
        let st = stream_emit_wire_parts(stream, raw_hdr[..], "");
        guard st == StreamWriteStatus.Ok else { return st; }
        stream.ended = true;
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
        return stream_flush(stream);
    }
    let _, ok_fin = quic::on_send_data(stream.quic_stream, stream.quic_stream.bytes_sent, 0, true);
    guard ok_fin else { return StreamWriteStatus.Error; }
    stream.h3_fin_emitted = true;
    stream.ended = true;
    return stream_flush(stream);
}

// Applies connection-level and stream-level flow-control credit increments
// (HTTP/2 WINDOW_UPDATE deltas or HTTP/3 QUIC MAX_DATA / MAX_STREAM_DATA deltas).
fn stream_on_window_update(stream: ResponseStream&, conn_delta: i64, stream_delta: i64) {
    if stream.protocol == StreamProtocol.Http2 {
        if conn_delta > 0 {
            stream.h2_conn_send_window = min(
                core::add_sat_i64(stream.h2_conn_send_window, conn_delta),
                rfc::H2_MAX_WINDOW_SIZE,
            );
        }
        if stream_delta > 0 {
            stream.h2_stream_send_window = min(
                core::add_sat_i64(stream.h2_stream_send_window, stream_delta),
                rfc::H2_MAX_WINDOW_SIZE,
            );
        }
        return;
    }
    if stream.protocol == StreamProtocol.Http3 {
        if conn_delta > 0 {
            let next_conn = min(
                core::add_sat_u64(stream.quic_flow.max_data_remote, conn_delta as u64),
                rfc::QUIC_VARINT_MAX,
            );
            let _ = quic::update_remote_max_data(stream.quic_flow, next_conn);
        }
        if stream_delta > 0 {
            let next_strm = min(
                core::add_sat_u64(stream.quic_stream.send_max_data, stream_delta as u64),
                rfc::QUIC_VARINT_MAX,
            );
            let _ = quic::update_send_max_data(stream.quic_stream, next_strm);
        }
    }
}

// Applies absolute monotonic QUIC MAX_DATA and MAX_STREAM_DATA limits (RFC 9000 Sections 19.9 and 19.10).
fn stream_on_quic_max_data(stream: ResponseStream&, new_max_data: u64, new_max_stream_data: u64) {
    guard stream.protocol == StreamProtocol.Http3 else { return; }
    let _ = quic::update_remote_max_data(stream.quic_flow, new_max_data);
    let _ = quic::update_send_max_data(stream.quic_stream, new_max_stream_data);
}

// Queries remaining writable payload credit allowed by flow control (and fixed Content-Length for H1).
fn stream_can_write(stream: const ResponseStream&) -> i64 {
    guard !stream.closed && !stream.ended else { return 0; }
    if stream.protocol == StreamProtocol.Http2 {
        return min(max(0, stream.h2_conn_send_window), max(0, stream.h2_stream_send_window));
    }
    if stream.protocol == StreamProtocol.Http3 {
        let conn_cr = quic::remaining_conn_credit(stream.quic_flow);
        let strm_cr = quic::remaining_stream_credit(stream.quic_stream);
        return min(min(conn_cr, strm_cr), 0x7FFFFFFF) as i64;
    }
    if !stream.h1_chunked && stream.h1_content_length >= 0 {
        return core::sub_sat_i64(stream.h1_content_length, stream.body_bytes_sent as i64);
    }
    if stream.cork.sock_fd <= 0 {
        return max(0, core::sub_sat_i64(stream.cork.buffer.cork_available(), 12));
    }
    return 0x7FFFFFFF;
}
