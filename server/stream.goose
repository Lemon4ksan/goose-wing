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
import .stream_internal;

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
    return server_internal::stream_flush_pending_ctrl(stream);
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

// ---- Public Unified Protocol-Agnostic Streaming API ------------------------

// Emits response status and headers for HTTP/1.1, HTTP/2, or HTTP/3 without buffering the body.
fn stream_begin(stream: ResponseStream&, res: http::Response&) -> StreamWriteStatus {
    guard !stream.closed else { return StreamWriteStatus.Closed; }
    guard !stream.headers_sent else { return StreamWriteStatus.Error; }
    return match stream.protocol {
        Http1 => server_internal::stream_begin_http1(stream, res),
        Http2 => server_internal::stream_begin_http2(stream, res),
        Http3 => server_internal::stream_begin_http3(stream, res),
    };
}

// Emits payload bytes under protocol flow-control and socket backpressure.
// Returns `(bytes_accepted, status)` so callers resume cleanly from `chunk[bytes_accepted..]` on `WouldBlock`.
fn stream_write(stream: ResponseStream&, chunk: const u8[:]) -> i64, StreamWriteStatus {
    guard !stream.closed && !stream.ended else { return 0, StreamWriteStatus.Closed; }
    guard stream.headers_sent else { return 0, StreamWriteStatus.Error; }
    guard chunk.len > 0 else { return 0, StreamWriteStatus.Ok; }
    if stream.protocol == StreamProtocol.Http1 {
        return server_internal::stream_write_http1(stream, chunk);
    }
    if stream.protocol == StreamProtocol.Http2 {
        return server_internal::stream_write_http2(stream, chunk);
    }
    return server_internal::stream_write_http3(stream, chunk);
}

// Idempotently terminates the response stream (`0\r\n\r\n` for H1, `END_STREAM` for H2, QUIC `FIN` for H3).
fn stream_end(stream: ResponseStream&) -> StreamWriteStatus {
    guard !stream.closed else { return StreamWriteStatus.Closed; }
    if stream.ended { return stream_flush(stream); }
    guard stream.headers_sent else { return StreamWriteStatus.Error; }
    if stream.protocol == StreamProtocol.Http1 {
        let ctrl_st = server_internal::stream_flush_pending_ctrl(stream);
        guard ctrl_st == StreamWriteStatus.Ok else { return ctrl_st; }
        guard stream.h1_in_chunk_rem == 0 else { return StreamWriteStatus.Error; }
        if stream.h1_need_chunk_crlf {
            let cr_st = server_internal::stream_h1_queue_crlf(stream);
            guard cr_st == StreamWriteStatus.Ok else { return cr_st; }
        }
        if stream.h1_chunked {
            let term_st = server_internal::stream_emit_wire_parts(stream, "0\r\n\r\n", "");
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
        let st = server_internal::stream_emit_wire_parts(stream, raw_hdr[..], "");
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
