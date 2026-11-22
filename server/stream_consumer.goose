// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Streaming HTTP/1.1 request body consumer and asynchronous backpressure / abort context
// (uWebSockets onData / onWritable / onAborted pattern).
namespace server;

import std;
import core;
import rfc.h2;
import rfc.h3_quic;
import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import http2.framing;
import quic.packet;
import .h1_codec;
import .internal;
import .h1_codec_internal;
import .stream_internal;

// State of a streaming HTTP/1.1 request body consumer (uWebSockets onData / onDataV2 pattern)
struct HttpStreamConsumer {
    content_length:    i64  = -1,
    bytes_received:    i64  = 0,
    header_end_idx:    i64  = 0,
    is_chunked:        bool = false,
    is_headers_parsed: bool = false,
    is_finished:       bool = false,
}

// Parses request headers and prepares a streaming body reader without buffering the entire body.
// Returns (ok, header_end_offset).
fn begin_http_stream_request<Req>(
    wire:     const u8[:],
    out_req:  Req&,
    consumer: HttpStreamConsumer&,
) -> bool, i64 {
    consumer = HttpStreamConsumer { .. };
    var committed = false;
    defer if !committed {
        consumer = HttpStreamConsumer { .. };
        server_internal::clear_request_headers_state(out_req);
        out_req.method.clear();
        out_req.url.clear();
        out_req.is_http10 = false;
    };

    var tracker = http::HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard server_internal::parse_http1_request_headers(wire, out_req, tracker, body_start_idx) else {
        return false, 0;
    }

    consumer.header_end_idx = body_start_idx;
    consumer.is_headers_parsed = true;

    let has_te = (tracker.mask & http::HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (tracker.mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0;

    if has_te {
        // RFC 9112 Section 6.1: A server MUST NOT apply Transfer-Encoding to an HTTP/1.0 request
        guard !out_req.is_http10 && server_internal::validate_span_te_header(out_req.headers, tracker.te_idx) else {
            return false, 0;
        }
        consumer.is_chunked = true;
        consumer.content_length = -1;
    } else if has_cl {
        guard tracker.parsed_cl >= 0 && tracker.parsed_cl <= MAX_SERVER_BODY_LIMIT else {
            return false, 0;
        }
        consumer.is_chunked = false;
        consumer.content_length = tracker.parsed_cl;
        if consumer.content_length == 0 {
            consumer.is_finished = true;
        }
    } else {
        consumer.is_chunked = false;
        consumer.content_length = 0;
        consumer.is_finished = true;
    }

    committed = true;
    return true, body_start_idx;
}

// Feeds incoming wire slice chunks to an onData callback (uWebSockets onData(chunk, is_last) pattern).
// Invokes `Callback(chunk, is_last)` as data arrives across packet boundaries.
// Returns (consumed_bytes, is_last, ok).
fn feed_http_stream_chunk<Callback: fn(const u8[:], bool)>(
    consumer: HttpStreamConsumer&,
    incoming: const u8[:],
) -> i64, bool, bool {
    let is_empty_done = consumer.is_headers_parsed && consumer.is_finished &&
        max(consumer.content_length, consumer.bytes_received) == 0;
    if is_empty_done {
        Callback("", true);
        return 0, true, true;
    }
    guard consumer.is_headers_parsed && !consumer.is_finished else { return 0, false, false; }
    guard incoming.len > 0 else { return 0, false, true; }

    if consumer.content_length >= 0 {
        let chunk_len, is_last, ok = server_internal::feed_fixed_length_http_stream(consumer, incoming);
        if chunk_len > 0 {
            Callback(incoming[..chunk_len], is_last);
        }
        return chunk_len, is_last, ok;
    }

    var cursor: i64 = 0;
    while cursor < incoming.len {
        let data_slice, has_data, is_last, ok = server_internal::step_chunked_http_stream_frame(
            consumer,
            incoming,
            cursor,
        );
        guard ok else {
            consumer.is_headers_parsed = false;
            consumer.is_finished = true;
            return cursor, false, false;
        }
        guard has_data || is_last else { return cursor, false, true; }
        Callback(data_slice, is_last);
        if is_last {
            return cursor, true, true;
        }
    }
    return cursor, false, true;
}

// Connection lifecycle context for asynchronous streaming backpressure and abort notifications
// (uWebSockets res->onWritable & res->onAborted pattern).
struct HttpAsyncContext {
    sock_fd:          i64  = -1,
    is_aborted:       bool = false,
    is_backpressured: bool = false,
    total_written:    u64  = 0,
    user_tag:         u64  = 0,
    in_use:           bool = false,
}

// Dispatches a client abort event if the client disconnected during async processing
fn notify_client_aborted<Callback: fn(i64, u64)>(
    ctx: HttpAsyncContext&,
) {
    if !ctx.is_aborted && ctx.in_use {
        ctx.is_aborted = true;
        Callback(ctx.sock_fd, ctx.user_tag);
    }
}

// Dispatches a writable notification when socket drains after backpressure (uWebSockets onWritable)
fn notify_socket_writable<Callback: fn(i64, u64, u64) -> bool>(
    ctx: HttpAsyncContext&,
) -> bool {
    guard ctx.in_use && !ctx.is_aborted else { return false; }
    let ok = Callback(ctx.sock_fd, ctx.total_written, ctx.user_tag);
    if ok {
        ctx.is_backpressured = false;
    }
    return ok;
}

// ---- Request Body Streaming Backpressure (H1 / H2 / H3 Credit Control) ----

enum WindowProtocol {
    Http1,
    Http2,
    Http3,
}

struct WindowReplenishment {
    should_update_stream: bool = false,
    should_update_conn:   bool = false,
    stream_increment:     u64  = 0,
    conn_increment:       u64  = 0,
}

// Pull-rate flow-control tracker linking consumer consumption to HTTP/2 WINDOW_UPDATE
// (RFC 9113 Section 6.9) and QUIC MAX_STREAM_DATA / MAX_DATA (RFC 9000 Section 4.1).
// Credit is replenished strictly after application bytes are consumed, preventing buffer growth.
struct RequestStreamWindow {
    protocol:              WindowProtocol = WindowProtocol.Http2,
    stream_id:             u64            = 0,
    stream_window_size:    u64            = 65536,
    conn_window_size:      u64            = 65536,
    bytes_received:        u64            = 0,
    bytes_consumed:        u64            = 0,
    conn_bytes_received:   u64            = 0,
    conn_bytes_consumed:   u64            = 0,
    advertised_stream_max: u64            = 65536,
    advertised_conn_max:   u64            = 65536,
    unacked_stream_bytes:  u64            = 0,
    unacked_conn_bytes:    u64            = 0,
    update_threshold_pct:  u32            = 50,
    is_backpressured:      bool           = false,
}

fn make_request_stream_window(
    protocol:             WindowProtocol,
    stream_id:            u64,
    stream_window:        u64 = 65536,
    conn_window:          u64 = 65536,
    update_threshold_pct: u32 = 50,
) -> RequestStreamWindow {
    let eff_stream = max(stream_window, 1);
    let eff_conn = max(conn_window, eff_stream);
    let eff_pct = clamp(update_threshold_pct as i64, 1, 100) as u32;
    return RequestStreamWindow {
        protocol:              protocol,
        stream_id:             stream_id,
        stream_window_size:    eff_stream,
        conn_window_size:      eff_conn,
        advertised_stream_max: eff_stream,
        advertised_conn_max:   eff_conn,
        update_threshold_pct:  eff_pct,
        ..
    };
}

// Records inbound wire payload bytes against advertised receive windows without replenishing credit.
// Returns `false` if the peer violated advertised connection or stream flow-control limits.
fn request_window_on_ingress(win: RequestStreamWindow&, received_bytes: u64) -> bool {
    guard received_bytes > 0 else { return true; }
    let next_strm = core::add_sat_u64(win.bytes_received, received_bytes);
    let next_conn = core::add_sat_u64(win.conn_bytes_received, received_bytes);
    guard next_strm <= win.advertised_stream_max && next_conn <= win.advertised_conn_max else {
        win.is_backpressured = true;
        return false;
    }
    win.bytes_received = next_strm;
    win.conn_bytes_received = next_conn;
    let rem_strm = core::sub_sat_u64(win.advertised_stream_max, win.bytes_received);
    let rem_conn = core::sub_sat_u64(win.advertised_conn_max, win.conn_bytes_received);
    win.is_backpressured = (rem_strm == 0) || (rem_conn == 0);
    return true;
}

// Returns remaining peer-sendable receive window credit (`min(stream_rem, conn_rem)`).
fn request_window_available(win: const RequestStreamWindow&) -> u64 {
    let rem_strm = core::sub_sat_u64(win.advertised_stream_max, win.bytes_received);
    let rem_conn = core::sub_sat_u64(win.advertised_conn_max, win.conn_bytes_received);
    return min(rem_strm, rem_conn);
}

// Records bytes pulled by the application consumer and emits replenishment commands once
// consumed bytes cross the configured threshold (`update_threshold_pct`).
fn request_window_on_consume(win: RequestStreamWindow&, consumed_bytes: u64) -> WindowReplenishment {
    var rep = WindowReplenishment { .. };
    guard consumed_bytes > 0 else { return rep; }
    let unread_strm = core::sub_sat_u64(win.bytes_received, win.bytes_consumed);
    let take = min(consumed_bytes, unread_strm);
    guard take > 0 else { return rep; }

    win.bytes_consumed = core::add_sat_u64(win.bytes_consumed, take);
    win.conn_bytes_consumed = core::add_sat_u64(win.conn_bytes_consumed, take);
    win.unacked_stream_bytes = core::add_sat_u64(win.unacked_stream_bytes, take);
    win.unacked_conn_bytes = core::add_sat_u64(win.unacked_conn_bytes, take);

    let strm_val, strm_ok = server_internal::replenish_single_window(
        win.protocol,
        win.stream_window_size,
        win.update_threshold_pct,
        win.unacked_stream_bytes,
        win.advertised_stream_max,
    );
    if strm_ok {
        rep.should_update_stream = true;
        rep.stream_increment = strm_val;
    }

    let conn_val, conn_ok = server_internal::replenish_single_window(
        win.protocol,
        win.conn_window_size,
        win.update_threshold_pct,
        win.unacked_conn_bytes,
        win.advertised_conn_max,
    );
    if conn_ok {
        rep.should_update_conn = true;
        rep.conn_increment = conn_val;
    }

    win.is_backpressured = request_window_available(win) == 0;
    return rep;
}

// Encodes HTTP/2 connection (stream 0) and stream WINDOW_UPDATE frames (RFC 9113 Section 6.9).
fn request_window_encode_h2_updates<B>(
    win: const RequestStreamWindow&,
    rep: const WindowReplenishment&,
    out: B&,
) -> bool {
    let saved = out.len;
    var committed = false;
    defer if !committed { out.resize(saved); };
    if rep.should_update_conn && rep.conn_increment > 0 {
        let fhdr = http2::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id:  0,
        };
        var raw_hdr: u8[9] = [0; 9];
        http2::encode_frame_header(fhdr, raw_hdr);
        guard out.try_append(raw_hdr[..]) else { return false; }
        let inc = (min(rep.conn_increment, rfc::H2_MAX_WINDOW_SIZE as u64) as u32) & 0x7FFFFFFF;
        var inc_be: u8[4] = [0; 4];
        core::write_be_u32_at(inc_be[..], 0, inc);
        guard out.try_append(inc_be[..]) else { return false; }
    }
    if rep.should_update_stream && rep.stream_increment > 0 && win.stream_id > 0 {
        let fhdr = http2::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id:  (win.stream_id as u32) & 0x7FFFFFFF,
        };
        var raw_hdr: u8[9] = [0; 9];
        http2::encode_frame_header(fhdr, raw_hdr);
        guard out.try_append(raw_hdr[..]) else { return false; }
        let inc = (min(rep.stream_increment, rfc::H2_MAX_WINDOW_SIZE as u64) as u32) & 0x7FFFFFFF;
        var inc_be: u8[4] = [0; 4];
        core::write_be_u32_at(inc_be[..], 0, inc);
        guard out.try_append(inc_be[..]) else { return false; }
    }
    committed = true;
    return true;
}

// Encodes QUIC MAX_DATA (0x10) and MAX_STREAM_DATA (0x11) frames (RFC 9000 Sections 19.9 and 19.10).
fn request_window_encode_quic_updates<B>(
    win: const RequestStreamWindow&,
    rep: const WindowReplenishment&,
    out: B&,
) -> bool {
    let saved = out.len;
    var committed = false;
    defer if !committed { out.resize(saved); };
    if rep.should_update_conn && rep.conn_increment > 0 {
        guard quic::encode_varint(rfc::QUIC_FRAME_MAX_DATA, out) &&
            quic::encode_varint(rep.conn_increment, out) else {
            return false;
        }
    }
    if rep.should_update_stream && rep.stream_increment > 0 {
        guard quic::encode_varint(rfc::QUIC_FRAME_MAX_STREAM_DATA, out) &&
            quic::encode_varint(win.stream_id, out) &&
            quic::encode_varint(rep.stream_increment, out) else {
            return false;
        }
    }
    committed = true;
    return true;
}
