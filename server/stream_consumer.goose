// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Streaming HTTP/1.1 request body consumer and asynchronous backpressure / abort context
// (uWebSockets onData / onWritable / onAborted pattern).
namespace wing;

import std;
import core from "..";
import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import .h1_codec;

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
    consumer.is_headers_parsed = false;
    consumer.is_finished = false;
    consumer.bytes_received = 0;

    var tracker = HeaderPresenceTracker { .. };
    var body_start_idx: i64 = 0;
    guard parse_http1_request_headers(wire, out_req, tracker, body_start_idx) else {
        return false, 0;
    }

    consumer.header_end_idx = body_start_idx;
    consumer.is_headers_parsed = true;

    let has_te = (tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0;

    if has_te {
        guard validate_span_te_header(out_req.headers, tracker.te_idx) else {
            consumer.is_headers_parsed = false;
            clear_request_headers_state(out_req);
            return false, 0;
        }
        consumer.is_chunked = true;
        consumer.content_length = -1;
    } else if has_cl {
        guard tracker.parsed_cl >= 0 && tracker.parsed_cl <= MAX_SERVER_BODY_LIMIT else {
            consumer.is_headers_parsed = false;
            clear_request_headers_state(out_req);
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

    return true, body_start_idx;
}

inline fn peek_terminal_zero_chunk(incoming: const u8[:], cursor: i64&) -> bool {
    guard cursor < incoming.len else { return false; }
    var peek_cur = cursor;
    var next_sz: u64 = 1;
    let next_err = read_chunk_size_line(incoming, peek_cur, next_sz);
    guard next_err == ChunkedDecodeError.None && next_sz == 0 else { return false; }
    let tr_err = parse_chunked_trailers(incoming, peek_cur);
    guard tr_err == ChunkedDecodeError.None else { return false; }
    cursor = peek_cur;
    return true;
}

inline fn feed_fixed_length_http_stream(
    consumer: HttpStreamConsumer&,
    incoming: const u8[:],
) -> i64, bool, bool {
    let remaining = core::sub_sat_i64(consumer.content_length, consumer.bytes_received);
    guard remaining > 0 else {
        consumer.is_finished = true;
        return 0, true, true;
    }

    let chunk_len = min(incoming.len, remaining);
    consumer.bytes_received = core::add_sat_i64(consumer.bytes_received, chunk_len);
    let is_last = consumer.bytes_received >= consumer.content_length;
    if is_last {
        consumer.is_finished = true;
    }
    return chunk_len, is_last, true;
}

// Steps one frame of a chunked HTTP stream at `cursor`, returning `(data_slice, has_data, is_last, ok)`.
// On partial input (`UnexpectedEof`), returns `has_data = false, is_last = false, ok = true` and leaves `cursor`
// at the start of the incomplete chunk.
//
// Example:
//   incoming = "5\r\nhello\r\n0\r\n\r\n", cursor = 0
//   returns: data_slice = "hello", has_data = true, is_last = true, ok = true, cursor = 15
fn step_chunked_http_stream_frame(
    consumer: HttpStreamConsumer&,
    incoming: const u8[:],
    cursor:   i64&,
) -> const u8[:], bool, bool, bool {
    let chunk_start = cursor;
    var chunk_size: u64 = 0;
    let line_err = read_chunk_size_line(incoming, cursor, chunk_size);
    if line_err == ChunkedDecodeError.UnexpectedEof {
        cursor = chunk_start;
        return "", false, false, true;
    }
    guard line_err == ChunkedDecodeError.None && chunk_size <= (MAX_SERVER_BODY_LIMIT as u64) else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    if chunk_size == 0 {
        let tr_err = parse_chunked_trailers(incoming, cursor);
        if tr_err == ChunkedDecodeError.UnexpectedEof {
            cursor = chunk_start;
            return "", false, false, true;
        }
        guard tr_err == ChunkedDecodeError.None else {
            cursor = chunk_start;
            return "", false, false, false;
        }
        consumer.is_finished = true;
        return "", false, true, true;
    }
    let csize = chunk_size as i64;
    let data_end = core::add_sat_i64(cursor, csize);
    let frame_end = core::add_sat_i64(data_end, 2);
    if frame_end > incoming.len {
        cursor = chunk_start;
        return "", false, false, true;
    }
    guard incoming[data_end] == '\r' && incoming[core::add_sat_i64(data_end, 1)] == '\n' else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    let next_received = core::add_sat_i64(consumer.bytes_received, csize);
    guard next_received <= MAX_SERVER_BODY_LIMIT else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    let data_slice = incoming[cursor..data_end];
    cursor = frame_end;
    consumer.bytes_received = next_received;

    let finished_now = peek_terminal_zero_chunk(incoming, cursor);
    if finished_now {
        consumer.is_finished = true;
    }
    return data_slice, true, finished_now, true;
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
        let chunk_len, is_last, ok = feed_fixed_length_http_stream(consumer, incoming);
        if chunk_len > 0 {
            Callback(incoming[..chunk_len], is_last);
        }
        return chunk_len, is_last, ok;
    }

    var cursor: i64 = 0;
    while cursor < incoming.len {
        let data_slice, has_data, is_last, ok = step_chunked_http_stream_frame(consumer, incoming, cursor);
        guard ok else { return cursor, false, false; }
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
