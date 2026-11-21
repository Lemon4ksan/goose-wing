// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Streaming HTTP/1.1 request body consumer and asynchronous backpressure / abort context
// (uWebSockets onData / onWritable / onAborted pattern).
namespace server;

import std;
import core;
import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import .h1_codec;
import .internal;
import .h1_codec_internal;

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
