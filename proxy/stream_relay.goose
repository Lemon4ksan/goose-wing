// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Non-blocking HTTP/1.1 upstream head parser and bidirectional streaming relay state
// over bounded 16 KiB `StreamRing` buffers and 64-bit `ChunkFsmDecoder` framing.
namespace proxy;

import std;
import core;
import rfc.http;
import http.headers;
import http.headers.chunked_fsm;
import http.early_hints;
import wire.h1;
import wire.h1_exchange;
import .reverse_proxy;
import .headers_internal;

const MAX_UPSTREAM_HEAD_BYTES: i64 = 65536; // RFC 9112 Section 5: bounded header block ceiling (64 KiB)

// ---- Upstream Response Head Parsing ----------------------------------------

struct UpstreamHeadResult {
    status_code:     i32                      = 0,
    is_upgrade_101:  bool                     = false,
    is_sse:          bool                     = false,
    is_chunked:      bool                     = false,
    content_length:  i64                      = -1,
    keep_alive:      bool                     = false,
    accel:           UpstreamAccelControl     = UpstreamAccelControl { .. },
    early_hints:     http::EarlyHintsResponse = http::EarlyHintsResponse { .. },
    has_early_hints: bool                     = false,
    headers:         http::HeaderMap          = http::HeaderMap { .. },
    body_offset:     i64                      = 0,
}

inline fn is_sse_content_type(raw_ct: const u8[:]) -> bool {
    let ct = raw_ct.trim_lws();
    guard ct.starts_with_fold("text/event-stream") else { return false; }
    return ct.len == 17 || ct[17] == ';' || ct[17] == ' ' || ct[17] == '\t';
}

fn capture_interim_early_hints(
    in_hdrs:         const http::HeaderMap&,
    early_hints:     http::EarlyHintsResponse&,
    has_early_hints: bool&,
) {
    for &entry in in_hdrs.entries {
        let name = http::entry_name(in_hdrs, entry);
        guard name.eq_ascii_fold("link") else { continue; }
        let val = http::entry_value(in_hdrs, entry);
        var parsed: http::EarlyHintLink[..8] = [];
        if http::parse_link_header(val, parsed) {
            for &link in parsed {
                let _ = early_hints.links.try_push(link);
            }
        }
    }
    if early_hints.links.len > 0 {
        early_hints.is_valid = true;
        has_early_hints = true;
    }
}

inline fn preserve_101_upgrade_headers(
    raw_hdrs: const http::HeaderMap&,
    out_hdrs: http::HeaderMap&,
) -> bool {
    if http::has_header(raw_hdrs, "upgrade") {
        let upg = http::get_header(raw_hdrs, "upgrade");
        guard http::append_header(out_hdrs, "Upgrade", upg) else { return false; }
    }
    if http::is_token_in_connection_header_map(raw_hdrs, "upgrade") {
        guard http::append_header(out_hdrs, "Connection", "Upgrade") else { return false; }
    }
    return true;
}

inline fn compute_upstream_keep_alive(
    raw_hdrs: const http::HeaderMap&,
    sc:       i32,
) -> bool {
    guard sc != rfc::STATUS_SWITCHING_PROTOCOLS else { return false; }
    let is_close = http::is_token_in_connection_header_map(raw_hdrs, "close");
    guard !is_close else { return false; }
    let is_h10 = (raw_hdrs.http_major == 1 && raw_hdrs.http_minor == 0);
    if is_h10 {
        return http::is_token_in_connection_header_map(raw_hdrs, "keep-alive");
    }
    return true;
}

fn resolve_upstream_head_framing(
    raw_hdrs: const http::HeaderMap&,
    sc:       i32,
    method:   const u8[:],
    out_res:  UpstreamHeadResult&,
) -> bool {
    let has_te = http::has_header(raw_hdrs, "transfer-encoding");
    let has_cl = http::has_header(raw_hdrs, "content-length");
    // RFC 9112 Section 6.3: Message Body Length - reject co-present Transfer-Encoding and Content-Length.
    guard !(has_te && has_cl) else { return false; }
    let is_h10 = (raw_hdrs.http_major == 1 && raw_hdrs.http_minor == 0);
    guard !(is_h10 && has_te) else { return false; }

    let is_101 = (sc == rfc::STATUS_SWITCHING_PROTOCOLS);
    out_res.is_upgrade_101 = is_101;
    let empty_body = method.eq_ascii_fold("HEAD") || rfc::is_empty_body_status(sc);
    if empty_body {
        out_res.content_length = 0;
        out_res.is_chunked = false;
        let rogue_empty = !is_101 && wing::has_rogue_empty_status_framing(method, sc, raw_hdrs);
        out_res.keep_alive = !rogue_empty && compute_upstream_keep_alive(raw_hdrs, sc);
        return true;
    }

    if has_te {
        out_res.is_chunked = true;
        out_res.content_length = -1;
        out_res.keep_alive = compute_upstream_keep_alive(raw_hdrs, sc);
        return true;
    }

    if has_cl {
        let cl_val, ok_cl = http::validate_content_length_value(
            http::get_header(raw_hdrs, "content-length"),
        );
        guard ok_cl && cl_val >= 0 else { return false; }
        out_res.content_length = cl_val;
        out_res.is_chunked = false;
        out_res.keep_alive = compute_upstream_keep_alive(raw_hdrs, sc);
        return true;
    }

    out_res.content_length = -1;
    out_res.is_chunked = false;
    out_res.keep_alive = false;
    return true;
}

fn finalize_upstream_head(
    raw_hdrs:        const http::HeaderMap&,
    sc:              i32,
    method:          const u8[:],
    early_hints:     const http::EarlyHintsResponse&,
    has_early_hints: bool,
    body_offset:     i64,
    out_res:         UpstreamHeadResult&,
) -> bool {
    var loc_buf: u8[..512] = [];
    guard process_and_filter_upstream_response_headers(
        raw_hdrs, "", "", out_res.headers, loc_buf, out_res.accel,
    ) else { return false; }

    if sc == rfc::STATUS_SWITCHING_PROTOCOLS {
        guard preserve_101_upgrade_headers(raw_hdrs, out_res.headers) else { return false; }
    }

    guard resolve_upstream_head_framing(raw_hdrs, sc, method, out_res) else { return false; }

    out_res.status_code = sc;
    out_res.early_hints = early_hints;
    out_res.has_early_hints = has_early_hints;
    out_res.body_offset = body_offset;
    if is_sse_content_type(http::get_header(out_res.headers, "content-type")) {
        out_res.is_sse = true;
        out_res.accel.disable_buffering = true;
    }
    return true;
}

inline fn is_interim_1xx_status(sc: i32) -> bool {
    return sc >= rfc::STATUS_CONTINUE && sc < rfc::STATUS_OK && sc != rfc::STATUS_SWITCHING_PROTOCOLS;
}

inline fn handle_interim_1xx_block(
    tmp_hdrs:        const http::HeaderMap&,
    sc:              i32,
    abs_body_off:    i64,
    cursor:          i64&,
    early_hints:     http::EarlyHintsResponse&,
    has_early_hints: bool&,
) -> bool {
    // RFC 9112 Section 6.3: Message Body Length - 1xx interim responses MUST NOT carry TE or CL.
    guard !http::has_header(tmp_hdrs, "transfer-encoding") &&
        !http::has_header(tmp_hdrs, "content-length") else {
        return false;
    }
    if sc == rfc::STATUS_EARLY_HINTS {
        capture_interim_early_hints(tmp_hdrs, early_hints, has_early_hints);
    }
    cursor = abs_body_off;
    return true;
}

// Parses an HTTP/1.x upstream response head block from `raw`, skipping interim 1xx
// responses (except 101 Switching Protocols), capturing 103 Early Hints, rejecting
// Transfer-Encoding + Content-Length conflicts (RFC 9112 Section 6.3), and flagging SSE.
// Returns `1` when complete, `0` when incomplete (needs more bytes), or `-1` on error.
//
// Example:
//   raw = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: 1\n\n", method = "GET"
//   returns: 1, out_res.is_sse = true, out_res.accel.disable_buffering = true, out_res.body_offset = 52
fn parse_upstream_response_head(
    raw:     const u8[:],
    method:  const u8[:],
    out_res: UpstreamHeadResult&,
) -> i32 {
    out_res = UpstreamHeadResult { .. };
    var committed = false;
    defer if !committed { out_res = UpstreamHeadResult { .. }; };

    var cursor:          i64                      = 0;
    var early_hints:     http::EarlyHintsResponse = http::EarlyHintsResponse { .. };
    var has_early_hints: bool                     = false;
    var tmp_hdrs:        http::HeaderMap          = http::HeaderMap { .. };

    // RFC 9110 Section 15.2: Informational 1xx - cap consecutive 1xx interim responses to 5.
    for interim_step in 6 {
        guard interim_step < 5 else { return -1; }
        let tail = raw[cursor..];
        let hdr_end = core::fast_find_crlfcrlf(tail);
        guard hdr_end >= 0 else {
            return if tail.len <= MAX_UPSTREAM_HEAD_BYTES { 0 } else { -1 };
        }
        guard hdr_end <= MAX_UPSTREAM_HEAD_BYTES else { return -1; }

        var sc_u16: u16 = 0;
        let local_body_off, err = wire::decode_h1_response_head(tail, sc_u16, tmp_hdrs, false);
        guard err == http::HeaderParseError.None else { return -1; }

        let sc = sc_u16 as i32;
        let abs_body_off = core::add_sat_i64(cursor, local_body_off);
        if is_interim_1xx_status(sc) {
            guard handle_interim_1xx_block(
                tmp_hdrs, sc, abs_body_off, cursor, early_hints, has_early_hints,
            ) else { return -1; }
            continue;
        }

        guard finalize_upstream_head(
            tmp_hdrs, sc, method, early_hints, has_early_hints, abs_body_off, out_res,
        ) else {
            return -1;
        }
        committed = true;
        return 1;
    }
    return -1;
}

// ---- Non-Blocking Bidirectional Stream Relay State -------------------------

enum StreamBodyMode {
    FixedLength,
    Chunked,
    UntilEof,
    RawTunnel,
}

// Non-blocking bidirectional body/tunnel relay over 16 KiB `StreamRing` buffers.
// In `Chunked` mode, raw HTTP/1.1 chunked wire framing is preserved in `c2u`/`u2c` while
// `ChunkFsmDecoder` validates every chunk boundary and stops at `0\r\n...\r\n`.
struct StreamRelayState {
    req_mode:       StreamBodyMode                 = StreamBodyMode.FixedLength,
    resp_mode:      StreamBodyMode                 = StreamBodyMode.UntilEof,
    req_remaining:  i64                            = 0,
    resp_remaining: i64                            = 0,
    req_chunk_fsm:  http_internal::ChunkFsmDecoder = http_internal::new_chunk_fsm_decoder(),
    resp_chunk_fsm: http_internal::ChunkFsmDecoder = http_internal::new_chunk_fsm_decoder(),
    c2u:            StreamRing                     = StreamRing { .. },
    u2c:            StreamRing                     = StreamRing { .. },
    req_done:       bool                           = false,
    resp_done:      bool                           = false,
}

fn relay_init(
    req_mode:  StreamBodyMode,
    req_len:   i64,
    resp_mode: StreamBodyMode,
    resp_len:  i64,
) -> StreamRelayState {
    let eff_req_rem = if req_mode == StreamBodyMode.FixedLength { max(req_len, 0) } else { 0 };
    let eff_resp_rem = if resp_mode == StreamBodyMode.FixedLength { max(resp_len, 0) } else { 0 };
    return StreamRelayState {
        req_mode:       req_mode,
        resp_mode:      resp_mode,
        req_remaining:  eff_req_rem,
        resp_remaining: eff_resp_rem,
        req_done:       req_mode == StreamBodyMode.FixedLength && eff_req_rem == 0,
        resp_done:      resp_mode == StreamBodyMode.FixedLength && eff_resp_rem == 0,
        ..
    };
}

inline fn prepare_ring_space(ring: StreamRing&, wanted: i64) -> i64 {
    let tail_avail = core::sub_sat_i64(ring.buf.cap, ring.buf.len);
    if wanted > tail_avail && ring.read_pos > 0 {
        compact_stream_ring(ring);
    }
    return core::sub_sat_i64(ring.buf.cap, ring.buf.len);
}

fn relay_feed_chunked_dir(
    fsm:  http_internal::ChunkFsmDecoder&,
    ring: StreamRing&,
    done: bool&,
    data: const u8[:],
) -> i64, bool {
    guard fsm.state != http_internal::CHUNK_STATE_IS_ERROR else { return 0, false; }
    let avail = prepare_ring_space(ring, data.len);
    guard avail > 0 else { return 0, true; }

    let slice = data[..min(data.len, avail)];
    var cursor: i64 = 0;
    while cursor < slice.len {
        let st_c, consumed, _ = http_internal::chunk_fsm_feed(fsm, slice[cursor..]);
        guard st_c != http_internal::ChunkFsmStatus.Error else {
            return 0, false;
        }
        cursor = core::add_sat_i64(cursor, consumed);
        if st_c == http_internal::ChunkFsmStatus.Complete {
            done = true;
            break;
        }
        if consumed == 0 {
            break;
        }
    }
    if cursor > 0 {
        guard feed_stream_chunk(ring, slice[..cursor]) else { return 0, false; }
    }
    return cursor, true;
}

fn relay_feed_dir(
    mode:      StreamBodyMode,
    remaining: i64&,
    fsm:       http_internal::ChunkFsmDecoder&,
    ring:      StreamRing&,
    done:      bool&,
    data:      const u8[:],
) -> i64, bool {
    if mode == StreamBodyMode.Chunked {
        guard !done && data.len > 0 else { return 0, true; }
        return relay_feed_chunked_dir(fsm, ring, done, data);
    }
    guard !done && data.len > 0 else { return 0, true; }

    if mode == StreamBodyMode.FixedLength {
        if remaining <= 0 {
            done = true;
            return 0, true;
        }
        let capped = min(data.len, remaining);
        let avail = prepare_ring_space(ring, capped);
        let take = min(capped, avail);
        guard take > 0 else { return 0, true; }
        guard feed_stream_chunk(ring, data[..take]) else { return 0, false; }
        remaining = core::sub_sat_i64(remaining, take);
        if remaining == 0 {
            done = true;
        }
        return take, true;
    }

    let avail = prepare_ring_space(ring, data.len);
    let take = min(data.len, avail);
    guard take > 0 else { return 0, true; }
    guard feed_stream_chunk(ring, data[..take]) else { return 0, false; }
    return take, true;
}

// Feeds client-to-upstream body or tunnel bytes into `st.c2u`.
// Returns `(accepted_bytes, ok)`; returns `(0, true)` when the 16 KiB ring is full (backpressure),
// or `(0, false)` on malformed chunked framing.
//
// Example:
//   st = relay_init(StreamBodyMode.FixedLength, 5, StreamBodyMode.UntilEof, 0), data = "hello"
//   returns: 5, true (st.req_done = true)
fn relay_feed_client(st: StreamRelayState&, data: const u8[:]) -> i64, bool {
    return relay_feed_dir(st.req_mode, st.req_remaining, st.req_chunk_fsm, st.c2u, st.req_done, data);
}

// Feeds upstream-to-client body or tunnel bytes into `st.u2c`.
// Returns `(accepted_bytes, ok)`; returns `(0, true)` when the 16 KiB ring is full (backpressure),
// or `(0, false)` on malformed chunked framing.
//
// Example:
//   st = relay_init(StreamBodyMode.FixedLength, 0, StreamBodyMode.Chunked, 0), data = "5\r\nhello\r\n0\r\n\r\n"
//   returns: 15, true (st.resp_done = true)
fn relay_feed_upstream(st: StreamRelayState&, data: const u8[:]) -> i64, bool {
    return relay_feed_dir(st.resp_mode, st.resp_remaining, st.resp_chunk_fsm, st.u2c, st.resp_done, data);
}

// Returns the currently buffered client-to-upstream slice ready for non-blocking write.
fn relay_drain_to_upstream(st: StreamRelayState&) -> const u8[:] {
    return incoming_slice(st.c2u);
}

// Advances the client-to-upstream ring read cursor by `n` written bytes.
fn relay_advance_upstream(st: StreamRelayState&, n: i64) -> bool {
    return advance_read(st.c2u, n);
}

// Returns the currently buffered upstream-to-client slice ready for non-blocking write.
fn relay_drain_to_client(st: StreamRelayState&) -> const u8[:] {
    return incoming_slice(st.u2c);
}

// Advances the upstream-to-client ring read cursor by `n` written bytes.
fn relay_advance_client(st: StreamRelayState&, n: i64) -> bool {
    return advance_read(st.u2c, n);
}
