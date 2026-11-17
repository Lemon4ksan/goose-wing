// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/2 Server Frame Multiplexer (RFC 9113 & RFC 7541).
// Manages server connection sessions, stream demultiplexing, HPACK decoding/encoding,
// flow control updates, anti-DoS barriers, and dispatching to the Wing Server Pipeline.
namespace server_internal;

import std;
import core from "..";
import .router;
import .pool;
import .pipeline;

// ---- Server Stream Descriptor --------------------------------------------

enum H2StreamPhase {
    Idle,
    Open,
    HalfClosedRemote,
    Closed,
}

struct H2ServerStream {
    stream_id:               u32             = 0,
    phase:                   H2StreamPhase   = H2StreamPhase.Idle,
    active:                  bool            = false,
    headers_received:        bool            = false,
    body_received:           bool            = false,
    headers_sent:            bool            = false,
    response_sent:           bool            = false,
    pending_has_trailers:    bool            = false,
    pending_async:           bool            = false,
    declared_content_length: i64             = -1,
    unclaimed_local_window:  i64             = 0,
    spill_slab_idx:          i32             = -1,
    slab_lease_deadline_ns:  u64             = 0,
    method:                  u8[..16]        = [],
    path:                    u8[..2048]      = [],
    scheme:                  u8[..16]        = [],
    authority:               u8[..256]       = [],
    headers:                 wing::HeaderMap = wing::HeaderMap { .. },
    trailers:                wing::HeaderMap = wing::HeaderMap { .. },
    body:                    u8[..8192]      = [],
}

fn reset_server_stream(st: H2ServerStream&) {
    st.stream_id = 0;
    st.phase = H2StreamPhase.Idle;
    st.active = false;
    st.headers_received = false;
    st.body_received = false;
    st.headers_sent = false;
    st.response_sent = false;
    st.pending_has_trailers = false;
    st.pending_async = false;
    st.spill_slab_idx = -1;
    st.slab_lease_deadline_ns = 0;
    st.method.clear();
    st.path.clear();
    st.scheme.clear();
    st.authority.clear();
    st.headers.clear();
    st.trailers.clear();
    st.body.clear();
    st.declared_content_length = -1;
    st.unclaimed_local_window = 0;
}

// ---- Server Connection Session -------------------------------------------

struct H2ServerSession {
    conn:                      h2_internal::H2Connection = h2_internal::H2Connection { .. },
    hpack_enc:                 h2_internal::DynamicTable = h2_internal::DynamicTable { .. },
    streams:                   H2ServerStream[..16]      = [],
    preface_handled:           bool                      = false,
    server_settings_sent:      bool                      = false,
    client_settings_acked:     bool                      = false,
    pending_settings_ack:      bool                      = false,
    pending_dyn_size_update:   bool                      = false,
    pending_min_dyn_size:      u64                       = 4096,
    min_pending_max_size:      i64                       = 4096,
    server_name:               u8[..64]                  = "goose-wing/1.0",
    header_accumulator:        u8[..16384]               = [],
    header_accum_stream_id:    u32                       = 0,
    header_accum_rejected_err: u32                       = 0,
    header_accum_end_stream:   bool                      = false,
    header_accum_is_trailer:   bool                      = false,
}

fn flush_server_control_frames(sess: H2ServerSession&) {
    while sess.conn.pending_control_frames > 0 {
        h2_internal::ack_control_frame_flushed(sess.conn);
    }
}

fn new_h2_server_session(
    server_name_str: const u8[:] = "goose-wing/1.0",
    now_ms:          u64         = 0,
) -> H2ServerSession {
    var conn = h2_internal::new_h2_connection(now_ms);
    conn.is_server = true;
    conn.enable_push = false;
    conn.max_concurrent_streams = 16;
    conn.local_initial_window_size = 8192;
    conn.max_header_list_size = 16384;
    var sess = H2ServerSession {
        conn:                  conn,
        hpack_enc:             h2_internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
        preface_handled:       false,
        server_settings_sent:  false,
        client_settings_acked: false,
        pending_settings_ack:  false,
        server_name:           [],
        ..
    };
    let _ = sess.server_name.try_set(server_name_str[..min(server_name_str.len, 64)]);
    return sess;
}

inline fn reset_hpack_dyn_table_inplace(dt: h2_internal::DynamicTable&) {
    dt.head = 0;
    dt.count = 0;
    dt.arena_write_pos = 0;
    dt.arena_head = 0;
    dt.arena_tail = 0;
    dt.next_generation = 1;
    dt.used_bytes = 0;
    dt.max_allowed_size = rfc::HPACK_DEFAULT_MAX_DYN_SIZE;
    dt.current_max_size = rfc::HPACK_DEFAULT_MAX_DYN_SIZE;
    for i in 256 {
        dt.hash_table.slots[i] = 0;
        dt.hash_table.generations[i] = 0;
    }
}

inline fn reset_h2_stream_nodes_inplace(conn: h2_internal::H2Connection&) {
    for n_i in 128 {
        conn.stream_nodes[n_i].stream_id = 0;
        conn.stream_nodes[n_i].next = -1;
        conn.stream_nodes[n_i].prev = -1;
    }
}

fn reset_h2_server_session_inplace(
    sess:            H2ServerSession&,
    server_name_str: const u8[:] = "goose-wing/1.0",
    now_ms:          u64         = 0,
) {
    reset_hpack_dyn_table_inplace(sess.conn.hpack_dec);
    sess.conn.conn_send_window = 65535;
    sess.conn.conn_recv_window = 65535;
    sess.conn.peer_initial_window_size = 65535;
    sess.conn.local_initial_window_size = 8192;
    sess.conn.local_max_frame_size = 16384;
    sess.conn.peer_max_frame_size = 16384;
    sess.conn.max_header_list_size = 16384;
    sess.conn.max_concurrent_streams = 16;
    sess.conn.active_stream_count = 0;
    sess.conn.last_peer_stream_id = 0;
    sess.conn.last_local_stream_id = 0;
    sess.conn.is_server = true;
    sess.conn.enable_push = false;
    sess.conn.enable_connect_protocol = 1;
    sess.conn.unclaimed_recv_window = 0;
    sess.conn.coalesce_window_updates = false;
    sess.conn.streams.clear();
    sess.conn.stream_index = [core::FlatIndexBucket { .. }; 256];
    sess.conn.idle_priorities.clear();
    sess.conn.continuation_stream_id = 0;
    sess.conn.continuation_frames_cnt = 0;
    sess.conn.accumulated_header_size = 0;
    sess.conn.continuation_start_ms = 0;
    sess.conn.max_header_block_duration_ms = 10000;
    sess.conn.reset_limiter.tokens = 1000;
    sess.conn.reset_limiter.burst = 1000;
    sess.conn.reset_limiter.rate_per_sec = 33;
    sess.conn.reset_limiter.last_refill_ms = now_ms;
    sess.conn.empty_frame_streak = 0;
    sess.conn.pending_control_frames = 0;
    sess.conn.concurrency_violations = 0;
    sess.conn.initial_window_update_count = 0;
    sess.conn.client_sent_priority = false;
    sess.conn.no_rfc7540_priorities = false;
    sess.conn.peer_no_rfc7540_set = false;
    sess.conn.is_behind_proxy = false;
    sess.conn.urgency_streak_count = 0;
    sess.conn.active_urgency_mask = 0;
    sess.conn.urgency_heads = [-1; 8];
    sess.conn.urgency_tails = [-1; 8];
    sess.conn.bucket_prefer_incremental = [false; 8];
    sess.conn.bucket_last_inc_idx = [-1; 8];
    reset_h2_stream_nodes_inplace(sess.conn);
    sess.conn.shutdown_notice_sent = false;
    sess.conn.shutdown_ping_opaque = 0x57494E47474F4157;
    sess.conn.goaway_sent = false;
    sess.conn.goaway_received = false;
    sess.conn.goaway_last_stream_id = 0;
    sess.conn.goaway_error_code = 0;
    reset_hpack_dyn_table_inplace(sess.hpack_enc);
    sess.streams.clear();
    sess.preface_handled = false;
    sess.server_settings_sent = false;
    sess.client_settings_acked = false;
    sess.pending_settings_ack = false;
    sess.pending_dyn_size_update = false;
    sess.pending_min_dyn_size = rfc::HPACK_DEFAULT_MAX_DYN_SIZE;
    sess.min_pending_max_size = rfc::HPACK_DEFAULT_MAX_DYN_SIZE as i64;
    let _ = sess.server_name.try_set(server_name_str[..min(server_name_str.len, 64)]);
    sess.header_accumulator.clear();
    sess.header_accum_stream_id = 0;
    sess.header_accum_rejected_err = 0;
    sess.header_accum_end_stream = false;
    sess.header_accum_is_trailer = false;
}

// Finds an active server stream slot by stream_id
fn find_server_stream_idx(sess: const H2ServerSession&, stream_id: u32) -> i32, bool {
    for i in sess.streams.len {
        if sess.streams[i].active && sess.streams[i].stream_id == stream_id {
            return i as i32, true;
        }
    }
    return -1, false;
}

// Finds an active server stream slot or an empty slot for a new stream
fn find_or_alloc_stream(sess: H2ServerSession&, stream_id: u32) -> i32, bool {
    for i in sess.streams.len {
        if sess.streams[i].active && sess.streams[i].stream_id == stream_id {
            return i as i32, true;
        }
    }

    for i in sess.streams.len {
        if !sess.streams[i].active {
            reset_server_stream(sess.streams[i]);
            sess.streams[i].stream_id = stream_id;
            sess.streams[i].phase = H2StreamPhase.Open;
            sess.streams[i].active = true;
            return i as i32, true;
        }
    }

    var new_st = H2ServerStream {
        stream_id: stream_id,
        phase:     H2StreamPhase.Open,
        active:    true,
        ..
    };
    if sess.streams.try_push(new_st) {
        return (sess.streams.len - 1) as i32, true;
    }

    return -1, false;
}

// ---- Protocol Frame Serialization Helpers --------------------------------

// Emits the server's initial SETTINGS frame (RFC 9113 Section 6.5)
fn emit_server_settings<B>(out: B&) {
    let hdr = h2_internal::FrameHeader {
        length:     24, // 4 settings * 6 bytes
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    h2_internal::encode_frame_header_to(hdr, out);

    out.append_u16_be(rfc::H2_SETTING_MAX_CONCURRENT_STREAMS);
    out.append_u32_be(16);

    out.append_u16_be(rfc::H2_SETTING_INITIAL_WINDOW_SIZE);
    out.append_u32_be(8192);

    out.append_u16_be(rfc::H2_SETTING_MAX_FRAME_SIZE);
    out.append_u32_be(16384);

    out.append_u16_be(rfc::H2_SETTING_ENABLE_CONNECT_PROTO);
    out.append_u32_be(1);
}

// Emits a SETTINGS ACK frame
fn emit_settings_ack<B>(out: B&) {
    let hdr = h2_internal::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    h2_internal::encode_frame_header_to(hdr, out);
}

// Emits a PING ACK frame echoing the client's 8-byte opaque payload
fn emit_ping_ack<B>(opaque: const u8[8]&, out: B&) {
    let hdr = h2_internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    h2_internal::encode_frame_header_to(hdr, out);
    for b in opaque {
        out.push(b);
    }
}

// Emits a WINDOW_UPDATE frame
fn emit_window_update<B>(stream_id: u32, increment: u32, out: B&) {
    let hdr = h2_internal::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
        flags:      0,
        stream_id:  stream_id,
    };
    h2_internal::encode_frame_header_to(hdr, out);
    out.append_u32_be(increment & 0x7FFFFFFF);
}

// Emits a RST_STREAM frame
fn emit_rst_stream<B>(stream_id: u32, error_code: u32, out: B&) {
    let hdr = h2_internal::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_RST_STREAM,
        flags:      0,
        stream_id:  stream_id,
    };
    h2_internal::encode_frame_header_to(hdr, out);
    out.append_u32_be(error_code);
}

// Emits a GOAWAY frame
fn emit_goaway<B>(last_stream_id: u32, error_code: u32, out: B&) {
    let hdr = h2_internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_GOAWAY,
        flags:      0,
        stream_id:  0,
    };
    h2_internal::encode_frame_header_to(hdr, out);
    out.append_u32_be(last_stream_id & 0x7FFFFFFF);
    out.append_u32_be(error_code);
}

// Emits a final GOAWAY frame with `sess.conn.last_peer_stream_id` and sets `goaway_sent = true`.
fn emit_goaway<B>(sess: H2ServerSession&, error_code: u32, out: B&) {
    emit_goaway(sess.conn.last_peer_stream_id, error_code, out);
    sess.conn.goaway_sent = true;
    sess.conn.goaway_last_stream_id = sess.conn.last_peer_stream_id;
    sess.conn.goaway_error_code = error_code;
}

// Initiates RFC 9113 §6.8 two-phase graceful shutdown by sending GOAWAY(2^31-1, NO_ERROR)
// followed by a non-ACK PING frame carrying `shutdown_ping_opaque`.
fn initiate_graceful_shutdown<B>(sess: H2ServerSession&, out: B&) {
    guard !sess.conn.shutdown_notice_sent && !sess.conn.goaway_sent else { return; }
    emit_goaway(0x7FFFFFFF, rfc::H2_ERR_NO_ERROR, out);
    let ping_hdr = h2_internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      0,
        stream_id:  0,
    };
    h2_internal::encode_frame_header_to(ping_hdr, out);
    out.append_u64_be(sess.conn.shutdown_ping_opaque);
    sess.conn.shutdown_notice_sent = true;
}

inline fn is_h2_forbidden_hop_header(name_slice: const u8[:]) -> bool {
    return name_slice.eq_ascii_fold("connection") ||
           name_slice.eq_ascii_fold("keep-alive") ||
           name_slice.eq_ascii_fold("proxy-connection") ||
           name_slice.eq_ascii_fold("transfer-encoding") ||
           name_slice.eq_ascii_fold("upgrade") ||
           name_slice.eq_ascii_fold("te");
}

inline fn emit_pending_dyn_size_updates<B>(sess: H2ServerSession&, hpack_block: B&) {
    guard sess.pending_dyn_size_update else { return; }
    let min_sz = if sess.min_pending_max_size >= 0 {
        min(sess.min_pending_max_size as u64, sess.pending_min_dyn_size)
    } else {
        sess.pending_min_dyn_size
    };
    if min_sz < sess.hpack_enc.current_max_size {
        let _ = h2_internal::hpack_encode_int(hpack_block, min_sz, 5, 0x20);
    }
    let _ = h2_internal::hpack_encode_int(hpack_block, sess.hpack_enc.current_max_size, 5, 0x20);
    sess.pending_dyn_size_update = false;
    sess.pending_min_dyn_size = sess.hpack_enc.current_max_size;
    sess.min_pending_max_size = sess.hpack_enc.current_max_size as i64;
}

// Encodes HTTP/2 Response HEADERS using HPACK
fn emit_response_headers<B>(
    sess:       H2ServerSession&,
    stream_id:  u32,
    res:        const wing::Response&,
    end_stream: bool,
    out:        B&,
) {
    var hpack_block: u8[..16384] = [];
    emit_pending_dyn_size_updates(sess, hpack_block);
    let max_tbl = sess.hpack_enc.current_max_size as i64;

    var status_buf: u8[..16] = [];
    format(status_buf, res.status_code as i64);
    let st_idx_mode = h2_internal::select_hpack_indexing(":status", status_buf[..], max_tbl);
    h2_internal::encode_hpack_field(sess.hpack_enc, hpack_block, ":status", status_buf[..], st_idx_mode, true);

    if sess.server_name.len > 0 && !res.has_header("server") {
        let srv_idx_mode = h2_internal::select_hpack_indexing("server", sess.server_name[..], max_tbl);
        h2_internal::encode_hpack_field(
            sess.hpack_enc, hpack_block, "server", sess.server_name[..], srv_idx_mode, true,
        );
    }

    let is_grpc = res.header("content-type").starts_with_fold("application/grpc");
    let has_cl = res.header("content-length").len > 0;
    if !is_grpc && !has_cl && res.status_code >= 200 && res.status_code != 204 && res.status_code != 304 {
        var cl_buf: u8[..32] = [];
        format(cl_buf, res.body.len);
        let cl_idx_mode = h2_internal::select_hpack_indexing("content-length", cl_buf[..], max_tbl);
        h2_internal::encode_hpack_field(sess.hpack_enc, hpack_block, "content-length", cl_buf[..], cl_idx_mode, true);
    }

    for &e in res.headers.entries {
        let name_slice = wing::entry_name(res.headers, e);
        let val_slice = wing::entry_value(res.headers, e);
        guard !is_h2_forbidden_hop_header(name_slice) else { continue; }
        var lower_name: u8[..256] = [];
        guard name_slice.len <= lower_name.cap else { continue; }
        name_slice.to_lower_ascii(lower_name);
        let hdr_idx_mode = h2_internal::select_hpack_indexing(lower_name[..], val_slice, max_tbl);
        h2_internal::encode_hpack_field(
            sess.hpack_enc, hpack_block, lower_name[..], val_slice, hdr_idx_mode, true,
        );
    }

    var flags: u8 = rfc::H2_FLAG_END_HEADERS;
    if end_stream { flags |= rfc::H2_FLAG_END_STREAM; }
    let frame_hdr = h2_internal::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream_id,
    };
    h2_internal::encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

inline fn deduct_send_windows(
    conn:     h2_internal::H2Connection&,
    c_idx:    i64,
    found:    bool,
    send_len: i64,
) {
    conn.conn_send_window -= send_len;
    if found {
        conn.streams[c_idx].send_window -= send_len;
    }
}

inline fn calc_data_chunk_size(rem: i64, limit: i64, quota: i64) -> i64 {
    let clamped_rem = min(rem, limit);
    return min(clamped_rem, quota);
}

fn emit_one_data_frame<B>(
    sess:       H2ServerSession&,
    stream_id:  u32,
    body:       const u8[:],
    offset:     i64,
    limit:      i64,
    quota:      i64,
    c_idx:      i64,
    found:      bool,
    out:        B&,
    end_stream: bool,
) -> i64 {
    let rem = body.len - offset;
    let chunk_size = calc_data_chunk_size(rem, limit, quota);
    let is_last = (offset + chunk_size >= body.len);
    let flags: u8 = if is_last && end_stream { rfc::H2_FLAG_END_STREAM } else { 0 };
    let hdr = h2_internal::FrameHeader {
        length:     chunk_size as u32,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      flags,
        stream_id:  stream_id,
    };
    h2_internal::encode_frame_header_to(hdr, out);
    out.append(body[offset..offset + chunk_size]);
    deduct_send_windows(sess.conn, c_idx, found, chunk_size);
    return chunk_size;
}

// Encodes HTTP/2 Response DATA chunks with flow-control window enforcement
fn emit_response_data<B>(
    sess:           H2ServerSession&,
    stream_id:      u32,
    body:           const u8[:],
    max_frame_size: u32,
    out:            B&,
    end_stream:     bool = true,
) -> i64 {
    guard body.len > 0 else { return 0; }

    var offset: i64 = 0;
    let limit = max(max_frame_size as i64, 16384);
    let c_idx, found = h2_internal::find_session_stream_idx(sess.conn, stream_id);

    while offset < body.len {
        let quota = h2_internal::compute_stream_send_quota(sess.conn, stream_id);
        if quota <= 0 {
            break;
        }

        let chunk_size = emit_one_data_frame(
            sess, stream_id, body, offset, limit, quota, c_idx, found, out, end_stream,
        );
        offset += chunk_size;
    }
    return offset;
}

// Encodes HTTP/2 Response Trailing HEADERS using HPACK
fn emit_response_trailers<B>(
    sess:      H2ServerSession&,
    stream_id: u32,
    trailers:  const wing::HeaderMap&,
    out:       B&,
) {
    guard trailers.entries.len > 0 else { return; }
    var hpack_block: u8[..4096] = [];

    for &e in trailers.entries {
        let name_slice = wing::entry_name(trailers, e);
        let val_slice = wing::entry_value(trailers, e);
        // RFC 9113 §8.1 / §8.2.2 & RFC 9110 §6.5.1: Trailers MUST NOT include pseudo-headers,
        // hop-by-hop connection headers, or disallowed framing/routing trailer fields.
        if name_slice.len > 0 && name_slice[0] != ':' &&
           !name_slice.eq_ascii_fold("connection") &&
           !name_slice.eq_ascii_fold("keep-alive") &&
           !name_slice.eq_ascii_fold("proxy-connection") &&
           !name_slice.eq_ascii_fold("transfer-encoding") &&
           !name_slice.eq_ascii_fold("upgrade") &&
           !name_slice.eq_ascii_fold("te") &&
           !rfc::is_disallowed_trailer_field(name_slice) {
            var lower_name: u8[..256] = [];
            guard name_slice.len <= lower_name.cap else { continue; }
            name_slice.to_lower_ascii(lower_name);
            if sess.pending_dyn_size_update && hpack_block.len == 0 {
                emit_pending_dyn_size_updates(sess, hpack_block);
            }
            h2_internal::encode_hpack_field(
                sess.hpack_enc, hpack_block, lower_name[..], val_slice, h2_internal::HpackIndexing.Incremental, false,
            );
        }
    }

    if hpack_block.len == 0 {
        let empty_data = h2_internal::FrameHeader {
            length:     0,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      rfc::H2_FLAG_END_STREAM,
            stream_id:  stream_id,
        };
        h2_internal::encode_frame_header_to(empty_data, out);
        return;
    }

    let frame_hdr = h2_internal::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  stream_id,
    };
    h2_internal::encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

fn apply_decoded_pseudo_to_stream(st: H2ServerStream&, pseudo: const h2_internal::H2PseudoHeaders&) -> bool {
    if pseudo.has_method {
        guard st.method.try_set(pseudo.method[..]) else { return false; }
    }
    if pseudo.has_path {
        guard st.path.try_set(pseudo.path[..]) else { return false; }
    }
    if pseudo.has_scheme {
        guard st.scheme.try_set(pseudo.scheme[..]) else { return false; }
    }
    if pseudo.has_authority {
        guard st.authority.try_set(pseudo.authority[..]) else { return false; }
    }
    if pseudo.has_protocol {
        guard wing::append_header(st.headers, ":protocol", pseudo.protocol[..]) &&
              wing::append_header(st.headers, ":scheme", pseudo.scheme[..]) &&
              wing::append_header(st.headers, ":path", pseudo.path[..]) &&
              wing::append_header(st.headers, ":authority", pseudo.authority[..]) else {
            return false;
        }
    }
    st.headers_received = true;
    st.phase = H2StreamPhase.Open;
    return true;
}

inline fn validate_decoded_map_bounds(map: const wing::HeaderMap&) -> bool {
    for &e in map.entries {
        let n = wing::entry_name(map, e);
        let v = wing::entry_value(map, e);
        guard n.len <= 256 && v.len <= 8192 else { return false; }
    }
    return true;
}

inline fn is_stream_cancelled_in_batch(cancelled: const u32[:], stream_id: u32) -> bool {
    return cancelled.contains(stream_id);
}

inline fn terminate_server_stream(
    sess:      H2ServerSession&,
    pipeline:  wing::ServerPipelineConfig&,
    stream_id: u32,
) {
    h2_internal::reset_session_stream(sess.conn, stream_id);
    if sess.conn.continuation_stream_id == stream_id {
        sess.conn.continuation_stream_id = 0;
    }
    if sess.header_accum_stream_id == stream_id {
        sess.header_accum_stream_id = 0;
        sess.header_accumulator.clear();
    }
    let s_idx, found = find_server_stream_idx(sess, stream_id);
    if found {
        if sess.streams[s_idx].spill_slab_idx >= 0 {
            release_spill_slab(pipeline.slab_pool, sess.streams[s_idx].spill_slab_idx);
        }
        reset_server_stream(sess.streams[s_idx]);
    }
}

fn cleanup_h2_server_session(sess: H2ServerSession&, pipeline: wing::ServerPipelineConfig&) {
    for i in sess.streams.len {
        if sess.streams[i].active && sess.streams[i].spill_slab_idx >= 0 {
            release_spill_slab(pipeline.slab_pool, sess.streams[i].spill_slab_idx);
        }
        reset_server_stream(sess.streams[i]);
    }
}

inline fn validate_request_pseudo_headers(
    pseudo:                  const h2_internal::H2PseudoHeaders&,
    end_stream:              bool,
    enable_connect_protocol: u32 = 1,
) -> bool {
    let is_connect = pseudo.has_method && pseudo.method[..] == "CONNECT";
    if pseudo.has_protocol {
        if !is_connect || enable_connect_protocol != 1 {
            return false;
        }
        if !pseudo.has_scheme || !pseudo.has_path || !pseudo.has_authority {
            return false;
        }
    } else if is_connect {
        if !pseudo.has_authority || pseudo.has_scheme || pseudo.has_path {
            return false;
        }
    } else if !pseudo.has_method || !pseudo.has_scheme || !pseudo.has_path {
        return false;
    }
    if end_stream && pseudo.has_content_length && pseudo.content_length_val != 0 {
        return false;
    }
    return true;
}

fn process_ingress_window_update<B>(
    sess:          H2ServerSession&,
    pipeline:      wing::ServerPipelineConfig&,
    hdr:           const h2_internal::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    guard frame_payload.len == 4 else { return true; }
    let raw_inc = core::read_be_u32(frame_payload, 0);
    let inc = raw_inc & 0x7FFFFFFF;
    if hdr.stream_id != 0 && ((hdr.stream_id & 1) == 0 || hdr.stream_id > sess.conn.last_peer_stream_id) {
        // RFC 9113 §5.1: Frame other than HEADERS or PRIORITY on idle stream is connection error PROTOCOL_ERROR
        // RFC 9113 §6.4: RST_STREAM frames MUST NOT be sent for an idle stream
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return false;
    }
    let wu_err = h2_internal::apply_window_update(sess.conn, hdr.stream_id, inc);
    guard wu_err != rfc::H2_ERR_NO_ERROR else { return true; }
    if hdr.stream_id == 0 || h2_internal::is_conn_error_on_window_update(sess.conn, hdr.stream_id) {
        emit_goaway(sess.conn.last_peer_stream_id, wu_err, out_wire);
        return false;
    }
    emit_rst_stream(hdr.stream_id, wu_err, out_wire);
    terminate_server_stream(sess, pipeline, hdr.stream_id);
    return true;
}

inline fn apply_header_table_size_setting(sess: H2ServerSession&, param_val: u32) {
    let allowed_max = min(param_val as u64, h2_internal::HPACK_MAX_ARENA_BYTES);
    let clamped_i64 = allowed_max as i64;
    sess.hpack_enc.max_allowed_size = allowed_max;
    if !sess.pending_dyn_size_update || allowed_max < sess.pending_min_dyn_size {
        sess.pending_min_dyn_size = allowed_max;
    }
    if !sess.pending_dyn_size_update || clamped_i64 < sess.min_pending_max_size {
        sess.min_pending_max_size = clamped_i64;
    }
    if sess.hpack_enc.current_max_size != allowed_max {
        sess.hpack_enc.current_max_size = allowed_max;
        h2_internal::evict_until(sess.hpack_enc, allowed_max);
        sess.pending_dyn_size_update = true;
    }
}

inline fn active_streams_fit_window_delta(
    conn:         const h2_internal::H2Connection&,
    cur_init_win: i64,
    new_init_win: i64,
) -> bool {
    guard new_init_win <= rfc::H2_MAX_WINDOW_SIZE else { return false; }
    let delta = core::sub_sat_i64(new_init_win, cur_init_win);
    for &stream in conn.streams {
        if stream.active && stream.state != h2_internal::H2StreamState.Closed {
            guard core::add_sat_i64(stream.send_window, delta) <= rfc::H2_MAX_WINDOW_SIZE else {
                return false;
            }
        }
    }
    return true;
}

// RFC 9113 Section 6.5: SETTINGS - validates all 6-byte parameters before mutating session state.
fn check_ingress_settings_frame(sess: const H2ServerSession&, frame_payload: const u8[:]) -> u32 {
    var sim_peer_win = sess.conn.peer_initial_window_size;
    var sim_win_updates = sess.conn.initial_window_update_count;
    var sim_no_prio_set = sess.conn.peer_no_rfc7540_set;
    var sim_no_prio = sess.conn.no_rfc7540_priorities;
    var rem = frame_payload;
    while rem.len >= 6 {
        let param_id = core::read_be_u16(rem, 0);
        let param_val = core::read_be_u32(rem, 2);
        rem = rem[6..];
        let val_err = h2_internal::validate_settings_parameter(param_id, param_val, false);
        guard val_err == rfc::H2_ERR_NO_ERROR else { return val_err; }
        if param_id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE {
            guard active_streams_fit_window_delta(sess.conn, sim_peer_win, param_val) else {
                return rfc::H2_ERR_FLOW_CONTROL_ERROR;
            }
            sim_win_updates = core::add_sat_u32(sim_win_updates, 1);
            guard sim_win_updates <= 16 else { return rfc::H2_ERR_ENHANCE_YOUR_CALM; }
            sim_peer_win = param_val;
        } else if param_id == rfc::H2_SETTING_NO_RFC7540_PRIORITIES {
            let no_prio = (param_val == 1);
            if sim_no_prio_set && no_prio != sim_no_prio {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
            sim_no_prio = no_prio;
            sim_no_prio_set = true;
        }
    }
    guard rem.len == 0 else { return rfc::H2_ERR_FRAME_SIZE_ERROR; }
    return rfc::H2_ERR_NO_ERROR;
}

fn process_ingress_settings<B>(
    sess:          H2ServerSession&,
    hdr:           const h2_internal::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        if hdr.length != 0 {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return false;
        }
        if !sess.pending_settings_ack {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
        sess.pending_settings_ack = false;
        sess.client_settings_acked = true;
        h2_internal::ack_control_frame_flushed(sess.conn);
        return true;
    }

    let pre_err = check_ingress_settings_frame(sess, frame_payload);
    guard pre_err == rfc::H2_ERR_NO_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, pre_err, out_wire);
        return false;
    }
    var off: i64 = 0;
    while off + 6 <= frame_payload.len {
        let param_id = core::read_be_u16(frame_payload, off);
        let param_val = core::read_be_u32(frame_payload, off + 2);
        off += 6;
        if param_id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE {
            let _ = h2_internal::apply_peer_initial_window_size_delta(sess.conn, param_val);
        } else if param_id == rfc::H2_SETTING_MAX_FRAME_SIZE {
            sess.conn.peer_max_frame_size = param_val;
        } else if param_id == rfc::H2_SETTING_HEADER_TABLE_SIZE {
            apply_header_table_size_setting(sess, param_val);
        } else if param_id == rfc::H2_SETTING_NO_RFC7540_PRIORITIES {
            sess.conn.no_rfc7540_priorities = (param_val == 1);
            sess.conn.peer_no_rfc7540_set = true;
        }
    }
    sess.conn.peer_no_rfc7540_set = true;
    emit_settings_ack(out_wire);
    return true;
}

inline fn apply_request_priority_header(
    conn:      h2_internal::H2Connection&,
    stream_id: u32,
    headers:   const wing::HeaderMap&,
) {
    let s_idx, found = h2_internal::find_session_stream_idx(conn, stream_id);
    if found && conn.streams[s_idx].has_explicit_priority_update {
        return;
    }
    let prio_hdr = wing::get_header(headers, "priority");
    guard prio_hdr.len > 0 else { return; }
    let parsed_prio, ok_prio = wing::parse_http_priority(prio_hdr, false);
    if ok_prio {
        let _ = h2_internal::apply_priority_update(conn, stream_id, parsed_prio);
    }
}

fn process_ingress_headers<B>(
    sess:              H2ServerSession&,
    pipeline:          wing::ServerPipelineConfig&,
    hdr:               const h2_internal::FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
    sess.header_accum_rejected_err = 0;
    var block_start: i64 = 0;
    var block_end:   i64 = frame_payload.len;

    // Handle PADDED flag RFC 9113 Section 6.1 / 6.2
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 {
        if frame_payload.len < 1 {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return false;
        }
        let pad_len = frame_payload[0] as i64;
        if pad_len >= frame_payload.len {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
        block_start += 1;
        block_end -= pad_len;
    }

    // Handle PRIORITY flag (RFC 9113 Section 5.3.1)
    if (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 {
        if (block_end - block_start) < 5 {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return false;
        }
        let b0 = frame_payload[block_start] as u32;
        let b1 = frame_payload[block_start + 1] as u32;
        let b2 = frame_payload[block_start + 2] as u32;
        let b3 = frame_payload[block_start + 3] as u32;
        let dep_raw = ((b0 & 0x7F) << 24) | (b1 << 16) | (b2 << 8) | b3;
        if !sess.conn.no_rfc7540_priorities && dep_raw == hdr.stream_id {
            // RFC 9113 §5.3.1: Stream cannot depend on itself; still decompress HPACK block (RFC 9113 §4.3)
            sess.header_accum_rejected_err = rfc::H2_ERR_PROTOCOL_ERROR;
        }
        block_start += 5;
    }

    let s_exist_idx, s_exists = find_server_stream_idx(sess, hdr.stream_id);
    let is_trailer = s_exists && sess.streams[s_exist_idx].headers_received;

    if is_trailer {
        // If stream already completed receiving body/trailers, extra HEADERS is invalid
        if sess.streams[s_exist_idx].body_received {
            // RFC 9113 §5.1: Frame on half-closed (remote) stream
            sess.header_accum_rejected_err = rfc::H2_ERR_STREAM_CLOSED;
        } else if (hdr.flags & rfc::H2_FLAG_END_STREAM) == 0 {
            // RFC 9113 §8.1.2: A HEADERS frame containing a trailer section MUST have END_STREAM set
            sess.header_accum_rejected_err = rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }

    guard block_start <= block_end && block_end <= frame_payload.len else { return true; }
    let fragment = frame_payload[block_start..block_end];
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        // Multi-frame header block: CONTINUATION follows
        sess.header_accumulator.clear();
        sess.header_accum_stream_id = hdr.stream_id;
        sess.header_accum_end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
        sess.header_accum_is_trailer = is_trailer;
        if sess.header_accumulator.try_set(fragment) {
            return true;
        }
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }

    var pseudo = h2_internal::H2PseudoHeaders { is_trailer: is_trailer, .. };
    var dec_headers = wing::HeaderMap { .. };
    let dec_err = h2_internal::decode_hpack_to_map(
        sess.conn.hpack_dec,
        fragment,
        pseudo,
        dec_headers,
        sess.conn.max_header_list_size,
        sess.header_accum_rejected_err == 0,
    );
    if sess.header_accum_rejected_err != 0 {
        let rej_err = sess.header_accum_rejected_err;
        sess.header_accum_rejected_err = 0;
        if dec_err == rfc::H2_ERR_COMPRESSION_ERROR {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_COMPRESSION_ERROR, out_wire);
            return false;
        }
        emit_rst_stream(hdr.stream_id, rej_err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    if dec_err != rfc::H2_ERR_NO_ERROR {
        if dec_err == rfc::H2_ERR_COMPRESSION_ERROR {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_COMPRESSION_ERROR, out_wire);
            return false;
        }
        // Stream error (e.g. invalid pseudo-header in trailer or request)
        emit_rst_stream(hdr.stream_id, dec_err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }

    if is_trailer {
        if !is_cancelled && s_exists {
            guard validate_decoded_map_bounds(dec_headers) else {
                emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
                terminate_server_stream(sess, pipeline, hdr.stream_id);
                return true;
            }
            wing::append_all_headers(dec_headers, sess.streams[s_exist_idx].trailers);
            sess.streams[s_exist_idx].body_received = true;
            sess.streams[s_exist_idx].phase = H2StreamPhase.HalfClosedRemote;
            let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, hdr.stream_id);
            if c_found {
                sess.conn.streams[c_idx].trailers_received = true;
                sess.conn.streams[c_idx].state = h2_internal::H2StreamState.HalfClosedRemote;
            }
        }
        return true;
    }

    guard validate_request_pseudo_headers(
        pseudo, (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0, sess.conn.enable_connect_protocol,
    ) else {
        // RFC 9113 §8.1.1: Malformed requests MUST be treated as a stream error of type PROTOCOL_ERROR
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }

    guard !is_cancelled else {
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    let s_idx, found = find_or_alloc_stream(sess, hdr.stream_id);
    guard found else {
        if (hdr.stream_id & 1) == 1 && hdr.stream_id > sess.conn.last_peer_stream_id
            && !(sess.conn.goaway_received || sess.conn.goaway_sent) {
            sess.conn.last_peer_stream_id = hdr.stream_id;
        }
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_REFUSED_STREAM, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    guard validate_decoded_map_bounds(dec_headers) &&
          apply_decoded_pseudo_to_stream(sess.streams[s_idx], pseudo) else {
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    wing::append_all_headers(dec_headers, sess.streams[s_idx].headers);
    apply_request_priority_header(sess.conn, hdr.stream_id, dec_headers);
    if pseudo.has_content_length {
        sess.streams[s_idx].declared_content_length = pseudo.content_length_val;
        let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].declared_content_length = pseudo.content_length_val;
        }
    }
    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        sess.streams[s_idx].body_received = true;
        sess.streams[s_idx].phase = H2StreamPhase.HalfClosedRemote;
    }
    return true;
}

fn process_ingress_continuation<B>(
    sess:              H2ServerSession&,
    pipeline:          wing::ServerPipelineConfig&,
    hdr:               const h2_internal::FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    guard hdr.stream_id == sess.header_accum_stream_id else { return true; }
    let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
    if !sess.header_accumulator.try_append(frame_payload) {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }
    guard (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 else { return true; }

    var pseudo = h2_internal::H2PseudoHeaders { is_trailer: sess.header_accum_is_trailer, .. };
    var dec_headers = wing::HeaderMap { .. };
    let dec_err = h2_internal::decode_hpack_to_map(
        sess.conn.hpack_dec,
        sess.header_accumulator[..],
        pseudo,
        dec_headers,
        sess.conn.max_header_list_size,
        sess.header_accum_rejected_err == 0,
    );
    if sess.header_accum_rejected_err != 0 {
        let rej_err = sess.header_accum_rejected_err;
        sess.header_accum_rejected_err = 0;
        sess.header_accum_stream_id = 0;
        sess.conn.continuation_stream_id = 0;
        sess.header_accumulator.clear();
        if dec_err == rfc::H2_ERR_COMPRESSION_ERROR {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_COMPRESSION_ERROR, out_wire);
            return false;
        }
        emit_rst_stream(hdr.stream_id, rej_err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    if dec_err != rfc::H2_ERR_NO_ERROR {
        if dec_err == rfc::H2_ERR_COMPRESSION_ERROR {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_COMPRESSION_ERROR, out_wire);
            return false;
        }
        emit_rst_stream(hdr.stream_id, dec_err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        sess.header_accum_stream_id = 0;
        sess.conn.continuation_stream_id = 0;
        sess.header_accumulator.clear();
        return true;
    }

    if sess.header_accum_is_trailer {
        sess.header_accum_stream_id = 0;
        sess.conn.continuation_stream_id = 0;
        sess.header_accumulator.clear();
        guard !is_cancelled else { return true; }
        let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
        guard found else { return true; }
        guard validate_decoded_map_bounds(dec_headers) else {
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            return true;
        }
        wing::append_all_headers(dec_headers, sess.streams[s_idx].trailers);
        sess.streams[s_idx].body_received = true;
        sess.streams[s_idx].phase = H2StreamPhase.HalfClosedRemote;
        let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].trailers_received = true;
            sess.conn.streams[c_idx].state = h2_internal::H2StreamState.HalfClosedRemote;
        }
        return true;
    }

    guard validate_request_pseudo_headers(
        pseudo, sess.header_accum_end_stream, sess.conn.enable_connect_protocol,
    ) else {
        // RFC 9113 §8.1.1: Malformed requests MUST be treated as a stream error of type PROTOCOL_ERROR
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        sess.header_accum_stream_id = 0;
        sess.conn.continuation_stream_id = 0;
        sess.header_accumulator.clear();
        return true;
    }

    sess.header_accum_stream_id = 0;
    sess.conn.continuation_stream_id = 0;
    sess.header_accumulator.clear();
    guard !is_cancelled else {
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    let s_idx, found = find_or_alloc_stream(sess, hdr.stream_id);
    guard found else {
        if (hdr.stream_id & 1) == 1 && hdr.stream_id > sess.conn.last_peer_stream_id
            && !(sess.conn.goaway_received || sess.conn.goaway_sent) {
            sess.conn.last_peer_stream_id = hdr.stream_id;
        }
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_REFUSED_STREAM, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    guard validate_decoded_map_bounds(dec_headers) &&
          apply_decoded_pseudo_to_stream(sess.streams[s_idx], pseudo) else {
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    wing::append_all_headers(dec_headers, sess.streams[s_idx].headers);
    apply_request_priority_header(sess.conn, hdr.stream_id, dec_headers);
    if pseudo.has_content_length {
        sess.streams[s_idx].declared_content_length = pseudo.content_length_val;
        let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].declared_content_length = pseudo.content_length_val;
        }
    }
    if sess.header_accum_end_stream {
        sess.streams[s_idx].body_received = true;
        sess.streams[s_idx].phase = H2StreamPhase.HalfClosedRemote;
    }
    return true;
}

// RFC 9113 Section 6.9: WINDOW_UPDATE - Window credit increment when promoting 8 KiB inline body to 64 KiB spill slab
const H2_SLAB_WINDOW_INCREMENT: u32 = 57344;

// RFC 9113 Section 6.1: DATA - Reassembles ingress stream payload with dynamic slab promotion.
// If payload exceeds inline 8 KiB capacity, leases a 64 KiB slab from the worker pool.
// Emits WINDOW_UPDATE to replenish credit when leasing slab.
//
// Example:
//   sess.streams[s_idx].spill_slab_idx = -1, payload.len = 16384, stream_id = 1
//   returns: true, promoted to slab with WINDOW_UPDATE emitted
fn process_stream_data_ingress<B>(
    sess:      H2ServerSession&,
    pool:      SpillSlabPool&,
    s_idx:     i32,
    payload:   const u8[:],
    stream_id: u32,
    out_wire:  B&,
) -> bool {
    let st_idx = s_idx as i64;
    guard st_idx >= 0 && st_idx < sess.streams.len else { return false; }

    // 1. Fast path: payload fits in inline 8 KiB buffer
    let has_inline_cap = sess.streams[st_idx].body.len + payload.len <= sess.streams[st_idx].body.cap;
    if sess.streams[st_idx].spill_slab_idx < 0 && has_inline_cap {
        sess.streams[st_idx].body.append(payload);
        return true;
    }

    // 2. Dynamic promotion: allocate slab upon exceeding 8 KiB threshold
    if sess.streams[st_idx].spill_slab_idx < 0 {
        guard core::add_sat_i64(sess.streams[st_idx].body.len, payload.len) <= 65536 else {
            emit_rst_stream(stream_id, rfc::H2_ERR_CANCEL, out_wire);
            return false;
        }
        let slab_idx = acquire_spill_slab(pool);
        guard slab_idx >= 0 else {
            // RFC 9113 Section 8.1: HTTP Message Framing - Stream rejected due to pool saturation
            emit_rst_stream(stream_id, rfc::H2_ERR_REFUSED_STREAM, out_wire);
            return false;
        }
        sess.streams[st_idx].spill_slab_idx = slab_idx;
        sess.streams[st_idx].slab_lease_deadline_ns = core::monotonic_now().as_nanos() + 3000000000;
        let slab_slot = slab_idx as i64;
        guard slab_slot >= 0 && slab_slot < pool.slabs.len else { return false; }
        pool.slabs[slab_slot].data.append(sess.streams[st_idx].body[..]);
        sess.streams[st_idx].body.clear();
        // RFC 9113 Section 6.9: WINDOW_UPDATE - Grant remaining credit up to 64 KiB
        emit_window_update(stream_id, H2_SLAB_WINDOW_INCREMENT, out_wire);
    }

    // 3. Bounds Check Elimination (BCE) guarded append with lease deadline check
    let now_ns = core::monotonic_now().as_nanos();
    if now_ns > sess.streams[st_idx].slab_lease_deadline_ns {
        emit_rst_stream(stream_id, rfc::H2_ERR_CANCEL, out_wire);
        return false;
    }

    let slab_slot = sess.streams[st_idx].spill_slab_idx as i64;
    guard slab_slot >= 0 && slab_slot < pool.slabs.len else { return false; }
    guard pool.slabs[slab_slot].data.try_append(payload) else {
        // Exceeds 64 KiB maximum slab capacity: emit CANCEL
        emit_rst_stream(stream_id, rfc::H2_ERR_CANCEL, out_wire);
        return false;
    }
    return true;
}

inline fn replenish_closed_stream_conn_window<B>(
    sess:     H2ServerSession&,
    data_len: u32,
    out_wire: B&,
) -> bool {
    sess.conn.conn_recv_window -= data_len as i64;
    guard sess.conn.conn_recv_window >= 0 else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FLOW_CONTROL_ERROR, out_wire);
        return false;
    }
    if data_len > 0 {
        emit_window_update(0, data_len, out_wire);
        sess.conn.conn_recv_window += data_len as i64;
    }
    return true;
}

inline fn replenish_ingress_data_windows<B>(
    sess:               H2ServerSession&,
    s_idx:              i32,
    stream_id:          u32,
    frame_len:          u32,
    skip_stream_window: bool,
    out_wire:           B&,
) {
    guard frame_len > 0 else { return; }
    let f_len = frame_len as i64;
    let threshold: i64 = if sess.conn.coalesce_window_updates && sess.conn.local_initial_window_size > 0 {
        ((sess.conn.local_initial_window_size as u64) >> 1) as i64
    } else {
        1
    };
    sess.conn.unclaimed_recv_window = core::add_sat_i64(sess.conn.unclaimed_recv_window, f_len);
    if sess.conn.unclaimed_recv_window >= threshold {
        let conn_inc = sess.conn.unclaimed_recv_window;
        emit_window_update(0, conn_inc as u32, out_wire);
        sess.conn.conn_recv_window = core::add_sat_i64(sess.conn.conn_recv_window, conn_inc);
        sess.conn.unclaimed_recv_window = 0;
    }
    guard !skip_stream_window else { return; }
    let st_idx = s_idx as i64;
    guard st_idx >= 0 && st_idx < sess.streams.len else { return; }
    sess.streams[st_idx].unclaimed_local_window = core::add_sat_i64(
        sess.streams[st_idx].unclaimed_local_window, f_len,
    );
    guard sess.streams[st_idx].unclaimed_local_window >= threshold else { return; }
    let st_inc = sess.streams[st_idx].unclaimed_local_window;
    emit_window_update(stream_id, st_inc as u32, out_wire);
    sess.streams[st_idx].unclaimed_local_window = 0;
    let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, stream_id);
    guard c_found else { return; }
    let c_slot = c_idx as i64;
    if c_slot >= 0 && c_slot < sess.conn.streams.len {
        sess.conn.streams[c_slot].recv_window = core::add_sat_i64(
            sess.conn.streams[c_slot].recv_window, st_inc,
        );
    }
}

fn process_ingress_data<B>(
    sess:          H2ServerSession&,
    pipeline:      wing::ServerPipelineConfig&,
    hdr:           const h2_internal::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    // Handle PADDED flag RFC 9113 Section 6.1
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 {
        if frame_payload.len < 1 {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return false;
        }
        let pad_len = frame_payload[0] as i64;
        if pad_len >= frame_payload.len {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
    }

    let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
    if !found {
        if (hdr.stream_id & 1) == 1 && hdr.stream_id <= sess.conn.last_peer_stream_id {
            // RFC 9113 §5.1 & §6.9: Account connection window before emitting stream error STREAM_CLOSED
            guard replenish_closed_stream_conn_window(sess, hdr.length, out_wire) else {
                return false;
            }
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
            return true;
        } else {
            // Idle stream receives DATA -> connection error PROTOCOL_ERROR (RFC 9113 §5.1)
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
    }

    // Stream is found; check if stream is already half-closed (remote)
    if sess.streams[s_idx].body_received {
        // RFC 9113 §5.1 & §6.9: Receiving DATA after END_STREAM is a stream error STREAM_CLOSED
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        guard replenish_closed_stream_conn_window(sess, hdr.length, out_wire) else {
            return false;
        }
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
        return true;
    }

    var d_start: i64 = 0;
    var d_end:   i64 = frame_payload.len;

    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 && frame_payload.len >= 1 {
        let pad_len = frame_payload[0] as i64;
        d_start += 1;
        d_end -= pad_len;
    }

    let d_len: i64 = if d_start <= d_end && d_end <= frame_payload.len { d_end - d_start } else { 0 };

    if sess.streams[s_idx].spill_slab_idx < 0 &&
       core::add_sat_i64(sess.streams[s_idx].body.len, d_len) > 8192 {
        let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].recv_window = core::add_sat_i64(
                sess.conn.streams[c_idx].recv_window, H2_SLAB_WINDOW_INCREMENT as i64,
            );
        }
    }

    // RFC 9113 §8.1.1 & §8.1.2: Pass application data length (d_len) for Content-Length validation,
    // while connection and stream flow-control windows account for the full frame payload (hdr.length).
    let flow_err = h2_internal::on_data_frame_received(sess.conn, hdr, d_len as u32);
    if flow_err != rfc::H2_ERR_NO_ERROR {
        if flow_err == rfc::H2_ERR_STREAM_CLOSED || flow_err == rfc::H2_ERR_PROTOCOL_ERROR {
            // RFC 9113 §8.1.2: Content-Length mismatch is a stream error of type PROTOCOL_ERROR
            emit_rst_stream(hdr.stream_id, flow_err, out_wire);
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            if hdr.length > 0 {
                emit_window_update(0, hdr.length, out_wire);
                sess.conn.conn_recv_window += hdr.length as i64;
            }
            return true;
        }
        emit_goaway(sess.conn.last_peer_stream_id, flow_err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return false;
    }

    let had_slab = sess.streams[s_idx].spill_slab_idx >= 0;
    if d_len > 0 {
        let app_ok = process_stream_data_ingress(
            sess, pipeline.slab_pool, s_idx, frame_payload[d_start..d_end], hdr.stream_id, out_wire,
        );
        guard app_ok else {
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            if hdr.length > 0 {
                emit_window_update(0, hdr.length, out_wire);
                sess.conn.conn_recv_window += hdr.length as i64;
            }
            return true;
        }
    }
    //
    //
    //
    let promoted_now = !had_slab && sess.streams[s_idx].spill_slab_idx >= 0;
    let is_end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;

    replenish_ingress_data_windows(sess, s_idx, hdr.stream_id, hdr.length, promoted_now || is_end_stream, out_wire);

    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        let dec_cl = sess.streams[s_idx].declared_content_length;
        let actual_len: i64 = if sess.streams[s_idx].spill_slab_idx >= 0 {
            let s_slot = sess.streams[s_idx].spill_slab_idx as i64;
            if s_slot >= 0 && s_slot < pipeline.slab_pool.slabs.len {
                pipeline.slab_pool.slabs[s_slot].data.len
            } else {
                0
            }
        } else {
            sess.streams[s_idx].body.len
        };
        if dec_cl >= 0 && dec_cl != actual_len {
            // RFC 9113 Section 8.1.1: Malformed Messages - Content-Length mismatch MUST be treated as malformed
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            return true;
        }
        sess.streams[s_idx].body_received = true;
        sess.streams[s_idx].phase = H2StreamPhase.HalfClosedRemote;
    }
    return true;
}

// ---- Complete Ingress Frame Processing & Pipeline Dispatch ---------------

// Processes incoming HTTP/2 wire data, executing complete streams through the server pipeline.
// Returns (total_bytes_consumed, success)
// Scans wire frames in batch to record stream IDs cancelled by RST_STREAM (CVE-2023-44487).
fn collect_cancelled_streams(
    sess:              const H2ServerSession&,
    wire:              const u8[:],
    offset:            i64,
    cancelled_streams: u32[..128]&,
) {
    var p_scan = offset;
    while p_scan + 9 <= wire.len {
        let sc_hdr, sc_err = h2_internal::parse_frame_header(wire[p_scan..p_scan + 9], sess.conn.local_max_frame_size);
        if sc_err != rfc::H2_ERR_NO_ERROR {
            break;
        }
        let sc_tot = 9 + (sc_hdr.length as i64);
        guard p_scan + sc_tot <= wire.len else { break; }
        if sc_hdr.frame_type == rfc::H2_FRAME_RST_STREAM && sc_hdr.stream_id != 0 && sc_hdr.length == 4 {
            guard cancelled_streams.try_push(sc_hdr.stream_id) else { break; }
        }
        p_scan += sc_tot;
    }
}

fn process_ingress_goaway<B>(
    sess:          H2ServerSession&,
    hdr:           const h2_internal::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    guard hdr.stream_id == 0 else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return false;
    }
    guard frame_payload.len >= 8 else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }
    let last_stream_id = core::read_be_u32(frame_payload, 0) & 0x7FFFFFFF;
    let err_code = core::read_be_u32(frame_payload, 4);
    sess.conn.is_server = true;
    let ga_err = h2_internal::apply_goaway(sess.conn, last_stream_id, err_code);
    guard ga_err == rfc::H2_ERR_NO_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, ga_err, out_wire);
        return false;
    }
    return true;
}

inline fn process_ingress_priority<B>(
    sess:          H2ServerSession&,
    pipeline:      wing::ServerPipelineConfig&,
    hdr:           const h2_internal::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    guard frame_payload.len == 5 else {
        // RFC 9113 §6.3: PRIORITY with length other than 5 is stream error FRAME_SIZE_ERROR
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    let dep_raw = core::read_be_u32(frame_payload, 0) & 0x7FFFFFFF;
    if !sess.conn.no_rfc7540_priorities && dep_raw == hdr.stream_id {
        // RFC 9113 §5.3.1: Stream cannot depend on itself -> stream error PROTOCOL_ERROR
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
    }
    return true;
}

inline fn process_ingress_ping<B>(
    sess:          H2ServerSession&,
    hdr:           const h2_internal::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) {
    guard frame_payload.len == 8 else { return; }
    if (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        var opaque: u8[8] = [0; 8];
        for i in 8 { opaque[i] = frame_payload[i]; }
        emit_ping_ack(opaque, out_wire);
        return;
    }
    let rx_opaque = core::read_be_u64(frame_payload, 0);
    if sess.conn.shutdown_notice_sent && !sess.conn.goaway_sent && rx_opaque == sess.conn.shutdown_ping_opaque {
        emit_goaway(sess, rfc::H2_ERR_NO_ERROR, out_wire);
    }
}

fn dispatch_ingress_frame<B>(
    sess:              H2ServerSession&,
    pipeline:          wing::ServerPipelineConfig&,
    hdr:               const h2_internal::FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS {
        return process_ingress_settings(sess, hdr, frame_payload, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_GOAWAY {
        return process_ingress_goaway(sess, hdr, frame_payload, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_PING {
        process_ingress_ping(sess, hdr, frame_payload, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_PRIORITY {
        return process_ingress_priority(sess, pipeline, hdr, frame_payload, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_PRIORITY_UPDATE {
        let prio_stream_id, prio_param, prio_err = h2_internal::parse_priority_update_payload(frame_payload, false);
        if prio_err != rfc::H2_ERR_NO_ERROR || (prio_stream_id & 1) == 0 {
            let final_err = if prio_err != rfc::H2_ERR_NO_ERROR { prio_err } else { rfc::H2_ERR_PROTOCOL_ERROR };
            emit_goaway(sess.conn.last_peer_stream_id, final_err, out_wire);
            return false;
        }
        h2_internal::apply_priority_update(sess.conn, prio_stream_id, prio_param);
    } else if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE {
        return process_ingress_window_update(sess, pipeline, hdr, frame_payload, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_RST_STREAM {
        for i in sess.streams.len {
            guard sess.streams[i].active && sess.streams[i].stream_id == hdr.stream_id else { continue; }
            sess.streams[i].active = false;
            if sess.streams[i].spill_slab_idx >= 0 {
                release_spill_slab(pipeline.slab_pool, sess.streams[i].spill_slab_idx);
            }
            reset_server_stream(sess.streams[i]);
        }
    } else if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        return process_ingress_headers(sess, pipeline, hdr, frame_payload, cancelled_streams, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_CONTINUATION {
        return process_ingress_continuation(sess, pipeline, hdr, frame_payload, cancelled_streams, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_DATA {
        return process_ingress_data(sess, pipeline, hdr, frame_payload, out_wire);
    }
    return true;
}

inline fn copy_stream_headers_and_trailers(st: const H2ServerStream&, req: wing::Request&) {
    if st.authority.len > 0 && !wing::has_header(st.headers, "host") {
        let _ = wing::append_header(req.headers, "host", st.authority[..]);
        req.presence_mask |= wing::HDR_PRESENCE_HOST;
    }
    for &e in st.headers.entries {
        let name = wing::entry_name(st.headers, e);
        let val = wing::entry_value(st.headers, e);
        guard wing::append_header(req.headers, name, val) else { break; }
        let known_id = wing::identify_known_header(name);
        req.presence_mask |= wing::header_id_to_bit(known_id);
    }
    wing::append_all_headers(st.trailers, req.trailers);
}

inline fn complete_server_stream_response(
    sess:             H2ServerSession&,
    stream_idx:       i64,
    target_stream_id: u32,
) {
    sess.streams[stream_idx].response_sent = true;
    sess.streams[stream_idx].phase = H2StreamPhase.Closed;
    sess.streams[stream_idx].active = false;

    let c_idx, c_found = h2_internal::find_session_stream_idx(sess.conn, target_stream_id);
    if c_found {
        sess.conn.streams[c_idx].state = h2_internal::H2StreamState.Closed;
        sess.conn.streams[c_idx].active = false;
        let _ = core::flat_index_remove(sess.conn.stream_index[..], target_stream_id);
        if sess.conn.active_stream_count > 0 {
            sess.conn.active_stream_count--;
        }
        h2_internal::sync_stream_urgency_node(sess.conn, c_idx);
    }
}

fn flush_pending_server_stream<B>(
    sess:       H2ServerSession&,
    pipeline:   wing::ServerPipelineConfig&,
    stream_idx: i64,
    out_wire:   B&,
) {
    let target_stream_id = sess.streams[stream_idx].stream_id;
    let quota = h2_internal::compute_stream_send_quota(sess.conn, target_stream_id);
    guard quota > 0 else { return; }

    let has_trailers = sess.streams[stream_idx].pending_has_trailers;
    if sess.streams[stream_idx].spill_slab_idx >= 0 {
        let s_slot = sess.streams[stream_idx].spill_slab_idx as i64;
        guard s_slot >= 0 && s_slot < pipeline.slab_pool.slabs.len else { return; }
        let sent = emit_response_data(
            sess,
            target_stream_id,
            pipeline.slab_pool.slabs[s_slot].data[..],
            sess.conn.peer_max_frame_size,
            out_wire,
            !has_trailers,
        );
        if sent < pipeline.slab_pool.slabs[s_slot].data.len {
            var rem_slab: u8[..65536] = [];
            let _ = rem_slab.try_set(pipeline.slab_pool.slabs[s_slot].data[sent..]);
            let _ = pipeline.slab_pool.slabs[s_slot].data.try_set(rem_slab[..]);
            return;
        }
        release_spill_slab(pipeline.slab_pool, sess.streams[stream_idx].spill_slab_idx);
        sess.streams[stream_idx].spill_slab_idx = -1;
    } else {
        let sent = emit_response_data(
            sess,
            target_stream_id,
            sess.streams[stream_idx].body[..],
            sess.conn.peer_max_frame_size,
            out_wire,
            !has_trailers,
        );
        if sent < sess.streams[stream_idx].body.len {
            var rem_body: u8[..8192] = [];
            let _ = rem_body.try_set(sess.streams[stream_idx].body[sent..]);
            let _ = sess.streams[stream_idx].body.try_set(rem_body[..]);
            return;
        }
        sess.streams[stream_idx].body.clear();
    }
    if has_trailers {
        emit_response_trailers(sess, target_stream_id, sess.streams[stream_idx].trailers, out_wire);
    }
    complete_server_stream_response(sess, stream_idx, target_stream_id);
}

inline fn stash_pending_response_body(
    sess:       H2ServerSession&,
    pipeline:   wing::ServerPipelineConfig&,
    stream_idx: i64,
    rem_slice:  const u8[:],
) -> bool {
    if sess.streams[stream_idx].body.try_set(rem_slice) {
        return true;
    }
    let slab_idx = acquire_spill_slab(pipeline.slab_pool);
    guard slab_idx >= 0 else { return false; }
    if pipeline.slab_pool.slabs[slab_idx].data.try_set(rem_slice) {
        sess.streams[stream_idx].spill_slab_idx = slab_idx;
        return true;
    }
    release_spill_slab(pipeline.slab_pool, slab_idx);
    return false;
}

inline fn buffer_unsent_response_tail<B>(
    sess:             H2ServerSession&,
    pipeline:         wing::ServerPipelineConfig&,
    stream_idx:       i64,
    target_stream_id: u32,
    rem_slice:        const u8[:],
    res:              const wing::Response&,
    has_trailers:     bool,
    out_wire:         B&,
) {
    if !stash_pending_response_body(sess, pipeline, stream_idx, rem_slice) {
        emit_rst_stream(target_stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, target_stream_id);
        return;
    }
    sess.streams[stream_idx].trailers.clear();
    if has_trailers {
        wing::append_all_headers(res.trailers, sess.streams[stream_idx].trailers);
    }
    sess.streams[stream_idx].pending_has_trailers = has_trailers;
}

fn emit_h2_stream_response<B>(
    sess:             H2ServerSession&,
    pipeline:         wing::ServerPipelineConfig&,
    stream_idx:       i64,
    target_stream_id: u32,
    res:              const wing::Response&,
    out_wire:         B&,
) {
    let has_body = res.body.len > 0 && !rfc::is_empty_body_status(res.status_code);
    let has_trailers = res.trailers.entries.len > 0;
    let end_headers = !has_body && !has_trailers;
    emit_response_headers(sess, target_stream_id, res, end_headers, out_wire);
    sess.streams[stream_idx].headers_sent = true;
    if has_body {
        let end_data = !has_trailers;
        let sent = emit_response_data(
            sess, target_stream_id, res.body[..], sess.conn.peer_max_frame_size, out_wire, end_data,
        );
        if sent < res.body.len {
            buffer_unsent_response_tail(
                sess, pipeline, stream_idx, target_stream_id, res.body[sent..], res, has_trailers, out_wire,
            );
            return;
        }
    }
    if has_trailers {
        emit_response_trailers(sess, target_stream_id, res.trailers, out_wire);
    }
    complete_server_stream_response(sess, stream_idx, target_stream_id);
}

fn find_active_h2_stream_by_id(sess: const H2ServerSession&, target_stream_id: u32) -> i64 {
    for i in sess.streams.len {
        if sess.streams[i].active && sess.streams[i].stream_id == target_stream_id {
            return i;
        }
    }
    return -1;
}

fn next_ready_h2_stream(sess: const H2ServerSession&) -> i64 {
    for i in sess.streams.len {
        let st .= sess.streams[i];
        if st.active && !st.response_sent && !st.headers_sent &&
           !st.pending_async && st.headers_received && st.body_received {
            return i;
        }
    }
    return -1;
}

fn flush_h2_stream_tails<B>(
    sess:     H2ServerSession&,
    pipeline: wing::ServerPipelineConfig&,
    out_wire: B&,
) {
    for i in sess.streams.len {
        if sess.streams[i].active && !sess.streams[i].response_sent && sess.streams[i].headers_sent {
            flush_pending_server_stream(sess, pipeline, i, out_wire);
        }
    }
}

fn execute_h2_stream_async<Stage, B>(
    sess:       H2ServerSession&,
    stream_idx: i64,
    pipeline:   wing::ServerPipelineConfig&,
    timer:      server_internal::ConnectionTimer&,
    client_ip:  const u8[:],
    now_ms:     u64,
    wake_token: core::WakeToken,
    out_req:    wing::Request&,
    out_sctx:   wing::ServerStageCtx&,
    out_wire:   B&,
    stage:      Stage&,
) -> wing::PipelineOutcome {
    let target_stream_id = sess.streams[stream_idx].stream_id;
    out_req = wing::new_request(sess.streams[stream_idx].method[..], sess.streams[stream_idx].path[..]);
    copy_stream_headers_and_trailers(sess.streams[stream_idx], out_req);
    if sess.streams[stream_idx].spill_slab_idx >= 0 {
        let s_slot = sess.streams[stream_idx].spill_slab_idx as i64;
        guard s_slot >= 0 && s_slot < pipeline.slab_pool.slabs.len else {
            return wing::PipelineOutcome.RateLimited;
        }
        out_req.body.append(pipeline.slab_pool.slabs[s_slot].data[..]);
        release_spill_slab(pipeline.slab_pool, sess.streams[stream_idx].spill_slab_idx);
        sess.streams[stream_idx].spill_slab_idx = -1;
    } else {
        out_req.body.append(sess.streams[stream_idx].body[..]);
        sess.streams[stream_idx].body.clear();
    }

    var res = wing::Response { .. };
    var future = server_internal::new_inline_handler_future(0);
    let now_ns = core::mul_sat_u64(now_ms, 1000000);
    out_sctx = wing::ServerStageCtx { wake_token: wake_token, now_ns: now_ns, .. };
    let outcome = wing::execute_server_pipeline_async(
        pipeline, timer, client_ip, out_req, now_ns, res, future, out_sctx, stage,
    );
    if outcome == wing::PipelineOutcome.Pending {
        sess.streams[stream_idx].pending_async = true;
        return wing::PipelineOutcome.Pending;
    }
    if res.status_code <= 0 {
        res.status_code = 500;
    }
    emit_h2_stream_response(sess, pipeline, stream_idx, target_stream_id, res, out_wire);
    return outcome;
}

fn complete_pending_h2_stream_response<Stage, B>(
    sess:             H2ServerSession&,
    target_stream_id: u32,
    pipeline:         wing::ServerPipelineConfig&,
    now_ms:           u64,
    req:              const wing::Request&,
    sctx:             wing::ServerStageCtx&,
    out_wire:         B&,
    stage:            Stage&,
) -> bool {
    let stream_idx = find_active_h2_stream_by_id(sess, target_stream_id);
    guard stream_idx >= 0 && sess.streams[stream_idx].pending_async else { return false; }
    sess.streams[stream_idx].pending_async = false;

    var res = wing::Response { .. };
    let now_ns = core::mul_sat_u64(now_ms, 1000000);
    let _ = wing::resume_server_pipeline_egress(pipeline, req, now_ns, sctx, res, stage);
    if res.status_code <= 0 {
        res.status_code = 500;
    }
    emit_h2_stream_response(sess, pipeline, stream_idx, target_stream_id, res, out_wire);
    return true;
}

fn execute_ready_server_stream<Stage, B>(
    sess:       H2ServerSession&,
    stream_idx: i64,
    pipeline:   wing::ServerPipelineConfig&,
    timer:      server_internal::ConnectionTimer&,
    client_ip:  const u8[:],
    now_ms:     u64,
    out_wire:   B&,
    stage:      Stage&,
) {
    var req = wing::Request { .. };
    var sctx = wing::ServerStageCtx { .. };
    let _ = execute_h2_stream_async(
        sess,
        stream_idx,
        pipeline,
        timer,
        client_ip,
        now_ms,
        core::WakeToken { .. },
        req,
        sctx,
        out_wire,
        stage,
    );
}

fn dispatch_ready_server_streams<Stage, B>(
    sess:      H2ServerSession&,
    pipeline:  wing::ServerPipelineConfig&,
    timer:     server_internal::ConnectionTimer&,
    client_ip: const u8[:],
    now_ms:    u64,
    out_wire:  B&,
    stage:     Stage&,
) {
    for i in sess.streams.len {
        guard sess.streams[i].active && !sess.streams[i].response_sent else { continue; }
        if sess.streams[i].headers_sent {
            flush_pending_server_stream(sess, pipeline, i, out_wire);
            continue;
        }
        guard !sess.streams[i].pending_async else { continue; }
        guard sess.streams[i].headers_received && sess.streams[i].body_received else { continue; }
        execute_ready_server_stream(sess, i, pipeline, timer, client_ip, now_ms, out_wire, stage);
    }
}

// Validates HTTP/2 connection preface from client and advances wire offset.
//
// Example:
//   wire = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", offset = 0
//   returns: true, offset = 24
fn check_ingress_preface<B>(sess: H2ServerSession&, wire: const u8[:], offset: i64&, out_wire: B&) -> bool {
    guard !sess.preface_handled else { return true; }
    guard wire.len >= 24 && wire[..24] == rfc::H2_CLIENT_PREFACE[..] else {
        return false;
    }
    sess.preface_handled = true;
    offset += 24;

    emit_server_settings(out_wire);
    sess.server_settings_sent = true;
    sess.pending_settings_ack = true;
    return true;
}

inline fn validate_continuation_boundary(sess: const H2ServerSession&, hdr: const h2_internal::FrameHeader&) -> bool {
    if sess.header_accum_stream_id != 0 {
        return hdr.frame_type == rfc::H2_FRAME_CONTINUATION && hdr.stream_id == sess.header_accum_stream_id;
    }
    return hdr.frame_type != rfc::H2_FRAME_CONTINUATION;
}

// Accumulates or discards an HPACK header block for a rejected HEADERS frame (RFC 7540 §4.3).
// Leaves `offset` unchanged on `false`; advances `offset` by `total_frame_len` on `true`.
//
// Example:
//   frame_payload = "\x82\x86\x84", total_frame_len = 12, offset = 0
//   returns: true, offset = 12
inline fn accumulate_rejected_headers_block<B>(
    sess:            H2ServerSession&,
    hdr:             const h2_internal::FrameHeader&,
    frame_payload:   const u8[:],
    err:             u32,
    total_frame_len: i64,
    now_ms:          u64,
    offset:          i64&,
    out_wire:        B&,
) -> bool {
    var b_start: i64 = 0;
    var b_end:   i64 = frame_payload.len;
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 {
        guard frame_payload.len >= 1 && (frame_payload[0] as i64) < frame_payload.len else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
        b_start += 1;
        b_end -= frame_payload[0] as i64;
    }
    if (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 {
        guard (b_end - b_start) >= 5 else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return false;
        }
        b_start += 5;
    }
    let frag = frame_payload[b_start..b_end];
    guard sess.header_accumulator.try_set(frag) else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }
    sess.header_accum_stream_id = hdr.stream_id;
    sess.header_accum_rejected_err = err;
    sess.header_accum_end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
    sess.header_accum_is_trailer = false;
    sess.conn.continuation_stream_id = hdr.stream_id;
    sess.conn.continuation_frames_cnt = 0;
    sess.conn.accumulated_header_size = hdr.length;
    sess.conn.continuation_start_ms = now_ms;
    offset += total_frame_len;
    return true;
}

inline fn decompress_rejected_headers_frame<B>(
    sess:          H2ServerSession&,
    hdr:           const h2_internal::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    let frag, f_err = h2_internal::extract_headers_frame_payload(hdr, frame_payload, true);
    guard f_err == rfc::H2_ERR_NO_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, f_err, out_wire);
        return false;
    }
    var dummy_pseudo = h2_internal::H2PseudoHeaders { .. };
    var dummy_headers = wing::HeaderMap { .. };
    let dec_err = h2_internal::decode_hpack_to_map(
        sess.conn.hpack_dec, frag, dummy_pseudo, dummy_headers, sess.conn.max_header_list_size, false,
    );
    guard dec_err != rfc::H2_ERR_COMPRESSION_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_COMPRESSION_ERROR, out_wire);
        return false;
    }
    return true;
}

// Handles frame header ingress errors, emitting stream resets and advancing offset.
fn handle_ingress_header_error<B>(
    sess:            H2ServerSession&,
    pipeline:        wing::ServerPipelineConfig&,
    hdr:             const h2_internal::FrameHeader&,
    frame_payload:   const u8[:],
    err:             u32,
    total_frame_len: i64,
    now_ms:          u64,
    offset:          i64&,
    out_wire:        B&,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_HEADERS && err == rfc::H2_ERR_STREAM_CLOSED {
        let c_idx, c_closed = h2_internal::find_closed_h2_stream_idx(sess.conn, hdr.stream_id);
        if c_closed && !sess.conn.streams[c_idx].closed_by_rst {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
            return false;
        }
    }
    let _, has_open_st = find_server_stream_idx(sess, hdr.stream_id);
    let is_trailer_proto_err = (hdr.frame_type == rfc::H2_FRAME_HEADERS && err == rfc::H2_ERR_PROTOCOL_ERROR &&
        has_open_st && !(hdr.length == 0 && (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0));
    let is_prio_size_err = (hdr.frame_type == rfc::H2_FRAME_PRIORITY && err == rfc::H2_ERR_FRAME_SIZE_ERROR);
    let is_stream_err = err == rfc::H2_ERR_STREAM_CLOSED || err == rfc::H2_ERR_REFUSED_STREAM ||
        is_prio_size_err || is_trailer_proto_err;
    guard is_stream_err else {
        emit_goaway(sess.conn.last_peer_stream_id, err, out_wire);
        return false;
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
            return accumulate_rejected_headers_block(
                sess, hdr, frame_payload, err, total_frame_len, now_ms, offset, out_wire,
            );
        }
        guard decompress_rejected_headers_frame(sess, hdr, frame_payload, out_wire) else {
            return false;
        }
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS && err == rfc::H2_ERR_REFUSED_STREAM
        && (hdr.stream_id & 1) == 1 && hdr.stream_id > sess.conn.last_peer_stream_id
        && !(sess.conn.goaway_received || sess.conn.goaway_sent) {
        sess.conn.last_peer_stream_id = hdr.stream_id;
    }
    emit_rst_stream(hdr.stream_id, err, out_wire);
    terminate_server_stream(sess, pipeline, hdr.stream_id);
    offset += total_frame_len;
    return true;
}

// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame - server MUST ignore client ALTSVC frames
// RFC 8336 Section 2.2: Processing ORIGIN Frames - server ignores client ORIGIN frames
inline fn skip_server_ignored_extension_frame<B>(
    sess:     H2ServerSession&,
    hdr:      const h2_internal::FrameHeader&,
    out_wire: B&,
) -> bool, bool {
    guard hdr.frame_type == rfc::H2_FRAME_ALTSVC || hdr.frame_type == rfc::H2_FRAME_ORIGIN else {
        return false, true;
    }
    if sess.conn.continuation_stream_id != 0 {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return true, false;
    }
    if hdr.length == 0 {
        sess.conn.empty_frame_streak = core::add_sat_u32(sess.conn.empty_frame_streak, 1);
        if sess.conn.empty_frame_streak > h2_internal::MAX_EMPTY_FRAME_STREAK {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_ENHANCE_YOUR_CALM, out_wire);
            return true, false;
        }
    } else {
        sess.conn.empty_frame_streak = 0;
    }
    return true, true;
}

// Validates and dispatches one HTTP/2 server ingress frame, advancing `offset` on success.
// Leaves `offset` unchanged on connection-fatal `false`.
//
// Example:
//   hdr = FrameHeader { length: 0, frame_type: 4, flags: 1, stream_id: 0 }, next_offset = 33, offset = 24
//   returns: true, offset = 33
inline fn step_h2_server_ingress_frame<B>(
    sess:              H2ServerSession&,
    pipeline:          wing::ServerPipelineConfig&,
    hdr:               const h2_internal::FrameHeader&,
    frame_payload:     const u8[:],
    total_frame_len:   i64,
    next_offset:       i64,
    now_ms:            u64,
    cancelled_streams: const u32[:],
    offset:            i64&,
    out_wire:          B&,
) -> bool {
    guard validate_continuation_boundary(sess, hdr) else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return false;
    }
    let ignored, ok_ext = skip_server_ignored_extension_frame(sess, hdr, out_wire);
    if ignored {
        if ok_ext {
            offset = next_offset;
        }
        return ok_ext;
    }

    let err = h2_internal::on_ingress_frame_header(sess.conn, hdr, now_ms);
    if err != rfc::H2_ERR_NO_ERROR {
        return handle_ingress_header_error(
            sess, pipeline, hdr, frame_payload, err, total_frame_len, now_ms, offset, out_wire,
        );
    }

    if hdr.frame_type == rfc::H2_FRAME_PUSH_PROMISE {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return false;
    }
    guard dispatch_ingress_frame(sess, pipeline, hdr, frame_payload, cancelled_streams, out_wire) else {
        return false;
    }
    offset = next_offset;
    return true;
}

// Parses and dispatches all complete HTTP/2 frames in `wire` without executing ready streams yet.
// Returns `(bytes_consumed, connection_ok)`.
//
// Example:
//   wire = H2_CLIENT_PREFACE + SETTINGS_FRAME, offset = 0
//   returns: consumed = 33, ok = true
fn ingest_h2_server_frames<B>(
    sess:     H2ServerSession&,
    pipeline: wing::ServerPipelineConfig&,
    wire:     const u8[:],
    now_ms:   u64,
    out_wire: B&,
) -> i64, bool {
    var offset: i64 = 0;
    var ok_conn = false;
    defer if !ok_conn { cleanup_h2_server_session(sess, pipeline); };
    guard check_ingress_preface(sess, wire, offset, out_wire) else { return 0, false; }

    var cancelled_streams: u32[..128] = [];
    collect_cancelled_streams(sess, wire, offset, cancelled_streams);

    while core::add_sat_i64(offset, 9) <= wire.len {
        let hdr_end = core::add_sat_i64(offset, 9);
        let hdr, err_hdr = h2_internal::parse_frame_header(wire[offset..hdr_end], sess.conn.local_max_frame_size);
        guard err_hdr == rfc::H2_ERR_NO_ERROR else {
            emit_goaway(sess.conn.last_peer_stream_id, err_hdr, out_wire);
            return offset, false;
        }
        let total_frame_len = core::add_sat_i64(9, hdr.length as i64);
        let next_offset = core::add_sat_i64(offset, total_frame_len);
        guard next_offset <= wire.len else { break; }
        let frame_payload = wire[hdr_end..next_offset];
        guard step_h2_server_ingress_frame(
            sess, pipeline, hdr, frame_payload, total_frame_len, next_offset, now_ms,
            cancelled_streams[..], offset, out_wire,
        ) else {
            return next_offset, false;
        }
    }

    flush_server_control_frames(sess);
    ok_conn = true;
    return offset, true;
}

// Processes incoming HTTP/2 wire data, executing complete streams through the server pipeline with `<Stage>`.
// Returns (total_bytes_consumed, success)
fn handle_h2_server_ingress<Stage, B>(
    sess:      H2ServerSession&,
    pipeline:  wing::ServerPipelineConfig&,
    timer:     server_internal::ConnectionTimer&,
    client_ip: const u8[:],
    wire:      const u8[:],
    now_ms:    u64,
    out_wire:  B&,
    stage:     Stage&,
) -> i64, bool {
    let offset, ok_conn = ingest_h2_server_frames(sess, pipeline, wire, now_ms, out_wire);
    guard ok_conn else { return offset, false; }
    dispatch_ready_server_streams(sess, pipeline, timer, client_ip, now_ms, out_wire, stage);
    return offset, true;
}

// Processes incoming HTTP/2 wire data, executing complete streams through the server pipeline.
// Returns (total_bytes_consumed, success)
fn handle_h2_server_ingress<B>(
    sess:      H2ServerSession&,
    pipeline:  wing::ServerPipelineConfig&,
    timer:     server_internal::ConnectionTimer&,
    client_ip: const u8[:],
    wire:      const u8[:],
    now_ms:    u64,
    out_wire:  B&,
) -> i64, bool {
    var noop = wire::NoOpStage {};
    return handle_h2_server_ingress(sess, pipeline, timer, client_ip, wire, now_ms, out_wire, noop);
}
