// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/2 server session and stream descriptors, lifecycle, and response frame emitters.
namespace server_internal;

import std;
import core;
import rfc.http;
import rfc.h2;
import http.headers;
import http.request;
import http.response;
import http2.framing;
import http2.hpack;
import http2.connection;
import .router;
import .pool;
import .pipeline;
import .pipeline_internal;
import .router_internal;

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
    headers:                 http::HeaderMap = http::HeaderMap { .. },
    trailers:                http::HeaderMap = http::HeaderMap { .. },
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
    conn:                      http2::Connection    = http2::Connection { .. },
    hpack_enc:                 http2::DynamicTable  = http2::DynamicTable { .. },
    streams:                   H2ServerStream[..16] = [],
    preface_handled:           bool                 = false,
    server_settings_sent:      bool                 = false,
    client_settings_acked:     bool                 = false,
    pending_settings_ack:      bool                 = false,
    pending_dyn_size_update:   bool                 = false,
    pending_min_dyn_size:      u64                  = 4096,
    min_pending_max_size:      i64                  = 4096,
    server_name:               u8[..64]             = "goose-wing/1.0",
    header_accumulator:        u8[..16384]          = [],
    header_accum_stream_id:    u32                  = 0,
    header_accum_rejected_err: u32                  = 0,
    header_accum_end_stream:   bool                 = false,
    header_accum_is_trailer:   bool                 = false,
}

fn flush_server_control_frames(sess: H2ServerSession&) {
    while sess.conn.pending_control_frames > 0 {
        http2::ack_control_frame_flushed(sess.conn);
    }
}

fn new_h2_server_session(
    server_name_str: const u8[:] = "goose-wing/1.0",
    now_ms:          u64         = 0,
) -> H2ServerSession {
    var conn = http2::new_h2_connection(now_ms);
    conn.is_server = true;
    conn.enable_push = false;
    conn.max_concurrent_streams = 16;
    conn.local_initial_window_size = 8192;
    conn.max_header_list_size = 16384;
    var sess = H2ServerSession {
        conn:                  conn,
        hpack_enc:             http2::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
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

inline fn reset_hpack_dyn_table_inplace(dt: http2::DynamicTable&) {
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

inline fn reset_h2_stream_nodes_inplace(conn: http2::Connection&) {
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
        return core::sub_sat_i64(sess.streams.len, 1) as i32, true;
    }

    return -1, false;
}

// ---- Protocol Frame Serialization Helpers --------------------------------

// Emits the server's initial SETTINGS frame (RFC 9113 Section 6.5)
fn emit_server_settings<B>(out: B&) {
    let hdr = http2::FrameHeader {
        length:     24, // 4 settings * 6 bytes
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    http2::encode_frame_header_to(hdr, out);

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
    let hdr = http2::FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    http2::encode_frame_header_to(hdr, out);
}

// Emits a PING ACK frame echoing the client's 8-byte opaque payload
fn emit_ping_ack<B>(opaque: const u8[8]&, out: B&) {
    let hdr = http2::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    http2::encode_frame_header_to(hdr, out);
    for b in opaque {
        out.push(b);
    }
}

// Emits a WINDOW_UPDATE frame
fn emit_window_update<B>(stream_id: u32, increment: u32, out: B&) {
    let hdr = http2::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
        flags:      0,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(hdr, out);
    out.append_u32_be(increment & 0x7FFFFFFF);
}

// Emits a RST_STREAM frame
fn emit_rst_stream<B>(stream_id: u32, error_code: u32, out: B&) {
    let hdr = http2::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_RST_STREAM,
        flags:      0,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(hdr, out);
    out.append_u32_be(error_code);
}

// Emits a GOAWAY frame
fn emit_goaway<B>(last_stream_id: u32, error_code: u32, out: B&) {
    let hdr = http2::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_GOAWAY,
        flags:      0,
        stream_id:  0,
    };
    http2::encode_frame_header_to(hdr, out);
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
    let ping_hdr = http2::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      0,
        stream_id:  0,
    };
    http2::encode_frame_header_to(ping_hdr, out);
    out.append_u64_be(sess.conn.shutdown_ping_opaque);
    sess.conn.shutdown_notice_sent = true;
}

inline fn is_h2_forbidden_hop_header(name_slice: const u8[:]) -> bool {
    return rfc::is_connection_specific_header(name_slice) || name_slice.eq_ascii_fold("te");
}

inline fn emit_pending_dyn_size_updates<B>(sess: H2ServerSession&, hpack_block: B&) {
    guard sess.pending_dyn_size_update else { return; }
    let min_sz = if sess.min_pending_max_size >= 0 {
        min(sess.min_pending_max_size as u64, sess.pending_min_dyn_size)
    } else {
        sess.pending_min_dyn_size
    };
    if min_sz < sess.hpack_enc.current_max_size {
        let _ = http2::hpack_encode_int(hpack_block, min_sz, 5, 0x20);
    }
    let _ = http2::hpack_encode_int(hpack_block, sess.hpack_enc.current_max_size, 5, 0x20);
    sess.pending_dyn_size_update = false;
    sess.pending_min_dyn_size = sess.hpack_enc.current_max_size;
    sess.min_pending_max_size = sess.hpack_enc.current_max_size as i64;
}

// Encodes HTTP/2 Response HEADERS using HPACK
fn emit_response_headers<B>(
    sess:       H2ServerSession&,
    stream_id:  u32,
    res:        const http::Response&,
    end_stream: bool,
    out:        B&,
) {
    var hpack_block: u8[..16384] = [];
    emit_pending_dyn_size_updates(sess, hpack_block);
    let max_tbl = sess.hpack_enc.current_max_size as i64;

    var status_buf: u8[..16] = [];
    format(status_buf, res.status_code as i64);
    let st_idx_mode = http2::select_hpack_indexing(":status", status_buf[..], max_tbl);
    http2::encode_hpack_field(sess.hpack_enc, hpack_block, ":status", status_buf[..], st_idx_mode, true);

    if sess.server_name.len > 0 && !res.has_header("server") {
        let srv_idx_mode = http2::select_hpack_indexing("server", sess.server_name[..], max_tbl);
        http2::encode_hpack_field(
            sess.hpack_enc, hpack_block, "server", sess.server_name[..], srv_idx_mode, true,
        );
    }

    let is_grpc = res.header("content-type").starts_with_fold("application/grpc");
    let has_cl = res.header("content-length").len > 0;
    if !is_grpc && !has_cl && res.status_code >= 200 && res.status_code != 204 && res.status_code != 304 {
        var cl_buf: u8[..32] = [];
        format(cl_buf, res.body.len);
        let cl_idx_mode = http2::select_hpack_indexing("content-length", cl_buf[..], max_tbl);
        http2::encode_hpack_field(sess.hpack_enc, hpack_block, "content-length", cl_buf[..], cl_idx_mode, true);
    }

    for &e in res.headers.entries {
        let name_slice = http::entry_name(res.headers, e);
        let val_slice = http::entry_value(res.headers, e);
        guard !is_h2_forbidden_hop_header(name_slice) else { continue; }
        var lower_name: u8[..256] = [];
        guard name_slice.len <= lower_name.cap else { continue; }
        name_slice.to_lower_ascii(lower_name);
        let hdr_idx_mode = http2::select_hpack_indexing(lower_name[..], val_slice, max_tbl);
        http2::encode_hpack_field(
            sess.hpack_enc, hpack_block, lower_name[..], val_slice, hdr_idx_mode, true,
        );
    }

    var flags: u8 = rfc::H2_FLAG_END_HEADERS;
    if end_stream { flags |= rfc::H2_FLAG_END_STREAM; }
    let frame_hdr = http2::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

inline fn deduct_send_windows(
    conn:     http2::Connection&,
    c_idx:    i64,
    found:    bool,
    send_len: i64,
) {
    conn.conn_send_window = core::sub_sat_i64(conn.conn_send_window, send_len);
    if found {
        conn.streams[c_idx].send_window = core::sub_sat_i64(conn.streams[c_idx].send_window, send_len);
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
    let rem = core::sub_sat_i64(body.len, offset);
    let chunk_size = calc_data_chunk_size(rem, limit, quota);
    let next_off = core::add_sat_i64(offset, chunk_size);
    let is_last = (next_off >= body.len);
    let flags: u8 = if is_last && end_stream { rfc::H2_FLAG_END_STREAM } else { 0 };
    let hdr = http2::FrameHeader {
        length:     chunk_size as u32,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      flags,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(hdr, out);
    out.append(body[offset..next_off]);
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
    let c_idx, found = http2::find_stream_idx(sess.conn, stream_id);

    while offset < body.len {
        let quota = http2::compute_stream_send_quota(sess.conn, stream_id);
        if quota <= 0 {
            break;
        }

        let chunk_size = emit_one_data_frame(
            sess, stream_id, body, offset, limit, quota, c_idx, found, out, end_stream,
        );
        offset = core::add_sat_i64(offset, chunk_size);
    }
    return offset;
}

// Encodes HTTP/2 Response Trailing HEADERS using HPACK
fn emit_response_trailers<B>(
    sess:      H2ServerSession&,
    stream_id: u32,
    trailers:  const http::HeaderMap&,
    out:       B&,
) {
    guard trailers.entries.len > 0 else { return; }
    var hpack_block: u8[..4096] = [];

    for &e in trailers.entries {
        let name_slice = http::entry_name(trailers, e);
        let val_slice = http::entry_value(trailers, e);
        // RFC 9113 §8.1 / §8.2.2 & RFC 9110 §6.5.1: Trailers MUST NOT include pseudo-headers,
        // hop-by-hop connection headers, or disallowed framing/routing trailer fields.
        if name_slice.len > 0 && name_slice[0] != ':' &&
           !is_h2_forbidden_hop_header(name_slice) &&
           !rfc::is_disallowed_trailer_field(name_slice) {
            var lower_name: u8[..256] = [];
            guard name_slice.len <= lower_name.cap else { continue; }
            name_slice.to_lower_ascii(lower_name);
            if sess.pending_dyn_size_update && hpack_block.len == 0 {
                emit_pending_dyn_size_updates(sess, hpack_block);
            }
            http2::encode_hpack_field(
                sess.hpack_enc, hpack_block, lower_name[..], val_slice, http2::HpackIndexing.Incremental, false,
            );
        }
    }

    if hpack_block.len == 0 {
        let empty_data = http2::FrameHeader {
            length:     0,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      rfc::H2_FLAG_END_STREAM,
            stream_id:  stream_id,
        };
        http2::encode_frame_header_to(empty_data, out);
        return;
    }

    let frame_hdr = http2::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

fn apply_decoded_pseudo_to_stream(st: H2ServerStream&, pseudo: const http2::PseudoHeaders&) -> bool {
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
        guard http::append_header(st.headers, ":protocol", pseudo.protocol[..]) &&
              http::append_header(st.headers, ":scheme", pseudo.scheme[..]) &&
              http::append_header(st.headers, ":path", pseudo.path[..]) &&
              http::append_header(st.headers, ":authority", pseudo.authority[..]) else {
            return false;
        }
    }
    st.headers_received = true;
    st.phase = H2StreamPhase.Open;
    return true;
}

inline fn validate_decoded_map_bounds(map: const http::HeaderMap&) -> bool {
    for &e in map.entries {
        let n = http::entry_name(map, e);
        let v = http::entry_value(map, e);
        guard n.len <= 256 && v.len <= 8192 else { return false; }
    }
    return true;
}

inline fn is_stream_cancelled_in_batch(cancelled: const u32[:], stream_id: u32) -> bool {
    return cancelled.contains(stream_id);
}

fn terminate_server_stream(
    sess:      H2ServerSession&,
    pipeline:  server::ServerPipelineConfig&,
    stream_id: u32,
) {
    http2::reset_stream(sess.conn, stream_id);
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

fn cleanup_h2_server_session(sess: H2ServerSession&, pipeline: server::ServerPipelineConfig&) {
    for i in sess.streams.len {
        if sess.streams[i].active && sess.streams[i].spill_slab_idx >= 0 {
            release_spill_slab(pipeline.slab_pool, sess.streams[i].spill_slab_idx);
        }
        reset_server_stream(sess.streams[i]);
    }
}
