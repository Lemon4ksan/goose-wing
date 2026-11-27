// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/2 inbound frame validators and decoders (RFC 9113 SETTINGS, WINDOW_UPDATE, HEADERS, DATA).
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
import .h2_mux_types_internal;

const MAX_H2_CONN_SPILL_SLABS: i64 = 4;

inline fn count_active_conn_spill_slabs(sess: const H2ServerSession&) -> i64 {
    var count: i64 = 0;
    for &st in sess.streams {
        if st.active && st.spill_slab_idx >= 0 {
            count = core::add_sat_i64(count, 1);
        }
    }
    return count;
}

// Emits RST_STREAM while debiting `sess.conn.reset_limiter` (MadeYouReset defense).
// Sends GOAWAY(ENHANCE_YOUR_CALM) and returns false when the reset budget is exhausted.
fn emit_rate_limited_rst_stream<B>(
    sess:       H2ServerSession&,
    stream_id:  u32,
    error_code: u32,
    out_wire:   B&,
) -> bool {
    let now_ms = sess.conn.reset_limiter.last_refill_ms;
    guard core::token_bucket_consume(sess.conn.reset_limiter, now_ms) else {
        emit_goaway(sess, rfc::H2_ERR_ENHANCE_YOUR_CALM, out_wire);
        return false;
    }
    emit_rst_stream(stream_id, error_code, out_wire);
    return true;
}

inline fn validate_request_pseudo_headers(
    pseudo:                  const http2::PseudoHeaders&,
    end_stream:              bool,
    enable_connect_protocol: u32 = 1,
) -> bool {
    guard !(end_stream && pseudo.has_content_length && pseudo.content_length_val != 0) else { return false; }
    let is_connect = pseudo.has_method && pseudo.method[..] == "CONNECT";
    if pseudo.has_protocol {
        return is_connect && enable_connect_protocol == 1
            && pseudo.has_scheme && pseudo.has_path && pseudo.has_authority;
    }
    if is_connect {
        return pseudo.has_authority && !pseudo.has_scheme && !pseudo.has_path;
    }
    return pseudo.has_method && pseudo.has_scheme && pseudo.has_path;
}

fn process_ingress_window_update<B>(
    sess:          H2ServerSession&,
    pipeline:      server::ServerPipelineConfig&,
    hdr:           const http2::FrameHeader&,
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
    let wu_err = http2::apply_window_update(sess.conn, hdr.stream_id, inc);
    guard wu_err != rfc::H2_ERR_NO_ERROR else { return true; }
    if hdr.stream_id == 0 || http2::is_conn_error_on_window_update(sess.conn, hdr.stream_id) {
        emit_goaway(sess, wu_err, out_wire);
        return false;
    }
    let ok_rst = emit_rate_limited_rst_stream(sess, hdr.stream_id, wu_err, out_wire);
    terminate_server_stream(sess, pipeline, hdr.stream_id);
    return ok_rst;
}

inline fn apply_header_table_size_setting(sess: H2ServerSession&, param_val: u32) {
    let allowed_max = min(param_val as u64, http2::HPACK_MAX_ARENA_BYTES);
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
        http2::evict_until(sess.hpack_enc, allowed_max);
        sess.pending_dyn_size_update = true;
    }
}

inline fn active_streams_fit_window_delta(
    conn:         const http2::Connection&,
    cur_init_win: i64,
    new_init_win: i64,
) -> bool {
    guard new_init_win <= rfc::H2_MAX_WINDOW_SIZE else { return false; }
    let delta = core::sub_sat_i64(new_init_win, cur_init_win);
    for &stream in conn.streams {
        if stream.active && stream.state != http2::StreamState.Closed {
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
        let val_err = http2::validate_settings_parameter(param_id, param_val, false);
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
    hdr:           const http2::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        guard hdr.length == 0 else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return false;
        }
        guard sess.pending_settings_ack else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
        sess.pending_settings_ack = false;
        sess.client_settings_acked = true;
        http2::ack_control_frame_flushed(sess.conn);
        return true;
    }

    let pre_err = check_ingress_settings_frame(sess, frame_payload);
    guard pre_err == rfc::H2_ERR_NO_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, pre_err, out_wire);
        return false;
    }
    var rem = frame_payload;
    while rem.len >= 6 {
        let param_id = core::read_be_u16(rem, 0);
        let param_val = core::read_be_u32(rem, 2);
        rem = rem[6..];
        if param_id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE {
            let _ = http2::apply_peer_initial_window_size_delta(sess.conn, param_val);
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
    conn:      http2::Connection&,
    stream_id: u32,
    headers:   const http::HeaderMap&,
) {
    let s_idx, found = http2::find_stream_idx(conn, stream_id);
    if found && conn.streams[s_idx].has_explicit_priority_update {
        return;
    }
    let prio_hdr = http::get_header(headers, "priority");
    guard prio_hdr.len > 0 else { return; }
    let parsed_prio, ok_prio = http::parse_priority(prio_hdr, false);
    if ok_prio {
        let _ = http2::apply_priority_update(conn, stream_id, parsed_prio);
    }
}

// Strips optional PADDED and PRIORITY prefixes from an HTTP/2 HEADERS payload (RFC 9113 Section 6.2).
//
// Example:
//   hdr.flags = H2_FLAG_PADDED, frame_payload = "\x02abc\x00\x00"
//   returns: "abc", ok = true
fn extract_h2_headers_fragment<B>(
    sess:          H2ServerSession&,
    hdr:           const http2::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> const u8[:], bool {
    var block_start: i64 = 0;
    var block_end:   i64 = frame_payload.len;
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 {
        guard frame_payload.len >= 1 else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return "", false;
        }
        let pad_len = frame_payload[0] as i64;
        guard pad_len < frame_payload.len else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return "", false;
        }
        block_start = 1;
        block_end = core::sub_sat_i64(block_end, pad_len);
    }
    if (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 {
        guard core::sub_sat_i64(block_end, block_start) >= 5 else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return "", false;
        }
        let dep_raw = core::read_be_u32(frame_payload, block_start) & 0x7FFFFFFF;
        if !sess.conn.no_rfc7540_priorities && dep_raw == hdr.stream_id {
            // RFC 9113 Section 5.3.1: Stream Dependencies - Still decompress HPACK block (RFC 9113 Section 4.3).
            sess.header_accum_rejected_err = rfc::H2_ERR_PROTOCOL_ERROR;
        }
        block_start = core::add_sat_i64(block_start, 5);
    }
    guard block_start <= block_end && block_end <= frame_payload.len else { return "", true; }
    return frame_payload[block_start..block_end], true;
}

inline fn clear_h2_header_accumulator(sess: H2ServerSession&) {
    sess.header_accum_stream_id = 0;
    sess.conn.continuation_stream_id = 0;
    sess.header_accumulator.clear();
}

inline fn apply_h2_trailer_block<B>(
    sess:         H2ServerSession&,
    pipeline:     server::ServerPipelineConfig&,
    stream_id:    u32,
    dec_headers:  const http::HeaderMap&,
    is_cancelled: bool,
    out_wire:     B&,
) -> bool {
    guard !is_cancelled else { return true; }
    let s_idx, found = find_server_stream_idx(sess, stream_id);
    guard found else { return true; }
    guard validate_decoded_map_bounds(dec_headers) else {
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, stream_id);
        return ok_rst;
    }
    http::append_all_headers(dec_headers, sess.streams[s_idx].trailers);
    sess.streams[s_idx].body_received = true;
    sess.streams[s_idx].phase = H2StreamPhase.HalfClosedRemote;
    let c_idx, c_found = http2::find_stream_idx(sess.conn, stream_id);
    if c_found {
        sess.conn.streams[c_idx].trailers_received = true;
        sess.conn.streams[c_idx].state = http2::StreamState.HalfClosedRemote;
    }
    return true;
}

struct H2HeaderCommitFlags {
    is_trailer:   bool = false,
    end_stream:   bool = false,
    is_cancelled: bool = false,
    clear_accum:  bool = false,
}

inline fn apply_h2_request_block<B>(
    sess:        H2ServerSession&,
    pipeline:    server::ServerPipelineConfig&,
    stream_id:   u32,
    pseudo:      const http2::PseudoHeaders&,
    dec_headers: const http::HeaderMap&,
    flags:       H2HeaderCommitFlags,
    out_wire:    B&,
) -> bool {
    guard validate_request_pseudo_headers(pseudo, flags.end_stream, sess.conn.enable_connect_protocol) else {
        // RFC 9113 Section 8.1.1: Malformed Messages - Invalid pseudo-headers trigger PROTOCOL_ERROR.
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, stream_id);
        return ok_rst;
    }
    guard !flags.is_cancelled else {
        terminate_server_stream(sess, pipeline, stream_id);
        return true;
    }
    let s_idx, found = find_or_alloc_stream(sess, stream_id);
    guard found else {
        if (stream_id & 1) == 1 && stream_id > sess.conn.last_peer_stream_id
            && !(sess.conn.goaway_received || sess.conn.goaway_sent) {
            sess.conn.last_peer_stream_id = stream_id;
        }
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_REFUSED_STREAM, out_wire);
        terminate_server_stream(sess, pipeline, stream_id);
        return ok_rst;
    }
    guard validate_decoded_map_bounds(dec_headers) && apply_decoded_pseudo_to_stream(sess.streams[s_idx], pseudo) else {
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, stream_id);
        return ok_rst;
    }
    http::append_all_headers(dec_headers, sess.streams[s_idx].headers);
    apply_request_priority_header(sess.conn, stream_id, dec_headers);
    if pseudo.has_content_length {
        sess.streams[s_idx].declared_content_length = pseudo.content_length_val;
        let c_idx, c_found = http2::find_stream_idx(sess.conn, stream_id);
        if c_found { sess.conn.streams[c_idx].declared_content_length = pseudo.content_length_val; }
    }
    if flags.end_stream {
        sess.streams[s_idx].body_received = true;
        sess.streams[s_idx].phase = H2StreamPhase.HalfClosedRemote;
    }
    return true;
}

fn commit_decoded_h2_header_block<B>(
    sess:      H2ServerSession&,
    pipeline:  server::ServerPipelineConfig&,
    stream_id: u32,
    hdr_block: const u8[:],
    flags:     H2HeaderCommitFlags,
    out_wire:  B&,
) -> bool {
    var pseudo = http2::PseudoHeaders { is_trailer: flags.is_trailer, .. };
    var dec_headers = http::HeaderMap { .. };
    let dec_err = http2::decode_hpack_to_map(
        sess.conn.hpack_dec,
        hdr_block,
        pseudo,
        dec_headers,
        sess.conn.max_header_list_size,
        sess.header_accum_rejected_err == 0,
    );
    if flags.clear_accum { clear_h2_header_accumulator(sess); }
    let rej_err = sess.header_accum_rejected_err;
    sess.header_accum_rejected_err = 0;
    if dec_err == rfc::H2_ERR_COMPRESSION_ERROR || dec_err == rfc::H2_ERR_ENHANCE_YOUR_CALM {
        emit_goaway(sess, dec_err, out_wire);
        return false;
    }
    let stream_err = if rej_err != 0 { rej_err } else { dec_err };
    guard stream_err == rfc::H2_ERR_NO_ERROR else {
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, stream_err, out_wire);
        terminate_server_stream(sess, pipeline, stream_id);
        return ok_rst;
    }
    if flags.is_trailer {
        return apply_h2_trailer_block(sess, pipeline, stream_id, dec_headers, flags.is_cancelled, out_wire);
    }
    return apply_h2_request_block(sess, pipeline, stream_id, pseudo, dec_headers, flags, out_wire);
}

fn process_ingress_headers<B>(
    sess:              H2ServerSession&,
    pipeline:          server::ServerPipelineConfig&,
    hdr:               const http2::FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
    sess.header_accum_rejected_err = 0;
    let fragment, ok_frag = extract_h2_headers_fragment(sess, hdr, frame_payload, out_wire);
    guard ok_frag else { return false; }

    let s_exist_idx, s_exists = find_server_stream_idx(sess, hdr.stream_id);
    let is_trailer = s_exists && sess.streams[s_exist_idx].headers_received;
    if is_trailer {
        if sess.streams[s_exist_idx].body_received {
            sess.header_accum_rejected_err = rfc::H2_ERR_STREAM_CLOSED;
        } else if (hdr.flags & rfc::H2_FLAG_END_STREAM) == 0 {
            sess.header_accum_rejected_err = rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }

    let end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        sess.header_accumulator.clear();
        sess.header_accum_stream_id = hdr.stream_id;
        sess.header_accum_end_stream = end_stream;
        sess.header_accum_is_trailer = is_trailer;
        if sess.header_accumulator.try_set(fragment) { return true; }
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }
    let cflags = H2HeaderCommitFlags {
        is_trailer:   is_trailer,
        end_stream:   end_stream,
        is_cancelled: is_cancelled,
        clear_accum:  false,
    };
    return commit_decoded_h2_header_block(sess, pipeline, hdr.stream_id, fragment, cflags, out_wire);
}

fn process_ingress_continuation<B>(
    sess:              H2ServerSession&,
    pipeline:          server::ServerPipelineConfig&,
    hdr:               const http2::FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    guard hdr.stream_id == sess.header_accum_stream_id else { return true; }
    let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
    guard sess.header_accumulator.try_append(frame_payload) else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }
    guard (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 else { return true; }
    let cflags = H2HeaderCommitFlags {
        is_trailer:   sess.header_accum_is_trailer,
        end_stream:   sess.header_accum_end_stream,
        is_cancelled: is_cancelled,
        clear_accum:  true,
    };
    return commit_decoded_h2_header_block(
        sess, pipeline, hdr.stream_id, sess.header_accumulator[..], cflags, out_wire,
    );
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
// Returns (stream_ok, conn_ok): conn_ok=false means rate limit triggered GOAWAY.
fn process_stream_data_ingress<B>(
    sess:      H2ServerSession&,
    pool:      SpillSlabPool&,
    s_idx:     i32,
    payload:   const u8[:],
    stream_id: u32,
    out_wire:  B&,
) -> bool, bool {
    let st_idx = s_idx as i64;
    guard st_idx >= 0 && st_idx < sess.streams.len else { return false, true; }

    let total_inline = core::add_sat_i64(sess.streams[st_idx].body.len, payload.len);
    if sess.streams[st_idx].spill_slab_idx < 0 && total_inline <= sess.streams[st_idx].body.cap {
        sess.streams[st_idx].body.append(payload);
        return true, true;
    }

    if sess.streams[st_idx].spill_slab_idx < 0 {
        guard total_inline <= 65536 else {
            let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_CANCEL, out_wire);
            return false, ok_rst;
        }
        guard count_active_conn_spill_slabs(sess) < MAX_H2_CONN_SPILL_SLABS else {
            let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_REFUSED_STREAM, out_wire);
            return false, ok_rst;
        }
        let slab_idx = acquire_spill_slab(pool);
        guard slab_idx >= 0 else {
            let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_REFUSED_STREAM, out_wire);
            return false, ok_rst;
        }
        sess.streams[st_idx].spill_slab_idx = slab_idx;
        sess.streams[st_idx].slab_lease_deadline_ns = core::add_sat_u64(core::monotonic_now().as_nanos(), 3000000000);
        let slab_slot = slab_idx as i64;
        guard slab_slot >= 0 && slab_slot < pool.slabs.len else { return false, true; }
        pool.slabs[slab_slot].data.append(sess.streams[st_idx].body[..]);
        sess.streams[st_idx].body.clear();
        emit_window_update(stream_id, H2_SLAB_WINDOW_INCREMENT, out_wire);
    }

    let now_ns = core::monotonic_now().as_nanos();
    if now_ns > sess.streams[st_idx].slab_lease_deadline_ns {
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_CANCEL, out_wire);
        return false, ok_rst;
    }

    let slab_slot = sess.streams[st_idx].spill_slab_idx as i64;
    guard slab_slot >= 0 && slab_slot < pool.slabs.len else { return false, true; }
    guard pool.slabs[slab_slot].data.try_append(payload) else {
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_CANCEL, out_wire);
        return false, ok_rst;
    }
    return true, true;
}

inline fn replenish_closed_stream_conn_window<B>(
    sess:     H2ServerSession&,
    data_len: u32,
    out_wire: B&,
) -> bool {
    let dl = data_len as i64;
    sess.conn.conn_recv_window = core::sub_sat_i64(sess.conn.conn_recv_window, dl);
    guard sess.conn.conn_recv_window >= 0 else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FLOW_CONTROL_ERROR, out_wire);
        return false;
    }
    if data_len > 0 {
        emit_window_update(0, data_len, out_wire);
        sess.conn.conn_recv_window = core::add_sat_i64(sess.conn.conn_recv_window, dl);
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
    let c_idx, c_found = http2::find_stream_idx(sess.conn, stream_id);
    guard c_found else { return; }
    let c_slot = c_idx as i64;
    if c_slot >= 0 && c_slot < sess.conn.streams.len {
        sess.conn.streams[c_slot].recv_window = core::add_sat_i64(
            sess.conn.streams[c_slot].recv_window, st_inc,
        );
    }
}

// Strips optional PADDED byte range from an HTTP/2 DATA payload (RFC 9113 Section 6.1).
//
// Example:
//   hdr.flags = H2_FLAG_PADDED, frame_payload = "\x02hi\x00\x00"
//   returns: "hi", ok = true
inline fn extract_h2_data_payload_slice<B>(
    sess:          H2ServerSession&,
    hdr:           const http2::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> const u8[:], bool {
    guard (hdr.flags & rfc::H2_FLAG_PADDED) != 0 else { return frame_payload, true; }
    guard frame_payload.len >= 1 else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return "", false;
    }
    let pad_len = frame_payload[0] as i64;
    guard pad_len < frame_payload.len else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return "", false;
    }
    let d_end = core::sub_sat_i64(frame_payload.len, pad_len);
    guard d_end >= 1 && d_end <= frame_payload.len else { return "", true; }
    return frame_payload[1..d_end], true;
}

inline fn replenish_conn_window_direct<B>(sess: H2ServerSession&, length: u32, out_wire: B&) {
    guard length > 0 else { return; }
    emit_window_update(0, length, out_wire);
    sess.conn.conn_recv_window = core::add_sat_i64(sess.conn.conn_recv_window, length as i64);
}

inline fn finalize_h2_data_end_stream<B>(
    sess:      H2ServerSession&,
    pipeline:  server::ServerPipelineConfig&,
    s_idx:     i32,
    stream_id: u32,
    out_wire:  B&,
) {
    let dec_cl = sess.streams[s_idx].declared_content_length;
    let s_slot = sess.streams[s_idx].spill_slab_idx as i64;
    let actual_len: i64 = if s_slot >= 0 && s_slot < pipeline.slab_pool.slabs.len {
        pipeline.slab_pool.slabs[s_slot].data.len
    } else if s_slot >= 0 {
        0
    } else {
        sess.streams[s_idx].body.len
    };
    if dec_cl >= 0 && dec_cl != actual_len {
        let ok_rst = emit_rate_limited_rst_stream(sess, stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, stream_id);
        return ok_rst;
    }
    sess.streams[s_idx].body_received = true;
    sess.streams[s_idx].phase = H2StreamPhase.HalfClosedRemote;
    return true;
}

inline fn handle_h2_data_flow_error<B>(
    sess:     H2ServerSession&,
    pipeline: server::ServerPipelineConfig&,
    hdr:      const http2::FrameHeader&,
    flow_err: u32,
    out_wire: B&,
) -> bool {
    if flow_err == rfc::H2_ERR_STREAM_CLOSED || flow_err == rfc::H2_ERR_PROTOCOL_ERROR {
        let ok_rst = emit_rate_limited_rst_stream(sess, hdr.stream_id, flow_err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        guard ok_rst else { return false; }
        replenish_conn_window_direct(sess, hdr.length, out_wire);
        return true;
    }
    emit_goaway(sess, flow_err, out_wire);
    terminate_server_stream(sess, pipeline, hdr.stream_id);
    return false;
}

inline fn resolve_open_h2_data_stream<B>(
    sess:     H2ServerSession&,
    pipeline: server::ServerPipelineConfig&,
    hdr:      const http2::FrameHeader&,
    out_wire: B&,
) -> i32, bool, bool {
    let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
    if !found {
        if (hdr.stream_id & 1) == 1 && hdr.stream_id <= sess.conn.last_peer_stream_id {
            guard replenish_closed_stream_conn_window(sess, hdr.length, out_wire) else { return -1, false, false; }
            let ok_rst = emit_rate_limited_rst_stream(sess, hdr.stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
            return -1, false, ok_rst;
        }
        emit_goaway(sess, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return -1, false, false;
    }
    if sess.streams[s_idx].body_received {
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        guard replenish_closed_stream_conn_window(sess, hdr.length, out_wire) else { return -1, false, false; }
        let ok_rst = emit_rate_limited_rst_stream(sess, hdr.stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
        return -1, false, ok_rst;
    }
    return s_idx, true, true;
}

fn process_ingress_data<B>(
    sess:          H2ServerSession&,
    pipeline:      server::ServerPipelineConfig&,
    hdr:           const http2::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    let data_slice, ok_pad = extract_h2_data_payload_slice(sess, hdr, frame_payload, out_wire);
    guard ok_pad else { return false; }

    let s_idx, ready, conn_ok = resolve_open_h2_data_stream(sess, pipeline, hdr, out_wire);
    guard ready else { return conn_ok; }

    let d_len = data_slice.len;
    if sess.streams[s_idx].spill_slab_idx < 0 && core::add_sat_i64(sess.streams[s_idx].body.len, d_len) > 8192 {
        let c_idx, c_found = http2::find_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].recv_window = core::add_sat_i64(
                sess.conn.streams[c_idx].recv_window, H2_SLAB_WINDOW_INCREMENT as i64,
            );
        }
    }

    let flow_err = http2::on_data_frame_received(sess.conn, hdr, d_len as u32);
    if flow_err != rfc::H2_ERR_NO_ERROR {
        return handle_h2_data_flow_error(sess, pipeline, hdr, flow_err, out_wire);
    }

    let had_slab = sess.streams[s_idx].spill_slab_idx >= 0;
    if d_len > 0 {
        let data_ok, data_conn_ok = process_stream_data_ingress(
            sess, pipeline.slab_pool, s_idx, data_slice, hdr.stream_id, out_wire,
        );
        if !data_ok {
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            guard data_conn_ok else { return false; }
            replenish_conn_window_direct(sess, hdr.length, out_wire);
            return true;
        }
    }
    let promoted_now = !had_slab && sess.streams[s_idx].spill_slab_idx >= 0;
    let is_end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
    replenish_ingress_data_windows(sess, s_idx, hdr.stream_id, hdr.length, promoted_now || is_end_stream, out_wire);
    if is_end_stream {
        return finalize_h2_data_end_stream(sess, pipeline, s_idx, hdr.stream_id, out_wire);
    }
    return true;
}
