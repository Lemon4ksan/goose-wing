// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/2 stream dispatch, async pipeline integration, response flushing, and ingress loop.
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
import .h2_mux_frames_internal;

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
    guard offset >= 0 && offset <= wire.len else { return; }
    var rem = wire[offset..];
    while rem.len >= 9 {
        let sc_hdr, sc_err = http2::parse_frame_header(rem[..9], sess.conn.local_max_frame_size);
        guard sc_err == rfc::H2_ERR_NO_ERROR else { break; }
        let sc_tot = core::add_sat_i64(9, sc_hdr.length);
        guard sc_tot <= rem.len else { break; }
        if sc_hdr.frame_type == rfc::H2_FRAME_RST_STREAM && sc_hdr.stream_id != 0 && sc_hdr.length == 4 {
            guard cancelled_streams.try_push(sc_hdr.stream_id) else { break; }
        }
        rem = rem[sc_tot..];
    }
}

fn process_ingress_goaway<B>(
    sess:          H2ServerSession&,
    hdr:           const http2::FrameHeader&,
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
    let ga_err = http2::apply_goaway(sess.conn, last_stream_id, err_code);
    guard ga_err == rfc::H2_ERR_NO_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, ga_err, out_wire);
        return false;
    }
    return true;
}

inline fn process_ingress_priority<B>(
    sess:          H2ServerSession&,
    pipeline:      server::ServerPipelineConfig&,
    hdr:           const http2::FrameHeader&,
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
    hdr:           const http2::FrameHeader&,
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

inline fn process_ingress_priority_update<B>(
    sess:          H2ServerSession&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    let prio_stream_id, prio_param, prio_err = http2::parse_priority_update_payload(frame_payload, false);
    if prio_err != rfc::H2_ERR_NO_ERROR || (prio_stream_id & 1) == 0 {
        let final_err = if prio_err != rfc::H2_ERR_NO_ERROR { prio_err } else { rfc::H2_ERR_PROTOCOL_ERROR };
        emit_goaway(sess.conn.last_peer_stream_id, final_err, out_wire);
        return false;
    }
    http2::apply_priority_update(sess.conn, prio_stream_id, prio_param);
    return true;
}

inline fn process_ingress_rst_stream(
    sess:      H2ServerSession&,
    pipeline:  server::ServerPipelineConfig&,
    stream_id: u32,
) {
    for i in sess.streams.len {
        guard sess.streams[i].active && sess.streams[i].stream_id == stream_id else { continue; }
        sess.streams[i].active = false;
        if sess.streams[i].spill_slab_idx >= 0 {
            release_spill_slab(pipeline.slab_pool, sess.streams[i].spill_slab_idx);
        }
        reset_server_stream(sess.streams[i]);
    }
}

fn dispatch_ingress_frame<B>(
    sess:              H2ServerSession&,
    pipeline:          server::ServerPipelineConfig&,
    hdr:               const http2::FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS { return process_ingress_settings(sess, hdr, frame_payload, out_wire); }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY { return process_ingress_goaway(sess, hdr, frame_payload, out_wire); }
    if hdr.frame_type == rfc::H2_FRAME_PING { process_ingress_ping(sess, hdr, frame_payload, out_wire); return true; }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY {
        return process_ingress_priority(sess, pipeline, hdr, frame_payload, out_wire);
    }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY_UPDATE {
        return process_ingress_priority_update(sess, frame_payload, out_wire);
    }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE {
        return process_ingress_window_update(sess, pipeline, hdr, frame_payload, out_wire);
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM {
        process_ingress_rst_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        return process_ingress_headers(sess, pipeline, hdr, frame_payload, cancelled_streams, out_wire);
    }
    if hdr.frame_type == rfc::H2_FRAME_CONTINUATION {
        return process_ingress_continuation(sess, pipeline, hdr, frame_payload, cancelled_streams, out_wire);
    }
    if hdr.frame_type == rfc::H2_FRAME_DATA {
        return process_ingress_data(sess, pipeline, hdr, frame_payload, out_wire);
    }
    return true;
}

inline fn copy_stream_headers_and_trailers(st: const H2ServerStream&, req: http::Request&) {
    if st.authority.len > 0 && !http::has_header(st.headers, "host") {
        let _ = http::append_header(req.headers, "host", st.authority[..]);
        req.presence_mask |= http::HDR_PRESENCE_HOST;
    }
    for &e in st.headers.entries {
        let name = http::entry_name(st.headers, e);
        let val = http::entry_value(st.headers, e);
        guard http::append_header(req.headers, name, val) else { break; }
        let known_id = http::identify_known_header(name);
        req.presence_mask |= http::header_id_to_bit(known_id);
    }
    http::append_all_headers(st.trailers, req.trailers);
}

inline fn complete_server_stream_response(
    sess:             H2ServerSession&,
    stream_idx:       i64,
    target_stream_id: u32,
) {
    sess.streams[stream_idx].response_sent = true;
    sess.streams[stream_idx].phase = H2StreamPhase.Closed;
    sess.streams[stream_idx].active = false;

    let c_idx, c_found = http2::find_stream_idx(sess.conn, target_stream_id);
    if c_found {
        sess.conn.streams[c_idx].state = http2::StreamState.Closed;
        sess.conn.streams[c_idx].active = false;
        let _ = core::flat_index_remove(sess.conn.stream_index[..], target_stream_id);
        sess.conn.active_stream_count = core::sub_sat_u32(sess.conn.active_stream_count, 1);
        http2::sync_stream_urgency_node(sess.conn, c_idx);
    }
}

fn flush_pending_server_stream<B>(
    sess:       H2ServerSession&,
    pipeline:   server::ServerPipelineConfig&,
    stream_idx: i64,
    out_wire:   B&,
) {
    let target_stream_id = sess.streams[stream_idx].stream_id;
    let quota = http2::compute_stream_send_quota(sess.conn, target_stream_id);
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
    pipeline:   server::ServerPipelineConfig&,
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
    pipeline:         server::ServerPipelineConfig&,
    stream_idx:       i64,
    target_stream_id: u32,
    rem_slice:        const u8[:],
    res:              const http::Response&,
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
        http::append_all_headers(res.trailers, sess.streams[stream_idx].trailers);
    }
    sess.streams[stream_idx].pending_has_trailers = has_trailers;
}

fn emit_h2_stream_response<B>(
    sess:             H2ServerSession&,
    pipeline:         server::ServerPipelineConfig&,
    stream_idx:       i64,
    target_stream_id: u32,
    res:              const http::Response&,
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
    pipeline: server::ServerPipelineConfig&,
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
    pipeline:   server::ServerPipelineConfig&,
    timer:      server_internal::ConnectionTimer&,
    client_ip:  const u8[:],
    now_ms:     u64,
    wake_token: core::WakeToken,
    out_req:    http::Request&,
    out_sctx:   server::ServerStageCtx&,
    out_wire:   B&,
    stage:      Stage&,
) -> server::PipelineOutcome {
    let target_stream_id = sess.streams[stream_idx].stream_id;
    out_req = http::new_request(sess.streams[stream_idx].method[..], sess.streams[stream_idx].path[..]);
    copy_stream_headers_and_trailers(sess.streams[stream_idx], out_req);
    if sess.streams[stream_idx].spill_slab_idx >= 0 {
        let s_slot = sess.streams[stream_idx].spill_slab_idx as i64;
        guard s_slot >= 0 && s_slot < pipeline.slab_pool.slabs.len else {
            return server::PipelineOutcome.RateLimited;
        }
        out_req.body.append(pipeline.slab_pool.slabs[s_slot].data[..]);
        release_spill_slab(pipeline.slab_pool, sess.streams[stream_idx].spill_slab_idx);
        sess.streams[stream_idx].spill_slab_idx = -1;
    } else {
        out_req.body.append(sess.streams[stream_idx].body[..]);
        sess.streams[stream_idx].body.clear();
    }

    var res = http::Response { .. };
    var future = server_internal::new_inline_handler_future(0);
    let now_ns = core::mul_sat_u64(now_ms, 1000000);
    out_sctx = server::ServerStageCtx { wake_token: wake_token, now_ns: now_ns, .. };
    let outcome = server::execute_server_pipeline_async(
        pipeline, timer, client_ip, out_req, now_ns, res, future, out_sctx, stage,
    );
    if outcome == server::PipelineOutcome.Pending {
        sess.streams[stream_idx].pending_async = true;
        return server::PipelineOutcome.Pending;
    }
    if res.status_code <= 0 {
        res.status_code = rfc::STATUS_INTERNAL_SERVER_ERROR;
    }
    emit_h2_stream_response(sess, pipeline, stream_idx, target_stream_id, res, out_wire);
    return outcome;
}

fn complete_pending_h2_stream_response<Stage, B>(
    sess:             H2ServerSession&,
    target_stream_id: u32,
    pipeline:         server::ServerPipelineConfig&,
    now_ms:           u64,
    req:              const http::Request&,
    sctx:             server::ServerStageCtx&,
    out_wire:         B&,
    stage:            Stage&,
) -> bool {
    let stream_idx = find_active_h2_stream_by_id(sess, target_stream_id);
    guard stream_idx >= 0 && sess.streams[stream_idx].pending_async else { return false; }
    sess.streams[stream_idx].pending_async = false;

    var res = http::Response { .. };
    let now_ns = core::mul_sat_u64(now_ms, 1000000);
    let _ = server::resume_server_pipeline_egress(pipeline, req, now_ns, sctx, res, stage);
    if res.status_code <= 0 {
        res.status_code = rfc::STATUS_INTERNAL_SERVER_ERROR;
    }
    emit_h2_stream_response(sess, pipeline, stream_idx, target_stream_id, res, out_wire);
    return true;
}

fn execute_ready_server_stream<Stage, B>(
    sess:       H2ServerSession&,
    stream_idx: i64,
    pipeline:   server::ServerPipelineConfig&,
    timer:      server_internal::ConnectionTimer&,
    client_ip:  const u8[:],
    now_ms:     u64,
    out_wire:   B&,
    stage:      Stage&,
) {
    var req = http::Request { .. };
    var sctx = server::ServerStageCtx { .. };
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
    pipeline:  server::ServerPipelineConfig&,
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
    offset = core::add_sat_i64(offset, 24);

    emit_server_settings(out_wire);
    sess.server_settings_sent = true;
    sess.pending_settings_ack = true;
    return true;
}

inline fn validate_continuation_boundary(sess: const H2ServerSession&, hdr: const http2::FrameHeader&) -> bool {
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
    hdr:             const http2::FrameHeader&,
    frame_payload:   const u8[:],
    err:             u32,
    total_frame_len: i64,
    now_ms:          u64,
    offset:          i64&,
    out_wire:        B&,
) -> bool {
    let frag, f_err = http2::extract_headers_frame_payload(hdr, frame_payload, true);
    guard f_err == rfc::H2_ERR_NO_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, f_err, out_wire);
        return false;
    }
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
    offset = core::add_sat_i64(offset, total_frame_len);
    return true;
}

inline fn decompress_rejected_headers_frame<B>(
    sess:          H2ServerSession&,
    hdr:           const http2::FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    let frag, f_err = http2::extract_headers_frame_payload(hdr, frame_payload, true);
    guard f_err == rfc::H2_ERR_NO_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, f_err, out_wire);
        return false;
    }
    var dummy_pseudo = http2::PseudoHeaders { .. };
    var dummy_headers = http::HeaderMap { .. };
    let dec_err = http2::decode_hpack_to_map(
        sess.conn.hpack_dec, frag, dummy_pseudo, dummy_headers, sess.conn.max_header_list_size, false,
    );
    guard dec_err != rfc::H2_ERR_COMPRESSION_ERROR else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_COMPRESSION_ERROR, out_wire);
        return false;
    }
    return true;
}

inline fn is_h2_stream_level_header_error(
    sess: const H2ServerSession&,
    hdr:  const http2::FrameHeader&,
    err:  u32,
) -> bool {
    if err == rfc::H2_ERR_STREAM_CLOSED || err == rfc::H2_ERR_REFUSED_STREAM { return true; }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY && err == rfc::H2_ERR_FRAME_SIZE_ERROR { return true; }
    guard hdr.frame_type == rfc::H2_FRAME_HEADERS && err == rfc::H2_ERR_PROTOCOL_ERROR else { return false; }
    let _, has_open_st = find_server_stream_idx(sess, hdr.stream_id);
    return has_open_st && !(hdr.length == 0 && (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0);
}

// Handles frame header ingress errors, emitting stream resets and advancing offset.
fn handle_ingress_header_error<B>(
    sess:            H2ServerSession&,
    pipeline:        server::ServerPipelineConfig&,
    hdr:             const http2::FrameHeader&,
    frame_payload:   const u8[:],
    err:             u32,
    total_frame_len: i64,
    now_ms:          u64,
    offset:          i64&,
    out_wire:        B&,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_HEADERS && err == rfc::H2_ERR_STREAM_CLOSED {
        let c_idx, c_closed = http2::find_closed_stream_idx(sess.conn, hdr.stream_id);
        if c_closed && !sess.conn.streams[c_idx].closed_by_rst {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
            return false;
        }
    }
    guard is_h2_stream_level_header_error(sess, hdr, err) else {
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
    offset = core::add_sat_i64(offset, total_frame_len);
    return true;
}

// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame - server MUST ignore client ALTSVC frames
// RFC 8336 Section 2.2: Processing ORIGIN Frames - server ignores client ORIGIN frames
inline fn skip_server_ignored_extension_frame<B>(
    sess:     H2ServerSession&,
    hdr:      const http2::FrameHeader&,
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
        if sess.conn.empty_frame_streak > http2::MAX_EMPTY_FRAME_STREAK {
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
    pipeline:          server::ServerPipelineConfig&,
    hdr:               const http2::FrameHeader&,
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

    let err = http2::on_ingress_frame_header(sess.conn, hdr, now_ms);
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
    pipeline: server::ServerPipelineConfig&,
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
        let hdr, err_hdr = http2::parse_frame_header(wire[offset..hdr_end], sess.conn.local_max_frame_size);
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
    pipeline:  server::ServerPipelineConfig&,
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
    pipeline:  server::ServerPipelineConfig&,
    timer:     server_internal::ConnectionTimer&,
    client_ip: const u8[:],
    wire:      const u8[:],
    now_ms:    u64,
    out_wire:  B&,
) -> i64, bool {
    var noop = wire::NoOpStage {};
    return handle_h2_server_ingress(sess, pipeline, timer, client_ip, wire, now_ms, out_wire, noop);
}
