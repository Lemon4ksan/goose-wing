// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/2 Server Frame Multiplexer (RFC 9113 & RFC 7541).
// Manages server connection sessions, stream demultiplexing, HPACK decoding/encoding,
// flow control updates, anti-DoS barriers, and dispatching to the Wing Server Pipeline.
namespace internal;

import std;
import core from "..";
import .router;
import .pool;
import .pipeline;

// ---- Server Stream Descriptor --------------------------------------------

struct H2ServerStream {
    stream_id:               u32                    = 0,
    active:                  bool                   = false,
    headers_received:        bool                   = false,
    body_received:           bool                   = false,
    response_sent:           bool                   = false,
    declared_content_length: i64                    = -1,
    spill_slab_idx:          i32                    = -1,
    slab_lease_deadline_ns:  u64                    = 0,
    method:                  u8[..16]               = [],
    path:                    u8[..2048]             = [],
    scheme:                  u8[..16]               = [],
    authority:               u8[..128]              = [],
    headers:                 wing::HeaderItem[..32] = [],
    trailers:                wing::HeaderItem[..16] = [],
    body:                    u8[..8192]             = [],
}

fn reset_server_stream(st: H2ServerStream&) {
    st.stream_id = 0;
    st.active = false;
    st.headers_received = false;
    st.body_received = false;
    st.response_sent = false;
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
}

// ---- Server Connection Session -------------------------------------------

struct H2ServerSession {
    conn:                    H2Connection         = H2Connection { .. },
    hpack_enc:               DynamicTable         = DynamicTable { .. },
    streams:                 H2ServerStream[..16] = [],
    preface_handled:         bool                 = false,
    server_settings_sent:    bool                 = false,
    client_settings_acked:   bool                 = false,
    pending_settings_ack:    bool                 = false,
    server_name:             u8[..64]             = "goose-wing/1.0",
    header_accumulator:      u8[..16384]          = [],
    header_accum_stream_id:  u32                  = 0,
    header_accum_end_stream: bool                 = false,
    header_accum_is_trailer: bool                 = false,
}

fn flush_server_control_frames(sess: H2ServerSession&) {
    while sess.conn.pending_control_frames > 0 {
        ack_control_frame_flushed(sess.conn);
    }
}

fn new_h2_server_session(
    server_name_str: const u8[:] = "goose-wing/1.0",
    now_ms:          u64         = 0,
) -> H2ServerSession {
    var sess = H2ServerSession {
        conn:                  new_h2_connection(now_ms),
        hpack_enc:             new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
        preface_handled:       false,
        server_settings_sent:  false,
        client_settings_acked: false,
        pending_settings_ack:  false,
        server_name:           [],
        ..
    };
    sess.server_name.append(server_name_str);
    return sess;
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
            sess.streams[i].active = true;
            return i as i32, true;
        }
    }

    if sess.streams.len < sess.streams.cap {
        var new_st = H2ServerStream {
            stream_id: stream_id,
            active:    true,
            ..
        };
        sess.streams.push(new_st);
        return (sess.streams.len - 1) as i32, true;
    }

    return -1, false;
}

// ---- Protocol Frame Serialization Helpers --------------------------------

// Emits the server's initial SETTINGS frame (RFC 9113 Section 6.5)
fn emit_server_settings<B>(out: B&) {
    let hdr = FrameHeader {
        length:     24, // 4 settings * 6 bytes
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    encode_frame_header_to(hdr, out);

    core::append_u16_be(out, rfc::H2_SETTING_MAX_CONCURRENT_STREAMS);
    core::append_u32_be(out, 16);

    core::append_u16_be(out, rfc::H2_SETTING_INITIAL_WINDOW_SIZE);
    core::append_u32_be(out, 8192);

    core::append_u16_be(out, rfc::H2_SETTING_MAX_FRAME_SIZE);
    core::append_u32_be(out, 16384);

    core::append_u16_be(out, rfc::H2_SETTING_ENABLE_CONNECT_PROTO);
    core::append_u32_be(out, 1);
}

// Emits a SETTINGS ACK frame
fn emit_settings_ack<B>(out: B&) {
    let hdr = FrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    encode_frame_header_to(hdr, out);
}

// Emits a PING ACK frame echoing the client's 8-byte opaque payload
fn emit_ping_ack<B>(opaque: const u8[8]&, out: B&) {
    let hdr = FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    encode_frame_header_to(hdr, out);
    for b in opaque {
        out.push(b);
    }
}

// Emits a WINDOW_UPDATE frame
fn emit_window_update<B>(stream_id: u32, increment: u32, out: B&) {
    let hdr = FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
        flags:      0,
        stream_id:  stream_id,
    };
    encode_frame_header_to(hdr, out);
    core::append_u32_be(out, increment & 0x7FFFFFFF);
}

// Emits a RST_STREAM frame
fn emit_rst_stream<B>(stream_id: u32, error_code: u32, out: B&) {
    let hdr = FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_RST_STREAM,
        flags:      0,
        stream_id:  stream_id,
    };
    encode_frame_header_to(hdr, out);
    core::append_u32_be(out, error_code);
}

// Emits a GOAWAY frame
fn emit_goaway<B>(last_stream_id: u32, error_code: u32, out: B&) {
    let hdr = FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_GOAWAY,
        flags:      0,
        stream_id:  0,
    };
    encode_frame_header_to(hdr, out);
    core::append_u32_be(out, last_stream_id & 0x7FFFFFFF);
    core::append_u32_be(out, error_code);
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

    var status_buf: u8[..16] = [];
    format(status_buf, res.status_code as i64);
    encode_hpack_field(sess.hpack_enc, hpack_block, ":status", status_buf[..], HpackIndexing.Incremental, false);

    if sess.server_name.len > 0 {
        encode_hpack_field(
            sess.hpack_enc, hpack_block, "server", sess.server_name[..], HpackIndexing.Incremental, false,
        );
    }

    let is_grpc = starts_with_fold(res.header("content-type"), "application/grpc");
    let has_cl = res.header("content-length").len > 0;
    if !is_grpc && !has_cl && res.status_code != 204 && res.status_code != 304 {
        var cl_buf: u8[..32] = [];
        format(cl_buf, res.body.len);
        encode_hpack_field(sess.hpack_enc, hpack_block, "content-length", cl_buf[..], HpackIndexing.Incremental, false);
    }

    for &hdr in res.headers {
        let name_slice = hdr.name[..];
        let val_slice = hdr.value[..];
        // Skip connection hop-by-hop headers forbidden in HTTP/2 (RFC 9113 Section 8.2.2)
        if !eq_ascii_fold(name_slice, "connection") &&
           !eq_ascii_fold(name_slice, "keep-alive") &&
           !eq_ascii_fold(name_slice, "proxy-connection") &&
           !eq_ascii_fold(name_slice, "transfer-encoding") &&
           !eq_ascii_fold(name_slice, "upgrade") {
            // RFC 9113 Section 8.2.1: Field names MUST be lowercase
            var lower_name: u8[..64] = [];
            for c in name_slice {
                let lc = if c >= 'A' && c <= 'Z' { c + 32 } else { c };
                lower_name.push(lc);
            }
            encode_hpack_field(
                sess.hpack_enc, hpack_block, lower_name[..], val_slice, HpackIndexing.Incremental, false,
            );
        }
    }

    var flags: u8 = rfc::H2_FLAG_END_HEADERS;
    if end_stream {
        flags |= rfc::H2_FLAG_END_STREAM;
    }

    let frame_hdr = FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream_id,
    };
    encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

inline fn deduct_send_windows(
    conn:     H2Connection&,
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
    var sz = if rem < limit { rem } else { limit };
    if sz > quota {
        sz = quota;
    }
    return sz;
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
    let hdr = FrameHeader {
        length:     chunk_size as u32,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      flags,
        stream_id:  stream_id,
    };
    encode_frame_header_to(hdr, out);
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
) {
    guard body.len > 0 else { return; }

    var offset: i64 = 0;
    let limit = if max_frame_size >= 16384 { max_frame_size as i64 } else { 16384 };
    let c_idx, found = find_session_stream_idx(sess.conn, stream_id);

    while offset < body.len {
        let quota = compute_stream_send_quota(sess.conn, stream_id);
        if quota <= 0 {
            break;
        }

        let chunk_size = emit_one_data_frame(
            sess, stream_id, body, offset, limit, quota, c_idx, found, out, end_stream,
        );
        offset += chunk_size;
    }
}

// Encodes HTTP/2 Response Trailing HEADERS using HPACK
fn emit_response_trailers<B>(
    sess:      H2ServerSession&,
    stream_id: u32,
    trailers:  const wing::HeaderItem[..16]&,
    out:       B&,
) {
    guard trailers.len > 0 else { return; }
    var hpack_block: u8[..4096] = [];

    for &hdr in trailers {
        let name_slice = hdr.name[..];
        let val_slice = hdr.value[..];
        // RFC 9113 §8.1 / §8.2.2 & RFC 9110 §6.5.1: Trailers MUST NOT include pseudo-headers,
        // hop-by-hop connection headers, or disallowed framing/routing trailer fields.
        if name_slice.len > 0 && name_slice[0] != ':' &&
           !eq_ascii_fold(name_slice, "connection") &&
           !eq_ascii_fold(name_slice, "keep-alive") &&
           !eq_ascii_fold(name_slice, "proxy-connection") &&
           !eq_ascii_fold(name_slice, "transfer-encoding") &&
           !eq_ascii_fold(name_slice, "upgrade") &&
           !wing::is_disallowed_trailer_field(name_slice) {
            var lower_name: u8[..64] = [];
            for c in name_slice {
                let lc = if c >= 'A' && c <= 'Z' { c + 32 } else { c };
                lower_name.push(lc);
            }
            encode_hpack_field(
                sess.hpack_enc, hpack_block, lower_name[..], val_slice, HpackIndexing.Incremental, false,
            );
        }
    }

    let flags: u8 = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM;
    let frame_hdr = FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream_id,
    };
    encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

fn apply_decoded_headers_to_stream(st: H2ServerStream&, dec_list: const DecodedH2HeaderList&) -> bool {
    for &entry in dec_list.fields {
        let n = entry.name[..];
        let v = entry.value[..];
        if n == ":method" {
            st.method.clear();
            guard v.len <= st.method.cap else { return false; }
            st.method.append(v);
        } else if n == ":path" {
            st.path.clear();
            guard v.len <= st.path.cap else { return false; }
            st.path.append(v);
        } else if n == ":scheme" {
            st.scheme.clear();
            guard v.len <= st.scheme.cap else { return false; }
            st.scheme.append(v);
        } else if n == ":authority" {
            st.authority.clear();
            guard v.len <= st.authority.cap else { return false; }
            st.authority.append(v);
        } else {
            guard st.headers.len < st.headers.cap else { return false; }
            st.headers.push(wing::make_header(n, v));
        }
    }
    st.headers_received = true;
    return true;
}

fn apply_decoded_trailers_to_stream(st: H2ServerStream&, dec_list: const DecodedH2HeaderList&) -> bool {
    for &entry in dec_list.fields {
        let n = entry.name[..];
        let v = entry.value[..];
        guard st.trailers.len < st.trailers.cap else { return false; }
        st.trailers.push(wing::make_header(n, v));
    }
    st.body_received = true;
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
    reset_session_stream(sess.conn, stream_id);
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

inline fn validate_request_pseudo_headers(dec_list: const DecodedH2HeaderList&, end_stream: bool) -> bool {
    var has_method = false;
    var has_scheme = false;
    var has_path = false;
    var is_connect = false;
    for &f in dec_list.fields {
        if f.name[..] == ":method" {
            has_method = true;
            if f.value[..] == "CONNECT" { is_connect = true; }
        } else if f.name[..] == ":scheme" {
            has_scheme = true;
        } else if f.name[..] == ":path" {
            has_path = true;
        }
    }
    if !has_method || (!is_connect && (!has_scheme || !has_path)) {
        return false;
    }
    if end_stream && dec_list.has_content_length && dec_list.content_length_val != 0 {
        return false;
    }
    return true;
}

fn process_ingress_window_update<B>(
    sess:          H2ServerSession&,
    pipeline:      wing::ServerPipelineConfig&,
    hdr:           const FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    guard frame_payload.len == 4 else { return true; }
    let raw_inc = core::read_be_u32(frame_payload, 0);
    let inc = raw_inc & 0x7FFFFFFF;
    if hdr.stream_id != 0 && hdr.stream_id > sess.conn.last_peer_stream_id {
        // RFC 9113 §5.1: Frame other than HEADERS or PRIORITY on idle stream is connection error PROTOCOL_ERROR
        // RFC 9113 §6.4: RST_STREAM frames MUST NOT be sent for an idle stream
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return false;
    }
    let wu_err = apply_window_update(sess.conn, hdr.stream_id, inc);
    guard wu_err != rfc::H2_ERR_NO_ERROR else { return true; }
    if hdr.stream_id == 0 {
        emit_goaway(sess.conn.last_peer_stream_id, wu_err, out_wire);
        return false;
    }
    emit_rst_stream(hdr.stream_id, wu_err, out_wire);
    terminate_server_stream(sess, pipeline, hdr.stream_id);
    return true;
}

fn process_ingress_origin<B>(
    sess:          H2ServerSession&,
    hdr:           const FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    if hdr.stream_id != 0 {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        return false;
    }
    var origins: const u8[:][..16] = [];
    let _, p_err = parse_origin_frame(frame_payload, hdr.stream_id, origins);
    if p_err != rfc::H2_ERR_NO_ERROR {
        emit_goaway(sess.conn.last_peer_stream_id, p_err, out_wire);
        return false;
    }
    return true;
}

fn process_ingress_altsvc<B>(
    sess:          H2ServerSession&,
    hdr:           const FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    let _, p_err = parse_altsvc_frame(frame_payload, hdr.stream_id);
    if p_err != rfc::H2_ERR_NO_ERROR {
        emit_goaway(sess.conn.last_peer_stream_id, p_err, out_wire);
        return false;
    }
    return true;
}

fn process_ingress_settings<B>(
    sess:          H2ServerSession&,
    hdr:           const FrameHeader&,
    frame_payload: const u8[:],
    out_wire:      B&,
) -> bool {
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        // RFC 9113 §6.5: SETTINGS with ACK and length != 0 MUST trigger FRAME_SIZE_ERROR
        if hdr.length != 0 {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return false;
        }
        // RFC 9113 §6.5 & §10.5: Reject unexpected or duplicate SETTINGS ACK
        if !sess.pending_settings_ack {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
        sess.pending_settings_ack = false;
        sess.client_settings_acked = true;
        ack_control_frame_flushed(sess.conn);
        return true;
    }

    // Parse client settings (pairs of u16 identifier + u32 value)
    guard (frame_payload.len % 6) == 0 else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }
    var off: i64 = 0;
    while off + 6 <= frame_payload.len {
        let param_id = core::read_be_u16(frame_payload, off);
        let param_val = core::read_be_u32(frame_payload, off + 2);
        off = off + 6;

        let val_err = validate_settings_parameter(param_id, param_val, false);
        if val_err != rfc::H2_ERR_NO_ERROR {
            emit_goaway(sess.conn.last_peer_stream_id, val_err, out_wire);
            return false;
        }

        if param_id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE {
            let win_err = apply_peer_initial_window_size_delta(sess.conn, param_val);
            if win_err != rfc::H2_ERR_NO_ERROR {
                emit_goaway(sess.conn.last_peer_stream_id, win_err, out_wire);
                return false;
            }
        } else if param_id == rfc::H2_SETTING_MAX_FRAME_SIZE {
            sess.conn.peer_max_frame_size = param_val;
        } else if param_id == rfc::H2_SETTING_HEADER_TABLE_SIZE {
            let pv_u64 = param_val as u64;
            let allowed_max: u64 = if pv_u64 < HPACK_MAX_ARENA_BYTES { pv_u64 } else { HPACK_MAX_ARENA_BYTES };
            sess.hpack_enc.max_allowed_size = allowed_max;
            if sess.hpack_enc.current_max_size > allowed_max {
                sess.hpack_enc.current_max_size = allowed_max;
                evict_until(sess.hpack_enc, allowed_max);
            }
        }
    }
    // Send SETTINGS ACK back to client
    emit_settings_ack(out_wire);
    return true;
}

fn process_ingress_headers<B>(
    sess:              H2ServerSession&,
    pipeline:          wing::ServerPipelineConfig&,
    hdr:               const FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
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
        if dep_raw == hdr.stream_id {
            // RFC 9113 §5.3.1: Stream cannot depend on itself
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            return true;
        }
        block_start += 5;
    }

    let s_exist_idx, s_exists = find_server_stream_idx(sess, hdr.stream_id);
    let is_trailer = s_exists && sess.streams[s_exist_idx].headers_received;

    if is_trailer {
        // If stream already completed receiving body/trailers, extra HEADERS is invalid
        if sess.streams[s_exist_idx].body_received {
            // RFC 9113 §5.1: Frame on half-closed (remote) stream
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
            return true;
        }
        // RFC 9113 §8.1.2: A HEADERS frame containing a trailer section MUST have END_STREAM set
        if (hdr.flags & rfc::H2_FLAG_END_STREAM) == 0 {
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            return true;
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
        if fragment.len <= sess.header_accumulator.cap {
            sess.header_accumulator.append(fragment);
            return true;
        }
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }

    var dec_list = DecodedH2HeaderList { .. };
    dec_list.is_trailer = is_trailer;
    let dec_err = decode_hpack_header_block(sess.conn.hpack_dec, fragment, dec_list);
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
            guard apply_decoded_trailers_to_stream(sess.streams[s_exist_idx], dec_list) else {
                emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
                terminate_server_stream(sess, pipeline, hdr.stream_id);
                return true;
            }
            let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
            if c_found {
                sess.conn.streams[c_idx].trailers_received = true;
                sess.conn.streams[c_idx].state = H2StreamState.HalfClosedRemote;
            }
        }
        return true;
    }

    guard validate_request_pseudo_headers(dec_list, (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0) else {
        // RFC 9113 §8.1.1: Malformed requests MUST be treated as a stream error of type PROTOCOL_ERROR
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }

    guard !is_cancelled else { return true; }
    let s_idx, found = find_or_alloc_stream(sess, hdr.stream_id);
    guard found else { return true; }
    guard apply_decoded_headers_to_stream(sess.streams[s_idx], dec_list) else {
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    if dec_list.has_content_length {
        sess.streams[s_idx].declared_content_length = dec_list.content_length_val;
        let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].declared_content_length = dec_list.content_length_val;
        }
    }
    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        sess.streams[s_idx].body_received = true;
    }
    return true;
}

fn process_ingress_continuation<B>(
    sess:              H2ServerSession&,
    pipeline:          wing::ServerPipelineConfig&,
    hdr:               const FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    guard hdr.stream_id == sess.header_accum_stream_id else { return true; }
    let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
    if sess.header_accumulator.len + frame_payload.len <= sess.header_accumulator.cap {
        sess.header_accumulator.append(frame_payload);
    } else {
        emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
        return false;
    }
    guard (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 else { return true; }

    var dec_list = DecodedH2HeaderList { .. };
    dec_list.is_trailer = sess.header_accum_is_trailer;
    let dec_err = decode_hpack_header_block(sess.conn.hpack_dec, sess.header_accumulator[..], dec_list);
    if dec_err != rfc::H2_ERR_NO_ERROR {
        if dec_err == rfc::H2_ERR_COMPRESSION_ERROR {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_COMPRESSION_ERROR, out_wire);
            return false;
        }
        emit_rst_stream(hdr.stream_id, dec_err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        sess.header_accum_stream_id = 0;
        sess.header_accumulator.clear();
        return true;
    }

    if sess.header_accum_is_trailer {
        sess.header_accum_stream_id = 0;
        sess.header_accumulator.clear();
        guard !is_cancelled else { return true; }
        let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
        guard found else { return true; }
        guard apply_decoded_trailers_to_stream(sess.streams[s_idx], dec_list) else {
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            return true;
        }
        let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].trailers_received = true;
            sess.conn.streams[c_idx].state = H2StreamState.HalfClosedRemote;
        }
        return true;
    }

    guard validate_request_pseudo_headers(dec_list, sess.header_accum_end_stream) else {
        // RFC 9113 §8.1.1: Malformed requests MUST be treated as a stream error of type PROTOCOL_ERROR
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        sess.header_accum_stream_id = 0;
        sess.header_accumulator.clear();
        return true;
    }

    sess.header_accum_stream_id = 0;
    sess.header_accumulator.clear();
    guard !is_cancelled else { return true; }
    let s_idx, found = find_or_alloc_stream(sess, hdr.stream_id);
    guard found else { return true; }
    guard apply_decoded_headers_to_stream(sess.streams[s_idx], dec_list) else {
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_INTERNAL_ERROR, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        return true;
    }
    if dec_list.has_content_length {
        sess.streams[s_idx].declared_content_length = dec_list.content_length_val;
        let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].declared_content_length = dec_list.content_length_val;
        }
    }
    if sess.header_accum_end_stream {
        sess.streams[s_idx].body_received = true;
    }
    return true;
}

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
        let slab_idx = acquire_spill_slab(pool);
        guard slab_idx >= 0 else {
            // RFC 9113 Section 8.1: HTTP Message Framing - Stream rejected due to pool saturation
            emit_rst_stream(stream_id, rfc::H2_ERR_REFUSED_STREAM, out_wire);
            return false;
        }
        sess.streams[st_idx].spill_slab_idx = slab_idx;
        sess.streams[st_idx].slab_lease_deadline_ns = core::as_nanos(core::monotonic_now()) + 3000000000;
        let slab_slot = slab_idx as i64;
        guard slab_slot >= 0 && slab_slot < pool.slabs.len else { return false; }
        pool.slabs[slab_slot].data.append(sess.streams[st_idx].body[..]);
        sess.streams[st_idx].body.clear();
        // RFC 9113 Section 6.9: WINDOW_UPDATE - Grant remaining credit up to 64 KiB
        emit_window_update(stream_id, 57344, out_wire);
        let c_idx, c_found = find_session_stream_idx(sess.conn, stream_id);
        if c_found {
            sess.conn.streams[c_idx].recv_window += 57344;
        }
    }

    // 3. Bounds Check Elimination (BCE) guarded append with lease deadline check
    let now_ns = core::as_nanos(core::monotonic_now());
    if now_ns > sess.streams[st_idx].slab_lease_deadline_ns {
        emit_rst_stream(stream_id, rfc::H2_ERR_CANCEL, out_wire);
        return false;
    }

    let slab_slot = sess.streams[st_idx].spill_slab_idx as i64;
    guard slab_slot >= 0 && slab_slot < pool.slabs.len else { return false; }
    guard pool.slabs[slab_slot].data.len + payload.len <= pool.slabs[slab_slot].data.cap else {
        // Exceeds 64 KiB maximum slab capacity: emit CANCEL
        emit_rst_stream(stream_id, rfc::H2_ERR_CANCEL, out_wire);
        return false;
    }
    pool.slabs[slab_slot].data.append(payload);
    return true;
}

fn process_ingress_data<B>(
    sess:          H2ServerSession&,
    pipeline:      wing::ServerPipelineConfig&,
    hdr:           const FrameHeader&,
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
        if hdr.stream_id <= sess.conn.last_peer_stream_id {
            // RFC 9113 §5.1: Closed stream receives DATA -> stream error STREAM_CLOSED
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
            // Account for flow control connection-wide per RFC 9113 §6.9
            sess.conn.conn_recv_window -= hdr.length as i64;
            if sess.conn.conn_recv_window < 0 {
                emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FLOW_CONTROL_ERROR, out_wire);
                return false;
            }
            emit_window_update(0, hdr.length, out_wire);
            sess.conn.conn_recv_window += hdr.length as i64;
            return true;
        } else {
            // Idle stream receives DATA -> connection error PROTOCOL_ERROR (RFC 9113 §5.1)
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return false;
        }
    }

    // Stream is found; check if stream is already half-closed (remote)
    if sess.streams[s_idx].body_received {
        // RFC 9113 §5.1: Receiving DATA after END_STREAM is a stream error STREAM_CLOSED
        emit_rst_stream(hdr.stream_id, rfc::H2_ERR_STREAM_CLOSED, out_wire);
        sess.conn.conn_recv_window -= hdr.length as i64;
        if sess.conn.conn_recv_window < 0 {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_FLOW_CONTROL_ERROR, out_wire);
            return false;
        }
        emit_window_update(0, hdr.length, out_wire);
        sess.conn.conn_recv_window += hdr.length as i64;
        return true;
    }

    var d_start: i64 = 0;
    var d_end:   i64 = frame_payload.len;

    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 && frame_payload.len >= 1 {
        let pad_len = frame_payload[0] as i64;
        d_start += 1;
        d_end -= pad_len;
    }

    var d_len: i64 = 0;
    if d_start <= d_end && d_end <= frame_payload.len {
        d_len = d_end - d_start;
        if d_len > 0 {
            let app_ok = process_stream_data_ingress(
                sess, pipeline.slab_pool, s_idx, frame_payload[d_start..d_end], hdr.stream_id, out_wire,
            );
            guard app_ok else {
                terminate_server_stream(sess, pipeline, hdr.stream_id);
                return true;
            }
        }
    }

    // RFC 9113 §8.1.1 & §8.1.2: Pass application data length (d_len) for Content-Length validation,
    // while connection and stream flow-control windows account for the full frame payload (hdr.length).
    let flow_err = on_data_frame_received(sess.conn, hdr, d_len as u32);
    if flow_err != rfc::H2_ERR_NO_ERROR {
        if flow_err == rfc::H2_ERR_STREAM_CLOSED || flow_err == rfc::H2_ERR_PROTOCOL_ERROR {
            // RFC 9113 §8.1.2: Content-Length mismatch is a stream error of type PROTOCOL_ERROR
            emit_rst_stream(hdr.stream_id, flow_err, out_wire);
            terminate_server_stream(sess, pipeline, hdr.stream_id);
            return true;
        }
        emit_goaway(sess.conn.last_peer_stream_id, flow_err, out_wire);
        return false;
    }

    // Replenish receive windows if consumed and non-zero
    if frame_payload.len > 0 {
        emit_window_update(0, frame_payload.len as u32, out_wire);
        emit_window_update(hdr.stream_id, frame_payload.len as u32, out_wire);
        // Replenish session tracking windows
        sess.conn.conn_recv_window += hdr.length as i64;
        let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
        if c_found {
            sess.conn.streams[c_idx].recv_window += hdr.length as i64;
        }
    }

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
        let sc_hdr, sc_err = parse_frame_header(wire[p_scan..p_scan + 9], sess.conn.local_max_frame_size);
        if sc_err != rfc::H2_ERR_NO_ERROR {
            break;
        }
        let sc_tot = 9 + (sc_hdr.length as i64);
        if sc_hdr.frame_type == rfc::H2_FRAME_RST_STREAM && sc_hdr.stream_id != 0 {
            guard cancelled_streams.len < cancelled_streams.cap else { break; }
            cancelled_streams.push(sc_hdr.stream_id);
        }
        p_scan += sc_tot;
    }
}

fn dispatch_ingress_frame<B>(
    sess:              H2ServerSession&,
    pipeline:          wing::ServerPipelineConfig&,
    hdr:               const FrameHeader&,
    frame_payload:     const u8[:],
    cancelled_streams: const u32[:],
    out_wire:          B&,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS {
        return process_ingress_settings(sess, hdr, frame_payload, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_PING {
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 && frame_payload.len == 8 {
            var opaque: u8[8] = [0; 8];
            for i in 8 { opaque[i] = frame_payload[i]; }
            emit_ping_ack(opaque, out_wire);
        }
    } else if hdr.frame_type == rfc::H2_FRAME_PRIORITY {
        if frame_payload.len != 5 {
            // RFC 9113 §6.3: PRIORITY with length other than 5 is stream error FRAME_SIZE_ERROR
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR, out_wire);
            return true;
        }
        let b0 = frame_payload[0] as u32;
        let b1 = frame_payload[1] as u32;
        let b2 = frame_payload[2] as u32;
        let b3 = frame_payload[3] as u32;
        let dep_raw = ((b0 & 0x7F) << 24) | (b1 << 16) | (b2 << 8) | b3;
        if dep_raw == hdr.stream_id {
            // RFC 9113 §5.3.1: Stream cannot depend on itself -> stream error PROTOCOL_ERROR
            emit_rst_stream(hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
        }
    } else if hdr.frame_type == rfc::H2_FRAME_PRIORITY_UPDATE {
        let prio_stream_id, prio_param, prio_err = parse_priority_update_payload(frame_payload, false);
        if prio_err != rfc::H2_ERR_NO_ERROR || (prio_stream_id % 2) == 0 {
            let final_err = if prio_err != rfc::H2_ERR_NO_ERROR { prio_err } else { rfc::H2_ERR_PROTOCOL_ERROR };
            emit_goaway(sess.conn.last_peer_stream_id, final_err, out_wire);
            return false;
        }
        apply_priority_update(sess.conn, prio_stream_id, prio_param);
    } else if hdr.frame_type == rfc::H2_FRAME_ORIGIN {
        return process_ingress_origin(sess, hdr, frame_payload, out_wire);
    } else if hdr.frame_type == rfc::H2_FRAME_ALTSVC {
        return process_ingress_altsvc(sess, hdr, frame_payload, out_wire);
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
    for &hdr_item in st.headers {
        guard req.headers.len < 32 else { break; }
        req.headers.push(hdr_item);
        wing::add_header(req.bloom_filter, hdr_item.name[..]);
    }
    for &tr_item in st.trailers {
        guard req.trailers.len < 16 else { break; }
        req.trailers.push(tr_item);
    }
}

fn execute_ready_server_stream<B>(
    sess:       H2ServerSession&,
    stream_idx: i64,
    pipeline:   wing::ServerPipelineConfig&,
    timer:      internal::ConnectionTimer&,
    client_ip:  const u8[:],
    now_ms:     u64,
    out_wire:   B&,
) {
    let target_stream_id = sess.streams[stream_idx].stream_id;

    // Construct Request
    var req = wing::new_request(sess.streams[stream_idx].method[..], sess.streams[stream_idx].path[..]);
    copy_stream_headers_and_trailers(sess.streams[stream_idx], req);
    if sess.streams[stream_idx].spill_slab_idx >= 0 {
        let s_slot = sess.streams[stream_idx].spill_slab_idx as i64;
        guard s_slot >= 0 && s_slot < pipeline.slab_pool.slabs.len else { return; }
        req.body.append(pipeline.slab_pool.slabs[s_slot].data[..]);
        release_spill_slab(pipeline.slab_pool, sess.streams[stream_idx].spill_slab_idx);
        sess.streams[stream_idx].spill_slab_idx = -1;
    } else {
        req.body.append(sess.streams[stream_idx].body[..]);
    }

    // Execute pipeline
    var res = wing::Response { .. };
    var future = internal::new_inline_handler_future(0);
    let now_ns = (now_ms as u64) * 1000000;
    wing::execute_pipeline(pipeline, timer, client_ip, req, now_ns, res, future);

    // Emit Response
    let has_body = res.body.len > 0;
    let has_trailers = res.trailers.len > 0;
    let end_headers = !has_body && !has_trailers;
    emit_response_headers(sess, target_stream_id, res, end_headers, out_wire);
    if has_body {
        let end_data = !has_trailers;
        emit_response_data(sess, target_stream_id, res.body[..], sess.conn.peer_max_frame_size, out_wire, end_data);
    }
    if has_trailers {
        emit_response_trailers(sess, target_stream_id, res.trailers, out_wire);
    }

    sess.streams[stream_idx].response_sent = true;
    sess.streams[stream_idx].active = false;

    // RFC 9113 §5.1: Response sent with END_STREAM -> stream transitions to Closed
    let c_idx, c_found = find_session_stream_idx(sess.conn, target_stream_id);
    if c_found {
        sess.conn.streams[c_idx].state = H2StreamState.Closed;
        sess.conn.streams[c_idx].active = false;
        if sess.conn.active_stream_count > 0 {
            sess.conn.active_stream_count--;
        }
    }
}

fn dispatch_ready_server_streams<B>(
    sess:      H2ServerSession&,
    pipeline:  wing::ServerPipelineConfig&,
    timer:     internal::ConnectionTimer&,
    client_ip: const u8[:],
    now_ms:    u64,
    out_wire:  B&,
) {
    for i in sess.streams.len {
        let is_ready = sess.streams[i].active &&
            sess.streams[i].headers_received &&
            sess.streams[i].body_received &&
            !sess.streams[i].response_sent;
        guard is_ready else { continue; }
        execute_ready_server_stream(sess, i, pipeline, timer, client_ip, now_ms, out_wire);
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

inline fn validate_continuation_boundary(sess: const H2ServerSession&, hdr: const FrameHeader&) -> bool {
    if sess.header_accum_stream_id != 0 {
        return hdr.frame_type == rfc::H2_FRAME_CONTINUATION && hdr.stream_id == sess.header_accum_stream_id;
    }
    return hdr.frame_type != rfc::H2_FRAME_CONTINUATION;
}

// Handles frame header ingress errors, emitting stream resets and advancing offset.
fn handle_ingress_header_error<B>(
    sess:            H2ServerSession&,
    pipeline:        wing::ServerPipelineConfig&,
    hdr:             const FrameHeader&,
    err:             u32,
    total_frame_len: i64,
    offset:          i64&,
    out_wire:        B&,
) -> bool {
    let is_prio_size_err = (hdr.frame_type == rfc::H2_FRAME_PRIORITY && err == rfc::H2_ERR_FRAME_SIZE_ERROR);
    if err == rfc::H2_ERR_STREAM_CLOSED || err == rfc::H2_ERR_REFUSED_STREAM || is_prio_size_err {
        emit_rst_stream(hdr.stream_id, err, out_wire);
        terminate_server_stream(sess, pipeline, hdr.stream_id);
        offset += total_frame_len;
        return true;
    }
    emit_goaway(sess.conn.last_peer_stream_id, err, out_wire);
    return false;
}

// Processes incoming HTTP/2 wire data, executing complete streams through the server pipeline.
// Returns (total_bytes_consumed, success)
fn handle_h2_server_ingress<B>(
    sess:      H2ServerSession&,
    pipeline:  wing::ServerPipelineConfig&,
    timer:     internal::ConnectionTimer&,
    client_ip: const u8[:],
    wire:      const u8[:],
    now_ms:    u64,
    out_wire:  B&,
) -> i64, bool {
    var offset: i64 = 0;
    guard check_ingress_preface(sess, wire, offset, out_wire) else {
        return 0, false;
    }

    var cancelled_streams: u32[..128] = [];
    collect_cancelled_streams(sess, wire, offset, cancelled_streams);

    while offset + 9 <= wire.len {
        let hdr, err_hdr = parse_frame_header(wire[offset..offset + 9], sess.conn.local_max_frame_size);
        guard err_hdr == rfc::H2_ERR_NO_ERROR else {
            emit_goaway(sess.conn.last_peer_stream_id, err_hdr, out_wire);
            return offset, false;
        }

        let total_frame_len = 9 + (hdr.length as i64);
        guard offset + total_frame_len <= wire.len else {
            break;
        }

        let frame_payload = wire[offset + 9..offset + total_frame_len];

        // RFC 9113 §6.10: Continuous header block boundaries
        guard validate_continuation_boundary(sess, hdr) else {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return offset + total_frame_len, false;
        }

        // Validate Anti-DoS barriers and protocol invariants
        let err = on_ingress_frame_header(sess.conn, hdr, now_ms);
        if err != rfc::H2_ERR_NO_ERROR {
            guard handle_ingress_header_error(sess, pipeline, hdr, err, total_frame_len, offset, out_wire) else {
                return offset + total_frame_len, false;
            }
            continue;
        }

        // RFC 9113 §6.6: Servers MUST NOT receive PUSH_PROMISE frames
        if hdr.frame_type == rfc::H2_FRAME_PUSH_PROMISE {
            emit_goaway(sess.conn.last_peer_stream_id, rfc::H2_ERR_PROTOCOL_ERROR, out_wire);
            return offset + total_frame_len, false;
        }

        guard dispatch_ingress_frame(sess, pipeline, hdr, frame_payload, cancelled_streams[..], out_wire) else {
            return offset + total_frame_len, false;
        }

        offset += total_frame_len;
    }

    dispatch_ready_server_streams(sess, pipeline, timer, client_ip, now_ms, out_wire);
    flush_server_control_frames(sess);
    return offset, true;
}
