// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

namespace http3;

import core.bytes;
import core.math;
import core.ufcs;
import fingerprint.types;
import http.headers;
import http.headers.lexical;
import http3.connection_internal;
import http3.framing;
import http3.internal;
import http3.qpack;
import http3.qpack_codec;
import http3.stream_internal;
import http3.types;
import quic.packet;
import rfc.h3_quic;

const H3_EDGE_DATA_CHUNK_CAP:            u64 = 16384;
const H3_EDGE_HDR_SECTION_CAP:           u64 = 65536;
const H3_EDGE_CTRL_BUF_CAP:              u64 = 1024;
const H3_EDGE_QENC_BUF_CAP:              u64 = 4096;
const H3_EDGE_QDEC_BUF_CAP:              u64 = 1024;
const H3_EDGE_COOKIE_BUF_CAP:            u64 = 8192;
const H3_EDGE_MAX_RETAINED_STREAMS:      i64 = 128;
const H3_EDGE_MAX_UNI_PENDING:           i64 = 16;
const H3_EDGE_MAX_IGNORED_UNI:           i64 = 1024;
const H3_EDGE_QPACK_DEFAULT_CAP:         u64 = 4096;
const H3_EDGE_QPACK_DEFAULT_BLOCKED:     u32 = 16;
const H3_EDGE_FIELD_OVERHEAD:            u64 = 32;
const H3_EDGE_STATUS_FIELD_OVERHEAD:     u64 = 39;
const H3_EDGE_STATUS_MIN:                i32 = 100;
const H3_EDGE_STATUS_SWITCHING_PROTOCOL: i32 = 101;
const H3_EDGE_STATUS_MAX:                i32 = 599;
const QUIC_STREAM_TYPE_MASK:             u64 = 0x03;
const QUIC_CLIENT_BIDI_TYPE:             u64 = 0x00;
const QUIC_CLIENT_UNI_TYPE:              u64 = 0x02;
const H3_EDGE_VARINT_MAX_HEADER_BYTES:   i64 = 16;

enum H3EdgeEventKind {
    None,
    RequestHead,
    RequestData,
    RequestEnd,
    StreamReset,
    GoAway,
    ProtocolError,
}

struct H3EdgeEvent {
    kind:       H3EdgeEventKind = H3EdgeEventKind.None,
    stream_id:  u64             = 0,
    headers:    http::HeaderMap = http::HeaderMap { .. },
    data:       const u8[:]     = "",
    end_stream: bool            = false,
    error_code: u64             = 0,
}

struct H3EdgeSession {
    slot_idx:   i64 = -1,
    generation: u64 = 0,
}

enum H3EdgeBidiStage {
    ReadHeader,
    ReadHeadersPayload,
    ReadDataPayload,
    SkipUnknownPayload,
}

enum H3EdgeCtrlStage {
    ReadHeader,
    ReadPayload,
    SkipUnknownPayload,
}

enum H3EdgeMsgPhase {
    ExpectHeaders,
    ReadingBody,
    ExpectEofAfterTrailers,
}

enum H3EdgeSectionRole {
    Request,
    Trailers,
}

enum H3EdgeEndFlag {
    Open,
    Fin,
}

enum H3HdrReadState {
    Ready,
    NeedMore,
    Error,
}

struct H3EdgeUniPending {
    in_use:    bool     = false,
    stream_id: u64      = 0,
    buf:       u8[..16] = [],
}

struct H3EdgeIgnoredUni {
    in_use:    bool = false,
    next_idx:  i64  = -1,
    stream_id: u64  = 0,
}

struct H3EdgeChunk {
    in_use:     bool        = false,
    next_chunk: i64         = -1,
    buf:        u8[..16384] = [],
}

struct H3EdgeHdrAccum {
    in_use: bool        = false,
    buf:    u8[..65536] = [],
}

struct H3EdgeQueuedEvent {
    in_use:     bool            = false,
    next_ev:    i64             = -1,
    kind:       H3EdgeEventKind = H3EdgeEventKind.None,
    stream_id:  u64             = 0,
    hdr_idx:    i64             = -1,
    chunk_idx:  i64             = -1,
    end_stream: bool            = false,
    error_code: u64             = 0,
}

struct H3EdgeStreamSlot {
    in_use:                  bool            = false,
    next_stream:             i64             = -1,
    stream_id:               u64             = 0,
    stage:                   H3EdgeBidiStage = H3EdgeBidiStage.ReadHeader,
    msg_phase:               H3EdgeMsgPhase  = H3EdgeMsgPhase.ExpectHeaders,
    hdr_buf:                 u8[..16]        = [],
    hdr_accum_idx:           i64             = -1,
    frame_remaining:         u64             = 0,
    empty_streak:            u32             = 0,
    has_content_length:      bool            = false,
    expected_content_length: u64             = 0,
    body_bytes_received:     u64             = 0,
    blocked_on_qpack:        bool            = false,
    blocked_is_trailers:     bool            = false,
    blocked_has_fin:         bool            = false,
    blocked_head:            i64             = -1,
    blocked_tail:            i64             = -1,
    deferred_trailers_idx:   i64             = -1,
    errored:                 bool            = false,
    finished:                bool            = false,
}

struct H3EdgeSlot {
    active:                 bool                    = false,
    generation:             u64                     = 0,
    conn_failed:            bool                    = false,
    has_peer_ctrl:          bool                    = false,
    peer_ctrl_stream_id:    u64                     = 0,
    has_peer_qenc:          bool                    = false,
    peer_qenc_stream_id:    u64                     = 0,
    has_peer_qdec:          bool                    = false,
    peer_qdec_stream_id:    u64                     = 0,
    peer_settings_received: bool                    = false,
    peer_settings:          fingerprint::H3Settings = fingerprint::H3Settings { .. },
    local_settings:         fingerprint::H3Settings = fingerprint::H3Settings { .. },
    peer_goaway_seen:       bool                    = false,
    peer_goaway_id:         u64                     = 0,
    has_max_push_id:        bool                    = false,
    max_push_id:            u64                     = 0,
    ctrl_stage:             H3EdgeCtrlStage         = H3EdgeCtrlStage.ReadHeader,
    ctrl_hdr_buf:           u8[..16]                = [],
    ctrl_frame_type:        u64                     = 0,
    ctrl_remaining:         u64                     = 0,
    ctrl_payload_buf:       u8[..1024]              = [],
    ctrl_empty_streak:      u32                     = 0,
    qenc_rx_buf:            u8[..4096]              = [],
    qdec_rx_buf:            u8[..1024]              = [],
    uni_pending:            H3EdgeUniPending[..16]  = [],
    ignored_uni_head:       i64                     = -1,
    ignored_uni_count:      i64                     = 0,
    qpack_dec_table:        QpackTable              = QpackTable { .. },
    qpack_enc_table:        QpackTable              = QpackTable { .. },
    stream_head:            i64                     = -1,
    stream_count:           i64                     = 0,
    ev_head:                i64                     = -1,
    ev_tail:                i64                     = -1,
    ev_data_buf:            u8[..16384]             = [],
}

var g_h3_edge_slots:      H3EdgeSlot[>..] = [];
var g_h3_edge_free_slots: i64[>..]        = [];
var g_h3_edge_next_gen:   u64             = 1;

var g_h3_edge_streams:      H3EdgeStreamSlot[>..] = [];
var g_h3_edge_free_streams: i64[>..]              = [];

var g_h3_edge_events:      H3EdgeQueuedEvent[>..] = [];
var g_h3_edge_free_events: i64[>..]               = [];

var g_h3_edge_headers:      http::HeaderMap[>..] = [];
var g_h3_edge_free_headers: i64[>..]             = [];

var g_h3_edge_chunks:      H3EdgeChunk[>..] = [];
var g_h3_edge_free_chunks: i64[>..]         = [];

var g_h3_edge_hdr_accums:      H3EdgeHdrAccum[>..] = [];
var g_h3_edge_free_hdr_accums: i64[>..]            = [];

var g_h3_edge_ignored_uni:      H3EdgeIgnoredUni[>..] = [];
var g_h3_edge_free_ignored_uni: i64[>..]              = [];

var g_h3_edge_replay_scratch: u8[..16384] = [];
var g_h3_resp_qpack_scratch:  u8[>..]     = [];

fn next_h3_edge_generation() -> u64 {
    let gen = g_h3_edge_next_gen;
    g_h3_edge_next_gen += 1;
    if g_h3_edge_next_gen == 0 {
        g_h3_edge_next_gen = 1;
    }
    return gen;
}

fn pop_free_index(free_list: i64[>..]&) -> i64, bool {
    if free_list.len == 0 {
        return -1, false;
    }
    let last_pos = core::sub_sat_i64(free_list.len, 1);
    let idx = free_list[last_pos];
    free_list.pop();
    return idx, true;
}

fn resolve_h3_edge_slot(sess: const H3EdgeSession&) -> i64, bool {
    if sess.generation == 0 || sess.slot_idx < 0 || sess.slot_idx >= g_h3_edge_slots.len {
        return -1, false;
    }
    let slot .= g_h3_edge_slots[sess.slot_idx];
    if !slot.active || slot.generation != sess.generation {
        return -1, false;
    }
    return sess.slot_idx, true;
}

fn alloc_h3_chunk() -> i64 {
    let idx, has_free = pop_free_index(g_h3_edge_free_chunks);
    if has_free {
        g_h3_edge_chunks[idx].in_use = true;
        g_h3_edge_chunks[idx].next_chunk = -1;
        g_h3_edge_chunks[idx].buf.clear();
        return idx;
    }
    let new_idx = g_h3_edge_chunks.len;
    g_h3_edge_chunks.push(H3EdgeChunk { in_use: true });
    return new_idx;
}

fn free_h3_chunk(idx: i64) {
    if idx < 0 || idx >= g_h3_edge_chunks.len || !g_h3_edge_chunks[idx].in_use {
        return;
    }
    g_h3_edge_chunks[idx].in_use = false;
    g_h3_edge_chunks[idx].next_chunk = -1;
    g_h3_edge_chunks[idx].buf.clear();
    g_h3_edge_free_chunks.push(idx);
}

fn free_h3_chunk_chain(head: i64) {
    var curr = head;
    while curr >= 0 {
        let next_id = g_h3_edge_chunks[curr].next_chunk;
        free_h3_chunk(curr);
        curr = next_id;
    }
}

fn alloc_h3_hdr_accum() -> i64 {
    let idx, has_free = pop_free_index(g_h3_edge_free_hdr_accums);
    if has_free {
        g_h3_edge_hdr_accums[idx].in_use = true;
        g_h3_edge_hdr_accums[idx].buf.clear();
        return idx;
    }
    let new_idx = g_h3_edge_hdr_accums.len;
    g_h3_edge_hdr_accums.push(H3EdgeHdrAccum { in_use: true });
    return new_idx;
}

fn free_h3_hdr_accum(idx: i64) {
    if idx < 0 || idx >= g_h3_edge_hdr_accums.len || !g_h3_edge_hdr_accums[idx].in_use {
        return;
    }
    g_h3_edge_hdr_accums[idx].in_use = false;
    g_h3_edge_hdr_accums[idx].buf.clear();
    g_h3_edge_free_hdr_accums.push(idx);
}

fn alloc_h3_header_map(src: const http::HeaderMap&) -> i64 {
    let idx, has_free = pop_free_index(g_h3_edge_free_headers);
    if has_free {
        g_h3_edge_headers[idx] = src;
        return idx;
    }
    let new_idx = g_h3_edge_headers.len;
    g_h3_edge_headers.push(src);
    return new_idx;
}

fn free_h3_header_map(idx: i64) {
    if idx < 0 || idx >= g_h3_edge_headers.len {
        return;
    }
    g_h3_edge_headers[idx] = http::HeaderMap { .. };
    g_h3_edge_free_headers.push(idx);
}

fn alloc_h3_event_node() -> i64 {
    let idx, has_free = pop_free_index(g_h3_edge_free_events);
    if has_free {
        g_h3_edge_events[idx] = H3EdgeQueuedEvent { in_use: true };
        return idx;
    }
    let new_idx = g_h3_edge_events.len;
    g_h3_edge_events.push(H3EdgeQueuedEvent { in_use: true });
    return new_idx;
}

fn free_h3_event_node(idx: i64) {
    if idx < 0 || idx >= g_h3_edge_events.len || !g_h3_edge_events[idx].in_use {
        return;
    }
    let ev .= g_h3_edge_events[idx];
    if ev.hdr_idx >= 0 {
        free_h3_header_map(ev.hdr_idx);
    }
    if ev.chunk_idx >= 0 {
        free_h3_chunk(ev.chunk_idx);
    }
    g_h3_edge_events[idx] = H3EdgeQueuedEvent { .. };
    g_h3_edge_free_events.push(idx);
}

fn enqueue_h3_event(
    slot_idx:   i64,
    kind:       H3EdgeEventKind,
    stream_id:  u64,
    hdr_idx:    i64,
    chunk_idx:  i64,
    end_stream: bool,
    error_code: u64,
) {
    let ev_idx = alloc_h3_event_node();
    let ev .= g_h3_edge_events[ev_idx];
    ev.kind = kind;
    ev.stream_id = stream_id;
    ev.hdr_idx = hdr_idx;
    ev.chunk_idx = chunk_idx;
    ev.end_stream = end_stream;
    ev.error_code = error_code;
    ev.next_ev = -1;

    let slot .= g_h3_edge_slots[slot_idx];
    if slot.ev_tail < 0 {
        slot.ev_head = ev_idx;
        slot.ev_tail = ev_idx;
        return;
    }
    g_h3_edge_events[slot.ev_tail].next_ev = ev_idx;
    slot.ev_tail = ev_idx;
}

fn emit_h3_protocol_error(slot_idx: i64, stream_id: u64, error_code: u64) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    if !slot.conn_failed {
        slot.conn_failed = true;
        enqueue_h3_event(
            slot_idx,
            H3EdgeEventKind.ProtocolError,
            stream_id,
            -1,
            -1,
            false,
            error_code,
        );
    }
    return false;
}

fn cleanup_h3_stream_resources(slot_idx: i64, st_idx: i64) {
    let slot .= g_h3_edge_slots[slot_idx];
    let st .= g_h3_edge_streams[st_idx];
    if st.hdr_accum_idx >= 0 {
        free_h3_hdr_accum(st.hdr_accum_idx);
        st.hdr_accum_idx = -1;
    }
    free_h3_chunk_chain(st.blocked_head);
    st.blocked_head = -1;
    st.blocked_tail = -1;
    st.blocked_has_fin = false;
    st.blocked_on_qpack = false;
    if st.deferred_trailers_idx >= 0 {
        free_h3_header_map(st.deferred_trailers_idx);
        st.deferred_trailers_idx = -1;
    }
    st.hdr_buf.clear();
    let _ = qpack_unblock_stream(slot.qpack_dec_table, st.stream_id);
}

fn emit_h3_stream_reset(slot_idx: i64, st_idx: i64, error_code: u64) {
    let st .= g_h3_edge_streams[st_idx];
    if st.errored {
        return;
    }
    st.errored = true;
    st.finished = true;
    cleanup_h3_stream_resources(slot_idx, st_idx);
    enqueue_h3_event(
        slot_idx,
        H3EdgeEventKind.StreamReset,
        st.stream_id,
        -1,
        -1,
        true,
        error_code,
    );
}

fn reset_h3_edge_slot(slot_idx: i64, gen: u64) {
    let slot .= g_h3_edge_slots[slot_idx];
    slot.active = true;
    slot.generation = gen;
    slot.conn_failed = false;
    slot.has_peer_ctrl = false;
    slot.peer_ctrl_stream_id = 0;
    slot.has_peer_qenc = false;
    slot.peer_qenc_stream_id = 0;
    slot.has_peer_qdec = false;
    slot.peer_qdec_stream_id = 0;
    slot.peer_settings_received = false;
    slot.peer_settings = fingerprint::H3Settings { .. };
    slot.local_settings = fingerprint::H3Settings { .. };
    slot.peer_goaway_seen = false;
    slot.peer_goaway_id = 0;
    slot.has_max_push_id = false;
    slot.max_push_id = 0;
    slot.ctrl_stage = H3EdgeCtrlStage.ReadHeader;
    slot.ctrl_hdr_buf.clear();
    slot.ctrl_frame_type = 0;
    slot.ctrl_remaining = 0;
    slot.ctrl_payload_buf.clear();
    slot.ctrl_empty_streak = 0;
    slot.qenc_rx_buf.clear();
    slot.qdec_rx_buf.clear();
    slot.uni_pending.clear();
    slot.ignored_uni_head = -1;
    slot.ignored_uni_count = 0;
    // RFC 9204 Section 3.2.1: Dynamic Table Capacity - Initial decoder capacity MUST be 0 until instructed.
    slot.qpack_dec_table = new_qpack_table(
        H3_EDGE_QPACK_DEFAULT_CAP,
        H3_EDGE_QPACK_DEFAULT_BLOCKED,
        0,
    );
    slot.qpack_enc_table = new_qpack_table(
        H3_EDGE_QPACK_DEFAULT_CAP,
        H3_EDGE_QPACK_DEFAULT_BLOCKED,
        0,
    );
    slot.stream_head = -1;
    slot.stream_count = 0;
    slot.ev_head = -1;
    slot.ev_tail = -1;
    slot.ev_data_buf.clear();
}

fn free_h3_stream_slot(st_idx: i64) {
    if st_idx < 0 || st_idx >= g_h3_edge_streams.len || !g_h3_edge_streams[st_idx].in_use {
        return;
    }
    let st .= g_h3_edge_streams[st_idx];
    if st.hdr_accum_idx >= 0 {
        free_h3_hdr_accum(st.hdr_accum_idx);
    }
    if st.blocked_head >= 0 {
        free_h3_chunk_chain(st.blocked_head);
    }
    if st.deferred_trailers_idx >= 0 {
        free_h3_header_map(st.deferred_trailers_idx);
    }
    g_h3_edge_streams[st_idx] = H3EdgeStreamSlot { .. };
    g_h3_edge_free_streams.push(st_idx);
}

fn unlink_h3_stream_node(slot: H3EdgeSlot&, prev_idx: i64, target_idx: i64) {
    let next_id = g_h3_edge_streams[target_idx].next_stream;
    if prev_idx < 0 {
        slot.stream_head = next_id;
    } else {
        g_h3_edge_streams[prev_idx].next_stream = next_id;
    }
    slot.stream_count = core::sub_sat_i64(slot.stream_count, 1);
    free_h3_stream_slot(target_idx);
}

fn reap_oldest_finished_stream(slot_idx: i64) {
    let slot .= g_h3_edge_slots[slot_idx];
    var prev: i64 = -1;
    var curr = slot.stream_head;
    var target_prev: i64 = -1;
    var target:      i64 = -1;
    while curr >= 0 {
        if g_h3_edge_streams[curr].finished || g_h3_edge_streams[curr].errored {
            target_prev = prev;
            target = curr;
        }
        prev = curr;
        curr = g_h3_edge_streams[curr].next_stream;
    }
    if target < 0 {
        return;
    }
    unlink_h3_stream_node(slot, target_prev, target);
}

fn find_h3_stream(slot_idx: i64, stream_id: u64) -> i64 {
    var curr = g_h3_edge_slots[slot_idx].stream_head;
    while curr >= 0 {
        if g_h3_edge_streams[curr].stream_id == stream_id {
            return curr;
        }
        curr = g_h3_edge_streams[curr].next_stream;
    }
    return -1;
}

fn find_or_create_h3_stream(slot_idx: i64, stream_id: u64) -> i64, bool {
    let existing = find_h3_stream(slot_idx, stream_id);
    if existing >= 0 {
        return existing, false;
    }
    let slot .= g_h3_edge_slots[slot_idx];
    if slot.stream_count >= H3_EDGE_MAX_RETAINED_STREAMS {
        reap_oldest_finished_stream(slot_idx);
    }
    let free_idx, has_free = pop_free_index(g_h3_edge_free_streams);
    var st_idx: i64 = -1;
    if has_free {
        st_idx = free_idx;
        g_h3_edge_streams[st_idx] = H3EdgeStreamSlot { in_use: true, stream_id: stream_id };
    } else {
        st_idx = g_h3_edge_streams.len;
        g_h3_edge_streams.push(H3EdgeStreamSlot { in_use: true, stream_id: stream_id });
    }
    g_h3_edge_streams[st_idx].next_stream = slot.stream_head;
    slot.stream_head = st_idx;
    slot.stream_count = core::add_sat_i64(slot.stream_count, 1);
    return st_idx, true;
}

// Opens a new streaming HTTP/3 server edge session.
fn h3_edge_open() -> H3EdgeSession {
    let gen = next_h3_edge_generation();
    let free_idx, has_free = pop_free_index(g_h3_edge_free_slots);
    var idx: i64 = -1;
    if has_free {
        idx = free_idx;
    } else {
        idx = g_h3_edge_slots.len;
        g_h3_edge_slots.push(H3EdgeSlot { .. });
    }
    reset_h3_edge_slot(idx, gen);
    return H3EdgeSession { slot_idx: idx, generation: gen };
}

fn clear_ignored_uni_streams(slot: H3EdgeSlot&) {
    var curr = slot.ignored_uni_head;
    while curr >= 0 {
        let next_node = g_h3_edge_ignored_uni[curr].next_idx;
        g_h3_edge_ignored_uni[curr] = H3EdgeIgnoredUni { .. };
        g_h3_edge_free_ignored_uni.push(curr);
        curr = next_node;
    }
    slot.ignored_uni_head = -1;
    slot.ignored_uni_count = 0;
}

// Closes an HTTP/3 edge session and reclaims its state idempotently.
fn h3_edge_close(sess: H3EdgeSession&) {
    let slot_idx, ok = resolve_h3_edge_slot(sess);
    if !ok {
        sess.slot_idx = -1;
        sess.generation = 0;
        return;
    }
    let slot .= g_h3_edge_slots[slot_idx];
    var st = slot.stream_head;
    while st >= 0 {
        let next_st = g_h3_edge_streams[st].next_stream;
        free_h3_stream_slot(st);
        st = next_st;
    }
    var ev = slot.ev_head;
    while ev >= 0 {
        let next_ev = g_h3_edge_events[ev].next_ev;
        free_h3_event_node(ev);
        ev = next_ev;
    }
    clear_ignored_uni_streams(slot);
    slot.stream_head = -1;
    slot.stream_count = 0;
    slot.ev_head = -1;
    slot.ev_tail = -1;
    slot.qenc_rx_buf.clear();
    slot.qdec_rx_buf.clear();
    slot.ctrl_payload_buf.clear();
    slot.ev_data_buf.clear();
    slot.active = false;
    slot.generation = 0;
    g_h3_edge_free_slots.push(slot_idx);
    sess.slot_idx = -1;
    sess.generation = 0;
}

fn is_ignored_uni_stream(slot: const H3EdgeSlot&, stream_id: u64) -> bool {
    var curr = slot.ignored_uni_head;
    while curr >= 0 {
        if g_h3_edge_ignored_uni[curr].stream_id == stream_id {
            return true;
        }
        curr = g_h3_edge_ignored_uni[curr].next_idx;
    }
    return false;
}

fn add_ignored_uni_stream(slot: H3EdgeSlot&, stream_id: u64) -> bool {
    if slot.ignored_uni_count >= H3_EDGE_MAX_IGNORED_UNI {
        return false;
    }
    let free_idx, has_free = pop_free_index(g_h3_edge_free_ignored_uni);
    var node_idx: i64 = -1;
    if has_free {
        node_idx = free_idx;
        g_h3_edge_ignored_uni[node_idx] = H3EdgeIgnoredUni {
            in_use:    true,
            next_idx:  slot.ignored_uni_head,
            stream_id: stream_id,
        };
    } else {
        node_idx = g_h3_edge_ignored_uni.len;
        g_h3_edge_ignored_uni.push(
            H3EdgeIgnoredUni {
                in_use:    true,
                next_idx:  slot.ignored_uni_head,
                stream_id: stream_id,
            },
        );
    }
    slot.ignored_uni_head = node_idx;
    slot.ignored_uni_count = core::add_sat_i64(slot.ignored_uni_count, 1);
    return true;
}

fn remove_ignored_uni_stream(slot: H3EdgeSlot&, stream_id: u64) {
    var prev: i64 = -1;
    var curr = slot.ignored_uni_head;
    while curr >= 0 {
        let next_node = g_h3_edge_ignored_uni[curr].next_idx;
        if g_h3_edge_ignored_uni[curr].stream_id == stream_id {
            if prev < 0 {
                slot.ignored_uni_head = next_node;
            } else {
                g_h3_edge_ignored_uni[prev].next_idx = next_node;
            }
            g_h3_edge_ignored_uni[curr] = H3EdgeIgnoredUni { .. };
            g_h3_edge_free_ignored_uni.push(curr);
            slot.ignored_uni_count = core::sub_sat_i64(slot.ignored_uni_count, 1);
            return;
        }
        prev = curr;
        curr = next_node;
    }
}

fn find_pending_uni_idx(slot: const H3EdgeSlot&, stream_id: u64) -> i64 {
    for i in 0..slot.uni_pending.len {
        if slot.uni_pending[i].in_use && slot.uni_pending[i].stream_id == stream_id {
            return i;
        }
    }
    return -1;
}

fn alloc_pending_uni_idx(slot: H3EdgeSlot&, stream_id: u64) -> i64, bool {
    for i in 0..slot.uni_pending.len {
        if !slot.uni_pending[i].in_use {
            slot.uni_pending[i].in_use = true;
            slot.uni_pending[i].stream_id = stream_id;
            slot.uni_pending[i].buf.clear();
            return i, true;
        }
    }
    if slot.uni_pending.len >= H3_EDGE_MAX_UNI_PENDING {
        return -1, false;
    }
    let idx = slot.uni_pending.len;
    guard slot.uni_pending.try_push(H3EdgeUniPending { in_use: true, stream_id: stream_id }) else {
        return -1, false;
    };
    return idx, true;
}

fn varint_encoded_len(first_byte: u8) -> i64 {
    let shift = (first_byte >> 6) & 0x03;
    return 1 << shift;
}

fn update_h3_empty_streak(streak: u32&, payload_len: u64) -> bool {
    if payload_len == 0 {
        streak = core::add_sat_u32(streak, 1);
        return streak <= h3_internal::MAX_H3_EMPTY_FRAME_STREAK;
    }
    streak = 0;
    return true;
}

// Begins decoding a uni stream type varint from `data[pos..]`, buffering partial bytes.
// Advances `pos` past consumed bytes.
//
// Example:
//   data = "\x00...", pos = 0, end_flag = Open
//   returns: stream_type = 0, resolved = true, ok = true, pos = 1
fn start_uni_stream_type(
    slot:      H3EdgeSlot&,
    stream_id: u64,
    data:      const u8[:],
    pos:       i64&,
    end_flag:  H3EdgeEndFlag,
) -> u64, bool, bool {
    if pos >= data.len {
        return 0, false, true;
    }
    let avail = core::sub_sat_i64(data.len, pos);
    let need = varint_encoded_len(data[pos]);
    if avail >= need {
        let stype, next_off, ok = quic::decode_varint(data, pos as u64);
        if !ok {
            return 0, false, false;
        }
        pos = next_off as i64;
        return stype, true, true;
    }
    if end_flag == H3EdgeEndFlag.Fin {
        return 0, false, false;
    }
    let new_idx, alloc_ok = alloc_pending_uni_idx(slot, stream_id);
    if !alloc_ok {
        return 0, false, false;
    }
    guard slot.uni_pending[new_idx].buf.try_append(data[pos..]) else {
        return 0, false, false;
    };
    pos = data.len;
    return 0, false, true;
}

// Completes a buffered uni stream type varint from incoming bytes.
// Advances `pos` past consumed bytes.
//
// Example:
//   pend.buf = "\x40", data = "\x21rest", pos = 0
//   returns: stream_type = 0x21, resolved = true, ok = true, pos = 1
fn continue_pending_uni_type(
    slot:     H3EdgeSlot&,
    p_idx:    i64,
    data:     const u8[:],
    pos:      i64&,
    end_flag: H3EdgeEndFlag,
) -> u64, bool, bool {
    let pend .= slot.uni_pending[p_idx];
    if pend.buf.len == 0 && pos < data.len {
        guard pend.buf.try_push(data[pos]) else { return 0, false, false; };
        pos = core::add_sat_i64(pos, 1);
    }
    let need = varint_encoded_len(pend.buf[0]);
    let rem_need = core::sub_sat_i64(need, pend.buf.len);
    let avail = core::sub_sat_i64(data.len, pos);
    let take = min(rem_need, avail);
    if take > 0 {
        let end_i = core::add_sat_i64(pos, take);
        guard pend.buf.try_append(data[pos..end_i]) else { return 0, false, false; };
        pos = end_i;
    }
    if pend.buf.len < need {
        return 0, false, end_flag != H3EdgeEndFlag.Fin;
    }
    let stype, _, ok = quic::decode_varint(pend.buf[..], 0);
    pend.in_use = false;
    pend.buf.clear();
    return stype, ok, ok;
}

// Decodes a uni stream type varint, buffering partial bytes across QUIC reads.
// Advances `pos` past any consumed type bytes on completion.
//
// Example:
//   data = "\x00...", pos = 0, end_flag = Open
//   returns: stream_type = 0, resolved = true, ok = true, pos = 1
fn decode_uni_stream_type_step(
    slot_idx:  i64,
    stream_id: u64,
    data:      const u8[:],
    pos:       i64&,
    end_flag:  H3EdgeEndFlag,
) -> u64, bool, bool {
    let slot .= g_h3_edge_slots[slot_idx];
    let p_idx = find_pending_uni_idx(slot, stream_id);
    if p_idx < 0 {
        return start_uni_stream_type(slot, stream_id, data, pos, end_flag);
    }
    return continue_pending_uni_type(slot, p_idx, data, pos, end_flag);
}

// Reads or buffers a variable-length HTTP/3 frame header across QUIC chunks.
// Advances `pos` past newly consumed header bytes.
//
// Example:
//   data = "\x00\x05hello", pos = 0
//   returns: H3HdrReadState.Ready, out_hdr = { DATA, 5, 2 }, pos = 2
fn read_varint_frame_hdr_step(
    hdr_buf: u8[..16]&,
    data:    const u8[:],
    pos:     i64&,
    out_hdr: FrameHeader&,
) -> H3HdrReadState {
    if hdr_buf.len == 0 {
        let hdr, ok = parse_frame_header(data, pos as u64);
        if ok {
            out_hdr = hdr;
            pos = core::add_sat_i64(pos, hdr.header_len as i64);
            return H3HdrReadState.Ready;
        }
        let avail = core::sub_sat_i64(data.len, pos);
        if avail >= H3_EDGE_VARINT_MAX_HEADER_BYTES {
            return H3HdrReadState.Error;
        }
        guard hdr_buf.try_append(data[pos..]) else {
            return H3HdrReadState.Error;
        };
        pos = data.len;
        return H3HdrReadState.NeedMore;
    }
    let old_len = hdr_buf.len;
    let max_room = core::sub_sat_i64(H3_EDGE_VARINT_MAX_HEADER_BYTES, old_len);
    let avail = core::sub_sat_i64(data.len, pos);
    let room = min(max_room, avail);
    if room > 0 {
        let end_i = core::add_sat_i64(pos, room);
        guard hdr_buf.try_append(data[pos..end_i]) else {
            return H3HdrReadState.Error;
        };
    }
    let hdr, ok = parse_frame_header(hdr_buf[..], 0);
    if !ok {
        if hdr_buf.len >= H3_EDGE_VARINT_MAX_HEADER_BYTES {
            return H3HdrReadState.Error;
        }
        pos = core::add_sat_i64(pos, room);
        return H3HdrReadState.NeedMore;
    }
    out_hdr = hdr;
    let delta = core::sub_sat_i64(hdr.header_len as i64, old_len);
    pos = core::add_sat_i64(pos, delta);
    hdr_buf.clear();
    return H3HdrReadState.Ready;
}

fn apply_h3_priority_update_ctrl(slot_idx: i64, frame_type: u64, payload: const u8[:]) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    if frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST {
        let elem_id, _, ok_id = quic::decode_varint(payload, 0);
        if !ok_id {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_ERROR);
        }
        // RFC 9218 Section 7.2: HTTP/3 PRIORITY_UPDATE Frame - Element ID MUST be client bidi stream.
        if (elem_id & 0x03) != 0 {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_ID_ERROR);
        }
        let _, _, ok = parse_priority_update_request(payload);
        if !ok {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_GENERAL_PROTOCOL);
        }
        return true;
    }
    if frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_PUSH {
        let _, _, ok = parse_priority_update_push(payload);
        if !ok {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_GENERAL_PROTOCOL);
        }
        return true;
    }
    return true;
}

fn apply_h3_ctrl_push_or_prio(slot_idx: i64, frame_type: u64, payload: const u8[:]) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    if frame_type == rfc::H3_FRAME_CANCEL_PUSH {
        let _, ok = parse_cancel_push(payload);
        if !ok {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_ERROR);
        }
        return true;
    }
    if frame_type == rfc::H3_FRAME_MAX_PUSH_ID {
        let max_id, ok = parse_max_push_id(payload);
        if !ok {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_ERROR);
        }
        if slot.has_max_push_id && max_id < slot.max_push_id {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_ID_ERROR);
        }
        slot.has_max_push_id = true;
        slot.max_push_id = max_id;
        return true;
    }
    return apply_h3_priority_update_ctrl(slot_idx, frame_type, payload);
}

// Validates and completes one decoded control stream frame on a server session.
// RFC 9114 Section 6.2.1: Control Streams - First frame MUST be SETTINGS; duplicates fail.
fn apply_h3_control_frame(slot_idx: i64, frame_type: u64, payload: const u8[:]) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    if !slot.peer_settings_received && frame_type != rfc::H3_FRAME_SETTINGS {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_MISSING_SETTINGS);
    }
    if frame_type == rfc::H3_FRAME_SETTINGS {
        if slot.peer_settings_received {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_UNEXPECTED);
        }
        let settings, err = parse_settings_frame(payload);
        if err != rfc::H3_ERR_NO_ERROR {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, err);
        }
        slot.peer_settings = settings;
        slot.peer_settings_received = true;
        return true;
    }
    if frame_type == rfc::H3_FRAME_GOAWAY {
        // RFC 9114 Section 7.2.6: GOAWAY - Subsequent GOAWAY MUST NOT carry a larger ID.
        let gid, ok = parse_goaway_frame(payload);
        if !ok {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_ERROR);
        }
        if slot.peer_goaway_seen && gid > slot.peer_goaway_id {
            return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_ID_ERROR);
        }
        slot.peer_goaway_seen = true;
        slot.peer_goaway_id = gid;
        enqueue_h3_event(slot_idx, H3EdgeEventKind.GoAway, gid, -1, -1, false, 0);
        return true;
    }
    return apply_h3_ctrl_push_or_prio(slot_idx, frame_type, payload);
}

fn is_known_h3_ctrl_frame(frame_type: u64) -> bool {
    return frame_type == rfc::H3_FRAME_SETTINGS
        || frame_type == rfc::H3_FRAME_GOAWAY
        || frame_type == rfc::H3_FRAME_CANCEL_PUSH
        || frame_type == rfc::H3_FRAME_MAX_PUSH_ID
        || frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST
        || frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_PUSH;
}

// Parses one control frame header from buffered/new bytes and transitions control stage.
// Advances `pos` past any consumed frame header bytes.
//
// Example:
//   data = "\x04\x00", pos = 0
//   returns: ok = true, ctrl_stage = ReadHeader, peer_settings_received = true
fn parse_ctrl_frame_header_step(slot_idx: i64, data: const u8[:], pos: i64&) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    var hdr = FrameHeader { .. };
    let rstate = read_varint_frame_hdr_step(slot.ctrl_hdr_buf, data, pos, hdr);
    if rstate == H3HdrReadState.Error {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_ERROR);
    }
    if rstate == H3HdrReadState.NeedMore {
        return true;
    }
    if !rfc::is_allowed_on_control_stream(hdr.frame_type) {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_UNEXPECTED);
    }
    if !update_h3_empty_streak(slot.ctrl_empty_streak, hdr.payload_len) {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
    }
    if !slot.peer_settings_received && hdr.frame_type != rfc::H3_FRAME_SETTINGS {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_MISSING_SETTINGS);
    }
    if hdr.frame_type == rfc::H3_FRAME_SETTINGS && hdr.payload_len > h3_internal::H3_MAX_SETTINGS_PAYLOAD_SIZE {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
    }
    slot.ctrl_frame_type = hdr.frame_type;
    slot.ctrl_remaining = hdr.payload_len;
    slot.ctrl_payload_buf.clear();
    if !is_known_h3_ctrl_frame(hdr.frame_type) {
        slot.ctrl_stage = if hdr.payload_len > 0 {
            H3EdgeCtrlStage.SkipUnknownPayload
        } else {
            H3EdgeCtrlStage.ReadHeader
        };
        return true;
    }
    if hdr.payload_len > H3_EDGE_CTRL_BUF_CAP {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_ERROR);
    }
    if hdr.payload_len == 0 {
        return apply_h3_control_frame(slot_idx, hdr.frame_type, "");
    }
    slot.ctrl_stage = H3EdgeCtrlStage.ReadPayload;
    return true;
}

// Consumes one chunk of control-frame payload or unknown-frame bytes.
// Advances `pos` past consumed payload bytes.
//
// Example:
//   ctrl_stage = ReadPayload, ctrl_remaining = 4, data = "abcd"
//   returns: ok = true, pos = 4, ctrl_stage = ReadHeader
fn step_ctrl_payload_bytes(slot_idx: i64, data: const u8[:], pos: i64&) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    let avail = core::sub_sat_i64(data.len, pos) as u64;
    let take = min(slot.ctrl_remaining, avail) as i64;
    let next_pos = core::add_sat_i64(pos, take);
    if slot.ctrl_stage == H3EdgeCtrlStage.SkipUnknownPayload {
        pos = next_pos;
        slot.ctrl_remaining = core::sub_sat_u64(slot.ctrl_remaining, take as u64);
        if slot.ctrl_remaining == 0 {
            slot.ctrl_stage = H3EdgeCtrlStage.ReadHeader;
        }
        return true;
    }
    guard slot.ctrl_payload_buf.try_append(data[pos..next_pos]) else {
        return emit_h3_protocol_error(slot_idx, slot.peer_ctrl_stream_id, rfc::H3_ERR_FRAME_ERROR);
    };
    pos = next_pos;
    slot.ctrl_remaining = core::sub_sat_u64(slot.ctrl_remaining, take as u64);
    if slot.ctrl_remaining > 0 {
        return true;
    }
    slot.ctrl_stage = H3EdgeCtrlStage.ReadHeader;
    guard apply_h3_control_frame(slot_idx, slot.ctrl_frame_type, slot.ctrl_payload_buf[..]) else {
        return false;
    };
    slot.ctrl_payload_buf.clear();
    return true;
}

fn feed_h3_control_bytes(slot_idx: i64, data: const u8[:]) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    var pos: i64 = 0;
    while pos < data.len {
        if slot.ctrl_stage == H3EdgeCtrlStage.ReadHeader {
            guard parse_ctrl_frame_header_step(slot_idx, data, pos) else { return false; };
            continue;
        }
        guard step_ctrl_payload_bytes(slot_idx, data, pos) else { return false; };
    }
    return true;
}

fn is_valid_token_tchar(s: const u8[:]) -> bool {
    if s.len == 0 {
        return false;
    }
    for b in s {
        if !core::is_tchar(b) {
            return false;
        }
    }
    return true;
}

fn validate_h3_connect_pseudo(slot: const H3EdgeSlot&, pseudo: const PseudoHeaders&) -> bool {
    if pseudo.has_protocol {
        // RFC 9114 Section 4.4: The CONNECT Method - Extended CONNECT requires enable_connect_protocol and token :protocol.
        if slot.local_settings.enable_connect_protocol == 0 {
            return false;
        }
        if !pseudo.has_scheme || !pseudo.has_path || !pseudo.has_authority {
            return false;
        }
        return is_valid_token_tchar(pseudo.protocol[..])
            && h3_internal::is_valid_uri_scheme(pseudo.scheme[..])
            && h3_internal::is_valid_h3_path_bytes(pseudo.path[..])
            && h3_internal::is_valid_authority_or_host(pseudo.authority[..]);
    }
    if pseudo.has_scheme || pseudo.has_path || !pseudo.has_authority {
        return false;
    }
    return h3_internal::is_valid_authority_or_host(pseudo.authority[..]);
}

fn validate_h3_request_pseudo(slot: const H3EdgeSlot&, pseudo: const PseudoHeaders&) -> bool {
    // RFC 9114 Section 4.3.1: Request Pseudo-Header Fields - Requests forbid :status.
    let method = pseudo.method[..];
    if pseudo.has_status || !pseudo.has_method || method.len == 0 {
        return false;
    }
    if !h3_internal::is_valid_http_method_token(method) {
        return false;
    }
    if method == "CONNECT" {
        return validate_h3_connect_pseudo(slot, pseudo);
    }
    // RFC 9220 Section 3: WebSockets Upgrade over HTTP/3 - Reject :protocol on non-CONNECT requests.
    if pseudo.has_protocol {
        return false;
    }
    let scheme = pseudo.scheme[..];
    let path = pseudo.path[..];
    if !pseudo.has_scheme || !pseudo.has_path || scheme.len == 0 || path.len == 0 {
        return false;
    }
    if !h3_internal::is_valid_uri_scheme(scheme) || !h3_internal::is_valid_h3_path_bytes(path) {
        return false;
    }
    if (path == "*" && method != "OPTIONS") || (path != "*" && path[0] != '/') {
        return false;
    }
    if pseudo.has_authority {
        let auth = pseudo.authority[..];
        return auth.len > 0 && h3_internal::is_valid_authority_or_host(auth);
    }
    return true;
}

fn append_header_with_sensitivity(
    out_hdrs:     http::HeaderMap&,
    name:         const u8[:],
    val:          const u8[:],
    is_sensitive: bool,
) -> bool {
    guard http::append_header(out_hdrs, name, val) else { return false; };
    if is_sensitive && out_hdrs.entries.len > 0 {
        let last_idx = core::sub_sat_i64(out_hdrs.entries.len, 1);
        out_hdrs.entries[last_idx].flags = out_hdrs.entries[last_idx].flags | http::HEADER_FLAG_SENSITIVE;
    }
    return true;
}

fn append_pseudo_headers_to_map(pseudo: const PseudoHeaders&, out_hdrs: http::HeaderMap&) -> bool {
    guard http::append_header(out_hdrs, ":method", pseudo.method[..]) else { return false; };
    if pseudo.has_scheme {
        guard http::append_header(out_hdrs, ":scheme", pseudo.scheme[..]) else { return false; };
    }
    if pseudo.has_authority {
        guard http::append_header(out_hdrs, ":authority", pseudo.authority[..]) else { return false; };
    }
    if pseudo.has_path {
        guard http::append_header(out_hdrs, ":path", pseudo.path[..]) else { return false; };
    }
    if pseudo.has_protocol {
        guard http::append_header(out_hdrs, ":protocol", pseudo.protocol[..]) else { return false; };
    }
    return true;
}

fn validate_edge_req_host_or_cl(
    name:     const u8[:],
    val:      const u8[:],
    pseudo:   const PseudoHeaders&,
    st_idx:   i64,
    has_host: bool&,
) -> bool {
    if name == "host" {
        if has_host || val.len == 0 || !h3_internal::is_valid_authority_or_host(val) {
            return false;
        }
        has_host = true;
        return !pseudo.has_authority || val.eq_ascii_fold(pseudo.authority[..]);
    }
    if name == "content-length" {
        let st .= g_h3_edge_streams[st_idx];
        let cl_val, cl_ok = val.parse_u64_dec();
        if !cl_ok || (st.has_content_length && st.expected_content_length != cl_val) {
            return false;
        }
        st.has_content_length = true;
        st.expected_content_length = cl_val;
    }
    return true;
}

fn validate_edge_req_field(
    name:     const u8[:],
    val:      const u8[:],
    pseudo:   const PseudoHeaders&,
    st_idx:   i64,
    has_host: bool&,
) -> bool {
    if name.len == 0 || name[0] == ':' || !http::is_valid_header_name_h2(name) {
        return false;
    }
    if h3_internal::has_ctl_chars(val) || h3_internal::is_forbidden_connection_header(name, val) {
        return false;
    }
    if name == "te" && val != "trailers" {
        return false;
    }
    return validate_edge_req_host_or_cl(name, val, pseudo, st_idx, has_host);
}

fn coalesce_edge_cookie(val: const u8[:], cookie_buf: u8[..8192]&, has_cookie: bool&) -> bool {
    // RFC 9114 Section 4.2.1: Field Compression - Coalesce split Cookie header fields with "; ".
    if has_cookie {
        guard cookie_buf.try_append("; ") else { return false; };
    }
    guard cookie_buf.try_append(val) else { return false; };
    has_cookie = true;
    return true;
}

fn build_edge_request_entries(
    raw_hdrs: const http::HeaderMap&,
    pseudo:   const PseudoHeaders&,
    st_idx:   i64,
    out_hdrs: http::HeaderMap&,
    has_host: bool&,
) -> u64 {
    var cookie_buf: u8[..8192] = [];
    var has_cookie = false;
    var cookie_sensitive = false;

    for i in 0..raw_hdrs.entries.len {
        let ent .= raw_hdrs.entries[i];
        let name = http::entry_name(raw_hdrs, ent);
        let val = http::entry_value(raw_hdrs, ent);
        let is_sens = http::is_sensitive(ent);
        guard validate_edge_req_field(name, val, pseudo, st_idx, has_host) else {
            return rfc::H3_ERR_MESSAGE_ERROR;
        };
        if name == "cookie" {
            if is_sens {
                cookie_sensitive = true;
            }
            guard coalesce_edge_cookie(val, cookie_buf, has_cookie) else { return rfc::H3_ERR_EXCESSIVE_LOAD; };
            continue;
        }
        guard append_header_with_sensitivity(out_hdrs, name, val, is_sens) else {
            return rfc::H3_ERR_EXCESSIVE_LOAD;
        };
    }
    if has_cookie {
        guard append_header_with_sensitivity(out_hdrs, "cookie", cookie_buf[..], cookie_sensitive) else {
            return rfc::H3_ERR_EXCESSIVE_LOAD;
        };
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn validate_and_build_edge_request_headers(
    slot:     const H3EdgeSlot&,
    pseudo:   const PseudoHeaders&,
    raw_hdrs: const http::HeaderMap&,
    st_idx:   i64,
    out_hdrs: http::HeaderMap&,
) -> u64 {
    guard validate_h3_request_pseudo(slot, pseudo) else {
        return rfc::H3_ERR_MESSAGE_ERROR;
    }
    guard append_pseudo_headers_to_map(pseudo, out_hdrs) else {
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    var has_host = false;
    let entry_err = build_edge_request_entries(raw_hdrs, pseudo, st_idx, out_hdrs, has_host);
    if entry_err != rfc::H3_ERR_NO_ERROR {
        return entry_err;
    }
    let method = pseudo.method[..];
    let scheme = pseudo.scheme[..];
    let needs_auth = scheme.eq_ascii_fold("http") || scheme.eq_ascii_fold("https");
    if !pseudo.has_authority && !has_host && method != "CONNECT" && needs_auth {
        return rfc::H3_ERR_MESSAGE_ERROR;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn validate_and_build_edge_trailers(
    pseudo:   const PseudoHeaders&,
    raw_hdrs: const http::HeaderMap&,
    out_hdrs: http::HeaderMap&,
) -> u64 {
    if pseudo.has_method || pseudo.has_scheme || pseudo.has_authority
        || pseudo.has_path || pseudo.has_protocol || pseudo.has_status
    {
        return rfc::H3_ERR_MESSAGE_ERROR;
    }
    for i in 0..raw_hdrs.entries.len {
        let ent .= raw_hdrs.entries[i];
        let name = http::entry_name(raw_hdrs, ent);
        let val = http::entry_value(raw_hdrs, ent);
        if name.len == 0 || name[0] == ':' || !http::is_valid_header_name_h2(name) {
            return rfc::H3_ERR_MESSAGE_ERROR;
        }
        if h3_internal::has_ctl_chars(val) || h3_internal::is_forbidden_connection_header(name, val) {
            return rfc::H3_ERR_MESSAGE_ERROR;
        }
        if name == "te" && val != "trailers" {
            return rfc::H3_ERR_MESSAGE_ERROR;
        }
        guard append_header_with_sensitivity(out_hdrs, name, val, http::is_sensitive(ent)) else {
            return rfc::H3_ERR_EXCESSIVE_LOAD;
        };
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn deliver_edge_request_head(
    slot_idx:   i64,
    st_idx:     i64,
    pseudo:     const PseudoHeaders&,
    raw_hdrs:   const http::HeaderMap&,
    at_msg_end: H3EdgeEndFlag,
) {
    let slot .= g_h3_edge_slots[slot_idx];
    let st .= g_h3_edge_streams[st_idx];
    var built = http::HeaderMap { .. };
    let build_err = validate_and_build_edge_request_headers(slot, pseudo, raw_hdrs, st_idx, built);
    if build_err != rfc::H3_ERR_NO_ERROR {
        emit_h3_stream_reset(slot_idx, st_idx, build_err);
        return;
    }
    let end_now = at_msg_end == H3EdgeEndFlag.Fin;
    if end_now && st.has_content_length && st.expected_content_length != 0 {
        emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_MESSAGE_ERROR);
        return;
    }
    let h_idx = alloc_h3_header_map(built);
    enqueue_h3_event(
        slot_idx,
        H3EdgeEventKind.RequestHead,
        st.stream_id,
        h_idx,
        -1,
        end_now,
        0,
    );
    st.msg_phase = H3EdgeMsgPhase.ReadingBody;
    if end_now {
        st.finished = true;
    }
}

fn deliver_edge_trailers(
    slot_idx:   i64,
    st_idx:     i64,
    pseudo:     const PseudoHeaders&,
    raw_hdrs:   const http::HeaderMap&,
    at_msg_end: H3EdgeEndFlag,
) {
    let st .= g_h3_edge_streams[st_idx];
    var built = http::HeaderMap { .. };
    let tr_err = validate_and_build_edge_trailers(pseudo, raw_hdrs, built);
    if tr_err != rfc::H3_ERR_NO_ERROR {
        emit_h3_stream_reset(slot_idx, st_idx, tr_err);
        return;
    }
    // RFC 9114 Section 4.1: HTTP Message Framing - No DATA may follow trailers, so Content-Length is final now.
    if st.has_content_length && st.body_bytes_received != st.expected_content_length {
        emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_MESSAGE_ERROR);
        return;
    }
    st.msg_phase = H3EdgeMsgPhase.ExpectEofAfterTrailers;
    let h_idx = alloc_h3_header_map(built);
    if at_msg_end == H3EdgeEndFlag.Fin {
        enqueue_h3_event(slot_idx, H3EdgeEventKind.RequestEnd, st.stream_id, h_idx, -1, true, 0);
        st.finished = true;
        return;
    }
    st.deferred_trailers_idx = h_idx;
}

// Decodes a QPACK field section into `out_ev` request or trailer headers, blocking if dynamic
// table entries have not yet arrived (RFC 9114 Section 4.1.2, RFC 9204 Section 2.2.1).
//
// Example:
//   section = [0x00, 0x00, 0xD1, ...], role = Request, at_msg_end = Fin
//   returns: blocked = false, ok = true (queues RequestHead with end_stream = true)
fn decode_and_deliver_headers_section(
    slot_idx:   i64,
    st_idx:     i64,
    section:    const u8[:],
    role:       H3EdgeSectionRole,
    at_msg_end: H3EdgeEndFlag,
) -> bool, bool {
    let slot .= g_h3_edge_slots[slot_idx];
    let st .= g_h3_edge_streams[st_idx];
    var pseudo = PseudoHeaders { is_trailer: role == H3EdgeSectionRole.Trailers, .. };
    var raw_hdrs = http::HeaderMap { .. };
    let qerr = decode_or_track_blocked_qpack_to_map(
        slot.qpack_dec_table,
        st.stream_id,
        section,
        pseudo,
        raw_hdrs,
        slot.local_settings.max_field_section_size,
    );
    if qerr == QpackError.StreamBlocked {
        return true, true;
    }
    if qerr == QpackError.MessageError {
        emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_MESSAGE_ERROR);
        return false, true;
    }
    if qerr == QpackError.HeaderListTooLarge {
        emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_EXCESSIVE_LOAD);
        return false, true;
    }
    if qerr != QpackError.None {
        return false, emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED);
    }
    if role == H3EdgeSectionRole.Request {
        deliver_edge_request_head(slot_idx, st_idx, pseudo, raw_hdrs, at_msg_end);
        return false, true;
    }
    deliver_edge_trailers(slot_idx, st_idx, pseudo, raw_hdrs, at_msg_end);
    return false, true;
}

fn queue_stream_blocked_tail(st_idx: i64, tail: const u8[:], end_flag: H3EdgeEndFlag) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    var pos: i64 = 0;
    while pos < tail.len {
        let rem = core::sub_sat_i64(tail.len, pos);
        let take = min((H3_EDGE_DATA_CHUNK_CAP as i64), rem);
        let next_pos = core::add_sat_i64(pos, take);
        let c_idx = alloc_h3_chunk();
        guard g_h3_edge_chunks[c_idx].buf.try_append(tail[pos..next_pos]) else {
            free_h3_chunk(c_idx);
            return false;
        };
        if st.blocked_tail < 0 {
            st.blocked_head = c_idx;
            st.blocked_tail = c_idx;
        } else {
            g_h3_edge_chunks[st.blocked_tail].next_chunk = c_idx;
            st.blocked_tail = c_idx;
        }
        pos = next_pos;
    }
    if end_flag == H3EdgeEndFlag.Fin {
        st.blocked_has_fin = true;
    }
    return true;
}

fn enter_stream_blocked(
    slot_idx: i64,
    st_idx:   i64,
    section:  const u8[:],
    role:     H3EdgeSectionRole,
    tail:     const u8[:],
    end_flag: H3EdgeEndFlag,
) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    if st.hdr_accum_idx < 0 {
        st.hdr_accum_idx = alloc_h3_hdr_accum();
        guard g_h3_edge_hdr_accums[st.hdr_accum_idx].buf.try_append(section) else {
            return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
        };
    }
    st.blocked_on_qpack = true;
    st.blocked_is_trailers = role == H3EdgeSectionRole.Trailers;
    guard queue_stream_blocked_tail(st_idx, tail, end_flag) else {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
    };
    return true;
}

// Starts decoding a bidi HEADERS section or begins accumulating split payload bytes.
// Advances `pos` past any consumed payload bytes.
//
// Example:
//   payload_len = 4, data = "\x00\x00\xD1\xD7", pos = 0
//   returns: ok = true, pos = 4 (delivers RequestHead)
fn start_bidi_headers_frame(
    slot_idx:    i64,
    st_idx:      i64,
    payload_len: u64,
    data:        const u8[:],
    pos:         i64&,
    end_flag:    H3EdgeEndFlag,
) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    if st.msg_phase == H3EdgeMsgPhase.ExpectEofAfterTrailers {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_FRAME_UNEXPECTED);
    }
    if payload_len > H3_EDGE_HDR_SECTION_CAP {
        emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_EXCESSIVE_LOAD);
        return true;
    }
    let role = if st.msg_phase == H3EdgeMsgPhase.ExpectHeaders {
        H3EdgeSectionRole.Request
    } else {
        H3EdgeSectionRole.Trailers
    };
    let avail = core::sub_sat_i64(data.len, pos) as u64;
    if avail >= payload_len {
        let end_pos = core::add_sat_i64(pos, payload_len as i64);
        let at_end = if end_flag == H3EdgeEndFlag.Fin && end_pos == data.len {
            H3EdgeEndFlag.Fin
        } else {
            H3EdgeEndFlag.Open
        };
        let section = data[pos..end_pos];
        pos = end_pos;
        let blocked, ok = decode_and_deliver_headers_section(slot_idx, st_idx, section, role, at_end);
        if !ok {
            return false;
        }
        if blocked {
            return enter_stream_blocked(slot_idx, st_idx, section, role, data[pos..], end_flag);
        }
        return true;
    }
    if st.hdr_accum_idx < 0 {
        st.hdr_accum_idx = alloc_h3_hdr_accum();
    }
    g_h3_edge_hdr_accums[st.hdr_accum_idx].buf.clear();
    guard g_h3_edge_hdr_accums[st.hdr_accum_idx].buf.try_append(data[pos..]) else {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
    };
    st.frame_remaining = core::sub_sat_u64(payload_len, avail);
    st.stage = H3EdgeBidiStage.ReadHeadersPayload;
    pos = data.len;
    return true;
}

// Parses one HTTP/3 bidi frame header from buffered/new bytes and updates stream stage.
// Advances `pos` past consumed header bytes.
//
// Example:
//   data = "\x00\x05hello", pos = 0
//   returns: ok = true, stage = ReadDataPayload, frame_remaining = 5
fn parse_bidi_frame_header_step(
    slot_idx: i64,
    st_idx:   i64,
    data:     const u8[:],
    pos:      i64&,
    end_flag: H3EdgeEndFlag,
) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    var hdr = FrameHeader { .. };
    let rstate = read_varint_frame_hdr_step(st.hdr_buf, data, pos, hdr);
    if rstate == H3HdrReadState.Error {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_FRAME_ERROR);
    }
    if rstate == H3HdrReadState.NeedMore {
        return true;
    }
    if hdr.frame_type == rfc::H3_FRAME_PUSH_PROMISE || !rfc::is_allowed_on_request_stream(hdr.frame_type) {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_FRAME_UNEXPECTED);
    }
    if !update_h3_empty_streak(st.empty_streak, hdr.payload_len) {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
    }
    if hdr.frame_type == rfc::H3_FRAME_DATA {
        if st.msg_phase != H3EdgeMsgPhase.ReadingBody {
            // RFC 9114 Section 4.1: HTTP Message Framing - DATA requires prior HEADERS and precedes trailers.
            return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_FRAME_UNEXPECTED);
        }
        st.frame_remaining = hdr.payload_len;
        st.stage = if hdr.payload_len > 0 { H3EdgeBidiStage.ReadDataPayload } else { H3EdgeBidiStage.ReadHeader };
        return true;
    }
    if hdr.frame_type == rfc::H3_FRAME_HEADERS {
        return start_bidi_headers_frame(slot_idx, st_idx, hdr.payload_len, data, pos, end_flag);
    }
    st.frame_remaining = hdr.payload_len;
    st.stage = if hdr.payload_len > 0 { H3EdgeBidiStage.SkipUnknownPayload } else { H3EdgeBidiStage.ReadHeader };
    return true;
}

fn stream_data_payload_chunks(slot_idx: i64, st_idx: i64, payload: const u8[:]) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    var off: i64 = 0;
    while off < payload.len {
        let rem = core::sub_sat_i64(payload.len, off);
        let take = min((H3_EDGE_DATA_CHUNK_CAP as i64), rem);
        let next_off = core::add_sat_i64(off, take);
        st.body_bytes_received = core::add_sat_u64(st.body_bytes_received, take as u64);
        if st.has_content_length && st.body_bytes_received > st.expected_content_length {
            emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_MESSAGE_ERROR);
            return true;
        }
        let c_idx = alloc_h3_chunk();
        guard g_h3_edge_chunks[c_idx].buf.try_append(payload[off..next_off]) else {
            free_h3_chunk(c_idx);
            return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_INTERNAL);
        };
        enqueue_h3_event(slot_idx, H3EdgeEventKind.RequestData, st.stream_id, -1, c_idx, false, 0);
        off = next_off;
    }
    return true;
}

fn handle_bidi_fin(slot_idx: i64, st_idx: i64) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    if st.errored {
        return true;
    }
    if st.blocked_on_qpack {
        st.blocked_has_fin = true;
        return true;
    }
    if st.hdr_buf.len > 0 || st.stage != H3EdgeBidiStage.ReadHeader {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_FRAME_ERROR);
    }
    if st.msg_phase == H3EdgeMsgPhase.ExpectHeaders {
        if !st.finished {
            emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_REQUEST_INCOMPLETE);
        }
        return true;
    }
    if st.has_content_length && st.body_bytes_received != st.expected_content_length {
        emit_h3_stream_reset(slot_idx, st_idx, rfc::H3_ERR_MESSAGE_ERROR);
        return true;
    }
    if !st.finished {
        if st.msg_phase == H3EdgeMsgPhase.ReadingBody {
            enqueue_h3_event(slot_idx, H3EdgeEventKind.RequestEnd, st.stream_id, -1, -1, true, 0);
        } else if st.msg_phase == H3EdgeMsgPhase.ExpectEofAfterTrailers {
            let tr_idx = st.deferred_trailers_idx;
            st.deferred_trailers_idx = -1;
            enqueue_h3_event(slot_idx, H3EdgeEventKind.RequestEnd, st.stream_id, tr_idx, -1, true, 0);
        }
        st.finished = true;
    }
    return true;
}

// Appends split HEADERS payload bytes up to `frame_remaining` and decodes on completion.
// Advances `pos` past all consumed payload bytes.
//
// Example:
//   data = "rest_of_qpack...", pos = 0, frame_remaining = 14
//   returns: ok = true, pos = 14, frame_remaining = 0
fn step_bidi_headers_payload(
    slot_idx: i64,
    st_idx:   i64,
    data:     const u8[:],
    pos:      i64&,
    end_flag: H3EdgeEndFlag,
) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    let avail = core::sub_sat_i64(data.len, pos) as u64;
    let take = min(st.frame_remaining, avail) as i64;
    let next_pos = core::add_sat_i64(pos, take);
    guard g_h3_edge_hdr_accums[st.hdr_accum_idx].buf.try_append(data[pos..next_pos]) else {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
    };
    pos = next_pos;
    st.frame_remaining = core::sub_sat_u64(st.frame_remaining, take as u64);
    if st.frame_remaining > 0 {
        return true;
    }
    st.stage = H3EdgeBidiStage.ReadHeader;
    let role = if st.msg_phase == H3EdgeMsgPhase.ExpectHeaders {
        H3EdgeSectionRole.Request
    } else {
        H3EdgeSectionRole.Trailers
    };
    let at_end = if end_flag == H3EdgeEndFlag.Fin && pos == data.len {
        H3EdgeEndFlag.Fin
    } else {
        H3EdgeEndFlag.Open
    };
    let accum_idx = st.hdr_accum_idx;
    let blocked, ok = decode_and_deliver_headers_section(
        slot_idx,
        st_idx,
        g_h3_edge_hdr_accums[accum_idx].buf[..],
        role,
        at_end,
    );
    if !ok {
        free_h3_hdr_accum(accum_idx);
        st.hdr_accum_idx = -1;
        return false;
    }
    if blocked {
        return enter_stream_blocked(slot_idx, st_idx, "", role, data[pos..], end_flag);
    }
    free_h3_hdr_accum(accum_idx);
    st.hdr_accum_idx = -1;
    return true;
}

// Consumes one chunk of DATA payload or unknown-frame bytes on a bidi stream.
// Advances `pos` past consumed bytes.
//
// Example:
//   stage = ReadDataPayload, frame_remaining = 5, data = "hello"
//   returns: ok = true, pos = 5, stage = ReadHeader
fn step_bidi_body_or_skip(slot_idx: i64, st_idx: i64, data: const u8[:], pos: i64&) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    let avail = core::sub_sat_i64(data.len, pos) as u64;
    let take = min(st.frame_remaining, avail) as i64;
    let next_pos = core::add_sat_i64(pos, take);
    if st.stage == H3EdgeBidiStage.ReadDataPayload {
        guard stream_data_payload_chunks(slot_idx, st_idx, data[pos..next_pos]) else {
            return false;
        };
    }
    pos = next_pos;
    st.frame_remaining = core::sub_sat_u64(st.frame_remaining, take as u64);
    if st.frame_remaining == 0 {
        st.stage = H3EdgeBidiStage.ReadHeader;
    }
    return true;
}

fn feed_blocked_bidi_bytes(
    slot_idx: i64,
    st_idx:   i64,
    data:     const u8[:],
    end_flag: H3EdgeEndFlag,
) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    if st.blocked_has_fin && data.len > 0 {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_FRAME_UNEXPECTED);
    }
    guard queue_stream_blocked_tail(st_idx, data, end_flag) else {
        return emit_h3_protocol_error(slot_idx, st.stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
    };
    return true;
}

// Dispatches one step of the bidirectional stream parser based on `st.stage`.
// Advances `pos` past any consumed frame bytes.
//
// Example:
//   stage = ReadHeader, data = "\x00\x05hello", pos = 0
//   returns: ok = true, pos = 2, stage = ReadDataPayload
fn dispatch_bidi_frame_step(
    slot_idx: i64,
    st_idx:   i64,
    data:     const u8[:],
    pos:      i64&,
    end_flag: H3EdgeEndFlag,
) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    if st.stage == H3EdgeBidiStage.ReadHeader {
        return parse_bidi_frame_header_step(slot_idx, st_idx, data, pos, end_flag);
    }
    if st.stage == H3EdgeBidiStage.ReadHeadersPayload {
        return step_bidi_headers_payload(slot_idx, st_idx, data, pos, end_flag);
    }
    return step_bidi_body_or_skip(slot_idx, st_idx, data, pos);
}

fn feed_bidi_stream_bytes(
    slot_idx: i64,
    st_idx:   i64,
    data:     const u8[:],
    end_flag: H3EdgeEndFlag,
) -> bool {
    let st .= g_h3_edge_streams[st_idx];
    if st.blocked_on_qpack {
        return feed_blocked_bidi_bytes(slot_idx, st_idx, data, end_flag);
    }
    var pos: i64 = 0;
    while pos < data.len && !st.errored && !st.blocked_on_qpack {
        guard dispatch_bidi_frame_step(slot_idx, st_idx, data, pos, end_flag) else { return false; };
    }
    if end_flag == H3EdgeEndFlag.Fin && !st.blocked_on_qpack {
        return handle_bidi_fin(slot_idx, st_idx);
    }
    return true;
}

fn attach_blocked_chunk_chain(st_idx: i64, chain_head: i64, saved_fin: bool) {
    let st .= g_h3_edge_streams[st_idx];
    if chain_head >= 0 {
        if st.blocked_tail < 0 {
            st.blocked_head = chain_head;
        } else {
            g_h3_edge_chunks[st.blocked_tail].next_chunk = chain_head;
        }
        var tail = chain_head;
        while g_h3_edge_chunks[tail].next_chunk >= 0 {
            tail = g_h3_edge_chunks[tail].next_chunk;
        }
        st.blocked_tail = tail;
    }
    st.blocked_has_fin = saved_fin;
}

fn replay_blocked_header_section(
    slot_idx:  i64,
    st_idx:    i64,
    ch:        i64,
    saved_fin: bool,
) -> bool, bool {
    let st .= g_h3_edge_streams[st_idx];
    let h_idx = st.hdr_accum_idx;
    if h_idx < 0 {
        return false, true;
    }
    let role = if st.blocked_is_trailers { H3EdgeSectionRole.Trailers } else { H3EdgeSectionRole.Request };
    let at_end = if ch < 0 && saved_fin { H3EdgeEndFlag.Fin } else { H3EdgeEndFlag.Open };
    let still_blocked, ok = decode_and_deliver_headers_section(
        slot_idx,
        st_idx,
        g_h3_edge_hdr_accums[h_idx].buf[..],
        role,
        at_end,
    );
    if !ok {
        free_h3_hdr_accum(h_idx);
        st.hdr_accum_idx = -1;
        free_h3_chunk_chain(ch);
        return false, false;
    }
    if still_blocked {
        st.blocked_on_qpack = true;
        attach_blocked_chunk_chain(st_idx, ch, saved_fin);
        return true, true;
    }
    free_h3_hdr_accum(h_idx);
    st.hdr_accum_idx = -1;
    return false, true;
}

fn replay_unblocked_stream(slot_idx: i64, blocked_stream_id: u64) -> bool {
    let st_idx = find_h3_stream(slot_idx, blocked_stream_id);
    if st_idx < 0 {
        return true;
    }
    let st .= g_h3_edge_streams[st_idx];
    if !st.blocked_on_qpack || st.errored {
        return true;
    }
    st.blocked_on_qpack = false;
    var ch = st.blocked_head;
    let saved_fin = st.blocked_has_fin;
    st.blocked_head = -1;
    st.blocked_tail = -1;
    st.blocked_has_fin = false;

    let still_blocked, hdr_ok = replay_blocked_header_section(slot_idx, st_idx, ch, saved_fin);
    if !hdr_ok || still_blocked {
        return hdr_ok;
    }
    while ch >= 0 {
        g_h3_edge_replay_scratch.clear();
        let _ = g_h3_edge_replay_scratch.try_append(g_h3_edge_chunks[ch].buf[..]);
        let next_ch = g_h3_edge_chunks[ch].next_chunk;
        free_h3_chunk(ch);
        let chunk_end = if next_ch < 0 && saved_fin { H3EdgeEndFlag.Fin } else { H3EdgeEndFlag.Open };
        guard feed_bidi_stream_bytes(slot_idx, st_idx, g_h3_edge_replay_scratch[..], chunk_end) else {
            free_h3_chunk_chain(next_ch);
            return false;
        };
        if st.blocked_on_qpack {
            attach_blocked_chunk_chain(st_idx, next_ch, saved_fin);
            return true;
        }
        ch = next_ch;
    }
    return true;
}

fn drain_qpack_enc_buffer(slot_idx: i64) -> bool, bool {
    let slot .= g_h3_edge_slots[slot_idx];
    var off: u64 = 0;
    var progressed = false;
    while off < (slot.qenc_rx_buf.len as u64) {
        let next_off, qerr = qpack_process_encoder_instruction(
            slot.qpack_dec_table,
            slot.qenc_rx_buf[..],
            off,
        );
        if qerr == QpackError.None {
            off = next_off;
            progressed = true;
            continue;
        }
        let max_cap = slot.qpack_dec_table.max_capacity_bytes;
        if h3_internal::is_qpack_enc_instr_incomplete(max_cap, slot.qenc_rx_buf[..], off) {
            break;
        }
        return false, emit_h3_protocol_error(
            slot_idx,
            slot.peer_qenc_stream_id,
            rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR,
        );
    }
    slot.qenc_rx_buf.compact_wire_buffer(off as i64);
    return progressed, true;
}

fn replay_ready_qpack_streams(slot_idx: i64) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    // RFC 9204 Section 2.2.1: Blocked Decoding - Unblock streams satisfied by new encoder instructions.
    while true {
        let b_entry, has_ready = h3_internal::pop_ready_blocked_qpack_stream(slot.qpack_dec_table);
        if !has_ready {
            return true;
        }
        guard replay_unblocked_stream(slot_idx, b_entry.stream_id) else { return false; };
    }
    return true;
}

fn feed_h3_qpack_enc_bytes(slot_idx: i64, data: const u8[:]) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    var pos: i64 = 0;
    while pos < data.len || slot.qenc_rx_buf.len > 0 {
        let room = core::sub_sat_i64(H3_EDGE_QENC_BUF_CAP as i64, slot.qenc_rx_buf.len);
        let avail = core::sub_sat_i64(data.len, pos);
        let take = min(room, avail);
        if take > 0 {
            let next_pos = core::add_sat_i64(pos, take);
            let _ = slot.qenc_rx_buf.try_append(data[pos..next_pos]);
            pos = next_pos;
        }
        let progressed, drain_ok = drain_qpack_enc_buffer(slot_idx);
        if !drain_ok {
            return false;
        }
        if progressed || take > 0 {
            continue;
        }
        if slot.qenc_rx_buf.len >= (H3_EDGE_QENC_BUF_CAP as i64) {
            return emit_h3_protocol_error(
                slot_idx,
                slot.peer_qenc_stream_id,
                rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR,
            );
        }
        break;
    }
    return replay_ready_qpack_streams(slot_idx);
}

fn drain_qpack_dec_buffer(slot_idx: i64) -> bool, bool {
    let slot .= g_h3_edge_slots[slot_idx];
    var off: u64 = 0;
    var progressed = false;
    while off < (slot.qdec_rx_buf.len as u64) {
        let next_off, qerr = qpack_process_decoder_instruction(
            slot.qpack_enc_table,
            slot.qdec_rx_buf[..],
            off,
        );
        if qerr == QpackError.None {
            off = next_off;
            progressed = true;
            continue;
        }
        if h3_internal::is_qpack_dec_instr_incomplete(slot.qdec_rx_buf[..], off) {
            break;
        }
        return false, emit_h3_protocol_error(
            slot_idx,
            slot.peer_qdec_stream_id,
            rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR,
        );
    }
    slot.qdec_rx_buf.compact_wire_buffer(off as i64);
    return progressed, true;
}

fn feed_h3_qpack_dec_bytes(slot_idx: i64, data: const u8[:]) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    var pos: i64 = 0;
    while pos < data.len || slot.qdec_rx_buf.len > 0 {
        let room = core::sub_sat_i64(H3_EDGE_QDEC_BUF_CAP as i64, slot.qdec_rx_buf.len);
        let avail = core::sub_sat_i64(data.len, pos);
        let take = min(room, avail);
        if take > 0 {
            let next_pos = core::add_sat_i64(pos, take);
            let _ = slot.qdec_rx_buf.try_append(data[pos..next_pos]);
            pos = next_pos;
        }
        let progressed, drain_ok = drain_qpack_dec_buffer(slot_idx);
        if !drain_ok {
            return false;
        }
        if progressed || take > 0 {
            continue;
        }
        if slot.qdec_rx_buf.len >= (H3_EDGE_QDEC_BUF_CAP as i64) {
            return emit_h3_protocol_error(
                slot_idx,
                slot.peer_qdec_stream_id,
                rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR,
            );
        }
        break;
    }
    return true;
}

fn dispatch_uni_stream_payload(
    slot_idx:  i64,
    stream_id: u64,
    data:      const u8[:],
    end_flag:  H3EdgeEndFlag,
) -> bool {
    let slot .= g_h3_edge_slots[slot_idx];
    let is_ctrl = slot.has_peer_ctrl && slot.peer_ctrl_stream_id == stream_id;
    let is_qenc = slot.has_peer_qenc && slot.peer_qenc_stream_id == stream_id;
    let is_qdec = slot.has_peer_qdec && slot.peer_qdec_stream_id == stream_id;
    if !is_ctrl && !is_qenc && !is_qdec {
        if end_flag == H3EdgeEndFlag.Fin {
            remove_ignored_uni_stream(slot, stream_id);
        }
        return true;
    }
    if data.len > 0 {
        var rx_ok = false;
        if is_ctrl {
            rx_ok = feed_h3_control_bytes(slot_idx, data);
        } else if is_qenc {
            rx_ok = feed_h3_qpack_enc_bytes(slot_idx, data);
        } else {
            rx_ok = feed_h3_qpack_dec_bytes(slot_idx, data);
        }
        guard rx_ok else { return false; };
    }
    if end_flag == H3EdgeEndFlag.Fin {
        // RFC 9114 Section 6.2.1 & RFC 9204 Section 4.2: Critical uni streams MUST NOT close.
        return emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_CLOSED_CRITICAL_STREAM);
    }
    return true;
}

fn assign_uni_stream_type(
    slot_idx:  i64,
    stream_id: u64,
    stype:     u64,
    end_flag:  H3EdgeEndFlag,
) -> bool, bool {
    let slot .= g_h3_edge_slots[slot_idx];
    if stype == rfc::H3_STREAM_CONTROL {
        if slot.has_peer_ctrl {
            return false, emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_STREAM_CREATION);
        }
        slot.has_peer_ctrl = true;
        slot.peer_ctrl_stream_id = stream_id;
        return false, true;
    }
    if stype == rfc::H3_STREAM_PUSH {
        // RFC 9114 Section 6.2.2: Push Streams - Client-initiated push stream is H3_STREAM_CREATION_ERROR.
        return false, emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_STREAM_CREATION);
    }
    if stype == rfc::H3_STREAM_QPACK_ENCODER {
        if slot.has_peer_qenc {
            return false, emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_STREAM_CREATION);
        }
        slot.has_peer_qenc = true;
        slot.peer_qenc_stream_id = stream_id;
        return false, true;
    }
    if stype == rfc::H3_STREAM_QPACK_DECODER {
        if slot.has_peer_qdec {
            return false, emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_STREAM_CREATION);
        }
        slot.has_peer_qdec = true;
        slot.peer_qdec_stream_id = stream_id;
        return false, true;
    }
    // RFC 9114 Section 6.2: Unidirectional Streams - Unknown/GREASE uni stream types are ignored.
    if end_flag == H3EdgeEndFlag.Open {
        if !add_ignored_uni_stream(slot, stream_id) {
            return false, emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_EXCESSIVE_LOAD);
        }
    }
    return true, true;
}

fn is_known_uni_stream(slot: const H3EdgeSlot&, stream_id: u64) -> bool {
    if slot.has_peer_ctrl && slot.peer_ctrl_stream_id == stream_id {
        return true;
    }
    if slot.has_peer_qenc && slot.peer_qenc_stream_id == stream_id {
        return true;
    }
    if slot.has_peer_qdec && slot.peer_qdec_stream_id == stream_id {
        return true;
    }
    return is_ignored_uni_stream(slot, stream_id);
}

// Feeds QUIC unidirectional stream bytes into an HTTP/3 edge session.
fn h3_edge_feed_uni_stream(
    sess:      H3EdgeSession&,
    stream_id: u64,
    data:      const u8[:],
    fin:       bool,
) -> bool {
    let slot_idx, ok = resolve_h3_edge_slot(sess);
    if !ok {
        return false;
    }
    let slot .= g_h3_edge_slots[slot_idx];
    if slot.conn_failed {
        return false;
    }
    if (stream_id & QUIC_STREAM_TYPE_MASK) != QUIC_CLIENT_UNI_TYPE || stream_id > rfc::QUIC_VARINT_MAX {
        return emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_STREAM_CREATION);
    }
    let end_flag = if fin { H3EdgeEndFlag.Fin } else { H3EdgeEndFlag.Open };
    if is_known_uni_stream(slot, stream_id) {
        return dispatch_uni_stream_payload(slot_idx, stream_id, data, end_flag);
    }
    if data.len == 0 && fin && find_pending_uni_idx(slot, stream_id) < 0 {
        return true;
    }
    var pos: i64 = 0;
    let stype, resolved, step_ok = decode_uni_stream_type_step(slot_idx, stream_id, data, pos, end_flag);
    if !step_ok {
        return emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_GENERAL_PROTOCOL);
    }
    if !resolved {
        return true;
    }
    let ignored, assign_ok = assign_uni_stream_type(slot_idx, stream_id, stype, end_flag);
    if !assign_ok {
        return false;
    }
    if ignored {
        return true;
    }
    return dispatch_uni_stream_payload(slot_idx, stream_id, data[pos..], end_flag);
}

// Feeds QUIC bidirectional request stream bytes into an HTTP/3 edge session.
fn h3_edge_feed_bidi_stream(
    sess:      H3EdgeSession&,
    stream_id: u64,
    data:      const u8[:],
    fin:       bool,
) -> bool {
    let slot_idx, ok = resolve_h3_edge_slot(sess);
    if !ok {
        return false;
    }
    let slot .= g_h3_edge_slots[slot_idx];
    if slot.conn_failed {
        return false;
    }
    if (stream_id & QUIC_STREAM_TYPE_MASK) != QUIC_CLIENT_BIDI_TYPE || stream_id > rfc::QUIC_VARINT_MAX {
        return emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_STREAM_CREATION);
    }
    let st_idx, _ = find_or_create_h3_stream(slot_idx, stream_id);
    let st .= g_h3_edge_streams[st_idx];
    if st.errored {
        return true;
    }
    if st.finished && data.len > 0 {
        return emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_FRAME_UNEXPECTED);
    }
    let end_flag = if fin { H3EdgeEndFlag.Fin } else { H3EdgeEndFlag.Open };
    return feed_bidi_stream_bytes(slot_idx, st_idx, data, end_flag);
}

fn reset_h3_uni_stream(slot_idx: i64, stream_id: u64) {
    let slot .= g_h3_edge_slots[slot_idx];
    let is_crit = (slot.has_peer_ctrl && slot.peer_ctrl_stream_id == stream_id)
        || (slot.has_peer_qenc && slot.peer_qenc_stream_id == stream_id)
        || (slot.has_peer_qdec && slot.peer_qdec_stream_id == stream_id);
    if is_crit {
        // RFC 9114 Section 6.2.1 & RFC 9204 Section 4.2: Critical uni streams MUST NOT close.
        let _ = emit_h3_protocol_error(slot_idx, stream_id, rfc::H3_ERR_CLOSED_CRITICAL_STREAM);
        return;
    }
    remove_ignored_uni_stream(slot, stream_id);
    let p_idx = find_pending_uni_idx(slot, stream_id);
    if p_idx >= 0 {
        slot.uni_pending[p_idx] = H3EdgeUniPending { .. };
    }
}

// Notifies the HTTP/3 edge session that QUIC stream `stream_id` was reset or stopped.
fn h3_edge_reset_stream(sess: H3EdgeSession&, stream_id: u64) {
    let slot_idx, ok = resolve_h3_edge_slot(sess);
    guard ok else { return; }
    let slot .= g_h3_edge_slots[slot_idx];
    if (stream_id & QUIC_STREAM_TYPE_MASK) == QUIC_CLIENT_UNI_TYPE {
        reset_h3_uni_stream(slot_idx, stream_id);
        return;
    }
    guard (stream_id & QUIC_STREAM_TYPE_MASK) == QUIC_CLIENT_BIDI_TYPE else { return; }
    var prev: i64 = -1;
    var curr = slot.stream_head;
    while curr >= 0 {
        if g_h3_edge_streams[curr].stream_id == stream_id {
            let st .= g_h3_edge_streams[curr];
            st.errored = true;
            st.finished = true;
            cleanup_h3_stream_resources(slot_idx, curr);
            unlink_h3_stream_node(slot, prev, curr);
            return;
        }
        prev = curr;
        curr = g_h3_edge_streams[curr].next_stream;
    }
}

// Polls the next queued HTTP/3 server event, returning false when empty.
fn h3_edge_poll_event(sess: H3EdgeSession&, out_ev: H3EdgeEvent&) -> bool {
    out_ev = H3EdgeEvent { .. };
    let slot_idx, ok = resolve_h3_edge_slot(sess);
    if !ok {
        return false;
    }
    let slot .= g_h3_edge_slots[slot_idx];
    if slot.ev_head < 0 {
        return false;
    }
    let ev_idx = slot.ev_head;
    let ev .= g_h3_edge_events[ev_idx];
    slot.ev_head = ev.next_ev;
    if slot.ev_head < 0 {
        slot.ev_tail = -1;
    }

    out_ev = H3EdgeEvent {
        kind:       ev.kind,
        stream_id:  ev.stream_id,
        end_stream: ev.end_stream,
        error_code: ev.error_code,
    };
    if ev.hdr_idx >= 0 {
        out_ev.headers = g_h3_edge_headers[ev.hdr_idx];
    }
    slot.ev_data_buf.clear();
    if ev.chunk_idx >= 0 {
        let _ = slot.ev_data_buf.try_append(g_h3_edge_chunks[ev.chunk_idx].buf[..]);
        out_ev.data = slot.ev_data_buf[..];
    }
    free_h3_event_node(ev_idx);
    return true;
}

fn is_forbidden_h3_resp_header(lower_name: const u8[:], val: const u8[:]) -> bool {
    if lower_name == "te" {
        return true;
    }
    return h3_internal::is_forbidden_connection_header(lower_name, val);
}

fn encode_edge_resp_header_entry(
    slot:               const H3EdgeSlot&,
    name:               const u8[:],
    val:                const u8[:],
    field_section_size: u64&,
    out_qpack:          u8[>..]&,
) -> bool {
    if name.len == 0 || name.len > 256 || name[0] == ':' {
        return false;
    }
    var lower_name: u8[..256] = [];
    name.to_lower_ascii(lower_name);
    if !validate_qpack_field_name(lower_name[..]) || !validate_qpack_field_val(val) {
        return false;
    }
    if is_forbidden_h3_resp_header(lower_name[..], val) {
        return false;
    }
    let name_val_len = core::add_sat_u64(lower_name.len as u64, val.len as u64);
    let line_cost = core::add_sat_u64(name_val_len, H3_EDGE_FIELD_OVERHEAD);
    field_section_size = core::add_sat_u64(field_section_size, line_cost);
    if slot.peer_settings_received && field_section_size > slot.peer_settings.max_field_section_size {
        return false;
    }
    return encode_qpack_field(out_qpack, lower_name[..], val, true);
}

// Encodes an HTTP/3 response HEADERS frame using QPACK static/literal compression.
fn h3_edge_encode_response_headers(
    sess:        H3EdgeSession&,
    status_code: i32,
    headers:     const http::HeaderMap&,
    out_wire:    u8[>..]&,
) -> bool {
    let slot_idx, ok = resolve_h3_edge_slot(sess);
    if !ok {
        return false;
    }
    let slot .= g_h3_edge_slots[slot_idx];
    // RFC 9114 Section 4.3.2: Response Pseudo-Header Fields - Reject status outside 100..599 and forbid 101.
    if slot.conn_failed
        || status_code < H3_EDGE_STATUS_MIN
        || status_code > H3_EDGE_STATUS_MAX
        || status_code == H3_EDGE_STATUS_SWITCHING_PROTOCOL
    {
        return false;
    }

    let saved_len = out_wire.len;
    var committed = false;
    defer if !committed {
        out_wire.resize(saved_len);
    };

    var status_buf: u8[..8] = [];
    (status_code as u32).format_u32_dec(status_buf);

    g_h3_resp_qpack_scratch.clear();
    // RFC 9204 Section 4.5: Field Line Representations - Static-only field section prefix (RIC=0, DeltaBase=0).
    g_h3_resp_qpack_scratch.push(0x00);
    g_h3_resp_qpack_scratch.push(0x00);
    guard encode_qpack_field(g_h3_resp_qpack_scratch, ":status", status_buf[..], true) else {
        return false;
    };

    var field_section_size = core::add_sat_u64(H3_EDGE_STATUS_FIELD_OVERHEAD, status_buf.len as u64);
    if slot.peer_settings_received && field_section_size > slot.peer_settings.max_field_section_size {
        return false;
    }
    for i in 0..headers.entries.len {
        let ent .= headers.entries[i];
        let name = http::entry_name(headers, ent);
        let val = http::entry_value(headers, ent);
        guard encode_edge_resp_header_entry(slot, name, val, field_section_size, g_h3_resp_qpack_scratch) else {
            return false;
        };
    }

    guard encode_headers_frame(out_wire, g_h3_resp_qpack_scratch[..]) else {
        return false;
    };
    committed = true;
    return true;
}

// Encodes an HTTP/3 DATA frame of arbitrary length (including > 4 KiB payloads).
fn h3_edge_encode_data_frame(data: const u8[:], out_wire: u8[>..]&) -> bool {
    if (data.len as u64) > rfc::QUIC_VARINT_MAX {
        return false;
    }
    let saved_len = out_wire.len;
    var committed = false;
    defer if !committed {
        out_wire.resize(saved_len);
    };
    guard encode_data_frame(out_wire, data) else {
        return false;
    };
    committed = true;
    return true;
}

// Encodes a server-to-client HTTP/3 GOAWAY frame for `last_stream_id`.
// RFC 9114 Section 5.2: Connection Shutdown - Server GOAWAY carries a client-initiated bidi stream ID.
fn h3_edge_encode_goaway(last_stream_id: u64, out_wire: u8[..32]&) -> bool {
    if (last_stream_id & QUIC_STREAM_TYPE_MASK) != QUIC_CLIENT_BIDI_TYPE || last_stream_id > rfc::QUIC_VARINT_MAX {
        return false;
    }
    let saved_len = out_wire.len;
    var committed = false;
    defer if !committed {
        out_wire.resize(saved_len);
    };
    guard encode_goaway_frame(out_wire, last_stream_id) else {
        return false;
    };
    committed = true;
    return true;
}
