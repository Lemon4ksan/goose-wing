// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Opt-in sans-IO HTTP/2 upstream client/multiplexer (RFC 9113, RFC 7541).
// Supports gRPC & Connect-RPC proxying, slow WAN stream fan-out, and
// full-duplex bidirectional HTTP/2 streaming over a pooled connection.
namespace proxy;

import core;
import rfc.http;
import rfc.h2;
import http.headers;
import http2.framing;
import http2.frames_internal;
import http2.hpack;
import http2.hpack_internal;
import http2.connection;
import http2.internal;
import grpc.constants;
import proxy.headers_internal;
import proxy.reverse_proxy;

// ---- Public Constants & Limits ---------------------------------------------

const H2_UP_INVALID_IDX:            i32 = -1;
const H2_UP_WIRE_IN_CAP:            i64 = 16393;
const H2_UP_WIRE_OUT_CAP:           i64 = 147456;
const H2_UP_HEADER_BLOCK_CAP:       i64 = 65536;
const H2_UP_MAX_CHUNK_DATA:         i64 = 16384;
const H2_UP_MIN_REPLENISH:          i64 = 16384;
const H2_UP_MAX_STREAMS_CAP:        u32 = 128;
const H2_UP_RST_RING_CAP:           i64 = 128;
const H2_UP_HPACK_NEVER_INDEX_MASK: u8  = 0xF0;
const H2_UP_HPACK_NEVER_INDEX_TAG:  u8  = 0x10;
const H2_UP_ERR_LEN:                i64 = 4;
const H2_UP_GOAWAY_LEN:             i64 = 8;
const H2_UP_PING_LEN:               i64 = 8;
const H2_UP_RST_WIRE_LEN:           i64 = 13;
const H2_UP_PING_WIRE_LEN:          i64 = 17;
const H2_UP_GOAWAY_WIRE_LEN:        i64 = 17;
const H2_UP_SETTINGS_PAIR_LEN:      i64 = 6;
const H2_UP_PRIORITY_LEN:           i64 = 5;
const H2_UP_MAX_SID:                u32 = 0x7FFFFFFF;
const H2_UP_DEF_HDR_LIST:           u32 = 65536;
const H2_UP_HEADER_OVERHEAD_I64:    i64 = 32;
const H2_UP_PSEUDO_METHOD_BASE:     i64 = 39;
const H2_UP_PSEUDO_SCHEME_BASE:     i64 = 39;
const H2_UP_PSEUDO_PATH_BASE:       i64 = 37;
const H2_UP_PSEUDO_AUTH_BASE:       i64 = 42;
const H2_UP_TE_TRAILERS_SIZE:       i64 = 42;

// ---- Public Types ----------------------------------------------------------

enum H2UpstreamTransport {
    H2Tls,
    H2c,
}

enum H2UpstreamStreamEnd {
    OpenBody,
    EndStream,
}

enum H2UpstreamHeaderFilter {
    ApplyProxyFilters,
    DirectHeaders,
}

enum H2UpstreamEventKind {
    None,
    ResponseHead,
    ResponseData,
    ResponseTrailers,
    ResponseEnd,
    StreamReset,
    GoAway,
    PingAck,
    ProtocolError,
}

struct H2UpstreamConfig {
    // Expected transport (validated via h2_upstream_validate_alpn).
    transport:              H2UpstreamTransport = H2UpstreamTransport.H2Tls,
    initial_window_size:    u32                 = rfc::H2_DEFAULT_WINDOW_SIZE,
    max_concurrent_streams: u32                 = 128,
    // Local SETTINGS_MAX_FRAME_SIZE (bounded to 16384 to fit chunk buffers).
    max_frame_size:       u32    = rfc::H2_DEFAULT_MAX_FRAME_SIZE,
    max_header_list_size: u32    = H2_UP_DEF_HDR_LIST,
    send_proxy_config:    Config = Config { .. },
}

struct H2UpstreamEvent {
    kind:           H2UpstreamEventKind = H2UpstreamEventKind.None,
    stream_id:      u32                 = 0,
    status_code:    i32                 = 0,
    headers:        http::HeaderMap     = http::HeaderMap { .. },
    data:           const u8[:]         = "",
    end_stream:     bool                = false,
    error_code:     u32                 = 0,
    last_stream_id: u32                 = 0,
    opaque_data:    u8[8]               = [0; 8],
}

struct H2UpstreamSession {
    slot_idx:   i64 = -1,
    generation: u64 = 0,
}

// ---- Thread-Local Pools ----------------------------------------------------

struct H2UpEventNode {
    kind:           H2UpstreamEventKind = H2UpstreamEventKind.None,
    stream_id:      u32                 = 0,
    status_code:    i32                 = 0,
    hdr_idx:        i32                 = H2_UP_INVALID_IDX,
    chunk_idx:      i32                 = H2_UP_INVALID_IDX,
    end_stream:     bool                = false,
    error_code:     u32                 = 0,
    last_stream_id: u32                 = 0,
    opaque_data:    u8[8]               = [0; 8],
    next_idx:       i32                 = H2_UP_INVALID_IDX,
}

struct H2UpDataChunk {
    len:      i64       = 0,
    data:     u8[16384] = [0; 16384],
    next_idx: i32       = H2_UP_INVALID_IDX,
}

struct H2UpHeaderNode {
    hdr:      http::HeaderMap = http::HeaderMap { .. },
    next_idx: i32             = H2_UP_INVALID_IDX,
}

struct H2UpSlot {
    active:                      bool                = false,
    generation:                  u64                 = 0,
    free_next:                   i64                 = -1,
    cfg:                         H2UpstreamConfig    = H2UpstreamConfig { .. },
    conn:                        http2::Connection   = http2::new_h2_connection(0, H2_UP_DEF_HDR_LIST, false),
    peer_max_concurrent_streams: u32                 = 128,
    peer_max_frame_size:         u32                 = rfc::H2_DEFAULT_MAX_FRAME_SIZE,
    peer_max_header_list_size:   u32                 = H2_UP_DEF_HDR_LIST,
    peer_header_table_size:      u32                 = rfc::HPACK_DEFAULT_MAX_DYN_SIZE as u32,
    next_client_sid:             u32                 = 1,
    last_local_sid:              u32                 = 0,
    sent_goaway_last_sid:        u32                 = 0,
    local_goaway_sent:           bool                = false,
    protocol_failed:             bool                = false,
    empty_data_streak:           u32                 = 0,
    hpack_enc:                   http2::DynamicTable = http2::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
    hpack_dec:                   http2::DynamicTable = http2::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
    hpack_enc_pending_sz_update: bool                = false,
    hpack_enc_min_sz:            u64                 = rfc::HPACK_DEFAULT_MAX_DYN_SIZE,
    stream_ids:                  u32[128]            = [0; 128],
    stream_is_head:              u8[128]             = [0; 128],
    stream_unclaimed_id:         u32[128]            = [0; 128],
    stream_unclaimed_rx:         i64[128]            = [0; 128],
    local_rst_ring:              u32[128]            = [0; 128],
    local_rst_head:              i64                 = 0,
    wire_in:                     u8[..16393]         = [],
    wire_out:                    u8[..147456]        = [],
    ev_data_buf:                 u8[16384]           = [0; 16384],
    in_cont:                     bool                = false,
    cont_stream_id:              u32                 = 0,
    cont_end_stream:             bool                = false,
    cont_count:                  u32                 = 0,
    header_accum:                u8[..65536]         = [],
    ev_head:                     i32                 = H2_UP_INVALID_IDX,
    ev_tail:                     i32                 = H2_UP_INVALID_IDX,
}

var g_h2_up_slots:      H2UpSlot[>..]       = [];
var g_h2_up_free_slot:  i64                 = -1;
var g_h2_up_next_gen:   u64                 = 1;
var g_h2_up_events:     H2UpEventNode[>..]  = [];
var g_h2_up_free_ev:    i32                 = H2_UP_INVALID_IDX;
var g_h2_up_headers:    H2UpHeaderNode[>..] = [];
var g_h2_up_free_hdr:   i32                 = H2_UP_INVALID_IDX;
var g_h2_up_chunks:     H2UpDataChunk[>..]  = [];
var g_h2_up_free_chunk: i32                 = H2_UP_INVALID_IDX;

// ---- Pool & Slot Helpers ---------------------------------------------------

fn resolve_up_slot_idx(sess: const H2UpstreamSession&) -> i64 {
    if sess.slot_idx < 0 || sess.slot_idx >= g_h2_up_slots.len || sess.generation == 0 {
        return -1;
    }
    let slot .= g_h2_up_slots[sess.slot_idx];
    if !slot.active || slot.generation != sess.generation {
        return -1;
    }
    return sess.slot_idx;
}

fn alloc_up_event(kind: H2UpstreamEventKind, sid: u32) -> i32 {
    if g_h2_up_free_ev != H2_UP_INVALID_IDX {
        let idx = g_h2_up_free_ev;
        let node .= g_h2_up_events[idx];
        g_h2_up_free_ev = node.next_idx;
        node = H2UpEventNode { kind: kind, stream_id: sid, .. };
        return idx;
    }
    let idx = g_h2_up_events.len as i32;
    g_h2_up_events.push(H2UpEventNode { kind: kind, stream_id: sid, .. });
    return idx;
}

fn alloc_up_hdr() -> i32 {
    if g_h2_up_free_hdr != H2_UP_INVALID_IDX {
        let idx = g_h2_up_free_hdr;
        let node .= g_h2_up_headers[idx];
        g_h2_up_free_hdr = node.next_idx;
        node = H2UpHeaderNode { .. };
        return idx;
    }
    let idx = g_h2_up_headers.len as i32;
    g_h2_up_headers.push(H2UpHeaderNode { .. });
    return idx;
}

fn recycle_up_hdr(hdr_idx: i32) {
    if hdr_idx < 0 || hdr_idx >= (g_h2_up_headers.len as i32) {
        return;
    }
    let node .= g_h2_up_headers[hdr_idx];
    core::secure_zeroize_slice(node.hdr.raw_buf[..]);
    node.hdr = http::HeaderMap { .. };
    node.next_idx = g_h2_up_free_hdr;
    g_h2_up_free_hdr = hdr_idx;
}

fn alloc_up_chunk(data: const u8[:]) -> i32 {
    if data.len > H2_UP_MAX_CHUNK_DATA {
        return H2_UP_INVALID_IDX;
    }
    var idx = g_h2_up_free_chunk;
    if idx != H2_UP_INVALID_IDX {
        g_h2_up_free_chunk = g_h2_up_chunks[idx].next_idx;
    } else {
        idx = g_h2_up_chunks.len as i32;
        g_h2_up_chunks.push(H2UpDataChunk { .. });
    }
    let ch .= g_h2_up_chunks[idx];
    ch.next_idx = H2_UP_INVALID_IDX;
    ch.len = data.len;
    for i in data.len {
        ch.data[i] = data[i];
    }
    return idx;
}

fn recycle_up_chunk(chunk_idx: i32) {
    if chunk_idx < 0 || chunk_idx >= (g_h2_up_chunks.len as i32) {
        return;
    }
    let ch .= g_h2_up_chunks[chunk_idx];
    if ch.len > 0 && ch.len <= H2_UP_MAX_CHUNK_DATA {
        core::secure_zeroize_slice(ch.data[..ch.len]);
    }
    ch.len = 0;
    ch.next_idx = g_h2_up_free_chunk;
    g_h2_up_free_chunk = chunk_idx;
}

fn recycle_up_event_node(ev_idx: i32) {
    if ev_idx < 0 || ev_idx >= (g_h2_up_events.len as i32) {
        return;
    }
    let node .= g_h2_up_events[ev_idx];
    if node.hdr_idx != H2_UP_INVALID_IDX {
        recycle_up_hdr(node.hdr_idx);
        node.hdr_idx = H2_UP_INVALID_IDX;
    }
    if node.chunk_idx != H2_UP_INVALID_IDX {
        recycle_up_chunk(node.chunk_idx);
        node.chunk_idx = H2_UP_INVALID_IDX;
    }
    node.kind = H2UpstreamEventKind.None;
    node.next_idx = g_h2_up_free_ev;
    g_h2_up_free_ev = ev_idx;
}

fn push_up_event(slot: H2UpSlot&, ev_idx: i32) {
    let node .= g_h2_up_events[ev_idx];
    node.next_idx = H2_UP_INVALID_IDX;
    if slot.ev_head == H2_UP_INVALID_IDX {
        slot.ev_head = ev_idx;
        slot.ev_tail = ev_idx;
        return;
    }
    g_h2_up_events[slot.ev_tail].next_idx = ev_idx;
    slot.ev_tail = ev_idx;
}

fn emit_up_frame(
    slot:       H2UpSlot&,
    frame_type: u8,
    flags:      u8,
    stream_id:  u32,
    payload:    const u8[:],
) -> bool {
    let need = core::add_sat_i64(rfc::H2_FRAME_HEADER_LEN, payload.len);
    if core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len) < need {
        return false;
    }
    let saved_len = slot.wire_out.len;
    let fh = http2::FrameHeader {
        length:     payload.len as u32,
        frame_type: frame_type,
        flags:      flags,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(fh, slot.wire_out);
    if payload.len > 0 && !slot.wire_out.try_append(payload) {
        slot.wire_out.resize(saved_len);
        return false;
    }
    return true;
}

fn append_setting_pair(buf: u8[..32]&, id: u16, val: u32) {
    buf.append_u16_be(id);
    buf.append_u32_be(val);
}

// RFC 9113 Section 3.4: HTTP/2 Connection Preface - emit client preface and initial SETTINGS.
fn emit_up_initial_preface(slot: H2UpSlot&) -> bool {
    guard slot.wire_out.try_append(rfc::H2_CLIENT_PREFACE[..]) else {
        return false;
    }
    var params: u8[..32] = [];
    // RFC 9113 Section 6.5.2: Defined Settings - disable server push with ENABLE_PUSH = 0.
    append_setting_pair(params, rfc::H2_SETTING_ENABLE_PUSH, 0);
    append_setting_pair(params, rfc::H2_SETTING_MAX_CONCURRENT_STREAMS, slot.cfg.max_concurrent_streams);
    append_setting_pair(params, rfc::H2_SETTING_INITIAL_WINDOW_SIZE, slot.cfg.initial_window_size);
    append_setting_pair(params, rfc::H2_SETTING_MAX_FRAME_SIZE, slot.cfg.max_frame_size);
    append_setting_pair(params, rfc::H2_SETTING_MAX_HEADER_LIST_SIZE, slot.cfg.max_header_list_size);
    return emit_up_frame(slot, rfc::H2_FRAME_SETTINGS, 0, 0, params[..]);
}

fn emit_up_goaway_wire(slot: H2UpSlot&, error_code: u32) -> bool {
    if core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len) < H2_UP_GOAWAY_WIRE_LEN {
        return false;
    }
    var p: u8[..8] = [];
    p.append_u32_be(slot.sent_goaway_last_sid & H2_UP_MAX_SID);
    p.append_u32_be(error_code);
    return emit_up_frame(slot, rfc::H2_FRAME_GOAWAY, 0, 0, p[..]);
}

fn fail_up_conn(slot: H2UpSlot&, error_code: u32) -> bool {
    if !slot.protocol_failed {
        slot.protocol_failed = true;
        if !slot.local_goaway_sent {
            slot.local_goaway_sent = true;
            let _ = emit_up_goaway_wire(slot, error_code);
        }
        let ev_idx = alloc_up_event(H2UpstreamEventKind.ProtocolError, 0);
        g_h2_up_events[ev_idx].error_code = error_code;
        push_up_event(slot, ev_idx);
    }
    return false;
}

fn clamp_up_config(raw: const H2UpstreamConfig&) -> H2UpstreamConfig {
    var out = raw;
    if out.initial_window_size > rfc::H2_MAX_WINDOW_SIZE {
        out.initial_window_size = rfc::H2_MAX_WINDOW_SIZE;
    }
    out.max_concurrent_streams = clamp(out.max_concurrent_streams, 1, H2_UP_MAX_STREAMS_CAP);
    out.max_frame_size = rfc::H2_DEFAULT_MAX_FRAME_SIZE;
    if out.max_header_list_size == 0 {
        out.max_header_list_size = H2_UP_DEF_HDR_LIST;
    }
    return out;
}

fn wipe_up_slot_buffers(slot: H2UpSlot&) {
    let _ = http2::update_dynamic_table_max_size(slot.hpack_enc, 0);
    let _ = http2::update_dynamic_table_max_size(slot.hpack_dec, 0);
    core::secure_zeroize_slice(slot.hpack_enc.arena[..]);
    core::secure_zeroize_slice(slot.hpack_dec.arena[..]);
    core::secure_zeroize_slice(slot.wire_in[..]);
    core::secure_zeroize_slice(slot.wire_out[..]);
    core::secure_zeroize_slice(slot.header_accum[..]);
    core::secure_zeroize_slice(slot.ev_data_buf[..]);
    slot.wire_in.clear();
    slot.wire_out.clear();
    slot.header_accum.clear();
}

fn reset_up_slot(slot: H2UpSlot&, raw_cfg: const H2UpstreamConfig&, gen: u64) {
    let cfg = clamp_up_config(raw_cfg);
    slot.active = true;
    slot.generation = gen;
    slot.free_next = -1;
    slot.cfg = cfg;
    slot.conn = http2::new_h2_connection(0, cfg.max_header_list_size, false);
    slot.conn.is_server = false;
    slot.conn.enable_push = false;
    slot.conn.local_max_frame_size = cfg.max_frame_size;
    slot.peer_max_concurrent_streams = H2_UP_MAX_STREAMS_CAP;
    slot.peer_max_frame_size = rfc::H2_DEFAULT_MAX_FRAME_SIZE;
    slot.peer_max_header_list_size = cfg.max_header_list_size;
    slot.peer_header_table_size = rfc::HPACK_DEFAULT_MAX_DYN_SIZE as u32;
    slot.next_client_sid = 1;
    slot.last_local_sid = 0;
    slot.sent_goaway_last_sid = 0;
    slot.local_goaway_sent = false;
    slot.protocol_failed = false;
    slot.empty_data_streak = 0;
    slot.hpack_enc_pending_sz_update = false;
    slot.hpack_enc_min_sz = rfc::HPACK_DEFAULT_MAX_DYN_SIZE;
    slot.local_rst_head = 0;
    slot.in_cont = false;
    slot.cont_stream_id = 0;
    slot.cont_end_stream = false;
    slot.cont_count = 0;
    slot.ev_head = H2_UP_INVALID_IDX;
    slot.ev_tail = H2_UP_INVALID_IDX;
    for i in 128 {
        slot.stream_ids[i] = 0;
        slot.stream_is_head[i] = 0;
        slot.stream_unclaimed_id[i] = 0;
        slot.stream_unclaimed_rx[i] = 0;
        slot.local_rst_ring[i] = 0;
    }
    wipe_up_slot_buffers(slot);
    slot.hpack_enc = http2::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    slot.hpack_dec = http2::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
}

// ---- Lifecycle & Wire Drain API --------------------------------------------

// Opens a pooled upstream HTTP/2 client session and queues client connection preface + SETTINGS.
fn h2_upstream_open(cfg: H2UpstreamConfig) -> H2UpstreamSession {
    var slot_idx: i64 = -1;
    if g_h2_up_free_slot >= 0 {
        slot_idx = g_h2_up_free_slot;
        g_h2_up_free_slot = g_h2_up_slots[slot_idx].free_next;
    } else {
        slot_idx = g_h2_up_slots.len;
        g_h2_up_slots.push(H2UpSlot { .. });
    }
    var gen = g_h2_up_next_gen;
    if gen == 0 {
        gen = 1;
    }
    g_h2_up_next_gen = gen + 1;
    if g_h2_up_next_gen == 0 {
        g_h2_up_next_gen = 1;
    }
    let slot .= g_h2_up_slots[slot_idx];
    reset_up_slot(slot, cfg, gen);
    let _ = emit_up_initial_preface(slot);
    return H2UpstreamSession { slot_idx: slot_idx, generation: gen };
}

// Idempotently closes an upstream session, wiping sensitive state and recycling pooled nodes.
fn h2_upstream_close(sess: H2UpstreamSession&) {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        sess.slot_idx = -1;
        sess.generation = 0;
        return;
    }
    let slot .= g_h2_up_slots[slot_idx];
    var cur = slot.ev_head;
    while cur != H2_UP_INVALID_IDX {
        let nxt = g_h2_up_events[cur].next_idx;
        recycle_up_event_node(cur);
        cur = nxt;
    }
    slot.ev_head = H2_UP_INVALID_IDX;
    slot.ev_tail = H2_UP_INVALID_IDX;
    wipe_up_slot_buffers(slot);
    slot.active = false;
    slot.generation = 0;
    slot.free_next = g_h2_up_free_slot;
    g_h2_up_free_slot = slot_idx;
    sess.slot_idx = -1;
    sess.generation = 0;
}

// Polls the next buffered upstream event into `out_ev`, releasing internal pool resources.
fn h2_upstream_poll_event(sess: H2UpstreamSession&, out_ev: H2UpstreamEvent&) -> bool {
    out_ev = H2UpstreamEvent { .. };
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    if slot.ev_head == H2_UP_INVALID_IDX {
        return false;
    }
    let ev_idx = slot.ev_head;
    let node .= g_h2_up_events[ev_idx];
    slot.ev_head = node.next_idx;
    if slot.ev_head == H2_UP_INVALID_IDX {
        slot.ev_tail = H2_UP_INVALID_IDX;
    }
    out_ev.kind = node.kind;
    out_ev.stream_id = node.stream_id;
    out_ev.status_code = node.status_code;
    out_ev.end_stream = node.end_stream;
    out_ev.error_code = node.error_code;
    out_ev.last_stream_id = node.last_stream_id;
    out_ev.opaque_data = node.opaque_data;
    if node.hdr_idx != H2_UP_INVALID_IDX {
        out_ev.headers = g_h2_up_headers[node.hdr_idx].hdr;
    }
    if node.chunk_idx != H2_UP_INVALID_IDX {
        let ch .= g_h2_up_chunks[node.chunk_idx];
        if ch.len > 0 && ch.len <= H2_UP_MAX_CHUNK_DATA {
            for i in ch.len {
                slot.ev_data_buf[i] = ch.data[i];
            }
            out_ev.data = slot.ev_data_buf[..ch.len];
        }
    }
    recycle_up_event_node(ev_idx);
    return true;
}

// Drains queued outbound HTTP/2 wire bytes into `out`, returning the byte count transferred.
fn h2_upstream_drain_wire(sess: H2UpstreamSession&, out: u8[>..]&) -> i64 {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return 0;
    }
    let slot .= g_h2_up_slots[slot_idx];
    let n = slot.wire_out.len;
    if n == 0 {
        return 0;
    }
    out.append(slot.wire_out[..n]);
    slot.wire_out.clear();
    return n;
}

fn h2_upstream_can_open_stream(sess: const H2UpstreamSession&) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    if slot.protocol_failed || slot.local_goaway_sent || slot.conn.goaway_received {
        return false;
    }
    if slot.next_client_sid > H2_UP_MAX_SID {
        return false;
    }
    let active = slot.conn.active_stream_count;
    if active >= slot.peer_max_concurrent_streams || active >= slot.cfg.max_concurrent_streams {
        return false;
    }
    return active < H2_UP_MAX_STREAMS_CAP;
}

fn h2_upstream_active_streams(sess: const H2UpstreamSession&) -> u32 {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return 0;
    }
    return g_h2_up_slots[slot_idx].conn.active_stream_count;
}

fn h2_upstream_is_draining(sess: const H2UpstreamSession&) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return true;
    }
    let slot .= g_h2_up_slots[slot_idx];
    return slot.conn.goaway_received || slot.local_goaway_sent || slot.protocol_failed;
}

// Validates the negotiated ALPN token against the session's configured H2UpstreamTransport.
fn h2_upstream_validate_alpn(sess: const H2UpstreamSession&, alpn: const u8[:]) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let transport = g_h2_up_slots[slot_idx].cfg.transport;
    if transport == H2UpstreamTransport.H2Tls {
        return alpn == "h2";
    }
    return alpn.len == 0 || alpn == "h2c";
}

// ---- Stream Allocation & Reset Ring Helpers --------------------------------

fn record_local_rst_sid(slot: H2UpSlot&, sid: u32) {
    let head = slot.local_rst_head & 127;
    slot.local_rst_ring[head] = sid;
    slot.local_rst_head = core::add_sat_i64(head, 1) & 127;
}

fn is_in_local_rst_ring(slot: const H2UpSlot&, sid: u32) -> bool {
    for i in H2_UP_RST_RING_CAP {
        if slot.local_rst_ring[i] == sid {
            return true;
        }
    }
    return false;
}

fn clear_up_stream_meta(slot: H2UpSlot&, s_idx: i64) {
    if s_idx >= 0 && s_idx < 128 {
        slot.stream_ids[s_idx] = 0;
        slot.stream_is_head[s_idx] = 0;
        slot.stream_unclaimed_id[s_idx] = 0;
        slot.stream_unclaimed_rx[s_idx] = 0;
    }
}

fn open_up_client_stream(slot: H2UpSlot&, sid: u32, end_stream: bool) -> i32, bool {
    let _, exists = http2::find_stream_idx(slot.conn, sid);
    guard !exists && slot.conn.active_stream_count < H2_UP_MAX_STREAMS_CAP else {
        return -1, false;
    }
    http2::open_stream(slot.conn, sid, false);
    let s_idx, found = http2::find_stream_idx(slot.conn, sid);
    guard found && s_idx >= 0 else {
        return -1, false;
    }
    let st .= slot.conn.streams[s_idx];
    st.state = if end_stream { http2::StreamState.HalfClosedLocal } else { http2::StreamState.Open };
    st.headers_received = false;
    st.trailers_received = false;
    st.status_code = 0;
    st.declared_content_length = -1;
    st.received_data_bytes = 0;
    st.recv_window = slot.cfg.initial_window_size;
    slot.last_local_sid = sid;
    slot.conn.last_local_stream_id = sid;
    slot.stream_ids[s_idx] = sid;
    slot.stream_unclaimed_id[s_idx] = sid;
    slot.stream_unclaimed_rx[s_idx] = 0;
    return s_idx, true;
}

fn close_up_streams_above(slot: H2UpSlot&, last_sid: u32) {
    for i in 128 {
        let sid = slot.stream_ids[i];
        if sid != 0 && sid > last_sid {
            let s_idx, found = http2::find_stream_idx(slot.conn, sid);
            clear_up_stream_meta(slot, i);
            if found && s_idx >= 0 {
                http2::close_local_stream(slot.conn, sid);
                http2::reset_stream(slot.conn, sid);
            }
        }
    }
}

// ---- Request Validation, Proxy Filtering & HPACK Encoding ------------------

fn validate_up_request_target(
    method:    const u8[:],
    scheme:    const u8[:],
    authority: const u8[:],
    path:      const u8[:],
) -> bool {
    guard h2_internal::is_valid_h2_token(method) else {
        return false;
    }
    if method == "CONNECT" {
        return h2_internal::is_valid_connect_authority(authority);
    }
    if path == "*" && method != "OPTIONS" {
        return false;
    }
    guard http2::is_valid_scheme(scheme) && http2::is_valid_path(path) else {
        return false;
    }
    if authority.len > 0 && !http2::is_valid_authority(authority) {
        return false;
    }
    return true;
}

fn has_sensitive_in_map(hdrs: const http::HeaderMap&, lower_name: const u8[:]) -> bool {
    for &e in hdrs.entries {
        if http::is_sensitive(e) && http::entry_name(hdrs, e).eq_ascii_fold(lower_name) {
            return true;
        }
    }
    return false;
}

fn validate_incoming_req_headers(hdrs: const http::HeaderMap&) -> bool {
    for &e in hdrs.entries {
        let name = http::entry_name(hdrs, e);
        let val = http::entry_value(hdrs, e);
        guard name.len > 0 && name[0] != ':' else {
            return false;
        }
        var low_buf: u8[..256] = [];
        guard name.len <= 256 else {
            return false;
        }
        name.to_lower_ascii(low_buf);
        guard http2::validate_field_syntax(low_buf[..], val) else {
            return false;
        }
        if low_buf[..] == "te" {
            let trimmed = val.trim_lws();
            guard trimmed.eq_ascii_fold("trailers") else {
                return false;
            }
        }
    }
    return true;
}

fn should_skip_h2_req_header(
    raw_hdrs:  const http::HeaderMap&,
    low_name:  const u8[:],
    authority: const u8[:],
) -> bool {
    if authority.len > 0 && low_name == "host" {
        return true;
    }
    if low_name == "te" {
        return true;
    }
    if h2_internal::is_forbidden_h2_hop_by_hop(low_name) {
        return true;
    }
    return http::is_token_in_connection_header_map(raw_hdrs, low_name);
}

fn calc_up_request_list_size(
    method:    const u8[:],
    scheme:    const u8[:],
    authority: const u8[:],
    path:      const u8[:],
    src_hdrs:  const http::HeaderMap&,
    raw_hdrs:  const http::HeaderMap&,
) -> i64 {
    var total = core::add_sat_i64(H2_UP_PSEUDO_METHOD_BASE, method.len);
    if method != "CONNECT" {
        total = core::add_sat_i64(total, core::add_sat_i64(H2_UP_PSEUDO_SCHEME_BASE, scheme.len));
        total = core::add_sat_i64(total, core::add_sat_i64(H2_UP_PSEUDO_PATH_BASE, path.len));
    }
    if authority.len > 0 {
        total = core::add_sat_i64(total, core::add_sat_i64(H2_UP_PSEUDO_AUTH_BASE, authority.len));
    }
    for &e in src_hdrs.entries {
        let raw_name = http::entry_name(src_hdrs, e);
        var low_buf: u8[..256] = [];
        raw_name.to_lower_ascii(low_buf);
        if !should_skip_h2_req_header(src_hdrs, low_buf[..], authority) {
            let v = http::entry_value(src_hdrs, e);
            let field_sz = core::add_sat_i64(low_buf.len, v.len);
            total = core::add_sat_i64(total, core::add_sat_i64(H2_UP_HEADER_OVERHEAD_I64, field_sz));
        }
    }
    if http::has_header(raw_hdrs, "te") {
        total = core::add_sat_i64(total, H2_UP_TE_TRAILERS_SIZE);
    }
    return total;
}

fn encode_up_request_entries(
    enc:       http2::DynamicTable&,
    src_hdrs:  const http::HeaderMap&,
    raw_hdrs:  const http::HeaderMap&,
    authority: const u8[:],
    out:       u8[..65536]&,
) -> bool {
    let max_tbl = enc.current_max_size as i64;
    for &e in src_hdrs.entries {
        let raw_name = http::entry_name(src_hdrs, e);
        let val = http::entry_value(src_hdrs, e);
        var low_buf: u8[..256] = [];
        guard raw_name.len <= 256 else {
            return false;
        }
        raw_name.to_lower_ascii(low_buf);
        let low_name = low_buf[..];
        if should_skip_h2_req_header(src_hdrs, low_name, authority) {
            continue;
        }
        let sens = http::is_sensitive(e)
            || has_sensitive_in_map(raw_hdrs, low_name)
            || http::is_heuristic_sensitive_header(low_name);
        // RFC 7541 Section 6.2.3: Literal Header Field Never Indexed - enforce NeverIndexed for sensitive fields.
        let mode = if sens {
            http2::HpackIndexing.NeverIndexed
        } else {
            http2::select_hpack_indexing(low_name, val, max_tbl)
        };
        guard http2::encode_hpack_field(enc, out, low_name, val, mode, true) else {
            return false;
        }
    }
    // RFC 9113 Section 8.2.2: Connection-Specific Header Fields - preserve lowercase `te: trailers` for gRPC.
    if http::has_header(raw_hdrs, "te") {
        let mode = http2::select_hpack_indexing("te", "trailers", max_tbl);
        guard http2::encode_hpack_field(enc, out, "te", "trailers", mode, true) else {
            return false;
        }
    }
    return true;
}

// RFC 7541 Section 6.3: Dynamic Table Size Update - emit pending encoder size transitions before fields.
fn emit_up_hpack_table_updates(slot: H2UpSlot&, out: u8[..65536]&) -> bool {
    if !slot.hpack_enc_pending_sz_update {
        return true;
    }
    let target_sz = slot.hpack_enc.current_max_size;
    if slot.hpack_enc_min_sz < target_sz {
        guard http2::hpack_encode_int(out, slot.hpack_enc_min_sz, 5, 0x20) else {
            return false;
        }
    }
    guard http2::hpack_encode_int(out, target_sz, 5, 0x20) else {
        return false;
    }
    slot.hpack_enc_pending_sz_update = false;
    slot.hpack_enc_min_sz = target_sz;
    return true;
}

fn encode_up_request_block(
    enc:       http2::DynamicTable&,
    method:    const u8[:],
    scheme:    const u8[:],
    authority: const u8[:],
    path:      const u8[:],
    src_hdrs:  const http::HeaderMap&,
    raw_hdrs:  const http::HeaderMap&,
    out:       u8[..65536]&,
) -> bool {
    guard http2::encode_hpack_field(enc, out, ":method", method, http2::HpackIndexing.Incremental, true) else {
        return false;
    }
    if method != "CONNECT" {
        guard http2::encode_hpack_field(enc, out, ":scheme", scheme, http2::HpackIndexing.Incremental, true) else {
            return false;
        }
    }
    if authority.len > 0 {
        guard http2::encode_hpack_field(
            enc,
            out,
            ":authority",
            authority,
            http2::HpackIndexing.Incremental,
            true,
        ) else {
            return false;
        }
    }
    if method != "CONNECT" {
        guard http2::encode_hpack_field(enc, out, ":path", path, http2::HpackIndexing.Incremental, true) else {
            return false;
        }
    }
    return encode_up_request_entries(enc, src_hdrs, raw_hdrs, authority, out);
}

// RFC 9113 Section 6.2: HEADERS - fragment encoded header blocks into HEADERS and CONTINUATION frames.
fn emit_up_header_fragments(
    slot:        H2UpSlot&,
    sid:         u32,
    hpack_bytes: const u8[:],
    end_stream:  bool,
) -> bool {
    let saved_len = slot.wire_out.len;
    var committed = false;
    defer if !committed {
        slot.wire_out.resize(saved_len);
    };
    let max_frag = slot.peer_max_frame_size as i64;
    var off: i64 = 0;
    var first = true;
    while first || off < hpack_bytes.len {
        let rem = core::sub_sat_i64(hpack_bytes.len, off);
        let frag_len = min(rem, max_frag);
        let next_off = core::add_sat_i64(off, frag_len);
        let is_last = (next_off == hpack_bytes.len);
        let ftype = if first { rfc::H2_FRAME_HEADERS } else { rfc::H2_FRAME_CONTINUATION };
        var flags: u8 = 0;
        if first && end_stream {
            flags |= rfc::H2_FLAG_END_STREAM;
        }
        if is_last {
            flags |= rfc::H2_FLAG_END_HEADERS;
        }
        guard emit_up_frame(slot, ftype, flags, sid, hpack_bytes[off..next_off]) else {
            return false;
        }
        off = next_off;
        first = false;
    }
    committed = true;
    return true;
}

fn open_up_stream_with_hdrs(
    slot:       H2UpSlot&,
    sid:        u32,
    method:     const u8[:],
    scheme:     const u8[:],
    authority:  const u8[:],
    path:       const u8[:],
    src_hdrs:   const http::HeaderMap&,
    raw_hdrs:   const http::HeaderMap&,
    end_stream: bool,
) -> u32, bool {
    let max_list: i64 = min(slot.peer_max_header_list_size, slot.cfg.max_header_list_size);
    guard calc_up_request_list_size(method, scheme, authority, path, src_hdrs, raw_hdrs) <= max_list else {
        return 0, false;
    }
    let saved_enc = slot.hpack_enc;
    let saved_pending = slot.hpack_enc_pending_sz_update;
    let saved_min_sz = slot.hpack_enc_min_sz;
    let saved_wire = slot.wire_out.len;
    var hpack_buf: u8[..65536] = [];
    var committed = false;
    defer if !committed {
        slot.hpack_enc = saved_enc;
        slot.hpack_enc_pending_sz_update = saved_pending;
        slot.hpack_enc_min_sz = saved_min_sz;
        slot.wire_out.resize(saved_wire);
    };
    guard emit_up_hpack_table_updates(slot, hpack_buf) else {
        return 0, false;
    }
    guard encode_up_request_block(
        slot.hpack_enc,
        method,
        scheme,
        authority,
        path,
        src_hdrs,
        raw_hdrs,
        hpack_buf,
    ) else {
        return 0, false;
    }
    guard emit_up_header_fragments(slot, sid, hpack_buf[..], end_stream) else {
        return 0, false;
    }
    let s_idx, ok_open = open_up_client_stream(slot, sid, end_stream);
    guard ok_open else {
        return 0, false;
    }
    slot.next_client_sid = core::add_sat_u32(slot.next_client_sid, 2);
    slot.stream_is_head[s_idx] = if method == "HEAD" { 1 } else { 0 };
    committed = true;
    return sid, true;
}

// Opens a client-initiated odd stream, applies proxy filtering, and encodes HEADERS/CONTINUATION.
fn h2_upstream_open_stream(
    sess:          H2UpstreamSession&,
    method:        const u8[:],
    scheme:        const u8[:],
    authority:     const u8[:],
    path:          const u8[:],
    in_headers:    const http::HeaderMap&,
    client_ip:     const u8[:],
    stream_end:    H2UpstreamStreamEnd    = H2UpstreamStreamEnd.OpenBody,
    header_filter: H2UpstreamHeaderFilter = H2UpstreamHeaderFilter.ApplyProxyFilters,
) -> u32, bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return 0, false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    guard !slot.protocol_failed && !slot.local_goaway_sent && !slot.conn.goaway_received else {
        return 0, false;
    }
    let sid = slot.next_client_sid;
    guard sid <= H2_UP_MAX_SID && (sid & 1) == 1 else {
        return 0, false;
    }
    let active = slot.conn.active_stream_count;
    guard active < slot.peer_max_concurrent_streams && active < slot.cfg.max_concurrent_streams else {
        return 0, false;
    }
    guard validate_up_request_target(method, scheme, authority, path) else {
        return 0, false;
    }
    guard validate_incoming_req_headers(in_headers) else {
        return 0, false;
    }
    let end_stream = (stream_end == H2UpstreamStreamEnd.EndStream);
    if header_filter == H2UpstreamHeaderFilter.DirectHeaders {
        return open_up_stream_with_hdrs(slot, sid, method, scheme, authority, path, in_headers, in_headers, end_stream);
    }
    var filtered = http::HeaderMap { .. };
    guard filter_and_forward_headers(
        in_headers,
        filtered,
        client_ip,
        scheme,
        authority,
        slot.cfg.send_proxy_config,
        method,
    ) else {
        return 0, false;
    }
    return open_up_stream_with_hdrs(slot, sid, method, scheme, authority, path, filtered, in_headers, end_stream);
}

// ---- Outbound DATA, Trailers, Control Frames -------------------------------

fn finish_up_local_end(slot: H2UpSlot&, s_idx: i32, sid: u32) {
    let st .= slot.conn.streams[s_idx];
    if st.state == http2::StreamState.HalfClosedRemote {
        clear_up_stream_meta(slot, s_idx);
        http2::close_local_stream(slot.conn, sid);
        return;
    }
    st.state = http2::StreamState.HalfClosedLocal;
}

fn can_send_on_up_stream(slot: const H2UpSlot&, stream_id: u32) -> i32, bool {
    if slot.protocol_failed || stream_id == 0 {
        return -1, false;
    }
    if slot.conn.goaway_received && stream_id > slot.conn.goaway_last_stream_id {
        return -1, false;
    }
    let s_idx, found = http2::find_stream_idx(slot.conn, stream_id);
    guard found && s_idx >= 0 else {
        return -1, false;
    }
    let state = slot.conn.streams[s_idx].state;
    guard state == http2::StreamState.Open || state == http2::StreamState.HalfClosedRemote else {
        return -1, false;
    }
    return s_idx, true;
}

fn send_up_empty_data(slot: H2UpSlot&, s_idx: i32, stream_id: u32, end_stream: bool) -> i64, bool {
    if !end_stream {
        return 0, true;
    }
    let avail_wire = core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len);
    guard avail_wire >= rfc::H2_FRAME_HEADER_LEN else {
        return 0, false;
    }
    guard emit_up_frame(slot, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, stream_id, "") else {
        return 0, false;
    }
    finish_up_local_end(slot, s_idx, stream_id);
    return 0, true;
}

fn flush_up_data_chunks(
    slot:       H2UpSlot&,
    s_idx:      i32,
    stream_id:  u32,
    data:       const u8[:],
    end_stream: bool,
    to_send:    i64,
) -> i64 {
    var sent: i64 = 0;
    let max_frame = slot.peer_max_frame_size as i64;
    while sent < to_send {
        let rem = core::sub_sat_i64(to_send, sent);
        let chunk_len = min(rem, max_frame);
        let next_sent = core::add_sat_i64(sent, chunk_len);
        let is_final = end_stream && (next_sent == data.len);
        let flags: u8 = if is_final { rfc::H2_FLAG_END_STREAM } else { 0 };
        guard emit_up_frame(slot, rfc::H2_FRAME_DATA, flags, stream_id, data[sent..next_sent]) else {
            break;
        }
        sent = next_sent;
    }
    if sent > 0 {
        slot.conn.conn_send_window = core::sub_sat_i64(slot.conn.conn_send_window, sent);
        slot.conn.streams[s_idx].send_window = core::sub_sat_i64(slot.conn.streams[s_idx].send_window, sent);
        if end_stream && sent == data.len {
            finish_up_local_end(slot, s_idx, stream_id);
        }
    }
    return sent;
}

// RFC 9113 Section 6.1: DATA - stream outbound chunks bounded by connection and stream send windows.
fn h2_upstream_send_data(
    sess:       H2UpstreamSession&,
    stream_id:  u32,
    data:       const u8[:],
    end_stream: bool,
) -> i64, bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return 0, false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    let s_idx, ok_st = can_send_on_up_stream(slot, stream_id);
    guard ok_st else {
        return 0, false;
    }
    if data.len == 0 {
        return send_up_empty_data(slot, s_idx, stream_id, end_stream);
    }
    let avail_wire = core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len);
    if avail_wire <= rfc::H2_FRAME_HEADER_LEN {
        return 0, true;
    }
    let win_quota = http2::compute_stream_send_quota(slot.conn, stream_id);
    let wire_quota = core::sub_sat_i64(avail_wire, rfc::H2_FRAME_HEADER_LEN);
    let to_send = min(data.len, min(win_quota, wire_quota));
    if to_send == 0 {
        return 0, true;
    }
    let sent = flush_up_data_chunks(slot, s_idx, stream_id, data, end_stream, to_send);
    return sent, true;
}

fn encode_up_trailers_block(
    enc:      http2::DynamicTable&,
    trailers: const http::HeaderMap&,
    max_list: i64,
    out:      u8[..65536]&,
) -> bool {
    var list_size: i64 = 0;
    let max_tbl = enc.current_max_size as i64;
    for &e in trailers.entries {
        let raw_name = http::entry_name(trailers, e);
        let val = http::entry_value(trailers, e);
        guard raw_name.len > 0 && raw_name.len <= 256 && raw_name[0] != ':' else {
            return false;
        }
        var low_buf: u8[..256] = [];
        raw_name.to_lower_ascii(low_buf);
        let low_name = low_buf[..];
        guard http2::validate_field_syntax(low_name, val) else {
            return false;
        }
        guard !h2_internal::is_forbidden_h2_trailer(low_name) && !rfc::is_disallowed_trailer_field(low_name) else {
            return false;
        }
        let field_sz = core::add_sat_i64(low_name.len, val.len);
        list_size = core::add_sat_i64(list_size, core::add_sat_i64(H2_UP_HEADER_OVERHEAD_I64, field_sz));
        guard list_size <= max_list else {
            return false;
        }
        let mode = if http::is_sensitive(e) || http::is_heuristic_sensitive_header(low_name) {
            http2::HpackIndexing.NeverIndexed
        } else {
            http2::select_hpack_indexing(low_name, val, max_tbl)
        };
        guard http2::encode_hpack_field(enc, out, low_name, val, mode, true) else {
            return false;
        }
    }
    return true;
}

// Encodes and queues trailing HEADERS(END_STREAM) on an open local stream.
fn h2_upstream_send_trailers(
    sess:      H2UpstreamSession&,
    stream_id: u32,
    trailers:  const http::HeaderMap&,
) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    let s_idx, ok_st = can_send_on_up_stream(slot, stream_id);
    guard ok_st else {
        return false;
    }
    let max_list: i64 = min(slot.peer_max_header_list_size, slot.cfg.max_header_list_size);
    let saved_enc = slot.hpack_enc;
    let saved_pending = slot.hpack_enc_pending_sz_update;
    let saved_min_sz = slot.hpack_enc_min_sz;
    let saved_wire = slot.wire_out.len;
    var hpack_buf: u8[..65536] = [];
    var committed = false;
    defer if !committed {
        slot.hpack_enc = saved_enc;
        slot.hpack_enc_pending_sz_update = saved_pending;
        slot.hpack_enc_min_sz = saved_min_sz;
        slot.wire_out.resize(saved_wire);
    };
    guard emit_up_hpack_table_updates(slot, hpack_buf) else {
        return false;
    }
    guard encode_up_trailers_block(slot.hpack_enc, trailers, max_list, hpack_buf) else {
        return false;
    }
    guard emit_up_header_fragments(slot, stream_id, hpack_buf[..], true) else {
        return false;
    }
    finish_up_local_end(slot, s_idx, stream_id);
    committed = true;
    return true;
}

// RFC 9113 Section 6.4: RST_STREAM - abruptly terminate a stream and track locally reset IDs.
fn h2_upstream_reset_stream(
    sess:       H2UpstreamSession&,
    stream_id:  u32,
    error_code: u32 = rfc::H2_ERR_CANCEL,
) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    guard !slot.protocol_failed && stream_id != 0 else {
        return false;
    }
    let s_idx, found = http2::find_stream_idx(slot.conn, stream_id);
    guard found && s_idx >= 0 && slot.conn.streams[s_idx].state != http2::StreamState.Closed else {
        return false;
    }
    guard core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len) >= H2_UP_RST_WIRE_LEN else {
        return false;
    }
    var p: u8[..4] = [];
    p.append_u32_be(error_code);
    guard emit_up_frame(slot, rfc::H2_FRAME_RST_STREAM, 0, stream_id, p[..]) else {
        return false;
    }
    record_local_rst_sid(slot, stream_id);
    clear_up_stream_meta(slot, s_idx);
    http2::close_local_stream(slot.conn, stream_id);
    http2::reset_stream(slot.conn, stream_id);
    return true;
}

// RFC 9113 Section 6.7: PING - send an 8-byte opaque keep-alive / RTT probe.
fn h2_upstream_send_ping(sess: H2UpstreamSession&, opaque_data: const u8[:]) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    guard !slot.protocol_failed && opaque_data.len == H2_UP_PING_LEN else {
        return false;
    }
    guard core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len) >= H2_UP_PING_WIRE_LEN else {
        return false;
    }
    return emit_up_frame(slot, rfc::H2_FRAME_PING, 0, 0, opaque_data);
}

// RFC 9113 Section 6.8: GOAWAY - signal graceful connection drain to upstream server.
fn h2_upstream_send_goaway(
    sess:       H2UpstreamSession&,
    error_code: u32 = rfc::H2_ERR_NO_ERROR,
) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    guard !slot.protocol_failed else {
        return false;
    }
    guard emit_up_goaway_wire(slot, error_code) else {
        return false;
    }
    slot.local_goaway_sent = true;
    return true;
}

// ---- Inbound Frame & HPACK Decoders ----------------------------------------

fn mark_new_header_sensitive(out: http::HeaderMap&, prev_len: i64, prev_cookie_len: i64) {
    if out.entries.len == 0 {
        return;
    }
    if out.entries.len > prev_len {
        let last_idx = core::sub_sat_i64(out.entries.len, 1);
        out.entries[last_idx].flags |= http::HEADER_FLAG_SENSITIVE;
        return;
    }
    if http::get_header(out, "cookie").len > prev_cookie_len {
        for &e in out.entries {
            if http::entry_name(out, e) == "cookie" {
                e.flags |= http::HEADER_FLAG_SENSITIVE;
            }
        }
    }
}

// Decodes an HPACK field block into `pseudo` and `out`, preserving NeverIndexed (0x10) flags.
//
// Example:
//   src = [0x88, 0x10, 0x06, 'x','-','s','e','c','r',0x01,'v']
//   returns: H2_ERR_NO_ERROR with pseudo.status == 200 and HEADER_FLAG_SENSITIVE set
fn decode_hpack_to_map_sensitive(
    dt:         http2::DynamicTable&,
    src:        const u8[:],
    pseudo:     http2::PseudoHeaders&,
    out:        http::HeaderMap&,
    max_list:   u32,
    is_trailer: bool,
) -> u32 {
    http2::clear_pseudo_headers(pseudo);
    pseudo.is_trailer = is_trailer;
    var rem = src;
    var updates_allowed = true;
    var update_count: u32 = 0;
    while rem.len > 0 {
        let is_never_idx = (rem[0] & H2_UP_HPACK_NEVER_INDEX_MASK) == H2_UP_HPACK_NEVER_INDEX_TAG;
        let prev_entries = out.entries.len;
        let prev_cookie_len = http::get_header(out, "cookie").len;
        let consumed, err = http2::decode_hpack_field_step_to_map(
            dt,
            rem,
            0,
            updates_allowed,
            update_count,
            pseudo,
            out,
            max_list,
            true,
        );
        if err != rfc::H2_ERR_NO_ERROR {
            return err;
        }
        guard consumed > 0 else {
            return rfc::H2_ERR_COMPRESSION_ERROR;
        }
        rem = rem[consumed..];
        if is_never_idx {
            mark_new_header_sensitive(out, prev_entries, prev_cookie_len);
        }
    }
    guard !dt.pending_size_update_req && dt.current_max_size <= dt.max_allowed_size else {
        return rfc::H2_ERR_COMPRESSION_ERROR;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn validate_up_resp_trailers(pseudo: const http2::PseudoHeaders&, hdrs: const http::HeaderMap&) -> bool {
    if pseudo.has_method || pseudo.has_scheme || pseudo.has_path || pseudo.has_authority || pseudo.has_status {
        return false;
    }
    for &e in hdrs.entries {
        let name = http::entry_name(hdrs, e);
        if h2_internal::is_forbidden_h2_trailer(name) || rfc::is_disallowed_trailer_field(name) {
            return false;
        }
    }
    return true;
}

fn apply_up_resp_content_length(
    slot:       H2UpSlot&,
    s_idx:      i32,
    status:     i32,
    hdr_idx:    i32,
    end_stream: bool,
) -> bool {
    if slot.stream_is_head[s_idx] != 0 || status == 304 {
        return true;
    }
    let cl_hdr = http::get_header(g_h2_up_headers[hdr_idx].hdr, "content-length");
    if cl_hdr.len == 0 {
        return true;
    }
    let cl_val, ok_cl = cl_hdr.parse_i64_dec();
    guard ok_cl && cl_val >= 0 && !(end_stream && cl_val > 0) else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    slot.conn.streams[s_idx].declared_content_length = cl_val;
    return true;
}

fn emit_up_resp_trailers_event(
    slot:       H2UpSlot&,
    s_idx:      i32,
    sid:        u32,
    pseudo:     const http2::PseudoHeaders&,
    hdr_idx:    i32,
    end_stream: bool,
) -> bool {
    var transferred = false;
    defer if !transferred {
        recycle_up_hdr(hdr_idx);
    };
    guard end_stream && validate_up_resp_trailers(pseudo, g_h2_up_headers[hdr_idx].hdr) else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    let st .= slot.conn.streams[s_idx];
    guard st.declared_content_length < 0 || st.declared_content_length == st.received_data_bytes else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    let ev_idx = alloc_up_event(H2UpstreamEventKind.ResponseTrailers, sid);
    g_h2_up_events[ev_idx].hdr_idx = hdr_idx;
    g_h2_up_events[ev_idx].end_stream = true;
    transferred = true;
    push_up_event(slot, ev_idx);
    h2_internal::apply_stream_end_remote(slot.conn, s_idx);
    let _, still_open = http2::find_stream_idx(slot.conn, sid);
    if !still_open {
        clear_up_stream_meta(slot, s_idx);
    }
    return true;
}

fn emit_up_resp_headers_event(
    slot:       H2UpSlot&,
    s_idx:      i32,
    sid:        u32,
    pseudo:     const http2::PseudoHeaders&,
    hdr_idx:    i32,
    end_stream: bool,
) -> bool {
    var transferred = false;
    defer if !transferred {
        recycle_up_hdr(hdr_idx);
    };
    let st .= slot.conn.streams[s_idx];
    if st.headers_received {
        transferred = true;
        return emit_up_resp_trailers_event(slot, s_idx, sid, pseudo, hdr_idx, end_stream);
    }
    guard pseudo.has_status && pseudo.status >= 100 && pseudo.status <= 599 else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    let is_interim = pseudo.status >= 100 && pseudo.status < 200;
    if is_interim && end_stream {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    if !is_interim {
        st.headers_received = true;
        st.status_code = pseudo.status;
        guard apply_up_resp_content_length(slot, s_idx, pseudo.status, hdr_idx, end_stream) else {
            return false;
        }
    }
    let ev_idx = alloc_up_event(H2UpstreamEventKind.ResponseHead, sid);
    g_h2_up_events[ev_idx].status_code = pseudo.status;
    g_h2_up_events[ev_idx].hdr_idx = hdr_idx;
    g_h2_up_events[ev_idx].end_stream = end_stream;
    transferred = true;
    push_up_event(slot, ev_idx);
    if !is_interim && end_stream {
        h2_internal::apply_stream_end_remote(slot.conn, s_idx);
        let _, still_open = http2::find_stream_idx(slot.conn, sid);
        if !still_open {
            clear_up_stream_meta(slot, s_idx);
        }
    }
    return true;
}

// Decodes accumulated header_accum bytes via HPACK and emits ResponseHead or ResponseTrailers.
//
// Example:
//   header_accum = [0x88], sid = 1, end_stream = true
//   returns: true with queued ResponseHead(status=200, end_stream=true)
fn decode_up_hpack_block(slot: H2UpSlot&, sid: u32, end_stream: bool) -> bool {
    let hdr_idx = alloc_up_hdr();
    var hdr_owned = true;
    defer if hdr_owned {
        recycle_up_hdr(hdr_idx);
    };
    let s_idx_pre, found_pre = http2::find_stream_idx(slot.conn, sid);
    let is_trailer = found_pre && s_idx_pre >= 0 && slot.conn.streams[s_idx_pre].headers_received;
    var pseudo = http2::PseudoHeaders { .. };
    let dec_err = decode_hpack_to_map_sensitive(
        slot.hpack_dec,
        slot.header_accum[..],
        pseudo,
        g_h2_up_headers[hdr_idx].hdr,
        slot.cfg.max_header_list_size,
        is_trailer,
    );
    slot.header_accum.clear();
    if dec_err != rfc::H2_ERR_NO_ERROR {
        return fail_up_conn(slot, dec_err);
    }
    let s_idx, found = http2::find_stream_idx(slot.conn, sid);
    if !found || s_idx < 0 {
        if is_in_local_rst_ring(slot, sid) {
            return true;
        }
        return fail_up_conn(slot, rfc::H2_ERR_STREAM_CLOSED);
    }
    let st .= slot.conn.streams[s_idx];
    guard st.state == http2::StreamState.Open || st.state == http2::StreamState.HalfClosedLocal else {
        return fail_up_conn(slot, rfc::H2_ERR_STREAM_CLOSED);
    }
    hdr_owned = false;
    return emit_up_resp_headers_event(slot, s_idx, sid, pseudo, hdr_idx, end_stream);
}

fn handle_up_headers_or_cont(
    slot:    H2UpSlot&,
    hdr:     const http2::FrameHeader&,
    payload: const u8[:],
) -> bool {
    let sid = hdr.stream_id;
    guard sid != 0 && (sid & 1) == 1 else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    var frag = payload;
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        guard sid <= slot.last_local_sid else {
            return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
        }
        let ex, ex_err = http2::extract_headers_frame_payload(hdr, payload);
        guard ex_err == rfc::H2_ERR_NO_ERROR else {
            return fail_up_conn(slot, ex_err);
        }
        frag = ex;
        slot.empty_data_streak = 0;
        slot.in_cont = true;
        slot.cont_stream_id = sid;
        slot.cont_end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
        slot.cont_count = 0;
        slot.header_accum.clear();
    } else {
        slot.cont_count = core::add_sat_u32(slot.cont_count, 1);
        guard slot.cont_count <= http2::MAX_CONT_FRAMES_LIMIT else {
            return fail_up_conn(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
        }
    }
    guard slot.header_accum.try_append(frag) else {
        return fail_up_conn(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        return true;
    }
    let end_stream = slot.cont_end_stream;
    slot.in_cont = false;
    slot.cont_stream_id = 0;
    slot.cont_end_stream = false;
    slot.cont_count = 0;
    return decode_up_hpack_block(slot, sid, end_stream);
}

fn emit_up_win_update(slot: H2UpSlot&, sid: u32, inc: u32) -> bool {
    var p: u8[..4] = [];
    p.append_u32_be(inc);
    return emit_up_frame(slot, rfc::H2_FRAME_WINDOW_UPDATE, 0, sid, p[..]);
}

// RFC 9113 Section 6.9: WINDOW_UPDATE - coalesce receive window updates above threshold.
fn replenish_up_recv_windows(
    slot:       H2UpSlot&,
    s_idx:      i32,
    sid:        u32,
    flow_len:   u32,
    end_stream: bool,
) -> bool {
    if flow_len == 0 {
        return true;
    }
    slot.conn.unclaimed_recv_window = core::add_sat_i64(slot.conn.unclaimed_recv_window, flow_len);
    if slot.conn.unclaimed_recv_window >= H2_UP_MIN_REPLENISH {
        let conn_inc = min(slot.conn.unclaimed_recv_window, rfc::H2_MAX_WINDOW_SIZE);
        guard emit_up_win_update(slot, 0, conn_inc as u32) else {
            return fail_up_conn(slot, rfc::H2_ERR_INTERNAL_ERROR);
        }
        slot.conn.conn_recv_window = core::add_sat_i64(slot.conn.conn_recv_window, conn_inc);
        slot.conn.unclaimed_recv_window = core::sub_sat_i64(slot.conn.unclaimed_recv_window, conn_inc);
    }
    if s_idx >= 0 && !end_stream && slot.stream_unclaimed_id[s_idx] == sid {
        let thresh = max(1, min(H2_UP_MIN_REPLENISH, (slot.cfg.initial_window_size as i64) >> 1));
        slot.stream_unclaimed_rx[s_idx] = core::add_sat_i64(slot.stream_unclaimed_rx[s_idx], flow_len);
        if slot.stream_unclaimed_rx[s_idx] >= thresh {
            let st_inc = min(slot.stream_unclaimed_rx[s_idx], rfc::H2_MAX_WINDOW_SIZE);
            guard emit_up_win_update(slot, sid, st_inc as u32) else {
                return fail_up_conn(slot, rfc::H2_ERR_INTERNAL_ERROR);
            }
            let cur_w = slot.conn.streams[s_idx].recv_window;
            slot.conn.streams[s_idx].recv_window = core::add_sat_i64(cur_w, st_inc);
            slot.stream_unclaimed_rx[s_idx] = core::sub_sat_i64(slot.stream_unclaimed_rx[s_idx], st_inc);
        }
    }
    return true;
}

fn handle_up_closed_rst_data(slot: H2UpSlot&, sid: u32, flow_len: u32) -> bool {
    if (sid & 1) == 0 || !h2_internal::is_closed_stream_id(slot.conn, sid) {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    if !is_in_local_rst_ring(slot, sid) {
        return fail_up_conn(slot, rfc::H2_ERR_STREAM_CLOSED);
    }
    guard flow_len <= slot.conn.conn_recv_window else {
        return fail_up_conn(slot, rfc::H2_ERR_FLOW_CONTROL_ERROR);
    }
    slot.conn.conn_recv_window = core::sub_sat_i64(slot.conn.conn_recv_window, flow_len);
    return replenish_up_recv_windows(slot, -1, sid, flow_len, true);
}

fn emit_up_data_events(
    slot:       H2UpSlot&,
    sid:        u32,
    data_bytes: const u8[:],
    end_stream: bool,
) -> bool {
    if data_bytes.len > 0 {
        let c_idx = alloc_up_chunk(data_bytes);
        guard c_idx != H2_UP_INVALID_IDX else {
            return fail_up_conn(slot, rfc::H2_ERR_INTERNAL_ERROR);
        }
        let ev_idx = alloc_up_event(H2UpstreamEventKind.ResponseData, sid);
        g_h2_up_events[ev_idx].chunk_idx = c_idx;
        g_h2_up_events[ev_idx].end_stream = end_stream;
        push_up_event(slot, ev_idx);
    }
    if end_stream {
        let ev_end = alloc_up_event(H2UpstreamEventKind.ResponseEnd, sid);
        g_h2_up_events[ev_end].end_stream = true;
        push_up_event(slot, ev_end);
    }
    return true;
}

fn validate_up_data_stream_state(
    slot:       H2UpSlot&,
    s_idx:      i32,
    data_len:   i64,
    end_stream: bool,
) -> bool {
    let st .= slot.conn.streams[s_idx];
    guard st.state == http2::StreamState.Open || st.state == http2::StreamState.HalfClosedLocal else {
        return fail_up_conn(slot, rfc::H2_ERR_STREAM_CLOSED);
    }
    guard st.headers_received && !(slot.stream_is_head[s_idx] != 0 && data_len > 0) else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    slot.empty_data_streak = if data_len == 0 && !end_stream {
        core::add_sat_u32(slot.empty_data_streak, 1)
    } else {
        0
    };
    guard slot.empty_data_streak <= http2::MAX_EMPTY_FRAME_STREAK else {
        return fail_up_conn(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    return true;
}

fn handle_up_data(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    let sid = hdr.stream_id;
    guard sid != 0 else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    let data_bytes, pad_err = http2::extract_padded_frame_payload(hdr, payload);
    guard pad_err == rfc::H2_ERR_NO_ERROR else {
        return fail_up_conn(slot, pad_err);
    }
    let end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
    let s_idx, found = http2::find_stream_idx(slot.conn, sid);
    if !found || s_idx < 0 {
        return handle_up_closed_rst_data(slot, sid, hdr.length);
    }
    guard validate_up_data_stream_state(slot, s_idx, data_bytes.len, end_stream) else {
        return false;
    }
    let df_err = http2::on_data_frame_received(slot.conn, hdr, data_bytes.len as u32);
    guard df_err == rfc::H2_ERR_NO_ERROR else {
        return fail_up_conn(slot, df_err);
    }
    let _, still_open = http2::find_stream_idx(slot.conn, sid);
    let rep_idx = if still_open { s_idx } else { -1 };
    guard replenish_up_recv_windows(slot, rep_idx, sid, hdr.length, end_stream) else {
        return false;
    }
    if !still_open {
        clear_up_stream_meta(slot, s_idx);
    }
    return emit_up_data_events(slot, sid, data_bytes, end_stream);
}

fn apply_up_setting_pair(slot: H2UpSlot&, id: u16, val: u32) -> u32 {
    let err = http2::validate_settings_parameter(id, val, true);
    if err != rfc::H2_ERR_NO_ERROR {
        return err;
    }
    if id == rfc::H2_SETTING_HEADER_TABLE_SIZE {
        let capped = min(val as u64, rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
        slot.hpack_enc.max_allowed_size = capped;
        let _ = http2::update_dynamic_table_max_size(slot.hpack_enc, capped);
        if !slot.hpack_enc_pending_sz_update || capped < slot.hpack_enc_min_sz {
            slot.hpack_enc_min_sz = capped;
        }
        slot.hpack_enc_pending_sz_update = true;
        slot.peer_header_table_size = capped as u32;
        return rfc::H2_ERR_NO_ERROR;
    }
    if id == rfc::H2_SETTING_MAX_CONCURRENT_STREAMS {
        slot.peer_max_concurrent_streams = val;
        return rfc::H2_ERR_NO_ERROR;
    }
    if id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE {
        return http2::apply_peer_initial_window_size_delta(slot.conn, val);
    }
    if id == rfc::H2_SETTING_MAX_FRAME_SIZE {
        slot.peer_max_frame_size = val;
        return rfc::H2_ERR_NO_ERROR;
    }
    if id == rfc::H2_SETTING_MAX_HEADER_LIST_SIZE {
        slot.peer_max_header_list_size = val;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn handle_up_settings(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    guard hdr.stream_id == 0 else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        guard payload.len == 0 else {
            return fail_up_conn(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
        }
        return true;
    }
    guard core::rem_euclid_i64(payload.len, H2_UP_SETTINGS_PAIR_LEN) == 0 else {
        return fail_up_conn(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    var off: i64 = 0;
    while core::add_sat_i64(off, H2_UP_SETTINGS_PAIR_LEN) <= payload.len {
        let pid = core::read_be_u16(payload, off);
        let pval = core::read_be_u32(payload, core::add_sat_i64(off, 2));
        let err = apply_up_setting_pair(slot, pid, pval);
        if err != rfc::H2_ERR_NO_ERROR {
            return fail_up_conn(slot, err);
        }
        off = core::add_sat_i64(off, H2_UP_SETTINGS_PAIR_LEN);
    }
    guard emit_up_frame(slot, rfc::H2_FRAME_SETTINGS, rfc::H2_FLAG_ACK, 0, "") else {
        return fail_up_conn(slot, rfc::H2_ERR_INTERNAL_ERROR);
    }
    return true;
}

fn handle_up_ping(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    guard hdr.stream_id == 0 else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    guard payload.len == H2_UP_PING_LEN else {
        return fail_up_conn(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        let ev_idx = alloc_up_event(H2UpstreamEventKind.PingAck, 0);
        for i in 8 {
            g_h2_up_events[ev_idx].opaque_data[i] = payload[i];
        }
        push_up_event(slot, ev_idx);
        return true;
    }
    guard emit_up_frame(slot, rfc::H2_FRAME_PING, rfc::H2_FLAG_ACK, 0, payload) else {
        return fail_up_conn(slot, rfc::H2_ERR_INTERNAL_ERROR);
    }
    return true;
}

fn handle_up_goaway(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    guard hdr.stream_id == 0 else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    guard payload.len >= H2_UP_GOAWAY_LEN else {
        return fail_up_conn(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    let last_sid = core::read_be_u32(payload, 0) & H2_UP_MAX_SID;
    let err_code = core::read_be_u32(payload, 4);
    guard rfc::validate_goaway_last_stream_id(last_sid, false) else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    if slot.conn.goaway_received && last_sid > slot.conn.goaway_last_stream_id {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    let ga_err = http2::apply_goaway(slot.conn, last_sid, err_code);
    guard ga_err == rfc::H2_ERR_NO_ERROR else {
        return fail_up_conn(slot, ga_err);
    }
    close_up_streams_above(slot, last_sid);
    let ev_idx = alloc_up_event(H2UpstreamEventKind.GoAway, 0);
    g_h2_up_events[ev_idx].last_stream_id = last_sid;
    g_h2_up_events[ev_idx].error_code = err_code;
    push_up_event(slot, ev_idx);
    return true;
}

// RFC 9113 Section 6.4: RST_STREAM - reset an active stream and notify the caller via StreamReset.
fn rst_up_stream_with_event(slot: H2UpSlot&, s_idx: i32, sid: u32, err_code: u32) -> bool {
    var p: u8[..4] = [];
    p.append_u32_be(err_code);
    guard emit_up_frame(slot, rfc::H2_FRAME_RST_STREAM, 0, sid, p[..]) else {
        return fail_up_conn(slot, rfc::H2_ERR_INTERNAL_ERROR);
    }
    record_local_rst_sid(slot, sid);
    clear_up_stream_meta(slot, s_idx);
    http2::close_local_stream(slot.conn, sid);
    http2::reset_stream(slot.conn, sid);
    let ev_idx = alloc_up_event(H2UpstreamEventKind.StreamReset, sid);
    g_h2_up_events[ev_idx].error_code = err_code;
    push_up_event(slot, ev_idx);
    return true;
}

// RFC 9113 Section 6.9: WINDOW_UPDATE - enforce flow-control increments and stream state rules.
fn handle_up_window_update(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    guard payload.len == H2_UP_ERR_LEN else {
        return fail_up_conn(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    let sid = hdr.stream_id;
    let inc = core::read_be_u32(payload, 0) & H2_UP_MAX_SID;
    let bad_target = sid != 0 && ((sid & 1) == 0 || http2::is_conn_error_on_window_update(slot.conn, sid));
    if inc == 0 {
        if sid == 0 || bad_target {
            return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
        }
        let s_idx, found = http2::find_stream_idx(slot.conn, sid);
        if found && s_idx >= 0 {
            return rst_up_stream_with_event(slot, s_idx, sid, rfc::H2_ERR_PROTOCOL_ERROR);
        }
        return true;
    }
    if bad_target {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    let wu_err = http2::apply_window_update(slot.conn, sid, inc);
    if wu_err == rfc::H2_ERR_NO_ERROR {
        return true;
    }
    if sid == 0 {
        return fail_up_conn(slot, wu_err);
    }
    let s_idx, found = http2::find_stream_idx(slot.conn, sid);
    if found && s_idx >= 0 {
        return rst_up_stream_with_event(slot, s_idx, sid, wu_err);
    }
    return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
}

fn handle_up_rst_stream(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    let sid = hdr.stream_id;
    guard sid != 0 else {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    guard payload.len == H2_UP_ERR_LEN else {
        return fail_up_conn(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    let err_code = core::read_be_u32(payload, 0);
    let s_idx, found = http2::find_stream_idx(slot.conn, sid);
    if found && s_idx >= 0 {
        clear_up_stream_meta(slot, s_idx);
        http2::close_local_stream(slot.conn, sid);
        http2::reset_stream(slot.conn, sid);
        let ev_idx = alloc_up_event(H2UpstreamEventKind.StreamReset, sid);
        g_h2_up_events[ev_idx].error_code = err_code;
        push_up_event(slot, ev_idx);
        return true;
    }
    if (sid & 1) == 0 || sid > slot.last_local_sid {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    return true;
}

fn dispatch_up_ctrl_frame(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS {
        return handle_up_settings(slot, hdr, payload);
    }
    if hdr.frame_type == rfc::H2_FRAME_PING {
        return handle_up_ping(slot, hdr, payload);
    }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY {
        return handle_up_goaway(slot, hdr, payload);
    }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE {
        return handle_up_window_update(slot, hdr, payload);
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM {
        return handle_up_rst_stream(slot, hdr, payload);
    }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY && (hdr.stream_id == 0 || payload.len != H2_UP_PRIORITY_LEN) {
        let p_err = if hdr.stream_id == 0 { rfc::H2_ERR_PROTOCOL_ERROR } else { rfc::H2_ERR_FRAME_SIZE_ERROR };
        return fail_up_conn(slot, p_err);
    }
    return true;
}

fn dispatch_up_frame(slot: H2UpSlot&, hdr: const http2::FrameHeader&, payload: const u8[:]) -> bool {
    if slot.in_cont && (hdr.frame_type != rfc::H2_FRAME_CONTINUATION || hdr.stream_id != slot.cont_stream_id) {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    if !slot.in_cont && hdr.frame_type == rfc::H2_FRAME_CONTINUATION {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    let rule_err = http2::validate_frame_header_rules(hdr, slot.conn.local_max_frame_size);
    guard rule_err == rfc::H2_ERR_NO_ERROR else {
        return fail_up_conn(slot, rule_err);
    }
    if hdr.frame_type == rfc::H2_FRAME_DATA {
        return handle_up_data(slot, hdr, payload);
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS || hdr.frame_type == rfc::H2_FRAME_CONTINUATION {
        return handle_up_headers_or_cont(slot, hdr, payload);
    }
    // RFC 9113 Section 6.6: PUSH_PROMISE - reject unsolicited server PUSH_PROMISE when ENABLE_PUSH = 0.
    if hdr.frame_type == rfc::H2_FRAME_PUSH_PROMISE {
        return fail_up_conn(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    return dispatch_up_ctrl_frame(slot, hdr, payload);
}

fn drain_up_wire_in_frames(slot: H2UpSlot&) -> bool {
    var off: i64 = 0;
    var ok_all = true;
    while core::add_sat_i64(off, rfc::H2_FRAME_HEADER_LEN) <= slot.wire_in.len {
        let hdr_end = core::add_sat_i64(off, rfc::H2_FRAME_HEADER_LEN);
        let fh, herr = http2::parse_frame_header(slot.wire_in[off..hdr_end], slot.conn.local_max_frame_size);
        if herr != rfc::H2_ERR_NO_ERROR {
            ok_all = fail_up_conn(slot, herr);
            break;
        }
        let total = core::add_sat_i64(rfc::H2_FRAME_HEADER_LEN, fh.length);
        let frame_end = core::add_sat_i64(off, total);
        if frame_end > slot.wire_in.len {
            break;
        }
        let payload = slot.wire_in[hdr_end..frame_end];
        off = frame_end;
        if !dispatch_up_frame(slot, fh, payload) {
            ok_all = false;
            break;
        }
    }
    if off > 0 {
        slot.wire_in.compact_wire_buffer(off);
    }
    return ok_all;
}

// Feeds incoming HTTP/2 server bytes (arbitrary chunking) into the upstream multiplexer.
fn h2_upstream_feed(sess: H2UpstreamSession&, wire_in: const u8[:]) -> bool {
    let slot_idx = resolve_up_slot_idx(sess);
    guard slot_idx >= 0 else {
        return false;
    }
    let slot .= g_h2_up_slots[slot_idx];
    guard !slot.protocol_failed else {
        return false;
    }
    var pos: i64 = 0;
    while pos < wire_in.len {
        let space = core::sub_sat_i64(slot.wire_in.cap, slot.wire_in.len);
        guard space > 0 else {
            return fail_up_conn(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
        }
        let rem = core::sub_sat_i64(wire_in.len, pos);
        let take = min(rem, space);
        let next_pos = core::add_sat_i64(pos, take);
        guard slot.wire_in.try_append(wire_in[pos..next_pos]) else {
            return fail_up_conn(slot, rfc::H2_ERR_INTERNAL_ERROR);
        }
        pos = next_pos;
        if !drain_up_wire_in_frames(slot) {
            return false;
        }
    }
    return !slot.protocol_failed;
}
