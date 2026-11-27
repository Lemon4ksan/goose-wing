// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Sans-IO event-driven HTTP/2 server session with incremental streaming ingress/egress,
// CONTINUATION reassembly, HPACK header codecs, and Rapid Reset defense (RFC 9113, RFC 7541).
namespace http2;

import std;
import core;
import rfc.h2;
import http.headers;
import .internal;
import .framing;
import .hpack;
import .connection;

// ---- Session Public Limits & Constants -----------------------------------

const MAX_H2_EDGE_SLOTS:          i64 = 4096;
const H2_EDGE_MAX_STREAMS:        u32 = 128;
const H2_EDGE_WIRE_IN_CAP:        i64 = 16393;  // 9-byte header + 16384-byte default MAX_FRAME_SIZE
const H2_EDGE_WIRE_OUT_CAP:       i64 = 147456; // 144 KiB outbound framing buffer (HEADERS + CONTINUATION + DATA)
const H2_EDGE_EV_DATA_CAP:        i64 = 16384;  // Max single DATA frame payload per RFC 9113 Section 4.2 default
const H2_EDGE_MAX_HEADER_LIST:    u32 = 65535;    // Bounded by http::OverflowArena u16 offsets (RFC 9113 Section 6.5.2)
const H2_EDGE_MAX_HEADER_ENTRIES: i64 = 512;      // Max decoded header entries queued per request/trailer event
const H2_EDGE_MIN_REPLENISH:      i64 = 16384;

// ---- Public Streaming Event & Session Handle Types -----------------------

enum H2EdgeEventKind {
    None,
    RequestHead,
    RequestData,
    RequestEnd,
    StreamReset,
    GoAway,
    ProtocolError,
}

struct H2EdgeEvent {
    kind:       H2EdgeEventKind = H2EdgeEventKind.None,
    stream_id:  u32             = 0,
    headers:    http::HeaderMap = http::HeaderMap { .. },
    data:       const u8[:]     = "",
    end_stream: bool            = false,
    error_code: u32             = 0,
}

// Zero-copy streaming event carrying a `http::HeaderView` backed by the session's reusable staging buffers.
struct H2EdgeEventView {
    kind:       H2EdgeEventKind  = H2EdgeEventKind.None,
    stream_id:  u32              = 0,
    headers:    http::HeaderView = http::HeaderView { .. },
    data:       const u8[:]      = "",
    end_stream: bool             = false,
    error_code: u32              = 0,
}

struct H2EdgeSession {
    slot_idx:   i64 = -1,
    generation: u64 = 0,
}

// ---- Thread-Local Slot & Event Arena Storage -----------------------------

struct H2EdgeDataChunk {
    in_use:   bool        = false,
    next_idx: i64         = -1,
    buf:      u8[..16384] = [],
}

struct H2EdgeHdrBuf {
    in_use:   bool                     = false,
    next_idx: i64                      = -1,
    entries:  http::HeaderEntry[..512] = [],
    raw:      u8[..65536]              = [],
}

struct H2EdgeEventNode {
    active:      bool            = false,
    kind:        H2EdgeEventKind = H2EdgeEventKind.None,
    stream_id:   u32             = 0,
    header_slot: i64             = -1,
    chunk_idx:   i64             = -1,
    end_stream:  bool            = false,
    error_code:  u32             = 0,
    next_idx:    i64             = -1,
}

struct H2EdgeSlot {
    in_use:                        bool                     = false,
    generation:                    u64                      = 0,
    preface_done:                  bool                     = false,
    first_settings_received:       bool                     = false,
    conn_failed:                   bool                     = false,
    hpack_enc_pending_size_update: bool                     = false,
    hpack_enc_pending_min_size:    u64                      = rfc::HPACK_DEFAULT_MAX_DYN_SIZE,
    has_peer_max_header_list_size: bool                     = false,
    peer_max_concurrent_streams:   u32                      = 128,
    peer_max_header_list_size:     u32                      = 0,
    queued_control_acks:           u32                      = 0,
    refused_cont_stream_id:        u32                      = 0,
    refused_cont_frames_cnt:       u32                      = 0,
    refused_cont_start_ms:         u64                      = 0,
    hdr_stream_id:                 u32                      = 0,
    hdr_end_stream:                bool                     = false,
    hdr_is_trailer:                bool                     = false,
    hdr_reject_err:                u32                      = 0,
    ev_head:                       i64                      = -1,
    ev_tail:                       i64                      = -1,
    conn:                          Connection               = Connection { .. },
    hpack_enc:                     DynamicTable             = DynamicTable { .. },
    stream_unclaimed_id:           u32[128]                 = [0; 128],
    stream_unclaimed_rx:           i64[128]                 = [0; 128],
    wire_in:                       u8[..16393]              = [],
    wire_out:                      u8[..147456]             = [],
    header_accum:                  u8[..65536]              = [],
    ev_hdr_entries:                http::HeaderEntry[..512] = [],
    ev_hdr_raw:                    u8[..65536]              = [],
    ev_data_buf:                   u8[..16384]              = [],
}

var g_h2_edge_slots:         H2EdgeSlot[>..]      = [];
var g_h2_edge_active_count:  i64                  = 0;
var g_h2_edge_next_gen:      u64                  = 0;
var g_h2_edge_events:        H2EdgeEventNode[>..] = [];
var g_h2_edge_free_event:    i64                  = -1;
var g_h2_edge_hdr_bufs:      H2EdgeHdrBuf[>..]    = [];
var g_h2_edge_free_hdr:      i64                  = -1;
var g_h2_edge_data_chunks:   H2EdgeDataChunk[>..] = [];
var g_h2_edge_free_chunk:    i64                  = -1;
var g_h2_edge_hpack_scratch: u8[>..]              = [];

// ---- Slot & Arena Lifecycle Helpers --------------------------------------

fn lookup_live_edge_slot_idx(sess: const H2EdgeSession&) -> i64 {
    guard sess.generation != 0 && sess.slot_idx >= 0 && sess.slot_idx < g_h2_edge_slots.len else {
        return -1;
    }
    let slot .= g_h2_edge_slots[sess.slot_idx];
    guard slot.in_use && slot.generation == sess.generation else {
        return -1;
    }
    return sess.slot_idx;
}

fn alloc_edge_hdr_buf() -> i64 {
    if g_h2_edge_free_hdr >= 0 {
        let idx = g_h2_edge_free_hdr;
        let hb .= g_h2_edge_hdr_bufs[idx];
        g_h2_edge_free_hdr = hb.next_idx;
        hb.next_idx = -1;
        hb.in_use = true;
        hb.entries.clear();
        hb.raw.clear();
        return idx;
    }
    let idx = g_h2_edge_hdr_bufs.len;
    g_h2_edge_hdr_bufs.push(H2EdgeHdrBuf { in_use: true, .. });
    return idx;
}

fn free_edge_hdr_buf(h_idx: i64) {
    guard h_idx >= 0 && h_idx < g_h2_edge_hdr_bufs.len else { return; }
    let hb .= g_h2_edge_hdr_bufs[h_idx];
    guard hb.in_use else { return; }
    hb.entries.clear();
    if hb.raw.len > 0 {
        core::secure_zeroize_slice(hb.raw[..]);
    }
    hb.raw.clear();
    hb.in_use = false;
    hb.next_idx = g_h2_edge_free_hdr;
    g_h2_edge_free_hdr = h_idx;
}

fn free_edge_data_chunk(c_idx: i64) {
    guard c_idx >= 0 && c_idx < g_h2_edge_data_chunks.len else { return; }
    let ch .= g_h2_edge_data_chunks[c_idx];
    guard ch.in_use else { return; }
    ch.buf.clear();
    ch.in_use = false;
    ch.next_idx = g_h2_edge_free_chunk;
    g_h2_edge_free_chunk = c_idx;
}

fn alloc_edge_data_chunk(payload: const u8[:]) -> i64 {
    guard payload.len <= H2_EDGE_EV_DATA_CAP else { return -1; }
    var c_idx: i64 = -1;
    if g_h2_edge_free_chunk >= 0 {
        c_idx = g_h2_edge_free_chunk;
        let ch .= g_h2_edge_data_chunks[c_idx];
        g_h2_edge_free_chunk = ch.next_idx;
        ch.next_idx = -1;
        ch.in_use = true;
        ch.buf.clear();
    } else {
        c_idx = g_h2_edge_data_chunks.len;
        g_h2_edge_data_chunks.push(H2EdgeDataChunk { in_use: true, .. });
    }
    guard g_h2_edge_data_chunks[c_idx].buf.try_set(payload) else {
        free_edge_data_chunk(c_idx);
        return -1;
    }
    return c_idx;
}

fn alloc_edge_event_node() -> i64 {
    if g_h2_edge_free_event >= 0 {
        let idx = g_h2_edge_free_event;
        g_h2_edge_free_event = g_h2_edge_events[idx].next_idx;
        g_h2_edge_events[idx] = H2EdgeEventNode { active: true, .. };
        return idx;
    }
    let idx = g_h2_edge_events.len;
    g_h2_edge_events.push(H2EdgeEventNode { active: true, .. });
    return idx;
}

fn free_edge_event_node(ev_idx: i64) {
    guard ev_idx >= 0 && ev_idx < g_h2_edge_events.len else { return; }
    let node .= g_h2_edge_events[ev_idx];
    if node.header_slot >= 0 {
        free_edge_hdr_buf(node.header_slot);
    }
    if node.chunk_idx >= 0 {
        free_edge_data_chunk(node.chunk_idx);
    }
    g_h2_edge_events[ev_idx] = H2EdgeEventNode { next_idx: g_h2_edge_free_event, .. };
    g_h2_edge_free_event = ev_idx;
}

fn clear_slot_event_queue(slot: H2EdgeSlot&) {
    var cur = slot.ev_head;
    while cur >= 0 {
        let nxt = g_h2_edge_events[cur].next_idx;
        free_edge_event_node(cur);
        cur = nxt;
    }
    slot.ev_head = -1;
    slot.ev_tail = -1;
}

fn enqueue_edge_event(
    slot:        H2EdgeSlot&,
    kind:        H2EdgeEventKind,
    stream_id:   u32,
    header_slot: i64,
    payload:     const u8[:],
    end_stream:  bool,
    error_code:  u32,
) -> bool {
    var chunk_idx: i64 = -1;
    if payload.len > 0 {
        chunk_idx = alloc_edge_data_chunk(payload);
        guard chunk_idx >= 0 else {
            free_edge_hdr_buf(header_slot);
            return false;
        }
    }

    let ev_idx = alloc_edge_event_node();
    let node .= g_h2_edge_events[ev_idx];
    node.kind = kind;
    node.stream_id = stream_id;
    node.header_slot = header_slot;
    node.chunk_idx = chunk_idx;
    node.end_stream = end_stream;
    node.error_code = error_code;
    node.next_idx = -1;

    if slot.ev_tail >= 0 {
        g_h2_edge_events[slot.ev_tail].next_idx = ev_idx;
    } else {
        slot.ev_head = ev_idx;
    }
    slot.ev_tail = ev_idx;
    return true;
}

// ---- Low-Level Wire Framing Helpers (RFC 9113 Section 4 & Section 6) -----

fn append_edge_frame(
    out:        u8[..147456]&,
    frame_type: u8,
    flags:      u8,
    stream_id:  u32,
    payload:    const u8[:],
) -> bool {
    let needed = core::add_sat_i64(rfc::H2_FRAME_HEADER_LEN, payload.len);
    guard core::sub_sat_i64(out.cap, out.len) >= needed else { return false; }
    let mark = out.len;
    var committed = false;
    defer if !committed { out.resize(mark); };
    let hdr = FrameHeader {
        length:     payload.len as u32,
        frame_type: frame_type,
        flags:      flags,
        stream_id:  stream_id & 0x7FFFFFFF,
    };
    encode_frame_header_to(hdr, out);
    guard out.len == core::add_sat_i64(mark, rfc::H2_FRAME_HEADER_LEN) else {
        out.resize(mark);
        return false;
    }
    if payload.len > 0 {
        guard out.try_append(payload) else {
            out.resize(mark);
            return false;
        }
    }
    committed = true;
    return true;
}

// Encodes server initial HTTP/2 SETTINGS payload (4 x 6-byte entries).
//
// Example:
//   max_concurrent = 128, init_win = 65535
//   returns: out appends 24 bytes, true
fn encode_edge_settings_payload<B>(max_concurrent: u32, init_win: u32, out: B&) -> bool {
    let mark = out.len;
    var committed = false;
    defer if !committed { out.resize(mark); };
    var p: u8[..24] = [];
    p.append_u16_be(rfc::H2_SETTING_MAX_CONCURRENT_STREAMS);
    p.append_u32_be(max_concurrent);
    p.append_u16_be(rfc::H2_SETTING_INITIAL_WINDOW_SIZE);
    p.append_u32_be(init_win);
    p.append_u16_be(rfc::H2_SETTING_MAX_FRAME_SIZE);
    p.append_u32_be(rfc::H2_DEFAULT_MAX_FRAME_SIZE);
    p.append_u16_be(rfc::H2_SETTING_MAX_HEADER_LIST_SIZE);
    p.append_u32_be(H2_EDGE_MAX_HEADER_LIST);
    guard out.try_append(p[..]) else { return false; }
    committed = true;
    return true;
}

fn emit_server_initial_settings(slot: H2EdgeSlot&) -> bool {
    var payload: u8[..24] = [];
    guard encode_edge_settings_payload(
        slot.conn.max_concurrent_streams,
        slot.conn.local_initial_window_size as u32,
        payload,
    ) else {
        return false;
    }
    return append_edge_frame(slot.wire_out, rfc::H2_FRAME_SETTINGS, rfc::H2_FLAG_NONE, 0, payload[..]);
}

fn emit_edge_window_update(slot: H2EdgeSlot&, stream_id: u32, increment: u32) -> bool {
    guard increment > 0 && increment <= rfc::H2_MAX_WINDOW_SIZE else { return false; }
    var p: u8[..4] = [];
    p.append_u32_be(increment & 0x7FFFFFFF);
    return append_edge_frame(slot.wire_out, rfc::H2_FRAME_WINDOW_UPDATE, rfc::H2_FLAG_NONE, stream_id, p[..]);
}

fn emit_edge_rst_stream(slot: H2EdgeSlot&, stream_id: u32, error_code: u32) -> bool {
    guard stream_id > 0 else { return false; }
    var p: u8[..4] = [];
    p.append_u32_be(error_code);
    return append_edge_frame(slot.wire_out, rfc::H2_FRAME_RST_STREAM, rfc::H2_FLAG_NONE, stream_id, p[..]);
}

fn emit_edge_goaway(slot: H2EdgeSlot&, error_code: u32) -> bool {
    let last_sid = slot.conn.last_peer_stream_id & 0x7FFFFFFF;
    var p: u8[..8] = [];
    p.append_u32_be(last_sid);
    p.append_u32_be(error_code);
    guard append_edge_frame(slot.wire_out, rfc::H2_FRAME_GOAWAY, rfc::H2_FLAG_NONE, 0, p[..]) else {
        return false;
    }
    slot.conn.goaway_sent = true;
    slot.conn.goaway_last_stream_id = last_sid;
    slot.conn.goaway_error_code = error_code;
    return true;
}

fn fail_edge_connection(slot: H2EdgeSlot&, error_code: u32) -> bool {
    if !slot.conn_failed {
        slot.conn_failed = true;
        slot.conn.continuation_stream_id = 0;
        slot.refused_cont_stream_id = 0;
        if slot.header_accum.len > 0 {
            core::secure_zeroize_slice(slot.header_accum[..]);
        }
        slot.header_accum.clear();
        let _ = emit_edge_goaway(slot, error_code);
        let _ = enqueue_edge_event(
            slot, H2EdgeEventKind.ProtocolError, slot.conn.last_peer_stream_id, -1, "", false, error_code,
        );
    }
    return false;
}

fn reject_edge_stream(slot: H2EdgeSlot&, stream_id: u32, error_code: u32) -> bool {
    let now_ms = slot.conn.reset_limiter.last_refill_ms;
    guard core::token_bucket_consume(slot.conn.reset_limiter, now_ms) else {
        return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    reset_stream(slot.conn, stream_id);
    guard emit_edge_rst_stream(slot, stream_id, error_code) else {
        return fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
    }
    let _ = enqueue_edge_event(slot, H2EdgeEventKind.StreamReset, stream_id, -1, "", false, error_code);
    return true;
}

// ---- HTTP/2 Header & Pseudo-Header Materialization (RFC 9113 Section 8) --

inline fn is_forbidden_h2_field(raw_name: const u8[:]) -> bool {
    return rfc::is_connection_specific_header(raw_name) || raw_name.eq_ascii_fold("te");
}

fn append_edge_hdr_buf_entry(
    out_hb:      H2EdgeHdrBuf&,
    name:        const u8[:],
    val:         const u8[:],
    extra_flags: u8 = 0,
) -> bool {
    let trimmed = val.trim_lws();
    let needed = core::add_sat_i64(name.len, trimmed.len);
    guard out_hb.entries.len < H2_EDGE_MAX_HEADER_ENTRIES &&
          core::add_sat_i64(out_hb.raw.len, needed) <= http::MAX_OVERFLOW_RAW_BYTES else {
        return false;
    }
    let nb = out_hb.raw.len as u16;
    out_hb.raw.append(name);
    let ne = out_hb.raw.len as u16;
    out_hb.raw.append(trimmed);
    let ve = out_hb.raw.len as u16;
    let ent, _, _ = http::make_header_entry(
        name, trimmed, nb, ne, ne, ve, http::HEADER_SRC_STACK, extra_flags,
    );
    out_hb.entries.push(ent);
    return true;
}

fn copy_decoded_headers_to_hdr_buf(
    decoded:       const http::HeaderMap&,
    decoded_arena: const http::OverflowArena&,
    out_hb:        H2EdgeHdrBuf&,
) -> bool {
    let total = http::header_count_spill(decoded, decoded_arena);
    for i in total {
        let e, ok_e = http::header_entry_at_spill(decoded, decoded_arena, i);
        guard ok_e else { return false; }
        let n = http::entry_name_spill(decoded, decoded_arena, e);
        let v = http::entry_value_spill(decoded, decoded_arena, e);
        guard append_edge_hdr_buf_entry(out_hb, n, v, e.flags & http::HEADER_FLAG_SENSITIVE) else {
            return false;
        }
    }
    return true;
}

// Builds a pooled `H2EdgeHdrBuf` containing validated HTTP/2 request pseudo-headers followed by regular headers.
//
// Example:
//   pseudo = PseudoHeaders { method: "GET", path: "/", .. }, decoded = HeaderMap { .. }
//   returns: out_hb has ":method" = "GET", ":path" = "/", true
fn build_request_event_hdr_buf(
    pseudo:        const PseudoHeaders&,
    decoded:       const http::HeaderMap&,
    decoded_arena: const http::OverflowArena&,
    out_hb:        H2EdgeHdrBuf&,
) -> bool {
    out_hb.entries.clear();
    out_hb.raw.clear();
    var committed = false;
    defer if !committed {
        out_hb.entries.clear();
        if out_hb.raw.len > 0 {
            core::secure_zeroize_slice(out_hb.raw[..]);
        }
        out_hb.raw.clear();
    };
    if pseudo.has_method {
        guard append_edge_hdr_buf_entry(out_hb, ":method", pseudo.method[..]) else { return false; }
    }
    if pseudo.has_protocol {
        guard append_edge_hdr_buf_entry(out_hb, ":protocol", pseudo.protocol[..]) else { return false; }
    }
    if pseudo.has_scheme {
        guard append_edge_hdr_buf_entry(out_hb, ":scheme", pseudo.scheme[..]) else { return false; }
    }
    if pseudo.has_authority {
        guard append_edge_hdr_buf_entry(out_hb, ":authority", pseudo.authority[..]) else { return false; }
    }
    if pseudo.has_path {
        guard append_edge_hdr_buf_entry(out_hb, ":path", pseudo.path[..]) else { return false; }
    }
    guard copy_decoded_headers_to_hdr_buf(decoded, decoded_arena, out_hb) else { return false; }
    committed = true;
    return true;
}

fn finalize_edge_header_block(slot: H2EdgeSlot&) -> bool {
    let sid = slot.hdr_stream_id;
    let is_trailer = slot.hdr_is_trailer;
    let end_stream = slot.hdr_end_stream;
    var pseudo = PseudoHeaders { is_trailer: is_trailer, .. };
    var decoded = http::HeaderMap { .. };
    var decoded_arena = http::OverflowArena { .. };
    defer {
        http::reset_overflow_arena(decoded_arena);
        core::secure_zeroize_slice(decoded.raw_buf[..]);
    };
    // RFC 9113 Section 4.3: Field Section Compression and Decompression - Keep HPACK table state synchronized.
    let dec_err = decode_hpack_to_map_spill(
        slot.conn.hpack_dec,
        slot.header_accum[..],
        pseudo,
        decoded,
        decoded_arena,
        slot.conn.max_header_list_size,
        true,
    );
    if slot.header_accum.len > 0 {
        core::secure_zeroize_slice(slot.header_accum[..]);
    }
    slot.header_accum.clear();
    slot.hdr_stream_id = 0;
    let rej_err = slot.hdr_reject_err;
    slot.hdr_reject_err = rfc::H2_ERR_NO_ERROR;

    if dec_err != rfc::H2_ERR_NO_ERROR {
        if dec_err == rfc::H2_ERR_COMPRESSION_ERROR || dec_err == rfc::H2_ERR_ENHANCE_YOUR_CALM {
            return fail_edge_connection(slot, dec_err);
        }
        return reject_edge_stream(slot, sid, dec_err);
    }
    if rej_err != rfc::H2_ERR_NO_ERROR {
        return reject_edge_stream(slot, sid, rej_err);
    }

    if is_trailer {
        let h_slot = alloc_edge_hdr_buf();
        guard copy_decoded_headers_to_hdr_buf(decoded, decoded_arena, g_h2_edge_hdr_bufs[h_slot]) else {
            free_edge_hdr_buf(h_slot);
            return reject_edge_stream(slot, sid, rfc::H2_ERR_ENHANCE_YOUR_CALM);
        }
        return enqueue_edge_event(slot, H2EdgeEventKind.RequestEnd, sid, h_slot, "", true, 0);
    }

    // RFC 9113 Section 8.3.1: Request Pseudo-Header Fields - Requests must omit :status and carry :method.
    if pseudo.has_status || !pseudo.has_method {
        return reject_edge_stream(slot, sid, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    // RFC 9113 Section 8.1.1: Malformed Messages - Non-zero Content-Length on an END_STREAM HEADERS frame is malformed.
    if end_stream && pseudo.has_content_length && pseudo.content_length_val != 0 {
        return reject_edge_stream(slot, sid, rfc::H2_ERR_PROTOCOL_ERROR);
    }

    let s_idx, found = find_stream_idx(slot.conn, sid);
    if found && pseudo.has_content_length {
        slot.conn.streams[s_idx].declared_content_length = pseudo.content_length_val;
    }

    let h_slot = alloc_edge_hdr_buf();
    guard build_request_event_hdr_buf(pseudo, decoded, decoded_arena, g_h2_edge_hdr_bufs[h_slot]) else {
        free_edge_hdr_buf(h_slot);
        return reject_edge_stream(slot, sid, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    return enqueue_edge_event(slot, H2EdgeEventKind.RequestHead, sid, h_slot, "", end_stream, 0);
}

// RFC 7540 Section 5.3.1: Stream Dependencies - Returns PROTOCOL_ERROR if HEADERS+PRIORITY depends on itself.
inline fn headers_priority_self_dep_error(
    hdr:                   const FrameHeader&,
    payload:               const u8[:],
    no_rfc7540_priorities: bool,
) -> u32 {
    guard !no_rfc7540_priorities && (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 else {
        return rfc::H2_ERR_NO_ERROR;
    }
    let prio_off: i64 = if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 { 1 } else { 0 };
    let dep_raw = core::read_be_u32(payload, prio_off) & 0x7FFFFFFF;
    return if dep_raw == hdr.stream_id { rfc::H2_ERR_PROTOCOL_ERROR } else { rfc::H2_ERR_NO_ERROR };
}

fn ingest_edge_headers_or_continuation(
    slot:       H2EdgeSlot&,
    hdr:        const FrameHeader&,
    payload:    const u8[:],
    is_trailer: bool,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        let hpack_frag, ext_err = extract_headers_frame_payload(hdr, payload, true);
        if ext_err != rfc::H2_ERR_NO_ERROR {
            return fail_edge_connection(slot, ext_err);
        }
        slot.hdr_stream_id = hdr.stream_id;
        slot.hdr_end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
        slot.hdr_is_trailer = is_trailer;
        slot.hdr_reject_err = headers_priority_self_dep_error(
            hdr, payload, slot.conn.no_rfc7540_priorities,
        );
        slot.header_accum.clear();
        guard slot.header_accum.try_append(hpack_frag) else {
            return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
        }
    } else {
        guard hdr.stream_id == slot.hdr_stream_id else {
            return fail_edge_connection(slot, rfc::H2_ERR_PROTOCOL_ERROR);
        }
        guard slot.header_accum.try_append(payload) else {
            return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
        }
    }

    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 {
        return finalize_edge_header_block(slot);
    }
    return true;
}

// ---- Frame Ingress Handlers (RFC 9113 Section 6) -------------------------

fn apply_single_edge_setting(slot: H2EdgeSlot&, param_id: u16, val: u32) -> u32 {
    let st_err = validate_settings_parameter(param_id, val, false);
    guard st_err == rfc::H2_ERR_NO_ERROR else { return st_err; }

    if param_id == rfc::H2_SETTING_HEADER_TABLE_SIZE {
        let cap = min(val as u64, slot.hpack_enc.max_allowed_size);
        if !slot.hpack_enc_pending_size_update || cap < slot.hpack_enc_pending_min_size {
            slot.hpack_enc_pending_min_size = cap;
        }
        slot.hpack_enc.current_max_size = cap;
        evict_until(slot.hpack_enc, cap);
        slot.hpack_enc_pending_size_update = true;
        return rfc::H2_ERR_NO_ERROR;
    }
    if param_id == rfc::H2_SETTING_MAX_CONCURRENT_STREAMS {
        slot.peer_max_concurrent_streams = val;
        return rfc::H2_ERR_NO_ERROR;
    }
    if param_id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE {
        return apply_peer_initial_window_size_delta(slot.conn, val);
    }
    if param_id == rfc::H2_SETTING_MAX_FRAME_SIZE {
        slot.conn.peer_max_frame_size = val;
        return rfc::H2_ERR_NO_ERROR;
    }
    if param_id == rfc::H2_SETTING_MAX_HEADER_LIST_SIZE {
        slot.has_peer_max_header_list_size = true;
        slot.peer_max_header_list_size = val;
        return rfc::H2_ERR_NO_ERROR;
    }
    if param_id == rfc::H2_SETTING_NO_RFC7540_PRIORITIES {
        let no_prio = (val == 1);
        if slot.conn.peer_no_rfc7540_set && no_prio != slot.conn.no_rfc7540_priorities {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        slot.conn.no_rfc7540_priorities = no_prio;
        slot.conn.peer_no_rfc7540_set = true;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn ingest_edge_settings_frame(slot: H2EdgeSlot&, hdr: const FrameHeader&, payload: const u8[:]) -> bool {
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        return true;
    }
    var i: i64 = 0;
    while core::add_sat_i64(i, 6) <= payload.len {
        let param_id = core::read_be_u16(payload, i);
        let val = core::read_be_u32(payload, core::add_sat_i64(i, 2));
        let err = apply_single_edge_setting(slot, param_id, val);
        if err != rfc::H2_ERR_NO_ERROR {
            return fail_edge_connection(slot, err);
        }
        i = core::add_sat_i64(i, 6);
    }
    slot.conn.peer_no_rfc7540_set = true;
    // RFC 9113 Section 6.5.3: Settings Synchronization - Acknowledge peer SETTINGS with an empty ACK frame.
    guard append_edge_frame(slot.wire_out, rfc::H2_FRAME_SETTINGS, rfc::H2_FLAG_ACK, 0, "") else {
        return fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
    }
    slot.queued_control_acks = core::add_sat_u32(slot.queued_control_acks, 1);
    return true;
}

fn ingest_edge_window_update(slot: H2EdgeSlot&, hdr: const FrameHeader&, payload: const u8[:]) -> bool {
    let inc = core::read_be_u32(payload, 0) & 0x7FFFFFFF;
    let wu_err = apply_window_update(slot.conn, hdr.stream_id, inc);
    guard wu_err != rfc::H2_ERR_NO_ERROR else { return true; }

    // RFC 9113 Section 6.9: WINDOW_UPDATE - Stream window overflow sends RST_STREAM; connection or idle errors send GOAWAY.
    if hdr.stream_id == 0 || is_conn_error_on_window_update(slot.conn, hdr.stream_id) {
        return fail_edge_connection(slot, wu_err);
    }
    return reject_edge_stream(slot, hdr.stream_id, wu_err);
}

fn replenish_edge_conn_recv_window(slot: H2EdgeSlot&, consumed_len: u32) {
    guard consumed_len > 0 else { return; }
    let thresh = max(1, min(H2_EDGE_MIN_REPLENISH, slot.conn.local_initial_window_size >> 1));
    let max_win: i64 = rfc::H2_MAX_WINDOW_SIZE;
    slot.conn.unclaimed_recv_window = core::add_sat_i64(slot.conn.unclaimed_recv_window, consumed_len);
    guard slot.conn.unclaimed_recv_window >= thresh else { return; }
    let upd_i64 = min(slot.conn.unclaimed_recv_window, max_win);
    if upd_i64 > 0 && emit_edge_window_update(slot, 0, upd_i64 as u32) {
        slot.conn.conn_recv_window = core::add_sat_i64(slot.conn.conn_recv_window, upd_i64);
        slot.conn.unclaimed_recv_window = core::sub_sat_i64(slot.conn.unclaimed_recv_window, upd_i64);
    }
}

fn replenish_edge_recv_windows(slot: H2EdgeSlot&, hdr: const FrameHeader&) {
    replenish_edge_conn_recv_window(slot, hdr.length);

    guard (hdr.flags & rfc::H2_FLAG_END_STREAM) == 0 else { return; }
    let thresh = max(1, min(H2_EDGE_MIN_REPLENISH, slot.conn.local_initial_window_size >> 1));
    let max_win: i64 = rfc::H2_MAX_WINDOW_SIZE;
    let s_idx, found = find_stream_idx(slot.conn, hdr.stream_id);
    guard found && s_idx >= 0 && s_idx < 128 else { return; }
    if slot.stream_unclaimed_id[s_idx] != hdr.stream_id {
        slot.stream_unclaimed_id[s_idx] = hdr.stream_id;
        slot.stream_unclaimed_rx[s_idx] = 0;
    }
    let next_u = core::add_sat_i64(slot.stream_unclaimed_rx[s_idx], hdr.length);
    slot.stream_unclaimed_rx[s_idx] = next_u;
    if next_u >= thresh {
        let s_upd = min(next_u, max_win);
        if s_upd > 0 && emit_edge_window_update(slot, hdr.stream_id, s_upd as u32) {
            slot.conn.streams[s_idx].recv_window = core::add_sat_i64(slot.conn.streams[s_idx].recv_window, s_upd);
            slot.stream_unclaimed_rx[s_idx] = core::sub_sat_i64(next_u, s_upd);
        }
    }
}

fn ingest_edge_data_frame(slot: H2EdgeSlot&, hdr: const FrameHeader&, payload: const u8[:]) -> bool {
    let data_bytes, pad_err = extract_padded_frame_payload(hdr, payload);
    if pad_err != rfc::H2_ERR_NO_ERROR {
        return fail_edge_connection(slot, pad_err);
    }

    let is_odd = (hdr.stream_id & 1) == 1;
    let _, was_open = find_stream_idx(slot.conn, hdr.stream_id);
    let d_err = on_data_frame_received(slot.conn, hdr, data_bytes.len as u32);
    if d_err != rfc::H2_ERR_NO_ERROR {
        if slot.conn.conn_recv_window < 0 || !is_odd || (!was_open && d_err != rfc::H2_ERR_STREAM_CLOSED) {
            return fail_edge_connection(slot, d_err);
        }
        replenish_edge_conn_recv_window(slot, hdr.length);
        return reject_edge_stream(slot, hdr.stream_id, d_err);
    }

    if data_bytes.len > 0 {
        guard enqueue_edge_event(
            slot, H2EdgeEventKind.RequestData, hdr.stream_id, -1, data_bytes, false, 0,
        ) else {
            return fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
        }
    }
    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        guard enqueue_edge_event(
            slot, H2EdgeEventKind.RequestEnd, hdr.stream_id, -1, "", true, 0,
        ) else {
            return fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
        }
    }
    replenish_edge_recv_windows(slot, hdr);
    return true;
}

fn ingest_edge_goaway_frame(slot: H2EdgeSlot&, payload: const u8[:]) -> bool {
    let last_sid = core::read_be_u32(payload, 0);
    let err_code = core::read_be_u32(payload, 4);
    let g_err = apply_goaway(slot.conn, last_sid, err_code);
    if g_err != rfc::H2_ERR_NO_ERROR {
        return fail_edge_connection(slot, g_err);
    }
    return enqueue_edge_event(slot, H2EdgeEventKind.GoAway, last_sid & 0x7FFFFFFF, -1, "", false, err_code);
}

fn finish_refused_hpack_sync(slot: H2EdgeSlot&, stream_id: u32) -> bool {
    var tmp_pseudo = PseudoHeaders { .. };
    var tmp_hdrs = http::HeaderMap { .. };
    var tmp_arena = http::OverflowArena { .. };
    defer {
        http::reset_overflow_arena(tmp_arena);
        core::secure_zeroize_slice(tmp_hdrs.raw_buf[..]);
    };
    let dec_err = decode_hpack_to_map_spill(
        slot.conn.hpack_dec,
        slot.header_accum[..],
        tmp_pseudo,
        tmp_hdrs,
        tmp_arena,
        slot.conn.max_header_list_size,
        false,
    );
    core::secure_zeroize_slice(slot.header_accum[..]);
    slot.header_accum.clear();
    slot.refused_cont_stream_id = 0;
    slot.refused_cont_frames_cnt = 0;
    if dec_err == rfc::H2_ERR_COMPRESSION_ERROR {
        return fail_edge_connection(slot, dec_err);
    }
    return reject_edge_stream(slot, stream_id, rfc::H2_ERR_REFUSED_STREAM);
}

fn step_refused_continuation(
    slot:    H2EdgeSlot&,
    hdr:     const FrameHeader&,
    payload: const u8[:],
    now_ms:  u64,
) -> bool {
    if hdr.length > slot.conn.local_max_frame_size {
        return fail_edge_connection(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    if hdr.frame_type != rfc::H2_FRAME_CONTINUATION || hdr.stream_id != slot.refused_cont_stream_id {
        return fail_edge_connection(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    if hdr.length == 0 && (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        return fail_edge_connection(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    if core::sub_sat_u64(now_ms, slot.refused_cont_start_ms) > slot.conn.max_header_block_duration_ms {
        return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    let next_cnt = core::add_sat_u32(slot.refused_cont_frames_cnt, 1);
    let max_hdr: i64 = slot.conn.max_header_list_size;
    let next_sz = core::add_sat_i64(slot.header_accum.len, hdr.length);
    if next_cnt > MAX_CONT_FRAMES_LIMIT || next_sz > max_hdr {
        return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    guard slot.header_accum.try_append(payload) else {
        return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    slot.refused_cont_frames_cnt = next_cnt;
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 {
        return finish_refused_hpack_sync(slot, hdr.stream_id);
    }
    return true;
}

fn start_refused_headers_stream(
    slot:    H2EdgeSlot&,
    hdr:     const FrameHeader&,
    payload: const u8[:],
    now_ms:  u64,
) -> bool {
    if !(slot.conn.goaway_received || slot.conn.goaway_sent) &&
       (hdr.stream_id & 1) == 1 && hdr.stream_id > slot.conn.last_peer_stream_id {
        slot.conn.last_peer_stream_id = hdr.stream_id;
    }
    let frag, ext_err = extract_headers_frame_payload(hdr, payload, slot.conn.no_rfc7540_priorities);
    guard ext_err == rfc::H2_ERR_NO_ERROR else {
        return fail_edge_connection(slot, ext_err);
    }
    slot.header_accum.clear();
    guard slot.header_accum.try_append(frag) else {
        return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 {
        return finish_refused_hpack_sync(slot, hdr.stream_id);
    }
    slot.refused_cont_stream_id = hdr.stream_id;
    slot.refused_cont_frames_cnt = 0;
    slot.refused_cont_start_ms = now_ms;
    return true;
}

fn handle_edge_ingress_error(
    slot:    H2EdgeSlot&,
    hdr:     const FrameHeader&,
    payload: const u8[:],
    ing_err: u32,
    now_ms:  u64,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY && hdr.stream_id != 0 &&
       ing_err == rfc::H2_ERR_FRAME_SIZE_ERROR && slot.conn.continuation_stream_id == 0 {
        return reject_edge_stream(slot, hdr.stream_id, ing_err);
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS && ing_err == rfc::H2_ERR_REFUSED_STREAM &&
       slot.conn.continuation_stream_id == 0 {
        return start_refused_headers_stream(slot, hdr, payload, now_ms);
    }
    return fail_edge_connection(slot, ing_err);
}

fn ingest_edge_priority_frame(slot: H2EdgeSlot&, hdr: const FrameHeader&, payload: const u8[:]) -> bool {
    guard payload.len == 5 else {
        return reject_edge_stream(slot, hdr.stream_id, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    let dep_raw = core::read_be_u32(payload, 0) & 0x7FFFFFFF;
    if !slot.conn.no_rfc7540_priorities && dep_raw == hdr.stream_id {
        return reject_edge_stream(slot, hdr.stream_id, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    return true;
}

fn ingest_edge_priority_update_frame(slot: H2EdgeSlot&, payload: const u8[:]) -> bool {
    let now_ms = slot.conn.reset_limiter.last_refill_ms;
    guard core::token_bucket_consume(slot.conn.reset_limiter, now_ms) else {
        return fail_edge_connection(slot, rfc::H2_ERR_ENHANCE_YOUR_CALM);
    }
    let psid, prio, pu_err = parse_priority_update_payload(payload, true);
    if pu_err == rfc::H2_ERR_FRAME_SIZE_ERROR || psid == 0 {
        let err_code = if pu_err == rfc::H2_ERR_FRAME_SIZE_ERROR {
            pu_err
        } else {
            rfc::H2_ERR_PROTOCOL_ERROR
        };
        return fail_edge_connection(slot, err_code);
    }
    if pu_err == rfc::H2_ERR_NO_ERROR {
        let ap_err = apply_priority_update(slot.conn, psid, prio);
        if ap_err != rfc::H2_ERR_NO_ERROR {
            return fail_edge_connection(slot, ap_err);
        }
    }
    return true;
}

fn dispatch_edge_control_frame(
    slot:    H2EdgeSlot&,
    hdr:     const FrameHeader&,
    payload: const u8[:],
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS { return ingest_edge_settings_frame(slot, hdr, payload); }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE { return ingest_edge_window_update(slot, hdr, payload); }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY { return ingest_edge_priority_frame(slot, hdr, payload); }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY { return ingest_edge_goaway_frame(slot, payload); }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY_UPDATE {
        return ingest_edge_priority_update_frame(slot, payload);
    }
    if hdr.frame_type == rfc::H2_FRAME_PING && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        guard append_edge_frame(slot.wire_out, rfc::H2_FRAME_PING, rfc::H2_FLAG_ACK, 0, payload) else {
            return false;
        }
        slot.queued_control_acks = core::add_sat_u32(slot.queued_control_acks, 1);
    }
    return true;
}

fn dispatch_edge_frame(slot: H2EdgeSlot&, raw_frame: const u8[:], now_ms: u64) -> bool {
    let hdr, hdr_err = parse_frame_header(raw_frame[..rfc::H2_FRAME_HEADER_LEN], slot.conn.local_max_frame_size);
    if hdr_err != rfc::H2_ERR_NO_ERROR {
        return fail_edge_connection(slot, hdr_err);
    }
    let payload = raw_frame[rfc::H2_FRAME_HEADER_LEN..];

    // RFC 9113 Section 3.4: HTTP/2 Connection Preface - First peer frame MUST be non-ACK SETTINGS on stream 0.
    if !slot.first_settings_received {
        guard hdr.frame_type == rfc::H2_FRAME_SETTINGS
            && (hdr.flags & rfc::H2_FLAG_ACK) == 0
            && hdr.stream_id == 0 else {
            return fail_edge_connection(slot, rfc::H2_ERR_PROTOCOL_ERROR);
        }
        slot.first_settings_received = true;
    }

    if slot.refused_cont_stream_id != 0 {
        return step_refused_continuation(slot, hdr, payload, now_ms);
    }

    var is_trailer_hdr = false;
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        let ex_idx, ex_found = find_stream_idx(slot.conn, hdr.stream_id);
        is_trailer_hdr = ex_found && slot.conn.streams[ex_idx].headers_received;
    }

    let ing_err = on_ingress_frame_header(slot.conn, hdr, now_ms);
    if ing_err != rfc::H2_ERR_NO_ERROR {
        return handle_edge_ingress_error(slot, hdr, payload, ing_err, now_ms);
    }

    if hdr.frame_type == rfc::H2_FRAME_DATA { return ingest_edge_data_frame(slot, hdr, payload); }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS || hdr.frame_type == rfc::H2_FRAME_CONTINUATION {
        return ingest_edge_headers_or_continuation(slot, hdr, payload, is_trailer_hdr);
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM {
        return enqueue_edge_event(
            slot, H2EdgeEventKind.StreamReset, hdr.stream_id, -1, "", false, core::read_be_u32(payload, 0),
        );
    }
    return dispatch_edge_control_frame(slot, hdr, payload);
}

// ---- Preface & Partial-Frame Reassembly Cursors ------------------------

// Incrementally matches and consumes the 24-byte client connection preface (RFC 9113 Section 3.4).
//
// Example:
//   chunk = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", pos = 0
//   returns: true, pos = 24, slot.preface_done = true
fn consume_edge_preface(slot: H2EdgeSlot&, chunk: const u8[:], pos: i64&) -> bool {
    let prefix_idx = slot.wire_in.len;
    let rem_pref = core::sub_sat_i64(rfc::H2_CLIENT_PREFACE.len, prefix_idx);
    let rem_chunk = core::sub_sat_i64(chunk.len, pos);
    let need = min(rem_pref, rem_chunk);
    let end_pos = core::add_sat_i64(pos, need);
    let end_pref = core::add_sat_i64(prefix_idx, need);
    guard chunk[pos..end_pos] == rfc::H2_CLIENT_PREFACE[prefix_idx..end_pref] else {
        return fail_edge_connection(slot, rfc::H2_ERR_PROTOCOL_ERROR);
    }
    guard slot.wire_in.try_append(chunk[pos..end_pos]) else {
        return fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
    }
    pos = end_pos;
    if slot.wire_in.len == rfc::H2_CLIENT_PREFACE.len {
        slot.preface_done = true;
        slot.wire_in.clear();
    }
    return true;
}

// Appends up to `target_len - slot.wire_in.len` bytes from `chunk[pos..]` into `slot.wire_in`.
//
// Example:
//   chunk = frame bytes, pos = 0, target_len = 9
//   returns: reached_target, ok = true, pos advances by copied bytes
fn pull_into_wire_in(
    slot:       H2EdgeSlot&,
    chunk:      const u8[:],
    pos:        i64&,
    target_len: i64,
) -> bool, bool {
    guard slot.wire_in.len < target_len else { return true, true; }
    let need = core::sub_sat_i64(target_len, slot.wire_in.len);
    let rem = core::sub_sat_i64(chunk.len, pos);
    let take = min(need, rem);
    let end_pos = core::add_sat_i64(pos, take);
    guard slot.wire_in.try_append(chunk[pos..end_pos]) else {
        return false, fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
    }
    pos = end_pos;
    return slot.wire_in.len >= target_len, true;
}

// Reassembles one split frame inside `slot.wire_in` and dispatches it when complete.
//
// Example:
//   chunk = remaining frame tail, pos = 0, slot.wire_in contains partial header/payload
//   returns: should_continue, ok = true, pos advances to end of frame
fn process_buffered_wire_in_frame(
    slot:   H2EdgeSlot&,
    chunk:  const u8[:],
    pos:    i64&,
    now_ms: u64,
) -> bool, bool {
    let hdr_ready, ok_hdr = pull_into_wire_in(slot, chunk, pos, rfc::H2_FRAME_HEADER_LEN);
    guard ok_hdr else { return false, false; }
    guard hdr_ready else { return false, true; }

    let hdr, hdr_err = parse_frame_header(slot.wire_in[..rfc::H2_FRAME_HEADER_LEN], slot.conn.local_max_frame_size);
    if hdr_err != rfc::H2_ERR_NO_ERROR {
        return false, fail_edge_connection(slot, hdr_err);
    }
    let total_len = core::add_sat_i64(rfc::H2_FRAME_HEADER_LEN, hdr.length);
    guard total_len <= slot.wire_in.cap else {
        return false, fail_edge_connection(slot, rfc::H2_ERR_FRAME_SIZE_ERROR);
    }
    let frame_ready, ok_pay = pull_into_wire_in(slot, chunk, pos, total_len);
    guard ok_pay else { return false, false; }
    guard frame_ready else { return false, true; }

    let ok_disp = dispatch_edge_frame(slot, slot.wire_in[..total_len], now_ms);
    slot.wire_in.clear();
    return ok_disp && (pos < chunk.len), ok_disp;
}

// Processes a complete frame directly from `chunk[pos..]` or stages a partial frame into `slot.wire_in`.
//
// Example:
//   chunk = full 9-byte PING ACK frame, pos = 0
//   returns: should_continue = false, ok = true, pos = 17
fn process_direct_chunk_frame(
    slot:   H2EdgeSlot&,
    chunk:  const u8[:],
    pos:    i64&,
    now_ms: u64,
) -> bool, bool {
    let rem = core::sub_sat_i64(chunk.len, pos);
    if rem < rfc::H2_FRAME_HEADER_LEN {
        guard slot.wire_in.try_append(chunk[pos..]) else {
            return false, fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
        }
        pos = chunk.len;
        return false, true;
    }

    let hdr_end = core::add_sat_i64(pos, rfc::H2_FRAME_HEADER_LEN);
    let hdr, hdr_err = parse_frame_header(chunk[pos..hdr_end], slot.conn.local_max_frame_size);
    if hdr_err != rfc::H2_ERR_NO_ERROR {
        return false, fail_edge_connection(slot, hdr_err);
    }
    let total_len = core::add_sat_i64(rfc::H2_FRAME_HEADER_LEN, hdr.length);
    if rem < total_len {
        guard slot.wire_in.try_append(chunk[pos..]) else {
            return false, fail_edge_connection(slot, rfc::H2_ERR_INTERNAL_ERROR);
        }
        pos = chunk.len;
        return false, true;
    }

    let next_pos = core::add_sat_i64(pos, total_len);
    let frame_slice = chunk[pos..next_pos];
    pos = next_pos;
    let ok_disp = dispatch_edge_frame(slot, frame_slice, now_ms);
    return ok_disp && (pos < chunk.len), ok_disp;
}

// ---- Outbound HPACK Response & Header Fragmentation Helpers --------------

fn encode_single_edge_resp_header_slices(
    dt:            DynamicTable&,
    headers:       const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    e:             const http::HeaderEntry&,
    lower_name:    u8[..256]&,
    out:           u8[>..]&,
) -> bool {
    let raw_name = http::resolve_entry_name_buf(headers.raw_buf[..], spill_raw, e);
    let val = http::resolve_entry_value_buf(headers.raw_buf[..], spill_raw, e);
    let in_conn = http::entries_have_connection_token(headers.entries[..], headers.raw_buf[..], spill_raw, raw_name) ||
        http::entries_have_connection_token(spill_entries, headers.raw_buf[..], spill_raw, raw_name);
    if (raw_name.len > 0 && raw_name[0] == ':') || is_forbidden_h2_field(raw_name) || in_conn {
        return true;
    }
    guard raw_name.len > 0 && raw_name.len <= lower_name.cap else { return false; }
    lower_name.clear();
    raw_name.to_lower_ascii(lower_name);
    guard validate_field_syntax(lower_name[..], val) else { return false; }
    let idx_mode = if http::is_sensitive(e) {
        HpackIndexing.NeverIndexed
    } else {
        select_hpack_indexing(lower_name[..], val, dt.current_max_size as i64)
    };
    return encode_hpack_field(dt, out, lower_name[..], val, idx_mode, true);
}

fn encode_edge_resp_entries_slices(
    dt:            DynamicTable&,
    entries:       const http::HeaderEntry[:],
    headers:       const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    lower_name:    u8[..256]&,
    out:           u8[>..]&,
) -> bool {
    for &e in entries {
        guard encode_single_edge_resp_header_slices(
            dt, headers, spill_entries, spill_raw, e, lower_name, out,
        ) else {
            return false;
        }
    }
    return true;
}

// Encodes HTTP/2 response `:status` and filtered headers into `out` using dynamic HPACK compression.
//
// Example:
//   status_code = 200, headers = {"content-type": "text/plain"}
//   returns: out holds HPACK bytes with ":status: 200", ok = true
fn encode_edge_response_hpack_slices(
    dt:                DynamicTable&,
    pending_sz_update: bool&,
    pending_min_sz:    u64&,
    status_code:       i32,
    headers:           const http::HeaderMap&,
    spill_entries:     const http::HeaderEntry[:],
    spill_raw:         const u8[:],
    out:               u8[>..]&,
) -> bool {
    let saved_dt = dt;
    let saved_pending = pending_sz_update;
    let saved_min = pending_min_sz;
    let mark = out.len;
    var committed = false;
    defer if !committed {
        dt = saved_dt;
        pending_sz_update = saved_pending;
        pending_min_sz = saved_min;
        out.resize(mark);
    };

    if pending_sz_update {
        if pending_min_sz < dt.current_max_size {
            guard hpack_encode_int(out, pending_min_sz, 5, 0x20) else { return false; }
        }
        guard hpack_encode_int(out, dt.current_max_size, 5, 0x20) else { return false; }
        pending_sz_update = false;
        pending_min_sz = dt.current_max_size;
    }

    var st_buf: u8[..8] = [];
    let st_val: i64 = status_code;
    st_val.format_i64_dec(st_buf);
    guard encode_hpack_field(dt, out, ":status", st_buf[..], HpackIndexing.Incremental, true) else {
        return false;
    }

    var lower_name: u8[..256] = [];
    guard encode_edge_resp_entries_slices(
        dt, headers.entries[..], headers, spill_entries, spill_raw, lower_name, out,
    ) else {
        return false;
    }
    if spill_entries.len > 0 {
        guard encode_edge_resp_entries_slices(
            dt, spill_entries, headers, spill_entries, spill_raw, lower_name, out,
        ) else {
            return false;
        }
    }
    committed = true;
    return true;
}

inline fn calc_edge_hdr_flags(off: i64, next_off: i64, total_len: i64, end_stream: bool) -> u8 {
    var flags: u8 = 0;
    if off == 0 && end_stream {
        flags |= rfc::H2_FLAG_END_STREAM;
    }
    if next_off == total_len {
        flags |= rfc::H2_FLAG_END_HEADERS;
    }
    return flags;
}

fn emit_edge_header_fragments(
    slot:        H2EdgeSlot&,
    stream_id:   u32,
    hpack_bytes: const u8[:],
    end_stream:  bool,
) -> bool {
    let mark = slot.wire_out.len;
    var committed = false;
    defer if !committed { slot.wire_out.resize(mark); };
    let def_mf:  i64 = rfc::H2_DEFAULT_MAX_FRAME_SIZE;
    let peer_mf: i64 = slot.conn.peer_max_frame_size;
    let max_frame = max(def_mf, peer_mf);

    var off: i64 = 0;
    while off < hpack_bytes.len {
        let take = min(core::sub_sat_i64(hpack_bytes.len, off), max_frame);
        let next_off = core::add_sat_i64(off, take);
        let ftype = if off == 0 { rfc::H2_FRAME_HEADERS } else { rfc::H2_FRAME_CONTINUATION };
        let flags = calc_edge_hdr_flags(off, next_off, hpack_bytes.len, end_stream);
        guard append_edge_frame(slot.wire_out, ftype, flags, stream_id, hpack_bytes[off..next_off]) else {
            return false;
        }
        off = next_off;
    }
    committed = true;
    return true;
}

// ---- Public Sans-IO Streaming Server API ---------------------------------

fn current_edge_ms() -> u64 {
    let dur = core::Duration { nanos: max(0, core::sim_now_ns()) };
    let ms = max(0, dur.as_millis());
    return ms as u64;
}

fn alloc_edge_slot_idx() -> i64, u64 {
    let next_gen = if g_h2_edge_next_gen == 0xFFFFFFFFFFFFFFFF { 1 } else { core::add_sat_u64(g_h2_edge_next_gen, 1) };
    g_h2_edge_next_gen = next_gen;

    for i in g_h2_edge_slots.len {
        if !g_h2_edge_slots[i].in_use {
            return i, next_gen;
        }
    }
    guard g_h2_edge_slots.len < MAX_H2_EDGE_SLOTS else { return -1, 0; }
    let idx = g_h2_edge_slots.len;
    g_h2_edge_slots.push(H2EdgeSlot { .. });
    return idx, next_gen;
}

// Opens a thread-local HTTP/2 server session initialized with server settings preface.
fn h2_edge_open(max_concurrent_streams: u32 = 128, initial_window_size: u32 = 65535) -> H2EdgeSession {
    let now_ms = current_edge_ms();
    let eff_mcs = min(max_concurrent_streams, H2_EDGE_MAX_STREAMS);
    let eff_win = min(initial_window_size, rfc::H2_MAX_WINDOW_SIZE);
    let idx, next_gen = alloc_edge_slot_idx();
    guard idx >= 0 else { return H2EdgeSession { .. }; }

    let slot .= g_h2_edge_slots[idx];
    slot = H2EdgeSlot {
        in_use:     true,
        generation: next_gen,
        conn:       new_h2_connection(now_ms, H2_EDGE_MAX_HEADER_LIST, false),
        hpack_enc:  new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
        ..
    };
    slot.conn.is_server = true;
    slot.conn.enable_push = false;
    slot.conn.max_concurrent_streams = eff_mcs;
    slot.conn.local_initial_window_size = eff_win;
    slot.conn.local_max_frame_size = rfc::H2_DEFAULT_MAX_FRAME_SIZE;
    g_h2_edge_active_count = core::add_sat_i64(g_h2_edge_active_count, 1);
    let _ = emit_server_initial_settings(slot);
    return H2EdgeSession { slot_idx: idx, generation: next_gen };
}

// Closes an `H2EdgeSession`, releasing all pooled events, header maps, and slot buffers idempotently.
fn h2_edge_close(sess: H2EdgeSession&) {
    let idx = lookup_live_edge_slot_idx(sess);
    sess = H2EdgeSession { .. };
    guard idx >= 0 else { return; }
    let slot .= g_h2_edge_slots[idx];
    clear_slot_event_queue(slot);
    if slot.ev_hdr_raw.len > 0 {
        core::secure_zeroize_slice(slot.ev_hdr_raw[..]);
    }
    if slot.ev_data_buf.len > 0 {
        core::secure_zeroize_slice(slot.ev_data_buf[..]);
    }
    if slot.header_accum.len > 0 {
        core::secure_zeroize_slice(slot.header_accum[..]);
    }
    slot = H2EdgeSlot { .. };
    g_h2_edge_active_count = core::sub_sat_i64(g_h2_edge_active_count, 1);
}

// Feeds incoming TLS application bytes into `sess`, emitting parsed wire replies and queueing events.
//
// Example:
//   wire_chunk = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + <SETTINGS>
//   returns: consumed = wire_chunk.len, ok = true
fn h2_edge_feed(sess: H2EdgeSession&, wire_chunk: const u8[:]) -> i64, bool {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return 0, false; }
    let slot .= g_h2_edge_slots[idx];
    guard !slot.conn_failed else { return 0, false; }
    guard wire_chunk.len > 0 else { return 0, true; }

    let now_ms = current_edge_ms();
    var pos: i64 = 0;
    while pos < wire_chunk.len {
        if !slot.preface_done {
            guard consume_edge_preface(slot, wire_chunk, pos) else {
                return pos, false;
            }
            continue;
        }
        var more = false;
        var ok = false;
        if slot.wire_in.len > 0 {
            more, ok = process_buffered_wire_in_frame(slot, wire_chunk, pos, now_ms);
        } else {
            more, ok = process_direct_chunk_frame(slot, wire_chunk, pos, now_ms);
        }
        guard ok else { return pos, false; }
        if !more { break; }
    }
    return pos, true;
}

fn pop_edge_event_head(
    sess:         const H2EdgeSession&,
    out_slot_idx: i64&,
    out_ev_idx:   i64&,
    out_node:     H2EdgeEventNode&,
) -> bool {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return false; }
    let slot .= g_h2_edge_slots[idx];
    let ev_idx = slot.ev_head;
    guard ev_idx >= 0 else { return false; }

    let node = g_h2_edge_events[ev_idx];
    slot.ev_head = node.next_idx;
    if slot.ev_head < 0 {
        slot.ev_tail = -1;
    }
    slot.ev_hdr_entries.clear();
    if slot.ev_hdr_raw.len > 0 {
        core::secure_zeroize_slice(slot.ev_hdr_raw[..]);
    }
    slot.ev_hdr_raw.clear();
    out_slot_idx = idx;
    out_ev_idx = ev_idx;
    out_node = node;
    return true;
}

inline fn stage_edge_event_data(
    slot:     H2EdgeSlot&,
    node:     const H2EdgeEventNode&,
    out_data: const u8[:]&,
) -> bool {
    guard node.chunk_idx >= 0 else {
        out_data = "";
        return true;
    }
    let src = g_h2_edge_data_chunks[node.chunk_idx].buf[..];
    guard slot.ev_data_buf.try_set(src) else { return false; }
    out_data = slot.ev_data_buf[..];
    return true;
}

fn copy_hdr_buf_to_legacy_map(hb: const H2EdgeHdrBuf&, out_headers: http::HeaderMap&) -> bool {
    guard hb.raw.len <= 8192 && hb.entries.len <= 128 else { return false; }
    for &e in hb.entries {
        let nb: i64 = e.name_begin;
        let ne: i64 = e.name_end;
        let vb: i64 = e.values_begin;
        let ve: i64 = e.values_end;
        guard ne <= hb.raw.len && ve <= hb.raw.len else { return false; }
        guard out_headers.append_header(hb.raw[nb..ne], hb.raw[vb..ve]) else { return false; }
        if http::is_sensitive(e) && out_headers.entries.len > 0 {
            let last_idx = core::sub_sat_i64(out_headers.entries.len, 1);
            out_headers.entries[last_idx].flags |= http::HEADER_FLAG_SENSITIVE;
        }
    }
    return true;
}

fn can_legacy_poll_head(sess: const H2EdgeSession&) -> bool {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return true; }
    let slot .= g_h2_edge_slots[idx];
    guard slot.ev_head >= 0 else { return true; }
    let hs = g_h2_edge_events[slot.ev_head].header_slot;
    guard hs >= 0 else { return true; }
    let hb .= g_h2_edge_hdr_bufs[hs];
    return hb.raw.len <= 8192 && hb.entries.len <= 128;
}

// Pops the next event into `out_ev` when headers fit `HeaderMap` (<= 8192 B / 128 entries).
// Leaves oversized events queued and returns `false` (use `_spill` or `_view`).
// Any `out_ev.data` slice remains valid until the next poll, feed, or close on `sess`.
fn h2_edge_poll_event(sess: H2EdgeSession&, out_ev: H2EdgeEvent&) -> bool {
    out_ev = H2EdgeEvent { .. };
    guard can_legacy_poll_head(sess) else { return false; }
    var slot_idx: i64 = -1;
    var ev_idx:   i64 = -1;
    var node = H2EdgeEventNode { .. };
    guard pop_edge_event_head(sess, slot_idx, ev_idx, node) else { return false; }
    defer free_edge_event_node(ev_idx);

    var committed = false;
    defer if !committed { out_ev = H2EdgeEvent { .. }; };

    let slot .= g_h2_edge_slots[slot_idx];
    out_ev.kind = node.kind;
    out_ev.stream_id = node.stream_id;
    out_ev.end_stream = node.end_stream;
    out_ev.error_code = node.error_code;
    if node.header_slot >= 0 {
        guard copy_hdr_buf_to_legacy_map(g_h2_edge_hdr_bufs[node.header_slot], out_ev.headers) else {
            return false;
        }
    }
    guard stage_edge_event_data(slot, node, out_ev.data) else { return false; }
    committed = true;
    return true;
}

// Pops the next event into `out_ev` + `out_arena`, spilling headers up to 64 KiB / 512 entries when needed.
fn h2_edge_poll_event_spill(
    sess:      H2EdgeSession&,
    out_ev:    H2EdgeEvent&,
    out_arena: http::OverflowArena&,
) -> bool {
    out_ev = H2EdgeEvent { .. };
    http::reset_overflow_arena(out_arena);
    var slot_idx: i64 = -1;
    var ev_idx:   i64 = -1;
    var node = H2EdgeEventNode { .. };
    guard pop_edge_event_head(sess, slot_idx, ev_idx, node) else { return false; }
    defer free_edge_event_node(ev_idx);

    var committed = false;
    defer if !committed {
        out_ev = H2EdgeEvent { .. };
        http::reset_overflow_arena(out_arena);
    };

    let slot .= g_h2_edge_slots[slot_idx];
    out_ev.kind = node.kind;
    out_ev.stream_id = node.stream_id;
    out_ev.end_stream = node.end_stream;
    out_ev.error_code = node.error_code;
    if node.header_slot >= 0 {
        let hb .= g_h2_edge_hdr_bufs[node.header_slot];
        let hv = http::HeaderView { entries: hb.entries[..], raw: hb.raw[..] };
        guard http::header_view_copy_to_spill(hv, out_ev.headers, out_arena) else { return false; }
    }
    guard stage_edge_event_data(slot, node, out_ev.data) else { return false; }
    committed = true;
    return true;
}

// Pops the next event into `out_ev` with a zero-copy `http::HeaderView` into slot staging.
// Both `out_ev.headers` and `out_ev.data` remain valid until the next poll, feed, or close.
fn h2_edge_poll_event_view(sess: H2EdgeSession&, out_ev: H2EdgeEventView&) -> bool {
    out_ev = H2EdgeEventView { .. };
    var slot_idx: i64 = -1;
    var ev_idx:   i64 = -1;
    var node = H2EdgeEventNode { .. };
    guard pop_edge_event_head(sess, slot_idx, ev_idx, node) else { return false; }
    defer free_edge_event_node(ev_idx);

    let slot .= g_h2_edge_slots[slot_idx];
    var committed = false;
    defer if !committed {
        out_ev = H2EdgeEventView { .. };
        slot.ev_hdr_entries.clear();
        if slot.ev_hdr_raw.len > 0 {
            core::secure_zeroize_slice(slot.ev_hdr_raw[..]);
        }
        slot.ev_hdr_raw.clear();
    };

    slot.ev_hdr_entries.clear();
    if slot.ev_hdr_raw.len > 0 {
        core::secure_zeroize_slice(slot.ev_hdr_raw[..]);
    }
    slot.ev_hdr_raw.clear();
    out_ev.kind = node.kind;
    out_ev.stream_id = node.stream_id;
    out_ev.end_stream = node.end_stream;
    out_ev.error_code = node.error_code;
    if node.header_slot >= 0 {
        let hb .= g_h2_edge_hdr_bufs[node.header_slot];
        guard slot.ev_hdr_entries.try_append(hb.entries[..]) && slot.ev_hdr_raw.try_append(hb.raw[..]) else {
            return false;
        }
        out_ev.headers = http::HeaderView { entries: slot.ev_hdr_entries[..], raw: slot.ev_hdr_raw[..] };
    }
    guard stage_edge_event_data(slot, node, out_ev.data) else { return false; }
    committed = true;
    return true;
}

fn sum_edge_resp_entries_size(
    entries:       const http::HeaderEntry[:],
    headers:       const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
) -> u64 {
    var total: u64 = 0;
    for &e in entries {
        let raw_name = http::resolve_entry_name_buf(headers.raw_buf[..], spill_raw, e);
        let val = http::resolve_entry_value_buf(headers.raw_buf[..], spill_raw, e);
        let in_conn = http::entries_have_connection_token(
            headers.entries[..], headers.raw_buf[..], spill_raw, raw_name,
        ) || http::entries_have_connection_token(
            spill_entries, headers.raw_buf[..], spill_raw, raw_name,
        );
        if (raw_name.len > 0 && raw_name[0] == ':') || is_forbidden_h2_field(raw_name) || in_conn {
            continue;
        }
        let n_u64 = raw_name.len as u64;
        let v_u64 = val.len as u64;
        let item_sz = core::add_sat_u64(core::add_sat_u64(n_u64, v_u64), rfc::HPACK_ENTRY_OVERHEAD);
        total = core::add_sat_u64(total, item_sz);
    }
    return total;
}

// Computes the RFC 7541 Section 4.1 uncompressed header list size across stack + spill outbound response headers.
fn calc_edge_resp_header_list_size_slices(
    headers:       const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
) -> u64 {
    // ":status" (7) + 3-digit code (3) + HPACK_ENTRY_OVERHEAD (32)
    let stack_sz = sum_edge_resp_entries_size(headers.entries[..], headers, spill_entries, spill_raw);
    let spill_sz = sum_edge_resp_entries_size(spill_entries, headers, spill_entries, spill_raw);
    return core::add_sat_u64(42, core::add_sat_u64(stack_sz, spill_sz));
}

fn validate_edge_send_headers_slices(
    slot:          const H2EdgeSlot&,
    stream_id:     u32,
    status_code:   i32,
    headers:       const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    end_stream:    bool,
) -> bool {
    guard !slot.conn_failed && stream_id > 0 && (stream_id & 1) == 1 else { return false; }
    guard status_code >= 100 && status_code <= 599 && status_code != 101 else { return false; }
    guard !(end_stream && status_code < 200) else { return false; }

    let s_idx, found = find_stream_idx(slot.conn, stream_id);
    guard found else { return false; }
    let st = slot.conn.streams[s_idx].state;
    guard st == StreamState.Open || st == StreamState.HalfClosedRemote else { return false; }
    if slot.has_peer_max_header_list_size {
        let list_sz = calc_edge_resp_header_list_size_slices(headers, spill_entries, spill_raw);
        let max_sz: u64 = slot.peer_max_header_list_size;
        guard list_sz <= max_sz else { return false; }
    }
    return true;
}

fn h2_edge_send_headers_slices(
    sess:          H2EdgeSession&,
    stream_id:     u32,
    status_code:   i32,
    headers:       const http::HeaderMap&,
    spill_entries: const http::HeaderEntry[:],
    spill_raw:     const u8[:],
    end_stream:    bool,
) -> bool {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return false; }
    let slot .= g_h2_edge_slots[idx];
    guard validate_edge_send_headers_slices(
        slot, stream_id, status_code, headers, spill_entries, spill_raw, end_stream,
    ) else {
        return false;
    }

    let saved_enc = slot.hpack_enc;
    let saved_pend = slot.hpack_enc_pending_size_update;
    let saved_min = slot.hpack_enc_pending_min_size;
    var committed = false;
    defer if !committed {
        slot.hpack_enc = saved_enc;
        slot.hpack_enc_pending_size_update = saved_pend;
        slot.hpack_enc_pending_min_size = saved_min;
    };

    g_h2_edge_hpack_scratch.clear();
    defer {
        if g_h2_edge_hpack_scratch.len > 0 {
            core::secure_zeroize_slice(g_h2_edge_hpack_scratch[..]);
        }
        g_h2_edge_hpack_scratch.clear();
    };
    guard encode_edge_response_hpack_slices(
        slot.hpack_enc,
        slot.hpack_enc_pending_size_update,
        slot.hpack_enc_pending_min_size,
        status_code,
        headers,
        spill_entries,
        spill_raw,
        g_h2_edge_hpack_scratch,
    ) else {
        return false;
    }
    guard emit_edge_header_fragments(slot, stream_id, g_h2_edge_hpack_scratch[..], end_stream) else {
        return false;
    }
    if end_stream {
        close_local_stream(slot.conn, stream_id);
    }
    committed = true;
    return true;
}

// Encodes and queues HTTP/2 response HEADERS (+ CONTINUATION if exceeding peer max frame size) on `stream_id`.
fn h2_edge_send_headers(
    sess:        H2EdgeSession&,
    stream_id:   u32,
    status_code: i32,
    headers:     const http::HeaderMap&,
    end_stream:  bool,
) -> bool {
    return h2_edge_send_headers_slices(
        sess, stream_id, status_code, headers, headers.entries[..0], "", end_stream,
    );
}

// Encodes and queues up to 64 KiB HTTP/2 response HEADERS + CONTINUATION from `headers` + `arena` on `stream_id`.
fn h2_edge_send_headers_spill(
    sess:        H2EdgeSession&,
    stream_id:   u32,
    status_code: i32,
    headers:     const http::HeaderMap&,
    arena:       const http::OverflowArena&,
    end_stream:  bool,
) -> bool {
    return h2_edge_send_headers_slices(
        sess, stream_id, status_code, headers, arena.spill_entries[..], arena.spill_raw[..], end_stream,
    );
}

fn send_edge_zero_data(slot: H2EdgeSlot&, stream_id: u32, end_stream: bool) -> i64, bool {
    guard end_stream else { return 0, true; }
    guard core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len) >= rfc::H2_FRAME_HEADER_LEN else {
        return 0, false;
    }
    guard append_edge_frame(slot.wire_out, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, stream_id, "") else {
        return 0, false;
    }
    close_local_stream(slot.conn, stream_id);
    return 0, true;
}

fn send_edge_data_loop(
    slot:       H2EdgeSlot&,
    s_idx:      i32,
    stream_id:  u32,
    data:       const u8[:],
    quota:      i64,
    end_stream: bool,
) -> i64 {
    let def_mf:  i64 = rfc::H2_DEFAULT_MAX_FRAME_SIZE;
    let peer_mf: i64 = slot.conn.peer_max_frame_size;
    let max_frame = max(def_mf, peer_mf);
    var sent: i64 = 0;
    while sent < data.len && sent < quota {
        let avail_wire = core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len);
        guard avail_wire > rfc::H2_FRAME_HEADER_LEN else { break; }
        let rem_data = core::sub_sat_i64(data.len, sent);
        let rem_quota = core::sub_sat_i64(quota, sent);
        let max_wire = core::sub_sat_i64(avail_wire, rfc::H2_FRAME_HEADER_LEN);
        let chunk = min(min(rem_data, rem_quota), min(max_frame, max_wire));
        guard chunk > 0 else { break; }
        let next_sent = core::add_sat_i64(sent, chunk);
        let flags: u8 = if end_stream && next_sent == data.len { rfc::H2_FLAG_END_STREAM } else { 0 };
        guard append_edge_frame(slot.wire_out, rfc::H2_FRAME_DATA, flags, stream_id, data[sent..next_sent]) else {
            break;
        }
        sent = next_sent;
        slot.conn.conn_send_window = core::sub_sat_i64(slot.conn.conn_send_window, chunk);
        slot.conn.streams[s_idx].send_window = core::sub_sat_i64(slot.conn.streams[s_idx].send_window, chunk);
    }
    return sent;
}

// Emits up to the minimum of connection window, stream window, peer max frame size, and wire space.
// Returns `(accepted, true)` on send or flow-control pause (`0`), or `(0, false)` on closed state
// or when a zero-length `end_stream` frame cannot fit in `wire_out`.
//
// Example:
//   stream send window = 1000, data.len = 2500, end_stream = true
//   returns: accepted = 1000, ok = true (END_STREAM withheld until remaining 1500 bytes are sent)
fn h2_edge_send_data(
    sess:       H2EdgeSession&,
    stream_id:  u32,
    data:       const u8[:],
    end_stream: bool,
) -> i64, bool {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return 0, false; }
    let slot .= g_h2_edge_slots[idx];
    guard !slot.conn_failed && stream_id > 0 else { return 0, false; }

    let s_idx, found = find_stream_idx(slot.conn, stream_id);
    guard found else { return 0, false; }
    let st = slot.conn.streams[s_idx].state;
    guard st == StreamState.Open || st == StreamState.HalfClosedRemote else { return 0, false; }
    guard data.len > 0 else { return send_edge_zero_data(slot, stream_id, end_stream); }

    let quota = compute_stream_send_quota(slot.conn, stream_id);
    guard quota > 0 else { return 0, true; }

    let sent = send_edge_data_loop(slot, s_idx, stream_id, data, quota, end_stream);
    if end_stream && sent == data.len {
        close_local_stream(slot.conn, stream_id);
    }
    return sent, true;
}

// Emits a RST_STREAM frame and closes the local stream state (RFC 9113 Section 6.4).
fn h2_edge_reset_stream(sess: H2EdgeSession&, stream_id: u32, error_code: u32) -> bool {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return false; }
    let slot .= g_h2_edge_slots[idx];
    guard !slot.conn_failed && stream_id > 0 && (stream_id & 1) == 1 else { return false; }
    let _, found = find_stream_idx(slot.conn, stream_id);
    guard found || h2_internal::is_closed_stream_id(slot.conn, stream_id) else { return false; }
    guard emit_edge_rst_stream(slot, stream_id, error_code) else { return false; }
    reset_stream(slot.conn, stream_id);
    return true;
}

// Emits a GOAWAY frame carrying the highest peer-initiated stream ID processed (RFC 9113 Section 6.8).
fn h2_edge_send_goaway(sess: H2EdgeSession&, error_code: u32) -> bool {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return false; }
    return emit_edge_goaway(g_h2_edge_slots[idx], error_code);
}

// Drains all queued outbound HTTP/2 wire bytes from `sess` into `out_wire`, returning byte count copied.
fn h2_edge_drain_wire(sess: H2EdgeSession&, out_wire: u8[>..]&) -> i64 {
    let idx = lookup_live_edge_slot_idx(sess);
    guard idx >= 0 else { return 0; }
    let slot .= g_h2_edge_slots[idx];
    let n = slot.wire_out.len;
    guard n > 0 else { return 0; }
    out_wire.append(slot.wire_out[..]);
    slot.wire_out.clear();
    while slot.queued_control_acks > 0 {
        ack_control_frame_flushed(slot.conn);
        slot.queued_control_acks = core::sub_sat_u32(slot.queued_control_acks, 1);
    }
    return n;
}
