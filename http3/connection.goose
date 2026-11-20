// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Connection Coordinator and Stream Multiplexer.
// Conforms to RFC 9114 (HTTP/3), RFC 9204 (QPACK), and RFC 9000 (QUIC Streams).
namespace h3_internal;

import std;
import core from "..";
import http.headers;
import quic.packet;
import http3.qpack;
import http3.framing;

// ---- Stream Kinds, States and Structures --------------------------------

const MAX_H3_EMPTY_FRAME_STREAK: u32 = 32;

enum H3StreamKind {
    Request,
    Control,
    QpackEncoder,
    QpackDecoder,
    Push,
    UnknownUni,
}

enum H3StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

struct H3StreamEntry {
    stream_id:            u64                 = 0,
    kind:                 H3StreamKind        = H3StreamKind.Request,
    state:                H3StreamState       = H3StreamState.Idle,
    is_bidi:              bool                = true,
    headers_sent:         bool                = false,
    headers_received:     bool                = false,
    trailers_received:    bool                = false,
    fin_sent:             bool                = false,
    fin_received:         bool                = false,
    status_code:          i32                 = 0,
    body_received_len:    u64                 = 0,
    content_length:       i64                 = -1,
    priority:             wing::PriorityParam = wing::PriorityParam { urgency: 3, incremental: false },
    priority_updated:     bool                = false,
    tx_pending_bytes:     u64                 = 0,
    last_scheduled_cycle: u64                 = 0,
    req_method:           u8[..16]            = [],
    req_path:             u8[..1024]          = [],
    req_authority:        u8[..256]           = [],
    headers:              wing::HeaderMap     = wing::HeaderMap { .. },
    trailers:             wing::HeaderMap     = wing::HeaderMap { .. },
    received_body:        u8[..4096]          = [],
    blocked_wire:         u8[..4096]          = [],
    rx_partial_buf:       u8[..4096]          = [],
}

struct PromisedPushRecord {
    push_id:    u64 = 0,
    field_hash: u64 = 0,
}

enum H3ConnRole {
    Client,
    Server,
}

enum H3ConnState {
    Connecting,
    Active,
    Draining,
    Closed,
}

// Fixed-capacity HTTP/3 connection state machine without heap allocations.
struct H3HeaderCounts {
    pseudo_status:    i32  = 0,
    pseudo_method:    i32  = 0,
    pseudo_scheme:    i32  = 0,
    pseudo_authority: i32  = 0,
    pseudo_path:      i32  = 0,
    pseudo_protocol:  i32  = 0,
    host:             i32  = 0,
    is_connect:       bool = false,
}

struct H3Connection {
    role:                      H3ConnRole               = H3ConnRole.Client,
    state:                     H3ConnState              = H3ConnState.Connecting,
    next_bidi_stream_id:       u64                      = 0,
    local_control_stream_id:   u64                      = 2,
    local_qpack_enc_stream_id: u64                      = 6,
    local_qpack_dec_stream_id: u64                      = 10,
    local_settings_sent:       bool                     = false,
    peer_control_stream_id:    u64                      = 0xFFFFFFFFFFFFFFFF,
    peer_control_opened:       bool                     = false,
    peer_settings_received:    bool                     = false,
    peer_qpack_enc_stream_id:  u64                      = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_enc_opened:     bool                     = false,
    peer_qpack_dec_stream_id:  u64                      = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_dec_opened:     bool                     = false,
    ignored_uni_streams:       u64[..64]                = [],
    opened_push_ids:           u64[..64]                = [],
    push_uni_streams:          u64[..16]                = [],
    promised_pushes:           PromisedPushRecord[..64] = [],
    goaway_received:           bool                     = false,
    goaway_max_stream_id:      u64                      = 0xFFFFFFFFFFFFFFFF,
    max_push_id_sent:          bool                     = false,
    max_push_id_advertised:    u64                      = 0,
    has_received_max_push_id:  bool                     = false,
    max_push_id_received:      u64                      = 0,
    has_promised_push_id:      bool                     = false,
    max_promised_push_id:      u64                      = 0,
    empty_frame_streak:        u32                      = 0,
    control_glitch_count:      u32                      = 0,
    max_control_glitches:      u32                      = 256,
    sched_cycle:               u64                      = 0,
    peer_origins:              u8[..128][..16]          = [],
    error_code:                u64                      = rfc::H3_ERR_NO_ERROR,
    local_settings:            fingerprint::H3Settings  = fingerprint::H3Settings { .. },
    peer_settings:             fingerprint::H3Settings  = fingerprint::H3Settings { .. },
    encoder_stream_buf:        u8[..4096]               = [],
    ctrl_partial_buf:          u8[..1024]               = [],
    qpack_enc_partial_buf:     u8[..4224]               = [],
    qpack_dec_partial_buf:     u8[..64]                 = [],
    local_qpack_enc_activated: bool                     = false,
    streams:                   H3StreamEntry[..32]      = [],
    qpack_static_only_tbl:     QpackTable               = QpackTable { .. },
    qpack_dec_table:           QpackTable               = QpackTable { .. },
    qpack_table:               QpackTable               = QpackTable { .. },
}

fn new_h3_client_connection(settings: const fingerprint::H3Settings&) -> H3Connection {
    let max_blk = min(settings.qpack_blocked_streams, 0xFFFFFFFF) as u32;
    return H3Connection {
        role:            H3ConnRole.Client,
        local_settings:  settings,
        qpack_dec_table: new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        qpack_table:     new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        ..
    };
}

fn new_h3_server_connection(settings: const fingerprint::H3Settings&) -> H3Connection {
    let max_blk = min(settings.qpack_blocked_streams, 0xFFFFFFFF) as u32;
    return H3Connection {
        role:            H3ConnRole.Server,
        local_settings:  settings,
        qpack_dec_table: new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        qpack_table:     new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        ..
    };
}

// RFC 9114 Section 7.2.7: MAX_PUSH_ID - A MAX_PUSH_ID frame cannot reduce the maximum push ID.
fn send_max_push_id<B>(conn: H3Connection&, max_push_id: u64, out: B&) -> bool {
    guard conn.role == H3ConnRole.Client && conn.state != H3ConnState.Closed else { return false; }
    guard !conn.max_push_id_sent || max_push_id >= conn.max_push_id_advertised else { return false; }
    guard encode_h3_max_push_id(out, max_push_id) else { return false; }
    conn.max_push_id_sent = true;
    conn.max_push_id_advertised = max_push_id;
    return true;
}

// ---- Preamble & Unidirectional Stream Creation ---------------------------

// Encodes client preambles for control, QPACK encoder, and QPACK decoder streams.
fn encode_client_preambles<B1, B2, B3>(
    conn:          H3Connection&,
    out_ctrl:      B1&,
    out_qpack_enc: B2&,
    out_qpack_dec: B3&,
) -> bool {
    let saved_ctrl = out_ctrl.len;
    let saved_enc = out_qpack_enc.len;
    let saved_dec = out_qpack_dec.len;
    var committed = false;
    defer if !committed {
        out_ctrl.resize(saved_ctrl);
        out_qpack_enc.resize(saved_enc);
        out_qpack_dec.resize(saved_dec);
    };

    guard quic_internal::quic_encode_varint(out_ctrl, rfc::H3_STREAM_CONTROL) else { return false; }
    guard encode_h3_settings_frame(out_ctrl, conn.local_settings) else { return false; }
    guard quic_internal::quic_encode_varint(out_qpack_enc, rfc::H3_STREAM_QPACK_ENCODER) else { return false; }
    guard quic_internal::quic_encode_varint(out_qpack_dec, rfc::H3_STREAM_QPACK_DECODER) else { return false; }

    conn.local_settings_sent = true;
    committed = true;
    return true;
}

// ---- Request Stream Lifecycle --------------------------------------------

// Finds an existing stream or returns false.
fn find_h3_stream_idx(conn: const H3Connection&, stream_id: u64) -> i32, bool {
    for i in conn.streams.len {
        if conn.streams[i].stream_id == stream_id {
            return i as i32, true;
        }
    }
    return -1, false;
}

// Allocates a new client request stream (0, 4, 8, ...).
fn open_request_stream(conn: H3Connection&) -> u64, bool {
    guard conn.state == H3ConnState.Active || conn.state == H3ConnState.Connecting else {
        return 0, false;
    }

    let sid = conn.next_bidi_stream_id;
    if conn.goaway_received && sid >= conn.goaway_max_stream_id {
        return 0, false;
    }

    var slot_idx: i32 = -1;
    for i in conn.streams.len {
        if conn.streams[i].state == H3StreamState.Closed {
            slot_idx = i as i32;
            break;
        }
    }

    let ent = H3StreamEntry {
        stream_id:         sid,
        kind:              H3StreamKind.Request,
        state:             H3StreamState.Open,
        is_bidi:           true,
        headers_sent:      false,
        headers_received:  false,
        trailers_received: false,
        fin_sent:          false,
        fin_received:      false,
        status_code:       0,
        body_received_len: 0,
        content_length:    -1,
        received_body:     [],
    };

    if slot_idx >= 0 {
        conn.streams[slot_idx] = ent;
    } else {
        guard conn.streams.try_push(ent) else { return 0, false; }
    }

    conn.next_bidi_stream_id += 4;
    return sid, true;
}

fn encode_single_h3_extra_header<B1, B2>(
    tbl:           QpackTable&,
    stream_id:     u64,
    base:          u64,
    extra_headers: const wing::HeaderMap&,
    entry:         const wing::HeaderEntry&,
    body_fields:   B1&,
    enc_stream:    B2&,
    max_dyn_abs:   u64&,
    used_any_dyn:  bool&,
) -> bool {
    let raw_len = extra_headers.raw_buf.len;
    let nb = entry.name_begin as i64;
    let ne = entry.name_end as i64;
    let vb = entry.values_begin as i64;
    let ve = entry.values_end as i64;
    guard nb >= 0 && ne >= nb && ne <= raw_len && vb >= 0 && ve >= vb && ve <= raw_len else {
        return false;
    }
    let raw_name = extra_headers.raw_buf[nb..ne];
    let val = extra_headers.raw_buf[vb..ve];
    if wire::is_h2_skipped_header_name(raw_name) {
        return true;
    }
    if raw_name.eq_ascii_fold("te") && !val.trim_lws().eq_ascii_fold("trailers") {
        return true;
    }
    var lower_name: u8[..256] = [];
    guard raw_name.len > 0 && raw_name.len <= lower_name.cap else { return false; }
    raw_name.to_lower_ascii(lower_name);
    return try_encode_qpack_field_dynamic(
        tbl, stream_id, base, lower_name[..], val,
        body_fields, enc_stream, max_dyn_abs, used_any_dyn, false,
    );
}

fn encode_h3_extra_headers<B1, B2>(
    tbl:           QpackTable&,
    stream_id:     u64,
    base:          u64,
    extra_headers: const wing::HeaderMap&,
    body_fields:   B1&,
    enc_stream:    B2&,
    max_dyn_abs:   u64&,
    used_any_dyn:  bool&,
) -> bool {
    for i in extra_headers.entries.len {
        let ok = encode_single_h3_extra_header(
            tbl, stream_id, base, extra_headers, extra_headers.entries[i],
            body_fields, enc_stream, max_dyn_abs, used_any_dyn,
        );
        guard ok else { return false; }
    }
    return true;
}

fn try_prepend_qpack_section_prefix<B>(
    tbl:          QpackTable&,
    stream_id:    u64,
    base:         u64,
    max_dyn_abs:  u64,
    used_any_dyn: bool,
    out_payload:  B&,
) -> bool {
    let saved_len = out_payload.len;
    let saved_tbl = tbl;
    var committed = false;
    defer if !committed {
        out_payload.resize(saved_len);
        tbl = saved_tbl;
    };
    if used_any_dyn {
        // RFC 9204 Section 4.5.1.1: Required Insert Count - Required Insert Count equals one more than the largest absolute index referenced.
        let ric = max_dyn_abs + 1;
        guard qpack_track_unacked_stream(tbl, stream_id, ric) else { return false; }
        let enc_ric = encode_ric(ric, tbl.max_capacity_bytes);
        guard h2_internal::hpack_encode_int(out_payload, enc_ric, 8, 0x00) else { return false; }
        let sign_bit, delta_base = encode_base(base, ric);
        let sign_mask: u8 = if sign_bit != 0 { 0x80 } else { 0x00 };
        guard h2_internal::hpack_encode_int(out_payload, delta_base, 7, sign_mask) else { return false; }
        committed = true;
        return true;
    }
    guard out_payload.try_push(0x00 as u8) && out_payload.try_push(0x00 as u8) else { return false; }
    committed = true;
    return true;
}

fn prepend_qpack_section_prefix<B>(
    tbl:          QpackTable&,
    stream_id:    u64,
    base:         u64,
    max_dyn_abs:  u64,
    used_any_dyn: bool,
    out_payload:  B&,
) {
    let _ = try_prepend_qpack_section_prefix(tbl, stream_id, base, max_dyn_abs, used_any_dyn, out_payload);
}

// RFC 9114 Section 4.1: HTTP Message Framing - Encodes a single client request HEADERS frame with atomic QPACK rollback on overflow.
fn send_request_headers<B>(
    conn:          H3Connection&,
    stream_id:     u64,
    method:        const u8[:],
    scheme:        const u8[:],
    authority:     const u8[:],
    path:          const u8[:],
    extra_headers: const wing::HeaderMap&,
    end_stream:    bool,
    out:           B&,
) -> bool {
    guard conn.role == H3ConnRole.Client && conn.state != H3ConnState.Closed else { return false; }
    guard !(conn.goaway_received && stream_id >= conn.goaway_max_stream_id) else { return false; }
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else { return false; }
    guard !conn.streams[s_idx].headers_sent && !conn.streams[s_idx].fin_sent else { return false; }

    var enc_tbl .= conn.qpack_static_only_tbl;
    if conn.local_qpack_enc_activated {
        enc_tbl .= conn.qpack_table;
    }
    let saved_out_len = out.len;
    let saved_enc_len = conn.encoder_stream_buf.len;
    let saved_tbl = enc_tbl;
    var committed = false;
    defer if !committed {
        out.resize(saved_out_len);
        conn.encoder_stream_buf.resize(saved_enc_len);
        enc_tbl = saved_tbl;
    };

    let base = enc_tbl.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    var body_fields: u8[..4096] = [];

    guard try_encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":method", method,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && try_encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":scheme", scheme,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && try_encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":authority", authority,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && try_encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":path", path,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && encode_h3_extra_headers(
        enc_tbl, stream_id, base, extra_headers,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn,
    ) else {
        return false;
    }

    var qpack_payload: u8[..4096] = [];
    guard try_prepend_qpack_section_prefix(
        enc_tbl, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload,
    ) && qpack_payload.try_append(body_fields[..]) &&
          encode_h3_headers_frame(out, qpack_payload[..]) else {
        return false;
    }

    let _ = conn.streams[s_idx].req_method.try_set(method);
    conn.streams[s_idx].headers_sent = true;
    if end_stream {
        conn.streams[s_idx].fin_sent = true;
        conn.streams[s_idx].state = if conn.streams[s_idx].fin_received {
            H3StreamState.Closed
        } else {
            H3StreamState.HalfClosedLocal
        };
    }
    committed = true;
    return true;
}

// Configures local QPACK dynamic table capacity from peer SETTINGS_QPACK_MAX_TABLE_CAPACITY
// and emits the Set Dynamic Table Capacity instruction onto `conn.encoder_stream_buf` (RFC 9204 Section 4.3.1).
fn h3_activate_qpack_dynamic_table(conn: H3Connection&, new_cap: u64) -> bool {
    if !conn.local_qpack_enc_activated {
        if conn.peer_qpack_enc_opened {
            conn.qpack_dec_table = conn.qpack_table;
            let max_blk = min(conn.local_settings.qpack_blocked_streams, 0xFFFFFFFF) as u32;
            conn.qpack_table = new_qpack_table(conn.local_settings.qpack_max_table_capacity, max_blk, 0);
        }
        conn.local_qpack_enc_activated = true;
    }
    if new_cap > conn.qpack_table.max_capacity_bytes {
        conn.qpack_table.max_capacity_bytes = new_cap;
    }
    return encode_qpack_set_capacity(conn.qpack_table, new_cap, conn.encoder_stream_buf);
}

// Encodes a DATA frame on an open request stream.
fn send_request_data<B>(
    conn:       H3Connection&,
    stream_id:  u64,
    data:       const u8[:],
    end_stream: bool,
    out:        B&,
) -> bool {
    guard conn.role == H3ConnRole.Client && conn.state != H3ConnState.Closed else { return false; }
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else { return false; }
    guard conn.streams[s_idx].headers_sent && !conn.streams[s_idx].fin_sent else { return false; }

    let ok_frame = encode_h3_data_frame(out, data);
    guard ok_frame else { return false; }

    if end_stream {
        conn.streams[s_idx].fin_sent = true;
        conn.streams[s_idx].state = if conn.streams[s_idx].fin_received {
            H3StreamState.Closed
        } else {
            H3StreamState.HalfClosedLocal
        };
    }
    return true;
}

// ---- Inbound Frame and Stream Processing ---------------------------------

fn handle_peer_origin_or_glitch(conn: H3Connection&, frame_type: u64, payload: const u8[:]) -> u64 {
    if frame_type == H3_FRAME_ORIGIN {
        guard conn.role != H3ConnRole.Server else {
            return rfc::H3_ERR_NO_ERROR;
        }
        guard parse_h3_origin_frame(payload, conn.peer_origins) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        return rfc::H3_ERR_NO_ERROR;
    }

    conn.control_glitch_count = min(conn.control_glitch_count, 0xFFFFFFFE) + 1;
    guard conn.control_glitch_count <= conn.max_control_glitches else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    return rfc::H3_ERR_NO_ERROR;
}

// RFC 9218 Section 7: The PRIORITY_UPDATE Frame - Failure to parse the Priority Field Value in HTTP/3 is H3_GENERAL_PROTOCOL_ERROR.
// RFC 9218 Section 7.2: HTTP/3 PRIORITY_UPDATE Frame - Request-stream Prioritized Element ID MUST be a client-initiated bidirectional stream ID.
fn handle_peer_priority_update(conn: H3Connection&, frame_type: u64, payload: const u8[:]) -> u64 {
    guard conn.role != H3ConnRole.Client else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    let elem_id, off, ok_id = quic_internal::quic_decode_varint(payload, 0);
    guard ok_id else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    if frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST {
        guard (elem_id & 0x03) == 0 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        let prio, ok_pu = parse_h3_priority_field_value(payload[(off as i64)..], false);
        guard ok_pu else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        apply_h3_stream_priority(conn, elem_id, prio);
        return rfc::H3_ERR_NO_ERROR;
    }
    if !conn.has_received_max_push_id || elem_id > conn.max_push_id_received ||
       !conn.has_promised_push_id || elem_id > conn.max_promised_push_id {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_ID_ERROR;
        return rfc::H3_ERR_ID_ERROR;
    }
    let _, ok_pu = parse_h3_priority_field_value(payload[(off as i64)..], false);
    guard ok_pu else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn handle_peer_extended_control_frame(conn: H3Connection&, frame_type: u64, payload: const u8[:]) -> u64 {
    if frame_type == rfc::H3_FRAME_MAX_PUSH_ID {
        guard conn.role != H3ConnRole.Client else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
            return rfc::H3_ERR_FRAME_UNEXPECTED;
        }
        let max_pid, ok_mp = parse_h3_max_push_id(payload);
        guard ok_mp else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        if conn.has_received_max_push_id && max_pid < conn.max_push_id_received {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        conn.has_received_max_push_id = true;
        conn.max_push_id_received = max_pid;
        return rfc::H3_ERR_NO_ERROR;
    }

    if frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST ||
       frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_PUSH {
        return handle_peer_priority_update(conn, frame_type, payload);
    }

    return handle_peer_origin_or_glitch(conn, frame_type, payload);
}

// Handles frames received on the peer control stream.
fn handle_peer_control_frame(conn: H3Connection&, hdr: const H3FrameHeader&, payload: const u8[:]) -> u64 {
    // First frame on Control Stream MUST be SETTINGS (RFC 9114 §6.2.1 & §7.2.4)
    if !conn.peer_settings_received {
        if hdr.frame_type != rfc::H3_FRAME_SETTINGS {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_MISSING_SETTINGS;
            return rfc::H3_ERR_MISSING_SETTINGS;
        }
        let set_err = parse_h3_settings_frame(payload, conn.peer_settings);
        guard set_err == rfc::H3_ERR_NO_ERROR else {
            conn.state = H3ConnState.Closed;
            conn.error_code = set_err;
            return set_err;
        }
        conn.peer_settings_received = true;
        conn.state = H3ConnState.Active;
        return rfc::H3_ERR_NO_ERROR;
    }

    // Subsequent strictly forbidden frames on control stream (RFC 9114 §7.2.1, §7.2.2, §7.2.5, §7.2.8)
    guard rfc::is_allowed_on_control_stream(hdr.frame_type) else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    // Subsequent frames must not be SETTINGS
    guard hdr.frame_type != rfc::H3_FRAME_SETTINGS else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    if hdr.frame_type == rfc::H3_FRAME_GOAWAY {
        let max_sid, ok_ga = parse_h3_goaway_frame(payload);
        guard ok_ga else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        if (max_sid & 0x03) != 0 {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        if conn.goaway_received && max_sid > conn.goaway_max_stream_id {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        conn.goaway_received = true;
        conn.goaway_max_stream_id = max_sid;
        conn.state = H3ConnState.Draining;
        return rfc::H3_ERR_NO_ERROR;
    }

    if hdr.frame_type == rfc::H3_FRAME_CANCEL_PUSH {
        let push_id, ok_cp = parse_h3_cancel_push(payload);
        guard ok_cp else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        if conn.has_received_max_push_id && push_id > conn.max_push_id_received {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        if conn.role == H3ConnRole.Client && (!conn.max_push_id_sent || push_id > conn.max_push_id_advertised) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        return rfc::H3_ERR_NO_ERROR;
    }

    return handle_peer_extended_control_frame(conn, hdr.frame_type, payload);
}

// RFC 9114 Section 4.3.1: Request Pseudo-Header Fields - All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4.
// RFC 9114 Section 4.4: The CONNECT Method - The :scheme and :path pseudo-header fields are omitted and :authority is present.
// RFC 9220 Section 3: WebSockets Upgrade over HTTP/3 - Extended CONNECT requests include :protocol, :scheme, :authority, and :path.
fn validate_h3_pseudo_headers(
    role:           H3ConnRole,
    status_count:   i32,
    method_count:   i32,
    scheme_count:   i32,
    path_count:     i32,
    auth_count:     i32,
    is_connect:     bool = false,
    protocol_count: i32  = 0,
) -> bool {
    if role == H3ConnRole.Client {
        return status_count == 1 && method_count == 0 && scheme_count == 0
            && path_count == 0 && auth_count == 0 && protocol_count == 0;
    }
    if is_connect && protocol_count > 0 {
        return status_count == 0 && method_count == 1 && scheme_count == 1
            && path_count == 1 && auth_count == 1 && protocol_count == 1;
    }
    if is_connect {
        return status_count == 0 && method_count == 1 && scheme_count == 0
            && path_count == 0 && auth_count == 1 && protocol_count == 0;
    }
    return status_count == 0 && method_count == 1 && scheme_count == 1 && path_count == 1 && protocol_count == 0;
}

inline fn record_bounded_stream_id<A>(arr: A&, id: u64) {
    if !arr.try_push(id) && arr.len > 0 {
        arr.remove_at(0);
        let _ = arr.try_push(id);
    }
}

fn has_opened_push_id(conn: const H3Connection&, push_id: u64) -> bool {
    for id in conn.opened_push_ids {
        if id == push_id {
            return true;
        }
    }
    return false;
}

fn is_push_uni_stream(conn: const H3Connection&, stream_id: u64) -> bool {
    for id in conn.push_uni_streams {
        if id == stream_id {
            return true;
        }
    }
    return false;
}

fn remove_push_uni_stream(conn: H3Connection&, stream_id: u64) {
    for i in conn.push_uni_streams.len {
        if conn.push_uni_streams[i] == stream_id {
            conn.push_uni_streams.remove_at(i);
            return;
        }
    }
}

// RFC 9114 Section 6.2.2: Push Streams - Each push ID MUST only be used once in a push stream header.
fn handle_push_stream_open(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
    offset:    u64,
) -> u64, u64 {
    if conn.role == H3ConnRole.Server {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_STREAM_CREATION;
        return 0, rfc::H3_ERR_STREAM_CREATION;
    }

    let push_id, rem_off, ok_p = quic_internal::quic_decode_varint(data, offset);
    guard ok_p else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return 0, rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    if !conn.max_push_id_sent || push_id > conn.max_push_id_advertised ||
       has_opened_push_id(conn, push_id) {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_ID_ERROR;
        return 0, rfc::H3_ERR_ID_ERROR;
    }

    record_bounded_stream_id(conn.opened_push_ids, push_id);
    record_bounded_stream_id(conn.push_uni_streams, stream_id);
    return rem_off, rfc::H3_ERR_NO_ERROR;
}

inline fn next_peer_push_stream_frame(data: const u8[:], offset: u64) -> u64, u64 {
    let hdr, ok_hdr = parse_h3_frame_header(data, offset);
    guard ok_hdr else { return offset, rfc::H3_ERR_FRAME_ERROR; }
    let after_hdr = core::add_sat_u64(offset, hdr.header_len);
    let after_pay = core::add_sat_u64(after_hdr, hdr.payload_len);
    guard after_pay <= (data.len as u64) else {
        return offset, rfc::H3_ERR_FRAME_ERROR;
    }
    if !rfc::is_allowed_on_request_stream(hdr.frame_type) ||
       hdr.frame_type == rfc::H3_FRAME_PUSH_PROMISE {
        return offset, rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    return after_pay, rfc::H3_ERR_NO_ERROR;
}

fn process_peer_push_stream(conn: H3Connection&, data: const u8[:], start_offset: u64) -> u64 {
    var offset = start_offset;
    while offset < (data.len as u64) {
        let next_off, err = next_peer_push_stream_frame(data, offset);
        if err != rfc::H3_ERR_NO_ERROR {
            conn.state = H3ConnState.Closed;
            conn.error_code = err;
            return err;
        }
        offset = next_off;
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn check_control_frame_header_bounds(conn: H3Connection&, hdr: const H3FrameHeader&) -> u64 {
    if !conn.peer_settings_received {
        if hdr.frame_type != rfc::H3_FRAME_SETTINGS {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_MISSING_SETTINGS;
            return rfc::H3_ERR_MISSING_SETTINGS;
        }
    } else if !rfc::is_allowed_on_control_stream(hdr.frame_type) || hdr.frame_type == rfc::H3_FRAME_SETTINGS {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    if hdr.frame_type == rfc::H3_FRAME_GOAWAY
        || hdr.frame_type == rfc::H3_FRAME_CANCEL_PUSH
        || hdr.frame_type == rfc::H3_FRAME_MAX_PUSH_ID {
        if hdr.payload_len == 0 || hdr.payload_len > 8 {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
    } else if hdr.frame_type == rfc::H3_FRAME_SETTINGS && hdr.payload_len > H3_MAX_SETTINGS_PAYLOAD_SIZE {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    } else if core::add_sat_u64(hdr.header_len, hdr.payload_len) > 1024 {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn process_peer_control_stream(conn: H3Connection&, data: const u8[:], start_offset: u64) -> u64 {
    let incoming = data[(start_offset as i64)..];
    var work_buf: u8[..2048] = [];
    if conn.ctrl_partial_buf.len > 0 {
        guard work_buf.try_append(conn.ctrl_partial_buf[..]) && work_buf.try_append(incoming) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        conn.ctrl_partial_buf.clear();
    }
    let buf = if work_buf.len > 0 { work_buf[..] } else { incoming };
    var offset: u64 = 0;
    while offset < (buf.len as u64) {
        let frame_start = offset;
        let hdr, ok_hdr = parse_h3_frame_header(buf, offset);
        if !ok_hdr {
            let rem = buf[(frame_start as i64)..];
            guard rem.len < 16 && conn.ctrl_partial_buf.try_set(rem) else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_FRAME_ERROR;
                return rfc::H3_ERR_FRAME_ERROR;
            }
            return rfc::H3_ERR_NO_ERROR;
        }
        let pre_err = check_control_frame_header_bounds(conn, hdr);
        guard pre_err == rfc::H3_ERR_NO_ERROR else { return pre_err; }

        offset += hdr.header_len;
        if (0xFFFFFFFFFFFFFFFF - offset) < hdr.payload_len || (offset + hdr.payload_len) > (buf.len as u64) {
            let rem = buf[(frame_start as i64)..];
            guard conn.ctrl_partial_buf.try_set(rem) else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_FRAME_ERROR;
                return rfc::H3_ERR_FRAME_ERROR;
            }
            return rfc::H3_ERR_NO_ERROR;
        }

        let p_start = offset as i64;
        let p_end = (offset + hdr.payload_len) as i64;
        let payload = buf[p_start..p_end];
        offset += hdr.payload_len;

        let c_err = handle_peer_control_frame(conn, hdr, payload);
        guard c_err == rfc::H3_ERR_NO_ERROR else { return c_err; }
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn pop_ready_blocked_qpack_stream(tbl: QpackTable&) -> BlockedStreamEntry, bool {
    for i in tbl.blocked_streams.len {
        if !has_blocked_stream_before(tbl.blocked_streams[..], i, tbl.blocked_streams[i].stream_id) &&
           tbl.blocked_streams[i].req_insert_count <= tbl.insert_count {
            let entry = tbl.blocked_streams[i];
            tbl.blocked_streams.remove_at(i as i32);
            return entry, true;
        }
    }
    return BlockedStreamEntry { .. }, false;
}

fn check_bidi_stream_fin_complete(conn: H3Connection&, s_idx: i32) -> u64 {
    if !conn.streams[s_idx].headers_received {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_REQUEST_INCOMPLETE;
        return rfc::H3_ERR_REQUEST_INCOMPLETE;
    }
    let sc = conn.streams[s_idx].status_code;
    let is_head = conn.role == H3ConnRole.Client && conn.streams[s_idx].req_method[..] == "HEAD";
    if sc != 204 && sc != 304 && !is_head && conn.streams[s_idx].content_length >= 0 &&
       conn.streams[s_idx].body_received_len != (conn.streams[s_idx].content_length as u64) {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn drain_unblocked_bidi_stream(conn: H3Connection&, stream_id: u64) -> u64 {
    var dec_tbl .= conn.qpack_table;
    if conn.local_qpack_enc_activated {
        dec_tbl .= conn.qpack_dec_table;
    }
    if qpack_is_stream_blocked(dec_tbl, stream_id) {
        return rfc::H3_ERR_NO_ERROR;
    }
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else {
        return rfc::H3_ERR_NO_ERROR;
    }
    if conn.streams[s_idx].blocked_wire.len > 0 {
        var pending: u8[..4096] = [];
        let _ = pending.try_set(conn.streams[s_idx].blocked_wire[..]);
        conn.streams[s_idx].blocked_wire.clear();
        let f_err = handle_bidi_stream_frames(conn, s_idx, pending[..], conn.streams[s_idx].fin_received);
        guard f_err == rfc::H3_ERR_NO_ERROR else { return f_err; }
    }
    if conn.streams[s_idx].fin_received && !qpack_is_stream_blocked(dec_tbl, stream_id) {
        return check_bidi_stream_fin_complete(conn, s_idx);
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn resume_single_blocked_entry(conn: H3Connection&, entry: const BlockedStreamEntry&) -> u64 {
    var dec_tbl .= conn.qpack_table;
    if conn.local_qpack_enc_activated {
        dec_tbl .= conn.qpack_dec_table;
    }
    if entry.is_push_promise {
        var pp_fields: HeaderField[..128] = [];
        let q_err = decode_qpack_section(
            dec_tbl,
            entry.encoded_data[..],
            pp_fields,
            conn.local_settings.max_field_section_size,
        );
        if q_err != QpackError.None {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
            return rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
        }
        let pp_err = validate_h3_push_promise_fields(conn, pp_fields);
        guard pp_err == rfc::H3_ERR_NO_ERROR else { return pp_err; }
        let dup_err = record_or_verify_promised_push(conn, entry.push_id, pp_fields);
        guard dup_err == rfc::H3_ERR_NO_ERROR else { return dup_err; }
        return drain_unblocked_bidi_stream(conn, entry.stream_id);
    }
    let s_idx, found = find_h3_stream_idx(conn, entry.stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len {
        let h_err = handle_bidi_headers(conn, s_idx, entry.encoded_data[..]);
        guard h_err == rfc::H3_ERR_NO_ERROR else { return h_err; }
    }
    return drain_unblocked_bidi_stream(conn, entry.stream_id);
}

fn resume_unblocked_qpack_streams(conn: H3Connection&) -> u64 {
    for _ in 128 {
        var dec_tbl .= conn.qpack_table;
        if conn.local_qpack_enc_activated {
            dec_tbl .= conn.qpack_dec_table;
        }
        let entry, ok_pop = pop_ready_blocked_qpack_stream(dec_tbl);
        guard ok_pop else {
            return rfc::H3_ERR_NO_ERROR;
        }
        let r_err = resume_single_blocked_entry(conn, entry);
        guard r_err == rfc::H3_ERR_NO_ERROR else { return r_err; }
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn is_qpack_int_truncated(src: const u8[:], offset: u64, prefix_bits: u8) -> bool {
    guard offset < (src.len as u64) else { return true; }
    let mask = core::sub_sat_u64(core::shl_sat_u64(1, prefix_bits), 1) as u8;
    if (src[offset] & mask) < mask {
        return false;
    }
    let rem = core::sub_sat_u64(core::sub_sat_u64(src.len as u64, offset), 1);
    guard rem < 9 else { return false; }
    let base_idx = core::add_sat_i64(offset as i64, 1);
    for i in (rem as i64) {
        if (src[core::add_sat_i64(base_idx, i)] & 0x80) == 0 {
            return false;
        }
    }
    return true;
}

inline fn is_qpack_str_truncated(src: const u8[:], offset: u64, prefix_bits: u8, max_len: u64) -> bool, u64 {
    if is_qpack_int_truncated(src, offset, prefix_bits) {
        return true, offset;
    }
    let slen, next_off, ok = qpack_decode_int(src, offset, prefix_bits);
    guard ok && slen <= max_len else { return false, offset; }
    let end_off = core::add_sat_u64(next_off, slen);
    if end_off > (src.len as u64) {
        return true, offset;
    }
    return false, end_off;
}

fn is_qpack_enc_instr_incomplete(cap_bytes: u64, src: const u8[:], offset: u64) -> bool {
    guard offset < (src.len as u64) else { return false; }
    let b = src[offset];
    if (b & 0xE0) == 0x20 {
        return is_qpack_int_truncated(src, offset, 5);
    }
    guard cap_bytes > 0 else { return false; }
    if (b & 0xE0) == 0x00 {
        return is_qpack_int_truncated(src, offset, 5);
    }
    if (b & 0x80) != 0 {
        if is_qpack_int_truncated(src, offset, 6) {
            return true;
        }
        let _, val_off, ok_idx = qpack_decode_int(src, offset, 6);
        guard ok_idx else { return false; }
        let trunc_v, _ = is_qpack_str_truncated(src, val_off, 7, 4096);
        return trunc_v;
    }
    if (b & 0xC0) == 0x40 {
        let trunc_n, val_start = is_qpack_str_truncated(src, offset, 5, 256);
        if trunc_n {
            return true;
        }
        guard val_start > offset else { return false; }
        let trunc_v, _ = is_qpack_str_truncated(src, val_start, 7, 4096);
        return trunc_v;
    }
    return false;
}

fn is_qpack_dec_instr_incomplete(src: const u8[:], offset: u64) -> bool {
    guard offset < (src.len as u64) else { return false; }
    let b = src[offset];
    let pbits: u8 = if (b & 0x80) != 0 { 7 } else { 6 };
    return is_qpack_int_truncated(src, offset, pbits);
}

fn process_peer_qpack_enc_bytes(conn: H3Connection&, incoming: const u8[:]) -> u64 {
    var work_buf: u8[..8448] = [];
    if conn.qpack_enc_partial_buf.len > 0 {
        guard work_buf.try_append(conn.qpack_enc_partial_buf[..]) && work_buf.try_append(incoming) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
            return rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
        }
        conn.qpack_enc_partial_buf.clear();
    }
    let buf = if work_buf.len > 0 { work_buf[..] } else { incoming };
    var offset: u64 = 0;
    while offset < (buf.len as u64) {
        var dec_tbl .= conn.qpack_table;
        if conn.local_qpack_enc_activated {
            dec_tbl .= conn.qpack_dec_table;
        }
        if is_qpack_enc_instr_incomplete(dec_tbl.capacity_bytes, buf, offset) {
            guard conn.qpack_enc_partial_buf.try_set(buf[(offset as i64)..]) else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
                return rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
            }
            return resume_unblocked_qpack_streams(conn);
        }
        let next_off, q_err = qpack_process_encoder_instruction(dec_tbl, buf, offset);
        if q_err != QpackError.None {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
            return rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
        }
        offset = next_off;
    }
    return resume_unblocked_qpack_streams(conn);
}

fn process_peer_qpack_dec_bytes(conn: H3Connection&, incoming: const u8[:]) -> u64 {
    var work_buf: u8[..128] = [];
    if conn.qpack_dec_partial_buf.len > 0 {
        guard work_buf.try_append(conn.qpack_dec_partial_buf[..]) && work_buf.try_append(incoming) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
            return rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
        }
        conn.qpack_dec_partial_buf.clear();
    }
    let buf = if work_buf.len > 0 { work_buf[..] } else { incoming };
    var offset: u64 = 0;
    while offset < (buf.len as u64) {
        if is_qpack_dec_instr_incomplete(buf, offset) {
            guard conn.qpack_dec_partial_buf.try_set(buf[(offset as i64)..]) else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
                return rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
            }
            return rfc::H3_ERR_NO_ERROR;
        }
        var enc_tbl .= conn.qpack_table;
        let next_off, q_err = qpack_process_decoder_instruction(enc_tbl, buf, offset);
        if q_err != QpackError.None {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
            return rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
        }
        offset = next_off;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn process_peer_qpack_stream(
    conn:         H3Connection&,
    stream_id:    u64,
    data:         const u8[:],
    start_offset: u64,
) -> u64 {
    let incoming = data[(start_offset as i64)..];
    if stream_id == conn.peer_qpack_enc_stream_id {
        return process_peer_qpack_enc_bytes(conn, incoming);
    }
    if stream_id == conn.peer_qpack_dec_stream_id {
        return process_peer_qpack_dec_bytes(conn, incoming);
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn register_peer_uni_stream(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
) -> u64, u64 {
    let stype, off1, ok_type = quic_internal::quic_decode_varint(data, 0);
    guard ok_type else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return 0, rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    if stype == rfc::H3_STREAM_CONTROL {
        if conn.peer_control_opened {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_STREAM_CREATION;
            return 0, rfc::H3_ERR_STREAM_CREATION;
        }
        conn.peer_control_opened = true;
        conn.peer_control_stream_id = stream_id;
        return off1, rfc::H3_ERR_NO_ERROR;
    }
    if stype == rfc::H3_STREAM_QPACK_ENCODER {
        if conn.peer_qpack_enc_opened {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_STREAM_CREATION;
            return 0, rfc::H3_ERR_STREAM_CREATION;
        }
        conn.peer_qpack_enc_opened = true;
        conn.peer_qpack_enc_stream_id = stream_id;
        return off1, rfc::H3_ERR_NO_ERROR;
    }
    if stype == rfc::H3_STREAM_QPACK_DECODER {
        if conn.peer_qpack_dec_opened {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_STREAM_CREATION;
            return 0, rfc::H3_ERR_STREAM_CREATION;
        }
        conn.peer_qpack_dec_opened = true;
        conn.peer_qpack_dec_stream_id = stream_id;
        return off1, rfc::H3_ERR_NO_ERROR;
    }
    if stype == rfc::H3_STREAM_PUSH {
        let rem_off, p_err = handle_push_stream_open(conn, stream_id, data, off1);
        return rem_off, p_err;
    }

    // RFC 9114 Section 6.2: Unidirectional Streams - The recipient MUST NOT consider unknown stream types to be a connection error of any kind.
    record_bounded_stream_id(conn.ignored_uni_streams, stream_id);
    return 0, rfc::H3_ERR_NO_ERROR;
}

fn is_critical_uni_stream(conn: const H3Connection&, stream_id: u64) -> bool {
    if conn.peer_control_opened && stream_id == conn.peer_control_stream_id {
        return true;
    }
    if conn.peer_qpack_enc_opened && stream_id == conn.peer_qpack_enc_stream_id {
        return true;
    }
    if conn.peer_qpack_dec_opened && stream_id == conn.peer_qpack_dec_stream_id {
        return true;
    }
    return false;
}

fn consume_ignored_uni_stream(conn: H3Connection&, stream_id: u64, fin: bool) -> bool {
    for i in conn.ignored_uni_streams.len {
        if conn.ignored_uni_streams[i] == stream_id {
            if fin {
                conn.ignored_uni_streams.remove_at(i);
            }
            return true;
        }
    }
    return false;
}

fn handle_uni_stream_data(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
    fin:       bool,
) -> u64 {
    guard data.len > 0 || fin else { return rfc::H3_ERR_NO_ERROR; }

    if consume_ignored_uni_stream(conn, stream_id, fin) {
        return rfc::H3_ERR_NO_ERROR;
    }

    if is_push_uni_stream(conn, stream_id) {
        let p_err = process_peer_push_stream(conn, data, 0);
        if fin {
            remove_push_uni_stream(conn, stream_id);
        }
        return p_err;
    }

    var offset: u64 = 0;
    let is_known = is_critical_uni_stream(conn, stream_id);

    // RFC 9114 Section 6.2: Unidirectional Streams - A sender can close or reset a unidirectional stream before sending the stream type.
    if !is_known && data.len == 0 {
        return rfc::H3_ERR_NO_ERROR;
    }

    if !is_known && data.len > 0 {
        let next_off, reg_err = register_peer_uni_stream(conn, stream_id, data);
        guard reg_err == rfc::H3_ERR_NO_ERROR else { return reg_err; }
        offset = next_off;
    }

    // Critical stream closure defense (RFC 9114 Section 6.2.1)
    if fin {
        if is_critical_uni_stream(conn, stream_id) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_CLOSED_CRITICAL_STREAM;
            return rfc::H3_ERR_CLOSED_CRITICAL_STREAM;
        }
        let _ = consume_ignored_uni_stream(conn, stream_id, true);
    }

    if is_push_uni_stream(conn, stream_id) {
        let p_err = process_peer_push_stream(conn, data, offset);
        if fin {
            remove_push_uni_stream(conn, stream_id);
        }
        return p_err;
    }

    if stream_id == conn.peer_control_stream_id && offset < (data.len as u64) {
        return process_peer_control_stream(conn, data, offset);
    }

    if (stream_id == conn.peer_qpack_enc_stream_id || stream_id == conn.peer_qpack_dec_stream_id) &&
       offset < (data.len as u64) {
        return process_peer_qpack_stream(conn, stream_id, data, offset);
    }

    return rfc::H3_ERR_NO_ERROR;
}

fn get_or_create_bidi_stream(conn: H3Connection&, stream_id: u64) -> i32, u64 {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    if found {
        return s_idx, rfc::H3_ERR_NO_ERROR;
    }
    if conn.role == H3ConnRole.Client {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_STREAM_CREATION;
        return -1, rfc::H3_ERR_STREAM_CREATION;
    }
    var reuse_slot: i32 = -1;
    for i in conn.streams.len {
        if conn.streams[i].state == H3StreamState.Closed {
            reuse_slot = i as i32;
            break;
        }
    }
    let ent = H3StreamEntry {
        stream_id:         stream_id,
        kind:              H3StreamKind.Request,
        state:             H3StreamState.Open,
        is_bidi:           true,
        headers_sent:      false,
        headers_received:  false,
        trailers_received: false,
        fin_sent:          false,
        fin_received:      false,
        status_code:       0,
        body_received_len: 0,
        content_length:    -1,
        received_body:     [],
    };
    if reuse_slot >= 0 {
        conn.streams[reuse_slot] = ent;
        return reuse_slot, rfc::H3_ERR_NO_ERROR;
    }
    guard conn.streams.try_push(ent) else {
        return -1, rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    return (conn.streams.len - 1) as i32, rfc::H3_ERR_NO_ERROR;
}

fn is_valid_authority_or_host(val: const u8[:]) -> bool {
    guard val.len > 0 && val.len <= 256 else { return false; }
    for b in val {
        if b <= 0x20 || b >= 0x7F || b == '/' || b == '?' || b == '#' || b == '@' || b == ','
            || b == '\\' || b == '"' || b == '<' || b == '>' || b == '^' || b == '`'
            || b == '{' || b == '|' || b == '}' {
            return false;
        }
    }
    return true;
}

fn has_ctl_chars(val: const u8[:]) -> bool {
    for b in val {
        if (b < 0x20 && b != 0x09) || b == 0x7F {
            return true;
        }
    }
    return false;
}

fn is_forbidden_connection_header(name: const u8[:], value: const u8[:]) -> bool {
    if name.eq_ascii_fold("connection") ||
       name.eq_ascii_fold("keep-alive") ||
       name.eq_ascii_fold("proxy-connection") ||
       name.eq_ascii_fold("transfer-encoding") ||
       name.eq_ascii_fold("upgrade") {
        return true;
    }
    if name.eq_ascii_fold("te") && !value.eq_ascii_fold("trailers") {
        return true;
    }
    return false;
}

fn validate_h3_trailers<F>(conn: H3Connection&, fields: const F&) -> u64 {
    for &field in fields {
        let fname = field.name[..];
        let fval = field.value[..];
        if fname.len > 0 && fname[0] == ':' {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if fname.eq_ascii_fold("content-length") ||
           fname.eq_ascii_fold("host") ||
           fname.eq_ascii_fold("trailer") ||
           fname.eq_ascii_fold("te") ||
           fname.eq_ascii_fold("transfer-encoding") ||
           fname.eq_ascii_fold("connection") ||
           fname.eq_ascii_fold("upgrade") ||
           fname.eq_ascii_fold("keep-alive") ||
           fname.eq_ascii_fold("proxy-connection") ||
           rfc::is_disallowed_trailer_field(fname) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if has_ctl_chars(fval) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if is_forbidden_connection_header(fname, fval) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn validate_pseudo_status(field: const HeaderField&, counts: H3HeaderCounts&, out_sc: i32&) -> bool {
    counts.pseudo_status++;
    guard counts.pseudo_status == 1 && field.value.len == 3 else { return false; }
    let sc, ok_sc = field.value[..].parse_i32_dec();
    guard ok_sc && sc >= 100 && sc <= 599 && sc != 101 else { return false; }
    out_sc = sc;
    return true;
}

fn is_valid_http_method_token(val: const u8[:]) -> bool {
    guard val.len > 0 && val.len <= 16 else { return false; }
    for b in val {
        if !core::is_tchar(b) {
            return false;
        }
    }
    return true;
}

fn is_valid_uri_scheme(val: const u8[:]) -> bool {
    guard val.len > 0 && val.len <= 16 else { return false; }
    let b0 = val[0];
    guard (b0 >= 'a' && b0 <= 'z') || (b0 >= 'A' && b0 <= 'Z') else { return false; }
    for b in val {
        let ok_b = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
            || (b >= '0' && b <= '9') || b == '+' || b == '-' || b == '.';
        if !ok_b {
            return false;
        }
    }
    return true;
}

fn validate_pseudo_method(field: const HeaderField&, counts: H3HeaderCounts&) -> bool {
    counts.pseudo_method++;
    guard counts.pseudo_method == 1 && is_valid_http_method_token(field.value[..]) else { return false; }
    counts.is_connect = (field.value[..] == "CONNECT");
    return true;
}

fn validate_pseudo_scheme(field: const HeaderField&, counts: H3HeaderCounts&) -> bool {
    counts.pseudo_scheme++;
    return counts.pseudo_scheme == 1 && is_valid_uri_scheme(field.value[..]);
}

fn validate_pseudo_authority(field: const HeaderField&, counts: H3HeaderCounts&, auth_val: u8[..256]&) -> bool {
    counts.pseudo_authority++;
    guard counts.pseudo_authority == 1 && is_valid_authority_or_host(field.value[..]) else { return false; }
    return auth_val.try_set(field.value[..]);
}

fn validate_pseudo_path(field: const HeaderField&, counts: H3HeaderCounts&) -> bool {
    counts.pseudo_path++;
    guard counts.pseudo_path == 1 && is_valid_h3_path_bytes(field.value[..]) else { return false; }
    return true;
}

fn validate_pseudo_protocol(field: const HeaderField&, counts: H3HeaderCounts&, enable_conn_proto: bool) -> bool {
    guard enable_conn_proto else { return false; }
    counts.pseudo_protocol++;
    guard counts.pseudo_protocol == 1 && field.value.len > 0 else { return false; }
    for b in field.value {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

fn process_h3_pseudo_field(
    conn:     H3Connection&,
    s_idx:    i32,
    field:    const HeaderField&,
    counts:   H3HeaderCounts&,
    auth_val: u8[..256]&,
) -> u64 {
    if field.name[..] == ":status" {
        var sc: i32 = 0;
        guard validate_pseudo_status(field, counts, sc) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        conn.streams[s_idx].status_code = sc;
        return rfc::H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":method" {
        guard validate_pseudo_method(field, counts) &&
              conn.streams[s_idx].req_method.try_set(field.value[..]) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":scheme" {
        guard validate_pseudo_scheme(field, counts) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":authority" {
        guard validate_pseudo_authority(field, counts, auth_val) &&
              conn.streams[s_idx].req_authority.try_set(field.value[..]) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":path" {
        guard validate_pseudo_path(field, counts) &&
              conn.streams[s_idx].req_path.try_set(field.value[..]) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":protocol" {
        let enable_proto = conn.role == H3ConnRole.Server && conn.local_settings.enable_connect_protocol > 0;
        guard validate_pseudo_protocol(field, counts, enable_proto) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    conn.state = H3ConnState.Closed;
    conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
    return rfc::H3_ERR_GENERAL_PROTOCOL;
}

fn process_h3_regular_field(
    conn:     H3Connection&,
    s_idx:    i32,
    field:    const HeaderField&,
    counts:   H3HeaderCounts&,
    host_val: u8[..256]&,
) -> u64 {
    let fname = field.name[..];
    let fval = field.value[..];
    if fname.eq_ascii_fold("host") {
        counts.host++;
        guard counts.host == 1 && is_valid_authority_or_host(fval) && host_val.try_set(fval) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    if fname.eq_ascii_fold("content-length") {
        let cl, ok_cl = fval.parse_i64_dec();
        let _, ok_u = fval.parse_u64_dec();
        guard ok_cl && ok_u else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if conn.streams[s_idx].content_length >= 0 && conn.streams[s_idx].content_length != cl {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        conn.streams[s_idx].content_length = cl;
        return rfc::H3_ERR_NO_ERROR;
    }
    if fname.eq_ascii_fold("priority") {
        if !conn.streams[s_idx].priority_updated && fval.trim_ascii_space().len > 0 {
            let parsed_p, ok_p = parse_h3_priority_field_value(fval, false);
            if ok_p {
                conn.streams[s_idx].priority = parsed_p;
            }
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn validate_single_h3_header(
    conn:         H3Connection&,
    s_idx:        i32,
    field:        const HeaderField&,
    seen_regular: bool&,
    counts:       H3HeaderCounts&,
    auth_val:     u8[..256]&,
    host_val:     u8[..256]&,
) -> u64 {
    if has_ctl_chars(field.value[..]) {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    let is_pseudo = field.name.len > 0 && field.name[0] == ':';
    if is_pseudo {
        guard !seen_regular else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return process_h3_pseudo_field(conn, s_idx, field, counts, auth_val);
    }

    seen_regular = true;
    if is_forbidden_connection_header(field.name[..], field.value[..])
        || (conn.role == H3ConnRole.Client && field.name[..].eq_ascii_fold("te")) {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return process_h3_regular_field(conn, s_idx, field, counts, host_val);
}

fn validate_h3_headers<F>(conn: H3Connection&, s_idx: i32, fields: const F&) -> u64 {
    var seen_regular = false;
    var counts = H3HeaderCounts { .. };
    var auth_val: u8[..256] = [];
    var host_val: u8[..256] = [];
    conn.streams[s_idx].content_length = -1;

    for &field in fields {
        let h_err = validate_single_h3_header(conn, s_idx, field, seen_regular, counts, auth_val, host_val);
        guard h_err == rfc::H3_ERR_NO_ERROR else { return h_err; }
    }

    if conn.role == H3ConnRole.Client && conn.streams[s_idx].status_code >= 100 &&
       conn.streams[s_idx].status_code < 200 && conn.streams[s_idx].content_length >= 0 {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    if counts.pseudo_authority > 0 && counts.host > 0 {
        if !auth_val[..].eq_ascii_fold(host_val[..]) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }

    if conn.role == H3ConnRole.Server && !counts.is_connect {
        guard counts.pseudo_authority > 0 || counts.host > 0 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }

    let ok_pseudos = validate_h3_pseudo_headers(
        conn.role, counts.pseudo_status, counts.pseudo_method,
        counts.pseudo_scheme, counts.pseudo_path, counts.pseudo_authority,
        counts.is_connect, counts.pseudo_protocol,
    );
    let bad_asterisk = conn.role == H3ConnRole.Server && conn.streams[s_idx].req_path[..] == "*"
        && conn.streams[s_idx].req_method[..] != "OPTIONS";
    guard ok_pseudos && !bad_asterisk else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    if conn.role == H3ConnRole.Server || conn.streams[s_idx].status_code >= 200 {
        conn.streams[s_idx].headers_received = true;
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn validate_push_promise_pseudo_field(
    field:      const HeaderField&,
    counts:     H3HeaderCounts&,
    req_method: u8[..16]&,
    req_path:   u8[..1024]&,
    auth_val:   u8[..256]&,
) -> bool {
    let fname = field.name[..];
    let fval = field.value[..];
    if fname == ":method" {
        return validate_pseudo_method(field, counts) && !counts.is_connect && req_method.try_set(fval);
    }
    if fname == ":scheme" {
        return validate_pseudo_scheme(field, counts);
    }
    if fname == ":authority" {
        return validate_pseudo_authority(field, counts, auth_val);
    }
    if fname == ":path" {
        return validate_pseudo_path(field, counts) && req_path.try_set(fval);
    }
    return false;
}

fn validate_single_push_promise_field(
    field:        const HeaderField&,
    seen_regular: bool&,
    counts:       H3HeaderCounts&,
    req_method:   u8[..16]&,
    req_path:     u8[..1024]&,
    auth_val:     u8[..256]&,
    host_val:     u8[..256]&,
) -> bool {
    let fname = field.name[..];
    let fval = field.value[..];
    guard wing::is_valid_header_name_h2(fname) && !has_ctl_chars(fval) else { return false; }
    if fname.len > 0 && fname[0] == ':' {
        guard !seen_regular else { return false; }
        return validate_push_promise_pseudo_field(field, counts, req_method, req_path, auth_val);
    }
    seen_regular = true;
    guard !is_forbidden_connection_header(fname, fval) && !fname.eq_ascii_fold("content-length") else {
        return false;
    }
    if fname.eq_ascii_fold("host") {
        guard counts.host == 0 && is_valid_authority_or_host(fval) && host_val.try_set(fval) else {
            return false;
        }
        counts.host = 1;
    }
    return true;
}

// RFC 9114 Section 4.6: Server Push - Promised requests MUST include :method, :scheme, :authority, and :path, and MUST NOT use CONNECT.
fn validate_h3_push_promise_fields<F>(
    conn:           H3Connection&,
    decoded_fields: const F&,
) -> u64 {
    if decoded_fields.len == 0 {
        return rfc::H3_ERR_NO_ERROR;
    }
    var seen_regular = false;
    var counts = H3HeaderCounts { .. };
    var req_method: u8[..16]   = [];
    var req_path:   u8[..1024] = [];
    var auth_val:   u8[..256]  = [];
    var host_val:   u8[..256]  = [];

    for &f in decoded_fields {
        let ok = validate_single_push_promise_field(
            f, seen_regular, counts, req_method, req_path, auth_val, host_val,
        );
        guard ok else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }

    let ok_host = counts.host == 0 || auth_val[..].eq_ascii_fold(host_val[..]);
    let ok_req = counts.pseudo_method == 1 && counts.pseudo_scheme == 1 &&
        counts.pseudo_authority == 1 && counts.pseudo_path == 1 &&
        counts.pseudo_status == 0 && counts.pseudo_protocol == 0;
    let bad_asterisk = req_path[..] == "*" && req_method[..] != "OPTIONS";
    guard ok_host && ok_req && !bad_asterisk else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn compute_header_fields_hash<F>(fields: const F&) -> u64 {
    var h: u64 = 0xcbf29ce484222325;
    for &f in fields {
        h = core::wyhash64(f.name[..], h ^ 0x9e3779b97f4a7c15);
        h = core::wyhash64(f.value[..], h ^ 0x517cc1b727220a95);
    }
    return h;
}

// RFC 9114 Section 7.2.5: PUSH_PROMISE - Receiving a duplicate push ID with different header fields MUST be treated as H3_GENERAL_PROTOCOL_ERROR.
fn record_or_verify_promised_push<F>(
    conn:           H3Connection&,
    push_id:        u64,
    decoded_fields: const F&,
) -> u64 {
    let field_hash = compute_header_fields_hash(decoded_fields);
    for &rec in conn.promised_pushes {
        if rec.push_id == push_id {
            guard rec.field_hash == field_hash else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
                return rfc::H3_ERR_GENERAL_PROTOCOL;
            }
            return rfc::H3_ERR_NO_ERROR;
        }
    }
    let new_rec = PromisedPushRecord { push_id: push_id, field_hash: field_hash };
    if !conn.promised_pushes.try_push(new_rec) && conn.promised_pushes.len > 0 {
        conn.promised_pushes.remove_at(0);
        let _ = conn.promised_pushes.try_push(new_rec);
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn handle_bidi_push_promise(conn: H3Connection&, s_idx: i32, payload: const u8[:]) -> u64 {
    // Clients MUST NOT send PUSH_PROMISE frames to servers
    if conn.role == H3ConnRole.Server {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    guard payload.len > 0 && s_idx >= 0 && s_idx < conn.streams.len else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    let push_id, qpack_off, ok_p = quic_internal::quic_decode_varint(payload, 0);
    if !ok_p {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    // Push ID MUST NOT exceed advertised MAX_PUSH_ID (or any push if never advertised)
    if !conn.max_push_id_sent || push_id > conn.max_push_id_advertised {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_ID_ERROR;
        return rfc::H3_ERR_ID_ERROR;
    }
    let qpack_data = payload[(qpack_off as i64)..];
    var dec_tbl .= conn.qpack_table;
    if conn.local_qpack_enc_activated {
        dec_tbl .= conn.qpack_dec_table;
    }
    var decoded_fields: HeaderField[..128] = [];
    let q_err = decode_or_block_qpack_section(
        dec_tbl,
        conn.streams[s_idx].stream_id,
        qpack_data,
        decoded_fields,
        conn.local_settings.max_field_section_size,
        true,
        push_id,
    );
    if q_err != QpackError.None && q_err != QpackError.StreamBlocked {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
        return rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
    }
    if q_err == QpackError.None {
        let v_err = validate_h3_push_promise_fields(conn, decoded_fields);
        guard v_err == rfc::H3_ERR_NO_ERROR else { return v_err; }
        let dup_err = record_or_verify_promised_push(conn, push_id, decoded_fields);
        guard dup_err == rfc::H3_ERR_NO_ERROR else { return dup_err; }
    }
    if !conn.has_promised_push_id || push_id > conn.max_promised_push_id {
        conn.max_promised_push_id = push_id;
    }
    conn.has_promised_push_id = true;
    return rfc::H3_ERR_NO_ERROR;
}

fn handle_bidi_headers(
    conn:    H3Connection&,
    s_idx:   i32,
    payload: const u8[:],
) -> u64 {
    // RFC 9114 §4.1: Extra HEADERS frame after trailers is forbidden
    if conn.streams[s_idx].trailers_received {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    var dec_tbl .= conn.qpack_table;
    if conn.local_qpack_enc_activated {
        dec_tbl .= conn.qpack_dec_table;
    }
    var decoded_fields: HeaderField[..128] = [];
    let q_err = decode_or_block_qpack_section(
        dec_tbl,
        conn.streams[s_idx].stream_id,
        payload,
        decoded_fields,
        conn.local_settings.max_field_section_size,
    );
    if q_err == QpackError.StreamBlocked {
        return rfc::H3_ERR_NO_ERROR;
    }
    if q_err != QpackError.None {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
        return rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
    }

    let is_trailer = conn.streams[s_idx].headers_received &&
        (conn.role == H3ConnRole.Server || conn.streams[s_idx].status_code >= 200);

    if is_trailer {
        let t_err = validate_h3_trailers(conn, decoded_fields);
        guard t_err == rfc::H3_ERR_NO_ERROR else { return t_err; }
        conn.streams[s_idx].trailers.clear();
        for &f in decoded_fields {
            guard wing::append_header(conn.streams[s_idx].trailers, f.name[..], f.value[..]) else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
                return rfc::H3_ERR_EXCESSIVE_LOAD;
            }
        }
        conn.streams[s_idx].trailers_received = true;
        return rfc::H3_ERR_NO_ERROR;
    }

    let v_err = validate_h3_headers(conn, s_idx, decoded_fields);
    guard v_err == rfc::H3_ERR_NO_ERROR else { return v_err; }
    conn.streams[s_idx].headers.clear();
    for &f in decoded_fields {
        if f.name.len > 0 && f.name[0] != ':' {
            guard wing::append_header(conn.streams[s_idx].headers, f.name[..], f.value[..]) else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
                return rfc::H3_ERR_EXCESSIVE_LOAD;
            }
        }
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn check_h3_empty_streak(conn: H3Connection&, payload_len: u64) -> bool {
    if payload_len == 0 {
        conn.empty_frame_streak++;
        return conn.empty_frame_streak <= MAX_H3_EMPTY_FRAME_STREAK;
    }
    conn.empty_frame_streak = 0;
    return true;
}

fn is_h3_data_allowed(stream: const H3StreamEntry&) -> bool {
    if !stream.headers_received || stream.trailers_received {
        return false;
    }
    let sc = stream.status_code;
    if sc == 204 || sc == 304 || (sc >= 100 && sc < 200) {
        return false;
    }
    if sc > 0 && stream.req_method[..] == "HEAD" {
        return false;
    }
    return true;
}

fn append_stream_body(stream: H3StreamEntry&, payload: const u8[:]) -> u64 {
    guard stream.received_body.try_append(payload) else {
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    stream.body_received_len += payload.len as u64;

    if stream.content_length >= 0 && stream.body_received_len > (stream.content_length as u64) {
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn handle_bidi_data(
    conn:        H3Connection&,
    s_idx:       i32,
    payload_len: u64,
    payload:     const u8[:],
) -> u64 {
    guard check_h3_empty_streak(conn, payload_len) else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }

    guard s_idx >= 0 && s_idx < conn.streams.len else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    guard is_h3_data_allowed(conn.streams[s_idx]) else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    let b_err = append_stream_body(conn.streams[s_idx], payload);
    guard b_err == rfc::H3_ERR_NO_ERROR else {
        conn.state = H3ConnState.Closed;
        conn.error_code = b_err;
        return b_err;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn dispatch_bidi_stream_frame(
    conn:    H3Connection&,
    s_idx:   i32,
    hdr:     const H3FrameHeader&,
    payload: const u8[:],
) -> u64 {
    if !rfc::is_allowed_on_request_stream(hdr.frame_type) {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    if hdr.frame_type == rfc::H3_FRAME_PUSH_PROMISE {
        return handle_bidi_push_promise(conn, s_idx, payload);
    }
    if hdr.frame_type == rfc::H3_FRAME_HEADERS {
        return handle_bidi_headers(conn, s_idx, payload);
    }
    if hdr.frame_type == rfc::H3_FRAME_DATA {
        return handle_bidi_data(conn, s_idx, hdr.payload_len, payload);
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn buffer_partial_bidi_frame(conn: H3Connection&, s_idx: i32, rem: const u8[:], fin: bool) -> u64 {
    guard !fin && conn.streams[s_idx].rx_partial_buf.try_set(rem) else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    return rfc::H3_ERR_NO_ERROR;
}

// RFC 9204 Section 2.2.1: Blocked Decoding - Wait for Required Insert Count entries before processing remaining frames on the blocked stream.
fn handle_bidi_stream_frames(
    conn:  H3Connection&,
    s_idx: i32,
    data:  const u8[:],
    fin:   bool = true,
) -> u64 {
    var work_buf: u8[..8192] = [];
    if conn.streams[s_idx].rx_partial_buf.len > 0 {
        guard work_buf.try_append(conn.streams[s_idx].rx_partial_buf[..]) && work_buf.try_append(data) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        conn.streams[s_idx].rx_partial_buf.clear();
    }
    let buf = if work_buf.len > 0 { work_buf[..] } else { data };
    var offset: u64 = 0;
    while offset < (buf.len as u64) {
        var dec_tbl .= conn.qpack_table;
        if conn.local_qpack_enc_activated {
            dec_tbl .= conn.qpack_dec_table;
        }
        if qpack_is_stream_blocked(dec_tbl, conn.streams[s_idx].stream_id) {
            guard conn.streams[s_idx].blocked_wire.try_append(buf[(offset as i64)..]) else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
                return rfc::H3_ERR_EXCESSIVE_LOAD;
            }
            return rfc::H3_ERR_NO_ERROR;
        }
        let frame_start = offset;
        let hdr, ok_hdr = parse_h3_frame_header(buf, offset);
        if !ok_hdr {
            let rem = buf[(frame_start as i64)..];
            guard rem.len < 16 else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_FRAME_ERROR;
                return rfc::H3_ERR_FRAME_ERROR;
            }
            return buffer_partial_bidi_frame(conn, s_idx, rem, fin);
        }
        if !rfc::is_allowed_on_request_stream(hdr.frame_type) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
            return rfc::H3_ERR_FRAME_UNEXPECTED;
        }
        offset = core::add_sat_u64(offset, hdr.header_len);
        let end_off = core::add_sat_u64(offset, hdr.payload_len);
        if end_off > (buf.len as u64) {
            guard core::add_sat_u64(hdr.header_len, hdr.payload_len) <= 4096 else {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_FRAME_ERROR;
                return rfc::H3_ERR_FRAME_ERROR;
            }
            return buffer_partial_bidi_frame(conn, s_idx, buf[(frame_start as i64)..], fin);
        }
        let payload = buf[(offset as i64)..(end_off as i64)];
        offset = end_off;
        let f_err = dispatch_bidi_stream_frame(conn, s_idx, hdr, payload);
        guard f_err == rfc::H3_ERR_NO_ERROR else { return f_err; }
    }
    return rfc::H3_ERR_NO_ERROR;
}

// Handles incoming raw bytes on a given stream.
fn handle_stream_data(
    conn:      H3Connection&,
    stream_id: u64,
    is_bidi:   bool,
    data:      const u8[:],
    fin:       bool,
) -> u64 {
    if !is_bidi {
        return handle_uni_stream_data(conn, stream_id, data, fin);
    }

    // RFC 9114 Section 6.1: HTTP/3 does not use server-initiated bidirectional streams.
    // Client-initiated bidirectional streams have (stream_id & 0x03) == 0.
    // WebTransport permits server-initiated bidirectional streams with (stream_id & 0x03) == 1.
    let is_client_bidi = (stream_id & 0x03) == 0;
    let wt_enabled = conn.local_settings.enable_webtransport > 0 &&
        conn.peer_settings.enable_webtransport > 0;
    let is_server_wt_bidi = wt_enabled && ((stream_id & 0x03) == 1);
    guard is_client_bidi || is_server_wt_bidi else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_STREAM_CREATION;
        return rfc::H3_ERR_STREAM_CREATION;
    }

    let s_idx, err = get_or_create_bidi_stream(conn, stream_id);
    guard err == rfc::H3_ERR_NO_ERROR else { return err; }

    guard !conn.streams[s_idx].fin_received else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    let f_err = handle_bidi_stream_frames(conn, s_idx, data, fin);
    guard f_err == rfc::H3_ERR_NO_ERROR else { return f_err; }

    if fin {
        conn.streams[s_idx].fin_received = true;
        if conn.streams[s_idx].fin_sent {
            conn.streams[s_idx].state = H3StreamState.Closed;
        } else {
            conn.streams[s_idx].state = H3StreamState.HalfClosedRemote;
        }
        var dec_tbl .= conn.qpack_table;
        if conn.local_qpack_enc_activated {
            dec_tbl .= conn.qpack_dec_table;
        }
        if !qpack_is_stream_blocked(dec_tbl, stream_id) {
            let fin_err = check_bidi_stream_fin_complete(conn, s_idx);
            guard fin_err == rfc::H3_ERR_NO_ERROR else { return fin_err; }
        }
    }

    return rfc::H3_ERR_NO_ERROR;
}

// ---- Stream Inspection Accessors ----------------------------------------

fn get_status_code(conn: const H3Connection&, stream_id: u64) -> i32, bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len && conn.streams[s_idx].headers_received {
        return conn.streams[s_idx].status_code, true;
    }
    return 0, false;
}

fn get_response_body(conn: const H3Connection&, stream_id: u64) -> const u8[:], bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len {
        return conn.streams[s_idx].received_body[..], true;
    }
    return "", false;
}

fn copy_stream_headers(conn: const H3Connection&, stream_id: u64, out_headers: wing::HeaderMap&) -> bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len && conn.streams[s_idx].headers_received else {
        return false;
    }
    out_headers.clear();
    let src .= conn.streams[s_idx].headers;
    for &e in src.entries {
        let name = wing::entry_name(src, e);
        let val = wing::entry_value(src, e);
        if !wing::append_header(out_headers, name, val) {
            return false;
        }
    }
    return true;
}

fn copy_stream_trailers(conn: const H3Connection&, stream_id: u64, out_trailers: wing::HeaderMap&) -> bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len && conn.streams[s_idx].trailers_received else {
        return false;
    }
    out_trailers.clear();
    let src .= conn.streams[s_idx].trailers;
    for &e in src.entries {
        let name = wing::entry_name(src, e);
        let val = wing::entry_value(src, e);
        if !wing::append_header(out_trailers, name, val) {
            return false;
        }
    }
    return true;
}

fn is_stream_finished(conn: const H3Connection&, stream_id: u64) -> bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len {
        return conn.streams[s_idx].fin_received;
    }
    return false;
}

// Encodes a server HTTP/3 response (HEADERS + optional DATA + optional trailing HEADERS) onto `out` (RFC 9114 §4.1).
fn send_response_headers_body_and_trailers<B>(
    conn:          H3Connection&,
    stream_id:     u64,
    status_code:   i32,
    extra_headers: const wing::HeaderMap&,
    body:          const u8[:],
    trailers:      const wing::HeaderMap&,
    out:           B&,
) -> bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found else { return false; }

    var enc_tbl .= conn.qpack_static_only_tbl;
    if conn.local_qpack_enc_activated {
        enc_tbl .= conn.qpack_table;
    }
    let saved_out_len = out.len;
    let saved_enc_len = conn.encoder_stream_buf.len;
    let saved_tbl = enc_tbl;
    let saved_headers_sent = conn.streams[s_idx].headers_sent;
    let saved_fin_sent = conn.streams[s_idx].fin_sent;
    let saved_state = conn.streams[s_idx].state;
    var committed = false;
    defer if !committed {
        out.resize(saved_out_len);
        conn.encoder_stream_buf.resize(saved_enc_len);
        enc_tbl = saved_tbl;
        conn.streams[s_idx].headers_sent = saved_headers_sent;
        conn.streams[s_idx].fin_sent = saved_fin_sent;
        conn.streams[s_idx].state = saved_state;
    };

    var sc_str: u8[..16] = [];
    status_code.format_i64_dec(sc_str);

    let base = enc_tbl.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    var body_fields: u8[..4096] = [];

    guard try_encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":status", sc_str[..],
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, false,
    ) && encode_h3_extra_headers(
        enc_tbl, stream_id, base, extra_headers,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn,
    ) else {
        return false;
    }

    var qpack_payload: u8[..4096] = [];
    guard try_prepend_qpack_section_prefix(
        enc_tbl, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload,
    ) && qpack_payload.try_append(body_fields[..]) &&
          encode_h3_headers_frame(out, qpack_payload[..]) else {
        return false;
    }

    conn.streams[s_idx].headers_sent = true;
    if body.len > 0 {
        guard encode_h3_data_frame(out, body) else { return false; }
    }
    if trailers.entries.len > 0 {
        let tr_base = enc_tbl.insert_count;
        var tr_max_dyn: u64 = 0;
        var tr_used_dyn = false;
        var tr_fields: u8[..4096] = [];
        guard encode_h3_extra_headers(
            enc_tbl, stream_id, tr_base, trailers,
            tr_fields, conn.encoder_stream_buf, tr_max_dyn, tr_used_dyn,
        ) else {
            return false;
        }
        var tr_payload: u8[..4096] = [];
        guard try_prepend_qpack_section_prefix(
            enc_tbl, stream_id, tr_base, tr_max_dyn, tr_used_dyn, tr_payload,
        ) && tr_payload.try_append(tr_fields[..]) &&
              encode_h3_headers_frame(out, tr_payload[..]) else {
            return false;
        }
    }
    conn.streams[s_idx].fin_sent = true;
    conn.streams[s_idx].state = H3StreamState.Closed;
    committed = true;
    return true;
}

fn apply_h3_stream_priority(conn: H3Connection&, stream_id: u64, prio: const wing::PriorityParam&) -> bool {
    var s_idx, found = find_h3_stream_idx(conn, stream_id);
    if !found && conn.role == H3ConnRole.Server && (stream_id & 0x03) == 0 {
        let new_idx, err = get_or_create_bidi_stream(conn, stream_id);
        if err == rfc::H3_ERR_NO_ERROR && new_idx >= 0 {
            s_idx = new_idx;
            found = true;
        }
    }
    guard found && s_idx >= 0 && s_idx < conn.streams.len else { return false; }
    conn.streams[s_idx].priority = prio;
    conn.streams[s_idx].priority_updated = true;
    return true;
}

fn get_stream_priority(conn: const H3Connection&, stream_id: u64) -> wing::PriorityParam, bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else {
        return wing::priority_default(false), false;
    }
    return conn.streams[s_idx].priority, true;
}

inline fn is_better_h3_tx_candidate(
    cand: const H3StreamEntry&,
    best: const H3StreamEntry&,
) -> bool {
    if cand.priority.urgency != best.priority.urgency {
        return cand.priority.urgency < best.priority.urgency;
    }
    if cand.priority.incremental {
        if cand.last_scheduled_cycle != best.last_scheduled_cycle {
            return cand.last_scheduled_cycle < best.last_scheduled_cycle;
        }
    }
    return cand.stream_id < best.stream_id;
}

// Selects the next writable request stream according to RFC 9218 Extensible Priorities.
// Scans streams with `tx_pending_bytes > 0`, selecting minimum `priority.urgency` (`0..7`),
// breaking ties by `stream_id` when `!priority.incremental` and by `last_scheduled_cycle`
// when `priority.incremental`.
fn select_next_h3_tx_stream(conn: H3Connection&) -> u64, bool {
    let next_cycle = min(conn.sched_cycle, 0xFFFFFFFFFFFFFFFE) + 1;
    var best_idx: i64 = -1;
    for i in conn.streams.len {
        if conn.streams[i].tx_pending_bytes > 0 {
            if best_idx < 0 || is_better_h3_tx_candidate(conn.streams[i], conn.streams[best_idx]) {
                best_idx = i;
            }
        }
    }
    guard best_idx >= 0 && best_idx < conn.streams.len else { return 0, false; }
    conn.sched_cycle = next_cycle;
    conn.streams[best_idx].last_scheduled_cycle = next_cycle;
    return conn.streams[best_idx].stream_id, true;
}
