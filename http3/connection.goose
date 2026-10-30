// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Connection Coordinator and Stream Multiplexer.
// Conforms to RFC 9114 (HTTP/3), RFC 9204 (QPACK), and RFC 9000 (QUIC Streams).
namespace internal;

import std;
import http.headers;
import quic.packet;
import http3.qpack;
import http3.framing;

// ---- 1. Stream Kinds, States and Structures --------------------------------

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
    stream_id:         u64                 = 0,
    kind:              H3StreamKind        = H3StreamKind.Request,
    state:             H3StreamState       = H3StreamState.Idle,
    is_bidi:           bool                = true,
    headers_sent:      bool                = false,
    headers_received:  bool                = false,
    trailers_received: bool                = false,
    fin_sent:          bool                = false,
    fin_received:      bool                = false,
    status_code:       i32                 = 0,
    body_received_len: u64                 = 0,
    content_length:    i64                 = -1,
    priority:          wing::PriorityParam = wing::PriorityParam { urgency: 3, incremental: false },
    received_body:     u8[..4096]          = [],
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
    pseudo_status:    i32 = 0,
    pseudo_method:    i32 = 0,
    pseudo_scheme:    i32 = 0,
    pseudo_authority: i32 = 0,
    pseudo_path:      i32 = 0,
    host:             i32 = 0,
}

struct H3Connection {
    role:                      H3ConnRole          = H3ConnRole.Client,
    state:                     H3ConnState         = H3ConnState.Connecting,
    next_bidi_stream_id:       u64                 = 0,
    local_control_stream_id:   u64                 = 2,
    local_qpack_enc_stream_id: u64                 = 6,
    local_qpack_dec_stream_id: u64                 = 10,
    local_settings_sent:       bool                = false,
    peer_control_stream_id:    u64                 = 0xFFFFFFFFFFFFFFFF,
    peer_control_opened:       bool                = false,
    peer_settings_received:    bool                = false,
    peer_qpack_enc_stream_id:  u64                 = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_enc_opened:     bool                = false,
    peer_qpack_dec_stream_id:  u64                 = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_dec_opened:     bool                = false,
    ignored_uni_streams:       u64[..16]           = [],
    goaway_received:           bool                = false,
    goaway_max_stream_id:      u64                 = 0xFFFFFFFFFFFFFFFF,
    max_push_id_sent:          bool                = false,
    max_push_id_advertised:    u64                 = 0,
    max_push_id_received:      u64                 = 0,
    empty_frame_streak:        u32                 = 0,
    error_code:                u64                 = H3_ERR_NO_ERROR,
    local_settings:            wing::H3Settings    = wing::H3Settings { .. },
    peer_settings:             wing::H3Settings    = wing::H3Settings { .. },
    streams:                   H3StreamEntry[..32] = [],
    qpack_table:               QpackTable          = QpackTable { .. }, // Resizable array must be final field
}

fn new_h3_client_connection(settings: const wing::H3Settings&) -> H3Connection {
    return H3Connection {
        role:           H3ConnRole.Client,
        local_settings: settings,
        qpack_table:    new_qpack_table(settings.qpack_max_table_capacity, settings.qpack_blocked_streams as u32, 0),
        ..
    };
}

fn new_h3_server_connection(settings: const wing::H3Settings&) -> H3Connection {
    return H3Connection {
        role:           H3ConnRole.Server,
        local_settings: settings,
        qpack_table:    new_qpack_table(settings.qpack_max_table_capacity, settings.qpack_blocked_streams as u32, 0),
        ..
    };
}

// Advertises MAX_PUSH_ID frame from client to server (RFC 9114 Section 7.2.7).
fn send_max_push_id<B>(conn: H3Connection&, max_push_id: u64, out: B&) -> bool {
    guard conn.role == H3ConnRole.Client else { return false; }
    guard encode_h3_max_push_id(out, max_push_id) else { return false; }
    conn.max_push_id_sent = true;
    conn.max_push_id_advertised = max_push_id;
    return true;
}

// ---- 2. Preamble & Unidirectional Stream Creation ---------------------------

// Encodes client preambles for control, QPACK encoder, and QPACK decoder streams.
fn encode_client_preambles<B1, B2, B3>(
    conn:          H3Connection&,
    out_ctrl:      B1&,
    out_qpack_enc: B2&,
    out_qpack_dec: B3&,
) -> bool {
    // 1. Control Stream: Stream Type 0x00 || SETTINGS Frame
    quic_encode_varint(out_ctrl, H3_STREAM_CONTROL);
    encode_h3_settings_frame(out_ctrl, conn.local_settings);

    // 2. QPACK Encoder Stream: Stream Type 0x02
    quic_encode_varint(out_qpack_enc, H3_STREAM_QPACK_ENCODER);

    // 3. QPACK Decoder Stream: Stream Type 0x03
    quic_encode_varint(out_qpack_dec, H3_STREAM_QPACK_DECODER);

    conn.local_settings_sent = true;
    return true;
}

// ---- 3. Request Stream Lifecycle --------------------------------------------

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

    var slot_idx: i32 = -1;
    for i in conn.streams.len {
        if conn.streams[i].state == H3StreamState.Closed {
            slot_idx = i as i32;
            break;
        }
    }
    if slot_idx < 0 {
        guard conn.streams.len < conn.streams.cap else { return 0, false; }
    }

    let sid = conn.next_bidi_stream_id;
    if conn.goaway_received && sid >= conn.goaway_max_stream_id {
        return 0, false;
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
        conn.streams.push(ent);
    }

    conn.next_bidi_stream_id += 4;
    return sid, true;
}

// Encodes request headers into QPACK field section and wraps in a HEADERS frame.
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
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found else { return false; }

    // Build QPACK field section:
    // Required prefix: EncodedInsertCount (0) and SignBit + DeltaBase (0) -> 2 bytes: 0x00, 0x00
    var qpack_payload: u8[..4096] = [];
    qpack_payload.push(0x00);
    qpack_payload.push(0x00);

    // Pseudo-headers (RFC 9114 Section 4.3.1)
    encode_qpack_field(qpack_payload, ":method", method, true);
    encode_qpack_field(qpack_payload, ":scheme", scheme, true);
    encode_qpack_field(qpack_payload, ":authority", authority, true);
    encode_qpack_field(qpack_payload, ":path", path, true);

    // Extra application headers
    for i in extra_headers.entries.len {
        let entry = extra_headers.entries[i];
        let name = extra_headers.raw_buf[entry.name_begin..entry.name_end];
        let val = extra_headers.raw_buf[entry.values_begin..entry.values_end];
        encode_qpack_field(qpack_payload, name, val, true);
    }

    // Wrap in HEADERS frame
    let ok_frame = encode_h3_headers_frame(out, qpack_payload[..]);
    guard ok_frame else { return false; }

    conn.streams[s_idx].headers_sent = true;
    if end_stream {
        conn.streams[s_idx].fin_sent = true;
        conn.streams[s_idx].state = H3StreamState.HalfClosedLocal;
    }
    return true;
}

// Encodes a DATA frame on an open request stream.
fn send_request_data<B>(
    conn:       H3Connection&,
    stream_id:  u64,
    data:       const u8[:],
    end_stream: bool,
    out:        B&,
) -> bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else { return false; }
    guard conn.streams[s_idx].headers_sent else { return false; }

    let ok_frame = encode_h3_data_frame(out, data);
    guard ok_frame else { return false; }

    if end_stream {
        conn.streams[s_idx].fin_sent = true;
        conn.streams[s_idx].state = H3StreamState.HalfClosedLocal;
    }
    return true;
}

// ---- 4. Inbound Frame and Stream Processing ---------------------------------

// Handles frames received on the peer control stream.
fn handle_peer_control_frame(conn: H3Connection&, hdr: const H3FrameHeader&, payload: const u8[:]) -> u64 {
    // Strictly forbidden frames on control stream take precedence (RFC 9114 §7.2.1, §7.2.2, §7.2.5, §7.2.8)
    guard is_allowed_on_control_stream(hdr.frame_type) else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
        return H3_ERR_FRAME_UNEXPECTED;
    }

    // First frame on Control Stream MUST be SETTINGS (RFC 9114 §6.2.1 & §7.2.4)
    if !conn.peer_settings_received {
        if hdr.frame_type != H3_FRAME_SETTINGS {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_MISSING_SETTINGS;
            return H3_ERR_MISSING_SETTINGS;
        }
        let set_err = parse_h3_settings_frame(payload, conn.peer_settings);
        guard set_err == H3_ERR_NO_ERROR else {
            conn.state = H3ConnState.Closed;
            conn.error_code = set_err;
            return set_err;
        }
        conn.peer_settings_received = true;
        conn.state = H3ConnState.Active;
        return H3_ERR_NO_ERROR;
    }

    // Subsequent frames must not be SETTINGS
    guard hdr.frame_type != H3_FRAME_SETTINGS else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
        return H3_ERR_FRAME_UNEXPECTED;
    }

    if hdr.frame_type == H3_FRAME_GOAWAY {
        let max_sid, ok_ga = parse_h3_goaway_frame(payload);
        guard ok_ga else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }
        if conn.role == H3ConnRole.Client && (max_sid & 0x03) != 0 {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_ID_ERROR;
            return H3_ERR_ID_ERROR;
        }
        if conn.goaway_received && max_sid > conn.goaway_max_stream_id {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_ID_ERROR;
            return H3_ERR_ID_ERROR;
        }
        conn.goaway_received = true;
        conn.goaway_max_stream_id = max_sid;
        conn.state = H3ConnState.Draining;
        return H3_ERR_NO_ERROR;
    }

    if hdr.frame_type == H3_FRAME_CANCEL_PUSH {
        let push_id, ok_cp = parse_h3_cancel_push(payload);
        guard ok_cp else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }
        if conn.max_push_id_sent && push_id > conn.max_push_id_advertised {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_ID_ERROR;
            return H3_ERR_ID_ERROR;
        }
        return H3_ERR_NO_ERROR;
    }

    if hdr.frame_type == H3_FRAME_MAX_PUSH_ID {
        guard conn.role != H3ConnRole.Client else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_UNEXPECTED;
            return H3_ERR_FRAME_UNEXPECTED;
        }
        let max_pid, ok_mp = parse_h3_max_push_id(payload);
        guard ok_mp else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }
        if conn.max_push_id_received > 0 && max_pid < conn.max_push_id_received {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_ID_ERROR;
            return H3_ERR_ID_ERROR;
        }
        conn.max_push_id_received = max_pid;
        return H3_ERR_NO_ERROR;
    }

    if hdr.frame_type == H3_FRAME_PRIORITY_UPDATE_REQUEST {
        guard conn.role != H3ConnRole.Client else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_UNEXPECTED;
            return H3_ERR_FRAME_UNEXPECTED;
        }
        let req_stream_id, prio, ok_pu = parse_h3_priority_update_request(payload);
        guard ok_pu else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }
        guard (req_stream_id & 0x03) == 0 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_ID_ERROR;
            return H3_ERR_ID_ERROR;
        }
        apply_h3_stream_priority(conn, req_stream_id, prio);
        return H3_ERR_NO_ERROR;
    }

    if hdr.frame_type == H3_FRAME_PRIORITY_UPDATE_PUSH {
        guard conn.role != H3ConnRole.Client else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_UNEXPECTED;
            return H3_ERR_FRAME_UNEXPECTED;
        }
        let push_id, prio, ok_pu = parse_h3_priority_update_push(payload);
        guard ok_pu else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }
        if conn.max_push_id_sent && push_id > conn.max_push_id_advertised {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_ID_ERROR;
            return H3_ERR_ID_ERROR;
        }
        return H3_ERR_NO_ERROR;
    }

    return H3_ERR_NO_ERROR;
}

// Validates required HTTP/3 pseudo-headers (RFC 9114 Section 4.3).
fn validate_h3_pseudo_headers(
    role:         H3ConnRole,
    status_count: i32,
    method_count: i32,
    scheme_count: i32,
    path_count:   i32,
    auth_count:   i32,
) -> bool {
    if role == H3ConnRole.Client {
        return status_count == 1 && method_count == 0 && scheme_count == 0 && path_count == 0 && auth_count == 0;
    }
    return status_count == 0 && method_count == 1 && scheme_count == 1 && path_count == 1;
}

// Handles the opening of an HTTP/3 unidirectional Push Stream (RFC 9114 §6.2.2 & §4.6).
//
// Example:
//   conn.role = Server, stype = H3_STREAM_PUSH
//   returns: H3_ERR_STREAM_CREATION (0x0103)
fn handle_push_stream_open(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
    offset:    u64,
) -> u64 {
    if conn.role == H3ConnRole.Server {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_STREAM_CREATION;
        return H3_ERR_STREAM_CREATION;
    }

    let push_id, _, ok_p = quic_decode_varint(data, offset);
    guard ok_p else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
        return H3_ERR_GENERAL_PROTOCOL;
    }

    if !conn.max_push_id_sent || push_id > conn.max_push_id_advertised {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_ID_ERROR;
        return H3_ERR_ID_ERROR;
    }

    guard conn.ignored_uni_streams.len < conn.ignored_uni_streams.cap else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_EXCESSIVE_LOAD;
        return H3_ERR_EXCESSIVE_LOAD;
    }
    conn.ignored_uni_streams.push(stream_id);
    return H3_ERR_NO_ERROR;
}

fn process_peer_control_stream(conn: H3Connection&, data: const u8[:], start_offset: u64) -> u64 {
    var offset = start_offset;
    while offset < (data.len as u64) {
        let hdr, ok_hdr = parse_h3_frame_header(data, offset);
        guard ok_hdr else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }

        offset += hdr.header_len;
        guard (0xFFFFFFFFFFFFFFFF - offset) >= hdr.payload_len &&
              (offset + hdr.payload_len) <= (data.len as u64) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }

        let p_start = offset as i64;
        let p_end = (offset + hdr.payload_len) as i64;
        let payload = data[p_start..p_end];
        offset += hdr.payload_len;

        let c_err = handle_peer_control_frame(conn, hdr, payload);
        guard c_err == H3_ERR_NO_ERROR else { return c_err; }
    }
    return H3_ERR_NO_ERROR;
}

fn process_peer_qpack_stream(
    conn:         H3Connection&,
    stream_id:    u64,
    data:         const u8[:],
    start_offset: u64,
) -> u64 {
    var offset = start_offset;
    if stream_id == conn.peer_qpack_enc_stream_id {
        while offset < (data.len as u64) {
            let next_off, q_err = qpack_process_encoder_instruction(conn.qpack_table, data, offset);
            if q_err != QpackError.None {
                conn.state = H3ConnState.Closed;
                conn.error_code = H3_ERR_QPACK_ENCODER_STREAM_ERROR;
                return H3_ERR_QPACK_ENCODER_STREAM_ERROR;
            }
            offset = next_off;
        }
        return H3_ERR_NO_ERROR;
    }
    if stream_id == conn.peer_qpack_dec_stream_id {
        while offset < (data.len as u64) {
            let next_off, q_err = qpack_process_decoder_instruction(conn.qpack_table, data, offset);
            if q_err != QpackError.None {
                conn.state = H3ConnState.Closed;
                conn.error_code = H3_ERR_QPACK_DECODER_STREAM_ERROR;
                return H3_ERR_QPACK_DECODER_STREAM_ERROR;
            }
            offset = next_off;
        }
        return H3_ERR_NO_ERROR;
    }
    return H3_ERR_NO_ERROR;
}

fn register_peer_uni_stream(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
) -> u64, u64 {
    let stype, off1, ok_type = quic_decode_varint(data, 0);
    guard ok_type else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
        return 0, H3_ERR_GENERAL_PROTOCOL;
    }

    if stype == H3_STREAM_CONTROL {
        if conn.peer_control_opened {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_STREAM_CREATION;
            return 0, H3_ERR_STREAM_CREATION;
        }
        conn.peer_control_opened = true;
        conn.peer_control_stream_id = stream_id;
        return off1, H3_ERR_NO_ERROR;
    }
    if stype == H3_STREAM_QPACK_ENCODER {
        if conn.peer_qpack_enc_opened {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_STREAM_CREATION;
            return 0, H3_ERR_STREAM_CREATION;
        }
        conn.peer_qpack_enc_opened = true;
        conn.peer_qpack_enc_stream_id = stream_id;
        return off1, H3_ERR_NO_ERROR;
    }
    if stype == H3_STREAM_QPACK_DECODER {
        if conn.peer_qpack_dec_opened {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_STREAM_CREATION;
            return 0, H3_ERR_STREAM_CREATION;
        }
        conn.peer_qpack_dec_opened = true;
        conn.peer_qpack_dec_stream_id = stream_id;
        return off1, H3_ERR_NO_ERROR;
    }
    if stype == H3_STREAM_PUSH {
        let p_err = handle_push_stream_open(conn, stream_id, data, off1);
        return off1, p_err;
    }

    // Unknown unidirectional stream: ignore payload (RFC 9114 Section 6.2)
    guard conn.ignored_uni_streams.len < conn.ignored_uni_streams.cap else {
        return 0, H3_ERR_NO_ERROR;
    }
    conn.ignored_uni_streams.push(stream_id);
    return 0, H3_ERR_NO_ERROR;
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

fn handle_uni_stream_data(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
    fin:       bool,
) -> u64 {
    guard data.len > 0 || fin else { return H3_ERR_NO_ERROR; }

    for sid in conn.ignored_uni_streams {
        if sid == stream_id {
            return H3_ERR_NO_ERROR;
        }
    }

    var offset: u64 = 0;
    let is_known = is_critical_uni_stream(conn, stream_id);

    // RFC 9114 §6.2: Closing a unidirectional stream before stream type header is an error
    if !is_known && data.len == 0 && fin {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
        return H3_ERR_GENERAL_PROTOCOL;
    }

    if !is_known && data.len > 0 {
        let next_off, reg_err = register_peer_uni_stream(conn, stream_id, data);
        guard reg_err == H3_ERR_NO_ERROR else { return reg_err; }
        offset = next_off;
    }

    // Critical stream closure defense (RFC 9114 Section 6.2.1)
    if fin {
        if is_critical_uni_stream(conn, stream_id) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_CLOSED_CRITICAL_STREAM;
            return H3_ERR_CLOSED_CRITICAL_STREAM;
        }
        for i in conn.ignored_uni_streams.len {
            if conn.ignored_uni_streams[i] == stream_id {
                conn.ignored_uni_streams.remove_at(i);
                break;
            }
        }
    }

    if stream_id == conn.peer_control_stream_id && offset < (data.len as u64) {
        return process_peer_control_stream(conn, data, offset);
    }

    if (stream_id == conn.peer_qpack_enc_stream_id || stream_id == conn.peer_qpack_dec_stream_id) &&
       offset < (data.len as u64) {
        return process_peer_qpack_stream(conn, stream_id, data, offset);
    }

    return H3_ERR_NO_ERROR;
}

fn get_or_create_bidi_stream(conn: H3Connection&, stream_id: u64) -> i32, u64 {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    if found {
        return s_idx, H3_ERR_NO_ERROR;
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
        return reuse_slot, H3_ERR_NO_ERROR;
    }
    guard conn.streams.len < conn.streams.cap else {
        return -1, H3_ERR_EXCESSIVE_LOAD;
    }
    conn.streams.push(ent);
    return (conn.streams.len - 1) as i32, H3_ERR_NO_ERROR;
}

fn is_valid_authority_or_host(val: const u8[:]) -> bool {
    guard val.len > 0 && val.len <= 256 else { return false; }
    for b in val {
        if b <= 0x20 || b == 0x7F || b == '/' || b == '?' || b == '#' || b == '@' || b == ',' {
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
    if eq_ascii_fold(name, "connection") ||
       eq_ascii_fold(name, "keep-alive") ||
       eq_ascii_fold(name, "proxy-connection") ||
       eq_ascii_fold(name, "transfer-encoding") ||
       eq_ascii_fold(name, "upgrade") {
        return true;
    }
    if eq_ascii_fold(name, "te") && !eq_ascii_fold(value, "trailers") {
        return true;
    }
    return false;
}

fn validate_h3_trailers(conn: H3Connection&, fields: const HeaderField[>..]&) -> u64 {
    for field in fields {
        if field.name.len > 0 && field.name[0] == ':' {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        if eq_ascii_fold(field.name[..], "content-length") ||
           eq_ascii_fold(field.name[..], "host") ||
           eq_ascii_fold(field.name[..], "trailer") ||
           eq_ascii_fold(field.name[..], "transfer-encoding") ||
           eq_ascii_fold(field.name[..], "connection") ||
           eq_ascii_fold(field.name[..], "upgrade") ||
           eq_ascii_fold(field.name[..], "keep-alive") ||
           eq_ascii_fold(field.name[..], "proxy-connection") {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        if has_ctl_chars(field.value[..]) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        if is_forbidden_connection_header(field.name[..], field.value[..]) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
    }
    return H3_ERR_NO_ERROR;
}

fn process_h3_pseudo_field(
    conn:     H3Connection&,
    s_idx:    i32,
    field:    const HeaderField&,
    counts:   H3HeaderCounts&,
    auth_val: u8[..256]&,
) -> u64 {
    if field.name[..] == ":status" {
        counts.pseudo_status++;
        guard counts.pseudo_status == 1 && field.value.len == 3 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        let sc, ok_sc = core::parse_i32_dec(field.value[..]);
        guard ok_sc && sc >= 100 && sc <= 599 && sc != 101 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        conn.streams[s_idx].status_code = sc;
        return H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":method" {
        counts.pseudo_method++;
        guard counts.pseudo_method == 1 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        return H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":scheme" {
        counts.pseudo_scheme++;
        guard counts.pseudo_scheme == 1 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        return H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":authority" {
        counts.pseudo_authority++;
        guard counts.pseudo_authority == 1 && is_valid_authority_or_host(field.value[..]) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        auth_val.clear();
        auth_val.append(field.value[..]);
        return H3_ERR_NO_ERROR;
    }
    if field.name[..] == ":path" {
        counts.pseudo_path++;
        guard counts.pseudo_path == 1 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        return H3_ERR_NO_ERROR;
    }
    conn.state = H3ConnState.Closed;
    conn.error_code = H3_ERR_GENERAL_PROTOCOL;
    return H3_ERR_GENERAL_PROTOCOL;
}

fn process_h3_regular_field(
    conn:     H3Connection&,
    s_idx:    i32,
    field:    const HeaderField&,
    counts:   H3HeaderCounts&,
    host_val: u8[..256]&,
) -> u64 {
    if eq_ascii_fold(field.name[..], "host") {
        counts.host++;
        guard counts.host == 1 && is_valid_authority_or_host(field.value[..]) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        host_val.clear();
        host_val.append(field.value[..]);
        return H3_ERR_NO_ERROR;
    }
    if eq_ascii_fold(field.name[..], "content-length") {
        let cl, ok_cl = core::parse_i64_dec(field.value[..]);
        guard ok_cl && cl >= 0 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        if conn.streams[s_idx].content_length >= 0 && conn.streams[s_idx].content_length != cl {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        conn.streams[s_idx].content_length = cl;
        return H3_ERR_NO_ERROR;
    }
    return H3_ERR_NO_ERROR;
}

fn validate_h3_headers(conn: H3Connection&, s_idx: i32, fields: const HeaderField[>..]&) -> u64 {
    var seen_regular = false;
    var counts = H3HeaderCounts { .. };
    var auth_val: u8[..256] = [];
    var host_val: u8[..256] = [];

    for field in fields {
        if has_ctl_chars(field.value[..]) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }

        let is_pseudo = field.name.len > 0 && field.name[0] == ':';
        if is_pseudo {
            guard !seen_regular else {
                conn.state = H3ConnState.Closed;
                conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                return H3_ERR_GENERAL_PROTOCOL;
            }
            let p_err = process_h3_pseudo_field(conn, s_idx, field, counts, auth_val);
            guard p_err == H3_ERR_NO_ERROR else { return p_err; }
            continue;
        }

        seen_regular = true;
        if is_forbidden_connection_header(field.name[..], field.value[..]) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        let r_err = process_h3_regular_field(conn, s_idx, field, counts, host_val);
        guard r_err == H3_ERR_NO_ERROR else { return r_err; }
    }

    if counts.pseudo_authority > 0 && counts.host > 0 {
        if !core::eq_ascii_fold(auth_val[..], host_val[..]) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
    }

    let ok_pseudos = validate_h3_pseudo_headers(
        conn.role, counts.pseudo_status, counts.pseudo_method,
        counts.pseudo_scheme, counts.pseudo_path, counts.pseudo_authority,
    );
    guard ok_pseudos else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
        return H3_ERR_GENERAL_PROTOCOL;
    }
    if conn.role == H3ConnRole.Server || conn.streams[s_idx].status_code >= 200 {
        conn.streams[s_idx].headers_received = true;
    }
    return H3_ERR_NO_ERROR;
}

fn handle_bidi_push_promise(conn: H3Connection&, payload: const u8[:]) -> u64 {
    // Clients MUST NOT send PUSH_PROMISE frames to servers
    if conn.role == H3ConnRole.Server {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
        return H3_ERR_FRAME_UNEXPECTED;
    }
    guard payload.len > 0 else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_ERROR;
        return H3_ERR_FRAME_ERROR;
    }
    let push_id, _, ok_p = quic_decode_varint(payload, 0);
    if !ok_p {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_ERROR;
        return H3_ERR_FRAME_ERROR;
    }
    // Push ID MUST NOT exceed advertised MAX_PUSH_ID (or any push if never advertised)
    if !conn.max_push_id_sent || push_id > conn.max_push_id_advertised {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_ID_ERROR;
        return H3_ERR_ID_ERROR;
    }
    return H3_ERR_NO_ERROR;
}

fn handle_bidi_headers(
    conn:    H3Connection&,
    s_idx:   i32,
    payload: const u8[:],
) -> u64 {
    // RFC 9114 §4.1: Extra HEADERS frame after trailers is forbidden
    if conn.streams[s_idx].trailers_received {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
        return H3_ERR_FRAME_UNEXPECTED;
    }

    var decoded_fields: HeaderField[>..] = [];
    let q_err = decode_qpack_section(
        conn.qpack_table, payload, decoded_fields, conn.local_settings.max_field_section_size,
    );
    if q_err != QpackError.None {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_QPACK_DECOMPRESSION_FAILED;
        return H3_ERR_QPACK_DECOMPRESSION_FAILED;
    }

    let is_trailer = conn.streams[s_idx].headers_received &&
        (conn.role == H3ConnRole.Server || conn.streams[s_idx].status_code >= 200);

    if is_trailer {
        let t_err = validate_h3_trailers(conn, decoded_fields);
        guard t_err == H3_ERR_NO_ERROR else { return t_err; }
        conn.streams[s_idx].trailers_received = true;
        return H3_ERR_NO_ERROR;
    }

    return validate_h3_headers(conn, s_idx, decoded_fields);
}

fn handle_bidi_data(
    conn:        H3Connection&,
    s_idx:       i32,
    payload_len: u64,
    payload:     const u8[:],
) -> u64 {
    // Track empty DATA frame streak for DoS / CPU exhaustion defense (CVE-2019-9518 / RFC 9114 §10.5)
    if payload_len == 0 {
        conn.empty_frame_streak++;
        if conn.empty_frame_streak > MAX_H3_EMPTY_FRAME_STREAK {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_EXCESSIVE_LOAD;
            return H3_ERR_EXCESSIVE_LOAD;
        }
    } else {
        conn.empty_frame_streak = 0;
    }

    // DATA before HEADERS or after trailers is a fatal protocol error
    if !conn.streams[s_idx].headers_received || conn.streams[s_idx].trailers_received {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
        return H3_ERR_FRAME_UNEXPECTED;
    }
    // RFC 9114 §4.1 & Go #81642: 1xx, 204, and 304 responses MUST NOT include DATA frames
    let sc = conn.streams[s_idx].status_code;
    if sc == 204 || sc == 304 || (sc >= 100 && sc < 200) {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
        return H3_ERR_FRAME_UNEXPECTED;
    }
    let avail = conn.streams[s_idx].received_body.cap - conn.streams[s_idx].received_body.len;
    if avail > 0 {
        let to_copy = if payload.len < avail { payload.len } else { avail };
        conn.streams[s_idx].received_body.append(payload[..to_copy]);
    }
    conn.streams[s_idx].body_received_len += payload.len as u64;

    if conn.streams[s_idx].content_length >= 0 &&
       conn.streams[s_idx].body_received_len > (conn.streams[s_idx].content_length as u64) {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
        return H3_ERR_GENERAL_PROTOCOL;
    }
    return H3_ERR_NO_ERROR;
}

fn handle_bidi_stream_frames(
    conn:  H3Connection&,
    s_idx: i32,
    data:  const u8[:],
) -> u64 {
    var offset: u64 = 0;
    while offset < (data.len as u64) {
        let hdr, ok_hdr = parse_h3_frame_header(data, offset);
        guard ok_hdr else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }

        offset += hdr.header_len;
        guard (0xFFFFFFFFFFFFFFFF - offset) >= hdr.payload_len &&
              (offset + hdr.payload_len) <= (data.len as u64) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }

        let p_start = offset as i64;
        let p_end = (offset + hdr.payload_len) as i64;
        let payload = data[p_start..p_end];
        offset += hdr.payload_len;

        if !is_allowed_on_request_stream(hdr.frame_type) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_UNEXPECTED;
            return H3_ERR_FRAME_UNEXPECTED;
        }

        if hdr.frame_type == H3_FRAME_PUSH_PROMISE {
            let p_err = handle_bidi_push_promise(conn, payload);
            guard p_err == H3_ERR_NO_ERROR else { return p_err; }
            continue;
        }

        if hdr.frame_type == H3_FRAME_HEADERS {
            let h_err = handle_bidi_headers(conn, s_idx, payload);
            guard h_err == H3_ERR_NO_ERROR else { return h_err; }
            continue;
        }

        if hdr.frame_type == H3_FRAME_DATA {
            let d_err = handle_bidi_data(conn, s_idx, hdr.payload_len, payload);
            guard d_err == H3_ERR_NO_ERROR else { return d_err; }
            continue;
        }
    }
    return H3_ERR_NO_ERROR;
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
    // Client-initiated bidirectional streams have (stream_id & 0x01) == 0.
    guard (stream_id & 0x01) == 0 else {
        conn.state = H3ConnState.Closed;
        conn.error_code = H3_ERR_STREAM_CREATION;
        return H3_ERR_STREAM_CREATION;
    }

    let s_idx, err = get_or_create_bidi_stream(conn, stream_id);
    guard err == H3_ERR_NO_ERROR else { return err; }

    let f_err = handle_bidi_stream_frames(conn, s_idx, data);
    guard f_err == H3_ERR_NO_ERROR else { return f_err; }

    if fin {
        conn.streams[s_idx].fin_received = true;
        if conn.streams[s_idx].content_length >= 0 &&
           conn.streams[s_idx].body_received_len != (conn.streams[s_idx].content_length as u64) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
            return H3_ERR_GENERAL_PROTOCOL;
        }
        if conn.streams[s_idx].fin_sent {
            conn.streams[s_idx].state = H3StreamState.Closed;
        } else {
            conn.streams[s_idx].state = H3StreamState.HalfClosedRemote;
        }
    }

    return H3_ERR_NO_ERROR;
}

// ---- 5. Stream Inspection Accessors ----------------------------------------

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

fn is_stream_finished(conn: const H3Connection&, stream_id: u64) -> bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len {
        return conn.streams[s_idx].fin_received;
    }
    return false;
}

fn apply_h3_stream_priority(conn: H3Connection&, stream_id: u64, prio: const wing::PriorityParam&) -> bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else { return false; }
    conn.streams[s_idx].priority = prio;
    return true;
}

fn get_stream_priority(conn: const H3Connection&, stream_id: u64) -> wing::PriorityParam, bool {
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else {
        return wing::priority_default(false), false;
    }
    return conn.streams[s_idx].priority, true;
}
