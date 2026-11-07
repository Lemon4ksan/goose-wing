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
    has_received_max_push_id:  bool                = false,
    max_push_id_received:      u64                 = 0,
    has_promised_push_id:      bool                = false,
    max_promised_push_id:      u64                 = 0,
    empty_frame_streak:        u32                 = 0,
    control_glitch_count:      u32                 = 0,
    max_control_glitches:      u32                 = 256,
    sched_cycle:               u64                 = 0,
    peer_origins:              u8[..128][..16]     = [],
    error_code:                u64                 = rfc::H3_ERR_NO_ERROR,
    local_settings:            wing::H3Settings    = wing::H3Settings { .. },
    peer_settings:             wing::H3Settings    = wing::H3Settings { .. },
    encoder_stream_buf:        u8[..4096]          = [],
    streams:                   H3StreamEntry[..32] = [],
    qpack_table:               QpackTable          = QpackTable { .. }, // Resizable array must be final field
}

fn new_h3_client_connection(settings: const wing::H3Settings&) -> H3Connection {
    let max_blk = min(settings.qpack_blocked_streams, 0xFFFFFFFF) as u32;
    return H3Connection {
        role:           H3ConnRole.Client,
        local_settings: settings,
        qpack_table:    new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        ..
    };
}

fn new_h3_server_connection(settings: const wing::H3Settings&) -> H3Connection {
    let max_blk = min(settings.qpack_blocked_streams, 0xFFFFFFFF) as u32;
    return H3Connection {
        role:           H3ConnRole.Server,
        local_settings: settings,
        qpack_table:    new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
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

// ---- Preamble & Unidirectional Stream Creation ---------------------------

// Encodes client preambles for control, QPACK encoder, and QPACK decoder streams.
fn encode_client_preambles<B1, B2, B3>(
    conn:          H3Connection&,
    out_ctrl:      B1&,
    out_qpack_enc: B2&,
    out_qpack_dec: B3&,
) -> bool {
    guard quic_encode_varint(out_ctrl, rfc::H3_STREAM_CONTROL) else { return false; }
    guard encode_h3_settings_frame(out_ctrl, conn.local_settings) else { return false; }
    guard quic_encode_varint(out_qpack_enc, rfc::H3_STREAM_QPACK_ENCODER) else { return false; }
    guard quic_encode_varint(out_qpack_dec, rfc::H3_STREAM_QPACK_DECODER) else { return false; }

    conn.local_settings_sent = true;
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

fn encode_h3_extra_headers<B1, B2>(
    tbl:           QpackTable&,
    stream_id:     u64,
    base:          u64,
    extra_headers: const wing::HeaderMap&,
    body_fields:   B1&,
    enc_stream:    B2&,
    max_dyn_abs:   u64&,
    used_any_dyn:  bool&,
) {
    let raw_len = extra_headers.raw_buf.len;
    for i in extra_headers.entries.len {
        let entry = extra_headers.entries[i];
        let nb = entry.name_begin as i64;
        let ne = entry.name_end as i64;
        let vb = entry.values_begin as i64;
        let ve = entry.values_end as i64;
        if nb >= 0 && ne >= nb && ne <= raw_len && vb >= 0 && ve >= vb && ve <= raw_len {
            let raw_name = extra_headers.raw_buf[nb..ne];
            let val = extra_headers.raw_buf[vb..ve];
            if wire::is_h2_skipped_header_name(raw_name) {
                continue;
            }
            if core::eq_ascii_fold(raw_name, "te") && !core::eq_ascii_fold(core::trim_lws(val), "trailers") {
                continue;
            }
            var lower_name: u8[..256] = [];
            if raw_name.len == 0 || raw_name.len > lower_name.cap {
                continue;
            }
            for b in raw_name {
                lower_name.push(core::to_lower_ascii_byte(b));
            }
            encode_qpack_field_dynamic(
                tbl, stream_id, base, lower_name[..], val,
                body_fields, enc_stream, max_dyn_abs, used_any_dyn, false,
            );
        }
    }
}

fn prepend_qpack_section_prefix<B>(
    tbl:          QpackTable&,
    stream_id:    u64,
    base:         u64,
    max_dyn_abs:  u64,
    used_any_dyn: bool,
    out_payload:  B&,
) {
    if used_any_dyn {
        let ric = max_dyn_abs + 1;
        let _ = qpack_track_unacked_stream(tbl, stream_id, ric);
        let enc_ric = encode_ric(ric, tbl.max_capacity_bytes);
        internal::hpack_encode_int(out_payload, enc_ric, 8, 0x00);
        let sign_bit, delta_base = encode_base(base, ric);
        let sign_mask: u8 = if sign_bit != 0 { 0x80 } else { 0x00 };
        internal::hpack_encode_int(out_payload, delta_base, 7, sign_mask);
    } else {
        out_payload.push(0x00);
        out_payload.push(0x00);
    }
}

// Encodes request headers into QPACK field section (utilizing the dynamic table when enabled)
// and wraps in a HEADERS frame (RFC 9114 §4.3.1, RFC 9204 §4.5).
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

    let base = conn.qpack_table.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    var body_fields: u8[..4096] = [];

    encode_qpack_field_dynamic(
        conn.qpack_table, stream_id, base, ":method", method,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    );
    encode_qpack_field_dynamic(
        conn.qpack_table, stream_id, base, ":scheme", scheme,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    );
    encode_qpack_field_dynamic(
        conn.qpack_table, stream_id, base, ":authority", authority,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    );
    encode_qpack_field_dynamic(
        conn.qpack_table, stream_id, base, ":path", path,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    );
    encode_h3_extra_headers(
        conn.qpack_table, stream_id, base, extra_headers,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn,
    );

    var qpack_payload: u8[..4096] = [];
    prepend_qpack_section_prefix(conn.qpack_table, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload);
    guard qpack_payload.try_append(body_fields[..]) else { return false; }

    let ok_frame = encode_h3_headers_frame(out, qpack_payload[..]);
    guard ok_frame else { return false; }

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
    return true;
}

// Configures local QPACK dynamic table capacity from peer SETTINGS_QPACK_MAX_TABLE_CAPACITY
// and emits the Set Dynamic Table Capacity instruction onto `conn.encoder_stream_buf` (RFC 9204 §4.3.1).
fn h3_activate_qpack_dynamic_table(conn: H3Connection&, new_cap: u64) -> bool {
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
    let s_idx, found = find_h3_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else { return false; }
    guard conn.streams[s_idx].headers_sent else { return false; }

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

    if hdr.frame_type == rfc::H3_FRAME_MAX_PUSH_ID {
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

    if hdr.frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST {
        guard conn.role != H3ConnRole.Client else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
            return rfc::H3_ERR_FRAME_UNEXPECTED;
        }
        let req_stream_id, prio, ok_pu = parse_h3_priority_update_request(payload);
        guard ok_pu else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        guard (req_stream_id & 0x03) == 0 else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        apply_h3_stream_priority(conn, req_stream_id, prio);
        return rfc::H3_ERR_NO_ERROR;
    }

    if hdr.frame_type == rfc::H3_FRAME_PRIORITY_UPDATE_PUSH {
        guard conn.role != H3ConnRole.Client else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
            return rfc::H3_ERR_FRAME_UNEXPECTED;
        }
        let push_id, prio, ok_pu = parse_h3_priority_update_push(payload);
        guard ok_pu else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        if !conn.has_received_max_push_id || push_id > conn.max_push_id_received ||
           !conn.has_promised_push_id || push_id > conn.max_promised_push_id {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        return rfc::H3_ERR_NO_ERROR;
    }

    return handle_peer_origin_or_glitch(conn, hdr.frame_type, payload);
}

// RFC 9114 Section 4.3.1: Request Pseudo-Header Fields - All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4.
// RFC 9114 Section 4.4: The CONNECT Method - The :scheme and :path pseudo-header fields are omitted and :authority is present.
// RFC 9220 Section 2.1: Extended CONNECT requests also include :protocol, :scheme, and :path.
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

// Handles the opening of an HTTP/3 unidirectional Push Stream (RFC 9114 §6.2.2 & §4.6).
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

    let push_id, rem_off, ok_p = quic_decode_varint(data, offset);
    guard ok_p else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return 0, rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    if !conn.max_push_id_sent || push_id > conn.max_push_id_advertised {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_ID_ERROR;
        return 0, rfc::H3_ERR_ID_ERROR;
    }

    guard conn.ignored_uni_streams.len < conn.ignored_uni_streams.cap else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
        return 0, rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    conn.ignored_uni_streams.push(stream_id);
    return rem_off, rfc::H3_ERR_NO_ERROR;
}

fn process_peer_control_stream(conn: H3Connection&, data: const u8[:], start_offset: u64) -> u64 {
    var offset = start_offset;
    while offset < (data.len as u64) {
        let hdr, ok_hdr = parse_h3_frame_header(data, offset);
        guard ok_hdr else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }

        offset += hdr.header_len;
        guard (0xFFFFFFFFFFFFFFFF - offset) >= hdr.payload_len &&
              (offset + hdr.payload_len) <= (data.len as u64) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }

        let p_start = offset as i64;
        let p_end = (offset + hdr.payload_len) as i64;
        let payload = data[p_start..p_end];
        offset += hdr.payload_len;

        let c_err = handle_peer_control_frame(conn, hdr, payload);
        guard c_err == rfc::H3_ERR_NO_ERROR else { return c_err; }
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn pop_ready_blocked_qpack_stream(tbl: QpackTable&) -> u64, u8[..4096], bool {
    var out_sec: u8[..4096] = [];
    for i in tbl.blocked_streams.len {
        if tbl.blocked_streams[i].req_insert_count <= tbl.insert_count {
            let out_sid = tbl.blocked_streams[i].stream_id;
            out_sec.append(tbl.blocked_streams[i].encoded_data[..]);
            tbl.blocked_streams.remove_at(i as i32);
            return out_sid, out_sec, true;
        }
    }
    return 0, out_sec, false;
}

fn resume_unblocked_qpack_streams(conn: H3Connection&) -> u64 {
    for _ in 128 {
        let b_sid, raw_sec, ok_pop = pop_ready_blocked_qpack_stream(conn.qpack_table);
        guard ok_pop else {
            return rfc::H3_ERR_NO_ERROR;
        }
        let s_idx, found = find_h3_stream_idx(conn, b_sid);
        if found && s_idx >= 0 && s_idx < conn.streams.len {
            let h_err = handle_bidi_headers(conn, s_idx, raw_sec[..]);
            guard h_err == rfc::H3_ERR_NO_ERROR else { return h_err; }
        }
    }
    return rfc::H3_ERR_NO_ERROR;
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
                conn.error_code = rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
                return rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR;
            }
            offset = next_off;
        }
        return resume_unblocked_qpack_streams(conn);
    }
    if stream_id == conn.peer_qpack_dec_stream_id {
        while offset < (data.len as u64) {
            let next_off, q_err = qpack_process_decoder_instruction(conn.qpack_table, data, offset);
            if q_err != QpackError.None {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
                return rfc::H3_ERR_QPACK_DECODER_STREAM_ERROR;
            }
            offset = next_off;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn register_peer_uni_stream(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
) -> u64, u64 {
    let stype, off1, ok_type = quic_decode_varint(data, 0);
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

    // Unknown unidirectional stream: ignore payload (RFC 9114 Section 6.2)
    guard conn.ignored_uni_streams.len < conn.ignored_uni_streams.cap else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
        return 0, rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    conn.ignored_uni_streams.push(stream_id);
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

fn handle_uni_stream_data(
    conn:      H3Connection&,
    stream_id: u64,
    data:      const u8[:],
    fin:       bool,
) -> u64 {
    guard data.len > 0 || fin else { return rfc::H3_ERR_NO_ERROR; }

    for i in conn.ignored_uni_streams.len {
        if conn.ignored_uni_streams[i] == stream_id {
            if fin {
                conn.ignored_uni_streams.remove_at(i);
            }
            return rfc::H3_ERR_NO_ERROR;
        }
    }

    var offset: u64 = 0;
    let is_known = is_critical_uni_stream(conn, stream_id);

    // RFC 9114 §6.2: Closing a unidirectional stream before stream type header is an error
    if !is_known && data.len == 0 && fin {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
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
    guard conn.streams.len < conn.streams.cap else {
        return -1, rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    conn.streams.push(ent);
    return (conn.streams.len - 1) as i32, rfc::H3_ERR_NO_ERROR;
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

fn validate_h3_trailers<F>(conn: H3Connection&, fields: const F&) -> u64 {
    for field in fields {
        if field.name.len > 0 && field.name[0] == ':' {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
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
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if has_ctl_chars(field.value[..]) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if is_forbidden_connection_header(field.name[..], field.value[..]) {
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
    let sc, ok_sc = core::parse_i32_dec(field.value[..]);
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
    auth_val.clear();
    auth_val.append(field.value[..]);
    return true;
}

fn validate_pseudo_path(field: const HeaderField&, counts: H3HeaderCounts&) -> bool {
    counts.pseudo_path++;
    guard counts.pseudo_path == 1 && field.value.len > 0 else { return false; }
    let p0 = field.value[0];
    return p0 == '/' || (p0 == '*' && field.value.len == 1);
}

fn validate_pseudo_protocol(field: const HeaderField&, counts: H3HeaderCounts&, enable_conn_proto: bool) -> bool {
    guard enable_conn_proto else { return false; }
    counts.pseudo_protocol++;
    return counts.pseudo_protocol == 1 && field.value.len > 0;
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
    if eq_ascii_fold(field.name[..], "host") {
        counts.host++;
        guard counts.host == 1 && is_valid_authority_or_host(field.value[..]) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        host_val.clear();
        host_val.append(field.value[..]);
        return rfc::H3_ERR_NO_ERROR;
    }
    if eq_ascii_fold(field.name[..], "content-length") {
        let cl, ok_cl = core::parse_i64_dec(field.value[..]);
        let _, ok_u = core::parse_u64_dec(field.value[..]);
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
    if eq_ascii_fold(field.name[..], "priority") {
        if !conn.streams[s_idx].priority_updated {
            let parsed_p, ok_p = wing::parse_http_priority(field.value[..]);
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
    if is_forbidden_connection_header(field.name[..], field.value[..]) {
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

    for field in fields {
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
        if !core::eq_ascii_fold(auth_val[..], host_val[..]) {
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

fn handle_bidi_push_promise(conn: H3Connection&, payload: const u8[:]) -> u64 {
    // Clients MUST NOT send PUSH_PROMISE frames to servers
    if conn.role == H3ConnRole.Server {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    guard payload.len > 0 else {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    let push_id, qpack_off, ok_p = quic_decode_varint(payload, 0);
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
    var decoded_fields: HeaderField[..64] = [];
    let q_err = decode_or_block_qpack_section(
        conn.qpack_table,
        push_id,
        qpack_data,
        decoded_fields,
        conn.local_settings.max_field_section_size,
    );
    if q_err != QpackError.None && q_err != QpackError.StreamBlocked {
        conn.state = H3ConnState.Closed;
        conn.error_code = rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
        return rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
    }
    if q_err == QpackError.None && decoded_fields.len > 0 {
        for &f in decoded_fields {
            if f.name[..] == ":status" || is_forbidden_connection_header(f.name[..], f.value[..]) ||
               has_ctl_chars(f.value[..]) || eq_ascii_fold(f.name[..], "content-length") {
                conn.state = H3ConnState.Closed;
                conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
                return rfc::H3_ERR_GENERAL_PROTOCOL;
            }
        }
    }
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

    var decoded_fields: HeaderField[..128] = [];
    let q_err = decode_or_block_qpack_section(
        conn.qpack_table,
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
    let avail = stream.received_body.cap - stream.received_body.len;
    guard payload.len <= avail else {
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    stream.received_body.append(payload);
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
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }

        offset += hdr.header_len;
        guard (0xFFFFFFFFFFFFFFFF - offset) >= hdr.payload_len &&
              (offset + hdr.payload_len) <= (data.len as u64) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }

        let p_start = offset as i64;
        let p_end = (offset + hdr.payload_len) as i64;
        let payload = data[p_start..p_end];
        offset += hdr.payload_len;

        if !rfc::is_allowed_on_request_stream(hdr.frame_type) {
            conn.state = H3ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
            return rfc::H3_ERR_FRAME_UNEXPECTED;
        }

        if hdr.frame_type == rfc::H3_FRAME_PUSH_PROMISE {
            let p_err = handle_bidi_push_promise(conn, payload);
            guard p_err == rfc::H3_ERR_NO_ERROR else { return p_err; }
            continue;
        }

        if hdr.frame_type == rfc::H3_FRAME_HEADERS {
            let h_err = handle_bidi_headers(conn, s_idx, payload);
            guard h_err == rfc::H3_ERR_NO_ERROR else { return h_err; }
            continue;
        }

        if hdr.frame_type == rfc::H3_FRAME_DATA {
            let d_err = handle_bidi_data(conn, s_idx, hdr.payload_len, payload);
            guard d_err == rfc::H3_ERR_NO_ERROR else { return d_err; }
            continue;
        }
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
    // Client-initiated bidirectional streams have (stream_id & 0x01) == 0.
    guard (stream_id & 0x01) == 0 else {
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

    let f_err = handle_bidi_stream_frames(conn, s_idx, data);
    guard f_err == rfc::H3_ERR_NO_ERROR else { return f_err; }

    if fin {
        conn.streams[s_idx].fin_received = true;
        if !conn.streams[s_idx].headers_received &&
           !qpack_is_stream_blocked(conn.qpack_table, stream_id) {
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
        if conn.streams[s_idx].fin_sent {
            conn.streams[s_idx].state = H3StreamState.Closed;
        } else {
            conn.streams[s_idx].state = H3StreamState.HalfClosedRemote;
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
    let src = conn.streams[s_idx].headers;
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
    let src = conn.streams[s_idx].trailers;
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

    var sc_str: u8[..16] = [];
    format(sc_str, status_code as i64);

    let base = conn.qpack_table.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    var body_fields: u8[..4096] = [];

    encode_qpack_field_dynamic(
        conn.qpack_table, stream_id, base, ":status", sc_str[..],
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, false,
    );
    encode_h3_extra_headers(
        conn.qpack_table, stream_id, base, extra_headers,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn,
    );

    var qpack_payload: u8[..4096] = [];
    prepend_qpack_section_prefix(conn.qpack_table, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload);
    guard qpack_payload.try_append(body_fields[..]) else { return false; }
    guard encode_h3_headers_frame(out, qpack_payload[..]) else { return false; }

    conn.streams[s_idx].headers_sent = true;
    if body.len > 0 {
        guard encode_h3_data_frame(out, body) else { return false; }
    }
    if trailers.entries.len > 0 {
        let tr_base = conn.qpack_table.insert_count;
        var tr_max_dyn: u64 = 0;
        var tr_used_dyn = false;
        var tr_fields: u8[..4096] = [];
        encode_h3_extra_headers(
            conn.qpack_table, stream_id, tr_base, trailers,
            tr_fields, conn.encoder_stream_buf, tr_max_dyn, tr_used_dyn,
        );
        var tr_payload: u8[..4096] = [];
        prepend_qpack_section_prefix(conn.qpack_table, stream_id, tr_base, tr_max_dyn, tr_used_dyn, tr_payload);
        guard tr_payload.try_append(tr_fields[..]) else { return false; }
        guard encode_h3_headers_frame(out, tr_payload[..]) else { return false; }
    }
    conn.streams[s_idx].fin_sent = true;
    conn.streams[s_idx].state = H3StreamState.Closed;
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
