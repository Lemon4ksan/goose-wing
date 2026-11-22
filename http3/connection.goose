// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Connection Coordinator and Stream Multiplexer.
// Conforms to RFC 9114 (HTTP/3), RFC 9204 (QPACK), and RFC 9000 (QUIC Streams).
namespace http3;

import std;
import core;
import rfc.h3_quic;
import http.headers;
import http.priority;
import fingerprint.profile;
import quic.packet;
import http2.hpack;
import .internal;
import .types;
import .framing;
import .qpack_codec;
import .qpack_internal;
import .qpack;
import .stream_internal;
import .connection_internal;

// ---- Connection Constructors & Push Control --------------------------------

fn new_client_connection(settings: const fingerprint::H3Settings&) -> Connection {
    let max_blk = min(settings.qpack_blocked_streams, 0xFFFFFFFF) as u32;
    return Connection {
        role:            ConnRole.Client,
        local_settings:  settings,
        qpack_dec_table: new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        qpack_table:     new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        ..
    };
}

fn new_server_connection(settings: const fingerprint::H3Settings&) -> Connection {
    let max_blk = min(settings.qpack_blocked_streams, 0xFFFFFFFF) as u32;
    return Connection {
        role:            ConnRole.Server,
        local_settings:  settings,
        qpack_dec_table: new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        qpack_table:     new_qpack_table(settings.qpack_max_table_capacity, max_blk, 0),
        ..
    };
}

// RFC 9114 Section 7.2.7: MAX_PUSH_ID - A MAX_PUSH_ID frame cannot reduce the maximum push ID.
fn send_max_push_id<B>(conn: Connection&, max_push_id: u64, out: B&) -> bool {
    guard conn.role == ConnRole.Client && conn.state != ConnState.Closed else { return false; }
    guard !conn.max_push_id_sent || max_push_id >= conn.max_push_id_advertised else { return false; }
    guard encode_max_push_id(out, max_push_id) else { return false; }
    conn.max_push_id_sent = true;
    conn.max_push_id_advertised = max_push_id;
    return true;
}

// ---- Preamble & Unidirectional Stream Creation -----------------------------

// Encodes client preambles for control, QPACK encoder, and QPACK decoder streams.
fn encode_client_preambles<B1, B2, B3>(
    conn:          Connection&,
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

    guard quic::encode_varint(rfc::H3_STREAM_CONTROL, out_ctrl) else { return false; }
    guard encode_settings_frame(out_ctrl, conn.local_settings) else { return false; }
    guard quic::encode_varint(rfc::H3_STREAM_QPACK_ENCODER, out_qpack_enc) else { return false; }
    guard quic::encode_varint(rfc::H3_STREAM_QPACK_DECODER, out_qpack_dec) else { return false; }

    conn.local_settings_sent = true;
    committed = true;
    return true;
}

// ---- Request Stream Lifecycle ----------------------------------------------

// Finds an existing stream or returns false.
fn find_stream_idx(conn: const Connection&, stream_id: u64) -> i32, bool {
    for &s, i in conn.streams {
        if s.stream_id == stream_id {
            return i as i32, true;
        }
    }
    return -1, false;
}

// Allocates a new client request stream (0, 4, 8, ...).
fn open_request_stream(conn: Connection&) -> u64, bool {
    guard conn.state == ConnState.Active || conn.state == ConnState.Connecting else {
        return 0, false;
    }

    let sid = conn.next_bidi_stream_id;
    if conn.goaway_received && sid >= conn.goaway_max_stream_id {
        return 0, false;
    }

    var slot_idx: i32 = -1;
    for &s, i in conn.streams {
        if s.state == StreamState.Closed {
            slot_idx = i as i32;
            break;
        }
    }

    let ent = StreamEntry {
        stream_id:         sid,
        kind:              StreamKind.Request,
        state:             StreamState.Open,
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

fn prepend_qpack_section_prefix<B>(
    tbl:          QpackTable&,
    stream_id:    u64,
    base:         u64,
    max_dyn_abs:  u64,
    used_any_dyn: bool,
    out:          B&,
) -> bool {
    let saved_len = out.len;
    let saved_tbl = tbl;
    var committed = false;
    defer if !committed {
        out.resize(saved_len);
        tbl = saved_tbl;
    };
    if used_any_dyn {
        // RFC 9204 Section 4.5.1.1: Required Insert Count - Required Insert Count equals one more than the largest absolute index referenced.
        let ric = max_dyn_abs + 1;
        guard qpack_track_unacked_stream(tbl, stream_id, ric) else { return false; }
        let enc_ric = encode_ric(ric, tbl.max_capacity_bytes);
        guard http2::hpack_encode_int(out, enc_ric, 8, 0x00) else { return false; }
        let sign_bit, delta_base = encode_base(base, ric);
        let sign_mask: u8 = if sign_bit != 0 { 0x80 } else { 0x00 };
        guard http2::hpack_encode_int(out, delta_base, 7, sign_mask) else { return false; }
        committed = true;
        return true;
    }
    guard out.try_push(0x00 as u8) && out.try_push(0x00 as u8) else { return false; }
    committed = true;
    return true;
}

// RFC 9114 Section 4.1: HTTP Message Framing - Encodes a single client request HEADERS frame with atomic QPACK rollback on overflow.
fn send_request_headers<B>(
    conn:          Connection&,
    stream_id:     u64,
    method:        const u8[:],
    scheme:        const u8[:],
    authority:     const u8[:],
    path:          const u8[:],
    extra_headers: const http::HeaderMap&,
    end_stream:    bool,
    out:           B&,
) -> bool {
    guard conn.role == ConnRole.Client && conn.state != ConnState.Closed else { return false; }
    guard !(conn.goaway_received && stream_id >= conn.goaway_max_stream_id) else { return false; }
    let s_idx, found = find_stream_idx(conn, stream_id);
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

    guard encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":method", method,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":scheme", scheme,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":authority", authority,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":path", path,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, true,
    ) && h3_internal::encode_h3_extra_headers(
        enc_tbl, stream_id, base, extra_headers,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn,
    ) else {
        return false;
    }

    var qpack_payload: u8[..4096] = [];
    guard prepend_qpack_section_prefix(
        enc_tbl, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload,
    ) && qpack_payload.try_append(body_fields[..]) &&
          encode_headers_frame(out, qpack_payload[..]) else {
        return false;
    }

    let _ = conn.streams[s_idx].req_method.try_set(method);
    conn.streams[s_idx].headers_sent = true;
    if end_stream {
        conn.streams[s_idx].fin_sent = true;
        conn.streams[s_idx].state = if conn.streams[s_idx].fin_received {
            StreamState.Closed
        } else {
            StreamState.HalfClosedLocal
        };
    }
    committed = true;
    return true;
}

// Configures local QPACK dynamic table capacity from peer SETTINGS_QPACK_MAX_TABLE_CAPACITY
// and emits the Set Dynamic Table Capacity instruction onto `conn.encoder_stream_buf` (RFC 9204 Section 4.3.1).
fn activate_qpack_dynamic_table(conn: Connection&, new_cap: u64) -> bool {
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
    conn:       Connection&,
    stream_id:  u64,
    data:       const u8[:],
    end_stream: bool,
    out:        B&,
) -> bool {
    guard conn.role == ConnRole.Client && conn.state != ConnState.Closed else { return false; }
    let s_idx, found = find_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else { return false; }
    guard conn.streams[s_idx].headers_sent && !conn.streams[s_idx].fin_sent else { return false; }

    let ok_frame = encode_data_frame(out, data);
    guard ok_frame else { return false; }

    if end_stream {
        conn.streams[s_idx].fin_sent = true;
        conn.streams[s_idx].state = if conn.streams[s_idx].fin_received {
            StreamState.Closed
        } else {
            StreamState.HalfClosedLocal
        };
    }
    return true;
}

// ---- Inbound Control, Validation & Stream Ingress --------------------------

// Handles frames received on the peer control stream.
fn handle_peer_control_frame(conn: Connection&, hdr: const FrameHeader&, payload: const u8[:]) -> u64 {
    // First frame on Control Stream MUST be SETTINGS (RFC 9114 §6.2.1 & §7.2.4)
    if !conn.peer_settings_received {
        if hdr.frame_type != rfc::H3_FRAME_SETTINGS {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_MISSING_SETTINGS;
            return rfc::H3_ERR_MISSING_SETTINGS;
        }
        let parsed_settings, set_err = parse_settings_frame(payload);
        guard set_err == rfc::H3_ERR_NO_ERROR else {
            conn.state = ConnState.Closed;
            conn.error_code = set_err;
            return set_err;
        }
        conn.peer_settings = parsed_settings;
        conn.peer_settings_received = true;
        conn.state = ConnState.Active;
        return rfc::H3_ERR_NO_ERROR;
    }

    // Subsequent strictly forbidden frames on control stream (RFC 9114 §7.2.1, §7.2.2, §7.2.5, §7.2.8)
    guard rfc::is_allowed_on_control_stream(hdr.frame_type) else {
        conn.state = ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    // Subsequent frames must not be SETTINGS
    guard hdr.frame_type != rfc::H3_FRAME_SETTINGS else {
        conn.state = ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    if hdr.frame_type == rfc::H3_FRAME_GOAWAY {
        let max_sid, ok_ga = parse_goaway_frame(payload);
        guard ok_ga else {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        if (max_sid & 0x03) != 0 {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        if conn.goaway_received && max_sid > conn.goaway_max_stream_id {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        conn.goaway_received = true;
        conn.goaway_max_stream_id = max_sid;
        conn.state = ConnState.Draining;
        return rfc::H3_ERR_NO_ERROR;
    }

    if hdr.frame_type == rfc::H3_FRAME_CANCEL_PUSH {
        let push_id, ok_cp = parse_cancel_push(payload);
        guard ok_cp else {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR;
        }
        if conn.has_received_max_push_id && push_id > conn.max_push_id_received {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        if conn.role == ConnRole.Client && (!conn.max_push_id_sent || push_id > conn.max_push_id_advertised) {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_ID_ERROR;
            return rfc::H3_ERR_ID_ERROR;
        }
        return rfc::H3_ERR_NO_ERROR;
    }

    return h3_internal::handle_peer_extended_control_frame(conn, hdr.frame_type, payload);
}

fn get_or_create_bidi_stream(conn: Connection&, stream_id: u64) -> i32, u64 {
    let s_idx, found = find_stream_idx(conn, stream_id);
    if found {
        return s_idx, rfc::H3_ERR_NO_ERROR;
    }
    if conn.role == ConnRole.Client {
        conn.state = ConnState.Closed;
        conn.error_code = rfc::H3_ERR_STREAM_CREATION;
        return -1, rfc::H3_ERR_STREAM_CREATION;
    }
    var reuse_slot: i32 = -1;
    for &s, i in conn.streams {
        if s.state == StreamState.Closed {
            reuse_slot = i as i32;
            break;
        }
    }
    let ent = StreamEntry {
        stream_id:         stream_id,
        kind:              StreamKind.Request,
        state:             StreamState.Open,
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

fn validate_h3_headers<F>(conn: Connection&, s_idx: i32, fields: const F&) -> u64 {
    var seen_regular = false;
    var counts = h3_internal::H3HeaderCounts { .. };
    var auth_val: u8[..256] = [];
    var host_val: u8[..256] = [];
    conn.streams[s_idx].content_length = -1;

    for &field in fields {
        let h_err = h3_internal::validate_single_h3_header(
            conn, s_idx, field, seen_regular, counts, auth_val, host_val,
        );
        guard h_err == rfc::H3_ERR_NO_ERROR else { return h_err; }
    }

    if conn.role == ConnRole.Client && conn.streams[s_idx].status_code >= 100 &&
       conn.streams[s_idx].status_code < 200 && conn.streams[s_idx].content_length >= 0 {
        conn.state = ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    if counts.pseudo_authority > 0 && counts.host > 0 {
        if !auth_val[..].eq_ascii_fold(host_val[..]) {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }

    if conn.role == ConnRole.Server && !counts.is_connect {
        guard counts.pseudo_authority > 0 || counts.host > 0 else {
            conn.state = ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }

    let ok_pseudos = h3_internal::validate_h3_pseudo_headers(
        conn.role, counts.pseudo_status, counts.pseudo_method,
        counts.pseudo_scheme, counts.pseudo_path, counts.pseudo_authority,
        counts.is_connect, counts.pseudo_protocol,
    );
    let bad_asterisk = conn.role == ConnRole.Server && conn.streams[s_idx].req_path[..] == "*"
        && conn.streams[s_idx].req_method[..] != "OPTIONS";
    guard ok_pseudos && !bad_asterisk else {
        conn.state = ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    if conn.role == ConnRole.Server || conn.streams[s_idx].status_code >= 200 {
        conn.streams[s_idx].headers_received = true;
    }
    return rfc::H3_ERR_NO_ERROR;
}

// Handles incoming raw bytes on a given stream.
fn handle_stream_data(
    conn:      Connection&,
    stream_id: u64,
    is_bidi:   bool,
    data:      const u8[:],
    fin:       bool,
) -> u64 {
    if !is_bidi {
        return h3_internal::handle_uni_stream_data(conn, stream_id, data, fin);
    }

    // RFC 9114 Section 6.1: HTTP/3 does not use server-initiated bidirectional streams.
    // Client-initiated bidirectional streams have (stream_id & 0x03) == 0.
    // WebTransport permits server-initiated bidirectional streams with (stream_id & 0x03) == 1.
    let is_client_bidi = (stream_id & 0x03) == 0;
    let wt_enabled = conn.local_settings.enable_webtransport > 0 &&
        conn.peer_settings.enable_webtransport > 0;
    let is_server_wt_bidi = wt_enabled && ((stream_id & 0x03) == 1);
    guard is_client_bidi || is_server_wt_bidi else {
        conn.state = ConnState.Closed;
        conn.error_code = rfc::H3_ERR_STREAM_CREATION;
        return rfc::H3_ERR_STREAM_CREATION;
    }

    let s_idx, err = get_or_create_bidi_stream(conn, stream_id);
    guard err == rfc::H3_ERR_NO_ERROR else { return err; }

    guard !conn.streams[s_idx].fin_received else {
        conn.state = ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    let f_err = h3_internal::handle_bidi_stream_frames(conn, s_idx, data, fin);
    guard f_err == rfc::H3_ERR_NO_ERROR else { return f_err; }

    if fin {
        conn.streams[s_idx].fin_received = true;
        if conn.streams[s_idx].fin_sent {
            conn.streams[s_idx].state = StreamState.Closed;
        } else {
            conn.streams[s_idx].state = StreamState.HalfClosedRemote;
        }
        var dec_tbl .= conn.qpack_table;
        if conn.local_qpack_enc_activated {
            dec_tbl .= conn.qpack_dec_table;
        }
        if !qpack_is_stream_blocked(dec_tbl, stream_id) {
            let fin_err = h3_internal::check_bidi_stream_fin_complete(conn, s_idx);
            guard fin_err == rfc::H3_ERR_NO_ERROR else { return fin_err; }
        }
    }

    return rfc::H3_ERR_NO_ERROR;
}

// ---- Stream Inspection Accessors & Server Response Encoding ----------------

fn get_status_code(conn: const Connection&, stream_id: u64) -> i32, bool {
    let s_idx, found = find_stream_idx(conn, stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len && conn.streams[s_idx].headers_received {
        return conn.streams[s_idx].status_code, true;
    }
    return 0, false;
}

fn get_response_body(conn: const Connection&, stream_id: u64) -> const u8[:], bool {
    let s_idx, found = find_stream_idx(conn, stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len {
        return conn.streams[s_idx].received_body[..], true;
    }
    return "", false;
}

fn copy_stream_headers(conn: const Connection&, stream_id: u64, out_headers: http::HeaderMap&) -> bool {
    let s_idx, found = find_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len && conn.streams[s_idx].headers_received else {
        return false;
    }
    out_headers.clear();
    let src .= conn.streams[s_idx].headers;
    for &e in src.entries {
        let name = http::entry_name(src, e);
        let val = http::entry_value(src, e);
        if !http::append_header(out_headers, name, val) {
            out_headers.clear();
            return false;
        }
    }
    return true;
}

fn copy_stream_trailers(conn: const Connection&, stream_id: u64, out_trailers: http::HeaderMap&) -> bool {
    let s_idx, found = find_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len && conn.streams[s_idx].trailers_received else {
        return false;
    }
    out_trailers.clear();
    let src .= conn.streams[s_idx].trailers;
    for &e in src.entries {
        let name = http::entry_name(src, e);
        let val = http::entry_value(src, e);
        if !http::append_header(out_trailers, name, val) {
            out_trailers.clear();
            return false;
        }
    }
    return true;
}

fn is_stream_finished(conn: const Connection&, stream_id: u64) -> bool {
    let s_idx, found = find_stream_idx(conn, stream_id);
    if found && s_idx >= 0 && s_idx < conn.streams.len {
        return conn.streams[s_idx].fin_received;
    }
    return false;
}

// Encodes a server HTTP/3 response (HEADERS + optional DATA + optional trailing HEADERS) onto `out` (RFC 9114 §4.1).
fn send_response_headers_body_and_trailers<B>(
    conn:          Connection&,
    stream_id:     u64,
    status_code:   i32,
    extra_headers: const http::HeaderMap&,
    body:          const u8[:],
    trailers:      const http::HeaderMap&,
    out:           B&,
) -> bool {
    let s_idx, found = find_stream_idx(conn, stream_id);
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

    guard encode_qpack_field_dynamic(
        enc_tbl, stream_id, base, ":status", sc_str[..],
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn, false,
    ) && h3_internal::encode_h3_extra_headers(
        enc_tbl, stream_id, base, extra_headers,
        body_fields, conn.encoder_stream_buf, max_dyn_abs, used_any_dyn,
    ) else {
        return false;
    }

    var qpack_payload: u8[..4096] = [];
    guard prepend_qpack_section_prefix(
        enc_tbl, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload,
    ) && qpack_payload.try_append(body_fields[..]) &&
          encode_headers_frame(out, qpack_payload[..]) else {
        return false;
    }

    conn.streams[s_idx].headers_sent = true;
    if body.len > 0 {
        guard encode_data_frame(out, body) else { return false; }
    }
    if trailers.entries.len > 0 {
        let tr_base = enc_tbl.insert_count;
        var tr_max_dyn: u64 = 0;
        var tr_used_dyn = false;
        var tr_fields: u8[..4096] = [];
        guard h3_internal::encode_h3_extra_headers(
            enc_tbl, stream_id, tr_base, trailers,
            tr_fields, conn.encoder_stream_buf, tr_max_dyn, tr_used_dyn,
        ) else {
            return false;
        }
        var tr_payload: u8[..4096] = [];
        guard prepend_qpack_section_prefix(
            enc_tbl, stream_id, tr_base, tr_max_dyn, tr_used_dyn, tr_payload,
        ) && tr_payload.try_append(tr_fields[..]) &&
              encode_headers_frame(out, tr_payload[..]) else {
            return false;
        }
    }
    conn.streams[s_idx].fin_sent = true;
    conn.streams[s_idx].state = StreamState.Closed;
    committed = true;
    return true;
}

// ---- RFC 9218 Extensible Stream Priority Scheduling ----------------------

fn apply_stream_priority(conn: Connection&, stream_id: u64, prio: const http::PriorityParam&) -> bool {
    var s_idx, found = find_stream_idx(conn, stream_id);
    if !found && conn.role == ConnRole.Server && (stream_id & 0x03) == 0 {
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

fn get_stream_priority(conn: const Connection&, stream_id: u64) -> http::PriorityParam, bool {
    let s_idx, found = find_stream_idx(conn, stream_id);
    guard found && s_idx >= 0 && s_idx < conn.streams.len else {
        return http::priority_default(false), false;
    }
    return conn.streams[s_idx].priority, true;
}

// Selects the next writable request stream according to RFC 9218 Extensible Priorities.
// Scans streams with `tx_pending_bytes > 0`, selecting minimum `priority.urgency` (`0..7`),
// breaking ties by `stream_id` when `!priority.incremental` and by `last_scheduled_cycle`
// when `priority.incremental`.
fn select_next_tx_stream(conn: Connection&) -> u64, bool {
    let next_cycle = min(conn.sched_cycle, 0xFFFFFFFFFFFFFFFE) + 1;
    var best_idx: i64 = -1;
    for &s, i in conn.streams {
        if s.tx_pending_bytes > 0 {
            if best_idx < 0 || h3_internal::is_better_h3_tx_candidate(s, conn.streams[best_idx]) {
                best_idx = i;
            }
        }
    }
    guard best_idx >= 0 && best_idx < conn.streams.len else { return 0, false; }
    conn.sched_cycle = next_cycle;
    conn.streams[best_idx].last_scheduled_cycle = next_cycle;
    return conn.streams[best_idx].stream_id, true;
}
