// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Connection Coordinator and Stream Multiplexer.
// Conforms to RFC 9114 (HTTP/3), RFC 9204 (QPACK), and RFC 9000 (QUIC Streams).
namespace wing;

import std;
import http.headers;
import quic.packet;
import http3.qpack;
import http3.framing;

// ---- 1. Stream Kinds, States and Structures --------------------------------

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
    stream_id: u64 = 0,
    kind: H3StreamKind = H3StreamKind.Request,
    state: H3StreamState = H3StreamState.Idle,
    is_bidi: bool = true,
    headers_sent: bool = false,
    headers_received: bool = false,
    trailers_received: bool = false,
    fin_sent: bool = false,
    fin_received: bool = false,
    status_code: i32 = 0,
    body_received_len: u64 = 0,
    content_length: i64 = -1,
    received_body: u8[..4096] = [],
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
struct H3Connection {
    role: H3ConnRole = H3ConnRole.Client,
    state: H3ConnState = H3ConnState.Connecting,
    next_bidi_stream_id: u64 = 0,
    local_control_stream_id: u64 = 2,
    local_qpack_enc_stream_id: u64 = 6,
    local_qpack_dec_stream_id: u64 = 10,
    local_settings_sent: bool = false,
    peer_control_stream_id: u64 = 0xFFFFFFFFFFFFFFFF,
    peer_control_opened: bool = false,
    peer_settings_received: bool = false,
    peer_qpack_enc_stream_id: u64 = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_enc_opened: bool = false,
    peer_qpack_dec_stream_id: u64 = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_dec_opened: bool = false,
    ignored_uni_streams: u64[..16] = [],
    goaway_received: bool = false,
    goaway_max_stream_id: u64 = 0xFFFFFFFFFFFFFFFF,
    max_push_id_sent: bool = false,
    max_push_id_advertised: u64 = 0,
    max_push_id_received: u64 = 0,
    error_code: u64 = H3_ERR_NO_ERROR,
    local_settings: H3Settings = H3Settings { .. },
    peer_settings: H3Settings = H3Settings { .. },
    streams: H3StreamEntry[..8] = [],
    qpack_table: QpackTable = QpackTable { .. }, // Resizable array must be final field
}

fn new_h3_client_connection(settings: const H3Settings&) -> H3Connection {
    return H3Connection {
        local_settings: settings,
        qpack_table: new_qpack_table(settings.qpack_max_table_capacity, settings.qpack_blocked_streams as u32),
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
    conn: H3Connection&,
    out_ctrl: B1&,
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
    guard conn.streams.len < conn.streams.cap else { return 0, false; }

    let sid = conn.next_bidi_stream_id;
    if conn.goaway_received && sid >= conn.goaway_max_stream_id {
        return 0, false;
    }

    conn.streams.push(H3StreamEntry {
        stream_id: sid,
        kind: H3StreamKind.Request,
        state: H3StreamState.Open,
        is_bidi: true,
        headers_sent: false,
        headers_received: false,
        trailers_received: false,
        fin_sent: false,
        fin_received: false,
        status_code: 0,
        body_received_len: 0,
        content_length: -1,
        received_body: [],
    });

    conn.next_bidi_stream_id += 4;
    return sid, true;
}

// Encodes request headers into QPACK field section and wraps in a HEADERS frame.
fn send_request_headers<B>(
    conn: H3Connection&,
    stream_id: u64,
    method: const u8[:],
    scheme: const u8[:],
    authority: const u8[:],
    path: const u8[:],
    extra_headers: const HeaderMap&,
    end_stream: bool,
    out: B&,
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
    conn: H3Connection&,
    stream_id: u64,
    data: const u8[:],
    end_stream: bool,
    out: B&,
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

// Handles incoming raw bytes on a given stream.
// Returns H3_ERR_NO_ERROR (0x0100) or appropriate HTTP/3 error code.
fn handle_stream_data(
    conn: H3Connection&,
    stream_id: u64,
    is_bidi: bool,
    data: const u8[:],
    fin: bool,
) -> u64 {
    // -------------------------------------------------------------------------
    // A. Unidirectional Streams (Control, QPACK Encoder/Decoder)
    // -------------------------------------------------------------------------
    if !is_bidi {
        guard data.len > 0 || fin else { return H3_ERR_NO_ERROR; }

        for sid in conn.ignored_uni_streams {
            if sid == stream_id {
                return H3_ERR_NO_ERROR;
            }
        }

        var offset: u64 = 0;

        let is_known = (conn.peer_control_opened && stream_id == conn.peer_control_stream_id) ||
                       (conn.peer_qpack_enc_opened && stream_id == conn.peer_qpack_enc_stream_id) ||
                       (conn.peer_qpack_dec_opened && stream_id == conn.peer_qpack_dec_stream_id);

        if !is_known && data.len > 0 {
            let stype, off1, ok_type = quic_decode_varint(data, offset);
            guard ok_type else { return H3_ERR_GENERAL_PROTOCOL; }
            offset = off1;

            if stype == H3_STREAM_CONTROL {
                if conn.peer_control_opened {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_STREAM_CREATION;
                    return H3_ERR_STREAM_CREATION;
                }
                conn.peer_control_opened = true;
                conn.peer_control_stream_id = stream_id;
            } else if stype == H3_STREAM_QPACK_ENCODER {
                if conn.peer_qpack_enc_opened {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_STREAM_CREATION;
                    return H3_ERR_STREAM_CREATION;
                }
                conn.peer_qpack_enc_opened = true;
                conn.peer_qpack_enc_stream_id = stream_id;
            } else if stype == H3_STREAM_QPACK_DECODER {
                if conn.peer_qpack_dec_opened {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_STREAM_CREATION;
                    return H3_ERR_STREAM_CREATION;
                }
                conn.peer_qpack_dec_opened = true;
                conn.peer_qpack_dec_stream_id = stream_id;
            } else {
                // Unknown unidirectional stream: ignore payload (RFC 9114 Section 6.2)
                if conn.ignored_uni_streams.len < conn.ignored_uni_streams.cap {
                    conn.ignored_uni_streams.push(stream_id);
                }
                return H3_ERR_NO_ERROR;
            }
        }

        // Critical stream closure defense (RFC 9114 Section 6.2.1)
        if fin {
            let is_critical = (conn.peer_control_opened && stream_id == conn.peer_control_stream_id) ||
                              (conn.peer_qpack_enc_opened && stream_id == conn.peer_qpack_enc_stream_id) ||
                              (conn.peer_qpack_dec_opened && stream_id == conn.peer_qpack_dec_stream_id);
            if is_critical {
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

        // Process frames on Peer Control Stream
        if stream_id == conn.peer_control_stream_id && offset < (data.len as u64) {
            while offset < (data.len as u64) {
                let hdr, ok_hdr = parse_h3_frame_header(data, offset);
                guard ok_hdr else {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_FRAME_ERROR;
                    return H3_ERR_FRAME_ERROR;
                }

                offset += hdr.header_len;
                guard (0xFFFFFFFFFFFFFFFF - offset) >= hdr.payload_len && (offset + hdr.payload_len) <= (data.len as u64) else {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_FRAME_ERROR;
                    return H3_ERR_FRAME_ERROR;
                }

                let p_start = offset as i64;
                let p_end = (offset + hdr.payload_len) as i64;
                let payload = data[p_start..p_end];
                offset += hdr.payload_len;

                // First frame on Control Stream MUST be SETTINGS (RFC 9114 §6.2.1 & §7.2.4)
                if !conn.peer_settings_received {
                    if hdr.frame_type != H3_FRAME_SETTINGS {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_MISSING_SETTINGS;
                        return H3_ERR_MISSING_SETTINGS;
                    }
                    let set_err = parse_h3_settings_frame(payload, conn.peer_settings);
                    if set_err != H3_ERR_NO_ERROR {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = set_err;
                        return set_err;
                    }
                    conn.peer_settings_received = true;
                    conn.state = H3ConnState.Active;
                } else {
                    // Control stream invariants for subsequent frames (RFC 9114 Section 7.2)
                    if !is_allowed_on_control_stream(hdr.frame_type) {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
                        return H3_ERR_FRAME_UNEXPECTED;
                    }

                    // Second SETTINGS frame is strictly forbidden
                    if hdr.frame_type == H3_FRAME_SETTINGS {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_FRAME_UNEXPECTED;
                        return H3_ERR_FRAME_UNEXPECTED;
                    }

                    // Process GOAWAY frame (RFC 9114 §5.2 & §7.2.6)
                    if hdr.frame_type == H3_FRAME_GOAWAY {
                        let max_sid, ok_ga = parse_h3_goaway_frame(payload);
                        if !ok_ga {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_FRAME_ERROR;
                            return H3_ERR_FRAME_ERROR;
                        }
                        // RFC 9114 §5.2: Stream ID MUST identify a client-initiated bidirectional stream ((id & 0x03) == 0)
                        if (max_sid & 0x03) != 0 {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_ID_ERROR;
                            return H3_ERR_ID_ERROR;
                        }
                        // RFC 9114 §5.2: Monotonicity - subsequent GOAWAY Stream ID must not be greater than previous
                        if conn.goaway_received {
                            if max_sid > conn.goaway_max_stream_id {
                                conn.state = H3ConnState.Closed;
                                conn.error_code = H3_ERR_ID_ERROR;
                                return H3_ERR_ID_ERROR;
                            }
                        }
                        conn.goaway_received = true;
                        conn.goaway_max_stream_id = max_sid;
                        conn.state = H3ConnState.Draining;
                    }

                    // Process CANCEL_PUSH frame (RFC 9114 §7.2.7)
                    if hdr.frame_type == H3_FRAME_CANCEL_PUSH {
                        let push_id, ok_cp = parse_h3_cancel_push(payload);
                        if !ok_cp {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_FRAME_ERROR;
                            return H3_ERR_FRAME_ERROR;
                        }
                        // RFC 9114 §7.2.7: push_id cannot exceed advertised max push ID
                        if conn.max_push_id_sent && push_id > conn.max_push_id_advertised {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_ID_ERROR;
                            return H3_ERR_ID_ERROR;
                        }
                    }

                    // Process MAX_PUSH_ID frame (RFC 9114 §7.2.7)
                    if hdr.frame_type == H3_FRAME_MAX_PUSH_ID {
                        let max_pid, ok_mp = parse_h3_max_push_id(payload);
                        if !ok_mp {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_FRAME_ERROR;
                            return H3_ERR_FRAME_ERROR;
                        }
                        // Monotonicity: subsequent MAX_PUSH_ID MUST NOT decrease
                        if conn.max_push_id_received > 0 && max_pid < conn.max_push_id_received {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_ID_ERROR;
                            return H3_ERR_ID_ERROR;
                        }
                        conn.max_push_id_received = max_pid;
                    }
                }
            }
        }

        // Process instructions on Peer QPACK Encoder Stream (RFC 9204 §4.3)
        if stream_id == conn.peer_qpack_enc_stream_id && offset < (data.len as u64) {
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

        // Process instructions on Peer QPACK Decoder Stream (RFC 9204 §4.4)
        if stream_id == conn.peer_qpack_dec_stream_id && offset < (data.len as u64) {
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

    // -------------------------------------------------------------------------
    // B. Bidirectional Request Streams
    // -------------------------------------------------------------------------
    var s_idx, found = find_h3_stream_idx(conn, stream_id);
    if !found {
        guard conn.streams.len < conn.streams.cap else { return H3_ERR_EXCESSIVE_LOAD; }
        conn.streams.push(H3StreamEntry {
            stream_id: stream_id,
            kind: H3StreamKind.Request,
            state: H3StreamState.Open,
            is_bidi: true,
            headers_sent: false,
            headers_received: false,
            trailers_received: false,
            fin_sent: false,
            fin_received: false,
            status_code: 0,
            body_received_len: 0,
            content_length: -1,
            received_body: [],
        });
        s_idx = (conn.streams.len - 1) as i32;
    }

    var offset: u64 = 0;
    while offset < (data.len as u64) {
        let hdr, ok_hdr = parse_h3_frame_header(data, offset);
        guard ok_hdr else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }

        offset += hdr.header_len;
        guard (0xFFFFFFFFFFFFFFFF - offset) >= hdr.payload_len && (offset + hdr.payload_len) <= (data.len as u64) else {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_ERROR;
            return H3_ERR_FRAME_ERROR;
        }

        let p_start = offset as i64;
        let p_end = (offset + hdr.payload_len) as i64;
        let payload = data[p_start..p_end];
        offset += hdr.payload_len;

        // Invariant: Frames forbidden on Request Stream (RFC 9114 Section 7.2)
        if !is_allowed_on_request_stream(hdr.frame_type) {
            conn.state = H3ConnState.Closed;
            conn.error_code = H3_ERR_FRAME_UNEXPECTED;
            return H3_ERR_FRAME_UNEXPECTED;
        }

        // PUSH_PROMISE Frame (RFC 9114 §7.2.5)
        if hdr.frame_type == H3_FRAME_PUSH_PROMISE {
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
            let push_id, off_p, ok_p = quic_decode_varint(payload, 0);
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
            continue;
        }

        // 1. HEADERS Frame
        if hdr.frame_type == H3_FRAME_HEADERS {
            var decoded_fields: HeaderField[>..] = [];
            let q_err = decode_qpack_section(conn.qpack_table, payload, decoded_fields);
            if q_err != QpackError.None {
                conn.state = H3ConnState.Closed;
                conn.error_code = H3_ERR_QPACK_DECOMPRESSION_FAILED;
                return H3_ERR_QPACK_DECOMPRESSION_FAILED;
            }

            var seen_regular = false;
            var pseudo_status_count: i32 = 0;
            var pseudo_method_count: i32 = 0;
            var pseudo_scheme_count: i32 = 0;
            var pseudo_authority_count: i32 = 0;
            var pseudo_path_count: i32 = 0;
            var host_count: i32 = 0;
            var auth_val: u8[..256] = [];
            var host_val: u8[..256] = [];

            // Extract status code and validate fields
            for field in decoded_fields {
                let is_pseudo = field.name.len > 0 && field.name[0] == ':';

                // Trailers MUST NOT contain pseudo-headers or disallowed framing headers (RFC 9114 Section 4.3)
                let is_trailer_section = conn.streams[s_idx].headers_received && conn.streams[s_idx].status_code >= 200;
                if is_trailer_section {
                    if is_pseudo {
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
                }

                // RFC 9114 Section 4.2: Field values MUST NOT contain forbidden CTL characters
                for b in field.value {
                    if (b < 0x20 && b != '\t') || b == 0x7F {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                        return H3_ERR_GENERAL_PROTOCOL;
                    }
                }

                // RFC 9114 Section 4.3: Pseudo-headers MUST appear before any regular headers
                if is_pseudo {
                    if seen_regular {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                        return H3_ERR_GENERAL_PROTOCOL;
                    }
                    if field.name[..] == ":status" {
                        pseudo_status_count++;
                        if pseudo_status_count > 1 {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                            return H3_ERR_GENERAL_PROTOCOL;
                        }
                    } else if field.name[..] == ":method" {
                        pseudo_method_count++;
                        if pseudo_method_count > 1 {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                            return H3_ERR_GENERAL_PROTOCOL;
                        }
                    } else if field.name[..] == ":scheme" {
                        pseudo_scheme_count++;
                        if pseudo_scheme_count > 1 {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                            return H3_ERR_GENERAL_PROTOCOL;
                        }
                    } else if field.name[..] == ":authority" {
                        pseudo_authority_count++;
                        if pseudo_authority_count > 1 || field.value.len == 0 {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                            return H3_ERR_GENERAL_PROTOCOL;
                        }
                        for b in field.value {
                            if b <= 0x20 || b == 0x7F || b == '/' || b == '?' || b == '#' || b == '@' || b == ',' {
                                conn.state = H3ConnState.Closed;
                                conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                                return H3_ERR_GENERAL_PROTOCOL;
                            }
                        }
                        auth_val.clear();
                        auth_val.append(field.value[..]);
                    } else if field.name[..] == ":path" {
                        pseudo_path_count++;
                        if pseudo_path_count > 1 {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                            return H3_ERR_GENERAL_PROTOCOL;
                        }
                    } else {
                        // Undefined or invalid pseudo-header (RFC 9114 Section 4.3)
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                        return H3_ERR_GENERAL_PROTOCOL;
                    }
                } else {
                    seen_regular = true;
                }

                // Forbidden connection-specific headers in HTTP/3 (RFC 9114 Section 4.2)
                if eq_ascii_fold(field.name[..], "connection") ||
                   eq_ascii_fold(field.name[..], "keep-alive") ||
                   eq_ascii_fold(field.name[..], "proxy-connection") ||
                   eq_ascii_fold(field.name[..], "transfer-encoding") ||
                   eq_ascii_fold(field.name[..], "upgrade") ||
                   (eq_ascii_fold(field.name[..], "te") && !eq_ascii_fold(field.value[..], "trailers")) {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                    return H3_ERR_GENERAL_PROTOCOL;
                }

                if field.name[..] == ":status" {
                    if field.value.len != 3 {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                        return H3_ERR_GENERAL_PROTOCOL;
                    }
                    let sc, ok_sc = core::parse_i32_dec(field.value[..]);
                    if !ok_sc || sc < 100 || sc > 599 || sc == 101 {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                        return H3_ERR_GENERAL_PROTOCOL;
                    }
                    conn.streams[s_idx].status_code = sc;
                } else if eq_ascii_fold(field.name[..], "host") {
                    host_count++;
                    if host_count > 1 || field.value.len == 0 {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                        return H3_ERR_GENERAL_PROTOCOL;
                    }
                    for b in field.value {
                        if b <= 0x20 || b == 0x7F || b == '/' || b == '?' || b == '#' || b == '@' || b == ',' {
                            conn.state = H3ConnState.Closed;
                            conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                            return H3_ERR_GENERAL_PROTOCOL;
                        }
                    }
                    host_val.clear();
                    host_val.append(field.value[..]);
                } else if eq_ascii_fold(field.name[..], "content-length") {
                    let cl, ok_cl = core::parse_i64_dec(field.value[..]);
                    if !ok_cl || cl < 0 || (conn.streams[s_idx].content_length >= 0 && conn.streams[s_idx].content_length != cl) {
                        conn.state = H3ConnState.Closed;
                        conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                        return H3_ERR_GENERAL_PROTOCOL;
                    }
                    conn.streams[s_idx].content_length = cl;
                }
            }

            if pseudo_authority_count > 0 && host_count > 0 {
                // RFC 9114 Section 4.3.1: :authority and host MUST match case-insensitively
                if !core::eq_ascii_fold(auth_val[..], host_val[..]) {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                    return H3_ERR_GENERAL_PROTOCOL;
                }
            }

            if conn.streams[s_idx].status_code >= 200 || pseudo_method_count > 0 {
                if !conn.streams[s_idx].headers_received {
                    conn.streams[s_idx].headers_received = true;
                } else if !conn.streams[s_idx].trailers_received {
                    conn.streams[s_idx].trailers_received = true;
                } else {
                    conn.state = H3ConnState.Closed;
                    conn.error_code = H3_ERR_FRAME_UNEXPECTED;
                    return H3_ERR_FRAME_UNEXPECTED;
                }
            }
        }

        // 2. DATA Frame
        if hdr.frame_type == H3_FRAME_DATA {
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

            if conn.streams[s_idx].content_length >= 0 && conn.streams[s_idx].body_received_len > (conn.streams[s_idx].content_length as u64) {
                conn.state = H3ConnState.Closed;
                conn.error_code = H3_ERR_GENERAL_PROTOCOL;
                return H3_ERR_GENERAL_PROTOCOL;
            }
        }
    }

    if fin {
        conn.streams[s_idx].fin_received = true;
        if conn.streams[s_idx].content_length >= 0 && conn.streams[s_idx].body_received_len != (conn.streams[s_idx].content_length as u64) {
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
