// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Transport Frames Codec, Demuxer & RFC 9000 Section 19 Frame Types.
// Implements zero-allocation parsing and serialization for STREAM, CRYPTO,
// RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, PING, and PADDING.
namespace quic;

import std;
import core;
import .packet;
import .frames_internal;

// ---- Frame Constants & Stream Flags (RFC 9000 Section 19) ----------------

enum QuicFrameType {
    Padding,
    Ping,
    Ack,
    AckEcn,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreamsBidi,
    MaxStreamsUni,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlockedBidi,
    StreamsBlockedUni,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    HandshakeDone,
    ImmediateAck,
    ConnectionClose,
    ConnectionCloseApp,
    Datagram,
    AckFrequency,
    Unknown,
}

// draft-ietf-quic-ack-frequency Section 4.1: ACK_FREQUENCY Frame (0xaf)
struct QuicAckFrequencyFrame {
    seq:                      u64 = 0,
    ack_eliciting_threshold:  u64 = 1,
    request_max_ack_delay_us: u64 = 0,
    reordering_threshold:     u64 = 0,
}

// RFC 9000 Section 18.2 & RFC 9368 Section 3: QUIC Transport Parameters
struct QuicTransportParams {
    original_destination_connection_id:  u8[..20] = [],
    max_idle_timeout:                    u64      = 0,
    stateless_reset_token:               u8[16]   = [0; 16],
    has_stateless_reset_token:           bool     = false,
    max_udp_payload_size:                u64      = 65527,
    initial_max_data:                    u64      = 0,
    initial_max_stream_data_bidi_local:  u64      = 0,
    initial_max_stream_data_bidi_remote: u64      = 0,
    initial_max_stream_data_uni:         u64      = 0,
    initial_max_streams_bidi:            u64      = 0,
    initial_max_streams_uni:             u64      = 0,
    ack_delay_exponent:                  u64      = 3,
    max_ack_delay:                       u64      = 25,
    disable_active_migration:            bool     = false,
    preferred_address:                   u8[..64] = [],
    active_connection_id_limit:          u64      = 2,
    initial_source_connection_id:        u8[..20] = [],
    retry_source_connection_id:          u8[..20] = [],
    chosen_version:                      u32      = 0,
    available_versions:                  u32[..8] = [],
    max_datagram_frame_size:             u64      = 0,
    grease_quic_bit:                     bool     = false,
    min_ack_delay_us:                    u64      = 0,
    seen_mask:                           u64      = 0,
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - 8-byte payload structure
// RFC 9000 Section 19.18: PATH_RESPONSE Frames - 8-byte payload structure
struct QuicPathFrame {
    data: u8[8] = [0; 8],
}

struct QuicStreamFrame {
    stream_id: u64         = 0,
    offset:    u64         = 0,
    fin:       bool        = false,
    data:      const u8[:] = "",
}

struct QuicStreamFlags {
    fin:         bool = false,
    with_len:    bool = true,
    with_offset: bool = false,
}

struct QuicCryptoFrame {
    offset: u64         = 0,
    data:   const u8[:] = "",
}

struct QuicResetStreamFrame {
    stream_id:  u64 = 0,
    error_code: u64 = 0,
    final_size: u64 = 0,
}

struct QuicStopSendingFrame {
    stream_id:  u64 = 0,
    error_code: u64 = 0,
}

struct QuicMaxDataFrame {
    max_data: u64 = 0,
}

struct QuicMaxStreamDataFrame {
    stream_id:       u64 = 0,
    max_stream_data: u64 = 0,
}

struct QuicFrame {
    frame_type: QuicFrameType = QuicFrameType.Unknown,
    raw_type:   u64           = 0,
    stream_id:  u64           = 0,
    offset:     u64           = 0,
    length:     u64           = 0,
    error_code: u64           = 0,
    final_size: u64           = 0,
    max_data:   u64           = 0,
    fin:        bool          = false,
    payload:    const u8[:]   = "",
}

// ---- Dedicated Frame Encoders (RFC 9000 Section 19) ----------------------

// Encodes one or more PADDING frames (0x00) into output buffer.
fn encode_padding_frame<B>(out: B&, count: u64 = 1) -> bool {
    guard count > 0 else { return true; }
    guard count <= (core::sub_sat_i64(out.cap, out.len) as u64) else { return false; }
    let new_len = core::add_sat_i64(out.len, count as i64);
    out.resize(new_len, 0);
    return true;
}

// Encodes a PING frame (0x01) into output buffer.
fn encode_ping_frame<B>(out: B&) -> bool {
    return out.try_push(rfc::QUIC_FRAME_PING as u8);
}

// Encodes a RESET_STREAM frame (0x04) (RFC 9000 Section 19.4).
fn encode_reset_stream_frame<B>(
    stream_id:  u64,
    error_code: u64,
    final_size: u64,
    out:        B&,
) -> bool {
    guard stream_id <= rfc::QUIC_VARINT_MAX else { return false; }
    guard error_code <= rfc::QUIC_VARINT_MAX else { return false; }
    guard final_size <= rfc::QUIC_VARINT_MAX else { return false; }

    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_RESET_STREAM, out)
        && encode_varint(stream_id, out)
        && encode_varint(error_code, out)
        && encode_varint(final_size, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a STOP_SENDING frame (0x05) (RFC 9000 Section 19.5).
fn encode_stop_sending_frame<B>(
    stream_id:  u64,
    error_code: u64,
    out:        B&,
) -> bool {
    guard stream_id <= rfc::QUIC_VARINT_MAX else { return false; }
    guard error_code <= rfc::QUIC_VARINT_MAX else { return false; }

    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_STOP_SENDING, out)
        && encode_varint(stream_id, out)
        && encode_varint(error_code, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a CRYPTO frame (0x06) (RFC 9000 Section 19.6).
fn encode_crypto_frame<B>(
    offset: u64,
    data:   const u8[:],
    out:    B&,
) -> bool {
    guard quic_internal::quic_valid_offset_len(offset, data.len as u64) else { return false; }

    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_CRYPTO, out)
        && encode_varint(offset, out)
        && encode_varint(data.len as u64, out)
        && out.try_append(data) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a standard STREAM frame (RFC 9000 Section 19.8).
fn encode_stream_frame<B>(
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    out:       B&,
    flags:     QuicStreamFlags = QuicStreamFlags { .. },
) -> bool {
    var fl = flags;
    fl.with_offset = offset > 0;
    return quic_internal::encode_stream_frame_explicit(stream_id, offset, data, fl, out);
}

// Encodes a MAX_DATA frame (0x10) (RFC 9000 Section 19.9).
fn encode_max_data_frame<B>(max_data: u64, out: B&) -> bool {
    guard max_data <= rfc::QUIC_VARINT_MAX else { return false; }
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_MAX_DATA, out)
        && encode_varint(max_data, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a MAX_STREAM_DATA frame (0x11) (RFC 9000 Section 19.10).
fn encode_max_stream_data_frame<B>(
    stream_id:       u64,
    max_stream_data: u64,
    out:             B&,
) -> bool {
    guard stream_id <= rfc::QUIC_VARINT_MAX else { return false; }
    guard max_stream_data <= rfc::QUIC_VARINT_MAX else { return false; }

    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_MAX_STREAM_DATA, out)
        && encode_varint(stream_id, out)
        && encode_varint(max_stream_data, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a MAX_STREAMS frame (0x12: bidi, 0x13: uni) (RFC 9000 Section 19.11).
fn encode_max_streams_frame<B>(max_streams: u64, is_bidi: bool, out: B&) -> bool {
    guard max_streams <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
    let ftype = if is_bidi { rfc::QUIC_FRAME_MAX_STREAMS_BIDI } else { rfc::QUIC_FRAME_MAX_STREAMS_UNI };
    let orig_len = out.len;
    guard encode_varint(ftype, out) && encode_varint(max_streams, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a DATA_BLOCKED frame (0x14) (RFC 9000 Section 19.12).
fn encode_data_blocked_frame<B>(max_data: u64, out: B&) -> bool {
    guard max_data <= rfc::QUIC_VARINT_MAX else { return false; }
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_DATA_BLOCKED, out)
        && encode_varint(max_data, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a STREAM_DATA_BLOCKED frame (0x15) (RFC 9000 Section 19.13).
fn encode_stream_data_blocked_frame<B>(stream_id: u64, limit: u64, out: B&) -> bool {
    guard stream_id <= rfc::QUIC_VARINT_MAX && limit <= rfc::QUIC_VARINT_MAX else { return false; }
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_STREAM_DATA_BLOCKED, out)
        && encode_varint(stream_id, out)
        && encode_varint(limit, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a STREAMS_BLOCKED frame (0x16: bidi, 0x17: uni) (RFC 9000 Section 19.14).
fn encode_streams_blocked_frame<B>(stream_limit: u64, is_bidi: bool, out: B&) -> bool {
    guard stream_limit <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
    let ftype = if is_bidi { rfc::QUIC_FRAME_STREAMS_BLOCKED_BIDI } else { rfc::QUIC_FRAME_STREAMS_BLOCKED_UNI };
    let orig_len = out.len;
    guard encode_varint(ftype, out) && encode_varint(stream_limit, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a NEW_TOKEN frame (0x07) (RFC 9000 Section 19.7).
// The token MUST NOT be empty.
fn encode_new_token_frame<B>(token: const u8[:], out: B&) -> bool {
    guard token.len > 0 else { return false; }
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_NEW_TOKEN, out)
        && encode_varint(token.len as u64, out)
        && out.try_append(token) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a NEW_CONNECTION_ID frame (0x18) (RFC 9000 Section 19.15).
fn encode_new_conn_id_frame<B>(
    seq:                   u64,
    retire_prior_to:       u64,
    conn_id:               const u8[:],
    stateless_reset_token: const u8[16]&,
    out:                   B&,
) -> bool {
    guard seq <= rfc::QUIC_VARINT_MAX && retire_prior_to <= seq else { return false; }
    guard conn_id.len >= 1 && conn_id.len <= 20 else { return false; }
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_NEW_CONNECTION_ID, out)
        && encode_varint(seq, out)
        && encode_varint(retire_prior_to, out)
        && out.try_push(conn_id.len as u8)
        && out.try_append(conn_id)
        && out.try_append(stateless_reset_token[..]) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a RETIRE_CONNECTION_ID frame (0x19) (RFC 9000 Section 19.16).
fn encode_retire_conn_id_frame<B>(seq: u64, out: B&) -> bool {
    guard seq <= rfc::QUIC_VARINT_MAX else { return false; }
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_RETIRE_CONNECTION_ID, out)
        && encode_varint(seq, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - PATH_CHALLENGE frame format
// Encodes a PATH_CHALLENGE frame (0x1A) containing 8-byte payload.
//
// Example:
//   data = [1, 2, 3, 4, 5, 6, 7, 8]
//   out: appends 0x1A followed by 8 data bytes
fn encode_path_challenge_frame<B>(data: const u8[8]&, out: B&) -> bool {
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_PATH_CHALLENGE, out)
        && out.try_append(data[..]) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// RFC 9000 Section 19.18: PATH_RESPONSE Frames - PATH_RESPONSE frame format
// Encodes a PATH_RESPONSE frame (0x1B) containing 8-byte payload.
//
// Example:
//   data = [1, 2, 3, 4, 5, 6, 7, 8]
//   out: appends 0x1B followed by 8 data bytes
fn encode_path_response_frame<B>(data: const u8[8]&, out: B&) -> bool {
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_PATH_RESPONSE, out)
        && out.try_append(data[..]) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a HANDSHAKE_DONE frame (0x1E) (RFC 9000 Section 19.20).
fn encode_handshake_done_frame<B>(out: B&) -> bool {
    guard encode_varint(rfc::QUIC_FRAME_HANDSHAKE_DONE, out) else { return false; }
    return true;
}

// Encodes an ACK_FREQUENCY frame (0xAF) (draft-ietf-quic-ack-frequency Section 4.1).
fn encode_ack_frequency_frame<B>(f: const QuicAckFrequencyFrame&, out: B&) -> bool {
    guard f.ack_eliciting_threshold >= 1 && f.ack_eliciting_threshold <= rfc::QUIC_VARINT_MAX else {
        return false;
    }
    guard f.seq <= rfc::QUIC_VARINT_MAX
        && f.request_max_ack_delay_us <= rfc::QUIC_VARINT_MAX
        && f.reordering_threshold <= rfc::QUIC_VARINT_MAX else {
        return false;
    }
    let orig_len = out.len;
    guard encode_varint(rfc::QUIC_FRAME_ACK_FREQUENCY, out)
        && encode_varint(f.seq, out)
        && encode_varint(f.ack_eliciting_threshold, out)
        && encode_varint(f.request_max_ack_delay_us, out)
        && encode_varint(f.reordering_threshold, out) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// Encodes a CONNECTION_CLOSE frame (0x1C or 0x1D) (RFC 9000 Section 19.19).
fn encode_connection_close_frame<B>(
    error_code: u64,
    frame_type: u64,
    reason:     const u8[:],
    out:        B&,
    is_app:     bool = false,
) -> bool {
    guard error_code <= rfc::QUIC_VARINT_MAX else { return false; }
    guard is_app || frame_type <= rfc::QUIC_VARINT_MAX else { return false; }
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len, 0); };

    let ftype = if is_app { rfc::QUIC_FRAME_CONNECTION_CLOSE_APP } else { rfc::QUIC_FRAME_CONNECTION_CLOSE };
    guard encode_varint(ftype, out) && encode_varint(error_code, out) else {
        return false;
    }
    if !is_app {
        guard encode_varint(frame_type, out) else { return false; }
    }
    guard encode_varint(reason.len as u64, out) && out.try_append(reason) else {
        return false;
    }
    committed = true;
    return true;
}

// ---- ACK Frequency & Datagram Extension Frames (RFC 9221) ----------------

// Decodes an ACK_FREQUENCY frame payload (draft-ietf-quic-ack-frequency Section 4.1) from a ByteCursor.
// Rejects `ack_eliciting_threshold == 0` with `false` (FRAME_ENCODING_ERROR).
//
// Example:
//   c.buf = [0x01, 0x02, 0x40, 0x64, 0x03] (seq=1, threshold=2, max_delay=100, reorder=3)
//   returns: QuicAckFrequencyFrame { seq: 1, ack_eliciting_threshold: 2, request_max_ack_delay_us: 100 }, ok = true
fn decode_ack_frequency_frame(c: core::ByteCursor&) -> QuicAckFrequencyFrame, bool {
    var idx: i64 = 0;
    let seq, ok1 = decode_varint_cursor(c.buf, idx);
    guard ok1 else { return QuicAckFrequencyFrame { .. }, false; }
    let thresh, ok2 = decode_varint_cursor(c.buf, idx);
    guard ok2 && thresh >= 1 else { return QuicAckFrequencyFrame { .. }, false; }
    let max_delay, ok3 = decode_varint_cursor(c.buf, idx);
    guard ok3 else { return QuicAckFrequencyFrame { .. }, false; }
    let reorder, ok4 = decode_varint_cursor(c.buf, idx);
    guard ok4 else { return QuicAckFrequencyFrame { .. }, false; }
    c.buf = c.buf[idx..];
    return QuicAckFrequencyFrame {
        seq:                      seq,
        ack_eliciting_threshold:  thresh,
        request_max_ack_delay_us: max_delay,
        reordering_threshold:     reorder,
    }, true;
}

// Encodes an RFC 9221 QUIC DATAGRAM frame into buffer.
// If with_length is true (default), encodes frame type 0x31 with VarInt length prefix.
// If with_length is false, encodes frame type 0x30 consuming remainder of packet.
fn encode_datagram_frame<B>(payload: const u8[:], out: B&, with_length: bool = true) -> bool {
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len, 0); };

    if with_length {
        guard encode_varint(rfc::QUIC_FRAME_DATAGRAM_LEN, out)
            && encode_varint(payload.len as u64, out) else {
            return false;
        }
    } else {
        guard encode_varint(rfc::QUIC_FRAME_DATAGRAM, out) else { return false; }
    }
    guard out.try_append(payload) else { return false; }
    committed = true;
    return true;
}

// Decodes an RFC 9221 QUIC DATAGRAM frame from wire slice.
//
// Example:
//   src = [0x31, 0x04, 't', 'e', 's', 't'], offset = 0
//   returns: payload = "test", next_offset = 6, ok = true
fn decode_datagram_frame(
    src:        const u8[:],
    offset:     u64,
    packet_end: u64 = 0,
) -> const u8[:], u64, bool {
    let total_len = src.len as u64;
    guard offset < total_len else { return "", offset, false; }
    if packet_end > 0 {
        guard packet_end <= total_len && offset < packet_end else { return "", offset, false; }
    }
    let limit = if packet_end > 0 { packet_end } else { total_len };
    let ftype, off1, ok1 = decode_varint(src, offset);
    guard ok1 && off1 <= limit else { return "", offset, false; }

    guard ftype == rfc::QUIC_FRAME_DATAGRAM || ftype == rfc::QUIC_FRAME_DATAGRAM_LEN else {
        return "", offset, false;
    }
    if ftype == rfc::QUIC_FRAME_DATAGRAM {
        return src[(off1 as i64)..(limit as i64)], limit, true;
    }
    let dlen, off2, ok2 = decode_varint(src, off1);
    let eff_end = core::add_sat_u64(off2, dlen);
    guard ok2 && eff_end <= limit else { return "", offset, false; }
    return src[(off2 as i64)..(eff_end as i64)], eff_end, true;
}

// ---- Zero-Allocation Frame Demuxer API -----------------------------------

// Decodes a single QUIC frame directly from slice with cursor (RFC 9000 §19).
// Advances `idx` past the decoded frame on success.
// On failure (`ok = false`), `idx` is restored to its original value.
//
// Example:
//   src = [0x01, 0x06, 0x00, 0x02, 'o', 'k'], idx = 0
//   returns: QuicFrame { frame_type: Ping }, ok = true, idx = 1
fn decode_frame_cursor(src: const u8[:], idx: i64&) -> QuicFrame, bool {
    let initial_idx = idx;
    guard idx >= 0 && idx < src.len else { return QuicFrame { .. }, false; }

    let ftype, ok_type = decode_varint_cursor(src, idx);
    guard ok_type else {
        idx = initial_idx;
        return QuicFrame { .. }, false;
    }

    var frame: QuicFrame = QuicFrame { .. };
    var ok:    bool      = false;

    if ftype <= 0x11 {
        frame, ok = quic_internal::demux_core_frame(src, idx, ftype, initial_idx);
    } else if ftype == rfc::QUIC_FRAME_MAX_STREAMS_BIDI || ftype == rfc::QUIC_FRAME_MAX_STREAMS_UNI ||
       ftype == rfc::QUIC_FRAME_STREAMS_BLOCKED_BIDI || ftype == rfc::QUIC_FRAME_STREAMS_BLOCKED_UNI {
        frame, ok = quic_internal::demux_streams_limit_frame(src, idx, ftype);
    } else if ftype == rfc::QUIC_FRAME_DATA_BLOCKED || ftype == rfc::QUIC_FRAME_STREAM_DATA_BLOCKED {
        frame, ok = quic_internal::demux_blocked_frame(src, idx, ftype);
    } else if ftype <= rfc::QUIC_FRAME_IMMEDIATE_ACK {
        frame, ok = quic_internal::demux_session_frame(src, idx, ftype);
    } else if ftype == rfc::QUIC_FRAME_DATAGRAM || ftype == rfc::QUIC_FRAME_DATAGRAM_LEN {
        frame, ok = quic_internal::demux_datagram_frame(src, idx, ftype);
    } else if ftype == rfc::QUIC_FRAME_ACK_FREQUENCY {
        frame, ok = quic_internal::demux_ack_frequency_frame(src, idx);
    } else {
        frame = QuicFrame { raw_type: ftype, frame_type: QuicFrameType.Unknown };
        ok = false;
    }

    if !ok {
        idx = initial_idx;
        return frame, false;
    }
    return frame, true;
}

// Decodes a single QUIC frame from a byte slice at `offset`.
// On failure (`ok = false`), `next_offset` remains equal to the input `offset`.
//
// Example:
//   src = [0x01, 0x06, 0x00, 0x02, 'h', 'i'], offset = 0
//   call 1: returns Ping frame, next_offset = 1, ok = true
//   call 2 (offset = 1): returns Crypto frame ("hi"), next_offset = 6, ok = true
fn decode_frame(src: const u8[:], offset: u64) -> QuicFrame, u64, bool {
    guard offset < (src.len as u64) else {
        return QuicFrame { .. }, offset, false;
    }
    var idx = offset as i64;
    let frame, ok = decode_frame_cursor(src, idx);
    guard ok else { return frame, offset, false; }
    return frame, idx as u64, true;
}

// ---- QUIC Transport Parameters Codec (RFC 9000 §18, RFC 9368 §3) ----------

// Encodes QUIC transport parameters (RFC 9000 §18, RFC 9368 §3) into `out`.
fn encode_transport_params<B>(
    tp:        const QuicTransportParams&,
    is_server: bool,
    out:       B&,
) -> bool {
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len, 0); };

    guard quic_internal::encode_tp_cids_and_server(tp, is_server, out) else { return false; }
    // RFC 9000 Section 7.3: Authenticating Connection IDs - Both endpoints MUST send initial_source_connection_id.
    let iscid_id = rfc::QUIC_TP_INITIAL_SOURCE_CONNECTION_ID;
    guard quic_internal::encode_tp_bytes(iscid_id, tp.initial_source_connection_id[..], out) else { return false; }
    guard quic_internal::encode_tp_flow_data(tp, out)
        && quic_internal::encode_tp_streams_and_ack(tp, out)
        && quic_internal::encode_tp_extensions(tp, out)
        && quic_internal::encode_tp_version_info(tp, out) else {
        return false;
    }
    committed = true;
    return true;
}

// Decodes QUIC transport parameters from TLS extension `0x0039` payload (RFC 9000 §18, RFC 9368 §3).
// `is_server` indicates whether the encoded parameters were sent by a server (`true`) or client (`false`).
//
// Example:
//   src = [0x00, 0x00, 0x0f, 0x00, 0x03, 0x02, 0x45, 0xDC, 0x0c, 0x00], is_server = true
//   returns: QuicTransportParams { max_udp_payload_size: 1500, disable_active_migration: true }, ok = true
//
// crap:trusted-bounds
fn decode_transport_params(
    src:       const u8[:],
    is_server: bool,
) -> QuicTransportParams, bool {
    var tp = QuicTransportParams { .. };
    var cur = core::cursor_from(src);
    while cur.buf.len > 0 {
        var idx: i64 = 0;
        let id, ok_id = decode_varint_cursor(cur.buf, idx);
        let vlen, ok_len = decode_varint_cursor(cur.buf, idx);
        guard ok_id && ok_len else { return QuicTransportParams { .. }, false; }
        cur.buf = cur.buf[idx..];
        let val, ok_val = cur.read_bytes(vlen as i64);
        guard ok_val && quic_internal::decode_single_tp(id, val, is_server, tp) else {
            return QuicTransportParams { .. }, false;
        }
    }
    // RFC 9000 Section 7.3: Authenticating Connection IDs - Reject missing initial_source_connection_id or server original_destination_connection_id.
    guard tp.seen_mask.has_flag(quic_internal::QUIC_TP_BIT_ISCID)
        && (!is_server || tp.seen_mask.has_flag(quic_internal::QUIC_TP_BIT_ODCID)) else {
        return QuicTransportParams { .. }, false;
    }
    if tp.seen_mask.has_flag(quic_internal::QUIC_TP_BIT_MIN_ACK_DELAY) {
        let max_delay_us = core::mul_sat_u64(tp.max_ack_delay, 1000);
        guard tp.min_ack_delay_us <= max_delay_us else { return QuicTransportParams { .. }, false; }
    }
    return tp, true;
}
