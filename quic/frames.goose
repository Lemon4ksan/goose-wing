// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Transport Frames Codec, Demuxer & RFC 9000 Section 19 Frame Types.
// Implements zero-allocation parsing and serialization for STREAM, CRYPTO,
// RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, PING, and PADDING.
namespace internal;

import std;
import core from "..";
import .packet;

// ---- Frame Constants & Stream Flags (RFC 9000 Section 19) ----------------

const QUIC_VARINT_MAX:        u64 = 0x3FFFFFFFFFFFFFFF;
const QUIC_MAX_STREAMS_LIMIT: u64 = 0x1000000000000000; // 2^60 (RFC 9000 §19.11, §19.14)

const QUIC_STREAM_FLAG_FIN: u64 = 0x01;
const QUIC_STREAM_FLAG_LEN: u64 = 0x02;
const QUIC_STREAM_FLAG_OFF: u64 = 0x04;
const QUIC_STREAM_MAX_TYPE: u64 = 0x0F;

// ---- Frame Type Enum and Unified Zero-Alloc Frame Model -----------------

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
    ConnectionClose,
    ConnectionCloseApp,
    Datagram,
    Unknown,
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

// ---- Helper Invariant Checkers (RFC 9000 Range Validation) ---------------

// Validates that offset and length are valid 62-bit VarInts and sum <= 2^62 - 1.
inline fn quic_valid_offset_len(offset: u64, len: u64) -> bool {
    if offset > QUIC_VARINT_MAX { return false; }
    if len > QUIC_VARINT_MAX { return false; }
    let rem = QUIC_VARINT_MAX - offset;
    return rem >= len;
}

// Builds the STREAM frame type byte (0x08 - 0x0F) based on flags (RFC 9000 §19.8).
//
// Example:
//   flags = QuicStreamFlags { fin: false, with_len: true, with_offset: true }
//   returns: 0x0E (QUIC_FRAME_STREAM_BASE | LEN | OFF)
inline fn build_stream_frame_type(flags: QuicStreamFlags) -> u64 {
    var t: u64 = QUIC_FRAME_STREAM_BASE;
    if flags.with_offset { t = t | QUIC_STREAM_FLAG_OFF; }
    if flags.with_len { t = t | QUIC_STREAM_FLAG_LEN; }
    if flags.fin { t = t | QUIC_STREAM_FLAG_FIN; }
    return t;
}

// ---- Dedicated Frame Encoders (RFC 9000 Section 19) ----------------------

// Encodes one or more PADDING frames (0x00) into output buffer.
fn encode_padding_frame<B>(out: B&, count: u64 = 1) -> bool {
    guard count > 0 else { return true; }
    for _ in count {
        out.push(QUIC_FRAME_PADDING as u8);
    }
    return true;
}

// Encodes a PING frame (0x01) into output buffer.
fn encode_ping_frame<B>(out: B&) -> bool {
    out.push(QUIC_FRAME_PING as u8);
    return true;
}

// Encodes a RESET_STREAM frame (0x04) (RFC 9000 Section 19.4).
fn encode_reset_stream_frame<B>(
    out:        B&,
    stream_id:  u64,
    error_code: u64,
    final_size: u64,
) -> bool {
    guard stream_id <= QUIC_VARINT_MAX else { return false; }
    guard error_code <= QUIC_VARINT_MAX else { return false; }
    guard final_size <= QUIC_VARINT_MAX else { return false; }

    guard quic_encode_varint(out, QUIC_FRAME_RESET_STREAM) else { return false; }
    guard quic_encode_varint(out, stream_id) else { return false; }
    guard quic_encode_varint(out, error_code) else { return false; }
    guard quic_encode_varint(out, final_size) else { return false; }
    return true;
}

// Encodes a STOP_SENDING frame (0x05) (RFC 9000 Section 19.5).
fn encode_stop_sending_frame<B>(
    out:        B&,
    stream_id:  u64,
    error_code: u64,
) -> bool {
    guard stream_id <= QUIC_VARINT_MAX else { return false; }
    guard error_code <= QUIC_VARINT_MAX else { return false; }

    guard quic_encode_varint(out, QUIC_FRAME_STOP_SENDING) else { return false; }
    guard quic_encode_varint(out, stream_id) else { return false; }
    guard quic_encode_varint(out, error_code) else { return false; }
    return true;
}

// Encodes a CRYPTO frame (0x06) (RFC 9000 Section 19.6).
fn encode_crypto_frame<B>(
    out:    B&,
    offset: u64,
    data:   const u8[:],
) -> bool {
    guard quic_valid_offset_len(offset, data.len as u64) else { return false; }

    guard quic_encode_varint(out, QUIC_FRAME_CRYPTO) else { return false; }
    guard quic_encode_varint(out, offset) else { return false; }
    guard quic_encode_varint(out, data.len as u64) else { return false; }
    if data.len > 0 {
        out.append(data);
    }
    return true;
}

// Encodes a STREAM frame with explicit OFF/LEN flags (RFC 9000 Section 19.8).
fn encode_stream_frame_explicit<B>(
    out:       B&,
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    flags:     QuicStreamFlags,
) -> bool {
    guard stream_id <= QUIC_VARINT_MAX else { return false; }
    guard quic_valid_offset_len(offset, data.len as u64) else { return false; }

    let ftype = build_stream_frame_type(flags);

    guard quic_encode_varint(out, ftype) else { return false; }
    guard quic_encode_varint(out, stream_id) else { return false; }
    if flags.with_offset {
        guard quic_encode_varint(out, offset) else { return false; }
    }
    if flags.with_len {
        guard quic_encode_varint(out, data.len as u64) else { return false; }
    }
    if data.len > 0 {
        out.append(data);
    }
    return true;
}

// Encodes a standard STREAM frame (RFC 9000 Section 19.8).
fn encode_stream_frame<B>(
    out:       B&,
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    flags:     QuicStreamFlags = QuicStreamFlags { .. },
) -> bool {
    var fl = flags;
    fl.with_offset = offset > 0;
    return encode_stream_frame_explicit(out, stream_id, offset, data, fl);
}

// Encodes a MAX_DATA frame (0x10) (RFC 9000 Section 19.9).
fn encode_max_data_frame<B>(out: B&, max_data: u64) -> bool {
    guard max_data <= QUIC_VARINT_MAX else { return false; }
    guard quic_encode_varint(out, QUIC_FRAME_MAX_DATA) else { return false; }
    guard quic_encode_varint(out, max_data) else { return false; }
    return true;
}

// Encodes a MAX_STREAM_DATA frame (0x11) (RFC 9000 Section 19.10).
fn encode_max_stream_data_frame<B>(
    out:             B&,
    stream_id:       u64,
    max_stream_data: u64,
) -> bool {
    guard stream_id <= QUIC_VARINT_MAX else { return false; }
    guard max_stream_data <= QUIC_VARINT_MAX else { return false; }

    guard quic_encode_varint(out, QUIC_FRAME_MAX_STREAM_DATA) else { return false; }
    guard quic_encode_varint(out, stream_id) else { return false; }
    guard quic_encode_varint(out, max_stream_data) else { return false; }
    return true;
}

// Encodes a MAX_STREAMS frame (0x12: bidi, 0x13: uni) (RFC 9000 Section 19.11).
fn encode_max_streams_frame<B>(out: B&, max_streams: u64, is_bidi: bool) -> bool {
    guard max_streams <= QUIC_MAX_STREAMS_LIMIT else { return false; }
    let ftype = if is_bidi { QUIC_FRAME_MAX_STREAMS_BIDI } else { QUIC_FRAME_MAX_STREAMS_UNI };
    guard quic_encode_varint(out, ftype) else { return false; }
    guard quic_encode_varint(out, max_streams) else { return false; }
    return true;
}

// Encodes a DATA_BLOCKED frame (0x14) (RFC 9000 Section 19.12).
fn encode_data_blocked_frame<B>(out: B&, max_data: u64) -> bool {
    guard max_data <= QUIC_VARINT_MAX else { return false; }
    guard quic_encode_varint(out, QUIC_FRAME_DATA_BLOCKED) else { return false; }
    guard quic_encode_varint(out, max_data) else { return false; }
    return true;
}

// Encodes a STREAM_DATA_BLOCKED frame (0x15) (RFC 9000 Section 19.13).
fn encode_stream_data_blocked_frame<B>(out: B&, stream_id: u64, limit: u64) -> bool {
    guard stream_id <= QUIC_VARINT_MAX && limit <= QUIC_VARINT_MAX else { return false; }
    guard quic_encode_varint(out, QUIC_FRAME_STREAM_DATA_BLOCKED) else { return false; }
    guard quic_encode_varint(out, stream_id) else { return false; }
    guard quic_encode_varint(out, limit) else { return false; }
    return true;
}

// Encodes a STREAMS_BLOCKED frame (0x16: bidi, 0x17: uni) (RFC 9000 Section 19.14).
fn encode_streams_blocked_frame<B>(out: B&, stream_limit: u64, is_bidi: bool) -> bool {
    guard stream_limit <= QUIC_MAX_STREAMS_LIMIT else { return false; }
    let ftype = if is_bidi { QUIC_FRAME_STREAMS_BLOCKED_BIDI } else { QUIC_FRAME_STREAMS_BLOCKED_UNI };
    guard quic_encode_varint(out, ftype) else { return false; }
    guard quic_encode_varint(out, stream_limit) else { return false; }
    return true;
}

// Encodes a NEW_TOKEN frame (0x07) (RFC 9000 Section 19.7).
// The token MUST NOT be empty.
fn encode_new_token_frame<B>(out: B&, token: const u8[:]) -> bool {
    guard token.len > 0 else { return false; }
    guard quic_encode_varint(out, QUIC_FRAME_NEW_TOKEN) else { return false; }
    guard quic_encode_varint(out, token.len as u64) else { return false; }
    out.append(token);
    return true;
}

// Encodes a NEW_CONNECTION_ID frame (0x18) (RFC 9000 Section 19.15).
fn encode_new_conn_id_frame<B>(
    out:                   B&,
    seq:                   u64,
    retire_prior_to:       u64,
    conn_id:               const u8[:],
    stateless_reset_token: const u8[16]&,
) -> bool {
    guard seq <= QUIC_VARINT_MAX && retire_prior_to <= seq else { return false; }
    guard conn_id.len >= 1 && conn_id.len <= 20 else { return false; }
    guard quic_encode_varint(out, QUIC_FRAME_NEW_CONNECTION_ID) else { return false; }
    guard quic_encode_varint(out, seq) else { return false; }
    guard quic_encode_varint(out, retire_prior_to) else { return false; }
    out.push(conn_id.len as u8);
    out.append(conn_id);
    for i in 16 {
        out.push(stateless_reset_token[i]);
    }
    return true;
}

// Encodes a RETIRE_CONNECTION_ID frame (0x19) (RFC 9000 Section 19.16).
fn encode_retire_conn_id_frame<B>(out: B&, seq: u64) -> bool {
    guard seq <= QUIC_VARINT_MAX else { return false; }
    guard quic_encode_varint(out, QUIC_FRAME_RETIRE_CONNECTION_ID) else { return false; }
    guard quic_encode_varint(out, seq) else { return false; }
    return true;
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - PATH_CHALLENGE frame format
// Encodes a PATH_CHALLENGE frame (0x1A) containing 8-byte payload.
//
// Example:
//   data = [1, 2, 3, 4, 5, 6, 7, 8]
//   out: appends 0x1A followed by 8 data bytes
fn encode_path_challenge_frame<B>(out: B&, data: const u8[8]&) -> bool {
    guard quic_encode_varint(out, QUIC_FRAME_PATH_CHALLENGE) else { return false; }
    for i in 8 {
        out.push(data[i]);
    }
    return true;
}

// RFC 9000 Section 19.18: PATH_RESPONSE Frames - PATH_RESPONSE frame format
// Encodes a PATH_RESPONSE frame (0x1B) containing 8-byte payload.
//
// Example:
//   data = [1, 2, 3, 4, 5, 6, 7, 8]
//   out: appends 0x1B followed by 8 data bytes
fn encode_path_response_frame<B>(out: B&, data: const u8[8]&) -> bool {
    guard quic_encode_varint(out, QUIC_FRAME_PATH_RESPONSE) else { return false; }
    for i in 8 {
        out.push(data[i]);
    }
    return true;
}

// Encodes a HANDSHAKE_DONE frame (0x1E) (RFC 9000 Section 19.20).
fn encode_handshake_done_frame<B>(out: B&) -> bool {
    guard quic_encode_varint(out, QUIC_FRAME_HANDSHAKE_DONE) else { return false; }
    return true;
}

// Encodes a CONNECTION_CLOSE frame (0x1C or 0x1D) (RFC 9000 Section 19.19).
fn encode_connection_close_frame<B>(
    out:        B&,
    error_code: u64,
    frame_type: u64,
    reason:     const u8[:],
    is_app:     bool = false,
) -> bool {
    guard error_code <= QUIC_VARINT_MAX else { return false; }
    let ftype = if is_app { QUIC_FRAME_CONNECTION_CLOSE_APP } else { QUIC_FRAME_CONNECTION_CLOSE };
    guard quic_encode_varint(out, ftype) else { return false; }
    guard quic_encode_varint(out, error_code) else { return false; }
    if !is_app {
        guard quic_encode_varint(out, frame_type) else { return false; }
    }
    guard quic_encode_varint(out, reason.len as u64) else { return false; }
    if reason.len > 0 {
        out.append(reason);
    }
    return true;
}

// ---- Dedicated Frame Decoders (RFC 9000 Section 19) ----------------------

// Decodes ACK frame range intervals, ensuring monotonically descending bounds (RFC 9000 §19.3.1).
//
// Example:
//   src = [gap=0, rlen=2], idx = 0, range_cnt = 1, largest_acked = 10, first_range = 2
//   returns: ok = true, idx = 2
inline fn decode_ack_ranges(
    src:           const u8[:],
    idx:           i64&,
    range_cnt:     u64,
    largest_acked: u64,
    first_range:   u64,
) -> bool {
    var cur_smallest = largest_acked - first_range;
    var r_idx: u64 = 0;
    while r_idx < range_cnt {
        let gap, ok_g = quic_decode_varint_cursor(src, idx);
        guard ok_g else { return false; }
        let rlen, ok_r = quic_decode_varint_cursor(src, idx);
        guard ok_r else { return false; }

        guard cur_smallest >= 2 && (cur_smallest - 2) >= gap else { return false; }
        let cur_largest = cur_smallest - gap - 2;
        guard cur_largest >= rlen else { return false; }
        cur_smallest = cur_largest - rlen;
        r_idx++;
    }
    return true;
}

// Decodes ACK ECN counters (ECT0, ECT1, ECN-CE) directly from slice with cursor (RFC 9000 §19.3.2).
//
// Example:
//   src = [ect0=0, ect1=0, ce=0], idx = 0
//   returns: ok = true, idx = 3
inline fn decode_ack_ecn_counts(src: const u8[:], idx: i64&) -> bool {
    let _, ok_e0 = quic_decode_varint_cursor(src, idx);
    guard ok_e0 else { return false; }
    let _, ok_e1 = quic_decode_varint_cursor(src, idx);
    guard ok_e1 else { return false; }
    let _, ok_ce = quic_decode_varint_cursor(src, idx);
    return ok_ce;
}

// Decodes an ACK (0x02) or ACK_ECN (0x03) frame directly from slice with cursor (RFC 9000 §19.3).
// Assumes the frame type varint has already been consumed.
//
// Example:
//   src = [largest_acked=10, delay=0, range_count=0, first_range=5], idx = 0, is_ecn = false
//   returns: QuicFrame { frame_type: Ack, offset: 10, length: 5 }, ok = true
inline fn decode_ack_frame_cursor(src: const u8[:], idx: i64&, is_ecn: bool) -> QuicFrame, bool {
    let largest_acked, ok_la = quic_decode_varint_cursor(src, idx);
    guard ok_la else { return QuicFrame { .. }, false; }

    let ack_delay, ok_ad = quic_decode_varint_cursor(src, idx);
    guard ok_ad else { return QuicFrame { .. }, false; }

    let range_cnt, ok_rc = quic_decode_varint_cursor(src, idx);
    guard ok_rc && range_cnt <= 64 else { return QuicFrame { .. }, false; }

    let first_range, ok_fr = quic_decode_varint_cursor(src, idx);
    guard ok_fr && largest_acked >= first_range else { return QuicFrame { .. }, false; }

    guard decode_ack_ranges(src, idx, range_cnt, largest_acked, first_range) else {
        return QuicFrame { .. }, false;
    }

    if is_ecn {
        guard decode_ack_ecn_counts(src, idx) else { return QuicFrame { .. }, false; }
    }

    let k = if is_ecn { QuicFrameType.AckEcn } else { QuicFrameType.Ack };
    let raw = if is_ecn { QUIC_FRAME_ACK_ECN } else { QUIC_FRAME_ACK };
    return QuicFrame {
        frame_type: k,
        raw_type:   raw,
        offset:     largest_acked,
        length:     first_range,
        max_data:   ack_delay,
    }, true;
}

// Decodes a NEW_TOKEN frame (0x07) directly from slice with cursor (RFC 9000 §19.7).
// The Token field MUST NOT be empty; empty token yields false (FRAME_ENCODING_ERROR).
//
// Example:
//   src = [0x04, 't', 'o', 'k', 'n'], idx = 0
//   returns: QuicFrame { frame_type: NewToken, length: 4, payload: "tokn" }, ok = true, idx = 5
inline fn decode_new_token_frame(src: const u8[:], idx: i64&) -> QuicFrame, bool {
    let tlen, ok_len = quic_decode_varint_cursor(src, idx);
    guard ok_len && tlen > 0 else { return QuicFrame { .. }, false; }
    let ilen = tlen as i64;
    guard idx + ilen <= src.len else { return QuicFrame { .. }, false; }
    let token = src[idx..idx + ilen];
    idx += ilen;
    return QuicFrame {
        frame_type: QuicFrameType.NewToken,
        raw_type:   QUIC_FRAME_NEW_TOKEN,
        length:     tlen,
        payload:    token,
    }, true;
}

// Decodes a RESET_STREAM frame (0x04) directly from slice with cursor (RFC 9000 §19.4).
//
// Example:
//   src = [stream_id=4, error_code=0x10c, final_size=1024], idx = 0
//   returns: QuicResetStreamFrame { stream_id: 4, error_code: 0x10c, final_size: 1024 }, ok = true
inline fn decode_reset_stream_frame(src: const u8[:], idx: i64&) -> QuicResetStreamFrame, bool {
    let stream_id, ok_sid = quic_decode_varint_cursor(src, idx);
    guard ok_sid else { return QuicResetStreamFrame { .. }, false; }

    let error_code, ok_err = quic_decode_varint_cursor(src, idx);
    guard ok_err else { return QuicResetStreamFrame { .. }, false; }

    let final_size, ok_fs = quic_decode_varint_cursor(src, idx);
    guard ok_fs else { return QuicResetStreamFrame { .. }, false; }

    return QuicResetStreamFrame {
        stream_id:  stream_id,
        error_code: error_code,
        final_size: final_size,
    }, true;
}

// Decodes a STOP_SENDING frame (0x05) directly from slice with cursor (RFC 9000 §19.5).
//
// Example:
//   src = [stream_id=4, error_code=0x10c], idx = 0
//   returns: QuicStopSendingFrame { stream_id: 4, error_code: 0x10c }, ok = true
inline fn decode_stop_sending_frame(src: const u8[:], idx: i64&) -> QuicStopSendingFrame, bool {
    let stream_id, ok_sid = quic_decode_varint_cursor(src, idx);
    guard ok_sid else { return QuicStopSendingFrame { .. }, false; }

    let error_code, ok_err = quic_decode_varint_cursor(src, idx);
    guard ok_err else { return QuicStopSendingFrame { .. }, false; }

    return QuicStopSendingFrame {
        stream_id:  stream_id,
        error_code: error_code,
    }, true;
}

// Decodes a CRYPTO frame (0x06) directly from slice with cursor (RFC 9000 Section 19.6).
// Assumes the frame type varint (0x06) has already been consumed.
//
// Example:
//   src = [0x00, 0x04, 't', 'e', 's', 't'], idx = 0
//   returns: QuicCryptoFrame { offset: 0, data: "test" }, ok = true, idx = 6
// crap:trusted
// crap:trusted-bounds
inline fn decode_crypto_frame(src: const u8[:], idx: i64&) -> QuicCryptoFrame, bool {
    let offset, ok_off = quic_decode_varint_cursor(src, idx);
    guard ok_off else { return QuicCryptoFrame { .. }, false; }

    let data_len, ok_len = quic_decode_varint_cursor(src, idx);
    guard ok_len else { return QuicCryptoFrame { .. }, false; }

    guard quic_valid_offset_len(offset, data_len) else {
        return QuicCryptoFrame { .. }, false;
    }
    let dlen = data_len as i64;
    guard idx + dlen <= src.len else {
        return QuicCryptoFrame { .. }, false;
    }

    let payload = src[idx..idx + dlen];
    idx += dlen;

    return QuicCryptoFrame {
        offset: offset,
        data:   payload,
    }, true;
}

// Decodes a STREAM frame (0x08-0x0F) directly from slice with cursor (RFC 9000 Section 19.8).
// Flags encoded in `ftype`: 0x04 = OFF, 0x02 = LEN, 0x01 = FIN.
// If LEN (0x02) is unset, consumes all remaining bytes in `src`.
//
// Example:
//   src = [0x04, 0x00, 0x02, 'o', 'k'], idx = 0, ftype = 0x0f (OFF|LEN|FIN)
//   returns: QuicStreamFrame { stream_id: 4, offset: 0, fin: true, data: "ok" }, ok = true, idx = 5
//
// crap:trusted-bounds
inline fn decode_stream_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicStreamFrame, bool {
    guard ftype >= QUIC_FRAME_STREAM_BASE && ftype <= QUIC_STREAM_MAX_TYPE else {
        return QuicStreamFrame { .. }, false;
    }
    let has_fin = (ftype & QUIC_STREAM_FLAG_FIN) != 0;
    let has_len = (ftype & QUIC_STREAM_FLAG_LEN) != 0;
    let has_off = (ftype & QUIC_STREAM_FLAG_OFF) != 0;

    let stream_id, ok_sid = quic_decode_varint_cursor(src, idx);
    guard ok_sid else { return QuicStreamFrame { .. }, false; }

    var offset: u64 = 0;
    if has_off {
        let off_val, ok_off = quic_decode_varint_cursor(src, idx);
        guard ok_off else { return QuicStreamFrame { .. }, false; }
        offset = off_val;
    }

    var data_len: u64 = 0;
    if has_len {
        let len_val, ok_len = quic_decode_varint_cursor(src, idx);
        guard ok_len else { return QuicStreamFrame { .. }, false; }
        data_len = len_val;
    } else {
        let rem = src.len - idx;
        guard rem >= 0 else { return QuicStreamFrame { .. }, false; }
        data_len = rem as u64;
    }

    guard quic_valid_offset_len(offset, data_len) else {
        return QuicStreamFrame { .. }, false;
    }
    let dlen = data_len as i64;
    guard idx + dlen <= src.len else {
        return QuicStreamFrame { .. }, false;
    }

    let payload = src[idx..idx + dlen];
    idx += dlen;

    return QuicStreamFrame {
        stream_id: stream_id,
        offset:    offset,
        fin:       has_fin,
        data:      payload,
    }, true;
}

// Decodes a MAX_DATA frame (0x10) directly from slice with cursor (RFC 9000 §19.9).
//
// Example:
//   src = [0x50, 0x00], idx = 0 (varint 4096)
//   returns: QuicMaxDataFrame { max_data: 4096 }, ok = true, idx = 2
inline fn decode_max_data_frame(src: const u8[:], idx: i64&) -> QuicMaxDataFrame, bool {
    let max_data, ok = quic_decode_varint_cursor(src, idx);
    guard ok && max_data <= QUIC_VARINT_MAX else { return QuicMaxDataFrame { .. }, false; }
    return QuicMaxDataFrame { max_data: max_data }, true;
}

// Decodes a MAX_STREAM_DATA frame (0x11) directly from slice with cursor (RFC 9000 §19.10).
//
// Example:
//   src = [0x04, 0x50, 0x00], idx = 0 (stream_id = 4, max_stream_data = 4096)
//   returns: QuicMaxStreamDataFrame { stream_id: 4, max_stream_data: 4096 }, ok = true, idx = 3
inline fn decode_max_stream_data_frame(src: const u8[:], idx: i64&) -> QuicMaxStreamDataFrame, bool {
    let stream_id, ok_sid = quic_decode_varint_cursor(src, idx);
    guard ok_sid else { return QuicMaxStreamDataFrame { .. }, false; }

    let max_stream_data, ok_msd = quic_decode_varint_cursor(src, idx);
    guard ok_msd && max_stream_data <= QUIC_VARINT_MAX else {
        return QuicMaxStreamDataFrame { .. }, false;
    }

    return QuicMaxStreamDataFrame {
        stream_id:       stream_id,
        max_stream_data: max_stream_data,
    }, true;
}

// Decodes a NEW_CONNECTION_ID frame (0x18) directly from slice with cursor (RFC 9000 §19.15).
//
// Example:
//   src = [seq=1, retire=0, len=4, 1, 2, 3, 4, ...16 token bytes...], idx = 0
//   returns: QuicFrame { frame_type: NewConnectionId, stream_id: 1, offset: 0, length: 4 }, ok = true
//
// crap:trusted-bounds
inline fn decode_new_conn_id_frame(src: const u8[:], idx: i64&) -> QuicFrame, bool {
    let seq, ok_seq = quic_decode_varint_cursor(src, idx);
    guard ok_seq else { return QuicFrame { .. }, false; }
    let retire_prior, ok_ret = quic_decode_varint_cursor(src, idx);
    guard ok_ret && retire_prior <= seq else { return QuicFrame { .. }, false; }
    guard idx < src.len else { return QuicFrame { .. }, false; }
    let cid_len = src[idx] as i64;
    idx += 1;
    guard cid_len >= 1 && cid_len <= 20 else { return QuicFrame { .. }, false; }
    guard idx + cid_len + 16 <= src.len else { return QuicFrame { .. }, false; }
    let payload = src[idx..idx + cid_len + 16];
    idx += cid_len + 16;
    return QuicFrame {
        frame_type: QuicFrameType.NewConnectionId,
        raw_type:   QUIC_FRAME_NEW_CONNECTION_ID,
        stream_id:  seq,
        offset:     retire_prior,
        length:     cid_len as u64,
        payload:    payload,
    }, true;
}

// Decodes a RETIRE_CONNECTION_ID frame (0x19) directly from slice with cursor (RFC 9000 §19.16).
//
// Example:
//   src = [seq=2], idx = 0
//   returns: QuicFrame { frame_type: RetireConnectionId, stream_id: 2 }, ok = true
inline fn decode_retire_conn_id_frame(src: const u8[:], idx: i64&) -> QuicFrame, bool {
    let seq, ok_seq = quic_decode_varint_cursor(src, idx);
    guard ok_seq else { return QuicFrame { .. }, false; }
    return QuicFrame {
        frame_type: QuicFrameType.RetireConnectionId,
        raw_type:   QUIC_FRAME_RETIRE_CONNECTION_ID,
        stream_id:  seq,
    }, true;
}

// Decodes a DATAGRAM frame (0x30 / 0x31) directly from slice with cursor (RFC 9221 §3).
//
// Example:
//   src = [0x04, 't', 'e', 's', 't'], idx = 0, ftype = 0x31
//   returns: QuicFrame { frame_type: Datagram, length: 4, payload: "test" }, ok = true, idx = 5
//
// crap:trusted-bounds
inline fn decode_datagram_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_DATAGRAM {
        let payload = src[idx..src.len];
        idx = src.len;
        return QuicFrame {
            frame_type: QuicFrameType.Datagram,
            raw_type:   ftype,
            length:     payload.len as u64,
            payload:    payload,
        }, true;
    }
    let dlen, ok = quic_decode_varint_cursor(src, idx);
    guard ok else { return QuicFrame { .. }, false; }
    let ilen = dlen as i64;
    guard idx + ilen <= src.len else { return QuicFrame { .. }, false; }
    let payload = src[idx..idx + ilen];
    idx += ilen;
    return QuicFrame {
        frame_type: QuicFrameType.Datagram,
        raw_type:   ftype,
        length:     dlen,
        payload:    payload,
    }, true;
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - 8-byte payload decoding
// Decodes a PATH_CHALLENGE frame payload (8 bytes) directly from slice with cursor.
//
// Example:
//   src = [1, 2, 3, 4, 5, 6, 7, 8], idx = 0
//   returns: QuicPathFrame { data: [1, 2, 3, 4, 5, 6, 7, 8] }, ok = true, idx = 8
//
// crap:trusted-bounds
inline fn decode_path_challenge_frame(src: const u8[:], idx: i64&) -> QuicPathFrame, bool {
    guard idx + 8 <= src.len else { return QuicPathFrame { .. }, false; }
    var frame = QuicPathFrame { .. };
    for i in 8 {
        frame.data[i] = src[idx + i];
    }
    idx += 8;
    return frame, true;
}

// RFC 9000 Section 19.18: PATH_RESPONSE Frames - 8-byte payload decoding
// Decodes a PATH_RESPONSE frame payload (8 bytes) directly from slice with cursor.
//
// Example:
//   src = [1, 2, 3, 4, 5, 6, 7, 8], idx = 0
//   returns: QuicPathFrame { data: [1, 2, 3, 4, 5, 6, 7, 8] }, ok = true, idx = 8
//
// crap:trusted-bounds
inline fn decode_path_response_frame(src: const u8[:], idx: i64&) -> QuicPathFrame, bool {
    guard idx + 8 <= src.len else { return QuicPathFrame { .. }, false; }
    var frame = QuicPathFrame { .. };
    for i in 8 {
        frame.data[i] = src[idx + i];
    }
    idx += 8;
    return frame, true;
}

// ---- Frame Demuxer Dispatch Subroutines ----------------------------------

// Demuxes MAX_DATA (0x10) or MAX_STREAM_DATA (0x11) frame.
//
// Example:
//   src = [max_data=1048576], idx = 0, ftype = 0x10
//   returns: QuicFrame { frame_type: MaxData, max_data: 1048576 }, ok = true
inline fn demux_flow_limit_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_MAX_DATA {
        let md, ok = decode_max_data_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.MaxData,
            raw_type:   ftype,
            max_data:   md.max_data,
        }, true;
    }
    let msd, ok = decode_max_stream_data_frame(src, idx);
    guard ok else { return QuicFrame { .. }, false; }
    return QuicFrame {
        frame_type: QuicFrameType.MaxStreamData,
        raw_type:   ftype,
        stream_id:  msd.stream_id,
        max_data:   msd.max_stream_data,
    }, true;
}

// Demuxes RESET_STREAM (0x04) or STOP_SENDING (0x05) frame.
//
// Example:
//   src = [stream_id=4, error_code=0x10c, final_size=1024], idx = 0, ftype = 0x04
//   returns: QuicFrame { frame_type: ResetStream, stream_id: 4, final_size: 1024 }, ok = true
inline fn demux_stream_control_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_RESET_STREAM {
        let rst, ok = decode_reset_stream_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.ResetStream,
            raw_type:   ftype,
            stream_id:  rst.stream_id,
            error_code: rst.error_code,
            final_size: rst.final_size,
        }, true;
    }
    let ss, ok = decode_stop_sending_frame(src, idx);
    guard ok else { return QuicFrame { .. }, false; }
    return QuicFrame {
        frame_type: QuicFrameType.StopSending,
        raw_type:   ftype,
        stream_id:  ss.stream_id,
        error_code: ss.error_code,
    }, true;
}

// Dispatches core QUIC frame types (0x00 - 0x11) directly from slice with cursor.
//
// Example:
//   src = [0x00, ...], idx = 0, ftype = QUIC_FRAME_PING (0x01)
//   returns: QuicFrame { frame_type: Ping, raw_type: 0x01 }, ok = true
fn demux_core_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_PADDING {
        return QuicFrame {
            frame_type: QuicFrameType.Padding,
            raw_type:   QUIC_FRAME_PADDING,
            length:     1,
        }, true;
    }
    if ftype == QUIC_FRAME_PING {
        return QuicFrame {
            frame_type: QuicFrameType.Ping,
            raw_type:   QUIC_FRAME_PING,
        }, true;
    }
    if ftype == QUIC_FRAME_ACK || ftype == QUIC_FRAME_ACK_ECN {
        return decode_ack_frame_cursor(src, idx, ftype == QUIC_FRAME_ACK_ECN);
    }
    if ftype == QUIC_FRAME_RESET_STREAM || ftype == QUIC_FRAME_STOP_SENDING {
        return demux_stream_control_frame(src, idx, ftype);
    }
    if ftype == QUIC_FRAME_CRYPTO {
        let cr, ok = decode_crypto_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.Crypto,
            raw_type:   ftype,
            offset:     cr.offset,
            length:     cr.data.len as u64,
            payload:    cr.data,
        }, true;
    }
    if ftype == QUIC_FRAME_NEW_TOKEN {
        return decode_new_token_frame(src, idx);
    }
    if ftype >= QUIC_FRAME_STREAM_BASE && ftype <= QUIC_STREAM_MAX_TYPE {
        let st, ok = decode_stream_frame(src, idx, ftype);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.Stream,
            raw_type:   ftype,
            stream_id:  st.stream_id,
            offset:     st.offset,
            length:     st.data.len as u64,
            fin:        st.fin,
            payload:    st.data,
        }, true;
    }
    if ftype == QUIC_FRAME_MAX_DATA || ftype == QUIC_FRAME_MAX_STREAM_DATA {
        return demux_flow_limit_frame(src, idx, ftype);
    }
    return QuicFrame { .. }, false;
}

// Dispatches stream count limit frames (0x12, 0x13, 0x16, 0x17).
// Limits cannot exceed 2^60 (RFC 9000 §19.11, §19.14).
//
// Example:
//   src = [varint(100)], idx = 0, ftype = QUIC_FRAME_MAX_STREAMS_BIDI (0x12)
//   returns: QuicFrame { frame_type: MaxStreamsBidi, max_data: 100 }, ok = true
fn demux_streams_limit_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_MAX_STREAMS_BIDI || ftype == QUIC_FRAME_MAX_STREAMS_UNI {
        let limit, ok = quic_decode_varint_cursor(src, idx);
        guard ok && limit <= QUIC_MAX_STREAMS_LIMIT else { return QuicFrame { .. }, false; }
        let k = if ftype == QUIC_FRAME_MAX_STREAMS_BIDI {
            QuicFrameType.MaxStreamsBidi
        } else {
            QuicFrameType.MaxStreamsUni
        };
        return QuicFrame { frame_type: k, raw_type: ftype, max_data: limit }, true;
    }
    if ftype == QUIC_FRAME_STREAMS_BLOCKED_BIDI || ftype == QUIC_FRAME_STREAMS_BLOCKED_UNI {
        let lim, ok = quic_decode_varint_cursor(src, idx);
        guard ok && lim <= QUIC_MAX_STREAMS_LIMIT else { return QuicFrame { .. }, false; }
        let k = if ftype == QUIC_FRAME_STREAMS_BLOCKED_BIDI {
            QuicFrameType.StreamsBlockedBidi
        } else {
            QuicFrameType.StreamsBlockedUni
        };
        return QuicFrame { frame_type: k, raw_type: ftype, max_data: lim }, true;
    }
    return QuicFrame { .. }, false;
}

// Dispatches data blocked frames (0x14, 0x15).
//
// Example:
//   src = [varint(5000)], idx = 0, ftype = QUIC_FRAME_DATA_BLOCKED (0x14)
//   returns: QuicFrame { frame_type: DataBlocked, max_data: 5000 }, ok = true
fn demux_blocked_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_DATA_BLOCKED {
        let limit, ok = quic_decode_varint_cursor(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame { frame_type: QuicFrameType.DataBlocked, raw_type: ftype, max_data: limit }, true;
    }
    if ftype == QUIC_FRAME_STREAM_DATA_BLOCKED {
        let sid, ok_sid = quic_decode_varint_cursor(src, idx);
        let lim, ok_lim = quic_decode_varint_cursor(src, idx);
        guard ok_sid && ok_lim else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.StreamDataBlocked,
            raw_type:   ftype,
            stream_id:  sid,
            max_data:   lim,
        }, true;
    }
    return QuicFrame { .. }, false;
}

// Decodes a CONNECTION_CLOSE frame (0x1C or 0x1D) directly from slice with cursor (RFC 9000 §19.19).
//
// Example:
//   src = [0x00, 0x00, 0x02, 'b', 'y', 'e'], idx = 0, ftype = 0x1C
//   returns: QuicFrame { frame_type: ConnectionClose, error_code: 0, payload: "bye" }, ok = true
//
// crap:trusted-bounds
inline fn decode_connection_close_frame(
    src:   const u8[:],
    idx:   i64&,
    ftype: u64,
) -> QuicFrame, bool {
    let err, ok_err = quic_decode_varint_cursor(src, idx);
    guard ok_err else { return QuicFrame { .. }, false; }
    var trigger_type: u64 = 0;
    if ftype == QUIC_FRAME_CONNECTION_CLOSE {
        let trg, ok_trg = quic_decode_varint_cursor(src, idx);
        guard ok_trg else { return QuicFrame { .. }, false; }
        trigger_type = trg;
    }
    let rlen, ok_rlen = quic_decode_varint_cursor(src, idx);
    guard ok_rlen else { return QuicFrame { .. }, false; }
    let ilen = rlen as i64;
    guard idx + ilen <= src.len else { return QuicFrame { .. }, false; }
    let reason = src[idx..idx + ilen];
    idx += ilen;
    let k = if ftype == QUIC_FRAME_CONNECTION_CLOSE {
        QuicFrameType.ConnectionClose
    } else {
        QuicFrameType.ConnectionCloseApp
    };
    return QuicFrame {
        frame_type: k,
        raw_type:   ftype,
        error_code: err,
        offset:     trigger_type,
        length:     rlen,
        payload:    reason,
    }, true;
}

// Decodes a PATH_CHALLENGE (0x1A) or PATH_RESPONSE (0x1B) frame into QuicFrame.
//
// Example:
//   src = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], idx = 0, ftype = 0x1A
//   returns: QuicFrame { length: 8 }, ok = true, idx = 8
inline fn demux_path_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    let cur = idx;
    let end = cur + 8;
    guard src.len >= end else { return QuicFrame { .. }, false; }
    idx = end;
    let k = if ftype == QUIC_FRAME_PATH_CHALLENGE { QuicFrameType.PathChallenge } else { QuicFrameType.PathResponse };
    return QuicFrame {
        frame_type: k,
        raw_type:   ftype,
        length:     8,
        payload:    src[cur..end],
    }, true;
}

// Dispatches connection management frames (0x1A - 0x1E).
//
// Example:
//   src = [], idx = 0, ftype = QUIC_FRAME_HANDSHAKE_DONE (0x1E)
//   returns: QuicFrame { frame_type: HandshakeDone, raw_type: 0x1E }, ok = true
fn demux_session_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_HANDSHAKE_DONE {
        return QuicFrame { frame_type: QuicFrameType.HandshakeDone, raw_type: ftype }, true;
    }
    if ftype == QUIC_FRAME_PATH_CHALLENGE || ftype == QUIC_FRAME_PATH_RESPONSE {
        return demux_path_frame(src, idx, ftype);
    }
    if ftype == QUIC_FRAME_NEW_CONNECTION_ID {
        return decode_new_conn_id_frame(src, idx);
    }
    if ftype == QUIC_FRAME_RETIRE_CONNECTION_ID {
        return decode_retire_conn_id_frame(src, idx);
    }
    if ftype == QUIC_FRAME_CONNECTION_CLOSE || ftype == QUIC_FRAME_CONNECTION_CLOSE_APP {
        return decode_connection_close_frame(src, idx, ftype);
    }
    return QuicFrame { .. }, false;
}

// ---- Zero-Allocation Frame Demuxer API -----------------------------------

// Decodes a single QUIC frame directly from slice with cursor (RFC 9000 §19).
// Advances `idx` past the decoded frame on success.
// On failure (`ok = false`), `idx` is restored to its original value.
//
// Example:
//   src = [0x01, 0x06, 0x00, 0x02, 'o', 'k'], idx = 0
//   returns: QuicFrame { frame_type: Ping }, ok = true, idx = 1
fn decode_quic_frame_cursor(src: const u8[:], idx: i64&) -> QuicFrame, bool {
    let initial_idx = idx;
    guard idx < src.len else { return QuicFrame { .. }, false; }

    let ftype, ok_type = quic_decode_varint_cursor(src, idx);
    guard ok_type else {
        idx = initial_idx;
        return QuicFrame { .. }, false;
    }

    var frame: QuicFrame = QuicFrame { .. };
    var ok:    bool      = false;

    if ftype <= 0x11 {
        frame, ok = demux_core_frame(src, idx, ftype);
    } else if ftype == QUIC_FRAME_MAX_STREAMS_BIDI || ftype == QUIC_FRAME_MAX_STREAMS_UNI ||
       ftype == QUIC_FRAME_STREAMS_BLOCKED_BIDI || ftype == QUIC_FRAME_STREAMS_BLOCKED_UNI {
        frame, ok = demux_streams_limit_frame(src, idx, ftype);
    } else if ftype == QUIC_FRAME_DATA_BLOCKED || ftype == QUIC_FRAME_STREAM_DATA_BLOCKED {
        frame, ok = demux_blocked_frame(src, idx, ftype);
    } else if ftype <= 0x1E {
        frame, ok = demux_session_frame(src, idx, ftype);
    } else if ftype == QUIC_FRAME_DATAGRAM || ftype == QUIC_FRAME_DATAGRAM_LEN {
        frame, ok = decode_datagram_frame(src, idx, ftype);
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
fn decode_quic_frame(src: const u8[:], offset: u64) -> QuicFrame, u64, bool {
    guard offset < (src.len as u64) else {
        return QuicFrame { .. }, offset, false;
    }
    var idx = offset as i64;
    let frame, ok = decode_quic_frame_cursor(src, idx);
    guard ok else { return frame, offset, false; }
    return frame, idx as u64, true;
}
