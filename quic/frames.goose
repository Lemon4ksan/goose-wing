// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Transport Frames Codec, Demuxer & RFC 9000 Section 19 Frame Types.
// Implements zero-allocation parsing and serialization for STREAM, CRYPTO,
// RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, PING, and PADDING.
namespace wing;

import std;
import core from "..";
import .packet;

// ---- 1. Frame Constants & Stream Flags (RFC 9000 Section 19) ----------------

const QUIC_VARINT_MAX: u64 = 0x3FFFFFFFFFFFFFFF;

const QUIC_STREAM_FLAG_FIN: u64 = 0x01;
const QUIC_STREAM_FLAG_LEN: u64 = 0x02;
const QUIC_STREAM_FLAG_OFF: u64 = 0x04;
const QUIC_STREAM_MAX_TYPE: u64 = 0x0F;

// ---- 2. Frame Type Enum and Unified Zero-Alloc Frame Model -----------------

enum QuicFrameType {
    Padding,
    Ping,
    ResetStream,
    StopSending,
    Crypto,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreamsBidi,
    MaxStreamsUni,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlockedBidi,
    StreamsBlockedUni,
    PathChallenge,
    PathResponse,
    HandshakeDone,
    ConnectionClose,
    ConnectionCloseApp,
    Unknown,
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - 8-byte payload structure
// RFC 9000 Section 19.18: PATH_RESPONSE Frames - 8-byte payload structure
struct QuicPathFrame {
    data: u8[8] = [0; 8],
}

struct QuicStreamFrame {
    stream_id: u64 = 0,
    offset: u64 = 0,
    fin: bool = false,
    data: const u8[:] = "",
}

struct QuicStreamFlags {
    fin: bool = false,
    with_len: bool = true,
    with_offset: bool = false,
}

struct QuicCryptoFrame {
    offset: u64 = 0,
    data: const u8[:] = "",
}

struct QuicResetStreamFrame {
    stream_id: u64 = 0,
    error_code: u64 = 0,
    final_size: u64 = 0,
}

struct QuicStopSendingFrame {
    stream_id: u64 = 0,
    error_code: u64 = 0,
}

struct QuicMaxDataFrame {
    max_data: u64 = 0,
}

struct QuicMaxStreamDataFrame {
    stream_id: u64 = 0,
    max_stream_data: u64 = 0,
}

struct QuicFrame {
    frame_type: QuicFrameType = QuicFrameType.Unknown,
    raw_type: u64 = 0,
    stream_id: u64 = 0,
    offset: u64 = 0,
    length: u64 = 0,
    error_code: u64 = 0,
    final_size: u64 = 0,
    max_data: u64 = 0,
    fin: bool = false,
    payload: const u8[:] = "",
}

// ---- 3. Helper Invariant Checkers (RFC 9000 Range Validation) ---------------

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

// ---- 4. Dedicated Frame Encoders (RFC 9000 Section 19) ----------------------

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
    out: B&,
    stream_id: u64,
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
    out: B&,
    stream_id: u64,
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
    out: B&,
    offset: u64,
    data: const u8[:],
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
    out: B&,
    stream_id: u64,
    offset: u64,
    data: const u8[:],
    flags: QuicStreamFlags,
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
    out: B&,
    stream_id: u64,
    offset: u64,
    data: const u8[:],
    flags: QuicStreamFlags = QuicStreamFlags { .. },
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
    out: B&,
    stream_id: u64,
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
    guard max_streams <= QUIC_VARINT_MAX else { return false; }
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
    guard stream_limit <= QUIC_VARINT_MAX else { return false; }
    let ftype = if is_bidi { QUIC_FRAME_STREAMS_BLOCKED_BIDI } else { QUIC_FRAME_STREAMS_BLOCKED_UNI };
    guard quic_encode_varint(out, ftype) else { return false; }
    guard quic_encode_varint(out, stream_limit) else { return false; }
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
    out: B&,
    error_code: u64,
    frame_type: u64,
    reason: const u8[:],
    is_app: bool = false,
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

// ---- 5. Dedicated Frame Decoders (RFC 9000 Section 19) ----------------------

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
        stream_id: stream_id,
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
        stream_id: stream_id,
        error_code: error_code,
    }, true;
}

// Decodes a CRYPTO frame (0x06) directly from slice with cursor (RFC 9000 Section 19.6).
// Assumes the frame type varint (0x06) has already been consumed.
//
// Example:
//   src = [0x00, 0x04, 't', 'e', 's', 't'], idx = 0
//   returns: QuicCryptoFrame { offset: 0, data: "test" }, ok = true, idx = 6
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
        data: payload,
    }, true;
}

// Decodes a STREAM frame (0x08-0x0F) directly from slice with cursor (RFC 9000 Section 19.8).
// Flags encoded in `ftype`: 0x04 = OFF, 0x02 = LEN, 0x01 = FIN.
// If LEN (0x02) is unset, consumes all remaining bytes in `src`.
//
// Example:
//   src = [0x04, 0x00, 0x02, 'o', 'k'], idx = 0, ftype = 0x0f (OFF|LEN|FIN)
//   returns: QuicStreamFrame { stream_id: 4, offset: 0, fin: true, data: "ok" }, ok = true, idx = 5
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
        offset: offset,
        fin: has_fin,
        data: payload,
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
        stream_id: stream_id,
        max_stream_data: max_stream_data,
    }, true;
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - 8-byte payload decoding
// Decodes a PATH_CHALLENGE frame payload (8 bytes) directly from slice with cursor.
//
// Example:
//   src = [1, 2, 3, 4, 5, 6, 7, 8], idx = 0
//   returns: QuicPathFrame { data: [1, 2, 3, 4, 5, 6, 7, 8] }, ok = true, idx = 8
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
inline fn decode_path_response_frame(src: const u8[:], idx: i64&) -> QuicPathFrame, bool {
    guard idx + 8 <= src.len else { return QuicPathFrame { .. }, false; }
    var frame = QuicPathFrame { .. };
    for i in 8 {
        frame.data[i] = src[idx + i];
    }
    idx += 8;
    return frame, true;
}

// ---- 6. Frame Demuxer Dispatch Subroutines ----------------------------------

// Dispatches core QUIC frame types (0x00 - 0x11) directly from slice with cursor.
//
// Example:
//   src = [0x00, ...], idx = 0, ftype = QUIC_FRAME_PING (0x01)
//   returns: QuicFrame { frame_type: Ping, raw_type: 0x01 }, ok = true
fn demux_core_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_PADDING {
        return QuicFrame {
            frame_type: QuicFrameType.Padding,
            raw_type: QUIC_FRAME_PADDING,
            length: 1,
        }, true;
    }
    if ftype == QUIC_FRAME_PING {
        return QuicFrame {
            frame_type: QuicFrameType.Ping,
            raw_type: QUIC_FRAME_PING,
        }, true;
    }
    if ftype == QUIC_FRAME_RESET_STREAM {
        let rst, ok = decode_reset_stream_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.ResetStream,
            raw_type: ftype,
            stream_id: rst.stream_id,
            error_code: rst.error_code,
            final_size: rst.final_size,
        }, true;
    }
    if ftype == QUIC_FRAME_STOP_SENDING {
        let ss, ok = decode_stop_sending_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.StopSending,
            raw_type: ftype,
            stream_id: ss.stream_id,
            error_code: ss.error_code,
        }, true;
    }
    if ftype == QUIC_FRAME_CRYPTO {
        let cr, ok = decode_crypto_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.Crypto,
            raw_type: ftype,
            offset: cr.offset,
            length: cr.data.len as u64,
            payload: cr.data,
        }, true;
    }
    if ftype >= QUIC_FRAME_STREAM_BASE && ftype <= QUIC_STREAM_MAX_TYPE {
        let st, ok = decode_stream_frame(src, idx, ftype);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.Stream,
            raw_type: ftype,
            stream_id: st.stream_id,
            offset: st.offset,
            length: st.data.len as u64,
            fin: st.fin,
            payload: st.data,
        }, true;
    }
    if ftype == QUIC_FRAME_MAX_DATA {
        let md, ok = decode_max_data_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.MaxData,
            raw_type: ftype,
            max_data: md.max_data,
        }, true;
    }
    if ftype == QUIC_FRAME_MAX_STREAM_DATA {
        let msd, ok = decode_max_stream_data_frame(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        return QuicFrame {
            frame_type: QuicFrameType.MaxStreamData,
            raw_type: ftype,
            stream_id: msd.stream_id,
            max_data: msd.max_stream_data,
        }, true;
    }
    return QuicFrame { .. }, false;
}

// Dispatches stream count limit frames (0x12, 0x13, 0x16, 0x17).
//
// Example:
//   src = [varint(100)], idx = 0, ftype = QUIC_FRAME_MAX_STREAMS_BIDI (0x12)
//   returns: QuicFrame { frame_type: MaxStreamsBidi, max_data: 100 }, ok = true
fn demux_streams_limit_frame(src: const u8[:], idx: i64&, ftype: u64) -> QuicFrame, bool {
    if ftype == QUIC_FRAME_MAX_STREAMS_BIDI || ftype == QUIC_FRAME_MAX_STREAMS_UNI {
        let limit, ok = quic_decode_varint_cursor(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
        let k = if ftype == QUIC_FRAME_MAX_STREAMS_BIDI {
            QuicFrameType.MaxStreamsBidi
        } else {
            QuicFrameType.MaxStreamsUni
        };
        return QuicFrame { frame_type: k, raw_type: ftype, max_data: limit }, true;
    }
    if ftype == QUIC_FRAME_STREAMS_BLOCKED_BIDI || ftype == QUIC_FRAME_STREAMS_BLOCKED_UNI {
        let lim, ok = quic_decode_varint_cursor(src, idx);
        guard ok else { return QuicFrame { .. }, false; }
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
            raw_type: ftype,
            stream_id: sid,
            max_data: lim,
        }, true;
    }
    return QuicFrame { .. }, false;
}

// Decodes a CONNECTION_CLOSE frame (0x1C or 0x1D) directly from slice with cursor (RFC 9000 §19.19).
//
// Example:
//   src = [0x00, 0x00, 0x02, 'b', 'y', 'e'], idx = 0, ftype = 0x1C
//   returns: QuicFrame { frame_type: ConnectionClose, error_code: 0, payload: "bye" }, ok = true
inline fn decode_connection_close_frame(
    src: const u8[:],
    idx: i64&,
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
        raw_type: ftype,
        error_code: err,
        offset: trigger_type,
        length: rlen,
        payload: reason,
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
        raw_type: ftype,
        length: 8,
        payload: src[cur..end],
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
    if ftype == QUIC_FRAME_CONNECTION_CLOSE || ftype == QUIC_FRAME_CONNECTION_CLOSE_APP {
        return decode_connection_close_frame(src, idx, ftype);
    }
    return QuicFrame { .. }, false;
}

// ---- 7. Zero-Allocation Frame Demuxer API -----------------------------------

// Decodes a single QUIC frame directly from slice with cursor (RFC 9000 §19).
// Advances `idx` past the decoded frame on success.
//
// Example:
//   src = [0x01, 0x06, 0x00, 0x02, 'o', 'k'], idx = 0
//   returns: QuicFrame { frame_type: Ping }, ok = true, idx = 1
fn decode_quic_frame_cursor(src: const u8[:], idx: i64&) -> QuicFrame, bool {
    guard idx < src.len else { return QuicFrame { .. }, false; }

    let ftype, ok_type = quic_decode_varint_cursor(src, idx);
    guard ok_type else { return QuicFrame { .. }, false; }

    if ftype <= 0x11 {
        return demux_core_frame(src, idx, ftype);
    }
    if ftype == QUIC_FRAME_MAX_STREAMS_BIDI || ftype == QUIC_FRAME_MAX_STREAMS_UNI ||
       ftype == QUIC_FRAME_STREAMS_BLOCKED_BIDI || ftype == QUIC_FRAME_STREAMS_BLOCKED_UNI {
        return demux_streams_limit_frame(src, idx, ftype);
    }
    if ftype == QUIC_FRAME_DATA_BLOCKED || ftype == QUIC_FRAME_STREAM_DATA_BLOCKED {
        return demux_blocked_frame(src, idx, ftype);
    }
    if ftype <= 0x1E {
        return demux_session_frame(src, idx, ftype);
    }
    return QuicFrame { raw_type: ftype, frame_type: QuicFrameType.Unknown }, false;
}

// Decodes a single QUIC frame from SliceReader (RFC 9000 §19).
// Advances cursor past the decoded frame on success.
//
// Example:
//   r = [0x01, 0x06, 0x00, 0x02, 'o', 'k'], cursor = 0
//   returns: QuicFrame { frame_type: Ping }, ok = true, cursor = 1
fn decode_quic_frame_reader(r: core::SliceReader&) -> QuicFrame, bool {
    return decode_quic_frame_cursor(r.data, r.cursor);
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
