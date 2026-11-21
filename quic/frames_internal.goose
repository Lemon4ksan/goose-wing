// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QUIC frame sub-decoders, demuxers, and transport parameter helpers.
namespace quic_internal;

import std;
import core;
import .packet;
import .frames;

// ---- Helper Invariant Checkers (RFC 9000 Range Validation) ---------------

// Validates that offset and length are valid 62-bit VarInts and sum <= 2^62 - 1.
inline fn quic_valid_offset_len(offset: u64, len: u64) -> bool {
    if offset > rfc::QUIC_VARINT_MAX { return false; }
    if len > rfc::QUIC_VARINT_MAX { return false; }
    let rem = rfc::QUIC_VARINT_MAX - offset;
    return rem >= len;
}

// Builds the STREAM frame type byte (0x08 - 0x0F) based on flags (RFC 9000 §19.8).
//
// Example:
//   flags = QuicStreamFlags { fin: false, with_len: true, with_offset: true }
//   returns: 0x0E (QUIC_FRAME_STREAM_BASE | LEN | OFF)
inline fn build_stream_frame_type(flags: quic::QuicStreamFlags) -> u64 {
    var t: u64 = rfc::QUIC_FRAME_STREAM_BASE;
    if flags.with_offset { t = t | rfc::QUIC_STREAM_FLAG_OFF; }
    if flags.with_len { t = t | rfc::QUIC_STREAM_FLAG_LEN; }
    if flags.fin { t = t | rfc::QUIC_STREAM_FLAG_FIN; }
    return t;
}

// Encodes a STREAM frame with explicit OFF/LEN flags (RFC 9000 Section 19.8).
fn encode_stream_frame_explicit<B>(
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    flags:     quic::QuicStreamFlags,
    out:       B&,
) -> bool {
    guard stream_id <= rfc::QUIC_VARINT_MAX else { return false; }
    guard quic_valid_offset_len(offset, data.len as u64) else { return false; }
    guard offset == 0 || flags.with_offset else { return false; }

    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len, 0); };

    let ftype = build_stream_frame_type(flags);
    guard quic::encode_varint(ftype, out) && quic::encode_varint(stream_id, out) else {
        return false;
    }
    if flags.with_offset {
        guard quic::encode_varint(offset, out) else { return false; }
    }
    if flags.with_len {
        guard quic::encode_varint(data.len as u64, out) else { return false; }
    }
    guard out.try_append(data) else { return false; }
    committed = true;
    return true;
}

// ---- Dedicated Frame Sub-Decoders (RFC 9000 Section 19) ------------------

// Decodes ACK frame range intervals, ensuring monotonically descending bounds (RFC 9000 §19.3.1).
// Restores `idx` on failure (`false`).
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
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    var cur_smallest = largest_acked - first_range;
    var r_idx: u64 = 0;
    while r_idx < range_cnt {
        let gap, ok_g = quic::decode_varint_cursor(src, idx);
        guard ok_g else { return false; }
        let rlen, ok_r = quic::decode_varint_cursor(src, idx);
        guard ok_r else { return false; }

        guard cur_smallest >= 2 && (cur_smallest - 2) >= gap else { return false; }
        let cur_largest = cur_smallest - gap - 2;
        guard cur_largest >= rlen else { return false; }
        cur_smallest = cur_largest - rlen;
        r_idx++;
    }
    committed = true;
    return true;
}

// Decodes ACK ECN counters (ECT0, ECT1, ECN-CE) directly from slice with cursor (RFC 9000 §19.3.2).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [ect0=0, ect1=0, ce=0], idx = 0
//   returns: ok = true, idx = 3
inline fn decode_ack_ecn_counts(src: const u8[:], idx: i64&) -> bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let _, ok_e0 = quic::decode_varint_cursor(src, idx);
    guard ok_e0 else { return false; }
    let _, ok_e1 = quic::decode_varint_cursor(src, idx);
    guard ok_e1 else { return false; }
    let _, ok_ce = quic::decode_varint_cursor(src, idx);
    guard ok_ce else { return false; }
    committed = true;
    return true;
}

// Decodes an ACK (0x02) or ACK_ECN (0x03) frame directly from slice with cursor (RFC 9000 §19.3).
// Assumes the frame type varint has already been consumed; restores `idx` on failure (`false`).
//
// Example:
//   src = [largest_acked=10, delay=0, range_count=0, first_range=5], idx = 0, is_ecn = false
//   returns: QuicFrame { frame_type: Ack, offset: 10, length: 5 }, ok = true
fn decode_ack_frame_cursor(
    src:         const u8[:],
    idx:         i64&,
    is_ecn:      bool,
    frame_start: i64 = 0,
) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let largest_acked, ok_la = quic::decode_varint_cursor(src, idx);
    guard ok_la else { return quic::QuicFrame { .. }, false; }

    let ack_delay, ok_ad = quic::decode_varint_cursor(src, idx);
    guard ok_ad else { return quic::QuicFrame { .. }, false; }

    let range_cnt, ok_rc = quic::decode_varint_cursor(src, idx);
    guard ok_rc else { return quic::QuicFrame { .. }, false; }

    let first_range, ok_fr = quic::decode_varint_cursor(src, idx);
    guard ok_fr && largest_acked >= first_range else { return quic::QuicFrame { .. }, false; }

    guard decode_ack_ranges(src, idx, range_cnt, largest_acked, first_range) else {
        return quic::QuicFrame { .. }, false;
    }

    if is_ecn {
        guard decode_ack_ecn_counts(src, idx) else { return quic::QuicFrame { .. }, false; }
    }

    let k = if is_ecn { quic::QuicFrameType.AckEcn } else { quic::QuicFrameType.Ack };
    let raw = if is_ecn { rfc::QUIC_FRAME_ACK_ECN } else { rfc::QUIC_FRAME_ACK };
    let payload_slice = if frame_start >= 0 && frame_start <= idx { src[frame_start..idx] } else { src[..0] };
    committed = true;
    return quic::QuicFrame {
        frame_type: k,
        raw_type:   raw,
        offset:     largest_acked,
        length:     first_range,
        max_data:   ack_delay,
        payload:    payload_slice,
    }, true;
}

// Decodes a NEW_TOKEN frame (0x07) directly from slice with cursor (RFC 9000 §19.7).
// The Token field MUST NOT be empty; empty token yields false (FRAME_ENCODING_ERROR).
//
// Example:
//   src = [0x04, 't', 'o', 'k', 'n'], idx = 0
//   returns: QuicFrame { frame_type: NewToken, length: 4, payload: "tokn" }, ok = true, idx = 5
inline fn decode_new_token_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let tlen, ok_len = quic::decode_varint_cursor(src, idx);
    guard ok_len && tlen > 0 else { return quic::QuicFrame { .. }, false; }
    let ilen = tlen as i64;
    guard ilen >= 0 && ilen <= src.len - idx else { return quic::QuicFrame { .. }, false; }
    let token = src[idx..idx + ilen];
    idx += ilen;
    committed = true;
    return quic::QuicFrame {
        frame_type: quic::QuicFrameType.NewToken,
        raw_type:   rfc::QUIC_FRAME_NEW_TOKEN,
        length:     tlen,
        payload:    token,
    }, true;
}

// Decodes a RESET_STREAM frame (0x04) directly from slice with cursor (RFC 9000 §19.4).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [stream_id=4, error_code=0x10c, final_size=1024], idx = 0
//   returns: QuicResetStreamFrame { stream_id: 4, error_code: 0x10c, final_size: 1024 }, ok = true
inline fn decode_reset_stream_frame(src: const u8[:], idx: i64&) -> quic::QuicResetStreamFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let stream_id, ok_sid = quic::decode_varint_cursor(src, idx);
    guard ok_sid else { return quic::QuicResetStreamFrame { .. }, false; }

    let error_code, ok_err = quic::decode_varint_cursor(src, idx);
    guard ok_err else { return quic::QuicResetStreamFrame { .. }, false; }

    let final_size, ok_fs = quic::decode_varint_cursor(src, idx);
    guard ok_fs else { return quic::QuicResetStreamFrame { .. }, false; }

    committed = true;
    return quic::QuicResetStreamFrame {
        stream_id:  stream_id,
        error_code: error_code,
        final_size: final_size,
    }, true;
}

// Decodes a STOP_SENDING frame (0x05) directly from slice with cursor (RFC 9000 §19.5).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [stream_id=4, error_code=0x10c], idx = 0
//   returns: QuicStopSendingFrame { stream_id: 4, error_code: 0x10c }, ok = true
inline fn decode_stop_sending_frame(src: const u8[:], idx: i64&) -> quic::QuicStopSendingFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let stream_id, ok_sid = quic::decode_varint_cursor(src, idx);
    guard ok_sid else { return quic::QuicStopSendingFrame { .. }, false; }

    let error_code, ok_err = quic::decode_varint_cursor(src, idx);
    guard ok_err else { return quic::QuicStopSendingFrame { .. }, false; }

    committed = true;
    return quic::QuicStopSendingFrame {
        stream_id:  stream_id,
        error_code: error_code,
    }, true;
}

// Decodes a CRYPTO frame (0x06) directly from slice with cursor (RFC 9000 Section 19.6).
// Assumes the frame type varint (0x06) has already been consumed; restores `idx` on failure (`false`).
//
// Example:
//   src = [0x00, 0x04, 't', 'e', 's', 't'], idx = 0
//   returns: QuicCryptoFrame { offset: 0, data: "test" }, ok = true, idx = 6
// crap:trusted
// crap:trusted-bounds
inline fn decode_crypto_frame(src: const u8[:], idx: i64&) -> quic::QuicCryptoFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let offset, ok_off = quic::decode_varint_cursor(src, idx);
    guard ok_off else { return quic::QuicCryptoFrame { .. }, false; }

    let data_len, ok_len = quic::decode_varint_cursor(src, idx);
    guard ok_len else { return quic::QuicCryptoFrame { .. }, false; }

    guard quic_valid_offset_len(offset, data_len) else {
        return quic::QuicCryptoFrame { .. }, false;
    }
    let dlen = data_len as i64;
    guard dlen >= 0 && dlen <= src.len - idx else {
        return quic::QuicCryptoFrame { .. }, false;
    }

    let payload = src[idx..idx + dlen];
    idx += dlen;
    committed = true;

    return quic::QuicCryptoFrame {
        offset: offset,
        data:   payload,
    }, true;
}

// Decodes a STREAM frame (0x08-0x0F) directly from slice with cursor (RFC 9000 Section 19.8).
// Flags encoded in `ftype`: 0x04 = OFF, 0x02 = LEN, 0x01 = FIN.
// If LEN (0x02) is unset, consumes all remaining bytes in `src`; restores `idx` on failure (`false`).
//
// Example:
//   src = [0x04, 0x00, 0x02, 'o', 'k'], idx = 0, ftype = 0x0f (OFF|LEN|FIN)
//   returns: QuicStreamFrame { stream_id: 4, offset: 0, fin: true, data: "ok" }, ok = true, idx = 5
//
// crap:trusted-bounds
fn decode_stream_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicStreamFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    guard ftype >= rfc::QUIC_FRAME_STREAM_BASE && ftype <= rfc::QUIC_STREAM_MAX_TYPE else {
        return quic::QuicStreamFrame { .. }, false;
    }
    let has_fin = (ftype & rfc::QUIC_STREAM_FLAG_FIN) != 0;
    let has_len = (ftype & rfc::QUIC_STREAM_FLAG_LEN) != 0;
    let has_off = (ftype & rfc::QUIC_STREAM_FLAG_OFF) != 0;

    let stream_id, ok_sid = quic::decode_varint_cursor(src, idx);
    guard ok_sid else { return quic::QuicStreamFrame { .. }, false; }

    var offset: u64 = 0;
    if has_off {
        let off_val, ok_off = quic::decode_varint_cursor(src, idx);
        guard ok_off else { return quic::QuicStreamFrame { .. }, false; }
        offset = off_val;
    }

    var data_len: u64 = 0;
    if has_len {
        let len_val, ok_len = quic::decode_varint_cursor(src, idx);
        guard ok_len else { return quic::QuicStreamFrame { .. }, false; }
        data_len = len_val;
    } else {
        let rem = src.len - idx;
        guard rem >= 0 else { return quic::QuicStreamFrame { .. }, false; }
        data_len = rem as u64;
    }

    guard quic_valid_offset_len(offset, data_len) else {
        return quic::QuicStreamFrame { .. }, false;
    }
    let dlen = data_len as i64;
    guard dlen >= 0 && dlen <= src.len - idx else {
        return quic::QuicStreamFrame { .. }, false;
    }

    let payload = src[idx..idx + dlen];
    idx += dlen;
    committed = true;

    return quic::QuicStreamFrame {
        stream_id: stream_id,
        offset:    offset,
        fin:       has_fin,
        data:      payload,
    }, true;
}

// Decodes a MAX_DATA frame (0x10) directly from slice with cursor (RFC 9000 §19.9).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [0x50, 0x00], idx = 0 (varint 4096)
//   returns: QuicMaxDataFrame { max_data: 4096 }, ok = true, idx = 2
inline fn decode_max_data_frame(src: const u8[:], idx: i64&) -> quic::QuicMaxDataFrame, bool {
    let saved_idx = idx;
    let max_data, ok = quic::decode_varint_cursor(src, idx);
    guard ok && max_data <= rfc::QUIC_VARINT_MAX else {
        idx = saved_idx;
        return quic::QuicMaxDataFrame { .. }, false;
    }
    return quic::QuicMaxDataFrame { max_data: max_data }, true;
}

// Decodes a MAX_STREAM_DATA frame (0x11) directly from slice with cursor (RFC 9000 §19.10).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [0x04, 0x50, 0x00], idx = 0 (stream_id = 4, max_stream_data = 4096)
//   returns: QuicMaxStreamDataFrame { stream_id: 4, max_stream_data: 4096 }, ok = true, idx = 3
inline fn decode_max_stream_data_frame(src: const u8[:], idx: i64&) -> quic::QuicMaxStreamDataFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let stream_id, ok_sid = quic::decode_varint_cursor(src, idx);
    guard ok_sid else { return quic::QuicMaxStreamDataFrame { .. }, false; }

    let max_stream_data, ok_msd = quic::decode_varint_cursor(src, idx);
    guard ok_msd && max_stream_data <= rfc::QUIC_VARINT_MAX else {
        return quic::QuicMaxStreamDataFrame { .. }, false;
    }

    committed = true;
    return quic::QuicMaxStreamDataFrame {
        stream_id:       stream_id,
        max_stream_data: max_stream_data,
    }, true;
}

// Decodes a NEW_CONNECTION_ID frame (0x18) directly from slice with cursor (RFC 9000 §19.15).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [seq=1, retire=0, len=4, 1, 2, 3, 4, ...16 token bytes...], idx = 0
//   returns: QuicFrame { frame_type: NewConnectionId, stream_id: 1, offset: 0, length: 4 }, ok = true
//
// crap:trusted-bounds
inline fn decode_new_conn_id_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let seq, ok_seq = quic::decode_varint_cursor(src, idx);
    guard ok_seq else { return quic::QuicFrame { .. }, false; }
    let retire_prior, ok_ret = quic::decode_varint_cursor(src, idx);
    guard ok_ret && retire_prior <= seq else { return quic::QuicFrame { .. }, false; }
    guard idx >= 0 && idx < src.len else { return quic::QuicFrame { .. }, false; }
    let cid_len = src[idx] as i64;
    idx += 1;
    guard cid_len >= 1 && cid_len <= 20 else { return quic::QuicFrame { .. }, false; }
    guard cid_len + 16 <= src.len - idx else { return quic::QuicFrame { .. }, false; }
    let payload = src[idx..idx + cid_len + 16];
    idx += cid_len + 16;
    committed = true;
    return quic::QuicFrame {
        frame_type: quic::QuicFrameType.NewConnectionId,
        raw_type:   rfc::QUIC_FRAME_NEW_CONNECTION_ID,
        stream_id:  seq,
        offset:     retire_prior,
        length:     cid_len as u64,
        payload:    payload,
    }, true;
}

// Decodes a RETIRE_CONNECTION_ID frame (0x19) directly from slice with cursor (RFC 9000 §19.16).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [seq=2], idx = 0
//   returns: QuicFrame { frame_type: RetireConnectionId, stream_id: 2 }, ok = true
inline fn decode_retire_conn_id_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    let seq, ok_seq = quic::decode_varint_cursor(src, idx);
    guard ok_seq else {
        idx = saved_idx;
        return quic::QuicFrame { .. }, false;
    }
    return quic::QuicFrame {
        frame_type: quic::QuicFrameType.RetireConnectionId,
        raw_type:   rfc::QUIC_FRAME_RETIRE_CONNECTION_ID,
        stream_id:  seq,
    }, true;
}

// Decodes a DATAGRAM frame (0x30 / 0x31) directly from slice with cursor (RFC 9221 §3).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [0x04, 't', 'e', 's', 't'], idx = 0, ftype = 0x31
//   returns: QuicFrame { frame_type: Datagram, length: 4, payload: "test" }, ok = true, idx = 5
//
// crap:trusted-bounds
inline fn demux_datagram_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    // RFC 9221 Section 4: Datagram Frame Types - Valid DATAGRAM frame types are 0x30 and 0x31.
    guard ftype == rfc::QUIC_FRAME_DATAGRAM || ftype == rfc::QUIC_FRAME_DATAGRAM_LEN else {
        return quic::QuicFrame { .. }, false;
    }
    guard idx >= 0 && idx <= src.len else { return quic::QuicFrame { .. }, false; }
    if ftype == rfc::QUIC_FRAME_DATAGRAM {
        let payload = src[idx..src.len];
        idx = src.len;
        committed = true;
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.Datagram,
            raw_type:   ftype,
            length:     payload.len as u64,
            payload:    payload,
        }, true;
    }
    let dlen, ok = quic::decode_varint_cursor(src, idx);
    guard ok else { return quic::QuicFrame { .. }, false; }
    let ilen = dlen as i64;
    guard ilen >= 0 && ilen <= src.len - idx else { return quic::QuicFrame { .. }, false; }
    let payload = src[idx..idx + ilen];
    idx += ilen;
    committed = true;
    return quic::QuicFrame {
        frame_type: quic::QuicFrameType.Datagram,
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
inline fn decode_path_challenge_frame(src: const u8[:], idx: i64&) -> quic::QuicPathFrame, bool {
    guard idx >= 0 && 8 <= src.len - idx else { return quic::QuicPathFrame { .. }, false; }
    var frame = quic::QuicPathFrame { .. };
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
inline fn decode_path_response_frame(src: const u8[:], idx: i64&) -> quic::QuicPathFrame, bool {
    guard idx >= 0 && 8 <= src.len - idx else { return quic::QuicPathFrame { .. }, false; }
    var frame = quic::QuicPathFrame { .. };
    for i in 8 {
        frame.data[i] = src[idx + i];
    }
    idx += 8;
    return frame, true;
}

// Decodes an ACK_FREQUENCY frame (0xAF) into QuicFrame using an in-out index cursor.
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [0x01, 0x02, 0x40, 0x64, 0x03], idx = 0
//   returns: QuicFrame { frame_type: AckFrequency, stream_id: 1, length: 2, max_data: 100, offset: 3 }, ok = true
inline fn demux_ack_frequency_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let seq, ok1 = quic::decode_varint_cursor(src, idx);
    let thresh, ok2 = quic::decode_varint_cursor(src, idx);
    let max_delay, ok3 = quic::decode_varint_cursor(src, idx);
    let reorder, ok4 = quic::decode_varint_cursor(src, idx);
    guard ok1 && ok2 && ok3 && ok4 && thresh >= 1 else { return quic::QuicFrame { .. }, false; }
    committed = true;
    return quic::QuicFrame {
        frame_type: quic::QuicFrameType.AckFrequency,
        raw_type:   rfc::QUIC_FRAME_ACK_FREQUENCY,
        stream_id:  seq,
        length:     thresh,
        max_data:   max_delay,
        offset:     reorder,
    }, true;
}

// ---- Frame Demuxer Dispatch Subroutines ----------------------------------

// Demuxes MAX_DATA (0x10) or MAX_STREAM_DATA (0x11) frame.
//
// Example:
//   src = [max_data=1048576], idx = 0, ftype = 0x10
//   returns: QuicFrame { frame_type: MaxData, max_data: 1048576 }, ok = true
inline fn demux_flow_limit_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    if ftype == rfc::QUIC_FRAME_MAX_DATA {
        let md, ok = decode_max_data_frame(src, idx);
        guard ok else { return quic::QuicFrame { .. }, false; }
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.MaxData,
            raw_type:   ftype,
            max_data:   md.max_data,
        }, true;
    }
    let msd, ok = decode_max_stream_data_frame(src, idx);
    guard ok else { return quic::QuicFrame { .. }, false; }
    return quic::QuicFrame {
        frame_type: quic::QuicFrameType.MaxStreamData,
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
inline fn demux_stream_control_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    if ftype == rfc::QUIC_FRAME_RESET_STREAM {
        let rst, ok = decode_reset_stream_frame(src, idx);
        guard ok else { return quic::QuicFrame { .. }, false; }
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.ResetStream,
            raw_type:   ftype,
            stream_id:  rst.stream_id,
            error_code: rst.error_code,
            final_size: rst.final_size,
        }, true;
    }
    let ss, ok = decode_stop_sending_frame(src, idx);
    guard ok else { return quic::QuicFrame { .. }, false; }
    return quic::QuicFrame {
        frame_type: quic::QuicFrameType.StopSending,
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
fn demux_core_frame(
    src:         const u8[:],
    idx:         i64&,
    ftype:       u64,
    frame_start: i64 = 0,
) -> quic::QuicFrame, bool {
    if ftype == rfc::QUIC_FRAME_PADDING {
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.Padding,
            raw_type:   rfc::QUIC_FRAME_PADDING,
            length:     1,
        }, true;
    }
    if ftype == rfc::QUIC_FRAME_PING {
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.Ping,
            raw_type:   rfc::QUIC_FRAME_PING,
        }, true;
    }
    if ftype == rfc::QUIC_FRAME_ACK || ftype == rfc::QUIC_FRAME_ACK_ECN {
        return decode_ack_frame_cursor(src, idx, ftype == rfc::QUIC_FRAME_ACK_ECN, frame_start);
    }
    if ftype == rfc::QUIC_FRAME_RESET_STREAM || ftype == rfc::QUIC_FRAME_STOP_SENDING {
        return demux_stream_control_frame(src, idx, ftype);
    }
    if ftype == rfc::QUIC_FRAME_CRYPTO {
        let cr, ok = decode_crypto_frame(src, idx);
        guard ok else { return quic::QuicFrame { .. }, false; }
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.Crypto,
            raw_type:   ftype,
            offset:     cr.offset,
            length:     cr.data.len as u64,
            payload:    cr.data,
        }, true;
    }
    if ftype == rfc::QUIC_FRAME_NEW_TOKEN {
        return decode_new_token_frame(src, idx);
    }
    if ftype >= rfc::QUIC_FRAME_STREAM_BASE && ftype <= rfc::QUIC_STREAM_MAX_TYPE {
        let st, ok = decode_stream_frame(src, idx, ftype);
        guard ok else { return quic::QuicFrame { .. }, false; }
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.Stream,
            raw_type:   ftype,
            stream_id:  st.stream_id,
            offset:     st.offset,
            length:     st.data.len as u64,
            fin:        st.fin,
            payload:    st.data,
        }, true;
    }
    if ftype == rfc::QUIC_FRAME_MAX_DATA || ftype == rfc::QUIC_FRAME_MAX_STREAM_DATA {
        return demux_flow_limit_frame(src, idx, ftype);
    }
    return quic::QuicFrame { .. }, false;
}

// Dispatches stream count limit frames (0x12, 0x13, 0x16, 0x17).
// Limits cannot exceed 2^60 (RFC 9000 §19.11, §19.14); restores `idx` on failure (`false`).
//
// Example:
//   src = [varint(100)], idx = 0, ftype = QUIC_FRAME_MAX_STREAMS_BIDI (0x12)
//   returns: QuicFrame { frame_type: MaxStreamsBidi, max_data: 100 }, ok = true
fn demux_streams_limit_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    if ftype == rfc::QUIC_FRAME_MAX_STREAMS_BIDI || ftype == rfc::QUIC_FRAME_MAX_STREAMS_UNI {
        let limit, ok = quic::decode_varint_cursor(src, idx);
        guard ok && limit <= rfc::QUIC_MAX_STREAMS_LIMIT else { return quic::QuicFrame { .. }, false; }
        let k = if ftype == rfc::QUIC_FRAME_MAX_STREAMS_BIDI {
            quic::QuicFrameType.MaxStreamsBidi
        } else {
            quic::QuicFrameType.MaxStreamsUni
        };
        committed = true;
        return quic::QuicFrame { frame_type: k, raw_type: ftype, max_data: limit }, true;
    }
    if ftype == rfc::QUIC_FRAME_STREAMS_BLOCKED_BIDI || ftype == rfc::QUIC_FRAME_STREAMS_BLOCKED_UNI {
        let lim, ok = quic::decode_varint_cursor(src, idx);
        guard ok && lim <= rfc::QUIC_MAX_STREAMS_LIMIT else { return quic::QuicFrame { .. }, false; }
        let k = if ftype == rfc::QUIC_FRAME_STREAMS_BLOCKED_BIDI {
            quic::QuicFrameType.StreamsBlockedBidi
        } else {
            quic::QuicFrameType.StreamsBlockedUni
        };
        committed = true;
        return quic::QuicFrame { frame_type: k, raw_type: ftype, max_data: lim }, true;
    }
    return quic::QuicFrame { .. }, false;
}

// Dispatches data blocked frames (0x14, 0x15).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [varint(5000)], idx = 0, ftype = QUIC_FRAME_DATA_BLOCKED (0x14)
//   returns: QuicFrame { frame_type: DataBlocked, max_data: 5000 }, ok = true
fn demux_blocked_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    if ftype == rfc::QUIC_FRAME_DATA_BLOCKED {
        let limit, ok = quic::decode_varint_cursor(src, idx);
        guard ok else { return quic::QuicFrame { .. }, false; }
        committed = true;
        return quic::QuicFrame { frame_type: quic::QuicFrameType.DataBlocked, raw_type: ftype, max_data: limit }, true;
    }
    if ftype == rfc::QUIC_FRAME_STREAM_DATA_BLOCKED {
        let sid, ok_sid = quic::decode_varint_cursor(src, idx);
        let lim, ok_lim = quic::decode_varint_cursor(src, idx);
        guard ok_sid && ok_lim else { return quic::QuicFrame { .. }, false; }
        committed = true;
        return quic::QuicFrame {
            frame_type: quic::QuicFrameType.StreamDataBlocked,
            raw_type:   ftype,
            stream_id:  sid,
            max_data:   lim,
        }, true;
    }
    return quic::QuicFrame { .. }, false;
}

// Decodes a CONNECTION_CLOSE frame (0x1C or 0x1D) directly from slice with cursor (RFC 9000 §19.19).
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [0x00, 0x00, 0x03, 'b', 'y', 'e'], idx = 0, ftype = 0x1C
//   returns: QuicFrame { frame_type: ConnectionClose, error_code: 0, payload: "bye" }, ok = true
//
// crap:trusted-bounds
fn decode_connection_close_frame(
    src:   const u8[:],
    idx:   i64&,
    ftype: u64,
) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    // RFC 9000 Section 19.19: CONNECTION_CLOSE Frames - Valid frame types are 0x1c and 0x1d.
    guard ftype == rfc::QUIC_FRAME_CONNECTION_CLOSE || ftype == rfc::QUIC_FRAME_CONNECTION_CLOSE_APP else {
        return quic::QuicFrame { .. }, false;
    }
    let err, ok_err = quic::decode_varint_cursor(src, idx);
    guard ok_err else { return quic::QuicFrame { .. }, false; }
    var trigger_type: u64 = 0;
    if ftype == rfc::QUIC_FRAME_CONNECTION_CLOSE {
        let trg, ok_trg = quic::decode_varint_cursor(src, idx);
        guard ok_trg else { return quic::QuicFrame { .. }, false; }
        trigger_type = trg;
    }
    let rlen, ok_rlen = quic::decode_varint_cursor(src, idx);
    guard ok_rlen else { return quic::QuicFrame { .. }, false; }
    let ilen = rlen as i64;
    guard ilen >= 0 && ilen <= src.len - idx else { return quic::QuicFrame { .. }, false; }
    let reason = src[idx..idx + ilen];
    idx += ilen;
    let k = if ftype == rfc::QUIC_FRAME_CONNECTION_CLOSE {
        quic::QuicFrameType.ConnectionClose
    } else {
        quic::QuicFrameType.ConnectionCloseApp
    };
    committed = true;
    return quic::QuicFrame {
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
inline fn demux_path_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    let cur = idx;
    guard cur >= 0 && 8 <= src.len - cur else { return quic::QuicFrame { .. }, false; }
    let end = cur + 8;
    idx = end;
    let k = if ftype == rfc::QUIC_FRAME_PATH_CHALLENGE {
        quic::QuicFrameType.PathChallenge
    } else {
        quic::QuicFrameType.PathResponse
    };
    return quic::QuicFrame {
        frame_type: k,
        raw_type:   ftype,
        length:     8,
        payload:    src[cur..end],
    }, true;
}

// Dispatches connection management frames (0x1A - 0x1F).
//
// Example:
//   src = [], idx = 0, ftype = QUIC_FRAME_HANDSHAKE_DONE (0x1E)
//   returns: QuicFrame { frame_type: HandshakeDone, raw_type: 0x1E }, ok = true
fn demux_session_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    if ftype == rfc::QUIC_FRAME_HANDSHAKE_DONE {
        return quic::QuicFrame { frame_type: quic::QuicFrameType.HandshakeDone, raw_type: ftype }, true;
    }
    if ftype == rfc::QUIC_FRAME_IMMEDIATE_ACK {
        return quic::QuicFrame { frame_type: quic::QuicFrameType.ImmediateAck, raw_type: ftype }, true;
    }
    if ftype == rfc::QUIC_FRAME_PATH_CHALLENGE || ftype == rfc::QUIC_FRAME_PATH_RESPONSE {
        return demux_path_frame(src, idx, ftype);
    }
    if ftype == rfc::QUIC_FRAME_NEW_CONNECTION_ID {
        return decode_new_conn_id_frame(src, idx);
    }
    if ftype == rfc::QUIC_FRAME_RETIRE_CONNECTION_ID {
        return decode_retire_conn_id_frame(src, idx);
    }
    if ftype == rfc::QUIC_FRAME_CONNECTION_CLOSE || ftype == rfc::QUIC_FRAME_CONNECTION_CLOSE_APP {
        return decode_connection_close_frame(src, idx, ftype);
    }
    return quic::QuicFrame { .. }, false;
}

// ---- QUIC Transport Parameters Internal Helpers (RFC 9000 §18) -----------

const QUIC_TP_BIT_ODCID:            u64 = (1 as u64) << 0;
const QUIC_TP_BIT_IDLE_TIMEOUT:     u64 = (1 as u64) << 1;
const QUIC_TP_BIT_SR_TOKEN:         u64 = (1 as u64) << 2;
const QUIC_TP_BIT_MAX_UDP_PAYLOAD:  u64 = (1 as u64) << 3;
const QUIC_TP_BIT_MAX_DATA:         u64 = (1 as u64) << 4;
const QUIC_TP_BIT_MAX_SD_BIDI_LOC:  u64 = (1 as u64) << 5;
const QUIC_TP_BIT_MAX_SD_BIDI_REM:  u64 = (1 as u64) << 6;
const QUIC_TP_BIT_MAX_SD_UNI:       u64 = (1 as u64) << 7;
const QUIC_TP_BIT_MAX_STREAMS_BIDI: u64 = (1 as u64) << 8;
const QUIC_TP_BIT_MAX_STREAMS_UNI:  u64 = (1 as u64) << 9;
const QUIC_TP_BIT_ACK_DELAY_EXP:    u64 = (1 as u64) << 10;
const QUIC_TP_BIT_MAX_ACK_DELAY:    u64 = (1 as u64) << 11;
const QUIC_TP_BIT_DISABLE_MIG:      u64 = (1 as u64) << 12;
const QUIC_TP_BIT_PREF_ADDR:        u64 = (1 as u64) << 13;
const QUIC_TP_BIT_ACTIVE_CID_LIM:   u64 = (1 as u64) << 14;
const QUIC_TP_BIT_ISCID:            u64 = (1 as u64) << 15;
const QUIC_TP_BIT_RSCID:            u64 = (1 as u64) << 16;
const QUIC_TP_BIT_VERSION_INFO:     u64 = (1 as u64) << 17;
const QUIC_TP_BIT_MAX_DATAGRAM:     u64 = (1 as u64) << 18;
const QUIC_TP_BIT_GREASE_QUIC_BIT:  u64 = (1 as u64) << 19;
const QUIC_TP_BIT_MIN_ACK_DELAY:    u64 = (1 as u64) << 20;

// Appends a varint-valued transport parameter `(id, varint_len(val), val)` into `out`.
fn encode_tp_varint<B>(id: u64, val: u64, out: B&) -> bool {
    var vbuf: u8[..8] = [];
    guard quic::encode_varint(val, vbuf) else { return false; }
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len); };
    guard quic::encode_varint(id, out)
        && quic::encode_varint(vbuf.len as u64, out)
        && out.try_append(vbuf[..]) else {
        return false;
    }
    committed = true;
    return true;
}

// Appends a raw byte-slice transport parameter `(id, bytes.len, bytes)` into `out`.
fn encode_tp_bytes<B>(id: u64, bytes: const u8[:], out: B&) -> bool {
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len); };
    guard quic::encode_varint(id, out)
        && quic::encode_varint(bytes.len as u64, out)
        && out.try_append(bytes) else {
        return false;
    }
    committed = true;
    return true;
}

// Encodes connection-level and stream data flow-control transport parameters (`0x01`, `0x03..0x07`).
fn encode_tp_flow_data<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    if tp.max_idle_timeout > 0 {
        guard encode_tp_varint(rfc::QUIC_TP_MAX_IDLE_TIMEOUT, tp.max_idle_timeout, out) else { return false; }
    }
    if tp.max_udp_payload_size != 65527 {
        guard tp.max_udp_payload_size >= rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_MAX_UDP_PAYLOAD_SIZE, tp.max_udp_payload_size, out) else { return false; }
    }
    if tp.initial_max_data > 0 {
        guard encode_tp_varint(rfc::QUIC_TP_INITIAL_MAX_DATA, tp.initial_max_data, out) else { return false; }
    }
    if tp.initial_max_stream_data_bidi_local > 0 {
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL;
        guard encode_tp_varint(id, tp.initial_max_stream_data_bidi_local, out) else { return false; }
    }
    if tp.initial_max_stream_data_bidi_remote > 0 {
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE;
        guard encode_tp_varint(id, tp.initial_max_stream_data_bidi_remote, out) else { return false; }
    }
    if tp.initial_max_stream_data_uni > 0 {
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI;
        guard encode_tp_varint(id, tp.initial_max_stream_data_uni, out) else { return false; }
    }
    return true;
}

// Encodes stream-count and ACK timing transport parameters (`0x08..0x0c`).
fn encode_tp_streams_and_ack<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    if tp.initial_max_streams_bidi > 0 {
        guard tp.initial_max_streams_bidi <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAMS_BIDI;
        guard encode_tp_varint(id, tp.initial_max_streams_bidi, out) else { return false; }
    }
    if tp.initial_max_streams_uni > 0 {
        guard tp.initial_max_streams_uni <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAMS_UNI;
        guard encode_tp_varint(id, tp.initial_max_streams_uni, out) else { return false; }
    }
    if tp.ack_delay_exponent != 3 {
        guard tp.ack_delay_exponent <= 20 else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_ACK_DELAY_EXPONENT, tp.ack_delay_exponent, out) else { return false; }
    }
    if tp.max_ack_delay != 25 {
        guard tp.max_ack_delay < 16384 else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_MAX_ACK_DELAY, tp.max_ack_delay, out) else { return false; }
    }
    if tp.disable_active_migration {
        guard encode_tp_bytes(rfc::QUIC_TP_DISABLE_ACTIVE_MIGRATION, "", out) else { return false; }
    }
    return true;
}

// RFC 9000 Section 18.2: Transport Parameter Definitions - Validates preferred_address structure and IP/port invariants.
//
// crap:trusted-bounds
inline fn is_valid_tp_preferred_address(val: const u8[:]) -> bool {
    var cur = core::cursor_from(val);
    let v4, ok4 = cur.read_bytes(4);
    let p4, okp4 = cur.read_u16();
    let v6, ok6 = cur.read_bytes(16);
    let p6, okp6 = cur.read_u16();
    let cid_slice, ok_cid = cur.read_u8_prefixed();
    let _, ok_tok = cur.read_bytes(16);
    guard ok4 && okp4 && ok6 && okp6 && ok_cid && ok_tok && cur.buf.len == 0 else { return false; }
    guard cid_slice.len >= 1 && cid_slice.len <= 20 else { return false; }
    let has_v4 = (v4[0] | v4[1] | v4[2] | v4[3]) != 0;
    var v6_or: u8 = 0;
    for i in 16 {
        v6_or = v6_or | v6[i];
    }
    let has_v6 = v6_or != 0;
    return has_v4 == (p4 != 0) && has_v6 == (p6 != 0) && (has_v4 || has_v6);
}

// Encodes CID limit and extension transport parameters (`0x0e`, `0x20`, `0x2ab2`, `0xde1a`).
fn encode_tp_extensions<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    if tp.active_connection_id_limit != 2 {
        guard tp.active_connection_id_limit >= 2 else { return false; }
        let id = rfc::QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT;
        guard encode_tp_varint(id, tp.active_connection_id_limit, out) else { return false; }
    }
    if tp.max_datagram_frame_size > 0 {
        let id = rfc::QUIC_TP_MAX_DATAGRAM_FRAME_SIZE;
        guard encode_tp_varint(id, tp.max_datagram_frame_size, out) else { return false; }
    }
    if tp.grease_quic_bit {
        guard encode_tp_bytes(rfc::QUIC_TP_GREASE_QUIC_BIT, "", out) else { return false; }
    }
    if tp.min_ack_delay_us > 0 {
        guard tp.min_ack_delay_us <= core::mul_sat_u64(tp.max_ack_delay, 1000) else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_MIN_ACK_DELAY, tp.min_ack_delay_us, out) else { return false; }
    }
    return true;
}

// Encodes RFC 9368 `version_information` (`0x11`) transport parameter into `out`.
fn encode_tp_version_info<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    // RFC 9369 Section 4: Version Negotiation Considerations - Reject non-empty available_versions when chosen_version is 0.
    if tp.chosen_version == 0 {
        return tp.available_versions.len == 0;
    }
    var vbuf: u8[..40] = [];
    vbuf.append_u32_be(tp.chosen_version);
    for i in tp.available_versions.len {
        let av = tp.available_versions[i];
        guard av != 0 else { return false; }
        vbuf.append_u32_be(av);
    }
    return encode_tp_bytes(rfc::QUIC_TP_VERSION_INFORMATION, vbuf[..], out);
}

// Encodes server-only and CID transport parameters into `out`.
fn encode_tp_cids_and_server<B>(
    tp:        const quic::QuicTransportParams&,
    is_server: bool,
    out:       B&,
) -> bool {
    if !is_server {
        return !tp.has_stateless_reset_token
            && tp.preferred_address.len == 0
            && tp.original_destination_connection_id.len == 0
            && tp.retry_source_connection_id.len == 0;
    }
    // RFC 9000 Section 7.3: Authenticating Connection IDs - Servers MUST send original_destination_connection_id.
    let odcid_id = rfc::QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID;
    guard encode_tp_bytes(odcid_id, tp.original_destination_connection_id[..], out) else { return false; }
    if tp.has_stateless_reset_token {
        guard encode_tp_bytes(rfc::QUIC_TP_STATELESS_RESET_TOKEN, tp.stateless_reset_token[..], out) else {
            return false;
        }
    }
    if tp.preferred_address.len > 0 {
        guard is_valid_tp_preferred_address(tp.preferred_address[..])
            && encode_tp_bytes(rfc::QUIC_TP_PREFERRED_ADDRESS, tp.preferred_address[..], out) else {
            return false;
        }
    }
    if tp.retry_source_connection_id.len > 0 {
        let id = rfc::QUIC_TP_RETRY_SOURCE_CONNECTION_ID;
        guard encode_tp_bytes(id, tp.retry_source_connection_id[..], out) else { return false; }
    }
    return true;
}

// Decodes a single exact-fitting varint from a transport parameter value slice.
//
// Example:
//   val = [0x44, 0xB0] (varint 1200)
//   returns: v = 1200, ok = true
inline fn decode_tp_exact_varint(val: const u8[:]) -> u64, bool {
    var v_idx: i64 = 0;
    let v, ok = quic::decode_varint_cursor(val, v_idx);
    guard ok && v_idx == val.len else { return 0, false; }
    return v, true;
}

// Marks `bit` in `seen_mask`, returning `false` on duplicate transport parameter ID.
inline fn mark_tp_seen(seen_mask: u64&, bit: u64) -> bool {
    guard !seen_mask.has_flag(bit) else { return false; }
    seen_mask.set_flag(bit);
    return true;
}

// Decodes RFC 9368 `version_information` (`0x11`) transport parameter value slice.
//
// Example:
//   val = [0x00, 0x00, 0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf]
//   returns: true, tp.chosen_version = 1, tp.available_versions = [0x6b3343cf]
//
// crap:trusted-bounds
inline fn decode_tp_version_info(val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    guard val.len >= 4 && (val.len & 3) == 0 else { return false; }
    var cur = core::cursor_from(val);
    let chosen, ok_c = cur.read_u32();
    guard ok_c && chosen != 0 else { return false; }
    var parsed_vers: u32[..8] = [];
    while cur.buf.len >= 4 {
        let av, ok_a = cur.read_u32();
        guard ok_a && av != 0 && parsed_vers.try_push(av) else { return false; }
    }
    tp.chosen_version = chosen;
    tp.available_versions = parsed_vers;
    return true;
}

// Validates RFC 9000 §18.2 `preferred_address` (`0x0d`) wire structure and copies into `tp`.
//
// Example:
//   val = [4B ipv4, 2B port, 16B ipv6, 2B port, cid_len=4, 1, 2, 3, 4, 16B reset_token]
//   returns: true, tp.preferred_address = val
//
// crap:trusted-bounds
inline fn decode_tp_preferred_addr(val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    guard is_valid_tp_preferred_address(val) else { return false; }
    return tp.preferred_address.try_set(val);
}

// Decodes connection and stream data flow-control parameters (`0x01`, `0x03..0x06`).
//
// Example:
//   id = 0x03 (max_udp_payload_size), val = [0x45, 0xDC] (1500)
//   returns: true, tp.max_udp_payload_size = 1500
fn decode_tp_flow_data(id: u64, v: u64, tp: quic::QuicTransportParams&) -> bool {
    if id == rfc::QUIC_TP_MAX_IDLE_TIMEOUT {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_IDLE_TIMEOUT) else { return false; }
        tp.max_idle_timeout = v;
        return true;
    }
    if id == rfc::QUIC_TP_MAX_UDP_PAYLOAD_SIZE {
        guard v >= rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN else { return false; }
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_UDP_PAYLOAD) else { return false; }
        tp.max_udp_payload_size = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_DATA {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_DATA) else { return false; }
        tp.initial_max_data = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_SD_BIDI_LOC) else { return false; }
        tp.initial_max_stream_data_bidi_local = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_SD_BIDI_REM) else { return false; }
        tp.initial_max_stream_data_bidi_remote = v;
        return true;
    }
    return false;
}

// Decodes unidirectional stream data and stream count transport parameters (`0x07..0x09`).
//
// Example:
//   id = 0x08 (initial_max_streams_bidi), val = [0x40, 0x64] (100)
//   returns: true, tp.initial_max_streams_bidi = 100
fn decode_tp_flow_param(id: u64, val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    let v, ok = decode_tp_exact_varint(val);
    guard ok else { return false; }
    if id <= rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE {
        return decode_tp_flow_data(id, v, tp);
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_SD_UNI) else { return false; }
        tp.initial_max_stream_data_uni = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAMS_BIDI {
        guard v <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_STREAMS_BIDI) else { return false; }
        tp.initial_max_streams_bidi = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAMS_UNI {
        guard v <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_STREAMS_UNI) else { return false; }
        tp.initial_max_streams_uni = v;
        return true;
    }
    return false;
}

// Copies a 16-byte stateless reset token slice into `tp`.
//
// crap:trusted-bounds
inline fn set_tp_stateless_reset_token(val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    guard val.len == 16 else { return false; }
    for i in 16 {
        tp.stateless_reset_token[i] = val[i];
    }
    tp.has_stateless_reset_token = true;
    return true;
}

// Decodes server-only and CID transport parameters (`0x00`, `0x02`, `0x0d`, `0x0f`, `0x10`).
//
// Example:
//   id = 0x0f (initial_source_connection_id), val = [1, 2, 3, 4], is_server = true
//   returns: true, tp.initial_source_connection_id = [1, 2, 3, 4]
fn decode_tp_cid_or_server_param(
    id:        u64,
    val:       const u8[:],
    is_server: bool,
    tp:        quic::QuicTransportParams&,
) -> bool {
    if id == rfc::QUIC_TP_INITIAL_SOURCE_CONNECTION_ID {
        guard !tp.seen_mask.has_flag(QUIC_TP_BIT_ISCID)
            && tp.initial_source_connection_id.try_set(val) else {
            return false;
        }
        tp.seen_mask.set_flag(QUIC_TP_BIT_ISCID);
        return true;
    }
    guard is_server else { return false; }
    if id == rfc::QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID {
        guard !tp.seen_mask.has_flag(QUIC_TP_BIT_ODCID)
            && tp.original_destination_connection_id.try_set(val) else {
            return false;
        }
        tp.seen_mask.set_flag(QUIC_TP_BIT_ODCID);
        return true;
    }
    if id == rfc::QUIC_TP_STATELESS_RESET_TOKEN {
        guard !tp.seen_mask.has_flag(QUIC_TP_BIT_SR_TOKEN)
            && set_tp_stateless_reset_token(val, tp) else {
            return false;
        }
        tp.seen_mask.set_flag(QUIC_TP_BIT_SR_TOKEN);
        return true;
    }
    if id == rfc::QUIC_TP_PREFERRED_ADDRESS {
        guard !tp.seen_mask.has_flag(QUIC_TP_BIT_PREF_ADDR)
            && decode_tp_preferred_addr(val, tp) else {
            return false;
        }
        tp.seen_mask.set_flag(QUIC_TP_BIT_PREF_ADDR);
        return true;
    }
    if id == rfc::QUIC_TP_RETRY_SOURCE_CONNECTION_ID {
        guard !tp.seen_mask.has_flag(QUIC_TP_BIT_RSCID)
            && tp.retry_source_connection_id.try_set(val) else {
            return false;
        }
        tp.seen_mask.set_flag(QUIC_TP_BIT_RSCID);
        return true;
    }
    return false;
}

// Decodes standard ACK timing and migration transport parameters (`0x0a..0x0c`, `0x0e`).
//
// Example:
//   id = 0x0a (ack_delay_exponent), val = [0x04]
//   returns: true, tp.ack_delay_exponent = 4
fn decode_tp_ack_and_mig(id: u64, val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    if id == rfc::QUIC_TP_DISABLE_ACTIVE_MIGRATION {
        guard val.len == 0 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_DISABLE_MIG) else { return false; }
        tp.disable_active_migration = true;
        return true;
    }
    let v, ok = decode_tp_exact_varint(val);
    guard ok else { return false; }
    if id == rfc::QUIC_TP_ACK_DELAY_EXPONENT {
        guard v <= 20 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_ACK_DELAY_EXP) else { return false; }
        tp.ack_delay_exponent = v;
        return true;
    }
    if id == rfc::QUIC_TP_MAX_ACK_DELAY {
        guard v < 16384 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_ACK_DELAY) else { return false; }
        tp.max_ack_delay = v;
        return true;
    }
    if id == rfc::QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT {
        guard v >= 2 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_ACTIVE_CID_LIM) else { return false; }
        tp.active_connection_id_limit = v;
        return true;
    }
    return false;
}

// Decodes extension transport parameters (`0x11`, `0x20`, `0x2ab2`, `0xde1a`).
//
// Example:
//   id = 0x2ab2 (grease_quic_bit), val = []
//   returns: true, tp.grease_quic_bit = true
fn decode_tp_ext_param(id: u64, val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    if id <= rfc::QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT {
        return decode_tp_ack_and_mig(id, val, tp);
    }
    if id == rfc::QUIC_TP_VERSION_INFORMATION {
        guard !tp.seen_mask.has_flag(QUIC_TP_BIT_VERSION_INFO)
            && decode_tp_version_info(val, tp) else {
            return false;
        }
        tp.seen_mask.set_flag(QUIC_TP_BIT_VERSION_INFO);
        return true;
    }
    if id == rfc::QUIC_TP_MAX_DATAGRAM_FRAME_SIZE {
        let v, ok = decode_tp_exact_varint(val);
        guard ok && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_DATAGRAM) else { return false; }
        tp.max_datagram_frame_size = v;
        return true;
    }
    if id == rfc::QUIC_TP_GREASE_QUIC_BIT {
        guard val.len == 0 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_GREASE_QUIC_BIT) else { return false; }
        tp.grease_quic_bit = true;
        return true;
    }
    if id == rfc::QUIC_TP_MIN_ACK_DELAY {
        let v, ok = decode_tp_exact_varint(val);
        guard ok && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MIN_ACK_DELAY) else { return false; }
        tp.min_ack_delay_us = v;
        return true;
    }
    return true;
}

// Decodes a single transport parameter `(id, val)` into `tp`.
//
// Example:
//   id = 0x04 (initial_max_data), val = [0x44, 0x00], is_server = true
//   returns: true, tp.initial_max_data = 1024
inline fn decode_single_tp(
    id:        u64,
    val:       const u8[:],
    is_server: bool,
    tp:        quic::QuicTransportParams&,
) -> bool {
    if id == rfc::QUIC_TP_MAX_IDLE_TIMEOUT
        || (id >= rfc::QUIC_TP_MAX_UDP_PAYLOAD_SIZE && id <= rfc::QUIC_TP_INITIAL_MAX_STREAMS_UNI) {
        return decode_tp_flow_param(id, val, tp);
    }
    if id == rfc::QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID
        || id == rfc::QUIC_TP_STATELESS_RESET_TOKEN
        || id == rfc::QUIC_TP_PREFERRED_ADDRESS
        || id == rfc::QUIC_TP_INITIAL_SOURCE_CONNECTION_ID
        || id == rfc::QUIC_TP_RETRY_SOURCE_CONNECTION_ID {
        return decode_tp_cid_or_server_param(id, val, is_server, tp);
    }
    return decode_tp_ext_param(id, val, tp);
}
