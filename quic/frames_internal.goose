// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QUIC frame range validation and dedicated frame sub-decoders (RFC 9000 Section 19).
namespace quic_internal;

import std;
import core;
import .packet;
import .frames;

// ---- Helper Invariant Checkers (RFC 9000 Range Validation) ---------------

// Validates that offset and length are valid 62-bit VarInts and sum <= 2^62 - 1.
checkfree inline fn quic_valid_offset_len(offset: u64, len: u64) -> bool {
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
checkfree inline fn build_stream_frame_type(flags: quic::QuicStreamFlags) -> u64 {
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
checkfree inline fn decode_ack_ranges(
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
    for _ in range_cnt {
        let gap, ok_g = quic::decode_varint_cursor(src, idx);
        guard ok_g else { return false; }
        let rlen, ok_r = quic::decode_varint_cursor(src, idx);
        guard ok_r else { return false; }

        guard cur_smallest >= 2 && (cur_smallest - 2) >= gap else { return false; }
        let cur_largest = cur_smallest - gap - 2;
        guard cur_largest >= rlen else { return false; }
        cur_smallest = cur_largest - rlen;
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
checkfree inline fn decode_ack_ecn_counts(src: const u8[:], idx: i64&) -> bool {
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
checkfree fn decode_ack_frame_cursor(
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
    let end_pos = idx;
    let payload_slice = if frame_start >= 0 && frame_start <= end_pos && end_pos <= src.len {
        src[frame_start..end_pos]
    } else {
        src[..0]
    };
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
checkfree fn decode_new_token_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let tlen, ok_len = quic::decode_varint_cursor(src, idx);
    let pos = idx;
    guard ok_len && tlen > 0 && pos >= 0 && pos <= src.len else { return quic::QuicFrame { .. }, false; }
    let ilen = tlen as i64;
    let tail = src[pos..];
    guard ilen >= 0 && ilen <= tail.len else { return quic::QuicFrame { .. }, false; }
    let token = tail[..ilen];
    idx = pos + ilen;
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
checkfree fn decode_reset_stream_frame(src: const u8[:], idx: i64&) -> quic::QuicResetStreamFrame, bool {
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
checkfree fn decode_stop_sending_frame(src: const u8[:], idx: i64&) -> quic::QuicStopSendingFrame, bool {
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
checkfree fn decode_crypto_frame(src: const u8[:], idx: i64&) -> quic::QuicCryptoFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let offset, ok_off = quic::decode_varint_cursor(src, idx);
    guard ok_off else { return quic::QuicCryptoFrame { .. }, false; }

    let data_len, ok_len = quic::decode_varint_cursor(src, idx);
    guard ok_len else { return quic::QuicCryptoFrame { .. }, false; }

    let pos = idx;
    guard quic_valid_offset_len(offset, data_len) && pos >= 0 && pos <= src.len else {
        return quic::QuicCryptoFrame { .. }, false;
    }
    let dlen = data_len as i64;
    let tail = src[pos..];
    guard dlen >= 0 && dlen <= tail.len else {
        return quic::QuicCryptoFrame { .. }, false;
    }

    let payload = tail[..dlen];
    idx = pos + dlen;
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
checkfree fn decode_stream_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicStreamFrame, bool {
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

    let pos = idx;
    guard quic_valid_offset_len(offset, data_len) && pos >= 0 && pos <= src.len else {
        return quic::QuicStreamFrame { .. }, false;
    }
    let dlen = data_len as i64;
    let tail = src[pos..];
    guard dlen >= 0 && dlen <= tail.len else {
        return quic::QuicStreamFrame { .. }, false;
    }

    let payload = tail[..dlen];
    idx = pos + dlen;
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
checkfree fn decode_max_data_frame(src: const u8[:], idx: i64&) -> quic::QuicMaxDataFrame, bool {
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
checkfree fn decode_max_stream_data_frame(src: const u8[:], idx: i64&) -> quic::QuicMaxStreamDataFrame, bool {
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
checkfree fn decode_new_conn_id_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let seq, ok_seq = quic::decode_varint_cursor(src, idx);
    guard ok_seq else { return quic::QuicFrame { .. }, false; }
    let retire_prior, ok_ret = quic::decode_varint_cursor(src, idx);
    guard ok_ret && retire_prior <= seq else { return quic::QuicFrame { .. }, false; }
    let pos = idx;
    guard pos >= 0 && pos < src.len else { return quic::QuicFrame { .. }, false; }
    let cid_len = src[pos] as i64;
    let body_pos = pos + 1;
    guard cid_len >= 1 && cid_len <= 20 && body_pos >= 0 && body_pos <= src.len else {
        return quic::QuicFrame { .. }, false;
    }
    let tail = src[body_pos..];
    let need = cid_len + 16;
    guard need <= tail.len else { return quic::QuicFrame { .. }, false; }
    let payload = tail[..need];
    idx = body_pos + need;
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
checkfree fn decode_retire_conn_id_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
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
checkfree fn demux_datagram_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    // RFC 9221 Section 4: Datagram Frame Types - Valid DATAGRAM frame types are 0x30 and 0x31.
    guard ftype == rfc::QUIC_FRAME_DATAGRAM || ftype == rfc::QUIC_FRAME_DATAGRAM_LEN else {
        return quic::QuicFrame { .. }, false;
    }
    let start_pos = idx;
    guard start_pos >= 0 && start_pos <= src.len else { return quic::QuicFrame { .. }, false; }
    if ftype == rfc::QUIC_FRAME_DATAGRAM {
        let payload = src[start_pos..];
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
    let pos = idx;
    guard ok && pos >= 0 && pos <= src.len else { return quic::QuicFrame { .. }, false; }
    let ilen = dlen as i64;
    let tail = src[pos..];
    guard ilen >= 0 && ilen <= tail.len else { return quic::QuicFrame { .. }, false; }
    let payload = tail[..ilen];
    idx = pos + ilen;
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
checkfree fn decode_path_challenge_frame(src: const u8[:], idx: i64&) -> quic::QuicPathFrame, bool {
    let pos = idx;
    guard pos >= 0 && pos <= src.len else { return quic::QuicPathFrame { .. }, false; }
    let tail = src[pos..];
    guard tail.len >= 8 else { return quic::QuicPathFrame { .. }, false; }
    var frame = quic::QuicPathFrame { .. };
    for i in 8 {
        frame.data[i] = tail[i];
    }
    idx = pos + 8;
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
checkfree fn decode_path_response_frame(src: const u8[:], idx: i64&) -> quic::QuicPathFrame, bool {
    let pos = idx;
    guard pos >= 0 && pos <= src.len else { return quic::QuicPathFrame { .. }, false; }
    let tail = src[pos..];
    guard tail.len >= 8 else { return quic::QuicPathFrame { .. }, false; }
    var frame = quic::QuicPathFrame { .. };
    for i in 8 {
        frame.data[i] = tail[i];
    }
    idx = pos + 8;
    return frame, true;
}

// Decodes an ACK_FREQUENCY frame (0xAF) into QuicFrame using an in-out index cursor.
// Restores `idx` on failure (`false`).
//
// Example:
//   src = [0x01, 0x02, 0x40, 0x64, 0x03], idx = 0
//   returns: QuicFrame { frame_type: AckFrequency, stream_id: 1, length: 2, max_data: 100, offset: 3 }, ok = true
checkfree fn demux_ack_frequency_frame(src: const u8[:], idx: i64&) -> quic::QuicFrame, bool {
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
