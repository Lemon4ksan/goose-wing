// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QUIC frame demuxer dispatch subroutines (RFC 9000 Section 19).
namespace quic_internal;

import std;
import core;
import .packet;
import .frames;
import .frames_internal;

// ---- Frame Demuxer Dispatch Subroutines ----------------------------------

// Demuxes MAX_DATA (0x10) or MAX_STREAM_DATA (0x11) frame.
//
// Example:
//   src = [max_data=1048576], idx = 0, ftype = 0x10
//   returns: QuicFrame { frame_type: MaxData, max_data: 1048576 }, ok = true
checkfree inline fn demux_flow_limit_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
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
checkfree inline fn demux_stream_control_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
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
checkfree fn demux_core_frame(
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
checkfree fn demux_streams_limit_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
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
checkfree fn demux_blocked_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
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
checkfree fn decode_connection_close_frame(
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
    let pos = idx;
    guard ok_rlen && pos >= 0 && pos <= src.len else { return quic::QuicFrame { .. }, false; }
    let ilen = rlen as i64;
    let tail = src[pos..];
    guard ilen >= 0 && ilen <= tail.len else { return quic::QuicFrame { .. }, false; }
    let reason = tail[..ilen];
    idx = core::add_sat_i64(pos, ilen);
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
checkfree inline fn demux_path_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
    let cur = idx;
    guard cur >= 0 && cur <= src.len else { return quic::QuicFrame { .. }, false; }
    let tail = src[cur..];
    guard tail.len >= 8 else { return quic::QuicFrame { .. }, false; }
    idx = core::add_sat_i64(cur, 8);
    let k = if ftype == rfc::QUIC_FRAME_PATH_CHALLENGE {
        quic::QuicFrameType.PathChallenge
    } else {
        quic::QuicFrameType.PathResponse
    };
    return quic::QuicFrame {
        frame_type: k,
        raw_type:   ftype,
        length:     8,
        payload:    tail[..8],
    }, true;
}

// Dispatches connection management frames (0x1A - 0x1F).
//
// Example:
//   src = [], idx = 0, ftype = QUIC_FRAME_HANDSHAKE_DONE (0x1E)
//   returns: QuicFrame { frame_type: HandshakeDone, raw_type: 0x1E }, ok = true
checkfree fn demux_session_frame(src: const u8[:], idx: i64&, ftype: u64) -> quic::QuicFrame, bool {
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
