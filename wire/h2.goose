// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 binary wire frame encoders, decoders, and frame stream readers (RFC 9113, RFC 9218).
namespace wire;

import std;
import core from "..";
import .types;

// Appends 9 serialized header bytes to any buffer (RFC 9113 Section 4.1).
fn encode_frame_header<B>(hdr: const WireFrameHeader&, out: B&) -> bool {
    let bytes: u8[9] = [
        ((hdr.length >> 16) & 0xFF) as u8,
        ((hdr.length >> 8) & 0xFF) as u8,
        (hdr.length & 0xFF) as u8,
        hdr.frame_type,
        hdr.flags,
        ((hdr.stream_id >> 24) & 0x7F) as u8,
        ((hdr.stream_id >> 16) & 0xFF) as u8,
        ((hdr.stream_id >> 8) & 0xFF) as u8,
        (hdr.stream_id & 0xFF) as u8,
    ];
    guard out.try_append(bytes[..]) else { return false; }
    return true;
}

// Parses a 9-byte HTTP/2 binary frame header (RFC 9113 Section 4.1).
//
// Example:
//   buf = [0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]
//   returns: hdr (len=0, type=4, flags=1, sid=0), err = 0, ok = true
fn parse_frame_header(buf: const u8[:]) -> WireFrameHeader, u32, bool {
    var hdr = WireFrameHeader { .. };
    guard buf.len >= 9 else {
        return hdr, 1, false;
    }
    let length_val = core::read_be_u24(buf, 0);
    let f_type = buf[3];
    let flags_val = buf[4];
    let raw_stream = core::read_be_u32(buf, 5);

    hdr.length = length_val;
    hdr.frame_type = f_type;
    hdr.flags = flags_val;
    hdr.stream_id = raw_stream & 0x7FFFFFFF;
    return hdr, 0, true;
}

// Encodes an HTTP/2 SETTINGS frame with explicit parameter list (RFC 9113 Section 6.5).
fn encode_settings_frame<B>(settings: const WireSetting[:], out: B&) -> bool {
    let payload_len = (settings.len as u32) * 6;
    let hdr = WireFrameHeader {
        length:     payload_len,
        frame_type: H2_FRAME_SETTINGS,
        flags:      H2_FLAG_NONE,
        stream_id:  0,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    for s in settings {
        let entry: u8[6] = [
            ((s.id >> 8) & 0xFF) as u8,
            (s.id & 0xFF) as u8,
            ((s.val >> 24) & 0xFF) as u8,
            ((s.val >> 16) & 0xFF) as u8,
            ((s.val >> 8) & 0xFF) as u8,
            (s.val & 0xFF) as u8,
        ];
        guard out.try_append(entry[..]) else { return false; }
    }
    return true;
}

// Encodes a WINDOW_UPDATE frame with explicit stream ID and increment (RFC 9113 Section 6.9).
fn encode_window_update_frame<B>(stream_id: u32, increment: u32, out: B&) -> bool {
    let hdr = WireFrameHeader {
        length:     4,
        frame_type: H2_FRAME_WINDOW_UPDATE,
        flags:      H2_FLAG_NONE,
        stream_id:  stream_id,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    let inc = increment & 0x7FFFFFFF;
    let bytes: u8[4] = [
        ((inc >> 24) & 0x7F) as u8,
        ((inc >> 16) & 0xFF) as u8,
        ((inc >> 8) & 0xFF) as u8,
        (inc & 0xFF) as u8,
    ];
    guard out.try_append(bytes[..]) else { return false; }
    return true;
}

inline fn format_urgency_byte(urgency: u8) -> u8 {
    return '0' + (urgency & 0x07);
}

inline fn format_priority_params<B>(urgency: u8, incremental: bool, out: B&) -> bool {
    let u_byte = format_urgency_byte(urgency);
    guard out.try_append("u=") else { return false; }
    guard out.try_push(u_byte) else { return false; }
    if incremental {
        guard out.try_append(", i") else { return false; }
    }
    return true;
}

inline fn calc_priority_payload_len(val_len: i64) -> u32 {
    return 4 + (val_len as u32);
}

// Encodes an RFC 9218 PRIORITY_UPDATE frame on stream 0 (RFC 9218 Section 7.1).
fn encode_priority_update_frame<B>(prioritized_stream_id: u32, urgency: u8, incremental: bool, out: B&) -> bool {
    var p_val: u8[..32] = [];
    guard format_priority_params(urgency, incremental, p_val) else { return false; }

    let payload_len = calc_priority_payload_len(p_val.len);
    let hdr = WireFrameHeader {
        length:     payload_len,
        frame_type: H2_FRAME_PRIORITY_UPDATE,
        flags:      H2_FLAG_NONE,
        stream_id:  0,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    let psid = prioritized_stream_id & 0x7FFFFFFF;
    let psid_bytes: u8[4] = [
        ((psid >> 24) & 0x7F) as u8,
        ((psid >> 16) & 0xFF) as u8,
        ((psid >> 8) & 0xFF) as u8,
        (psid & 0xFF) as u8,
    ];
    guard out.try_append(psid_bytes[..]) else { return false; }
    guard out.try_append(p_val[..]) else { return false; }
    return true;
}

// Encodes a RST_STREAM frame (RFC 9113 Section 6.4).
fn encode_rst_stream_frame<B>(stream_id: u32, error_code: u32, out: B&) -> bool {
    let hdr = WireFrameHeader {
        length:     4,
        frame_type: H2_FRAME_RST_STREAM,
        flags:      H2_FLAG_NONE,
        stream_id:  stream_id,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    guard out.try_push(((error_code >> 24) & 0xFF) as u8) &&
          out.try_push(((error_code >> 16) & 0xFF) as u8) &&
          out.try_push(((error_code >> 8) & 0xFF) as u8) &&
          out.try_push((error_code & 0xFF) as u8) else {
        return false;
    }
    return true;
}

// Encodes a PING frame with 8-byte payload (RFC 9113 Section 6.7).
fn encode_ping_frame<B>(payload: const u8[8], is_ack: bool, out: B&) -> bool {
    let hdr = WireFrameHeader {
        length:     8,
        frame_type: H2_FRAME_PING,
        flags:      if is_ack { H2_FLAG_ACK } else { H2_FLAG_NONE },
        stream_id:  0,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    guard out.try_append(payload[..]) else { return false; }
    return true;
}

inline fn select_data_frame_flags(end_stream: bool) -> u8 {
    return if end_stream { H2_FLAG_END_STREAM } else { H2_FLAG_NONE };
}

// Encodes a DATA frame (RFC 9113 Section 6.1).
fn encode_data_frame<B>(stream_id: u32, payload: const u8[:], end_stream: bool, out: B&) -> bool {
    let hdr = WireFrameHeader {
        length:     payload.len as u32,
        frame_type: H2_FRAME_DATA,
        flags:      select_data_frame_flags(end_stream),
        stream_id:  stream_id,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    guard out.try_append(payload) else { return false; }
    return true;
}

// Zero-copy streaming reader for incoming HTTP/2 frames.
struct WireH2FrameReader {
    src:    const u8[:] = "",
    cursor: i64         = 0,
}

// Instantiates a frame stream reader over a borrowed byte slice.
fn new_wire_h2_frame_reader(src: const u8[:]) -> WireH2FrameReader {
    return WireH2FrameReader {
        src:    src,
        cursor: 0,
    };
}

// Checks if another 9-byte frame header can be read.
fn has_next(r: const WireH2FrameReader&) -> bool {
    return r.cursor + 9 <= r.src.len;
}

// Parses the next HTTP/2 frame and slices its payload without memory allocations.
//
// Example:
//   r.src = [0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00], r.cursor = 0
//   returns: hdr.frame_type = 0x08, payload.len = 4, ok = true, r.cursor = 13
fn next_frame(r: WireH2FrameReader&) -> WireFrameHeader, const u8[:], bool {
    let unread = r.src[r.cursor..];
    guard unread.len >= 9 else {
        return WireFrameHeader { .. }, "", false;
    }
    let hdr, _, ok = parse_frame_header(unread);
    guard ok else {
        return WireFrameHeader { .. }, "", false;
    }
    let body = unread[9..];
    let flen = hdr.length as i64;
    guard body.len >= flen else {
        return WireFrameHeader { .. }, "", false;
    }
    let payload = body[..flen];
    let total_size = (flen + 9);
    r.cursor = r.cursor + total_size;
    return hdr, payload, true;
}
