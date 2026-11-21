// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 binary wire frame encoders, decoders, and frame stream readers (RFC 9113, RFC 9218).
namespace wire;

import std;
import core from "..";
import http.headers;
import http2.hpack;
import .types;
import .hpack;

// Appends 9 serialized header bytes to any buffer (RFC 9113 Section 4.1).
fn encode_frame_header<B>(hdr: const WireFrameHeader&, out: B&) -> bool {
    guard hdr.length <= rfc::H2_MAX_FRAME_SIZE_LIMIT && hdr.stream_id <= 0x7FFFFFFF else {
        return false;
    }
    var bytes: u8[..9] = [];
    bytes.append_u24_be(hdr.length);
    bytes.push(hdr.frame_type);
    bytes.push(hdr.flags);
    bytes.append_u32_be(hdr.stream_id & 0x7FFFFFFF);
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
        return hdr, 0, false;
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

inline fn is_valid_wire_setting(s: const WireSetting&) -> bool {
    if s.id == rfc::H2_SETTING_ENABLE_PUSH
        || s.id == rfc::H2_SETTING_ENABLE_CONNECT_PROTO
        || s.id == rfc::H2_SETTING_NO_RFC7540_PRIORITIES {
        return s.val <= 1;
    }
    if s.id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE {
        return s.val <= rfc::H2_MAX_WINDOW_SIZE;
    }
    if s.id == rfc::H2_SETTING_MAX_FRAME_SIZE {
        return s.val >= rfc::H2_DEFAULT_MAX_FRAME_SIZE && s.val <= rfc::H2_MAX_FRAME_SIZE_LIMIT;
    }
    return true;
}

// Encodes an HTTP/2 SETTINGS frame with explicit parameter list (RFC 9113 Section 6.5).
fn encode_settings_frame<B>(settings: const WireSetting[:], out: B&) -> bool {
    let payload_len = (settings.len as u32) * 6;
    guard settings.len <= 2796202 else { return false; }
    for s in settings {
        guard is_valid_wire_setting(s) else { return false; }
    }
    let start_len = out.len;
    let hdr = WireFrameHeader {
        length:     payload_len,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      rfc::H2_FLAG_NONE,
        stream_id:  0,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    for s in settings {
        var entry: u8[..6] = [];
        entry.append_u16_be(s.id);
        entry.append_u32_be(s.val);
        guard out.try_append(entry[..]) else {
            out.resize(start_len);
            return false;
        }
    }
    return true;
}

// Encodes a WINDOW_UPDATE frame with explicit stream ID and increment (RFC 9113 Section 6.9).
fn encode_window_update_frame<B>(stream_id: u32, increment: u32, out: B&) -> bool {
    guard stream_id <= 0x7FFFFFFF && increment >= 1 && increment <= rfc::H2_MAX_WINDOW_SIZE else {
        return false;
    }
    let start_len = out.len;
    let hdr = WireFrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
        flags:      rfc::H2_FLAG_NONE,
        stream_id:  stream_id,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    var bytes: u8[..4] = [];
    bytes.append_u32_be(increment & 0x7FFFFFFF);
    guard out.try_append(bytes[..]) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

inline fn format_urgency_byte(urgency: u8) -> u8 {
    return '0' + urgency;
}

inline fn format_priority_params<B>(urgency: u8, incremental: bool, out: B&) -> bool {
    guard urgency <= 7 else { return false; }
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
    guard prioritized_stream_id > 0 && prioritized_stream_id <= 0x7FFFFFFF else { return false; }
    var p_val: u8[..32] = [];
    guard format_priority_params(urgency, incremental, p_val) else { return false; }

    let start_len = out.len;
    let payload_len = calc_priority_payload_len(p_val.len);
    let hdr = WireFrameHeader {
        length:     payload_len,
        frame_type: rfc::H2_FRAME_PRIORITY_UPDATE,
        flags:      rfc::H2_FLAG_NONE,
        stream_id:  0,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    var psid_bytes: u8[..4] = [];
    psid_bytes.append_u32_be(prioritized_stream_id & 0x7FFFFFFF);
    guard out.try_append(psid_bytes[..]) && out.try_append(p_val[..]) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

// Encodes a RST_STREAM frame (RFC 9113 Section 6.4).
fn encode_rst_stream_frame<B>(stream_id: u32, error_code: u32, out: B&) -> bool {
    guard stream_id > 0 && stream_id <= 0x7FFFFFFF else { return false; }
    let start_len = out.len;
    let hdr = WireFrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_RST_STREAM,
        flags:      rfc::H2_FLAG_NONE,
        stream_id:  stream_id,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    var err_bytes: u8[..4] = [];
    err_bytes.append_u32_be(error_code);
    guard out.try_append(err_bytes[..]) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

// Encodes a PING frame with 8-byte payload (RFC 9113 Section 6.7).
fn encode_ping_frame<B>(payload: const u8[8], is_ack: bool, out: B&) -> bool {
    let start_len = out.len;
    let hdr = WireFrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      if is_ack { rfc::H2_FLAG_ACK } else { rfc::H2_FLAG_NONE },
        stream_id:  0,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    guard out.try_append(payload[..]) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

inline fn select_data_frame_flags(end_stream: bool) -> u8 {
    return if end_stream { rfc::H2_FLAG_END_STREAM } else { rfc::H2_FLAG_NONE };
}

// Encodes a DATA frame (RFC 9113 Section 6.1).
fn encode_data_frame<B>(stream_id: u32, payload: const u8[:], end_stream: bool, out: B&) -> bool {
    guard stream_id > 0 && stream_id <= 0x7FFFFFFF &&
          payload.len <= (rfc::H2_MAX_FRAME_SIZE_LIMIT as i64) else {
        return false;
    }
    let start_len = out.len;
    let hdr = WireFrameHeader {
        length:     payload.len as u32,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      select_data_frame_flags(end_stream),
        stream_id:  stream_id,
    };
    guard encode_frame_header(hdr, out) else { return false; }
    guard out.try_append(payload) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

// Parses the next HTTP/2 frame from `raw` at `cursor` and slices its payload (RFC 9113 Section 4.1).
// Guarantees transactional cursor semantics: `cursor` remains unchanged on `false`.
//
// Example:
//   raw = [0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00], cursor = 0
//   returns: hdr.frame_type = 0x08, payload.len = 4, ok = true, cursor = 13
fn read_wire_h2_frame(raw: const u8[:], cursor: i64&) -> WireFrameHeader, const u8[:], bool {
    guard cursor >= 0 && cursor <= raw.len else {
        return WireFrameHeader { .. }, "", false;
    }
    let unread = raw[cursor..];
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
    cursor = core::add_sat_i64(cursor, core::add_sat_i64(flen, 9));
    return hdr, payload, true;
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
    return r.cursor >= 0 && core::add_sat_i64(r.cursor, 9) <= r.src.len;
}

// Parses the next HTTP/2 frame and slices its payload without memory allocations.
//
// Example:
//   r.src = [0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00], r.cursor = 0
//   returns: hdr.frame_type = 0x08, payload.len = 4, ok = true, r.cursor = 13
fn next_frame(r: WireH2FrameReader&) -> WireFrameHeader, const u8[:], bool {
    return read_wire_h2_frame(r.src, r.cursor);
}

inline fn calc_h2_headers_chunk_flags(f_type: u8, end_stream: bool, rem_after: i64) -> u8 {
    let es: u8 = if f_type == rfc::H2_FRAME_HEADERS && end_stream { rfc::H2_FLAG_END_STREAM } else { 0 };
    let eh: u8 = if rem_after <= 0 { rfc::H2_FLAG_END_HEADERS } else { 0 };
    return es | eh;
}

// Encodes an HTTP/2 HEADERS frame (and any required CONTINUATION frames when exceeding `max_frame_size`)
// directly from `pseudo` and `headers: const wing::HeaderMap&` using HPACK dynamic table `dt` (RFC 9113 §6.2).
//
// Example:
//   encode_h2_headers_frame_from_map(dt, 1, pseudo, headers, true, out, 16384)
//   returns: true, out contains 9-byte HEADERS frame header + HPACK block
fn emit_h2_headers_chunks<B>(
    stream_id:      u32,
    hpack_bytes:    const u8[:],
    end_stream:     bool,
    out:            B&,
    max_frame_size: u32,
) -> bool {
    let max_chunk = max_frame_size as i64;
    var offset: i64 = 0;
    var first = true;
    while first || offset < hpack_bytes.len {
        let rem = core::sub_sat_i64(hpack_bytes.len, offset);
        let chunk_len = min(rem, max_chunk);
        let rem_after = core::sub_sat_i64(rem, chunk_len);
        let next_off = core::add_sat_i64(offset, chunk_len);
        let f_type = if first { rfc::H2_FRAME_HEADERS } else { rfc::H2_FRAME_CONTINUATION };
        let hdr = WireFrameHeader {
            length:     chunk_len as u32,
            frame_type: f_type,
            flags:      calc_h2_headers_chunk_flags(f_type, end_stream, rem_after),
            stream_id:  stream_id,
        };
        guard encode_frame_header(hdr, out) && out.try_append(hpack_bytes[offset..next_off]) else {
            return false;
        }
        offset = next_off;
        first = false;
    }
    return true;
}

fn encode_h2_headers_frame_from_map<B>(
    dt:             http2::DynamicTable&,
    stream_id:      u32,
    pseudo:         const http2::PseudoHeaders&,
    headers:        const wing::HeaderMap&,
    end_stream:     bool,
    out:            B&,
    max_frame_size: u32 = 16384,
) -> bool {
    let is_1xx = pseudo.has_status && pseudo.status >= 100 && pseudo.status < 200;
    guard stream_id > 0 && stream_id <= 0x7FFFFFFF &&
          max_frame_size > 0 && max_frame_size <= rfc::H2_MAX_FRAME_SIZE_LIMIT &&
          (!pseudo.is_trailer || end_stream) && !(is_1xx && end_stream) else {
        return false;
    }
    let saved_dt = dt;
    let start_len = out.len;
    var committed = false;
    defer if !committed {
        out.resize(start_len);
        dt = saved_dt;
    };

    var hpack_buf: u8[..16384] = [];
    guard encode_hpack_from_map(dt, pseudo, headers, hpack_buf, true) else { return false; }
    guard emit_h2_headers_chunks(stream_id, hpack_buf[..], end_stream, out, max_frame_size) else {
        return false;
    }
    committed = true;
    return true;
}

// Encodes HTTP/2 pseudo-headers and `HeaderMap` into a HEADERS frame (and any
// required CONTINUATION frames) using a stateful `WireHpackState`, rolling back
// `out` and `state` cleanly on failure (RFC 9113 Sections 6.2, 6.10).
//
// Example:
//   let ok = wire::encode_h2_headers_frame_from_map(st, 1, pseudo, hdrs, true, out);
//   returns: true with framed HTTP/2 HEADERS (+CONTINUATION) bytes appended to `out`
fn encode_h2_headers_frame_from_map<B>(
    state:          WireHpackState&,
    stream_id:      u32,
    pseudo:         const WireH2PseudoHeaders&,
    headers:        const wing::HeaderMap&,
    end_stream:     bool,
    out:            B&,
    max_frame_size: u32 = 16384,
) -> bool {
    let is_1xx = pseudo.has_status && pseudo.status >= 100 && pseudo.status < 200;
    guard stream_id > 0 && stream_id <= 0x7FFFFFFF &&
          max_frame_size > 0 && max_frame_size <= rfc::H2_MAX_FRAME_SIZE_LIMIT &&
          (!pseudo.is_trailer || end_stream) && !(is_1xx && end_stream) else {
        return false;
    }
    let saved_state = state;
    let start_len = out.len;
    var committed = false;
    defer if !committed {
        out.resize(start_len);
        state = saved_state;
    };

    var hpack_buf: u8[..16384] = [];
    guard hpack_encode_header_block(state, pseudo, headers, hpack_buf, true) else { return false; }
    guard emit_h2_headers_chunks(stream_id, hpack_buf[..], end_stream, out, max_frame_size) else {
        return false;
    }
    committed = true;
    return true;
}

// Decodes a 9-byte HTTP/2 frame header and validates RFC 9113 §4.1–4.2 size bounds.
//
// Example:
//   raw = [0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]
//   returns: WireFrameHeader { length: 4, frame_type: 0, flags: 1, stream_id: 1 }, rfc::H2_ERR_NO_ERROR
fn decode_h2_frame_header(raw: const u8[:], max_frame_size: u32 = 16384) -> WireFrameHeader, u32 {
    let hdr, _, ok = parse_frame_header(raw);
    guard ok else {
        return hdr, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    let f_hdr = http2::FrameHeader {
        length:     hdr.length,
        frame_type: hdr.frame_type,
        flags:      hdr.flags,
        stream_id:  hdr.stream_id,
    };
    return hdr, http2::validate_frame_header_rules(f_hdr, max_frame_size);
}
