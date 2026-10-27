// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Frame Codec and Stream Invariant Enforcer.
// Conforms to RFC 9114 Section 7 (HTTP/3 Framing) and RFC 9204 Section 5.
namespace wing;

import std;

// ---- 1. Frame Headers and Settings Structures -------------------------------

struct H3FrameHeader {
    frame_type: u64 = 0,
    payload_len: u64 = 0,
    header_len: u64 = 0,
}

// Checks if a frame type is a reserved GREASE frame (RFC 9114 Section 7.2.8: 0x1f * N + 0x21).
fn is_h3_grease_frame(frame_type: u64) -> bool {
    if frame_type < 0x21 { return false; }
    return ((frame_type - 0x21) % 0x1F) == 0;
}

// Checks if a frame type is reserved from HTTP/2 (RFC 9114 Section 7.2.8: 0x02, 0x06, 0x08, 0x09).
fn is_h2_reserved_frame_in_h3(frame_type: u64) -> bool {
    return frame_type == 0x02 || frame_type == 0x06 || frame_type == 0x08 || frame_type == 0x09;
}

// Checks if a frame is permitted on the HTTP/3 Control Stream (RFC 9114 Section 7.2).
// Permitted: SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, or GREASE/unknown.
// Strictly FORBIDDEN: DATA, HEADERS, PUSH_PROMISE, and HTTP/2-reserved types.
fn is_allowed_on_control_stream(frame_type: u64) -> bool {
    if is_h2_reserved_frame_in_h3(frame_type) { return false; }
    if frame_type == H3_FRAME_DATA || frame_type == H3_FRAME_HEADERS || frame_type == H3_FRAME_PUSH_PROMISE {
        return false;
    }
    return true;
}

// Checks if a frame is permitted on an HTTP/3 Request Stream (RFC 9114 Section 7.2 & RFC 9218 Section 7.2).
// Permitted: DATA, HEADERS, or GREASE/unknown.
// Strictly FORBIDDEN: SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, PRIORITY_UPDATE, and HTTP/2-reserved types.
fn is_allowed_on_request_stream(frame_type: u64) -> bool {
    if is_h2_reserved_frame_in_h3(frame_type) { return false; }
    if frame_type == H3_FRAME_SETTINGS || frame_type == H3_FRAME_GOAWAY ||
       frame_type == H3_FRAME_CANCEL_PUSH || frame_type == H3_FRAME_MAX_PUSH_ID ||
       frame_type == H3_FRAME_PRIORITY_UPDATE_REQUEST || frame_type == H3_FRAME_PRIORITY_UPDATE_PUSH {
        return false;
    }
    return true;
}

// ---- 2. Frame Header Encoding & Decoding -----------------------------------

// Parses an HTTP/3 frame header (Type: VarInt, Length: VarInt).
fn parse_h3_frame_header(src: const u8[:], offset: u64) -> H3FrameHeader, bool {
    let ftype, off1, ok1 = quic_decode_varint(src, offset);
    guard ok1 else { return H3FrameHeader { .. }, false; }

    let plen, off2, ok2 = quic_decode_varint(src, off1);
    guard ok2 else { return H3FrameHeader { .. }, false; }

    return H3FrameHeader {
        frame_type: ftype,
        payload_len: plen,
        header_len: off2 - offset,
    }, true;
}

// Encodes an HTTP/3 frame header (Type: VarInt, Length: VarInt) into buffer.
fn encode_h3_frame_header<B>(out: B&, frame_type: u64, payload_len: u64) -> bool {
    let ok_t = quic_encode_varint(out, frame_type);
    let ok_l = quic_encode_varint(out, payload_len);
    return ok_t && ok_l;
}

// ---- 3. DATA & HEADERS Frames (RFC 9114 Sections 7.2.1 and 7.2.2) -----------

// Encodes a DATA frame (Type 0x00).
fn encode_h3_data_frame<B>(out: B&, data: const u8[:]) -> bool {
    let ok_hdr = encode_h3_frame_header(out, H3_FRAME_DATA, data.len as u64);
    guard ok_hdr else { return false; }
    out.append(data);
    return true;
}

// Encodes a HEADERS frame (Type 0x01).
fn encode_h3_headers_frame<B>(out: B&, qpack_field_section: const u8[:]) -> bool {
    let ok_hdr = encode_h3_frame_header(out, H3_FRAME_HEADERS, qpack_field_section.len as u64);
    guard ok_hdr else { return false; }
    out.append(qpack_field_section);
    return true;
}

// ---- 4. SETTINGS Frame (RFC 9114 Section 7.2.4 & RFC 9204 Section 5) --------

// Encodes a SETTINGS frame (Type 0x04).
fn encode_h3_settings_frame<B>(out: B&, settings: const H3Settings&) -> bool {
    // Build payload first in a temporary stack buffer
    var payload: u8[..64] = [];

    // 1. QPACK_MAX_TABLE_CAPACITY (0x01)
    quic_encode_varint(payload, H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
    quic_encode_varint(payload, settings.qpack_max_table_capacity);

    // 2. MAX_FIELD_SECTION_SIZE (0x06)
    quic_encode_varint(payload, H3_SETTING_MAX_FIELD_SECTION_SIZE);
    quic_encode_varint(payload, settings.max_field_section_size);

    // 3. QPACK_BLOCKED_STREAMS (0x07)
    quic_encode_varint(payload, H3_SETTING_QPACK_BLOCKED_STREAMS);
    quic_encode_varint(payload, settings.qpack_blocked_streams);

    // 4. ENABLE_CONNECT_PROTOCOL (0x08)
    if settings.enable_connect_protocol > 0 {
        quic_encode_varint(payload, H3_SETTING_ENABLE_CONNECT_PROTOCOL);
        quic_encode_varint(payload, settings.enable_connect_protocol);
    }

    let ok_hdr = encode_h3_frame_header(out, H3_FRAME_SETTINGS, payload.len as u64);
    guard ok_hdr else { return false; }
    out.append(payload[..]);
    return true;
}

// Parses and validates a SETTINGS frame payload.
// Returns H3_ERR_NO_ERROR (0x0100) on success, or appropriate error code:
// - H3_ERR_SETTINGS_ERROR (0x0109) on duplicate settings or forbidden HTTP/2 settings (0x02..0x05)
// - H3_ERR_FRAME_ERROR (0x0106) on truncated payload.
fn parse_h3_settings_frame(payload: const u8[:], out_settings: H3Settings&) -> u64 {
    var offset: u64 = 0;
    let total = payload.len as u64;

    var seen_table_cap = false;
    var seen_section_size = false;
    var seen_blocked_streams = false;
    var seen_connect_proto = false;

    while offset < total {
        let id, off1, ok1 = quic_decode_varint(payload, offset);
        guard ok1 else { return H3_ERR_FRAME_ERROR; }

        let val, off2, ok2 = quic_decode_varint(payload, off1);
        guard ok2 else { return H3_ERR_FRAME_ERROR; }

        offset = off2;

        // RFC 9114 Section 7.2.4.1: An endpoint that receives any reserved HTTP/2 setting identifier
        // (0x00, 0x02, 0x03, 0x04, 0x05) MUST treat this as a connection error of type H3_SETTINGS_ERROR.
        if id == 0x00 || id == 0x02 || id == 0x03 || id == 0x04 || id == 0x05 {
            return H3_ERR_SETTINGS_ERROR;
        }

        // Duplicate checks (RFC 9114 Section 7.2.4)
        if id == H3_SETTING_QPACK_MAX_TABLE_CAPACITY {
            if seen_table_cap { return H3_ERR_SETTINGS_ERROR; }
            seen_table_cap = true;
            out_settings.qpack_max_table_capacity = val;
        } else if id == H3_SETTING_MAX_FIELD_SECTION_SIZE {
            if seen_section_size { return H3_ERR_SETTINGS_ERROR; }
            seen_section_size = true;
            out_settings.max_field_section_size = val;
        } else if id == H3_SETTING_QPACK_BLOCKED_STREAMS {
            if seen_blocked_streams { return H3_ERR_SETTINGS_ERROR; }
            seen_blocked_streams = true;
            out_settings.qpack_blocked_streams = val;
        } else if id == H3_SETTING_ENABLE_CONNECT_PROTOCOL {
            if seen_connect_proto { return H3_ERR_SETTINGS_ERROR; }
            if val != 0 && val != 1 { return H3_ERR_SETTINGS_ERROR; }
            seen_connect_proto = true;
            out_settings.enable_connect_protocol = val;
        } else {
            // Unknown or GREASE settings identifiers are ignored (RFC 9114 Section 7.2.4.1)
        }
    }

    return H3_ERR_NO_ERROR;
}

// ---- 5. GOAWAY, CANCEL_PUSH, and MAX_PUSH_ID Frames ------------------------

// Encodes a GOAWAY frame (Type 0x07).
fn encode_h3_goaway_frame<B>(out: B&, stream_id: u64) -> bool {
    var payload: u8[..8] = [];
    quic_encode_varint(payload, stream_id);
    let ok_hdr = encode_h3_frame_header(out, H3_FRAME_GOAWAY, payload.len as u64);
    guard ok_hdr else { return false; }
    out.append(payload[..]);
    return true;
}

// Parses a GOAWAY frame payload.
fn parse_h3_goaway_frame(payload: const u8[:]) -> u64, bool {
    let stream_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return stream_id, true;
}

// Encodes a CANCEL_PUSH frame (Type 0x03).
fn encode_h3_cancel_push<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    quic_encode_varint(payload, push_id);
    let ok_hdr = encode_h3_frame_header(out, H3_FRAME_CANCEL_PUSH, payload.len as u64);
    guard ok_hdr else { return false; }
    out.append(payload[..]);
    return true;
}

// Parses a CANCEL_PUSH frame payload.
fn parse_h3_cancel_push(payload: const u8[:]) -> u64, bool {
    let push_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// Encodes a MAX_PUSH_ID frame (Type 0x0D).
fn encode_h3_max_push_id<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    quic_encode_varint(payload, push_id);
    let ok_hdr = encode_h3_frame_header(out, H3_FRAME_MAX_PUSH_ID, payload.len as u64);
    guard ok_hdr else { return false; }
    out.append(payload[..]);
    return true;
}

// Parses a MAX_PUSH_ID frame payload.
fn parse_h3_max_push_id(payload: const u8[:]) -> u64, bool {
    let push_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// ---- 6. RFC 9218 PRIORITY_UPDATE Frames for HTTP/3 --------------------------

// Encodes a PRIORITY_UPDATE frame for a request stream (RFC 9218 Section 7.2, Type 0xF0700).
fn encode_h3_priority_update_request<B>(out: B&, stream_id: u64, prio: const PriorityParam&) -> bool {
    var payload: u8[..64] = [];
    guard quic_encode_varint(payload, stream_id) else { return false; }
    write_priority_param_rfc9218(prio, payload);
    guard encode_h3_frame_header(out, H3_FRAME_PRIORITY_UPDATE_REQUEST, payload.len as u64) else { return false; }
    out.append(payload[..]);
    return true;
}

// Parses a PRIORITY_UPDATE frame for a request stream (RFC 9218 Section 7.2).
// Returns (prioritized_stream_id, PriorityParam, ok).
fn parse_h3_priority_update_request(payload: const u8[:], default_incremental: bool = false) -> u64, PriorityParam, bool {
    var prio = PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, prio, false; }
    let stream_id, off, ok = quic_decode_varint(payload, 0);
    guard ok else { return 0, prio, false; }
    let field_value = payload[off..];
    let parsed, _ = parse_priority_param_rfc9218(field_value, default_incremental);
    return stream_id, parsed, true;
}

// Encodes a PRIORITY_UPDATE frame for a push stream (RFC 9218 Section 7.2, Type 0xF0701).
fn encode_h3_priority_update_push<B>(out: B&, push_id: u64, prio: const PriorityParam&) -> bool {
    var payload: u8[..64] = [];
    guard quic_encode_varint(payload, push_id) else { return false; }
    write_priority_param_rfc9218(prio, payload);
    guard encode_h3_frame_header(out, H3_FRAME_PRIORITY_UPDATE_PUSH, payload.len as u64) else { return false; }
    out.append(payload[..]);
    return true;
}

// Parses a PRIORITY_UPDATE frame for a push stream (RFC 9218 Section 7.2).
fn parse_h3_priority_update_push(payload: const u8[:], default_incremental: bool = false) -> u64, PriorityParam, bool {
    var prio = PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, prio, false; }
    let push_id, off, ok = quic_decode_varint(payload, 0);
    guard ok else { return 0, prio, false; }
    let field_value = payload[off..];
    let parsed, _ = parse_priority_param_rfc9218(field_value, default_incremental);
    return push_id, parsed, true;
}
