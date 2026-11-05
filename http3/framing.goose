// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Frame Codec and Stream Invariant Enforcer.
// Conforms to RFC 9114 Section 7 (HTTP/3 Framing) and RFC 9204 Section 5.
namespace internal;

import std;

// ---- Frame Headers and Settings Structures -------------------------------

struct H3FrameHeader {
    frame_type:  u64 = 0,
    payload_len: u64 = 0,
    header_len:  u64 = 0,
}

// ---- Frame Header Encoding & Decoding -----------------------------------

// Parses an HTTP/3 frame header (Type: VarInt, Length: VarInt).
//
// Example:
//   src = [0x00, 0x05], offset = 0
//   returns: H3FrameHeader { frame_type: 0, payload_len: 5, header_len: 2 }, true
fn parse_h3_frame_header(src: const u8[:], offset: u64) -> H3FrameHeader, bool {
    let ftype, off1, ok1 = quic_decode_varint(src, offset);
    guard ok1 else { return H3FrameHeader { .. }, false; }

    let plen, off2, ok2 = quic_decode_varint(src, off1);
    guard ok2 else { return H3FrameHeader { .. }, false; }

    return H3FrameHeader {
        frame_type:  ftype,
        payload_len: plen,
        header_len:  off2 - offset,
    }, true;
}

inline fn append_h3_frame_parts(out: u8[>..]&, hdr: const u8[:], payload: const u8[:]) -> bool {
    out.append(hdr);
    out.append(payload);
    return true;
}

inline fn append_h3_frame_parts<B>(out: B&, hdr: const u8[:], payload: const u8[:]) -> bool {
    let need = core::add_sat_i64(hdr.len, payload.len);
    guard core::add_sat_i64(out.len, need) <= out.cap else { return false; }
    out.append(hdr);
    out.append(payload);
    return true;
}

// Encodes an HTTP/3 frame header (Type: VarInt, Length: VarInt) into buffer.
fn encode_h3_frame_header<B>(out: B&, frame_type: u64, payload_len: u64) -> bool {
    var hdr: u8[..16] = [];
    let ok_t = quic_encode_varint(hdr, frame_type);
    let ok_l = quic_encode_varint(hdr, payload_len);
    guard ok_t && ok_l else { return false; }
    let empty: u8[0] = [];
    return append_h3_frame_parts(out, hdr[..], empty[..]);
}

// ---- DATA & HEADERS Frames (RFC 9114 Sections 7.2.1 and 7.2.2) -----------

// Encodes a DATA frame (Type 0x00).
fn encode_h3_data_frame<B>(out: B&, data: const u8[:]) -> bool {
    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_DATA, data.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], data);
}

// Encodes a HEADERS frame (Type 0x01).
fn encode_h3_headers_frame<B>(out: B&, qpack_field_section: const u8[:]) -> bool {
    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_HEADERS, qpack_field_section.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], qpack_field_section);
}

// Encodes a PUSH_PROMISE frame (Type 0x05, RFC 9114 Section 7.2.5).
fn encode_h3_push_promise<B>(out: B&, push_id: u64, qpack_field_section: const u8[:]) -> bool {
    var pid_buf: u8[..8] = [];
    guard quic_encode_varint(pid_buf, push_id) else { return false; }
    let plen = (pid_buf.len as u64) + (qpack_field_section.len as u64);
    var hdr: u8[..24] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_PUSH_PROMISE, plen) else { return false; }
    hdr.append(pid_buf[..]);
    return append_h3_frame_parts(out, hdr[..], qpack_field_section);
}

// ---- SETTINGS Frame (RFC 9114 Section 7.2.4 & RFC 9204 Section 5) --------

// Encodes a SETTINGS frame (Type 0x04).
fn encode_h3_settings_frame<B>(out: B&, settings: const H3Settings&) -> bool {
    // Build payload first in a temporary stack buffer
    var payload: u8[..64] = [];

    // 1. QPACK_MAX_TABLE_CAPACITY (0x01)
    quic_encode_varint(payload, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
    quic_encode_varint(payload, settings.qpack_max_table_capacity);

    // 2. MAX_FIELD_SECTION_SIZE (0x06)
    quic_encode_varint(payload, rfc::H3_SETTING_MAX_FIELD_SECTION_SIZE);
    quic_encode_varint(payload, settings.max_field_section_size);

    // 3. QPACK_BLOCKED_STREAMS (0x07)
    quic_encode_varint(payload, rfc::H3_SETTING_QPACK_BLOCKED_STREAMS);
    quic_encode_varint(payload, settings.qpack_blocked_streams);

    // 4. ENABLE_CONNECT_PROTOCOL (0x08)
    if settings.enable_connect_protocol > 0 {
        quic_encode_varint(payload, rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL);
        quic_encode_varint(payload, settings.enable_connect_protocol);
    }

    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_SETTINGS, payload.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Records a setting identifier into the seen list, ensuring uniqueness (RFC 9114 §7.2.4).
fn record_setting_identifier(seen: u64[..64]&, id: u64) -> bool {
    var i: i64 = 0;
    while i < seen.len {
        if seen[i] == id {
            return false;
        }
        i = i + 1;
    }
    guard seen.len < seen.cap else {
        return false;
    }
    seen.push(id);
    return true;
}

// Parses and validates a SETTINGS frame payload.
// Returns H3_ERR_NO_ERROR (0x0100) on success, or appropriate error code:
// - H3_ERR_SETTINGS_ERROR (0x0109) on duplicate settings or forbidden HTTP/2 settings (0x02..0x05)
// - H3_ERR_FRAME_ERROR (0x0106) on truncated payload.
//
// Example:
//   payload = [0x06, 0x40, 0x00], out_settings = H3Settings { .. }
//   returns: H3_ERR_NO_ERROR (0x0100), populates out_settings
fn parse_h3_settings_frame(payload: const u8[:], out_settings: H3Settings&) -> u64 {
    var offset: u64 = 0;
    let total = payload.len as u64;
    var seen_ids: u64[..64] = [];

    while offset < total {
        let id, off1, ok1 = quic_decode_varint(payload, offset);
        guard ok1 else { return rfc::H3_ERR_FRAME_ERROR; }

        let val, off2, ok2 = quic_decode_varint(payload, off1);
        guard ok2 else { return rfc::H3_ERR_FRAME_ERROR; }

        offset = off2;

        // RFC 9114 Section 7.2.4.1: An endpoint that receives any reserved HTTP/2 setting identifier
        // (0x00, 0x02, 0x03, 0x04, 0x05) MUST treat this as a connection error of type H3_SETTINGS_ERROR.
        if rfc::is_h2_reserved_setting_in_h3(id) {
            return rfc::H3_ERR_SETTINGS_ERROR;
        }

        // Duplicate checks (RFC 9114 Section 7.2.4):
        // The same setting identifier MUST NOT occur more than once.
        guard record_setting_identifier(seen_ids, id) else {
            return rfc::H3_ERR_SETTINGS_ERROR;
        }

        if id == rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY {
            out_settings.qpack_max_table_capacity = val;
        } else if id == rfc::H3_SETTING_MAX_FIELD_SECTION_SIZE {
            out_settings.max_field_section_size = val;
        } else if id == rfc::H3_SETTING_QPACK_BLOCKED_STREAMS {
            out_settings.qpack_blocked_streams = val;
        } else if id == rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL {
            if val != 0 && val != 1 { return rfc::H3_ERR_SETTINGS_ERROR; }
            out_settings.enable_connect_protocol = val;
        } else {
            // Unknown or GREASE settings identifiers are ignored (RFC 9114 Section 7.2.4.1)
        }
    }

    return rfc::H3_ERR_NO_ERROR;
}

// ---- GOAWAY, CANCEL_PUSH, and MAX_PUSH_ID Frames ------------------------

// Encodes a GOAWAY frame (Type 0x07).
fn encode_h3_goaway_frame<B>(out: B&, stream_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic_encode_varint(payload, stream_id) else { return false; }
    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_GOAWAY, payload.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a GOAWAY frame payload.
//
// Example:
//   payload = [0x04]
//   returns: stream_id = 4, true
fn parse_h3_goaway_frame(payload: const u8[:]) -> u64, bool {
    let stream_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return stream_id, true;
}

// Encodes a CANCEL_PUSH frame (Type 0x03).
fn encode_h3_cancel_push<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic_encode_varint(payload, push_id) else { return false; }
    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_CANCEL_PUSH, payload.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a CANCEL_PUSH frame payload.
//
// Example:
//   payload = [0x02]
//   returns: push_id = 2, true
fn parse_h3_cancel_push(payload: const u8[:]) -> u64, bool {
    let push_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// Encodes a MAX_PUSH_ID frame (Type 0x0D).
fn encode_h3_max_push_id<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic_encode_varint(payload, push_id) else { return false; }
    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_MAX_PUSH_ID, payload.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a MAX_PUSH_ID frame payload.
//
// Example:
//   payload = [0x08]
//   returns: push_id = 8, true
fn parse_h3_max_push_id(payload: const u8[:]) -> u64, bool {
    let push_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// ---- RFC 9218 PRIORITY_UPDATE Frames for HTTP/3 --------------------------

// Encodes a PRIORITY_UPDATE frame for a request stream (RFC 9218 Section 7.2, Type 0xF0700).
fn encode_h3_priority_update_request<B>(out: B&, stream_id: u64, prio: const wing::PriorityParam&) -> bool {
    var payload: u8[..64] = [];
    guard quic_encode_varint(payload, stream_id) else { return false; }
    wing::serialize_http_priority(prio, payload);
    var hdr: u8[..16] = [];
    let plen = payload.len as u64;
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST, plen) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a PRIORITY_UPDATE frame for a request stream (RFC 9218 Section 7.2).
// Returns (prioritized_stream_id, PriorityParam, ok).
//
// Example:
//   payload = [0x04, 'u', '=', '3']
//   returns: stream_id = 4, prio = { urgency: 3, incremental: false }, ok = true
fn parse_h3_priority_update_request(
    payload:             const u8[:],
    default_incremental: bool = false,
) -> u64, wing::PriorityParam, bool {
    var prio = wing::PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, prio, false; }
    let stream_id, off, ok = quic_decode_varint(payload, 0);
    guard ok else { return 0, prio, false; }
    let field_value = payload[off..];
    let parsed, ok_prio = wing::parse_http_priority(field_value, default_incremental);
    guard ok_prio else { return stream_id, prio, false; }
    return stream_id, parsed, true;
}

// Encodes a PRIORITY_UPDATE frame for a push stream (RFC 9218 Section 7.2, Type 0xF0701).
fn encode_h3_priority_update_push<B>(out: B&, push_id: u64, prio: const wing::PriorityParam&) -> bool {
    var payload: u8[..64] = [];
    guard quic_encode_varint(payload, push_id) else { return false; }
    wing::serialize_http_priority(prio, payload);
    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_PRIORITY_UPDATE_PUSH, payload.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a PRIORITY_UPDATE frame for a push stream (RFC 9218 Section 7.2).
//
// Example:
//   payload = [0x01, 'u', '=', '5']
//   returns: push_id = 1, prio = { urgency: 5, incremental: false }, ok = true
fn parse_h3_priority_update_push(
    payload:             const u8[:],
    default_incremental: bool = false,
) -> u64, wing::PriorityParam, bool {
    var prio = wing::PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, prio, false; }
    let push_id, off, ok = quic_decode_varint(payload, 0);
    guard ok else { return 0, prio, false; }
    let field_value = payload[off..];
    let parsed, ok_prio = wing::parse_http_priority(field_value, default_incremental);
    guard ok_prio else { return push_id, prio, false; }
    return push_id, parsed, true;
}
