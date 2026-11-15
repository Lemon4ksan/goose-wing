// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Frame Codec and Stream Invariant Enforcer.
// Conforms to RFC 9114 Section 7 (HTTP/3 Framing) and RFC 9204 Section 5.
namespace h3_internal;

import std;
import core from "..";

// ---- Frame Headers and Settings Structures -------------------------------

// RFC 8336 Section 2: The ORIGIN HTTP/2 Frame - Frame type 0x0c.
const H3_FRAME_ORIGIN:                       u64 = 0x0c;
const H3_SETTINGS_H3_DATAGRAM:               u64 = 0x33;       // RFC 9297 §2.1.1
const H3_SETTINGS_H3_DATAGRAM_DRAFT00:       u64 = 0x276;      // draft-ietf-masque-h3-datagram-00
const H3_SETTINGS_ENABLE_WEBTRANSPORT:       u64 = 0x2b603742; // draft-ietf-webtrans-http3
const H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0xc671706a; // draft-ietf-webtrans-http3 §3.1
const H3_MAX_SETTINGS_PAYLOAD_SIZE:          i64 = 256;        // RFC 9114 §7.2.4

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
    let ftype, off1, ok1 = quic_internal::quic_decode_varint(src, offset);
    guard ok1 else { return H3FrameHeader { .. }, false; }

    let plen, off2, ok2 = quic_internal::quic_decode_varint(src, off1);
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
    let ok_t = quic_internal::quic_encode_varint(hdr, frame_type);
    let ok_l = quic_internal::quic_encode_varint(hdr, payload_len);
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
    guard quic_internal::quic_encode_varint(pid_buf, push_id) else { return false; }
    let plen = (pid_buf.len as u64) + (qpack_field_section.len as u64);
    var hdr: u8[..24] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_PUSH_PROMISE, plen) else { return false; }
    hdr.append(pid_buf[..]);
    return append_h3_frame_parts(out, hdr[..], qpack_field_section);
}

// ---- SETTINGS Frame (RFC 9114 Section 7.2.4 & RFC 9204 Section 5) --------

// Encodes a SETTINGS frame (Type 0x04).
fn encode_h3_settings_frame<B>(out: B&, settings: const H3Settings&) -> bool {
    // RFC 9220 Section 3: WebSockets Upgrade over HTTP/3 - SETTINGS_ENABLE_CONNECT_PROTOCOL value MUST be 0 or 1.
    guard settings.enable_connect_protocol <= 1 &&
          settings.h3_datagram <= 1 &&
          settings.enable_webtransport <= 1 else {
        return false;
    }

    var payload: u8[..128] = [];
    guard quic_internal::quic_encode_varint(payload, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY) &&
          quic_internal::quic_encode_varint(payload, settings.qpack_max_table_capacity) &&
          quic_internal::quic_encode_varint(payload, rfc::H3_SETTING_MAX_FIELD_SECTION_SIZE) &&
          quic_internal::quic_encode_varint(payload, settings.max_field_section_size) &&
          quic_internal::quic_encode_varint(payload, rfc::H3_SETTING_QPACK_BLOCKED_STREAMS) &&
          quic_internal::quic_encode_varint(payload, settings.qpack_blocked_streams) else {
        return false;
    }

    if settings.enable_connect_protocol > 0 {
        guard quic_internal::quic_encode_varint(payload, rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL) &&
              quic_internal::quic_encode_varint(payload, settings.enable_connect_protocol) else {
            return false;
        }
    }

    if settings.h3_datagram > 0 {
        guard quic_internal::quic_encode_varint(payload, H3_SETTINGS_H3_DATAGRAM) &&
              quic_internal::quic_encode_varint(payload, settings.h3_datagram) else {
            return false;
        }
    }

    if settings.enable_webtransport > 0 {
        guard quic_internal::quic_encode_varint(payload, H3_SETTINGS_ENABLE_WEBTRANSPORT) &&
              quic_internal::quic_encode_varint(payload, settings.enable_webtransport) else {
            return false;
        }
    }

    if settings.webtransport_max_sessions > 0 {
        guard quic_internal::quic_encode_varint(payload, H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS) &&
              quic_internal::quic_encode_varint(payload, settings.webtransport_max_sessions) else {
            return false;
        }
    }

    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, rfc::H3_FRAME_SETTINGS, payload.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// RFC 9114 Section 7.2.4: SETTINGS - Each setting identifier MUST NOT appear more than once.
fn record_setting_identifier(seen: u64[..128]&, id: u64) -> bool {
    for s in seen {
        if s == id {
            return false;
        }
    }
    return seen.try_push(id);
}

inline fn apply_parsed_h3_setting(id: u64, val: u64, out_settings: H3Settings&) -> bool {
    if id == rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY {
        out_settings.qpack_max_table_capacity = val;
        return true;
    }
    if id == rfc::H3_SETTING_MAX_FIELD_SECTION_SIZE {
        out_settings.max_field_section_size = val;
        return true;
    }
    if id == rfc::H3_SETTING_QPACK_BLOCKED_STREAMS {
        out_settings.qpack_blocked_streams = val;
        return true;
    }
    if id == rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL {
        guard val <= 1 else { return false; }
        out_settings.enable_connect_protocol = val;
        return true;
    }
    if id == H3_SETTINGS_H3_DATAGRAM || id == H3_SETTINGS_H3_DATAGRAM_DRAFT00 {
        guard val <= 1 else { return false; }
        out_settings.h3_datagram = val;
        return true;
    }
    if id == H3_SETTINGS_ENABLE_WEBTRANSPORT {
        guard val <= 1 else { return false; }
        out_settings.enable_webtransport = val;
        return true;
    }
    if id == H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS {
        out_settings.webtransport_max_sessions = val;
        return true;
    }
    return true;
}

// Parses and validates a SETTINGS frame payload.
// Returns H3_ERR_NO_ERROR (0x0100) on success, or appropriate error code:
// - H3_ERR_EXCESSIVE_LOAD (0x0107) on oversized payload (> H3_MAX_SETTINGS_PAYLOAD_SIZE)
// - H3_ERR_SETTINGS_ERROR (0x0109) on duplicate settings or forbidden HTTP/2 settings (0x02..0x05)
// - H3_ERR_FRAME_ERROR (0x0106) on truncated payload.
//
// Example:
//   payload = [0x06, 0x40, 0x00], out_settings = H3Settings { .. }
//   returns: H3_ERR_NO_ERROR (0x0100), populates out_settings
fn parse_h3_settings_frame(payload: const u8[:], out_settings: H3Settings&) -> u64 {
    guard payload.len <= H3_MAX_SETTINGS_PAYLOAD_SIZE else {
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    let saved_settings = out_settings;
    var committed = false;
    defer if !committed { out_settings = saved_settings; };

    var offset: u64 = 0;
    let total = payload.len as u64;
    var seen_ids: u64[..128] = [];

    while offset < total {
        let id, off1, ok1 = quic_internal::quic_decode_varint(payload, offset);
        guard ok1 else { return rfc::H3_ERR_FRAME_ERROR; }

        let val, off2, ok2 = quic_internal::quic_decode_varint(payload, off1);
        guard ok2 else { return rfc::H3_ERR_FRAME_ERROR; }

        offset = off2;

        guard !rfc::is_h2_reserved_setting_in_h3(id) &&
              record_setting_identifier(seen_ids, id) &&
              apply_parsed_h3_setting(id, val, out_settings) else {
            return rfc::H3_ERR_SETTINGS_ERROR;
        }
    }

    committed = true;
    return rfc::H3_ERR_NO_ERROR;
}

// ---- GOAWAY, CANCEL_PUSH, and MAX_PUSH_ID Frames ------------------------

// Encodes a GOAWAY frame (Type 0x07).
fn encode_h3_goaway_frame<B>(out: B&, stream_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic_internal::quic_encode_varint(payload, stream_id) else { return false; }
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
    let stream_id, off, ok = quic_internal::quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return stream_id, true;
}

// Encodes a CANCEL_PUSH frame (Type 0x03).
fn encode_h3_cancel_push<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic_internal::quic_encode_varint(payload, push_id) else { return false; }
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
    let push_id, off, ok = quic_internal::quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// Encodes a MAX_PUSH_ID frame (Type 0x0D).
fn encode_h3_max_push_id<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic_internal::quic_encode_varint(payload, push_id) else { return false; }
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
    let push_id, off, ok = quic_internal::quic_decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// ---- RFC 9218 PRIORITY_UPDATE Frames for HTTP/3 --------------------------

inline fn apply_h3_priority_entry(
    entry: const wing::SfDictEntry&,
    prio:  wing::PriorityParam&,
) -> bool {
    if entry.key == "u" {
        if !entry.is_inner_list &&
           entry.item.kind == wing::SfType.Integer &&
           wing::is_valid_urgency(entry.item.int_val) {
            prio.urgency = entry.item.int_val as u8;
        }
        return true;
    }
    if entry.key == "i" {
        if !entry.is_inner_list && entry.item.kind == wing::SfType.Boolean {
            prio.incremental = entry.item.bool_val;
        }
        return true;
    }
    return true;
}

// RFC 9218 Section 4: Priority Parameters - Receivers MUST ignore unrecognized parameters and out-of-range urgency values.
//
// Example:
//   field_value = "u=1, i", default_incremental = false
//   returns: { urgency: 1, incremental: true }, true
fn parse_h3_priority_field_value(
    field_value:         const u8[:],
    default_incremental: bool = false,
) -> wing::PriorityParam, bool {
    var prio = wing::PriorityParam { urgency: 3, incremental: default_incremental };
    let trimmed = field_value.trim_ascii_space();
    if trimmed.len == 0 {
        return prio, true;
    }
    var entries: wing::SfDictEntry[..16] = [];
    guard wing::parse_sf_dict(trimmed, entries) else { return prio, false; }
    for &entry in entries {
        guard apply_h3_priority_entry(entry, prio) else { return prio, false; }
    }
    return prio, true;
}

// RFC 9218 Section 7.2: HTTP/3 PRIORITY_UPDATE Frame - Request-stream Prioritized Element ID MUST be a client-initiated bidirectional stream ID.
fn encode_h3_priority_update_request<B>(out: B&, stream_id: u64, prio: const wing::PriorityParam&) -> bool {
    guard (stream_id & 0x03) == 0 && prio.urgency <= 7 else { return false; }
    var payload: u8[..64] = [];
    guard quic_internal::quic_encode_varint(payload, stream_id) else { return false; }
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
    let default_prio = wing::PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, default_prio, false; }
    let stream_id, off, ok = quic_internal::quic_decode_varint(payload, 0);
    guard ok else { return 0, default_prio, false; }
    let parsed, ok_prio = parse_h3_priority_field_value(payload[off..], default_incremental);
    guard ok_prio else { return stream_id, default_prio, false; }
    return stream_id, parsed, true;
}

// Encodes a PRIORITY_UPDATE frame for a push stream (RFC 9218 Section 7.2, Type 0xF0701).
fn encode_h3_priority_update_push<B>(out: B&, push_id: u64, prio: const wing::PriorityParam&) -> bool {
    guard prio.urgency <= 7 else { return false; }
    var payload: u8[..64] = [];
    guard quic_internal::quic_encode_varint(payload, push_id) else { return false; }
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
    let default_prio = wing::PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, default_prio, false; }
    let push_id, off, ok = quic_internal::quic_decode_varint(payload, 0);
    guard ok else { return 0, default_prio, false; }
    let parsed, ok_prio = parse_h3_priority_field_value(payload[off..], default_incremental);
    guard ok_prio else { return push_id, default_prio, false; }
    return push_id, parsed, true;
}

// ---- RFC 8336 ORIGIN Frame for HTTP/3 ------------------------------------

inline fn is_valid_ascii_origin(entry: const u8[:]) -> bool {
    guard entry.len > 0 else { return false; }
    for b in entry {
        guard core::is_ascii_vchar(b) else { return false; }
    }
    return true;
}

// RFC 8336 Section 2.1: Syntax - Encodes an ORIGIN frame (Type 0x0c) containing ASCII-Origin entries.
fn encode_h3_origin_frame<B>(out: B&, origins: const (const u8[:])[:]) -> bool {
    var payload: u8[..2048] = [];
    for org in origins {
        let rem = core::sub_sat_i64(payload.cap, payload.len);
        guard is_valid_ascii_origin(org) && org.len <= 0xFFFF && core::sub_sat_i64(rem, 2) >= org.len else {
            return false;
        }
        payload.append_u16_be(org.len as u16);
        payload.append(org);
    }
    var hdr: u8[..16] = [];
    guard encode_h3_frame_header(hdr, H3_FRAME_ORIGIN, payload.len as u64) else { return false; }
    return append_h3_frame_parts(out, hdr[..], payload[..]);
}

// RFC 8336 Section 2.1: Syntax - Each Origin-Entry is a serialized ASCII-Origin containing printable ASCII bytes.
// Rejects truncated 2-byte big-endian Origin-Len, 0-length entries, or non-VCHAR octets.
//
// Example:
//   payload = [0x00, 0x06, 'e', 'x', '.', 'c', 'o', 'm']
//   returns: true, out_origins = ["ex.com"]
fn parse_h3_origin_frame(payload: const u8[:], out_origins: u8[..128][..16]&) -> bool {
    let saved_len = out_origins.len;
    var committed = false;
    defer if !committed { out_origins.resize(saved_len); };

    var rem = payload;
    while rem.len > 0 {
        guard rem.len >= 2 else { return false; }
        let olen = core::read_be_u16(rem, 0) as i64;
        let after_hdr = rem[2..];
        guard olen > 0 && olen <= 128 && olen <= after_hdr.len else {
            return false;
        }
        let raw_origin = after_hdr[..olen];
        guard is_valid_ascii_origin(raw_origin) else { return false; }
        var entry: u8[..128] = [];
        guard entry.try_set(raw_origin) && out_origins.try_push(entry) else {
            return false;
        }
        rem = after_hdr[olen..];
    }
    committed = true;
    return true;
}
