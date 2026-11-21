// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/3 Frame Codec and Stream Invariant Enforcer.
// Conforms to RFC 9114 Section 7 (HTTP/3 Framing) and RFC 9204 Section 5.
namespace http3;

import std;
import core from "..";
import rfc.h3_quic;
import http.priority;
import fingerprint.profile;
import quic.packet;
import .internal;
import .types;

// ---- Public HTTP/3 Framing Constants ---------------------------------------

// RFC 8336 Section 2: The ORIGIN HTTP/2 Frame - Frame type 0x0c.
const H3_FRAME_ORIGIN:         u64 = rfc::H3_FRAME_ORIGIN;
const H3_SETTINGS_H3_DATAGRAM: u64 = rfc::H3_SETTING_H3_DATAGRAM; // RFC 9297 §2.1.1

// ---- Frame Header Encoding & Decoding --------------------------------------

// Parses an HTTP/3 frame header (Type: VarInt, Length: VarInt).
//
// Example:
//   src = [0x00, 0x05], offset = 0
//   returns: FrameHeader { frame_type: 0, payload_len: 5, header_len: 2 }, true
fn parse_frame_header(src: const u8[:], offset: u64) -> FrameHeader, bool {
    let ftype, off1, ok1 = quic::decode_varint(src, offset);
    guard ok1 else { return FrameHeader { .. }, false; }

    let plen, off2, ok2 = quic::decode_varint(src, off1);
    guard ok2 else { return FrameHeader { .. }, false; }

    return FrameHeader {
        frame_type:  ftype,
        payload_len: plen,
        header_len:  off2 - offset,
    }, true;
}

// Encodes an HTTP/3 frame header (Type: VarInt, Length: VarInt) into buffer.
fn encode_frame_header<B>(out: B&, frame_type: u64, payload_len: u64) -> bool {
    var hdr: u8[..16] = [];
    let ok_t = quic::encode_varint(frame_type, hdr);
    let ok_l = quic::encode_varint(payload_len, hdr);
    guard ok_t && ok_l else { return false; }
    let empty: u8[0] = [];
    return h3_internal::append_h3_frame_parts(out, hdr[..], empty[..]);
}

// ---- DATA & HEADERS Frames (RFC 9114 Sections 7.2.1 and 7.2.2) --------------

// Encodes a DATA frame (Type 0x00).
fn encode_data_frame<B>(out: B&, data: const u8[:]) -> bool {
    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_DATA, data.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], data);
}

// Encodes a HEADERS frame (Type 0x01).
fn encode_headers_frame<B>(out: B&, qpack_field_section: const u8[:]) -> bool {
    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_HEADERS, qpack_field_section.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], qpack_field_section);
}

// Encodes a PUSH_PROMISE frame (Type 0x05, RFC 9114 Section 7.2.5).
fn encode_push_promise<B>(out: B&, push_id: u64, qpack_field_section: const u8[:]) -> bool {
    var pid_buf: u8[..8] = [];
    guard quic::encode_varint(push_id, pid_buf) else { return false; }
    let plen = (pid_buf.len as u64) + (qpack_field_section.len as u64);
    var hdr: u8[..24] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_PUSH_PROMISE, plen) else { return false; }
    hdr.append(pid_buf[..]);
    return h3_internal::append_h3_frame_parts(out, hdr[..], qpack_field_section);
}

// ---- SETTINGS Frame (RFC 9114 Section 7.2.4 & RFC 9204 Section 5) -----------

// Encodes a SETTINGS frame (Type 0x04).
fn encode_settings_frame<B>(out: B&, settings: const fingerprint::H3Settings&) -> bool {
    // RFC 9220 Section 3: WebSockets Upgrade over HTTP/3 - SETTINGS_ENABLE_CONNECT_PROTOCOL value MUST be 0 or 1.
    guard settings.enable_connect_protocol <= 1 &&
          settings.h3_datagram <= 1 &&
          settings.enable_webtransport <= 1 else {
        return false;
    }

    var payload: u8[..128] = [];
    guard quic::encode_varint(rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY, payload) &&
          quic::encode_varint(settings.qpack_max_table_capacity, payload) &&
          quic::encode_varint(rfc::H3_SETTING_MAX_FIELD_SECTION_SIZE, payload) &&
          quic::encode_varint(settings.max_field_section_size, payload) &&
          quic::encode_varint(rfc::H3_SETTING_QPACK_BLOCKED_STREAMS, payload) &&
          quic::encode_varint(settings.qpack_blocked_streams, payload) else {
        return false;
    }

    if settings.enable_connect_protocol > 0 {
        guard quic::encode_varint(rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL, payload) &&
              quic::encode_varint(settings.enable_connect_protocol, payload) else {
            return false;
        }
    }

    if settings.h3_datagram > 0 {
        guard quic::encode_varint(H3_SETTINGS_H3_DATAGRAM, payload) &&
              quic::encode_varint(settings.h3_datagram, payload) else {
            return false;
        }
    }

    if settings.enable_webtransport > 0 {
        guard quic::encode_varint(h3_internal::H3_SETTINGS_ENABLE_WEBTRANSPORT, payload) &&
              quic::encode_varint(settings.enable_webtransport, payload) else {
            return false;
        }
    }

    if settings.webtransport_max_sessions > 0 {
        guard quic::encode_varint(h3_internal::H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS, payload) &&
              quic::encode_varint(settings.webtransport_max_sessions, payload) else {
            return false;
        }
    }

    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_SETTINGS, payload.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses and validates a SETTINGS frame payload.
// Returns (H3Settings, error_code):
// - H3_ERR_NO_ERROR (0x0100) on success
// - H3_ERR_EXCESSIVE_LOAD (0x0107) on oversized payload (> H3_MAX_SETTINGS_PAYLOAD_SIZE)
// - H3_ERR_SETTINGS_ERROR (0x0109) on duplicate settings or forbidden HTTP/2 settings (0x02..0x05)
// - H3_ERR_FRAME_ERROR (0x0106) on truncated payload.
//
// Example:
//   payload = [0x06, 0x40, 0x00]
//   returns: H3Settings { max_field_section_size: 0, .. }, H3_ERR_NO_ERROR (0x0100)
fn parse_settings_frame(payload: const u8[:]) -> fingerprint::H3Settings, u64 {
    var settings = fingerprint::H3Settings { .. };
    guard payload.len <= h3_internal::H3_MAX_SETTINGS_PAYLOAD_SIZE else {
        return settings, rfc::H3_ERR_EXCESSIVE_LOAD;
    }

    var offset: u64 = 0;
    let total = payload.len as u64;
    var seen_ids: u64[..128] = [];

    while offset < total {
        let id, off1, ok1 = quic::decode_varint(payload, offset);
        guard ok1 else { return fingerprint::H3Settings { .. }, rfc::H3_ERR_FRAME_ERROR; }

        let val, off2, ok2 = quic::decode_varint(payload, off1);
        guard ok2 else { return fingerprint::H3Settings { .. }, rfc::H3_ERR_FRAME_ERROR; }

        offset = off2;

        guard !rfc::is_h2_reserved_setting_in_h3(id) &&
              h3_internal::record_setting_identifier(seen_ids, id) &&
              h3_internal::apply_parsed_h3_setting(id, val, settings) else {
            return fingerprint::H3Settings { .. }, rfc::H3_ERR_SETTINGS_ERROR;
        }
    }

    return settings, rfc::H3_ERR_NO_ERROR;
}

// ---- GOAWAY, CANCEL_PUSH, and MAX_PUSH_ID Frames ---------------------------

// Encodes a GOAWAY frame (Type 0x07).
fn encode_goaway_frame<B>(out: B&, stream_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic::encode_varint(stream_id, payload) else { return false; }
    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_GOAWAY, payload.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a GOAWAY frame payload.
//
// Example:
//   payload = [0x04]
//   returns: stream_id = 4, true
fn parse_goaway_frame(payload: const u8[:]) -> u64, bool {
    let stream_id, off, ok = quic::decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return stream_id, true;
}

// Encodes a CANCEL_PUSH frame (Type 0x03).
fn encode_cancel_push<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic::encode_varint(push_id, payload) else { return false; }
    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_CANCEL_PUSH, payload.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a CANCEL_PUSH frame payload.
//
// Example:
//   payload = [0x02]
//   returns: push_id = 2, true
fn parse_cancel_push(payload: const u8[:]) -> u64, bool {
    let push_id, off, ok = quic::decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// Encodes a MAX_PUSH_ID frame (Type 0x0D).
fn encode_max_push_id<B>(out: B&, push_id: u64) -> bool {
    var payload: u8[..8] = [];
    guard quic::encode_varint(push_id, payload) else { return false; }
    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_MAX_PUSH_ID, payload.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a MAX_PUSH_ID frame payload.
//
// Example:
//   payload = [0x08]
//   returns: push_id = 8, true
fn parse_max_push_id(payload: const u8[:]) -> u64, bool {
    let push_id, off, ok = quic::decode_varint(payload, 0);
    guard ok && off == (payload.len as u64) else { return 0, false; }
    return push_id, true;
}

// ---- RFC 9218 PRIORITY_UPDATE Frames for HTTP/3 ----------------------------

// RFC 9218 Section 7.2: HTTP/3 PRIORITY_UPDATE Frame - Request-stream Prioritized Element ID MUST be a client-initiated bidirectional stream ID.
fn encode_priority_update_request<B>(out: B&, stream_id: u64, prio: const wing::PriorityParam&) -> bool {
    guard (stream_id & 0x03) == 0 && prio.urgency <= 7 else { return false; }
    var payload: u8[..64] = [];
    guard quic::encode_varint(stream_id, payload) else { return false; }
    wing::serialize_http_priority(prio, payload);
    var hdr: u8[..16] = [];
    let plen = payload.len as u64;
    guard encode_frame_header(hdr, rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST, plen) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a PRIORITY_UPDATE frame for a request stream (RFC 9218 Section 7.2).
// Returns (prioritized_stream_id, PriorityParam, ok).
//
// Example:
//   payload = [0x04, 'u', '=', '3']
//   returns: stream_id = 4, prio = { urgency: 3, incremental: false }, ok = true
fn parse_priority_update_request(
    payload:             const u8[:],
    default_incremental: bool = false,
) -> u64, wing::PriorityParam, bool {
    let default_prio = wing::PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, default_prio, false; }
    let stream_id, off, ok = quic::decode_varint(payload, 0);
    guard ok else { return 0, default_prio, false; }
    let parsed, ok_prio = h3_internal::parse_h3_priority_field_value(payload[off..], default_incremental);
    guard ok_prio else { return stream_id, default_prio, false; }
    return stream_id, parsed, true;
}

// Encodes a PRIORITY_UPDATE frame for a push stream (RFC 9218 Section 7.2, Type 0xF0701).
fn encode_priority_update_push<B>(out: B&, push_id: u64, prio: const wing::PriorityParam&) -> bool {
    guard prio.urgency <= 7 else { return false; }
    var payload: u8[..64] = [];
    guard quic::encode_varint(push_id, payload) else { return false; }
    wing::serialize_http_priority(prio, payload);
    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, rfc::H3_FRAME_PRIORITY_UPDATE_PUSH, payload.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], payload[..]);
}

// Parses a PRIORITY_UPDATE frame for a push stream (RFC 9218 Section 7.2).
//
// Example:
//   payload = [0x01, 'u', '=', '5']
//   returns: push_id = 1, prio = { urgency: 5, incremental: false }, ok = true
fn parse_priority_update_push(
    payload:             const u8[:],
    default_incremental: bool = false,
) -> u64, wing::PriorityParam, bool {
    let default_prio = wing::PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len > 0 else { return 0, default_prio, false; }
    let push_id, off, ok = quic::decode_varint(payload, 0);
    guard ok else { return 0, default_prio, false; }
    let parsed, ok_prio = h3_internal::parse_h3_priority_field_value(payload[off..], default_incremental);
    guard ok_prio else { return push_id, default_prio, false; }
    return push_id, parsed, true;
}

// ---- RFC 8336 ORIGIN Frame for HTTP/3 --------------------------------------

// RFC 8336 Section 2.1: Syntax - Encodes an ORIGIN frame (Type 0x0c) containing ASCII-Origin entries.
fn encode_origin_frame<B>(out: B&, origins: const (const u8[:])[:]) -> bool {
    var payload: u8[..2048] = [];
    for org in origins {
        let rem = core::sub_sat_i64(payload.cap, payload.len);
        guard h3_internal::is_valid_ascii_origin(org) &&
              org.len <= 0xFFFF &&
              core::sub_sat_i64(rem, 2) >= org.len else {
            return false;
        }
        payload.append_u16_be(org.len as u16);
        payload.append(org);
    }
    var hdr: u8[..16] = [];
    guard encode_frame_header(hdr, H3_FRAME_ORIGIN, payload.len as u64) else { return false; }
    return h3_internal::append_h3_frame_parts(out, hdr[..], payload[..]);
}

// RFC 8336 Section 2.1: Syntax - Each Origin-Entry is a serialized ASCII-Origin containing printable ASCII bytes.
// Rejects truncated 2-byte big-endian Origin-Len, 0-length entries, or non-VCHAR octets.
//
// Example:
//   payload = [0x00, 0x06, 'e', 'x', '.', 'c', 'o', 'm']
//   returns: true, out_origins = ["ex.com"]
fn parse_origin_frame(payload: const u8[:], out_origins: u8[..128][..16]&) -> bool {
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
        guard h3_internal::is_valid_ascii_origin(raw_origin) else { return false; }
        var entry: u8[..128] = [];
        guard entry.try_set(raw_origin) && out_origins.try_push(entry) else {
            return false;
        }
        rem = after_hdr[olen..];
    }
    committed = true;
    return true;
}
