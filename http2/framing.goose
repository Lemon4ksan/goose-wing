// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 binary framing layer and RFC 9218 extensible prioritization (RFC 9113, RFC 9218).
// Zero-allocation frame header parsing, stream ID validation, and Structured Field priority codecs.
namespace internal;

import std;
import core from "..";

// ---- frame types (rfc 9113 section 6 & rfc 9218 section 7.1) -------------

const FRAME_DATA:            u8 = 0x00;
const FRAME_HEADERS:         u8 = 0x01;
const FRAME_PRIORITY:        u8 = 0x02;
const FRAME_RST_STREAM:      u8 = 0x03;
const FRAME_SETTINGS:        u8 = 0x04;
const FRAME_PUSH_PROMISE:    u8 = 0x05;
const FRAME_PING:            u8 = 0x06;
const FRAME_GOAWAY:          u8 = 0x07;
const FRAME_WINDOW_UPDATE:   u8 = 0x08;
const FRAME_CONTINUATION:    u8 = 0x09;
const FRAME_ALTSVC:          u8 = 0x0A; // RFC 7838 Section 4
const FRAME_ORIGIN:          u8 = 0x0C; // RFC 8336 Section 2
const FRAME_PRIORITY_UPDATE: u8 = 0x10; // RFC 9218 Section 7.1

// ---- frame flags (rfc 9113 section 4.1) ----------------------------------

const FLAG_END_STREAM:  u8 = 0x01;
const FLAG_ACK:         u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED:      u8 = 0x08;
const FLAG_PRIORITY:    u8 = 0x20;

// ---- error codes (rfc 9113 section 7) ------------------------------------

const ERR_NO_ERROR:            u32 = 0x00;
const ERR_PROTOCOL_ERROR:      u32 = 0x01;
const ERR_INTERNAL_ERROR:      u32 = 0x02;
const ERR_FLOW_CONTROL_ERROR:  u32 = 0x03;
const ERR_SETTINGS_TIMEOUT:    u32 = 0x04;
const ERR_STREAM_CLOSED:       u32 = 0x05;
const ERR_FRAME_SIZE_ERROR:    u32 = 0x06;
const ERR_REFUSED_STREAM:      u32 = 0x07;
const ERR_CANCEL:              u32 = 0x08;
const ERR_COMPRESSION_ERROR:   u32 = 0x09;
const ERR_CONNECT_ERROR:       u32 = 0x0A;
const ERR_ENHANCE_YOUR_CALM:   u32 = 0x0B;
const ERR_INADEQUATE_SECURITY: u32 = 0x0C;
const ERR_HTTP_1_1_REQUIRED:   u32 = 0x0D;

// ---- settings identifiers (rfc 9113 section 6.5.2 & rfc 9218) -----------

const SETTING_HEADER_TABLE_SIZE:      u16 = 0x01; // default 4096
const SETTING_ENABLE_PUSH:            u16 = 0x02; // default 1
const SETTING_MAX_CONCURRENT_STREAMS: u16 = 0x03; // unlimited
const SETTING_INITIAL_WINDOW_SIZE:    u16 = 0x04; // default 65535
const SETTING_MAX_FRAME_SIZE:         u16 = 0x05; // default 16384
const SETTING_MAX_HEADER_LIST_SIZE:   u16 = 0x06; // unlimited
const SETTING_ENABLE_CONNECT_PROTO:   u16 = 0x08; // RFC 8441
const SETTING_NO_RFC7540_PRIORITIES:  u16 = 0x09; // RFC 9218 Section 5.1

// Client connection preface (RFC 9113 Section 3.4)
let H2_CLIENT_PREFACE: const u8[24] = [
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
    '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
];

// ---- 9-byte frame header -------------------------------------------------

struct FrameHeader {
    length:     u32 = 0,  // 24-bit big-endian unsigned
    frame_type: u8  = 0, // 8-bit wire frame type code
    flags:      u8  = 0, // 8-bit type-specific bitmask
    stream_id:  u32 = 0,  // 31-bit stream identifier (R bit masked)
}

// Parses a 9-byte HTTP/2 binary frame header (RFC 9113 Section 4.1).
// Masks out the reserved high bit (R) of the stream identifier.
//
// Example:
//   buf = [0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]
//   returns: FrameHeader { length: 4, frame_type: 0, flags: 1, stream_id: 1 }, ERR_NO_ERROR
fn parse_frame_header(buf: const u8[:], max_frame_size: u32 = 16384) -> FrameHeader, u32 {
    var hdr = FrameHeader { .. };
    guard buf.len >= 9 else {
        return hdr, ERR_FRAME_SIZE_ERROR;
    }

    var r = core::new_slice_reader(buf);
    let length_val, _ = r.read_u24_be();
    let f_type, _ = r.read_u8();
    let flags_val, _ = r.read_u8();
    let raw_stream, _ = r.read_u32_be();
    let stream_id_val = raw_stream & 0x7FFFFFFF;

    hdr.length = length_val;
    hdr.frame_type = f_type;
    hdr.flags = flags_val;
    hdr.stream_id = stream_id_val;

    if length_val > max_frame_size {
        return hdr, ERR_FRAME_SIZE_ERROR;
    }
    return hdr, ERR_NO_ERROR;
}

// Serializes a 9-byte HTTP/2 binary frame header in big-endian wire format.
fn encode_frame_header(hdr: const FrameHeader&, out: u8[9]&) {
    var w = core::new_slice_writer(out[..]);
    w.write_u24_be(hdr.length & 0x00FFFFFF);
    w.write_u8(hdr.frame_type);
    w.write_u8(hdr.flags);
    w.write_u32_be(hdr.stream_id & 0x7FFFFFFF);
}

// Appends 9 serialized header bytes to any buffer.
fn encode_frame_header_to<B>(hdr: const FrameHeader&, out: B&) {
    core::append_u24_be(out, hdr.length & 0x00FFFFFF);
    out.push(hdr.frame_type);
    out.push(hdr.flags);
    core::append_u32_be(out, hdr.stream_id & 0x7FFFFFFF);
}

// Validates frame header invariants against stream 0 / non-zero stream rules and lengths.
fn validate_frame_header_rules(hdr: const FrameHeader&, max_frame_size: u32 = 16384) -> u32 {
    guard hdr.length <= max_frame_size else {
        return ERR_FRAME_SIZE_ERROR;
    }

    // Stream ID 0 rules (RFC 9113 Section 5.1.1)
    if hdr.stream_id == 0 {
        if hdr.frame_type == FRAME_DATA ||
           hdr.frame_type == FRAME_HEADERS ||
           hdr.frame_type == FRAME_PRIORITY ||
           hdr.frame_type == FRAME_RST_STREAM ||
           hdr.frame_type == FRAME_CONTINUATION ||
           hdr.frame_type == FRAME_PUSH_PROMISE {
            return ERR_PROTOCOL_ERROR;
        }
    } else {
        // Stream ID > 0 rules (RFC 9113 §6.5, §6.7, §6.8, §6.10 & RFC 8336 Section 2.1)
        if hdr.frame_type == FRAME_SETTINGS ||
           hdr.frame_type == FRAME_PING ||
           hdr.frame_type == FRAME_GOAWAY ||
           hdr.frame_type == FRAME_PRIORITY_UPDATE ||
           hdr.frame_type == FRAME_ORIGIN {
            return ERR_PROTOCOL_ERROR;
        }
    }

    // Exact length checks for fixed-size frames
    if hdr.frame_type == FRAME_RST_STREAM && hdr.length != 4 {
        return ERR_FRAME_SIZE_ERROR;
    }
    if hdr.frame_type == FRAME_PING && hdr.length != 8 {
        return ERR_FRAME_SIZE_ERROR;
    }
    if hdr.frame_type == FRAME_SETTINGS {
        if (hdr.flags & FLAG_ACK) != 0 {
            if hdr.length != 0 { return ERR_FRAME_SIZE_ERROR; }
        } else {
            if (hdr.length % 6) != 0 { return ERR_FRAME_SIZE_ERROR; }
        }
    }
    if hdr.frame_type == FRAME_PRIORITY && hdr.length != 5 {
        return ERR_FRAME_SIZE_ERROR;
    }
    if hdr.frame_type == FRAME_WINDOW_UPDATE && hdr.length != 4 {
        return ERR_FRAME_SIZE_ERROR;
    }
    if hdr.frame_type == FRAME_GOAWAY && hdr.length < 8 {
        return ERR_FRAME_SIZE_ERROR;
    }
    if hdr.frame_type == FRAME_PRIORITY_UPDATE && hdr.length < 4 {
        return ERR_FRAME_SIZE_ERROR;
    }
    if hdr.frame_type == FRAME_ALTSVC && hdr.length < 2 {
        return ERR_FRAME_SIZE_ERROR;
    }
    if hdr.frame_type == FRAME_PUSH_PROMISE {
        let min_len: u32 = if (hdr.flags & FLAG_PADDED) != 0 { 5 } else { 4 };
        if hdr.length < min_len {
            return ERR_FRAME_SIZE_ERROR;
        }
    }

    return ERR_NO_ERROR;
}

// RFC 9113 Section 6.8 & Go #80759:
// Validates GOAWAY Last-Stream-ID based on peer stream initiation roles.
// A client can only acknowledge peer streams (server-initiated: even or 0).
// A server can only acknowledge peer streams (client-initiated: odd or 0, or 2^31 - 1 for graceful shutdown).
fn validate_goaway_last_stream_id(last_stream_id: u32, sender_is_client: bool) -> bool {
    let sid = last_stream_id & 0x7FFFFFFF;
    if sid == 0 {
        return true;
    }
    if sender_is_client {
        return (sid % 2) == 0;
    } else {
        return (sid % 2) != 0;
    }
}

// ---- payload extractors & padding validation ----------------------------

// Strips PADDED flag length byte and trailing padding octets from frame payload.
//
// Example:
//   hdr = FrameHeader { flags: FLAG_PADDED, length: 6 }, payload = [0x02, 'd', 'a', 't', 0x00, 0x00]
//   returns: "dat", ERR_NO_ERROR
fn extract_padded_frame_payload(hdr: const FrameHeader&, payload: const u8[:]) -> const u8[:], u32 {
    if (hdr.flags & FLAG_PADDED) == 0 {
        return payload, ERR_NO_ERROR;
    }
    guard payload.len >= 1 else {
        return payload, ERR_FRAME_SIZE_ERROR;
    }
    let pad_len = payload[0] as u32;
    guard (1 + pad_len) <= hdr.length else {
        return payload, ERR_PROTOCOL_ERROR;
    }
    let eff_end = payload.len - pad_len;
    guard eff_end >= 1 else {
        return payload, ERR_PROTOCOL_ERROR;
    }
    return payload[1..eff_end], ERR_NO_ERROR;
}

// Strips PADDED and PRIORITY fields from HEADERS frame payload.
// Returns the raw HPACK header block fragment.
//
// Example:
//   hdr = FrameHeader { flags: 0, length: 4 }, payload = [0x82, 0x86, 0x84, 0x41]
//   returns: [0x82, 0x86, 0x84, 0x41], ERR_NO_ERROR
fn extract_headers_frame_payload(
    hdr:                   const FrameHeader&,
    payload:               const u8[:],
    no_rfc7540_priorities: bool = true,
) -> const u8[:], u32 {
    let has_pad = (hdr.flags & FLAG_PADDED) != 0;
    let has_prio = (hdr.flags & FLAG_PRIORITY) != 0;
    let min_overhead = (if has_pad { 1 } else { 0 }) + (if has_prio { 5 } else { 0 });
    guard payload.len >= min_overhead else { return payload, ERR_FRAME_SIZE_ERROR; }

    var raw = payload;
    if has_pad {
        let pad_len = raw[0] as u32;
        guard (1 + pad_len + (if has_prio { 5 } else { 0 })) <= hdr.length else {
            return raw, ERR_PROTOCOL_ERROR;
        }
        let eff_end = raw.len - pad_len;
        guard eff_end >= (1 + (if has_prio { 5 } else { 0 })) else {
            return raw, ERR_PROTOCOL_ERROR;
        }
        raw = raw[1..eff_end];
    }

    if has_prio {
        // PRIORITY in HEADERS adds 5 bytes: 4 bytes Stream Dep + 1 byte Weight
        guard raw.len >= 5 else {
            return raw, ERR_FRAME_SIZE_ERROR;
        }
        if !no_rfc7540_priorities {
            let s0 = ((raw[0] & 0x7F) as u32) << 24;
            let s1 = (raw[1] as u32) << 16;
            let s2 = (raw[2] as u32) << 8;
            let stream_dep = s0 | s1 | s2 | raw[3];
            // RFC 7540 / RFC 9113: stream cannot depend on itself
            if stream_dep == hdr.stream_id {
                return raw, ERR_PROTOCOL_ERROR;
            }
        }
        raw = raw[5..];
    }

    return raw, ERR_NO_ERROR;
}

// ---- settings parameter validation --------------------------------------

// Validates an HTTP/2 SETTINGS parameter bounds (RFC 9113 Section 6.5.2 & RFC 9218 Section 5.1).
fn validate_settings_parameter(param_id: u16, val: u32, receiver_is_client: bool = false) -> u32 {
    if param_id == SETTING_ENABLE_PUSH {
        if val != 0 && val != 1 {
            return ERR_PROTOCOL_ERROR;
        }
        // RFC 9113 Section 6.5.2: Server MUST NOT send ENABLE_PUSH with val != 0 to client
        if receiver_is_client && val != 0 {
            return ERR_PROTOCOL_ERROR;
        }
    }
    if param_id == SETTING_INITIAL_WINDOW_SIZE && val > 0x7FFFFFFF {
        return ERR_FLOW_CONTROL_ERROR;
    }
    // SETTINGS_MAX_FRAME_SIZE must be in 16384..16777215 (CVE-2026-33814 / Go #78476)
    if param_id == SETTING_MAX_FRAME_SIZE && (val < 16384 || val > 16777215) {
        return ERR_PROTOCOL_ERROR;
    }
    if param_id == SETTING_ENABLE_CONNECT_PROTO && val != 0 && val != 1 {
        return ERR_PROTOCOL_ERROR;
    }
    if param_id == SETTING_NO_RFC7540_PRIORITIES && val != 0 && val != 1 {
        return ERR_PROTOCOL_ERROR;
    }
    return ERR_NO_ERROR;
}

// ---- rfc 9218 extensible prioritization (urgency & incremental) ---------

// Parses PRIORITY_UPDATE frame payload (RFC 9218 Section 7.1).
// Returns (prioritized_stream_id, PriorityParam, error_code).
//
// Example:
//   payload = [0x00, 0x00, 0x00, 0x03, 'u', '=', '5']
//   returns: 3, PriorityParam { urgency: 5, incremental: false }, ERR_NO_ERROR
fn parse_priority_update_payload(
    payload:             const u8[:],
    default_incremental: bool = false,
) -> u32, wing::PriorityParam, u32 {
    var p = wing::priority_default(default_incremental);
    guard payload.len >= 4 else {
        return 0, p, ERR_FRAME_SIZE_ERROR;
    }

    let p0 = ((payload[0] & 0x7F) as u32) << 24;
    let p1 = (payload[1] as u32) << 16;
    let p2 = (payload[2] as u32) << 8;
    let prioritized_stream_id = p0 | p1 | p2 | payload[3];

    guard prioritized_stream_id != 0 else {
        return 0, p, ERR_PROTOCOL_ERROR;
    }

    let field_value = payload[4..];
    let parsed, _ = wing::parse_http_priority(field_value, default_incremental);
    return prioritized_stream_id, parsed, ERR_NO_ERROR;
}

// Encodes PRIORITY_UPDATE frame payload (RFC 9218 Section 7.1).
fn encode_priority_update_payload<B>(prioritized_stream_id: u32, prio: const wing::PriorityParam&, out: B&) {
    let id_bytes: u8[4] = [
        ((prioritized_stream_id >> 24) & 0x7F) as u8,
        ((prioritized_stream_id >> 16) & 0xFF) as u8,
        ((prioritized_stream_id >> 8) & 0xFF) as u8,
        (prioritized_stream_id & 0xFF) as u8,
    ];
    out.append(id_bytes[..]);
    wing::serialize_http_priority(prio, out);
}
