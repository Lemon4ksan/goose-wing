// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 binary framing layer and RFC 9218 extensible prioritization (RFC 9113, RFC 9218).
// Zero-allocation frame header parsing, stream ID validation, and Structured Field priority codecs.
namespace wing;

import std;
import core from "..";

// ---- 1. frame types (rfc 9113 section 6 & rfc 9218 section 7.1) -------------

const FRAME_DATA: u8 = 0x00;
const FRAME_HEADERS: u8 = 0x01;
const FRAME_PRIORITY: u8 = 0x02;
const FRAME_RST_STREAM: u8 = 0x03;
const FRAME_SETTINGS: u8 = 0x04;
const FRAME_PUSH_PROMISE: u8 = 0x05;
const FRAME_PING: u8 = 0x06;
const FRAME_GOAWAY: u8 = 0x07;
const FRAME_WINDOW_UPDATE: u8 = 0x08;
const FRAME_CONTINUATION: u8 = 0x09;
const FRAME_PRIORITY_UPDATE: u8 = 0x10; // RFC 9218 Section 7.1

// ---- 2. frame flags (rfc 9113 section 4.1) ----------------------------------

const FLAG_END_STREAM: u8 = 0x01;
const FLAG_ACK: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

// ---- 3. error codes (rfc 9113 section 7) ------------------------------------

const ERR_NO_ERROR: u32 = 0x00;
const ERR_PROTOCOL_ERROR: u32 = 0x01;
const ERR_INTERNAL_ERROR: u32 = 0x02;
const ERR_FLOW_CONTROL_ERROR: u32 = 0x03;
const ERR_SETTINGS_TIMEOUT: u32 = 0x04;
const ERR_STREAM_CLOSED: u32 = 0x05;
const ERR_FRAME_SIZE_ERROR: u32 = 0x06;
const ERR_REFUSED_STREAM: u32 = 0x07;
const ERR_CANCEL: u32 = 0x08;
const ERR_COMPRESSION_ERROR: u32 = 0x09;
const ERR_CONNECT_ERROR: u32 = 0x0A;
const ERR_ENHANCE_YOUR_CALM: u32 = 0x0B;
const ERR_INADEQUATE_SECURITY: u32 = 0x0C;
const ERR_HTTP_1_1_REQUIRED: u32 = 0x0D;

// ---- 4. settings identifiers (rfc 9113 section 6.5.2 & rfc 9218) -----------

const SETTING_HEADER_TABLE_SIZE: u16 = 0x01;      // default 4096
const SETTING_ENABLE_PUSH: u16 = 0x02;            // default 1
const SETTING_MAX_CONCURRENT_STREAMS: u16 = 0x03; // unlimited
const SETTING_INITIAL_WINDOW_SIZE: u16 = 0x04;    // default 65535
const SETTING_MAX_FRAME_SIZE: u16 = 0x05;         // default 16384
const SETTING_MAX_HEADER_LIST_SIZE: u16 = 0x06;   // unlimited
const SETTING_ENABLE_CONNECT_PROTO: u16 = 0x08;   // RFC 8441
const SETTING_NO_RFC7540_PRIORITIES: u16 = 0x09;  // RFC 9218 Section 5.1

// Client connection preface (RFC 9113 Section 3.4)
let H2_CLIENT_PREFACE: const u8[24] = [
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
    '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
];

// ---- 5. 9-byte frame header -------------------------------------------------

struct FrameHeader {
    length: u32 = 0,      // 24-bit big-endian unsigned
    frame_type: u8 = 0,  // 8-bit wire frame type code
    flags: u8 = 0,       // 8-bit type-specific bitmask
    stream_id: u32 = 0,   // 31-bit stream identifier (R bit masked)
}

// Parses a 9-byte HTTP/2 binary frame header (RFC 9113 Section 4.1).
// Masks out the reserved high bit (R) of the stream identifier.
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
        // Stream ID > 0 rules
        if hdr.frame_type == FRAME_SETTINGS ||
           hdr.frame_type == FRAME_PING ||
           hdr.frame_type == FRAME_PRIORITY_UPDATE {
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
    if hdr.frame_type == FRAME_PUSH_PROMISE {
        let min_len: u32 = if (hdr.flags & FLAG_PADDED) != 0 { 5 } else { 4 };
        if hdr.length < min_len {
            return ERR_FRAME_SIZE_ERROR;
        }
    }

    return ERR_NO_ERROR;
}

// ---- 6. payload extractors & padding validation ----------------------------

// Strips PADDED flag length byte and trailing padding octets from frame payload.
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
fn extract_headers_frame_payload(
    hdr: const FrameHeader&,
    payload: const u8[:],
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
            let stream_dep = (((raw[0] & 0x7F) as u32) << 24) |
                             ((raw[1] as u32) << 16) |
                             ((raw[2] as u32) << 8) |
                             raw[3];
            // RFC 7540 / RFC 9113: stream cannot depend on itself
            if stream_dep == hdr.stream_id {
                return raw, ERR_PROTOCOL_ERROR;
            }
        }
        raw = raw[5..];
    }

    return raw, ERR_NO_ERROR;
}

// ---- 7. settings parameter validation --------------------------------------

// Validates an HTTP/2 SETTINGS parameter bounds (RFC 9113 Section 6.5.2 & RFC 9218 Section 5.1).
fn validate_settings_parameter(param_id: u16, val: u32) -> u32 {
    if param_id == SETTING_ENABLE_PUSH && val != 0 && val != 1 {
        return ERR_PROTOCOL_ERROR;
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

// ---- 8. rfc 9218 extensible prioritization (urgency & incremental) ---------

struct PriorityParam {
    urgency: u8 = 3,       // 0..7 (0 = highest / render-blocking, 3 = default, 7 = background)
    incremental: bool = false, // false by default, true for round-robin progressive loading
}

// Parses RFC 9218 Structured Field dictionary: e.g. "u=0, i", "u=5", "i=?0, u=2".
// Ignores unknown parameters per RFC 9218 Section 4.
fn parse_priority_param_rfc9218(raw: const u8[:], default_incremental: bool = false) -> PriorityParam, bool {
    var p = PriorityParam { urgency: 3, incremental: default_incremental };
    var i: i64 = 0;
    let n = raw.len;
    var found_any = false;

    while i < n {
        // Skip whitespace and commas
        while i < n && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == ',') {
            i++;
        }
        guard i < n else { break; }

        let key_start = i;
        while i < n && raw[i] != '=' && raw[i] != ',' && raw[i] != ' ' && raw[i] != '\t' {
            i++;
        }
        let key = raw[key_start..i];

        // Skip whitespace before '='
        while i < n && (raw[i] == ' ' || raw[i] == '\t') { i++; }

        var has_val = false;
        var val_start: i64 = 0;
        var val_end: i64 = 0;

        if i < n && raw[i] == '=' {
            i++; // consume '='
            while i < n && (raw[i] == ' ' || raw[i] == '\t') { i++; }
            val_start = i;
            while i < n && raw[i] != ',' && raw[i] != ' ' && raw[i] != '\t' {
                i++;
            }
            val_end = i;
            has_val = true;
        }

        if key.len == 1 && key[0] == 'u' && has_val {
            let val_slice = raw[val_start..val_end];
            if val_slice.len == 1 && val_slice[0] >= '0' && val_slice[0] <= '7' {
                p.urgency = val_slice[0] - '0';
                found_any = true;
            }
        } else if key.len == 1 && key[0] == 'i' {
            if !has_val {
                p.incremental = true;
                found_any = true;
            } else {
                let val_slice = raw[val_start..val_end];
                if val_slice.len == 2 && val_slice[0] == '?' && val_slice[1] == '1' {
                    p.incremental = true;
                    found_any = true;
                } else if val_slice.len == 2 && val_slice[0] == '?' && val_slice[1] == '0' {
                    p.incremental = false;
                    found_any = true;
                }
            }
        }
    }

    return p, found_any;
}

// Parses PRIORITY_UPDATE frame payload (RFC 9218 Section 7.1).
// Returns (prioritized_stream_id, PriorityParam, error_code).
fn parse_priority_update_payload(
    payload: const u8[:],
    default_incremental: bool = false,
) -> u32, PriorityParam, u32 {
    var p = PriorityParam { urgency: 3, incremental: default_incremental };
    guard payload.len >= 4 else {
        return 0, p, ERR_FRAME_SIZE_ERROR;
    }

    let prioritized_stream_id = (((payload[0] & 0x7F) as u32) << 24) |
                                ((payload[1] as u32) << 16) |
                                ((payload[2] as u32) << 8) |
                                payload[3];

    guard prioritized_stream_id != 0 else {
        return 0, p, ERR_PROTOCOL_ERROR;
    }

    let field_value = payload[4..];
    let parsed, _ = parse_priority_param_rfc9218(field_value, default_incremental);
    return prioritized_stream_id, parsed, ERR_NO_ERROR;
}

// Writes RFC 9218 Priority header value: e.g. "u=3", "u=0, i".
fn write_priority_param_rfc9218<B>(prio: const PriorityParam&, out: B&) {
    out.append("u=");
    out.push(('0' + prio.urgency) as u8);
    if prio.incremental {
        out.append(", i");
    }
}

// Encodes PRIORITY_UPDATE frame payload (RFC 9218 Section 7.1).
fn encode_priority_update_payload<B>(prioritized_stream_id: u32, prio: const PriorityParam&, out: B&) {
    let id_bytes: u8[4] = [
        ((prioritized_stream_id >> 24) & 0x7F) as u8,
        ((prioritized_stream_id >> 16) & 0xFF) as u8,
        ((prioritized_stream_id >> 8) & 0xFF) as u8,
        (prioritized_stream_id & 0xFF) as u8,
    ];
    out.append(id_bytes[..]);
    write_priority_param_rfc9218(prio, out);
}
