// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 binary framing layer and RFC 9218 extensible prioritization (RFC 9113, RFC 9218).
// Zero-allocation frame header parsing, stream ID validation, and Structured Field priority codecs.
namespace http2;

import std;
import core;
import .frames_internal;

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
checkfree fn parse_frame_header(buf: const u8[:], max_frame_size: u32 = 16384) -> FrameHeader, u32 {
    var hdr = FrameHeader { .. };
    guard buf.len >= 9 else {
        return hdr, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    let length_val = h2_internal::h2_read_be_u24(buf);
    let f_type = buf[3];
    let flags_val = buf[4];
    let raw_stream = h2_internal::h2_read_be_u32(buf[5..]);
    let stream_id_val = raw_stream & 0x7FFFFFFF;

    hdr.length = length_val;
    hdr.frame_type = f_type;
    hdr.flags = flags_val;
    hdr.stream_id = stream_id_val;

    if length_val > max_frame_size {
        return hdr, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    return hdr, rfc::H2_ERR_NO_ERROR;
}

// Serializes a 9-byte HTTP/2 binary frame header in big-endian wire format.
checkfree fn encode_frame_header(hdr: const FrameHeader&, out: u8[9]&) {
    let len_val = hdr.length & 0x00FFFFFF;
    let sid = hdr.stream_id & 0x7FFFFFFF;
    out[0] = ((len_val >> 16) & 0xFF) as u8;
    out[1] = ((len_val >> 8) & 0xFF) as u8;
    out[2] = (len_val & 0xFF) as u8;
    out[3] = hdr.frame_type;
    out[4] = hdr.flags;
    out[5] = ((sid >> 24) & 0xFF) as u8;
    out[6] = ((sid >> 16) & 0xFF) as u8;
    out[7] = ((sid >> 8) & 0xFF) as u8;
    out[8] = (sid & 0xFF) as u8;
}

// Appends 9 serialized header bytes to any buffer.
fn encode_frame_header_to<B>(hdr: const FrameHeader&, out: B&) {
    var raw: u8[9] = [0; 9];
    encode_frame_header(hdr, raw);
    let _ = out.try_append(raw[..]);
}

// Validates frame header invariants against stream 0 / non-zero stream rules and lengths.
fn validate_frame_header_rules(hdr: const FrameHeader&, max_frame_size: u32 = 16384) -> u32 {
    guard hdr.length <= max_frame_size else {
        return rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    let stream_err = rfc::validate_stream_id_association(hdr.stream_id, hdr.frame_type);
    guard stream_err == rfc::H2_ERR_NO_ERROR else {
        return stream_err;
    }

    return h2_internal::validate_frame_type_length(hdr);
}

// ---- payload extractors & padding validation ----------------------------

// Strips PADDED flag length byte and trailing padding octets from frame payload.
//
// Example:
//   hdr = FrameHeader { flags: FLAG_PADDED, length: 6 }, payload = [0x02, 'd', 'a', 't', 0x00, 0x00]
//   returns: "dat", ERR_NO_ERROR
checkfree fn extract_padded_frame_payload(hdr: const FrameHeader&, payload: const u8[:]) -> const u8[:], u32 {
    if (hdr.flags & rfc::H2_FLAG_PADDED) == 0 {
        return payload, rfc::H2_ERR_NO_ERROR;
    }
    guard payload.len >= 1 else {
        return payload, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    let pad_len = payload[0] as i64;
    guard (1 + pad_len) <= payload.len else {
        return payload, rfc::H2_ERR_PROTOCOL_ERROR;
    }
    let eff_end = payload.len - pad_len;
    guard eff_end >= 1 && eff_end <= payload.len else {
        return payload, rfc::H2_ERR_PROTOCOL_ERROR;
    }
    return payload[1..eff_end], rfc::H2_ERR_NO_ERROR;
}

// Strips PADDED and PRIORITY fields from HEADERS frame payload.
// Returns the raw HPACK header block fragment.
//
// Example:
//   hdr = FrameHeader { flags: 0, length: 4 }, payload = [0x82, 0x86, 0x84, 0x41]
//   returns: [0x82, 0x86, 0x84, 0x41], ERR_NO_ERROR
checkfree fn extract_headers_frame_payload(
    hdr:                   const FrameHeader&,
    payload:               const u8[:],
    no_rfc7540_priorities: bool = true,
) -> const u8[:], u32 {
    let has_pad = (hdr.flags & rfc::H2_FLAG_PADDED) != 0;
    let has_prio = (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0;
    let prio_overhead: i64 = if has_prio { 5 } else { 0 };
    let pad_overhead:  i64 = if has_pad { 1 } else { 0 };
    guard payload.len >= (pad_overhead + prio_overhead) else {
        return payload, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    var raw = payload;
    if has_pad {
        if raw.len < 1 { return raw, rfc::H2_ERR_FRAME_SIZE_ERROR; }
        let pad_len = raw[0] as i64;
        let min_hdr = 1 + prio_overhead;
        guard (min_hdr + pad_len) <= raw.len else {
            return raw, rfc::H2_ERR_PROTOCOL_ERROR;
        }
        let eff_end = raw.len - pad_len;
        guard eff_end >= min_hdr && eff_end >= 1 && eff_end <= raw.len else {
            return raw, rfc::H2_ERR_PROTOCOL_ERROR;
        }
        raw = raw[1..eff_end];
    }

    if has_prio {
        // PRIORITY in HEADERS adds 5 bytes: 4 bytes Stream Dep + 1 byte Weight
        guard raw.len >= 5 else {
            return raw, rfc::H2_ERR_FRAME_SIZE_ERROR;
        }
        if !no_rfc7540_priorities {
            let stream_dep = h2_internal::h2_read_be_u32(raw) & 0x7FFFFFFF;
            // RFC 7540 / RFC 9113: stream cannot depend on itself
            if stream_dep == hdr.stream_id {
                return raw, rfc::H2_ERR_PROTOCOL_ERROR;
            }
        }
        raw = raw[5..];
    }

    return raw, rfc::H2_ERR_NO_ERROR;
}

// ---- settings parameter validation --------------------------------------

// Validates an HTTP/2 SETTINGS parameter bounds (RFC 9113 Section 6.5.2 & RFC 9218 Section 5.1).
checkfree fn validate_settings_parameter(param_id: u16, val: u32, receiver_is_client: bool = false) -> u32 {
    if param_id == rfc::H2_SETTING_ENABLE_PUSH {
        if val != 0 && val != 1 {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        // RFC 9113 Section 6.5.2: Server MUST NOT send ENABLE_PUSH with val != 0 to client
        if receiver_is_client && val != 0 {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }
    if param_id == rfc::H2_SETTING_INITIAL_WINDOW_SIZE && val > 0x7FFFFFFF {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }
    // SETTINGS_MAX_FRAME_SIZE must be in 16384..16777215 (CVE-2026-33814 / Go #78476)
    if param_id == rfc::H2_SETTING_MAX_FRAME_SIZE && (val < 16384 || val > 16777215) {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    if param_id == rfc::H2_SETTING_ENABLE_CONNECT_PROTO {
        if !receiver_is_client {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        if val != 0 && val != 1 {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }
    if param_id == rfc::H2_SETTING_NO_RFC7540_PRIORITIES && val != 0 && val != 1 {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    return rfc::H2_ERR_NO_ERROR;
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
) -> u32, http::PriorityParam, u32 {
    var p = http::priority_default(default_incremental);
    guard payload.len >= 4 else {
        return 0, p, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    let prioritized_stream_id = core::read_be_u32(payload, 0) & 0x7FFFFFFF;

    guard prioritized_stream_id != 0 else {
        return 0, p, rfc::H2_ERR_PROTOCOL_ERROR;
    }

    let field_value = payload[4..];
    if field_value.trim_ascii_space().len == 0 {
        return prioritized_stream_id, p, rfc::H2_ERR_NO_ERROR;
    }
    let parsed, ok = http::parse_priority(field_value, default_incremental);
    guard ok else {
        return prioritized_stream_id, p, rfc::H2_ERR_PROTOCOL_ERROR;
    }
    return prioritized_stream_id, parsed, rfc::H2_ERR_NO_ERROR;
}

// RFC 9218 Section 7.1: HTTP/2 PRIORITY_UPDATE Frame - Encodes PRIORITY_UPDATE payload atomically.
fn encode_priority_update_payload<B>(prioritized_stream_id: u32, prio: const http::PriorityParam&, out: B&) {
    let clean_id = prioritized_stream_id & 0x7FFFFFFF;
    guard clean_id != 0 && prio.urgency <= 7 else { return; }
    var tmp: u8[..32] = [];
    tmp.append_u32_be(clean_id);
    http::serialize_priority(prio, tmp);
    let _ = out.try_append(tmp[..]);
}
