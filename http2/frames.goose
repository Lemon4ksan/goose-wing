// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose-Wing HTTP/2 Frames: ORIGIN and ALTSVC Extensions
// RFC 8336 (ORIGIN Frame), RFC 7838 (ALTSVC Frame)
// Zero-allocation, wire-bounded codecs for HTTP/2 extension frames.

namespace internal;

import core from "..";
import .framing;

// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame
// Origin-Len (16 bits) | Origin (variable) | Alt-Svc-Value (variable)
struct H2AltSvcFrame {
    origin:        const u8[:] = "",
    alt_svc_value: const u8[:] = "",
}

// RFC 8336 Section 2.1: Syntax - Decodes length of single Origin Entry
inline fn read_origin_len(src: const u8[:]) -> i64 {
    let high = (src[0] as i64) << 8;
    let low = src[1] as i64;
    return high | low;
}

// Decodes a single Origin Entry from slice without cursor mutation
//
// Example:
//   rem = [0x00, 0x07, 'e', 'x', '.', 'c', 'o', 'm']
//   returns: "ex.com", total = 9, ok = true
inline fn decode_origin_slice(rem: const u8[:]) -> const u8[:], i64, bool {
    guard rem.len >= 2 else { return "", 0, false; }
    let len = read_origin_len(rem);
    let total = 2 + len;
    guard rem.len >= total else { return "", 0, false; }
    return rem[2..total], total, true;
}

// RFC 8336 Section 2: The ORIGIN HTTP/2 Frame - Parses ORIGIN frame payload
// Validates stream 0 requirement and populates out_entries.
//
// Example:
//   payload = [0x00, 0x06, 'e', 'x', '.', 'c', 'o', 'm'], stream_id = 0
//   returns: count = 1, H2_ERR_NO_ERROR, out_entries = ["ex.com"]
fn parse_origin_frame(
    payload:     const u8[:],
    stream_id:   u32,
    out_entries: const u8[:][..16]&,
) -> u32, u32 {
    let saved_len = out_entries.len;
    var committed = false;
    defer if !committed { out_entries.resize(saved_len); };
    guard stream_id == 0 else {
        return 0, rfc::H2_ERR_PROTOCOL_ERROR;
    }
    var idx: i64 = 0;
    while idx < payload.len {
        let entry, total, ok = decode_origin_slice(payload[idx..]);
        guard ok else { return saved_len as u32, rfc::H2_ERR_FRAME_SIZE_ERROR; }
        guard out_entries.try_push(entry) else {
            return saved_len as u32, rfc::H2_ERR_PROTOCOL_ERROR;
        }
        idx += total;
    }
    committed = true;
    return out_entries.len as u32, rfc::H2_ERR_NO_ERROR;
}

// RFC 8336 Section 2.1: Syntax - Encodes a single Origin Entry into output buffer
//
// Example:
//   origin = "https://example.com"
//   out: appends 16-bit length (19) followed by "https://example.com"
fn encode_origin_entry<B>(out: B&, origin: const u8[:]) -> bool {
    guard origin.len <= 0xFFFF else { return false; }
    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };
    var len_be: u8[..2] = [];
    len_be.append_u16_be(origin.len as u16);
    guard out.try_append(len_be[..]) && out.try_append(origin) else { return false; }
    committed = true;
    return true;
}

inline fn sum_origins_payload_len(origins: const u8[:][..16]&) -> u32, bool {
    var payload_len: u64 = 0;
    for org in origins {
        payload_len += 2 + (org.len as u64);
    }
    guard payload_len <= 16384 else { return 0, false; }
    return payload_len as u32, true;
}

// RFC 8336 Section 2: The ORIGIN HTTP/2 Frame - Serializes full ORIGIN frame with 9-byte header
fn encode_origin_frame<B>(out: B&, origins: const u8[:][..16]&) -> bool {
    let payload_len, ok = sum_origins_payload_len(origins);
    guard ok else { return false; }
    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };
    let hdr = FrameHeader {
        length:     payload_len,
        frame_type: rfc::H2_FRAME_ORIGIN,
        flags:      0,
        stream_id:  0,
    };
    var raw_hdr: u8[9] = [0; 9];
    encode_frame_header(hdr, raw_hdr);
    guard out.try_append(raw_hdr[..]) else { return false; }
    for org in origins {
        guard encode_origin_entry(out, org) else {
            return false;
        }
    }
    committed = true;
    return true;
}

// RFC 7838 Section 4.1: The ALTSVC Frame - Parses ALTSVC frame payload
//
// Example:
//   payload = [0x00, 0x06, 'e', 'x', '.', 'c', 'o', 'm', 'h', '3'], stream_id = 0
//   returns: H2AltSvcFrame { origin: "ex.com", alt_svc_value: "h3" }, ERR_NO_ERROR
fn parse_altsvc_frame(payload: const u8[:], stream_id: u32) -> H2AltSvcFrame, u32 {
    guard payload.len >= 2 else {
        return H2AltSvcFrame { .. }, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    let origin_len = core::read_be_u16(payload, 0) as i64;
    let origin_end = 2 + origin_len;
    guard origin_end <= payload.len else {
        return H2AltSvcFrame { .. }, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    let valid_origin = if stream_id == 0 { origin_len > 0 } else { origin_len == 0 };
    guard valid_origin && origin_end < payload.len else {
        // RFC 7838 §4: An ALTSVC frame with invalid origin or empty field value MUST be ignored
        return H2AltSvcFrame { .. }, rfc::H2_ERR_NO_ERROR;
    }
    return H2AltSvcFrame {
        origin:        payload[2..origin_end],
        alt_svc_value: payload[origin_end..],
    }, rfc::H2_ERR_NO_ERROR;
}

// RFC 7838 Section 4.1: The ALTSVC Frame - Encodes ALTSVC frame payload into buffer
//
// Example:
//   origin = "example.com", alt_svc_val = "h3=\":443\"", stream_id = 0
//   out: appends 16-bit length (11), "example.com", "h3=\":443\""
fn encode_altsvc_payload<B>(
    out:         B&,
    origin:      const u8[:],
    alt_svc_val: const u8[:],
    stream_id:   u32,
) -> bool {
    guard alt_svc_val.len > 0 else { return false; }
    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };
    var len_be: u8[..2] = [];
    if stream_id == 0 {
        guard origin.len > 0 && origin.len <= 0xFFFF else { return false; }
        len_be.append_u16_be(origin.len as u16);
        guard out.try_append(len_be[..]) && out.try_append(origin) else { return false; }
    } else {
        guard origin.len == 0 else { return false; }
        len_be.append_u16_be(0 as u16);
        guard out.try_append(len_be[..]) else { return false; }
    }
    guard out.try_append(alt_svc_val) else { return false; }
    committed = true;
    return true;
}

inline fn calc_altsvc_payload_len(origin_len: i64, alt_svc_len: i64, stream_id: u32) -> u32, bool {
    let eff_origin: u64 = if stream_id == 0 { origin_len as u64 } else { 0 };
    let total:      u64 = 2 + eff_origin + (alt_svc_len as u64);
    guard total <= 16384 else { return 0, false; }
    return total as u32, true;
}

// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame - Encodes full ALTSVC frame with 9-byte header
fn encode_altsvc_frame<B>(
    out:         B&,
    origin:      const u8[:],
    alt_svc_val: const u8[:],
    stream_id:   u32,
) -> bool {
    guard alt_svc_val.len > 0 else { return false; }
    if stream_id == 0 {
        guard origin.len > 0 else { return false; }
    } else {
        guard origin.len == 0 else { return false; }
    }
    let payload_len, ok = calc_altsvc_payload_len(origin.len, alt_svc_val.len, stream_id);
    guard ok else { return false; }

    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };
    let hdr = FrameHeader {
        length:     payload_len,
        frame_type: rfc::H2_FRAME_ALTSVC,
        flags:      0,
        stream_id:  stream_id,
    };
    var raw_hdr: u8[9] = [0; 9];
    encode_frame_header(hdr, raw_hdr);
    guard out.try_append(raw_hdr[..]) else { return false; }
    guard encode_altsvc_payload(out, origin, alt_svc_val, stream_id) else { return false; }
    committed = true;
    return true;
}
