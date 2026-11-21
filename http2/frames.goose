// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose-Wing HTTP/2 Frames: ORIGIN and ALTSVC Extensions
// RFC 8336 (ORIGIN Frame), RFC 7838 (ALTSVC Frame)
// Zero-allocation, wire-bounded codecs for HTTP/2 extension frames.

namespace http2;

import core from "..";
import .framing;
import .internal;

// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame
// Origin-Len (16 bits) | Origin (variable) | Alt-Svc-Value (variable)
struct AltSvcFrame {
    origin:        const u8[:] = "",
    alt_svc_value: const u8[:] = "",
}

// RFC 8336 Section 2.2: Processing ORIGIN Frames - Ignores non-zero streams and reserved flags.
// Parses stream 0 ORIGIN frame payload, skips malformed Origin-Entry values, and populates out_entries.
//
// Example:
//   payload = [0x00, 0x0E, 'h', 't', 't', 'p', 's', ':', '/', '/', 'e', 'x', '.', 'c', 'o', 'm'], stream_id = 0
//   returns: count = 1, H2_ERR_NO_ERROR, out_entries = ["https://ex.com"]
fn parse_origin_frame(
    payload:     const u8[:],
    stream_id:   u32,
    out_entries: const u8[:][..16]&,
    flags:       u8 = 0,
) -> u32, u32 {
    let saved_len = out_entries.len;
    var committed = false;
    defer if !committed { out_entries.resize(saved_len); };
    if (stream_id & 0x7FFFFFFF) != 0 || (flags & h2_internal::H2_ORIGIN_RESERVED_FLAGS) != 0 {
        committed = true;
        return saved_len as u32, rfc::H2_ERR_NO_ERROR;
    }
    var idx: i64 = 0;
    while idx < payload.len {
        let entry, total, ok = h2_internal::decode_origin_slice(payload[idx..]);
        guard ok else { return saved_len as u32, rfc::H2_ERR_FRAME_SIZE_ERROR; }
        if h2_internal::is_valid_h2_origin_entry(entry) {
            guard out_entries.try_push(entry) else {
                return saved_len as u32, rfc::H2_ERR_PROTOCOL_ERROR;
            }
        }
        idx += total;
    }
    committed = true;
    return out_entries.len as u32, rfc::H2_ERR_NO_ERROR;
}

// RFC 8336 Section 2: The ORIGIN HTTP/2 Frame - Serializes full ORIGIN frame with 9-byte header
fn encode_origin_frame<B>(out: B&, origins: const u8[:][..16]&) -> bool {
    let payload_len, ok = h2_internal::sum_origins_payload_len(origins);
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
        guard h2_internal::encode_origin_entry(out, org) else {
            return false;
        }
    }
    committed = true;
    return true;
}

// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame - Parses ALTSVC frame payload
//
// Example:
//   payload = [0x00, 0x06, 'e', 'x', '.', 'c', 'o', 'm', 'h', '3'], stream_id = 0
//   returns: AltSvcFrame { origin: "ex.com", alt_svc_value: "h3" }, ERR_NO_ERROR
fn parse_altsvc_frame(payload: const u8[:], stream_id: u32) -> AltSvcFrame, u32 {
    guard payload.len >= 2 else {
        return AltSvcFrame { .. }, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    let origin_len = core::read_be_u16(payload, 0) as i64;
    let origin_end = 2 + origin_len;
    guard origin_end <= payload.len else {
        return AltSvcFrame { .. }, rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    let valid_origin = if stream_id == 0 { origin_len > 0 } else { origin_len == 0 };
    guard valid_origin && origin_end < payload.len else {
        // RFC 7838 §4: An ALTSVC frame with invalid origin or empty field value MUST be ignored
        return AltSvcFrame { .. }, rfc::H2_ERR_NO_ERROR;
    }
    return AltSvcFrame {
        origin:        payload[2..origin_end],
        alt_svc_value: payload[origin_end..],
    }, rfc::H2_ERR_NO_ERROR;
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
    let payload_len, ok = h2_internal::calc_altsvc_payload_len(origin.len, alt_svc_val.len, stream_id);
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
    guard h2_internal::encode_altsvc_payload(out, origin, alt_svc_val, stream_id) else { return false; }
    committed = true;
    return true;
}
