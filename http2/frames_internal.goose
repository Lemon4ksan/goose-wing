// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal extension frame and binary framing helpers for package http2.
namespace h2_internal;

import std;
import core;
import rfc.h2;
import .framing;

// ---- Extension Frame Constants & Helpers (RFC 8336 / RFC 7838) -----------

checkfree inline fn h2_read_be_u16(s: const u8[:]) -> u16 {
    if s.len < 2 { return 0; }
    return ((s[0] as u16) << 8) | s[1];
}

checkfree inline fn h2_read_be_u24(s: const u8[:]) -> u32 {
    if s.len < 3 { return 0; }
    let hi = h2_read_be_u16(s) as u32;
    return (hi << 8) | s[2];
}

checkfree inline fn h2_read_be_u32(s: const u8[:]) -> u32 {
    if s.len < 4 { return 0; }
    let hi = h2_read_be_u16(s) as u32;
    let lo = h2_read_be_u16(s[2..]) as u32;
    return (hi << 16) | lo;
}

// Decodes a single Origin Entry from slice without cursor mutation.
//
// Example:
//   rem = [0x00, 0x06, 'e', 'x', '.', 'c', 'o', 'm']
//   returns: "ex.com", total = 8, ok = true
checkfree inline fn decode_origin_slice(rem: const u8[:]) -> const u8[:], i64, bool {
    guard rem.len >= 2 else { return "", 0, false; }
    let len = h2_read_be_u16(rem) as i64;
    let total = core::add_sat_i64(2, len);
    guard total >= 2 && total <= rem.len else { return "", 0, false; }
    return rem[2..total], total, true;
}

inline fn is_valid_h2_origin_scheme(scheme: const u8[:]) -> bool {
    guard scheme.len > 0 && core::is_ascii_alpha(scheme[0]) else { return false; }
    for b in scheme {
        let ok = (b >= 'a' && b <= 'z') || core::is_ascii_digit(b)
            || b == '+' || b == '-' || b == '.';
        guard ok else { return false; }
    }
    return true;
}

inline fn is_valid_h2_origin_port(port_str: const u8[:]) -> bool {
    guard port_str.len >= 1 && port_str.len <= 5 && port_str[0] != '0' else {
        return false;
    }
    for b in port_str {
        guard core::is_ascii_digit(b) else { return false; }
    }
    let port, ok = port_str.parse_u32_dec();
    return ok && port >= 1 && port <= 65535;
}

inline fn is_valid_h2_origin_ipv6_authority(rest: const u8[:]) -> bool {
    let ipv6_body, tail, has_close = rest[1..].split_once_byte(']');
    guard has_close && ipv6_body.len > 0 else { return false; }
    for b in ipv6_body {
        let ok = core::is_ascii_hexdigit(b) || b == ':' || b == '.';
        guard ok else { return false; }
    }
    if tail.len == 0 {
        return true;
    }
    guard tail[0] == ':' else { return false; }
    return is_valid_h2_origin_port(tail[1..]);
}

// RFC 8336 Section 2.2: Processing ORIGIN Frames - Validates serialized ASCII-Origin syntax.
fn is_valid_h2_origin_entry(raw: const u8[:]) -> bool {
    let scheme, rest, has_sep = raw.split_once("://");
    guard has_sep && is_valid_h2_origin_scheme(scheme) && rest.len > 0 else {
        return false;
    }
    for b in raw {
        guard core::is_ascii_vchar(b) else { return false; }
    }
    if rest[0] == '[' {
        return is_valid_h2_origin_ipv6_authority(rest);
    }
    let host, port_str, has_port = rest.split_once_byte(':');
    let eff_host = if has_port { host } else { rest };
    guard eff_host.len > 0 else { return false; }
    for b in eff_host {
        let bad = b == '/' || b == '?' || b == '#' || b == '@'
            || b == '*' || b == ':' || b == '[' || b == ']';
        guard !bad else { return false; }
    }
    if has_port {
        return is_valid_h2_origin_port(port_str);
    }
    return true;
}

// RFC 8336 Section 2.1: Syntax - Encodes a single Origin Entry into output buffer.
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
        payload_len = core::add_sat_u64(payload_len, core::add_sat_u64(2, org.len as u64));
    }
    guard payload_len <= 16384 else { return 0, false; }
    return payload_len as u32, true;
}

// RFC 7838 Section 4: The ALTSVC HTTP/2 Frame - Encodes ALTSVC frame payload into buffer.
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
        len_be.append_u16_be(0);
        guard out.try_append(len_be[..]) else { return false; }
    }
    guard out.try_append(alt_svc_val) else { return false; }
    committed = true;
    return true;
}

inline fn calc_altsvc_payload_len(origin_len: i64, alt_svc_len: i64, stream_id: u32) -> u32, bool {
    let eff_origin: u64 = if stream_id == 0 { origin_len as u64 } else { 0 };
    let total = core::add_sat_u64(2, core::add_sat_u64(eff_origin, alt_svc_len as u64));
    guard total <= 16384 else { return 0, false; }
    return total as u32, true;
}

// ---- Binary Framing Validation Helper (RFC 9113 §4.2) --------------------

// Returns true iff `len` is a multiple of 6 (RFC 9113 Section 6.5 SETTINGS entry width).
checkfree inline fn is_multiple_of_six(len: u32) -> bool {
    guard (len & 1) == 0 else { return false; }
    var x = len >> 1;
    x = core::add_sat_u32(x & 0xFFFF, x >> 16);
    x = core::add_sat_u32(x & 0xFF, x >> 8);
    x = core::add_sat_u32(x & 0xF, x >> 4);
    x = core::add_sat_u32(x & 0x3, x >> 2);
    x = core::add_sat_u32(x & 0x3, x >> 2);
    return x == 0 || x == 3 || x == 6;
}

// Validates fixed-size and SETTINGS HTTP/2 frame lengths (RFC 9113 Section 4.2).
checkfree inline fn validate_fixed_frame_length(hdr: const http2::FrameHeader&) -> u32 {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS {
        let ok = if (hdr.flags & rfc::H2_FLAG_ACK) != 0 { hdr.length == 0 } else { is_multiple_of_six(hdr.length) };
        return if ok { rfc::H2_ERR_NO_ERROR } else { rfc::H2_ERR_FRAME_SIZE_ERROR };
    }
    var expected: i32 = -1;
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM || hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE {
        expected = 4;
    } else if hdr.frame_type == rfc::H2_FRAME_PING {
        expected = 8;
    } else if hdr.frame_type == rfc::H2_FRAME_PRIORITY {
        expected = 5;
    }
    if expected >= 0 && hdr.length != (expected as u32) {
        return rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    return rfc::H2_ERR_NO_ERROR;
}

// Computes the mandatory minimum payload length for variable-size HTTP/2 frames (RFC 9113 Section 4.2).
checkfree inline fn min_variable_frame_length(hdr: const http2::FrameHeader&) -> u32 {
    let pad_len: u32 = if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 { 1 } else { 0 };
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY { return 8; }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY_UPDATE { return 4; }
    if hdr.frame_type == rfc::H2_FRAME_ALTSVC { return 2; }
    if hdr.frame_type == rfc::H2_FRAME_PUSH_PROMISE { return core::add_sat_u32(4, pad_len); }
    if hdr.frame_type == rfc::H2_FRAME_DATA { return pad_len; }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        let prio_len: u32 = if (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 { 5 } else { 0 };
        return core::add_sat_u32(pad_len, prio_len);
    }
    return 0;
}

// RFC 9113 Section 4.2: Frame Size - An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame type, or is too small to contain mandatory frame data.
checkfree fn validate_frame_type_length(hdr: const http2::FrameHeader&) -> u32 {
    let fixed_err = validate_fixed_frame_length(hdr);
    guard fixed_err == rfc::H2_ERR_NO_ERROR else { return fixed_err; }
    if hdr.length < min_variable_frame_length(hdr) {
        return rfc::H2_ERR_FRAME_SIZE_ERROR;
    }
    return rfc::H2_ERR_NO_ERROR;
}
