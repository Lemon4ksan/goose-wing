// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC status code management, percent-encoded grpc-message, and grpc-timeout codecs.
// Conforms to gRPC Over HTTP/2 Specification and RFC 3986.
namespace wing;

import std;
import grpc.constants;
import http.headers;

// ---- 1. Hex Helpers & Percent Codec for grpc-message ------------------------

inline fn grpc_hex_val(c: u8) -> i32 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

inline fn grpc_hex_char(n: u8) -> u8 {
    return if n < 10 { '0' + n } else { 'A' + n - 10 };
}

// Percent-encodes message string for `grpc-message` header.
// Characters in 0x20..0x7E except '%' remain unescaped; all others are %XX encoded.
fn encode_grpc_message<B>(raw: const u8[:], out: B&) {
    for b in raw {
        if b >= 0x20 && b <= 0x7E && b != '%' {
            out.push(b);
        } else {
            out.push('%');
            out.push(grpc_hex_char((b >> 4) & 0x0F));
            out.push(grpc_hex_char(b & 0x0F));
        }
    }
}

// Percent-decodes `grpc-message` header value into raw message bytes.
//
// Example:
//   encoded = "unknown%20error"
//   returns: out = "unknown error"
fn decode_grpc_message<B>(encoded: const u8[:], out: B&) {
    out.clear();
    var i = 0;
    while i < encoded.len {
        if encoded[i] == '%' && i + 2 < encoded.len {
            let h = grpc_hex_val(encoded[i + 1]);
            let l = grpc_hex_val(encoded[i + 2]);
            if h >= 0 && l >= 0 {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(encoded[i]);
        i++;
    }
}

// ---- 2. grpc-timeout Codec (Units: H, M, S, m, u, n) -----------------------

// Formats millisecond duration into standard gRPC timeout string.
fn encode_grpc_timeout<B>(timeout_ms: u64, out: B&) {
    guard timeout_ms > 0 else { return; }

    if timeout_ms % 3600000 == 0 {
        core::format_u64_dec(timeout_ms / 3600000, out);
        out.push('H');
    } else if timeout_ms % 60000 == 0 {
        core::format_u64_dec(timeout_ms / 60000, out);
        out.push('M');
    } else if timeout_ms % 1000 == 0 {
        core::format_u64_dec(timeout_ms / 1000, out);
        out.push('S');
    } else {
        core::format_u64_dec(timeout_ms, out);
        out.push('m');
    }
}

// Parses standard gRPC timeout string into milliseconds.
// Supports H (Hours), M (Minutes), S (Seconds), m (Millis), u (Micros), n (Nanos).
//
// Example:
//   val = "100m"
//   returns: 100, true
fn parse_grpc_timeout(val: const u8[:]) -> u64, bool {
    let trimmed = trim_lws(val);
    guard trimmed.len >= 2 else { return 0, false; }

    let unit = trimmed[trimmed.len - 1];
    let num_slice = trimmed[..(trimmed.len - 1)];

    guard num_slice.len <= 8 else { return 0, false; } // gRPC spec max 8 digits
    let num, ok_num = core::parse_u64_dec(num_slice);
    guard ok_num else { return 0, false; }

    var multiplier: u64 = 0;
    if unit == 'H' {
        multiplier = 3600000;
    } else if unit == 'M' {
        multiplier = 60000;
    } else if unit == 'S' {
        multiplier = 1000;
    } else if unit == 'm' {
        multiplier = 1;
    } else if unit == 'u' {
        let ms = if num > 0 && num < 1000 { 1 } else { num / 1000 };
        return ms, true;
    } else if unit == 'n' {
        let ms = if num > 0 && num < 1000000 { 1 } else { num / 1000000 };
        return ms, true;
    } else {
        return 0, false;
    }

    return num * multiplier, true;
}

// ---- 3. Status Extraction from Headers & Trailers --------------------------

// Extracts gRPC status and message from trailers (or headers in Trailers-Only responses).
// Returns true if a wire grpc-status header was explicitly found.
// If absent, falls back to mapping the HTTP status code and returns false.
//
// Example:
//   headers = { ":status": "200" }, trailers = { "grpc-status": "0" }
//   returns: true, out_status = GrpcStatusCode.Ok
fn extract_grpc_status(
    headers:     const HeaderMap&,
    trailers:    const HeaderMap&,
    out_status:  GrpcStatusCode&,
    out_message: u8[..256]&,
) -> bool {
    out_message.clear();

    // 1. Check trailers first
    let trailer_status = get_header(trailers, HEADER_GRPC_STATUS);
    if trailer_status.len > 0 {
        let code_int, ok_code = core::parse_u32_dec(trim_lws(trailer_status));
        if ok_code {
            out_status = grpc_status_from_code(code_int);
        } else {
            out_status = GrpcStatusCode.Unknown;
        }

        let trailer_msg = get_header(trailers, HEADER_GRPC_MESSAGE);
        if trailer_msg.len > 0 {
            decode_grpc_message(trailer_msg, out_message);
        }
        return true;
    }

    // 2. Check headers (Trailers-Only response)
    let header_status = get_header(headers, HEADER_GRPC_STATUS);
    if header_status.len > 0 {
        let code_int, ok_code = core::parse_u32_dec(trim_lws(header_status));
        if ok_code {
            out_status = grpc_status_from_code(code_int);
        } else {
            out_status = GrpcStatusCode.Unknown;
        }

        let header_msg = get_header(headers, HEADER_GRPC_MESSAGE);
        if header_msg.len > 0 {
            decode_grpc_message(header_msg, out_message);
        }
        return true;
    }

    // 3. Fallback to HTTP status mapping
    out_status = grpc_status_from_http(headers.status_code);
    return false;
}
