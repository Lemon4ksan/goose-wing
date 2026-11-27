// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Binary HTTP messages (RFC 9292), known-length framing only.
// Zero-allocation codec: decode outputs land in fixed struct buffers;
// encode writes into a caller-owned u8[..8192] and reports overflow as -1.
namespace http;

import std;
import core;
import .headers;
import http.codec_internal;

// ---- RFC 9292 Framing Indicators (Section 3.3) -----------------------------

// Binary-encoded HTTP request (RFC 9292 Section 3.1 known-length form).
// `scheme`, `authority`, and `target` map to RFC 9292 Section 3.4 Request Control Data
// (Method, Scheme, Authority, Path). When `target` is a full URL, `bhttp_encode_request`
// decomposes it into `(scheme, authority, path)` automatically.
struct BhttpRequest {
    method:    u8[..16]   = "GET",
    scheme:    u8[..16]   = "https",
    authority: u8[..256]  = [],
    target:    u8[..2048] = [],
    headers:   HeaderMap  = HeaderMap { .. },
    body:      u8[..4096] = [],
    body_len:  i32        = 0,
}

// Binary-encoded HTTP response (RFC 9292 Section 3.1 known-length form).
// Final status only; informational responses (Section 3.5.1) are out of scope.
struct BhttpResponse {
    status:   i32        = 200,
    headers:  HeaderMap  = HeaderMap { .. },
    body:     u8[..4096] = [],
    body_len: i32        = 0,
}

// ---- variable-length integer helpers (RFC 9000 Section 16 encoding) --------

// Consumes one length-prefixed byte string starting at idx (RFC 9292 Section 3.6).
// Advances idx past the value on success; idx is unchanged on failure.
//
// Example:
//   raw = [0x03, 'G', 'E', 'T'], idx = 0
//   returns: value = "GET", ok = true, idx = 4
fn bhttp_read_len_bytes(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    var scan = idx;
    let n, ok = quic::decode_varint_cursor(raw, scan);
    guard ok else { return "", false; }
    guard n <= ((raw.len - scan) as u64) else { return "", false; }
    let end = scan + (n as i64);
    let val = raw[scan..end];
    idx = end;
    return val, true;
}

// ---- field section and content (RFC 9292 Sections 3.6-3.7) -----------------

// Decodes a single binary HTTP trailer field line and advances `idx` (RFC 9292 §3.3).
//
// Example:
//   sec = [0x04, 'e', 't', 'a', 'g', 0x02, '3', '3'], idx = 0
//   returns: true, idx = 8 (consumed 8 bytes)
fn bhttp_decode_trailer_line(sec: const u8[:], idx: i64&) -> bool {
    var scan = idx;
    let name_len, ok1 = quic::decode_varint_cursor(sec, scan);
    guard ok1 && name_len >= 1 && name_len <= ((sec.len - scan) as u64) else { return false; }
    let name_end = scan + (name_len as i64);
    let name = sec[scan..name_end];
    scan = name_end;

    let val_len, ok2 = quic::decode_varint_cursor(sec, scan);
    guard ok2 && val_len <= ((sec.len - scan) as u64) else { return false; }
    let val_end = scan + (val_len as i64);
    let val = sec[scan..val_end];

    guard !rfc::is_disallowed_trailer_field(name) else { return false; }
    guard is_valid_header_name_h2(name) && is_valid_header_value(val) else {
        return false;
    }
    idx = val_end;
    return true;
}

// ---- request codec (RFC 9292 Sections 3.1, 3.3, 3.4) -----------------------

// RFC 9292 Section 3.4: Request Control Data - Encodes a known-length binary HTTP request (framing indicator 0).
//
// Example:
//   req = { method: "GET", scheme: "https", target: "/index.html", ... }, out = []
//   returns: n > 0 with out[0] == 0x00, or -1 on overflow/invalid control data
fn bhttp_encode_request(req: const BhttpRequest&, out: u8[..8192]&) -> i32 {
    guard req.method.len >= 1 && is_valid_token_swar(req.method[..]) else { return -1; }
    guard req.body_len >= 0 && req.body_len <= req.body.len else { return -1; }

    var scheme_buf: u8[..16]   = [];
    var auth_buf:   u8[..256]  = [];
    var path_buf:   u8[..2048] = [];
    guard http_internal::resolve_bhttp_request_control(req, scheme_buf, auth_buf, path_buf) else { return -1; }

    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };

    out.push(rfc::BHTTP_FRAME_KNOWN_LEN_REQUEST);
    guard http_internal::bhttp_put_len_bytes(out, req.method[..]) else { return -1; }
    guard http_internal::bhttp_put_len_bytes(out, scheme_buf[..]) else { return -1; }
    guard http_internal::bhttp_put_len_bytes(out, auth_buf[..]) else { return -1; }
    guard http_internal::bhttp_put_len_bytes(out, path_buf[..]) else { return -1; }
    let blen = req.body_len as i64;
    guard http_internal::bhttp_encode_tail(req.headers, req.body[..blen], out) else { return -1; }
    committed = true;
    return out.len as i32;
}

// Decodes a known-length binary HTTP request; rejects framing indicators other
// than 0 (RFC 9292 Sections 3.3, 4). Truncated trailing sections decode as
// empty (Section 3.8). Leaves `out` reset on failure.
//
// Example:
//   raw = [0x00, 0x03, 'G', 'E', 'T', 0x05, 'h', 't', 't', 'p', 's', 0x00, 0x01, '/', 0x00], out = BhttpRequest { .. }
//   returns: ok = true, out.method = "GET", out.scheme = "https", out.target = "/"
fn bhttp_decode_request(raw: const u8[:], out: BhttpRequest&) -> bool {
    http_internal::reset_bhttp_request(out);

    var idx: i64 = 0;
    let frame, ok0 = quic::decode_varint_cursor(raw, idx);
    guard ok0 && frame == rfc::BHTTP_FRAME_KNOWN_LEN_REQUEST else { return false; }

    let method, ok1 = bhttp_read_len_bytes(raw, idx);
    guard ok1 && method.len >= 1 && method.len <= 16 && is_valid_token_swar(method) else {
        return false;
    }

    let scheme, ok2 = bhttp_read_len_bytes(raw, idx);
    let authority, ok3 = bhttp_read_len_bytes(raw, idx);
    let path, ok4 = bhttp_read_len_bytes(raw, idx);
    guard ok2 && ok3 && ok4 && http_internal::validate_bhttp_decoded_control(method, scheme, authority, path) else {
        return false;
    }
    out.method.append(method);
    out.scheme.append(scheme);
    out.authority.append(authority);
    out.target.append(path);

    if !http_internal::bhttp_decode_tail(raw, idx, out.headers, out.body, out.body_len) {
        http_internal::reset_bhttp_request(out);
        return false;
    }
    return true;
}

// ---- response codec (RFC 9292 Sections 3.1, 3.3, 3.5) ----------------------

// Encodes a known-length binary HTTP response (framing indicator 1).
// Informational responses (Section 3.5.1) are out of scope: status must be final.
//
// Example:
//   res = { status: 200, ... }, out = []
//   returns: n > 0 with out[0] == 0x01, or -1 on overflow/invalid status
fn bhttp_encode_response(res: const BhttpResponse&, out: u8[..8192]&) -> i32 {
    guard res.status >= 200 && res.status <= 599 else { return -1; }
    guard res.body_len >= 0 && res.body_len <= res.body.len else { return -1; }

    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };

    out.push(rfc::BHTTP_FRAME_KNOWN_LEN_RESPONSE);
    guard quic::encode_varint(res.status as u64, out) else { return -1; }
    let blen = res.body_len as i64;
    guard http_internal::bhttp_encode_tail(res.headers, res.body[..blen], out) else { return -1; }
    committed = true;
    return out.len as i32;
}

// Decodes a known-length binary HTTP response; rejects framing indicators other
// than 1 and non-final status codes (RFC 9292 Sections 3.3, 3.5, 4).
//
// Example:
//   raw = [0x01, 0x40, 0xC8], out = BhttpResponse { .. }
//   returns: ok = true, out.status = 200 (truncated sections decode as empty)
fn bhttp_decode_response(raw: const u8[:], out: BhttpResponse&) -> bool {
    out.status = 200;
    out.headers.reset_for_keep_alive();
    out.body.clear();
    out.body_len = 0;

    var idx: i64 = 0;
    let frame, ok0 = quic::decode_varint_cursor(raw, idx);
    guard ok0 && frame == rfc::BHTTP_FRAME_KNOWN_LEN_RESPONSE else { return false; }

    var status:     u64 = 0;
    var info_count: i32 = 0;
    loop {
        let st, ok1 = quic::decode_varint_cursor(raw, idx);
        guard ok1 && st >= 100 && st <= 599 && st != 101 else { return false; }
        status = st;
        guard status < 200 else { break; }
        info_count += 1;
        guard info_count <= 8 else { return false; }
        guard idx < raw.len else { return false; }
        let sec_len, ok_sec = quic::decode_varint_cursor(raw, idx);
        guard ok_sec && sec_len <= ((raw.len - idx) as u64) else { return false; }
        let sec_end = idx + (sec_len as i64);
        let sec = raw[idx..sec_end];
        var jdx: i64 = 0;
        var seen_regular = false;
        while jdx < sec.len {
            guard http_internal::bhttp_decode_field_line(sec, jdx, out.headers, seen_regular) else {
                out.headers.reset_for_keep_alive();
                return false;
            }
        }
        out.headers.reset_for_keep_alive();
        idx = sec_end;
    }
    out.status = status as i32;

    if !http_internal::bhttp_decode_tail(raw, idx, out.headers, out.body, out.body_len) {
        out.status = 200;
        out.headers.reset_for_keep_alive();
        out.body.clear();
        out.body_len = 0;
        return false;
    }
    return true;
}
