// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Binary HTTP messages (RFC 9292), known-length framing only.
// Zero-allocation codec: decode outputs land in fixed struct buffers;
// encode writes into a caller-owned u8[..8192] and reports overflow as -1.
namespace wing;

import std;
import core from "..";
import .headers;

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

// Encoded byte length of a bhttp length prefix (QUIC-style varint).
fn bhttp_varint_size(v: u64) -> u64 {
    if v <= 63 {
        return 1;
    }
    if v <= 16383 {
        return 2;
    }
    if v <= 1073741823 {
        return 4;
    }
    return 8;
}

// Appends one length-prefixed byte string (varint length + bytes) with an
// explicit capacity guard; returns false when the output would overflow.
fn bhttp_put_len_bytes(out: u8[..8192]&, val: const u8[:]) -> bool {
    let need = bhttp_varint_size(val.len as u64) + (val.len as u64);
    guard out.len + (need as i64) <= out.cap else { return false; }
    guard quic_internal::quic_encode_varint(out, val.len as u64) else { return false; }
    out.append(val);
    return true;
}

// Consumes one length-prefixed byte string starting at idx (RFC 9292 Section 3.6).
// Advances idx past the value on success; idx is unchanged on failure.
//
// Example:
//   raw = [0x03, 'G', 'E', 'T'], idx = 0
//   returns: value = "GET", ok = true, idx = 4
fn bhttp_read_len_bytes(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    var scan = idx;
    let n, ok = quic_internal::quic_decode_varint_cursor(raw, scan);
    guard ok else { return "", false; }
    guard n <= ((raw.len - scan) as u64) else { return "", false; }
    let end = scan + (n as i64);
    let val = raw[scan..end];
    idx = end;
    return val, true;
}

// ---- field section and content (RFC 9292 Sections 3.6-3.7) -----------------

// Serialized size in bytes of all field lines in a header map (Section 3.6).
fn bhttp_field_section_size(map: const HeaderMap&) -> u64 {
    var total: u64 = 0;
    for &entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if name.len == 0 {
            continue;
        }
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        total += bhttp_varint_size(name.len as u64) + (name.len as u64);
        total += bhttp_varint_size(val.len as u64) + (val.len as u64);
    }
    return total;
}

// Writes header section (length prefix + field lines), content, and empty
// trailers after control data; returns false on capacity overflow.
fn bhttp_encode_tail(map: const HeaderMap&, body: const u8[:], out: u8[..8192]&) -> bool {
    let section_len = bhttp_field_section_size(map);
    let section_need = bhttp_varint_size(section_len) + section_len;
    let content_need = bhttp_varint_size(body.len as u64) + (body.len as u64);
    // Pre-validate total capacity (section + content + 1-byte empty trailers)
    // so no partial write can occur on overflow.
    guard out.len + (section_need as i64) + (content_need as i64) + 1 <= out.cap else { return false; }
    guard quic_internal::quic_encode_varint(out, section_len) else { return false; }
    for &entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if name.len == 0 {
            continue;
        }
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        guard bhttp_put_len_bytes(out, name) else { return false; }
        guard bhttp_put_len_bytes(out, val) else { return false; }
    }

    guard bhttp_put_len_bytes(out, body) else { return false; } // content
    guard bhttp_put_len_bytes(out, "") else { return false; }   // empty trailers
    return true;
}

// Parses one field line at idx within the bounded view `sec`, appending it to
// `headers`. Enforces name length >= 1, bounds, pseudo-field ordering, and
// rejects the reserved pseudo-fields (RFC 9292 Section 3.6).
// Advances idx past the field line on success; idx is unchanged on failure.
//
// Example:
//   sec = [0x06, 'a', 'c', 'c', 'e', 'p', 't', 0x03, '*', '/', '*'], idx = 0
//   returns: ok = true, headers gains ("accept", "*/*"), idx = 11
fn bhttp_decode_field_line(
    sec:          const u8[:],
    idx:          i64&,
    headers:      HeaderMap&,
    seen_regular: bool&,
) -> bool {
    var scan = idx;
    let name_len, ok1 = quic_internal::quic_decode_varint_cursor(sec, scan);
    guard ok1 && name_len >= 1 && name_len <= ((sec.len - scan) as u64) else { return false; }
    let name_end = scan + (name_len as i64);
    let name = sec[scan..name_end];
    scan = name_end;

    let val_len, ok2 = quic_internal::quic_decode_varint_cursor(sec, scan);
    guard ok2 && val_len <= ((sec.len - scan) as u64) else { return false; }
    let val_end = scan + (val_len as i64);
    let val = sec[scan..val_end];

    if name[0] == ':' {
        // Pseudo-fields must precede regular fields; reserved names are invalid (Section 3.6).
        guard !seen_regular else { return false; }
        guard !rfc::bhttp_is_reserved_pseudo(name) else { return false; }
        guard is_valid_header_name_h2(name) && is_valid_header_value(val) else { return false; }
    } else {
        seen_regular = true;
        guard is_valid_header_name_h2(name) && is_valid_header_value(val) else { return false; }
    }
    guard headers.append_header(name, val) else { return false; }
    idx = val_end;
    return true;
}

// Decodes a single binary HTTP trailer field line and advances `idx` (RFC 9292 §3.3).
//
// Example:
//   sec = [0x04, 'e', 't', 'a', 'g', 0x02, '3', '3'], idx = 0
//   returns: true, idx = 8 (consumed 8 bytes)
fn bhttp_decode_trailer_line(sec: const u8[:], idx: i64&) -> bool {
    var scan = idx;
    let name_len, ok1 = quic_internal::quic_decode_varint_cursor(sec, scan);
    guard ok1 && name_len >= 1 && name_len <= ((sec.len - scan) as u64) else { return false; }
    let name_end = scan + (name_len as i64);
    let name = sec[scan..name_end];
    scan = name_end;

    let val_len, ok2 = quic_internal::quic_decode_varint_cursor(sec, scan);
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

// Shared tail of every known-length decode: field section, content, trailers,
// and zero-padding validation after control data (RFC 9292 Sections 3.1, 3.8).
// Truncated missing lengths are treated as zero (Section 3.8).
//
// Example:
//   raw = [0x03,'G','E','T',0x00,0x00,0x00,0x00,0x00,0x00], idx = 7
//   returns: ok = true, empty headers/body, idx = 10 (all sections zero-length)
fn bhttp_decode_tail(
    raw:      const u8[:],
    idx:      i64&,
    headers:  HeaderMap&,
    body:     u8[..4096]&,
    body_len: i32&,
) -> bool {
    var scan = idx;
    if scan < raw.len {
        let sec_len, ok = quic_internal::quic_decode_varint_cursor(raw, scan);
        guard ok && sec_len <= ((raw.len - scan) as u64) else { return false; }
        let sec_end = scan + (sec_len as i64);
        let sec = raw[scan..sec_end];
        var jdx: i64 = 0;
        var seen_regular = false;
        while jdx < sec.len {
            guard bhttp_decode_field_line(sec, jdx, headers, seen_regular) else { return false; }
        }
        scan = sec_end;
    }

    if scan < raw.len {
        let clen, ok = quic_internal::quic_decode_varint_cursor(raw, scan);
        guard ok && clen <= ((raw.len - scan) as u64) else { return false; }
        let cend = scan + (clen as i64);
        guard body.try_set(raw[scan..cend]) else { return false; }
        body_len = clen as i32;
        scan = cend;
    }

    if scan < raw.len {
        let tlen, ok = quic_internal::quic_decode_varint_cursor(raw, scan);
        guard ok && tlen <= ((raw.len - scan) as u64) else { return false; }
        let tend = scan + (tlen as i64);
        let trailers = raw[scan..tend];
        var jdx: i64 = 0;
        while jdx < trailers.len {
            // Trailer field lines are validated but discarded (Section 3.1).
            guard bhttp_decode_trailer_line(trailers, jdx) else { return false; }
        }
        scan = tend;
    }

    // Remaining bytes are padding and must be zero-valued (Section 3.8).
    while scan < raw.len {
        guard raw[scan] == 0 else { return false; }
        scan += 1;
    }
    idx = scan;
    return true;
}

// ---- request codec (RFC 9292 Sections 3.1, 3.3, 3.4) -----------------------

inline fn is_valid_bhttp_uri_part(s: const u8[:]) -> bool {
    for b in s {
        guard b > 0x20 && b < 0x7F else { return false; }
    }
    return true;
}

// RFC 9292 Section 3.4: Request Control Data - Scheme follows RFC 3986 ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
inline fn is_valid_bhttp_scheme(s: const u8[:]) -> bool {
    guard s.len > 0 && s.len <= 16 && core::is_ascii_alpha(s[0]) else { return false; }
    for b in s[1..] {
        guard core::is_ascii_alpha(b) || core::is_ascii_digit(b) || b == '+' || b == '-' || b == '.' else {
            return false;
        }
    }
    return true;
}

fn resolve_bhttp_full_url_control(
    raw_url:    const u8[:],
    scheme_out: u8[..16]&,
    auth_out:   u8[..256]&,
    path_out:   u8[..2048]&,
) -> bool {
    let view, _ = core::parse_url_view(raw_url);
    guard view.valid && is_valid_bhttp_scheme(view.scheme) && scheme_out.try_set(view.scheme) else {
        return false;
    }
    guard auth_out.try_set(view.host) else { return false; }
    if view.port > 0 {
        var pbuf: u8[..16] = [];
        view.port.format_i64_dec(pbuf);
        guard auth_out.try_push(':') && auth_out.try_append(pbuf[..]) else { return false; }
    }
    let p = if view.pathname.len > 0 { view.pathname } else { "/" };
    guard path_out.try_set(p) && (view.search.len == 0 || path_out.try_append(view.search)) else {
        return false;
    }
    return is_valid_bhttp_uri_part(auth_out[..]) && is_valid_bhttp_uri_part(path_out[..]);
}

fn resolve_bhttp_request_control(
    req:        const BhttpRequest&,
    scheme_out: u8[..16]&,
    auth_out:   u8[..256]&,
    path_out:   u8[..2048]&,
) -> bool {
    if core::contains(req.target[..], "://") {
        return resolve_bhttp_full_url_control(req.target[..], scheme_out, auth_out, path_out);
    }
    if req.method[..] == "CONNECT" {
        let auth_src = if req.authority.len > 0 {
            req.authority[..]
        } else if req.target.len > 0 {
            req.target[..]
        } else {
            req.headers.get_header("host")
        };
        return auth_src.len > 0 && is_valid_bhttp_uri_part(auth_src) && auth_out.try_set(auth_src);
    }
    guard is_valid_bhttp_scheme(req.scheme[..]) && scheme_out.try_set(req.scheme[..]) else {
        return false;
    }
    let auth_src = if req.authority.len > 0 { req.authority[..] } else { req.headers.get_header("host") };
    guard is_valid_bhttp_uri_part(auth_src) && auth_out.try_set(auth_src) else { return false; }
    return req.target.len > 0 && is_valid_bhttp_uri_part(req.target[..]) && path_out.try_set(req.target[..]);
}

// RFC 9292 Section 3.4: Request Control Data - Encodes a known-length binary HTTP request (framing indicator 0).
//
// Example:
//   req = { method: "GET", scheme: "https", target: "/index.html", ... }, out = []
//   returns: n > 0 with out[0] == 0x00, or -1 on overflow/invalid control data
fn bhttp_encode_request(req: const BhttpRequest&, out: u8[..8192]&) -> i32 {
    out.clear();
    guard req.method.len >= 1 && is_valid_token_swar(req.method[..]) else { return -1; }
    guard req.body_len >= 0 && req.body_len <= req.body.len else { return -1; }

    var scheme_buf: u8[..16]   = [];
    var auth_buf:   u8[..256]  = [];
    var path_buf:   u8[..2048] = [];
    guard resolve_bhttp_request_control(req, scheme_buf, auth_buf, path_buf) else { return -1; }

    var committed = false;
    defer if !committed { out.clear(); };

    out.push(rfc::BHTTP_FRAME_KNOWN_LEN_REQUEST);
    guard bhttp_put_len_bytes(out, req.method[..]) else { return -1; }
    guard bhttp_put_len_bytes(out, scheme_buf[..]) else { return -1; }
    guard bhttp_put_len_bytes(out, auth_buf[..]) else { return -1; }
    guard bhttp_put_len_bytes(out, path_buf[..]) else { return -1; }
    let blen = req.body_len as i64;
    guard bhttp_encode_tail(req.headers, req.body[..blen], out) else { return -1; }
    committed = true;
    return out.len as i32;
}

inline fn reset_bhttp_request(out: BhttpRequest&) {
    out.method.clear();
    out.scheme.clear();
    out.authority.clear();
    out.target.clear();
    out.headers.reset_for_keep_alive();
    out.body.clear();
    out.body_len = 0;
}

inline fn validate_bhttp_decoded_control(
    method:    const u8[:],
    scheme:    const u8[:],
    authority: const u8[:],
    path:      const u8[:],
) -> bool {
    if method == "CONNECT" {
        return scheme.len == 0 && path.len == 0 &&
               authority.len > 0 && authority.len <= 256 && is_valid_bhttp_uri_part(authority);
    }
    return is_valid_bhttp_scheme(scheme) &&
           authority.len <= 256 && is_valid_bhttp_uri_part(authority) &&
           path.len > 0 && path.len <= 2048 && is_valid_bhttp_uri_part(path);
}

// Decodes a known-length binary HTTP request; rejects framing indicators other
// than 0 (RFC 9292 Sections 3.3, 4). Truncated trailing sections decode as
// empty (Section 3.8). Leaves `out` reset on failure.
//
// Example:
//   raw = [0x00, 0x03, 'G', 'E', 'T', 0x05, 'h', 't', 't', 'p', 's', 0x00, 0x01, '/', 0x00], out = BhttpRequest { .. }
//   returns: ok = true, out.method = "GET", out.scheme = "https", out.target = "/"
fn bhttp_decode_request(raw: const u8[:], out: BhttpRequest&) -> bool {
    reset_bhttp_request(out);

    var idx: i64 = 0;
    let frame, ok0 = quic_internal::quic_decode_varint_cursor(raw, idx);
    guard ok0 && frame == rfc::BHTTP_FRAME_KNOWN_LEN_REQUEST else { return false; }

    let method, ok1 = bhttp_read_len_bytes(raw, idx);
    guard ok1 && method.len >= 1 && method.len <= 16 && is_valid_token_swar(method) else {
        return false;
    }

    let scheme, ok2 = bhttp_read_len_bytes(raw, idx);
    let authority, ok3 = bhttp_read_len_bytes(raw, idx);
    let path, ok4 = bhttp_read_len_bytes(raw, idx);
    guard ok2 && ok3 && ok4 && validate_bhttp_decoded_control(method, scheme, authority, path) else {
        return false;
    }
    out.method.append(method);
    out.scheme.append(scheme);
    out.authority.append(authority);
    out.target.append(path);

    if !bhttp_decode_tail(raw, idx, out.headers, out.body, out.body_len) {
        reset_bhttp_request(out);
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
    out.clear();
    guard res.status >= 200 && res.status <= 599 else { return -1; }
    guard res.body_len >= 0 && res.body_len <= res.body.len else { return -1; }

    var committed = false;
    defer if !committed { out.clear(); };

    out.push(rfc::BHTTP_FRAME_KNOWN_LEN_RESPONSE);
    guard quic_internal::quic_encode_varint(out, res.status as u64) else { return -1; }
    let blen = res.body_len as i64;
    guard bhttp_encode_tail(res.headers, res.body[..blen], out) else { return -1; }
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
    let frame, ok0 = quic_internal::quic_decode_varint_cursor(raw, idx);
    guard ok0 && frame == rfc::BHTTP_FRAME_KNOWN_LEN_RESPONSE else { return false; }

    var status: u64 = 0;
    loop {
        let st, ok1 = quic_internal::quic_decode_varint_cursor(raw, idx);
        guard ok1 && st >= 100 && st <= 599 else { return false; }
        status = st;
        guard status < 200 else { break; }
        guard idx < raw.len else { return false; }
        let sec_len, ok_sec = quic_internal::quic_decode_varint_cursor(raw, idx);
        guard ok_sec && sec_len <= ((raw.len - idx) as u64) else { return false; }
        let sec_end = idx + (sec_len as i64);
        let sec = raw[idx..sec_end];
        var jdx: i64 = 0;
        var seen_regular = false;
        while jdx < sec.len {
            guard bhttp_decode_field_line(sec, jdx, out.headers, seen_regular) else {
                out.headers.reset_for_keep_alive();
                return false;
            }
        }
        out.headers.reset_for_keep_alive();
        idx = sec_end;
    }
    out.status = status as i32;

    if !bhttp_decode_tail(raw, idx, out.headers, out.body, out.body_len) {
        out.status = 200;
        out.headers.reset_for_keep_alive();
        out.body.clear();
        out.body_len = 0;
        return false;
    }
    return true;
}
