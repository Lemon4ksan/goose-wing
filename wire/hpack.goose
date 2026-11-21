// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation HPACK integer and string wire codecs (RFC 7541).
namespace wire;

import std;
import core from "..";
import http.headers;
import http2.hpack;

const HPACK_PREFIX_MASKS: const u64[256] = [
    0, 1, 3, 7, 15, 31, 63, 127, 255, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

checkfree inline fn hpack_prefix_mask(prefix_bits: u8) -> u64 {
    return HPACK_PREFIX_MASKS[prefix_bits];
}

// Encodes an integer with an N-bit prefix into out (RFC 7541 Section 5.1).
fn hpack_encode_int<B>(out: B&, val: u64, prefix_bits: u8, prefix_mask: u8) -> bool {
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return false; }
    let max_prefix = hpack_prefix_mask(prefix_bits);

    if val < max_prefix {
        guard out.try_push(prefix_mask | (val as u8)) else { return false; }
        return true;
    }

    guard out.try_push(prefix_mask | (max_prefix as u8)) else { return false; }
    var rem = val - max_prefix;

    while rem >= 128 {
        guard out.try_push((0x80 | (rem & 0x7F)) as u8) else { return false; }
        rem = rem >> 7;
    }
    guard out.try_push((rem & 0x7F) as u8) else { return false; }
    return true;
}

// Encodes an indexed header field representation (RFC 7541 Section 6.1).
inline fn hpack_encode_indexed<B>(out: B&, index: u64) -> bool {
    guard index > 0 else { return false; }
    return hpack_encode_int(out, index, 7, 0x80);
}

// Encodes an uncompressed octet sequence string with 7-bit prefix length (RFC 7541 Section 5.2).
fn hpack_encode_string<B>(out: B&, str: const u8[:]) -> bool {
    let start_len = out.len;
    guard hpack_encode_int(out, str.len as u64, 7, 0x00) && out.try_append(str) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

// Encodes a literal header field without indexing (RFC 7541 Section 6.2.2).
fn hpack_encode_literal_without_indexing<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool {
    guard http2::validate_field_syntax(name, val) else { return false; }
    let start_len = out.len;
    guard out.try_push(0x00 as u8) &&
          hpack_encode_string(out, name) &&
          hpack_encode_string(out, val) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

// Encodes a literal header field never indexed (RFC 7541 Section 6.2.3).
fn hpack_encode_literal_never_indexed<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool {
    guard http2::validate_field_syntax(name, val) else { return false; }
    let start_len = out.len;
    guard out.try_push(0x10 as u8) &&
          hpack_encode_string(out, name) &&
          hpack_encode_string(out, val) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

// Decodes a variable-length multi-byte HPACK integer continuation (RFC 7541 Section 5.1).
// Advances `offset` past the multi-byte integer octets.
//
// Example:
//   src = [0x9A, 0x0A], offset = 0, initial_offset = 0, max_prefix = 127
//   returns: val = 1461, ok = true, offset = 2
fn decode_hpack_int_multibyte(src: const u8[:], offset: u64&, initial_offset: u64, max_prefix: u64) -> u64, bool {
    var committed = false;
    defer if !committed { offset = initial_offset; };
    var val: u64 = max_prefix;
    var m:   u64 = 0;
    while offset < (src.len as u64) {
        let nb = src[offset];
        offset += 1;
        let term = ((nb & 0x7F) as u64) << m;
        guard val <= (0xFFFFFFFFFFFFFFFF - term) else { return 0, false; }
        val += term;
        m += 7;
        if (nb & 0x80) == 0 {
            committed = true;
            return val, true;
        }
        guard m <= 56 else { return 0, false; }
    }
    return 0, false;
}

// Decodes an integer with an N-bit prefix from slice and advances cursor (RFC 7541 Section 5.1).
//
// Example:
//   src = [0x82], offset = 0, prefix_bits = 7
//   returns: val = 2, ok = true, offset = 1
fn hpack_decode_int(src: const u8[:], offset: u64&, prefix_bits: u8) -> u64, bool {
    let initial_offset = offset;
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return 0, false; }
    guard offset < (src.len as u64) else { return 0, false; }

    let max_prefix = hpack_prefix_mask(prefix_bits);
    let mask = max_prefix as u8;
    let b = src[offset];
    offset += 1;

    let val = (b & mask) as u64;
    guard val == max_prefix else { return val, true; }

    return decode_hpack_int_multibyte(src, offset, initial_offset, max_prefix);
}

// Decodes raw or Huffman-encoded HPACK string and advances cursor (RFC 7541 Section 5.2).
//
// Example:
//   src = [0x04, 't', 'e', 's', 't'], offset = 0
//   returns: ok = true, out = "test", offset = 5
fn hpack_decode_string<B>(src: const u8[:], offset: u64&, out: B&) -> bool {
    let initial_offset = offset;
    var committed = false;
    defer if !committed { offset = initial_offset; };
    guard offset < (src.len as u64) else { return false; }
    let is_huffman = (src[offset] & 0x80) != 0;

    let str_len, len_ok = hpack_decode_int(src, offset, 7);
    let rem = (src.len as u64) - offset;
    guard len_ok && str_len <= rem else { return false; }
    let end = offset + str_len;
    let raw_slice = src[offset..end];
    if is_huffman {
        guard http2::huff_decode_bytes(raw_slice, out) else { return false; }
    } else {
        guard out.try_append(raw_slice) else { return false; }
    }
    offset = end;
    committed = true;
    return true;
}

inline fn is_h2_skipped_header_name(name: const u8[:]) -> bool {
    return name.eq_ascii_fold("host")
        || name.eq_ascii_fold("connection")
        || name.eq_ascii_fold("keep-alive")
        || name.eq_ascii_fold("proxy-connection")
        || name.eq_ascii_fold("transfer-encoding")
        || name.eq_ascii_fold("upgrade");
}

enum WireHeaderSectionKind {
    Request,
    Response,
    Trailer,
}

fn is_valid_h2_request_pseudo_fields(pseudo: const http2::PseudoHeaders&) -> bool {
    guard pseudo.has_method && wing::is_valid_token_swar(pseudo.method[..]) else { return false; }
    if pseudo.has_authority {
        guard http2::is_valid_authority(pseudo.authority[..]) else { return false; }
    }
    if pseudo.has_protocol {
        // RFC 8441 Section 4: The Extended CONNECT Method - requires :scheme, :path, :authority, and token :protocol.
        guard pseudo.method[..] == "CONNECT" && pseudo.has_authority
            && pseudo.protocol.len > 0 && wing::is_valid_token_swar(pseudo.protocol[..]) else {
            return false;
        }
    }
    let is_classic_connect = pseudo.method[..] == "CONNECT" && !pseudo.has_protocol;
    if is_classic_connect {
        return pseudo.has_authority && !pseudo.has_scheme && !pseudo.has_path;
    }
    guard pseudo.has_scheme && http2::is_valid_scheme(pseudo.scheme[..]) else { return false; }
    guard pseudo.has_path && http2::is_valid_path(pseudo.path[..]) else { return false; }
    if pseudo.path[..] == "*" {
        return pseudo.method[..] == "OPTIONS";
    }
    return true;
}

fn encode_hpack_pseudo_fields<B>(
    dt:          http2::DynamicTable&,
    pseudo:      const http2::PseudoHeaders&,
    out:         B&,
    use_huffman: bool,
) -> bool {
    let has_req_pseudo = pseudo.has_method || pseudo.has_scheme || pseudo.has_path
        || pseudo.has_authority || pseudo.has_protocol;
    if pseudo.is_trailer {
        return !pseudo.has_status && !has_req_pseudo;
    }
    let inc = http2::HpackIndexing.Incremental;
    if pseudo.has_status {
        guard !has_req_pseudo && pseudo.status >= 100 && pseudo.status <= 599 && pseudo.status != 101 else {
            return false;
        }
        var st_buf: u8[..16] = [];
        pseudo.status.format_i64_dec(st_buf);
        return http2::encode_hpack_field(dt, out, ":status", st_buf[..], inc, use_huffman);
    }
    guard is_valid_h2_request_pseudo_fields(pseudo) else { return false; }
    if pseudo.has_method {
        guard http2::encode_hpack_field(dt, out, ":method", pseudo.method[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_protocol {
        guard http2::encode_hpack_field(dt, out, ":protocol", pseudo.protocol[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_scheme {
        guard http2::encode_hpack_field(dt, out, ":scheme", pseudo.scheme[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_authority {
        guard http2::encode_hpack_field(dt, out, ":authority", pseudo.authority[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_path {
        guard http2::encode_hpack_field(dt, out, ":path", pseudo.path[..], inc, use_huffman) else {
            return false;
        }
    }
    return true;
}

inline fn should_skip_h2_entry(
    headers:  const wing::HeaderMap&,
    raw_name: const u8[:],
    val:      const u8[:],
    kind:     WireHeaderSectionKind,
) -> bool {
    if raw_name.len > 0 && raw_name[0] == ':' {
        return true;
    }
    if is_h2_skipped_header_name(raw_name) || wing::is_token_in_connection_header_map(headers, raw_name) {
        return true;
    }
    // RFC 9113 Section 8.2.2: Connection-Specific Header Fields - TE is only permitted in requests with "trailers".
    if raw_name.eq_ascii_fold("te") {
        if kind == WireHeaderSectionKind.Trailer {
            return false;
        }
        if kind == WireHeaderSectionKind.Response {
            return true;
        }
        return !val.trim_lws().eq_ascii_fold("trailers");
    }
    return false;
}

inline fn is_forbidden_h2_trailer_field(lower_name: const u8[:]) -> bool {
    return lower_name == "content-length" || lower_name == "host"
        || lower_name == "trailer" || lower_name == "te";
}

fn encode_single_hpack_map_entry<B>(
    dt:          http2::DynamicTable&,
    headers:     const wing::HeaderMap&,
    e:           const wing::HeaderEntry&,
    kind:        WireHeaderSectionKind,
    out:         B&,
    use_huffman: bool,
) -> bool {
    let raw_name = wing::entry_name(headers, e);
    let val = wing::entry_value(headers, e);
    if should_skip_h2_entry(headers, raw_name, val, kind) {
        return true;
    }
    var lower_name: u8[..256] = [];
    guard raw_name.len > 0 && raw_name.len <= lower_name.cap else { return false; }
    raw_name.to_lower_ascii(lower_name);
    if kind == WireHeaderSectionKind.Trailer && is_forbidden_h2_trailer_field(lower_name[..]) {
        return false;
    }
    let eff_val = if lower_name[..] == "te" { "trailers" } else { val };
    guard http2::validate_field_syntax(lower_name[..], eff_val) else { return false; }
    let is_sens = wing::is_sensitive(e);
    let idx_mode = if is_sens {
        http2::HpackIndexing.NeverIndexed
    } else {
        http2::HpackIndexing.Incremental
    };
    return http2::encode_hpack_field(dt, out, lower_name[..], eff_val, idx_mode, use_huffman);
}

// Encodes HTTP/2 pseudo-headers and regular headers from `headers: const wing::HeaderMap&`
// into an HPACK block using dynamic table compression (RFC 7541, RFC 9113 §8.2).
// Automatically lowercases regular header names and strips HTTP/1.1 connection-specific headers.
//
// Example:
//   encode_hpack_from_map(dt, pseudo, headers, out, true)
//   returns: true, out contains encoded HPACK octets
fn encode_hpack_from_map<B>(
    dt:          http2::DynamicTable&,
    pseudo:      const http2::PseudoHeaders&,
    headers:     const wing::HeaderMap&,
    out:         B&,
    use_huffman: bool = true,
) -> bool {
    let start_len = out.len;
    let saved_dt = dt;
    var committed = false;
    defer if !committed {
        out.resize(start_len);
        dt = saved_dt;
    };
    guard encode_hpack_pseudo_fields(dt, pseudo, out, use_huffman) else { return false; }
    let kind = if pseudo.is_trailer {
        WireHeaderSectionKind.Trailer
    } else if pseudo.has_status {
        WireHeaderSectionKind.Response
    } else {
        WireHeaderSectionKind.Request
    };

    for &e in headers.entries {
        guard encode_single_hpack_map_entry(dt, headers, e, kind, out, use_huffman) else {
            return false;
        }
    }
    committed = true;
    return true;
}

fn coalesce_h2_cookie_headers(map: wing::HeaderMap&) -> bool {
    var count: i64 = 0;
    for &e in map.entries {
        if wing::entry_name(map, e).eq_ascii_fold("cookie") {
            count = core::add_sat_i64(count, 1);
        }
    }
    guard count >= 2 else { return true; }
    var combined: u8[..8192] = [];
    var first = true;
    for &e in map.entries {
        guard wing::entry_name(map, e).eq_ascii_fold("cookie") else { continue; }
        if !first {
            guard combined.try_append("; ") else { return false; }
        }
        first = false;
        guard combined.try_append(wing::entry_value(map, e)) else { return false; }
    }
    return wing::set_or_replace(map, "cookie", combined[..], true);
}

// Decodes an HPACK header block into `out_pseudo` and `out_headers` using `dt` (RFC 7541, RFC 9113 §8.2).
// Returns RFC 9113 error code (`rfc::H2_ERR_NO_ERROR` on success).
//
// Example:
//   src = [0x82, 0x86, 0x84], decode_hpack_to_map(dt, src, out_pseudo, out_headers)
//   returns: rfc::H2_ERR_NO_ERROR, out_pseudo.method = "GET"
fn decode_hpack_to_map(
    dt:                   http2::DynamicTable&,
    src:                  const u8[:],
    out_pseudo:           http2::PseudoHeaders&,
    out_headers:          wing::HeaderMap&,
    max_header_list_size: u32  = 8192,
    validate_http2_rules: bool = true,
) -> u32 {
    var offset: u64 = 0;
    let src_len = src.len as u64;
    var updates_allowed = true;
    var update_count: u32 = 0;
    var first_err:    u32 = rfc::H2_ERR_NO_ERROR;
    var committed = false;

    http2::clear_pseudo_headers(out_pseudo, true);
    out_headers.clear();
    defer if !committed {
        http2::clear_pseudo_headers(out_pseudo, true);
        out_headers.clear();
    };

    while offset < src_len {
        let next_off, err = http2::decode_hpack_field_step_to_map(
            dt,
            src,
            offset,
            updates_allowed,
            update_count,
            out_pseudo,
            out_headers,
            max_header_list_size,
            validate_http2_rules,
        );
        if err == rfc::H2_ERR_COMPRESSION_ERROR || next_off <= offset {
            return if err != rfc::H2_ERR_NO_ERROR { err } else { rfc::H2_ERR_COMPRESSION_ERROR };
        }
        if err != rfc::H2_ERR_NO_ERROR && first_err == rfc::H2_ERR_NO_ERROR {
            first_err = err;
        }
        offset = next_off;
    }

    guard first_err == rfc::H2_ERR_NO_ERROR else { return first_err; }

    if validate_http2_rules && !out_pseudo.is_trailer {
        let v_err = http2::validate_mandatory_pseudo_headers(out_pseudo);
        guard v_err == rfc::H2_ERR_NO_ERROR else { return v_err; }
        if out_pseudo.has_status && wing::has_header(out_headers, "te") {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }

    guard coalesce_h2_cookie_headers(out_headers) else {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }
    committed = true;
    return rfc::H2_ERR_NO_ERROR;
}

// Public HTTP/2 pseudo-header set (RFC 9113 Section 8.3).
struct WireH2PseudoHeaders {
    method:             u8[..16]   = [],
    scheme:             u8[..16]   = [],
    authority:          u8[..256]  = [],
    path:               u8[..2048] = [],
    protocol:           u8[..64]   = [],
    status:             i32        = 0,
    has_method:         bool       = false,
    has_scheme:         bool       = false,
    has_authority:      bool       = false,
    has_path:           bool       = false,
    has_protocol:       bool       = false,
    has_status:         bool       = false,
    has_regular_header: bool       = false,
    has_content_length: bool       = false,
    content_length_val: i64        = -1,
    is_trailer:         bool       = false,
    wireframe_size:     u32        = 0,
}

// Stateful public HPACK codec context bundling a dynamic table and accounting
// counters/limits without exposing `http2::DynamicTable` to callers.
struct WireHpackState {
    table:                http2::DynamicTable = http2::DynamicTable {},
    max_header_list_size: u32                 = 8192,
    blocks_encoded:       u64                 = 0,
    blocks_decoded:       u64                 = 0,
    bytes_encoded:        u64                 = 0,
    bytes_decoded:        u64                 = 0,
}

// Initializes a bounded stateful HPACK codec context (`max_table_size <= 4096`
// and `max_header_list_size > 0`).
//
// Example:
//   let st, ok = wire::init_hpack_state(4096, 8192);
//   returns: initialized WireHpackState, ok = true (or ok = false if limits invalid)
fn init_hpack_state(
    max_table_size:       u64 = 4096,
    max_header_list_size: u32 = 8192,
) -> WireHpackState, bool {
    guard max_table_size <= http2::HPACK_MAX_ARENA_BYTES && max_header_list_size > 0 else {
        return WireHpackState {}, false;
    }
    return WireHpackState {
        table:                http2::new_dynamic_table(max_table_size),
        max_header_list_size: max_header_list_size,
        ..
    }, true;
}

// Updates the active dynamic table max size within the negotiated arena cap and
// evicts entries exceeding `new_max_size` (RFC 7541 Section 4.2).
//
// Example:
//   let ok = wire::hpack_reset_table_size(st, 1024);
//   returns: true if within bounds, false otherwise
fn hpack_reset_table_size(state: WireHpackState&, new_max_size: u64) -> bool {
    guard new_max_size <= state.table.max_allowed_size &&
          new_max_size <= http2::HPACK_MAX_ARENA_BYTES else {
        return false;
    }
    http2::update_dynamic_table_max_size(state.table, new_max_size);
    return true;
}

// Builds and validates HTTP/2 request pseudo-headers (`:method`, `:scheme`,
// optional `:authority`, and optional `:path`) (RFC 9113 Section 8.3.1).
//
// Example:
//   let pseudo, ok = wire::make_h2_request_pseudo("GET", "https", "example.com", "/");
//   returns: populated WireH2PseudoHeaders, ok = true
fn make_h2_request_pseudo(
    method:    const u8[:],
    scheme:    const u8[:],
    authority: const u8[:],
    path:      const u8[:],
) -> WireH2PseudoHeaders, bool {
    var p = WireH2PseudoHeaders {};
    guard method.len > 0 && p.method.try_set(method) else { return WireH2PseudoHeaders {}, false; }
    for b in method {
        guard core::is_tchar(b) else { return WireH2PseudoHeaders {}, false; }
    }
    guard http2::is_valid_scheme(scheme) && p.scheme.try_set(scheme) else {
        return WireH2PseudoHeaders {}, false;
    }
    p.has_method = true;
    p.has_scheme = true;

    if authority.len > 0 {
        guard http2::is_valid_authority(authority) && p.authority.try_set(authority) else {
            return WireH2PseudoHeaders {}, false;
        }
        p.has_authority = true;
    }
    if path.len > 0 {
        guard http2::is_valid_path(path) && p.path.try_set(path) else {
            return WireH2PseudoHeaders {}, false;
        }
        p.has_path = true;
    }
    return p, true;
}

// Builds and validates HTTP/2 response `:status` pseudo-headers (`100..599`)
// (RFC 9113 Section 8.3.2).
//
// Example:
//   let pseudo, ok = wire::make_h2_response_pseudo(200);
//   returns: WireH2PseudoHeaders { status: 200, has_status: true, .. }, ok = true
fn make_h2_response_pseudo(status: i32) -> WireH2PseudoHeaders, bool {
    guard status >= 100 && status <= 599 else { return WireH2PseudoHeaders {}, false; }
    return WireH2PseudoHeaders { status: status, has_status: true, .. }, true;
}

fn to_internal_h2_pseudo(src: const WireH2PseudoHeaders&) -> http2::PseudoHeaders {
    var dst = http2::PseudoHeaders {
        status:             src.status,
        has_method:         src.has_method,
        has_scheme:         src.has_scheme,
        has_authority:      src.has_authority,
        has_path:           src.has_path,
        has_protocol:       src.has_protocol,
        has_status:         src.has_status,
        has_regular_header: src.has_regular_header,
        has_content_length: src.has_content_length,
        content_length_val: src.content_length_val,
        is_trailer:         src.is_trailer,
        wireframe_size:     src.wireframe_size,
        ..
    };
    dst.method.try_set(src.method[..]);
    dst.scheme.try_set(src.scheme[..]);
    dst.authority.try_set(src.authority[..]);
    dst.path.try_set(src.path[..]);
    dst.protocol.try_set(src.protocol[..]);
    return dst;
}

fn from_internal_h2_pseudo(src: const http2::PseudoHeaders&) -> WireH2PseudoHeaders {
    var dst = WireH2PseudoHeaders {
        status:             src.status,
        has_method:         src.has_method,
        has_scheme:         src.has_scheme,
        has_authority:      src.has_authority,
        has_path:           src.has_path,
        has_protocol:       src.has_protocol,
        has_status:         src.has_status,
        has_regular_header: src.has_regular_header,
        has_content_length: src.has_content_length,
        content_length_val: src.content_length_val,
        is_trailer:         src.is_trailer,
        wireframe_size:     src.wireframe_size,
        ..
    };
    dst.method.try_set(src.method[..]);
    dst.scheme.try_set(src.scheme[..]);
    dst.authority.try_set(src.authority[..]);
    dst.path.try_set(src.path[..]);
    dst.protocol.try_set(src.protocol[..]);
    return dst;
}

// Encodes HTTP/2 pseudo-headers and regular headers into an HPACK block using
// `state`, rolling back `out` and `state` cleanly on failure (RFC 7541).
//
// Example:
//   let ok = wire::hpack_encode_header_block(st, pseudo, headers, out, true);
//   returns: true with HPACK block appended to `out` and `st.blocks_encoded` incremented
fn hpack_encode_header_block<B>(
    state:       WireHpackState&,
    pseudo:      const WireH2PseudoHeaders&,
    headers:     const wing::HeaderMap&,
    out:         B&,
    use_huffman: bool = true,
) -> bool {
    let start_len = out.len;
    let saved_table = state.table;
    var committed = false;
    defer if !committed {
        out.resize(start_len);
        state.table = saved_table;
    };

    let int_pseudo = to_internal_h2_pseudo(pseudo);
    guard encode_hpack_from_map(state.table, int_pseudo, headers, out, use_huffman) else {
        return false;
    }

    let encoded_bytes = core::sub_sat_i64(out.len, start_len) as u64;
    state.blocks_encoded = core::add_sat_u64(state.blocks_encoded, 1);
    state.bytes_encoded = core::add_sat_u64(state.bytes_encoded, encoded_bytes);
    committed = true;
    return true;
}

// Decodes an HPACK header block into `out_pseudo` and `out_headers` using
// `state`, rolling back `state.table`, `out_pseudo`, and `out_headers` on any
// error (RFC 7541, RFC 9113 Section 8.2).
//
// Example:
//   let err = wire::hpack_decode_block(st, raw, out_pseudo, out_headers);
//   returns: rfc::H2_ERR_NO_ERROR with `out_pseudo` and `out_headers` populated
fn hpack_decode_block(
    state:                WireHpackState&,
    src:                  const u8[:],
    out_pseudo:           WireH2PseudoHeaders&,
    out_headers:          wing::HeaderMap&,
    validate_http2_rules: bool = true,
) -> u32 {
    let saved_table = state.table;
    let was_trailer = out_pseudo.is_trailer;
    var int_pseudo = http2::PseudoHeaders { is_trailer: was_trailer, .. };

    let err = decode_hpack_to_map(
        state.table,
        src,
        int_pseudo,
        out_headers,
        state.max_header_list_size,
        validate_http2_rules,
    );
    guard err == rfc::H2_ERR_NO_ERROR else {
        // RFC 7541 Section 2.2: Encoding and Decoding Contexts - retain table updates on stream-level HTTP/2 errors.
        if err == rfc::H2_ERR_COMPRESSION_ERROR {
            state.table = saved_table;
        }
        out_pseudo = WireH2PseudoHeaders { is_trailer: was_trailer, .. };
        out_headers.clear();
        return err;
    }

    out_pseudo = from_internal_h2_pseudo(int_pseudo);
    state.blocks_decoded = core::add_sat_u64(state.blocks_decoded, 1);
    state.bytes_decoded = core::add_sat_u64(state.bytes_decoded, src.len as u64);
    return rfc::H2_ERR_NO_ERROR;
}
