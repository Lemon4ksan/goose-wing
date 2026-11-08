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
    guard internal::validate_h2_field_syntax(name, val) else { return false; }
    let start_len = out.len;
    guard out.try_push(0x00) &&
          hpack_encode_string(out, name) &&
          hpack_encode_string(out, val) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

// Encodes a literal header field never indexed (RFC 7541 Section 6.2.3).
fn hpack_encode_literal_never_indexed<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool {
    guard internal::validate_h2_field_syntax(name, val) else { return false; }
    let start_len = out.len;
    guard out.try_push(0x10) &&
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
        guard internal::huff_decode_bytes(raw_slice, out) else { return false; }
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

fn is_valid_h2_request_pseudo_fields(pseudo: const internal::H2PseudoHeaders&) -> bool {
    guard pseudo.has_method && wing::is_valid_token_swar(pseudo.method[..]) else { return false; }
    if pseudo.has_authority {
        guard internal::is_valid_h2_authority(pseudo.authority[..]) else { return false; }
    }
    if pseudo.has_protocol {
        guard pseudo.method[..] == "CONNECT" && pseudo.protocol.len > 0
            && internal::validate_h2_field_syntax(":protocol", pseudo.protocol[..]) else {
            return false;
        }
    }
    let is_classic_connect = pseudo.method[..] == "CONNECT" && !pseudo.has_protocol;
    if is_classic_connect {
        return pseudo.has_authority && !pseudo.has_scheme && !pseudo.has_path;
    }
    guard pseudo.has_scheme && internal::is_valid_h2_scheme(pseudo.scheme[..]) else { return false; }
    guard pseudo.has_path && internal::is_valid_h2_path(pseudo.path[..]) else { return false; }
    if pseudo.path[..] == "*" {
        return pseudo.method[..] == "OPTIONS";
    }
    return true;
}

fn encode_hpack_pseudo_fields<B>(
    dt:          internal::DynamicTable&,
    pseudo:      const internal::H2PseudoHeaders&,
    out:         B&,
    use_huffman: bool,
) -> bool {
    let has_req_pseudo = pseudo.has_method || pseudo.has_scheme || pseudo.has_path
        || pseudo.has_authority || pseudo.has_protocol;
    if pseudo.is_trailer {
        return !pseudo.has_status && !has_req_pseudo;
    }
    let inc = internal::HpackIndexing.Incremental;
    if pseudo.has_status {
        guard !has_req_pseudo && pseudo.status >= 100 && pseudo.status <= 599 && pseudo.status != 101 else {
            return false;
        }
        var st_buf: u8[..16] = [];
        (pseudo.status as u64).format_u64_dec(st_buf);
        return internal::encode_hpack_field(dt, out, ":status", st_buf[..], inc, use_huffman);
    }
    guard is_valid_h2_request_pseudo_fields(pseudo) else { return false; }
    if pseudo.has_method {
        guard internal::encode_hpack_field(dt, out, ":method", pseudo.method[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_protocol {
        guard internal::encode_hpack_field(dt, out, ":protocol", pseudo.protocol[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_scheme {
        guard internal::encode_hpack_field(dt, out, ":scheme", pseudo.scheme[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_authority {
        guard internal::encode_hpack_field(dt, out, ":authority", pseudo.authority[..], inc, use_huffman) else {
            return false;
        }
    }
    if pseudo.has_path {
        guard internal::encode_hpack_field(dt, out, ":path", pseudo.path[..], inc, use_huffman) else {
            return false;
        }
    }
    return true;
}

inline fn should_skip_h2_entry(
    headers:  const wing::HeaderMap&,
    raw_name: const u8[:],
    val:      const u8[:],
) -> bool {
    if raw_name.len > 0 && raw_name[0] == ':' {
        return true;
    }
    if is_h2_skipped_header_name(raw_name) || wing::is_token_in_connection_header_map(headers, raw_name) {
        return true;
    }
    return raw_name.eq_ascii_fold("te") && !val.trim_lws().eq_ascii_fold("trailers");
}

inline fn is_forbidden_h2_trailer_field(lower_name: const u8[:]) -> bool {
    return lower_name == "content-length" || lower_name == "host"
        || lower_name == "trailer" || lower_name == "te";
}

fn encode_single_hpack_map_entry<B>(
    dt:          internal::DynamicTable&,
    headers:     const wing::HeaderMap&,
    e:           const wing::HeaderEntry&,
    is_trailer:  bool,
    out:         B&,
    use_huffman: bool,
) -> bool {
    let raw_name = wing::entry_name(headers, e);
    let val = wing::entry_value(headers, e);
    if should_skip_h2_entry(headers, raw_name, val) {
        return true;
    }
    var lower_name: u8[..256] = [];
    guard raw_name.len > 0 && raw_name.len <= lower_name.cap else { return false; }
    raw_name.to_lower_ascii(lower_name);
    if is_trailer && is_forbidden_h2_trailer_field(lower_name[..]) {
        return false;
    }
    let eff_val = if lower_name[..] == "te" { "trailers" } else { val };
    guard internal::validate_h2_field_syntax(lower_name[..], eff_val) else { return false; }
    let is_sens = wing::is_sensitive(e);
    let idx_mode = if is_sens { internal::HpackIndexing.NeverIndexed } else { internal::HpackIndexing.Incremental };
    return internal::encode_hpack_field(dt, out, lower_name[..], eff_val, idx_mode, use_huffman);
}

// Encodes HTTP/2 pseudo-headers and regular headers from `headers: const wing::HeaderMap&`
// into an HPACK block using dynamic table compression (RFC 7541, RFC 9113 §8.2).
// Automatically lowercases regular header names and strips HTTP/1.1 connection-specific headers.
//
// Example:
//   encode_hpack_from_map(dt, pseudo, headers, out, true)
//   returns: true, out contains encoded HPACK octets
fn encode_hpack_from_map<B>(
    dt:          internal::DynamicTable&,
    pseudo:      const internal::H2PseudoHeaders&,
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

    for &e in headers.entries {
        guard encode_single_hpack_map_entry(dt, headers, e, pseudo.is_trailer, out, use_huffman) else {
            return false;
        }
    }
    committed = true;
    return true;
}

// Decodes an HPACK header block into `out_pseudo` and `out_headers` using `dt` (RFC 7541, RFC 9113 §8.2).
// Returns RFC 9113 error code (`rfc::H2_ERR_NO_ERROR` on success).
//
// Example:
//   src = [0x82, 0x86, 0x84], decode_hpack_to_map(dt, src, out_pseudo, out_headers)
//   returns: rfc::H2_ERR_NO_ERROR, out_pseudo.method = "GET"
fn decode_hpack_to_map(
    dt:                   internal::DynamicTable&,
    src:                  const u8[:],
    out_pseudo:           internal::H2PseudoHeaders&,
    out_headers:          wing::HeaderMap&,
    max_header_list_size: u32  = 8192,
    validate_http2_rules: bool = true,
) -> u32 {
    var offset: u64 = 0;
    let src_len = src.len as u64;
    var updates_allowed = true;
    var update_count: u32 = 0;

    internal::clear_h2_pseudo_headers(out_pseudo, true);
    out_headers.clear();

    while offset < src_len {
        let next_off, err = internal::decode_hpack_field_step_to_map(
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
        guard err == rfc::H2_ERR_NO_ERROR else { return err; }
        offset = next_off;
    }

    if validate_http2_rules && !out_pseudo.is_trailer {
        let v_err = internal::validate_mandatory_pseudo_headers(out_pseudo);
        guard v_err == rfc::H2_ERR_NO_ERROR else { return v_err; }
    }
    return rfc::H2_ERR_NO_ERROR;
}
