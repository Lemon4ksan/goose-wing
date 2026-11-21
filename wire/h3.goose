// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Sans-IO HTTP/3 QPACK header and frame codecs (RFC 9114, RFC 9204).
namespace wire;

import std;
import core from "..";
import http.headers;
import http3.qpack;
import http3.framing;
import http3.connection;
import .hpack;

inline fn is_valid_h3_request_stream_id(stream_id: u64) -> bool {
    // RFC 9114 Section 4.1: HTTP Message Framing - HTTP/3 requests use client-initiated bidirectional streams.
    return stream_id <= rfc::QUIC_VARINT_MAX && (stream_id & 0x03) == 0;
}

fn is_valid_h3_request_pseudo_fields(pseudo: const http3::PseudoHeaders&) -> bool {
    guard pseudo.has_method && wing::is_valid_token_swar(pseudo.method[..]) else { return false; }
    if pseudo.has_authority {
        guard http2::is_valid_authority(pseudo.authority[..]) else { return false; }
    }
    if pseudo.has_protocol {
        // RFC 9220 Section 3: WebSockets Upgrade over HTTP/3 - Extended CONNECT requires :authority and token :protocol.
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

fn is_valid_h3_pseudo_fields(pseudo: const http3::PseudoHeaders&) -> bool {
    let has_req_pseudo = pseudo.has_method || pseudo.has_scheme || pseudo.has_path
        || pseudo.has_authority || pseudo.has_protocol;
    if pseudo.is_trailer {
        return !pseudo.has_status && !has_req_pseudo;
    }
    if pseudo.has_status {
        return !has_req_pseudo && pseudo.status >= 100 && pseudo.status <= 599 && pseudo.status != 101;
    }
    return is_valid_h3_request_pseudo_fields(pseudo);
}

fn encode_qpack_sensitive_field<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool {
    let start_len = out.len;
    let s_idx_name, _ = http3::find_qpack_static_field(name, "");
    let s_ent, ok_s = http3::get_qpack_static_field(s_idx_name);
    if ok_s && name == s_ent.name {
        guard http2::hpack_encode_int(out, s_idx_name, 4, 0x70)
            && http2::encode_hpack_string_literal(out, val, false) else {
            out.resize(start_len);
            return false;
        }
        return true;
    }
    guard http2::hpack_encode_int(out, name.len as u64, 3, 0x30)
        && out.try_append(name)
        && http2::encode_hpack_string_literal(out, val, false) else {
        out.resize(start_len);
        return false;
    }
    return true;
}

fn encode_h3_pseudo_fields<B1, B2>(
    tbl:            http3::QpackTable&,
    stream_id:      u64,
    base:           u64,
    pseudo:         const http3::PseudoHeaders&,
    body_fields:    B1&,
    out_enc_stream: B2&,
    max_dyn_abs:    u64&,
    used_any_dyn:   bool&,
) -> bool {
    guard is_valid_h3_request_stream_id(stream_id) && is_valid_h3_pseudo_fields(pseudo) else { return false; }
    guard !pseudo.is_trailer else { return true; }
    if pseudo.has_status {
        var st_buf: u8[..16] = [];
        pseudo.status.format_i64_dec(st_buf);
        let prev_len = body_fields.len;
        http3::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":status", st_buf[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        return body_fields.len > prev_len;
    }
    if pseudo.has_method {
        let prev_len = body_fields.len;
        http3::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":method", pseudo.method[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_scheme {
        let prev_len = body_fields.len;
        http3::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":scheme", pseudo.scheme[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_authority {
        let prev_len = body_fields.len;
        http3::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":authority", pseudo.authority[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_path {
        let prev_len = body_fields.len;
        http3::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":path", pseudo.path[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_protocol {
        let prev_len = body_fields.len;
        http3::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":protocol", pseudo.protocol[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    return true;
}

fn encode_single_h3_map_entry<B1, B2>(
    tbl:            http3::QpackTable&,
    stream_id:      u64,
    base:           u64,
    headers:        const wing::HeaderMap&,
    e:              const wing::HeaderEntry&,
    kind:           WireHeaderSectionKind,
    body_fields:    B1&,
    out_enc_stream: B2&,
    max_dyn_abs:    u64&,
    used_any_dyn:   bool&,
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
    if wing::is_sensitive(e) {
        return encode_qpack_sensitive_field(body_fields, lower_name[..], eff_val);
    }
    let prev_body = body_fields.len;
    http3::encode_qpack_field_dynamic(
        tbl, stream_id, base, lower_name[..], eff_val,
        body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, false,
    );
    return body_fields.len > prev_body;
}

// Encodes HTTP/3 pseudo-headers and regular headers from `headers: const wing::HeaderMap&`
// into an HTTP/3 HEADERS frame (Type 0x01) using QPACK compression (RFC 9114 §7.2.2, RFC 9204 §4.5).
//
// Example:
//   encode_h3_headers_from_map(tbl, 0, pseudo, headers, enc_stream, out)
//   returns: true, out contains HTTP/3 HEADERS frame octets
fn encode_h3_headers_from_map<B1, B2>(
    tbl:            http3::QpackTable&,
    stream_id:      u64,
    pseudo:         const http3::PseudoHeaders&,
    headers:        const wing::HeaderMap&,
    out_enc_stream: B1&,
    out_frame:      B2&,
) -> bool {
    guard is_valid_h3_request_stream_id(stream_id) else { return false; }
    let start_enc = out_enc_stream.len;
    let start_frame = out_frame.len;
    let saved_tbl = tbl;
    var committed = false;
    defer if !committed {
        out_enc_stream.resize(start_enc);
        out_frame.resize(start_frame);
        tbl = saved_tbl;
    };

    let base = tbl.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    var body_fields: u8[..16384] = [];

    guard encode_h3_pseudo_fields(
        tbl, stream_id, base, pseudo,
        body_fields, out_enc_stream, max_dyn_abs, used_any_dyn,
    ) else {
        return false;
    }

    let kind = if pseudo.is_trailer {
        WireHeaderSectionKind.Trailer
    } else if pseudo.has_status {
        WireHeaderSectionKind.Response
    } else {
        WireHeaderSectionKind.Request
    };

    for &e in headers.entries {
        guard encode_single_h3_map_entry(
            tbl, stream_id, base, headers, e, kind,
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn,
        ) else {
            return false;
        }
    }

    var qpack_payload: u8[..16384] = [];
    guard http3::prepend_qpack_section_prefix(tbl, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload) &&
          qpack_payload.try_append(body_fields[..]) &&
          http3::encode_headers_frame(out_frame, qpack_payload[..]) else {
        return false;
    }
    committed = true;
    return true;
}

// Decodes a QPACK field section payload directly into `out_pseudo` and `out_headers` (RFC 9204 §4.5).
//
// Example:
//   qpack_payload = [0x00, 0x00, 0xD1], decode_h3_headers_to_map(tbl, 0, qpack_payload, out_pseudo, out_headers)
//   returns: http3::QpackError.None, out_pseudo.method = "GET"
fn decode_h3_headers_to_map(
    tbl:               http3::QpackTable&,
    stream_id:         u64,
    qpack_payload:     const u8[:],
    out_pseudo:        http3::PseudoHeaders&,
    out_headers:       wing::HeaderMap&,
    max_field_section: u64 = 16384,
) -> http3::QpackError {
    let was_trailer = out_pseudo.is_trailer;
    var committed = false;
    defer if !committed {
        out_pseudo = http3::PseudoHeaders { is_trailer: was_trailer, .. };
        out_headers.clear();
    };
    guard is_valid_h3_request_stream_id(stream_id) else {
        return http3::QpackError.MessageError;
    }
    let err = http3::decode_or_block_qpack_to_map(
        tbl,
        stream_id,
        qpack_payload,
        out_pseudo,
        out_headers,
        max_field_section,
    );
    guard err == http3::QpackError.None else { return err; }
    guard is_valid_h3_pseudo_fields(out_pseudo) else {
        return http3::QpackError.MessageError;
    }
    if out_pseudo.has_status && wing::has_header(out_headers, "te") {
        return http3::QpackError.MessageError;
    }
    if !out_pseudo.is_trailer && !out_pseudo.has_status && out_pseudo.method[..] != "CONNECT" {
        let is_http_scheme = out_pseudo.scheme[..].eq_ascii_fold("http")
            || out_pseudo.scheme[..].eq_ascii_fold("https");
        if is_http_scheme && !out_pseudo.has_authority && !wing::has_header(out_headers, "host") {
            return http3::QpackError.MessageError;
        }
    }
    guard coalesce_h2_cookie_headers(out_headers) else {
        return http3::QpackError.MessageError;
    }
    committed = true;
    return http3::QpackError.None;
}

// Encodes an HTTP/3 DATA frame (Type 0x00) into `out` (RFC 9114 §7.2.1).
//
// Example:
//   data = "hello", encode_h3_data_frame(data, out)
//   returns: true, out = [0x00, 0x05, 'h', 'e', 'l', 'l', 'o']
fn encode_h3_data_frame<B>(data: const u8[:], out: B&) -> bool {
    return http3::encode_data_frame(out, data);
}
