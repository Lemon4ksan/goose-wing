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

fn encode_h3_pseudo_fields<B1, B2>(
    tbl:            internal::QpackTable&,
    stream_id:      u64,
    base:           u64,
    pseudo:         const internal::H3PseudoHeaders&,
    body_fields:    B1&,
    out_enc_stream: B2&,
    max_dyn_abs:    u64&,
    used_any_dyn:   bool&,
) -> bool {
    guard !pseudo.is_trailer else { return true; }
    if pseudo.has_status {
        guard pseudo.status >= 100 && pseudo.status <= 599 else { return false; }
        var st_buf: u8[..16] = [];
        core::format_u64_dec(pseudo.status as u64, st_buf);
        let prev_len = body_fields.len;
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":status", st_buf[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        return body_fields.len > prev_len;
    }
    if pseudo.has_method {
        let prev_len = body_fields.len;
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":method", pseudo.method[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_scheme {
        let prev_len = body_fields.len;
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":scheme", pseudo.scheme[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_authority {
        let prev_len = body_fields.len;
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":authority", pseudo.authority[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_path {
        let prev_len = body_fields.len;
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":path", pseudo.path[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    if pseudo.has_protocol {
        let prev_len = body_fields.len;
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":protocol", pseudo.protocol[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        guard body_fields.len > prev_len else { return false; }
    }
    return true;
}

fn encode_single_h3_map_entry<B1, B2>(
    tbl:            internal::QpackTable&,
    stream_id:      u64,
    base:           u64,
    headers:        const wing::HeaderMap&,
    e:              const wing::HeaderEntry&,
    body_fields:    B1&,
    out_enc_stream: B2&,
    max_dyn_abs:    u64&,
    used_any_dyn:   bool&,
) -> bool {
    let raw_name = wing::entry_name(headers, e);
    let val = wing::entry_value(headers, e);
    if should_skip_h2_entry(raw_name, val) {
        return true;
    }
    var lower_name: u8[..256] = [];
    guard raw_name.len > 0 && raw_name.len <= lower_name.cap else { return false; }
    for b in raw_name {
        lower_name.push(core::to_lower_ascii_byte(b));
    }
    let prev_body = body_fields.len;
    internal::encode_qpack_field_dynamic(
        tbl, stream_id, base, lower_name[..], val,
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
    tbl:            internal::QpackTable&,
    stream_id:      u64,
    pseudo:         const internal::H3PseudoHeaders&,
    headers:        const wing::HeaderMap&,
    out_enc_stream: B1&,
    out_frame:      B2&,
) -> bool {
    let start_enc = out_enc_stream.len;
    let start_frame = out_frame.len;
    let base = tbl.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    var body_fields: u8[..16384] = [];

    guard encode_h3_pseudo_fields(
        tbl, stream_id, base, pseudo,
        body_fields, out_enc_stream, max_dyn_abs, used_any_dyn,
    ) else {
        out_enc_stream.resize(start_enc);
        out_frame.resize(start_frame);
        return false;
    }

    for &e in headers.entries {
        guard encode_single_h3_map_entry(
            tbl, stream_id, base, headers, e,
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn,
        ) else {
            out_enc_stream.resize(start_enc);
            out_frame.resize(start_frame);
            return false;
        }
    }

    var qpack_payload: u8[..16384] = [];
    internal::prepend_qpack_section_prefix(tbl, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload);
    guard qpack_payload.try_append(body_fields[..]) &&
          internal::encode_h3_headers_frame(out_frame, qpack_payload[..]) else {
        out_enc_stream.resize(start_enc);
        out_frame.resize(start_frame);
        return false;
    }
    return true;
}

// Decodes a QPACK field section payload directly into `out_pseudo` and `out_headers` (RFC 9204 §4.5).
//
// Example:
//   qpack_payload = [0x00, 0x00, 0xD1], decode_h3_headers_to_map(tbl, 0, qpack_payload, out_pseudo, out_headers)
//   returns: internal::QpackError.None, out_pseudo.method = "GET"
fn decode_h3_headers_to_map(
    tbl:               internal::QpackTable&,
    stream_id:         u64,
    qpack_payload:     const u8[:],
    out_pseudo:        internal::H3PseudoHeaders&,
    out_headers:       wing::HeaderMap&,
    max_field_section: u64 = 16384,
) -> internal::QpackError {
    return internal::decode_or_block_qpack_to_map(
        tbl,
        stream_id,
        qpack_payload,
        out_pseudo,
        out_headers,
        max_field_section,
    );
}

// Encodes an HTTP/3 DATA frame (Type 0x00) into `out` (RFC 9114 §7.2.1).
//
// Example:
//   data = "hello", encode_h3_data_frame(data, out)
//   returns: true, out = [0x00, 0x05, 'h', 'e', 'l', 'l', 'o']
fn encode_h3_data_frame<B>(data: const u8[:], out: B&) -> bool {
    return internal::encode_h3_data_frame(out, data);
}
