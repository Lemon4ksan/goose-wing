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

fn encode_h3_pseudo_fields<B1, B2>(
    tbl:            internal::QpackTable&,
    stream_id:      u64,
    base:           u64,
    pseudo:         const internal::H3PseudoHeaders&,
    body_fields:    B1&,
    out_enc_stream: B2&,
    max_dyn_abs:    u64&,
    used_any_dyn:   bool&,
) {
    guard !pseudo.is_trailer else { return; }
    if pseudo.has_status && pseudo.status > 0 {
        var st_buf: u8[..16] = [];
        core::format_u64_dec(pseudo.status as u64, st_buf);
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":status", st_buf[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
        return;
    }
    if pseudo.has_method {
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":method", pseudo.method[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
    }
    if pseudo.has_scheme {
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":scheme", pseudo.scheme[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
    }
    if pseudo.has_authority {
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":authority", pseudo.authority[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
    }
    if pseudo.has_path {
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":path", pseudo.path[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
    }
    if pseudo.has_protocol {
        internal::encode_qpack_field_dynamic(
            tbl, stream_id, base, ":protocol", pseudo.protocol[..],
            body_fields, out_enc_stream, max_dyn_abs, used_any_dyn, true,
        );
    }
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
    let base = tbl.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    var body_fields: u8[..4096] = [];

    encode_h3_pseudo_fields(
        tbl, stream_id, base, pseudo,
        body_fields, out_enc_stream, max_dyn_abs, used_any_dyn,
    );

    internal::encode_h3_extra_headers(
        tbl, stream_id, base, headers,
        body_fields, out_enc_stream, max_dyn_abs, used_any_dyn,
    );

    var qpack_payload: u8[..4096] = [];
    internal::prepend_qpack_section_prefix(tbl, stream_id, base, max_dyn_abs, used_any_dyn, qpack_payload);
    guard qpack_payload.try_append(body_fields[..]) else { return false; }

    return internal::encode_h3_headers_frame(out_frame, qpack_payload[..]);
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
