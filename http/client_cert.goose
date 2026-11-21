// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client-Cert / Client-Cert-Chain HTTP header codec (RFC 9440).
// Zero-heap SFV Byte Sequence (`:<base64>:`) and List decode/encode for
// DER-encoded X.509 client certificates carried by a TLS-terminating reverse proxy.
namespace http;

import std;
import core from "..";
import http.sfv;
import http.sfv_sig_internal;
import http.codec_internal;

// Enterprise buffer limits for certificate material (plan: DER <= 4096 B).
const CLIENT_CERT_MAX_DER_LEN:     i64 = 4096;
const CLIENT_CERT_CHAIN_MAX_ITEMS: i64 = 4;
// Encoded field size for a 4096 B DER: ':' + 4 * ceil(4096 / 3) base64 chars + ':' = 5466.
const CLIENT_CERT_ENCODE_FIELD_LEN: i64 = 5466;

// Parses a singleton Client-Cert field value: exactly one SFV Byte Sequence
// whose payload is a DER certificate (RFC 9440 §2.1 / §2.2). Rejects trailing
// content after the closing colon and DER larger than CLIENT_CERT_MAX_DER_LEN.
//
// Example:
//   raw = ":aGVsbG8=:", out_der = []
//   returns: ok = true, out_der = "hello" (out_der.len == 5)
fn parse_client_cert(raw: const u8[:], out_der: u8[..4096]&) -> bool {
    var committed = false;
    defer if !committed { out_der.clear(); };
    out_der.clear();

    let parsed, ok = parse_sf_item(raw);
    guard ok && http_internal::sf_decode_byte_sequence(parsed.item, out_der) else {
        return false;
    }
    guard out_der.len > 0 && out_der.len <= CLIENT_CERT_MAX_DER_LEN else {
        return false;
    }
    committed = true;
    return true;
}

// Encodes DER into the SFV Byte Sequence form `:<base64>:` (RFC 9440 §2.1).
// Rolls back `out` on empty/oversize DER or buffer overflow and returns false.
//
// Example:
//   der = "hello", out = []
//   returns: true, out = ":aGVsbG8=:"
fn encode_client_cert<B>(der: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    guard der.len > 0 && der.len <= CLIENT_CERT_MAX_DER_LEN else { return false; }
    let encoded_len = 2 + ((der.len + 2) / 3) * 4;
    guard encoded_len <= CLIENT_CERT_ENCODE_FIELD_LEN && out.len + encoded_len <= out.cap else {
        return false;
    }

    out.push(':');
    core::base64_encode(der, out);
    out.push(':');
    committed = true;
    return true;
}

// Parses a Client-Cert-Chain SFV List of Byte Sequences (RFC 9440 §2.3).
// Accepts up to CLIENT_CERT_CHAIN_MAX_ITEMS items; any malformed item rejects
// the whole field (ok = false, out_certs cleared). Trailing commas are permitted
// by the `#` list rule (RFC 9110 §5.6.1).
//
// Example:
//   raw = ":aGVsbG8=:, :d29ybGQ=:", out_certs = []
//   returns: ok = true, out_certs.len = 2, out_certs[0] = "hello", out_certs[1] = "world"
fn parse_client_cert_chain(
    raw:       const u8[:],
    out_certs: u8[..4096][..4]&,
) -> bool {
    var committed = false;
    defer if !committed { out_certs.clear(); };
    out_certs.clear();

    let trimmed = raw.trim_lws();
    let without_comma, _ = trimmed.strip_suffix(",");
    let cleaned = without_comma.trim_lws();
    guard cleaned.len > 0 else { return false; }

    var items: SfParameterizedItem[..16] = [];
    guard parse_sf_list(cleaned, items) &&
          items.len > 0 &&
          items.len <= CLIENT_CERT_CHAIN_MAX_ITEMS else {
        return false;
    }

    for &entry in items {
        guard !entry.is_inner_list &&
              http_internal::append_client_cert_chain_item(entry.item, out_certs) else {
            return false;
        }
    }

    committed = true;
    return true;
}
