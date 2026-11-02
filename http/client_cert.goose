// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client-Cert / Client-Cert-Chain HTTP header codec (RFC 9440).
// Zero-heap SFV Byte Sequence (`:<base64>:`) and List decode/encode for
// DER-encoded X.509 client certificates carried by a TLS-terminating reverse proxy.
namespace wing;

import std;
import core from "..";
import http.mime;

// Enterprise buffer limits for certificate material (plan: DER <= 4096 B).
const CLIENT_CERT_MAX_DER_LEN:     i64 = 4096;
const CLIENT_CERT_CHAIN_MAX_ITEMS: i64 = 4;
// Encoded field size for a 4096 B DER: ':' + 4 * ceil(4096 / 3) base64 chars + ':' = 5466.
const CLIENT_CERT_ENCODE_FIELD_LEN: i64 = 5466;

// Finds the index of the Byte Sequence closing colon in s, or -1 when absent.
// Base64 alphabet and padding validation is delegated to decode_base64.
//
// Example:
//   s = "aGVsbG8=:, rest"
//   returns: 8 (index of the closing ':')
fn scan_byte_sequence_end(s: const u8[:]) -> i64 {
    for i in s.len {
        if s[i] == ':' {
            return i;
        }
    }
    return -1;
}

// Scans one SFV Byte Sequence `:<base64>:` at the start of raw.
// Returns the base64 payload and the remainder after the closing colon.
// On false, returns ("", raw): the opening or closing colon is missing,
// or the payload is empty.
//
// Example:
//   raw = ":aGVsbG8=:, rest"
//   returns: "aGVsbG8=", ", rest", ok = true
fn scan_sf_byte_sequence(raw: const u8[:]) -> const u8[:], const u8[:], bool {
    guard raw.len > 0 && raw[0] == ':' else { return "", raw, false; }
    let body = raw[1..];
    let col_pos = scan_byte_sequence_end(body);
    guard col_pos > 0 else { return "", raw, false; }
    let rest = body[col_pos..]; // starts at the closing colon
    return body[..col_pos], rest[1..], true;
}

// Parses a singleton Client-Cert field value: exactly one SFV Byte Sequence
// whose payload is a DER certificate (RFC 9440 §2.1 / §2.2). Rejects trailing
// content after the closing colon and DER larger than CLIENT_CERT_MAX_DER_LEN.
//
// Example:
//   raw = ":aGVsbG8=:", out_der = [], out_len = 0
//   returns: ok = true, out_der = "hello", out_len = 5
fn parse_client_cert(raw: const u8[:], out_der: u8[..4096]&, out_len: i32&) -> bool {
    out_len = 0;
    out_der.clear();

    var idx: i64 = 0;
    sfv_skip_ows(raw, idx);
    let b64, rest, ok = scan_sf_byte_sequence(raw[idx..]);
    guard ok else { return false; }

    let tail = rest.trim_lws();
    guard tail.len == 0 else { return false; }

    guard decode_base64(b64, out_der) else {
        out_der.clear();
        return false;
    }
    guard out_der.len > 0 && out_der.len <= CLIENT_CERT_MAX_DER_LEN else {
        out_der.clear();
        return false;
    }
    out_len = out_der.len as i32;
    return true;
}

// Encodes DER into the SFV Byte Sequence form `:<base64>:` (RFC 9440 §2.1).
// Returns bytes written into `out`, or -1 on empty/oversize DER and when the
// output buffer cannot hold CLIENT_CERT_ENCODE_FIELD_LEN bytes.
//
// Example:
//   der = "hello", out = []
//   returns: 12, out = ":aGVsbG8=:"
fn encode_client_cert(der: const u8[:], out: u8[..8192]&) -> i32 {
    out.clear();
    guard der.len > 0 && der.len <= CLIENT_CERT_MAX_DER_LEN else { return -1; }
    guard CLIENT_CERT_ENCODE_FIELD_LEN <= out.cap else { return -1; }

    out.push(':');
    core::base64_encode(der, out);
    out.push(':');
    return out.len as i32;
}

// Clears chain outputs after a mid-parse rejection (RFC 9440 §2.3: any malformed
// item rejects the whole field with out_count == 0).
fn reject_client_cert_chain(out_certs: u8[..4096][..4]&, out_lens: i32[..4]&, out_count: i32&) {
    out_certs.clear();
    out_lens.clear();
    out_count = 0;
}

// Decodes one Byte Sequence payload into the next chain slot (RFC 9440 §2.3).
//
// Example:
//   b64 = "aGVsbG8=", out_certs = [], out_lens = []
//   returns: ok = true, out_certs[0] = "hello", out_lens[0] = 5
fn append_client_cert_chain_item(
    b64:       const u8[:],
    out_certs: u8[..4096][..4]&,
    out_lens:  i32[..4]&,
) -> bool {
    guard out_certs.len < CLIENT_CERT_CHAIN_MAX_ITEMS else { return false; }

    var item: u8[..4096] = [];
    guard decode_base64(b64, item) else { return false; }
    guard item.len > 0 && item.len <= CLIENT_CERT_MAX_DER_LEN else { return false; }

    out_certs.push(item);
    out_lens.push(item.len as i32);
    return true;
}

// Parses a Client-Cert-Chain SFV List of Byte Sequences (RFC 9440 §2.3).
// Accepts up to CLIENT_CERT_CHAIN_MAX_ITEMS items; any malformed item rejects
// the whole field (ok = false, out_count = 0). Trailing commas are permitted
// by the `#` list rule (RFC 9110 §5.6.1).
//
// Example:
//   raw = ":aGVsbG8=:, :d29ybGQ=:", out_certs = [], out_lens = [], out_count = 0
//   returns: ok = true, out_count = 2, out_certs[0] = "hello", out_certs[1] = "world"
fn parse_client_cert_chain(
    raw:       const u8[:],
    out_certs: u8[..4096][..4]&,
    out_lens:  i32[..4]&,
    out_count: i32&,
) -> bool {
    reject_client_cert_chain(out_certs, out_lens, out_count);

    var rem = raw.trim_lws();
    while rem.len > 0 {
        let b64, rest, ok = scan_sf_byte_sequence(rem);
        guard ok else {
            reject_client_cert_chain(out_certs, out_lens, out_count);
            return false;
        }
        guard append_client_cert_chain_item(b64, out_certs, out_lens) else {
            reject_client_cert_chain(out_certs, out_lens, out_count);
            return false;
        }

        let tail = rest.trim_lws();
        if tail.len == 0 {
            break; // end of list, trailing comma already consumed
        }
        guard tail[0] == ',' else {
            reject_client_cert_chain(out_certs, out_lens, out_count);
            return false;
        }
        rem = tail[1..].trim_lws();
    }

    out_count = out_certs.len as i32;
    return true;
}
