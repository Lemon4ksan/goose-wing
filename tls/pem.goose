// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7468 PEM textual encoding decoder and PKCS#8 / SEC 1 private key DER parsers.
namespace wing;

import std;
import core from "..";
import rfc.tls;
import .asn1;
import .x509;
import .session;

const PEM_PRE_EB:        const u8[:] = "-----BEGIN ";
const PEM_POST_EB:       const u8[:] = "-----END ";
const PEM_DASHES:        const u8[:] = "-----";
const PEM_MAX_DER_LEN:   i64         = 4096;
const PEM_MAX_LABEL_LEN: i64         = 64;

enum PrivateKeyKind {
    Unknown,
    Ed25519,
    EcdsaP256,
}

inline fn pem_is_ws(b: u8) -> bool {
    return b == ' ' || b == '\t' || b == '\r' || b == '\n';
}

inline fn pem_skip_to_next_line(raw: const u8[:], pos: i64) -> i64, bool {
    var p = pos;
    while p < raw.len && (raw[p] == ' ' || raw[p] == '\t') {
        p = core::add_sat_i64(p, 1);
    }
    guard p < raw.len && (raw[p] == '\r' || raw[p] == '\n') else { return p, false; }
    while p < raw.len && (raw[p] == '\r' || raw[p] == '\n') {
        p = core::add_sat_i64(p, 1);
    }
    return p, true;
}

inline fn pem_skip_end_line(raw: const u8[:], pos: i64) -> i64, bool {
    var p = pos;
    while p < raw.len && (raw[p] == ' ' || raw[p] == '\t') {
        p = core::add_sat_i64(p, 1);
    }
    guard p == raw.len || raw[p] == '\r' || raw[p] == '\n' else { return p, false; }
    while p < raw.len && (raw[p] == '\r' || raw[p] == '\n') {
        p = core::add_sat_i64(p, 1);
    }
    return p, true;
}

inline fn pem_find_begin_line(
    raw:            const u8[:],
    start_idx:      i64,
    out_label:      u8[..64]&,
    out_body_start: i64&,
) -> bool {
    guard start_idx >= 0 && start_idx < raw.len else { return false; }
    let rel_begin = core::find(raw[start_idx..], PEM_PRE_EB);
    guard rel_begin >= 0 else { return false; }
    let begin_pos = core::add_sat_i64(start_idx, rel_begin);
    let label_start = core::add_sat_i64(begin_pos, PEM_PRE_EB.len);
    guard label_start < raw.len else { return false; }

    let rel_dash = core::find(raw[label_start..], PEM_DASHES);
    guard rel_dash > 0 && rel_dash <= PEM_MAX_LABEL_LEN else { return false; }
    let label_end = core::add_sat_i64(label_start, rel_dash);
    guard out_label.try_set(raw[label_start..label_end]) else { return false; }

    let line_pos = core::add_sat_i64(label_end, PEM_DASHES.len);
    let next_p, ok_p = pem_skip_to_next_line(raw, line_pos);
    guard ok_p else { return false; }
    out_body_start = next_p;
    return true;
}

inline fn pem_find_end_line(
    raw:          const u8[:],
    body_start:   i64,
    label:        const u8[:],
    out_body_end: i64&,
    out_next_idx: i64&,
) -> bool {
    guard body_start >= 0 && body_start < raw.len else { return false; }
    let rel_end = core::find(raw[body_start..], PEM_POST_EB);
    guard rel_end >= 0 else { return false; }
    let end_pos = core::add_sat_i64(body_start, rel_end);
    let lbl_start = core::add_sat_i64(end_pos, PEM_POST_EB.len);
    let lbl_end = core::add_sat_i64(lbl_start, label.len);
    let dash_end = core::add_sat_i64(lbl_end, PEM_DASHES.len);
    guard dash_end <= raw.len else { return false; }
    guard raw[lbl_start..lbl_end] == label && raw[lbl_end..dash_end] == PEM_DASHES else {
        return false;
    }

    let next_p, ok_p = pem_skip_end_line(raw, dash_end);
    guard ok_p else { return false; }
    out_body_end = end_pos;
    out_next_idx = next_p;
    return true;
}

inline fn pem_decode_body(body: const u8[:], out_der: u8[..4096]&) -> bool {
    var b64_clean: u8[..6144] = [];
    defer core::secure_zeroize_slice(b64_clean[..]);
    for b in body {
        if pem_is_ws(b) { continue; }
        guard b64_clean.try_push(b) else { return false; }
    }
    guard b64_clean.len > 0 else { return false; }
    out_der.clear();
    guard core::base64_decode(b64_clean[..], out_der) && out_der.len > 0 else {
        out_der.clear();
        return false;
    }
    return true;
}

// Scans `raw` starting at `idx` for the next PEM-encapsulated block (RFC 7468).
// Extracts the encapsulation label and decodes the Base64 payload into `out_der`.
// On failure, restores `idx` and clears `out_label` and `out_der`.
//
// Example:
//   raw = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n", idx = 0
//   returns: ok = true, out_label = "CERTIFICATE", out_der = [0x01, 0x02, 0x03], idx = 59
fn pem_next_block(
    raw:       const u8[:],
    idx:       i64&,
    out_label: u8[..64]&,
    out_der:   u8[..4096]&,
) -> bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        out_label.clear();
        out_der.clear();
    };

    var body_start: i64 = 0;
    guard pem_find_begin_line(raw, idx, out_label, body_start) else { return false; }
    var body_end: i64 = 0;
    var next_idx: i64 = 0;
    guard pem_find_end_line(raw, body_start, out_label[..], body_end, next_idx) else {
        return false;
    }
    guard pem_decode_body(raw[body_start..body_end], out_der) else { return false; }

    idx = next_idx;
    committed = true;
    return true;
}

// Parses all "CERTIFICATE" PEM blocks in `pem_bundle` into `store`.
// Returns `(added_count, ok)` where `ok` is true if at least one certificate was added
// and no malformed PEM block was encountered.
//
// Example:
//   pem_bundle = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
//   returns: added_count = 1, ok = true
fn add_trust_anchors_pem(store: TrustAnchorStore&, pem_bundle: const u8[:]) -> i64, bool {
    var idx:   i64        = 0;
    var count: i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];

    while idx < pem_bundle.len {
        let rel_begin = core::find(pem_bundle[idx..], PEM_PRE_EB);
        if rel_begin < 0 { break; }
        guard pem_next_block(pem_bundle, idx, label, der) else { return count, false; }
        if label[..] == "CERTIFICATE" {
            guard add_trust_anchor_cert_der(store, der[..]) else { return count, false; }
            count = core::add_sat_i64(count, 1);
        }
    }
    return count, count > 0;
}

inline fn sec1_check_curve_oid(ec_seq: ByteCursor&, der_ref: const u8[:]) -> bool {
    guard ec_seq.cursor_len() > 0 else { return true; }
    var tag: u8 = 0;
    var opt_val = core::cursor_from(der_ref[..0]);
    guard get_any_asn1_element(ec_seq, tag, opt_val) else { return false; }
    guard tag == 0xA0 else { return true; }
    var curve_oid = core::cursor_from(der_ref[..0]);
    return get_asn1_element(opt_val, rfc::ASN1_TAG_OID, curve_oid)
        && opt_val.cursor_len() == 0
        && curve_oid.buf == rfc::OID_SECP256R1[..];
}

// Parses an unencrypted SEC 1 `ECPrivateKey` DER sequence for P-256 (RFC 5915 Section 3).
// Zeroizes `out_key` on failure.
//
// Example:
//   der = [0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, ...]
//   returns: ok = true, out_key = <32-byte scalar>
fn parse_sec1_ec_private_key_der(der: const u8[:], out_key: u8[32]&) -> bool {
    var committed = false;
    defer if !committed { core::secure_zeroize_32(out_key); };

    var root = core::cursor_from(der);
    var ec_seq = core::cursor_from(der[..0]);
    guard get_asn1_element(root, rfc::ASN1_TAG_SEQUENCE, ec_seq) && root.cursor_len() == 0 else {
        return false;
    }

    var version: i64 = -1;
    guard get_asn1_integer(ec_seq, version) && version == 1 else { return false; }

    var priv_oct = core::cursor_from(der[..0]);
    guard get_asn1_element(ec_seq, rfc::ASN1_TAG_OCTET_STRING, priv_oct) else { return false; }
    guard priv_oct.buf.len == 32 else { return false; }
    guard sec1_check_curve_oid(ec_seq, der) else { return false; }

    for i in 32 {
        out_key[i] = priv_oct.buf[i];
    }
    committed = true;
    return true;
}

inline fn pkcs8_extract_ed25519(
    alg_seq:  ByteCursor&,
    priv_oct: ByteCursor&,
    out_key:  u8[32]&,
) -> bool {
    guard alg_seq.cursor_len() == 0 else { return false; }
    var curve_key = core::cursor_from(priv_oct.buf[..0]);
    guard get_asn1_element(priv_oct, rfc::ASN1_TAG_OCTET_STRING, curve_key)
        && priv_oct.cursor_len() == 0
        && curve_key.buf.len == 32 else {
        return false;
    }
    for i in 32 {
        out_key[i] = curve_key.buf[i];
    }
    return true;
}

inline fn pkcs8_extract_p256(
    alg_seq:  ByteCursor&,
    priv_oct: ByteCursor&,
    out_key:  u8[32]&,
) -> bool {
    var curve_oid = core::cursor_from(alg_seq.buf[..0]);
    guard get_asn1_element(alg_seq, rfc::ASN1_TAG_OID, curve_oid)
        && alg_seq.cursor_len() == 0
        && curve_oid.buf == rfc::OID_SECP256R1[..] else {
        return false;
    }
    return parse_sec1_ec_private_key_der(priv_oct.buf, out_key);
}

// Parses an unencrypted PKCS#8 `PrivateKeyInfo` DER sequence (RFC 5208 / RFC 5958 / RFC 8410).
// Supports Ed25519 and ECDSA P-256 keys. Zeroizes `out_key` on failure.
//
// Example:
//   der = [0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...]
//   returns: kind = PrivateKeyKind.Ed25519, ok = true
fn parse_pkcs8_private_key_der(der: const u8[:], out_key: u8[32]&) -> PrivateKeyKind, bool {
    var committed = false;
    defer if !committed { core::secure_zeroize_32(out_key); };

    var root = core::cursor_from(der);
    var pki_seq = core::cursor_from(der[..0]);
    guard get_asn1_element(root, rfc::ASN1_TAG_SEQUENCE, pki_seq) && root.cursor_len() == 0 else {
        return PrivateKeyKind.Unknown, false;
    }

    var version: i64 = -1;
    guard get_asn1_integer(pki_seq, version) && version == 0 else {
        return PrivateKeyKind.Unknown, false;
    }

    var alg_seq = core::cursor_from(der[..0]);
    var alg_oid = core::cursor_from(der[..0]);
    var priv_oct = core::cursor_from(der[..0]);
    guard get_asn1_element(pki_seq, rfc::ASN1_TAG_SEQUENCE, alg_seq)
        && get_asn1_element(alg_seq, rfc::ASN1_TAG_OID, alg_oid)
        && get_asn1_element(pki_seq, rfc::ASN1_TAG_OCTET_STRING, priv_oct) else {
        return PrivateKeyKind.Unknown, false;
    }

    if alg_oid.buf == rfc::OID_ED25519[..] {
        guard pkcs8_extract_ed25519(alg_seq, priv_oct, out_key) else {
            return PrivateKeyKind.Unknown, false;
        }
        committed = true;
        return PrivateKeyKind.Ed25519, true;
    }

    if alg_oid.buf == rfc::OID_EC_PUBLIC_KEY[..] {
        guard pkcs8_extract_p256(alg_seq, priv_oct, out_key) else {
            return PrivateKeyKind.Unknown, false;
        }
        committed = true;
        return PrivateKeyKind.EcdsaP256, true;
    }

    return PrivateKeyKind.Unknown, false;
}

// Parses a PEM-encoded unencrypted private key ("PRIVATE KEY" PKCS#8 or "EC PRIVATE KEY" SEC 1).
// Zeroizes temporary DER buffers and `out_key` on failure.
//
// Example:
//   pem = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
//   returns: kind = PrivateKeyKind.Ed25519, ok = true
fn parse_private_key_pem(pem: const u8[:], out_key: u8[32]&) -> PrivateKeyKind, bool {
    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    defer core::secure_zeroize_slice(der[..]);

    guard pem_next_block(pem, idx, label, der) else {
        core::secure_zeroize_32(out_key);
        return PrivateKeyKind.Unknown, false;
    }
    if label[..] == "PRIVATE KEY" {
        return parse_pkcs8_private_key_der(der[..], out_key);
    }
    if label[..] == "EC PRIVATE KEY" {
        guard parse_sec1_ec_private_key_der(der[..], out_key) else {
            return PrivateKeyKind.Unknown, false;
        }
        return PrivateKeyKind.EcdsaP256, true;
    }
    core::secure_zeroize_32(out_key);
    return PrivateKeyKind.Unknown, false;
}

// Loads a PEM certificate and matching PEM private key into `TlsServerHandshakeConfig`.
// Validates X.509 DER structure and ensures the private key algorithm matches the certificate SPKI.
// On failure, clears `out_cfg.cert_der` and zeroizes `out_cfg.priv_seed`.
//
// Example:
//   load_tls_server_credentials_pem(cert_pem, key_pem, cfg) -> true
fn load_tls_server_credentials_pem(
    cert_pem: const u8[:],
    key_pem:  const u8[:],
    out_cfg:  TlsServerHandshakeConfig&,
) -> bool {
    var committed = false;
    defer if !committed {
        out_cfg.cert_der.clear();
        core::secure_zeroize_32(out_cfg.priv_seed);
    };

    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    guard pem_next_block(cert_pem, idx, label, der) && label[..] == "CERTIFICATE" else {
        return false;
    }
    var parsed_cert = ParsedCert { .. };
    guard parse_x509_certificate(der[..], parsed_cert) else { return false; }
    guard out_cfg.cert_der.try_set(der[..]) else { return false; }

    let key_kind, ok_key = parse_private_key_pem(key_pem, out_cfg.priv_seed);
    guard ok_key else { return false; }

    let spki_oid = span_slice(der[..], parsed_cert.spki_alg_oid);
    if key_kind == PrivateKeyKind.Ed25519 {
        guard spki_oid == rfc::OID_ED25519[..] else { return false; }
    } else if key_kind == PrivateKeyKind.EcdsaP256 {
        guard spki_oid == rfc::OID_SECP256R1[..] else { return false; }
    } else {
        return false;
    }

    committed = true;
    return true;
}
