// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 6962 Certificate Transparency v1 SignedCertificateTimestamp (SCT) wire parser.
namespace tls;

import std;
import core;
import .internal;
import .asn1;
import .types;

// Parses a single RFC 6962 §3.2 v1 SignedCertificateTimestamp entry from `raw`.
//
// Example:
//   raw = [0x00, <32B log_id>, <8B timestamp_ms>, 0x00, 0x00, 0x04, 0x03, 0x00, 0x02, 0xAA, 0xBB]
//   returns: true, out.version = 0, out.hash_alg = 4, out.sig_alg = 3, out.signature.length = 2
fn parse_sct_entry(raw: const u8[:], out: ParsedSct&) -> bool {
    guard raw.len >= rfc::SCT_V1_HEADER_MIN_LEN && raw.len <= 65535 else { return false; }
    var c = core::cursor_from(raw);
    let ver, ok_v = c.read_u8();
    guard ok_v && ver == rfc::SCT_VERSION_V1 else { return false; }

    let log_id, ok_l = c.read_bytes(rfc::SCT_LOG_ID_LEN);
    let ts_hi, ok_th = c.read_u32();
    let ts_lo, ok_tl = c.read_u32();
    let ext_sub, ok_ext = c.read_u16_sub_cursor();
    let ext_span = span_from_end(raw.len, c.buf.len, ext_sub.buf.len);
    let hash_alg, ok_h = c.read_u8();
    let sig_alg, ok_s = c.read_u8();
    let sig_bytes, ok_sig = c.read_u16_prefixed();
    let sig_span = span_from_end(raw.len, c.buf.len, sig_bytes.len);
    let valid_algs = hash_alg == rfc::SCT_HASH_ALG_SHA256 &&
        (sig_alg == rfc::SCT_SIG_ALG_RSA || sig_alg == rfc::SCT_SIG_ALG_ECDSA);
    guard ok_l && ok_th && ok_tl && ok_ext && ok_h && ok_s && valid_algs &&
        ok_sig && sig_bytes.len > 0 && c.buf.len == 0 else { return false; }

    out.version = ver;
    core::ct_copy_bytes(out.log_id[..], log_id);
    out.timestamp_ms = tls_internal::pack_sct_timestamp_ms(ts_hi, ts_lo);
    out.hash_alg = hash_alg;
    out.sig_alg = sig_alg;
    out.extensions = ext_span;
    out.signature = sig_span;
    return true;
}

// Parses an RFC 6962 §3.3 `SignedCertificateTimestampList` into `out_scts`.
// Computes `extensions` and `signature` spans relative to `raw_list` (PKI-07).
//
// Example:
//   raw_list = [0x00, 0x31, 0x00, 0x2F, <47B v1 SerializedSCT>]
//   returns: true, out_scts.len = 1
fn parse_sct_list(raw_list: const u8[:], out_scts: ParsedSct[..8]&) -> bool {
    var committed = false;
    defer if !committed { out_scts.clear(); };
    guard raw_list.len <= 65535 else { return false; }
    var c = core::cursor_from(raw_list);
    var list_cursor, ok_l = c.read_u16_sub_cursor();
    guard ok_l && c.buf.len == 0 && list_cursor.buf.len > 0 else { return false; }

    out_scts.clear();
    while list_cursor.buf.len > 0 {
        let sct_cursor, ok_s = list_cursor.read_u16_sub_cursor();
        guard ok_s && sct_cursor.buf.len > 0 else { return false; }
        let entry_end = core::sub_sat_i64(raw_list.len, list_cursor.buf.len);
        let entry_off = core::sub_sat_i64(entry_end, sct_cursor.buf.len);
        var sct = ParsedSct { .. };
        guard parse_sct_entry(sct_cursor.buf, sct) else { return false; }
        if sct.extensions.length > 0 {
            sct.extensions.offset = core::add_sat_i64(sct.extensions.offset, entry_off) as u16;
        }
        if sct.signature.length > 0 {
            sct.signature.offset = core::add_sat_i64(sct.signature.offset, entry_off) as u16;
        }
        guard out_scts.try_push(sct) else { return false; }
    }
    guard out_scts.len > 0 else { return false; }
    committed = true;
    return true;
}

inline fn sct_entry_wire_len(cert_der: const u8[:], is_precert: bool, issuer_key_hash: const u8[:]) -> i64, bool {
    if !is_precert {
        guard cert_der.len > 0 else { return 0, false; }
        return core::add_sat_i64(5, cert_der.len), true;
    }
    // RFC 6962 Section 3.2: PreCert entries MUST provide an explicit 32-byte issuer_key_hash.
    guard issuer_key_hash.len == 32 && cert_der.len > 0 else { return 0, false; }
    return core::add_sat_i64(37, cert_der.len), true;
}

inline fn append_sct_signed_entry<B>(
    cert_der:        const u8[:],
    is_precert:      bool,
    issuer_key_hash: const u8[:],
    out:             B&,
) {
    if !is_precert {
        out.append_u16_be(tls_internal::SCT_ENTRY_TYPE_X509);
        out.append_u24_be(cert_der.len as u32);
        out.append(cert_der);
        return;
    }
    out.append_u16_be(tls_internal::SCT_ENTRY_TYPE_PRECERT);
    out.append(issuer_key_hash);
    out.append_u24_be(cert_der.len as u32);
    out.append(cert_der);
}

// Builds the RFC 6962 Section 3.2 digitally-signed SCT payload into `out`.
// Validates all lengths and buffer capacity before mutating `out` (Invariant 18).
//
// Example:
//   sct = ParsedSct { version: 0, timestamp_ms: 1700000000000, .. }, is_precert = false
//   returns: true, out appended with version || sig_type || timestamp || entry_type || entry || exts
fn build_sct_signed_data<B>(
    sct:             const ParsedSct&,
    raw_sct:         const u8[:],
    cert_der:        const u8[:],
    is_precert:      bool,
    out:             B&,
    issuer_key_hash: const u8[:] = "",
) -> bool {
    guard sct.version == rfc::SCT_VERSION_V1 else { return false; }
    let entry_len, ok_entry = sct_entry_wire_len(cert_der, is_precert, issuer_key_hash);
    let ext_bytes = span_slice(raw_sct, sct.extensions);
    guard ok_entry && ext_bytes.len == sct.extensions.length && ext_bytes.len <= 65535 else {
        return false;
    }

    let total_len = core::add_sat_i64(
        core::add_sat_i64(12, entry_len),
        ext_bytes.len,
    );
    guard core::add_sat_i64(out.len, total_len) <= out.cap else { return false; }

    out.push(sct.version);
    out.push(tls_internal::SCT_SIG_TYPE_CERT_TIMESTAMP);
    out.append_u64_be(sct.timestamp_ms);
    append_sct_signed_entry(cert_der, is_precert, issuer_key_hash, out);
    out.append_u16_be(ext_bytes.len as u16);
    out.append(ext_bytes);
    return true;
}

inline fn sct_spki_alg_matches(spki_alg: core::ByteCursor&, expected_sig_alg: u8) -> bool {
    var alg_oid = core::cursor_from(spki_alg.buf[..0]);
    guard get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, alg_oid) else { return false; }
    if expected_sig_alg == rfc::SCT_SIG_ALG_ECDSA {
        var curve_oid = core::cursor_from(spki_alg.buf[..0]);
        return alg_oid.buf == rfc::OID_EC_PUBLIC_KEY[..] &&
            get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, curve_oid) &&
            curve_oid.buf == rfc::OID_SECP256R1[..] &&
            spki_alg.cursor_len() == 0;
    }
    if expected_sig_alg == rfc::SCT_SIG_ALG_RSA {
        guard alg_oid.buf == rfc::OID_RSA_ENCRYPTION[..] else { return false; }
        if spki_alg.cursor_len() == 0 { return true; }
        var null_el = core::cursor_from(spki_alg.buf[..0]);
        return get_asn1_element(spki_alg, rfc::ASN1_TAG_NULL, null_el) &&
            null_el.cursor_len() == 0 && spki_alg.cursor_len() == 0;
    }
    return false;
}

// Extracts raw key bytes from a canonical DER X.509 SPKI and enforces RFC 6962 Section 3.2
// `log_id == SHA-256(SPKI)` and algorithm-to-signature binding (PKI-07).
//
// Example:
//   log_pubkey_der = DER SPKI(P-256), expected_log_id = SHA-256(log_pubkey_der)
//   returns: true, out_key = 65-byte uncompressed P-256 public key
fn extract_sct_log_pubkey(
    log_pubkey_der:   const u8[:],
    expected_log_id:  const u8[32]&,
    expected_sig_alg: u8,
    out_key:          u8[..600]&,
) -> bool {
    out_key.clear();
    guard log_pubkey_der.len > 0 else { return false; }
    var top = core::cursor_from(log_pubkey_der);
    var spki = core::cursor_from(log_pubkey_der[..0]);
    var spki_alg = core::cursor_from(log_pubkey_der[..0]);
    var spki_pk = core::cursor_from(log_pubkey_der[..0]);
    guard get_asn1_element(top, rfc::ASN1_TAG_SEQUENCE, spki) &&
        top.cursor_len() == 0 &&
        get_asn1_element(spki, rfc::ASN1_TAG_SEQUENCE, spki_alg) &&
        sct_spki_alg_matches(spki_alg, expected_sig_alg) &&
        get_asn1_element(spki, rfc::ASN1_TAG_BIT_STRING, spki_pk) &&
        spki.cursor_len() == 0 &&
        validate_asn1_bit_string(spki_pk.buf) &&
        spki_pk.buf.len >= 2 &&
        spki_pk.buf[0] == 0 else {
        return false;
    }
    let log_hash = core::sha256(log_pubkey_der);
    guard core::ct_eq_tag32(expected_log_id, log_hash) else { return false; }
    return out_key.try_set(spki_pk.buf[1..]);
}

// Verifies an RFC 6962 Section 3.2 SignedCertificateTimestamp cryptographic signature
// against a CT log DER SPKI public key (ECDSA P-256 SHA-256 or >= 2048-bit RSA PKCS#1 v1.5 SHA-256).
// When `now_ms > 0`, rejects SCTs with future timestamps (`sct.timestamp_ms > now_ms`, RFC 6962 §5.3).
fn verify_sct_signature(
    sct:             const ParsedSct&,
    raw_sct:         const u8[:],
    cert_der:        const u8[:],
    log_pubkey_der:  const u8[:],
    is_precert:      bool,
    issuer_key_hash: const u8[:] = "",
    now_ms:          u64         = 0,
) -> bool {
    guard sct.version == rfc::SCT_VERSION_V1 &&
        sct.hash_alg == rfc::SCT_HASH_ALG_SHA256 &&
        sct.signature.length > 0 else {
        return false;
    }
    if now_ms > 0 && sct.timestamp_ms > now_ms {
        return false;
    }
    let sig_bytes = span_slice(raw_sct, sct.signature);
    guard sig_bytes.len == sct.signature.length && sig_bytes.len > 0 else { return false; }

    var signed_data: u8[..8192] = [];
    guard build_sct_signed_data(sct, raw_sct, cert_der, is_precert, signed_data, issuer_key_hash) else {
        return false;
    }

    var raw_key: u8[..600] = [];
    guard extract_sct_log_pubkey(log_pubkey_der, sct.log_id, sct.sig_alg, raw_key) else {
        return false;
    }

    if sct.sig_alg == rfc::SCT_SIG_ALG_ECDSA {
        return core::ecdsa_p256_verify_der(raw_key[..], signed_data[..], sig_bytes);
    }
    if sct.sig_alg == rfc::SCT_SIG_ALG_RSA {
        let n_be, e_be, ok_rsa = core::parse_rsa_public_key_der(raw_key[..]);
        guard ok_rsa &&
            n_be.len >= tls_internal::MIN_RSA_MODULUS_BYTES &&
            (n_be[0] & 0x80) != 0 else {
            return false;
        }
        return core::rsa_pkcs1_sha256_verify(n_be, e_be, signed_data[..], sig_bytes);
    }
    return false;
}
