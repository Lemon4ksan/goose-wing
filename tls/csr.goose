// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// PKCS#10 Certification Request (CSR) ASN.1 DER builder for ECDSA P-256 (RFC 2986).
namespace tls;

import std;
import core;
import rfc.tls;
import .x509_san;

// RFC 2986 Section 4.1 / PKCS #9: pkcs-9-at-extensionRequest (1.2.840.113549.1.9.14).
const OID_PKCS9_EXTENSION_REQUEST: const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];

// ASN.1 context-specific constructed tag [0] for CertificationRequestInfo attributes.
const ASN1_TAG_CTX0_CONSTRUCTED: u8 = 0xA0;

// ASN.1 context-specific primitive tag [2] for GeneralName dNSName (RFC 5280 Section 4.2.1.6).
const ASN1_TAG_GENERAL_NAME_DNS: u8 = 0x82;

// Appends canonical ASN.1 DER length octets for `length` (X.690 Section 10.1).
inline fn csr_append_der_len(out: u8[>..]&, length: i64) -> bool {
    guard length >= 0 && length <= 16777215 else { return false; }
    if length < 128 {
        out.push(length as u8);
        return true;
    }
    if length < 256 {
        out.push(0x81);
        out.push(length as u8);
        return true;
    }
    if length < 65536 {
        out.push(0x82);
        out.push(((length >> 8) & 0xFF) as u8);
        out.push((length & 0xFF) as u8);
        return true;
    }
    out.push(0x83);
    out.push(((length >> 16) & 0xFF) as u8);
    out.push(((length >> 8) & 0xFF) as u8);
    out.push((length & 0xFF) as u8);
    return true;
}

// Appends a complete ASN.1 DER TLV element (`tag || len || body`) to `out`.
inline fn csr_append_tlv(out: u8[>..]&, tag: u8, body: const u8[:]) -> bool {
    out.push(tag);
    guard csr_append_der_len(out, body.len) else { return false; }
    out.append(body);
    return true;
}

// Encodes SubjectPublicKeyInfo for uncompressed NIST P-256 EC public key (`0x04 || X || Y`).
fn csr_encode_p256_spki(pub_key: const u8[65]&, out: u8[>..]&) -> bool {
    var alg_body: u8[>..] = [];
    guard csr_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]) else { return false; }
    guard csr_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]) else { return false; }

    var bit_body: u8[>..] = [];
    bit_body.push(0x00);
    bit_body.append(pub_key[..]);

    var spki_body: u8[>..] = [];
    guard csr_append_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, alg_body[..]) else { return false; }
    guard csr_append_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, bit_body[..]) else { return false; }
    return csr_append_tlv(out, rfc::ASN1_TAG_SEQUENCE, spki_body[..]);
}

// Encodes CertificationRequestInfo attributes `[0] IMPLICIT` containing SubjectAltName DNS entries.
fn csr_encode_san_attributes(domains: const u8[..255][:], out: u8[>..]&) -> bool {
    var general_names: u8[>..] = [];
    for &dom in domains {
        guard csr_append_tlv(general_names, ASN1_TAG_GENERAL_NAME_DNS, dom[..]) else { return false; }
    }

    var san_seq: u8[>..] = [];
    guard csr_append_tlv(san_seq, rfc::ASN1_TAG_SEQUENCE, general_names[..]) else { return false; }

    var ext_body: u8[>..] = [];
    guard csr_append_tlv(ext_body, rfc::ASN1_TAG_OID, rfc::OID_SUBJECT_ALT_NAME[..]) else { return false; }
    guard csr_append_tlv(ext_body, rfc::ASN1_TAG_OCTET_STRING, san_seq[..]) else { return false; }

    var ext_entry: u8[>..] = [];
    guard csr_append_tlv(ext_entry, rfc::ASN1_TAG_SEQUENCE, ext_body[..]) else { return false; }

    var exts_seq: u8[>..] = [];
    guard csr_append_tlv(exts_seq, rfc::ASN1_TAG_SEQUENCE, ext_entry[..]) else { return false; }

    var attr_set: u8[>..] = [];
    guard csr_append_tlv(attr_set, rfc::ASN1_TAG_SET, exts_seq[..]) else { return false; }

    var attr_body: u8[>..] = [];
    guard csr_append_tlv(attr_body, rfc::ASN1_TAG_OID, OID_PKCS9_EXTENSION_REQUEST[..]) else { return false; }
    attr_body.append(attr_set[..]);

    var attr_seq: u8[>..] = [];
    guard csr_append_tlv(attr_seq, rfc::ASN1_TAG_SEQUENCE, attr_body[..]) else { return false; }
    return csr_append_tlv(out, ASN1_TAG_CTX0_CONSTRUCTED, attr_seq[..]);
}

// Validates CSR domain list and derives the P-256 public key.
fn csr_validate_inputs(
    priv_key: const u8[32]&,
    domains:  const u8[..255][:],
    out_pub:  u8[65]&,
) -> bool {
    guard domains.len > 0 else { return false; }
    for &dom in domains {
        guard validate_san_dns_name(dom[..]) else { return false; }
    }
    out_pub = core::ecdsa_p256_public_key(priv_key);
    return out_pub[0] == 0x04;
}

// Builds a DER-encoded PKCS#10 CertificationRequest signed with ECDSA P-256 SHA-256 (RFC 2986 §4.1).
// Clears `out_der` on any error.
//
// Example:
//   domains = ["example.com"]
//   returns: true, out_der = ASN.1 DER CertificationRequest SEQUENCE
fn build_pkcs10_csr_p256_der(
    priv_key: const u8[32]&,
    domains:  const u8[..255][:],
    out_der:  u8[>..]&,
) -> bool {
    out_der.clear();
    var pub_key: u8[65] = [0; 65];
    guard csr_validate_inputs(priv_key, domains, pub_key) else { return false; }

    // RFC 2986 Section 4.1: CertificationRequestInfo (version 0, empty subject Name, P-256 SPKI, [0] SAN).
    var cri_body: u8[>..] = [];
    let version_zero:  const u8[3] = [rfc::ASN1_TAG_INTEGER, 0x01, 0x00];
    let empty_subject: const u8[2] = [rfc::ASN1_TAG_SEQUENCE, 0x00];
    cri_body.append(version_zero[..]);
    cri_body.append(empty_subject[..]);
    guard csr_encode_p256_spki(pub_key, cri_body) else { return false; }
    guard csr_encode_san_attributes(domains, cri_body) else { return false; }

    var cri_tlv: u8[>..] = [];
    guard csr_append_tlv(cri_tlv, rfc::ASN1_TAG_SEQUENCE, cri_body[..]) else { return false; }

    let raw_sig = core::ecdsa_p256_sign(priv_key, cri_tlv[..]);
    var der_sig: u8[..72] = [];
    guard core::ecdsa_p256_encode_der_sig(raw_sig, der_sig) else { return false; }

    // ecdsa-with-SHA256 AlgorithmIdentifier (parameters omitted per RFC 5758 §3.2).
    var sig_alg_body: u8[>..] = [];
    guard csr_append_tlv(sig_alg_body, rfc::ASN1_TAG_OID, rfc::OID_SIG_ECDSA_SHA256[..]) else { return false; }

    var sig_bits_body: u8[>..] = [];
    sig_bits_body.push(0x00);
    sig_bits_body.append(der_sig[..]);

    var outer_body: u8[>..] = [];
    outer_body.append(cri_tlv[..]);
    guard csr_append_tlv(outer_body, rfc::ASN1_TAG_SEQUENCE, sig_alg_body[..]) else { return false; }
    guard csr_append_tlv(outer_body, rfc::ASN1_TAG_BIT_STRING, sig_bits_body[..]) else { return false; }

    var full_csr: u8[>..] = [];
    guard csr_append_tlv(full_csr, rfc::ASN1_TAG_SEQUENCE, outer_body[..]) else { return false; }
    out_der.append(full_csr[..]);
    return true;
}
