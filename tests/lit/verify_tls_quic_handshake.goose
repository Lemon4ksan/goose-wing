// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of RFC 9001 TLS 1.3-over-QUIC CRYPTO Handshake Engine:
// 1. Deferred pre-handshake SNI (`NeedSniCredentials`), ECDSA P-256 2-cert fullchain, ALPN "h3",
//    opaque `0x0039` transport parameters exchange, fragmented `provide_crypto`, and matching
//    Handshake / Application secrets without prematurely establishing before client Finished.
// 2. RSA-2048 PKCS#1 and PKCS#8 server credentials with trust-verified client & zero leaked slots.
// 3. P-256 `key_share` + HelloRetryRequest (`HRR_RANDOM` / `message_hash`) and CH1->CH2 invariance.
// 4. Negative RFC 9001 guards: missing `0x0039` (`MissingExtension`), missing/wrong ALPN
//    (`NoApplicationProtocol`), non-empty `legacy_session_id`, `0x0039` rejected over TCP
//    (`UnsupportedExtension`), premature `Application` CRYPTO, bad PEM, and ABA stale handles.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

const TEST_RSA_N: const u8[256] = [
    0xBA, 0x01, 0x1F, 0x1D, 0x6E, 0xF1, 0xA8, 0x09, 0x6F, 0x85, 0x31, 0x54, 0x48, 0x19, 0xE6, 0x51,
    0x75, 0x7C, 0x31, 0x5C, 0xF9, 0x97, 0x75, 0x21, 0x10, 0x25, 0x87, 0xC6, 0x6C, 0x41, 0xFA, 0x7C,
    0x42, 0xC0, 0xBA, 0x03, 0x39, 0xB9, 0xD7, 0x3F, 0xA4, 0xC2, 0x98, 0x07, 0x39, 0xF0, 0x96, 0x27,
    0xB2, 0x40, 0x28, 0x52, 0x7F, 0x50, 0x06, 0x88, 0x01, 0x98, 0x92, 0xC7, 0x3A, 0xC9, 0xC1, 0x5B,
    0xBA, 0x11, 0xBE, 0x38, 0x68, 0x39, 0x43, 0xBA, 0x2D, 0x1A, 0x7D, 0x3F, 0x64, 0x4F, 0xD6, 0x46,
    0x80, 0xF8, 0xBD, 0xBD, 0xE8, 0x9F, 0x7C, 0xDD, 0x9B, 0xA2, 0x23, 0x68, 0x32, 0x52, 0xAA, 0x32,
    0x68, 0x8E, 0xE5, 0x0A, 0xFA, 0x69, 0xE1, 0xE4, 0x82, 0xB1, 0x95, 0xDE, 0x7E, 0x93, 0x65, 0xAC,
    0xA2, 0x10, 0x91, 0x95, 0x1A, 0xD1, 0x71, 0xA5, 0xB7, 0x52, 0x0F, 0x26, 0xE2, 0xCA, 0x55, 0x63,
    0x85, 0x57, 0x96, 0x45, 0x5B, 0x0E, 0xB8, 0x8D, 0xEF, 0x9B, 0xD4, 0x81, 0x2D, 0x9A, 0x26, 0x0D,
    0x0A, 0xAE, 0x4D, 0xEC, 0x27, 0x15, 0x5A, 0xA3, 0x35, 0x0E, 0x80, 0xCC, 0x5D, 0xF8, 0x35, 0x01,
    0x61, 0xA9, 0xAA, 0xBC, 0x03, 0xA7, 0xDE, 0x5E, 0x11, 0xE9, 0x79, 0xF1, 0xFE, 0x92, 0x60, 0x47,
    0xF4, 0xA8, 0x33, 0x13, 0x25, 0x77, 0x65, 0x84, 0x69, 0xAE, 0x8A, 0xF0, 0xDF, 0x4F, 0x44, 0xF7,
    0x88, 0xAA, 0x0B, 0x7E, 0x12, 0xF8, 0xD5, 0x74, 0x4B, 0x31, 0xDC, 0x77, 0xAC, 0xA1, 0xEF, 0x56,
    0xA1, 0xEF, 0xF9, 0x2A, 0x44, 0xEA, 0xB8, 0x49, 0x18, 0xD4, 0x9B, 0x98, 0x32, 0xAB, 0x25, 0x26,
    0x08, 0x23, 0xAF, 0x91, 0xFA, 0x36, 0xEE, 0x77, 0x02, 0x1E, 0xF6, 0x14, 0x92, 0x92, 0x16, 0xC8,
    0x93, 0xCB, 0x8C, 0x2C, 0xEE, 0x88, 0x86, 0x3B, 0xB6, 0x3E, 0x4E, 0x50, 0xC5, 0x4A, 0x5A, 0x0F,
];

const TEST_RSA_E: const u8[3] = [0x01, 0x00, 0x01];

const TEST_RSA_D: const u8[256] = [
    0x1C, 0x0E, 0xDB, 0x40, 0xB7, 0x61, 0xA0, 0xB5, 0x7B, 0xAB, 0x1D, 0xDB, 0xD6, 0xDC, 0x81, 0x4F,
    0xBC, 0x67, 0x35, 0x93, 0x0E, 0xDB, 0x78, 0x01, 0xBA, 0xCB, 0xCE, 0x85, 0x72, 0x03, 0x29, 0xE3,
    0xE0, 0xB5, 0xED, 0xD9, 0x5A, 0xB5, 0xDB, 0xF0, 0x6F, 0xCC, 0x22, 0xDE, 0xC4, 0x30, 0xB4, 0x95,
    0xDC, 0x5F, 0xAD, 0x35, 0x74, 0x9A, 0xFF, 0xC1, 0x38, 0x6C, 0x69, 0x87, 0xC0, 0x28, 0x7B, 0x10,
    0x79, 0x2B, 0x00, 0x04, 0xC6, 0x44, 0x0D, 0x21, 0x62, 0x78, 0x62, 0x78, 0x53, 0x8B, 0x6F, 0x89,
    0x47, 0x1F, 0x3E, 0x90, 0x0D, 0x2D, 0x31, 0xCA, 0xC4, 0x15, 0x5B, 0x3D, 0xF6, 0x89, 0x5D, 0xBF,
    0x28, 0xE2, 0x95, 0x4E, 0x68, 0xA3, 0xDC, 0x3D, 0x7A, 0x31, 0x8B, 0xA7, 0xFA, 0x74, 0x05, 0x9C,
    0x5A, 0xFE, 0x20, 0xD7, 0xDB, 0x29, 0xC8, 0xF8, 0xF4, 0x84, 0x5E, 0x60, 0xC1, 0x49, 0x40, 0x43,
    0xF6, 0xF9, 0x20, 0x2B, 0x12, 0xA5, 0x8E, 0x94, 0x12, 0xBF, 0xB6, 0x76, 0x49, 0x74, 0xAA, 0xDE,
    0xE7, 0x8D, 0x17, 0x1B, 0x3A, 0xCC, 0xE4, 0xDD, 0x1B, 0xF1, 0xD5, 0x98, 0x86, 0x9F, 0xE3, 0xE2,
    0xC7, 0x4B, 0xBB, 0x53, 0xA6, 0x3C, 0xC5, 0xB9, 0x68, 0x40, 0x5F, 0x23, 0x6B, 0xA6, 0x2B, 0x54,
    0xEA, 0x89, 0x9A, 0x61, 0xB1, 0x02, 0x12, 0x48, 0xEB, 0x28, 0x71, 0xF2, 0x31, 0x51, 0x94, 0x4C,
    0x85, 0x1E, 0x5D, 0xEE, 0x19, 0x1A, 0xA1, 0xDC, 0x23, 0xCB, 0xAE, 0x0B, 0x16, 0x0B, 0x7E, 0xB7,
    0x7E, 0xD8, 0xB9, 0x56, 0x15, 0x78, 0xA9, 0xDC, 0xC1, 0x59, 0x78, 0xE3, 0xAB, 0x73, 0x2E, 0x82,
    0x64, 0xCB, 0x21, 0x36, 0xB4, 0x81, 0xC9, 0xDF, 0x94, 0x1D, 0x98, 0x2B, 0xB9, 0xC1, 0xAC, 0x5D,
    0x82, 0x5E, 0x10, 0xB0, 0xE3, 0xC8, 0xA5, 0x08, 0x2F, 0x10, 0x3E, 0x8E, 0x6D, 0xF9, 0x6C, 0x61,
];

const TEST_RSA_P: const u8[128] = [
    0xE9, 0x14, 0xEE, 0x51, 0x12, 0xAF, 0xDF, 0x73, 0x7A, 0x88, 0x61, 0x45, 0x87, 0x09, 0x45, 0xE2,
    0x6F, 0xF4, 0x68, 0x9F, 0x49, 0xB4, 0xA6, 0xB6, 0x5D, 0xB9, 0x65, 0xFC, 0x19, 0x31, 0x0F, 0xBF,
    0xD8, 0xC4, 0xFF, 0xCC, 0xE1, 0xCB, 0x5F, 0x36, 0xBF, 0x58, 0x71, 0x74, 0xCD, 0x13, 0xD5, 0x59,
    0xE2, 0x3E, 0x57, 0x9E, 0xB1, 0xCA, 0x90, 0x37, 0x31, 0x9A, 0x7E, 0x17, 0x4F, 0xD3, 0xC8, 0x03,
    0xED, 0x41, 0x83, 0x5C, 0x08, 0xDE, 0x9A, 0xC1, 0xFF, 0xAC, 0x75, 0xC5, 0xE4, 0x5C, 0xAB, 0xBA,
    0xA5, 0x71, 0x3B, 0x2E, 0xC5, 0x49, 0xFC, 0xD3, 0xEE, 0x38, 0xB0, 0x8A, 0x75, 0x2A, 0xC7, 0x86,
    0x32, 0xBA, 0xC1, 0x37, 0x26, 0xED, 0x88, 0x2D, 0xED, 0x24, 0x9D, 0x5B, 0xC4, 0xD7, 0x3C, 0x5F,
    0x6A, 0x3D, 0xAD, 0x29, 0x09, 0x05, 0xAB, 0xF6, 0x00, 0x07, 0x57, 0x9E, 0xD1, 0x25, 0x91, 0x79,
];

const TEST_RSA_Q: const u8[128] = [
    0xCC, 0x4B, 0x2C, 0x03, 0xBF, 0x36, 0x93, 0x3F, 0x66, 0xBC, 0x4E, 0xAB, 0x42, 0xD8, 0x3C, 0x00,
    0x7C, 0xE5, 0x1F, 0xA8, 0xE6, 0x13, 0x48, 0xED, 0x14, 0x43, 0xEC, 0x16, 0xDA, 0x71, 0x01, 0x3E,
    0x8D, 0x55, 0x80, 0xBD, 0xAF, 0x07, 0xF3, 0x28, 0xD3, 0x38, 0x3A, 0x78, 0xDF, 0xD4, 0xDA, 0x16,
    0xE2, 0xDB, 0x41, 0x23, 0x42, 0xA2, 0xC0, 0x9C, 0x93, 0x8E, 0x81, 0x84, 0x62, 0x60, 0xFB, 0x36,
    0xCB, 0x57, 0xE1, 0x40, 0x91, 0xAB, 0xBC, 0x41, 0x8E, 0x63, 0x1E, 0xBC, 0xDC, 0xF8, 0xBF, 0xFB,
    0xF7, 0x1A, 0x6B, 0x5B, 0x15, 0x2D, 0xE0, 0xDD, 0x8B, 0x66, 0x41, 0xD3, 0x28, 0x10, 0x65, 0x5A,
    0x24, 0x4C, 0x8C, 0xBB, 0xF0, 0x89, 0x17, 0x87, 0x55, 0x94, 0xFC, 0x3D, 0xE8, 0x28, 0x98, 0x09,
    0x62, 0x04, 0x49, 0xD5, 0x88, 0x25, 0x24, 0x84, 0xAF, 0xBA, 0xD4, 0xF6, 0x4D, 0xA4, 0x2D, 0xC7,
];

const TEST_RSA_DP: const u8[128] = [
    0x2C, 0x7B, 0x25, 0x1B, 0xED, 0xC0, 0x08, 0x99, 0xC6, 0x29, 0x9E, 0xBE, 0xA1, 0x0D, 0xA0, 0xFB,
    0x9C, 0xB7, 0xFC, 0xFB, 0x61, 0x1A, 0x8B, 0xB2, 0x43, 0xE2, 0xAC, 0xD6, 0xD6, 0x8B, 0xE9, 0x60,
    0x88, 0x62, 0xD8, 0x1A, 0x66, 0x80, 0xE4, 0x53, 0xD3, 0x62, 0x72, 0x8C, 0x82, 0xD2, 0xA5, 0x25,
    0xB9, 0x2A, 0x82, 0x98, 0x33, 0x7F, 0xDF, 0xD3, 0xD8, 0xB0, 0x8E, 0x1D, 0xAE, 0xCB, 0x50, 0xE1,
    0x86, 0xF6, 0xB8, 0xB5, 0xE8, 0xAF, 0x6A, 0xC3, 0x59, 0x22, 0xB5, 0x7B, 0x25, 0xA0, 0x95, 0xD9,
    0x51, 0xD7, 0x71, 0x1E, 0xF4, 0xE1, 0xB0, 0xD1, 0x55, 0x26, 0x16, 0x72, 0xE5, 0xF7, 0x5B, 0x0A,
    0x7E, 0x45, 0xEB, 0xB7, 0xB5, 0xC3, 0x20, 0xF8, 0xFA, 0xC7, 0xC1, 0x0C, 0x11, 0x5D, 0xAE, 0x14,
    0xDB, 0x76, 0x97, 0xC4, 0x3C, 0x07, 0x8C, 0x10, 0xAF, 0x62, 0xB7, 0x53, 0x04, 0xC0, 0xF1, 0xA9,
];

const TEST_RSA_DQ: const u8[128] = [
    0x2C, 0xF7, 0x4A, 0xCB, 0xD4, 0x55, 0x95, 0xD9, 0x79, 0xAA, 0x6F, 0x02, 0x61, 0x27, 0x29, 0x25,
    0xCE, 0x57, 0xBC, 0x3D, 0x37, 0xCE, 0xFC, 0xD9, 0x3A, 0x01, 0xAD, 0x40, 0x66, 0x7A, 0x43, 0x14,
    0xDA, 0x94, 0xFC, 0x4E, 0x43, 0xED, 0x53, 0x07, 0x24, 0x5E, 0x96, 0xF8, 0x2E, 0x04, 0x32, 0xB0,
    0xA0, 0xE4, 0x33, 0x95, 0x28, 0x40, 0x9C, 0x76, 0x9A, 0x3F, 0xDE, 0xA0, 0x1D, 0xEB, 0x4C, 0xC0,
    0x05, 0xC7, 0xE5, 0x0B, 0x8A, 0x44, 0xAB, 0x9E, 0x1E, 0x52, 0x10, 0xDC, 0xEF, 0x22, 0x4D, 0x57,
    0x8F, 0x4F, 0x20, 0x5C, 0x1E, 0xF0, 0x47, 0x33, 0x5C, 0x50, 0x78, 0xA2, 0x9A, 0x89, 0xE9, 0x55,
    0x0A, 0xF2, 0x52, 0x73, 0xB7, 0x80, 0xE5, 0x4D, 0xE3, 0x77, 0x74, 0x81, 0xC7, 0xCC, 0xCF, 0x92,
    0x19, 0x21, 0xEA, 0x82, 0x76, 0x81, 0xFE, 0x64, 0xBA, 0x2D, 0x3C, 0x5C, 0xAE, 0x40, 0x39, 0xD7,
];

const TEST_RSA_QINV: const u8[128] = [
    0xCA, 0x15, 0xB7, 0x69, 0xA6, 0x2E, 0xB0, 0xB0, 0xBC, 0x02, 0x18, 0x13, 0x99, 0x2F, 0x3C, 0x4B,
    0x79, 0xC8, 0xCC, 0x47, 0xCF, 0x9D, 0x7F, 0xFD, 0x32, 0x0E, 0xB0, 0x09, 0x8A, 0xD3, 0x72, 0x42,
    0x64, 0xC3, 0xDF, 0xC3, 0x7A, 0xA1, 0xBA, 0xD4, 0xF1, 0xA9, 0xD3, 0xED, 0x51, 0x99, 0x03, 0xC9,
    0x85, 0xBE, 0x7C, 0x7D, 0x84, 0x57, 0xFB, 0x86, 0x04, 0x37, 0xBE, 0x94, 0xE5, 0x38, 0xF4, 0x98,
    0xCF, 0x72, 0x9C, 0x36, 0x14, 0xD7, 0xDB, 0x69, 0xCE, 0x6E, 0x53, 0x55, 0xD7, 0x85, 0x9D, 0xF9,
    0x9E, 0x10, 0x03, 0x80, 0x2A, 0xA4, 0x98, 0xE9, 0x9F, 0x88, 0xD1, 0xB7, 0x00, 0x4B, 0x59, 0x36,
    0x2D, 0x32, 0x1B, 0x9E, 0x9C, 0x1C, 0xF7, 0x89, 0x44, 0xF5, 0x1F, 0xEE, 0x25, 0x47, 0x09, 0xF1,
    0xFA, 0x7C, 0xC2, 0x51, 0x2F, 0xAE, 0xE1, 0x50, 0xCA, 0x8A, 0x71, 0x00, 0x53, 0xE1, 0x84, 0xE0,
];

fn der_push_len<B>(out: B&, len: i64) {
    if len < 128 {
        assert(out.try_push(len as u8));
    } else if len < 256 {
        assert(out.try_push(0x81) && out.try_push(len as u8));
    } else {
        assert(
            out.try_push(0x82) &&
            out.try_push(((len >> 8) & 0xFF) as u8) &&
            out.try_push((len & 0xFF) as u8),
        );
    }
}

fn der_wrap<B>(tag: u8, body: const u8[:], out: B&) {
    out.clear();
    assert(out.try_push(tag));
    der_push_len(out, body.len);
    assert(out.try_append(body));
}

fn der_append_tlv<B>(out: B&, tag: u8, body: const u8[:]) {
    assert(out.try_push(tag));
    der_push_len(out, body.len);
    assert(out.try_append(body));
}

fn der_append_pos_int<B>(out: B&, be: const u8[:]) {
    let needs_pad = be.len > 0 && (be[0] & 0x80) != 0;
    let total = if needs_pad { be.len + 1 } else { be.len };
    assert(out.try_push(rfc::ASN1_TAG_INTEGER));
    der_push_len(out, total);
    if needs_pad { assert(out.try_push(0x00)); }
    assert(out.try_append(be));
}

fn append_pem_block(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var pos: i64 = 0;
    while pos < b64.len {
        let end = min(pos + 64, b64.len);
        out.append(b64[pos..end]);
        out.push('\n');
        pos = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn encode_name_cn<B>(cn: const u8[:], out: B&) {
    var atv_body: u8[..128] = [];
    der_append_tlv(atv_body, rfc::ASN1_TAG_OID, rfc::OID_COMMON_NAME[..]);
    der_append_tlv(atv_body, rfc::ASN1_TAG_UTF8_STRING, cn);
    var atv: u8[..140] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, atv_body[..], atv);
    var rdn: u8[..148] = [];
    der_wrap(rfc::ASN1_TAG_SET, atv[..], rdn);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, rdn[..], out);
}

fn encode_ext_entry<B>(out: B&, oid: const u8[:], critical: bool, val: const u8[:]) {
    var body: u8[..4096] = [];
    der_append_tlv(body, rfc::ASN1_TAG_OID, oid);
    if critical {
        let crit_val: u8[1] = [0xFF];
        der_append_tlv(body, rfc::ASN1_TAG_BOOLEAN, crit_val[..]);
    }
    der_append_tlv(body, rfc::ASN1_TAG_OCTET_STRING, val);
    der_append_tlv(out, rfc::ASN1_TAG_SEQUENCE, body[..]);
}

fn build_p256_cert_der<B>(
    issuer_priv: const u8[32]&,
    subj_priv:   const u8[32]&,
    issuer_cn:   const u8[:],
    subject_cn:  const u8[:],
    is_ca:       bool,
    dns_san:     const u8[:],
    out_der:     B&,
) {
    let subj_pub = core::ecdsa_p256_public_key(subj_priv);
    var tbs_body: u8[..4096] = [];
    let ver_v3: u8[3] = [0x02, 0x01, 0x02];
    der_append_tlv(tbs_body, 0xA0, ver_v3[..]);
    let ser: u8[2] = [0x01, 0x11];
    der_append_tlv(tbs_body, rfc::ASN1_TAG_INTEGER, ser[..]);

    var ecdsa_alg: u8[..16] = [];
    der_append_tlv(ecdsa_alg, rfc::ASN1_TAG_OID, rfc::OID_SIG_ECDSA_SHA256[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, ecdsa_alg[..]);

    var iss_dn: u8[..160] = [];
    encode_name_cn(issuer_cn, iss_dn);
    assert(tbs_body.try_append(iss_dn[..]));

    var val_body: u8[..64] = [];
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "240101000000Z");
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "351231235959Z");
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, val_body[..]);

    var sub_dn: u8[..160] = [];
    encode_name_cn(subject_cn, sub_dn);
    assert(tbs_body.try_append(sub_dn[..]));

    var spki_alg: u8[..32] = [];
    der_append_tlv(spki_alg, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]);
    der_append_tlv(spki_alg, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]);
    var spki_body: u8[..120] = [];
    der_append_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, spki_alg[..]);
    var pk_bits: u8[66] = [0; 66];
    for i in 65 { pk_bits[i + 1] = subj_pub[i]; }
    der_append_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, pk_bits[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, spki_body[..]);

    var exts_body: u8[..1024] = [];
    if is_ca {
        let bc_true: u8[5] = [0x30, 0x03, 0x01, 0x01, 0xFF];
        encode_ext_entry(exts_body, rfc::OID_BASIC_CONSTRAINTS[..], true, bc_true[..]);
    } else {
        let ku_dig: u8[4] = [0x03, 0x02, 0x07, 0x80];
        encode_ext_entry(exts_body, rfc::OID_KEY_USAGE[..], false, ku_dig[..]);
    }
    if dns_san.len > 0 {
        var san_inner: u8[..128] = [];
        der_append_tlv(san_inner, 0x82, dns_san);
        let ip4: u8[4] = [127, 0, 0, 1];
        der_append_tlv(san_inner, 0x87, ip4[..]);
        var san_seq: u8[..140] = [];
        der_wrap(rfc::ASN1_TAG_SEQUENCE, san_inner[..], san_seq);
        encode_ext_entry(exts_body, rfc::OID_SUBJECT_ALT_NAME[..], false, san_seq[..]);
    }
    var exts_seq: u8[..1080] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, exts_body[..], exts_seq);
    der_append_tlv(tbs_body, 0xA3, exts_seq[..]);

    var tbs_der: u8[..4040] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, tbs_body[..], tbs_der);
    let raw_sig = core::ecdsa_p256_sign(issuer_priv, tbs_der[..]);
    var der_sig: u8[..72] = [];
    assert(core::ecdsa_p256_encode_der_sig(raw_sig, der_sig));

    var cert_body: u8[..4096] = [];
    assert(cert_body.try_append(tbs_der[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_SEQUENCE, ecdsa_alg[..]);
    var sig_bits: u8[..80] = [];
    assert(sig_bits.try_push(0x00) && sig_bits.try_append(der_sig[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_BIT_STRING, sig_bits[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, cert_body[..], out_der);
}

fn build_p256_pkcs8_pem(priv_key: const u8[32]&, out_pem: u8[>..]&) {
    out_pem.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    var b_ec = core::builder_init();
    b_ec.put_bytes("\x02\x01\x01\x04\x20");
    b_ec.put_bytes(priv_key[..]);
    b_ec.put_bytes("\xA1\x44\x03\x42\x00");
    b_ec.put_bytes(pub65[..]);
    var b_ec_seq: u8[..256] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, b_ec.buf[..], b_ec_seq);

    var b_pki: u8[..512] = [];
    let zero_v: u8[1] = [0x00];
    der_append_pos_int(b_pki, zero_v[..]);
    var alg_body: u8[..32] = [];
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]);
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]);
    der_append_tlv(b_pki, rfc::ASN1_TAG_SEQUENCE, alg_body[..]);
    der_append_tlv(b_pki, rfc::ASN1_TAG_OCTET_STRING, b_ec_seq[..]);

    var pkcs8_der: u8[..512] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, b_pki[..], pkcs8_der);
    append_pem_block("PRIVATE KEY", pkcs8_der[..], out_pem);
}

fn build_rsa_pkcs1_der(out_der: u8[>..]&) {
    out_der.clear();
    var body: u8[..2048] = [];
    let zero_v: u8[1] = [0x00];
    der_append_pos_int(body, zero_v[..]);
    der_append_pos_int(body, TEST_RSA_N[..]);
    der_append_pos_int(body, TEST_RSA_E[..]);
    der_append_pos_int(body, TEST_RSA_D[..]);
    der_append_pos_int(body, TEST_RSA_P[..]);
    der_append_pos_int(body, TEST_RSA_Q[..]);
    der_append_pos_int(body, TEST_RSA_DP[..]);
    der_append_pos_int(body, TEST_RSA_DQ[..]);
    der_append_pos_int(body, TEST_RSA_QINV[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, body[..], out_der);
}

fn build_rsa_pkcs8_der(out_der: u8[>..]&) {
    out_der.clear();
    var pkcs1: u8[>..] = [];
    build_rsa_pkcs1_der(pkcs1);
    var pki_body: u8[..2048] = [];
    let zero_v: u8[1] = [0x00];
    der_append_pos_int(pki_body, zero_v[..]);
    var alg_body: u8[..32] = [];
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_RSA_ENCRYPTION[..]);
    der_append_tlv(alg_body, rfc::ASN1_TAG_NULL, "");
    der_append_tlv(pki_body, rfc::ASN1_TAG_SEQUENCE, alg_body[..]);
    der_append_tlv(pki_body, rfc::ASN1_TAG_OCTET_STRING, pkcs1[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, pki_body[..], out_der);
}

fn build_rsa_leaf_cert_der(common_name: const u8[:], dns_san: const u8[:], out_der: u8[..4096]&) {
    out_der.clear();
    var tbs_body: u8[..2048] = [];
    let ver_v3: u8[3] = [0x02, 0x01, 0x02];
    der_append_tlv(tbs_body, 0xA0, ver_v3[..]);
    let ser: u8[2] = [0x01, 0x09];
    der_append_tlv(tbs_body, rfc::ASN1_TAG_INTEGER, ser[..]);

    var sig_alg_body: u8[..32] = [];
    der_append_tlv(sig_alg_body, rfc::ASN1_TAG_OID, rfc::OID_SIG_SHA256_RSA[..]);
    der_append_tlv(sig_alg_body, rfc::ASN1_TAG_NULL, "");
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, sig_alg_body[..]);

    var dn: u8[..160] = [];
    encode_name_cn(common_name, dn);
    assert(tbs_body.try_append(dn[..]));

    var val_body: u8[..64] = [];
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "240101000000Z");
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "351231235959Z");
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, val_body[..]);
    assert(tbs_body.try_append(dn[..]));

    var rsa_pub_inner: u8[..320] = [];
    der_append_pos_int(rsa_pub_inner, TEST_RSA_N[..]);
    der_append_pos_int(rsa_pub_inner, TEST_RSA_E[..]);
    var rsa_pub_seq: u8[..330] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, rsa_pub_inner[..], rsa_pub_seq);
    var spki_alg_body: u8[..32] = [];
    der_append_tlv(spki_alg_body, rfc::ASN1_TAG_OID, rfc::OID_RSA_ENCRYPTION[..]);
    der_append_tlv(spki_alg_body, rfc::ASN1_TAG_NULL, "");
    var spki_body: u8[..400] = [];
    der_append_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, spki_alg_body[..]);
    var spki_bits: u8[..400] = [];
    assert(spki_bits.try_push(0x00) && spki_bits.try_append(rsa_pub_seq[..]));
    der_append_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, spki_bits[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, spki_body[..]);

    var exts_body: u8[..256] = [];
    let ku_dig: u8[4] = [0x03, 0x02, 0x07, 0x80];
    encode_ext_entry(exts_body, rfc::OID_KEY_USAGE[..], false, ku_dig[..]);
    var san_inner: u8[..128] = [];
    der_append_tlv(san_inner, 0x82, dns_san);
    let ip4: u8[4] = [127, 0, 0, 1];
    der_append_tlv(san_inner, 0x87, ip4[..]);
    var san_seq: u8[..140] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, san_inner[..], san_seq);
    encode_ext_entry(exts_body, rfc::OID_SUBJECT_ALT_NAME[..], false, san_seq[..]);
    var exts_seq: u8[..300] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, exts_body[..], exts_seq);
    der_append_tlv(tbs_body, 0xA3, exts_seq[..]);

    var tbs_der: u8[..2200] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, tbs_body[..], tbs_der);

    var sig: u8[..512] = [];
    assert(core::rsa_pkcs1_sha256_sign_blinded(TEST_RSA_N[..], TEST_RSA_D[..], TEST_RSA_E[..], tbs_der[..], sig));

    var cert_body: u8[..3000] = [];
    assert(cert_body.try_append(tbs_der[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_SEQUENCE, sig_alg_body[..]);
    var sig_bits: u8[..520] = [];
    assert(sig_bits.try_push(0x00) && sig_bits.try_append(sig[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_BIT_STRING, sig_bits[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, cert_body[..], out_der);
}

fn build_custom_quic_ch_msg(
    rand_bytes: const u8[32]&,
    sni_host:   const u8[:],
    alpn_proto: const u8[:],
    tp_bytes:   const u8[:],
    include_tp: bool,
    session_id: const u8[:],
    out_msg:    u8[..4096]&,
) {
    out_msg.clear();
    var pay: u8[..4096] = [];
    pay.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    pay.append(rand_bytes[..]);
    pay.push(session_id.len as u8);
    pay.append(session_id);
    pay.append_u16_be(2);
    pay.append_u16_be(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    pay.push(1);
    pay.push(0);

    var ext: u8[..2560] = [];
    if sni_host.len > 0 {
        ext.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
        ext.append_u16_be((sni_host.len + 5) as u16);
        ext.append_u16_be((sni_host.len + 3) as u16);
        ext.push(0);
        ext.append_u16_be(sni_host.len as u16);
        ext.append(sni_host);
    }
    if alpn_proto.len > 0 {
        ext.append_u16_be(rfc::TLS_EXT_ALPN);
        ext.append_u16_be((alpn_proto.len + 3) as u16);
        ext.append_u16_be((alpn_proto.len + 1) as u16);
        ext.push(alpn_proto.len as u8);
        ext.append(alpn_proto);
    }
    ext.append_u16_be(rfc::TLS_EXT_SUPPORTED_VERSIONS);
    ext.append_u16_be(3);
    ext.push(2);
    ext.append_u16_be(rfc::TLS_VERSION_1_3);

    ext.append_u16_be(rfc::TLS_EXT_SUPPORTED_GROUPS);
    ext.append_u16_be(6);
    ext.append_u16_be(4);
    ext.append_u16_be(rfc::GROUP_X25519);
    ext.append_u16_be(rfc::GROUP_SECP256R1);

    ext.append_u16_be(rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    ext.append_u16_be(8);
    ext.append_u16_be(6);
    ext.append_u16_be(rfc::SIG_SCHEME_ED25519);
    ext.append_u16_be(rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256);
    ext.append_u16_be(rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256);

    var x25519_priv: u8[32] = [0x31; 32];
    let x25519_pub = core::x25519_base_scalarmult(x25519_priv);
    ext.append_u16_be(rfc::TLS_EXT_KEY_SHARE);
    ext.append_u16_be(38);
    ext.append_u16_be(36);
    ext.append_u16_be(rfc::GROUP_X25519);
    ext.append_u16_be(32);
    ext.append(x25519_pub[..]);

    if include_tp {
        ext.append_u16_be(rfc::TLS_EXT_QUIC_TRANSPORT_PARAMETERS);
        ext.append_u16_be(tp_bytes.len as u16);
        ext.append(tp_bytes);
    }

    pay.append_u16_be(ext.len as u16);
    pay.append(ext[..]);

    out_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(out_msg, pay.len as u32);
    out_msg.append(pay[..]);
}

fn count_active_rsa_slots() -> i64 {
    var count: i64 = 0;
    for i in tls::g_tls_rsa_keys.len {
        if tls::g_tls_rsa_keys[i].in_use {
            count += 1;
        }
    }
    return count;
}

fn test_deferred_sni_fullchain_and_fragmented() {
    var ca_priv: u8[32] = [0x11; 32];
    ca_priv[31] = 0x05;
    var leaf_priv: u8[32] = [0x22; 32];
    leaf_priv[31] = 0x09;

    var ca_der:   u8[..4096] = [];
    var leaf_der: u8[..4096] = [];
    build_p256_cert_der(ca_priv, ca_priv, "QUIC Test Root CA", "QUIC Test Root CA", true, "", ca_der);
    build_p256_cert_der(ca_priv, leaf_priv, "QUIC Test Root CA", "h3.example.test", false, "h3.example.test", leaf_der);

    var root_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", ca_der[..], root_pem);

    var fullchain_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", leaf_der[..], fullchain_pem);
    append_pem_block("CERTIFICATE", ca_der[..], fullchain_pem);

    var key_pem: u8[>..] = [];
    build_p256_pkcs8_pem(leaf_priv, key_pem);

    let cli_tp = "\x01\x04\x80\x00\x75\x30\x04\x04\x80\x10\x00\x00";
    let srv_tp = "\x01\x04\x80\x00\xea\x60\x04\x04\x80\x20\x00\x00";

    var cli = tls::quic_tls_client_open("h3.example.test", "\x02h3", cli_tp, root_pem[..]);
    var srv = tls::quic_tls_server_open("h3,http/1.1", srv_tp, true);

    assert(tls::quic_tls_client_start(cli) == tls::QuicTlsStatus.Ok);
    var c2s_init: u8[>..] = [];
    let c2s_n = tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Initial, c2s_init);
    assert(c2s_n > 40);
    assert(c2s_init[0] == rfc::TLS_HS_CLIENT_HELLO);
    assert(c2s_init[4 + 34] == 0);

    // Feed CH1 in two fragments.
    let split = c2s_init.len / 2;
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Initial, c2s_init[..split]) == tls::QuicTlsStatus.WantMore);
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Initial, c2s_init[split..]) == tls::QuicTlsStatus.NeedSniCredentials);

    let sni = tls::quic_tls_server_client_sni(srv);
    assert(sni[..] == "h3.example.test");
    assert(tls::quic_tls_server_peer_tp(srv) == cli_tp);

    assert(tls::quic_tls_server_set_credentials_pem(srv, fullchain_pem[..], key_pem[..]) == tls::QuicTlsStatus.Ok);
    assert(tls::quic_tls_server_negotiated_alpn(srv)[..] == "h3");

    var s2c_init: u8[>..] = [];
    var s2c_hs:   u8[>..] = [];
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Initial, s2c_init) > 40);
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Handshake, s2c_hs) > 80);
    assert(s2c_init[0] == rfc::TLS_HS_SERVER_HELLO);
    assert(s2c_hs[0] == rfc::TLS_HS_ENCRYPTED_EXTENSIONS);

    var srv_hs_sec = tls::QuicTlsSecrets { .. };
    var srv_app_tx = tls::QuicTlsSecrets { .. };
    var srv_extra = tls::QuicTlsSecrets { .. };
    assert(tls::quic_tls_server_take_secrets(srv, srv_hs_sec));
    assert(srv_hs_sec.level == tls::QuicTlsLevel.Handshake && srv_hs_sec.has_read && srv_hs_sec.has_write);
    assert(tls::quic_tls_server_take_secrets(srv, srv_app_tx));
    assert(srv_app_tx.level == tls::QuicTlsLevel.Application && srv_app_tx.has_write && !srv_app_tx.has_read);
    assert(!tls::quic_tls_server_take_secrets(srv, srv_extra));

    // Client processes Initial ServerHello + fragmented Handshake flight.
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Initial, s2c_init[..]) == tls::QuicTlsStatus.Ok);
    var cli_hs_sec = tls::QuicTlsSecrets { .. };
    assert(tls::quic_tls_client_take_secrets(cli, cli_hs_sec));
    assert(cli_hs_sec.level == tls::QuicTlsLevel.Handshake && cli_hs_sec.has_read && cli_hs_sec.has_write);
    assert(cli_hs_sec.cipher_suite == srv_hs_sec.cipher_suite);
    assert(core::ct_eq_bytes(cli_hs_sec.read_secret[..cli_hs_sec.hash_len], srv_hs_sec.write_secret[..srv_hs_sec.hash_len]));
    assert(core::ct_eq_bytes(cli_hs_sec.write_secret[..cli_hs_sec.hash_len], srv_hs_sec.read_secret[..srv_hs_sec.hash_len]));

    let hs_c1 = s2c_hs.len / 3;
    let hs_c2 = (s2c_hs.len * 2) / 3;
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Handshake, s2c_hs[..hs_c1]) == tls::QuicTlsStatus.WantMore);
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Handshake, s2c_hs[hs_c1..hs_c2]) == tls::QuicTlsStatus.WantMore);
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Handshake, s2c_hs[hs_c2..]) == tls::QuicTlsStatus.Established);

    assert(tls::quic_tls_client_peer_tp(cli) == srv_tp);
    assert(tls::quic_tls_client_negotiated_alpn(cli)[..] == "h3");

    var cli_app_sec = tls::QuicTlsSecrets { .. };
    assert(tls::quic_tls_client_take_secrets(cli, cli_app_sec));
    assert(cli_app_sec.level == tls::QuicTlsLevel.Application && cli_app_sec.has_read && cli_app_sec.has_write);

    var c2s_hs: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Handshake, c2s_hs) >= 36);
    assert(c2s_hs[0] == rfc::TLS_HS_FINISHED);

    // Server verifies client Finished before Established and releasing Application read secret.
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Handshake, c2s_hs[..]) == tls::QuicTlsStatus.Established);
    var srv_app_rx = tls::QuicTlsSecrets { .. };
    assert(tls::quic_tls_server_take_secrets(srv, srv_app_rx));
    assert(srv_app_rx.level == tls::QuicTlsLevel.Application && srv_app_rx.has_read && !srv_app_rx.has_write);

    assert(core::ct_eq_bytes(cli_app_sec.read_secret[..cli_app_sec.hash_len], srv_app_tx.write_secret[..srv_app_tx.hash_len]));
    assert(core::ct_eq_bytes(cli_app_sec.write_secret[..cli_app_sec.hash_len], srv_app_rx.read_secret[..srv_app_rx.hash_len]));

    let stale_srv = srv;
    tls::quic_tls_server_close(srv);
    tls::quic_tls_server_close(srv);
    tls::quic_tls_client_close(cli);
    tls::quic_tls_client_close(cli);
    assert(tls::quic_tls_server_peer_tp(stale_srv).len == 0);
    assert(tls::quic_tls_client_peer_tp(cli).len == 0);
    assert(tls::quic_tls_server_provide_crypto(stale_srv, tls::QuicTlsLevel.Initial, "") == tls::QuicTlsStatus.AlertError);
    assert(tls::quic_tls_server_last_alert(stale_srv) == tls::Alert.CloseNotify);
    assert(tls::quic_tls_client_last_alert(cli) == tls::Alert.CloseNotify);
    print("CHECK_QUIC_SNI_FULLCHAIN_OK\n");
}

fn run_rsa_key_format_case(use_pkcs8: bool) {
    let base_rsa_slots = count_active_rsa_slots();
    var rsa_der: u8[..4096] = [];
    build_rsa_leaf_cert_der("rsa.example.test", "rsa.example.test", rsa_der);

    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", rsa_der[..], cert_pem);

    var key_der: u8[>..] = [];
    var key_pem: u8[>..] = [];
    if use_pkcs8 {
        build_rsa_pkcs8_der(key_der);
        append_pem_block("PRIVATE KEY", key_der[..], key_pem);
    } else {
        build_rsa_pkcs1_der(key_der);
        append_pem_block("RSA PRIVATE KEY", key_der[..], key_pem);
    }

    var cli = tls::quic_tls_client_open("rsa.example.test", "h3", "\x01\x01\x10", cert_pem[..]);
    var srv = tls::quic_tls_server_open("h3", "\x01\x01\x20", false, cert_pem[..], key_pem[..]);
    assert(count_active_rsa_slots() == base_rsa_slots + 1);

    assert(tls::quic_tls_client_start(cli) == tls::QuicTlsStatus.Ok);
    var buf: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Initial, buf) > 40);
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Initial, buf[..]) == tls::QuicTlsStatus.Ok);

    var s_init: u8[>..] = [];
    var s_hs:   u8[>..] = [];
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Initial, s_init) > 40);
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Handshake, s_hs) > 80);

    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Initial, s_init[..]) == tls::QuicTlsStatus.Ok);
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Handshake, s_hs[..]) == tls::QuicTlsStatus.Established);

    var c_hs: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Handshake, c_hs) >= 36);
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Handshake, c_hs[..]) == tls::QuicTlsStatus.Established);

    tls::quic_tls_server_close(srv);
    tls::quic_tls_client_close(cli);
    assert(count_active_rsa_slots() == base_rsa_slots);
}

fn test_p256_hrr_and_invariance() {
    var ca_priv: u8[32] = [0x33; 32];
    ca_priv[31] = 0x07;
    var leaf_priv: u8[32] = [0x44; 32];
    leaf_priv[31] = 0x0B;

    var ca_der:   u8[..4096] = [];
    var leaf_der: u8[..4096] = [];
    build_p256_cert_der(ca_priv, ca_priv, "HRR Test CA", "HRR Test CA", true, "", ca_der);
    build_p256_cert_der(ca_priv, leaf_priv, "HRR Test CA", "hrr.example.test", false, "hrr.example.test", leaf_der);

    var root_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", ca_der[..], root_pem);
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", leaf_der[..], cert_pem);
    var key_pem: u8[>..] = [];
    build_p256_pkcs8_pem(leaf_priv, key_pem);

    var cli = tls::quic_tls_client_open(
        "hrr.example.test",
        "h3",
        "\x01\x01\x11",
        root_pem[..],
        rfc::GROUP_SECP256R1,
        tls::QuicClientKeyShareMode.OmitInitialShareForHrr,
    );
    var srv = tls::quic_tls_server_open("h3", "\x01\x01\x22", true);

    assert(tls::quic_tls_client_start(cli) == tls::QuicTlsStatus.Ok);
    var ch1: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Initial, ch1) > 40);
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Initial, ch1[..]) == tls::QuicTlsStatus.NeedSniCredentials);
    assert(tls::quic_tls_server_set_credentials_pem(srv, cert_pem[..], key_pem[..]) == tls::QuicTlsStatus.Ok);

    var hrr: u8[>..] = [];
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Initial, hrr) > 40);
    assert(hrr[0] == rfc::TLS_HS_SERVER_HELLO);
    assert(core::ct_eq_bytes(hrr[6..38], rfc::HRR_RANDOM[..]));

    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Initial, hrr[..]) == tls::QuicTlsStatus.Ok);
    var ch2: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Initial, ch2) > 60);

    // Clone negative CH2 mismatch test using a fresh HRR-state server verifying SNI mismatch rejection.
    var srv_bad = tls::quic_tls_server_open("h3", "\x01\x01\x22", false, cert_pem[..], key_pem[..]);
    assert(tls::quic_tls_server_provide_crypto(srv_bad, tls::QuicTlsLevel.Initial, ch1[..]) == tls::QuicTlsStatus.Ok);
    var bad_hrr: u8[>..] = [];
    let _ = tls::quic_tls_server_drain_crypto(srv_bad, tls::QuicTlsLevel.Initial, bad_hrr);
    var bad_ch2: u8[..4096] = [];
    var r2:      u8[32]     = [0x99; 32];
    build_custom_quic_ch_msg(r2, "mismatch.example.test", "h3", "\x01\x01\x11", true, "", bad_ch2);
    assert(tls::quic_tls_server_provide_crypto(srv_bad, tls::QuicTlsLevel.Initial, bad_ch2[..]) == tls::QuicTlsStatus.AlertError);
    tls::quic_tls_server_close(srv_bad);

    // Complete real P-256 HRR handshake.
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Initial, ch2[..]) == tls::QuicTlsStatus.Ok);
    var s2c_init: u8[>..] = [];
    var s2c_hs:   u8[>..] = [];
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Initial, s2c_init) > 40);
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Handshake, s2c_hs) > 80);

    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Initial, s2c_init[..]) == tls::QuicTlsStatus.Ok);
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Handshake, s2c_hs[..]) == tls::QuicTlsStatus.Established);

    var c2s_hs: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Handshake, c2s_hs) >= 36);
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Handshake, c2s_hs[..]) == tls::QuicTlsStatus.Established);

    // Secrets are coalesced if taken after Established on server.
    var s_hs = tls::QuicTlsSecrets { .. };
    var s_app = tls::QuicTlsSecrets { .. };
    assert(tls::quic_tls_server_take_secrets(srv, s_hs));
    assert(tls::quic_tls_server_take_secrets(srv, s_app));
    assert(s_app.level == tls::QuicTlsLevel.Application && s_app.has_read && s_app.has_write);

    var c_hs = tls::QuicTlsSecrets { .. };
    var c_app = tls::QuicTlsSecrets { .. };
    assert(tls::quic_tls_client_take_secrets(cli, c_hs));
    assert(tls::quic_tls_client_take_secrets(cli, c_app));
    assert(core::ct_eq_bytes(c_app.read_secret[..c_app.hash_len], s_app.write_secret[..s_app.hash_len]));
    assert(core::ct_eq_bytes(c_app.write_secret[..c_app.hash_len], s_app.read_secret[..s_app.hash_len]));

    tls::quic_tls_server_close(srv);
    tls::quic_tls_client_close(cli);
    print("CHECK_QUIC_P256_HRR_OK\n");
}

fn test_negative_rfc9001_guards() {
    var seed:     u8[32]     = [0x55; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "neg.example.test", "neg.example.test", "127.0.0.1", cert_der));
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    var pkcs8_der: u8[>..] = [
        0x30, 0x2E, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ];
    for i in 32 { pkcs8_der.push(seed[i]); }
    var key_pem: u8[>..] = [];
    append_pem_block("PRIVATE KEY", pkcs8_der[..], key_pem);

    var rand_b: u8[32] = [0x77; 32];
    // 1. Missing 0x0039 in ClientHello -> MissingExtension (109).
    var ch_no_tp: u8[..4096] = [];
    build_custom_quic_ch_msg(rand_b, "neg.example.test", "h3", "", false, "", ch_no_tp);
    var srv1 = tls::quic_tls_server_open("h3", "\x01\x01\x01", false, cert_pem[..], key_pem[..]);
    assert(tls::quic_tls_server_provide_crypto(srv1, tls::QuicTlsLevel.Initial, ch_no_tp[..]) == tls::QuicTlsStatus.AlertError);
    assert(tls::quic_tls_server_last_alert(srv1) == tls::Alert.MissingExtension);
    tls::quic_tls_server_close(srv1);

    // 2. Missing ALPN in QUIC ClientHello -> NoApplicationProtocol (120).
    var ch_no_alpn: u8[..4096] = [];
    build_custom_quic_ch_msg(rand_b, "neg.example.test", "", "\x01\x01\x02", true, "", ch_no_alpn);
    var srv2 = tls::quic_tls_server_open("h3", "\x01\x01\x01", false, cert_pem[..], key_pem[..]);
    assert(tls::quic_tls_server_provide_crypto(srv2, tls::QuicTlsLevel.Initial, ch_no_alpn[..]) == tls::QuicTlsStatus.AlertError);
    assert(tls::quic_tls_server_last_alert(srv2) == tls::Alert.NoApplicationProtocol);
    tls::quic_tls_server_close(srv2);

    // 3. Wrong ALPN -> NoApplicationProtocol (120).
    var ch_bad_alpn: u8[..4096] = [];
    build_custom_quic_ch_msg(rand_b, "neg.example.test", "h2", "\x01\x01\x02", true, "", ch_bad_alpn);
    var srv3 = tls::quic_tls_server_open("h3", "\x01\x01\x01", false, cert_pem[..], key_pem[..]);
    assert(tls::quic_tls_server_provide_crypto(srv3, tls::QuicTlsLevel.Initial, ch_bad_alpn[..]) == tls::QuicTlsStatus.AlertError);
    assert(tls::quic_tls_server_last_alert(srv3) == tls::Alert.NoApplicationProtocol);
    tls::quic_tls_server_close(srv3);

    // 4. Non-empty legacy_session_id in QUIC CH (RFC 9001 Section 8.4).
    var fake_sid: u8[32]     = [0xAA; 32];
    var ch_sid:   u8[..4096] = [];
    build_custom_quic_ch_msg(rand_b, "neg.example.test", "h3", "\x01\x01\x02", true, fake_sid[..], ch_sid);
    var srv4 = tls::quic_tls_server_open("h3", "\x01\x01\x01", false, cert_pem[..], key_pem[..]);
    assert(tls::quic_tls_server_provide_crypto(srv4, tls::QuicTlsLevel.Initial, ch_sid[..]) == tls::QuicTlsStatus.AlertError);
    tls::quic_tls_server_close(srv4);

    // 5. Invalid PEM passed to quic_tls_server_set_credentials_pem leaks zero RSA slots & fails closed.
    let rsa_before = count_active_rsa_slots();
    var ch_valid: u8[..4096] = [];
    build_custom_quic_ch_msg(rand_b, "neg.example.test", "h3", "\x01\x01\x02", true, "", ch_valid);
    var srv5 = tls::quic_tls_server_open("h3", "\x01\x01\x01", true);
    assert(tls::quic_tls_server_provide_crypto(srv5, tls::QuicTlsLevel.Initial, ch_valid[..]) == tls::QuicTlsStatus.NeedSniCredentials);
    assert(tls::quic_tls_server_set_credentials_pem(srv5, "BAD CERT", "BAD KEY") == tls::QuicTlsStatus.AlertError);
    assert(count_active_rsa_slots() == rsa_before);
    tls::quic_tls_server_close(srv5);

    // 6. Premature Application CRYPTO on unestablished server fails closed.
    var srv6 = tls::quic_tls_server_open("h3", "\x01\x01\x01", false, cert_pem[..], key_pem[..]);
    assert(tls::quic_tls_server_provide_crypto(srv6, tls::QuicTlsLevel.Application, "\x18\x00\x00\x01\x00") == tls::QuicTlsStatus.AlertError);
    assert(tls::quic_tls_server_last_alert(srv6) == tls::Alert.UnexpectedMessage);
    tls::quic_tls_server_close(srv6);

    // 7. Client receiving EncryptedExtensions missing 0x0039 fails with MissingExtension (109).
    var cli7 = tls::quic_tls_client_open("neg.example.test", "h3", "\x01\x01\x02", cert_pem[..]);
    var srv7 = tls::quic_tls_server_open("h3", "\x01\x01\x01", false, cert_pem[..], key_pem[..]);
    assert(tls::quic_tls_client_start(cli7) == tls::QuicTlsStatus.Ok);
    var init_c: u8[>..] = [];
    let _ = tls::quic_tls_client_drain_crypto(cli7, tls::QuicTlsLevel.Initial, init_c);
    assert(tls::quic_tls_server_provide_crypto(srv7, tls::QuicTlsLevel.Initial, init_c[..]) == tls::QuicTlsStatus.Ok);
    var init_s: u8[>..] = [];
    let _ = tls::quic_tls_server_drain_crypto(srv7, tls::QuicTlsLevel.Initial, init_s);
    assert(tls::quic_tls_client_provide_crypto(cli7, tls::QuicTlsLevel.Initial, init_s[..]) == tls::QuicTlsStatus.Ok);
    let empty_ee: u8[6] = [rfc::TLS_HS_ENCRYPTED_EXTENSIONS, 0x00, 0x00, 0x02, 0x00, 0x00];
    assert(tls::quic_tls_client_provide_crypto(cli7, tls::QuicTlsLevel.Handshake, empty_ee[..]) == tls::QuicTlsStatus.AlertError);
    assert(tls::quic_tls_client_last_alert(cli7) == tls::Alert.MissingExtension);
    tls::quic_tls_server_close(srv7);
    tls::quic_tls_client_close(cli7);

    // 8. TCP ClientHello carrying 0x0039 is rejected with UnsupportedExtension (110).
    var tcp_ch: u8[..4096] = [];
    build_custom_quic_ch_msg(rand_b, "neg.example.test", "h3", "\x01\x01\x02", true, rand_b[..], tcp_ch);
    var tcp_choice = tls_internal::ServerClientHelloChoice { .. };
    assert(
        !tls_internal::parse_server_client_hello(
            tcp_ch[..],
            "h3",
            0,
            0,
            tls_internal::ServerHrrMode.Allow,
            tcp_choice,
        ),
    );
    assert(tcp_choice.failure_alert == tls::Alert.UnsupportedExtension);

    print("CHECK_QUIC_NEGATIVE_OK\n");
}

thread_fn quic_tls_thread_worker(tag: i64) {
    var seed: u8[32] = [0x66; 32];
    seed[0] = (tag + 1) as u8;
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "thread.example.test", "thread.example.test", "127.0.0.1", cert_der));
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    var pkcs8_der: u8[>..] = [
        0x30, 0x2E, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ];
    for i in 32 { pkcs8_der.push(seed[i]); }
    var key_pem: u8[>..] = [];
    append_pem_block("PRIVATE KEY", pkcs8_der[..], key_pem);

    var cli = tls::quic_tls_client_open("thread.example.test", "h3", "\x01\x01\x15", cert_pem[..]);
    var srv = tls::quic_tls_server_open("h3", "\x01\x01\x25", true);
    assert(tls::quic_tls_client_start(cli) == tls::QuicTlsStatus.Ok);
    var buf: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Initial, buf) > 40);
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Initial, buf[..]) == tls::QuicTlsStatus.NeedSniCredentials);
    assert(tls::quic_tls_server_set_credentials_pem(srv, cert_pem[..], key_pem[..]) == tls::QuicTlsStatus.Ok);

    var s_i: u8[>..] = [];
    var s_h: u8[>..] = [];
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Initial, s_i) > 40);
    assert(tls::quic_tls_server_drain_crypto(srv, tls::QuicTlsLevel.Handshake, s_h) > 60);
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Initial, s_i[..]) == tls::QuicTlsStatus.Ok);
    assert(tls::quic_tls_client_provide_crypto(cli, tls::QuicTlsLevel.Handshake, s_h[..]) == tls::QuicTlsStatus.Established);

    var c_h: u8[>..] = [];
    assert(tls::quic_tls_client_drain_crypto(cli, tls::QuicTlsLevel.Handshake, c_h) >= 36);
    assert(tls::quic_tls_server_provide_crypto(srv, tls::QuicTlsLevel.Handshake, c_h[..]) == tls::QuicTlsStatus.Established);
    assert(tls::quic_tls_client_peer_tp(cli) == "\x01\x01\x25");
    assert(tls::quic_tls_server_peer_tp(srv) == "\x01\x01\x15");
    tls::quic_tls_server_close(srv);
    tls::quic_tls_client_close(cli);
}

fn test_concurrent_thread_local_arenas() {
    let t1 = thread_spawn(quic_tls_thread_worker, 1);
    let t2 = thread_spawn(quic_tls_thread_worker, 2);
    assert(thread_wait(t1));
    assert(thread_wait(t2));
    print("CHECK_QUIC_THREAD_OK\n");
}

fn main() {
    test_deferred_sni_fullchain_and_fragmented();
    run_rsa_key_format_case(false);
    run_rsa_key_format_case(true);
    print("CHECK_QUIC_RSA_OK\n");
    test_p256_hrr_and_invariance();
    test_negative_rfc9001_guards();
    test_concurrent_thread_local_arenas();
}

// CHECK: CHECK_QUIC_SNI_FULLCHAIN_OK
// CHECK: CHECK_QUIC_RSA_OK
// CHECK: CHECK_QUIC_P256_HRR_OK
// CHECK: CHECK_QUIC_NEGATIVE_OK
// CHECK: CHECK_QUIC_THREAD_OK
