// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of TLS 1.3 server compatibility upgrades:
// 1. Full-chain PEM credential loading (leaf + intermediate) & live chain delivery/verification.
// 2. RSA-2048 PEM server credentials (PKCS#8 & PKCS#1), 0x0804 RSA-PSS-SHA256 handshake,
//    modulus mismatch fail-closed rollback, and zeroizing release_server_credentials.
// 3. Client secp256r1 (0x0017) key_share handshake.
// 4. Empty key_share HelloRetryRequest (HRR_RANDOM + message_hash) for X25519 & secp256r1,
//    plus rejection of a second HRR attempt.
// 5. cert_expires_within_sec renewal-window boundary and overflow safety.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// ---- Deterministic RSA-2048 Test Key Components (e = 65537) ----------------

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

// ---- ASN.1 DER & PEM Test Fixture Helpers ----------------------------------

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

fn build_ed25519_cert_der<B>(
    issuer_seed:   const u8[32]&,
    subj_seed:     const u8[32]&,
    issuer_cn:     const u8[:],
    subject_cn:    const u8[:],
    is_ca:         bool,
    dns_san:       const u8[:],
    out_der:       B&,
    extra_pad_len: i64 = 0,
) {
    let subj_pub = core::ed25519_public_key(subj_seed);
    var tbs_body: u8[..4096] = [];
    let ver_v3: u8[3] = [0x02, 0x01, 0x02];
    der_append_tlv(tbs_body, 0xA0, ver_v3[..]);
    let ser: u8[2] = [0x01, 0x07];
    der_append_tlv(tbs_body, rfc::ASN1_TAG_INTEGER, ser[..]);

    var ed_alg: u8[..16] = [];
    der_append_tlv(ed_alg, rfc::ASN1_TAG_OID, rfc::OID_ED25519[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, ed_alg[..]);

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

    var spki_body: u8[..64] = [];
    der_append_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, ed_alg[..]);
    var pk_bits: u8[33] = [0; 33];
    for i in 32 { pk_bits[i + 1] = subj_pub[i]; }
    der_append_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, pk_bits[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, spki_body[..]);

    var exts_body: u8[..4000] = [];
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
    if extra_pad_len > 0 {
        let pad_oid: u8[6] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x01];
        var pad_oct: u8[..3900] = [];
        pad_oct.resize(extra_pad_len, 0x5A);
        encode_ext_entry(exts_body, pad_oid[..], false, pad_oct[..]);
    }
    if exts_body.len > 0 {
        var exts_seq: u8[..4020] = [];
        der_wrap(rfc::ASN1_TAG_SEQUENCE, exts_body[..], exts_seq);
        der_append_tlv(tbs_body, 0xA3, exts_seq[..]);
    }

    var tbs_der: u8[..4040] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, tbs_body[..], tbs_der);
    let sig = core::ed25519_sign(issuer_seed, tbs_der[..]);

    var cert_body: u8[..4096] = [];
    assert(cert_body.try_append(tbs_der[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_SEQUENCE, ed_alg[..]);
    var sig_bits: u8[65] = [0; 65];
    for i in 64 { sig_bits[i + 1] = sig[i]; }
    der_append_tlv(cert_body, rfc::ASN1_TAG_BIT_STRING, sig_bits[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, cert_body[..], out_der);
}

fn build_ed25519_pkcs8_pem(seed: const u8[32]&, out_pem: u8[>..]&) {
    var der: u8[>..] = [
        0x30, 0x2E, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ];
    for i in 32 { der.push(seed[i]); }
    append_pem_block("PRIVATE KEY", der[..], out_pem);
}

fn build_rsa_pkcs1_der(n_be: const u8[:], out_der: u8[>..]&) {
    out_der.clear();
    var body: u8[..2048] = [];
    let zero_v: u8[1] = [0x00];
    der_append_pos_int(body, zero_v[..]);
    der_append_pos_int(body, n_be);
    der_append_pos_int(body, TEST_RSA_E[..]);
    der_append_pos_int(body, TEST_RSA_D[..]);
    der_append_pos_int(body, TEST_RSA_P[..]);
    der_append_pos_int(body, TEST_RSA_Q[..]);
    der_append_pos_int(body, TEST_RSA_DP[..]);
    der_append_pos_int(body, TEST_RSA_DQ[..]);
    der_append_pos_int(body, TEST_RSA_QINV[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, body[..], out_der);
}

fn build_rsa_pkcs8_der(n_be: const u8[:], out_der: u8[>..]&) {
    out_der.clear();
    var pkcs1: u8[>..] = [];
    build_rsa_pkcs1_der(n_be, pkcs1);
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

fn is_all_zero(buf: const u8[:]) -> bool {
    for b in buf {
        if b != 0 { return false; }
    }
    return true;
}

// ---- Test 1 & 2: Full-Chain & RSA PEM Loading / Expiry / Release -----------

fn test_pem_fullchain_rsa_and_expiry() {
    let root_seed:  u8[32] = [0x11; 32];
    let inter_seed: u8[32] = [0x22; 32];
    let leaf_seed:  u8[32] = [0x33; 32];

    var root_der:  u8[..2048] = [];
    var inter_der: u8[..2048] = [];
    var leaf_der:  u8[..2048] = [];
    build_ed25519_cert_der(root_seed, root_seed, "Wing Root CA", "Wing Root CA", true, "", root_der);
    build_ed25519_cert_der(root_seed, inter_seed, "Wing Root CA", "Wing Inter CA", true, "", inter_der);
    build_ed25519_cert_der(inter_seed, leaf_seed, "Wing Inter CA", "localhost", false, "localhost", leaf_der);

    var fullchain_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", leaf_der[..], fullchain_pem);
    append_pem_block("CERTIFICATE", inter_der[..], fullchain_pem);
    var leaf_key_pem: u8[>..] = [];
    build_ed25519_pkcs8_pem(leaf_seed, leaf_key_pem);

    var cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(fullchain_pem[..], leaf_key_pem[..], cfg));
    assert(cfg.cert_der[..] == leaf_der[..]);
    assert(cfg.extra_certs_der.len == 1);
    assert(cfg.extra_certs_der[0][..] == inter_der[..]);
    assert(cfg.key_kind == tls::PrivateKeyKind.Ed25519);
    assert(cfg.rsa_key_slot == -1);

    // Negative: > 3 extra certs (5 total) MUST fail and roll back cfg completely.
    var five_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", leaf_der[..], five_pem);
    for _ in 4 { append_pem_block("CERTIFICATE", inter_der[..], five_pem); }
    assert(!tls::load_server_credentials_pem(five_pem[..], leaf_key_pem[..], cfg));
    assert(cfg.cert_der.len == 0 && cfg.extra_certs_der.len == 0);
    assert(cfg.key_kind == tls::PrivateKeyKind.Unknown && cfg.rsa_key_slot == -1);
    assert(is_all_zero(cfg.priv_seed[..]));

    // RSA-2048 cert + PKCS#8 and PKCS#1 loading, mismatch rejection, and release_server_credentials.
    var rsa_der: u8[..4096] = [];
    build_rsa_leaf_cert_der("localhost", "localhost", rsa_der);
    var rsa_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", rsa_der[..], rsa_pem);

    var rsa_p8_der: u8[>..] = [];
    build_rsa_pkcs8_der(TEST_RSA_N[..], rsa_p8_der);
    var rsa_p8_pem: u8[>..] = [];
    append_pem_block("PRIVATE KEY", rsa_p8_der[..], rsa_p8_pem);

    var rsa_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(rsa_pem[..], rsa_p8_pem[..], rsa_cfg));
    assert(rsa_cfg.key_kind == tls::PrivateKeyKind.Rsa);
    let slot_p8 = rsa_cfg.rsa_key_slot;
    assert(slot_p8 >= 0);

    tls::release_server_credentials(rsa_cfg);
    assert(rsa_cfg.rsa_key_slot == -1 && rsa_cfg.key_kind == tls::PrivateKeyKind.Unknown);
    assert(is_all_zero(rsa_cfg.priv_seed[..]));
    assert(!tls::g_tls_rsa_keys[slot_p8 as i64].in_use);
    assert(tls::g_tls_rsa_keys[slot_p8 as i64].n.len == 0);
    assert(tls::g_tls_rsa_keys[slot_p8 as i64].d.len == 0);
    tls::release_server_credentials(rsa_cfg); // idempotent

    // PKCS#1 RSA PRIVATE KEY reuses released slot 0.
    var rsa_p1_der: u8[>..] = [];
    build_rsa_pkcs1_der(TEST_RSA_N[..], rsa_p1_der);
    var rsa_p1_pem: u8[>..] = [];
    append_pem_block("RSA PRIVATE KEY", rsa_p1_der[..], rsa_p1_pem);
    assert(tls::load_server_credentials_pem(rsa_pem[..], rsa_p1_pem[..], rsa_cfg));
    assert(rsa_cfg.key_kind == tls::PrivateKeyKind.Rsa && rsa_cfg.rsa_key_slot == slot_p8);

    // Mismatched RSA modulus MUST fail closed with rsa_key_slot == -1 and roll back.
    var bad_n: u8[256] = TEST_RSA_N;
    bad_n[100] ^= 0x01;
    var bad_rsa_der: u8[>..] = [];
    build_rsa_pkcs8_der(bad_n[..], bad_rsa_der);
    var bad_rsa_pem: u8[>..] = [];
    append_pem_block("PRIVATE KEY", bad_rsa_der[..], bad_rsa_pem);
    assert(!tls::load_server_credentials_pem(rsa_pem[..], bad_rsa_pem[..], rsa_cfg));
    assert(rsa_cfg.rsa_key_slot == -1 && rsa_cfg.key_kind == tls::PrivateKeyKind.Unknown);
    assert(rsa_cfg.cert_der.len == 0 && rsa_cfg.extra_certs_der.len == 0);
    assert(!tls::g_tls_rsa_keys[slot_p8 as i64].in_use);

    // Negative: malformed second PEM block after valid leaf MUST fail closed and roll back.
    var bad_tail_pem: u8[>..] = [];
    bad_tail_pem.append(rsa_pem[..]);
    bad_tail_pem.append("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n");
    assert(!tls::load_server_credentials_pem(bad_tail_pem[..], rsa_p1_pem[..], rsa_cfg));
    assert(rsa_cfg.rsa_key_slot == -1 && rsa_cfg.cert_der.len == 0);

    // Negative: 1024-bit RSA key (< 2048-bit floor) MUST be rejected by PKCS#1 parser.
    var small_n:  u8[128] = [0xBB; 128];
    var small_p1: u8[>..] = [];
    build_rsa_pkcs1_der(small_n[..], small_p1);
    let _, _, _, ok_small = tls_internal::parse_rsa_pkcs1_private_key_der(small_p1[..]);
    assert(!ok_small);

    // Negative: RSA PKCS#1 with zero/even exponent or even prime p MUST fail.
    var zero_e_body: u8[..2048] = [];
    let zero_v: u8[1] = [0x00];
    der_append_pos_int(zero_e_body, zero_v[..]);
    der_append_pos_int(zero_e_body, TEST_RSA_N[..]);
    der_append_pos_int(zero_e_body, zero_v[..]);
    der_append_pos_int(zero_e_body, TEST_RSA_D[..]);
    der_append_pos_int(zero_e_body, TEST_RSA_P[..]);
    der_append_pos_int(zero_e_body, TEST_RSA_Q[..]);
    der_append_pos_int(zero_e_body, TEST_RSA_DP[..]);
    der_append_pos_int(zero_e_body, TEST_RSA_DQ[..]);
    der_append_pos_int(zero_e_body, TEST_RSA_QINV[..]);
    var zero_e_der: u8[>..] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, zero_e_body[..], zero_e_der);
    let _, _, _, ok_ze = tls_internal::parse_rsa_pkcs1_private_key_der(zero_e_der[..]);
    assert(!ok_ze);

    // cert_expires_within_sec boundary & overflow safety checks.
    var parsed_leaf = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(leaf_der[..], parsed_leaf));
    let na = parsed_leaf.validity_not_after;
    assert(tls::cert_expires_within_sec(fullchain_pem[..], na - 3600, 86400));
    assert(tls::cert_expires_within_sec(fullchain_pem[..], na - 86400, 86400));
    assert(!tls::cert_expires_within_sec(fullchain_pem[..], na - 86401, 86400));
    assert(tls::cert_expires_within_sec(fullchain_pem[..], na + 10, 0));
    assert(!tls::cert_expires_within_sec(fullchain_pem[..], -1000, 86400));
    assert(tls::cert_expires_within_sec("NOT-A-PEM", 1750000000, 86400));

    print("PEM_FULLCHAIN_RSA_EXPIRY: OK");
    // CHECK: PEM_FULLCHAIN_RSA_EXPIRY: OK
}

// ---- Custom ClientHello Builder & Wire Driver for P-256 + HRR --------------

fn build_custom_ch_msg(
    random:       const u8[32]&,
    groups:       const u16[:],
    sig_schemes:  const u16[:],
    send_p256_ks: bool,
    p256_pub:     const u8[:],
    send_x25519:  bool,
    x25519_pub:   const u8[32]&,
    out_msg:      u8[..4096]&,
) {
    out_msg.clear();
    var pay: u8[..4096] = [];
    pay.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    pay.append(random[..]);
    pay.push(32);
    pay.append(random[..]);
    pay.append_u16_be(2);
    pay.append_u16_be(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    pay.push(1);
    pay.push(0);

    var ext: u8[..2048] = [];
    ext.append_u16_be(rfc::TLS_EXT_SUPPORTED_VERSIONS);
    ext.append_u16_be(3);
    ext.push(2);
    ext.append_u16_be(rfc::TLS_VERSION_1_3);

    tls_internal::encode_supported_groups_extension(ext, groups);

    ext.append_u16_be(rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    let sig_bytes_len = (sig_schemes.len * 2) as u16;
    ext.append_u16_be(sig_bytes_len + 2);
    ext.append_u16_be(sig_bytes_len);
    for sc in sig_schemes { ext.append_u16_be(sc); }

    var shares: u8[..256] = [];
    if send_x25519 {
        shares.append_u16_be(rfc::GROUP_X25519);
        shares.append_u16_be(32);
        shares.append(x25519_pub[..]);
    }
    if send_p256_ks && p256_pub.len == 65 {
        shares.append_u16_be(rfc::GROUP_SECP256R1);
        shares.append_u16_be(65);
        shares.append(p256_pub);
    }
    ext.append_u16_be(rfc::TLS_EXT_KEY_SHARE);
    ext.append_u16_be((shares.len + 2) as u16);
    ext.append_u16_be(shares.len as u16);
    ext.append(shares[..]);

    let sni = "localhost";
    ext.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
    ext.append_u16_be((sni.len + 5) as u16);
    ext.append_u16_be((sni.len + 3) as u16);
    ext.push(0);
    ext.append_u16_be(sni.len as u16);
    ext.append(sni);

    pay.append_u16_be(ext.len as u16);
    pay.append(ext[..]);
    assert(tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, pay[..], out_msg));
}

fn client_complete_with_ch1(
    fd:          i64,
    ch1_msg:     const u8[:],
    cli_rand:    const u8[32]&,
    cli_priv:    const u8[32]&,
    trust_store: const tls::TrustAnchorStore&,
    expect_hrr:  bool,
    exp_group:   u16,
    ch2_empty:   bool,
) -> bool {
    guard tls_internal::send_plaintext_handshake_record(fd, ch1_msg, rfc::TLS_LEGACY_VERSION_1_0) else {
        return false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard tls_internal::tls_write_all(fd, ccs[..]) else { return false; }

    var tr = tls::Transcript { .. };
    tls_internal::transcript_update(tr, ch1_msg);

    var active_priv = cli_priv;
    if expect_hrr {
        var hrr_msg: u8[..16384] = [];
        guard tls_internal::read_plaintext_handshake_record(fd, hrr_msg, 5000) else { return false; }
        var hrr_sh = tls::ParsedServerHello { .. };
        guard tls::parse_live_server_hello(hrr_msg[..], hrr_sh) &&
            hrr_sh.is_hrr &&
            hrr_sh.selected_group == exp_group &&
            core::ct_eq_bytes(hrr_msg[6..38], rfc::HRR_RANDOM[..]) &&
            core::ct_eq_bytes(hrr_sh.session_id_echo[..], cli_rand[..]) else {
            return false;
        }
        var ks_hrr, ok_kshr = tls_internal::ks_init(hrr_sh.cipher_suite);
        guard ok_kshr && tls_internal::transcript_replace_with_message_hash(tr, ks_hrr.hash_id, ks_hrr.hash_len) else {
            return false;
        }
        tls_internal::transcript_update(tr, hrr_msg[..]);

        var ch2_msg: u8[..4096] = [];
        let groups: u16[2] = [rfc::GROUP_X25519, rfc::GROUP_SECP256R1];
        let sigs: u16[3] = [
            rfc::SIG_SCHEME_ED25519,
            rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
            rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        ];
        if ch2_empty {
            let zero32: u8[32] = [0; 32];
            build_custom_ch_msg(cli_rand, groups[..], sigs[..], false, "", false, zero32, ch2_msg);
        } else if exp_group == rfc::GROUP_SECP256R1 {
            let p256_pub = core::ecdsa_p256_public_key(active_priv);
            let zero32: u8[32] = [0; 32];
            build_custom_ch_msg(cli_rand, groups[..], sigs[..], true, p256_pub[..], false, zero32, ch2_msg);
        } else {
            let x_pub = core::x25519_base_scalarmult(active_priv);
            build_custom_ch_msg(cli_rand, groups[..], sigs[..], false, "", true, x_pub, ch2_msg);
        }
        guard tls_internal::send_plaintext_handshake_record(fd, ch2_msg[..], rfc::TLS_LEGACY_VERSION_1_2) else {
            return false;
        }
        tls_internal::transcript_update(tr, ch2_msg[..]);
    }

    var sh_msg: u8[..16384] = [];
    guard tls_internal::read_plaintext_handshake_record(fd, sh_msg, 5000) else { return false; }
    var sh = tls::ParsedServerHello { .. };
    guard tls::parse_live_server_hello(sh_msg[..], sh) && !sh.is_hrr && sh.selected_group == exp_group else {
        return false;
    }
    tls_internal::transcript_update(tr, sh_msg[..]);

    var ecdhe: u8[32] = [0; 32];
    if exp_group == rfc::GROUP_SECP256R1 {
        let ss, ok_ss = core::p256_ecdh_shared_secret(active_priv, sh.server_share[..]);
        guard ok_ss else { return false; }
        ecdhe = ss;
    } else {
        guard sh.server_share.len == 32 else { return false; }
        var srv_pub: u8[32] = [0; 32];
        core::ct_copy_bytes(srv_pub[..], sh.server_share[..]);
        let ss, ok_ss = core::x25519_shared_secret(active_priv, srv_pub);
        guard ok_ss else { return false; }
        ecdhe = ss;
    }

    var ks, ok_ks = tls_internal::ks_init(sh.cipher_suite);
    guard ok_ks &&
        tls_internal::ks_init_early_secret(ks, "") &&
        tls_internal::ks_advance_to_handshake(ks, ecdhe[..]) else {
        return false;
    }
    var ch_sh_hash: u8[..48] = [];
    tls_internal::transcript_current_hash(tr, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else { return false; }

    let klen_u16 = rfc::tls13_cipher_suite_key_len(sh.cipher_suite);
    let klen = klen_u16 as i64;
    let hlen = ks.hash_len as i64;
    var c_hs_key: u8[32] = [0; 32];
    var s_hs_key: u8[32] = [0; 32];
    var c_hs_iv:  u8[12] = [0; 12];
    var s_hs_iv:  u8[12] = [0; 12];
    guard tls_internal::ks_derive_key_iv(ks.hash_id, ks.client_hs_traffic[..hlen], klen_u16, c_hs_key[..klen], c_hs_iv) &&
        tls_internal::ks_derive_key_iv(ks.hash_id, ks.server_hs_traffic[..hlen], klen_u16, s_hs_key[..klen], s_hs_iv) else {
        return false;
    }

    let slot_idx = tls::alloc_cipher_slot();
    guard slot_idx != 0xFFFF else { return false; }
    defer tls::free_cipher_slot(slot_idx);

    var cli_cfg = tls::ClientHandshakeConfig {
        trust_store:            trust_store,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(cli_cfg.server_name.try_set("localhost"));

    var hs_reader = tls::HandshakeRecordReader { .. };
    var ech_st = tls_internal::EchClientState { .. };
    var neg_alpn: u8[..255] = [];
    var cr_rx = false;
    var cr_msg = tls::CertificateRequestMsg { .. };
    guard tls_internal::tls_client_process_server_flight(
        hs_reader, fd, sh.cipher_suite, s_hs_key[..klen], s_hs_iv, c_hs_key[..klen], c_hs_iv,
        ks, tr, cli_cfg, ech_st, false, neg_alpn, cr_rx, cr_msg, slot_idx,
    ) else { return false; }

    var h_srv_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(tr, ks.hash_id, h_srv_fin);
    guard tls_internal::ks_advance_to_master(ks, h_srv_fin[..]) else { return false; }
    guard tls_internal::tls_client_send_finished(
        fd, sh.cipher_suite, c_hs_key[..klen], c_hs_iv, ks, tr, cli_cfg, cr_rx, cr_msg,
    ) else { return false; }

    var c_ap_key: u8[32] = [0; 32];
    var s_ap_key: u8[32] = [0; 32];
    var c_ap_iv:  u8[12] = [0; 12];
    var s_ap_iv:  u8[12] = [0; 12];
    guard tls_internal::ks_derive_key_iv(ks.hash_id, ks.client_ap_traffic[..hlen], klen_u16, c_ap_key[..klen], c_ap_iv) &&
        tls_internal::ks_derive_key_iv(ks.hash_id, ks.server_ap_traffic[..hlen], klen_u16, s_ap_key[..klen], s_ap_iv) else {
        return false;
    }
    tls_internal::tls_setup_client_cipher_slot(
        slot_idx, sh.cipher_suite, klen_u16, ks,
        c_ap_key[..klen], c_ap_iv, s_ap_key[..klen], s_ap_iv, "localhost", neg_alpn[..], false,
    );

    guard tls::transport_send(fd, slot_idx, "PING") == 4 else { return false; }
    var rx: u8[16] = [0; 16];
    let n = tls::transport_recv_slice(fd, slot_idx, rx[..], 5000);
    return n == 4 && rx[..4] == "PONG";
}

// ---- Live Loopback Server Worker -------------------------------------------

fn serve_one_expect_ok(listener_fd: i64, srv_cfg: const tls::ServerHandshakeConfig&, use_with_ch: bool) {
    let conn = net::tcp_accept(listener_fd, 5000);
    assert(conn > 0);
    var slot: u16 = 0xFFFF;
    var ok = false;
    if use_with_ch {
        var ch_msg: u8[..16384] = [];
        assert(tls_internal::read_plaintext_handshake_record(conn, ch_msg, 5000));
        let s, res = tls::server_handshake_with_ch(conn, ch_msg[..], srv_cfg);
        slot = s;
        ok = res;
    } else {
        let s, res = tls::server_handshake(conn, srv_cfg);
        slot = s;
        ok = res;
    }
    assert(ok && slot != 0xFFFF);
    var rx: u8[16] = [0; 16];
    let n = tls::transport_recv_slice(conn, slot, rx[..], 5000);
    assert(n == 4 && rx[..4] == "PING");
    assert(tls::transport_send(conn, slot, "PONG") == 4);
    tls::transport_close(conn, slot);
}

fn serve_one_expect_fail(listener_fd: i64, srv_cfg: const tls::ServerHandshakeConfig&) {
    let conn = net::tcp_accept(listener_fd, 5000);
    assert(conn > 0);
    var ch_msg: u8[..16384] = [];
    if tls_internal::read_plaintext_handshake_record(conn, ch_msg, 5000) {
        let slot, ok = tls::server_handshake_with_ch(conn, ch_msg[..], srv_cfg);
        assert(!ok && slot == 0xFFFF);
    }
    net::tcp_close(conn);
}

thread_fn compat_server_worker(listener_fd: i64) {
    let root_seed:  u8[32] = [0x11; 32];
    let inter_seed: u8[32] = [0x22; 32];
    let leaf_seed:  u8[32] = [0x33; 32];
    var root_der:  u8[..2048] = [];
    var inter_der: u8[..2048] = [];
    var leaf_der:  u8[..2048] = [];
    build_ed25519_cert_der(root_seed, root_seed, "Wing Root CA", "Wing Root CA", true, "", root_der);
    build_ed25519_cert_der(root_seed, inter_seed, "Wing Root CA", "Wing Inter CA", true, "", inter_der);
    build_ed25519_cert_der(inter_seed, leaf_seed, "Wing Inter CA", "localhost", false, "localhost", leaf_der);

    var fullchain_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", leaf_der[..], fullchain_pem);
    append_pem_block("CERTIFICATE", inter_der[..], fullchain_pem);
    var leaf_key_pem: u8[>..] = [];
    build_ed25519_pkcs8_pem(leaf_seed, leaf_key_pem);

    var chain_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(fullchain_pem[..], leaf_key_pem[..], chain_cfg));
    defer tls::release_server_credentials(chain_cfg);

    // Conn 1: Full-chain 2-cert delivery (leaf + intermediate -> root anchor)
    serve_one_expect_ok(listener_fd, chain_cfg, false);

    // Conn 2: Client secp256r1 (0x0017) key_share handshake
    serve_one_expect_ok(listener_fd, chain_cfg, true);

    // Conn 3: Empty key_share + [X25519, secp256r1] -> HRR(X25519) -> CH2 -> OK
    serve_one_expect_ok(listener_fd, chain_cfg, true);

    // Conn 4: Empty key_share + [secp256r1] -> HRR(secp256r1) -> CH2 -> OK
    serve_one_expect_ok(listener_fd, chain_cfg, true);

    // Conn 5: Double-HRR attempt (CH2 still empty key_share) -> FAIL
    serve_one_expect_fail(listener_fd, chain_cfg);

    // Conn 6 & 7: RSA-2048 PKCS#8 cert/key live handshake (0x0804) & sig_alg rejection
    var rsa_der: u8[..4096] = [];
    build_rsa_leaf_cert_der("localhost", "localhost", rsa_der);
    var rsa_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", rsa_der[..], rsa_pem);
    var rsa_p8_der: u8[>..] = [];
    build_rsa_pkcs8_der(TEST_RSA_N[..], rsa_p8_der);
    var rsa_p8_pem: u8[>..] = [];
    append_pem_block("PRIVATE KEY", rsa_p8_der[..], rsa_p8_pem);

    var rsa_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(rsa_pem[..], rsa_p8_pem[..], rsa_cfg));
    defer tls::release_server_credentials(rsa_cfg);

    serve_one_expect_ok(listener_fd, rsa_cfg, false);
    serve_one_expect_fail(listener_fd, rsa_cfg);

    // Conn 8: 4-cert (>16 KiB) fullchain fragmented Certificate flight
    let inter2_seed: u8[32] = [0x44; 32];
    let inter3_seed: u8[32] = [0x55; 32];
    let leaf4_seed:  u8[32] = [0x66; 32];
    var i1_big: u8[..4096] = [];
    var i2_big: u8[..4096] = [];
    var i3_big: u8[..4096] = [];
    var l4_big: u8[..4096] = [];
    build_ed25519_cert_der(root_seed, inter_seed, "Wing Root CA", "Wing CA1", true, "", i1_big, 3834);
    build_ed25519_cert_der(inter_seed, inter2_seed, "Wing CA1", "Wing CA2", true, "", i2_big, 3838);
    build_ed25519_cert_der(inter2_seed, inter3_seed, "Wing CA2", "Wing CA3", true, "", i3_big, 3838);
    build_ed25519_cert_der(inter3_seed, leaf4_seed, "Wing CA3", "localhost", false, "localhost", l4_big, 3810);

    var big_chain_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", l4_big[..], big_chain_pem);
    append_pem_block("CERTIFICATE", i3_big[..], big_chain_pem);
    append_pem_block("CERTIFICATE", i2_big[..], big_chain_pem);
    append_pem_block("CERTIFICATE", i1_big[..], big_chain_pem);
    var l4_key_pem: u8[>..] = [];
    build_ed25519_pkcs8_pem(leaf4_seed, l4_key_pem);

    var big_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(big_chain_pem[..], l4_key_pem[..], big_cfg));
    defer tls::release_server_credentials(big_cfg);
    assert(big_cfg.extra_certs_der.len == 3);
    var encoded_cert_msg: u8[..20480] = [];
    assert(tls_internal::encode_server_cert_chain_msg(
        big_cfg.cert_der[..], big_cfg.extra_certs_der[..], encoded_cert_msg,
    ));
    assert(encoded_cert_msg.len > rfc::TLS_MAX_RECORD_PLAINTEXT_LEN);
    serve_one_expect_ok(listener_fd, big_cfg, false);

    // Conn 9: Live RSA-2048 PKCS#1 (BEGIN RSA PRIVATE KEY) handshake
    var rsa_p1_der: u8[>..] = [];
    build_rsa_pkcs1_der(TEST_RSA_N[..], rsa_p1_der);
    var rsa_p1_pem: u8[>..] = [];
    append_pem_block("RSA PRIVATE KEY", rsa_p1_der[..], rsa_p1_pem);
    var rsa_p1_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(rsa_pem[..], rsa_p1_pem[..], rsa_p1_cfg));
    defer tls::release_server_credentials(rsa_p1_cfg);
    serve_one_expect_ok(listener_fd, rsa_p1_cfg, false);
}

fn test_live_handshakes() {
    let root_seed: u8[32] = [0x11; 32];
    var root_der: u8[..2048] = [];
    build_ed25519_cert_der(root_seed, root_seed, "Wing Root CA", "Wing Root CA", true, "", root_der);

    var root_store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(root_store, root_der[..]));

    var rsa_der: u8[..4096] = [];
    build_rsa_leaf_cert_der("localhost", "localhost", rsa_der);
    var rsa_store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(rsa_store, rsa_der[..]));

    let listener = net::tcp_listen("127.0.0.1", 0, 16);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(compat_server_worker, listener);

    // 1. Live full-chain 2-cert handshake (client trusts ONLY root_der, not intermediate!)
    let fd1 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd1 > 0);
    var cli_cfg1 = tls::ClientHandshakeConfig {
        trust_store:            root_store,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(cli_cfg1.server_name.try_set("localhost"));
    let cslot1, ok1 = tls::client_handshake(fd1, cli_cfg1);
    assert(ok1 && cslot1 != 0xFFFF);
    assert(tls::transport_send(fd1, cslot1, "PING") == 4);
    var rx1: u8[16] = [0; 16];
    assert(tls::transport_recv_slice(fd1, cslot1, rx1[..], 5000) == 4 && rx1[..4] == "PONG");
    tls::transport_close(fd1, cslot1);
    print("LIVE_FULLCHAIN_2CERT: OK");
    // CHECK: LIVE_FULLCHAIN_2CERT: OK

    // 2. Client secp256r1 (0x0017) key_share handshake
    let fd2 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd2 > 0);
    let r2:    u8[32] = [0xA1; 32];
    let priv2: u8[32] = [0xB1; 32];
    let pub2_65 = core::ecdsa_p256_public_key(priv2);
    let grps_p256: u16[1] = [rfc::GROUP_SECP256R1];
    let sigs_all: u16[3] = [
        rfc::SIG_SCHEME_ED25519,
        rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256,
    ];
    var ch_p256: u8[..4096] = [];
    let zero32: u8[32] = [0; 32];
    build_custom_ch_msg(r2, grps_p256[..], sigs_all[..], true, pub2_65[..], false, zero32, ch_p256);
    assert(client_complete_with_ch1(fd2, ch_p256[..], r2, priv2, root_store, false, rfc::GROUP_SECP256R1, false));
    net::tcp_close(fd2);
    print("LIVE_P256_KEYSHARE: OK");
    // CHECK: LIVE_P256_KEYSHARE: OK

    // 3. Empty key_share + [X25519, secp256r1] -> HRR(X25519) -> CH2 -> OK
    let fd3 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd3 > 0);
    let r3:        u8[32] = [0xA2; 32];
    let priv3:     u8[32] = [0xB2; 32];
    let grps_both: u16[2] = [rfc::GROUP_X25519, rfc::GROUP_SECP256R1];
    var ch_empty_both: u8[..4096] = [];
    build_custom_ch_msg(r3, grps_both[..], sigs_all[..], false, "", false, zero32, ch_empty_both);
    assert(client_complete_with_ch1(fd3, ch_empty_both[..], r3, priv3, root_store, true, rfc::GROUP_X25519, false));
    net::tcp_close(fd3);
    print("LIVE_HRR_X25519: OK");
    // CHECK: LIVE_HRR_X25519: OK

    // 4. Empty key_share + [secp256r1] -> HRR(secp256r1) -> CH2 -> OK
    let fd4 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd4 > 0);
    let r4:    u8[32] = [0xA3; 32];
    let priv4: u8[32] = [0xB3; 32];
    var ch_empty_p256: u8[..4096] = [];
    build_custom_ch_msg(r4, grps_p256[..], sigs_all[..], false, "", false, zero32, ch_empty_p256);
    assert(client_complete_with_ch1(fd4, ch_empty_p256[..], r4, priv4, root_store, true, rfc::GROUP_SECP256R1, false));
    net::tcp_close(fd4);
    print("LIVE_HRR_P256: OK");
    // CHECK: LIVE_HRR_P256: OK

    // 5. Double-HRR attempt (CH2 lacks requested key_share) MUST fail closed
    let fd5 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd5 > 0);
    let r5:    u8[32] = [0xA4; 32];
    let priv5: u8[32] = [0xB4; 32];
    var ch_empty_5: u8[..4096] = [];
    build_custom_ch_msg(r5, grps_both[..], sigs_all[..], false, "", false, zero32, ch_empty_5);
    assert(!client_complete_with_ch1(fd5, ch_empty_5[..], r5, priv5, root_store, true, rfc::GROUP_X25519, true));
    net::tcp_close(fd5);
    print("DOUBLE_HRR_REJECTED: OK");
    // CHECK: DOUBLE_HRR_REJECTED: OK

    // 6. Live RSA-2048 handshake (0x0804 rsa_pss_rsae_sha256)
    let fd6 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd6 > 0);
    var cli_cfg6 = tls::ClientHandshakeConfig {
        trust_store:            rsa_store,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(cli_cfg6.server_name.try_set("localhost"));
    let cslot6, ok6 = tls::client_handshake(fd6, cli_cfg6);
    assert(ok6 && cslot6 != 0xFFFF);
    assert(tls::transport_send(fd6, cslot6, "PING") == 4);
    var rx6: u8[16] = [0; 16];
    assert(tls::transport_recv_slice(fd6, cslot6, rx6[..], 5000) == 4 && rx6[..4] == "PONG");
    tls::transport_close(fd6, cslot6);
    print("LIVE_RSA2048_HANDSHAKE: OK");
    // CHECK: LIVE_RSA2048_HANDSHAKE: OK

    // 7. Negative: client omitting 0x0804 from signature_algorithms MUST fail against RSA server
    let fd7 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd7 > 0);
    let r7:    u8[32] = [0xA5; 32];
    let priv7: u8[32] = [0xB5; 32];
    let pub7 = core::x25519_base_scalarmult(priv7);
    let sigs_ed_only: u16[1] = [rfc::SIG_SCHEME_ED25519];
    var ch_no_rsa_sig: u8[..4096] = [];
    build_custom_ch_msg(r7, grps_both[..], sigs_ed_only[..], false, "", true, pub7, ch_no_rsa_sig);
    assert(!client_complete_with_ch1(fd7, ch_no_rsa_sig[..], r7, priv7, rsa_store, false, rfc::GROUP_X25519, false));
    net::tcp_close(fd7);
    print("RSA_SIG_ALG_REQUIRED: OK");
    // CHECK: RSA_SIG_ALG_REQUIRED: OK

    // 8. Live 4-cert >16 KiB fullchain fragmentation handshake
    let fd8 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd8 > 0);
    let cslot8, ok8 = tls::client_handshake(fd8, cli_cfg1);
    assert(ok8 && cslot8 != 0xFFFF);
    assert(tls::transport_send(fd8, cslot8, "PING") == 4);
    var rx8: u8[16] = [0; 16];
    assert(tls::transport_recv_slice(fd8, cslot8, rx8[..], 5000) == 4 && rx8[..4] == "PONG");
    tls::transport_close(fd8, cslot8);
    print("LIVE_FULLCHAIN_4CERT_FRAG: OK");
    // CHECK: LIVE_FULLCHAIN_4CERT_FRAG: OK

    // 9. Live RSA-2048 PKCS#1 (BEGIN RSA PRIVATE KEY) handshake
    let fd9 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd9 > 0);
    let cslot9, ok9 = tls::client_handshake(fd9, cli_cfg6);
    assert(ok9 && cslot9 != 0xFFFF);
    assert(tls::transport_send(fd9, cslot9, "PING") == 4);
    var rx9: u8[16] = [0; 16];
    assert(tls::transport_recv_slice(fd9, cslot9, rx9[..], 5000) == 4 && rx9[..4] == "PONG");
    tls::transport_close(fd9, cslot9);
    print("LIVE_RSA2048_PKCS1: OK");
    // CHECK: LIVE_RSA2048_PKCS1: OK

    assert(thread_wait(tid));
    net::tcp_close(listener);
}

fn pump_pure_endpoints(cli: tls::TlsEndpoint&, srv: tls::TlsEndpoint&) -> bool {
    for _ in 32 {
        var c_out: u8[32768] = [0; 32768];
        let c_n, st_co = tls::tls_endpoint_drain_wire(cli, c_out[..]);
        guard st_co == tls::TlsBackendStatus.Ok else { return false; }
        if c_n > 0 {
            let fed_c, st_fc = tls::tls_endpoint_feed_wire(srv, c_out[..c_n]);
            guard st_fc == tls::TlsBackendStatus.Ok && fed_c == c_n else {
                return false;
            }
        }
        let s_st = tls::tls_endpoint_step_handshake(srv);
        guard s_st == tls::TlsBackendStatus.Ok || s_st == tls::TlsBackendStatus.WantRead else {
            return false;
        }
        var s_out: u8[32768] = [0; 32768];
        let s_n, st_so = tls::tls_endpoint_drain_wire(srv, s_out[..]);
        guard st_so == tls::TlsBackendStatus.Ok else { return false; }
        if s_n > 0 {
            let fed_s, st_fs = tls::tls_endpoint_feed_wire(cli, s_out[..s_n]);
            guard st_fs == tls::TlsBackendStatus.Ok && fed_s == s_n else {
                return false;
            }
        }
        let c_st = tls::tls_endpoint_step_handshake(cli);
        guard c_st == tls::TlsBackendStatus.Ok || c_st == tls::TlsBackendStatus.WantRead else {
            return false;
        }
        if cli.established && srv.established {
            return true;
        }
    }
    return false;
}

fn test_pure_endpoint_compat() {
    // 1. Sans-IO TlsEndpoint RSA-2048 PKCS#1 handshake + RSA key slot zeroization on close
    var rsa_der: u8[..4096] = [];
    build_rsa_leaf_cert_der("localhost", "localhost", rsa_der);
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", rsa_der[..], cert_pem);
    var rsa_p1_der: u8[>..] = [];
    build_rsa_pkcs1_der(TEST_RSA_N[..], rsa_p1_der);
    var key_pem: u8[>..] = [];
    append_pem_block("RSA PRIVATE KEY", rsa_p1_der[..], key_pem);

    var tmp_dir: u8[>..] = [];
    if !(env("TEMP", tmp_dir) || env("TMP", tmp_dir) || env("TMPDIR", tmp_dir)) {
        tmp_dir.append("/tmp");
    }
    var cert_path_buf: u8[..256] = [];
    var key_path_buf:  u8[..256] = [];
    assert(cert_path_buf.try_append(tmp_dir[..]) && cert_path_buf.try_append("/wing_compat_ep_rsa.pem"));
    assert(key_path_buf.try_append(tmp_dir[..]) && key_path_buf.try_append("/wing_compat_ep_key.pem"));
    let cert_path = cert_path_buf[..];
    let key_path = key_path_buf[..];
    assert(write_file_atomic(cert_path, cert_pem[..]));
    assert(write_file_atomic(key_path, key_pem[..]));
    defer {
        let _ = delete_file(cert_path);
        let _ = delete_file(key_path);
    };

    var srv_cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        ..
    };
    assert(srv_cfg.cert_pem_file.try_set(cert_path));
    assert(srv_cfg.key_pem_file.try_set(key_path));
    var srv, srv_st = tls::tls_endpoint_open(srv_cfg);
    assert(srv_st == tls::TlsBackendStatus.Ok && srv.pure_slot >= 0);
    let ep_rsa_slot = tls_internal::g_pure_tls_slots[srv.pure_slot as i64].rsa_key_slot;
    assert(ep_rsa_slot >= 0 && tls::g_tls_rsa_keys[ep_rsa_slot as i64].in_use);

    var store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(store, rsa_der[..]));
    var cli_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        trust_store:            store,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(cli_cfg.server_name.try_set("localhost"));
    var cli, cli_st = tls::tls_endpoint_open(cli_cfg);
    assert(cli_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(cli);

    assert(tls::tls_endpoint_step_handshake(cli) == tls::TlsBackendStatus.WantRead);
    assert(pump_pure_endpoints(cli, srv));

    let n_wr, st_wr = tls::tls_endpoint_write_app(cli, "PING-PURE");
    assert(st_wr == tls::TlsBackendStatus.Ok && n_wr == 9);
    var ct_app: u8[256] = [0; 256];
    let n_dr, st_dr = tls::tls_endpoint_drain_wire(cli, ct_app[..]);
    assert(st_dr == tls::TlsBackendStatus.Ok && n_dr > 0);
    let n_fd, st_fd = tls::tls_endpoint_feed_wire(srv, ct_app[..n_dr]);
    assert(st_fd == tls::TlsBackendStatus.Ok && n_fd == n_dr);
    var pt_app: u8[256] = [0; 256];
    let n_rd, st_rd = tls::tls_endpoint_read_app(srv, pt_app[..]);
    assert(st_rd == tls::TlsBackendStatus.Ok && n_rd == 9 && pt_app[..n_rd] == "PING-PURE");
    tls::tls_endpoint_close(srv);
    assert(!tls::g_tls_rsa_keys[ep_rsa_slot as i64].in_use &&
        tls::g_tls_rsa_keys[ep_rsa_slot as i64].d.len == 0);

    // 2. Sans-IO TlsEndpoint Ed25519 2-cert fullchain PEM handshake (trusting only Root CA)
    let root_seed:  u8[32] = [0x11; 32];
    let inter_seed: u8[32] = [0x22; 32];
    let leaf_seed:  u8[32] = [0x33; 32];
    var root_der:  u8[..2048] = [];
    var inter_der: u8[..2048] = [];
    var leaf_der:  u8[..2048] = [];
    build_ed25519_cert_der(root_seed, root_seed, "Wing Root CA", "Wing Root CA", true, "", root_der);
    build_ed25519_cert_der(root_seed, inter_seed, "Wing Root CA", "Wing Inter CA", true, "", inter_der);
    build_ed25519_cert_der(inter_seed, leaf_seed, "Wing Inter CA", "localhost", false, "localhost", leaf_der);
    var fc_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", leaf_der[..], fc_pem);
    append_pem_block("CERTIFICATE", inter_der[..], fc_pem);
    var fc_key_pem: u8[>..] = [];
    build_ed25519_pkcs8_pem(leaf_seed, fc_key_pem);
    var fc_cpath: u8[..256] = [];
    var fc_kpath: u8[..256] = [];
    assert(fc_cpath.try_append(tmp_dir[..]) && fc_cpath.try_append("/wing_compat_ep_fc_cert.pem"));
    assert(fc_kpath.try_append(tmp_dir[..]) && fc_kpath.try_append("/wing_compat_ep_fc_key.pem"));
    assert(write_file_atomic(fc_cpath[..], fc_pem[..]));
    assert(write_file_atomic(fc_kpath[..], fc_key_pem[..]));
    defer {
        let _ = delete_file(fc_cpath[..]);
        let _ = delete_file(fc_kpath[..]);
    };

    var fc_srv_cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        ..
    };
    assert(fc_srv_cfg.cert_pem_file.try_set(fc_cpath[..]));
    assert(fc_srv_cfg.key_pem_file.try_set(fc_kpath[..]));
    var fc_srv, fc_sst = tls::tls_endpoint_open(fc_srv_cfg);
    assert(fc_sst == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(fc_srv);

    var fc_store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(fc_store, root_der[..]));
    var fc_cli_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        trust_store:            fc_store,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(fc_cli_cfg.server_name.try_set("localhost"));
    var fc_cli, fc_cst = tls::tls_endpoint_open(fc_cli_cfg);
    assert(fc_cst == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(fc_cli);
    assert(tls::tls_endpoint_step_handshake(fc_cli) == tls::TlsBackendStatus.WantRead);
    assert(pump_pure_endpoints(fc_cli, fc_srv));

    // 3. Sans-IO TlsEndpoint HRR emission when client CH1 sends empty key_share
    var ed_der: u8[..4096] = [];
    build_ed25519_cert_der(leaf_seed, leaf_seed, "localhost", "localhost", false, "localhost", ed_der);
    var hrr_srv_cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        priv_seed: leaf_seed,
        ..
    };
    assert(hrr_srv_cfg.cert_der.try_set(ed_der[..]));
    var hrr_srv, hst = tls::tls_endpoint_open(hrr_srv_cfg);
    assert(hst == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(hrr_srv);

    let r_ep:   u8[32] = [0x77; 32];
    let zero32: u8[32] = [0; 32];
    let grps_h: u16[2] = [rfc::GROUP_X25519, rfc::GROUP_SECP256R1];
    let sigs_h: u16[1] = [rfc::SIG_SCHEME_ED25519];
    var ch1_ep: u8[..4096] = [];
    build_custom_ch_msg(r_ep, grps_h[..], sigs_h[..], false, "", false, zero32, ch1_ep);
    var ch1_rec: u8[..4096] = [];
    ch1_rec.push(rfc::TLS_CONTENT_HANDSHAKE);
    ch1_rec.append_u16_be(rfc::TLS_LEGACY_VERSION_1_0);
    ch1_rec.append_u16_be(ch1_ep.len as u16);
    ch1_rec.append(ch1_ep[..]);
    let fed_h, st_fh = tls::tls_endpoint_feed_wire(hrr_srv, ch1_rec[..]);
    assert(st_fh == tls::TlsBackendStatus.Ok && fed_h == ch1_rec.len);
    assert(tls::tls_endpoint_step_handshake(hrr_srv) == tls::TlsBackendStatus.WantRead);

    var hrr_wire: u8[4096] = [0; 4096];
    let hn, h_st = tls::tls_endpoint_drain_wire(hrr_srv, hrr_wire[..]);
    assert(h_st == tls::TlsBackendStatus.Ok && hn > 43);
    assert(hrr_wire[0] == rfc::TLS_CONTENT_HANDSHAKE);
    let rec_len = core::read_be_u16(hrr_wire[..], 3) as i64;
    var parsed_hrr = tls::ParsedServerHello { .. };
    assert(tls::parse_live_server_hello(hrr_wire[5..5 + rec_len], parsed_hrr));
    assert(parsed_hrr.is_hrr && parsed_hrr.selected_group == rfc::GROUP_X25519);

    print("PURE_ENDPOINT_COMPAT: OK");
    // CHECK: PURE_ENDPOINT_COMPAT: OK
}

fn main() {
    test_pem_fullchain_rsa_and_expiry();
    test_live_handshakes();
    test_pure_endpoint_compat();
}
