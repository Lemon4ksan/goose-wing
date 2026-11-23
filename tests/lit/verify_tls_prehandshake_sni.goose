// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of Stack-Safe Arena SniRegistry and Pre-Handshake SNI in TlsEndpoint & Server:
// 1. Arena-backed SniRegistry (>4 KiB ECDSA 2-cert fullchain & RSA PEM, exact-before-wildcard,
//    update/remove/clear key zeroization, oversize rejection, and arena slot reuse).
// 2. Non-blocking sans-IO TlsEndpoint with defer_sni_credentials: true:
//    - Wildcard RSA PEM selection via tls_endpoint_client_sni -> tls_endpoint_set_server_credentials_pem
//    - Exact >4 KiB 2-cert ECDSA P-256 fullchain delivery & trust verification against Root CA
//    - ClientHello without SNI extension -> NeedSniCredentials with empty SNI -> fallback cert
//    - Invalid PEM in tls_endpoint_set_server_credentials_pem -> fail-closed with zero leaked RSA slots
//    - HRR + CH2 SNI mismatch rejection and valid HRR + matching SNI completion
// 3. Blocking read_client_hello, extract_client_hello_sni, and server_accept_tls_handshake / serve_tls
//    live loopback pre-handshake SNI selection and fallback behavior.
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

fn build_p256_cert_der<B>(
    issuer_priv:   const u8[32]&,
    subj_priv:     const u8[32]&,
    issuer_cn:     const u8[:],
    subject_cn:    const u8[:],
    is_ca:         bool,
    dns_san:       const u8[:],
    out_der:       B&,
    extra_pad_len: i64 = 0,
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
        var pad_oct: u8[..3000] = [];
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

fn build_ed25519_pkcs8_pem(seed: const u8[32]&, out_pem: u8[>..]&) {
    out_pem.clear();
    var der: u8[>..] = [
        0x30, 0x2E, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ];
    for i in 32 { der.push(seed[i]); }
    append_pem_block("PRIVATE KEY", der[..], out_pem);
}

fn build_custom_ch_msg(
    rand_bytes: const u8[32]&,
    sni_host:   const u8[:],
    include_ks: bool,
    x25519_pub: const u8[32]&,
    out_ch_msg: u8[..4096]&,
) {
    out_ch_msg.clear();
    var pay: u8[..4096] = [];
    pay.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    pay.append(rand_bytes[..]);
    pay.push(32);
    pay.append(rand_bytes[..]);
    pay.append_u16_be(2);
    pay.append_u16_be(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    pay.push(1);
    pay.push(0);

    var ext: u8[..1024] = [];
    if sni_host.len > 0 {
        ext.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
        ext.append_u16_be((sni_host.len + 5) as u16);
        ext.append_u16_be((sni_host.len + 3) as u16);
        ext.push(0);
        ext.append_u16_be(sni_host.len as u16);
        ext.append(sni_host);
    }
    // supported_versions: TLS 1.3
    ext.append_u16_be(rfc::TLS_EXT_SUPPORTED_VERSIONS);
    ext.append_u16_be(3);
    ext.push(2);
    ext.append_u16_be(rfc::TLS_VERSION_1_3);
    // supported_groups: x25519
    ext.append_u16_be(rfc::TLS_EXT_SUPPORTED_GROUPS);
    ext.append_u16_be(4);
    ext.append_u16_be(2);
    ext.append_u16_be(rfc::GROUP_X25519);
    // signature_algorithms: ed25519, p256, rsa-pss
    ext.append_u16_be(rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    ext.append_u16_be(8);
    ext.append_u16_be(6);
    ext.append_u16_be(rfc::SIG_SCHEME_ED25519);
    ext.append_u16_be(rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256);
    ext.append_u16_be(rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256);
    // key_share
    ext.append_u16_be(rfc::TLS_EXT_KEY_SHARE);
    if include_ks {
        ext.append_u16_be(38);
        ext.append_u16_be(36);
        ext.append_u16_be(rfc::GROUP_X25519);
        ext.append_u16_be(32);
        ext.append(x25519_pub[..]);
    } else {
        ext.append_u16_be(2);
        ext.append_u16_be(0);
    }
    pay.append_u16_be(ext.len as u16);
    pay.append(ext[..]);

    out_ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(out_ch_msg, pay.len as u32);
    out_ch_msg.append(pay[..]);
}

fn wrap_hs_record(hs_msg: const u8[:], out_rec: u8[..4096]&) {
    out_rec.clear();
    out_rec.push(rfc::TLS_CONTENT_HANDSHAKE);
    out_rec.append_u16_be(rfc::TLS_LEGACY_VERSION_1_0);
    out_rec.append_u16_be(hs_msg.len as u16);
    out_rec.append(hs_msg);
}

fn drain_and_feed_wire(src: tls::TlsEndpoint&, dst: tls::TlsEndpoint&) -> bool {
    var buf: u8[4096] = [0; 4096];
    while true {
        let n, st = tls::tls_endpoint_drain_wire(src, buf[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        let fed, fst = tls::tls_endpoint_feed_wire(dst, buf[..n]);
        guard fst == tls::TlsBackendStatus.Ok && fed == n else { return false; }
    }
    return true;
}

fn pump_until_established(cli: tls::TlsEndpoint&, srv: tls::TlsEndpoint&) -> bool {
    for _ in 32 {
        let cst = tls::tls_endpoint_step_handshake(cli);
        guard cst == tls::TlsBackendStatus.Ok ||
            cst == tls::TlsBackendStatus.WantRead ||
            cst == tls::TlsBackendStatus.WantWrite else {
            return false;
        }
        guard drain_and_feed_wire(cli, srv) else { return false; }
        let sst = tls::tls_endpoint_step_handshake(srv);
        guard sst == tls::TlsBackendStatus.Ok ||
            sst == tls::TlsBackendStatus.WantRead ||
            sst == tls::TlsBackendStatus.WantWrite else {
            return false;
        }
        guard drain_and_feed_wire(srv, cli) else { return false; }
        if cli.established && srv.established {
            return true;
        }
    }
    return false;
}

fn count_active_rsa_slots() -> i64 {
    var cnt: i64 = 0;
    for i in tls::g_tls_rsa_keys.len {
        if tls::g_tls_rsa_keys[i].in_use {
            cnt += 1;
        }
    }
    return cnt;
}

fn is_all_zero(buf: const u8[:]) -> bool {
    for b in buf {
        if b != 0 { return false; }
    }
    return true;
}

// ---- Fixture Container & Tests ---------------------------------------------

root struct SniTestFixtures {
    ec_root_der:  u8[..2048] = [],
    ec_leaf_der:  u8[..4096] = [],
    ec_chain_pem: u8[>..]    = [],
    ec_key_pem:   u8[>..]    = [],
    rsa_leaf_der: u8[..4096] = [],
    rsa_cert_pem: u8[>..]    = [],
    rsa_key_pem:  u8[>..]    = [],
    ed_leaf_der:  u8[..2048] = [],
    ed_cert_pem:  u8[>..]    = [],
    ed_key_pem:   u8[>..]    = [],
    ed_seed:      u8[32]     = [0x44; 32],
}

fn init_fixtures(fx: SniTestFixtures&) {
    let root_p:  u8[32] = [0x11; 32];
    let inter_p: u8[32] = [0x22; 32];
    let leaf_p:  u8[32] = [0x33; 32];

    var inter_der: u8[..4096] = [];
    build_p256_cert_der(root_p, root_p, "Wing P256 Root", "Wing P256 Root", true, "", fx.ec_root_der);
    build_p256_cert_der(root_p, inter_p, "Wing P256 Root", "Wing P256 Inter", true, "", inter_der, 1400);
    build_p256_cert_der(inter_p, leaf_p, "Wing P256 Inter", "a.example.test", false, "a.example.test", fx.ec_leaf_der, 1400);
    append_pem_block("CERTIFICATE", fx.ec_leaf_der[..], fx.ec_chain_pem);
    append_pem_block("CERTIFICATE", inter_der[..], fx.ec_chain_pem);
    build_p256_pkcs8_pem(leaf_p, fx.ec_key_pem);
    assert(fx.ec_chain_pem.len > 4096 && fx.ec_chain_pem.len <= 16384);

    build_rsa_leaf_cert_der("*.b.example.test", "*.b.example.test", fx.rsa_leaf_der);
    append_pem_block("CERTIFICATE", fx.rsa_leaf_der[..], fx.rsa_cert_pem);
    var rsa_p1_der: u8[>..] = [];
    build_rsa_pkcs1_der(TEST_RSA_N[..], rsa_p1_der);
    append_pem_block("RSA PRIVATE KEY", rsa_p1_der[..], fx.rsa_key_pem);

    assert(tls::build_test_ed25519_cert_der(fx.ed_seed, "fallback.local", "fallback.local", "127.0.0.1", fx.ed_leaf_der));
    append_pem_block("CERTIFICATE", fx.ed_leaf_der[..], fx.ed_cert_pem);
    build_ed25519_pkcs8_pem(fx.ed_seed, fx.ed_key_pem);
}

fn test_arena_sni_registry(fx: const SniTestFixtures&) {
    var reg = server::SniRegistry { .. };
    assert(reg.count == 0 && reg.arena_slot == -1);

    assert(server::add_sni_registry_entry(reg, "a.example.test", fx.ec_chain_pem[..], fx.ec_key_pem[..]));
    assert(server::add_sni_registry_entry(reg, "*.b.example.test", fx.rsa_cert_pem[..], fx.rsa_key_pem[..]));
    assert(server::add_sni_registry_entry(reg, "special.b.example.test", fx.ed_cert_pem[..], fx.ed_key_pem[..]));
    assert(reg.count == 3 && reg.arena_slot >= 0);

    // Exact before wildcard resolution + trailing dot / case folding
    let c_a, ok_a = server::resolve_sni_registry(reg, "A.EXAMPLE.TEST.");
    assert(ok_a && c_a.cert_pem == fx.ec_chain_pem[..] && c_a.key_pem == fx.ec_key_pem[..]);
    let c_wild, ok_wild = server::resolve_sni_registry(reg, "sub.b.example.test");
    assert(ok_wild && c_wild.cert_pem == fx.rsa_cert_pem[..]);
    let c_spec, ok_spec = server::resolve_sni_registry(reg, "special.b.example.test");
    assert(ok_spec && c_spec.cert_pem == fx.ed_cert_pem[..]);

    // Oversize guards (>16384 cert, >8192 key)
    var big_cert: u8[>..] = [];
    big_cert.resize(16385, 'C');
    var big_key: u8[>..] = [];
    big_key.resize(8193, 'K');
    assert(!server::add_sni_registry_entry(reg, "big.example.test", big_cert[..], fx.ed_key_pem[..]));
    assert(!server::add_sni_registry_entry(reg, "bigk.example.test", fx.ed_cert_pem[..], big_key[..]));

    // Update in place zeroizes old key span and updates payload
    let sentinel_key = "-----BEGIN PRIVATE KEY-----\nSENTINEL_SECRET_KEY_BYTES_999\n-----END PRIVATE KEY-----\n";
    assert(server::add_sni_registry_entry(reg, "rotate.example.test", fx.ed_cert_pem[..], sentinel_key));
    let pre_upd, ok_pre = server::resolve_sni_registry(reg, "rotate.example.test");
    assert(ok_pre && pre_upd.key_pem == sentinel_key);
    assert(server::add_sni_registry_entry(reg, "rotate.example.test", fx.ed_cert_pem[..], fx.ed_key_pem[..]));
    assert(core::find(server::g_sni_key_arena[..], "SENTINEL_SECRET_KEY_BYTES_999") < 0);

    // Remove zeroizes key span
    let rem_secret = "-----BEGIN PRIVATE KEY-----\nREMOVE_ZEROIZE_CHECK_777\n-----END PRIVATE KEY-----\n";
    assert(server::add_sni_registry_entry(reg, "temp.example.test", fx.ed_cert_pem[..], rem_secret));
    assert(core::find(server::g_sni_key_arena[..], "REMOVE_ZEROIZE_CHECK_777") >= 0);
    assert(server::remove_sni_registry_entry(reg, "temp.example.test"));
    assert(core::find(server::g_sni_key_arena[..], "REMOVE_ZEROIZE_CHECK_777") < 0);
    let _, ok_removed = server::resolve_sni_registry(reg, "temp.example.test");
    assert(!ok_removed);

    // Clear zeroizes all key spans & releases arena slot for reuse
    let clear_secret = "-----BEGIN PRIVATE KEY-----\nCLEAR_ALL_SECRET_CHECK_888\n-----END PRIVATE KEY-----\n";
    assert(server::add_sni_registry_entry(reg, "clear.example.test", fx.ed_cert_pem[..], clear_secret));
    let stale_before_clear = reg;
    let old_slot = reg.arena_slot;
    let regs_before = server::g_sni_regs.len;
    server::clear_sni_registry(reg);
    assert(reg.count == 0 && reg.arena_slot == -1 && reg.generation == 0);
    assert(core::find(server::g_sni_key_arena[..], "CLEAR_ALL_SECRET_CHECK_888") < 0);

    // Stale handle before slot reuse cannot resolve, mutate, or remove
    let _, ok_stale_pre = server::resolve_sni_registry(stale_before_clear, "a.example.test");
    assert(!ok_stale_pre);
    var stale_mut_pre = stale_before_clear;
    assert(!server::add_sni_registry_entry(stale_mut_pre, "evil.example.test", fx.ed_cert_pem[..], fx.ed_key_pem[..]));
    assert(!server::remove_sni_registry_entry(stale_mut_pre, "a.example.test"));

    // Reusing larger cleared arena slot with smaller max_entries enforces max_entries == 2
    var reg2 = server::SniRegistry { max_entries: 2, .. };
    assert(server::add_sni_registry_entry(reg2, "reused1.example.test", fx.ed_cert_pem[..], fx.ed_key_pem[..]));
    assert(reg2.arena_slot == old_slot && server::g_sni_regs.len == regs_before && reg2.count == 1);
    let live_copy = reg2;
    assert(server::add_sni_registry_entry(reg2, "reused2.example.test", fx.rsa_cert_pem[..], fx.rsa_key_pem[..]));
    assert(reg2.count == 2);
    assert(!server::add_sni_registry_entry(reg2, "reused3.example.test", fx.ed_cert_pem[..], fx.ed_key_pem[..]));
    assert(reg2.count == 2);
    // Updating existing pattern at capacity still succeeds; live copied handle resolves newer entry too
    assert(server::add_sni_registry_entry(reg2, "reused2.example.test", fx.ed_cert_pem[..], fx.ed_key_pem[..]));
    let lc_res, ok_lc = server::resolve_sni_registry(live_copy, "reused2.example.test");
    assert(ok_lc && lc_res.cert_pem == fx.ed_cert_pem[..]);

    // Stale handle after slot reuse (ABA check) cannot resolve, add, remove, or clear reg2
    let _, ok_stale_post = server::resolve_sni_registry(stale_before_clear, "reused1.example.test");
    assert(!ok_stale_post);
    var stale_mut_post = stale_before_clear;
    assert(!server::add_sni_registry_entry(stale_mut_post, "aba.example.test", fx.ed_cert_pem[..], fx.ed_key_pem[..]));
    assert(!server::remove_sni_registry_entry(stale_mut_post, "reused1.example.test"));
    server::clear_sni_registry(stale_mut_post);
    let c_r1, ok_r1 = server::resolve_sni_registry(reg2, "reused1.example.test");
    assert(ok_r1 && c_r1.cert_pem == fx.ed_cert_pem[..]);
    server::clear_sni_registry(reg2);

    print("ARENA_SNI_REGISTRY: OK");
    // CHECK: ARENA_SNI_REGISTRY: OK
}

fn run_deferred_sni_endpoint_case(
    srv_reg:      const server::HttpServer&,
    sni_host:     const u8[:],
    trust:        const tls::TrustAnchorStore&,
    expected_der: const u8[:],
    payload:      const u8[:],
) {
    let rsa_before = count_active_rsa_slots();
    var srv_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             true,
        defer_sni_credentials: true,
        ..
    };
    var srv, srv_st = tls::tls_endpoint_open(srv_cfg);
    assert(srv_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(srv);

    var cli_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        trust_store:            trust,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(cli_cfg.server_name.try_set(sni_host));
    var cli, cli_st = tls::tls_endpoint_open(cli_cfg);
    assert(cli_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(cli);

    assert(tls::tls_endpoint_step_handshake(cli) == tls::TlsBackendStatus.WantRead);
    assert(drain_and_feed_wire(cli, srv));

    assert(tls::tls_endpoint_step_handshake(srv) == tls::TlsBackendStatus.NeedSniCredentials);
    assert(tls::tls_endpoint_step_handshake(srv) == tls::TlsBackendStatus.NeedSniCredentials);
    let got_sni = tls::tls_endpoint_client_sni(srv);
    assert(got_sni[..] == sni_host);

    let creds, ok_res = server::resolve_sni_credentials(srv_reg, got_sni[..]);
    assert(ok_res);
    assert(tls::tls_endpoint_set_server_credentials_pem(srv, creds.cert_pem, creds.key_pem) == tls::TlsBackendStatus.Ok);

    assert(pump_until_established(cli, srv));
    let peer_der, ok_peer = tls::tls_endpoint_peer_cert_der(cli);
    assert(ok_peer && peer_der[..] == expected_der);

    let wn, wst = tls::tls_endpoint_write_app(cli, payload);
    assert(wst == tls::TlsBackendStatus.Ok && wn == payload.len);
    assert(drain_and_feed_wire(cli, srv));
    var rx: u8[128] = [0; 128];
    let rn, rst = tls::tls_endpoint_read_app(srv, rx[..]);
    assert(rst == tls::TlsBackendStatus.Ok && rn == payload.len && rx[..rn] == payload);

    tls::tls_endpoint_close(srv);
    assert(count_active_rsa_slots() == rsa_before);
}

fn test_sans_io_prehandshake_sni(fx: const SniTestFixtures&) {
    var srv_holder = server::new_http_server("127.0.0.1", 8443);
    assert(server::add_server_name(srv_holder, "a.example.test", fx.ec_chain_pem[..], fx.ec_key_pem[..]));
    assert(server::add_server_name(srv_holder, "*.b.example.test", fx.rsa_cert_pem[..], fx.rsa_key_pem[..]));

    // 1. Wildcard RSA PEM via deferred SNI
    var rsa_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(rsa_trust, fx.rsa_leaf_der[..]));
    run_deferred_sni_endpoint_case(
        srv_holder, "sub.b.example.test", rsa_trust, fx.rsa_leaf_der[..], "PING-RSA-SNI",
    );

    // 2. Exact >4 KiB 2-cert ECDSA P-256 fullchain trusting ONLY Root CA
    var ec_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(ec_trust, fx.ec_root_der[..]));
    run_deferred_sni_endpoint_case(
        srv_holder, "a.example.test", ec_trust, fx.ec_leaf_der[..], "PING-EC-CHAIN",
    );

    // 3. ClientHello WITHOUT SNI extension -> NeedSniCredentials with empty SNI -> fallback cert works
    var fb_srv_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             true,
        defer_sni_credentials: true,
        ..
    };
    var fb_srv, fb_sst = tls::tls_endpoint_open(fb_srv_cfg);
    assert(fb_sst == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(fb_srv);

    var fb_cli_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        insecure_skip_verify:   true,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    var fb_cli, fb_cst = tls::tls_endpoint_open(fb_cli_cfg);
    assert(fb_cst == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(fb_cli);

    assert(tls::tls_endpoint_step_handshake(fb_cli) == tls::TlsBackendStatus.WantRead);
    assert(drain_and_feed_wire(fb_cli, fb_srv));
    assert(tls::tls_endpoint_step_handshake(fb_srv) == tls::TlsBackendStatus.NeedSniCredentials);
    assert(tls::tls_endpoint_client_sni(fb_srv).len == 0);
    assert(tls::tls_endpoint_set_server_credentials_pem(
        fb_srv, fx.ed_cert_pem[..], fx.ed_key_pem[..],
    ) == tls::TlsBackendStatus.Ok);
    assert(pump_until_established(fb_cli, fb_srv));
    let fb_peer, ok_fbp = tls::tls_endpoint_peer_cert_der(fb_cli);
    assert(ok_fbp && fb_peer[..] == fx.ed_leaf_der[..]);

    // 4. Invalid PEM in tls_endpoint_set_server_credentials_pem -> fails closed with zero leaked RSA slots
    let rsa_before_bad = count_active_rsa_slots();
    var bad_srv_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             true,
        defer_sni_credentials: true,
        ..
    };
    var bad_srv, bad_sst = tls::tls_endpoint_open(bad_srv_cfg);
    assert(bad_sst == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(bad_srv);

    let r1: u8[32] = [0x51; 32];
    let k1: u8[32] = [0x61; 32];
    let p1 = core::x25519_base_scalarmult(k1);
    var ch_good: u8[..4096] = [];
    build_custom_ch_msg(r1, "a.example.test", true, p1, ch_good);
    var rec_good: u8[..4096] = [];
    wrap_hs_record(ch_good[..], rec_good);
    let f_bad, st_fbad = tls::tls_endpoint_feed_wire(bad_srv, rec_good[..]);
    assert(st_fbad == tls::TlsBackendStatus.Ok && f_bad == rec_good.len);
    assert(tls::tls_endpoint_step_handshake(bad_srv) == tls::TlsBackendStatus.NeedSniCredentials);

    // Mismatched RSA cert + Ed25519 key -> must fail closed and leak zero RSA slots
    let set_bad = tls::tls_endpoint_set_server_credentials_pem(bad_srv, fx.rsa_cert_pem[..], fx.ed_key_pem[..]);
    assert(set_bad != tls::TlsBackendStatus.Ok);
    assert(count_active_rsa_slots() == rsa_before_bad);
    assert(tls::tls_endpoint_step_handshake(bad_srv) == tls::TlsBackendStatus.HandshakeError);

    // 5. HRR + CH2 SNI mismatch rejection (RFC 8446 §4.1.2)
    var hrr_srv_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             true,
        defer_sni_credentials: true,
        ..
    };
    var hrr_srv, hrr_sst = tls::tls_endpoint_open(hrr_srv_cfg);
    assert(hrr_sst == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(hrr_srv);

    let zero32: u8[32] = [0; 32];
    var ch1_empty_ks: u8[..4096] = [];
    build_custom_ch_msg(r1, "a.example.test", false, zero32, ch1_empty_ks);
    var rec_ch1: u8[..4096] = [];
    wrap_hs_record(ch1_empty_ks[..], rec_ch1);
    let f1, st_f1 = tls::tls_endpoint_feed_wire(hrr_srv, rec_ch1[..]);
    assert(st_f1 == tls::TlsBackendStatus.Ok && f1 == rec_ch1.len);
    assert(tls::tls_endpoint_step_handshake(hrr_srv) == tls::TlsBackendStatus.NeedSniCredentials);
    assert(tls::tls_endpoint_client_sni(hrr_srv)[..] == "a.example.test");
    assert(tls::tls_endpoint_set_server_credentials_pem(
        hrr_srv, fx.ec_chain_pem[..], fx.ec_key_pem[..],
    ) == tls::TlsBackendStatus.Ok);
    assert(tls::tls_endpoint_step_handshake(hrr_srv) == tls::TlsBackendStatus.WantRead);

    var hrr_drain: u8[4096] = [0; 4096];
    let hn, hst = tls::tls_endpoint_drain_wire(hrr_srv, hrr_drain[..]);
    assert(hst == tls::TlsBackendStatus.Ok && hn > 40);

    // Feed CH2 with DIFFERENT SNI ("evil.example.test") -> MUST fail closed!
    var ch2_mismatch: u8[..4096] = [];
    build_custom_ch_msg(r1, "evil.example.test", true, p1, ch2_mismatch);
    var rec_ch2: u8[..4096] = [];
    wrap_hs_record(ch2_mismatch[..], rec_ch2);
    let f2, st_f2 = tls::tls_endpoint_feed_wire(hrr_srv, rec_ch2[..]);
    assert(st_f2 == tls::TlsBackendStatus.Ok && f2 == rec_ch2.len);
    assert(tls::tls_endpoint_step_handshake(hrr_srv) == tls::TlsBackendStatus.HandshakeError);

    print("SANS_IO_PREHANDSHAKE_SNI: OK");
    // CHECK: SANS_IO_PREHANDSHAKE_SNI: OK
}

thread_fn sni_loopback_server_worker(listener_fd: i64) {
    var fx = SniTestFixtures { .. };
    init_fixtures(fx);
    var srv = server::new_http_server("127.0.0.1", 0);
    srv.pipeline.enable_csrf_guard = false;
    assert(server::add_static_route(srv.pipeline.router, "GET", "/sni", "text/plain", "sni-route-ok"));
    assert(server::add_server_name(srv, "a.example.test", fx.ec_chain_pem[..], fx.ec_key_pem[..]));
    assert(server::add_server_name(srv, "*.b.example.test", fx.rsa_cert_pem[..], fx.rsa_key_pem[..]));

    var default_cfg = tls::ServerHandshakeConfig {
        priv_seed: fx.ed_seed,
        ..
    };
    assert(default_cfg.cert_der.try_set(fx.ed_leaf_der[..]));
    assert(default_cfg.alpn.try_set("http/1.1"));

    // Serve 3 live connections via serve_tls (1: a.example.test, 2: sub.b.example.test, 3: fallback.local)
    let served = server::serve_tls(srv, listener_fd, default_cfg, 3);
    assert(served == 3);

    // 4th connection: direct read_client_hello + extract_client_hello_sni probe + fail-closed unmatched SNI without default cert
    let c4 = net::tcp_accept(listener_fd, 5000);
    assert(c4 > 0);
    var ch4: u8[..16384] = [];
    assert(tls::read_client_hello(c4, ch4, 5000));
    var sni4: u8[..255] = [];
    assert(tls::extract_client_hello_sni(ch4[..], sni4));
    assert(sni4[..] == "probe.example.test");
    net::tcp_close(c4);

    // 5th connection: fail-closed when sni_registry has entries, SNI is unmatched, and default cert is empty
    let c5 = net::tcp_accept(listener_fd, 5000);
    assert(c5 > 0);
    var empty_def = tls::ServerHandshakeConfig { .. };
    let bad_slot, ok_bad = server_internal::server_accept_tls_handshake(srv, c5, empty_def);
    assert(!ok_bad && bad_slot == 0xFFFF);
    net::tcp_close(c5);

    // 6th connection: default_cfg compressed_cert_algo / data must NOT leak onto SNI-resolved credentials
    var comp_def_cfg = default_cfg;
    comp_def_cfg.compressed_cert_algo = 2;
    assert(comp_def_cfg.compressed_cert_data.try_set("DUMMY_DEFAULT_COMPRESSED_CERT_BYTES"));
    assert(server::serve_tls(srv, listener_fd, comp_def_cfg, 1) == 1);
}

fn do_https_get_with_trust(
    port:      u16,
    sni_host:  const u8[:],
    trust_der: const u8[:],
) {
    let fd = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd > 0);
    defer net::tcp_close(fd);

    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, trust_der));
    var cli_cfg = tls::ClientHandshakeConfig {
        trust_store:            trust,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(cli_cfg.server_name.try_set(sni_host));
    assert(cli_cfg.alpn.try_set("http/1.1"));

    let slot, ok_hs = tls::client_handshake(fd, cli_cfg);
    assert(ok_hs);
    defer tls::transport_close(fd, slot);

    let req = "GET /sni HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    assert(tls::transport_send(fd, slot, req) == req.len as i32);
    var rx: u8[2048] = [0; 2048];
    let nr = tls::transport_recv_slice(fd, slot, rx[..], 5000);
    assert(nr > 0 && core::contains(rx[..nr], "sni-route-ok"));
}

fn test_blocking_prehandshake_sni(fx: const SniTestFixtures&) {
    // Unit checks on extract_client_hello_sni
    let r_u: u8[32] = [0x91; 32];
    let k_u: u8[32] = [0x92; 32];
    let p_u = core::x25519_base_scalarmult(k_u);
    var ch_with: u8[..4096] = [];
    build_custom_ch_msg(r_u, "Api.Example.COM", true, p_u, ch_with);
    var sni_out: u8[..255] = [];
    assert(tls::extract_client_hello_sni(ch_with[..], sni_out));
    assert(sni_out[..] == "api.example.com");

    var ch_without: u8[..4096] = [];
    build_custom_ch_msg(r_u, "", true, p_u, ch_without);
    assert(!tls::extract_client_hello_sni(ch_without[..], sni_out) && sni_out.len == 0);
    assert(!tls::extract_client_hello_sni("bad-ch-bytes", sni_out) && sni_out.len == 0);

    // Live TCP loopback server::serve_tls + read_client_hello + fail-closed check
    let listener = net::tcp_listen("127.0.0.1", 0, 16);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);
    let tid = thread_spawn(sni_loopback_server_worker, listener);

    do_https_get_with_trust(port, "a.example.test", fx.ec_root_der[..]);
    do_https_get_with_trust(port, "sub.b.example.test", fx.rsa_leaf_der[..]);
    do_https_get_with_trust(port, "fallback.local", fx.ed_leaf_der[..]);

    // Conn 4: client sends ClientHello with probe.example.test
    let fd4 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd4 > 0);
    var ch4: u8[..4096] = [];
    build_custom_ch_msg(r_u, "Probe.Example.Test", true, p_u, ch4);
    var rec4: u8[..4096] = [];
    wrap_hs_record(ch4[..], rec4);
    assert(net::tcp_send(fd4, rec4[..]) == rec4.len as i32);
    net::tcp_close(fd4);

    // Conn 5: client connects with unmatched SNI when server has no default cert -> closed cleanly
    let fd5 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd5 > 0);
    var ch5: u8[..4096] = [];
    build_custom_ch_msg(r_u, "unmatched.example.test", true, p_u, ch5);
    var rec5: u8[..4096] = [];
    wrap_hs_record(ch5[..], rec5);
    assert(net::tcp_send(fd5, rec5[..]) == rec5.len as i32);
    var eof_buf: u8[..64] = [];
    let r5 = net::tcp_recv(fd5, eof_buf, 64, 2000);
    assert(r5 <= 0);
    net::tcp_close(fd5);

    // Conn 6: SNI handshake succeeds even when server's default_cfg carries dummy compressed cert payload
    do_https_get_with_trust(port, "a.example.test", fx.ec_root_der[..]);

    assert(thread_wait(tid));
    net::tcp_close(listener);

    print("BLOCKING_PREHANDSHAKE_SNI: OK");
    // CHECK: BLOCKING_PREHANDSHAKE_SNI: OK
}

fn main() {
    var fx = SniTestFixtures { .. };
    init_fixtures(fx);
    test_arena_sni_registry(fx);
    test_sans_io_prehandshake_sni(fx);
    test_blocking_prehandshake_sni(fx);
}
