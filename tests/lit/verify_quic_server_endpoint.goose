// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of Sans-IO Multi-Client QuicServerEndpoint:
// 1. Two concurrent QUIC clients over one dual-stack UDP loopback socket (IPv4 + IPv6)
//    demuxed by DCID with deferred SNI ("a.example.test" ECDSA 2-cert fullchain,
//    "b.example.test" RSA-2048 PEM).
// 2. Encrypted Initial -> Handshake -> 1-RTT (HANDSHAKE_DONE + NEW_CONNECTION_ID),
//    64 KiB bidirectional stream payload exchange with MAX_DATA / MAX_STREAM_DATA
//    flow control, simulated packet drop triggering PTO retransmission, and clean
//    idle timeout / CONNECTION_CLOSE teardown.
// 3. RFC 9000 Section 14.1 undersized Initial (< 1200 bytes) rejection and
//    RFC 9000 Section 8.1 3x anti-amplification budget enforcement.
// 4. Thread-local safety inside `thread_fn` and zero leaked RSA slots.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// ---- Test Certificate & Key Builders ---------------------------------------

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

fn build_rsa_pkcs8_pem(out_pem: u8[>..]&) {
    out_pem.clear();
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
    var der: u8[>..] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, pki_body[..], der);
    append_pem_block("PRIVATE KEY", der[..], out_pem);
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

fn count_active_rsa_slots() -> i64 {
    var count: i64 = 0;
    for i in tls::g_tls_rsa_keys.len {
        if tls::g_tls_rsa_keys[i].in_use { count += 1; }
    }
    return count;
}

// ---- Test QUIC Client Harness ----------------------------------------------

struct TestQuicClient {
    fd:                    i64                       = -1,
    dst_ip:                u8[..64]                  = [],
    dst_port:              u16                       = 0,
    conn:                  quic::QuicConnection      = quic::QuicConnection { .. },
    tls_cli:               tls::QuicTlsClient        = tls::QuicTlsClient { .. },
    next_init_pn:          u64                       = 0,
    next_hs_pn:            u64                       = 0,
    next_app_pn:           u64                       = 0,
    init_crypto_sent:      u64                       = 0,
    hs_crypto_sent:        u64                       = 0,
    init_ack_needed:       bool                      = false,
    hs_ack_needed:         bool                      = false,
    app_ack_needed:        bool                      = false,
    handshake_done_seen:   bool                      = false,
    new_cid_seen:          bool                      = false,
    alt_srv_cid:           u8[..20]                  = [],
    peer_tp_parsed:        bool                      = false,
    peer_tp:               quic::QuicTransportParams = quic::QuicTransportParams { .. },
    saw_max_data:          bool                      = false,
    saw_max_stream_data:   bool                      = false,
    last_max_data:         u64                       = 0,
    last_max_stream_data:  u64                       = 0,
    saw_conn_close_tpt:    bool                      = false,
    saw_reset_stream:      bool                      = false,
    reset_stream_count:    i64                       = 0,
    last_reset_sid:        u64                       = 0,
    last_reset_err:        u64                       = 0,
    last_reset_final_size: u64                       = 0,
    stream_rx_fin:         bool                      = false,
    stream_rx_base:        u64                       = 0,
    stream_rx_contig:      u64                       = 0,
    stream_rx_final:       u64                       = 0,
    has_uni3_rx:           bool                      = false,
    uni3_buf:              u8[..2048]                = [],
    stream_rx_intervals:   quic::Interval[..64]      = [],
    stream_rx_buf:         u8[>..]                   = [],
}

fn init_test_client(
    c:             TestQuicClient&,
    bind_ip:       const u8[:],
    dst_ip:        const u8[:],
    dst_port:      u16,
    sni:           const u8[:],
    trust_pem:     const u8[:],
    odcid:         const u8[:],
    scid:          const u8[:],
    init_max_data: u64 = 32768,
    init_max_sd:   u64 = 16384,
) {
    c.fd = net::udp_open_dual(bind_ip, 0, 0);
    assert(c.fd > 0);
    assert(c.dst_ip.try_set(dst_ip));
    c.dst_port = dst_port;
    c.conn = quic::new_client_connection(odcid, scid);
    assert(quic::install_initial_keys(c.conn, odcid));

    var tp = quic::QuicTransportParams {
        max_idle_timeout:                    30000,
        max_udp_payload_size:                1500,
        initial_max_data:                    init_max_data,
        initial_max_stream_data_bidi_local:  init_max_sd,
        initial_max_stream_data_bidi_remote: init_max_sd,
        initial_max_stream_data_uni:         init_max_sd,
        initial_max_streams_bidi:            16,
        initial_max_streams_uni:             16,
        active_connection_id_limit:          4,
        ..
    };
    assert(tp.initial_source_connection_id.try_set(scid));
    var tp_wire: u8[..256] = [];
    assert(quic::encode_transport_params(tp, false, tp_wire));

    c.tls_cli = tls::quic_tls_client_open(sni, "\x02h3", tp_wire[..], trust_pem);
    assert(tls::quic_tls_client_start(c.tls_cli) == tls::QuicTlsStatus.Ok);
}

fn close_test_client(c: TestQuicClient&) {
    tls::quic_tls_client_close(c.tls_cli);
    if c.fd > 0 { net::tcp_close(c.fd); c.fd = -1; }
}

fn client_send_initial_flight(c: TestQuicClient&, now_us: u64, pad_to_min: bool) {
    var ch: u8[>..] = [];
    let n = tls::quic_tls_client_drain_crypto(c.tls_cli, tls::QuicTlsLevel.Initial, ch);
    guard n > 0 else { return; }

    var plain: u8[..1300] = [];
    assert(quic::encode_crypto_frame(c.init_crypto_sent, ch[..], plain));
    c.init_crypto_sent += n as u64;
    if pad_to_min {
        let min_plain = 1200 - (7 + c.conn.dcid.len + c.conn.scid.len + 1 + 2 + 2 + 16);
        if plain.len < min_plain {
            assert(quic::encode_padding_frame(plain, (min_plain - plain.len) as u64));
        }
    }
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.Initial,
        version:       rfc::QUIC_VERSION_1,
        packet_number: c.next_init_pn,
        ..
    };
    assert(hdr.dcid.try_set(c.conn.dcid[..]));
    assert(hdr.scid.try_set(c.conn.scid[..]));
    var pkt: u8[..1500] = [];
    assert(quic::seal_packet_tracked(c.conn.tx_initial_space, hdr, 2, plain[..], pkt));
    quic::record_sent(c.conn, quic::PnSpaceId.Initial, c.next_init_pn, pkt.len as u64, true, now_us);
    c.next_init_pn += 1;
    assert(net::udp_sendto_dual(c.fd, pkt[..], c.dst_ip[..], c.dst_port) == (pkt.len as i32));
}

fn client_install_pending_secrets(c: TestQuicClient&) {
    var sec = tls::QuicTlsSecrets { .. };
    while tls::quic_tls_client_take_secrets(c.tls_cli, sec) {
        if sec.has_read {
            assert(quic::install_tls_secret(c.conn, sec.level, true, sec.read_secret[..], sec.cipher_suite));
        }
        if sec.has_write {
            assert(quic::install_tls_secret(c.conn, sec.level, false, sec.write_secret[..], sec.cipher_suite));
        }
    }
}

fn client_record_rx_stream_bytes(c: TestQuicClient&, offset: u64, data: const u8[:], fin: bool) {
    let end_off = offset + (data.len as u64);
    if data.len > 0 && end_off > c.stream_rx_base {
        let needed = (end_off - c.stream_rx_base) as i64;
        if c.stream_rx_buf.len < needed { c.stream_rx_buf.resize(needed, 0); }
        let start_off = max(offset, c.stream_rx_base);
        let skip = (start_off - offset) as i64;
        let dst_off = (start_off - c.stream_rx_base) as i64;
        for i in (data.len - skip) {
            c.stream_rx_buf[dst_off + i] = data[skip + i];
        }
        var cur_s = start_off;
        var cur_e = end_off;
        var idx: i64 = 0;
        while idx < c.stream_rx_intervals.len {
            let it = c.stream_rx_intervals[idx];
            if cur_e < it.start {
                c.stream_rx_intervals.insert_at(idx, quic::Interval { start: cur_s, end: cur_e });
                break;
            }
            if cur_s > it.end { idx += 1; continue; }
            cur_s = min(cur_s, it.start);
            cur_e = max(cur_e, it.end);
            c.stream_rx_intervals.remove_at(idx);
        }
        if idx == c.stream_rx_intervals.len {
            let _ = c.stream_rx_intervals.try_push(quic::Interval { start: cur_s, end: cur_e });
        }
        if c.stream_rx_intervals.len > 0 && c.stream_rx_intervals[0].start == c.stream_rx_base {
            c.stream_rx_contig = c.stream_rx_intervals[0].end;
        }
    }
    if fin {
        c.stream_rx_fin = true;
        c.stream_rx_final = end_off;
    }
}

fn client_inspect_plain_frames(c: TestQuicClient&, plain: const u8[:]) {
    var idx: i64 = 0;
    while idx < plain.len {
        let f, ok = quic::decode_frame_cursor(plain, idx);
        if !ok { break; }
        if f.frame_type == quic::QuicFrameType.HandshakeDone {
            c.handshake_done_seen = true;
        } else if f.frame_type == quic::QuicFrameType.NewConnectionId {
            c.new_cid_seen = true;
            let clen = f.length as i64;
            if clen > 0 && clen <= f.payload.len {
                let _ = c.alt_srv_cid.try_set(f.payload[..clen]);
            }
        } else if f.frame_type == quic::QuicFrameType.MaxData {
            c.saw_max_data = true;
            c.last_max_data = f.max_data;
        } else if f.frame_type == quic::QuicFrameType.MaxStreamData {
            c.saw_max_stream_data = true;
            c.last_max_stream_data = f.max_data;
        } else if f.frame_type == quic::QuicFrameType.Stream && f.stream_id == 0 {
            client_record_rx_stream_bytes(c, f.offset, f.payload, f.fin);
        } else if f.frame_type == quic::QuicFrameType.Stream && f.stream_id == 3 {
            let _ = c.uni3_buf.try_append(f.payload);
            if f.fin { c.has_uni3_rx = true; }
        } else if f.frame_type == quic::QuicFrameType.ResetStream {
            c.saw_reset_stream = true;
            c.reset_stream_count += 1;
            c.last_reset_sid = f.stream_id;
            c.last_reset_err = f.error_code;
            c.last_reset_final_size = f.final_size;
        } else if f.frame_type == quic::QuicFrameType.ConnectionClose {
            c.saw_conn_close_tpt = true;
            c.conn.state = quic::QuicConnState.Draining;
            c.conn.close_code = f.error_code;
        } else if f.frame_type == quic::QuicFrameType.ConnectionCloseApp {
            c.conn.state = quic::QuicConnState.Draining;
            c.conn.close_code = f.error_code;
        }
    }
}

fn client_pump_tls(c: TestQuicClient&, htype: quic::QuicHeaderType) {
    if htype == quic::QuicHeaderType.Initial && c.conn.initial_crypto.buf.len > 0 {
        let st = tls::quic_tls_client_provide_crypto(c.tls_cli, tls::QuicTlsLevel.Initial, c.conn.initial_crypto.buf[..]);
        c.conn.initial_crypto.buf.clear();
        assert(st == tls::QuicTlsStatus.Ok);
        client_install_pending_secrets(c);
    }
    if htype == quic::QuicHeaderType.Handshake && c.conn.handshake_crypto.buf.len > 0 {
        let st = tls::quic_tls_client_provide_crypto(c.tls_cli, tls::QuicTlsLevel.Handshake, c.conn.handshake_crypto.buf[..]);
        c.conn.handshake_crypto.buf.clear();
        assert(st == tls::QuicTlsStatus.Ok || st == tls::QuicTlsStatus.WantMore || st == tls::QuicTlsStatus.Established);
        client_install_pending_secrets(c);
        if st == tls::QuicTlsStatus.Established && !c.peer_tp_parsed {
            let raw_tp = tls::quic_tls_client_peer_tp(c.tls_cli);
            let tp, ok_tp = quic::decode_transport_params(raw_tp, true);
            assert(ok_tp);
            assert(tp.original_destination_connection_id[..] == c.conn.original_dcid[..]);
            c.peer_tp = tp;
            c.peer_tp_parsed = true;
            c.conn.flow_ctrl.max_data_remote = tp.initial_max_data;
        }
    }
}

fn client_feed_dgram(c: TestQuicClient&, dgram: const u8[:], now_us: u64) {
    var offset: i64 = 0;
    while offset < dgram.len {
        var ack = quic::AckFrame { .. };
        var plain: u8[..16384] = [];
        var htype = quic::QuicHeaderType.Initial;
        let consumed, res = quic::process_coalesced_packet(c.conn, dgram[offset..], dgram.len, now_us, ack, plain, htype);
        if !res.handled || consumed <= 0 { break; }
        if htype == quic::QuicHeaderType.Initial {
            if res.needs_ack { c.init_ack_needed = true; }
            if c.conn.dcid.len > 0 && c.conn.dcid[..] != c.conn.original_dcid[..] {
                // Server SCID latched into c.conn.dcid by server Initial? Let's ensure c.conn.dcid latches server SCID.
            }
            // Extract server SCID from Initial header so subsequent Handshake/1-RTT packets use server SCID.
            let hdr, ok_h = quic_internal::parse_quic_long_header(
                dgram[offset..],
                dgram[offset],
                quic_internal::QuicHeaderOptions { is_masked: true, .. },
            );
            if ok_h && hdr.scid.len > 0 { let _ = c.conn.dcid.try_set(hdr.scid[..]); }
        } else if htype == quic::QuicHeaderType.Handshake {
            if res.needs_ack { c.hs_ack_needed = true; }
        } else if htype == quic::QuicHeaderType.OneRtt {
            if res.needs_ack { c.app_ack_needed = true; }
            client_inspect_plain_frames(c, plain[..]);
        }
        client_pump_tls(c, htype);
        offset += consumed;
    }
}

fn client_send_handshake_and_ack(c: TestQuicClient&, now_us: u64) {
    var hs_out: u8[>..] = [];
    let n_hs = tls::quic_tls_client_drain_crypto(c.tls_cli, tls::QuicTlsLevel.Handshake, hs_out);
    if n_hs > 0 || c.hs_ack_needed {
        var plain: u8[..512] = [];
        if c.hs_ack_needed && c.conn.handshake_space.recv_ranges.len > 0 {
            let ack, ok_a = quic::build_ack_frame(c.conn.handshake_space.recv_ranges, 0);
            if ok_a { assert(quic::encode_ack_frame(ack, plain)); }
            c.hs_ack_needed = false;
        }
        if n_hs > 0 {
            assert(quic::encode_crypto_frame(c.hs_crypto_sent, hs_out[..], plain));
            c.hs_crypto_sent += n_hs as u64;
        }
        while plain.len < 4 { assert(quic::encode_padding_frame(plain, 1)); }
        var hdr = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.Handshake,
            version:       rfc::QUIC_VERSION_1,
            packet_number: c.next_hs_pn,
            ..
        };
        assert(hdr.dcid.try_set(c.conn.dcid[..]));
        assert(hdr.scid.try_set(c.conn.scid[..]));
        var pkt: u8[..1500] = [];
        assert(quic::seal_packet_tracked(c.conn.tx_handshake_space, hdr, 2, plain[..], pkt));
        quic::record_sent(c.conn, quic::PnSpaceId.Handshake, c.next_hs_pn, pkt.len as u64, n_hs > 0, now_us);
        c.next_hs_pn += 1;
        assert(net::udp_sendto_dual(c.fd, pkt[..], c.dst_ip[..], c.dst_port) == (pkt.len as i32));
    }
}

fn client_send_1rtt_frames(c: TestQuicClient&, dcid: const u8[:], plain: const u8[:], ack_el: bool, now_us: u64) {
    var pbuf: u8[..1400] = [];
    assert(pbuf.try_append(plain));
    while pbuf.len < 4 { assert(quic::encode_padding_frame(pbuf, 1)); }
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.OneRtt,
        packet_number: c.next_app_pn,
        ..
    };
    assert(hdr.dcid.try_set(dcid));
    var pkt: u8[..1500] = [];
    assert(quic::seal_packet_tracked(c.conn.tx_app_space, hdr, 2, pbuf[..], pkt));
    quic::record_sent(c.conn, quic::PnSpaceId.ApplicationData, c.next_app_pn, pkt.len as u64, ack_el, now_us);
    c.next_app_pn += 1;
    assert(net::udp_sendto_dual(c.fd, pkt[..], c.dst_ip[..], c.dst_port) == (pkt.len as i32));
}

fn client_send_app_ack_and_fc(c: TestQuicClient&, dcid: const u8[:], extra_max_data: u64, extra_max_sd: u64, now_us: u64) {
    var plain: u8[..128] = [];
    var ack_el = false;
    if c.app_ack_needed && c.conn.app_space.recv_ranges.len > 0 {
        let ack, ok_a = quic::build_ack_frame(c.conn.app_space.recv_ranges, 0);
        if ok_a { assert(quic::encode_ack_frame(ack, plain)); }
        c.app_ack_needed = false;
    }
    if extra_max_data > 0 {
        if extra_max_data > c.conn.flow_ctrl.max_data_local {
            c.conn.flow_ctrl.max_data_local = extra_max_data;
        }
        assert(quic::encode_max_data_frame(extra_max_data, plain));
        ack_el = true;
    }
    if extra_max_sd > 0 {
        let sidx, ok_s = quic::find_stream(c.conn.stream_table, 0);
        if ok_s && extra_max_sd > c.conn.stream_table.streams[sidx].recv_max_data {
            c.conn.stream_table.streams[sidx].recv_max_data = extra_max_sd;
        }
        assert(quic::encode_max_stream_data_frame(0, extra_max_sd, plain));
        ack_el = true;
    }
    if plain.len > 0 {
        client_send_1rtt_frames(c, dcid, plain[..], ack_el, now_us);
    }
}

// ---- Test 1: Anti-Amplification & Undersized Initial Rejection -------------

fn test_anti_amplification_and_undersized_initial() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);
    assert(srv_port > 0);

    var ep = quic::quic_server_open("\x02h3", 16, 30000);
    defer quic::quic_server_close(ep);

    var seed:      u8[32]     = [0x17; 32];
    var cert_der:  u8[..4096] = [];
    var leaf_priv: u8[32]     = [0x18; 32];
    build_p256_cert_der(seed, leaf_priv, "Amp Root", "amp.example.test", false, "amp.example.test", cert_der);
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    var key_pem: u8[>..] = [];
    build_p256_pkcs8_pem(leaf_priv, key_pem);

    var cli = TestQuicClient { .. };
    let odcid_short: u8[8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];
    let scid_short:  u8[4] = [0x11, 0x22, 0x33, 0x44];
    init_test_client(cli, "127.0.0.1", "127.0.0.1", srv_port, "amp.example.test", cert_pem[..], odcid_short[..], scid_short[..]);
    defer close_test_client(cli);

    // 1. Undersized unvalidated Initial (< 1200 bytes) MUST be rejected per RFC 9000 Section 14.1.
    client_send_initial_flight(cli, 1000000, false);

    var rx_buf: u8[2048] = [0; 2048];
    var rx_ip:  u8[64]   = [0; 64];
    var rx_ipl: i32      = 0;
    var rx_p:   u16      = 0;
    let nr1 = net::udp_recvfrom_dual(srv_fd, rx_buf[..], rx_ip[..], rx_ipl, rx_p);
    assert(nr1 > 0 && nr1 < 1200);
    assert(!quic::quic_server_feed_datagram(ep, rx_buf[..nr1], rx_ip[..rx_ipl], rx_p, 1000000000));

    var out_pkt: u8[..1500] = [];
    var out_ip:  u8[..64]   = [];
    var out_p:   u16        = 0;
    assert(!quic::quic_server_poll_transmit(ep, 1000000000, out_pkt, out_ip, out_p));

    // 2. Valid 1200-byte Initial establishes unvalidated connection with 3x = 3600 byte limit (RFC 9000 Section 8.1).
    var cli2 = TestQuicClient { .. };
    let odcid2: u8[8] = [0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8];
    let scid2:  u8[4] = [0x55, 0x66, 0x77, 0x88];
    init_test_client(cli2, "127.0.0.1", "127.0.0.1", srv_port, "amp.example.test", cert_pem[..], odcid2[..], scid2[..]);
    defer close_test_client(cli2);
    client_send_initial_flight(cli2, 1000000, true);

    let nr2 = net::udp_recvfrom_dual(srv_fd, rx_buf[..], rx_ip[..], rx_ipl, rx_p);
    assert(nr2 >= 1200);
    assert(quic::quic_server_feed_datagram(ep, rx_buf[..nr2], rx_ip[..rx_ipl], rx_p, 1000000000));

    var ev = quic::QuicServerEvent { .. };
    assert(quic::quic_server_poll_event(ep, ev));
    assert(ev.kind == quic::QuicServerEventKind.NeedSniCredentials);
    assert(quic::quic_server_set_credentials_pem(ep, ev.conn_id, cert_pem[..], key_pem[..]));

    // Total bytes transmitted before address validation MUST NOT exceed 3 * nr2.
    var total_tx: i64 = 0;
    while quic::quic_server_poll_transmit(ep, 1000000000, out_pkt, out_ip, out_p) {
        total_tx += out_pkt.len;
        assert(total_tx <= 3 * nr2);
    }
    assert(total_tx > 0 && total_tx <= 3 * nr2);

    // Advancing timers repeatedly before Handshake packet arrives MUST NOT bypass 3x anti-amplification.
    var t_ns: u64 = 1000000000;
    for _ in 4 {
        let nxt = quic::quic_server_next_timeout_ns(ep);
        if nxt > t_ns { t_ns = nxt; } else { t_ns += 500000000; }
        quic::quic_server_on_timeout(ep, t_ns);
        while quic::quic_server_poll_transmit(ep, t_ns, out_pkt, out_ip, out_p) {
            total_tx += out_pkt.len;
            assert(total_tx <= 3 * nr2);
        }
    }

    // 3. Server close_conn emits CONNECTION_CLOSE_APP and rejects subsequent stream I/O.
    quic::quic_server_close_conn(ep, ev.conn_id, 0x77, "stop");
    if quic::quic_server_poll_transmit(ep, t_ns, out_pkt, out_ip, out_p) {
        total_tx += out_pkt.len;
        assert(total_tx <= 3 * nr2);
    }
    var dummy_fin = false;
    var dummy_out: u8[>..] = [];
    assert(quic::quic_server_stream_read(ep, ev.conn_id, 0, dummy_out, dummy_fin) == -1);
    let cw, cok = quic::quic_server_stream_write(ep, ev.conn_id, 0, "no", true);
    assert(!cok && cw == 0);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_AA_OK\n");
}

// ---- Test 2: Concurrent Dual-Stack Multi-Client + 64 KiB + PTO + Close -----

fn drain_server_to_clients(
    ep:        quic::QuicServerEndpoint&,
    srv_fd:    i64,
    ca:        TestQuicClient&,
    cb:        TestQuicClient&,
    drop_once: bool&,
    now_ns:    u64,
) -> i64 {
    var sent_cnt: i64        = 0;
    var out_pkt:  u8[..1500] = [];
    var out_ip:   u8[..64]   = [];
    var out_p:    u16        = 0;
    while quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p) {
        sent_cnt += 1;
        if drop_once {
            drop_once = false;
            continue; // Simulated packet drop on wire
        }
        assert(net::udp_sendto_dual(srv_fd, out_pkt[..], out_ip[..], out_p) == (out_pkt.len as i32));
        var buf:  u8[2048] = [0; 2048];
        var rip:  u8[64]   = [0; 64];
        var ripl: i32      = 0;
        var rp:   u16      = 0;
        let n_a = net::udp_recvfrom_dual(ca.fd, buf[..], rip[..], ripl, rp);
        if n_a > 0 { client_feed_dgram(ca, buf[..n_a], now_ns / 1000); }
        let n_b = net::udp_recvfrom_dual(cb.fd, buf[..], rip[..], ripl, rp);
        if n_b > 0 { client_feed_dgram(cb, buf[..n_b], now_ns / 1000); }
    }
    return sent_cnt;
}

fn drain_udp_into_server(srv_fd: i64, ep: quic::QuicServerEndpoint&, now_ns: u64) -> i64 {
    var rx_cnt: i64      = 0;
    var buf:    u8[2048] = [0; 2048];
    var rip:    u8[64]   = [0; 64];
    var ripl:   i32      = 0;
    var rp:     u16      = 0;
    while true {
        let nr = net::udp_recvfrom_dual(srv_fd, buf[..], rip[..], ripl, rp);
        if nr <= 0 { break; }
        assert(quic::quic_server_feed_datagram(ep, buf[..nr], rip[..ripl], rp, now_ns));
        rx_cnt += 1;
    }
    return rx_cnt;
}

fn test_concurrent_multi_client_64k_pto_and_close() {
    let base_rsa = count_active_rsa_slots();
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);
    assert(srv_port > 0);

    // Build ECDSA P-256 2-cert fullchain for "a.example.test"
    var ca_priv: u8[32] = [0x31; 32];
    ca_priv[31] = 0x05;
    var leaf_a_priv: u8[32] = [0x32; 32];
    leaf_a_priv[31] = 0x09;
    var ca_der:     u8[..4096] = [];
    var leaf_a_der: u8[..4096] = [];
    build_p256_cert_der(ca_priv, ca_priv, "Root A", "Root A", true, "", ca_der);
    build_p256_cert_der(ca_priv, leaf_a_priv, "Root A", "a.example.test", false, "a.example.test", leaf_a_der);
    var trust_a_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", ca_der[..], trust_a_pem);
    var cert_a_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", leaf_a_der[..], cert_a_pem);
    append_pem_block("CERTIFICATE", ca_der[..], cert_a_pem);
    var key_a_pem: u8[>..] = [];
    build_p256_pkcs8_pem(leaf_a_priv, key_a_pem);

    // Build RSA-2048 PEM for "b.example.test"
    var cert_b_der: u8[..4096] = [];
    build_rsa_leaf_cert_der("b.example.test", "b.example.test", cert_b_der);
    var cert_b_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", cert_b_der[..], cert_b_pem);
    var key_b_pem: u8[>..] = [];
    build_rsa_pkcs8_pem(key_b_pem);

    var ep = quic::quic_server_open("\x02h3", 16, 400);
    var now_ns: u64 = 1000000000;

    var ca = TestQuicClient { .. };
    let odcid_a: u8[8] = [0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let scid_a:  u8[4] = [0xCA, 0x01, 0x02, 0x03];
    init_test_client(ca, "127.0.0.1", "127.0.0.1", srv_port, "a.example.test", trust_a_pem[..], odcid_a[..], scid_a[..]);

    var cb = TestQuicClient { .. };
    let odcid_b: u8[8] = [0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let scid_b:  u8[4] = [0xCB, 0x01, 0x02, 0x03];
    init_test_client(cb, "::1", "::1", srv_port, "b.example.test", cert_b_pem[..], odcid_b[..], scid_b[..]);

    // Both clients send Initial flights concurrently on single dual-stack UDP socket.
    client_send_initial_flight(ca, now_ns / 1000, true);
    client_send_initial_flight(cb, now_ns / 1000, true);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 2);

    var conn_a: u64 = 0;
    var conn_b: u64 = 0;
    var ev = quic::QuicServerEvent { .. };
    while quic::quic_server_poll_event(ep, ev) {
        assert(ev.kind == quic::QuicServerEventKind.NeedSniCredentials);
        if ev.sni[..] == "a.example.test" {
            conn_a = ev.conn_id;
            assert(quic::quic_server_set_credentials_pem(ep, conn_a, cert_a_pem[..], key_a_pem[..]));
        } else if ev.sni[..] == "b.example.test" {
            conn_b = ev.conn_id;
            assert(quic::quic_server_set_credentials_pem(ep, conn_b, cert_b_pem[..], key_b_pem[..]));
        }
    }
    assert(conn_a != 0 && conn_b != 0 && conn_a != conn_b);
    // Server RSA slot MUST already be reclaimed immediately after CertificateVerify signature generation.
    assert(count_active_rsa_slots() == base_rsa);

    // Server sends ServerHello + Handshake flights; clients send Handshake Finished; server emits HANDSHAKE_DONE + NEW_CONNECTION_ID.
    var no_drop = false;
    now_ns += 5000000;
    let _ = drain_server_to_clients(ep, srv_fd, ca, cb, no_drop, now_ns);
    client_send_handshake_and_ack(ca, now_ns / 1000);
    client_send_handshake_and_ack(cb, now_ns / 1000);
    now_ns += 5000000;
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 2);

    var hs_a = false;
    var hs_b = false;
    while quic::quic_server_poll_event(ep, ev) {
        if ev.kind == quic::QuicServerEventKind.HandshakeComplete {
            if ev.conn_id == conn_a { hs_a = true; }
            if ev.conn_id == conn_b { hs_b = true; }
        }
    }
    assert(hs_a && hs_b);

    let _ = drain_server_to_clients(ep, srv_fd, ca, cb, no_drop, now_ns);
    assert(ca.handshake_done_seen && cb.handshake_done_seen);
    assert(ca.new_cid_seen && cb.new_cid_seen && cb.alt_srv_cid.len > 0);
    assert(count_active_rsa_slots() == base_rsa);

    // Build 64 KiB deterministic payload and stream bidirectionally on both clients.
    var payload_64k: u8[>..] = [];
    for i in 65536 {
        payload_64k.push(((i * 131 + 17) & 0xFF) as u8);
    }

    var rx_a_srv: u8[>..] = [];
    var rx_b_srv: u8[>..] = [];
    var fin_a_srv = false;
    var fin_b_srv = false;
    var off_a: i64 = 0;
    var off_b: i64 = 0;
    var echo_started_a = false;
    var echo_started_b = false;
    var drop_one_echo = true;
    var drop_triggered = false;

    let sid_a, _, ok_st_a = quic::open_local_stream(ca.conn.stream_table, true, 65536);
    let sid_b, _, ok_st_b = quic::open_local_stream(cb.conn.stream_table, true, 65536);
    assert(ok_st_a && sid_a == 0 && ok_st_b && sid_b == 0);
    ca.conn.flow_ctrl.max_data_local = 131072;
    cb.conn.flow_ctrl.max_data_local = 131072;

    // Also test server-initiated unidirectional stream (stream ID 3).
    let wn3, wok3 = quic::quic_server_stream_write(ep, conn_a, 3, "h3-ctrl-pre", true);
    assert(wok3 && wn3 == 11);

    // Client B switches to alternate DCID issued via NEW_CONNECTION_ID.
    var cb_dcid_buf: u8[..20] = [];
    assert(cb_dcid_buf.try_set(cb.alt_srv_cid[..]));
    var cli_a_fc_max_d: u64 = 32768;
    var cli_a_fc_max_s: u64 = 16384;
    var cli_b_fc_max_d: u64 = 32768;
    var cli_b_fc_max_s: u64 = 16384;

    for round in 400 {
        now_ns += 5000000;
        let now_us = now_ns / 1000;
        if off_a < payload_64k.len {
            let chunk = min(1100, payload_64k.len - off_a);
            let next_a = off_a + chunk;
            var sf: u8[..1200] = [];
            let flags = quic::QuicStreamFlags { fin: next_a == payload_64k.len, with_len: true, .. };
            assert(quic::encode_stream_frame(0, off_a as u64, payload_64k[off_a..next_a], sf, flags));
            client_send_1rtt_frames(ca, ca.conn.dcid[..], sf[..], true, now_us);
            off_a = next_a;
        }
        if off_b < payload_64k.len {
            let chunk = min(1100, payload_64k.len - off_b);
            let next_b = off_b + chunk;
            var sf: u8[..1200] = [];
            let flags = quic::QuicStreamFlags { fin: next_b == payload_64k.len, with_len: true, .. };
            assert(quic::encode_stream_frame(0, off_b as u64, payload_64k[off_b..next_b], sf, flags));
            client_send_1rtt_frames(cb, cb_dcid_buf[..], sf[..], true, now_us);
            off_b = next_b;
        }

        let _ = drain_udp_into_server(srv_fd, ep, now_ns);
        while quic::quic_server_poll_event(ep, ev) {
            if ev.kind == quic::QuicServerEventKind.StreamReadable {
                if ev.conn_id == conn_a {
                    var df = false;
                    let nr = quic::quic_server_stream_read(ep, conn_a, ev.stream_id, rx_a_srv, df);
                    assert(nr >= 0);
                    if df { fin_a_srv = true; }
                } else if ev.conn_id == conn_b {
                    var df = false;
                    let nr = quic::quic_server_stream_read(ep, conn_b, ev.stream_id, rx_b_srv, df);
                    assert(nr >= 0);
                    if df { fin_b_srv = true; }
                }
            }
        }

        if fin_a_srv && !echo_started_a {
            assert(rx_a_srv[..] == payload_64k[..]);
            let wn, wok = quic::quic_server_stream_write(ep, conn_a, 0, payload_64k[..], true);
            assert(wok && wn == payload_64k.len);
            echo_started_a = true;
        }
        if fin_b_srv && !echo_started_b {
            assert(rx_b_srv[..] == payload_64k[..]);
            let wn, wok = quic::quic_server_stream_write(ep, conn_b, 0, payload_64k[..], true);
            assert(wok && wn == payload_64k.len);
            echo_started_b = true;
        }

        // Drop exactly one echoed 1-RTT packet once echo starts to exercise PTO retransmission.
        if echo_started_a && !drop_triggered {
            let sent_n = drain_server_to_clients(ep, srv_fd, ca, cb, drop_one_echo, now_ns);
            if sent_n > 0 { drop_triggered = true; }
        } else {
            let _ = drain_server_to_clients(ep, srv_fd, ca, cb, no_drop, now_ns);
        }

        // Advance clients' flow control windows as echo chunks arrive.
        var send_d_a: u64 = 0;
        var send_s_a: u64 = 0;
        if ca.stream_rx_contig + 8192 > cli_a_fc_max_s {
            cli_a_fc_max_s = ca.stream_rx_contig + 16384;
            send_s_a = cli_a_fc_max_s;
        }
        if ca.stream_rx_contig + 16384 > cli_a_fc_max_d {
            cli_a_fc_max_d = ca.stream_rx_contig + 32768;
            send_d_a = cli_a_fc_max_d;
        }
        client_send_app_ack_and_fc(ca, ca.conn.dcid[..], send_d_a, send_s_a, now_us);

        var send_d_b: u64 = 0;
        var send_s_b: u64 = 0;
        if cb.stream_rx_contig + 8192 > cli_b_fc_max_s {
            cli_b_fc_max_s = cb.stream_rx_contig + 16384;
            send_s_b = cli_b_fc_max_s;
        }
        if cb.stream_rx_contig + 16384 > cli_b_fc_max_d {
            cli_b_fc_max_d = cb.stream_rx_contig + 32768;
            send_d_b = cli_b_fc_max_d;
        }
        client_send_app_ack_and_fc(cb, cb_dcid_buf[..], send_d_b, send_s_b, now_us);

        // Trigger PTO timer when waiting for dropped packet retransmission.
        let nxt_t = quic::quic_server_next_timeout_ns(ep);
        if drop_triggered && (!ca.stream_rx_fin || !cb.stream_rx_fin) && nxt_t > 0 && (round % 4) == 3 {
            if nxt_t > now_ns && nxt_t - now_ns < 200000000 {
                now_ns = nxt_t;
                quic::quic_server_on_timeout(ep, now_ns);
                let _ = drain_server_to_clients(ep, srv_fd, ca, cb, no_drop, now_ns);
            }
        }

        if ca.stream_rx_fin && ca.stream_rx_contig == 65536 && cb.stream_rx_fin && cb.stream_rx_contig == 65536 {
            break;
        }
    }

    assert(drop_triggered);
    assert(ca.has_uni3_rx && ca.uni3_buf[..] == "h3-ctrl-pre");
    assert(ca.stream_rx_fin && ca.stream_rx_buf.len == 65536 && ca.stream_rx_buf[..] == payload_64k[..]);
    assert(cb.stream_rx_fin && cb.stream_rx_buf.len == 65536 && cb.stream_rx_buf[..] == payload_64k[..]);
    assert(ca.saw_max_data && ca.saw_max_stream_data);
    assert(cb.saw_max_data && cb.saw_max_stream_data);

    // Client A sends CONNECTION_CLOSE_APP (0x42).
    var cc_plain: u8[..64] = [];
    assert(quic::encode_connection_close_frame(0x42, 0, "done", cc_plain, true));
    client_send_1rtt_frames(ca, ca.conn.dcid[..], cc_plain[..], false, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) >= 1);

    var saw_close_a = false;
    while quic::quic_server_poll_event(ep, ev) {
        if ev.kind == quic::QuicServerEventKind.ConnectionClosed && ev.conn_id == conn_a {
            assert(ev.error_code == 0x42);
            saw_close_a = true;
        }
    }
    assert(saw_close_a);

    // Client B idles until idle timeout fires cleanly.
    var saw_close_b = false;
    for _ in 12 {
        let nxt_idle = quic::quic_server_next_timeout_ns(ep);
        if nxt_idle == 0 { break; }
        now_ns = max(now_ns + 50000000, nxt_idle);
        quic::quic_server_on_timeout(ep, now_ns);
        while quic::quic_server_poll_event(ep, ev) {
            if ev.kind == quic::QuicServerEventKind.ConnectionClosed && ev.conn_id == conn_b {
                saw_close_b = true;
            }
        }
        if saw_close_b { break; }
    }
    assert(saw_close_b);

    quic::quic_server_close(ep);
    quic::quic_server_close(ep); // Idempotent double-close
    close_test_client(ca);
    close_test_client(cb);
    net::tcp_close(srv_fd);
    assert(count_active_rsa_slots() == base_rsa);
    print("CHECK_QUIC_ENDPOINT_E2E_OK\n");
}

// ---- Test 3: Server Close Conn & Thread-Local Safety ----------------------

thread_fn quic_endpoint_thread_worker(tag: i64) {
    var ep = quic::quic_server_open("\x02h3", 4, 1000);
    var ev = quic::QuicServerEvent { .. };
    assert(!quic::quic_server_poll_event(ep, ev));
    assert(quic::quic_server_next_timeout_ns(ep) == 0);
    quic::quic_server_close_conn(ep, 999 + (tag as u64), 0, "missing");
    quic::quic_server_close(ep);
}

fn test_server_close_conn_and_threads() {
    let t1 = thread_spawn(quic_endpoint_thread_worker, 1);
    let t2 = thread_spawn(quic_endpoint_thread_worker, 2);
    assert(thread_wait(t1) && thread_wait(t2));
    print("CHECK_QUIC_THREADS_OK\n");
}

// ---- Regressions: Fix Round 1 Findings 1-6 --------------------------------

fn make_p256_test_creds(cert_pem: u8[>..]&, key_pem: u8[>..]&, tag: u8) {
    cert_pem.clear();
    key_pem.clear();
    var leaf_priv: u8[32]     = [tag; 32];
    var cert_der:  u8[..4096] = [];
    build_p256_cert_der(
        leaf_priv, leaf_priv, "fix.example.test", "fix.example.test", false, "fix.example.test", cert_der,
    );
    append_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    build_p256_pkcs8_pem(leaf_priv, key_pem);
}

fn connect_p256_session(
    ep:            quic::QuicServerEndpoint&,
    srv_fd:        i64,
    srv_port:      u16,
    cli:           TestQuicClient&,
    cert_pem:      const u8[:],
    key_pem:       const u8[:],
    odcid:         const u8[:],
    scid:          const u8[:],
    now_ns:        u64&,
    init_max_data: u64 = 32768,
    init_max_sd:   u64 = 16384,
) -> u64 {
    init_test_client(
        cli, "127.0.0.1", "127.0.0.1", srv_port, "fix.example.test",
        cert_pem, odcid, scid, init_max_data, init_max_sd,
    );
    client_send_initial_flight(cli, now_ns / 1000, true);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    var conn_id: u64 = 0;
    var ev = quic::QuicServerEvent { .. };
    while quic::quic_server_poll_event(ep, ev) {
        if ev.kind == quic::QuicServerEventKind.NeedSniCredentials {
            conn_id = ev.conn_id;
            assert(quic::quic_server_set_credentials_pem(ep, conn_id, cert_pem, key_pem));
        }
    }
    assert(conn_id != 0);

    var no_drop = false;
    var dummy = TestQuicClient { .. };
    now_ns += 5000000;
    let _ = drain_server_to_clients(ep, srv_fd, cli, dummy, no_drop, now_ns);
    client_send_handshake_and_ack(cli, now_ns / 1000);
    now_ns += 5000000;
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    var hs_ok = false;
    while quic::quic_server_poll_event(ep, ev) {
        if ev.kind == quic::QuicServerEventKind.HandshakeComplete && ev.conn_id == conn_id {
            hs_ok = true;
        }
    }
    assert(hs_ok);
    let _ = drain_server_to_clients(ep, srv_fd, cli, dummy, no_drop, now_ns);
    assert(cli.handshake_done_seen);
    now_ns += 5000000;
    client_send_app_ack_and_fc(cli, cli.conn.dcid[..], 0, 0, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);
    return conn_id;
}

fn client_send_stream_bytes(
    cli:       TestQuicClient&,
    stream_id: u64,
    start_off: u64,
    data:      const u8[:],
    fin:       bool,
    now_us:    u64,
) {
    var pos: i64 = 0;
    while pos < data.len || (fin && pos == data.len) {
        let take = min(1200, data.len - pos);
        let send_fin = fin && (pos + take == data.len);
        var plain: u8[..1300] = [];
        let flags = quic::QuicStreamFlags { fin: send_fin, with_len: true, .. };
        assert(quic::encode_stream_frame(stream_id, start_off + (pos as u64), data[pos..(pos + take)], plain, flags));
        client_send_1rtt_frames(cli, cli.conn.dcid[..], plain[..], true, now_us);
        pos += take;
        if pos >= data.len { break; }
    }
}

fn client_recv_direct_packets(cli: TestQuicClient&, ep: quic::QuicServerEndpoint&, now_ns: u64) -> i64 {
    var cnt:     i64        = 0;
    var out_pkt: u8[..1500] = [];
    var out_ip:  u8[..64]   = [];
    var out_p:   u16        = 0;
    while quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p) {
        client_feed_dgram(cli, out_pkt[..], now_ns / 1000);
        cnt += 1;
    }
    return cnt;
}

fn client_drain_and_ack(cli: TestQuicClient&, srv_fd: i64, ep: quic::QuicServerEndpoint&, now_ns: u64) -> i64 {
    var total: i64 = 0;
    for _ in 12 {
        let tx = client_recv_direct_packets(cli, ep, now_ns);
        total += tx;
        if cli.app_ack_needed {
            client_send_app_ack_and_fc(cli, cli.conn.dcid[..], 0, 0, now_ns / 1000);
            let _ = drain_udp_into_server(srv_fd, ep, now_ns);
        }
        if tx == 0 { break; }
    }
    return total;
}

// Finding 1: Error-path close, peer Draining close, and long-idle close_conn arm drain_deadline_ns and reclaim slots.
fn test_close_drain_lifecycle_reclaim() {
    let base_rsa = count_active_rsa_slots();
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0x41);

    // Endpoint with max_conns = 1 to observe slot reclaim directly.
    var ep = quic::quic_server_open("\x02h3", 1, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    // 1a. Protocol error inside quic::process_payload transitions conn to Closing with CONNECTION_CLOSE + 3*PTO drain.
    var c1 = TestQuicClient { .. };
    let od1: u8[8] = [0xC1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc1: u8[4] = [0xD1, 0x01, 0x02, 0x03];
    let cid1 = connect_p256_session(ep, srv_fd, srv_port, c1, cert_pem[..], key_pem[..], od1[..], sc1[..], now_ns);
    defer close_test_client(c1);

    // While c1 holds the single slot, a new client is rejected.
    var c_blocked = TestQuicClient { .. };
    let od_blk: u8[8] = [0xC0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x99];
    let sc_blk: u8[4] = [0xD0, 0x01, 0x02, 0x99];
    init_test_client(c_blocked, "127.0.0.1", "127.0.0.1", srv_port, "fix.example.test", cert_pem[..], od_blk[..], sc_blk[..]);
    defer close_test_client(c_blocked);
    client_send_initial_flight(c_blocked, now_ns / 1000, true);
    var tmp_rx: u8[2048] = [0; 2048];
    var tmp_ip: u8[64]   = [0; 64];
    var tmp_il: i32      = 0;
    var tmp_p:  u16      = 0;
    let n_blk = net::udp_recvfrom_dual(srv_fd, tmp_rx[..], tmp_ip[..], tmp_il, tmp_p);
    assert(n_blk >= 1200);
    assert(!quic::quic_server_feed_datagram(ep, tmp_rx[..n_blk], tmp_ip[..tmp_il], tmp_p, now_ns));

    // Send malformed unknown frame 0xFF in 1-RTT so quic::process_payload closes c1 with FRAME_ENCODING_ERROR.
    let bad_plain: u8[4] = [0xFF, 0x00, 0x00, 0x00];
    client_send_1rtt_frames(c1, c1.conn.dcid[..], bad_plain[..], true, now_ns / 1000);
    let n_bad = net::udp_recvfrom_dual(srv_fd, tmp_rx[..], tmp_ip[..], tmp_il, tmp_p);
    assert(n_bad > 0);
    assert(!quic::quic_server_feed_datagram(ep, tmp_rx[..n_bad], tmp_ip[..tmp_il], tmp_p, now_ns));

    var ev = quic::QuicServerEvent { .. };
    var saw_err_close = false;
    while quic::quic_server_poll_event(ep, ev) {
        if ev.kind == quic::QuicServerEventKind.ConnectionClosed && ev.conn_id == cid1 {
            assert(ev.error_code != 0);
            saw_err_close = true;
        }
    }
    assert(saw_err_close);
    assert(client_recv_direct_packets(c1, ep, now_ns) >= 1);
    assert(c1.saw_conn_close_tpt && c1.conn.close_code != 0);

    let dl1 = quic::quic_server_next_timeout_ns(ep);
    assert(dl1 > now_ns);
    now_ns = dl1;
    quic::quic_server_on_timeout(ep, now_ns);
    assert(quic::quic_server_next_timeout_ns(ep) == 0);

    // 1b. Reclaimed max_conns = 1 slot accepts c2; test peer CONNECTION_CLOSE (Draining) sets 3*PTO drain and frees slot.
    var c2 = TestQuicClient { .. };
    let od2: u8[8] = [0xC2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc2: u8[4] = [0xD2, 0x01, 0x02, 0x03];
    let cid2 = connect_p256_session(ep, srv_fd, srv_port, c2, cert_pem[..], key_pem[..], od2[..], sc2[..], now_ns);
    defer close_test_client(c2);

    var cc_plain: u8[..64] = [];
    assert(quic::encode_connection_close_frame(0x33, 0, "bye", cc_plain, true));
    client_send_1rtt_frames(c2, c2.conn.dcid[..], cc_plain[..], false, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    var saw_drain_close = false;
    while quic::quic_server_poll_event(ep, ev) {
        if ev.kind == quic::QuicServerEventKind.ConnectionClosed && ev.conn_id == cid2 {
            assert(ev.error_code == 0x33);
            saw_drain_close = true;
        }
    }
    assert(saw_drain_close);
    assert(client_recv_direct_packets(c2, ep, now_ns) == 0); // Draining does not reply with CONNECTION_CLOSE
    let dl2 = quic::quic_server_next_timeout_ns(ep);
    assert(dl2 > now_ns);
    now_ns = dl2;
    quic::quic_server_on_timeout(ep, now_ns);
    assert(quic::quic_server_next_timeout_ns(ep) == 0);

    // 1c. Long-idle connection closed via quic_server_close_conn still transmits CONNECTION_CLOSE_APP after on_timeout.
    var c3 = TestQuicClient { .. };
    let od3: u8[8] = [0xC3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc3: u8[4] = [0xD3, 0x01, 0x02, 0x03];
    let cid3 = connect_p256_session(ep, srv_fd, srv_port, c3, cert_pem[..], key_pem[..], od3[..], sc3[..], now_ns);
    defer close_test_client(c3);

    now_ns += 5000000000; // 5s idle (<< 30s idle timeout, >> 3*PTO since last_activity_ns)
    quic::quic_server_close_conn(ep, cid3, 0x55, "admin");
    quic::quic_server_on_timeout(ep, now_ns);
    assert(client_recv_direct_packets(c3, ep, now_ns) >= 1);
    assert(c3.conn.state == quic::QuicConnState.Draining && c3.conn.close_code == 0x55);

    let dl3 = quic::quic_server_next_timeout_ns(ep);
    assert(dl3 > now_ns);
    now_ns = dl3;
    quic::quic_server_on_timeout(ep, now_ns);
    assert(quic::quic_server_next_timeout_ns(ep) == 0);

    net::tcp_close(srv_fd);
    assert(count_active_rsa_slots() == base_rsa);
    print("CHECK_QUIC_FIX1_DRAIN_OK\n");
}

// Finding 2: Unhandled/undersized/mismatched datagrams never inflate AA budget; only authenticated 1-RTT migrates peer addr.
fn test_aa_unvalidated_spoof_and_1rtt_migration() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0x51);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    var c = TestQuicClient { .. };
    let od: u8[8] = [0xE1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc: u8[4] = [0xF1, 0x01, 0x02, 0x03];
    init_test_client(c, "127.0.0.1", "127.0.0.1", srv_port, "fix.example.test", cert_pem[..], od[..], sc[..]);
    defer close_test_client(c);
    client_send_initial_flight(c, now_ns / 1000, true);

    var rx_buf: u8[2048] = [0; 2048];
    var rx_ip:  u8[64]   = [0; 64];
    var rx_il:  i32      = 0;
    var rx_p:   u16      = 0;
    let init_len = net::udp_recvfrom_dual(srv_fd, rx_buf[..], rx_ip[..], rx_il, rx_p);
    assert(init_len >= 1200);
    assert(quic::quic_server_feed_datagram(ep, rx_buf[..init_len], rx_ip[..rx_il], rx_p, now_ns));

    var ev = quic::QuicServerEvent { .. };
    assert(quic::quic_server_poll_event(ep, ev) && ev.kind == quic::QuicServerEventKind.NeedSniCredentials);
    let conn_id = ev.conn_id;
    assert(quic::quic_server_set_credentials_pem(ep, conn_id, cert_pem[..], key_pem[..]));

    // Feed 1400-byte spoofed/mismatched and corrupt datagrams while !validated_address.
    var spoof_init: u8[1400] = [0; 1400];
    for i in min(init_len, 40) { spoof_init[i] = rx_buf[i]; }
    assert(!quic::quic_server_feed_datagram(ep, spoof_init[..], "127.0.0.1", rx_p + 1, now_ns));
    spoof_init[39] ^= 0xFF;
    assert(!quic::quic_server_feed_datagram(ep, spoof_init[..], rx_ip[..rx_il], rx_p, now_ns));

    // AA ceiling MUST remain bounded by 3 * init_len (never inflated by rejected 1400-byte datagrams).
    var total_tx: i64        = 0;
    var out_pkt:  u8[..1500] = [];
    var out_ip:   u8[..64]   = [];
    var out_p:    u16        = 0;
    for _ in 4 {
        while quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p) {
            total_tx += out_pkt.len;
            assert(total_tx <= 3 * init_len);
            client_feed_dgram(c, out_pkt[..], now_ns / 1000);
        }
        now_ns += 400000000;
        quic::quic_server_on_timeout(ep, now_ns);
    }
    assert(total_tx > 0 && total_tx <= 3 * init_len);

    // Complete handshake -> validated_address == true.
    client_send_handshake_and_ack(c, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) >= 1);
    let _ = client_recv_direct_packets(c, ep, now_ns);
    assert(c.handshake_done_seen && c.conn.dcid.len == 8);

    // Unauthenticated short-header packet from wrong port MUST fail and MUST NOT migrate peer address.
    var fake_1rtt: u8[64] = [0x40; 64];
    for k in 8 { fake_1rtt[1 + k] = c.conn.dcid[k]; }
    assert(!quic::quic_server_feed_datagram(ep, fake_1rtt[..], "127.0.0.1", rx_p + 77, now_ns));
    let w1, ok_w1 = quic::quic_server_stream_write(ep, conn_id, 3, "stay", false);
    assert(ok_w1 && w1 == 4);
    assert(quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p));
    assert(out_p == rx_p);
    client_feed_dgram(c, out_pkt[..], now_ns / 1000);

    // Authenticated 1-RTT packet from migrated client socket DOES migrate peer address to mig_port.
    let mig_fd = net::udp_open_dual("127.0.0.1", 0, 0);
    assert(mig_fd > 0);
    defer net::tcp_close(mig_fd);
    let mig_port = net::tcp_getsockname_port(mig_fd);
    assert(mig_port != rx_p);
    let old_fd = c.fd;
    c.fd = mig_fd;
    let ping_p: u8[4] = [0x01, 0x00, 0x00, 0x00];
    client_send_1rtt_frames(c, c.conn.dcid[..], ping_p[..], true, now_ns / 1000);
    c.fd = old_fd;
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    let w2, ok_w2 = quic::quic_server_stream_write(ep, conn_id, 3, "migrated", true);
    assert(ok_w2 && w2 == 8);
    assert(quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p));
    assert(out_p == mig_port);

    // Migrated path MUST enforce 3x AA ceiling until PATH_RESPONSE validates it (H4_C02).
    var mig_tx:  i64     = out_pkt.len;
    var big_buf: u8[512] = [0x42; 512];
    let w3, ok_w3 = quic::quic_server_stream_write(ep, conn_id, 7, big_buf[..], false);
    assert(ok_w3 && w3 == 512);
    while quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p) {
        mig_tx += out_pkt.len;
    }
    assert(mig_tx <= 93);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_FIX2_AA_MIGRATION_OK\n");
}

// Finding 3: Lost MaxData/MaxStreamData retransmission tracks new PN; smaller ACK preserves larger sibling.
fn test_window_update_retx_pn_and_sibling_order() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0x61);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    var c = TestQuicClient { .. };
    let od: u8[8] = [0xE2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc: u8[4] = [0xF2, 0x01, 0x02, 0x03];
    let conn_id = connect_p256_session(ep, srv_fd, srv_port, c, cert_pem[..], key_pem[..], od[..], sc[..], now_ns);
    defer close_test_client(c);
    let sid, _, ok_s = quic::open_local_stream(c.conn.stream_table, true, 65536);
    assert(ok_s && sid == 0);

    var chunk_40k: u8[>..] = [];
    for i in 40000 { chunk_40k.push((i & 0xFF) as u8); }
    var srv_rx: u8[>..] = [];
    var srv_fin = false;

    // Round 1: server emits P1 with MaxData/MaxStreamData = 105536; client saves ACK covering P1 only.
    client_send_stream_bytes(c, 0, 0, chunk_40k[..], false, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) >= 1);
    assert(quic::quic_server_stream_read(ep, conn_id, 0, srv_rx, srv_fin) == 40000);
    srv_rx.clear();
    assert(client_recv_direct_packets(c, ep, now_ns) == 1);
    let val1 = c.last_max_data;
    let val1_sd = c.last_max_stream_data;
    assert(val1 == 105536 && val1_sd == 105536);
    let ack_p1, ok_a1 = quic::build_ack_frame(c.conn.app_space.recv_ranges, 0);
    assert(ok_a1);

    // Round 2: server emits P2 with larger 145536, dropped on wire before client sees it.
    client_send_stream_bytes(c, 0, 40000, chunk_40k[..], false, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) >= 1);
    assert(quic::quic_server_stream_read(ep, conn_id, 0, srv_rx, srv_fin) == 40000);
    var out_pkt: u8[..1500] = [];
    var out_ip:  u8[..64]   = [];
    var out_p:   u16        = 0;
    assert(quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p)); // Drop P2!

    // Client ACKs ONLY P1 (smaller val1). Larger P2 MUST NOT be retired by sib.val <= ref_ch.val.
    var ack_plain: u8[..64] = [];
    assert(quic::encode_ack_frame(ack_p1, ack_plain));
    client_send_1rtt_frames(c, c.conn.dcid[..], ack_plain[..], false, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    // PTO 1 triggers P3 (retx of P2's 145536) -> drop P3 too to prove P3's new PN was tracked!
    let t1 = quic::quic_server_next_timeout_ns(ep);
    assert(t1 > now_ns);
    now_ns = t1;
    quic::quic_server_on_timeout(ep, now_ns);
    assert(quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p)); // Drop P3!

    // PTO 2 retransmits P4 -> deliver to client and confirm larger 145536 values arrive.
    let t2 = quic::quic_server_next_timeout_ns(ep);
    assert(t2 > now_ns);
    now_ns = t2;
    quic::quic_server_on_timeout(ep, now_ns);
    assert(client_recv_direct_packets(c, ep, now_ns) >= 1);
    assert(c.last_max_data == 145536 && c.last_max_stream_data == 145536);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_FIX3_WINDOW_RETX_OK\n");
}

// Finding 4: Peer TP < 65536 and MAX_STREAM_DATA <= 65536 before first write are honored accurately.
fn test_small_tp_and_early_max_stream_data() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0x71);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    var c = TestQuicClient { .. };
    let od: u8[8] = [0xE3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc: u8[4] = [0xF3, 0x01, 0x02, 0x03];
    // Advertise < 65536 peer TP limits: max_data = 16384, max_stream_data_* = 1024.
    let conn_id = connect_p256_session(
        ep, srv_fd, srv_port, c, cert_pem[..], key_pem[..], od[..], sc[..], now_ns, 16384, 1024,
    );
    defer close_test_client(c);
    let sid, _, ok_s = quic::open_local_stream(c.conn.stream_table, true, 65536);
    assert(ok_s && sid == 0);

    // Client opens stream 0 with "hi", then raises stream 0 send window to 8192 (still <= 65536) BEFORE server writes.
    client_send_stream_bytes(c, 0, 0, "hi", false, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);
    var msd0: u8[..32] = [];
    assert(quic::encode_max_stream_data_frame(0, 8192, msd0));
    client_send_1rtt_frames(c, c.conn.dcid[..], msd0[..], true, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    var p9000: u8[>..] = [];
    for i in 9000 { p9000.push(((i * 7 + 3) & 0xFF) as u8); }
    let w0, ok0 = quic::quic_server_stream_write(ep, conn_id, 0, p9000[..], true);
    assert(ok0 && w0 == 9000);
    assert(client_drain_and_ack(c, srv_fd, ep, now_ns) >= 1);
    assert(c.stream_rx_contig == 8192 && !c.stream_rx_fin);

    // Raise stream 0 limit to 12000 -> remaining 808 bytes + FIN arrive.
    msd0.clear();
    assert(quic::encode_max_stream_data_frame(0, 12000, msd0));
    client_send_1rtt_frames(c, c.conn.dcid[..], msd0[..], true, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);
    assert(client_drain_and_ack(c, srv_fd, ep, now_ns) >= 1);
    assert(c.stream_rx_fin && c.stream_rx_contig == 9000 && c.stream_rx_buf[..] == p9000[..]);

    // Stream 3 starts with peer TP limit 1024 (< 65536): write 1500 bytes + FIN, expect 1024 byte stall first.
    let w3, ok3 = quic::quic_server_stream_write(ep, conn_id, 3, p9000[..1500], true);
    assert(ok3 && w3 == 1500);
    assert(client_drain_and_ack(c, srv_fd, ep, now_ns) >= 1);
    assert(c.uni3_buf.len == 1024 && !c.has_uni3_rx);

    var msd3: u8[..32] = [];
    assert(quic::encode_max_stream_data_frame(3, 2048, msd3));
    client_send_1rtt_frames(c, c.conn.dcid[..], msd3[..], true, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);
    assert(client_drain_and_ack(c, srv_fd, ep, now_ns) >= 1);
    assert(c.has_uni3_rx && c.uni3_buf.len == 1500 && c.uni3_buf[..] == p9000[..1500]);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_FIX4_SMALL_TP_OK\n");
}

// Finding 5: ACKing out-of-order FIN packet before earlier stream chunk does not complete stream send or lose chunk 0.
fn test_ooo_fin_ack_retx_earlier_chunk() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0x81);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    var c = TestQuicClient { .. };
    let od: u8[8] = [0xE4, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc: u8[4] = [0xF4, 0x01, 0x02, 0x03];
    let conn_id = connect_p256_session(ep, srv_fd, srv_port, c, cert_pem[..], key_pem[..], od[..], sc[..], now_ns);
    defer close_test_client(c);
    let sid, _, ok_s = quic::open_local_stream(c.conn.stream_table, true, 65536);
    assert(ok_s && sid == 0);

    client_send_stream_bytes(c, 0, 0, "go", false, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    var p4000: u8[>..] = [];
    for i in 4000 { p4000.push(((i * 19 + 5) & 0xFF) as u8); }
    let w, ok_w = quic::quic_server_stream_write(ep, conn_id, 0, p4000[..], true);
    assert(ok_w && w == 4000);

    // Drop packet 0 (chunk 0) while delivering later packets including the FIN packet.
    var pkt_idx: i64        = 0;
    var out_pkt: u8[..1500] = [];
    var out_ip:  u8[..64]   = [];
    var out_p:   u16        = 0;
    while quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p) {
        if pkt_idx > 0 { client_feed_dgram(c, out_pkt[..], now_ns / 1000); }
        pkt_idx += 1;
    }
    assert(pkt_idx >= 4);
    assert(c.stream_rx_fin && c.stream_rx_contig == 0);

    // Client ACKs ONLY packets 1..last (FIN packet ACKed first, packet 0 still missing).
    client_send_app_ack_and_fc(c, c.conn.dcid[..], 0, 0, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    // Server MUST retransmit chunk 0 cleanly upon loss/PTO rather than discarding tx buffer early.
    if client_recv_direct_packets(c, ep, now_ns) == 0 {
        let nxt = quic::quic_server_next_timeout_ns(ep);
        assert(nxt > now_ns);
        now_ns = nxt;
        quic::quic_server_on_timeout(ep, now_ns);
        assert(client_recv_direct_packets(c, ep, now_ns) >= 1);
    }
    assert(c.stream_rx_fin && c.stream_rx_contig == 4000 && c.stream_rx_buf[..] == p4000[..]);

    client_send_app_ack_and_fc(c, c.conn.dcid[..], 0, 0, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_FIX5_OOO_FIN_OK\n");
}

// Finding 6: Tracking >128 concurrently unacked chunks up to 256 cap never silently drops chunks.
fn test_sent_chunks_capacity_and_no_drop() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0x91);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    var c = TestQuicClient { .. };
    let od: u8[8] = [0xE5, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc: u8[4] = [0xF5, 0x01, 0x02, 0x03];
    let conn_id = connect_p256_session(ep, srv_fd, srv_port, c, cert_pem[..], key_pem[..], od[..], sc[..], now_ns);
    defer close_test_client(c);
    let sid, _, ok_s = quic::open_local_stream(c.conn.stream_table, true, 65536);
    assert(ok_s && sid == 0);

    var chunk_40k: u8[>..] = [];
    for i in 40000 { chunk_40k.push(((i + 3) & 0xFF) as u8); }
    var srv_rx:   u8[>..] = [];
    var expected: u8[>..] = [];
    var srv_off:  u64     = 0;
    var srv_fin = false;

    // 86 rounds * 3 chunks/pkt (MaxData + MaxStreamData + StreamData) = 258 > 128 old cap & exercises 252 room guard.
    var emitted_rounds: i64 = 0;
    for r in 86 {
        client_send_stream_bytes(c, 0, srv_off, chunk_40k[..], false, now_ns / 1000);
        srv_off += 40000;
        assert(drain_udp_into_server(srv_fd, ep, now_ns) >= 1);
        assert(quic::quic_server_stream_read(ep, conn_id, 0, srv_rx, srv_fin) == 40000);
        srv_rx.clear();

        var small_w: u8[8] = [r as u8; 8];
        for k in 8 { expected.push(small_w[k]); }
        let wn, wok = quic::quic_server_stream_write(ep, conn_id, 0, small_w[..], r == 85);
        assert(wok && wn == 8);
        // Feed packets to client WITHOUT client sending ACKs yet so all emitted chunks stay unacked.
        emitted_rounds += client_recv_direct_packets(c, ep, now_ns);
    }
    // Past old 128 cap (>43 rounds * 3 = 129) was emitted without dropping, and room guard capped < 86*3 when unacked.
    assert(emitted_rounds >= 70);

    // Once client ACKs, server drains all backpressured queued writes + FIN cleanly with zero holes.
    for _ in 6 {
        client_send_app_ack_and_fc(c, c.conn.dcid[..], 0, 0, now_ns / 1000);
        if drain_udp_into_server(srv_fd, ep, now_ns) <= 0 { break; }
        let _ = client_recv_direct_packets(c, ep, now_ns);
        if c.stream_rx_fin && c.stream_rx_contig == (expected.len as u64) { break; }
    }
    assert(c.stream_rx_fin && c.stream_rx_contig == 688 && c.stream_rx_buf[..] == expected[..]);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_FIX6_SENT_CHUNKS_OK\n");
}

fn count_active_quic_srv_slabs() -> i64 {
    var cnt: i64 = 0;
    for i in quic::g_quic_srv_slabs.len {
        if quic::g_quic_srv_slabs[i].active { cnt += 1; }
    }
    return cnt;
}

fn find_srv_conn_slot_idx(conn_id: u64) -> i64 {
    for i in quic::g_quic_srv_conns.len {
        let cs .= quic::g_quic_srv_conns[i];
        if cs.active && cs.conn_id == conn_id { return i; }
    }
    return -1;
}

fn test_persistent_max_streams_beyond_128() {
    let base_slabs = count_active_quic_srv_slabs();
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0xA1);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    var c = TestQuicClient { .. };
    let od: u8[8] = [0xEA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc: u8[4] = [0xFA, 0x01, 0x02, 0x03];
    let conn_id = connect_p256_session(
        ep, srv_fd, srv_port, c, cert_pem[..], key_pem[..], od[..], sc[..], now_ns, 1048576, 65536,
    );
    defer close_test_client(c);
    c.conn.stream_table.remote_max_streams_bidi = c.peer_tp.initial_max_streams_bidi;
    c.conn.stream_table.has_remote_max_streams_bidi = true;
    assert(c.conn.stream_table.remote_max_streams_bidi == 100);

    var srv_rx: u8[>..] = [];
    var ev = quic::QuicServerEvent { .. };
    for r in 135 {
        let sid, st_idx, ok_open = quic::open_local_stream(c.conn.stream_table, true, 65536);
        assert(ok_open && sid == ((r as u64) * 4));
        let _, ok_tx = quic::on_send_data(c.conn.stream_table.streams[st_idx], 0, 2, true);
        assert(ok_tx);

        client_send_stream_bytes(c, sid, 0, "ok", true, now_ns / 1000);
        assert(drain_udp_into_server(srv_fd, ep, now_ns) >= 1);

        var read_fin = false;
        while quic::quic_server_poll_event(ep, ev) {
            if ev.kind == quic::QuicServerEventKind.StreamReadable && ev.stream_id == sid {
                srv_rx.clear();
                var fin = false;
                let nr = quic::quic_server_stream_read(ep, conn_id, sid, srv_rx, fin);
                assert(nr == 2 && fin && srv_rx[..] == "ok");
                read_fin = true;
            }
        }
        assert(read_fin);

        let wn, wok = quic::quic_server_stream_write(ep, conn_id, sid, "pong", true);
        assert(wok && wn == 4);
        assert(client_drain_and_ack(c, srv_fd, ep, now_ns) >= 1);

        let c_st, ok_cs = quic::find_stream(c.conn.stream_table, sid);
        assert(ok_cs);
        assert(c.conn.stream_table.streams[c_st].recv_state == quic::QuicRecvState.DataRecvd);
        let _ = quic::on_send_ack(c.conn.stream_table.streams[c_st], true);
        assert(quic::on_app_read(c.conn.stream_table.streams[c_st], 4));
    }

    assert(c.conn.stream_table.remote_max_streams_bidi >= 135);
    let cs_idx = find_srv_conn_slot_idx(conn_id);
    assert(cs_idx >= 0 && quic::g_quic_srv_conns[cs_idx].conn.stream_table.streams.len == 0);
    assert(count_active_quic_srv_slabs() == base_slabs);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_MAX_STREAMS_135_OK\n");
}

fn test_stop_sending_halts_tx_and_emits_reset_stream() {
    let base_slabs = count_active_quic_srv_slabs();
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    make_p256_test_creds(cert_pem, key_pem, 0xB2);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);
    var now_ns: u64 = 2000000000;

    var c = TestQuicClient { .. };
    let od: u8[8] = [0xEB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let sc: u8[4] = [0xFB, 0x01, 0x02, 0x03];
    let conn_id = connect_p256_session(ep, srv_fd, srv_port, c, cert_pem[..], key_pem[..], od[..], sc[..], now_ns);
    defer close_test_client(c);
    let sid, _, ok_open = quic::open_local_stream(c.conn.stream_table, true, 65536);
    assert(ok_open && sid == 0);

    client_send_stream_bytes(c, 0, 0, "req", true, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);
    var srv_rx: u8[>..] = [];
    var srv_fin = false;
    assert(quic::quic_server_stream_read(ep, conn_id, 0, srv_rx, srv_fin) == 3 && srv_fin);
    var ev = quic::QuicServerEvent { .. };
    while quic::quic_server_poll_event(ep, ev) {}

    var body_6k: u8[>..] = [];
    for i in 6000 { body_6k.push((i & 0xFF) as u8); }
    let wn, wok = quic::quic_server_stream_write(ep, conn_id, 0, body_6k[..], false);
    assert(wok && wn == 6000);

    // Emit ONLY the first STREAM packet (~1200 bytes), leaving >4500 bytes buffered on server.
    var out_pkt: u8[..1500] = [];
    var out_ip:  u8[..64]   = [];
    var out_p:   u16        = 0;
    assert(quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p));
    client_feed_dgram(c, out_pkt[..], now_ns / 1000);
    let bytes_before_stop = c.stream_rx_contig;
    assert(bytes_before_stop > 0 && bytes_before_stop < 6000);

    // Client sends STOP_SENDING(0, 0x1234). Server MUST stop emitting STREAM frames and emit StreamReset.
    var stop_plain: u8[..32] = [];
    assert(quic::encode_stop_sending_frame(0, 0x1234, stop_plain));
    client_send_1rtt_frames(c, c.conn.dcid[..], stop_plain[..], true, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);

    var saw_reset_ev = false;
    while quic::quic_server_poll_event(ep, ev) {
        if ev.kind == quic::QuicServerEventKind.StreamReset && ev.conn_id == conn_id && ev.stream_id == 0 {
            assert(ev.error_code == 0x1234);
            saw_reset_ev = true;
        }
    }
    assert(saw_reset_ev);

    let w_post, ok_post = quic::quic_server_stream_write(ep, conn_id, 0, "more", true);
    assert(!ok_post && w_post == 0);

    // First server packet after STOP_SENDING carries RESET_STREAM (no further STREAM packets!); simulate drop + PTO retx.
    var post_drop_cnt: i64 = 0;
    while quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p) {
        post_drop_cnt += 1;
    }
    assert(post_drop_cnt == 1 && !c.saw_reset_stream);

    let pto_ns = quic::quic_server_next_timeout_ns(ep);
    assert(pto_ns > now_ns);
    now_ns = pto_ns;
    quic::quic_server_on_timeout(ep, now_ns);
    assert(client_recv_direct_packets(c, ep, now_ns) == 1);
    assert(c.saw_reset_stream && c.last_reset_sid == 0 && c.last_reset_err == 0x1234);
    assert(c.last_reset_final_size == bytes_before_stop);
    assert(c.stream_rx_contig == bytes_before_stop);

    // Client ACKs retransmitted RESET_STREAM; server reclaims stream slot & slabs completely.
    client_send_app_ack_and_fc(c, c.conn.dcid[..], 0, 0, now_ns / 1000);
    assert(drain_udp_into_server(srv_fd, ep, now_ns) == 1);
    let cs_idx = find_srv_conn_slot_idx(conn_id);
    assert(cs_idx >= 0 && quic::g_quic_srv_conns[cs_idx].conn.stream_table.streams.len == 0);
    assert(count_active_quic_srv_slabs() == base_slabs);

    net::tcp_close(srv_fd);
    print("CHECK_QUIC_STOP_SENDING_OK\n");
}

fn verify_quic_ack_and_padding_guards(ep: quic::QuicServerEndpoint&, conn_id: u64, cs_idx: i64) {
    let cs .= quic::g_quic_srv_conns[cs_idx];
    // 1. Coalesced Initial + ACK-only Handshake (!hs_ack_el) pads datagram >= 1200B
    cs.tx_hs_crypto.clear();
    cs.tx_hs_crypto_sent = 0;
    cs.needs_ack_hs = true;
    assert(cs.conn.handshake_space.recv_ranges.try_push(quic::AckInterval {
        smallest: 0,
        largest:  0,
    }));
    cs.conn.bytes_received = 1200;
    cs.conn.bytes_sent = 0;
    cs.peer_max_udp_payload = 1280;
    var dg: u8[..1500] = [];
    assert(quic::try_build_conn_datagram(cs_idx, 1000000000, dg));
    assert(dg.len >= 1200 && !cs.needs_ack_initial && !cs.needs_ack_hs);

    // 2. Preserve needs_ack_initial / needs_ack_hs when encoded ACK exceeds max_plain
    var k: u64 = 2;
    while k <= 20 {
        assert(cs.conn.initial_space.recv_ranges.try_push(quic::AckInterval {
            smallest: k,
            largest:  k,
        }));
        assert(cs.conn.handshake_space.recv_ranges.try_push(quic::AckInterval {
            smallest: k,
            largest:  k,
        }));
        k += 2;
    }
    let hdr_ov = core::add_sat_u64(
        28,
        core::add_sat_u64(cs.conn.dcid.len as u64, cs.conn.scid.len as u64),
    );
    var small_pkt: u8[..1500] = [];
    var dummy_el = false;
    cs.needs_ack_initial = true;
    assert(!quic::emit_crypto_space_packet(
        cs, true, core::add_sat_u64(hdr_ov, 17), 1000, small_pkt, 0, dummy_el,
    ));
    assert(small_pkt.len == 0 && cs.needs_ack_initial);
    cs.needs_ack_hs = true;
    assert(!quic::emit_crypto_space_packet(
        cs, false, core::add_sat_u64(hdr_ov - 1, 17), 1000, small_pkt, 0, dummy_el,
    ));
    assert(small_pkt.len == 0 && cs.needs_ack_hs);

    // 3. try_emit_app_packet enforces plain.len <= max_plain and preserves needs_ack_app
    cs.conn.tx_app_space = cs.conn.tx_initial_space;
    cs.conn.state = quic::QuicConnState.Established;
    var a: u64 = 2;
    while a <= 20 {
        assert(cs.conn.app_space.recv_ranges.try_push(quic::AckInterval {
            smallest: a,
            largest:  a,
        }));
        a += 2;
    }
    cs.needs_ack_app = true;
    small_pkt.clear();
    let app_budget = core::add_sat_u64(19, core::add_sat_u64(cs.conn.dcid.len as u64, 9));
    assert(!quic::try_emit_app_packet(cs, cs_idx, app_budget, 1000, small_pkt, dummy_el));
    assert(small_pkt.len == 0 && cs.needs_ack_app);
    let _ = ep;
    let _ = conn_id;
}

fn test_quic_ack_padding_max_plain_and_aa_pto() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    let srv_port = net::tcp_getsockname_port(srv_fd);
    assert(srv_port > 0);
    var cert_der: u8[..4096] = [];
    build_rsa_leaf_cert_der("fix7.example.test", "fix7.example.test", cert_der);
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    var key_pem: u8[>..] = [];
    build_rsa_pkcs8_pem(key_pem);

    var ep = quic::quic_server_open("\x02h3", 8, 30000);
    defer quic::quic_server_close(ep);

    var cli = TestQuicClient { .. };
    let odcid: u8[8] = [0x91; 8];
    let scid:  u8[8] = [0x92; 8];
    init_test_client(
        cli, "127.0.0.1", "127.0.0.1", srv_port,
        "fix7.example.test", cert_pem[..], odcid[..], scid[..],
    );
    client_send_initial_flight(cli, 1000, true);
    assert(drain_udp_into_server(srv_fd, ep, 1000000000) == 1);
    var ev = quic::QuicServerEvent { .. };
    assert(quic::quic_server_poll_event(ep, ev));
    assert(ev.kind == quic::QuicServerEventKind.NeedSniCredentials);
    assert(quic::quic_server_set_credentials_pem(ep, ev.conn_id, cert_pem[..], key_pem[..]));
    let cs_idx = find_srv_conn_slot_idx(ev.conn_id);
    assert(cs_idx >= 0);

    verify_quic_ack_and_padding_guards(ep, ev.conn_id, cs_idx);

    // Remaining AA budget below oversized lost CRYPTO chunk avoids pto_count spin
    let cs .= quic::g_quic_srv_conns[cs_idx];
    cs.conn.validated_address = false;
    cs.conn.state = quic::QuicConnState.Handshake;
    cs.conn.bytes_received = 1200;
    cs.conn.bytes_sent = 3400; // rem_budget = 200 (>= 128, < 900B retx chunk)
    cs.pto_count = 0;
    cs.sent_chunks.clear();
    assert(cs.sent_chunks.try_push(quic::QuicSentChunk {
        active:     true,
        in_flight:  false,
        retransmit: true,
        space:      quic::PnSpaceId.Handshake,
        kind:       quic::QuicSentChunkKind.CryptoHandshake,
        length:     900,
        ..
    }));
    for step in 5 {
        quic::quic_server_on_timeout(ep, ((step + 5) as u64) * 1000000000);
    }
    assert(cs.pto_count == 0);
    assert(quic::eval_conn_pto(cs, 5000000).mode == quic::PtoTimerMode.AntiAmplification);

    cs.sent_chunks[0].in_flight = true;
    cs.sent_chunks[0].retransmit = false;
    cs.ping_probe_pending = false;
    quic::schedule_pto_probe_in_space(cs, quic::PnSpaceId.Handshake);
    assert(!cs.sent_chunks[0].retransmit && cs.ping_probe_pending);

    net::tcp_close(cli.fd);
    net::tcp_close(srv_fd);
    print("CHECK_QUIC_ACK_PAD_AA_PTO_OK\n");
}

fn test_stateless_version_negotiation() {
    let alpn_h3: u8[3] = [2, 'h', '3'];
    var ep = quic::quic_server_open(alpn_h3[..], 8, 30000);
    let now_ns: u64 = 1000000000;
    let peer_ip = "198.51.100.77";
    let peer_port: u16 = 54321;

    // RFC 9000 §6.1: Undersized unknown-version datagram (< 1200B) MUST NOT trigger Version Negotiation.
    var small_probe: u8[64] = [0; 64];
    small_probe[0] = 0xC0;
    small_probe[1] = 0xBA;
    small_probe[2] = 0xBA;
    small_probe[3] = 0xBA;
    small_probe[4] = 0xBA;
    small_probe[5] = 4;
    small_probe[10] = 4;
    assert(!quic::quic_server_feed_datagram(ep, small_probe[..], peer_ip, peer_port, now_ns));

    var out_pkt: u8[..1500] = [];
    var out_ip:  u8[..64]   = [];
    var out_pt:  u16        = 0;
    assert(!quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_pt));

    // Padded GREASE version probe (1200B, 0xBABABABA) produces Version Negotiation echoing swapped CIDs.
    var grease_probe: u8[1200] = [0; 1200];
    grease_probe[0] = 0xC0;
    grease_probe[1] = 0xBA;
    grease_probe[2] = 0xBA;
    grease_probe[3] = 0xBA;
    grease_probe[4] = 0xBA;
    grease_probe[5] = 4;
    grease_probe[6] = 0xD1;
    grease_probe[7] = 0xD2;
    grease_probe[8] = 0xD3;
    grease_probe[9] = 0xD4;
    grease_probe[10] = 4;
    grease_probe[11] = 0xA1;
    grease_probe[12] = 0xA2;
    grease_probe[13] = 0xA3;
    grease_probe[14] = 0xA4;
    assert(quic::quic_server_feed_datagram(ep, grease_probe[..], peer_ip, peer_port, now_ns));
    assert(quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_pt));
    assert(out_ip[..] == peer_ip && out_pt == peer_port);
    let empty_hdr = quic::QuicHeader {};
    let vn_hdr, ok_vn = quic_internal::parse_quic_version_negotiation(out_pkt[..], empty_hdr);
    assert(ok_vn && vn_hdr.version == 0);
    assert(vn_hdr.dcid[..] == grease_probe[11..15]);
    assert(vn_hdr.scid[..] == grease_probe[6..10]);
    assert(out_pkt.len == 15 + 8);
    assert(!quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_pt));

    // RFC 9000 Section 17.2.1: Long CIDs (> 20 bytes, e.g., 32B DCID and 32B SCID) MUST still produce VN.
    var long_probe: u8[1200] = [0; 1200];
    long_probe[0] = 0xC0;
    long_probe[1] = 0xFA;
    long_probe[2] = 0xCE;
    long_probe[3] = 0xB0;
    long_probe[4] = 0x0C;
    long_probe[5] = 32;
    for i in 32 { long_probe[6 + i] = (0x20 + i) as u8; }
    long_probe[38] = 32;
    for i in 32 { long_probe[39 + i] = (0x80 + i) as u8; }
    out_pkt.clear();
    out_ip.clear();
    out_pt = 0;
    assert(quic::quic_server_feed_datagram(ep, long_probe[..], peer_ip, peer_port, now_ns));
    assert(quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_pt));
    assert(out_ip[..] == peer_ip && out_pt == peer_port);
    assert(out_pkt.len == 1 + 4 + 1 + 32 + 1 + 32 + 8);
    assert((out_pkt[0] & 0x80) != 0 && quic_internal::quic_read_be_u32(out_pkt[1..]) == 0);
    assert(out_pkt[5] == 32 && out_pkt[6..38] == long_probe[39..71]);
    assert(out_pkt[38] == 32 && out_pkt[39..71] == long_probe[6..38]);
    assert(quic_internal::quic_read_be_u32(out_pkt[71..]) == rfc::QUIC_VERSION_1);
    assert(quic_internal::quic_read_be_u32(out_pkt[75..]) == rfc::QUIC_VERSION_2);

    quic::quic_server_close(ep);
    print("CHECK_QUIC_VN_OK\n");
}

fn main() {
    assert(net::tcp_init());
    test_anti_amplification_and_undersized_initial();
    test_concurrent_multi_client_64k_pto_and_close();
    test_server_close_conn_and_threads();
    test_close_drain_lifecycle_reclaim();
    test_aa_unvalidated_spoof_and_1rtt_migration();
    test_window_update_retx_pn_and_sibling_order();
    test_small_tp_and_early_max_stream_data();
    test_ooo_fin_ack_retx_earlier_chunk();
    test_sent_chunks_capacity_and_no_drop();
    test_persistent_max_streams_beyond_128();
    test_stop_sending_halts_tx_and_emits_reset_stream();
    test_quic_ack_padding_max_plain_and_aa_pto();
    test_stateless_version_negotiation();
}

// CHECK: CHECK_QUIC_AA_OK
// CHECK: CHECK_QUIC_ENDPOINT_E2E_OK
// CHECK: CHECK_QUIC_THREADS_OK
// CHECK: CHECK_QUIC_FIX1_DRAIN_OK
// CHECK: CHECK_QUIC_FIX2_AA_MIGRATION_OK
// CHECK: CHECK_QUIC_FIX3_WINDOW_RETX_OK
// CHECK: CHECK_QUIC_FIX4_SMALL_TP_OK
// CHECK: CHECK_QUIC_FIX5_OOO_FIN_OK
// CHECK: CHECK_QUIC_FIX6_SENT_CHUNKS_OK
// CHECK: CHECK_QUIC_MAX_STREAMS_135_OK
// CHECK: CHECK_QUIC_STOP_SENDING_OK
// CHECK: CHECK_QUIC_ACK_PAD_AA_PTO_OK
// CHECK: CHECK_QUIC_VN_OK
