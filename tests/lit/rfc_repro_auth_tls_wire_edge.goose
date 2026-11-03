// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_tls_wire_edge.goose
// RFC 8446 TLS 1.3 Handshake Extension Syntax, CertificateRequest Invariants & CertificateVerify.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // ---- 1. RFC 8446 Section 4.2: Duplicate Extension in CertificateRequest -
    // RFC 8446 Section 4.2: Extensions - There MUST NOT be more than one extension of the same type in a given extension block.
    // Wire payload with ctx_len=0, extensions containing TWO signature_algorithms (0x000D) extensions.
    let cr_duplicate_sig_algs: u8[19] = [
        0x00,                   // ctx_len = 0
        0x00, 0x10,             // extensions length = 16 bytes
        // Extension 1: signature_algorithms (0x000D)
        0x00, 0x0D,             // ext_type = 13
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02,             // list_len = 2
        0x04, 0x03,             // ecdsa_secp256r1_sha256
        // Extension 2: duplicate signature_algorithms (0x000D) - STRICTLY FORBIDDEN
        0x00, 0x0D,             // ext_type = 13 (duplicate!)
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02,             // list_len = 2
        0x08, 0x07,             // ed25519
    ];
    var cr1 = wing::CertificateRequestMsg { .. };
    let ok_dup = wing::parse_certificate_request(cr_duplicate_sig_algs[..], false, cr1);
    assert(!ok_dup); // MUST REJECT duplicate extensions in CertificateRequest!
    print("TLS_CR_REJECT_DUPLICATE_EXT: OK");

    // ---- 2. RFC 8446 Section 4.2 Table: Forbidden Extension in CertificateRequest -
    // RFC 8446 Section 4.2: Extensions - If an implementation receives an extension which it recognizes and which is not specified for the message in which it appears, it MUST abort the handshake with an "illegal_parameter" alert.
    // Wire payload with ctx_len=0, valid signature_algorithms + FORBIDDEN key_share (0x0033 = 51)
    let cr_forbidden_key_share: u8[19] = [
        0x00,                   // ctx_len = 0
        0x00, 0x10,             // extensions length = 16 bytes
        // Extension 1: valid signature_algorithms
        0x00, 0x0D,             // ext_type = 13
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02,             // list_len = 2
        0x04, 0x03,             // ecdsa_secp256r1_sha256
        // Extension 2: key_share (51) - forbidden in CertificateRequest per Section 4.2 Table
        0x00, 0x33,             // ext_type = 51 (key_share)
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02, 0xAA, 0xBB, // dummy share data
    ];
    var cr2 = wing::CertificateRequestMsg { .. };
    let ok_forbidden_cr = wing::parse_certificate_request(cr_forbidden_key_share[..], false, cr2);
    assert(!ok_forbidden_cr); // MUST REJECT forbidden extension in CertificateRequest!
    print("TLS_CR_REJECT_FORBIDDEN_EXT: OK");

    // ---- 3. RFC 8446 Section 4.2 Table: Forbidden Extension in NewSessionTicket -
    // RFC 8446 Section 4.2: Extensions - If an implementation receives an extension which it recognizes and which is not specified for the message in which it appears, it MUST abort the handshake with an "illegal_parameter" alert.
    // Wire payload with valid NST containing certificate_authorities (ext_type 47 = 0x002F) - FORBIDDEN in NST!
    let nst_forbidden_ext: u8[23] = [
        0x00, 0x00, 0x0E, 0x10, // ticket_lifetime = 3600
        0x00, 0x00, 0x00, 0x01, // ticket_age_add = 1
        0x01, 0xAA,             // ticket_nonce<0..255>: len=1, nonce=[0xAA]
        0x00, 0x02, 0xBB, 0xCC, // ticket<1..2^16-1>: len=2, ticket=[0xBB, 0xCC]
        0x00, 0x07,             // extensions length = 7 bytes
        // Extension: certificate_authorities (47) - forbidden in NewSessionTicket
        0x00, 0x2F,             // ext_type = 47
        0x00, 0x03,             // ext_len = 3
        0x00, 0x01, 0x00,       // authorities data
    ];
    var nst1 = wing::NewSessionTicketMsg { .. };
    let ok_nst_forbidden = wing::parse_new_session_ticket(nst_forbidden_ext[..], nst1);
    assert(!ok_nst_forbidden); // MUST REJECT forbidden extension in NewSessionTicket!
    print("TLS_NST_REJECT_FORBIDDEN_EXT: OK");

    // ---- 4. RFC 8446 Section 4.4.3: Official CertificateVerify Test Vector -
    // RFC 8446 Section 4.4.3: Certificate Verify - The digital signature is then computed over the concatenation of: 64 spaces, context string, separator 0x00, content to be signed.
    var transcript_32: u8[32]  = [0x01; 32];
    var msg_buf:       u8[160] = [0; 160];
    let msg_len, ok_msg = wing::build_certificate_verify_message(true, transcript_32[..], msg_buf[..]);
    assert(ok_msg);
    assert(msg_len == 130);

    // Verify 64 spaces (0x20)
    for i in 64 { assert(msg_buf[i] == 0x20); }

    // Verify Context string: "TLS 1.3, server CertificateVerify" (33 bytes)
    let expected_ctx = "TLS 1.3, server CertificateVerify";
    for i in expected_ctx.len {
        assert(msg_buf[64 + i] == expected_ctx[i]);
    }

    // Verify separator 0x00
    assert(msg_buf[64 + expected_ctx.len] == 0x00);

    // Verify transcript hash bytes (32 bytes of 0x01)
    let hash_start = 64 + expected_ctx.len + 1;
    for i in 32 {
        assert(msg_buf[hash_start + i] == 0x01);
    }
    print("TLS_CERT_VERIFY_VECTOR: OK");
}

// CHECK: TLS_CR_REJECT_DUPLICATE_EXT: OK
// CHECK: TLS_CR_REJECT_FORBIDDEN_EXT: OK
// CHECK: TLS_NST_REJECT_FORBIDDEN_EXT: OK
// CHECK: TLS_CERT_VERIFY_VECTOR: OK
