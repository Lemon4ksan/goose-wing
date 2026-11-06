// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_tls_bug_fixes.goose
// Regression tests for TLS bug fixes: ALPN validation, KeyUpdate bounds, and Ciphertext header type.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // ---- 1. Bug 1: Malformed ALPN extension in ClientHello (RFC 7301 §3.1) ----
    // Malformed 1-byte ALPN extension MUST be rejected (return false)
    let malformed_alpn_1b: u8[1] = [0x00];
    var out_alpn: u8[..32] = [];
    let ok1 = wing::select_server_alpn_from_ext(malformed_alpn_1b[..], "h2", out_alpn);
    assert(!ok1); // MUST fail on malformed 1-byte ALPN extension!
    print("TLS_ALPN_REJECT_MALFORMED_1B: OK");

    // Malformed 2-byte ALPN extension MUST also be rejected (empty list length)
    let malformed_alpn_2b: u8[2] = [0x00, 0x00];
    let ok2 = wing::select_server_alpn_from_ext(malformed_alpn_2b[..], "h2", out_alpn);
    assert(!ok2); // MUST fail on malformed 2-byte ALPN extension!
    print("TLS_ALPN_REJECT_MALFORMED_2B: OK");

    // Valid ALPN extension with "h2" (len=2: 0x00, 0x03, 0x02, 'h', '2') MUST succeed
    let valid_alpn: u8[5] = [0x00, 0x03, 0x02, 'h', '2'];
    let ok3 = wing::select_server_alpn_from_ext(valid_alpn[..], "h2", out_alpn);
    assert(ok3);
    assert(out_alpn == "h2");
    print("TLS_ALPN_ACCEPT_VALID: OK");

    // ---- 2. Bug 2: encode_key_update bounded array truncation (GOOSE-BUG-2) ----
    // Zero-capacity destination buffer MUST cause encode_key_update to fail closed (false)
    var zero_buf: u8[..0] = [];
    let ok_ku_fail = wing::encode_key_update(zero_buf, 0);
    assert(!ok_ku_fail); // MUST fail closed when buffer has no remaining capacity!
    print("TLS_KEY_UPDATE_REJECT_NOCAP: OK");

    var normal_buf: u8[..4] = [];
    let ok_ku_succ = wing::encode_key_update(normal_buf, 0);
    assert(ok_ku_succ);
    assert(normal_buf.len == 1 && normal_buf[0] == 0);
    print("TLS_KEY_UPDATE_ACCEPT_VALID: OK");

    // ---- 3. Bug 3: encode_tls_ciphertext_header rejecting ChangeCipherSpec outer type (RFC 8446 §5.2) ----
    // Outer content type in TLS 1.3 TLSCiphertext is strictly application_data (0x17).
    // ChangeCipherSpec (0x14) is an unencrypted record and MUST NOT be accepted as ciphertext header!
    var hdr_buf: u8[..16] = [];
    let ok_ccs_hdr = wing::encode_tls_ciphertext_header(hdr_buf, rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 32);
    assert(!ok_ccs_hdr); // MUST reject ChangeCipherSpec as ciphertext header!
    print("TLS_CIPHERTEXT_HDR_REJECT_CCS: OK");

    let ok_app_hdr = wing::encode_tls_ciphertext_header(hdr_buf, rfc::TLS_CONTENT_APPLICATION_DATA, 32);
    assert(ok_app_hdr);
    print("TLS_CIPHERTEXT_HDR_ACCEPT_APP: OK");
}

// CHECK: TLS_ALPN_REJECT_MALFORMED_1B: OK
// CHECK: TLS_ALPN_REJECT_MALFORMED_2B: OK
// CHECK: TLS_ALPN_ACCEPT_VALID: OK
// CHECK: TLS_KEY_UPDATE_REJECT_NOCAP: OK
// CHECK: TLS_KEY_UPDATE_ACCEPT_VALID: OK
// CHECK: TLS_CIPHERTEXT_HDR_REJECT_CCS: OK
// CHECK: TLS_CIPHERTEXT_HDR_ACCEPT_APP: OK
