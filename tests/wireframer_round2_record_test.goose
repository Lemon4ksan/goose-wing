// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/wireframer_round2_record_test.goose
// Red Test Suite for Audit Swarm lowlevel-redteam-01 (Round 2: WireFramer).
// Reproduces:
// 1. RFC 8446 §5.4: Empty record handling (all-zeros vs valid empty application data vs forbidden empty handshake/alert/CCS)
// 2. RFC 8446 §5.1 & §5.4: Maximum plaintext and inner plaintext bounds (16624B max inner plaintext)
// 3. RFC 8446 §5.2: TLSCiphertext minimum payload framing (< 17 bytes) in header encoding & parsing
// 4. RFC 8446 §5.2: Outer TLSCiphertext ContentType restriction (only application_data 0x17 or CCS 0x14 allowed)
// 5. OpenSSL #31533: Early data skipped volume integer overflow defense

import std;
import core from "..";
import wing from "..";

fn test_round2_padding_and_empty_record_invariants(t: core::T&) {
    t.run("RFC 8446 §5.4: Empty records forbidden for handshake, alert, and CCS") { sub =>
        // Vector 1: Decrypted payload with 0 content bytes and inner type Handshake (0x16)
        // [0x16] -> content_len = 0, inner_type = 0x16
        // RFC 8446 §5.4: "Endpoints MUST NOT send empty records with types other than application_data."
        let empty_hs: u8[1] = [0x16];
        let _, _, alert_hs = wing::unpack_tls_inner_plaintext(empty_hs[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_hs),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "empty handshake record must yield unexpected_message (RFC 8446 §5.4)",
        );

        // Vector 2: Decrypted payload with 0 content bytes and inner type Alert (0x15)
        let empty_alert: u8[1] = [0x15];
        let _, _, alert_al = wing::unpack_tls_inner_plaintext(empty_alert[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_al),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "empty alert record must yield unexpected_message (RFC 8446 §5.4)",
        );

        // Vector 3: Decrypted payload with 0 content bytes and inner type ChangeCipherSpec (0x14)
        let empty_ccs: u8[1] = [0x14];
        let _, _, alert_ccs = wing::unpack_tls_inner_plaintext(empty_ccs[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_ccs),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "empty CCS record must yield unexpected_message (RFC 8446 §5.4)",
        );

        // Vector 4: Valid empty Application Data record [0x17] + padding zeroes
        // RFC 8446 §5.4: "An empty TLSInnerPlaintext (content of length 0) for application_data MAY be sent"
        let valid_empty_app: u8[4] = [0x17, 0x00, 0x00, 0x00];
        let pt, inner_type, alert_app = wing::unpack_tls_inner_plaintext(valid_empty_app[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_app),
            wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify),
            "empty application_data record is permitted to conceal traffic",
        );
        sub.assert_eq(inner_type, 0x17, "extracted inner type is application_data (0x17)");
        sub.assert_eq(pt.len, 0, "plaintext length is 0");
    };

    t.run("RFC 8446 §5.1 & §5.4: Inner plaintext maximum limit (16624 bytes)") { sub =>
        // TLSCiphertext max is 16640 bytes. AEAD tag is 16 bytes.
        // Therefore, decrypted TLSInnerPlaintext cannot exceed 16640 - 16 = 16624 bytes.
        // A decrypted payload of 16625 bytes MUST be rejected with RecordOverflow.
        var oversized_inner: u8[16625] = [0x00; 16625];
        oversized_inner[10] = 0x17; // 10 bytes content + type + 16614 padding zeroes = 16625B
        let _, _, alert_ov = wing::unpack_tls_inner_plaintext(oversized_inner[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_ov),
            wing::tls_alert_to_u8(wing::TlsAlert.RecordOverflow),
            "decrypted inner plaintext > 16624 bytes yields record_overflow",
        );
    };
}

fn test_round2_framing_and_dos_invariants(t: core::T&) {
    t.run("RFC 8446 §5.2: TLSCiphertext header minimum size and outer type restrictions") { sub =>
        var out: u8[>..] = [];

        // 1. Ciphertext length < 17 bytes (tag 16 + type 1) is impossible in TLS 1.3
        sub.assert_false(
            wing::encode_tls_ciphertext_header(out, 0x17, 16),
            "encoder rejects ciphertext length < 17 bytes",
        );
        sub.assert_false(
            wing::encode_tls_ciphertext_header(out, 0x17, 0),
            "encoder rejects ciphertext length of 0 bytes",
        );

        // 2. Outer ContentType in TLS 1.3 TLSCiphertext MUST be application_data (0x17) or CCS (0x14)
        // Handshake (0x16) or Alert (0x15) outer types are forbidden for ciphertext records
        sub.assert_false(
            wing::encode_tls_ciphertext_header(out, 0x16, 100),
            "encoder rejects outer handshake (0x16) type for ciphertext",
        );
        sub.assert_false(
            wing::encode_tls_ciphertext_header(out, 0x15, 100),
            "encoder rejects outer alert (0x15) type for ciphertext",
        );

        // 3. Valid encoding: application_data (0x17) with length 17
        sub.assert_true(
            wing::encode_tls_ciphertext_header(out, 0x17, 17),
            "encoder accepts valid ciphertext header",
        );
    };

    t.run("OpenSSL #31533: Early data skipped volume overflow protection") { sub =>
        var filter = wing::RecordFilterState { empty_records_count: 0, early_data_skipped_bytes: 16000 };

        // Exceeding 16384 bytes within normal bounds
        let res_exceed = wing::check_record_payload_length(filter, 500, true);
        sub.assert_eq(
            wing::tls_alert_to_u8(res_exceed),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "early data exceeding 16384 rejected",
        );

        // Integer overflow attack: early_data_skipped_bytes close to i64::MAX wrapping to negative
        var filter_overflow = wing::RecordFilterState {
            empty_records_count: 0,
            early_data_skipped_bytes: 0x7FFFFFFFFFFFFFFF - 10,
        };
        let res_overflow = wing::check_record_payload_length(filter_overflow, 100, true);
        sub.assert_eq(
            wing::tls_alert_to_u8(res_overflow),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "integer overflow in early data skipped volume rejected",
        );
    };
}

fn main() {
    var runner = core::new_runner("WireFramer Round 2 Test Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 8446 Padding, All-Zero & InnerPlaintext Invariants", test_round2_padding_and_empty_record_invariants);
    core::run_case(runner, "2. RFC 8446 Framing, Minimum Size & DoS Invariants", test_round2_framing_and_dos_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
