// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/wireframer_round1_record_test.goose
// Red Test Suite for Audit Swarm lowlevel-redteam-01 (Round 1: WireFramer).
// Reproduces wire framing vulnerabilities in ByteCursor, ByteBuilder, and TLS 1.3 Record Layer:
// - WING-BUG-WF-01:
//   1. ByteCursor Length-Prefixed Underflow & Cursor Desync (Go framing CVE-2021-34558 / Go #44913)
//   2. ByteBuilder Negative Length Underflow & Memory BCE Hazards
//   3. Sequence Number 2^64 - 1 UnexpectedMessage Alert Violation (RFC 8446 §5.3 / OpenSSL #30879)
//   4. RFC 8446 §6 Standard Alert Code (47: illegal_parameter) Non-Recognition
//   5. TLSCiphertext Truncated Payload (< 17 bytes) Framing DecodeError Bypass (RFC 8446 §5.2, §5.4)

import std;
import core from "..";
import wing from "..";

fn test_wireframer_cursor_and_builder_framing(t: core::T&) {
    t.run("ByteCursor length-prefixed underflow preserves cursor without desynchronization") { sub =>
        // Vector 1: Truncated u8 length-prefixed field
        // Header declares length 5, but only 2 payload bytes exist (total 3 bytes)
        let truncated_u8: u8[3] = [0x05, 0xAA, 0xBB];
        var c8 = wing::cursor_from(truncated_u8[..]);
        var out8 = wing::cursor_from(truncated_u8[..0]);

        let ok8 = wing::get_u8_length_prefixed(c8, out8);
        sub.assert_false(ok8, "u8 length-prefixed underflow returns false");
        // On underflow, cursor MUST NOT be mutated or consume the length prefix!
        sub.assert_eq(wing::cursor_len(c8), 3, "cursor position preserved on u8 underflow");

        // Vector 2: Truncated u16 length-prefixed field
        // Header declares length 10, but only 2 payload bytes exist (total 4 bytes)
        let truncated_u16: u8[4] = [0x00, 0x0A, 0xAA, 0xBB];
        var c16 = wing::cursor_from(truncated_u16[..]);
        var out16 = wing::cursor_from(truncated_u16[..0]);

        let ok16 = wing::get_u16_length_prefixed(c16, out16);
        sub.assert_false(ok16, "u16 length-prefixed underflow returns false");
        sub.assert_eq(wing::cursor_len(c16), 4, "cursor position preserved on u16 underflow");

        // Vector 3: Truncated u24 length-prefixed field
        // Header declares length 100, but only 2 payload bytes exist (total 5 bytes)
        let truncated_u24: u8[5] = [0x00, 0x00, 0x64, 0xAA, 0xBB];
        var c24 = wing::cursor_from(truncated_u24[..]);
        var out24 = wing::cursor_from(truncated_u24[..0]);

        let ok24 = wing::get_u24_length_prefixed(c24, out24);
        sub.assert_false(ok24, "u24 length-prefixed underflow returns false");
        sub.assert_eq(wing::cursor_len(c24), 5, "cursor position preserved on u24 underflow");
    };

    t.run("ByteBuilder negative length underflow & bounds safety") { sub =>
        // Vector 1: u8 prefix backpatching on truncated buffer
        var b8 = wing::builder_init();
        sub.assert_true(wing::start_u8_prefix(b8), "start u8 prefix");
        // Buffer is externally cleared/truncated after start_prefix
        b8.buf.clear();
        let ok_finish8 = wing::finish_u8_prefix(b8);
        sub.assert_false(ok_finish8, "finish_u8_prefix on truncated buffer must fail safely");

        // Vector 2: u16 prefix backpatching on truncated buffer
        var b16 = wing::builder_init();
        sub.assert_true(wing::start_u16_prefix(b16), "start u16 prefix");
        b16.buf.clear();
        let ok_finish16 = wing::finish_u16_prefix(b16);
        sub.assert_false(ok_finish16, "finish_u16_prefix on truncated buffer must fail safely");

        // Vector 3: u24 prefix backpatching on truncated buffer
        var b24 = wing::builder_init();
        sub.assert_true(wing::start_u24_prefix(b24), "start u24 prefix");
        b24.buf.clear();
        let ok_finish24 = wing::finish_u24_prefix(b24);
        sub.assert_false(ok_finish24, "finish_u24_prefix on truncated buffer must fail safely");
    };
}

fn test_wireframer_tls_record_invariants(t: core::T&) {
    t.run("Sequence number 2^64 - 1 exhaustion yields unexpected_message (RFC 8446 §5.3)") { sub =>
        let key: u8[16] = [0x01; 16];
        let iv: u8[12] = [0x02; 12];
        let hdr: u8[5] = [0x17, 0x03, 0x03, 0x00, 0x11];
        let payload: u8[17] = [0xAA; 17];
        var out: u8[>..] = [];

        // When sequence number reaches 2^64 - 1 (0xFFFFFFFFFFFFFFFF), decryption MUST terminate
        // with unexpected_message alert per RFC 8446 §5.3 (not internal_error).
        let _, alert = wing::tls_record_decrypt_aes128_gcm(key, iv, 0xFFFFFFFFFFFFFFFF, hdr[..], payload[..], out);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "seq 2^64 - 1 exhaustion returns unexpected_message alert (code 10)",
        );
    };

    t.run("RFC 8446 §6 alert code 47 (illegal_parameter) is recognized") { sub =>
        // Code 47 is illegal_parameter, the primary TLS 1.3 protocol violation alert.
        let _, ok_47 = wing::u8_to_tls_alert(47);
        sub.assert_true(ok_47, "alert code 47 (illegal_parameter) is recognized");
    };

    t.run("TLSCiphertext payload < 17 bytes rejected with DecodeError (RFC 8446 §5.2, §5.4)") { sub =>
        let key: u8[16] = [0x01; 16];
        let iv: u8[12] = [0x02; 12];
        let hdr: u8[5] = [0x17, 0x03, 0x03, 0x00, 0x10];
        // 16-byte payload has AEAD tag but 0 bytes of TLSInnerPlaintext (missing ContentType)
        let payload_16: u8[16] = [0xAA; 16];
        var out: u8[>..] = [];

        let _, alert = wing::tls_record_decrypt_aes128_gcm(key, iv, 0, hdr[..], payload_16[..], out);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert),
            wing::tls_alert_to_u8(wing::TlsAlert.DecodeError),
            "record payload < 17 bytes fails with DecodeError",
        );
    };
}

fn main() {
    var runner = core::new_runner("WireFramer Round 1 Test Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. ByteCursor & ByteBuilder Framing Invariants", test_wireframer_cursor_and_builder_framing);
    core::run_case(runner, "2. TLS Record Layer Framing & Alert Invariants", test_wireframer_tls_record_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
