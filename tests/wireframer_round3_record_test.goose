// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/wireframer_round3_record_test.goose
// Red Test Suite for Audit Swarm lowlevel-redteam-01 (Round 3: WireFramer).
// Reproduces:
// 1. RFC 8446 Appendix D.4 & §5.4: Protected ChangeCipherSpec (CCS) inner type rejection
// 2. RFC 8446 Appendix D.4 & OpenSSL #10065 / CVE-2020-1967: CCS handshake phase & flooding protection
// 3. RFC 9001 §5.4.2: QUIC Header Protection sample bounds checking (pn_offset == 0 rejection)
// 4. RFC 9000 §19.6: QUIC CRYPTO frame offset varint 2^62 - 1 maximum bounds overflow
// 5. RFC 9001 §4 & RFC 9000 §19.6: QUIC CRYPTO gateway empty frame and buffer quota limits

import std;
import core from "..";
import wing from "..";

fn test_round3_ccs_and_protected_record_invariants(t: core::T&) {
    t.run("RFC 8446 §5.4 & Appendix D.4: Protected ChangeCipherSpec inner type strictly forbidden") { sub =>
        // Vector 1: Decrypted inner plaintext with ContentType = ChangeCipherSpec (0x14)
        // RFC 8446 Appendix D.4: "Implementations which receive a protected change_cipher_spec record
        // MUST abort the handshake with an unexpected_message alert."
        // Inner ContentType MUST only be alert (21), handshake (22), or application_data (23).
        let protected_ccs: u8[2] = [0x01, 0x14];
        let _, _, alert_pccs = wing::unpack_tls_inner_plaintext(protected_ccs[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_pccs),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "protected CCS record MUST be rejected with unexpected_message alert (RFC 8446 App D.4)",
        );
    };

    t.run("RFC 8446 Appendix D.4 & OpenSSL #10065 / CVE-2020-1967: CCS phase and flooding protection") { sub =>
        var filter = wing::RecordFilterState {
            empty_records_count: 0,
            early_data_skipped_bytes: 0,
            ccs_count: 0,
        };
        let valid_ccs: u8[1] = [0x01];

        // 1. CCS received before ClientHello or post-handshake (handshake_active == false)
        let alert_inactive = wing::check_change_cipher_spec_record(filter, valid_ccs[..], false);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_inactive),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "CCS received outside active handshake rejected with unexpected_message",
        );

        // 2. First CCS received during active handshake (handshake_active == true) succeeds
        let alert_first = wing::check_change_cipher_spec_record(filter, valid_ccs[..], true);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_first),
            wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify),
            "first valid CCS during handshake is accepted",
        );
        sub.assert_eq(filter.ccs_count, 1, "ccs_count is incremented to 1");

        // 3. Second CCS received during handshake (CCS flooding / DoS attack: OpenSSL #10065)
        let alert_second = wing::check_change_cipher_spec_record(filter, valid_ccs[..], true);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_second),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "second CCS record rejected with unexpected_message (OpenSSL #10065 flood prevention)",
        );

        // 4. Third CCS record also rejected
        let alert_third = wing::check_change_cipher_spec_record(filter, valid_ccs[..], true);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_third),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "third CCS record rejected with unexpected_message",
        );

        // 5. Malformed CCS payloads in stateful check
        var filter_fresh = wing::RecordFilterState { empty_records_count: 0, early_data_skipped_bytes: 0, ccs_count: 0 };
        let empty_payload: u8[0] = [];
        let alert_empty = wing::check_change_cipher_spec_record(filter_fresh, empty_payload[..], true);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_empty),
            wing::tls_alert_to_u8(wing::TlsAlert.DecodeError),
            "empty CCS payload rejected with decode_error",
        );

        let bad_val: u8[1] = [0x02];
        let alert_bad_val = wing::check_change_cipher_spec_record(filter_fresh, bad_val[..], true);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_bad_val),
            wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage),
            "invalid CCS byte value rejected with unexpected_message",
        );
    };
}

fn test_round3_quic_crypto_and_framing_invariants(t: core::T&) {
    t.run("RFC 9001 §5.4.2: QUIC Header Protection sample offset validation") { sub =>
        var pkt: u8[24] = [0; 24];
        for i in 24 { pkt[i] = i as u8; }

        // pn_offset == 0 is impossible in QUIC (byte 0 is header flags)
        let _, ok_zero = wing::quic_extract_hp_sample(pkt[..], 0);
        sub.assert_false(ok_zero, "quic_extract_hp_sample rejects pn_offset == 0");

        // Valid packet with pn_offset == 1
        let sample, ok_valid = wing::quic_extract_hp_sample(pkt[..], 1);
        sub.assert_true(ok_valid, "quic_extract_hp_sample accepts valid pn_offset == 1");
        sub.assert_eq(sample.len, 16, "extracted sample is 16 bytes");
        sub.assert_eq(sample[0], 5, "sample begins at offset pn_offset + 4 = 5");
    };

    t.run("RFC 9000 §19.6: QUIC CRYPTO frame 2^62 - 1 varint overflow bounds") { sub =>
        var stream = wing::new_quic_crypto_stream();
        let frame: u8[4] = [0x11, 0x22, 0x33, 0x44];

        // 1. Offset exceeding 2^62 - 1 (RFC 9000 §19.6: maximum offset is 2^62 - 1)
        // 0x3FFFFFFFFFFFFFFF = 2^62 - 1
        let ok_max, _ = wing::quic_crypto_stream_ingest(stream, 0x4000000000000000, frame[..]);
        sub.assert_false(ok_max, "quic_crypto_stream_ingest rejects offset >= 2^62");

        // 2. Offset + len exceeding 2^62 - 1
        var stream2 = wing::new_quic_crypto_stream();
        stream2.consumed_offset = 0x3FFFFFFFFFFFFFFF;
        let ok_end_ovf, _ = wing::quic_crypto_stream_ingest(stream2, 0x3FFFFFFFFFFFFFFF, frame[..]);
        sub.assert_false(ok_end_ovf, "quic_crypto_stream_ingest rejects offset + len > 2^62 - 1");
    };

    t.run("RFC 9001 §4: QUIC CRYPTO gateway empty frame and length quota bounds") { sub =>
        var conn = wing::new_quic_crypto_conn();
        conn.read_level = wing::QuicEncryptionLevel.Handshake;

        // 1. Empty CRYPTO frame (data.len == 0) is invalid protocol syntax
        let empty_data: u8[0] = [];
        let alert_empty = wing::provide_quic_data(conn, wing::QuicEncryptionLevel.Handshake, empty_data[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_empty),
            wing::tls_alert_to_u8(wing::TlsAlert.DecodeError),
            "empty CRYPTO frame rejected with decode_error",
        );

        // 2. Oversized CRYPTO flight exceeding MAX_QUIC_CRYPTO_BUFFER_LEN (16384 bytes)
        var oversized: u8[16385] = [0x01; 16385];
        let alert_ovf = wing::provide_quic_data(conn, wing::QuicEncryptionLevel.Handshake, oversized[..]);
        sub.assert_eq(
            wing::tls_alert_to_u8(alert_ovf),
            wing::tls_alert_to_u8(wing::TlsAlert.RecordOverflow),
            "oversized CRYPTO data > 16384 bytes rejected with record_overflow",
        );
    };
}

fn main() {
    var runner = core::new_runner("WireFramer Round 3 Test Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 8446 CCS Invariants & Flood Protection", test_round3_ccs_and_protected_record_invariants);
    core::run_case(runner, "2. RFC 9001 QUIC Crypto Gateway & Stream Bounds", test_round3_quic_crypto_and_framing_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
