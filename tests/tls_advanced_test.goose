// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: TLS 1.3 Record Layer, ECH, mTLS, and PKI Extensions Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: tls_record_framing ---
// tests/wireframer_round1_record_test.goose
// Red Test Suite for Audit Swarm lowlevel-redteam-01 (Round 1: WireFramer).
// Reproduces wire framing vulnerabilities in ByteCursor, ByteBuilder, and TLS 1.3 Record Layer:
// - WING-BUG-WF-01:
//   1. ByteCursor Length-Prefixed Underflow & Cursor Desync (Go framing CVE-2021-34558 / Go #44913)
//   2. ByteBuilder Negative Length Underflow & Memory BCE Hazards
//   3. Sequence Number 2^64 - 1 UnexpectedMessage Alert Violation (RFC 8446 §5.3 / OpenSSL #30879)
//   4. RFC 8446 §6 Standard Alert Code (47: illegal_parameter) Non-Recognition
//   5. TLSCiphertext Truncated Payload (< 17 bytes) Framing DecodeError Bypass (RFC 8446 §5.2, §5.4)

// ----------------------------------------------------------------------------
// 1. ByteCursor & ByteBuilder Framing Invariants
// ----------------------------------------------------------------------------
fn test_wireframer_cursor_and_builder_framing(t: lit::T&) {
    t.run("ByteCursor length-prefixed underflow preserves cursor without desynchronization") { sub =>
        // Vector 1: Truncated u8 length-prefixed field
        // Header declares length 5, but only 2 payload bytes exist (total 3 bytes)
        let truncated_u8: u8[3] = [0x05, 0xAA, 0xBB];
        var c8 = core::cursor_from(truncated_u8[..]);
        var out8 = core::cursor_from(truncated_u8[..0]);

        let ok8 = core::get_u8_length_prefixed(c8, out8);
        sub.assert_false(ok8, "u8 length-prefixed underflow returns false");
        // On underflow, cursor MUST NOT be mutated or consume the length prefix!
        sub.assert_eq(core::cursor_len(c8), 3, "cursor position preserved on u8 underflow");

        // Vector 2: Truncated u16 length-prefixed field
        // Header declares length 10, but only 2 payload bytes exist (total 4 bytes)
        let truncated_u16: u8[4] = [0x00, 0x0A, 0xAA, 0xBB];
        var c16 = core::cursor_from(truncated_u16[..]);
        var out16 = core::cursor_from(truncated_u16[..0]);

        let ok16 = core::get_u16_length_prefixed(c16, out16);
        sub.assert_false(ok16, "u16 length-prefixed underflow returns false");
        sub.assert_eq(core::cursor_len(c16), 4, "cursor position preserved on u16 underflow");

        // Vector 3: Truncated u24 length-prefixed field
        // Header declares length 100, but only 2 payload bytes exist (total 5 bytes)
        let truncated_u24: u8[5] = [0x00, 0x00, 0x64, 0xAA, 0xBB];
        var c24 = core::cursor_from(truncated_u24[..]);
        var out24 = core::cursor_from(truncated_u24[..0]);

        let ok24 = core::get_u24_length_prefixed(c24, out24);
        sub.assert_false(ok24, "u24 length-prefixed underflow returns false");
        sub.assert_eq(core::cursor_len(c24), 5, "cursor position preserved on u24 underflow");
    };

    t.run("ByteBuilder negative length underflow & bounds safety") { sub =>
        // Vector 1: u8 prefix backpatching on truncated buffer
        var b8 = core::builder_init();
        sub.assert_true(core::start_u8_prefix(b8), "start u8 prefix");
        // Buffer is externally cleared/truncated after start_prefix
        b8.buf.clear();
        let ok_finish8 = core::finish_u8_prefix(b8);
        sub.assert_false(ok_finish8, "finish_u8_prefix on truncated buffer must fail safely");

        // Vector 2: u16 prefix backpatching on truncated buffer
        var b16 = core::builder_init();
        sub.assert_true(core::start_u16_prefix(b16), "start u16 prefix");
        b16.buf.clear();
        let ok_finish16 = core::finish_u16_prefix(b16);
        sub.assert_false(ok_finish16, "finish_u16_prefix on truncated buffer must fail safely");

        // Vector 3: u24 prefix backpatching on truncated buffer
        var b24 = core::builder_init();
        sub.assert_true(core::start_u24_prefix(b24), "start u24 prefix");
        b24.buf.clear();
        let ok_finish24 = core::finish_u24_prefix(b24);
        sub.assert_false(ok_finish24, "finish_u24_prefix on truncated buffer must fail safely");
    };
}

// ----------------------------------------------------------------------------
// 2. TLS Record Layer Framing & Alert Invariants
// ----------------------------------------------------------------------------
fn test_wireframer_tls_record_invariants(t: lit::T&) {
    t.run("Sequence number 2^64 - 1 exhaustion yields unexpected_message (RFC 8446 §5.3)") { sub =>
        let key:     u8[16] = [0x01; 16];
        let iv:      u8[12] = [0x02; 12];
        let hdr:     u8[5]  = [0x17, 0x03, 0x03, 0x00, 0x11];
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
        let iv:  u8[12] = [0x02; 12];
        let hdr: u8[5]  = [0x17, 0x03, 0x03, 0x00, 0x10];
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

// --- Component: tls_record_padding ---
// tests/wireframer_round2_record_test.goose
// Red Test Suite for Audit Swarm lowlevel-redteam-01 (Round 2: WireFramer).
// Reproduces:
// 1. RFC 8446 §5.4: Empty record handling (all-zeros vs valid empty application data vs forbidden empty handshake/alert/CCS)
// 2. RFC 8446 §5.1 & §5.4: Maximum plaintext and inner plaintext bounds (16624B max inner plaintext)
// 3. RFC 8446 §5.2: TLSCiphertext minimum payload framing (< 17 bytes) in header encoding & parsing
// 4. RFC 8446 §5.2: Outer TLSCiphertext ContentType restriction (only application_data 0x17 or CCS 0x14 allowed)
// 5. OpenSSL #31533: Early data skipped volume integer overflow defense

// ----------------------------------------------------------------------------
// 3. RFC 8446 Padding, All-Zero & InnerPlaintext Invariants
// ----------------------------------------------------------------------------
fn test_round2_padding_and_empty_record_invariants(t: lit::T&) {
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

// ----------------------------------------------------------------------------
// 4. RFC 8446 Framing, Minimum Size & DoS Invariants
// ----------------------------------------------------------------------------
fn test_round2_framing_and_dos_invariants(t: lit::T&) {
    t.run("RFC 8446 §5.2: TLSCiphertext header minimum size and outer type restrictions") { sub =>
        var out: u8[..64] = [];

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
            empty_records_count:      0,
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

// --- Component: tls_record_alerts ---
// tests/wireframer_round3_record_test.goose
// Red Test Suite for Audit Swarm lowlevel-redteam-01 (Round 3: WireFramer).
// Reproduces:
// 1. RFC 8446 Appendix D.4 & §5.4: Protected ChangeCipherSpec (CCS) inner type rejection
// 2. RFC 8446 Appendix D.4 & OpenSSL #10065 / CVE-2020-1967: CCS handshake phase & flooding protection
// 3. RFC 9001 §5.4.2: QUIC Header Protection sample bounds checking (pn_offset == 0 rejection)
// 4. RFC 9000 §19.6: QUIC CRYPTO frame offset varint 2^62 - 1 maximum bounds overflow
// 5. RFC 9001 §4 & RFC 9000 §19.6: QUIC CRYPTO gateway empty frame and buffer quota limits

// ----------------------------------------------------------------------------
// 5. RFC 8446 CCS Invariants & Flood Protection
// ----------------------------------------------------------------------------
fn test_round3_ccs_and_protected_record_invariants(t: lit::T&) {
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
            empty_records_count:      0,
            early_data_skipped_bytes: 0,
            ccs_count:                0,
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

// ----------------------------------------------------------------------------
// 6. RFC 9001 QUIC Crypto Gateway & Stream Bounds
// ----------------------------------------------------------------------------
fn test_round3_quic_crypto_and_framing_invariants(t: lit::T&) {
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

// --- Component: tls_ech ---
// tests/ech_test.goose
// Verification test suite for DNS Engine, RFC 9460 HTTPS RR (Type 65), and Encrypted Client Hello (ECH).

// 7. DNS Wire Format & RFC 9460 HTTPS/SVCB Resource Records (Type 65)
fn test_dns_and_https_rr(t: lit::T&) {
    t.run("DNS-01: Query Encoding and Name Compression Decoding") { sub =>
        var query: u8[..512] = [];
        let ok_q = wing::build_dns_query("cloudflare.com", rfc::DNS_QTYPE_HTTPS, 0x1234, query);
        sub.assert_true(ok_q, "build_dns_query succeeds");
        sub.assert_gt(query.len, 12, "query has header and question");
        sub.assert_eq(query[0], 0x12, "tx_id hi matches");
        sub.assert_eq(query[1], 0x34, "tx_id lo matches");

        // Question: 10 'cloudflare' 3 'com' 0
        // QTYPE = 65 (0x0041), QCLASS = 1 (0x0001)
        let qlen = query.len;
        sub.assert_eq(query[qlen - 4], 0x00, "qtype hi is 0x00");
        sub.assert_eq(query[qlen - 3], 65, "qtype lo is 65 (HTTPS)");
        sub.assert_eq(query[qlen - 2], 0x00, "qclass hi is 0x00");
        sub.assert_eq(query[qlen - 1], 0x01, "qclass lo is 0x01 (IN)");
    };

    t.run("DNS-02: RFC 9460 HTTPS Resource Record Parser with ALPN, Hints & ECH") { sub =>
        // Construct a synthetic DNS response containing a Type 65 HTTPS RR:
        // Header: ID=0xABCD, Flags=0x8180 (Response, RD, RA, NoError), QD=1, AN=1, NS=0, AR=0
        var resp: u8[>..] = [];
        // Header (12B)
        resp.push(0xAB); resp.push(0xCD);
        resp.push(0x81); resp.push(0x80);
        resp.push(0x00); resp.push(0x01); // QDCOUNT=1
        resp.push(0x00); resp.push(0x01); // ANCOUNT=1
        resp.push(0x00); resp.push(0x00);
        resp.push(0x00); resp.push(0x00);

        // Question section: cloudflare.com HTTPS IN
        guard wing::dns_encode_name("cloudflare.com", resp) else { return; }
        resp.push(0x00); resp.push(65); // QTYPE=HTTPS
        resp.push(0x00); resp.push(0x01); // QCLASS=IN

        // Answer section: Name ptr to question (0xC00C), Type=65, Class=1, TTL=300
        resp.push(0xC0); resp.push(0x0C); // Pointer to 12 (offset of domain name)
        resp.push(0x00); resp.push(65);   // TYPE=65
        resp.push(0x00); resp.push(0x01); // CLASS=1
        resp.push(0x00); resp.push(0x00); resp.push(0x01); resp.push(0x2C); // TTL=300

        // RDATA:
        // Priority = 1 (ServiceMode)
        // TargetName = root ("\x00")
        // SvcParams:
        //   - Key 1 (ALPN): len=6, val="\x02h2\x02h3"
        //   - Key 3 (port): len=2, val=0x01BB (443)
        //   - Key 4 (ipv4hint): len=4, val=192.0.2.1
        //   - Key 5 (ech): len=8, val=0xFE0D0004...
        var rdata: u8[>..] = [];
        rdata.push(0x00); rdata.push(0x01); // Priority = 1
        rdata.push(0x00);                   // Target = "." (root)

        // Key 1 (ALPN)
        rdata.push(0x00); rdata.push(rfc::SVC_PARAM_ALPN as u8);
        rdata.push(0x00); rdata.push(0x06); // len = 6
        rdata.push(0x02); rdata.append("h2");
        rdata.push(0x02); rdata.append("h3");

        // Key 3 (port)
        rdata.push(0x00); rdata.push(rfc::SVC_PARAM_PORT as u8);
        rdata.push(0x00); rdata.push(0x02);
        rdata.push(0x01); rdata.push(0xBB); // 443

        // Key 4 (ipv4hint)
        rdata.push(0x00); rdata.push(rfc::SVC_PARAM_IPV4HINT as u8);
        rdata.push(0x00); rdata.push(0x04);
        rdata.push(192); rdata.push(0); rdata.push(2); rdata.push(1);

        // Key 5 (ech)
        rdata.push(0x00); rdata.push(rfc::SVC_PARAM_ECH as u8);
        rdata.push(0x00); rdata.push(0x04);
        rdata.push(0xFE); rdata.push(0x0D); rdata.push(0xAA); rdata.push(0xBB);

        // Append RDLENGTH and RDATA
        let rdlen = rdata.len;
        resp.push(((rdlen >> 8) & 0xFF) as u8);
        resp.push((rdlen & 0xFF) as u8);
        resp.append(rdata[..]);

        // Parse DNS response
        var dns_parsed = wing::DnsResponse { .. };
        let ok_parse = wing::parse_dns_response(resp[..], dns_parsed);
        sub.assert_true(ok_parse, "parse_dns_response succeeds");
        sub.assert_eq(dns_parsed.tx_id, 0xABCD, "tx_id matches");
        sub.assert_true(dns_parsed.is_response, "is_response is true");
        sub.assert_eq(dns_parsed.https_records.len, 1, "found 1 HTTPS record");

        let rec = dns_parsed.https_records[0];
        sub.assert_eq(rec.priority, 1, "priority is 1");
        sub.assert_eq(rec.port, 443, "port is 443");
        sub.assert_eq(rec.alpns.len, 2, "2 ALPN protocols parsed");
        sub.assert_eq(rec.ipv4_hints.len, 1, "1 ipv4 hint parsed");
        sub.assert_eq(rec.ipv4_hints[0], 0xC0000201, "ipv4 is 192.0.2.1");
        sub.assert_true(rec.has_ech, "ECH parameter detected");
        sub.assert_eq(rec.ech_config_list.len, 4, "ECH config wire bytes extracted");
        sub.assert_eq(rec.ech_config_list[0], 0xFE, "ECH byte 0 matches");
        sub.assert_eq(rec.ech_config_list[1], 0x0D, "ECH byte 1 matches");
    };
}

// 8. Encrypted Client Hello (ECH) Wire Formats & HPKE Privacy Handshake
fn test_ech_protocol(t: lit::T&) {
    t.run("ECH-01: ECHConfig & ECHConfigList Parsing") { sub =>
        // Construct a realistic synthetic ECHConfig wire buffer:
        // version: 0xFE0D (RFC 9849)
        // length: u16
        // KeyConfig:
        //   config_id: 42
        //   kem_id: 0x0020 (DHKEM(X25519, HKDF-SHA256))
        //   pk_len: 32 || pk (32 bytes from Bob)
        //   cs_len: 4 || kdf=0x0001, aead=0x0001 (AES-128-GCM)
        // maximum_name_length: 64
        // public_name: len=18 || "cloudflare-ech.com"
        // extensions: len=0
        let bob_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_pk = core::x25519_base_scalarmult(bob_sk);

        var contents: u8[>..] = [];
        contents.push(42);                  // config_id
        contents.push(0x00); contents.push(0x20); // kem_id = 0x0020
        // public key (length-prefixed 32 bytes)
        contents.push(0x00); contents.push(32);
        contents.append(bob_pk[..]);
        // cipher suites: len=4, kdf=1, aead=1
        contents.push(0x00); contents.push(4);
        contents.push(0x00); contents.push(0x01); // KDF HKDF-SHA256
        contents.push(0x00); contents.push(0x01); // AEAD AES-128-GCM
        // maximum_name_length = 64
        contents.push(64);
        // public_name = "cloudflare-ech.com" (18 bytes)
        let pub_name = "cloudflare-ech.com";
        contents.push(pub_name.len as u8);
        contents.append(pub_name);
        // extensions: len=0
        contents.push(0x00); contents.push(0x00);

        // Build single ECHConfig
        var raw_cfg: u8[>..] = [];
        raw_cfg.push(0xFE); raw_cfg.push(0x0D); // version 0xFE0D
        let clen = contents.len;
        raw_cfg.push(((clen >> 8) & 0xFF) as u8);
        raw_cfg.push((clen & 0xFF) as u8);
        raw_cfg.append(contents[..]);

        // Build ECHConfigList: u16 total_len || ECHConfig...
        var raw_list: u8[>..] = [];
        let list_payload_len = raw_cfg.len;
        raw_list.push(((list_payload_len >> 8) & 0xFF) as u8);
        raw_list.push((list_payload_len & 0xFF) as u8);
        raw_list.append(raw_cfg[..]);

        // Parse list
        var cfg_list = wing::EchConfigList { .. };
        let ok_list = wing::parse_ech_config_list(raw_list[..], cfg_list);
        sub.assert_true(ok_list, "parse_ech_config_list succeeds");
        sub.assert_eq(cfg_list.configs.len, 1, "1 config parsed from list");

        var selected_cfg = wing::EchConfig { .. };
        var selected_cs = wing::EchCipherSuite { .. };
        let ok_sel = wing::select_ech_config(cfg_list, selected_cfg, selected_cs);
        sub.assert_true(ok_sel, "select_ech_config succeeds");
        sub.assert_eq(selected_cfg.config_id, 42, "config_id is 42");
        sub.assert_eq(selected_cfg.maximum_name_length, 64, "max_name_len is 64");
        sub.assert_eq(selected_cs.kdf_id, rfc::HPKE_KDF_HKDF_SHA256, "kdf is SHA256");
        sub.assert_eq(selected_cs.aead_id, rfc::HPKE_AEAD_AES_128_GCM, "aead is AES-128-GCM");

        // Verify public key extracted matches Bob's PK
        for i in 32 {
            sub.assert_eq(selected_cfg.public_key[i], bob_pk[i], "public key matches");
        }
    };

    t.run("ECH-02: Padding, Outer AAD Binding & End-to-End Privacy Handshake") { sub =>
        let server_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let server_pk = core::x25519_base_scalarmult(server_sk);

        var config = wing::EchConfig { .. };
        config.version = rfc::ECH_VERSION_RFC9849;
        config.config_id = 7;
        config.kem_id = rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256;
        config.maximum_name_length = 64;
        for i in 32 { config.public_key[i] = server_pk[i]; }
        config.raw_bytes.append("synthetic-ech-config-raw-bytes");

        let cs = wing::EchCipherSuite {
            kdf_id:  rfc::HPKE_KDF_HKDF_SHA256,
            aead_id: rfc::HPKE_AEAD_AES_128_GCM,
        };

        // Real hidden SNI: "secret.crypto.internal"
        let real_sni = "secret.crypto.internal";
        var inner_hello: u8[>..] = [];
        inner_hello.append("ClientHelloInner:sni=");
        inner_hello.append(real_sni);
        inner_hello.append(";alpn=h2;keyshare=x25519");

        // Pad inner hello to hide length
        var inner_padded: u8[..512] = [];
        let ok_pad = wing::pad_ech_inner(inner_hello[..], config.maximum_name_length, real_sni.len, inner_padded);
        sub.assert_true(ok_pad, "pad_ech_inner succeeds");
        sub.assert_gt(inner_padded.len, inner_hello.len, "padding added");
        sub.assert_eq(inner_padded.len % 32, 0, "padded length aligned to 32 bytes");

        // Outer AAD binds the ClientHelloOuter
        let outer_aad = "ClientHelloOuter:sni=cloudflare-ech.com;ech_outer_placeholder";

        let client_ephemeral_sk: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];

        var enc:        u8[32]    = [0; 32];
        var ciphertext: u8[..512] = [];
        let ok_seal = config.seal_ech_inner(
            cs,
            outer_aad,
            inner_padded[..],
            client_ephemeral_sk,
            enc,
            ciphertext,
        );
        sub.assert_true(ok_seal, "seal_ech_inner succeeds");
        sub.assert_eq(ciphertext.len, inner_padded.len + 16, "ciphertext len = padded len + 16B tag");

        // Format outer ECH extension
        var outer_ext_bytes: u8[..512] = [];
        let ok_ext = wing::build_ech_outer_extension(config.config_id, cs, enc, ciphertext[..], outer_ext_bytes);
        sub.assert_true(ok_ext, "build_ech_outer_extension succeeds");
        sub.assert_eq(outer_ext_bytes[0], rfc::ECH_CLIENT_OUTER, "outer flag is 0x00");
        sub.assert_eq(outer_ext_bytes[5], 7, "config_id is 7");

        // Format inner ECH extension (must be 1 byte: 0x01)
        var inner_ext_bytes: u8[>..] = [];
        wing::build_ech_inner_extension(inner_ext_bytes);
        sub.assert_eq(inner_ext_bytes.len, 1, "inner extension is 1 byte");
        sub.assert_eq(inner_ext_bytes[0], rfc::ECH_CLIENT_INNER, "inner flag is 0x01");

        // Server decrypts ciphertext using server_sk:
        var info: u8[..600] = [];
        info.append("tls ech");
        info.push(0x00);
        for i in config.raw_bytes.len { info.push(config.raw_bytes[i]); }

        var decrypted: u8[..512] = [];
        let ok_open = wing::hpke_open_base(
            enc,
            server_sk,
            info[..],
            outer_aad,
            ciphertext[..],
            cs.aead_id,
            decrypted,
        );
        sub.assert_true(ok_open, "server decrypts ECH ciphertext successfully");
        sub.assert_eq(decrypted.len, inner_padded.len, "decrypted length matches padded inner");

        // Verify inner plaintext contains original secret SNI
        var decrypted_sni_matches = true;
        for i in inner_hello.len {
            if decrypted[i] != inner_hello[i] {
                decrypted_sni_matches = false;
                break;
            }
        }
        sub.assert_true(decrypted_sni_matches, "recovered inner ClientHello matches authentic payload");
    };
}

// RFC 9849 ECH wire constants: extension type and ECHConfig.version share 0xFE0D.
// ----------------------------------------------------------------------------
// 9. RFC 9849 ECH constants
// ----------------------------------------------------------------------------
fn test_ech_rfc9849_citations(t: lit::T&) {
    t.run("RFC 9849 ECH constants match corpus") { sub =>
        // rfc9849.txt: encrypted_client_hello(0xfe0d) extension and ECHConfig case 0xfe0d
        sub.assert_eq(rfc::ECH_VERSION_RFC9849, 0xFE0D, "rfc::ECH_VERSION_RFC9849 == 0xFE0D");
        sub.assert_eq(rfc::EXT_ENCRYPTED_CLIENT_HELLO, 0xFE0D, "ext type == 0xFE0D");
        sub.assert_eq(rfc::ECH_VERSION_RFC9849, rfc::EXT_ENCRYPTED_CLIENT_HELLO, "version == ext type");
    };
}

// 10. DNS-over-HTTPS (RFC 8484) & Automated ECH Discovery (RFC 9460)
fn test_doh_and_automated_ech_discovery(t: lit::T&) {
    t.run("DoH-01: Wire Format Query Construction & URL Formatter") { sub =>
        // POST body
        var post_body: u8[>..] = [];
        let ok_post = wing::build_doh_post_body("cloudflare.com", rfc::DNS_QTYPE_HTTPS, 0x1122, post_body);
        sub.assert_true(ok_post, "build_doh_post_body succeeds");
        sub.assert_gt(post_body.len, 12, "DoH post body contains DNS header + question");

        // GET URL
        var get_url: u8[..512] = [];
        let ok_get = wing::build_doh_get_url("https://cloudflare-dns.com/dns-query", "cloudflare.com", rfc::DNS_QTYPE_HTTPS, get_url);
        sub.assert_true(ok_get, "build_doh_get_url succeeds");
        let prefix = "https://cloudflare-dns.com/dns-query?dns=";
        sub.assert_true(get_url.len >= prefix.len, "GET URL length sufficient");
        sub.assert_bytes_eq(get_url[..prefix.len], prefix, "GET URL starts with query param");
    };

    t.run("DoH-02: Automated ECH Discovery and DNS Cache Integration") { sub =>
        var client = wing::new_client();
        wing::enable_doh(client, "https://mock-dns.local/dns-query", true);
        wing::enable_ech(client, true);

        sub.assert_true(client.enable_doh, "DoH enabled");
        sub.assert_true(client.enable_ech, "ECH enabled");
        sub.assert_true(client.auto_ech_discovery, "Auto ECH discovery enabled");

        // Construct synthetic DNS response containing Type 65 HTTPS RR with Key 5 (ECH)
        var dns_resp_wire: u8[>..] = [];
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x00); // ID 0x0000 (RFC 8484 §4.1)
        dns_resp_wire.push(0x81); dns_resp_wire.push(0x80); // Flags: standard response
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // QDCOUNT=1
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // ANCOUNT=1
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x00);
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x00);

        // Question: crypto.example.com HTTPS IN
        guard wing::dns_encode_name("crypto.example.com", dns_resp_wire) else { return; }
        dns_resp_wire.push(0x00); dns_resp_wire.push(65); // QTYPE=HTTPS
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // QCLASS=IN

        // Answer
        dns_resp_wire.push(0xC0); dns_resp_wire.push(0x0C); // Ptr to question name
        dns_resp_wire.push(0x00); dns_resp_wire.push(65);   // Type 65
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // Class IN
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); dns_resp_wire.push(0x2C); // TTL 300

        // RDATA
        var rdata: u8[>..] = [];
        rdata.push(0x00); rdata.push(0x01); // Priority 1
        rdata.push(0x00);                   // Target "."
        // Key 5 (ECH)
        rdata.push(0x00); rdata.push(rfc::SVC_PARAM_ECH as u8);
        rdata.push(0x00); rdata.push(0x08); // 8 bytes
        rdata.push(0xFE); rdata.push(0x0D);
        rdata.push(0x00); rdata.push(0x04);
        rdata.push(0xCA); rdata.push(0xFE); rdata.push(0xBA); rdata.push(0xBE);

        let rdlen = rdata.len;
        dns_resp_wire.push(((rdlen >> 8) & 0xFF) as u8);
        dns_resp_wire.push((rdlen & 0xFF) as u8);
        dns_resp_wire.append(rdata[..]);

        // Register mock DoH endpoint
        var mock = wing::MockExchange {
            pattern_url: "https://mock-dns.local/dns-query",
            method:      "POST",
            status_code: 200,
            ..
        };
        wing::append_header(mock.headers, "content-type", "application/dns-message");
        mock.body.append(dns_resp_wire[..]);
        client.mock_routes.push(mock);

        // 1st call: Performs DoH query and populates cache
        var discovered_ech: u8[..512] = [];
        let now = 1700000000;
        let ok_disc = wing::resolve_ech_config(client, "crypto.example.com", now, discovered_ech);

        sub.assert_true(ok_disc, "ECH config discovered via DoH");
        sub.assert_eq(discovered_ech.len, 8, "Extracted 8 bytes ECHConfigList");
        sub.assert_eq(discovered_ech[0], 0xFE, "ECH header byte 0 is 0xFE");
        sub.assert_eq(discovered_ech[1], 0x0D, "ECH header byte 1 is 0x0D");
        sub.assert_eq(discovered_ech[4], 0xCA, "ECH payload matches 0xCA");
        sub.assert_eq(discovered_ech[5], 0xFE, "ECH payload matches 0xFE");

        // 2nd call: Resolves from DnsCache directly without DoH request
        client.mock_routes.clear(); // Clear mock routes so any network hop would fail
        var cached_ech: u8[..512] = [];
        let ok_cache = wing::resolve_ech_config(client, "crypto.example.com", now + 60, cached_ech);

        sub.assert_true(ok_cache, "ECH resolved from DNS cache without network hop");
        sub.assert_bytes_eq(cached_ech[..], discovered_ech[..], "Cached ECH matches discovered ECH");
    };
}

// Main ECH & DNS Verification Runner

// --- Component: tls_mtls ---
// Verification suite for TLS 1.3 Mutual Authentication (mTLS / RFC 8446 Section 4.4.2):
// - CertificateRequest message encoding & parsing (RFC 8446 §4.3.2)
// - Empty client Certificate handling and CertificateVerify omission (RFC 8446 §4.4.2)
// - Client certificate formatting & digital signature generation (RFC 8446 §4.4.3)
// - Cryptographic signature verification via Ed25519 against transcript hash
// - Strict rejection on signature tampering, wrong public key, or context tampering

// ----------------------------------------------------------------------------
// 11. CertificateRequest Codec
// ----------------------------------------------------------------------------
fn test_certificate_request_codec(t: lit::T&) {
    t.run("CertificateRequest Encoding & Parsing (RFC 8446 §4.3.2)") { sub =>
        var req_buf: u8[..256] = [];
        let sig_algs: u16[3] = [
            rfc::SIG_SCHEME_ED25519,
            rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
            rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        ];
        let enc_ok = wing::encode_certificate_request(req_buf, "", sig_algs[..]);
        sub.assert_true(enc_ok, "Encoded CertificateRequest");
        sub.assert_gt(req_buf.len, 8, "Message has length");

        var parsed_req = wing::CertificateRequestMsg { .. };
        let parse_ok = wing::parse_certificate_request(req_buf[..], false, parsed_req);
        sub.assert_true(parse_ok, "Parsed CertificateRequest");
        sub.assert_eq(parsed_req.context.len, 0, "Initial handshake context is 0 bytes");
        sub.assert_true(parsed_req.has_signature_algorithms, "Has signature algorithms extension");
        sub.assert_eq(parsed_req.sig_algorithms.len, 3, "Contains 3 signature schemes");
        sub.assert_eq(parsed_req.sig_algorithms[0], rfc::SIG_SCHEME_ED25519, "First scheme is Ed25519");
        sub.assert_eq(parsed_req.sig_algorithms[1], rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256, "Second is P-256");
        sub.assert_eq(parsed_req.sig_algorithms[2], rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256, "Third is RSA-PSS");
    };
}

// ----------------------------------------------------------------------------
// 12. Empty Client Certificate
// ----------------------------------------------------------------------------
fn test_empty_client_certificate(t: lit::T&) {
    t.run("Empty Client Certificate Handling (RFC 8446 §4.4.2)") { sub =>
        // Client without certificate must send empty Certificate message
        var cert_buf: u8[..256] = [];
        let enc_ok = wing::encode_client_certificate(cert_buf, "", "");
        sub.assert_true(enc_ok, "Encoded empty client Certificate");

        let is_empty, ok_p = wing::parse_certificate_header_is_empty(cert_buf[..]);
        sub.assert_true(ok_p, "Parsed certificate header");
        sub.assert_true(is_empty, "Certificate list is empty");

        // FSM verification: empty client cert transitions directly to ServerWaitFinished (CV omitted)
        let next_state, ok_trans = wing::server_wait_cert_step(rfc::TLS_HS_CERTIFICATE, true);
        sub.assert_true(ok_trans, "Empty cert valid in ServerWaitCert");
        sub.assert_eq(next_state, wing::HsState.ServerWaitFinished, "Transitions directly to ServerWaitFinished");

        // Negative: if client mistakenly sends CertificateVerify after empty cert, server must reject
        let _, bad_cv = wing::server_wait_cv_step(rfc::TLS_HS_CERTIFICATE_VERIFY, true);
        sub.assert_false(bad_cv, "CertificateVerify after empty cert strictly rejected");
    };
}

// ----------------------------------------------------------------------------
// 13. Client CertificateVerify Ed25519
// ----------------------------------------------------------------------------
fn test_client_certificate_verify_ed25519(t: lit::T&) {
    t.run("Client CertificateVerify Generation & Verification (Ed25519)") { sub =>
        // 1. Generate Ed25519 client keypair
        var seed: u8[32] = [0; 32];
        for i in 32 { seed[i] = (i + 1) as u8; }
        let client_pub = core::ed25519_public_key(seed);

        // Simulated transcript hash (SHA-256 of ClientHello..Certificate)
        var transcript_hash: u8[32] = [0x5A; 32];

        // 2. Client side: construct signed message and sign
        var sign_input: u8[160] = [0; 160];
        let input_len, ok_in = wing::build_certificate_verify_message(false, transcript_hash[..], sign_input[..]);
        sub.assert_true(ok_in, "Built client CertificateVerify input");

        let sig = core::ed25519_sign(seed, sign_input[..input_len]);

        // Encode CertificateVerify message
        var cv_buf: u8[..256] = [];
        let enc_cv = wing::encode_client_certificate_verify(cv_buf, rfc::SIG_SCHEME_ED25519, sig[..]);
        sub.assert_true(enc_cv, "Encoded CertificateVerify message");

        // 3. Server side: parse and cryptographically verify
        let scheme, parsed_sig, ok_parse_cv = wing::parse_certificate_verify(cv_buf[..]);
        sub.assert_true(ok_parse_cv, "Parsed CertificateVerify");
        sub.assert_eq(scheme, rfc::SIG_SCHEME_ED25519, "Scheme is Ed25519");
        sub.assert_eq(parsed_sig.len, 64, "Signature length is 64 bytes");

        let verify_ok = wing::verify_client_certificate_verify(
            scheme,
            parsed_sig,
            client_pub[..],
            transcript_hash[..],
        );
        sub.assert_true(verify_ok, "Cryptographic signature verifies successfully");

        // 4. Security checks: Tampered signature rejected
        var tampered_sig: u8[64] = [0; 64];
        for i in 64 { tampered_sig[i] = parsed_sig[i]; }
        tampered_sig[10] = tampered_sig[10] ^ 0xFF;
        let tampered_ok = wing::verify_client_certificate_verify(
            scheme,
            tampered_sig[..],
            client_pub[..],
            transcript_hash[..],
        );
        sub.assert_false(tampered_ok, "Tampered signature rejected");

        // Wrong public key rejected
        var wrong_pub: u8[32] = [0xFF; 32];
        let wrong_pub_ok = wing::verify_client_certificate_verify(
            scheme,
            parsed_sig,
            wrong_pub[..],
            transcript_hash[..],
        );
        sub.assert_false(wrong_pub_ok, "Wrong public key rejected");

        // Wrong transcript hash rejected
        var wrong_hash: u8[32] = [0x00; 32];
        let wrong_hash_ok = wing::verify_client_certificate_verify(
            scheme,
            parsed_sig,
            client_pub[..],
            wrong_hash[..],
        );
        sub.assert_false(wrong_hash_ok, "Mismatched transcript hash rejected");
    };
}

// --- Component: tls_post_quantum ---
// Verification suite for RFC 10024 & FIPS 203 Hybrid Post-Quantum Key Agreement:
// - NamedGroup validation (0x11EC X25519MLKEM768, 0x6399 X25519Kyber768)
// - 1184-byte hybrid ClientHello key share wire serialization and deserialization
// - 1120-byte hybrid ServerHello key share wire serialization and deserialization
// - Hybrid shared secret derivation combiner (RFC 10024 §4)

// ----------------------------------------------------------------------------
// 14. Post-Quantum TLS 1.3 Key Exchange
// ----------------------------------------------------------------------------
fn test_post_quantum_hybrid(t: lit::T&) {
    t.run("IANA NamedGroup Recognition") { sub =>
        sub.assert_true(rfc::is_post_quantum_group(rfc::GROUP_X25519_MLKEM768), "0x11EC is post-quantum group");
        sub.assert_true(rfc::is_post_quantum_group(rfc::GROUP_X25519_KYBER768_DRAFT00), "0x6399 is post-quantum draft group");
        sub.assert_false(rfc::is_post_quantum_group(0x001D), "0x001D (X25519 classical) is NOT PQ group");
        sub.assert_false(rfc::is_post_quantum_group(0x0017), "0x0017 (secp256r1) is NOT PQ group");
    };

    t.run("Hybrid 1216-Byte Client Key Share Wire Codec") { sub =>
        var share = internal::PostQuantumKeyShare {
            group: rfc::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { share.x25519_public[i] = (i + 1) as u8; }
        for i in 1184 { share.mlkem768_public[i] = ((i * 7 + 3) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        share.format_hybrid_key_share(wire);
        // group (2) + len (2) + 1216 = 1220 bytes total
        sub.assert_eq(wire.len, 1220, "Wire length is exactly 1220 bytes");

        var parsed = internal::PostQuantumKeyShare { .. };
        let ok_parse = parsed.parse_hybrid_key_share(wire[..]);
        sub.assert_true(ok_parse, "Hybrid key share parsed via UFCS");
        sub.assert_eq(parsed.group, rfc::GROUP_X25519_MLKEM768, "Group is 0x11EC");
        sub.assert_bytes_eq(parsed.x25519_public[..], share.x25519_public[..], "X25519 component matches");

        var mlkem_match = true;
        for i in 1184 {
            if parsed.mlkem768_public[i] != share.mlkem768_public[i] {
                mlkem_match = false;
                break;
            }
        }
        sub.assert_true(mlkem_match, "ML-KEM-768 1184-byte component matches verbatim");

        // Edge cases
        var bad_parsed = internal::PostQuantumKeyShare { .. };
        sub.assert_false(bad_parsed.parse_hybrid_key_share(wire[..10]), "Truncated wire fails");

        var corrupt_wire: u8[>..] = [];
        corrupt_wire.append(wire[..]);
        corrupt_wire[0] = 0x00;
        corrupt_wire[1] = 0x1D; // classical X25519, not PQ
        sub.assert_false(bad_parsed.parse_hybrid_key_share(corrupt_wire[..]), "Non-PQ group fails");
    };

    t.run("Hybrid 1120-Byte Server Key Share Wire Codec") { sub =>
        var server_share = internal::PostQuantumServerShare {
            group: rfc::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { server_share.x25519_public[i] = (i + 5) as u8; }
        for i in 1088 { server_share.mlkem768_ciphertext[i] = ((i * 11 + 7) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        server_share.format_hybrid_server_key_share(wire);
        // group (2) + len (2) + 1120 = 1124 bytes total
        sub.assert_eq(wire.len, 1124, "Server wire length is exactly 1124 bytes");

        var parsed_server = internal::PostQuantumServerShare { .. };
        let ok_parse = parsed_server.parse_hybrid_server_key_share(wire[..]);
        sub.assert_true(ok_parse, "Server hybrid key share parsed via UFCS");
        sub.assert_eq(parsed_server.group, rfc::GROUP_X25519_MLKEM768, "Server group is 0x11EC");
        sub.assert_bytes_eq(parsed_server.x25519_public[..], server_share.x25519_public[..], "Server X25519 component matches");

        var ct_match = true;
        for i in 1088 {
            if parsed_server.mlkem768_ciphertext[i] != server_share.mlkem768_ciphertext[i] {
                ct_match = false;
                break;
            }
        }
        sub.assert_true(ct_match, "ML-KEM-768 1088-byte ciphertext matches verbatim");

        // Edge case
        var bad_parsed = internal::PostQuantumServerShare { .. };
        sub.assert_false(bad_parsed.parse_hybrid_server_key_share(wire[..500]), "Truncated server wire fails");
    };

    t.run("Hybrid Shared Secret Combiner (RFC 10024 §4)") { sub =>
        var classical_ss: u8[32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        var pq_ss: u8[32] = [
            33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ];

        let combined_secret = internal::derive_hybrid_shared_secret(classical_ss, pq_ss);
        var zero_cnt = 0;
        for b in combined_secret {
            if b == 0 { zero_cnt += 1; }
        }
        sub.assert_true(zero_cnt < 32, "Hybrid secret is high-entropy 32-byte SHA-256");
    };
}

// --- Component: tls_cert_compression ---
// Verification Suite for RFC 8879 (TLS Certificate Compression via Zstandard),
// TLS ClientHello Fragmentation, and DNS Cache with Stale-While-Revalidate.

// ----------------------------------------------------------------------------
// 15. RFC 8879 TLS Certificate Compression via Zstandard
// ----------------------------------------------------------------------------
fn test_rfc8879_certificate_compression(t: lit::T&) {
    t.run("1. RFC 8879 Extension & Handshake Message Codecs") { sub =>
        let algos: u16[2] = [rfc::CERT_COMPRESSION_ZSTD, rfc::CERT_COMPRESSION_BROTLI];
        var ext_wire: u8[>..] = [];
        wing::encode_compress_certificate_extension(ext_wire, algos[..]);

        sub.assert_eq(ext_wire.len, 2 + 2 + 1 + 4, "Extension wire length: 2 type + 2 len + 1 list_len + 4 algorithms = 9 bytes");
        let ext_type = ((ext_wire[0] as u16) << 8) | ext_wire[1];
        sub.assert_eq(ext_type, rfc::TLS_EXT_COMPRESS_CERTIFICATE, "Extension type is 27 (compress_certificate)");

        // Handshake payload roundtrip
        let fake_cert = "MIIB...Simulated X.509 Certificate Chain Data with Repetitive Certificate Metadata Blocks...";
        var compressed: u8[>..] = [];
        sub.assert_true(core::zstd_compress(fake_cert, compressed), "Zstandard compression of certificate succeeds");

        var hs_payload: u8[>..] = [];
        wing::encode_compressed_certificate_payload(
            hs_payload,
            rfc::CERT_COMPRESSION_ZSTD,
            fake_cert.len as u32,
            compressed[..],
        );

        let parsed, ok_parse = wing::parse_compressed_certificate(hs_payload[..]);
        sub.assert_true(ok_parse, "Parse CompressedCertificate payload");
        sub.assert_eq(parsed.algorithm, rfc::CERT_COMPRESSION_ZSTD, "Algorithm is Zstandard (3)");
        sub.assert_eq(parsed.uncompressed_len as i64, fake_cert.len as i64, "Uncompressed length matches original");

        // Decompress with native RFC 8878 Zstandard engine
        var decompressed: u8[..4096] = [];
        sub.assert_true(wing::decompress_certificate_zstd(parsed.compressed_data, parsed.uncompressed_len, decompressed), "Decompression succeeds");
        sub.assert_bytes_eq(decompressed[..], fake_cert, "Decompressed certificate matches original plaintext exactly");
    };
}

// ----------------------------------------------------------------------------
// 16. TLS ClientHello Fragmentation & DPI Evasion
// ----------------------------------------------------------------------------
fn test_tls_client_hello_fragmentation(t: lit::T&) {
    t.run("1. ClientHello Record Fragmentation for Anti-Censorship / DPI Evasion") { sub =>
        let dummy_ch = "ClientHelloPayloadContainingServerNameIndicationSNIAndCiphersAndExtensionsForTesting";
        var records: u8[>..] = [];

        let split_point: i64 = 20;
        sub.assert_true(wing::fragment_client_hello(dummy_ch, split_point, records), "fragment_client_hello succeeds");

        // Record 1: 5 bytes header + 20 bytes data = 25 bytes
        sub.assert_eq(records[0], 22, "Record 1 content type is Handshake (22)");
        sub.assert_eq(records[1], 0x03, "Record 1 legacy major 3");
        sub.assert_eq(records[2], 0x01, "Record 1 legacy minor 1 (TLS 1.0)");
        let len1 = ((records[3] as i64) << 8) | (records[4] as i64);
        sub.assert_eq(len1, 20, "Record 1 payload length is 20");
        sub.assert_bytes_eq(records[5..25], dummy_ch[..20], "Record 1 payload matches first slice");

        // Record 2: 5 bytes header + (total - 20) bytes data
        let rec2_start = 25;
        sub.assert_eq(records[rec2_start], 22, "Record 2 content type is Handshake (22)");
        let len2 = ((records[rec2_start + 3] as i64) << 8) | (records[rec2_start + 4] as i64);
        sub.assert_eq(len2, dummy_ch.len - 20, "Record 2 payload length matches remainder");
        sub.assert_bytes_eq(records[rec2_start + 5..], dummy_ch[20..], "Record 2 payload matches remainder");

        // Invariant: Total payload concatenated across records exactly equals original message
        var reassembled: u8[>..] = [];
        reassembled.append(records[5..25]);
        reassembled.append(records[rec2_start + 5..]);
        sub.assert_bytes_eq(reassembled[..], dummy_ch, "Reassembled handshake records exactly equal original ClientHello");
    };
}

// ----------------------------------------------------------------------------
// 17. DNS Cache with Stale-While-Revalidate
// ----------------------------------------------------------------------------
fn test_dns_cache_and_stale_revalidate(t: lit::T&) {
    t.run("1. DNS Cache TTL and Stale-While-Revalidate Lifecycle") { sub =>
        var cache = wing::DnsCache { .. };

        var entry = wing::DnsCacheEntry {
            qtype:           rfc::DNS_QTYPE_A,
            inserted_at_sec: 1000,
            ttl_sec:         300,  // 5 minutes
            stale_ttl_sec:   3600, // 1 hour grace period
            ..
        };
        entry.domain.append("example.com");
        entry.ipv4_hints.push(0x5DB8D822); // 93.184.216.34

        wing::dns_cache_insert(cache, entry);

        // 1. Fresh lookup at t = 1100 (100s elapsed < 300s TTL)
        var hit1 = wing::DnsCacheEntry { .. };
        let status1 = wing::dns_cache_lookup(cache, "example.com", rfc::DNS_QTYPE_A, 1100, hit1);
        sub.assert_eq(status1, wing::DnsCacheStatus.Fresh, "Lookup within TTL returns Fresh");
        sub.assert_eq(hit1.ipv4_hints[0], 0x5DB8D822, "Cached IPv4 address preserved");

        // 2. Stale lookup at t = 1500 (500s elapsed > 300s TTL, but < 3900s stale limit)
        var hit2 = wing::DnsCacheEntry { .. };
        let status2 = wing::dns_cache_lookup(cache, "example.com", rfc::DNS_QTYPE_A, 1500, hit2);
        sub.assert_eq(status2, wing::DnsCacheStatus.Stale, "Lookup past TTL returns Stale (trigger background revalidation)");
        sub.assert_eq(hit2.ipv4_hints[0], 0x5DB8D822, "Stale cache hit still provides IP for zero-latency connection");

        // 3. Expired lookup at t = 5000 (4000s elapsed > 3900s total limit)
        var hit3 = wing::DnsCacheEntry { .. };
        let status3 = wing::dns_cache_lookup(cache, "example.com", rfc::DNS_QTYPE_A, 5000, hit3);
        sub.assert_eq(status3, wing::DnsCacheStatus.Expired, "Lookup beyond stale window returns Expired");

        // 4. Missing domain lookup
        var hit4 = wing::DnsCacheEntry { .. };
        let status4 = wing::dns_cache_lookup(cache, "notfound.org", rfc::DNS_QTYPE_A, 1100, hit4);
        sub.assert_eq(status4, wing::DnsCacheStatus.Expired, "Missing domain returns Expired");
    };
}

// --- Component: tls_asn1_x509_invariants ---
// Hardening & Security Invariants Suite for ASN.1 DER & X.509 Certificate Decoders (ITU-T X.690 & RFC 5280):
// 1. ASN.1 DER length canonicality, indefinite length bans, and integer overflow guards.
// 2. ASN.1 INTEGER canonical padding, negative serial number bans, and 20-octet limits.
// 3. SAN dNSName validation (null bytes, label lengths, hyphen boundaries).
// 4. ASN.1 UTCTime & GeneralizedTime strict DER canonical parsing.

// ----------------------------------------------------------------------------
// 18. ASN.1 DER Length Canonicality & Bounds
// ----------------------------------------------------------------------------
fn test_asn1_der_length_canonicality(t: lit::T&) {
    t.run("ASN1-SEC-01: Short Form and Long Form Valid Lengths") { sub =>
        // Short form: 0x42 = 66
        let short_der: u8[1] = [0x42];
        var c1 = core::cursor_from(short_der[..]);
        var out_len1: i64 = 0;
        let ok1 = wing::get_asn1_length(c1, out_len1);
        sub.assert_true(ok1, "short form length succeeds");
        sub.assert_eq(out_len1, 66, "out_len matches 66");

        // Long form: 2 bytes: 0x82 0x01 0x00 = 256
        let long_der: u8[3] = [0x82, 0x01, 0x00];
        var c2 = core::cursor_from(long_der[..]);
        var out_len2: i64 = 0;
        let ok2 = wing::get_asn1_length(c2, out_len2);
        sub.assert_true(ok2, "long form length succeeds");
        sub.assert_eq(out_len2, 256, "out_len matches 256");
    };

    t.run("ASN1-SEC-02: BER Indefinite Length (0x80) strictly forbidden in DER") { sub =>
        let indef_der: u8[1] = [0x80];
        var c = core::cursor_from(indef_der[..]);
        var out_len: i64 = 0;
        let ok = wing::get_asn1_length(c, out_len);
        sub.assert_false(ok, "indefinite length 0x80 must fail in DER per X.690 §8.1.3.6");
    };

    t.run("ASN1-SEC-03: Redundant Leading Zero in Long Form Length Rejected") { sub =>
        // 0x82 0x00 0x80 (2-byte length where first length byte is 0x00)
        let red_der: u8[3] = [0x82, 0x00, 0x80];
        var c = core::cursor_from(red_der[..]);
        var out_len: i64 = 0;
        let ok = wing::get_asn1_length(c, out_len);
        sub.assert_false(ok, "redundant leading zero in long form length must be rejected");
    };

    t.run("ASN1-SEC-04: Reserved Initial Octet 0xFF and Truncated Lengths Rejected") { sub =>
        let ff_der: u8[1] = [0xFF];
        var c1 = core::cursor_from(ff_der[..]);
        var out_len1: i64 = 0;
        let ok1 = wing::get_asn1_length(c1, out_len1);
        sub.assert_false(ok1, "reserved initial octet 0xFF must be rejected");

        // Declares 3 length bytes (0x83), but only 1 byte follows
        let trunc_der: u8[2] = [0x83, 0x01];
        var c2 = core::cursor_from(trunc_der[..]);
        var out_len2: i64 = 0;
        let ok2 = wing::get_asn1_length(c2, out_len2);
        sub.assert_false(ok2, "truncated long form length must be rejected");
    };
}

// ----------------------------------------------------------------------------
// 19. ASN.1 INTEGER Canonical Rules & Serial Invariants
// ----------------------------------------------------------------------------
fn test_asn1_der_integer_and_serial_invariants(t: lit::T&) {
    t.run("ASN1-SEC-05: Empty Integer and Redundant Zero Padding") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_false(wing::validate_asn1_integer(empty_buf[..], false), "empty integer is forbidden");

        // 0x00 0x7F: redundant leading zero (0x7F has bit 7 clear, so 0x00 was unnecessary)
        let red_zero: u8[2] = [0x00, 0x7F];
        sub.assert_false(wing::validate_asn1_integer(red_zero[..], false), "redundant zero padding must be rejected");

        // 0x00 0x80: valid canonical padding (0x80 has bit 7 set, so 0x00 is required to remain positive)
        let canon_pos: u8[2] = [0x00, 0x80];
        sub.assert_true(wing::validate_asn1_integer(canon_pos[..], false), "valid zero prefix for positive int accepted");
    };

    t.run("ASN1-SEC-06: Negative Serial Number and Zero Serial Number Rejection") { sub =>
        // 0x80: negative integer (-128)
        let neg_serial: u8[1] = [0x80];
        sub.assert_true(wing::validate_asn1_integer(neg_serial[..], false), "general integer can be negative");
        sub.assert_false(wing::validate_asn1_integer(neg_serial[..], true), "serial number MUST be positive per RFC 5280 §4.1.2.2");

        // 0x00: zero serial number (RFC 5280 requires strictly positive serial numbers)
        let zero_serial: u8[1] = [0x00];
        sub.assert_false(wing::validate_asn1_integer(zero_serial[..], true), "serial number 0 is forbidden per RFC 5280");
    };

    t.run("ASN1-SEC-07: Serial Number 20-Octet Limit (RFC 5280 §4.1.2.2)") { sub =>
        // 20-byte serial number (valid)
        let valid_20: u8[20] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        sub.assert_true(wing::validate_asn1_integer(valid_20[..], true), "20-byte serial number accepted");

        // 22-byte serial number (forbidden)
        let bad_22: u8[22] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16,
        ];
        sub.assert_false(wing::validate_asn1_integer(bad_22[..], true), "serial number > 20 octets must be rejected");
    };
}

// ----------------------------------------------------------------------------
// 20. X.509 SAN dNSName Hostname Validation
// ----------------------------------------------------------------------------
fn test_x509_san_dns_name_validation(t: lit::T&) {
    t.run("ASN1-SEC-08: Valid DNS Names in SAN") { sub =>
        sub.assert_true(wing::validate_san_dns_name("example.com"), "standard domain name valid");
        sub.assert_true(wing::validate_san_dns_name("api.sub.domain.co.uk"), "multilevel domain valid");
        sub.assert_true(wing::validate_san_dns_name("host-with-dash.com"), "embedded hyphen valid");
    };

    t.run("ASN1-SEC-09: Embedded Null Byte in DNS Name (CVE-2009-2408)") { sub =>
        let null_dns: u8[21] = [
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00,
            '.', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm',
        ];
        sub.assert_false(wing::validate_san_dns_name(null_dns[..]), "embedded null byte in SAN DNS must be rejected");
    };

    t.run("ASN1-SEC-10: Leading/Trailing Dots, Empty Labels and Hyphen Violations") { sub =>
        sub.assert_false(wing::validate_san_dns_name(".example.com"), "leading dot invalid");
        sub.assert_false(wing::validate_san_dns_name("example.com."), "trailing dot invalid in SAN");
        sub.assert_false(wing::validate_san_dns_name("example..com"), "empty label (consecutive dots) invalid");
        sub.assert_false(wing::validate_san_dns_name("-example.com"), "leading hyphen in label invalid");
        sub.assert_false(wing::validate_san_dns_name("example-.com"), "trailing hyphen in label invalid");
    };

    t.run("ASN1-SEC-11: DNS Name and Label Length Limits (RFC 5280 / RFC 1035)") { sub =>
        // Empty DNS name
        sub.assert_false(wing::validate_san_dns_name(""), "empty DNS name invalid");

        // Label > 63 octets
        var long_label: u8[..128] = [];
        for i in 64 { long_label.push('a'); }
        long_label.append(".com");
        sub.assert_false(wing::validate_san_dns_name(long_label[..]), "label > 63 octets invalid");
    };
}

// ----------------------------------------------------------------------------
// 21. ASN.1 Time (UTCTime & GeneralizedTime) Canonical DER Parsing
// ----------------------------------------------------------------------------
fn test_x509_asn1_time_parsing(t: lit::T&) {
    t.run("ASN1-SEC-12: Valid UTCTime and GeneralizedTime Canonical DER") { sub =>
        // UTCTime: "261028120000Z" (2026-10-28 12:00:00 UTC)
        let utc_valid = "261028120000Z";
        let ts_utc, ok_utc = wing::parse_asn1_time(rfc::ASN1_TAG_UTC_TIME, utc_valid);
        sub.assert_true(ok_utc, "valid UTCTime parses successfully");
        sub.assert_true(ts_utc > 0, "timestamp > 0");

        // GeneralizedTime: "20261028120000Z"
        let gen_valid = "20261028120000Z";
        let ts_gen, ok_gen = wing::parse_asn1_time(rfc::ASN1_TAG_GENERALIZED_TIME, gen_valid);
        sub.assert_true(ok_gen, "valid GeneralizedTime parses successfully");
        sub.assert_true(ts_gen > 0, "timestamp > 0");
    };

    t.run("ASN1-SEC-13: Out-of-Bounds Calendar Values and Non-UTC Suffix Rejection") { sub =>
        // Month 13
        let bad_month = "261328120000Z";
        let _, ok_m = wing::parse_asn1_time(rfc::ASN1_TAG_UTC_TIME, bad_month);
        sub.assert_false(ok_m, "month 13 must be rejected");

        // Day 32
        let bad_day = "261032120000Z";
        let _, ok_d = wing::parse_asn1_time(rfc::ASN1_TAG_UTC_TIME, bad_day);
        sub.assert_false(ok_d, "day 32 must be rejected");

        // Hour 25
        let bad_hour = "261028250000Z";
        let _, ok_h = wing::parse_asn1_time(rfc::ASN1_TAG_UTC_TIME, bad_hour);
        sub.assert_false(ok_h, "hour 25 must be rejected");

        // Non-UTC suffix: local time without 'Z' (strictly forbidden in DER per X.690 §11.7)
        let no_z = "261028120000";
        let _, ok_z = wing::parse_asn1_time(rfc::ASN1_TAG_UTC_TIME, no_z);
        sub.assert_false(ok_z, "missing 'Z' timezone must be rejected in DER");
    };
}

// --- Component: tls_certificate_transparency ---
// Tests for constant-time primitives, cryptographic functions, and CryptoJar.

fn hex_to_bytes(hex: const u8[:], out: u8[>..]&) {
    var i = 0;
    while i + 1 < hex.len {
        let hi = hex_nibble(hex[i]);
        let lo = hex_nibble(hex[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
}

inline fn hex_nibble(ch: u8) -> u8 {
    if ch >= '0' && ch <= '9' { return ch - '0'; }
    if ch >= 'a' && ch <= 'f' { return ch - 'a' + 10; }
    if ch >= 'A' && ch <= 'F' { return ch - 'A' + 10; }
    return 0;
}

fn bytes_to_hex(bytes: const u8[:], out: u8[>..]&) {
    let hex_chars: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    for b in bytes {
        out.push(hex_chars[(b >> 4) & 0x0F]);
        out.push(hex_chars[b & 0x0F]);
    }
}

// ----------------------------------------------------------------------------
// 22. Constant-Time Primitives & KeySlot Redaction
// ----------------------------------------------------------------------------
fn test_constant_time_primitives(t: lit::T&) {
    t.run("Branchless Equality and Select") { sub =>
        sub.assert_eq(core::ct_eq_u8(0x42, 0x42), 1, "ct_eq_u8 match");
        sub.assert_eq(core::ct_eq_u8(0x42, 0x43), 0, "ct_eq_u8 mismatch");
        sub.assert_eq(core::ct_eq_u8(0x00, 0x00), 1, "ct_eq_u8 zero match");
        sub.assert_eq(core::ct_eq_u8(0xFF, 0x00), 0, "ct_eq_u8 boundary");

        sub.assert_eq(core::ct_select_u8(1, 0xAA, 0xBB), 0xAA, "ct_select_u8 true");
        sub.assert_eq(core::ct_select_u8(0, 0xAA, 0xBB), 0xBB, "ct_select_u8 false");
    };

    t.run("Constant-Time Slice Equality and Copy") { sub =>
        let a: const u8[4] = [1, 2, 3, 4];
        let b: const u8[4] = [1, 2, 3, 4];
        let c: const u8[4] = [1, 2, 3, 5];
        let d: const u8[3] = [1, 2, 3];

        sub.assert_true(core::ct_eq_bytes(a[..], b[..]), "identical slices match");
        sub.assert_false(core::ct_eq_bytes(a[..], c[..]), "last byte difference fails");
        sub.assert_false(core::ct_eq_bytes(a[..], d[..]), "length difference fails");

        var dst: u8[4] = [0, 0, 0, 0];
        core::ct_copy_bytes(dst[..], a[..]);
        sub.assert_true(core::ct_eq_bytes(dst[..], a[..]), "ct_copy_bytes copied identical bytes");
    };

    t.run("KeySlot Redaction and Zeroization") { sub =>
        var raw_key: u8[32] = [0x5A; 32];
        var slot = core::new_key_slot(1001, raw_key[..], 1700000000);
        sub.assert_eq(slot.key_id, 1001, "key id matches");
        sub.assert_false(slot.revoked, "slot starts non-revoked");

        // Display redacted string must hide raw key
        var red_buf: u8[..64] = [];
        core::display_redacted(slot, red_buf);
        sub.assert_contains(red_buf[..], "[REDACTED]", "secrecy redaction format");
        sub.assert_contains(red_buf[..], "1001", "key id preserved");

        // Revoke and zeroize
        core::zeroize_key_slot(slot);
        sub.assert_true(slot.revoked, "slot revoked after zeroize");
        sub.assert_eq(slot.master_key[0], 0, "first key byte zeroized");
        sub.assert_eq(slot.master_key[31], 0, "last key byte zeroized");
    };
}

// ----------------------------------------------------------------------------
// 23. Dudect Statistical Welch's t-test Simulation
// ----------------------------------------------------------------------------
fn test_dudect_context_and_filtering(t: lit::T&) {
    t.run("Outlier Cropping & Statistical Lockstep") { sub =>
        var ctx = core::new_dudect_context();

        // Feed normal samples (around 100 ns)
        for i in 100 {
            sub.assert_true(core::dudect_push_sample(ctx, 0, 100.0 + (i as f64) * 0.1), "normal sample class 0 accepted");
            sub.assert_true(core::dudect_push_sample(ctx, 1, 100.0 + (i as f64) * 0.1), "normal sample class 1 accepted");
        }

        // Outlier sample (> 2000 ns) must be discarded
        sub.assert_false(core::dudect_push_sample(ctx, 0, 2500.0), "outlier > 2000 ns rejected");
        sub.assert_false(core::dudect_push_sample(ctx, 1, 3000.0), "outlier > 2000 ns rejected");

        // Verify t-statistic is near 0 for identical distributions
        let t_stat = core::dudect_abs_t(ctx);
        sub.assert_true(t_stat < 1.0, "Welch t-stat < 1.0 for symmetric distributions");
        sub.assert_true(core::dudect_is_constant_time(ctx, 4.5), "Passes 99.999% confidence CT threshold");
    };
}

// ----------------------------------------------------------------------------
// 24. NIST / RFC Cryptographic Primitives
// ----------------------------------------------------------------------------
fn test_pure_goose_crypto_primitives(t: lit::T&) {
    t.run("SHA-256 NIST Vectors") { sub =>
        // Vector 1: Empty string
        let h_empty = core::sha256("");
        var hex_empty: u8[>..] = [];
        bytes_to_hex(h_empty[..], hex_empty);
        sub.assert_eq(hex_empty[..], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 empty");

        // Vector 2: "abc"
        let h_abc = core::sha256("abc");
        var hex_abc: u8[>..] = [];
        bytes_to_hex(h_abc[..], hex_abc);
        sub.assert_eq(hex_abc[..], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 'abc'");

        // Vector 3: 56-byte multi-block
        let h_56 = core::sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        var hex_56: u8[>..] = [];
        bytes_to_hex(h_56[..], hex_56);
        sub.assert_eq(hex_56[..], "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA-256 56-byte");
    };

    t.run("HMAC-SHA256 RFC 4231 Vector 2") { sub =>
        // Key: "Jefe", Data: "what do ya want for nothing?"
        let hmac = core::hmac_sha256("Jefe", "what do ya want for nothing?");
        var hex_hmac: u8[>..] = [];
        bytes_to_hex(hmac[..], hex_hmac);
        sub.assert_eq(hex_hmac[..], "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "HMAC-SHA256 RFC 4231 #2");
    };

    t.run("HKDF-SHA256 RFC 5869 Vector 1") { sub =>
        var ikm: u8[>..] = [];
        hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm);
        var salt: u8[>..] = [];
        hex_to_bytes("000102030405060708090a0b0c", salt);
        var info: u8[>..] = [];
        hex_to_bytes("f0f1f2f3f4f5f6f7f8f9", info);

        let prk = core::hkdf_extract(salt[..], ikm[..]);
        var hex_prk: u8[>..] = [];
        bytes_to_hex(prk[..], hex_prk);
        sub.assert_eq(hex_prk[..], "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "HKDF PRK");

        let okm32 = core::hkdf_expand_32(prk, info[..]);
        var hex_okm: u8[>..] = [];
        bytes_to_hex(okm32[..], hex_okm);
        // First 32 bytes of RFC 5869 Test Case 1 OKM
        sub.assert_eq(hex_okm[..], "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf", "HKDF OKM first 32 bytes");
    };

    t.run("AES-256 Block Cipher FIPS 197") { sub =>
        var key: u8[>..] = [];
        hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key);
        var pt: u8[>..] = [];
        hex_to_bytes("00112233445566778899aabbccddeeff", pt);

        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = key[i]; }
        var pt16: u8[16] = [0; 16];
        for i in 16 { pt16[i] = pt[i]; }

        let ks = core::aes256_key_schedule(key32);
        let ct16 = core::aes_encrypt_block(ks, pt16);

        var hex_ct: u8[>..] = [];
        bytes_to_hex(ct16[..], hex_ct);
        sub.assert_eq(hex_ct[..], "8ea2b7ca516745bfeafc49904b496089", "AES-256 FIPS 197 C.3 vector");
    };

    t.run("Base64URL RFC 4648 Codec") { sub =>
        var out_enc: u8[>..] = [];
        core::base64url_encode("foobar", out_enc);
        sub.assert_eq(out_enc[..], "Zm9vYmFy", "foobar encoded without padding");

        var out_dec: u8[>..] = [];
        sub.assert_true(core::base64url_decode(out_enc[..], out_dec), "decode foobar");
        sub.assert_eq(out_dec[..], "foobar", "foobar round-trip match");

        // Test with URL-safe characters '-' and '_'
        var special_in: u8[>..] = [];
        special_in.push(0xFB); // 11111011 -> '+' in standard, '-' in url
        special_in.push(0xFF); // 11111111 -> '/' in standard, '_' in url
        var enc_spec: u8[>..] = [];
        core::base64url_encode(special_in[..], enc_spec);
        sub.assert_true(enc_spec[0] == '-' || enc_spec[1] == '-' || enc_spec[2] == '_', "uses url-safe chars");

        var dec_spec: u8[>..] = [];
        sub.assert_true(core::base64url_decode(enc_spec[..], dec_spec), "decodes url-safe chars");
        sub.assert_true(core::ct_eq_bytes(special_in[..], dec_spec[..]), "binary round trip match");
    };
}

// ----------------------------------------------------------------------------
// 25. AEAD Authenticated Encryption: XChaCha20-Poly1305 & AES-256-GCM
// ----------------------------------------------------------------------------
fn test_aead_ciphers(t: lit::T&) {
    t.run("XChaCha20-Poly1305 Round-Trip & Tamper Resistance") { sub =>
        var key:   u8[32] = [0x42; 32];
        var nonce: u8[24] = [0x19; 24];
        let aad = "cookie_name=session_id";
        let plaintext = "user_id=12345&role=admin";

        var ciphertext: u8[..256] = [];
        let tag = core::xchacha20_poly1305_seal(key, nonce, plaintext, aad, ciphertext);
        sub.assert_eq(ciphertext.len, plaintext.len, "ciphertext length equals plaintext length");

        // Authentic decryption
        var decrypted: u8[..256] = [];
        let ok_auth = core::xchacha20_poly1305_open(key, nonce, ciphertext[..], aad, tag, decrypted);
        sub.assert_true(ok_auth, "authentic ciphertext opens successfully");
        sub.assert_eq(decrypted[..], plaintext, "decrypted plaintext matches original");

        // Tampered ciphertext bit must be rejected
        ciphertext[0] ^= 0x01;
        var dec_tampered: u8[..256] = [];
        let ok_ct_tamper = core::xchacha20_poly1305_open(key, nonce, ciphertext[..], aad, tag, dec_tampered);
        sub.assert_false(ok_ct_tamper, "tampered ciphertext rejected by Poly1305 tag");
        ciphertext[0] ^= 0x01; // restore

        // Tampered AAD must be rejected
        let ok_aad_tamper = core::xchacha20_poly1305_open(key, nonce, ciphertext[..], "cookie_name=tampered", tag, dec_tampered);
        sub.assert_false(ok_aad_tamper, "tampered AAD context rejected");
    };

    t.run("AES-256-GCM Round-Trip & Tamper Resistance") { sub =>
        var key: u8[32] = [0x77; 32];
        var iv:  u8[12] = [0x12; 12];
        let aad = "cookie_name=auth_token";
        let plaintext = "secret_session_token_xyz987";

        var ciphertext: u8[..256] = [];
        for i in plaintext.len { ciphertext.push(0); }
        let tag, _, _ = core::aes256_gcm_seal(key, iv, plaintext, aad, ciphertext[..]);
        sub.assert_eq(ciphertext.len, plaintext.len, "ciphertext length matches");

        // Authentic decryption
        var decrypted: u8[..256] = [];
        let ok_auth = core::aes256_gcm_open(key, iv, ciphertext[..], aad, tag, decrypted);
        sub.assert_true(ok_auth, "AES-256-GCM authentic decryption succeeds");
        sub.assert_eq(decrypted[..], plaintext, "decrypted plaintext matches original");

        // Tampered tag must be rejected
        var bad_tag = tag;
        bad_tag[15] ^= 0x80;
        var dec_bad: u8[..256] = [];
        let ok_tag_tamper = core::aes256_gcm_open(key, iv, ciphertext[..], aad, bad_tag, dec_bad);
        sub.assert_false(ok_tag_tamper, "tampered GHASH tag rejected");
    };
}

// ----------------------------------------------------------------------------
// 26. CryptoJar Container: PrivateJar & SignedJar with Key Rotation
// ----------------------------------------------------------------------------
fn test_crypto_jar_container(t: lit::T&) {
    t.run("PrivateJar XChaCha20-Poly1305 (53B Overhead) & AAD Binding") { sub =>
        var store = wing::KeyStore { .. };
        var raw_key: u8[32] = [0x33; 32];
        let slot = core::new_key_slot(1, raw_key[..], 1700000000);
        wing::add_key(store, slot);

        var jar = wing::new_private_jar(store, false);

        var sealed_cookie: u8[..256] = [];
        let ok_seal = wing::private_jar_seal_binary(jar, "session_jwt", "payload_data_123", 1700000010, 0x123456789ABCDEF0, sealed_cookie);
        sub.assert_true(ok_seal, "private jar binary seal succeeds");
        sub.assert_eq(sealed_cookie.len, 53 + "payload_data_123".len, "exact 53B wire overhead");

        // Authentic open
        var opened: u8[..256] = [];
        let ok_open = wing::private_jar_open_binary(jar, "session_jwt", sealed_cookie[..], 1700000020, opened);
        sub.assert_true(ok_open, "private jar opens authentic cookie");
        sub.assert_eq(opened[..], "payload_data_123", "cookie payload verified");

        // AAD Binding: Trying to open with different cookie name must fail!
        var opened_bad: u8[..256] = [];
        let ok_bad_name = wing::private_jar_open_binary(jar, "other_cookie", sealed_cookie[..], 1700000020, opened_bad);
        sub.assert_false(ok_bad_name, "AAD cookie name alteration rejected");

        // Expired cookie timestamp rejection
        let ok_expired = wing::private_jar_open_binary(jar, "session_jwt", sealed_cookie[..], 1700000010 + 2592001, opened_bad);
        sub.assert_false(ok_expired, "expired session cookie rejected");
    };

    t.run("PrivateJar HKDF-AES-GCM (65B Overhead)") { sub =>
        var store = wing::KeyStore { .. };
        var raw_key: u8[32] = [0x44; 32];
        let slot = core::new_key_slot(2, raw_key[..], 1700000000);
        wing::add_key(store, slot);

        var jar = wing::new_private_jar(store, true);

        var sealed_cookie: u8[..256] = [];
        let ok_seal = wing::private_jar_seal_binary(jar, "secure_sess", "secret_info", 1700000010, 0xFEDCBA9876543210, sealed_cookie);
        sub.assert_true(ok_seal, "HKDF AES-GCM seal succeeds");
        sub.assert_eq(sealed_cookie.len, 65 + "secret_info".len, "exact 65B wire overhead");

        var opened: u8[..256] = [];
        let ok_open = wing::private_jar_open_binary(jar, "secure_sess", sealed_cookie[..], 1700000020, opened);
        sub.assert_true(ok_open, "HKDF AES-GCM authentic cookie opens");
        sub.assert_eq(opened[..], "secret_info", "payload matches");
    };

    t.run("SignedJar HMAC-SHA256 (45B Overhead) & Forgery Resistance") { sub =>
        var store = wing::KeyStore { .. };
        var raw_key: u8[32] = [0x88; 32];
        let slot = core::new_key_slot(7, raw_key[..], 1700000000);
        wing::add_key(store, slot);

        var jar = wing::new_signed_jar(store);

        var signed_cookie: u8[>..] = [];
        let ok_sign = wing::signed_jar_seal_binary(jar, "pref_cookie", "dark_mode=true", 1700000010, signed_cookie);
        sub.assert_true(ok_sign, "signed jar seal succeeds");
        sub.assert_eq(signed_cookie.len, 45 + "dark_mode=true".len, "exact 45B wire overhead");

        var verified_val: u8[>..] = [];
        let ok_verify = wing::signed_jar_open_binary(jar, "pref_cookie", signed_cookie[..], 1700000020, verified_val);
        sub.assert_true(ok_verify, "authentic signed cookie verified");
        sub.assert_eq(verified_val[..], "dark_mode=true", "verified payload matches");

        // Tamper with value byte
        signed_cookie[13] ^= 0x01;
        var bad_val: u8[>..] = [];
        let ok_tamper = wing::signed_jar_open_binary(jar, "pref_cookie", signed_cookie[..], 1700000020, bad_val);
        sub.assert_false(ok_tamper, "forged signature rejected");
    };

    t.run("KeyStore Proactive Key Rotation") { sub =>
        var store = wing::KeyStore { .. };
        var k1: u8[32] = [0x11; 32];
        var k2: u8[32] = [0x22; 32];
        wing::add_key(store, core::new_key_slot(10, k1[..], 1700000000));
        wing::add_key(store, core::new_key_slot(20, k2[..], 1700086400)); // 24h later

        // Rotate active key to key 20
        sub.assert_true(wing::set_active_key_id(store, 20), "rotated active key to id 20");

        var jar = wing::new_signed_jar(store);
        var cookie_k2: u8[>..] = [];
        wing::signed_jar_seal_binary(jar, "sess", "user=alice", 1700086410, cookie_k2);

        // Header must use key_id 20
        sub.assert_eq(cookie_k2[4], 20, "signed with new active key 20");

        // Old key 10 can still verify existing cookies before revocation
        var cookie_k1: u8[>..] = [];
        jar.store.active_idx = 0; // temporarily sign with old key 10
        wing::signed_jar_seal_binary(jar, "sess", "user=bob", 1700086410, cookie_k1);
        jar.store.active_idx = 1; // restore active key 20

        var out_bob: u8[>..] = [];
        let ok_old = wing::signed_jar_open_binary(jar, "sess", cookie_k1[..], 1700086420, out_bob);
        sub.assert_true(ok_old, "old key 10 still verifies historical session");

        // Revoke key 10 directly on jar.store
        sub.assert_true(wing::revoke_key(jar.store, 10), "revoked key 10");
        let ok_after_revocation = wing::signed_jar_open_binary(jar, "sess", cookie_k1[..], 1700086420, out_bob);
        sub.assert_false(ok_after_revocation, "cookie signed with revoked key 10 is now rejected");
    };
}

// ----------------------------------------------------------------------------
// 27. Vendor Conformance Vectors (rustls handshake_test.rs & record_layer.rs)
// ----------------------------------------------------------------------------

fn test_rustls_vendor_conformance(t: lit::T&) {
    t.run("RUSTLS-HS-01: Client & Server Handshake FSM Out-of-Order Rejection Matrix (rustls)") { sub =>
        // Client in ClientWaitSH must reject EE, Cert, CV, Finished, KeyUpdate, NST
        let forbidden_in_wait_sh: u8[6] = [
            rfc::TLS_HS_ENCRYPTED_EXTENSIONS,
            rfc::TLS_HS_CERTIFICATE,
            rfc::TLS_HS_CERTIFICATE_VERIFY,
            rfc::TLS_HS_FINISHED,
            rfc::TLS_HS_KEY_UPDATE,
            rfc::TLS_HS_NEW_SESSION_TICKET,
        ];
        for msg_t in forbidden_in_wait_sh {
            let _, ok_step = wing::validate_client_handshake_transition(wing::HsState.ClientWaitSH, msg_t, wing::HandshakeMode.Full, false);
            sub.assert_false(ok_step, "ClientWaitSH rejects non-ServerHello message");
        }
        // Synthetic message_hash (254) rejected from wire in any state
        let _, ok_mh = wing::validate_client_handshake_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_MESSAGE_HASH, wing::HandshakeMode.Full, false);
        sub.assert_false(ok_mh, "ClientWaitSH rejects synthetic message_hash (254) from wire");

        // HelloRetryRequest in ClientWaitSH stays in ClientWaitSH (waiting for ServerHello2, not ClientWaitEE)
        let s_sh2, ok_hrr = wing::validate_client_handshake_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_SERVER_HELLO, wing::HandshakeMode.Full, true);
        sub.assert_true(ok_hrr, "ClientWaitSH accepts HRR");
        sub.assert_eq(s_sh2, wing::HsState.ClientWaitSH, "HRR stays in ClientWaitSH waiting for ServerHello2");

        // PSK mode in ClientWaitCertCr transitions directly to ClientWaitFinished on Finished
        let s_psk_fin, ok_psk_fin = wing::validate_client_handshake_transition(wing::HsState.ClientWaitCertCr, rfc::TLS_HS_FINISHED, wing::HandshakeMode.Psk, false);
        sub.assert_true(ok_psk_fin, "ClientWaitCertCr in PSK mode accepts Finished directly");
        sub.assert_eq(s_psk_fin, wing::HsState.Connected, "PSK Finished transitions to Connected");
        let _, ok_full_skip = wing::validate_client_handshake_transition(wing::HsState.ClientWaitCertCr, rfc::TLS_HS_FINISHED, wing::HandshakeMode.Full, false);
        sub.assert_false(ok_full_skip, "ClientWaitCertCr in Full mode rejects Finished without Certificate");

        // Valid transition path: ClientWaitSH -> ClientWaitEE -> ClientWaitCertCr -> ClientWaitCert -> ClientWaitCV -> ClientWaitFinished -> Connected
        let s_ee, ok_sh = wing::validate_client_handshake_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_SERVER_HELLO, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_sh, "ClientWaitSH accepts ServerHello");
        sub.assert_eq(s_ee, wing::HsState.ClientWaitEE, "transitions to ClientWaitEE");

        let s_ccr, ok_ee = wing::validate_client_handshake_transition(s_ee, rfc::TLS_HS_ENCRYPTED_EXTENSIONS, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_ee, "ClientWaitEE accepts EncryptedExtensions");
        sub.assert_eq(s_ccr, wing::HsState.ClientWaitCertCr, "transitions to ClientWaitCertCr");

        // Optional CertificateRequest in ClientWaitCertCr transitions to ClientWaitCert
        let s_cert, ok_cr = wing::validate_client_handshake_transition(s_ccr, rfc::TLS_HS_CERTIFICATE_REQUEST, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_cr, "ClientWaitCertCr accepts CertificateRequest");
        sub.assert_eq(s_cert, wing::HsState.ClientWaitCert, "transitions to ClientWaitCert");

        // Duplicate CertificateRequest in ClientWaitCert must be rejected
        let _, ok_dup_cr = wing::validate_client_handshake_transition(s_cert, rfc::TLS_HS_CERTIFICATE_REQUEST, wing::HandshakeMode.Full, false);
        sub.assert_false(ok_dup_cr, "ClientWaitCert rejects duplicate CertificateRequest");

        let s_cv, ok_c = wing::validate_client_handshake_transition(s_cert, rfc::TLS_HS_CERTIFICATE, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_c, "ClientWaitCert accepts Certificate");
        sub.assert_eq(s_cv, wing::HsState.ClientWaitCV, "transitions to ClientWaitCV");

        // Skipping CertificateVerify directly to Finished must be rejected
        let _, ok_skip_cv = wing::validate_client_handshake_transition(s_cv, rfc::TLS_HS_FINISHED, wing::HandshakeMode.Full, false);
        sub.assert_false(ok_skip_cv, "ClientWaitCV rejects Finished before CertificateVerify");

        let s_fin, ok_cv = wing::validate_client_handshake_transition(s_cv, rfc::TLS_HS_CERTIFICATE_VERIFY, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_cv, "ClientWaitCV accepts CertificateVerify");
        sub.assert_eq(s_fin, wing::HsState.ClientWaitFinished, "transitions to ClientWaitFinished");

        let s_conn, ok_fin = wing::validate_client_handshake_transition(s_fin, rfc::TLS_HS_FINISHED, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_fin, "ClientWaitFinished accepts Finished");
        sub.assert_eq(s_conn, wing::HsState.Connected, "transitions to Connected");

        // Connected accepts NewSessionTicket and KeyUpdate, rejects re-handshake ServerHello
        let s_nst, ok_nst = wing::validate_client_handshake_transition(s_conn, rfc::TLS_HS_NEW_SESSION_TICKET, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_nst, "Connected accepts NewSessionTicket");
        sub.assert_eq(s_nst, wing::HsState.Connected, "remains Connected after NST");

        let s_ku, ok_ku = wing::validate_client_handshake_transition(s_conn, rfc::TLS_HS_KEY_UPDATE, wing::HandshakeMode.Full, false);
        sub.assert_true(ok_ku, "Connected accepts KeyUpdate");
        sub.assert_eq(s_ku, wing::HsState.Connected, "remains Connected after KeyUpdate");

        let _, ok_re_sh = wing::validate_client_handshake_transition(s_conn, rfc::TLS_HS_SERVER_HELLO, wing::HandshakeMode.Full, false);
        sub.assert_false(ok_re_sh, "Connected rejects unexpected ServerHello");
    };

    t.run("RUSTLS-MSG-01: Handshake Message Byte-by-Byte Truncation & Malformed Extensions (handshake_test.rs)") { sub =>
        // 1. CertificateRequest byte-by-byte truncation loop
        var cr_wire: u8[..128] = [];
        let schemes: u16[2] = [rfc::SIG_SCHEME_ED25519, rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256];
        sub.assert_true(wing::encode_certificate_request(cr_wire, "ctx", schemes[..]), "encode CertificateRequest with context");
        var i: i64 = 0;
        while i < cr_wire.len - 1 {
            var tmp_cr = wing::CertificateRequestMsg { .. };
            // Post-handshake allow non-empty context (true)
            let ok_t = wing::parse_certificate_request(cr_wire[..i], true, tmp_cr);
            sub.assert_false(ok_t, "truncated CertificateRequest rejected");
            i += 1;
        }
        // Non-empty context in initial handshake (post_handshake = false) must be rejected per RFC 8446 §4.3.2
        var init_cr = wing::CertificateRequestMsg { .. };
        sub.assert_false(wing::parse_certificate_request(cr_wire[..], false, init_cr), "non-empty context in initial handshake rejected");
        sub.assert_true(wing::parse_certificate_request(cr_wire[..], true, init_cr), "non-empty context in post-handshake accepted");

        // 2. CertificateVerify byte-by-byte truncation loop
        var cv_wire: u8[..128] = [];
        let dummy_sig: u8[64] = [0x42; 64];
        sub.assert_true(wing::encode_client_certificate_verify(cv_wire, rfc::SIG_SCHEME_ED25519, dummy_sig[..]), "encode CertificateVerify");
        var j: i64 = 0;
        while j < cv_wire.len - 1 {
            let _, _, ok_cv_t = wing::parse_certificate_verify(cv_wire[..j]);
            sub.assert_false(ok_cv_t, "truncated CertificateVerify rejected");
            j += 1;
        }

        // 3. CompressedCertificate (RFC 8879) malformed header & truncation checks via both wing::parse_compressed_certificate and internal::parse_compressed_certificate_msg
        let comp_bytes = "compressed_payload_bytes";
        var cc_msg = internal::CompressedCertificate {
            algorithm:                      rfc::CERT_COMPRESSION_ZSTD,
            uncompressed_length:            128,
            compressed_certificate_message: comp_bytes,
        };
        var cc_wire: u8[..128] = [];
        sub.assert_true(internal::encode_compressed_certificate(cc_msg, cc_wire), "encode CompressedCertificate message");
        var pub_cc_wire: u8[>..] = [];
        wing::encode_compressed_certificate_payload(pub_cc_wire, rfc::CERT_COMPRESSION_ZSTD, 128, comp_bytes);
        sub.assert_bytes_eq(pub_cc_wire[..], cc_wire[..], "public and internal RFC 8879 encoders produce identical 8B+data wire format");

        var k: i64 = 0;
        while k < cc_wire.len {
            var tmp_cc = internal::CompressedCertificate { .. };
            let ok_cc_t = internal::parse_compressed_certificate_msg(cc_wire[..k], tmp_cc);
            sub.assert_false(ok_cc_t, "truncated CompressedCertificate rejected by internal parser");
            let _, ok_pub_t = wing::parse_compressed_certificate(pub_cc_wire[..k]);
            sub.assert_false(ok_pub_t, "truncated CompressedCertificate rejected by public wing::parse_compressed_certificate");
            k += 1;
        }
        var full_cc = internal::CompressedCertificate { .. };
        sub.assert_true(internal::parse_compressed_certificate_msg(cc_wire[..], full_cc), "full CompressedCertificate parsed");
        sub.assert_eq(full_cc.algorithm, rfc::CERT_COMPRESSION_ZSTD, "algorithm matches Zstd");
        sub.assert_eq(full_cc.uncompressed_length, 128, "uncompressed_length matches 128");
        let full_pub_cc, ok_full_pub = wing::parse_compressed_certificate(pub_cc_wire[..]);
        sub.assert_true(ok_full_pub, "full CompressedCertificate parsed by public API");
        sub.assert_eq(full_pub_cc.uncompressed_len, 128, "public API uncompressed_len matches 128");

        // Unknown compression algorithm (0x9999) rejected
        var bad_algo_wire: u8[..128] = [];
        bad_algo_wire.append(cc_wire[..]);
        bad_algo_wire[0] = 0x99;
        bad_algo_wire[1] = 0x99;
        var bad_cc = internal::CompressedCertificate { .. };
        sub.assert_false(internal::parse_compressed_certificate_msg(bad_algo_wire[..], bad_cc), "unknown compression algorithm 0x9999 rejected");

        // Zero uncompressed_len (0) rejected per RFC 8879 §4
        var zero_ulen_wire: u8[..128] = [];
        zero_ulen_wire.append(cc_wire[..]);
        zero_ulen_wire[2] = 0x00;
        zero_ulen_wire[3] = 0x00;
        zero_ulen_wire[4] = 0x00;
        sub.assert_false(internal::parse_compressed_certificate_msg(zero_ulen_wire[..], bad_cc), "uncompressed_len == 0 rejected");
    };

    t.run("RUSTLS-X509-01: SAN Exact Label Boundaries & Leap-Year ASN.1 Time Vectors") { sub =>
        // Exact 63-char label is valid per RFC 1035; 64-char label is invalid
        var label_63: u8[..128] = [];
        for _ in 63 { label_63.push('a'); }
        label_63.append(".example.com");
        sub.assert_true(wing::validate_san_dns_name(label_63[..]), "exact 63-byte label accepted");

        // Leap year date: 2024-02-29 23:59:59 UTC is valid; 2023-02-29 is invalid
        let _, ok_leap_2024 = wing::parse_asn1_time(rfc::ASN1_TAG_GENERALIZED_TIME, "20240229235959Z");
        sub.assert_true(ok_leap_2024, "2024-02-29 (leap year) is valid");

        let _, ok_nonleap_2023 = wing::parse_asn1_time(rfc::ASN1_TAG_GENERALIZED_TIME, "20230229235959Z");
        sub.assert_false(ok_nonleap_2023, "2023-02-29 (non-leap year) rejected");

        // 30-day month boundary: April 31 (04-31) rejected
        let _, ok_apr31 = wing::parse_asn1_time(rfc::ASN1_TAG_GENERALIZED_TIME, "20260431120000Z");
        sub.assert_false(ok_apr31, "2026-04-31 rejected");
    };

    t.run("RUSTLS-REC-01: TLS 1.3 Record AEAD Sequence Desync & AAD Header Tamper Defense") { sub =>
        let key: u8[16] = [0x3A; 16];
        let iv:  u8[12] = [0x7C; 12];
        let msg = "rustls record layer test payload";

        var ct_buf: u8[128] = [0; 128];
        let sealed_len, alert_seal, ok_enc = wing::tls_record_seal_into(
            rfc::TLS_CIPHER_AES_128_GCM_SHA256,
            key[..],
            iv,
            42,
            0x17,
            msg,
            ct_buf[..],
        );
        sub.assert_true(ok_enc, "seal TLS 1.3 record at seq=42");
        sub.assert_eq(wing::tls_alert_to_u8(alert_seal), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "seal alert is CloseNotify");
        sub.assert_eq(sealed_len, 5 + msg.len + 1 + 16, "5B header + payload + 1B inner type + 16B tag");

        let ct_out = ct_buf[..sealed_len];

        // 1. Decrypt with matching seq=42 succeeds
        var pt_out: u8[>..] = [];
        let inner_t, alert_ok = wing::tls_record_decrypt_aes128_gcm(key, iv, 42, ct_out[..5], ct_out[5..], pt_out);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "decrypt succeeds at seq=42");
        sub.assert_eq(inner_t, 0x17, "inner type is 0x17");
        sub.assert_bytes_eq(pt_out[..], msg, "decrypted payload matches");

        // 2. Decrypt with mismatched sequence number (seq=43) fails with BadRecordMac
        var pt_bad_seq: u8[>..] = [];
        let _, alert_seq = wing::tls_record_decrypt_aes128_gcm(key, iv, 43, ct_out[..5], ct_out[5..], pt_bad_seq);
        sub.assert_eq(wing::tls_alert_to_u8(alert_seq), wing::tls_alert_to_u8(wing::TlsAlert.BadRecordMac), "wrong seq number fails with BadRecordMac");

        // 3. Decrypt with tampered legacy_record_version in 5-byte AAD header (0x0301 instead of 0x0303) fails with BadRecordMac
        let tampered_hdr: u8[5] = [ct_out[0], 0x03, 0x01, ct_out[3], ct_out[4]];
        var pt_bad_aad: u8[>..] = [];
        let _, alert_aad = wing::tls_record_decrypt_aes128_gcm(key, iv, 42, tampered_hdr[..], ct_out[5..], pt_bad_aad);
        sub.assert_eq(wing::tls_alert_to_u8(alert_aad), wing::tls_alert_to_u8(wing::TlsAlert.BadRecordMac), "tampered AAD header version fails with BadRecordMac");
    };

    t.run("RUSTLS-EXT-01: Duplicate Extensions, SupportedVersions & NewSessionTicket Validation (handshake_test.rs)") { sub =>
        // 1. Duplicate extensions in parse_extensions_block must be rejected (RFC 8446 §4.2)
        // Two extensions with type 0x002B (supported_versions)
        let dup_ext_block: u8[14] = [
            0x00, 0x0C,
            0x00, 0x2B, 0x00, 0x02, 0x03, 0x04,
            0x00, 0x2B, 0x00, 0x02, 0x03, 0x03,
        ];
        var ext_entries: wing::TlsExtensionEntry[..32] = [];
        sub.assert_false(wing::parse_extensions_block(dup_ext_block[..], ext_entries), "duplicate extension 0x002B rejected");

        // Trailing byte after extension block length rejected
        let trailing_ext_block: u8[9] = [0x00, 0x06, 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, 0xFF];
        sub.assert_false(wing::parse_extensions_block(trailing_ext_block[..], ext_entries), "trailing byte after extensions block rejected");

        // 2. parse_client_supported_versions edge cases (RFC 8446 §4.2.1)
        let sv_valid: u8[5] = [0x04, 0x03, 0x04, 0x03, 0x03];
        let has_13, ok_sv = wing::parse_client_supported_versions(sv_valid[..]);
        sub.assert_true(ok_sv && has_13, "valid client supported_versions [0x0304, 0x0303] accepted");

        let sv_dup: u8[5] = [0x04, 0x03, 0x04, 0x03, 0x04];
        let _, ok_sv_dup = wing::parse_client_supported_versions(sv_dup[..]);
        sub.assert_false(ok_sv_dup, "duplicate version 0x0304 in supported_versions rejected");

        let sv_empty: u8[1] = [0x00];
        let _, ok_sv_empty = wing::parse_client_supported_versions(sv_empty[..]);
        sub.assert_false(ok_sv_empty, "empty supported_versions list rejected");

        let sv_odd: u8[4] = [0x03, 0x03, 0x04, 0x03];
        let _, ok_sv_odd = wing::parse_client_supported_versions(sv_odd[..]);
        sub.assert_false(ok_sv_odd, "odd byte length in supported_versions rejected");

        // 3. NewSessionTicket validation (RFC 8446 §4.6.1):
        // Valid ticket with max_early_data_size = 16384
        var valid_nst_wire: u8[..64] = [];
        sub.assert_true(
            wing::encode_new_session_ticket(valid_nst_wire, 3600, 0x11223344, "nonce1", "ticket-bytes-01", 16384),
            "encode valid NewSessionTicket",
        );
        var parsed_nst = wing::NewSessionTicketMsg { .. };
        sub.assert_true(wing::parse_new_session_ticket(valid_nst_wire[..], parsed_nst), "parse valid NewSessionTicket");
        sub.assert_true(parsed_nst.has_early_data, "has_early_data is true");
        sub.assert_eq(parsed_nst.max_early_data_size, 16384, "max_early_data_size is 16384");

        // Lifetime > 604800s (7 days) rejected
        var bad_life_wire: u8[..64] = [];
        core::append_u32_be(bad_life_wire, 604801);
        core::append_u32_be(bad_life_wire, 1);
        bad_life_wire.push(1); bad_life_wire.push(0xAA);
        core::append_u16_be(bad_life_wire, 1); bad_life_wire.push(0xBB);
        core::append_u16_be(bad_life_wire, 0);
        sub.assert_false(wing::parse_new_session_ticket(bad_life_wire[..], parsed_nst), "ticket_lifetime > 604800 rejected");

        // Empty ticket (ticket<1..2^16-1> with length 0) rejected
        var empty_tkt_wire: u8[..64] = [];
        core::append_u32_be(empty_tkt_wire, 300);
        core::append_u32_be(empty_tkt_wire, 1);
        empty_tkt_wire.push(1); empty_tkt_wire.push(0xAA);
        core::append_u16_be(empty_tkt_wire, 0); // ticket length = 0 (illegal)
        core::append_u16_be(empty_tkt_wire, 0);
        sub.assert_false(wing::parse_new_session_ticket(empty_tkt_wire[..], parsed_nst), "zero-length ticket in NST rejected");

        // Duplicate ticket_nonce in SessionTicketCache rejected
        var cache = wing::SessionTicketCache { .. };
        sub.assert_true(wing::cache_session_ticket(cache, parsed_nst), "first NST cached");
        sub.assert_false(wing::cache_session_ticket(cache, parsed_nst), "duplicate NST nonce/ticket rejected by cache");
    };
}

// ----------------------------------------------------------------------------
// 28. X.509, Server CONNECT Hygiene & Akamai (tls/*, server/*, fingerprint/*)
// ----------------------------------------------------------------------------
fn test_x509_critical_ext_server_connect_and_akamai(t: lit::T&) {
    t.run("verify_signature_scheme_curve_binding rejects generic EC OID without curve match") { sub =>
        let ok = wing::verify_signature_scheme_curve_binding(
            rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
            rfc::OID_EC_PUBLIC_KEY[..],
        );
        sub.assert_false(ok, "Generic id-ecPublicKey without curve binding MUST be rejected");
    };

    t.run("HTTP/1 CONNECT sets Connection: close and consumes all bytes (CVE-2026-94439)") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);

        var wire_in: u8[..256] = [];
        wire_in.append("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: example.com\r\n\r\n");

        var wire_out: u8[..1024] = [];
        let count, total_consumed, ok, wants_close = wing::handle_connection_wire_pipelined_stream(server, "127.0.0.1", wire_in[..], 1000, wire_out);
        sub.assert_true(ok, "CONNECT request handled");
        sub.assert_true(wants_close, "CONNECT request must set wants_close");
        sub.assert_eq(count, 1, "Only the CONNECT request was processed");
        sub.assert_eq(total_consumed, wire_in.len, "All post-CONNECT tunnel bytes consumed to prevent HTTP/1 pipelining smuggling");
        sub.assert_true(core::contains(wire_out[..], "connection: close") || core::contains(wire_out[..], "Connection: close"), "CONNECT response must contain Connection: close");
    };

    t.run("parse_akamai_fingerprint rejects > 16 settings") { sub =>
        var raw_fp: u8[..512] = [];
        for i in 17 {
            if i > 0 { raw_fp.push(';'); }
            format(raw_fp, i + 1);
            raw_fp.push(':');
            raw_fp.append("100");
        }
        raw_fp.append("|15663105|0|m,a,s,p");

        let fp, ok = wing::parse_akamai_fingerprint(raw_fp[..]);
        sub.assert_false(ok, "Akamai fingerprint with > 16 settings MUST return false rather than dropping settings");
    };

    t.run("order_pseudo_headers handles pseudo_headers > 4 chars without abort") { sub =>
        var fp = wing::AkamaiFingerprint { .. };
        fp.pseudo_headers.push('m');
        fp.pseudo_headers.push('a');
        fp.pseudo_headers.push('s');
        fp.pseudo_headers.push('p');
        fp.pseudo_headers.push('x'); // 5th pseudo header

        var out_hdrs = wing::HeaderMap { .. };
        wing::order_pseudo_headers(fp, "GET", "example.com", "https", "/", out_hdrs);
        sub.assert_eq(out_hdrs.entries.len, 4, "Bounded to 4 pseudo headers without abort");
    };
}

// ----------------------------------------------------------------------------
// 29. X.509 URI Name Constraints Evasion via @ in Path/Query & ?/# Suffix
// ----------------------------------------------------------------------------
fn test_x509_uri_name_constraints_evasion(t: lit::T&) {
    t.run("URI name constraints: reject @ in path/query smuggling permitted host") { sub =>
        // Attacker attempts to bypass name constraints by putting @ in the path:
        // Host is "evil.com", path contains "@permitted.example.com"
        let candidate = "https://evil.com/path@permitted.example.com";
        let res = wing::match_uri_name_constraint(candidate, "permitted.example.com");
        sub.assert_false(res, "evil.com with @permitted in path MUST NOT match constraint permitted.example.com");

        let candidate_q = "https://evil.com/resource?foo=bar@permitted.example.com";
        let res_q = wing::match_uri_name_constraint(candidate_q, "permitted.example.com");
        sub.assert_false(res_q, "evil.com with @permitted in query MUST NOT match constraint permitted.example.com");
    };

    t.run("URI name constraints: reject ? or # suffix confusion after host") { sub =>
        // Attacker attempts to smuggle suffix match by ending host with ? or #
        let candidate_q = "https://evil.com?.permitted.example.com";
        let res_q = wing::match_uri_name_constraint(candidate_q, "permitted.example.com");
        sub.assert_false(res_q, "evil.com?.permitted.example.com MUST NOT match permitted.example.com");

        let candidate_h = "https://evil.com#.permitted.example.com";
        let res_h = wing::match_uri_name_constraint(candidate_h, "permitted.example.com");
        sub.assert_false(res_h, "evil.com#.permitted.example.com MUST NOT match permitted.example.com");
    };

    t.run("URI name constraints: reject userinfo in authority and IPv4 literals for dNSName") { sub =>
        // RFC 5280 §4.2.1.10: URI SAN with userinfo cannot satisfy a DNS name constraint
        let cand_user = "https://user:pass@permitted.example.com/path";
        let res_u = wing::match_uri_name_constraint(cand_user, "permitted.example.com");
        sub.assert_false(res_u, "userinfo in URI authority MUST NOT satisfy DNS constraint");

        // IPv4 address literal cannot satisfy a dNSName constraint
        let cand_ip = "https://192.168.1.1/path";
        let res_ip = wing::match_uri_name_constraint(cand_ip, "192.168.1.1");
        sub.assert_false(res_ip, "IPv4 literal MUST NOT satisfy dNSName constraint");
    };

    t.run("URI name constraints: valid DNS matches succeed") { sub =>
        let cand_valid = "https://sub.permitted.example.com/path";
        let res_v = wing::match_uri_name_constraint(cand_valid, "permitted.example.com");
        sub.assert_true(res_v, "valid subdomain matches constraint");

        let cand_exact = "https://permitted.example.com/path";
        let res_e = wing::match_uri_name_constraint(cand_exact, "permitted.example.com");
        sub.assert_true(res_e, "exact domain matches constraint");
    };
}

// ----------------------------------------------------------------------------
// 30. X.509 DNS Name Constraints Wildcard & Empty/Leading Dot Validation
// ----------------------------------------------------------------------------
fn test_x509_dns_name_constraint_wildcard_and_empty_labels(t: lit::T&) {
    t.run("DNS name constraints: reject empty labels and leading dots in candidate") { sub =>
        // Candidate with empty label: "..example.com"
        let res_empty = wing::match_dns_name_constraint("..example.com", ".example.com");
        sub.assert_false(res_empty, "candidate with .. MUST NOT match constraint");

        // Candidate with leading dot: ".example.com"
        let res_lead = wing::match_dns_name_constraint(".example.com", ".example.com");
        sub.assert_false(res_lead, "candidate with leading dot MUST NOT match constraint");

        // Candidate with interior empty label: "sub..example.com"
        let res_inner = wing::match_dns_name_constraint("sub..example.com", "example.com");
        sub.assert_false(res_inner, "candidate with interior .. MUST NOT match constraint");
    };

    t.run("DNS name constraints: wildcard matching rules") { sub =>
        // *.example.com matches constraint .example.com
        let res_wc = wing::match_dns_name_constraint("*.example.com", ".example.com");
        sub.assert_true(res_wc, "*.example.com MUST match .example.com");

        // *.example.com matches constraint example.com
        let res_wc2 = wing::match_dns_name_constraint("*.example.com", "example.com");
        sub.assert_true(res_wc2, "*.example.com MUST match example.com");

        // *.other.com does not match example.com
        let res_diff = wing::match_dns_name_constraint("*.other.com", "example.com");
        sub.assert_false(res_diff, "*.other.com MUST NOT match example.com");
    };

    t.run("DNS name constraints: apex and subdomain distinction") { sub =>
        // Constraint .example.com MUST NOT match example.com itself
        let res_apex = wing::match_dns_name_constraint("example.com", ".example.com");
        sub.assert_false(res_apex, "example.com MUST NOT match .example.com");

        // Constraint example.com MUST match example.com itself
        let res_apex2 = wing::match_dns_name_constraint("example.com", "example.com");
        sub.assert_true(res_apex2, "example.com MUST match example.com");

        // Suffix collision: badexample.com MUST NOT match example.com
        let res_bad = wing::match_dns_name_constraint("badexample.com", "example.com");
        sub.assert_false(res_bad, "badexample.com MUST NOT match example.com");
    };
}

// ----------------------------------------------------------------------------
// 31. X.509 ASN.1 Time Parsing Bounds & Overflow Defense
// ----------------------------------------------------------------------------
fn test_x509_asn1_time_parsing_bounds(t: lit::T&) {
    t.run("parse_utc_time: reject out-of-bound calendar fields") { sub =>
        // Valid: "260101120000Z" (2026-01-01 12:00:00 UTC)
        let _, ok_valid = wing::parse_utc_time("260101120000Z");
        sub.assert_true(ok_valid, "valid UTC time parsed");

        // Month 00
        let _, ok_m0 = wing::parse_utc_time("260001120000Z");
        sub.assert_false(ok_m0, "Month 00 rejected");

        // Month 13
        let _, ok_m13 = wing::parse_utc_time("261301120000Z");
        sub.assert_false(ok_m13, "Month 13 rejected");

        // Day 00
        let _, ok_d0 = wing::parse_utc_time("260100120000Z");
        sub.assert_false(ok_d0, "Day 00 rejected");

        // Day 32
        let _, ok_d32 = wing::parse_utc_time("260132120000Z");
        sub.assert_false(ok_d32, "Day 32 rejected");

        // Hour 24
        let _, ok_h24 = wing::parse_utc_time("260101240000Z");
        sub.assert_false(ok_h24, "Hour 24 rejected");

        // Minute 60
        let _, ok_min60 = wing::parse_utc_time("260101126000Z");
        sub.assert_false(ok_min60, "Minute 60 rejected");

        // Second 61
        let _, ok_s61 = wing::parse_utc_time("260101120061Z");
        sub.assert_false(ok_s61, "Second 61 rejected");
    };

    t.run("parse_generalized_time: reject out-of-bound calendar fields") { sub =>
        // Valid: "20260101120000Z"
        let _, ok_valid = wing::parse_generalized_time("20260101120000Z");
        sub.assert_true(ok_valid, "valid Generalized time parsed");

        // Month 00
        let _, ok_m0 = wing::parse_generalized_time("20260001120000Z");
        sub.assert_false(ok_m0, "Month 00 rejected");

        // Month 13
        let _, ok_m13 = wing::parse_generalized_time("20261301120000Z");
        sub.assert_false(ok_m13, "Month 13 rejected");

        // Day 00
        let _, ok_d0 = wing::parse_generalized_time("20260100120000Z");
        sub.assert_false(ok_d0, "Day 00 rejected");

        // Day 32
        let _, ok_d32 = wing::parse_generalized_time("20260132120000Z");
        sub.assert_false(ok_d32, "Day 32 rejected");

        // Hour 24
        let _, ok_h24 = wing::parse_generalized_time("20260101240000Z");
        sub.assert_false(ok_h24, "Hour 24 rejected");

        // Minute 60
        let _, ok_min60 = wing::parse_generalized_time("20260101126000Z");
        sub.assert_false(ok_min60, "Minute 60 rejected");

        // Second 61
        let _, ok_s61 = wing::parse_generalized_time("20260101120061Z");
        sub.assert_false(ok_s61, "Second 61 rejected");
    };
}

// ----------------------------------------------------------------------------
// 32. X.509 Basic Constraints Negative or Non-CA PathLen Defense (RFC 5280 §4.2.1.9)
// ----------------------------------------------------------------------------
fn test_x509_basic_constraints_negative_or_non_ca_pathlen(t: lit::T&) {
    t.run("BasicConstraints: reject negative pathLenConstraint in CA cert") { sub =>
        // DER sequence: [BOOLEAN TRUE, INTEGER -1]
        // 30 06:
        //   01 01 FF (cA: TRUE)
        //   02 01 FF (pathLen: -1)
        var bc_der: u8[..8] = [0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0xFF];
        var cert = wing::ParsedCert { .. };
        var c = core::cursor_from(bc_der[..]);
        wing::x509_parse_basic_constraints_ext(c, cert);

        sub.assert_true(cert.has_unsupported_critical, "negative pathLenConstraint MUST mark cert unsupported/malformed");
    };

    t.run("BasicConstraints: reject pathLenConstraint when cA is false") { sub =>
        // DER sequence: [BOOLEAN FALSE, INTEGER 3]
        // 30 06:
        //   01 01 00 (cA: FALSE)
        //   02 01 03 (pathLen: 3)
        var bc_der: u8[..8] = [0x30, 0x06, 0x01, 0x01, 0x00, 0x02, 0x01, 0x03];
        var cert = wing::ParsedCert { .. };
        var c = core::cursor_from(bc_der[..]);
        wing::x509_parse_basic_constraints_ext(c, cert);

        sub.assert_true(cert.has_unsupported_critical, "pathLenConstraint on non-CA cert MUST mark cert unsupported/malformed");
    };
}

// ----------------------------------------------------------------------------
// 33. X.509 Name Constraints Subtree Base dNSName Validation (RFC 5280 §4.2.1.10)
// ----------------------------------------------------------------------------
fn test_x509_name_constraints_subtree_dns_nul(t: lit::T&) {
    t.run("NameConstraints: reject subtree base dNSName with embedded NUL") { sub =>
        var subtree_buf: u8[..32] = [];
        // [2] dNSName tag 0x82, length 12: "example\0.com"
        subtree_buf.push(0x82);
        subtree_buf.push(12);
        subtree_buf.append("example\0.com");

        var c = core::cursor_from(subtree_buf[..]);
        var out_type = wing::SanType.Other;
        var out_val = core::cursor_from(subtree_buf[..0]);
        let ok = wing::x509_parse_general_subtree_base(c, out_type, out_val);
        sub.assert_false(ok, "subtree base dNSName with embedded NUL MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 34. X.509 DNS SAN TLD Wildcard & IP Literal Defense
// ----------------------------------------------------------------------------
fn test_x509_san_tld_wildcard(t: lit::T&) {
    // TLD wildcard *.com must NOT match evil.com (RFC 6125 §6.4.3)
    t.assert_false(wing::match_dns_san("*.com", "evil.com"), "*.com must not match evil.com");
    // Valid wildcard *.example.com must match sub.example.com
    t.assert_true(wing::match_dns_san("*.example.com", "sub.example.com"), "*.example.com matches sub.example.com");
    // Wildcard must not match IPv4
    t.assert_false(wing::match_dns_san("*.168.1.1", "192.168.1.1"), "Wildcard must not match IPv4 literal");
}

fn main() {
    var runner = lit::new_runner("TLS 1.3 Record Layer, ECH, mTLS, and PKI Extensions Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. ByteCursor & ByteBuilder Framing Invariants", test_wireframer_cursor_and_builder_framing);
    lit::run_case(runner, "2. TLS Record Layer Framing & Alert Invariants", test_wireframer_tls_record_invariants);
    lit::run_case(runner, "3. RFC 8446 Padding, All-Zero & InnerPlaintext Invariants", test_round2_padding_and_empty_record_invariants);
    lit::run_case(runner, "4. RFC 8446 Framing, Minimum Size & DoS Invariants", test_round2_framing_and_dos_invariants);
    lit::run_case(runner, "5. RFC 8446 CCS Invariants & Flood Protection", test_round3_ccs_and_protected_record_invariants);
    lit::run_case(runner, "6. RFC 9001 QUIC Crypto Gateway & Stream Bounds", test_round3_quic_crypto_and_framing_invariants);
    lit::run_case(runner, "7. DNS Wire Format & RFC 9460 HTTPS Resource Records", test_dns_and_https_rr);
    lit::run_case(runner, "8. Encrypted Client Hello (ECH) Wire & HPKE Handshake", test_ech_protocol);
    lit::run_case(runner, "9. RFC 9849 ECH constants", test_ech_rfc9849_citations);
    lit::run_case(runner, "10. DNS-over-HTTPS (DoH RFC 8484) & Automated ECH Discovery", test_doh_and_automated_ech_discovery);
    lit::run_case(runner, "11. CertificateRequest Codec", test_certificate_request_codec);
    lit::run_case(runner, "12. Empty Client Certificate", test_empty_client_certificate);
    lit::run_case(runner, "13. Client CertificateVerify Ed25519", test_client_certificate_verify_ed25519);
    lit::run_case(runner, "14. Post-Quantum TLS 1.3 Key Exchange", test_post_quantum_hybrid);
    lit::run_case(runner, "15. RFC 8879 TLS Certificate Compression via Zstandard", test_rfc8879_certificate_compression);
    lit::run_case(runner, "16. TLS ClientHello Fragmentation & DPI Evasion", test_tls_client_hello_fragmentation);
    lit::run_case(runner, "17. DNS Cache with Stale-While-Revalidate", test_dns_cache_and_stale_revalidate);
    lit::run_case(runner, "18. ASN.1 DER Length Canonicality & Bounds", test_asn1_der_length_canonicality);
    lit::run_case(runner, "19. ASN.1 INTEGER Canonical Rules & Serial Invariants", test_asn1_der_integer_and_serial_invariants);
    lit::run_case(runner, "20. X.509 SAN dNSName Hostname Validation", test_x509_san_dns_name_validation);
    lit::run_case(runner, "21. ASN.1 Time (UTCTime & GeneralizedTime) Canonical DER Parsing", test_x509_asn1_time_parsing);
    lit::run_case(runner, "22. Constant-Time Primitives & KeySlot Redaction", test_constant_time_primitives);
    lit::run_case(runner, "23. Dudect Statistical Welch's t-test Simulation", test_dudect_context_and_filtering);
    lit::run_case(runner, "24. NIST / RFC Cryptographic Primitives", test_pure_goose_crypto_primitives);
    lit::run_case(runner, "25. AEAD Authenticated Encryption: XChaCha20 & AES-GCM", test_aead_ciphers);
    lit::run_case(runner, "26. CryptoJar Container: PrivateJar, SignedJar & Rotation", test_crypto_jar_container);
    lit::run_case(runner, "27. Vendor Conformance Vectors (rustls Handshake, Extensions & Record Layer)", test_rustls_vendor_conformance);
    lit::run_case(runner, "28. X.509, Server CONNECT hygiene & Akamai (tls/*, server/*, fingerprint/*)", test_x509_critical_ext_server_connect_and_akamai);
    lit::run_case(runner, "29. X.509 URI Name Constraints Evasion via @ in Path/Query & ?/# Suffix", test_x509_uri_name_constraints_evasion);
    lit::run_case(runner, "30. X.509 DNS Name Constraints Wildcard & Empty/Leading Dot Validation", test_x509_dns_name_constraint_wildcard_and_empty_labels);
    lit::run_case(runner, "31. X.509 ASN.1 Time Parsing Bounds & Overflow Defense", test_x509_asn1_time_parsing_bounds);
    lit::run_case(runner, "32. X.509 Basic Constraints Negative or Non-CA PathLen Defense", test_x509_basic_constraints_negative_or_non_ca_pathlen);
    lit::run_case(runner, "33. X.509 Name Constraints Subtree Base dNSName Validation", test_x509_name_constraints_subtree_dns_nul);
    lit::run_case(runner, "34. X.509 DNS SAN TLD Wildcard & IP Literal Defense", test_x509_san_tld_wildcard);

    let ok = lit::finish(runner);
    assert(ok);
}
