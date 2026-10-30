// RUN: goose build -o %t.exe %s
// RUN: %t.exe
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: TLS 1.3 Record Layer, ECH, mTLS, and PKI Extensions Suite
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

fn test_wireframer_cursor_and_builder_framing(t: lit::T&) {
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

fn test_round2_framing_and_dos_invariants(t: lit::T&) {
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

// 1. DNS Wire Format & RFC 9460 HTTPS/SVCB Resource Records (Type 65)
fn test_dns_and_https_rr(t: lit::T&) {
    t.run("DNS-01: Query Encoding and Name Compression Decoding") { sub =>
        var query: u8[>..] = [];
        let ok_q = wing::build_dns_query("cloudflare.com", wing::DNS_QTYPE_HTTPS, 0x1234, query);
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
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_ALPN as u8);
        rdata.push(0x00); rdata.push(0x06); // len = 6
        rdata.push(0x02); rdata.append("h2");
        rdata.push(0x02); rdata.append("h3");

        // Key 3 (port)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_PORT as u8);
        rdata.push(0x00); rdata.push(0x02);
        rdata.push(0x01); rdata.push(0xBB); // 443

        // Key 4 (ipv4hint)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_IPV4HINT as u8);
        rdata.push(0x00); rdata.push(0x04);
        rdata.push(192); rdata.push(0); rdata.push(2); rdata.push(1);

        // Key 5 (ech)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_ECH as u8);
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

// 2. Encrypted Client Hello (ECH) Wire Formats & HPKE Privacy Handshake
fn test_ech_protocol(t: lit::T&) {
    t.run("ECH-01: ECHConfig & ECHConfigList Parsing") { sub =>
        // Construct a realistic synthetic ECHConfig wire buffer:
        // version: 0xFE0D (draft-13)
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
        sub.assert_eq(selected_cs.kdf_id, wing::HPKE_KDF_HKDF_SHA256, "kdf is SHA256");
        sub.assert_eq(selected_cs.aead_id, wing::HPKE_AEAD_AES_128_GCM, "aead is AES-128-GCM");

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
        config.version = wing::ECH_VERSION_DRAFT13;
        config.config_id = 7;
        config.kem_id = wing::HPKE_KEM_DHKEM_X25519_HKDF_SHA256;
        config.maximum_name_length = 64;
        for i in 32 { config.public_key[i] = server_pk[i]; }
        config.raw_bytes.append("synthetic-ech-config-raw-bytes");

        let cs = wing::EchCipherSuite {
            kdf_id:  wing::HPKE_KDF_HKDF_SHA256,
            aead_id: wing::HPKE_AEAD_AES_128_GCM,
        };

        // Real hidden SNI: "secret.crypto.internal"
        let real_sni = "secret.crypto.internal";
        var inner_hello: u8[>..] = [];
        inner_hello.append("ClientHelloInner:sni=");
        inner_hello.append(real_sni);
        inner_hello.append(";alpn=h2;keyshare=x25519");

        // Pad inner hello to hide length
        var inner_padded: u8[>..] = [];
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

        var enc:        u8[32]  = [0; 32];
        var ciphertext: u8[>..] = [];
        let ok_seal = wing::seal_ech_inner(
            config,
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
        var outer_ext_bytes: u8[>..] = [];
        let ok_ext = wing::build_ech_outer_extension(config.config_id, cs, enc, ciphertext[..], outer_ext_bytes);
        sub.assert_true(ok_ext, "build_ech_outer_extension succeeds");
        sub.assert_eq(outer_ext_bytes[0], wing::ECH_CLIENT_OUTER, "outer flag is 0x00");
        sub.assert_eq(outer_ext_bytes[5], 7, "config_id is 7");

        // Format inner ECH extension (must be 1 byte: 0x01)
        var inner_ext_bytes: u8[>..] = [];
        wing::build_ech_inner_extension(inner_ext_bytes);
        sub.assert_eq(inner_ext_bytes.len, 1, "inner extension is 1 byte");
        sub.assert_eq(inner_ext_bytes[0], wing::ECH_CLIENT_INNER, "inner flag is 0x01");

        // Server decrypts ciphertext using server_sk:
        var info: u8[..600] = [];
        info.append("tls ech");
        info.push(0x00);
        for i in config.raw_bytes.len { info.push(config.raw_bytes[i]); }

        var decrypted: u8[>..] = [];
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

// 3. DNS-over-HTTPS (RFC 8484) & Automated ECH Discovery (RFC 9460)
fn test_doh_and_automated_ech_discovery(t: lit::T&) {
    t.run("DoH-01: Wire Format Query Construction & URL Formatter") { sub =>
        // POST body
        var post_body: u8[>..] = [];
        let ok_post = wing::build_doh_post_body("cloudflare.com", wing::DNS_QTYPE_HTTPS, 0x1122, post_body);
        sub.assert_true(ok_post, "build_doh_post_body succeeds");
        sub.assert_gt(post_body.len, 12, "DoH post body contains DNS header + question");

        // GET URL
        var get_url: u8[..512] = [];
        let ok_get = wing::build_doh_get_url("https://cloudflare-dns.com/dns-query", "cloudflare.com", wing::DNS_QTYPE_HTTPS, get_url);
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
        dns_resp_wire.push(0x12); dns_resp_wire.push(0x34); // ID 0x1234
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
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_ECH as u8);
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
        mock.headers.push(wing::make_header("content-type", "application/dns-message"));
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

fn test_certificate_request_codec(t: lit::T&) {
    t.run("CertificateRequest Encoding & Parsing (RFC 8446 §4.3.2)") { sub =>
        var req_buf: u8[>..] = [];
        let sig_algs: u16[3] = [
            wing::SIG_SCHEME_ED25519,
            wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
            wing::SIG_SCHEME_RSA_PSS_RSAE_SHA256,
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
        sub.assert_eq(parsed_req.sig_algorithms[0], wing::SIG_SCHEME_ED25519, "First scheme is Ed25519");
        sub.assert_eq(parsed_req.sig_algorithms[1], wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256, "Second is P-256");
        sub.assert_eq(parsed_req.sig_algorithms[2], wing::SIG_SCHEME_RSA_PSS_RSAE_SHA256, "Third is RSA-PSS");
    };
}

fn test_empty_client_certificate(t: lit::T&) {
    t.run("Empty Client Certificate Handling (RFC 8446 §4.4.2)") { sub =>
        // Client without certificate must send empty Certificate message
        var cert_buf: u8[>..] = [];
        let enc_ok = wing::encode_client_certificate(cert_buf, "", "");
        sub.assert_true(enc_ok, "Encoded empty client Certificate");

        let is_empty, ok_p = wing::parse_certificate_header_is_empty(cert_buf[..]);
        sub.assert_true(ok_p, "Parsed certificate header");
        sub.assert_true(is_empty, "Certificate list is empty");

        // FSM verification: empty client cert transitions directly to ServerWaitFinished (CV omitted)
        let next_state, ok_trans = wing::server_wait_cert_step(wing::HS_MSG_CERTIFICATE, true);
        sub.assert_true(ok_trans, "Empty cert valid in ServerWaitCert");
        sub.assert_eq(next_state, wing::HsState.ServerWaitFinished, "Transitions directly to ServerWaitFinished");

        // Negative: if client mistakenly sends CertificateVerify after empty cert, server must reject
        let _, bad_cv = wing::server_wait_cv_step(wing::HS_MSG_CERTIFICATE_VERIFY, true);
        sub.assert_false(bad_cv, "CertificateVerify after empty cert strictly rejected");
    };
}

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
        var cv_buf: u8[>..] = [];
        let enc_cv = wing::encode_client_certificate_verify(cv_buf, wing::SIG_SCHEME_ED25519, sig[..]);
        sub.assert_true(enc_cv, "Encoded CertificateVerify message");

        // 3. Server side: parse and cryptographically verify
        let scheme, parsed_sig, ok_parse_cv = wing::parse_certificate_verify(cv_buf[..]);
        sub.assert_true(ok_parse_cv, "Parsed CertificateVerify");
        sub.assert_eq(scheme, wing::SIG_SCHEME_ED25519, "Scheme is Ed25519");
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

fn test_post_quantum_hybrid(t: lit::T&) {
    t.run("IANA NamedGroup Recognition") { sub =>
        sub.assert_true(internal::is_post_quantum_group(internal::GROUP_X25519_MLKEM768), "0x11EC is post-quantum group");
        sub.assert_true(internal::is_post_quantum_group(internal::GROUP_X25519_KYBER768_DRAFT00), "0x6399 is post-quantum draft group");
        sub.assert_false(internal::is_post_quantum_group(0x001D), "0x001D (X25519 classical) is NOT PQ group");
        sub.assert_false(internal::is_post_quantum_group(0x0017), "0x0017 (secp256r1) is NOT PQ group");
    };

    t.run("Hybrid 1184-Byte Client Key Share Wire Codec") { sub =>
        var share = internal::PostQuantumKeyShare {
            group: internal::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { share.x25519_public[i] = (i + 1) as u8; }
        for i in 1152 { share.mlkem768_public[i] = ((i * 7 + 3) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        share.format_hybrid_key_share(wire);
        // group (2) + len (2) + 1184 = 1188 bytes total
        sub.assert_eq(wire.len, 1188, "Wire length is exactly 1188 bytes");

        var parsed = internal::PostQuantumKeyShare { .. };
        let ok_parse = parsed.parse_hybrid_key_share(wire[..]);
        sub.assert_true(ok_parse, "Hybrid key share parsed via UFCS");
        sub.assert_eq(parsed.group, internal::GROUP_X25519_MLKEM768, "Group is 0x11EC");
        sub.assert_bytes_eq(parsed.x25519_public[..], share.x25519_public[..], "X25519 component matches");

        var mlkem_match = true;
        for i in 1152 {
            if parsed.mlkem768_public[i] != share.mlkem768_public[i] {
                mlkem_match = false;
                break;
            }
        }
        sub.assert_true(mlkem_match, "ML-KEM-768 1152-byte component matches verbatim");

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
            group: internal::GROUP_X25519_MLKEM768,
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
        sub.assert_eq(parsed_server.group, internal::GROUP_X25519_MLKEM768, "Server group is 0x11EC");
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

fn test_rfc8879_certificate_compression(t: lit::T&) {
    t.run("1. RFC 8879 Extension & Handshake Message Codecs") { sub =>
        let algos: u16[2] = [wing::CERT_COMPRESS_ZSTD, wing::CERT_COMPRESS_BROTLI];
        var ext_wire: u8[>..] = [];
        wing::encode_compress_certificate_extension(ext_wire, algos[..]);

        sub.assert_eq(ext_wire.len, 2 + 2 + 1 + 4, "Extension wire length: 2 type + 2 len + 1 list_len + 4 algorithms = 9 bytes");
        let ext_type = ((ext_wire[0] as u16) << 8) | ext_wire[1];
        sub.assert_eq(ext_type, wing::EXT_COMPRESS_CERTIFICATE, "Extension type is 27 (compress_certificate)");

        // Handshake payload roundtrip
        let fake_cert = "MIIB...Simulated X.509 Certificate Chain Data with Repetitive Certificate Metadata Blocks...";
        var compressed: u8[>..] = [];
        sub.assert_true(core::zstd_compress(fake_cert, compressed), "Zstandard compression of certificate succeeds");

        var hs_payload: u8[>..] = [];
        wing::encode_compressed_certificate_payload(
            hs_payload,
            wing::CERT_COMPRESS_ZSTD,
            fake_cert.len as u32,
            compressed[..],
        );

        let parsed, ok_parse = wing::parse_compressed_certificate(hs_payload[..]);
        sub.assert_true(ok_parse, "Parse CompressedCertificate payload");
        sub.assert_eq(parsed.algorithm, wing::CERT_COMPRESS_ZSTD, "Algorithm is Zstandard (3)");
        sub.assert_eq(parsed.uncompressed_len as i64, fake_cert.len as i64, "Uncompressed length matches original");

        // Decompress with native RFC 8878 Zstandard engine
        var decompressed: u8[>..] = [];
        sub.assert_true(wing::decompress_certificate_zstd(parsed.compressed_data, parsed.uncompressed_len, decompressed), "Decompression succeeds");
        sub.assert_bytes_eq(decompressed[..], fake_cert, "Decompressed certificate matches original plaintext exactly");
    };
}

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

fn test_dns_cache_and_stale_revalidate(t: lit::T&) {
    t.run("1. DNS Cache TTL and Stale-While-Revalidate Lifecycle") { sub =>
        var cache = wing::DnsCache { .. };

        var entry = wing::DnsCacheEntry {
            qtype:           wing::DNS_QTYPE_A,
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
        let status1 = wing::dns_cache_lookup(cache, "example.com", wing::DNS_QTYPE_A, 1100, hit1);
        sub.assert_eq(status1, wing::DnsCacheStatus.Fresh, "Lookup within TTL returns Fresh");
        sub.assert_eq(hit1.ipv4_hints[0], 0x5DB8D822, "Cached IPv4 address preserved");

        // 2. Stale lookup at t = 1500 (500s elapsed > 300s TTL, but < 3900s stale limit)
        var hit2 = wing::DnsCacheEntry { .. };
        let status2 = wing::dns_cache_lookup(cache, "example.com", wing::DNS_QTYPE_A, 1500, hit2);
        sub.assert_eq(status2, wing::DnsCacheStatus.Stale, "Lookup past TTL returns Stale (trigger background revalidation)");
        sub.assert_eq(hit2.ipv4_hints[0], 0x5DB8D822, "Stale cache hit still provides IP for zero-latency connection");

        // 3. Expired lookup at t = 5000 (4000s elapsed > 3900s total limit)
        var hit3 = wing::DnsCacheEntry { .. };
        let status3 = wing::dns_cache_lookup(cache, "example.com", wing::DNS_QTYPE_A, 5000, hit3);
        sub.assert_eq(status3, wing::DnsCacheStatus.Expired, "Lookup beyond stale window returns Expired");

        // 4. Missing domain lookup
        var hit4 = wing::DnsCacheEntry { .. };
        let status4 = wing::dns_cache_lookup(cache, "notfound.org", wing::DNS_QTYPE_A, 1100, hit4);
        sub.assert_eq(status4, wing::DnsCacheStatus.Expired, "Missing domain returns Expired");
    };
}

// --- Component: tls_asn1_x509_invariants ---
// Hardening & Security Invariants Suite for ASN.1 DER & X.509 Certificate Decoders (ITU-T X.690 & RFC 5280):
// 1. ASN.1 DER length canonicality, indefinite length bans, and integer overflow guards.
// 2. ASN.1 INTEGER canonical padding, negative serial number bans, and 20-octet limits.
// 3. SAN dNSName validation (null bytes, label lengths, hyphen boundaries).
// 4. ASN.1 UTCTime & GeneralizedTime strict DER canonical parsing.

fn test_asn1_der_length_canonicality(t: lit::T&) {
    t.run("ASN1-SEC-01: Short Form and Long Form Valid Lengths") { sub =>
        // Short form: 0x42 = 66
        let short_der: u8[1] = [0x42];
        var c1 = wing::cursor_from(short_der[..]);
        var out_len1: i64 = 0;
        let ok1 = wing::get_asn1_length(c1, out_len1);
        sub.assert_true(ok1, "short form length succeeds");
        sub.assert_eq(out_len1, 66, "out_len matches 66");

        // Long form: 2 bytes: 0x82 0x01 0x00 = 256
        let long_der: u8[3] = [0x82, 0x01, 0x00];
        var c2 = wing::cursor_from(long_der[..]);
        var out_len2: i64 = 0;
        let ok2 = wing::get_asn1_length(c2, out_len2);
        sub.assert_true(ok2, "long form length succeeds");
        sub.assert_eq(out_len2, 256, "out_len matches 256");
    };

    t.run("ASN1-SEC-02: BER Indefinite Length (0x80) strictly forbidden in DER") { sub =>
        let indef_der: u8[1] = [0x80];
        var c = wing::cursor_from(indef_der[..]);
        var out_len: i64 = 0;
        let ok = wing::get_asn1_length(c, out_len);
        sub.assert_false(ok, "indefinite length 0x80 must fail in DER per X.690 §8.1.3.6");
    };

    t.run("ASN1-SEC-03: Redundant Leading Zero in Long Form Length Rejected") { sub =>
        // 0x82 0x00 0x80 (2-byte length where first length byte is 0x00)
        let red_der: u8[3] = [0x82, 0x00, 0x80];
        var c = wing::cursor_from(red_der[..]);
        var out_len: i64 = 0;
        let ok = wing::get_asn1_length(c, out_len);
        sub.assert_false(ok, "redundant leading zero in long form length must be rejected");
    };

    t.run("ASN1-SEC-04: Reserved Initial Octet 0xFF and Truncated Lengths Rejected") { sub =>
        let ff_der: u8[1] = [0xFF];
        var c1 = wing::cursor_from(ff_der[..]);
        var out_len1: i64 = 0;
        let ok1 = wing::get_asn1_length(c1, out_len1);
        sub.assert_false(ok1, "reserved initial octet 0xFF must be rejected");

        // Declares 3 length bytes (0x83), but only 1 byte follows
        let trunc_der: u8[2] = [0x83, 0x01];
        var c2 = wing::cursor_from(trunc_der[..]);
        var out_len2: i64 = 0;
        let ok2 = wing::get_asn1_length(c2, out_len2);
        sub.assert_false(ok2, "truncated long form length must be rejected");
    };
}

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

fn test_x509_asn1_time_parsing(t: lit::T&) {
    t.run("ASN1-SEC-12: Valid UTCTime and GeneralizedTime Canonical DER") { sub =>
        // UTCTime: "261028120000Z" (2026-10-28 12:00:00 UTC)
        let utc_valid = "261028120000Z";
        let ts_utc, ok_utc = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, utc_valid);
        sub.assert_true(ok_utc, "valid UTCTime parses successfully");
        sub.assert_true(ts_utc > 0, "timestamp > 0");

        // GeneralizedTime: "20261028120000Z"
        let gen_valid = "20261028120000Z";
        let ts_gen, ok_gen = wing::parse_asn1_time(wing::ASN1_TAG_GENERALIZED_TIME, gen_valid);
        sub.assert_true(ok_gen, "valid GeneralizedTime parses successfully");
        sub.assert_true(ts_gen > 0, "timestamp > 0");
    };

    t.run("ASN1-SEC-13: Out-of-Bounds Calendar Values and Non-UTC Suffix Rejection") { sub =>
        // Month 13
        let bad_month = "261328120000Z";
        let _, ok_m = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, bad_month);
        sub.assert_false(ok_m, "month 13 must be rejected");

        // Day 32
        let bad_day = "261032120000Z";
        let _, ok_d = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, bad_day);
        sub.assert_false(ok_d, "day 32 must be rejected");

        // Hour 25
        let bad_hour = "261028250000Z";
        let _, ok_h = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, bad_hour);
        sub.assert_false(ok_h, "hour 25 must be rejected");

        // Non-UTC suffix: local time without 'Z' (strictly forbidden in DER per X.690 §11.7)
        let no_z = "261028120000";
        let _, ok_z = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, no_z);
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
// 1. Constant-Time Primitives & KeySlot Redaction
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
// 2. Dudect Statistical Welch's t-test Simulation
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
// 3. NIST / RFC Cryptographic Primitives
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
// 4. AEAD Authenticated Encryption: XChaCha20-Poly1305 & AES-256-GCM
// ----------------------------------------------------------------------------
fn test_aead_ciphers(t: lit::T&) {
    t.run("XChaCha20-Poly1305 Round-Trip & Tamper Resistance") { sub =>
        var key:   u8[32] = [0x42; 32];
        var nonce: u8[24] = [0x19; 24];
        let aad = "cookie_name=session_id";
        let plaintext = "user_id=12345&role=admin";

        var ciphertext: u8[>..] = [];
        let tag = core::xchacha20_poly1305_seal(key, nonce, plaintext, aad, ciphertext);
        sub.assert_eq(ciphertext.len, plaintext.len, "ciphertext length equals plaintext length");

        // Authentic decryption
        var decrypted: u8[>..] = [];
        let ok_auth = core::xchacha20_poly1305_open(key, nonce, ciphertext[..], aad, tag, decrypted);
        sub.assert_true(ok_auth, "authentic ciphertext opens successfully");
        sub.assert_eq(decrypted[..], plaintext, "decrypted plaintext matches original");

        // Tampered ciphertext bit must be rejected
        ciphertext[0] ^= 0x01;
        var dec_tampered: u8[>..] = [];
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

        var ciphertext: u8[>..] = [];
        let tag = core::aes256_gcm_seal(key, iv, plaintext, aad, ciphertext);
        sub.assert_eq(ciphertext.len, plaintext.len, "ciphertext length matches");

        // Authentic decryption
        var decrypted: u8[>..] = [];
        let ok_auth = core::aes256_gcm_open(key, iv, ciphertext[..], aad, tag, decrypted);
        sub.assert_true(ok_auth, "AES-256-GCM authentic decryption succeeds");
        sub.assert_eq(decrypted[..], plaintext, "decrypted plaintext matches original");

        // Tampered tag must be rejected
        var bad_tag = tag;
        bad_tag[15] ^= 0x80;
        var dec_bad: u8[>..] = [];
        let ok_tag_tamper = core::aes256_gcm_open(key, iv, ciphertext[..], aad, bad_tag, dec_bad);
        sub.assert_false(ok_tag_tamper, "tampered GHASH tag rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. CryptoJar Container: PrivateJar & SignedJar with Key Rotation
// ----------------------------------------------------------------------------
fn test_crypto_jar_container(t: lit::T&) {
    t.run("PrivateJar XChaCha20-Poly1305 (53B Overhead) & AAD Binding") { sub =>
        var store = wing::KeyStore { .. };
        var raw_key: u8[32] = [0x33; 32];
        let slot = core::new_key_slot(1, raw_key[..], 1700000000);
        wing::add_key(store, slot);

        var jar = wing::new_private_jar(store, false);

        var sealed_cookie: u8[>..] = [];
        let ok_seal = wing::private_jar_seal_binary(jar, "session_jwt", "payload_data_123", 1700000010, 0x123456789ABCDEF0, sealed_cookie);
        sub.assert_true(ok_seal, "private jar binary seal succeeds");
        sub.assert_eq(sealed_cookie.len, 53 + "payload_data_123".len, "exact 53B wire overhead");

        // Authentic open
        var opened: u8[>..] = [];
        let ok_open = wing::private_jar_open_binary(jar, "session_jwt", sealed_cookie[..], 1700000020, opened);
        sub.assert_true(ok_open, "private jar opens authentic cookie");
        sub.assert_eq(opened[..], "payload_data_123", "cookie payload verified");

        // AAD Binding: Trying to open with different cookie name must fail!
        var opened_bad: u8[>..] = [];
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

        var sealed_cookie: u8[>..] = [];
        let ok_seal = wing::private_jar_seal_binary(jar, "secure_sess", "secret_info", 1700000010, 0xFEDCBA9876543210, sealed_cookie);
        sub.assert_true(ok_seal, "HKDF AES-GCM seal succeeds");
        sub.assert_eq(sealed_cookie.len, 65 + "secret_info".len, "exact 65B wire overhead");

        var opened: u8[>..] = [];
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
// Suite Runner
// ----------------------------------------------------------------------------

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
    lit::run_case(runner, "9. DNS-over-HTTPS (DoH RFC 8484) & Automated ECH Discovery", test_doh_and_automated_ech_discovery);
    lit::run_case(runner, "10. CertificateRequest Codec", test_certificate_request_codec);
    lit::run_case(runner, "11. Empty Client Certificate", test_empty_client_certificate);
    lit::run_case(runner, "12. Client CertificateVerify Ed25519", test_client_certificate_verify_ed25519);
    lit::run_case(runner, "13. Post-Quantum TLS 1.3 Key Exchange", test_post_quantum_hybrid);
    lit::run_case(runner, "14. RFC 8879 TLS Certificate Compression via Zstandard", test_rfc8879_certificate_compression);
    lit::run_case(runner, "15. TLS ClientHello Fragmentation & DPI Evasion", test_tls_client_hello_fragmentation);
    lit::run_case(runner, "16. DNS Cache with Stale-While-Revalidate", test_dns_cache_and_stale_revalidate);
    lit::run_case(runner, "17. ASN.1 DER Length Canonicality & Bounds", test_asn1_der_length_canonicality);
    lit::run_case(runner, "18. ASN.1 INTEGER Canonical Rules & Serial Invariants", test_asn1_der_integer_and_serial_invariants);
    lit::run_case(runner, "19. X.509 SAN dNSName Hostname Validation", test_x509_san_dns_name_validation);
    lit::run_case(runner, "20. ASN.1 Time (UTCTime & GeneralizedTime) Canonical DER Parsing", test_x509_asn1_time_parsing);
    lit::run_case(runner, "21. Constant-Time Primitives & KeySlot Redaction", test_constant_time_primitives);
    lit::run_case(runner, "22. Dudect Statistical Welch's t-test Simulation", test_dudect_context_and_filtering);
    lit::run_case(runner, "23. NIST / RFC Cryptographic Primitives", test_pure_goose_crypto_primitives);
    lit::run_case(runner, "24. AEAD Authenticated Encryption: XChaCha20 & AES-GCM", test_aead_ciphers);
    lit::run_case(runner, "25. CryptoJar Container: PrivateJar, SignedJar & Rotation", test_crypto_jar_container);

    let ok = lit::finish(runner);
    assert(ok);
}
