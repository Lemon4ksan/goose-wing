// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/tls_test.goose
// Deterministic test suite for TLS 1.3 and X.509 PKI in Goose.
// Validates RFC 8446, RFC 9001 (QUIC Crypto), RFC 5280, RFC 6125, and zero-allocation invariants.
import std;
import core from "..";
import wing from "..";

// ============================================================================
// 1. ByteCursor, ByteBuilder, and Serialization Conformance
// ============================================================================
fn test_byte_cursor_and_builder(t: core::T&) {
    t.run("TLS-01: Zero-Copy ByteCursor Reading & Primitive Extraction") { sub =>
        let raw: u8[10] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAA, 0xBB];
        var c = wing::cursor_from(raw[..]);

        sub.assert_eq(wing::cursor_len(c), 10, "cursor starts at length 10");

        var u8_val: u8 = 0;
        sub.assert_true(wing::get_u8(c, u8_val), "get_u8 succeeds");
        sub.assert_eq(u8_val, 0x12, "u8 matches 0x12");
        sub.assert_eq(wing::cursor_len(c), 9, "len after u8 is 9");

        var u16_val: u16 = 0;
        sub.assert_true(wing::get_u16(c, u16_val), "get_u16 succeeds");
        sub.assert_eq(u16_val, 0x3456, "u16 matches 0x3456");

        var u24_val: u32 = 0;
        sub.assert_true(wing::get_u24(c, u24_val), "get_u24 succeeds");
        sub.assert_eq(u24_val, 0x789ABC, "u24 matches 0x789ABC");

        var u32_val: u32 = 0;
        sub.assert_true(wing::get_u32(c, u32_val), "get_u32 succeeds");
        sub.assert_eq(u32_val, 0xDEF0AABB, "u32 matches 0xDEF0AABB");

        sub.assert_eq(wing::cursor_len(c), 0, "cursor is empty");
        var underflow: u8 = 0;
        sub.assert_false(wing::get_u8(c, underflow), "underflow fails safely");
    };

    t.run("TLS-02: Length-Prefixed Zero-Copy Slicing") { sub =>
        // [len: 3, 0x01, 0x02, 0x03] || [len: 0x0002, 0xAA, 0xBB]
        let data: u8[8] = [0x03, 0x01, 0x02, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        var c = wing::cursor_from(data[..]);

        var p8 = wing::cursor_from(data[..0]);
        sub.assert_true(wing::get_u8_length_prefixed(c, p8), "read u8 prefixed slice");
        sub.assert_eq(wing::cursor_len(p8), 3, "p8 length is 3");
        sub.assert_eq(p8.buf[0], 0x01, "p8[0] == 1");
        sub.assert_eq(p8.buf[2], 0x03, "p8[2] == 3");

        var p16 = wing::cursor_from(data[..0]);
        sub.assert_true(wing::get_u16_length_prefixed(c, p16), "read u16 prefixed slice");
        sub.assert_eq(wing::cursor_len(p16), 2, "p16 length is 2");
        sub.assert_eq(p16.buf[0], 0xAA, "p16[0] == 0xAA");
        sub.assert_eq(p16.buf[1], 0xBB, "p16[1] == 0xBB");
    };

    t.run("TLS-03: ByteBuilder Nested Prefixes & Backpatching") { sub =>
        var b = wing::builder_init();
        wing::put_u8(b, 0xAA);

        // Nested u16 length-prefixed block
        sub.assert_true(wing::start_u16_prefix(b), "start u16 prefix");
        wing::put_u8(b, 0xBB);
        wing::put_u8(b, 0xCC);

        // Nested u8 length-prefixed block inside u16 block
        sub.assert_true(wing::start_u8_prefix(b), "start u8 prefix");
        wing::put_u8(b, 0xDD);
        sub.assert_true(wing::finish_u8_prefix(b), "finish u8 prefix");

        sub.assert_true(wing::finish_u16_prefix(b), "finish u16 prefix");

        // Expected output:
        // [0xAA] || [u16 len: 4 (0x00, 0x04)] || [0xBB, 0xCC] || [u8 len: 1 (0x01)] || [0xDD]
        sub.assert_eq(b.buf.len, 7, "total builder output length is 7");
        sub.assert_eq(b.buf[0], 0xAA, "byte 0 is 0xAA");
        sub.assert_eq(b.buf[1], 0x00, "byte 1 is u16 high len 0");
        sub.assert_eq(b.buf[2], 0x04, "byte 2 is u16 low len 4");
        sub.assert_eq(b.buf[3], 0xBB, "byte 3 is 0xBB");
        sub.assert_eq(b.buf[4], 0xCC, "byte 4 is 0xCC");
        sub.assert_eq(b.buf[5], 0x01, "byte 5 is u8 len 1");
        sub.assert_eq(b.buf[6], 0xDD, "byte 6 is 0xDD");
    };
}

// ============================================================================
// 2. TLS Record Layer Framing, Nonce & DoS Defenses
// ============================================================================
fn test_record_layer_and_dos(t: core::T&) {
    t.run("TLS-04: Record Header Parsing & Overflow Defense") { sub =>
        // Valid Handshake record (0x16, TLS 1.2 legacy version 0x0303, len 100)
        let valid_hdr: u8[5] = [0x16, 0x03, 0x03, 0x00, 0x64];
        let ct, ver, len, alert, ok = wing::parse_tls_record_header(valid_hdr[..]);
        sub.assert_true(ok, "valid header parsed");
        sub.assert_eq(ct, 0x16, "content type is handshake");
        sub.assert_eq(ver, 0x0303, "version is 0x0303");
        sub.assert_eq(len, 100, "length is 100");
        sub.assert_eq(wing::tls_alert_to_u8(alert), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "no error alert");

        // Record length exceeding MAX_RECORD_CIPHERTEXT_LEN (16640)
        let overflow_hdr: u8[5] = [0x17, 0x03, 0x03, 0x41, 0x01]; // 16641
        let _, _, _, alert_of, ok_of = wing::parse_tls_record_header(overflow_hdr[..]);
        sub.assert_false(ok_of, "overflow header rejected");
        sub.assert_eq(wing::tls_alert_to_u8(alert_of), wing::tls_alert_to_u8(wing::TlsAlert.RecordOverflow), "record overflow alert");

        // Non-compliant version: 0x0304 (TLS 1.3 in legacy_record_version forbidden by RFC 8446 §5.1)
        let v13_hdr: u8[5] = [0x17, 0x03, 0x04, 0x00, 0x10];
        let _, _, _, alert_ver, ok_ver = wing::parse_tls_record_header(v13_hdr[..]);
        sub.assert_false(ok_ver, "legacy version 0x0304 rejected");
        sub.assert_eq(wing::tls_alert_to_u8(alert_ver), wing::tls_alert_to_u8(wing::TlsAlert.ProtocolVersion), "protocol version alert");

        // Non-compliant version: 0x0300 (SSL 3.0)
        let v30_hdr: u8[5] = [0x17, 0x03, 0x00, 0x00, 0x10];
        let _, _, _, alert_v30, ok_v30 = wing::parse_tls_record_header(v30_hdr[..]);
        sub.assert_false(ok_v30, "legacy version 0x0300 rejected");
        sub.assert_eq(wing::tls_alert_to_u8(alert_v30), wing::tls_alert_to_u8(wing::TlsAlert.ProtocolVersion), "protocol version alert");

        // Invalid record content type (0x42 not in 0x14..0x17)
        let bad_ct_hdr: u8[5] = [0x42, 0x03, 0x03, 0x00, 0x10];
        let _, _, _, alert_ct, ok_ct = wing::parse_tls_record_header(bad_ct_hdr[..]);
        sub.assert_false(ok_ct, "unknown content type rejected");
        sub.assert_eq(wing::tls_alert_to_u8(alert_ct), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "unexpected message alert");

        // Header encoder bounds: rejecting ciphertext > 16640 and bad content type
        var enc_out: u8[>..] = [];
        sub.assert_false(wing::encode_tls_ciphertext_header(enc_out, 0x17, 16641), "encoder rejects oversized ciphertext");
        sub.assert_false(wing::encode_tls_ciphertext_header(enc_out, 0x99, 100), "encoder rejects invalid content type");
    };

    t.run("TLS-05: Nonce XOR Derivation & Sequence Overflow Defense") { sub =>
        var iv: u8[12] = [
            0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33,
        ];
        // Seq num = 1 -> nonce[11] ^= 1 -> 0x33 ^ 1 = 0x32
        let nonce1, ok_n1 = wing::compute_record_nonce(iv, 1);
        sub.assert_true(ok_n1, "nonce 1 derivation succeeds");
        sub.assert_eq(nonce1[0], 0x10, "nonce[0] unchanged");
        sub.assert_eq(nonce1[3], 0x13, "nonce[3] unchanged");
        sub.assert_eq(nonce1[11], 0x32, "nonce[11] XORed with 1");

        // Seq num = 0x0102 -> nonce[10] ^= 0x01, nonce[11] ^= 0x02
        let nonce2, ok_n2 = wing::compute_record_nonce(iv, 0x0102);
        sub.assert_true(ok_n2, "nonce 2 derivation succeeds");
        sub.assert_eq(nonce2[10], 0x32 ^ 0x01, "nonce[10] XORed with 0x01");
        sub.assert_eq(nonce2[11], 0x33 ^ 0x02, "nonce[11] XORed with 0x02");

        // Sequence number overflow protection (RFC 8446 Section 5.3):
        // 2^64 - 1 must not be used for nonce computation
        let _, ok_overflow = wing::compute_record_nonce(iv, 0xFFFFFFFFFFFFFFFF);
        sub.assert_false(ok_overflow, "rejects sequence number 2^64 - 1");

        // Counter wraparound protection
        var seq: u64 = 0xFFFFFFFFFFFFFFFE;
        sub.assert_true(wing::increment_record_seq_num(seq), "increment to 2^64 - 1 succeeds");
        sub.assert_eq(seq, 0xFFFFFFFFFFFFFFFF, "seq is 2^64 - 1");
        sub.assert_false(wing::increment_record_seq_num(seq), "refuses wraparound past 2^64 - 1");
        sub.assert_eq(seq, 0xFFFFFFFFFFFFFFFF, "counter preserved at 2^64 - 1 without wrapping");
    };

    t.run("TLS-06: TLSInnerPlaintext Unpacking & Trailing Padding Removal") { sub =>
        // Payload: "Hello World" (11 bytes) || ContentType: ApplicationData (0x17) || 4 zeroes padding
        let decrypted: u8[16] = [
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
            0x17, // true type
            0x00, 0x00, 0x00, 0x00, // padding
        ];

        let plain, inner_type, alert = wing::unpack_tls_inner_plaintext(decrypted[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "unpack ok");
        sub.assert_eq(inner_type, 0x17, "extracted application data type 0x17");
        sub.assert_eq(plain.len, 11, "plaintext length is 11");
        sub.assert_eq(plain[0], 0x48, "first byte is 'H'");
        sub.assert_eq(plain[10], 0x64, "last byte is 'd'");

        // Malformed record: all zero padding without ContentType
        let all_zeros: u8[8] = [0, 0, 0, 0, 0, 0, 0, 0];
        let _, _, alert_bad = wing::unpack_tls_inner_plaintext(all_zeros[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_bad), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "rejects all-zero record");

        // Plaintext length overflow (> 16384 bytes, RFC 8446 Section 5.4)
        var oversized: u8[16386] = [0xAA; 16386];
        oversized[16385] = 0x17; // valid inner content type, but plaintext len is 16385 > 16384
        let _, _, alert_overflow = wing::unpack_tls_inner_plaintext(oversized[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_overflow), wing::tls_alert_to_u8(wing::TlsAlert.RecordOverflow), "record overflow alert for inner plaintext > 16384");

        // Invalid inner ContentType (e.g. 0x42)
        let bad_inner: u8[4] = [0xAA, 0xBB, 0x42, 0x00];
        let _, _, alert_inner = wing::unpack_tls_inner_plaintext(bad_inner[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_inner), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "rejects invalid inner ContentType");
    };

    t.run("TLS-07: DoS Guard: Empty Records & Early Data Skipped Volume") { sub =>
        var filter = wing::RecordFilterState { empty_records_count: 0, early_data_skipped_bytes: 0 };

        // Send 32 empty records: all within allowed limit
        for i in 32 {
            let res = wing::check_record_payload_length(filter, 0, false);
            sub.assert_eq(wing::tls_alert_to_u8(res), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "32 empty records tolerated");
        }

        // 33rd empty record triggers DoS defense
        let res_dos = wing::check_record_payload_length(filter, 0, false);
        sub.assert_eq(wing::tls_alert_to_u8(res_dos), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "33rd empty record rejected");

        // Non-empty record resets the counter
        let res_reset = wing::check_record_payload_length(filter, 100, false);
        sub.assert_eq(wing::tls_alert_to_u8(res_reset), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "counter reset");
        sub.assert_eq(filter.empty_records_count, 0, "empty counter is 0");

        // Early data skipped volume limit (16384 bytes)
        let ok_early = wing::check_record_payload_length(filter, 16384, true);
        sub.assert_eq(wing::tls_alert_to_u8(ok_early), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "16384 bytes early data ok");

        // Exceeding 16384 bytes triggers DoS defense
        let fail_early = wing::check_record_payload_length(filter, 1, true);
        sub.assert_eq(wing::tls_alert_to_u8(fail_early), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "exceeding early data limit rejected");
    };

    t.run("TLS-27: Dummy ChangeCipherSpec Strict Validation (RFC 8446 Appendix D.4)") { sub =>
        // 1. Exactly 1 byte of value 0x01 is valid
        let valid_ccs: u8[1] = [0x01];
        let alert_ok = wing::validate_change_cipher_spec_record(valid_ccs[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid CCS record [0x01] accepted");

        // 2. Empty payload is rejected with DecodeError
        let empty_ccs: u8[0] = [];
        let alert_empty = wing::validate_change_cipher_spec_record(empty_ccs[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_empty), wing::tls_alert_to_u8(wing::TlsAlert.DecodeError), "empty CCS record rejected with DecodeError");

        // 3. Multi-byte payload is rejected with DecodeError
        let multi_ccs: u8[2] = [0x01, 0x01];
        let alert_multi = wing::validate_change_cipher_spec_record(multi_ccs[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_multi), wing::tls_alert_to_u8(wing::TlsAlert.DecodeError), "multi-byte CCS record rejected with DecodeError");

        // 4. Invalid byte value (e.g. 0x02) rejected with UnexpectedMessage
        let bad_val_ccs: u8[1] = [0x02];
        let alert_bad_val = wing::validate_change_cipher_spec_record(bad_val_ccs[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_bad_val), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "invalid CCS value 0x02 rejected with UnexpectedMessage");
    };

    t.run("TLS-28: TLS 1.3 Alert Framing & Warning-to-Fatal Promotion (RFC 8446 §6)") { sub =>
        // 1. Valid warning CloseNotify (level 1, desc 0) -> not fatal
        let warn_cn: u8[2] = [1, 0];
        let lvl1, alt1, fatal1, ok1 = wing::parse_tls_alert_message(warn_cn[..]);
        sub.assert_true(ok1, "warning close_notify parses ok");
        sub.assert_eq(lvl1, 1, "level is warning");
        sub.assert_eq(wing::tls_alert_to_u8(alt1), 0, "alert is close_notify");
        sub.assert_false(fatal1, "close_notify is not fatal");

        // 2. Valid warning UserCanceled (level 1, desc 90) -> not fatal
        let warn_uc: u8[2] = [1, 90];
        let lvl2, alt2, fatal2, ok2 = wing::parse_tls_alert_message(warn_uc[..]);
        sub.assert_true(ok2, "warning user_canceled parses ok");
        sub.assert_eq(lvl2, 1, "level is warning");
        sub.assert_eq(wing::tls_alert_to_u8(alt2), 90, "alert is user_canceled");
        sub.assert_false(fatal2, "user_canceled is not fatal");

        // 3. Warning HandshakeFailure (level 1, desc 40) -> promoted to fatal in TLS 1.3
        let warn_hf: u8[2] = [1, 40];
        let lvl3, alt3, fatal3, ok3 = wing::parse_tls_alert_message(warn_hf[..]);
        sub.assert_true(ok3, "warning handshake_failure parses ok");
        sub.assert_eq(lvl3, 1, "level is warning");
        sub.assert_eq(wing::tls_alert_to_u8(alt3), 40, "alert is handshake_failure");
        sub.assert_true(fatal3, "warning handshake_failure promoted to fatal in TLS 1.3");

        // 4. Fatal DecodeError (level 2, desc 50)
        let fatal_de: u8[2] = [2, 50];
        let lvl4, alt4, fatal4, ok4 = wing::parse_tls_alert_message(fatal_de[..]);
        sub.assert_true(ok4, "fatal decode_error parses ok");
        sub.assert_eq(lvl4, 2, "level is fatal");
        sub.assert_eq(wing::tls_alert_to_u8(alt4), 50, "alert is decode_error");
        sub.assert_true(fatal4, "fatal alert is fatal");

        // 5. Invalid length (1 byte or 3 bytes)
        let short_alert: u8[1] = [1];
        let _, _, _, ok_short = wing::parse_tls_alert_message(short_alert[..]);
        sub.assert_false(ok_short, "1-byte alert rejected");

        let long_alert: u8[3] = [1, 0, 0];
        let _, _, _, ok_long = wing::parse_tls_alert_message(long_alert[..]);
        sub.assert_false(ok_long, "3-byte alert rejected");

        // 6. Invalid alert level (3)
        let invalid_lvl: u8[2] = [3, 0];
        let _, _, _, ok_inv = wing::parse_tls_alert_message(invalid_lvl[..]);
        sub.assert_false(ok_inv, "invalid alert level 3 rejected");
    };

    t.run("TLS-31: Constant-Time Record Padding Oracle Defense & All-Zero InnerPlaintext (RFC 8446 §5.4)") { sub =>
        // 1. All-zero decrypted record of 10 bytes -> unexpected_message
        let all_zeros_10: u8[10] = [0; 10];
        let _, _, alert_z10 = wing::unpack_tls_inner_plaintext(all_zeros_10[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_z10), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "all-zero 10-byte record yields unexpected_message");

        // 2. All-zero record of 1 byte -> unexpected_message
        let all_zeros_1: u8[1] = [0];
        let _, _, alert_z1 = wing::unpack_tls_inner_plaintext(all_zeros_1[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_z1), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "all-zero 1-byte record yields unexpected_message");

        // 3. Empty slice -> unexpected_message
        let empty_slice: u8[0] = [];
        let _, _, alert_empty = wing::unpack_tls_inner_plaintext(empty_slice[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_empty), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "empty decrypted record yields unexpected_message");

        // 4. Record with maximum 16384 zero padding bytes + 1 ContentType byte (0x17)
        // Inner plaintext is empty, but inner type is ApplicationData (0x17)
        var max_padded: u8[16385] = [0; 16385];
        max_padded[0] = 0x17; // ContentType at offset 0, followed by 16384 zero padding bytes
        let pt, inner_type, alert_max = wing::unpack_tls_inner_plaintext(max_padded[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_max), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "max-padded record unpacks ok");
        sub.assert_eq(inner_type, 0x17, "inner type is application data (0x17)");
        sub.assert_eq(pt.len, 0, "empty inner plaintext with 16384 padding bytes has length 0");

        // 5. Normal record with 5 bytes payload + ContentType (0x16 Handshake) + 10 zeroes padding
        var padded_msg: u8[16] = [0; 16];
        padded_msg[0] = 0x01; padded_msg[1] = 0x02; padded_msg[2] = 0x03; padded_msg[3] = 0x04; padded_msg[4] = 0x05;
        padded_msg[5] = 0x16; // Handshake type
        // remaining 10 bytes are 0x00 padding
        let pt_msg, type_msg, alert_msg = wing::unpack_tls_inner_plaintext(padded_msg[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert_msg), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "padded handshake record unpacks ok");
        sub.assert_eq(type_msg, 0x16, "inner type is handshake (0x16)");
        sub.assert_eq(pt_msg.len, 5, "plaintext len is 5");
        sub.assert_eq(pt_msg[0], 0x01, "pt[0] matches");
        sub.assert_eq(pt_msg[4], 0x05, "pt[4] matches");
    };

    t.run("TLS-32: AEAD Record Decryption Isolation, Tag Verification & Zero-Leakage (RFC 8446 §5.2)") { sub =>
        // 1. Constant-time tag comparison
        let tag1: u8[16] = [0xAA; 16];
        let tag2: u8[16] = [0xAA; 16];
        var tag_diff = tag1;
        tag_diff[15] ^= 0x01;
        sub.assert_true(wing::ct_compare_tag16(tag1, tag2), "identical tags match");
        sub.assert_false(wing::ct_compare_tag16(tag1, tag_diff), "differing tags reject");

        // 2. Encrypt authentic record payload with AES-128-GCM
        let key: u8[16] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
        let iv: u8[12] = [0x01; 12];
        let seq_num: u64 = 42;
        let nonce, _ = wing::compute_record_nonce(iv, seq_num);

        // Header: ContentType ApplicationData (0x17), TLS 1.2 legacy version (0x0303), length = 8 + 1 (type) + 16 (tag) = 25
        let hdr: u8[5] = [0x17, 0x03, 0x03, 0x00, 25];
        // Plaintext: "TopSecrt" (8 bytes) + ContentType (0x17)
        let inner_pt: u8[9] = [0x54, 0x6F, 0x70, 0x53, 0x65, 0x63, 0x72, 0x74, 0x17];

        var ct: u8[>..] = [];
        let tag = core::aes128_gcm_seal(key, nonce, inner_pt[..], hdr[..], ct);
        var payload: u8[>..] = [];
        payload.append(ct[..]);
        payload.append(tag[..]);

        // Decrypt authentic record
        var out_dec: u8[>..] = [];
        let dec_type, alert_dec = wing::tls_record_decrypt_aes128_gcm(key, iv, seq_num, hdr[..], payload[..], out_dec);
        sub.assert_eq(wing::tls_alert_to_u8(alert_dec), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "authentic record decrypts ok");
        sub.assert_eq(dec_type, 0x17, "decrypted inner type is application data");
        sub.assert_eq(out_dec.len, 8, "decrypted plaintext len is 8");
        sub.assert_eq(out_dec[0], 0x54, "first byte is 'T'");
        sub.assert_eq(out_dec[7], 0x74, "last byte is 't'");

        // 3. Tag mismatch / forgery attack: must return BadRecordMac and ZEROIZE destination
        var bad_payload: u8[>..] = [];
        bad_payload.append(payload[..]);
        bad_payload[bad_payload.len - 1] ^= 0x55; // corrupt tag byte
        var out_forged: u8[>..] = [];
        let _, alert_forged = wing::tls_record_decrypt_aes128_gcm(key, iv, seq_num, hdr[..], bad_payload[..], out_forged);
        sub.assert_eq(wing::tls_alert_to_u8(alert_forged), wing::tls_alert_to_u8(wing::TlsAlert.BadRecordMac), "tag corruption yields bad_record_mac");
        sub.assert_eq(out_forged.len, 0, "destination buffer cleared on authentication failure (zero leakage)");

        // 4. Ciphertext corruption: must return BadRecordMac and zeroize destination
        var ct_corrupt: u8[>..] = [];
        ct_corrupt.append(payload[..]);
        ct_corrupt[0] ^= 0xFF; // corrupt ciphertext byte
        var out_ct_bad: u8[>..] = [];
        let _, alert_ct = wing::tls_record_decrypt_aes128_gcm(key, iv, seq_num, hdr[..], ct_corrupt[..], out_ct_bad);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ct), wing::tls_alert_to_u8(wing::TlsAlert.BadRecordMac), "ciphertext corruption yields bad_record_mac");
        sub.assert_eq(out_ct_bad.len, 0, "destination cleared on ciphertext corruption");

        // 5. Short payload (< 16 bytes tag) returns DecodeError
        let short_pay: u8[10] = [0; 10];
        var out_short: u8[>..] = [];
        let _, alert_short = wing::tls_record_decrypt_aes128_gcm(key, iv, seq_num, hdr[..], short_pay[..], out_short);
        sub.assert_eq(wing::tls_alert_to_u8(alert_short), wing::tls_alert_to_u8(wing::TlsAlert.DecodeError), "short payload (< 16B tag) yields decode_error");

        // 6. Bad header length (!= 5 bytes) returns DecodeError
        let bad_hdr: u8[4] = [0; 4];
        var out_bad_hdr: u8[>..] = [];
        let _, alert_bhdr = wing::tls_record_decrypt_aes128_gcm(key, iv, seq_num, bad_hdr[..], payload[..], out_bad_hdr);
        sub.assert_eq(wing::tls_alert_to_u8(alert_bhdr), wing::tls_alert_to_u8(wing::TlsAlert.DecodeError), "bad header length yields decode_error");
    };
}

// ============================================================================
// 3. QUIC Crypto Gateway & Header Protection (RFC 9001)
// ============================================================================
fn test_quic_crypto_gateway(t: core::T&) {
    t.run("TLS-08: QUIC ChangeCipherSpec Rejection & Level Checking") { sub =>
        var conn = wing::new_quic_crypto_conn();
        conn.read_level = wing::QuicEncryptionLevel.Handshake;

        // Message at correct level without CCS succeeds
        let valid_data: u8[4] = [0x01, 0x02, 0x03, 0x04];
        let alert1 = wing::provide_quic_data(conn, wing::QuicEncryptionLevel.Handshake, valid_data[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert1), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid quic data accepted");

        // Message at incorrect encryption level rejected
        let alert2 = wing::provide_quic_data(conn, wing::QuicEncryptionLevel.Initial, valid_data[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert2), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "wrong level rejected");

        // ChangeCipherSpec (0x14) frame strictly forbidden in QUIC
        let ccs_data: u8[3] = [0x01, 0x14, 0x02];
        let alert3 = wing::provide_quic_data(conn, wing::QuicEncryptionLevel.Handshake, ccs_data[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert3), wing::tls_alert_to_u8(wing::TlsAlert.UnexpectedMessage), "CCS in QUIC strictly rejected");
    };

    t.run("TLS-09: QUIC Header Protection Sample Extraction") { sub =>
        // Packet: 20 bytes total, pn_offset = 2.
        // Sample offset = pn_offset + 4 = 6. Sample length = 16 bytes (offset 6..22).
        var pkt: u8[24] = [0; 24];
        for i in 24 { pkt[i] = i as u8; }

        let sample, ok = wing::quic_extract_hp_sample(pkt[..], 2);
        sub.assert_true(ok, "hp sample extracted");
        sub.assert_eq(sample.len, 16, "sample length is 16");
        sub.assert_eq(sample[0], 6, "sample starts at byte 6");
        sub.assert_eq(sample[15], 21, "sample ends at byte 21");

        // Out-of-bounds packet extraction fails safely
        let _, ok_short = wing::quic_extract_hp_sample(pkt[..], 10);
        sub.assert_false(ok_short, "short packet sample extraction fails safely");
    };

    t.run("TLS-29: QUIC CRYPTO Stream Zero-Allocation Reassembly (RFC 9001 §4)") { sub =>
        var stream = wing::new_quic_crypto_stream();
        sub.assert_eq(stream.consumed_offset, 0, "stream starts at offset 0");
        sub.assert_eq(stream.buf.len, 0, "stream buffer starts empty");

        // 1. In-order frame at offset 0, len 4
        let frame1: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let ok1, n1 = wing::quic_crypto_stream_ingest(stream, 0, frame1[..]);
        sub.assert_true(ok1, "frame 1 ingested");
        sub.assert_eq(n1, 4, "4 bytes ingested");
        sub.assert_eq(stream.consumed_offset, 4, "consumed offset is 4");
        sub.assert_eq(stream.buf.len, 4, "buffer len is 4");

        // 2. Duplicate frame at offset 0, len 4 (entirely duplicate)
        let ok_dup, n_dup = wing::quic_crypto_stream_ingest(stream, 0, frame1[..]);
        sub.assert_true(ok_dup, "duplicate frame handled successfully");
        sub.assert_eq(n_dup, 0, "0 new bytes ingested from duplicate");
        sub.assert_eq(stream.consumed_offset, 4, "consumed offset unchanged at 4");

        // 3. Overlapping frame at offset 2, len 4: [0xCC, 0xDD, 0xEE, 0xFF]
        // 2 bytes overlap, 2 new bytes
        let frame2: u8[4] = [0xCC, 0xDD, 0xEE, 0xFF];
        let ok_ovl, n_ovl = wing::quic_crypto_stream_ingest(stream, 2, frame2[..]);
        sub.assert_true(ok_ovl, "overlapping frame ingested");
        sub.assert_eq(n_ovl, 2, "2 new bytes ingested after prefix trim");
        sub.assert_eq(stream.consumed_offset, 6, "consumed offset advanced to 6");
        sub.assert_eq(stream.buf.len, 6, "buffer len is 6");
        sub.assert_eq(stream.buf[4], 0xEE, "stream byte 4 matches");
        sub.assert_eq(stream.buf[5], 0xFF, "stream byte 5 matches");

        // 4. Out-of-order frame creating a gap at offset 10 (consumed is 6)
        let frame_gap: u8[2] = [0x11, 0x22];
        let ok_gap, n_gap = wing::quic_crypto_stream_ingest(stream, 10, frame_gap[..]);
        sub.assert_false(ok_gap, "frame gap rejected");
        sub.assert_eq(n_gap, 0, "0 bytes ingested on gap");
        sub.assert_eq(stream.consumed_offset, 6, "consumed offset unchanged on gap");

        // 5. Overflow attack: offset close to 2^64 - 1
        let ok_ovf, _ = wing::quic_crypto_stream_ingest(stream, 0xFFFFFFFFFFFFFFFE, frame1[..]);
        sub.assert_false(ok_ovf, "u64 offset overflow rejected");
    };
}

// ============================================================================
// 4. HKDF-Expand-Label & Key Schedule Derivations (RFC 8446 §7.1)
// ============================================================================
fn test_key_schedule_and_derivations(t: core::T&) {
    t.run("TLS-10: HKDF-Expand-Label Formatting & Derivation") { sub =>
        let prk: u8[32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        var out_key: u8[16] = [0; 16];
        let ok = internal::hkdf_expand_label(internal::HASH_SHA256, prk[..], "key", [], 16, out_key[..]);
        sub.assert_true(ok, "hkdf_expand_label succeeds");

        // Verify non-zero derivation
        var all_zero = true;
        for b in out_key {
            if b != 0 { all_zero = false; }
        }
        sub.assert_false(all_zero, "derived key is non-zero");

        // Info capacity test with large context (exceeding original 128-byte buffer limit)
        var large_ctx: u8[200] = [0x5A; 200];
        var out_expanded: u8[32] = [0; 32];
        let ok_large = internal::hkdf_expand_label(internal::HASH_SHA256, prk[..], "large_test", large_ctx[..], 32, out_expanded[..]);
        sub.assert_true(ok_large, "hkdf_expand_label handles large context (> 128 bytes) safely");

        // Secret length bound rejection
        let short_prk: u8[16] = [0x42; 16];
        let ok_short = internal::hkdf_expand_label(internal::HASH_SHA256, short_prk[..], "key", [], 16, out_key[..]);
        sub.assert_false(ok_short, "hkdf_expand_label rejects secret shorter than hash length (32 bytes)");

        // Empty label rejected
        let ok_empty_lbl = internal::hkdf_expand_label(internal::HASH_SHA256, prk[..], "", [], 16, out_key[..]);
        sub.assert_false(ok_empty_lbl, "empty label rejected");
    };

    t.run("TLS-11: Full Key Schedule Lifecycle: Early -> Handshake -> Master -> Resumption") { sub =>
        let ks, ok_init = internal::ks_init(internal::TLS_AES_128_GCM_SHA256);
        sub.assert_true(ok_init, "ks_init succeeds for AES_128_GCM_SHA256");
        sub.assert_eq(ks.hash_id, internal::HASH_SHA256, "hash_id is SHA256");
        sub.assert_eq(ks.hash_len, 32, "hash_len is 32");

        var sched = ks;

        // 1. Early Secret (zero PSK)
        let ok_early = internal::ks_init_early_secret(sched, []);
        sub.assert_true(ok_early, "init early secret ok");
        sub.assert_eq(sched.stage, internal::KS_STAGE_EARLY, "stage is early");

        // All-zero ECDHE shared secret rejection (RFC 7748 §6.1 / RFC 8446 §4.2.8.2)
        let zero_ecdhe: u8[32] = [0x00; 32];
        var sched_fail = sched;
        let ok_zero_hs = internal::ks_advance_to_handshake(sched_fail, zero_ecdhe[..]);
        sub.assert_false(ok_zero_hs, "rejects all-zero (EC)DHE shared secret");

        // Empty ECDHE secret rejected
        let ok_empty_hs = internal::ks_advance_to_handshake(sched_fail, []);
        sub.assert_false(ok_empty_hs, "rejects empty (EC)DHE shared secret");

        // 2. Advance to Handshake with mock ECDHE secret (32 bytes)
        let ecdhe_secret: u8[32] = [0x42; 32];
        let ok_hs = internal::ks_advance_to_handshake(sched, ecdhe_secret[..]);
        sub.assert_true(ok_hs, "advance to handshake ok");
        sub.assert_eq(sched.stage, internal::KS_STAGE_HANDSHAKE, "stage is handshake");

        // Transcript hash length bound validation
        let bad_hash: u8[16] = [0x55; 16];
        let ok_bad_hash = internal::ks_derive_handshake_traffic(sched, bad_hash[..]);
        sub.assert_false(ok_bad_hash, "rejects mismatched handshake transcript hash length");

        // Derives handshake traffic secrets
        let ch_sh_hash: u8[32] = [0x55; 32];
        let ok_hs_traffic = internal::ks_derive_handshake_traffic(sched, ch_sh_hash[..]);
        sub.assert_true(ok_hs_traffic, "derive handshake traffic ok");

        // 3. Advance to Master Secret
        let transcript_hash: u8[32] = [0xAA; 32];
        let ok_master = internal::ks_advance_to_master(sched, transcript_hash[..]);
        sub.assert_true(ok_master, "advance to master ok");
        sub.assert_eq(sched.stage, internal::KS_STAGE_MASTER, "stage is master");

        // 4. Advance to Resumption
        let fin_hash: u8[32] = [0xBB; 32];
        let ok_res = internal::ks_advance_to_resumption(sched, fin_hash[..]);
        sub.assert_true(ok_res, "advance to resumption ok");
        sub.assert_eq(sched.stage, internal::KS_STAGE_RESUMPTION, "stage is resumption");

        // Derive key and IV from application traffic secret
        var app_key: u8[16] = [0; 16];
        var app_iv: u8[12] = [0; 12];
        let ok_kiv = internal::ks_derive_key_iv(
            sched.hash_id,
            sched.client_ap_traffic[..32],
            16,
            app_key[..],
            app_iv,
        );
        sub.assert_true(ok_kiv, "derive key and IV ok");

        // Derive QUIC HP Key
        var hp_key: u8[16] = [0; 16];
        let ok_hp = internal::ks_derive_quic_hp_key(sched.hash_id, sched.client_ap_traffic[..32], 16, hp_key[..]);
        sub.assert_true(ok_hp, "derive quic hp key ok");

        // Finished verify_data computation
        var verify_data: u8[32] = [0; 32];
        let ok_vd = internal::ks_compute_finished_verify_data(
            sched.hash_id,
            sched.hash_len,
            sched.client_hs_traffic[..32],
            transcript_hash[..],
            verify_data[..],
        );
        sub.assert_true(ok_vd, "finished verify data computed");

        // Key Schedule zeroization
        internal::ks_zeroize(sched);
        sub.assert_eq(sched.stage, internal::KS_STAGE_UNINIT, "stage is uninit after zeroize");
        sub.assert_eq(sched.current_secret[0], 0, "current secret wiped");
    };

    t.run("TLS-12: Traffic Secret Update (RFC 8446 Section 7.2)") { sub =>
        var traffic_secret: u8[32] = [0x77; 32];
        let orig_b0 = traffic_secret[0];

        let ok_upd = internal::ks_update_traffic_secret(internal::HASH_SHA256, 32, traffic_secret[..]);
        sub.assert_true(ok_upd, "traffic secret update succeeds");
        sub.assert_false(traffic_secret[0] == orig_b0, "traffic secret successfully mutated");
    };

    t.run("TLS-33: TLS 1.3 Key Schedule Exporter Master Secret Derivation (RFC 8446 §7.5)") { sub =>
        let ks, ok_init = internal::ks_init(internal::TLS_AES_128_GCM_SHA256);
        sub.assert_true(ok_init, "ks_init succeeds");

        var sched = ks;
        internal::ks_init_early_secret(sched, []);
        let ecdhe_secret: u8[32] = [0x42; 32];
        internal::ks_advance_to_handshake(sched, ecdhe_secret[..]);
        let ch_sh_hash: u8[32] = [0x55; 32];
        internal::ks_derive_handshake_traffic(sched, ch_sh_hash[..]);

        // Exporter cannot be called before Master Secret stage
        var out_exp: u8[32] = [0; 32];
        let ok_early_exp = internal::ks_export_keying_material(sched, "test-label", [], 32, out_exp[..]);
        sub.assert_false(ok_early_exp, "calling exporter before master secret fails");

        // Advance to Master stage
        let transcript_hash: u8[32] = [0xAA; 32];
        internal::ks_advance_to_master(sched, transcript_hash[..]);
        sub.assert_eq(sched.stage, internal::KS_STAGE_MASTER, "stage is master");

        // 1. Export with empty context ("") -> uses Hash("")
        var out_exp_empty: u8[32] = [0; 32];
        let ok_empty = internal::ks_export_keying_material(sched, "test-label", [], 32, out_exp_empty[..]);
        sub.assert_true(ok_empty, "exporter with empty context succeeds");

        // 2. Export with non-empty context
        var out_exp_ctx: u8[32] = [0; 32];
        let ok_ctx = internal::ks_export_keying_material(sched, "test-label", "channel-binding-context", 32, out_exp_ctx[..]);
        sub.assert_true(ok_ctx, "exporter with custom context succeeds");

        // Different context MUST produce different exporter key material
        var is_diff = false;
        for i in 32 {
            if out_exp_empty[i] != out_exp_ctx[i] { is_diff = true; break; }
        }
        sub.assert_true(is_diff, "empty context vs custom context produce distinct exporter outputs");

        // 3. Exporter context length bound (> 255 bytes, RFC 8446 §7.5) MUST be rejected
        var long_ctx: u8[256] = [0x77; 256];
        let ok_long_ctx = internal::ks_export_keying_material(sched, "test-label", long_ctx[..], 32, out_exp[..]);
        sub.assert_false(ok_long_ctx, "context > 255 bytes rejected");

        // 4. Empty label MUST be rejected
        let ok_no_lbl = internal::ks_export_keying_material(sched, "", [], 32, out_exp[..]);
        sub.assert_false(ok_no_lbl, "empty exporter label rejected");
    };

    t.run("TLS-34: External PSK Early Secret & Resumption Ticket Nonce Derivation (RFC 8446 §7.1 & §4.6.1)") { sub =>
        let ks, ok_init = internal::ks_init(internal::TLS_AES_128_GCM_SHA256);
        sub.assert_true(ok_init, "ks_init succeeds");

        // 1. External PSK generates "ext binder"
        var sched_ext = ks;
        let ext_psk: u8[32] = [0x88; 32];
        let ok_ext = internal::ks_init_early_secret_with_mode(sched_ext, ext_psk[..], true);
        sub.assert_true(ok_ext, "external PSK early secret initialized");
        sub.assert_eq(sched_ext.stage, internal::KS_STAGE_EARLY, "stage is early");

        // Resumption PSK with same key generates "res binder"
        var sched_res = ks;
        let ok_res = internal::ks_init_early_secret_with_mode(sched_res, ext_psk[..], false);
        sub.assert_true(ok_res, "resumption PSK early secret initialized");

        // External binder key MUST differ from resumption binder key
        var binders_differ = false;
        for i in 32 {
            if sched_ext.binder_key[i] != sched_res.binder_key[i] {
                binders_differ = true;
                break;
            }
        }
        sub.assert_true(binders_differ, "external binder key differs from resumption binder key");

        // 2. Advance to Resumption stage
        let ecdhe_secret: u8[32] = [0x42; 32];
        internal::ks_advance_to_handshake(sched_res, ecdhe_secret[..]);
        let ch_sh_hash: u8[32] = [0x55; 32];
        internal::ks_derive_handshake_traffic(sched_res, ch_sh_hash[..]);
        let transcript_hash: u8[32] = [0xAA; 32];
        internal::ks_advance_to_master(sched_res, transcript_hash[..]);
        let fin_hash: u8[32] = [0xBB; 32];
        internal::ks_advance_to_resumption(sched_res, fin_hash[..]);
        sub.assert_eq(sched_res.stage, internal::KS_STAGE_RESUMPTION, "stage is resumption");

        // 3. Derive resumption PSK from ticket nonce (RFC 8446 §4.6.1)
        let ticket_nonce_1: u8[8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ticket_nonce_2: u8[8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
        var psk_out_1: u8[32] = [0; 32];
        var psk_out_2: u8[32] = [0; 32];

        let ok_psk1 = internal::ks_derive_resumption_psk(sched_res, ticket_nonce_1[..], psk_out_1[..]);
        sub.assert_true(ok_psk1, "resumption psk 1 derived");
        let ok_psk2 = internal::ks_derive_resumption_psk(sched_res, ticket_nonce_2[..], psk_out_2[..]);
        sub.assert_true(ok_psk2, "resumption psk 2 derived");

        // Distinct ticket nonces derive distinct resumption PSKs
        var psks_differ = false;
        for i in 32 {
            if psk_out_1[i] != psk_out_2[i] { psks_differ = true; break; }
        }
        sub.assert_true(psks_differ, "different ticket nonces yield distinct resumption PSKs");

        // Ticket nonce > 255 bytes rejected
        var long_nonce: u8[256] = [0x01; 256];
        var psk_fail: u8[32] = [0; 32];
        let ok_long_nonce = internal::ks_derive_resumption_psk(sched_res, long_nonce[..], psk_fail[..]);
        sub.assert_false(ok_long_nonce, "ticket nonce > 255 bytes rejected");
    };
}

// ============================================================================
// 5. Anti-Replay Strike Register & PSK Binders
// ============================================================================
fn test_anti_replay_and_psk(t: core::T&) {
    t.run("TLS-13: ZeroRttStrikeRegister Anti-Replay Detection & Epoch Rotation") { sub =>
        var reg = internal::strike_register_init(10000, 2000); // 10s epoch, 2s tolerance
        let ticket_a: u8[16] = [0x01; 16];
        let ticket_b: u8[16] = [0x02; 16];

        // 1. Initial arrival of ticket A succeeds
        let ok_a1 = internal::strike_register_check_and_insert(reg, ticket_a[..], 1000);
        sub.assert_true(ok_a1, "ticket A accepted in epoch 0");

        // 2. Immediate replay of ticket A in same epoch fails
        let ok_a_replay = internal::strike_register_check_and_insert(reg, ticket_a[..], 1500);
        sub.assert_false(ok_a_replay, "ticket A replay detected and rejected");

        // 3. Different ticket B in same epoch succeeds
        let ok_b = internal::strike_register_check_and_insert(reg, ticket_b[..], 2000);
        sub.assert_true(ok_b, "ticket B accepted in epoch 0");

        // 4. Advance time to epoch 1 (11000ms): ticket A is in previous window, still rejected!
        let ok_a_ep1 = internal::strike_register_check_and_insert(reg, ticket_a[..], 11000);
        sub.assert_false(ok_a_ep1, "ticket A rejected across epoch boundary into previous window");

        // 5. Advance time by 2 epochs (> 25000ms): old epochs cleared, ticket A is accepted again
        let ok_a_ep3 = internal::strike_register_check_and_insert(reg, ticket_a[..], 25000);
        sub.assert_true(ok_a_ep3, "ticket A accepted after full 2-epoch retirement");

        // 6. Negative timestamp rejected
        sub.assert_false(internal::strike_register_check_and_insert(reg, ticket_a[..], -1), "negative now_ms rejected");

        // 7. Empty ticket identifier rejected
        let empty_ticket: u8[0] = [];
        sub.assert_false(internal::strike_register_check_and_insert(reg, empty_ticket[..], 26000), "empty ticket_id rejected");

        // 8. Backward clock skew / ancient epoch rejected
        var reg_skew = internal::strike_register_init(10000, 2000);
        let ok_fwd = internal::strike_register_check_and_insert(reg_skew, ticket_a[..], 50000);
        sub.assert_true(ok_fwd, "advance to epoch 5");
        let ok_skew = internal::strike_register_check_and_insert(reg_skew, ticket_b[..], 10000);
        sub.assert_false(ok_skew, "ancient epoch rejected as clock skew / out of window");
    };

    t.run("TLS-14: Obfuscated Ticket Age Validation") { sub =>
        let ticket_age_add: u32 = 100000;
        let expected_age_ms: i64 = 5000;
        let tolerance_ms: i64 = 1000;

        // Exact match: obfuscated = ticket_age_add + 5000 = 105000
        let ok1 = internal::validate_ticket_age(105000, ticket_age_add, expected_age_ms, tolerance_ms);
        sub.assert_true(ok1, "exact ticket age valid");

        // Within tolerance: 5500ms (diff = 500ms <= 1000ms)
        let ok2 = internal::validate_ticket_age(105500, ticket_age_add, expected_age_ms, tolerance_ms);
        sub.assert_true(ok2, "ticket age within tolerance valid");

        // Out of tolerance: 7000ms (diff = 2000ms > 1000ms)
        let ok3 = internal::validate_ticket_age(107000, ticket_age_add, expected_age_ms, tolerance_ms);
        sub.assert_false(ok3, "ticket age out of tolerance rejected");

        // Negative expected age rejected
        let ok_neg_age = internal::validate_ticket_age(105000, ticket_age_add, -1, tolerance_ms);
        sub.assert_false(ok_neg_age, "negative expected age rejected");

        // Negative tolerance rejected
        let ok_neg_tol = internal::validate_ticket_age(105000, ticket_age_add, expected_age_ms, -1);
        sub.assert_false(ok_neg_tol, "negative tolerance rejected");

        // Exceeding 7-day maximum ticket lifetime (604800000 ms, RFC 8446 §4.6.1)
        let ok_exp_max = internal::validate_ticket_age(ticket_age_add + 604800001, ticket_age_add, 604800001, tolerance_ms);
        sub.assert_false(ok_exp_max, "age exceeding 7 days rejected");
    };

    t.run("TLS-15: PSK Binder Constant-Time Verification") { sub =>
        let binder_key: u8[32] = [0x33; 32];
        let truncated_ch: u8[16] = [0x55; 16];

        // Derive true expected binder
        var finished_key: u8[32] = [0; 32];
        internal::hkdf_expand_label(internal::HASH_SHA256, binder_key[..], "finished", [], 32, finished_key[..]);
        let ch_hash = core::sha256(truncated_ch[..]);
        let expected_binder = core::hmac_sha256(finished_key[..], ch_hash[..]);

        // Verification of genuine binder succeeds
        let ok_v = internal::verify_psk_binder(internal::HASH_SHA256, 32, binder_key[..], truncated_ch[..], expected_binder[..]);
        sub.assert_true(ok_v, "genuine PSK binder verified");

        // Tampered binder fails
        var tampered_binder = expected_binder;
        tampered_binder[0] ^= 0xFF;
        let ok_bad = internal::verify_psk_binder(internal::HASH_SHA256, 32, binder_key[..], truncated_ch[..], tampered_binder[..]);
        sub.assert_false(ok_bad, "tampered PSK binder rejected");
    };

    t.run("TLS-30: PSK Binder Truncation & Identity Count Validation (RFC 8446 §4.2.11)") { sub =>
        // 1. Truncate ClientHello for binder
        // Mock ClientHello of 60 bytes, binders_len 33 (1 binder: 1 byte len + 32 bytes hmac)
        // binders overhead = 2 (binders vector len) + 33 = 35 bytes
        // Expected truncated length = 60 - 35 = 25 bytes
        var ch_mock: u8[60] = [0x42; 60];
        let trunc_ch, ok_trunc = internal::truncate_client_hello_for_binder(ch_mock[..], 33);
        sub.assert_true(ok_trunc, "ClientHello truncated for binder");
        sub.assert_eq(trunc_ch.len, 25, "truncated length is 25 bytes");

        // 2. Underflow: binders length larger than ClientHello
        let _, ok_underflow = internal::truncate_client_hello_for_binder(ch_mock[..], 60);
        sub.assert_false(ok_underflow, "binders longer than ClientHello rejected");

        // 3. Zero binders length rejected
        let _, ok_zero = internal::truncate_client_hello_for_binder(ch_mock[..], 0);
        sub.assert_false(ok_zero, "zero binders length rejected");

        // 4. Validate PSK identities and binders count (must match and be > 0)
        sub.assert_true(internal::validate_psk_identities_and_binders_count(1, 1), "matching 1 identity and 1 binder valid");
        sub.assert_true(internal::validate_psk_identities_and_binders_count(3, 3), "matching 3 identities and 3 binders valid");
        sub.assert_false(internal::validate_psk_identities_and_binders_count(2, 1), "mismatched identities > binders rejected");
        sub.assert_false(internal::validate_psk_identities_and_binders_count(1, 2), "mismatched identities < binders rejected");
        sub.assert_false(internal::validate_psk_identities_and_binders_count(0, 0), "zero identities/binders rejected");
        sub.assert_false(internal::validate_psk_identities_and_binders_count(-1, -1), "negative counts rejected");
    };
}

// ============================================================================
// 6. Handshake State Machine, HRR & Extension Parsers
// ============================================================================
fn test_handshake_state_machine(t: core::T&) {
    t.run("TLS-16: Client & Server State Machine Transitions") { sub =>
        // Client transitions
        let st1, ok1 = wing::can_client_transition(wing::HsState.ClientWaitSH, wing::HS_MSG_SERVER_HELLO);
        sub.assert_true(ok1, "ClientWaitSH -> ClientWaitEE");
        sub.assert_true(st1 == wing::HsState.ClientWaitEE, "state is ClientWaitEE");

        let st2, ok2 = wing::can_client_transition(wing::HsState.ClientWaitEE, wing::HS_MSG_ENCRYPTED_EXTENSIONS);
        sub.assert_true(ok2, "ClientWaitEE -> ClientWaitCertCr");
        sub.assert_true(st2 == wing::HsState.ClientWaitCertCr, "state is ClientWaitCertCr");

        let st3, ok3 = wing::can_client_transition(wing::HsState.ClientWaitCertCr, wing::HS_MSG_CERTIFICATE);
        sub.assert_true(ok3, "ClientWaitCertCr -> ClientWaitCV");
        sub.assert_true(st3 == wing::HsState.ClientWaitCV, "state is ClientWaitCV");

        let st4, ok4 = wing::can_client_transition(wing::HsState.ClientWaitCV, wing::HS_MSG_CERTIFICATE_VERIFY);
        sub.assert_true(ok4, "ClientWaitCV -> ClientWaitFinished");
        sub.assert_true(st4 == wing::HsState.ClientWaitFinished, "state is ClientWaitFinished");

        let st5, ok5 = wing::can_client_transition(wing::HsState.ClientWaitFinished, wing::HS_MSG_FINISHED);
        sub.assert_true(ok5, "ClientWaitFinished -> Connected");
        sub.assert_true(st5 == wing::HsState.Connected, "state is Connected");

        // Invalid transition: ClientWaitSH receiving Finished
        let _, ok_inv = wing::can_client_transition(wing::HsState.ClientWaitSH, wing::HS_MSG_FINISHED);
        sub.assert_false(ok_inv, "invalid client transition rejected");
    };

    t.run("TLS-17: HelloRetryRequest Detection & Synthetic message_hash") { sub =>
        // HRR Random check
        sub.assert_true(wing::is_hello_retry_request(wing::HRR_RANDOM), "HRR random recognized");
        var bad_random: u8[32] = [0; 32];
        sub.assert_false(wing::is_hello_retry_request(bad_random), "arbitrary random is not HRR");

        // Synthetic message_hash compression (RFC 8446 §4.4.1)
        let ch1_hash: u8[32] = [0x99; 32];
        var out_msg: u8[36] = [0; 36];
        let written, ok_comp = wing::compress_hrr_transcript(32, ch1_hash[..], out_msg[..]);
        sub.assert_true(ok_comp, "synthetic message_hash generated");
        sub.assert_eq(written, 36, "length is 36 bytes");
        sub.assert_eq(out_msg[0], 0xFE, "msg_type is message_hash (254 / 0xFE)");
        sub.assert_eq(out_msg[1], 0x00, "u24 length byte 1 is 0");
        sub.assert_eq(out_msg[2], 0x00, "u24 length byte 2 is 0");
        sub.assert_eq(out_msg[3], 0x20, "u24 length byte 3 is 32");
        sub.assert_eq(out_msg[4], 0x99, "payload contains ch1 hash");
    };

    t.run("TLS-18: SNI Parsing, Lowercase Normalization & IP Rejection") { sub =>
        // Construct valid SNI extension:
        // [list len: 17] || [name_type: 0] || [name len: 14] || "WikiPedia.ORG"
        var b = wing::builder_init();
        wing::start_u16_prefix(b); // list
        wing::put_u8(b, 0);        // host_name type
        wing::start_u16_prefix(b); // name
        wing::put_bytes(b, "WikiPedia.ORG");
        wing::finish_u16_prefix(b);
        wing::finish_u16_prefix(b);

        var sni: u8[..255] = [];
        let ok_sni = wing::parse_sni_extension(b.buf[..], sni);
        sub.assert_true(ok_sni, "valid SNI parsed");
        sub.assert_eq(sni[..], "wikipedia.org", "SNI normalized to lowercase");

        // Rejection of IPv4 literal in SNI (RFC 6066 Section 3)
        var b_ip4 = wing::builder_init();
        wing::start_u16_prefix(b_ip4);
        wing::put_u8(b_ip4, 0);
        wing::start_u16_prefix(b_ip4);
        wing::put_bytes(b_ip4, "192.168.1.1");
        wing::finish_u16_prefix(b_ip4);
        wing::finish_u16_prefix(b_ip4);

        var sni_ip: u8[..255] = [];
        let ok_ip4 = wing::parse_sni_extension(b_ip4.buf[..], sni_ip);
        sub.assert_false(ok_ip4, "IPv4 literal in SNI strictly rejected");

        // Rejection of IPv6 literal in SNI
        var b_ip6 = wing::builder_init();
        wing::start_u16_prefix(b_ip6);
        wing::put_u8(b_ip6, 0);
        wing::start_u16_prefix(b_ip6);
        wing::put_bytes(b_ip6, "2001:db8::1");
        wing::finish_u16_prefix(b_ip6);
        wing::finish_u16_prefix(b_ip6);

        let ok_ip6 = wing::parse_sni_extension(b_ip6.buf[..], sni_ip);
        sub.assert_false(ok_ip6, "IPv6 literal in SNI strictly rejected");
    };

    t.run("TLS-19: ALPN Negotiation (QUIC h3 requirement & TCP prioritization)") { sub =>
        // Construct ALPN list: ["h2", "http/1.1"]
        var b_tcp = wing::builder_init();
        wing::start_u16_prefix(b_tcp);
        wing::start_u8_prefix(b_tcp);
        wing::put_bytes(b_tcp, "h2");
        wing::finish_u8_prefix(b_tcp);
        wing::start_u8_prefix(b_tcp);
        wing::put_bytes(b_tcp, "http/1.1");
        wing::finish_u8_prefix(b_tcp);
        wing::finish_u16_prefix(b_tcp);

        // TCP prefers "h2"
        let neg_tcp = wing::negotiate_alpn(b_tcp.buf[..], false);
        sub.assert_true(neg_tcp == wing::NegotiatedAlpn.H2, "TCP negotiates h2");

        // QUIC strictly rejects list without "h3"
        let neg_quic_fail = wing::negotiate_alpn(b_tcp.buf[..], true);
        sub.assert_true(neg_quic_fail == wing::NegotiatedAlpn.None, "QUIC rejects absence of h3");

        // Construct ALPN list with "h3"
        var b_quic = wing::builder_init();
        wing::start_u16_prefix(b_quic);
        wing::start_u8_prefix(b_quic);
        wing::put_bytes(b_quic, "h3");
        wing::finish_u8_prefix(b_quic);
        wing::finish_u16_prefix(b_quic);

        let neg_quic_ok = wing::negotiate_alpn(b_quic.buf[..], true);
        sub.assert_true(neg_quic_ok == wing::NegotiatedAlpn.H3, "QUIC negotiates h3");
    };
}

// ============================================================================
// 7. ASN.1 DER Parser, RFC 6125 SAN Matcher & CertificateVerify
// ============================================================================
fn test_asn1_x509_and_verify(t: core::T&) {
    t.run("TLS-20: Canonical ASN.1 DER Length & Integer Validation") { sub =>
        // Short form: tag 0x02, len 3, [0x01, 0x02, 0x03]
        let der_int: u8[5] = [0x02, 0x03, 0x01, 0x02, 0x03];
        var c = wing::cursor_from(der_int[..]);
        var out_val = wing::cursor_from(der_int[..0]);
        sub.assert_true(wing::get_asn1_element(c, wing::ASN1_TAG_INTEGER, out_val), "read short form DER integer");
        sub.assert_eq(wing::cursor_len(out_val), 3, "length is 3");
        sub.assert_true(wing::validate_asn1_integer(out_val.buf, true), "valid integer");

        // Canonical DER rule: Reject non-minimal long form (e.g. len 5 encoded as 0x81 0x05)
        let non_minimal: u8[4] = [0x02, 0x81, 0x05, 0x01];
        var c_nm = wing::cursor_from(non_minimal[..]);
        var out_nm = wing::cursor_from(non_minimal[..0]);
        sub.assert_false(wing::get_asn1_element(c_nm, wing::ASN1_TAG_INTEGER, out_nm), "reject non-minimal length < 128 in long form");

        // Canonical DER rule: Reject BER indefinite form (0x80)
        let ber_indef: u8[3] = [0x30, 0x80, 0x00];
        var c_ber = wing::cursor_from(ber_indef[..]);
        var out_ber = wing::cursor_from(ber_indef[..0]);
        sub.assert_false(wing::get_asn1_element(c_ber, wing::ASN1_TAG_SEQUENCE, out_ber), "reject BER indefinite form 0x80");

        // Canonical DER rule: Reject redundant leading zeros in integers (e.g. [0x00, 0x42] where 0x42 high bit is 0)
        let redundant_zero: u8[2] = [0x00, 0x42];
        sub.assert_false(wing::validate_asn1_integer(redundant_zero[..], false), "reject redundant leading zero padding");

        // Legal zero prefix: [0x00, 0x85] where high bit of 0x85 is 1 (needed to keep positive sign)
        let legal_zero: u8[2] = [0x00, 0x85];
        sub.assert_true(wing::validate_asn1_integer(legal_zero[..], true), "accept necessary leading zero for sign");

        // Negative serial number rejected
        let negative_serial: u8[1] = [0x85];
        sub.assert_false(wing::validate_asn1_integer(negative_serial[..], true), "reject negative serial number in X.509");
    };

    t.run("TLS-21: ASN.1 Time Parsing (UTCTime & GeneralizedTime)") { sub =>
        // UTCTime: "261024195200Z" -> Year 2026, Oct 24, 19:52:00
        let utc_str = "261024195200Z";
        let t_utc, ok_utc = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, utc_str);
        sub.assert_true(ok_utc, "parse UTCTime succeeds");
        sub.assert_true(t_utc > 1700000000, "timestamp is modern epoch");

        // GeneralizedTime: "20261024195200Z"
        let gen_str = "20261024195200Z";
        let t_gen, ok_gen = wing::parse_asn1_time(wing::ASN1_TAG_GENERALIZED_TIME, gen_str);
        sub.assert_true(ok_gen, "parse GeneralizedTime succeeds");
        sub.assert_eq(t_utc, t_gen, "UTCTime and GeneralizedTime evaluate to identical timestamp");
    };

    t.run("TLS-22: RFC 6125 SAN Wildcard Matching Rules") { sub =>
        // Exact match
        sub.assert_true(wing::match_dns_san("example.com", "example.com"), "exact match");
        sub.assert_true(wing::match_dns_san("EXAMPLE.COM", "example.com"), "case-insensitive exact match");

        // Leftmost wildcard: *.example.com matches sub.example.com
        sub.assert_true(wing::match_dns_san("*.example.com", "sub.example.com"), "wildcard matches single sub-label");
        sub.assert_true(wing::match_dns_san("*.example.com", "api.example.com"), "wildcard matches api.example.com");

        // Wildcard must NOT match apex domain
        sub.assert_false(wing::match_dns_san("*.example.com", "example.com"), "wildcard does NOT match apex domain");

        // Wildcard must NOT match multi-level subdomains
        sub.assert_false(wing::match_dns_san("*.example.com", "a.b.example.com"), "wildcard does NOT match multi-level domain");

        // Invalid wildcard placements
        sub.assert_false(wing::match_dns_san("foo.*.com", "foo.bar.com"), "middle wildcard rejected");
        sub.assert_false(wing::match_dns_san("*bar.com", "foobar.com"), "partial wildcard rejected");
    };

    t.run("TLS-23: CertificateVerify Context Formatting & Signature Scheme Binding") { sub =>
        // Server CertificateVerify context construction
        let transcript_hash: u8[32] = [0x5A; 32];
        var out_msg: u8[150] = [0; 150];
        let msg_len, ok_bld = wing::build_certificate_verify_message(true, transcript_hash[..], out_msg[..]);
        sub.assert_true(ok_bld, "build server certificate verify message succeeds");
        sub.assert_eq(msg_len, 98 + 32, "server message length is 130 bytes");

        // Check 64 spaces prefix
        for i in 64 {
            sub.assert_eq(out_msg[i], 0x20, "byte is space 0x20");
        }

        // Check "TLS 1.3, server CertificateVerify"
        let expected_ctx = "TLS 1.3, server CertificateVerify";
        sub.assert_eq(out_msg[64..64 + expected_ctx.len], expected_ctx, "context string matches");
        sub.assert_eq(out_msg[64 + expected_ctx.len], 0x00, "separator is 0x00");

        // Check hash trailer
        sub.assert_eq(out_msg[98], 0x5A, "hash byte matches 0x5A");

        // Signature scheme curve binding (RFC 8446 Section 4.4.3)
        // 0x0403 (secp256r1) requires P-256
        sub.assert_true(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256, wing::OID_SECP256R1[..]),
            "secp256r1 scheme binds to P-256 SPKI",
        );
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256, wing::OID_SECP384R1[..]),
            "secp256r1 scheme rejects P-384 SPKI",
        );

        // Ed25519 requires Ed25519 OID
        sub.assert_true(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_ED25519, wing::OID_ED25519[..]),
            "ed25519 binds to ed25519 SPKI",
        );

        // Strict RFC 8446 Invariant: Legacy PKCS#1 v1.5 RSA schemes MUST be rejected in CertificateVerify
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_RSA_PKCS1_SHA256, wing::OID_RSA_ENCRYPTION[..]),
            "legacy PKCS#1 RSA is strictly forbidden in TLS 1.3 CertificateVerify",
        );
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_RSA_PKCS1_SHA384, wing::OID_RSA_ENCRYPTION[..]),
            "legacy PKCS#1 SHA384 is strictly forbidden in TLS 1.3 CertificateVerify",
        );
    };

    t.run("TLS-24: Trust Anchor Matching & RFC 5280 Chain Rules") { sub =>
        var store = wing::TrustAnchorStore { anchors: [] };
        let root_subject: u8[10] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let root_spki: u8[8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        sub.assert_true(wing::add_trust_anchor(store, root_subject[..], root_spki[..]), "add root trust anchor");
        sub.assert_eq(store.anchors.len, 1, "trust anchor count is 1");

        // Construct mock root cert descriptor
        var raw_root: u8[30] = [0; 30];
        for i in 10 { raw_root[i] = root_subject[i]; }
        for i in 8 { raw_root[10 + i] = root_spki[i]; }

        var cert = wing::ParsedCert {
            raw_len: 30,
            tbs_cert: wing::Span16 { offset: 0, length: 30 },
            serial_number: wing::Span16 { offset: 0, length: 1 },
            sig_alg_oid: wing::Span16 { offset: 0, length: 1 },
            issuer_raw: wing::Span16 { offset: 0, length: 10 },
            validity_not_before: 1000,
            validity_not_after: 5000,
            subject_raw: wing::Span16 { offset: 0, length: 10 },
            spki_raw: wing::Span16 { offset: 10, length: 8 },
            spki_alg_oid: wing::Span16 { offset: 10, length: 1 },
            spki_pubkey: wing::Span16 { offset: 10, length: 7 },
            extensions_raw: wing::Span16 { offset: 0, length: 0 },
            is_ca: true,
            has_basic_constraints: true,
            path_len_constraint: -1,
            key_usage: wing::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage: true,
        };

        sub.assert_true(wing::matches_trust_anchor(store, cert, raw_root[..]), "root cert matches trusted anchor");

        // Test chain verification with expired time
        var chain: wing::ParsedCert[..8] = [];
        chain.push(cert);
        var raw_chain: const u8[:][..8] = [];
        raw_chain.push(raw_root[..]);

        let alert_exp = wing::verify_certificate_chain(chain, raw_chain, store, 6000); // 6000 > 5000
        sub.assert_eq(wing::tls_alert_to_u8(alert_exp), wing::tls_alert_to_u8(wing::TlsAlert.CertificateExpired), "expired cert detected");

        // Valid time: 2000
        let alert_ok = wing::verify_certificate_chain(chain, raw_chain, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid certificate chain verified");
    };
}

// ============================================================================
// 8. Hybrid Post-Quantum Key Agreement (RFC 10024 & FIPS 203)
// ============================================================================
fn test_post_quantum_hybrid_exchange(t: core::T&) {
    t.run("TLS-25: Hybrid Key Share Entry Framing & Smuggling Defense") { sub =>
        var client_share = wing::PostQuantumKeyShare {
            group: wing::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { client_share.x25519_public[i] = (i + 1) as u8; }
        for i in 1152 { client_share.mlkem768_public[i] = ((i * 3 + 1) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        client_share.format_hybrid_key_share(wire);
        sub.assert_eq(wire.len, 1188, "Client KeyShareEntry wire length is 1188 bytes");

        var parsed = wing::PostQuantumKeyShare { .. };
        let ok_parse = parsed.parse_hybrid_key_share(wire[..]);
        sub.assert_true(ok_parse, "Client hybrid key share parsed");

        // Smuggling attempt: Appending trailing unparsed bytes to KeyShareEntry must fail
        var smuggled_wire: u8[>..] = [];
        smuggled_wire.append(wire[..]);
        smuggled_wire.push(0xCC); // 1 extra byte
        var bad_client = wing::PostQuantumKeyShare { .. };
        sub.assert_false(bad_client.parse_hybrid_key_share(smuggled_wire[..]), "rejects KeyShareEntry with trailing smuggled bytes");

        // Server Share framing test
        var server_share = wing::PostQuantumServerShare {
            group: wing::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { server_share.x25519_public[i] = (i + 7) as u8; }
        for i in 1088 { server_share.mlkem768_ciphertext[i] = ((i * 5 + 3) & 0xFF) as u8; }

        var server_wire: u8[>..] = [];
        server_share.format_hybrid_server_key_share(server_wire);
        sub.assert_eq(server_wire.len, 1124, "Server KeyShareEntry wire length is 1124 bytes");

        var parsed_server = wing::PostQuantumServerShare { .. };
        sub.assert_true(parsed_server.parse_hybrid_server_key_share(server_wire[..]), "Server share parsed");

        var smuggled_server: u8[>..] = [];
        smuggled_server.append(server_wire[..]);
        smuggled_server.push(0xDD);
        var bad_server = wing::PostQuantumServerShare { .. };
        sub.assert_false(bad_server.parse_hybrid_server_key_share(smuggled_server[..]), "rejects server share with trailing smuggled bytes");
    };

    t.run("TLS-26: Hybrid Shared Secret Combiner & All-Zero Contributory Defense") { sub =>
        let classical_ss: u8[32] = [0x11; 32];
        let pq_ss: u8[32] = [0x22; 32];
        var out_secret: u8[32] = [0; 32];

        // Valid derivation succeeds
        let ok_comb = wing::derive_hybrid_shared_secret_checked(classical_ss[..], pq_ss[..], out_secret[..]);
        sub.assert_true(ok_comb, "valid hybrid shared secret derived");

        // Contributory attack defense: all-zero classical X25519 secret rejected (RFC 7748 §6.1)
        let zero_classical: u8[32] = [0x00; 32];
        let ok_bad_classical = wing::derive_hybrid_shared_secret_checked(zero_classical[..], pq_ss[..], out_secret[..]);
        sub.assert_false(ok_bad_classical, "rejects all-zero classical ECDH shared secret");

        // Degenerate ML-KEM secret: all-zero PQ secret rejected
        let zero_pq: u8[32] = [0x00; 32];
        let ok_bad_pq = wing::derive_hybrid_shared_secret_checked(classical_ss[..], zero_pq[..], out_secret[..]);
        sub.assert_false(ok_bad_pq, "rejects all-zero post-quantum shared secret");

        // Short classical or PQ slice rejected
        let ok_short = wing::derive_hybrid_shared_secret_checked(classical_ss[..16], pq_ss[..], out_secret[..]);
        sub.assert_false(ok_short, "rejects truncated classical shared secret slice");
    };

    t.run("TLS-35: Post-Quantum ML-KEM-768 Decapsulation & FIPS 203 Implicit Rejection") { sub =>
        var sk = wing::MLKEM768PrivateKey { .. };
        // Implicit rejection seed z (32 bytes)
        for i in 32 { sk.z[i] = (i + 0x41) as u8; }
        // Private key (mock 1152 bytes)
        for i in 1152 { sk.private_key[i] = ((i * 13 + 5) & 0xFF) as u8; }
        for i in 1152 { sk.public_key[i] = ((i * 7 + 1) & 0xFF) as u8; }

        // 1. Valid ciphertext decapsulation
        var valid_ct: u8[1088] = [0xAA; 1088];
        var ss_valid: u8[32] = [0; 32];
        let is_rej_valid, ok_valid = wing::mlkem768_decapsulate_with_implicit_rejection(sk, valid_ct[..], ss_valid[..]);
        sub.assert_true(ok_valid, "valid ciphertext decapsulation succeeds");
        sub.assert_false(is_rej_valid, "valid ciphertext does NOT trigger implicit rejection");

        // Verify derived secret is non-zero
        var ss_has_nonzero = false;
        for b in ss_valid {
            if b != 0 { ss_has_nonzero = true; break; }
        }
        sub.assert_true(ss_has_nonzero, "derived shared secret has non-zero entropy");

        // 2. All-zero ciphertext (1088 bytes) MUST trigger deterministic implicit rejection (FIPS 203 §7.2)
        var zero_ct: u8[1088] = [0x00; 1088];
        var ss_zero: u8[32] = [0; 32];
        let is_rej_zero, ok_zero = wing::mlkem768_decapsulate_with_implicit_rejection(sk, zero_ct[..], ss_zero[..]);
        sub.assert_true(ok_zero, "all-zero ciphertext decapsulation succeeds via implicit rejection");
        sub.assert_true(is_rej_zero, "all-zero ciphertext triggers implicit rejection");

        // Verify that the implicit rejection key matches K_bar = HMAC-SHA256(z, c)
        var expected_k_bar: u8[32] = [0; 32];
        let ok_k_bar = wing::mlkem768_compute_implicit_rejection(sk.z, zero_ct[..], expected_k_bar[..]);
        sub.assert_true(ok_k_bar, "expected k_bar computed");
        sub.assert_bytes_eq(ss_zero[..], expected_k_bar[..], "implicit rejection key matches FIPS 203 derivation from seed z");

        // Determinism: decapsulating with same corrupt ciphertext produces identical shared key
        var ss_zero_again: u8[32] = [0; 32];
        wing::mlkem768_decapsulate_with_implicit_rejection(sk, zero_ct[..], ss_zero_again[..]);
        sub.assert_bytes_eq(ss_zero[..], ss_zero_again[..], "implicit rejection is deterministic");

        // 3. Different rejection seed z produces different implicit rejection key
        var sk2 = sk;
        sk2.z[0] ^= 0xFF;
        var ss_diff_z: u8[32] = [0; 32];
        wing::mlkem768_decapsulate_with_implicit_rejection(sk2, zero_ct[..], ss_diff_z[..]);
        var diff_z_matches = true;
        for i in 32 {
            if ss_diff_z[i] != ss_zero[i] { diff_z_matches = false; break; }
        }
        sub.assert_false(diff_z_matches, "different seed z produces distinct implicit rejection key");

        // 4. Truncated ciphertext (< 1088 bytes) rejected safely without panic or hang
        let short_ct: u8[500] = [0xAA; 500];
        var ss_short: u8[32] = [0; 32];
        let _, ok_short = wing::mlkem768_decapsulate_with_implicit_rejection(sk, short_ct[..], ss_short[..]);
        sub.assert_false(ok_short, "truncated ciphertext fails safely");

        // 5. Short destination buffer (< 32 bytes) rejected safely
        var ss_tiny: u8[16] = [0; 16];
        let _, ok_tiny = wing::mlkem768_decapsulate_with_implicit_rejection(sk, valid_ct[..], ss_tiny[..]);
        sub.assert_false(ok_tiny, "short output buffer fails safely");
    };
}

// ============================================================================
// Main TLS 1.3 & X.509 Conformance Runner
// ============================================================================
fn main() {
    var runner = core::new_runner("TLS 1.3 & X.509 PKI Zero-Allocation Conformance Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. ByteCursor, ByteBuilder, and Serialization Conformance", test_byte_cursor_and_builder);
    core::run_case(runner, "2. TLS Record Layer Framing, Nonce & DoS Defenses", test_record_layer_and_dos);
    core::run_case(runner, "3. QUIC Crypto Gateway & Header Protection (RFC 9001)", test_quic_crypto_gateway);
    core::run_case(runner, "4. HKDF-Expand-Label & Key Schedule Derivations (RFC 8446)", test_key_schedule_and_derivations);
    core::run_case(runner, "5. Anti-Replay Strike Register & PSK Binders", test_anti_replay_and_psk);
    core::run_case(runner, "6. Handshake State Machine, HRR & Extension Parsers", test_handshake_state_machine);
    core::run_case(runner, "7. ASN.1 DER Parser, RFC 6125 SAN Matcher & CertificateVerify", test_asn1_x509_and_verify);
    core::run_case(runner, "8. Hybrid Post-Quantum Key Agreement (RFC 10024 & FIPS 203)", test_post_quantum_hybrid_exchange);

    let ok = core::finish(runner);
    assert(ok);
}
