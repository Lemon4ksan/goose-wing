// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/tls_test.goose
// Deterministic test suite for TLS 1.3 and X.509 PKI in Goose.
// Validates RFC 8446, RFC 9001 (QUIC Crypto), RFC 5280, RFC 6125, and zero-allocation invariants.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// 1. ByteCursor, ByteBuilder, and Serialization Conformance
fn test_byte_cursor_and_builder(t: lit::T&) {
    t.run("TLS-01: Zero-Copy ByteCursor Reading & Primitive Extraction") { sub =>
        let raw: u8[10] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAA, 0xBB];
        var c = core::cursor_from(raw[..]);

        sub.assert_eq(core::cursor_len(c), 10, "cursor starts at length 10");

        var u8_val: u8 = 0;
        sub.assert_true(core::get_u8(c, u8_val), "get_u8 succeeds");
        sub.assert_eq(u8_val, 0x12, "u8 matches 0x12");
        sub.assert_eq(core::cursor_len(c), 9, "len after u8 is 9");

        var u16_val: u16 = 0;
        sub.assert_true(core::get_u16(c, u16_val), "get_u16 succeeds");
        sub.assert_eq(u16_val, 0x3456, "u16 matches 0x3456");

        var u24_val: u32 = 0;
        sub.assert_true(core::get_u24(c, u24_val), "get_u24 succeeds");
        sub.assert_eq(u24_val, 0x789ABC, "u24 matches 0x789ABC");

        var u32_val: u32 = 0;
        sub.assert_true(core::get_u32(c, u32_val), "get_u32 succeeds");
        sub.assert_eq(u32_val, 0xDEF0AABB, "u32 matches 0xDEF0AABB");

        sub.assert_eq(core::cursor_len(c), 0, "cursor is empty");
        var underflow: u8 = 0;
        sub.assert_false(core::get_u8(c, underflow), "underflow fails safely");
    };

    t.run("TLS-02: Length-Prefixed Zero-Copy Slicing") { sub =>
        // [len: 3, 0x01, 0x02, 0x03] || [len: 0x0002, 0xAA, 0xBB]
        let data: u8[8] = [0x03, 0x01, 0x02, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        var c = core::cursor_from(data[..]);

        var p8 = core::cursor_from(data[..0]);
        sub.assert_true(core::get_u8_length_prefixed(c, p8), "read u8 prefixed slice");
        sub.assert_eq(core::cursor_len(p8), 3, "p8 length is 3");
        sub.assert_eq(p8.buf[0], 0x01, "p8[0] == 1");
        sub.assert_eq(p8.buf[2], 0x03, "p8[2] == 3");

        var p16 = core::cursor_from(data[..0]);
        sub.assert_true(core::get_u16_length_prefixed(c, p16), "read u16 prefixed slice");
        sub.assert_eq(core::cursor_len(p16), 2, "p16 length is 2");
        sub.assert_eq(p16.buf[0], 0xAA, "p16[0] == 0xAA");
        sub.assert_eq(p16.buf[1], 0xBB, "p16[1] == 0xBB");
    };

    t.run("TLS-03: ByteBuilder Nested Prefixes & Backpatching") { sub =>
        var b = core::builder_init();
        core::put_u8(b, 0xAA);

        // Nested u16 length-prefixed block
        sub.assert_true(core::start_u16_prefix(b), "start u16 prefix");
        core::put_u8(b, 0xBB);
        core::put_u8(b, 0xCC);

        // Nested u8 length-prefixed block inside u16 block
        sub.assert_true(core::start_u8_prefix(b), "start u8 prefix");
        core::put_u8(b, 0xDD);
        sub.assert_true(core::finish_u8_prefix(b), "finish u8 prefix");

        sub.assert_true(core::finish_u16_prefix(b), "finish u16 prefix");

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

// 2. TLS Record Layer Framing, Nonce & DoS Defenses
fn test_record_layer_and_dos(t: lit::T&) {
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
        var enc_out: u8[..64] = [];
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
        let key:     u8[16] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
        let iv:      u8[12] = [0x01; 12];
        let seq_num: u64    = 42;
        let nonce, _ = wing::compute_record_nonce(iv, seq_num);

        // Header: ContentType ApplicationData (0x17), TLS 1.2 legacy version (0x0303), length = 8 + 1 (type) + 16 (tag) = 25
        let hdr: u8[5] = [0x17, 0x03, 0x03, 0x00, 25];
        // Plaintext: "TopSecrt" (8 bytes) + ContentType (0x17)
        let inner_pt: u8[9] = [0x54, 0x6F, 0x70, 0x53, 0x65, 0x63, 0x72, 0x74, 0x17];

        var ct: u8[>..] = [];
        for i in inner_pt.len { ct.push(0); }
        let tag, _, _ = core::aes128_gcm_seal(key, nonce, inner_pt[..], hdr[..], ct[..]);
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

// 3. QUIC Crypto Gateway & Header Protection (RFC 9001)
fn test_quic_crypto_gateway(t: lit::T&) {
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

        // Handshake Finished (0x14) and payload containing 0x14 byte are valid in QUIC CRYPTO frames
        let finished_data: u8[3] = [0x14, 0x00, 0x04];
        let alert3 = wing::provide_quic_data(conn, wing::QuicEncryptionLevel.Handshake, finished_data[..]);
        sub.assert_eq(wing::tls_alert_to_u8(alert3), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "Finished (0x14) in QUIC accepted");
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

// 4. HKDF-Expand-Label & Key Schedule Derivations (RFC 8446 §7.1)
fn test_key_schedule_and_derivations(t: lit::T&) {
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
        var large_ctx:    u8[200] = [0x5A; 200];
        var out_expanded: u8[32]  = [0; 32];
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
        let ks, ok_init = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
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
        var app_iv:  u8[12] = [0; 12];
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
        let ks, ok_init = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
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
        let ks, ok_init = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
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
        var psk_fail:   u8[32]  = [0; 32];
        let ok_long_nonce = internal::ks_derive_resumption_psk(sched_res, long_nonce[..], psk_fail[..]);
        sub.assert_false(ok_long_nonce, "ticket nonce > 255 bytes rejected");
    };
}

// 5. Anti-Replay Strike Register & PSK Binders
fn test_anti_replay_and_psk(t: lit::T&) {
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
        let ticket_age_add:  u32 = 100000;
        let expected_age_ms: i64 = 5000;
        let tolerance_ms:    i64 = 1000;

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

        // Wrapping u32 subtraction when ticket_age_add causes uint32 overflow (RFC 8446 §4.2.11.1)
        let large_add: u32 = 0xFFFFFFFF;
        // If age = 5000ms, obfuscated = (0xFFFFFFFF + 5000) mod 2^32 = 4999
        let ok_wrap = internal::validate_ticket_age(4999, large_add, 5000, 1000);
        sub.assert_true(ok_wrap, "wrapping u32 ticket age calculation succeeds");
    };

    t.run("TLS-15: PSK Binder Constant-Time Verification") { sub =>
        let binder_key:   u8[32] = [0x33; 32];
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

// 6. Handshake State Machine, HRR & Extension Parsers
fn test_handshake_state_machine(t: lit::T&) {
    t.run("TLS-16: Client & Server State Machine Transitions") { sub =>
        // Client transitions
        let st1, ok1 = wing::can_client_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_SERVER_HELLO);
        sub.assert_true(ok1, "ClientWaitSH -> ClientWaitEE");
        sub.assert_true(st1 == wing::HsState.ClientWaitEE, "state is ClientWaitEE");

        let st2, ok2 = wing::can_client_transition(wing::HsState.ClientWaitEE, rfc::TLS_HS_ENCRYPTED_EXTENSIONS);
        sub.assert_true(ok2, "ClientWaitEE -> ClientWaitCertCr");
        sub.assert_true(st2 == wing::HsState.ClientWaitCertCr, "state is ClientWaitCertCr");

        let st3, ok3 = wing::can_client_transition(wing::HsState.ClientWaitCertCr, rfc::TLS_HS_CERTIFICATE);
        sub.assert_true(ok3, "ClientWaitCertCr -> ClientWaitCV");
        sub.assert_true(st3 == wing::HsState.ClientWaitCV, "state is ClientWaitCV");

        let st4, ok4 = wing::can_client_transition(wing::HsState.ClientWaitCV, rfc::TLS_HS_CERTIFICATE_VERIFY);
        sub.assert_true(ok4, "ClientWaitCV -> ClientWaitFinished");
        sub.assert_true(st4 == wing::HsState.ClientWaitFinished, "state is ClientWaitFinished");

        let st5, ok5 = wing::can_client_transition(wing::HsState.ClientWaitFinished, rfc::TLS_HS_FINISHED);
        sub.assert_true(ok5, "ClientWaitFinished -> Connected");
        sub.assert_true(st5 == wing::HsState.Connected, "state is Connected");

        // Invalid transition: ClientWaitSH receiving Finished
        let _, ok_inv = wing::can_client_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_FINISHED);
        sub.assert_false(ok_inv, "invalid client transition rejected");
    };

    t.run("TLS-17: HelloRetryRequest Detection & Synthetic message_hash") { sub =>
        // HRR Random check
        sub.assert_true(wing::is_hello_retry_request(rfc::HRR_RANDOM), "HRR random recognized");
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
        var b = core::builder_init();
        core::start_u16_prefix(b); // list
        core::put_u8(b, 0);        // host_name type
        core::start_u16_prefix(b); // name
        core::put_bytes(b, "WikiPedia.ORG");
        core::finish_u16_prefix(b);
        core::finish_u16_prefix(b);

        var sni: u8[..255] = [];
        let ok_sni = wing::parse_sni_extension(b.buf[..], sni);
        sub.assert_true(ok_sni, "valid SNI parsed");
        sub.assert_eq(sni[..], "wikipedia.org", "SNI normalized to lowercase");

        // Rejection of IPv4 literal in SNI (RFC 6066 Section 3)
        var b_ip4 = core::builder_init();
        core::start_u16_prefix(b_ip4);
        core::put_u8(b_ip4, 0);
        core::start_u16_prefix(b_ip4);
        core::put_bytes(b_ip4, "192.168.1.1");
        core::finish_u16_prefix(b_ip4);
        core::finish_u16_prefix(b_ip4);

        var sni_ip: u8[..255] = [];
        let ok_ip4 = wing::parse_sni_extension(b_ip4.buf[..], sni_ip);
        sub.assert_false(ok_ip4, "IPv4 literal in SNI strictly rejected");

        // Rejection of IPv6 literal in SNI
        var b_ip6 = core::builder_init();
        core::start_u16_prefix(b_ip6);
        core::put_u8(b_ip6, 0);
        core::start_u16_prefix(b_ip6);
        core::put_bytes(b_ip6, "2001:db8::1");
        core::finish_u16_prefix(b_ip6);
        core::finish_u16_prefix(b_ip6);

        let ok_ip6 = wing::parse_sni_extension(b_ip6.buf[..], sni_ip);
        sub.assert_false(ok_ip6, "IPv6 literal in SNI strictly rejected");
    };

    t.run("TLS-19: ALPN Negotiation (QUIC h3 requirement & TCP prioritization)") { sub =>
        // Construct ALPN list: ["h2", "http/1.1"]
        var b_tcp = core::builder_init();
        core::start_u16_prefix(b_tcp);
        core::start_u8_prefix(b_tcp);
        core::put_bytes(b_tcp, "h2");
        core::finish_u8_prefix(b_tcp);
        core::start_u8_prefix(b_tcp);
        core::put_bytes(b_tcp, "http/1.1");
        core::finish_u8_prefix(b_tcp);
        core::finish_u16_prefix(b_tcp);

        // TCP prefers "h2"
        let neg_tcp = wing::negotiate_alpn(b_tcp.buf[..], false);
        sub.assert_true(neg_tcp == wing::NegotiatedAlpn.H2, "TCP negotiates h2");

        // QUIC strictly rejects list without "h3"
        let neg_quic_fail = wing::negotiate_alpn(b_tcp.buf[..], true);
        sub.assert_true(neg_quic_fail == wing::NegotiatedAlpn.None, "QUIC rejects absence of h3");

        // Construct ALPN list with "h3"
        var b_quic = core::builder_init();
        core::start_u16_prefix(b_quic);
        core::start_u8_prefix(b_quic);
        core::put_bytes(b_quic, "h3");
        core::finish_u8_prefix(b_quic);
        core::finish_u16_prefix(b_quic);

        let neg_quic_ok = wing::negotiate_alpn(b_quic.buf[..], true);
        sub.assert_true(neg_quic_ok == wing::NegotiatedAlpn.H3, "QUIC negotiates h3");
    };
}

// 7. ASN.1 DER Parser, RFC 6125 SAN Matcher & CertificateVerify
fn test_asn1_x509_and_verify(t: lit::T&) {
    t.run("TLS-20: Canonical ASN.1 DER Length & Integer Validation") { sub =>
        // Short form: tag 0x02, len 3, [0x01, 0x02, 0x03]
        let der_int: u8[5] = [0x02, 0x03, 0x01, 0x02, 0x03];
        var c = core::cursor_from(der_int[..]);
        var out_val = core::cursor_from(der_int[..0]);
        sub.assert_true(wing::get_asn1_element(c, rfc::ASN1_TAG_INTEGER, out_val), "read short form DER integer");
        sub.assert_eq(core::cursor_len(out_val), 3, "length is 3");
        sub.assert_true(wing::validate_asn1_integer(out_val.buf, true), "valid integer");

        // Canonical DER rule: Reject non-minimal long form (e.g. len 5 encoded as 0x81 0x05)
        let non_minimal: u8[4] = [0x02, 0x81, 0x05, 0x01];
        var c_nm = core::cursor_from(non_minimal[..]);
        var out_nm = core::cursor_from(non_minimal[..0]);
        sub.assert_false(wing::get_asn1_element(c_nm, rfc::ASN1_TAG_INTEGER, out_nm), "reject non-minimal length < 128 in long form");

        // Canonical DER rule: Reject BER indefinite form (0x80)
        let ber_indef: u8[3] = [0x30, 0x80, 0x00];
        var c_ber = core::cursor_from(ber_indef[..]);
        var out_ber = core::cursor_from(ber_indef[..0]);
        sub.assert_false(wing::get_asn1_element(c_ber, rfc::ASN1_TAG_SEQUENCE, out_ber), "reject BER indefinite form 0x80");

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
        let t_utc, ok_utc = wing::parse_asn1_time(rfc::ASN1_TAG_UTC_TIME, utc_str);
        sub.assert_true(ok_utc, "parse UTCTime succeeds");
        sub.assert_true(t_utc > 1700000000, "timestamp is modern epoch");

        // GeneralizedTime: "20261024195200Z"
        let gen_str = "20261024195200Z";
        let t_gen, ok_gen = wing::parse_asn1_time(rfc::ASN1_TAG_GENERALIZED_TIME, gen_str);
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

        // RFC 6125 §6.4.3: Trailing dot normalization (both presented and reference identifiers)
        sub.assert_true(wing::match_dns_san("example.com", "example.com."), "exact match with trailing dot in host");
        sub.assert_true(wing::match_dns_san("example.com.", "example.com"), "exact match with trailing dot in SAN pattern");
        sub.assert_true(wing::match_dns_san("example.com.", "example.com."), "exact match with trailing dots in both");
        sub.assert_true(wing::match_dns_san("*.example.com", "sub.example.com."), "wildcard match with trailing dot in host");
        sub.assert_true(wing::match_dns_san("*.example.com.", "sub.example.com"), "wildcard match with trailing dot in SAN pattern");
        sub.assert_true(wing::match_dns_san("*.example.com.", "sub.example.com."), "wildcard match with trailing dots in both");

        // CVE-2009-3555 / CVE-2021-3712: Embedded NUL-byte injection rejection
        sub.assert_false(wing::match_dns_san("example.com\0.evil.com", "example.com"), "reject embedded NUL in SAN pattern");
        sub.assert_false(wing::match_dns_san("example.com", "example.com\0.evil.com"), "reject embedded NUL in host");
        sub.assert_false(wing::match_uri_san("http://example.com\0.evil.com", "example.com"), "reject embedded NUL in URI SAN host");
        sub.assert_false(wing::match_uri_san("example.com", "example.com\0.evil.com"), "reject embedded NUL in URI request host");
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
            wing::verify_signature_scheme_curve_binding(rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256, rfc::OID_SECP256R1[..]),
            "secp256r1 scheme binds to P-256 SPKI",
        );
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256, rfc::OID_SECP384R1[..]),
            "secp256r1 scheme rejects P-384 SPKI",
        );

        // Ed25519 requires Ed25519 OID
        sub.assert_true(
            wing::verify_signature_scheme_curve_binding(rfc::SIG_SCHEME_ED25519, rfc::OID_ED25519[..]),
            "ed25519 binds to ed25519 SPKI",
        );

        // Strict RFC 8446 Invariant: Legacy PKCS#1 v1.5 RSA schemes MUST be rejected in CertificateVerify
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(rfc::SIG_SCHEME_RSA_PKCS1_SHA256, rfc::OID_RSA_ENCRYPTION[..]),
            "legacy PKCS#1 RSA is strictly forbidden in TLS 1.3 CertificateVerify",
        );
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(rfc::SIG_SCHEME_RSA_PKCS1_SHA384, rfc::OID_RSA_ENCRYPTION[..]),
            "legacy PKCS#1 SHA384 is strictly forbidden in TLS 1.3 CertificateVerify",
        );
    };

    t.run("TLS-24: Trust Anchor Matching & RFC 5280 Chain Rules") { sub =>
        var store = wing::TrustAnchorStore { anchors: [] };
        let root_subject: u8[10] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let root_spki:    u8[8]  = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        sub.assert_true(wing::add_trust_anchor(store, root_subject[..], root_spki[..]), "add root trust anchor");
        sub.assert_eq(store.anchors.len, 1, "trust anchor count is 1");

        // Construct mock root cert descriptor
        var raw_root: u8[30] = [0; 30];
        for i in 10 { raw_root[i] = root_subject[i]; }
        for i in 8 { raw_root[10 + i] = root_spki[i]; }

        var cert = wing::ParsedCert {
            raw_len:               30,
            tbs_cert:              wing::Span16 { offset: 0, length: 30 },
            serial_number:         wing::Span16 { offset: 0, length: 1 },
            sig_alg_oid:           wing::Span16 { offset: 0, length: 1 },
            issuer_raw:            wing::Span16 { offset: 0, length: 10 },
            validity_not_before:   1000,
            validity_not_after:    5000,
            subject_raw:           wing::Span16 { offset: 0, length: 10 },
            spki_raw:              wing::Span16 { offset: 10, length: 8 },
            spki_alg_oid:          wing::Span16 { offset: 10, length: 1 },
            spki_pubkey:           wing::Span16 { offset: 10, length: 7 },
            extensions_raw:        wing::Span16 { offset: 0, length: 0 },
            is_ca:                 true,
            has_basic_constraints: true,
            path_len_constraint:   -1,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
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

    t.run("TLS-25: CS-01 ASN.1 DER Length 4-Byte Bounds, Signed Overflow & Reserved Octet Defense") { sub =>
        // 1. 4-byte overflow (bit 31 set: 0x80000000 = 2147483648)
        let of_4byte: u8[5] = [0x84, 0x80, 0x00, 0x00, 0x00];
        var c_of = core::cursor_from(of_4byte[..]);
        var len_of: i64 = 0;
        sub.assert_false(wing::get_asn1_length(c_of, len_of), "reject 4-byte length with signed bit set (overflow)");

        // 2. Initial octet 0xFF strictly forbidden per X.690 Section 8.1.3.5(c)
        let ff_len: u8[3] = [0xFF, 0x01, 0x01];
        var c_ff = core::cursor_from(ff_len[..]);
        var len_ff: i64 = 0;
        sub.assert_false(wing::get_asn1_length(c_ff, len_ff), "reject initial octet 0xFF");

        // 3. Length > 4 bytes (e.g. 5 bytes) forbidden
        let five_byte_len: u8[6] = [0x85, 0x01, 0x00, 0x00, 0x00, 0x00];
        var c_5 = core::cursor_from(five_byte_len[..]);
        var len_5: i64 = 0;
        sub.assert_false(wing::get_asn1_length(c_5, len_5), "reject 5-byte length");

        // 4. make_span target longer than base must safely return zero span without underflow
        let empty_span = wing::make_span("abc", "abcdef");
        sub.assert_eq(empty_span.offset, 0, "make_span target > base offset 0");
        sub.assert_eq(empty_span.length, 0, "make_span target > base len 0");
    };

    t.run("TLS-26: CS-02 ASN.1 DER Integer Parsing & Positive Serial Invariants") { sub =>
        // 1. Valid integers decoded by get_asn1_integer
        // 0 -> [0x02, 0x01, 0x00]
        let zero_int: u8[3] = [0x02, 0x01, 0x00];
        var c0 = core::cursor_from(zero_int[..]);
        var v0: i64 = -999;
        sub.assert_true(wing::get_asn1_integer(c0, v0), "decode integer 0");
        sub.assert_eq(v0, 0, "v0 == 0");

        // 127 -> [0x02, 0x01, 0x7F]
        let int_127: u8[3] = [0x02, 0x01, 0x7F];
        var c127 = core::cursor_from(int_127[..]);
        var v127: i64 = 0;
        sub.assert_true(wing::get_asn1_integer(c127, v127), "decode integer 127");
        sub.assert_eq(v127, 127, "v127 == 127");

        // 128 -> [0x02, 0x02, 0x00, 0x80] (requires 0x00 prefix to stay positive)
        let int_128: u8[4] = [0x02, 0x02, 0x00, 0x80];
        var c128 = core::cursor_from(int_128[..]);
        var v128: i64 = 0;
        sub.assert_true(wing::get_asn1_integer(c128, v128), "decode integer 128");
        sub.assert_eq(v128, 128, "v128 == 128");

        // Negative integer -1 -> [0x02, 0x01, 0xFF]
        let neg_one: u8[3] = [0x02, 0x01, 0xFF];
        var cn1 = core::cursor_from(neg_one[..]);
        var vn1: i64 = 0;
        sub.assert_true(wing::get_asn1_integer(cn1, vn1), "decode integer -1");
        sub.assert_eq(vn1, -1, "vn1 == -1");

        // Negative integer -128 -> [0x02, 0x01, 0x80]
        let neg_128: u8[3] = [0x02, 0x01, 0x80];
        var cn128 = core::cursor_from(neg_128[..]);
        var vn128: i64 = 0;
        sub.assert_true(wing::get_asn1_integer(cn128, vn128), "decode integer -128");
        sub.assert_eq(vn128, -128, "vn128 == -128");

        // 2. Reject zero-length integer [0x02, 0x00]
        let zero_len: u8[2] = [0x02, 0x00];
        var cz = core::cursor_from(zero_len[..]);
        var vz: i64 = 0;
        sub.assert_false(wing::get_asn1_integer(cz, vz), "reject zero-length integer");

        // 3. Reject redundant leading zeros [0x02, 0x02, 0x00, 0x7F]
        let red_zero: u8[4] = [0x02, 0x02, 0x00, 0x7F];
        var crz = core::cursor_from(red_zero[..]);
        var vrz: i64 = 0;
        sub.assert_false(wing::get_asn1_integer(crz, vrz), "reject redundant leading zero");

        // 4. Reject redundant negative sign extension [0x02, 0x02, 0xFF, 0x80]
        let red_sign: u8[4] = [0x02, 0x02, 0xFF, 0x80];
        var crs = core::cursor_from(red_sign[..]);
        var vrs: i64 = 0;
        sub.assert_false(wing::get_asn1_integer(crs, vrs), "reject redundant negative sign");

        // 5. RFC 5280 §4.1.2.2: Serial number zero [0x00] is strictly forbidden (must be positive)
        let zero_serial: u8[1] = [0x00];
        sub.assert_false(wing::validate_asn1_integer(zero_serial[..], true), "reject serial number zero in X.509");
        sub.assert_true(wing::validate_asn1_integer(zero_serial[..], false), "allow integer zero in general ASN.1");
    };

    t.run("TLS-27: CS-03 ASN.1 BIT STRING Unused Bits & Trailing Padding Validation") { sub =>
        // 1. Valid empty BIT STRING: 1 byte [0x00] (0 unused bits, 0 data)
        let empty_bs: u8[1] = [0x00];
        sub.assert_true(wing::validate_asn1_bit_string(empty_bs[..]), "empty bit string with 0 unused bits valid");

        // 2. Invalid empty BIT STRING with non-zero unused bits: [0x01]
        let bad_empty_bs: u8[1] = [0x01];
        sub.assert_false(wing::validate_asn1_bit_string(bad_empty_bs[..]), "empty bit string with unused bits > 0 rejected");

        // 3. Unused bits > 7 is strictly forbidden
        let bad_unused: u8[2] = [0x08, 0xAA];
        sub.assert_false(wing::validate_asn1_bit_string(bad_unused[..]), "unused bits == 8 rejected");
        let bad_unused_ff: u8[2] = [0xFF, 0xAA];
        sub.assert_false(wing::validate_asn1_bit_string(bad_unused_ff[..]), "unused bits == 0xFF rejected");

        // 4. Zero length (missing unused bits octet) rejected
        let empty_slice: u8[0] = [];
        sub.assert_false(wing::validate_asn1_bit_string(empty_slice[..]), "zero length bit string rejected");

        // 5. Canonical DER: trailing unused bits must be zero
        // 3 unused bits, byte is 0b10100000 (0xA0) -> lower 3 bits are 0 -> valid
        let valid_padding: u8[2] = [0x03, 0xA0];
        sub.assert_true(wing::validate_asn1_bit_string(valid_padding[..]), "trailing unused bits all zero is valid");

        // 3 unused bits, byte is 0b10100101 (0xA5) -> lower 3 bits are non-zero (5) -> rejected
        let non_zero_padding: u8[2] = [0x03, 0xA5];
        sub.assert_false(wing::validate_asn1_bit_string(non_zero_padding[..]), "non-zero trailing unused bits strictly rejected");

        // 6. get_asn1_bit_string element parser
        let full_der_bs: u8[4] = [0x03, 0x02, 0x00, 0x55];
        var c_bs = core::cursor_from(full_der_bs[..]);
        var out_bits = core::cursor_from(full_der_bs[..0]);
        var out_unused: u8 = 0xFF;
        sub.assert_true(wing::get_asn1_bit_string(c_bs, out_bits, out_unused), "parse DER bit string");
        sub.assert_eq(out_unused, 0, "unused bits is 0");
        sub.assert_eq(out_bits.buf.len, 1, "bit payload len is 1");
        sub.assert_eq(out_bits.buf[0], 0x55, "bit payload is 0x55");
    };

    t.run("TLS-28: CS-04 X.509 UTCTime & GeneralizedTime Leap Year, Date & Cutoff Validation") { sub =>
        // 1. Leap year Feb 29 tests
        // 2024 is leap year: Feb 29 valid
        let _, ok_leap24 = wing::parse_utc_time("240229120000Z");
        sub.assert_true(ok_leap24, "2024-02-29 valid leap year date in UTCTime");

        // 2023 is not leap year: Feb 29 invalid
        let _, ok_non_leap23 = wing::parse_utc_time("230229120000Z");
        sub.assert_false(ok_non_leap23, "2023-02-29 rejected (not leap year)");

        // 2000 is leap year: Feb 29 valid
        let _, ok_leap2000 = wing::parse_generalized_time("20000229120000Z");
        sub.assert_true(ok_leap2000, "2000-02-29 valid leap year date in GeneralizedTime");

        // 1900 is not leap year: Feb 29 invalid
        let _, ok_non_leap1900 = wing::parse_generalized_time("19000229120000Z");
        sub.assert_false(ok_non_leap1900, "1900-02-29 rejected (not leap year)");

        // 2. Invalid month days
        let _, ok_apr31 = wing::parse_utc_time("240431120000Z");
        sub.assert_false(ok_apr31, "April 31 rejected");
        let _, ok_jun31 = wing::parse_utc_time("240631120000Z");
        sub.assert_false(ok_jun31, "June 31 rejected");
        let _, ok_feb30 = wing::parse_utc_time("240230120000Z");
        sub.assert_false(ok_feb30, "February 30 rejected");

        // 3. Out-of-bounds fields
        let _, ok_m0 = wing::parse_utc_time("240001120000Z");
        sub.assert_false(ok_m0, "Month 00 rejected");
        let _, ok_m13 = wing::parse_utc_time("241301120000Z");
        sub.assert_false(ok_m13, "Month 13 rejected");
        let _, ok_d0 = wing::parse_utc_time("240100120000Z");
        sub.assert_false(ok_d0, "Day 00 rejected");
        let _, ok_h24 = wing::parse_utc_time("240101240000Z");
        sub.assert_false(ok_h24, "Hour 24 rejected");
        let _, ok_min60 = wing::parse_utc_time("240101126000Z");
        sub.assert_false(ok_min60, "Minute 60 rejected");
        let _, ok_sec60 = wing::parse_utc_time("240101120060Z");
        sub.assert_false(ok_sec60, "Second 60 rejected");

        // 4. Missing or invalid 'Z' suffix
        let _, ok_no_z = wing::parse_utc_time("240101120000X");
        sub.assert_false(ok_no_z, "Missing 'Z' in UTCTime rejected");
        let _, ok_gen_no_z = wing::parse_generalized_time("20240101120000X");
        sub.assert_false(ok_gen_no_z, "Missing 'Z' in GeneralizedTime rejected");

        // 5. Length mismatches & fractional seconds
        let _, ok_trunc = wing::parse_utc_time("240101120000");
        sub.assert_false(ok_trunc, "Truncated UTCTime rejected");
        let _, ok_frac = wing::parse_generalized_time("20240101120000.5Z");
        sub.assert_false(ok_frac, "Fractional seconds in GeneralizedTime rejected");

        // 6. RFC 5280 §4.1.2.5.1: YY >= 50 is 19YY, YY < 50 is 20YY
        let t_50, ok_50 = wing::parse_utc_time("500101000000Z");
        sub.assert_true(ok_50, "YY=50 parsed as 1950");
        let t_49, ok_49 = wing::parse_utc_time("490101000000Z");
        sub.assert_true(ok_49, "YY=49 parsed as 2049");
        sub.assert_true(t_49 > t_50, "year 2049 is after year 1950");
    };

    t.run("TLS-29: CS-05 SAN Extension Parsing, Empty SAN Rejection & IP/DNS Conformance") { sub =>
        // 1. Empty SAN sequence strictly rejected (RFC 5280 §4.2.1.6 SIZE (1..MAX))
        let empty_san: u8[2] = [0x30, 0x00];
        var out_sans_empty: wing::SanEntry[..16] = [];
        sub.assert_false(wing::parse_san_extension(empty_san[..], out_sans_empty), "empty SAN sequence rejected");

        // 2. Invalid IP address length in SAN rejected
        let bad_ip_san: u8[5] = [0x30, 0x03, 0x87, 0x01, 0x0A]; // len 1
        var out_bad_ip: wing::SanEntry[..16] = [];
        sub.assert_false(wing::parse_san_extension(bad_ip_san[..], out_bad_ip), "IP SAN with 1 byte rejected");

        let bad_ip3_san: u8[7] = [0x30, 0x05, 0x87, 0x03, 0x0A, 0x00, 0x01]; // len 3
        sub.assert_false(wing::parse_san_extension(bad_ip3_san[..], out_bad_ip), "IP SAN with 3 bytes rejected");

        let bad_ip5_san: u8[9] = [0x30, 0x07, 0x87, 0x05, 0x0A, 0x00, 0x00, 0x01, 0x02]; // len 5
        sub.assert_false(wing::parse_san_extension(bad_ip5_san[..], out_bad_ip), "IP SAN with 5 bytes rejected");

        // 3. Valid IPv4 SAN (4 bytes)
        let valid_ip4_san: u8[8] = [0x30, 0x06, 0x87, 0x04, 192, 168, 1, 100];
        var out_ip4: wing::SanEntry[..16] = [];
        sub.assert_true(wing::parse_san_extension(valid_ip4_san[..], out_ip4), "valid IPv4 SAN parsed");
        sub.assert_eq(out_ip4.len, 1, "1 SAN parsed");
        sub.assert_true(out_ip4[0].san_type == wing::SanType.Ip, "type is IP");
        sub.assert_true(wing::match_san(out_ip4[0], "192.168.1.100"), "matches decimal IPv4 string");
        sub.assert_false(wing::match_san(out_ip4[0], "192.168.1.101"), "rejects mismatched IPv4");

        // Direct binary match
        let raw_ip: u8[4] = [192, 168, 1, 100];
        sub.assert_true(wing::match_ip_san(out_ip4[0].val, raw_ip[..]), "matches raw binary IPv4");

        // 4. DNS syntax validation in SAN
        sub.assert_true(wing::validate_san_dns_name("example.com"), "valid DNS name");
        sub.assert_true(wing::validate_san_dns_name("*.example.com"), "valid wildcard DNS name");
        sub.assert_true(wing::validate_san_dns_name("sub.api.example.com"), "valid multi-level DNS name");

        // Malformed DNS names
        sub.assert_false(wing::validate_san_dns_name(""), "empty DNS name rejected");
        sub.assert_false(wing::validate_san_dns_name(".example.com"), "leading dot rejected");
        sub.assert_false(wing::validate_san_dns_name("example.com."), "trailing dot rejected");
        sub.assert_false(wing::validate_san_dns_name("example..com"), "double dot rejected");
        sub.assert_false(wing::validate_san_dns_name("-bad.com"), "leading hyphen rejected");
        sub.assert_false(wing::validate_san_dns_name("bad-.com"), "trailing hyphen rejected");
        sub.assert_false(wing::validate_san_dns_name("foo.*.com"), "wildcard in non-leftmost label rejected");
        sub.assert_false(wing::validate_san_dns_name("bad space.com"), "space in DNS name rejected");

        // 5. Valid SAN extension with mixed DNS and IP entries
        // SEQUENCE { [2] "api.example.com" (15 bytes), [7] 10.0.0.1 (4 bytes) }
        var b = core::builder_init();
        core::put_u8(b, 0x30); // outer SEQUENCE tag
        core::start_u8_prefix(b);
        core::put_u8(b, 0x82); // dNSName
        core::put_u8(b, 15);
        core::put_bytes(b, "api.example.com");
        core::put_u8(b, 0x87); // iPAddress
        core::put_u8(b, 4);
        core::put_u8(b, 10);
        core::put_u8(b, 0);
        core::put_u8(b, 0);
        core::put_u8(b, 1);
        sub.assert_true(core::finish_u8_prefix(b), "finish sequence prefix");

        var multi_sans: wing::SanEntry[..16] = [];
        sub.assert_true(wing::parse_san_extension(b.buf[..], multi_sans), "parse multi-entry SAN extension");
        sub.assert_eq(multi_sans.len, 2, "2 SAN entries parsed");
        sub.assert_true(wing::match_any_san(multi_sans, "api.example.com"), "match DNS in multi-SAN");
        sub.assert_true(wing::match_any_san(multi_sans, "10.0.0.1"), "match IP in multi-SAN");
        sub.assert_false(wing::match_any_san(multi_sans, "other.com"), "reject unmatched host in multi-SAN");
    };

    t.run("TLS-30: CS-06 Validity Period Inversion & Expiration Validation") { sub =>
        // 1. Inverted validity in ParsedCert (notBefore > notAfter)
        var cert_inv = wing::ParsedCert {
            validity_not_before: 5000,
            validity_not_after:  1000,
        };
        let alert_inv = wing::validate_chain_cert_validity(cert_inv, 3000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_inv), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "inverted validity returns BadCertificate");

        // 2. read_tbs_validity rejects DER sequence with notBefore > notAfter
        // SEQUENCE { UTCTime "261028000000Z", UTCTime "251028000000Z" }
        // 261028000000Z (2026-10-28) > 251028000000Z (2025-10-28)
        var b_inv = core::builder_init();
        core::put_u8(b_inv, 0x30); // outer SEQUENCE
        core::start_u8_prefix(b_inv);
        // notBefore: 2026-10-28 00:00:00Z
        core::put_u8(b_inv, 0x17);
        core::put_u8(b_inv, 13);
        core::put_bytes(b_inv, "261028000000Z");
        // notAfter: 2025-10-28 00:00:00Z
        core::put_u8(b_inv, 0x17);
        core::put_u8(b_inv, 13);
        core::put_bytes(b_inv, "251028000000Z");
        sub.assert_true(core::finish_u8_prefix(b_inv), "finish inverted validity DER");

        var c_inv = core::cursor_from(b_inv.buf[..]);
        var dummy_cert = wing::ParsedCert {};
        sub.assert_false(wing::read_tbs_validity(b_inv.buf[..], c_inv, dummy_cert), "read_tbs_validity rejects inverted time");

        // 3. Valid validity sequence parses correctly
        var b_val = core::builder_init();
        core::put_u8(b_val, 0x30);
        core::start_u8_prefix(b_val);
        // notBefore: 2025-10-28 00:00:00Z
        core::put_u8(b_val, 0x17);
        core::put_u8(b_val, 13);
        core::put_bytes(b_val, "251028000000Z");
        // notAfter: 2026-10-28 00:00:00Z
        core::put_u8(b_val, 0x17);
        core::put_u8(b_val, 13);
        core::put_bytes(b_val, "261028000000Z");
        sub.assert_true(core::finish_u8_prefix(b_val), "finish valid validity DER");

        var c_val = core::cursor_from(b_val.buf[..]);
        var out_cert = wing::ParsedCert {};
        sub.assert_true(wing::read_tbs_validity(b_val.buf[..], c_val, out_cert), "read_tbs_validity accepts valid time");
        sub.assert_true(out_cert.validity_not_before < out_cert.validity_not_after, "notBefore < notAfter");

        // 4. Temporal expiration & not-yet-valid alerts
        var cert_exp = wing::ParsedCert {
            validity_not_before: 1000,
            validity_not_after:  2000,
        };
        let alert_expired = wing::validate_chain_cert_validity(cert_exp, 2500);
        sub.assert_eq(wing::tls_alert_to_u8(alert_expired), wing::tls_alert_to_u8(wing::TlsAlert.CertificateExpired), "now > notAfter returns CertificateExpired");

        let alert_not_yet = wing::validate_chain_cert_validity(cert_exp, 500);
        sub.assert_eq(wing::tls_alert_to_u8(alert_not_yet), wing::tls_alert_to_u8(wing::TlsAlert.CertificateExpired), "now < notBefore returns CertificateExpired");

        let alert_ok = wing::validate_chain_cert_validity(cert_exp, 1500);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid time returns CloseNotify");
    };

    t.run("TLS-31: CS-07 End-Entity vs Intermediate CA KeyUsage & CA Flag Enforcement") { sub =>
        // 1. End-entity MUST NOT assert CA: TRUE
        var ee_ca = wing::ParsedCert {
            is_ca:                 true,
            has_basic_constraints: true,
        };
        let alert_ee_ca = wing::validate_end_entity_constraints(ee_ca);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ee_ca), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "EE with is_ca returns BadCertificate");

        // 2. End-entity MUST NOT assert keyCertSign
        var ee_sign = wing::ParsedCert {
            is_ca:         false,
            key_usage:     rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage: true,
        };
        let alert_ee_sign = wing::validate_end_entity_constraints(ee_sign);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ee_sign), wing::tls_alert_to_u8(wing::TlsAlert.UnsupportedCertificate), "EE with keyCertSign returns UnsupportedCertificate");

        // 3. Valid end-entity (digitalSignature, not CA)
        var ee_valid = wing::ParsedCert {
            is_ca:         false,
            key_usage:     rfc::KEY_USAGE_DIGITAL_SIGNATURE,
            has_key_usage: true,
        };
        let alert_ee_ok = wing::validate_end_entity_constraints(ee_valid);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ee_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid EE returns CloseNotify");

        // 4. Intermediate CA MUST assert BasicConstraints with is_ca: TRUE
        var ca_no_bc = wing::ParsedCert {
            is_ca:                 false,
            has_basic_constraints: false,
        };
        let alert_ca_no_bc = wing::validate_intermediate_ca_constraints(ca_no_bc, 1);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ca_no_bc), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "intermediate without BC returns BadCertificate");

        var ca_false = wing::ParsedCert {
            is_ca:                 false,
            has_basic_constraints: true,
        };
        let alert_ca_false = wing::validate_intermediate_ca_constraints(ca_false, 1);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ca_false), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "intermediate with is_ca=false returns BadCertificate");

        // 5. Intermediate CA MUST assert keyCertSign if KeyUsage is present
        var ca_no_sign = wing::ParsedCert {
            is_ca:                 true,
            has_basic_constraints: true,
            key_usage:             rfc::KEY_USAGE_DIGITAL_SIGNATURE, // Missing keyCertSign
            has_key_usage:         true,
        };
        let alert_ca_no_sign = wing::validate_intermediate_ca_constraints(ca_no_sign, 1);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ca_no_sign), wing::tls_alert_to_u8(wing::TlsAlert.UnsupportedCertificate), "intermediate without keyCertSign returns UnsupportedCertificate");

        // 6. Valid Intermediate CA
        var ca_valid = wing::ParsedCert {
            is_ca:                 true,
            has_basic_constraints: true,
            path_len_constraint:   -1,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };
        let alert_ca_ok = wing::validate_intermediate_ca_constraints(ca_valid, 1);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ca_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid intermediate CA returns CloseNotify");
    };

    t.run("TLS-32: CS-08 BasicConstraints pathLenConstraint Invariants & Decrementation") { sub =>
        // 1. read_cert_extensions DER parsing:
        // BasicConstraints SEQUENCE { cA: FALSE (omitted), pathLenConstraint: 2 }
        // RFC 5280 §4.2.1.9: pathLenConstraint is meaningful ONLY if cA is TRUE.
        var b_bc_ee = core::builder_init();
        core::put_u8(b_bc_ee, 0x30); // outer Extension SEQUENCE
        core::start_u8_prefix(b_bc_ee);
        core::put_u8(b_bc_ee, 0x06); // OID tag
        core::put_u8(b_bc_ee, 3);
        core::put_bytes(b_bc_ee, "\x55\x1D\x13"); // 2.5.29.19
        core::put_u8(b_bc_ee, 0x04); // OCTET STRING tag
        core::start_u8_prefix(b_bc_ee);
        core::put_u8(b_bc_ee, 0x30); // BasicConstraints SEQUENCE
        core::start_u8_prefix(b_bc_ee);
        core::put_u8(b_bc_ee, 0x02); // INTEGER tag
        core::put_u8(b_bc_ee, 1);
        core::put_u8(b_bc_ee, 2);    // pathLen = 2
        sub.assert_true(core::finish_u8_prefix(b_bc_ee), "finish BC seq");
        sub.assert_true(core::finish_u8_prefix(b_bc_ee), "finish octet str");
        sub.assert_true(core::finish_u8_prefix(b_bc_ee), "finish ext seq");

        var c_bc_ee = core::cursor_from(b_bc_ee.buf[..]);
        var cert_parsed_ee = wing::ParsedCert {};
        wing::read_cert_extensions(b_bc_ee.buf[..], c_bc_ee, cert_parsed_ee);
        sub.assert_true(cert_parsed_ee.has_basic_constraints, "has BC");
        sub.assert_false(cert_parsed_ee.is_ca, "is_ca is false");
        sub.assert_eq(cert_parsed_ee.path_len_constraint, -1, "pathLen ignored when is_ca is false");

        // 2. BasicConstraints with cA: TRUE and pathLen: 2
        var b_bc_ca = core::builder_init();
        core::put_u8(b_bc_ca, 0x30); // outer Extension SEQUENCE
        core::start_u8_prefix(b_bc_ca);
        core::put_u8(b_bc_ca, 0x06); // OID tag
        core::put_u8(b_bc_ca, 3);
        core::put_bytes(b_bc_ca, "\x55\x1D\x13"); // 2.5.29.19
        core::put_u8(b_bc_ca, 0x04); // OCTET STRING tag
        core::start_u8_prefix(b_bc_ca);
        core::put_u8(b_bc_ca, 0x30); // BasicConstraints SEQUENCE
        core::start_u8_prefix(b_bc_ca);
        core::put_u8(b_bc_ca, 0x01); // BOOLEAN tag
        core::put_u8(b_bc_ca, 1);
        core::put_u8(b_bc_ca, 0xFF); // TRUE
        core::put_u8(b_bc_ca, 0x02); // INTEGER tag
        core::put_u8(b_bc_ca, 1);
        core::put_u8(b_bc_ca, 2);    // pathLen = 2
        sub.assert_true(core::finish_u8_prefix(b_bc_ca), "finish BC ca seq");
        sub.assert_true(core::finish_u8_prefix(b_bc_ca), "finish octet str");
        sub.assert_true(core::finish_u8_prefix(b_bc_ca), "finish ext seq");

        var c_bc_ca = core::cursor_from(b_bc_ca.buf[..]);
        var cert_parsed_ca = wing::ParsedCert {};
        wing::read_cert_extensions(b_bc_ca.buf[..], c_bc_ca, cert_parsed_ca);
        sub.assert_true(cert_parsed_ca.has_basic_constraints, "has BC");
        sub.assert_true(cert_parsed_ca.is_ca, "is_ca is true");
        sub.assert_eq(cert_parsed_ca.path_len_constraint, 2, "pathLen parsed as 2 when is_ca is true");

        // 3. Path length decrementation and enforcement across chain depth:
        // Intermediate CA at depth 1 with pathLen = 0 (issuing EE at depth 0) -> allowed (0 intermediate certs follow)
        var ca_depth1 = wing::ParsedCert {
            is_ca:                 true,
            has_basic_constraints: true,
            path_len_constraint:   0,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };
        let alert_d1 = wing::validate_intermediate_ca_constraints(ca_depth1, 1);
        sub.assert_eq(wing::tls_alert_to_u8(alert_d1), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "intermediate at depth 1 with pathLen=0 succeeds");

        // Intermediate CA at depth 2 with pathLen = 0 (1 intermediate cert follows it) -> violated!
        var ca_depth2 = wing::ParsedCert {
            is_ca:                 true,
            has_basic_constraints: true,
            path_len_constraint:   0,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };
        let alert_d2 = wing::validate_intermediate_ca_constraints(ca_depth2, 2);
        sub.assert_eq(wing::tls_alert_to_u8(alert_d2), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "intermediate at depth 2 with pathLen=0 returns BadCertificate");

        // Intermediate CA at depth 2 with pathLen = 1 -> allowed (1 <= 1)
        var ca_depth2_ok = wing::ParsedCert {
            is_ca:                 true,
            has_basic_constraints: true,
            path_len_constraint:   1,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };
        let alert_d2_ok = wing::validate_intermediate_ca_constraints(ca_depth2_ok, 2);
        sub.assert_eq(wing::tls_alert_to_u8(alert_d2_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "intermediate at depth 2 with pathLen=1 succeeds");
    };

    t.run("TLS-33: CS-09 Forbidden TLS 1.3 Signature Schemes & Certificate Signature Algorithms") { sub =>
        // 1. Forbidden TLS 1.3 signature schemes (RFC 8446 §4.2.3)
        sub.assert_true(rfc::is_forbidden_tls13_sig_scheme(0x0401), "RSA-PKCS1-SHA256 (0x0401) is forbidden");
        sub.assert_true(rfc::is_forbidden_tls13_sig_scheme(0x0501), "RSA-PKCS1-SHA384 (0x0501) is forbidden");
        sub.assert_true(rfc::is_forbidden_tls13_sig_scheme(0x0601), "RSA-PKCS1-SHA512 (0x0601) is forbidden");
        sub.assert_true(rfc::is_forbidden_tls13_sig_scheme(0x0201), "RSA-PKCS1-SHA1 (0x0201) is forbidden");
        sub.assert_true(rfc::is_forbidden_tls13_sig_scheme(0x0203), "ECDSA-SHA1 (0x0203) is forbidden");
        sub.assert_true(rfc::is_forbidden_tls13_sig_scheme(0x0101), "RSA-PKCS1-MD5 (0x0101) is forbidden");

        // Permitted TLS 1.3 schemes
        sub.assert_false(rfc::is_forbidden_tls13_sig_scheme(0x0403), "ECDSA-SECP256R1-SHA256 (0x0403) is permitted");
        sub.assert_false(rfc::is_forbidden_tls13_sig_scheme(0x0804), "RSA-PSS-RSAE-SHA256 (0x0804) is permitted");
        sub.assert_false(rfc::is_forbidden_tls13_sig_scheme(0x0807), "ED25519 (0x0807) is permitted");

        // 2. verify_signature_scheme_curve_binding enforces rejection of forbidden schemes
        sub.assert_false(wing::verify_signature_scheme_curve_binding(0x0401, rfc::OID_RSA_ENCRYPTION[..]), "reject 0x0401 in curve binding");
        sub.assert_false(wing::verify_signature_scheme_curve_binding(0x0501, rfc::OID_RSA_ENCRYPTION[..]), "reject 0x0501 in curve binding");
        sub.assert_true(wing::verify_signature_scheme_curve_binding(0x0804, rfc::OID_RSA_ENCRYPTION[..]), "accept 0x0804 in curve binding");
        sub.assert_true(wing::verify_signature_scheme_curve_binding(0x0403, rfc::OID_SECP256R1[..]), "accept 0x0403 in curve binding");

        // 3. Forbidden Certificate Signature Algorithm OIDs (MD5 & SHA-1)
        sub.assert_true(rfc::is_forbidden_cert_signature_algorithm(rfc::OID_SIG_MD5_RSA[..]), "MD5-RSA is forbidden");
        sub.assert_true(rfc::is_forbidden_cert_signature_algorithm(rfc::OID_SIG_SHA1_RSA[..]), "SHA1-RSA is forbidden");
        sub.assert_true(rfc::is_forbidden_cert_signature_algorithm(rfc::OID_SIG_SHA1_ECDSA[..]), "SHA1-ECDSA is forbidden");
        sub.assert_true(rfc::is_forbidden_cert_signature_algorithm(rfc::OID_SIG_SHA1_DSA[..]), "SHA1-DSA is forbidden");

        // Valid SHA-256 RSA OID (1.2.840.113549.1.1.11)
        let oid_sha256_rsa: u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        sub.assert_false(rfc::is_forbidden_cert_signature_algorithm(oid_sha256_rsa[..]), "SHA256-RSA is permitted");

        // 4. verify_certificate_chain rejects cert signed with forbidden algorithm
        var store = wing::TrustAnchorStore { anchors: [] };
        let root_sub:  u8[4] = [1, 2, 3, 4];
        let root_spki: u8[4] = [5, 6, 7, 8];
        sub.assert_true(wing::add_trust_anchor(store, root_sub[..], root_spki[..]), "add anchor");

        var bad_sig_raw: u8[20] = [0; 20];
        // Put OID_SIG_SHA1_RSA at offset 10 (length 9)
        for i in 9 { bad_sig_raw[10 + i] = rfc::OID_SIG_SHA1_RSA[i]; }

        var bad_cert = wing::ParsedCert {
            sig_alg_oid:         wing::Span16 { offset: 10, length: 9 },
            validity_not_before: 1000,
            validity_not_after:  5000,
            subject_raw:         wing::Span16 { offset: 0, length: 4 },
            spki_raw:            wing::Span16 { offset: 4, length: 4 },
        };
        var chain_bad: wing::ParsedCert[..8] = [];
        chain_bad.push(bad_cert);
        var raw_bad: const u8[:][..8] = [];
        raw_bad.push(bad_sig_raw[..]);

        let alert_sig = wing::verify_certificate_chain(chain_bad, raw_bad, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_sig), wing::tls_alert_to_u8(wing::TlsAlert.UnsupportedCertificate), "forbidden cert sig returns UnsupportedCertificate");
    };

    t.run("TLS-34: CS-10 Certificate Chain Cycle Detection & Depth Limits") { sub =>
        var store = wing::TrustAnchorStore { anchors: [] };
        let root_dn:   u8[4] = [0x52, 0x4F, 0x4F, 0x54]; // "ROOT"
        let root_spki: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        sub.assert_true(wing::add_trust_anchor(store, root_dn[..], root_spki[..]), "anchor added");

        // Raw buffer with shared components
        var raw_buf: u8[64] = [0; 64];
        for i in 4 { raw_buf[0 + i] = root_dn[i]; }     // offset 0: ROOT DN
        for i in 4 { raw_buf[4 + i] = root_spki[i]; }   // offset 4: ROOT SPKI
        raw_buf[8] = 0xEE; raw_buf[9] = 0x01;           // offset 8: EE DN
        raw_buf[10] = 0xEE; raw_buf[11] = 0x02;         // offset 10: EE SPKI
        raw_buf[12] = 0xCA; raw_buf[13] = 0x01;         // offset 12: CA DN
        raw_buf[14] = 0xCA; raw_buf[15] = 0x02;         // offset 14: CA SPKI

        // 1. Cycle detection: Duplicate Subject DN between two certs in chain
        var cert_ee_dup_sub = wing::ParsedCert {
            issuer_raw:          wing::Span16 { offset: 8, length: 2 },
            validity_not_before: 1000,
            validity_not_after:  5000,
            subject_raw:         wing::Span16 { offset: 8, length: 2 }, // EE DN
            spki_raw:            wing::Span16 { offset: 10, length: 2 },
        };
        var cert_ca_dup_sub = wing::ParsedCert {
            issuer_raw:            wing::Span16 { offset: 0, length: 4 },
            validity_not_before:   1000,
            validity_not_after:    5000,
            subject_raw:           wing::Span16 { offset: 8, length: 2 }, // DUPLICATE EE DN!
            spki_raw:              wing::Span16 { offset: 14, length: 2 },
            is_ca:                 true,
            has_basic_constraints: true,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };
        var chain_dup_sub: wing::ParsedCert[..8] = [];
        chain_dup_sub.push(cert_ee_dup_sub);
        chain_dup_sub.push(cert_ca_dup_sub);
        var raw_dup_sub: const u8[:][..8] = [];
        raw_dup_sub.push(raw_buf[..]);
        raw_dup_sub.push(raw_buf[..]);

        let alert_dup_sub = wing::verify_certificate_chain(chain_dup_sub, raw_dup_sub, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_dup_sub), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "duplicate subject DN returns BadCertificate");

        // 2. Cycle detection: Duplicate SPKI (public key reuse loop)
        var cert_ee_dup_spki = wing::ParsedCert {
            issuer_raw:          wing::Span16 { offset: 12, length: 2 },
            validity_not_before: 1000,
            validity_not_after:  5000,
            subject_raw:         wing::Span16 { offset: 8, length: 2 },
            spki_raw:            wing::Span16 { offset: 10, length: 2 }, // EE SPKI
        };
        var cert_ca_dup_spki = wing::ParsedCert {
            issuer_raw:            wing::Span16 { offset: 0, length: 4 },
            validity_not_before:   1000,
            validity_not_after:    5000,
            subject_raw:           wing::Span16 { offset: 12, length: 2 },
            spki_raw:              wing::Span16 { offset: 10, length: 2 }, // DUPLICATE EE SPKI!
            is_ca:                 true,
            has_basic_constraints: true,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };
        var chain_dup_spki: wing::ParsedCert[..8] = [];
        chain_dup_spki.push(cert_ee_dup_spki);
        chain_dup_spki.push(cert_ca_dup_spki);
        var raw_dup_spki: const u8[:][..8] = [];
        raw_dup_spki.push(raw_buf[..]);
        raw_dup_spki.push(raw_buf[..]);

        let alert_dup_spki = wing::verify_certificate_chain(chain_dup_spki, raw_dup_spki, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_dup_spki), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "duplicate SPKI returns BadCertificate");

        // 3. Valid multi-cert chain (EE -> Intermediate -> Root Anchor)
        var cert_ee_good = wing::ParsedCert {
            issuer_raw:          wing::Span16 { offset: 12, length: 2 }, // Issued by CA
            validity_not_before: 1000,
            validity_not_after:  5000,
            subject_raw:         wing::Span16 { offset: 8, length: 2 },
            spki_raw:            wing::Span16 { offset: 10, length: 2 },
        };
        var cert_ca_good = wing::ParsedCert {
            issuer_raw:            wing::Span16 { offset: 0, length: 4 }, // Issued by Root
            validity_not_before:   1000,
            validity_not_after:    5000,
            subject_raw:           wing::Span16 { offset: 12, length: 2 },
            spki_raw:              wing::Span16 { offset: 14, length: 2 },
            is_ca:                 true,
            has_basic_constraints: true,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };
        var cert_root_good = wing::ParsedCert {
            issuer_raw:            wing::Span16 { offset: 0, length: 4 },
            validity_not_before:   1000,
            validity_not_after:    5000,
            subject_raw:           wing::Span16 { offset: 0, length: 4 },
            spki_raw:              wing::Span16 { offset: 4, length: 4 },
            is_ca:                 true,
            has_basic_constraints: true,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };

        var chain_3: wing::ParsedCert[..8] = [];
        chain_3.push(cert_ee_good);
        chain_3.push(cert_ca_good);
        chain_3.push(cert_root_good);
        var raw_3: const u8[:][..8] = [];
        raw_3.push(raw_buf[..]);
        raw_3.push(raw_buf[..]);
        raw_3.push(raw_buf[..]);

        let alert_chain3 = wing::verify_certificate_chain(chain_3, raw_3, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_chain3), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid 3-cert chain verified successfully");

        // 4. Empty chain rejection
        var chain_empty: wing::ParsedCert[..8] = [];
        var raw_empty:   const u8[:][..8]      = [];
        let alert_empty = wing::verify_certificate_chain(chain_empty, raw_empty, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_empty), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "empty chain returns BadCertificate");
    };

    t.run("TLS-35: CS-11 Name Constraints Subtree Enforcement & CIDR Subnet Mask Validation") { sub =>
        // 1. Contiguous CIDR subnet mask validation (RFC 5280 §4.2.1.10)
        let mask_24: u8[4] = [255, 255, 255, 0];
        sub.assert_true(wing::validate_cidr_mask(mask_24[..]), "valid /24 mask");
        let mask_17: u8[4] = [255, 255, 128, 0];
        sub.assert_true(wing::validate_cidr_mask(mask_17[..]), "valid /17 mask");
        let mask_32: u8[4] = [255, 255, 255, 255];
        sub.assert_true(wing::validate_cidr_mask(mask_32[..]), "valid /32 mask");
        let mask_0: u8[4] = [0, 0, 0, 0];
        sub.assert_true(wing::validate_cidr_mask(mask_0[..]), "valid /0 mask");

        // Non-contiguous subnet masks
        let mask_bad1: u8[4] = [255, 255, 0, 255];
        sub.assert_false(wing::validate_cidr_mask(mask_bad1[..]), "reject non-contiguous 255.255.0.255");
        let mask_bad2: u8[4] = [255, 255, 129, 0];
        sub.assert_false(wing::validate_cidr_mask(mask_bad2[..]), "reject non-contiguous 255.255.129.0");

        // Invalid mask length (e.g. 3 bytes or 5 bytes)
        let mask_bad_len: u8[3] = [255, 255, 255];
        sub.assert_false(wing::validate_cidr_mask(mask_bad_len[..]), "reject 3-byte mask");

        // 2. DNS Name Constraint matching (RFC 5280 §4.2.1.10)
        // Without leading dot: "example.com"
        sub.assert_true(wing::match_dns_name_constraint("example.com", "example.com"), "matches exact domain");
        sub.assert_true(wing::match_dns_name_constraint("sub.example.com", "example.com"), "matches subdomain");
        sub.assert_true(wing::match_dns_name_constraint("a.b.example.com", "example.com"), "matches multi-level subdomain");
        sub.assert_false(wing::match_dns_name_constraint("otherexample.com", "example.com"), "rejects prefix without dot boundary");
        sub.assert_false(wing::match_dns_name_constraint("notexample.com", "example.com"), "rejects notexample.com");

        // With leading dot: ".example.com"
        sub.assert_true(wing::match_dns_name_constraint("sub.example.com", ".example.com"), "matches subdomain under .example.com");
        sub.assert_true(wing::match_dns_name_constraint("a.b.example.com", ".example.com"), "matches deep subdomain");
        sub.assert_false(wing::match_dns_name_constraint("example.com", ".example.com"), "rejects apex for .example.com");
        sub.assert_false(wing::match_dns_name_constraint("otherexample.com", ".example.com"), "rejects non-subdomain");

        // RFC 5280 §4.2.1.10: Trailing dot in DNS name constraints & candidates (prevent ExcludedSubtree bypass)
        sub.assert_true(wing::match_dns_name_constraint("sub.example.com.", ".example.com"), "candidate with trailing dot matches leading dot constraint");
        sub.assert_true(wing::match_dns_name_constraint("sub.example.com.", "example.com"), "candidate with trailing dot matches subdomain constraint");
        sub.assert_true(wing::match_dns_name_constraint("example.com.", "example.com"), "candidate with trailing dot matches exact domain constraint");
        sub.assert_true(wing::match_dns_name_constraint("sub.example.com", ".example.com."), "constraint with trailing dot matches candidate");

        // CVE-2021-3712 / OpenSSL #31686: Embedded NUL rejection in NameConstraints
        sub.assert_false(wing::match_dns_name_constraint("sub.example.com\0.evil.com", "example.com"), "reject embedded NUL in candidate DNS");
        sub.assert_false(wing::match_dns_name_constraint("sub.example.com", "example.com\0.evil.com"), "reject embedded NUL in constraint");

        // 3. IP Name Constraint matching (RFC 5280 §4.2.1.10)
        // Subnet 192.168.1.0/24 (8 octets: 192.168.1.0 || 255.255.255.0)
        let ip_constraint: u8[8] = [192, 168, 1, 0, 255, 255, 255, 0];
        let cand_in_sub:   u8[4] = [192, 168, 1, 100];
        sub.assert_true(wing::match_ip_name_constraint(cand_in_sub[..], ip_constraint[..]), "matches IPv4 in subnet");
        let cand_out_sub: u8[4] = [192, 168, 2, 100];
        sub.assert_false(wing::match_ip_name_constraint(cand_out_sub[..], ip_constraint[..]), "rejects IPv4 outside subnet");
        let cand_diff_net: u8[4] = [10, 0, 0, 1];
        sub.assert_false(wing::match_ip_name_constraint(cand_diff_net[..], ip_constraint[..]), "rejects 10.0.0.1 outside subnet");

        // RFC 5280 §4.2.1.10: IP name constraint length validation (4/8 octets IPv4, 16/32 octets IPv6)
        let empty_ip: u8[0] = [];
        sub.assert_false(wing::match_ip_name_constraint(empty_ip[..], empty_ip[..]), "reject empty IP and empty constraint");
        let bad_len_cons: u8[4] = [192, 168, 1, 0]; // 4 octets instead of 8
        sub.assert_false(wing::match_ip_name_constraint(cand_in_sub[..], bad_len_cons[..]), "reject 4-octet IPv4 constraint (must be 8 octets)");
        sub.assert_false(wing::match_ip_name_constraint(cand_in_sub[..], empty_ip[..]), "reject empty constraint with IPv4 candidate");

        // 4. Empty NameConstraints SEQUENCE rejection (RFC 5280 §4.2.1.10)
        let empty_nc: u8[2] = [0x30, 0x00];
        var out_nc_empty: wing::NameConstraintEntry[..16] = [];
        sub.assert_false(wing::parse_name_constraints(empty_nc[..], out_nc_empty), "reject empty NameConstraints sequence");

        // 5. End-entity asserting Name Constraints rejection (RFC 5280 §4.2.1.10)
        var ee_with_nc = wing::ParsedCert {
            has_name_constraints: true,
        };
        let alert_ee_nc = wing::validate_end_entity_constraints(ee_with_nc);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ee_nc), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "EE with name constraints returns BadCertificate");
    };

    t.run("TLS-36: CS-12 Unrecognized Critical Extension Rejection") { sub =>
        // 1. Extension with unrecognized OID marked critical: TRUE
        // Extension SEQUENCE { OID 1.3.153 (2B 06 99), critical BOOLEAN TRUE (0xFF), extnValue OCTET STRING "val" }
        var b_crit = core::builder_init();
        core::put_u8(b_crit, 0x30); // Extension SEQUENCE
        core::start_u8_prefix(b_crit);
        core::put_u8(b_crit, 0x06); // OID
        core::put_u8(b_crit, 3);
        core::put_bytes(b_crit, "\x2B\x06\x99"); // Unrecognized OID
        core::put_u8(b_crit, 0x01); // BOOLEAN (critical)
        core::put_u8(b_crit, 1);
        core::put_u8(b_crit, 0xFF); // TRUE
        core::put_u8(b_crit, 0x04); // OCTET STRING
        core::put_u8(b_crit, 3);
        core::put_bytes(b_crit, "val");
        sub.assert_true(core::finish_u8_prefix(b_crit), "finish crit ext");

        var c_crit = core::cursor_from(b_crit.buf[..]);
        var cert_crit = wing::ParsedCert {};
        wing::read_cert_extensions(b_crit.buf[..], c_crit, cert_crit);
        sub.assert_true(cert_crit.has_unsupported_critical, "unrecognized critical extension detected");

        // 2. Chain verification rejects cert with unrecognized critical extension
        var store = wing::TrustAnchorStore { anchors: [] };
        let root_dn:   u8[4] = [1, 2, 3, 4];
        let root_spki: u8[4] = [5, 6, 7, 8];
        sub.assert_true(wing::add_trust_anchor(store, root_dn[..], root_spki[..]), "add anchor");

        var raw_cert_buf:    u8[20]                = [0; 20];
        var cert_chain_crit: wing::ParsedCert[..8] = [];
        cert_chain_crit.push(cert_crit);
        var raw_chain_crit: const u8[:][..8] = [];
        raw_chain_crit.push(raw_cert_buf[..]);

        let alert_crit = wing::verify_certificate_chain(cert_chain_crit, raw_chain_crit, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_crit), wing::tls_alert_to_u8(wing::TlsAlert.UnsupportedExtension), "unrecognized critical extension returns UnsupportedExtension");

        // 3. Extension with unrecognized OID marked critical: FALSE (allowed to be ignored per RFC 5280 §4.2)
        var b_noncrit = core::builder_init();
        core::put_u8(b_noncrit, 0x30); // Extension SEQUENCE
        core::start_u8_prefix(b_noncrit);
        core::put_u8(b_noncrit, 0x06); // OID
        core::put_u8(b_noncrit, 3);
        core::put_bytes(b_noncrit, "\x2B\x06\x99");
        core::put_u8(b_noncrit, 0x01); // BOOLEAN (critical)
        core::put_u8(b_noncrit, 1);
        core::put_u8(b_noncrit, 0x00); // FALSE
        core::put_u8(b_noncrit, 0x04); // OCTET STRING
        core::put_u8(b_noncrit, 3);
        core::put_bytes(b_noncrit, "val");
        sub.assert_true(core::finish_u8_prefix(b_noncrit), "finish noncrit ext");

        var c_noncrit = core::cursor_from(b_noncrit.buf[..]);
        var cert_noncrit = wing::ParsedCert {};
        wing::read_cert_extensions(b_noncrit.buf[..], c_noncrit, cert_noncrit);
        sub.assert_false(cert_noncrit.has_unsupported_critical, "unrecognized non-critical extension ignored");
    };

    t.run("TLS-37: CS-13 AKID and SKID Chain Linking & KeyID Invariants") { sub =>
        // 1. SubjectKeyIdentifier (2.5.29.14) DER extraction
        var b_skid = core::builder_init();
        core::put_u8(b_skid, 0x30); // Extension SEQUENCE
        core::start_u8_prefix(b_skid);
        core::put_u8(b_skid, 0x06); // OID
        core::put_u8(b_skid, 3);
        core::put_bytes(b_skid, "\x55\x1D\x0E"); // 2.5.29.14
        core::put_u8(b_skid, 0x04); // OCTET STRING extnValue
        core::start_u8_prefix(b_skid);
        core::put_u8(b_skid, 0x04); // KeyIdentifier OCTET STRING
        core::put_u8(b_skid, 4);
        core::put_bytes(b_skid, "\x11\x22\x33\x44");
        sub.assert_true(core::finish_u8_prefix(b_skid), "finish skid val");
        sub.assert_true(core::finish_u8_prefix(b_skid), "finish skid ext");

        var c_skid = core::cursor_from(b_skid.buf[..]);
        var cert_parsed_skid = wing::ParsedCert {};
        wing::read_cert_extensions(b_skid.buf[..], c_skid, cert_parsed_skid);
        sub.assert_true(cert_parsed_skid.has_skid, "has SKID");
        let skid_slice = wing::span_slice(b_skid.buf[..], cert_parsed_skid.skid_key_id);
        sub.assert_eq(skid_slice, "\x11\x22\x33\x44", "SKID key ID matches");

        // 2. AuthorityKeyIdentifier (2.5.29.35) DER extraction
        var b_akid = core::builder_init();
        core::put_u8(b_akid, 0x30); // Extension SEQUENCE
        core::start_u8_prefix(b_akid);
        core::put_u8(b_akid, 0x06); // OID
        core::put_u8(b_akid, 3);
        core::put_bytes(b_akid, "\x55\x1D\x23"); // 2.5.29.35
        core::put_u8(b_akid, 0x04); // OCTET STRING extnValue
        core::start_u8_prefix(b_akid);
        core::put_u8(b_akid, 0x30); // AuthorityKeyIdentifier SEQUENCE
        core::start_u8_prefix(b_akid);
        core::put_u8(b_akid, 0x80); // keyIdentifier [0] IMPLICIT
        core::put_u8(b_akid, 4);
        core::put_bytes(b_akid, "\x11\x22\x33\x44");
        sub.assert_true(core::finish_u8_prefix(b_akid), "finish akid seq");
        sub.assert_true(core::finish_u8_prefix(b_akid), "finish akid val");
        sub.assert_true(core::finish_u8_prefix(b_akid), "finish akid ext");

        var c_akid = core::cursor_from(b_akid.buf[..]);
        var cert_parsed_akid = wing::ParsedCert {};
        wing::read_cert_extensions(b_akid.buf[..], c_akid, cert_parsed_akid);
        sub.assert_true(cert_parsed_akid.has_akid, "has AKID");
        let akid_slice = wing::span_slice(b_akid.buf[..], cert_parsed_akid.akid_key_id);
        sub.assert_eq(akid_slice, "\x11\x22\x33\x44", "AKID key ID matches");

        // 3. Chain Linking with AKID / SKID: Matching key IDs
        var store = wing::TrustAnchorStore { anchors: [] };
        let root_dn:   u8[4] = [0x52, 0x4F, 0x4F, 0x54]; // "ROOT"
        let root_spki: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        sub.assert_true(wing::add_trust_anchor(store, root_dn[..], root_spki[..]), "add anchor");

        var raw_buf: u8[64] = [0; 64];
        for i in 4 { raw_buf[0 + i] = root_dn[i]; }     // offset 0: ROOT DN
        for i in 4 { raw_buf[4 + i] = root_spki[i]; }   // offset 4: ROOT SPKI
        raw_buf[8] = 0xEE; raw_buf[9] = 0x01;           // offset 8: EE DN
        raw_buf[10] = 0xEE; raw_buf[11] = 0x02;         // offset 10: EE SPKI
        raw_buf[12] = 0xCA; raw_buf[13] = 0x01;         // offset 12: CA DN
        raw_buf[14] = 0xCA; raw_buf[15] = 0x02;         // offset 14: CA SPKI
        // Key IDs:
        // offset 20..24: "KID1"
        raw_buf[20] = 0x4B; raw_buf[21] = 0x49; raw_buf[22] = 0x44; raw_buf[23] = 0x31;
        // offset 24..28: "KID2"
        raw_buf[24] = 0x4B; raw_buf[25] = 0x49; raw_buf[26] = 0x44; raw_buf[27] = 0x32;

        var cert_ee_match = wing::ParsedCert {
            issuer_raw:          wing::Span16 { offset: 12, length: 2 }, // Issued by CA
            validity_not_before: 1000,
            validity_not_after:  5000,
            subject_raw:         wing::Span16 { offset: 8, length: 2 },
            spki_raw:            wing::Span16 { offset: 10, length: 2 },
            akid_key_id:         wing::Span16 { offset: 20, length: 4 }, // AKID = KID1
            has_akid:            true,
        };
        var cert_ca_match = wing::ParsedCert {
            issuer_raw:            wing::Span16 { offset: 0, length: 4 }, // Issued by Root
            validity_not_before:   1000,
            validity_not_after:    5000,
            subject_raw:           wing::Span16 { offset: 12, length: 2 },
            spki_raw:              wing::Span16 { offset: 14, length: 2 },
            is_ca:                 true,
            has_basic_constraints: true,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
            skid_key_id:           wing::Span16 { offset: 20, length: 4 }, // SKID = KID1
            has_skid:              true,
        };
        var cert_root = wing::ParsedCert {
            issuer_raw:            wing::Span16 { offset: 0, length: 4 },
            validity_not_before:   1000,
            validity_not_after:    5000,
            subject_raw:           wing::Span16 { offset: 0, length: 4 },
            spki_raw:              wing::Span16 { offset: 4, length: 4 },
            is_ca:                 true,
            has_basic_constraints: true,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };

        var chain_match: wing::ParsedCert[..8] = [];
        chain_match.push(cert_ee_match);
        chain_match.push(cert_ca_match);
        chain_match.push(cert_root);
        var raw_chain: const u8[:][..8] = [];
        raw_chain.push(raw_buf[..]);
        raw_chain.push(raw_buf[..]);
        raw_chain.push(raw_buf[..]);

        let alert_match = wing::verify_certificate_chain(chain_match, raw_chain, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_match), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "matching AKID->SKID succeeds");

        // 4. Chain Linking with AKID / SKID: Mismatched key IDs
        var cert_ee_mismatch = wing::ParsedCert {
            issuer_raw:          wing::Span16 { offset: 12, length: 2 },
            validity_not_before: 1000,
            validity_not_after:  5000,
            subject_raw:         wing::Span16 { offset: 8, length: 2 },
            spki_raw:            wing::Span16 { offset: 10, length: 2 },
            akid_key_id:         wing::Span16 { offset: 24, length: 4 }, // AKID = KID2 != KID1
            has_akid:            true,
        };
        var chain_mismatch: wing::ParsedCert[..8] = [];
        chain_mismatch.push(cert_ee_mismatch);
        chain_mismatch.push(cert_ca_match);
        chain_mismatch.push(cert_root);

        let alert_mismatch = wing::verify_certificate_chain(chain_mismatch, raw_chain, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_mismatch), wing::tls_alert_to_u8(wing::TlsAlert.UnknownCa), "mismatched AKID->SKID returns UnknownCa");
    };

    t.run("TLS-38: CS-14 Policy Constraints & InhibitAnyPolicy Negative Bounds & Empty Sequence Defense") { sub =>
        // 1. PolicyConstraints (2.5.29.36) empty sequence rejection (RFC 5280 §4.2.1.11)
        var b_pc_empty = core::builder_init();
        core::put_u8(b_pc_empty, 0x30); // Extension SEQUENCE
        core::start_u8_prefix(b_pc_empty);
        core::put_u8(b_pc_empty, 0x06); // OID
        core::put_u8(b_pc_empty, 3);
        core::put_bytes(b_pc_empty, "\x55\x1D\x24"); // 2.5.29.36
        core::put_u8(b_pc_empty, 0x04); // OCTET STRING
        core::start_u8_prefix(b_pc_empty);
        core::put_u8(b_pc_empty, 0x30); // Empty SEQUENCE
        core::put_u8(b_pc_empty, 0);
        sub.assert_true(core::finish_u8_prefix(b_pc_empty), "finish octet str");
        sub.assert_true(core::finish_u8_prefix(b_pc_empty), "finish ext seq");

        var c_pc_empty = core::cursor_from(b_pc_empty.buf[..]);
        var cert_pc_empty = wing::ParsedCert {};
        wing::read_cert_extensions(b_pc_empty.buf[..], c_pc_empty, cert_pc_empty);
        sub.assert_true(cert_pc_empty.has_malformed_policy_constraints, "empty PolicyConstraints flagged as malformed");

        // 2. PolicyConstraints with negative SkipCerts integer
        var b_pc_neg = core::builder_init();
        core::put_u8(b_pc_neg, 0x30);
        core::start_u8_prefix(b_pc_neg);
        core::put_u8(b_pc_neg, 0x06);
        core::put_u8(b_pc_neg, 3);
        core::put_bytes(b_pc_neg, "\x55\x1D\x24");
        core::put_u8(b_pc_neg, 0x04);
        core::start_u8_prefix(b_pc_neg);
        core::put_u8(b_pc_neg, 0x30);
        core::start_u8_prefix(b_pc_neg);
        core::put_u8(b_pc_neg, 0x80); // [0] requireExplicitPolicy
        core::put_u8(b_pc_neg, 1);
        core::put_u8(b_pc_neg, 0xFF); // Negative integer in DER!
        sub.assert_true(core::finish_u8_prefix(b_pc_neg), "finish pc seq");
        sub.assert_true(core::finish_u8_prefix(b_pc_neg), "finish octet str");
        sub.assert_true(core::finish_u8_prefix(b_pc_neg), "finish ext seq");

        var c_pc_neg = core::cursor_from(b_pc_neg.buf[..]);
        var cert_pc_neg = wing::ParsedCert {};
        wing::read_cert_extensions(b_pc_neg.buf[..], c_pc_neg, cert_pc_neg);
        sub.assert_true(cert_pc_neg.has_malformed_policy_constraints, "negative SkipCerts flagged as malformed");

        // 3. InhibitAnyPolicy (2.5.29.54) with negative integer
        var b_iap_neg = core::builder_init();
        core::put_u8(b_iap_neg, 0x30);
        core::start_u8_prefix(b_iap_neg);
        core::put_u8(b_iap_neg, 0x06);
        core::put_u8(b_iap_neg, 3);
        core::put_bytes(b_iap_neg, "\x55\x1D\x36"); // 2.5.29.54
        core::put_u8(b_iap_neg, 0x04);
        core::start_u8_prefix(b_iap_neg);
        core::put_u8(b_iap_neg, 0x02); // INTEGER
        core::put_u8(b_iap_neg, 1);
        core::put_u8(b_iap_neg, 0x80); // Negative integer
        sub.assert_true(core::finish_u8_prefix(b_iap_neg), "finish octet str");
        sub.assert_true(core::finish_u8_prefix(b_iap_neg), "finish ext seq");

        var c_iap_neg = core::cursor_from(b_iap_neg.buf[..]);
        var cert_iap_neg = wing::ParsedCert {};
        wing::read_cert_extensions(b_iap_neg.buf[..], c_iap_neg, cert_iap_neg);
        sub.assert_true(cert_iap_neg.has_malformed_policy_constraints, "negative InhibitAnyPolicy flagged as malformed");

        // 4. Chain verification rejects cert with malformed policy constraints
        var store = wing::TrustAnchorStore { anchors: [] };
        let root_dn:   u8[4] = [1, 2, 3, 4];
        let root_spki: u8[4] = [5, 6, 7, 8];
        sub.assert_true(wing::add_trust_anchor(store, root_dn[..], root_spki[..]), "add anchor");

        var raw_buf:       u8[20]                = [0; 20];
        var cert_chain_pc: wing::ParsedCert[..8] = [];
        cert_chain_pc.push(cert_pc_neg);
        var raw_chain_pc: const u8[:][..8] = [];
        raw_chain_pc.push(raw_buf[..]);

        let alert_pc = wing::verify_certificate_chain(cert_chain_pc, raw_chain_pc, store, 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_pc), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "malformed policy constraints returns BadCertificate");
    };

    t.run("TLS-39: CS-15 OCSP Stapling Wire Framing, ResponseStatus, Temporal Inversion & CertID Matching") { sub =>
        // 1. Wire unwrapping (unwrap_tls_ocsp_response)
        var b_wire = core::builder_init();
        core::put_u8(b_wire, 0); // uint24 high
        core::put_u8(b_wire, 0); // uint24 mid
        core::put_u8(b_wire, 4); // uint24 low = 4 bytes
        core::put_bytes(b_wire, "OCSP");
        let unwrapped, ok_unwrap = wing::unwrap_tls_ocsp_response(b_wire.buf[..]);
        sub.assert_true(ok_unwrap, "unwrap valid wire response");
        sub.assert_eq(unwrapped, "OCSP", "unwrapped content matches");

        // Truncated wire response
        let trunc_wire: u8[5] = [0, 0, 10, 0xAA, 0xBB]; // Declares 10, only 2 provided
        let _, ok_trunc = wing::unwrap_tls_ocsp_response(trunc_wire[..]);
        sub.assert_false(ok_trunc, "reject truncated wire response");

        // Trailing wire response
        let trail_wire: u8[6] = [0, 0, 2, 0xAA, 0xBB, 0xCC]; // Declares 2, 3 provided
        let _, ok_trail = wing::unwrap_tls_ocsp_response(trail_wire[..]);
        sub.assert_false(ok_trail, "reject trailing bytes wire response");

        // 2. OCSP Response with error status (e.g. TryLater = 3)
        // SEQUENCE { ENUMERATED 3 }
        let ocsp_try_later: u8[5] = [0x30, 0x03, 0x0A, 0x01, 0x03];
        var parsed_later = wing::ParsedOcspResponse {};
        sub.assert_true(wing::parse_ocsp_response(ocsp_try_later[..], parsed_later), "parse TryLater status");
        sub.assert_true(parsed_later.status == wing::OcspResponseStatus.TryLater, "status is TryLater");

        var dummy_leaf = wing::ParsedCert {};
        let alert_later = wing::validate_ocsp_stapling(ocsp_try_later[..], dummy_leaf, "dummy", 2000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_later), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificateStatusResponse), "non-successful status returns BadCertificateStatusResponse");

        // 3. Construct a full valid OCSP Response
        // Serial number: 0x42 (1 byte)
        // CertStatus: good [0] NULL
        // thisUpdate: 2026-10-28 00:00:00Z ("20261028000000Z")
        // nextUpdate: 2026-10-29 00:00:00Z ("20261029000000Z")
        var b_tbs = core::builder_init();
        core::put_u8(b_tbs, 0x30); // tbsResponseData SEQUENCE
        core::start_u8_prefix(b_tbs);

        // responderID [1] EXPLICIT byName (empty sequence for mock)
        core::put_u8(b_tbs, 0xA1);
        core::put_u8(b_tbs, 2);
        core::put_u8(b_tbs, 0x30);
        core::put_u8(b_tbs, 0);

        // producedAt GeneralizedTime
        core::put_u8(b_tbs, 0x18);
        core::put_u8(b_tbs, 15);
        core::put_bytes(b_tbs, "20261028000000Z");

        // responses SEQUENCE OF SingleResponse
        core::put_u8(b_tbs, 0x30);
        core::start_u8_prefix(b_tbs);
        core::put_u8(b_tbs, 0x30); // SingleResponse SEQUENCE
        core::start_u8_prefix(b_tbs);

        // certID SEQUENCE
        core::put_u8(b_tbs, 0x30);
        core::put_u8(b_tbs, 9);
        // hashAlgorithm SEQUENCE (empty)
        core::put_u8(b_tbs, 0x30);
        core::put_u8(b_tbs, 0);
        // issuerNameHash OCTET STRING (empty)
        core::put_u8(b_tbs, 0x04);
        core::put_u8(b_tbs, 0);
        // issuerKeyHash OCTET STRING (empty)
        core::put_u8(b_tbs, 0x04);
        core::put_u8(b_tbs, 0);
        // serialNumber INTEGER 0x42
        core::put_u8(b_tbs, 0x02);
        core::put_u8(b_tbs, 1);
        core::put_u8(b_tbs, 0x42);

        // certStatus [0] IMPLICIT NULL (Good)
        core::put_u8(b_tbs, 0x80);
        core::put_u8(b_tbs, 0);

        // thisUpdate GeneralizedTime: 2026-10-28 00:00:00Z
        core::put_u8(b_tbs, 0x18);
        core::put_u8(b_tbs, 15);
        core::put_bytes(b_tbs, "20261028000000Z");

        // nextUpdate [0] EXPLICIT GeneralizedTime: 2026-10-29 00:00:00Z
        core::put_u8(b_tbs, 0xA0);
        core::put_u8(b_tbs, 17);
        core::put_u8(b_tbs, 0x18);
        core::put_u8(b_tbs, 15);
        core::put_bytes(b_tbs, "20261029000000Z");

        sub.assert_true(core::finish_u8_prefix(b_tbs), "finish single_resp");
        sub.assert_true(core::finish_u8_prefix(b_tbs), "finish responses");
        sub.assert_true(core::finish_u8_prefix(b_tbs), "finish tbsResponseData");

        var b_basic = core::builder_init();
        core::put_u8(b_basic, 0x30); // BasicOCSPResponse SEQUENCE
        core::start_u8_prefix(b_basic);
        core::put_bytes(b_basic, b_tbs.buf[..]);
        sub.assert_true(core::finish_u8_prefix(b_basic), "finish BasicOCSPResponse");

        var b_ocsp = core::builder_init();
        core::put_u8(b_ocsp, 0x30); // outer OCSPResponse SEQUENCE
        core::start_u8_prefix(b_ocsp);
        core::put_u8(b_ocsp, 0x0A); // ENUMERATED responseStatus
        core::put_u8(b_ocsp, 1);
        core::put_u8(b_ocsp, 0);    // 0 = Successful

        core::put_u8(b_ocsp, 0xA0); // [0] EXPLICIT ResponseBytes
        core::start_u8_prefix(b_ocsp);
        core::put_u8(b_ocsp, 0x30); // ResponseBytes SEQUENCE
        core::start_u8_prefix(b_ocsp);
        core::put_u8(b_ocsp, 0x06); // OID id-pkix-ocsp-basic
        core::put_u8(b_ocsp, 9);
        core::put_bytes(b_ocsp, "\x2B\x06\x01\x05\x05\x07\x30\x01\x01");
        core::put_u8(b_ocsp, 0x04); // response OCTET STRING
        core::start_u8_prefix(b_ocsp);
        core::put_bytes(b_ocsp, b_basic.buf[..]);
        sub.assert_true(core::finish_u8_prefix(b_ocsp), "finish response OCTET STRING");
        sub.assert_true(core::finish_u8_prefix(b_ocsp), "finish ResponseBytes SEQUENCE");
        sub.assert_true(core::finish_u8_prefix(b_ocsp), "finish [0] ResponseBytes");
        sub.assert_true(core::finish_u8_prefix(b_ocsp), "finish OCSPResponse");

        var parsed_ok = wing::ParsedOcspResponse {};
        sub.assert_true(wing::parse_ocsp_response(b_ocsp.buf[..], parsed_ok), "parse full OCSP response");
        sub.assert_true(parsed_ok.status == wing::OcspResponseStatus.Successful, "status is Successful");
        sub.assert_true(parsed_ok.cert_status == wing::OcspCertStatus.Good, "cert status is Good");
        sub.assert_true(parsed_ok.has_next_update, "has nextUpdate");
        sub.assert_true(parsed_ok.this_update < parsed_ok.next_update, "thisUpdate < nextUpdate");

        // Mock leaf cert with serialNumber 0x42
        let raw_leaf_serial: u8[1] = [0x42];
        var leaf_matching = wing::ParsedCert {
            serial_number: wing::Span16 { offset: 0, length: 1 },
        };
        // Verify with valid timestamp (halfway between 2026-10-28 and 2026-10-29)
        let mid_time = (parsed_ok.this_update + parsed_ok.next_update) / 2;
        let alert_ocsp_ok = wing::validate_ocsp_stapling(b_ocsp.buf[..], leaf_matching, raw_leaf_serial[..], mid_time);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ocsp_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "valid OCSP stapling succeeds");

        // Serial number mismatch defense: leaf cert with serial 0x99
        let raw_mismatch_serial: u8[1] = [0x99];
        let alert_mismatch = wing::validate_ocsp_stapling(b_ocsp.buf[..], leaf_matching, raw_mismatch_serial[..], mid_time);
        sub.assert_eq(wing::tls_alert_to_u8(alert_mismatch), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificateStatusResponse), "serial mismatch returns BadCertificateStatusResponse");

        // Temporal expiration defense: now > nextUpdate
        let alert_expired = wing::validate_ocsp_stapling(b_ocsp.buf[..], leaf_matching, raw_leaf_serial[..], parsed_ok.next_update + 1000);
        sub.assert_eq(wing::tls_alert_to_u8(alert_expired), wing::tls_alert_to_u8(wing::TlsAlert.CertificateExpired), "expired OCSP returns CertificateExpired");
    };

    t.run("TLS-40: Ed25519 X.509 Cryptographic Signature Chain Verification & Tamper Detection") { sub =>
        let root_seed: u8[32] = [0x55; 32];
        let root_kp = core::ed25519_keypair(root_seed);
        let leaf_seed: u8[32] = [0x77; 32];
        let leaf_kp = core::ed25519_keypair(leaf_seed);

        // 1. Build TBSCertificate payload for leaf
        var b_tbs_body = core::builder_init();
        // serialNumber (INTEGER: 0x42)
        core::put_u8(b_tbs_body, 0x02);
        core::put_u8(b_tbs_body, 1);
        core::put_u8(b_tbs_body, 0x42);
        // signature (AlgorithmIdentifier: OID_ED25519)
        core::put_u8(b_tbs_body, 0x30);
        core::put_u8(b_tbs_body, 5);
        core::put_u8(b_tbs_body, 0x06);
        core::put_u8(b_tbs_body, 3);
        core::put_bytes(b_tbs_body, "\x2B\x65\x70");
        // issuer (SEQUENCE "ROOT")
        core::put_u8(b_tbs_body, 0x30);
        core::put_u8(b_tbs_body, 6);
        core::put_u8(b_tbs_body, 0x13);
        core::put_u8(b_tbs_body, 4);
        core::put_bytes(b_tbs_body, "ROOT");
        // validity (240101000000Z to 260101000000Z: 1704067200 to 1767225600)
        core::put_u8(b_tbs_body, 0x30);
        core::put_u8(b_tbs_body, 30);
        core::put_u8(b_tbs_body, 0x17);
        core::put_u8(b_tbs_body, 13);
        core::put_bytes(b_tbs_body, "240101000000Z");
        core::put_u8(b_tbs_body, 0x17);
        core::put_u8(b_tbs_body, 13);
        core::put_bytes(b_tbs_body, "260101000000Z");
        // subject (SEQUENCE "LEAF")
        core::put_u8(b_tbs_body, 0x30);
        core::put_u8(b_tbs_body, 6);
        core::put_u8(b_tbs_body, 0x13);
        core::put_u8(b_tbs_body, 4);
        core::put_bytes(b_tbs_body, "LEAF");
        // SPKI
        core::put_u8(b_tbs_body, 0x30);
        core::put_u8(b_tbs_body, 42);
        core::put_u8(b_tbs_body, 0x30);
        core::put_u8(b_tbs_body, 5);
        core::put_u8(b_tbs_body, 0x06);
        core::put_u8(b_tbs_body, 3);
        core::put_bytes(b_tbs_body, "\x2B\x65\x70");
        core::put_u8(b_tbs_body, 0x03);
        core::put_u8(b_tbs_body, 33);
        core::put_u8(b_tbs_body, 0x00);
        core::put_bytes(b_tbs_body, leaf_kp.public_key[..]);

        // Wrap in TBSCertificate SEQUENCE
        var b_tbs_full = core::builder_init();
        core::put_u8(b_tbs_full, 0x30);
        core::put_u8(b_tbs_full, b_tbs_body.buf.len as u8);
        core::put_bytes(b_tbs_full, b_tbs_body.buf[..]);

        // Compute Ed25519 signature over TBSCertificate DER
        let leaf_sig = core::ed25519_sign(root_kp.seed, b_tbs_full.buf[..]);

        // Build outer Certificate SEQUENCE
        var b_cert_inner = core::builder_init();
        core::put_bytes(b_cert_inner, b_tbs_full.buf[..]);
        // outer signatureAlgorithm
        core::put_u8(b_cert_inner, 0x30);
        core::put_u8(b_cert_inner, 5);
        core::put_u8(b_cert_inner, 0x06);
        core::put_u8(b_cert_inner, 3);
        core::put_bytes(b_cert_inner, "\x2B\x65\x70");
        // outer signatureValue (BIT STRING: len 65 = 1 unused bits octet + 64 sig bytes)
        core::put_u8(b_cert_inner, 0x03);
        core::put_u8(b_cert_inner, 65);
        core::put_u8(b_cert_inner, 0x00);
        core::put_bytes(b_cert_inner, leaf_sig[..]);

        var b_leaf_cert = core::builder_init();
        core::put_u8(b_leaf_cert, 0x30);
        core::put_u8(b_leaf_cert, 0x81);
        core::put_u8(b_leaf_cert, b_cert_inner.buf.len as u8);
        core::put_bytes(b_leaf_cert, b_cert_inner.buf[..]);

        // Parse leaf certificate with zero-copy DER parser
        var parsed_leaf = wing::ParsedCert { .. };
        let ok_parse = wing::parse_x509_certificate(b_leaf_cert.buf[..], parsed_leaf);
        sub.assert_true(ok_parse, "Leaf certificate successfully parsed by parse_x509_certificate");
        sub.assert_eq(parsed_leaf.signature_value.length as i64, 64, "Extracted 64-byte signatureValue");
        sub.assert_eq(parsed_leaf.tbs_cert.length as i64, b_tbs_full.buf.len, "TBSCertificate span matches signed data");

        // Construct Root CA ParsedCert
        let leaf_issuer = wing::span_slice(b_leaf_cert.buf[..], parsed_leaf.issuer_raw);
        var raw_root: u8[>..] = [];
        raw_root.append(leaf_issuer);
        raw_root.append(root_kp.public_key[..]);

        var parsed_root = wing::ParsedCert {
            raw_len:               raw_root.len as u32,
            tbs_cert:              wing::Span16 { offset: 0, length: raw_root.len as u16 },
            serial_number:         wing::Span16 { offset: 0, length: 1 },
            sig_alg_oid:           wing::Span16 { offset: 0, length: 1 },
            issuer_raw:            wing::Span16 { offset: 0, length: leaf_issuer.len as u16 },
            validity_not_before:   1704067200,
            validity_not_after:    1767225600,
            subject_raw:           wing::Span16 { offset: 0, length: leaf_issuer.len as u16 },
            spki_raw:              wing::Span16 { offset: leaf_issuer.len as u16, length: 32 },
            spki_pubkey:           wing::Span16 { offset: leaf_issuer.len as u16, length: 32 },
            extensions_raw:        wing::Span16 { offset: 0, length: 0 },
            is_ca:                 true,
            has_basic_constraints: true,
            path_len_constraint:   -1,
            key_usage:             rfc::KEY_USAGE_KEY_CERT_SIGN,
            has_key_usage:         true,
        };

        var store = wing::TrustAnchorStore { anchors: [] };
        sub.assert_true(wing::add_trust_anchor(store, leaf_issuer, root_kp.public_key[..]), "Root trust anchor added");

        var chain: wing::ParsedCert[..8] = [];
        chain.push(parsed_leaf);
        chain.push(parsed_root);

        var raw_chain: const u8[:][..8] = [];
        raw_chain.push(b_leaf_cert.buf[..]);
        raw_chain.push(raw_root[..]);

        // Verify chain with valid timestamp (2025-01-01 -> 1735689600)
        let alert_ok = wing::verify_certificate_chain(chain, raw_chain, store, 1735689600);
        sub.assert_eq(wing::tls_alert_to_u8(alert_ok), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "Valid Ed25519 signature chain verified");

        // Tamper test: corrupt 1 byte of the leaf certificate signature
        var tampered_cert: u8[>..] = [];
        tampered_cert.append(b_leaf_cert.buf[..]);
        let sig_pos = (parsed_leaf.signature_value.offset as i64) + 10;
        tampered_cert[sig_pos] ^= 0x01;

        var tampered_raw_chain: const u8[:][..8] = [];
        tampered_raw_chain.push(tampered_cert[..]);
        tampered_raw_chain.push(raw_root[..]);

        let alert_tampered = wing::verify_certificate_chain(chain, tampered_raw_chain, store, 1735689600);
        sub.assert_eq(wing::tls_alert_to_u8(alert_tampered), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "Tampered signature rejected with BadCertificate");
    };
}

// 8. Hybrid Post-Quantum Key Agreement (RFC 10024 & FIPS 203)
fn test_post_quantum_hybrid_exchange(t: lit::T&) {
    t.run("TLS-25: Hybrid Key Share Entry Framing & Smuggling Defense") { sub =>
        var client_share = internal::PostQuantumKeyShare {
            group: rfc::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { client_share.x25519_public[i] = (i + 1) as u8; }
        for i in 1152 { client_share.mlkem768_public[i] = ((i * 3 + 1) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        client_share.format_hybrid_key_share(wire);
        sub.assert_eq(wire.len, 1188, "Client KeyShareEntry wire length is 1188 bytes");

        var parsed = internal::PostQuantumKeyShare { .. };
        let ok_parse = parsed.parse_hybrid_key_share(wire[..]);
        sub.assert_true(ok_parse, "Client hybrid key share parsed");
        sub.assert_bytes_eq(wire[4..1156], client_share.mlkem768_public[..], "0x11EC wire starts with ML-KEM-768 public key (PQ || Classical)");
        sub.assert_bytes_eq(wire[1156..1188], client_share.x25519_public[..], "0x11EC wire ends with X25519 public key");

        // Draft 0x6399 (Classical || PQ) ordering verification
        var draft_share = internal::PostQuantumKeyShare {
            group: rfc::GROUP_X25519_KYBER768_DRAFT00,
            ..
        };
        for i in 32 { draft_share.x25519_public[i] = (i + 1) as u8; }
        for i in 1152 { draft_share.mlkem768_public[i] = ((i * 3 + 1) & 0xFF) as u8; }
        var draft_wire: u8[>..] = [];
        draft_share.format_hybrid_key_share(draft_wire);
        sub.assert_eq(draft_wire.len, 1188, "Draft 0x6399 wire length 1188");
        sub.assert_bytes_eq(draft_wire[4..36], draft_share.x25519_public[..], "0x6399 starts with X25519 (Classical || PQ)");
        sub.assert_bytes_eq(draft_wire[36..1188], draft_share.mlkem768_public[..], "0x6399 ends with PQ key");
        var parsed_draft = internal::PostQuantumKeyShare { .. };
        sub.assert_true(parsed_draft.parse_hybrid_key_share(draft_wire[..]), "Draft share parsed");
        sub.assert_eq(parsed_draft.group, rfc::GROUP_X25519_KYBER768_DRAFT00, "Draft group preserved");
        sub.assert_bytes_eq(parsed_draft.x25519_public[..], draft_share.x25519_public[..], "Draft x25519 matches");

        // Smuggling attempt: Appending trailing unparsed bytes to KeyShareEntry must fail
        var smuggled_wire: u8[>..] = [];
        smuggled_wire.append(wire[..]);
        smuggled_wire.push(0xCC); // 1 extra byte
        var bad_client = internal::PostQuantumKeyShare { .. };
        sub.assert_false(bad_client.parse_hybrid_key_share(smuggled_wire[..]), "rejects KeyShareEntry with trailing smuggled bytes");

        // Server Share framing test
        var server_share = internal::PostQuantumServerShare {
            group: rfc::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { server_share.x25519_public[i] = (i + 7) as u8; }
        for i in 1088 { server_share.mlkem768_ciphertext[i] = ((i * 5 + 3) & 0xFF) as u8; }

        var server_wire: u8[>..] = [];
        server_share.format_hybrid_server_key_share(server_wire);
        sub.assert_eq(server_wire.len, 1124, "Server KeyShareEntry wire length is 1124 bytes");

        var parsed_server = internal::PostQuantumServerShare { .. };
        sub.assert_true(parsed_server.parse_hybrid_server_key_share(server_wire[..]), "Server share parsed");
        sub.assert_bytes_eq(server_wire[4..1092], server_share.mlkem768_ciphertext[..], "0x11EC server wire starts with ML-KEM-768 ciphertext (PQ || Classical)");
        sub.assert_bytes_eq(server_wire[1092..1124], server_share.x25519_public[..], "0x11EC server wire ends with X25519 public key");

        var smuggled_server: u8[>..] = [];
        smuggled_server.append(server_wire[..]);
        smuggled_server.push(0xDD);
        var bad_server = internal::PostQuantumServerShare { .. };
        sub.assert_false(bad_server.parse_hybrid_server_key_share(smuggled_server[..]), "rejects server share with trailing smuggled bytes");
    };

    t.run("TLS-26: Hybrid Shared Secret Combiner & All-Zero Contributory Defense") { sub =>
        let classical_ss: u8[32] = [0x11; 32];
        let pq_ss:        u8[32] = [0x22; 32];
        var out_secret: u8[32] = [0; 32];

        // Valid derivation succeeds
        let ok_comb = internal::derive_hybrid_shared_secret_checked(classical_ss[..], pq_ss[..], out_secret[..]);
        sub.assert_true(ok_comb, "valid hybrid shared secret derived");

        var out_x25519_mlkem: u8[32] = [0; 32];
        let ok_mlkem_comb = internal::derive_x25519_mlkem768_shared_secret_checked(classical_ss[..], pq_ss[..], out_x25519_mlkem[..]);
        sub.assert_true(ok_mlkem_comb, "valid x25519_mlkem768 shared secret derived (PQ || Classical)");
        let direct_sec = internal::derive_x25519_mlkem768_shared_secret(classical_ss, pq_ss);
        sub.assert_bytes_eq(out_x25519_mlkem[..], direct_sec[..], "direct derivation matches checked");

        // Contributory attack defense: all-zero classical X25519 secret rejected (RFC 7748 §6.1)
        let zero_classical: u8[32] = [0x00; 32];
        let ok_bad_classical = internal::derive_hybrid_shared_secret_checked(zero_classical[..], pq_ss[..], out_secret[..]);
        sub.assert_false(ok_bad_classical, "rejects all-zero classical ECDH shared secret");

        // Degenerate ML-KEM secret: all-zero PQ secret rejected
        let zero_pq: u8[32] = [0x00; 32];
        let ok_bad_pq = internal::derive_hybrid_shared_secret_checked(classical_ss[..], zero_pq[..], out_secret[..]);
        sub.assert_false(ok_bad_pq, "rejects all-zero post-quantum shared secret");

        // Short classical or PQ slice rejected
        let ok_short = internal::derive_hybrid_shared_secret_checked(classical_ss[..16], pq_ss[..], out_secret[..]);
        sub.assert_false(ok_short, "rejects truncated classical shared secret slice");
    };

    t.run("TLS-35: Post-Quantum ML-KEM-768 Decapsulation & FIPS 203 Implicit Rejection") { sub =>
        var sk = internal::MLKEM768PrivateKey { .. };
        // Implicit rejection seed z (32 bytes)
        for i in 32 { sk.z[i] = (i + 0x41) as u8; }
        // Private key (mock 1152 bytes)
        for i in 1152 { sk.private_key[i] = ((i * 13 + 5) & 0xFF) as u8; }
        for i in 1152 { sk.public_key[i] = ((i * 7 + 1) & 0xFF) as u8; }

        // 1. Valid ciphertext decapsulation
        var valid_ct: u8[1088] = [0xAA; 1088];
        var ss_valid: u8[32]   = [0; 32];
        let is_rej_valid, ok_valid = internal::mlkem768_decapsulate_with_implicit_rejection(sk, valid_ct[..], ss_valid[..]);
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
        var ss_zero: u8[32]   = [0; 32];
        let is_rej_zero, ok_zero = internal::mlkem768_decapsulate_with_implicit_rejection(sk, zero_ct[..], ss_zero[..]);
        sub.assert_true(ok_zero, "all-zero ciphertext decapsulation succeeds via implicit rejection");
        sub.assert_true(is_rej_zero, "all-zero ciphertext triggers implicit rejection");

        // Verify that the implicit rejection key matches K_bar = HMAC-SHA256(z, c)
        var expected_k_bar: u8[32] = [0; 32];
        let ok_k_bar = internal::mlkem768_compute_implicit_rejection(sk.z, zero_ct[..], expected_k_bar[..]);
        sub.assert_true(ok_k_bar, "expected k_bar computed");
        sub.assert_bytes_eq(ss_zero[..], expected_k_bar[..], "implicit rejection key matches FIPS 203 derivation from seed z");

        // Determinism: decapsulating with same corrupt ciphertext produces identical shared key
        var ss_zero_again: u8[32] = [0; 32];
        internal::mlkem768_decapsulate_with_implicit_rejection(sk, zero_ct[..], ss_zero_again[..]);
        sub.assert_bytes_eq(ss_zero[..], ss_zero_again[..], "implicit rejection is deterministic");

        // 3. Different rejection seed z produces different implicit rejection key
        var sk2 = sk;
        sk2.z[0] ^= 0xFF;
        var ss_diff_z: u8[32] = [0; 32];
        internal::mlkem768_decapsulate_with_implicit_rejection(sk2, zero_ct[..], ss_diff_z[..]);
        var diff_z_matches = true;
        for i in 32 {
            if ss_diff_z[i] != ss_zero[i] { diff_z_matches = false; break; }
        }
        sub.assert_false(diff_z_matches, "different seed z produces distinct implicit rejection key");

        // 4. Truncated ciphertext (< 1088 bytes) rejected safely without panic or hang
        let short_ct: u8[500] = [0xAA; 500];
        var ss_short: u8[32] = [0; 32];
        let _, ok_short = internal::mlkem768_decapsulate_with_implicit_rejection(sk, short_ct[..], ss_short[..]);
        sub.assert_false(ok_short, "truncated ciphertext fails safely");

        // 5. Short destination buffer (< 32 bytes) rejected safely
        var ss_tiny: u8[16] = [0; 16];
        let _, ok_tiny = internal::mlkem768_decapsulate_with_implicit_rejection(sk, valid_ct[..], ss_tiny[..]);
        sub.assert_false(ok_tiny, "short output buffer fails safely");
    };

    t.run("TLS-42: RFC 10024 Traditional Post-Quantum Hybrids (SecP256r1MLKEM768 & SecP384r1MLKEM1024)") { sub =>
        // RFC 10024 Section 4: Negotiated Groups - Post-Quantum Traditional Hybrid NamedGroup Identifiers
        sub.assert_eq(rfc::GROUP_SECP256R1_MLKEM768, 0x11EB, "SecP256r1MLKEM768 is 0x11EB");
        sub.assert_eq(rfc::GROUP_X25519_MLKEM768, 0x11EC, "X25519MLKEM768 is 0x11EC");
        sub.assert_eq(rfc::GROUP_SECP384R1_MLKEM1024, 0x11ED, "SecP384r1MLKEM1024 is 0x11ED");

        // NamedGroup recognition
        sub.assert_true(rfc::is_post_quantum_group(rfc::GROUP_SECP256R1_MLKEM768), "0x11EB is PQ group");
        sub.assert_true(rfc::is_post_quantum_group(rfc::GROUP_SECP384R1_MLKEM1024), "0x11ED is PQ group");
        sub.assert_true(rfc::is_post_quantum_group(rfc::GROUP_X25519_MLKEM768), "0x11EC is PQ group");
        sub.assert_false(rfc::is_post_quantum_group(0x0017), "0x0017 (secp256r1 classical) is not PQ");
        sub.assert_false(rfc::is_post_quantum_group(0x0018), "0x0018 (secp384r1 classical) is not PQ");
        sub.assert_false(rfc::is_post_quantum_group(0x001D), "0x001D (x25519 classical) is not PQ");

        // Key share wire lengths (RFC 10024 Section 3)
        sub.assert_eq(rfc::SECP256R1_POINT_LEN, 65, "P-256 uncompressed point is 65 bytes");
        sub.assert_eq(rfc::SECP384R1_POINT_LEN, 97, "P-384 uncompressed point is 97 bytes");
        sub.assert_eq(rfc::MLKEM768_PUBLIC_LEN, 1152, "ML-KEM-768 public key is 1152 bytes");
        sub.assert_eq(rfc::MLKEM768_CIPHERTEXT_LEN, 1088, "ML-KEM-768 ciphertext is 1088 bytes");
        sub.assert_eq(rfc::MLKEM1024_PUBLIC_LEN, 1568, "ML-KEM-1024 public key is 1568 bytes");
        sub.assert_eq(rfc::MLKEM1024_CIPHERTEXT_LEN, 1568, "ML-KEM-1024 ciphertext is 1568 bytes");

        sub.assert_eq(internal::pq_hybrid_client_share_len(0x11EB), 1217, "SecP256r1+ML-KEM-768 client share 1217B");
        sub.assert_eq(internal::pq_hybrid_server_share_len(0x11EB), 1153, "SecP256r1+ML-KEM-768 server share 1153B");
        sub.assert_eq(internal::pq_hybrid_client_share_len(0x11ED), 1665, "SecP384r1+ML-KEM-1024 client share 1665B");
        sub.assert_eq(internal::pq_hybrid_server_share_len(0x11ED), 1665, "SecP384r1+ML-KEM-1024 server share 1665B");

        // SecP256r1MLKEM768 (0x11EB) Codecs
        var client_share = internal::SecP256r1MLKEM768KeyShare { .. };
        client_share.secp256r1_public[0] = 0x04;
        for i in 64 { client_share.secp256r1_public[1 + i] = ((i * 5 + 3) & 0xFF) as u8; }
        for i in 1152 { client_share.mlkem768_public[i] = ((i * 7 + 1) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        internal::format_secp256r1_mlkem768_key_share(client_share, wire);
        sub.assert_eq(wire.len, 4 + 1217, "Client key share wire length is exactly 1221 bytes");

        var parsed_client = internal::SecP256r1MLKEM768KeyShare { .. };
        let ok_parse = internal::parse_secp256r1_mlkem768_key_share(parsed_client, wire[..]);
        sub.assert_true(ok_parse, "Client key share parsed successfully");
        sub.assert_eq(parsed_client.group, rfc::GROUP_SECP256R1_MLKEM768, "Group is 0x11EB");
        sub.assert_bytes_eq(parsed_client.secp256r1_public[..], client_share.secp256r1_public[..], "P-256 point matches");

        var bad_client = internal::SecP256r1MLKEM768KeyShare { .. };
        sub.assert_false(internal::parse_secp256r1_mlkem768_key_share(bad_client, wire[..1000]), "Truncated client share fails");

        // SecP384r1MLKEM1024 (0x11ED) Codecs
        var client_384 = internal::SecP384r1MLKEM1024KeyShare { .. };
        client_384.secp384r1_public[0] = 0x04;
        for i in 96 { client_384.secp384r1_public[1 + i] = ((i * 3 + 7) & 0xFF) as u8; }
        for i in 1568 { client_384.mlkem1024_public[i] = ((i * 11 + 3) & 0xFF) as u8; }

        var wire_384: u8[>..] = [];
        internal::format_secp384r1_mlkem1024_key_share(client_384, wire_384);
        sub.assert_eq(wire_384.len, 4 + 1665, "SecP384r1 client wire length is 1669 bytes");

        var parsed_384 = internal::SecP384r1MLKEM1024KeyShare { .. };
        let ok_p384 = internal::parse_secp384r1_mlkem1024_key_share(parsed_384, wire_384[..]);
        sub.assert_true(ok_p384, "SecP384r1 client share parsed");
        sub.assert_eq(parsed_384.group, rfc::GROUP_SECP384R1_MLKEM1024, "Group is 0x11ED");

        // Extension wiring & secret combiners
        let groups: u16[3] = [
            rfc::GROUP_SECP256R1_MLKEM768,
            rfc::GROUP_X25519_MLKEM768,
            rfc::GROUP_SECP384R1_MLKEM1024,
        ];
        var ext_wire: u8[>..] = [];
        wing::encode_supported_groups_extension(ext_wire, groups[..]);
        sub.assert_eq(ext_wire.len, 2 + 2 + 2 + 6, "Supported groups wire length");

        var parsed_groups: u16[..32] = [];
        let ok_sg = wing::parse_supported_groups_extension(ext_wire[4..], parsed_groups);
        sub.assert_true(ok_sg, "Parsed supported groups");
        sub.assert_eq(parsed_groups.len, 3, "Parsed 3 groups");

        var ecdh256: u8[32] = [0; 32];
        for i in 32 { ecdh256[i] = (i + 1) as u8; }
        var pq_ss: u8[32] = [0; 32];
        for i in 32 { pq_ss[i] = (i + 33) as u8; }
        let ss256 = internal::derive_secp256r1_mlkem768_shared_secret(ecdh256, pq_ss);
        var nz_cnt = 0;
        for b in ss256 { if b != 0 { nz_cnt += 1; } }
        sub.assert_gt(nz_cnt, 28, "Combined SecP256r1 shared secret has high entropy");
    };
}

// 8. Handshake Extension Bounds, Supported Versions, ECH & Anti-Splitting Conformance
fn test_handshake_and_ech_security(t: lit::T&) {
    t.run("TLS-25: RFC 8446 §4.2 Duplicate Extension Rejection & Block Bounds") { sub =>
        // 1. Construct valid extensions block with distinct extension IDs
        var b_valid = core::builder_init();
        core::start_u16_prefix(b_valid); // block len

        // Extension 1: EXT_SERVER_NAME (0)
        core::put_u16(b_valid, rfc::TLS_EXT_SERVER_NAME);
        core::start_u16_prefix(b_valid);
        core::put_bytes(b_valid, "mock_sni");
        core::finish_u16_prefix(b_valid);

        // Extension 2: EXT_SUPPORTED_VERSIONS (43)
        core::put_u16(b_valid, rfc::TLS_EXT_SUPPORTED_VERSIONS);
        core::start_u16_prefix(b_valid);
        core::put_bytes(b_valid, "mock_ver");
        core::finish_u16_prefix(b_valid);

        core::finish_u16_prefix(b_valid);

        var entries: wing::TlsExtensionEntry[..32] = [];
        let ok_val = wing::parse_extensions_block(b_valid.buf[..], entries);
        sub.assert_true(ok_val, "distinct extensions parsed successfully");
        sub.assert_eq(entries.len, 2, "2 extensions parsed");

        // 2. Duplicate extension attack (RFC 8446 §4.2 violation)
        var b_dup = core::builder_init();
        core::start_u16_prefix(b_dup);

        core::put_u16(b_dup, rfc::TLS_EXT_SERVER_NAME);
        core::start_u16_prefix(b_dup);
        core::put_bytes(b_dup, "mock_sni_1");
        core::finish_u16_prefix(b_dup);

        core::put_u16(b_dup, rfc::TLS_EXT_SERVER_NAME); // DUPLICATE!
        core::start_u16_prefix(b_dup);
        core::put_bytes(b_dup, "mock_sni_2");
        core::finish_u16_prefix(b_dup);

        core::finish_u16_prefix(b_dup);

        var entries_dup: wing::TlsExtensionEntry[..32] = [];
        let ok_dup = wing::parse_extensions_block(b_dup.buf[..], entries_dup);
        sub.assert_false(ok_dup, "duplicate extension MUST be strictly rejected per RFC 8446 Section 4.2");

        // 3. Trailing garbage after extensions block
        var b_trail = core::builder_init();
        core::put_bytes(b_trail, b_valid.buf[..]);
        core::put_u8(b_trail, 0xFF); // trailing unparsed byte
        var entries_trail: wing::TlsExtensionEntry[..32] = [];
        let ok_trail = wing::parse_extensions_block(b_trail.buf[..], entries_trail);
        sub.assert_false(ok_trail, "trailing garbage after extensions block rejected");
    };

    t.run("TLS-26: RFC 6066 SNI Strict Boundary, Duplicate HostName & Dot Format Invariants") { sub =>
        // 1. Duplicate host_name in single ServerNameList (RFC 6066 §3 violation)
        var b_dup = core::builder_init();
        core::start_u16_prefix(b_dup); // list
        // Name 1
        core::put_u8(b_dup, 0); // host_name
        core::start_u16_prefix(b_dup);
        core::put_bytes(b_dup, "a.example.com");
        core::finish_u16_prefix(b_dup);
        // Name 2 (duplicate host_name!)
        core::put_u8(b_dup, 0); // host_name
        core::start_u16_prefix(b_dup);
        core::put_bytes(b_dup, "b.example.com");
        core::finish_u16_prefix(b_dup);
        core::finish_u16_prefix(b_dup);

        var sni_out: u8[..255] = [];
        let ok_dup = wing::parse_sni_extension(b_dup.buf[..], sni_out);
        sub.assert_false(ok_dup, "duplicate host_name in ServerNameList strictly rejected");

        // 2. Empty ServerNameList (RFC 6066 §3 server_name_list<1..2^16-1>)
        var b_empty = core::builder_init();
        core::start_u16_prefix(b_empty);
        core::finish_u16_prefix(b_empty); // length 0
        let ok_empty = wing::parse_sni_extension(b_empty.buf[..], sni_out);
        sub.assert_false(ok_empty, "empty ServerNameList strictly rejected");

        // 3. Trailing dot in host_name ("example.com.")
        var b_dot = core::builder_init();
        core::start_u16_prefix(b_dot);
        core::put_u8(b_dot, 0);
        core::start_u16_prefix(b_dot);
        core::put_bytes(b_dot, "example.com.");
        core::finish_u16_prefix(b_dot);
        core::finish_u16_prefix(b_dot);
        let ok_dot = wing::parse_sni_extension(b_dot.buf[..], sni_out);
        sub.assert_false(ok_dot, "trailing dot in SNI rejected per RFC 6066");

        // 4. Leading dot in host_name (".example.com")
        var b_ldot = core::builder_init();
        core::start_u16_prefix(b_ldot);
        core::put_u8(b_ldot, 0);
        core::start_u16_prefix(b_ldot);
        core::put_bytes(b_ldot, ".example.com");
        core::finish_u16_prefix(b_ldot);
        core::finish_u16_prefix(b_ldot);
        let ok_ldot = wing::parse_sni_extension(b_ldot.buf[..], sni_out);
        sub.assert_false(ok_ldot, "leading dot in SNI rejected");

        // 5. Consecutive dots in host_name ("foo..bar.com")
        var b_cdots = core::builder_init();
        core::start_u16_prefix(b_cdots);
        core::put_u8(b_cdots, 0);
        core::start_u16_prefix(b_cdots);
        core::put_bytes(b_cdots, "foo..bar.com");
        core::finish_u16_prefix(b_cdots);
        core::finish_u16_prefix(b_cdots);
        let ok_cdots = wing::parse_sni_extension(b_cdots.buf[..], sni_out);
        sub.assert_false(ok_cdots, "consecutive dots in SNI rejected");

        // 6. Trailing garbage in extension_data after server_name_list
        var b_trail = core::builder_init();
        core::start_u16_prefix(b_trail);
        core::put_u8(b_trail, 0);
        core::start_u16_prefix(b_trail);
        core::put_bytes(b_trail, "example.com");
        core::finish_u16_prefix(b_trail);
        core::finish_u16_prefix(b_trail);
        core::put_u8(b_trail, 0xEE); // trailing unparsed byte
        let ok_trail = wing::parse_sni_extension(b_trail.buf[..], sni_out);
        sub.assert_false(ok_trail, "trailing garbage in SNI extension rejected");
    };

    t.run("TLS-27: RFC 7301 ALPN Empty List, Zero-Length Name & Trailing Garbage Defenses") { sub =>
        // 1. Empty ProtocolNameList (length 0, RFC 7301 §3.1 violation)
        var b_empty = core::builder_init();
        core::start_u16_prefix(b_empty);
        core::finish_u16_prefix(b_empty); // len 0
        sub.assert_false(wing::validate_alpn_extension(b_empty.buf[..]), "empty ALPN list rejected by validator");
        let neg_empty = wing::negotiate_alpn(b_empty.buf[..], false);
        sub.assert_true(neg_empty == wing::NegotiatedAlpn.None, "empty ALPN list negotiates None");

        // 2. Protocol name with 0-length (empty string "")
        var b_zlen = core::builder_init();
        core::start_u16_prefix(b_zlen);
        core::start_u8_prefix(b_zlen);
        // 0-length name
        core::finish_u8_prefix(b_zlen);
        core::finish_u16_prefix(b_zlen);
        sub.assert_false(wing::validate_alpn_extension(b_zlen.buf[..]), "0-length protocol name rejected");
        let neg_zlen = wing::negotiate_alpn(b_zlen.buf[..], false);
        sub.assert_true(neg_zlen == wing::NegotiatedAlpn.None, "0-length protocol name negotiates None");

        // 3. Trailing garbage in ALPN extension
        var b_valid = core::builder_init();
        core::start_u16_prefix(b_valid);
        core::start_u8_prefix(b_valid);
        core::put_bytes(b_valid, "h2");
        core::finish_u8_prefix(b_valid);
        core::finish_u16_prefix(b_valid);
        core::put_u8(b_valid, 0x99); // trailing garbage
        sub.assert_false(wing::validate_alpn_extension(b_valid.buf[..]), "trailing bytes in ALPN rejected");
        let neg_trail = wing::negotiate_alpn(b_valid.buf[..], false);
        sub.assert_true(neg_trail == wing::NegotiatedAlpn.None, "trailing bytes in ALPN negotiates None");
    };

    t.run("TLS-28: RFC 8446 Supported Versions Validation & Strict TLS 1.3 Negotiation") { sub =>
        // 1. ClientHello offering TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
        var b_ch = core::builder_init();
        core::start_u8_prefix(b_ch); // 1-byte length prefix
        core::put_u16(b_ch, 0x0304); // TLS 1.3
        core::put_u16(b_ch, 0x0303); // TLS 1.2
        core::finish_u8_prefix(b_ch);

        let has_tls13, ok_ch = wing::parse_client_supported_versions(b_ch.buf[..]);
        sub.assert_true(ok_ch, "ClientHello supported_versions parsed");
        sub.assert_true(has_tls13, "TLS 1.3 supported");

        // 2. ClientHello offering only legacy versions (0x0303 TLS 1.2, 0x0301 TLS 1.0)
        var b_legacy = core::builder_init();
        core::start_u8_prefix(b_legacy);
        core::put_u16(b_legacy, 0x0303);
        core::put_u16(b_legacy, 0x0301);
        core::finish_u8_prefix(b_legacy);

        let has_tls13_leg, ok_leg = wing::parse_client_supported_versions(b_legacy.buf[..]);
        sub.assert_true(ok_leg, "legacy list parses");
        sub.assert_false(has_tls13_leg, "TLS 1.3 NOT supported in legacy-only ClientHello");

        // 3. ClientHello odd length (RFC 8446 §4.2.1 violation: each version is 2 bytes)
        var b_odd = core::builder_init();
        core::put_u8(b_odd, 3); // odd length 3
        core::put_u8(b_odd, 0x03);
        core::put_u8(b_odd, 0x04);
        core::put_u8(b_odd, 0x03);
        let _, ok_odd = wing::parse_client_supported_versions(b_odd.buf[..]);
        sub.assert_false(ok_odd, "odd length supported_versions rejected");

        // 4. ClientHello duplicate versions rejected
        var b_dup = core::builder_init();
        core::start_u8_prefix(b_dup);
        core::put_u16(b_dup, 0x0304);
        core::put_u16(b_dup, 0x0304); // duplicate!
        core::finish_u8_prefix(b_dup);
        let _, ok_dup = wing::parse_client_supported_versions(b_dup.buf[..]);
        sub.assert_false(ok_dup, "duplicate version in ClientHello supported_versions rejected");

        // 5. ServerHello valid selection (0x0304 TLS 1.3)
        let sh_valid: u8[2] = [0x03, 0x04];
        let sel_ver, ok_sh = wing::parse_server_supported_versions(sh_valid[..]);
        sub.assert_true(ok_sh, "ServerHello TLS 1.3 accepted");
        sub.assert_eq(sel_ver, 0x0304, "selected version is 0x0304");

        // 6. ServerHello selecting legacy TLS 1.2 (0x0303 downgrade attempt)
        let sh_downgrade: u8[2] = [0x03, 0x03];
        let _, ok_dg = wing::parse_server_supported_versions(sh_downgrade[..]);
        sub.assert_false(ok_dg, "ServerHello TLS 1.2 downgrade strictly rejected");

        // 7. ServerHello length != 2 bytes
        let sh_badlen: u8[3] = [0x03, 0x04, 0x00];
        let _, ok_bl = wing::parse_server_supported_versions(sh_badlen[..]);
        sub.assert_false(ok_bl, "ServerHello supported_versions length != 2 rejected");
    };

    t.run("TLS-29: RFC 8446 §5.1 Handshake Header Length & Record Boundary Verification") { sub =>
        // 1. Handshake header parsing and buffer overflow prevention
        let hs_hdr: u8[4] = [0x01, 0x00, 0x00, 0x05]; // type 1 (CH), len 5
        let _, _, ok_trunc = wing::parse_handshake_header(hs_hdr[..]);
        sub.assert_false(ok_trunc, "handshake header where payload is truncated rejected");

        // 2. Valid handshake message with complete payload
        let hs_msg: u8[9] = [0x01, 0x00, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55];
        let m_type, m_len, ok_msg = wing::parse_handshake_header(hs_msg[..]);
        sub.assert_true(ok_msg, "complete handshake message header accepted");
        sub.assert_eq(m_type, 1, "msg_type is 1");
        sub.assert_eq(m_len, 5, "msg_len is 5");

        // 3. Record boundary validation: record payload len == 9 (4 header + 5 payload)
        let _, _, ok_bnd = wing::validate_handshake_record_boundary(hs_msg[..], 9);
        sub.assert_true(ok_bnd, "record boundary exactly matches message length");

        // Record boundary mismatch (declared 9, record is 8)
        let _, _, ok_mismatch = wing::validate_handshake_record_boundary(hs_msg[..], 8);
        sub.assert_false(ok_mismatch, "record boundary mismatch rejected");

        // 4. Handshake header encoding length check (cannot exceed 2^24 - 1)
        var out_hdr: u8[4] = [0; 4];
        sub.assert_true(wing::encode_handshake_header(1, 1000, out_hdr), "encode valid header length");
        sub.assert_false(wing::encode_handshake_header(1, 16777216, out_hdr), "overflow > 2^24-1 rejected");

        // 5. RFC 8446 Section 5.1: Handshake headers MUST NOT be split across records
        let dummy_ch = "ClientHelloWirePayloadForTestingFragmentationRules1234567890";
        var recs: u8[>..] = [];
        // Attempting to split at byte 2 (splitting 4-byte handshake header)
        sub.assert_false(wing::fragment_client_hello(dummy_ch, 2, recs), "splitting handshake header (< 4 bytes) strictly rejected");
        // Valid split at byte 10 (>= 4 bytes)
        sub.assert_true(wing::fragment_client_hello(dummy_ch, 10, recs), "valid fragmentation >= 4 bytes succeeds");

        // 6. RFC 8446 Section 4: Synthetic message_hash (254 / 0xFE) MUST NEVER appear on wire
        let hs_synth: u8[36] = [
            0xFE, 0x00, 0x00, 0x20, // msg_type 254 (HS_MSG_MESSAGE_HASH), len 32
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let _, _, ok_wire_synth = wing::parse_handshake_header(hs_synth[..]);
        sub.assert_false(ok_wire_synth, "synthetic message_hash (254) on wire strictly rejected in parse_handshake_header");

        let _, _, ok_bnd_synth = wing::validate_handshake_record_boundary(hs_synth[..], 36);
        sub.assert_false(ok_bnd_synth, "synthetic message_hash (254) strictly rejected in validate_handshake_record_boundary");
    };

    t.run("TLS-30: RFC 9849 ECHConfig Parsing, Downgrade Protection & Skipped Versions") { sub =>
        // Helper to build a valid RFC 9849 ECHConfig wire payload
        var b_cfg = core::builder_init();
        core::put_u16(b_cfg, rfc::ECH_VERSION_RFC9849); // version 0xFE0D
        core::start_u16_prefix(b_cfg); // length prefix for contents

        core::put_u8(b_cfg, 0x01); // config_id
        core::put_u16(b_cfg, rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256); // kem_id (0x0020)

        // public_key<1..2^16-1>: 32 bytes
        core::start_u16_prefix(b_cfg);
        for i in 32 { core::put_u8(b_cfg, (i + 1) as u8); }
        core::finish_u16_prefix(b_cfg);

        // cipher_suites<4..2^16-1>: KDF HKDF-SHA256 (0x0001), AEAD AES-128-GCM (0x0001)
        core::start_u16_prefix(b_cfg);
        core::put_u16(b_cfg, rfc::HPKE_KDF_HKDF_SHA256);
        core::put_u16(b_cfg, rfc::HPKE_AEAD_AES_128_GCM);
        core::finish_u16_prefix(b_cfg);

        core::put_u8(b_cfg, 64); // maximum_name_length

        // public_name: "public.cloudflare.com"
        core::start_u8_prefix(b_cfg);
        core::put_bytes(b_cfg, "public.cloudflare.com");
        core::finish_u8_prefix(b_cfg);

        // extensions: 0 length
        core::start_u16_prefix(b_cfg);
        core::finish_u16_prefix(b_cfg);

        core::finish_u16_prefix(b_cfg); // end contents

        // 1. Parsing genuine ECHConfig succeeds
        var cfg = wing::EchConfig { .. };
        let ok_cfg = wing::parse_ech_config(b_cfg.buf[..], cfg);
        sub.assert_true(ok_cfg, "valid RFC 9849 ECHConfig parsed");
        sub.assert_eq(cfg.version, rfc::ECH_VERSION_RFC9849, "version is 0xFE0D");
        sub.assert_eq(cfg.config_id, 0x01, "config_id is 1");
        sub.assert_eq(cfg.cipher_suites.len, 1, "1 cipher suite parsed");
        sub.assert_bytes_eq(cfg.public_name[..], "public.cloudflare.com", "public_name matches");

        // 2. Unsupported ECH version (e.g. 0xFE0C or 0x0001) in parse_ech_config rejected
        var b_badver = core::builder_init();
        core::put_bytes(b_badver, b_cfg.buf[..]);
        b_badver.buf[0] = 0xFE;
        b_badver.buf[1] = 0x0C; // unsupported version
        var cfg_bad = wing::EchConfig { .. };
        let ok_badver = wing::parse_ech_config(b_badver.buf[..], cfg_bad);
        sub.assert_false(ok_badver, "unsupported ECHConfig version strictly rejected in parse_ech_config");

        // 3. ECHConfig with empty public_name (RFC 9849 public_name<1..255>) rejected
        var b_emptypub = core::builder_init();
        core::put_u16(b_emptypub, rfc::ECH_VERSION_RFC9849);
        core::start_u16_prefix(b_emptypub);
        core::put_u8(b_emptypub, 0x01);
        core::put_u16(b_emptypub, rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256);
        core::start_u16_prefix(b_emptypub);
        for i in 32 { core::put_u8(b_emptypub, 0x11); }
        core::finish_u16_prefix(b_emptypub);
        core::start_u16_prefix(b_emptypub);
        core::put_u16(b_emptypub, rfc::HPKE_KDF_HKDF_SHA256);
        core::put_u16(b_emptypub, rfc::HPKE_AEAD_AES_128_GCM);
        core::finish_u16_prefix(b_emptypub);
        core::put_u8(b_emptypub, 64);
        core::put_u8(b_emptypub, 0); // 0-length public_name!
        core::start_u16_prefix(b_emptypub);
        core::finish_u16_prefix(b_emptypub);
        core::finish_u16_prefix(b_emptypub);

        let ok_emptypub = wing::parse_ech_config(b_emptypub.buf[..], cfg_bad);
        sub.assert_false(ok_emptypub, "empty public_name in ECHConfig rejected");

        // 4. ECHConfig with IP literal public_name rejected
        var b_ippub = core::builder_init();
        core::put_u16(b_ippub, rfc::ECH_VERSION_RFC9849);
        core::start_u16_prefix(b_ippub);
        core::put_u8(b_ippub, 0x01);
        core::put_u16(b_ippub, rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256);
        core::start_u16_prefix(b_ippub);
        for i in 32 { core::put_u8(b_ippub, 0x11); }
        core::finish_u16_prefix(b_ippub);
        core::start_u16_prefix(b_ippub);
        core::put_u16(b_ippub, rfc::HPKE_KDF_HKDF_SHA256);
        core::put_u16(b_ippub, rfc::HPKE_AEAD_AES_128_GCM);
        core::finish_u16_prefix(b_ippub);
        core::put_u8(b_ippub, 64);
        core::start_u8_prefix(b_ippub);
        core::put_bytes(b_ippub, "192.168.1.1"); // IP literal!
        core::finish_u8_prefix(b_ippub);
        core::start_u16_prefix(b_ippub);
        core::finish_u16_prefix(b_ippub);
        core::finish_u16_prefix(b_ippub);

        let ok_ippub = wing::parse_ech_config(b_ippub.buf[..], cfg_bad);
        sub.assert_false(ok_ippub, "IP literal in ECHConfig public_name rejected");

        // 5. ECHConfigList containing an unsupported version entry before an RFC 9849 entry:
        // RFC 9849 §4: Client MUST ignore unsupported versions and successfully parse supported versions.
        var b_list = core::builder_init();
        core::start_u16_prefix(b_list); // list length
        // Entry 1: unsupported version 0x9999 (len 6)
        core::put_u16(b_list, 0x9999);
        core::put_u16(b_list, 6);
        core::put_bytes(b_list, "ignore");
        // Entry 2: valid RFC 9849 config
        core::put_bytes(b_list, b_cfg.buf[..]);
        core::finish_u16_prefix(b_list);

        var cfg_list = wing::EchConfigList { .. };
        let ok_list = wing::parse_ech_config_list(b_list.buf[..], cfg_list);
        sub.assert_true(ok_list, "ECHConfigList with unsupported version skipped and valid entry parsed");
        sub.assert_eq(cfg_list.configs.len, 1, "1 valid config in list");
        sub.assert_eq(cfg_list.configs[0].version, rfc::ECH_VERSION_RFC9849, "parsed entry is RFC 9849");

        // 6. ECHConfigList with truncated trailing bytes rejected
        var b_trunc = core::builder_init();
        core::put_bytes(b_trunc, b_list.buf[..]);
        core::put_u8(b_trunc, 0xAA); // trailing byte after list
        var cfg_list_bad = wing::EchConfigList { .. };
        let ok_trunc_list = wing::parse_ech_config_list(b_trunc.buf[..], cfg_list_bad);
        sub.assert_false(ok_trunc_list, "ECHConfigList with trailing garbage rejected");

        // 7. ECH inner padding bounds
        var padded: u8[..512] = [];
        sub.assert_false(wing::pad_ech_inner("", 64, 10, padded), "empty inner_bytes rejected");
        sub.assert_false(wing::pad_ech_inner("inner", 64, -1, padded), "negative real_sni_len rejected");
        sub.assert_true(wing::pad_ech_inner("inner", 64, 10, padded), "valid padding succeeds");
        sub.assert_eq(padded.len % 32, 0, "padded output is aligned to 32 bytes");
    };
}

// 9. Round 2: State Machine Transitions, HRR Invariants, Downgrade & ECH FSM
fn test_handshake_r2_invariants(t: lit::T&) {
    t.run("TLS-31: RFC 8446 §4 State Machine Transition Desync & Finished Bypass Prevention") { sub =>
        // 1. Finished before Certificate/CertificateVerify in full handshake MUST BE REJECTED
        let st_bad, ok_bad = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitCertCr,
            rfc::TLS_HS_FINISHED,
            wing::HandshakeMode.Full,
            false,
        );
        sub.assert_false(ok_bad, "Finished received before Certificate/CertificateVerify strictly rejected");
        sub.assert_true(st_bad == wing::HsState.Closed, "state is Closed");

        // can_client_transition also rejects Finished before Certificate
        let _, ok_c_fin = wing::can_client_transition(wing::HsState.ClientWaitCertCr, rfc::TLS_HS_FINISHED);
        sub.assert_false(ok_c_fin, "can_client_transition rejects Finished in ClientWaitCertCr");

        // 2. PSK mode allows Finished directly in ClientWaitCertCr -> transitions to Connected
        let st_psk, ok_psk = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitCertCr,
            rfc::TLS_HS_FINISHED,
            wing::HandshakeMode.Psk,
            false,
        );
        sub.assert_true(ok_psk, "PSK mode accepts Finished after EncryptedExtensions");
        sub.assert_true(st_psk == wing::HsState.Connected, "PSK handshake transitions to Connected");

        // 3. EncryptedExtensions outside slot rejected
        let _, ok_ee_sh = wing::validate_client_handshake_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_ENCRYPTED_EXTENSIONS, wing::HandshakeMode.Full, false);
        sub.assert_false(ok_ee_sh, "EE in ClientWaitSH rejected");
        let _, ok_ee_cert = wing::validate_client_handshake_transition(wing::HsState.ClientWaitCert, rfc::TLS_HS_ENCRYPTED_EXTENSIONS, wing::HandshakeMode.Full, false);
        sub.assert_false(ok_ee_cert, "EE in ClientWaitCert rejected");

        // 4. Post-handshake: client sending messages other than KeyUpdate rejected by server
        let _, ok_srv_fin = wing::validate_server_handshake_transition(wing::HsState.Connected, rfc::TLS_HS_FINISHED, false);
        sub.assert_false(ok_srv_fin, "post-handshake Finished rejected by server");
        let _, ok_srv_ch = wing::validate_server_handshake_transition(wing::HsState.Connected, rfc::TLS_HS_CLIENT_HELLO, false);
        sub.assert_false(ok_srv_ch, "post-handshake ClientHello rejected by server");
        let _, ok_srv_ku = wing::validate_server_handshake_transition(wing::HsState.Connected, rfc::TLS_HS_KEY_UPDATE, false);
        sub.assert_true(ok_srv_ku, "post-handshake KeyUpdate accepted by server");

        // 5. Server state machine: client authentication enforcement
        let st_auth, ok_auth = wing::validate_server_handshake_transition(wing::HsState.ServerWaitCH, rfc::TLS_HS_CLIENT_HELLO, true);
        sub.assert_true(ok_auth, "server accepts CH with client auth");
        sub.assert_true(st_auth == wing::HsState.ServerWaitCert, "server transitions to ServerWaitCert when client auth requested");

        // 6. Server state machine: 0-RTT early data acceptance (ServerWaitCH -> ServerWaitEOED)
        let st_0rtt, ok_0rtt = wing::validate_server_handshake_transition(
            wing::HsState.ServerWaitCH,
            rfc::TLS_HS_CLIENT_HELLO,
            false,
            wing::EarlyDataAccepted.Accepted,
        );
        sub.assert_true(ok_0rtt, "server accepts CH with early data accepted");
        sub.assert_true(st_0rtt == wing::HsState.ServerWaitEOED, "server transitions to ServerWaitEOED on early data acceptance");

        let st_eoed, ok_eoed = wing::validate_server_handshake_transition(
            wing::HsState.ServerWaitEOED,
            rfc::TLS_HS_END_OF_EARLY_DATA,
            false,
        );
        sub.assert_true(ok_eoed, "server accepts EndOfEarlyData in ServerWaitEOED");
        sub.assert_true(st_eoed == wing::HsState.ServerWaitFinished, "server transitions to ServerWaitFinished after EOED");
    };

    t.run("TLS-32: RFC 8446 §4.1.4 HelloRetryRequest Single HRR Limit & Transcript message_hash") { sub =>
        // 1. Single HRR limit: first HRR valid, second HRR rejected
        sub.assert_true(wing::validate_hrr_count(0), "first HRR permitted");
        sub.assert_false(wing::validate_hrr_count(1), "second HRR strictly rejected per RFC 8446 Section 4.1.4");
        sub.assert_false(wing::validate_hrr_count(2), "third HRR rejected");

        // 2. Client state transition on HRR: remains waiting for ServerHello2
        let st_hrr, ok_hrr = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitSH,
            rfc::TLS_HS_SERVER_HELLO,
            wing::HandshakeMode.Full,
            true, // is_hrr
        );
        sub.assert_true(ok_hrr, "HRR transition valid");
        sub.assert_true(st_hrr == wing::HsState.ClientWaitSH, "client transitions back to ClientWaitSH waiting for ServerHello2");

        // 3. Transcript synthetic message_hash generation
        let mock_ch1 = "ClientHello1DataForTranscriptCompression123456789";
        var out_synth: u8[36] = [0; 36];
        let synth_len, ok_synth = wing::build_synthetic_message_hash(mock_ch1, 32, out_synth[..]);
        sub.assert_true(ok_synth, "build synthetic message_hash succeeds");
        sub.assert_eq(synth_len, 36, "message_hash length is 36 bytes (4 hdr + 32 sha256)");
        sub.assert_eq(out_synth[0], rfc::TLS_HS_MESSAGE_HASH, "type is 254 (message_hash)");
        sub.assert_eq(out_synth[1], 0x00, "len byte 1 is 0");
        sub.assert_eq(out_synth[2], 0x00, "len byte 2 is 0");
        sub.assert_eq(out_synth[3], 32, "len byte 3 is 32");

        let expected_hash = core::sha256(mock_ch1);
        sub.assert_bytes_eq(out_synth[4..36], expected_hash[..], "synthetic message_hash contains SHA-256(ClientHello1)");

        // 4. RFC 8446 Section 4.4.1: compress_hrr_transcript MUST reject non-TLS 1.3 hash algorithms
        let dummy_md5: u8[16] = [0; 16];
        var out_md5: u8[20] = [0; 20];
        let _, ok_md5 = wing::compress_hrr_transcript(16, dummy_md5[..], out_md5[..]);
        sub.assert_false(ok_md5, "compress_hrr_transcript strictly rejects non-TLS 1.3 hash length (16)");
    };

    t.run("TLS-33: RFC 8446 §4.1.4 HRR Cipher Suite & Selected Group Matching Rules") { sub =>
        // 1. HRR cipher suite matching ServerHello
        sub.assert_true(wing::validate_hrr_cipher_suite(0x1301, 0x1301), "identical cipher suite accepted");
        sub.assert_false(wing::validate_hrr_cipher_suite(0x1301, 0x1302), "cipher suite mismatch strictly rejected");
        sub.assert_false(wing::validate_hrr_cipher_suite(0, 0x1301), "uninitialized HRR cipher suite rejected");

        // 2. HRR selected_group validation:
        // Client supported: X25519 (0x001D), SecP256r1 (0x0017)
        // Client initial key_shares: X25519 (0x001D)
        let supp_groups:    u16[2] = [0x001D, 0x0017];
        let initial_shares: u16[1] = [0x001D];

        // Server requests SecP256r1 (0x0017) -> supported and NOT in initial shares -> VALID!
        sub.assert_true(
            wing::validate_hrr_selected_group(0x0017, supp_groups[..], initial_shares[..]),
            "HRR selecting supported group not in initial shares accepted",
        );

        // Server requests group NOT in client supported_groups (e.g. SecP384r1 0x0018) -> REJECTED!
        sub.assert_false(
            wing::validate_hrr_selected_group(0x0018, supp_groups[..], initial_shares[..]),
            "HRR selecting unsupported group strictly rejected",
        );

        // Server requests group that client ALREADY sent key_share for (X25519 0x001D) -> REJECTED!
        sub.assert_false(
            wing::validate_hrr_selected_group(0x001D, supp_groups[..], initial_shares[..]),
            "HRR selecting group already present in initial key_shares strictly rejected per RFC 8446 Section 4.1.4",
        );
    };

    t.run("TLS-34: RFC 8446 §4.1.3 Downgrade Sentinel Detection in ServerHello.random") { sub =>
        // 1. Legitimate ServerRandom for TLS 1.3
        var s_rand: u8[32] = [0; 32];
        for i in 32 { s_rand[i] = (i + 1) as u8; }
        sub.assert_false(wing::has_downgrade_sentinel(s_rand), "clean random has no sentinel");
        sub.assert_true(
            wing::validate_server_random_downgrade(s_rand, rfc::TLS_VERSION_1_3, true),
            "TLS 1.3 negotiation with clean random valid",
        );

        // 2. Active downgrade attack on TLS 1.3: ServerHello negotiated version is TLS 1.3 but contains sentinel
        var s_rand_dg12 = s_rand;
        for i in 8 { s_rand_dg12[24 + i] = rfc::DOWNGRADE_SENTINEL_TLS12[i]; }
        sub.assert_true(wing::has_downgrade_sentinel(s_rand_dg12), "sentinel TLS 1.2 detected");
        sub.assert_false(
            wing::validate_server_random_downgrade(s_rand_dg12, rfc::TLS_VERSION_1_3, true),
            "downgrade sentinel in TLS 1.3 ServerHello strictly rejected",
        );

        var s_rand_dg11 = s_rand;
        for i in 8 { s_rand_dg11[24 + i] = rfc::DOWNGRADE_SENTINEL_TLS11[i]; }
        sub.assert_true(wing::has_downgrade_sentinel(s_rand_dg11), "sentinel TLS 1.1 detected");
        sub.assert_false(
            wing::validate_server_random_downgrade(s_rand_dg11, rfc::TLS_VERSION_1_3, true),
            "downgrade sentinel 1.1 in TLS 1.3 ServerHello strictly rejected",
        );

        // 3. Downgrade attack detection: TLS 1.3-capable client negotiating TLS 1.2 (0x0303)
        // when server sends downgrade sentinel
        sub.assert_false(
            wing::validate_server_random_downgrade(s_rand_dg12, 0x0303, true),
            "TLS 1.3 client detects active MITM downgrade to TLS 1.2 and aborts",
        );

        // 4. Legitimate TLS 1.2 server (no sentinel) accepted when downgrading
        sub.assert_true(
            wing::validate_server_random_downgrade(s_rand, 0x0303, true),
            "TLS 1.2 server without sentinel accepted",
        );
    };

    t.run("TLS-35: RFC 8446 §4.1.2 & Appendix B.4 TLS 1.3 Cipher Suite Restrictions") { sub =>
        // 1. Supported TLS 1.3 suites
        sub.assert_true(rfc::is_supported_tls13_cipher_suite(0x1301), "rfc::TLS_CIPHER_AES_128_GCM_SHA256 supported");
        sub.assert_true(rfc::is_supported_tls13_cipher_suite(0x1302), "rfc::TLS_CIPHER_AES_256_GCM_SHA384 supported");
        sub.assert_true(rfc::is_supported_tls13_cipher_suite(0x1303), "rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 supported");

        // 2. Legacy TLS 1.2 suites strictly rejected in TLS 1.3
        sub.assert_false(rfc::is_supported_tls13_cipher_suite(0xC02F), "ECDHE-RSA-AES128-GCM-SHA256 forbidden in TLS 1.3");
        sub.assert_false(rfc::is_supported_tls13_cipher_suite(0xC030), "ECDHE-RSA-AES256-GCM-SHA384 forbidden in TLS 1.3");
        sub.assert_false(rfc::is_supported_tls13_cipher_suite(0x009C), "RSA-AES128-GCM forbidden");

        // 3. Negotiation against client-offered list
        let client_ciphers: u16[2] = [0x1301, 0x1303];
        sub.assert_true(wing::validate_server_cipher_suite(0x1301, client_ciphers[..]), "offered suite 0x1301 accepted");
        sub.assert_false(wing::validate_server_cipher_suite(0x1302, client_ciphers[..]), "unoffered suite 0x1302 rejected");
        sub.assert_false(wing::validate_server_cipher_suite(0xC02F, client_ciphers[..]), "legacy suite 0xC02F rejected");
    };

    t.run("TLS-36: RFC 9849 §§5-7 ECH HRR Handling, RetryConfigs & Acceptance Confirmation") { sub =>
        // 1. Acceptance confirmation verification in ServerHello (8 bytes)
        let expected_confirm: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        sub.assert_true(
            wing::verify_ech_acceptance_confirmation(expected_confirm[..], expected_confirm),
            "genuine 8-byte confirmation matches",
        );

        var bad_confirm = expected_confirm;
        bad_confirm[7] ^= 0x01;
        sub.assert_false(
            wing::verify_ech_acceptance_confirmation(bad_confirm[..], expected_confirm),
            "tampered confirmation strictly rejected",
        );

        let short_confirm: u8[4] = [0x11, 0x22, 0x33, 0x44];
        sub.assert_false(
            wing::verify_ech_acceptance_confirmation(short_confirm[..], expected_confirm),
            "truncated confirmation rejected",
        );

        // 2. Validate parse_and_validate_ech_retry_configs
        var b_cfg = core::builder_init();
        core::put_u16(b_cfg, rfc::ECH_VERSION_RFC9849);
        core::start_u16_prefix(b_cfg);
        core::put_u8(b_cfg, 0x02); // config_id
        core::put_u16(b_cfg, rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256);
        core::start_u16_prefix(b_cfg);
        for i in 32 { core::put_u8(b_cfg, 0x22); }
        core::finish_u16_prefix(b_cfg);
        core::start_u16_prefix(b_cfg);
        core::put_u16(b_cfg, rfc::HPKE_KDF_HKDF_SHA256);
        core::put_u16(b_cfg, rfc::HPKE_AEAD_AES_128_GCM);
        core::finish_u16_prefix(b_cfg);
        core::put_u8(b_cfg, 64);
        core::start_u8_prefix(b_cfg);
        core::put_bytes(b_cfg, "retry.cloudflare.com");
        core::finish_u8_prefix(b_cfg);
        core::start_u16_prefix(b_cfg);
        core::finish_u16_prefix(b_cfg);
        core::finish_u16_prefix(b_cfg);

        // Wrap into ECHConfigList
        var b_list = core::builder_init();
        core::start_u16_prefix(b_list);
        core::put_bytes(b_list, b_cfg.buf[..]);
        core::finish_u16_prefix(b_list);

        var out_rc = wing::EchConfigList { .. };
        sub.assert_true(
            wing::parse_and_validate_ech_retry_configs(b_list.buf[..], out_rc),
            "valid ECHConfigList retry_configs parsed",
        );
        sub.assert_eq(out_rc.configs.len, 1, "1 retry config parsed");

        // Corrupted retry_configs rejected
        let corrupted_rc: u8[6] = [0x00, 0x04, 0xFE, 0x0D, 0xAA, 0xBB];
        sub.assert_false(
            wing::parse_and_validate_ech_retry_configs(corrupted_rc[..], out_rc),
            "corrupted retry_configs rejected",
        );

        // 3. parse_ech_hrr_retry_configs rejection on malformed wire
        var hrr_wire: u8[>..] = [];
        sub.assert_false(
            wing::parse_ech_hrr_retry_configs(corrupted_rc[..], hrr_wire),
            "parse_ech_hrr_retry_configs rejects malformed wire payload",
        );

        // 4. ECH FSM progression on HRR and ServerHello
        var fsm = wing::EchFsm {
            mode:              wing::EchHandshakeMode.Offered,
            has_hrr:           false,
            offered_config_id: 1,
        };

        // HRR with retry_configs
        var dummy_rc = wing::EchConfigList { .. };
        let ok_fsm_hrr = wing::ech_fsm_on_server_hello(
            fsm,
            wing::EchServerHelloType.HelloRetryRequest,
            true, // has_ech_ext
            b_list.buf[..],
            expected_confirm,
            dummy_rc,
        );
        sub.assert_true(ok_fsm_hrr, "fsm handles HRR with retry configs");
        sub.assert_true(fsm.mode == wing::EchHandshakeMode.RejectedWithRetry, "mode is RejectedWithRetry");

        // Second HRR strictly rejected!
        let ok_fsm_hrr2 = wing::ech_fsm_on_server_hello(
            fsm,
            wing::EchServerHelloType.HelloRetryRequest,
            true,
            b_list.buf[..],
            expected_confirm,
            dummy_rc,
        );
        sub.assert_false(ok_fsm_hrr2, "second HRR in ECH FSM strictly rejected");

        // Fresh FSM: ECH accepted in ServerHello
        var fsm_accept = wing::EchFsm {
            mode:              wing::EchHandshakeMode.Offered,
            has_hrr:           false,
            offered_config_id: 1,
        };
        let ok_fsm_sh = wing::ech_fsm_on_server_hello(
            fsm_accept,
            wing::EchServerHelloType.ServerHello,
            true,  // has_ech_ext
            expected_confirm[..],
            expected_confirm,
            dummy_rc,
        );
        sub.assert_true(ok_fsm_sh, "fsm handles SH with valid confirmation");
        sub.assert_true(fsm_accept.mode == wing::EchHandshakeMode.Accepted, "mode is Accepted");

        // 5. Post-HRR ECH Acceptance Downgrade / Stripping Attack Defense (RFC 9849 §7.2)
        // If HRR accepted ECH (has_ech_ext == false), ServerHello MUST confirm acceptance.
        // ServerHello omitting ECH extension MUST NOT silently downgrade to Bypassed; it MUST be rejected!
        var fsm_hrr_accept = wing::EchFsm {
            mode:              wing::EchHandshakeMode.Offered,
            has_hrr:           false,
            offered_config_id: 1,
        };
        // HRR accepts ECH
        let ok_hrr_acc = wing::ech_fsm_on_server_hello(
            fsm_hrr_accept,
            wing::EchServerHelloType.HelloRetryRequest,
            false, // has_ech_ext == false -> ECH accepted for HRR flight
            corrupted_rc[..0],
            expected_confirm,
            dummy_rc,
        );
        sub.assert_true(ok_hrr_acc, "HRR accepts ECH");
        sub.assert_true(fsm_hrr_accept.has_hrr, "has_hrr is true");
        sub.assert_true(fsm_hrr_accept.mode == wing::EchHandshakeMode.Offered, "mode remains Offered for ClientHello2");

        // Attacker strips ECH confirmation from ServerHello2 (has_ech_ext == false)
        let ok_sh_strip = wing::ech_fsm_on_server_hello(
            fsm_hrr_accept,
            wing::EchServerHelloType.ServerHello,
            false, // ECH extension missing / stripped!
            corrupted_rc[..0],
            expected_confirm,
            dummy_rc,
        );
        sub.assert_false(ok_sh_strip, "RFC 9849 §7.2: ServerHello omitting ECH confirmation after HRR acceptance MUST abort");

        // 6. ECH Outer ALPN Separation (RFC 9849 - OpenSSL Issue #33428 ALPN separation)
        let inner_alpn = "h2";
        let outer_alpn = "http/1.1";

        // When ECH is accepted: selected ALPN MUST match inner ALPN offer
        sub.assert_true(
            wing::validate_ech_alpn_negotiation(true, "h2", inner_alpn, outer_alpn),
            "ECH accepted: inner ALPN 'h2' negotiated successfully",
        );
        sub.assert_false(
            wing::validate_ech_alpn_negotiation(true, "http/1.1", inner_alpn, outer_alpn),
            "ECH accepted: outer ALPN 'http/1.1' strictly rejected",
        );

        // When ECH is rejected/bypassed: selected ALPN MUST match outer ALPN offer
        sub.assert_true(
            wing::validate_ech_alpn_negotiation(false, "http/1.1", inner_alpn, outer_alpn),
            "ECH bypassed: outer ALPN 'http/1.1' negotiated successfully",
        );
        sub.assert_false(
            wing::validate_ech_alpn_negotiation(false, "h2", inner_alpn, outer_alpn),
            "ECH bypassed: inner ALPN 'h2' strictly rejected per OpenSSL #33428",
        );

        // Empty selected ALPN strictly rejected
        let empty_alpn = "";
        sub.assert_false(
            wing::validate_ech_alpn_negotiation(false, empty_alpn, inner_alpn, outer_alpn),
            "empty selected ALPN rejected",
        );
    };
}

fn test_handshake_r3_invariants(t: lit::T&) {
    // ------------------------------------------------------------------------
    // TLS-37: Post-Handshake NewSessionTicket (RFC 8446 §4.6.1 & §4.2.10)
    // ------------------------------------------------------------------------
    t.run("TLS-37: Post-Handshake NewSessionTicket Lifetime, Nonce & EarlyData Bounds") { sub =>
        // 1. Valid NewSessionTicket
        var b_ticket: u8[..512] = [];
        let valid_nonce: u8[4] = [0x01, 0x02, 0x03, 0x04];
        let valid_ticket_data = "encrypted_session_ticket_sample";
        sub.assert_true(
            wing::encode_new_session_ticket(
                b_ticket,
                3600, // lifetime: 1 hour <= 604800
                0x12345678, // age_add
                valid_nonce[..],
                valid_ticket_data,
                16384, // max_early_data_size
            ),
            "encode valid NewSessionTicket succeeds",
        );

        var nst = wing::NewSessionTicketMsg { .. };
        sub.assert_true(
            wing::parse_new_session_ticket(b_ticket[..], nst),
            "parse valid NewSessionTicket succeeds",
        );
        sub.assert_eq(nst.ticket_lifetime as i64, 3600, "ticket_lifetime matches");
        sub.assert_eq(nst.ticket_age_add as i64, 0x12345678, "ticket_age_add matches");
        sub.assert_eq(nst.ticket_nonce.len, 4, "ticket_nonce length is 4");
        sub.assert_eq(nst.ticket.len, valid_ticket_data.len, "ticket length matches");
        sub.assert_true(nst.has_early_data, "ticket has early_data extension");
        sub.assert_eq(nst.max_early_data_size as i64, 16384, "max_early_data_size is 16384");

        // 2. Reject ticket_lifetime > 604800 (7 days)
        var b_bad_life: u8[..512] = [];
        wing::encode_new_session_ticket(b_bad_life, 604801, 0, valid_nonce[..], valid_ticket_data, 0);
        var nst_bad = wing::NewSessionTicketMsg { .. };
        sub.assert_false(
            wing::parse_new_session_ticket(b_bad_life[..], nst_bad),
            "ticket_lifetime > 604800 rejected",
        );

        // 3. Reject empty ticket data (length 0)
        let empty_ticket_wire: u8[13] = [
            0x00, 0x00, 0x0E, 0x10, // lifetime = 3600
            0x00, 0x00, 0x00, 0x01, // age_add = 1
            0x00,                   // nonce_len = 0
            0x00, 0x00,             // ticket_len = 0 (FORBIDDEN: ticket<1..2^16-1>)
            0x00, 0x00,             // ext_len = 0
        ];
        sub.assert_false(
            wing::parse_new_session_ticket(empty_ticket_wire[..], nst_bad),
            "empty ticket payload strictly rejected",
        );

        // 4. Reject max_early_data_size == 0 (RFC 8446 §4.2.10)
        let zero_early_data_wire: u8[25] = [
            0x00, 0x00, 0x0E, 0x10, // lifetime = 3600
            0x00, 0x00, 0x00, 0x01, // age_add = 1
            0x00,                   // nonce_len = 0
            0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // ticket_len = 4
            0x00, 0x08,             // ext_len = 8
            0x00, 0x2A,             // ext_type = 42 (early_data)
            0x00, 0x04,             // ext_data_len = 4
            0x00, 0x00, 0x00, 0x00, // max_early_data_size = 0 (FORBIDDEN)
        ];
        sub.assert_false(
            wing::parse_new_session_ticket(zero_early_data_wire[..], nst_bad),
            "early_data with max_early_data_size == 0 strictly rejected",
        );

        // 5. Multiple tickets caching & circular eviction
        var cache = wing::SessionTicketCache { .. };
        for i in 10 {
            var t_item = wing::NewSessionTicketMsg {
                ticket_lifetime: (1000 + i * 100) as u32,
                ticket_age_add:  i as u32,
                ..
            };
            sub.assert_true(
                wing::cache_session_ticket(cache, t_item),
                "cache_session_ticket succeeds",
            );
        }
        sub.assert_eq(cache.total_received as i64, 10, "total_received is 10");
        sub.assert_eq(cache.tickets.len, 8, "cache bounded to capacity 8");
        // Oldest (index 0) was evicted; last entry (index 7) has lifetime of ticket 9 (1900)
        sub.assert_eq(cache.tickets[7].ticket_lifetime as i64, 1900, "latest ticket preserved");

        // Lifetime 0 ticket is discarded immediately without taking cache slot
        var t_zero = wing::NewSessionTicketMsg { ticket_lifetime: 0, .. };
        let len_before = cache.tickets.len;
        sub.assert_true(wing::cache_session_ticket(cache, t_zero), "lifetime 0 ticket handled");
        sub.assert_eq(cache.tickets.len, len_before, "lifetime 0 ticket not cached");
    };

    // ------------------------------------------------------------------------
    // TLS-38: KeyUpdate Protocol & Ping-Pong DoS Rate Limiting (RFC 8446 §4.6.3)
    // ------------------------------------------------------------------------
    t.run("TLS-38: KeyUpdate Transitions, Byte Validation & DoS Rate Limiting") { sub =>
        // 1. KeyUpdate rejected prior to Connected state
        sub.assert_false(
            wing::validate_key_update_state(wing::HsState.ClientStart),
            "KeyUpdate rejected in ClientStart",
        );
        sub.assert_false(
            wing::validate_key_update_state(wing::HsState.ClientWaitSH),
            "KeyUpdate rejected in ClientWaitSH",
        );
        sub.assert_false(
            wing::validate_key_update_state(wing::HsState.ClientWaitFinished),
            "KeyUpdate rejected in ClientWaitFinished",
        );
        sub.assert_true(
            wing::validate_key_update_state(wing::HsState.Connected),
            "KeyUpdate accepted in Connected",
        );

        // 2. parse_key_update byte validation
        let ku_not_req: u8[1] = [0];
        let req0, ok0 = wing::parse_key_update(ku_not_req[..]);
        sub.assert_true(ok0, "parse update_not_requested succeeds");
        sub.assert_eq(req0, rfc::KEY_UPDATE_NOT_REQUESTED, "request_update is 0");

        let ku_req: u8[1] = [1];
        let req1, ok1 = wing::parse_key_update(ku_req[..]);
        sub.assert_true(ok1, "parse update_requested succeeds");
        sub.assert_eq(req1, rfc::KEY_UPDATE_REQUESTED, "request_update is 1");

        let ku_bad: u8[1] = [2]; // 2..255 forbidden
        let _, ok_bad = wing::parse_key_update(ku_bad[..]);
        sub.assert_false(ok_bad, "parse request_update=2 rejected");

        let ku_empty: u8[0] = [];
        let _, ok_empty = wing::parse_key_update(ku_empty[..]);
        sub.assert_false(ok_empty, "parse empty KeyUpdate rejected");

        let ku_multi: u8[2] = [0, 0];
        let _, ok_multi = wing::parse_key_update(ku_multi[..]);
        sub.assert_false(ok_multi, "parse 2-byte KeyUpdate rejected");

        // 3. DoS Rate Limiting / Ping-Pong defense
        var tracker = wing::KeyUpdateTracker { .. };
        for i in 32 {
            let needs_resp, ok_tr = wing::track_received_key_update(tracker, wing::HsState.Connected, ku_req[..]);
            sub.assert_true(ok_tr, "track KeyUpdate within limit succeeds");
            sub.assert_true(needs_resp, "update_requested signals response required");
        }
        sub.assert_eq(tracker.consecutive_updates as i64, 32, "consecutive_updates is 32");

        // 33rd consecutive update without application data MUST be rejected!
        let _, ok_overflow = wing::track_received_key_update(tracker, wing::HsState.Connected, ku_req[..]);
        sub.assert_false(ok_overflow, "33rd consecutive KeyUpdate rejected (DoS defense)");

        // Intervening application data resets consecutive counter
        wing::on_key_update_app_data(tracker);
        sub.assert_eq(tracker.consecutive_updates as i64, 0, "consecutive_updates reset after app data");
        let _, ok_after_reset = wing::track_received_key_update(tracker, wing::HsState.Connected, ku_not_req[..]);
        sub.assert_true(ok_after_reset, "KeyUpdate accepted after app data reset");
    };

    // ------------------------------------------------------------------------
    // TLS-39: CertificateRequest Context & Mandatory Signature Algorithms (RFC 8446 §4.3.2)
    // ------------------------------------------------------------------------
    t.run("TLS-39: CertificateRequest Context Bounds & Signature Algorithms Invariants") { sub =>
        // 1. Valid initial handshake CertificateRequest (context length MUST be 0)
        let valid_cr_wire: u8[11] = [
            0x00,                   // ctx_len = 0
            0x00, 0x08,             // ext_len = 8
            0x00, 0x0D,             // ext_type = 13 (signature_algorithms)
            0x00, 0x04,             // ext_data_len = 4
            0x00, 0x02,             // supported_signature_algorithms list len = 2
            0x04, 0x03,             // ecdsa_secp256r1_sha256
        ];
        var cr = wing::CertificateRequestMsg { .. };
        sub.assert_true(
            wing::parse_certificate_request(valid_cr_wire[..], false, cr),
            "parse valid initial CertificateRequest succeeds",
        );
        sub.assert_eq(cr.context.len, 0, "initial context length is 0");
        sub.assert_true(cr.has_signature_algorithms, "signature_algorithms extension present");
        sub.assert_eq(cr.sig_algorithms.len, 1, "1 signature algorithm parsed");
        sub.assert_eq(cr.sig_algorithms[0], 0x0403, "algorithm is 0x0403");

        // 2. Reject non-zero context in initial handshake
        let bad_initial_ctx: u8[12] = [
            0x01, 0xFF,             // ctx_len = 1 (FORBIDDEN in initial handshake!)
            0x00, 0x08,             // ext_len = 8
            0x00, 0x0D,             // ext_type = 13
            0x00, 0x04,             // ext_data_len = 4
            0x00, 0x02,             // list_len = 2
            0x04, 0x03,             // ecdsa_secp256r1_sha256
        ];
        sub.assert_false(
            wing::parse_certificate_request(bad_initial_ctx[..], false, cr),
            "non-zero context in initial CertificateRequest rejected",
        );

        // 3. Post-handshake CertificateRequest allows context <= 32 bytes
        sub.assert_true(
            wing::parse_certificate_request(bad_initial_ctx[..], true, cr),
            "non-zero context in post-handshake CertificateRequest accepted",
        );

        // 4. Missing signature_algorithms extension strictly rejected (RFC 8446 §4.3.2)
        let missing_sig_wire: u8[7] = [
            0x00,                   // ctx_len = 0
            0x00, 0x04,             // ext_len = 4
            0x00, 0x05,             // ext_type = 5 (status_request, NOT signature_algorithms)
            0x00, 0x00,             // data_len = 0
        ];
        sub.assert_false(
            wing::parse_certificate_request(missing_sig_wire[..], false, cr),
            "CertificateRequest lacking signature_algorithms extension strictly rejected",
        );
    };

    // ------------------------------------------------------------------------
    // TLS-40: Client Authentication with Empty Certificate Flight (RFC 8446 §4.4.2)
    // ------------------------------------------------------------------------
    t.run("TLS-40: Client Auth with Empty Certificate & CertificateVerify Omission") { sub =>
        // 1. Certificate message with empty certificate_list (no client cert)
        let empty_cert_wire: u8[4] = [
            0x00,                   // context len = 0
            0x00, 0x00, 0x00,       // certificate_list len = 0
        ];
        let is_empty, ok_cert = wing::parse_certificate_header_is_empty(empty_cert_wire[..]);
        sub.assert_true(ok_cert, "parse Certificate header succeeds");
        sub.assert_true(is_empty, "certificate_list is recognized as empty");

        // 2. Server transition when client sends empty certificate:
        // Skips CertificateVerify and expects Finished directly
        var st = wing::HsState.ServerWaitCert;
        let next_st, ok_tr = wing::validate_server_handshake_transition_auth(
            st,
            rfc::TLS_HS_CERTIFICATE,
            wing::ClientAuthMode.Requested,
            true, // client_cert_is_empty
        );
        sub.assert_true(ok_tr, "empty certificate accepted in ServerWaitCert");
        sub.assert_true(next_st == wing::HsState.ServerWaitFinished, "server skips ServerWaitCV and transitions to ServerWaitFinished");

        // In ServerWaitFinished, Finished transitions to Connected
        let final_st, ok_fin = wing::validate_server_handshake_transition_auth(
            next_st,
            rfc::TLS_HS_FINISHED,
            wing::ClientAuthMode.Requested,
            true,
        );
        sub.assert_true(ok_fin, "Finished accepted after empty certificate");
        sub.assert_true(final_st == wing::HsState.Connected, "server reaches Connected state");

        // 3. Client sending CertificateVerify when certificate was empty MUST be rejected (RFC 8446 §4.4.2)
        let _, ok_bad_cv = wing::validate_server_handshake_transition_auth(
            wing::HsState.ServerWaitCV,
            rfc::TLS_HS_CERTIFICATE_VERIFY,
            wing::ClientAuthMode.Requested,
            true, // client_cert_is_empty = true
        );
        sub.assert_false(ok_bad_cv, "CertificateVerify strictly rejected when client cert is empty");

        // 4. Normal client auth with cert: proceeds through ServerWaitCV
        let next_full, ok_full = wing::validate_server_handshake_transition_auth(
            wing::HsState.ServerWaitCert,
            rfc::TLS_HS_CERTIFICATE,
            wing::ClientAuthMode.Requested,
            false, // client_cert_is_empty = false
        );
        sub.assert_true(ok_full, "full certificate accepted");
        sub.assert_true(next_full == wing::HsState.ServerWaitCV, "server transitions to ServerWaitCV");
    };

    // ------------------------------------------------------------------------
    // TLS-41: 0-RTT Early Data State Machine & Recovery (RFC 8446 §4.2.10, RFC 9849)
    // ------------------------------------------------------------------------
    t.run("TLS-41: 0-RTT Early Data Acceptance, Rejection Recovery & ECH Placement") { sub =>
        // 1. Early data accepted by server
        var ctrl_accept = wing::EarlyDataController {
            state:                   wing::EarlyDataState.Offered,
            max_early_data_size:     16384,
            psk_cipher_suite:        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
            negotiated_cipher_suite: rfc::TLS_CIPHER_AES_128_GCM_SHA256,
            ..
        };
        sub.assert_true(
            wing::early_data_on_encrypted_extensions(ctrl_accept, true),
            "early_data accepted in EncryptedExtensions",
        );
        sub.assert_true(ctrl_accept.state == wing::EarlyDataState.Accepted, "state is Accepted");
        sub.assert_true(wing::early_data_can_send_eoed(ctrl_accept), "client permitted to send EndOfEarlyData");

        // 2. Early data rejected by server (recovery mode)
        var ctrl_reject = wing::EarlyDataController {
            state:               wing::EarlyDataState.Offered,
            max_early_data_size: 16384,
            ..
        };
        sub.assert_true(
            wing::early_data_on_encrypted_extensions(ctrl_reject, false),
            "early_data rejected in EncryptedExtensions handled cleanly",
        );
        sub.assert_true(ctrl_reject.state == wing::EarlyDataState.Rejected, "state is Rejected");
        sub.assert_true(ctrl_reject.keys_discarded, "0-RTT traffic keys discarded immediately");
        sub.assert_false(wing::early_data_can_send_eoed(ctrl_reject), "client MUST NOT send EndOfEarlyData when rejected");

        // 3. Early data record size bounds
        var ctrl_send = wing::EarlyDataController {
            state:               wing::EarlyDataState.Offered,
            max_early_data_size: 100,
            ..
        };
        sub.assert_true(wing::early_data_record_sent(ctrl_send, 50), "send 50 bytes within limit succeeds");
        sub.assert_true(wing::early_data_record_sent(ctrl_send, 50), "send another 50 bytes reaching limit succeeds");
        sub.assert_false(wing::early_data_record_sent(ctrl_send, 1), "send exceeding max_early_data_size rejected");

        // 4. ECH early_data placement rules (stricter than RFC 9849 §6.1 step 7)
        sub.assert_true(
            wing::validate_ech_early_data_placement(wing::EchClientHelloType.Inner, true),
            "early_data in ClientHelloInner permitted",
        );
        sub.assert_false(
            wing::validate_ech_early_data_placement(wing::EchClientHelloType.Outer, true),
            "early_data in ClientHelloOuter strictly forbidden",
        );
        sub.assert_true(
            wing::validate_ech_early_data_placement(wing::EchClientHelloType.Outer, false),
            "no early_data in ClientHelloOuter permitted",
        );

        // 5. OpenSSL Bug #31406 & RFC 8446 §4.2.10: 0-RTT PSK cipher suite mismatch handling
        // Case A: server validator strictly rejects mismatched cipher suite
        sub.assert_true(
            wing::validate_server_early_data_cipher(rfc::TLS_CIPHER_AES_128_CCM_SHA256, rfc::TLS_CIPHER_AES_128_CCM_SHA256),
            "identical cipher suites permit early data acceptance",
        );
        sub.assert_false(
            wing::validate_server_early_data_cipher(rfc::TLS_CIPHER_AES_128_CCM_SHA256, rfc::TLS_CIPHER_AES_128_CCM_8_SHA256),
            "mismatched PSK vs negotiated cipher suite strictly rejected on server (OpenSSL #31406)",
        );
        sub.assert_false(
            wing::validate_server_early_data_cipher(0, rfc::TLS_CIPHER_AES_128_GCM_SHA256),
            "uninitialized PSK cipher rejected",
        );

        // Case B: client controller aborts early data when server sends ee_has_early_data on cipher mismatch
        var ctrl_mismatch = wing::EarlyDataController {
            state:                   wing::EarlyDataState.Offered,
            max_early_data_size:     16384,
            psk_cipher_suite:        rfc::TLS_CIPHER_AES_128_CCM_SHA256,
            negotiated_cipher_suite: rfc::TLS_CIPHER_AES_128_CCM_8_SHA256,
            ..
        };
        let ok_ee_mismatch = wing::early_data_on_encrypted_extensions(ctrl_mismatch, true);
        sub.assert_false(ok_ee_mismatch, "client aborts early data when EE accepts despite cipher mismatch");
        sub.assert_true(ctrl_mismatch.state == wing::EarlyDataState.Rejected, "state transitions to Rejected");
        sub.assert_true(ctrl_mismatch.keys_discarded, "0-RTT keys discarded on mismatch");
        sub.assert_false(wing::early_data_can_send_eoed(ctrl_mismatch), "client cannot send EOED on mismatch");
    };

    // ------------------------------------------------------------------------
    // TLS-42: RFC 8879 CompressedCertificate Parser Sanity Bounds & Decompression Bomb Protection
    // ------------------------------------------------------------------------
    t.run("TLS-42: CompressedCertificate Bounds, Decompression Bomb Defense & Transitions") { sub =>
        // 1. Valid CompressedCertificate payload (RFC 8879 §4: 2B algo + 3B ulen + 3B comp_len + data)
        let valid_comp_payload: u8[13] = [
            0x00, 0x03,             // algorithm = 3 (zstd)
            0x00, 0x00, 0x10,       // uncompressed_length = 16
            0x00, 0x00, 0x05,       // compressed_certificate_message length = 5
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // compressed_data (5 bytes)
        ];
        let parsed, ok_parse = wing::parse_compressed_certificate(valid_comp_payload[..]);
        sub.assert_true(ok_parse, "parse valid CompressedCertificate succeeds");
        sub.assert_eq(parsed.algorithm, rfc::CERT_COMPRESSION_ZSTD, "algorithm is zstd");
        sub.assert_eq(parsed.uncompressed_len as i64, 16, "uncompressed_len is 16");

        // 2. Reject unknown algorithm ID (e.g. 0 or 4)
        let unknown_algo: u8[13] = [
            0x00, 0x04,             // algorithm = 4 (unknown)
            0x00, 0x00, 0x10,
            0x00, 0x00, 0x05,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        ];
        let _, ok_unknown = wing::parse_compressed_certificate(unknown_algo[..]);
        sub.assert_false(ok_unknown, "unknown compression algorithm rejected");

        // 3. Reject uncompressed_length == 0
        let zero_ulen: u8[13] = [
            0x00, 0x03,
            0x00, 0x00, 0x00,       // uncompressed_length = 0
            0x00, 0x00, 0x05,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        ];
        let _, ok_zero_ulen = wing::parse_compressed_certificate(zero_ulen[..]);
        sub.assert_false(ok_zero_ulen, "uncompressed_length == 0 rejected");

        // 4. Reject uncompressed_length > MAX_UNCOMPRESSED_CERT_LEN (65536)
        let bomb_payload: u8[13] = [
            0x00, 0x03,
            0x01, 0x00, 0x00,       // uncompressed_length = 65,536 + 1 = 65537+
            0x00, 0x00, 0x05,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        ];
        let _, ok_bomb = wing::parse_compressed_certificate(bomb_payload[..]);
        sub.assert_false(ok_bomb, "decompression bomb exceeding MAX_UNCOMPRESSED_CERT_LEN rejected");

        // 5. Client transition accepts CompressedCertificate in place of Certificate
        let next_cc_cr, ok_cc_cr = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitCertCr,
            rfc::TLS_HS_COMPRESSED_CERTIFICATE,
            wing::HandshakeMode.Full,
            false,
        );
        sub.assert_true(ok_cc_cr, "CompressedCertificate accepted in ClientWaitCertCr");
        sub.assert_true(next_cc_cr == wing::HsState.ClientWaitCV, "transitions to ClientWaitCV");

        let next_cc, ok_cc = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitCert,
            rfc::TLS_HS_COMPRESSED_CERTIFICATE,
            wing::HandshakeMode.Full,
            false,
        );
        sub.assert_true(ok_cc, "CompressedCertificate accepted in ClientWaitCert");
        sub.assert_true(next_cc == wing::HsState.ClientWaitCV, "transitions to ClientWaitCV");
    };
}

// RFC 8879 Section 3: Negotiating Certificate Compression - Brotli certificate decompression
fn test_rfc8879_brotli_cert_compression(t: lit::T&) {
    t.run("1. RFC 8879 Algorithm Identifiers & Models") { sub =>
        sub.assert_eq(rfc::CERT_COMPRESSION_BROTLI, 2, "Brotli algorithm ID is 2");
        sub.assert_eq(rfc::CERT_COMPRESSION_ZSTD, 3, "Zstandard ID is 3 in specification (RFC 8879 §3)");
        sub.assert_eq(rfc::CERT_COMPRESSION_ZSTD, 3, "Zstandard IANA official ID is 3");
        sub.assert_eq(rfc::CERT_COMPRESSION_ZLIB, 1, "zlib algorithm ID is 1");

        sub.assert_true(rfc::is_valid_compression_algorithm(rfc::CERT_COMPRESSION_BROTLI), "Brotli valid");
        sub.assert_true(rfc::is_valid_compression_algorithm(rfc::CERT_COMPRESSION_ZSTD), "Zstd 3 valid");
        sub.assert_true(rfc::is_valid_compression_algorithm(rfc::CERT_COMPRESSION_ZSTD), "Zstd 3 valid");
        sub.assert_false(rfc::is_valid_compression_algorithm(0), "Algorithm 0 invalid");
        sub.assert_false(rfc::is_valid_compression_algorithm(4), "Algorithm 4 invalid");
    };

    t.run("2. Brotli CompressedCertificate Serialization and Roundtrip") { sub =>
        let cert_plaintext = "MIIB...X509_CERTIFICATE_PAYLOAD_TEST_VECTOR_REPETITIVE_METADATA_HEADER_AND_EXTENSIONS...";
        var compressed_data: u8[>..] = [];
        let ok_c = core::brotli_compress(cert_plaintext, compressed_data, 0);
        sub.assert_true(ok_c, "Brotli level 0 compression of certificate succeeds");

        var decomp2:     u8[..4096] = [];
        var decomp_zlib: u8[..4096] = [];
        var decomp_zstd: u8[..4096] = [];

        var test_cert_msg = internal::CompressedCertificate {
            algorithm:                      rfc::CERT_COMPRESSION_BROTLI,
            uncompressed_length:            cert_plaintext.len as u32,
            compressed_certificate_message: compressed_data[..],
        };

        var wire: u8[..4096] = [];
        let ok_enc = internal::encode_compressed_certificate(test_cert_msg, wire);
        sub.assert_true(ok_enc, "CompressedCertificate encoded");
        sub.assert_eq(wire.len, 8 + compressed_data.len, "Wire length matches 8 + compressed len");
        sub.assert_eq(wire[0], 0, "Algorithm high byte is 0");
        sub.assert_eq(wire[1], 2, "Algorithm low byte is 2 (Brotli)");

        {
            var parsed = internal::CompressedCertificate { .. };
            let ok_dec = internal::parse_compressed_certificate_msg(wire[..], parsed);
            sub.assert_true(ok_dec, "CompressedCertificate parsed");
            sub.assert_eq(parsed.algorithm, rfc::CERT_COMPRESSION_BROTLI, "Parsed algorithm is Brotli");
            sub.assert_eq(parsed.uncompressed_length, cert_plaintext.len as u32, "Parsed length matches plaintext");
            sub.assert_true(parsed.compressed_certificate_message == compressed_data[..], "Compressed bytes match");

            // Safe decompression via handler interface
            var decompressed: u8[..4096] = [];
            let ok_decomp = internal::decompress_certificate_message(parsed, 10000, decompressed);
            sub.assert_true(ok_decomp, "Safe decompression succeeds");
            sub.assert_bytes_eq(decompressed[..], cert_plaintext, "Decompressed certificate matches original exactly");
        }

        let ok_brotli = internal::decompress_certificate_brotli(compressed_data[..], cert_plaintext.len as u32, decomp2);
        sub.assert_true(ok_brotli, "decompress_certificate_brotli succeeds");
        sub.assert_bytes_eq(decomp2[..], cert_plaintext, "decomp2 matches original exactly");

        var wire_copy: u8[..4096] = [];
        wire_copy.append(wire[..]);
        var decomp3: u8[..4096] = [];
        let ok_incoming = wing::decompress_incoming_certificate(wire_copy[..], decomp3);
        sub.assert_true(ok_incoming, "decompress_incoming_certificate succeeds on handshake wire payload");
        sub.assert_bytes_eq(decomp3[..], cert_plaintext, "decomp3 matches original plaintext");

        // Zlib compression/decompression verification
        var zlib_comp: u8[>..] = [];
        let ok_zcomp = core::zlib_compress(cert_plaintext, zlib_comp);
        sub.assert_true(ok_zcomp, "zlib compression succeeds");

        var zlib_msg = internal::CompressedCertificate {
            algorithm:                      rfc::CERT_COMPRESSION_ZLIB,
            uncompressed_length:            cert_plaintext.len as u32,
            compressed_certificate_message: zlib_comp[..],
        };
        let ok_zdecomp = internal::decompress_certificate_message(zlib_msg, 10000, decomp_zlib);
        sub.assert_true(ok_zdecomp, "zlib certificate decompression succeeds");
        sub.assert_bytes_eq(decomp_zlib[..], cert_plaintext, "decompressed zlib matches plaintext");

        // Zstandard (IANA 3) compression/decompression verification
        var zstd_comp: u8[>..] = [];
        let ok_zstd_comp = core::zstd_compress(cert_plaintext, zstd_comp);
        sub.assert_true(ok_zstd_comp, "zstd compression succeeds");
        var zstd_msg = internal::CompressedCertificate {
            algorithm:                      rfc::CERT_COMPRESSION_ZSTD,
            uncompressed_length:            cert_plaintext.len as u32,
            compressed_certificate_message: zstd_comp[..],
        };
        let ok_zstd_decomp = internal::decompress_certificate_message(zstd_msg, 10000, decomp_zstd);
        sub.assert_true(ok_zstd_decomp, "zstd certificate decompression succeeds");
        sub.assert_bytes_eq(decomp_zstd[..], cert_plaintext, "decompressed zstd matches plaintext");
    };

    t.run("3. Enterprise Decompression Bomb and Boundary Protection") { sub =>
        // 1. Decompression bomb: uncompressed_length exceeds caller's max buffer ceiling
        var bomb_msg = internal::CompressedCertificate {
            algorithm:                      rfc::CERT_COMPRESSION_BROTLI,
            uncompressed_length:            50000,
            compressed_certificate_message: "abc",
        };
        var out_sink: u8[..1024] = [];
        let ok_b1 = internal::decompress_certificate_message(bomb_msg, 1024, out_sink);
        sub.assert_false(ok_b1, "Decompression bomb exceeding max_allowed_len rejected");

        // 2. Uncompressed length exceeding global MAX_UNCOMPRESSED_CERT_SIZE (65536)
        bomb_msg.uncompressed_length = 70000;
        let ok_b2 = internal::decompress_certificate_message(bomb_msg, 100000, out_sink);
        sub.assert_false(ok_b2, "Length exceeding 64KB ceiling rejected");

        // 3. Zero uncompressed length rejected
        bomb_msg.uncompressed_length = 0;
        let ok_b3 = internal::decompress_certificate_message(bomb_msg, 100000, out_sink);
        sub.assert_false(ok_b3, "Zero uncompressed length rejected");

        // 4. Decompression bomb ratio sanity check (> 1024x expansion ratio)
        let tiny_comp: u8[2] = [0x5B, 0x00];
        var bad_ratio_wire: u8[10] = [
            0x00, 0x02,             // algo: 2
            0x00, 0xFA, 0x00,       // uncompressed_length: 64000 (ratio = 32000x > 1024x)
            0x00, 0x00, 0x02,       // compressed_length: 2 (uint24 vector prefix)
            tiny_comp[0], tiny_comp[1],
        ];
        var parsed_bad = internal::CompressedCertificate { .. };
        let ok_ratio = internal::parse_compressed_certificate_msg(bad_ratio_wire[..], parsed_bad);
        sub.assert_false(ok_ratio, "Insane expansion ratio (>1024x) rejected by wire parser");

        // 5. Corrupted compressed payload
        let corrupt_payload: u8[10] = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66];
        var corrupt_msg = internal::CompressedCertificate {
            algorithm:                      rfc::CERT_COMPRESSION_BROTLI,
            uncompressed_length:            10,
            compressed_certificate_message: corrupt_payload[..],
        };
        var out_corrupt: u8[..1024] = [];
        let ok_c_fail = internal::decompress_certificate_message(corrupt_msg, 1024, out_corrupt);
        sub.assert_false(ok_c_fail, "Corrupted Brotli payload fails gracefully without crash");
    };
}

// 13. CryptoShield Remediation Conformance
fn test_remediation_post_quantum(t: lit::T&) {
    t.run("CryptoShield: FIPS 203 NTT/InvNTT Roundtrip & Polynomial Arithmetic") { sub =>
        var p = internal::Poly256 {};
        p.coeffs[0] = 1;
        p.coeffs[1] = 2;
        p.coeffs[2] = 3328;
        p.coeffs[255] = 17;

        var p2 = internal::Poly256 {};
        p2.coeffs[0] = 10;
        p2.coeffs[1] = 20;

        let p_sum = internal::poly_add(p, p2);
        sub.assert_eq(p_sum.coeffs[0], 11, "poly_add coeff 0");
        sub.assert_eq(p_sum.coeffs[1], 22, "poly_add coeff 1");

        let p_diff = internal::poly_sub(p_sum, p2);
        sub.assert_eq(p_diff.coeffs[0], p.coeffs[0], "poly_sub restores coeff 0");
        sub.assert_eq(p_diff.coeffs[1], p.coeffs[1], "poly_sub restores coeff 1");

        let p_hat = internal::poly_ntt(p);
        let p_rec = internal::poly_invntt(p_hat);
        sub.assert_eq(p_rec.coeffs[0], p.coeffs[0], "NTT roundtrip coeff 0");
        sub.assert_eq(p_rec.coeffs[1], p.coeffs[1], "NTT roundtrip coeff 1");
        sub.assert_eq(p_rec.coeffs[2], p.coeffs[2], "NTT roundtrip coeff 2");
        sub.assert_eq(p_rec.coeffs[255], p.coeffs[255], "NTT roundtrip coeff 255");
    };
}

fn test_remediation_x509_signatures(t: lit::T&) {
    t.run("CryptoShield: X.509 Signature & OCSP/CRL Verification") { sub =>
        let empty_cert = wing::ParsedCert {};
        let dummy_parent = wing::ParsedCert {};
        let empty_alert = wing::x509_verify_cert_signature(empty_cert, "", dummy_parent, "");
        sub.assert_eq(wing::tls_alert_to_u8(empty_alert), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "empty cert sig returns CloseNotify");

        let empty_ocsp = wing::ParsedOcspResponse {};
        let ocsp_sig_alert = wing::x509_verify_ocsp_signature(empty_ocsp, "", dummy_parent, "");
        sub.assert_eq(wing::tls_alert_to_u8(ocsp_sig_alert), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificateStatusResponse), "empty ocsp sig returns BadCertificateStatusResponse");

        let empty_crl = wing::ParsedCrl {};
        let crl_sig_alert = wing::x509_verify_crl_signature(empty_crl, "", dummy_parent, "");
        sub.assert_eq(wing::tls_alert_to_u8(crl_sig_alert), wing::tls_alert_to_u8(wing::TlsAlert.BadCertificate), "empty crl sig returns BadCertificate");
    };
}

fn test_remediation_misc(t: lit::T&) {
    t.run("CryptoShield: Post-Handshake Auth, Boundary & ECH Public Name") { sub =>
        let st, ok_pha = wing::validate_client_handshake_transition(
            wing::HsState.Connected,
            rfc::TLS_HS_CERTIFICATE_REQUEST,
            wing::HandshakeMode.Full,
            false,
        );
        sub.assert_true(ok_pha, "post-handshake CertificateRequest allowed in Connected");
        sub.assert_true(st == wing::HsState.Connected, "state remains Connected");

        let hs_msg: u8[14] = [0x01, 0x00, 0x00, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let m_type, m_len, ok_fit = wing::validate_handshake_record_boundary(hs_msg[..], 20);
        sub.assert_true(ok_fit, "handshake fits in record");
        sub.assert_eq(m_type, 1, "parsed message type matches");
        sub.assert_eq(m_len, 10, "parsed message len matches");

        let _, _, ok_exceed = wing::validate_handshake_record_boundary(hs_msg[..], 10);
        sub.assert_false(ok_exceed, "handshake + 4 header exceeds record");

        var pad_buf: u8[..512] = [];
        let ok_pad0 = wing::pad_ech_inner("inner-hello", 64, 0, pad_buf);
        sub.assert_true(ok_pad0, "pad_ech_inner with real_sni_len == 0 succeeds");
        sub.assert_eq(pad_buf.len % 32, 0, "pad_buf is 32-byte aligned");

        sub.assert_true(wing::validate_ech_public_name_bytes("public.cloudflare-ech.com"), "valid DNS public name");
        sub.assert_false(wing::validate_ech_public_name_bytes("trailing.dot."), "trailing dot rejected");
        sub.assert_false(wing::validate_ech_public_name_bytes("192.168.1.1"), "all digits and dots rejected");

        // RFC Appendix D.4 CCS validations
        sub.assert_true(rfc::is_valid_ccs_payload([0x01]), "valid CCS payload");
        sub.assert_false(rfc::is_valid_ccs_payload([0x00]), "invalid CCS byte");
        sub.assert_false(rfc::is_valid_ccs_payload([0x01, 0x01]), "multi-byte CCS rejected");
        sub.assert_false(rfc::is_valid_ccs_payload([]), "empty CCS rejected");

        // RFC Appendix B.4 Cipher Suite properties
        sub.assert_eq(rfc::tls13_cipher_suite_key_len(rfc::TLS_CIPHER_AES_128_GCM_SHA256), 16, "aes128 key len 16");
        sub.assert_eq(rfc::tls13_cipher_suite_key_len(rfc::TLS_CIPHER_AES_256_GCM_SHA384), 32, "aes256 key len 32");
        sub.assert_eq(
            rfc::tls13_cipher_suite_key_len(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256),
            32,
            "chacha key len 32",
        );
        sub.assert_eq(rfc::tls13_cipher_suite_hash_len(rfc::TLS_CIPHER_AES_128_GCM_SHA256), 32, "aes128 hash len 32");
        sub.assert_eq(rfc::tls13_cipher_suite_hash_len(rfc::TLS_CIPHER_AES_256_GCM_SHA384), 48, "aes256 hash len 48");

        // RFC 6960 OCSP Status
        var ocsp_st = wing::OcspResponseStatus.Unknown;
        sub.assert_true(wing::x509_parse_ocsp_status(rfc::OCSP_STATUS_SUCCESSFUL, ocsp_st), "ocsp successful");
        sub.assert_true(ocsp_st == wing::OcspResponseStatus.Successful, "ocsp status matches");
        sub.assert_true(wing::x509_parse_ocsp_status(rfc::OCSP_STATUS_UNAUTHORIZED, ocsp_st), "ocsp unauthorized");
        sub.assert_true(ocsp_st == wing::OcspResponseStatus.Unauthorized, "ocsp status unauthorized");
        sub.assert_false(wing::x509_parse_ocsp_status(99, ocsp_st), "unknown ocsp status rejected");
    };
}

fn test_remediation_record_aead(t: lit::T&) {
    t.run("CryptoShield: Unified AEAD Dispatch for AES-256-GCM and ChaCha20-Poly1305") { sub =>
        let key32: u8[32]      = [0x55; 32];
        let iv12:  u8[12]      = [0xAA; 12];
        let pt:    const u8[:] = "CryptoShield AEAD Test";

        var ct_raw: u8[128] = [0; 128];
        let ct_len, alert_seal256, ok_seal256 = wing::tls_record_seal_into(
            rfc::TLS_CIPHER_AES_256_GCM_SHA384,
            key32[..],
            iv12,
            0,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            pt,
            ct_raw[..],
        );
        sub.assert_true(ok_seal256, "seal AES-256-GCM succeeds");
        sub.assert_eq(wing::tls_alert_to_u8(alert_seal256), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "seal alert CloseNotify");

        var pt_raw: u8[128] = [0; 128];
        let dec_len, in_type, alert_dec256, ok_dec256 = wing::tls_record_decrypt_into(
            rfc::TLS_CIPHER_AES_256_GCM_SHA384,
            key32[..],
            iv12,
            0,
            ct_raw[..5],
            ct_raw[5..ct_len],
            pt_raw[..],
        );
        sub.assert_true(ok_dec256, "decrypt AES-256-GCM succeeds");
        sub.assert_eq(wing::tls_alert_to_u8(alert_dec256), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "dec alert CloseNotify");
        sub.assert_eq(in_type, rfc::TLS_CONTENT_APPLICATION_DATA, "inner type is application data");
        sub.assert_bytes_eq(pt_raw[..dec_len], pt, "AES-256-GCM plaintext matches");

        var ct_ch_raw: u8[128] = [0; 128];
        let ct_ch_len, alert_seal_ch, ok_seal_ch = wing::tls_record_seal_into(
            rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256,
            key32[..],
            iv12,
            0,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            pt,
            ct_ch_raw[..],
        );
        sub.assert_true(ok_seal_ch, "seal ChaCha20-Poly1305 succeeds");

        var pt_ch_raw: u8[128] = [0; 128];
        let dec_ch_len, in_ch_type, alert_dec_ch, ok_dec_ch = wing::tls_record_decrypt_into(
            rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256,
            key32[..],
            iv12,
            0,
            ct_ch_raw[..5],
            ct_ch_raw[5..ct_ch_len],
            pt_ch_raw[..],
        );
        sub.assert_true(ok_dec_ch, "decrypt ChaCha20-Poly1305 succeeds");
        sub.assert_bytes_eq(pt_ch_raw[..dec_ch_len], pt, "ChaCha20 plaintext matches");
    };
}

// 17. Live TLS 1.3 Transport, Handshake Orchestration & Session Tickets
fn test_live_tls_transport_session(t: lit::T&) {
    t.run("TLS-43: Canonical Ed25519 X.509 Certificate Generation & Trust Anchor Validation") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9c, 0x4f, 0x61, 0x97, 0xf8,
            0x9a, 0x21, 0xe1, 0xf3, 0xc2, 0x55, 0xa0, 0x45,
            0x82, 0xe2, 0x15, 0x68, 0x77, 0x11, 0x0f, 0x2e,
            0xa0, 0x21, 0x86, 0xc4, 0x2d, 0x39, 0x53, 0x4f,
        ];
        var cert_der: u8[..2048] = [];
        let ok_gen = wing::build_test_ed25519_cert_der(seed, "localhost", "localhost", "127.0.0.1", cert_der);
        sub.assert_true(ok_gen, "canonical Ed25519 self-signed DER cert generated");

        var parsed = wing::ParsedCert { .. };
        let ok_parse = wing::parse_x509_certificate(cert_der[..], parsed);
        sub.assert_true(ok_parse, "generated cert parsed by X.509 parser");
        sub.assert_true(parsed.has_san, "cert has Subject Alternative Name extension");
        sub.assert_true(parsed.has_basic_constraints, "cert has Basic Constraints extension");
        sub.assert_true(parsed.is_ca, "self-signed test cert has is_ca true");

        var sans: wing::SanEntry[..16] = [];
        let ok_san = wing::get_cert_san_extension(parsed, cert_der[..], sans);
        sub.assert_true(ok_san, "extracted SAN entries");
        sub.assert_true(wing::match_any_san(sans, "localhost"), "matches DNS SAN 'localhost'");
        sub.assert_true(wing::match_any_san(sans, "127.0.0.1"), "matches IP SAN '127.0.0.1'");
        sub.assert_false(wing::match_any_san(sans, "evil.com"), "rejects untrusted SAN 'evil.com'");

        var store = wing::TrustAnchorStore { .. };
        let ok_anchor = wing::add_trust_anchor_cert_der(store, cert_der[..]);
        sub.assert_true(ok_anchor, "added cert to trust anchor store");

        var chain_parsed: wing::ParsedCert[..8] = [];
        chain_parsed.push(parsed);
        var chain_raw: const u8[:][..8] = [];
        chain_raw.push(cert_der[..]);

        let alert = wing::verify_certificate_chain(chain_parsed, chain_raw, store, 1735689600);
        sub.assert_eq(wing::tls_alert_to_u8(alert), wing::tls_alert_to_u8(wing::TlsAlert.CloseNotify), "chain verified against trusted anchor store");

        var empty_store = wing::TrustAnchorStore { .. };
        let alert_untrusted = wing::verify_certificate_chain(chain_parsed, chain_raw, empty_store, 1735689600);
        sub.assert_eq(wing::tls_alert_to_u8(alert_untrusted), wing::tls_alert_to_u8(wing::TlsAlert.UnknownCa), "untrusted cert rejected with UnknownCa alert");
    };

    t.run("TLS-44: Post-Handshake Session Ticket & KeyUpdate Dispatch") { sub =>
        let slot_idx = wing::alloc_tls_cipher_slot();
        sub.assert_true(slot_idx != 0xFFFF, "allocated cipher slot");

        let ok_ku = wing::tls_send_key_update(0, slot_idx, 0);
        sub.assert_false(ok_ku, "KeyUpdate rejected on uninitialized/invalid socket descriptor");

        let ok_nst = wing::tls_send_new_session_ticket(0, slot_idx, 86400, "nonce", "ticket");
        sub.assert_false(ok_nst, "NewSessionTicket rejected on invalid socket descriptor");

        let srv_cfg = wing::TlsServerHandshakeConfig { .. };
        let _, ok_srv = wing::tls_server_handshake(-1, srv_cfg);
        sub.assert_false(ok_srv, "tls_server_handshake safely fails on closed fd");

        sub.assert_bytes_eq(wing::tls_session_alpn(slot_idx), "", "initial negotiated ALPN is empty");
        sub.assert_false(wing::tls_session_is_resumed(slot_idx), "initial session is not PSK resumed");

        wing::free_tls_cipher_slot(slot_idx);
    };

    t.run("TLS-45: ALPN Negotiation & PSK Session Ticket Resumption Wire Conformance") { sub =>
        wing::clear_tls13_session_tickets();

        let psk: u8[32] = [0x42; 32];
        wing::store_tls13_session_ticket("example.com", "ticket-id-01", psk, 0x11223344, 3600);

        var out_ticket: u8[..256] = [];
        var out_psk:    u8[32]    = [0; 32];
        var out_age:    u32       = 0;
        let found = wing::lookup_tls13_session_ticket("example.com", out_ticket, out_psk, out_age);
        sub.assert_true(found, "cached session ticket found by hostname");
        sub.assert_bytes_eq(out_ticket[..], "ticket-id-01", "ticket identity matches");
        sub.assert_eq(out_age, 0x11223344, "ticket age_add matches");

        let cli_rand: u8[32] = [0x11; 32];
        let cli_priv: u8[32] = [0x22; 32];
        let cli_pub = core::x25519_base_scalarmult(cli_priv);

        var ch_payload: u8[..2048] = [];
        wing::build_tls13_client_hello_payload(
            cli_rand, cli_pub, "example.com", "h2,http/1.1",
            ch_payload, out_ticket[..], out_age,
        );
        var ch_msg: u8[..2048] = [];
        ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
        core::append_u24_be(ch_msg, ch_payload.len as u32);
        ch_msg.append(ch_payload[..]);

        var ks_early, ok_kse = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
        sub.assert_true(ok_kse && internal::ks_init_early_secret(ks_early, out_psk[..]), "ks_init_early_secret succeeds");
        var b_key: u8[32] = [0; 32];
        for i in 32 { b_key[i] = ks_early.binder_key[i]; }
        let trunc_ch, ok_tr = internal::truncate_client_hello_for_binder(ch_msg[..], 33);
        sub.assert_true(ok_tr, "truncate_client_hello_for_binder succeeds");
        var binder: u8[32] = [0; 32];
        sub.assert_true(wing::compute_tls13_psk_binder(b_key, trunc_ch, binder), "compute_tls13_psk_binder succeeds");
        let b_start = ch_msg.len - 32;
        for i in 32 { ch_msg[b_start + i] = binder[i]; }

        var srv_sid:     u8[..32] = [];
        var srv_cli_pub: u8[32]   = [0; 32];
        var srv_alpn:    u8[..32] = [];
        var srv_resumed: bool     = false;
        var srv_psk:     u8[32]   = [0; 32];
        let ok_ch = wing::parse_client_hello_for_server(
            ch_msg[..], "h2,http/1.1", srv_sid, srv_cli_pub,
            srv_alpn, srv_resumed, srv_psk,
        );
        sub.assert_true(ok_ch, "server parsed ClientHello with multi-ALPN and PSK");
        sub.assert_bytes_eq(srv_alpn[..], "h2", "server selected h2 from client ALPN list");
        sub.assert_true(srv_resumed, "server verified PSK binder and accepted resumption");

        wing::clear_tls13_session_tickets();
    };
}

// Main TLS 1.3 & X.509 Conformance Runner
fn main() {
    var runner = lit::new_runner("TLS 1.3 & X.509 PKI Zero-Allocation Conformance Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. ByteCursor, ByteBuilder, and Serialization Conformance", test_byte_cursor_and_builder);
    lit::run_case(runner, "2. TLS Record Layer Framing, Nonce & DoS Defenses", test_record_layer_and_dos);
    lit::run_case(runner, "3. QUIC Crypto Gateway & Header Protection (RFC 9001)", test_quic_crypto_gateway);
    lit::run_case(runner, "4. HKDF-Expand-Label & Key Schedule Derivations (RFC 8446)", test_key_schedule_and_derivations);
    lit::run_case(runner, "5. Anti-Replay Strike Register & PSK Binders", test_anti_replay_and_psk);
    lit::run_case(runner, "6. Handshake State Machine, HRR & Extension Parsers", test_handshake_state_machine);
    lit::run_case(runner, "7. ASN.1 DER Parser, RFC 6125 SAN Matcher & CertificateVerify", test_asn1_x509_and_verify);
    lit::run_case(runner, "8. Hybrid Post-Quantum Key Agreement (RFC 10024 & FIPS 203)", test_post_quantum_hybrid_exchange);
    lit::run_case(runner, "9. Handshake Extension Bounds, Supported Versions, ECH & Anti-Splitting Conformance", test_handshake_and_ech_security);
    lit::run_case(runner, "10. State Machine Transitions, HRR Invariants, Downgrade & ECH FSM", test_handshake_r2_invariants);
    lit::run_case(runner, "11. NewSessionTicket, KeyUpdate, ClientAuth, 0-RTT Recovery & CertComp", test_handshake_r3_invariants);
    lit::run_case(runner, "12. RFC 8879 Brotli Certificate Decompression & Bomb Defenses", test_rfc8879_brotli_cert_compression);
    lit::run_case(runner, "13. FIPS 203 NTT & Polynomial Arithmetic", test_remediation_post_quantum);
    lit::run_case(runner, "14. X.509 Signatures & OCSP/CRL", test_remediation_x509_signatures);
    lit::run_case(runner, "15. Handshake PHA, Boundary & ECH", test_remediation_misc);
    lit::run_case(runner, "16. Record Unified AEAD Dispatch", test_remediation_record_aead);
    lit::run_case(runner, "17. Live TLS 1.3 Transport, Handshake Orchestration & Session Tickets", test_live_tls_transport_session);

    let ok = lit::finish(runner);
    assert(ok);
}
