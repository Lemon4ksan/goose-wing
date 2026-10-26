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
    };

    t.run("TLS-05: Nonce XOR Derivation") { sub =>
        var iv: u8[12] = [
            0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33
        ];
        // Seq num = 1 -> nonce[11] ^= 1 -> 0x33 ^ 1 = 0x32
        let nonce1 = wing::compute_record_nonce(iv, 1);
        sub.assert_eq(nonce1[0], 0x10, "nonce[0] unchanged");
        sub.assert_eq(nonce1[3], 0x13, "nonce[3] unchanged");
        sub.assert_eq(nonce1[11], 0x32, "nonce[11] XORed with 1");

        // Seq num = 0x0102 -> nonce[10] ^= 0x01, nonce[11] ^= 0x02
        let nonce2 = wing::compute_record_nonce(iv, 0x0102);
        sub.assert_eq(nonce2[10], 0x32 ^ 0x01, "nonce[10] XORed with 0x01");
        sub.assert_eq(nonce2[11], 0x33 ^ 0x02, "nonce[11] XORed with 0x02");
    };

    t.run("TLS-06: TLSInnerPlaintext Unpacking & Trailing Padding Removal") { sub =>
        // Payload: "Hello World" (11 bytes) || ContentType: ApplicationData (0x17) || 4 zeroes padding
        let decrypted: u8[16] = [
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
            0x17, // true type
            0x00, 0x00, 0x00, 0x00 // padding
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
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
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

        // 2. Advance to Handshake with mock ECDHE secret (32 bytes)
        let ecdhe_secret: u8[32] = [0x42; 32];
        let ok_hs = internal::ks_advance_to_handshake(sched, ecdhe_secret[..]);
        sub.assert_true(ok_hs, "advance to handshake ok");
        sub.assert_eq(sched.stage, internal::KS_STAGE_HANDSHAKE, "stage is handshake");

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
            app_iv
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
            verify_data[..]
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
            "secp256r1 scheme binds to P-256 SPKI"
        );
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256, wing::OID_SECP384R1[..]),
            "secp256r1 scheme rejects P-384 SPKI"
        );

        // Ed25519 requires Ed25519 OID
        sub.assert_true(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_ED25519, wing::OID_ED25519[..]),
            "ed25519 binds to ed25519 SPKI"
        );

        // Strict RFC 8446 Invariant: Legacy PKCS#1 v1.5 RSA schemes MUST be rejected in CertificateVerify
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_RSA_PKCS1_SHA256, wing::OID_RSA_ENCRYPTION[..]),
            "legacy PKCS#1 RSA is strictly forbidden in TLS 1.3 CertificateVerify"
        );
        sub.assert_false(
            wing::verify_signature_scheme_curve_binding(wing::SIG_SCHEME_RSA_PKCS1_SHA384, wing::OID_RSA_ENCRYPTION[..]),
            "legacy PKCS#1 SHA384 is strictly forbidden in TLS 1.3 CertificateVerify"
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

    let ok = core::finish(runner);
    assert(ok);
}
