// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_tls_resumption_0rtt.goose
// Verification of TLS 1.3 Session Resumption & 0-RTT Early Data Mechanics (RFC 8446 §4.2.10, §4.6.1).
// Tests NewSessionTicket codec, resumption PSK derivation, two-epoch Bloom filter strike register,
// ticket age de-obfuscation, and 0-RTT traffic controllers under OpenSSL Bug #31406 invariants.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn test_new_session_ticket_codec() {
    var raw_nst: u8[..256] = [];
    let nonce:       u8[8]       = [1, 2, 3, 4, 5, 6, 7, 8];
    let ticket_body: const u8[:] = "encrypted_session_ticket_payload_bytes";

    // Encode NST with 1 hour lifetime (3600s), age_add = 0x12345678, max_early_data = 16384
    let enc_ok = wing::encode_new_session_ticket(raw_nst, 3600, 0x12345678, nonce[..], ticket_body, 16384);
    assert(enc_ok);
    assert(raw_nst.len > 0);
    print("NST_ENCODE: OK");

    var nst = wing::NewSessionTicketMsg { .. };
    let dec_ok = wing::parse_new_session_ticket(raw_nst[..], nst);
    assert(dec_ok);
    assert(nst.ticket_lifetime == 3600);
    assert(nst.ticket_age_add == 0x12345678);
    assert(nst.has_early_data);
    assert(nst.max_early_data_size == 16384);
    assert(nst.ticket_nonce.len == 8);
    print("NST_DECODE_ROUNDTRIP: OK");
}

fn test_strike_register_anti_replay() {
    var reg = internal::strike_register_init(10000, 2000);
    let ticket_id: const u8[:] = "unique_session_ticket_id_alpha";

    // First presentation at t = 1000 ms: MUST be accepted
    let first_check = internal::strike_register_check_and_insert(reg, ticket_id, 1000);
    assert(first_check);
    print("STRIKE_REG_FIRST_INSERT: OK");

    // Immediate replay of same ticket at t = 1050 ms: MUST be rejected
    let replay_check = internal::strike_register_check_and_insert(reg, ticket_id, 1050);
    assert(!replay_check);
    print("STRIKE_REG_REPLAY_DETECTED: OK");

    // Advance time to next epoch (t = 12000 ms): ticket is in previous window, STILL REJECTED
    let next_epoch_replay = internal::strike_register_check_and_insert(reg, ticket_id, 12000);
    assert(!next_epoch_replay);
    print("STRIKE_REG_PREV_EPOCH_REPLAY_DETECTED: OK");

    // Unrelated ticket in new epoch MUST be accepted
    let new_ticket: const u8[:] = "fresh_ticket_beta";
    let new_check = internal::strike_register_check_and_insert(reg, new_ticket, 12000);
    assert(new_check);
    print("STRIKE_REG_FRESH_TICKET_ACCEPTED: OK");
}

fn test_ticket_age_validation() {
    let ticket_age_add: u32 = 0x50000000;
    let actual_age_ms:  i64 = 5000; // 5 seconds
    let obfuscated_age: u32 = (actual_age_ms as u32) + ticket_age_add;

    // Expected age matches actual age within 2000ms tolerance
    let ok_match = internal::validate_ticket_age(obfuscated_age, ticket_age_add, 5000, 2000);
    assert(ok_match);
    print("TICKET_AGE_VALID: OK");

    // Clock skew / delay exceeding tolerance (expected 1000ms vs actual 5000ms) -> MUST FAIL
    let bad_skew = internal::validate_ticket_age(obfuscated_age, ticket_age_add, 1000, 2000);
    assert(!bad_skew);
    print("TICKET_AGE_SKEW_REJECTED: OK");
}

fn test_0rtt_controller_lifecycle() {
    var ctrl = wing::EarlyDataController {
        state:                   wing::EarlyDataState.Offered,
        max_early_data_size:     1000,
        psk_cipher_suite:        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        negotiated_cipher_suite: rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        ..
    };

    // Send 500 bytes of early data (under 1000 limit)
    assert(wing::early_data_record_sent(ctrl, 500));
    assert(ctrl.bytes_sent == 500);

    // Try sending 600 bytes (500 + 600 = 1100 > 1000 limit) -> MUST FAIL
    assert(!wing::early_data_record_sent(ctrl, 600));
    assert(ctrl.bytes_sent == 500);
    print("0RTT_SIZE_LIMIT_ENFORCED: OK");

    // Server accepts early data in EncryptedExtensions with matching cipher
    assert(wing::early_data_on_encrypted_extensions(ctrl, true));
    assert(ctrl.state == wing::EarlyDataState.Accepted);
    assert(wing::early_data_can_send_eoed(ctrl));
    print("0RTT_ACCEPTED_LIFECYCLE: OK");

    // Test OpenSSL Bug #31406: Cipher mismatch between PSK and server selection MUST be rejected
    var ctrl_mismatch = wing::EarlyDataController {
        state:                   wing::EarlyDataState.Offered,
        max_early_data_size:     1000,
        psk_cipher_suite:        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        negotiated_cipher_suite: rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256,
        ..
    };
    let accepted = wing::early_data_on_encrypted_extensions(ctrl_mismatch, true);
    assert(!accepted);
    assert(ctrl_mismatch.state == wing::EarlyDataState.Rejected);
    assert(ctrl_mismatch.keys_discarded);
    print("0RTT_CIPHER_MISMATCH_REJECTED: OK");
}

fn main() {
    print("=== RUNNING TLS 1.3 RESUMPTION & 0-RTT SUITE ===");
    test_new_session_ticket_codec();
    test_strike_register_anti_replay();
    test_ticket_age_validation();
    test_0rtt_controller_lifecycle();
    print("TLS 1.3 RESUMPTION & 0-RTT COMPLETE: ALL INVARIANTS PASSED");
}

// CHECK: === RUNNING TLS 1.3 RESUMPTION & 0-RTT SUITE ===
// CHECK: NST_ENCODE: OK
// CHECK: NST_DECODE_ROUNDTRIP: OK
// CHECK: STRIKE_REG_FIRST_INSERT: OK
// CHECK: STRIKE_REG_REPLAY_DETECTED: OK
// CHECK: STRIKE_REG_PREV_EPOCH_REPLAY_DETECTED: OK
// CHECK: STRIKE_REG_FRESH_TICKET_ACCEPTED: OK
// CHECK: TICKET_AGE_VALID: OK
// CHECK: TICKET_AGE_SKEW_REJECTED: OK
// CHECK: 0RTT_SIZE_LIMIT_ENFORCED: OK
// CHECK: 0RTT_ACCEPTED_LIFECYCLE: OK
// CHECK: 0RTT_CIPHER_MISMATCH_REJECTED: OK
// CHECK: TLS 1.3 RESUMPTION & 0-RTT COMPLETE: ALL INVARIANTS PASSED
