// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_tls_handshake_wire.goose
// Verification of TLS 1.3 Handshake FSM Transitions, Record Layer Invariants, and Overflow Defenses.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn parse_tls_record_step(buf: const u8[:]) -> i64 {
    guard buf.len >= 5 else { return -1; }
    let ct, _, len, alert, ok = wing::parse_tls_record_header(buf);
    guard ok else {
        if alert == wing::TlsAlert.RecordOverflow {
            return -22;
        }
        if alert == wing::TlsAlert.ProtocolVersion {
            return -70;
        }
        return -2;
    }
    guard buf.len >= 5 + (len as i64) else { return -1; }
    return ct as! i64;
}

fn main() {
    print("=== TLS_HANDSHAKE_AND_RECORD_VERIFICATION ===");

    // 1. Client handshake state machine progression (RFC 8446 §4)
    let st1, ok1 = wing::can_client_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_SERVER_HELLO);
    assert(ok1 && st1 == wing::HsState.ClientWaitEE);
    print("FSM_CLIENT: ClientWaitSH -> ClientWaitEE");

    let st2, ok2 = wing::can_client_transition(wing::HsState.ClientWaitEE, rfc::TLS_HS_ENCRYPTED_EXTENSIONS);
    assert(ok2 && st2 == wing::HsState.ClientWaitCertCr);
    print("FSM_CLIENT: ClientWaitEE -> ClientWaitCertCr");

    let st3, ok3 = wing::can_client_transition(wing::HsState.ClientWaitCertCr, rfc::TLS_HS_CERTIFICATE);
    assert(ok3 && st3 == wing::HsState.ClientWaitCV);
    print("FSM_CLIENT: ClientWaitCertCr -> ClientWaitCV");

    let st4, ok4 = wing::can_client_transition(wing::HsState.ClientWaitCV, rfc::TLS_HS_CERTIFICATE_VERIFY);
    assert(ok4 && st4 == wing::HsState.ClientWaitFinished);
    print("FSM_CLIENT: ClientWaitCV -> ClientWaitFinished");

    let st5, ok5 = wing::can_client_transition(wing::HsState.ClientWaitFinished, rfc::TLS_HS_FINISHED);
    assert(ok5 && st5 == wing::HsState.Connected);
    print("FSM_CLIENT: ClientWaitFinished -> Connected");

    // 2. Illegal handshake transition: unexpected Finished in ClientWaitSH
    let _, ok_inv = wing::can_client_transition(wing::HsState.ClientWaitSH, rfc::TLS_HS_FINISHED);
    assert(!ok_inv);
    print("ILLEGAL_TRANSITION: REJECTED");

    // 3. HelloRetryRequest detection & synthetic message_hash compression (RFC 8446 §4.4.1)
    assert(wing::is_hello_retry_request(rfc::HRR_RANDOM));
    var arbitrary_rand: u8[32] = [0x55; 32];
    assert(!wing::is_hello_retry_request(arbitrary_rand));
    print("HRR_RANDOM_DETECTION: OK");

    let ch1_hash: u8[32] = [0xAA; 32];
    var synthetic_msg: u8[36] = [0; 36];
    let written, ok_comp = wing::compress_hrr_transcript(32, ch1_hash[..], synthetic_msg[..]);
    assert(ok_comp && written == 36);
    assert(synthetic_msg[0] == 0xFE); // message_hash pseudo-handshake type
    print("SYNTHETIC_MESSAGE_HASH: OK");

    // 4. Record layer header parsing: Handshake record
    var valid_hs_rec: u8[>..] = [];
    assert(wire_kit::parse_hex("16030300050102030405", valid_hs_rec));
    assert(parse_tls_record_step(valid_hs_rec[..]) == 22);
    assert(wire_kit::verify_split_stream(valid_hs_rec[..], -1, 22, parse_tls_record_step));
    assert(wire_kit::fuzz_payload(valid_hs_rec[..], 200, parse_tls_record_step));
    print("TLS_RECORD_SPLIT_AND_FUZZ: PASS");

    // 5. Record overflow defense: length 16641 (> 16640)
    var overflow_rec: u8[>..] = [];
    assert(wire_kit::parse_hex("1703034101", overflow_rec));
    assert(parse_tls_record_step(overflow_rec[..]) == -22);
    print("TLS_RECORD_OVERFLOW: ALERT_22");

    // 6. Incompatible legacy record version: 0x0304 forbidden in legacy_record_version
    var v13_rec: u8[>..] = [];
    assert(wire_kit::parse_hex("1703040010", v13_rec));
    assert(parse_tls_record_step(v13_rec[..]) == -70);
    print("TLS_RECORD_VERSION_BAN: ALERT_70");
}

// CHECK-LABEL: === TLS_HANDSHAKE_AND_RECORD_VERIFICATION ===
// CHECK-NEXT: FSM_CLIENT: ClientWaitSH -> ClientWaitEE
// CHECK-NEXT: FSM_CLIENT: ClientWaitEE -> ClientWaitCertCr
// CHECK-NEXT: FSM_CLIENT: ClientWaitCertCr -> ClientWaitCV
// CHECK-NEXT: FSM_CLIENT: ClientWaitCV -> ClientWaitFinished
// CHECK-NEXT: FSM_CLIENT: ClientWaitFinished -> Connected
// CHECK-NEXT: ILLEGAL_TRANSITION: REJECTED
// CHECK-NEXT: HRR_RANDOM_DETECTION: OK
// CHECK-NEXT: SYNTHETIC_MESSAGE_HASH: OK
// CHECK-NEXT: TLS_RECORD_SPLIT_AND_FUZZ: PASS
// CHECK-NEXT: TLS_RECORD_OVERFLOW: ALERT_22
// CHECK-NEXT: TLS_RECORD_VERSION_BAN: ALERT_70
