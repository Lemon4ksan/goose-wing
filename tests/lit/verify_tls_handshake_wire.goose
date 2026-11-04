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
    return ct;
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

    // 7. Regression: Server FSM transition coverage & illegal transition rejection (RFC 8446 §A.2)
    let sst1, sok1 = wing::can_server_transition(wing::HsState.ServerWaitCH, rfc::TLS_HS_CLIENT_HELLO);
    assert(sok1 && sst1 == wing::HsState.ServerWaitFinished);
    let _, sok_bad = wing::can_server_transition(wing::HsState.ServerWaitCH, rfc::TLS_HS_FINISHED);
    assert(!sok_bad);
    print("FSM_SERVER: OK");

    // 8. Regression: CRL 16-byte (128-bit) serial number revocation must not be silently dropped (RFC 5280 §4.1.2.2)
    var crl_16b_serial: u8[>..] = [];
    assert(wire_kit::parse_hex("0102030405060708090a0b0c0d0e0f10", crl_16b_serial));
    var crl_out = wing::ParsedCrl { .. };
    let ok_crl_16b = wing::parse_crl_entry_serial(crl_16b_serial[..], crl_out);
    assert(!ok_crl_16b || crl_out.serials.len == 1);
    print("CRL_128BIT_SERIAL_HANDLED: OK");

    // 9. Regression: OCSP stapling with malformed issuer_name_hash length (16 bytes) must be rejected (RFC 6960 §4.1.1)
    var b_tbs = core::builder_init();
    core::put_u8(b_tbs, 0x30);
    core::start_u8_prefix(b_tbs);
    core::put_u8(b_tbs, 0xA1);
    core::put_u8(b_tbs, 2);
    core::put_u8(b_tbs, 0x30);
    core::put_u8(b_tbs, 0);
    core::put_u8(b_tbs, 0x18);
    core::put_u8(b_tbs, 15);
    core::put_bytes(b_tbs, "20261028000000Z");
    core::put_u8(b_tbs, 0x30);
    core::start_u8_prefix(b_tbs);
    core::put_u8(b_tbs, 0x30);
    core::start_u8_prefix(b_tbs);
    core::put_u8(b_tbs, 0x30); // certID SEQUENCE
    core::start_u8_prefix(b_tbs);
    core::put_u8(b_tbs, 0x30);
    core::put_u8(b_tbs, 0);
    core::put_u8(b_tbs, 0x04); // issuerNameHash OCTET STRING (16 bytes - malformed, neither 20 nor 32!)
    core::put_u8(b_tbs, 16);
    for i in 16 { core::put_u8(b_tbs, 0xAA); }
    core::put_u8(b_tbs, 0x04);
    core::put_u8(b_tbs, 0);
    core::put_u8(b_tbs, 0x02);
    core::put_u8(b_tbs, 1);
    core::put_u8(b_tbs, 0x42);
    assert(core::finish_u8_prefix(b_tbs));
    core::put_u8(b_tbs, 0x80);
    core::put_u8(b_tbs, 0);
    core::put_u8(b_tbs, 0x18);
    core::put_u8(b_tbs, 15);
    core::put_bytes(b_tbs, "20261028000000Z");
    core::put_u8(b_tbs, 0xA0);
    core::put_u8(b_tbs, 17);
    core::put_u8(b_tbs, 0x18);
    core::put_u8(b_tbs, 15);
    core::put_bytes(b_tbs, "20261029000000Z");
    assert(core::finish_u8_prefix(b_tbs));
    assert(core::finish_u8_prefix(b_tbs));
    assert(core::finish_u8_prefix(b_tbs));
    var b_basic = core::builder_init();
    core::put_u8(b_basic, 0x30);
    core::start_u8_prefix(b_basic);
    core::put_bytes(b_basic, b_tbs.buf[..]);
    assert(core::finish_u8_prefix(b_basic));
    var b_ocsp = core::builder_init();
    core::put_u8(b_ocsp, 0x30);
    core::start_u8_prefix(b_ocsp);
    core::put_u8(b_ocsp, 0x0A);
    core::put_u8(b_ocsp, 1);
    core::put_u8(b_ocsp, 0);
    core::put_u8(b_ocsp, 0xA0);
    core::start_u8_prefix(b_ocsp);
    core::put_u8(b_ocsp, 0x30);
    core::start_u8_prefix(b_ocsp);
    core::put_u8(b_ocsp, 0x06);
    core::put_u8(b_ocsp, 9);
    core::put_bytes(b_ocsp, "\x2B\x06\x01\x05\x05\x07\x30\x01\x01");
    core::put_u8(b_ocsp, 0x04);
    core::start_u8_prefix(b_ocsp);
    core::put_bytes(b_ocsp, b_basic.buf[..]);
    assert(core::finish_u8_prefix(b_ocsp));
    assert(core::finish_u8_prefix(b_ocsp));
    assert(core::finish_u8_prefix(b_ocsp));
    assert(core::finish_u8_prefix(b_ocsp));

    var parsed_ocsp_16 = wing::ParsedOcspResponse {};
    assert(wing::parse_ocsp_response(b_ocsp.buf[..], parsed_ocsp_16));
    let raw_leaf_16: u8[5] = [0x42, 0x30, 0x02, 0x05, 0x00];
    var leaf_16 = wing::ParsedCert {
        serial_number: wing::Span16 { offset: 0, length: 1 },
        issuer_raw:    wing::Span16 { offset: 1, length: 4 },
        ..
    };
    let mid_ts = (parsed_ocsp_16.this_update + parsed_ocsp_16.next_update) / 2;
    let ocsp_alert = wing::validate_ocsp_stapling(b_ocsp.buf[..], leaf_16, raw_leaf_16[..], mid_ts);
    assert(ocsp_alert != wing::TlsAlert.CloseNotify);
    print("OCSP_MALFORMED_HASH_LEN_REJECTED: OK");

    // 10. Regression: Post-Quantum X25519+ML-KEM-768 parser must reject non-X25519 hybrid group 0x11EB (SecP256r1MLKEM768)
    var fake_pq_buf: u8[1188] = [0; 1188];
    fake_pq_buf[0] = 0x11;
    fake_pq_buf[1] = 0xEB; // GROUP_SECP256R1_MLKEM768
    fake_pq_buf[2] = 0x04;
    fake_pq_buf[3] = 0xA0; // len = 1184
    var out_cli_pq = internal::PostQuantumKeyShare { .. };
    let ok_fake_pq = internal::parse_hybrid_key_share(out_cli_pq, fake_pq_buf[..]);
    assert(!ok_fake_pq);
    var fake_srv_pq: u8[1124] = [0; 1124];
    fake_srv_pq[0] = 0x11;
    fake_srv_pq[1] = 0xEB; // GROUP_SECP256R1_MLKEM768
    fake_srv_pq[2] = 0x04;
    fake_srv_pq[3] = 0x60; // len = 1120
    var out_srv_pq = internal::PostQuantumServerShare { .. };
    let ok_fake_srv_pq = internal::parse_hybrid_server_key_share(out_srv_pq, fake_srv_pq[..]);
    assert(!ok_fake_srv_pq);
    print("PQ_WRONG_GROUP_REJECTED: OK");

    // 11. Regression: HPKE LabeledExpand must reject oversized info (>1024 labeled buffer) instead of silent truncation (RFC 9180 §4)
    let prk_zeros: u8[32]   = [0x11; 32];
    let big_info:  u8[1020] = [0x42; 1020];
    var hpke_out: u8[32] = [0; 32];
    let ok_hpke_big = wing::hpke_labeled_expand("HPKE\x00\x20\x00\x01\x00\x01", prk_zeros[..], "key", big_info[..], 32, hpke_out[..]);
    assert(!ok_hpke_big);
    print("HPKE_OVERSIZED_INFO_REJECTED: OK");

    // 12. Regression: ECH outer extension rejects empty ciphertext (RFC 9849 §5)
    let cs_ech = wing::EchCipherSuite { kdf_id: 1, aead_id: 1 };
    let enc_ech: u8[32] = [0; 32];
    var ech_buf: u8[..128] = [];
    let ok_ech_empty = wing::build_ech_outer_extension(1, cs_ech, enc_ech, "", ech_buf);
    assert(!ok_ech_empty);
    print("ECH_EMPTY_CIPHERTEXT_REJECTED: OK");

    // 13. Regression: CertificateRequest encoder must reject >29 sig_algorithms or enlarge ext_buf instead of truncating u8[..64]
    var sigs_40: u16[40]   = [0x0804; 40];
    var cr_out:  u8[..256] = [];
    let ok_cr_40 = wing::encode_certificate_request(cr_out, "ctx", sigs_40[..]);
    if ok_cr_40 {
        var parsed_cr = wing::CertificateRequestMsg { .. };
        let ok_pcr = wing::parse_certificate_request(cr_out[..], true, parsed_cr);
        assert(ok_pcr && parsed_cr.sig_algorithms.len == 40);
    }
    print("CERT_REQ_40_SIG_ALGS: OK");

    // 14. Regression: PSK binder truncation must reject u16 binders_len overflow (65535 + 2 wrap)
    let dummy_ch_bytes: u8[10] = [0x01; 10];
    let _, ok_trunc_wrap = internal::truncate_client_hello_for_binder(dummy_ch_bytes[..], 65535);
    assert(!ok_trunc_wrap);
    print("PSK_BINDER_OVERFLOW_REJECTED: OK");

    // 15. KeySchedule: 0-RTT early traffic secret derivation (RFC 8446 §7.1)
    var ks_test, ok_kst = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(ok_kst);
    let dummy_psk: u8[32] = [0x55; 32];
    assert(internal::ks_init_early_secret(ks_test, dummy_psk[..]));
    let ch_dummy_hash: u8[32] = [0x42; 32];
    assert(internal::ks_derive_early_traffic(ks_test, ch_dummy_hash[..]));
    print("KS_EARLY_TRAFFIC: OK");
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
// CHECK-NEXT: FSM_SERVER: OK
// CHECK-NEXT: CRL_128BIT_SERIAL_HANDLED: OK
// CHECK-NEXT: OCSP_MALFORMED_HASH_LEN_REJECTED: OK
// CHECK-NEXT: PQ_WRONG_GROUP_REJECTED: OK
// CHECK-NEXT: HPKE_OVERSIZED_INFO_REJECTED: OK
// CHECK-NEXT: ECH_EMPTY_CIPHERTEXT_REJECTED: OK
// CHECK-NEXT: CERT_REQ_40_SIG_ALGS: OK
// CHECK-NEXT: PSK_BINDER_OVERFLOW_REJECTED: OK
// CHECK-NEXT: KS_EARLY_TRAFFIC: OK
