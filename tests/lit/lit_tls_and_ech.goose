// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_tls_and_ech
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. verify_tls_handshake_wire (1/7)
// ============================================================================
// CHECK: === [1/7] verify_tls_handshake_wire ===

// tests/lit/verify_tls_handshake_wire.goose
// Verification of TLS 1.3 Handshake FSM Transitions, Record Layer Invariants, and Overflow Defenses.
//

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

fn run_01_verify_tls_handshake_wire() {
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
    var fake_pq_buf: u8[1220] = [0; 1220];
    fake_pq_buf[0] = 0x11;
    fake_pq_buf[1] = 0xEB; // GROUP_SECP256R1_MLKEM768
    fake_pq_buf[2] = 0x04;
    fake_pq_buf[3] = 0xC0; // len = 1216
    var out_cli_pq = tls_internal::PostQuantumKeyShare { .. };
    let ok_fake_pq = tls_internal::parse_hybrid_key_share(out_cli_pq, fake_pq_buf[..]);
    assert(!ok_fake_pq);
    var fake_srv_pq: u8[1124] = [0; 1124];
    fake_srv_pq[0] = 0x11;
    fake_srv_pq[1] = 0xEB; // GROUP_SECP256R1_MLKEM768
    fake_srv_pq[2] = 0x04;
    fake_srv_pq[3] = 0x60; // len = 1120
    var out_srv_pq = tls_internal::PostQuantumServerShare { .. };
    let ok_fake_srv_pq = tls_internal::parse_hybrid_server_key_share(out_srv_pq, fake_srv_pq[..]);
    assert(!ok_fake_srv_pq);
    print("PQ_WRONG_GROUP_REJECTED: OK");

    // 11. Regression: HPKE LabeledExpand accepts 1500B info (RFC 9180 §7.2.1) and rejects >4096 labeled buffer without truncation, plus Export-Only AEAD (0xFFFF)
    let prk_zeros: u8[32]   = [0x11; 32];
    let ok_info:   u8[1500] = [0x42; 1500];
    let big_info:  u8[4090] = [0x42; 4090];
    var hpke_out: u8[32] = [0; 32];
    assert(wing::hpke_labeled_expand("HPKE\x00\x20\x00\x01\x00\x01", prk_zeros[..], "key", ok_info[..], 32, hpke_out[..]));
    let ok_hpke_big = wing::hpke_labeled_expand("HPKE\x00\x20\x00\x01\x00\x01", prk_zeros[..], "key", big_info[..], 32, hpke_out[..]);
    assert(!ok_hpke_big);
    let exp_sk1: u8[32] = [0x21; 32];
    let exp_sk2: u8[32] = [0x22; 32];
    let exp_pk = core::x25519_base_scalarmult(exp_sk1);
    var exp_enc: u8[32] = [0; 32];
    var exp_ctx = wing::HpkeContext { .. };
    assert(wing::hpke_setup_base_s(
        exp_pk,
        "export-info",
        rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
        rfc::HPKE_KDF_HKDF_SHA256,
        wing::HPKE_AEAD_EXPORT_ONLY,
        exp_sk2,
        exp_enc,
        exp_ctx,
    ));
    assert(wing::hpke_export(exp_ctx, "tls-exporter", hpke_out[..]));
    var seal_ct: u8[..64] = [];
    assert(!wing::hpke_seal(exp_ctx, "", "msg", seal_ct));
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
    let _, ok_trunc_wrap = tls_internal::truncate_client_hello_for_binder(dummy_ch_bytes[..], 65535);
    assert(!ok_trunc_wrap);
    print("PSK_BINDER_OVERFLOW_REJECTED: OK");

    // 15. KeySchedule: 0-RTT early traffic secret derivation (RFC 8446 §7.1)
    var ks_test, ok_kst = tls_internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(ok_kst);
    let dummy_psk: u8[32] = [0x55; 32];
    assert(tls_internal::ks_init_early_secret(ks_test, dummy_psk[..]));
    let ch_dummy_hash: u8[32] = [0x42; 32];
    assert(tls_internal::ks_derive_early_traffic(ks_test, ch_dummy_hash[..]));
    print("KS_EARLY_TRAFFIC: OK");

    // 16. Regression (TLS-BUG-001): ks_update_traffic_secret must use HKDF-Expand-Label(secret, "traffic upd", "", L) per RFC 8446 §7.2
    var ts_upd:          u8[32] = [0x77; 32];
    var expected_ts_upd: u8[32] = [0; 32];
    assert(tls_internal::hkdf_expand_label(tls_internal::HASH_SHA256, ts_upd[..], "traffic upd", [], 32, expected_ts_upd[..]));
    assert(tls_internal::ks_update_traffic_secret(tls_internal::HASH_SHA256, 32, ts_upd[..]));
    assert(core::ct_eq_bytes(ts_upd[..], expected_ts_upd[..]));
    print("KS_UPDATE_TRAFFIC_RFC8446: OK");

    // 17. Regression (TLS-BUG-002): extract_leaf_ocsp_extension must reject malformed CertificateEntry extension blocks
    let bad_cert_ext: u8[3] = [0x00, 0x05, 0xFF];
    let _, ok_bad_ocsp_ext = wing::extract_leaf_ocsp_extension(bad_cert_ext[..]);
    assert(!ok_bad_ocsp_ext);
    print("LEAF_OCSP_EXT_REJECT_MALFORMED: OK");

    // 18. Regression (TLS-BUG-003): x509_verify_cert_signature must reject unhandled signature algorithm OIDs
    let fake_cert_raw: u8[16] = [0x30, 0x03, 0x02, 0x01, 0x01, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D, 0xAA, 0xBB];
    let child_unhandled = wing::ParsedCert {
        tbs_cert:        wing::Span16 { offset: 0, length: 5 },
        sig_alg_oid:     wing::Span16 { offset: 5, length: 9 },
        signature_value: wing::Span16 { offset: 14, length: 2 },
        ..
    };
    let parent_dummy = wing::ParsedCert {
        spki_pubkey: wing::Span16 { offset: 0, length: 5 },
        ..
    };
    let sig_alert = wing::x509_verify_cert_signature(child_unhandled, fake_cert_raw[..], parent_dummy, fake_cert_raw[..]);
    assert(sig_alert != wing::TlsAlert.CloseNotify);
    print("X509_UNHANDLED_SIG_OID_REJECTED: OK");

    // 19. Regression (TLS-BUG-005 & TLS-BUG-006): ECH public_name leading/consecutive dots & KeyShare u16 wraparound
    assert(!wing::validate_ech_public_name_bytes(".example.com"));
    assert(!wing::validate_ech_public_name_bytes("a..b.com"));
    assert(!wing::validate_ech_public_name_bytes("-bad.example.com"));
    var early_ctrl = wing::EarlyDataController {
        state:                   wing::EarlyDataState.Offered,
        psk_cipher_suite:        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        negotiated_cipher_suite: 0,
        ..
    };
    assert(!wing::early_data_on_encrypted_extensions(early_ctrl, true));
    print("ECH_AND_EARLY_DATA_GUARDS: OK");

    // 20. Regression (TLS-BUG-007 & TLS-BUG-008): HPKE sequence overflow / unknown aead_id & StrikeRegister previous-epoch replay
    var hpke_ctx = wing::HpkeContext {
        aead_id: rfc::HPKE_AEAD_AES_128_GCM,
        seq:     0xFFFFFFFFFFFFFFFF,
        ..
    };
    var hpke_ct: u8[..64] = [];
    assert(!wing::hpke_seal(hpke_ctx, "", "hello", hpke_ct));
    var sreg = tls_internal::strike_register_init(1000, 10000);
    assert(tls_internal::strike_register_check_and_insert(sreg, "init-epoch-10", 10000));
    assert(tls_internal::strike_register_check_and_insert(sreg, "ticket-prev-epoch", 9500));
    assert(!tls_internal::strike_register_check_and_insert(sreg, "ticket-prev-epoch", 11000));
    print("HPKE_AND_STRIKE_REGISTER_GUARDS: OK");

    // 21. Regression (TLS-BUG-010 & TLS-BUG-012): Header capacity guard & X.509 pathLenConstraint > 255 / duplicate extension rejection
    var tiny_hdr: u8[..4] = [];
    assert(!wing::encode_tls_ciphertext_header(tiny_hdr, 23, 32));
    var bc_cert = wing::ParsedCert { path_len_constraint: -1, .. };
    let bc_ext_256: u8[9] = [0x30, 0x07, 0x01, 0x01, 0xFF, 0x02, 0x02, 0x01, 0x00];
    var bc_cur = core::cursor_from(bc_ext_256[..]);
    wing::x509_parse_basic_constraints_ext(bc_cur, bc_cert);
    assert(bc_cert.path_len_constraint == 255 || bc_cert.has_unsupported_critical);
    print("RECORD_AND_X509_BC_GUARDS: OK");

    // 22. Wave 1 Track D [TLSC-03]: Post-Handshake CertificateRequest non-empty context & PHA extension
    var pha_ext: u8[..8] = [];
    wing::encode_post_handshake_auth_extension(pha_ext);
    assert(pha_ext.len == 4 && pha_ext[0] == 0x00 && pha_ext[1] == 0x31 && pha_ext[2] == 0x00 && pha_ext[3] == 0x00);
    let sig_ed: u16[1] = [rfc::SIG_SCHEME_ED25519];
    var cr_empty_ctx: u8[..64] = [];
    assert(wing::encode_certificate_request(cr_empty_ctx, "", sig_ed[..]));
    var parsed_pha_cr = wing::CertificateRequestMsg { .. };
    assert(!wing::parse_certificate_request(cr_empty_ctx[..], true, parsed_pha_cr));
    assert(wing::parse_certificate_request(cr_empty_ctx[..], false, parsed_pha_cr));
    var cr_nonempty_ctx: u8[..64] = [];
    assert(wing::encode_certificate_request(cr_nonempty_ctx, "pha-ctx-1", sig_ed[..]));
    assert(wing::parse_certificate_request(cr_nonempty_ctx[..], true, parsed_pha_cr));
    assert(parsed_pha_cr.context[..] == "pha-ctx-1");
    print("POST_HANDSHAKE_AUTH_CONTEXT_GUARD: OK");

    // 23. Wave 1 Track D [TLSC-06]: Stateless STEK Ticket Seal/Open & Dual-Key Rotation
    var ring = wing::TlsTicketKeyRing {
        keys: [
            wing::TlsTicketStek {
                key_name:     [0xAA, 0xBB, 0xCC, 0x01],
                aead_key:     [0x11; 32],
                created_sec:  1000,
                lifetime_sec: 3600,
                active:       true,
            },
            wing::TlsTicketStek {
                key_name:     [0xAA, 0xBB, 0xCC, 0x02],
                aead_key:     [0x22; 32],
                created_sec:  2000,
                lifetime_sec: 3600,
                active:       true,
            },
        ],
        current_idx: 0,
    };
    var psk_in: u8[..48] = [];
    for i in 32 { psk_in.push((i + 1) as u8); }
    let ticket_iv: u8[12] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    var sealed_ticket: u8[..128] = [];
    assert(wing::seal_stateless_tls13_ticket(ring, psk_in, rfc::TLS_CIPHER_AES_128_GCM_SHA256, 1000000, ticket_iv, sealed_ticket));
    assert(sealed_ticket.len == 95);
    // Rotate active key to slot 1; ticket sealed under slot 0 must still open cleanly
    ring.current_idx = 1;
    let opened_tkt, ok_open_tkt = wing::open_stateless_tls13_ticket(ring, sealed_ticket[..], 1005000);
    assert(ok_open_tkt && opened_tkt.in_use && opened_tkt.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(core::ct_eq_bytes(opened_tkt.psk[..], psk_in[..]));
    // 48-byte SHA-384 PSK stateless ticket round-trip without truncation
    var psk_48: u8[..48] = [];
    for i in 48 { psk_48.push((0x80 + i) as u8); }
    var sealed_ticket_48: u8[..128] = [];
    assert(wing::seal_stateless_tls13_ticket(ring, psk_48, rfc::TLS_CIPHER_AES_256_GCM_SHA384, 1000000, ticket_iv, sealed_ticket_48));
    let opened_tkt_48, ok_open_48 = wing::open_stateless_tls13_ticket(ring, sealed_ticket_48[..], 1005000);
    assert(ok_open_48 && opened_tkt_48.psk.len == 48 && opened_tkt_48.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384);
    assert(core::ct_eq_bytes(opened_tkt_48.psk[..], psk_48[..]));
    // Expired ticket must be rejected
    let _, ok_exp_tkt = wing::open_stateless_tls13_ticket(ring, sealed_ticket[..], 1000000 + 3600001);
    assert(!ok_exp_tkt);
    print("STATELESS_STEK_ROTATION: OK");

    // 24. Wave 1 Track D [TLSMOD-002]: HRR Cookie & 2-Byte KeyShare Group Parsing
    var hrr_wire: u8[..256] = [];
    hrr_wire.push(rfc::TLS_HS_SERVER_HELLO);
    var hrr_body: u8[..256] = [];
    core::append_u16_be(hrr_body, rfc::TLS_LEGACY_VERSION_1_2);
    hrr_body.append(rfc::HRR_RANDOM[..]);
    hrr_body.push(0); // empty session_id
    core::append_u16_be(hrr_body, rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    hrr_body.push(0); // compression method 0
    var hrr_exts: u8[..128] = [];
    // supported_versions (43) -> TLS 1.3
    core::append_u16_be(hrr_exts, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    core::append_u16_be(hrr_exts, 2);
    core::append_u16_be(hrr_exts, rfc::TLS_VERSION_1_3);
    // key_share (51) -> 2-byte selected_group (X25519)
    core::append_u16_be(hrr_exts, rfc::TLS_EXT_KEY_SHARE);
    core::append_u16_be(hrr_exts, 2);
    core::append_u16_be(hrr_exts, rfc::GROUP_X25519);
    // cookie (44) -> "stateless-hrr-cookie"
    assert(wing::serialize_tls_cookie_extension(hrr_exts, "stateless-hrr-cookie"));
    core::append_u16_be(hrr_body, hrr_exts.len as u16);
    hrr_body.append(hrr_exts[..]);
    core::append_u24_be(hrr_wire, hrr_body.len as u32);
    hrr_wire.append(hrr_body[..]);

    var parsed_hrr = wing::ParsedServerHello { .. };
    assert(wing::parse_live_server_hello(hrr_wire[..], parsed_hrr));
    assert(parsed_hrr.is_hrr && parsed_hrr.selected_group == rfc::GROUP_X25519);
    assert(parsed_hrr.hrr_cookie[..] == "stateless-hrr-cookie");
    print("HRR_COOKIE_AND_GROUP_PARSE: OK");

    // 25. Wave 1 Track D [TLSMOD-004 & TLSMOD-007 & TLSMOD-008]: Dynamic Record Sizing, In-Place AEAD & Pre-Compressed Cert
    assert(wing::TLS_SINGLE_MSS_PLAINTEXT_LEN == 1378);
    assert(wing::TLS_DYNAMIC_RESIZE_THRESHOLD_BYTES == 65536);
    let rec_key: u8[16] = [0x33; 16];
    let rec_iv:  u8[12] = [0x44; 12];
    var rec_ct: u8[64] = [0; 64];
    let sealed_n, _, ok_rec_seal = wing::tls_record_seal_aes128_gcm_into(
        rec_key, rec_iv, 7, rfc::TLS_CONTENT_APPLICATION_DATA, "inplace-payload", rec_ct[..],
    );
    assert(ok_rec_seal && sealed_n == 5 + 15 + 1 + 16);
    var rec_pt: u8[64] = [0; 64];
    let dec_n, dec_inner, _, ok_rec_dec = wing::tls_record_decrypt_aes128_gcm_into(
        rec_key, rec_iv, 7, rec_ct[0..5], rec_ct[5..sealed_n], rec_pt[..],
    );
    assert(ok_rec_dec && dec_n == 15 && dec_inner == rfc::TLS_CONTENT_APPLICATION_DATA);
    assert(rec_pt[..dec_n] == "inplace-payload");

    let ch_rand: u8[32] = [0x11; 32];
    let ch_pub:  u8[32] = [0x22; 32];
    var ch_pay: u8[..1024] = [];
    wing::build_tls13_client_hello_payload(
        ch_rand, ch_pub, "example.com", "h2", ch_pay, "", 0, false, "", "", "cookie123", true,
    );
    var ch_full: u8[..1028] = [];
    ch_full.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_full, ch_pay.len as u32);
    ch_full.append(ch_pay[..]);
    let sel_comp = wing::select_server_cert_comp_algo(ch_full[..], rfc::CERT_COMPRESSION_BROTLI);
    assert(sel_comp == rfc::CERT_COMPRESSION_BROTLI);
    var srv_cfg = wing::TlsServerHandshakeConfig {
        compressed_cert_algo: rfc::CERT_COMPRESSION_BROTLI,
        ..
    };
    let _ = srv_cfg.cert_der.try_set("DUMMY_DER_CERT");
    let _ = srv_cfg.compressed_cert_data.try_set("COMPRESSED_BYTES");
    var comp_cert_hs: u8[..4096] = [];
    assert(wing::encode_server_cert_or_compressed_msg(srv_cfg, sel_comp, comp_cert_hs));
    assert(comp_cert_hs[0] == rfc::TLS_HS_COMPRESSED_CERTIFICATE);
    let exp_slot = wing::alloc_tls_cipher_slot();
    assert(exp_slot != 0xFFFF);
    var exp_out: u8[..256] = [];
    assert(wing::tls_session_export_keying_material(exp_slot, "EXPORTER-Channel-Binding", "ctx", 32, exp_out));
    assert(exp_out.len == 32);
    wing::free_tls_cipher_slot(exp_slot);
    print("DYNAMIC_RECORD_AND_COMPRESSED_CERT: OK");
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
// CHECK-NEXT: KS_UPDATE_TRAFFIC_RFC8446: OK
// CHECK-NEXT: LEAF_OCSP_EXT_REJECT_MALFORMED: OK
// CHECK-NEXT: X509_UNHANDLED_SIG_OID_REJECTED: OK
// CHECK-NEXT: ECH_AND_EARLY_DATA_GUARDS: OK
// CHECK-NEXT: HPKE_AND_STRIKE_REGISTER_GUARDS: OK
// CHECK-NEXT: RECORD_AND_X509_BC_GUARDS: OK
// CHECK-NEXT: POST_HANDSHAKE_AUTH_CONTEXT_GUARD: OK
// CHECK-NEXT: STATELESS_STEK_ROTATION: OK
// CHECK-NEXT: HRR_COOKIE_AND_GROUP_PARSE: OK
// CHECK-NEXT: DYNAMIC_RECORD_AND_COMPRESSED_CERT: OK

// ============================================================================
// 2. verify_tls_fusion (2/7)
// ============================================================================
// CHECK: === [2/7] verify_tls_fusion ===

// tests/lit/verify_tls_fusion.goose
// Verification of Team Cipher-Fusion deliverables:
// 1. Constant-time X25519 scalar multiplication (RFC 7748 Section 5.2).
// 2. 4-block fused AES-128-GCM encryption/decryption (NIST SP 800-38D) and tampered tag rejection.
// 3. Canonical slice + cursor TLS record framing, zero-heap record decryption, and >16384 overflow rejection.
// 4. ML-KEM-768 decapsulation with constant-time Fujisaki-Okamoto implicit rejection (FIPS 203 Section 7.3).
// 5. X.509 CRL DER parsing, O(log N) binary-search revocation lookup, and 129th serial overflow rejection.
//

// crap:ignore
fn verify_x25519_rfc7748() {
    var scalar_buf:   u8[>..] = [];
    var u_coord_buf:  u8[>..] = [];
    var expected_buf: u8[>..] = [];

    assert(wire_kit::parse_hex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        scalar_buf,
    ));
    assert(wire_kit::parse_hex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        u_coord_buf,
    ));
    assert(wire_kit::parse_hex(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        expected_buf,
    ));

    var scalar:  u8[32] = [0; 32];
    var u_coord: u8[32] = [0; 32];
    for i in 32 {
        scalar[i] = scalar_buf[i];
        u_coord[i] = u_coord_buf[i];
    }

    let out = core::x25519_scalarmult(scalar, u_coord);
    assert(core::ct_eq_bytes(out[..], expected_buf[..]));
    print("X25519_RFC7748_OK: true");
}

// crap:ignore
fn verify_fused_aes_gcm() {
    var key_buf:     u8[>..] = [];
    var iv_buf:      u8[>..] = [];
    var pt_buf:      u8[>..] = [];
    var aad_buf:     u8[>..] = [];
    var exp_ct_buf:  u8[>..] = [];
    var exp_tag_buf: u8[>..] = [];

    // NIST SP 800-38D Test Case 4 (60-byte plaintext + 20-byte AAD)
    assert(wire_kit::parse_hex("feffe9928665731c6d6a8f9467308308", key_buf));
    assert(wire_kit::parse_hex("cafebabefacedbaddecaf888", iv_buf));
    assert(wire_kit::parse_hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        pt_buf,
    ));
    assert(wire_kit::parse_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad_buf));
    assert(wire_kit::parse_hex(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        exp_ct_buf,
    ));
    assert(wire_kit::parse_hex("5bc94fbc3221a5db94fae95ae7121a47", exp_tag_buf));

    var key: u8[16] = [0; 16];
    var iv:  u8[12] = [0; 12];
    for i in 16 { key[i] = key_buf[i]; }
    for i in 12 { iv[i] = iv_buf[i]; }

    var ct_out: u8[60] = [0; 60];
    let tag, enc_len, enc_ok = core::fused_aes_gcm_encrypt(key, iv, pt_buf[..], aad_buf[..], ct_out[..]);
    assert(enc_ok && enc_len == 60);
    assert(core::ct_eq_bytes(ct_out[..], exp_ct_buf[..]));
    assert(core::ct_eq_bytes(tag[..], exp_tag_buf[..]));

    var dec_out: u8[60] = [0; 60];
    let dec_len, dec_ok = core::fused_aes_gcm_decrypt(key, iv, ct_out[..], aad_buf[..], tag, dec_out[..]);
    assert(dec_ok && dec_len == 60);
    assert(core::ct_eq_bytes(dec_out[..], pt_buf[..]));

    // Exercise 4-block (80-byte >= 64-byte) interleaved loop + tampered tag rejection + capacity overflow
    var pt80: u8[80] = [0; 80];
    for i in 80 { pt80[i] = ((i * 7 + 3) & 0xFF) as u8; }
    var ct80: u8[80] = [0; 80];
    let tag80, enc80_len, enc80_ok = core::fused_aes_gcm_encrypt(key, iv, pt80[..], aad_buf[..], ct80[..]);
    assert(enc80_ok && enc80_len == 80);

    var dec80: u8[80] = [0; 80];
    let dec80_len, dec80_ok = core::fused_aes_gcm_decrypt(key, iv, ct80[..], aad_buf[..], tag80, dec80[..]);
    assert(dec80_ok && dec80_len == 80);
    assert(core::ct_eq_bytes(dec80[..], pt80[..]));

    var bad_tag = tag80;
    bad_tag[15] ^= 0x01;
    let _, bad_ok = core::fused_aes_gcm_decrypt(key, iv, ct80[..], aad_buf[..], bad_tag, dec80[..]);
    assert(!bad_ok);

    var small_dst: u8[16] = [0; 16];
    let _, _, small_enc_ok = core::fused_aes_gcm_encrypt(key, iv, pt80[..], aad_buf[..], small_dst[..]);
    let _, small_dec_ok = core::fused_aes_gcm_decrypt(key, iv, ct80[..], aad_buf[..], tag80, small_dst[..]);
    assert(!small_enc_ok && !small_dec_ok);

    print("FUSED_AES_GCM_OK: true");
}

// crap:ignore
fn verify_tls_record_slice_and_bounds() {
    let wire_bytes: u8[18] = [
        0x17, 0x03, 0x03, 0x00, 0x05,
        0xAA,
        0x01, 0x02,
        0x00, 0x01, 0x02,
        0x01, 0x02, 0x03, 0x04,
        0x02, 0xDE, 0xAD,
    ];
    var cursor: i64 = 0;
    let ctype, ver, rlen, hdr_alert, hdr_ok = wing::parse_tls_record_header_at(wire_bytes[..], cursor);
    assert(hdr_ok && ctype == 0x17 && ver == 0x0303 && rlen == 5 && hdr_alert == wing::TlsAlert.CloseNotify);
    assert(cursor == 5);

    var b8:  u8  = 0;
    var b16: u16 = 0;
    var b24: u32 = 0;
    var b32: u32 = 0;
    assert(wing::slice_get_u8(wire_bytes[..], cursor, b8) && b8 == 0xAA);
    assert(wing::slice_get_u16(wire_bytes[..], cursor, b16) && b16 == 0x0102);
    assert(wing::slice_get_u24(wire_bytes[..], cursor, b24) && b24 == 0x000102);
    assert(wing::slice_get_u32(wire_bytes[..], cursor, b32) && b32 == 0x01020304);
    let sub8, ok_s8 = wing::slice_get_u8_length_prefixed(wire_bytes[..], cursor);
    assert(ok_s8 && sub8.len == 2 && cursor == 18);

    var r_cursor: i64 = 5;
    let r_b8, ok_r8 = wing::slice_read_u8(wire_bytes[..], r_cursor);
    assert(ok_r8 && r_b8 == 0xAA && r_cursor == 6);
    let r_b16, ok_r16 = wing::slice_read_u16(wire_bytes[..], r_cursor);
    assert(ok_r16 && r_b16 == 0x0102 && r_cursor == 8);
    let r_b24, ok_r24 = wing::slice_read_u24(wire_bytes[..], r_cursor);
    assert(ok_r24 && r_b24 == 0x000102 && r_cursor == 11);
    let r_b32, ok_r32 = wing::slice_read_u32(wire_bytes[..], r_cursor);
    assert(ok_r32 && r_b32 == 0x01020304 && r_cursor == 15);

    let pfx16: u8[4] = [0x00, 0x02, 0xBE, 0xEF];
    var c16: i64 = 0;
    let sub16, ok_s16 = wing::slice_get_u16_length_prefixed(pfx16[..], c16);
    assert(ok_s16 && sub16.len == 2 && c16 == 4);

    let pfx24: u8[5] = [0x00, 0x00, 0x02, 0xCA, 0xFE];
    var c24: i64 = 0;
    let sub24, ok_s24 = wing::slice_get_u24_length_prefixed(pfx24[..], c24);
    assert(ok_s24 && sub24.len == 2 && c24 == 5);

    var bc = core::cursor_from(pfx24[..]);
    var last_b: u8 = 0;
    assert(core::get_last_u8(bc, last_b) && last_b == 0xFE);
    var bb = core::builder_init();
    core::put_u24(bb, 0x010203);
    core::put_u32(bb, 0x04050607);
    assert(bb.buf.len == 7);

    // Decrypt valid TLS 1.3 record using zero-heap tls_record_decrypt_aes128_gcm_into
    let key:      u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let iv:       u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let hdr:      u8[5]  = [0x17, 0x03, 0x03, 0x00, 0x15];
    let inner_pt: u8[5]  = [0x70, 0x69, 0x6E, 0x67, 0x17]; // "ping" + ContentType 0x17
    let nonce, ok_n = wing::compute_record_nonce(iv, 0);
    assert(ok_n);

    var payload: u8[21] = [0; 21];
    let rec_tag, _, ok_s = core::fused_aes_gcm_encrypt(key, nonce, inner_pt[..], hdr[..], payload[..5]);
    assert(ok_s);
    for i in 16 { payload[5 + i] = rec_tag[i]; }

    var plain_buf: u8[64] = [0; 64];
    let plain_len, inner_type, dec_alert, dec_ok = wing::tls_record_decrypt_aes128_gcm_into(
        key, iv, 0, hdr[..], payload[..], plain_buf[..],
    );
    assert(dec_ok && plain_len == 4 && inner_type == 0x17 && dec_alert == wing::TlsAlert.CloseNotify);

    // Oversized ciphertext (> 16640 bytes) MUST fail closed with RecordOverflow (Invariant 13)
    var oversize_payload: u8[16641] = [0; 16641];
    var out_over:         u8[16384] = [0; 16384];
    let _, _, over_alert, over_ok = wing::tls_record_decrypt_aes128_gcm_into(
        key, iv, 0, hdr[..], oversize_payload[..], out_over[..],
    );
    if over_ok {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP");
    }
    assert(!over_ok && over_alert == wing::TlsAlert.RecordOverflow);
    print("TLS_RECORD_FUSION_OK: true");
}

// crap:ignore
fn verify_mlkem768_decapsulate() {
    var sk: u8[2400] = [0; 2400];
    for i in 2400 {
        sk[i] = ((i * 13 + 5) & 0xFF) as u8;
    }

    var ct_valid: u8[1088] = [0; 1088];
    for i in 1056 {
        ct_valid[i] = ((i * 17 + 9) & 0xFF) as u8;
    }
    let m_prime = core::hmac_sha256(sk[0..32], ct_valid[0..1056]);
    let valid_tag = core::hmac_sha256(sk[1152..1184], m_prime[..]);
    for i in 32 {
        ct_valid[1056 + i] = valid_tag[i];
    }

    var ss_valid: u8[32] = [0; 32];
    assert(tls_internal::mlkem768_decapsulate(ct_valid[..], sk[..], ss_valid[..]));

    var ct_tampered = ct_valid;
    ct_tampered[0] ^= 0xFF;
    var ss_tampered: u8[32] = [0; 32];
    assert(tls_internal::mlkem768_decapsulate(ct_tampered[..], sk[..], ss_tampered[..]));
    assert(!core::ct_eq_bytes(ss_valid[..], ss_tampered[..]));

    let expected_k_bar = core::hmac_sha256(sk[2368..2400], ct_tampered[..]);
    assert(core::ct_eq_bytes(ss_tampered[..], expected_k_bar[..]));

    var tiny_ss: u8[16] = [0; 16];
    if tls_internal::mlkem768_decapsulate(ct_valid[..], sk[..], tiny_ss[..]) {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP");
    }

    var p256_srv = tls_internal::SecP256r1MLKEM768ServerShare { .. };
    let sk256: u8[32] = [0x11; 32];
    p256_srv.secp256r1_public = core::ecdsa_p256_public_key(sk256);
    var p256_wire: u8[>..] = [];
    tls_internal::format_secp256r1_mlkem768_server_share(p256_srv, p256_wire);
    var p256_parsed = tls_internal::SecP256r1MLKEM768ServerShare { .. };
    assert(tls_internal::parse_secp256r1_mlkem768_server_share(p256_parsed, p256_wire[..]));

    var p384_srv = tls_internal::SecP384r1MLKEM1024ServerShare { .. };
    let sk384: u8[48] = [0x22; 48];
    p384_srv.secp384r1_public = core::ecdsa_p384_public_key(sk384);
    var p384_wire: u8[>..] = [];
    tls_internal::format_secp384r1_mlkem1024_server_share(p384_srv, p384_wire);
    var p384_parsed = tls_internal::SecP384r1MLKEM1024ServerShare { .. };
    assert(tls_internal::parse_secp384r1_mlkem1024_server_share(p384_parsed, p384_wire[..]));

    let c48:  u8[48] = [1; 48];
    let pq32: u8[32] = [2; 32];
    let comb48 = tls_internal::derive_secp384r1_mlkem1024_shared_secret(c48, pq32);
    assert(comb48.len == 48);
    print("MLKEM768_DECAPS_OK: true");
}

// crap:ignore
fn verify_x509_crl_binary_search() {
    var b = core::builder_init();
    assert(core::start_u8_prefix(b));
    b.buf[0] = 0x30;
    assert(core::start_u8_prefix(b)); // outer SEQUENCE
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b)); // tbsCertList SEQUENCE

    // version INTEGER 1
    let ver_der: u8[3] = [0x02, 0x01, 0x01];
    core::put_bytes(b, ver_der[..]);
    // signature AlgorithmIdentifier SEQUENCE
    let sig_der: u8[7] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
    core::put_bytes(b, sig_der[..]);
    // issuer Name SEQUENCE
    let iss_der: u8[13] = [0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x00];
    core::put_bytes(b, iss_der[..]);
    // thisUpdate UTCTime "260101000000Z"
    let time_der: u8[15] = [0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A];
    core::put_bytes(b, time_der[..]);

    // revokedCertificates SEQUENCE
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b));
    // Entry 1: serial 0x0300
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b));
    let ser1: u8[4] = [0x02, 0x02, 0x03, 0x00];
    core::put_bytes(b, ser1[..]);
    core::put_bytes(b, time_der[..]);
    assert(core::finish_u8_prefix(b));
    // Entry 2: serial 0x0100
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b));
    let ser2: u8[4] = [0x02, 0x02, 0x01, 0x00];
    core::put_bytes(b, ser2[..]);
    core::put_bytes(b, time_der[..]);
    assert(core::finish_u8_prefix(b));
    assert(core::finish_u8_prefix(b)); // finish revokedCertificates

    assert(core::finish_u8_prefix(b)); // finish tbsCertList
    core::put_bytes(b, sig_der[..]);
    let sig_val: u8[3] = [0x03, 0x01, 0x00];
    core::put_bytes(b, sig_val[..]);
    assert(core::finish_u8_prefix(b)); // finish outer length
    b.offsets.pop();

    var crl = wing::ParsedCrl { .. };
    assert(wing::parse_x509_crl(b.buf[..], crl));
    assert(crl.serial_count == 2);
    assert(crl.serials[0] == 0x0100);
    assert(crl.serials[1] == 0x0300);
    assert(wing::crl_is_revoked(crl, 0x0100));
    assert(wing::crl_is_revoked(crl, 0x0300));
    assert(!wing::crl_is_revoked(crl, 99));

    // Fill up to 128 serials and verify 129th returns false (Invariant 13)
    var full_crl = wing::ParsedCrl { .. };
    for i in 128 {
        let s = (200 - i) as u64;
        assert(wing::crl_insert_serial(full_crl, s));
    }
    assert(full_crl.serial_count == 128);
    assert(wing::crl_is_revoked(full_crl, 73));
    assert(wing::crl_is_revoked(full_crl, 200));
    assert(!wing::crl_is_revoked(full_crl, 500));

    let overflow_ok = wing::crl_insert_serial(full_crl, 999);
    if overflow_ok {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP");
    }
    assert(!overflow_ok);
    print("X509_CRL_BSEARCH_OK: true");
}

fn run_02_verify_tls_fusion() {
    verify_x25519_rfc7748();
    verify_fused_aes_gcm();
    verify_tls_record_slice_and_bounds();
    verify_mlkem768_decapsulate();
    verify_x509_crl_binary_search();
}

// CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
// CHECK: X25519_RFC7748_OK: true
// CHECK: FUSED_AES_GCM_OK: true
// CHECK: TLS_RECORD_FUSION_OK: true
// CHECK: MLKEM768_DECAPS_OK: true
// CHECK: X509_CRL_BSEARCH_OK: true

// ============================================================================
// 3. verify_tls_resumption_0rtt (3/7)
// ============================================================================
// CHECK: === [3/7] verify_tls_resumption_0rtt ===

// tests/lit/verify_tls_resumption_0rtt.goose
// Verification of TLS 1.3 Session Resumption & 0-RTT Early Data Mechanics (RFC 8446 §4.2.10, §4.6.1).
// Tests NewSessionTicket codec, resumption PSK derivation, two-epoch Bloom filter strike register,
// ticket age de-obfuscation, and 0-RTT traffic controllers under OpenSSL Bug #31406 invariants.
//

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
    var reg = tls_internal::strike_register_init(10000, 2000);
    let ticket_id: const u8[:] = "unique_session_ticket_id_alpha";

    // First presentation at t = 1000 ms: MUST be accepted
    let first_check = tls_internal::strike_register_check_and_insert(reg, ticket_id, 1000);
    assert(first_check);
    print("STRIKE_REG_FIRST_INSERT: OK");

    // Immediate replay of same ticket at t = 1050 ms: MUST be rejected
    let replay_check = tls_internal::strike_register_check_and_insert(reg, ticket_id, 1050);
    assert(!replay_check);
    print("STRIKE_REG_REPLAY_DETECTED: OK");

    // Advance time to next epoch (t = 12000 ms): ticket is in previous window, STILL REJECTED
    let next_epoch_replay = tls_internal::strike_register_check_and_insert(reg, ticket_id, 12000);
    assert(!next_epoch_replay);
    print("STRIKE_REG_PREV_EPOCH_REPLAY_DETECTED: OK");

    // Unrelated ticket in new epoch MUST be accepted
    let new_ticket: const u8[:] = "fresh_ticket_beta";
    let new_check = tls_internal::strike_register_check_and_insert(reg, new_ticket, 12000);
    assert(new_check);
    print("STRIKE_REG_FRESH_TICKET_ACCEPTED: OK");
}

fn test_ticket_age_validation() {
    let ticket_age_add: u32 = 0x50000000;
    let actual_age_ms:  i64 = 5000; // 5 seconds
    let obfuscated_age: u32 = (actual_age_ms as u32) + ticket_age_add;

    // Expected age matches actual age within 2000ms tolerance
    let ok_match = tls_internal::validate_ticket_age(obfuscated_age, ticket_age_add, 5000, 2000);
    assert(ok_match);
    print("TICKET_AGE_VALID: OK");

    // Clock skew / delay exceeding tolerance (expected 1000ms vs actual 5000ms) -> MUST FAIL
    let bad_skew = tls_internal::validate_ticket_age(obfuscated_age, ticket_age_add, 1000, 2000);
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

fn run_03_verify_tls_resumption_0rtt() {
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

// ============================================================================
// 4. rfc_repro_tls_bug_fixes (4/7)
// ============================================================================
// CHECK: === [4/7] rfc_repro_tls_bug_fixes ===

// tests/lit/rfc_repro_tls_bug_fixes.goose
// Regression tests for TLS bug fixes: ALPN validation, KeyUpdate bounds, and Ciphertext header type.
//

fn run_04_rfc_repro_tls_bug_fixes() {
    // ---- 1. Bug 1: Malformed ALPN extension in ClientHello (RFC 7301 §3.1) ----
    // Malformed 1-byte ALPN extension MUST be rejected (return false)
    let malformed_alpn_1b: u8[1] = [0x00];
    var out_alpn: u8[..32] = [];
    let ok1 = wing::select_server_alpn_from_ext(malformed_alpn_1b[..], "h2", out_alpn);
    assert(!ok1); // MUST fail on malformed 1-byte ALPN extension!
    print("TLS_ALPN_REJECT_MALFORMED_1B: OK");

    // Malformed 2-byte ALPN extension MUST also be rejected (empty list length)
    let malformed_alpn_2b: u8[2] = [0x00, 0x00];
    let ok2 = wing::select_server_alpn_from_ext(malformed_alpn_2b[..], "h2", out_alpn);
    assert(!ok2); // MUST fail on malformed 2-byte ALPN extension!
    print("TLS_ALPN_REJECT_MALFORMED_2B: OK");

    // Valid ALPN extension with "h2" (len=2: 0x00, 0x03, 0x02, 'h', '2') MUST succeed
    let valid_alpn: u8[5] = [0x00, 0x03, 0x02, 'h', '2'];
    let ok3 = wing::select_server_alpn_from_ext(valid_alpn[..], "h2", out_alpn);
    assert(ok3);
    assert(out_alpn == "h2");
    print("TLS_ALPN_ACCEPT_VALID: OK");

    // ---- 2. Bug 2: encode_key_update bounded array truncation (GOOSE-BUG-2) ----
    // Zero-capacity destination buffer MUST cause encode_key_update to fail closed (false)
    var zero_buf: u8[..0] = [];
    let ok_ku_fail = wing::encode_key_update(zero_buf, 0);
    assert(!ok_ku_fail); // MUST fail closed when buffer has no remaining capacity!
    print("TLS_KEY_UPDATE_REJECT_NOCAP: OK");

    var normal_buf: u8[..4] = [];
    let ok_ku_succ = wing::encode_key_update(normal_buf, 0);
    assert(ok_ku_succ);
    assert(normal_buf.len == 1 && normal_buf[0] == 0);
    print("TLS_KEY_UPDATE_ACCEPT_VALID: OK");

    // ---- 3. Bug 3: encode_tls_ciphertext_header rejecting ChangeCipherSpec outer type (RFC 8446 §5.2) ----
    // Outer content type in TLS 1.3 TLSCiphertext is strictly application_data (0x17).
    // ChangeCipherSpec (0x14) is an unencrypted record and MUST NOT be accepted as ciphertext header!
    var hdr_buf: u8[..16] = [];
    let ok_ccs_hdr = wing::encode_tls_ciphertext_header(hdr_buf, rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 32);
    assert(!ok_ccs_hdr); // MUST reject ChangeCipherSpec as ciphertext header!
    print("TLS_CIPHERTEXT_HDR_REJECT_CCS: OK");

    let ok_app_hdr = wing::encode_tls_ciphertext_header(hdr_buf, rfc::TLS_CONTENT_APPLICATION_DATA, 32);
    assert(ok_app_hdr);
    print("TLS_CIPHERTEXT_HDR_ACCEPT_APP: OK");

    // ---- 4. FIPS 203 ML-KEM-768 KeyGen + Encaps + Decaps Roundtrip (TLSMOD-003) ----
    let d_seed: u8[32] = [0x42; 32];
    let z_seed: u8[32] = [0x99; 32];
    let m_rand: u8[32] = [0x77; 32];
    let ek, dk = tls_internal::mlkem768_keygen(d_seed, z_seed);
    let ct, ss_enc, ok_enc = tls_internal::mlkem768_encapsulate(ek, m_rand);
    assert(ok_enc);
    var ss_dec: u8[32] = [0; 32];
    let ok_dec = tls_internal::mlkem768_decapsulate(ct[..], dk[..], ss_dec[..]);
    assert(ok_dec);
    assert(core::ct_eq_bytes(ss_enc[..], ss_dec[..]));

    // Tampered ciphertext triggers FIPS 203 implicit rejection
    var ct_bad = ct;
    ct_bad[0] ^= 0x55;
    var ss_rej: u8[32] = [0; 32];
    assert(tls_internal::mlkem768_decapsulate(ct_bad[..], dk[..], ss_rej[..]));
    assert(!core::ct_eq_bytes(ss_enc[..], ss_rej[..]));

    // Invalid encapsulation key (modulus >= 3329) fails closed
    var bad_ek = ek;
    bad_ek[0] = 0xFF;
    bad_ek[1] = 0xFF;
    bad_ek[2] = 0xFF;
    let _, _, ok_bad_ek = tls_internal::mlkem768_encapsulate(bad_ek, m_rand);
    assert(!ok_bad_ek);
    print("TLS_MLKEM768_ROUNDTRIP_OK: true");

    // ---- 5. RFC 9849 ECH Outer Extensions, Inner Encoding & Acceptance Confirmation (TLSMOD-001) ----
    let outer_exts: u16[3] = [
        rfc::TLS_EXT_SUPPORTED_GROUPS,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS,
        rfc::TLS_EXT_KEY_SHARE,
    ];
    var outer_ext_wire: u8[..64] = [];
    assert(wing::encode_ech_outer_extensions(outer_ext_wire, outer_exts[..]));
    assert(outer_ext_wire.len == 11);
    assert(outer_ext_wire[0] == 0xFD && outer_ext_wire[1] == 0x00 && outer_ext_wire[4] == 6);

    let inner_rand: u8[32] = [0x33; 32];
    var ch_inner_buf: u8[..512] = [];
    assert(wing::build_encoded_client_hello_inner(
        ch_inner_buf, inner_rand, "secret.example.com", "h2", outer_exts[..], 64,
    ));
    assert(ch_inner_buf.len > 0 && (ch_inner_buf.len & 31) == 0);

    var sh_wire: u8[48] = [0x11; 48];
    sh_wire[0] = rfc::TLS_HS_SERVER_HELLO;
    sh_wire[1] = 0x00;
    sh_wire[2] = 0x00;
    sh_wire[3] = 44;
    let confirm1, ok_conf1 = wing::compute_ech_accept_confirmation(inner_rand, ch_inner_buf[..], sh_wire[..], false);
    assert(ok_conf1);

    // Mutating ServerHello.random[24..32] (sh_wire[30..38]) MUST produce the identical confirmation
    var sh_wire2 = sh_wire;
    core::ct_copy_bytes(sh_wire2[30..38], confirm1[..]);
    let confirm2, ok_conf2 = wing::compute_ech_accept_confirmation(inner_rand, ch_inner_buf[..], sh_wire2[..], false);
    assert(ok_conf2 && confirm1 == confirm2);
    assert(wing::verify_ech_acceptance_confirmation(sh_wire2[30..38], confirm2));

    let hrr_confirm, ok_hrr_conf = wing::compute_ech_accept_confirmation(inner_rand, ch_inner_buf[..], sh_wire[..], true);
    assert(ok_hrr_conf && hrr_confirm != confirm1);
    print("TLS_ECH_CONFIRMATION_OK: true");

    // ---- 6. RFC 8446 §7.5 Exporters: >255B Context & Early Exporter Secret (TLSMOD-005) ----
    var ks, ok_ks = tls_internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(ok_ks);
    let psk_ikm: u8[32] = [0xAA; 32];
    let ch_hash: u8[32] = [0xBB; 32];
    assert(tls_internal::ks_init_early_secret(ks, psk_ikm[..]));
    assert(tls_internal::ks_derive_early_traffic(ks, ch_hash[..]));
    assert(ks.early_exporter_secret.len == 32);

    let ecdhe_ss: u8[32] = [0xCC; 32];
    assert(tls_internal::ks_advance_to_handshake(ks, ecdhe_ss[..]));
    assert(tls_internal::ks_advance_to_master(ks, ch_hash[..]));

    var large_ctx: u8[300] = [0x5A; 300];
    var exp_out:   u8[32]  = [0; 32];
    assert(tls_internal::ks_export_keying_material(ks, "EXPORTER-Channel-Binding", large_ctx[..], 32, exp_out[..]));
    print("TLS_EXPORTER_LARGE_CTX_OK: true");

    // ---- 7. ECDSA P-256 & P-384 Jacobian Projective & Shamir Dual-Scalar (TLSC-07) ----
    var priv256: u8[32] = [0; 32];
    priv256[31] = 7;
    let pub256 = core::ecdsa_p256_public_key(priv256);
    let q256, q256_ok = core::decode_p256_public_key(pub256[..]);
    assert(q256_ok);
    let g256 = core::P256Point {
        x:        core::U256 { v: core::P256_GX },
        y:        core::U256 { v: core::P256_GY },
        infinity: false,
    };
    var u1_256 = core::U256 { .. };
    u1_256.v[0] = 13;
    var u2_256 = core::U256 { .. };
    u2_256.v[0] = 5;
    let shamir256 = core::p256_muladd_shamir(g256, u1_256, q256, u2_256);
    let dbl256 = core::p256_point_double(g256);
    assert(!dbl256.infinity && !shamir256.infinity);
    let sep256 = core::p256_point_add(core::p256_scalar_mul(g256, u1_256), core::p256_scalar_mul(q256, u2_256));
    assert(core::u256_cmp(shamir256.x, sep256.x.v) == 0);
    let sig256 = core::ecdsa_p256_sign(priv256, "Jacobian Shamir P-256");
    assert(core::ecdsa_p256_verify(pub256[..], "Jacobian Shamir P-256", sig256[..]));
    assert(!core::ecdsa_p256_verify(pub256[..], "tampered", sig256[..]));

    var priv384: u8[48] = [0; 48];
    priv384[47] = 11;
    let pub384 = core::ecdsa_p384_public_key(priv384);
    let q384, q384_ok = core::decode_p384_public_key(pub384[..]);
    assert(q384_ok);
    let g384 = core::P384Point {
        x:        core::U384 { v: core::P384_GX },
        y:        core::U384 { v: core::P384_GY },
        infinity: false,
    };
    var u1_384 = core::U384 { .. };
    u1_384.v[0] = 9;
    var u2_384 = core::U384 { .. };
    u2_384.v[0] = 4;
    let shamir384 = core::p384_muladd_shamir(g384, u1_384, q384, u2_384);
    let dbl384 = core::p384_point_double(g384);
    assert(!dbl384.infinity && !shamir384.infinity);
    let sep384 = core::p384_point_add(core::p384_scalar_mul(g384, u1_384), core::p384_scalar_mul(q384, u2_384));
    assert(core::u384_cmp(shamir384.x, sep384.x.v) == 0);
    let sig384 = core::ecdsa_p384_sign(priv384, "Jacobian Shamir P-384");
    assert(core::ecdsa_p384_verify(pub384[..], "Jacobian Shamir P-384", sig384[..]));
    assert(!core::ecdsa_p384_verify(pub384[..], "tampered", sig384[..]));
    print("TLS_ECDSA_JACOBIAN_SHAMIR_OK: true");

    // ---- 8. RSA-2048 & RSA-4096 32-Bit Montgomery CIOS (TLSC-08) ----
    let e3_be:  u8[1]  = [0x03];
    let exp2:   u8[1]  = [0x02];
    let salt32: u8[32] = [0x42; 32];
    var n2048_prime: u8[256] = [0xFF; 256];
    n2048_prime[253] = 0xE2;
    n2048_prime[254] = 0x5C;
    n2048_prime[255] = 0xEF;
    var d2048_prime: u8[256] = [0xAA; 256];
    d2048_prime[253] = 0x96;
    d2048_prime[254] = 0xE8;
    d2048_prime[255] = 0x9F;
    var sig2048_pss: u8[..512] = [];
    assert(core::rsa_pss_sha256_sign(n2048_prime[..], d2048_prime[..], salt32[..], "RSA-2048 Montgomery", sig2048_pss));
    assert(core::rsa_pss_sha256_verify(n2048_prime[..], e3_be[..], "RSA-2048 Montgomery", sig2048_pss[..]));
    var p3:          u8[..512] = [];
    var p2:          u8[..512] = [];
    var p2_mul_base: u8[..512] = [];
    assert(core::rsa_mod_exp(sig2048_pss[..], e3_be[..], n2048_prime[..], p3));
    assert(core::rsa_mod_exp(sig2048_pss[..], exp2[..], n2048_prime[..], p2));
    core::rsa_be_mul_mod(p2[..], sig2048_pss[..], n2048_prime[..], p2_mul_base);
    assert(p3[..] == p2_mul_base[..]);
    print("TLS_RSA_MONTGOMERY_OK: true");
}

// CHECK: TLS_ALPN_REJECT_MALFORMED_1B: OK
// CHECK: TLS_ALPN_REJECT_MALFORMED_2B: OK
// CHECK: TLS_ALPN_ACCEPT_VALID: OK
// CHECK: TLS_KEY_UPDATE_REJECT_NOCAP: OK
// CHECK: TLS_KEY_UPDATE_ACCEPT_VALID: OK
// CHECK: TLS_CIPHERTEXT_HDR_REJECT_CCS: OK
// CHECK: TLS_CIPHERTEXT_HDR_ACCEPT_APP: OK
// CHECK: TLS_MLKEM768_ROUNDTRIP_OK: true
// CHECK: TLS_ECH_CONFIRMATION_OK: true
// CHECK: TLS_EXPORTER_LARGE_CTX_OK: true
// CHECK: TLS_ECDSA_JACOBIAN_SHAMIR_OK: true
// CHECK: TLS_RSA_MONTGOMERY_OK: true

// ============================================================================
// 5. rfc_repro_tls_cross_rfc (5/7)
// ============================================================================
// CHECK: === [5/7] rfc_repro_tls_cross_rfc ===

// tests/lit/rfc_repro_tls_cross_rfc.goose
// Regression tests for cross-component and RFC edge-case bugs in TLS 1.3 & X.509.
//

fn test_bug1_x509_empty_sig_and_unsigned_ocsp_crl() {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(wing::build_test_ed25519_cert_der(seed, "example.com", "example.com", "127.0.0.1", cert_der));

    var valid_parsed = wing::ParsedCert { .. };
    assert(wing::parse_x509_certificate(cert_der[..], valid_parsed));

    // Forge certificate by replacing 64-byte signature BIT STRING (03 41 00 <64B>) with empty BIT STRING (03 01 00)
    // Header of cert_der is 4 bytes (0x30 0x82 hi lo), inner body is cert_der[4..orig_len].
    let orig_len = cert_der.len;
    let new_inner_len = (orig_len - 4) - 64;
    var forged_der: u8[..1024] = [];
    forged_der.push(0x30);
    if new_inner_len >= 256 {
        forged_der.push(0x82);
        forged_der.push(((new_inner_len >> 8) & 0xFF) as u8);
        forged_der.push((new_inner_len & 0xFF) as u8);
    } else {
        forged_der.push(0x81);
        forged_der.push(new_inner_len as u8);
    }
    var copy_idx: i64 = 4;
    while copy_idx < orig_len - 67 {
        forged_der.push(cert_der[copy_idx]);
        copy_idx++;
    }
    forged_der.push(0x03);
    forged_der.push(0x01);
    forged_der.push(0x00);

    var forged_parsed = wing::ParsedCert { .. };
    let ok_parse_forged = wing::parse_x509_certificate(forged_der[..], forged_parsed);
    let verify_alert = wing::x509_verify_cert_signature(
        forged_parsed, forged_der[..], valid_parsed, cert_der[..],
    );
    assert(!ok_parse_forged);
    assert(verify_alert == wing::TlsAlert.BadCertificate);
    print("BUG1_X509_EMPTY_SIG_REJECTED: OK");

    // BasicOCSPResponse with empty signature BIT STRING (03 01 00) MUST be rejected by parse_ocsp_response
    let unsigned_ocsp: u8[93] = [
        0x30, 0x5B,
        0x0A, 0x01, 0x00, // responseStatus = successful (0)
        0xA0, 0x56,
        0x30, 0x54,
        0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, // id-pkix-ocsp-basic
        0x04, 0x47,
        0x30, 0x45, // BasicOCSPResponse SEQUENCE
        0x30, 0x39, // tbsResponseData
        0xA1, 0x04, 0x30, 0x02, 0x31, 0x00, // responderID
        0x18, 0x0F, '2', '0', '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x30, 0x20,
        0x30, 0x1E,
        0x30, 0x09,
        0x30, 0x00,
        0x04, 0x00,
        0x04, 0x00,
        0x02, 0x01, 0x01,
        0x80, 0x00,
        0x18, 0x0F, '2', '0', '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, // signatureAlgorithm (Ed25519)
        0x03, 0x01, 0x00, // empty 0-byte signature BIT STRING
    ];
    var ocsp_out = wing::ParsedOcspResponse { .. };
    assert(!wing::parse_ocsp_response(unsigned_ocsp[..], ocsp_out));
    print("BUG1_UNSIGNED_OCSP_REJECTED: OK");

    // Unsigned CRL (CertificateList missing outer signatureAlgorithm and signatureValue) MUST be rejected
    let unsigned_crl: u8[34] = [
        0x30, 0x20,
        0x30, 0x1E, // tbsCertList only, no outer signatureAlgorithm or signatureValue
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, // signature (Ed25519)
        0x30, 0x06, 0x31, 0x04, 0x30, 0x02, 0x06, 0x00, // issuer
        0x17, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
    ];
    var crl_out = wing::ParsedCrl { .. };
    assert(!wing::parse_x509_crl(unsigned_crl[..], crl_out));
    print("BUG1_UNSIGNED_CRL_REJECTED: OK");
}

fn test_bug2_x509_malformed_extensions_bypass() {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(wing::build_test_ed25519_cert_der(seed, "example.com", "example.com", "127.0.0.1", cert_der));

    // Locate [3] EXPLICIT extensions tag (0xA3) inside tbsCertificate and corrupt the inner SEQUENCE header
    // or first extension SEQUENCE tag so read_cert_extensions breaks early before critical extensions.
    var corrupted: u8[..1024] = [];
    corrupted.append(cert_der[..]);
    var a3_idx: i64 = -1;
    for i in (corrupted.len - 80) {
        if corrupted[i] == 0xA3 && corrupted[i + 2] == 0x30 {
            a3_idx = i;
        }
    }
    assert(a3_idx > 0);
    // Corrupt first extension tag inside Extensions SEQUENCE from 0x30 (SEQUENCE) to 0x05 (NULL)
    corrupted[a3_idx + 4] = 0x05;

    var parsed_corrupt = wing::ParsedCert { .. };
    let ok_parse = wing::parse_x509_certificate(corrupted[..], parsed_corrupt);
    assert(!ok_parse);
    print("BUG2_X509_MALFORMED_EXT_REJECTED: OK");
}

fn test_bug3_handshake_forbidden_extensions_and_ch_rules() {
    // 1. EncryptedExtensions containing forbidden key_share extension (0x00, 0x33) MUST be rejected (RFC 8446 §4.2 Table 2)
    let ee_with_key_share: u8[8] = [
        0x00, 0x06,       // extensions length = 6
        0x00, 0x33,       // ext_type = key_share (51) - FORBIDDEN in EncryptedExtensions!
        0x00, 0x02,       // ext_len = 2
        0x00, 0x1D,
    ];
    var neg_alpn: u8[..32] = [];
    assert(!wing::parse_encrypted_extensions_alpn(ee_with_key_share[..], neg_alpn));
    print("BUG3_EE_FORBIDDEN_EXT_REJECTED: OK");

    // 2. ServerHello containing forbidden ALPN extension (0x00, 0x10) MUST be rejected (RFC 8446 §4.2 Table 2)
    let srv_rand: u8[32] = [0x11; 32];
    let srv_pub:  u8[32] = [0x22; 32];
    var sh_payload: u8[..512] = [];
    wing::build_tls13_server_hello_payload(srv_rand, "", srv_pub, sh_payload, false);
    // Append forbidden ALPN extension (00 10 00 05 00 03 02 'h' '2') into ServerHello extensions block
    // In build_tls13_server_hello_payload: ver(2) + rand(32) + sid(1) + cs(2) + comp(1) = 38, then ext_total_len(2) at 38..40
    let old_ext_len = core::read_be_u16(sh_payload[..], 38);
    let new_ext_len = old_ext_len + 9;
    sh_payload[38] = ((new_ext_len >> 8) & 0xFF) as u8;
    sh_payload[39] = (new_ext_len & 0xFF) as u8;
    let alpn_ext_bytes: u8[9] = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'];
    sh_payload.append(alpn_ext_bytes[..]);

    var sh_msg: u8[..512] = [];
    sh_msg.push(rfc::TLS_HS_SERVER_HELLO);
    core::append_u24_be(sh_msg, sh_payload.len as u32);
    sh_msg.append(sh_payload[..]);

    var out_cs: u16 = 0;
    var out_hrr = false;
    var out_grp:   u16        = 0;
    var out_share: u8[..2048] = [];
    var out_psk = false;
    assert(!wing::parse_server_hello_or_hrr(sh_msg[..], out_cs, out_hrr, out_grp, out_share, out_psk));
    print("BUG3_SH_FORBIDDEN_EXT_REJECTED: OK");

    // 3. ClientHello with non-null legacy_compression_methods ([0x01]) MUST be rejected by server (RFC 8446 §4.1.2)
    let cli_rand: u8[32] = [0x33; 32];
    let cli_pub:  u8[32] = [0x44; 32];
    var ch_payload: u8[..512] = [];
    wing::build_tls13_client_hello_payload(cli_rand, cli_pub, "example.com", "h2", ch_payload);
    // In build_tls13_client_hello_payload: ver(2) + rand(32) + sid_len(1) + sid(32) + cs_len(2) + cs(6) + comp_len(1) + comp_byte(1 at idx 76)
    ch_payload[76] = 0x01; // non-zero compression method (DEFLATE)
    var ch_msg: u8[..512] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_msg, ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    var srv_sid:  u8[..32] = [];
    var srv_cpub: u8[32]   = [0; 32];
    var srv_alpn: u8[..32] = [];
    var srv_psk_res = false;
    var srv_psk_sec: u8[32] = [0; 32];
    assert(!wing::parse_client_hello_for_server(
        ch_msg[..], "h2", srv_sid, srv_cpub, srv_alpn, srv_psk_res, srv_psk_sec,
    ));
    print("BUG3_CH_INVALID_COMPRESSION_REJECTED: OK");
}

fn test_bug4_sha384_nst_resumption_psk() {
    wing::clear_tls13_session_tickets();
    let slot_idx = wing::alloc_tls_cipher_slot();
    assert(slot_idx != 0xFFFF);
    let idx = slot_idx as i64;
    wing::g_tls_cipher_slots[idx].cipher_suite = rfc::TLS_CIPHER_AES_256_GCM_SHA384;
    wing::g_tls_cipher_slots[idx].hash_id = 2;
    wing::g_tls_cipher_slots[idx].hash_len = 48;
    wing::g_tls_cipher_slots[idx].key_len = 32;
    let _ = wing::g_tls_cipher_slots[idx].server_name.try_set("sha384.example.com");
    for i in 48 {
        wing::g_tls_cipher_slots[idx].resumption_secret[i] = (0xA0 + i) as u8;
    }

    var nst_body: u8[..128] = [];
    let nonce: u8[4] = [1, 2, 3, 4];
    assert(wing::encode_new_session_ticket(nst_body, 3600, 0x12345678, nonce[..], "sha384-ticket-01", 0));

    wing::tls_process_received_nst(idx, nst_body[..]);

    var out_ticket: u8[..256] = [];
    var out_psk:    u8[32]    = [0; 32];
    var out_age:    u32       = 0;
    let found = wing::lookup_tls13_session_ticket("sha384.example.com", out_ticket, out_psk, out_age);
    assert(found);
    assert(out_ticket[..] == "sha384-ticket-01");
    var out_psk_full: u8[..48] = [];
    var out_cs:       u16      = 0;
    assert(wing::lookup_tls13_session_ticket_full("sha384.example.com", out_ticket, out_psk_full, out_age, out_cs));
    assert(out_psk_full.len == 48 && out_cs == rfc::TLS_CIPHER_AES_256_GCM_SHA384);
    wing::free_tls_cipher_slot(slot_idx);
    print("BUG4_SHA384_NST_PSK_CACHED: OK");
}

fn test_bug5_post_handshake_server_rejects_client_nst() {
    let slot_idx = wing::alloc_tls_cipher_slot();
    assert(slot_idx != 0xFFFF);
    let idx = slot_idx as i64;
    wing::g_tls_cipher_slots[idx].is_server = true;

    var nst_body: u8[..128] = [];
    let nonce: u8[2] = [0x01, 0x02];
    assert(wing::encode_new_session_ticket(nst_body, 3600, 100, nonce[..], "cli-sent-ticket", 0));
    var hs_msg: u8[..160] = [];
    hs_msg.push(rfc::TLS_HS_NEW_SESSION_TICKET);
    core::append_u24_be(hs_msg, nst_body.len as u32);
    hs_msg.append(nst_body[..]);

    // Server MUST NOT accept NewSessionTicket from client (RFC 8446 §4.6.1)
    assert(!wing::tls_dispatch_post_handshake_record(-1, slot_idx, hs_msg[..]));
    // Malformed post-handshake message MUST also return false
    let bad_post_hs: u8[3] = [rfc::TLS_HS_KEY_UPDATE, 0x00, 0x00];
    assert(!wing::tls_dispatch_post_handshake_record(-1, slot_idx, bad_post_hs[..]));
    // Fragmented plaintext handshake message (declared len 10, only 6 bytes received) MUST wait for next record
    let frag_hs: u8[6] = [rfc::TLS_HS_CLIENT_HELLO, 0x00, 0x00, 0x0A, 0x03, 0x03];
    assert(!wing::has_complete_plaintext_handshake_msg(frag_hs[..]));
    wing::free_tls_cipher_slot(slot_idx);
    print("BUG5_SERVER_REJECTS_CLIENT_NST: OK");
}

fn test_tlsc01_tls_feature_must_staple() {
    assert(wing::is_known_extension_oid(rfc::OID_TLS_FEATURE[..]));
    let feat_der: u8[5] = [0x30, 0x03, 0x02, 0x01, 0x05];
    var cert = wing::ParsedCert { .. };
    assert(wing::x509_parse_tls_feature_ext(feat_der[..], cert));
    assert(cert.has_must_staple);
    assert(!cert.has_unsupported_critical);

    let empty_seq: u8[2] = [0x30, 0x00];
    var bad_cert = wing::ParsedCert { .. };
    assert(!wing::x509_parse_tls_feature_ext(empty_seq[..], bad_cert));
    assert(bad_cert.has_unsupported_critical);
    print("TLSC01_MUST_STAPLE_EXT: OK");
}

fn test_tlsc02_sct_list_parsing() {
    assert(wing::is_known_extension_oid(rfc::OID_CT_PRECERT_SCTS[..]));
    // Build a 49-byte v1 SerializedSCT:
    // version(1)=0, log_id(32)=0xAA.., timestamp(8)=0x0000018E00000001, ext_len(2)=0, hash(1)=4, sig(1)=3, sig_len(2)=2, sig=[0xDE,0xAD]
    var sct_bytes: u8[..64] = [];
    sct_bytes.push(0x00);
    for _ in 32 {
        sct_bytes.push(0xAA);
    }
    let ts_and_tail: u8[16] = [
        0x00, 0x00, 0x01, 0x8E, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,
        0x04, 0x03, 0x00, 0x02, 0xDE, 0xAD,
    ];
    sct_bytes.append(ts_and_tail[..]);

    var single_sct = wing::ParsedSct { .. };
    assert(wing::parse_sct_entry(sct_bytes[..], single_sct));
    assert(single_sct.version == 0);
    assert(single_sct.log_id[0] == 0xAA && single_sct.log_id[31] == 0xAA);
    assert(single_sct.timestamp_ms == 0x0000018E00000001);
    assert(single_sct.hash_alg == 4 && single_sct.sig_alg == 3);
    assert(single_sct.signature.length == 2);

    var sct_list_raw: u8[..80] = [];
    core::append_u16_be(sct_list_raw, (sct_bytes.len + 2) as u16);
    core::append_u16_be(sct_list_raw, sct_bytes.len as u16);
    sct_list_raw.append(sct_bytes[..]);

    var scts: wing::ParsedSct[..8] = [];
    assert(wing::parse_sct_list(sct_list_raw[..], scts));
    assert(scts.len == 1);

    // Dispatch via X.509 OCTET STRING wrapper
    var ext_oct: u8[..96] = [];
    ext_oct.push(rfc::ASN1_TAG_OCTET_STRING);
    ext_oct.push(sct_list_raw.len as u8);
    ext_oct.append(sct_list_raw[..]);
    var ext_cur = core::cursor_from(ext_oct[..]);
    var cert = wing::ParsedCert { .. };
    wing::x509_dispatch_extension(ext_oct[..], rfc::OID_CT_PRECERT_SCTS[..], ext_cur, cert);
    assert(cert.has_sct_list && cert.sct_count == 1);
    print("TLSC02_SCT_LIST_PARSED: OK");
}

fn test_tlsc04_eku_parsing_and_enforcement() {
    assert(wing::is_known_extension_oid(rfc::OID_EXT_KEY_USAGE[..]));
    // SEQUENCE { id-kp-serverAuth, id-kp-clientAuth }
    let eku_srv_cli: u8[22] = [
        0x30, 0x14,
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
    ];
    var cert_ok = wing::ParsedCert { .. };
    assert(wing::x509_parse_eku_ext(eku_srv_cli[..], cert_ok));
    assert(cert_ok.has_eku);
    assert(cert_ok.eku_mask == (rfc::EKU_SERVER_AUTH | rfc::EKU_CLIENT_AUTH));
    assert(wing::validate_end_entity_constraints(cert_ok) == wing::TlsAlert.CloseNotify);

    // SEQUENCE { id-kp-OCSPSigning } -> leaf cert must fail end-entity TLS constraint check
    let eku_ocsp_only: u8[12] = [
        0x30, 0x0A,
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09,
    ];
    var cert_ocsp = wing::ParsedCert { .. };
    assert(wing::x509_parse_eku_ext(eku_ocsp_only[..], cert_ocsp));
    assert(cert_ocsp.has_eku && cert_ocsp.eku_mask == rfc::EKU_OCSP_SIGNING);
    assert(wing::validate_end_entity_constraints(cert_ocsp) == wing::TlsAlert.UnsupportedCertificate);

    // Empty EKU SEQUENCE MUST be rejected
    let empty_eku: u8[2] = [0x30, 0x00];
    var cert_empty = wing::ParsedCert { .. };
    assert(!wing::x509_parse_eku_ext(empty_eku[..], cert_empty));
    print("TLSC04_EKU_ENFORCED: OK");
}

fn test_tlsc05_email_name_constraints() {
    // 1. Exact mailbox constraint (local part case-sensitive, host part case-insensitive)
    assert(wing::match_email_name_constraint("alice@Example.COM", "alice@example.com"));
    assert(!wing::match_email_name_constraint("Alice@example.com", "alice@example.com"));

    // 2. Leading-dot domain suffix constraint (.example.com)
    assert(wing::match_email_name_constraint("bob@mail.example.com", ".example.com"));
    assert(!wing::match_email_name_constraint("bob@example.com", ".example.com"));

    // 3. Exact host constraint after '@' (example.com)
    assert(wing::match_email_name_constraint("carol@EXAMPLE.COM", "example.com"));
    assert(!wing::match_email_name_constraint("carol@sub.example.com", "example.com"));

    // 4. End-to-end SAN [1] + NameConstraints [1] evaluation
    let san_der: u8[19] = [
        0x30, 0x11,
        0x81, 0x0F, 'u', 's', 'e', 'r', '@', 's', 'u', 'b', '.', 'o', 'r', 'g', '.', 'u', 'k',
    ];
    var sans: wing::SanEntry[..16] = [];
    assert(wing::parse_san_extension(san_der[..], sans));
    assert(sans.len == 1 && sans[0].san_type == wing::SanType.Email);

    let nc_permitted_der: u8[17] = [
        0x30, 0x0F,
        0xA0, 0x0D,
        0x30, 0x0B,
        0x30, 0x09,
        0x81, 0x07, '.', 'o', 'r', 'g', '.', 'u', 'k',
    ];
    var nc_list: wing::NameConstraintEntry[..16] = [];
    assert(wing::parse_name_constraints(nc_permitted_der[..], nc_list));
    assert(wing::check_name_constraints(nc_list, sans[0]));

    let nc_implicit_der: u8[15] = [
        0x30, 0x0D, 0xA0, 0x0B, 0x30, 0x09,
        0x81, 0x07, '.', 'o', 'r', 'g', '.', 'u', 'k',
    ];
    var nc_imp: wing::NameConstraintEntry[..16] = [];
    assert(wing::parse_name_constraints(nc_implicit_der[..], nc_imp));
    assert(nc_imp.len == 1 && wing::check_name_constraints(nc_imp, sans[0]));
    print("TLSC05_EMAIL_NAME_CONSTRAINTS: OK");
}

fn test_goose2rfc_tls_audit_regressions() {
    let hs_ovf: u8[5] = [0x16, 0x03, 0x03, 0x40, 0x01];
    let _, _, _, al_ovf, ok_ovf = wing::parse_tls_record_header(hs_ovf[..]);
    assert(!ok_ovf && al_ovf == wing::TlsAlert.RecordOverflow);
    let hs_zero: u8[5] = [0x16, 0x03, 0x03, 0x00, 0x00];
    let _, _, _, al_z, ok_z = wing::parse_tls_record_header(hs_zero[..]);
    assert(!ok_z && al_z == wing::TlsAlert.UnexpectedMessage);

    assert(!wing::validate_ech_public_name_bytes("example.123"));
    assert(!wing::validate_ech_public_name_bytes("example.0x1a"));
    var ext_mand: u8[6] = [0x80, 0x01, 0x00, 0x02, 0xAA, 0xBB];
    var cur_mand = core::cursor_from(ext_mand[..]);
    assert(!wing::validate_ech_config_extensions(cur_mand));

    var dup_ks: u8[..80] = [0x00, 0x48];
    for _ in 2 {
        dup_ks.push(0x00); dup_ks.push(0x1D);
        dup_ks.push(0x00); dup_ks.push(0x20);
        for _ in 32 { dup_ks.push(0x42); }
    }
    var out_shares: u8[..4096] = [];
    assert(!wing::parse_key_share_client_extension(dup_ks[..], out_shares));

    let bad_cert_msg: u8[10] = [0x01, 0xAA, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0xFF, 0x00];
    var certs_out: const u8[:][..8] = [];
    let _, ok_cert = wing::parse_tls13_certificate_chain_and_ocsp(bad_cert_msg[..], certs_out);
    assert(!ok_cert);
    print("GOOSE2RFC_TLS_AUDIT_REGRESSIONS: OK");
}

fn run_05_rfc_repro_tls_cross_rfc() {
    test_bug1_x509_empty_sig_and_unsigned_ocsp_crl();
    test_bug2_x509_malformed_extensions_bypass();
    test_bug3_handshake_forbidden_extensions_and_ch_rules();
    test_bug4_sha384_nst_resumption_psk();
    test_bug5_post_handshake_server_rejects_client_nst();
    test_tlsc01_tls_feature_must_staple();
    test_tlsc02_sct_list_parsing();
    test_tlsc04_eku_parsing_and_enforcement();
    test_tlsc05_email_name_constraints();
    test_goose2rfc_tls_audit_regressions();
}

// CHECK: BUG1_X509_EMPTY_SIG_REJECTED: OK
// CHECK: BUG1_UNSIGNED_OCSP_REJECTED: OK
// CHECK: BUG1_UNSIGNED_CRL_REJECTED: OK
// CHECK: BUG2_X509_MALFORMED_EXT_REJECTED: OK
// CHECK: BUG3_EE_FORBIDDEN_EXT_REJECTED: OK
// CHECK: BUG3_SH_FORBIDDEN_EXT_REJECTED: OK
// CHECK: BUG3_CH_INVALID_COMPRESSION_REJECTED: OK
// CHECK: BUG4_SHA384_NST_PSK_CACHED: OK
// CHECK: BUG5_SERVER_REJECTS_CLIENT_NST: OK
// CHECK: TLSC01_MUST_STAPLE_EXT: OK
// CHECK: TLSC02_SCT_LIST_PARSED: OK
// CHECK: TLSC04_EKU_ENFORCED: OK
// CHECK: TLSC05_EMAIL_NAME_CONSTRAINTS: OK
// CHECK: GOOSE2RFC_TLS_AUDIT_REGRESSIONS: OK

// ============================================================================
// 6. rfc_repro_auth_tls_wire_edge (6/7)
// ============================================================================
// CHECK: === [6/7] rfc_repro_auth_tls_wire_edge ===

// tests/lit/rfc_repro_auth_tls_wire_edge.goose
// RFC 8446 TLS 1.3 Handshake Extension Syntax, CertificateRequest Invariants & CertificateVerify.
//

fn run_06_rfc_repro_auth_tls_wire_edge() {
    // ---- 1. RFC 8446 Section 4.2: Duplicate Extension in CertificateRequest -
    // RFC 8446 Section 4.2: Extensions - There MUST NOT be more than one extension of the same type in a given extension block.
    // Wire payload with ctx_len=0, extensions containing TWO signature_algorithms (0x000D) extensions.
    let cr_duplicate_sig_algs: u8[19] = [
        0x00,                   // ctx_len = 0
        0x00, 0x10,             // extensions length = 16 bytes
        // Extension 1: signature_algorithms (0x000D)
        0x00, 0x0D,             // ext_type = 13
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02,             // list_len = 2
        0x04, 0x03,             // ecdsa_secp256r1_sha256
        // Extension 2: duplicate signature_algorithms (0x000D) - STRICTLY FORBIDDEN
        0x00, 0x0D,             // ext_type = 13 (duplicate!)
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02,             // list_len = 2
        0x08, 0x07,             // ed25519
    ];
    var cr1 = wing::CertificateRequestMsg { .. };
    let ok_dup = wing::parse_certificate_request(cr_duplicate_sig_algs[..], false, cr1);
    assert(!ok_dup); // MUST REJECT duplicate extensions in CertificateRequest!
    print("TLS_CR_REJECT_DUPLICATE_EXT: OK");

    // ---- 2. RFC 8446 Section 4.2 Table: Forbidden Extension in CertificateRequest -
    // RFC 8446 Section 4.2: Extensions - If an implementation receives an extension which it recognizes and which is not specified for the message in which it appears, it MUST abort the handshake with an "illegal_parameter" alert.
    // Wire payload with ctx_len=0, valid signature_algorithms + FORBIDDEN key_share (0x0033 = 51)
    let cr_forbidden_key_share: u8[19] = [
        0x00,                   // ctx_len = 0
        0x00, 0x10,             // extensions length = 16 bytes
        // Extension 1: valid signature_algorithms
        0x00, 0x0D,             // ext_type = 13
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02,             // list_len = 2
        0x04, 0x03,             // ecdsa_secp256r1_sha256
        // Extension 2: key_share (51) - forbidden in CertificateRequest per Section 4.2 Table
        0x00, 0x33,             // ext_type = 51 (key_share)
        0x00, 0x04,             // ext_len = 4
        0x00, 0x02, 0xAA, 0xBB, // dummy share data
    ];
    var cr2 = wing::CertificateRequestMsg { .. };
    let ok_forbidden_cr = wing::parse_certificate_request(cr_forbidden_key_share[..], false, cr2);
    assert(!ok_forbidden_cr); // MUST REJECT forbidden extension in CertificateRequest!
    print("TLS_CR_REJECT_FORBIDDEN_EXT: OK");

    // ---- 3. RFC 8446 Section 4.2 Table: Forbidden Extension in NewSessionTicket -
    // RFC 8446 Section 4.2: Extensions - If an implementation receives an extension which it recognizes and which is not specified for the message in which it appears, it MUST abort the handshake with an "illegal_parameter" alert.
    // Wire payload with valid NST containing certificate_authorities (ext_type 47 = 0x002F) - FORBIDDEN in NST!
    let nst_forbidden_ext: u8[23] = [
        0x00, 0x00, 0x0E, 0x10, // ticket_lifetime = 3600
        0x00, 0x00, 0x00, 0x01, // ticket_age_add = 1
        0x01, 0xAA,             // ticket_nonce<0..255>: len=1, nonce=[0xAA]
        0x00, 0x02, 0xBB, 0xCC, // ticket<1..2^16-1>: len=2, ticket=[0xBB, 0xCC]
        0x00, 0x07,             // extensions length = 7 bytes
        // Extension: certificate_authorities (47) - forbidden in NewSessionTicket
        0x00, 0x2F,             // ext_type = 47
        0x00, 0x03,             // ext_len = 3
        0x00, 0x01, 0x00,       // authorities data
    ];
    var nst1 = wing::NewSessionTicketMsg { .. };
    let ok_nst_forbidden = wing::parse_new_session_ticket(nst_forbidden_ext[..], nst1);
    assert(!ok_nst_forbidden); // MUST REJECT forbidden extension in NewSessionTicket!
    print("TLS_NST_REJECT_FORBIDDEN_EXT: OK");

    // ---- 4. RFC 8446 Section 4.4.3: Official CertificateVerify Test Vector -
    // RFC 8446 Section 4.4.3: Certificate Verify - The digital signature is then computed over the concatenation of: 64 spaces, context string, separator 0x00, content to be signed.
    var transcript_32: u8[32]  = [0x01; 32];
    var msg_buf:       u8[160] = [0; 160];
    let msg_len, ok_msg = wing::build_certificate_verify_message(true, transcript_32[..], msg_buf[..]);
    assert(ok_msg);
    assert(msg_len == 130);

    // Verify 64 spaces (0x20)
    for i in 64 { assert(msg_buf[i] == 0x20); }

    // Verify Context string: "TLS 1.3, server CertificateVerify" (33 bytes)
    let expected_ctx = "TLS 1.3, server CertificateVerify";
    for i in expected_ctx.len {
        assert(msg_buf[64 + i] == expected_ctx[i]);
    }

    // Verify separator 0x00
    assert(msg_buf[64 + expected_ctx.len] == 0x00);

    // Verify transcript hash bytes (32 bytes of 0x01)
    let hash_start = 64 + expected_ctx.len + 1;
    for i in 32 {
        assert(msg_buf[hash_start + i] == 0x01);
    }
    print("TLS_CERT_VERIFY_VECTOR: OK");
}

// CHECK: TLS_CR_REJECT_DUPLICATE_EXT: OK
// CHECK: TLS_CR_REJECT_FORBIDDEN_EXT: OK
// CHECK: TLS_NST_REJECT_FORBIDDEN_EXT: OK
// CHECK: TLS_CERT_VERIFY_VECTOR: OK

// ============================================================================
// 7. rfc_repro_fingerprint_cross_rfc (7/7)
// ============================================================================
// CHECK: === [7/7] rfc_repro_fingerprint_cross_rfc ===

// Cross-component & RFC edge-case regression suite for `fingerprint/`.
//

fn test_akamai_regressions() {
    // F001: 514-byte max valid Akamai fingerprint formatting and hashing without capacity abort
    var max_fp = wing::AkamaiFingerprint {};
    for i in 16 {
        max_fp.settings.push(wing::AkamaiSetting { id: (65500 + i) as u16, val: 4294967295 });
    }
    max_fp.window_update = 2147483647;
    for i in 8 {
        max_fp.priority_frames.push(wing::AkamaiPriorityFrame {
            stream_id:     (2147483600 + i) as u32,
            exclusive:     1,
            dep_stream_id: (2147483500 + i) as u32,
            weight:        256,
        });
    }
    max_fp.pseudo_headers.push('m');
    max_fp.pseudo_headers.push('a');
    max_fp.pseudo_headers.push('s');
    max_fp.pseudo_headers.push('p');

    let max_str = wing::akamai_fingerprint_to_string(max_fp);
    assert(max_str.len == 514);
    var max_hash: u8[..32] = [];
    wing::compute_akamai_hash(max_fp, max_hash);
    assert(max_hash.len == 32);

    // F002 & F003: RFC 9113 stream ID, window_update, settings, priority, and pseudo-header validation
    let _, ok1 = wing::parse_akamai_fingerprint("1:65536||0|m,a,s,p");
    assert(!ok1);
    let _, ok2 = wing::parse_akamai_fingerprint("1:65536|2147483648|0|m,a,s,p");
    assert(!ok2);
    let _, ok3 = wing::parse_akamai_fingerprint("1:65536;;2:0|0|0|m,a,s,p");
    assert(!ok3);
    let _, ok4 = wing::parse_akamai_fingerprint("1:65536|0|0:0:0:16|m,a,s,p");
    assert(!ok4);
    let _, ok5 = wing::parse_akamai_fingerprint("1:65536|0|3:0:3:16|m,a,s,p");
    assert(!ok5);
    let _, ok6 = wing::parse_akamai_fingerprint("1:65536|0|2147483648:0:0:16|m,a,s,p");
    assert(!ok6);
    let _, ok7 = wing::parse_akamai_fingerprint("1:65536|0|0|m,m,a,s");
    assert(!ok7);
    let _, ok8 = wing::parse_akamai_fingerprint("1:65536|0|0|,,,");
    assert(!ok8);

    // F003: order_pseudo_headers deduplication & window_update=0 anomaly
    var dup_fp = wing::akamai_wing_preset();
    dup_fp.pseudo_headers.clear();
    dup_fp.pseudo_headers.append("mmasp");
    var hmap = wing::HeaderMap { .. };
    wing::order_pseudo_headers(dup_fp, "GET", "example.com", "https", "/index", hmap);
    assert(hmap.entries.len == 4);
    assert(wing::get_header(hmap, ":path") == "/index");

    let expected_wing = wing::akamai_wing_preset();
    var bad_wu = wing::akamai_wing_preset();
    bad_wu.window_update = 0;
    let anom, _ = wing::detect_akamai_anomaly(bad_wu, expected_wing);
    assert(anom == wing::AkamaiAnomaly.WindowUpdateAnomaly);
    print("AKAMAI_OK");
}

fn test_ja4_and_profile_regressions() {
    // F004 & F005: CSV ALPN ("h2,http/1.1"), DTLS versions, and draft version (0x7f1c) filtering
    let ciphers: u16[2] = [0x1301, 0x1302];
    let exts:    u16[2] = [0x0000, 0x0010];
    let vers:    u16[2] = [0x0304, 0x7f1c];
    let sigs:    u16[1] = [0x0403];

    let ja4_csv = wing::compute_ja4(ciphers[..], exts[..], vers[..], true, "h2,http/1.1", sigs[..], false);
    assert(ja4_csv[..11] == "t13d0202h2_");

    let dtls_vers: u16[2] = [0xfefd, 0xfeff];
    let ja4_dtls = wing::compute_ja4(ciphers[..], exts[..], dtls_vers[..], true, "h2", sigs[..], false);
    assert(ja4_dtls[..4] == "td2d");

    // F006 & F007: JA4H language ';' delimiter, HTTP/2 :pseudo stripping, "h2" version, and reusable buffer clear()
    let hdrs:    const u8[:][4] = [":method", ":path", "Host", "Accept-Language"];
    let cookies: const u8[:][1] = ["session_id"];
    var reusable_ja4h: u8[..64] = [];
    wing::compute_ja4h("GET", "h2", hdrs[..], wing::Ja4hFlags {}, "en;q=0.9,fr;q=0.8", cookies[..], cookies[..], reusable_ja4h);
    wing::compute_ja4h("GET", "h2", hdrs[..], wing::Ja4hFlags {}, "en;q=0.9,fr;q=0.8", cookies[..], cookies[..], reusable_ja4h);
    assert(reusable_ja4h[..12] == "ge20cn02en00");

    // F007: set_akamai syncs ClientProfile.h2
    var prof = wing::new_client_profile(wing::Profile.Wing);
    var custom_fp = wing::custom_akamai_fingerprint(12517377, "m,p,a,s");
    let _ = wing::akamai_push_setting(custom_fp, 1, 65536);
    let _ = wing::akamai_push_setting(custom_fp, 4, 131072);
    let _ = wing::akamai_push_setting(custom_fp, 5, 16384);
    wing::set_akamai(prof, custom_fp);
    assert(prof.h2.initial_window_size == 131072);
    assert(prof.h2.max_frame_size == 16384);
    print("JA4_PROFILE_OK");
}

fn test_p0f_regressions() {
    // F008 & F009: Wildcard window scale round-trip, MTU multiplier matching, and integer bounds
    let p_any, ok_any = wing::parse_p0f("4:64:0:1460:*,8:mss,sok,ts,nop,ws:df,id+:0");
    assert(ok_any);
    let fmt_any = wing::format_p0f(p_any);
    assert(fmt_any[..] == "4:64:0:1460:*,8:mss,sok,ts,nop,ws:df,id+:0");

    let target_mtu, ok_mtu = wing::parse_p0f("4:64-:0:*:mtu*4,7:mss,sok,ts,nop,ws:df:0");
    assert(ok_mtu);
    let actual_pkt, ok_pkt = wing::parse_p0f("4:60:0:1460:6000,7:mss,sok,ts,nop,ws:df:0");
    assert(ok_pkt);
    assert(wing::match_p0f(actual_pkt, target_mtu));

    let _, ok_ovf = wing::parse_p0f("4:64:0:999999999999:65535,8:mss:df:0");
    assert(!ok_ovf);
    let _, ok_ttl0 = wing::parse_p0f("4:0:0:1460:65535,8:mss:df:0");
    assert(!ok_ttl0);
    let _, ok_bad_quirk = wing::parse_p0f("4:64:0:1460:65535,8:mss:df,unknown_quirk:0");
    assert(!ok_bad_quirk);
    let _, ok_bad_eol = wing::parse_p0f("4:64:0:1460:65535,8:mss,eol+abc:df:0");
    assert(!ok_bad_eol);
    let _, ok_empty_payload = wing::parse_p0f("4:64:0:1460:65535,8:mss:df:");
    assert(!ok_empty_payload);
    print("P0F_OK");
}

fn run_07_rfc_repro_fingerprint_cross_rfc() {
    test_akamai_regressions();
    test_ja4_and_profile_regressions();
    test_p0f_regressions();
}

// CHECK: AKAMAI_OK
// CHECK-NEXT: JA4_PROFILE_OK
// CHECK-NEXT: P0F_OK

fn main() {
    print("\n=== [1/7] verify_tls_handshake_wire ===\n");
    run_01_verify_tls_handshake_wire();
    print("\n=== [2/7] verify_tls_fusion ===\n");
    run_02_verify_tls_fusion();
    print("\n=== [3/7] verify_tls_resumption_0rtt ===\n");
    run_03_verify_tls_resumption_0rtt();
    print("\n=== [4/7] rfc_repro_tls_bug_fixes ===\n");
    run_04_rfc_repro_tls_bug_fixes();
    print("\n=== [5/7] rfc_repro_tls_cross_rfc ===\n");
    run_05_rfc_repro_tls_cross_rfc();
    print("\n=== [6/7] rfc_repro_auth_tls_wire_edge ===\n");
    run_06_rfc_repro_auth_tls_wire_edge();
    print("\n=== [7/7] rfc_repro_fingerprint_cross_rfc ===\n");
    run_07_rfc_repro_fingerprint_cross_rfc();
}
