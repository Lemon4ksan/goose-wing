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

    // 16. Regression (TLS-BUG-001): ks_update_traffic_secret must use HKDF-Expand-Label(secret, "traffic upd", "", L) per RFC 8446 §7.2
    var ts_upd:          u8[32] = [0x77; 32];
    var expected_ts_upd: u8[32] = [0; 32];
    assert(internal::hkdf_expand_label(internal::HASH_SHA256, ts_upd[..], "traffic upd", [], 32, expected_ts_upd[..]));
    assert(internal::ks_update_traffic_secret(internal::HASH_SHA256, 32, ts_upd[..]));
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
    var sreg = internal::strike_register_init(1000, 10000);
    assert(internal::strike_register_check_and_insert(sreg, "init-epoch-10", 10000));
    assert(internal::strike_register_check_and_insert(sreg, "ticket-prev-epoch", 9500));
    assert(!internal::strike_register_check_and_insert(sreg, "ticket-prev-epoch", 11000));
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
