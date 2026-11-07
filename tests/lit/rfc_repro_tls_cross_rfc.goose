// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_tls_cross_rfc.goose
// Regression tests for cross-component and RFC edge-case bugs in TLS 1.3 & X.509.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

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
    assert(cert_ok.eku_mask == (wing::EKU_SERVER_AUTH | wing::EKU_CLIENT_AUTH));
    assert(wing::validate_end_entity_constraints(cert_ok) == wing::TlsAlert.CloseNotify);

    // SEQUENCE { id-kp-OCSPSigning } -> leaf cert must fail end-entity TLS constraint check
    let eku_ocsp_only: u8[12] = [
        0x30, 0x0A,
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09,
    ];
    var cert_ocsp = wing::ParsedCert { .. };
    assert(wing::x509_parse_eku_ext(eku_ocsp_only[..], cert_ocsp));
    assert(cert_ocsp.has_eku && cert_ocsp.eku_mask == wing::EKU_OCSP_SIGNING);
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
    print("TLSC05_EMAIL_NAME_CONSTRAINTS: OK");
}

fn main() {
    test_bug1_x509_empty_sig_and_unsigned_ocsp_crl();
    test_bug2_x509_malformed_extensions_bypass();
    test_bug3_handshake_forbidden_extensions_and_ch_rules();
    test_bug4_sha384_nst_resumption_psk();
    test_bug5_post_handshake_server_rejects_client_nst();
    test_tlsc01_tls_feature_must_staple();
    test_tlsc02_sct_list_parsing();
    test_tlsc04_eku_parsing_and_enforcement();
    test_tlsc05_email_name_constraints();
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
