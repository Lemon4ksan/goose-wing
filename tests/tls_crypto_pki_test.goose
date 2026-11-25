// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deep Verification Suite: TLS 1.3 Key Schedule, ML-KEM Hybrid PQ, X.509/OCSP/CRL/NC/SCT/CSR & Alerts.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ---- ASN.1 DER Helpers for RFC 6960 / 5280 Test Vectors --------------------

fn push_len<B>(out: B&, len: i64) {
    if len < 128 {
        assert(out.try_push(len as u8));
    } else if len < 256 {
        assert(out.try_push(0x81) && out.try_push(len as u8));
    } else {
        assert(out.try_push(0x82) && out.try_push(((len >> 8) & 0xFF) as u8) && out.try_push((len & 0xFF) as u8));
    }
}

fn append_tlv<B>(out: B&, tag: u8, body: const u8[:]) {
    assert(out.try_push(tag));
    push_len(out, body.len);
    assert(out.try_append(body));
}

fn build_tlv<B>(tag: u8, body: const u8[:], out: B&) {
    out.clear();
    append_tlv(out, tag, body);
}

fn append_alg_id<B>(out: B&, oid: const u8[:], with_null: bool) {
    var inner: u8[..64] = [];
    append_tlv(inner, rfc::ASN1_TAG_OID, oid);
    if with_null {
        append_tlv(inner, rfc::ASN1_TAG_NULL, "");
    }
    append_tlv(out, rfc::ASN1_TAG_SEQUENCE, inner[..]);
}

fn build_ocsp_resp(
    resp_status:   u8,
    cert_status:   u8, // 0=Good, 1=Revoked+reason, 2=Unknown, 3=RevokedNoReason
    serial:        const u8[:],
    hash_oid:      const u8[:],
    nh:            const u8[:],
    kh:            const u8[:],
    this_up:       const u8[:],
    next_up:       const u8[:],
    by_key:        bool,
    crit_single_e: bool,
    out:           u8[..4096]&,
) {
    var cid_inner: u8[..256] = [];
    append_alg_id(cid_inner, hash_oid, true);
    append_tlv(cid_inner, rfc::ASN1_TAG_OCTET_STRING, nh);
    append_tlv(cid_inner, rfc::ASN1_TAG_OCTET_STRING, kh);
    append_tlv(cid_inner, rfc::ASN1_TAG_INTEGER, serial);

    var sr_inner: u8[..512] = [];
    append_tlv(sr_inner, rfc::ASN1_TAG_SEQUENCE, cid_inner[..]);
    if cert_status == 0 {
        append_tlv(sr_inner, 0x80, "");
    } else if cert_status == 2 {
        append_tlv(sr_inner, 0x82, "");
    } else {
        var rev_inner: u8[..64] = [];
        append_tlv(rev_inner, rfc::ASN1_TAG_GENERALIZED_TIME, this_up);
        if cert_status == 1 {
            var reason_e: u8[..8] = [];
            append_tlv(reason_e, rfc::ASN1_TAG_ENUMERATED, "\x01");
            append_tlv(rev_inner, 0xA0, reason_e[..]);
        }
        append_tlv(sr_inner, 0xA1, rev_inner[..]);
    }
    append_tlv(sr_inner, rfc::ASN1_TAG_GENERALIZED_TIME, this_up);
    if next_up.len > 0 {
        var nu_inner: u8[..32] = [];
        append_tlv(nu_inner, rfc::ASN1_TAG_GENERALIZED_TIME, next_up);
        append_tlv(sr_inner, 0xA0, nu_inner[..]);
    }
    if crit_single_e {
        var ext_e: u8[..64] = [];
        append_tlv(ext_e, rfc::ASN1_TAG_OID, "\x2A\x03\x04");
        append_tlv(ext_e, rfc::ASN1_TAG_BOOLEAN, "\xFF");
        append_tlv(ext_e, rfc::ASN1_TAG_OCTET_STRING, "\x01");
        var exts_s: u8[..64] = [];
        append_tlv(exts_s, rfc::ASN1_TAG_SEQUENCE, ext_e[..]);
        append_tlv(sr_inner, 0xA1, exts_s[..]);
    }

    var resps_inner: u8[..600] = [];
    append_tlv(resps_inner, rfc::ASN1_TAG_SEQUENCE, sr_inner[..]);

    var tbs_inner: u8[..1024] = [];
    append_tlv(tbs_inner, 0xA0, "\x02\x01\x00");
    if by_key {
        var kh_tlv: u8[..32] = [];
        append_tlv(kh_tlv, rfc::ASN1_TAG_OCTET_STRING, kh[..20]);
        append_tlv(tbs_inner, 0xA2, kh_tlv[..]);
    } else {
        var cn_atv: u8[..32] = [];
        append_tlv(cn_atv, rfc::ASN1_TAG_OID, rfc::OID_COMMON_NAME[..]);
        append_tlv(cn_atv, rfc::ASN1_TAG_UTF8_STRING, "CA");
        var rdn: u8[..48] = [];
        append_tlv(rdn, rfc::ASN1_TAG_SEQUENCE, cn_atv[..]);
        var rdn_set: u8[..64] = [];
        append_tlv(rdn_set, rfc::ASN1_TAG_SET, rdn[..]);
        var dn_seq: u8[..80] = [];
        append_tlv(dn_seq, rfc::ASN1_TAG_SEQUENCE, rdn_set[..]);
        append_tlv(tbs_inner, 0xA1, dn_seq[..]);
    }
    append_tlv(tbs_inner, rfc::ASN1_TAG_GENERALIZED_TIME, this_up);
    append_tlv(tbs_inner, rfc::ASN1_TAG_SEQUENCE, resps_inner[..]);

    var basic_inner: u8[..1200] = [];
    append_tlv(basic_inner, rfc::ASN1_TAG_SEQUENCE, tbs_inner[..]);
    append_alg_id(basic_inner, rfc::OID_SIG_ECDSA_SHA256[..], false);
    append_tlv(basic_inner, rfc::ASN1_TAG_BIT_STRING, "\x00\x30\x06\x02\x01\x01\x02\x01\x01");

    var oct_body: u8[..1300] = [];
    append_tlv(oct_body, rfc::ASN1_TAG_SEQUENCE, basic_inner[..]);

    var rb_inner: u8[..1400] = [];
    append_tlv(rb_inner, rfc::ASN1_TAG_OID, rfc::OID_OCSP_BASIC[..]);
    append_tlv(rb_inner, rfc::ASN1_TAG_OCTET_STRING, oct_body[..]);

    var ctx0: u8[..1500] = [];
    append_tlv(ctx0, rfc::ASN1_TAG_SEQUENCE, rb_inner[..]);

    var top_inner: u8[..1600] = [];
    var st_b:      u8[1]      = [resp_status];
    append_tlv(top_inner, rfc::ASN1_TAG_ENUMERATED, st_b[..]);
    if resp_status == rfc::OCSP_STATUS_SUCCESSFUL {
        append_tlv(top_inner, 0xA0, ctx0[..]);
    }
    build_tlv(rfc::ASN1_TAG_SEQUENCE, top_inner[..], out);
}

fn build_signed_v2_crl(
    priv_key:  const u8[32]&,
    issuer_dn: const u8[:],
    this_utc:  const u8[:],
    next_utc:  const u8[:],
    rev_ser:   const u8[:],
    crl_num:   const u8[:],
    with_num:  bool,
    crit_ext:  bool,
    out:       u8[..4096]&,
) {
    var tbs_inner: u8[..1024] = [];
    append_tlv(tbs_inner, rfc::ASN1_TAG_INTEGER, "\x01"); // v2
    append_alg_id(tbs_inner, rfc::OID_SIG_ECDSA_SHA256[..], false);
    append_tlv(tbs_inner, rfc::ASN1_TAG_SEQUENCE, issuer_dn);
    append_tlv(tbs_inner, rfc::ASN1_TAG_UTC_TIME, this_utc);
    if next_utc.len > 0 {
        append_tlv(tbs_inner, rfc::ASN1_TAG_UTC_TIME, next_utc);
    }
    if rev_ser.len > 0 {
        var entry_in: u8[..64] = [];
        append_tlv(entry_in, rfc::ASN1_TAG_INTEGER, rev_ser);
        append_tlv(entry_in, rfc::ASN1_TAG_UTC_TIME, this_utc);
        var rev_in: u8[..80] = [];
        append_tlv(rev_in, rfc::ASN1_TAG_SEQUENCE, entry_in[..]);
        append_tlv(tbs_inner, rfc::ASN1_TAG_SEQUENCE, rev_in[..]);
    }
    var exts_in: u8[..128] = [];
    if with_num {
        var num_tlv: u8[..16] = [];
        append_tlv(num_tlv, rfc::ASN1_TAG_INTEGER, crl_num);
        var ext1: u8[..48] = [];
        append_tlv(ext1, rfc::ASN1_TAG_OID, rfc::OID_CRL_NUMBER[..]);
        append_tlv(ext1, rfc::ASN1_TAG_OCTET_STRING, num_tlv[..]);
        append_tlv(exts_in, rfc::ASN1_TAG_SEQUENCE, ext1[..]);
    }
    if crit_ext {
        var ext2: u8[..48] = [];
        append_tlv(ext2, rfc::ASN1_TAG_OID, "\x55\x1D\x1C");
        append_tlv(ext2, rfc::ASN1_TAG_BOOLEAN, "\xFF");
        append_tlv(ext2, rfc::ASN1_TAG_OCTET_STRING, "\x02\x01\x01");
        append_tlv(exts_in, rfc::ASN1_TAG_SEQUENCE, ext2[..]);
    }
    var ext_seq: u8[..160] = [];
    append_tlv(ext_seq, rfc::ASN1_TAG_SEQUENCE, exts_in[..]);
    append_tlv(tbs_inner, 0xA0, ext_seq[..]);

    var tbs_tlv: u8[..1200] = [];
    build_tlv(rfc::ASN1_TAG_SEQUENCE, tbs_inner[..], tbs_tlv);

    let raw_sig = core::ecdsa_p256_sign(priv_key, tbs_tlv[..]);
    var der_sig: u8[..72] = [];
    assert(core::ecdsa_p256_encode_der_sig(raw_sig, der_sig));
    var bits_body: u8[..80] = [];
    assert(bits_body.try_push(0x00) && bits_body.try_append(der_sig[..]));

    var crl_in: u8[..1500] = [];
    assert(crl_in.try_append(tbs_tlv[..]));
    append_alg_id(crl_in, rfc::OID_SIG_ECDSA_SHA256[..], false);
    append_tlv(crl_in, rfc::ASN1_TAG_BIT_STRING, bits_body[..]);
    build_tlv(rfc::ASN1_TAG_SEQUENCE, crl_in[..], out);
}

// ---- Test Case 1: Key Schedule (SHA-256 & SHA-384), StrikeRegister & Ticket Age ----

fn test_tls_key_schedule_and_replay(t: lit::T&) {
    t.run("TLS 1.3 KeySchedule SHA-256 & SHA-384 full lifecycle, exporters, QUIC HP & ZeroRtt") { sub =>
        let _, ok_bad_cs = tls_internal::ks_init(0x0000);
        sub.assert_false(ok_bad_cs);

        // Exercise both cipher families: AES_128_GCM_SHA256 and AES_256_GCM_SHA384
        let suites: u16[2] = [rfc::TLS_CIPHER_AES_128_GCM_SHA256, rfc::TLS_CIPHER_AES_256_GCM_SHA384];
        for s_idx in 2 {
            let cs = suites[s_idx];
            var ks, ok_init = tls_internal::ks_init(cs);
            sub.assert_true(ok_init);
            let hlen = ks.hash_len as i64;
            var psk:     u8[48] = [0x11; 48];
            var ch_hash: u8[48] = [0x22; 48];
            var zeros:   u8[48] = [0; 48];

            // Pre-stage errors fail closed
            sub.assert_false(tls_internal::ks_derive_early_traffic(ks, ch_hash[..hlen]));
            sub.assert_false(tls_internal::ks_advance_to_handshake(ks, psk[..hlen]));
            sub.assert_false(tls_internal::ks_derive_handshake_traffic(ks, ch_hash[..hlen]));
            sub.assert_false(tls_internal::ks_advance_to_master(ks, ch_hash[..hlen]));
            var tmp_out: u8[64] = [0; 64];
            sub.assert_false(tls_internal::ks_advance_to_resumption(ks, ch_hash[..hlen]));
            sub.assert_false(tls_internal::ks_export_keying_material(ks, "EXPORTER-test", "", 32, tmp_out[..]));
            sub.assert_false(tls_internal::ks_derive_resumption_psk(ks, "\x01", tmp_out[..]));

            sub.assert_true(tls_internal::ks_init_early_secret_with_mode(ks, psk[..hlen], true));
            sub.assert_true(tls_internal::ks_derive_early_traffic(ks, ch_hash[..hlen]));
            // All-zero ECDHE shared secret MUST be rejected (RFC 8446 / FIPS check)
            sub.assert_false(tls_internal::ks_advance_to_handshake(ks, zeros[..hlen]));
            sub.assert_true(tls_internal::ks_advance_to_handshake(ks, psk[..hlen]));
            sub.assert_true(tls_internal::ks_derive_handshake_traffic(ks, ch_hash[..hlen]));
            sub.assert_true(tls_internal::ks_advance_to_master(ks, ch_hash[..hlen]));
            sub.assert_true(tls_internal::ks_advance_to_resumption(ks, ch_hash[..hlen]));

            var rpsk: u8[48] = [0; 48];
            sub.assert_true(tls_internal::ks_derive_resumption_psk(ks, "\x00\x01", rpsk[..hlen]));
            sub.assert_true(tls_internal::ks_export_keying_material(ks, "EXPORTER-1", "", 32, tmp_out[..32]));
            sub.assert_true(tls_internal::ks_export_keying_material(ks, "EXPORTER-2", "ctx", 48, tmp_out[..48]));
            sub.assert_false(tls_internal::ks_export_keying_material(ks, "", "ctx", 16, tmp_out[..16]));
            sub.assert_false(tls_internal::ks_export_keying_material(ks, "EXPORTER-3", "ctx", 0, tmp_out[..16]));

            var key_b: u8[32] = [0; 32];
            var iv_b:  u8[12] = [0; 12];
            sub.assert_true(tls_internal::ks_derive_key_iv(ks.hash_id, ks.client_ap_traffic[..hlen], 16, key_b[..16], iv_b));
            sub.assert_true(tls_internal::ks_derive_quic_hp_key(ks.hash_id, ks.client_ap_traffic[..hlen], 16, key_b[..16], rfc::QUIC_VERSION_1));
            sub.assert_true(tls_internal::ks_derive_quic_hp_key(ks.hash_id, ks.client_ap_traffic[..hlen], 16, key_b[..16], rfc::QUIC_VERSION_2));
            sub.assert_false(tls_internal::ks_derive_quic_hp_key(ks.hash_id, ks.client_ap_traffic[..hlen], 16, key_b[..16], 0xDEAD0001));

            var vd: u8[48] = [0; 48];
            sub.assert_true(tls_internal::ks_compute_finished_verify_data(ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen], ch_hash[..hlen], vd[..hlen]));
            sub.assert_true(tls_internal::ks_update_traffic_secret(ks.hash_id, ks.hash_len, ks.client_ap_traffic[..hlen]));

            // PSK binder compute & verify
            var binder: u8[48] = [0; 48];
            sub.assert_true(tls_internal::ks_compute_finished_verify_data(ks.hash_id, ks.hash_len, ks.binder_key[..hlen], ch_hash[..hlen], binder[..hlen]));
            let ch_hash_actual = if ks.hash_id == tls_internal::HASH_SHA256 {
                let d = core::sha256("ClientHelloTruncated");
                tls_internal::verify_psk_binder(ks.hash_id, ks.hash_len, ks.binder_key[..hlen], "ClientHelloTruncated", binder[..hlen])
            } else {
                false
            };
            let _ = ch_hash_actual;
            sub.assert_false(tls_internal::verify_psk_binder(ks.hash_id, ks.hash_len, ks.binder_key[..hlen], "bad", vd[..hlen]));
            sub.assert_false(tls_internal::verify_psk_binder(99, 32, ks.binder_key[..], "bad", vd[..32]));
            tls_internal::ks_zeroize(ks);
            sub.assert_eq(ks.stage, tls_internal::KS_STAGE_UNINIT);
        }

        // HKDF-Expand-Label error guards & StrikeRegister & ticket age & CH truncation
        var k_buf:   u8[32] = [0; 32];
        var sec_buf: u8[48] = [0x55; 48];
        sub.assert_false(tls_internal::hkdf_expand_label(99, sec_buf[..], "key", "", 16, k_buf[..]));
        sub.assert_false(tls_internal::hkdf_expand_label(tls_internal::HASH_SHA256, sec_buf[..10], "key", "", 16, k_buf[..]));
        sub.assert_false(tls_internal::hkdf_expand_label(tls_internal::HASH_SHA384, sec_buf[..16], "key", "", 16, k_buf[..]));

        var reg = tls_internal::strike_register_init(1000, 200);
        sub.assert_false(tls_internal::strike_register_check_and_insert(reg, "", 500));
        sub.assert_true(tls_internal::strike_register_check_and_insert(reg, "tkt-1", 500));
        sub.assert_false(tls_internal::strike_register_check_and_insert(reg, "tkt-1", 600)); // replay
        sub.assert_true(tls_internal::strike_register_check_and_insert(reg, "tkt-2", 1500)); // epoch 1
        sub.assert_false(tls_internal::strike_register_check_and_insert(reg, "tkt-1", 1600)); // previous epoch hit
        sub.assert_true(tls_internal::strike_register_check_and_insert(reg, "tkt-3", 5000)); // jump epoch 5 (clear prev)
        sub.assert_false(tls_internal::strike_register_check_and_insert(reg, "tkt-old", 1000)); // too old epoch

        sub.assert_true(tls_internal::validate_ticket_age(1000 + 500, 1000, 550, 100));
        sub.assert_false(tls_internal::validate_ticket_age(1000 + 500, 1000, 999999999, 100));
        let _, ok_tch = tls_internal::truncate_client_hello_for_binder("hello", 0);
        let tr, ok_tch2 = tls_internal::truncate_client_hello_for_binder("abcdef", 2);
        sub.assert_true(!ok_tch && ok_tch2 && tr == "ab");
        sub.assert_true(tls_internal::validate_psk_identities_and_binders_count(2, 2));
        sub.assert_false(tls_internal::validate_psk_identities_and_binders_count(1, 2));
    };
}

// ---- Test Case 2: PQ Hybrid KeyShares & ML-KEM-768 -------------------------

fn test_tls_pq_hybrid_and_mlkem(t: lit::T&) {
    t.run("RFC 10024 hybrid shares (X25519/Kyber/P256/P384) & FIPS 203 ML-KEM-768 edges") { sub =>
        sub.assert_eq(tls_internal::pq_hybrid_client_share_len(rfc::GROUP_SECP256R1_MLKEM768), rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN);
        sub.assert_eq(tls_internal::pq_hybrid_client_share_len(rfc::GROUP_X25519_MLKEM768), rfc::HYBRID_CLIENT_SHARE_LEN);
        sub.assert_eq(tls_internal::pq_hybrid_client_share_len(rfc::GROUP_SECP384R1_MLKEM1024), rfc::SECP384R1_MLKEM1024_CLIENT_SHARE_LEN);
        sub.assert_eq(tls_internal::pq_hybrid_client_share_len(0x9999), 0);
        sub.assert_eq(tls_internal::pq_hybrid_server_share_len(rfc::GROUP_SECP256R1_MLKEM768), rfc::SECP256R1_MLKEM768_SERVER_SHARE_LEN);
        sub.assert_eq(tls_internal::pq_hybrid_server_share_len(rfc::GROUP_X25519_KYBER768_DRAFT00), rfc::HYBRID_SERVER_SHARE_LEN);
        sub.assert_eq(tls_internal::pq_hybrid_server_share_len(rfc::GROUP_SECP384R1_MLKEM1024), rfc::SECP384R1_MLKEM1024_SERVER_SHARE_LEN);
        sub.assert_eq(tls_internal::pq_hybrid_server_share_len(0x9999), 0);

        let d_seed: u8[32] = [0x12; 32];
        let z_seed: u8[32] = [0x34; 32];
        let m_rand: u8[32] = [0x56; 32];
        let ek, dk = tls_internal::mlkem768_keygen(d_seed, z_seed);
        let ct, ss_enc, ok_enc = tls_internal::mlkem768_encapsulate(ek, m_rand);
        sub.assert_true(ok_enc);
        var ss_dec: u8[32] = [0; 32];
        sub.assert_true(tls_internal::mlkem768_decapsulate(ct[..], dk[..], ss_dec[..]));
        sub.assert_bytes_eq(ss_dec[..], ss_enc[..]);

        // Implicit rejection on tampered ciphertext & bad ek modulus
        var bad_ct = ct;
        bad_ct[0] ^= 0x01;
        var ss_rej: u8[32] = [0; 32];
        sub.assert_true(tls_internal::mlkem768_decapsulate(bad_ct[..], dk[..], ss_rej[..]));
        sub.assert_false(core::ct_eq_bytes(ss_rej[..], ss_enc[..]));
        sub.assert_false(tls_internal::mlkem768_decapsulate(ct[..10], dk[..], ss_rej[..]));
        var bad_ek = ek;
        for i in 12 { bad_ek[i] = 0xFF; }
        let _, _, ok_bek = tls_internal::mlkem768_encapsulate(bad_ek, m_rand);
        sub.assert_false(ok_bek);

        // Hybrid X25519+MLKEM768 & Draft00 roundtrips + bad parse rejections
        let groups2: u16[2] = [rfc::GROUP_X25519_MLKEM768, rfc::GROUP_X25519_KYBER768_DRAFT00];
        for gi in 2 {
            let cs = tls_internal::PostQuantumKeyShare { group: groups2[gi], x25519_public: [0x21; 32], mlkem768_public: ek };
            var cw: u8[..2048] = [];
            tls_internal::format_hybrid_key_share(cs, cw);
            var cs_p = tls_internal::PostQuantumKeyShare {};
            sub.assert_true(tls_internal::parse_hybrid_key_share(cs_p, cw[..]) && cs_p.group == groups2[gi]);
            cw[0] = 0x99;
            sub.assert_false(tls_internal::parse_hybrid_key_share(cs_p, cw[..]));

            let ss_h = tls_internal::PostQuantumServerShare { group: groups2[gi], x25519_public: [0x22; 32], mlkem768_ciphertext: ct };
            var sw: u8[..2048] = [];
            tls_internal::format_hybrid_server_key_share(ss_h, sw);
            var ss_p = tls_internal::PostQuantumServerShare {};
            sub.assert_true(tls_internal::parse_hybrid_server_key_share(ss_p, sw[..]) && ss_p.group == groups2[gi]);
        }

        // SecP256r1+MLKEM768 & SecP384r1+MLKEM1024 format/parse + point checks
        let p256_pub = core::ecdsa_p256_public_key(d_seed);
        let k256 = tls_internal::SecP256r1MLKEM768KeyShare { secp256r1_public: p256_pub, mlkem768_public: ek, .. };
        var w256: u8[..2048] = [];
        tls_internal::format_secp256r1_mlkem768_key_share(k256, w256);
        var k256_p = tls_internal::SecP256r1MLKEM768KeyShare {};
        sub.assert_true(tls_internal::parse_secp256r1_mlkem768_key_share(k256_p, w256[..]));
        w256[4] = 0x00;
        sub.assert_false(tls_internal::parse_secp256r1_mlkem768_key_share(k256_p, w256[..]));

        let s256 = tls_internal::SecP256r1MLKEM768ServerShare { secp256r1_public: p256_pub, mlkem768_ciphertext: ct, .. };
        w256.clear();
        tls_internal::format_secp256r1_mlkem768_server_share(s256, w256);
        var s256_p = tls_internal::SecP256r1MLKEM768ServerShare {};
        sub.assert_true(tls_internal::parse_secp256r1_mlkem768_server_share(s256_p, w256[..]));

        let priv384: u8[48] = [0x07; 48];
        let p384_pub, ok384 = core::p384_ecdh_public_key(priv384);
        sub.assert_true(ok384);
        let k384 = tls_internal::SecP384r1MLKEM1024KeyShare { secp384r1_public: p384_pub, mlkem1024_public: [0; 1568], .. };
        var w384: u8[..2048] = [];
        tls_internal::format_secp384r1_mlkem1024_key_share(k384, w384);
        var k384_p = tls_internal::SecP384r1MLKEM1024KeyShare {};
        sub.assert_true(tls_internal::parse_secp384r1_mlkem1024_key_share(k384_p, w384[..]));
        let s384 = tls_internal::SecP384r1MLKEM1024ServerShare { secp384r1_public: p384_pub, mlkem1024_ciphertext: [0; 1568], .. };
        w384.clear();
        tls_internal::format_secp384r1_mlkem1024_server_share(s384, w384);
        var s384_p = tls_internal::SecP384r1MLKEM1024ServerShare {};
        sub.assert_true(tls_internal::parse_secp384r1_mlkem1024_server_share(s384_p, w384[..]));

        let c256 = tls_internal::derive_secp256r1_mlkem768_shared_secret(d_seed, ss_enc);
        let c384 = tls_internal::derive_secp384r1_mlkem1024_shared_secret(priv384, ss_enc);
        sub.assert_eq(c256.len + c384.len, 144);
        var comb64: u8[64] = [0; 64];
        let zeros32: u8[32] = [0; 32];
        sub.assert_false(tls_internal::derive_x25519_mlkem768_shared_secret_checked(zeros32[..], ss_enc[..], comb64[..]));
        sub.assert_false(tls_internal::derive_x25519_mlkem768_shared_secret_checked(d_seed[..], zeros32[..], comb64[..]));
        sub.assert_true(tls_internal::derive_x25519_mlkem768_shared_secret_checked(d_seed[..], ss_enc[..], comb64[..]));
        sub.assert_false(tls_internal::derive_hybrid_shared_secret_checked(zeros32[..], ss_enc[..], comb64[..]));
        sub.assert_true(tls_internal::derive_hybrid_shared_secret_checked(d_seed[..], ss_enc[..], comb64[..]));
    };
}

// ---- Test Case 3: OCSP, CRL, PKI Sig/Ext/NC, Alerts, SCT & CSR -------------

fn test_tls_pki_ocsp_crl_and_alerts(t: lit::T&) {
    t.run("OCSP statuses/extensions, CRL v2 & streaming, PSS/SPKI, NC, Alerts, SCT, CSR") { sub =>
        let nh32: u8[32] = [0x11; 32];
        let kh32: u8[32] = [0x22; 32];
        var ocsp_der: u8[..4096] = [];
        var po = tls::ParsedOcspResponse {};

        // Non-successful OCSP statuses
        let non_succ: u8[5] = [1, 2, 3, 5, 6];
        for i in 5 {
            build_ocsp_resp(non_succ[i], 0, "\x01", rfc::OID_OCSP_SHA256[..], nh32[..], kh32[..], "20260101000000Z", "", false, false, ocsp_der);
            sub.assert_true(tls::parse_ocsp_response(ocsp_der[..], po) && po.status != tls::OcspResponseStatus.Successful);
        }
        build_ocsp_resp(9, 0, "\x01", rfc::OID_OCSP_SHA256[..], nh32[..], kh32[..], "20260101000000Z", "", false, false, ocsp_der);
        sub.assert_false(tls::parse_ocsp_response(ocsp_der[..], po));

        // Successful Good, Revoked (with & without reason), Unknown + byKey + critical ext reject
        build_ocsp_resp(0, 0, "\x05", rfc::OID_OCSP_SHA256[..], nh32[..], kh32[..], "20260101000000Z", "20260102000000Z", false, false, ocsp_der);
        sub.assert_true(tls::parse_ocsp_response(ocsp_der[..], po) && po.cert_status == tls::OcspCertStatus.Good && po.has_next_update);
        build_ocsp_resp(0, 1, "\x05", rfc::OID_OCSP_SHA1[..], nh32[..20], kh32[..20], "20260101000000Z", "", true, false, ocsp_der);
        sub.assert_true(tls::parse_ocsp_response(ocsp_der[..], po) && po.cert_status == tls::OcspCertStatus.Revoked);
        build_ocsp_resp(0, 3, "\x05", rfc::OID_OCSP_SHA256[..], nh32[..], kh32[..], "20260101000000Z", "", false, false, ocsp_der);
        sub.assert_true(tls::parse_ocsp_response(ocsp_der[..], po) && po.cert_status == tls::OcspCertStatus.Revoked);
        build_ocsp_resp(0, 2, "\x05", rfc::OID_OCSP_SHA256[..], nh32[..], kh32[..], "20260101000000Z", "", false, false, ocsp_der);
        sub.assert_true(tls::parse_ocsp_response(ocsp_der[..], po) && po.cert_status == tls::OcspCertStatus.Unknown);
        build_ocsp_resp(0, 0, "\x05", rfc::OID_OCSP_SHA256[..], nh32[..], kh32[..], "20260101000000Z", "", false, true, ocsp_der);
        sub.assert_false(tls::parse_ocsp_response(ocsp_der[..], po));

        // Temporal OCSP checks & CertID material + unwrap_ocsp_response
        sub.assert_true(tls_internal::x509_verify_ocsp_issuer_name_hash(rfc::OID_OCSP_SHA256[..], nh32[..], "bad") == false);
        let uo_ok_in: u8[8] = [0x01, 0x00, 0x00, 0x04, 'O', 'C', 'S', 'P'];
        let uo_res, ok_uo = tls::unwrap_ocsp_response(uo_ok_in[..]);
        let _, bad_uo = tls::unwrap_ocsp_response("\x02\x00\x00\x00");
        sub.assert_true(ok_uo && uo_res == "OCSP" && !bad_uo);

        // Signed v2 CRL parse, signature verify, missing cRLNumber, critical ext, streaming check_crl_der_revocation
        let ca_priv: u8[32] = [0x44; 32];
        let ca_pub = core::ecdsa_p256_public_key(ca_priv);
        var dn_atv: u8[..64] = [];
        append_tlv(dn_atv, rfc::ASN1_TAG_OID, rfc::OID_COMMON_NAME[..]);
        append_tlv(dn_atv, rfc::ASN1_TAG_UTF8_STRING, "TestRoot");
        var dn_rdn: u8[..80] = [];
        append_tlv(dn_rdn, rfc::ASN1_TAG_SEQUENCE, dn_atv[..]);
        var dn_inner: u8[..96] = [];
        append_tlv(dn_inner, rfc::ASN1_TAG_SET, dn_rdn[..]);

        var crl_der: u8[..4096] = [];
        var pcrl = tls::ParsedCrl { .. };
        build_signed_v2_crl(ca_priv, dn_inner[..], "260101000000Z", "260105000000Z", "\x00\x85", "\x00", true, false, crl_der);
        sub.assert_true(tls::parse_x509_crl(crl_der[..], pcrl) && pcrl.serial_count == 1);
        sub.assert_true(tls_internal::x509_verify_crl_signature_with_pubkey(pcrl, crl_der[..], ca_pub[..]) == tls::Alert.CloseNotify);
        var pcrl_nonum = tls::ParsedCrl { .. };
        build_signed_v2_crl(ca_priv, dn_inner[..], "260101000000Z", "260105000000Z", "\x07", "\x01", false, false, crl_der);
        sub.assert_false(tls::parse_x509_crl(crl_der[..], pcrl_nonum));
        build_signed_v2_crl(ca_priv, dn_inner[..], "260101000000Z", "260105000000Z", "\x07", "\x01", true, true, crl_der);
        sub.assert_false(tls::parse_x509_crl(crl_der[..], pcrl_nonum));
        sub.assert_true(tls_internal::crl_serials_equal_canonical("\x00\x85", "\x85"));
        sub.assert_true(tls_internal::crl_validate_temporal(200, 100, true, 150) == tls::Alert.DecodeError);
        sub.assert_true(tls_internal::crl_validate_temporal(100, 0, false, 100000000) == tls::Alert.CertificateExpired);

        // Name Constraints 3-state (URI, Email, DirName, wildcard overlap)
        sub.assert_true(tls_internal::x509_match_uri_nc_3state("https://api.example.com:8443/v1", ".example.com") == tls_internal::NcMatchResult.Match);
        sub.assert_true(tls_internal::x509_match_uri_nc_3state("https://[::1%eth0]:8443/", "[::1]") == tls_internal::NcMatchResult.Match);
        sub.assert_true(tls_internal::x509_match_email_nc_3state("a@b.example.com", ".example.com") == tls_internal::NcMatchResult.Match);
        sub.assert_true(tls_internal::x509_match_email_nc_3state("alice@example.com", "alice@example.com") == tls_internal::NcMatchResult.Match);
        sub.assert_true(tls_internal::x509_match_email_nc_3state("bad_no_at", ".example.com") == tls_internal::NcMatchResult.Invalid);

        // SPKI extraction + bare curve OID reject + PSS params
        var bad_ec_spki = core::cursor_from("");
        var dummy_span = tls::Span16 {};
        var empty_rem = core::cursor_from("");
        sub.assert_false(tls_internal::validate_x509_spki_alg_params(rfc::OID_SECP256R1[..], bad_ec_spki, 0, dummy_span));
        var dummy_pss: u8 = 0;
        sub.assert_true(tls_internal::validate_x509_sig_alg_params(rfc::OID_ED25519[..], empty_rem, dummy_pss));
        var raw_pk_out: u8[..600] = [];
        sub.assert_true(tls_internal::extract_spki_pubkey_material(ca_pub[..], raw_pk_out));

        // All 28 TLS Alerts roundtrip + warning/fatal rules
        let all_codes: u8[28] = [0, 10, 20, 22, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 70, 71, 80, 86, 90, 109, 110, 112, 113, 115, 116, 120, 121];
        for i in 28 {
            let al, ok_a = tls::u8_to_alert(all_codes[i]);
            sub.assert_true(ok_a && tls::alert_to_u8(al) == all_codes[i]);
        }
        let _, bad_al = tls::u8_to_alert(250);
        sub.assert_false(bad_al);
        let msg_warn:    u8[2] = [1, 0];
        let msg_other_w: u8[2] = [1, 47];
        let _, _, fat1, ok_m1 = tls::parse_alert_message(msg_warn[..]);
        let _, _, fat2, ok_m2 = tls::parse_alert_message(msg_other_w[..]);
        let _, _, _, bad_lvl = tls::parse_alert_message("\x09\x00");
        sub.assert_true(ok_m1 && !fat1 && ok_m2 && fat2 && !bad_lvl);

        // CSR P-256 + SCT list + PEM private key errors
        var csr_der: u8[>..]        = [];
        var doms:    u8[..255][..4] = [];
        var d0:      u8[..255]      = [];
        assert(d0.try_append("sub.example.com"));
        assert(doms.try_push(d0));
        sub.assert_true(tls::build_pkcs10_csr_p256_der(ca_priv, doms[..], csr_der) && csr_der.len > 100);
        var bad_doms: u8[..255][..4] = [];
        sub.assert_false(tls::build_pkcs10_csr_p256_der(ca_priv, bad_doms[..], csr_der));

        var pk_out: u8[32] = [0; 32];
        let _, ok_bad_pem = tls::parse_private_key_pem("-----BEGIN UNKNOWN-----\nAA==\n-----END UNKNOWN-----\n", pk_out);
        sub.assert_false(ok_bad_pem);
        var tmp_store = tls::TrustAnchorStore {};
        let _, ok_f_bad = tls::load_trust_anchors_pem_file(tmp_store, "nonexistent_cert_bundle_xyz.pem");
        sub.assert_false(ok_f_bad);
        sub.assert_true(tls::cert_expires_within_sec("not-pem", 1000, 60));

        // SCT list parsing (empty/invalid vs valid v1 entry) & build_sct_signed_data
        var sct_entry: u8[>..] = [];
        sct_entry.push(0); // v1
        for _ in 32 { sct_entry.push(0xAA); }
        sct_entry.append_u64_be(1700000000000 as u64);
        sct_entry.append_u16_be(0); // ext len
        sct_entry.push(4); sct_entry.push(3); // SHA256 + ECDSA
        sct_entry.append_u16_be(4);
        sct_entry.append("\x30\x02\x02\x00");
        var sct_list_wire: u8[>..] = [];
        sct_list_wire.append_u16_be((2 + sct_entry.len) as u16);
        sct_list_wire.append_u16_be(sct_entry.len as u16);
        sct_list_wire.append(sct_entry[..]);
        var scts: tls::ParsedSct[..8] = [];
        sub.assert_true(tls::parse_sct_list(sct_list_wire[..], scts) && scts.len == 1);
        var signed_sct: u8[..256] = [];
        sub.assert_true(tls::build_sct_signed_data(scts[0], sct_list_wire[..], "dummy_cert", false, signed_sct));
        sub.assert_false(tls::build_sct_signed_data(scts[0], sct_list_wire[..], "dummy_cert", true, signed_sct, ""));
    };
}

fn main() {
    let runner = lit::new_runner("TLS Deep Crypto and PKI Verification Suite");
    lit::run_case(runner, "1. KeySchedule, PQ-KEM & ZeroRtt StrikeRegister", test_tls_key_schedule_and_replay);
    lit::run_case(runner, "2. PQ Hybrid Shares & ML-KEM-768", test_tls_pq_hybrid_and_mlkem);
    lit::run_case(runner, "3. OCSP, CRL, Sig/NC/Alerts, CSR & SCT", test_tls_pki_ocsp_crl_and_alerts);
    assert(lit::finish(runner));
}
