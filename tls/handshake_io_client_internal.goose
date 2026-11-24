// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal live TLS 1.3 client handshake flight, HRR, certificate verification, and key setup.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .record_internal;
import .key_schedule;
import .handshake;
import .handshake_internal;
import .ech_internal;
import .asn1;
import .types;
import .sct;
import .x509;
import .pem;
import .ocsp;
import .crl;
import .ticket;
import .ticket_internal;
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .cert_compression;
import .ech;
import .session_internal;
import .session_codec_internal;
import .session;
import .handshake_wire_internal;
import .session_slot_internal;
import .session_wire_internal;
import security.hpke;

// Parses and validates intermediate X.509 certificates after the leaf entry (`idx = 1..parse_limit-1`).
//
// Example:
//   chain_slices = [leaf_der, inter_der], parse_limit = 2
//   returns: true, chain_parsed.len = 2
fn parse_server_cert_chain_tail(
    chain_slices:  const (const u8[:])[..64]&,
    parse_limit:   i64,
    chain_parsed:  tls::ParsedCert[..8]&,
    verify_slices: (const u8[:])[..8]&,
) -> bool {
    var idx: i64 = 1;
    while idx < parse_limit {
        var c_parsed = tls::ParsedCert { .. };
        guard tls::parse_x509_certificate(chain_slices[idx], c_parsed) else { return false; }
        guard chain_parsed.try_push(c_parsed) && verify_slices.try_push(chain_slices[idx]) else { return false; }
        idx = core::add_sat_i64(idx, 1);
    }
    return true;
}

fn verify_server_leaf_cv_sig(
    leaf_cert:            const tls::ParsedCert&,
    leaf_der:             const u8[:],
    cv_body:              const u8[:],
    transcript_to_cert:   const u8[:],
    insecure_skip_verify: bool,
) -> bool {
    if leaf_cert.has_key_usage && (leaf_cert.key_usage & rfc::KEY_USAGE_DIGITAL_SIGNATURE) == 0 {
        return false;
    }
    let leaf_spki_oid = tls::span_slice(leaf_der, leaf_cert.spki_alg_oid);
    guard leaf_spki_oid != rfc::OID_SIG_RSASSA_PSS[..] else { return false; }

    var leaf_pub = tls::span_slice(leaf_der, leaf_cert.spki_pubkey);
    if leaf_pub.len >= 2 && leaf_pub[0] == 0 { leaf_pub = leaf_pub[1..]; }

    let sig_scheme, sig_bytes, ok_parse_cv = tls::parse_certificate_verify(cv_body);
    guard ok_parse_cv else { return false; }

    if !insecure_skip_verify {
        guard tls::verify_signature_scheme_curve_binding(sig_scheme, leaf_spki_oid) else { return false; }
    }

    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = tls::build_certificate_verify_message(true, transcript_to_cert, cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }

    return verify_cv_sig_with_min_rsa(sig_scheme, sig_bytes, leaf_pub, cv_msg_buf[..cv_len]);
}

fn verify_server_chain_and_san(
    leaf_cert:     const tls::ParsedCert&,
    chain_parsed:  const tls::ParsedCert[..8]&,
    verify_slices: const (const u8[:])[..8]&,
    leaf_ocsp:     const u8[:],
    config:        const tls::ClientHandshakeConfig&,
) -> bool {
    guard !config.insecure_skip_verify else { return true; }
    // RFC 6125 / RFC 8446 Section 4.4.2: Require explicit target server_name when verifying certificates.
    guard config.server_name.len > 0 else { return false; }
    let eff_clock = if config.virtual_clock_sec > 0 { config.virtual_clock_sec } else { core::now().wall_sec };
    guard verify_chain_ocsp_and_crl(chain_parsed, verify_slices, leaf_ocsp, config, eff_clock) else {
        return false;
    }
    return tls::match_cert_san_host(leaf_cert, verify_slices[0], config.server_name[..]);
}

// Validates server Certificate and CertificateVerify against trust anchor store and transcript (RFC 8446 §4.4).
fn verify_server_cert_and_signature(
    cert_body:          const u8[:],
    cv_body:            const u8[:],
    transcript_to_cert: const u8[:],
    config:             const tls::ClientHandshakeConfig&,
    slot_idx:           u16 = 0xFFFF,
) -> bool {
    var chain_slices: const u8[:][..64] = [];
    let leaf_ocsp, ok_chain = parse_certificate_chain_and_ocsp(cert_body, chain_slices);
    guard ok_chain else { return false; }
    var leaf_cert = tls::ParsedCert { .. };
    guard tls::parse_x509_certificate(chain_slices[0], leaf_cert) else { return false; }
    if slot_idx != 0xFFFF { let _ = tls::populate_slot_san_hosts_from_der(slot_idx, chain_slices[0]); }

    var chain_parsed:  tls::ParsedCert[..8] = [];
    var verify_slices: const u8[:][..8]     = [];
    guard chain_parsed.try_push(leaf_cert) && verify_slices.try_push(chain_slices[0]) else { return false; }

    let parse_limit = if config.insecure_skip_verify { 1 } else { chain_slices.len };
    guard parse_server_cert_chain_tail(chain_slices, parse_limit, chain_parsed, verify_slices) else { return false; }
    guard verify_server_chain_and_san(leaf_cert, chain_parsed, verify_slices, leaf_ocsp, config) else { return false; }

    return verify_server_leaf_cv_sig(
        leaf_cert, chain_slices[0], cv_body, transcript_to_cert, config.insecure_skip_verify,
    );
}

fn classify_ee_failure_alert(ee_body: const u8[:]) -> tls::Alert {
    var entries: tls::ExtensionEntry[..32] = [];
    guard tls::parse_extensions_block(ee_body, entries) else { return tls::Alert.DecodeError; }
    for &e in entries {
        if e.ext_type == rfc::TLS_EXT_SERVER_NAME && e.data.len != 0 {
            return tls::Alert.DecodeError;
        }
    }
    return tls::Alert.UnsupportedExtension;
}

fn has_duplicate_extension_type(ext_block: const u8[:]) -> bool {
    var c = core::cursor_from(ext_block);
    var body, ok_b = c.read_u16_sub_cursor();
    guard ok_b && c.cursor_len() == 0 else { return false; }
    var seen: u16[..32] = [];
    while body.cursor_len() > 0 {
        let et, ok_t = body.read_u16();
        let _, ok_d = body.read_u16_prefixed();
        guard ok_t && ok_d else { return false; }
        if seen.contains(et) { return true; }
        guard seen.try_push(et) else { return false; }
    }
    return false;
}

fn has_unsolicited_cert_entry_ext(ext_bytes: const u8[:]) -> bool {
    var cur = core::cursor_from(ext_bytes);
    while cur.cursor_len() > 0 {
        let et, ok_t = cur.read_u16();
        let _, ok_d = cur.read_u16_prefixed();
        guard ok_t && ok_d else { return false; }
        if et != rfc::TLS_EXT_STATUS_REQUEST && et != rfc::TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP {
            return true;
        }
    }
    return false;
}

fn classify_cert_failure_alert(cert_body: const u8[:]) -> tls::Alert {
    var c = core::cursor_from(cert_body);
    let ctx, ok_ctx = c.read_u8_prefixed();
    guard ok_ctx && ctx.len == 0 else { return tls::Alert.DecodeError; }
    let list_bytes, ok_list = c.read_u24_prefixed();
    guard ok_list && c.cursor_len() == 0 else { return tls::Alert.DecodeError; }
    var lc = core::cursor_from(list_bytes);
    while lc.cursor_len() > 0 {
        let cert_bytes, ok_c = lc.read_u24_prefixed();
        let ext_bytes, ok_e = lc.read_u16_prefixed();
        guard ok_c && cert_bytes.len > 0 && ok_e else { return tls::Alert.DecodeError; }
        if ext_bytes.len > 0 && has_unsolicited_cert_entry_ext(ext_bytes) {
            return tls::Alert.UnsupportedExtension;
        }
    }
    return tls::Alert.DecodeError;
}

fn classify_sh_failure_alert(sh_msg: const u8[:]) -> tls::Alert {
    let _, msg_len, ok_hdr = tls::parse_handshake_header(sh_msg);
    if ok_hdr && sh_msg.len > core::add_sat_i64(4, msg_len) {
        return tls::Alert.UnexpectedMessage;
    }
    var tmp = tls::ParsedServerHello { .. };
    var rand_arr: u8[32] = [0; 32];
    let ext_bytes, ok_pre = read_server_hello_preamble(sh_msg, rand_arr, tmp);
    guard ok_pre else { return tls::Alert.DecodeError; }
    var entries: tls::ExtensionEntry[..32] = [];
    if !tls::parse_extensions_block(ext_bytes, entries) {
        return if has_duplicate_extension_type(ext_bytes) {
            tls::Alert.IllegalParameter
        } else {
            tls::Alert.DecodeError
        };
    }
    if !validate_sh_or_hrr_extensions(entries, tmp.is_hrr) {
        return tls::Alert.UnsupportedExtension;
    }
    return tls::Alert.IllegalParameter;
}

fn tls_setup_client_cipher_slot(
    slot_idx:     u16,
    cipher_suite: u16,
    key_len_u16:  u16,
    ks:           const tls_internal::KeySchedule&,
    c_ap_key:     const u8[:],
    c_ap_iv:      const u8[12]&,
    s_ap_key:     const u8[:],
    s_ap_iv:      const u8[12]&,
    server_name:  const u8[:],
    neg_alpn:     const u8[:],
    psk_resumed:  bool,
) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else { return; }
    let _ = tls::g_tls_cipher_slots[idx].server_name.try_set(server_name);
    let _ = tls::g_tls_cipher_slots[idx].negotiated_alpn.try_set(neg_alpn);
    tls::g_tls_cipher_slots[idx].resumed = psk_resumed;
    tls::g_tls_cipher_slots[idx].cipher_suite = cipher_suite;
    tls::g_tls_cipher_slots[idx].key_len = key_len_u16;
    tls::g_tls_cipher_slots[idx].hash_id = ks.hash_id;
    tls::g_tls_cipher_slots[idx].hash_len = ks.hash_len;
    tls::g_tls_cipher_slots[idx].is_server = false;
    for i in c_ap_key.len { tls::g_tls_cipher_slots[idx].tx_key[i] = c_ap_key[i]; }
    prepare_cipher_aes_key(cipher_suite, c_ap_key, tls::g_tls_cipher_slots[idx].tx_aes_key);
    for i in 12 { tls::g_tls_cipher_slots[idx].tx_iv[i] = c_ap_iv[i]; }
    tls::g_tls_cipher_slots[idx].tx_seq = 0;
    for i in s_ap_key.len { tls::g_tls_cipher_slots[idx].rx_key[i] = s_ap_key[i]; }
    prepare_cipher_aes_key(cipher_suite, s_ap_key, tls::g_tls_cipher_slots[idx].rx_aes_key);
    for i in 12 { tls::g_tls_cipher_slots[idx].rx_iv[i] = s_ap_iv[i]; }
    tls::g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { tls::g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
}

fn patch_client_hello_psk_binder<B>(ch_msg: B&, psk_secret: const u8[:], psk_suite: u16) {
    guard ch_msg.len > 35 && (psk_secret.len == 32 || psk_secret.len == 48) else { return; }
    let suite = if rfc::is_supported_tls13_cipher_suite(psk_suite) {
        psk_suite
    } else {
        rfc::TLS_CIPHER_AES_128_GCM_SHA256
    };
    var ks_early, ok_kse = tls_internal::ks_init(suite);
    defer tls_internal::ks_zeroize(ks_early);
    guard ok_kse && tls_internal::ks_init_early_secret(ks_early, psk_secret) else { return; }
    let hlen = ks_early.hash_len;
    let entry_len: u16 = if hlen == 48 { 49 } else { 33 };
    let trunc_ch, ok_tr = tls_internal::truncate_client_hello_for_binder(ch_msg[..], entry_len);
    var binder: u8[..48] = [];
    defer core::secure_zeroize_slice(binder[..]);
    guard ok_tr && compute_tls13_psk_binder_for_hash(
        ks_early.hash_id, ks_early.binder_key[..hlen as i64], trunc_ch, binder,
    ) else { return; }
    while ch_msg.len > trunc_ch.len { ch_msg.pop(); }
    ch_msg.append_u16_be(entry_len);
    ch_msg.push(hlen);
    ch_msg.append(binder[..]);
}

// Locates the ciphertext payload offset of `encrypted_client_hello` inside a ClientHelloOuter body.
//
// Example:
//   ch_payload = [0x03, 0x03, ...extensions containing 0xFE0D...], ct_len = 160
//   returns: offset to payload[0..160], ok = true
fn find_ch_outer_ech_payload_offset(ch_payload: const u8[:], ct_len: i64) -> i64, bool {
    var c = core::cursor_from(ch_payload);
    let _, ok_v = c.read_u16();
    let _, ok_r = c.read_bytes(32);
    let _, ok_s = c.read_u8_prefixed();
    let _, ok_cs = c.read_u16_prefixed();
    let _, ok_cm = c.read_u8_prefixed();
    guard ok_v && ok_r && ok_s && ok_cs && ok_cm else { return 0, false; }
    var exts, ok_e = c.read_u16_sub_cursor();
    guard ok_e && c.buf.len == 0 else { return 0, false; }

    var ext_base = core::sub_sat_i64(ch_payload.len, exts.buf.len);
    while exts.buf.len > 0 {
        let et, ok_t = exts.read_u16();
        let data, ok_d = exts.read_u16_prefixed();
        guard ok_t && ok_d else { return 0, false; }
        let data_off = core::add_sat_i64(ext_base, 4);
        if et == rfc::EXT_ENCRYPTED_CLIENT_HELLO {
            var ec = core::cursor_from(data);
            let _, ok_hdr = ec.read_bytes(6);
            let enc, ok_enc = ec.read_u16_prefixed();
            let pay, ok_pay = ec.read_u16_prefixed();
            guard ok_hdr && ok_enc && ok_pay && ec.buf.len == 0 && pay.len == ct_len else {
                return 0, false;
            }
            let pay_off = core::add_sat_i64(data_off, core::add_sat_i64(10, enc.len));
            guard core::add_sat_i64(pay_off, ct_len) <= ch_payload.len else { return 0, false; }
            return pay_off, true;
        }
        ext_base = core::add_sat_i64(data_off, data.len);
    }
    return 0, false;
}

fn init_ech_sender_state(
    config:    const tls::ClientHandshakeConfig&,
    ech_state: EchClientState&,
    out_enc:   u8[32]&,
) -> bool {
    var ech_list = tls::EchConfigList { .. };
    guard tls::parse_ech_config_list(config.ech_config_list[..], ech_list) else { return false; }
    guard tls::select_ech_config(ech_list, ech_state.cfg, ech_state.cs) else { return false; }
    var eph_sk: u8[32] = [0; 32];
    defer core::secure_zeroize_32(eph_sk);
    guard random_bytes_32_checked(ech_state.inner_random) && random_bytes_32_checked(eph_sk) else {
        return false;
    }
    var info: u8[..2064] = [];
    info.append("tls ech");
    info.push(0x00);
    guard info.try_append(ech_state.cfg.raw_bytes[..]) else { return false; }
    guard security::hpke_setup_base_s(
        ech_state.cfg.public_key, info[..], ech_state.cfg.kem_id,
        ech_state.cs.kdf_id, ech_state.cs.aead_id, eph_sk, out_enc, ech_state.hpke_ctx,
    ) else { return false; }
    ech_state.active = true;
    ech_state.fsm = tls::EchFsm {
        mode:              tls::EchHandshakeMode.Offered,
        has_hrr:           false,
        offered_config_id: ech_state.cfg.config_id,
    };
    return true;
}

// Builds RFC 9849 ClientHelloOuter sealed with ClientHelloOuterAAD (zeroed payload bytes)
// and records ClientHelloInner into `ech_state.inner_tr`. Fails closed on any ECH error.
fn build_ech_sealed_client_hello(
    config:        const tls::ClientHandshakeConfig&,
    client_random: const u8[32]&,
    client_pub:    const u8[32]&,
    enable_pq:     bool,
    pq_pub:        const u8[:],
    hrr_cookie:    const u8[:],
    nist_pub:      const u8[:],
    is_hrr_ch2:    bool,
    ech_state:     EchClientState&,
    out_ch_msg:    u8[..4096]&,
) -> bool {
    var ech_enc: u8[32] = [0; 32];
    if !is_hrr_ch2 {
        guard init_ech_sender_state(config, ech_state, ech_enc) else { return false; }
    }
    let outer_exts: u16[3] = [
        rfc::TLS_EXT_SUPPORTED_GROUPS,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS,
        rfc::TLS_EXT_KEY_SHARE,
    ];
    let inner_sni = if config.server_name.len > 0 { config.server_name[..] } else { ech_state.cfg.public_name[..] };
    var inner_padded: u8[..512] = [];
    defer core::secure_zeroize_slice(inner_padded[..]);
    guard build_encoded_client_hello_inner(
        inner_padded, ech_state.inner_random, inner_sni, config.alpn[..],
        outer_exts[..], ech_state.cfg.maximum_name_length,
    ) else { return false; }

    var ch_inner_pay: u8[..4096] = [];
    let inner_ech_ext: u8[1] = [rfc::ECH_CLIENT_INNER];
    build_client_hello_payload(
        ech_state.inner_random, client_pub, inner_sni, config.alpn[..],
        ch_inner_pay, "", 0, enable_pq, pq_pub, inner_ech_ext[..],
        hrr_cookie, config.client_cert_der.len > 0, 32, nist_pub,
    );
    guard frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch_inner_pay[..], ech_state.ch_inner_msg) else {
        return false;
    }
    transcript_update(ech_state.inner_tr, ech_state.ch_inner_msg[..]);

    let ct_len = core::add_sat_i64(inner_padded.len, 16);
    var zero_ct: u8[..544] = [];
    guard ct_len <= zero_ct.cap else { return false; }
    zero_ct.resize(ct_len, 0);
    var placeholder_ext: u8[..640] = [];
    guard build_ech_outer_extension(
        ech_state.cfg.config_id, ech_state.cs, ech_enc, zero_ct[..], placeholder_ext, !is_hrr_ch2,
    ) else { return false; }

    // RFC 9849 Section 5.2: Outer SNI MUST be public_name (never secret target server_name).
    var ch_outer_pay: u8[..4096] = [];
    build_client_hello_payload(
        client_random, client_pub, ech_state.cfg.public_name[..], config.alpn[..],
        ch_outer_pay, "", 0, enable_pq, pq_pub, placeholder_ext[..],
        hrr_cookie, config.client_cert_der.len > 0, 32, nist_pub,
    );
    let pay_off, ok_off = find_ch_outer_ech_payload_offset(ch_outer_pay[..], ct_len);
    guard ok_off else { return false; }

    var ech_ct: u8[..544] = [];
    guard security::hpke_seal(ech_state.hpke_ctx, ch_outer_pay[..], inner_padded[..], ech_ct) &&
        ech_ct.len == ct_len else { return false; }
    core::ct_copy_bytes(ch_outer_pay[pay_off..core::add_sat_i64(pay_off, ct_len)], ech_ct[..]);
    return frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch_outer_pay[..], out_ch_msg);
}

fn verify_ech_server_hello_acceptance(
    ech_state:  EchClientState&,
    sh:         const tls::ParsedServerHello&,
    sh_msg:     const u8[:],
    transcript: tls::Transcript&,
) -> bool {
    guard ech_state.active else {
        transcript_update(transcript, sh_msg);
        return true;
    }
    guard sh_msg.len >= rfc::ECH_SH_MIN_HEADER_LEN else { return false; }
    let hash_id: u8 = if sh.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        HASH_SHA384
    } else {
        HASH_SHA256
    };
    let expected_confirm, ok_c = compute_ech_confirm_from_transcript(
        ech_state.inner_random, ech_state.inner_tr, sh_msg, false, hash_id,
    );
    guard ok_c && ech_fsm_on_server_hello(
        ech_state.fsm, tls::EchServerHelloType.ServerHello, sh.has_ech_ext,
        sh_msg[rfc::ECH_SH_CONFIRM_START..rfc::ECH_SH_MIN_HEADER_LEN],
        expected_confirm, ech_state.retry_configs,
    ) else { return false; }
    if ech_state.fsm.mode == tls::EchHandshakeMode.Accepted {
        transcript = ech_state.inner_tr;
    }
    transcript_update(transcript, sh_msg);
    return true;
}

inline fn is_group_offered_in_client_hello(selected_group: u16, offered_group: u16, offered_pq: bool) -> bool {
    if selected_group == rfc::GROUP_X25519_MLKEM768 {
        return offered_pq;
    }
    return selected_group != 0 && selected_group == offered_group;
}

fn regenerate_client_hrr_keyshare(
    selected_group: u16,
    enable_pq_cfg:  bool,
    client_priv:    u8[32]&,
    client_pub:     u8[32]&,
    pq_priv:        u8[2400]&,
    pq_pub:         u8[1184]&,
    out_p384_priv:  u8[48]&,
    out_nist_pub:   u8[..97]&,
) -> bool, u16, bool {
    out_nist_pub.clear();
    guard selected_group != 0 else { return enable_pq_cfg, rfc::GROUP_X25519, true; }
    if selected_group == rfc::GROUP_X25519 {
        guard random_bytes_32_checked(client_priv) else { return false, 0, false; }
        client_pub = core::x25519_base_scalarmult(client_priv);
        return false, rfc::GROUP_X25519, true;
    }
    if selected_group == rfc::GROUP_SECP256R1 {
        guard random_bytes_32_checked(client_priv) else { return false, 0, false; }
        let pub65 = core::ecdsa_p256_public_key(client_priv);
        guard out_nist_pub.try_set(pub65[..]) else { return false, 0, false; }
        return false, rfc::GROUP_SECP256R1, true;
    }
    if selected_group == rfc::GROUP_SECP384R1 {
        var r1: u8[32] = [0; 32];
        var r2: u8[32] = [0; 32];
        defer core::secure_zeroize_32(r1);
        defer core::secure_zeroize_32(r2);
        guard random_bytes_32_checked(r1) && random_bytes_32_checked(r2) else { return false, 0, false; }
        core::ct_copy_bytes(out_p384_priv[0..32], r1[..]);
        core::ct_copy_bytes(out_p384_priv[32..48], r2[0..16]);
        let pub97, ok_p384 = core::p384_ecdh_public_key(out_p384_priv);
        guard ok_p384 && out_nist_pub.try_set(pub97[..]) else { return false, 0, false; }
        return false, rfc::GROUP_SECP384R1, true;
    }
    guard enable_pq_cfg && selected_group == rfc::GROUP_X25519_MLKEM768 else {
        return false, 0, false;
    }
    var pq_d: u8[32] = [0; 32];
    var pq_z: u8[32] = [0; 32];
    defer core::secure_zeroize_32(pq_d);
    defer core::secure_zeroize_32(pq_z);
    guard random_bytes_32_checked(client_priv) &&
        random_bytes_32_checked(pq_d) &&
        random_bytes_32_checked(pq_z) else { return false, 0, false; }
    client_pub = core::x25519_base_scalarmult(client_priv);
    var ek, dk = tls_internal::mlkem768_keygen(pq_d, pq_z);
    defer core::secure_zeroize_slice(dk[..]);
    pq_priv = dk;
    pq_pub = ek;
    return true, rfc::GROUP_X25519, true;
}
