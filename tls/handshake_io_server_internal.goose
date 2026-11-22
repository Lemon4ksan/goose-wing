// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal live TLS 1.3 server handshake flight, client auth verification, and key setup.
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
import net.tcp;
import net.transport;
import .handshake_io_client_internal;
import .handshake_wire_internal;
import .session_slot_internal;
import .session_wire_internal;

// Validates mTLS client Certificate and CertificateVerify against trust anchor store (RFC 8446 §4.4).
fn verify_client_cert_and_signature(
    cert_body:          const u8[:],
    cv_body:            const u8[:],
    transcript_to_cert: const u8[:],
    trust_store:        const tls::TrustAnchorStore&,
    now_unix:           i64,
) -> bool {
    var chain_slices: const u8[:][..8] = [];
    let _, ok_chain = parse_certificate_chain_and_ocsp(cert_body, chain_slices);
    guard ok_chain else { return false; }

    var chain_parsed: tls::ParsedCert[..8] = [];
    for idx in chain_slices.len {
        var c_parsed = tls::ParsedCert { .. };
        guard tls::parse_x509_certificate(chain_slices[idx], c_parsed) &&
            chain_parsed.try_push(c_parsed) else {
            return false;
        }
    }

    let alert = tls::verify_certificate_chain(
        chain_parsed, chain_slices, trust_store, now_unix, tls::CertValidationRole.Client,
    );
    guard alert == tls::Alert.CloseNotify else { return false; }

    let leaf_cert .= chain_parsed[0];
    // RFC 8446 Section 4.4.2.2: Server Certificate - Signing certificates must include digitalSignature KeyUsage.
    if leaf_cert.has_key_usage && (leaf_cert.key_usage & rfc::KEY_USAGE_DIGITAL_SIGNATURE) == 0 {
        return false;
    }
    var leaf_pub = tls::span_slice(chain_slices[0], leaf_cert.spki_pubkey);
    if leaf_pub.len >= 2 && leaf_pub[0] == 0 { leaf_pub = leaf_pub[1..]; }

    let sig_scheme, sig_bytes, ok_parse_cv = tls::parse_certificate_verify(cv_body);
    let spki_oid = tls::span_slice(chain_slices[0], leaf_cert.spki_alg_oid);
    guard ok_parse_cv && tls::verify_signature_scheme_curve_binding(sig_scheme, spki_oid) else {
        return false;
    }

    var cv_msg_buf: u8[160] = [0; 160];
    let cv_len, ok_cv_msg = tls::build_certificate_verify_message(false, transcript_to_cert, cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }
    return verify_cv_sig_with_min_rsa(sig_scheme, sig_bytes, leaf_pub, cv_msg_buf[..cv_len]);
}

// Parses a TLS 1.3 ClientHello message for server-side negotiation (RFC 8446 Section 4.1.2).
//
// Example:
//   payload = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, ...0x13, 0x01...]
//   returns: true, out_cipher_suite = 0x1301
fn parse_client_hello_for_server_full<A>(
    payload:             const u8[:],
    server_alpn_csv:     const u8[:],
    required_sig_scheme: u16,
    out_session_id:      u8[..32]&,
    out_client_pub:      u8[32]&,
    out_alpn:            A&,
    out_sni:             u8[..255]&,
    out_cipher_suite:    u16&,
    out_psk_resumed:     bool&,
    out_psk_secret:      u8[..48]&,
    out_selected_psk_id: u16&,
    require_client_cert: bool = false,
) -> bool {
    out_session_id.clear();
    core::secure_zeroize_32(out_client_pub);
    out_alpn.clear();
    out_sni.clear();
    out_cipher_suite = 0;
    out_psk_resumed = false;
    core::secure_zeroize_slice(out_psk_secret[..]);
    out_psk_secret.clear();
    out_selected_psk_id = 0;
    var committed = false;
    defer if !committed {
        out_session_id.clear();
        core::secure_zeroize_32(out_client_pub);
        out_alpn.clear();
        out_sni.clear();
        out_cipher_suite = 0;
        out_psk_resumed = false;
        core::secure_zeroize_slice(out_psk_secret[..]);
        out_psk_secret.clear();
        out_selected_psk_id = 0;
    };

    var entries: tls::ExtensionEntry[..32] = [];
    let sel_cs, ok_pre = decode_ch_server_preamble(payload, out_session_id, entries);
    guard ok_pre else { return false; }
    let sig_ext, ok_mand = extract_ch_mandatory_exts(entries, out_client_pub);
    guard ok_mand else { return false; }

    let sni_ext, has_sni = tls::find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    if has_sni {
        guard tls::parse_sni_extension(sni_ext, out_sni) else { return false; }
    }
    let alpn_ext, has_alpn = tls::find_extension(entries, rfc::TLS_EXT_ALPN);
    if has_alpn {
        guard select_server_alpn_from_ext(alpn_ext, server_alpn_csv, out_alpn) else { return false; }
    }
    let psk_ext, has_psk = tls::find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
    if has_psk {
        let psk_matched, psk_ok = eval_client_hello_psk_entry(
            entries, payload, psk_ext, sel_cs, out_psk_secret, out_selected_psk_id, require_client_cert,
        );
        guard psk_ok else { return false; }
        out_psk_resumed = psk_matched;
    }
    if !out_psk_resumed && required_sig_scheme != 0 {
        guard validate_ch_sig_algorithms(sig_ext, required_sig_scheme) else { return false; }
    }
    out_cipher_suite = sel_cs;
    committed = true;
    return true;
}

fn tls_server_send_cv(
    fd:            i64,
    cipher_suite:  u16,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    server_seq:    u64&,
    priv_seed:     const u8[32]&,
    transcript:    tls::Transcript&,
    cert_der:      const u8[:] = "",
) -> bool {
    let hash_id: u8 = if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        tls_internal::HASH_SHA384
    } else {
        tls_internal::HASH_SHA256
    };
    var h_to_cert: u8[..48] = [];
    transcript_current_hash(transcript, hash_id, h_to_cert);
    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = tls::build_certificate_verify_message(true, h_to_cert[..], cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }
    var sig_buf: u8[..128] = [];
    let sig_scheme, ok_sig = sign_certificate_verify(
        cert_der, priv_seed, cv_msg_buf[..cv_len], sig_buf,
    );
    guard ok_sig else { return false; }

    var cv_payload: u8[..512] = [];
    guard tls::encode_client_certificate_verify(cv_payload, sig_scheme, sig_buf[..]) else { return false; }
    var cv_msg: u8[..512] = [];
    cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
    cv_msg.append_u24_be(cv_payload.len as u32);
    cv_msg.append(cv_payload[..]);

    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cv_msg[..]) else {
        return false;
    }
    server_seq = core::add_sat_u64(server_seq, 1);
    transcript_update(transcript, cv_msg[..]);
    return true;
}

fn tls_server_send_ee(
    fd:              i64,
    cipher_suite:    u16,
    server_hs_key:   const u8[:],
    server_hs_iv:    const u8[12]&,
    server_seq:      u64&,
    negotiated_alpn: const u8[:],
    transcript:      tls::Transcript&,
) -> bool {
    var ee_ext: u8[..264] = [];
    if negotiated_alpn.len > 0 {
        encode_alpn_extension_from_csv(ee_ext, negotiated_alpn);
    }
    var ee_msg: u8[..280] = [];
    ee_msg.push(rfc::TLS_HS_ENCRYPTED_EXTENSIONS);
    ee_msg.append_u24_be(core::add_sat_i64(2, ee_ext.len) as u32);
    ee_msg.append_u16_be(ee_ext.len as u16);
    ee_msg.append(ee_ext[..]);
    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, ee_msg[..]) else {
        return false;
    }
    server_seq = core::add_sat_u64(server_seq, 1);
    transcript_update(transcript, ee_msg[..]);
    return true;
}

fn tls_server_send_cert_req(
    fd:            i64,
    cipher_suite:  u16,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    server_seq:    u64&,
    transcript:    tls::Transcript&,
) -> bool {
    let sig_algs: u16[5] = [
        rfc::SIG_SCHEME_ED25519,
        rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        rfc::SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384,
    ];
    var cr_payload: u8[..128] = [];
    guard tls::encode_certificate_request(cr_payload, "", sig_algs[..]) else { return false; }
    var cr_msg: u8[..140] = [];
    guard cr_msg.try_push(rfc::TLS_HS_CERTIFICATE_REQUEST) else { return false; }
    cr_msg.append_u24_be(cr_payload.len as u32);
    guard cr_msg.try_append(cr_payload[..]) else { return false; }
    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cr_msg[..]) else {
        return false;
    }
    server_seq = core::add_sat_u64(server_seq, 1);
    transcript_update(transcript, cr_msg[..]);
    return true;
}

fn tls_server_recv_client_auth(
    hs_reader:     tls::HandshakeRecordReader&,
    fd:            i64,
    cipher_suite:  u16,
    client_hs_key: const u8[:],
    client_hs_iv:  const u8[12]&,
    ks:            const tls_internal::KeySchedule&,
    transcript:    tls::Transcript&,
    config:        const tls::ServerHandshakeConfig&,
) -> bool {
    var msg_cert:  u8          = 0;
    var cert_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, client_hs_key, client_hs_iv,
        msg_cert, cert_body, config.handshake_timeout_ms,
    ) && msg_cert == rfc::TLS_HS_CERTIFICATE else { return false; }
    transcript_update_msg(transcript, msg_cert, cert_body[..]);

    var h_to_cert: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cert);

    var msg_cv:  u8          = 0;
    var cv_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, client_hs_key, client_hs_iv,
        msg_cv, cv_body, config.handshake_timeout_ms,
    ) && msg_cv == rfc::TLS_HS_CERTIFICATE_VERIFY else { return false; }

    let now_unix = core::now().wall_sec;
    guard verify_client_cert_and_signature(
        cert_body[..], cv_body[..], h_to_cert[..], config.client_trust_store, now_unix,
    ) else { return false; }
    transcript_update_msg(transcript, msg_cv, cv_body[..]);
    return true;
}

// Encrypts and transmits the server handshake flight: EncryptedExtensions, [CertificateRequest],
// [Certificate, CertificateVerify], Finished.
fn tls_server_send_flight(
    fd:                        i64,
    server_hs_key:             const u8[:],
    server_hs_iv:              const u8[12]&,
    ks:                        const tls_internal::KeySchedule&,
    transcript:                tls::Transcript&,
    config:                    const tls::ServerHandshakeConfig&,
    negotiated_alpn:           const u8[:],
    psk_resumed:               bool,
    negotiated_cert_comp_algo: u16 = 0,
    cipher_suite:              u16 = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
) -> bool {
    var server_seq: u64 = 0;

    guard tls_server_send_ee(
        fd, cipher_suite, server_hs_key, server_hs_iv,
        server_seq, negotiated_alpn, transcript,
    ) else { return false; }

    if !psk_resumed && config.require_client_cert {
        guard tls_server_send_cert_req(
            fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, transcript,
        ) else { return false; }
    }

    if !psk_resumed {
        var cert_msg: u8[..4096] = [];
        guard encode_server_cert_or_compressed_msg(config, negotiated_cert_comp_algo, cert_msg) else {
            return false;
        }

        guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cert_msg[..]) else {
            return false;
        }
        server_seq = core::add_sat_u64(server_seq, 1);
        transcript_update(transcript, cert_msg[..]);

        guard tls_server_send_cv(
            fd, cipher_suite, server_hs_key, server_hs_iv,
            server_seq, config.priv_seed, transcript, config.cert_der[..],
        ) else {
            return false;
        }
    }

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var srv_fin_data: u8[48] = [0; 48];
    defer core::secure_zeroize_48(srv_fin_data);
    let hlen = ks.hash_len as i64;
    let ok_fin_calc = tls_internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen],
        h_to_cv[..], srv_fin_data[..hlen],
    );
    guard ok_fin_calc else { return false; }

    let fin_len = core::add_sat_i64(4, hlen);
    var srv_fin_msg: u8[64] = [0; 64];
    srv_fin_msg[0] = rfc::TLS_HS_FINISHED;
    srv_fin_msg[1] = 0; srv_fin_msg[2] = 0; srv_fin_msg[3] = ks.hash_len;
    core::ct_copy_bytes(srv_fin_msg[4..fin_len], srv_fin_data[..hlen]);

    let ok_send_fin = tls_seal_and_send_hs(
        fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, srv_fin_msg[..fin_len],
    );
    guard ok_send_fin else { return false; }
    transcript_update(transcript, srv_fin_msg[..fin_len]);
    return true;
}

fn tls_setup_server_cipher_slot(
    slot_idx:     u16,
    cipher_suite: u16,
    key_len_u16:  u16,
    ks:           const tls_internal::KeySchedule&,
    s_ap_key:     const u8[:],
    s_ap_iv:      const u8[12]&,
    c_ap_key:     const u8[:],
    c_ap_iv:      const u8[12]&,
) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else { return; }
    tls::g_tls_cipher_slots[idx].cipher_suite = cipher_suite;
    tls::g_tls_cipher_slots[idx].key_len = key_len_u16;
    tls::g_tls_cipher_slots[idx].hash_id = ks.hash_id;
    tls::g_tls_cipher_slots[idx].hash_len = ks.hash_len;
    tls::g_tls_cipher_slots[idx].is_server = true;
    for i in s_ap_key.len { tls::g_tls_cipher_slots[idx].tx_key[i] = s_ap_key[i]; }
    prepare_cipher_aes_key(cipher_suite, s_ap_key, tls::g_tls_cipher_slots[idx].tx_aes_key);
    for i in 12 { tls::g_tls_cipher_slots[idx].tx_iv[i] = s_ap_iv[i]; }
    tls::g_tls_cipher_slots[idx].tx_seq = 0;
    for i in c_ap_key.len { tls::g_tls_cipher_slots[idx].rx_key[i] = c_ap_key[i]; }
    prepare_cipher_aes_key(cipher_suite, c_ap_key, tls::g_tls_cipher_slots[idx].rx_aes_key);
    for i in 12 { tls::g_tls_cipher_slots[idx].rx_iv[i] = c_ap_iv[i]; }
    tls::g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { tls::g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
}

//
// Example:
//   payload = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, 0x00, 0x13, 0x01]
//   returns: true, out_session_id = [], out_client_pub = [32 bytes], out_sni = "api.example.com"
fn parse_client_hello_for_server_sni(
    payload:         const u8[:],
    server_alpn_csv: const u8[:],
    out_session_id:  u8[..32]&,
    out_client_pub:  u8[32]&,
    out_alpn:        u8[..32]&,
    out_sni:         u8[..255]&,
    out_psk_resumed: bool&,
    out_psk_secret:  u8[32]&,
) -> bool {
    core::secure_zeroize_32(out_psk_secret);
    var full_psk: u8[..48] = [];
    defer core::secure_zeroize_slice(full_psk[..]);
    var sel_cs: u16 = 0;
    var sel_id: u16 = 0;
    guard parse_client_hello_for_server_full(
        payload, server_alpn_csv, 0, out_session_id, out_client_pub,
        out_alpn, out_sni, sel_cs, out_psk_resumed, full_psk, sel_id,
    ) else { return false; }
    if out_psk_resumed && full_psk.len >= 32 {
        core::ct_copy_bytes(out_psk_secret[..], full_psk[0..32]);
    }
    return true;
}

// Parses ClientHello payload for server handshake, extracting session ID, client X25519 key share, ALPN, and PSK.
//
// Example:
//   payload = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, 0x00, 0x13, 0x01]
//   returns: true, out_session_id = [], out_client_pub = [32 bytes]
fn parse_client_hello_for_server(
    payload:         const u8[:],
    server_alpn_csv: const u8[:],
    out_session_id:  u8[..32]&,
    out_client_pub:  u8[32]&,
    out_alpn:        u8[..32]&,
    out_psk_resumed: bool&,
    out_psk_secret:  u8[32]&,
) -> bool {
    var unused_sni: u8[..255] = [];
    return parse_client_hello_for_server_sni(
        payload, server_alpn_csv, out_session_id, out_client_pub,
        out_alpn, unused_sni, out_psk_resumed, out_psk_secret,
    );
}

// Generates ephemeral server randomness, X25519 keypair, and ECDHE shared secret.
// Fails closed and wipes secret material if OS CSPRNG or X25519 key exchange fails.
fn generate_server_handshake_keys(
    client_pub:       const u8[32]&,
    out_random:       u8[32]&,
    out_server_pub:   u8[32]&,
    out_ecdhe_secret: u8[32]&,
) -> bool {
    var committed = false;
    defer if !committed {
        core::secure_zeroize_32(out_random);
        core::secure_zeroize_32(out_server_pub);
        core::secure_zeroize_32(out_ecdhe_secret);
    };
    var server_priv: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_priv);
    guard random_bytes_32_checked(out_random) && random_bytes_32_checked(server_priv) else {
        return false;
    }
    out_server_pub = core::x25519_base_scalarmult(server_priv);
    var ecdhe, ok_ecdhe = core::x25519_shared_secret(server_priv, client_pub);
    defer core::secure_zeroize_32(ecdhe);
    guard ok_ecdhe else { return false; }
    out_ecdhe_secret = ecdhe;
    committed = true;
    return true;
}
