// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TLS 1.3 Server Handshake Orchestrator (RFC 8446 §4, RFC 8879 Cert Compression).
namespace tls;

import std;
import core;
import .record;
import .record_internal;
import .key_schedule;
import .handshake;
import .handshake_internal;
import .types;
import .x509;
import .ticket;
import .post_quantum;
import .cert_compression;
import .session_internal;
import .session;
import .handshake_io_internal;
import net.tcp;

// Parses ClientHello payload for server handshake, extracting session ID,
// client X25519 key share, ALPN, SNI, and PSK.
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
    guard tls_internal::parse_client_hello_for_server_full(
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

// Executes full TLS 1.3 server handshake given an already-read ClientHello handshake message (RFC 8446 §4).
fn server_handshake_with_ch(
    fd:     i64,
    ch_msg: const u8[:],
    config: const ServerHandshakeConfig&,
) -> u16, bool {
    let slot_idx = alloc_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }
    let idx = slot_idx as i64;

    var transcript = Transcript { .. };
    transcript_update(transcript, ch_msg);

    var session_id:      u8[..32]  = [];
    var client_pub:      u8[32]    = [0; 32];
    var neg_alpn:        u8[..255] = [];
    var client_sni:      u8[..255] = [];
    var cipher_suite:    u16       = 0;
    var psk_resumed:     bool      = false;
    var psk_secret:      u8[..48]  = [];
    var selected_psk_id: u16       = 0;
    defer core::secure_zeroize_slice(psk_secret[..]);
    let req_sig = tls_internal::detect_cert_sig_scheme(config.cert_der[..]);
    guard tls_internal::parse_client_hello_for_server_full(
        ch_msg, config.alpn[..], req_sig, session_id, client_pub,
        neg_alpn, client_sni, cipher_suite, psk_resumed, psk_secret, selected_psk_id,
    ) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    var client_random: u8[32] = [0; 32];
    let _ = tls_internal::extract_ch_client_random(ch_msg, client_random);
    let _ = g_tls_cipher_slots[idx].server_name.try_set(client_sni[..]);

    var server_random: u8[32] = [0; 32];
    var server_pub:    u8[32] = [0; 32];
    var ecdhe_secret:  u8[32] = [0; 32];
    defer core::secure_zeroize_32(ecdhe_secret);
    guard generate_server_handshake_keys(client_pub, server_random, server_pub, ecdhe_secret) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var sh_payload: u8[..2048] = [];
    build_server_hello_payload(
        server_random, session_id[..], server_pub, sh_payload,
        psk_resumed, cipher_suite, selected_psk_id,
    );
    var sh_msg: u8[..2048] = [];
    sh_msg.push(rfc::TLS_HS_SERVER_HELLO);
    sh_msg.append_u24_be(sh_payload.len as u32);
    sh_msg.append(sh_payload[..]);

    guard tls_internal::send_plaintext_handshake_record(fd, sh_msg[..], rfc::TLS_LEGACY_VERSION_1_2) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    tls_internal::tls_write_all(fd, ccs[..]);
    transcript_update(transcript, sh_msg[..]);

    var ks, ok_ks = tls_internal::ks_init(cipher_suite);
    defer tls_internal::ks_zeroize(ks);
    let early_ikm = if psk_resumed { psk_secret[..] } else { "" };
    let ok_ks_adv = ok_ks &&
        tls_internal::ks_init_early_secret(ks, early_ikm) &&
        tls_internal::ks_advance_to_handshake(ks, ecdhe_secret[..]);
    guard ok_ks_adv else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ch_sh_hash: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    tls_internal::emit_tls13_hs_keylog(config.keylog_file[..], client_random, ks);

    let key_len_u16 = rfc::tls13_cipher_suite_key_len(cipher_suite);
    let klen = key_len_u16 as i64;
    let hlen = ks.hash_len as i64;
    var client_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_hs_key);
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_hs_key);
    var server_hs_iv: u8[12] = [0; 12];
    let ok_c_hs = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_hs_traffic[..hlen], key_len_u16,
        client_hs_key[..klen], client_hs_iv,
    );
    guard ok_c_hs else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_hs = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_hs_traffic[..hlen], key_len_u16,
        server_hs_key[..klen], server_hs_iv,
    );
    guard ok_s_hs else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let negotiated_cert_comp_algo = select_server_cert_comp_algo(ch_msg, config.compressed_cert_algo);
    guard tls_internal::tls_server_send_flight(
        fd, server_hs_key[..klen], server_hs_iv, ks,
        transcript, config, neg_alpn[..], psk_resumed, negotiated_cert_comp_algo, cipher_suite,
    ) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_srv_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard tls_internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    tls_internal::emit_tls13_app_keylog(config.keylog_file[..], client_random, ks);

    var hs_reader = HandshakeRecordReader { .. };
    if !psk_resumed && config.require_client_cert {
        guard tls_internal::tls_server_recv_client_auth(
            hs_reader, fd, cipher_suite, client_hs_key[..klen], client_hs_iv, ks, transcript, config,
        ) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    }

    var cli_fin_body: u8[..16384] = [];
    var msg_fin:      u8          = 0;
    let ok_msg = tls_internal::next_handshake_message(
        hs_reader, fd, cipher_suite, client_hs_key[..klen],
        client_hs_iv, msg_fin, cli_fin_body, config.handshake_timeout_ms,
    );
    guard ok_msg else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    guard msg_fin == rfc::TLS_HS_FINISHED &&
        cli_fin_body.len == hlen &&
        hs_reader.current_offset == hs_reader.current_record_plain.len else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_before_cli_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_before_cli_fin);
    var exp_cli_fin: u8[48] = [0; 48];
    let ok_exp_fin = tls_internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.client_hs_traffic[..hlen],
        h_before_cli_fin[..], exp_cli_fin[..hlen],
    );
    guard ok_exp_fin else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    guard core::ct_eq_bytes(exp_cli_fin[..hlen], cli_fin_body[..hlen]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    transcript_update_msg(transcript, msg_fin, cli_fin_body[..hlen]);
    var h_through_cli_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_cli_fin);
    tls_internal::ks_advance_to_resumption(ks, h_through_cli_fin[..]);

    var client_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_ap_key);
    var client_ap_iv:  u8[12] = [0; 12];
    var server_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_ap_key);
    var server_ap_iv: u8[12] = [0; 12];
    let ok_c_ap = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_ap_traffic[..hlen], key_len_u16,
        client_ap_key[..klen], client_ap_iv,
    );
    guard ok_c_ap else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_ap = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_ap_traffic[..hlen], key_len_u16,
        server_ap_key[..klen], server_ap_iv,
    );
    guard ok_s_ap else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    tls_internal::tls_setup_server_cipher_slot(
        slot_idx, cipher_suite, key_len_u16, ks,
        server_ap_key[..klen], server_ap_iv,
        client_ap_key[..klen], client_ap_iv,
    );
    g_tls_cipher_slots[idx].resumed = psk_resumed;
    let _ = g_tls_cipher_slots[idx].negotiated_alpn.try_set(neg_alpn[..]);
    return slot_idx, true;
}

// Executes full TLS 1.3 server handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn server_handshake(fd: i64, config: const ServerHandshakeConfig&) -> u16, bool {
    var ch_msg: u8[..16384] = [];
    guard tls_internal::read_plaintext_handshake_record(fd, ch_msg, config.handshake_timeout_ms) else {
        return 0xFFFF, false;
    }
    return server_handshake_with_ch(fd, ch_msg[..], config);
}
