// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TLS 1.3 Client Handshake Orchestrator (RFC 8446 §4, RFC 9849 ECH, RFC 10024 PQ Hybrid).
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
import .handshake_io_client_internal;
import .handshake_io_server_internal;
import net.tcp;
import .handshake_wire_internal;
import .ech_internal;
import .session_slot_internal;
import .session_wire_internal;

// Generates client handshake randomness, X25519 keypair, and optional ML-KEM-768 keypair.
// Fails closed and wipes all private key material if OS CSPRNG fails.

// Executes full TLS 1.3 client handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn client_handshake(fd: i64, config: const ClientHandshakeConfig&) -> u16, bool {
    let slot_idx = alloc_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }

    var client_random: u8[32] = [0; 32];
    var client_priv:   u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_priv);
    var p384_priv: u8[48] = [0; 48];
    defer core::secure_zeroize_48(p384_priv);
    var client_pub: u8[32]   = [0; 32];
    var pq_priv:    u8[2400] = [0; 2400];
    defer core::secure_zeroize_slice(pq_priv[..]);
    var pq_pub: u8[1184] = [0; 1184];
    guard tls_internal::generate_client_handshake_keys(
        config.enable_pq_hybrid, client_random, client_priv, client_pub, pq_priv, pq_pub,
    ) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var psk_ticket: u8[..1536] = [];
    var psk_secret: u8[..48]   = [];
    defer core::secure_zeroize_slice(psk_secret[..]);
    var psk_obf_age: u32 = 0;
    var psk_suite:   u16 = 0;
    let use_ech = config.ech_config_list.len > 0;
    var offered_psk = !use_ech && config.enable_session_tickets && tls_internal::lookup_client_ticket_for_ch(
        config.server_name[..], psk_ticket, psk_secret, psk_obf_age, psk_suite,
    );
    let psk_hash_len: u8 = if offered_psk && rfc::tls13_cipher_suite_hash_len(psk_suite) == 48 { 48 } else { 32 };

    var ech_state = tls_internal::EchClientState { .. };
    defer tls_internal::zeroize_ech_client_state(ech_state);
    var ch_msg: u8[..4096] = [];
    if use_ech {
        guard tls_internal::build_ech_sealed_client_hello(
            config, client_random, client_pub, config.enable_pq_hybrid,
            if config.enable_pq_hybrid { pq_pub[..] } else { "" },
            "", "", false, ech_state, ch_msg,
        ) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else {
        var ch_payload: u8[..4096] = [];
        tls_internal::build_client_hello_payload(
            client_random, client_pub, config.server_name[..], config.alpn[..],
            ch_payload, psk_ticket[..], psk_obf_age,
            config.enable_pq_hybrid, if config.enable_pq_hybrid { pq_pub[..] } else { "" },
            "", "", config.client_cert_der.len > 0, psk_hash_len,
        );
        guard tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch_payload[..], ch_msg) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        if offered_psk {
            tls_internal::patch_client_hello_psk_binder(ch_msg, psk_secret[..], psk_suite);
        }
    }

    guard tls_internal::send_plaintext_handshake_record(fd, ch_msg[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    tls_internal::tls_write_all(fd, ccs[..]);

    var transcript = Transcript { .. };
    tls_internal::transcript_update(transcript, ch_msg[..]);

    var sh_msg: u8[..16384] = [];
    guard tls_internal::read_plaintext_handshake_record(fd, sh_msg, config.handshake_timeout_ms) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var sh = ParsedServerHello { .. };
    guard parse_live_server_hello(sh_msg[..], sh) else {
        tls_internal::send_plaintext_fatal_alert(fd, tls_internal::classify_sh_failure_alert(sh_msg[..]));
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var offered_group: u16 = rfc::GROUP_X25519;
    var offered_pq = config.enable_pq_hybrid;
    if sh.is_hrr {
        offered_psk = false;
        let ok_hrr = tls_internal::handle_client_hrr_transition(
            fd, config, client_random, client_priv, client_pub, p384_priv,
            pq_priv, pq_pub, ech_state, transcript, sh_msg[..], sh, offered_group, offered_pq,
        );
        guard ok_hrr else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else {
        guard tls_internal::validate_live_client_sh(sh, client_random) &&
            tls_internal::is_group_offered_in_client_hello(sh.selected_group, offered_group, offered_pq) &&
            tls_internal::verify_ech_server_hello_acceptance(ech_state, sh, sh_msg[..], transcript) else {
            tls_internal::send_plaintext_fatal_alert(fd, Alert.IllegalParameter);
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    }

    let cipher_suite = sh.cipher_suite;
    let srv_group = sh.selected_group;
    let srv_share = sh.server_share[..];
    let psk_resumed = sh.psk_resumed;

    if psk_resumed && (!offered_psk || rfc::tls13_cipher_suite_hash_len(cipher_suite) != psk_hash_len) {
        tls_internal::send_plaintext_fatal_alert(fd, Alert.IllegalParameter);
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ecdhe_secret: u8[..80] = [];
    defer core::secure_zeroize_slice(ecdhe_secret[..]);
    if srv_group == rfc::GROUP_X25519_MLKEM768 && offered_pq {
        var srv_share_raw: u8[..2048] = [];
        srv_share_raw.append_u16_be(srv_group);
        srv_share_raw.append_u16_be(srv_share.len as u16);
        srv_share_raw.append(srv_share[..]);
        var srv_pq_share = tls_internal::PostQuantumServerShare { .. };
        guard tls_internal::parse_hybrid_server_key_share(srv_pq_share, srv_share_raw[..]) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        var classic_ss, ok_c = core::x25519_shared_secret(client_priv, srv_pq_share.x25519_public);
        defer core::secure_zeroize_32(classic_ss);
        guard ok_c else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        var pq_ss: u8[32] = [0; 32];
        defer core::secure_zeroize_32(pq_ss);
        guard tls_internal::mlkem768_decapsulate(srv_pq_share.mlkem768_ciphertext[..], pq_priv[..], pq_ss[..]) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        var pq_comb: u8[64] = [0; 64];
        defer core::secure_zeroize_64(pq_comb);
        let ok_pq = tls_internal::derive_x25519_mlkem768_shared_secret_checked(
            classic_ss[..], pq_ss[..], pq_comb[..],
        );
        guard ok_pq && ecdhe_secret.try_set(pq_comb[..]) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else if srv_group == rfc::GROUP_X25519 && offered_group == rfc::GROUP_X25519 && srv_share.len == 32 {
        var srv_pub: u8[32] = [0; 32];
        core::ct_copy_bytes(srv_pub[..], srv_share[..]);
        var ss, ok_ss = core::x25519_shared_secret(client_priv, srv_pub);
        defer core::secure_zeroize_32(ss);
        guard ok_ss && ecdhe_secret.try_set(ss[..]) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else if srv_group == rfc::GROUP_SECP256R1 && offered_group == rfc::GROUP_SECP256R1 && srv_share.len == 65 {
        var ss256, ok_ss256 = core::p256_ecdh_shared_secret(client_priv, srv_share[..]);
        defer core::secure_zeroize_32(ss256);
        guard ok_ss256 && ecdhe_secret.try_set(ss256[..]) else {
            tls_internal::send_plaintext_fatal_alert(fd, Alert.IllegalParameter);
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else if srv_group == rfc::GROUP_SECP384R1 && offered_group == rfc::GROUP_SECP384R1 && srv_share.len == 97 {
        var ss384, ok_ss384 = core::p384_ecdh_shared_secret(p384_priv, srv_share[..]);
        defer core::secure_zeroize_48(ss384);
        guard ok_ss384 && ecdhe_secret.try_set(ss384[..]) else {
            tls_internal::send_plaintext_fatal_alert(fd, Alert.IllegalParameter);
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else {
        tls_internal::send_plaintext_fatal_alert(fd, Alert.IllegalParameter);
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

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
    tls_internal::transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    tls_internal::emit_tls13_hs_keylog(config.keylog_file[..], client_random, ks);

    var client_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_hs_key);
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_hs_key);
    var server_hs_iv: u8[12] = [0; 12];
    let key_len_u16 = rfc::tls13_cipher_suite_key_len(cipher_suite);
    let klen = key_len_u16 as i64;
    let hlen = ks.hash_len as i64;
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

    var hs_reader = HandshakeRecordReader { .. };
    var neg_alpn: u8[..255] = [];
    var cert_req_received = false;
    var cert_req = CertificateRequestMsg { .. };
    let ok_flight = tls_internal::tls_client_process_server_flight(
        hs_reader, fd, cipher_suite, server_hs_key[..klen],
        server_hs_iv, client_hs_key[..klen], client_hs_iv,
        ks, transcript, config, ech_state, psk_resumed, neg_alpn,
        cert_req_received, cert_req, slot_idx,
    );
    guard ok_flight else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_srv_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard tls_internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    tls_internal::emit_tls13_app_keylog(config.keylog_file[..], client_random, ks);

    guard tls_internal::tls_client_send_finished(
        fd, cipher_suite, client_hs_key[..klen], client_hs_iv, ks, transcript,
        config, cert_req_received, cert_req,
    ) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_cli_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(transcript, ks.hash_id, h_through_cli_fin);
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

    tls_internal::tls_setup_client_cipher_slot(
        slot_idx, cipher_suite, key_len_u16, ks,
        client_ap_key[..klen], client_ap_iv,
        server_ap_key[..klen], server_ap_iv,
        config.server_name[..], neg_alpn[..], psk_resumed,
    );
    let s_idx = slot_idx as i64;
    if s_idx >= 0 && s_idx < g_tls_cipher_slots.len {
        g_tls_cipher_slots[s_idx].enable_session_tickets = config.enable_session_tickets;
    }
    return slot_idx, true;
}
