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
import .post_quantum;
import .cert_compression;
import .ech;
import .session_internal;
import .session;
import .handshake_io_internal;
import net.tcp;

// Executes full TLS 1.3 client handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn client_handshake(fd: i64, config: const ClientHandshakeConfig&) -> u16, bool {
    let slot_idx = alloc_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }

    let client_random = random_bytes_32();
    var client_priv = random_bytes_32();
    defer core::secure_zeroize_32(client_priv);
    var client_pub = core::x25519_base_scalarmult(client_priv);

    var pq_priv: u8[2400] = [0; 2400];
    defer core::secure_zeroize_slice(pq_priv[..]);
    var pq_pub: u8[1184] = [0; 1184];
    if config.enable_pq_hybrid {
        var pq_d = random_bytes_32();
        var pq_z = random_bytes_32();
        defer core::secure_zeroize_32(pq_d);
        defer core::secure_zeroize_32(pq_z);
        var ek, dk = tls_internal::mlkem768_keygen(pq_d, pq_z);
        defer core::secure_zeroize_slice(dk[..]);
        pq_priv = dk;
        pq_pub = ek;
    }

    var psk_ticket: u8[..256] = [];
    var psk_secret: u8[..48]  = [];
    defer core::secure_zeroize_slice(psk_secret[..]);
    var psk_age_add: u32 = 0;
    var psk_suite:   u16 = 0;
    let has_ticket = lookup_session_ticket_full(
        config.server_name[..], psk_ticket, psk_secret, psk_age_add, psk_suite,
    );
    let psk_hash_len: u8 = if has_ticket && rfc::tls13_cipher_suite_hash_len(psk_suite) == 48 { 48 } else { 32 };

    var ech_ext_raw: u8[..512] = [];
    tls_internal::prepare_ech_outer_extension(config, ech_ext_raw);

    var ch_payload: u8[..4096] = [];
    build_client_hello_payload(
        client_random, client_pub, config.server_name[..], config.alpn[..],
        ch_payload, psk_ticket[..], psk_age_add,
        config.enable_pq_hybrid, if config.enable_pq_hybrid { pq_pub[..] } else { "" },
        ech_ext_raw[..], "", config.client_cert_der.len > 0, psk_hash_len,
    );
    var ch_msg: u8[..4096] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    ch_msg.append_u24_be(ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    if has_ticket {
        tls_internal::patch_client_hello_psk_binder(ch_msg, psk_secret[..], psk_suite);
    }

    guard tls_internal::send_plaintext_handshake_record(fd, ch_msg[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    tls_internal::tls_write_all(fd, ccs[..]);

    var transcript = Transcript { .. };
    transcript_update(transcript, ch_msg[..]);

    var sh_msg: u8[..16384] = [];
    guard tls_internal::read_plaintext_handshake_record(fd, sh_msg) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var sh = ParsedServerHello { .. };
    guard parse_live_server_hello(sh_msg[..], sh) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    if sh.is_hrr {
        let ok_hrr = tls_internal::handle_client_hrr_transition(
            fd, config, client_random, client_priv, client_pub,
            pq_priv, pq_pub, ech_ext_raw[..], transcript, sh_msg[..], sh,
        );
        guard ok_hrr else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else {
        guard tls_internal::validate_live_client_sh(sh, client_random) else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        transcript_update(transcript, sh_msg[..]);
    }

    let cipher_suite = sh.cipher_suite;
    let srv_group = sh.selected_group;
    let srv_share = sh.server_share[..];
    let psk_resumed = sh.psk_resumed;

    if psk_resumed && (!has_ticket || rfc::tls13_cipher_suite_hash_len(cipher_suite) != psk_hash_len) {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ecdhe_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(ecdhe_secret);
    if srv_group == rfc::GROUP_X25519_MLKEM768 {
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
        let ok_pq = tls_internal::derive_x25519_mlkem768_shared_secret_checked(
            classic_ss[..], pq_ss[..], ecdhe_secret[..],
        );
        guard ok_pq else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else if srv_group == rfc::GROUP_X25519 && srv_share.len == 32 {
        var srv_pub: u8[32] = [0; 32];
        core::ct_copy_bytes(srv_pub[..], srv_share[..]);
        var ss, ok_ss = core::x25519_shared_secret(client_priv, srv_pub);
        defer core::secure_zeroize_32(ss);
        guard ok_ss else {
            free_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        core::ct_copy_bytes(ecdhe_secret[..], ss[..]);
    } else {
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
    transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

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
        server_hs_iv, ks, transcript, config, psk_resumed, neg_alpn,
        cert_req_received, cert_req, slot_idx,
    );
    guard ok_flight else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_srv_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard tls_internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    guard tls_internal::tls_client_send_finished(
        fd, cipher_suite, client_hs_key[..klen], client_hs_iv, ks, transcript,
        config, cert_req_received, cert_req,
    ) else {
        free_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

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

    tls_internal::tls_setup_client_cipher_slot(
        slot_idx, cipher_suite, key_len_u16, ks,
        client_ap_key[..klen], client_ap_iv,
        server_ap_key[..klen], server_ap_iv,
        config.server_name[..], neg_alpn[..], psk_resumed,
    );
    return slot_idx, true;
}
