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
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .cert_compression;
import .session_internal;
import .session_codec_internal;
import .session;
import .handshake_io_client_internal;
import .handshake_io_server_internal;
import net.tcp;
import .handshake_wire_internal;
import .session_slot_internal;
import .session_wire_internal;

// Reads and validates a single TLS 1.3 plaintext ClientHello handshake message from `fd` (RFC 8446 Section 4.1.2).
// Clears `out_ch_msg` and returns false on timeout, I/O error, or malformed framing.
fn read_client_hello(
    fd:         i64,
    out_ch_msg: u8[..16384]&,
    timeout_ms: u32 = 5000,
) -> bool {
    out_ch_msg.clear();
    guard fd > 0 && tls_internal::read_plaintext_handshake_record(fd, out_ch_msg, timeout_ms) else {
        out_ch_msg.clear();
        return false;
    }
    let msg_type, msg_len, ok_h = parse_handshake_header(out_ch_msg[..]);
    guard ok_h && msg_type == rfc::TLS_HS_CLIENT_HELLO && out_ch_msg.len == core::add_sat_i64(4, msg_len) else {
        out_ch_msg.clear();
        return false;
    }
    return true;
}

// Parses a TLS 1.3 ClientHello handshake message and extracts the normalized SNI hostname (RFC 6066 Section 3).
// Returns true if a valid server_name extension was extracted into `out_sni`; clears `out_sni`
// and returns false if the ClientHello is malformed, omits SNI, or carries an invalid host_name.
//
// Example:
//   ch_msg = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, ...server_name "Api.Example.COM"...]
//   returns: true, out_sni = "api.example.com"
fn extract_client_hello_sni(ch_msg: const u8[:], out_sni: u8[..255]&) -> bool {
    out_sni.clear();
    var sid:     u8[..32]             = [];
    var entries: ExtensionEntry[..32] = [];
    let _, ok_pre = tls_internal::decode_ch_server_preamble(ch_msg, sid, entries);
    guard ok_pre else { return false; }
    let sni_ext, has_sni = find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    guard has_sni && parse_sni_extension(sni_ext, out_sni) else {
        out_sni.clear();
        return false;
    }
    return true;
}

fn server_emit_hrr_and_recv_ch2(
    fd:        i64,
    config:    const ServerHandshakeConfig&,
    ch_choice: tls_internal::ServerClientHelloChoice&,
    tr:        Transcript&,
) -> bool {
    let hrr_cipher = ch_choice.cipher_suite;
    let hrr_group = ch_choice.selected_group;
    let hrr_sid = ch_choice.session_id;
    let hrr_sni = ch_choice.client_sni;
    var hrr_pay: u8[..256] = [];
    tls_internal::build_hrr_payload(hrr_sid[..], hrr_cipher, hrr_group, hrr_pay);
    var hrr_msg: u8[..280] = [];
    guard tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_SERVER_HELLO, hrr_pay[..], hrr_msg) else {
        return false;
    }
    guard tls_internal::send_plaintext_handshake_record(fd, hrr_msg[..], rfc::TLS_LEGACY_VERSION_1_2) else {
        return false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard tls_internal::tls_write_all(fd, ccs[..]) else { return false; }

    var ks_hrr, ok_kshr = tls_internal::ks_init(hrr_cipher);
    defer tls_internal::ks_zeroize(ks_hrr);
    guard ok_kshr && tls_internal::transcript_replace_with_message_hash(tr, ks_hrr.hash_id, ks_hrr.hash_len) else {
        return false;
    }
    tls_internal::transcript_update(tr, hrr_msg[..]);

    var ch2_msg: u8[..16384] = [];
    guard tls_internal::read_plaintext_handshake_record(fd, ch2_msg, config.handshake_timeout_ms) else {
        return false;
    }
    let req_sig = tls_internal::detect_cert_sig_scheme(config.cert_der[..]);
    guard tls_internal::parse_server_client_hello(
        ch2_msg[..], config.alpn[..], req_sig, config.compressed_cert_algo,
        tls_internal::ServerHrrMode.Reject, ch_choice, config.require_client_cert,
    ) else { return false; }
    guard ch_choice.cipher_suite == hrr_cipher &&
        ch_choice.selected_group == hrr_group &&
        ch_choice.session_id[..] == hrr_sid[..] &&
        ch_choice.client_sni[..] == hrr_sni[..] else {
        return false;
    }
    tls_internal::transcript_update(tr, ch2_msg[..]);
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
    var committed = false;
    defer if !committed { free_cipher_slot(slot_idx); };
    let idx = slot_idx as i64;

    var transcript = Transcript { .. };
    tls_internal::transcript_update(transcript, ch_msg);

    var ch_choice = tls_internal::ServerClientHelloChoice { .. };
    defer tls_internal::zeroize_server_ch_choice(ch_choice);
    let req_sig = tls_internal::detect_cert_sig_scheme(config.cert_der[..]);
    guard tls_internal::parse_server_client_hello(
        ch_msg, config.alpn[..], req_sig, config.compressed_cert_algo,
        tls_internal::ServerHrrMode.Allow, ch_choice, config.require_client_cert,
    ) else { return 0xFFFF, false; }

    let did_hrr = ch_choice.needs_hrr;
    if did_hrr {
        guard server_emit_hrr_and_recv_ch2(fd, config, ch_choice, transcript) else {
            return 0xFFFF, false;
        }
    }

    let cipher_suite = ch_choice.cipher_suite;
    let psk_resumed = ch_choice.psk_resumed;
    let _ = g_tls_cipher_slots[idx].server_name.try_set(ch_choice.client_sni[..]);

    var server_random: u8[32]   = [0; 32];
    var server_share:  u8[..65] = [];
    var ecdhe_secret:  u8[32]   = [0; 32];
    defer core::secure_zeroize_32(ecdhe_secret);
    guard tls_internal::generate_server_handshake_keys_for_group(
        ch_choice.selected_group, ch_choice.client_share[..], server_random, server_share, ecdhe_secret,
    ) else { return 0xFFFF, false; }

    var sh_payload: u8[..2048] = [];
    tls_internal::build_server_hello_payload_for_group(
        server_random, ch_choice.session_id[..], ch_choice.selected_group, server_share[..],
        sh_payload, psk_resumed, cipher_suite, ch_choice.selected_psk_id,
    );
    var sh_msg: u8[..2048] = [];
    guard tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_SERVER_HELLO, sh_payload[..], sh_msg) else {
        return 0xFFFF, false;
    }
    guard tls_internal::send_plaintext_handshake_record(fd, sh_msg[..], rfc::TLS_LEGACY_VERSION_1_2) else {
        return 0xFFFF, false;
    }
    if !did_hrr {
        let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
        tls_internal::tls_write_all(fd, ccs[..]);
    }
    tls_internal::transcript_update(transcript, sh_msg[..]);

    var ks, ok_ks = tls_internal::ks_init(cipher_suite);
    defer tls_internal::ks_zeroize(ks);
    let early_ikm = if psk_resumed { ch_choice.psk_secret[..] } else { "" };
    guard ok_ks &&
        tls_internal::ks_init_early_secret(ks, early_ikm) &&
        tls_internal::ks_advance_to_handshake(ks, ecdhe_secret[..]) else {
        return 0xFFFF, false;
    }

    var ch_sh_hash: u8[..48] = [];
    tls_internal::transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else { return 0xFFFF, false; }
    tls_internal::emit_tls13_hs_keylog(config.keylog_file[..], ch_choice.client_random, ks);

    let key_len_u16 = rfc::tls13_cipher_suite_key_len(cipher_suite);
    let klen = key_len_u16 as i64;
    let hlen = ks.hash_len as i64;
    var client_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_hs_key);
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_hs_key);
    var server_hs_iv: u8[12] = [0; 12];
    guard tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_hs_traffic[..hlen], key_len_u16, client_hs_key[..klen], client_hs_iv,
    ) && tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_hs_traffic[..hlen], key_len_u16, server_hs_key[..klen], server_hs_iv,
    ) else { return 0xFFFF, false; }

    guard tls_internal::tls_server_send_flight(
        fd, server_hs_key[..klen], server_hs_iv, ks,
        transcript, config, ch_choice.negotiated_alpn[..], psk_resumed, ch_choice.cert_comp_algo, cipher_suite,
    ) else { return 0xFFFF, false; }

    var h_through_srv_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard tls_internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else { return 0xFFFF, false; }
    tls_internal::emit_tls13_app_keylog(config.keylog_file[..], ch_choice.client_random, ks);

    var hs_reader = HandshakeRecordReader { .. };
    if !psk_resumed && config.require_client_cert {
        guard tls_internal::tls_server_recv_client_auth(
            hs_reader, fd, cipher_suite, client_hs_key[..klen], client_hs_iv, ks, transcript, config,
        ) else { return 0xFFFF, false; }
    }

    var cli_fin_body: u8[..16384] = [];
    var msg_fin:      u8          = 0;
    guard tls_internal::next_handshake_message(
        hs_reader, fd, cipher_suite, client_hs_key[..klen],
        client_hs_iv, msg_fin, cli_fin_body, config.handshake_timeout_ms,
    ) && msg_fin == rfc::TLS_HS_FINISHED &&
        cli_fin_body.len == hlen &&
        hs_reader.current_offset == hs_reader.current_record_plain.len else {
        return 0xFFFF, false;
    }

    var h_before_cli_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(transcript, ks.hash_id, h_before_cli_fin);
    var exp_cli_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(exp_cli_fin);
    guard tls_internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.client_hs_traffic[..hlen],
        h_before_cli_fin[..], exp_cli_fin[..hlen],
    ) && core::ct_eq_bytes(exp_cli_fin[..hlen], cli_fin_body[..hlen]) else {
        return 0xFFFF, false;
    }

    tls_internal::transcript_update_msg(transcript, msg_fin, cli_fin_body[..hlen]);
    var h_through_cli_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(transcript, ks.hash_id, h_through_cli_fin);
    tls_internal::ks_advance_to_resumption(ks, h_through_cli_fin[..]);

    var client_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_ap_key);
    var client_ap_iv:  u8[12] = [0; 12];
    var server_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_ap_key);
    var server_ap_iv: u8[12] = [0; 12];
    guard tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_ap_traffic[..hlen], key_len_u16, client_ap_key[..klen], client_ap_iv,
    ) && tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_ap_traffic[..hlen], key_len_u16, server_ap_key[..klen], server_ap_iv,
    ) else { return 0xFFFF, false; }

    tls_internal::tls_setup_server_cipher_slot(
        slot_idx, cipher_suite, key_len_u16, ks,
        server_ap_key[..klen], server_ap_iv,
        client_ap_key[..klen], client_ap_iv,
    );
    g_tls_cipher_slots[idx].resumed = psk_resumed;
    g_tls_cipher_slots[idx].client_authenticated = config.require_client_cert;
    let _ = g_tls_cipher_slots[idx].negotiated_alpn.try_set(ch_choice.negotiated_alpn[..]);
    committed = true;
    return slot_idx, true;
}

// Executes full TLS 1.3 server handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn server_handshake(fd: i64, config: const ServerHandshakeConfig&) -> u16, bool {
    var ch_msg: u8[..16384] = [];
    guard read_client_hello(fd, ch_msg, config.handshake_timeout_ms) else {
        return 0xFFFF, false;
    }
    return server_handshake_with_ch(fd, ch_msg[..], config);
}
