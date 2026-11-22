// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal PureGoose sans-IO client and server handshake state machine steps.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .record_internal;
import .key_schedule;
import .handshake_internal;
import .handshake_wire_internal;
import .handshake;
import .types;
import .x509;
import .pem;
import .ticket;
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .session_internal;
import .session_slot_internal;
import .session_codec_internal;
import .session_wire_internal;
import .session;
import .handshake_io_client_internal;
import .handshake_io_server_internal;
import .backend_native_internal;
import .backend_pure_internal;

fn pure_client_step_init(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var client_pub: u8[32]   = [0; 32];
    var pq_pub:     u8[1184] = [0; 1184];
    guard generate_client_handshake_keys(
        slot.enable_pq_hybrid, slot.client_random, slot.eph_priv, client_pub, slot.pq_priv, pq_pub,
    ) else {
        return tls::TlsBackendStatus.HandshakeError;
    }

    var psk_ticket:  u8[..1536] = [];
    var psk_age_add: u32        = 0;
    var psk_suite:   u16        = 0;
    slot.psk_secret.clear();
    slot.has_psk_ticket = slot.enable_session_tickets && tls::lookup_session_ticket_full(
        slot.server_name[..], psk_ticket, slot.psk_secret, psk_age_add, psk_suite,
    );
    slot.psk_hash_len = if slot.has_psk_ticket && rfc::tls13_cipher_suite_hash_len(psk_suite) == 48 {
        48
    } else {
        32
    };

    var ch_payload: u8[..4096] = [];
    build_client_hello_payload(
        slot.client_random, client_pub, slot.server_name[..], slot.alpn_csv[..], ch_payload,
        psk_ticket[..], psk_age_add,
        slot.enable_pq_hybrid, if slot.enable_pq_hybrid { pq_pub[..] } else { "" },
        "", "", false, slot.psk_hash_len,
    );
    var ch_msg: u8[..4096] = [];
    guard frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch_payload[..], ch_msg) else {
        return tls::TlsBackendStatus.Error;
    }
    if slot.has_psk_ticket {
        patch_client_hello_psk_binder(ch_msg, slot.psk_secret[..], psk_suite);
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard pure_append_plaintext_hs(slot.wire_out, ch_msg[..]) && slot.wire_out.try_append(ccs[..]) else {
        return tls::TlsBackendStatus.Error;
    }
    transcript_update(slot.transcript, ch_msg[..]);
    slot.stage = PureHsStage.ClientWaitServerHello;
    return tls::TlsBackendStatus.WantRead;
}

fn pure_compute_client_ecdhe(
    slot:       PureTlsSlot&,
    sh:         const tls::ParsedServerHello&,
    out_secret: u8[..80]&,
) -> bool {
    defer core::secure_zeroize_32(slot.eph_priv);
    defer core::secure_zeroize_slice(slot.pq_priv[..]);
    out_secret.clear();
    if sh.selected_group == rfc::GROUP_X25519_MLKEM768 && slot.enable_pq_hybrid {
        var srv_share_raw: u8[..2048] = [];
        srv_share_raw.append_u16_be(sh.selected_group);
        srv_share_raw.append_u16_be(sh.server_share.len as u16);
        guard srv_share_raw.try_append(sh.server_share[..]) else { return false; }
        var srv_pq = PostQuantumServerShare { .. };
        guard parse_hybrid_server_key_share(srv_pq, srv_share_raw[..]) else { return false; }
        var classic_ss, ok_c = core::x25519_shared_secret(slot.eph_priv, srv_pq.x25519_public);
        defer core::secure_zeroize_32(classic_ss);
        var pq_ss: u8[32] = [0; 32];
        defer core::secure_zeroize_32(pq_ss);
        guard ok_c &&
            mlkem768_decapsulate(srv_pq.mlkem768_ciphertext[..], slot.pq_priv[..], pq_ss[..]) else {
            return false;
        }
        var pq_comb: u8[64] = [0; 64];
        defer core::secure_zeroize_64(pq_comb);
        guard derive_x25519_mlkem768_shared_secret_checked(
            classic_ss[..], pq_ss[..], pq_comb[..],
        ) else {
            return false;
        }
        return out_secret.try_set(pq_comb[..]);
    }
    guard sh.selected_group == rfc::GROUP_X25519 && sh.server_share.len == 32 else { return false; }
    var srv_pub: u8[32] = [0; 32];
    core::ct_copy_bytes(srv_pub[..], sh.server_share[..]);
    var ss, ok_ss = core::x25519_shared_secret(slot.eph_priv, srv_pub);
    defer core::secure_zeroize_32(ss);
    guard ok_ss else { return false; }
    return out_secret.try_set(ss[..]);
}

fn pure_client_step_sh(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var sh_msg: u8[..16384] = [];
    let st = pure_pop_plaintext_hs_msg(slot, sh_msg);
    guard st == tls::TlsBackendStatus.Ok else { return st; }

    var sh = tls::ParsedServerHello { .. };
    guard tls::parse_live_server_hello(sh_msg[..], sh) &&
        !sh.is_hrr &&
        validate_live_client_sh(sh, slot.client_random) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    if sh.psk_resumed {
        guard slot.has_psk_ticket &&
            rfc::tls13_cipher_suite_hash_len(sh.cipher_suite) == slot.psk_hash_len else {
            return tls::TlsBackendStatus.HandshakeError;
        }
    }
    slot.psk_resumed = sh.psk_resumed;
    transcript_update(slot.transcript, sh_msg[..]);
    slot.cipher_suite = sh.cipher_suite;

    var ecdhe_secret: u8[..80] = [];
    defer core::secure_zeroize_slice(ecdhe_secret[..]);
    let early_ikm = if slot.psk_resumed { slot.psk_secret[..] } else { "" };
    guard pure_compute_client_ecdhe(slot, sh, ecdhe_secret) &&
        pure_derive_hs_traffic_keys(slot, ecdhe_secret[..], early_ikm) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    slot.stage = PureHsStage.ClientWaitEE;
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_verify_cv(slot: PureTlsSlot&, cv_body: const u8[:]) -> tls::TlsBackendStatus {
    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);
    var cfg = tls::ClientHandshakeConfig {
        insecure_skip_verify:  slot.insecure_skip_verify,
        use_system_roots:      slot.use_system_roots,
        require_ocsp_stapling: slot.require_ocsp_stapling,
        trust_store:           slot.trust_store,
        ..
    };
    let _ = cfg.server_name.try_set(slot.server_name[..]);
    let _ = cfg.crl_der.try_set(slot.crl_der[..]);
    let ok_v = verify_server_cert_and_signature(
        slot.peer_cert_body[..], cv_body, h_to_cert[..], cfg, 0xFFFF,
    );
    slot.peer_cert_body.clear();
    guard ok_v else { return tls::TlsBackendStatus.VerifyError; }
    transcript_update_msg(slot.transcript, rfc::TLS_HS_CERTIFICATE_VERIFY, cv_body);
    slot.stage = PureHsStage.ClientWaitFinished;
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_finish_hs(slot: PureTlsSlot&, fin_body: const u8[:]) -> tls::TlsBackendStatus {
    let hlen = slot.ks.hash_len as i64;
    guard fin_body.len == hlen else { return tls::TlsBackendStatus.HandshakeError; }
    var h_to_cv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cv);
    var exp_srv_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(exp_srv_fin);
    guard ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.server_hs_traffic[..hlen], h_to_cv[..], exp_srv_fin[..hlen],
    ) && core::ct_eq_bytes(exp_srv_fin[..hlen], fin_body[..hlen]) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    transcript_update_msg(slot.transcript, rfc::TLS_HS_FINISHED, fin_body[..hlen]);

    var h_through_srv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_through_srv);
    guard ks_advance_to_master(slot.ks, h_through_srv[..]) else {
        return tls::TlsBackendStatus.HandshakeError;
    }

    var cli_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(cli_fin);
    guard ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.client_hs_traffic[..hlen], h_through_srv[..], cli_fin[..hlen],
    ) else { return tls::TlsBackendStatus.HandshakeError; }

    var cli_msg: u8[64] = [0; 64];
    cli_msg[0] = rfc::TLS_HS_FINISHED;
    cli_msg[3] = slot.ks.hash_len;
    core::ct_copy_bytes(cli_msg[4..core::add_sat_i64(4, hlen)], cli_fin[..hlen]);
    let msg_slice = cli_msg[..core::add_sat_i64(4, hlen)];
    guard pure_seal_hs_to_wire(slot, msg_slice) else { return tls::TlsBackendStatus.Error; }

    transcript_update(slot.transcript, msg_slice);
    var h_through_cli: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_through_cli);
    let _ = ks_advance_to_resumption(slot.ks, h_through_cli[..]);
    guard pure_install_app_keys(slot) else { return tls::TlsBackendStatus.Error; }
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_step_ee(slot: PureTlsSlot&, body: const u8[:]) -> tls::TlsBackendStatus {
    let sni_st = if validate_sni_host_bytes(slot.server_name[..]) {
        tls::SniOfferState.Offered
    } else {
        tls::SniOfferState.Omitted
    };
    guard parse_encrypted_extensions_alpn(body, slot.selected_alpn, slot.alpn_csv[..], sni_st, false) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    transcript_update_msg(slot.transcript, rfc::TLS_HS_ENCRYPTED_EXTENSIONS, body);
    slot.stage = if slot.psk_resumed { PureHsStage.ClientWaitFinished } else { PureHsStage.ClientWaitCert };
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_step_encrypted(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var msg_t: u8          = 0;
    var body:  u8[..16384] = [];
    let st = pure_next_encrypted_hs_msg(slot, msg_t, body);
    guard st == tls::TlsBackendStatus.Ok else { return st; }

    if slot.stage == PureHsStage.ClientWaitEE {
        guard msg_t == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else { return tls::TlsBackendStatus.HandshakeError; }
        return pure_client_step_ee(slot, body[..]);
    }
    if slot.stage == PureHsStage.ClientWaitCert {
        guard msg_t == rfc::TLS_HS_CERTIFICATE && slot.peer_cert_body.try_set(body[..]) else {
            return tls::TlsBackendStatus.HandshakeError;
        }
        transcript_update_msg(slot.transcript, msg_t, body[..]);
        slot.stage = PureHsStage.ClientWaitCV;
        return tls::TlsBackendStatus.Ok;
    }
    if slot.stage == PureHsStage.ClientWaitCV {
        guard msg_t == rfc::TLS_HS_CERTIFICATE_VERIFY else { return tls::TlsBackendStatus.HandshakeError; }
        return pure_client_verify_cv(slot, body[..]);
    }
    guard msg_t == rfc::TLS_HS_FINISHED else { return tls::TlsBackendStatus.HandshakeError; }
    return pure_client_finish_hs(slot, body[..]);
}

fn pure_server_emit_encrypted_flight(slot: PureTlsSlot&) -> bool {
    var ee_ext: u8[..264] = [];
    if slot.selected_alpn.len > 0 {
        encode_alpn_extension_from_csv(ee_ext, slot.selected_alpn[..]);
    }
    var ee_msg: u8[..280] = [];
    guard ee_msg.try_push(rfc::TLS_HS_ENCRYPTED_EXTENSIONS) else { return false; }
    ee_msg.append_u24_be(core::add_sat_i64(2, ee_ext.len) as u32);
    ee_msg.append_u16_be(ee_ext.len as u16);
    guard ee_msg.try_append(ee_ext[..]) && pure_seal_hs_to_wire(slot, ee_msg[..]) else { return false; }
    transcript_update(slot.transcript, ee_msg[..]);

    var srv_cfg = tls::ServerHandshakeConfig { priv_seed: slot.priv_seed, .. };
    guard srv_cfg.cert_der.try_set(slot.cert_der[..]) else { return false; }
    var cert_msg: u8[..4096] = [];
    guard encode_server_cert_or_compressed_msg(srv_cfg, 0, cert_msg) &&
        pure_seal_hs_to_wire(slot, cert_msg[..]) else { return false; }
    transcript_update(slot.transcript, cert_msg[..]);

    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);
    var cv_input: u8[160] = [0; 160];
    let cv_len, ok_cv = tls::build_certificate_verify_message(true, h_to_cert[..], cv_input[..]);
    var sig_buf: u8[..128] = [];
    let sig_scheme, ok_sig = sign_certificate_verify(slot.cert_der[..], slot.priv_seed, cv_input[..cv_len], sig_buf);
    var cv_pay: u8[..512] = [];
    guard ok_cv &&
        ok_sig &&
        tls::encode_client_certificate_verify(cv_pay, sig_scheme, sig_buf[..]) else {
        return false;
    }
    var cv_msg: u8[..512] = [];
    cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
    cv_msg.append_u24_be(cv_pay.len as u32);
    guard cv_msg.try_append(cv_pay[..]) && pure_seal_hs_to_wire(slot, cv_msg[..]) else { return false; }
    transcript_update(slot.transcript, cv_msg[..]);

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cv);
    let hlen = slot.ks.hash_len as i64;
    var srv_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(srv_fin);
    guard ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.server_hs_traffic[..hlen], h_to_cv[..], srv_fin[..hlen],
    ) else { return false; }
    var fin_msg: u8[64] = [0; 64];
    fin_msg[0] = rfc::TLS_HS_FINISHED;
    fin_msg[3] = slot.ks.hash_len;
    core::ct_copy_bytes(fin_msg[4..core::add_sat_i64(4, hlen)], srv_fin[..hlen]);
    let fin_slice = fin_msg[..core::add_sat_i64(4, hlen)];
    guard pure_seal_hs_to_wire(slot, fin_slice) else { return false; }
    transcript_update(slot.transcript, fin_slice);
    return true;
}

fn pure_server_step_ch(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var ch_msg: u8[..16384] = [];
    let st = pure_pop_plaintext_hs_msg(slot, ch_msg);
    guard st == tls::TlsBackendStatus.Ok else { return st; }

    transcript_update(slot.transcript, ch_msg[..]);
    var sid:        u8[..32]  = [];
    var client_pub: u8[32]    = [0; 32];
    var client_sni: u8[..255] = [];
    var psk_res:    bool      = false;
    var psk_sec:    u8[..48]  = [];
    var sel_psk_id: u16       = 0;
    defer core::secure_zeroize_slice(psk_sec[..]);
    let req_sig = detect_cert_sig_scheme(slot.cert_der[..]);
    guard parse_client_hello_for_server_full(
        ch_msg[..], slot.alpn_csv[..], req_sig, sid, client_pub,
        slot.selected_alpn, client_sni, slot.cipher_suite, psk_res, psk_sec, sel_psk_id,
    ) else { return tls::TlsBackendStatus.HandshakeError; }
    let _ = extract_ch_client_random(ch_msg[..], slot.client_random);

    let srv_rand = random_bytes_32();
    var srv_priv = random_bytes_32();
    defer core::secure_zeroize_32(srv_priv);
    let srv_pub = core::x25519_base_scalarmult(srv_priv);
    var ecdhe, ok_ss = core::x25519_shared_secret(srv_priv, client_pub);
    defer core::secure_zeroize_32(ecdhe);
    guard ok_ss else { return tls::TlsBackendStatus.HandshakeError; }

    var sh_pay: u8[..2048] = [];
    build_server_hello_payload(srv_rand, sid[..], srv_pub, sh_pay, false, slot.cipher_suite, 0);
    var sh_msg: u8[..2048] = [];
    sh_msg.push(rfc::TLS_HS_SERVER_HELLO);
    sh_msg.append_u24_be(sh_pay.len as u32);
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard sh_msg.try_append(sh_pay[..]) &&
        pure_append_plaintext_hs(slot.wire_out, sh_msg[..]) &&
        slot.wire_out.try_append(ccs[..]) else {
        return tls::TlsBackendStatus.Error;
    }
    transcript_update(slot.transcript, sh_msg[..]);
    guard pure_derive_hs_traffic_keys(slot, ecdhe[..]) && pure_server_emit_encrypted_flight(slot) else {
        return tls::TlsBackendStatus.HandshakeError;
    }

    transcript_current_hash(slot.transcript, slot.ks.hash_id, slot.srv_fin_hash);
    guard ks_advance_to_master(slot.ks, slot.srv_fin_hash[..]) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    slot.stage = PureHsStage.ServerWaitClientFinished;
    return tls::TlsBackendStatus.WantRead;
}

fn pure_server_step_fin(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var msg_t: u8          = 0;
    var body:  u8[..16384] = [];
    let st = pure_next_encrypted_hs_msg(slot, msg_t, body);
    guard st == tls::TlsBackendStatus.Ok else { return st; }

    let hlen = slot.ks.hash_len as i64;
    guard msg_t == rfc::TLS_HS_FINISHED && body.len == hlen else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    var exp_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(exp_fin);
    guard ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.client_hs_traffic[..hlen], slot.srv_fin_hash[..], exp_fin[..hlen],
    ) && core::ct_eq_bytes(exp_fin[..hlen], body[..hlen]) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    transcript_update_msg(slot.transcript, msg_t, body[..hlen]);
    var h_cli: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_cli);
    let _ = ks_advance_to_resumption(slot.ks, h_cli[..]);
    guard pure_install_app_keys(slot) else { return tls::TlsBackendStatus.Error; }
    return tls::TlsBackendStatus.Ok;
}

fn pure_step_handshake_loop(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    for _ in 8 {
        if slot.stage == PureHsStage.Established { return tls::TlsBackendStatus.Ok; }
        if slot.stage == PureHsStage.Failed { return tls::TlsBackendStatus.HandshakeError; }
        let st = match slot.stage {
            ClientInit => pure_client_step_init(slot),
            ClientWaitServerHello => pure_client_step_sh(slot),
            ClientWaitEE => pure_client_step_encrypted(slot),
            ClientWaitCert => pure_client_step_encrypted(slot),
            ClientWaitCV => pure_client_step_encrypted(slot),
            ClientWaitFinished => pure_client_step_encrypted(slot),
            ServerWaitClientHello => pure_server_step_ch(slot),
            ServerWaitClientFinished => pure_server_step_fin(slot),
            _ => tls::TlsBackendStatus.Ok,
        };
        if st != tls::TlsBackendStatus.Ok {
            if st != tls::TlsBackendStatus.WantRead && st != tls::TlsBackendStatus.WantWrite {
                slot.stage = PureHsStage.Failed;
            }
            return st;
        }
    }
    return if slot.stage == PureHsStage.Established {
        tls::TlsBackendStatus.Ok
    } else {
        tls::TlsBackendStatus.WantRead
    };
}

fn pure_load_server_pem_files(
    cert_path: const u8[:],
    key_path:  const u8[:],
    slot:      PureTlsSlot&,
) -> bool {
    guard cert_path.len > 0 && key_path.len > 0 else { return false; }
    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    defer core::secure_zeroize_slice(cert_pem[..]);
    defer core::secure_zeroize_slice(key_pem[..]);
    guard read_file(cert_path, cert_pem) && read_file(key_path, key_pem) else { return false; }
    var srv_cfg = tls::ServerHandshakeConfig { .. };
    defer core::secure_zeroize_32(srv_cfg.priv_seed);
    guard tls::load_server_credentials_pem(cert_pem[..], key_pem[..], srv_cfg) else { return false; }
    guard slot.cert_der.try_set(srv_cfg.cert_der[..]) else { return false; }
    slot.priv_seed = srv_cfg.priv_seed;
    return true;
}

fn pure_init_slot_credentials(
    slot:      PureTlsSlot&,
    cfg:       const tls::TlsBackendConfig&,
    is_server: bool,
) -> tls::TlsBackendStatus {
    if is_server {
        if cfg.cert_der.len > 0 {
            let _ = slot.cert_der.try_set(cfg.cert_der[..]);
            slot.priv_seed = cfg.priv_seed;
            return tls::TlsBackendStatus.Ok;
        }
        guard pure_load_server_pem_files(cfg.cert_pem_file[..], cfg.key_pem_file[..], slot) else {
            return tls::TlsBackendStatus.HandshakeError;
        }
        return tls::TlsBackendStatus.Ok;
    }
    if cfg.cert_pem_file.len > 0 || cfg.key_pem_file.len > 0 {
        return tls::TlsBackendStatus.Unavailable;
    }
    slot.trust_store = cfg.trust_store;
    let load_ca = !cfg.insecure_skip_verify && slot.trust_store.anchors.len == 0 && cfg.ca_file.len > 0;
    if load_ca {
        let _, ok_ca = tls::load_trust_anchors_pem_file(slot.trust_store, cfg.ca_file[..]);
        guard ok_ca else { return tls::TlsBackendStatus.VerifyError; }
    }
    return tls::TlsBackendStatus.Ok;
}

fn open_pure_endpoint(cfg: const tls::TlsBackendConfig&, is_server: bool) -> tls::TlsEndpoint, tls::TlsBackendStatus {
    let has_pem = cfg.cert_pem_file.len > 0 && cfg.key_pem_file.len > 0;
    if is_server && cfg.cert_der.len == 0 && !has_pem {
        return tls::TlsEndpoint { .. }, tls::TlsBackendStatus.HandshakeError;
    }
    let idx, gen = alloc_pure_tls_slot();
    guard idx >= 0 else { return tls::TlsEndpoint { .. }, tls::TlsBackendStatus.Error; }
    let slot .= g_pure_tls_slots[idx as i64];
    slot.is_server = is_server;
    slot.insecure_skip_verify = cfg.insecure_skip_verify;
    slot.use_system_roots = cfg.use_system_roots;
    slot.enable_pq_hybrid = cfg.enable_pq_hybrid;
    slot.enable_session_tickets = cfg.enable_session_tickets;
    slot.require_ocsp_stapling = cfg.require_ocsp_stapling;
    slot.stage = if is_server { PureHsStage.ServerWaitClientHello } else { PureHsStage.ClientInit };
    let _ = slot.server_name.try_set(cfg.server_name[..]);
    let _ = slot.crl_der.try_set(cfg.crl_der[..]);
    let _ = slot.keylog_file.try_set(cfg.keylog_file[..]);
    decode_alpn_wire_to_csv(cfg.alpn_wire[..], slot.alpn_csv);
    let cred_st = pure_init_slot_credentials(slot, cfg, is_server);
    guard cred_st == tls::TlsBackendStatus.Ok else {
        reset_and_wipe_pure_slot(slot);
        return tls::TlsEndpoint { .. }, cred_st;
    }
    return tls::TlsEndpoint {
        kind:        cfg.kind,
        active_kind: tls::TlsBackendKind.PureGoose,
        is_server:   is_server,
        established: false,
        closed:      false,
        pure_slot:   idx,
        pure_gen:    gen,
        native_id:   -1,
    }, tls::TlsBackendStatus.Ok;
}

fn open_endpoint_with_role(
    cfg:       const tls::TlsBackendConfig&,
    is_server: bool,
) -> tls::TlsEndpoint, tls::TlsBackendStatus {
    if should_route_to_pure_backend(cfg, is_server) {
        return open_pure_endpoint(cfg, is_server);
    }

    var st_i32:     i32 = 0;
    var active_i32: i32 = 0;
    let nid = native_tls_backend_open(
        kind_to_native_i32(cfg.kind),
        if is_server { 1 } else { 0 },
        pack_native_verify_flags(cfg),
        min_version_to_native_i32(cfg.min_version),
        cfg.server_name[..],
        cfg.alpn_wire[..],
        cfg.ca_file[..],
        cfg.cert_pem_file[..],
        cfg.key_pem_file[..],
        st_i32,
        active_i32,
    );
    if nid > 0 && st_i32 == 0 {
        if cfg.keylog_file.len > 0 {
            let _ = native_tls_backend_set_keylog(nid, cfg.keylog_file[..]);
        }
        return tls::TlsEndpoint {
            kind:        cfg.kind,
            active_kind: native_i32_to_kind(active_i32),
            is_server:   is_server,
            established: false,
            closed:      false,
            pure_slot:   -1,
            native_id:   nid,
        }, tls::TlsBackendStatus.Ok;
    }
    if cfg.kind == tls::TlsBackendKind.Auto {
        return open_pure_endpoint(cfg, is_server);
    }
    return tls::TlsEndpoint { .. }, native_i32_to_status(st_i32);
}
