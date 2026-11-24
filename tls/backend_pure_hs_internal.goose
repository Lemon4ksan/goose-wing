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
import .cert_compression;
import .ech;
import .ech_internal;
import .ticket;
import .ticket_internal;
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

fn pure_client_build_initial_ch(
    slot:   PureTlsSlot&,
    out_ch: u8[..4096]&,
) -> bool {
    var psk_ticket:  u8[..1536] = [];
    var psk_age_add: u32        = 0;
    var psk_suite:   u16        = 0;
    slot.psk_secret.clear();
    let use_ech = slot.client_cfg.ech_config_list.len > 0;
    slot.has_psk_ticket = !use_ech &&
        slot.client_cfg.enable_session_tickets &&
        lookup_client_ticket_for_ch(
            slot.client_cfg.server_name[..], psk_ticket, slot.psk_secret, psk_age_add, psk_suite,
        );
    slot.psk_hash_len = if slot.has_psk_ticket && rfc::tls13_cipher_suite_hash_len(psk_suite) == 48 {
        48
    } else {
        32
    };
    let pq_pub_slice = if slot.offered_pq_ch { slot.pq_pub[..] } else { "" };
    if use_ech {
        return build_ech_sealed_client_hello(
            slot.client_cfg, slot.client_random, slot.eph_pub, slot.offered_pq_ch,
            pq_pub_slice, "", "", false, slot.ech_state, out_ch,
        );
    }
    var ch_payload: u8[..4096] = [];
    build_client_hello_payload(
        slot.client_random, slot.eph_pub, slot.client_cfg.server_name[..], slot.alpn_csv[..], ch_payload,
        psk_ticket[..], psk_age_add, slot.offered_pq_ch, pq_pub_slice,
        "", "", slot.client_cfg.client_cert_der.len > 0, slot.psk_hash_len,
    );
    guard frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch_payload[..], out_ch) else {
        return false;
    }
    if slot.has_psk_ticket {
        patch_client_hello_psk_binder(out_ch, slot.psk_secret[..], psk_suite);
    }
    return true;
}

fn pure_client_step_init(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    guard generate_client_handshake_keys(
        slot.client_cfg.enable_pq_hybrid, slot.client_random,
        slot.eph_priv, slot.eph_pub, slot.pq_priv, slot.pq_pub,
    ) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    slot.offered_group = rfc::GROUP_X25519;
    slot.offered_pq_ch = slot.client_cfg.enable_pq_hybrid;

    var ch_msg: u8[..4096] = [];
    guard pure_client_build_initial_ch(slot, ch_msg) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard pure_append_plaintext_hs(slot.wire_out, ch_msg[..], 0x01) && slot.wire_out.try_append(ccs[..]) else {
        return tls::TlsBackendStatus.Error;
    }
    transcript_update(slot.transcript, ch_msg[..]);
    slot.stage = PureHsStage.ClientWaitServerHello;
    return tls::TlsBackendStatus.WantRead;
}

fn pure_compute_client_pq_ecdhe(
    slot:       PureTlsSlot&,
    sh:         const tls::ParsedServerHello&,
    out_secret: u8[..80]&,
) -> bool {
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
    guard ok_c && mlkem768_decapsulate(srv_pq.mlkem768_ciphertext[..], slot.pq_priv[..], pq_ss[..]) else {
        return false;
    }
    var pq_comb: u8[64] = [0; 64];
    defer core::secure_zeroize_64(pq_comb);
    guard derive_x25519_mlkem768_shared_secret_checked(classic_ss[..], pq_ss[..], pq_comb[..]) else {
        return false;
    }
    return out_secret.try_set(pq_comb[..]);
}

fn pure_compute_client_ecdhe(
    slot:       PureTlsSlot&,
    sh:         const tls::ParsedServerHello&,
    out_secret: u8[..80]&,
) -> bool {
    defer core::secure_zeroize_32(slot.eph_priv);
    defer core::secure_zeroize_48(slot.p384_priv);
    defer core::secure_zeroize_slice(slot.pq_priv[..]);
    out_secret.clear();
    if sh.selected_group == rfc::GROUP_X25519_MLKEM768 && slot.offered_pq_ch {
        return pure_compute_client_pq_ecdhe(slot, sh, out_secret);
    }
    if sh.selected_group == rfc::GROUP_SECP256R1 &&
        slot.offered_group == rfc::GROUP_SECP256R1 &&
        sh.server_share.len == 65 {
        var ss256, ok_ss256 = core::p256_ecdh_shared_secret(slot.eph_priv, sh.server_share[..]);
        defer core::secure_zeroize_32(ss256);
        guard ok_ss256 else { return false; }
        return out_secret.try_set(ss256[..]);
    }
    if sh.selected_group == rfc::GROUP_SECP384R1 &&
        slot.offered_group == rfc::GROUP_SECP384R1 &&
        sh.server_share.len == 97 {
        var ss384, ok_ss384 = core::p384_ecdh_shared_secret(slot.p384_priv, sh.server_share[..]);
        defer core::secure_zeroize_48(ss384);
        guard ok_ss384 else { return false; }
        return out_secret.try_set(ss384[..]);
    }
    guard sh.selected_group == rfc::GROUP_X25519 &&
        slot.offered_group == rfc::GROUP_X25519 &&
        sh.server_share.len == 32 else {
        return false;
    }
    var srv_pub: u8[32] = [0; 32];
    core::ct_copy_bytes(srv_pub[..], sh.server_share[..]);
    var ss, ok_ss = core::x25519_shared_secret(slot.eph_priv, srv_pub);
    defer core::secure_zeroize_32(ss);
    guard ok_ss else { return false; }
    return out_secret.try_set(ss[..]);
}

fn pure_client_build_hrr_ch2(
    slot:        PureTlsSlot&,
    sh:          const tls::ParsedServerHello&,
    hrr_raw_msg: const u8[:],
    nist_pub:    const u8[:],
    out_ch2:     u8[..4096]&,
) -> bool {
    // RFC 8446 Section 4.4.1: The Transcript Hash - Replace CH1 with synthetic message_hash before appending HRR.
    var ks_hrr, ok_kshr = ks_init(sh.cipher_suite);
    defer ks_zeroize(ks_hrr);
    guard ok_kshr && transcript_replace_with_message_hash(slot.transcript, ks_hrr.hash_id, ks_hrr.hash_len) else {
        return false;
    }
    transcript_update(slot.transcript, hrr_raw_msg);

    let pq_pub_slice = if slot.offered_pq_ch { slot.pq_pub[..] } else { "" };
    if slot.ech_state.active {
        let exp_hrr, ok_hc = compute_ech_confirm_from_transcript(
            slot.ech_state.inner_random, slot.ech_state.inner_tr, hrr_raw_msg, true, ks_hrr.hash_id,
        );
        guard ok_hc && ech_fsm_on_server_hello(
            slot.ech_state.fsm, tls::EchServerHelloType.HelloRetryRequest,
            sh.has_ech_ext, sh.ech_ext_data[..], exp_hrr, slot.ech_state.retry_configs,
        ) else { return false; }
        guard transcript_replace_with_message_hash(slot.ech_state.inner_tr, ks_hrr.hash_id, ks_hrr.hash_len) else {
            return false;
        }
        transcript_update(slot.ech_state.inner_tr, hrr_raw_msg);
        return build_ech_sealed_client_hello(
            slot.client_cfg, slot.client_random, slot.eph_pub, slot.offered_pq_ch,
            pq_pub_slice, sh.hrr_cookie[..], nist_pub, true, slot.ech_state, out_ch2,
        );
    }

    var ch2_payload: u8[..4096] = [];
    build_client_hello_payload(
        slot.client_random, slot.eph_pub, slot.client_cfg.server_name[..], slot.alpn_csv[..],
        ch2_payload, "", 0, slot.offered_pq_ch, pq_pub_slice,
        "", sh.hrr_cookie[..], slot.client_cfg.client_cert_der.len > 0, 32, nist_pub,
    );
    return frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch2_payload[..], out_ch2);
}

fn pure_client_handle_hrr(
    slot:   PureTlsSlot&,
    sh_msg: const u8[:],
    sh:     const tls::ParsedServerHello&,
) -> tls::TlsBackendStatus {
    guard !slot.hrr_sent else {
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }
    guard validate_live_client_sh(sh, slot.client_random) &&
        (sh.selected_group != 0 || sh.hrr_cookie.len > 0) else {
        return pure_fail_with_alert(slot, tls::Alert.IllegalParameter, tls::TlsBackendStatus.HandshakeError);
    }
    if sh.selected_group != 0 {
        let all_groups: u16[4] = [
            rfc::GROUP_X25519_MLKEM768,
            rfc::GROUP_X25519,
            rfc::GROUP_SECP256R1,
            rfc::GROUP_SECP384R1,
        ];
        let init_shares: u16[2] = [rfc::GROUP_X25519_MLKEM768, rfc::GROUP_X25519];
        let grp_start = if slot.client_cfg.enable_pq_hybrid { 0 } else { 1 };
        guard validate_hrr_selected_group(sh.selected_group, all_groups[grp_start..], init_shares[grp_start..]) else {
            return pure_fail_with_alert(slot, tls::Alert.IllegalParameter, tls::TlsBackendStatus.HandshakeError);
        }
    }

    slot.has_psk_ticket = false;
    core::secure_zeroize_slice(slot.psk_secret[..]);
    slot.psk_secret.clear();

    var nist_pub: u8[..97] = [];
    let enable_pq_ch2, ch2_group, ok_regen = regenerate_client_hrr_keyshare(
        sh.selected_group, slot.client_cfg.enable_pq_hybrid,
        slot.eph_priv, slot.eph_pub, slot.pq_priv, slot.pq_pub, slot.p384_priv, nist_pub,
    );
    guard ok_regen else {
        return pure_fail_with_alert(slot, tls::Alert.IllegalParameter, tls::TlsBackendStatus.HandshakeError);
    }
    slot.offered_pq_ch = enable_pq_ch2;
    slot.offered_group = ch2_group;

    var ch2_msg: u8[..4096] = [];
    guard pure_client_build_hrr_ch2(slot, sh, sh_msg, nist_pub[..], ch2_msg) else {
        return pure_fail_with_alert(slot, tls::Alert.IllegalParameter, tls::TlsBackendStatus.HandshakeError);
    }
    guard pure_append_plaintext_hs(slot.wire_out, ch2_msg[..], 0x03) else { return tls::TlsBackendStatus.Error; }
    transcript_update(slot.transcript, ch2_msg[..]);
    slot.hrr_sent = true;
    slot.hrr_cipher = sh.cipher_suite;
    slot.hrr_group = sh.selected_group;
    return tls::TlsBackendStatus.WantRead;
}

fn pure_client_step_sh(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var sh_msg: u8[..16384] = [];
    let st = pure_pop_plaintext_hs_msg(slot, sh_msg);
    guard st == tls::TlsBackendStatus.Ok else { return st; }
    // RFC 8446 Section 5.1: Record Layer - No plaintext bytes may cross the ServerHello key-change epoch.
    guard slot.hs_plain.len == 0 else {
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }

    var sh = tls::ParsedServerHello { .. };
    guard tls::parse_live_server_hello(sh_msg[..], sh) else {
        let alert = classify_sh_failure_alert(sh_msg[..]);
        return pure_fail_with_alert(slot, alert, tls::TlsBackendStatus.HandshakeError);
    }
    if sh.is_hrr {
        return pure_client_handle_hrr(slot, sh_msg[..], sh);
    }

    let hrr_suite_ok = !slot.hrr_sent || validate_hrr_cipher_suite(slot.hrr_cipher, sh.cipher_suite);
    let group_ok = if slot.hrr_sent && slot.hrr_group != 0 {
        sh.selected_group == slot.hrr_group
    } else {
        is_group_offered_in_client_hello(sh.selected_group, slot.offered_group, slot.offered_pq_ch)
    };
    guard validate_live_client_sh(sh, slot.client_random) &&
        hrr_suite_ok &&
        group_ok &&
        verify_ech_server_hello_acceptance(slot.ech_state, sh, sh_msg[..], slot.transcript) else {
        return pure_fail_with_alert(slot, tls::Alert.IllegalParameter, tls::TlsBackendStatus.HandshakeError);
    }
    if sh.psk_resumed {
        guard slot.has_psk_ticket &&
            rfc::tls13_cipher_suite_hash_len(sh.cipher_suite) == slot.psk_hash_len else {
            return pure_fail_with_alert(slot, tls::Alert.IllegalParameter, tls::TlsBackendStatus.HandshakeError);
        }
    }
    slot.psk_resumed = sh.psk_resumed;
    slot.cipher_suite = sh.cipher_suite;

    var ecdhe_secret: u8[..80] = [];
    defer core::secure_zeroize_slice(ecdhe_secret[..]);
    let early_ikm = if slot.psk_resumed { slot.psk_secret[..] } else { "" };
    guard pure_compute_client_ecdhe(slot, sh, ecdhe_secret) &&
        pure_derive_hs_traffic_keys(slot, ecdhe_secret[..], early_ikm) else {
        return pure_fail_with_alert(slot, tls::Alert.IllegalParameter, tls::TlsBackendStatus.HandshakeError);
    }
    slot.stage = PureHsStage.ClientWaitEE;
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_step_ee(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    let active_sni = if slot.ech_state.active && slot.ech_state.fsm.mode != tls::EchHandshakeMode.Accepted {
        slot.ech_state.cfg.public_name[..]
    } else {
        slot.client_cfg.server_name[..]
    };
    let sni_st = if validate_sni_host_bytes(active_sni) {
        tls::SniOfferState.Offered
    } else {
        tls::SniOfferState.Omitted
    };
    let allow_ech_retry = slot.ech_state.active && slot.ech_state.fsm.mode == tls::EchHandshakeMode.Bypassed;
    guard parse_encrypted_extensions_alpn(
        slot.hs_msg_body[..], slot.selected_alpn, slot.alpn_csv[..], sni_st, allow_ech_retry,
    ) else {
        let alert = classify_ee_failure_alert(slot.hs_msg_body[..]);
        return pure_fail_with_alert(slot, alert, tls::TlsBackendStatus.HandshakeError);
    }
    if slot.ech_state.active {
        var entries: tls::ExtensionEntry[..32] = [];
        guard tls::parse_extensions_block(slot.hs_msg_body[..], entries) else {
            return pure_fail_with_alert(slot, tls::Alert.DecodeError, tls::TlsBackendStatus.HandshakeError);
        }
        let ech_ext_data, has_ech_ext = tls::find_extension(entries, rfc::EXT_ENCRYPTED_CLIENT_HELLO);
        guard tls::ech_fsm_on_encrypted_extensions(
            slot.ech_state.fsm, has_ech_ext, ech_ext_data, slot.ech_state.retry_configs,
        ) else {
            return pure_fail_with_alert(slot, tls::Alert.UnsupportedExtension, tls::TlsBackendStatus.HandshakeError);
        }
    }
    transcript_update_msg(slot.transcript, rfc::TLS_HS_ENCRYPTED_EXTENSIONS, slot.hs_msg_body[..]);
    slot.stage = if slot.psk_resumed { PureHsStage.ClientWaitFinished } else { PureHsStage.ClientWaitCertCr };
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_step_cert(slot: PureTlsSlot&, msg_t: u8) -> tls::TlsBackendStatus {
    if msg_t == rfc::TLS_HS_COMPRESSED_CERTIFICATE {
        transcript_update_msg(slot.transcript, msg_t, slot.hs_msg_body[..]);
        let offered_comp: u16[3] = [
            rfc::CERT_COMPRESSION_BROTLI,
            rfc::CERT_COMPRESSION_ZSTD,
            rfc::CERT_COMPRESSION_ZLIB,
        ];
        guard decompress_incoming_certificate(
            slot.hs_msg_body[..], slot.peer_cert_body, offered_comp[..],
        ) else {
            return pure_fail_with_alert(slot, tls::Alert.BadCertificate, tls::TlsBackendStatus.VerifyError);
        }
        slot.stage = PureHsStage.ClientWaitCV;
        return tls::TlsBackendStatus.Ok;
    }
    guard msg_t == rfc::TLS_HS_CERTIFICATE else {
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }
    guard slot.peer_cert_body.try_set(slot.hs_msg_body[..]) else {
        return pure_fail_with_alert(slot, tls::Alert.DecodeError, tls::TlsBackendStatus.HandshakeError);
    }
    transcript_update_msg(slot.transcript, msg_t, slot.hs_msg_body[..]);
    slot.stage = PureHsStage.ClientWaitCV;
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_step_cert_cr(slot: PureTlsSlot&, msg_t: u8) -> tls::TlsBackendStatus {
    if msg_t == rfc::TLS_HS_CERTIFICATE_REQUEST {
        guard tls::parse_certificate_request(slot.hs_msg_body[..], false, slot.cert_req) else {
            return pure_fail_with_alert(slot, tls::Alert.DecodeError, tls::TlsBackendStatus.HandshakeError);
        }
        transcript_update_msg(slot.transcript, msg_t, slot.hs_msg_body[..]);
        slot.cert_req_received = true;
        slot.stage = PureHsStage.ClientWaitCert;
        return tls::TlsBackendStatus.Ok;
    }
    return pure_client_step_cert(slot, msg_t);
}

fn pure_client_verify_cv(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);

    var saved_sni: u8[..256] = slot.client_cfg.server_name;
    defer { slot.client_cfg.server_name = saved_sni; };
    if slot.ech_state.active && slot.ech_state.fsm.mode != tls::EchHandshakeMode.Accepted {
        guard slot.client_cfg.server_name.try_set(slot.ech_state.cfg.public_name[..]) else {
            return tls::TlsBackendStatus.Error;
        }
    }

    let ok_v = verify_server_cert_and_signature(
        slot.peer_cert_body[..], slot.hs_msg_body[..], h_to_cert[..], slot.client_cfg, 0xFFFF,
    );
    let ok_leaf = ok_v && extract_leaf_cert_der(slot.peer_cert_body[..], slot.peer_leaf_der);
    if !ok_v || !ok_leaf {
        let cert_alert = classify_cert_failure_alert(slot.peer_cert_body[..]);
        slot.peer_cert_body.clear();
        slot.peer_leaf_der.clear();
        return pure_fail_with_alert(slot, cert_alert, tls::TlsBackendStatus.VerifyError);
    }
    slot.peer_cert_body.clear();
    transcript_update_msg(slot.transcript, rfc::TLS_HS_CERTIFICATE_VERIFY, slot.hs_msg_body[..]);
    slot.stage = PureHsStage.ClientWaitFinished;
    return tls::TlsBackendStatus.Ok;
}

fn pure_client_emit_client_cert_flight(slot: PureTlsSlot&) -> bool {
    var cert_payload: u8[..16384] = [];
    guard encode_client_certificate_chain(
        cert_payload,
        slot.cert_req.context[..],
        slot.client_cfg.client_cert_der[..],
        slot.client_cfg.client_chain_der[..],
    ) else { return false; }

    var cert_msg: u8[..16384] = [];
    guard frame_handshake_msg_4k(rfc::TLS_HS_CERTIFICATE, cert_payload[..], cert_msg) &&
        pure_seal_hs_to_wire(slot, cert_msg[..]) else {
        return false;
    }
    transcript_update(slot.transcript, cert_msg[..]);

    guard slot.client_cfg.client_cert_der.len > 0 else { return true; }

    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);
    var cv_input: u8[160] = [0; 160];
    let cv_len, ok_cv = tls::build_certificate_verify_message(false, h_to_cert[..], cv_input[..]);
    var sig_buf: u8[..128] = [];
    let sig_scheme, ok_sig = sign_certificate_verify(
        slot.client_cfg.client_cert_der[..], slot.client_cfg.client_priv_seed, cv_input[..cv_len], sig_buf,
    );
    // RFC 8446 Section 4.4.3: Certificate Verify - Selected scheme must appear in CertificateRequest.signature_algorithms.
    guard ok_cv && ok_sig && slot.cert_req.sig_algorithms.contains(sig_scheme) else { return false; }

    var cv_pay: u8[..512] = [];
    guard tls::encode_client_certificate_verify(cv_pay, sig_scheme, sig_buf[..]) else { return false; }
    var cv_msg: u8[..512] = [];
    guard frame_handshake_msg_4k(rfc::TLS_HS_CERTIFICATE_VERIFY, cv_pay[..], cv_msg) &&
        pure_seal_hs_to_wire(slot, cv_msg[..]) else {
        return false;
    }
    transcript_update(slot.transcript, cv_msg[..]);
    return true;
}

fn pure_client_finish_hs(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    let hlen = slot.ks.hash_len as i64;
    guard slot.hs_msg_body.len == hlen else {
        return pure_fail_with_alert(slot, tls::Alert.DecryptError, tls::TlsBackendStatus.HandshakeError);
    }
    // RFC 8446 Section 5.1: Record Layer - No handshake bytes may cross the Finished key-change epoch.
    guard slot.hs_plain_pos == slot.hs_plain.len else {
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }
    var h_to_cv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cv);
    var exp_srv_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(exp_srv_fin);
    guard ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.server_hs_traffic[..hlen], h_to_cv[..], exp_srv_fin[..hlen],
    ) && core::ct_eq_bytes(exp_srv_fin[..hlen], slot.hs_msg_body[..hlen]) else {
        return pure_fail_with_alert(slot, tls::Alert.DecryptError, tls::TlsBackendStatus.HandshakeError);
    }
    transcript_update_msg(slot.transcript, rfc::TLS_HS_FINISHED, slot.hs_msg_body[..hlen]);

    // RFC 9849 Section 6.1.6: Abort with ech_required if ECH was offered and rejected by server.
    if slot.ech_state.active && slot.ech_state.fsm.mode != tls::EchHandshakeMode.Accepted {
        return pure_fail_with_alert(slot, tls::Alert.EchRequired, tls::TlsBackendStatus.HandshakeError);
    }

    var h_through_srv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_through_srv);
    guard ks_advance_to_master(slot.ks, h_through_srv[..]) else {
        return tls::TlsBackendStatus.HandshakeError;
    }

    if slot.cert_req_received {
        guard pure_client_emit_client_cert_flight(slot) else {
            return pure_fail_with_alert(slot, tls::Alert.HandshakeFailure, tls::TlsBackendStatus.HandshakeError);
        }
    }

    var h_before_fin: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_before_fin);
    var cli_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(cli_fin);
    guard ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.client_hs_traffic[..hlen], h_before_fin[..], cli_fin[..hlen],
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

fn pure_client_step_encrypted(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var msg_t: u8 = 0;
    let st = pure_next_encrypted_hs_msg(slot, msg_t);
    guard st == tls::TlsBackendStatus.Ok else { return st; }

    if slot.stage == PureHsStage.ClientWaitEE {
        guard msg_t == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else {
            return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
        }
        return pure_client_step_ee(slot);
    }
    if slot.stage == PureHsStage.ClientWaitCertCr {
        return pure_client_step_cert_cr(slot, msg_t);
    }
    if slot.stage == PureHsStage.ClientWaitCert {
        return pure_client_step_cert(slot, msg_t);
    }
    if slot.stage == PureHsStage.ClientWaitCV {
        guard msg_t == rfc::TLS_HS_CERTIFICATE_VERIFY else {
            return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
        }
        return pure_client_verify_cv(slot);
    }
    guard msg_t == rfc::TLS_HS_FINISHED else {
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }
    return pure_client_finish_hs(slot);
}

inline fn pure_server_emit_cert_req(slot: PureTlsSlot&) -> bool {
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
    guard cr_msg.try_append(cr_payload[..]) && pure_seal_hs_to_wire(slot, cr_msg[..]) else { return false; }
    transcript_update(slot.transcript, cr_msg[..]);
    return true;
}

fn pure_server_emit_cert_and_cv(slot: PureTlsSlot&) -> bool {
    var cert_msg: u8[..20480] = [];
    guard encode_server_cert_with_optional_compression(
        slot.cert_der[..],
        slot.extra_certs_der[..],
        slot.compressed_cert_algo,
        slot.compressed_cert_data[..],
        slot.negotiated_cert_comp_algo,
        cert_msg,
    ) && pure_seal_hs_to_wire(slot, cert_msg[..]) else {
        return false;
    }
    transcript_update(slot.transcript, cert_msg[..]);

    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);
    var cv_input: u8[160] = [0; 160];
    let cv_len, ok_cv = tls::build_certificate_verify_message(true, h_to_cert[..], cv_input[..]);
    var sig_buf: u8[..512] = [];
    let sig_scheme, ok_sig = sign_certificate_verify(
        slot.cert_der[..], slot.priv_seed, cv_input[..cv_len],
        sig_buf, slot.rsa_key_slot, slot.rsa_key_gen,
    );
    var cv_pay: u8[..1024] = [];
    guard ok_cv &&
        ok_sig &&
        tls::encode_client_certificate_verify(cv_pay, sig_scheme, sig_buf[..]) else {
        return false;
    }
    var cv_msg: u8[..1024] = [];
    guard frame_handshake_msg_4k(rfc::TLS_HS_CERTIFICATE_VERIFY, cv_pay[..], cv_msg) &&
        pure_seal_hs_to_wire(slot, cv_msg[..]) else {
        return false;
    }
    transcript_update(slot.transcript, cv_msg[..]);
    return true;
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

    if !slot.psk_resumed {
        if slot.require_client_cert {
            guard pure_server_emit_cert_req(slot) else { return false; }
        }
        guard pure_server_emit_cert_and_cv(slot) else { return false; }
    }

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

fn pure_server_emit_hrr(
    slot:      PureTlsSlot&,
    ch_choice: const ServerClientHelloChoice&,
) -> tls::TlsBackendStatus {
    var hrr_pay: u8[..256] = [];
    build_hrr_payload(ch_choice.session_id[..], ch_choice.cipher_suite, ch_choice.selected_group, hrr_pay);
    var hrr_msg: u8[..280] = [];
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard frame_handshake_msg_4k(rfc::TLS_HS_SERVER_HELLO, hrr_pay[..], hrr_msg) &&
        pure_append_plaintext_hs(slot.wire_out, hrr_msg[..], 0x03) &&
        slot.wire_out.try_append(ccs[..]) else {
        return tls::TlsBackendStatus.Error;
    }
    var ks_hrr, ok_kshr = ks_init(ch_choice.cipher_suite);
    defer ks_zeroize(ks_hrr);
    guard ok_kshr &&
        transcript_replace_with_message_hash(slot.transcript, ks_hrr.hash_id, ks_hrr.hash_len) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    transcript_update(slot.transcript, hrr_msg[..]);
    slot.hrr_sent = true;
    slot.hrr_group = ch_choice.selected_group;
    slot.hrr_cipher = ch_choice.cipher_suite;
    let _ = slot.hrr_sid.try_set(ch_choice.session_id[..]);
    return tls::TlsBackendStatus.WantRead;
}

fn pure_server_pop_or_resume_ch(slot: PureTlsSlot&, out_ch: u8[..16384]&) -> tls::TlsBackendStatus {
    if slot.pending_ch_msg.len > 0 {
        guard out_ch.try_set(slot.pending_ch_msg[..]) else {
            return tls::TlsBackendStatus.Error;
        }
        slot.pending_ch_msg.clear();
        return tls::TlsBackendStatus.Ok;
    }
    let st = pure_pop_plaintext_hs_msg(slot, out_ch);
    guard st == tls::TlsBackendStatus.Ok else { return st; }
    // RFC 8446 Section 5.1: Record Layer - No plaintext bytes may cross the ClientHello key-change epoch.
    guard slot.hs_plain.len == 0 else { return tls::TlsBackendStatus.HandshakeError; }
    return tls::TlsBackendStatus.Ok;
}

fn pure_fail_ch_parse(slot: PureTlsSlot&, fail_alert: tls::Alert) -> tls::TlsBackendStatus {
    if fail_alert == tls::Alert.NoApplicationProtocol ||
        fail_alert == tls::Alert.UnsupportedExtension {
        return pure_fail_with_alert(slot, fail_alert, tls::TlsBackendStatus.HandshakeError);
    }
    return tls::TlsBackendStatus.HandshakeError;
}

fn pure_server_stash_deferred_sni(
    slot:     PureTlsSlot&,
    ch_msg:   const u8[:],
    hrr_mode: ServerHrrMode,
) -> tls::TlsBackendStatus {
    var pre_ch = ServerClientHelloChoice { .. };
    defer zeroize_server_ch_choice(pre_ch);
    let alpn_policy = if slot.require_alpn_match {
        ServerAlpnPolicy.RequireMatch
    } else {
        ServerAlpnPolicy.Optional
    };
    guard parse_server_client_hello(
        ch_msg, slot.alpn_csv[..], 0, 0, hrr_mode, pre_ch,
        slot.require_client_cert, ServerPskPolicy.DisableResumption, alpn_policy,
    ) else {
        return pure_fail_ch_parse(slot, pre_ch.failure_alert);
    }
    guard slot.server_name.try_set(pre_ch.client_sni[..]) &&
        slot.pending_ch_msg.try_set(ch_msg) else {
        return tls::TlsBackendStatus.Error;
    }
    slot.client_hello_parsed = true;
    slot.stage = PureHsStage.ServerNeedSniCredentials;
    return tls::TlsBackendStatus.NeedSniCredentials;
}

inline fn pure_server_matches_hrr_ch2(
    slot:      const PureTlsSlot&,
    ch_choice: const ServerClientHelloChoice&,
) -> bool {
    return ch_choice.cipher_suite == slot.hrr_cipher &&
        ch_choice.selected_group == slot.hrr_group &&
        ch_choice.session_id[..] == slot.hrr_sid[..] &&
        (!slot.hrr_sni_recorded || ch_choice.client_sni[..] == slot.hrr_sni[..]);
}

fn pure_server_emit_sh_and_flight(
    slot:      PureTlsSlot&,
    ch_choice: const ServerClientHelloChoice&,
) -> tls::TlsBackendStatus {
    slot.cipher_suite = ch_choice.cipher_suite;
    slot.client_random = ch_choice.client_random;
    let _ = slot.server_name.try_set(ch_choice.client_sni[..]);
    slot.client_hello_parsed = true;
    let _ = slot.selected_alpn.try_set(ch_choice.negotiated_alpn[..]);
    slot.psk_resumed = ch_choice.psk_resumed;
    slot.selected_psk_id = ch_choice.selected_psk_id;
    slot.negotiated_cert_comp_algo = ch_choice.cert_comp_algo;
    if slot.psk_resumed {
        guard slot.psk_secret.try_set(ch_choice.psk_secret[..]) else {
            return tls::TlsBackendStatus.HandshakeError;
        }
    }

    var srv_rand:  u8[32]   = [0; 32];
    var srv_share: u8[..65] = [];
    var ecdhe:     u8[32]   = [0; 32];
    defer core::secure_zeroize_32(ecdhe);
    guard generate_server_handshake_keys_for_group(
        ch_choice.selected_group, ch_choice.client_share[..], srv_rand, srv_share, ecdhe,
    ) else { return tls::TlsBackendStatus.HandshakeError; }

    var sh_pay: u8[..2048] = [];
    build_server_hello_payload_for_group(
        srv_rand, ch_choice.session_id[..], ch_choice.selected_group, srv_share[..],
        sh_pay, slot.psk_resumed, slot.cipher_suite, slot.selected_psk_id,
    );
    var sh_msg: u8[..2048] = [];
    guard frame_handshake_msg_4k(rfc::TLS_HS_SERVER_HELLO, sh_pay[..], sh_msg) &&
        pure_append_plaintext_hs(slot.wire_out, sh_msg[..], 0x03) else {
        return tls::TlsBackendStatus.Error;
    }
    if !slot.hrr_sent {
        let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
        guard slot.wire_out.try_append(ccs[..]) else { return tls::TlsBackendStatus.Error; }
    }
    transcript_update(slot.transcript, sh_msg[..]);
    let early_ikm = if slot.psk_resumed { slot.psk_secret[..] } else { "" };
    guard pure_derive_hs_traffic_keys(slot, ecdhe[..], early_ikm) &&
        pure_server_emit_encrypted_flight(slot) else {
        return tls::TlsBackendStatus.HandshakeError;
    }

    transcript_current_hash(slot.transcript, slot.ks.hash_id, slot.srv_fin_hash);
    guard ks_advance_to_master(slot.ks, slot.srv_fin_hash[..]) else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    slot.stage = if !slot.psk_resumed && slot.require_client_cert {
        PureHsStage.ServerWaitClientCert
    } else {
        PureHsStage.ServerWaitClientFinished
    };
    return tls::TlsBackendStatus.WantRead;
}

fn pure_server_step_ch(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var ch_msg: u8[..16384] = [];
    let pop_st = pure_server_pop_or_resume_ch(slot, ch_msg);
    guard pop_st == tls::TlsBackendStatus.Ok else { return pop_st; }

    let hrr_mode = if slot.hrr_sent { ServerHrrMode.Reject } else { ServerHrrMode.Allow };
    if slot.defer_sni_credentials {
        return pure_server_stash_deferred_sni(slot, ch_msg[..], hrr_mode);
    }
    guard slot.cert_der.len > 0 else { return tls::TlsBackendStatus.HandshakeError; }

    var ch_choice = ServerClientHelloChoice { .. };
    defer zeroize_server_ch_choice(ch_choice);
    let req_sig = detect_cert_sig_scheme(slot.cert_der[..]);
    let alpn_policy = if slot.require_alpn_match {
        ServerAlpnPolicy.RequireMatch
    } else {
        ServerAlpnPolicy.Optional
    };
    guard parse_server_client_hello(
        ch_msg[..], slot.alpn_csv[..], req_sig, slot.compressed_cert_algo,
        hrr_mode, ch_choice, slot.require_client_cert, slot.psk_policy, alpn_policy,
    ) else { return pure_fail_ch_parse(slot, ch_choice.failure_alert); }

    if !slot.hrr_sent && ch_choice.needs_hrr {
        slot.hrr_sni_recorded = true;
        let _ = slot.hrr_sni.try_set(ch_choice.client_sni[..]);
        let _ = slot.server_name.try_set(ch_choice.client_sni[..]);
        slot.client_hello_parsed = true;
        transcript_update(slot.transcript, ch_msg[..]);
        return pure_server_emit_hrr(slot, ch_choice);
    }
    if slot.hrr_sent {
        guard pure_server_matches_hrr_ch2(slot, ch_choice) else {
            return tls::TlsBackendStatus.HandshakeError;
        }
    }

    transcript_update(slot.transcript, ch_msg[..]);
    return pure_server_emit_sh_and_flight(slot, ch_choice);
}

fn pure_server_step_client_cert(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var msg_t: u8 = 0;
    let st = pure_next_encrypted_hs_msg(slot, msg_t);
    guard st == tls::TlsBackendStatus.Ok else { return st; }
    guard msg_t == rfc::TLS_HS_CERTIFICATE && slot.peer_cert_body.try_set(slot.hs_msg_body[..]) else {
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }
    transcript_update_msg(slot.transcript, msg_t, slot.hs_msg_body[..]);
    slot.stage = PureHsStage.ServerWaitClientCV;
    return tls::TlsBackendStatus.Ok;
}

fn pure_server_step_client_cv(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var msg_t: u8 = 0;
    let st = pure_next_encrypted_hs_msg(slot, msg_t, 16384);
    guard st == tls::TlsBackendStatus.Ok else { return st; }
    guard msg_t == rfc::TLS_HS_CERTIFICATE_VERIFY else {
        slot.peer_cert_body.clear();
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }
    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);
    let now_unix = core::now().wall_sec;
    let ok_cli = verify_client_cert_and_signature(
        slot.peer_cert_body[..], slot.hs_msg_body[..], h_to_cert[..], slot.client_cfg.trust_store, now_unix,
    );
    let ok_leaf = ok_cli && extract_leaf_cert_der(slot.peer_cert_body[..], slot.peer_leaf_der);
    slot.peer_cert_body.clear();
    guard ok_cli && ok_leaf else {
        slot.peer_leaf_der.clear();
        return pure_fail_with_alert(slot, tls::Alert.BadCertificate, tls::TlsBackendStatus.VerifyError);
    }
    transcript_update_msg(slot.transcript, msg_t, slot.hs_msg_body[..]);
    slot.stage = PureHsStage.ServerWaitClientFinished;
    return tls::TlsBackendStatus.Ok;
}

fn pure_server_step_fin(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    var msg_t: u8 = 0;
    let st = pure_next_encrypted_hs_msg(slot, msg_t, 16384);
    guard st == tls::TlsBackendStatus.Ok else { return st; }

    let hlen = slot.ks.hash_len as i64;
    guard msg_t == rfc::TLS_HS_FINISHED else {
        return pure_fail_with_alert(slot, tls::Alert.UnexpectedMessage, tls::TlsBackendStatus.HandshakeError);
    }
    // RFC 8446 Section 5.1: Record Layer - No handshake bytes may cross the Finished key-change epoch.
    guard slot.hs_msg_body.len == hlen && slot.hs_plain_pos == slot.hs_plain.len else {
        return pure_fail_with_alert(slot, tls::Alert.DecryptError, tls::TlsBackendStatus.HandshakeError);
    }
    var h_before_fin: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_before_fin);
    var exp_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(exp_fin);
    guard ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.client_hs_traffic[..hlen], h_before_fin[..], exp_fin[..hlen],
    ) && core::ct_eq_bytes(exp_fin[..hlen], slot.hs_msg_body[..hlen]) else {
        return pure_fail_with_alert(slot, tls::Alert.DecryptError, tls::TlsBackendStatus.HandshakeError);
    }
    transcript_update_msg(slot.transcript, msg_t, slot.hs_msg_body[..hlen]);
    var h_cli: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_cli);
    let _ = ks_advance_to_resumption(slot.ks, h_cli[..]);
    guard pure_install_app_keys(slot) else { return tls::TlsBackendStatus.Error; }
    return tls::TlsBackendStatus.Ok;
}

fn pure_step_handshake_loop(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    for _ in 16 {
        if slot.stage == PureHsStage.Established { return tls::TlsBackendStatus.Ok; }
        if slot.stage == PureHsStage.Failed { return tls::TlsBackendStatus.HandshakeError; }
        let st = match slot.stage {
            ClientInit => pure_client_step_init(slot),
            ClientWaitServerHello => pure_client_step_sh(slot),
            ClientWaitEE => pure_client_step_encrypted(slot),
            ClientWaitCertCr => pure_client_step_encrypted(slot),
            ClientWaitCert => pure_client_step_encrypted(slot),
            ClientWaitCV => pure_client_step_encrypted(slot),
            ClientWaitFinished => pure_client_step_encrypted(slot),
            ServerWaitClientHello => pure_server_step_ch(slot),
            ServerNeedSniCredentials => tls::TlsBackendStatus.NeedSniCredentials,
            ServerWaitClientCert => pure_server_step_client_cert(slot),
            ServerWaitClientCV => pure_server_step_client_cv(slot),
            ServerWaitClientFinished => pure_server_step_fin(slot),
            _ => tls::TlsBackendStatus.Ok,
        };
        if st != tls::TlsBackendStatus.Ok {
            if st != tls::TlsBackendStatus.WantRead &&
                st != tls::TlsBackendStatus.WantWrite &&
                st != tls::TlsBackendStatus.NeedSniCredentials {
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
    defer tls::release_server_credentials(srv_cfg);
    guard tls::load_server_credentials_pem(cert_pem[..], key_pem[..], srv_cfg) else { return false; }
    guard slot.cert_der.try_set(srv_cfg.cert_der[..]) else { return false; }
    slot.extra_certs_der = copy(srv_cfg.extra_certs_der);
    slot.priv_seed = srv_cfg.priv_seed;
    slot.key_kind = srv_cfg.key_kind;
    slot.rsa_key_slot = srv_cfg.rsa_key_slot;
    slot.rsa_key_gen = srv_cfg.rsa_key_gen;
    slot.owns_rsa_key_slot = srv_cfg.rsa_key_slot >= 0;
    srv_cfg.rsa_key_slot = -1;
    srv_cfg.rsa_key_gen = 0;
    return true;
}

fn pure_init_server_credentials(
    slot: PureTlsSlot&,
    cfg:  const tls::TlsBackendConfig&,
) -> tls::TlsBackendStatus {
    if cfg.cert_der.len > 0 {
        guard slot.cert_der.try_set(cfg.cert_der[..]) else {
            return tls::TlsBackendStatus.HandshakeError;
        }
        slot.priv_seed = cfg.priv_seed;
    } else if cfg.cert_pem_file.len > 0 || cfg.key_pem_file.len > 0 {
        guard pure_load_server_pem_files(cfg.cert_pem_file[..], cfg.key_pem_file[..], slot) else {
            return tls::TlsBackendStatus.HandshakeError;
        }
    } else {
        guard cfg.defer_sni_credentials else {
            return tls::TlsBackendStatus.HandshakeError;
        }
    }
    if slot.require_client_cert {
        slot.client_cfg.trust_store = cfg.trust_store;
        if slot.client_cfg.trust_store.anchors.len == 0 && cfg.ca_file.len > 0 {
            let _, ok_ca = tls::load_trust_anchors_pem_file(slot.client_cfg.trust_store, cfg.ca_file[..]);
            guard ok_ca else { return tls::TlsBackendStatus.VerifyError; }
        }
        guard slot.client_cfg.trust_store.anchors.len > 0 else { return tls::TlsBackendStatus.VerifyError; }
    }
    return tls::TlsBackendStatus.Ok;
}

fn pure_init_client_credentials(
    slot: PureTlsSlot&,
    cfg:  const tls::TlsBackendConfig&,
) -> tls::TlsBackendStatus {
    if cfg.cert_pem_file.len > 0 || cfg.key_pem_file.len > 0 {
        return tls::TlsBackendStatus.Unavailable;
    }
    slot.client_cfg.insecure_skip_verify = cfg.insecure_skip_verify;
    slot.client_cfg.use_system_roots = cfg.use_system_roots;
    slot.client_cfg.enable_pq_hybrid = cfg.enable_pq_hybrid;
    slot.client_cfg.enable_session_tickets = cfg.enable_session_tickets;
    slot.client_cfg.require_ocsp_stapling = cfg.require_ocsp_stapling;
    let _ = slot.client_cfg.server_name.try_set(cfg.server_name[..]);
    let _ = slot.client_cfg.alpn.try_set(slot.alpn_csv[..]);
    let _ = slot.client_cfg.crl_der.try_set(cfg.crl_der[..]);
    let _ = slot.client_cfg.keylog_file.try_set(cfg.keylog_file[..]);
    slot.client_cfg.trust_store = cfg.trust_store;
    let load_ca = !cfg.insecure_skip_verify && slot.client_cfg.trust_store.anchors.len == 0 && cfg.ca_file.len > 0;
    if load_ca {
        let _, ok_ca = tls::load_trust_anchors_pem_file(slot.client_cfg.trust_store, cfg.ca_file[..]);
        guard ok_ca else { return tls::TlsBackendStatus.VerifyError; }
    }
    return tls::TlsBackendStatus.Ok;
}

fn open_pure_endpoint(cfg: const tls::TlsBackendConfig&, is_server: bool) -> tls::TlsEndpoint, tls::TlsBackendStatus {
    let has_pem = cfg.cert_pem_file.len > 0 && cfg.key_pem_file.len > 0;
    let half_pem = (cfg.cert_pem_file.len > 0) != (cfg.key_pem_file.len > 0);
    guard !half_pem else {
        return tls::TlsEndpoint { .. }, tls::TlsBackendStatus.HandshakeError;
    }
    if is_server && !cfg.defer_sni_credentials && cfg.cert_der.len == 0 && !has_pem {
        return tls::TlsEndpoint { .. }, tls::TlsBackendStatus.HandshakeError;
    }
    let idx, gen = alloc_pure_tls_slot();
    guard idx >= 0 else { return tls::TlsEndpoint { .. }, tls::TlsBackendStatus.Error; }
    let slot .= g_pure_tls_slots[idx as i64];
    slot.is_server = is_server;
    slot.defer_sni_credentials = is_server && cfg.defer_sni_credentials;
    slot.require_client_cert = cfg.require_client_cert;
    slot.require_alpn_match = cfg.require_alpn_match;
    slot.psk_policy = ServerPskPolicy.DisableResumption;
    slot.stage = if is_server { PureHsStage.ServerWaitClientHello } else { PureHsStage.ClientInit };
    let _ = slot.server_name.try_set(cfg.server_name[..]);
    let _ = slot.keylog_file.try_set(cfg.keylog_file[..]);
    decode_alpn_wire_to_csv(cfg.alpn_wire[..], slot.alpn_csv);
    let cred_st = if is_server {
        pure_init_server_credentials(slot, cfg)
    } else {
        pure_init_client_credentials(slot, cfg)
    };
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
    if cfg.kind != tls::TlsBackendKind.Auto && native_backend_rejects_cfg(cfg, is_server) {
        return tls::TlsEndpoint { .. }, tls::TlsBackendStatus.Unavailable;
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
    let native_st = native_i32_to_status(st_i32);
    if cfg.kind == tls::TlsBackendKind.Auto && native_st == tls::TlsBackendStatus.Unavailable {
        return open_pure_endpoint(cfg, is_server);
    }
    return tls::TlsEndpoint { .. }, native_st;
}
