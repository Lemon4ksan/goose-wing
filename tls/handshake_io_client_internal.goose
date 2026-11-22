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
import net.tcp;
import net.transport;
import .handshake_wire_internal;
import .session_slot_internal;
import .session_wire_internal;

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
    let eff_clock = if config.virtual_clock_sec > 0 { config.virtual_clock_sec } else { core::now().wall_sec };
    guard verify_chain_ocsp_and_crl(chain_parsed, verify_slices, leaf_ocsp, config, eff_clock) else {
        return false;
    }
    if config.server_name.len > 0 {
        guard tls::match_cert_san_host(leaf_cert, verify_slices[0], config.server_name[..]) else { return false; }
    }
    return true;
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

fn tls_client_recv_ee<B>(
    hs_reader:     tls::HandshakeRecordReader&,
    fd:            i64,
    cipher_suite:  u16,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    client_hs_key: const u8[:],
    client_hs_iv:  const u8[12]&,
    transcript:    tls::Transcript&,
    config:        const tls::ClientHandshakeConfig&,
    out_alpn:      B&,
) -> bool {
    var msg_ee:  u8          = 0;
    var ee_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_ee, ee_body, config.handshake_timeout_ms,
    ) else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, hs_reader.last_alert);
        return false;
    }
    guard msg_ee == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.UnexpectedMessage);
        return false;
    }
    let sni_state = if validate_sni_host_bytes(config.server_name[..]) {
        tls::SniOfferState.Offered
    } else {
        tls::SniOfferState.Omitted
    };
    guard parse_encrypted_extensions_alpn(
        ee_body[..], out_alpn, config.alpn[..], sni_state, config.ech_config_list.len > 0,
    ) else {
        send_hs_fatal_alert(
            fd, cipher_suite, client_hs_key, client_hs_iv, classify_ee_failure_alert(ee_body[..]),
        );
        return false;
    }
    transcript_update_msg(transcript, msg_ee, ee_body[..]);
    return true;
}

fn tls_client_recv_server_cert_and_cv(
    hs_reader:             tls::HandshakeRecordReader&,
    fd:                    i64,
    cipher_suite:          u16,
    server_hs_key:         const u8[:],
    server_hs_iv:          const u8[12]&,
    client_hs_key:         const u8[:],
    client_hs_iv:          const u8[12]&,
    ks:                    const KeySchedule&,
    transcript:            tls::Transcript&,
    config:                const tls::ClientHandshakeConfig&,
    out_cert_req_received: bool&,
    out_cert_req:          tls::CertificateRequestMsg&,
    slot_idx:              u16,
) -> bool {
    var msg_next:  u8          = 0;
    var next_body: u8[..65536] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_next, next_body, config.handshake_timeout_ms,
    ) else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, hs_reader.last_alert);
        return false;
    }

    if msg_next == rfc::TLS_HS_CERTIFICATE_REQUEST {
        guard tls::parse_certificate_request(next_body[..], false, out_cert_req) else {
            send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.DecodeError);
            return false;
        }
        transcript_update_msg(transcript, msg_next, next_body[..]);
        out_cert_req_received = true;
        next_body.clear();
        guard next_handshake_message(
            hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv,
            msg_next, next_body, config.handshake_timeout_ms,
        ) else {
            send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, hs_reader.last_alert);
            return false;
        }
    }

    var decomp_cert: u8[..65536] = [];
    var is_comp_cert = false;
    if msg_next == rfc::TLS_HS_COMPRESSED_CERTIFICATE {
        is_comp_cert = true;
        transcript_update_msg(transcript, msg_next, next_body[..]);
        let offered_comp: u16[3] = [
            rfc::CERT_COMPRESSION_BROTLI,
            rfc::CERT_COMPRESSION_ZSTD,
            rfc::CERT_COMPRESSION_ZLIB,
        ];
        guard decompress_incoming_certificate(next_body[..], decomp_cert, offered_comp[..]) else {
            send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.BadCertificate);
            return false;
        }
    } else if msg_next == rfc::TLS_HS_CERTIFICATE {
        transcript_update_msg(transcript, msg_next, next_body[..]);
    } else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.UnexpectedMessage);
        return false;
    }

    let cert_body_slice = if is_comp_cert { decomp_cert[..] } else { next_body[..] };
    var msg_cv:  u8          = 0;
    var cv_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_cv, cv_body, config.handshake_timeout_ms,
    ) else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, hs_reader.last_alert);
        return false;
    }
    guard msg_cv == rfc::TLS_HS_CERTIFICATE_VERIFY else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.UnexpectedMessage);
        return false;
    }

    var h_to_cert: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cert);
    guard verify_server_cert_and_signature(cert_body_slice, cv_body[..], h_to_cert[..], config, slot_idx) else {
        let cert_alert = classify_cert_failure_alert(cert_body_slice);
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, cert_alert);
        return false;
    }
    transcript_update_msg(transcript, msg_cv, cv_body[..]);
    return true;
}

fn tls_client_recv_server_finished(
    hs_reader:     tls::HandshakeRecordReader&,
    fd:            i64,
    cipher_suite:  u16,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    client_hs_key: const u8[:],
    client_hs_iv:  const u8[12]&,
    ks:            const KeySchedule&,
    transcript:    tls::Transcript&,
    timeout_ms:    u32,
) -> bool {
    var msg_fin:  u8          = 0;
    var fin_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_fin, fin_body, timeout_ms,
    ) else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, hs_reader.last_alert);
        return false;
    }
    let hlen = ks.hash_len as i64;
    guard msg_fin == rfc::TLS_HS_FINISHED else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.UnexpectedMessage);
        return false;
    }
    guard fin_body.len == hlen else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.DecryptError);
        return false;
    }
    guard hs_reader.current_offset == hs_reader.current_record_plain.len else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.UnexpectedMessage);
        return false;
    }

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var exp_srv_fin: u8[48] = [0; 48];
    guard ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen], h_to_cv[..], exp_srv_fin[..hlen],
    ) else { return false; }
    guard core::ct_eq_bytes(exp_srv_fin[..hlen], fin_body[..hlen]) else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.DecryptError);
        return false;
    }
    transcript_update_msg(transcript, msg_fin, fin_body[..]);
    return true;
}

// Ingests and verifies the encrypted server flight: EncryptedExtensions, [CertificateRequest],
// [Certificate | CompressedCertificate, CertificateVerify], Finished.
fn tls_client_process_server_flight<B>(
    hs_reader:             tls::HandshakeRecordReader&,
    fd:                    i64,
    cipher_suite:          u16,
    server_hs_key:         const u8[:],
    server_hs_iv:          const u8[12]&,
    client_hs_key:         const u8[:],
    client_hs_iv:          const u8[12]&,
    ks:                    const KeySchedule&,
    transcript:            tls::Transcript&,
    config:                const tls::ClientHandshakeConfig&,
    psk_resumed:           bool,
    out_alpn:              B&,
    out_cert_req_received: bool&,
    out_cert_req:          tls::CertificateRequestMsg&,
    slot_idx:              u16 = 0xFFFF,
) -> bool {
    out_cert_req_received = false;
    out_cert_req.context.clear();
    guard tls_client_recv_ee(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv,
        client_hs_key, client_hs_iv, transcript, config, out_alpn,
    ) else { return false; }

    if !psk_resumed {
        guard tls_client_recv_server_cert_and_cv(
            hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv,
            client_hs_key, client_hs_iv, ks, transcript, config,
            out_cert_req_received, out_cert_req, slot_idx,
        ) else { return false; }
    }

    return tls_client_recv_server_finished(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv,
        client_hs_key, client_hs_iv, ks, transcript, config.handshake_timeout_ms,
    );
}

fn tls_client_send_client_cert(
    fd:            i64,
    cipher_suite:  u16,
    client_hs_key: const u8[:],
    client_hs_iv:  const u8[12]&,
    client_seq:    u64&,
    ks:            const tls_internal::KeySchedule&,
    transcript:    tls::Transcript&,
    config:        const tls::ClientHandshakeConfig&,
    cert_req:      const tls::CertificateRequestMsg&,
) -> bool {
    var cert_payload: u8[..16384] = [];
    guard encode_client_certificate_chain(
        cert_payload,
        cert_req.context[..],
        config.client_cert_der[..],
        config.client_chain_der[..],
    ) else {
        return false;
    }
    var cert_msg: u8[..16384] = [];
    cert_msg.push(rfc::TLS_HS_CERTIFICATE);
    cert_msg.append_u24_be(cert_payload.len as u32);
    cert_msg.append(cert_payload[..]);

    guard tls_seal_and_send_hs(fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, cert_msg[..]) else {
        return false;
    }
    client_seq = core::add_sat_u64(client_seq, 1);
    transcript_update(transcript, cert_msg[..]);

    if config.client_cert_der.len > 0 {
        var h_to_cert: u8[..48] = [];
        transcript_current_hash(transcript, ks.hash_id, h_to_cert);
        var cv_msg_buf: u8[..256] = [];
        while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
        let cv_len, ok_cv = tls::build_certificate_verify_message(false, h_to_cert[..], cv_msg_buf[..]);
        guard ok_cv else { return false; }
        var sig_buf: u8[..128] = [];
        let sig_scheme, ok_sig = sign_certificate_verify(
            config.client_cert_der[..], config.client_priv_seed, cv_msg_buf[..cv_len], sig_buf,
        );
        // RFC 8446 Section 4.4.3: Certificate Verify - Selected scheme must appear in CertificateRequest.signature_algorithms.
        guard ok_sig && cert_req.sig_algorithms.contains(sig_scheme) else { return false; }

        var cv_payload: u8[..512] = [];
        guard tls::encode_client_certificate_verify(cv_payload, sig_scheme, sig_buf[..]) else { return false; }
        var cv_msg: u8[..512] = [];
        cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
        cv_msg.append_u24_be(cv_payload.len as u32);
        cv_msg.append(cv_payload[..]);

        guard tls_seal_and_send_hs(fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, cv_msg[..]) else {
            return false;
        }
        client_seq = core::add_sat_u64(client_seq, 1);
        transcript_update(transcript, cv_msg[..]);
    }
    return true;
}

fn tls_client_send_finished(
    fd:                i64,
    cipher_suite:      u16,
    client_hs_key:     const u8[:],
    client_hs_iv:      const u8[12]&,
    ks:                const tls_internal::KeySchedule&,
    transcript:        tls::Transcript&,
    config:            const tls::ClientHandshakeConfig&,
    cert_req_received: bool,
    cert_req:          const tls::CertificateRequestMsg&,
) -> bool {
    var client_seq: u64 = 0;
    if cert_req_received {
        guard tls_client_send_client_cert(
            fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, ks, transcript, config, cert_req,
        ) else { return false; }
    }

    var h_through_prev: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_prev);
    var cli_fin_data: u8[48] = [0; 48];
    let hlen = ks.hash_len as i64;
    guard tls_internal::ks_compute_finished_verify_data(
        ks.hash_id,
        ks.hash_len,
        ks.client_hs_traffic[..hlen],
        h_through_prev[..],
        cli_fin_data[..hlen],
    ) else { return false; }

    let fin_total_len = core::add_sat_i64(4, hlen);
    var cli_fin_msg: u8[64] = [0; 64];
    cli_fin_msg[0] = rfc::TLS_HS_FINISHED;
    cli_fin_msg[1] = 0;
    cli_fin_msg[2] = 0;
    cli_fin_msg[3] = ks.hash_len;
    core::ct_copy_bytes(cli_fin_msg[4..fin_total_len], cli_fin_data[..hlen]);

    let ok_send_fin = tls_seal_and_send_hs(
        fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, cli_fin_msg[..fin_total_len],
    );
    guard ok_send_fin else { return false; }
    transcript_update(transcript, cli_fin_msg[..fin_total_len]);
    return true;
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

fn prepare_ech_outer_extension(config: const tls::ClientHandshakeConfig&, out: u8[..512]&) {
    let ech_config_list = config.ech_config_list[..];
    guard ech_config_list.len > 0 else { return; }
    var ech_list = tls::EchConfigList { .. };
    guard tls::parse_ech_config_list(ech_config_list, ech_list) else { return; }
    var ech_cfg = tls::EchConfig { .. };
    var ech_cs = tls::EchCipherSuite { .. };
    guard tls::select_ech_config(ech_list, ech_cfg, ech_cs) else { return; }
    let inner_random = random_bytes_32();
    let outer_exts: u16[3] = [
        rfc::TLS_EXT_SUPPORTED_GROUPS,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS,
        rfc::TLS_EXT_KEY_SHARE,
    ];
    let inner_sni = if config.server_name.len > 0 { config.server_name[..] } else { ech_cfg.public_name[..] };
    var inner_padded: u8[..384] = [];
    guard build_encoded_client_hello_inner(
        inner_padded, inner_random, inner_sni, "h2", outer_exts[..], ech_cfg.maximum_name_length,
    ) else { return; }
    var eph_sk = random_bytes_32();
    defer core::secure_zeroize_32(eph_sk);
    var ech_enc: u8[32]    = [0; 32];
    var ech_ct:  u8[..448] = [];
    let outer_aad = ech_cfg.public_name[..];
    guard tls::seal_ech_inner(ech_cfg, ech_cs, outer_aad, inner_padded[..], eph_sk, ech_enc, ech_ct) else { return; }
    build_ech_outer_extension(ech_cfg.config_id, ech_cs, ech_enc, ech_ct[..], out);
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
) -> bool, bool {
    out_nist_pub.clear();
    guard selected_group != 0 else { return enable_pq_cfg, true; }
    if selected_group == rfc::GROUP_X25519 {
        client_priv = random_bytes_32();
        client_pub = core::x25519_base_scalarmult(client_priv);
        return false, true;
    }
    if selected_group == rfc::GROUP_SECP256R1 {
        client_priv = random_bytes_32();
        let pub65 = core::ecdsa_p256_public_key(client_priv);
        guard out_nist_pub.try_set(pub65[..]) else { return false, false; }
        return false, true;
    }
    if selected_group == rfc::GROUP_SECP384R1 {
        var r1 = random_bytes_32();
        var r2 = random_bytes_32();
        defer core::secure_zeroize_32(r1);
        defer core::secure_zeroize_32(r2);
        core::ct_copy_bytes(out_p384_priv[0..32], r1[..]);
        core::ct_copy_bytes(out_p384_priv[32..48], r2[0..16]);
        let pub97, ok_p384 = core::p384_ecdh_public_key(out_p384_priv);
        guard ok_p384 && out_nist_pub.try_set(pub97[..]) else { return false, false; }
        return false, true;
    }
    guard enable_pq_cfg && selected_group == rfc::GROUP_X25519_MLKEM768 else {
        return false, false;
    }
    client_priv = random_bytes_32();
    client_pub = core::x25519_base_scalarmult(client_priv);
    var pq_d = random_bytes_32();
    var pq_z = random_bytes_32();
    defer core::secure_zeroize_32(pq_d);
    defer core::secure_zeroize_32(pq_z);
    var ek, dk = tls_internal::mlkem768_keygen(pq_d, pq_z);
    defer core::secure_zeroize_slice(dk[..]);
    pq_priv = dk;
    pq_pub = ek;
    return true, true;
}

fn recv_and_validate_hrr_sh2(
    fd:            i64,
    config:        const tls::ClientHandshakeConfig&,
    client_random: const u8[32]&,
    hrr_cipher:    u16,
    hrr_group:     u16,
    transcript:    tls::Transcript&,
    sh:            tls::ParsedServerHello&,
) -> bool {
    var sh2_msg: u8[..16384] = [];
    guard read_plaintext_handshake_record(fd, sh2_msg, config.handshake_timeout_ms) else { return false; }
    guard tls::parse_live_server_hello(sh2_msg[..], sh) else {
        send_plaintext_fatal_alert(fd, classify_sh_failure_alert(sh2_msg[..]));
        return false;
    }
    guard !sh.is_hrr else {
        send_plaintext_fatal_alert(fd, tls::Alert.UnexpectedMessage);
        return false;
    }
    guard validate_live_client_sh(sh, client_random) &&
        validate_hrr_cipher_suite(hrr_cipher, sh.cipher_suite) &&
        (hrr_group == 0 || sh.selected_group == hrr_group) else {
        send_plaintext_fatal_alert(fd, tls::Alert.IllegalParameter);
        return false;
    }
    transcript_update(transcript, sh2_msg[..]);
    return true;
}

fn handle_client_hrr_transition(
    fd:            i64,
    config:        const tls::ClientHandshakeConfig&,
    client_random: const u8[32]&,
    client_priv:   u8[32]&,
    client_pub:    u8[32]&,
    p384_priv:     u8[48]&,
    pq_priv:       u8[2400]&,
    pq_pub:        u8[1184]&,
    ech_ext_raw:   const u8[:],
    transcript:    tls::Transcript&,
    hrr_raw_msg:   const u8[:],
    sh:            tls::ParsedServerHello&,
) -> bool {
    guard validate_live_client_sh(sh, client_random) else {
        send_plaintext_fatal_alert(fd, tls::Alert.IllegalParameter);
        return false;
    }
    let hrr_cipher = sh.cipher_suite;
    let hrr_group = sh.selected_group;
    let has_group = hrr_group != 0;
    guard has_group || sh.hrr_cookie.len > 0 else {
        send_plaintext_fatal_alert(fd, tls::Alert.IllegalParameter);
        return false;
    }
    if has_group {
        let all_groups: u16[4] = [
            rfc::GROUP_X25519_MLKEM768,
            rfc::GROUP_X25519,
            rfc::GROUP_SECP256R1,
            rfc::GROUP_SECP384R1,
        ];
        let init_shares: u16[2] = [rfc::GROUP_X25519_MLKEM768, rfc::GROUP_X25519];
        let grp_start = if config.enable_pq_hybrid { 0 } else { 1 };
        guard validate_hrr_selected_group(hrr_group, all_groups[grp_start..], init_shares[grp_start..]) else {
            send_plaintext_fatal_alert(fd, tls::Alert.IllegalParameter);
            return false;
        }
    }

    var nist_pub: u8[..97] = [];
    let enable_pq_ch2, ok_regen = regenerate_client_hrr_keyshare(
        hrr_group, config.enable_pq_hybrid, client_priv, client_pub, pq_priv, pq_pub, p384_priv, nist_pub,
    );
    guard ok_regen else { return false; }

    // RFC 8446 Section 4.4.1: The Transcript Hash - Replace CH1 with synthetic message_hash before appending HRR.
    var ks_hrr, ok_kshr = tls_internal::ks_init(hrr_cipher);
    guard ok_kshr && transcript_replace_with_message_hash(transcript, ks_hrr.hash_id, ks_hrr.hash_len) else {
        return false;
    }
    transcript_update(transcript, hrr_raw_msg);

    var ch2_payload: u8[..4096] = [];
    build_client_hello_payload(
        client_random, client_pub, config.server_name[..], config.alpn[..],
        ch2_payload, "", 0,
        enable_pq_ch2, if enable_pq_ch2 { pq_pub[..] } else { "" },
        ech_ext_raw, sh.hrr_cookie[..], config.client_cert_der.len > 0, 32, nist_pub[..],
    );
    var ch2_msg: u8[..4096] = [];
    guard frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch2_payload[..], ch2_msg) else {
        return false;
    }

    guard send_plaintext_handshake_record(fd, ch2_msg[..], rfc::TLS_LEGACY_VERSION_1_2) else { return false; }
    transcript_update(transcript, ch2_msg[..]);
    return recv_and_validate_hrr_sh2(fd, config, client_random, hrr_cipher, hrr_group, transcript, sh);
}
