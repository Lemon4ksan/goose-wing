// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal live TLS 1.3 client/server handshake flight and key-setup helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .record_internal;
import .key_schedule;
import .handshake;
import .handshake_internal;
import .asn1;
import .types;
import .sct;
import .x509;
import .pem;
import .ocsp;
import .crl;
import .ticket;
import .ticket_internal;
import .post_quantum;
import .cert_compression;
import .ech;
import .session_internal;
import .session;
import net.tcp;
import net.transport;

// Reads the next unencrypted handshake message record from the socket, discarding ChangeCipherSpec
// and reassembling multi-record plaintext handshake fragments (RFC 8446 §5.1).
fn read_plaintext_handshake_record(
    fd:          i64,
    out_payload: u8[..16384]&,
    timeout_ms:  u32 = 5000,
) -> bool {
    var raw_msg:   u8[..16384] = [];
    var ccs_count: u32         = 0;
    var found = false;
    while !found {
        var hdr: u8[5] = [0; 5];
        guard tls_read_exact(fd, hdr[..], timeout_ms) else { return false; }
        let ct, ver, p_len_u16, alert, ok_hdr = tls::parse_record_header(hdr[..]);
        guard ok_hdr else { return false; }
        let p_len = p_len_u16 as i64;
        guard p_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }

        var body: u8[..16384] = [];
        while body.len < p_len { body.push(0); }
        guard tls_read_exact(fd, body[..p_len], timeout_ms) else { return false; }

        if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
            guard ccs_count < 1 &&
                raw_msg.len == 0 &&
                ver == rfc::TLS_LEGACY_VERSION_1_2 &&
                tls::validate_change_cipher_spec_record(body[..p_len]) == tls::Alert.CloseNotify else {
                return false;
            }
            ccs_count = core::add_sat_u32(ccs_count, 1);
            continue;
        }
        guard ct == rfc::TLS_CONTENT_HANDSHAKE && raw_msg.try_append(body[..p_len]) else { return false; }
        found = tls::has_complete_plaintext_handshake_msg(raw_msg[..]);
    }
    guard found else { return false; }
    return out_payload.try_set(raw_msg[..]);
}

fn verify_chain_ocsp_and_crl(
    chain_parsed: const tls::ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    leaf_ocsp:    const u8[:],
    config:       const tls::ClientHandshakeConfig&,
    eff_clock:    i64,
) -> bool {
    if config.trust_store.anchors.len > 0 || !config.use_system_roots {
        let alert = tls::verify_certificate_chain(
            chain_parsed, chain_slices, config.trust_store, eff_clock, tls::CertValidationRole.Server,
        );
        guard alert == tls::Alert.CloseNotify else { return false; }
        guard verify_stapled_ocsp_for_chain(
            leaf_ocsp, chain_parsed, chain_slices, eff_clock, config.trust_store, config.require_ocsp_stapling,
        ) else {
            return false;
        }
        return verify_crl_for_chain_with_store(
            config.crl_der[..], chain_parsed, chain_slices, eff_clock, config.trust_store,
        );
    }

    guard chain_parsed.len > 0 && chain_slices.len == chain_parsed.len else { return false; }

    var sys_store = tls::TrustAnchorStore { .. };
    let top_idx = core::sub_sat_i64(chain_parsed.len, 1);
    let top_issuer = tls::span_slice(chain_slices[top_idx], chain_parsed[top_idx].issuer_raw);
    let _ = tls::load_system_roots_for_issuer(sys_store, top_issuer);
    let top_subj = tls::span_slice(chain_slices[top_idx], chain_parsed[top_idx].subject_raw);
    if top_subj != top_issuer {
        let _ = tls::load_system_roots_for_issuer(sys_store, top_subj);
    }
    let alert = tls::verify_certificate_chain(
        chain_parsed, chain_slices, sys_store, eff_clock, tls::CertValidationRole.Server,
    );
    guard alert == tls::Alert.CloseNotify else { return false; }
    guard verify_stapled_ocsp_for_chain(
        leaf_ocsp, chain_parsed, chain_slices, eff_clock, sys_store, config.require_ocsp_stapling,
    ) else {
        return false;
    }
    return verify_crl_for_chain_with_store(
        config.crl_der[..], chain_parsed, chain_slices, eff_clock, sys_store,
    );
}

inline fn verify_cv_sig_with_min_rsa(
    sig_scheme: u16,
    sig_bytes:  const u8[:],
    leaf_pub:   const u8[:],
    cv_msg:     const u8[:],
) -> bool {
    if sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256 ||
        sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384 {
        guard is_valid_rsa_pubkey_min_bits(leaf_pub) else { return false; }
    }
    return tls::verify_certificate_verify_sig(sig_scheme, sig_bytes, leaf_pub, cv_msg);
}

// Validates mTLS client Certificate and CertificateVerify against trust anchor store (RFC 8446 §4.4).
fn verify_client_cert_and_signature(
    cert_body:          const u8[:],
    cv_body:            const u8[:],
    transcript_to_cert: const u8[:],
    trust_store:        const tls::TrustAnchorStore&,
    now_unix:           i64,
) -> bool {
    var chain_slices: const u8[:][..8] = [];
    let _, ok_chain = tls::parse_certificate_chain_and_ocsp(cert_body, chain_slices);
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

// Validates server Certificate and CertificateVerify against trust anchor store and transcript (RFC 8446 §4.4).
fn verify_server_cert_and_signature(
    cert_body:          const u8[:],
    cv_body:            const u8[:],
    transcript_to_cert: const u8[:],
    config:             const tls::ClientHandshakeConfig&,
    slot_idx:           u16 = 0xFFFF,
) -> bool {
    var chain_slices: const u8[:][..64] = [];
    let leaf_ocsp, ok_chain = tls::parse_certificate_chain_and_ocsp(cert_body, chain_slices);
    guard ok_chain else { return false; }
    var leaf_cert = tls::ParsedCert { .. };
    guard tls::parse_x509_certificate(chain_slices[0], leaf_cert) else { return false; }
    if slot_idx != 0xFFFF { let _ = tls::populate_slot_san_hosts_from_der(slot_idx, chain_slices[0]); }

    var chain_parsed:  tls::ParsedCert[..8] = [];
    var verify_slices: const u8[:][..8]     = [];
    guard chain_parsed.try_push(leaf_cert) && verify_slices.try_push(chain_slices[0]) else { return false; }

    var idx: i64 = 1;
    let parse_limit = if config.insecure_skip_verify { 1 } else { chain_slices.len };
    while idx < parse_limit {
        var c_parsed = tls::ParsedCert { .. };
        guard tls::parse_x509_certificate(chain_slices[idx], c_parsed) else { return false; }
        guard chain_parsed.try_push(c_parsed) && verify_slices.try_push(chain_slices[idx]) else { return false; }
        idx++;
    }

    if !config.insecure_skip_verify {
        let eff_clock = if config.virtual_clock_sec > 0 { config.virtual_clock_sec } else { core::now().wall_sec };
        guard verify_chain_ocsp_and_crl(chain_parsed, verify_slices, leaf_ocsp, config, eff_clock) else {
            return false;
        }

        if config.server_name.len > 0 {
            guard tls::match_cert_san_host(leaf_cert, chain_slices[0], config.server_name[..]) else { return false; }
        }
    }

    if leaf_cert.has_key_usage && (leaf_cert.key_usage & rfc::KEY_USAGE_DIGITAL_SIGNATURE) == 0 {
        return false;
    }
    let leaf_spki_oid = tls::span_slice(chain_slices[0], leaf_cert.spki_alg_oid);
    guard leaf_spki_oid != rfc::OID_SIG_RSASSA_PSS[..] else { return false; }

    var leaf_pub = tls::span_slice(chain_slices[0], leaf_cert.spki_pubkey);
    if leaf_pub.len >= 2 && leaf_pub[0] == 0 { leaf_pub = leaf_pub[1..]; }

    let sig_scheme, sig_bytes, ok_parse_cv = tls::parse_certificate_verify(cv_body);
    guard ok_parse_cv else { return false; }

    if !config.insecure_skip_verify {
        guard tls::verify_signature_scheme_curve_binding(sig_scheme, leaf_spki_oid) else { return false; }
    }

    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = tls::build_certificate_verify_message(true, transcript_to_cert, cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }

    return verify_cv_sig_with_min_rsa(sig_scheme, sig_bytes, leaf_pub, cv_msg_buf[..cv_len]);
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
    let ext_bytes, ok_pre = tls::read_server_hello_preamble(sh_msg, rand_arr, tmp);
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
    ks:                    const tls_internal::KeySchedule&,
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
    guard tls::parse_encrypted_extensions_alpn(
        ee_body[..], out_alpn, config.alpn[..], sni_state, config.ech_config_list.len > 0,
    ) else {
        send_hs_fatal_alert(
            fd, cipher_suite, client_hs_key, client_hs_iv, classify_ee_failure_alert(ee_body[..]),
        );
        return false;
    }
    tls::transcript_update_msg(transcript, msg_ee, ee_body[..]);

    if !psk_resumed {
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
            tls::transcript_update_msg(transcript, msg_next, next_body[..]);
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
            tls::transcript_update_msg(transcript, msg_next, next_body[..]);
            let offered_comp: u16[3] = [
                rfc::CERT_COMPRESSION_BROTLI,
                rfc::CERT_COMPRESSION_ZSTD,
                rfc::CERT_COMPRESSION_ZLIB,
            ];
            guard tls::decompress_incoming_certificate(next_body[..], decomp_cert, offered_comp[..]) else {
                send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.BadCertificate);
                return false;
            }
        } else if msg_next == rfc::TLS_HS_CERTIFICATE {
            tls::transcript_update_msg(transcript, msg_next, next_body[..]);
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
        tls::transcript_current_hash(transcript, ks.hash_id, h_to_cert);
        let ok_v = verify_server_cert_and_signature(cert_body_slice, cv_body[..], h_to_cert[..], config, slot_idx);
        guard ok_v else {
            let cert_alert = classify_cert_failure_alert(cert_body_slice);
            send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, cert_alert);
            return false;
        }
        tls::transcript_update_msg(transcript, msg_cv, cv_body[..]);
    }

    var msg_fin:  u8          = 0;
    var fin_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_fin, fin_body, config.handshake_timeout_ms,
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
    tls::transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var exp_srv_fin: u8[48] = [0; 48];
    guard tls_internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen], h_to_cv[..], exp_srv_fin[..hlen],
    ) else { return false; }
    guard core::ct_eq_bytes(exp_srv_fin[..hlen], fin_body[..hlen]) else {
        send_hs_fatal_alert(fd, cipher_suite, client_hs_key, client_hs_iv, tls::Alert.DecryptError);
        return false;
    }
    tls::transcript_update_msg(transcript, msg_fin, fin_body[..]);
    return true;
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
    guard tls::encode_client_certificate_chain(
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
    client_seq++;
    tls::transcript_update(transcript, cert_msg[..]);

    if config.client_cert_der.len > 0 {
        var h_to_cert: u8[..48] = [];
        tls::transcript_current_hash(transcript, ks.hash_id, h_to_cert);
        var cv_msg_buf: u8[..256] = [];
        while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
        let cv_len, ok_cv = tls::build_certificate_verify_message(false, h_to_cert[..], cv_msg_buf[..]);
        guard ok_cv else { return false; }
        var sig_buf: u8[..128] = [];
        let sig_scheme, ok_sig = tls::sign_certificate_verify(
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
        client_seq++;
        tls::transcript_update(transcript, cv_msg[..]);
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
    tls::transcript_current_hash(transcript, ks.hash_id, h_through_prev);
    var cli_fin_data: u8[48] = [0; 48];
    let hlen = ks.hash_len as i64;
    guard tls_internal::ks_compute_finished_verify_data(
        ks.hash_id,
        ks.hash_len,
        ks.client_hs_traffic[..hlen],
        h_through_prev[..],
        cli_fin_data[..hlen],
    ) else { return false; }

    var cli_fin_msg: u8[64] = [0; 64];
    cli_fin_msg[0] = rfc::TLS_HS_FINISHED;
    cli_fin_msg[1] = 0;
    cli_fin_msg[2] = 0;
    cli_fin_msg[3] = ks.hash_len;
    core::ct_copy_bytes(cli_fin_msg[4..4 + hlen], cli_fin_data[..hlen]);

    let ok_send_fin = tls_seal_and_send_hs(
        fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, cli_fin_msg[..4 + hlen],
    );
    guard ok_send_fin else { return false; }
    tls::transcript_update(transcript, cli_fin_msg[..4 + hlen]);
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
    tls::prepare_cipher_aes_key(cipher_suite, c_ap_key, tls::g_tls_cipher_slots[idx].tx_aes_key);
    for i in 12 { tls::g_tls_cipher_slots[idx].tx_iv[i] = c_ap_iv[i]; }
    tls::g_tls_cipher_slots[idx].tx_seq = 0;
    for i in s_ap_key.len { tls::g_tls_cipher_slots[idx].rx_key[i] = s_ap_key[i]; }
    tls::prepare_cipher_aes_key(cipher_suite, s_ap_key, tls::g_tls_cipher_slots[idx].rx_aes_key);
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
    let inner_random = tls::random_bytes_32();
    let outer_exts: u16[3] = [
        rfc::TLS_EXT_SUPPORTED_GROUPS,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS,
        rfc::TLS_EXT_KEY_SHARE,
    ];
    let inner_sni = if config.server_name.len > 0 { config.server_name[..] } else { ech_cfg.public_name[..] };
    var inner_padded: u8[..384] = [];
    guard tls::build_encoded_client_hello_inner(
        inner_padded, inner_random, inner_sni, "h2", outer_exts[..], ech_cfg.maximum_name_length,
    ) else { return; }
    var eph_sk = tls::random_bytes_32();
    defer core::secure_zeroize_32(eph_sk);
    var ech_enc: u8[32]    = [0; 32];
    var ech_ct:  u8[..448] = [];
    let outer_aad = ech_cfg.public_name[..];
    guard tls::seal_ech_inner(ech_cfg, ech_cs, outer_aad, inner_padded[..], eph_sk, ech_enc, ech_ct) else { return; }
    tls::build_ech_outer_extension(ech_cfg.config_id, ech_cs, ech_enc, ech_ct[..], out);
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
        client_priv = tls::random_bytes_32();
        client_pub = core::x25519_base_scalarmult(client_priv);
        return false, true;
    }
    if selected_group == rfc::GROUP_SECP256R1 {
        client_priv = tls::random_bytes_32();
        let pub65 = core::ecdsa_p256_public_key(client_priv);
        guard out_nist_pub.try_set(pub65[..]) else { return false, false; }
        return false, true;
    }
    if selected_group == rfc::GROUP_SECP384R1 {
        var r1 = tls::random_bytes_32();
        var r2 = tls::random_bytes_32();
        defer core::secure_zeroize_32(r1);
        defer core::secure_zeroize_32(r2);
        core::ct_copy_bytes(out_p384_priv[0..32], r1[..]);
        core::ct_copy_bytes(out_p384_priv[32..48], r2[0..16]);
        let pub97 = core::p384_ecdh_public_key(out_p384_priv);
        guard out_nist_pub.try_set(pub97[..]) else { return false, false; }
        return false, true;
    }
    guard enable_pq_cfg && selected_group == rfc::GROUP_X25519_MLKEM768 else {
        return false, false;
    }
    client_priv = tls::random_bytes_32();
    client_pub = core::x25519_base_scalarmult(client_priv);
    var pq_d = tls::random_bytes_32();
    var pq_z = tls::random_bytes_32();
    defer core::secure_zeroize_32(pq_d);
    defer core::secure_zeroize_32(pq_z);
    var ek, dk = tls_internal::mlkem768_keygen(pq_d, pq_z);
    defer core::secure_zeroize_slice(dk[..]);
    pq_priv = dk;
    pq_pub = ek;
    return true, true;
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
        guard tls::validate_hrr_selected_group(hrr_group, all_groups[grp_start..], init_shares[grp_start..]) else {
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
    guard ok_kshr && tls::transcript_replace_with_message_hash(transcript, ks_hrr.hash_id, ks_hrr.hash_len) else {
        return false;
    }
    tls::transcript_update(transcript, hrr_raw_msg);

    var ch2_payload: u8[..4096] = [];
    tls::build_client_hello_payload(
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
    tls::transcript_update(transcript, ch2_msg[..]);

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
        tls::validate_hrr_cipher_suite(hrr_cipher, sh.cipher_suite) &&
        (hrr_group == 0 || sh.selected_group == hrr_group) else {
        send_plaintext_fatal_alert(fd, tls::Alert.IllegalParameter);
        return false;
    }
    tls::transcript_update(transcript, sh2_msg[..]);
    return true;
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
        guard tls::select_server_alpn_from_ext(alpn_ext, server_alpn_csv, out_alpn) else { return false; }
    }
    let psk_ext, has_psk = tls::find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
    if has_psk {
        let psk_matched, psk_ok = eval_client_hello_psk_entry(
            entries, payload, psk_ext, sel_cs, out_psk_secret, out_selected_psk_id,
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
    tls::transcript_current_hash(transcript, hash_id, h_to_cert);
    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = tls::build_certificate_verify_message(true, h_to_cert[..], cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }
    var sig_buf: u8[..128] = [];
    let sig_scheme, ok_sig = tls::sign_certificate_verify(
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
    server_seq++;
    tls::transcript_update(transcript, cv_msg[..]);
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
    ee_msg.append_u24_be((2 + ee_ext.len) as u32);
    ee_msg.append_u16_be(ee_ext.len as u16);
    ee_msg.append(ee_ext[..]);
    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, ee_msg[..]) else {
        return false;
    }
    server_seq++;
    tls::transcript_update(transcript, ee_msg[..]);
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
    tls::transcript_update(transcript, cr_msg[..]);
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
    tls::transcript_update_msg(transcript, msg_cert, cert_body[..]);

    var h_to_cert: u8[..48] = [];
    tls::transcript_current_hash(transcript, ks.hash_id, h_to_cert);

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
    tls::transcript_update_msg(transcript, msg_cv, cv_body[..]);
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
        guard tls::encode_server_cert_or_compressed_msg(config, negotiated_cert_comp_algo, cert_msg) else {
            return false;
        }

        guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cert_msg[..]) else {
            return false;
        }
        server_seq++;
        tls::transcript_update(transcript, cert_msg[..]);

        guard tls_server_send_cv(
            fd, cipher_suite, server_hs_key, server_hs_iv,
            server_seq, config.priv_seed, transcript, config.cert_der[..],
        ) else {
            return false;
        }
    }

    var h_to_cv: u8[..48] = [];
    tls::transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var srv_fin_data: u8[48] = [0; 48];
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
    tls::transcript_update(transcript, srv_fin_msg[..fin_len]);
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
    tls::prepare_cipher_aes_key(cipher_suite, s_ap_key, tls::g_tls_cipher_slots[idx].tx_aes_key);
    for i in 12 { tls::g_tls_cipher_slots[idx].tx_iv[i] = s_ap_iv[i]; }
    tls::g_tls_cipher_slots[idx].tx_seq = 0;
    for i in c_ap_key.len { tls::g_tls_cipher_slots[idx].rx_key[i] = c_ap_key[i]; }
    tls::prepare_cipher_aes_key(cipher_suite, c_ap_key, tls::g_tls_cipher_slots[idx].rx_aes_key);
    for i in 12 { tls::g_tls_cipher_slots[idx].rx_iv[i] = c_ap_iv[i]; }
    tls::g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { tls::g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { tls::g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
}
