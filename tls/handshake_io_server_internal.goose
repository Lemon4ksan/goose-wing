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

enum ServerHrrMode {
    Allow,
    Reject,
}

enum ServerPskPolicy {
    AllowResumption,
    DisableResumption,
}

struct ServerClientHelloChoice {
    session_id:      u8[..32]  = [],
    client_random:   u8[32]    = [0; 32],
    client_sni:      u8[..255] = [],
    negotiated_alpn: u8[..255] = [],
    cipher_suite:    u16       = 0,
    selected_group:  u16       = 0,
    needs_hrr:       bool      = false,
    client_share:    u8[..65]  = [],
    psk_resumed:     bool      = false,
    psk_secret:      u8[..48]  = [],
    selected_psk_id: u16       = 0,
    cert_comp_algo:  u16       = 0,
}

fn zeroize_server_ch_choice(c: ServerClientHelloChoice&) {
    core::secure_zeroize_slice(c.psk_secret[..]);
    core::secure_zeroize_32(c.client_random);
    c = ServerClientHelloChoice { .. };
}

// Parses a TLS 1.3 ClientHello for server negotiation supporting X25519, secp256r1, and HRR
// (RFC 8446 Section 4.1.2 & RFC 8446 Section 4.1.4).
//
// Example:
//   payload = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, ...0x13, 0x01...]
//   returns: true, out.cipher_suite = 0x1301
fn parse_server_client_hello(
    payload:             const u8[:],
    server_alpn_csv:     const u8[:],
    required_sig_scheme: u16,
    config_comp_algo:    u16,
    hrr_mode:            ServerHrrMode,
    out:                 ServerClientHelloChoice&,
    require_client_cert: bool            = false,
    psk_policy:          ServerPskPolicy = ServerPskPolicy.AllowResumption,
) -> bool {
    zeroize_server_ch_choice(out);
    var committed = false;
    defer if !committed { zeroize_server_ch_choice(out); };

    var entries: tls::ExtensionEntry[..32] = [];
    let sel_cs, ok_pre = decode_ch_server_preamble(payload, out.session_id, entries);
    guard ok_pre else { return false; }
    let allow_hrr = hrr_mode == ServerHrrMode.Allow;
    let sig_ext, ok_mand = extract_ch_mandatory_exts(
        entries, allow_hrr, out.selected_group, out.needs_hrr, out.client_share,
    );
    guard ok_mand else { return false; }

    let sni_ext, has_sni = tls::find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    if has_sni {
        guard tls::parse_sni_extension(sni_ext, out.client_sni) else { return false; }
    }
    let alpn_ext, has_alpn = tls::find_extension(entries, rfc::TLS_EXT_ALPN);
    if has_alpn {
        guard select_server_alpn_from_ext(alpn_ext, server_alpn_csv, out.negotiated_alpn) else {
            return false;
        }
    }
    let psk_ext, has_psk = tls::find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
    if has_psk && psk_policy == ServerPskPolicy.AllowResumption {
        let psk_matched, psk_ok = eval_client_hello_psk_entry(
            entries, payload, psk_ext, sel_cs, out.psk_secret, out.selected_psk_id, require_client_cert,
        );
        guard psk_ok else { return false; }
        out.psk_resumed = psk_matched;
    }
    if !out.psk_resumed && required_sig_scheme != 0 {
        guard validate_ch_sig_algorithms(sig_ext, required_sig_scheme) else { return false; }
    }
    out.cert_comp_algo = select_server_cert_comp_algo_from_entries(entries, config_comp_algo);
    let _ = extract_ch_client_random(payload, out.client_random);
    out.cipher_suite = sel_cs;
    committed = true;
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

    var ch = ServerClientHelloChoice { .. };
    defer zeroize_server_ch_choice(ch);
    guard parse_server_client_hello(
        payload, server_alpn_csv, required_sig_scheme, 0, ServerHrrMode.Reject, ch,
        require_client_cert, ServerPskPolicy.AllowResumption,
    ) else { return false; }
    guard !ch.needs_hrr && ch.selected_group == rfc::GROUP_X25519 && ch.client_share.len == 32 else {
        return false;
    }
    guard out_session_id.try_set(ch.session_id[..]) &&
        out_alpn.try_set(ch.negotiated_alpn[..]) &&
        out_sni.try_set(ch.client_sni[..]) &&
        out_psk_secret.try_set(ch.psk_secret[..]) else {
        return false;
    }
    core::ct_copy_bytes(out_client_pub[..], ch.client_share[..]);
    out_cipher_suite = ch.cipher_suite;
    out_psk_resumed = ch.psk_resumed;
    out_selected_psk_id = ch.selected_psk_id;
    committed = true;
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

fn derive_server_p256_ecdhe(
    client_share:     const u8[:],
    out_server_share: u8[..65]&,
    out_ecdhe_secret: u8[32]&,
) -> bool {
    var server_priv: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_priv);
    var scalar_ok = false;
    for _ in 16 {
        guard random_bytes_32_checked(server_priv) else { return false; }
        if is_valid_p256_scalar(server_priv[..]) {
            scalar_ok = true;
            break;
        }
    }
    guard scalar_ok else { return false; }
    let srv_pub = core::ecdsa_p256_public_key(server_priv);
    guard srv_pub[0] == 0x04 else { return false; }
    var ecdhe, ok_ss = core::p256_ecdh_shared_secret(server_priv, client_share);
    defer core::secure_zeroize_32(ecdhe);
    guard ok_ss && out_server_share.try_set(srv_pub[..]) else { return false; }
    out_ecdhe_secret = ecdhe;
    return true;
}

// Generates ephemeral server randomness, keypair, and ECDHE secret for X25519 or secp256r1.
// Fails closed and wipes secret material if CSPRNG or key exchange fails.
fn generate_server_handshake_keys_for_group(
    selected_group:   u16,
    client_share:     const u8[:],
    out_random:       u8[32]&,
    out_server_share: u8[..65]&,
    out_ecdhe_secret: u8[32]&,
) -> bool {
    var committed = false;
    defer if !committed {
        core::secure_zeroize_32(out_random);
        out_server_share.clear();
        core::secure_zeroize_32(out_ecdhe_secret);
    };
    out_server_share.clear();
    guard random_bytes_32_checked(out_random) else { return false; }

    if selected_group == rfc::GROUP_X25519 {
        guard client_share.len == 32 else { return false; }
        var server_priv: u8[32] = [0; 32];
        defer core::secure_zeroize_32(server_priv);
        guard random_bytes_32_checked(server_priv) else { return false; }
        var cli_pub: u8[32] = [0; 32];
        core::ct_copy_bytes(cli_pub[..], client_share);
        let srv_pub = core::x25519_base_scalarmult(server_priv);
        var ecdhe, ok_ecdhe = core::x25519_shared_secret(server_priv, cli_pub);
        defer core::secure_zeroize_32(ecdhe);
        guard ok_ecdhe && out_server_share.try_set(srv_pub[..]) else { return false; }
        out_ecdhe_secret = ecdhe;
        committed = true;
        return true;
    }

    if selected_group == rfc::GROUP_SECP256R1 {
        guard derive_server_p256_ecdhe(client_share, out_server_share, out_ecdhe_secret) else {
            return false;
        }
        committed = true;
        return true;
    }

    return false;
}
