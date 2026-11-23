// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 ClientHello, ServerHello, EncryptedExtensions, and certificate wire-codec helpers.
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
import .asn1;
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
import .pki_sig_internal;
import .pki_x509_ext_internal;
import .pki_nc_san_internal;
import .pki_ocsp_internal;
import .pki_crl_internal;
import .session_internal;
import .session_codec_internal;
import .session;

// Extracts the optional stapled OCSP response from a CertificateEntry extension block (RFC 8446 Section 4.4.2.1).
//
// Example:
//   ext_bytes = [0x00, 0x05, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x30, 0x00]
//   returns: [0x30, 0x00], ok = true
fn extract_leaf_ocsp_extension(ext_bytes: const u8[:]) -> const u8[:], bool {
    var entries: tls::ExtensionEntry[..32] = [];
    var cursor = core::cursor_from(ext_bytes);
    while cursor.cursor_len() > 0 {
        let ext_type, ok_t = cursor.read_u16();
        let ext_data, ok_d = cursor.read_u16_sub_cursor();
        guard ok_t && ok_d &&
            (ext_type == rfc::TLS_EXT_STATUS_REQUEST || ext_type == rfc::TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP) &&
            check_and_add_extension(entries, ext_type, ext_data.buf) else {
            return "", false;
        }
    }
    let status_data, has_st = tls::find_extension(entries, rfc::TLS_EXT_STATUS_REQUEST);
    guard has_st else { return "", true; }
    return tls::unwrap_ocsp_response(status_data);
}

// Parses a Certificate message payload into DER cert slices and optional leaf OCSP (RFC 8446 Section 4.4.2).
//
// Example:
//   payload = [0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x04, 'C', 'E', 'R', 'T', 0x00, 0x00]
//   returns: out_leaf_ocsp = "", ok = true, out_certs.len = 1
inline fn read_cert_entry_ocsp(ext_bytes: const u8[:], is_leaf: bool) -> const u8[:], bool {
    guard ext_bytes.len > 0 else { return "", true; }
    let ocsp_der, ok_ocsp = extract_leaf_ocsp_extension(ext_bytes);
    guard ok_ocsp else { return "", false; }
    return if is_leaf { ocsp_der } else { "" }, true;
}

fn parse_certificate_chain_and_ocsp<CertList>(
    payload:   const u8[:],
    out_certs: CertList&,
) -> const u8[:], bool {
    var committed = false;
    defer if !committed { out_certs.clear(); };
    var out_leaf_ocsp = payload[..0];
    var c = core::cursor_from(payload);
    let ctx, ok_ctx = c.read_u8_prefixed();
    guard ok_ctx && ctx.len == 0 else { return "", false; }
    let list_bytes, ok_list = c.read_u24_prefixed();
    guard ok_list && c.buf.len == 0 else { return "", false; }
    out_certs.clear();

    var lc = core::cursor_from(list_bytes);
    while lc.buf.len > 0 {
        let cert_bytes, ok_cert = lc.read_u24_prefixed();
        guard ok_cert && cert_bytes.len > 0 else { return "", false; }
        let ext_bytes, ok_ext = lc.read_u16_prefixed();
        guard ok_ext else { return "", false; }
        let is_leaf = out_certs.len == 0;
        let ocsp_der, ok_ocsp = read_cert_entry_ocsp(ext_bytes, is_leaf);
        guard ok_ocsp else { return "", false; }
        if is_leaf && ocsp_der.len > 0 {
            out_leaf_ocsp = ocsp_der;
        }
        guard out_certs.try_push(cert_bytes) else { return "", false; }
    }
    guard out_certs.len > 0 else { return "", false; }
    committed = true;
    return out_leaf_ocsp, true;
}

// Extracts the DER-encoded leaf X.509 certificate from a verified TLS 1.3 Certificate payload.
//
// Example:
//   cert_body = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x04, 'C', 'E', 'R', 'T', 0x00, 0x00]
//   returns: out_leaf_der = "CERT", ok = true
fn extract_leaf_cert_der(cert_body: const u8[:], out_leaf_der: u8[..8192]&) -> bool {
    var chain_slices: const u8[:][..64] = [];
    let _, ok = parse_certificate_chain_and_ocsp(cert_body, chain_slices);
    guard ok && chain_slices.len > 0 && out_leaf_der.try_set(chain_slices[0]) else {
        out_leaf_der.clear();
        return false;
    }
    return true;
}

// Computes a TLS 1.3 SHA-256 PSK binder tag over a truncated ClientHello handshake message (RFC 8446 §4.2.11.2).
fn compute_psk_binder(
    binder_key:   const u8[32]&,
    truncated_ch: const u8[:],
    out_binder:   u8[32]&,
) -> bool {
    var full: u8[..48] = [];
    defer core::secure_zeroize_slice(full[..]);
    guard compute_tls13_psk_binder_for_hash(
        HASH_SHA256, binder_key[..], truncated_ch, full,
    ) && full.len == 32 else {
        return false;
    }
    core::ct_copy_bytes(out_binder[..], full[..32]);
    return true;
}

// Serializes a TLS 1.3 ClientHello payload with standard extensions (RFC 8446 §4.1.2).
fn build_client_hello_payload<B>(
    random:         const u8[32]&,
    client_pub:     const u8[32]&,
    server_name:    const u8[:],
    alpn:           const u8[:],
    out:            B&,
    psk_ticket:     const u8[:] = "",
    psk_age_add:    u32         = 0,
    enable_pq:      bool        = false,
    pq_pub:         const u8[:] = "",
    ech_ext_raw:    const u8[:] = "",
    hrr_cookie:     const u8[:] = "",
    offer_pha:      bool        = false,
    psk_binder_len: u8          = 32,
    p256_pub:       const u8[:] = "",
) {
    out.clear();
    out.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    out.append(random[..]);
    out.push(32);
    out.append(random[..]);

    out.append_u16_be(6);
    out.append_u16_be(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    out.append_u16_be(rfc::TLS_CIPHER_AES_256_GCM_SHA384);
    out.append_u16_be(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256);
    out.push(1);
    out.push(0);

    var ext_buf: u8[..4096] = [];
    ext_buf.append_u16_be(rfc::TLS_EXT_SUPPORTED_VERSIONS);
    ext_buf.append_u16_be(3);
    ext_buf.push(2);
    ext_buf.append_u16_be(rfc::TLS_VERSION_1_3);

    let groups: u16[4] = [
        rfc::GROUP_X25519_MLKEM768,
        rfc::GROUP_X25519,
        rfc::GROUP_SECP256R1,
        rfc::GROUP_SECP384R1,
    ];
    let group_start = if enable_pq { 0 } else { 1 };
    encode_supported_groups_extension(ext_buf, groups[group_start..]);

    ext_buf.append_u16_be(rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    ext_buf.append_u16_be(12);
    ext_buf.append_u16_be(10);
    ext_buf.append_u16_be(rfc::SIG_SCHEME_ED25519);
    ext_buf.append_u16_be(rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256);
    ext_buf.append_u16_be(rfc::SIG_SCHEME_ECDSA_SECP384R1_SHA384);
    ext_buf.append_u16_be(rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256);
    ext_buf.append_u16_be(rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384);

    let comp_algos: u16[3] = [
        rfc::CERT_COMPRESSION_BROTLI,
        rfc::CERT_COMPRESSION_ZSTD,
        rfc::CERT_COMPRESSION_ZLIB,
    ];
    encode_compress_certificate_extension(ext_buf, comp_algos[..]);

    // RFC 6066 Section 8: Certificate Status Request - Solicit stapled OCSP responses (status_type = ocsp (1)).
    ext_buf.append_u16_be(rfc::TLS_EXT_STATUS_REQUEST);
    ext_buf.append_u16_be(5);
    ext_buf.push(1);
    ext_buf.append_u16_be(0);
    ext_buf.append_u16_be(0);

    if offer_pha {
        encode_post_handshake_auth_extension(ext_buf);
    }

    if hrr_cookie.len > 0 {
        let _ = serialize_cookie_extension(ext_buf, hrr_cookie);
    }

    var shares: u8[..1280] = [];
    if p256_pub.len == 65 {
        shares.append_u16_be(rfc::GROUP_SECP256R1);
        shares.append_u16_be(65);
        shares.append(p256_pub);
    } else if p256_pub.len == 97 {
        shares.append_u16_be(rfc::GROUP_SECP384R1);
        shares.append_u16_be(97);
        shares.append(p256_pub);
    } else {
        if enable_pq && pq_pub.len == rfc::MLKEM768_PUBLIC_LEN {
            var pq_share = PostQuantumKeyShare {
                group:         rfc::GROUP_X25519_MLKEM768,
                x25519_public: client_pub,
                ..
            };
            core::ct_copy_bytes(pq_share.mlkem768_public[..], pq_pub);
            format_hybrid_key_share(pq_share, shares);
        }
        shares.append_u16_be(rfc::GROUP_X25519);
        shares.append_u16_be(32);
        shares.append(client_pub[..]);
    }
    encode_key_share_client_extension(ext_buf, shares[..]);

    if validate_sni_host_bytes(server_name) {
        ext_buf.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
        let sni_len = core::add_sat_i64(server_name.len, 3) as u16;
        ext_buf.append_u16_be(core::add_sat_u64(sni_len as u64, 2) as u16);
        ext_buf.append_u16_be(sni_len);
        ext_buf.push(0);
        ext_buf.append_u16_be(server_name.len as u16);
        ext_buf.append(server_name);
    }

    if alpn.len > 0 && alpn.len <= 255 {
        encode_alpn_extension_from_csv(ext_buf, alpn);
    }

    if ech_ext_raw.len > 0 && ech_ext_raw.len <= 1024 {
        ext_buf.append_u16_be(rfc::EXT_ENCRYPTED_CLIENT_HELLO);
        ext_buf.append_u16_be(ech_ext_raw.len as u16);
        ext_buf.append(ech_ext_raw);
    }

    encode_psk_client_extensions(ext_buf, psk_ticket, psk_age_add, psk_binder_len);

    out.append_u16_be(ext_buf.len as u16);
    out.append(ext_buf[..]);
}

fn has_complete_plaintext_handshake_msg(raw_msg: const u8[:]) -> bool {
    guard raw_msg.len >= 4 else { return false; }
    let _, msg_len, ok_m = tls::parse_handshake_header(raw_msg);
    return ok_m && raw_msg.len >= core::add_sat_i64(4, msg_len);
}

// Parses ServerHello or HelloRetryRequest (RFC 8446 §4.1.3, §4.1.4).
//
// Example:
//   payload = [0x02, 0x00, 0x00, 0x46, 0x03, 0x03, 0x00, 0x13, 0x01]
//   returns: true, out_cipher_suite = 0x1301, out_is_hrr = false
fn parse_server_hello_or_hrr(
    payload:          const u8[:],
    out_cipher_suite: u16&,
    out_is_hrr:       bool&,
    out_group:        u16&,
    out_server_share: u8[..2048]&,
    out_psk_resumed:  bool&,
) -> bool {
    var sh = tls::ParsedServerHello { .. };
    guard tls::parse_live_server_hello(payload, sh) else {
        out_is_hrr = false;
        out_psk_resumed = false;
        out_group = 0;
        out_server_share.clear();
        return false;
    }
    out_cipher_suite = sh.cipher_suite;
    out_is_hrr = sh.is_hrr;
    out_group = sh.selected_group;
    out_psk_resumed = sh.psk_resumed;
    return out_server_share.try_set(sh.server_share[..]);
}

// Parses server EncryptedExtensions and extracts a negotiated ALPN protocol (RFC 7301 Section 3.1).
//
// Example:
//   ee_body = [0x00, 0x09, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2']
//   returns: true, out_alpn = "h2"
fn parse_encrypted_extensions_alpn<B>(
    ee_body:          const u8[:],
    out_alpn:         B&,
    offered_alpn_csv: const u8[:]        = "*",
    sni_state:        tls::SniOfferState = tls::SniOfferState.Offered,
    allow_ech_retry:  bool               = false,
) -> bool {
    var committed = false;
    defer if !committed { out_alpn.clear(); };
    var entries: tls::ExtensionEntry[..32] = [];
    guard tls::parse_extensions_block(ee_body, entries) else { return false; }
    guard validate_ee_solicited_extensions(entries, offered_alpn_csv, sni_state, allow_ech_retry) else {
        return false;
    }
    out_alpn.clear();
    let alpn_data, has_alpn = tls::find_extension(entries, rfc::TLS_EXT_ALPN);
    if !has_alpn {
        committed = true;
        return true;
    }

    var ac = core::cursor_from(alpn_data);
    let list_bytes, ok_l = ac.read_u16_prefixed();
    guard ok_l && ac.buf.len == 0 && list_bytes.len >= 2 else { return false; }

    var lc = core::cursor_from(list_bytes);
    let proto, ok_p = lc.read_u8_prefixed();
    guard ok_p && lc.buf.len == 0 && proto.len >= 1 && proto.len <= 255 else { return false; }
    guard alpn_csv_contains_proto(offered_alpn_csv, proto) && out_alpn.try_set(proto) else {
        return false;
    }
    committed = true;
    return true;
}

fn verify_crl_for_chain(
    crl_der:      const u8[:],
    chain_parsed: const tls::ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    now_unix:     i64 = 0,
) -> bool {
    let empty_store = tls::TrustAnchorStore { .. };
    return verify_crl_for_chain_with_store(crl_der, chain_parsed, chain_slices, now_unix, empty_store);
}

// Signs a TLS 1.3 CertificateVerify message using Ed25519 (`0x0807`), ECDSA P-256 (`0x0403` DER),
// or RSA-PSS-SHA256 (`0x0804`) according to the certificate SPKI OID (RFC 8446 Section 4.4.3).
fn sign_certificate_verify<B>(
    cert_der:     const u8[:],
    priv_seed:    const u8[32]&,
    cv_msg:       const u8[:],
    out_sig:      B&,
    rsa_key_slot: i32 = -1,
) -> u16, bool {
    out_sig.clear();
    let scheme = detect_cert_sig_scheme(cert_der);
    if scheme == rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        let raw_sig = core::ecdsa_p256_sign(priv_seed, cv_msg);
        var der_sig: u8[..72] = [];
        guard core::ecdsa_p256_encode_der_sig(raw_sig, der_sig) && out_sig.try_set(der_sig[..]) else {
            return 0, false;
        }
        return scheme, true;
    }
    if scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256 {
        let slot_i = rsa_key_slot as i64;
        guard slot_i >= 0 && slot_i < tls::g_tls_rsa_keys.len else { return 0, false; }
        let rkey .= tls::g_tls_rsa_keys[slot_i];
        guard rkey.in_use else { return 0, false; }
        var salt: u8[32] = [0; 32];
        defer core::secure_zeroize_32(salt);
        guard random_bytes_32_checked(salt) else { return 0, false; }
        var rsa_sig: u8[..512] = [];
        defer core::secure_zeroize_slice(rsa_sig[..]);
        guard core::rsa_pss_sha256_sign_blinded(
            rkey.n[..], rkey.d[..], rkey.e[..], salt[..], cv_msg, rsa_sig,
        ) && out_sig.try_set(rsa_sig[..]) else {
            return 0, false;
        }
        return scheme, true;
    }
    let ed_sig = core::ed25519_sign(priv_seed, cv_msg);
    guard out_sig.try_set(ed_sig[..]) else { return 0, false; }
    return rfc::SIG_SCHEME_ED25519, true;
}

fn validate_alpn_wire_list(list_bytes: const u8[:]) -> bool {
    var vlc = core::cursor_from(list_bytes);
    while vlc.buf.len > 0 {
        let p, ok_vp = vlc.read_u8_prefixed();
        guard ok_vp && p.len >= 1 && p.len <= 255 else { return false; }
    }
    return true;
}

fn alpn_wire_list_contains(list_bytes: const u8[:], target: const u8[:]) -> bool {
    var lc = core::cursor_from(list_bytes);
    while lc.buf.len > 0 {
        let cli_proto, _ = lc.read_u8_prefixed();
        if cli_proto == target {
            return true;
        }
    }
    return false;
}

fn find_preferred_server_alpn(list_bytes: const u8[:], server_alpn_csv: const u8[:]) -> const u8[:] {
    var tok = core::make_byte_tokenizer(server_alpn_csv, ',');
    while true {
        let srv_proto, has_tok = core::token_next(tok);
        if !has_tok { break; }
        if srv_proto.len >= 1 && srv_proto.len <= 255 && alpn_wire_list_contains(list_bytes, srv_proto) {
            return srv_proto;
        }
    }
    return "";
}

// Matches a client ALPN extension against server comma-separated ALPN preferences (RFC 7301 Section 3.2).
fn select_server_alpn_from_ext<B>(
    alpn_ext:        const u8[:],
    server_alpn_csv: const u8[:],
    out_alpn:        B&,
) -> bool {
    var committed = false;
    defer if !committed { out_alpn.clear(); };
    guard alpn_ext.len >= 3 else { return false; }
    var c = core::cursor_from(alpn_ext);
    let list_bytes, ok_l = c.read_u16_prefixed();
    guard ok_l && c.buf.len == 0 && list_bytes.len >= 2 else { return false; }
    guard validate_alpn_wire_list(list_bytes) else { return false; }
    out_alpn.clear();
    guard server_alpn_csv.len > 0 else {
        committed = true;
        return true;
    }

    let matched = find_preferred_server_alpn(list_bytes, server_alpn_csv);
    if matched.len > 0 {
        guard out_alpn.try_set(matched) else { return false; }
    }
    committed = true;
    return true;
}

// Negotiates a TLS 1.3 cipher suite from the client's offered cipher suite list or ClientHello (RFC 8446 §4.1.2).
//
// Example:
//   raw = [0x13, 0x02, 0x13, 0x01]
//   returns: cs = 0x1302, ok = true
fn select_cipher_suite(raw: const u8[:]) -> u16, bool {
    return select_cipher_suite_from_list(ch_cipher_suites_slice(raw));
}

// Builds a TLS 1.3 ServerHello wire payload echoing session ID and selected group share (RFC 8446 §4.1.3).
fn build_server_hello_payload_for_group<B>(
    server_random:   const u8[32]&,
    session_id:      const u8[:],
    selected_group:  u16,
    server_share:    const u8[:],
    out:             B&,
    psk_resumed:     bool = false,
    cipher_suite:    u16  = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
    selected_psk_id: u16  = 0,
) {
    out.clear();
    out.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    out.append(server_random[..]);
    out.push(session_id.len as u8);
    out.append(session_id);
    out.append_u16_be(cipher_suite);
    out.push(0);

    var ext_buf: u8[..512] = [];
    ext_buf.append_u16_be(rfc::TLS_EXT_SUPPORTED_VERSIONS);
    ext_buf.append_u16_be(2);
    ext_buf.append_u16_be(rfc::TLS_VERSION_1_3);

    encode_key_share_server_extension(ext_buf, selected_group, server_share);
    if psk_resumed {
        ext_buf.append_u16_be(rfc::TLS_EXT_PRE_SHARED_KEY);
        ext_buf.append_u16_be(2);
        ext_buf.append_u16_be(selected_psk_id);
    }
    out.append_u16_be(ext_buf.len as u16);
    out.append(ext_buf[..]);
}

// Builds a minimal TLS 1.3 ServerHello wire payload echoing session ID and offering X25519 share.
fn build_server_hello_payload<B>(
    server_random:   const u8[32]&,
    session_id:      const u8[:],
    server_pub:      const u8[32]&,
    out:             B&,
    psk_resumed:     bool = false,
    cipher_suite:    u16  = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
    selected_psk_id: u16  = 0,
) {
    build_server_hello_payload_for_group(
        server_random, session_id, rfc::GROUP_X25519, server_pub[..],
        out, psk_resumed, cipher_suite, selected_psk_id,
    );
}

// RFC 8446 Section 4.1.4: Hello Retry Request - Builds HRR payload with HRR_RANDOM and selected key_share group.
fn build_hrr_payload<B>(
    session_id:     const u8[:],
    cipher_suite:   u16,
    selected_group: u16,
    out:            B&,
) {
    out.clear();
    out.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    out.append(rfc::HRR_RANDOM[..]);
    out.push(session_id.len as u8);
    out.append(session_id);
    out.append_u16_be(cipher_suite);
    out.push(0);

    var ext_buf: u8[..64] = [];
    ext_buf.append_u16_be(rfc::TLS_EXT_SUPPORTED_VERSIONS);
    ext_buf.append_u16_be(2);
    ext_buf.append_u16_be(rfc::TLS_VERSION_1_3);
    ext_buf.append_u16_be(rfc::TLS_EXT_KEY_SHARE);
    ext_buf.append_u16_be(2);
    ext_buf.append_u16_be(selected_group);

    out.append_u16_be(ext_buf.len as u16);
    out.append(ext_buf[..]);
}

fn select_server_cert_comp_algo(ch_msg: const u8[:], server_algo: u16) -> u16 {
    guard server_algo != 0 && rfc::is_valid_compression_algorithm(server_algo) else { return 0; }
    var c = core::cursor_from(ch_msg);
    let hs_type, ok_t = c.read_u8();
    guard ok_t && hs_type == rfc::TLS_HS_CLIENT_HELLO else { return 0; }
    let body, ok_b = c.read_u24_prefixed();
    guard ok_b else { return 0; }

    var bc = core::cursor_from(body);
    let _, ok_v = bc.read_u16();
    let _, ok_r = bc.read_bytes(32);
    let _, ok_sid = bc.read_u8_prefixed();
    let _, ok_cs = bc.read_u16_prefixed();
    let _, ok_cm = bc.read_u8_prefixed();
    guard ok_v && ok_r && ok_sid && ok_cs && ok_cm else { return 0; }

    var entries: tls::ExtensionEntry[..32] = [];
    guard tls::parse_extensions_block(bc.buf, entries) else { return 0; }
    return select_server_cert_comp_algo_from_entries(entries, server_algo);
}

// RFC 8446 Section 4.4.2: Certificate - Encodes framed Certificate message containing leaf and intermediate chain.
fn encode_server_cert_chain_msg<B>(
    cert_der:        const u8[:],
    extra_certs_der: const u8[..4096][:],
    out_msg:         B&,
) -> bool {
    out_msg.clear();
    guard cert_der.len > 0 else { return false; }
    var cert_payload: u8[..20480] = [];
    guard encode_client_certificate_chain(cert_payload, "", cert_der, extra_certs_der) else {
        return false;
    }
    return frame_handshake_msg_4k(rfc::TLS_HS_CERTIFICATE, cert_payload[..], out_msg);
}

fn encode_server_cert_or_compressed_msg<B>(
    config:                    const tls::ServerHandshakeConfig&,
    negotiated_cert_comp_algo: u16,
    out_msg:                   B&,
) -> bool {
    out_msg.clear();
    guard config.cert_der.len > 0 else { return false; }

    let can_compress = negotiated_cert_comp_algo != 0 &&
        negotiated_cert_comp_algo == config.compressed_cert_algo &&
        config.compressed_cert_data.len > 0;
    if can_compress {
        var cert_payload: u8[..20480] = [];
        guard encode_client_certificate_chain(
            cert_payload, "", config.cert_der[..], config.extra_certs_der[..],
        ) else {
            return false;
        }
        var comp_payload: u8[..4096] = [];
        guard build_compressed_cert_payload(
            config.compressed_cert_algo,
            cert_payload.len,
            config.compressed_cert_data[..],
            comp_payload,
        ) else {
            return false;
        }
        return frame_handshake_msg_4k(rfc::TLS_HS_COMPRESSED_CERTIFICATE, comp_payload[..], out_msg);
    }

    return encode_server_cert_chain_msg(config.cert_der[..], config.extra_certs_der[..], out_msg);
}

fn generate_client_handshake_keys(
    enable_pq_hybrid: bool,
    out_random:       u8[32]&,
    out_x25519_priv:  u8[32]&,
    out_x25519_pub:   u8[32]&,
    out_pq_priv:      u8[2400]&,
    out_pq_pub:       u8[1184]&,
) -> bool {
    var committed = false;
    defer if !committed {
        core::secure_zeroize_32(out_random);
        core::secure_zeroize_32(out_x25519_priv);
        core::secure_zeroize_32(out_x25519_pub);
        core::secure_zeroize_slice(out_pq_priv[..]);
        core::secure_zeroize_slice(out_pq_pub[..]);
    };
    guard random_bytes_32_checked(out_random) && random_bytes_32_checked(out_x25519_priv) else {
        return false;
    }
    out_x25519_pub = core::x25519_base_scalarmult(out_x25519_priv);
    if enable_pq_hybrid {
        var pq_d: u8[32] = [0; 32];
        var pq_z: u8[32] = [0; 32];
        defer core::secure_zeroize_32(pq_d);
        defer core::secure_zeroize_32(pq_z);
        guard random_bytes_32_checked(pq_d) && random_bytes_32_checked(pq_z) else {
            return false;
        }
        var ek, dk = mlkem768_keygen(pq_d, pq_z);
        defer core::secure_zeroize_slice(dk[..]);
        out_pq_priv = dk;
        out_pq_pub = ek;
    }
    committed = true;
    return true;
}
