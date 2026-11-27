// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 ClientHello, PSK binder, ALPN, cipher-suite, and keylog codec helpers.
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
import .ocsp;
import .crl;
import .ticket;
import .ticket_internal;
import .session_internal;
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .cert_compression;
import .ech;
import .pki_sig_internal;
import .pki_x509_ext_internal;
import .pki_nc_san_internal;
import .pki_ocsp_internal;
import .pki_crl_internal;
import net.tcp;
import net.transport;
import .session_internal;
import .handshake_wire_internal;
import .session_wire_internal;

// Encodes an ALPN extension (RFC 7301 §3.1) supporting single or comma-separated protocol names (e.g. "h2,http/1.1").
fn encode_alpn_extension_from_csv<B>(out: B&, alpn_csv: const u8[:]) {
    guard alpn_csv.len > 0 && alpn_csv.len <= 255 else { return; }
    var proto_list: u8[..256] = [];
    var cursor:     i64       = 0;
    while cursor < alpn_csv.len {
        var comma_idx = cursor;
        while comma_idx < alpn_csv.len && alpn_csv[comma_idx] != ',' {
            comma_idx = core::add_sat_i64(comma_idx, 1);
        }
        let item = alpn_csv[cursor..comma_idx];
        if item.len > 0 && item.len <= 255 {
            proto_list.push(item.len as u8);
            proto_list.append(item);
        }
        cursor = core::add_sat_i64(comma_idx, 1);
    }
    guard proto_list.len >= 2 else { return; }
    out.append_u16_be(rfc::TLS_EXT_ALPN);
    out.append_u16_be(core::add_sat_i64(proto_list.len, 2) as u16);
    out.append_u16_be(proto_list.len as u16);
    out.append(proto_list[..]);
}

// Computes a TLS 1.3 PSK binder tag (SHA-256 or SHA-384) over a truncated ClientHello (RFC 8446 Section 4.2.11.2).
fn compute_tls13_psk_binder_for_hash(
    hash_id:      u8,
    binder_key:   const u8[:],
    truncated_ch: const u8[:],
    out_binder:   u8[..48]&,
) -> bool {
    out_binder.clear();
    if hash_id == tls_internal::HASH_SHA256 {
        guard binder_key.len >= 32 else { return false; }
        let ch_hash = core::sha256(truncated_ch);
        var mac: u8[32] = [0; 32];
        defer core::secure_zeroize_32(mac);
        guard tls_internal::ks_compute_finished_verify_data(
            tls_internal::HASH_SHA256, 32, binder_key[..32], ch_hash[..], mac[..],
        ) else { return false; }
        return out_binder.try_set(mac[..]);
    }
    if hash_id == tls_internal::HASH_SHA384 {
        guard binder_key.len >= 48 else { return false; }
        let ch_hash = core::sha384(truncated_ch);
        var mac: u8[48] = [0; 48];
        defer core::secure_zeroize_48(mac);
        guard tls_internal::ks_compute_finished_verify_data(
            tls_internal::HASH_SHA384, 48, binder_key[..48], ch_hash[..], mac[..],
        ) else { return false; }
        return out_binder.try_set(mac[..]);
    }
    return false;
}

// Encodes psk_key_exchange_modes (RFC 8446 §4.2.9) and pre_shared_key (RFC 8446 §4.2.11) extensions.
fn encode_psk_client_extensions<B>(
    out:         B&,
    psk_ticket:  const u8[:],
    psk_age_add: u32,
    binder_len:  u8 = 32,
) {
    // RFC 8446 Section 4.2.9: Pre-Shared Key Exchange Modes - Advertise psk_dhe_ke (1) so servers may issue tickets.
    out.append_u16_be(rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES);
    out.append_u16_be(2);
    out.push(1);
    out.push(1);
    guard psk_ticket.len > 0 && psk_ticket.len <= 1536 && (binder_len == 32 || binder_len == 48) else { return; }

    let id_entry_len = core::add_sat_i64(psk_ticket.len, 6) as u16;
    let binders_entry_len: u16 = if binder_len == 48 { 49 } else { 33 };
    let psk_ext_len = core::add_sat_i64(id_entry_len as i64, core::add_sat_i64(binders_entry_len as i64, 4)) as u16;
    out.append_u16_be(rfc::TLS_EXT_PRE_SHARED_KEY);
    out.append_u16_be(psk_ext_len);
    out.append_u16_be(id_entry_len);
    out.append_u16_be(psk_ticket.len as u16);
    out.append(psk_ticket);
    out.append_u32_be(psk_age_add);
    out.append_u16_be(binders_entry_len);
    out.push(binder_len);
    for i in (binder_len as i64) { out.push(0); }
}

inline fn alpn_csv_contains_proto(alpn_csv: const u8[:], target: const u8[:]) -> bool {
    if alpn_csv == "*" {
        return true;
    }
    guard alpn_csv.len > 0 && target.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(alpn_csv, ',');
    while true {
        let item, ok = core::token_next(tok);
        if !ok { break; }
        if item == target { return true; }
    }
    return false;
}

fn validate_ee_solicited_extensions(
    entries:          const tls::ExtensionEntry[..64]&,
    offered_alpn_csv: const u8[:],
    sni_state:        tls::SniOfferState,
    allow_ech_retry:  bool,
    quic_mode:        tls::QuicExtensionMode = tls::QuicExtensionMode.Tcp,
) -> bool {
    for &e in entries {
        if e.ext_type == rfc::TLS_EXT_SERVER_NAME {
            guard sni_state == tls::SniOfferState.Offered && e.data.len == 0 else { return false; }
        } else if e.ext_type == rfc::TLS_EXT_SUPPORTED_GROUPS {
            // RFC 8446 Section 4.2.7: Supported Groups - Server may echo NamedGroupList in EncryptedExtensions.
            guard e.data.len >= 4 else { return false; }
            let list_len = core::read_be_u16(e.data, 0) as i64;
            guard list_len >= 2 && (list_len & 1) == 0 && core::add_sat_i64(list_len, 2) == e.data.len else {
                return false;
            }
        } else if e.ext_type == rfc::TLS_EXT_ALPN {
            guard offered_alpn_csv.len > 0 else { return false; }
        } else if e.ext_type == rfc::EXT_ENCRYPTED_CLIENT_HELLO {
            guard allow_ech_retry && e.data.len >= 2 else { return false; }
        } else if e.ext_type == rfc::TLS_EXT_QUIC_TRANSPORT_PARAMETERS {
            // RFC 9001 Section 8.2: QUIC Transport Parameters Extension - Permit 0x0039 only on QUIC handshakes.
            guard quic_mode == tls::QuicExtensionMode.Quic && e.data.len <= 2048 else {
                return false;
            }
        } else {
            return false;
        }
    }
    return true;
}

// Detects the TLS 1.3 SignatureScheme (Ed25519, ECDSA P-256, or RSA-PSS-SHA256)
// from the leaf certificate's SubjectPublicKeyInfo OID (RFC 8446 Section 4.4.3).
fn detect_cert_sig_scheme(cert_der: const u8[:]) -> u16 {
    var cert = tls::ParsedCert { .. };
    guard cert_der.len > 0 && tls::parse_x509_certificate(cert_der, cert) else { return 0; }
    let spki_oid = tls::span_slice(cert_der, cert.spki_alg_oid);
    if spki_oid == rfc::OID_SECP256R1[..] {
        return rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256;
    }
    if spki_oid == rfc::OID_RSA_ENCRYPTION[..] {
        return rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256;
    }
    if spki_oid == rfc::OID_ED25519[..] {
        return rfc::SIG_SCHEME_ED25519;
    }
    return 0;
}

inline fn is_client_offered_tls13_suite(cs: u16) -> bool {
    return cs == rfc::TLS_CIPHER_AES_128_GCM_SHA256 ||
        cs == rfc::TLS_CIPHER_AES_256_GCM_SHA384 ||
        cs == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256;
}

// RFC 8446 Section 4.1.3: Server Hello - Verify legacy_session_id_echo, offered cipher suite, and key_share.
fn validate_live_client_sh(sh: const tls::ParsedServerHello&, client_random: const u8[32]&) -> bool {
    guard sh.session_id_echo.len == 32 &&
        core::ct_eq_bytes(sh.session_id_echo[..], client_random[..]) &&
        is_client_offered_tls13_suite(sh.cipher_suite) else {
        return false;
    }
    return sh.is_hrr || sh.server_share.len > 0;
}

// RFC 9001 Section 8.4: Prohibit TLS Middlebox Compatibility Mode - Verify 0-byte legacy_session_id_echo.
fn validate_quic_client_sh(sh: const tls::ParsedServerHello&) -> bool {
    guard sh.session_id_echo.len == 0 &&
        !sh.psk_resumed &&
        !sh.has_ech_ext &&
        is_client_offered_tls13_suite(sh.cipher_suite) else {
        return false;
    }
    return sh.is_hrr || sh.server_share.len > 0;
}

fn frame_handshake_msg_4k<B>(msg_type: u8, payload: const u8[:], out_msg: B&) -> bool {
    out_msg.clear();
    guard payload.len >= 0 && payload.len <= (rfc::MAX_HANDSHAKE_MSG_LEN as i64) else {
        return false;
    }
    let payload_u32 = (payload.len & 0xFFFFFF) as u32;
    let total_len = core::add_sat_i64(payload.len, 4);
    guard total_len <= out_msg.cap else { return false; }
    var hdr: u8[4] = [0; 4];
    guard encode_handshake_header(msg_type, payload_u32, hdr) else { return false; }
    out_msg.append(hdr[..]);
    out_msg.append(payload);
    return true;
}

fn try_match_single_psk_binder(
    ticket_id:           const u8[:],
    binder_slice:        const u8[:],
    ch_msg:              const u8[:],
    binders_len:         u16,
    selected_cs:         u16,
    out_psk:             u8[..48]&,
    require_client_cert: bool                  = false,
    client_sni:          const u8[:]           = "",
    has_hrr_prefix:      bool                  = false,
    hrr_prefix_tr:       const tls::Transcript = tls::Transcript { .. },
) -> bool, bool {
    out_psk.clear();
    var full_psk: u8[..48] = [];
    defer core::secure_zeroize_slice(full_psk[..]);
    var cs: u16 = 0;
    if !lookup_server_ticket_by_identity(ticket_id, require_client_cert, full_psk, cs, 0, client_sni) ||
        (full_psk.len != 32 && full_psk.len != 48) {
        return false, true;
    }
    let suite = if cs != 0 { cs } else { rfc::TLS_CIPHER_AES_128_GCM_SHA256 };
    if selected_cs != 0 && rfc::tls13_cipher_suite_hash_len(suite) != rfc::tls13_cipher_suite_hash_len(selected_cs) {
        return false, true;
    }
    var ks_early, ok_kse = tls_internal::ks_init(suite);
    defer tls_internal::ks_zeroize(ks_early);
    guard ok_kse && tls_internal::ks_init_early_secret(ks_early, full_psk[..]) else { return false, false; }
    let hlen = ks_early.hash_len as i64;
    guard binder_slice.len == hlen else { return false, false; }

    let trunc_ch, ok_tr = tls_internal::truncate_client_hello_for_binder(ch_msg, binders_len);
    guard ok_tr else { return false, false; }
    var ok_binder = false;
    if has_hrr_prefix {
        var tr_copy = hrr_prefix_tr;
        transcript_update(tr_copy, trunc_ch);
        var tr_hash: u8[..48] = [];
        transcript_current_hash(tr_copy, ks_early.hash_id, tr_hash);
        ok_binder = tls_internal::verify_psk_binder_hash(
            ks_early.hash_id, ks_early.hash_len, ks_early.binder_key[..hlen], tr_hash[..], binder_slice,
        );
    } else {
        ok_binder = tls_internal::verify_psk_binder(
            ks_early.hash_id, ks_early.hash_len, ks_early.binder_key[..hlen], trunc_ch, binder_slice,
        );
    }
    guard ok_binder else { return false, false; }
    guard out_psk.try_set(full_psk[..]) else { return false, false; }
    return true, true;
}

// Reads one PskIdentity and matching PskBinderEntry from OfferedPsks cursors (RFC 8446 Section 4.2.11).
//
// Example:
//   ic = [0x00, 0x04, 'T', 'K', 'T', '1', 0, 0, 0, 0], bc = [0x20, ...32 bytes...]
//   returns: ticket_id = "TKT1", binder_slice = [32 bytes], ok = true
inline fn read_psk_identity_and_binder(
    ic: core::ByteCursor&,
    bc: core::ByteCursor&,
) -> const u8[:], const u8[:], bool {
    let ticket_id, ok_t = ic.read_u16_prefixed();
    let _, ok_age = ic.read_u32();
    let binder_slice, ok_bs = bc.read_u8_prefixed();
    guard ok_t && ticket_id.len > 0 && ok_age && ok_bs else { return "", "", false; }
    guard binder_slice.len == 32 || binder_slice.len == 48 else { return "", "", false; }
    return ticket_id, binder_slice, true;
}

// Splits a TLS 1.3 pre_shared_key ClientHello extension into identities and binders slices.
//
// Example:
//   psk_ext = <2B ids_len><ids...><2B binders_len><binders...>
//   returns: ids, binders, ok = true
inline fn parse_psk_extension_lists(psk_ext: const u8[:]) -> const u8[:], const u8[:], bool {
    var c = core::cursor_from(psk_ext);
    let ids_bytes, ok_ids = c.read_u16_prefixed();
    let binders_bytes, ok_b = c.read_u16_prefixed();
    let ok = ok_ids && ids_bytes.len >= 7 && ok_b && c.buf.len == 0 && binders_bytes.len >= 33;
    return ids_bytes, binders_bytes, ok;
}

fn eval_client_hello_psk_binders(
    ch_msg:              const u8[:],
    psk_ext:             const u8[:],
    selected_cs:         u16,
    out_psk:             u8[..48]&,
    out_selected_id:     u16&,
    require_client_cert: bool                  = false,
    client_sni:          const u8[:]           = "",
    has_hrr_prefix:      bool                  = false,
    hrr_prefix_tr:       const tls::Transcript = tls::Transcript { .. },
) -> bool, bool {
    core::secure_zeroize_slice(out_psk[..]);
    out_psk.clear();
    out_selected_id = 0;

    let ids_bytes, binders_bytes, ok_lists = parse_psk_extension_lists(psk_ext);
    guard ok_lists else { return false, false; }

    var ic = core::cursor_from(ids_bytes);
    var bc = core::cursor_from(binders_bytes);
    var matched_psk: u8[..48] = [];
    defer core::secure_zeroize_slice(matched_psk[..]);
    var matched = false;
    var cur_idx:   u16 = 0;
    var chosen_id: u16 = 0;

    while ic.buf.len > 0 && bc.buf.len > 0 {
        let ticket_id, binder_slice, ok_entry = read_psk_identity_and_binder(ic, bc);
        guard ok_entry && cur_idx < 0xFFFF else { return false, false; }
        if !matched {
            let entry_matched, entry_ok = try_match_single_psk_binder(
                ticket_id, binder_slice, ch_msg, binders_bytes.len as u16, selected_cs,
                matched_psk, require_client_cert, client_sni, has_hrr_prefix, hrr_prefix_tr,
            );
            guard entry_ok else { return false, false; }
            if entry_matched {
                matched = true;
                chosen_id = cur_idx;
            }
        }
        cur_idx = core::add_sat_u64(cur_idx, 1) as u16;
    }
    guard ic.buf.len == 0 && bc.buf.len == 0 else { return false, false; }
    if !matched {
        return false, true;
    }
    guard out_psk.try_set(matched_psk[..]) else { return false, false; }
    out_selected_id = chosen_id;
    return true, true;
}

fn has_valid_psk_dhe_ke_mode(modes_ext: const u8[:]) -> bool {
    var c = core::cursor_from(modes_ext);
    let modes, ok = c.read_u8_prefixed();
    guard ok && c.buf.len == 0 && modes.len >= 1 else { return false; }
    var has_dhe = false;
    for m in modes {
        guard m == 0 || m == 1 else { return false; }
        if m == 1 { has_dhe = true; }
    }
    return has_dhe;
}

fn eval_client_hello_psk_entry(
    entries:             const tls::ExtensionEntry[..64]&,
    payload:             const u8[:],
    psk_ext:             const u8[:],
    selected_cs:         u16,
    out_psk:             u8[..48]&,
    out_selected_id:     u16&,
    require_client_cert: bool                  = false,
    client_sni:          const u8[:]           = "",
    has_hrr_prefix:      bool                  = false,
    hrr_prefix_tr:       const tls::Transcript = tls::Transcript { .. },
) -> bool, bool {
    let last_idx = core::sub_sat_i64(entries.len, 1);
    guard entries.len > 0 && last_idx >= 0 && last_idx < entries.len else { return false, false; }
    guard entries[last_idx].ext_type == rfc::TLS_EXT_PRE_SHARED_KEY else { return false, false; }
    let modes_ext, has_modes = tls::find_extension(entries, rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES);
    guard has_modes && has_valid_psk_dhe_ke_mode(modes_ext) else { return false, false; }
    return eval_client_hello_psk_binders(
        payload, psk_ext, selected_cs, out_psk, out_selected_id,
        require_client_cert, client_sni, has_hrr_prefix, hrr_prefix_tr,
    );
}

inline fn select_hrr_group_from_ext(grp_ext: const u8[:]) -> u16, bool {
    var gc = core::cursor_from(grp_ext);
    let grp_bytes, ok_gb = gc.read_u16_prefixed();
    guard ok_gb && gc.buf.len == 0 else { return 0, false; }
    if group_bytes_contains(grp_bytes, rfc::GROUP_X25519) {
        return rfc::GROUP_X25519, true;
    }
    if group_bytes_contains(grp_bytes, rfc::GROUP_SECP256R1) {
        return rfc::GROUP_SECP256R1, true;
    }
    return 0, false;
}

// Extracts client key_share (preferring X25519, falling back to secp256r1) or selects
// an HRR group from `supported_groups` when `allow_hrr` is true (RFC 8446 Section 4.1.4).
//
// Example:
//   grp_ext = [0x00, 0x02, 0x00, 0x17], shares = [0x00, 0x17, 0x00, 0x41, 0x04, ...], allow_hrr = false
//   returns: selected_group = 0x0017, needs_hrr = false, ok = true
fn extract_server_group_and_share(
    grp_ext:   const u8[:],
    shares:    const u8[:],
    allow_hrr: bool,
    out_share: u8[..65]&,
) -> u16, bool, bool {
    out_share.clear();
    var x_kex = shares[..0];
    var p_kex = shares[..0];
    var has_x = false;
    var has_p256 = false;
    var sc = core::cursor_from(shares);
    while sc.buf.len > 0 {
        let grp, ok_g = sc.read_u16();
        let kex, ok_k = sc.read_u16_prefixed();
        guard ok_g && ok_k else { return 0, false, false; }
        if grp == rfc::GROUP_X25519 {
            guard kex.len == 32 else { return 0, false, false; }
            x_kex = kex;
            has_x = true;
        } else if grp == rfc::GROUP_SECP256R1 {
            let _, ok_pt = core::decode_p256_public_key(kex);
            guard ok_pt else { return 0, false, false; }
            p_kex = kex;
            has_p256 = true;
        }
    }
    if has_x {
        return rfc::GROUP_X25519, false, out_share.try_set(x_kex);
    }
    if has_p256 {
        return rfc::GROUP_SECP256R1, false, out_share.try_set(p_kex);
    }
    guard allow_hrr else { return 0, false, false; }
    let hrr_grp, ok_hrr = select_hrr_group_from_ext(grp_ext);
    guard ok_hrr else { return 0, false, false; }
    return hrr_grp, true, true;
}

fn ch_cipher_suites_slice(raw: const u8[:]) -> const u8[:] {
    guard raw.len > 38 && raw[0] == rfc::TLS_HS_CLIENT_HELLO else { return raw; }
    var c = core::cursor_from(raw);
    let _, _ = c.read_u8();
    let body, ok_b = c.read_u24_prefixed();
    guard ok_b && c.buf.len == 0 else { return raw; }
    var bc = core::cursor_from(body);
    let ver, ok_v = bc.read_u16();
    let _, ok_r = bc.read_bytes(32);
    let sid, ok_sid = bc.read_u8_prefixed();
    let cs_bytes, ok_cs = bc.read_u16_prefixed();
    let comp, ok_cm = bc.read_u8_prefixed();
    let _, ok_ext = bc.read_u16_prefixed();
    guard ok_v && ver == rfc::TLS_LEGACY_VERSION_1_2 && ok_r && ok_sid && sid.len <= 32 &&
        ok_cs && ok_cm && comp.len >= 1 && ok_ext && bc.buf.len == 0 else {
        return raw;
    }
    return cs_bytes;
}

fn select_cipher_suite_from_list(cs_bytes: const u8[:]) -> u16, bool {
    guard cs_bytes.len >= 2 && (cs_bytes.len & 1) == 0 else { return 0, false; }
    var c = core::cursor_from(cs_bytes);
    while c.buf.len >= 2 {
        let cs, ok = c.read_u16();
        guard ok else { return 0, false; }
        if is_client_offered_tls13_suite(cs) {
            return cs, true;
        }
    }
    return 0, false;
}

fn has_forbidden_extension(entries: const tls::ExtensionEntry[..64]&) -> bool {
    for &e in entries {
        if rfc::is_forbidden_ch_extension(e.ext_type) { return true; }
    }
    return false;
}

// RFC 8446 Section 4.2.3: Signature Algorithms - Validates SignatureSchemeList syntax and required server scheme.
fn validate_ch_sig_algorithms(sig_ext: const u8[:], required_scheme: u16) -> bool {
    var c = core::cursor_from(sig_ext);
    let list_bytes, ok = c.read_u16_prefixed();
    guard ok && c.buf.len == 0 && list_bytes.len >= 2 && (list_bytes.len & 1) == 0 else { return false; }
    var lc = core::cursor_from(list_bytes);
    var has_supported = false;
    while lc.buf.len >= 2 {
        let scheme, ok_s = lc.read_u16();
        guard ok_s else { return false; }
        if required_scheme != 0 {
            if scheme == required_scheme { has_supported = true; }
        } else if scheme == rfc::SIG_SCHEME_ED25519 ||
            scheme == rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256 ||
            scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256 {
            has_supported = true;
        }
    }
    return has_supported;
}

inline fn group_bytes_contains(grp_bytes: const u8[:], target: u16) -> bool {
    var gc = core::cursor_from(grp_bytes);
    while gc.buf.len >= 2 {
        let g, ok = gc.read_u16();
        if ok && g == target { return true; }
    }
    return false;
}

// RFC 8446 Section 4.2.8: Key Share - Every non-GREASE KeyShareEntry group must appear in supported_groups in the same order.
// RFC 8701 Section 3.3: ClientHello - Servers MUST ignore GREASE values when offered in a ClientHello.
fn validate_ch_groups_and_shares(grp_ext: const u8[:], shares: const u8[:]) -> bool {
    var c = core::cursor_from(grp_ext);
    let grp_bytes, ok = c.read_u16_prefixed();
    guard ok && c.buf.len == 0 && grp_bytes.len >= 2 && (grp_bytes.len & 1) == 0 else { return false; }
    let has_supported = group_bytes_contains(grp_bytes, rfc::GROUP_X25519) ||
        group_bytes_contains(grp_bytes, rfc::GROUP_SECP256R1);
    guard has_supported else { return false; }

    var sc = core::cursor_from(shares);
    var gc = core::cursor_from(grp_bytes);
    while sc.buf.len > 0 {
        let ks_grp, ok_g = sc.read_u16();
        let _, ok_k = sc.read_u16_prefixed();
        guard ok_g && ok_k else { return false; }
        if is_tls_grease_u16(ks_grp) {
            continue;
        }
        var matched = false;
        while gc.buf.len >= 2 && !matched {
            let g, ok_grp = gc.read_u16();
            matched = ok_grp && g == ks_grp;
        }
        guard matched else { return false; }
    }
    return true;
}

// Reads and validates ClientHello legacy version, random, session_id, cipher_suites, and compression_methods.
//
// Example:
//   bc = [0x03, 0x03, ...32B random..., 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]
//   returns: cs_bytes = [0x13, 0x01], ok = true
fn decode_ch_legacy_preamble(bc: core::ByteCursor&, out_sid: u8[..32]&) -> const u8[:], bool {
    out_sid.clear();
    let ver, ok_v = bc.read_u16();
    let _, ok_r = bc.read_bytes(32);
    let sid, ok_sid = bc.read_u8_prefixed();
    let cs_bytes, ok_cs = bc.read_u16_prefixed();
    let comp_bytes, ok_cm = bc.read_u8_prefixed();
    guard ok_v && ver == rfc::TLS_LEGACY_VERSION_1_2 && ok_r else { return "", false; }
    guard ok_cs && ok_cm && comp_bytes.len == 1 && comp_bytes[0] == 0 else { return "", false; }
    guard ok_sid && sid.len <= 32 && out_sid.try_set(sid) else { return "", false; }
    return cs_bytes, true;
}

// Decodes ClientHello handshake framing, legacy preamble, selected cipher suite, and extension table.
//
// Example:
//   payload = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, ...0x13, 0x01...]
//   returns: sel_cs = 0x1301, ok = true
fn decode_ch_server_preamble(
    payload:     const u8[:],
    out_sid:     u8[..32]&,
    out_entries: tls::ExtensionEntry[..64]&,
) -> u16, bool {
    out_sid.clear();
    out_entries.clear();
    var committed = false;
    defer if !committed {
        out_sid.clear();
        out_entries.clear();
    };
    var c = core::cursor_from(payload);
    let hs_type, ok_t = c.read_u8();
    let body, ok_b = c.read_u24_prefixed();
    guard ok_t && hs_type == rfc::TLS_HS_CLIENT_HELLO && ok_b && c.buf.len == 0 else {
        return 0, false;
    }
    var bc = core::cursor_from(body);
    let cs_bytes, ok_leg = decode_ch_legacy_preamble(bc, out_sid);
    guard ok_leg else { return 0, false; }
    let sel_cs, ok_sel = select_cipher_suite_from_list(cs_bytes);
    guard ok_sel && tls::parse_extensions_block(bc.buf, out_entries) && !has_forbidden_extension(out_entries) else {
        return 0, false;
    }
    committed = true;
    return sel_cs, true;
}

// Validates mandatory TLS 1.3 ClientHello extensions and extracts key_share or HRR target group.
//
// Example:
//   entries = [supported_versions, signature_algorithms, supported_groups, key_share]
//   returns: sig_ext, ok = true, out_group = 0x001D, out_needs_hrr = false
fn extract_ch_mandatory_exts(
    entries:       const tls::ExtensionEntry[..64]&,
    allow_hrr:     bool,
    out_group:     u16&,
    out_needs_hrr: bool&,
    out_share:     u8[..65]&,
) -> const u8[:], bool {
    out_group = 0;
    out_needs_hrr = false;
    out_share.clear();
    let sv_ext, has_sv = tls::find_extension(entries, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    guard has_sv else { return "", false; }
    let supports_13, ok_sv = parse_client_supported_versions(sv_ext);
    guard ok_sv && supports_13 else { return "", false; }

    let sig_ext, has_sig = tls::find_extension(entries, rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    guard has_sig && validate_ch_sig_algorithms(sig_ext, 0) else { return "", false; }

    let grp_ext, has_grp = tls::find_extension(entries, rfc::TLS_EXT_SUPPORTED_GROUPS);
    let ks_data, has_ks = tls::find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_grp && has_ks else { return "", false; }
    var shares: u8[..4096] = [];
    guard parse_key_share_client_extension(ks_data, shares, allow_hrr) &&
        validate_ch_groups_and_shares(grp_ext, shares[..]) else {
        return "", false;
    }
    let sel_grp, needs_hrr, ok_ks = extract_server_group_and_share(
        grp_ext, shares[..], allow_hrr, out_share,
    );
    guard ok_ks else { return "", false; }
    out_group = sel_grp;
    out_needs_hrr = needs_hrr;
    return sig_ext, true;
}

fn select_server_cert_comp_algo_from_entries(
    entries:     const tls::ExtensionEntry[..64]&,
    server_algo: u16,
) -> u16 {
    guard server_algo != 0 && rfc::is_valid_compression_algorithm(server_algo) else { return 0; }
    let comp_ext, has_comp = tls::find_extension(entries, rfc::TLS_EXT_COMPRESS_CERTIFICATE);
    guard has_comp else { return 0; }
    var algos: u16[..127] = [];
    guard parse_compress_certificate_ext(comp_ext, algos) else { return 0; }
    if algos.contains(server_algo) {
        return server_algo;
    }
    return 0;
}

fn build_compressed_cert_payload(
    algo:             u16,
    uncompressed_len: i64,
    compressed_data:  const u8[:],
    out_payload:      u8[..4096]&,
) -> bool {
    let uncomp_u32 = (uncompressed_len & 0xFFFFFF) as u32;
    guard uncompressed_len > 0 && uncompressed_len <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else {
        return false;
    }
    var comp_msg = tls_internal::CompressedCertificate {
        algorithm:                      algo,
        uncompressed_length:            uncomp_u32,
        compressed_certificate_message: compressed_data,
    };
    return tls_internal::encode_compressed_certificate(comp_msg, out_payload);
}

// Extracts the 32-byte ClientHello.random field from a framed ClientHello handshake message (RFC 8446 Section 4.1.2).
//
// Example:
//   ch_msg = [0x01, 0x00, 0x00, 0x22, 0x03, 0x03, ...32 random bytes...]
//   returns: true, out_random = [32 random bytes]
fn extract_ch_client_random(ch_msg: const u8[:], out_random: u8[32]&) -> bool {
    core::secure_zeroize_32(out_random);
    guard ch_msg.len >= 38 && ch_msg[0] == rfc::TLS_HS_CLIENT_HELLO else { return false; }
    core::ct_copy_bytes(out_random[..], ch_msg[6..38]);
    return true;
}

// Formats one NSS Key Log Format line (`<LABEL> <client_random_hex> <secret_hex>\n`) into `out`.
fn append_keylog_secret_line(
    out:           u8[..1024]&,
    label:         const u8[:],
    client_random: const u8[32]&,
    secret:        const u8[:],
) -> bool {
    let saved = out.len;
    var committed = false;
    defer if !committed {
        if out.len > saved {
            core::secure_zeroize_slice(out[saved..out.len]);
        }
        out.resize(saved);
    };
    guard label.len > 0 && (secret.len == 32 || secret.len == 48) else { return false; }
    let hex_secret_len = core::add_sat_i64(secret.len, secret.len);
    let line_len = core::add_sat_i64(core::add_sat_i64(label.len, 67), hex_secret_len);
    guard core::sub_sat_i64(out.cap, out.len) >= line_len else { return false; }
    guard out.try_append(label) && out.try_push(' ') else { return false; }
    for b in client_random {
        core::format_u8_hex(b, out, false);
    }
    guard out.try_push(' ') else { return false; }
    for b in secret {
        core::format_u8_hex(b, out, false);
    }
    guard out.try_push('\n') else { return false; }
    committed = true;
    return true;
}

// Appends TLS 1.3 handshake traffic secrets in NSS Key Log Format to `keylog_path`.
// No-op when `keylog_path` is empty.
fn emit_tls13_hs_keylog(
    keylog_path:   const u8[:],
    client_random: const u8[32]&,
    ks:            const KeySchedule&,
) {
    guard keylog_path.len > 0 else { return; }
    let hlen = ks.hash_len as i64;
    guard hlen == 32 || hlen == 48 else { return; }
    var buf: u8[..1024] = [];
    defer core::secure_zeroize_slice(buf[..]);
    guard append_keylog_secret_line(
        buf, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, ks.client_hs_traffic[..hlen],
    ) && append_keylog_secret_line(
        buf, "SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, ks.server_hs_traffic[..hlen],
    ) else { return; }
    let _ = append_file(keylog_path, buf[..]);
}

// Appends TLS 1.3 application traffic and exporter secrets in NSS Key Log Format to `keylog_path`.
// No-op when `keylog_path` is empty.
fn emit_tls13_app_keylog(
    keylog_path:   const u8[:],
    client_random: const u8[32]&,
    ks:            const KeySchedule&,
) {
    guard keylog_path.len > 0 else { return; }
    let hlen = ks.hash_len as i64;
    guard hlen == 32 || hlen == 48 else { return; }
    var buf: u8[..1024] = [];
    defer core::secure_zeroize_slice(buf[..]);
    guard append_keylog_secret_line(
        buf, "CLIENT_TRAFFIC_SECRET_0", client_random, ks.client_ap_traffic[..hlen],
    ) && append_keylog_secret_line(
        buf, "SERVER_TRAFFIC_SECRET_0", client_random, ks.server_ap_traffic[..hlen],
    ) && append_keylog_secret_line(
        buf, "EXPORTER_SECRET", client_random, ks.exporter_secret[..hlen],
    ) else { return; }
    let _ = append_file(keylog_path, buf[..]);
}
