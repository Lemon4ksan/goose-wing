// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QUIC packet protection key derivation, AEAD, header protection,
// and coalesced packet decryption helpers (RFC 9001, RFC 9369).
namespace quic_internal;

import std;
import core;
import .packet;
import .packet_internal;
import .AckFrame;
import .bbr;
import .frames;
import .stream;
import .flow_control;
import .migration;
import .connection;
import .conn_internal;
import tls.record;
import tls.key_schedule;

// Derives AEAD key, IV, and Header Protection key from `secret` and installs them into `space`
// (RFC 9001 Section 5.1, RFC 9369 Section 3.3.2).
fn quic_derive_and_install_keys(
    space:           quic::PnSpaceState&,
    secret:          const u8[:],
    cipher_suite:    u16,
    version:         u32,
    keep_app_secret: bool,
) -> bool {
    let prefix = rfc::quic_hkdf_label_prefix(version);
    guard prefix.len > 0 else { return false; }

    let is_sha384 = cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384;
    let hash_id = if is_sha384 { tls_internal::HASH_SHA384 } else { tls_internal::HASH_SHA256 };
    let hash_len: i64 = if is_sha384 { 48 } else { 32 };
    let key_len:  u16 = if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 { 16 } else { 32 };
    guard secret.len >= hash_len else { return false; }

    let sec = secret[..hash_len];
    var lbl_key: u8[..16] = [];
    lbl_key.append(prefix);
    lbl_key.append("key");
    var lbl_iv: u8[..16] = [];
    lbl_iv.append(prefix);
    lbl_iv.append("iv");

    var aead_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(aead_key);
    var aead_iv: u8[12] = [0; 12];
    var hp_key:  u8[32] = [0; 32];
    defer core::secure_zeroize_32(hp_key);

    let klen_i = key_len as i64;
    guard tls_internal::hkdf_expand_label(hash_id, sec, lbl_key[..], [], key_len, aead_key[..klen_i])
        && tls_internal::hkdf_expand_label(hash_id, sec, lbl_iv[..], [], 12, aead_iv[..])
        && tls_internal::ks_derive_quic_hp_key(hash_id, sec, key_len, hp_key[..klen_i], version) else {
        return false;
    }
    if keep_app_secret {
        return quic::install_keys_with_secret(
            space, hp_key[..klen_i], aead_key[..klen_i], aead_iv[..], sec, cipher_suite,
        );
    }
    return quic::install_keys(space, hp_key[..klen_i], aead_key[..klen_i], aead_iv[..], cipher_suite);
}

// Derives QUIC Initial encryption keys and header protection keys for client and server
// from the initial Destination Connection ID (RFC 9001 Section 5.2, RFC 9369 Section 3.3).
fn quic_derive_initial_space_keys(
    dcid:     const u8[:],
    version:  u32,
    role:     quic::QuicRole,
    rx_space: quic::PnSpaceState&,
    tx_space: quic::PnSpaceState&,
) -> bool {
    let salt = rfc::quic_initial_salt(version);
    guard salt.len == 20 else { return false; }

    var initial_secret = core::hkdf_extract(salt, dcid);
    defer core::secure_zeroize_32(initial_secret);
    var client_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_secret);
    var server_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_secret);
    let sha256 = tls_internal::HASH_SHA256;
    guard tls_internal::hkdf_expand_label(sha256, initial_secret[..], "client in", [], 32, client_secret[..])
        && tls_internal::hkdf_expand_label(sha256, initial_secret[..], "server in", [], 32, server_secret[..]) else {
        return false;
    }

    if role == quic::QuicRole.Client {
        return quic_derive_and_install_keys(tx_space, client_secret[..], 0x1301, version, false)
            && quic_derive_and_install_keys(rx_space, server_secret[..], 0x1301, version, false);
    }
    return quic_derive_and_install_keys(rx_space, client_secret[..], 0x1301, version, false)
        && quic_derive_and_install_keys(tx_space, server_secret[..], 0x1301, version, false);
}

// RFC 9001 Section 6.6: Limits on AEAD Usage - Per-key confidentiality packet limit.
inline fn quic_aead_confidentiality_limit(cipher_suite: u16) -> u64 {
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        return rfc::QUIC_MAX_PN;
    }
    return rfc::QUIC_AES_GCM_CONFIDENTIALITY_LIMIT;
}

// RFC 9001 Section 6.6: Limits on AEAD Usage - Connection-wide failed decryption integrity limit.
inline fn quic_aead_integrity_limit(cipher_suite: u16) -> u64 {
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        return rfc::QUIC_CHACHA20_INTEGRITY_LIMIT;
    }
    return rfc::QUIC_AES_GCM_INTEGRITY_LIMIT;
}

// Derives the next 1-RTT traffic secret, AEAD key, and IV (RFC 9001 §6.1, RFC 9369 §3.3.2).
fn quic_derive_next_key_update(
    cipher_suite: u16,
    version:      u32,
    cur_secret:   const u8[:],
    next_secret:  u8[..48]&,
    next_key:     u8[..32]&,
    next_iv:      u8[..12]&,
) -> bool {
    let prefix = rfc::quic_hkdf_label_prefix(version);
    guard prefix.len > 0 else { return false; }

    let is_sha384 = cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384;
    let hash_id = if is_sha384 { tls_internal::HASH_SHA384 } else { tls_internal::HASH_SHA256 };
    let hash_len: u16 = if is_sha384 { 48 } else { 32 };
    let key_len:  u16 = if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 { 16 } else { 32 };
    guard cur_secret.len == hash_len else { return false; }

    var lbl_ku: u8[..16] = [];
    lbl_ku.append(prefix);
    lbl_ku.append("ku");
    var lbl_key: u8[..16] = [];
    lbl_key.append(prefix);
    lbl_key.append("key");
    var lbl_iv: u8[..16] = [];
    lbl_iv.append(prefix);
    lbl_iv.append("iv");

    next_secret.resize(hash_len as i64, 0);
    next_key.resize(key_len as i64, 0);
    next_iv.resize(12, 0);
    let ok_ku = tls_internal::hkdf_expand_label(hash_id, cur_secret, lbl_ku[..], [], hash_len, next_secret[..]);
    let ok_k = ok_ku
        && tls_internal::hkdf_expand_label(hash_id, next_secret[..], lbl_key[..], [], key_len, next_key[..]);
    let ok_iv = ok_k && tls_internal::hkdf_expand_label(hash_id, next_secret[..], lbl_iv[..], [], 12, next_iv[..]);
    guard ok_iv else {
        core::secure_zeroize_slice(next_secret[..]);
        core::secure_zeroize_slice(next_key[..]);
        next_secret.clear();
        next_key.clear();
        next_iv.clear();
        return false;
    }
    return true;
}

inline fn quic_commit_space_key_update(
    space:       quic::PnSpaceState&,
    next_secret: const u8[:],
    next_key:    const u8[:],
    next_iv:     const u8[:],
) -> bool {
    core::secure_zeroize_slice(space.prev_aead_key[..]);
    core::secure_zeroize_slice(space.prev_aead_iv[..]);
    core::secure_zeroize_slice(space.next_traffic_secret[..]);
    core::secure_zeroize_slice(space.next_aead_key[..]);
    core::secure_zeroize_slice(space.next_aead_iv[..]);
    space.next_traffic_secret.clear();
    space.next_aead_key.clear();
    space.next_aead_iv.clear();
    space.has_next_keys = false;
    guard space.prev_aead_key.try_set(space.aead_key[..])
        && space.prev_aead_iv.try_set(space.aead_iv[..])
        && space.aead_key.try_set(next_key)
        && space.aead_iv.try_set(next_iv)
        && space.traffic_secret.try_set(next_secret) else {
        return false;
    }
    space.has_prev_keys = true;
    space.key_phase = !space.key_phase;
    space.aead_encrypted_packets = 0;
    return true;
}

inline fn quic_commit_cached_next_keys(space: quic::PnSpaceState&) -> bool {
    guard space.has_next_keys else { return false; }
    core::secure_zeroize_slice(space.prev_aead_key[..]);
    core::secure_zeroize_slice(space.prev_aead_iv[..]);
    let ok = space.prev_aead_key.try_set(space.aead_key[..])
        && space.prev_aead_iv.try_set(space.aead_iv[..])
        && space.aead_key.try_set(space.next_aead_key[..])
        && space.aead_iv.try_set(space.next_aead_iv[..])
        && space.traffic_secret.try_set(space.next_traffic_secret[..]);
    core::secure_zeroize_slice(space.next_traffic_secret[..]);
    core::secure_zeroize_slice(space.next_aead_key[..]);
    core::secure_zeroize_slice(space.next_aead_iv[..]);
    space.next_traffic_secret.clear();
    space.next_aead_key.clear();
    space.next_aead_iv.clear();
    space.has_next_keys = false;
    guard ok else { return false; }
    space.has_prev_keys = true;
    space.key_phase = !space.key_phase;
    space.aead_encrypted_packets = 0;
    return true;
}

fn quic_ratchet_space_keys(space: quic::PnSpaceState&, version: u32) -> bool {
    guard space.keys_installed && space.has_app_secret else { return false; }
    var next_secret: u8[..48] = [];
    defer core::secure_zeroize_slice(next_secret[..]);
    var next_key: u8[..32] = [];
    defer core::secure_zeroize_slice(next_key[..]);
    var next_iv: u8[..12] = [];
    guard quic_derive_next_key_update(
        space.cipher_suite, version, space.traffic_secret[..], next_secret, next_key, next_iv,
    ) else {
        return false;
    }
    return quic_commit_space_key_update(space, next_secret[..], next_key[..], next_iv[..]);
}

fn quic_compute_hp_mask_raw(
    cipher_suite: u16,
    hp_key:       const u8[:],
    sample_slice: const u8[:],
) -> u8[5], bool {
    guard sample_slice.len == 16 else { return [0; 5], false; }
    var sample: u8[16] = [0; 16];
    for i in 16 { sample[i] = sample_slice[i]; }

    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard hp_key.len == 16 else { return [0; 5], false; }
        var hp16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(hp16);
        for i in 16 { hp16[i] = hp_key[i]; }
        return aes128_header_protect_mask(hp16, sample), true;
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(hp32);
        for i in 32 { hp32[i] = hp_key[i]; }
        return aes256_header_protect_mask(hp32, sample), true;
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(hp32);
        for i in 32 { hp32[i] = hp_key[i]; }
        return chacha20_header_protect_mask(hp32, sample), true;
    }
    return [0; 5], false;
}

fn quic_compute_hp_mask(space: const quic::PnSpaceState&, sample_slice: const u8[:]) -> u8[5], bool {
    guard space.keys_installed else { return [0; 5], false; }
    return quic_compute_hp_mask_raw(space.cipher_suite, space.hp_key[..], sample_slice);
}

inline fn quic_aead_open_cipher_raw(
    cipher_suite: u16,
    aead_key:     const u8[:],
    nonce:        const u8[12]&,
    aad:          const u8[:],
    ct_slice:     const u8[:],
    tag:          const u8[16]&,
    out_plain:    u8[..16384]&,
) -> bool {
    let pt_len = ct_slice.len;
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 && aead_key.len == 16 {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = aead_key[i]; }
        let dec_len, ok_open = core::fused_aes_gcm_decrypt(key16, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        return ok_open && dec_len == pt_len;
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 && aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = aead_key[i]; }
        let dec_len, ok_open = core::aes256_gcm_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        return ok_open && dec_len == pt_len;
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 && aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = aead_key[i]; }
        let dec_len, ok_open = core::chacha20_poly1305_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        return ok_open && dec_len == pt_len;
    }
    return false;
}

fn quic_aead_open_raw(
    cipher_suite: u16,
    aead_key:     const u8[:],
    aead_iv:      const u8[:],
    pn:           u64,
    aad:          const u8[:],
    ciphertext:   const u8[:],
    out_plain:    u8[..16384]&,
) -> bool {
    guard ciphertext.len >= 16 && aead_iv.len == 12 else { return false; }
    let pt_len = core::sub_sat_i64(ciphertext.len, 16);
    guard pt_len <= out_plain.cap else { return false; }

    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = aead_iv[i]; }
    let nonce, ok_nonce = tls::compute_record_nonce(iv12, pn);
    guard ok_nonce else { return false; }

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ciphertext[core::add_sat_i64(pt_len, i)]; }
    let ct_slice = ciphertext[..pt_len];

    out_plain.resize(pt_len, 0);
    guard quic_aead_open_cipher_raw(cipher_suite, aead_key, nonce, aad, ct_slice, tag, out_plain) else {
        out_plain.clear();
        return false;
    }
    return true;
}

fn quic_aead_open_payload(
    space:      const quic::PnSpaceState&,
    pn:         u64,
    aad:        const u8[:],
    ciphertext: const u8[:],
    out_plain:  u8[..16384]&,
) -> bool {
    guard space.keys_installed else { return false; }
    return quic_aead_open_raw(
        space.cipher_suite, space.aead_key[..], space.aead_iv[..], pn, aad, ciphertext, out_plain,
    );
}

fn quic_aead_seal_payload_inplace(
    space: const quic::PnSpaceState&,
    nonce: const u8[12]&,
    aad:   const u8[:],
    ct:    u8[:],
) -> u8[16], bool {
    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 && space.aead_key.len == 16 {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = space.aead_key[i]; }
        return core::aes128_gcm_seal_inplace(key16, nonce, ct, aad);
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = space.aead_key[i]; }
        return core::aes256_gcm_seal_inplace(key32, nonce, ct, aad);
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = space.aead_key[i]; }
        return core::chacha20_poly1305_seal_inplace(key32, nonce, ct, aad);
    }
    return [0; 16], false;
}

// Computes the total wire length of a single QUIC packet within a coalesced datagram slice.
fn calc_coalesced_packet_wire_len(pkt_slice: const u8[:], hdr: const quic::QuicHeader&) -> i64, bool {
    if hdr.header_type == quic::QuicHeaderType.Initial
        || hdr.header_type == quic::QuicHeaderType.ZeroRtt
        || hdr.header_type == quic::QuicHeaderType.Handshake {
        let total_len = core::add_sat_i64(hdr.pn_offset, hdr.payload_length as i64);
        guard total_len > 0 && total_len <= pkt_slice.len else { return 0, false; }
        return total_len, true;
    }
    return pkt_slice.len, true;
}

inline fn is_valid_inbound_dcid(conn: const quic::QuicConnection&, hdr: const quic::QuicHeader&) -> bool {
    if conn.role == quic::QuicRole.Server && hdr.header_type == quic::QuicHeaderType.Initial {
        if conn.packets_rx == 0 {
            // RFC 9000 Section 7.2: Negotiating Connection IDs - Accept >= 8-byte ODCID or server-chosen SCID.
            return hdr.dcid.len >= 8 || (conn.scid.len > 0 && core::ct_eq_bytes(hdr.dcid, conn.scid[..]));
        }
        if conn.original_dcid.len > 0 && core::ct_eq_bytes(hdr.dcid, conn.original_dcid[..]) {
            return true;
        }
    }
    if conn.scid.len == 0 {
        return hdr.dcid.len == 0;
    }
    if core::ct_eq_bytes(hdr.dcid, conn.scid[..]) {
        return true;
    }
    for i in conn.alt_scids.len {
        if conn.alt_scids[i].len > 0 && core::ct_eq_bytes(hdr.dcid, conn.alt_scids[i][..]) {
            return true;
        }
    }
    return false;
}

inline fn get_rx_space_keys_installed(conn: const quic::QuicConnection&, space_id: quic::PnSpaceId) -> bool {
    if space_id == quic::PnSpaceId.Initial { return conn.initial_space.keys_installed; }
    if space_id == quic::PnSpaceId.Handshake { return conn.handshake_space.keys_installed; }
    return conn.app_space.keys_installed;
}

inline fn is_pn_already_received(
    ranges:             const quic::AckInterval[..64]&,
    pn:                 u64,
    has_min_tracked_pn: bool = false,
    min_tracked_pn:     u64  = 0,
) -> bool {
    if has_min_tracked_pn && pn <= min_tracked_pn {
        return true;
    }
    if ranges.len >= ranges.cap && pn < ranges[ranges.len - 1].smallest {
        return true;
    }
    for i in ranges.len {
        let r = ranges[i];
        if pn > r.largest {
            return false;
        }
        if pn >= r.smallest {
            return true;
        }
    }
    return false;
}

// Decodes an unmasked packet number from an unencrypted test packet slice.
//
// Example:
//   pkt_slice = [0x40, 0x05], pn_offset = 1, pn_len = 1, space.largest_recv_pn = 4
//   returns: 5, ok = true
inline fn decode_unencrypted_test_pn(
    space:     const quic::PnSpaceState&,
    pkt_slice: const u8[:],
    pn_offset: u32,
    pn_len:    u8,
) -> u64, bool {
    let off:  i64 = pn_offset;
    let plen: i64 = pn_len;
    guard off >= 0 && plen >= 1 && plen <= 4 && core::add_sat_i64(off, plen) <= pkt_slice.len else {
        return 0, false;
    }
    var trunc_pn: u64 = 0;
    for i in plen {
        trunc_pn = core::shl_sat_u64(trunc_pn, 8) | pkt_slice[core::add_sat_i64(off, i)];
    }
    return quic::decode_packet_number_checked(space.largest_recv_pn, trunc_pn, pn_len);
}

// Validates unencrypted unit-test packets when explicitly invoked through `process_unencrypted_test_datagram`.
fn verify_unencrypted_test_packet(
    conn:          const quic::QuicConnection&,
    space:         const quic::PnSpaceState&,
    pkt_slice:     const u8[:],
    pkt_wire_len:  i64,
    hdr:           quic::QuicHeader&,
    out_plaintext: u8[..16384]&,
) -> u64, bool {
    // RFC 9000 Section 17.2.2: Initial Packet - Clients MUST reject Initial packets with non-zero Token Length.
    if conn.role == quic::QuicRole.Client && hdr.header_type == quic::QuicHeaderType.Initial && hdr.token.len > 0 {
        return rfc::QUIC_ERR_PROTOCOL_VIOLATION, false;
    }
    let saved_hdr = hdr;
    let pn_len = core::add_sat_u32(pkt_slice[0] & 0x03, 1) as u8;
    let test_pn, test_pn_ok = decode_unencrypted_test_pn(space, pkt_slice[..pkt_wire_len], hdr.pn_offset, pn_len);
    guard test_pn_ok && !is_pn_already_received(space.recv_ranges, test_pn) else { return 0, false; }
    hdr.packet_number = test_pn;
    hdr.pn_length = pn_len;
    hdr.header_len = core::add_sat_u32(hdr.pn_offset, pn_len);
    let raw_pl = get_packet_payload(pkt_slice[..pkt_wire_len], hdr);
    guard !(hdr.payload_length > hdr.pn_length && raw_pl.len == 0) && out_plaintext.try_set(raw_pl) else {
        hdr = saved_hdr;
        return 0, false;
    }
    return 0, true;
}

// Validates RFC 9000 Section 17.2 / 17.2.2 / 17.3.1 post-AEAD reserved bits and Initial token rules.
inline fn validate_decrypted_packet_bits(
    conn:        const quic::QuicConnection&,
    hdr:         const quic::QuicHeader&,
    unmasked_b0: u8,
) -> u64 {
    // RFC 9000 Section 17.2.2: Initial Packet - Clients MUST reject Initial packets with non-zero Token Length.
    if conn.role == quic::QuicRole.Client && hdr.header_type == quic::QuicHeaderType.Initial && hdr.token.len > 0 {
        return rfc::QUIC_ERR_PROTOCOL_VIOLATION;
    }
    // RFC 9000 Section 17.2: Long Header Packets - Non-zero reserved bits after AEAD open are PROTOCOL_VIOLATION.
    // RFC 9000 Section 17.3.1: 1-RTT Packet - Non-zero reserved bits after AEAD open are PROTOCOL_VIOLATION.
    let reserved_mask: u8 = if (unmasked_b0 & 0x80) != 0 { 0x0C } else { 0x18 };
    guard (unmasked_b0 & reserved_mask) == 0 else {
        return rfc::QUIC_ERR_PROTOCOL_VIOLATION;
    }
    return 0;
}

// Removes RFC 9001 Section 5.4 header protection in place and decodes the full non-duplicate packet number.
inline fn unprotect_packet_header_raw(
    cipher_suite:       u16,
    hp_key:             const u8[:],
    largest_recv_pn:    u64,
    recv_ranges:        const quic::AckInterval[..64]&,
    has_min_tracked_pn: bool,
    min_tracked_pn:     u64,
    work_pkt:           u8[:],
    hdr:                quic::QuicHeader&,
) -> u64, u8, bool {
    let sample_slice, ok_samp = tls::quic_extract_hp_sample(work_pkt, hdr.pn_offset);
    guard ok_samp else { return 0, 0, false; }
    let hp_mask, ok_mask = quic_compute_hp_mask_raw(cipher_suite, hp_key, sample_slice);
    guard ok_mask else { return 0, 0, false; }

    let pn_len, trunc_pn = quic::remove_header_protection(work_pkt, hdr.pn_offset, hp_mask);
    guard pn_len >= 1 && pn_len <= 4 else { return 0, 0, false; }

    let full_pn, pn_ok = quic::decode_packet_number_checked(largest_recv_pn, trunc_pn, pn_len);
    // RFC 9000 Section 12.3: Packet Numbers - Discard duplicate packets before payload processing.
    let dup = is_pn_already_received(recv_ranges, full_pn, has_min_tracked_pn, min_tracked_pn);
    guard pn_ok && !dup else { return 0, 0, false; }

    let unmasked_b0 = work_pkt[0];
    if (unmasked_b0 & 0x80) == 0 {
        hdr.key_phase = (unmasked_b0 & 0x04) != 0;
    }
    hdr.packet_number = full_pn;
    hdr.pn_length = pn_len;
    hdr.header_len = core::add_sat_u32(hdr.pn_offset, pn_len);
    return full_pn, unmasked_b0, true;
}

inline fn quic_record_aead_decrypt_failure(conn: quic::QuicConnection&, cipher_suite: u16) -> u64 {
    conn.aead_failed_decrypts = core::add_sat_u64(conn.aead_failed_decrypts, 1);
    if conn.aead_failed_decrypts >= quic_aead_integrity_limit(cipher_suite) {
        return rfc::QUIC_ERR_AEAD_LIMIT_REACHED;
    }
    return 0;
}

// Verifies and decrypts an inbound 0-RTT packet using dedicated 0-RTT keys (RFC 9000 §17.2.3, RFC 9001 §5.3).
fn verify_and_decrypt_zero_rtt_packet(
    conn:          quic::QuicConnection&,
    pkt_slice:     const u8[:],
    pkt_wire_len:  i64,
    hdr:           quic::QuicHeader&,
    out_plaintext: u8[..16384]&,
) -> u64, bool {
    // RFC 9000 Section 17.2.3: 0-RTT - Only servers receive 0-RTT packets; clients MUST reject them.
    if conn.role == quic::QuicRole.Client {
        return rfc::QUIC_ERR_PROTOCOL_VIOLATION, false;
    }
    guard conn.zero_rtt_keys.keys_installed
        && hdr.version == conn.version
        && is_valid_inbound_dcid(conn, hdr) else {
        return 0, false;
    }

    var work_pkt: u8[..16512] = [];
    guard pkt_wire_len > 0 && work_pkt.try_append(pkt_slice[..pkt_wire_len]) else { return 0, false; }

    let saved_hdr = hdr;
    let full_pn, unmasked_b0, ok_hp = unprotect_packet_header_raw(
        conn.zero_rtt_keys.cipher_suite,
        conn.zero_rtt_keys.hp_key[..],
        conn.app_space.largest_recv_pn,
        conn.app_space.recv_ranges,
        conn.app_space.has_min_tracked_pn,
        conn.app_space.min_tracked_pn,
        work_pkt[..],
        hdr,
    );
    guard ok_hp else { return 0, false; }

    let hdr_end = hdr.header_len as i64;
    let ok_open = hdr_end < work_pkt.len && quic_aead_open_raw(
        conn.zero_rtt_keys.cipher_suite,
        conn.zero_rtt_keys.aead_key[..],
        conn.zero_rtt_keys.aead_iv[..],
        full_pn,
        work_pkt[..hdr_end],
        work_pkt[hdr_end..],
        out_plaintext,
    );
    guard ok_open else {
        hdr = saved_hdr;
        return quic_record_aead_decrypt_failure(conn, conn.zero_rtt_keys.cipher_suite), false;
    }

    let post_err = validate_decrypted_packet_bits(conn, hdr, unmasked_b0);
    guard post_err == 0 else {
        hdr = saved_hdr;
        out_plaintext.clear();
        return post_err, false;
    }
    return 0, true;
}

// Authenticates a peer-initiated 1-RTT Key Update before committing the key ratchet (RFC 9001 §6.1).
inline fn try_peer_key_update_open(
    conn:          quic::QuicConnection&,
    hdr:           const quic::QuicHeader&,
    full_pn:       u64,
    unmasked_b0:   u8,
    aad:           const u8[:],
    ciphertext:    const u8[:],
    out_plaintext: u8[..16384]&,
) -> u64, bool {
    let cs = conn.app_space.cipher_suite;
    guard conn.state == quic::QuicConnState.Established
        && conn.app_space.has_app_secret
        && (!conn.app_space.has_recv_packets || full_pn > conn.app_space.phase_highest_pn) else {
        return quic_record_aead_decrypt_failure(conn, cs), false;
    }
    if !conn.app_space.has_next_keys {
        var cur_secret: u8[..48] = [];
        defer core::secure_zeroize_slice(cur_secret[..]);
        guard cur_secret.try_set(conn.app_space.traffic_secret[..])
            && quic_derive_next_key_update(
                cs,
                conn.version,
                cur_secret[..],
                conn.app_space.next_traffic_secret,
                conn.app_space.next_aead_key,
                conn.app_space.next_aead_iv,
            ) else {
                return quic_record_aead_decrypt_failure(conn, cs), false;
            }
        conn.app_space.has_next_keys = true;
    }
    guard quic_aead_open_raw(
        cs,
        conn.app_space.next_aead_key[..],
        conn.app_space.next_aead_iv[..],
        full_pn,
        aad,
        ciphertext,
        out_plaintext,
    ) else {
        return quic_record_aead_decrypt_failure(conn, cs), false;
    }
    let post_err = validate_decrypted_packet_bits(conn, hdr, unmasked_b0);
    guard post_err == 0 else {
        out_plaintext.clear();
        return post_err, false;
    }
    guard quic_commit_cached_next_keys(conn.app_space) else {
        out_plaintext.clear();
        return rfc::QUIC_ERR_KEY_UPDATE_ERROR, false;
    }
    conn.app_space.phase_highest_pn = full_pn;
    if conn.tx_app_space.keys_installed && conn.tx_app_space.has_app_secret
        && conn.tx_app_space.key_phase != conn.app_space.key_phase {
        guard quic_ratchet_space_keys(conn.tx_app_space, conn.version) else {
            out_plaintext.clear();
            return rfc::QUIC_ERR_KEY_UPDATE_ERROR, false;
        }
    }
    return 0, true;
}

// Decrypts a 1-RTT packet with RFC 9001 Section 6 Key Phase verification and post-AEAD key-update ratcheting.
fn verify_and_decrypt_one_rtt_payload(
    conn:          quic::QuicConnection&,
    hdr:           const quic::QuicHeader&,
    full_pn:       u64,
    unmasked_b0:   u8,
    aad:           const u8[:],
    ciphertext:    const u8[:],
    out_plaintext: u8[..16384]&,
) -> u64, bool {
    let cs = conn.app_space.cipher_suite;
    if hdr.key_phase == conn.app_space.key_phase {
        guard quic_aead_open_payload(conn.app_space, full_pn, aad, ciphertext, out_plaintext) else {
            return quic_record_aead_decrypt_failure(conn, cs), false;
        }
        let post_err = validate_decrypted_packet_bits(conn, hdr, unmasked_b0);
        guard post_err == 0 else {
            out_plaintext.clear();
            return post_err, false;
        }
        if !conn.app_space.has_recv_packets || full_pn > conn.app_space.phase_highest_pn {
            conn.app_space.phase_highest_pn = full_pn;
        }
        return 0, true;
    }

    // Delayed packet from the previous key phase (RFC 9001 Section 6.5).
    if conn.app_space.has_prev_keys && full_pn < conn.app_space.phase_highest_pn {
        guard quic_aead_open_raw(
            cs,
            conn.app_space.prev_aead_key[..],
            conn.app_space.prev_aead_iv[..],
            full_pn,
            aad,
            ciphertext,
            out_plaintext,
        ) else {
            return quic_record_aead_decrypt_failure(conn, cs), false;
        }
        let post_err = validate_decrypted_packet_bits(conn, hdr, unmasked_b0);
        guard post_err == 0 else {
            out_plaintext.clear();
            return post_err, false;
        }
        return 0, true;
    }

    return try_peer_key_update_open(conn, hdr, full_pn, unmasked_b0, aad, ciphertext, out_plaintext);
}

// Removes RFC 9001 Header Protection and AEAD-decrypts an inbound QUIC packet when space keys are installed.
// Fails closed when keys are absent unless explicitly invoked from the internal unencrypted test harness.
// Returns `(fatal_err: u64, ok: bool)`, where `fatal_err != 0` indicates a fatal protocol violation.
fn verify_and_decrypt_packet(
    conn:                   quic::QuicConnection&,
    space_id:               quic::PnSpaceId,
    pkt_slice:              const u8[:],
    pkt_wire_len:           i64,
    dgram_len:              i64,
    hdr:                    quic::QuicHeader&,
    out_plaintext:          u8[..16384]&,
    allow_unencrypted_test: bool = false,
) -> u64, bool {
    if hdr.header_type == quic::QuicHeaderType.ZeroRtt {
        return verify_and_decrypt_zero_rtt_packet(conn, pkt_slice, pkt_wire_len, hdr, out_plaintext);
    }

    var space .= conn.app_space;
    if space_id == quic::PnSpaceId.Initial {
        space .= conn.initial_space;
    } else if space_id == quic::PnSpaceId.Handshake {
        space .= conn.handshake_space;
    }
    if !get_rx_space_keys_installed(conn, space_id) {
        guard allow_unencrypted_test else { return 0, false; }
        return verify_unencrypted_test_packet(conn, space, pkt_slice, pkt_wire_len, hdr, out_plaintext);
    }

    let is_long = hdr.header_type == quic::QuicHeaderType.Initial
        || hdr.header_type == quic::QuicHeaderType.Handshake;
    let is_srv_init = hdr.header_type == quic::QuicHeaderType.Initial && conn.role == quic::QuicRole.Server;
    guard (!is_long || hdr.version == conn.version)
        && (!is_srv_init || dgram_len >= 1200)
        && is_valid_inbound_dcid(conn, hdr) else {
        return 0, false;
    }

    var work_pkt: u8[..16512] = [];
    guard pkt_wire_len > 0 && work_pkt.try_append(pkt_slice[..pkt_wire_len]) else { return 0, false; }

    let saved_hdr = hdr;
    let full_pn, unmasked_b0, ok_hp = unprotect_packet_header_raw(
        space.cipher_suite, space.hp_key[..], space.largest_recv_pn, space.recv_ranges,
        space.has_min_tracked_pn, space.min_tracked_pn, work_pkt[..], hdr,
    );
    guard ok_hp else { return 0, false; }

    let hdr_end = hdr.header_len as i64;
    guard hdr_end < work_pkt.len else {
        hdr = saved_hdr;
        return 0, false;
    }

    if hdr.header_type == quic::QuicHeaderType.OneRtt {
        let fatal_err, ok_1rtt = verify_and_decrypt_one_rtt_payload(
            conn, hdr, full_pn, unmasked_b0, work_pkt[..hdr_end], work_pkt[hdr_end..], out_plaintext,
        );
        guard ok_1rtt else {
            hdr = saved_hdr;
            return fatal_err, false;
        }
        return 0, true;
    }

    guard quic_aead_open_payload(space, full_pn, work_pkt[..hdr_end], work_pkt[hdr_end..], out_plaintext) else {
        hdr = saved_hdr;
        return quic_record_aead_decrypt_failure(conn, space.cipher_suite), false;
    }

    let post_err = validate_decrypted_packet_bits(conn, hdr, unmasked_b0);
    guard post_err == 0 else {
        hdr = saved_hdr;
        out_plaintext.clear();
        return post_err, false;
    }
    return 0, true;
}

// Authenticates and applies a Retry packet on a client in Initial state (RFC 9000 §17.2.5, RFC 9001 §5.8).
fn quic_process_retry_packet(
    conn:      quic::QuicConnection&,
    hdr:       const quic::QuicHeader&,
    retry_pkt: const u8[:],
) -> bool {
    guard conn.role == quic::QuicRole.Client
        && conn.state == quic::QuicConnState.Initial
        && !conn.retry_received
        && conn.packets_rx == 0
        && hdr.version == conn.version
        && hdr.token.len > 0 else {
        return false;
    }
    guard core::ct_eq_bytes(hdr.dcid[..], conn.scid[..]) else { return false; }
    let odcid = if conn.original_dcid.len > 0 { conn.original_dcid[..] } else { conn.dcid[..] };
    // RFC 9000 Section 17.2.5.2: Client MUST discard Retry whose SCID matches the original DCID.
    guard !core::ct_eq_bytes(hdr.scid[..], odcid) else { return false; }
    guard quic::verify_retry_integrity_tag(odcid, retry_pkt, hdr.version) else { return false; }

    guard conn.retry_token.try_set(hdr.token[..]) && conn.dcid.try_set(hdr.scid[..]) else {
        return false;
    }
    conn.retry_received = true;
    if conn.initial_space.keys_installed || conn.tx_initial_space.keys_installed {
        return quic_derive_initial_space_keys(
            hdr.scid[..], hdr.version, conn.role, conn.initial_space, conn.tx_initial_space,
        );
    }
    return true;
}

// Verifies whether an incoming short-header datagram matches any registered peer
// Stateless Reset Token in constant time (RFC 9000 §10.3).
fn is_stateless_reset_datagram(conn: const quic::QuicConnection&, dgram: const u8[:]) -> bool {
    guard dgram.len >= 21 && (dgram[0] & 0x80) == 0 else { return false; }
    let tail_offset = core::sub_sat_u64(dgram.len as u64, 16) as i64;
    guard tail_offset >= 5 && tail_offset <= dgram.len else { return false; }
    let tail = dgram[tail_offset..];
    var matched = false;
    for i in conn.peer_reset_tokens.len {
        if core::ct_eq_bytes(tail, conn.peer_reset_tokens[i][..]) {
            matched = true;
        }
    }
    return matched;
}

// Reads a QUIC packet header before header protection removal by clearing masked reserved bits on byte 0
// when packet number space keys are installed (RFC 9001 §5.4, RFC 9287).
//
// Example:
//   pkt_slice = [0xC5, 0x00, 0x00, 0x00, 0x01, ...], dcid_len = 8 (initial keys installed)
//   returns: QuicHeader { header_type: Initial, version: 1, ... }, ok = true
fn parse_quic_packet_pre_hp(
    conn:      const quic::QuicConnection&,
    pkt_slice: const u8[:],
    dcid_len:  u8,
) -> quic::QuicHeader, bool {
    guard pkt_slice.len > 0 else { return quic::QuicHeader { .. }, false; }
    let raw_b0 = pkt_slice[0];
    if (raw_b0 & 0x80) != 0 {
        guard pkt_slice.len >= 5 else { return quic::QuicHeader { .. }, false; }
        let ver = core::read_be_u32(pkt_slice, 1);
        if ver == rfc::QUIC_VERSION_NEGOTIATION {
            return parse_quic_long_header(pkt_slice, raw_b0);
        }
        let opts = QuicHeaderOptions {
            allow_grease: conn.allow_grease_quic_bit,
            is_masked:    true,
        };
        return parse_quic_long_header(pkt_slice, raw_b0, opts);
    }
    let opts = QuicHeaderOptions {
        allow_grease: conn.allow_grease_quic_bit,
        is_masked:    true,
    };
    return parse_quic_short_header(pkt_slice, raw_b0, dcid_len, opts);
}

inline fn handle_packet_decrypt_failure(
    conn:      quic::QuicConnection&,
    hdr:       const quic::QuicHeader&,
    pkt_slice: const u8[:],
    fatal_err: u64,
) {
    if fatal_err != 0 {
        quic::close(conn, fatal_err);
    } else if hdr.header_type == quic::QuicHeaderType.OneRtt && is_stateless_reset_datagram(conn, pkt_slice) {
        conn.state = quic::QuicConnState.Closed;
    }
}

// Processes a single QUIC packet slice extracted from an inbound UDP datagram and returns its
// decrypted frame payload and header type when handled.
fn process_single_coalesced_packet_with_plain(
    conn:                   quic::QuicConnection&,
    pkt_slice:              const u8[:],
    dgram_len:              i64,
    now_us:                 u64,
    out_ack:                quic::AckFrame&,
    out_plain:              u8[..16384]&,
    out_htype:              quic::QuicHeaderType&,
    allow_unencrypted_test: bool = false,
) -> i64, quic::ProcessResult {
    out_plain.clear();
    guard !quic_conn_is_closing_or_closed(conn.state) else {
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    let dcid_len = conn.scid.len as u8;
    var hdr, ok = parse_quic_packet_pre_hp(conn, pkt_slice, dcid_len);
    guard ok else {
        if is_stateless_reset_datagram(conn, pkt_slice) {
            conn.state = quic::QuicConnState.Closed;
        }
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    let pkt_wire_len, len_ok = calc_coalesced_packet_wire_len(pkt_slice, hdr);
    guard len_ok else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }
    out_htype = hdr.header_type;

    if hdr.header_type == quic::QuicHeaderType.Retry {
        guard quic_process_retry_packet(conn, hdr, pkt_slice[..pkt_wire_len]) else {
            return 0, quic::ProcessResult { handled: false, needs_ack: false };
        }
        return pkt_wire_len, quic::ProcessResult { handled: true, needs_ack: false };
    }

    if hdr.header_type == quic::QuicHeaderType.VersionNegotiation {
        guard conn.role == quic::QuicRole.Client && conn.packets_rx == 0 else {
            return 0, quic::ProcessResult { handled: false, needs_ack: false };
        }
        let res_pkt = dispatch_packet_type(conn, hdr, out_ack);
        guard res_pkt.handled else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }
        return pkt_wire_len, res_pkt;
    }

    let space_id = header_type_to_space_id(hdr.header_type);
    let fatal_err, ok_dec = verify_and_decrypt_packet(
        conn, space_id, pkt_slice, pkt_wire_len, dgram_len, hdr, out_plain, allow_unencrypted_test,
    );
    guard ok_dec else {
        core::secure_zeroize_slice(out_plain[..]);
        out_plain.clear();
        handle_packet_decrypt_failure(conn, hdr, pkt_slice, fatal_err);
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    let res_frames = quic::process_payload(conn, out_plain[..], hdr.header_type, now_us);
    guard res_frames.handled else {
        core::secure_zeroize_slice(out_plain[..]);
        out_plain.clear();
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    conn.packets_rx = core::add_sat_u64(conn.packets_rx, 1);
    bind_initial_server_cids(conn, hdr);
    if quic_conn_is_closing_or_closed(conn.state) {
        return pkt_wire_len, quic::ProcessResult { handled: true, needs_ack: false };
    }
    let res_pkt = dispatch_packet_type(conn, hdr, out_ack);
    guard res_pkt.handled else {
        core::secure_zeroize_slice(out_plain[..]);
        out_plain.clear();
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }
    return pkt_wire_len, quic::ProcessResult { handled: true, needs_ack: res_frames.needs_ack };
}

// Processes a single QUIC packet slice extracted from an inbound UDP datagram.
fn process_single_coalesced_packet(
    conn:                   quic::QuicConnection&,
    pkt_slice:              const u8[:],
    dgram_len:              i64,
    now_us:                 u64,
    out_ack:                quic::AckFrame&,
    allow_unencrypted_test: bool = false,
) -> i64, quic::ProcessResult {
    var plaintext_payload: u8[..16384] = [];
    defer core::secure_zeroize_slice(plaintext_payload[..]);
    var htype = quic::QuicHeaderType.Initial;
    return process_single_coalesced_packet_with_plain(
        conn, pkt_slice, dgram_len, now_us, out_ack, plaintext_payload, htype, allow_unencrypted_test,
    );
}

// Internal unit-test harness that permits unencrypted packet payloads when space keys are absent.
// Production traffic MUST use `quic::process_datagram`, which always requires installed keys.
fn process_unencrypted_test_datagram(
    conn:   quic::QuicConnection&,
    dgram:  const u8[:],
    now_us: u64,
    ack:    quic::AckFrame&,
) -> quic::ProcessResult {
    guard dgram.len > 0 else { return quic::ProcessResult { handled: false, needs_ack: false }; }
    conn.bytes_received = core::add_sat_u64(conn.bytes_received, dgram.len as u64);

    var offset: i64 = 0;
    var any_handled = false;
    var final_needs_ack = false;

    while offset < dgram.len {
        let rem = dgram[offset..];
        let consumed, res = process_single_coalesced_packet(conn, rem, dgram.len, now_us, ack, true);
        guard res.handled && consumed > 0 else {
            return quic::ProcessResult { handled: any_handled, needs_ack: final_needs_ack };
        }
        any_handled = true;
        if res.needs_ack {
            final_needs_ack = true;
        }
        offset = core::add_sat_i64(offset, consumed);
    }

    return quic::ProcessResult { handled: any_handled, needs_ack: final_needs_ack };
}
