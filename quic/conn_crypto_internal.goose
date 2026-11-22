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

// Derives QUIC Initial encryption keys and header protection keys for client and server
// from the initial Destination Connection ID (RFC 9001 §5.2, RFC 9369 §3.3).
fn quic_derive_initial_space_keys(
    dcid:     const u8[:],
    version:  u32,
    role:     quic::QuicRole,
    rx_space: quic::PnSpaceState&,
    tx_space: quic::PnSpaceState&,
) -> bool {
    let salt = rfc::quic_initial_salt(version);
    guard salt.len == 20 else { return false; }
    let prefix = rfc::quic_hkdf_label_prefix(version);
    guard prefix.len > 0 else { return false; }

    var initial_secret = core::hkdf_extract(salt, dcid);
    defer core::secure_zeroize_32(initial_secret);
    var client_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_secret);
    var server_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_secret);
    let sha256 = tls_internal::HASH_SHA256;
    let ok_c = tls_internal::hkdf_expand_label(
        sha256, initial_secret[..], "client in", [], 32, client_secret[..],
    );
    let ok_s = tls_internal::hkdf_expand_label(
        sha256, initial_secret[..], "server in", [], 32, server_secret[..],
    );
    guard ok_c && ok_s else { return false; }

    var lbl_key: u8[..16] = [];
    lbl_key.append(prefix);
    lbl_key.append("key");
    var lbl_iv: u8[..16] = [];
    lbl_iv.append(prefix);
    lbl_iv.append("iv");

    var c_key: u8[16] = [0; 16];
    defer core::secure_zeroize_16(c_key);
    var c_iv: u8[12] = [0; 12];
    var c_hp: u8[16] = [0; 16];
    defer core::secure_zeroize_16(c_hp);
    guard tls_internal::hkdf_expand_label(sha256, client_secret[..], lbl_key[..], [], 16, c_key[..])
        && tls_internal::hkdf_expand_label(sha256, client_secret[..], lbl_iv[..], [], 12, c_iv[..])
        && tls_internal::ks_derive_quic_hp_key(sha256, client_secret[..], 16, c_hp[..], version) else {
        return false;
    }

    var s_key: u8[16] = [0; 16];
    defer core::secure_zeroize_16(s_key);
    var s_iv: u8[12] = [0; 12];
    var s_hp: u8[16] = [0; 16];
    defer core::secure_zeroize_16(s_hp);
    guard tls_internal::hkdf_expand_label(sha256, server_secret[..], lbl_key[..], [], 16, s_key[..])
        && tls_internal::hkdf_expand_label(sha256, server_secret[..], lbl_iv[..], [], 12, s_iv[..])
        && tls_internal::ks_derive_quic_hp_key(sha256, server_secret[..], 16, s_hp[..], version) else {
        return false;
    }

    if role == quic::QuicRole.Client {
        return quic::install_keys(tx_space, c_hp[..], c_key[..], c_iv[..], 0x1301)
            && quic::install_keys(rx_space, s_hp[..], s_key[..], s_iv[..], 0x1301);
    }
    return quic::install_keys(rx_space, c_hp[..], c_key[..], c_iv[..], 0x1301)
        && quic::install_keys(tx_space, s_hp[..], s_key[..], s_iv[..], 0x1301);
}

fn quic_compute_hp_mask(space: const quic::PnSpaceState&, sample_slice: const u8[:]) -> u8[5], bool {
    guard sample_slice.len == 16 else { return [0; 5], false; }
    var sample: u8[16] = [0; 16];
    for i in 16 { sample[i] = sample_slice[i]; }

    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard space.hp_key.len == 16 else { return [0; 5], false; }
        var hp16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(hp16);
        for i in 16 { hp16[i] = space.hp_key[i]; }
        return aes128_header_protect_mask(hp16, sample), true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard space.hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(hp32);
        for i in 32 { hp32[i] = space.hp_key[i]; }
        return aes256_header_protect_mask(hp32, sample), true;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard space.hp_key.len == 32 else { return [0; 5], false; }
        var hp32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(hp32);
        for i in 32 { hp32[i] = space.hp_key[i]; }
        return chacha20_header_protect_mask(hp32, sample), true;
    }
    return [0; 5], false;
}

inline fn quic_aead_open_cipher(
    space:     const quic::PnSpaceState&,
    nonce:     const u8[12]&,
    aad:       const u8[:],
    ct_slice:  const u8[:],
    tag:       const u8[16]&,
    out_plain: u8[..16384]&,
) -> bool {
    let pt_len = ct_slice.len;
    if space.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 && space.aead_key.len == 16 {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::fused_aes_gcm_decrypt(key16, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        return ok_open && dec_len == pt_len;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::aes256_gcm_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        return ok_open && dec_len == pt_len;
    }
    if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 && space.aead_key.len == 32 {
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = space.aead_key[i]; }
        let dec_len, ok_open = core::chacha20_poly1305_open_into(key32, nonce, ct_slice, aad, tag, out_plain[..pt_len]);
        return ok_open && dec_len == pt_len;
    }
    return false;
}

fn quic_aead_open_payload(
    space:      const quic::PnSpaceState&,
    pn:         u64,
    aad:        const u8[:],
    ciphertext: const u8[:],
    out_plain:  u8[..16384]&,
) -> bool {
    guard ciphertext.len >= 16 && space.aead_iv.len == 12 else { return false; }
    let pt_len = core::sub_sat_i64(ciphertext.len, 16);
    guard pt_len <= out_plain.cap else { return false; }

    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = space.aead_iv[i]; }
    let nonce, ok_nonce = tls::compute_record_nonce(iv12, pn);
    guard ok_nonce else { return false; }

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ciphertext[core::add_sat_i64(pt_len, i)]; }
    let ct_slice = ciphertext[..pt_len];

    out_plain.resize(pt_len, 0);
    guard quic_aead_open_cipher(space, nonce, aad, ct_slice, tag, out_plain) else {
        out_plain.clear();
        return false;
    }
    return true;
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
    return core::ct_eq_bytes(hdr.dcid, conn.scid[..]);
}

inline fn get_rx_space_keys_installed(conn: const quic::QuicConnection&, space_id: quic::PnSpaceId) -> bool {
    if space_id == quic::PnSpaceId.Initial { return conn.initial_space.keys_installed; }
    if space_id == quic::PnSpaceId.Handshake { return conn.handshake_space.keys_installed; }
    return conn.app_space.keys_installed;
}

inline fn is_pn_already_received(ranges: const quic::AckInterval[..64]&, pn: u64) -> bool {
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

// Validates unencrypted unit-test packets when PN-space keys are not installed.
fn verify_unencrypted_test_packet(
    conn:          const quic::QuicConnection&,
    space:         const quic::PnSpaceState&,
    pkt_slice:     const u8[:],
    pkt_wire_len:  i64,
    hdr:           quic::QuicHeader&,
    out_plaintext: u8[..16384]&,
) -> u64, bool {
    guard conn.allow_unencrypted_test_packets else { return 0, false; }
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
inline fn unprotect_packet_header(
    space:    const quic::PnSpaceState&,
    work_pkt: u8[:],
    hdr:      quic::QuicHeader&,
) -> u64, u8, bool {
    let sample_slice, ok_samp = tls::quic_extract_hp_sample(work_pkt, hdr.pn_offset);
    guard ok_samp else { return 0, 0, false; }
    let hp_mask, ok_mask = quic_compute_hp_mask(space, sample_slice);
    guard ok_mask else { return 0, 0, false; }

    let pn_len, trunc_pn = quic::remove_header_protection(work_pkt, hdr.pn_offset, hp_mask);
    guard pn_len >= 1 && pn_len <= 4 else { return 0, 0, false; }

    let full_pn, pn_ok = quic::decode_packet_number_checked(space.largest_recv_pn, trunc_pn, pn_len);
    // RFC 9000 Section 12.3: Packet Numbers - Discard duplicate packets before payload processing.
    guard pn_ok && !is_pn_already_received(space.recv_ranges, full_pn) else { return 0, 0, false; }

    let unmasked_b0 = work_pkt[0];
    if (unmasked_b0 & 0x80) == 0 {
        hdr.key_phase = (unmasked_b0 & 0x04) != 0;
    }
    hdr.packet_number = full_pn;
    hdr.pn_length = pn_len;
    hdr.header_len = core::add_sat_u32(hdr.pn_offset, pn_len);
    return full_pn, unmasked_b0, true;
}

// Removes RFC 9001 Header Protection and AEAD-decrypts an inbound QUIC packet when space keys are installed.
// Preserves `out_plaintext` with the unencrypted payload when `keys_installed` is false for unit test vectors.
// Returns `(fatal_err: u64, ok: bool)`, where `fatal_err != 0` indicates a fatal protocol violation.
fn verify_and_decrypt_packet(
    conn:          const quic::QuicConnection&,
    space_id:      quic::PnSpaceId,
    pkt_slice:     const u8[:],
    pkt_wire_len:  i64,
    dgram_len:     i64,
    hdr:           quic::QuicHeader&,
    out_plaintext: u8[..16384]&,
) -> u64, bool {
    var space .= conn.app_space;
    if space_id == quic::PnSpaceId.Initial {
        space .= conn.initial_space;
    } else if space_id == quic::PnSpaceId.Handshake {
        space .= conn.handshake_space;
    }
    if !get_rx_space_keys_installed(conn, space_id) {
        return verify_unencrypted_test_packet(conn, space, pkt_slice, pkt_wire_len, hdr, out_plaintext);
    }

    let is_srv_init = hdr.header_type == quic::QuicHeaderType.Initial && conn.role == quic::QuicRole.Server;
    guard (!is_srv_init || dgram_len >= 1200) && is_valid_inbound_dcid(conn, hdr) else { return 0, false; }

    var work_pkt: u8[..16512] = [];
    guard pkt_wire_len > 0 && work_pkt.try_append(pkt_slice[..pkt_wire_len]) else { return 0, false; }

    let saved_hdr = hdr;
    let full_pn, unmasked_b0, ok_hp = unprotect_packet_header(space, work_pkt[..], hdr);
    guard ok_hp else { return 0, false; }

    let hdr_end = hdr.header_len as i64;
    guard hdr_end < work_pkt.len
        && quic_aead_open_payload(space, full_pn, work_pkt[..hdr_end], work_pkt[hdr_end..], out_plaintext) else {
        hdr = saved_hdr;
        return 0, false;
    }

    let post_err = validate_decrypted_packet_bits(conn, hdr, unmasked_b0);
    guard post_err == 0 else {
        hdr = saved_hdr;
        out_plaintext.clear();
        return post_err, false;
    }
    return 0, true;
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

// Processes a single QUIC packet slice extracted from an inbound UDP datagram.
fn process_single_coalesced_packet(
    conn:      quic::QuicConnection&,
    pkt_slice: const u8[:],
    dgram_len: i64,
    now_us:    u64,
    out_ack:   quic::AckFrame&,
) -> i64, quic::ProcessResult {
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

    if hdr.header_type == quic::QuicHeaderType.VersionNegotiation
        || hdr.header_type == quic::QuicHeaderType.Retry {
        let res_pkt = dispatch_packet_type(conn, hdr, out_ack);
        guard res_pkt.handled else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }
        conn.packets_rx = core::add_sat_u64(conn.packets_rx, 1);
        return pkt_wire_len, res_pkt;
    }

    let space_id = header_type_to_space_id(hdr.header_type);
    var plaintext_payload: u8[..16384] = [];
    let fatal_err, ok_dec = verify_and_decrypt_packet(
        conn, space_id, pkt_slice, pkt_wire_len, dgram_len, hdr, plaintext_payload,
    );
    guard ok_dec else {
        handle_packet_decrypt_failure(conn, hdr, pkt_slice, fatal_err);
        return 0, quic::ProcessResult { handled: false, needs_ack: false };
    }

    let res_frames = quic::process_payload(conn, plaintext_payload[..], hdr.header_type, now_us);
    guard res_frames.handled else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }

    conn.packets_rx = core::add_sat_u64(conn.packets_rx, 1);
    bind_initial_server_cids(conn, hdr);
    if quic_conn_is_closing_or_closed(conn.state) {
        return pkt_wire_len, quic::ProcessResult { handled: true, needs_ack: false };
    }
    let res_pkt = dispatch_packet_type(conn, hdr, out_ack);
    guard res_pkt.handled else { return 0, quic::ProcessResult { handled: false, needs_ack: false }; }
    return pkt_wire_len, quic::ProcessResult { handled: true, needs_ack: res_frames.needs_ack };
}
