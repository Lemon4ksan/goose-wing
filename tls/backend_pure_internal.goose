// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal PureGoose sans-IO TLS 1.3 endpoint slot storage, record framing, and key setup.
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

const MAX_PURE_TLS_SLOTS: i64 = 4096;

enum PureHsStage {
    ClientInit,
    ClientWaitServerHello,
    ClientWaitEE,
    ClientWaitCert,
    ClientWaitCV,
    ClientWaitFinished,
    ServerWaitClientHello,
    ServerWaitClientCert,
    ServerWaitClientCV,
    ServerWaitClientFinished,
    Established,
    Failed,
}

struct PureTlsSlot {
    in_use:                 bool                  = false,
    generation:             u32                   = 0,
    is_server:              bool                  = false,
    require_client_cert:    bool                  = false,
    insecure_skip_verify:   bool                  = false,
    use_system_roots:       bool                  = true,
    enable_pq_hybrid:       bool                  = false,
    enable_session_tickets: bool                  = true,
    require_ocsp_stapling:  bool                  = false,
    has_psk_ticket:         bool                  = false,
    psk_resumed:            bool                  = false,
    hrr_sent:               bool                  = false,
    psk_hash_len:           u8                    = 32,
    hrr_group:              u16                   = 0,
    hrr_cipher:             u16                   = 0,
    hrr_sid:                u8[..32]              = [],
    peer_closed:            bool                  = false,
    stage:                  PureHsStage           = PureHsStage.ClientInit,
    cipher_slot:            u16                   = 0xFFFF,
    cipher_suite:           u16                   = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
    key_len:                u16                   = 16,
    server_name:            u8[..256]             = [],
    alpn_csv:               u8[..64]              = [],
    selected_alpn:          u8[..64]              = [],
    cert_der:               u8[..4096]            = [],
    extra_certs_der:        u8[..4096][..3]       = [],
    key_kind:               tls::PrivateKeyKind   = tls::PrivateKeyKind.Unknown,
    rsa_key_slot:           i32                   = -1,
    priv_seed:              u8[32]                = [0; 32],
    trust_store:            tls::TrustAnchorStore = tls::TrustAnchorStore { .. },
    crl_der:                u8[..4096]            = [],
    keylog_file:            u8[..256]             = [],
    client_random:          u8[32]                = [0; 32],
    eph_priv:               u8[32]                = [0; 32],
    pq_priv:                u8[2400]              = [0; 2400],
    psk_secret:             u8[..48]              = [],
    hs_tx_key:              u8[32]                = [0; 32],
    hs_tx_iv:               u8[12]                = [0; 12],
    hs_rx_key:              u8[32]                = [0; 32],
    hs_rx_iv:               u8[12]                = [0; 12],
    hs_tx_seq:              u64                   = 0,
    hs_rx_seq:              u64                   = 0,
    ccs_seen:               u32                   = 0,
    transcript:             tls::Transcript       = tls::Transcript { .. },
    ks:                     KeySchedule           = KeySchedule { .. },
    srv_fin_hash:           u8[..48]              = [],
    peer_cert_body:         u8[..20480]           = [],
    peer_leaf_der:          u8[..8192]            = [],
    hs_plain:               u8[..20480]           = [],
    hs_plain_pos:           i64                   = 0,
    wire_in:                u8[..32768]           = [],
    wire_out:               u8[..32768]           = [],
    app_in:                 u8[..16640]           = [],
    app_in_pos:             i64                   = 0,
}

var g_pure_tls_slots: PureTlsSlot[>..] = [];

var g_pure_tls_active: i64 = 0;

var g_pure_tls_next_gen: u32 = 0;

inline fn is_live_pure_slot(slot: const PureTlsSlot&, gen: u32) -> bool {
    return slot.in_use && slot.generation == gen && gen != 0;
}

fn wipe_pure_hs_secrets(slot: PureTlsSlot&) {
    core::secure_zeroize_32(slot.eph_priv);
    core::secure_zeroize_slice(slot.pq_priv[..]);
    core::secure_zeroize_slice(slot.psk_secret[..]);
    slot.psk_secret.clear();
    core::secure_zeroize_32(slot.hs_tx_key);
    core::secure_zeroize_32(slot.hs_rx_key);
    core::secure_zeroize_slice(slot.hs_tx_iv[..]);
    core::secure_zeroize_slice(slot.hs_rx_iv[..]);
    ks_zeroize(slot.ks);
    core::secure_zeroize_slice(slot.srv_fin_hash[..]);
    slot.srv_fin_hash.clear();
}

fn reset_and_wipe_pure_slot(slot: PureTlsSlot&) {
    if slot.in_use {
        g_pure_tls_active = core::sub_sat_i64(g_pure_tls_active, 1);
    }
    if slot.cipher_slot != 0xFFFF {
        tls::free_cipher_slot(slot.cipher_slot);
    }
    if slot.rsa_key_slot >= 0 {
        tls::release_rsa_key_slot(slot.rsa_key_slot);
    }
    wipe_pure_hs_secrets(slot);
    core::secure_zeroize_32(slot.priv_seed);
    core::secure_zeroize_slice(slot.wire_in[..]);
    core::secure_zeroize_slice(slot.wire_out[..]);
    core::secure_zeroize_slice(slot.app_in[..]);
    core::secure_zeroize_slice(slot.hs_plain[..]);
    slot = PureTlsSlot { .. };
}

fn alloc_pure_tls_slot() -> i32, u32 {
    let gen = if g_pure_tls_next_gen == 0xFFFFFFFF { 1 } else { core::add_sat_u32(g_pure_tls_next_gen, 1) };
    g_pure_tls_next_gen = gen;
    if g_pure_tls_active == g_pure_tls_slots.len {
        guard g_pure_tls_slots.len < MAX_PURE_TLS_SLOTS else { return -1, 0; }
        let idx = g_pure_tls_slots.len;
        g_pure_tls_slots.push(PureTlsSlot { in_use: true, generation: gen, .. });
        g_pure_tls_active = core::add_sat_i64(g_pure_tls_active, 1);
        return idx as i32, gen;
    }
    for i in g_pure_tls_slots.len {
        let slot .= g_pure_tls_slots[i];
        if !slot.in_use {
            reset_and_wipe_pure_slot(slot);
            slot.in_use = true;
            slot.generation = gen;
            g_pure_tls_active = core::add_sat_i64(g_pure_tls_active, 1);
            return i as i32, gen;
        }
    }
    return -1, 0;
}

// Decodes RFC 7301 length-prefixed ALPN wire bytes into comma-separated protocol names.
// Falls back to copying raw ASCII CSV if the input is not length-prefixed wire format.
//
// Example:
//   alpn_wire = [0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1']
//   out_csv = "h2,http/1.1"
fn decode_alpn_wire_to_csv(alpn_wire: const u8[:], out_csv: u8[..64]&) {
    out_csv.clear();
    guard alpn_wire.len > 0 else { return; }
    var c = core::cursor_from(alpn_wire);
    var parsed: u8[..64] = [];
    var ok_wire = true;
    while c.buf.len > 0 {
        let proto, ok = c.read_u8_prefixed();
        if !ok || proto.len == 0 {
            ok_wire = false;
            break;
        }
        if parsed.len > 0 && !parsed.try_push(',') {
            ok_wire = false;
            break;
        }
        if !parsed.try_append(proto) {
            ok_wire = false;
            break;
        }
    }
    if ok_wire && parsed.len > 0 {
        let _ = out_csv.try_set(parsed[..]);
        return;
    }
    let take = min(alpn_wire.len, out_csv.cap);
    let _ = out_csv.try_set(alpn_wire[..take]);
}

fn pure_append_plaintext_hs(
    out:              u8[..32768]&,
    hs_msg:           const u8[:],
    legacy_ver_minor: u8 = 0x03,
) -> bool {
    guard hs_msg.len > 0 && hs_msg.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    let saved = out.len;
    var committed = false;
    defer if !committed { out.resize(saved); };
    guard out.try_push(rfc::TLS_CONTENT_HANDSHAKE) &&
        out.try_push(0x03) &&
        out.try_push(legacy_ver_minor) else {
        return false;
    }
    let len_u16 = hs_msg.len as u16;
    guard out.try_push(((len_u16 >> 8) & 0xFF) as u8) &&
        out.try_push((len_u16 & 0xFF) as u8) &&
        out.try_append(hs_msg) else {
        return false;
    }
    committed = true;
    return true;
}

fn pure_seal_hs_to_wire(slot: PureTlsSlot&, hs_msg: const u8[:]) -> bool {
    guard hs_msg.len > 0 else { return false; }
    let klen = slot.key_len as i64;
    var ct_buf: u8[16640] = [0; 16640];
    var off:    i64       = 0;
    while off < hs_msg.len {
        let rem = core::sub_sat_i64(hs_msg.len, off);
        let chunk_len = min(rfc::TLS_MAX_RECORD_PLAINTEXT_LEN, rem);
        let end_off = core::add_sat_i64(off, chunk_len);
        let needed = core::add_sat_i64(chunk_len, 32);
        guard needed <= ct_buf.len else { return false; }
        let s_len, _, ok_s = tls::record_seal_into(
            slot.cipher_suite,
            slot.hs_tx_key[..klen],
            slot.hs_tx_iv,
            slot.hs_tx_seq,
            rfc::TLS_CONTENT_HANDSHAKE,
            hs_msg[off..end_off],
            ct_buf[..needed],
        );
        guard ok_s && s_len > 0 && slot.wire_out.try_append(ct_buf[..s_len]) else { return false; }
        guard tls::increment_record_seq_num(slot.hs_tx_seq) else { return false; }
        off = end_off;
    }
    return true;
}

// Validates a single RFC 8446 Section 5 middlebox-compatibility ChangeCipherSpec record.
fn pure_accept_ccs_record(slot: PureTlsSlot&, ver: u16, body: const u8[:]) -> bool {
    guard slot.ccs_seen < 1 &&
        slot.hs_plain.len == 0 &&
        ver == rfc::TLS_LEGACY_VERSION_1_2 &&
        tls::validate_change_cipher_spec_record(body) == tls::Alert.CloseNotify else {
        return false;
    }
    slot.ccs_seen = core::add_sat_u32(slot.ccs_seen, 1);
    return true;
}

fn pure_pop_plaintext_hs_msg(slot: PureTlsSlot&, out_msg: u8[..16384]&) -> tls::TlsBackendStatus {
    out_msg.clear();
    while true {
        if has_complete_plaintext_handshake_msg(slot.hs_plain[..]) {
            let _, mlen, ok_h = tls::parse_handshake_header(slot.hs_plain[..]);
            guard ok_h else { return tls::TlsBackendStatus.HandshakeError; }
            let full_len = core::add_sat_i64(4, mlen);
            guard out_msg.try_set(slot.hs_plain[..full_len]) else { return tls::TlsBackendStatus.Error; }
            slot.hs_plain.compact_wire_buffer(full_len);
            return tls::TlsBackendStatus.Ok;
        }
        guard slot.wire_in.len >= 5 else { return tls::TlsBackendStatus.WantRead; }
        let ct, ver, plen_u16, _, ok_hdr = tls::parse_record_header(slot.wire_in[..5]);
        guard ok_hdr else { return tls::TlsBackendStatus.HandshakeError; }
        let plen = plen_u16 as i64;
        let rec_total = core::add_sat_i64(5, plen);
        guard plen <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return tls::TlsBackendStatus.HandshakeError; }
        guard slot.wire_in.len >= rec_total else { return tls::TlsBackendStatus.WantRead; }
        let body = slot.wire_in[5..rec_total];
        if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
            guard pure_accept_ccs_record(slot, ver, body) else { return tls::TlsBackendStatus.HandshakeError; }
            slot.wire_in.compact_wire_buffer(rec_total);
            continue;
        }
        guard ct == rfc::TLS_CONTENT_HANDSHAKE && slot.hs_plain.try_append(body) else {
            return tls::TlsBackendStatus.HandshakeError;
        }
        slot.wire_in.compact_wire_buffer(rec_total);
    }
    return tls::TlsBackendStatus.WantRead;
}

fn pure_try_consume_hs_plain_msg<B>(
    slot:     PureTlsSlot&,
    out_type: u8&,
    out_body: B&,
) -> bool {
    let rem = core::sub_sat_i64(slot.hs_plain.len, slot.hs_plain_pos);
    guard rem >= 4 else { return false; }
    let slice = slot.hs_plain[slot.hs_plain_pos..];
    let mt, mlen, ok_h = tls::parse_handshake_header(slice);
    guard ok_h else { return false; }
    let total = core::add_sat_i64(4, mlen);
    guard rem >= total && out_body.try_set(slice[4..total]) else { return false; }
    out_type = mt;
    slot.hs_plain_pos = core::add_sat_i64(slot.hs_plain_pos, total);
    if slot.hs_plain_pos >= slot.hs_plain.len {
        slot.hs_plain.clear();
        slot.hs_plain_pos = 0;
    }
    return true;
}

fn pure_decrypt_one_hs_record(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    guard slot.wire_in.len >= 5 else { return tls::TlsBackendStatus.WantRead; }
    let ct, ver, plen_u16, _, ok_hdr = tls::parse_record_header(slot.wire_in[..5]);
    guard ok_hdr else { return tls::TlsBackendStatus.HandshakeError; }
    let plen = plen_u16 as i64;
    let rec_total = core::add_sat_i64(5, plen);
    guard plen <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else { return tls::TlsBackendStatus.HandshakeError; }
    guard slot.wire_in.len >= rec_total else { return tls::TlsBackendStatus.WantRead; }

    if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
        let ccs_ok = slot.ccs_seen < 1 &&
            slot.hs_plain_pos == slot.hs_plain.len &&
            ver == rfc::TLS_LEGACY_VERSION_1_2 &&
            tls::validate_change_cipher_spec_record(slot.wire_in[5..rec_total]) == tls::Alert.CloseNotify;
        guard ccs_ok else { return tls::TlsBackendStatus.HandshakeError; }
        slot.ccs_seen = core::add_sat_u32(slot.ccs_seen, 1);
        slot.wire_in.compact_wire_buffer(rec_total);
        return tls::TlsBackendStatus.Ok;
    }
    guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return tls::TlsBackendStatus.HandshakeError; }

    if slot.hs_plain_pos > 0 {
        slot.hs_plain.compact_wire_buffer(slot.hs_plain_pos);
        slot.hs_plain_pos = 0;
    }
    var plain_dec: u8[16640] = [0; 16640];
    defer core::secure_zeroize_slice(plain_dec[..plen]);
    let klen = slot.key_len as i64;
    let dec_len, inner_t, _, ok_dec = tls::record_decrypt_into(
        slot.cipher_suite,
        slot.hs_rx_key[..klen],
        slot.hs_rx_iv,
        slot.hs_rx_seq,
        slot.wire_in[..5],
        slot.wire_in[5..rec_total],
        plain_dec[..plen],
    );
    guard ok_dec && inner_t == rfc::TLS_CONTENT_HANDSHAKE && dec_len > 0 else {
        return tls::TlsBackendStatus.HandshakeError;
    }
    let _ = tls::increment_record_seq_num(slot.hs_rx_seq);
    slot.wire_in.compact_wire_buffer(rec_total);
    guard slot.hs_plain.try_append(plain_dec[..dec_len]) else { return tls::TlsBackendStatus.Error; }
    return tls::TlsBackendStatus.Ok;
}

fn pure_next_encrypted_hs_msg<B>(
    slot:     PureTlsSlot&,
    out_type: u8&,
    out_body: B&,
) -> tls::TlsBackendStatus {
    while true {
        if pure_try_consume_hs_plain_msg(slot, out_type, out_body) {
            return tls::TlsBackendStatus.Ok;
        }
        let st = pure_decrypt_one_hs_record(slot);
        guard st == tls::TlsBackendStatus.Ok else { return st; }
    }
    return tls::TlsBackendStatus.WantRead;
}

fn pure_derive_hs_traffic_keys(
    slot:         PureTlsSlot&,
    ecdhe_secret: const u8[:],
    early_ikm:    const u8[:] = "",
) -> bool {
    var ks, ok_ks = ks_init(slot.cipher_suite);
    defer ks_zeroize(ks);
    guard ok_ks &&
        ks_init_early_secret(ks, early_ikm) &&
        ks_advance_to_handshake(ks, ecdhe_secret) else {
        return false;
    }
    var ch_sh_hash: u8[..48] = [];
    transcript_current_hash(slot.transcript, ks.hash_id, ch_sh_hash);
    guard ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        return false;
    }
    let klen_u16 = rfc::tls13_cipher_suite_key_len(slot.cipher_suite);
    let klen = klen_u16 as i64;
    let hlen = ks.hash_len as i64;
    let tx_sec = if slot.is_server { ks.server_hs_traffic[..hlen] } else { ks.client_hs_traffic[..hlen] };
    let rx_sec = if slot.is_server { ks.client_hs_traffic[..hlen] } else { ks.server_hs_traffic[..hlen] };
    let ok_tx = ks_derive_key_iv(ks.hash_id, tx_sec, klen_u16, slot.hs_tx_key[..klen], slot.hs_tx_iv);
    let ok_rx = ks_derive_key_iv(ks.hash_id, rx_sec, klen_u16, slot.hs_rx_key[..klen], slot.hs_rx_iv);
    guard ok_tx && ok_rx else {
        return false;
    }
    slot.key_len = klen_u16;
    slot.ks = ks;
    slot.hs_tx_seq = 0;
    slot.hs_rx_seq = 0;
    emit_tls13_hs_keylog(slot.keylog_file[..], slot.client_random, slot.ks);
    return true;
}

fn pure_install_app_keys(slot: PureTlsSlot&) -> bool {
    let cs_idx = tls::alloc_cipher_slot();
    guard cs_idx != 0xFFFF else { return false; }
    let klen_u16 = slot.key_len;
    let klen = klen_u16 as i64;
    let hlen = slot.ks.hash_len as i64;
    var c_ap_key: u8[32] = [0; 32];
    var s_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(c_ap_key);
    defer core::secure_zeroize_32(s_ap_key);
    var c_ap_iv: u8[12] = [0; 12];
    var s_ap_iv: u8[12] = [0; 12];
    let ok_c = ks_derive_key_iv(
        slot.ks.hash_id, slot.ks.client_ap_traffic[..hlen], klen_u16, c_ap_key[..klen], c_ap_iv,
    );
    let ok_s = ks_derive_key_iv(
        slot.ks.hash_id, slot.ks.server_ap_traffic[..hlen], klen_u16, s_ap_key[..klen], s_ap_iv,
    );
    guard ok_c && ok_s else {
        tls::free_cipher_slot(cs_idx);
        return false;
    }
    emit_tls13_app_keylog(slot.keylog_file[..], slot.client_random, slot.ks);
    let c_slot_i = cs_idx as i64;
    if slot.is_server {
        tls_setup_server_cipher_slot(
            cs_idx, slot.cipher_suite, klen_u16, slot.ks,
            s_ap_key[..klen], s_ap_iv, c_ap_key[..klen], c_ap_iv,
        );
        if c_slot_i >= 0 && c_slot_i < tls::g_tls_cipher_slots.len {
            let _ = tls::g_tls_cipher_slots[c_slot_i].negotiated_alpn.try_set(slot.selected_alpn[..]);
            tls::g_tls_cipher_slots[c_slot_i].client_authenticated = slot.require_client_cert;
        }
    } else {
        tls_setup_client_cipher_slot(
            cs_idx, slot.cipher_suite, klen_u16, slot.ks,
            c_ap_key[..klen], c_ap_iv, s_ap_key[..klen], s_ap_iv,
            slot.server_name[..], slot.selected_alpn[..], slot.psk_resumed,
        );
        if c_slot_i >= 0 && c_slot_i < tls::g_tls_cipher_slots.len {
            tls::g_tls_cipher_slots[c_slot_i].enable_session_tickets = slot.enable_session_tickets;
        }
    }
    slot.cipher_slot = cs_idx;
    wipe_pure_hs_secrets(slot);
    slot.stage = PureHsStage.Established;
    return true;
}

// Unseals at most one complete TLS record from `slot.wire_in` into `slot.app_in` so pipelined
// records never overflow the 16640-byte plaintext buffer.
fn pure_unseal_one_app_record(slot: PureTlsSlot&) -> tls::TlsBackendStatus {
    let rec_total, peek_st = peek_ciphertext_record_len(slot.wire_in[..]);
    if peek_st == tls::SliceUnsealStatus.NeedMore { return tls::TlsBackendStatus.WantRead; }
    guard peek_st == tls::SliceUnsealStatus.Ok && rec_total > 0 else { return tls::TlsBackendStatus.Error; }
    slot.app_in.clear();
    slot.app_in_pos = 0;
    let consumed, ust = tls::cipher_slot_unseal_records(slot.cipher_slot, slot.wire_in[..rec_total], slot.app_in);
    if consumed > 0 { slot.wire_in.compact_wire_buffer(consumed); }
    if ust == tls::SliceUnsealStatus.Closed {
        slot.peer_closed = true;
        return tls::TlsBackendStatus.Closed;
    }
    if ust == tls::SliceUnsealStatus.Error { return tls::TlsBackendStatus.Error; }
    return tls::TlsBackendStatus.Ok;
}
