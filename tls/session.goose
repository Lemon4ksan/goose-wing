// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TLS 1.3 Transport Session, Handshake Orchestrator, and Cipher Slot Storage.
// Conforms to RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN), and RFC 5280 / RFC 6125 (X.509 PKI).
namespace wing;

import std;
import core from "..";
import .record;
import .key_schedule;
import .handshake;
import .asn1;
import .sct;
import .x509;
import .ocsp;
import .crl;
import .ticket;
import .post_quantum;
import .cert_compression;
import .ech;
import net.tcp;
import net.transport;
import net.driver.smartnic;

// ---- Streaming TLS 1.3 Transcript Hash Context (RFC 8446 §4.4.1) ----------

struct TlsTranscript {
    sha256_ctx: core::Sha256Ctx = core::Sha256Ctx { .. },
    sha384_ctx: core::Sha384Ctx = core::Sha384Ctx { .. },
}

fn transcript_update(t: TlsTranscript&, data: const u8[:]) {
    core::sha256_update(t.sha256_ctx, data);
    core::sha384_update(t.sha384_ctx, data);
}

fn transcript_update_msg(t: TlsTranscript&, msg_type: u8, body: const u8[:]) {
    var hdr: u8[4] = [0; 4];
    hdr[0] = msg_type;
    hdr[1] = ((body.len >> 16) & 0xFF) as u8;
    hdr[2] = ((body.len >> 8) & 0xFF) as u8;
    hdr[3] = (body.len & 0xFF) as u8;
    transcript_update(t, hdr[..]);
    transcript_update(t, body);
}

fn transcript_current_hash(t: const TlsTranscript&, hash_id: u8, out_hash: u8[..48]&) {
    out_hash.clear();
    if hash_id == tls_internal::HASH_SHA384 {
        var ctx = t.sha384_ctx;
        let h = core::sha384_final(ctx);
        out_hash.append(h[..]);
    } else {
        var ctx = t.sha256_ctx;
        let h = core::sha256_final(ctx);
        out_hash.append(h[..]);
    }
}

// Replaces transcript state with synthetic message_hash after HelloRetryRequest (RFC 8446 §4.4.1).
fn transcript_replace_with_message_hash(t: TlsTranscript&, hash_id: u8, hash_len: u8) -> bool {
    var ch1_hash: u8[..48] = [];
    transcript_current_hash(t, hash_id, ch1_hash);
    var synth: u8[64] = [0; 64];
    let synth_len, ok_s = compress_hrr_transcript(hash_len, ch1_hash[..], synth[..]);
    guard ok_s else { return false; }
    t.sha256_ctx = core::Sha256Ctx { .. };
    t.sha384_ctx = core::Sha384Ctx { .. };
    transcript_update(t, synth[..synth_len]);
    return true;
}

// ---- Stateful Entropy Generator (RFC 8446 Appendix C.1, Invariant 16) ------

extern fn native_tls_csprng_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

var g_tls_entropy_pool:    u8[32] = [0; 32];
var g_tls_entropy_counter: u64    = 0;

// Mixes OS kernel CSPRNG (`RtlGenRandom` / `getrandom`), hardware monotonic timer, wall clock,
// entropy pool, and sequence counter using Fast-Key-Erasure / NIST SP 800-90A domain-separated
// SHA-256 ratcheting (Invariant 16).
fn tls_random_bytes_32() -> u8[32] {
    var os_seed: u8[32] = [0; 32];
    if native_tls_csprng_bytes(os_seed[..]) == 0 {
        for i in 32 {
            g_tls_entropy_pool[i] ^= os_seed[i];
        }
    }
    core::secure_zeroize_32(os_seed);

    g_tls_entropy_counter = core::add_sat_u64(g_tls_entropy_counter, 1);
    let mono_ns = core::monotonic_now().nanos;
    let wall_now = core::now();
    let wall_sec = wall_now.wall_sec as u64;
    let wall_nsec = (wall_now.nsec as u64) & 0xFFFFFFFF;

    var mix: u8[64] = [0; 64];
    core::ct_copy_bytes(mix[0..32], g_tls_entropy_pool[..]);
    core::write_le_u64_at(mix[..], 32, g_tls_entropy_counter);
    core::write_le_u64_at(mix[..], 40, mono_ns);
    core::write_le_u64_at(mix[..], 48, wall_sec);
    core::write_le_u32_at(mix[..], 56, wall_nsec as! u32);
    mix[60] = 0x01;
    let out_bytes = core::sha256(mix[..]);

    core::ct_copy_bytes(mix[0..32], g_tls_entropy_pool[..]);
    mix[60] = 0x02;
    for i in 32 {
        mix[32 + i] ^= out_bytes[i];
    }
    g_tls_entropy_pool = core::sha256(mix[..]);
    core::secure_zeroize_64(mix);
    return out_bytes;
}

// ---- Global Lazy Cipher Slot Table (Grow-on-Demand, Zero Startup Faults) ----

const MAX_TLS_CIPHER_SLOTS: i64 = 256;

enum TlsSliceUnsealStatus {
    Ok,
    NeedMore,
    Closed,
    ControlHandled,
    Error,
}

struct TlsCipherSlot {
    in_use:             bool               = false,
    is_server:          bool               = false,
    ktls_tx_active:     bool               = false,
    ktls_rx_active:     bool               = false,
    cipher_suite:       u16                = 0,
    hash_id:            u8                 = 1,
    hash_len:           u8                 = 32,
    key_len:            u16                = 16,
    rx_seq:             u64                = 0,
    tx_seq:             u64                = 0,
    rx_key:             u8[32]             = [0; 32],
    tx_key:             u8[32]             = [0; 32],
    rx_aes_key:         core::AesGcmKey    = core::AesGcmKey { .. },
    tx_aes_key:         core::AesGcmKey    = core::AesGcmKey { .. },
    rx_iv:              u8[12]             = [0; 12],
    tx_iv:              u8[12]             = [0; 12],
    rx_traffic_secret:  u8[48]             = [0; 48],
    tx_traffic_secret:  u8[48]             = [0; 48],
    exporter_secret:    u8[48]             = [0; 48],
    resumption_secret:  u8[48]             = [0; 48],
    peer_closed:        bool               = false,
    resumed:            bool               = false,
    negotiated_alpn:    u8[..255]          = [],
    server_name:        u8[..256]          = [],
    san_hosts:          u8[..128][..8]     = [],
    rx_plain_buf:       u8[..16384]        = [],
    rx_plain_pos:       i64                = 0,
    bytes_sent:         u64                = 0,
    key_update_tracker: KeyUpdateTracker   = KeyUpdateTracker { .. },
    ticket_cache:       SessionTicketCache = SessionTicketCache { .. },
}

var g_tls_cipher_slots: TlsCipherSlot[>..] = [];

// Returns the ALPN protocol negotiated on a cipher slot (empty if none).
inline fn tls_session_alpn(slot_idx: u16) -> const u8[:] {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return ""; }
    return g_tls_cipher_slots[idx].negotiated_alpn[..];
}

// Returns true if the TLS 1.3 session was established via PSK resumption.
inline fn tls_session_is_resumed(slot_idx: u16) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }
    return g_tls_cipher_slots[idx].resumed;
}

// Wipes all cryptographic keys, IVs, traffic secrets, ticket cache material, and buffered
// plaintext in `slot` and resets metadata fields to inactive defaults (Invariant 11).
fn wipe_and_reset_tls_cipher_slot(slot: TlsCipherSlot&) {
    core::secure_zeroize_32(slot.rx_key);
    core::secure_zeroize_32(slot.tx_key);
    core::zeroize_aes_gcm_key(slot.rx_aes_key);
    core::zeroize_aes_gcm_key(slot.tx_aes_key);
    core::secure_zeroize_slice(slot.rx_iv[..]);
    core::secure_zeroize_slice(slot.tx_iv[..]);
    core::secure_zeroize_48(slot.rx_traffic_secret);
    core::secure_zeroize_48(slot.tx_traffic_secret);
    core::secure_zeroize_48(slot.exporter_secret);
    core::secure_zeroize_48(slot.resumption_secret);
    core::secure_zeroize_slice(slot.rx_plain_buf[..]);
    for &t in slot.ticket_cache.tickets {
        core::secure_zeroize_slice(t.ticket_nonce[..]);
        core::secure_zeroize_slice(t.ticket[..]);
    }
    slot.in_use = false;
    slot.is_server = false;
    slot.ktls_tx_active = false;
    slot.ktls_rx_active = false;
    slot.cipher_suite = 0;
    slot.hash_id = 1;
    slot.hash_len = 32;
    slot.key_len = 16;
    slot.rx_seq = 0;
    slot.tx_seq = 0;
    slot.peer_closed = false;
    slot.resumed = false;
    slot.negotiated_alpn.clear();
    slot.server_name.clear();
    slot.san_hosts.clear();
    slot.rx_plain_buf.clear();
    slot.rx_plain_pos = 0;
    slot.bytes_sent = 0;
    slot.key_update_tracker = KeyUpdateTracker { .. };
    slot.ticket_cache = SessionTicketCache { .. };
}

// Allocates a cipher slot lazily: reuses an inactive slot first, otherwise grows `g_tls_cipher_slots`
// up to `MAX_TLS_CIPHER_SLOTS`.
fn alloc_tls_cipher_slot() -> u16 {
    for i in g_tls_cipher_slots.len {
        let slot .= g_tls_cipher_slots[i];
        if !slot.in_use {
            wipe_and_reset_tls_cipher_slot(slot);
            slot.in_use = true;
            return (i & 0xFFFF) as u16;
        }
    }
    guard g_tls_cipher_slots.len < MAX_TLS_CIPHER_SLOTS else { return 0xFFFF; }
    let new_idx = g_tls_cipher_slots.len;
    g_tls_cipher_slots.push(TlsCipherSlot { in_use: true, .. });
    return (new_idx & 0xFFFF) as u16;
}

inline fn tls_prepare_cipher_aes_key(cipher_suite: u16, key: const u8[:], ctx: core::AesGcmKey&) {
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 || cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        let _ = core::aes_gcm_prepare_key(key, ctx);
    } else {
        core::zeroize_aes_gcm_key(ctx);
    }
}

// Releases a cipher slot and securely wipes all cryptographic key material.
fn free_tls_cipher_slot(slot_idx: u16) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return; }
    wipe_and_reset_tls_cipher_slot(g_tls_cipher_slots[idx]);
}

fn tls_init_cipher_slot_for_test(
    slot_idx:     u16,
    cipher_suite: u16,
    tx_key:       const u8[:],
    tx_iv:        const u8[12]&,
    rx_key:       const u8[:],
    rx_iv:        const u8[12]&,
) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return; }
    let slot .= g_tls_cipher_slots[idx];
    let klen: i64 = if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 ||
        cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        32
    } else {
        16
    };
    guard tx_key.len >= klen && rx_key.len >= klen else { return; }
    slot.cipher_suite = cipher_suite;
    slot.key_len = klen as u16;
    slot.hash_id = if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        tls_internal::HASH_SHA384
    } else {
        tls_internal::HASH_SHA256
    };
    slot.hash_len = if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 { 48 } else { 32 };
    slot.ktls_tx_active = false;
    slot.ktls_rx_active = false;
    slot.peer_closed = false;
    slot.tx_seq = 0;
    slot.rx_seq = 0;
    core::secure_zeroize_32(slot.tx_key);
    core::secure_zeroize_32(slot.rx_key);
    for i in klen { slot.tx_key[i] = tx_key[i]; }
    tls_prepare_cipher_aes_key(cipher_suite, tx_key[..klen], slot.tx_aes_key);
    for i in 12 { slot.tx_iv[i] = tx_iv[i]; }
    for i in klen { slot.rx_key[i] = rx_key[i]; }
    tls_prepare_cipher_aes_key(cipher_suite, rx_key[..klen], slot.rx_aes_key);
    for i in 12 { slot.rx_iv[i] = rx_iv[i]; }
}

fn tls_try_enable_ktls(slot_idx: u16, fd: i64) -> net_internal::SmartNicSession, bool {
    guard fd > 0 && !is_virtual_pipe_fd(fd) else {
        return net_internal::new_smartnic_session(fd), false;
    }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else {
        return net_internal::new_smartnic_session(fd), false;
    }
    let slot .= g_tls_cipher_slots[idx];
    guard slot.in_use && !slot.peer_closed && slot.rx_plain_pos >= slot.rx_plain_buf.len else {
        return net_internal::new_smartnic_session(fd), false;
    }
    var nic_cipher = net_internal::SmartNicCipherSuite.AesGcm128;
    if slot.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        nic_cipher = net_internal::SmartNicCipherSuite.AesGcm128;
    } else if slot.cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        nic_cipher = net_internal::SmartNicCipherSuite.AesGcm256;
    } else {
        return net_internal::new_smartnic_session(fd), false;
    }
    let klen = slot.key_len as i64;
    var tx_seq_be: u8[8] = [0; 8];
    var rx_seq_be: u8[8] = [0; 8];
    core::write_be_u64_at(tx_seq_be[..], 0, slot.tx_seq);
    core::write_be_u64_at(rx_seq_be[..], 0, slot.rx_seq);
    defer core::secure_zeroize_slice(tx_seq_be[..]);
    defer core::secure_zeroize_slice(rx_seq_be[..]);

    let sess, err = net_internal::smartnic_attach_hardware_tls(
        fd,
        nic_cipher,
        slot.tx_key[..klen],
        slot.tx_iv[4..12],
        slot.tx_iv[0..4],
        tx_seq_be[..],
        slot.rx_key[..klen],
        slot.rx_iv[4..12],
        slot.rx_iv[0..4],
        rx_seq_be[..],
    );
    guard err == 0 && sess.ktls_active else { return sess, false; }
    slot.ktls_tx_active = sess.tx_offloaded;
    slot.ktls_rx_active = sess.rx_offloaded;
    return sess, true;
}

fn ratchet_slot_rx_traffic_keys(slot: TlsCipherSlot&) {
    let h_id = slot.hash_id;
    let h_len = slot.hash_len;
    let k_len = slot.key_len;
    let h_len_i64 = h_len as i64;
    let k_len_i64 = k_len as i64;
    tls_internal::ks_update_traffic_secret(h_id, h_len, slot.rx_traffic_secret[..h_len_i64]);
    tls_internal::ks_derive_key_iv(
        h_id,
        slot.rx_traffic_secret[..h_len_i64],
        k_len,
        slot.rx_key[..k_len_i64],
        slot.rx_iv,
    );
    tls_prepare_cipher_aes_key(slot.cipher_suite, slot.rx_key[..k_len_i64], slot.rx_aes_key);
    slot.rx_seq = 0;
}

inline fn inspect_unsealed_handshake_control(hs_bytes: const u8[:]) -> TlsSliceUnsealStatus {
    guard hs_bytes.len >= 4 else { return TlsSliceUnsealStatus.Error; }
    var rem = hs_bytes;
    while rem.len > 0 {
        guard rem.len >= 4 else { return TlsSliceUnsealStatus.Error; }
        let msg_type, msg_len, ok_m = parse_handshake_header(rem);
        guard ok_m else { return TlsSliceUnsealStatus.Error; }
        let full_len = core::add_sat_i64(4, msg_len);
        guard rem.len >= full_len else { return TlsSliceUnsealStatus.Error; }
        if msg_type == rfc::TLS_HS_KEY_UPDATE {
            return TlsSliceUnsealStatus.Closed;
        }
        guard msg_type == rfc::TLS_HS_NEW_SESSION_TICKET else {
            return TlsSliceUnsealStatus.Error;
        }
        rem = rem[full_len..];
    }
    return TlsSliceUnsealStatus.ControlHandled;
}

inline fn apply_unsealed_slot_handshake_control(slot: TlsCipherSlot&, hs_bytes: const u8[:]) -> TlsSliceUnsealStatus {
    guard hs_bytes.len >= 4 else { return TlsSliceUnsealStatus.Error; }
    var rem = hs_bytes;
    while rem.len > 0 {
        guard rem.len >= 4 else { return TlsSliceUnsealStatus.Error; }
        let msg_type, msg_len, ok_m = parse_handshake_header(rem);
        guard ok_m else { return TlsSliceUnsealStatus.Error; }
        let full_len = core::add_sat_i64(4, msg_len);
        guard rem.len >= full_len else { return TlsSliceUnsealStatus.Error; }
        let msg_body = rem[4..full_len];
        if msg_type == rfc::TLS_HS_KEY_UPDATE {
            let _, ok_ku = track_received_key_update(slot.key_update_tracker, HsState.Connected, msg_body);
            guard ok_ku else { return TlsSliceUnsealStatus.Error; }
            ratchet_slot_rx_traffic_keys(slot);
        } else if msg_type == rfc::TLS_HS_NEW_SESSION_TICKET {
            guard !slot.is_server else { return TlsSliceUnsealStatus.Error; }
            var nst = NewSessionTicketMsg { .. };
            guard parse_new_session_ticket(msg_body, nst) && cache_session_ticket(slot.ticket_cache, nst) else {
                return TlsSliceUnsealStatus.Error;
            }
        } else {
            return TlsSliceUnsealStatus.Error;
        }
        rem = rem[full_len..];
    }
    return TlsSliceUnsealStatus.ControlHandled;
}

inline fn unseal_single_slot_record<B>(
    slot:      TlsCipherSlot&,
    rec_hdr:   const u8[:],
    rec_body:  const u8[:],
    scratch:   u8[:],
    out_plain: B&,
) -> TlsSliceUnsealStatus {
    let klen = slot.key_len as i64;
    let dec_len, inner_type, _, ok_dec = tls_record_decrypt_prepared_into(
        slot.cipher_suite,
        slot.rx_key[..klen],
        slot.rx_aes_key,
        slot.rx_iv,
        slot.rx_seq,
        rec_hdr,
        rec_body,
        scratch[..rec_body.len],
    );
    guard ok_dec else { return TlsSliceUnsealStatus.Error; }
    increment_record_seq_num(slot.rx_seq);

    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        guard out_plain.try_append(scratch[..dec_len]) else { return TlsSliceUnsealStatus.Error; }
        on_key_update_app_data(slot.key_update_tracker);
        return TlsSliceUnsealStatus.Ok;
    }
    if inner_type == rfc::TLS_CONTENT_ALERT {
        let alert_level, alert_code, _, ok_a = parse_tls_alert_message(scratch[..dec_len]);
        if ok_a && alert_code == TlsAlert.CloseNotify {
            slot.peer_closed = true;
            return TlsSliceUnsealStatus.Closed;
        }
        if ok_a && alert_level == 1 && alert_code == TlsAlert.UserCanceled {
            return TlsSliceUnsealStatus.ControlHandled;
        }
        return TlsSliceUnsealStatus.Error;
    }
    if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
        let hs_st = apply_unsealed_slot_handshake_control(slot, scratch[..dec_len]);
        if hs_st == TlsSliceUnsealStatus.Closed {
            slot.peer_closed = true;
        }
        return hs_st;
    }
    return TlsSliceUnsealStatus.Error;
}

inline fn peek_ciphertext_record_len(rem: const u8[:]) -> i64, TlsSliceUnsealStatus {
    if rem.len < rfc::TLS_RECORD_HEADER_LEN {
        return 0, TlsSliceUnsealStatus.NeedMore;
    }
    let ct, _, rec_len_u16, _, ok_hdr = parse_tls_record_header(rem[..rfc::TLS_RECORD_HEADER_LEN]);
    let rec_len = rec_len_u16 as i64;
    guard ok_hdr && ct == rfc::TLS_CONTENT_APPLICATION_DATA &&
        rec_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, TlsSliceUnsealStatus.Error;
    }
    let total_rec = core::add_sat_i64(rfc::TLS_RECORD_HEADER_LEN, rec_len);
    if rem.len < total_rec {
        return 0, TlsSliceUnsealStatus.NeedMore;
    }
    return total_rec, TlsSliceUnsealStatus.Ok;
}

inline fn consume_next_ciphertext_record<B>(
    slot:      TlsCipherSlot&,
    rem:       const u8[:],
    scratch:   u8[:],
    out_plain: B&,
) -> i64, TlsSliceUnsealStatus {
    let total_rec, hdr_st = peek_ciphertext_record_len(rem);
    guard hdr_st == TlsSliceUnsealStatus.Ok else { return 0, hdr_st; }
    let rec_slice = rem[..total_rec];
    let st = unseal_single_slot_record(
        slot,
        rec_slice[..rfc::TLS_RECORD_HEADER_LEN],
        rec_slice[rfc::TLS_RECORD_HEADER_LEN..],
        scratch,
        out_plain,
    );
    return total_rec, st;
}

// Decrypts complete TLS 1.3 records from `cipher_in` into `out_plain` (RFC 8446 Section 5.2).
// Leaves trailing incomplete record bytes unconsumed so reactor buffers can compact them.
//
// Example:
//   cipher_in = <40-byte sealed "GET / HTTP/1.1\r\n\r\n" record>
//   returns: consumed = 40, status = TlsSliceUnsealStatus.Ok, out_plain = "GET / HTTP/1.1\r\n\r\n"
fn tls_cipher_slot_unseal_records<B>(
    slot_idx:  u16,
    cipher_in: const u8[:],
    out_plain: B&,
) -> i64, TlsSliceUnsealStatus {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else {
        return 0, TlsSliceUnsealStatus.Error;
    }
    let slot .= g_tls_cipher_slots[idx];
    if slot.peer_closed { return 0, TlsSliceUnsealStatus.Closed; }

    let saved_len = out_plain.len;
    var scratch: u8[16640] = [0; 16640];
    defer core::secure_zeroize_slice(scratch[..]);

    var rem = cipher_in;
    var consumed: i64 = 0;
    var final_status = TlsSliceUnsealStatus.ControlHandled;
    while rem.len > 0 {
        let total_rec, st = consume_next_ciphertext_record(slot, rem, scratch[..], out_plain);
        if st == TlsSliceUnsealStatus.NeedMore { break; }
        if st == TlsSliceUnsealStatus.Error {
            out_plain.resize(saved_len);
            return 0, TlsSliceUnsealStatus.Error;
        }
        consumed = core::add_sat_i64(consumed, total_rec);
        rem = rem[total_rec..];
        if st == TlsSliceUnsealStatus.Closed { return consumed, TlsSliceUnsealStatus.Closed; }
        if st == TlsSliceUnsealStatus.Ok { final_status = TlsSliceUnsealStatus.Ok; }
    }

    if consumed == 0 { return 0, TlsSliceUnsealStatus.NeedMore; }
    return consumed, final_status;
}

fn tls_cipher_slot_seal_app_data<B>(
    slot_idx:   u16,
    plain_in:   const u8[:],
    out_cipher: B&,
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    let slot .= g_tls_cipher_slots[idx];
    guard slot.in_use && !slot.peer_closed else { return false; }
    if plain_in.len == 0 { return true; }

    let saved_len = out_cipher.len;
    let saved_seq = slot.tx_seq;
    var committed = false;
    defer if !committed {
        out_cipher.resize(saved_len);
        slot.tx_seq = saved_seq;
    };

    var rec_buf: u8[16645] = [0; 16645];
    let klen = slot.key_len as i64;
    var rem = plain_in;
    while rem.len > 0 {
        let chunk_len = min(rem.len, rfc::TLS_MAX_RECORD_PLAINTEXT_LEN);
        let sealed_len, _, ok_seal = tls_record_seal_prepared_into(
            slot.cipher_suite,
            slot.tx_key[..klen],
            slot.tx_aes_key,
            slot.tx_iv,
            slot.tx_seq,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            rem[..chunk_len],
            rec_buf[..],
        );
        guard ok_seal && sealed_len > 0 && out_cipher.try_append(rec_buf[..sealed_len]) else {
            return false;
        }
        increment_record_seq_num(slot.tx_seq);
        rem = rem[chunk_len..];
    }
    on_key_update_app_data(slot.key_update_tracker);
    committed = true;
    return true;
}

// Extracts DNS SubjectAltName entries from a DER X.509 certificate into `g_tls_cipher_slots[slot_idx].san_hosts`.
fn tls_populate_slot_san_hosts_from_der(slot_idx: u16, cert_der: const u8[:]) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }
    var leaf_cert = ParsedCert { .. };
    guard parse_x509_certificate(cert_der, leaf_cert) else { return false; }
    var sans: SanEntry[..64] = [];
    guard get_cert_san_extension(leaf_cert, cert_der, sans) else { return false; }
    g_tls_cipher_slots[idx].san_hosts.clear();
    for &san in sans {
        guard san.san_type == SanType.Dns else { continue; }
        var h_buf: u8[..128] = [];
        if h_buf.try_set(san.val) {
            let _ = g_tls_cipher_slots[idx].san_hosts.try_push(h_buf);
        }
    }
    return true;
}

// Copies verified DNS SubjectAltName entries from `slot_idx` into `out_sans` for HTTP/2 connection coalescing.
fn tls_copy_slot_san_hosts(slot_idx: u16, out_sans: u8[..128][..8]&) {
    out_sans.clear();
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return; }
    for &san in g_tls_cipher_slots[idx].san_hosts {
        let _ = out_sans.try_push(copy(san));
    }
}

// Exports RFC 5705 / RFC 8446 §7.5 keying material from an active TLS 1.3 cipher slot.
fn tls_session_export_keying_material(
    slot_idx: u16,
    label:    const u8[:],
    context:  const u8[:],
    length:   u16,
    out:      u8[..256]&,
) -> bool {
    out.clear();
    let idx = slot_idx as i64;
    let out_len = length as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }
    guard out_len > 0 && out_len <= out.cap else { return false; }
    let hlen = g_tls_cipher_slots[idx].hash_len as i64;
    guard hlen == 32 || hlen == 48 else { return false; }
    var ks = tls_internal::KeySchedule {
        hash_id:         g_tls_cipher_slots[idx].hash_id,
        hash_len:        g_tls_cipher_slots[idx].hash_len,
        stage:           tls_internal::KS_STAGE_MASTER,
        exporter_secret: g_tls_cipher_slots[idx].exporter_secret,
        ..
    };
    defer tls_internal::ks_zeroize(ks);
    while out.len < out_len { out.push(0); }
    return tls_internal::ks_export_keying_material(ks, label, context, length, out[..out_len]);
}

// Reads exactly dst.len bytes from socket, returning false on error or clean EOF before full read.
fn tls_read_exact(fd: i64, dst: u8[:], timeout_ms: u32) -> bool {
    guard fd > 0 && dst.len > 0 else { return false; }
    var total_read: i64 = 0;
    while total_read < dst.len {
        let recvd = if is_virtual_pipe_fd(fd) {
            virtual_fd_recv(fd, dst[total_read..])
        } else {
            tcp_recv_slice(fd, dst[total_read..], timeout_ms)
        };
        guard recvd > 0 else { return false; }
        total_read = core::add_sat_i64(total_read, recvd);
    }
    return true;
}

// Writes entire data buffer to socket, returning false on error or partial write failure.
fn tls_write_all(fd: i64, data: const u8[:]) -> bool {
    guard fd > 0 && data.len > 0 else { return false; }
    var total_sent: i64 = 0;
    while total_sent < data.len {
        let sent = if is_virtual_pipe_fd(fd) {
            virtual_fd_send(fd, data[total_sent..])
        } else {
            tcp_send(fd, data[total_sent..])
        };
        guard sent > 0 else { return false; }
        total_sent = core::add_sat_i64(total_sent, sent);
    }
    return true;
}

// Encrypts and transmits a single TLS 1.3 record over socket using slot keys.
fn tls_send_encrypted_record(
    fd:         i64,
    slot_idx:   u16,
    inner_type: u8,
    payload:    const u8[:],
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    guard g_tls_cipher_slots[idx].in_use else { return false; }

    guard payload.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    var ct_buf: u8[..16640] = [];
    guard payload.len + 22 <= ct_buf.cap else { return false; }
    while ct_buf.len < payload.len + 22 {
        ct_buf.push(0);
    }
    let klen = g_tls_cipher_slots[idx].key_len as i64;
    let sealed_len, alert, ok_seal = tls_record_seal_prepared_into(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].tx_key[..klen],
        g_tls_cipher_slots[idx].tx_aes_key,
        g_tls_cipher_slots[idx].tx_iv,
        g_tls_cipher_slots[idx].tx_seq,
        inner_type,
        payload,
        ct_buf[..],
    );
    guard ok_seal && sealed_len > 0 else { return false; }
    increment_record_seq_num(g_tls_cipher_slots[idx].tx_seq);
    return tls_write_all(fd, ct_buf[..sealed_len]);
}

inline fn select_tls_outbound_chunk_len(rem: i64, bytes_sent: u64) -> i64, u64 {
    let max_rec_len = if bytes_sent < TLS_DYNAMIC_RESIZE_THRESHOLD_BYTES {
        TLS_SINGLE_MSS_PLAINTEXT_LEN
    } else {
        rfc::TLS_MAX_RECORD_PLAINTEXT_LEN
    };
    let chunk_len = min(rem, max_rec_len);
    let cur_i64 = (bytes_sent & 0x7FFFFFFFFFFFFFFF) as i64;
    let next_i64 = core::add_sat_i64(cur_i64, chunk_len);
    let next_bytes = (next_i64 & 0x7FFFFFFFFFFFFFFF) as u64;
    return chunk_len, next_bytes;
}

// Sends application data chunks over TLS 1.3 record layer (RFC 8446 §5.2).
// Uses single-MSS records (`TLS_SINGLE_MSS_PLAINTEXT_LEN` = 1378 B) during the first 64 KB
// (`TLS_DYNAMIC_RESIZE_THRESHOLD_BYTES`) to eliminate multi-packet TCP head-of-line blocking during Slow Start.
fn tls_transport_send(fd: i64, slot_idx: u16, data: const u8[:]) -> i32 {
    let ret_len = (data.len & 0x7FFFFFFF) as i32;
    guard fd > 0 && data.len > 0 else { return 0; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return -1; }
    guard g_tls_cipher_slots[idx].in_use && !g_tls_cipher_slots[idx].peer_closed else { return -1; }

    var offset: i64 = 0;
    while offset < data.len {
        let rem = core::sub_sat_i64(data.len, offset);
        let chunk_len, next_bytes = select_tls_outbound_chunk_len(rem, g_tls_cipher_slots[idx].bytes_sent);
        let next_offset = core::add_sat_i64(offset, chunk_len);
        let ok_s = tls_send_encrypted_record(
            fd,
            slot_idx,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            data[offset..next_offset],
        );
        guard ok_s else { return -1; }
        g_tls_cipher_slots[idx].bytes_sent = next_bytes;
        offset = next_offset;
    }
    on_key_update_app_data(g_tls_cipher_slots[idx].key_update_tracker);
    return ret_len;
}

// Sends a post-handshake NewSessionTicket message over an active TLS 1.3 channel (RFC 8446 §4.6.1).
fn tls_send_new_session_ticket(
    fd:                  i64,
    slot_idx:            u16,
    ticket_lifetime:     u32,
    ticket_nonce:        const u8[:],
    ticket:              const u8[:],
    max_early_data_size: u32 = 0,
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }

    var nst_body: u8[..512] = [];
    guard encode_new_session_ticket(
        nst_body,
        ticket_lifetime,
        0,
        ticket_nonce,
        ticket,
        max_early_data_size,
    ) else { return false; }
    var hs_msg: u8[..516] = [];
    hs_msg.push(rfc::TLS_HS_NEW_SESSION_TICKET);
    hs_msg.append_u24_be(nst_body.len as u32);
    hs_msg.append(nst_body[..]);
    guard tls_send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]) else { return false; }

    if ticket_lifetime > 0 && ticket.len > 0 && ticket.len <= 256 {
        var ks_res = tls_internal::KeySchedule {
            hash_id:           g_tls_cipher_slots[idx].hash_id,
            hash_len:          g_tls_cipher_slots[idx].hash_len,
            stage:             tls_internal::KS_STAGE_RESUMPTION,
            resumption_secret: g_tls_cipher_slots[idx].resumption_secret,
            ..
        };
        defer tls_internal::ks_zeroize(ks_res);
        let h_len = g_tls_cipher_slots[idx].hash_len as i64;
        var psk_full: u8[48] = [0; 48];
        defer core::secure_zeroize_48(psk_full);
        if (h_len == 32 || h_len == 48) &&
            tls_internal::ks_derive_resumption_psk(ks_res, ticket_nonce, psk_full[..h_len]) {
            let sni = if g_tls_cipher_slots[idx].server_name.len > 0 {
                g_tls_cipher_slots[idx].server_name[..]
            } else {
                "server"
            };
            store_tls13_session_ticket(
                sni,
                ticket,
                psk_full[..h_len],
                0,
                ticket_lifetime,
                g_tls_cipher_slots[idx].cipher_suite,
            );
        }
    }
    return true;
}

// Sends a post-handshake KeyUpdate message and rotates transmitter traffic keys (RFC 8446 §4.6.3).
fn tls_send_key_update(fd: i64, slot_idx: u16, request_update: u8) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    guard g_tls_cipher_slots[idx].in_use else { return false; }

    var ku_body: u8[..4] = [];
    guard encode_key_update(ku_body, request_update) else { return false; }
    var hs_msg: u8[..8] = [];
    hs_msg.push(rfc::TLS_HS_KEY_UPDATE);
    hs_msg.push(0x00); hs_msg.push(0x00); hs_msg.push(0x01);
    hs_msg.append(ku_body[..]);
    let ok_s = tls_send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]);
    guard ok_s else { return false; }

    let h_id = g_tls_cipher_slots[idx].hash_id;
    let h_len = g_tls_cipher_slots[idx].hash_len;
    let k_len = g_tls_cipher_slots[idx].key_len;
    tls_internal::ks_update_traffic_secret(
        h_id,
        h_len,
        g_tls_cipher_slots[idx].tx_traffic_secret[..h_len as i64],
    );
    tls_internal::ks_derive_key_iv(
        h_id,
        g_tls_cipher_slots[idx].tx_traffic_secret[..h_len as i64],
        k_len,
        g_tls_cipher_slots[idx].tx_key[..k_len as i64],
        g_tls_cipher_slots[idx].tx_iv,
    );
    tls_prepare_cipher_aes_key(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].tx_key[..k_len as i64],
        g_tls_cipher_slots[idx].tx_aes_key,
    );
    g_tls_cipher_slots[idx].tx_seq = 0;
    return true;
}

fn tls_apply_rx_key_update(slot_idx: u16, needs_resp: bool, fd: i64) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return; }
    let h_id = g_tls_cipher_slots[idx].hash_id;
    let h_len = g_tls_cipher_slots[idx].hash_len;
    let k_len = g_tls_cipher_slots[idx].key_len;
    let h_len_i64 = h_len as i64;
    let k_len_i64 = k_len as i64;

    tls_internal::ks_update_traffic_secret(h_id, h_len, g_tls_cipher_slots[idx].rx_traffic_secret[..h_len_i64]);
    tls_internal::ks_derive_key_iv(
        h_id,
        g_tls_cipher_slots[idx].rx_traffic_secret[..h_len_i64],
        k_len,
        g_tls_cipher_slots[idx].rx_key[..k_len_i64],
        g_tls_cipher_slots[idx].rx_iv,
    );
    tls_prepare_cipher_aes_key(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].rx_key[..k_len_i64],
        g_tls_cipher_slots[idx].rx_aes_key,
    );
    g_tls_cipher_slots[idx].rx_seq = 0;
    if needs_resp {
        tls_send_key_update(fd, slot_idx, rfc::KEY_UPDATE_NOT_REQUESTED);
    }
}

fn tls_process_received_nst(idx: i64, msg_body: const u8[:]) -> bool {
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }
    guard !g_tls_cipher_slots[idx].is_server else { return false; }
    var nst = NewSessionTicketMsg { .. };
    guard parse_new_session_ticket(msg_body, nst) else { return false; }
    guard cache_session_ticket(g_tls_cipher_slots[idx].ticket_cache, nst) else { return false; }
    guard g_tls_cipher_slots[idx].server_name.len > 0 && nst.ticket_lifetime > 0 else { return true; }
    var ks_res = tls_internal::KeySchedule {
        hash_id:           g_tls_cipher_slots[idx].hash_id,
        hash_len:          g_tls_cipher_slots[idx].hash_len,
        stage:             tls_internal::KS_STAGE_RESUMPTION,
        resumption_secret: g_tls_cipher_slots[idx].resumption_secret,
        ..
    };
    defer tls_internal::ks_zeroize(ks_res);
    let h_len = g_tls_cipher_slots[idx].hash_len as i64;
    var psk_full: u8[48] = [0; 48];
    defer core::secure_zeroize_48(psk_full);
    if (h_len == 32 || h_len == 48) &&
        tls_internal::ks_derive_resumption_psk(ks_res, nst.ticket_nonce[..], psk_full[..h_len]) {
        store_tls13_session_ticket(
            g_tls_cipher_slots[idx].server_name[..],
            nst.ticket[..],
            psk_full[..h_len],
            nst.ticket_age_add,
            nst.ticket_lifetime,
            g_tls_cipher_slots[idx].cipher_suite,
        );
    }
    return true;
}

fn tls_dispatch_post_handshake_record(fd: i64, slot_idx: u16, hs_bytes: const u8[:]) -> bool {
    guard hs_bytes.len >= 4 else { return false; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }
    var c_hs = core::cursor_from(hs_bytes);
    while c_hs.cursor_len() > 0 {
        guard c_hs.cursor_len() >= 4 else { return false; }
        let msg_type, msg_len, ok_m = parse_handshake_header(c_hs.buf);
        guard ok_m else { return false; }
        let full_msg_len = core::add_sat_i64(4, msg_len);
        guard c_hs.buf.len >= full_msg_len else { return false; }
        let msg_body = c_hs.buf[4..full_msg_len];

        if msg_type == rfc::TLS_HS_NEW_SESSION_TICKET {
            guard tls_process_received_nst(idx, msg_body) else { return false; }
        } else if msg_type == rfc::TLS_HS_KEY_UPDATE {
            let needs_resp, ok_ku = track_received_key_update(
                g_tls_cipher_slots[idx].key_update_tracker,
                HsState.Connected,
                msg_body,
            );
            guard ok_ku else { return false; }
            tls_apply_rx_key_update(slot_idx, needs_resp, fd);
        } else {
            return false;
        }
        c_hs.buf = c_hs.buf[full_msg_len..];
    }
    return true;
}

fn tls_drain_rx_buf(idx: i64, dst: u8[:]) -> i32 {
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return 0; }
    let rem_buf = core::sub_sat_i64(g_tls_cipher_slots[idx].rx_plain_buf.len, g_tls_cipher_slots[idx].rx_plain_pos);
    if rem_buf <= 0 { return 0; }
    let to_copy = min(rem_buf, dst.len);
    let start = g_tls_cipher_slots[idx].rx_plain_pos;
    for i in to_copy {
        let src_idx = core::add_sat_i64(start, i);
        dst[i] = g_tls_cipher_slots[idx].rx_plain_buf[src_idx];
    }
    g_tls_cipher_slots[idx].rx_plain_pos = core::add_sat_i64(start, to_copy);
    if g_tls_cipher_slots[idx].rx_plain_pos >= g_tls_cipher_slots[idx].rx_plain_buf.len {
        core::secure_zeroize_slice(g_tls_cipher_slots[idx].rx_plain_buf[..]);
        g_tls_cipher_slots[idx].rx_plain_buf.clear();
        g_tls_cipher_slots[idx].rx_plain_pos = 0;
    }
    return (to_copy & 0x7FFFFFFF) as i32;
}

fn tls_recv_app_record(fd: i64, slot_idx: u16, idx: i64, dst: u8[:], timeout_ms: u32) -> i32 {
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return -1; }
    var hdr_buf: u8[5] = [0; 5];
    let ok_hdr = tls_read_exact(fd, hdr_buf[..], timeout_ms);
    guard ok_hdr else { return 0; }

    let ct, ver, payload_len_u16, alert, ok_p = parse_tls_record_header(hdr_buf[..]);
    guard ok_p else { return -1; }
    let payload_len = payload_len_u16 as i64;
    guard payload_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else { return -1; }

    var ct_payload: u8[..16640] = [];
    while ct_payload.len < payload_len { ct_payload.push(0); }
    let ok_body = tls_read_exact(fd, ct_payload[..payload_len], timeout_ms);
    guard ok_body else { return -1; }

    guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return -1; }

    var plain_dec: u8[..16640] = [];
    defer core::secure_zeroize_slice(plain_dec[..]);
    while plain_dec.len < payload_len { plain_dec.push(0); }
    let klen = g_tls_cipher_slots[idx].key_len as i64;
    let dec_len, inner_type, alert_dec, ok_dec = tls_record_decrypt_prepared_into(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].rx_key[..klen],
        g_tls_cipher_slots[idx].rx_aes_key,
        g_tls_cipher_slots[idx].rx_iv,
        g_tls_cipher_slots[idx].rx_seq,
        hdr_buf[..],
        ct_payload[..payload_len],
        plain_dec[..],
    );
    guard ok_dec else { return -1; }
    increment_record_seq_num(g_tls_cipher_slots[idx].rx_seq);

    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        let to_user = min(dec_len, dst.len);
        for i in to_user { dst[i] = plain_dec[i]; }
        if dec_len > dst.len {
            let _ = g_tls_cipher_slots[idx].rx_plain_buf.try_set(plain_dec[dst.len..dec_len]);
            g_tls_cipher_slots[idx].rx_plain_pos = 0;
        }
        on_key_update_app_data(g_tls_cipher_slots[idx].key_update_tracker);
        return to_user as i32;
    }

    if inner_type == rfc::TLS_CONTENT_ALERT {
        let alert_level, alert_code, _, ok_a = parse_tls_alert_message(plain_dec[..dec_len]);
        if ok_a && alert_code == TlsAlert.CloseNotify {
            g_tls_cipher_slots[idx].peer_closed = true;
            return 0;
        }
        if ok_a && alert_level == 1 && alert_code == TlsAlert.UserCanceled {
            return 0;
        }
        return -1;
    }

    if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
        guard tls_dispatch_post_handshake_record(fd, slot_idx, plain_dec[..dec_len]) else { return -1; }
        return 0;
    }
    return -1;
}

// Receives decrypted application data bytes from TLS 1.3 socket, handling residual buffers,
// post-handshake NewSessionTicket, KeyUpdate, and CloseNotify alerts (RFC 8446 §5.2, §4.6).
fn tls_transport_recv_slice(fd: i64, slot_idx: u16, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return -1; }
    guard g_tls_cipher_slots[idx].in_use else { return -1; }
    if g_tls_cipher_slots[idx].peer_closed { return 0; }

    let drained = tls_drain_rx_buf(idx, dst);
    if drained > 0 { return drained; }

    loop {
        let res = tls_recv_app_record(fd, slot_idx, idx, dst, timeout_ms);
        if res != 0 { return res; }
        if g_tls_cipher_slots[idx].peer_closed { return 0; }
    }
    return 0;
}

// Sends a CloseNotify alert, wipes secrets, and closes socket (RFC 8446 §6.1).
fn tls_transport_close(fd: i64, slot_idx: u16) {
    if fd > 0 {
        let idx = slot_idx as i64;
        let valid_slot = idx >= 0 && idx < g_tls_cipher_slots.len &&
            g_tls_cipher_slots[idx].in_use && !g_tls_cipher_slots[idx].peer_closed;
        if valid_slot {
            let alert_data: u8[2] = [1, 0];
            if g_tls_cipher_slots[idx].ktls_tx_active {
                let _ = net_internal::smartnic_send_record(fd, alert_data[..], rfc::TLS_CONTENT_ALERT);
            } else {
                tls_send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_ALERT, alert_data[..]);
            }
        }
        if is_virtual_pipe_fd(fd) {
            virtual_fd_close(fd);
        } else {
            tcp_close(fd);
        }
    }
    free_tls_cipher_slot(slot_idx);
}

// ---- Zero-Allocation Handshake Record Stream Reader ------------------------

struct HandshakeRecordReader {
    current_record_plain: u8[..32768] = [],
    current_offset:       i64         = 0,
    seq_num:              u64         = 0,
    ccs_count:            u32         = 0,
}

fn try_read_handshake_msg(
    r:            HandshakeRecordReader&,
    msg_type:     u8&,
    out_msg_body: u8[..16384]&,
) -> bool {
    let remaining_plain = r.current_record_plain.len - r.current_offset;
    guard remaining_plain >= 4 else { return false; }
    let slice = r.current_record_plain[r.current_offset..];
    let mt, m_len, ok_hdr = parse_handshake_header(slice);
    guard ok_hdr else { return false; }
    let total_len = 4 + (m_len as i64);
    guard remaining_plain >= total_len && out_msg_body.try_set(slice[4..total_len]) else { return false; }
    msg_type = mt;
    r.current_offset += total_len;
    return true;
}

fn compact_handshake_reader(r: HandshakeRecordReader&) {
    let remaining_plain = core::sub_sat_i64(r.current_record_plain.len, r.current_offset);
    if remaining_plain > 0 && r.current_offset > 0 {
        var k: i64 = 0;
        while k < remaining_plain {
            let src_idx = core::add_sat_i64(r.current_offset, k);
            r.current_record_plain[k] = r.current_record_plain[src_idx];
            k = core::add_sat_i64(k, 1);
        }
        while r.current_record_plain.len > remaining_plain {
            r.current_record_plain.pop();
        }
    } else if remaining_plain <= 0 {
        r.current_record_plain.clear();
    }
    r.current_offset = 0;
}

// Consumes the next handshake message from the reader, reading and decrypting
// subsequent TLS records from `fd` when the buffered record is exhausted.
//
// Example:
//   r.current_record_plain = [0x08, 0x00, 0x00, 0x02, 0x00, 0x00], r.current_offset = 0
//   returns: true, msg_type = 8, out_msg_body = [0x00, 0x00]
fn next_handshake_message(
    r:            HandshakeRecordReader&,
    fd:           i64,
    cipher_suite: u16,
    key:          const u8[:],
    iv:           const u8[12]&,
    msg_type:     u8&,
    out_msg_body: u8[..16384]&,
    timeout_ms:   u32,
) -> bool {
    loop {
        if try_read_handshake_msg(r, msg_type, out_msg_body) {
            return true;
        }

        var hdr_buf: u8[5] = [0; 5];
        guard tls_read_exact(fd, hdr_buf[..], timeout_ms) else { return false; }

        let ct, ver, payload_len_u16, alert, ok_p = parse_tls_record_header(hdr_buf[..]);
        guard ok_p else { return false; }
        let payload_len = payload_len_u16 as i64;
        guard payload_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else { return false; }

        var ct_payload: u8[..16640] = [];
        while ct_payload.len < payload_len { ct_payload.push(0); }
        guard tls_read_exact(fd, ct_payload[..payload_len], timeout_ms) else { return false; }

        if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
            guard r.ccs_count < 1 &&
                r.current_offset == r.current_record_plain.len &&
                ver == rfc::TLS_LEGACY_VERSION_1_2 &&
                validate_change_cipher_spec_record(ct_payload[..payload_len]) == TlsAlert.CloseNotify else {
                return false;
            }
            r.ccs_count = core::add_sat_u32(r.ccs_count, 1);
            continue;
        }
        guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return false; }

        compact_handshake_reader(r);
        var plain_dec: u8[..16640] = [];
        while plain_dec.len < payload_len { plain_dec.push(0); }
        let dec_len, inner_type, alert_dec, ok_dec = tls_record_decrypt_into(
            cipher_suite,
            key,
            iv,
            r.seq_num,
            hdr_buf[..],
            ct_payload[..payload_len],
            plain_dec[..],
        );
        guard ok_dec && inner_type == rfc::TLS_CONTENT_HANDSHAKE && dec_len > 0 else { return false; }
        increment_record_seq_num(r.seq_num);

        guard r.current_record_plain.try_append(plain_dec[..dec_len]) else { return false; }
    }
    return false;
}

// ---- Test Certificate Generator (RFC 5280 / RFC 8446) --------------------

// Builds a self-signed X.509 v3 Ed25519 certificate in canonical ASN.1 DER format.
fn build_test_ed25519_cert_der(
    seed:        const u8[32]&,
    common_name: const u8[:],
    dns_san:     const u8[:],
    ip_san:      const u8[:],
    out_der:     u8[..2048]&,
) -> bool {
    out_der.clear();
    let kp = core::ed25519_keypair(seed);

    var b_tbs = core::builder_init();

    // version [0] EXPLICIT INTEGER v3 (2)
    b_tbs.put_u8(0xA0);
    b_tbs.put_u8(3);
    b_tbs.put_u8(0x02);
    b_tbs.put_u8(1);
    b_tbs.put_u8(2);

    // serialNumber (INTEGER: 1)
    b_tbs.put_u8(0x02);
    b_tbs.put_u8(1);
    b_tbs.put_u8(1);

    // signature (AlgorithmIdentifier: OID_ED25519)
    b_tbs.put_u8(0x30);
    b_tbs.put_u8(5);
    b_tbs.put_u8(0x06);
    b_tbs.put_u8(3);
    b_tbs.put_bytes("\x2B\x65\x70");

    // issuer (SEQUENCE OF SET OF SEQUENCE { OID_COMMON_NAME, UTF8String })
    var b_cn = core::builder_init();
    b_cn.put_u8(0x30);
    b_cn.put_u8((2 + 3 + 2 + common_name.len) as u8);
    b_cn.put_u8(0x06);
    b_cn.put_u8(3);
    b_cn.put_bytes("\x55\x04\x03");
    b_cn.put_u8(0x0C);
    b_cn.put_u8(common_name.len as u8);
    b_cn.put_bytes(common_name);

    var b_issuer = core::builder_init();
    b_issuer.put_u8(0x30);
    b_issuer.put_u8((2 + b_cn.buf.len) as u8);
    b_issuer.put_u8(0x31);
    b_issuer.put_u8(b_cn.buf.len as u8);
    b_issuer.put_bytes(b_cn.buf[..]);
    b_tbs.put_bytes(b_issuer.buf[..]);

    // validity: 2024-01-01 to 2035-12-31
    b_tbs.put_u8(0x30);
    b_tbs.put_u8(30);
    b_tbs.put_u8(0x17);
    b_tbs.put_u8(13);
    b_tbs.put_bytes("240101000000Z");
    b_tbs.put_u8(0x17);
    b_tbs.put_u8(13);
    b_tbs.put_bytes("351231235959Z");

    // subject (same as issuer)
    b_tbs.put_bytes(b_issuer.buf[..]);

    // SPKI: SubjectPublicKeyInfo
    b_tbs.put_u8(0x30);
    b_tbs.put_u8(42);
    b_tbs.put_u8(0x30);
    b_tbs.put_u8(5);
    b_tbs.put_u8(0x06);
    b_tbs.put_u8(3);
    b_tbs.put_bytes("\x2B\x65\x70");
    b_tbs.put_u8(0x03);
    b_tbs.put_u8(33);
    b_tbs.put_u8(0x00);
    b_tbs.put_bytes(kp.public_key[..]);

    // extensions [3] EXPLICIT
    var b_ext_body = core::builder_init();

    // Extension 1: BasicConstraints (cA = true)
    b_ext_body.put_u8(0x30);
    b_ext_body.put_u8(12);
    b_ext_body.put_u8(0x06);
    b_ext_body.put_u8(3);
    b_ext_body.put_bytes("\x55\x1D\x13");
    b_ext_body.put_u8(0x04);
    b_ext_body.put_u8(5);
    b_ext_body.put_u8(0x30);
    b_ext_body.put_u8(3);
    b_ext_body.put_u8(0x01);
    b_ext_body.put_u8(1);
    b_ext_body.put_u8(0xFF);

    // Extension 2: SubjectAltName (if dns_san or ip_san present)
    if dns_san.len > 0 || ip_san.len > 0 {
        var b_san_names = core::builder_init();
        if dns_san.len > 0 {
            b_san_names.put_u8(0x82);
            b_san_names.put_u8(dns_san.len as u8);
            b_san_names.put_bytes(dns_san);
        }
        if ip_san.len == 4 {
            b_san_names.put_u8(0x87);
            b_san_names.put_u8(4);
            b_san_names.put_bytes(ip_san);
        } else if ip_san.len > 0 {
            var ip4: u8[4] = [0; 4];
            if parse_ipv4_literal(ip_san, ip4) {
                b_san_names.put_u8(0x87);
                b_san_names.put_u8(4);
                b_san_names.put_bytes(ip4[..]);
            }
        }

        var b_san_seq = core::builder_init();
        b_san_seq.put_u8(0x30);
        b_san_seq.put_u8(b_san_names.buf.len as u8);
        b_san_seq.put_bytes(b_san_names.buf[..]);

        b_ext_body.put_u8(0x30);
        let ext_len = 2 + 3 + 2 + b_san_seq.buf.len;
        b_ext_body.put_u8(ext_len as u8);
        b_ext_body.put_u8(0x06);
        b_ext_body.put_u8(3);
        b_ext_body.put_bytes("\x55\x1D\x11");
        b_ext_body.put_u8(0x04);
        b_ext_body.put_u8(b_san_seq.buf.len as u8);
        b_ext_body.put_bytes(b_san_seq.buf[..]);
    }

    var b_ext_full = core::builder_init();
    b_ext_full.put_u8(0xA3);
    let ext_seq_len = 2 + b_ext_body.buf.len;
    b_ext_full.put_u8(ext_seq_len as u8);
    b_ext_full.put_u8(0x30);
    b_ext_full.put_u8(b_ext_body.buf.len as u8);
    b_ext_full.put_bytes(b_ext_body.buf[..]);
    b_tbs.put_bytes(b_ext_full.buf[..]);

    var b_tbs_full = core::builder_init();
    b_tbs_full.put_u8(0x30);
    if b_tbs.buf.len >= 256 {
        b_tbs_full.put_u8(0x82);
        b_tbs_full.put_u8((b_tbs.buf.len >> 8) as u8);
        b_tbs_full.put_u8((b_tbs.buf.len & 0xFF) as u8);
    } else if b_tbs.buf.len >= 128 {
        b_tbs_full.put_u8(0x81);
        b_tbs_full.put_u8(b_tbs.buf.len as u8);
    } else {
        b_tbs_full.put_u8(b_tbs.buf.len as u8);
    }
    b_tbs_full.put_bytes(b_tbs.buf[..]);

    let sig = core::ed25519_sign(seed, b_tbs_full.buf[..]);

    var b_cert_inner = core::builder_init();
    b_cert_inner.put_bytes(b_tbs_full.buf[..]);
    b_cert_inner.put_u8(0x30);
    b_cert_inner.put_u8(5);
    b_cert_inner.put_u8(0x06);
    b_cert_inner.put_u8(3);
    b_cert_inner.put_bytes("\x2B\x65\x70");
    b_cert_inner.put_u8(0x03);
    b_cert_inner.put_u8(65);
    b_cert_inner.put_u8(0x00);
    b_cert_inner.put_bytes(sig[..]);

    out_der.push(0x30);
    if b_cert_inner.buf.len >= 256 {
        out_der.push(0x82);
        out_der.push((b_cert_inner.buf.len >> 8) as u8);
        out_der.push((b_cert_inner.buf.len & 0xFF) as u8);
    } else if b_cert_inner.buf.len >= 128 {
        out_der.push(0x81);
        out_der.push(b_cert_inner.buf.len as u8);
    } else {
        out_der.push(b_cert_inner.buf.len as u8);
    }
    out_der.append(b_cert_inner.buf[..]);
    return true;
}

// ---- TLS 1.3 Handshake Orchestration (RFC 8446 §4) -----------------------

struct TlsClientHandshakeConfig {
    server_name:          u8[..256]        = [],
    alpn:                 u8[..255]        = [],
    trust_store:          TrustAnchorStore = TrustAnchorStore { .. },
    insecure_skip_verify: bool             = false,
    virtual_clock_sec:    i64              = 0,
    client_cert_der:      u8[..4096]       = [],
    client_priv_seed:     u8[32]           = [0; 32],
    enable_pq_hybrid:     bool             = false,
    ech_config_list:      u8[..512]        = [],
    crl_der:              u8[..4096]       = [],
}

struct TlsServerHandshakeConfig {
    cert_der:             u8[..4096] = [],
    priv_seed:            u8[32]     = [0; 32],
    alpn:                 u8[..255]  = [],
    compressed_cert_algo: u16        = 0,
    compressed_cert_data: u8[..4096] = [],
}

// Extracts the optional stapled OCSP response from a CertificateEntry extension block (RFC 8446 Section 4.4.2.1).
//
// Example:
//   ext_bytes = [0x00, 0x05, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x30, 0x00]
//   returns: [0x30, 0x00], ok = true
fn extract_leaf_ocsp_extension(ext_bytes: const u8[:]) -> const u8[:], bool {
    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(ext_bytes, entries) else { return "", false; }
    for e in entries {
        guard e.ext_type == rfc::TLS_EXT_STATUS_REQUEST ||
            e.ext_type == rfc::TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP else {
            return "", false;
        }
    }
    let status_data, has_st = find_extension(entries, rfc::TLS_EXT_STATUS_REQUEST);
    guard has_st else { return "", true; }
    return unwrap_tls_ocsp_response(status_data);
}

// Parses a Certificate message payload into DER cert slices and optional leaf OCSP (RFC 8446 Section 4.4.2).
//
// Example:
//   payload = [0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x04, 'C', 'E', 'R', 'T', 0x00, 0x00]
//   returns: out_leaf_ocsp = "", ok = true, out_certs.len = 1
fn parse_tls13_certificate_chain_and_ocsp(
    payload:   const u8[:],
    out_certs: const u8[:][..8]&,
) -> const u8[:], bool {
    out_certs.clear();
    var committed = false;
    defer if !committed { out_certs.clear(); };
    var out_leaf_ocsp = payload[..0];
    var c = core::cursor_from(payload);
    let ctx, ok_ctx = c.read_u8_prefixed();
    guard ok_ctx && ctx.len == 0 else { return "", false; }
    let list_bytes, ok_list = c.read_u24_prefixed();
    guard ok_list && c.buf.len == 0 else { return "", false; }

    var lc = core::cursor_from(list_bytes);
    while lc.buf.len > 0 {
        let cert_bytes, ok_cert = lc.read_u24_prefixed();
        guard ok_cert && cert_bytes.len > 0 else { return "", false; }
        let ext_bytes, ok_ext = lc.read_u16_prefixed();
        guard ok_ext else { return "", false; }
        if ext_bytes.len > 0 {
            let ocsp_der, ok_ocsp = extract_leaf_ocsp_extension(ext_bytes);
            guard ok_ocsp else { return "", false; }
            if out_certs.len == 0 {
                out_leaf_ocsp = ocsp_der;
            }
        }
        guard out_certs.try_push(cert_bytes) else { return "", false; }
    }
    guard out_certs.len > 0 else { return "", false; }
    committed = true;
    return out_leaf_ocsp, true;
}

// Encodes an ALPN extension (RFC 7301 §3.1) supporting single or comma-separated protocol names (e.g. "h2,http/1.1").
fn encode_alpn_extension_from_csv<B>(out: B&, alpn_csv: const u8[:]) {
    guard alpn_csv.len > 0 && alpn_csv.len <= 255 else { return; }
    var proto_list: u8[..256] = [];
    var cursor:     i64       = 0;
    while cursor < alpn_csv.len {
        var comma_idx = cursor;
        while comma_idx < alpn_csv.len && alpn_csv[comma_idx] != ',' {
            comma_idx++;
        }
        let item = alpn_csv[cursor..comma_idx];
        if item.len > 0 && item.len <= 255 {
            proto_list.push(item.len as u8);
            proto_list.append(item);
        }
        cursor = comma_idx + 1;
    }
    guard proto_list.len >= 2 else { return; }
    out.append_u16_be(rfc::TLS_EXT_ALPN);
    out.append_u16_be((proto_list.len + 2) as u16);
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

// Computes a TLS 1.3 SHA-256 PSK binder tag over a truncated ClientHello handshake message (RFC 8446 §4.2.11.2).
fn compute_tls13_psk_binder(
    binder_key:   const u8[32]&,
    truncated_ch: const u8[:],
    out_binder:   u8[32]&,
) -> bool {
    var full: u8[..48] = [];
    defer core::secure_zeroize_slice(full[..]);
    guard compute_tls13_psk_binder_for_hash(tls_internal::HASH_SHA256, binder_key[..], truncated_ch, full) &&
        full.len == 32 else {
        return false;
    }
    core::ct_copy_bytes(out_binder[..], full[..32]);
    return true;
}

// Serializes a TLS 1.3 ClientHello payload with standard extensions (RFC 8446 §4.1.2).
fn build_tls13_client_hello_payload<B>(
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
        let _ = serialize_tls_cookie_extension(ext_buf, hrr_cookie);
    }

    var shares: u8[..1280] = [];
    if enable_pq && pq_pub.len == rfc::MLKEM768_PUBLIC_LEN {
        var pq_share = tls_internal::PostQuantumKeyShare {
            group:         rfc::GROUP_X25519_MLKEM768,
            x25519_public: client_pub,
            ..
        };
        core::ct_copy_bytes(pq_share.mlkem768_public[..], pq_pub);
        tls_internal::format_hybrid_key_share(pq_share, shares);
    }
    shares.append_u16_be(rfc::GROUP_X25519);
    shares.append_u16_be(32);
    shares.append(client_pub[..]);
    encode_key_share_client_extension(ext_buf, shares[..]);

    if validate_sni_host_bytes(server_name) {
        ext_buf.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
        let sni_len = (server_name.len + 3) as u16;
        ext_buf.append_u16_be(sni_len + 2);
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

// Encodes psk_key_exchange_modes (RFC 8446 §4.2.9) and pre_shared_key (RFC 8446 §4.2.11) extensions.
fn encode_psk_client_extensions<B>(
    out:         B&,
    psk_ticket:  const u8[:],
    psk_age_add: u32,
    binder_len:  u8 = 32,
) {
    guard psk_ticket.len > 0 && psk_ticket.len <= 256 && (binder_len == 32 || binder_len == 48) else { return; }
    out.append_u16_be(rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES);
    out.append_u16_be(2);
    out.push(1);
    out.push(1);

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

// Sends a plaintext TLS record containing a handshake message (RFC 8446 §5.1).
fn send_plaintext_handshake_record(fd: i64, hs_msg: const u8[:]) -> bool {
    guard hs_msg.len > 0 && hs_msg.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    var rec_buf: u8[..16640] = [];
    rec_buf.push(rfc::TLS_CONTENT_HANDSHAKE);
    rec_buf.push(0x03);
    rec_buf.push(0x01); // legacy record version 1.0 (RFC 8446 §5.1)
    rec_buf.append_u16_be(hs_msg.len as u16);
    rec_buf.append(hs_msg);
    return tls_write_all(fd, rec_buf[..]);
}

fn has_complete_plaintext_handshake_msg(raw_msg: const u8[:]) -> bool {
    guard raw_msg.len >= 4 else { return false; }
    let _, msg_len, ok_m = parse_handshake_header(raw_msg);
    return ok_m && raw_msg.len >= core::add_sat_i64(4, msg_len);
}

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
        let ct, ver, p_len_u16, alert, ok_hdr = parse_tls_record_header(hdr[..]);
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
                validate_change_cipher_spec_record(body[..p_len]) == TlsAlert.CloseNotify else {
                return false;
            }
            ccs_count = core::add_sat_u32(ccs_count, 1);
            continue;
        }
        guard ct == rfc::TLS_CONTENT_HANDSHAKE && raw_msg.try_append(body[..p_len]) else { return false; }
        found = has_complete_plaintext_handshake_msg(raw_msg[..]);
    }
    guard found else { return false; }
    return out_payload.try_set(raw_msg[..]);
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
    var sh = ParsedServerHello { .. };
    guard parse_live_server_hello(payload, sh) else {
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

enum SniOfferState {
    Omitted,
    Offered,
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
    entries:          const TlsExtensionEntry[..32]&,
    offered_alpn_csv: const u8[:],
    sni_state:        SniOfferState,
    allow_ech_retry:  bool,
) -> bool {
    for e in entries {
        if e.ext_type == rfc::TLS_EXT_SERVER_NAME {
            guard sni_state == SniOfferState.Offered && e.data.len == 0 else { return false; }
        } else if e.ext_type == rfc::TLS_EXT_ALPN {
            guard offered_alpn_csv.len > 0 else { return false; }
        } else if e.ext_type == rfc::EXT_ENCRYPTED_CLIENT_HELLO {
            guard allow_ech_retry && e.data.len >= 2 else { return false; }
        } else {
            return false;
        }
    }
    return true;
}

// Parses server EncryptedExtensions and extracts a negotiated ALPN protocol (RFC 7301 Section 3.1).
//
// Example:
//   ee_body = [0x00, 0x09, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2']
//   returns: true, out_alpn = "h2"
fn parse_encrypted_extensions_alpn<B>(
    ee_body:          const u8[:],
    out_alpn:         B&,
    offered_alpn_csv: const u8[:]   = "*",
    sni_state:        SniOfferState = SniOfferState.Offered,
    allow_ech_retry:  bool          = false,
) -> bool {
    out_alpn.clear();
    var committed = false;
    defer if !committed { out_alpn.clear(); };
    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(ee_body, entries) else { return false; }
    guard validate_ee_solicited_extensions(entries, offered_alpn_csv, sni_state, allow_ech_retry) else {
        return false;
    }
    let alpn_data, has_alpn = find_extension(entries, rfc::TLS_EXT_ALPN);
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

fn verify_ocsp_against_trust_store(
    leaf_ocsp:   const u8[:],
    leaf_cert:   const ParsedCert&,
    leaf_raw:    const u8[:],
    eff_clock:   i64,
    trust_store: const TrustAnchorStore&,
) -> bool, bool {
    let leaf_issuer_dn = span_slice(leaf_raw, leaf_cert.issuer_raw);
    guard leaf_issuer_dn.len > 0 else { return false, false; }
    for i in trust_store.anchors.len {
        let a .= trust_store.anchors[i];
        if a.is_valid && a.has_pub_material && a.subject_raw[..] == leaf_issuer_dn {
            let alert = validate_ocsp_stapling(leaf_ocsp, leaf_cert, leaf_raw, eff_clock);
            guard alert == TlsAlert.CloseNotify else { return true, false; }
            var ocsp_parsed = ParsedOcspResponse { .. };
            guard parse_ocsp_response(leaf_ocsp, ocsp_parsed) else { return true, false; }
            guard x509_verify_ocsp_cert_id_material(
                ocsp_parsed, leaf_ocsp, a.subject_raw[..], a.spki_pubkey[..],
            ) else { return true, false; }
            let sig_alert = x509_verify_ocsp_signature_with_pubkey(
                ocsp_parsed, leaf_ocsp, a.spki_pubkey[..],
            );
            return true, sig_alert == TlsAlert.CloseNotify;
        }
    }
    return false, false;
}

fn verify_stapled_ocsp_for_chain(
    leaf_ocsp:    const u8[:],
    chain_parsed: const ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    eff_clock:    i64,
    trust_store:  const TrustAnchorStore&,
) -> bool {
    guard leaf_ocsp.len > 0 else { return !chain_parsed[0].has_must_staple; }
    if chain_parsed.len >= 2 {
        return validate_ocsp_stapling(
            leaf_ocsp, chain_parsed[0], chain_slices[0], eff_clock, chain_slices[1],
        ) == TlsAlert.CloseNotify;
    }
    let anchor_matched, anchor_ok = verify_ocsp_against_trust_store(
        leaf_ocsp, chain_parsed[0], chain_slices[0], eff_clock, trust_store,
    );
    if anchor_matched {
        return anchor_ok;
    }
    let leaf_subj = span_slice(chain_slices[0], chain_parsed[0].subject_raw);
    let leaf_iss = span_slice(chain_slices[0], chain_parsed[0].issuer_raw);
    guard leaf_subj.len > 0 && leaf_subj == leaf_iss else { return false; }
    return validate_ocsp_stapling(
        leaf_ocsp, chain_parsed[0], chain_slices[0], eff_clock, chain_slices[0],
    ) == TlsAlert.CloseNotify;
}

// RFC 5280 Section 6.3.3: CRL Processing - Resolves the CRL issuer certificate or trust anchor and verifies cRLSign key usage and signature.
fn verify_crl_signer_for_cert(
    crl_parsed:   const ParsedCrl&,
    crl_der:      const u8[:],
    cert_idx:     i64,
    chain_parsed: const ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    trust_store:  const TrustAnchorStore&,
) -> bool {
    let next_idx = core::add_sat_i64(cert_idx, 1);
    if next_idx < chain_parsed.len {
        let iss .= chain_parsed[next_idx];
        guard !iss.has_key_usage || (iss.key_usage & rfc::KEY_USAGE_CRL_SIGN) != 0 else { return false; }
        return x509_verify_crl_signature(crl_parsed, crl_der, iss, chain_slices[next_idx]) == TlsAlert.CloseNotify;
    }
    for j in trust_store.anchors.len {
        let a .= trust_store.anchors[j];
        if a.is_valid && a.has_pub_material && a.subject_raw[..] == crl_parsed.issuer {
            guard !a.has_key_usage || (a.key_usage & rfc::KEY_USAGE_CRL_SIGN) != 0 else { return false; }
            let alert = x509_verify_crl_signature_with_pubkey(crl_parsed, crl_der, a.spki_pubkey[..]);
            return alert == TlsAlert.CloseNotify;
        }
    }
    let self_cert .= chain_parsed[cert_idx];
    let self_subj = span_slice(chain_slices[cert_idx], self_cert.subject_raw);
    guard self_subj.len > 0 && self_subj == crl_parsed.issuer else { return false; }
    guard !self_cert.has_key_usage || (self_cert.key_usage & rfc::KEY_USAGE_CRL_SIGN) != 0 else { return false; }
    return x509_verify_crl_signature(crl_parsed, crl_der, self_cert, chain_slices[cert_idx]) == TlsAlert.CloseNotify;
}

// RFC 5280 Section 6.3.3: CRL Processing - Verifies CRL freshness, issuer signature, and revocation status across matching chain certificates.
fn verify_crl_for_chain_with_store(
    crl_der:      const u8[:],
    chain_parsed: const ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    now_unix:     i64,
    trust_store:  const TrustAnchorStore&,
) -> bool {
    guard crl_der.len > 0 else { return true; }
    guard chain_parsed.len > 0 && chain_slices.len == chain_parsed.len else { return false; }
    var crl_parsed = ParsedCrl { .. };
    guard parse_x509_crl(crl_der, crl_parsed) else { return false; }
    let now_sec = if now_unix > 0 { now_unix } else { core::unix(core::now()) };
    guard crl_parsed.this_update <= now_sec else { return false; }
    if crl_parsed.next_update > 0 {
        guard now_sec <= crl_parsed.next_update else { return false; }
    }
    var matched_any = false;
    for i in chain_parsed.len {
        let cert_issuer = span_slice(chain_slices[i], chain_parsed[i].issuer_raw);
        if cert_issuer == crl_parsed.issuer {
            matched_any = true;
            guard verify_crl_signer_for_cert(
                crl_parsed, crl_der, i, chain_parsed, chain_slices, trust_store,
            ) else { return false; }
            let ser_bytes = span_slice(chain_slices[i], chain_parsed[i].serial_number);
            let ser_u64, ok_ser = parse_asn1_serial_u64(ser_bytes);
            guard ok_ser && !crl_is_revoked(crl_parsed, ser_u64) else { return false; }
        }
    }
    return matched_any;
}

fn verify_crl_for_chain(
    crl_der:      const u8[:],
    chain_parsed: const ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    now_unix:     i64 = 0,
) -> bool {
    let empty_store = TrustAnchorStore { .. };
    return verify_crl_for_chain_with_store(crl_der, chain_parsed, chain_slices, now_unix, empty_store);
}

// Validates server Certificate and CertificateVerify against trust anchor store and transcript (RFC 8446 §4.4).
fn verify_server_cert_and_signature(
    cert_body:          const u8[:],
    cv_body:            const u8[:],
    transcript_to_cert: const u8[:],
    config:             const TlsClientHandshakeConfig&,
    slot_idx:           u16 = 0xFFFF,
) -> bool {
    var chain_slices: const u8[:][..8] = [];
    let leaf_ocsp, ok_chain = parse_tls13_certificate_chain_and_ocsp(cert_body, chain_slices);
    guard ok_chain else { return false; }
    var leaf_cert = ParsedCert { .. };
    guard parse_x509_certificate(chain_slices[0], leaf_cert) else { return false; }
    if slot_idx != 0xFFFF { let _ = tls_populate_slot_san_hosts_from_der(slot_idx, chain_slices[0]); }

    var chain_parsed: ParsedCert[..8] = [];
    guard chain_parsed.try_push(leaf_cert) else { return false; }

    var idx: i64 = 1;
    let parse_limit = if config.insecure_skip_verify { 1 } else { chain_slices.len };
    while idx < parse_limit {
        var c_parsed = ParsedCert { .. };
        guard parse_x509_certificate(chain_slices[idx], c_parsed) else { return false; }
        guard chain_parsed.try_push(c_parsed) else { return false; }
        idx++;
    }

    if !config.insecure_skip_verify {
        let eff_clock = if config.virtual_clock_sec > 0 { config.virtual_clock_sec } else { core::now().wall_sec };
        let alert = verify_certificate_chain(chain_parsed, chain_slices, config.trust_store, eff_clock);
        guard alert == TlsAlert.CloseNotify else { return false; }
        guard verify_stapled_ocsp_for_chain(
            leaf_ocsp, chain_parsed, chain_slices, eff_clock, config.trust_store,
        ) else { return false; }
        guard verify_crl_for_chain_with_store(
            config.crl_der[..], chain_parsed, chain_slices, eff_clock, config.trust_store,
        ) else { return false; }

        if config.server_name.len > 0 {
            var sans: SanEntry[..64] = [];
            let ok_san = get_cert_san_extension(leaf_cert, chain_slices[0], sans);
            guard ok_san && match_any_san(sans, config.server_name[..]) else { return false; }
        }
    }

    var leaf_pub = span_slice(chain_slices[0], leaf_cert.spki_pubkey);
    if leaf_pub.len >= 2 && leaf_pub[0] == 0 { leaf_pub = leaf_pub[1..]; }

    let sig_scheme, sig_bytes, ok_parse_cv = parse_certificate_verify(cv_body);
    guard ok_parse_cv else { return false; }

    if !config.insecure_skip_verify {
        let spki_oid = span_slice(chain_slices[0], leaf_cert.spki_alg_oid);
        guard verify_signature_scheme_curve_binding(sig_scheme, spki_oid) else { return false; }
    }

    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = build_certificate_verify_message(true, transcript_to_cert, cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }

    return verify_tls13_certificate_verify_sig(sig_scheme, sig_bytes, leaf_pub, cv_msg_buf[..cv_len]);
}

// Ingests and verifies the encrypted server flight: EncryptedExtensions, [CertificateRequest],
// [Certificate | CompressedCertificate, CertificateVerify], Finished.
fn tls_client_process_server_flight<B>(
    hs_reader:             HandshakeRecordReader&,
    fd:                    i64,
    cipher_suite:          u16,
    server_hs_key:         const u8[:],
    server_hs_iv:          const u8[12]&,
    ks:                    const tls_internal::KeySchedule&,
    transcript:            TlsTranscript&,
    config:                const TlsClientHandshakeConfig&,
    psk_resumed:           bool,
    out_alpn:              B&,
    out_cert_req_received: bool&,
    out_cert_req:          CertificateRequestMsg&,
    slot_idx:              u16 = 0xFFFF,
) -> bool {
    out_cert_req_received = false;
    out_cert_req.context.clear();
    var msg_ee:  u8          = 0;
    var ee_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_ee, ee_body, 5000,
    ) else { return false; }
    guard msg_ee == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else { return false; }
    let sni_state = if validate_sni_host_bytes(config.server_name[..]) {
        SniOfferState.Offered
    } else {
        SniOfferState.Omitted
    };
    guard parse_encrypted_extensions_alpn(
        ee_body[..], out_alpn, config.alpn[..], sni_state, config.ech_config_list.len > 0,
    ) else { return false; }
    transcript_update_msg(transcript, msg_ee, ee_body[..]);

    if !psk_resumed {
        var msg_next:  u8          = 0;
        var next_body: u8[..16384] = [];
        guard next_handshake_message(
            hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_next, next_body, 5000,
        ) else { return false; }

        if msg_next == rfc::TLS_HS_CERTIFICATE_REQUEST {
            guard parse_certificate_request(next_body[..], false, out_cert_req) else { return false; }
            transcript_update_msg(transcript, msg_next, next_body[..]);
            out_cert_req_received = true;

            next_body.clear();
            guard next_handshake_message(
                hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_next, next_body, 5000,
            ) else { return false; }
        }

        var decomp_cert: u8[..16384] = [];
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
                return false;
            }
        } else if msg_next == rfc::TLS_HS_CERTIFICATE {
            transcript_update_msg(transcript, msg_next, next_body[..]);
        } else {
            return false;
        }

        let cert_body_slice = if is_comp_cert { decomp_cert[..] } else { next_body[..] };

        var msg_cv:  u8          = 0;
        var cv_body: u8[..16384] = [];
        guard next_handshake_message(
            hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_cv, cv_body, 5000,
        ) else { return false; }
        guard msg_cv == rfc::TLS_HS_CERTIFICATE_VERIFY else { return false; }

        var h_to_cert: u8[..48] = [];
        transcript_current_hash(transcript, ks.hash_id, h_to_cert);
        let ok_v = verify_server_cert_and_signature(cert_body_slice, cv_body[..], h_to_cert[..], config, slot_idx);
        guard ok_v else { return false; }
        transcript_update_msg(transcript, msg_cv, cv_body[..]);
    }

    var msg_fin:  u8          = 0;
    var fin_body: u8[..16384] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_fin, fin_body, 5000,
    ) else { return false; }
    let hlen = ks.hash_len as i64;
    guard msg_fin == rfc::TLS_HS_FINISHED &&
        fin_body.len == hlen &&
        hs_reader.current_offset == hs_reader.current_record_plain.len else {
        return false;
    }

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var exp_srv_fin: u8[48] = [0; 48];
    guard tls_internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen], h_to_cv[..], exp_srv_fin[..hlen],
    ) else { return false; }
    guard core::ct_eq_bytes(exp_srv_fin[..hlen], fin_body[..hlen]) else { return false; }
    transcript_update_msg(transcript, msg_fin, fin_body[..]);
    return true;
}

// Seals and sends an encrypted handshake record, advancing sequence number.
fn tls_seal_and_send_hs(
    fd:           i64,
    cipher_suite: u16,
    key:          const u8[:],
    iv:           const u8[12]&,
    seq:          u64,
    hs_msg:       const u8[:],
) -> bool {
    var ct_buf: u8[..4096] = [];
    let needed = hs_msg.len + 32;
    guard needed <= ct_buf.cap else { return false; }
    ct_buf.resize(needed, 0);
    let s_len, _, ok_seal = tls_record_seal_into(
        cipher_suite, key, iv, seq,
        rfc::TLS_CONTENT_HANDSHAKE, hs_msg, ct_buf[..],
    );
    guard ok_seal && tls_write_all(fd, ct_buf[..s_len]) else { return false; }
    return true;
}

// Detects the TLS 1.3 SignatureScheme (`SIG_SCHEME_ECDSA_SECP256R1_SHA256` or `SIG_SCHEME_ED25519`)
// from the leaf certificate's SubjectPublicKeyInfo OID (RFC 8446 Section 4.4.3).
fn detect_cert_sig_scheme(cert_der: const u8[:]) -> u16 {
    var cert = ParsedCert { .. };
    if cert_der.len > 0 && parse_x509_certificate(cert_der, cert) {
        let spki_oid = span_slice(cert_der, cert.spki_alg_oid);
        if spki_oid == rfc::OID_SECP256R1[..] {
            return rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256;
        }
    }
    return rfc::SIG_SCHEME_ED25519;
}

// Signs a TLS 1.3 CertificateVerify message using Ed25519 (`0x0807`) or ECDSA P-256 (`0x0403` DER)
// according to the certificate's SubjectPublicKeyInfo algorithm (RFC 8446 Section 4.4.3).
fn sign_tls13_certificate_verify(
    cert_der:  const u8[:],
    priv_seed: const u8[32]&,
    cv_msg:    const u8[:],
    out_sig:   u8[..128]&,
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
    let ed_sig = core::ed25519_sign(priv_seed, cv_msg);
    guard out_sig.try_set(ed_sig[..]) else { return 0, false; }
    return rfc::SIG_SCHEME_ED25519, true;
}

fn tls_client_send_client_cert(
    fd:            i64,
    cipher_suite:  u16,
    client_hs_key: const u8[:],
    client_hs_iv:  const u8[12]&,
    client_seq:    u64&,
    ks:            const tls_internal::KeySchedule&,
    transcript:    TlsTranscript&,
    config:        const TlsClientHandshakeConfig&,
    cert_req:      const CertificateRequestMsg&,
) -> bool {
    var cert_payload: u8[..4096] = [];
    guard encode_client_certificate(cert_payload, cert_req.context[..], config.client_cert_der[..]) else {
        return false;
    }
    var cert_msg: u8[..4096] = [];
    cert_msg.push(rfc::TLS_HS_CERTIFICATE);
    cert_msg.append_u24_be(cert_payload.len as u32);
    cert_msg.append(cert_payload[..]);

    guard tls_seal_and_send_hs(fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, cert_msg[..]) else {
        return false;
    }
    client_seq++;
    transcript_update(transcript, cert_msg[..]);

    if config.client_cert_der.len > 0 {
        var h_to_cert: u8[..48] = [];
        transcript_current_hash(transcript, ks.hash_id, h_to_cert);
        var cv_msg_buf: u8[..256] = [];
        while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
        let cv_len, ok_cv = build_certificate_verify_message(false, h_to_cert[..], cv_msg_buf[..]);
        guard ok_cv else { return false; }
        var sig_buf: u8[..128] = [];
        let sig_scheme, ok_sig = sign_tls13_certificate_verify(
            config.client_cert_der[..], config.client_priv_seed, cv_msg_buf[..cv_len], sig_buf,
        );
        // RFC 8446 Section 4.4.3: Certificate Verify - Selected scheme must appear in CertificateRequest.signature_algorithms.
        guard ok_sig && cert_req.sig_algorithms.contains(sig_scheme) else { return false; }

        var cv_payload: u8[..512] = [];
        guard encode_client_certificate_verify(cv_payload, sig_scheme, sig_buf[..]) else { return false; }
        var cv_msg: u8[..512] = [];
        cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
        cv_msg.append_u24_be(cv_payload.len as u32);
        cv_msg.append(cv_payload[..]);

        guard tls_seal_and_send_hs(fd, cipher_suite, client_hs_key, client_hs_iv, client_seq, cv_msg[..]) else {
            return false;
        }
        client_seq++;
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
    transcript:        TlsTranscript&,
    config:            const TlsClientHandshakeConfig&,
    cert_req_received: bool,
    cert_req:          const CertificateRequestMsg&,
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
    transcript_update(transcript, cli_fin_msg[..4 + hlen]);
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
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return; }
    let _ = g_tls_cipher_slots[idx].server_name.try_set(server_name);
    let _ = g_tls_cipher_slots[idx].negotiated_alpn.try_set(neg_alpn);
    g_tls_cipher_slots[idx].resumed = psk_resumed;
    g_tls_cipher_slots[idx].cipher_suite = cipher_suite;
    g_tls_cipher_slots[idx].key_len = key_len_u16;
    g_tls_cipher_slots[idx].hash_id = ks.hash_id;
    g_tls_cipher_slots[idx].hash_len = ks.hash_len;
    g_tls_cipher_slots[idx].is_server = false;
    for i in c_ap_key.len { g_tls_cipher_slots[idx].tx_key[i] = c_ap_key[i]; }
    tls_prepare_cipher_aes_key(cipher_suite, c_ap_key, g_tls_cipher_slots[idx].tx_aes_key);
    for i in 12 { g_tls_cipher_slots[idx].tx_iv[i] = c_ap_iv[i]; }
    g_tls_cipher_slots[idx].tx_seq = 0;
    for i in s_ap_key.len { g_tls_cipher_slots[idx].rx_key[i] = s_ap_key[i]; }
    tls_prepare_cipher_aes_key(cipher_suite, s_ap_key, g_tls_cipher_slots[idx].rx_aes_key);
    for i in 12 { g_tls_cipher_slots[idx].rx_iv[i] = s_ap_iv[i]; }
    g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
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

inline fn is_client_offered_tls13_suite(cs: u16) -> bool {
    return cs == rfc::TLS_CIPHER_AES_128_GCM_SHA256 ||
        cs == rfc::TLS_CIPHER_AES_256_GCM_SHA384 ||
        cs == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256;
}

// RFC 8446 Section 4.1.3: Server Hello - Verify legacy_session_id_echo, offered cipher suite, and key_share.
fn validate_live_client_sh(sh: const ParsedServerHello&, client_random: const u8[32]&) -> bool {
    guard sh.session_id_echo.len == 32 &&
        core::ct_eq_bytes(sh.session_id_echo[..], client_random[..]) &&
        is_client_offered_tls13_suite(sh.cipher_suite) else {
        return false;
    }
    return sh.is_hrr || sh.server_share.len > 0;
}

fn prepare_ech_outer_extension(config: const TlsClientHandshakeConfig&, out: u8[..512]&) {
    let ech_config_list = config.ech_config_list[..];
    guard ech_config_list.len > 0 else { return; }
    var ech_list = EchConfigList { .. };
    guard parse_ech_config_list(ech_config_list, ech_list) else { return; }
    var ech_cfg = EchConfig { .. };
    var ech_cs = EchCipherSuite { .. };
    guard select_ech_config(ech_list, ech_cfg, ech_cs) else { return; }
    let inner_random = tls_random_bytes_32();
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
    var eph_sk = tls_random_bytes_32();
    defer core::secure_zeroize_32(eph_sk);
    var ech_enc: u8[32]    = [0; 32];
    var ech_ct:  u8[..448] = [];
    let outer_aad = ech_cfg.public_name[..];
    guard seal_ech_inner(ech_cfg, ech_cs, outer_aad, inner_padded[..], eph_sk, ech_enc, ech_ct) else { return; }
    build_ech_outer_extension(ech_cfg.config_id, ech_cs, ech_enc, ech_ct[..], out);
}

fn regenerate_client_hrr_keyshare(
    selected_group: u16,
    enable_pq_cfg:  bool,
    client_priv:    u8[32]&,
    client_pub:     u8[32]&,
    pq_priv:        u8[2400]&,
    pq_pub:         u8[1184]&,
) -> bool, bool {
    guard selected_group != 0 else { return enable_pq_cfg, true; }
    if selected_group == rfc::GROUP_X25519 {
        client_priv = tls_random_bytes_32();
        client_pub = core::x25519_base_scalarmult(client_priv);
        return false, true;
    }
    guard enable_pq_cfg && selected_group == rfc::GROUP_X25519_MLKEM768 else {
        return false, false;
    }
    client_priv = tls_random_bytes_32();
    client_pub = core::x25519_base_scalarmult(client_priv);
    var pq_d = tls_random_bytes_32();
    var pq_z = tls_random_bytes_32();
    defer core::secure_zeroize_32(pq_d);
    defer core::secure_zeroize_32(pq_z);
    var ek, dk = tls_internal::mlkem768_keygen(pq_d, pq_z);
    defer core::secure_zeroize_slice(dk[..]);
    pq_priv = dk;
    pq_pub = ek;
    return true, true;
}

fn frame_handshake_msg_4k(msg_type: u8, payload: const u8[:], out_msg: u8[..4096]&) -> bool {
    out_msg.clear();
    let payload_u32 = (payload.len & 0xFFFFFF) as u32;
    let total_len = core::add_sat_i64(payload.len, 4);
    guard payload.len >= 0 && total_len <= out_msg.cap else { return false; }
    var hdr: u8[4] = [0; 4];
    guard encode_handshake_header(msg_type, payload_u32, hdr) else { return false; }
    out_msg.append(hdr[..]);
    out_msg.append(payload);
    return true;
}

fn handle_client_hrr_transition(
    fd:            i64,
    config:        const TlsClientHandshakeConfig&,
    client_random: const u8[32]&,
    client_priv:   u8[32]&,
    client_pub:    u8[32]&,
    pq_priv:       u8[2400]&,
    pq_pub:        u8[1184]&,
    ech_ext_raw:   const u8[:],
    transcript:    TlsTranscript&,
    hrr_raw_msg:   const u8[:],
    sh:            ParsedServerHello&,
) -> bool {
    guard validate_live_client_sh(sh, client_random) else { return false; }
    let hrr_cipher = sh.cipher_suite;
    let hrr_group = sh.selected_group;
    let has_group = hrr_group != 0;
    guard has_group || sh.hrr_cookie.len > 0 else { return false; }
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
            return false;
        }
    }

    let enable_pq_ch2, ok_regen = regenerate_client_hrr_keyshare(
        hrr_group, config.enable_pq_hybrid, client_priv, client_pub, pq_priv, pq_pub,
    );
    guard ok_regen else { return false; }

    transcript_update(transcript, hrr_raw_msg);
    var ks_hrr, ok_kshr = tls_internal::ks_init(hrr_cipher);
    guard ok_kshr && transcript_replace_with_message_hash(transcript, ks_hrr.hash_id, ks_hrr.hash_len) else {
        return false;
    }

    var ch2_payload: u8[..4096] = [];
    build_tls13_client_hello_payload(
        client_random, client_pub, config.server_name[..], config.alpn[..],
        ch2_payload, "", 0,
        enable_pq_ch2, if enable_pq_ch2 { pq_pub[..] } else { "" },
        ech_ext_raw, sh.hrr_cookie[..], config.client_cert_der.len > 0,
    );
    var ch2_msg: u8[..4096] = [];
    guard frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, ch2_payload[..], ch2_msg) else {
        return false;
    }

    guard send_plaintext_handshake_record(fd, ch2_msg[..]) else { return false; }
    transcript_update(transcript, ch2_msg[..]);

    var sh2_msg: u8[..16384] = [];
    guard read_plaintext_handshake_record(fd, sh2_msg) else { return false; }
    guard parse_live_server_hello(sh2_msg[..], sh) &&
        !sh.is_hrr &&
        validate_live_client_sh(sh, client_random) &&
        validate_hrr_cipher_suite(hrr_cipher, sh.cipher_suite) &&
        (hrr_group == 0 || sh.selected_group == hrr_group) else {
        return false;
    }
    transcript_update(transcript, sh2_msg[..]);
    return true;
}

// Executes full TLS 1.3 client handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn tls_client_handshake(fd: i64, config: const TlsClientHandshakeConfig&) -> u16, bool {
    let slot_idx = alloc_tls_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }

    let client_random = tls_random_bytes_32();
    var client_priv = tls_random_bytes_32();
    defer core::secure_zeroize_32(client_priv);
    var client_pub = core::x25519_base_scalarmult(client_priv);

    var pq_priv: u8[2400] = [0; 2400];
    defer core::secure_zeroize_slice(pq_priv[..]);
    var pq_pub: u8[1184] = [0; 1184];
    if config.enable_pq_hybrid {
        var pq_d = tls_random_bytes_32();
        var pq_z = tls_random_bytes_32();
        defer core::secure_zeroize_32(pq_d);
        defer core::secure_zeroize_32(pq_z);
        var ek, dk = tls_internal::mlkem768_keygen(pq_d, pq_z);
        defer core::secure_zeroize_slice(dk[..]);
        pq_priv = dk;
        pq_pub = ek;
    }

    var psk_ticket: u8[..256] = [];
    var psk_secret: u8[..48]  = [];
    defer core::secure_zeroize_slice(psk_secret[..]);
    var psk_age_add: u32 = 0;
    var psk_suite:   u16 = 0;
    let has_ticket = lookup_tls13_session_ticket_full(
        config.server_name[..], psk_ticket, psk_secret, psk_age_add, psk_suite,
    );
    let psk_hash_len: u8 = if has_ticket && rfc::tls13_cipher_suite_hash_len(psk_suite) == 48 { 48 } else { 32 };

    var ech_ext_raw: u8[..512] = [];
    prepare_ech_outer_extension(config, ech_ext_raw);

    var ch_payload: u8[..4096] = [];
    build_tls13_client_hello_payload(
        client_random, client_pub, config.server_name[..], config.alpn[..],
        ch_payload, psk_ticket[..], psk_age_add,
        config.enable_pq_hybrid, if config.enable_pq_hybrid { pq_pub[..] } else { "" },
        ech_ext_raw[..], "", config.client_cert_der.len > 0, psk_hash_len,
    );
    var ch_msg: u8[..4096] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    ch_msg.append_u24_be(ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    if has_ticket {
        patch_client_hello_psk_binder(ch_msg, psk_secret[..], psk_suite);
    }

    guard send_plaintext_handshake_record(fd, ch_msg[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    tls_write_all(fd, ccs[..]);

    var transcript = TlsTranscript { .. };
    transcript_update(transcript, ch_msg[..]);

    var sh_msg: u8[..16384] = [];
    guard read_plaintext_handshake_record(fd, sh_msg) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var sh = ParsedServerHello { .. };
    guard parse_live_server_hello(sh_msg[..], sh) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    if sh.is_hrr {
        let ok_hrr = handle_client_hrr_transition(
            fd, config, client_random, client_priv, client_pub,
            pq_priv, pq_pub, ech_ext_raw[..], transcript, sh_msg[..], sh,
        );
        guard ok_hrr else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else {
        guard validate_live_client_sh(sh, client_random) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        transcript_update(transcript, sh_msg[..]);
    }

    let cipher_suite = sh.cipher_suite;
    let srv_group = sh.selected_group;
    let srv_share = sh.server_share[..];
    let psk_resumed = sh.psk_resumed;

    if psk_resumed && (!has_ticket || rfc::tls13_cipher_suite_hash_len(cipher_suite) != psk_hash_len) {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ecdhe_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(ecdhe_secret);
    if srv_group == rfc::GROUP_X25519_MLKEM768 {
        var srv_share_raw: u8[..2048] = [];
        srv_share_raw.append_u16_be(srv_group);
        srv_share_raw.append_u16_be(srv_share.len as u16);
        srv_share_raw.append(srv_share[..]);
        var srv_pq_share = tls_internal::PostQuantumServerShare { .. };
        guard tls_internal::parse_hybrid_server_key_share(srv_pq_share, srv_share_raw[..]) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        var classic_ss, ok_c = core::x25519_shared_secret(client_priv, srv_pq_share.x25519_public);
        defer core::secure_zeroize_32(classic_ss);
        guard ok_c else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        var pq_ss: u8[32] = [0; 32];
        defer core::secure_zeroize_32(pq_ss);
        guard tls_internal::mlkem768_decapsulate(srv_pq_share.mlkem768_ciphertext[..], pq_priv[..], pq_ss[..]) else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        let ok_pq = tls_internal::derive_x25519_mlkem768_shared_secret_checked(
            classic_ss[..], pq_ss[..], ecdhe_secret[..],
        );
        guard ok_pq else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
    } else if srv_group == rfc::GROUP_X25519 && srv_share.len == 32 {
        var srv_pub: u8[32] = [0; 32];
        core::ct_copy_bytes(srv_pub[..], srv_share[..]);
        var ss, ok_ss = core::x25519_shared_secret(client_priv, srv_pub);
        defer core::secure_zeroize_32(ss);
        guard ok_ss else {
            free_tls_cipher_slot(slot_idx);
            return 0xFFFF, false;
        }
        core::ct_copy_bytes(ecdhe_secret[..], ss[..]);
    } else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ks, ok_ks = tls_internal::ks_init(cipher_suite);
    defer tls_internal::ks_zeroize(ks);
    let early_ikm = if psk_resumed { psk_secret[..] } else { "" };
    let ok_ks_adv = ok_ks &&
        tls_internal::ks_init_early_secret(ks, early_ikm) &&
        tls_internal::ks_advance_to_handshake(ks, ecdhe_secret[..]);
    guard ok_ks_adv else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ch_sh_hash: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var client_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_hs_key);
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_hs_key);
    var server_hs_iv: u8[12] = [0; 12];
    let key_len_u16 = rfc::tls13_cipher_suite_key_len(cipher_suite);
    let klen = key_len_u16 as i64;
    let hlen = ks.hash_len as i64;
    let ok_c_hs = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_hs_traffic[..hlen], key_len_u16,
        client_hs_key[..klen], client_hs_iv,
    );
    guard ok_c_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_hs = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_hs_traffic[..hlen], key_len_u16,
        server_hs_key[..klen], server_hs_iv,
    );
    guard ok_s_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var hs_reader = HandshakeRecordReader { .. };
    var neg_alpn: u8[..255] = [];
    var cert_req_received = false;
    var cert_req = CertificateRequestMsg { .. };
    let ok_flight = tls_client_process_server_flight(
        hs_reader, fd, cipher_suite, server_hs_key[..klen],
        server_hs_iv, ks, transcript, config, psk_resumed, neg_alpn,
        cert_req_received, cert_req, slot_idx,
    );
    guard ok_flight else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_srv_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard tls_internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    guard tls_client_send_finished(
        fd, cipher_suite, client_hs_key[..klen], client_hs_iv, ks, transcript,
        config, cert_req_received, cert_req,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_cli_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_cli_fin);
    tls_internal::ks_advance_to_resumption(ks, h_through_cli_fin[..]);

    var client_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_ap_key);
    var client_ap_iv:  u8[12] = [0; 12];
    var server_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_ap_key);
    var server_ap_iv: u8[12] = [0; 12];
    let ok_c_ap = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_ap_traffic[..hlen], key_len_u16,
        client_ap_key[..klen], client_ap_iv,
    );
    guard ok_c_ap else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_ap = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_ap_traffic[..hlen], key_len_u16,
        server_ap_key[..klen], server_ap_iv,
    );
    guard ok_s_ap else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    tls_setup_client_cipher_slot(
        slot_idx, cipher_suite, key_len_u16, ks,
        client_ap_key[..klen], client_ap_iv,
        server_ap_key[..klen], server_ap_iv,
        config.server_name[..], neg_alpn[..], psk_resumed,
    );
    return slot_idx, true;
}

// Matches a client ALPN extension against server comma-separated ALPN preferences (RFC 7301 Section 3.2).
fn select_server_alpn_from_ext<B>(
    alpn_ext:        const u8[:],
    server_alpn_csv: const u8[:],
    out_alpn:        B&,
) -> bool {
    out_alpn.clear();
    guard alpn_ext.len >= 3 else { return false; }
    var c = core::cursor_from(alpn_ext);
    let list_bytes, ok_l = c.read_u16_prefixed();
    guard ok_l && c.buf.len == 0 && list_bytes.len >= 2 else { return false; }
    var vlc = core::cursor_from(list_bytes);
    while vlc.buf.len > 0 {
        let p, ok_vp = vlc.read_u8_prefixed();
        guard ok_vp && p.len >= 1 && p.len <= 255 else { return false; }
    }
    guard server_alpn_csv.len > 0 else { return true; }

    var sc: i64 = 0;
    while sc < server_alpn_csv.len {
        var comma = sc;
        while comma < server_alpn_csv.len && server_alpn_csv[comma] != ',' { comma++; }
        let srv_proto = server_alpn_csv[sc..comma];
        sc = comma + 1;
        if srv_proto.len == 0 || srv_proto.len > 255 { continue; }
        var lc = core::cursor_from(list_bytes);
        while lc.buf.len > 0 {
            let cli_proto, _ = lc.read_u8_prefixed();
            if cli_proto == srv_proto { return out_alpn.try_set(srv_proto); }
        }
    }
    return true;
}

fn try_match_single_psk_binder(
    ticket_id:    const u8[:],
    binder_slice: const u8[:],
    ch_msg:       const u8[:],
    binders_len:  u16,
    selected_cs:  u16,
    out_psk:      u8[..48]&,
) -> bool, bool {
    out_psk.clear();
    var full_psk: u8[..48] = [];
    defer core::secure_zeroize_slice(full_psk[..]);
    var cs: u16 = 0;
    if !lookup_tls13_ticket_by_identity_full(ticket_id, full_psk, cs) ||
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
    guard tls_internal::verify_psk_binder(
        ks_early.hash_id, ks_early.hash_len, ks_early.binder_key[..hlen], trunc_ch, binder_slice,
    ) else { return false, false; }
    guard out_psk.try_set(full_psk[..]) else { return false, false; }
    return true, true;
}

// Reads one PskIdentity and matching PskBinderEntry from OfferedPsks cursors (RFC 8446 Section 4.2.11).
//
// Example:
//   ic = [0x00, 0x04, 'T', 'K', 'T', '1', 0, 0, 0, 0], bc = [0x20, ...32 bytes...]
//   returns: ticket_id = "TKT1", binder_slice = [32 bytes], ok = true
inline fn read_psk_identity_and_binder(
    ic: ByteCursor&,
    bc: ByteCursor&,
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
    ch_msg:          const u8[:],
    psk_ext:         const u8[:],
    selected_cs:     u16,
    out_psk:         u8[..48]&,
    out_selected_id: u16&,
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
                ticket_id, binder_slice, ch_msg, binders_bytes.len as u16, selected_cs, matched_psk,
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
    entries:         const TlsExtensionEntry[..32]&,
    payload:         const u8[:],
    psk_ext:         const u8[:],
    selected_cs:     u16,
    out_psk:         u8[..48]&,
    out_selected_id: u16&,
) -> bool, bool {
    let last_idx = core::sub_sat_i64(entries.len, 1);
    guard entries.len > 0 && last_idx >= 0 && last_idx < entries.len else { return false, false; }
    guard entries[last_idx].ext_type == rfc::TLS_EXT_PRE_SHARED_KEY else { return false, false; }
    let modes_ext, has_modes = find_extension(entries, rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES);
    guard has_modes && has_valid_psk_dhe_ke_mode(modes_ext) else { return false, false; }
    return eval_client_hello_psk_binders(payload, psk_ext, selected_cs, out_psk, out_selected_id);
}

// Extracts the 32-byte X25519 key share from a parsed KeyShareEntry list.
//
// Example:
//   shares = [0x00, 0x1D, 0x00, 0x20, ...32 bytes...]
//   returns: true, out_client_pub = [32 bytes]
fn extract_x25519_client_share(shares: const u8[:], out_client_pub: u8[32]&) -> bool {
    guard validate_client_key_share_entries(shares) else { return false; }
    var sc = core::cursor_from(shares);
    var found = false;
    while sc.buf.len > 0 {
        let group, ok_g = sc.read_u16();
        let kex_bytes, ok_k = sc.read_u16_prefixed();
        guard ok_g && ok_k else { return false; }
        if group == rfc::GROUP_X25519 {
            guard kex_bytes.len == 32 else { return false; }
            for i in 32 { out_client_pub[i] = kex_bytes[i]; }
            found = true;
        }
    }
    return found;
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

// Negotiates a TLS 1.3 cipher suite from the client's offered cipher suite list or ClientHello (RFC 8446 §4.1.2).
//
// Example:
//   raw = [0x13, 0x02, 0x13, 0x01]
//   returns: cs = 0x1302, ok = true
fn select_cipher_suite(raw: const u8[:]) -> u16, bool {
    return select_cipher_suite_from_list(ch_cipher_suites_slice(raw));
}

fn has_forbidden_extension(entries: const TlsExtensionEntry[..32]&) -> bool {
    for e in entries {
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
        } else if scheme == rfc::SIG_SCHEME_ED25519 || scheme == rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
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

// RFC 8446 Section 4.2.8: Key Share - Every KeyShareEntry group must appear in supported_groups in the same order.
fn validate_ch_groups_and_shares(grp_ext: const u8[:], shares: const u8[:]) -> bool {
    var c = core::cursor_from(grp_ext);
    let grp_bytes, ok = c.read_u16_prefixed();
    guard ok && c.buf.len == 0 && grp_bytes.len >= 2 && (grp_bytes.len & 1) == 0 else { return false; }
    guard group_bytes_contains(grp_bytes, rfc::GROUP_X25519) else { return false; }

    var sc = core::cursor_from(shares);
    var gc = core::cursor_from(grp_bytes);
    while sc.buf.len > 0 {
        let ks_grp, ok_g = sc.read_u16();
        let _, ok_k = sc.read_u16_prefixed();
        guard ok_g && ok_k else { return false; }
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
fn decode_ch_legacy_preamble(bc: ByteCursor&, out_sid: u8[..32]&) -> const u8[:], bool {
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
    out_entries: TlsExtensionEntry[..32]&,
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
    guard ok_sel && parse_extensions_block(bc.buf, out_entries) && !has_forbidden_extension(out_entries) else {
        return 0, false;
    }
    committed = true;
    return sel_cs, true;
}

// Validates mandatory TLS 1.3 ClientHello extensions and extracts the client X25519 share and sig_algs slice.
//
// Example:
//   entries = [supported_versions, signature_algorithms, supported_groups, key_share]
//   returns: sig_ext, ok = true, out_client_pub = [32 bytes]
fn extract_ch_mandatory_exts(
    entries:        const TlsExtensionEntry[..32]&,
    out_client_pub: u8[32]&,
) -> const u8[:], bool {
    core::secure_zeroize_32(out_client_pub);
    let sv_ext, has_sv = find_extension(entries, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    guard has_sv else { return "", false; }
    let supports_13, ok_sv = parse_client_supported_versions(sv_ext);
    guard ok_sv && supports_13 else { return "", false; }

    let sig_ext, has_sig = find_extension(entries, rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    guard has_sig && validate_ch_sig_algorithms(sig_ext, 0) else { return "", false; }

    let grp_ext, has_grp = find_extension(entries, rfc::TLS_EXT_SUPPORTED_GROUPS);
    let ks_data, has_ks = find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_grp && has_ks else { return "", false; }
    var shares: u8[..4096] = [];
    guard parse_key_share_client_extension(ks_data, shares) &&
        validate_ch_groups_and_shares(grp_ext, shares[..]) &&
        extract_x25519_client_share(shares[..], out_client_pub) else {
        core::secure_zeroize_32(out_client_pub);
        return "", false;
    }
    return sig_ext, true;
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

    var entries: TlsExtensionEntry[..32] = [];
    let sel_cs, ok_pre = decode_ch_server_preamble(payload, out_session_id, entries);
    guard ok_pre else { return false; }
    let sig_ext, ok_mand = extract_ch_mandatory_exts(entries, out_client_pub);
    guard ok_mand else { return false; }

    let sni_ext, has_sni = find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    if has_sni {
        guard parse_sni_extension(sni_ext, out_sni) else { return false; }
    }
    let alpn_ext, has_alpn = find_extension(entries, rfc::TLS_EXT_ALPN);
    if has_alpn {
        guard select_server_alpn_from_ext(alpn_ext, server_alpn_csv, out_alpn) else { return false; }
    }
    let psk_ext, has_psk = find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
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

// Parses ClientHello payload for server handshake, extracting session ID,
// client X25519 key share, ALPN, SNI, and PSK.
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

// Builds a minimal TLS 1.3 ServerHello wire payload echoing session ID and offering X25519 share.
fn build_tls13_server_hello_payload<B>(
    server_random:   const u8[32]&,
    session_id:      const u8[:],
    server_pub:      const u8[32]&,
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

    encode_key_share_server_extension(ext_buf, rfc::GROUP_X25519, server_pub[..]);
    if psk_resumed {
        ext_buf.append_u16_be(rfc::TLS_EXT_PRE_SHARED_KEY);
        ext_buf.append_u16_be(2);
        ext_buf.append_u16_be(selected_psk_id);
    }
    out.append_u16_be(ext_buf.len as u16);
    out.append(ext_buf[..]);
}

fn tls_server_send_cv(
    fd:            i64,
    cipher_suite:  u16,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    server_seq:    u64&,
    priv_seed:     const u8[32]&,
    transcript:    TlsTranscript&,
    cert_der:      const u8[:] = "",
) -> bool {
    let hash_id: u8 = if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        tls_internal::HASH_SHA384
    } else {
        tls_internal::HASH_SHA256
    };
    var h_to_cert: u8[..48] = [];
    transcript_current_hash(transcript, hash_id, h_to_cert);
    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 160 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = build_certificate_verify_message(true, h_to_cert[..], cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }
    var sig_buf: u8[..128] = [];
    let sig_scheme, ok_sig = sign_tls13_certificate_verify(
        cert_der, priv_seed, cv_msg_buf[..cv_len], sig_buf,
    );
    guard ok_sig else { return false; }

    var cv_payload: u8[..512] = [];
    guard encode_client_certificate_verify(cv_payload, sig_scheme, sig_buf[..]) else { return false; }
    var cv_msg: u8[..512] = [];
    cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
    cv_msg.append_u24_be(cv_payload.len as u32);
    cv_msg.append(cv_payload[..]);

    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cv_msg[..]) else {
        return false;
    }
    server_seq++;
    transcript_update(transcript, cv_msg[..]);
    return true;
}

fn tls_server_send_ee(
    fd:              i64,
    cipher_suite:    u16,
    server_hs_key:   const u8[:],
    server_hs_iv:    const u8[12]&,
    server_seq:      u64&,
    negotiated_alpn: const u8[:],
    transcript:      TlsTranscript&,
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
    transcript_update(transcript, ee_msg[..]);
    return true;
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

    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(bc.buf, entries) else { return 0; }
    let comp_ext, has_comp = find_extension(entries, rfc::TLS_EXT_COMPRESS_CERTIFICATE);
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

fn encode_server_cert_or_compressed_msg(
    config:                    const TlsServerHandshakeConfig&,
    negotiated_cert_comp_algo: u16,
    out_msg:                   u8[..4096]&,
) -> bool {
    out_msg.clear();
    var cert_payload: u8[..4096] = [];
    guard encode_client_certificate(cert_payload, "", config.cert_der[..]) else { return false; }

    let can_compress = negotiated_cert_comp_algo != 0 &&
        negotiated_cert_comp_algo == config.compressed_cert_algo &&
        config.compressed_cert_data.len > 0;
    if can_compress {
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

    return frame_handshake_msg_4k(rfc::TLS_HS_CERTIFICATE, cert_payload[..], out_msg);
}

// Encrypts and transmits the server handshake flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
fn tls_server_send_flight(
    fd:                        i64,
    server_hs_key:             const u8[:],
    server_hs_iv:              const u8[12]&,
    ks:                        const tls_internal::KeySchedule&,
    transcript:                TlsTranscript&,
    config:                    const TlsServerHandshakeConfig&,
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

    if !psk_resumed {
        var cert_msg: u8[..4096] = [];
        guard encode_server_cert_or_compressed_msg(config, negotiated_cert_comp_algo, cert_msg) else {
            return false;
        }

        guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cert_msg[..]) else {
            return false;
        }
        server_seq++;
        transcript_update(transcript, cert_msg[..]);

        guard tls_server_send_cv(
            fd, cipher_suite, server_hs_key, server_hs_iv,
            server_seq, config.priv_seed, transcript, config.cert_der[..],
        ) else {
            return false;
        }
    }

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_to_cv);
    var srv_fin_data: u8[48] = [0; 48];
    let hlen = ks.hash_len as i64;
    let ok_fin_calc = tls_internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen],
        h_to_cv[..], srv_fin_data[..hlen],
    );
    guard ok_fin_calc else { return false; }

    var srv_fin_msg: u8[64] = [0; 64];
    srv_fin_msg[0] = rfc::TLS_HS_FINISHED;
    srv_fin_msg[1] = 0; srv_fin_msg[2] = 0; srv_fin_msg[3] = ks.hash_len;
    core::ct_copy_bytes(srv_fin_msg[4..4 + hlen], srv_fin_data[..hlen]);

    let ok_send_fin = tls_seal_and_send_hs(
        fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, srv_fin_msg[..4 + hlen],
    );
    guard ok_send_fin else { return false; }
    transcript_update(transcript, srv_fin_msg[..4 + hlen]);
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
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return; }
    g_tls_cipher_slots[idx].cipher_suite = cipher_suite;
    g_tls_cipher_slots[idx].key_len = key_len_u16;
    g_tls_cipher_slots[idx].hash_id = ks.hash_id;
    g_tls_cipher_slots[idx].hash_len = ks.hash_len;
    g_tls_cipher_slots[idx].is_server = true;
    for i in s_ap_key.len { g_tls_cipher_slots[idx].tx_key[i] = s_ap_key[i]; }
    tls_prepare_cipher_aes_key(cipher_suite, s_ap_key, g_tls_cipher_slots[idx].tx_aes_key);
    for i in 12 { g_tls_cipher_slots[idx].tx_iv[i] = s_ap_iv[i]; }
    g_tls_cipher_slots[idx].tx_seq = 0;
    for i in c_ap_key.len { g_tls_cipher_slots[idx].rx_key[i] = c_ap_key[i]; }
    tls_prepare_cipher_aes_key(cipher_suite, c_ap_key, g_tls_cipher_slots[idx].rx_aes_key);
    for i in 12 { g_tls_cipher_slots[idx].rx_iv[i] = c_ap_iv[i]; }
    g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
}

// Executes full TLS 1.3 server handshake given an already-read ClientHello handshake message (RFC 8446 §4).
fn tls_server_handshake_with_ch(
    fd:     i64,
    ch_msg: const u8[:],
    config: const TlsServerHandshakeConfig&,
) -> u16, bool {
    let slot_idx = alloc_tls_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }
    let idx = slot_idx as i64;

    var transcript = TlsTranscript { .. };
    transcript_update(transcript, ch_msg);

    var session_id:      u8[..32]  = [];
    var client_pub:      u8[32]    = [0; 32];
    var neg_alpn:        u8[..255] = [];
    var client_sni:      u8[..255] = [];
    var cipher_suite:    u16       = 0;
    var psk_resumed:     bool      = false;
    var psk_secret:      u8[..48]  = [];
    var selected_psk_id: u16       = 0;
    defer core::secure_zeroize_slice(psk_secret[..]);
    let req_sig = detect_cert_sig_scheme(config.cert_der[..]);
    guard parse_client_hello_for_server_full(
        ch_msg, config.alpn[..], req_sig, session_id, client_pub,
        neg_alpn, client_sni, cipher_suite, psk_resumed, psk_secret, selected_psk_id,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let _ = g_tls_cipher_slots[idx].server_name.try_set(client_sni[..]);

    let server_random = tls_random_bytes_32();
    var server_priv = tls_random_bytes_32();
    defer core::secure_zeroize_32(server_priv);
    let server_pub = core::x25519_base_scalarmult(server_priv);

    var ecdhe_secret, ok_ecdhe = core::x25519_shared_secret(server_priv, client_pub);
    defer core::secure_zeroize_32(ecdhe_secret);
    guard ok_ecdhe else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var sh_payload: u8[..2048] = [];
    build_tls13_server_hello_payload(
        server_random, session_id[..], server_pub, sh_payload,
        psk_resumed, cipher_suite, selected_psk_id,
    );
    var sh_msg: u8[..2048] = [];
    sh_msg.push(rfc::TLS_HS_SERVER_HELLO);
    sh_msg.append_u24_be(sh_payload.len as u32);
    sh_msg.append(sh_payload[..]);

    guard send_plaintext_handshake_record(fd, sh_msg[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    tls_write_all(fd, ccs[..]);
    transcript_update(transcript, sh_msg[..]);

    var ks, ok_ks = tls_internal::ks_init(cipher_suite);
    defer tls_internal::ks_zeroize(ks);
    let early_ikm = if psk_resumed { psk_secret[..] } else { "" };
    let ok_ks_adv = ok_ks &&
        tls_internal::ks_init_early_secret(ks, early_ikm) &&
        tls_internal::ks_advance_to_handshake(ks, ecdhe_secret[..]);
    guard ok_ks_adv else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ch_sh_hash: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let key_len_u16 = rfc::tls13_cipher_suite_key_len(cipher_suite);
    let klen = key_len_u16 as i64;
    let hlen = ks.hash_len as i64;
    var client_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_hs_key);
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_hs_key);
    var server_hs_iv: u8[12] = [0; 12];
    let ok_c_hs = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_hs_traffic[..hlen], key_len_u16,
        client_hs_key[..klen], client_hs_iv,
    );
    guard ok_c_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_hs = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_hs_traffic[..hlen], key_len_u16,
        server_hs_key[..klen], server_hs_iv,
    );
    guard ok_s_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let negotiated_cert_comp_algo = select_server_cert_comp_algo(ch_msg, config.compressed_cert_algo);
    guard tls_server_send_flight(
        fd, server_hs_key[..klen], server_hs_iv, ks,
        transcript, config, neg_alpn[..], psk_resumed, negotiated_cert_comp_algo, cipher_suite,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var h_through_srv_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_srv_fin);
    guard tls_internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var hs_reader = HandshakeRecordReader { .. };
    var cli_fin_body: u8[..16384] = [];
    var msg_fin:      u8          = 0;
    let ok_msg = next_handshake_message(
        hs_reader, fd, cipher_suite, client_hs_key[..klen],
        client_hs_iv, msg_fin, cli_fin_body, 5000,
    );
    guard ok_msg else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    guard msg_fin == rfc::TLS_HS_FINISHED &&
        cli_fin_body.len == hlen &&
        hs_reader.current_offset == hs_reader.current_record_plain.len else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var exp_cli_fin: u8[48] = [0; 48];
    let ok_exp_fin = tls_internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.client_hs_traffic[..hlen],
        h_through_srv_fin[..], exp_cli_fin[..hlen],
    );
    guard ok_exp_fin else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    guard core::ct_eq_bytes(exp_cli_fin[..hlen], cli_fin_body[..hlen]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    transcript_update_msg(transcript, msg_fin, cli_fin_body[..hlen]);
    var h_through_cli_fin: u8[..48] = [];
    transcript_current_hash(transcript, ks.hash_id, h_through_cli_fin);
    tls_internal::ks_advance_to_resumption(ks, h_through_cli_fin[..]);

    var client_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(client_ap_key);
    var client_ap_iv:  u8[12] = [0; 12];
    var server_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(server_ap_key);
    var server_ap_iv: u8[12] = [0; 12];
    let ok_c_ap = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.client_ap_traffic[..hlen], key_len_u16,
        client_ap_key[..klen], client_ap_iv,
    );
    guard ok_c_ap else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_ap = tls_internal::ks_derive_key_iv(
        ks.hash_id, ks.server_ap_traffic[..hlen], key_len_u16,
        server_ap_key[..klen], server_ap_iv,
    );
    guard ok_s_ap else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    tls_setup_server_cipher_slot(
        slot_idx, cipher_suite, key_len_u16, ks,
        server_ap_key[..klen], server_ap_iv,
        client_ap_key[..klen], client_ap_iv,
    );
    g_tls_cipher_slots[idx].resumed = psk_resumed;
    let _ = g_tls_cipher_slots[idx].negotiated_alpn.try_set(neg_alpn[..]);
    return slot_idx, true;
}

// Executes full TLS 1.3 server handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn tls_server_handshake(fd: i64, config: const TlsServerHandshakeConfig&) -> u16, bool {
    var ch_msg: u8[..16384] = [];
    guard read_plaintext_handshake_record(fd, ch_msg) else {
        return 0xFFFF, false;
    }
    return tls_server_handshake_with_ch(fd, ch_msg[..], config);
}
