// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TLS 1.3 Transport Session, Cipher Slot Storage, and Handshake Wire Codecs.
// Conforms to RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN), and RFC 5280 / RFC 6125 (X.509 PKI).
namespace tls;

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
import .post_quantum;
import .cert_compression;
import .ech;
import .pki_internal;
import .session_internal;
import net.tcp;
import net.transport;
import net.driver.smartnic;

fn transcript_update(t: Transcript&, data: const u8[:]) {
    core::sha256_update(t.sha256_ctx, data);
    core::sha384_update(t.sha384_ctx, data);
}

fn transcript_update_msg(t: Transcript&, msg_type: u8, body: const u8[:]) {
    var hdr: u8[4] = [0; 4];
    hdr[0] = msg_type;
    hdr[1] = ((body.len >> 16) & 0xFF) as u8;
    hdr[2] = ((body.len >> 8) & 0xFF) as u8;
    hdr[3] = (body.len & 0xFF) as u8;
    transcript_update(t, hdr[..]);
    transcript_update(t, body);
}

fn transcript_current_hash(t: const Transcript&, hash_id: u8, out_hash: u8[..48]&) {
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
fn transcript_replace_with_message_hash(t: Transcript&, hash_id: u8, hash_len: u8) -> bool {
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

// Fills `out` with 32 cryptographically secure random bytes by mixing OS kernel CSPRNG
// (`BCryptGenRandom` / `RtlGenRandom` / `getrandom`), monotonic timer, wall clock,
// entropy pool, and sequence counter via Fast-Key-Erasure SHA-256 ratcheting (Invariant 16).
// Returns deterministic `core::sim_rng_fill` bytes directly when DST simulation entropy is active.
// Fails closed on OS CSPRNG error by wiping `out` and `g_tls_entropy_pool` and returning `false`.
fn random_bytes_32_checked(out: u8[32]&) -> bool {
    if core::sim_rng_is_active() {
        guard core::sim_rng_fill(out[..]) else {
            core::secure_zeroize_32(out);
            return false;
        }
        return true;
    }
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_ENTROPY_POOL);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_ENTROPY_POOL);

    var os_seed: u8[32] = [0; 32];
    defer core::secure_zeroize_32(os_seed);
    guard tls_internal::native_tls_csprng_bytes(os_seed[..]) == 0 else {
        core::secure_zeroize_32(g_tls_entropy_pool);
        g_tls_entropy_counter = 0;
        core::secure_zeroize_32(out);
        return false;
    }
    for i in 32 {
        g_tls_entropy_pool[i] ^= os_seed[i];
    }

    g_tls_entropy_counter = core::add_sat_u64(g_tls_entropy_counter, 1);
    let mono_ns = core::monotonic_now().nanos;
    let wall_now = core::now();
    let wall_sec = (max(0, wall_now.wall_sec) & 0x7FFFFFFFFFFFFFFF) as u64;
    let wall_nsec = (max(0, wall_now.nsec) & 0x7FFFFFFF) as u32;

    var mix: u8[64] = [0; 64];
    defer core::secure_zeroize_64(mix);
    core::ct_copy_bytes(mix[0..32], g_tls_entropy_pool[..]);
    core::write_le_u64_at(mix[..], 32, g_tls_entropy_counter);
    core::write_le_u64_at(mix[..], 40, mono_ns);
    core::write_le_u64_at(mix[..], 48, wall_sec);
    core::write_le_u32_at(mix[..], 56, wall_nsec);
    mix[60] = 0x01;
    let out_bytes = core::sha256(mix[..]);

    core::ct_copy_bytes(mix[0..32], g_tls_entropy_pool[..]);
    mix[60] = 0x02;
    for i in 32 {
        let off = core::add_sat_i64(32, i);
        mix[off] ^= out_bytes[i];
    }
    g_tls_entropy_pool = core::sha256(mix[..]);
    out = out_bytes;
    return true;
}

// Returns 32 cryptographically secure random bytes, failing closed with zeroed output
// and a wiped entropy pool if the OS CSPRNG fails.
fn random_bytes_32() -> u8[32] {
    var out: u8[32] = [0; 32];
    if !random_bytes_32_checked(out) {
        core::secure_zeroize_32(out);
    }
    return out;
}

// Returns the ALPN protocol negotiated on a cipher slot (empty if none).
inline fn session_alpn(slot_idx: u16) -> const u8[:] {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return ""; }
    return g_tls_cipher_slots[idx].negotiated_alpn[..];
}

// Returns true if the TLS 1.3 session was established via PSK resumption.
inline fn session_is_resumed(slot_idx: u16) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }
    return g_tls_cipher_slots[idx].resumed;
}

// Allocates a cipher slot lazily: reuses an inactive slot first, otherwise grows `g_tls_cipher_slots`
// up to `MAX_TLS_CIPHER_SLOTS`.
fn alloc_cipher_slot() -> u16 {
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_CIPHER_SLOTS);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_CIPHER_SLOTS);
    for i in g_tls_cipher_slots.len {
        let slot .= g_tls_cipher_slots[i];
        if !slot.in_use {
            tls_internal::wipe_and_reset_tls_cipher_slot(slot);
            slot.in_use = true;
            return (i & 0xFFFF) as u16;
        }
    }
    guard g_tls_cipher_slots.len < MAX_CIPHER_SLOTS else { return 0xFFFF; }
    let new_idx = g_tls_cipher_slots.len;
    g_tls_cipher_slots.push(CipherSlot { in_use: true, .. });
    return (new_idx & 0xFFFF) as u16;
}

inline fn prepare_cipher_aes_key(cipher_suite: u16, key: const u8[:], ctx: core::AesGcmKey&) {
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 || cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        let _ = core::aes_gcm_prepare_key(key, ctx);
    } else {
        core::zeroize_aes_gcm_key(ctx);
    }
}

// Releases a cipher slot and securely wipes all cryptographic key material.
fn free_cipher_slot(slot_idx: u16) {
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_CIPHER_SLOTS);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_CIPHER_SLOTS);
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return; }
    tls_internal::wipe_and_reset_tls_cipher_slot(g_tls_cipher_slots[idx]);
}

fn init_cipher_slot_for_test(
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
    prepare_cipher_aes_key(cipher_suite, tx_key[..klen], slot.tx_aes_key);
    for i in 12 { slot.tx_iv[i] = tx_iv[i]; }
    for i in klen { slot.rx_key[i] = rx_key[i]; }
    prepare_cipher_aes_key(cipher_suite, rx_key[..klen], slot.rx_aes_key);
    for i in 12 { slot.rx_iv[i] = rx_iv[i]; }
}

fn try_enable_ktls(slot_idx: u16, fd: i64) -> net_internal::SmartNicSession, bool {
    guard fd > 0 && !net::is_virtual_pipe_fd(fd) else {
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

fn ratchet_slot_rx_traffic_keys(slot: CipherSlot&) {
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
    prepare_cipher_aes_key(slot.cipher_suite, slot.rx_key[..k_len_i64], slot.rx_aes_key);
    slot.rx_seq = 0;
}

inline fn inspect_unsealed_handshake_control(hs_bytes: const u8[:]) -> SliceUnsealStatus {
    guard hs_bytes.len >= 4 else { return SliceUnsealStatus.Error; }
    var rem = hs_bytes;
    while rem.len > 0 {
        guard rem.len >= 4 else { return SliceUnsealStatus.Error; }
        let msg_type, msg_len, ok_m = parse_handshake_header(rem);
        guard ok_m else { return SliceUnsealStatus.Error; }
        let full_len = core::add_sat_i64(4, msg_len);
        guard rem.len >= full_len else { return SliceUnsealStatus.Error; }
        if msg_type == rfc::TLS_HS_KEY_UPDATE {
            return SliceUnsealStatus.Closed;
        }
        guard msg_type == rfc::TLS_HS_NEW_SESSION_TICKET else {
            return SliceUnsealStatus.Error;
        }
        rem = rem[full_len..];
    }
    return SliceUnsealStatus.ControlHandled;
}

fn store_slot_nst_global(slot: const CipherSlot&, nst: const NewSessionTicketMsg&) {
    guard slot.enable_session_tickets && slot.server_name.len > 0 && nst.ticket_lifetime > 0 else { return; }
    var ks_res = tls_internal::KeySchedule {
        hash_id:           slot.hash_id,
        hash_len:          slot.hash_len,
        stage:             tls_internal::KS_STAGE_RESUMPTION,
        resumption_secret: slot.resumption_secret,
        ..
    };
    defer tls_internal::ks_zeroize(ks_res);
    let h_len = slot.hash_len as i64;
    var psk_full: u8[48] = [0; 48];
    defer core::secure_zeroize_48(psk_full);
    if (h_len == 32 || h_len == 48) &&
        tls_internal::ks_derive_resumption_psk(ks_res, nst.ticket_nonce[..], psk_full[..h_len]) {
        store_session_ticket(
            slot.server_name[..],
            nst.ticket[..],
            psk_full[..h_len],
            nst.ticket_age_add,
            nst.ticket_lifetime,
            slot.cipher_suite,
        );
    }
}

inline fn apply_unsealed_slot_handshake_control(slot: CipherSlot&, hs_bytes: const u8[:]) -> SliceUnsealStatus {
    guard hs_bytes.len >= 4 else { return SliceUnsealStatus.Error; }
    var rem = hs_bytes;
    while rem.len > 0 {
        guard rem.len >= 4 else { return SliceUnsealStatus.Error; }
        let msg_type, msg_len, ok_m = parse_handshake_header(rem);
        guard ok_m else { return SliceUnsealStatus.Error; }
        let full_len = core::add_sat_i64(4, msg_len);
        guard rem.len >= full_len else { return SliceUnsealStatus.Error; }
        let msg_body = rem[4..full_len];
        if msg_type == rfc::TLS_HS_KEY_UPDATE {
            let _, ok_ku = track_received_key_update(slot.key_update_tracker, HsState.Connected, msg_body);
            guard ok_ku else { return SliceUnsealStatus.Error; }
            ratchet_slot_rx_traffic_keys(slot);
        } else if msg_type == rfc::TLS_HS_NEW_SESSION_TICKET {
            guard !slot.is_server else { return SliceUnsealStatus.Error; }
            var nst = NewSessionTicketMsg { .. };
            guard parse_new_session_ticket(msg_body, nst) && cache_session_ticket(slot.ticket_cache, nst) else {
                return SliceUnsealStatus.Error;
            }
            store_slot_nst_global(slot, nst);
        } else {
            return SliceUnsealStatus.Error;
        }
        rem = rem[full_len..];
    }
    return SliceUnsealStatus.ControlHandled;
}

fn unseal_single_slot_record<B>(
    slot:      CipherSlot&,
    rec_hdr:   const u8[:],
    rec_body:  const u8[:],
    scratch:   u8[:],
    out_plain: B&,
) -> SliceUnsealStatus {
    guard !aead_exceeds_hard_limit(slot.cipher_suite, slot.rx_seq) else {
        return SliceUnsealStatus.Error;
    }
    let klen = slot.key_len as i64;
    let dec_len, inner_type, _, ok_dec = tls_internal::record_decrypt_prepared_into(
        slot.cipher_suite,
        slot.rx_key[..klen],
        slot.rx_aes_key,
        slot.rx_iv,
        slot.rx_seq,
        rec_hdr,
        rec_body,
        scratch[..rec_body.len],
    );
    guard ok_dec else { return SliceUnsealStatus.Error; }
    increment_record_seq_num(slot.rx_seq);

    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        guard out_plain.try_append(scratch[..dec_len]) else { return SliceUnsealStatus.Error; }
        on_key_update_app_data(slot.key_update_tracker);
        return SliceUnsealStatus.Ok;
    }
    if inner_type == rfc::TLS_CONTENT_ALERT {
        let alert_level, alert_code, _, ok_a = parse_alert_message(scratch[..dec_len]);
        if ok_a && alert_code == Alert.CloseNotify {
            slot.peer_closed = true;
            return SliceUnsealStatus.Closed;
        }
        if ok_a && alert_level == 1 && alert_code == Alert.UserCanceled {
            return SliceUnsealStatus.ControlHandled;
        }
        return SliceUnsealStatus.Error;
    }
    if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
        let hs_st = apply_unsealed_slot_handshake_control(slot, scratch[..dec_len]);
        if hs_st == SliceUnsealStatus.Closed {
            slot.peer_closed = true;
        }
        return hs_st;
    }
    return SliceUnsealStatus.Error;
}

inline fn consume_next_ciphertext_record<B>(
    slot:      CipherSlot&,
    rem:       const u8[:],
    scratch:   u8[:],
    out_plain: B&,
) -> i64, SliceUnsealStatus {
    let total_rec, hdr_st = tls_internal::peek_ciphertext_record_len(rem);
    guard hdr_st == SliceUnsealStatus.Ok else { return 0, hdr_st; }
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

fn tls_unseal_records_with_scratch<B>(
    slot:      CipherSlot&,
    cipher_in: const u8[:],
    scratch:   u8[:],
    out_plain: B&,
) -> i64, SliceUnsealStatus {
    let saved_len = out_plain.len;
    var rem = cipher_in;
    var consumed:    i64 = 0;
    var max_touched: i64 = 0;
    var final_status = SliceUnsealStatus.ControlHandled;
    defer if max_touched > 0 { core::secure_zeroize_slice(scratch[..max_touched]); };
    while rem.len > 0 {
        let total_rec, st = consume_next_ciphertext_record(slot, rem, scratch, out_plain);
        if total_rec > rfc::TLS_RECORD_HEADER_LEN {
            let body_len = min(core::sub_sat_i64(total_rec, rfc::TLS_RECORD_HEADER_LEN), scratch.len);
            max_touched = max(max_touched, body_len);
        }
        if st == SliceUnsealStatus.NeedMore { break; }
        if st == SliceUnsealStatus.Error {
            out_plain.resize(saved_len);
            return 0, SliceUnsealStatus.Error;
        }
        consumed = core::add_sat_i64(consumed, total_rec);
        rem = rem[total_rec..];
        if st == SliceUnsealStatus.Closed { return consumed, SliceUnsealStatus.Closed; }
        if st == SliceUnsealStatus.Ok { final_status = SliceUnsealStatus.Ok; }
    }
    if consumed == 0 { return 0, SliceUnsealStatus.NeedMore; }
    return consumed, final_status;
}

// Decrypts complete TLS 1.3 records from `cipher_in` into `out_plain` (RFC 8446 Section 5.2).
// Leaves trailing incomplete record bytes unconsumed so reactor buffers can compact them.
//
// Example:
//   cipher_in = <40-byte sealed "GET / HTTP/1.1\r\n\r\n" record>
//   returns: consumed = 40, status = TlsSliceUnsealStatus.Ok, out_plain = "GET / HTTP/1.1\r\n\r\n"
fn cipher_slot_unseal_records<B>(
    slot_idx:  u16,
    cipher_in: const u8[:],
    out_plain: B&,
) -> i64, SliceUnsealStatus {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else {
        return 0, SliceUnsealStatus.Error;
    }
    let slot .= g_tls_cipher_slots[idx];
    if slot.peer_closed { return 0, SliceUnsealStatus.Closed; }

    if cipher_in.len <= 2048 {
        var small_scratch: u8[2048] = [0; 2048];
        return tls_unseal_records_with_scratch(slot, cipher_in, small_scratch[..], out_plain);
    }
    var scratch: u8[16640] = [0; 16640];
    return tls_unseal_records_with_scratch(slot, cipher_in, scratch[..], out_plain);
}

fn tls_seal_app_data_with_buf<B>(
    slot:       CipherSlot&,
    plain_in:   const u8[:],
    rec_buf:    u8[:],
    out_cipher: B&,
) -> bool {
    let saved_len = out_cipher.len;
    let saved_seq = slot.tx_seq;
    var committed = false;
    defer if !committed {
        out_cipher.resize(saved_len);
        slot.tx_seq = saved_seq;
    };

    let klen = slot.key_len as i64;
    var rem = plain_in;
    while rem.len > 0 {
        guard !aead_exceeds_hard_limit(slot.cipher_suite, slot.tx_seq) else {
            return false;
        }
        let chunk_len = min(rem.len, rfc::TLS_MAX_RECORD_PLAINTEXT_LEN);
        let sealed_len, _, ok_seal = tls_internal::record_seal_prepared_into(
            slot.cipher_suite,
            slot.tx_key[..klen],
            slot.tx_aes_key,
            slot.tx_iv,
            slot.tx_seq,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            rem[..chunk_len],
            rec_buf,
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

fn cipher_slot_seal_app_data<B>(
    slot_idx:   u16,
    plain_in:   const u8[:],
    out_cipher: B&,
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    let slot .= g_tls_cipher_slots[idx];
    guard slot.in_use && !slot.peer_closed else { return false; }
    if plain_in.len == 0 { return true; }

    if plain_in.len <= 2000 {
        var small_rec: u8[2048] = [0; 2048];
        return tls_seal_app_data_with_buf(slot, plain_in, small_rec[..], out_cipher);
    }
    var rec_buf: u8[16645] = [0; 16645];
    return tls_seal_app_data_with_buf(slot, plain_in, rec_buf[..], out_cipher);
}

// Seals an RFC 8446 Section 6.1 encrypted CloseNotify alert record into `out_cipher`.
fn cipher_slot_seal_close_notify<B>(slot_idx: u16, out_cipher: B&) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    let slot .= g_tls_cipher_slots[idx];
    guard slot.in_use && !aead_exceeds_hard_limit(slot.cipher_suite, slot.tx_seq) else { return false; }
    let saved_len = out_cipher.len;
    let saved_seq = slot.tx_seq;
    var committed = false;
    defer if !committed {
        out_cipher.resize(saved_len);
        slot.tx_seq = saved_seq;
    };
    let alert_data: u8[2] = [1, 0];
    var rec_buf: u8[64] = [0; 64];
    let klen = slot.key_len as i64;
    let sealed_len, _, ok_seal = tls_internal::record_seal_prepared_into(
        slot.cipher_suite,
        slot.tx_key[..klen],
        slot.tx_aes_key,
        slot.tx_iv,
        slot.tx_seq,
        rfc::TLS_CONTENT_ALERT,
        alert_data[..],
        rec_buf[..],
    );
    guard ok_seal && sealed_len > 0 && out_cipher.try_append(rec_buf[..sealed_len]) else {
        return false;
    }
    increment_record_seq_num(slot.tx_seq);
    committed = true;
    return true;
}

// Extracts DNS SubjectAltName entries from a DER X.509 certificate into `g_tls_cipher_slots[slot_idx].san_hosts`.
fn populate_slot_san_hosts_from_der(slot_idx: u16, cert_der: const u8[:]) -> bool {
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
fn copy_slot_san_hosts<B>(slot_idx: u16, out_sans: B&) {
    out_sans.clear();
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return; }
    for &san in g_tls_cipher_slots[idx].san_hosts {
        let _ = out_sans.try_push(copy(san));
    }
}

// Exports RFC 5705 / RFC 8446 §7.5 keying material from an active TLS 1.3 cipher slot.
fn session_export_keying_material(
    slot_idx: u16,
    label:    const u8[:],
    context:  const u8[:],
    length:   u16,
    out:      u8[..256]&,
) -> bool {
    var committed = false;
    defer if !committed { out.clear(); };
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
    var tmp: u8[256] = [0; 256];
    defer core::secure_zeroize_slice(tmp[..out_len]);
    guard tls_internal::ks_export_keying_material(ks, label, context, length, tmp[..out_len]) else {
        return false;
    }
    guard out.try_set(tmp[..out_len]) else { return false; }
    committed = true;
    return true;
}

// Seals and transmits a single TLS 1.3 record using active slot keys, enforcing the
// RFC 8446 Section 5.5 hard AEAD record limit without triggering automatic KeyUpdate.
fn send_encrypted_record_raw(
    fd:         i64,
    slot_idx:   u16,
    inner_type: u8,
    payload:    const u8[:],
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    guard g_tls_cipher_slots[idx].in_use else { return false; }
    guard payload.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    guard !aead_exceeds_hard_limit(
        g_tls_cipher_slots[idx].cipher_suite, g_tls_cipher_slots[idx].tx_seq,
    ) else {
        return false;
    }

    var ct_buf: u8[..16640] = [];
    let needed = core::add_sat_i64(payload.len, 22);
    guard needed <= ct_buf.cap else { return false; }
    ct_buf.resize(needed, 0);
    let klen = g_tls_cipher_slots[idx].key_len as i64;
    let sealed_len, alert, ok_seal = tls_internal::record_seal_prepared_into(
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
    return tls_internal::tls_write_all(fd, ct_buf[..sealed_len]);
}

// Encrypts and transmits a single TLS 1.3 record over socket using slot keys.
// Automatically triggers an RFC 8446 Section 5.5 KeyUpdate before sealing application
// data when the TX sequence number reaches the AEAD key-update ceiling.
fn send_encrypted_record(
    fd:         i64,
    slot_idx:   u16,
    inner_type: u8,
    payload:    const u8[:],
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else {
        return false;
    }
    guard !aead_exceeds_hard_limit(
        g_tls_cipher_slots[idx].cipher_suite, g_tls_cipher_slots[idx].tx_seq,
    ) else {
        return false;
    }
    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA &&
        fd > 0 &&
        aead_needs_key_update(g_tls_cipher_slots[idx].cipher_suite, g_tls_cipher_slots[idx].tx_seq) {
        guard send_key_update(fd, slot_idx, rfc::KEY_UPDATE_NOT_REQUESTED) else { return false; }
    }
    return send_encrypted_record_raw(fd, slot_idx, inner_type, payload);
}

// Sends application data chunks over TLS 1.3 record layer (RFC 8446 §5.2).
// Uses single-MSS records (`TLS_SINGLE_MSS_PLAINTEXT_LEN` = 1378 B) during the first 64 KB
// (`TLS_DYNAMIC_RESIZE_THRESHOLD_BYTES`) to eliminate multi-packet TCP head-of-line blocking during Slow Start.
fn transport_send(fd: i64, slot_idx: u16, data: const u8[:]) -> i32 {
    let ret_len = (data.len & 0x7FFFFFFF) as i32;
    guard fd > 0 && data.len > 0 else { return 0; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return -1; }
    guard g_tls_cipher_slots[idx].in_use && !g_tls_cipher_slots[idx].peer_closed else { return -1; }

    var offset: i64 = 0;
    while offset < data.len {
        let rem = core::sub_sat_i64(data.len, offset);
        let chunk_len, next_bytes = tls_internal::select_tls_outbound_chunk_len(
            rem, g_tls_cipher_slots[idx].bytes_sent,
        );
        let next_offset = core::add_sat_i64(offset, chunk_len);
        let ok_s = send_encrypted_record(
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
fn send_new_session_ticket(
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
    guard send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]) else { return false; }

    if ticket_lifetime > 0 && ticket.len > 0 && ticket.len <= 1536 {
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
            store_session_ticket(
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
fn send_key_update(fd: i64, slot_idx: u16, request_update: u8) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    guard g_tls_cipher_slots[idx].in_use else { return false; }

    var ku_body: u8[..4] = [];
    guard encode_key_update(ku_body, request_update) else { return false; }
    var hs_msg: u8[..8] = [];
    hs_msg.push(rfc::TLS_HS_KEY_UPDATE);
    hs_msg.push(0x00); hs_msg.push(0x00); hs_msg.push(0x01);
    hs_msg.append(ku_body[..]);
    let ok_s = send_encrypted_record_raw(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]);
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
    prepare_cipher_aes_key(
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
    prepare_cipher_aes_key(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].rx_key[..k_len_i64],
        g_tls_cipher_slots[idx].rx_aes_key,
    );
    g_tls_cipher_slots[idx].rx_seq = 0;
    if needs_resp {
        send_key_update(fd, slot_idx, rfc::KEY_UPDATE_NOT_REQUESTED);
    }
}

fn process_received_nst(idx: i64, msg_body: const u8[:]) -> bool {
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return false; }
    guard !g_tls_cipher_slots[idx].is_server else { return false; }
    var nst = NewSessionTicketMsg { .. };
    guard parse_new_session_ticket(msg_body, nst) else { return false; }
    guard cache_session_ticket(g_tls_cipher_slots[idx].ticket_cache, nst) else { return false; }
    store_slot_nst_global(g_tls_cipher_slots[idx], nst);
    return true;
}

fn dispatch_post_handshake_record(fd: i64, slot_idx: u16, hs_bytes: const u8[:]) -> bool {
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
            guard process_received_nst(idx, msg_body) else { return false; }
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

fn tls_recv_app_record(fd: i64, slot_idx: u16, idx: i64, dst: u8[:], timeout_ms: u32) -> i32 {
    guard idx >= 0 && idx < g_tls_cipher_slots.len && g_tls_cipher_slots[idx].in_use else { return -1; }
    guard !aead_exceeds_hard_limit(
        g_tls_cipher_slots[idx].cipher_suite, g_tls_cipher_slots[idx].rx_seq,
    ) else {
        return -1;
    }
    var hdr_buf: u8[5] = [0; 5];
    let hdr_st = tls_internal::tls_read_exact_status(fd, hdr_buf[..], timeout_ms);
    if hdr_st == -2 { return -2; }
    if hdr_st == 0 {
        g_tls_cipher_slots[idx].peer_closed = true;
        return 0;
    }
    guard hdr_st == 1 else { return -1; }

    let ct, ver, payload_len_u16, alert, ok_p = parse_record_header(hdr_buf[..]);
    guard ok_p else { return -1; }
    let payload_len = payload_len_u16 as i64;
    guard payload_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else { return -1; }

    var ct_payload: u8[16640] = [0; 16640];
    let ok_body = tls_internal::tls_read_exact(fd, ct_payload[..payload_len], timeout_ms);
    guard ok_body && ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return -1; }

    var plain_dec: u8[16640] = [0; 16640];
    defer core::secure_zeroize_slice(plain_dec[..payload_len]);
    let klen = g_tls_cipher_slots[idx].key_len as i64;
    let dec_len, inner_type, alert_dec, ok_dec = tls_internal::record_decrypt_prepared_into(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].rx_key[..klen],
        g_tls_cipher_slots[idx].rx_aes_key,
        g_tls_cipher_slots[idx].rx_iv,
        g_tls_cipher_slots[idx].rx_seq,
        hdr_buf[..],
        ct_payload[..payload_len],
        plain_dec[..payload_len],
    );
    guard ok_dec else { return -1; }
    increment_record_seq_num(g_tls_cipher_slots[idx].rx_seq);

    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        let to_user = min(dec_len, dst.len);
        core::ct_copy_bytes(dst[..to_user], plain_dec[..to_user]);
        if dec_len > dst.len {
            let _ = g_tls_cipher_slots[idx].rx_plain_buf.try_set(plain_dec[dst.len..dec_len]);
            g_tls_cipher_slots[idx].rx_plain_pos = 0;
        }
        on_key_update_app_data(g_tls_cipher_slots[idx].key_update_tracker);
        return to_user as i32;
    }

    if inner_type == rfc::TLS_CONTENT_ALERT {
        let alert_level, alert_code, _, ok_a = parse_alert_message(plain_dec[..dec_len]);
        if ok_a && alert_code == Alert.CloseNotify {
            g_tls_cipher_slots[idx].peer_closed = true;
            return 0;
        }
        if ok_a && alert_level == 1 && alert_code == Alert.UserCanceled {
            return 0;
        }
        return -1;
    }

    if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
        guard dispatch_post_handshake_record(fd, slot_idx, plain_dec[..dec_len]) else { return -1; }
        return 0;
    }
    return -1;
}

// Receives decrypted application data bytes from TLS 1.3 socket, handling residual buffers,
// post-handshake NewSessionTicket, KeyUpdate, and CloseNotify alerts (RFC 8446 §5.2, §4.6).
fn transport_recv_slice(fd: i64, slot_idx: u16, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return -1; }
    guard g_tls_cipher_slots[idx].in_use else { return -1; }
    if g_tls_cipher_slots[idx].peer_closed { return 0; }

    let drained = tls_internal::tls_drain_rx_buf(idx, dst);
    if drained > 0 { return drained; }

    for _ in 16 {
        let res = tls_recv_app_record(fd, slot_idx, idx, dst, timeout_ms);
        if res != 0 { return res; }
        if g_tls_cipher_slots[idx].peer_closed { return 0; }
    }
    return -1;
}

// Sends a CloseNotify alert, wipes secrets, and closes socket (RFC 8446 §6.1).
fn transport_close(fd: i64, slot_idx: u16) {
    if fd > 0 {
        let idx = slot_idx as i64;
        let valid_slot = idx >= 0 && idx < g_tls_cipher_slots.len &&
            g_tls_cipher_slots[idx].in_use && !g_tls_cipher_slots[idx].peer_closed;
        if valid_slot {
            let alert_data: u8[2] = [1, 0];
            if g_tls_cipher_slots[idx].ktls_tx_active {
                let _ = net_internal::smartnic_send_record(fd, alert_data[..], rfc::TLS_CONTENT_ALERT);
            } else {
                send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_ALERT, alert_data[..]);
            }
        }
        if net::is_virtual_pipe_fd(fd) {
            net::virtual_fd_close(fd);
        } else {
            net::tcp_close(fd);
        }
    }
    free_cipher_slot(slot_idx);
}

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
            if tls_internal::parse_ipv4_literal(ip_san, ip4) {
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

// Extracts the optional stapled OCSP response from a CertificateEntry extension block (RFC 8446 Section 4.4.2.1).
//
// Example:
//   ext_bytes = [0x00, 0x05, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x30, 0x00]
//   returns: [0x30, 0x00], ok = true
fn extract_leaf_ocsp_extension(ext_bytes: const u8[:]) -> const u8[:], bool {
    var entries: ExtensionEntry[..32] = [];
    var cursor = core::cursor_from(ext_bytes);
    while cursor.cursor_len() > 0 {
        let ext_type, ok_t = cursor.read_u16();
        let ext_data, ok_d = cursor.read_u16_sub_cursor();
        guard ok_t && ok_d &&
            (ext_type == rfc::TLS_EXT_STATUS_REQUEST || ext_type == rfc::TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP) &&
            tls_internal::check_and_add_extension(entries, ext_type, ext_data.buf) else {
            return "", false;
        }
    }
    let status_data, has_st = find_extension(entries, rfc::TLS_EXT_STATUS_REQUEST);
    guard has_st else { return "", true; }
    return unwrap_ocsp_response(status_data);
}

// Parses a Certificate message payload into DER cert slices and optional leaf OCSP (RFC 8446 Section 4.4.2).
//
// Example:
//   payload = [0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x04, 'C', 'E', 'R', 'T', 0x00, 0x00]
//   returns: out_leaf_ocsp = "", ok = true, out_certs.len = 1
fn parse_certificate_chain_and_ocsp(
    payload:   const u8[:],
    out_certs: const u8[:][..8]&,
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

// Computes a TLS 1.3 SHA-256 PSK binder tag over a truncated ClientHello handshake message (RFC 8446 §4.2.11.2).
fn compute_psk_binder(
    binder_key:   const u8[32]&,
    truncated_ch: const u8[:],
    out_binder:   u8[32]&,
) -> bool {
    var full: u8[..48] = [];
    defer core::secure_zeroize_slice(full[..]);
    guard tls_internal::compute_tls13_psk_binder_for_hash(
        tls_internal::HASH_SHA256, binder_key[..], truncated_ch, full,
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
    tls_internal::encode_key_share_client_extension(ext_buf, shares[..]);

    if tls_internal::validate_sni_host_bytes(server_name) {
        ext_buf.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
        let sni_len = (server_name.len + 3) as u16;
        ext_buf.append_u16_be(sni_len + 2);
        ext_buf.append_u16_be(sni_len);
        ext_buf.push(0);
        ext_buf.append_u16_be(server_name.len as u16);
        ext_buf.append(server_name);
    }

    if alpn.len > 0 && alpn.len <= 255 {
        tls_internal::encode_alpn_extension_from_csv(ext_buf, alpn);
    }

    if ech_ext_raw.len > 0 && ech_ext_raw.len <= 1024 {
        ext_buf.append_u16_be(rfc::EXT_ENCRYPTED_CLIENT_HELLO);
        ext_buf.append_u16_be(ech_ext_raw.len as u16);
        ext_buf.append(ech_ext_raw);
    }

    tls_internal::encode_psk_client_extensions(ext_buf, psk_ticket, psk_age_add, psk_binder_len);

    out.append_u16_be(ext_buf.len as u16);
    out.append(ext_buf[..]);
}

fn has_complete_plaintext_handshake_msg(raw_msg: const u8[:]) -> bool {
    guard raw_msg.len >= 4 else { return false; }
    let _, msg_len, ok_m = parse_handshake_header(raw_msg);
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
    var committed = false;
    defer if !committed { out_alpn.clear(); };
    var entries: ExtensionEntry[..32] = [];
    guard parse_extensions_block(ee_body, entries) else { return false; }
    guard tls_internal::validate_ee_solicited_extensions(entries, offered_alpn_csv, sni_state, allow_ech_retry) else {
        return false;
    }
    out_alpn.clear();
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
    guard tls_internal::alpn_csv_contains_proto(offered_alpn_csv, proto) && out_alpn.try_set(proto) else {
        return false;
    }
    committed = true;
    return true;
}

fn verify_crl_for_chain(
    crl_der:      const u8[:],
    chain_parsed: const ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    now_unix:     i64 = 0,
) -> bool {
    let empty_store = TrustAnchorStore { .. };
    return tls_internal::verify_crl_for_chain_with_store(crl_der, chain_parsed, chain_slices, now_unix, empty_store);
}

// Signs a TLS 1.3 CertificateVerify message using Ed25519 (`0x0807`) or ECDSA P-256 (`0x0403` DER)
// according to the certificate's SubjectPublicKeyInfo algorithm (RFC 8446 Section 4.4.3).
fn sign_certificate_verify(
    cert_der:  const u8[:],
    priv_seed: const u8[32]&,
    cv_msg:    const u8[:],
    out_sig:   u8[..128]&,
) -> u16, bool {
    out_sig.clear();
    let scheme = tls_internal::detect_cert_sig_scheme(cert_der);
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
    var vlc = core::cursor_from(list_bytes);
    while vlc.buf.len > 0 {
        let p, ok_vp = vlc.read_u8_prefixed();
        guard ok_vp && p.len >= 1 && p.len <= 255 else { return false; }
    }
    out_alpn.clear();
    guard server_alpn_csv.len > 0 else {
        committed = true;
        return true;
    }

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
            if cli_proto == srv_proto {
                guard out_alpn.try_set(srv_proto) else { return false; }
                committed = true;
                return true;
            }
        }
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
    return tls_internal::select_cipher_suite_from_list(tls_internal::ch_cipher_suites_slice(raw));
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

    tls_internal::encode_key_share_server_extension(ext_buf, rfc::GROUP_X25519, server_pub[..]);
    if psk_resumed {
        ext_buf.append_u16_be(rfc::TLS_EXT_PRE_SHARED_KEY);
        ext_buf.append_u16_be(2);
        ext_buf.append_u16_be(selected_psk_id);
    }
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

    var entries: ExtensionEntry[..32] = [];
    guard parse_extensions_block(bc.buf, entries) else { return 0; }
    let comp_ext, has_comp = find_extension(entries, rfc::TLS_EXT_COMPRESS_CERTIFICATE);
    guard has_comp else { return 0; }
    var algos: u16[..127] = [];
    guard tls_internal::parse_compress_certificate_ext(comp_ext, algos) else { return 0; }
    if algos.contains(server_algo) {
        return server_algo;
    }
    return 0;
}

fn encode_server_cert_or_compressed_msg(
    config:                    const ServerHandshakeConfig&,
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
        guard tls_internal::build_compressed_cert_payload(
            config.compressed_cert_algo,
            cert_payload.len,
            config.compressed_cert_data[..],
            comp_payload,
        ) else {
            return false;
        }
        return tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_COMPRESSED_CERTIFICATE, comp_payload[..], out_msg);
    }

    return tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_CERTIFICATE, cert_payload[..], out_msg);
}
