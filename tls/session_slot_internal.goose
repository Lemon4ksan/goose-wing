// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 cipher-slot record sealing, unsealing, key-ratchet, and post-handshake helpers.
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
import .ticket;
import .ticket_internal;
import .session_internal;
import .session;
import net.tcp;
import net.transport;

inline fn prepare_cipher_aes_key(cipher_suite: u16, key: const u8[:], ctx: core::AesGcmKey&) {
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 || cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        let _ = core::aes_gcm_prepare_key(key, ctx);
    } else {
        core::zeroize_aes_gcm_key(ctx);
    }
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
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else { return; }
    let slot .= tls::g_tls_cipher_slots[idx];
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
        HASH_SHA384
    } else {
        HASH_SHA256
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

fn ratchet_slot_rx_traffic_keys(slot: tls::CipherSlot&) -> bool {
    let h_id = slot.hash_id;
    let h_len = slot.hash_len;
    let k_len = slot.key_len;
    let h_len_i64 = h_len as i64;
    let k_len_i64 = k_len as i64;
    guard (h_len_i64 == 32 || h_len_i64 == 48) && (k_len_i64 == 16 || k_len_i64 == 32) else { return false; }

    var next_secret: u8[48] = slot.rx_traffic_secret;
    var next_key:    u8[32] = [0; 32];
    var next_iv:     u8[12] = [0; 12];
    defer core::secure_zeroize_48(next_secret);
    defer core::secure_zeroize_32(next_key);
    defer core::secure_zeroize_slice(next_iv[..]);
    guard ks_update_traffic_secret(h_id, h_len, next_secret[..h_len_i64]) &&
        ks_derive_key_iv(h_id, next_secret[..h_len_i64], k_len, next_key[..k_len_i64], next_iv) else {
        return false;
    }

    slot.rx_traffic_secret = next_secret;
    slot.rx_key = next_key;
    slot.rx_iv = next_iv;
    prepare_cipher_aes_key(slot.cipher_suite, slot.rx_key[..k_len_i64], slot.rx_aes_key);
    slot.rx_seq = 0;
    return true;
}

fn ratchet_slot_tx_traffic_keys(slot: tls::CipherSlot&) -> bool {
    let h_id = slot.hash_id;
    let h_len = slot.hash_len;
    let k_len = slot.key_len;
    let h_len_i64 = h_len as i64;
    let k_len_i64 = k_len as i64;
    guard (h_len_i64 == 32 || h_len_i64 == 48) && (k_len_i64 == 16 || k_len_i64 == 32) else { return false; }

    var next_secret: u8[48] = slot.tx_traffic_secret;
    var next_key:    u8[32] = [0; 32];
    var next_iv:     u8[12] = [0; 12];
    defer core::secure_zeroize_48(next_secret);
    defer core::secure_zeroize_32(next_key);
    defer core::secure_zeroize_slice(next_iv[..]);
    guard ks_update_traffic_secret(h_id, h_len, next_secret[..h_len_i64]) &&
        ks_derive_key_iv(h_id, next_secret[..h_len_i64], k_len, next_key[..k_len_i64], next_iv) else {
        return false;
    }

    slot.tx_traffic_secret = next_secret;
    slot.tx_key = next_key;
    slot.tx_iv = next_iv;
    prepare_cipher_aes_key(slot.cipher_suite, slot.tx_key[..k_len_i64], slot.tx_aes_key);
    slot.tx_seq = 0;
    return true;
}

fn store_slot_nst_global(slot: const tls::CipherSlot&, nst: const tls::NewSessionTicketMsg&) {
    guard slot.enable_session_tickets && slot.server_name.len > 0 && nst.ticket_lifetime > 0 else { return; }
    var ks_res = KeySchedule {
        hash_id:           slot.hash_id,
        hash_len:          slot.hash_len,
        stage:             KS_STAGE_RESUMPTION,
        resumption_secret: slot.resumption_secret,
        ..
    };
    defer ks_zeroize(ks_res);
    let h_len = slot.hash_len as i64;
    var psk_full: u8[48] = [0; 48];
    defer core::secure_zeroize_48(psk_full);
    if (h_len == 32 || h_len == 48) &&
        ks_derive_resumption_psk(ks_res, nst.ticket_nonce[..], psk_full[..h_len]) {
        tls::store_session_ticket(
            slot.server_name[..],
            nst.ticket[..],
            psk_full[..h_len],
            nst.ticket_age_add,
            nst.ticket_lifetime,
            slot.cipher_suite,
            0,
            slot.port,
            slot.tenant_hash,
            slot.alpn_hash,
            slot.policy_hash,
        );
    }
}

inline fn apply_unsealed_slot_handshake_control(
    slot:     tls::CipherSlot&,
    hs_bytes: const u8[:],
) -> tls::SliceUnsealStatus {
    guard hs_bytes.len >= 4 else { return tls::SliceUnsealStatus.Error; }
    var rem = hs_bytes;
    while rem.len > 0 {
        guard rem.len >= 4 else { return tls::SliceUnsealStatus.Error; }
        let msg_type, msg_len, ok_m = tls::parse_handshake_header(rem);
        guard ok_m else { return tls::SliceUnsealStatus.Error; }
        let full_len = core::add_sat_i64(4, msg_len);
        guard rem.len >= full_len else { return tls::SliceUnsealStatus.Error; }
        let msg_body = rem[4..full_len];
        if msg_type == rfc::TLS_HS_KEY_UPDATE {
            // RFC 8446 Section 5.1: Record Layer - KeyUpdate MUST end on a record boundary.
            guard rem.len == full_len else { return tls::SliceUnsealStatus.Error; }
            let needs_resp, ok_ku = track_received_key_update(
                slot.key_update_tracker, tls::HsState.Connected, msg_body,
            );
            guard ok_ku && ratchet_slot_rx_traffic_keys(slot) else { return tls::SliceUnsealStatus.Error; }
            if needs_resp {
                slot.key_update_tracker.pending_response = true;
            }
        } else if msg_type == rfc::TLS_HS_NEW_SESSION_TICKET {
            guard !slot.is_server else { return tls::SliceUnsealStatus.Error; }
            var nst = tls::NewSessionTicketMsg { .. };
            guard tls::parse_new_session_ticket(msg_body, nst) &&
                tls::cache_session_ticket(slot.ticket_cache, nst) else {
                return tls::SliceUnsealStatus.Error;
            }
            store_slot_nst_global(slot, nst);
        } else {
            return tls::SliceUnsealStatus.Error;
        }
        rem = rem[full_len..];
    }
    return tls::SliceUnsealStatus.ControlHandled;
}

fn unseal_single_slot_record<B>(
    slot:      tls::CipherSlot&,
    rec_hdr:   const u8[:],
    rec_body:  const u8[:],
    scratch:   u8[:],
    out_plain: B&,
) -> tls::SliceUnsealStatus {
    guard !tls::aead_exceeds_hard_limit(slot.cipher_suite, slot.rx_seq) else {
        return tls::SliceUnsealStatus.Error;
    }
    let klen = slot.key_len as i64;
    let dec_len, inner_type, _, ok_dec = record_decrypt_prepared_into(
        slot.cipher_suite,
        slot.rx_key[..klen],
        slot.rx_aes_key,
        slot.rx_iv,
        slot.rx_seq,
        rec_hdr,
        rec_body,
        scratch[..rec_body.len],
    );
    guard ok_dec else { return tls::SliceUnsealStatus.Error; }
    tls::increment_record_seq_num(slot.rx_seq);

    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        guard out_plain.try_append(scratch[..dec_len]) else { return tls::SliceUnsealStatus.Error; }
        if dec_len > 0 {
            slot.empty_app_records = 0;
            slot.warning_alerts = 0;
            on_key_update_app_data(slot.key_update_tracker);
            return tls::SliceUnsealStatus.Ok;
        }
        let empty_cnt = core::add_sat_u64(slot.empty_app_records, 1);
        guard empty_cnt <= 32 else { return tls::SliceUnsealStatus.Error; }
        slot.empty_app_records = empty_cnt as u8;
        return tls::SliceUnsealStatus.ControlHandled;
    }
    if inner_type == rfc::TLS_CONTENT_ALERT {
        let alert_level, alert_code, _, ok_a = tls::parse_alert_message(scratch[..dec_len]);
        if ok_a && alert_code == tls::Alert.CloseNotify {
            slot.peer_closed = true;
            return tls::SliceUnsealStatus.Closed;
        }
        if ok_a && alert_level == 1 && alert_code == tls::Alert.UserCanceled {
            let warn_cnt = core::add_sat_u64(slot.warning_alerts, 1);
            guard warn_cnt <= 4 else { return tls::SliceUnsealStatus.Error; }
            slot.warning_alerts = warn_cnt as u8;
            return tls::SliceUnsealStatus.ControlHandled;
        }
        return tls::SliceUnsealStatus.Error;
    }
    if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
        let hs_st = apply_unsealed_slot_handshake_control(slot, scratch[..dec_len]);
        if hs_st == tls::SliceUnsealStatus.Closed {
            slot.peer_closed = true;
        }
        return hs_st;
    }
    return tls::SliceUnsealStatus.Error;
}

inline fn finish_direct_control_record<B>(
    slot:       tls::CipherSlot&,
    inner_type: u8,
    start:      i64,
    dec_len:    i64,
    cap_end:    i64,
    out_plain:  B&,
) -> tls::SliceUnsealStatus {
    let ctrl_end = core::add_sat_i64(start, dec_len);
    var st = tls::SliceUnsealStatus.Error;
    if inner_type == rfc::TLS_CONTENT_ALERT {
        let alert_level, alert_code, _, ok_a = tls::parse_alert_message(out_plain[start..ctrl_end]);
        if ok_a && alert_code == tls::Alert.CloseNotify {
            slot.peer_closed = true;
            st = tls::SliceUnsealStatus.Closed;
        } else if ok_a && alert_level == 1 && alert_code == tls::Alert.UserCanceled {
            let warn_cnt = core::add_sat_u64(slot.warning_alerts, 1);
            if warn_cnt <= 4 {
                slot.warning_alerts = warn_cnt as u8;
                st = tls::SliceUnsealStatus.ControlHandled;
            }
        }
    } else if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
        st = apply_unsealed_slot_handshake_control(slot, out_plain[start..ctrl_end]);
        if st == tls::SliceUnsealStatus.Closed {
            slot.peer_closed = true;
        }
    }
    core::secure_zeroize_slice(out_plain[start..cap_end]);
    out_plain.resize(start);
    return st;
}

inline fn unseal_single_record_direct<B>(
    slot:      tls::CipherSlot&,
    rec_hdr:   const u8[:],
    rec_body:  const u8[:],
    out_plain: B&,
) -> tls::SliceUnsealStatus {
    guard !tls::aead_exceeds_hard_limit(slot.cipher_suite, slot.rx_seq) else {
        return tls::SliceUnsealStatus.Error;
    }
    let avail = core::sub_sat_i64(out_plain.cap, out_plain.len);
    guard avail >= rec_body.len else { return tls::SliceUnsealStatus.Error; }
    let start = out_plain.len;
    let cap_end = core::add_sat_i64(start, rec_body.len);
    out_plain.resize(cap_end, 0);
    let klen = slot.key_len as i64;
    let dec_len, inner_type, _, ok_dec = record_decrypt_prepared_into(
        slot.cipher_suite,
        slot.rx_key[..klen],
        slot.rx_aes_key,
        slot.rx_iv,
        slot.rx_seq,
        rec_hdr,
        rec_body,
        out_plain[start..cap_end],
    );
    guard ok_dec && dec_len <= rec_body.len else {
        core::secure_zeroize_slice(out_plain[start..cap_end]);
        out_plain.resize(start);
        return tls::SliceUnsealStatus.Error;
    }
    tls::increment_record_seq_num(slot.rx_seq);
    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        let plain_end = core::add_sat_i64(start, dec_len);
        if cap_end > plain_end {
            core::secure_zeroize_slice(out_plain[plain_end..cap_end]);
        }
        out_plain.resize(plain_end);
        if dec_len > 0 {
            slot.empty_app_records = 0;
            slot.warning_alerts = 0;
            on_key_update_app_data(slot.key_update_tracker);
            return tls::SliceUnsealStatus.Ok;
        }
        let empty_cnt = core::add_sat_u64(slot.empty_app_records, 1);
        guard empty_cnt <= 32 else { return tls::SliceUnsealStatus.Error; }
        slot.empty_app_records = empty_cnt as u8;
        return tls::SliceUnsealStatus.ControlHandled;
    }
    return finish_direct_control_record(slot, inner_type, start, dec_len, cap_end, out_plain);
}

fn tls_unseal_records_direct<B>(
    slot:      tls::CipherSlot&,
    cipher_in: const u8[:],
    out_plain: B&,
) -> i64, tls::SliceUnsealStatus {
    let saved_len = out_plain.len;
    var rem = cipher_in;
    var consumed: i64 = 0;
    var final_status = tls::SliceUnsealStatus.ControlHandled;
    while rem.len > 0 {
        let total_rec, hdr_st = peek_ciphertext_record_len(rem);
        guard hdr_st == tls::SliceUnsealStatus.Ok else { break; }
        let rec_slice = rem[..total_rec];
        let st = unseal_single_record_direct(
            slot,
            rec_slice[..rfc::TLS_RECORD_HEADER_LEN],
            rec_slice[rfc::TLS_RECORD_HEADER_LEN..],
            out_plain,
        );
        if st == tls::SliceUnsealStatus.Error {
            if out_plain.len > saved_len {
                core::secure_zeroize_slice(out_plain[saved_len..out_plain.len]);
            }
            out_plain.resize(saved_len);
            slot.peer_closed = true;
            return consumed, tls::SliceUnsealStatus.Error;
        }
        consumed = core::add_sat_i64(consumed, total_rec);
        rem = rem[total_rec..];
        if st == tls::SliceUnsealStatus.Closed { return consumed, tls::SliceUnsealStatus.Closed; }
        if st == tls::SliceUnsealStatus.Ok { final_status = tls::SliceUnsealStatus.Ok; }
    }
    if consumed == 0 { return 0, tls::SliceUnsealStatus.NeedMore; }
    return consumed, final_status;
}

inline fn slot_needs_sans_io_key_update(slot: const tls::CipherSlot&) -> bool {
    if slot.key_update_tracker.pending_response {
        return true;
    }
    guard tls::aead_needs_key_update(slot.cipher_suite, slot.tx_seq) else { return false; }
    let h_len = slot.hash_len as i64;
    guard h_len == 32 || h_len == 48 else { return false; }
    return !is_all_zero_slice(slot.tx_traffic_secret[..h_len]);
}

inline fn seal_sans_io_key_update_if_needed<B>(
    slot:       tls::CipherSlot&,
    rec_buf:    u8[:],
    out_cipher: B&,
) -> bool {
    guard slot_needs_sans_io_key_update(slot) else { return true; }
    guard !tls::aead_exceeds_hard_limit(slot.cipher_suite, slot.tx_seq) else { return false; }
    let ku_msg: u8[5] = [rfc::TLS_HS_KEY_UPDATE, 0x00, 0x00, 0x01, rfc::KEY_UPDATE_NOT_REQUESTED];
    let klen = slot.key_len as i64;
    let sealed_len, _, ok_ku = record_seal_prepared_into(
        slot.cipher_suite,
        slot.tx_key[..klen],
        slot.tx_aes_key,
        slot.tx_iv,
        slot.tx_seq,
        rfc::TLS_CONTENT_HANDSHAKE,
        ku_msg[..],
        rec_buf,
    );
    guard ok_ku && sealed_len > 0 && out_cipher.try_append(rec_buf[..sealed_len]) else { return false; }
    tls::increment_record_seq_num(slot.tx_seq);
    guard ratchet_slot_tx_traffic_keys(slot) else { return false; }
    slot.key_update_tracker.pending_response = false;
    return true;
}

fn tls_seal_app_data_direct<B>(
    slot:       tls::CipherSlot&,
    plain_in:   const u8[:],
    out_cipher: B&,
) -> bool {
    guard !tls::aead_exceeds_hard_limit(slot.cipher_suite, slot.tx_seq) else { return false; }
    let needs_ku = slot_needs_sans_io_key_update(slot);
    let ku_wire_len: i64 = if needs_ku { 27 } else { 0 };
    let rec_cnt = if plain_in.len == 0 {
        0
    } else {
        core::add_sat_i64(plain_in.len, 16383) >> 14
    };
    let app_wire_len = core::add_sat_i64(plain_in.len, core::mul_sat_u64(rec_cnt as u64, 22) as i64);
    guard core::sub_sat_i64(out_cipher.cap, out_cipher.len) >= core::add_sat_i64(ku_wire_len, app_wire_len) else {
        return false;
    }

    let saved_len = out_cipher.len;
    let saved_seq = slot.tx_seq;
    var committed = false;
    defer if !committed {
        out_cipher.resize(saved_len);
        slot.tx_seq = saved_seq;
    };

    if needs_ku {
        var ku_buf: u8[64] = [0; 64];
        guard seal_sans_io_key_update_if_needed(slot, ku_buf[..], out_cipher) else { return false; }
    }

    let klen = slot.key_len as i64;
    var rem = plain_in;
    while rem.len > 0 {
        guard !tls::aead_exceeds_hard_limit(slot.cipher_suite, slot.tx_seq) else {
            return false;
        }
        let chunk_len = min(rem.len, rfc::TLS_MAX_RECORD_PLAINTEXT_LEN);
        let rec_len = core::add_sat_i64(chunk_len, 22);
        let start = out_cipher.len;
        let cap_end = core::add_sat_i64(start, rec_len);
        out_cipher.resize(cap_end, 0);
        let sealed_len, _, ok_seal = record_seal_prepared_into(
            slot.cipher_suite,
            slot.tx_key[..klen],
            slot.tx_aes_key,
            slot.tx_iv,
            slot.tx_seq,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            rem[..chunk_len],
            out_cipher[start..cap_end],
        );
        guard ok_seal && sealed_len > 0 && sealed_len <= rec_len else {
            return false;
        }
        out_cipher.resize(core::add_sat_i64(start, sealed_len));
        tls::increment_record_seq_num(slot.tx_seq);
        rem = rem[chunk_len..];
    }
    on_key_update_app_data(slot.key_update_tracker);
    committed = true;
    return true;
}

// Seals and sends an RFC 8446 Section 6.2 encrypted fatal alert on an active TLS 1.3 cipher slot.
fn send_encrypted_fatal_alert(fd: i64, slot_idx: u16, alert: tls::Alert) {
    let idx = slot_idx as i64;
    guard fd > 0 && idx >= 0 && idx < tls::g_tls_cipher_slots.len else { return; }
    let slot .= tls::g_tls_cipher_slots[idx];
    guard slot.in_use && !tls::aead_exceeds_hard_limit(slot.cipher_suite, slot.tx_seq) else { return; }
    let alert_data: u8[2] = [2, tls::alert_to_u8(alert)];
    var rec_buf: u8[64] = [0; 64];
    let klen = slot.key_len as i64;
    let sealed_len, _, ok_seal = record_seal_prepared_into(
        slot.cipher_suite,
        slot.tx_key[..klen],
        slot.tx_aes_key,
        slot.tx_iv,
        slot.tx_seq,
        rfc::TLS_CONTENT_ALERT,
        alert_data[..],
        rec_buf[..],
    );
    if ok_seal && sealed_len > 0 {
        tls::increment_record_seq_num(slot.tx_seq);
        let _ = net::tcp_send(fd, rec_buf[..sealed_len]);
    }
    slot.peer_closed = true;
}

// Seals and transmits a single TLS 1.3 record using active slot keys, enforcing the
// RFC 8446 Section 5.5 hard AEAD record limit without triggering automatic KeyUpdate.
recursive fn send_encrypted_record_raw(
    fd:         i64,
    slot_idx:   u16,
    inner_type: u8,
    payload:    const u8[:],
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len else { return false; }
    guard tls::g_tls_cipher_slots[idx].in_use else { return false; }
    guard payload.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    guard !tls::aead_exceeds_hard_limit(
        tls::g_tls_cipher_slots[idx].cipher_suite, tls::g_tls_cipher_slots[idx].tx_seq,
    ) else {
        return false;
    }

    var ct_buf: u8[..16640] = [];
    let needed = core::add_sat_i64(payload.len, 22);
    guard needed <= ct_buf.cap else { return false; }
    ct_buf.resize(needed, 0);
    let klen = tls::g_tls_cipher_slots[idx].key_len as i64;
    let sealed_len, alert, ok_seal = record_seal_prepared_into(
        tls::g_tls_cipher_slots[idx].cipher_suite,
        tls::g_tls_cipher_slots[idx].tx_key[..klen],
        tls::g_tls_cipher_slots[idx].tx_aes_key,
        tls::g_tls_cipher_slots[idx].tx_iv,
        tls::g_tls_cipher_slots[idx].tx_seq,
        inner_type,
        payload,
        ct_buf[..],
    );
    guard ok_seal && sealed_len > 0 else { return false; }
    tls::increment_record_seq_num(tls::g_tls_cipher_slots[idx].tx_seq);
    return tls_write_all(fd, ct_buf[..sealed_len]);
}

// Encrypts and transmits a single TLS 1.3 record over socket using slot keys.
// Automatically triggers an RFC 8446 Section 5.5 KeyUpdate before sealing application
// data when the TX sequence number reaches the AEAD key-update ceiling.
recursive fn send_encrypted_record(
    fd:         i64,
    slot_idx:   u16,
    inner_type: u8,
    payload:    const u8[:],
) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else {
        return false;
    }
    guard !tls::aead_exceeds_hard_limit(
        tls::g_tls_cipher_slots[idx].cipher_suite, tls::g_tls_cipher_slots[idx].tx_seq,
    ) else {
        return false;
    }
    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA &&
        fd > 0 &&
        (tls::g_tls_cipher_slots[idx].key_update_tracker.pending_response ||
         tls::aead_needs_key_update(tls::g_tls_cipher_slots[idx].cipher_suite, tls::g_tls_cipher_slots[idx].tx_seq)) {
            tls::g_tls_cipher_slots[idx].key_update_tracker.pending_response = false;
            guard tls::send_key_update(fd, slot_idx, rfc::KEY_UPDATE_NOT_REQUESTED) else { return false; }
        }
    return send_encrypted_record_raw(fd, slot_idx, inner_type, payload);
}

fn tls_apply_rx_key_update(slot_idx: u16, needs_resp: bool) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else {
        return false;
    }
    guard ratchet_slot_rx_traffic_keys(tls::g_tls_cipher_slots[idx]) else { return false; }
    if needs_resp {
        tls::g_tls_cipher_slots[idx].key_update_tracker.pending_response = true;
    }
    return true;
}

fn process_received_nst(idx: i64, msg_body: const u8[:]) -> bool {
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else { return false; }
    guard !tls::g_tls_cipher_slots[idx].is_server else { return false; }
    var nst = tls::NewSessionTicketMsg { .. };
    guard tls::parse_new_session_ticket(msg_body, nst) else { return false; }
    guard tls::cache_session_ticket(tls::g_tls_cipher_slots[idx].ticket_cache, nst) else { return false; }
    store_slot_nst_global(tls::g_tls_cipher_slots[idx], nst);
    return true;
}

fn dispatch_post_handshake_record(slot_idx: u16, hs_bytes: const u8[:]) -> tls::Alert {
    guard hs_bytes.len >= 4 else { return tls::Alert.DecodeError; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else {
        return tls::Alert.InternalError;
    }
    var off: i64 = 0;
    while off < hs_bytes.len {
        let rem = hs_bytes[off..];
        guard rem.len >= 4 else { return tls::Alert.DecodeError; }
        let msg_type, msg_len, ok_m = tls::parse_handshake_header(rem);
        guard ok_m else { return tls::Alert.DecodeError; }
        let full_msg_len = core::add_sat_i64(4, msg_len);
        guard rem.len >= full_msg_len else { return tls::Alert.DecodeError; }
        let msg_body = rem[4..full_msg_len];

        if msg_type == rfc::TLS_HS_NEW_SESSION_TICKET {
            guard process_received_nst(idx, msg_body) else {
                return classify_nst_failure_alert(msg_body);
            }
        } else if msg_type == rfc::TLS_HS_KEY_UPDATE {
            // RFC 8446 Section 5.1: Record Layer - KeyUpdate MUST end on a record boundary.
            guard core::add_sat_i64(off, full_msg_len) == hs_bytes.len else {
                return tls::Alert.UnexpectedMessage;
            }
            let needs_resp, ok_ku = track_received_key_update(
                tls::g_tls_cipher_slots[idx].key_update_tracker,
                tls::HsState.Connected,
                msg_body,
            );
            guard ok_ku else { return tls::Alert.UnexpectedMessage; }
            guard tls_apply_rx_key_update(slot_idx, needs_resp) else { return tls::Alert.InternalError; }
        } else {
            return tls::Alert.UnexpectedMessage;
        }
        off = core::add_sat_i64(off, full_msg_len);
    }
    return tls::Alert.CloseNotify;
}

// Reads and decrypts a single application-layer TLS 1.3 ciphertext record from `fd`.
// Returns: >0 (decrypted payload length in `plain_dec`), -2 (timeout), -1 (error or unclean TCP EOF).
fn tls_read_and_unseal_app_record(
    fd:             i64,
    slot_idx:       u16,
    idx:            i64,
    timeout_ms:     u32,
    plain_dec:      u8[:],
    out_inner_type: u8&,
) -> i64 {
    var hdr_buf: u8[5] = [0; 5];
    let hdr_st = tls_read_exact_status(fd, hdr_buf[..], timeout_ms);
    if hdr_st == -2 { return -2; }
    // RFC 8446 Section 6.1: Closure Alerts - TCP EOF before receiving encrypted close_notify is an unclean EOF.
    guard hdr_st == 1 else { return -1; }

    let ct, _, payload_len_u16, alert, ok_p = tls::parse_record_header(hdr_buf[..]);
    guard ok_p else {
        send_encrypted_fatal_alert(fd, slot_idx, alert);
        return -1;
    }
    let payload_len = payload_len_u16 as i64;
    guard payload_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        send_encrypted_fatal_alert(fd, slot_idx, tls::Alert.RecordOverflow);
        return -1;
    }

    var ct_payload: u8[16640] = [0; 16640];
    guard tls_read_exact(fd, ct_payload[..payload_len], timeout_ms) else { return -1; }
    guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else {
        send_encrypted_fatal_alert(fd, slot_idx, tls::Alert.UnexpectedMessage);
        return -1;
    }

    let klen = tls::g_tls_cipher_slots[idx].key_len as i64;
    let dec_len, inner_type, alert_dec, ok_dec = record_decrypt_prepared_into(
        tls::g_tls_cipher_slots[idx].cipher_suite,
        tls::g_tls_cipher_slots[idx].rx_key[..klen],
        tls::g_tls_cipher_slots[idx].rx_aes_key,
        tls::g_tls_cipher_slots[idx].rx_iv,
        tls::g_tls_cipher_slots[idx].rx_seq,
        hdr_buf[..],
        ct_payload[..payload_len],
        plain_dec[..payload_len],
    );
    guard ok_dec else {
        tls::g_tls_cipher_slots[idx].peer_closed = true;
        send_encrypted_fatal_alert(fd, slot_idx, alert_dec);
        return -1;
    }
    tls::increment_record_seq_num(tls::g_tls_cipher_slots[idx].rx_seq);
    out_inner_type = inner_type;
    return dec_len;
}

// Handles a decrypted TLS 1.3 Alert record. Returns 1 to continue reading, 0 on CloseNotify, -1 on error.
fn tls_handle_rx_alert_record(fd: i64, slot_idx: u16, idx: i64, alert_bytes: const u8[:]) -> i32 {
    let alert_level, alert_code, _, ok_a = tls::parse_alert_message(alert_bytes);
    if ok_a && alert_code == tls::Alert.CloseNotify {
        tls::g_tls_cipher_slots[idx].peer_closed = true;
        return 0;
    }
    if ok_a && alert_level == 1 && alert_code == tls::Alert.UserCanceled {
        let warn_cnt = core::add_sat_u64(tls::g_tls_cipher_slots[idx].warning_alerts, 1);
        guard warn_cnt <= 4 else {
            tls::g_tls_cipher_slots[idx].peer_closed = true;
            send_encrypted_fatal_alert(fd, slot_idx, tls::Alert.UnexpectedMessage);
            return -1;
        }
        tls::g_tls_cipher_slots[idx].warning_alerts = warn_cnt as u8;
        return 1;
    }
    tls::g_tls_cipher_slots[idx].peer_closed = true;
    if !ok_a {
        send_encrypted_fatal_alert(fd, slot_idx, alert_code);
    } else if alert_level != 2 {
        send_encrypted_fatal_alert(fd, slot_idx, tls::Alert.DecodeError);
    }
    return -1;
}

// Copies decrypted application data into `dst` and stages overflow into the slot buffer.
fn tls_deliver_rx_app_data(idx: i64, plain: const u8[:], dst: u8[:]) -> i32 {
    tls::g_tls_cipher_slots[idx].empty_app_records = 0;
    tls::g_tls_cipher_slots[idx].warning_alerts = 0;
    let to_user = min(plain.len, dst.len);
    core::ct_copy_bytes(dst[..to_user], plain[..to_user]);
    if plain.len > dst.len {
        let _ = tls::g_tls_cipher_slots[idx].rx_plain_buf.try_set(plain[dst.len..]);
        tls::g_tls_cipher_slots[idx].rx_plain_pos = 0;
    }
    on_key_update_app_data(tls::g_tls_cipher_slots[idx].key_update_tracker);
    return to_user as i32;
}

const MAX_POST_HANDSHAKE_CTRL_RECORDS_PER_READ: u32 = 64;

fn tls_recv_app_record(fd: i64, slot_idx: u16, idx: i64, dst: u8[:], timeout_ms: u32) -> i32 {
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else { return -1; }
    var plain_dec: u8[16640] = [0; 16640];
    defer core::secure_zeroize_slice(plain_dec[..]);
    var ctrl_records: u32 = 0;

    while ctrl_records < MAX_POST_HANDSHAKE_CTRL_RECORDS_PER_READ {
        guard !tls::aead_exceeds_hard_limit(
            tls::g_tls_cipher_slots[idx].cipher_suite, tls::g_tls_cipher_slots[idx].rx_seq,
        ) else {
            return -1;
        }
        var inner_type: u8 = 0;
        let dec_len = tls_read_and_unseal_app_record(fd, slot_idx, idx, timeout_ms, plain_dec[..], inner_type);
        if dec_len <= 0 && inner_type == 0 {
            return dec_len as i32;
        }
        if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
            if dec_len > 0 {
                return tls_deliver_rx_app_data(idx, plain_dec[..dec_len], dst);
            }
            let empty_cnt = core::add_sat_u64(tls::g_tls_cipher_slots[idx].empty_app_records, 1);
            guard empty_cnt <= 32 else {
                tls::g_tls_cipher_slots[idx].peer_closed = true;
                send_encrypted_fatal_alert(fd, slot_idx, tls::Alert.UnexpectedMessage);
                return -1;
            }
            tls::g_tls_cipher_slots[idx].empty_app_records = empty_cnt as u8;
            ctrl_records = core::add_sat_u32(ctrl_records, 1);
            continue;
        }
        if inner_type == rfc::TLS_CONTENT_ALERT {
            let alert_rc = tls_handle_rx_alert_record(fd, slot_idx, idx, plain_dec[..dec_len]);
            guard alert_rc == 1 else { return alert_rc; }
            ctrl_records = core::add_sat_u32(ctrl_records, 1);
            continue;
        }
        if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
            let ph_alert = dispatch_post_handshake_record(slot_idx, plain_dec[..dec_len]);
            guard ph_alert == tls::Alert.CloseNotify else {
                tls::g_tls_cipher_slots[idx].peer_closed = true;
                send_encrypted_fatal_alert(fd, slot_idx, ph_alert);
                return -1;
            }
            ctrl_records = core::add_sat_u32(ctrl_records, 1);
            continue;
        }
        tls::g_tls_cipher_slots[idx].peer_closed = true;
        send_encrypted_fatal_alert(fd, slot_idx, tls::Alert.UnexpectedMessage);
        return -1;
    }
    tls::g_tls_cipher_slots[idx].peer_closed = true;
    send_encrypted_fatal_alert(fd, slot_idx, tls::Alert.UnexpectedMessage);
    return -1;
}
