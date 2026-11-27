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
import net.tcp;
import net.transport;
import net.driver.smartnic;
import .handshake_wire_internal;
import .session_slot_internal;
import .session_wire_internal;

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

// Releases a cipher slot and securely wipes all cryptographic key material.
fn free_cipher_slot(slot_idx: u16) {
    tls_internal::native_tls_state_lock(tls_internal::TLS_LOCK_CIPHER_SLOTS);
    defer tls_internal::native_tls_state_unlock(tls_internal::TLS_LOCK_CIPHER_SLOTS);
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return; }
    tls_internal::wipe_and_reset_tls_cipher_slot(g_tls_cipher_slots[idx]);
}

fn try_enable_ktls(slot_idx: u16, fd: i64) -> net_internal::SmartNicSession, bool {
    guard fd > 0 && !net::is_virtual_pipe_fd(fd) && !net::is_tunnel_fd(fd) else {
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

    return tls_internal::tls_unseal_records_direct(slot, cipher_in, out_plain);
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

    return tls_internal::tls_seal_app_data_direct(slot, plain_in, out_cipher);
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
    guard parse_x509_certificate(cert_der, leaf_cert) && leaf_cert.has_san else { return false; }
    var names_seq = core::cursor_from(cert_der[..0]);
    guard tls_internal::x509_open_san_sequence(span_slice(cert_der, leaf_cert.san_raw), names_seq) else {
        return false;
    }
    g_tls_cipher_slots[idx].san_hosts.clear();
    var seen_any = false;
    while names_seq.cursor_len() > 0 {
        let san, ok = tls_internal::x509_next_san_entry(names_seq);
        guard ok else {
            g_tls_cipher_slots[idx].san_hosts.clear();
            return false;
        }
        seen_any = true;
        guard san.san_type == SanType.Dns else { continue; }
        var h_buf: u8[..128] = [];
        if h_buf.try_set(san.val) {
            let _ = g_tls_cipher_slots[idx].san_hosts.try_push(h_buf);
        }
    }
    return seen_any;
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

// Sends application data chunks over TLS 1.3 record layer (RFC 8446 §5.2).
// Uses single-MSS records (`TLS_SINGLE_MSS_PLAINTEXT_LEN` = 1378 B) during the first 64 KB
// (`TLS_DYNAMIC_RESIZE_THRESHOLD_BYTES`) to eliminate multi-packet TCP head-of-line blocking during Slow Start.
recursive fn transport_send(fd: i64, slot_idx: u16, data: const u8[:]) -> i32 {
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
        let ok_s = tls_internal::send_encrypted_record(
            fd,
            slot_idx,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            data[offset..next_offset],
        );
        guard ok_s else { return -1; }
        g_tls_cipher_slots[idx].bytes_sent = next_bytes;
        offset = next_offset;
    }
    tls_internal::on_key_update_app_data(g_tls_cipher_slots[idx].key_update_tracker);
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

    var age_bytes: u8[4] = [0; 4];
    guard core::csprng_fill(age_bytes[..]) else { return false; }
    let ticket_age_add = core::read_be_u32(age_bytes[..], 0);

    var nst_body: u8[..512] = [];
    guard tls_internal::encode_new_session_ticket(
        nst_body,
        ticket_lifetime,
        ticket_age_add,
        ticket_nonce,
        ticket,
        max_early_data_size,
    ) else { return false; }
    var hs_msg: u8[..516] = [];
    hs_msg.push(rfc::TLS_HS_NEW_SESSION_TICKET);
    hs_msg.append_u24_be(nst_body.len as u32);
    hs_msg.append(nst_body[..]);
    guard tls_internal::send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]) else {
        return false;
    }

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
            tls_internal::store_server_session_ticket(
                sni,
                ticket,
                psk_full[..h_len],
                ticket_age_add,
                ticket_lifetime,
                g_tls_cipher_slots[idx].cipher_suite,
                g_tls_cipher_slots[idx].client_authenticated,
                0,
                g_tls_cipher_slots[idx].ca_policy_hash,
            );
        }
    }
    return true;
}

// Sends a post-handshake KeyUpdate message and rotates transmitter traffic keys (RFC 8446 §4.6.3).
recursive fn send_key_update(fd: i64, slot_idx: u16, request_update: u8) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return false; }
    guard g_tls_cipher_slots[idx].in_use else { return false; }

    var ku_body: u8[..4] = [];
    guard tls_internal::encode_key_update(ku_body, request_update) else { return false; }
    var hs_msg: u8[..8] = [];
    hs_msg.push(rfc::TLS_HS_KEY_UPDATE);
    hs_msg.push(0x00); hs_msg.push(0x00); hs_msg.push(0x01);
    hs_msg.append(ku_body[..]);

    let h_id = g_tls_cipher_slots[idx].hash_id;
    let h_len = g_tls_cipher_slots[idx].hash_len;
    let k_len = g_tls_cipher_slots[idx].key_len;
    let h_len_i64 = h_len as i64;
    let k_len_i64 = k_len as i64;
    guard (h_len_i64 == 32 || h_len_i64 == 48) && (k_len_i64 == 16 || k_len_i64 == 32) else { return false; }

    var next_secret: u8[48] = g_tls_cipher_slots[idx].tx_traffic_secret;
    var next_key:    u8[32] = [0; 32];
    var next_iv:     u8[12] = [0; 12];
    defer core::secure_zeroize_48(next_secret);
    defer core::secure_zeroize_32(next_key);
    defer core::secure_zeroize_slice(next_iv[..]);
    guard tls_internal::ks_update_traffic_secret(h_id, h_len, next_secret[..h_len_i64]) &&
        tls_internal::ks_derive_key_iv(h_id, next_secret[..h_len_i64], k_len, next_key[..k_len_i64], next_iv) else {
        return false;
    }

    let ok_s = tls_internal::send_encrypted_record_raw(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]);
    guard ok_s else { return false; }

    g_tls_cipher_slots[idx].tx_traffic_secret = next_secret;
    g_tls_cipher_slots[idx].tx_key = next_key;
    g_tls_cipher_slots[idx].tx_iv = next_iv;
    tls_internal::prepare_cipher_aes_key(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].tx_key[..k_len_i64],
        g_tls_cipher_slots[idx].tx_aes_key,
    );
    g_tls_cipher_slots[idx].tx_seq = 0;
    return true;
}

// Receives decrypted application data bytes from TLS 1.3 socket, handling residual buffers,
// post-handshake NewSessionTicket, KeyUpdate, and CloseNotify alerts (RFC 8446 §5.2, §4.6).
recursive fn transport_recv_slice(fd: i64, slot_idx: u16, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < g_tls_cipher_slots.len else { return -1; }
    guard g_tls_cipher_slots[idx].in_use else { return -1; }
    if g_tls_cipher_slots[idx].peer_closed { return 0; }

    let drained = tls_internal::tls_drain_rx_buf(idx, dst);
    if drained > 0 { return drained; }

    for _ in 16 {
        let res = tls_internal::tls_recv_app_record(fd, slot_idx, idx, dst, timeout_ms);
        if res != 0 { return res; }
        if g_tls_cipher_slots[idx].peer_closed { return 0; }
    }
    return -1;
}

// Sends a CloseNotify alert, wipes secrets, and closes socket (RFC 8446 §6.1).
recursive fn transport_close(fd: i64, slot_idx: u16) {
    if fd > 0 {
        let idx = slot_idx as i64;
        let valid_slot = idx >= 0 && idx < g_tls_cipher_slots.len &&
            g_tls_cipher_slots[idx].in_use && !g_tls_cipher_slots[idx].peer_closed;
        if valid_slot {
            let alert_data: u8[2] = [1, 0];
            if g_tls_cipher_slots[idx].ktls_tx_active {
                let _ = net_internal::smartnic_send_record(fd, alert_data[..], rfc::TLS_CONTENT_ALERT);
            } else {
                tls_internal::send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_ALERT, alert_data[..]);
            }
        }
        net::fd_close(fd);
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
