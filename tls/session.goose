// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tls/session.goose
// Live TLS 1.3 Transport Session, Handshake Orchestrator, and Cipher Slot Storage.
// Conforms to RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN), and RFC 5280 / RFC 6125 (X.509 PKI).
namespace wing;

import std;
import core from "..";
import .record;
import .key_schedule;
import .handshake;
import .x509;
import net.tcp;

// ---- Stateful Entropy Generator (RFC 8446 Appendix C.1, Invariant 16) ------

var g_tls_entropy_pool:    u8[32] = [0; 32];
var g_tls_entropy_counter: u64    = 0;

// Mixes hardware monotonic timer, entropy pool, and sequence counter using SHA-256 (Invariant 16).
fn tls_random_bytes_32() -> u8[32] {
    g_tls_entropy_counter++;
    let now_ns = core::monotonic_now().nanos;
    var mix: u8[48] = [0; 48];
    for i in 32 { mix[i] = g_tls_entropy_pool[i]; }
    for i in 8 {
        mix[32 + i] = ((g_tls_entropy_counter >> (i * 8)) & 0xFF) as u8;
        mix[40 + i] = ((now_ns >> (i * 8)) & 0xFF) as u8;
    }
    let h = core::sha256(mix[..]);
    for i in 32 { g_tls_entropy_pool[i] = h[i]; }
    return h;
}

// ---- Global Static Cipher Slot Table (Zero-Allocation POD) ----------------

const MAX_TLS_CIPHER_SLOTS: i64 = 64;

struct TlsCipherSlot {
    in_use:             bool               = false,
    is_server:          bool               = false,
    cipher_suite:       u16                = 0,
    hash_id:            u8                 = 1,
    hash_len:           u8                 = 32,
    key_len:            u16                = 16,
    rx_seq:             u64                = 0,
    tx_seq:             u64                = 0,
    rx_key:             u8[32]             = [0; 32],
    tx_key:             u8[32]             = [0; 32],
    rx_iv:              u8[12]             = [0; 12],
    tx_iv:              u8[12]             = [0; 12],
    rx_traffic_secret:  u8[48]             = [0; 48],
    tx_traffic_secret:  u8[48]             = [0; 48],
    exporter_secret:    u8[48]             = [0; 48],
    resumption_secret:  u8[48]             = [0; 48],
    peer_closed:        bool               = false,
    rx_plain_buf:       u8[..16384]        = [],
    rx_plain_pos:       i64                = 0,
    key_update_tracker: KeyUpdateTracker   = KeyUpdateTracker { .. },
    ticket_cache:       SessionTicketCache = SessionTicketCache { .. },
}

var g_tls_cipher_slots: TlsCipherSlot[64] = [TlsCipherSlot { .. }; 64];

// Allocates an unused slot from the global static cipher slot pool.
fn alloc_tls_cipher_slot() -> u16, bool {
    for i in MAX_TLS_CIPHER_SLOTS {
        if !g_tls_cipher_slots[i].in_use {
            g_tls_cipher_slots[i].in_use = true;
            g_tls_cipher_slots[i].is_server = false;
            g_tls_cipher_slots[i].cipher_suite = 0;
            g_tls_cipher_slots[i].hash_id = 1;
            g_tls_cipher_slots[i].hash_len = 32;
            g_tls_cipher_slots[i].key_len = 16;
            g_tls_cipher_slots[i].rx_seq = 0;
            g_tls_cipher_slots[i].tx_seq = 0;
            g_tls_cipher_slots[i].peer_closed = false;
            g_tls_cipher_slots[i].rx_plain_buf.clear();
            g_tls_cipher_slots[i].rx_plain_pos = 0;
            g_tls_cipher_slots[i].key_update_tracker = KeyUpdateTracker { .. };
            g_tls_cipher_slots[i].ticket_cache = SessionTicketCache { .. };
            return i as u16, true;
        }
    }
    return 0, false;
}

// Releases a cipher slot and securely wipes all cryptographic key material.
fn free_tls_cipher_slot(slot_idx: u16) {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return; }
    core::secure_zeroize_32(g_tls_cipher_slots[idx].rx_key);
    core::secure_zeroize_32(g_tls_cipher_slots[idx].tx_key);
    for i in 12 {
        g_tls_cipher_slots[idx].rx_iv[i] = 0;
        g_tls_cipher_slots[idx].tx_iv[i] = 0;
    }
    core::secure_zeroize_48(g_tls_cipher_slots[idx].rx_traffic_secret);
    core::secure_zeroize_48(g_tls_cipher_slots[idx].tx_traffic_secret);
    core::secure_zeroize_48(g_tls_cipher_slots[idx].exporter_secret);
    core::secure_zeroize_48(g_tls_cipher_slots[idx].resumption_secret);
    g_tls_cipher_slots[idx].rx_plain_buf.clear();
    g_tls_cipher_slots[idx].rx_plain_pos = 0;
    g_tls_cipher_slots[idx].in_use = false;
}

// Reads exactly dst.len bytes from socket, returning false on error or clean EOF before full read.
fn tls_read_exact(fd: i64, dst: u8[:], timeout_ms: u32) -> bool {
    guard fd > 0 && dst.len > 0 else { return false; }
    var total_read: i64 = 0;
    while total_read < dst.len {
        let recvd = tcp_recv_slice(fd, dst[total_read..], timeout_ms);
        guard recvd > 0 else { return false; }
        total_read += recvd;
    }
    return true;
}

// Writes entire data buffer to socket, returning false on error or partial write failure.
fn tls_write_all(fd: i64, data: const u8[:]) -> bool {
    guard fd > 0 && data.len > 0 else { return false; }
    var total_sent: i64 = 0;
    while total_sent < data.len {
        let sent = tcp_send(fd, data[total_sent..]);
        guard sent > 0 else { return false; }
        total_sent += sent;
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
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return false; }
    guard g_tls_cipher_slots[idx].in_use else { return false; }

    var ct_buf: u8[..16640] = [];
    while ct_buf.len < payload.len + 21 {
        ct_buf.push(0);
    }
    let klen = g_tls_cipher_slots[idx].key_len as i64;
    let sealed_len, alert, ok_seal = tls_record_seal_into(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].tx_key[..klen],
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

// Sends application data chunks over TLS 1.3 record layer (RFC 8446 §5.2).
fn tls_transport_send(fd: i64, slot_idx: u16, data: const u8[:]) -> i32 {
    guard fd > 0 && data.len > 0 else { return 0; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return -1; }
    guard g_tls_cipher_slots[idx].in_use && !g_tls_cipher_slots[idx].peer_closed else { return -1; }

    var offset: i64 = 0;
    while offset < data.len {
        let rem = data.len - offset;
        let chunk_len = if rem > rfc::TLS_MAX_RECORD_PLAINTEXT_LEN {
            rfc::TLS_MAX_RECORD_PLAINTEXT_LEN
        } else {
            rem
        };
        let ok_s = tls_send_encrypted_record(
            fd,
            slot_idx,
            rfc::TLS_CONTENT_APPLICATION_DATA,
            data[offset..offset + chunk_len],
        );
        guard ok_s else { return -1; }
        offset += chunk_len;
    }
    on_key_update_app_data(g_tls_cipher_slots[idx].key_update_tracker);
    return data.len as i32;
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
    hs_msg.push(((nst_body.len >> 16) & 0xFF) as u8);
    hs_msg.push(((nst_body.len >> 8) & 0xFF) as u8);
    hs_msg.push((nst_body.len & 0xFF) as u8);
    hs_msg.append(nst_body[..]);
    return tls_send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_HANDSHAKE, hs_msg[..]);
}

// Sends a post-handshake KeyUpdate message and rotates transmitter traffic keys (RFC 8446 §4.6.3).
fn tls_send_key_update(fd: i64, slot_idx: u16, request_update: u8) -> bool {
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return false; }
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
    internal::ks_update_traffic_secret(
        h_id,
        h_len,
        g_tls_cipher_slots[idx].tx_traffic_secret[..h_len as i64],
    );
    internal::ks_derive_key_iv(
        h_id,
        g_tls_cipher_slots[idx].tx_traffic_secret[..h_len as i64],
        k_len,
        g_tls_cipher_slots[idx].tx_key[..k_len as i64],
        g_tls_cipher_slots[idx].tx_iv,
    );
    g_tls_cipher_slots[idx].tx_seq = 0;
    return true;
}

fn tls_apply_rx_key_update(slot_idx: u16, needs_resp: bool, fd: i64) {
    let idx = slot_idx as i64;
    let h_id = g_tls_cipher_slots[idx].hash_id;
    let h_len = g_tls_cipher_slots[idx].hash_len;
    let k_len = g_tls_cipher_slots[idx].key_len;
    let h_len_i64 = h_len as i64;
    let k_len_i64 = k_len as i64;

    internal::ks_update_traffic_secret(h_id, h_len, g_tls_cipher_slots[idx].rx_traffic_secret[..h_len_i64]);
    internal::ks_derive_key_iv(
        h_id,
        g_tls_cipher_slots[idx].rx_traffic_secret[..h_len_i64],
        k_len,
        g_tls_cipher_slots[idx].rx_key[..k_len_i64],
        g_tls_cipher_slots[idx].rx_iv,
    );
    g_tls_cipher_slots[idx].rx_seq = 0;
    if needs_resp {
        tls_send_key_update(fd, slot_idx, rfc::KEY_UPDATE_NOT_REQUESTED);
    }
}

fn tls_handle_post_handshake_record(fd: i64, slot_idx: u16, hs_bytes: const u8[:]) {
    let idx = slot_idx as i64;
    var c_hs = cursor_from(hs_bytes);
    while cursor_len(c_hs) >= 4 {
        let msg_type, msg_len, ok_m = parse_handshake_header(c_hs.buf);
        guard ok_m else { return; }
        let full_msg_len = 4 + (msg_len as i64);
        guard c_hs.buf.len >= full_msg_len else { return; }
        let msg_body = c_hs.buf[4..full_msg_len];

        if msg_type == rfc::TLS_HS_NEW_SESSION_TICKET {
            var nst = NewSessionTicketMsg { .. };
            if parse_new_session_ticket(msg_body, nst) {
                cache_session_ticket(g_tls_cipher_slots[idx].ticket_cache, nst);
            }
        } else if msg_type == rfc::TLS_HS_KEY_UPDATE {
            let needs_resp, ok_ku = track_received_key_update(
                g_tls_cipher_slots[idx].key_update_tracker,
                HsState.Connected,
                msg_body,
            );
            if ok_ku {
                tls_apply_rx_key_update(slot_idx, needs_resp, fd);
            }
        }
        c_hs.buf = c_hs.buf[full_msg_len..];
    }
}

fn tls_drain_rx_buf(idx: i64, dst: u8[:]) -> i32 {
    let rem_buf = g_tls_cipher_slots[idx].rx_plain_buf.len - g_tls_cipher_slots[idx].rx_plain_pos;
    if rem_buf <= 0 { return 0; }
    let to_copy = if rem_buf > dst.len { dst.len } else { rem_buf };
    let start = g_tls_cipher_slots[idx].rx_plain_pos;
    for i in to_copy {
        dst[i] = g_tls_cipher_slots[idx].rx_plain_buf[start + i];
    }
    g_tls_cipher_slots[idx].rx_plain_pos += to_copy;
    if g_tls_cipher_slots[idx].rx_plain_pos >= g_tls_cipher_slots[idx].rx_plain_buf.len {
        g_tls_cipher_slots[idx].rx_plain_buf.clear();
        g_tls_cipher_slots[idx].rx_plain_pos = 0;
    }
    return to_copy as i32;
}

fn tls_recv_app_record(fd: i64, slot_idx: u16, idx: i64, dst: u8[:], timeout_ms: u32) -> i32 {
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

    if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
        return 0;
    }
    guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return -1; }

    var plain_dec: u8[..16640] = [];
    while plain_dec.len < payload_len { plain_dec.push(0); }
    let klen = g_tls_cipher_slots[idx].key_len as i64;
    let dec_len, inner_type, alert_dec, ok_dec = tls_record_decrypt_into(
        g_tls_cipher_slots[idx].cipher_suite,
        g_tls_cipher_slots[idx].rx_key[..klen],
        g_tls_cipher_slots[idx].rx_iv,
        g_tls_cipher_slots[idx].rx_seq,
        hdr_buf[..],
        ct_payload[..payload_len],
        plain_dec[..],
    );
    guard ok_dec else { return -1; }
    increment_record_seq_num(g_tls_cipher_slots[idx].rx_seq);

    if inner_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        let to_user = if dec_len > dst.len { dst.len } else { dec_len };
        for i in to_user { dst[i] = plain_dec[i]; }
        if dec_len > dst.len {
            g_tls_cipher_slots[idx].rx_plain_buf.clear();
            g_tls_cipher_slots[idx].rx_plain_buf.append(plain_dec[dst.len..dec_len]);
            g_tls_cipher_slots[idx].rx_plain_pos = 0;
        }
        on_key_update_app_data(g_tls_cipher_slots[idx].key_update_tracker);
        return to_user as i32;
    }

    if inner_type == rfc::TLS_CONTENT_ALERT {
        let _, alert_code, _, ok_a = parse_tls_alert_message(plain_dec[..dec_len]);
        if ok_a && alert_code == TlsAlert.CloseNotify {
            g_tls_cipher_slots[idx].peer_closed = true;
            return 0;
        }
        return -1;
    }

    if inner_type == rfc::TLS_CONTENT_HANDSHAKE {
        tls_handle_post_handshake_record(fd, slot_idx, plain_dec[..dec_len]);
        return 0;
    }
    return -1;
}

// Receives decrypted application data bytes from TLS 1.3 socket, handling residual buffers,
// post-handshake NewSessionTicket, KeyUpdate, and CloseNotify alerts (RFC 8446 §5.2, §4.6).
// crap:ignore
fn tls_transport_recv_slice(fd: i64, slot_idx: u16, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    let idx = slot_idx as i64;
    guard idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS else { return -1; }
    guard g_tls_cipher_slots[idx].in_use else { return -1; }
    if g_tls_cipher_slots[idx].peer_closed { return 0; }

    let drained = tls_drain_rx_buf(idx, dst);
    if drained > 0 { return drained; }

    while true {
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
        let valid_slot = idx >= 0 && idx < MAX_TLS_CIPHER_SLOTS &&
            g_tls_cipher_slots[idx].in_use && !g_tls_cipher_slots[idx].peer_closed;
        if valid_slot {
            let alert_data: u8[2] = [1, 0];
            tls_send_encrypted_record(fd, slot_idx, rfc::TLS_CONTENT_ALERT, alert_data[..]);
        }
        tcp_close(fd);
    }
    free_tls_cipher_slot(slot_idx);
}

// ---- Zero-Allocation Handshake Record Stream Reader ------------------------

struct HandshakeRecordReader {
    current_record_plain: u8[..16640] = [],
    current_offset:       i64         = 0,
    seq_num:              u64         = 0,
}

fn try_read_handshake_msg(
    r:            HandshakeRecordReader&,
    msg_type:     u8&,
    out_msg_body: u8[..8192]&,
) -> bool {
    let remaining_plain = r.current_record_plain.len - r.current_offset;
    guard remaining_plain >= 4 else { return false; }
    let slice = r.current_record_plain[r.current_offset..];
    let mt, m_len, ok_hdr = parse_handshake_header(slice);
    guard ok_hdr else { return false; }
    let total_len = 4 + (m_len as i64);
    guard remaining_plain >= total_len else { return false; }
    guard m_len <= out_msg_body.cap else { return false; }
    msg_type = mt;
    out_msg_body.clear();
    out_msg_body.append(slice[4..total_len]);
    r.current_offset += total_len;
    return true;
}

// Consumes the next handshake message from the reader, reading and decrypting
// subsequent TLS records from `fd` when the buffered record is exhausted.
//
// Example:
//   r.current_record_plain = [0x08, 0x00, 0x00, 0x02, 0x00, 0x00], r.current_offset = 0
//   returns: true, msg_type = 8, out_msg_body = [0x00, 0x00]
// crap:ignore
fn next_handshake_message(
    r:            HandshakeRecordReader&,
    fd:           i64,
    cipher_suite: u16,
    key:          const u8[:],
    iv:           const u8[12]&,
    msg_type:     u8&,
    out_msg_body: u8[..8192]&,
    timeout_ms:   u32,
) -> bool {
    while true {
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
            continue;
        }
        guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return false; }

        r.current_record_plain.clear();
        while r.current_record_plain.len < payload_len { r.current_record_plain.push(0); }
        let dec_len, inner_type, alert_dec, ok_dec = tls_record_decrypt_into(
            cipher_suite,
            key,
            iv,
            r.seq_num,
            hdr_buf[..],
            ct_payload[..payload_len],
            r.current_record_plain[..],
        );
        guard ok_dec && inner_type == rfc::TLS_CONTENT_HANDSHAKE else { return false; }
        increment_record_seq_num(r.seq_num);

        while r.current_record_plain.len > dec_len {
            r.current_record_plain.pop();
        }
        r.current_offset = 0;
    }
    return false;
}

// ---- Test Certificate Generator (RFC 5280 / RFC 8446) --------------------

// Builds a self-signed X.509 v3 Ed25519 certificate in canonical ASN.1 DER format.
// crap:ignore
fn build_test_ed25519_cert_der(
    seed:        const u8[32]&,
    common_name: const u8[:],
    dns_san:     const u8[:],
    ip_san:      const u8[:],
    out_der:     u8[..2048]&,
) -> bool {
    out_der.clear();
    let kp = core::ed25519_keypair(seed);

    var b_tbs = builder_init();

    // version [0] EXPLICIT INTEGER v3 (2)
    put_u8(b_tbs, 0xA0);
    put_u8(b_tbs, 3);
    put_u8(b_tbs, 0x02);
    put_u8(b_tbs, 1);
    put_u8(b_tbs, 2);

    // serialNumber (INTEGER: 1)
    put_u8(b_tbs, 0x02);
    put_u8(b_tbs, 1);
    put_u8(b_tbs, 1);

    // signature (AlgorithmIdentifier: OID_ED25519)
    put_u8(b_tbs, 0x30);
    put_u8(b_tbs, 5);
    put_u8(b_tbs, 0x06);
    put_u8(b_tbs, 3);
    put_bytes(b_tbs, "\x2B\x65\x70");

    // issuer (SEQUENCE OF SET OF SEQUENCE { OID_COMMON_NAME, UTF8String })
    var b_cn = builder_init();
    put_u8(b_cn, 0x30);
    put_u8(b_cn, (2 + 3 + 2 + common_name.len) as u8);
    put_u8(b_cn, 0x06);
    put_u8(b_cn, 3);
    put_bytes(b_cn, "\x55\x04\x03");
    put_u8(b_cn, 0x0C);
    put_u8(b_cn, common_name.len as u8);
    put_bytes(b_cn, common_name);

    var b_issuer = builder_init();
    put_u8(b_issuer, 0x30);
    put_u8(b_issuer, (2 + b_cn.buf.len) as u8);
    put_u8(b_issuer, 0x31);
    put_u8(b_issuer, b_cn.buf.len as u8);
    put_bytes(b_issuer, b_cn.buf[..]);
    put_bytes(b_tbs, b_issuer.buf[..]);

    // validity: 2024-01-01 to 2035-12-31
    put_u8(b_tbs, 0x30);
    put_u8(b_tbs, 30);
    put_u8(b_tbs, 0x17);
    put_u8(b_tbs, 13);
    put_bytes(b_tbs, "240101000000Z");
    put_u8(b_tbs, 0x17);
    put_u8(b_tbs, 13);
    put_bytes(b_tbs, "351231235959Z");

    // subject (same as issuer)
    put_bytes(b_tbs, b_issuer.buf[..]);

    // SPKI: SubjectPublicKeyInfo
    put_u8(b_tbs, 0x30);
    put_u8(b_tbs, 42);
    put_u8(b_tbs, 0x30);
    put_u8(b_tbs, 5);
    put_u8(b_tbs, 0x06);
    put_u8(b_tbs, 3);
    put_bytes(b_tbs, "\x2B\x65\x70");
    put_u8(b_tbs, 0x03);
    put_u8(b_tbs, 33);
    put_u8(b_tbs, 0x00);
    put_bytes(b_tbs, kp.public_key[..]);

    // extensions [3] EXPLICIT
    var b_ext_body = builder_init();

    // Extension 1: BasicConstraints (cA = true)
    put_u8(b_ext_body, 0x30);
    put_u8(b_ext_body, 12);
    put_u8(b_ext_body, 0x06);
    put_u8(b_ext_body, 3);
    put_bytes(b_ext_body, "\x55\x1D\x13");
    put_u8(b_ext_body, 0x04);
    put_u8(b_ext_body, 5);
    put_u8(b_ext_body, 0x30);
    put_u8(b_ext_body, 3);
    put_u8(b_ext_body, 0x01);
    put_u8(b_ext_body, 1);
    put_u8(b_ext_body, 0xFF);

    // Extension 2: SubjectAltName (if dns_san or ip_san present)
    if dns_san.len > 0 || ip_san.len > 0 {
        var b_san_names = builder_init();
        if dns_san.len > 0 {
            put_u8(b_san_names, 0x82);
            put_u8(b_san_names, dns_san.len as u8);
            put_bytes(b_san_names, dns_san);
        }
        if ip_san.len == 4 {
            put_u8(b_san_names, 0x87);
            put_u8(b_san_names, 4);
            put_bytes(b_san_names, ip_san);
        } else if ip_san.len > 0 {
            var ip4: u8[4] = [0; 4];
            if parse_ipv4_literal(ip_san, ip4) {
                put_u8(b_san_names, 0x87);
                put_u8(b_san_names, 4);
                put_bytes(b_san_names, ip4[..]);
            }
        }

        var b_san_seq = builder_init();
        put_u8(b_san_seq, 0x30);
        put_u8(b_san_seq, b_san_names.buf.len as u8);
        put_bytes(b_san_seq, b_san_names.buf[..]);

        put_u8(b_ext_body, 0x30);
        let ext_len = 2 + 3 + 2 + b_san_seq.buf.len;
        put_u8(b_ext_body, ext_len as u8);
        put_u8(b_ext_body, 0x06);
        put_u8(b_ext_body, 3);
        put_bytes(b_ext_body, "\x55\x1D\x11");
        put_u8(b_ext_body, 0x04);
        put_u8(b_ext_body, b_san_seq.buf.len as u8);
        put_bytes(b_ext_body, b_san_seq.buf[..]);
    }

    var b_ext_full = builder_init();
    put_u8(b_ext_full, 0xA3);
    let ext_seq_len = 2 + b_ext_body.buf.len;
    put_u8(b_ext_full, ext_seq_len as u8);
    put_u8(b_ext_full, 0x30);
    put_u8(b_ext_full, b_ext_body.buf.len as u8);
    put_bytes(b_ext_full, b_ext_body.buf[..]);
    put_bytes(b_tbs, b_ext_full.buf[..]);

    var b_tbs_full = builder_init();
    put_u8(b_tbs_full, 0x30);
    if b_tbs.buf.len >= 256 {
        put_u8(b_tbs_full, 0x82);
        put_u8(b_tbs_full, (b_tbs.buf.len >> 8) as u8);
        put_u8(b_tbs_full, (b_tbs.buf.len & 0xFF) as u8);
    } else if b_tbs.buf.len >= 128 {
        put_u8(b_tbs_full, 0x81);
        put_u8(b_tbs_full, b_tbs.buf.len as u8);
    } else {
        put_u8(b_tbs_full, b_tbs.buf.len as u8);
    }
    put_bytes(b_tbs_full, b_tbs.buf[..]);

    let sig = core::ed25519_sign(seed, b_tbs_full.buf[..]);

    var b_cert_inner = builder_init();
    put_bytes(b_cert_inner, b_tbs_full.buf[..]);
    put_u8(b_cert_inner, 0x30);
    put_u8(b_cert_inner, 5);
    put_u8(b_cert_inner, 0x06);
    put_u8(b_cert_inner, 3);
    put_bytes(b_cert_inner, "\x2B\x65\x70");
    put_u8(b_cert_inner, 0x03);
    put_u8(b_cert_inner, 65);
    put_u8(b_cert_inner, 0x00);
    put_bytes(b_cert_inner, sig[..]);

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
    alpn:                 u8[..32]         = [],
    trust_store:          TrustAnchorStore = TrustAnchorStore { .. },
    insecure_skip_verify: bool             = false,
    virtual_clock_sec:    i64              = 0,
}

struct TlsServerHandshakeConfig {
    cert_der:  u8[..4096] = [],
    priv_seed: u8[32]     = [0; 32],
    alpn:      u8[..32]   = [],
}

// Parses raw Certificate message payload into an array of DER certificate slices (RFC 8446 §4.4.2).
//
// Example:
//   payload = [0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x04, 'C', 'E', 'R', 'T', 0x00, 0x00]
//   returns: true, out_certs.len = 1
fn parse_tls13_certificate_chain(payload: const u8[:], out_certs: const u8[:][..8]&) -> bool {
    guard payload.len >= 4 else { return false; }
    let ctx_len = payload[0] as i64;
    var cursor = 1 + ctx_len;
    guard cursor + 3 <= payload.len else { return false; }

    let list_len = (payload[cursor] << 16) | (payload[cursor + 1] << 8) | payload[cursor + 2];
    cursor += 3;
    guard cursor + list_len == payload.len else { return false; }

    out_certs.clear();
    while cursor < payload.len {
        guard cursor + 3 <= payload.len else { return false; }
        let c_len = (payload[cursor] << 16) | (payload[cursor + 1] << 8) | payload[cursor + 2];
        cursor += 3;
        guard cursor + c_len <= payload.len else { return false; }
        let cert_bytes = payload[cursor..cursor + c_len];
        cursor += c_len;

        guard cursor + 2 <= payload.len else { return false; }
        let ext_len = (payload[cursor] << 8) | payload[cursor + 1];
        cursor += 2 + ext_len;
        guard cursor <= payload.len else { return false; }

        guard out_certs.len < out_certs.cap else { return false; }
        out_certs.push(cert_bytes);
    }
    return out_certs.len > 0;
}

// Serializes a TLS 1.3 ClientHello payload with standard extensions (RFC 8446 §4.1.2).
// crap:ignore
fn build_tls13_client_hello_payload<B>(
    random:      const u8[32]&,
    client_pub:  const u8[32]&,
    server_name: const u8[:],
    alpn:        const u8[:],
    out:         B&,
) {
    out.clear();
    core::append_u16_be(out, 0x0303);
    out.append(random[..]);
    out.push(32);
    out.append(random[..]);

    core::append_u16_be(out, 4);
    core::append_u16_be(out, rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    core::append_u16_be(out, rfc::TLS_CIPHER_AES_256_GCM_SHA384);
    out.push(1);
    out.push(0);

    var ext_buf: u8[..2048] = [];
    core::append_u16_be(ext_buf, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    core::append_u16_be(ext_buf, 3);
    ext_buf.push(2);
    core::append_u16_be(ext_buf, rfc::TLS_VERSION_1_3);

    core::append_u16_be(ext_buf, rfc::TLS_EXT_SUPPORTED_GROUPS);
    core::append_u16_be(ext_buf, 4);
    core::append_u16_be(ext_buf, 2);
    core::append_u16_be(ext_buf, rfc::GROUP_X25519);

    core::append_u16_be(ext_buf, rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    core::append_u16_be(ext_buf, 4);
    core::append_u16_be(ext_buf, 2);
    core::append_u16_be(ext_buf, rfc::SIG_SCHEME_ED25519);

    var shares: u8[..64] = [];
    core::append_u16_be(shares, rfc::GROUP_X25519);
    core::append_u16_be(shares, 32);
    shares.append(client_pub[..]);
    encode_key_share_client_extension(ext_buf, shares[..]);

    if server_name.len > 0 && server_name.len <= 255 {
        core::append_u16_be(ext_buf, rfc::TLS_EXT_SERVER_NAME);
        let sni_len = (server_name.len + 3) as u16;
        core::append_u16_be(ext_buf, sni_len + 2);
        core::append_u16_be(ext_buf, sni_len);
        ext_buf.push(0);
        core::append_u16_be(ext_buf, server_name.len as u16);
        ext_buf.append(server_name);
    }

    if alpn.len > 0 && alpn.len <= 255 {
        core::append_u16_be(ext_buf, rfc::TLS_EXT_ALPN);
        core::append_u16_be(ext_buf, (alpn.len + 3) as u16);
        core::append_u16_be(ext_buf, (alpn.len + 1) as u16);
        ext_buf.push(alpn.len as u8);
        ext_buf.append(alpn);
    }

    core::append_u16_be(out, ext_buf.len as u16);
    out.append(ext_buf[..]);
}

// Sends a plaintext TLS record containing a handshake message (RFC 8446 §5.1).
fn send_plaintext_handshake_record(fd: i64, hs_msg: const u8[:]) -> bool {
    guard hs_msg.len > 0 && hs_msg.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    var rec_buf: u8[..4096] = [];
    rec_buf.push(rfc::TLS_CONTENT_HANDSHAKE);
    rec_buf.push(0x03);
    rec_buf.push(0x01); // legacy record version 1.0 (RFC 8446 §5.1)
    core::append_u16_be(rec_buf, hs_msg.len as u16);
    rec_buf.append(hs_msg);
    return tls_write_all(fd, rec_buf[..]);
}

// Reads the next unencrypted handshake message record from the socket, discarding ChangeCipherSpec.
fn read_plaintext_handshake_record(
    fd:          i64,
    out_payload: u8[..4096]&,
    timeout_ms:  u32 = 5000,
) -> bool {
    var raw_msg: u8[..4096] = [];
    var found = false;
    while !found {
        var hdr: u8[5] = [0; 5];
        guard tls_read_exact(fd, hdr[..], timeout_ms) else { return false; }
        let ct, ver, p_len_u16, alert, ok_hdr = parse_tls_record_header(hdr[..]);
        guard ok_hdr else { return false; }
        let p_len = p_len_u16 as i64;
        guard p_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }

        var body: u8[..4096] = [];
        while body.len < p_len { body.push(0); }
        guard tls_read_exact(fd, body[..p_len], timeout_ms) else { return false; }

        if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
            continue;
        }
        guard ct == rfc::TLS_CONTENT_HANDSHAKE else { return false; }
        raw_msg.append(body[..p_len]);
        found = true;
    }
    guard found else { return false; }
    out_payload.clear();
    out_payload.append(raw_msg[..]);
    return true;
}

// Parses ServerHello wire payload, extracting negotiated cipher suite and ephemeral public key.
//
// Example:
//   payload = [0x02, 0x00, 0x00, 0x46, 0x03, 0x03, 0x00, 0x13, 0x01]
//   returns: true, out_cipher_suite = 0x1301, out_server_pub = [32 bytes]
// crap:ignore
fn parse_server_hello_fields(
    payload:          const u8[:],
    out_cipher_suite: u16&,
    out_server_pub:   u8[32]&,
) -> bool {
    guard payload.len >= 38 else { return false; }
    guard payload[0] == rfc::TLS_HS_SERVER_HELLO else { return false; }
    let msg_len = (payload[1] << 16) | (payload[2] << 8) | payload[3];
    guard 4 + msg_len == payload.len else { return false; }

    var server_random: u8[32] = [0; 32];
    for i in 32 { server_random[i] = payload[6 + i]; }
    guard !is_hello_retry_request(server_random) else { return false; }

    let sid_len = payload[38] as i64;
    let cs_offset = 39 + sid_len;
    guard cs_offset + 2 <= payload.len else { return false; }
    out_cipher_suite = core::read_be_u16(payload, cs_offset);
    let cs_valid = out_cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 ||
        out_cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384;
    guard cs_valid else { return false; }

    let ext_offset = cs_offset + 3;
    guard ext_offset + 2 <= payload.len else { return false; }
    let ext_total = core::read_be_u16(payload, ext_offset) as i64;
    guard ext_offset + 2 + ext_total == payload.len else { return false; }
    let ext_bytes = payload[ext_offset + 2..];

    let negotiated_ver, ok_ver = parse_server_supported_versions(ext_bytes);
    guard ok_ver && negotiated_ver == rfc::TLS_VERSION_1_3 else { return false; }

    var srv_group: u16        = 0;
    var srv_share: u8[..2048] = [];
    let ok_share = parse_key_share_server_extension(ext_bytes, srv_group, srv_share);
    guard ok_share && srv_group == rfc::GROUP_X25519 && srv_share.len == 32 else { return false; }

    for i in 32 { out_server_pub[i] = srv_share[i]; }
    return true;
}

// Validates server Certificate and CertificateVerify against trust anchor store and transcript (RFC 8446 §4.4).
// crap:ignore
fn verify_server_cert_and_signature(
    cert_body:          const u8[:],
    cv_body:            const u8[:],
    transcript_to_cert: const u8[:],
    config:             const TlsClientHandshakeConfig&,
) -> bool {
    var chain_slices: const u8[:][..8] = [];
    guard parse_tls13_certificate_chain(cert_body, chain_slices) else { return false; }
    var leaf_cert = ParsedCert { .. };
    guard parse_x509_certificate(chain_slices[0], leaf_cert) else { return false; }

    if !config.insecure_skip_verify {
        var chain_parsed: ParsedCert[..8] = [];
        chain_parsed.push(leaf_cert);
        let alert = verify_certificate_chain(chain_parsed, chain_slices, config.trust_store, config.virtual_clock_sec);
        guard alert == TlsAlert.CloseNotify else { return false; }

        if config.server_name.len > 0 {
            var sans: SanEntry[..16] = [];
            let ok_san = get_cert_san_extension(leaf_cert, chain_slices[0], sans) &&
                match_any_san(sans, config.server_name[..]);
            guard ok_san else { return false; }
        }
    }

    var leaf_pub = span_slice(chain_slices[0], leaf_cert.spki_pubkey);
    if leaf_pub.len == 33 && leaf_pub[0] == 0 {
        leaf_pub = leaf_pub[1..];
    }
    guard leaf_pub.len == 32 else { return false; }

    let sig_scheme, sig_bytes, ok_parse_cv = parse_certificate_verify(cv_body);
    guard ok_parse_cv && sig_scheme == rfc::SIG_SCHEME_ED25519 && sig_bytes.len == 64 else { return false; }

    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 130 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = build_certificate_verify_message(true, transcript_to_cert, cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }

    var pub_arr: u8[32] = [0; 32];
    for i in 32 { pub_arr[i] = leaf_pub[i]; }
    var sig_arr: u8[64] = [0; 64];
    for i in 64 { sig_arr[i] = sig_bytes[i]; }
    return core::ed25519_verify(pub_arr, cv_msg_buf[..cv_len], sig_arr);
}

// Ingests and verifies the encrypted server flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
// crap:ignore
fn tls_client_process_server_flight(
    hs_reader:     HandshakeRecordReader&,
    fd:            i64,
    cipher_suite:  u16,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    ks:            const internal::KeySchedule&,
    transcript:    u8[..4096]&,
    config:        const TlsClientHandshakeConfig&,
) -> bool {
    var msg_ee:  u8         = 0;
    var ee_body: u8[..8192] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_ee, ee_body, 5000,
    ) else { return false; }
    guard msg_ee == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else { return false; }
    transcript.push(msg_ee);
    core::append_u24_be(transcript, ee_body.len as u32);
    transcript.append(ee_body[..]);

    var msg_cert:  u8         = 0;
    var cert_body: u8[..8192] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_cert, cert_body, 5000,
    ) else { return false; }
    guard msg_cert == rfc::TLS_HS_CERTIFICATE else { return false; }
    transcript.push(msg_cert);
    core::append_u24_be(transcript, cert_body.len as u32);
    transcript.append(cert_body[..]);

    var msg_cv:  u8         = 0;
    var cv_body: u8[..8192] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_cv, cv_body, 5000,
    ) else { return false; }
    guard msg_cv == rfc::TLS_HS_CERTIFICATE_VERIFY else { return false; }

    let h_to_cert = core::sha256(transcript[..]);
    guard verify_server_cert_and_signature(cert_body[..], cv_body[..], h_to_cert[..], config) else { return false; }
    transcript.push(msg_cv);
    core::append_u24_be(transcript, cv_body.len as u32);
    transcript.append(cv_body[..]);

    var msg_fin:  u8         = 0;
    var fin_body: u8[..8192] = [];
    guard next_handshake_message(
        hs_reader, fd, cipher_suite, server_hs_key, server_hs_iv, msg_fin, fin_body, 5000,
    ) else { return false; }
    guard msg_fin == rfc::TLS_HS_FINISHED && fin_body.len == 32 else { return false; }

    let h_to_cv = core::sha256(transcript[..]);
    var exp_srv_fin: u8[32] = [0; 32];
    let hlen = ks.hash_len as i64;
    guard internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen], h_to_cv[..], exp_srv_fin[..],
    ) else { return false; }
    guard core::ct_eq_bytes(exp_srv_fin[..], fin_body[..32]) else { return false; }
    transcript.push(msg_fin);
    core::append_u24_be(transcript, fin_body.len as u32);
    transcript.append(fin_body[..]);
    return true;
}

inline fn cipher_suite_key_len(cs: u16) -> u16 {
    if cs == rfc::TLS_CIPHER_AES_256_GCM_SHA384 || cs == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        return 32;
    }
    return 16;
}

fn tls_client_send_finished(
    fd:            i64,
    cipher_suite:  u16,
    client_hs_key: const u8[:],
    client_hs_iv:  const u8[12]&,
    ks:            const internal::KeySchedule&,
    transcript:    u8[..4096]&,
) -> bool {
    let h_through_srv_fin = core::sha256(transcript[..]);
    var cli_fin_data: u8[32] = [0; 32];
    let hlen = ks.hash_len as i64;
    guard internal::ks_compute_finished_verify_data(
        ks.hash_id,
        ks.hash_len,
        ks.client_hs_traffic[..hlen],
        h_through_srv_fin[..],
        cli_fin_data[..],
    ) else { return false; }

    var cli_fin_msg: u8[36] = [0; 36];
    cli_fin_msg[0] = rfc::TLS_HS_FINISHED;
    cli_fin_msg[1] = 0;
    cli_fin_msg[2] = 0;
    cli_fin_msg[3] = 32;
    for i in 32 { cli_fin_msg[4 + i] = cli_fin_data[i]; }

    var ct_cli_fin: u8[..256] = [];
    while ct_cli_fin.len < 100 { ct_cli_fin.push(0); }
    let s_len, _, ok_seal = tls_record_seal_into(
        cipher_suite,
        client_hs_key,
        client_hs_iv,
        0,
        rfc::TLS_CONTENT_HANDSHAKE,
        cli_fin_msg[..],
        ct_cli_fin[..],
    );
    guard ok_seal && tls_write_all(fd, ct_cli_fin[..s_len]) else { return false; }
    transcript.append(cli_fin_msg[..]);
    return true;
}

fn tls_setup_client_cipher_slot(
    slot_idx:     u16,
    cipher_suite: u16,
    key_len_u16:  u16,
    ks:           const internal::KeySchedule&,
    c_ap_key:     const u8[:],
    c_ap_iv:      const u8[12]&,
    s_ap_key:     const u8[:],
    s_ap_iv:      const u8[12]&,
) {
    let idx = slot_idx as i64;
    g_tls_cipher_slots[idx].cipher_suite = cipher_suite;
    g_tls_cipher_slots[idx].key_len = key_len_u16;
    g_tls_cipher_slots[idx].hash_id = ks.hash_id;
    g_tls_cipher_slots[idx].hash_len = ks.hash_len;
    g_tls_cipher_slots[idx].is_server = false;
    for i in 32 { g_tls_cipher_slots[idx].tx_key[i] = c_ap_key[i]; }
    for i in 12 { g_tls_cipher_slots[idx].tx_iv[i] = c_ap_iv[i]; }
    g_tls_cipher_slots[idx].tx_seq = 0;
    for i in 32 { g_tls_cipher_slots[idx].rx_key[i] = s_ap_key[i]; }
    for i in 12 { g_tls_cipher_slots[idx].rx_iv[i] = s_ap_iv[i]; }
    g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
}

// Executes full TLS 1.3 client handshake over raw TCP socket, returning slot index (RFC 8446 §4).
// crap:ignore
fn tls_client_handshake(fd: i64, config: const TlsClientHandshakeConfig&) -> u16, bool {
    let slot_idx = alloc_tls_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }
    let idx = slot_idx as i64;

    let client_random = tls_random_bytes_32();
    let client_priv = tls_random_bytes_32();
    let client_pub = core::x25519_base_scalarmult(client_priv);

    var ch_payload: u8[..2048] = [];
    build_tls13_client_hello_payload(client_random, client_pub, config.server_name[..], config.alpn[..], ch_payload);
    var ch_msg: u8[..2048] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_msg, ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    guard send_plaintext_handshake_record(fd, ch_msg[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    tls_write_all(fd, ccs[..]);

    var transcript: u8[..4096] = [];
    transcript.append(ch_msg[..]);

    var sh_msg: u8[..4096] = [];
    guard read_plaintext_handshake_record(fd, sh_msg) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    transcript.append(sh_msg[..]);

    var cipher_suite: u16    = 0;
    var server_pub:   u8[32] = [0; 32];
    guard parse_server_hello_fields(sh_msg[..], cipher_suite, server_pub) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let ecdhe_secret, ok_ecdhe = core::x25519_shared_secret(client_priv, server_pub);
    guard ok_ecdhe else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var ks, ok_ks = internal::ks_init(cipher_suite);
    let ok_ks_adv = ok_ks &&
        internal::ks_init_early_secret(ks, []) &&
        internal::ks_advance_to_handshake(ks, ecdhe_secret[..]);
    guard ok_ks_adv else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ch_sh_hash = core::sha256(transcript[..]);
    guard internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var client_hs_key: u8[32] = [0; 32];
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    var server_hs_iv:  u8[12] = [0; 12];
    let key_len_u16 = cipher_suite_key_len(cipher_suite);
    let klen = key_len_u16 as i64;
    let hlen = ks.hash_len as i64;
    let ok_c_hs = internal::ks_derive_key_iv(
        ks.hash_id, ks.client_hs_traffic[..hlen], key_len_u16,
        client_hs_key[..klen], client_hs_iv,
    );
    guard ok_c_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_hs = internal::ks_derive_key_iv(
        ks.hash_id, ks.server_hs_traffic[..hlen], key_len_u16,
        server_hs_key[..klen], server_hs_iv,
    );
    guard ok_s_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var hs_reader = HandshakeRecordReader { .. };
    let ok_flight = tls_client_process_server_flight(
        hs_reader, fd, cipher_suite, server_hs_key[..klen],
        server_hs_iv, ks, transcript, config,
    );
    guard ok_flight else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    guard tls_client_send_finished(
        fd, cipher_suite, client_hs_key[..klen], client_hs_iv, ks, transcript,
    ) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var client_ap_key: u8[32] = [0; 32];
    var client_ap_iv:  u8[12] = [0; 12];
    var server_ap_key: u8[32] = [0; 32];
    var server_ap_iv:  u8[12] = [0; 12];
    let ok_c_ap = internal::ks_derive_key_iv(
        ks.hash_id, ks.client_ap_traffic[..hlen], key_len_u16,
        client_ap_key[..klen], client_ap_iv,
    );
    guard ok_c_ap else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_ap = internal::ks_derive_key_iv(
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
    );
    return slot_idx, true;
}

// Parses ClientHello payload for server handshake, extracting session ID and client X25519 key share.
//
// Example:
//   payload = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, 0x00, 0x13, 0x01]
//   returns: true, out_session_id = [], out_client_pub = [32 bytes]
// crap:ignore
fn parse_client_hello_for_server(
    payload:        const u8[:],
    out_session_id: u8[..32]&,
    out_client_pub: u8[32]&,
) -> bool {
    guard payload.len >= 38 else { return false; }
    guard payload[0] == rfc::TLS_HS_CLIENT_HELLO else { return false; }
    let msg_len = (payload[1] << 16) | (payload[2] << 8) | payload[3];
    guard 4 + msg_len == payload.len else { return false; }

    var tmp_sid: u8[..32] = [];
    let sid_len = payload[38] as i64;
    guard 39 + sid_len <= payload.len else { return false; }
    if sid_len > 0 && sid_len <= tmp_sid.cap {
        tmp_sid.append(payload[39..39 + sid_len]);
    }

    let cs_offset = 39 + sid_len;
    guard cs_offset + 2 <= payload.len else { return false; }
    let cs_len = core::read_be_u16(payload, cs_offset) as i64;
    let comp_offset = cs_offset + 2 + cs_len;
    guard comp_offset + 1 <= payload.len else { return false; }
    let comp_len = payload[comp_offset] as i64;
    let ext_offset = comp_offset + 1 + comp_len;
    guard ext_offset + 2 <= payload.len else { return false; }
    let ext_total = core::read_be_u16(payload, ext_offset) as i64;
    guard ext_offset + 2 + ext_total == payload.len else { return false; }
    let ext_bytes = payload[ext_offset + 2..];

    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(ext_bytes, entries) else { return false; }

    let ks_data, has_ks = find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_ks else { return false; }
    var shares: u8[..4096] = [];
    guard parse_key_share_client_extension(ks_data, shares) else { return false; }

    var cursor: i64 = 0;
    var found_share = false;
    while cursor + 4 <= shares.len {
        let group = core::read_be_u16(shares[..], cursor);
        let kex_len = core::read_be_u16(shares[..], cursor + 2) as i64;
        cursor += 4;
        guard cursor + kex_len <= shares.len else { return false; }
        if group == rfc::GROUP_X25519 && kex_len == 32 {
            for i in 32 { out_client_pub[i] = shares[cursor + i]; }
            found_share = true;
            break;
        }
        cursor += kex_len;
    }
    guard found_share else { return false; }

    out_session_id.clear();
    out_session_id.append(tmp_sid[..]);
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
    while ct_buf.len < hs_msg.len + 32 { ct_buf.push(0); }
    let s_len, _, ok_seal = tls_record_seal_into(
        cipher_suite, key, iv, seq,
        rfc::TLS_CONTENT_HANDSHAKE, hs_msg, ct_buf[..],
    );
    guard ok_seal && tls_write_all(fd, ct_buf[..s_len]) else { return false; }
    return true;
}

// Builds a minimal TLS 1.3 ServerHello wire payload echoing session ID and offering X25519 share.
fn build_tls13_server_hello_payload<B>(
    server_random: const u8[32]&,
    session_id:    const u8[:],
    server_pub:    const u8[32]&,
    out:           B&,
) {
    out.clear();
    core::append_u16_be(out, 0x0303);
    out.append(server_random[..]);
    out.push(session_id.len as u8);
    out.append(session_id);
    core::append_u16_be(out, rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    out.push(0);

    var ext_buf: u8[..512] = [];
    core::append_u16_be(ext_buf, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    core::append_u16_be(ext_buf, 2);
    core::append_u16_be(ext_buf, rfc::TLS_VERSION_1_3);

    encode_key_share_server_extension(ext_buf, rfc::GROUP_X25519, server_pub[..]);
    core::append_u16_be(out, ext_buf.len as u16);
    out.append(ext_buf[..]);
}

fn tls_server_send_cv(
    fd:            i64,
    cipher_suite:  u16,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    server_seq:    u64&,
    priv_seed:     const u8[32]&,
    transcript:    u8[..4096]&,
) -> bool {
    let h_to_cert = core::sha256(transcript[..]);
    var cv_msg_buf: u8[..256] = [];
    while cv_msg_buf.len < 130 { cv_msg_buf.push(0); }
    let cv_len, ok_cv_msg = build_certificate_verify_message(true, h_to_cert[..], cv_msg_buf[..]);
    guard ok_cv_msg else { return false; }
    let sig = core::ed25519_sign(priv_seed, cv_msg_buf[..cv_len]);

    var cv_payload: u8[..512] = [];
    guard encode_client_certificate_verify(cv_payload, rfc::SIG_SCHEME_ED25519, sig[..]) else { return false; }
    var cv_msg: u8[..512] = [];
    cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
    core::append_u24_be(cv_msg, cv_payload.len as u32);
    cv_msg.append(cv_payload[..]);

    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cv_msg[..]) else {
        return false;
    }
    server_seq++;
    transcript.append(cv_msg[..]);
    return true;
}

// Encrypts and transmits the server handshake flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
// crap:ignore
fn tls_server_send_flight(
    fd:            i64,
    server_hs_key: const u8[:],
    server_hs_iv:  const u8[12]&,
    ks:            const internal::KeySchedule&,
    transcript:    u8[..4096]&,
    config:        const TlsServerHandshakeConfig&,
) -> bool {
    let cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    var server_seq: u64 = 0;

    var ee_msg: u8[6] = [rfc::TLS_HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0];
    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, ee_msg[..]) else {
        return false;
    }
    server_seq++;
    transcript.append(ee_msg[..]);

    var cert_payload: u8[..4096] = [];
    guard encode_client_certificate(cert_payload, "", config.cert_der[..]) else { return false; }
    var cert_msg: u8[..4096] = [];
    cert_msg.push(rfc::TLS_HS_CERTIFICATE);
    core::append_u24_be(cert_msg, cert_payload.len as u32);
    cert_msg.append(cert_payload[..]);

    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, cert_msg[..]) else {
        return false;
    }
    server_seq++;
    transcript.append(cert_msg[..]);

    guard tls_server_send_cv(
        fd, cipher_suite, server_hs_key, server_hs_iv,
        server_seq, config.priv_seed, transcript,
    ) else {
        return false;
    }

    let h_to_cv = core::sha256(transcript[..]);
    var srv_fin_data: u8[32] = [0; 32];
    let hlen = ks.hash_len as i64;
    let ok_fin_calc = internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.server_hs_traffic[..hlen],
        h_to_cv[..], srv_fin_data[..],
    );
    guard ok_fin_calc else { return false; }

    var srv_fin_msg: u8[36] = [0; 36];
    srv_fin_msg[0] = rfc::TLS_HS_FINISHED;
    srv_fin_msg[1] = 0; srv_fin_msg[2] = 0; srv_fin_msg[3] = 32;
    for i in 32 { srv_fin_msg[4 + i] = srv_fin_data[i]; }

    guard tls_seal_and_send_hs(fd, cipher_suite, server_hs_key, server_hs_iv, server_seq, srv_fin_msg[..]) else {
        return false;
    }
    transcript.append(srv_fin_msg[..]);
    return true;
}

fn tls_setup_server_cipher_slot(
    slot_idx:     u16,
    cipher_suite: u16,
    key_len_u16:  u16,
    ks:           const internal::KeySchedule&,
    s_ap_key:     const u8[:],
    s_ap_iv:      const u8[12]&,
    c_ap_key:     const u8[:],
    c_ap_iv:      const u8[12]&,
) {
    let idx = slot_idx as i64;
    g_tls_cipher_slots[idx].cipher_suite = cipher_suite;
    g_tls_cipher_slots[idx].key_len = key_len_u16;
    g_tls_cipher_slots[idx].hash_id = ks.hash_id;
    g_tls_cipher_slots[idx].hash_len = ks.hash_len;
    g_tls_cipher_slots[idx].is_server = true;
    for i in 32 { g_tls_cipher_slots[idx].tx_key[i] = s_ap_key[i]; }
    for i in 12 { g_tls_cipher_slots[idx].tx_iv[i] = s_ap_iv[i]; }
    g_tls_cipher_slots[idx].tx_seq = 0;
    for i in 32 { g_tls_cipher_slots[idx].rx_key[i] = c_ap_key[i]; }
    for i in 12 { g_tls_cipher_slots[idx].rx_iv[i] = c_ap_iv[i]; }
    g_tls_cipher_slots[idx].rx_seq = 0;
    for i in 48 { g_tls_cipher_slots[idx].tx_traffic_secret[i] = ks.server_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].rx_traffic_secret[i] = ks.client_ap_traffic[i]; }
    for i in 48 { g_tls_cipher_slots[idx].exporter_secret[i] = ks.exporter_secret[i]; }
    for i in 48 { g_tls_cipher_slots[idx].resumption_secret[i] = ks.resumption_secret[i]; }
}

// Executes full TLS 1.3 server handshake over raw TCP socket, returning slot index (RFC 8446 §4).
// crap:ignore
fn tls_server_handshake(fd: i64, config: const TlsServerHandshakeConfig&) -> u16, bool {
    let slot_idx = alloc_tls_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }
    let idx = slot_idx as i64;

    var ch_msg: u8[..4096] = [];
    guard read_plaintext_handshake_record(fd, ch_msg) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    var transcript: u8[..4096] = [];
    transcript.append(ch_msg[..]);

    var session_id: u8[..32] = [];
    var client_pub: u8[32]   = [0; 32];
    guard parse_client_hello_for_server(ch_msg[..], session_id, client_pub) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let server_random = tls_random_bytes_32();
    let server_priv = tls_random_bytes_32();
    let server_pub = core::x25519_base_scalarmult(server_priv);

    let ecdhe_secret, ok_ecdhe = core::x25519_shared_secret(server_priv, client_pub);
    guard ok_ecdhe else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var sh_payload: u8[..2048] = [];
    build_tls13_server_hello_payload(server_random, session_id[..], server_pub, sh_payload);
    var sh_msg: u8[..2048] = [];
    sh_msg.push(rfc::TLS_HS_SERVER_HELLO);
    core::append_u24_be(sh_msg, sh_payload.len as u32);
    sh_msg.append(sh_payload[..]);

    guard send_plaintext_handshake_record(fd, sh_msg[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    tls_write_all(fd, ccs[..]);
    transcript.append(sh_msg[..]);

    let cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    var ks, ok_ks = internal::ks_init(cipher_suite);
    let ok_ks_adv = ok_ks &&
        internal::ks_init_early_secret(ks, []) &&
        internal::ks_advance_to_handshake(ks, ecdhe_secret[..]);
    guard ok_ks_adv else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let ch_sh_hash = core::sha256(transcript[..]);
    guard internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let key_len_u16 = cipher_suite_key_len(cipher_suite);
    let klen = key_len_u16 as i64;
    let hlen = ks.hash_len as i64;
    var client_hs_key: u8[32] = [0; 32];
    var client_hs_iv:  u8[12] = [0; 12];
    var server_hs_key: u8[32] = [0; 32];
    var server_hs_iv:  u8[12] = [0; 12];
    let ok_c_hs = internal::ks_derive_key_iv(
        ks.hash_id, ks.client_hs_traffic[..hlen], key_len_u16,
        client_hs_key[..klen], client_hs_iv,
    );
    guard ok_c_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_hs = internal::ks_derive_key_iv(
        ks.hash_id, ks.server_hs_traffic[..hlen], key_len_u16,
        server_hs_key[..klen], server_hs_iv,
    );
    guard ok_s_hs else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    guard tls_server_send_flight(fd, server_hs_key[..klen], server_hs_iv, ks, transcript, config) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    let h_through_srv_fin = core::sha256(transcript[..]);
    guard internal::ks_advance_to_master(ks, h_through_srv_fin[..]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var hs_reader = HandshakeRecordReader { .. };
    var cli_fin_body: u8[..8192] = [];
    var msg_fin:      u8         = 0;
    let ok_msg = next_handshake_message(
        hs_reader, fd, cipher_suite, client_hs_key[..klen],
        client_hs_iv, msg_fin, cli_fin_body, 5000,
    );
    guard ok_msg else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    guard msg_fin == rfc::TLS_HS_FINISHED && cli_fin_body.len == 32 else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    var exp_cli_fin: u8[32] = [0; 32];
    let ok_exp_fin = internal::ks_compute_finished_verify_data(
        ks.hash_id, ks.hash_len, ks.client_hs_traffic[..hlen],
        h_through_srv_fin[..], exp_cli_fin[..],
    );
    guard ok_exp_fin else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    guard core::ct_eq_bytes(exp_cli_fin[..], cli_fin_body[..32]) else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }

    transcript.push(msg_fin);
    core::append_u24_be(transcript, 32);
    transcript.append(cli_fin_body[..32]);
    let h_through_cli_fin = core::sha256(transcript[..]);
    internal::ks_advance_to_resumption(ks, h_through_cli_fin[..]);

    var client_ap_key: u8[32] = [0; 32];
    var client_ap_iv:  u8[12] = [0; 12];
    var server_ap_key: u8[32] = [0; 32];
    var server_ap_iv:  u8[12] = [0; 12];
    let ok_c_ap = internal::ks_derive_key_iv(
        ks.hash_id, ks.client_ap_traffic[..hlen], key_len_u16,
        client_ap_key[..klen], client_ap_iv,
    );
    guard ok_c_ap else {
        free_tls_cipher_slot(slot_idx);
        return 0xFFFF, false;
    }
    let ok_s_ap = internal::ks_derive_key_iv(
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
    return slot_idx, true;
}
